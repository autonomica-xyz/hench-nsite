#!/usr/bin/env node
// NIP-5A host server — serves nsites (kinds 15128/35128/5128) from a Nostr
// relay + Blossom blobs, per https://github.com/nostr-protocol/nips/blob/master/5A.md
//
// Local-test defaults point at `nak serve --blossom` (see test-local.sh);
// override with env: NSITE_RELAY, NSITE_BLOSSOM, PORT, NSITE_BIND.
//
// Trust model:
//  - Manifests are fully verified (NIP-01 id recompute + BIP-340 schnorr sig)
//    and must match the requested filter — a hostile relay cannot forge sites.
//  - Blob bodies are sha256-checked against the manifest's path tags.
//  - Blob servers (manifest `server` tags and BUD-03 kind-10063 user servers)
//    are fetched through a dispatcher that refuses non-public IPs at connect
//    time — no SSRF into LAN/metadata. The operator's NSITE_BLOSSOM fallback
//    is trusted separately and may be a private host.
//  - Tenants are isolated by origin via canonical subdomain labels
//    (<npub>.host, v<b36id>.host, <b36pk><dtag>.host). Path-prefix routing
//    /<label>/<path> shares one origin, so it is DEV-ONLY.
//
// Dev mode (path-prefix routing + private-IP blob hosts) requires the explicit
// NSITE_DEV=1 opt-in — a loopback bind is not proof requests are local
// (a reverse proxy terminates on loopback and forwards public traffic).
// NSITE_ALLOW_PRIVATE=1 allows private manifest blob hosts on its own.
// NSITE_MAX_BLOB caps each blob body; NSITE_MAX_INFLIGHT_BLOBS bounds
// concurrent blob downloads.

import http from "node:http";
import crypto from "node:crypto";
import os from "node:os";
import net from "node:net";
import dns from "node:dns";
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { schnorr } from "@noble/curves/secp256k1.js";
import { Agent, fetch as undiciFetch } from "undici";

const RELAY = process.env.NSITE_RELAY ?? "ws://localhost:10547";
const PORT = +(process.env.PORT ?? 8933);
const BIND = process.env.NSITE_BIND ?? "0.0.0.0"; // LAN access for phone testing
const MAX_BLOB = +(process.env.NSITE_MAX_BLOB || 32 * 1024 * 1024) || 32 * 1024 * 1024;
const MAX_INFLIGHT = Math.max(1, +(process.env.NSITE_MAX_INFLIGHT_BLOBS || 16) || 16);
const MAX_WS_BYTES = 1 * 1024 * 1024; // relay message cap — hostile relays can't exhaust memory
const FALLBACK_BLOSSOM = process.env.NSITE_BLOSSOM ?? "http://localhost:10547"; // operator-trusted

const flag = (v) => v === "1" || v === "true" || v === "yes";
// Explicit opt-in only: the bind address says nothing about request provenance.
export const DEV = flag(process.env.NSITE_DEV);
const ALLOW_PRIVATE = DEV || flag(process.env.NSITE_ALLOW_PRIVATE);

for (const [name, url, schemes] of [
  ["NSITE_RELAY", RELAY, ["ws:", "wss:"]],
  ["NSITE_BLOSSOM", FALLBACK_BLOSSOM, ["http:", "https:"]],
]) {
  let ok = false;
  try { ok = schemes.includes(new URL(url).protocol); } catch { /* invalid */ }
  if (!ok) { console.error(`host: ${name} must be one of ${schemes.join("/")}, got ${url}`); process.exit(1); }
}

const CONTENT_TYPES = {
  html: "text/html; charset=utf-8", css: "text/css", js: "text/javascript",
  mjs: "text/javascript", json: "application/json", txt: "text/plain; charset=utf-8",
  md: "text/markdown", svg: "image/svg+xml", png: "image/png", jpg: "image/jpeg",
  jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", ico: "image/x-icon",
  xml: "application/xml", wasm: "application/wasm", woff2: "font/woff2",
};

// ---------- base36 labels (NIP-5A: pubkeyB36 / snapshotIdB36, exactly 50 chars) ----------

const B36 = "0123456789abcdefghijklmnopqrstuvwxyz";
export function hexToB36(hex) {
  let n = BigInt("0x" + hex), s = "";
  while (n > 0n) { s = B36[Number(n % 36n)] + s; n /= 36n; }
  return s.padStart(50, "0");
}
function b36ToHex(s) {
  if (!/^[0-9a-z]{50}$/.test(s)) return null;
  let n = 0n;
  for (const c of s) n = n * 36n + BigInt(B36.indexOf(c));
  if (n >= 1n << 256n) return null;
  return n.toString(16).padStart(64, "0");
}

// ---------- bech32 (npub decode only) ----------

const BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
function bech32Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= BECH32_GEN[i];
  }
  return chk;
}
function npubToHex(npub) {
  if (npub !== npub.toLowerCase()) return null;
  const pos = npub.lastIndexOf("1");
  if (pos < 1 || npub.length > 90) return null;
  const hrp = npub.slice(0, pos);
  if (hrp !== "npub") return null;
  const data = [];
  for (const c of npub.slice(pos + 1)) {
    const v = BECH32.indexOf(c);
    if (v === -1) return null;
    data.push(v);
  }
  const hrpExpand = [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];
  if (bech32Polymod([...hrpExpand, ...data]) !== 1) return null;
  const five = data.slice(0, -6); // drop checksum
  let acc = 0, bits = 0;
  const bytes = [];
  for (const v of five) {
    acc = (acc << 5) | v; bits += 5;
    while (bits >= 8) { bits -= 8; bytes.push((acc >> bits) & 0xff); }
  }
  if (bits >= 5 || ((acc << (8 - bits)) & 0xff)) return null; // stray bits
  return bytes.length === 32 ? Buffer.from(bytes).toString("hex") : null;
}

// ---------- label parsing (NIP-5A "Host server implementation" order) ----------

export function parseLabel(label) {
  if (typeof label !== "string" || label.length < 4) return null;
  const npubHex = /^npub1[02-9ac-hj-np-z]+$/.test(label) ? npubToHex(label) : null;
  if (npubHex) return { type: "root", pubkey: npubHex };
  const snap = label.match(/^v([0-9a-z]{50})$/);
  if (snap) {
    const id = b36ToHex(snap[1]);
    if (id) return { type: "snapshot", id };
  }
  const named = label.match(/^([0-9a-z]{50})([a-z0-9-]{1,13})$/);
  if (named && !named[2].endsWith("-")) {
    const pubkey = b36ToHex(named[1]);
    if (pubkey) return { type: "named", pubkey, d: named[2] };
  }
  return null;
}

// ---------- event verification (NIP-01 id + BIP-340 sig + filter match) ----------

const HEX64 = /^[0-9a-f]{64}$/;

function eventHash(e) {
  return crypto.createHash("sha256")
    .update(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content]), "utf8")
    .digest("hex");
}

export function verifyEvent(e) {
  if (!e || typeof e !== "object" || Array.isArray(e)) return false;
  if (!HEX64.test(e.id ?? "") || !HEX64.test(e.pubkey ?? "") || !/^[0-9a-f]{128}$/.test(e.sig ?? "")) return false;
  if (!Number.isInteger(e.kind) || !Number.isInteger(e.created_at)) return false;
  if (e.created_at < 0 || e.created_at > Math.floor(Date.now() / 1000) + 900) return false; // not from the future
  if (!Array.isArray(e.tags) || typeof e.content !== "string") return false;
  if (!e.tags.every((tag) => Array.isArray(tag) && tag.every((value) => typeof value === "string"))) return false;
  if (eventHash(e) !== e.id) return false;
  try {
    return schnorr.verify(Buffer.from(e.sig, "hex"), Buffer.from(e.id, "hex"), Buffer.from(e.pubkey, "hex"));
  } catch { return false; }
}

// The relay may return events outside the filter; only accept exact matches.
function matchesRef(e, ref) {
  switch (ref.type) {
    case "root": return e.kind === 15128 && e.pubkey === ref.pubkey &&
      !e.tags.some((t) => t[0] === "d"); // NIP-5A: root manifests MUST NOT carry a d tag
    case "named": return e.kind === 35128 && e.pubkey === ref.pubkey &&
      e.tags.some((t) => t[0] === "d" && t[1] === ref.d);
    case "snapshot": return e.kind === 5128 && e.id === ref.id;
    default: return false;
  }
}

// ---------- relay ----------

async function fetchEvents(filter, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const events = [];
    let ws;
    try { ws = new WebSocket(RELAY); } catch { return resolve(events); }
    const done = () => { clearTimeout(timer); try { ws.close(); } catch { /* closed */ } resolve(events); };
    const timer = setTimeout(done, timeoutMs);
    ws.addEventListener("open", () =>
      ws.send(JSON.stringify(["REQ", `nsite-${Math.random().toString(36).slice(2, 8)}`, filter])));
    let bytes = 0;
    ws.addEventListener("message", ({ data }) => {
      bytes += typeof data === "string" ? data.length : (data.byteLength ?? 0);
      if (bytes > MAX_WS_BYTES) return done(); // hostile relay flooding → bail
      let m; try { m = JSON.parse(data); } catch { return; }
      if (m[0] === "EVENT" && m[2]) events.push(m[2]);
      else if (m[0] === "EOSE") done();
    });
    ws.addEventListener("error", done);
    ws.addEventListener("close", () => { clearTimeout(timer); resolve(events); });
  });
}

async function resolveManifest(ref) {
  const filter =
    ref.type === "root" ? { kinds: [15128], authors: [ref.pubkey], limit: 1 } :
    ref.type === "named" ? { kinds: [35128], authors: [ref.pubkey], "#d": [ref.d], limit: 1 } :
    { ids: [ref.id] };
  const events = (await fetchEvents(filter))
    .filter((e) => verifyEvent(e) && matchesRef(e, ref));
  return events.sort((a, b) => b.created_at - a.created_at)[0] ?? null;
}

// BUD-03: the publisher's kind-10063 user-server list, verified and filtered.
async function resolveBudServers(pubkey) {
  const events = (await fetchEvents({ kinds: [10063], authors: [pubkey], limit: 1 }))
    .filter((e) => verifyEvent(e) && e.kind === 10063 && e.pubkey === pubkey);
  const ev = events.sort((a, b) => b.created_at - a.created_at)[0];
  return ev
    ? ev.tags.filter((t) => t[0] === "server" && safeHttpUrl(t[1] ?? "")).map((t) => t[1]).slice(0, 3)
    : [];
}

// ---------- path + blob resolution ----------

export function resolvePathTag(manifest, pathname) {
  // NIP-5A: ["path", "/absolute/path", "sha256hash"] — the spec defines no MIME field.
  const pathTags = manifest.tags.filter((t) =>
    t[0] === "path" && typeof t[1] === "string" && t[1].startsWith("/") && HEX64.test(t[2] ?? ""));
  const find = (p) => pathTags.find((t) => t[1] === p);
  // NIP-5A: request path not ending with a filename → fall back to index.html
  if (!/\.[^/]*$/.test(pathname)) pathname = (pathname.endsWith("/") ? pathname : pathname + "/") + "index.html";
  const exact = find(pathname);
  if (exact) return { hash: exact[2], pathname, notFound: false };
  const fallback = find("/404.html"); // NIP-5A: not-found fallback path
  return fallback ? { hash: fallback[2], pathname: "/404.html", notFound: true } : null;
}

// ---------- SSRF guard: non-public IPs never connect ----------

export function isBlockedIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b, c] = ip.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return true;            // this-net, RFC1918, loopback, mcast/reserved
    if (a === 100 && b >= 64 && b <= 127) return true;                        // CGNAT
    if (a === 169 && b === 254) return true;                                  // link-local (incl. cloud metadata)
    if (a === 172 && b >= 16 && b <= 31) return true;                         // RFC1918
    if (a === 192 && (b === 0 || b === 168)) return true;                     // IETF proto + doc ranges, RFC1918
    if (a === 198 && (b === 18 || b === 19)) return true;                     // benchmark
    if ((a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return true; // doc ranges
    return false;
  }
  if (!net.isIPv6(ip)) return true; // not an IP at all → block
  const s = ip.toLowerCase();
  const mapped = s.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);               // ::ffff:a.b.c.d
  if (mapped) return isBlockedIp(mapped[1]);
  const parts = s.split("::");
  if (parts.length > 2) return true;
  const toHex = (p) => (p === "" ? [] : p.split(":").map((t) => parseInt(t, 16)));
  const left = toHex(parts[0]), right = parts.length === 2 ? toHex(parts[1]) : [];
  if ([...left, ...right].some((n) => !(n >= 0 && n <= 0xffff))) return true;
  const h = [...left, ...Array(8 - left.length - right.length).fill(0), ...right];
  if (h.length !== 8) return true;
  if (h.slice(0, 5).every((x) => x === 0) && h[5] === 0xffff)                 // ::ffff:0:0/96 (hex form)
    return isBlockedIp(`${h[6] >> 8}.${h[6] & 255}.${h[7] >> 8}.${h[7] & 255}`);
  if (h[0] === 0) return true;                                                // ::/8 (unspecified, loopback, compat)
  if ((h[0] & 0xfe00) === 0xfc00) return true;                                // fc00::/7 unique-local
  if ((h[0] & 0xff80) === 0xfe80) return true;                                // link-local + deprecated site-local
  if ((h[0] & 0xff00) === 0xff00) return true;                                // ff00::/8 multicast
  if (h[0] === 0x2001 && h[1] === 0x0db8) return true;                        // documentation range
  return false;
}

// DNS answers are checked at connect time (no TOCTOU): only public IPs are
// ever returned to undici, so a lookup that resolves to a private host fails.
function guardedLookup(hostname, options, cb) {
  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) {
      const err = new Error(`blocked private address ${hostname}`);
      err.code = "ENOTFOUND";
      return cb(err);
    }
    return dns.lookup(hostname, options, cb);
  }
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return cb(err);
    const good = (addresses ?? []).filter((a) => !isBlockedIp(a.address));
    if (!good.length) {
      const e = new Error(`no public addresses for ${hostname}`);
      e.code = "ENOTFOUND";
      return cb(e);
    }
    if (options?.all) return cb(null, good);
    cb(null, good[0].address, good[0].family);
  });
}

// Manifest/BUD-03 server tags are publisher-controlled → guarded dispatcher.
// The operator's NSITE_BLOSSOM fallback is trusted separately: it may be a
// private host even on a public bind without opening publisher SSRF.
const manifestAgent = ALLOW_PRIVATE ? new Agent() : new Agent({ connect: { lookup: guardedLookup } });
const fallbackAgent = new Agent();

// server tag / redirect target: http(s) only, no credentials
function safeHttpUrl(u, base) {
  try {
    const x = new URL(u, base);
    if ((x.protocol !== "http:" && x.protocol !== "https:") || x.username || x.password) return null;
    return x.href;
  } catch { return null; }
}

async function readBody(res) {
  const len = res.headers.get("content-length");
  if (len !== null && +len > MAX_BLOB) { res.body?.cancel().catch(() => {}); return null; }
  try {
    const reader = res.body.getReader();
    const chunks = [];
    let n = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      n += value.byteLength;
      if (n > MAX_BLOB) { reader.cancel().catch(() => {}); return null; }
      chunks.push(value);
    }
    return Buffer.concat(chunks);
  } catch { return null; }
}

// Bounds concurrent downloads — a per-body byte cap alone still lets N
// requests each buffer MAX_BLOB at once.
let blobInflight = 0;
const blobWaiters = [];
const takeBlobSlot = () =>
  blobWaiters.length || blobInflight >= MAX_INFLIGHT
    ? new Promise((r) => blobWaiters.push(r))
    : (blobInflight++, Promise.resolve());
const giveBlobSlot = () => { if (blobWaiters.length) blobWaiters.shift()(); else blobInflight--; };

// servers: [{ base, agent }] — try each until a hash-matching body arrives
async function fetchBlob(servers, hash) {
  await takeBlobSlot();
  try {
    for (const { base, agent } of servers) {
      let url = `${base.replace(/\/+$/, "")}/${hash}`;
      let res = null;
      for (let hop = 0; hop < 4; hop++) { // ≤3 redirects, each revalidated
        // Literal addresses bypass the socket's DNS lookup hook.
        const hostname = new URL(url).hostname.replace(/^\[|\]$/g, "");
        if (!ALLOW_PRIVATE && agent === manifestAgent && net.isIP(hostname) && isBlockedIp(hostname)) {
          res = null;
          break;
        }
        try {
          res = await undiciFetch(url, { redirect: "manual", dispatcher: agent, signal: AbortSignal.timeout(5000) });
        } catch { res = null; break; }
        if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
          const next = safeHttpUrl(res.headers.get("location"), url);
          res.body?.cancel().catch(() => {});
          if (!next) { res = null; break; }
          url = next;
          continue;
        }
        break; // final response
      }
      if (!res || !res.ok) { res?.body?.cancel().catch(() => {}); continue; }
      const buf = await readBody(res);
      if (buf && crypto.createHash("sha256").update(buf).digest("hex") === hash)
        return { buf, type: res.headers.get("content-type") }; // NIP-5A: blob hash verified
    }
    return null;
  } finally { giveBlobSlot(); }
}

const SCRIPTABLE = /^\s*(text\/html|application\/xhtml\+xml|image\/svg\+xml|text\/javascript|application\/javascript|text\/xml|application\/xml)/i;
const MIME_TOKEN = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/i;

// Deviation from NIP-5A ("MUST forward the Blossom Content-Type"): a blob
// server is untrusted — it can relabel signed .txt bytes as text/html and get
// script execution under the site origin. The publisher-signed manifest path
// wins; an upstream type is honored only when no extension maps and it can't
// execute as markup/script.
function contentTypeFor(blossomType, pathname) {
  const ext = pathname.split(".").pop().toLowerCase();
  if (CONTENT_TYPES[ext]) return CONTENT_TYPES[ext];
  if (MIME_TOKEN.test(blossomType ?? "") && !SCRIPTABLE.test(blossomType)) return blossomType;
  return "application/octet-stream"; // never let an extensionless blob execute as html/svg/js
}

function send(res, status, type, body, head) {
  res.writeHead(status, {
    "Content-Type": type,
    "Content-Length": body.length,
    "X-Content-Type-Options": "nosniff",
  });
  res.end(head ? undefined : body);
}

// ---------- http server ----------

export const server = http.createServer(async (req, res) => {
  const head = req.method === "HEAD";
  try {
    if (req.method !== "GET" && !head)
      return send(res, 405, "text/plain; charset=utf-8", "method not allowed\n", head);
    if ((req.url ?? "").length > 2048)
      return send(res, 414, "text/plain; charset=utf-8", "uri too long\n", head);

    let pathname;
    try { pathname = decodeURIComponent((req.url ?? "/").split("?")[0]); }
    catch { return send(res, 400, "text/plain; charset=utf-8", "bad path\n", head); }
    if (!pathname.startsWith("/") || pathname.includes("\0") || pathname.includes("\\") || /(^|\/)\.\.($|\/)/.test(pathname))
      return send(res, 400, "text/plain; charset=utf-8", "bad path\n", head);

    let ref = null;
    // canonical: subdomain label from Host (leftmost DNS label of a multi-label host)
    const rawHost = req.headers.host ?? "";
    const hostNoPort = rawHost.startsWith("[") ? rawHost.slice(1, rawHost.indexOf("]")) : rawHost.split(":")[0];
    const hostLabel = hostNoPort.split(".")[0];
    if (hostNoPort.includes(".") && parseLabel(hostLabel)) {
      ref = parseLabel(hostLabel);
    } else if (DEV) {
      // dev-only convenience: /<label>/<site-path> path prefix (single origin,
      // tenants not isolated — explicit NSITE_DEV=1 only, never bind-inferred)
      const seg = pathname.split("/")[1] ?? "";
      const parsed = parseLabel(seg);
      if (parsed) {
        ref = parsed;
        pathname = pathname.slice(seg.length + 1) || "/";
      }
    }
    if (!ref) return send(res, 404, "text/plain; charset=utf-8", "not found: no nsite label in Host or path\n", head);

    const manifest = await resolveManifest(ref);
    if (!manifest) return send(res, 404, "text/plain; charset=utf-8", "not found: no valid site manifest\n", head);

    const resolved = resolvePathTag(manifest, pathname);
    if (!resolved) return send(res, 404, "text/plain; charset=utf-8", "not found\n", head);

    // NIP-5A order: manifest server hints first, then the author's BUD-03
    // user servers, then the operator fallback. Publisher-chosen servers go
    // through the guarded dispatcher; the fallback uses the trusted one.
    const guarded = (base) => ({ base, agent: manifestAgent });
    const manifestServers = manifest.tags
      .filter((t) => t[0] === "server" && safeHttpUrl(t[1] ?? ""))
      .map((t) => t[1]).slice(0, 3).map(guarded);
    let blob = await fetchBlob(manifestServers, resolved.hash);
    if (!blob)
      blob = await fetchBlob((await resolveBudServers(manifest.pubkey)).map(guarded), resolved.hash);
    if (!blob)
      blob = await fetchBlob([{ base: FALLBACK_BLOSSOM, agent: fallbackAgent }], resolved.hash);
    if (!blob) return send(res, 404, "text/plain; charset=utf-8", "not found: blob unavailable or hash mismatch\n", head);

    const headers = {
      "Content-Type": contentTypeFor(blob.type, resolved.pathname),
      "Content-Length": blob.buf.length,
      "X-Content-Type-Options": "nosniff",
      // only snapshots are immutable — root/named manifests are replaceable,
      // so they must revalidate; blob bytes are content-addressed regardless
      "Cache-Control": ref.type === "snapshot"
        ? "public, max-age=31536000, immutable"
        : "public, max-age=60",
    };
    res.writeHead(resolved.notFound ? 404 : 200, headers);
    res.end(head ? undefined : blob.buf);
  } catch (error) {
    send(res, 500, "text/plain; charset=utf-8", `error: ${error.message}\n`, head);
  }
});

const isMain = process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href;
if (isMain) {
  const lanUrls = BIND === "0.0.0.0"
    ? Object.values(os.networkInterfaces()).flat()
        .filter((a) => a?.family === "IPv4" && !a.internal)
        .map((a) => `http://${a.address}:${PORT}/`)
    : [];
  server.listen(PORT, BIND, () => {
    console.log(`nsite host on ${BIND === "0.0.0.0" ? lanUrls.join(" ") : `http://${BIND}:${PORT}/`} — relay ${RELAY}, blossom fallback ${FALLBACK_BLOSSOM}`);
    if (!DEV) {
      console.log("dev features off: no /<label>/ path-prefix routing, manifest/BUD-03 servers restricted to public IPs");
      if (/^(ws|http)s?:\/\/(localhost|127\.|::1|\[::1\])/.test(RELAY))
        console.log("local relay detected — run with NSITE_DEV=1 to enable path-prefix routing and private blob hosts");
    }
  });
}
