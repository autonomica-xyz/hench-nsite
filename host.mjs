#!/usr/bin/env node
// NIP-5A host server — serves nsites (kinds 15128/35128/5128) from a Nostr
// relay + Blossom blobs, per https://github.com/nostr-protocol/nips/blob/master/5A.md
//
// Local-test defaults point at `nak serve --blossom` (see test-local.sh);
// override with env: NSITE_RELAY, NSITE_BLOSSOM, PORT.
//
// Routing: canonical subdomain labels (Host header, e.g. <npub>.localhost:8933,
// v<b36id>.…, <b36pk><dtag>.…) plus a path-prefix form for curl/testing:
// http://localhost:8933/<label>/<site-path>.
//
// ponytail: manifests are trusted as the relay delivered them (no sig check);
// add schnorr verify if this ever fronts an untrusted relay.
// ponytail: no BUD-03 (kind 10063) user-server lookup; manifest `server` tags
// plus NSITE_BLOSSOM fallback cover the local case.

import http from "node:http";
import crypto from "node:crypto";
import os from "node:os";

const RELAY = process.env.NSITE_RELAY ?? "ws://localhost:10547";
const FALLBACK_BLOSSOM = process.env.NSITE_BLOSSOM ?? "http://localhost:10547";
const PORT = +(process.env.PORT ?? 8933);

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
    ws.addEventListener("message", ({ data }) => {
      let m; try { m = JSON.parse(data); } catch { return; }
      if (m[0] === "EVENT" && m[2]) events.push(m[2]);
      else if (m[0] === "EOSE") done();
    });
    ws.addEventListener("error", done);
    ws.addEventListener("close", () => { clearTimeout(timer); resolve(events); });
  });
}

async function resolveManifest({ type, pubkey, d, id }) {
  const filter =
    type === "root" ? { kinds: [15128], authors: [pubkey], limit: 1 } :
    type === "named" ? { kinds: [35128], authors: [pubkey], "#d": [d], limit: 1 } :
    { ids: [id] };
  const events = (await fetchEvents(filter)).filter((e) =>
    type === "snapshot" ? e.kind === 5128 : e.kind === filter.kinds[0]);
  return events.sort((a, b) => b.created_at - a.created_at)[0] ?? null;
}

// ---------- path + blob resolution ----------

function resolvePathTag(manifest, pathname) {
  const pathTags = manifest.tags.filter((t) => t[0] === "path" && t[1] && t[2]);
  const find = (p) => pathTags.find((t) => t[1] === p);
  // NIP-5A: request path not ending with a filename → fall back to index.html
  if (!/\.[^/]*$/.test(pathname)) pathname = (pathname.endsWith("/") ? pathname : pathname + "/") + "index.html";
  const exact = find(pathname);
  if (exact) return { hash: exact[2], pathname, notFound: false };
  const fallback = find("/404.html"); // NIP-5A: not-found fallback path
  return fallback ? { hash: fallback[2], pathname: "/404.html", notFound: true } : null;
}

async function fetchBlob(servers, hash) {
  for (const base of servers) {
    try {
      const res = await fetch(`${base.replace(/\/$/, "")}/${hash}`, { signal: AbortSignal.timeout(5000) });
      if (!res.ok) continue;
      const buf = Buffer.from(await res.arrayBuffer());
      if (crypto.createHash("sha256").update(buf).digest("hex") !== hash) continue; // NIP-5A: verify blob hash
      return { buf, type: res.headers.get("content-type") };
    } catch { /* try next server */ }
  }
  return null;
}

function contentTypeFor(blossomType, pathname) {
  if (blossomType && blossomType !== "application/octet-stream") return blossomType;
  const ext = pathname.split(".").pop().toLowerCase();
  return CONTENT_TYPES[ext] ?? "application/octet-stream";
}

function send(res, status, type, body) {
  res.writeHead(status, { "Content-Type": type, "Content-Length": body.length });
  res.end(body);
}

// ---------- http server ----------

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    let pathname;
    try { pathname = decodeURIComponent(url.pathname); } catch { pathname = url.pathname; }

    let ref = null;
    // canonical: subdomain label from Host (leftmost DNS label of a multi-label host)
    const hostLabel = (req.headers.host ?? "").split(":")[0].split(".")[0];
    if ((req.headers.host ?? "").includes(".") && parseLabel(hostLabel)) {
      ref = parseLabel(hostLabel);
      pathname = url.pathname;
    } else {
      // local convenience: /<label>/<site-path> path prefix
      const seg = pathname.split("/")[1] ?? "";
      const parsed = parseLabel(seg);
      if (parsed) {
        ref = parsed;
        pathname = pathname.slice(seg.length + 1) || "/";
      }
    }
    if (!ref) return send(res, 404, "text/plain; charset=utf-8", "not found: no nsite label in Host or path\n");

    const manifest = await resolveManifest(ref);
    if (!manifest) return send(res, 404, "text/plain; charset=utf-8", "not found: no site manifest\n");

    const resolved = resolvePathTag(manifest, pathname);
    if (!resolved) return send(res, 404, "text/plain; charset=utf-8", "not found\n");

    const servers = [
      ...manifest.tags.filter((t) => t[0] === "server" && /^https?:\/\//.test(t[1] ?? "")).map((t) => t[1]).slice(0, 3),
      FALLBACK_BLOSSOM,
    ];
    const blob = await fetchBlob(servers, resolved.hash);
    if (!blob) return send(res, 404, "text/plain; charset=utf-8", "not found: blob unavailable or hash mismatch\n");

    res.writeHead(resolved.notFound ? 404 : 200, {
      "Content-Type": contentTypeFor(blob.type, resolved.pathname),
      "Content-Length": blob.buf.length,
      "Cache-Control": "public, max-age=31536000, immutable",
    });
    res.end(blob.buf);
  } catch (error) {
    send(res, 500, "text/plain; charset=utf-8", `error: ${error.message}\n`);
  }
});

const BIND = process.env.NSITE_BIND ?? "0.0.0.0"; // LAN access for phone testing; set NSITE_BIND=127.0.0.1 to lock down

const lanUrls = Object.values(os.networkInterfaces())
  .flat()
  .filter((a) => a?.family === "IPv4" && !a.internal)
  .map((a) => `http://${a.address}:${PORT}/`);

server.listen(PORT, BIND, () =>
  console.log(`nsite host on ${BIND === "0.0.0.0" ? lanUrls.join(" ") : `http://${BIND}:${PORT}/`} — relay ${RELAY}, blossom fallback ${FALLBACK_BLOSSOM}`));
