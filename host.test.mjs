// Regressions for hostile relay / SSRF / path handling — run: node --test host.test.mjs
// Hosts exercised:
//   in-process dev instance (NSITE_DEV=1): forged manifests, fixture blobs,
//     MIME protection, redirects, BUD-03, concurrency and size bounds
//   spawned non-dev instances (public + loopback binds): path-prefix off,
//     publisher server tags guarded, operator fallback still reachable
// host.mjs binds env at import, so fixtures start and env is set first.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import crypto from "node:crypto";
import net from "node:net";
import { spawn } from "node:child_process";
import { schnorr } from "@noble/curves/secp256k1.js";

const B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
function npubEncode(hex) {
  const bytes = Buffer.from(hex, "hex");
  const data = [];
  let acc = 0, bits = 0;
  for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; data.push((acc >> bits) & 31); } }
  if (bits) data.push((acc << (5 - bits)) & 31);
  let chk = 1;
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  const pm = (vs) => { for (const v of vs) { const b = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]; } };
  const hrp = [...[..."npub"].map((c) => c.charCodeAt(0) >> 5), 0, ...[..."npub"].map((c) => c.charCodeAt(0) & 31)];
  pm(hrp); pm(data); pm([0, 0, 0, 0, 0, 0]);
  const sum = chk ^ 1;
  const check = [25, 20, 15, 10, 5, 0].map((s) => (sum >> s) & 31); // BIP-173
  return "npub1" + [...data, ...check].map((d) => B32[d]).join("");
}

const SEC_A = "1".repeat(64);
const SEC_B = "2".repeat(64);
const SEC_C = "3".repeat(64);
const PK_A = Buffer.from(schnorr.getPublicKey(Buffer.from(SEC_A, "hex"))).toString("hex");

function signEvent(secHex, partial) {
  const pubkey = Buffer.from(schnorr.getPublicKey(Buffer.from(secHex, "hex"))).toString("hex");
  const e = { pubkey, created_at: Math.floor(Date.now() / 1000), kind: 15128, tags: [], content: "", ...partial };
  e.id = crypto.createHash("sha256").update(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])).digest("hex");
  e.sig = Buffer.from(schnorr.sign(Buffer.from(e.id, "hex"), Buffer.from(secHex, "hex"))).toString("hex");
  return e;
}

function wsFrame(str) {
  const p = Buffer.from(str);
  const hdr = p.length < 126 ? [p.length] : [126, p.length >> 8, p.length & 255];
  return Buffer.concat([Buffer.from([0x81, ...hdr]), p]);
}
function fakeRelay(events) {
  const srv = http.createServer();
  const sockets = new Set(); // upgraded sockets outlive srv.close() — reaped via srv.teardown
  srv.on("upgrade", (req, socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    const accept = crypto.createHash("sha1")
      .update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
    setTimeout(() => {
      for (const e of events) socket.write(wsFrame(JSON.stringify(["EVENT", "x", e])));
      socket.write(wsFrame(JSON.stringify(["EOSE", "x"])));
    }, 30);
  });
  srv.teardown = () => { for (const s of sockets) s.destroy(); };
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv)));
}
// map: hash → { buf, type?, delay? }; counts hits and peak concurrent bodies
function fakeBlobs(map) {
  const srv = http.createServer((req, res) => {
    srv.hits++;
    const item = map[req.url.slice(1)];
    if (!item) { res.writeHead(404); return res.end(); }
    srv.inflight++; srv.peak = Math.max(srv.peak, srv.inflight);
    res.on("finish", () => srv.inflight--);
    const sendIt = () => {
      res.writeHead(200, { "Content-Type": item.type ?? "application/octet-stream" });
      res.end(item.buf);
    };
    item.delay ? setTimeout(sendIt, item.delay) : sendIt();
  });
  srv.hits = 0; srv.inflight = 0; srv.peak = 0;
  return new Promise((r) => srv.listen(0, "127.0.0.1", () => r(srv)));
}
const get = (port, path, headers) => new Promise((r, j) => {
  http.get({ host: "127.0.0.1", port, path, headers }, (res) => {
    const c = []; res.on("data", (d) => c.push(d)); res.on("end", () => r({ status: res.statusCode, body: Buffer.concat(c), headers: res.headers }));
  }).on("error", j);
});
const freePort = () => new Promise((r) => { const s = net.createServer().listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });

// spawn a host.mjs child; readiness = stdout banner, early exit rejects
const spawnHost = (env) => {
  const child = spawn(process.execPath, ["host.mjs"], {
    env: { ...process.env, NSITE_DEV: "0", NSITE_ALLOW_PRIVATE: "0", ...env },
    stdio: ["ignore", "pipe", "inherit"],
  });
  const ready = new Promise((r, j) => {
    const to = setTimeout(() => j(new Error("spawned host did not start")), 8000);
    child.stdout.on("data", (d) => { if (d.toString().includes("nsite host on")) { clearTimeout(to); r(); } });
    child.on("exit", (code) => { clearTimeout(to); j(new Error(`spawned host exited early (${code})`)); });
  });
  return { child, ready };
};

// ---------- fixtures (started before host.mjs is imported) ----------

const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const blob = Buffer.from("<h1>real nsite</h1>");
const hash = sha(blob);
const docBlob = Buffer.from("docs with <script>alert(1)</script> inside"); // hash-matching but blossom lies about type
const docHash = sha(docBlob);
const slowBlob = Buffer.from("slow"); // under MAX_BLOB=64
const slowHash = sha(slowBlob);
const bigBlob = Buffer.alloc(200, 0x42); // over MAX_BLOB=64
const bigHash = sha(bigBlob);
const budBlob = Buffer.from("via bud03"); // reachable only through the kind-10063 server
const budHash = sha(budBlob);
const redirBlob = Buffer.from("via redirect");
const redirHash = sha(redirBlob);
const evilBlob = Buffer.from("evil bytes");
const evilHash = sha(evilBlob);
const nfBlob = Buffer.from("<h1>custom 404</h1>");
const nfHash = sha(nfBlob);

// manifest-tag server: publisher-selected, so guarded on non-dev hosts
const tagSrv = await fakeBlobs({
  [hash]: { buf: blob },
  [docHash]: { buf: docBlob, type: "text/html" },   // tries to escalate .txt → html
  [slowHash]: { buf: slowBlob, delay: 150 },
  [bigHash]: { buf: bigBlob },
  [nfHash]: { buf: nfBlob, type: "text/html" },
});
const tagPort = tagSrv.address().port;
// operator fallback: trusted, must work even private on a public bind
const fbSrv = await fakeBlobs({
  [hash]: { buf: blob },
  [redirHash]: { buf: redirBlob },
});
const fbPort = fbSrv.address().port;
// BUD-03 advertised server
const budSrv = await fakeBlobs({ [budHash]: { buf: budBlob } });
const budPort = budSrv.address().port;
// redirector: schemes are revalidated hop-by-hop
const redirSrv = http.createServer((req, res) => {
  const target = req.url.slice(1) === evilHash
    ? "file:///etc/passwd"
    : `http://127.0.0.1:${fbPort}${req.url}`;
  res.writeHead(302, { location: target });
  res.end();
});
await new Promise((r) => redirSrv.listen(0, "127.0.0.1", r));
const redirPort = redirSrv.address().port;

const victimPub = "a".repeat(64);
const forged1 = { id: "f".repeat(64), pubkey: victimPub, created_at: 1, kind: 15128,
  tags: [["path", "/index.html", hash]], content: "", sig: "e".repeat(128) };
const forged2 = { ...forged1, // self-consistent id, still invalid sig
  id: crypto.createHash("sha256").update(JSON.stringify([0, victimPub, 1, 15128, forged1.tags, ""])).digest("hex") };
const good = signEvent(SEC_A, { tags: [
  ["path", "/index.html", hash],
  ["path", "/doc.txt", docHash],
  ["path", "/slow.bin", slowHash],
  ["path", "/big.bin", bigHash],
  ["path", "/bud.txt", budHash],
  ["path", "/redir.txt", redirHash],
  ["path", "/404.html", nfHash],
  ["server", `http://127.0.0.1:${tagPort}`],
  ["server", `http://127.0.0.1:${redirPort}`],
  ["server", "file:///etc/passwd"], // must be filtered by scheme
] });
// other author's site: only reachable through a private redirect → must not be followed
const evil = signEvent(SEC_B, { tags: [
  ["path", "/index.html", evilHash],
  ["server", `http://127.0.0.1:${redirPort}`],
] });
// snapshot of `good` — immutable caching applies here only
const snap = signEvent(SEC_A, {
  kind: 5128,
  tags: [["path", "/index.html", hash], ["a", `15128:${PK_A}:`]],
});
// BUD-03 user-server record for PK_A
const bud03 = signEvent(SEC_A, { kind: 10063, tags: [["server", `http://127.0.0.1:${budPort}`]] });
// kind-15128 carrying a d tag — signed, but NIP-5A says a root manifest MUST
// NOT have one, so it must never resolve as a root site
const dOnly = signEvent(SEC_C, { tags: [
  ["d", "x"],
  ["path", "/index.html", hash], // servable — 404 must come from manifest rejection
  ["server", `http://127.0.0.1:${tagPort}`],
] });
const relay = await fakeRelay([forged1, forged2, good, evil, snap, bud03, dOnly]);
const relayPort = relay.address().port;

process.env.NSITE_DEV = "1";
process.env.NSITE_RELAY = `ws://127.0.0.1:${relayPort}`;
process.env.NSITE_BLOSSOM = `http://127.0.0.1:${fbPort}`;
process.env.PORT = "0";
process.env.NSITE_MAX_BLOB = "64";
process.env.NSITE_MAX_INFLIGHT_BLOBS = "2";
const host = await import("./host.mjs");
await new Promise((r) => host.server.listen(0, "127.0.0.1", r));
const devPort = host.server.address().port;
test.after(() => {
  host.server.closeAllConnections?.(); host.server.close();
  relay.close(); relay.teardown();
  tagSrv.close(); fbSrv.close(); budSrv.close(); redirSrv.close();
});

const snapLabel = "v" + host.hexToB36(snap.id);

// ---------- pure-function units ----------

test("verifyEvent: valid signed manifest passes, forgeries fail", () => {
  const ev = signEvent(SEC_A, { kind: 15128, tags: [["path", "/index.html", "0".repeat(64)]] });
  assert.equal(host.verifyEvent(ev), true);
  // forged id + forged sig (parent repro: fixture accepted these)
  assert.equal(host.verifyEvent({ ...ev, id: "a".repeat(64), sig: "b".repeat(128) }), false);
  // real sig but tampered content → id mismatch
  assert.equal(host.verifyEvent({ ...ev, content: "evil" }), false);
  // real sig over a different event's id
  const other = signEvent(SEC_A, { kind: 1 });
  assert.equal(host.verifyEvent({ ...ev, id: other.id, sig: other.sig }), false);
  // future timestamp
  assert.equal(host.verifyEvent(signEvent(SEC_A, { created_at: Math.floor(Date.now() / 1000) + 3600 })), false);
  // garbage shapes
  assert.equal(host.verifyEvent(null), false);
  assert.equal(host.verifyEvent({ id: ev.id, pubkey: ev.pubkey, sig: ev.sig, kind: "x", created_at: 1, tags: [], content: "" }), false);
  assert.equal(host.verifyEvent(signEvent(SEC_A, { tags: [null] })), false);
  assert.equal(host.verifyEvent(signEvent(SEC_A, { tags: [["path", 42]] })), false);
});

test("isBlockedIp: private/reserved blocked, public allowed", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.1.1", "172.16.0.1",
    "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "::", "fe80::1", "fc00::1",
    "fec0::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.5"])
    assert.equal(host.isBlockedIp(ip), true, ip);
  for (const ip of ["8.8.8.8", "1.1.1.1", "203.0.114.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"])
    assert.equal(host.isBlockedIp(ip), false, ip);
});

test("resolvePathTag: index fallback, 404 fallback, malformed hash tags ignored", () => {
  const man = { tags: [
    ["path", "/index.html", "a".repeat(64)],
    ["path", "/404.html", "b".repeat(64)],
    ["path", "/evil.js", "not-a-hash"],          // non-hex hash: unusable
    ["path", "relative", "c".repeat(64)],         // no leading slash: unusable
  ] };
  assert.equal(host.resolvePathTag(man, "/").hash, "a".repeat(64));
  const miss = host.resolvePathTag(man, "/missing.js");
  assert.equal(miss.notFound, true);
  assert.equal(miss.hash, "b".repeat(64));
  // bad-hash tag is skipped, so /evil.js misses and falls back to /404.html
  const evilMiss = host.resolvePathTag(man, "/evil.js");
  assert.equal(evilMiss.notFound, true);
  assert.equal(evilMiss.hash, "b".repeat(64));
  assert.equal(host.resolvePathTag({ tags: [] }, "/"), null);
});

test("parseLabel: all NIP-5A forms + rejects", () => {
  const npub = npubEncode(PK_A);
  assert.deepEqual(host.parseLabel(npub), { type: "root", pubkey: PK_A });
  const b36 = host.hexToB36(PK_A);
  assert.deepEqual(host.parseLabel(b36 + "demo1"), { type: "named", pubkey: PK_A, d: "demo1" });
  assert.equal(host.parseLabel(b36 + "demo1-"), null);
  assert.equal(host.parseLabel("v" + host.hexToB36("ab".repeat(32))).type, "snapshot");
  assert.equal(host.parseLabel("zzz"), null);
  assert.equal(host.parseLabel("npub1qqqq"), null);
});

// ---------- dev host: hostile relay, MIME, bounds, redirects, BUD-03 ----------

test("hostile relay + content protections on the dev host", async () => {
  const victimNpub = npubEncode(victimPub);
  // forged manifests must NOT resolve — both forgeries rejected
  let r = await get(devPort, `/${victimNpub}/`);
  assert.equal(r.status, 404, "forged manifest must not serve");
  assert.match(r.body.toString(), /no valid site manifest/);

  // signed but d-tagged kind-15128 is not a root manifest
  const dNpub = npubEncode(dOnly.pubkey);
  r = await get(devPort, `/${dNpub}/`);
  assert.equal(r.status, 404, "root manifest carrying a d tag must be rejected");

  // valid manifest serves through the manifest's server tag, hash verified
  const goodNpub = npubEncode(PK_A);
  r = await get(devPort, `/${goodNpub}/`);
  assert.equal(r.status, 200);
  assert.equal(r.body.toString(), blob.toString());
  assert.equal(r.headers["x-content-type-options"], "nosniff");
  assert.equal(r.headers["cache-control"], "public, max-age=60",
    "root manifests are replaceable — never immutable");

  // subdomain Host routing also works in dev
  r = await get(devPort, "/", { host: `${goodNpub}.localhost:${devPort}` });
  assert.equal(r.status, 200);

  // blossom claims text/html for a .txt blob — publisher path wins, no script
  r = await get(devPort, `/${goodNpub}/doc.txt`);
  assert.equal(r.status, 200);
  assert.equal(r.headers["content-type"], "text/plain; charset=utf-8");

  // manifest /404.html is served as the not-found body with a 404 status
  r = await get(devPort, `/${goodNpub}/nope.html`);
  assert.equal(r.status, 404);
  assert.equal(r.body.toString(), nfBlob.toString());

  // body over NSITE_MAX_BLOB is rejected before hashing → 404
  r = await get(devPort, `/${goodNpub}/big.bin`);
  assert.equal(r.status, 404);

  // redirects: http(s) target honored through the redirector…
  r = await get(devPort, `/${goodNpub}/redir.txt`);
  assert.equal(r.status, 200);
  assert.equal(r.body.toString(), redirBlob.toString());
  // …but a file: redirect is refused even in dev
  const evilNpub = npubEncode(evil.pubkey);
  r = await get(devPort, `/${evilNpub}/`);
  assert.equal(r.status, 404, "file: redirect target must be refused");

  // BUD-03 kind-10063 server consulted after manifest servers miss
  const budHits = budSrv.hits;
  r = await get(devPort, `/${goodNpub}/bud.txt`);
  assert.equal(r.status, 200);
  assert.equal(r.body.toString(), budBlob.toString());
  assert.ok(budSrv.hits > budHits, "BUD-03 server must be tried");

  // concurrent downloads bounded at NSITE_MAX_INFLIGHT_BLOBS=2
  tagSrv.inflight = 0; tagSrv.peak = 0;
  const rs = await Promise.all(Array.from({ length: 6 }, () => get(devPort, `/${goodNpub}/slow.bin`)));
  assert.ok(rs.every((x) => x.status === 200));
  assert.ok(tagSrv.peak > 0 && tagSrv.peak <= 2, `peak blob downloads ${tagSrv.peak} must be ≤ 2`);

  // snapshot site serves through the v-label and IS immutable
  r = await get(devPort, `/${snapLabel}/`);
  assert.equal(r.status, 200);
  assert.match(r.headers["cache-control"] ?? "", /immutable/);
});

// ---------- spawned non-dev hosts: no dev affordances on any bind ----------

test("non-dev binds: no path-prefix, guarded manifest servers, trusted fallback", async (t) => {
  const goodNpub = npubEncode(PK_A);

  // --- public bind ---
  const pubPort = await freePort();
  const pub = spawnHost({
    NSITE_BIND: "0.0.0.0", PORT: String(pubPort),
    NSITE_RELAY: `ws://127.0.0.1:${relayPort}`, NSITE_BLOSSOM: "http://127.0.0.1:9/",
  });
  t.after(() => pub.child.kill());
  await pub.ready;

  // path-prefix routing disabled → tenants share no origin
  let r = await get(pubPort, `/${goodNpub}/`);
  assert.equal(r.status, 404, "path-prefix routing must be off publicly");

  // canonical label resolves the manifest, but every publisher server target
  // is private → refused at connect time (never even hit) → 404
  const tagHits = tagSrv.hits;
  r = await get(pubPort, "/", { host: `${goodNpub}.localhost:${pubPort}` });
  assert.equal(r.status, 404);
  assert.equal(tagSrv.hits, tagHits, "private manifest server tag must be refused");

  // traversal is rejected before label routing
  r = await get(pubPort, `/${goodNpub}/%2e%2e/etc`, { host: `x.localhost:${pubPort}` });
  assert.equal(r.status, 400);

  // --- loopback bind, still no NSITE_DEV: a proxy in front must not unlock dev ---
  const lbPort = await freePort();
  const lb = spawnHost({
    NSITE_BIND: "127.0.0.1", PORT: String(lbPort),
    NSITE_RELAY: `ws://127.0.0.1:${relayPort}`, NSITE_BLOSSOM: `http://127.0.0.1:${fbPort}`,
  });
  t.after(() => lb.child.kill());
  await lb.ready;

  // a loopback listener behind a reverse proxy serves external traffic —
  // bind address proves nothing, so path-prefix routing stays off
  r = await get(lbPort, `/${goodNpub}/`);
  assert.equal(r.status, 404, "loopback bind must not imply dev mode");

  // publisher-chosen private servers still refused…
  const tagBefore = tagSrv.hits, fbBefore = fbSrv.hits;
  r = await get(lbPort, "/", { host: `${goodNpub}.localhost:${lbPort}` });
  assert.equal(r.status, 200, "operator fallback must serve even when private");
  // …while the operator-configured fallback is trusted and serves
  assert.equal(tagSrv.hits, tagBefore, "private manifest server stays refused");
  assert.ok(fbSrv.hits > fbBefore, "private NSITE_BLOSSOM fallback must be reachable");
});
