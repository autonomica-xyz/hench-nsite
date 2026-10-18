// hench.js — drop-in browser client for Hench phone workers (ContextVM / MCP over Nostr, CEP-8 payments).
// No build step: ES module, dependencies vendored under ./vendor/. Extracted from hench-web/app.js.
//
// Usage:
//   import { discoverWorkers, callTool, qrInto } from "./hench.js";
//   const workers = await discoverWorkers();            // [{ pubkey, name, about, tools, caps, relays }]
//   const { text, uris } = await callTool({
//     workerPubkey, tool: "web_fetch", args: { url },
//     onEvent: (e) => { if (e.type === "payment_required") qrInto(canvas, e.params); },
//   });

import {
  finalizeEvent, generateSecretKey, getPublicKey, verifyEvent, nip44,
} from "./vendor/nostr-tools.mjs";
import { bytesToHex, hexToBytes } from "./vendor/noble-hashes-utils.mjs";
import {
  KIND_CTXVM, KIND_WRAP, KIND_WRAP_ALT, KIND_SERVER_ANNOUNCEMENT, KIND_TOOLS_LIST,
  MCP_PROTOCOL_VERSION, CLIENT_SECRET_KEY, DEFAULT_RELAYS,
  isEventObject, announcementFresh, discoverySince, fromWorker, cleanBolt11,
  InvocationRouter,
} from "./lib.mjs";

export { DEFAULT_RELAYS };

// Discovery round state — bumped per discoverWorkers() call so late events or
// sockets from a superseded scan can't contaminate the current selection.
let discoveryRound = 0;
const discoverySockets = new Set();

export async function discoverWorkers({
  relays = DEFAULT_RELAYS,
  waitMs = 8000,
  henchOnly = true,
} = {}) {
  // Each call is a round: kill the previous round's sockets and ignore its
  // late events — an old relay selection must never contaminate a new scan.
  const round = ++discoveryRound;
  for (const socket of discoverySockets) closeQuietly(socket);
  discoverySockets.clear();
  const discovered = new Map();
  const seen = new Set();
  await Promise.allSettled(
    relays.map(
      (url) =>
        new Promise((resolve) => {
          let socket;
          try { socket = new WebSocket(url); } catch { return resolve(); }
          discoverySockets.add(socket);
          const done = () => { discoverySockets.delete(socket); closeQuietly(socket); resolve(); };
          socket.addEventListener("open", () => {
            if (round !== discoveryRound) return done();
            socket.send(JSON.stringify(["REQ", `hench-disc-${Math.random().toString(36).slice(2, 10)}`, { kinds: [KIND_SERVER_ANNOUNCEMENT, KIND_TOOLS_LIST], since: discoverySince(), limit: 200 }])); // randomUUID needs a secure context; LAN http isn't one
            setTimeout(done, waitMs);
          });
          socket.addEventListener("message", ({ data }) => {
            if (round !== discoveryRound) return; // late event from a superseded scan
            const message = parseJson(data);
            if (!Array.isArray(message) || message[0] !== "EVENT" || !message[2]) return;
            const event = message[2];
            if (seen.has(event.id)) return;
            seen.add(event.id);
            ingestAnnouncement(discovered, event, url);
          });
          socket.addEventListener("error", done);
          socket.addEventListener("close", () => { discoverySockets.delete(socket); done(); });
          // Close even if the socket never opened — a stuck CONNECTING socket
          // otherwise leaks until the tab closes.
          setTimeout(done, waitMs + 1000);
        }),
    ),
  );
  // A newer call won while we waited — its results are authoritative.
  if (round !== discoveryRound) return [];
  return [...discovered.values()]
    .filter((w) => w.tools.length > 0 && announcementFresh({ created_at: w.lastAnnounced }))
    .filter((w) => !henchOnly || w.isHench)
    .sort((a, b) => (a.name || "").localeCompare(b.name || ""));
}

function ingestAnnouncement(discovered, event, relayUrl) {
  // Relays (or anyone who can write to one) can push anything; only signed,
  // well-formed, fresh announcements count.
  if (!isEventObject(event)) return false;
  if (event.kind !== KIND_SERVER_ANNOUNCEMENT && event.kind !== KIND_TOOLS_LIST) return false;
  if (!announcementFresh(event)) return false;
  if (!verifyEvent(event)) return false;
  if (!discovered.has(event.pubkey)) {
    discovered.set(event.pubkey, { pubkey: event.pubkey, name: null, about: null, tools: [], caps: new Map(), relays: new Set(), lastAnnounced: 0 });
  }
  const worker = discovered.get(event.pubkey);
  worker.relays.add(relayUrl);
  worker.lastAnnounced = Math.max(worker.lastAnnounced, event.created_at);
  for (const tag of event.tags) {
    if (!Array.isArray(tag)) continue;
    if (tag[0] === "name" && tag[1]) worker.name = tag[1];
    if (tag[0] === "about" && tag[1]) worker.about = tag[1];
    if (tag[0] === "cap" && tag[1]) worker.caps.set(tag[1], { range: tag[2], unit: tag[3] });
    if (tag[0] === "agent" && tag[1] === "hench") worker.isHench = true;
  }
  const payload = parseJson(event.content) || {};
  if (payload.name === "Hench" || String(payload.about || "").startsWith("Hench:")) worker.isHench = true;
  if (event.kind === KIND_SERVER_ANNOUNCEMENT) {
    if (payload.name) worker.name = payload.name;
    if (payload.about) worker.about = payload.about;
  }
  if (event.kind === KIND_TOOLS_LIST) {
    for (const tool of Array.isArray(payload.tools) ? payload.tools : []) {
      if (!tool?.name || worker.tools.some((t) => t.name === tool.name)) continue;
      const schema = tool.inputSchema && typeof tool.inputSchema === "object" ? tool.inputSchema : {};
      const properties = schema.properties && typeof schema.properties === "object" ? schema.properties : {};
      worker.tools.push({
        name: tool.name,
        description: typeof tool.description === "string" ? tool.description : "",
        inputSchema: { ...schema, type: "object", properties },
      });
    }
  }
  return true;
}

// ---------- one-shot job ----------

// Resolves { result, text, uris } once the job completes (after payment settles).
// onEvent receives { type, params } for: payment_required, payment_accepted,
// payment_rejected, progress.
export async function callTool({
  relays = DEFAULT_RELAYS,
  workerPubkey,
  tool,
  args,
  onEvent = () => {},
  timeoutMs = 10 * 60 * 1000,
}) {
  const session = new CvmSession(relays, workerPubkey, onEvent);
  try {
    await session.start();
    const response = await session.callTool(tool, args, timeoutMs);
    if (response.error) throw new Error(response.error.message || "tool error");
    const result = response.result ?? {};
    const blocks = Array.isArray(result.content) ? result.content : [];
    const text = blocks.map((b) => b.text || "").filter(Boolean).join("\n");
    const uris = [
      ...blocks.map((b) => b.uri).filter(Boolean),
      ...(result.structuredContent?.url_result ? [result.structuredContent.url_result] : []),
    ];
    if (result.isError) throw new Error(text || "tool error");
    return { result, text, uris };
  } finally {
    session.close();
  }
}

// ---------- CVM session (gift-wrapped JSON-RPC over Nostr) ----------

class CvmSession {
  constructor(relays, serverPubkey, onEvent) {
    this.relays = relays;
    this.serverPubkey = serverPubkey;
    this.onEvent = onEvent;
    this.sk = hexToBytes(getOrCreateSecretKeyHex());
    this.clientPubkey = getPublicKey(this.sk);
    this.sockets = new Map();
    this.seen = new Set();
    this.invocations = new InvocationRouter(); // request inner-event id -> pending call
    this.closed = false;
  }

  async start() {
    const since = Math.floor(Date.now() / 1000) - 90;
    await Promise.allSettled(this.relays.map((url) => this.openRelay(url, since)));
    if (!this.sockets.size) throw new Error("could not connect any relay");
    await this.request({
      jsonrpc: "2.0",
      id: this.invocations.takeId(),
      method: "initialize",
      params: {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "hench-example", version: "0.1.0" },
      },
    });
    this.broadcast({ jsonrpc: "2.0", method: "notifications/initialized" });
  }

  openRelay(relayUrl, since) {
    return new Promise((resolve) => {
      let socket;
      try { socket = new WebSocket(relayUrl); } catch { return resolve(); }
      socket.addEventListener("open", () => {
        if (this.closed) { closeQuietly(socket); return resolve(); }
        socket.send(JSON.stringify([
          "REQ",
          `hench-${Math.random().toString(36).slice(2, 10)}`,
          { kinds: [KIND_WRAP, KIND_WRAP_ALT], "#p": [this.clientPubkey], since },
        ]));
        this.sockets.set(relayUrl, socket);
        resolve();
      });
      socket.addEventListener("message", ({ data }) => this.handleFrame(data));
      socket.addEventListener("error", () => { closeQuietly(socket); resolve(); });
      socket.addEventListener("close", () => resolve());
      setTimeout(() => {
        // Never opened in time — close it so a late open can't subscribe and leak.
        if (!this.sockets.has(relayUrl)) closeQuietly(socket);
        resolve();
      }, 5000);
    });
  }

  handleFrame(raw) {
    const message = parseJson(raw);
    if (!Array.isArray(message) || message[0] !== "EVENT" || !message[2]) return;
    const event = message[2];
    if ((event.kind !== KIND_WRAP && event.kind !== KIND_WRAP_ALT) || this.seen.has(event.id)) return;
    if (!Array.isArray(event.tags) || !event.tags.some((t) => Array.isArray(t) && t[0] === "p" && t[1] === this.clientPubkey)) return;
    this.seen.add(event.id);
    let inner;
    try {
      const key = nip44.v2.utils.getConversationKey(this.sk, event.pubkey);
      inner = JSON.parse(nip44.decrypt(event.content, key));
    } catch { return; }
    // The gift wrap is ephemeral-signed; identity is proven by the inner
    // event's schnorr signature — without this anyone can claim inner.pubkey.
    if (!fromWorker(inner, this.serverPubkey) || !verifyEvent(inner)) return;
    // Route strictly by invocation: the inner event must "e"-tag one of this
    // session's own request event ids. A replayed prior-session invoice or
    // result — even one genuinely signed by this worker — names a request
    // event this session never published, so it is dropped here.
    const routed = this.invocations.route(inner);
    if (!routed) return;
    if (routed.type === "notification") {
      const params = routed.payload.params && typeof routed.payload.params === "object" ? routed.payload.params : {};
      this.onEvent({ type: routed.payload.method.replace("notifications/", ""), params });
    } else {
      routed.entry.resolve(routed.payload);
    }
  }

  // Returns { wrap, innerId }: innerId is the signed request/notification
  // event id the worker "e"-tags its reply to.
  wrap(message) {
    const inner = finalizeEvent(
      { kind: KIND_CTXVM, created_at: Math.floor(Date.now() / 1000), tags: [["p", this.serverPubkey]], content: JSON.stringify(message) },
      this.sk,
    );
    const ephemeral = generateSecretKey();
    const key = nip44.v2.utils.getConversationKey(ephemeral, this.serverPubkey);
    const wrap = finalizeEvent(
      { kind: KIND_WRAP, created_at: Math.floor(Date.now() / 1000), tags: [["p", this.serverPubkey]], content: nip44.encrypt(JSON.stringify(inner), key) },
      ephemeral,
    );
    return { wrap, innerId: inner.id };
  }

  broadcast(message) {
    const { wrap } = this.wrap(message);
    for (const socket of this.sockets.values()) {
      if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(["EVENT", wrap]));
    }
  }

  request(message, timeoutMs = 20000, progressToken) {
    return new Promise((resolve, reject) => {
      const { wrap, innerId } = this.wrap(message);
      // Correlation key = this request's signed inner-event id (what the
      // worker e-tags back), not the JSON-RPC id — replayed events can't
      // mint a matching one.
      this.invocations.register(innerId, message.id, progressToken, resolve);
      for (const socket of this.sockets.values()) {
        if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(["EVENT", wrap]));
      }
      setTimeout(() => {
        if (this.invocations.drop(innerId)) {
          reject(new Error(`no response to ${message.method} — worker offline?`));
        }
      }, timeoutMs);
    });
  }

  callTool(toolName, args, timeoutMs = 10 * 60 * 1000) {
    const id = this.invocations.takeId();
    return this.request({
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: { name: toolName, arguments: args, _meta: { progressToken: id } },
    }, timeoutMs, id);
  }

  close() {
    this.closed = true;
    for (const socket of this.sockets.values()) closeQuietly(socket);
    this.sockets.clear();
  }
}

// ---------- helpers ----------

// Render a lightning: QR for a payment_required event into a <canvas>.
export async function qrInto(canvas, params) {
  const { toCanvas } = await import("./vendor/qrcode.mjs");
  await toCanvas(canvas, `lightning:${cleanBolt11(params?.pay_req)}`, { errorCorrectionLevel: "M", margin: 2, width: 220 });
}

function getOrCreateSecretKeyHex() {
  // Persistent key = stable invocation identity (replays return cached results
  // without a second invoice). Falls back to ephemeral when storage is blocked.
  try {
    let hex = localStorage.getItem(CLIENT_SECRET_KEY);
    if (!hex || !/^[0-9a-f]{64}$/i.test(hex)) {
      hex = bytesToHex(generateSecretKey());
      localStorage.setItem(CLIENT_SECRET_KEY, hex);
    }
    return hex;
  } catch {
    return bytesToHex(generateSecretKey());
  }
}
function parseJson(text) { try { return JSON.parse(text); } catch { return null; } }
function closeQuietly(socket) { try { socket.close(1000, "done"); } catch { /* closed */ } }
