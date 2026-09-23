// hench.js — drop-in browser client for Hench phone workers (ContextVM / MCP over Nostr, CEP-8 payments).
// No build step: ES module, dependencies from esm.sh. Extracted from hench-web/app.js.
//
// Usage:
//   import { discoverWorkers, callTool, qrInto } from "./hench.js";
//   const workers = await discoverWorkers();            // [{ pubkey, name, about, tools, caps, relays }]
//   const { text, uris } = await callTool({
//     workerPubkey, tool: "web_fetch", args: { url },
//     onEvent: (e) => { if (e.type === "payment_required") qrInto(canvas, e.params); },
//   });

import { finalizeEvent, generateSecretKey, getPublicKey } from "https://esm.sh/nostr-tools@2.25.1/pure?bundle";
import { bytesToHex, hexToBytes } from "https://esm.sh/@noble/hashes@2.4.0/utils?bundle";
import * as nip44 from "https://esm.sh/nostr-tools@2.25.1/nip44?bundle";

export const DEFAULT_RELAYS = [
  "wss://relay.damus.io",
  "wss://nos.lol",
  "wss://relay.primal.net",
  "wss://relay.nostr.net",
];

const KIND_CTXVM = 25910;
const KIND_WRAP = 21059;
const KIND_WRAP_ALT = 1059;
const KIND_SERVER_ANNOUNCEMENT = 11316;
const KIND_TOOLS_LIST = 11317;
const MCP_PROTOCOL_VERSION = "2025-06-18";
const CLIENT_SECRET_KEY = "hench-client-secret-key"; // shared with hench-web: same key = same identity, cached replays
const STALE_AFTER_MS = 12 * 60 * 60 * 1000;

// ---------- discovery ----------

export async function discoverWorkers({
  relays = DEFAULT_RELAYS,
  waitMs = 8000,
  henchOnly = true,
} = {}) {
  const discovered = new Map();
  const seen = new Set();
  await Promise.allSettled(
    relays.map(
      (url) =>
        new Promise((resolve) => {
          let socket;
          try { socket = new WebSocket(url); } catch { return resolve(); }
          const done = () => { closeQuietly(socket); resolve(); };
          socket.addEventListener("open", () => {
            socket.send(JSON.stringify(["REQ", `hench-disc-${Math.random().toString(36).slice(2, 10)}`, { kinds: [KIND_SERVER_ANNOUNCEMENT, KIND_TOOLS_LIST], limit: 200 }])); // randomUUID needs a secure context; LAN http isn't one
            setTimeout(done, waitMs);
          });
          socket.addEventListener("message", ({ data }) => {
            const message = parseJson(data);
            if (!Array.isArray(message) || message[0] !== "EVENT" || !message[2]) return;
            const event = message[2];
            if (seen.has(event.id)) return;
            seen.add(event.id);
            ingestAnnouncement(discovered, event, url);
          });
          socket.addEventListener("error", done);
          socket.addEventListener("close", resolve);
          setTimeout(resolve, waitMs + 1000);
        }),
    ),
  );
  const now = Date.now() / 1000;
  return [...discovered.values()]
    .filter((w) => w.tools.length > 0 && now - w.lastAnnounced < STALE_AFTER_MS / 1000)
    .filter((w) => !henchOnly || w.isHench)
    .sort((a, b) => (a.name || "").localeCompare(b.name || ""));
}

function ingestAnnouncement(discovered, event, relayUrl) {
  if (!discovered.has(event.pubkey)) {
    discovered.set(event.pubkey, { pubkey: event.pubkey, name: null, about: null, tools: [], caps: new Map(), relays: new Set(), lastAnnounced: 0 });
  }
  const worker = discovered.get(event.pubkey);
  worker.relays.add(relayUrl);
  worker.lastAnnounced = Math.max(worker.lastAnnounced, event.created_at);
  for (const tag of event.tags) {
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
    for (const tool of payload.tools || []) {
      if (tool?.name && !worker.tools.some((t) => t.name === tool.name)) {
        worker.tools.push({ name: tool.name, description: tool.description || "", inputSchema: tool.inputSchema || { type: "object", properties: {} } });
      }
    }
  }
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
    this.pending = new Map(); // jsonrpc id -> resolve/reject
    this.nextId = 1;
  }

  async start() {
    const since = Math.floor(Date.now() / 1000) - 90;
    await Promise.allSettled(this.relays.map((url) => this.openRelay(url, since)));
    if (!this.sockets.size) throw new Error("could not connect any relay");
    await this.request({
      jsonrpc: "2.0",
      id: this.takeId(),
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
        socket.send(JSON.stringify([
          "REQ",
          `hench-${Math.random().toString(36).slice(2, 10)}`,
          { kinds: [KIND_WRAP, KIND_WRAP_ALT], "#p": [this.clientPubkey], since },
        ]));
        this.sockets.set(relayUrl, socket);
        resolve();
      });
      socket.addEventListener("message", ({ data }) => this.handleFrame(data));
      socket.addEventListener("error", () => resolve());
      socket.addEventListener("close", () => resolve());
      setTimeout(resolve, 5000);
    });
  }

  handleFrame(raw) {
    const message = parseJson(raw);
    if (!Array.isArray(message) || message[0] !== "EVENT" || !message[2]) return;
    const event = message[2];
    if ((event.kind !== KIND_WRAP && event.kind !== KIND_WRAP_ALT) || this.seen.has(event.id)) return;
    if (!event.tags.some((t) => t[0] === "p" && t[1] === this.clientPubkey)) return;
    this.seen.add(event.id);
    let inner;
    try {
      const key = nip44.v2.utils.getConversationKey(this.sk, event.pubkey);
      inner = JSON.parse(nip44.decrypt(event.content, key));
    } catch { return; }
    if (inner.pubkey !== this.serverPubkey || inner.kind !== KIND_CTXVM) return;
    const payload = parseJson(inner.content);
    if (!payload) return;
    if (payload.method) {
      const params = payload.params || {};
      this.onEvent({ type: payload.method.replace("notifications/", ""), params });
    } else if (payload.id !== undefined) {
      const entry = this.pending.get(jsonIdKey(payload.id));
      if (entry) {
        this.pending.delete(jsonIdKey(payload.id));
        entry(payload);
      }
    }
  }

  wrap(message) {
    const inner = finalizeEvent(
      { kind: KIND_CTXVM, created_at: Math.floor(Date.now() / 1000), tags: [["p", this.serverPubkey]], content: JSON.stringify(message) },
      this.sk,
    );
    const ephemeral = generateSecretKey();
    const key = nip44.v2.utils.getConversationKey(ephemeral, this.serverPubkey);
    return finalizeEvent(
      { kind: KIND_WRAP, created_at: Math.floor(Date.now() / 1000), tags: [["p", this.serverPubkey]], content: nip44.encrypt(JSON.stringify(inner), key) },
      ephemeral,
    );
  }

  broadcast(message) {
    const wrap = this.wrap(message);
    for (const socket of this.sockets.values()) {
      if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(["EVENT", wrap]));
    }
  }

  takeId() { return this.nextId++; }

  request(message, timeoutMs = 20000) {
    return new Promise((resolve, reject) => {
      const key = jsonIdKey(message.id);
      this.pending.set(key, resolve);
      this.broadcast(message);
      setTimeout(() => {
        if (this.pending.has(key)) {
          this.pending.delete(key);
          reject(new Error(`no response to ${message.method} — worker offline?`));
        }
      }, timeoutMs);
    });
  }

  callTool(toolName, args, timeoutMs = 10 * 60 * 1000) {
    return this.request({
      jsonrpc: "2.0",
      id: this.takeId(),
      method: "tools/call",
      params: { name: toolName, arguments: args, _meta: { progressToken: this.nextId } },
    }, timeoutMs);
  }

  close() {
    for (const socket of this.sockets.values()) closeQuietly(socket);
    this.sockets.clear();
  }
}

// ---------- helpers ----------

// Render a lightning: QR for a payment_required event into a <canvas>.
export async function qrInto(canvas, params) {
  const { toCanvas } = await import("https://esm.sh/qrcode@1.5.4?bundle");
  await toCanvas(canvas, `lightning:${params.pay_req || ""}`, { errorCorrectionLevel: "M", margin: 2, width: 220 });
}

function getOrCreateSecretKeyHex() {
  let hex = localStorage.getItem(CLIENT_SECRET_KEY);
  if (!hex || !/^[0-9a-f]{64}$/.test(hex)) {
    hex = bytesToHex(generateSecretKey());
    localStorage.setItem(CLIENT_SECRET_KEY, hex);
  }
  return hex;
}
function parseJson(text) { try { return JSON.parse(text); } catch { return null; } }
function jsonIdKey(id) { return typeof id === "object" ? JSON.stringify(id) : String(id); }
function closeQuietly(socket) { try { socket.close(1000, "done"); } catch { /* closed */ } }
