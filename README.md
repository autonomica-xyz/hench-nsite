# hench-nsite — static sites on Nostr (NIP-5A)

Publish a static site to Nostr and serve it back, no server of your own
required: `publish.sh` uploads the files as Blossom blobs and writes a
[NIP-5A](https://github.com/nostr-protocol/nips/blob/master/5A.md) manifest
(path → sha256) to a relay; `host.mjs` serves sites from any relay + blossom.
Part of [autonomica.xyz](https://autonomica.xyz).

| File | Role |
|---|---|
| `publish.sh` | Publisher — kind 15128 root / 35128 named / 5128 snapshot manifests with `path` + aggregate `x` tags. Refuses non-local targets without `NSITE_SEC`. |
| `host.mjs` | Host server — resolves and **cryptographically verifies** manifests (NIP-01 id + BIP-340 signature), fetches and sha256-verifies blobs via manifest `server` tags, BUD-03 user servers, or the operator fallback, routes canonical labels, blocks SSRF to private IPs, falls back to `index.html` / `404.html` |
| `*.test.mjs` | Regressions — forged/mismatched manifests, SSRF, label/path attacks, unsafe publishing |
| `demo-site/` | Example site — the [hench-web](https://github.com/autonomica-xyz/hench-web) dispatch console, no build step |
| `test-local.sh` | End-to-end local test — relay, blossom, publisher, host, asserts |

## Try it locally

Nothing leaves localhost. Requires `nak` (≥ v0.18), `node` (≥ 22.19),
`python3`, `curl`:

```bash
npm ci           # once — @noble/curves (manifest signatures) + undici (SSRF-safe fetch)
./test-local.sh
```

Starts `nak serve --blossom` (relay + blossom on :10547) and `host.mjs`
(:8933, loopback), publishes the demo site three ways (root, named `demo1`,
snapshot), and asserts serving for every NIP-5A label form:

If port 8933 is occupied, use `PORT=18933 ./test-local.sh`. The test uses
its own local services and built-in test key, never an inherited publishing key.

- root: `http://localhost:8933/<npub>/` or Host `<npub>.localhost:8933`
- named: `http://localhost:8933/<pubkeyB36><dtag>/` or Host subdomain
- snapshot: `http://localhost:8933/v<snapshotIdB36>/`

Path-prefix routing (`/<label>/<path>`) is a dev convenience — it shares one
origin across tenants, so the host only enables it with an explicit
`NSITE_DEV=1`. A loopback `NSITE_BIND` does not imply it: a reverse proxy
terminates on loopback and forwards public traffic, so the listener address
is not request provenance. Canonical subdomain labels work everywhere via the
Host header (`*.localhost` resolves to loopback in most browsers).
Snapshot/named labels use base36 (50 chars) per the NIP.

To expose the test on your LAN (e.g. a phone running the
[Hench](https://github.com/autonomica-xyz/hench) app worker that announces to
the relay): `LAN=1 ./test-local.sh`.

## Run a local host

`test-local.sh` is a finite check — it stops its services when it exits. To
browse a live local site, run the pieces yourself:

```bash
nak serve --blossom --hostname 127.0.0.1 --port 10547 &  # relay + blossom
NSITE_DEV=1 node host.mjs &                            # host, dev path-prefix on
./publish.sh demo-site                                  # prints the site URL
```

## Publish a site

```bash
export NSITE_SEC=$(nak key generate)             # your key — required for real relays
export NSITE_RELAY=wss://relay.damus.io          # real relay(s)
export NSITE_BLOSSOM_HOST=blossom.primal.net     # real blossom server (https assumed)
export NSITE_HOST=your-nsite-host.example.com    # cosmetic: printed URLs

./publish.sh my-site/                # root site (kind 15128)
./publish.sh my-site/ --name blog    # named site (kind 35128)
./publish.sh --snapshot              # snapshot of the latest (kind 5128)
```

`NSITE_TITLE`, `NSITE_DESCRIPTION`, `NSITE_SOURCE` set the manifest tags.
The built-in test key only works against loopback targets — the publisher
refuses to ship to real relays or blossom servers without `NSITE_SEC`.
Symlinks are rejected; hidden files and directories are excluded. Filenames
with control characters, `;`, `..`, or a trailing `/` are rejected before upload.

## Run a host

```bash
NSITE_RELAY=wss://relay.damus.io NSITE_BLOSSOM=https://blossom.primal.net \
  PORT=8933 node host.mjs
```

The host is safe to point at untrusted relays:

- manifests are verified (id recompute + schnorr signature) and must exactly
  match the requested pubkey/`d`/id — forged manifests get 404;
- blob bodies are sha256-checked against the manifest;
- `server` tags, BUD-03 (kind 10063) user servers, and redirect targets are
  fetched only if they are `http(s)` URLs resolving to public IPs (checked at
  connect time) — LAN hosts, link-local/metadata (`169.254.x`), and
  `file:`/`gopher:` can't be reached. The operator's `NSITE_BLOSSOM` fallback
  is trusted separately and may be private;
- responses are capped at `NSITE_MAX_BLOB` (32 MiB default), concurrent blob
  downloads at `NSITE_MAX_INFLIGHT_BLOBS` (16), requests at 2 KiB URLs, relay
  messages at 1 MiB, every fetch at 5 s;
- `Content-Type` is derived from the publisher-signed manifest path, with a
  non-scriptable Blossom fallback — an intentional deviation from the NIP's
  "forward the Blossom Content-Type": an untrusted blob server could
  otherwise relabel `.txt` bytes as `text/html` and run script in the site
  origin;
- only snapshot sites are cached immutably — root/named manifests are
  replaceable, so they revalidate (`max-age=60`);
- tenants are isolated by origin: only canonical subdomain labels route,
  regardless of bind address. Path-prefix routing requires `NSITE_DEV=1`.

Env: `NSITE_RELAY` (ws/wss, required semantics), `NSITE_BLOSSOM` (fallback
blob server), `PORT`, `NSITE_BIND`, `NSITE_DEV`, `NSITE_ALLOW_PRIVATE`,
`NSITE_MAX_BLOB`, `NSITE_MAX_INFLIGHT_BLOBS`.

## Limitations

- Blobs are buffered in memory up to `NSITE_MAX_BLOB` — fine for sites,
  not a CDN.

## Release readiness

See the [cross-project release-readiness report](https://github.com/autonomica-xyz/hench/blob/main/docs/release-readiness.html)
for observed verification and remaining production checks. Download the HTML
file to view or print it in a browser.

## License

MIT (see [LICENSE](LICENSE)).
