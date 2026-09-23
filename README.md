# hench-nsite — static sites on Nostr (NIP-5A)

Publish a static site to Nostr and serve it back, no server of your own
required: `publish.sh` uploads the files as Blossom blobs and writes a
[NIP-5A](https://github.com/nostr-protocol/nips/blob/master/5A.md) manifest
(path → sha256) to a relay; `host.mjs` serves sites from any relay + blossom.

| File | Role |
|---|---|
| `publish.sh` | Publisher — kind 15128 root / 35128 named / 5128 snapshot manifests with `path` + aggregate `x` tags |
| `host.mjs` | Host server — resolves manifests, fetches and sha256-verifies blobs, routes labels, falls back to `index.html` / `404.html` |
| `demo-site/` | Example site — the [hench-web](https://github.com/nostr-net/hench-web) dispatch console, no build step |
| `test-local.sh` | End-to-end local test — relay, blossom, publisher, host, asserts |

## Try it locally

Nothing leaves localhost. Requires `nak` (≥ v0.18), `node` (≥ 22),
`python3`, `curl`:

```bash
./test-local.sh
```

Starts `nak serve --blossom` (relay + blossom on :10547) and `host.mjs`
(:8933), publishes the demo site three ways (root, named `demo1`, snapshot),
and asserts serving for every NIP-5A label form:

- root: `http://localhost:8933/<npub>/` or Host `<npub>.localhost:8933`
- named: `http://localhost:8933/<pubkeyB36><dtag>/` or Host subdomain
- snapshot: `http://localhost:8933/v<snapshotIdB36>/`

Path-prefix routing is a local convenience; canonical subdomain labels work
via the Host header (`*.localhost` resolves to loopback in most browsers).
Snapshot/named labels use base36 (50 chars) per the NIP.

Both the relay and host bind `0.0.0.0`, so LAN devices can join — e.g. a
phone running the [Hench](https://github.com/nostr-net/hench) app with
its relay set to `ws://<lan-ip>:10547` is discoverable from the demo page.

## Publish a site

```bash
export NSITE_SEC=$(nak key generate)             # your key — never the built-in test key
export NSITE_RELAY=wss://relay.damus.io          # real relay(s)
export NSITE_BLOSSOM_HOST=blossom.primal.net     # real blossom server
export NSITE_HOST=your-nsite-host.example.com    # cosmetic: printed URLs

./publish.sh my-site/                # root site (kind 15128)
./publish.sh my-site/ --name blog    # named site (kind 35128)
./publish.sh --snapshot              # snapshot of the latest (kind 5128)
```

`NSITE_TITLE`, `NSITE_DESCRIPTION`, `NSITE_SOURCE` set the manifest tags.

## Run a host

```bash
NSITE_RELAY=wss://relay.damus.io NSITE_BLOSSOM=http://blossom.primal.net PORT=8933 node host.mjs
```

## Limitations

- `host.mjs` trusts manifests as the relay delivered them (no signature
  verification) and skips BUD-03 (kind 10063) user-server lookup — manifest
  `server` tags plus `NSITE_BLOSSOM` cover it. Add both before pointing
  `host.mjs` at untrusted relays.
