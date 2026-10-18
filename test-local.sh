#!/usr/bin/env bash
# End-to-end local NIP-5A test — nothing leaves localhost by default:
#   relay + blossom  ← nak serve --blossom
#   publisher        ← ./publish.sh demo-site
#   host server      ← ./host.mjs
# Asserts root, named, snapshot, index-fallback, 404, and dev gating behavior.
# LAN=1 binds both to 0.0.0.0 (e.g. a phone worker announcing to the relay).
set -euo pipefail
cd "$(dirname "$0")"

RELAY_PORT=10547
HOST_PORT="${PORT:-8933}"
BIND="${NSITE_TEST_BIND:-127.0.0.1}"
[ "${LAN:-0}" = 1 ] && BIND=0.0.0.0
export PORT="$HOST_PORT"
export NSITE_RELAY="ws://127.0.0.1:$RELAY_PORT"
export NSITE_BLOSSOM="http://127.0.0.1:$RELAY_PORT"
export NSITE_BLOSSOM_HOST="127.0.0.1:$RELAY_PORT"
export NSITE_HOST="localhost:$HOST_PORT"
unset NSITE_SEC

TMP_DIR="$(mktemp -d)"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait "${PIDS[@]}" 2>/dev/null || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "== starting local relay + blossom (nak serve) and nsite host (bind $BIND)"
nak serve --blossom --hostname "$BIND" --port "$RELAY_PORT" >"$TMP_DIR/nak.log" 2>&1 & PIDS+=($!)
# test host: dev mode on (path-prefix routing + private blob hosts on this loopback rig)
NSITE_BIND="$BIND" NSITE_DEV=1 node host.mjs >"$TMP_DIR/host.log" 2>&1 & PIDS+=($!)
ready() {
  kill -0 "${PIDS[0]}" 2>/dev/null && kill -0 "${PIDS[1]}" 2>/dev/null \
    && grep -q '^nsite host on ' "$TMP_DIR/host.log" \
    && curl -s -o /dev/null "http://localhost:$HOST_PORT/" \
    && (exec 3<>/dev/tcp/localhost/$RELAY_PORT) 2>/dev/null
}
for i in $(seq 1 40); do if ready; then break; fi; sleep 0.3; done
ready || { echo "FAIL  services did not start"; cat "$TMP_DIR/nak.log" "$TMP_DIR/host.log" >&2 || true; exit 1; }

echo "== unit + hostile-input regressions"
node --test *.test.mjs

echo "== publisher rejects real targets without NSITE_SEC"
if NSITE_RELAY=wss://relay.damus.io ./publish.sh demo-site >/dev/null 2>&1; then
  echo "FAIL  publish to real relay with test key was allowed"; exit 1
else echo "PASS  publish to real relay refused without NSITE_SEC"; fi

echo "== publishing demo-site (root)"
./publish.sh demo-site | tee "$TMP_DIR/root.out"
ROOT_LABEL="$(grep -oE 'http://localhost:[0-9]+/[a-z0-9]+/' "$TMP_DIR/root.out" | head -1 | sed -E 's|http://localhost:[0-9]+/([a-z0-9]+)/|\1|')"

echo "== publishing demo-site (named)"
./publish.sh demo-site --name demo1 | tee "$TMP_DIR/named.out"
NAMED_LABEL="$(grep -oE '/[a-z0-9]{51,63}/' "$TMP_DIR/named.out" | head -1 | tr -d /)"

echo "== publishing snapshot of root"
./publish.sh --snapshot | tee "$TMP_DIR/snap.out"
SNAP_LABEL="$(grep -oE '/v[a-z0-9]{50}/' "$TMP_DIR/snap.out" | head -1 | tr -d /)"

fail=0
check() { # check <desc> <expected-file> <curl-args…> (url last)
  local desc="$1" want="$2"; shift 2
  if curl -sf "$@" | cmp -s - "$want"; then echo "PASS  $desc"; else echo "FAIL  $desc"; fail=1; fi
}
status() { # status <want> <desc> <curl-args…> (url last)
  local want="$1" desc="$2" got; shift 2
  got="$(curl -s -o /dev/null -w '%{http_code}' "$@")"
  if [ "$got" = "$want" ]; then echo "PASS  $desc"; else echo "FAIL  $desc: got $got want $want"; fail=1; fi
}

echo "== asserts"
[ -n "$ROOT_LABEL" ] && [ -n "$NAMED_LABEL" ] && [ -n "$SNAP_LABEL" ] || { echo "FAIL  labels not parsed from publish output"; exit 1; }

# root site, path-prefix routing (dev mode), index.html fallback on "/"
check "root / serves index.html"        demo-site/index.html "http://localhost:$HOST_PORT/$ROOT_LABEL/"
check "root /index.html direct"         demo-site/index.html "http://localhost:$HOST_PORT/$ROOT_LABEL/index.html"
check "root /hench.js"                  demo-site/hench.js   "http://localhost:$HOST_PORT/$ROOT_LABEL/hench.js"
# root site, canonical npub subdomain label via Host header
check "root npub-label Host /hench.js"  demo-site/hench.js   -H "Host: $ROOT_LABEL.localhost:$HOST_PORT" "http://localhost:$HOST_PORT/hench.js"
# named site (kind 35128, b36+dtag label)
check "named / serves index.html"       demo-site/index.html "http://localhost:$HOST_PORT/$NAMED_LABEL/"
check "named label Host /hench.js"      demo-site/hench.js   -H "Host: $NAMED_LABEL.localhost:$HOST_PORT" "http://localhost:$HOST_PORT/hench.js"
# snapshot (kind 5128, v+b36 label)
check "snapshot / serves index.html"    demo-site/index.html "http://localhost:$HOST_PORT/$SNAP_LABEL/"
check "snapshot /hench.js"              demo-site/hench.js   "http://localhost:$HOST_PORT/$SNAP_LABEL/hench.js"
# not found: no /404.html in demo-site → plain 404
status 404 "missing path is 404"        "http://localhost:$HOST_PORT/$ROOT_LABEL/nope.html"
status 404 "garbage label is 404"       "http://localhost:$HOST_PORT/zzz/"
status 404 "trailing-dash d label 404"  "http://localhost:$HOST_PORT/${NAMED_LABEL%demo1}demo1-/"
status 400 "traversal path is 400" --path-as-is "http://localhost:$HOST_PORT/$ROOT_LABEL/%2e%2e/index.html"
status 405 "POST is 405" -X POST        "http://localhost:$HOST_PORT/$ROOT_LABEL/"

echo
if [ "$fail" = 0 ]; then
  echo "ALL PASS — test services stop on exit; to browse a live site run the"
  echo "manual steps under 'Run a local host' in README.md"
else echo "SOME CHECKS FAILED"; exit 1; fi
