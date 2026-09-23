#!/usr/bin/env bash
# End-to-end local NIP-5A test — nothing leaves localhost:
#   relay + blossom  ← nak serve --blossom
#   publisher        ← ./publish.sh demo-site
#   host server      ← ./host.mjs
# Asserts root, named, snapshot, index-fallback, and 404 behavior.
set -euo pipefail
cd "$(dirname "$0")"

RELAY_PORT=10547
HOST_PORT=8933

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

echo "== starting local relay + blossom (nak serve) and nsite host"
# --hostname 0.0.0.0: LAN-exposed so a phone Hench worker can announce to it
nak serve --blossom --hostname 0.0.0.0 --port "$RELAY_PORT" >/tmp/nsite-nak.log 2>&1 & PIDS+=($!)
node host.mjs >/tmp/nsite-host.log 2>&1 & PIDS+=($!)
for i in $(seq 1 30); do
  curl -s -o /dev/null "http://localhost:$HOST_PORT/ping" \
    && (exec 3<>/dev/tcp/localhost/$RELAY_PORT) 2>/dev/null && break
  sleep 0.3
done

echo "== publishing demo-site (root)"
./publish.sh demo-site | tee /tmp/nsite-root.out
ROOT_LABEL="$(grep -oE 'http://localhost:[0-9]+/[a-z0-9]+/' /tmp/nsite-root.out | head -1 | sed -E 's|http://localhost:[0-9]+/([a-z0-9]+)/|\1|')"

echo "== publishing demo-site (named)"
./publish.sh demo-site --name demo1 | tee /tmp/nsite-named.out
NAMED_LABEL="$(grep -oE '/[a-z0-9]{51,63}/' /tmp/nsite-named.out | head -1 | tr -d /)"

echo "== publishing snapshot of root"
./publish.sh --snapshot | tee /tmp/nsite-snap.out
SNAP_LABEL="$(grep -oE '/v[a-z0-9]{50}/' /tmp/nsite-snap.out | head -1 | tr -d /)"

fail=0
check() { # check <desc> <expected-file> <curl-args…> (url last)
  local desc="$1" want="$2"; shift 2
  if curl -sf "$@" | cmp -s - "$want"; then echo "PASS  $desc"; else echo "FAIL  $desc"; fail=1; fi
}
status() { # status <want> <desc> <url>
  local want="$1" desc="$2" url="$3" got
  got="$(curl -s -o /dev/null -w '%{http_code}' "$url")"
  if [ "$got" = "$want" ]; then echo "PASS  $desc"; else echo "FAIL  $desc ($url): got $got want $want"; fail=1; fi
}

echo "== asserts"
[ -n "$ROOT_LABEL" ] && [ -n "$NAMED_LABEL" ] && [ -n "$SNAP_LABEL" ] || { echo "FAIL  labels not parsed from publish output"; exit 1; }

# root site, path-prefix routing, index.html fallback on "/"
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

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
if [ "$fail" = 0 ]; then
  echo "ALL PASS — open http://localhost:$HOST_PORT/$ROOT_LABEL/ in a browser"
  [ -n "$LAN_IP" ] && echo "LAN:    http://$LAN_IP:$HOST_PORT/$ROOT_LABEL/  (phone: add ws://$LAN_IP:$RELAY_PORT to Hench app relays)"
else echo "SOME CHECKS FAILED"; exit 1; fi
