#!/usr/bin/env bash
# Publish a static directory as an NIP-5A nsite.
#
#   ./publish.sh <site-dir> [--name <d>]   root site (kind 15128) or named site (kind 35128)
#   ./publish.sh --snapshot [--name <d>]   manifest snapshot (kind 5128) of the latest site
#
# Blobs go to a Blossom server (BUD-01), the manifest to a Nostr relay.
# Defaults point at local `nak serve --blossom` (see test-local.sh) — nothing
# leaves localhost. For real publishing set: NSITE_SEC, NSITE_RELAY,
# NSITE_BLOSSOM_HOST, and optionally NSITE_TITLE/NSITE_DESCRIPTION/NSITE_SOURCE.
set -euo pipefail

RELAY="${NSITE_RELAY:-ws://localhost:10547}"
BLOSSOM_HOST="${NSITE_BLOSSOM_HOST:-localhost:10547}"
NSITE_HOST="${NSITE_HOST:-localhost:8933}"
# ponytail: fixed TEST key so local republishes keep one npub — always set NSITE_SEC for anything public.
SEC="${NSITE_SEC:-0101010101010101010101010101010101010101010101010101010101010101}"
TITLE="${NSITE_TITLE:-Hench nsite demo}"
DESCRIPTION="${NSITE_DESCRIPTION:-Dispatch paid tasks to Hench phone workers — NIP-5A nsite demo}"
SOURCE="${NSITE_SOURCE:-https://github.com/nostr-protocol/nips/blob/master/5A.md}"

die() { echo "publish: $*" >&2; exit 1; }
for dep in nak python3; do command -v "$dep" >/dev/null || die "missing dependency: $dep"; done

b36() { python3 -c '
import sys
n = int(sys.argv[1], 16); digits = "0123456789abcdefghijklmnopqrstuvwxyz"; s = ""
while n: s = digits[n % 36] + s; n //= 36
print(s.zfill(50))' "$1"; }

json_field() { python3 -c 'import json,sys; print(json.loads(sys.stdin.read())[sys.argv[1]])' "$1"; }

# ---------- snapshot mode: copy path/x tags from the latest manifest, add a/A ----------

if [ "${1:-}" = "--snapshot" ]; then
  NAME=""; shift
  [ "${1:-}" = "--name" ] && NAME="${2:?}"; [ -n "${1:-}" ] && shift $(( $# >= 2 ? 2 : 1 ))
  KIND=15128; DTAG_FILTER=()
  [ -n "$NAME" ] && { KIND=35128; DTAG_FILTER=(--tag "d=$NAME"); }
  PUBKEY="$(nak key public "$SEC" 2>/dev/null)"
  MANIFEST="$(nak req -q -k "$KIND" --author "$PUBKEY" "${DTAG_FILTER[@]}" "$RELAY" 2>/dev/null \
    | grep '^{' | python3 -c 'import json,sys; es=[json.loads(l) for l in sys.stdin if l.strip()]; print(json.dumps(max(es, key=lambda e: e["created_at"])))' || true)"
  [ -n "$MANIFEST" ] || die "no published $KIND manifest found to snapshot"
  SNAPTAGS="$(python3 -c '
import json, sys
e = json.loads(sys.stdin.read())
tags = [t for t in e["tags"] if t[0] == "path"]
x = next(t for t in e["tags"] if t[0] == "x")
d = next((t[1] for t in e["tags"] if t[0] == "d"), "")
addr = "{}:{}{}".format(e["kind"], e["pubkey"], (":" + d) if d else "")
tags += [x, ["a", addr]] + [t for t in e["tags"] if t[0] == "A"][:1] \
     + [t for t in e["tags"] if t[0] in ("title", "description", "source")]
print(json.dumps({"tags": tags}))' <<<"$MANIFEST")"
  EVENT="$(printf '%s' "$SNAPTAGS" | nak event -q -k 5128 --sec "$SEC" -c '' "$RELAY" 2>/dev/null | grep '^{' | tail -1)"
  [ -n "$EVENT" ] || die "snapshot publish failed"
  SID="$(<<<"$EVENT" json_field id)"
  echo "snapshot kind=5128 id=$SID"
  echo "  label:  v$(b36 "$SID")"
  echo "  try:    http://v$(b36 "$SID").$NSITE_HOST/  or  http://$NSITE_HOST/v$(b36 "$SID")/"
  exit 0
fi

# ---------- normal mode: upload blobs + publish manifest ----------

DIR="${1:?usage: publish.sh <site-dir> [--name <d>] | --snapshot [--name <d>]}"; shift || true
NAME=""
if [ "${1:-}" = "--name" ]; then NAME="${2:?}"; fi
[ -n "$NAME" ] && { [[ "$NAME" =~ ^[a-z0-9-]{1,13}$ ]] && [[ "$NAME" != *- ]] || die "name must match ^[a-z0-9-]{1,13}\$ and not end with '-'"; }
DIR="${DIR%/}"
[ -d "$DIR" ] || die "not a directory: $DIR"

mapfile -t FILES < <(cd "$DIR" && find . -type f ! -name '.*' | sed 's|^\./|/|' | LC_ALL=C sort)
[ "${#FILES[@]}" -gt 0 ] || die "no files in $DIR"

TAGS=()
AGG=""
for f in "${FILES[@]}"; do
  hash="$(sha256sum "$DIR$f" | cut -d' ' -f1)"
  TAGS+=(--tag "path=$f;$hash")
  AGG+="$hash $f"$'\n'
  resp="$(nak blossom upload -q -s "$BLOSSOM_HOST" --sec "$SEC" "$DIR$f" 2>/dev/null | grep '^{' | tail -1)"
  [ "$(<<<"$resp" json_field sha256)" = "$hash" ] || die "blossom upload mismatch for $f"
  echo "  uploaded $f → $hash"
done

AGG="$(printf '%s' "$AGG" | LC_ALL=C sort | sha256sum | cut -d' ' -f1)"  # NIP-5A aggregate: sorted "<hash> <path>\n" lines

KIND=15128; DTAG=()
[ -n "$NAME" ] && { KIND=35128; DTAG=(-d "$NAME"); }
EVENT="$(nak event -q -k "$KIND" --sec "$SEC" "${DTAG[@]}" "${TAGS[@]}" \
  --tag "x=$AGG;aggregate" \
  --tag "server=http://$BLOSSOM_HOST" \
  --tag "title=$TITLE" --tag "description=$DESCRIPTION" --tag "source=$SOURCE" \
  -c '' "$RELAY" 2>/dev/null | grep '^{' | tail -1)"
[ -n "$EVENT" ] || die "manifest publish failed"

ID="$(<<<"$EVENT" json_field id)"
PUBKEY="$(<<<"$EVENT" json_field pubkey)"
NPUB="$(nak encode npub "$PUBKEY" 2>/dev/null)"
B36="$(b36 "$PUBKEY")"

echo "published kind=$KIND id=$ID aggregate=$AGG"
if [ -n "$NAME" ]; then
  echo "  named:  $B36$NAME  (d=$NAME)"
  echo "  try:    http://$B36$NAME.$NSITE_HOST/  or  http://$NSITE_HOST/$B36$NAME/"
else
  echo "  root:   $NPUB"
  echo "  try:    http://$NPUB.$NSITE_HOST/  or  http://$NSITE_HOST/$NPUB/"
fi
