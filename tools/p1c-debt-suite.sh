#!/bin/bash
# P1c debt suite: nested SLO, ranged SLO segment fetch, manifest-aware
# copy (SLO+DLO), ACL/info-cache cross-proxy consistency smoke.
# Usage: p1c-debt-suite.sh <endpoint> <user> <key> [label]
set -u
EP=${1:?endpoint}; USR=${2:?user}; KEY=${3:?key}; LABEL=${4:-p1c}
CO="-s -m60 --http1.1"
PASS=0; FAIL=0; FAILED=()

ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  FAIL  %s  -- %s\n' "$1" "$2"; }
ck()   { [ "$2" = "$3" ] && ok "$1" || bad "$1" "want=$2 got=$3 ${4:-}"; }
ckin() { if printf '%s' "$3" | grep -qiF "$2"; then ok "$1"; else bad "$1" "missing '$2'"; fi; }
code() { curl $CO -o /dev/null -w '%{http_code}' "$@"; }
body() { curl $CO "$@"; }

echo "==================================================================="
echo "P1c DEBT SUITE  label=$LABEL  endpoint=$EP  $(date -u +%FT%TZ)"
echo "==================================================================="

AUTH=$(curl $CO -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$EP/auth/v1.0")
TOK=$(printf '%s' "$AUTH" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
SURL=$(printf '%s' "$AUTH" | awk 'tolower($1)=="x-storage-url:"{print $2}' | tr -d '\r')
if [ -z "$TOK" ]; then echo "FATAL: no token"; exit 3; fi
PATHV1=$(printf '%s' "$SURL" | sed -E 's#https?://[^/]+##')
BASE="$EP$PATHV1"
H=(-H "X-Auth-Token: $TOK")
ok "auth: token acquired"

C="p1c-$RANDOM"
cleanup() {
  for o in $(curl $CO "${H[@]}" "$BASE/$C?format=json" 2>/dev/null \
    | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'); do
    curl $CO -X DELETE "${H[@]}" "$BASE/$C/$o" >/dev/null 2>&1
  done
  curl $CO -X DELETE "${H[@]}" "$BASE/$C" >/dev/null 2>&1
}
trap cleanup EXIT

ck "container: PUT 201" 201 "$(code -X PUT "${H[@]}" "$BASE/$C")"

# ---- nested SLO ---------------------------------------------------------
ck "nested: put leaf a 201" 201 "$(code -X PUT "${H[@]}" -H "Content-Type: text/plain" -d 'aa' "$BASE/$C/leaf-a")"
ck "nested: put leaf b 201" 201 "$(code -X PUT "${H[@]}" -H "Content-Type: text/plain" -d 'bb' "$BASE/$C/leaf-b")"
ck "nested: put leaf c 201" 201 "$(code -X PUT "${H[@]}" -H "Content-Type: text/plain" -d 'cc' "$BASE/$C/leaf-c")"
EA=$(curl $CO -D - -o /dev/null "${H[@]}" -X HEAD "$BASE/$C/leaf-a" | awk 'tolower($1)=="etag:"{print $2}' | tr -d '\r"')
EB=$(curl $CO -D - -o /dev/null "${H[@]}" -X HEAD "$BASE/$C/leaf-b" | awk 'tolower($1)=="etag:"{print $2}' | tr -d '\r"')
EC_ET=$(curl $CO -D - -o /dev/null "${H[@]}" -X HEAD "$BASE/$C/leaf-c" | awk 'tolower($1)=="etag:"{print $2}' | tr -d '\r"')
INNER=$(printf '[{"path":"/%s/leaf-a","etag":"%s","size_bytes":2},{"path":"/%s/leaf-b","etag":"%s","size_bytes":2}]' "$C" "$EA" "$C" "$EB")
ck "nested: inner SLO PUT 201" 201 "$(code -X PUT "${H[@]}" -H "Content-Type: application/json" \
  --data-binary "$INNER" "$BASE/$C/inner?multipart-manifest=put")"
IET=$(curl $CO -D - -o /dev/null "${H[@]}" -X HEAD "$BASE/$C/inner" | awk 'tolower($1)=="etag:"{print $2}' | tr -d '\r"')
ICL=$(curl $CO -D - -o /dev/null "${H[@]}" -X HEAD "$BASE/$C/inner" | awk 'tolower($1)=="content-length:"{print $2}' | tr -d '\r')
ck "nested: inner HEAD Content-Length is aggregate" "4" "$ICL"
OUTER=$(printf '[{"path":"/%s/inner","etag":"%s","size_bytes":4},{"path":"/%s/leaf-c","etag":"%s","size_bytes":2}]' \
  "$C" "$IET" "$C" "$EC_ET")
OUT_CODE=$(code -X PUT "${H[@]}" -H "Content-Type: text/plain" \
  --data-binary "$OUTER" "$BASE/$C/outer?multipart-manifest=put")
if [ "$OUT_CODE" != "201" ]; then
  # null etag is valid for sub_slo when HEAD etag was the manifest md5
  OUTER=$(printf '[{"path":"/%s/inner","etag":null,"size_bytes":4},{"path":"/%s/leaf-c","etag":"%s","size_bytes":2}]' \
    "$C" "$C" "$EC_ET")
  OUT_CODE=$(code -X PUT "${H[@]}" -H "Content-Type: text/plain" \
    --data-binary "$OUTER" "$BASE/$C/outer?multipart-manifest=put")
fi
ck "nested: outer SLO PUT 201" "201" "$OUT_CODE"
NEST_BODY=$(body "${H[@]}" "$BASE/$C/outer")
ck "nested: reassembled body" "aabbcc" "$NEST_BODY"
CL=$(curl $CO -D - -o /dev/null "${H[@]}" "$BASE/$C/outer" | awk 'tolower($1)=="content-length:"{print $2}' | tr -d '\r')
ck "nested: Content-Length header" "6" "$CL"

# ---- ranged SLO (per-segment) -------------------------------------------
RANGE_BODY=$(body "${H[@]}" -H "Range: bytes=3-4" "$BASE/$C/outer")
ck "range: nested bytes=3-4" "bc" "$RANGE_BODY"
RC=$(code "${H[@]}" -H "Range: bytes=3-4" "$BASE/$C/outer")
ck "range: status 206" "206" "$RC"

# ---- manifest-aware copy (SLO) ------------------------------------------
ck "copy-slo: multipart-manifest=get 201" 201 "$(code -X PUT "${H[@]}" \
  -H "X-Copy-From: /$C/outer" "$BASE/$C/outer-copy?multipart-manifest=get")"
COPY_BODY=$(body "${H[@]}" "$BASE/$C/outer-copy")
ck "copy-slo: reassembled equals source" "aabbcc" "$COPY_BODY"
RAW=$(body "${H[@]}" "$BASE/$C/outer-copy?multipart-manifest=get&format=raw")
ckin "copy-slo: raw manifest has path" '"path"' "$RAW"
ckin "copy-slo: raw manifest has etag" '"etag"' "$RAW"

# ---- manifest-aware copy (DLO) ------------------------------------------
ck "dlo: put seg0 201" 201 "$(code -X PUT "${H[@]}" -d 'xx' "$BASE/$C/dsegs/0")"
ck "dlo: put seg1 201" 201 "$(code -X PUT "${H[@]}" -d 'yy' "$BASE/$C/dsegs/1")"
ck "dlo: put manifest 201" 201 "$(code -X PUT "${H[@]}" -H "X-Object-Manifest: $C/dsegs/" \
  -H "Content-Type: text/plain" -d '' "$BASE/$C/dlo-man")"
DLO_BODY=$(body "${H[@]}" "$BASE/$C/dlo-man")
ck "dlo: reassembled" "xxyy" "$DLO_BODY"
ck "copy-dlo: multipart-manifest=get 201" 201 "$(code -X PUT "${H[@]}" \
  -H "X-Copy-From: /$C/dlo-man" "$BASE/$C/dlo-copy?multipart-manifest=get")"
DLO_COPY=$(body "${H[@]}" "$BASE/$C/dlo-copy")
ck "copy-dlo: reassembled equals source" "xxyy" "$DLO_COPY"
DH=$(curl $CO -D - -o /dev/null "${H[@]}" -X HEAD "$BASE/$C/dlo-copy")
ckin "copy-dlo: X-Object-Manifest present" "x-object-manifest:" "$DH"

# ---- ACL cross-proxy consistency (VIP) ----------------------------------
ck "acl: put private obj 201" 201 "$(code -X PUT "${H[@]}" -d 'pub' "$BASE/$C/pub.txt")"
ck "acl: set .r:* 204" 204 "$(code -X POST "${H[@]}" -H "X-Container-Read: .r:*" "$BASE/$C")"
sleep 0.2
ANON=0
for i in 1 2 3 4 5 6 7 8; do
  AC=$(code "$BASE/$C/pub.txt")
  if [ "$AC" = "200" ]; then ANON=$((ANON+1)); fi
done
if [ "$ANON" -ge 6 ]; then ok "acl: anonymous GET via VIP ($ANON/8)"; else bad "acl: anonymous GET via VIP" "$ANON/8 got 200"; fi
# Swift remove header (empty value is unreliable across curl versions)
ck "acl: revoke read 204" 204 "$(code -X POST "${H[@]}" -H "X-Remove-Container-Read: x" "$BASE/$C")"
sleep 0.2
DENY=0
for i in 1 2 3 4 5 6; do
  AC=$(code "$BASE/$C/pub.txt")
  if [ "$AC" = "401" ] || [ "$AC" = "403" ]; then DENY=$((DENY+1)); fi
done
if [ "$DENY" -ge 4 ]; then ok "acl: revoke visible via VIP ($DENY/6)"; else bad "acl: revoke visible via VIP" "$DENY/6 denied"; fi

echo "==================================================================="
echo "RESULT  label=$LABEL  PASS=$PASS  FAIL=$FAIL"
if [ "$FAIL" -gt 0 ]; then
  echo "FAILED:"; printf '  - %s\n' "${FAILED[@]}"
  exit 1
fi
exit 0
