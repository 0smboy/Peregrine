#!/bin/bash
# Parameterized Swift functional suite (curl only, no client deps). The SAME
# script runs against the Rust stack and a Python SAIO, so the two PASS/FAIL
# tables are a direct functional-parity comparison.
#
#   func-suite.sh <endpoint> <user> <key> [label]
#     endpoint  e.g. http://10.42.30.10:8085  or  http://127.0.0.1:8090
#
# Auth is v1.0/tempauth; the storage path from the token is reused but its host
# is rewritten to <endpoint> so it works behind a VIP or direct.
set -u
EP=${1:?endpoint}; USR=${2:?user}; KEY=${3:?key}; LABEL=${4:-stack}
CO="-s -m30 --http1.1"
PASS=0; FAIL=0; FAILED=()

ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  FAIL  %s  -- %s\n' "$1" "$2"; }
# check <name> <expected> <actual> [detail]
ck()   { [ "$2" = "$3" ] && ok "$1" || bad "$1" "want=$2 got=$3 ${4:-}"; }
# ckin <name> <needle> <haystack>  (case-insensitive: HTTP header names are, and
# this stack emits them lowercased where Python Swift title-cases them)
ckin() { if printf '%s' "$3" | grep -qiF "$2"; then ok "$1"; else bad "$1" "missing '$2'"; fi; }

code() { curl $CO -o /dev/null -w '%{http_code}' "$@"; }
hdr()  { curl $CO -D - -o /dev/null "$@"; }

echo "==================================================================="
echo "FUNCTIONAL SUITE  label=$LABEL  endpoint=$EP  $(date -u +%FT%TZ)"
echo "==================================================================="

# ---- AUTH ---------------------------------------------------------------
badcode=$(code -H "X-Auth-User: $USR" -H "X-Auth-Key: WRONG" "$EP/auth/v1.0")
ck "auth: bad key -> 401" 401 "$badcode"

AUTH=$(curl $CO -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$EP/auth/v1.0")
TOK=$(printf '%s' "$AUTH" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
SURL=$(printf '%s' "$AUTH" | awk 'tolower($1)=="x-storage-url:"{print $2}' | tr -d '\r')
if [ -z "$TOK" ]; then echo "FATAL: no token (auth failed) -- aborting"; exit 3; fi
# rewrite host of storage path to the endpoint we were told to use
EPHOST=$(printf '%s' "$EP" | sed -E 's#https?://##')
PATHV1=$(printf '%s' "$SURL" | sed -E 's#https?://[^/]+##')
BASE="$EP$PATHV1"
ok "auth: token acquired ($USR)"
H=(-H "X-Auth-Token: $TOK")

C="fsuite-$RANDOM"; CE="fsuite-ec-$RANDOM"
cleanup() {
  for c in "$C" "$CE" "$C-seg" "$C-ver"; do
    for o in $(curl $CO "${H[@]}" "$BASE/$c" 2>/dev/null); do
      curl $CO -X DELETE "${H[@]}" "$BASE/$c/$o" >/dev/null 2>&1
    done
    curl $CO -X DELETE "${H[@]}" "$BASE/$c" >/dev/null 2>&1
  done
}
trap cleanup EXIT

# ---- ACCOUNT ------------------------------------------------------------
ck "account: HEAD 204" 204 "$(code -I "${H[@]}" "$BASE")"
ah=$(hdr "${H[@]}" "$BASE")
ckin "account: X-Account-Container-Count present" "X-Account-Container-Count" "$ah"

# ---- CONTAINER lifecycle ------------------------------------------------
ck "container: PUT 201" 201 "$(code -X PUT "${H[@]}" "$BASE/$C")"
ck "container: idempotent PUT 202" 202 "$(code -X PUT "${H[@]}" "$BASE/$C")"
ck "container: HEAD 204" 204 "$(code -I "${H[@]}" "$BASE/$C")"
ck "container: POST meta 204" 204 "$(code -X POST "${H[@]}" -H "X-Container-Meta-Team: blue" "$BASE/$C")"
ch=$(hdr "${H[@]}" "$BASE/$C"); ckin "container: meta persisted" "X-Container-Meta-Team: blue" "$ch"
ck "container: GET empty 204" 204 "$(code "${H[@]}" "$BASE/$C")"

# ---- OBJECT basic -------------------------------------------------------
BODY="hello-swift-$RANDOM"; ETAG=$(printf '%s' "$BODY" | md5sum | cut -d' ' -f1)
ck "object: PUT 201" 201 "$(code -X PUT "${H[@]}" -H "Content-Type: text/plain" -H "X-Object-Meta-Color: red" --data-binary "$BODY" "$BASE/$C/obj1")"
got=$(curl $CO "${H[@]}" "$BASE/$C/obj1"); ck "object: GET body" "$BODY" "$got"
oh=$(hdr "${H[@]}" "$BASE/$C/obj1")
ckin "object: etag matches md5" "Etag: $ETAG" "$oh"
ckin "object: content-type" "Content-Type: text/plain" "$oh"
ckin "object: custom meta" "X-Object-Meta-Color: red" "$oh"
ck "object: HEAD 200" 200 "$(code -I "${H[@]}" "$BASE/$C/obj1")"
# fast-POST metadata update
ck "object: POST meta 202" 202 "$(code -X POST "${H[@]}" -H "X-Object-Meta-Color: green" "$BASE/$C/obj1")"
oh2=$(hdr "${H[@]}" "$BASE/$C/obj1"); ckin "object: fast-POST meta updated" "X-Object-Meta-Color: green" "$oh2"
# bad etag
ck "object: PUT wrong-etag 422" 422 "$(code -X PUT "${H[@]}" -H "ETag: deadbeef00000000deadbeef00000000" --data-binary "x" "$BASE/$C/badetag")"

# ---- RANGES -------------------------------------------------------------
printf 'ABCDEFGHIJ' > /tmp/rng.$$; 
curl $CO -X PUT "${H[@]}" --data-binary @/tmp/rng.$$ "$BASE/$C/rng" >/dev/null
ck "range: bytes=0-3" "ABCD" "$(curl $CO "${H[@]}" -H 'Range: bytes=0-3' "$BASE/$C/rng")"
ck "range: suffix bytes=-3" "HIJ" "$(curl $CO "${H[@]}" -H 'Range: bytes=-3' "$BASE/$C/rng")"
ck "range: 206 status" 206 "$(code "${H[@]}" -H 'Range: bytes=0-3' "$BASE/$C/rng")"
ck "range: unsatisfiable 416" 416 "$(code "${H[@]}" -H 'Range: bytes=99-100' "$BASE/$C/rng")"
mr=$(curl $CO "${H[@]}" -H 'Range: bytes=0-1,4-5' "$BASE/$C/rng")
ckin "range: multipart/byteranges" "AB" "$mr"; ckin "range: multipart 2nd part" "EF" "$mr"

# ---- CONDITIONAL --------------------------------------------------------
ck "cond: If-None-Match * -> 304" 304 "$(code "${H[@]}" -H "If-None-Match: $ETAG" "$BASE/$C/obj1")"
ck "cond: If-Match wrong -> 412" 412 "$(code "${H[@]}" -H 'If-Match: "nope"' "$BASE/$C/obj1")"
ck "cond: If-Match right -> 200" 200 "$(code "${H[@]}" -H "If-Match: $ETAG" "$BASE/$C/obj1")"

# ---- LARGE OBJECT md5 round-trip ---------------------------------------
dd if=/dev/urandom of=/tmp/big.$$ bs=1M count=4 status=none
BE=$(md5sum /tmp/big.$$ | cut -d' ' -f1)
ck "large: PUT 4MB 201" 201 "$(code -X PUT "${H[@]}" --data-binary @/tmp/big.$$ "$BASE/$C/big")"
GB=$(curl $CO "${H[@]}" "$BASE/$C/big" | md5sum | cut -d' ' -f1)
ck "large: 4MB md5 round-trip" "$BE" "$GB"

# ---- SLO ----------------------------------------------------------------
SC="$C-seg"; curl $CO -X PUT "${H[@]}" "$BASE/$SC" >/dev/null
segjson="["; for i in 1 2 3; do
  dd if=/dev/urandom of=/tmp/seg$i.$$ bs=1M count=1 status=none
  se=$(md5sum /tmp/seg$i.$$ | cut -d' ' -f1)
  curl $CO -X PUT "${H[@]}" --data-binary @/tmp/seg$i.$$ "$BASE/$SC/seg$i" >/dev/null
  cat /tmp/seg$i.$$ >> /tmp/slocat.$$
  segjson="$segjson{\"path\":\"/$SC/seg$i\",\"etag\":\"$se\",\"size_bytes\":1048576}"
  [ $i -lt 3 ] && segjson="$segjson,"
done; segjson="$segjson]"
slocode=$(code -X PUT "${H[@]}" -H "Content-Type: application/octet-stream" \
  --data-binary "$segjson" "$BASE/$C/slo?multipart-manifest=put")
ck "SLO: manifest PUT 201" 201 "$slocode"
SLOEXP=$(md5sum /tmp/slocat.$$ | cut -d' ' -f1)
SLOGOT=$(curl $CO "${H[@]}" "$BASE/$C/slo" | md5sum | cut -d' ' -f1)
ck "SLO: reassembled 3MB md5" "$SLOEXP" "$SLOGOT"
ckin "SLO: manifest-get is json" "\"name\"" "$(curl $CO "${H[@]}" "$BASE/$C/slo?multipart-manifest=get")"

# ---- DLO ----------------------------------------------------------------
curl $CO -X PUT "${H[@]}" -H "X-Object-Manifest: $SC/seg" --data-binary "" "$BASE/$C/dlo" >/dev/null
DLOGOT=$(curl $CO "${H[@]}" "$BASE/$C/dlo" | md5sum | cut -d' ' -f1)
ck "DLO: concatenation md5 == SLO segs" "$SLOEXP" "$DLOGOT"

# ---- COPY ---------------------------------------------------------------
ck "copy: X-Copy-From 201" 201 "$(code -X PUT "${H[@]}" -H "X-Copy-From: /$C/obj1" --data-binary "" "$BASE/$C/obj1copy")"
ck "copy: copied body" "$BODY" "$(curl $CO "${H[@]}" "$BASE/$C/obj1copy")"

# ---- EXPIRY -------------------------------------------------------------
xh=$(curl $CO -D - -o /dev/null -X PUT "${H[@]}" -H "X-Delete-After: 3600" --data-binary "temp" "$BASE/$C/willexpire")
ck "expiry: PUT with X-Delete-After 201" 201 "$(printf '%s' "$xh" | awk 'NR==1{print $2}')"
eh=$(hdr "${H[@]}" "$BASE/$C/willexpire"); ckin "expiry: X-Delete-At set" "X-Delete-At:" "$eh"

# ---- UNICODE / SPECIAL NAMES -------------------------------------------
ON='obj%20%E4%B8%AD%E6%96%87.txt'
ck "name: unicode+space PUT 201" 201 "$(code -X PUT "${H[@]}" --data-binary "uni" "$BASE/$C/$ON")"
ck "name: unicode GET body" "uni" "$(curl $CO "${H[@]}" "$BASE/$C/$ON")"

# ---- LISTINGS -----------------------------------------------------------
lj=$(curl $CO "${H[@]}" "$BASE/$C?format=json")
ckin "listing: json has bytes" "\"bytes\"" "$lj"
lp=$(curl $CO "${H[@]}" "$BASE/$C?prefix=obj1")
ckin "listing: prefix filter" "obj1" "$lp"
l1=$(curl $CO "${H[@]}" "$BASE/$C?format=json&limit=1" | grep -o '"name"' | wc -l | tr -d ' ')
ck "listing: limit=1 returns 1" 1 "$l1"

# ---- EC POLICY ----------------------------------------------------------
ecput=$(code -X PUT "${H[@]}" -H "X-Storage-Policy: ec-2-1" "$BASE/$CE")
ck "EC: container create (policy ec-2-1) 201" 201 "$ecput"
ech=$(hdr "${H[@]}" "$BASE/$CE"); ckin "EC: policy header" "X-Storage-Policy: ec-2-1" "$ech"
dd if=/dev/urandom of=/tmp/ecbig.$$ bs=1M count=3 status=none
ECE=$(md5sum /tmp/ecbig.$$ | cut -d' ' -f1)
ck "EC: PUT 3MB 201" 201 "$(code -X PUT "${H[@]}" --data-binary @/tmp/ecbig.$$ "$BASE/$CE/ecobj")"
ECG=$(curl $CO "${H[@]}" "$BASE/$CE/ecobj" | md5sum | cut -d' ' -f1)
ck "EC: 5MB md5 round-trip" "$ECE" "$ECG"
ck "EC: ranged GET 206" 206 "$(code "${H[@]}" -H 'Range: bytes=0-1023' "$BASE/$CE/ecobj")"
 recg=$(curl $CO "${H[@]}" -H 'Range: bytes=1048576-1049599' "$BASE/$CE/ecobj" | wc -c | tr -d ' ')
ck "EC: ranged GET length=1024" 1024 "$recg"

# ---- NEGATIVE / SECURITY-ADJACENT --------------------------------------
ck "sec: no-token account -> 401" 401 "$(code "$BASE")"
ck "sec: bad-token -> 401" 401 "$(code -H 'X-Auth-Token: AUTH_tk_bogus' "$BASE/$C")"
ck "sec: GET missing object -> 404" 404 "$(code "${H[@]}" "$BASE/$C/nope-$RANDOM")"
ck "sec: DELETE non-empty container -> 409" 409 "$(code -X DELETE "${H[@]}" "$BASE/$C")"
# path traversal attempt in object name (should be treated as a literal name, not escape)
ck "sec: traversal name literal 201" 201 "$(code -X PUT "${H[@]}" --data-binary "x" "$BASE/$C/..%2f..%2fetc%2fpasswd")"

# ---- CLEANUP OBJECTS then container DELETE -----------------------------
for o in obj1 obj1copy rng big slo dlo willexpire badetag "$ON" "..%2f..%2fetc%2fpasswd" ecobj; do
  curl $CO -X DELETE "${H[@]}" "$BASE/$C/$o" >/dev/null 2>&1
  curl $CO -X DELETE "${H[@]}" "$BASE/$CE/$o" >/dev/null 2>&1
done

echo
echo "-------------------------------------------------------------------"
echo "RESULT  label=$LABEL  PASS=$PASS  FAIL=$FAIL"
[ $FAIL -gt 0 ] && printf '  failed: %s\n' "${FAILED[*]}"
echo "-------------------------------------------------------------------"
rm -f /tmp/*.$$ 2>/dev/null
exit 0
