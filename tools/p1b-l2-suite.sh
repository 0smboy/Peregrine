#!/bin/bash
# P1b L2 suite: formpost (+ negatives), staticweb, quotas, symlink,
# versioned_writes (stack DELETE restore), /info accuracy.
# Usage: p1b-l2-suite.sh <endpoint> <user> <key> [label]
set -u
EP=${1:?endpoint}; USR=${2:?user}; KEY=${3:?key}; LABEL=${4:-p1b}
CO="-s -m30 --http1.1"
PASS=0; FAIL=0; FAILED=()

ok()   { PASS=$((PASS+1)); printf '  PASS  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  FAIL  %s  -- %s\n' "$1" "$2"; }
ck()   { [ "$2" = "$3" ] && ok "$1" || bad "$1" "want=$2 got=$3 ${4:-}"; }
ckin() { if printf '%s' "$3" | grep -qiF "$2"; then ok "$1"; else bad "$1" "missing '$2'"; fi; }
cknotin() { if printf '%s' "$3" | grep -qiF "$2"; then bad "$1" "unexpected '$2'"; else ok "$1"; fi; }
ckjson() {
  local name=$1 key=$2 want=$3 body=$4
  if printf '%s' "$body" | grep -qE "\"$key\"[[:space:]]*:[[:space:]]*$want"; then
    ok "$name"
  else
    bad "$name" "missing \"$key\": $want in $(printf '%s' "$body" | head -c 200)"
  fi
}
code() { curl $CO -o /dev/null -w '%{http_code}' "$@"; }
hdr()  { curl $CO -D - -o /dev/null "$@"; }

echo "==================================================================="
echo "P1b L2 SUITE  label=$LABEL  endpoint=$EP  $(date -u +%FT%TZ)"
echo "==================================================================="

AUTH=$(curl $CO -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$EP/auth/v1.0")
TOK=$(printf '%s' "$AUTH" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
SURL=$(printf '%s' "$AUTH" | awk 'tolower($1)=="x-storage-url:"{print $2}' | tr -d '\r')
if [ -z "$TOK" ]; then echo "FATAL: no token"; exit 3; fi
PATHV1=$(printf '%s' "$SURL" | sed -E 's#https?://[^/]+##')
BASE="$EP$PATHV1"
H=(-H "X-Auth-Token: $TOK")
ok "auth: token acquired"

# ---- /info accuracy -----------------------------------------------------
INFO=$(curl $CO "$EP/info")
ckin "info: formpost present" '"formpost"' "$INFO"
ckin "info: staticweb present" '"staticweb"' "$INFO"
ckin "info: container_quotas present" '"container_quotas"' "$INFO"
ckin "info: account_quotas present" '"account_quotas"' "$INFO"
ckin "info: symlink present" '"symlink"' "$INFO"
ckin "info: versioned_writes present" '"versioned_writes"' "$INFO"
cknotin "info: bulk_upload absent" '"bulk_upload"' "$INFO"
# P1a still present
ckin "info: bulk_delete still present" '"bulk_delete"' "$INFO"
ckin "info: tempurl still present" '"tempurl"' "$INFO"

C="p1b-$RANDOM"
CQ="p1b-q-$RANDOM"
CS="p1b-s-$RANDOM"
CV="p1b-v-$RANDOM"
V="p1b-vers-$RANDOM"
cleanup() {
  for cont in "$C" "$CQ" "$CS" "$CV" "$V"; do
    for o in $(curl $CO "${H[@]}" "$BASE/$cont?format=json" 2>/dev/null \
      | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p'); do
      curl $CO -X DELETE "${H[@]}" "$BASE/$cont/$o" >/dev/null 2>&1
    done
    curl $CO -X DELETE "${H[@]}" "$BASE/$cont" >/dev/null 2>&1
  done
}
trap cleanup EXIT

ck "container: PUT 201" 201 "$(code -X PUT "${H[@]}" "$BASE/$C")"
ck "quota container: PUT 201" 201 "$(code -X PUT "${H[@]}" "$BASE/$CQ")"
ck "symlink container: PUT 201" 201 "$(code -X PUT "${H[@]}" "$BASE/$CS")"
ck "vw data container: PUT 201" 201 "$(code -X PUT "${H[@]}" "$BASE/$CV")"

# ---- formpost -----------------------------------------------------------
ck "formpost: set account key 204" 204 "$(code -X POST "${H[@]}" \
  -H "X-Account-Meta-Temp-URL-Key: p1b-form-key" "$BASE")"
FP_PATH="$PATHV1/$C/"
EXPIRES=$(( $(date +%s) + 3600 ))
# HMAC body: path\nredirect\max_file_size\max_file_count\nexpires
MSG=$(printf '%s\n%s\n%s\n%s\n%s' "$FP_PATH" "" "1024" "2" "$EXPIRES")
SIG=$(printf '%s' "$MSG" | openssl dgst -sha256 -hmac 'p1b-form-key' | awk '{print $NF}')
BOUND="BOUND$RANDOM"
BODY=$(printf -- '--%s\r\nContent-Disposition: form-data; name="redirect"\r\n\r\n\r\n--%s\r\nContent-Disposition: form-data; name="max_file_size"\r\n\r\n1024\r\n--%s\r\nContent-Disposition: form-data; name="max_file_count"\r\n\r\n2\r\n--%s\r\nContent-Disposition: form-data; name="expires"\r\n\r\n%s\r\n--%s\r\nContent-Disposition: form-data; name="signature"\r\n\r\n%s\r\n--%s\r\nContent-Disposition: form-data; name="file1"; filename="hello.txt"\r\nContent-Type: text/plain\r\n\r\nhi-p1b\r\n--%s--\r\n' \
  "$BOUND" "$BOUND" "$BOUND" "$BOUND" "$EXPIRES" "$BOUND" "$SIG" "$BOUND" "$BOUND")
fp_code=$(code -X POST -H "Content-Type: multipart/form-data; boundary=$BOUND" \
  --data-binary "$BODY" "$EP$FP_PATH")
[ "$fp_code" = "201" ] || { sleep 1; fp_code=$(code -X POST -H "Content-Type: multipart/form-data; boundary=$BOUND" --data-binary "$BODY" "$EP$FP_PATH"); }
ck "formpost: valid upload 201" 201 "$fp_code"
GOT=$(curl $CO "${H[@]}" "$BASE/$C/hello.txt"); ck "formpost: uploaded body" "hi-p1b" "$GOT"

# tampered signature
BADBODY=$(printf -- '--%s\r\nContent-Disposition: form-data; name="redirect"\r\n\r\n\r\n--%s\r\nContent-Disposition: form-data; name="max_file_size"\r\n\r\n1024\r\n--%s\r\nContent-Disposition: form-data; name="max_file_count"\r\n\r\n2\r\n--%s\r\nContent-Disposition: form-data; name="expires"\r\n\r\n%s\r\n--%s\r\nContent-Disposition: form-data; name="signature"\r\n\r\ndeadbeef\r\n--%s\r\nContent-Disposition: form-data; name="file1"; filename="x.txt"\r\nContent-Type: text/plain\r\n\r\nx\r\n--%s--\r\n' \
  "$BOUND" "$BOUND" "$BOUND" "$BOUND" "$EXPIRES" "$BOUND" "$BOUND" "$BOUND")
ck "formpost: tampered sig -> 401" 401 "$(code -X POST -H "Content-Type: multipart/form-data; boundary=$BOUND" --data-binary "$BADBODY" "$EP$FP_PATH")"

# expired
MSG1=$(printf '%s\n%s\n%s\n%s\n%s' "$FP_PATH" "" "1024" "1" "1")
SIG1=$(printf '%s' "$MSG1" | openssl dgst -sha256 -hmac 'p1b-form-key' | awk '{print $NF}')
EXPBODY=$(printf -- '--%s\r\nContent-Disposition: form-data; name="redirect"\r\n\r\n\r\n--%s\r\nContent-Disposition: form-data; name="max_file_size"\r\n\r\n1024\r\n--%s\r\nContent-Disposition: form-data; name="max_file_count"\r\n\r\n1\r\n--%s\r\nContent-Disposition: form-data; name="expires"\r\n\r\n1\r\n--%s\r\nContent-Disposition: form-data; name="signature"\r\n\r\n%s\r\n--%s\r\nContent-Disposition: form-data; name="file1"; filename="y.txt"\r\nContent-Type: text/plain\r\n\r\ny\r\n--%s--\r\n' \
  "$BOUND" "$BOUND" "$BOUND" "$BOUND" "$BOUND" "$SIG1" "$BOUND" "$BOUND")
ck "formpost: expired -> 401" 401 "$(code -X POST -H "Content-Type: multipart/form-data; boundary=$BOUND" --data-binary "$EXPBODY" "$EP$FP_PATH")"

# ---- staticweb ----------------------------------------------------------
ck "staticweb: put index 201" 201 "$(code -X PUT "${H[@]}" --data-binary "INDEX" "$BASE/$C/idx.html")"
ck "staticweb: enable web-index 204" 204 "$(code -X POST "${H[@]}" \
  -H "X-Container-Meta-Web-Index: idx.html" \
  -H "X-Container-Meta-Web-Listings: true" \
  -H "X-Container-Read: .r:*,.rlistings" "$BASE/$C")"
# unauth GET of container should serve index
SW=$(curl $CO "$EP$PATHV1/$C/")
ck "staticweb: unauth index body" "INDEX" "$SW"

# ---- container quotas ---------------------------------------------------
ck "quota: set bytes=5 204" 204 "$(code -X POST "${H[@]}" \
  -H "X-Container-Meta-Quota-Bytes: 5" "$BASE/$CQ")"
ck "quota: oversize PUT -> 413" 413 "$(code -X PUT "${H[@]}" --data-binary "too-big!" "$BASE/$CQ/over")"
ck "quota: small PUT ok 201" 201 "$(code -X PUT "${H[@]}" --data-binary "ok" "$BASE/$CQ/small")"

# ---- symlink ------------------------------------------------------------
ck "symlink: put target 201" 201 "$(code -X PUT "${H[@]}" --data-binary "TGT" "$BASE/$CS/target")"
ck "symlink: put link 201" 201 "$(code -X PUT "${H[@]}" -H "X-Symlink-Target: $CS/target" \
  -H "Content-Length: 0" "$BASE/$CS/link")"
LGET=$(curl $CO "${H[@]}" "$BASE/$CS/link")
ck "symlink: follow GET body" "TGT" "$LGET"
ckin "symlink: Content-Location" "Content-Location" "$(hdr "${H[@]}" "$BASE/$CS/link")"

# ---- versioned_writes (stack) -------------------------------------------
ck "vw: versions container 201" 201 "$(code -X PUT "${H[@]}" "$BASE/$V")"
ck "vw: enable versions-location 204" 204 "$(code -X POST "${H[@]}" \
  -H "X-Versions-Location: $V" "$BASE/$CV")"
ck "vw: PUT v1 201" 201 "$(code -X PUT "${H[@]}" --data-binary "one" "$BASE/$CV/v1")"
ck "vw: PUT v1 overwrite 201" 201 "$(code -X PUT "${H[@]}" --data-binary "two" "$BASE/$CV/v1")"
V1=$(curl $CO "${H[@]}" "$BASE/$CV/v1"); ck "vw: current is two" "two" "$V1"
# DELETE should restore previous (stack pop → body "one")
DCODE=$(code -X DELETE "${H[@]}" "$BASE/$CV/v1")
case "$DCODE" in
  2??) ok "vw: DELETE status $DCODE" ;;
  *) bad "vw: DELETE status" "want=2xx got=$DCODE" ;;
esac
AFTER=$(curl $CO "${H[@]}" "$BASE/$CV/v1")
ck "vw: restored previous body" "one" "$AFTER"

echo
echo "-------------------------------------------------------------------"
echo "RESULT  label=$LABEL  PASS=$PASS  FAIL=$FAIL"
[ $FAIL -gt 0 ] && printf '  failed: %s\n' "${FAILED[*]}"
echo "-------------------------------------------------------------------"
exit 0
