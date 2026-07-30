#!/bin/bash
# Verify two security-relevant behaviors against a stack, vs the Python oracle:
#   ACL revocation (does removing/​restricting read ACL actually deny anon?)
#   metadata value length limit (Swift MAX_META_VALUE_LENGTH=256 -> 400)
# Usage: acl-meta-verify.sh <label> <endpoint>
set -u
L=$1; EP=$2
CO="-s -m10"
A=$(curl $CO -D - -o /dev/null -H "X-Auth-User: test:tester" -H "X-Auth-Key: azure-swift-2026.bench" "$EP/auth/v1.0")
TOK=$(printf '%s' "$A" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
P=$(printf '%s' "$A" | awk 'tolower($1)=="x-storage-url:"{print $2}' | tr -d '\r' | sed -E 's#https?://[^/]+##')
B="$EP$P"; H=(-H "X-Auth-Token: $TOK")
c="aclm-$RANDOM"
echo "--- $L ($EP) ---"

curl $CO "${H[@]}" -X PUT -H "X-Container-Read: .r:*,.rlistings" "$B/$c" >/dev/null
printf hi | curl $CO "${H[@]}" -X PUT --data-binary @- "$B/$c/o" >/dev/null
echo "  anon GET while public:        $(curl $CO -o /dev/null -w '%{http_code}' "$B/$c/o")"

# revoke by overwriting with a restrictive (non-anon) ACL
curl $CO "${H[@]}" -X POST -H "X-Container-Read: AUTH_test:noone" "$B/$c" >/dev/null
echo "  anon GET after restrict ACL:  $(curl $CO -o /dev/null -w '%{http_code}' "$B/$c/o")"

# revoke by force-sending an EMPTY header (curl 'Header;' forces empty value)
curl $CO "${H[@]}" -X POST -H "X-Container-Read;" "$B/$c" >/dev/null
echo "  anon GET after empty ACL:     $(curl $CO -o /dev/null -w '%{http_code}' "$B/$c/o")"

# metadata value length
v300=$(head -c 300 </dev/zero | tr '\0' a)
v200=$(head -c 200 </dev/zero | tr '\0' a)
echo "  obj meta value 300 chars:     $(curl $CO -o /dev/null -w '%{http_code}' "${H[@]}" -X POST -H "X-Object-Meta-Big: $v300" "$B/$c/o")"
echo "  obj meta value 200 chars:     $(curl $CO -o /dev/null -w '%{http_code}' "${H[@]}" -X POST -H "X-Object-Meta-Ok: $v200" "$B/$c/o")"

curl $CO "${H[@]}" -X DELETE "$B/$c/o" >/dev/null; curl $CO "${H[@]}" -X DELETE "$B/$c" >/dev/null
