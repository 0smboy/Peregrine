#!/bin/bash
set -u
LB=http://10.42.30.11:8085
A=$(curl -s -m10 -D - -o /dev/null -H "X-Auth-User: test:tester" -H "X-Auth-Key: azure-swift-2026.bench" "$LB/auth/v1.0")
TOK=$(printf '%s' "$A" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
echo "token=${TOK:0:16}..."
B="$LB/v1/AUTH_test"
echo "container PUT: $(curl -s -m10 -o /dev/null -w '%{http_code}' -X PUT -H "X-Auth-Token: $TOK" "$B/hadbg")"
echo "object PUT:    $(printf hi | curl -s -m10 -o /dev/null -w '%{http_code}' -X PUT -H "X-Auth-Token: $TOK" --data-binary @- "$B/hadbg/o")"
echo "object GET:    $(curl -s -m10 -H "X-Auth-Token: $TOK" "$B/hadbg/o")"
echo "--- full response headers of a PUT (to see any error) ---"
printf hi | curl -s -m10 -i -X PUT -H "X-Auth-Token: $TOK" --data-binary @- "$B/hadbg/o2" | head -6
curl -s -X DELETE -H "X-Auth-Token: $TOK" "$B/hadbg/o" >/dev/null
curl -s -X DELETE -H "X-Auth-Token: $TOK" "$B/hadbg/o2" >/dev/null
curl -s -X DELETE -H "X-Auth-Token: $TOK" "$B/hadbg" >/dev/null
