#!/usr/bin/env bash
# PUT → HEAD → GET → DELETE against a live Swift endpoint.
# Env: SWIFT_AUTH_URL (default http://127.0.0.1:8080/auth/v1.0)
#      SWIFT_USER (default test:tester)
#      SWIFT_KEY  (default testing)
set -euo pipefail

AUTH_URL="${SWIFT_AUTH_URL:-http://127.0.0.1:8080/auth/v1.0}"
USER="${SWIFT_USER:-test:tester}"
KEY="${SWIFT_KEY:-testing}"
CONT="canary-smoke"
OBJ="obj-$(date +%s)-$$"

HDR=$(mktemp)
trap 'rm -f "$HDR"' EXIT

curl -sS -D "$HDR" -o /dev/null \
  -H "X-Auth-User: $USER" -H "X-Auth-Key: $KEY" "$AUTH_URL"
TOK=$(awk 'tolower($1)=="x-auth-token:"{print $2}' "$HDR" | tr -d '\r')
STOR=$(awk 'tolower($1)=="x-storage-url:"{print $2}' "$HDR" | tr -d '\r')
if [[ -z "$TOK" || -z "$STOR" ]]; then
  echo "auth failed against $AUTH_URL" >&2
  exit 2
fi

# ensure container exists
curl -sS -o /dev/null -X PUT -H "X-Auth-Token: $TOK" "$STOR/$CONT" || true
body="canary-$(date -u +%Y%m%dT%H%M%SZ)"
t0=$(python3 -c "import time;print(int(time.time()*1000))")
curl -sS -o /dev/null -w "PUT %{http_code} %{time_total}\n" \
  -X PUT -H "X-Auth-Token: $TOK" -H "Content-Type: text/plain" \
  --data-binary "$body" "$STOR/$CONT/$OBJ"
t1=$(python3 -c "import time;print(int(time.time()*1000))")
curl -sS -o /dev/null -w "HEAD %{http_code} %{time_total}\n" \
  -I -H "X-Auth-Token: $TOK" "$STOR/$CONT/$OBJ"
t2=$(python3 -c "import time;print(int(time.time()*1000))")
got=$(curl -sS -w "\nGET %{http_code} %{time_total}\n" \
  -H "X-Auth-Token: $TOK" "$STOR/$CONT/$OBJ")
echo "$got" | tail -1
body_got=$(echo "$got" | sed '$d')
if [ "$body_got" = "$body" ]; then echo "GET body: OK"; else echo "GET body: MISMATCH"; fi
curl -sS -o /dev/null -w "DELETE %{http_code} %{time_total}\n" \
  -X DELETE -H "X-Auth-Token: $TOK" "$STOR/$CONT/$OBJ"
# best-effort container cleanup
curl -sS -o /dev/null -X DELETE -H "X-Auth-Token: $TOK" "$STOR/$CONT" || true

echo "elapsed_ms_put_head_get=$((t2 - t0))"
