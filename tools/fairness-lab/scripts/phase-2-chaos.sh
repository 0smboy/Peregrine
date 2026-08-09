#!/usr/bin/env bash
# Phase-2 chaos v2: create container first; inject on non-VIP backend.
set -euo pipefail
source "$(dirname "$0")/../../../swift-rust/tools/lib/lab-auth.sh"
peregrine_load_lab_auth
OUT="${OUT:-/tmp/phase2-20260804/chaos}"
LB="${LB:-http://10.0.0.10:8085}"
USR="${USR:-$ST_USER}"
KEY="${KEY:-$ST_KEY}"
mkdir -p "$OUT"
ssh_node() { ssh -o BatchMode=yes -o StrictHostKeyChecking=no "root@$1" "${@:2}"; }

token() {
  curl -sS -m 10 -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$LB/auth/v1.0" \
    | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r'
}

mkctn() {
  local tok=$1 ctn=$2
  curl -sS -m 15 -o /dev/null -w '%{http_code}' -X PUT -H "X-Auth-Token: $tok" "$LB/v1/AUTH_test/$ctn"
}

run_puts() {
  local tok=$1 ctn=$2 n=${3:-20}
  local ok=0 fail=0 code
  for i in $(seq 1 "$n"); do
    code=$(curl -sS -m 12 -o /dev/null -w '%{http_code}' -H "X-Auth-Token: $tok" \
      -X PUT --data-binary "chaos-$i-$(date +%s)" "$LB/v1/AUTH_test/${ctn}/o$i" || echo 000)
    [[ "$code" =~ ^20 ]] && ok=$((ok+1)) || fail=$((fail+1))
  done
  echo "$ok $fail"
}

echo "VIP holder check" | tee "$OUT/vip-holder.txt"
for ip in 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4; do
  if ssh_node "$ip" "ip -4 addr show | grep -q '10.0.0.10/'"; then
    echo "VIP_ON=$ip" | tee -a "$OUT/vip-holder.txt"
  fi
done

echo "=== proxy-loss swift3 ===" | tee "$OUT/proxy-loss.log"
TOK=$(token)
CTN="p2-pl-$(date +%s)"
echo "mkctn=$(mkctn "$TOK" "$CTN")" | tee -a "$OUT/proxy-loss.log"
ssh_node 10.0.0.3 'systemctl stop swift-proxy'
sleep 2
read -r POK PFAIL <<<"$(run_puts "$TOK" "$CTN" 20)"
ssh_node 10.0.0.3 'systemctl start swift-proxy'
sleep 3
P_ACTIVE=$(ssh_node 10.0.0.3 'systemctl is-active swift-proxy')
TOK2=$(token)
CTN2="p2-plr-$(date +%s)"
echo "mkctn_rec=$(mkctn "$TOK2" "$CTN2")" | tee -a "$OUT/proxy-loss.log"
read -r POK2 PFAIL2 <<<"$(run_puts "$TOK2" "$CTN2" 10)"
echo "during ok=$POK fail=$PFAIL; after active=$P_ACTIVE ok=$POK2 fail=$PFAIL2" | tee -a "$OUT/proxy-loss.log"
python3 -c "import json; print(json.dumps({'scenario':'proxy-loss','target':'swift3','during_ok':$POK,'during_fail':$PFAIL,'recovered_active':'$P_ACTIVE','after_ok':$POK2,'after_fail':$PFAIL2,'pass':($POK>=15 and $PFAIL2==0 and '$P_ACTIVE'=='active')}, indent=2))" | tee "$OUT/proxy-loss.json"

echo "=== object-loss swift4 ===" | tee "$OUT/object-loss.log"
TOK=$(token)
CTN="p2-ol-$(date +%s)"
echo "mkctn=$(mkctn "$TOK" "$CTN")" | tee -a "$OUT/object-loss.log"
ssh_node 10.0.0.4 'systemctl stop swift-object'
sleep 2
read -r OOK OFAIL <<<"$(run_puts "$TOK" "$CTN" 20)"
ssh_node 10.0.0.4 'systemctl start swift-object'
sleep 3
O_ACTIVE=$(ssh_node 10.0.0.4 'systemctl is-active swift-object')
TOK2=$(token)
CTN2="p2-olr-$(date +%s)"
echo "mkctn_rec=$(mkctn "$TOK2" "$CTN2")" | tee -a "$OUT/object-loss.log"
read -r OOK2 OFAIL2 <<<"$(run_puts "$TOK2" "$CTN2" 10)"
echo "during ok=$OOK fail=$OFAIL; after active=$O_ACTIVE ok=$OOK2 fail=$OFAIL2" | tee -a "$OUT/object-loss.log"
python3 -c "import json; print(json.dumps({'scenario':'object-loss','target':'swift4','during_ok':$OOK,'during_fail':$OFAIL,'recovered_active':'$O_ACTIVE','after_ok':$OOK2,'after_fail':$OFAIL2,'pass':($OOK>=15 and $OFAIL2==0 and '$O_ACTIVE'=='active')}, indent=2))" | tee "$OUT/object-loss.json"

echo "=== residual ===" | tee "$OUT/residual.log"
for ip in 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4; do
  ssh_node "$ip" 'echo $(hostname) proxy=$(systemctl is-active swift-proxy) object=$(systemctl is-active swift-object)' | tee -a "$OUT/residual.log"
done
AUTH=$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$LB/auth/v1.0" || echo 000)
echo "vip_auth=$AUTH" | tee -a "$OUT/residual.log"
python3 - <<PY | tee "$OUT/SUMMARY.json"
import json, pathlib
out = pathlib.Path("$OUT")
p = json.loads((out/"proxy-loss.json").read_text())
o = json.loads((out/"object-loss.json").read_text())
resid = (out/"residual.log").read_text()
all_active = resid.count("proxy=active") == 4 and resid.count("object=active") == 4
gate = "PASS" if (p["pass"] and o["pass"] and all_active and "$AUTH"=="200") else "FAIL"
print(json.dumps({
  "gate": gate, "proxy_loss": p, "object_loss": o,
  "residual_all_active": all_active, "vip_auth": "$AUTH",
  "note": "v2: create container; inject non-VIP proxy (swift3) + object (swift4)",
}, indent=2))
PY
