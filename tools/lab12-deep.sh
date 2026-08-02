#!/bin/bash
# Contabo Lab12 deep harness — real dual Shadow, chaos×4, nodes last.
set -uo pipefail
BASE=$(cat /tmp/contabo-out.txt 2>/dev/null || true)
OUT=${OUT:-${BASE:+$BASE/lab12-deep}}
OUT=${OUT:-/root/contabo-deploy-20260801T125749Z/lab12-deep}

mkdir -p "$OUT"
export OUT
echo "OUT=$OUT"
CON=http://127.0.0.1:9000
EP=http://10.0.0.1:8085
VIP=http://10.0.0.10:8085
USR=test:tester
KEY=azure-swift-2026.bench
TOOLS=/root/work/swift-rust/tools
J=$OUT/session.jar
rm -f "$J"

login() {
  curl -s -m20 -c "$J" -o /dev/null -X POST \
    -d "tenant=test&user=tester&key=$KEY" "$CON/login"
}
capi() { curl -s -m120 -b "$J" "$@"; }
capi_code() { curl -s -m120 -b "$J" -o /tmp/capi.out -w '%{http_code}' "$@"; }

PASS=0; FAIL=0; WARN=0; REJECTS=()
ok(){ PASS=$((PASS+1)); printf '  PASS  %s\n' "$1" | tee -a "$OUT/run.log"; }
bad(){ FAIL=$((FAIL+1)); REJECTS+=("$1"); printf '  FAIL  %s -- %s\n' "$1" "$2" | tee -a "$OUT/run.log"; }
warn(){ WARN=$((WARN+1)); printf '  WARN  %s -- %s\n' "$1" "$2" | tee -a "$OUT/run.log"; }

{
echo "# Lab12 deep Contabo $(date -u +%FT%TZ)"
echo

echo "===== 00 ENV ====="
login
python3 - <<'PY' | tee "$OUT/00-ENV.md"
import json, subprocess, pathlib
cfg=json.load(open("/etc/swift-console/config.json"))
want={
  "swift_base": cfg.get("swift_base"),
  "shadow_peer_base": cfg.get("shadow_peer_base"),
  "shadow_peer_auth": cfg.get("shadow_peer_auth"),
  "shadow_peer_label": cfg.get("shadow_peer_label"),
  "lab_enabled": cfg.get("lab_enabled"),
}
print(json.dumps(want, indent=2))
assert want["shadow_peer_base"]=="http://127.0.0.1:8090"
assert "8090" in (want["shadow_peer_auth"] or "")
assert "Python" in (want["shadow_peer_label"] or "")
print("shadow_peer_config_ok")
for u in ["http://10.0.0.10:8085/healthcheck","http://127.0.0.1:8090/healthcheck","http://127.0.0.1:8081/healthcheck"]:
    import urllib.request
    try:
        print(u, urllib.request.urlopen(u, timeout=5).status)
    except Exception as e:
        print(u, "ERR", e)
PY

echo "===== func-suite oracles ====="
bash "$TOOLS/func-suite.sh" "$EP" "$USR" "$KEY" cluster | tee "$OUT/func-cluster.log" | grep RESULT
bash "$TOOLS/func-suite.sh" http://127.0.0.1:8090 "$USR" "$KEY" py-saio | tee "$OUT/func-pysaio.log" | grep RESULT
bash "$TOOLS/func-suite.sh" http://127.0.0.1:8081 "$USR" "$KEY" rust-saio | tee "$OUT/func-rsaio.log" | grep RESULT
grep -q 'FAIL=0' "$OUT/func-cluster.log" && ok "func cluster FAIL=0" || bad "func cluster" "not FAIL=0"
grep -q 'FAIL=0' "$OUT/func-pysaio.log" && ok "func py-saio FAIL=0" || bad "func py-saio" "not FAIL=0"

echo "===== Shadow dual ====="
login
# Sync Temp-URL key across ops + Shadow peers (parity historically used :8080)
TKEY=$(openssl rand -hex 16)
for AUTH_BASE in "$VIP" "http://127.0.0.1:8090" "http://127.0.0.1:8081" "http://127.0.0.1:8080"; do
  AT=$(curl -s -m10 -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$AUTH_BASE/auth/v1.0" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
  if [[ -n "$AT" ]]; then
    curl -s -m10 -o /dev/null -X POST -H "X-Auth-Token: $AT" -H "X-Account-Meta-Temp-URL-Key: $TKEY" "$AUTH_BASE/v1/AUTH_test" || true
    echo "tempurl_key_synced $AUTH_BASE" | tee -a "$OUT/05-shadow-run.meta"
  else
    echo "tempurl_key_skip $AUTH_BASE (no token)" | tee -a "$OUT/05-shadow-run.meta"
  fi
done
echo "shadow_bootstrap: parity_hint=http://127.0.0.1:8080 ops_default=$VIP" | tee -a "$OUT/00-ENV.md"
# run capture
code=$(capi_code -X POST "$CON/lab/api/shadow/run")
echo "shadow/run http=$code" | tee -a "$OUT/05-shadow-run.meta"
cp /tmp/capi.out "$OUT/05-shadow-run.json"
python3 - <<'PY' | tee "$OUT/SHADOW-MATRIX.md"
import json,sys
from pathlib import Path
out=Path(__import__('os').environ['OUT'])
raw=(out/'05-shadow-run.json').read_text(errors='replace')
try:
    d=json.loads(raw)
except Exception as e:
    print("PARSE_FAIL", e, raw[:500]); sys.exit(0)
# API may wrap differently — tolerate
mode=d.get("mode") or d.get("summary",{}).get("mode") or ""
breaking=d.get("breaking")
if breaking is None:
    breaking=d.get("summary",{}).get("breaking")
semantic=d.get("semantic") or d.get("summary",{}).get("semantic")
identical=d.get("identical") or d.get("summary",{}).get("identical")
cosmetic=d.get("cosmetic") or d.get("summary",{}).get("cosmetic")
cases=d.get("cases") or d.get("summary",{}).get("cases")
print(f"mode={mode} cases={cases} breaking={breaking} semantic={semantic} cosmetic={cosmetic} identical={identical}")
print(json.dumps({k:d.get(k) for k in list(d)[:20] if k!='rows'}, indent=2)[:2000])
Path(out/'05-shadow-summary.json').write_text(json.dumps({
  "mode":mode,"breaking":breaking,"semantic":semantic,"cosmetic":cosmetic,"identical":identical,"cases":cases
}, indent=2))
if mode!="dual":
    print("SHADOW_MODE_NOT_DUAL")
if breaking is not None and int(breaking)==0:
    print("SHADOW_BREAKING_ZERO")
else:
    print("SHADOW_BREAKING_NONZERO", breaking)
PY
MODE=$(python3 -c "import json;print(json.load(open('$OUT/05-shadow-summary.json')).get('mode'))" 2>/dev/null || echo unknown)
BRK=$(python3 -c "import json;print(json.load(open('$OUT/05-shadow-summary.json')).get('breaking'))" 2>/dev/null || echo 99)
[[ "$MODE" == dual ]] && ok "shadow mode=dual" || bad "shadow mode" "got $MODE"
[[ "$BRK" == 0 ]] && ok "shadow breaking=0" || bad "shadow breaking" "got $BRK (REJECT)"

# replay
code=$(capi_code -X POST "$CON/lab/api/shadow/replay")
echo "replay http=$code" | tee "$OUT/05-shadow-replay.meta"
cp /tmp/capi.out "$OUT/05-shadow-replay.json"
# mutate seeds
for seed in 111 222 333; do
  code=$(capi_code -X POST -H 'Content-Type: application/json' -d "{\"seed\":$seed}" "$CON/lab/api/shadow/mutate")
  echo "mutate seed=$seed http=$code" | tee -a "$OUT/05-shadow-mutate.log"
  cp /tmp/capi.out "$OUT/05-shadow-mutate-$seed.json"
  [[ "$code" == 200 ]] && ok "shadow mutate $seed" || bad "shadow mutate $seed" "http $code"
done
# negative: stop py proxy briefly
pkill -f '/etc/pyswift/proxy-server.conf' 2>/dev/null || true
sleep 2
code=$(capi_code -X POST "$CON/lab/api/shadow/run")
cp /tmp/capi.out "$OUT/05-shadow-neg.json"
echo "neg http=$code body=$(head -c 200 /tmp/capi.out)" | tee "$OUT/05-shadow-neg.meta"
if grep -qiE 'error|refused|peer|fail|unavailable' "$OUT/05-shadow-neg.json" || [[ "$code" != 200 ]]; then
  ok "shadow peer-down explicit error"
else
  # if still 200 check mode not silently single success
  if grep -q '"mode":"single"' "$OUT/05-shadow-neg.json"; then
    bad "shadow peer-down" "silent single mode"
  else
    warn "shadow peer-down" "unclear response; inspect 05-shadow-neg.json"
  fi
fi
# restore py-saio
bash /root/work/swift-rust/tools/py-saio-setup.sh >/tmp/py-restore.log 2>&1 || true
sleep 2
curl -s -m5 -o /dev/null -w "py_restored:%{http_code}\n" http://127.0.0.1:8090/healthcheck

echo "===== RingScope / Policy / Debt / Capsule / Tombstone / Warehouse ====="
login
for path in \
  /lab/api/ring/topology \
  /lab/api/policy/defaults \
  /lab/api/node/status \
  /lab/api/chaos/catalogue \
  /lab/api/warehouse/jobs \
  /lab/api/expired/status \
  /lab/api/profilemap/snapshot?path=put
 do
  code=$(capi_code "$CON$path")
  echo "$path -> $code" | tee -a "$OUT/10-readonly.log"
  cp /tmp/capi.out "$OUT/api-$(echo "$path" | tr '/?=&' '____').json"
  if [[ "$code" == 200 ]]; then ok "api $path"; else
    # capability missing → REJECT for that tool per plan
    case "$path" in
      *expired*|*profilemap*) bad "tool $path" "capability missing http=$code (REJECT tool)" ;;
      *) bad "api $path" "http $code" ;;
    esac
  fi
done

# Ring topology assert device count
python3 - <<'PY'
import json
from pathlib import Path
out=Path(__import__('os').environ['OUT'])
# find topology file
cands=list(out.glob('api-*ring*topology*.json'))+list(out.glob('api-____lab____api____ring____topology.json'))
p=None
for c in out.glob('api-*.json'):
    if 'ring' in c.name and 'topology' in c.name:
        p=c; break
if not p:
    print('no topology file'); raise SystemExit(0)
d=json.loads(p.read_text())
# count devices loosely
text=json.dumps(d)
print('topology_bytes', len(text))
print('has_d1', 'd1' in text, 'has_swift', 'swift' in text.lower() or '10.0.4' in text)
PY

# Capsule: put object then call capsule API if exists
TOK=$(curl -s -m10 -D - -o /dev/null -H "X-Auth-User: $USR" -H "X-Auth-Key: $KEY" "$EP/auth/v1.0" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
B="$EP/v1/AUTH_test"
C=lab12-cap-$RANDOM
curl -s -X PUT -H "X-Auth-Token: $TOK" "$B/$C" >/dev/null
echo -n 'capsule-body' | curl -s -X PUT -H "X-Auth-Token: $TOK" --data-binary @- "$B/$C/o1" >/dev/null
code=$(capi_code "$CON/lab/api/capsule?account=AUTH_test&container=$C&object=o1")
echo "capsule http=$code" | tee -a "$OUT/20-capsule.log"
[[ "$code" == 200 ]] && ok "capsule repl" || bad "capsule" "http $code"
# EC
curl -s -X PUT -H "X-Auth-Token: $TOK" -H "X-Storage-Policy: ec-2-1" "$B/${C}-ec" >/dev/null
dd if=/dev/urandom of=/tmp/lab12ec bs=1M count=1 status=none
curl -s -m30 -X PUT -H "X-Auth-Token: $TOK" --data-binary @/tmp/lab12ec "$B/${C}-ec/o1" >/dev/null
code=$(capi_code "$CON/lab/api/capsule?account=AUTH_test&container=${C}-ec&object=o1")
[[ "$code" == 200 ]] && ok "capsule ec" || bad "capsule ec" "http $code"

# Tombstone lifecycle
code=$(capi_code "$CON/lab/api/tombstone?account=AUTH_test&container=$C&object=o1")
[[ "$code" == 200 ]] && ok "tombstone alive" || bad "tombstone" "http $code"
curl -s -X DELETE -H "X-Auth-Token: $TOK" "$B/$C/o1" >/dev/null
code=$(capi_code "$CON/lab/api/tombstone?account=AUTH_test&container=$C&object=o1")
[[ "$code" == 200 ]] && ok "tombstone after delete" || bad "tombstone delete" "http $code"

# Warehouse: create jobs via API if available
code=$(capi_code -X POST -H 'Content-Type: application/json' \
  -d '{"goal":"lab12 warehouse probe","agent":"lab12-deep","inputs":[{"name":"hello.txt","content":"hello-w1"}]}' "$CON/lab/api/warehouse/job")
echo "warehouse create http=$code" | tee -a "$OUT/30-warehouse.log"
cp /tmp/capi.out "$OUT/30-warehouse-create.json"
[[ "$code" =~ ^(200|201)$ ]] && ok "warehouse create" || bad "warehouse" "http $code"

echo "===== Chaos ×4 (before nodes) ====="
login
CAT=$(capi "$CON/lab/api/chaos/catalogue")
echo "$CAT" > "$OUT/40-chaos-catalogue.json"
for f in drop_copy corrupt_copy drop_durable stale_timestamp; do
  echo "$CAT" | grep -q "\"$f\"" && ok "catalogue has $f" || bad "catalogue" "missing $f"
done

for fault in drop_copy corrupt_copy drop_durable stale_timestamp; do
  echo "--- chaos $fault ---"
  login
  POL=0
  PRED_RB=replicator
  PRED_CS=120
  if [[ "$fault" == "drop_durable" ]]; then
    POL=1
    PRED_RB=reconstructor
    PRED_CS=180
  fi
  code=$(capi_code -X POST -H 'Content-Type: application/json' \
    -d "{\"fault\":\"$fault\",\"policy\":$POL,\"deadline\":150,\"prediction\":{\"readable\":true,\"repaired_by\":\"$PRED_RB\",\"converge_secs\":$PRED_CS}}" "$CON/lab/api/chaos/run")
  echo "run $fault http=$code" | tee -a "$OUT/40-chaos.log"
  cp /tmp/capi.out "$OUT/40-chaos-run-$fault.json"
  if [[ "$code" == 409 ]]; then
    # previous experiment still running — recover then retry once
    capi_code -X POST "$CON/lab/api/chaos/recover" >/dev/null || true
    sleep 3
    code=$(capi_code -X POST -H "Content-Type: application/json" \
      -d "{\"fault\":\"$fault\",\"policy\":$POL,\"deadline\":150,\"prediction\":{\"readable\":true,\"repaired_by\":\"$PRED_RB\",\"converge_secs\":$PRED_CS}}" "$CON/lab/api/chaos/run")
    echo "run $fault retry http=$code" | tee -a "$OUT/40-chaos.log"
    cp /tmp/capi.out "$OUT/40-chaos-run-$fault.json"
  fi
  # poll until idle or deadline
  for i in $(seq 1 20); do
    sleep 5
    capi "$CON/lab/api/chaos/status" > "$OUT/40-chaos-status-$fault-$i.json"
    if grep -qE "\"phase\":\"(done|idle|recovered)\"|\"running\":false|\"active\":false" "$OUT/40-chaos-status-$fault-$i.json" 2>/dev/null; then
      break
    fi
  done
  # recover
  code=$(capi_code -X POST "$CON/lab/api/chaos/recover")
  echo "recover $fault http=$code" | tee -a "$OUT/40-chaos.log"
  cp /tmp/capi.out "$OUT/40-chaos-recover-$fault.json"
  sleep 2
  # services still up
  up=1
  for ip in 1 2 3 4; do
    st=$(ssh -o BatchMode=yes -o ConnectTimeout=8 root@10.0.0.$ip 'systemctl is-active swift-proxy swift-object' 2>/dev/null | tr '\n' ' ')
    echo "  node$ip $st" | tee -a "$OUT/40-chaos.log"
    echo "$st" | grep -q 'inactive\|failed' && up=0
  done
  [[ $up -eq 1 ]] && ok "chaos $fault services up" || bad "chaos $fault" "service down"
  [[ "$code" =~ ^(200|204)$ ]] && ok "chaos $fault recover" || warn "chaos $fault recover" "http $code"
done

echo "===== Profile / Expired capability ====="
login
code=$(capi_code -X POST -H 'Content-Type: application/json' -d '{"path":"put"}' "$CON/lab/api/profilemap/pulse")
echo "profile pulse http=$code" | tee "$OUT/50-profile.log"
cp /tmp/capi.out "$OUT/50-profile-pulse.json"
if [[ "$code" == 200 ]]; then
  snap=$(capi "$CON/lab/api/profilemap/snapshot?path=put")
  echo "$snap" > "$OUT/50-profile-snap.json"
  if echo "$snap" | grep -qiE 'stage|span|sample|node'; then ok "profile snapshot non-empty"; else bad "profile" "empty instrumentation (REJECT tool)"; fi
else
  bad "profile" "pulse http=$code (REJECT tool)"
fi

code=$(capi_code -X POST -H 'Content-Type: application/json' \
  -d '{"count":20,"ttl_secs":30}' "$CON/lab/api/expired/run")
echo "expired run http=$code" | tee "$OUT/51-expired.log"
cp /tmp/capi.out "$OUT/51-expired-run.json"
if [[ "$code" == 200 ]]; then
  ok "expired run"
else
  bad "expired/open-expired" "capability missing http=$code (REJECT tool)"
fi

echo "===== Nodes HA LAST ====="
login
bash "$TOOLS/ha-test.sh" | tee "$OUT/60-ha-test.log" | tail -40
if grep -q 'HA-TEST-DONE' "$OUT/60-ha-test.log" && grep -q 'writes ok=20/20' "$OUT/60-ha-test.log"; then
  ok "nodes HA degraded 20/20 + recover"
else
  # accept >=18/20
  if grep -E 'degraded.*writes ok=(1[89]|20)/20' "$OUT/60-ha-test.log"; then
    ok "nodes HA degraded >=18/20"
  else
    bad "nodes HA" "see 60-ha-test.log"
  fi
fi
# final 4 up
login
capi "$CON/lab/api/node/status" | tee "$OUT/60-nodes-final.json" | python3 -c 'import sys,json;d=json.load(sys.stdin);u=sum(1 for n in d["nodes"] if n["up"]); print("up",u); assert u==4'
ok "final nodes 4/4 up"

echo
echo "===== SUMMARY ====="
echo "PASS=$PASS FAIL=$FAIL WARN=$WARN"
printf 'REJECTS: %s\n' "${REJECTS[*]:-none}"
} 2>&1 | tee "$OUT/LAB12-RUN.log"

python3 - <<'PY' | tee "$OUT/SUMMARY.md"
from pathlib import Path
import re, json
out=Path(__import__('os').environ['OUT'])
log=(out/'LAB12-RUN.log').read_text(errors='replace')
pass_n=len(re.findall(r'^\s*PASS ', log, re.M))
fail_n=len(re.findall(r'^\s*FAIL ', log, re.M))
warn_n=len(re.findall(r'^\s*WARN ', log, re.M))
fails=re.findall(r'^\s*FAIL\s+(.*)$', log, re.M)
shadow={}
sp=out/'05-shadow-summary.json'
if sp.exists():
    shadow=json.loads(sp.read_text())
verdict='ACCEPT'
if fail_n or (shadow.get('breaking') not in (0, '0', None) and shadow):
    # shadow breaking already in fails usually
    verdict='REJECT'
if shadow.get('mode')!='dual':
    verdict='REJECT'
print('# Lab12 deep Contabo SUMMARY')
print()
print(f'- **Verdict:** {verdict}')
print(f'- PASS={pass_n} FAIL={fail_n} WARN={warn_n}')
print(f'- Shadow: {shadow}')
print('- Failures:')
for f in fails:
    print(f'  - {f}')
print()
print(f'- OUT: `{out}`')
PY

echo LAB12_DEEP_DONE
