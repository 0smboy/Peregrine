#!/usr/bin/env bash
# Deploy R0 swift-recon textfile exporter + node_exporter textfile collector
# + Prometheus alert rules on Contabo (swift1–4; Prometheus on swift4).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
HOSTS=(swift1 swift2 swift3 swift4)
OUT_DIR="${1:-$REPO/tools/test-results/r0-metrics-prom-20260805}"
mkdir -p "$OUT_DIR"

deploy_node() {
  local h="$1"
  echo "=== deploy $h ===" | tee -a "$OUT_DIR/00-deploy.log"
  ssh -o BatchMode=yes -o ConnectTimeout=12 "$h" 'mkdir -p /var/lib/node_exporter/textfile_collector /etc/prometheus/rules'
  scp -o BatchMode=yes \
    "$ROOT/systemd/node_exporter.service" \
    "$ROOT/systemd/swift-recon-textfile.service" \
    "$ROOT/systemd/swift-recon-textfile.timer" \
    "$h:/etc/systemd/system/"
  scp -o BatchMode=yes \
    "$ROOT/rules/swift-ops-alerts.yml" \
    "$h:/tmp/swift-ops-alerts.yml"
  ssh -o BatchMode=yes "$h" 'bash -s' <<'REMOTE'
set -euo pipefail
systemctl daemon-reload
systemctl enable --now swift-recon-textfile.timer
systemctl restart node_exporter
systemctl start swift-recon-textfile.service || true
# Only swift4 hosts Prometheus; still drop rules file on all for parity.
if [[ -f /etc/prometheus/prometheus.yml ]]; then
  install -m 644 /tmp/swift-ops-alerts.yml /etc/prometheus/rules/swift-ops-alerts.yml
  # keep existing swift-compat.yml
  promtool check rules /etc/prometheus/rules/*.yml 2>/dev/null || true
  systemctl reload prometheus 2>/dev/null || systemctl restart prometheus
fi
systemctl is-active node_exporter swift-recon-textfile.timer
ls -la /var/lib/node_exporter/textfile_collector/ || true
head -20 /var/lib/node_exporter/textfile_collector/swift-recon.prom 2>/dev/null || true
REMOTE
}

for h in "${HOSTS[@]}"; do
  deploy_node "$h" 2>&1 | tee -a "$OUT_DIR/00-deploy.log"
done

echo "=== scrape + query evidence ===" | tee -a "$OUT_DIR/00-deploy.log"
ssh -o BatchMode=yes swift4 'bash -s' <<'REMOTE' | tee "$OUT_DIR/01-prom-queries.txt"
set -euo pipefail
echo "## textfile on :9100 (swift4 local)"
curl -sS -m 5 http://127.0.0.1:9100/metrics | grep -E '^swift_(object_tombstone|db_)' | head -40
echo
echo "## instant queries"
for q in \
  'sum by (node) (swift_object_tombstones)' \
  'sum by (node) (swift_object_tombstone_bytes)' \
  'sum by (node,kind) (swift_db_file_bytes)' \
  'sum by (node,kind) (swift_db_freelist_bytes)' \
  'count(swift_object_tombstones)' \
  'count(up{job="node"}==1)' \
  'ALERTS{alertname=~"Swift.*|Galera.*|Keystone.*"}' \
  ; do
  echo "### QUERY $q"
  curl -sS -m 10 --get 'http://127.0.0.1:9090/api/v1/query' --data-urlencode "query=$q"
  echo
done
echo
echo "## rules loaded"
curl -sS -m 5 http://127.0.0.1:9090/api/v1/rules | python3 -c 'import sys,json; d=json.load(sys.stdin); gs=d.get("data",{}).get("groups",[]);
print("groups", [g.get("name") for g in gs]);
for g in gs:
  if "swift_ops" in g.get("name",""):
    for r in g.get("rules",[]):
      print(g["name"], r.get("name") or r.get("alert"), r.get("state"), r.get("health"))'
REMOTE

cp -f "$ROOT/rules/swift-ops-alerts.yml" "$OUT_DIR/swift-ops-alerts.yml"
cp -f "$ROOT/grafana/swift-tombstone-dbspace.json" "$OUT_DIR/grafana-swift-tombstone-dbspace.json"
echo "DONE deploy -> $OUT_DIR"
