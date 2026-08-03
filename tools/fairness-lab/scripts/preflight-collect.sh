#!/usr/bin/env bash
# P1: immutable infrastructure baseline from Contabo nodes.
# Usage: preflight-collect.sh [OUTDIR]
# Requires SSH aliases swift1..swift4.
set -euo pipefail
OUT="${1:-}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
if [[ -z "$OUT" ]]; then
  OUT="$ROOT/tools/test-results/fairness-lab-20260803/preflight"
fi
mkdir -p "$OUT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
META="$OUT/META.txt"
{
  echo "collected_utc=$STAMP"
  echo "script=$(basename "$0")"
} | tee "$META"

collect_host() {
  local h=$1
  local d="$OUT/$h"
  mkdir -p "$d"
  echo "### $h ###"
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$h" 'bash -s' <<'REMOTE' >"$d/host.txt" 2>&1 || echo "SSH_FAIL $h" | tee -a "$d/host.txt"
set +e
echo "=== hostname ==="; hostname; date -u +%FT%TZ
echo "=== uname ==="; uname -a
echo "=== lscpu ==="; lscpu
echo "=== nproc ==="; nproc
echo "=== free ==="; free -b
echo "=== swapon ==="; swapon --show
echo "=== cgroup cpu ==="; cat /sys/fs/cgroup/cpu.max 2>/dev/null; cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null
echo "=== cgroup mem ==="; cat /sys/fs/cgroup/memory.max 2>/dev/null; cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null
echo "=== lsblk ==="; lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID,MODEL
echo "=== by-id ==="; ls -l /dev/disk/by-id/ 2>/dev/null | head -80
echo "=== findmnt srv ==="; findmnt -T /srv/node -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null; findmnt | grep /srv/node || true
echo "=== xfs_info ==="
for m in /srv/node/d1 /srv/node/d2 /srv/node/d3; do
  echo "-- $m --"; xfs_info "$m" 2>&1 | head -20
done
echo "=== ip -br ==="; ip -br addr
echo "=== ip route ==="; ip route
echo "=== chrony ==="; chronyc tracking 2>&1 | head -20
echo "=== ss listeners interesting ==="; ss -lnt | grep -E ':(8085|8081|8090|9000|9090|6200|6201|6202|18080)\s' || true
echo "=== systemctl swift ==="; systemctl list-units 'swift*' --no-pager --no-legend 2>/dev/null | head -40
echo "=== steal sample ==="; grep -E 'cpu |steal' /proc/stat | head -5
REMOTE
}

for h in swift1 swift2 swift3 swift4; do
  collect_host "$h"
done

# Network matrix (best-effort short iperf if available)
NET="$OUT/network"
mkdir -p "$NET"
{
  echo "note=short RTT matrix; iperf3 optional"
  for src in swift1 swift2 swift3 swift4; do
    for dst_ip in 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4; do
      rtt=$(ssh -o BatchMode=yes "$src" "ping -c 3 -W 1 $dst_ip 2>/dev/null | tail -1" || true)
      echo "$src -> $dst_ip :: $rtt"
    done
  done
} | tee "$NET/rtt-matrix.txt"

# Disk fio sample on swift1 only (non-destructive, short)
ssh -o BatchMode=yes swift1 'bash -s' <<'FIO' >"$OUT/swift1/fio-sample.txt" 2>&1 || true
set +e
command -v fio >/dev/null || { echo "fio_missing"; exit 0; }
for d in d1 d2 d3; do
  echo "=== fio randread $d ==="
  fio --name=rr --directory=/srv/node/$d --rw=randread --bs=4k --size=64M --numjobs=1 --iodepth=16 --runtime=10 --time_based --group_reporting 2>&1 | tail -20
done
FIO

# Summarize
python3 - <<PY
import json, pathlib, re
out = pathlib.Path("$OUT")
summary = {"collected_utc": "$STAMP", "hosts": {}}
for h in ["swift1","swift2","swift3","swift4"]:
    text = (out/h/"host.txt").read_text(errors="replace") if (out/h/"host.txt").exists() else ""
    nproc = re.search(r"(?m)^=== nproc ===\n(\d+)", text)
    mem = re.search(r"Mem:\s+(\d+)", text)
    listeners = [ln.strip() for ln in text.splitlines() if re.search(r":(8085|8081|8090|9000|9090|6200)\b", ln)]
    summary["hosts"][h] = {
        "nproc": int(nproc.group(1)) if nproc else None,
        "mem_total_bytes_line": mem.group(0) if mem else None,
        "interesting_listeners": listeners[:20],
        "ssh_ok": "SSH_FAIL" not in text and "=== hostname ===" in text,
    }
(out/"SUMMARY.json").write_text(json.dumps(summary, indent=2)+"\n")
print(json.dumps(summary, indent=2))
PY

echo "OK preflight -> $OUT"
