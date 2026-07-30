#!/bin/bash
# Schedule the object auditor, which exists on every node and has never run.
#
# Chaos Arcade proved why this matters: corrupting one replica's bytes while
# leaving its name and size intact was invisible to everything. 71 replicator
# and reconstructor passes across four nodes all reported suffix_syncs=0, and
# every client read returned 200, because the proxy happened not to pick the
# damaged copy. Nothing that compares directories can see silent damage — only
# something that re-reads the bytes and checksums them can, and that is exactly
# what this binary does.
#
# It is a one-shot per (device, policy) rather than a daemon, so a timer is the
# right shape: a sweep, then idle, rather than a process holding disk all day.
set -e
K="-i /etc/swift/replication_key -o BatchMode=yes -o ConnectTimeout=15"

apply() {
  cat > /usr/local/bin/swift-audit-sweep <<'SWEEP'
#!/bin/bash
# One pass over every mounted device, for every configured policy.
# Reports per device so a quarantine can be traced to a disk, not just a node.
set -u
export SWIFT_DIR=/etc/swift
tp=0; tq=0; te=0
for dev in /srv/node/*; do
  mountpoint -q "$dev" || continue
  for pol in $(awk -F'[:]' '/^\[storage-policy:/{gsub(/\]/,"",$2); print $2}' /etc/swift/swift.conf); do
    out=$(/usr/local/bin/swift-object-auditor "$dev" "$pol" 2>&1) || true
    p=$(awk '/^passed/{print $2}' <<<"$out"); q=$(awk '/^quarantined/{print $2}' <<<"$out")
    e=$(awk '/^errors/{print $2}' <<<"$out")
    tp=$((tp+${p:-0})); tq=$((tq+${q:-0})); te=$((te+${e:-0}))
    [ "${q:-0}" != "0" ] || [ "${e:-0}" != "0" ] && \
      logger -t object-auditor "device=$(basename "$dev") policy=$pol passed=${p:-0} quarantined=${q:-0} errors=${e:-0}"
  done
done
logger -t object-auditor "audit sweep: passed=$tp quarantined=$tq errors=$te"
echo "passed=$tp quarantined=$tq errors=$te"
SWEEP
  chmod 755 /usr/local/bin/swift-audit-sweep
  restorecon -F /usr/local/bin/swift-audit-sweep 2>/dev/null || true

  cat > /etc/systemd/system/swift-object-auditor.service <<'UNIT'
[Unit]
Description=Swift object auditor sweep (rust)
After=network-online.target

[Service]
Type=oneshot
Environment=SWIFT_DIR=/etc/swift
ExecStart=/usr/local/bin/swift-audit-sweep
Nice=10
IOSchedulingClass=idle
UNIT

  cat > /etc/systemd/system/swift-object-auditor.timer <<'TIMER'
[Unit]
Description=Run the Swift object auditor periodically

[Timer]
# Every 30 minutes, jittered so four nodes do not all read their disks at once.
OnBootSec=10min
OnUnitActiveSec=30min
RandomizedDelaySec=5min
Persistent=true

[Install]
WantedBy=timers.target
TIMER

  restorecon -F /etc/systemd/system/swift-object-auditor.* 2>/dev/null || true
  systemctl daemon-reload
  systemctl enable -q --now swift-object-auditor.timer
  printf "  %-8s timer=%s next=%s\n" "$(hostname)" \
    "$(systemctl is-active swift-object-auditor.timer)" \
    "$(systemctl show -p NextElapseUSecRealtime --value swift-object-auditor.timer | cut -c1-20)"
}

if [ "$1" = "--local" ]; then apply; exit 0; fi
apply
for n in 12 13 14; do
  scp -q $K "$0" root@10.42.10.$n:/root/deploy-auditor.sh
  ssh -n $K root@10.42.10.$n "bash /root/deploy-auditor.sh --local"
done
