#!/usr/bin/env bash
# Migrate the Azure Swift Rust *dev environment* from swift-old* to swift*.
# Old and new VNets cannot talk; traffic relays through this Mac.
set -Eeuo pipefail

OLD=${OLD:-swift-old1}
NEW=${NEW:-swift1}
KEY_PUB=${KEY_PUB:-/Users/oboy/Documents/Codex/2026-07-25/b/work/ssh/id_ed25519.pub}

log() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null || die "missing $1"; }
need ssh
need ssh-copy-id || true

ssh_old() { ssh -o BatchMode=yes -o ConnectTimeout=20 "$OLD" "$@"; }
ssh_new() { ssh -o BatchMode=yes -o ConnectTimeout=20 "$NEW" "$@"; }
ssh_new_n() { ssh -o BatchMode=yes -o ConnectTimeout=20 "$1" "${@:2}"; }

log "sanity: old=$OLD new=$NEW"
ssh_old 'hostname; test -f /usr/local/bin/swift-proxy-server && echo old_bins_ok'
ssh_new 'hostname; sudo -n true && echo new_sudo_ok'

log "bootstrap packages + root SSH on all new nodes"
for h in swift1 swift2 swift3 swift4; do
  echo "--- $h ---"
  ssh_new_n "$h" 'sudo bash -s' <<'EOS'
set -euo pipefail
dnf -y install epel-release >/dev/null 2>&1 || true
dnf -y install \
  haproxy rsync curl tar gzip which gcc make git \
  liberasurecode liberasurecode-devel \
  python3 xfsprogs \
  >/dev/null
# Root login for inter-node replication (matches old cluster).
mkdir -p /root/.ssh
chmod 700 /root/.ssh
if [ -f /home/azureuser/.ssh/authorized_keys ]; then
  cat /home/azureuser/.ssh/authorized_keys >> /root/.ssh/authorized_keys
  sort -u /root/.ssh/authorized_keys -o /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
fi
# PermitRootLogin
if grep -q '^PermitRootLogin' /etc/ssh/sshd_config; then
  sed -i 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
else
  echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config
fi
systemctl reload sshd || systemctl reload ssh
# Data dirs already mounted; ensure ownership for root daemons.
for d in /srv/node/d1 /srv/node/d2 /srv/node/d3; do
  mkdir -p "$d"
  chown root:root "$d"
done
mkdir -p /var/cache/swift /var/log/swift /var/run/swift /etc/swift
echo bootstrap_ok
EOS
done

log "stream configs + systemd + binaries old -> new (via this host)"
# Phase 1: small critical paths
ssh_old 'sudo tar -C / -czf - \
  etc/swift \
  etc/haproxy \
  etc/swift-console \
  etc/swift-deploy \
  etc/prometheus \
  etc/loki \
  etc/alloy \
  etc/systemd/system/swift-*.service \
  etc/systemd/system/haproxy.service \
  etc/systemd/system/prometheus.service \
  etc/systemd/system/loki.service \
  etc/systemd/system/alloy.service \
  etc/systemd/system/node_exporter.service \
  etc/systemd/system/statsd_exporter.service \
  usr/lib64/liberasurecode* \
  usr/lib64/libJerasure* \
  usr/lib64/libXorcode* \
  2>/dev/null' \
| ssh_new 'sudo tar -C / -xzf - && echo phase1_ok'

log "stream /usr/local/bin swift* tools"
ssh_old 'sudo bash -c "
  cd /usr/local/bin
  tar -czf - \
    swift-* \
    node_exporter prometheus promtool loki alloy statsd_exporter \
    2>/dev/null
"' | ssh_new 'sudo tar -C /usr/local/bin -xzf - && sudo ldconfig && echo phase2_bins_ok'

log "install replication key auth across new nodes"
# Ensure every new node trusts the replication key for root@storage IPs.
PUB=$(ssh_old 'sudo cat /etc/swift/replication_key.pub')
PRIV_B64=$(ssh_old 'sudo base64 -w0 /etc/swift/replication_key')
for h in swift1 swift2 swift3 swift4; do
  ssh_new_n "$h" "sudo bash -s" <<EOS
set -euo pipefail
mkdir -p /etc/swift /root/.ssh
echo '$PRIV_B64' | base64 -d > /etc/swift/replication_key
chmod 600 /etc/swift/replication_key
echo '$PUB' > /etc/swift/replication_key.pub
chmod 644 /etc/swift/replication_key.pub
grep -qxF '$PUB' /root/.ssh/authorized_keys 2>/dev/null || echo '$PUB' >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
EOS
done

log "fan-out binaries + /etc/swift to swift2-4 from new swift1"
ssh_new 'sudo bash -s' <<'EOS'
set -euo pipefail
K="-i /etc/swift/replication_key -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=12"
BINS=$(ls /usr/local/bin/swift-* 2>/dev/null)
for ip in 10.42.10.12 10.42.10.13 10.42.10.14; do
  echo "=== fanout $ip ==="
  # First connection may need host key accept
  ssh $K root@$ip 'mkdir -p /usr/local/bin /etc/swift /etc/haproxy /var/cache/swift /var/log/swift /var/run/swift /srv/node/d1 /srv/node/d2 /srv/node/d3'
  tar -C /usr/local/bin -czf - swift-* 2>/dev/null | ssh $K root@$ip 'tar -C /usr/local/bin -xzf -'
  tar -C /etc -czf - swift haproxy 2>/dev/null | ssh $K root@$ip 'tar -C /etc -xzf -'
  # unit files
  tar -C /etc/systemd/system -czf - swift-*.service haproxy.service 2>/dev/null \
    | ssh $K root@$ip 'tar -C /etc/systemd/system -xzf -'
  ssh $K root@$ip 'ldconfig; systemctl daemon-reload'
done
echo fanout_ok
EOS

log "enable + start core services on all nodes"
for h in swift1 swift2 swift3 swift4; do
  echo "--- start $h ---"
  ssh_new_n "$h" 'sudo bash -s' <<'EOS'
set -euo pipefail
systemctl daemon-reload
systemctl enable --now \
  swift-account swift-account-replicator \
  swift-container swift-container-replicator swift-container-updater \
  swift-object swift-object-replicator swift-object-reconstructor swift-object-updater \
  swift-proxy haproxy \
  2>&1 | tail -5 || true
# optional monitoring (hub mainly on swift1)
if [ "$(hostname -s)" = swift1 ]; then
  systemctl enable --now node_exporter statsd_exporter prometheus loki alloy swift-console swift-deploy-ui 2>&1 | tail -8 || true
else
  systemctl enable --now node_exporter 2>&1 | tail -3 || true
fi
sleep 2
systemctl is-active swift-proxy swift-object haproxy || true
curl -sS -m3 -o /dev/null -w "health=%{http_code}\n" http://127.0.0.1:8080/healthcheck || true
curl -sS -m3 -o /dev/null -w "haproxy=%{http_code}\n" http://127.0.0.1:8085/healthcheck || true
EOS
done

log "auth smoke via new LB VIP from swift1"
ssh_new 'curl -sS -m8 -D- -o /dev/null \
  -H "X-Auth-User: test:tester" -H "X-Auth-Key: azure-swift-2026.bench" \
  http://10.42.30.10:8085/auth/v1.0 | head -20' || \
ssh_new 'curl -sS -m8 -D- -o /dev/null \
  -H "X-Auth-User: test:tester" -H "X-Auth-Key: testing" \
  http://127.0.0.1:8080/auth/v1.0 | head -20' || true

log "stream source trees (no target/) for continued development"
ssh_old 'sudo bash -c "
  mkdir -p /tmp/mig
  tar -C /root -czf /tmp/mig/cargo-bin.tgz .cargo/bin .cargo/env 2>/dev/null || true
  tar -C /root/work --exclude=target --exclude=node_modules --exclude=dist -czf /tmp/mig/swift-rust.tgz swift-rust 2>/dev/null || true
  tar -C /root/work --exclude=target --exclude=node_modules --exclude=dist -czf /tmp/mig/peregrine.tgz Peregrine 2>/dev/null || true
  ls -lh /tmp/mig/
"'
# Pull to Mac then push — avoids double compression memory spikes on thin hosts
mkdir -p /tmp/swift-mig
scp -o BatchMode=yes "$OLD:/tmp/mig/*.tgz" /tmp/swift-mig/ || \
  ssh_old 'sudo tar -C /tmp/mig -cf - .' | tar -C /tmp/swift-mig -xf -
scp -o BatchMode=yes /tmp/swift-mig/*.tgz "$NEW:/tmp/" 
ssh_new 'sudo bash -s' <<'EOS'
set -euo pipefail
mkdir -p /root/work /root/.cargo
for f in /tmp/swift-rust.tgz /tmp/peregrine.tgz /tmp/cargo-bin.tgz; do
  [ -f "$f" ] || continue
  case "$f" in
    *cargo*) tar -C /root -xzf "$f" ;;
    *) tar -C /root/work -xzf "$f" ;;
  esac
done
# rustup toolchain if missing: keep cargo bin from old
grep -q '.cargo/env' /root/.bashrc 2>/dev/null || echo '. "$HOME/.cargo/env"' >> /root/.bashrc
test -x /root/.cargo/bin/rustc && /root/.cargo/bin/rustc --version || true
ls /root/work | head
echo sources_ok
EOS

log "done — verify summary"
ssh_new 'sudo bash -s' <<'EOS'
set -euo pipefail
echo "hostname=$(hostname)"
systemctl is-active swift-proxy swift-object swift-console haproxy 2>/dev/null || true
curl -sS -m3 -o /dev/null -w "proxy8080=%{http_code}\n" http://127.0.0.1:8080/healthcheck || true
curl -sS -m3 -o /dev/null -w "lb8085=%{http_code}\n" http://10.42.30.10:8085/healthcheck || true
curl -sS -m3 -o /dev/null -w "console=%{http_code}\n" http://127.0.0.1:9000/login || true
df -h / /srv/node/d1 | sed -n '1,3p'
EOS
