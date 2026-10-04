#!/bin/bash
set -euo pipefail
SRC=/tmp/hk-payload
test -d "$SRC/bin"
mkdir -p /usr/local/bin /etc/swift /etc/haproxy /usr/local/lib /etc/systemd/system
install -m 0755 "$SRC"/bin/swift-* /usr/local/bin/
if compgen -G "$SRC/lib/*.so*" >/dev/null; then
  install -m 0755 "$SRC"/lib/*.so* /usr/local/lib/
  ldconfig || true
fi
install -m 0644 "$SRC"/unit/*.service /etc/systemd/system/
install -m 0644 "$SRC"/conf/swift.conf "$SRC"/conf/proxy-server.conf \
  "$SRC"/conf/account-server.conf "$SRC"/conf/container-server.conf \
  "$SRC"/conf/object-server.conf /etc/swift/
install -m 0600 "$SRC"/conf/replication_key /etc/swift/replication_key
install -m 0644 "$SRC"/conf/replication_key.pub /etc/swift/replication_key.pub
install -m 0644 "$SRC"/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg
install -m 0600 "$SRC"/haproxy/haproxyCA.pem /etc/haproxy/haproxyCA.pem
mkdir -p /root/.ssh
chmod 700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
PUB=$(cat /etc/swift/replication_key.pub)
grep -qxF "$PUB" /root/.ssh/authorized_keys || echo "$PUB" >> /root/.ssh/authorized_keys
restorecon -v /usr/local/bin/swift-proxy-server /usr/local/bin/swift-object-server \
  /usr/local/bin/swift-container-server /usr/local/bin/swift-account-server \
  /usr/local/bin/swift-object-replicator /usr/local/bin/swift-db-replicator \
  /usr/local/bin/swift-object-reconstructor /usr/local/bin/swift-object-updater \
  /usr/local/bin/swift-container-updater /usr/local/bin/swift-object-auditor \
  /usr/local/bin/swift-db-auditor /usr/local/bin/swift-container-sharder \
  /usr/local/bin/swift-container-reconciler /usr/local/bin/swift-object-expirer \
  || true
echo INSTALL_FILES_DONE
