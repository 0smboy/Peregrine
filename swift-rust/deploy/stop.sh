#!/usr/bin/env bash
# Stop the cluster. With --wipe, also delete all stored data and rings so
# the next bootstrap/setup starts from a clean slate.
set -u
systemctl stop swift-rust-saio 2>/dev/null || pkill -f 'swift-.*-server' 2>/dev/null || true
echo "cluster stopped."
if [ "${1:-}" = --wipe ]; then
  rm -rf /srv/node*/sdb*/objects* /srv/node*/sdb*/accounts \
         /srv/node*/sdb*/containers /srv/node*/sdb*/tmp
  rm -f /etc/swift/*.ring.gz
  echo "data + rings wiped."
fi
