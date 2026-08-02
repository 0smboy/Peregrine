# Phase D — edge/hub
2026-08-01T13:23Z

## Services
swift-console        active
prometheus           active
statsd_exporter      active
node_exporter        active
memcached            active
haproxy              active
swift-proxy          active
loki                 active

## Endpoints
http://127.0.0.1:8090/healthcheck -> 200
http://127.0.0.1:8081/healthcheck -> 200
http://10.0.0.10:8085/healthcheck -> 200
http://127.0.0.1:9000/ -> 303
http://127.0.0.1:9090/-/ready -> 200
http://127.0.0.1:3100/ready -> 503

## Console shadow
{
  "swift_base": "http://10.0.0.10:8085",
  "shadow_peer_base": "http://127.0.0.1:8090",
  "shadow_peer_auth": "http://127.0.0.1:8090/auth/v1.0",
  "shadow_peer_label": "Python SAIO",
  "auth_url": "http://10.0.0.10:8085/auth/v1.0"
}

## Prom node targets up
4 /4 node

## Bins
/usr/local/bin/autocos
/usr/local/bin/cosbench-rs
/usr/local/bin/cabt
/usr/local/bin/swift-console
