# HA + Keepalived correction (2026-08-04)

User call: prior “负载均衡 HA+keepalived” was useless / added friction.
This note records what was wrong, what changed, and what was re-tested.

## Before (why it looked useless)

| Piece | Reality |
|-------|---------|
| HAProxy backends | Only `127.0.0.1:8080` on each node |
| Reason | Rust tempauth token was per-process memory → fan-out → **401** |
| VIP `10.0.0.10:8085` | Failover IP only; throughput = **one** local proxy |
| VIP bind | Only swift1 had `bind 10.0.0.10:8085` |
| Failover | VIP moved to swift2, but **8085 connection refused** (no listener) |

So “VIP vs DIRECT-4PROXY” was an unfair path comparison, not a real LB test.

## Fixes applied

1. **Shared tempauth** — HMAC token `AUTH_tkv1.<payload>.<mac>` using
   `swift_hash_path_prefix:suffix` from `swift.conf`. Deployed new
   `swift-proxy-server` to all four nodes (backup `.bak.pre-ha-lb`).
2. **Real pool** — on all nodes, HAProxy backends:
   `s1..s4` → `10.0.0.1..4:8080 check`, `balance roundrobin`
   (cfg backup `.bak.pre-ha-lb`).
3. **VIP bind everywhere** — each node binds `10.0.0.N:8085` **and**
   `10.0.0.10:8085` with `ip_nonlocal_bind=1` (cfg backup `.bak.pre-vip-bind.*`).

## Verification (client = swift4, not laptop)

Laptop → `10.0.0.*` is flaky (timeout / empty reply). All pass/fail below
are **in-cluster**.

| Check | Result |
|-------|--------|
| VIP holder default | swift1 |
| VIP `/auth/v1.0` | 200, `AUTH_tkv1.*` |
| Same token → proxy1..4 `:8080` | 200 / 200 / 200 / 200 |
| VIP PUT/GET object `ha-lb-verify/obj1` | 201 / 200, body MATCH |
| VIP 40× account GET | 40/40 |
| VIP 60× GET fanout (HAProxy stats delta) | s1:+15 s2:+16 s3:+15 s4:+15, all UP |
| Stop keepalived+haproxy on swift1 | VIP → **swift2**, listener on VIP |
| After failover: auth + acct + obj + 20 GET | 200 / 200 / 200 / 20/20 |
| Restore swift1 services | VIP → swift1, auth 200 |

## Verdict

VIP is now a **real load-balanced + failover** front door to four proxies.
Old R5 “HA-PATH ONLY” numbers remain historical noise for throughput claims;
re-run perf on VIP if you need an apples-to-apples LB scorecard.

## Ops notes

- Priorities: swift1=140, swift2=130, swift3=120, swift4=110 (all BACKUP election).
- Stats: `ssh swiftN 'curl -su admin:admin http://127.0.0.1:8404/stats\;csv'`
  backend name `swift_back`, servers `s1..s4`.
- Do not revert backends to loopback without also removing shared tempauth.
