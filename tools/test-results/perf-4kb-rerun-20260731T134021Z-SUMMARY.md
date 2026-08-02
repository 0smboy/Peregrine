# 4KB read failure RCA + tuned rerun — 20260731T134021Z

## Verdict: **FIXED (client-side) — fail=0**

Original full-matrix WARN (`perf-test-20260731T131513Z`): `4KB_read_128` normal stage **fail=36537 / success=83.94%** after `4KB_write_128`.

### Root cause (not Swift data path)

1. **Ephemeral port / TIME_WAIT pressure** on the load host under 128 workers (~45k TIME_WAIT after write storm).
2. **Default shell `ulimit -n=1024`** on the bench process (proxy systemd already has 524288).
3. Risk amplifier: auth returns VIP `10.42.30.10`; without `ST_ENDPOINT` → node HAProxy, ILB hairpin can compound client failures.

Controlled A/B: same workload with `ST_ENDPOINT=http://10.42.30.11:8085/v1/AUTH_test` + `ulimit -n 65535` → **fail=0**.

### Tuning applied (swift1 load node)

| Knob | Value | Persist |
|------|-------|---------|
| `ulimit -n` | 65535 | `/etc/security/limits.conf` (`*` + root) |
| `net.ipv4.ip_local_port_range` | 1024–65535 | `/etc/sysctl.d/99-swift-bench.conf` |
| `net.ipv4.tcp_tw_reuse` | 1 | same |
| `net.ipv4.tcp_fin_timeout` | 15 | same |
| `ST_ENDPOINT` | `http://10.42.30.11:8085/v1/AUTH_test` | harness / env |

Harness: `Peregrine/swift-rust/tools/autocos-sweep.sh` now forces `ulimit -n 65535` and documents the sysctl.

### Retest (60s write → 60s read, 128 workers, 4000 objs × 4 cont)

| Stage | ok | fail | success | p99 |
|-------|---:|-----:|--------:|-----|
| write normal | 30801 | **0** | 100% | ~2.6s |
| read prepare | 16000 | **0** | 100% | ~2.7s |
| read normal | **377121** | **0** | 100% | ~48ms |

On-host: `/root/perf-4kb-rerun-20260731T134021Z/`  
Drive: `gdrive:Peregrine/2026-07-31-lab-456/perf-tests/20260731T134021Z-4kb-rca/`
