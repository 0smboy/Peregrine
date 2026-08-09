# Contabo Swift full deploy — SUMMARY (2026-08-01)

- **Deploy verdict:** ACCEPT
- **Cluster:** Contabo 4-node greenfield; VIP `10.0.0.10:8085`; auth `test:tester` / `PEREGRINE_LAB_KEY_REQUIRED`
- **Cutover doc:** [`CONTABO-CLUSTER.md`](../../CONTABO-CLUSTER.md)
- **On-host evidence:** `/root/contabo-deploy-20260801T125749Z/`

## Install gates (G0–G8)

All PASS. VIP auth 100/100; func-suite 54/54 on VIP + node HAProxy; HA drill;
EC heal; Prometheus nodes_up=4; console APIs; EC-linked bins.

## Deep suites

| Suite | Verdict |
|-------|---------|
| R1 func ×4 + ACL/meta/edge + rust-saio | FAIL=0 |
| R2 HA + console + recon + **py-saio** | FAIL=0 |
| Perf (bench/cbench/wbench/autocos) | ACCEPT_WITH_WARN; **4KB fail=0** |
| Lab12 deep | **ACCEPT** — Shadow dual `breaking=0` (run `r1785596893-bc2f9c`); chaos×4 phase=done; nodes HA 20/20 last |

Lab12 details: `lab12-deep-final/SUMMARY.md` on host (mirrored under this tree when synced).

## Parity fixes landed (Rust)

- 416 body text + multipart `Content-Range:` header name
- Account/container HEAD `Content-Length: 0` / `Accept-Ranges`
- PUT 422 HTML body + `Last-Modified` from request timestamp
- Shadow: multipart/byteranges body digest skipped when lengths match (Python random boundary)

## Constraints retained

- No disk wipe of `/srv/node/d{1,2,3}`
- Keepalived VIP only (no second VRRP)
- HAProxy backends local-only (Rust tempauth per-process)
- Security hardening (firewall / disable password SSH) **not** in this pass

## Write-path lever A/B (2026-08-02) — CLOSED

| Lever | Decision | Primary note |
|-------|----------|--------------|
| L1a parallel `container_update` | **KEEP** (deployed) | `4KB_write_128` c1 ≈ **+24% PUT/s**, p99 ≈ **−30%** vs Phase0; fail=0 |
| L1b always-async | **DROP** (reverted to sync) | ≈0.95× Phase0; code kept behind `container_update_mode=async` |
| L3a multi-container | **OPS KEEP** | c4/c1 ≈1.19× @128; sharding (L3b) deferred |
| L2 `fsync_on_close=false` | **DROP** | +4.9% &lt; 10% gate |
| L4 `SO_REUSEPORT` | **DROP** | 0.84× baseline |
| L5 tokio | SKIP / ADR | SAIO Rust 1KB c32 ≈ **3.8×** Python |

Evidence pack: `perf-levers/SUMMARY.json` (+ Phase0 / L1a–L4 DECISION+COMPARE).  
Git: Peregrine `main` @ `bda936f`.

## Drive

`gdrive:Peregrine/2026-08-01-contabo/`
