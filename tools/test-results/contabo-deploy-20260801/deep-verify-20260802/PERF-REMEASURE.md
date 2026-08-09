# Clean-load perf re-measure — 2026-08-02

- **Client:** swift4 (not VIP MASTER)
- **Target:** Keepalived VIP `http://10.0.0.10:8085`
- **Auth:** `test:tester` / `PEREGRINE_LAB_KEY_REQUIRED`
- **Prod knobs:** workers=16, `container_update_mode=sync`, `fsync_on_close=true`, `reuse_port=false`
- **Raw:** `cleanload-swift4/SUMMARY.json` (last rep per task log)

## Results (normal stage)

| Task | ok | fail | success | ~ops/s | p99 |
|------|---:|-----:|--------:|-------:|----:|
| 4KB_write_128 / 60s | 8301 | 0 | 100% | 138.4 | 1.84 s |
| 4KB_read_128 / 60s | 63272 | 0 | 100% | 1054.5 | 0.37 s |
| 1MB_write_32 / 60s | 2516 | 0 | 100% | 41.9 | 1.34 s |
| 1MB_read_32 / 60s | 4793 | 0 | 100% | 79.9 | 1.25 s |
| 16MB_write_8 / 180s | 497 | 0 | 100% | 2.8 | 5.15 s |
| 16MB_read_8 / 120s | 632 | **6267** | **9.16%** | 5.3 | 3.13 s |

16MB prepare seeded **80/80** (100%) with longer budget; normal-stage failures remain.
**Verdict:** keep **ACCEPT_WITH_WARN** for 16MB read; do not upgrade by prose.

## SAIO 1KB PUT re-check (same host)

| Side | c1 median | c32 median |
|------|----------:|-----------:|
| Rust `:8081` | 54.3 | 236.7 |
| Python `:8090` | 26.5 | 68.6 |

Ratio c32 ≈ **3.45×** (phase0 pack was 3.79×). Drift >10% on some cells vs
`saio_phase0`; absolute conclusion unchanged (Rust ≫ Python). Published table
keeps phase0 medians as the dated evidence pack; this re-check is recorded here.
