# R4 Stop — DIRECT-4PROXY Performance (Rust)

| | |
|--|--|
| **Status** | **GREEN with WARN cell** |
| **When** | 2026-08-03T07:04Z |
| **Evidence** | `runs/*/SUMMARY.json` · `SCORECARD.json` |

## Stop 验收

| 条 | 结果 |
|----|------|
| mode `perf-rust` 独占 | PASS（开跑前 gate） |
| 每声明 cell ≥8 measured | **PASS** — 8/8 cells `reps_met=true` |
| 主表仅 DIRECT-4PROXY + profile + track | **PASS** — data-path / ISO-CONFIG / rust |
| Python formal | **FROZEN** (`PYTHON_CLUSTER_ABSENT`) |
| 16MB_read 有效性 | **WARN** — prepare/normal fail_rate≈0.999；ops/s 不作 ACCEPT 吞吐 |

## Scorecard（ops/s median · DIRECT-4PROXY）

| Task | median ops/s | n | fail_rate | validity |
|------|-------------:|--:|----------:|----------|
| `16MB_read_4` | 1.02 | 8 | 0.9990 | WARN |
| `16MB_write_4` | 2.29 | 8 | 0.0000 | ACCEPT |
| `1KB_read_64` | 685.40 | 8 | 0.0000 | ACCEPT |
| `1KB_write_64` | 140.69 | 8 | 0.0000 | ACCEPT |
| `1MB_read_16` | 67.88 | 8 | 0.0000 | ACCEPT |
| `1MB_write_16` | 33.40 | 8 | 0.0000 | ACCEPT |
| `64KB_read_32` | 505.95 | 8 | 0.0000 | ACCEPT |
| `64KB_write_32` | 140.33 | 8 | 0.0000 | ACCEPT |

## 方法

- Client: **swift4**（非 VIP MASTER）
- Entry: `ST_ENDPOINT` round-robin `http://10.0.0.1–4:8085/v1/AUTH_test`（auth 广告 VIP，数据面强制 DIRECT）
- Warm-up 2 + measured 8；runtime=30s
- A-B-B-A 跨实现：Python formal 冻结，本轮单轨 Rust（记为 incomplete A/B pairing）

## 下一轮

**R4 → 允许 R5**（HA-PATH 分册）与 **R6**（chaos/soak）。
