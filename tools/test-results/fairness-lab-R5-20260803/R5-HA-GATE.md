# R5 Stop — HA-PATH Scorecard（分册）

| | |
|--|--|
| **Status** | **GREEN with WARN cells** |
| **When** | 2026-08-03T08:35Z |
| **Label** | **HA-PATH ONLY** — 不与 DIRECT 主表混写「更快/更慢」 |

## Stop 验收

| 条 | 结果 |
|----|------|
| 全部结果标 HA-PATH ONLY | **PASS** |
| 与 R4 分目录/分文件 | **PASS** — `fairness-lab-R5-*/` |
| ≥8 measured / cell | **PASS** — 8/8 |
| 正文无 DIRECT 对比升格 | **PASS** |

## HA-PATH ops/s median（VIP `10.0.0.10:8085`）

| Task | median | n | fail_rate | validity |
|------|-------:|--:|----------:|----------|
| `16MB_read_4` | 1.03 | 8 | 0.9950 | WARN |
| `16MB_write_4` | 2.25 | 8 | 0.0000 | ACCEPT |
| `1KB_read_64` | 82.41 | 8 | 0.0000 | ACCEPT |
| `1KB_write_64` | 136.47 | 8 | 0.0000 | ACCEPT |
| `1MB_read_16` | 15.56 | 8 | 0.6624 | WARN |
| `1MB_write_16` | 12.51 | 8 | 0.0000 | ACCEPT |
| `64KB_read_32` | 42.41 | 8 | 0.0000 | ACCEPT |
| `64KB_write_32` | 26.46 | 8 | 0.0000 | ACCEPT |

## 并发污染声明（NOISY）

R5 与 R6 1h soak（swift4 客户端）时间窗重叠（~07:18–08:18Z）。  
`1MB_read_16` fail_rate≈0.66 → **WARN/NOISY**（客户端争用，非 VIP「慢于 DIRECT」结论）。  
`16MB_read_4` 同 R4：prepare 失败 → **WARN**。

## 下一轮

R5 分册完成 → R6 chaos 已绿；soak 1h 已绿。
