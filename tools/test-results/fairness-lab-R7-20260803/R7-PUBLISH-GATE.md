# R7 Stop — Four Scorecards + Publish Pack

| | |
|--|--|
| **Status** | **GREEN**（文档/证据齐；Drive optional） |
| **When** | 2026-08-03T10:08Z |

## 四卡

| Scorecard | Status | Path |
|-----------|--------|------|
| Compatibility | GREEN (compat 11/11, func 54/54) | `fairness-lab-R3-20260803` |
| Performance DIRECT | GREEN + 16MB_read WARN | `fairness-lab-R4-20260803` |
| HA-PATH | GREEN + WARN/NOISY cells | `fairness-lab-R5-20260803` |
| Chaos / Soak | GREEN (chaos 20/20 + ha-test; soak 1h fails=0) | `fairness-lab-R6-20260803` |

## 能说 / 不能说

**能说**
- R1 hub 清污 + R2 Rust 独占 + R3 CORE-PATH 等价（compat）在 Contabo 现布局下成立
- Rust DIRECT-4PROXY formal（data-path/ISO-CONFIG）对 1KB/64KB/1MB write+read 与 16MB write 有 ≥8-run 主表
- Chaos proxy-loss / object-loss / ha-test 在故障注入后收敛
- 1h soak fails=0

**不能说**
- Python formal 吞吐对比（FROZEN）
- 旧 SAIO 3.45×/3.79× 或 VIP-only 作主结论
- HA-PATH「比 DIRECT 更快/更慢」（分册；且部分 cell 与 soak 并发 NOISY）
- 16MB_read 吞吐 ACCEPT（WARN）
- L3b / plugin backlog（R8 only）

## 证据索引

见 `FOUR-SCORECARDS.json` 与各轮 `*-GATE.md` / `REPORT.html`。
