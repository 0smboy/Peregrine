# R3 Stop — COMPAT GATE

| | |
|--|--|
| **Status** | **GREEN** |
| **When** | 2026-08-03T05:35Z |
| **Evidence** | `compatibility/` · `func/` · `saio/` · `layout/` |

## Stop 验收

| 条 | 结果 | 证据 |
|----|------|------|
| L1 CORE-PATH `compat-diff` fail=0 | **PASS** | `compatibility/SUMMARY.json` → gate=PASS cases=11 |
| Layout 仍 R1-clean | **PASS** | swift1 无 `:8090/:8081`；hub=swift4；SAIO 在 **swift3** |
| VIP + SAIO func-suite | **PASS** | VIP 54/54；rust-saio 54/54；py-saio **rerun** 54/54 |
| unsupported 仅登记 | **PASS** | 无未登记 unsupported；首轮 py HEAD flake 已复测消除 |
| console shadow_peer | **PASS** | swift4 → `http://10.0.0.3:8090` (Python SAIO @swift3) |

## SAIO 重建

| 项 | 值 |
|----|-----|
| Host | **swift3** (`10.0.0.3`) |
| Py | `:8090` bind `10.0.0.3` |
| Rust | `:8081` bind `10.0.0.3` |
| Binaries | rsync from swift1 `/root/work/{swift-rust,pyswift-venv,swift-master}` |
| Disk | `/srv/node/d1/{pysaio,rsaio}`（未 wipe 集群数据） |
| memcached | loopback `:11211`（本轮为 SAIO 新装；未改其他节点集群 memcached） |

## 数字纪律

- 本轮 **无** 吞吐主结论；旧 SAIO 3.45×/3.79× 仍 **NOISY**
- func-suite 标签：**CORE-PATH-ONLY**

## 下一轮入口

**R3 GREEN → 允许开 R4**（Rust DIRECT-4PROXY formal；Python formal 仍 FROZEN）。
