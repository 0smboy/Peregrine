# R2 Stop — MODE GATE

| | |
|--|--|
| **Status** | **GREEN**（Rust 独占可证；Python formal 轨冻结） |
| **When** | 2026-08-03T05:04Z |
| **Evidence** | `logs/` · `residual/` · `RING-12-FLOW.md` |

## Stop 验收

| 条 | 结果 | 证据 |
|----|------|------|
| `perf-rust`：无 Python SAIO / openstack-swift 残留；Rust proxy 起 | **PASS** | `logs/perf-rust.txt` → `MODE_GATE=PASS`；四节点 `GATE_OK` |
| `perf-python`：无全量 Py 集群则冻结 | **PYTHON_CLUSTER_ABSENT** | `logs/perf-python.txt` — 四节点 `openstack-swift-*` unit count=0；**未**停 Rust |
| destructive reset 流程演练 | **PASS (dry)** | `logs/destructive-reset-dry.txt` — inventory_ok；agent exit **3**（拒自动 wipe） |
| VIP 仍健康 | **PASS** | `logs/vip-after-perf-rust.txt` → `vip=200` |

## 残留检查摘要（perf-rust）

| Host | :8081/:8090 | SAIO procs | swift-proxy | openstack-swift |
|------|-------------|------------|-------------|-----------------|
| swift1 | clear | NONE | active | absent |
| swift2 | clear | NONE | active | absent |
| swift3 | clear | NONE | active | absent |
| swift4 | clear | NONE | active | absent |

原始：`residual/perf-rust-*.txt` · `residual/final-*.txt`

## 工具固化（本轮改动）

`tools/fairness-lab/scripts/mode-switch.sh`：

- 停 `/etc/pyswift` `/etc/rsaio` SAIO（不碰 `/etc/swift`）
- `gate_perf_rust` 机械门禁（监听 + unit + proc）
- `perf-python` 无 unit 时输出 `PYTHON_CLUSTER_ABSENT` 并**拒绝拆 Rust**
- `RUST_UNITS` 含 `swift-container-updater`

`destructive-reset.sh`：inventory 接受 `by-uuid`（仍禁 `/dev/sdX`）

## 冻结声明

| 轨 | 状态 |
|----|------|
| Rust Performance formal（R4 DIRECT-4PROXY） | **允许进入 R3 后开**（R2 Rust 独占绿） |
| Python Performance formal | **FROZEN** — `PYTHON_CLUSTER_ABSENT`，直至部署 4 节点 openstack-swift 或等价全量 Py 集群 |
| Compatibility SAIO A/B | 不依赖本门禁；R3 前需在 **swift3** 重建 SAIO（见 R1） |

## 下一轮入口

**R2 GREEN → 允许开 R3**（compat-diff + func-suite 在非 hub 污染布局下重跑）。  
**禁止**在双实现残留监听时开 R4（本轮已证无残留）。
