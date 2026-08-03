# Performance 模式 · 12 盘 ring 流程（文档化）

权威：`docs/fairness-lab/MODES.md` · `CONFIG-PARITY.md`。  
本文件只固化 **操作顺序**；R2 **不**执行 wipe / 不换 ring。

## 前置

1. `mode-switch.sh perf-rust`（或未来 `perf-python`）门禁绿  
2. 客户端非 VIP MASTER；入口计划为 `DIRECT-4PROXY`  
3. 若需空盘基线：人工票 +  
   `ALLOW_DESTRUCTIVE_RESET=YES CONFIRM_TICKET=<id> destructive-reset.sh inventory/devices.json`  
   → agent 仅校验 inventory（exit 3）；**人工**按 by-uuid 执行 wipe

## Ring 参数（Performance）

| 项 | 值 |
|----|-----|
| devices | 12 = 4 节点 × `{d1,d2,d3}` |
| part_power | **11** |
| replicas | 3（default policy） |
| ports | object 6200 / container 6201 / account 6202（storage plane `10.0.4.N`） |
| checksum | `sha256sum /etc/swift/*.ring.gz` → 写入 run manifest |

## 建议命令骨架（操作员）

```bash
# on build host with swift-ring-builder + current /etc/swift
cd /etc/swift
for name in account container object object-1; do
  # create / add 12 devices / rebalance — exact add lines from inventory
  :
done
# push rings to all nodes; restart swift-* ; record checksums
```

EC policy `object-1` 与 default 共用 object port；fragment 布局跟 Contabo 既有 `ec-2-1`。

## R4 挂钩

- 每个 formal run manifest 必须含 ring checksum + `mode=perf-rust` + `entry=DIRECT-4PROXY`  
- 换 ring 后丢弃 warm-up；再开 A-B-B-A cell
