# R1 维护窗操作单 — hub / SAIO 离 VIP MASTER

| | |
|--|--|
| **窗目标** | R1 Stop：swift1 无 `:8090/:8081`；Prometheus/console 不在 VIP MASTER；VIP 健康仍 OK |
| **窗开始** | 见 `START.txt` |
| **风险面** | 短时监控/日志空窗；console/deploy-ui 短暂不可达；**不**动 `/srv/node` 集群数据；**不**停 keepalived/haproxy/swift 集群 |
| **回滚** | swift4 上 stop hub units；swift1 上 `systemctl start prometheus loki swift-console swift-deploy-ui`；SAIO 按需从 `/etc/pyswift` `/etc/rsaio` 再起 |

## 布局目标

| 角色 | 节点 | 说明 |
|------|------|------|
| VIP MASTER + 集群 | swift1 | 仅集群面；无 SAIO / 无 Prom/console hub |
| 观测 + console hub | **swift4** | prometheus / loki / swift-console / deploy-ui |
| Alloy / node_exporter | 全节点 | 保留；Alloy push Loki → `10.0.0.4:3100` |
| SAIO（本轮） | **停在 swift1**；重建延后 R3 前（需同步 `/root/work`） | Stop 不要求 SAIO 已在别处运行 |
| memcached | 各节点集群用途 | **不动**（`10.0.0.N:11211` 属集群缓存） |

## 步骤清单

1. 采迁前 `ss` / unit 状态 → `before/`
2. 停 swift1 双 SAIO 进程（仅 `/etc/pyswift` `/etc/rsaio`）
3. 同步 hub 二进制/配置/数据 → swift4；装 unit；起服务
4. 停并 disable swift1 hub units
5. 四节点 Alloy `loki.write` → `http://10.0.0.4:3100/...`
6. console `shadow_peer_*` 改为指向未来 SAIO 位或清空标注（本轮 SAIO 已停：标 `SAIO_STOPPED`）
7. VIP healthcheck + 迁后 `ss` → `after/` + `HUB-CLEARED.md`

## 禁止

- wipe `/srv/node`
- 第二套 Keepalived
- 在 R1 未绿时开 R2 formal / R4
