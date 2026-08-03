# R1 Stop — HUB-CLEARED

| | |
|--|--|
| **Status** | **GREEN** |
| **When** | 2026-08-03T04:42Z |
| **Evidence** | `before/` · `after/` · `MAINTENANCE-WINDOW.md` |

## Stop 验收

| 条 | 结果 | 证据 |
|----|------|------|
| swift1 无 `:8090/:8081` | **PASS** | `after/swift1.txt` — SS 无该端口；SAIO=NONE |
| Prometheus/console 不在 VIP MASTER | **PASS** | swift1 hub units=`inactive`；swift4 `prometheus/loki/console/deploy-ui`=`active`，监听 `127.0.0.1:9090/9000/8789` + `*:3100` |
| 集群 VIP 健康仍 OK | **PASS** | `after/vip-auth.txt` → `HTTP/1.1 200 OK`，`X-Storage-Url: http://10.0.0.10:8085/v1/AUTH_test` |

## 迁前 → 迁后（swift1 关键端口）

| 端口 | 迁前 (MASTER) | 迁后 |
|------|---------------|------|
| 8090 Py-SAIO | LISTEN 127.0.0.1 | **gone** |
| 8081 Rust-SAIO | LISTEN 127.0.0.1 | **gone** |
| 9090 Prometheus | LISTEN 127.0.0.1 | **gone** (→ swift4) |
| 3100 Loki | LISTEN * | **gone** (→ swift4) |
| 9000 console | LISTEN 127.0.0.1 | **gone** (→ swift4) |
| 8789 deploy-ui | LISTEN 127.0.0.1 | **gone** (→ swift4) |
| 8085 haproxy + VIP | kept | kept |
| 11211 memcached | kept（集群缓存，未动） | kept |

## 新布局

| 角色 | 节点 |
|------|------|
| VIP MASTER + 集群数据面 | **swift1**（已清 hub/SAIO） |
| Observability + console hub | **swift4** |
| Alloy → Loki | 全节点 `http://10.0.0.4:3100/loki/api/v1/push` |
| 双 SAIO | **已停**；配置仍在 swift1 `/etc/pyswift` `/etc/rsaio`，**未**在监控机重建。重建目标：**swift3**（R3 前，需同步 `/root/work`） |

## 操作员访问变更

```bash
# console / prom / loki（原打到 swift1，现打到 swift4）
ssh -L 9000:127.0.0.1:9000 -L 9090:127.0.0.1:9090 -L 3100:127.0.0.1:3100 swift4
```

## 明确未做（不挡 R1 Stop）

- SAIO 迁到 swift3（需 ~1.5G `/root/work` 同步）→ R3 入口前完成
- memcached 迁出（属集群，保留）
- `/srv/node` wipe（禁止无票）
- R2 mode-switch formal

## 下一轮入口

**R1 GREEN → 允许开 R2**（Performance 模式独占机械）。
