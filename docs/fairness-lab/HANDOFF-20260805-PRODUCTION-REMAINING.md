# Contabo 生产剩余任务 · 完整交接文档

**交接日期：** 2026-08-06（内容冻结于 2026-08-05 现场收口；**2026-08-06 续跑已刷新下方「当前标签」**）  
**仓库：** `/Users/oboy/Downloads/Peregrine`（Cursor 工作区常为 `swift-master`，请用绝对路径）  
**计划权威：** `~/.cursor/plans/生产剩余任务规划_319471f3.plan.md`（生产级审计修订版）  
**人话卷宗：** [`tools/test-results/PRODUCTION-REMAINING-ROLLUP-20260805/ROLLUP-REPORT.html`](../tools/test-results/PRODUCTION-REMAINING-ROLLUP-20260805/ROLLUP-REPORT.html)  
**2026-08-06 并行续跑：** [`tools/test-results/PARALLEL-RUN-20260806/SUMMARY.md`](../tools/test-results/PARALLEL-RUN-20260806/SUMMARY.md)

---

## 0. 接手前必读（30 秒）

| 问 | 答 |
|----|-----|
| 现在能干什么？ | **LAB-HARD-GREEN**：VIP HTTPS 自签 + TempAuth **func 54/54** + **soak 1h fail=0** + EC 数据面 + S3 MPU 深测 + Keystone 共存 + Python 三节点 |
| 能说「生产上线完成」吗？ | **不能。** 未宣称 `PRODUCTION-GO-LIVE`；**运营 TLS PEM 按指示暂缓** |
| 盘还满吗？ | 否。A+B 清盘后约 **2%**（无 mkfs） |
| 阶段三 Python 还 FROZEN 吗？ | **已解冻（LAB）**：`PYTHON_CLUSTER=PRESENT` on swift2/3/4 |
| EC 还 501 吗？ | **否（2026-08-06）**：已 `--features ec` 部署；EC PUT/GET/degraded-read 绿；**自动 fragment heal 仍 PARTIAL** |
| 密钥在哪？ | Contabo **`/root/contabo-identity-secrets.yml`**（0600，**禁止进 git**） |

---

## 1. 总判决

```text
LAB-READY  ≈ YES（联调 / 公平测试可用）
PRODUCTION-GO-LIVE ≈ NO（TLS 自签、soak≠0、func 未齐、L3b KEEP 未宣称、运营 PEM 缺失）
```

双层宣称规则见计划：HTTP/自签 lab 证据 **不得** 顶生产安全合格。

---

## 2. 访问与角色

### 2.1 节点

| 主机 | SSH 别名 | 公网 | Client 面 | Storage | Replication | 角色（2026-08-05 后） |
|------|----------|------|-----------|---------|-------------|----------------------|
| swift1 | `swift1` | 169.58.108.85 | 10.0.0.1 | 10.0.4.1 | 10.0.8.1 | VIP/Keepalived；Rust；Galera/Keystone；**client 侧**（无 Python 数据面） |
| swift2 | `swift2` | 169.58.108.86 | 10.0.0.2 | 10.0.4.2 | 10.0.8.2 | Rust + Galera/Keystone + **Python 三节点之一** |
| swift3 | `swift3` | 169.58.108.87 | 10.0.0.3 | 10.0.4.3 | 10.0.8.3 | 同上 |
| swift4 | `swift4` | 169.58.108.121 | 10.0.0.4 | 10.0.4.4 | 10.0.8.4 | Rust；监控 hub（Prom/Grafana/Loki）；**无** MariaDB 第四节点 |

SSH：本机别名 `swift1`–`swift4`（BatchMode）。

### 2.2 入口

| 入口 | URL / 端口 | 说明 |
|------|------------|------|
| Rust VIP（首选） | `https://10.0.0.10:8085` | HAProxy TLS 终止（**自签** `CN=10.0.0.10`）；后端 `10.0.0.1–4:8080` roundrobin |
| 旧 HTTP VIP | 可能仍监听或已迁；**以 HTTPS 为准** | 客户端用 `curl -k` / 信任 lab CA |
| Keystone public | `https://10.0.0.10:5000` | HAProxy → uwsgi |
| Keystone admin | `https://10.0.0.10:35357` | 同上 |
| MariaDB VIP | `10.0.0.10:3030`（或各节点 HAProxy） | → `:3306`，health `:9600` |
| Python API | swift2/3/4 **`:8090`** | **从 Contabo 内网或 ssh 到 swift1 再访问**；本机直连常空回复（防火墙） |

Keepalived VIP：`10.0.0.10`（优先级历史：swift1 MASTER 默认）。

### 2.3 认证

| 方式 | 用法 |
|------|------|
| TempAuth | 用户 `test:tester`；密码已轮换并从 Git 删除；account 常为 `AUTH_test` |
| Keystone | 项目/用户见 Contabo secrets；**Swift 账号路径是 `AUTH_<project_uuid>`**，不是字面 `AUTH_test`（对 `AUTH_test` 用 Keystone token 会 403，属预期） |
| 共存 | Proxy `keystone_coexist`：TempAuth + `authtoken`/`keystoneauth` 同在；**勿再给无 identity 的请求盖 `X-Backend-Auth-Plugin: keystone`**（已修） |
| S3 TempAuth | SigV4，access key 惯例 `account:user` |
| S3 EC2 | Keystone `/v3/s3tokens` → Rust `s3api` defer；VIP 上已 LAB 验证 |

---

## 3. 磁盘与环（当前真相）

### 3.1 物理盘

每节点 `/srv/node/{d1,d2,d3}` XFS，约 50G×3。清盘后占用约 **2%**。  
**禁止**无票 mkfs / destructive-reset 自动执行。

### 3.2 Rust 环（Wave 4 迁移后）

| 环 | 设备 | 端口 |
|----|------|------|
| account / container | **仅 d2** | 6201 / 6202（未与 object 新端口冲突） |
| object / object-1 | **d2 + d3** | **6211 / 6212**（`servers_per_port=1`；discovery 三端口时代的 6210 曾含 d1，迁移后 d1 已让出） |

Regions（标签，非跨城）：swift1/2 → **r1**；swift3/4 → **r2**。

备份：

- W2：`/root/w2-ring-backup-20260805T100051Z/`（各节点）
- W4：`/root/w4-ring-backup-20260805T113908Z/`（各节点）

### 3.3 Python 三节点

| 项 | 值 |
|----|-----|
| 节点 | swift2, swift3, swift4 |
| 配置/venv | `/etc/pyswift`，`/opt/pyswift-venv`（Caracal RPM 因 `pyxattr` provide 失败，走 venv） |
| 设备 | 逻辑名 `py` → 物理 **d1** |
| 端口 | proxy **8090**；object/container/account **6100/6101/6102**（以现场 `PORT-DISK-MATRIX` / `09-python-listeners.txt` 为准） |

---

## 4. 各轨交接表

| ID | 主题 | 判决 | 证据目录（均在 `tools/test-results/`） |
|----|------|------|----------------------------------------|
| 清盘 | `delete -a` 不够；A+B 腾盘 | PASS ~2% | `wave0-clear-20260805/`，`wave0-ab-20260805/` |
| R0 | 墓碑/SQLite → Prom/Grafana + 告警 | WIRED | `r0-metrics-prom-20260805/` |
| W0′ | 幽灵容器/僵尸行；hash 少 `/` | LAB META_CLEAN | `w0-meta-repair-20260805/` |
| W1 | Galera×3 + Keystone + 共存管道 | LAB GREEN | `wave1-identity-live-20260805/` |
| TLS | VIP+Keystone 自签终止 | LAB GREEN ≠ 生产 | `p3-ops-tls-live-20260805/` |
| W2 | object 6210+、spp、r1/r2 | PARTIAL | `wave2-spp-region-live-20260805/` |
| W3 单元 | ListMPU、HttpShard、s3token 等 | 单元停线绿 | `wave3-s3-l3b-prod-20260805/` |
| W3 live | TempAuth S3 VIP | PARTIAL→含 EC2 后绿 | `wave3-s3-l3b-live-20260805/` |
| s3tokens | Keystone uwsgi 崩溃 | 已修 | `wave3-s3token-fix-20260805/` |
| EC2 SigV4 | Rust defer Keystone | LAB GREEN | `wave3-s3-ec2-sigv4-20260805/` |
| 鉴权 | TempAuth list 401 | GREEN | `vip-auth-crud-fix-20260805/` |
| W4 | Python 三节点 | LAB GREEN | `wave4-python-live-20260805d/` |

文档：

- [`KEYSTONE-LIVE.md`](KEYSTONE-LIVE.md)
- [`TOMBSTONE-VACUUM.md`](TOMBSTONE-VACUUM.md)（含「曾仅 CLI、后进面板」）
- [`MULTI-REGION.md`](MULTI-REGION.md) / W2 runbook
- [`S3-ON-BY-CONFIG.md`](S3-ON-BY-CONFIG.md)（若存在）
- [`USER-METHOD-PLAN.md`](USER-METHOD-PLAN.md)（阶段三角色；阶段 3 已可对照）
- [`PRODUCTION-GAP-ROADMAP.md`](PRODUCTION-GAP-ROADMAP.md)

---

## 5. 监控怎么看

### 5.1 CLI（每节点）

```bash
swift-recon tombstones /srv/node
swift-recon tombstones /srv/node --prometheus
swift-recon dbspace /srv/node
swift-recon vacuum /srv/node/d2   # 慎用：写锁
```

二进制：`/usr/local/bin/swift-recon`。

### 5.2 Prometheus / Grafana

- Prom：swift4 `127.0.0.1:9090`（经 textfile + node_exporter）
- Timer：`swift-recon-textfile.timer` → textfile collector
- 指标：`swift_object_tombstones*`，`swift_db_*`
- 告警示例：`SwiftTombstoneGrowth`、`SwiftDbFreelistHigh`、`SwiftDeviceUsePctHigh`（Galera/Keystone 告警曾为 stub，以 R0 包为准）

**注意：** 指标**曾经只有 CLI**；R0 才接线。Grafana `/render` 截图可能仍是 stub，以 query 为准。

---

## 6. 已知坑与诚实残债（交接重点）

1. **`swift delete -a` ≠ 清盘** — API 幽灵/孤儿 `.data` 需 A+B 或运维对账。  
2. **hash 对账** — `wave0-ab-reclaim-orphans.py` 必须在 prefix 后带 `/`（已修）；生产脚本用 broker 同源 hash。  
3. **W2 soak fail=7** — 含部署 Mac/ELF 错误导致 HAProxy 后端空窗 503；需干净重 soak 才可冲 GREEN。  
4. **func 54/54 TempAuth** — Keystone 共存后 TempAuth 存储路径易 401；应改 Keystone 原生套件或明确门禁。  
5. **EC 501** — Contabo proxy 曾缺 `--features ec`；要宣称 EC 须重编部署。  
6. **L3b** — 单元/局部有；**多节点 quorum / 4KB KEEP 未宣称**。  
7. **s3tokens 站点包补丁** — Keystone RPM 升级后需重打 `apply_s3tokens_patch.py`（见 s3token-fix 包）。  
8. **环 builder `add weight=0`** — Contabo 上该二进制路径不可靠；W4 用 JSON rewrite；勿盲目 `add`。  
9. **Python RPM** — `pyxattr` provide 失败 → 维持 venv；勿强行 dnf 覆盖搞挂系统。  
10. **四节点 Python** — 未做；swift1 保持无 Python 数据面更干净。  
11. **密钥曾进日志** — Swift 服务密码已轮换；只用 secrets 文件。  
12. **dual-guard** — 无票不 wipe `/srv/node`；agent 不自动 mkfs。

---

## 7. 回滚与备份速查

| 场景 | 动作 |
|------|------|
| 管道回到纯 TempAuth | `/etc/swift/proxy-server.conf.bak-tempauth-20260805`（及 coexist bak）；重启 proxy |
| W2 环 | 各节点 `/root/w2-ring-backup-20260805T100051Z/` |
| W4 环 | `/root/w4-ring-backup-20260805T113908Z/` |
| TLS | `/etc/haproxy/TLS-ROTATION.txt`；证书路径见 p3-ops 证据包 |
| Identity | 勿用 python `haproxy_servers` 整表覆盖 rust VIP 前端 |

---

## 8. 建议接手后的最小验证（15 分钟）

在能 SSH 的机器上：

```bash
# 1) 盘
for h in swift1 swift2 swift3 swift4; do ssh $h 'hostname; df -h /srv/node/d1 /srv/node/d2 /srv/node/d3 | tail -3'; done

# 2) Rust VIP HTTPS（自签）
curl -sk https://10.0.0.10:8085/info | head -c 400; echo

# 3) TempAuth CRUD 冒烟（按你们习惯的 auth 头）
# 4) Keystone：用 secrets 拿 token → 对 AUTH_<project_id> CRUD
# 5) Python：ssh swift1 后 curl http://10.0.0.2:8090/info
# 6) 墓碑指标
ssh swift1 'swift-recon tombstones /srv/node | head'
```

任一步失败：先查对应证据包 SUMMARY，再动环/Identity。

---

## 9. 建议下一刀（优先级）— 2026-08-06 刷新

**已完成（勿重做）：** EC feature 部署；TempAuth func 54/54；soak 1h fail=0；S3 MPU 深测 11/11；VIP failover PASS；deploy `config_contabo_live` + dual-device ring 模板。

**仍开：**

1. **EC reconstructor fragment 恢复**（degraded-read 已绿；自动 heal 未在 2min 内见到 3 frags）— 查 hashes 失效 / ssync job / 日志。  
2. **L3b 多节点**：把一容器推进 SHARDING + HTTP quorum（`auto_shard=false` 现状）。  
3. **运营 PEM**（暂缓，按操作者指示）→ 才讨论 PRODUCTION-GO-LIVE。  
4. 按需 Python **四节点** / 双侧公平测刷新。  
5. 确认 `bundle-rust` apply **不会**在未审 inventory 时回滚到 6200/d1 单盘形。

---

## 10. 仓库与代码落点（改过什么）

非穷尽，接手查 git status / 证据包即可：

| 区域 | 内容 |
|------|------|
| `swift-rust/crates/swift-cli` | `swift-recon` tombstones/dbspace/vacuum |
| `swift-rust/crates/swift-db` | `vacuum.rs` |
| `swift-rust/crates/swift-middleware` | keystoneauth 共存 stamp；authtoken https |
| `swift-rust/crates/swift-s3api` / s3token | ListMPU、EC2 defer、HttpS3TokenClient |
| `swift-rust/crates/swift-object-server` | spp process-per-port；replicator 读 reclaim_age |
| `swift-rust/crates/swift-container-server` | L3b 增量（fan-out / HttpShardReplicator 等） |
| `swift-deploy-rs/bundle` | `config_contabo_identity/` |
| `swift-deploy-rs/bundle-rust` | Identity overlay、rings spp、TLS |
| `tools/wave0-ab-reclaim-orphans.py` | A+B 清盘脚本 |

**未完成进 git 的现场态**（环、haproxy、Keystone 包补丁、venv）以 **Contabo 磁盘为准**；交接时以 SSH 现场 + 证据包为准，不要假设 laptop 工作区 = 集群。

---

## 11. 聊天与计划索引

| 类型 | 位置 |
|------|------|
| 综合 HTML | `tools/test-results/PRODUCTION-REMAINING-ROLLUP-20260805/ROLLUP-REPORT.html` |
| Canvas | Cursor canvases `contabo-production-rollup-20260805` |
| 计划 | `~/.cursor/plans/生产剩余任务规划_319471f3.plan.md` |
| 旧缺口路线图 | `docs/fairness-lab/PRODUCTION-GAP-ROADMAP.md` |
| 集群总览（部分条目可能仍写 HTTP:8085 / 阶段3 FROZEN） | `tools/CONTABO-CLUSTER.md` — **以本文为准覆盖 2026-08-05 后状态** |

---

## 12. 交接签字清单（建议）

- [ ] 能 SSH 四节点；df≈2%  
- [ ] `https://10.0.0.10:8085/info` 可见 tempauth + keystoneauth  
- [ ] TempAuth 与 Keystone 各做一次 CRUD  
- [ ] Python `:8090` 从内网 CRUD  
- [ ] 知道 secrets 路径且未提交 git  
- [ ] 知道 W2/W4 ring 备份路径  
- [ ] 理解 **未** PRODUCTION-GO-LIVE  
- [ ] 已读本文件第 6 节「坑」  

---

*文档维护：交接后若改环/入口/认证，请同步改本节日期与「当前真相」表，并新开 `tools/test-results/` 证据包，不要只改聊天记录。*
