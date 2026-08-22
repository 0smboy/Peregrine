# 独立测试资源申请（2026-08-22）

**SUPERSEDED BY OWNER CONSTRAINT 2026-08-22.**  
Owner 决定：Swift1–4 即本项目测试机，不新增 builder / lab-a / lab-b / staging。G0–G8 在四机分阶段复用上完成。本文件保留为史实，**不得删除**，也**不得**再当作 G7/G8 blocker。

现行角色与模式：`PEREGRINE-FOUR-NODE-G0-G8-EXECUTION-DIRECTIVE-20260822.md`。

~~**状态：BLOCKER。** 现有 swift1–4 **全部**跑生产 `:8080` + HAProxy `:8085`。swift3 是生产节点兼唯一 Linux 编译机，**不是**干净测试机。把 RSAIO 迁到 swift3 **不能**关闭 G7/G8。~~

本文件是向操作者申请资源的清单。在资源到位前：

- G6/G7/G8 = **NOT RUN / INVALID**
- 现有 SAIO 只允许 **compatibility feedback**
- 禁止把 cgroup 套在生产节点上假装干净主机

## 需要的四类车道

| 车道 | 规格 | 用途 | 禁止 |
|---|---|---|---|
| 独立 Rocky 9 builder | 与生产同 glibc/kernel 族；≥8 核、≥16G、≥80G 空盘；`CARGO_HOME` 本地 | 离线 `--locked` 编制品；写入 `git_sha`/`source_tree_sha256`/`cargo_lock`/`rustc -Vv` | 不跑 SAIO、不跑 soak、不跑生产二进制 |
| lab-a + lab-b | **两台全新、同规格、无生产服务**；相同镜像/磁盘/NIC；cgroup v2；NTP | AB/BA、G7、G8 P1/P2 | 不编译；不跑 HAProxy VIP；不混生产 rings |
| 独立 load generator | 第三台（或容器），不与 lab-a/b 共磁盘/IRQ | 发压、slowloris、1k slow PUT、50k idle 客户端 | 客户端本身不得成为瓶颈 |
| 四节点 staging | 生产同构（Keepalived/HAProxy/rings **副本**、独立 account） | G6 probe、P3、24h soak、滚动演练 | **禁止客户数据/生产 rings**；禁止在现网 probe |

## 明确不接受的替代

- 在 swift2 上 cgroup 限制 rsaio 然后跑 G7
- 把 RSAIO 搬到 swift3
- 用 `PEREGRINE_SOAK_SECS=30` 声称 24h G8
- idle 测试 opened<target 仍 PASS

## 解除条件（owner：实验室操作者）

1. builder SSH 可达，与现网隔离。
2. lab-a/lab-b `ss -lntp` 无 `:8080/:8085`，无 VIP。
3. loadgen 独立。
4. staging 四节点与生产 SHA 对齐流程，但 rings/account 独立。

未签字解除前，Grok Build **不得**把 G6/G7/G8 标 GREEN。
