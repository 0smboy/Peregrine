# Peregrine 四机 G0-G8 生产级验收执行令

日期：2026-08-22  
适用对象：Grok Build  
代码基线：`checkpoint/g0-g3-integration-20260822` / `8d6ee60381e40df624ad536780a04d4de3a948a9`  
环境：Swift1、Swift2、Swift3、Swift4 均为测试机器，无新增服务器

## 0. Owner 决策，立即生效

此前“Swift1-4 是生产节点，绝不允许动 VIP / HAProxy / Keepalived / :8080”的前提已经被 owner 更正：

> Swift1-4 是本项目现有的测试机器。没有额外 builder、lab-a、lab-b、loadgen 或 staging 资源。本轮就在这四台上完成验收。

因此：

1. `docs/fairness-lab/LAB-RESOURCE-REQUEST-20260822.md` 不再是阻塞条件。保留文件作为历史记录，但标记 `SUPERSEDED BY OWNER CONSTRAINT 2026-08-22`，不得删除。
2. 不再等待新机器。立即从 `8d6ee60` 开始 S3 native async 改造。
3. Swift1-4 必须按阶段切换角色。禁止试图同时保留四节点目标集群、独立 builder 和独立 loadgen。
4. 允许在书面维护窗口内停止测试机上的 VIP、HAProxy、Keepalived、`:8080` 和后台 daemon，但必须先冻结现场、使用测试专用数据根和配置、保留一键回滚。禁止盲改和删除现有基线。
5. 当前 `/usr/local/bin` SHA `ab5cb95c...` 和 RSAIO `f47d480b...` 只作为旧基线。最终 G0 必须使用从新的干净提交重建、哈希一致的候选制品。

## 1. 最终实验室形态

四台机器采用时间复用，不采用永久固定角色。

| 模式 | Swift1 | Swift2 | Swift3 | Swift4 | 回答的问题 |
|---|---|---|---|---|---|
| M0 冻结/开发 | Python SAIO oracle | Rust SAIO candidate | 唯一 Linux builder | controller/证据机 | S3 小步改造、G0-G3 |
| M1 官方兼容 | Python oracle | Rust candidate | builder 停止后空闲 | 唯一 test runner | G4/G5，按 test name 差分 |
| M2 单机 crossover | Python/Rust 轮换 | Rust/Python 轮换 | 被动观测，不编译 | 独立 loadgen | G7、P1、P2、AB/BA |
| M3 三节点 staging | target node 1 | target node 2 | target node 3，禁止编译 | 独立 loadgen/controller | G6、P3、24h soak |

生产形态主证明使用：

```text
Swift4 loadgen
      |
      v
test VIP / HAProxy
      |
      +--> Swift1 proxy + storage
      +--> Swift2 proxy + storage
      +--> Swift3 proxy + storage
```

三副本策略在三节点上具有完整的节点故障、复制、重构和 quorum 语义。它是本轮 P3 的预注册目标拓扑。

### 可以关闭的门

- G0-G5：可以。
- G6：可以，在 Swift1-3 staging 上跑官方 probe。
- G7：可以，Swift4 作为独立 loadgen，Swift1/2 做 AB/BA 单机 crossover；集群类故障在 Swift1-3 上补齐。
- G8 P1/P2：可以，Swift1/2 crossover，Swift4 发压。
- G8 P3：可以，Swift1-3 同一套三节点硬件先跑 Python、清场后跑 Rust，Swift4 发压。
- 24h soak：可以，Swift1-3 target，Swift4 连续发压。

### 不能宣称的内容

本轮不能宣称“四个 storage target 节点加独立第五台 loadgen 的峰值吞吐”。最终报告必须写：

```text
Validated production topology: 3 target nodes + 1 independent load generator
Four-target-node peak throughput: NOT MEASURED in this lab
```

这不阻止 G0-G8 对预注册三节点生产拓扑验收，但禁止把结果外推成任意规模集群线性性能。

## 2. 先修正当前现场，不要开始跑大套件

### 2.1 保留 dirty tree，建立干净开发线

当前 `checkpoint/g0-g3-integration-20260822` 的 HEAD 是 `8d6ee60`，但工作树在该提交之上仍有已修改和未跟踪文件。不得 reset、clean、覆盖或从当前目录直接制作发布制品。

强制动作：

1. 保留 `.agent-handoff/workflow-runs/20260822-g0-checkpoint/` 全部证据。
2. 保留当前 dirty tree，尤其不要碰 monitoring、OAuth、临时证据和用户文件。
3. 从 `8d6ee60` 创建独立干净 worktree 和分支 `g3/s3-native-async-20260822`。
4. S3 每一片改造形成独立可审查 commit。不得把报告、监控凭据或无关工具混入产品提交。
5. 最终候选只能从干净 commit 在 Swift3 离线 `--locked` 构建。

### 2.2 改正 gate report 和 preflight 的错误前提

`GATE-REPORT-20260822.md` 应追加 owner correction：Swift1-4 是测试资源，外部资源申请已取消；G1 不再因“机器名字叫生产节点”永久 RED。

当前 preflight 把 `swift2_vip_present` 直接推导成 `host_production_traffic=true`。这在新实验模型中不成立：VIP 可能是 P3 被测系统的一部分，VIP 存在不代表有非实验流量。

改为模式感知、实测闭环：

- `LAB-MODE.json` 声明本轮角色、允许的进程、监听端口、VIP、target SHA、loadgen IP 和测试窗口。
- M2 中，旧 `/etc/swift`、HAProxy、Keepalived、复制进程和所有非本轮服务必须停止，VIP 必须撤下。
- M3 中，test VIP / HAProxy 可以存在，但只允许 Swift4 的已登记测试流量。
- `uncontrolled_competing_traffic = 0` 必须由监听器、连接、HAProxy 日志、进程和 NIC 采样共同证明，禁止操作者布尔值。
- preflight 若发现模式外进程、外部连接、编译进程或后台扫描，立即 ABORT。

保留 T5 的用户可见标签 `host production traffic = 0`，但 reason 必须写明实际测量：`no uncontrolled traffic; only registered loadgen`。

## 3. 实验模式切换必须可恢复

第一次停止任何现有服务前，生成 `BASELINE-RESTORE-BUNDLE`：

- 四机 `ss`、进程、systemd、VIP、路由、接口、挂载、cgroup、sysctl、ulimit。
- `/etc/swift`、HAProxy、Keepalived、rings、service units 的归档及 SHA-256。
- `/usr/local/bin/swift-*`、RSAIO 和 Python venv 的 SHA/commit。
- 数据盘设备、文件系统、mount options、剩余空间和 SMART/虚拟盘信息。
- 明确的 stop、start、restore、verify 命令，先做 dry-run。

测试数据必须使用独立配置根、独立数据根、独立 account 前缀和 run UUID。禁止清理现有基线数据目录。每轮清场只能命中 manifest 中列出的测试路径，路径解析失败立即停止。

每次模式切换执行：

```text
capture -> validate target list -> stop old mode -> verify quiescent
-> activate new mode -> preflight -> run -> collect -> deactivate
-> verify cleanup
```

M2/M3 开始前，Swift3 已冻结制品并停止编译；进入 M3 前重启 Swift3，证明无 cargo/rustc、无旧服务、page cache 和后台 IO 已回到预注册状态。

## 4. 代码与测试必须边修边闭环

不允许等 S3 全部重写后才测试。每个 slice 都执行同一闭环：

```text
architecture test RED
-> implement one slice
-> unit/integration/boundary CI
-> clean Linux build
-> deploy only to Rust candidate endpoint
-> real S3 request + before/after route counters
-> pinned official sentinel tests on Python and Rust
-> compare by test name
-> commit code and evidence
```

sentinel 只能当开发反馈，不能代替最终 G4/G5 全量 gate。

### S3-1：Streaming middleware ABI

目标：S3 interceptor 接收 `AsyncRequest/IncomingBody`，proxy 不再为 S3 PUT/UploadPart 先执行 `materialize(MAX_CONTROL_BODY)`。

退出条件：

- `handle_request_async` 不包含 `block_in_place`、reactor `block_on` 或同步 `handle()`。
- `AsyncNextFn` 能把 streaming body 继续传给下游。
- 256 MiB signed PutObject 成功，不受 64 MiB control cap 限制。
- 首个后端写入在客户端完整上传前发生，证明不是先全量缓存。
- native async route counter 增加；legacy、block_in_place、blocking network wait 均不增加。

### S3-2：aws-chunked 增量解码

目标：签名校验、dechunk、checksum 和 backpressure 都按 chunk 增量执行。

退出条件：

- 大于 64 MiB 的 aws-chunked PutObject 和 UploadPart 成功。
- 损坏 chunk/signature 必须 fail closed，不能提交半对象。
- 慢速 aws-chunked 上传时 normal HEAD p99 在预注册上限内。
- 内存随 body size 不线性增长。

### S3-3：取消、超时和 durability 边界

目标：客户端断开能取消网络编排，但 durability commit 一旦进入受保护状态必须完成或明确回滚。

退出条件：

- 上传中途断连无 orphan temp、无 stuck commit。
- SIGTERM during body 与 SIGTERM during durability barrier 产生不同且正确的结果。
- retry 不产生重复对象版本、错误 ETag 或不可判定提交。

### S3-4：把字符扫描测试升级为行为证明

当前 `s3_g3_characterization.rs` 的源码字符串检查只是施工护栏。最终 G3 必须由真实请求、route trace、资源计数器和故障注入证明，禁止用“源码里没有关键字”代替执行证据。

## 5. G0-G3 关闭标准

### G0 Provenance

一次运行只允许一个不可变 manifest：

- Peregrine clean commit 和 source tree SHA。
- Swift Python oracle、`test/functional`、`test/s3api`、known-failures 全部来自同一 upstream commit `541a598...`，或在开始前统一改为另一个明确 commit，禁止混线。
- `tipabu/s3compat` top-level SHA 和它的 `ceph-tests` submodule SHA 均固定。`ceph/s3-tests@5522...` 不能充当该项。
- Rust `/info` 的 Swift version 必须与选定 upstream lineage 的实际 tag/describe 一致；不得继续硬报无对应关系的 `2.33.0`。
- Swift3 clean offline build 的 rustc、Cargo.lock、features、命令、制品 SHA 完整记录。
- 目标机 `/proc/$pid/exe` SHA 必须等于 manifest 的制品 SHA。

### G1 Environment

先做两类等价：

1. M2 Swift1/Swift2 host crossover。先在两台都跑同一个 Python 基线；关键 point 差异超过 15% 时停止归因，先修主机不均衡。
2. M3 Python/Rust 使用同一组三节点、同一 rings、同一端口、同一测试数据根，按时间顺序切换实现。

预算：

- P1：1 logical CPU；固定内存；同一 IO/FD/连接/request ceiling。
- P2：4 logical CPU、6 GiB memory；相同 `io.max`、FD、连接、active request、storage、DB ceilings。
- P3：各自 best-known tuning，但仍受同一物理四机和同一数据集约束。

不要对齐线程数，只记录进程、Tokio worker、blocking domain 和 Eventlet worker 拓扑。

### G2 Configuration

- 从一个 canonical profile 同时渲染 Python 和 Rust 配置。
- M2 两实现顺序占用同一服务端口和同一 normalized ring manifest。
- M3 Python/Rust 复用同一份 ring archive，字节 SHA 必须相同。
- `SWIFT-CORE`、`SWIFT-EC`、`S3-TEMPAUTH` 分开。
- pipeline unexpected diff 必须为 0。

### G3 Activation

对每个路径分别 reset counters、发真实请求、记录 delta：

```text
Swift PUT / GET / HEAD
COPY / Range / SLO
EC PUT / EC GET
S3 PUT / GET
multipart create / upload part / complete / abort
SSYNC
```

每个宣称迁移的路径必须满足：

```text
native_async_requests_total > 0
legacy_sync_handler_requests_total == 0
block_in_place_total == 0
blocking_network_wait_total == 0
```

计数器必须带固定枚举 route label 和 `trans_id` 关联证据。只看全局绝对值不通过。

## 6. G4-G6 官方兼容性

### G4 Swift functional

由 Swift4 使用同一 pinned test runner 依次指向 Python 和 Rust。运行：

- `tox -e func`
- `tox -e func-ec`
- `tox -e func-encryption`

先冻结 `collected-tests.txt`。比较主键是完整 test name：

- Python PASS / Rust FAIL 或 ERROR：release-blocking regression。
- Python FAIL / Rust FAIL：环境或 upstream baseline，不自动算 Rust PASS。
- Python FAIL / Rust PASS：单独复核，不以 aggregate 数量抵消 regression。
- skip 集合不同：必须逐名解释 capability，不得靠 `/info` 隐藏。

每个 profile 重新建立干净 account/container/object/memcache 状态。

### G5 S3，两层顺序固定

1. Swift in-tree `test/s3api`。
2. pinned `tipabu/s3compat` + pinned ceph-tests submodule + Swift `541a598...` known-failures。

Python baseline 先跑。若 Python 对 pinned known-failures 仍有 unexpected failure/error/skip，先修实验室，禁止用坏 baseline 测 Rust。

最终只以这些集合判定：Expected Pass、Expected Failure、Unexpected Failure、Unexpected Error、Unexpected Skip、Unexpected Pass。禁止再报“670 ERROR”或 PASS 总数作为结论。

### G6 Probe

切到 M3：Swift1-3 target，Swift4 test runner。Python staging 先跑，完全清场后 Rust staging 跑同一 collected set。

至少覆盖 replication、EC reconstruction、handoff、quorum、node/service restart、consistency、background daemon recovery。故障注入只能命中测试专用设备和数据根。

## 7. G7 并发架构验证

先校准 Swift4：

- 无其他服务；FD 上限、port range、conntrack、NIC queue 和内存满足目标。
- 100k 单目标连接需要多个已验证未冲突的 source IP；单 source tuple 的 ephemeral port 上限不能伪装成服务端失败。
- loadgen 必须先对简单 acceptor 证明能达到目标，且自身 CPU、RSS、packet loss 不成为瓶颈。

然后在 M2/M3 运行：

- 10k、50k、100k idle keep-alive，opened 必须等于 target。
- 1000 slow PUT，全部连接建立，storage threads 不超过配置上限。
- slowloris、slow GET receiver、keepalive churn。
- fsync stall、SQLite stall、backend blackhole、quorum degradation。
- bounded queue overload、client cancellation。
- SIGTERM during PUT、SIGTERM during durability barrier。
- ENOSPC、EIO、partial write、FD exhaustion、backend connect timeout。

运行前冻结 `acceptance.yaml`，不得测试后改阈值。最低硬条件：

- 非注入窗口 response correctness 和 data integrity 100%。
- normal health/HEAD p99 不超过 250 ms。
- scheduler lag p99 不超过 100 ms，p99.9 不超过 500 ms。
- threads 不随连接数线性增长；storage/DB active 和 queue 不突破声明边界。
- 压力解除后 FD/task/thread 回到稳态基线 `max(1%, 16)` 范围。
- 无 orphan temp、无 stuck commit、无 ambiguous durability。
- 任一目标连接数未达到只可标 `ENVIRONMENT BLOCKED`，不能 PASS。

## 8. G8 性能与 soak

G0-G7 全 GREEN 后才能启动。

### P1/P2 crossover

在 Swift1/Swift2 做完整 AB/BA：

```text
Round A: Swift1 Python, Swift2 Rust
Round B: Swift1 Rust,   Swift2 Python
```

两个实现均必须安装到两台主机，且一次只跑一个 workload。顺序随机化；每个 point warmup 后 5-10 次 measured run。

对象：1 KiB、64 KiB、1 MiB、16 MiB、256 MiB、1 GiB。  
操作：PUT、GET、HEAD、DELETE、mixed 70/20/10。  
并发：1 到 512。  
连接：new connection、persistent、90% idle keepalive、100% active 分开。

报告 median、95% CI、CV；CV 超过预注册阈值则该 point INVALID，不用平均值掩盖。

### P3 三节点生产调优

Swift1-3 使用同一 ring、磁盘、数据集和 VIP/HAProxy 拓扑：

1. Python best-known production tuning。
2. 清场、校验数据根、重置缓存策略。
3. Rust best-known production tuning。
4. 第二轮反转先后顺序，控制 warm/cold 和时间漂移。

Swift4 始终是唯一 loadgen，不跑 storage、builder 或观测重任务。

### 24h soak

Python 24h baseline 和 Rust 24h candidate 各跑一次同一预注册 schedule。短跑只能叫 developer soak。

持续负载包括 mixed、churn、slow clients；按固定时间表执行 backend failure、replication、reconstruction 和滚动重启。每 10 秒采样指标，前 2 小时为 warmup，不纳入泄漏斜率。

GREEN：

- 外部非注入窗口错误为 0，注入窗口错误只在预期集合内。
- loadgen 达成至少 95% 预定负载，无大于 60 秒的未知采样缺口。
- RSS Theil-Sen slope 不超过 memory budget 的 0.1%/hour，且 drain 后不超过稳态中位数 5%。
- FD/task count 的 95% slope interval 包含 0；drain 后回到 `max(1%, 16)` 范围。
- 数据校验 100%，无 orphan temp、stuck commit、ambiguous durability。
- 所有注入故障按预期恢复，replication/reconstruction 最终收敛。

## 9. 证据与报告纪律

每次 run 独立目录：

```text
.agent-handoff/workflow-runs/<UTC>-<mode>-<gate>-<impl>-<run-id>/
  LAB-MODE.json
  TEST-PROVENANCE.json
  preflight.txt
  exact-command.txt
  configs/ rings/ inventory/
  collected-tests.txt
  junit/ raw-logs/ metrics/
  before-after-counters.json
  cleanup-proof.txt
  verdict.json
```

`verdict.json` 只能由原始证据生成，不能由操作者直接填 GREEN。每条 gate 只有：

```text
GREEN
RED
ENVIRONMENT BLOCKED
NOT RUN
INVALID
```

不得再使用“partial GREEN”。部分覆盖就是 gate 未关闭，可在 notes 中说明已完成子路径。

## 10. 强制停止条件

出现任一项立即停止当前阶段：

- source、binary、`/proc/exe` SHA 不一致。
- dirty worktree 被用于正式 build。
- G3 route 出现 legacy、block_in_place 或 blocking network wait。
- Python baseline 出现未解释 unexpected regression。
- collected test identities 不一致。
- pipeline、ring、policy 或预算漂移。
- loadgen 未达到目标或自身成为瓶颈。
- 模式外进程、外部流量、编译任务或后台 IO 出现。
- 数据完整性、durability 或 cleanup 不可判定。

## 11. Grok Build 的立即执行顺序

现在开始，不等待新机器：

1. 把资源申请标记 superseded，修订 gate report 的环境前提。
2. 保留当前 dirty tree，从 `8d6ee60` 建立干净 `g3/s3-native-async-20260822` worktree。
3. 修改 preflight 为模式感知和实测竞争流量；新增回归测试，VIP 存在但仅有登记 loadgen 时不得误判。
4. 实施 S3-1 streaming ABI。只做这一片，跑行为证明和官方 sentinel。
5. 继续 S3-2、S3-3，直到 G3 全部要求路径 GREEN。
6. 关闭 G0-G3 后运行 G4、G5。
7. 建立 baseline restore bundle，申请一次明确的四机维护窗口，切到 M2/M3。
8. 依次 G6、G7；全部 GREEN 后才跑 P1/P2/P3 和两次 24h soak。
9. 每完成一个 gate 更新唯一现行报告，不新建互相矛盾的矩阵。

当前正确状态仍是：

```text
G0-G3: RED / incomplete
G4-G8: NOT RUN
Production readiness: NO-GO
Next executable work: S3-1 on a clean worktree, not another diagnosis report
```
