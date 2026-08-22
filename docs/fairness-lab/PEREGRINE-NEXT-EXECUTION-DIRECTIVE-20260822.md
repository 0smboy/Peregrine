# Peregrine 下一阶段执行指令

日期：2026-08-22  
范围：`/Users/oboy/Downloads/swift-master/.agent-handoff/peregrine-grok-merge-20260814/`  
目标：把现有“失败记录”转成可关闭的 G0-G8 门禁，并建立边修复、边运行生产级测试、最后安全进入生产 canary 的主线。

## 1. 当前判定

当前不能进入 G7/G8，更不能宣布 production ready。原因不止是 Swift2 有 VIP。

只读现场核验显示：

- swift1、swift2、swift3、swift4 都运行生产 `:8080` 和 HAProxy `:8085`。
- swift2 持有 VIP `10.0.0.10`，同时运行 Rust SAIO `127.0.0.1:8081`。
- swift3 虽无 VIP，但仍运行生产 Swift，另有 `/etc/rsaio` 服务，而且还是唯一 Linux 编译机。因此 swift3 也不是零生产负载测试机。
- 四台现有机器都不能作为正式 G7/G8 主机。把 RSAIO 从 swift2 搬到 swift3，不能关闭环境门。
- 生产 `/usr/local/bin/swift-proxy-server` 四节点仍为 `ab5cb95c…`，本轮没有改生产二进制。

当前 Gate 状态应写成：

```text
G0 provenance: RED
G1 environment: RED for G7/G8
G2 SAIO pipeline: partial GREEN, live semantic diff reported 0
G3 Swift PUT/GET: partial evidence only
G3 required route set: RED
G3 S3: RED
G4: NOT GATED
G5: NOT GATED
G6: NOT RUN
G7: NOT RUN
G8: INVALID
Production readiness: NO-GO
```

## 2. 三个必须先纠正的根问题

### 2.1 G0 目前是假 PASS

`TEST-PROVENANCE.json` 记录 `peregrine_git_sha=e65d26a…`，但实际产品 Git 树同时存在约 6,222 行改动、48 个已跟踪文件变化和大量未跟踪的新 crate、测试及工具。`e65d26a…` 不能单独重建已部署的 RSAIO 二进制。

此外，`tools/test-lab/preflight.py` 虽调用 `validate_manifest()`，但得到的 `prov_fails` 没有进入任何 PASS/FAIL 判定；它主要检查字符串是否像 40 位 SHA，而不检查：

- 提交对象是否存在；
- 工作树是否干净；
- 未跟踪生产源文件是否存在；
- 构建机源码是否与 Mac 产品树一致；
- 已部署二进制是否来自该提交；
- top-level Git SHA、源码树哈希和 Cargo.lock 是否共同匹配。

因此第一项工作不是继续改 S3，而是创建一个可复现的 integration checkpoint。

要求：

1. 先保存 `git status --porcelain=v2`、`git diff --binary`、未跟踪文件列表和全部文件 SHA-256，不能清理或覆盖现有证据。
2. 在新分支保存当前 integration baseline。只纳入 Peregrine concurrency、test-lab 和对应文档；排除 `__pycache__`、临时结果、密钥、OAuth 数据和无关 monitoring 改动。
3. 当前大改允许先成为一个明确标注的 checkpoint commit，不伪装成可审查的最终提交系列。后续每个修复必须小步、可构建、可测试、可回退。
4. 构建入口必须拒绝 dirty tree，并把 `git_sha`、`source_tree_sha256`、`cargo_lock_sha256`、`rustc -Vv` 和构建参数写入制品 manifest。
5. 安装证明必须同时核对 manifest、Linux 编译树、目标二进制 SHA 和运行中 `/proc/<pid>/exe`。

完成条件：从一个干净提交可以在独立 Linux builder 上离线重建相同功能的二进制；G0 才可 GREEN。

### 2.2 Preflight 还不是证据采集器

当前 `collect_facts.py` 的 `--rings-equivalent`、`--cpu-equivalent`、`--data-clean` 等参数是人工布尔声明。生产级 preflight 必须自行测量并附原始证据，不能由操作者把 PASS 传进去。

重构为三种 fail-closed preflight：

```text
preflight compatibility  -> G0/G2/G3/G4/G5
preflight concurrency    -> compatibility + clean dedicated host + resource limits
preflight performance    -> concurrency + AB/BA + idle host + separate load generator
```

这不是降低 T5，而是让每条要求只阻止它真正影响的 Gate：

- 有生产进程时，G7/G8 必须 ABORT。
- G4/G5 的开发反馈可以在端口、配置和数据目录完全隔离的 SAIO 上运行，但只能标为 feedback，不能越过 G3 领取 Gate GREEN。
- G6 probe 不能在当前四台生产节点运行。

Preflight 必须直接测量：Git cleanliness、commit object、进程和监听器、VIP、cgroup v2、CPU affinity、memory.max、磁盘/文件系统、ring semantic dump、policy dump、数据目录、测试 collect 名单、后台负载和 load-generator 身份。

### 2.3 现有 G3 证明粒度不足

`native_async_requests_total` 是进程级总量。它能证明“有某些请求走过 async”，不能证明 Swift PUT、GET、COPY、SLO、EC、S3、SSYNC 各自走对路径。

现有 live `/recon/concurrency` 在 proxy 进程看到 storage/db `spawn_blocking_total=0` 也不是端到端证明，因为 object/account/container 是独立进程。G3 必须：

- 在 proxy、object、account、container 四类服务同时取 before/after；
- 用同一个 `X-Trans-Id` 或测试 trace id 串联；
- 使用有限枚举标签，如 `route="s3_put_object"`，禁止 object path 等高基数标签；
- 同时保留静态 blocking audit、动态 metrics 和行为测试；
- 每条路径给出原始请求、服务链、counter delta、线程/队列变化和最终响应。

`block_in_place_total=0` 只说明已插桩调用没有发生，不能替代对 `Handle::block_on`、同步 socket、同步文件和 SQLite 的静态审计。

## 3. 正确的测试拓扑

```text
开发反馈车道
当前 swift1 Python SAIO :8090 + swift2 Rust SAIO :8081
用途：targeted test、官方 suite 反馈、G2/G3 调试
禁止：性能结论、probe、故障注入、生产就绪声明

机制与性能车道
两台全新、同规格、无生产服务的 lab-a/lab-b
用途：AB/BA、G7、G8 P1/P2
要求：独立 load generator、相同镜像/磁盘/NIC、cgroup v2、无编译任务

生产形态 staging 车道
独立四节点 staging + 独立 load generator
用途：G6、P3、replication/reconstruction、滚动升级、24h soak
要求：生产同构配置，但绝不使用客户数据或生产 rings

生产 canary 车道
现有 swift1-4
用途：全部 G0-G8 GREEN 后的小流量、可回滚验证
禁止：在这里开发、跑 probe、跑破坏性 fault injection、直接追测试失败
```

当前环境可以继续做兼容性反馈，但不能靠 cgroup 把共享磁盘、page cache、IRQ、NIC 和生产后台任务变成“干净主机”。正式 G7/G8 必须新增测试资源。

Linux 编译也应从 swift3 迁到独立 Rocky 9 builder。编译任务本身会污染生产节点的 CPU、磁盘和 page cache。

## 4. S3 native async 不是只替换 `block_in_place`

当前路径还有更深的问题：proxy 在任何 filter `intercepts_request()` 时，先把请求体 `materialize(MAX_CONTROL_BODY)`；`MAX_CONTROL_BODY` 是 64 MiB。S3 对所有签名请求都 intercept，所以 PutObject、UploadPart 和 aws-chunked 数据面在进入 S3 handler 前已经被整体缓冲并受 64 MiB 上限约束。

因此以下改法仍然失败：

```text
handle_request_async + AsyncNextFn
但入口仍 Request + Body::Buffered
```

它也许让 `block_in_place_total=0`，却仍违反 streaming、bounded memory 和 slow PUT 不占工作线程的目标。

### S3 改造顺序

#### S3-0 Characterization first

先增加会失败的测试：

- PutObject >64 MiB；
- UploadPart >64 MiB；
- 1 KiB/s slow PutObject；
- aws-chunked 分块签名中途错误；
- slow GET receiver；
- S3Token/Keystone 延迟；
- client cancellation；
- multipart complete、copy 和 range 的 Python differential。

失败必须是测试失败，不允许“环境不可用但测试 PASS”。

#### S3-1 Streaming middleware ABI

- `handle_request_async` 接收 `AsyncRequest/IncomingBody`，不能先降级成同步 `Request`。
- `AsyncNextFn` 保留 streaming request 和 streaming response。
- header/auth context 与 body stream 分开。
- 只有明确的小型控制 XML/JSON 操作可用 operation-specific cap materialize。

#### S3-2 Async auth

- SigV2/SigV4 header 验证不等待完整 body。
- S3Token/Keystone 使用 async client 和 typed deadline。
- aws-chunked 做增量 dechunk、增量签名验证和 bounded buffering。

#### S3-3 Data-plane operations

先迁移并证明：

```text
PutObject
GetObject / HeadObject / Range
UploadPart
CopyObject / UploadPartCopy
```

每个操作必须满足：无全体 materialize、无 `block_in_place`、无 reactor `block_on`、无同步网络等待、内存和 backend pending bytes 有界。

#### S3-4 Control and composite operations

再迁移 ListBuckets、bucket metadata、ACL、tagging、versioning、lifecycle、multi-delete、multipart create/list/complete/abort。所有内部 Swift subrequest 必须 `next(...).await`，有 deadline、cancel 和 bounded response body。

#### S3-5 Remove sync escape hatch

- migrated route 进入同步 `handle()` 立即测试失败；
- 删除或严格隔离 S3 production sync adapter；
- `/info` 只在整套 S3 G3 + G5 达标后 advertise `s3api`，不能靠隐藏 capability 改 skip。

每个 S3 slice 的循环固定为：

```text
失败 characterization
-> 最小实现
-> Rust unit/integration
-> targeted pinned Swift test/s3api case
-> targeted Python/Rust differential
-> RSAIO live route trace + counters
-> checkpoint commit
```

Targeted suite 是开发反馈。只有 route coverage 完整后，才运行完整 G3 并进入正式 G5。

## 5. 测试本身也要去掉“诚实失败即 PASS”

当前 `idle_50k.rs` 和 `idle_density.rs` 在只打开少量 socket、甚至未达到 10k 时仍可 PASS，只把“unavailable”写到 stderr。这不能作为 G7。

规则改为：

- 目标 10k 就必须 `opened == 10_000`；目标 50k/100k 同理。
- 客户机 fd、ephemeral ports 或内核参数不足时，结果是 `ENVIRONMENT BLOCKED`，不是 test PASS。
- 必须采样真实进程线程数、RSS、fd、task count、scheduler lag 和健康请求 p99。
- slow PUT 必须达到规定并发，例如 1,000 条，不得用 2 条连接替代后领取同一 Gate。
- `PEREGRINE_SOAK_SECS` 的短跑只能叫 developer soak。G8 24h 必须真实运行 86,400 秒，覆盖完整部署进程、proxy、storage、DB、S3、replication 和故障注入；单进程临时目录 object-server 测试不能代替。

当前 `ci/check-concurrency-boundaries.sh` 也未通过：它把 metrics 帮助字符串里的 `spawn_blocking_total` 识别为非法调用。先修 matcher，使它检查语法调用而不是文档/metric 名，再要求 CI 真正打印完整 summary 和 exit 0。

## 6. G0-G8 的关闭顺序

### G0

- 干净、可重建的 Peregrine checkpoint commit；
- pinned Python Swift `541a598…`；
- pinned official test tree；
- pinned S3 harness；
- build + install + runtime binary provenance 闭环。

注意：pinned Swift CI 在 `541a598…` 的 Ceph job 克隆的是 `tipabu/s3compat`，再使用其 `ceph-tests` submodule。当前直接 clone 的 `ceph/s3-tests@5522d1c…` 不是同一 harness lineage。应 pin：

```text
Swift commit
tipabu/s3compat commit
s3compat ceph-tests submodule commit
known-failures file hash
config hash
```

Rust `/info` 的 `swift.version=2.33.0` 也不能代替 `541a598…`。该 commit 没有 exact release tag。对外应单独暴露 compatibility commit，不能虚构精确版本对应关系。

### G1/G2

- 用 canonical profile 生成 Python/Rust 配置；
- policy 完整字段一致；
- ring 以 semantic normalized dump 比较，不比较不同地址/端口导致的压缩文件字节哈希；
- G7/G8 使用 dedicated hosts，AB/BA crossover；
- P1 绑 1 CPU，P2 绑 4 CPU；memory.max、TasksMax、nofile、IO 权重和 device class 一致；
- load generator 独立，NTP 同步，客户端本身不成为瓶颈。

Ring semantic key 至少包括：part_power、replica count、min_part_hours、policy index/type、region/zone/device 数、weight、partition assignment distribution。IP/port 只按角色归一化。

### G3

按固定 route identity 逐项关闭：Swift PUT/GET/HEAD、COPY、Range、SLO、EC PUT/GET、S3 PUT/GET/multipart、SSYNC。四类服务端到端 trace，所有 required route 的 legacy/block-in-place/blocking-network-wait 都为 0。

### G4

用 `Swift@541a598…` 的 `.functests` / `tox -e func`。同一 collection、同一配置、干净且独立的数据 namespace，先 Python baseline 后 Rust。比较 test identity 和每个结果，不比较总数。

### G5

先运行 pinned Swift `tox -e s3api` black-box suite，再运行 pinned `tipabu/s3compat` + submodule Ceph suite。先证明 Python baseline 的 unexpected 集合为 0，再测 Rust；按 pinned known-failures 分类。

### G6

只在独立 staging 运行 probe、replication、reconstruction、handoff、quorum、background daemons、node loss 和恢复。当前生产四节点禁止运行 probe。

### G7

在 clean lab/staging 运行 50k idle、slowloris、1,000 slow PUT、slow reader、fsync/SQLite stall、backend blackhole、ENOSPC/EIO/partial write、fd exhaustion、SIGTERM 和 durability barrier。每项同时验证响应、资源上限、清理和恢复。

### G8

P1/P2/P3 分开。每点 warmup + 5-10 measured runs，报告 median、95% CI、CV。正确性回归为 0；无解释的 throughput 回退 >5% 或 p99 回退 >10% 为 NO-GO。最后运行真实 24h soak，检查 RSS/fd/task/thread/temp/commit 的趋势和遗留物。

## 7. 进入真实生产的顺序

“生产级测试”从今天开始持续运行，但“真实生产流量”必须最后进入。

### Stage A: read-only shadow

G0-G6、关键 G7 和短期 soak GREEN 后，在不修改 `/usr/local/bin` 的独立 canary 端口部署同一签名制品。只允许 health、info、GET、HEAD、LIST 和脱敏请求回放。禁止镜像真实写请求。

### Stage B: synthetic write canary

G0-G8 GREEN，并再次确认备份/快照与回滚条件后，使用独立测试 account 和唯一 run id 做有限 PUT/GET/DELETE、S3 multipart 和 invalid-request zero-side-effect。不得使用历史 `AUTH_test`。这是生产写入，需要单独明确授权。

### Stage C: drained node

先从负载均衡摘除一个非 VIP 节点，只部署一个服务/一类路径。验证 PID、二进制 hash、配置 hash、journal、metrics、Python oracle 和回滚，再逐步恢复受控流量。

### Stage D: rolling canary

顺序保持非 VIP 节点在前，swift2/VIP 最后。每一步都要等待观察窗，不允许同时滚多个节点。

任何一项立即回滚：

- 新增 semantic mismatch 或数据不一致；
- required route 出现 legacy/block_in_place/blocking network wait；
- 5xx、timeout、scheduler lag、queue wait 超过预先批准阈值；
- p99 回退 >10% 或 throughput 回退 >5% 且无已批准 ADR；
- RSS/fd/task/thread 单调增长；
- orphan temp、stuck commit、replication/reconstruction backlog 异常；
- 证据采集缺失或制品 provenance 断链。

## 8. Grok Build 现在必须执行的第一批任务

按顺序，不得并行改大块业务代码：

1. 保存 dirty tree 的完整证据，创建可重建 integration checkpoint，修正 G0。
2. 修 `preflight.py` 的 provenance 忽略问题；把人工布尔开关改成实际测量；增加 clean-worktree/build/runtime provenance。
3. 修 concurrency boundary checker 的 metric-string false positive，保证它输出完整审计 summary。
4. 把 50k/100k、slow PUT 和 soak 的“未达到目标仍 PASS”改成 fail/blocked 分离。
5. 建立 dedicated lab/staging 资源申请；禁止把 swift3 当 clean test host。
6. 增加 S3 >64 MiB、slow streaming、aws-chunked 和 cancellation 的失败测试。
7. 实施 S3 streaming middleware ABI，之后按 S3-1 到 S3-5 做小步 vertical slice。
8. 每个 slice 运行 targeted upstream test 作为反馈；全部 required paths G3 GREEN 后，才正式开启 G4/G5 全量。
9. G6/G7/G8 只在新测试资源执行。
10. 每轮只保留一份由 raw evidence 自动生成的 Gate report；旧报告标明 superseded，禁止手工复制出互相冲突的状态。

## 9. 完工定义

本阶段不以“写完计划”“workflow complete”或“记录完失败”为完成。

完成必须同时满足：

```text
source reproducible
test harness reproducible
required async routes proven
official compatibility green
storage recovery green
concurrency invariants green
controlled performance valid
24h soak stable
production canary reversible
```

任何暂时不能关闭的门，必须给出外部资源 blocker、owner 和解除条件；不得用失败矩阵替代修复，也不得为了全 GREEN 修改测试发现、隐藏 capability、放大线程/队列或降低断言。
