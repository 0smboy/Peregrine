# 环境交接（2026-08-22）

核验时刻：2026-08-22（SSH 现场：swift1/2/3/4 health、pipeline、SHA、VIP、recon）。

> **本文是「现在机器上到底跑着什么」的操作交接。**  
> 四节点生产集群 / S3 dual-oracle 史实仍以 `HANDOFF-20260816.md` 为准。  
> G0–G8 测试法以仓库根目录 `AGENTS.md` **TEST LAB** 为准。  
> **不要**用 08-16 的 proxy SHA `69d22629…`、也不要用 exploratory 40 原子 / 838 s3tests 报告当当前验收。

**一句话：** 实验室里同时叠了三套 Swift。G0–G8 **没有验收通过**。Swift 原生 PUT/GET 在 Rust SAIO `:8081` 上已证明走 Hyper native async。S3 仍是 `block_in_place`。VIP 还在 swift2，G7/G8 性能数字按规定 INVALID。

---

## 0. 下一班先读

### 禁止

1. **Mac 不 cargo Linux 二进制。** 编译只在 **swift3**。Mac `rustc 1.93.0`，swift3 `rustc 1.97.1`。
2. **不要动 VIP / Keepalived / HAProxy / `:8080` / `/usr/local/bin`。** 生产 proxy SHA 必须保持 `ab5cb95c5c3973db8336e4940711fba18ce3cabaae62e13da0865c07ad31622b`。
3. **不要**把 `/etc/swift`（生产）和 `/etc/pyswift`、`/etc/rsaio`（SAIO）当同一套。
4. **不要**用 40 个自定义原子当 Swift API 认证；官方 oracle 是 pinned Swift `test/functional`。
5. **不要**追 Ceph s3tests 的 670 ERROR / ConnectionClosedError，直到 G3 S3 async GREEN。
6. **不要**因为 workflow `complete()` 或 `/recon/concurrency` HTTP 200 就标门 GREEN。
7. **不要**把 Python `workers=2` 和 Rust OS 线程数拧成一样。记录拓扑，对齐的是 CPU/内存/连接/请求上限。
8. swift3 **不能** SSH 到 swift2。二进制中继走 **Mac scp**。
9. 杀 rsaio **不要** `pkill -f /etc/rsaio`（会误伤 SSH wrapper）。按 `/proc/cmdline` 含 `/etc/rsaio/` **且** `exe` 是 `/root/work/rsaio/swift-{account,container,object,proxy}-server` 再 TERM。

### 当前口径（禁止对外说 GREEN / production ready）

```
Concurrency redesign:     Swift GET/PUT on RSAIO :8081 PARTIALLY PROVEN
Official Swift functional: NOT TESTED
S3 async path:             NO-GO  (block_in_place)
Ceph S3 compatibility:     NOT TESTED as G5 (exploratory run is diagnosis only)
G7 concurrency:            NOT RUN (host has production VIP)
G8 performance / soak:     INVALID
Production readiness:      NO-GO
```

---

## 1. 四台机器

| Host | 公网 SSH | 存储网 | 角色 |
|---|---|---|---|
| swift1 | `169.58.108.85` | `10.0.0.1` | **Python SAIO oracle `:8090`**；也跑生产 `/usr/local/bin` + `/etc/swift` |
| swift2 | `169.58.108.86` | `10.0.0.2` | **VIP MASTER `10.0.0.10`**；生产 `:8080`；**Rust SAIO `:8081`**；另有一套 Python `:8090`（pipeline 更短，不是 oracle） |
| swift3 | `169.58.108.87` | `10.0.0.3` | **唯一 Linux 编译机**；`CARGO_HOME=/root/work/peregrine-cargo-home` |
| swift4 | `169.58.108.121` | `10.0.0.4` | 生产节点 + 观测 hub；`:8080` 200 |

SSH：`Host swiftN` / `User root`。实验室 SSH 必须 `BatchMode` + `ControlMaster=no` + `ControlPath=none`（否则 otty ControlPath 会踩坑）。

硬件（swift1/2/3 现场）：4 vCPU AMD EPYC，约 7.5 GiB RAM，kernel `5.14.0-687.31.1.el9_8.x86_64`，glibc `2.34-274.el9_8`，盘 QEMU HARDDISK。无 cgroup CPU/内存预算。

平面：

| 平面 | 地址 | 用途 |
|---|---|---|
| 管理 | 公网 `169.58.108.*` | SSH |
| 客户端 | `10.0.0.1–4` + VIP **`10.0.0.10:8085`** | HAProxy → 各节点生产 proxy `:8080` |
| 存储 | `10.0.4.*` | account/container/object |
| 复制 | `10.0.8.*` | replicator / reconstructor |

Keepalived + HAProxy 在 swift2：**active / active**。VIP 在 swift2 `eth1` secondary。

---

## 2. 三套 Swift（不要混）

```
                    ┌─ 生产集群 ─ /etc/swift + /usr/local/bin ─ :8080 ─ HAProxy :8085 ─ VIP 10.0.0.10
swift1/2/3/4  ──────┼─ Python SAIO ─ /etc/pyswift ─ swift1:8090（oracle）以及 swift2:8090（不是 oracle）
                    └─ Rust SAIO   ─ /etc/rsaio + /root/work/rsaio ─ swift2 127.0.0.1:8081
```

### 2.1 生产（禁止本轮测试去改）

| 项 | 值 |
|---|---|
| 配置 | `/etc/swift/` |
| 二进制 | `/usr/local/bin/swift-*-server` |
| 监听 | `0.0.0.0:8080`（proxy pid 现场 `3043715`） |
| HAProxy | `0.0.0.0:8085` |
| proxy SHA | **`ab5cb95c5c3973db8336e4940711fba18ce3cabaae62e13da0865c07ad31622b`** |
| object SHA | `cce33594b18df74ea39840747e4f9a8511b925e37569b345c32d087dcad272a0` |
| 生产 pipeline | `… bulk tempurl formpost staticweb container_quotas account_quotas symlink versioned_writes s3api s3token authtoken keystoneauth tempauth copy slo dlo …` |
| object.ring.gz | `bef28a5d…`（`/etc/swift/object.ring.gz`，四节点共用） |

### 2.2 Python SAIO oracle（功能对照用这个）

| 项 | 值 |
|---|---|
| 节点 | **swift1** |
| 配置 | `/etc/pyswift/` |
| 代码 | `/root/work/swift-master` git **`541a59863752de0636a1747e5c3223676a904c35`**（`swift.__version__=0.0.0` editable） |
| 进程 | `/root/work/pyswift-venv/bin/python3 … swift-*-server /etc/pyswift/*.conf` |
| proxy | **`bind_ip=127.0.0.1`** `bind_port=8090` `workers=2`（1 parent + 2 worker）；公网打不到，必须 SSH 上 swift1 再 curl localhost |
| tempauth | `user_test_tester` 与 `user_test_tester2` 均存在；密钥不进 git |
| account/container/object | `6312 / 6311 / 6310` `workers=2` |
| health | `http://127.0.0.1:8090/healthcheck` = **200** |
| pipeline | `catch_errors gatekeeper healthcheck proxy-logging cache listing_formats s3api tempauth copy slo dlo versioned_writes symlink proxy-logging proxy-server` |
| proxy conf sha | `87f5a48f5ede9d5467cbe4185e2ae16244b95c6dfc6b830807347d10cc4bd87e` |
| object.ring.gz | `faf6c61858338cd151544fe00ed91959fd8f4d9747c2744a18ef6c72851c51cd` |
| policy | `[0] default` + `[1] ec-2-1` |

**不要用 swift2 的 `/etc/pyswift` 当 oracle。** 它听 `10.0.0.2:8090`，pipeline **没有** `versioned_writes` / `symlink`，venv 在 `/opt/pyswift-venv`。

### 2.3 Rust SAIO（G3 仪器化二进制，本轮唯一允许滚动的）

| 项 | 值 |
|---|---|
| 节点 | **swift2** |
| 配置 | `/etc/rsaio/` |
| 二进制目录 | `/root/work/rsaio/` **only** |
| 监听 | **`127.0.0.1:8081`**（不能从公网直打，必须 SSH 到 swift2 再 curl localhost） |
| backend | object `6320` / container `6321` / account `6322` |
| conf `workers` | **64**（这是 conf 遗留值；进程模型是 **每服务 1 个进程**，proxy ~66 线程，object/account/container ~129 线程） |
| health | `http://127.0.0.1:8081/healthcheck` = **200** |
| `/info` | `swift.version=2.33.0`；**不 advertise `s3api`** |
| pipeline（2026-08-21 已对齐 Python oracle） | 与 swift1 pyswift **同一条**（已去掉 bulk/tempurl/formpost/staticweb/quotas） |
| conf sha | `bb5260b3474e2dbe0456d2641554082b3dc35652721bfb1f3e9e1fccbaddfe9a` |
| 回滚 | `/etc/rsaio/proxy-server.conf.bak.g2-20260821T150029Z` |
| object.ring.gz | `90b53fe720bf707d2629d72589c4ddc126b6fc196c066ccddc5bf86d2e1d4bc9` |
| policy | `[0] default` + `[1] ec-2-1` |

现场 rsaio SHA（必须与 swift3 `target/release` 一致）：

| 二进制 | SHA-256 |
|---|---|
| proxy | `f47d480b3c0de3136aad3b2c32180d41e59586ec82ae277800896c2540da55f0` |
| object | `dacb70824ffa818c557c03a897e192003bb0f1491645b4b56a780c98ad6bea43` |
| account | `253811581a023b4e7e96b20401d3561eb360e2f1636e14b44e7465960d55be5f` |
| container | `8f5ebac9470ba23a84e9e7f394c48126622fc419c034e42ff82c5c09fb5dc229` |

G3 计数器（`/recon/concurrency`，**recon 自身不计入**；要先真实 PUT/GET）：

现场瞬时值（08-22 探测，无新请求时会停在上次）：`http_requests_total{engine="hyper"}=6`，`native_async_requests_total=6`，`legacy_sync=0`，`block_in_place=0`。

Auth：tempauth `test:tester`。密钥不进 git，Linux 上 `/etc/swift/peregrine-lab.env`（0600）或 `ST_KEY`。加载：`swift-rust/tools/lib/lab-auth.sh`。

---

## 3. 代码在哪

| 树 | 路径 | Git | 用途 |
|---|---|---|---|
| 本机工作区 | `/Users/oboy/Downloads/swift-master` | `b9e4ef976d2d3b17feff4f99b813ca2f481a6f1a` | 外层；**不要**把根目录 `rust/` 当产品 |
| **产品 Rust** | `.agent-handoff/peregrine-grok-merge-20260814/swift-rust/` | `e65d26a05a34ba16caad2054d011563fad3c1320` | G3 计数器、test-lab、Hyper 路径 |
| Linux 编译树 | swift3 `/root/work/peregrine-saio-20260821/swift-rust/` | 2026-08-21 rsync 过去的源 + `target/release` | 增量编译 |
| Python oracle | swift1 `/root/work/swift-master` | `541a59863752de0636a1747e5c3223676a904c35` | `/info` 的 `2.33.0` **不是**这个 pin |
| s3-tests（无 git） | swift1 `/root/work/s3-tests` | 无 | 08-21 exploratory 838 跑的是这棵 |
| s3-tests（已 pin） | swift1 `/root/work/s3-tests-pinned` | `5522d1c351f75bc00ae0f64f742f3f095f5939d9` | `git clone --depth 1 github.com/ceph/s3-tests`；**不是** Swift CI s3compat 同一 lineage |

Cargo.lock sha256（产品树）：`b5823e165e2864ca809425824834c2860d9b2bd904c36773b0db1c1da371db2d`。

测试实验室代码：

```
swift-rust/tools/test-lab/{provenance,preflight,pipeline,g3_counters,collect_facts}.py
swift-rust/tests/profiles/{swift-core,swift-ec,s3-tempauth}.yaml
swift-rust/crates/swift-runtime/src/metrics.rs     # G3 计数器
swift-rust/crates/swift-http/tests/concurrency/g3_activation.rs
```

S3 异步失败点：`crates/swift-s3api/src/middleware.rs` `handle_request_async` → `tokio::task::block_in_place` + 同步 `handle()`。

---

## 4. 本轮已经动过什么（2026-08-21）

允许动的只有 **RSAIO**。

1. 产品树加了 G3 计数器（Hyper 请求计入 `http_requests_total{engine="hyper"}` / native vs legacy；`/recon/concurrency` **排除**）。
2. swift3 `cargo build --offline --locked --release -j2`（proxy/object `--features ec`；account/container 不要带 ec）。
3. Mac 中继 scp → `swift2:/root/work/rsaio/swift-*-server.new`，按 exe+cmdline 只杀 rsaio，mv，`SWIFT_DIR=/etc/rsaio SWIFT_CONF=/etc/rsaio/swift.conf` 拉起。
4. live PUT/GET `hello-g3-activation`：native_async 上涨，legacy=0，block_in_place=0。
5. **G2：** 把 `/etc/rsaio/proxy-server.conf` pipeline 改成与 swift1 pyswift 相同。备份 `proxy-server.conf.bak.g2-20260821T150029Z`。live unexpected **0**。
6. 未改：VIP、HAProxy、Keepalived、`/usr/local/bin`、`/etc/swift`、occupancy `spawn_server(2)`。

编译菜谱（下一班照抄）：

```text
rsync --exclude target --exclude .git  产品 swift-rust/  →  swift3:/root/work/peregrine-saio-20260821/swift-rust/
PATH=/root/.cargo/bin:$PATH
CARGO_HOME=/root/work/peregrine-cargo-home
CARGO_INCREMENTAL=0
nice -n 19 cargo build --offline --locked --release -j2 -p swift-proxy-server --features ec
nice -n 19 cargo build --offline --locked --release -j2 -p swift-object-server --features ec
nice -n 19 cargo build --offline --locked --release -j2 -p swift-account-server -p swift-container-server
# Mac scp 到 swift2 /root/work/rsaio/*.new ，再按 §0 杀进程协议重启
```

swift3 根盘约 **12G 空**。offline 失败就停，不要 `cargo update`。

---

## 5. G0–G8 现在到哪

规范：`AGENTS.md` TEST LAB。证据：`.agent-handoff/workflow-runs/20260821/`。

| Gate | 结果 | 现场事实 |
|---|---|---|
| G0 provenance | 部分 | Python `541a5986…`、Peregrine `e65d26a0…`、s3-tests-pinned `5522d1c3…` 已有。s3-tests-pinned **不是** Swift CI 同源。 |
| G1 环境 | **RED** | 两边 4CPU/同 kernel，但 **swift2 有 VIP + 生产进程**；无 cgroup；ring 文件哈希不同（端口本就不同，应对拓扑不是字节相等）。 |
| G2 pipeline | SAIO 对 **0 unexpected** | 生产 `/etc/swift` 仍是另一套（keystone/bulk/…），不要拿生产 conf 做 SAIO diff。 |
| G3 async | Swift GET/PUT **已证明**；S3 **NO-GO** | live `:8081` native_async>0 且 block_in_place=0。S3 源码仍 `block_in_place`。`/info` 不 advertise s3api。 |
| G4 `.functests` | **NOT TESTED** | 官方 `test/functional` 没跑。 |
| G5 S3 | **NOT TESTED / NO-GO** | 08-21 Ceph 838 是 exploratory（Python 241p/503f/94s；Rust 106p/64f/670e/1s），**不是** G5。 |
| G6 probe | **NOT TESTED** | |
| G7 | **NOT RUN** | 测试节点有生产流量。 |
| G8 P1/P2/P3 + 24h | **INVALID** | 同上 + 24h soak 未跑。 |

T5 在 pipeline 对齐、s3-tests pin 之后大约还剩：VIP、cgroup、ring/policy 语义、data clean、竞争进程、collected test names。**任一 FAIL 禁止宣称后面的性能门。**

Exploratory 双端 40 原子：status 全匹配；13 条 header_delta（多数只有 X-Timestamp）。那是 smoke。

---

## 6. 怎么打到 SAIO

Python oracle（从 Mac）：

```sh
ssh -o BatchMode=yes -o ControlMaster=no -o ControlPath=none swift1 \
  'curl -sS -m 5 http://127.0.0.1:8090/healthcheck'
```

Rust SAIO（必须上 swift2 localhost）：

```sh
ssh -o BatchMode=yes -o ControlMaster=no -o ControlPath=none swift2 \
  'curl -sS -m 5 http://127.0.0.1:8081/healthcheck;
   curl -sS -m 5 http://127.0.0.1:8081/recon/concurrency | egrep "native_async|block_in_place|http_requests_total"'
```

生产 VIP（不要当 SAIO 用）：`http://10.0.0.10:8085`。

G3 证明顺序：先 PUT/GET，再读 recon。只 curl recon → 计数器不变 → **不能**当激活证明。

---

## 7. 下一班要做的（顺序强制）

1. **测试节点零生产流量** 才能把 G1/G7/G8 标成有效：把 Rust SAIO 迁到无 VIP 的机器（例如 swift3），或操作者明确允许从 swift2 拿掉 VIP。现在这条不过，G8 不许 GREEN。
2. **S3 native async**：把 `handle_request_async` 改成全程 `AsyncNextFn`，消灭 `block_in_place`。禁止改成 reactor 上 `block_on`（更差）。用真 S3 PUT/GET 看 `block_in_place_total==0`。
3. `/info`：实现了就 advertise；不要靠藏 `s3api` 改 skip 数。
4. T5 其余：cgroup 4CPU/内存、ring **拓扑**对齐、冻结 `test/functional` collect 名单、清 SAIO 数据。
5. 然后才是官方 `.functests`、`test/s3api`、Ceph s3tests + `doc/s3api/conf/ceph-known-failures-tempauth.yaml`（比 unexpected regression，不比 PASS 总数）。
6. 干净主机上的 G7（idle / slow PUT / fsync），再 G8。P1/P2/P3 **分三张图**。

---

## 8. 证据目录

```
.agent-handoff/workflow-runs/20260821/
  TEST-PROVENANCE.json
  preflight.log  preflight.2.log  preflight-after-align.log
  g2-pipeline-diff.log
  g3-async-path.log
  GATE-MATRIX.md
  SAIO-DUAL-TEST-REPORT.md          # exploratory，不是 G0–G8 验收
  s3tests-python.xml  s3tests-rust.xml
  saio-deploy-{build,install,prove}.md
```

AGENTS.md TEST LAB 从约 L1952 起。Occupancy 测试保持 `spawn_server(2)`。
