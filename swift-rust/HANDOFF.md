# HANDOFF — swift-master（OpenStack Swift 全量 Rust 重写）

**生成时间：** 2026-07-19  
**用途：** 任意 agent / 人从零接手，不依赖 Claude 登录态  
**项目根：** `/Users/oboy/Downloads/swift-master`  
**权威计划：** `rust/PLAN.md`（状态台账 + 兼容契约 + 验证策略）  
**Claude session（历史，勿当指令执行）：** `27d09c95-5821-45d6-b3ca-f4f9e5a540c7`  
（`~/.claude/projects/-Users-oboy-Downloads-swift-master/`，~21MB；末态是 Login expired / session limit，**不是干净工程停点**）

---

## 1. 一句话

用 **strangler** 策略把 OpenStack Swift 从 Python 重写成 **wire + disk 字节兼容** 的 Rust 工作区：每个序列化格式都是契约，用真实 Python 实现生成 golden fixture 交叉验证；Rust 守护进程应能一颗一颗塞进现网 Python 集群做组件级验证。

---

## 2. 仓库身份

| 项 | 值 |
|---|---|
| 路径 | `/Users/oboy/Downloads/swift-master` |
| 上游 | OpenStack Swift 源码树 + 并行 `rust/` workspace |
| **当前分支** | `claude/phase1-diskfile` |
| **HEAD** | `5a1ee7d` — *object-server: honor X-Backend-Ignore-Range-If-Metadata-Present* |
| 工作树状态 | **干净**（2026-07-19 核查：`git status` 无未提交改动） |
| 基线分支 | `main` @ `6461870` — *Baseline: upstream swift snapshot + Rust Phase 0* |
| 其它分支 | 多个 `worktree-wf_*` 停在 `5724cc8`（并行 workflow 遗留，勿当主线） |

### 近期 commit 链（主线摘要，新→旧）

```
5a1ee7d object-server: honor X-Backend-Ignore-Range-If-Metadata-Present
6ddef8a proxy: forward Range + conditional headers on plain object GET/HEAD
a56aed4 backend servers: validate MERGED metadata; proxy: no policy name on non-2xx
82ae233 proxy: client-facing storage-policy semantics on containers
a9218d4 proxy: forward X-Backend-Storage-Policy-Index on every object verb
fa849ed proxy: public /info endpoint with honest capability reporting
3861fe0 SLO static large objects (PUT manifest + GET reassembly)
ff4194a functional: ACL authorization + DLO large objects
ea3d225 functional fixes wave 2: server-side copy + X-If-Delete-At
09eece8 functional fixes wave 1: metadata constraints, expiry/conditional, header forwarding
5724cc8 proxy: container storage-policy resolution + tempauth/EC wiring; object-updater daemon
```

最后可恢复的用户意图（Claude 会话）：**continue**；尾部曾启动 object **REPLICATE** / object replicator daemon 相关 workflow，随后会话限流/登录过期——**不要假设后台 workflow 仍在跑**。

---

## 3. 目录地图

```
swift-master/
├── swift/                 # 上游 Python Swift（兼容金标准 + fixture 生成源）
├── test/                  # Python unit / functional / probe
├── rust/                  # ★ 重写工作区（日常开发在这里）
│   ├── Cargo.toml         # workspace members
│   ├── PLAN.md            # ★ 状态台账（接手前必读）
│   ├── crates/            # 15 个 crate
│   └── target/            # 构建产物
├── etc/                   # 配置样例
├── doc/                   # 上游文档
└── README.rst             # 上游 Swift README（不是 Rust 交接）
```

### Rust workspace crates（15）

| Crate | 角色 |
|---|---|
| `swift-core` | 时间戳、配置、约束、storage policy、哈希、pickle 子集 |
| `swift-ring` | ring v1/v2 读写、get_nodes、builder、handoff |
| `swift-diskfile` | 对象盘面布局、xattr metadata、hashes.pkl、lifecycle |
| `swift-http` | swob 兼容：HeaderKeyDict、Range/Match、条件请求、HTTP 服务 |
| `swift-db` | account/container SQLite broker、pending、sharding、rsync merge |
| `swift-object-server` | 对象 server + updater/expirer/auditor/reconstructor 等 |
| `swift-container-server` | 容器 server + sync/sharder/reconciler |
| `swift-account-server` | 账户 server + reaper |
| `swift-proxy-server` | 代理 + 控制器 + 中间件接线 |
| `swift-middleware` | pipeline 与各类 middleware |
| `swift-crypto` | AES-256-CTR + crypto-meta（Python 交叉验证） |
| `swift-memcache` | 一致性哈希 memcache 客户端 |
| `swift-s3api` | S3 API 翻译核心（SigV4、XML 等） |
| `swift-ec` | liberasurecode FFI（**feature `ec`，Linux**） |
| `swift-cli` | ring-builder、recon、drive-audit、get-nodes、info 等 |

工作区根还有误放的 `crates/lib.rs` / `crates/main.rs` 历史噪音（曾有 commit 清理 proxy crate 根下的同类文件）；以各 crate 内 `src/` 为准。

---

## 4. 完成度（以 PLAN.md 台账为准）

### 已完成（大块）

- **Phase 0：** swift-core、swift-ring（golden）
- **Phase 1：** diskfile 格式层 + lifecycle；object-server 主动词（GET/HEAD/PUT/POST/DELETE + container_update）
- **Phase 2/3 守护进程：** auditor、updater、expirer、reaper、db_replicator 循环、container-sync、sharder 端到端、reconciler move 等
- **Phase 3：** account/container backend + server 全动词 + REPLICATE 接收侧
- **Phase 4：** proxy 基础与 object 路径、middleware 批次 1/2、SLO/DLO、ACL、keystone **authorize 决策**、crypto-meta、条件请求与 multipart/byteranges
- **Phase 4 EC：** 数据面在 **Linux** 上完成（`ec` feature）：encode/fan-out/GET decode/reconstructor；macOS 默认构建不碰 liberasurecode
- **Phase 5：** ring builder/CLI、recon、relinker、drive-audit、manage-shard-ranges、dispersion 等

PLAN 在 ultracode 冲刺中多次记录 **500+ workspace tests green + clippy clean**（数字随会话增长：518 → 561 → 571 → 597…）。接手时应用：

```bash
cd /Users/oboy/Downloads/swift-master/rust
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

自行确认当前绿红，**不要盲信历史数字**。

### 未完成 / 后续（诚实清单）

| 优先级 | 项 | 说明 |
|---|---|---|
| 高 | **Phase 6 cutover** | 打包、文档、迁移指南；组件级混部验证剧本 |
| 高 | **Object REPLICATE 动词** | `swift-object-server` 现显式 **501**（`lib.rs`：`REPLICATE not yet implemented`）；Allow 头已广告该动词 |
| 高 | **ssync** 对象复制通道 | 与 REPLICATE/rsync 并列的一致性路径；历史上 deferred |
| 高 | **EC 协议完整形态** | multipart-MIME + multiphase-commit PUT；ranged EC GET；ssync fragment 传输（数据面已可用的 plain-fragment 契约之外） |
| 中 | memcache 缓存 account/container info | 正确性已有 live HEAD，这是优化 |
| 中 | 流式 encrypter/decrypter middleware 接线 | 原语 + crypto-meta 已有 |
| 中 | proxy X-Newest / resumable GET 迭代器 | 跟进优化 |
| 低/外依赖 | Keystone **token 校验** | authorize 逻辑已 port；活 Keystone 外置 |
| 低/外依赖 | KMIP/KMS keymaster | 外置 KMS |
| 环境 | macOS 无 liberasurecode | EC 只在 Linux（`ec` feature）验证 |

**注意：** PLAN.md 中部有一段 ultracode 早期「Still open」列表（SLO/keystone/EC blocked）**已被后文推翻**，以文末 **Cutover & remaining** + 台账表为准。

---

## 5. 工作约定（不可破）

1. **契约优先：** 每个 on-disk / wire 格式必须能 Python 写 → Rust 读 与 Rust 写 → Python 读（golden）。
2. **模块头注释** 写明对应 Python 文件 + deferrals。
3. **fixture：** 各 crate `tests/fixtures/generate.py` 用真实 Python Swift（python3.11 / mise 环境）产出 `expectations.json`。
4. **里程碑定义：** `cargo test` 绿 + clippy 干净 + 独立 commit + 更新 `PLAN.md` 台账。
5. **strangler：** 不追求一次性替换整集群；单组件可混部。
6. **EC：** 默认 `cargo test` 不含 `ec`；Linux 上：`cargo test -p swift-ec --features ec` 及 object/proxy 相关 integration。

### 依赖映射（Python → Rust）

eventlet→tokio · WSGI/Paste→hyper+tower · swob→swift-http · sqlite3→rusqlite ·  
PyECLib→liberasurecode FFI · xattr→rustix · pickle→手写 codec（字节级）· cryptography→RustCrypto

---

## 6. 怎么跑

```bash
cd /Users/oboy/Downloads/swift-master/rust

# 默认工作区（macOS）
# 注意：2026-07-19 在本机 macOS 上 `cargo test --workspace` 曾因
# swift-ec 链接 liberasurecode 失败而整仓 list/compile 中断。
# 若再现，先排除 ec 或只测非 ec crate：
cargo test --workspace --exclude swift-ec
cargo build --workspace --exclude swift-ec
cargo clippy --workspace --exclude swift-ec

# 单测某个 crate
cargo test -p swift-proxy-server
cargo test -p swift-diskfile
cargo test -p swift-object-server

# Linux + liberasurecode 时
cargo test -p swift-ec --features ec
# 以及 PLAN 中 ec_integration 相关路径
```

二进制（build 后在 `target/debug/` 或 `release/`）：  
`swift-proxy-server`、`swift-object-server`、`swift-container-server`、`swift-account-server`、  
`swift-ring-builder`、`swift-recon`、`swift-drive-audit`、`swift-manage-shard-ranges`、  
`swift-object-updater` 等（以各 crate `Cargo.toml` `[[bin]]` 为准）。

上游 Python 树仍可按 OpenStack 方式跑 functional（`.functests`）——Phase 4 门禁愿景是 **Rust proxy 顶在 Python 集群前跑未修改的 functional**。

---

## 7. 兼容契约速查

| 契约 | Python 锚点 | 状态 |
|---|---|---|
| Client REST + S3 | `swift/proxy/`、`middleware/s3api/` | 大部分；S3 核心 crate 在，完整互通需持续测 |
| Ring v1/v2 | `swift/common/ring/` | ✅ |
| Object on-disk | `swift/obj/diskfile.py` | ✅ golden（pickle in xattrs 是最大雷区，已对过） |
| Account/Container DB | `swift/common/db.py`、`*/backend.py` | ✅ |
| Replication | `db_replicator.py`、`ssync_*` | REPLICATE/rsync 路径大量完成；**ssync 对象路径仍欠** |
| Internal backend HTTP | `bufferedhttp`、`request_helpers` | 进行中随 proxy/server 修 header 语义（见近期 commit） |

---

## 8. 接手后最安全的下一步（推荐顺序）

1. **读** `rust/PLAN.md` 全文台账 + Cutover 节（30–45 min）。  
2. **跑** `cargo test --workspace`，记录失败清单（若有）。  
3. **不要** 从 21MB Claude transcript 恢复工具调用；只把 PLAN + git log 当真相。  
4. 选一条未完成主线（建议二选一）：  
   - **A. 一致性/复制：** 实现 object-server **REPLICATE**（现 501）+ ssync / replicator 与 Python probe 对齐；  
   - **B. 验收/cutover：** 写混部剧本（Rust object-server 进 SAIO/探针）+ Phase 6 文档骨架；修好 macOS 下 workspace 测试对 `swift-ec` 的链接干扰（exclude 或纯 feature-gate）。  
5. 每完成一块：**测试绿 → commit → 改 PLAN 台账一行**。  
6. EC 相关只在 Linux runner 上开 `ec` feature。

### 明确不要做的事

- 不要在 macOS 上硬链 liberasurecode 当成功标准。  
- 不要把 `worktree-wf_*` 分支当最新功能源。  
- 不要手改 golden fixture 去「凑绿」——先查 Python 是否才是真相。  
- 不要假设 Claude session 的 background task 仍有效。

---

## 9. 相关路径与 session

| 资源 | 路径 |
|---|---|
| 计划 | `rust/PLAN.md` |
| 工作区 | `rust/Cargo.toml` |
| Claude 历史 | `~/.claude/projects/-Users-oboy-Downloads-swift-master/27d09c95-….jsonl` |
| 本交接副本 | `~/Downloads/HANDOFF-swift-master.md`（建议同步进仓：`rust/HANDOFF.md`） |

---

## 10. 状态一句话（给下一任）

**Rust Swift 重写已越过「能否字节兼容」的主峰，进入 cutover、ssync、EC 协议完整化与持续 functional 对齐阶段。分支 `claude/phase1-diskfile` @ `5a1ee7d` 干净可编；从 PLAN 台账接，不从过期 Claude 会话接。**
