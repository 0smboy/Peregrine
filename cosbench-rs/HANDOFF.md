# 交接文档：COSBench / cabt 维护与 Rust 重写

**日期：** 2026-07-17  
**主机：** AWS Rocky Linux `root@18.232.108.188`  
**账号：** GitHub `0smboy`  
**状态：** 已在 AWS 构建、mock 验证；代码已推送到你的 GitHub 分支  

---

## 1. 一句话结论

| 项目 | 结论 |
|------|------|
| 磁盘 | 100G EBS 原先只用 ~9G 根分区，已在线扩到 ~99G |
| COSBench（Java） | 上游休眠；本地维护分支整合了高价值 PR |
| cosbench-rs | Java 核心引擎的 Rust 重写（v1.0），可独立压测 S3/Swift |
| cabt-rs | 原 `x86-64/cabt` bash 自动化的 Rust 重写，默认驱动 cosbench-rs |
| Excel 报告 | 原 Python2 + `standard.so`/`fool.so` 已用纯 Rust 重写 |

**新工作主线：** `/root/work/cabt-rs` + `/root/work/cosbench-rs`  
**旧 Java COSBench 维护快照：** `/root/work/cosbench` @ `maintained/0.4.2-plus`

---

## 2. 机器与目录布局

```
/root/work/
├── COSBENCH_PLAN.md          # COSBench PR/Issue  triage 计划
├── cosbench/                 # Java 源码维护 fork
│   └── branch: maintained/0.4.2-plus
├── cosbench-rs/              # Rust 压测引擎 v1.0
│   └── target/release/cosbench-rs
├── cabt-rs/                  # Rust cabt 自动化 v1.0
│   └── target/release/cabt
├── cabt-src/                 # 原 cabt 仓库拷贝（参考）
└── HANDOFF.md                # 本文件（若已同步）

/root/.cabt/                  # cabt 运行时状态
├── config/                   # wid 计数、中间 csv
├── result/                   # 普通任务结果
└── fool/                     # fool 套件结果
```

### 磁盘（已完成）

| 项 | 值 |
|----|-----|
| 盘 | `nvme0n1` 100G |
| 根 LV | `rocky/lvroot` XFS |
| 扩容前 | ~8.8G，约 51% |
| 扩容后 | ~99G，约 6–12% 使用 |
| 路径 | `growpart` → `pvresize` → `lvextend +100%FREE` → `xfs_growfs /`（在线，未重启） |

---

## 3. GitHub 位置（你的账号）

> 当前 PAT **不能创建新仓库名**，故主仓复用了已有空仓/分支。可在网页 Settings 里改名。

| 内容 | 仓库 / 分支 | 说明 |
|------|-------------|------|
| **cosbench-rs 主发布** | https://github.com/0smboy/myfile **main** | 建议网页改名为 `cosbench-rs` |
| cosbench-rs 镜像 | https://github.com/0smboy/testone/tree/cosbench-rs | |
| Java COSBench 维护快照 | https://github.com/0smboy/testone/tree/cosbench-maintained | 含整合 PR 的树快照 |
| **cabt Rust** | https://github.com/0smboy/cabt/tree/rust-x86-64/x86-64-rs | 原私有仓 `cabt` 新分支 |
| cabt 镜像 | https://github.com/0smboy/myfile/tree/cabt-rs | |
| cabt 镜像 | https://github.com/0smboy/testone/tree/cabt-rs | |

本地原 cabt 仓：`/Users/oboy/cabt`，分支 `rust-x86-64` 已推送。

---

## 4. COSBench（Java）维护说明

### 4.1 上游现实

- 仓库：https://github.com/intel-cloud/cosbench  
- 最后有意义 release：`v0.4.2`（约 2017）  
- 无写权限，**不能往上游 merge**  
- 本地：`/root/work/cosbench`，分支 **`maintained/0.4.2-plus`**

### 4.2 已整合的 PR / 修复

| PR | 内容 | 处理 |
|----|------|------|
| #426 | hashCheck >2GB int 溢出 | merge |
| #417 | 去 CORBA（Java 11+） | merge |
| #420 / #418 | classpath 构建修复 | merge |
| #345 | librados sample XML | merge |
| #424 | S3 list | 与 #351 合并进 S3Storage |
| #351 | S3 range GET | 同上 |
| #396 | 错误统计 / 负 index / 计时 | **选择性**核心修复 |
| #428 | Keystone v3 | 应用（替代 #421） |
| #416 | equinox launcher 升级 | merge + 脚本引用更新 |

拒绝/延后：#410 jar 轰炸、#403/#338 噪音、#373 大杂烩、#355 ECS 等。详见 `/root/work/COSBENCH_PLAN.md`。

### 4.3 Issue 策略

- 有 PR 的 bug：在维护分支已修  
- 问答类 issue：未逐条关  
- 指标/超时等问题：在 cosbench-rs 侧用正确设计规避  

---

## 5. cosbench-rs（压测引擎）

### 5.1 能力（v1.0）

- Stages：init / prepare / main / cleanup（可 sequential）  
- Ops：write / read / delete / list / create_container / delete_container  
- Storage：**mock**、**S3**（multipart、range GET、path-style）、**Swift**（Keystone token）  
- Auth：Keystone v3（domain name/id）  
- 指标：ops、bytes、success、p50/p95/p99、吞吐  
- 报告：JSON / CSV  
- HTTP 控制面：`cosbench-rs serve --bind 0.0.0.0:8080`  
- COSBench XML 子集 → YAML：`import-xml`  

**不是** OSGi + Freemarker 双进程 Web UI 的逐行移植。

### 5.2 命令

```bash
cd /root/work/cosbench-rs
./target/release/cosbench-rs run -c examples/mock-mixed.yaml
./target/release/cosbench-rs run -c examples/s3-write-read.yaml --report-dir reports
./target/release/cosbench-rs import-xml -i examples/sample-cosbench.xml -o /tmp/w.yaml
./target/release/cosbench-rs serve --bind 0.0.0.0:8080
cargo test --workspace
```

### 5.3 示例配置

- `examples/mock-mixed.yaml`  
- `examples/s3-write-read.yaml`  
- `examples/s3-multipart-large.yaml`  
- `examples/keystone-v3.yaml`  
- `examples/swift-keystone.yaml`  

---

## 6. cabt-rs（自动化包装）

### 6.1 相对原 x86-64/cabt

| 原件 | Rust |
|------|------|
| `x86-64/cabt` bash + base64 自解压 | `/root/work/cabt-rs` 单一二进制 |
| 调 Java COSBench HTTP | 默认 **cosbench-rs**；可选 `--backend java` |
| Python2 + standard.so / fool.so 出 Excel | `src/report_xlsx.rs` 纯 Rust xlsx |
| `~/.cabt/` 状态目录 | 保留同结构 |

### 6.2 CLI

```bash
# 安装
install -m 755 /root/work/cabt-rs/target/release/cabt /usr/local/bin/cabt

# 任务名: <size>_<read|write>_<workers>
cabt run 64KB_write_20 --backend mock              # 无对象存储干跑
cabt run 64KB_write_20 --backend cosbench-rs       # 真实 S3（默认）
cabt run 64KB_write_20 --backend java              # 旧 controller
cabt run fool --start-task 64KB_write_100
cabt list
cabt list fool
cabt remove w1
cabt collect --out standard.xlsx                   # Excel + csv sidecar
cabt run fool --collect                            # fool 基准/并发 Excel
```

### 6.3 环境变量

| 变量 | 含义 |
|------|------|
| `accesskey` / `secretkey` / `endpoint` | S3 凭证（或 `~/.s3cfg`） |
| `CABT_SKIP_S3_PROBE=1` | 跳过 endpoint TCP 探测 |
| `cosbench_url` | 报告抬头 / Java 后端（默认 `http://127.0.0.1:19088/controller`） |
| `CABT_POLICY` / `CABT_POLICY_NUM` / `CABT_POLICY_STR` | 报告里的策略文案 |
| `CABT_STORAGE_NODES` | 报告存储节点说明 |

`endpoint` 写 `host:port`，不要带 `http://`（代码会补）。

### 6.4 依赖关系

```
cabt-rs  --path-->  cosbench-rs/crates/cosbench-core
```

构建要求两者并列：

```text
/root/work/cosbench-rs
/root/work/cabt-rs
```

---

## 7. Python 出报告 → Rust（重点）

### 7.1 原实现

| 文件 | 库 | 函数 |
|------|-----|------|
| `dep-packages/standard.so` | xltpl + Jinja2 | `render(template, collect, values, out)` |
| `dep-packages/fool.so` | openpyxl | `update_xlsx(one_csv, more_csv, template, out, values)` |
| 模板 | `standard.xlsx` / `fool.xlsx` | 中英表头 + 策略说明 |

### 7.2 新实现

- 模块：`cabt-rs/src/report_xlsx.rs`  
- 库：`rust_xlsxwriter`  
- `write_standard_xlsx`：普通任务汇总表（对齐原 standard 列）  
- `write_fool_xlsx`：基准（1 worker）+ 并发 +「明细」sheet  

**不再需要** Python2、`~/.cabt/site-packages`、`.so`。

已验证：`file` 识别为 `Microsoft Excel 2007+`。

---

## 8. 验证记录（2026-07-17）

| 检查 | 结果 |
|------|------|
| 根盘扩容 | 99G，可用充足 |
| cosbench-rs unit + e2e mock | 通过，main 100% success |
| cosbench-rs release 二进制 | ~26MB |
| cabt unit tests | 通过 |
| cabt mock write/read/list/collect | 通过 |
| cabt Excel collect | 生成合法 xlsx |
| GitHub 推送 | myfile / testone / cabt 分支已更新 |

---

## 9. 未做 / 明确不做

1. 往 `intel-cloud/cosbench` 上游提 PR / merge（无权限 + 项目休眠）  
2. 完整 OSGi Controller/Driver Freemarker Web UI 移植  
3. Amplidata / CDMI / ECS / OpenIO / librados JNI 等冷门插件  
4. 与原 `standard.xlsx` 像素级样式 1:1（布局与列等价，样式简化）  
5. 真实 MinIO / Ceph / 生产 Swift 的联调（mock 与代码路径已通，需你方 endpoint）  
6. 新 GitHub 空仓名 `cosbench-rs`（PAT 无 create；请网页改名 `myfile`）  

---

## 10. 建议后续步骤

1. **GitHub 改名（可选）**  
   - `myfile` → `cosbench-rs`  
   - 或新建正式仓后把 `main` / `cabt-rs` 迁过去  

2. **真实压测**  
   ```bash
   export accesskey=... secretkey=... endpoint=minio:9000
   cabt run 64KB_write_100 --backend cosbench-rs --runtime 150
   cabt collect --out /tmp/report.xlsx
   ```

3. **合并 cabt 分支**  
   - PR：`0smboy/cabt` 的 `rust-x86-64` → `main`  

4. **清理**  
   - 部分分支里可能夹带生成的 `benchmark_report*.xlsx` 样例，可删  

---

## 11. 快速恢复命令

```bash
# SSH
ssh root@18.232.108.188

# 引擎
cd /root/work/cosbench-rs && cargo build --release -p cosbench-cli
./target/release/cosbench-rs run -c examples/mock-mixed.yaml

# 自动化
cd /root/work/cabt-rs && cargo build --release
./target/release/cabt run 64KB_write_4 --backend mock --runtime 2
./target/release/cabt collect --out /tmp/out.xlsx

# 拉代码
git clone -b main https://github.com/0smboy/myfile.git cosbench-rs
git clone -b cabt-rs https://github.com/0smboy/myfile.git cabt-rs
# cabt 官方仓：
git clone -b rust-x86-64 https://github.com/0smboy/cabt.git
# 构建 cabt-rs 需 sibling cosbench-rs（见 cabt-rs Cargo.toml path）
```

---

## 12. 关键人 / 范围边界

- 本交接覆盖：**磁盘扩容、COSBench PR 整合、cosbench-rs、cabt-rs、Excel Rust 化、GitHub 分支推送**。  
- 压测业务参数（对象大小矩阵、生产 endpoint、策略文案）由使用方配置。  
- 原 cabt 依赖的 Swift 节点策略探测（读 `/etc/swift/swift.conf`）未强绑；报告策略字段可用环境变量注入。  

---

*文档生成：会话交付用。权威可运行状态以 AWS `/root/work` 与上述 GitHub 分支为准。*
