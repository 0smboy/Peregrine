# S3 全量目录计划（测试门，不是对齐门）

- 日期：2026-08-18
- 官方目录：https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html
- 口径：一次做完整个 AWS 目录是假话。本计划把 **Amazon S3 数据面** 收进合同，用 **现场客户端测试** 当唯一 PASS。
- 冻结 57 案 `strict-s3-parity.py`（SHA `f622b336…`）**只当 Python 对齐对照，不当客户端保证**。禁止改它。

## 1. 合同切分

| 集合 | 来源 | 进合同？ | PASS 条件 |
|---|---|---|---|
| **IN** | Amazon S3 Actions（CreateBucket … WriteGetObjectResponse） | 是 | 每条有现场用例；实现面 AWS 语义对；未实现必须 `501` + `Code=NotImplemented` + 非空 XML |
| **OUT** | S3 Control / Outposts / Tables / Vectors / Files | 否 | 永不宣称。列在附录，不进 PASS |

IN 约 116 条（以官方页 Amazon S3 段为准，页面增删时重抓）。

## 2. 禁止的假 PASS

下列任一出现，该案 **FAIL**，对齐分再高也不算：

1. HTTP 2xx 且 body 空，而客户端要解 XML（`s3cmd ls` 的 204 空 body）。
2. 只测了 `GET /bucket`，没测 `GET /bucket/`（s3cmd 2.4 path-style）。
3. 只用单元 mock，没有打 VIP `https://10.0.0.10:8085`。
4. 用改 57 案断言、或把 extras 改 501，刷出来的分。
5. 把 leftover `s3://mytest` / `AUTH_lab` / `AUTH_test` 当客户验收。

## 3. 记分板（每条官方 Action 一行）

| 分 | 含义 |
|---|---|
| **LIVE_PASS** | 现场真实客户端（s3cmd 和/或 SigV4 path-style）状态码 + Error/Result `Code` 符合 AWS |
| **HONEST_501** | `501` + `NotImplemented` + 非空 `application/xml`（允许暂时停在未实现） |
| **FAIL** | 错码、空 body、末尾斜杠分叉、落到 Swift 账户面、或根本没用例 |
| **OUT** | 不在 IN |

总门：`FAIL == 0`。`HONEST_501 > 0` 时 **不是**「全量跑通」，只能报「实现面 LIVE_PASS + 其余诚实 501」。全量跑通 = IN 全部 LIVE_PASS。

## 4. 波次（测试先行，实现随后）

### W0 — 现在并行（保证物：矩阵跑手 + 对账表 + 第一份现场 JSON）

- **W0-A 对账**：官方 IN 116 ↔ `middleware.rs` 分发。每条标：已实现 / 声明 501 / 未接线（漏到 Swift = 按 FAIL 设计用例）。
- **W0-B 矩阵跑手**：新文件 `tools/strict-s3-live-matrix.py`。Stdlib + 节点 `s3cmd`。读 `/root/.s3cfg-tempauth`。不打印密钥。不覆盖已有 JSON。自建 `s3-matrix-*` 桶，测完删。禁止写 `mytest`。
- **W0-C 负例**：所有桶操作的 `/bucket` 与 `/bucket/`；`HEAD`/`PUT`/`DELETE` 同样成对。账户根 `PUT/DELETE/POST/HEAD /` 必须 405（Guard 已上，禁止当无害触摸去删租户）。
- **W0-D 跑 VIP**：`--rust https://10.0.0.10:8085 --rust-insecure`，报告 `/root/work/evidence/strict-s3-live-matrix-YYYYMMDD.json`。

W0 完成定义：JSON 里 IN 每条都有结果；`executed == required`；`FAIL` 列表可点名到 Action。

### W1 — 已声称实现面上的 FAIL

先修测试抓到的洞（空 body、斜杠、错码），swift3 `--offline --locked` 编，1→4→3→2 滚 proxy，再跑矩阵。不宣称 W1 等于全量。

### W2 — 标准桶配置（现 501 → 实现 + 用例先红后绿）

policy, website, logging, notification, encryption, publicAccessBlock, ownershipControls, requestPayment, accelerate。每条：先加红测，再实现，再 VIP 绿。

### W3 — 分析 / 复制 / 选择

analytics, inventory, metrics, intelligent-tiering, replication, select, torrent。同上：红测 → 实现 → 绿。

### W4 — 新 AWS 面（Metadata / ABAC / Annotations / Rename / Directory / Session / Object Lambda）

默认 HONEST_501，直到单独开窗。禁止静默落到 Swift。

## 5. 现场约束（所有 agent 必须遵守）

- 产品树：`…/peregrine-grok-merge-20260814`。Mac 不 Cargo。编译只在 swift3。
- 不改 `strict-s3-parity.py`。不 501 掉 extras。
- 不启 reaper。不重启 Keepalived / 不挪 VIP。
- 不删 leftover。探针桶自建自删。
- 密钥只在节点，报告里只写状态码和 Code。

## 6. 并行分工（W0）

| Agent | 交付 | 完成定义 |
|---|---|---|
| A 对账 | `docs/fairness-lab/S3-IN-INVENTORY-20260818.md` | 116 行，每行一个官方 Action + rust 路径 + 预期分 |
| B 矩阵 | `tools/strict-s3-live-matrix.py` | `--selftest` 过；覆盖 IN + 斜杠对 + s3cmd 核心 |
| C 现场 | VIP 跑一份 JSON | `FAIL`/`LIVE_PASS`/`HONEST_501` 计数；空 body 必 FAIL |

A/B 可并行。C 等 B 落地后立刻跑。W1 只修 C 点名的 FAIL。
