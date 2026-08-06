# 三阶段公平测试（用户口径 · 权威）

旧 R0–R8（2026-08-03）只作**历史基线 / 非正式**。正式结论只认本文件下的阶段。

并行工程线：在阶段 2 开测前，用 `swift-deploy apply`（`stack=rust`）收敛出合格 Keepalived+HAProxy 四节点集群（见下「合格」定义）。阶段 1A **不依赖** LB / 全管道。

## 固定角色

| 阶段 | 发请求 | 被测 | 监控/留存 | 硬约束 |
|------|--------|------|-----------|--------|
| 一 | swift1（只发请求） | swift2=Python SAIO；swift3=Rust SAIO | swift4（只监控） | **swift1/4 不安装、不启动任何 Swift 服务** |
| 二 | swift1 | 四台只跑 Rust 集群；单机全关 | swift4 | 阶段 2 前门禁：deploy-rs 合格 LB |
| 三 | swift1（请求+监控） | swift2/3/4 上 Python+Rust 各一套三节点 | swift1 | 数据面只在 2/3/4；分盘分端口 |

## 阶段一：双单机 API

| 轮次 | 中间件 | 停线 |
|------|--------|------|
| 1A 薄管道 | 两侧最小集对齐 | 套件失败=0；差异只记「尚未支持」 |
| 1B 已实现子集 | 两侧同一可部署名单；缺口单表 | **禁止**写成全 Paste 已对齐 |

## 阶段二：仅 Rust 集群

小→大性能；单入口与 VIP **分表**；故障注入。开测前必须通过下方「合格」门禁。

## 阶段三：三节点双实现

3A 装齐 → 3B 双侧 API → 3C 停 Python 测 Rust → 3D 停 Rust 测 Python。

## 「合格」Rust LB 集群（阶段 2 门禁）

由 `swift-deploy-rs/bundle-rust` 收敛，禁止再以手工 `install-cluster` HA 当真理源。

| 项 | 验收 |
|----|------|
| 入口 | `ingress.mode=keepalived`：VIP + 每节点 HAProxy，后端=全部 proxy business IP |
| 均衡 | `balance roundrobin`（共享 HMAC tempauth） |
| VIP bind | `bind *` + `ip_nonlocal_bind=1`；failover 后新 MASTER 可服务 |
| 部署 | `swift-deploy apply` 可收敛；重启后仍健康 |
| 冒烟 | VIP auth；同 token 四 proxy；PUT/GET；≥40 请求四后端有流量；停 MASTER keepalived+haproxy 后 VIP 漂移且 IO 通 |
| 中间件 | catch_errors/gatekeeper/healthcheck/tempauth/copy/slo/dlo（+可配 ratelimit）；不宣称 bulk/tempurl/Keystone/S3 |

证据目录约定：`tools/test-results/deploy-rs-rust-lb-YYYYMMDD/`。

## 报告纪律

每阶段/子轮一份人话 HTML（需求 / 动作·环境·效果 / 剩余）。禁止用 R0–R8 主表冒充本规划正式结论。

## 开工顺序

1. 文档归档（本文件 + ROUNDS/CONTABO/lab-cluster）
2. 并行：bundle-rust HMAC/roundrobin/Keepalived + Contabo apply 验收
3. 阶段 1A → 1B →（门禁绿）阶段 2 → 阶段 3

## 状态（2026-08-04）

| 项 | 状态 | 证据 |
|----|------|------|
| 阶段 1A 薄管道 | **PASS** 双侧 54/54 | `tools/test-results/phase-1a-20260804/` |
| 阶段 1B 已实现子集 | **PASS** 双侧 54/54；缺口表诚实 | `tools/test-results/phase-1b-20260804/` |
| B4 子集 pipeline 接线 | **代码 DONE**（可选 `[pipeline:main]`） | proxy `main.rs` + 单测 |
| B3 deploy-rs LB 门禁 | **PASS** | `tools/test-results/deploy-rs-rust-lb-20260804/` |
| 阶段 2 | **补全**：VIP 矩阵 fail=0 **PASS**；DIRECT 单入口 **WARN**（分表）；chaos **PASS**；soak≥1h fail=0 **PASS** | `tools/test-results/phase-2-20260804/` |
| 阶段 3 | **3A/3B/3D FROZEN**（`PYTHON_CLUSTER_ABSENT`）；3C Rust 独占 2/3/4 **backlog** | `tools/test-results/phase-3-20260804/` · prep `wave4-python-prep-20260805/`（仍无 live 集群） |
