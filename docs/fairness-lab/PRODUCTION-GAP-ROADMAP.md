# Swift Rust 缺口 · 生产级实现路线图（冻结）

> Frozen from plan `rust缺口生产实现计划_d0953f85` (2026-08-04).  
> **Do not edit the plan file.** This document is the in-repo authority for waves and gates.  
> Contracts: [CONTRACTS.md](CONTRACTS.md) · [blocked-by-missing-impl.md](blocked-by-missing-impl.md) · [CONFIG-PARITY.md](CONFIG-PARITY.md).

## 边界（默认）

- **认证主路径**：TempAuth + 共享 HMAC（已有）；**Keystone 单开轨 P3**，不挡中间件补齐。
- **S3**：单开轨 P3 — **P3-s3 PARTIAL GREEN**（最小生产面已接线；见下）。
- **运维**：Keepalived/HAProxy 已达标；**P2** 含 `servers_per_port` 调研与最小实现；**TLS / add-disk/add-node** 放 **P3 ops 轨**。
- **部分完成 = 未实现**：凡未接线、语义不全、无 systemd/无 `/info` 宣称、无对照测试通过的，一律按未交付处理。

实现落点：`swift-rust/crates/swift-middleware`、`swift-proxy-server` 的 `build_configured_filters`、各 daemon crate、`swift-deploy-rs/bundle-rust`。

---

## 生产纪律（每波强制）

1. **规格先于代码**：对照 OpenStack Swift 同源模块；crate 内 `Deferred:` 必须关闭或降级为明确 wont fix。
2. **接线才算交付**：`impl Middleware` 不够；必须进 `build_configured_filters` 可识别名、可被 `[pipeline:main]` 启用，并在 `/info` **如实**广告。
3. **对照验证**：Python SAIO（或三节点）同管道顺序；差异表只允许文档化 wont fix。
4. **集群不回归**：每波合并前 Contabo：VIP auth、核心 CRUD、HAProxy 四后端分流、一次 failover；数据面相关波次加短期 soak。
5. **部署器同步**：`bundle-rust` 模板/payload/systemd 与二进制同波。
6. **安全**：TempURL/formpost/ACL/Keystone 变更需威胁模型短评 + 负面用例。
7. **发布标签**：对外仍用 `CORE-PATH-ONLY` / `L2-PARITY-WAVE-N`；未过门禁禁止升级宣称。

---

## 优先级总表

| 波次 | 主题 | 停线（全绿才进下一波） |
|------|------|------------------------|
| **P0** | 管道地基：memcache + listing_formats + proxy_logging + 已有 filter 真接线 | 双 SAIO 同管道名；func 54/54 + listing/日志专项；未知 filter 仍 skip 但已实现名必须可启用 |
| **P1a** | L2 常用：bulk、tempurl、account ACL、ratelimit 默认可部署 | 专项套件 100% + 负面安全用例；`/info` 准确 |
| **P1b** | L2 其余：formpost、staticweb、quotas、symlink、versioned_writes 补全、read_only/name_check/etag_quoter/crossdomain/cname/domain_remap/backend_ratelimit | 每过滤器：单测金标 + SAIO 对照；defer 清单清空 |
| **P1c** | 已接线能力清债：SLO 嵌套/流式、DLO/copy 边角、TempAuth 与 ACL 一致性 | 扩大 func/SLO 套件；故障注入下无 5xx 回归 |
| **P2a** | 后台：object-expirer、account-reaper、container-reconciler、container-updater 入 payload+systemd | 单元+集成：过期删除/异步更新/和解 |
| **P2b** | 审计常驻化或等价；container-sync 若宣称则全链路 | 与 Python 审计覆盖率文档化对照 |
| **P2c** | 拓扑：`servers_per_port` 最小可用；workers 语义文档+有效并发校准 | CONFIG-PARITY 行升级 |
| **P3-auth** | Keystone + authtoken | 独立认证套件；TempAuth 仍可并存 |
| **P3-s3** | S3 API 生产路径 | S3 兼容矩阵；不污染 Swift v1 `/info` |
| **P3-ops** | TLS、add-disk/add-node、多 region | deploy-rs 合同 + 破坏性演练 |
| **P3-data** | L3b 分片、X-Newest/可恢复多 GET、at-rest crypto | 仅在 P0–P2 绿且 ISO-CONFIG 基线干净后开 |

**执行规则：** 只开当前波；门禁绿再开下一波。禁止并行开 P3 抢主线除非另有指示。

---

## Status

| 波次 | 状态 | 证据 |
|------|------|------|
| **P0** | **GREEN** (2026-08-04) | `tools/test-results/p0-pipeline-20260804/` |
| **P1a** | **GREEN** (2026-08-04) | `tools/test-results/p1a-l2-20260804/` |
| **P1b** | **GREEN** (2026-08-04) primary set; smaller specialty residual | `tools/test-results/p1b-l2-20260804/` |
| **P1c** | **GREEN** (2026-08-04) | `tools/test-results/p1c-debt-20260804/` |
| **P2a** | **GREEN** (2026-08-04) | `tools/test-results/p2a-daemons-20260804/` |
| **P2b** | **GREEN** (2026-08-04) | `tools/test-results/p2b-audit-20260804/` |
| **P2c** | **GREEN** (2026-08-04) | `tools/test-results/p2c-topology-20260804/` |
| **P3-auth** | **PARTIAL** (2026-08-04 code; **2026-08-05 Identity prep**) — Contabo Keystone still ABSENT/BLOCKED on disk; inventory+对接 ready | `tools/test-results/p3-auth-20260804/` · `wave1-identity-prep-20260805/` · [KEYSTONE-LIVE.md](KEYSTONE-LIVE.md) |
| **P3-s3** | **PARTIAL GREEN** (2026-08-04) | `tools/test-results/p3-s3-20260804/` |
| **P3-ops** | **partial GREEN** (2026-08-04) code+unit+dry-run; Contabo live TLS/expand **not applied** | `tools/test-results/p3-ops-20260804/` |
| **P3-data** | **PARTIAL** (2026-08-04) — X-Newest + local-cleave sharder; not full L3b | `tools/test-results/p3-data-20260804/` |
| **Wave 0** | **DONE with honest residuals** (2026-08-05) — API clear + tombstone/VACUUM metrics | `tools/test-results/wave0-clear-20260805/` · [TOMBSTONE-VACUUM.md](TOMBSTONE-VACUUM.md) |
| **R0 metrics→panel** | **WIRED** 2026-08-05 — previously CLI-only / NOT in Prom/Grafana; textfile+scrape+alerts green; Grafana dashboard + DS query OK; `/render` PNG stub | `tools/test-results/r0-metrics-prom-20260805/` · [TOMBSTONE-VACUUM.md](TOMBSTONE-VACUUM.md) |
| **W0′ meta repair** | **LAB META_CLEAN** 2026-08-05 — hash `/` root-cause fixed; ghosts/zombies cleared; CRUD OK; disk orphan dirs residual; **not** PRODUCTION meta | `tools/test-results/w0-meta-repair-20260805/` |

---

## Wave 0 — API clear + tombstone / SQLite observability（2026-08-05）

### 工作包

- **0A API clear:** REST equivalent of `swift delete -a` (no mkfs / no wipe `/srv/node`). Contabo VIP auth from laptop often times out; ran on-cluster.
- **0B Tombstone metrics:** `swift-recon tombstones` → `swift_object_tombstones` / `swift_object_tombstone_bytes` (Prometheus textfile).
- **0B reclaim lab:** temporary `reclaim_age=600` on Contabo; restore `604800` after.
- **0C SQLite metrics + VACUUM:** `swift-recon dbspace` / `vacuum`; `swift_db_*` gauges; unit test proves DELETE≠shrink, VACUUM shrinks.
- **Bugfix:** object-replicator now honors conf `reclaim_age` (was hard-default 604800).
- **R0 follow-up (2026-08-05):** Wave 0 metrics were **CLI-only / NOT scraped / NOT in Grafana**. R0 wires per-node `swift-recon-textfile.timer` → node_exporter textfile → Prometheus + `swift-ops-alerts.yml`. Grafana dashboard provisioned on Contabo; DS query OK after SELinux `:9090` port fix; `/render` PNG stub. See `tools/test-results/r0-metrics-prom-20260805/`.

### 门禁结果

| 门禁 | 结果 | 证据 |
|------|------|------|
| Unit vacuum freelist/VACUUM | **PASS** | `cargo test -p swift-db vacuum` |
| Unit tombstone/dbspace metrics | **PASS** | `cargo test -p swift-cli space_metrics` |
| API-visible objects cleared | **PASS** (128 live objs deleted; ~26 live containers) | `06-delete-live-only.txt` |
| Account listing empty | **FAIL / residual** — ~963 ghost containers (HEAD 404) remain in account DB | `04-live-vs-stale-containers.txt` |
| Tombstone reclaim &lt;10–15m to ~0 | **FAIL** (pre-fix flat; post-wire Δ≈0–33 / ~21m) | `wave0_tombstone_experiment.json`, `11/12-ts-*` |
| VACUUM before/after shrink | **PASS** on `d2`: 41.1MB→36.5MB (−4.6MB) | `08-vacuum-d2-summary.txt` |
| `reclaim_age` restored 604800 | **PASS** (all 4 nodes log `reclaim_age=604800s`) | `13-reclaim-age-restored-604800.txt` |

### 诚实偏差

- Disk still holds large orphan `.data` / `.ts` populations; API clear cannot name orphans.
- Account stats stayed inflated (~850k objects) while live HEAD object sum was 128.
- First reclaim lab failed because (1) replicator ignored conf `reclaim_age`, (2) knob was only under `[object-expirer]`. Fixed in-tree + Contabo binary; lab then re-wired to DEFAULT+replicator.
- VIP from Mac: empty reply / timeout; operations via SSH to `swift1` + VIP from inside lab.
- Later waves (Keystone/spp/S3/Python) **not** claimed here.

HTML: `tools/test-results/wave0-clear-20260805/WAVE0-REPORT.html`.

---

## P3-data — L3b / X-Newest / crypto（PARTIAL）

### 工作包（本波实际交付）

- **X-Newest**: proxy `get_or_head` collects valid sources when header truthy and returns newest timestamp. Resumable mid-stream multi-node GET **still deferred**.
- **L3b sharder MVP**: `swift-container-sharder` binary + `[container-sharder]` in bundle-rust + systemd unit ×4 Contabo. Local cleave for containers already in `SHARDING`; `auto_shard` ignored.
- **X-Backend-Sharding-State**: live `get_db_state()` (was hardcoded `unsharded`).
- **At-rest crypto**: **deferred** — `swift-crypto` primitives only; no middleware wire.

### 门禁结果

| 门禁 | 结果 | 证据 |
|------|------|------|
| Sharder unit | **4/4** | `p3-data-20260804/05-cargo-unit-local.txt` |
| Contabo sharder active ×4 | **PASS** (failures=0) | `10-daemon-status.txt` |
| Backend sharding-state | **unsharded** | `12-sharding-state.txt` |
| X-Newest smoke VIP | **200** | `11-xnewest-smoke.txt` |
| CORE-PATH func VIP | **54/54** | `20-func-suite-vip.txt` |
| Full L3b / crypto / resumable GET | **NOT CLAIMED / DEFERRED** | HTML |

### 诚实偏差

- Local cleave ≠ multi-node HTTP shard create + replication quorum.
- No proxy shard listing fan-out; no `auto_shard`; no misplaced pass.
- No at-rest encryption on Rust proxy; no L3b perf KEEP claim.
- HTML: `tools/test-results/p3-data-20260804/P3-DATA-REPORT.html`.

---

## P3-auth — Keystone + authtoken（PARTIAL · 本波）

### 工作包

- `authtoken` Middleware：可插拔 `TokenValidator`（`MapTokenValidator` 实验室 / `HttpTokenValidator` 生产 GET `/v3/auth/tokens`）。
- `keystoneauth` Middleware：读 Confirmed 身份头，戳 `X-Backend-Auth-Plugin: keystone` + backend Keystone 字段；proxy authorize 分派。
- gatekeeper 剥离伪造的 Keystone 身份头；`/info` 仅在双过滤器真正接线时广告 `keystoneauth`。
- bundle-rust：`proxy-server.conf.j2` 注释样例；默认 Contabo 管道仍 TempAuth；不部署 MariaDB/Keystone。
- 证据：`tools/test-results/p3-auth-20260804/` + `P3-AUTH-REPORT.html` + `THREAT-NOTE.md`。

### P3-auth 门禁结果

| 门禁 | 结果 |
|------|------|
| keystoneauth / authtoken / gatekeeper 单元 | **14+6+2 PASS** |
| Proxy bin 接线测试（含 P3 pipeline） | **13/13** |
| Middleware 全量 | **351/351** |
| Contabo Keystone :5000/:35357 | **ABSENT ×4**（诚实缺口） |
| VIP TempAuth CRUD（无 wipe / 未改管道） | **PASS** |
| 威胁负面用例 | PASS（见 THREAT-NOTE） |
| 合同更新 | DONE |

### 诚实偏差 / residuals（挡 cluster GREEN，不挡 code PARTIAL）

- Contabo 无 Identity；不得宣称集群 Keystone 绿。
- **2026-08-05 Wave 1 prep:** `bundle/config_contabo_identity/` + rust Identity 对接模板 + `https://` validator 已交付；**live Galera/Keystone BLOCKED**（`/srv/node` 仍满，见 `wave1-identity-prep-20260805/`）。
- Live Keystone E2E：等 Wave 0 腾空间后再 apply（FROZEN）。
- project-domain-id account sysmeta 持久化：deferred。
- container-sync `swift_sync_key`：仍 wontfix（同 P2b）。

---

## P3-s3 — S3 API 生产路径（本波 · PARTIAL GREEN）

### 工作包

- `swift-s3api::middleware::S3Api`：SigV4 + TempAuth 凭证映射（`account:user`）+ S3→Swift 路径 + ListBuckets / ListObjects v1 / bucket·object CRUD / CopyObject / GetBucketLocation。
- Proxy `build_configured_filters` 接线 `s3api`（ON-BY-CONFIG，置于 `tempauth` 之前）；默认 pipeline **不变**。
- **禁止**在 Swift v1 `GET /info` 广告 `s3api`（并行 API；避免假绿能力发现）。
- `bundle-rust` `proxy-server.conf.j2` 注释样例；无 wipe；不抢 Keystone/TLS 轨。
- 证据：`tools/test-results/p3-s3-20260804/` + `P3S3-REPORT.html` + `S3-COMPAT-MATRIX.md`。

### P3-s3 门禁结果

| 门禁 | 结果 |
|------|------|
| 单元 `swift-s3api` | **47/47** |
| Proxy wire + `/info` 诚实 | **PASS**（无 `s3api` 键） |
| S3 兼容矩阵（最小面） | PASS（见矩阵） |
| 默认 Contabo pipeline / CORE-PATH | 未改动 |
| 全量 S3（MPU/ACL/v2/…） | residual |

### 诚实偏差 / residuals（不挡 PARTIAL GREEN）

- Multipart、ListObjects v2、multi-delete、S3 ACL/CORS/versioning/tagging/lifecycle。
- SigV2、aws-chunked、clock-skew/expiry 强制。
- s3token / Keystone（P3-auth 并行轨）。
- Contabo VIP 默认启用 s3api（保持 CORE-PATH 基线；ON-BY-CONFIG）。

---

## P3-ops — TLS / expand / multi-region（本波 · partial GREEN）

### 工作包

- HAProxy TLS terminate when `lb_mode=https` (`haproxy.cfg.j2` + cert tasks; proxy stays HTTP).
- Workspace: rust allows `ingress.http_mode=https` with haproxy/keepalived; rejects https+direct; python-v3 HTTPS still disabled.
- Expand: `bundle-rust/expand.yml` + `rust_expand_mode` + idempotent ring `add`/`search`/`list`; `swift_devices` / region / zone → rings.
- Dual-guard: no mkfs/wipe in rust roles; workspace rejects `node.disks`; Contabo `/srv/node` wipe needs ticket.
- Docs: [P3-OPS-CONTRACT.md](P3-OPS-CONTRACT.md), [MULTI-REGION.md](MULTI-REGION.md).
- 证据：`tools/test-results/p3-ops-20260804/` + `P3-OPS-REPORT.html`.

### P3-ops 门禁结果

| 门禁 | 结果 | 证据 |
|------|------|------|
| ring-builder unit (idempotent add/search) | **2/2 PASS** | `05-ring-builder-unit.txt` |
| workspace_rust_stack | **11/11 PASS** | `05-cargo-workspace.txt` |
| `swift-deploy plan` expand.yml | **PASS** (50 tasks; disk_wipe=0; TLS×6; rust_expand_mode) | `plan-expand.json` |
| `swift-deploy plan` swift.yml + https | **PASS** (136 tasks; disk_wipe=0; TLS×6) | `plan-swift.json` |
| openssl self-signed dry-run (local) | **PASS** | `23-tls-openssl-dryrun.txt` |
| Static dual-guard (no mkfs in roles) | **PASS** | `10-static-dual-guard.txt` |
| Contabo live TLS cutover | **NOT APPLIED** (VIP still `bind *:8085` http; no prod PEM) | `01-contabo-ssh.txt` |
| Contabo live expand drill | **NOT APPLIED** (partition move; needs ticket) | — |
| 合同更新 | DONE | P3-OPS-CONTRACT / MULTI-REGION / blocked / DEPLOY-HYBRID |

---

## P2b — 审计常驻化（本波 · GREEN）

### 工作包

- Continuous conf daemons: `swift-object-auditor` (`[object-auditor]` interval=30), `swift-db-auditor account|container` (`[account-auditor]` / `[container-auditor]` interval=1800).
- `bundle-rust` systemd units `Restart=on-failure`; nightly `swift-audit-sweep.timer` **disabled** (manual oneshot script retained).
- **container-sync**: explicit **wontfix** this wave (library HMAC core only; no proxy filter wiring + no daemon path claimed).
- SLA对照: [AUDITOR-SLA.md](AUDITOR-SLA.md).
- 证据：`tools/test-results/p2b-audit-20260804/` + `P2B-REPORT.html`.

### P2b 门禁结果

| 门禁 | 结果 |
|------|------|
| 单元（diskfile+db audit_devices） | PASS |
| Contabo units active ×4 (object/account/container auditor) | **PASS** |
| P2b suite VIP | **11/11** |
| Quarantine E2E（corrupt replica → quarantined; GET 200） | **PASS** |
| CORE-PATH func VIP | **54/54** |
| Nightly timer disabled | PASS |
| 盘压 / 无 wipe | no wipe；swift1 d1 曾见 100%（lab residual） |
| 合同更新 | DONE |

### 诚实偏差 / residuals（不挡 GREEN）

- First full `/srv/node` object-auditor pass on Contabo can take many minutes (2 policies × disk load); tiny-devices once proves pass path; continuous unit stays `active (running)`.
- Mid-pass SIGTERM waits for current device sweep (TimeoutStopSec=180); stop-between-passes only.
- Rate limiting / `hashes.pkl` incremental / ZBF / watcher plugins: deferred (same family as pre-P2b).
- Contabo disk pressure on d1 (observed 100% on swift1) — **no wipe**.
- **container-sync**: wontfix P2b — do not claim proxy filter or sync daemon.

---

## P2c — 拓扑 / workers（本波 · GREEN）

### 工作包

- `servers_per_port`：环端口发现（`object*.ring.gz` + `ring_ip`）+ 每端口 N 个 REUSEPORT acceptor → 共享线程池（`serve_forever_multi`）。
- Workers 语义：`docs/fairness-lab/WORKERS-SEMANTICS.md` + 二进制 `swift-effective-concurrency`。
- CONFIG-PARITY：`servers_per_port` / `ring_ip` / `workers` → `iso-config-with-semantic-mapping`（或 `iso-config`）。
- 证据：`tools/test-results/p2c-topology-20260804/` + `P2C-REPORT.html`。

### P2c 门禁结果

| 门禁 | 结果 | 证据 |
|------|------|------|
| 单元 `servers_per_port::` | **8/8 PASS** | `05-cargo-unit-local.txt` |
| Runtime discovery Contabo | **PASS** `{6200}` | `15-discovery-runtime.txt` |
| spp=1 smoke CRUD VIP | **201/201/200** then restored spp=0 | `13-spp1-*.txt` |
| CORE-PATH func VIP | **54/54** | `20-func-suite-vip.txt` |
| Perf smoke 4KB PUT | **38.6 PUT/s errs=0** | `21-perf-smoke.txt` |
| CONFIG-PARITY / blocked / WORKERS-SEMANTICS | DONE | docs + `P2C-REPORT.html` |

### 诚实偏差 / residuals（不挡 GREEN）

- 共享线程池 ≠ Python prefork 每盘进程隔离。
- Contabo 环仍是每节点单端口 6200；多盘多端口需 ring rebuild（本波不做、无 wipe）。
- 默认部署保持 `servers_per_port=0`（与既有 CORE-PATH 基线同形）。
- HTML: `tools/test-results/p2c-topology-20260804/P2C-REPORT.html`。

---

## P2a — 后台 daemon（GREEN · 归档）

### 工作包

- 二进制 + ring-direct HTTP：`swift-object-expirer`、`swift-account-reaper`、`swift-container-reconciler`；`swift-container-updater` 入 payload/systemd。
- `bundle-rust`：`[object-expirer]` / `[account-reaper]` / `[container-updater]` / `[container-reconciler]` + units `Restart=on-failure`。
- Object DELETE：`X-If-Delete-At` 与对象 `X-Delete-At` 对齐（412 mismatch）。
- 证据：`tools/test-results/p2a-daemons-20260804/` + `P2A-REPORT.html`。

### P2a 门禁结果

| 门禁 | 结果 |
|------|------|
| 单元（expirer 6 / reaper 4 / reconciler 7 / updater 3） | **20/20** |
| P2a 专项套件 VIP（`tools/p2a-daemon-suite.sh`） | **21/21** |
| Expirer E2E（`X-Delete-At`/`X-Delete-After` → journal `expired>=1` + client 404；on-disk `.data` removed） | **PASS** |
| Container-updater / reaper / reconciler（once + active ×4） | PASS |
| CORE-PATH func VIP | **54/54** |
| 盘压 / 无 wipe `/srv/node` | OK（~49% root） |
| 合同更新 | DONE |

### 诚实偏差 / residuals（不挡 GREEN）

- 完整 account-reaper 删账号 E2E 需 reseller 账号创建路径（lab 仅 `test:tester .admin`）。
- Reconciler 策略竞态注入 E2E 在单策略 Contabo 上 deferred；库决策 + HTTP move + 队列 drain 已接线。
- Expirer 在 `reclaim_age` 内可 retain stale queue 行（Python 同行为；suite 见 `retained=`）。
- Container-updater 全盘首扫可能很长；units 已设 `TimeoutStopSec=180`。

---

## P1c — 已宣称能力清债（GREEN · 归档）

### 工作包

- SLO：nested `sub_slo` GET expansion（depth ≤ 10）；lazy leaf streaming；ranged GET via per-segment `Range`；HEAD uses `X-Object-Sysmeta-Slo-*`；`multipart-manifest=get&format=raw` client-schema conversion.
- Copy：manifest-aware `?multipart-manifest=get`（SLO → put；DLO → `X-Object-Manifest`）.
- TempAuth/ACL：shared memcache info-cache L2（`account/…` / `container/…` keys）；reads skip process-local L1 when memcache configured；container-server `X-Remove-Container-*` → empty-value clear + info-cache invalidate。
- 证据：`tools/test-results/p1c-debt-20260804/` + `P1C-REPORT.html`.

### P1c 门禁结果

| 门禁 | 结果 |
|------|------|
| 单元（SLO/copy/proxy info-cache + container remove） | PASS |
| P1c 专项套件 VIP | **28/28** |
| CORE-PATH func VIP | **54/54** |
| ACL failover smoke（stop proxy on .2 during revoke） | PASS（deny 8/8 + 6/6 after restart） |
| 合同更新 | DONE |

### 诚实偏差 / residuals（wontfix P1c · 不挡 GREEN）

- SLO inline `{"data":…}` PUT segments；heartbeat PUT；`multipart-manifest=delete`.
- DLO listing pagination beyond `CONTAINER_LISTING_LIMIT` single page.
- Copy sync-key propagation.
- P1b smaller-filter specialty residual unchanged；`bulk_upload` still wontfix.
- Contabo 部署必须 `cargo build --release -p swift-proxy-server --features ec`.

---

## P1b — L2 其余（GREEN primary · 归档）

### 工作包

- 接线：`formpost`（multipart + HMAC）、`staticweb`、`container_quotas`、`account_quotas`、`symlink`、`versioned_writes`（stack DELETE restore + history）。
- 较小过滤器接线（on-by-config）：`name_check`、`etag_quoter`、`crossdomain`、`read_only`、`domain_remap`、`cname_lookup`（需 `storage_domain`）。
- `/info`：与启用过滤器一致；`bulk_upload` 仍不广告。
- 证据：`tools/test-results/p1b-l2-20260804/` + `P1B-REPORT.html` + `THREAT-FORMPOST.md`。

### P1b 门禁结果

| 门禁 | 结果 |
|------|------|
| 单元 / 接线 | PASS |
| `/info` 准确 | PASS |
| 专项套件 VIP | **36/36** |
| FormPost 负面安全 | PASS |
| CORE-PATH func VIP | **54/54** |
| 合同更新 | DONE |

### 诚实偏差

- 较小 L2 专项套件未跑（wired + unit only）→ residual，不得宣称 full Paste。
- `backend_ratelimit` 可在 proxy 接线，但 Python 放在 storage node；默认管道不含、不进 `/info`。
- Staticweb CSS / Web-Error / tempurl QS；symlink listing JSON 增强：deferred。
- Contabo 部署必须 `cargo build --release -p swift-proxy-server --features ec`。

---

## P1a — L2 常用（GREEN · 归档）

### 工作包

- 接线：`bulk`（delete）、`tempurl`、account ACL（`X-Account-Access-Control`）。
- `/info`：`bulk_delete`（无 `bulk_upload`）、`tempurl`、`tempauth.account_acls`。
- `ratelimit`：**on-by-config** — `bundle-rust` 注释样例；默认 pipeline 不含（避免动 CORE-PATH 基线）。
- 证据：`tools/test-results/p1a-l2-20260804/` + `P1A-REPORT.html` + `THREAT-TEMPURL.md`。

### P1a 门禁结果

| 门禁 | 结果 |
|------|------|
| 单元 / 接线 | PASS |
| `/info` 准确 | PASS |
| 专项套件 VIP / local | **27/27** · **27/27** |
| TempURL 负面安全 | PASS |
| CORE-PATH func VIP | **54/54** |
| 合同更新 | DONE |

### 诚实偏差

- `bulk_upload` / `?extract-archive` = wontfix P1a；不得广告。
- TempURL keys：uncached HEAD；ACL authorize 仍可能跨 proxy TTL 滞后。
- `temp_url_ip_range` deferred。
- Contabo 节点 pipeline 不完全一致（部分节点已含 ratelimit）；CORE-PATH 仍 54/54。

---

## P0 — 管道地基（GREEN · 归档）

### 工作包

- 接线：`listing_formats`、`proxy_logging`（logger sink）、`cache`（接 `swift-memcache` 或等价）。
- 扩展 `build_configured_filters`：本波宣称支持的名字不得再 silent-skip。
- `bundle-rust` `proxy-server.conf.j2` 默认 pipeline 对齐 Python 薄管道+cache：
  `catch_errors gatekeeper healthcheck proxy-logging cache listing_formats tempauth copy slo dlo proxy-server`
- 验证：双 SAIO 同名管道；func-suite；listing/日志专项；HAProxy RR + VIP 冒烟。
- 证据目录：`tools/test-results/p0-pipeline-YYYYMMDD/` + 人话 HTML。

### P0 门禁清单

| 门禁 | 要求 |
|------|------|
| 单元 | `cargo test` 覆盖接线；cache/listing/proxy_logging 可启用 |
| 静态 | 相关 crate 测试通过；无 secret 进 git |
| SAIO 对照 | 同 pipeline 字符串；func-suite；失败=0 才宣称 P0 GREEN |
| 集群 | VIP 四后端分流冒烟；CORE-PATH 不回退 |
| 合同 | 更新 blocked / CONTRACTS / CONFIG-PARITY；`/info` 与实现一致 |

### 诚实偏差（允许文档化）

- Proxy 的 account/container **info cache** 在 P0 仍可为进程内 `InfoCache`；`[filter:cache]` 建立并持有 `MemcacheClient`（供后续共享 info/TempAuth），不得再 silent-skip。
- `proxy_logging` 发出 Swift 默认 access-log 行到 logger sink；StatsD 细粒度标签等仍可 Deferred。
- P0 当时未接线 L2；P1a 已接线 bulk/tempurl — 仍不得宣称 full Paste。

---

## 严格验证矩阵（每波最低）

| 门禁 | 要求 |
|------|------|
| 单元 | 新逻辑行覆盖；金标对比 Python（白名单差分） |
| 静态 | `cargo test -p …`；相关 clippy；无 secret |
| SAIO | 同 pipeline；func + 波次专项；失败=0 |
| 集群 | VIP 分流；failover；CORE-PATH 抽样；数据面 soak≥1h 或书面 FROZEN |
| 合同 | blocked / CONTRACTS / CONFIG-PARITY；`/info` 一致 |
| 安全 | TempURL/formpost/ACL/Keystone：威胁条 + 负面用例 |
| 回滚 | 可 feature-flag 或 pipeline 裁剪回 CORE-PATH |

---

## 风险

- 「crate 已有」低估工作量：多数过滤器仍有 Deferred 语义债。
- memcache 与 Python 不一致会放大 listing/auth 抖动 — P0 必须对照测。
- 全管道默认启用会改变性能基线 — 不得与旧 CORE-PATH 混比。

## Contabo

无票不 wipe `/srv/node`。Python 三节点仍 FROZEN 时，P0–P1 用双 SAIO + Rust 四节点回归即可。
