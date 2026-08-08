# Hard-9 residual implementation wave · 2026-08-08

**User list (1–9) · no lazy stubs · multi-workflow verify**

## Gate (mainline orchestrator)

| Package | Result |
|---------|--------|
| `cargo test -p swift-s3api --lib` | **204 passed** |
| `cargo test -p swift-middleware --lib` | **414 passed** |
| `cargo test -p swift-proxy-server --bin swift-proxy-server` | **23 tests** (incl. process_workers + pipeline) |

## Item → implementation

| # | Item | Status | What shipped |
|---|------|--------|--------------|
| 1 | 任意 Paste 滤镜名全量 | **KEEP (OpenStack 标准名可接线)** | 全量标准 filter 在 `build_configured_filters` 有 real 或 `NamedPassthrough`；真正随机名仍 skip/`strict_pipeline` 失败。**非**无限第三方滤镜名自动生成 |
| 2 | xprofile 等小众 Paste | **KEEP** | `xprofile` 模块（`X-Profile-Duration-Ms`）；`list_endpoints`；passthrough for catch_errors/gatekeeper/healthcheck/memcache/recon |
| 3 | Lifecycle Transition | **KEEP (执行语义)** | 到期 → `SYS_TRANSITIONED`；冷存储类 GET → `InvalidObjectState`；`apply_restore_days` 临时可读；非第三方 Glacier 后端 |
| 4 | grant-header + ACP XML 存/取 | **KEEP** | 既有 + 本波维持；unit 覆盖 |
| 5 | ACP grant 鉴权执行 | **KEEP 扩展** | GET/HEAD READ + **PUT/DELETE WRITE**（`acl_write_check_object`） |
| 6 | 完整 IAM 身份服务 | **KEEP (本地 identity directory)** | `iam::IdentityDirectory`：access_key/email→canonical id；**非** AWS IAM 云服务 |
| 7 | eventlet 多进程 workers | **KEEP (prefork 模型)** | `process_workers` / `worker_model=process` + Unix `fork` prefork；线程池仍在进程内 |
| 8 | HEAD 并发 pile + yield_frequency | **KEEP (runtime)** | `concurrent_head_warm` 真并发 HEAD；heartbeat `yield_frequency` 墙钟节流；默认 0=每 HEAD 心跳 |
| 9 | listing etag refetch 竞态 | **KEEP** | `refetch_listing_slo_etag` + unit |

## Workflows (parallel verify)

- `hard9-paste-xprofile`
- `hard9-lifecycle-transition`
- `hard9-acp-iam`
- `hard9-slo-workers`

## Claim boundary

LAB-HARD-GREEN.  
**不 claim：** AWS IAM 云服务、真·第三方分层存储（物理 tape）、无限自定义 Paste 插件自动实现、eventlet greenlet 语义 bit-identical。

## Key paths

- `swift-middleware/src/{xprofile,list_endpoints,passthrough,slo}.rs`
- `swift-s3api/src/{iam,lifecycle_exec,acl_cors,middleware}.rs`
- `swift-proxy-server/src/main.rs` (pipeline + prefork)
