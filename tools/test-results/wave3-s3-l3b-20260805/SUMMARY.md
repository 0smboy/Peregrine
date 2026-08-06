# Wave 3 — S3 + L3b (2026-08-05)

## Verdict: **PARTIAL GREEN**

| Gate | Result | Evidence |
|------|--------|----------|
| `swift-s3api` unit | **61/61 PASS** | `05-cargo-s3api.txt` |
| `s3token` middleware unit | **3/3 PASS** | `05-cargo-s3token.txt` |
| Proxy `s3api` wire + `/info` clean | **PASS** | `05-cargo-proxy-s3api.txt` |
| Sharder (CleavingContext persist, auto_shard, cleave) | **7/7 PASS** | `05-cargo-sharder.txt` |
| Container HTTP shard PUT/GET/redirect | **PASS** | `cargo test -p swift-container-server --test sharding` |
| Proxy shard listing fan-out | **CODE landed** | `swift-proxy-server` `maybe_sharded_container_listing` — no dedicated live Contabo drill |
| HTTP shard replicate | **Trait + LocalShardReplicator** | multi-node live quorum backlog |
| Misplaced pass | **Local retiring→shard move** | unit path via `process_sharding_container` |
| Contabo VIP s3api / full L3b perf KEEP | **Not run** | ON-BY-CONFIG / backlog |

## S3 stop-line

Implemented vs Python s3api surface for this wave: MultiDelete, ListObjectsV2, MPU (initiate/part/complete/abort via `+segments` + SLO), ACL/CORS basics, s3token filter hooks. Matrix: `S3-COMPAT-MATRIX.md`.

## L3b stop-line

Order from plan: proxy fan-out → HTTP shard create/replicate → CleavingContext persist → misplaced → auto_shard.

| Piece | Status |
|-------|--------|
| CleavingContext DB/sysmeta persist | **PASS** (unit) |
| Proxy listing fan-out | **CODE** (unit/live drill residual) |
| HTTP shard replicate | **Local stub + trait**; live multi-node backlog |
| Misplaced from retiring | **CODE** (local) |
| `auto_shard` gate | **PASS** (unit; size threshold) |
| 4KB write KEEP claim | **Not claimed** (no Contabo data this cycle) |

## Residuals / backlog

- Contabo: enable s3api ON-BY-CONFIG; Keystone live s3tokens after Wave 1
- ListMultipartUploads store; SigV2; aws-chunked; full IAM ACL
- Live multi-node shard HTTP quorum + shrink/expand
- Proxy fan-out integration test against multi-node SAIO/Contabo

## FROZEN

- Contabo disk wipe / mkfs
- Claiming PRODUCTION-COMPLETE or GREEN for Contabo live S3/L3b without evidence
