# Priority unimplemented wave · 2026-08-07 · STRICT VERIFY

**Claim:** LAB-HARD-GREEN (not PRODUCTION-GO-LIVE)  
**Gate:** `cargo test -p swift-s3api --lib` → **176 passed / 0 failed** (was 151 before wave)

## Priority backlog (all unimplemented before wave)

See [`00-PRIORITY-BACKLOG.md`](00-PRIORITY-BACKLOG.md).

## Parallel workflows launched

| Display name | Item | Isolation |
|--------------|------|-----------|
| `impl-chunk-sig-enforce` | P0-1 per-chunk sig enforce | worktree |
| `impl-worm-governance-bypass` | P0-2 governance bypass | worktree |
| `impl-grant-acp-acl` | P0-3 grant + ACP | worktree |
| `impl-lifecycle-transitions` | P0-4 Transition + AbortMPU | worktree |

Mainline tree also integrated concurrent edits (orchestrator + agents) under `/Users/oboy/Downloads/Peregrine/swift-rust`.

## P0 results (mainline KEEP)

| # | Item | Verdict | Key proof |
|---|------|---------|-----------|
| P0-1 | aws-chunked per-chunk HMAC enforce | **KEEP** | `InvalidChunkSignature` → middleware `SignatureDoesNotMatch` 403; tests `dechunk_bad_chunk_signature_errors`, `aws_chunked_bad_chunk_signature_is_signature_does_not_match` |
| P0-2 | WORM `x-amz-bypass-governance-retention` | **KEEP** | GOVERNANCE+bypass allow; COMPLIANCE/legal-hold still block; `worm_blocks_delete_with_bypass` + multi-delete wired |
| P0-3 | Grant-header + ACP XML ACL | **KEEP (store/GET)** | `parse_acp_xml`, grant headers, JSON sysmeta, `handle_acl` PUT/GET; residual: grant **enforcement** on subsequent ops |
| P0-4 | Lifecycle Transition + AbortIncompleteMPU | **KEEP** | Transition meta stamps; MPU marker `X-Delete-At`; middleware put/init wired; no tiering backend |

## Files touched (main)

- `swift-s3api/src/aws_chunked.rs`
- `swift-s3api/src/object_lock_worm.rs`
- `swift-s3api/src/lifecycle_exec.rs`
- `swift-s3api/src/acl_cors.rs`
- `swift-s3api/src/middleware.rs`
- `swift-s3api/src/lib.rs` (residual notes)

## Still open after this wave

| Pri | Item |
|-----|------|
| P1 | ListObjects XML / s3cmd `ls`; ListVersions pagination edges; encryption footer |
| P2 | Multi-primary auto-shrink KEEP; multi-cluster sync; operator PEM |
| P3 | SigV2 WONTFIX; eventlet process model; full Paste; KMIP; full ansible role twin |

## Evidence

- This dir: `cargo-test-lib.txt` (lib gate)
- Per-item dirs: `impl-chunk-sig-enforce-20260807/`, `impl-worm-governance-bypass-20260807/`, `impl-grant-acp-acl-20260807/`, `impl-lifecycle-transitions-20260807/`
- Workflow scripts: `Peregrine/.grok/workflows/impl-*.rhai` + `swift-master/.grok/workflows/`
