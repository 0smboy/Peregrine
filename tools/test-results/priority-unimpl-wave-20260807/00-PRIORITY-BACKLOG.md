# Unimplemented residual backlog (priority) · 2026-08-07

**Claim boundary:** LAB-HARD-GREEN — not PRODUCTION-GO-LIVE.  
**Rule:** partial = 未实现.

## P0 — Client-visible S3 correctness (this wave · implement + strict unit verify)

| # | Item | Why P0 | Status before wave |
|---|------|--------|--------------------|
| P0-1 | **aws-chunked per-chunk signature enforce** | Clients that stream with `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` currently dechunk even when chunk-sig fails; must 403 `SignatureDoesNotMatch` | Residual (dechunk OK, soft ignore) |
| P0-2 | **Object Lock governance bypass** | `x-amz-bypass-governance-retention: true` must allow DELETE/overwrite only when mode=GOVERNANCE (not COMPLIANCE, not legal-hold) | **DONE** unit (`impl-worm-governance-bypass-20260807`) |
| P0-3 | **Grant-header + ACP XML ACL** | `x-amz-grant-*` + PUT `?acl` AccessControlPolicy body → store grants; GET `?acl` round-trip (beyond canned `x-amz-acl`) | Residual (canned only) |
| P0-4 | **Lifecycle Transitions + AbortIncompleteMPU** | Parse Transition / AbortIncompleteMultipartUpload from LifecycleConfiguration; stamp storage-class meta / MPU abort meta; Expiration already KEEP | Residual |

## P1 — High value, next wave (code-ready, not ops-blocked)

| # | Item | Notes |
|---|------|-------|
| P1-1 | ListVersions pagination fidelity (`key-marker` / `version-id-marker` edge + multi-key) | Data plane EXISTS; empty residual only when `+versions` 404 |
| P1-2 | authenticated-read canned ACL XML store (still no Swift AuthenticatedUsers enforce) | Python also NotImplemented for container translate |
| P1-3 | ListObjects XML / Content-Type for s3cmd `ls` | mb/put/get/del OK; list XML parse residual |
| P1-4 | Encryption footer / unbuffered ciphertext residual | Multi-root crypto KEEP; buffering residual |
| P1-5 | StatsD fine labels on proxy_logging | Functional residual |

## P2 — Cluster / ops (need live Contabo + second cluster or operator action)

| # | Item | Notes |
|---|------|-------|
| P2-1 | Multi-primary auto-shrink KEEP | Peer roots empty live ranges residual |
| P2-2 | Multi-cluster container-sync realm soak | No second cluster / realms conf |
| P2-3 | Operator PEM + trust path on VIP :8085 | Code GREEN; Contabo still self-signed LAB |
| P2-4 | Multi-hour L3b soak product claim | Not claimed |

## P3 — Explicit non-goals / WONTFIX / niche

| # | Item | Disposition |
|---|------|-------------|
| P3-1 | SigV2 auth | **WONTFIX** stable 501 |
| P3-2 | ECDSA STREAMING payload | **501** NotImplemented (Python parity) |
| P3-3 | Full arbitrary Paste every filter name | Unknown skip + `strict_pipeline` hard-fail |
| P3-4 | xprofile / niche Paste filters | ❌ |
| P3-5 | True eventlet multi-process worker clone | Tooling GREEN; process-model residual |
| P3-6 | KMIP keymaster | Residual |
| P3-7 | Full ansible role twin of every Python role | opt-in v3 twin 26/26 COVERED; not bit-identical |

## This wave workflows (parallel)

1. `impl-chunk-sig-enforce` → P0-1  
2. `impl-worm-governance-bypass` → P0-2  
3. `impl-grant-acp-acl` → P0-3  
4. `impl-lifecycle-transitions` → P0-4  

Root: `/Users/oboy/Downloads/Peregrine`  
Evidence: `tools/test-results/priority-unimpl-wave-20260807/` + per-item dirs.  
Gate: `cargo test -p swift-s3api` must PASS; update `docs/fairness-lab/RUST-VS-PYTHON-PARITY.md` only on KEEP.

---

## Wave outcome (strict)

| # | After | Gate |
|---|-------|------|
| P0-1 chunk-sig | **KEEP** | 176/176 lib |
| P0-2 worm bypass | **KEEP** | 176/176 lib |
| P0-3 grant/ACP | **KEEP store/GET** (enforcement residual) | 176/176 lib |
| P0-4 lifecycle trans | **KEEP** (meta + abort stamp) | 176/176 lib |

Mainline: `/Users/oboy/Downloads/Peregrine`  
`cargo test -p swift-s3api --lib` **176 passed, 0 failed** (2026-08-07).
