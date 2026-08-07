# impl-s3-versioning-surface · 2026-08-07

**Claim level:** unit only (meta round-trip handlers). **Not** live Contabo KEEP. **Not** multi-version object data plane.

**Command:** `cd swift-rust && cargo test -p swift-s3api -- --nocapture`  
**Result:** **108 passed; 0 failed** (see `01-cargo-test.txt`)

## Implemented (subresource API — must not 501)

| Subresource | Methods | Storage | Unit evidence |
|-------------|---------|---------|---------------|
| `?versioning` | GET/PUT | `X-Container-Meta-S3-Versioning` = `Enabled`\|`Suspended` | `versioning_put_get_round_trip`, `versioning_get_unconfigured_empty_xml` |
| `?tagging` (bucket) | GET/PUT/DELETE | `X-Container-Sysmeta-S3-Tagging` compact TagSet | `bucket_tagging_put_get_delete_round_trip` |
| `?tagging` (object) | GET/PUT/DELETE | `X-Object-Sysmeta-S3-Tagging` | `object_tagging_put_get_round_trip` |
| `?lifecycle` | GET/PUT/DELETE | `X-Container-Meta-S3-Lifecycle` percent-encoded raw XML | `lifecycle_put_get_delete_round_trip` (+ `NoSuchLifecycleConfiguration` when missing) |
| `?object-lock` | GET/PUT | `X-Container-Meta-S3-Object-Lock` percent-encoded raw XML | `object_lock_put_get_round_trip` (+ `ObjectLockConfigurationNotFoundError` when missing) |
| `?versions` | GET | local empty `ListVersionsResult` (no Swift hop) | `versions_list_returns_empty_list_versions_result` |

Removed from `UNSUPPORTED_SUBRESOURCES` 501 list: `versioning`, `tagging`, `lifecycle`, `object-lock`, `versions`.

Still 501 (example): `policy` — `unsupported_policy_still_501`.

## Residuals (honest — do not claim KEEP)

* **Multi-version object bodies** / versionId on GET-DELETE / delete-markers — **not** implemented. `?versioning` only persists status; puts still overwrite a single object unless Swift `object_versioning` / versioned-writes is separately wired and creates version containers.
* **ListObjectVersions** returns an empty listing only (API surface, not data).
* Lifecycle rules are **stored**, not executed by expirer from this meta alone.
* Object Lock config is **stored**; WORM / retention / legal-hold enforcement residual.
* Tagging is not evaluated by IAM/condition policies.

## Code anchors

* `swift-rust/crates/swift-s3api/src/bucket_config.rs` — meta encode/decode + XML
* `swift-rust/crates/swift-s3api/src/middleware.rs` — dispatch + handlers; `UNSUPPORTED_SUBRESOURCES` no longer lists these
* `swift-rust/crates/swift-s3api/src/lib.rs` — residual docs
* `swift-rust/crates/swift-s3api/src/response.rs` — `NoSuchLifecycleConfiguration`, `ObjectLockConfigurationNotFoundError`, `NoSuchTagSet`
