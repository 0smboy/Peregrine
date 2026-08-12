# Peregrine honesty pass — 2026-08-12

Branch: `honesty/eventlet-paste-cold-aam` (from `origin/build/phase1-deploy-rs-lb` @ `36b7719`).

Clean worktree: `/Users/oboy/Downloads/Peregrine-honesty` (main tree left dirty / untouched).

## Closed in this PR

### 0) Tip compile break (36b7719)
- DLO called `Request::set_path` but tip `Request` had no setter → added `set_path`.
- Tip `swift-proxy-server` was also uncompilable against tip middleware/s3api (proxy ahead of exports). Minimal shims added for AUTHORIZE header, EndpointResolver/ListEndpoints, RateLimit/Symlink try_from_conf, ContainerSync try_with_realms_path, Copy yield_frequency, VersionedWrites authorization probe flag, S3Api clock skew/extended subresources.
- Verified on swift3: cargo check -p swift-middleware and -p swift-proxy-server.

### 1) Eventlet claims honesty
- Renamed `swift-http` module `eventlet_parity` → `thread_concurrency`.
- Module docs state: OS-thread / prefork adapter only; **not** greenlet; **not** wired into HTTP serve path as eventlet.
- Kept historical type names (`EventletConcurrency`, `GreenthreadPool`, …) for low churn; scrubbed docs/logs/formula strings.
- Proxy log: `eventlet-like prefork` → `prefork workers`.
- Formula string: `eventlet:` → `prefork:` (`worker_model=eventlet` still accepted as prefork sizing alias).
- Light scrub of body/server protocol comments (`eventlet parity` → Python swob semantics).

### 2) Paste plugin ABI honesty
- Deploy template already had `strict_pipeline = true` and `plugin_default = skip` (confirmed / retained).
- Added `docs/fairness-lab/PIPELINE-PLUGINS.md`: unknown filters skip/fail-closed; `NamedPassthrough` is **not** third-party Paste ABI.
- Updated `swift-middleware` `passthrough.rs` docs + `bundle-rust/README.md` honest non-goals.
- Existing `swift-proxy-server` unit tests already cover skip / passthrough / strict fail-closed (unchanged).

### 3) Physical cold backend honesty
- Strengthened `cold_tier` / `swift-s3api` docs: **policy map + metadata stamps only**; physical cold/Glacier/tape backend **not implemented**.
- `apply_physical_*` APIs explicitly documented as meta stamps (no byte move).
- Parity matrix row updated accordingly.

### 4) `allow_account_management`
- Code default remains **false** when unset (unchanged).
- Rust lab deploy template sets `allow_account_management = true` (matches Python lab).
- Fixed docs contradiction:
  - `CONFIG-PARITY.md` / `.json`: was **unsupported** → now **iso-config / supported** (405 gate + `/info`).
  - `RUST-VS-PYTHON-PARITY.md`: reinforced supported wording (default false; lab templates true; `/info`).

## Still OPEN (out of scope for this PR)

- Full behavioral parity for tip compile shims (deep versioned_writes probe, realms parse fail paths, SigV clock-skew enforcement, copy yield during stream) — shims unblock build.

- Bulk `rustfmt` / `clippy` cleanup on the dirty main checkout (~222 accidental fmt files) — **do not** land via this branch.
- Full S3 API matrix / live AWS-parity surface (Sig residual, specialty subresources, hosted IAM, etc.).
- **Physical cold backend implementation** (mover that copies bytes between policies / tape / Glacier) — only honesty + policy map today.
- Full workspace fmt / clippy gates; Contabo live ring rebuild backlog; remaining L2+ Paste specialty residuals per fairness-lab roadmaps.

## Tests

Prefer Linux (`swift3`) offline cargo against synced crates (see commit message / PR body for results).

## Non-goals / safety

- Did not commit dirty files from `/Users/oboy/Downloads/Peregrine`.
- Did not print or modify `peregrine-lab.env` secrets.
