# Clippy key packages — 2026-08-12

Branch: `chore/clippy-key-packages` (from fmt tip `53e43d8`).

## Gate
```bash
cd swift-rust
export CARGO_HOME=/root/work/peregrine-cargo-home   # lab
cargo clippy -p swift-http -p swift-middleware -p swift-s3api \
  -p swift-proxy-server -p swift-db --all-targets --no-deps -- -D warnings
```
Result on **swift3**: **PASS** (EXIT 0).

Also: `cargo clippy -p swift-container-server --all-targets --no-deps -- -D warnings` PASS.

## Config
- `swift-rust/clippy.toml`: `too-many-arguments-threshold = 12`, `type-complexity-threshold = 500`

## Honesty (same branch)
- Cold tier: `PhysicalTransition` → `ColdMetaStamp`; `apply_physical_*` → `stamp_cold_*` (meta only; deprecated aliases kept).
- S3 matrix runner landed: `tools/strict-s3-parity.py` + selftest; status note `S3-MATRIX-STATUS-20260812.md`.
- Offline selftest: `python3 tools/strict-s3-parity-selftest.py tools/strict-s3-parity.py` → PASS.

Claim boundary: **IMPLEMENTED_SUBSET_ONLY**. Live fleet binary remains `77a9100` until a rebuild is intentionally rolled.
