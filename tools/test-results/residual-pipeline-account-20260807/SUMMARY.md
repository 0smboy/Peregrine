# Residual: pipeline unknown filter + allow_account_management · 2026-08-07

**Claim level:** unit reaffirm only. **Not** Contabo live KEEP re-run. **Not** PRODUCTION-GO-LIVE.  
**Evidence:** `tools/test-results/residual-pipeline-account-20260807/`

## Commands

```bash
cd swift-rust
cargo test -p swift-proxy-server --lib -- --nocapture
# focus
cargo test -p swift-proxy-server --lib allow_account -- --nocapture
cargo test -p swift-proxy-server --bin swift-proxy-server -- --nocapture pipeline
cargo test -p swift-proxy-server --bin swift-proxy-server -- --nocapture allow_account
```

Full transcript: `01-cargo-test.txt`

## Results

| Suite | Result |
|-------|--------|
| lib full (`--lib`) | **19 passed; 0 failed** |
| lib focus `allow_account` | **1 passed** — `p1a_wiring_tests::allow_account_management_gates_put_delete_405` |
| binary focus `pipeline` | **15 passed; 0 failed** (incl. strict/unknown) |
| binary focus `allow_account` | **1 passed** — `startup_policy_tests::allow_account_management_defaults_false_and_can_enable` |

### Focus tests (pass)

| Test | Area |
|------|------|
| `allow_account_management_gates_put_delete_405` | conf off → account PUT/DELETE **405** + `Allow: GET, HEAD, POST, OPTIONS`; conf on → not 405 |
| `allow_account_management_defaults_false_and_can_enable` | conf parse default false / enable true |
| `pipeline_unknown_filter_note_when_lenient` | `strict_pipeline=false` → unknown note, non-fatal |
| `pipeline_unknown_filter_still_skips` | unknown names skipped from wired filters |
| `pipeline_strict_true_surfaces_fatal_unknown_filter` | `strict_pipeline=true` → fatal notes for unknown + unimplemented |
| `pipeline_strict_conf_parses_true` | true/yes/on/1 + DEFAULT fallback; false/off stay lenient |

## Behavior (honest)

### `strict_pipeline` (unknown Paste filter residual)

| Mode | Behavior |
|------|----------|
| **default `false`** (Contabo-safe) | Unknown / unimplemented filter names → **skip + note** (not hard-fail) |
| **`true`** | Same notes classified fatal → main **hard-fails startup** (Paste-like) |

Does **not** implement every Python Paste filter name. Only optional hard-fail on unknown/unwired names.

### `allow_account_management`

| Mode | Behavior |
|------|----------|
| **default `false`** | Account PUT/DELETE gated **405** (Python `account.py` method removal shape) |
| **`true`** | Gate open; request proceeds to backend path (unit: not 405) |

## Verdict

| Item | Status |
|------|--------|
| `allow_account_management` | **KEEP / GREEN** (unit reaffirm) |
| Unknown filter + `strict_pipeline` | **CLOSED residual** for optional Paste-like hard-fail; default remains lenient skip |
| Full arbitrary Paste pipeline (any filter impl) | **Still ❌ / partial** — names not implemented remain skip-or-strict, not wired |

## Parity rows updated

`docs/fairness-lab/RUST-VS-PYTHON-PARITY.md` §1:

- **Allow account management** → ✅ with unit reaffirm pointer `residual-pipeline-account-20260807`
- **Full Paste arbitrary pipeline** → partial: unknown skip by default; `strict_pipeline=true` hard-fail; every filter name still ❌

## Code anchors

- `swift-rust/crates/swift-proxy-server/src/main.rs` — `strict_pipeline_from_conf`, `pipeline_note_is_strict_fatal`, `build_configured_filters`, startup gate
- `swift-rust/crates/swift-proxy-server/src/lib.rs` — `ProxyConfig.allow_account_management`, PUT/DELETE 405 gate
