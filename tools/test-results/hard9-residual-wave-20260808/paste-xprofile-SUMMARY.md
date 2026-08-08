# Paste+xprofile STRICT verify · 2026-08-08

**Claim level:** unit reaffirm only. **Not** Contabo live KEEP re-run. **Not** PRODUCTION-GO-LIVE.  
**Evidence dir:** `tools/test-results/hard9-residual-wave-20260808/`

## VERDICT: **KEEP**

| Gate | Result |
|------|--------|
| `swift-middleware` lib: `xprofile` | **2 passed / 0 failed** |
| `swift-middleware` lib: `list_endpoints` | **2 passed / 0 failed** |
| `swift-middleware` lib: `passthrough` | **24 passed / 0 failed** (includes `passthrough::tests::passes_through`) |
| `swift-proxy-server` bin: `pipeline` | **15 passed / 0 failed** |
| `build_configured_filters` wires `xprofile` / `list_endpoints` / `NamedPassthrough` | **CONFIRMED** (source) |

---

## Commands

```bash
cd /Users/oboy/Downloads/Peregrine/swift-rust
# Note: cargo accepts a single TESTNAME filter; ran the three filters separately.
export CARGO_HOME=/Users/oboy/Downloads/Peregrine/.cargo-home   # root-owned ~/.cargo/registry/cache workaround

cargo test -p swift-middleware --lib xprofile -- --nocapture
cargo test -p swift-middleware --lib list_endpoints -- --nocapture
cargo test -p swift-middleware --lib passthrough -- --nocapture
cargo test -p swift-proxy-server --bin swift-proxy-server pipeline -- --nocapture
```

Transcripts:

- `01-cargo-middleware-xprofile-list_endpoints-passthrough.txt`
- `02-cargo-proxy-pipeline.txt`
- `03-wiring-grep.txt`

Env note: default `~/.cargo/registry/cache/index.crates.io-*` was root-owned (Permission denied). Tests ran with writable `CARGO_HOME=/Users/oboy/Downloads/Peregrine/.cargo-home` against the same workspace `target/`.

---

## Results

### 1) `cargo test -p swift-middleware --lib` (focus filters)

| Filter | Tests | Exit |
|--------|-------|------|
| `xprofile` | `xprofile::tests::adds_duration_header`, `profile_path_prefix_filters` → **2 ok** | 0 |
| `list_endpoints` | `returns_json_endpoints`, `passthrough_other_paths` → **2 ok** | 0 |
| `passthrough` | 24 tests matching name (incl. `passthrough::tests::passes_through` for `NamedPassthrough`) → **24 ok** | 0 |

### 2) `cargo test -p swift-proxy-server --bin swift-proxy-server pipeline`

**15 passed; 0 failed** — includes:

- `pipeline_order_from_conf_reorders_implemented_filters`
- `pipeline_unknown_filter_note_when_lenient` / `pipeline_unknown_filter_still_skips`
- `pipeline_strict_true_surfaces_fatal_unknown_filter` (**asserts `list_endpoints enabled` is wired, not fatal residual**)
- P1a/P1b/P3/s3api/crypto/container_sync wiring tests

### 3) `build_configured_filters` wiring (source confirm)

**File:** `swift-rust/crates/swift-proxy-server/src/main.rs` → `fn build_configured_filters`

| Pipeline name | Wired as | Note string |
|---------------|----------|-------------|
| `list_endpoints` / `list-endpoints` | `swift_middleware::ListEndpoints` via `build_list_endpoints` | `list_endpoints enabled (path_root=…)` |
| `xprofile` / `x-profile` | `swift_middleware::XProfile` via `build_xprofile` | `xprofile enabled (enabled=…, profile_path=…)` |
| `catch_errors` / `catch-errors` | `NamedPassthrough::new(name)` | `registered as NamedPassthrough (claimable slot)` |
| `gatekeeper` | `NamedPassthrough::new(name)` | same |
| `healthcheck` / `health_check` / `health-check` | `NamedPassthrough::new(name)` | same |
| `memcache` / `mem_cache` | `NamedPassthrough::new(name)` | same |
| `recon` | `NamedPassthrough::new(name)` | same |
| (+ `swob`) | `NamedPassthrough::new(name)` | same arm |

Anchor (match arms ~1408–1433):

```text
"list_endpoints" | "list-endpoints" => { … ListEndpoints … }
"xprofile" | "x-profile" => { … XProfile … }
"catch_errors" | "catch-errors" | "gatekeeper" | "healthcheck" | "health_check"
| "health-check" | "memcache" | "mem_cache" | "swob" | "recon" => {
    … NamedPassthrough::new(name) …
}
```

**Middleware modules/exports:** `swift-middleware` exports `ListEndpoints`, `NamedPassthrough`, `XProfile` (`lib.rs` mod + `pub use`).

**Interaction with always-on strip:** `ALWAYS_ON_OR_APP` drops exact names `catch_errors`, `gatekeeper`, `healthcheck` when parsing `pipeline:main` (real always-on path is separate). Hyphen/underscore aliases and `memcache` / `recon` still hit the `NamedPassthrough` arm when present in the name list. Strict-pipeline residual test still expects `list_endpoints enabled` when listed.

---

## Behavior (honest)

| Item | Status |
|------|--------|
| **xprofile** | Lightweight Paste filter: duration / path headers; conf `enabled`, `profile_path`, optional `log_filename`. Always pass-through. |
| **list_endpoints** | GET/HEAD under path root → JSON endpoints when resolver set; else 501 on match path; other paths passthrough. Wired in proxy pipeline. |
| **NamedPassthrough** | Claimable no-op slots for OpenStack-standard pipeline names so they are **not** “unknown/not implemented”. |
| Full Python xprofile (cProfile dump UI etc.) | **Partial** — timing/headers + optional JSON log line, not full Python profiler UI. |
| Full list_endpoints with live ring resolver | **Partial** at unit level — unit uses `StaticEndpoints`; proxy build does not inject ring resolver in this residual. |

---

## Verdict table

| Item | Status |
|------|--------|
| Paste+xprofile residual (unit + wiring) | **KEEP** |
| list_endpoints pipeline wire (not unknown residual) | **KEEP** |
| NamedPassthrough for catch_errors / gatekeeper / healthcheck / memcache / recon | **KEEP** (arms present; always-on strip for underscore trio noted) |
| Contabo live / production GO | **Not claimed** |

## Code anchors

- `swift-rust/crates/swift-middleware/src/xprofile.rs`
- `swift-rust/crates/swift-middleware/src/list_endpoints.rs`
- `swift-rust/crates/swift-middleware/src/passthrough.rs` (`NamedPassthrough`)
- `swift-rust/crates/swift-proxy-server/src/main.rs` — `build_configured_filters`, `build_xprofile`, `build_list_endpoints`, `ALWAYS_ON_OR_APP`, `startup_policy_tests::pipeline_strict_true_surfaces_fatal_unknown_filter`
