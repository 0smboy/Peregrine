# STRICT VERIFY — item2 Paste plugins

**Date:** 2026-08-08  
**Workspace:** `/Users/oboy/Downloads/Peregrine/swift-rust`  
**Commands:**
```bash
export CARGO_HOME=/Users/oboy/Downloads/Peregrine/.cargo-home
cd /Users/oboy/Downloads/Peregrine/swift-rust
cargo test -p swift-middleware --lib -- plugin_registry
cargo test -p swift-proxy-server --bin swift-proxy-server -- pipeline_unknown
```

## VERDICT: KEEP

Unknown pipeline filter names **register `NamedPassthrough` by default** (`plugin_default` unset or non-skip). Optional `plugin_default = skip` drops them. Conf `use=` / `plugin=` hits `PluginRegistry` factories (`paste.passthrough`, `named_passthrough`, `egg:swift#passthrough`, or custom `register`).

## Cargo results

### `swift-middleware --lib -- plugin_registry`
| Metric | Count |
|--------|------:|
| passed | 4 |
| failed | 0 |
| ignored | 0 |
| measured | 0 |
| filtered out | 414 |
| duration | 0.00s |

```
test plugin_registry::tests::no_default_returns_none ... ok
test plugin_registry::tests::unknown_name_default_passthrough ... ok
test plugin_registry::tests::use_paste_passthrough ... ok
test plugin_registry::tests::custom_factory_registered ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 414 filtered out; finished in 0.00s
```

### `swift-proxy-server --bin -- pipeline_unknown`
| Metric | Count |
|--------|------:|
| passed | 3 |
| failed | 0 |
| ignored | 0 |
| measured | 0 |
| filtered out | 21 |
| duration | 0.00s |

```
test startup_policy_tests::pipeline_unknown_filter_skips_when_plugin_default_skip ... ok
test startup_policy_tests::pipeline_unknown_filter_note_when_lenient ... ok
test startup_policy_tests::pipeline_unknown_filter_registers_passthrough_plugin ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 21 filtered out; finished in 0.00s
```

## Required claim checks

| Requirement | Evidence | Result |
|-------------|----------|--------|
| Unknown filter → NamedPassthrough by default | `pipeline_unknown_filter_registers_passthrough_plugin` (`not_a_real_filter` note contains NamedPassthrough; filters.len()==3) | ok |
| `plugin_default=skip` skips unknown | `pipeline_unknown_filter_skips_when_plugin_default_skip` | ok |
| Registry default passthrough | `plugin_registry::tests::unknown_name_default_passthrough` | ok |
| `use=paste.passthrough` factory | `plugin_registry::tests::use_paste_passthrough` | ok |
| Custom factory register | `plugin_registry::tests::custom_factory_registered` | ok |
| No default → None | `plugin_registry::tests::no_default_returns_none` | ok |

## Source (already in tree — no paste required)

| Path | Role |
|------|------|
| `crates/swift-middleware/src/plugin_registry.rs` | `PluginRegistry` + `global_registry`; default NamedPassthrough |
| `crates/swift-middleware/src/passthrough.rs` | `NamedPassthrough` no-op middleware |
| `crates/swift-middleware/src/lib.rs` | `mod plugin_registry`; `pub use` NamedPassthrough / PluginRegistry |
| `crates/swift-proxy-server/src/main.rs` | `build_configured_filters` `other` arm: conf `use`/`plugin` + `plugin_default` (default passthrough) |

### Default path (proxy)

```text
other => {
  // plugin_default unset → default_passthrough = true
  global_registry().build(other, &conf_items, default_passthrough)
  // → NamedPassthrough + note "third-party slot"
}
```

## Notes
- Build: Finished test profile; proxy recompiled (~1.5s); middleware lib cache hit.
- Warnings only (unused mut / unused import / dead code in middleware); no test failures.
- Claim boundary: in-process Rust factory registry + claimable NamedPassthrough slots — **not** load of arbitrary Python Paste eggs (`egg:pkg#filter` as real Python entry points).
