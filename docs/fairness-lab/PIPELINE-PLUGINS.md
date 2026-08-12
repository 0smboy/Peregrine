# Pipeline / Paste plugin honesty (Rust Swift)

## Defaults (deploy)

Rust proxy deploy templates (`swift-deploy-rs/bundle-rust/…/proxy-server.conf.j2`) set:

- `strict_pipeline = true` — refuse to start if a configured filter has no Rust implementation
- `plugin_default = skip` — unknown names are skipped (typed issue); with strict mode they fail closed

A deliberate no-op for an *explicit* alias requires both `strict_pipeline=false` and `plugin_default=passthrough`.

## What is **not** claimed

- **`NamedPassthrough` is not third-party Paste ABI.** It is an in-process Rust identity middleware for selected known names. There is no Python egg loader, shared-library plugin ABI, or WASM Paste factory.
- Unlimited arbitrary Paste `use = egg:…` factories are **unsupported**.
- Unit coverage in `swift-proxy-server` already asserts skip vs passthrough vs strict fail-closed for unknown filters.

## Related

- [RUST-VS-PYTHON-PARITY.md](RUST-VS-PYTHON-PARITY.md) — matrix rows for Paste / NamedPassthrough
- [CONFIG-PARITY.md](CONFIG-PARITY.md) — knobs including `allow_account_management`
