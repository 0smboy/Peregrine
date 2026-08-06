# Linux redeploy · Contabo · 2026-08-06

## Build

| Item | Value |
|------|--------|
| Host | swift1 (`169.58.108.85`) |
| Source | rsync `/usr/local/src/swift-rust` from laptop Peregrine |
| Toolchain | rustc/cargo **1.97.0** |
| Profile | `cargo build --release` (manage-shard-ranges, container-sharder, container-sync) |
| Duration | ~2m04s |

### SHA256 (deployed to all 4 nodes)

| Binary | sha256 |
|--------|--------|
| `swift-manage-shard-ranges` | `22d26ea8bb2c97976ce8f8d9b199aab98ff1f5792aee66228a4f9ce40d257766` |
| `swift-container-sharder` | `2900f2cf020622134d807b343e6911223529c434923ab30503e69fa36f0f0a35` |
| `swift-container-sync` | `50f4ca3969a0d7f54e75a37063ede02aed246bc1564a41b1af3591ba9ddd36be` |

## Deploy

- Nodes: `10.0.0.1–4` (swift1–4)
- Destination: `/usr/local/bin/` (with timestamped `.bak-*`)
- `systemctl restart swift-container-sharder` → **active** ×4
- CLI smoke: full subcommand list (find/show/info/enable/analyze/compact/repair)

## Evidence

- `01-build.log`, `02-deploy.log`
