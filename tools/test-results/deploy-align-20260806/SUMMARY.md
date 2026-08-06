# Deploy align audit · 2026-08-06

## Live topology (PASS observed)

| Service | Port / device |
|---------|----------------|
| HAProxy VIP | `:8085` SSL |
| Proxy | `:8080` |
| Object | **6211, 6212** (spp=1; conf bind_port=6210) |
| Container | 6201 |
| Account | 6202 |
| Devices | d1 (Python), d2+d3 (Rust object); A/C d2-centric rings |
| get-nodes sample | `10.0.4.x:6211/d2`, `:6212/d3` |

## Template drift (PARTIAL)

| Issue | Severity | Action |
|-------|----------|--------|
| sample `object_bind_port: 6200` | High if re-apply | Contabo overlay uses **6210** |
| sample `object_servers_per_port: 0` | High | Overlay **1** |
| sample devices default `d1` only | High | Overlay **d2,d3**; d1 left for Python |
| No separate A/C device list | Medium | Need `account_container_devices` in build_rings.j2 |
| Index vs live 6211/6212 | Medium | Live rings already correct; template must not rebuild from d1 index 0 |

## Delivered

- `swift-deploy-rs/bundle-rust/config_contabo_live/` inventory overlay + README

## Not done this pack

- Code change to `build_rings.sh.j2` for dual device lists (follow-up PR)
- Live ring rebuild (not needed; dual-guard)

## Verdict

**PARTIAL** — drift documented + overlay landed; template code still sample-default until PR.

## Template patch (this session)

`build_rings.sh.j2` now honors:
- `host_vars.account_container_devices` (fallback `swift_devices`)
- `host_vars.object_devices` (fallback `swift_devices`)

Contabo overlay uses A/C=`[d2]`, object=`[d2,d3]`, `object_bind_port: 6211` → 6211/6212.
