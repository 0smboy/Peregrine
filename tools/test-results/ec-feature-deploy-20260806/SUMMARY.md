# EC feature deploy · 2026-08-06

**Verdict: GREEN (LAB)**  
Closes handoff residual: Contabo proxy returned **501** `erasure coding not built`.

## What changed

| Item | Value |
|------|--------|
| Build host | swift1 `/root/work/swift-rust` |
| Features | `swift-proxy-server/ec,swift-object-server/ec` |
| Build | `cargo build --release` · 33.7s · BUILD_END 0 |
| Deploy | rolling stop→install→start on swift1–4 |
| Backup | `/root/bin-backup-pre-ec-20260806T041831Z/` |

### New SHA256 (×4 identical)

| Binary | sha256 |
|--------|--------|
| swift-proxy-server | `da5ab2f1818c828577a522497a7a3d461c32d6840a1b465ca43e45551a40fc79` |
| swift-object-server | `5bc9aa465df345aac416645ec7e1455196c3543e555b955e544a0733742e82aa` |
| swift-object-reconstructor | `f548c09c276f7653675e9abf25c5dfb22cd9ffe400f7eebc7e9628dca06b61c5` |

Proxy + reconstructor link `liberasurecode` / `liberasurecode_rs_vand` (ldd).

## Gates

| Gate | Result |
|------|--------|
| Repl PUT/GET/DEL | **PASS** 201/200/204 |
| EC container PUT (policy ec-2-1) | **PASS** 201 |
| EC object PUT 128KiB | **PASS** 201 (was 501) |
| EC GET size+md5 match | **PASS** 200 · MATCH True |
| sha256 align ×4 | **PASS** |

## Not claimed

- EC heal demo this pack (optional follow-up)
- soak fail=0 / PRODUCTION-GO-LIVE
- operator PEM

## Rollback

```bash
# on each node from backup tarball on swift1
BAK=/root/bin-backup-pre-ec-20260806T041831Z
# scp bins → stop proxy/object → install → start
```

## Next

Phase 2: clean soak (≥1h fail=0) + redefine func gate for Keystone coexist.
