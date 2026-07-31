# Final destroy check — 2026-07-31

## Verdict

| Scope | Decision |
|-------|----------|
| **Dev / runtime migration** (bins, conf, rings, keys, EC libs, HAProxy, systemd, monitoring, SAIO, console shadow, build toolchain) | **GO** — parity verified on all 4 new nodes |
| **Object / account / container store data on old `/srv/node`** | **NO-GO unless you accept permanent loss** — not migrated |
| **Prometheus / Loki history on old** | Acceptable loss for lab (new cluster has fresh TSDB) |

**Bottom line:** You may destroy the old four VMs **only if** you do **not** need the old AUTH_test dataset (~31 GiB logical / ~82 GiB on disk). The new cluster is a working empty-ish lab, not a data clone.

---

## Hard evidence (re-checked this pass)

### Secrets / rings (byte-identical old ↔ new)

| File | sha256 |
|------|--------|
| `replication_key` | `ec635f57…12fe31` |
| `swift.conf` | `7656d42d…1f187d` |
| `proxy-server.conf` | `b9c2c85e…a05233` |
| `object.ring.gz` / `object-1.ring.gz` | `0ee4c105…d776f9` (same on old and new) |

Ring device IPs present: `10.42.10.11–14` + `10.42.20.11–14`.

### Services (all 8 hosts)

On **every** old and new node: `swift-proxy`, `haproxy`, `node_exporter`, `statsd_exporter`, `swift-object-reconstructor`, `swift-object-auditor.timer` = **active**.

EC libs: `libnullcode` + `liberasurecode_rs_vand` present (vand link OK) on all 8.

`cabt` / `autocos` only on node1 (same as old layout).

### New cluster smoke (just now)

- Auth OK; replicated PUT/GET OK; EC container + PUT/GET **201/200**
- Prometheus `nodes_up=4`; node_exporter `:9100` → 200 on all four mgmt IPs
- Reconstructor active, clean passes
- Proxy binary: zero “erasure coding not built” strings

### Data scale (the destroy risk)

| | OLD AUTH_test | NEW AUTH_test |
|--|---------------|---------------|
| containers | **81** | ~7 (lab) |
| objects | **43 734** | ~105 |
| bytes used | **~30.9 GiB** | ~6.6 MiB |

| Node | OLD `/srv/node` | NEW `/srv/node` |
|------|-----------------|-----------------|
| 1 | **22G** (~47k `.data`) | ~7–8M |
| 2 | **20G** (~33k) | ~7–8M |
| 3 | **20G** (~33k) | ~7–8M |
| 4 | **20G** (~33k) | ~7–8M |

Also only on old (not needed for runtime): Prometheus ~338M, Loki ~512M; `sc.bundle`/`sc-push`; large `target/` trees under `cabt-rs`/`cosbench-rs`.

---

## Already archived off old (safe to lose originals)

| Archive | Mac | New swift1 |
|---------|-----|------------|
| EC-good bin backups + console.bak | `Peregrine/tools/test-results/pre-destroy-archive/old-bin-backups.tgz` (23M) | `/root/archive-from-old/` |
| `swift-rust-bundle-fixed` + `liberasurecode` | `…/old-ec-bundle-liberasure.tgz` (39M) | `/root/archive-from-old/old-ec-bundle-liberasure.tgz` |

Mac source of truth already has: `Peregrine/{swift-rust,autocos,cosbench-rs,swift-console,swift-deploy-rs,docs,tools}` and `~/Downloads/peregrine-src/cabt-rs`.

---

## Will be lost forever if you destroy old now

1. **All Swift object data** on old disks (bench/cabt/autocos containers listed under AUTH_test, including ~6 GiB EC policy data).
2. Old Prometheus / Loki history.
3. Old-only worktree build artifacts (`target/`, CI logs) — **rebuildable** from Mac sources.
4. Inactive keepalived sample (Azure ILB replaces it; intentional skip).

---

## Explicit skip list (do not block destroy)

- Object data migration (was never part of cutover; Mac ↔ Azure relay only for env)
- keepalived
- Binary backup dirs beyond the two tarballs above
- Full Prometheus/Loki TSDB copy

---

## Destroy checklist (you confirm)

- [ ] I accept **permanent loss** of old AUTH_test (~31 GiB / 43k objects).
- [ ] I will use **new** `swift1`–`swift4` / `52.176.126.60` only after destroy.
- [ ] Tests use node `:8085` (VIP hairpin from backends may still WARN).
- [ ] Future Rust builds on Linux with `--features ec`; install then `restorecon`.

If any box is unchecked → **do not destroy**. If all checked → **GO to destroy old subscription VMs**.
