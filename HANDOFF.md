# Peregrine — session handoff

**Date:** 2026-07-31  
**Repo:** https://github.com/0smboy/Peregrine  
**Latest commit on this work:** `1ff6f05` (plus uncommitted Testing / Excel chart follow-ups if present)

Docs site: https://peregrine-docs-ochre.vercel.app

---

## What is done

### swift-console

| Item | Status | Notes |
|------|--------|--------|
| EN/ZH language switch | Done | Theme form is JS-intercepted; language form (`/lang`) submits natively so server-rendered strings re-render. |
| Monitor metrics + drill-down | Done | Expanded panels (backends, storage, services, per-node). Click a card or node → drill dialog with full series + table. |
| RingScope charts | Done | Device before/after + data flow as charts; original tables under “Data table”. |
| Policy economics charts | Done | Candidate comparison as small-multiple bars; tables preserved. |
| Tombstone Museum | Done | Live paths verified on swift1; empty-state copy explains reclaim_age / log retention; anthropomorphic “cause of death” wording removed. |
| Twin Shadow | Done | Handlers take no JSON body; form posts no longer hit `Content-Type: application/json`. |
| Chaos Arcade | Done | “Who did the work” → pass timeline chart; table under details. |
| Agent warehouse | Done | Larger lineage SVG, wrapping tables, bigger type. |
| Testing page charts | In progress / local | KPI strip + SVG column charts + read/write compare; default view is Chart. Deploy to swift1 still needed. |

### cosbench-rs

- Timeline sampling (`sample_interval_secs`)
- Self-contained HTML report with inline SVG charts (`html_report`, `svgchart`, `timeline`)
- CLI `report` subcommand + serve integration

### Benchmark automation → `autocos/`

- Directory, binary, config keys, docs, deploy role, and tools renamed to **autocos**
- State dir: `~/.autocos/`
- Console config: `autocos_bin` / `autocos_home` (defaults `/usr/local/bin/autocos`, `/root/.autocos`)
- Excel collect report now embeds a **图表** sheet (throughput / bandwidth / latency column charts)
- Do **not** reintroduce the old automation name in code, docs, commit messages, or UI

### Deploy / naming cleanup

- Legacy vendor hostname / temp-path prefixes in `swift-deploy-rs` bundle rewritten to `peregrine` (and related markers)
- Do **not** reintroduce the old vendor string in diffs or commits

### Docs

- Nimbus site page `/autocos` (was the old automation page)
- README / architecture / testing docs updated

---

## What is left

1. **Deploy console + autocos to swift1** and click-verify:
   - Language EN
   - Monitor drill-down
   - Each lab tool (RingScope, policy, tombstone, shadow, chaos, warehouse)
   - Testing chart view with ≥2 runs
2. **Cluster config.json** on swift1: ensure `autocos_bin` / `autocos_home` are set, install the `autocos` binary, and move any leftover result dir under `~/.autocos` if an older home path is still on disk.
3. **History rewrite (optional but requested):** older commits still contain retired product / vendor names in messages. Squash or filter-repo before a public push if those strings must never appear in `git log`.
4. **Push** to `origin` after verification (not done in this session unless asked).

---

## Lab / cluster pointers

- Nodes: swift1–swift4 (Azure HA + Azure LB)
- Prefer testing against HAProxy backends, not the VIP (Azure ILB hairpin)
- Console typically on swift1; config: `/etc/swift-console/config.json`
- Tempauth re-auth between HA phases (memcache tokens die with a node)

---

## Verify locally

```bash
cd swift-console && cargo test
cd ../cosbench-rs && cargo test --workspace
cd ../autocos && rustup run 1.97.0 cargo test   # needs newer rustc than 1.93 for AWS SDK
cd ../docs-site && npm run build
```

Banned terms for future commits and UI copy: the old automation product name, the old vendor hostname prefix, and AI marketing jargon in object-storage surfaces.

---

## Suggested next command sequence

```bash
# on build host
cd Peregrine/swift-console && cargo build --release
cd ../autocos && rustup run 1.97.0 cargo build --release
# scp binaries + static assets to swift1, restart console unit
# update /etc/swift-console/config.json keys for autocos
# click through the checklist above
```
