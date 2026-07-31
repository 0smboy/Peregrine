# Peregrine — session handoff

**Date:** 2026-07-31  
**Repo:** https://github.com/0smboy/Peregrine  
**Latest commits:** `1ff6f05` (console/lab/cosbench/autocos rename) · `c2ec71b` (Excel charts, Testing dashboard, this handoff)

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
| Testing page charts | Done (deployed) | KPI strip + SVG column charts + read/write compare; default view is Chart. Built and installed on swift1. |

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

## Deployed on swift1 (2026-07-31)

- `/usr/local/bin/swift-console` and `/usr/local/bin/autocos` (release builds from `/root/work/Peregrine/`)
- `/etc/swift-console/config.json` uses `autocos_bin` / `autocos_home`
- Result home moved to `/root/.autocos`
- Smoke: login 200, `sc_lang=en` cookie set, static JS contains drill/chart helpers, shadow API returns 401 without session (not a Content-Type rejection)

## What is left

1. **Click-verify in a browser** (console is loopback-only — SSH tunnel or on-host browser):
   - Language EN
   - Monitor drill-down
   - Each lab tool (RingScope, policy, tombstone, shadow, chaos, warehouse)
   - Testing chart view with ≥2 runs
2. **History rewrite (optional but requested):** older commits still contain retired product / vendor names in messages. Squash or filter-repo before a public push if those strings must never appear in `git log`.
3. **Push** to `origin` after browser verification (not done unless asked).

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
