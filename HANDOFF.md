# Peregrine — session handoff

> **2026-08-16 现行交接：** [`docs/fairness-lab/HANDOFF-20260816.md`](docs/fairness-lab/HANDOFF-20260816.md)
> Live proxy Size `69d22629…` · dual-oracle **49/8 FAIL** · not GREEN.
> 下文 2026-07-31 条目是更早的 console/cutover 史实。


**Date:** 2026-07-31  
**Repo:** https://github.com/0smboy/Peregrine  
**Engine repo:** https://github.com/0smboy/swift-rust (`claude/object-replicator`)

Docs site: https://docs.myswift.rs

---

## What is done

### swift-console

| Item | Status | Notes |
|------|--------|--------|
| EN/ZH language switch | Done | Theme form is JS-intercepted; language form (`/lang`) submits natively. |
| Monitor metrics + drill-down | Done | Expanded panels; per-series drill charts. |
| Lab tools | Done | RingScope, policy economics, tombstone, twin shadow, chaos, warehouse, observatory / profile cartographer / genome. |
| Testing page charts | Done (deployed) | KPI strip + SVG charts; default Chart view. |

### cosbench-rs / autocos

- Timeline sampling, HTML/SVG reports, Excel **图表** sheet on collect
- Product name is **autocos** only — do not reintroduce retired automation names

### Lab cluster cutover (PAYG)

- New four-node cluster accepted for daily dev (func-suite 54/54, HA, EC heal, `nodes_up=4`)
- Object store bytes were **not** migrated (empty disks by design)
- Operator docs: [`docs/lab-cluster.md`](docs/lab-cluster.md), [`tools/NEW-CLUSTER-CUTOVER.md`](tools/NEW-CLUSTER-CUTOVER.md)
- Destroy go/no-go: [`tools/test-results/DESTROY-GO-NOGO-20260731.md`](tools/test-results/DESTROY-GO-NOGO-20260731.md)
- EC bin backups archived under `tools/test-results/pre-destroy-archive/` (gitignored binaries; summaries committed)

### Docs

- Nimbus site page `/lab-cluster`; testing + operations cross-links
- README / `docs/testing.md` / `docs/lab-cluster.md` updated for cutover and VIP hairpin

---

## Deployed on new swift1 (2026-07-31)

- `/usr/local/bin/swift-*` with `--features ec`, SELinux `bin_t`
- Console, autocos/cabt, Prometheus/Loki/Alloy/statsd, SAIO (`:8090` / `:8081`)
- Auth lab account: tempauth `test:tester` (key in cutover note / SSH host config)

Prefer node `:8085` for tests from backends; VIP may hairpin-fail.

---

## Publish status

- Push Peregrine `main` and swift-rust `claude/object-replicator` after this handoff commit.
- Optional: history rewrite if retired product/vendor strings must never appear in `git log`.

## Verify locally

```bash
cd swift-console && cargo test
cd ../cosbench-rs && cargo test --workspace
cd ../autocos && rustup run 1.97.0 cargo test
cd ../docs-site && npm run build
```

Banned terms for future commits and UI copy: the old automation product name, the old vendor hostname prefix, and AI marketing jargon in object-storage surfaces.
