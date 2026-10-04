# Peregrine — session handoff

> **Current lab record (2026-10-02):** console acceptance is ACCEPT_WITH_WARN.
> Evidence: [`tools/test-results/console-accept-20261002/SUMMARY.md`](tools/test-results/console-accept-20261002/SUMMARY.md).
> VIP `10.0.0.10` is on swift1
> ([`0F-vip.md`](tools/test-results/optimize-ae-20261003/0F-vip.md), 2026-10-03).
> The console listens on swift4 at `127.0.0.1:9000`. The G7 lab gate is
> 20/20 PASS on swift1 `:18080`
> ([`verdict.json`](tools/test-results/optimize-ae-20261003/verdict.json)).
> The production cluster passed G7. Production G7 readiness is GO.
> `docs/fairness-lab/HANDOFF-20260816.md` is the
> 2026-08-16 fairness-lab handoff, not the current site.
>
> The 2026-07-31 notes below are earlier console/cutover history.


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
