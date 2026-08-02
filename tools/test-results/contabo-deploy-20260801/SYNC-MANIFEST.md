# Contabo evidence sync manifest (2026-08-02 deep-verify)

## Publish channels

| Channel | Status | Location |
|---------|--------|----------|
| GitHub Peregrine `main` | See latest SHA after Phase F push | `https://github.com/0smboy/Peregrine` |
| Mac mirror | Complete | `Peregrine/tools/test-results/contabo-deploy-20260801/` |
| Google Drive | `gdrive:Peregrine/2026-08-01-contabo/` | includes `deep-verify-20260802/` |
| Contabo host (source) | Authoritative runtime | `/root/contabo-deploy-20260801T125749Z/` + `/root/contabo-deep-verify-20260802/` |

## Deep verify (2026-08-02)

| Item | Path |
|------|------|
| Gate table | `deep-verify-20260802/GATES.md` |
| Alignment audit | `deep-verify-20260802/ALIGNMENT-AUDIT.md` |
| Clean-load perf | `deep-verify-20260802/PERF-REMEASURE.md` + `cleanload-swift4/SUMMARY.json` |
| SAIO 1KB re-check | `deep-verify-20260802/saio-1kb/` |
| Host evidence | `/root/contabo-deep-verify-20260802/` (+ `-cleanload` on swift4) |

## Included in this tree

- Install / gates / deep / perf logs (`00`–`71`, `SUMMARY.md`, `CONTABO-CLUSTER.md` on Drive root)
- `console-hardening/`, `gates/`, `host-evidence/`
- Lab12: `lab12-deep*` directories + summaries
- Deep R1/R2: `deep-r1/`, `deep-r2/`
- Early perf: `perf/`
- Write-path A/B: `perf-levers/` (Phase0, L1a–L4, SAIO, DECISION/COMPARE/SUMMARY.json)
- Deep verify: `deep-verify-20260802/`

## Excluded on purpose

- `swift-object-server` binary blobs under evidence
- autocos `*.csv` result dumps
- Cursor IDE canvases under `~/.cursor/projects/.../canvases/` (IDE-local; data mirrored in `perf-levers/`)
- Secrets / jar cookies

## docs-site (Vercel)

| Item | Value |
|------|-------|
| Live URL | https://peregrine-docs-ochre.vercel.app |
| Performance page | https://peregrine-docs-ochre.vercel.app/performance/ |
| Source | `docs-site/` (+ write-concurrency docs in Git) |
| Manual / agent publish | `cd docs-site && npm run deploy:prod` |
| Auto on `main` | `.github/workflows/deploy-docs.yml` (needs `VERCEL_*` Actions secrets) |
| Claim audit | `bash tools/docs-claim-audit.sh` before declaring docs done |

## Next cycle (not executed here)

- L3b brief: `docs/superpowers/plans/2026-08-02-l3b-sharding-next-cycle.md`
