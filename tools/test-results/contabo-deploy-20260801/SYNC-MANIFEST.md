# Contabo evidence sync manifest (2026-08-02)

## Publish channels

| Channel | Status | Location |
|---------|--------|----------|
| GitHub Peregrine `main` | Pushed | `bda936f` (levers) + `c0af009` (cutover) |
| Mac mirror | Complete | `Peregrine/tools/test-results/contabo-deploy-20260801/` |
| Google Drive | Target of this sync | `gdrive:Peregrine/2026-08-01-contabo/` |
| Contabo host (source) | Authoritative runtime | `/root/contabo-deploy-20260801T125749Z/` |

## Included in this tree

- Install / gates / deep / perf logs (`00`–`71`, `SUMMARY.md`, `CONTABO-CLUSTER.md` on Drive root)
- `console-hardening/`, `gates/`, `host-evidence/`
- Lab12: `lab12-deep*` directories + summaries
- Deep R1/R2: `deep-r1/`, `deep-r2/`
- Early perf: `perf/`
- Write-path A/B: `perf-levers/` (Phase0, L1a–L4, SAIO, DECISION/COMPARE/SUMMARY.json)

## Excluded on purpose

- `swift-object-server` binary blobs under evidence
- autocos `*.csv` result dumps
- Cursor IDE canvases under `~/.cursor/projects/.../canvases/` (IDE-local; data mirrored in `perf-levers/`)

## docs-site (Vercel)

| Item | Value |
|------|-------|
| Live URL | https://peregrine-docs-ochre.vercel.app |
| Performance page | https://peregrine-docs-ochre.vercel.app/performance/ |
| Source | `docs-site/` (+ `docs/write-concurrency-optimization.md` in Git) |
| Last prod deploy | 2026-08-02 — `dpl_5o97iFr9QscS9Xj7myfvxfFUS93V` (includes write-path L1a–L4) |
| Manual / agent publish | `cd docs-site && npm run deploy:prod` |
| Auto on `main` | `.github/workflows/deploy-docs.yml` (needs `VERCEL_*` Actions secrets) |

Verified live: Performance → Write-concurrency optimization includes
“Write-path lever A/B (2026-08-02 … L1a KEEP … L1b/L2/L4 DROP …)”.
