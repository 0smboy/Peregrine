# Wave 2 — servers_per_port full + multi-region (2026-08-05)

## Verdict: **PARTIAL GREEN** (code + unit/workspace GREEN; Contabo live ring rebuild / region drill BACKLOG)

Stop-line from plan: per-device ring ports + process-per-port isolation + multi-region host_vars/docs drill.

| Item | Status | Evidence |
|------|--------|----------|
| Ring: `object_port_per_device` (d1→6200, d2→6201, …) in `build_rings.sh.j2` | **PASS** (template) | `05-cargo-workspace-wave2.txt`, template contract test |
| Runtime: process-per-port supervise (OS child per port×worker) | **PASS** (unit) | `05-cargo-spp.txt` 9/9 |
| CONFIG-PARITY / WORKERS-SEMANTICS honesty | **Updated** | `docs/fairness-lab/{CONFIG-PARITY,WORKERS-SEMANTICS}.md` → `iso-config` |
| Multi-region sample host_vars r1/r2 | **PASS** | `config_sample/host_vars/10.0.0.{11..14}.yml` |
| MULTI-REGION.md Contabo label map + dry-run procedure | **PASS** | `docs/fairness-lab/MULTI-REGION.md` + `MULTI-REGION-DRILL.md` |
| Contabo live ring rebuild (no wipe) | **BACKLOG** | Wave 0 space not confirmed this agent; see `RING-REBUILD-PLAN.md` |
| Contabo live r1/r2 expand drill | **BACKLOG** | label plan ready; no WAN claim |
| func 54/54 + spp smoke on VIP | **Not run** | blocked on live rebuild |

## What changed (code)

- `bundle-rust/roles/rust_rings/templates/build_rings.sh.j2` — per-device object ports
- `swift-object-server` `servers_per_port.rs` + `main.rs` — parent re-exec supervise, child single-port bind
- Docs + sample host_vars + `object_port_per_device: true` group_vars

## Residuals (honest)

1. Contabo rings still single-port `6200` until rebuild ticket after Wave 0.
2. Live multi-region is **label affinity only** (not WAN/async container-sync).
3. Default Contabo conf keeps `servers_per_port=0` until operators enable + rebuild.

## Next (FROZEN / backlog)

- **FROZEN for this agent:** Contabo disk wipe / destructive reset
- **Backlog:** Contabo `expand.yml` / force-rebuild rings with `object_port_per_device`; enable `servers_per_port≥1`; discovery must return three ports on multi-disk nodes; func 54/54 + perf note
