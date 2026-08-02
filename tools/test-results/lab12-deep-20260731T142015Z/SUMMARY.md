# Lab 12 Deep Test — SUMMARY

- **OUT (cluster, stranded):** `/root/lab12-deep-20260731T142015Z` on swift1
- **OUT (Mac salvage):** `Peregrine/tools/test-results/lab12-deep-20260731T142015Z/`
- **UTC run id:** `20260731T142015Z`
- **Overall verdict: REJECT**
- **Blocker:** Azure subscription `fc5a426a-57bd-4e73-b999-1122d02c6083` entered ReadOnlyDisabled / non-paying warning; all 4 VMs force-stopped ~2026-07-31T14:50:34Z mid-run. `az vm start` refused. SSH dead. Remaining Profile/Nodes/Chaos-retry/Warehouse-fix/archive-from-disk cannot finish until subscription write access returns and VMs are restarted.

## Locked gates honored

| Gate | Result |
|------|--------|
| Shadow peer = real Python SAIO `:8090` (not Rust `:8081`) | Config verified; label `Python SAIO` matches peer |
| No mock / no single-mode PASS | Shadow ran `mode=dual` `peer=true`; peer-down negative returned explicit error |
| Breaking = 0 zero exemption | **breaking=15 → Shadow REJECT** |
| Profile / Open-Expired missing → REJECT tool | Profile not completed (VM death). Expired: `open_status` field present + N=20 seed; dual-read after ghost incomplete |
| Chaos all 4 faults | 3/4 completed before overlap; `drop_durable` retry blocked by VM death |

## E0 environment

| Check | Result |
|-------|--------|
| Peer fix | `shadow_peer_base=http://127.0.0.1:8090`, auth `:8090/auth/v1.0`, label `Python SAIO`; `swift_base=http://10.42.30.11:8085` |
| Python SAIO repair | Rings expected `sdb1..sdb4` under `/srv/node/d1/pysaio` but dirs missing → 503 autocreate. Created device trees; restarted pyswift |
| func-suite cluster-ha `:8085` | **PASS=54 FAIL=0** |
| func-suite py-saio `:8090` | **PASS=54 FAIL=0** (after repair; was 5/49 before) |
| Rust SAIO `:8081` | Optional only; lab key 401; never labeled Python |

## Per-tool table

| Tool | Verdict | One-line reason |
|------|---------|-----------------|
| RingScope | **PASS** | Topology 12 devices / 4 nodes; ≥16 parts OK; fail_device/node/zone/set_weight simulate 200 with survival; live ring md5 unchanged |
| Policy Economist | **REJECT** | defaults OK from live cluster; compare API requires `candidates` (schema not completed before stop); no valid compare matrix archived |
| Object Capsule | **PASS** | repl+EC capsule API 200; SSR 200; `swift-get-nodes` placement proof (primaries+handoffs) |
| Tombstone Museum | **PASS** | alive→DELETE→resurrect→EC delete all API 200 with timeline payloads |
| API Parity / Shadow | **REJECT** | Real dual vs Python:8090; **breaking=15** / semantic=12 / identical=4; replay holds=31 drifted=0; mutate seeds 111/222/333 identical; peer-down → explicit error (not silent single) |
| Chaos Arcade | **WARN** | drop_copy / corrupt_copy / stale_timestamp ran+recover; drop_durable first attempt collided (`still running`); retry not finished (VM stop). No service stop used |
| Node HA Drill | **REJECT** | Not executed — Nodes LAST never reached; cluster VMs stopped by Azure |
| Agent Warehouse | **REJECT** | jobs list stayed 0 (create needs `goal`; form 303 did not leave visible jobs); MCP `/mcp` tools/list worked; promote/HEAD incomplete |
| Repair Debt Index | **PASS** | Live snapshot with contributions/proxies/per-node; baseline only (no disturbance) |
| Expired Observatory | **WARN** | N=20 seeded; FSM Alive→RecoverableGhost observed; `open_status` present. Manual probe after short TTL got 404/404 (object gone). Disk SSH proof + full dual-read matrix incomplete (VM stop) |
| Profile Cartographer | **REJECT** | Not completed — capability gate (`/recon/stage` or `swift_stage_*`) not proven before VM stop |
| Cluster Genome | **PASS** | pop=16 gen=8 front≥1 with fitness vectors; note says weight-only / no live write; object.ring.gz md5 unchanged |

## Shadow breaking count

**15** (run `r1785508038-148b56`, mode=dual, peer=true, cases=31, semantic=12, cosmetic=0)

Dominant breaking rules observed: `hdr.missing accept-ranges` (B/Python), account meta/temp-url, range boundary / 416 body shape, etag mismatch body.

## Drive path

Not uploaded — cluster OUT stranded on stopped VM; Mac salvage only under:

`Peregrine/tools/test-results/lab12-deep-20260731T142015Z/`

Intended Drive target when VM returns:

`gdrive:Peregrine/2026-07-31-lab-456/lab-tests/20260731T142015Z/`

## Blockers / next actions

1. **Re-enable Azure subscription write** (billing) for `fc5a426a-57bd-4e73-b999-1122d02c6083`.
2. `az vm start` all four nodes; wait SSH; confirm services + Python SAIO devices still present.
3. Resume serial tail only: Chaos `drop_durable` → Expired dual-read/disk → Profile capability → Warehouse `goal=`×3 → Nodes ha-test ≥18/20 → archive `$OUT` → rclone → cutover line.
4. Do **not** claim ACCEPT until Shadow breaking=0 or an explicit signed exemption list exists (default: none).

## Honesty note

This is a partial deep run with hard REJECT on Shadow and several incomplete tools. No cheating: peer was real Python SAIO; dual mode proven; breaking counted without exemption; capability gaps not marked PASS.
