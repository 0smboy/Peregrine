# W0′ meta repair — SUMMARY

**Date:** 2026-08-05  
**Verdict:** **LAB META_CLEAN (listing + zombie rows)** · **not** PRODUCTION-GO-LIVE. Residuals below are honest, not GREENwashed.

## Root cause (`kept_dirs=0` in wave0-ab)

`tools/wave0-ab-reclaim-orphans.py` hashed  
`{prefix}{account}/{container}/{obj}{suffix}`  
but Swift / `swift-core` `HashPathConfig` uses  
`{prefix}/{account}/{container}/{obj}{suffix}`  
(slash **after** prefix).

Proof (`00-hash-root-cause.txt`): container `AUTH_test/autocos1026990a1` DB hash  
`66369328010f0b6b76653d5725d314a4` matches **correct** formula only.

Script fixed in-tree. Secondary finding: many container DBs sit on **wrong ring partitions** (e.g. on-disk part `408` vs ring `6541`) → proxy HEAD 404 even when local container-server HEAD on old part returns 204.

## Before → after (AUTH_test / Contabo)

| Gate | Before | After |
|------|--------|-------|
| API container listing | 968 (963 HEAD 404 ghosts + 5 live) | **0 ghosts**; empty listing then CRUD recreate OK |
| Account `X-Account-Object-Count` | 846331 (inflated) | **0** |
| Container DB `object where deleted=0` | ~650k zombies | **0** on all four nodes |
| Sample hash vs disk | N/A (disk purged by A+B) | **0** live rows (consistent with “or zero”) |
| VIP CRUD smoke | — | PUT/GET/DELETE **OK** (`07-crud-smoke.txt`) |

## What we ran

1. Diagnose + hash proof on swift1.  
2. Classify API live vs ghost (`03-api-live-vs-ghost.txt`).  
3. `--ghosts-only --apply --vacuum` on swift1–4 with `preserve-live.json` (5 names).  
4. VACUUM of soft-deleted container DBs (freelist → ~0 in Prom).  

Tool: `tools/wave0-meta-repair.py`.

## Threat / integrity note

- Raw SQLite DELETE used with a local `chexor()` stub so broker triggers allow repair. Brokers rewrite hashes on next real write.  
- Account-replicator can race preserves across replicas (five pre-existing live names were not reliably retained in listing after multi-node apply). Lab accepted empty listing + CRUD recreate.  
- Orphan object hash dirs were purged to **0** on swift1–4 after DB zero (`05-orphan-purge-*.txt`, `07-disk-after-purge.txt`).  
- Orphan container `.db` files under drifted partitions may remain on disk as soft-deleted brokers.  
- Historical `deleted=1` object rows may remain inside SQLite (not listing-visible).  
- **Forbidden claim:** PRODUCTION meta OK / PRODUCTION-GO-LIVE. Contabo LAB listing+row gate only.

## Evidence files

- `00-hash-root-cause.txt`, `00-diagnose-swift1.json`, `01-api-before.json`
- `03-api-live-vs-ghost.txt`, `03-zero2-swift{1,2}.json`, `04-apply-swift{1..4}.json`
- `04-node-db-counts.jsonl`, `05-orphan-purge-swift{1..4}.txt`, `06-gate.json`
- `07-disk-after-purge.txt`, `07-crud-smoke.txt`
- `preserve-live.json`, `W0-META-REPORT.html`

## Stop-line

W0′ listing/zombie/disk-hash stop-line **met for LAB** (`META_CLEAN`). Label remains **not PRODUCTION**. If future waves reintroduce ghosts, re-run `--ghosts-only`.
