# Contract levels — Contabo fairness lab

| Level | Required behavior | Gate |
|-------|-------------------|------|
| **L1** Public Swift v1 API | HTTP methods, headers, bodies, listings, metadata, conditional, ranges, SLO/DLO, errors | **Mandatory** before any formal perf citation |
| **L2** Middleware / auth | TempAuth, ACLs; TempURL, bulk, expiration, versioning, Keystone, S3 | Feature-dependent; **unsupported ≠ FAIL** |
| **L3** Backend protocol | Proxy→storage verbs, replication, SSYNC, ring placement | Only if drop-in / protocol compatibility is claimed |
| **L4** On-disk / ops | Diskfile layout, tombstones, async_pending, auditor, mixed-component | Only if drop-in claimed |

## Peregrine claim defaults (2026-08-03)

| Claimed | Not claimed this cycle |
|---------|------------------------|
| L1 core path (CRUD, listing basics, copy, SLO/DLO, TempAuth) | Full Paste pipeline, memcache filter, Keystone, S3 |
| Partial L2 (tempauth, copy, slo, dlo) | TempURL, bulk, formpost, staticweb, quotas |
| Partial L3 (replication, SSYNC, EC reconstructor present) | Full mixed-component interchange as production drop-in |
| EC track separate (`ec-heal-test`) | EC mixed into replicated formal perf tables |

`func-suite` **54/54** must be labeled **CORE-PATH-ONLY**.

## Fairness tracks

| Track | Tag | Rule |
|-------|-----|------|
| Iso-configuration | `ISO-CONFIG` | Knobs in both parsers; align **effective** concurrency/CPU, not raw `workers` |
| Iso-resource optimized | `ISO-RESOURCE` | Same CPU/RAM/disk/network quotas; implementation-specific tuning allowed |

See [CONFIG-PARITY.md](CONFIG-PARITY.md).
