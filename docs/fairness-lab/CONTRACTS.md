# Contract levels — Contabo fairness lab

| Level | Required behavior | Gate |
|-------|-------------------|------|
| **L1** Public Swift v1 API | HTTP methods, headers, bodies, listings, metadata, conditional, ranges, SLO/DLO, errors | **Mandatory** before any formal perf citation |
| **L2** Middleware / auth | TempAuth, ACLs; TempURL, bulk, expiration, versioning, Keystone, S3 | Feature-dependent; **unsupported ≠ FAIL** |
| **L3** Backend protocol | Proxy→storage verbs, replication, SSYNC, ring placement | Only if drop-in / protocol compatibility is claimed |
| **L4** On-disk / ops | Diskfile layout, tombstones, async_pending, auditor, mixed-component | Only if drop-in claimed |

## Peregrine claim defaults (2026-08-04 P2b+P2c+P3-auth+P3-s3)

| Claimed | Not claimed this cycle |
|---------|------------------------|
| L1 core path (CRUD, listing basics, copy, SLO/DLO, TempAuth) | Full Paste pipeline on Contabo VIP |
| P0–P1c middleware / debt (see prior rows in ROADMAP) | `bulk_upload`; smaller-filter specialty residual |
| P2a daemons as conf services | Reseller account-reaper purge E2E; reconciler policy-race inject |
| **P2b continuous auditors:** object interval=30, DB interval=1800; systemd Restart=on-failure | **container-sync** full path (**wontfix P2b**) |
| **P2c topology:** `servers_per_port` minimal (ring discovery + REUSEPORT acceptors); workers semantics docs + `swift-effective-concurrency` | Python prefork per-disk I/O isolation; Contabo multi-port ring rebuild |
| **P3-auth code path:** ON-BY-CONFIG `authtoken` + `keystoneauth`; TempAuth may coexist; threat negatives unit-covered | Contabo live Keystone / MariaDB (ABSENT); cluster Keystone GREEN |
| **P3-s3 / W3 S3 unit stop-line:** ON-BY-CONFIG `s3api` (SigV4 + CRUD + List v1/v2 + MultiDelete + MPU + ListMPU + ACL/CORS basics); live-ready `s3token` HTTP; **not** on Swift `/info` | Contabo VIP default-pipeline enable + Keystone live s3tokens (W1); SigV2/aws-chunked/versioning **WONTFIX** (see S3-ON-BY-CONFIG.md) |
| **P3-ops** HAProxy TLS terminate + expand/multi-region host_vars (code) | Contabo live TLS apply (may be dry-run only); Python-v3 HTTPS |
| Partial L3 (replication, SSYNC, EC reconstructor present) | Full mixed-component interchange as production drop-in |
| EC track separate (`ec-heal-test`); proxy build needs `--features ec` | EC mixed into replicated formal perf tables |

See [PRODUCTION-GAP-ROADMAP.md](PRODUCTION-GAP-ROADMAP.md) · [AUDITOR-SLA.md](AUDITOR-SLA.md) · [WORKERS-SEMANTICS.md](WORKERS-SEMANTICS.md).  
Evidence: `tools/test-results/p3-auth-20260804/`, `p3-s3-20260804/`, `p2b-audit-20260804/`, `p2c-topology-20260804/` (also `p2a-daemons-20260804/`, …).  
`func-suite` **54/54** remains **CORE-PATH-ONLY**.

## Fairness tracks

| Track | Tag | Rule |
|-------|-----|------|
| Iso-configuration | `ISO-CONFIG` | Knobs in both parsers; align **effective** concurrency/CPU, not raw `workers` |
| Iso-resource optimized | `ISO-RESOURCE` | Same CPU/RAM/disk/network quotas; implementation-specific tuning allowed |

See [CONFIG-PARITY.md](CONFIG-PARITY.md).
