# Blocked by missing Rust implementation

These items explain why Contabo/deploy cannot mirror full Python ansible.  
**This cycle does not implement them** — it only prevents false parity claims.

**Strict full matrix (partial = 未实现):** [RUST-VS-PYTHON-PARITY.md](RUST-VS-PYTHON-PARITY.md) · public docs [/parity](https://peregrine-docs-ochre.vercel.app/parity).

| Item | Impact on fairness | Priority backlog |
|------|--------------------|------------------|
| Full Paste `pipeline=` for **remaining** L2+ (live Keystone cluster; full S3; bulk_upload; smaller-filter specialty residual) | Middleware surface unequal beyond P0–P2 + P3-auth/s3 code paths | High (P3) |
| P3-auth Keystone + authtoken path | — | **PARTIAL (P3-auth)** — proxy wiring + unit/threat GREEN; Contabo Keystone ABSENT; see `tools/test-results/p3-auth-20260804/` |
| P3-s3 / Wave 3 S3 path (`s3api`: SigV4 + CRUD + List v1/v2 + MultiDelete + MPU + ListMPU + ACL/CORS basics + live-ready s3token HTTP) | — | **PARTIAL** — unit GREEN; Contabo TempAuth S3 live **GREEN** (`wave3-s3-l3b-live-20260805/`); live Keystone s3tokens exchange **BLOCKED** (uwsgi crash); L3b quorum not run; see [S3-ON-BY-CONFIG.md](S3-ON-BY-CONFIG.md) |
| Implemented-subset pipeline ordering (`catch_errors`/`gatekeeper`/`healthcheck` + `ratelimit`/`tempauth`/`copy`/`slo`/`dlo`) | — | **DONE (B4 / build/phase1)** — optional `[pipeline:main]`; unknown names skipped |
| P0 wire: `cache` + `listing_formats` + `proxy_logging` (logger sink) in `build_configured_filters` | — | **DONE (P0 code)** — names enable; not silent-skip. SAIO same-pipeline + func gate: see `tools/test-results/p0-pipeline-*` |
| P1a wire: `bulk` (delete) + `tempurl` + account ACL + `ratelimit` on-by-config | — | **DONE (P1a)** — `/info` accurate; specialty 27/27; VIP func 54/54; see `tools/test-results/p1a-l2-20260804/` |
| P1b wire: formpost/staticweb/quotas/symlink/versioned_writes (+ smaller on-by-config) | — | **DONE (P1b primary)** — specialty 36/36; VIP func 54/54; see `tools/test-results/p1b-l2-20260804/` |
| P1c debt: nested SLO / streaming / manifest copy / shared info-cache ACL | — | **DONE (P1c)** — specialty 28/28; VIP func 54/54; failover smoke PASS; see `tools/test-results/p1c-debt-20260804/` |
| memcache-backed account/container **info** cache (shared across proxies) | — | **DONE (P1c)** — L2 authoritative when `memcache_servers` set; L1-only fallback without memcache |
| P2a: object-expirer / account-reaper / container-reconciler / container-updater as conf services | — | **DONE (P2a)** — VIP E2E expirer+updater; func 54/54; see `tools/test-results/p2a-daemons-20260804/` |
| `servers_per_port` / per-disk object listeners | — | **Wave 2 CODE GREEN / Contabo PARTIAL** — per-device ring ports (`object_port_per_device`) + process-per-port supervise; Contabo live ring rebuild backlog (no wipe). See `tools/test-results/wave2-spp-region-20260805/` |
| `bulk_upload` / `?extract-archive` | — | **DONE (2026-08-06)** — tar/tar.gz/tar.bz2 + `/info` bulk_upload |
| Keystone / MariaDB on Contabo | Identity infra absent; VIP stays TempAuth | Medium — code path PARTIAL; live cutover FROZEN without external Keystone |
| Full S3 API (SigV2 / aws-chunked / versioning WONTFIX; full IAM ACL; Contabo VIP enable) | Beyond unit stop-line | Medium — see wave3-s3-l3b-prod matrix; [S3-ON-BY-CONFIG.md](S3-ON-BY-CONFIG.md) |
| Continuous auditor SLA | — | **DONE (P2b)** — continuous systemd daemons (object interval=30, DB=1800); nightly timer disabled; see `tools/test-results/p2b-audit-20260804/` + AUDITOR-SLA.md |
| container-sync full proxy filter + daemon path | — | **DONE path (2026-08-06)** — proxy filter + `swift-container-sync` daemon; multi-cluster live soak not claimed |
| `workers` prefork semantics | Integer knobs mislead A/B | **DONE (P2c)** — WORKERS-SEMANTICS.md + `swift-effective-concurrency` / `effective-concurrency.py` + library `effective_concurrency` |
| Keepalived inside bundle-rust | Was Contabo-only overlay | **DONE (build/phase1)** — `rust_keepalived` + workspace allows `ingress.mode=keepalived` |
| HAProxy TLS termination (`lb_mode=https`) | Client HTTPS at VIP | **DONE (P3-ops code)** — self-signed or `haproxy_tls_pem_src`; Contabo live cert apply = dry-run only (lab stays http:8085). Evidence `tools/test-results/p3-ops-20260804/` |
| add-disk / add-node automation | Topology expand | **DONE (P3-ops code)** — `expand.yml` + idempotent ring `add`/`search`/`list`; dual-guard no wipe `/srv/node`. Live Contabo expand drill = backlog without ticket |
| Multi-region ring labels | Cross-region affinity | **Wave 2 samples + dry-run** — r1/r2 host_vars samples + drill plan; Contabo live label drill backlog (not WAN). [MULTI-REGION.md](MULTI-REGION.md) · `wave2-spp-region-20260805/` |
| P3-ops: HAProxy TLS + expand + multi-region host_vars | Ops completeness | **DONE (P3-ops code)** — `lb_mode=https` TLS terminate; `expand.yml`; region/zone/swift_devices in rings; dual-guard no wipe. Contabo live TLS may be dry-run only. See `tools/test-results/p3-ops-*` + P3-OPS-CONTRACT.md |

L3b container sharding: **Wave 3 PARTIAL** (2026-08-05 prod stop-line; CLI
expanded 2026-08-06) — CleavingContext persist, auto_shard gate + unit path,
misplaced unit, `HttpShardReplicator` quorum (unit), proxy listing fan-out,
manage-shard-ranges find/show/info/enable/delete/merge/find_and_replace.
**Multi-node KEEP blockers:** live Contabo quorum drill; ring-directed HTTP
shard create on all primaries wired through daemon; compact/repair/analyze;
shrink/expand sequences. Contabo multi-node live quorum + 4KB KEEP **not
claimed**. See `tools/test-results/wave3-s3-l3b-prod-20260805/`.

| Item (2026-08-03 refresh) | Status |
|---------------------------|--------|
| Full 4-node `openstack-swift` Performance cluster | **Absent** → Python formal **FROZEN** (`PYTHON_CLUSTER_ABSENT`) |
| Stage-3 Python 3-node on swift2/3/4 (separate ports/disks) | **Absent** → 3A/3B/3D **FROZEN** (`phase-3-20260804/`) — no wipe of `/srv/node` |
| autocos multi-endpoint true 4-proxy fanout | Pilot uses `ST_ENDPOINT` RR; full fanout backlog |
| 16MB_read formal ACCEPT | **DONE R8** — DIRECT+HA ACCEPT (oc=40/rt=180, n=8) |
| 6h soak per impl | **DONE R8** — DIRECT 4KB_write_128 6h fail_total=0 |
| P3-data X-Newest best-source | **PARTIAL DONE** — proxy collect+newest; resumable multi-GET still deferred |
| P3-data / Wave 3 L3b sharder | **PARTIAL** — lab clean listing KEEP PASS (`l3b-clean-e2e-20260806` listed 60, ring-part, no relocate); product multi-node 4KB KEEP / Python对照 **not claimed** |
| P3-data at-rest crypto middleware | **DONE path (2026-08-06)** — keymaster/encrypter/decrypter/encryption ON-BY-CONFIG; KMIP residual |
