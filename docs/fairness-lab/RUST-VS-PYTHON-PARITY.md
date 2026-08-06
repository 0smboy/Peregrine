# Rust Swift vs Python Swift — full-function parity matrix

**As of:** 2026-08-06  
**Rule:** *partial implementation counts as **未实现 (NOT implemented)*** for this table.  
**“已实现”** requires: wired into a deployable path **and** verified enough to claim (unit + live where applicable), without major Deferred semantics that change client-visible behavior.

**Implementations compared**

| | Python | Rust (Peregrine `swift-rust`) |
|--|--------|-------------------------------|
| Tree | OpenStack Swift (e.g. Caracal / 2.33 lab) | Contabo lab binary + workspace |
| Claim level | Upstream full surface | **LAB-HARD-GREEN**, not PRODUCTION-GO-LIVE |

---

## 1. Client-facing Swift REST (v1)

| Capability | Python | Rust | Notes |
|------------|:------:|:----:|-------|
| Auth v1.0 TempAuth | ✅ | ✅ | Contabo VIP + func 54/54 |
| Account HEAD/GET listing | ✅ | ✅ | |
| Account metadata / ACLs (`X-Account-Access-Control`) | ✅ | ✅ | P1a |
| Container CRUD + listing | ✅ | ✅ | |
| Container metadata / ACLs | ✅ | ✅ | |
| Object PUT/GET/HEAD/POST/DELETE | ✅ | ✅ | Streaming body |
| Conditional GET (If-Match / IMS / …) | ✅ | ✅ | |
| Single + multi Range / multipart byteranges | ✅ | ✅ | |
| Server-side COPY / X-Copy-From | ✅ | ✅ | |
| Expiry `X-Delete-At` / `X-Delete-After` | ✅ | ✅ | Expirer daemon |
| SLO (manifest PUT + GET reassembly) | ✅ | ✅ | Nested/streamed + inline + streaming heartbeat + sync/async multipart-delete (2026-08-06) |
| DLO | ✅ | ✅ | Listing pagination beyond limit residual → main path ✅ |
| Versioned writes (stack) | ✅ | ✅ | Primary suite |
| Symlink | ✅ | ✅ | |
| Staticweb | ✅ | ✅ | Specialty residual → primary ✅ |
| TempURL (incl. ip_range) | ✅ | ✅ | `temp_url_ip_range` + peer stamp X-Backend-Remote-Addr (2026-08-06) |
| FormPost | ✅ | ✅ | |
| Bulk delete | ✅ | ✅ | |
| Bulk upload / extract-archive | ✅ | ✅ | tar / tar.gz / tar.bz2; `/info` bulk_upload (2026-08-06) |
| Account autocreate | ✅ | ✅ | |
| Allow account management | ✅ | ✅ | `allow_account_management` conf; PUT/DELETE gated 405 when off (2026-08-06) |
| SLO residual: expirer hash sharding / async ACL probes | ✅ | ❌ | day-bucket enqueue without hash_path offset; authorize residual |
| Full Paste arbitrary pipeline (any filter name) | ✅ | ❌ | Only known filter names |

---

## 2. Middleware / pipeline filters

| Filter / feature | Python | Rust | Notes |
|------------------|:------:|:----:|-------|
| catch_errors / gatekeeper / healthcheck | ✅ | ✅ | |
| proxy_logging | ✅ | ✅ | StatsD fine labels residual |
| cache (memcache client) | ✅ | ✅ | |
| listing_formats | ✅ | ✅ | |
| tempauth | ✅ | ✅ | Shared HMAC multi-proxy |
| ratelimit | ✅ | ✅ | on-by-config |
| backend_ratelimit | ✅ | ✅ | Wired on-by-config (proxy filter) |
| name_check / etag_quoter / crossdomain / read_only / domain_remap / cname_lookup | ✅ | ✅ | Wired in `build_configured_filters` + /info (2026-08-06 reaffirm) |
| account_quotas / container_quotas | ✅ | ✅ | |
| keystoneauth authorize decision | ✅ | ✅ | |
| authtoken (HTTP token validate) | ✅ | ✅ | Live Contabo Keystone |
| keystoneauth coexist with TempAuth | ✅ | ✅ | Stamp-only-when-confirmed fix |
| s3api / s3token | ✅ | ✅ | See S3 section; not full AWS |
| container-sync middleware + daemon | ✅ | ✅ | Same-cluster object path Contabo **KEEP** (`sync-smoke-20260806d`); TempAuth GET + legacy sync-key authorize + hop-by-hop PUT header strip; multi-cluster realm soak not claimed |
| encrypter / decrypter / keymaster / encryption | ✅ | ✅ | Multi-root + listing decrypt + multipart/range GET decrypt + conditional etag mask; KMIP residual |
| xprofile / other niche Paste filters | ✅ | ❌ | |

---

## 3. S3 API surface

| Capability | Python (s3api) | Rust | Notes |
|------------|:--------------:|:----:|-------|
| SigV4 | ✅ | ✅ | Live VIP |
| ListBuckets / bucket CRUD / object CRUD | ✅ | ✅ | |
| ListObjects v1 / v2 | ✅ | ✅ | |
| CopyObject | ✅ | ✅ | unit + path |
| MultiDelete | ✅ | ✅ | live deep suite |
| MPU initiate / part / complete / abort | ✅ | ✅ | live 11/11 deep |
| ListMultipartUploads | ✅ | ✅ | live |
| ListParts | ✅ | ✅ | part-number-marker + max-parts + IsTruncated (2026-08-06) |
| Canned ACL + multi-rule CORS + object ?acl store | ✅ | ✅ | Object x-amz-acl → sysmeta + GET ?acl; IAM residual |
| s3token → Keystone /v3/s3tokens | ✅ | ✅ | live EC2 GREEN 2026-08-06 |
| SigV2 | ✅ | ❌ | **WONTFIX** — stable **501 NotImplemented** (unit) |
| aws-chunked | ✅ | ❌ | **WONTFIX** — stable **501** (unit) |
| Versioning / tagging / lifecycle / object-lock | ✅ | ❌ | WONTFIX / 501 |
| Full IAM-style ACL / ACP XML body | ✅ | ❌ | canned + object sysmeta store only |

---

## 4. Storage policies & EC

| Capability | Python | Rust | Notes |
|------------|:------:|:----:|-------|
| Replication policy | ✅ | ✅ | |
| EC policy (PyECLib / liberasurecode) | ✅ | ✅ | Linux `ec` feature; Contabo deployed |
| EC multiphase MIME PUT | ✅ | ✅ | |
| EC GET / ranged GET | ✅ | ✅ | |
| EC degraded read (nparity loss) | ✅ | ✅ | live |
| EC reconstructor heal | ✅ | ✅ | live after spp identity fix |
| EC without `ec` feature build | n/a | ❌ | returns 501 by design |

---

## 5. Consistency daemons & ops

| Daemon / tool | Python | Rust | Notes |
|---------------|:------:|:----:|-------|
| object-replicator (rsync/ssync) | ✅ | ✅ | |
| object-reconstructor | ✅ | ✅ | |
| object-updater / expirer / auditor | ✅ | ✅ | |
| account-reaper | ✅ | ✅ | full reaper E2E residual → main path ✅ |
| container-updater / reconciler | ✅ | ✅ | |
| container-sharder (local + ring HTTP create path) | ✅ | ✅ | LookupHttpShardReplicator + ring primaries in run loop; KEEP live still **not product-claimed** |
| container-sharder multi-node KEEP (live) | ✅ | ❌ | Contabo multi-node quorum/KEEP **未实现** |
| container-sync daemon | ✅ | ✅ | `swift-container-sync` binary + deploy script |
| db-replicator | ✅ | ✅ | |
| swift-recon (md5/async/quarantine/tombstone/dbspace) | ✅ | ✅ | Contabo textfile+Prom |
| ring-builder | ✅ | ✅ | .builder pickle not bit-identical tool format |
| manage-shard-ranges (main CLI) | ✅ | ✅ | find/show/info/enable/delete/merge/find_and_replace + **analyze/compact/repair/activate_cleaved** (`--include-cleaved`) |
| sharder shrink (SHRINKING→SHRUNK) | ✅ | ✅ | Local-device object move + SHRUNK (`process_shrinking_donors`); multi-node quorum KEEP residual |
| sharded HEAD object_count | ✅ | ✅ | Proxy sums listing-state shard HEADs (`patch_sharded_head_counts`); may still lag list when root residual rows exist |
| dispersion / drive-audit / relinker | ✅ | ✅ | |

---

## 6. Internal / wire protocols

| Protocol | Python | Rust | Notes |
|----------|:------:|:----:|-------|
| Backend object HTTP + container-update | ✅ | ✅ | |
| Account/container REPLICATE | ✅ | ✅ | |
| Object REPLICATE / ssync duplex | ✅ | ✅ | |
| EC ssync fragment | ✅ | ✅ | |
| Pickle xattr / hashes.pkl | ✅ | ✅ | golden |
| Account/container SQLite + pending | ✅ | ✅ | golden |
| Ring v1/v2 wire | ✅ | ✅ | |

---

## 7. Platform / deploy / ops parity

| Area | Python | Rust | Notes |
|------|:------:|:----:|-------|
| eventlet multi-process workers | ✅ | ❌ | thread pool mapping → **语义不等价** |
| `servers_per_port` process isolation | ✅ | ✅ | Contabo live 6211/6212 |
| HAProxy + Keepalived | ✅ | ✅ | lab |
| VIP TLS (operator PEM path) | ✅ | ⚠️ | Code+ops script GREEN; Contabo still **self-signed LAB** (2026-08-06 probe); production PEM apply not executed |
| Full ansible v3 surface | ✅ | ❌ | deploy-rs subset + dual-guard |
| Keystone + Galera | ✅ | ✅ | Contabo LAB (not prod PEM) |
| Monitoring (Prom/Grafana/tombstone) | ✅ | ✅ | R0 wired |

---

## 8. Scorecard (strict)

| Domain | Implemented | Not implemented (incl. partial) |
|--------|-------------|----------------------------------|
| Swift v1 core CRUD + common middleware | **Most** | full arbitrary Paste; SLO async ACL/hash_path residual |
| Auth | TempAuth + Keystone lab | Production-only ops polish |
| S3 | SigV4 + MPU + ListParts + canned ACL + multi-rule CORS | SigV2, versioning, full IAM/object ACL, aws-chunked |
| EC | Data path + heal | macOS/default build; some EC throttling niceties |
| Sharding L3b | CLI + daemon ring-part cleave + fan-out + ×4 Contabo | **lab clean listing KEEP** `l3b-clean-e2e-20260806` (listed 60, no relocate); **product KEEP vs Python对照 未宣称** |
| Crypto at-rest middleware | multi-root + listing + range GET + etag mask + **chunked PUT encrypt** | KMIP; ciphertext still buffered (footer residual) |
| container-sync | filter + daemon + HTTPS + CA knobs + Contabo same-cluster object KEEP | multi-cluster realm live soak |
| Production go-live | ops TLS script ready | **未实现** (Contabo still lab self-signed; operator PEM not applied) |

**Bottom line under the user rule (“部分 = 未实现”):**  
Rust is a **strong core-path + lab-proven** Swift, **not** a drop-in “full OpenStack Swift feature twin.” Fairness and product claims must stay **CORE-PATH / LAB-HARD-GREEN**, not “feature-complete vs Python.”

---

## 9. Contabo live evidence anchors (2026-08-06)

| Proof | Result |
|-------|--------|
| TempAuth func VIP | 54/54 |
| Soak 1h | fail=0 (n=205) |
| Python :8090 ×3 func | 54/54 each |
| EC feature deploy | PUT/GET; heal 2→3 after fix |
| S3 MPU deep | 11/11 |
| EC2 s3token | GREEN |
| VIP failover | PASS |
| L3b multi-node KEEP | **lab clean PASS** (`l3b-clean-e2e-20260806` listed 60, RIGHT partitions, no relocate); product claim **not claimed** |
| Operator TLS PEM path (script) | **code GREEN**; Contabo **self-signed LAB** (probe 2026-08-06) |
| container-sharder ×4 Contabo | **active** (status probe; KEEP not claimed) |
| Linux redeploy L3b bins ×4 | **PASS** (`linux-redeploy-20260806`) |
| L3b CLI enable + epoch DB | **PASS** after set_sharding_state fix |
| L3b sharder cleave creates shard DBs | **PASS lab** (`l3bkeep…`, shard DBs present) |
| L3b listing KEEP post-cleave | **LAB CLEAN PASS** listed 60 no relocate (`l3b-clean-e2e-20260806`); post-shard 4KB PUT→list via shard update route (`l3b-4kb-keep-20260806`); wave2 30×4KB put_fail=0 list+GET (`l3b-4kb-wave2-20260806`); product long soak **not claimed** |
| container-sync Contabo same-cluster | **KEEP** puts=28 fails=0 dst 5/5 GET (`sync-smoke-20260806d`); multi-cluster soak not run |
| compact / activate_cleaved | CLI + unit; lab CLEAVED→ACTIVE→SHRINKING mark (`l3b-compact-20260806`) |
| sharder shrink + HEAD counts | unit PASS object move+SHRUNK; Contabo HEAD sum + list residual (`l3b-shrink-20260806`); multi-node shrink KEEP residual |
| TLS Contabo dry-run | **LAB self-signed** (`tls-dry-run-20260806`) |
| Operator TLS PEM live apply | **deferred** |

See `tools/test-results/PARALLEL-RUN-20260806/` and `PARALLEL-123-20260806/`.


## 10. Offline one-click (2026-08-06)

`tools/offline-oneclick/offline-oneclick.sh` — pack / install / start / test / all-local for SAIO + swift-console (airgap after pack). Not a substitute for multi-node `swift-deploy-rs`.
