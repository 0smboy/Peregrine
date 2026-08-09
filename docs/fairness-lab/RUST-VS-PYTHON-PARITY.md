# Rust Swift vs Python Swift — full-function parity matrix

**As of:** 2026-08-09
**Rule:** *partial implementation counts as **未实现 (NOT implemented)*** for this table.  
**“已实现”** requires: wired into a deployable path **and** verified enough to claim (unit + live where applicable), without major Deferred semantics that change client-visible behavior.  
**Hard9 wave (2026-08-08):** OpenStack-standard Paste + xprofile/list_endpoints; Lifecycle Transition cold GET+restore; ACP READ/WRITE enforce + local IAM dir; process_workers prefork; SLO concurrent HEAD + listing etag refetch. Evidence `tools/test-results/hard9-residual-wave-20260808/`.  
**Correction (2026-08-09):** the hard residual wave proved several library and unit surfaces, not deployable product parity. Unknown Paste filters were no-op placeholders; IAM and cold-tier configuration was not wired by the proxy builder; Eventlet helpers were not used by the serving path; and auto-shrink covered same-host tests only. These are marked not implemented under this matrix's strict rule. Evidence and correction: `tools/test-results/hard-residual-wave-20260808/`.

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
| SLO (manifest PUT + GET reassembly) | ✅ | ✅ | Nested/streamed + inline + heartbeat + sync/async delete; **concurrent HEAD pile** + **yield_frequency**; **listing etag refetch**; Contabo live audit KEEP (`slo-full-audit-20260807` + hard9) |
| DLO | ✅ | ✅ | Listing pagination beyond limit residual → main path ✅ |
| Versioned writes (stack) | ✅ | ✅ | Primary suite |
| Symlink | ✅ | ✅ | |
| Staticweb | ✅ | ✅ | Specialty residual → primary ✅ |
| TempURL (incl. ip_range) | ✅ | ✅ | `temp_url_ip_range` + peer stamp X-Backend-Remote-Addr (2026-08-06) |
| FormPost | ✅ | ✅ | |
| Bulk delete | ✅ | ✅ | |
| Bulk upload / extract-archive | ✅ | ✅ | tar / tar.gz / tar.bz2; `/info` bulk_upload (2026-08-06) |
| Account autocreate | ✅ | ✅ | |
| Allow account management | ✅ | ✅ | `allow_account_management` conf; PUT/DELETE gated **405** when off; unit reaffirm 2026-08-07 (`residual-pipeline-account-20260807`: lib 19/19 + gate test) |
| SLO residual: expirer hash sharding / async ACL probes | ✅ | ✅ | hash_path day-bucket offset + HEAD write probes (`impl-slo-expirer-hash-20260807`) |
| OpenStack-standard Paste pipeline filter behavior | ✅ | ❌ | Implemented Rust filters work; several names are explicit no-op aliases rather than Python-equivalent middleware |
| Unlimited third-party arbitrary Paste plugins | ✅ | ❌ | In-process Rust factories can be registered in code; no Python egg, shared-library, or WASM loader. Unknown names fail closed by default |

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
| xprofile | ✅ | ✅ | `X-Profile-Duration-Ms` (+ optional log); unit (`hard9`) |
| list_endpoints | ✅ | ✅ | `/endpoints/...` JSON; 501 without ring resolver; unit |
| NamedPassthrough slots (memcache/recon/healthcheck aliases in pipeline) | ✅ | ✅ | Claimable pipeline slots |
| Dynamic Paste plugin loading (third-party `use=` factories) | ✅ | ❌ | Registry accepts factories registered by the Rust process; configuration cannot load arbitrary third-party code |

---

## 3. S3 API surface

| Capability | Python (s3api) | Rust | Notes |
|------------|:--------------:|:----:|-------|
| SigV4 | ✅ | ✅ | Live VIP; unit verify |
| ListBuckets / bucket CRUD / object CRUD | ✅ | ✅ | |
| ListObjects v1 / v2 | ✅ | ✅ | |
| CopyObject | ✅ | ✅ | unit + path |
| MultiDelete | ✅ | ✅ | live deep suite |
| MPU initiate / part / complete / abort | ✅ | ✅ | live 11/11 deep |
| ListMultipartUploads | ✅ | ✅ | live |
| ListParts | ✅ | ✅ | part-number-marker + max-parts + IsTruncated (2026-08-06) |
| Canned bucket ACL (`private` / `public-read` / `public-read-write`) | ✅ | ✅ | `x-amz-acl` → `X-Container-Read/Write`; unit |
| Object canned ACL store + GET `?acl` | ✅ | ✅ | `x-amz-acl` → `X-Object-Sysmeta-S3-Acl`; unit 2026-08-07; **not** anonymous Swift GET by itself |
| Multi-rule CORS put/get | ✅ | ✅ |
| Lifecycle Expiration **execution** | ✅ | ✅ | Enabled Days/Date → `X-Delete-At` on PUT; AbortIncompleteMPU marker delete-at |
| Lifecycle **Transition** metadata execution | ✅ | ✅ | cold class after Transition-At → GET `InvalidObjectState`; restore window and metadata stamps |
| Physical cold-tier storage-policy routing | ✅ | ❌ | `ColdPolicyMap` and memory backend are unit-only; proxy config does not populate `S3Api.cold_map`; no physical adapter |
| Object Lock WORM (legal-hold/retention) | ✅ | ✅ | blocks DELETE/overwrite; **GOVERNANCE bypass**; COMPLIANCE/legal-hold hard-block |
| s3token → Keystone /v3/s3tokens | ✅ | ✅ | live EC2 GREEN 2026-08-06 |
| SigV2 | ✅ | ✅ | HMAC-SHA1 Base64 header+query; AWS vector + middleware good-sig path (`hard-residual-wave-20260808`) |
| aws-chunked / STREAMING-* | ✅ | ✅ | dechunk after SigV4 header verify; **per-chunk HMAC enforced** → `SignatureDoesNotMatch` (`impl-chunk-sig-enforce` / priority-unimpl-wave-20260807) |
| Multi-version object data plane | ✅ | ✅ | archive `{bucket}+versions`; versionId GET/DELETE; delete-marker; ListVersions (`impl-s3-multiversion-data-20260807`)
| Versioning status GET/PUT | ✅ | ✅ | meta `X-Container-Meta-S3-Versioning`; unit `versioning_put_get_round_trip` `impl-s3-versioning-surface-20260807` |
| List object versions (`?versions`) | ✅ | ✅ | `ListVersionsResult` from `{bucket}+versions` indexes; empty only when versions container 404; **pagination KEEP** `key-marker`/`version-id-marker`/`max-keys` → `IsTruncated`+`NextKeyMarker`+`NextVersionIdMarker` (`impl-listversions-pagination-20260807`) |
| Tagging GET/PUT/DELETE (bucket + object) | ⚠️ (GET empty / PUT NotImpl) | ✅ | meta TagSet round-trip; unit `*_tagging_*_round_trip` |
| Lifecycle GET/PUT/DELETE | ❌ / limited | ✅ | raw XML in container meta; unit `lifecycle_put_get_delete_round_trip` (no expirer) |
| Object-lock config GET/PUT | ❌ GET not-found / PUT NotImpl | ✅ | raw XML meta round-trip; unit `object_lock_put_get_round_trip` (no WORM) |
| grant-header + ACP XML store/GET | ✅ | ✅ | JSON sysmeta + AllUsers→container ACL; canned wins if both present |
| ACP grant **enforcement** (READ/WRITE) | ✅ | ✅ | GET/HEAD READ + PUT/DELETE WRITE (`acl_write_check_object`); unit (`hard9` / P1) |
| Local IAM identity directory (email/access_key map) | ✅ | ✅ | `iam::IdentityDirectory` |
| Multi-tenant IAM policy engine (local) | ✅ | ❌ | `IamService` evaluation is unit-tested, but the proxy builder does not load policies or call `with_iam` |
| AWS IAM cloud hosted product | ✅ | ❌ | External AWS service — out of scope |
| authenticated-read / log-delivery-write canned | ❌ / NotImpl | ❌ | map to private; no AuthenticatedUsers Swift ACL |

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
| sharder shrink helper (SHRINKING→SHRUNK) | ✅ | ✅ | Explicit local/same-host helper path with unit coverage |
| Multi-primary auto-shrink product | ✅ | ❌ | Disabled by default; same-host tests only; no cross-node quorum, crash recovery, or sustained cluster soak |
| sharded HEAD object_count | ✅ | ✅ | HEAD reuses listing fan-out → Object-Count matches list (`l3b-head-list-20260806`) |
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
| process worker prefork | ✅ | ✅ | `process_workers` is wired into proxy startup |
| eventlet/greenlet scheduling semantics | ✅ | ❌ | `eventlet_parity` is an isolated OS-thread helper module and is not used by the serving path |
| `servers_per_port` process isolation | ✅ | ✅ | Contabo live 6211/6212 |
| HAProxy + Keepalived | ✅ | ✅ | lab |
| VIP TLS (operator PEM path) | ✅ | ⚠️ | Code+ops script GREEN; Contabo still **self-signed LAB** (2026-08-06 probe); production PEM apply not executed |
| Full ansible v3 surface | ✅ | ⚠️ | **PARTIAL/GREEN** for implemented subset (data-plane + LB/Keepalived + TLS knobs + `expand.yml` + Identity 对接 flags); **not** full Python role parity — matrix [`ANSIBLE-V3-SURFACE.md`](ANSIBLE-V3-SURFACE.md) + evidence `tools/test-results/impl-ansible-v3-surface-20260807/` |
| Keystone + Galera | ✅ | ✅ | Contabo LAB (not prod PEM) |
| Monitoring (Prom/Grafana/tombstone) | ✅ | ✅ | R0 wired |

---

## 8. Scorecard (strict)

| Domain | Implemented | Not implemented (incl. partial) |
|--------|-------------|----------------------------------|
| Swift v1 core CRUD + common middleware | **Most** | KMIP; multi-cluster sync soak; operator PEM |
| Auth | TempAuth + Keystone lab + SigV2 | Production PEM polish |
| S3 | SigV4 + **SigV2** + MPU + ACL/CORS + chunk-sig + versioning + Transition metadata + WORM + ACP | Runtime-wired IAM; physical cold-tier adapter/routing; hosted AWS IAM |
| EC | Data path + heal | macOS/default build; some EC throttling niceties |
| Sharding L3b | CLI + daemon + explicit local shrink helper | Auto-shrink product path; cross-node quorum/recovery; sustained cluster soak |
| Crypto at-rest middleware | multi-root + listing + range GET + etag mask + **chunked PUT encrypt** | KMIP; ciphertext still buffered (footer residual) |
| container-sync | filter + daemon + HTTPS + CA knobs + Contabo same-cluster object KEEP | multi-cluster realm live soak (no second cluster / realms conf) |
| Production go-live | ops TLS script ready; VIP :8085 **lab SSL live** (self-signed) | **未实现** operator PEM + trust path (`priority-wave-20260806`) |
| Full ansible v3 surface (deploy) | near-full `bundle/` | **PARTIAL** matrix [ANSIBLE-V3-SURFACE.md](ANSIBLE-V3-SURFACE.md); evidence `impl-ansible-v3-surface-20260807` — do **not** claim full role twin |

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
| L3b multi-node KEEP | **lab clean PASS** (`l3b-clean-e2e-20260806` listed 60); **product-style 40×4KB KEEP** on SHARDED container (`priority-wave-20260806` put=40 HEAD=LIST=100 GET 5/5); Python对照 **not claimed** |
| Operator TLS PEM path (script) | **code GREEN**; Contabo **self-signed LAB live** on VIP :8085 (`priority-wave-20260806/01-tls-lab-status.txt`); operator PEM **not applied** |
| container-sharder ×4 Contabo | **active**; shrink + listing KEEP lab paths claimed separately |
| Linux redeploy L3b bins ×4 | **PASS** (`linux-redeploy-20260806`) |
| L3b CLI enable + epoch DB | **PASS** after set_sharding_state fix |
| L3b sharder cleave creates shard DBs | **PASS lab** (`l3bkeep…`, shard DBs present) |
| L3b listing KEEP post-cleave | **LAB CLEAN PASS** listed 60 no relocate (`l3b-clean-e2e-20260806`); post-shard 4KB PUT→list (`l3b-4kb-keep-20260806`); wave2 30×4KB (`l3b-4kb-wave2-20260806`); **priority-wave 40×4KB product KEEP** + VIP `-k` path (`priority-wave-20260806`); multi-hour soak **not claimed** |
| container-sync Contabo same-cluster | **KEEP** puts=28 fails=0 (`sync-smoke-20260806d`); **re-verify KEEP 2026-08-07** when daemon runs on SRC primary (`residual-wave-20260807/08`); multi-cluster soak **residual** (no realms) |
| compact / activate_cleaved | CLI + unit; lab CLEAVED→ACTIVE→SHRINKING mark (`l3b-compact-20260806`) |
| sharder shrink + HEAD counts | **LAB KEEP** shrinklab 20→SHRUNK+acceptor 20 + GET 20/20 (`l3b-shrink-20260806`); multi-primary auto-shrink **residual** — peer roots can lack live `shard_range` rows (`residual-wave-20260807/04b`) |
| TLS Contabo dry-run | **LAB self-signed** (`tls-dry-run-20260806` + `priority-wave-20260806`) |
| Operator TLS PEM live apply | **deferred** → blocks PRODUCTION-GO-LIVE |

See `tools/test-results/PARALLEL-RUN-20260806/` and `PARALLEL-123-20260806/`.


## 10. Offline one-click (2026-08-06)

`tools/offline-oneclick/offline-oneclick.sh` — pack / install / start / test / all-local for SAIO + swift-console (airgap after pack). Not a substitute for multi-node `swift-deploy-rs`.
