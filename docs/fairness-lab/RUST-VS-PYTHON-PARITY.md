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
| SLO (manifest PUT + GET reassembly) | ✅ | ✅ | Nested/streamed P1c; some specialty residual → strict: main path ✅ |
| DLO | ✅ | ✅ | Listing pagination beyond limit residual → main path ✅ |
| Versioned writes (stack) | ✅ | ✅ | Primary suite |
| Symlink | ✅ | ✅ | |
| Staticweb | ✅ | ✅ | Specialty residual → primary ✅ |
| TempURL | ✅ | ✅ | `temp_url_ip_range` residual → **未实现** if claiming full TempURL |
| FormPost | ✅ | ✅ | |
| Bulk delete | ✅ | ✅ | |
| Bulk upload / extract-archive | ✅ | ❌ | **WONTFIX / 未实现** |
| Account autocreate | ✅ | ✅ | |
| Allow account management (full reseller) | ✅ | ❌ | Config unsupported |
| Large object edge: inline data SLO, heartbeat PUT, multipart-manifest=delete | ✅ | ❌ | Documented residual → **未实现** |
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
| backend_ratelimit | ✅ | ❌ | Can wire but not default / storage-node semantics incomplete → **未实现** as full parity |
| name_check / etag_quoter / crossdomain / read_only / domain_remap / cname_lookup | ✅ | ❌ | Wired unit-level in places; specialty residual & incomplete ops proof → **未实现** under strict rule |
| account_quotas / container_quotas | ✅ | ✅ | |
| keystoneauth authorize decision | ✅ | ✅ | |
| authtoken (HTTP token validate) | ✅ | ✅ | Live Contabo Keystone |
| keystoneauth coexist with TempAuth | ✅ | ✅ | Stamp-only-when-confirmed fix |
| s3api / s3token | ✅ | ✅ | See S3 section; not full AWS |
| container-sync middleware + daemon | ✅ | ❌ | Library HMAC only → **未实现** |
| encrypter / decrypter / keymaster middleware | ✅ | ❌ | crypto lib only → **未实现** |
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
| ListParts | ✅ | ❌ | “minimal” only → **未实现** full |
| Basic canned ACL / CORS | ✅ | ❌ | unit “basics” residual → **未实现** full |
| s3token → Keystone /v3/s3tokens | ✅ | ✅ | live EC2 GREEN 2026-08-06 |
| SigV2 | ✅ | ❌ | WONTFIX |
| aws-chunked | ✅ | ❌ | WONTFIX |
| Versioning / tagging / lifecycle / object-lock | ✅ | ❌ | WONTFIX / 501 |
| Full IAM-style ACL fidelity | ✅ | ❌ | |

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
| container-sharder (full multi-node) | ✅ | ❌ | local cleave + unit HTTP; live multi-node/KEEP **未实现** |
| container-sync daemon | ✅ | ❌ | |
| db-replicator | ✅ | ✅ | |
| swift-recon (md5/async/quarantine/tombstone/dbspace) | ✅ | ✅ | Contabo textfile+Prom |
| ring-builder | ✅ | ✅ | .builder pickle not bit-identical tool format |
| manage-shard-ranges (full) | ✅ | ❌ | `find` only → **未实现** full CLI |
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
| VIP TLS (operator PEM) | ✅ | ❌ | self-signed LAB only → **生产 TLS 未实现** |
| Full ansible v3 surface | ✅ | ❌ | deploy-rs subset + dual-guard |
| Keystone + Galera | ✅ | ✅ | Contabo LAB (not prod PEM) |
| Monitoring (Prom/Grafana/tombstone) | ✅ | ✅ | R0 wired |

---

## 8. Scorecard (strict)

| Domain | Implemented | Not implemented (incl. partial) |
|--------|-------------|----------------------------------|
| Swift v1 core CRUD + common middleware | **Most** | bulk upload; full Paste; some SLO/TempURL edges; niche filters |
| Auth | TempAuth + Keystone lab | Production-only ops polish; KMIP |
| S3 | Core SigV4 + MPU path | SigV2, versioning, full ACL/CORS, aws-chunked |
| EC | Data path + heal | macOS/default build; some EC throttling niceties |
| Sharding L3b | — | **Treat as 未实现** for multi-node product claim |
| Crypto at-rest middleware | — | **未实现** |
| container-sync | — | **未实现** |
| Production go-live | — | **未实现** (TLS PEM deferred) |

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
| L3b multi-node KEEP | **not claimed** |
| Operator TLS PEM | **deferred** |

See `tools/test-results/PARALLEL-RUN-20260806/` and `PARALLEL-123-20260806/`.
