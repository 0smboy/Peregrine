# P1b L2 — GREEN (primary) · 2026-08-04

## Verdict

**P1b primary GREEN.** Highest-value filters delivered end-to-end; smaller L2 filters wired but specialty residual.

| Gate | Result | Evidence |
|------|--------|----------|
| Unit / wiring | PASS (334 middleware; pipeline_p1b) | `18-cargo-middleware.txt`, `19-cargo-proxy.txt` |
| Contabo VIP `/info` | formpost, staticweb, quotas, symlink, versioned_writes; no bulk_upload | `10-vip-info.txt` |
| P1b specialty suite VIP | **36/36** | `p1b-suite-vip.log` |
| FormPost negatives | PASS (tamper/expired → 401) | suite + `THREAT-FORMPOST.md` |
| CORE-PATH func VIP | **54/54** | `func-suite-vip.log` |
| Contracts | UPDATED | CONTRACTS / blocked / CONFIG-PARITY / ROADMAP |

## What shipped

1. `formpost` — multipart parser + HMAC + PUT fan-out + KeyProvider
2. `staticweb` — wired (index/listings)
3. `container_quotas` / `account_quotas` — wired; chunked/HAProxy CL fix
4. `symlink` — wired
5. `versioned_writes` — PUT archive + stack DELETE restore + history + container headers
6. Smaller filters wired on-by-config: name_check, etag_quoter, crossdomain, read_only, domain_remap, cname_lookup

## Contabo deploy

- Binary: `cargo build --release -p swift-proxy-server --features ec` on swift1
- Pipeline on all four proxies includes P1b primary filters
- No wipe of `/srv/node`

## Residual (claim freeze — not full Paste)

- Smaller-filter specialty suite not run (unit + wire only)
- `backend_ratelimit` not in default pipeline / not in `/info`
- Staticweb CSS / Web-Error / tempurl QS deferred
- Symlink listing JSON augmentation deferred
- `bulk_upload` remains wontfix

## Human report

`P1B-REPORT.html`
