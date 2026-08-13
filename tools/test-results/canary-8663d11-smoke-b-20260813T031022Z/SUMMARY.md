# Smoke B retry 20260813T031022Z — GREEN

Host: swift3 only. Canary SHA b64deec2… unchanged. Proxy left up. Health 200/200.
No cargo on Mac. No rollback. No fleet-roll. swift1/2/4 not SSHed.

## Header constants (lifecycle_exec.rs / cold_tier.rs)
- META_STORAGE_CLASS = X-Object-Meta-S3-Storage-Class
- SYS_TRANSITIONED = X-Object-Sysmeta-S3-Transitioned
- SYS_COLD_BACKEND_URI = X-Object-Sysmeta-S3-Cold-Backend-Uri

## HTTP
| step | code | notes |
| PUT container | 201 | TempAuth :8080 |
| PUT object | 201 | + X-Object-Meta-S3-Storage-Class=GLACIER |
| plant filecold | — | /var/cache/peregrine-cold/0/AUTH_test/…/636f6c642d6f626a6563742e747874 size=37 |
| v1 proxy POST sysmeta | 202 | gatekeeper stripped inbound sysmeta |
| v1 proxy HEAD | 200 | uri_present=False (outbound strip) |
| v1 object-server HEAD | 200 | uri_present=False (never stored) |
| v2 object-server POST | 202 | local 127.0.0.1:6211/d2 + internodal 10.0.4.2/4:6211 (data path, no SSH) |
| v2 proxy HEAD | 200 | uri_present=False (gatekeeper outbound) |
| v2 object-server HEAD | 200 | **URI present**, Transitioned=1 |
| S3 POST ?restore Days=1 | **202** | |
| S3 GET ?restore | 200 | RestoreStatus XML, x-amz-restore set |

GREEN because restore_post=202 AND URI visible on object-server HEAD before restore.
Proxy client HEAD never shows X-Object-Sysmeta-* (gatekeeper). That is expected.
