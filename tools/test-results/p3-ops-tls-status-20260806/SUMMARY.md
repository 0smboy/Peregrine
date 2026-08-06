# TLS status · 2026-08-06

**Verdict: LAB GREEN / PRODUCTION BLOCKED**

| Item | Status |
|------|--------|
| VIP :8085 SSL | Active, cert `/etc/haproxy/haproxyCA.pem` |
| Keystone :5000/:35357 SSL | Same PEM |
| Cert type | **Self-signed** CN=10.0.0.10 O=Contabo-LAB |
| Validity | 2026-08-05 → 2028-11-07 |
| Operator PEM | **ABSENT** on Contabo |
| TLS-ROTATION.txt | Present (LAB generated stamp) |

## PRODUCTION-GO-LIVE gate

Requires operator-trusted PEM (or ACME) at `haproxy_tls_pem_src`, client success **without** `curl -k`, and HTTP close/redirect policy.

No cutover performed this pack (no PEM available).
