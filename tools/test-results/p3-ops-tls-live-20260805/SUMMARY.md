# P3-ops TLS live — 2026-08-05

**Verdict: LAB GREEN (self-signed) · PRODUCTION-GO-LIVE = NOT MET**

Per [P3-OPS-CONTRACT.md](../../../docs/fairness-lab/P3-OPS-CONTRACT.md): Contabo live TLS
apply with self-signed PEM is allowed for LAB; production requires operator PEM.

## What was done

1. Generated self-signed PEM `CN=10.0.0.10` (825 days) → `/etc/haproxy/haproxyCA.pem` on all nodes.
2. Rotation record: `/etc/haproxy/TLS-ROTATION.txt` (`TLS-GENERATED 2026-08-05T09:51:47Z … self-signed LAB`).
3. HAProxy binds: `:8085`, `:5000`, `:35357` → `ssl crt /etc/haproxy/haproxyCA.pem`.
4. Proxies validate tokens against local Keystone HTTP `:5001` (avoids self-signed client verify failure); clients use `https://10.0.0.10:5000`.

## Measured gates

| Gate | Result |
|------|--------|
| `https://10.0.0.10:8085/healthcheck` | 200 |
| `https://10.0.0.10:5000/v3` token issue | 201 + X-Subject-Token |
| HTTPS Swift CRUD (Keystone token) | put_c=201 put_o=201 get=tls-obj del=204 |
| Bad token | 401 |
| Plain HTTP `:8085` | fail / empty (TLS-only bind) |
| Operator production PEM | ABSENT → no PRODUCTION-GO-LIVE |

Evidence: `20-vip-tls-info.txt` · parent Identity pack `../wave1-identity-live-20260805/`
