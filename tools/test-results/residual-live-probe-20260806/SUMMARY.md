# Residual live probe · Contabo · 2026-08-06

**Mode:** read-only SSH (no config mutation, no PEM replace).

## TLS (VIP HAProxy)

| Item | Result |
|------|--------|
| PEM path | `/etc/haproxy/haproxyCA.pem` present on swift1 |
| Subject | `CN=10.0.0.10, O=Contabo-LAB, OU=Peregrine` |
| Issuer | self-signed (same as subject) |
| Validity | 2026-08-05 → 2028-11-07 |
| Claim | **LAB self-signed only** — not operator production PEM go-live |

Operator apply path (not executed this probe): `tools/ops/apply-vip-tls-pem.sh`.

## Sharder / sync daemons

| Node | public | sharder | container-sync | binaries |
|------|--------|---------|----------------|----------|
| swift1 | 169.58.108.85 | **active** | inactive | sharder + manage-shard-ranges present |
| swift2 | 169.58.108.86 | **active** | inactive | same |
| swift3 | 169.58.108.87 | **active** | inactive | same |
| swift4 | 169.58.108.121 | **active** | inactive | same |

**Claim:** sharder **daemon deployed ×4** (lab). Multi-node KEEP product claim still requires dedicated quorum/cleave drill evidence — not this status probe.

container-sync unit not enabled on Contabo (code path exists; live multi-cluster not claimed).

## Evidence files

- `01-tls-sharder-status.txt`
