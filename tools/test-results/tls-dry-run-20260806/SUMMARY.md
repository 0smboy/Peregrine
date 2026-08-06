# Contabo TLS dry-run · 2026-08-06

**Mode:** read-only SSH (`BatchMode=yes`). **No PEM apply. No service restart.**

**Verdict:** `LAB_SELF_SIGNED` — **PRODUCTION-GO-LIVE BLOCKED** until operator-trusted PEM

| Check | Result |
|-------|--------|
| SSH ×4 (swift1–4) | OK |
| PEM path | `/etc/haproxy/haproxyCA.pem` present ×4 |
| Cert kind | **self-signed** (subject == issuer) ×4 |
| Lab marker | `O=Contabo-LAB` / `TLS-GENERATED … self-signed LAB` |
| Operator PEM applied | **NO** (this run print-only) |
| haproxy unit | active ×4 |

## Hosts (from `tools/CONTABO-CLUSTER.md`)

| Alias | Public SSH | PEM | Kind | Subject / Issuer |
|-------|------------|-----|------|------------------|
| swift1 | 169.58.108.85 | yes | self-signed | `CN=10.0.0.10, O=Contabo-LAB, OU=Peregrine` |
| swift2 | 169.58.108.86 | yes | self-signed | same |
| swift3 | 169.58.108.87 | yes | self-signed | same |
| swift4 | 169.58.108.121 | yes | self-signed | same |

Validity (all nodes): **2026-08-05 → 2028-11-07** (notBefore Aug 5 09:51:47 2026 GMT / notAfter Nov 7 09:51:47 2028 GMT).

## HAProxy bind ssl lines (identical ×4)

```
bind *:8085 ssl crt /etc/haproxy/haproxyCA.pem
bind *:35357 ssl crt /etc/haproxy/haproxyCA.pem
bind *:5000 ssl crt /etc/haproxy/haproxyCA.pem
```

Source cfg: `/etc/haproxy/haproxy.cfg`. Rotation stamp: `TLS-GENERATED 2026-08-05T09:51:47Z CN=10.0.0.10 days=825 self-signed LAB`.

## Exact operator apply (NOT executed this run)

```sh
# from repo root — dry-run + print remote commands (no mutation)
./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.fullchain.pem \
  --ssh swift1,swift2,swift3,swift4 --reload --dry-run --print-commands

# same Contabo public IPs (explicit list only)
./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.fullchain.pem \
  --ssh 169.58.108.85,169.58.108.86,169.58.108.87,169.58.108.121 \
  --reload --dry-run --print-commands

# live apply ONLY after operator confirms PEM trust + targets
./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.fullchain.pem \
  --ssh swift1,swift2,swift3,swift4 --reload
```

Helpers:

- inventory probe: `tools/ops/contabo-tls-dry-run.sh`
- apply one-shot: `tools/ops/apply-vip-tls-pem.sh`
- static contract: `tools/ops/check-haproxy-tls-contract.sh`

## Safety

- `contabo-tls-dry-run.sh` never scp/installs PEM and never reloads haproxy.
- `apply-vip-tls-pem.sh --dry-run` never scp/ssh-mutates; `--print-commands` is documentation only.
- Live path requires explicit operator PEM + `--ssh` host confirmation (no Contabo auto-discovery).

## Per-host logs

- `host-swift1.txt`
- `host-swift2.txt`
- `host-swift3.txt`
- `host-swift4.txt`

## Reproduce

```sh
cd /path/to/Peregrine
./tools/ops/contabo-tls-dry-run.sh --out tools/test-results/tls-dry-run-20260806
```
