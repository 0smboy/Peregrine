# tools/ops — production operator hooks

Scripts that bridge **lab** (self-signed / dry-run) and **production** (operator
PEM) without committing secrets or auto-mutating Contabo.

## HAProxy VIP TLS PEM

| Item | Value |
|------|--------|
| Where TLS terminates | HAProxy only (`lb_mode=https`) |
| Dest on nodes | `/etc/haproxy/haproxyCA.pem` (`haproxy_tls_pem`) |
| Controller source | `haproxy_tls_pem_src` (path on deploy controller) |
| Bundle role | `swift-deploy-rs/bundle-rust/roles/rust_haproxy/` |
| Lab default | `haproxy_tls_self_signed: true` |
| Production | Operator PEM, `haproxy_tls_self_signed: false` |

### One-shot apply

```sh
cd /path/to/Peregrine

# 1) Validate PEM (cert + key concatenated)
./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.fullchain.pem --check

# 2) Dry-run + print exact remote commands (no SSH mutation)
./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.fullchain.pem \
  --ssh swift1,swift2,swift3,swift4 --reload --dry-run --print-commands
# Contabo public IPs also OK (from tools/CONTABO-CLUSTER.md):
#   --ssh 169.58.108.85,169.58.108.86,169.58.108.87,169.58.108.121

# 2b) Live inventory only (subject/issuer + bind ssl; never applies)
./tools/ops/contabo-tls-dry-run.sh \
  --out tools/test-results/tls-dry-run-$(date -u +%Y%m%d)

# 3) Live apply ONLY after operator confirms SSH targets
./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.fullchain.pem \
  --ssh swift1,swift2,swift3,swift4 --reload

# Local single-host (e.g. lab VM with haproxy)
sudo SWIFT_TLS_PEM=/secure/vip.fullchain.pem \
  ./tools/ops/apply-vip-tls-pem.sh --local --reload
```

Env alternatives: `SWIFT_TLS_PEM` (source), `HAPROXY_TLS_PEM` (dest).

**Safety:** the script never invents Contabo hosts. No `--ssh` → no remote write.
Do not force-push or change live without explicit SSH confirmation.

### Contabo live apply steps

Current lab state (see `tools/test-results/p3-ops-tls-*`): VIP
`https://10.0.0.10:8085` may already terminate TLS with a **self-signed** PEM.
`PRODUCTION-GO-LIVE` requires a trusted operator PEM and client success
**without** `curl -k`.

1. **Obtain PEM** — full chain + private key concatenated (no passphrase),
   kept outside git (e.g. root-only path on the operator laptop or controller).
2. **Validate**
   ```sh
   ./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem --check
   ```
3. **Plan via deploy-rs (optional full path)**  
   Set in project `group_vars` / workspace (never commit secrets):
   ```yaml
   lb_mode: https
   haproxy_tls_pem: /etc/haproxy/haproxyCA.pem
   haproxy_tls_pem_src: /secure/vip.pem   # controller-local path
   haproxy_tls_self_signed: false
   ```
   Then `swift-deploy plan` (stack=rust) and inspect TLS copy tasks. Prefer plan
   evidence before apply.
4. **Or one-shot SSH install (this toolkit)** — after confirming host list:
   ```sh
   ./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem \
     --ssh swift1,swift2,swift3,swift4 --reload
   ```
   Script: stages PEM → `0600` dest → `haproxy -c` → `systemctl reload|restart`.
5. **Smoke**
   ```sh
   curl -fsS --cacert /secure/ca-or-fullchain.pem \
     https://10.0.0.10:8085/healthcheck
   # TempAuth / Keystone CRUD with real trust store (no -k)
   ```
6. **Record** — nodes append `/etc/haproxy/TLS-ROTATION.txt`; keep operator
   evidence under `tools/test-results/p3-ops-tls-<date>/` (no PEM content).

Honest stop-line: if only self-signed material is available, stay
**LAB-HARD-GREEN**; do not claim production TLS.

### Contract dry-run (no cluster)

```sh
./tools/ops/check-haproxy-tls-contract.sh
```

Static checks that bundle-rust templates/tasks still wire `haproxy_tls_pem_src`,
`ssl crt`, and refuse https without material.

## Offline SAIO vs production VIP

| Path | TLS |
|------|-----|
| `tools/offline-oneclick` | HTTP `:8080` SAIO; optional `SWIFT_TLS_PEM` staging only |
| Contabo / multi-node | HAProxy VIP TLS via this ops toolkit or deploy-rs |

```sh
# SAIO staging (does not terminate TLS on the proxy)
./tools/offline-oneclick/offline-oneclick.sh tls --pem /path/to.pem --check
./tools/offline-oneclick/offline-oneclick.sh tls --pem /path/to.pem
# Production VIP → tools/ops/apply-vip-tls-pem.sh (above)
```

## Related docs

- [P3-OPS-CONTRACT.md](../../docs/fairness-lab/P3-OPS-CONTRACT.md)
- [bundle-rust README](../../swift-deploy-rs/bundle-rust/README.md) (P3-ops TLS)
- [CONTABO-CLUSTER.md](../CONTABO-CLUSTER.md)
- Evidence: `tools/test-results/p3-ops-20260804/`, `p3-ops-tls-live-20260805/`,
  `p3-ops-tls-status-20260806/`
