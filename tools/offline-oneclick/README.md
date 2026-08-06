# Offline one-click — Peregrine swift-rust + console

Air-gapped **pack → install → start → test** for a single-host SAIO lab (or
any host that already has conf/rings). Multi-node Contabo / HA production
continues to use `swift-deploy-rs`.

## One command (build host with toolchain)

```sh
cd /path/to/Peregrine
./tools/offline-oneclick/offline-oneclick.sh all-local --console
```

This builds release binaries, stages under `dist/offline-pack`, installs to
`~/.local/peregrine`, starts SAIO + console, runs smoke + func + lab probes.

## Airgap transfer

On a machine **with** Rust toolchain (same OS/arch as target):

```sh
./tools/offline-oneclick/offline-oneclick.sh pack --features ec
# → dist/offline-pack-peregrine-*.tar.gz
```

Copy the tarball to the offline host, then:

```sh
tar xzf offline-pack-peregrine-*.tar.gz
cd offline-pack   # or dist/offline-pack
sudo ./offline-oneclick.sh install --prefix /opt/peregrine --from .
source /opt/peregrine/env.sh
./offline-oneclick.sh start --console
./offline-oneclick.sh test --smoke --func --lab
./offline-oneclick.sh status
```

## Credentials (SAIO defaults)

| Item | Value |
|------|--------|
| Auth | `http://127.0.0.1:8080/auth/v1.0` |
| User | `test:tester` |
| Key | `testing` |
| Console | `http://127.0.0.1:9090` (if `--console`) |

## Production TLS PEM

This SAIO path serves **HTTP on `:8080`**. TLS is not terminated by the proxy.

### Operator one-shot (SAIO stage)

```sh
# Validate only (also accepts env SWIFT_TLS_PEM)
./tools/offline-oneclick/offline-oneclick.sh tls --pem /secure/lab.pem --check

# Stage under $PEREGRINE_PREFIX/etc/tls/server.pem (front with nginx/caddy)
./tools/offline-oneclick/offline-oneclick.sh tls --pem /secure/lab.pem
```

### Production VIP (HAProxy)

Contabo / multi-node VIP TLS uses HAProxy (`lb_mode=https`), not SAIO:

```sh
# Prefer the dedicated ops script
./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem --check
./tools/ops/apply-vip-tls-pem.sh --pem /secure/vip.pem \
  --ssh swift1,swift2,swift3,swift4 --reload   # only after SSH confirmation

# Or via offline-oneclick delegate
./tools/offline-oneclick/offline-oneclick.sh tls --vip -- \
  --pem /secure/vip.pem --ssh swift1 --dry-run --print-commands
```

Deploy-rs path: set `haproxy_tls_pem_src` (controller-local PEM) +
`haproxy_tls_self_signed: false` + `lb_mode: https`. See
[`tools/ops/README.md`](../ops/README.md) and
[`docs/fairness-lab/P3-OPS-CONTRACT.md`](../../docs/fairness-lab/P3-OPS-CONTRACT.md).

**No secrets in git.** Contabo is never mutated without explicit `--ssh` hosts.

## Commands

| Command | Purpose |
|---------|---------|
| `pack` | Release build + stage + tarball |
| `install` | Copy bins/scripts/conf to prefix |
| `start [--console]` | saio-setup + saio-start (+ console) |
| `stop` | Stop SAIO services + console |
| `test [--smoke\|--func\|--lab]` | Verification |
| `tls [--pem\|--check\|--vip]` | Validate/stage PEM or delegate VIP apply |
| `status` | Process + auth probe |
| `all-local` | Full local path |

## Honest limits

- Pack must be built on the **same OS family** as the target (Darwin vs Linux).
- Does not replace multi-node ring rebuild / Keystone / Galera.
- EC requires pack with `--features ec` **and** liberasurecode on the host.
