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

This SAIO path serves HTTP on `:8080`. For production VIP TLS:

1. Place fullchain+key PEM where HAProxy expects it.
2. Set `SWIFT_TLS_PEM=/path/to/pem` as documentation for operators.
3. Use `swift-deploy-rs` `lb_mode=https` + `haproxy_tls_pem_src` on Contabo.

## Commands

| Command | Purpose |
|---------|---------|
| `pack` | Release build + stage + tarball |
| `install` | Copy bins/scripts/conf to prefix |
| `start [--console]` | saio-setup + saio-start (+ console) |
| `stop` | Stop SAIO services + console |
| `test [--smoke\|--func\|--lab]` | Verification |
| `status` | Process + auth probe |
| `all-local` | Full local path |

## Honest limits

- Pack must be built on the **same OS family** as the target (Darwin vs Linux).
- Does not replace multi-node ring rebuild / Keystone / Galera.
- EC requires pack with `--features ec` **and** liberasurecode on the host.
