# Deploy — one-click Swift-in-Rust SAIO cluster

These scripts stand up a **4-node single-host** Swift cluster (SAIO
topology, both a 3x replication policy and an EC-4-2 erasure-coding
policy) from prebuilt binaries, with no compiler and no dependency
installs. They are shipped both here (version-controlled) and inside the
Google Drive bundle alongside the binaries and the liberasurecode
shared libraries.

## Fastest path — the prebuilt bundle

On a fresh **x86_64 Linux** box (Rocky 9 / AlmaLinux 9 / Debian, glibc
≥ 2.34), as root:

```sh
tar xzf swift-rust-bundle.tar.gz
cd swift-rust-bundle
sudo bash bootstrap.sh
```

That installs the EC libraries and binaries, builds the rings, starts the
cluster as a systemd service, and runs a smoke test. When it prints
`SMOKE: PASS` the cluster is live at `http://127.0.0.1:8080`.

The bundle directory contains: `bin/` (binaries), `lib/` (liberasurecode
`.so` family), the scripts below, `VERSION` (source commit + build date),
and this README.

## What runs

| | |
|---|---|
| Proxy | `http://127.0.0.1:8080` |
| Auth | tempauth — `test:tester` / `testing` (also `admin:admin`/`admin`) |
| Policies | `Policy-0` (3x replication, default), `EC-4-2` (erasure coding) |
| Nodes | 4 single-host nodes, `/srv/node{1..4}`, devices `sdb{1..8}` |
| Ports | object `60N0`, container `60N1`, account `60N2` (N=1..4) |
| Service | `swift-rust-saio.service` (systemd, keeps all 13 processes up) |
| Logs | `journalctl -u swift-rust-saio` and `/var/log/swift/*.log` |

## Scripts

| Script | Purpose |
|--------|---------|
| `bootstrap.sh` | the one-click entry: install libs+bins, setup, start, smoke |
| `saio-setup.sh` | (re)generate `/etc/swift` confs + rings |
| `saio-start.sh` | the systemd `ExecStart` supervisor (starts + reaps the 13 servers) |
| `smoke.sh` | end-to-end check: replication + EC PUT/GET/DELETE/range |
| `ec-heal-demo.sh` | delete an EC fragment; the reconstructor rebuilds and re-pushes it |
| `stop.sh` | stop the cluster (`--wipe` also clears data + rings) |

Common operations:

```sh
bash smoke.sh                 # re-run the smoke test
bash ec-heal-demo.sh          # watch EC self-heal
systemctl restart swift-rust-saio
bash stop.sh --wipe && sudo bash bootstrap.sh   # clean restart
```

A quick manual poke:

```sh
url_tok=$(curl -si -H 'X-Auth-User: test:tester' -H 'X-Auth-Key: testing' \
  http://127.0.0.1:8080/auth/v1.0)
TOK=$(echo "$url_tok" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r')
URL=$(echo "$url_tok" | awk 'tolower($1)=="x-storage-url:"{print $2}' | tr -d '\r')
curl -X PUT "$URL/mybox" -H "X-Auth-Token: $TOK"                 # container
echo hello | curl -T- "$URL/mybox/hi" -H "X-Auth-Token: $TOK"    # object
curl "$URL/mybox/hi" -H "X-Auth-Token: $TOK"                     # -> hello
```

## Building the bundle yourself

The binaries must be built on Linux with liberasurecode present (the `ec`
cargo feature is Linux-only). From a checkout of the repo:

```sh
cd rust
cargo build --release --features swift-proxy-server/ec,swift-object-server/ec
```

Then assemble a bundle directory:

```
swift-rust-bundle/
  bin/    <- rust/target/release/swift-*        (the binaries)
  lib/    <- /usr/lib64/liberasurecode*.so*  libnullcode*.so*  libXorcode*.so*
  bootstrap.sh saio-setup.sh saio-start.sh smoke.sh ec-heal-demo.sh stop.sh README.md
  VERSION <- "commit <sha>  built <date>"
```

`tar czf swift-rust-bundle.tar.gz swift-rust-bundle` and it is ready for
any matching-glibc box.

## Notes

- The SAIO device dirs are ordinary directories, not mounts
  (`mount_check = false`); `setenforce 0` is issued because SELinux
  relabelling of freshly-created object dirs is fine but a clean demo
  avoids it.
- `bootstrap.sh` is idempotent — re-running re-installs and restarts.
- This is a single-host SAIO for validation and demos. A real
  multi-machine deployment uses the same binaries with real rings and
  the replicators' rsync-over-ssh mode; see the repo `PLAN.md` and the
  project notes.
