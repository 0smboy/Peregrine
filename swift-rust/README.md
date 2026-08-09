# Swift-in-Rust

A ground-up rewrite of [OpenStack Swift](https://github.com/openstack/swift)
in Rust, built toward a **strangler** migration model. Compatibility is
claimed only for implemented formats and paths covered by golden or live
interop evidence. This is not yet a feature-complete Swift twin or a safe
drop-in replacement for an arbitrary production node. Python Swift remains
the parity oracle for the scoped fixtures and tests.

- **Status:** advanced lab implementation with strong core data paths and
  unresolved production, cross-node, and runtime-integration gaps. See the
  [strict matrix](../docs/fairness-lab/RUST-VS-PYTHON-PARITY.md).
- **Workspace:** 15 crates, including the Linux-only `swift-ec` codec, with
  unit, probe, functional, interop, and heal evidence of varying scope.
- **One-click deploy:** a prebuilt bundle (binaries + liberasurecode +
  scripts) stands up a full 4-node EC cluster on a fresh Linux box with a
  single command for SAIO/lab use. See
  [Deploy](#deploy-one-click) and [`deploy/`](deploy).

---

## Why

Swift's correctness lives in its formats — the ring, the SQLite account
and container databases, the diskfile layout, pickled hashes, crypto
metadata, HMAC signatures, and erasure-coded fragment archives. If a
rewrite reproduces those exactly, it interoperates with the existing
fleet and can be rolled out node-by-node instead of as a big-bang
replacement. That is the whole design constraint: **format fidelity over
everything**, proven by cross-checking against Python.

## Architecture

The workspace is a set of focused crates that mirror Swift's module
boundaries:

| Crate | Swift analogue | What it holds |
|-------|----------------|---------------|
| `swift-core` | `swift.common.*` | timestamps, ring hashing, storage-policy parsing, pickle, config, statsd/syslog/recon, fs + lock utilities |
| `swift-ring` | `swift.common.ring` | ring load/build, `get_nodes`, handoffs, per-policy rings |
| `swift-http` | `swift.common.swob` + WSGI | swob primitives, a bounded threaded HTTP/1.1 server, **streaming bodies**, multipart-MIME parsing, connection hijack |
| `swift-diskfile` | `swift.obj.diskfile` | the on-disk object format, DiskFile lifecycle, EC fragment naming, hashes.pkl |
| `swift-db` | `swift.account/container.backend` | account + container SQLite backends, broker, sharding |
| `swift-account-server` | `swift.account.server` | account REST + REPLICATE |
| `swift-container-server` | `swift.container.server` | container REST + REPLICATE + sharding paths |
| `swift-object-server` | `swift.obj.server` | object REST, streaming PUT/GET, ssync receiver + sender, reconstructor |
| `swift-proxy-server` | `swift.proxy.*` | node iteration, quorum, account/container/object controllers, EC controller |
| `swift-middleware` | `swift.common.middleware.*` | the pipeline: tempauth, copy, SLO/DLO, versioned_writes, symlink, staticweb, listings, quotas, … |
| `swift-crypto` | `swift.common.middleware.crypto` | crypto-meta, HMAC etag |
| `swift-memcache` | `swift.common.memcached` | memcache client |
| `swift-s3api` | `swift.common.middleware.s3api` | S3 request parsing, SigV4 |
| `swift-cli` | `swift-*` scripts | ring-builder, recon, get-nodes, *-info, shard-range mgmt, db-replicator |
| `swift-ec` | `pyeclib` / liberasurecode | the erasure-coding codec (Linux-only, `ec` feature) |

The data path works end to end: **client → Rust proxy → Rust object
server → container-update side channel → Rust container server**, and the
proxy fans out to real backend HTTP servers with quorum best-response
selection.

## Status

The entries below describe implemented surfaces. Each claim is limited to its
stated test level; library or unit coverage alone is not a deployable-path
claim. The strict matrix is authoritative when this file and older ledgers
differ.

**Core (formats + data path)**
- swob/HTTP, ring, diskfile, account/container SQLite backends, all four
  servers, the proxy with per-policy object rings, and the middleware
  pipeline, with scoped golden and live compatibility evidence.
- Container sharding end to end (cleave state machine, shard-range
  merge/get, sharder daemon).

**Daemons**
- Object + DB replicators (suffix-hash push, handoff revert, rsync and
  rsync-over-ssh, staged DB rsync with `complete_rsync` / `rsync_then_merge`).
- Object updater, container updater, expirer, account reaper,
  container-sync, reconciler, relinker, recon, drive-audit, auditors.

**Erasure coding** (`ec` feature, Linux — fragments byte-identical to PyECLib)
- Streaming EC PUT via the **real multipart-MIME + multiphase-commit
  backend protocol** (footers carry the whole-object etag/length; the
  two-phase commit makes fragments durable only after quorum acks).
- Streaming EC GET: segment-wise decode from `ndata` fragment sources.
- **Ranged EC GET**: only the covered segment span is fetched and
  decoded; multi-range streams multipart/byteranges.
- **EC ssync**: full-duplex fragment transfer — duplex receiver, sender,
  reconstructor SYNC/REVERT jobs, rebuild-on-the-fly at the receiver's
  index, REPLICATE-scoped suffix comparison, and Python-compatible
  partition locks.
- The reconstructor **heals a lost fragment**: delete a node's fragment,
  run the reconstructor, and a partner rebuilds it from the erasure code
  and pushes it back — proven live.

**Streaming data path** (the P1 audit blocker)
- Request/response bodies stream end to end through 64KB buffers; a 5GB
  PUT/GET no longer materializes the object in memory. Measured: a 1GB
  object through the cluster moves with a **~8–12 MB** peak-RSS delta
  across all servers (was multi-GB). Lazy `Expect: 100-continue`, a
  slowloris head-deadline, streamed SLO/DLO segment assembly, and a
  connect-then-tee proxy PUT.

**Ops readiness** (P2)
- RFC3164 syslog logging, statsd, recon cache, graceful SIGTERM drain,
  live ring hot-reload, fallocate_reserve enforcement, conf-driven
  timeouts/workers/pipeline.

**Cross-stack interoperability — proven live (the strangler claim)**
- EC PUT: Rust proxy → Python object servers, and Python proxy → Rust
  object servers, over the same devices — durable fragments, matching
  md5, container-update overrides flowing across the boundary.
- SSYNC: Python's own `ssync_sender` → Rust duplex receiver (fragment
  lands durable); Rust reconstructor revert → Python receiver (fragment
  moves cross-stack, local copy deleted).

**Not yet done:** production go-live, whole-fleet cutover soak, operator TLS
trust completion, KMIP, full cross-node auto-shrink semantics, arbitrary Paste
plugin loading, runtime wiring for the new IAM/cold-tier libraries, and full
eventlet-equivalent scheduling. See the strict parity matrix for the current
boundary.

## Build

Two profiles: the **default** build (no erasure coding — builds anywhere,
including macOS) and the **`ec`** build (adds the liberasurecode codec —
Linux only).

```sh
cd swift-rust

# default build + full test suite (no EC)
cargo build --release
cargo test --workspace --exclude swift-ec      # swift-ec needs liberasurecode
cargo clippy --workspace --exclude swift-ec --all-targets

# EC build (Linux, with liberasurecode installed — see deploy/)
cargo build --release --features swift-proxy-server/ec,swift-object-server/ec
cargo test  -p swift-proxy-server -p swift-object-server -p swift-ec \
            --features swift-proxy-server/ec,swift-object-server/ec
```

The `ec` feature links `liberasurecode` (+ `liberasurecode_rs_vand`,
`libnullcode`, `libXorcode`). On a box without them, build/run the
default profile, or install the prebuilt `.so`s from the deploy bundle.
`rusqlite` is statically bundled, so the binaries are portable across
same-or-newer-glibc Linux hosts (built against glibc 2.34).

### Two-host workflow (macOS dev + Linux EC)

macOS cannot link liberasurecode. The working pattern: edit locally,
`rsync` to a Linux box, build/test the `ec` feature there, and fetch the
commits back. All infra details are in the deploy notes and the project
memory.

## Test

| Layer | Command / script | Proves |
|-------|------------------|--------|
| Unit + golden | `cargo test --workspace --exclude swift-ec` | format fidelity vs Python fixtures |
| EC unit + e2e | `cargo test … --features …/ec` | codec + EC controller, multi-node PUT/GET/loss |
| Probe | Python `test/probe/*` against the Rust cluster | replication, handoff, metadata sync |
| Functional | Python `test/functional/test_{account,container,object}.py` | client-facing behavior |
| Interop oracle | `deploy/`-style scripts, both stacks on one device tree | cross-stack EC PUT + ssync |
| Large-object RSS | 1GB PUT/GET while sampling VmRSS | flat memory (streaming) |
| EC heal | `deploy/ec-heal-demo.sh` | reconstructor rebuilds a lost fragment |

## Deploy (one-click)

The [`deploy/`](deploy) directory holds a self-contained bootstrap that
stands up a **4-node single-host EC cluster** (SAIO-style) on a fresh
Linux box. The prebuilt bundle on Google Drive contains the EC binaries,
the liberasurecode `.so` family, and these scripts, so a new machine
needs **no build and no dependency install**:

```sh
# on a fresh Rocky 9 / AlmaLinux 9 / Debian x86_64 box, as root:
tar xzf swift-rust-bundle.tar.gz
cd swift-rust-bundle
sudo bash bootstrap.sh          # installs libs+bins, builds rings, starts the
                                # cluster as a systemd service, runs a smoke test
```

`bootstrap.sh` is idempotent and finishes by printing the cluster
endpoints and a green smoke result (replication PUT/GET + EC PUT/GET).
After it runs:

```sh
bash smoke.sh          # re-run the end-to-end check
bash ec-heal-demo.sh   # delete an EC fragment and watch the reconstructor heal it
systemctl status swift-rust-saio    # the cluster service
```

See [`deploy/README.md`](deploy/README.md) for the topology, ports,
auth (`test:tester` / `testing`), and how to point it at the source repo
to rebuild from scratch.

## Layout

```
swift-rust/
  crates/            the 15 workspace crates (see Architecture)
  deploy/            one-click bootstrap + SAIO scripts + service unit
  PLAN.md            the canonical dated status ledger
  HANDOFF.md         resumable working notes
  STREAMING_CONTRACT.md   the pinned streaming-body API contract
  README.md          this file
```

## License

Apache-2.0, matching upstream OpenStack Swift.
