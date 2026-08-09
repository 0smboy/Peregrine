# Architecture

Peregrine is five cooperating programs. This document explains what each owns,
how they talk to each other, and the invariants that hold the system together.

## The design constraint: format fidelity

Swift's correctness lives in its formats: the ring, SQLite account and
container databases, diskfile layout, pickled hashes, crypto metadata, HMAC
signatures, and erasure-coded fragments. Peregrine treats each implemented
format as a compatibility contract and verifies specific paths with fixtures
from Python Swift. Those proofs do not imply complete fleet-wide
interchangeability; consult the strict parity matrix before any mixed rollout.

## The data plane — `swift-rust`

A 15-crate workspace mirroring Swift's module boundaries:

| Crate | Swift analogue | Holds |
|-------|----------------|-------|
| `swift-core` | `swift.common.*` | timestamps, ring hashing, storage-policy parsing, pickle, config, statsd/syslog/recon, fs + lock utilities, constraints |
| `swift-ring` | `swift.common.ring` | ring load/build, `get_nodes`, handoffs, per-policy rings |
| `swift-http` | `swob` + WSGI | swob primitives, a bounded threaded HTTP/1.1 server, streaming bodies, multipart-MIME, connection hijack |
| `swift-diskfile` | `swift.obj.diskfile` | the on-disk object format, DiskFile lifecycle, EC fragment naming, `hashes.pkl` |
| `swift-db` | `account`/`container` backends | SQLite backends, broker, sharding |
| `swift-account-server` | `swift.account.server` | account REST + REPLICATE + reaper |
| `swift-container-server` | `swift.container.server` | container REST + REPLICATE + sharding + sync + reconciler |
| `swift-object-server` | `swift.obj.server` | object REST, streaming PUT/GET, ssync, reconstructor, updater, auditor, expirer |
| `swift-proxy-server` | `swift.proxy.*` | node iteration, quorum, controllers, the EC controller |
| `swift-middleware` | `swift.common.middleware.*` | tempauth, copy, SLO/DLO, versioned_writes, symlink, staticweb, quotas, ratelimit, … |
| `swift-crypto` | crypto middleware | AES-256-CTR at rest, crypto-meta, HMAC etag |
| `swift-memcache` | `memcached` client | consistent-hash memcache client |
| `swift-s3api` | `s3api` middleware | S3 SigV4 + minimal CRUD/list gateway (P3-s3; ON-BY-CONFIG; not on Swift `/info`) |
| `swift-cli` | `swift-*` scripts | ring-builder, recon, get-nodes, info tools, shard-range mgmt, ring-sim |
| `swift-ec` | `pyeclib` / liberasurecode | the erasure-coding codec (Linux-only, `ec` feature) |

The path a request travels: **client → proxy → object/container/account
servers → container-update side channel → container server**. The proxy fans
out to real backend HTTP servers and selects a quorum best-response. Object
bodies stream end to end through 64 KB buffers, so a multi-GB PUT/GET does not
materialize in memory.

### Storage policies

- **Replication** (default): N replicas placed by the ring, kept whole by the
  object replicator (rsync / rsync-over-ssh) and the DB replicator.
- **Erasure coding** (`ec` feature, Linux): fragments byte-identical to
  PyECLib, a streaming multipart-MIME + multiphase-commit PUT, segment-wise
  decode on GET, ranged GET over the covered segment span, and a reconstructor
  that heals a lost fragment from its peers.

## The control plane — `swift-deploy-rs`

A bounded executor for the upstream Swift Ansible v3 plan, with no Python or
Ansible at runtime. It parses the inventory, host/group vars, and ring config;
expands plays, roles, includes, blocks, loops, handlers, `register`,
`delegate`, and `run_once` into a deterministic JSON plan; seals the plan with
SHA-256; and re-verifies the plan, bundle, inventory, and digests before
`apply`. Disk wipes, firewall changes, and SSH reconfiguration each require
separate authorization. It embeds its own web control console in the same
binary.

## The test plane — `cosbench-rs`, `autocos`, and the console Lab

- **`cosbench-rs`** is a Rust rewrite of Intel's COSBench core: workloads with
  sequential prepare / main / cleanup stages, mock / S3 / Swift drivers,
  Keystone v3 auth, hash-integrity verification, and JSON/CSV reports.
- **`autocos`** scripts the benchmark lifecycle over `cosbench-rs`: submit a
  workload, watch progress, list and collect and archive results, with state
  under `~/.autocos/`.
- **The console Lab** injects faults (fragment loss, node down) and runs
  read-back integrity checks against the live cluster.

## The console — `swift-console`

A single Rust binary that serves four surfaces over one authenticated session:

- **Files** — an S3-style browser: buckets/containers, objects, upload, trash
  with restore, TempURL, search, and bulk ZIP download.
- **Deploy** — a front end over `swift-deploy-rs`'s plan/validate/apply API.
- **Monitor** — live metrics proxied from Prometheus / Loki / statsd.
- **Lab** — chaos and verification tooling.

## Cross-component invariants

1. **Compatibility is evidence-scoped.** Only formats and paths covered by
   golden or live interop evidence are claimable as byte-compatible.
2. **No runtime Python.** Every component is a self-contained Rust binary.
3. **Sealed deploys.** A plan that changed after it was sealed does not apply.
4. **The oracle is Python.** Correctness claims are checked against the real
   Python implementation, not against Peregrine's own expectations.
