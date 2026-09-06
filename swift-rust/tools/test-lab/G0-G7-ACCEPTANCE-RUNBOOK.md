# G0–G7 acceptance runbook (single frozen candidate)

Run this on **Swift2 / Linux**. Do not compile or relay binaries through a
Mac. Do not touch production `:8080`, VIP `10.0.0.10`, HAProxy, Keepalived,
or `/srv` production mounts.

A package-green result on a laptop is **not** a gate GREEN.

## 0. Freeze one candidate

```bash
cd /path/to/Peregrine
git checkout cursor/g0-g7-acceptance-1ad4   # or the SHA you will accept
# Writes PENDING_FREEZE → HEAD in acceptance.yaml + acceptance.json.
# Idempotent for the same SHA. Refuses a different SHA. No production touch.
python3 swift-rust/tools/test-lab/freeze-candidate.py
# Preview only:
# python3 swift-rust/tools/test-lab/freeze-candidate.py --dry-run
```

The script prints the G0 in-repo checklist (`peregrine_git_sha`, both
acceptance sha256 values, `Cargo.lock` sha256, `rustc --version`,
worktree dirty count). Remaining G0 keys (`python_swift_git_sha`, live
`/proc/exe`, rings, …) stay **NOT RUN** until Swift2 fills
`TEST-PROVENANCE.json`. After this point do not edit `acceptance.yaml`
thresholds.

## 1. In-repo unit gates (can also run on this cloud VM)

```bash
cd swift-rust/tools/test-lab
./run_unittests.sh

cd /path/to/Peregrine/swift-rust
cargo test -p swift-runtime --lib storage
cargo test -p swift-http --lib from_channel_does_not_charge
cargo test -p swift-http --lib metered_incoming
cargo test -p swift-http --lib production_http_pumps_use_metered
cargo test -p swift-object-server --lib async_ssync_does_not_ack
cargo test -p swift-object-server --lib streaming_put_client_disconnect
cargo test -p swift-object-server --lib streaming_put_future_cancel
cargo test -p swift-runtime --lib submit_held
# Linux + liberasurecode only:
cargo test -p swift-proxy-server --test ec_integration --features ec
```

These are **package** results. They do not close G0–G7.

## 2. G0 provenance (Swift2)

Fill `TEST-PROVENANCE.json` using `swift-rust/tools/test-lab/provenance.py`
keys: git SHA, dirty/clean, lockfile SHA, rustc, features (`ec`), artifact
SHA, live `/proc/exe` SHA of the isolated rust binaries (not production
`/usr/local/bin/swift-proxy-server`).

Fail closed if any required key is missing.

## 3. G1 environment

Run `preflight.py` against the **isolated** G6 rust stack
(`/etc/g6-rust`, port `18080`). Production VIP present on a host is
allowed for G4/G5 canaries only when labelled; it **invalidates** G7/G8.

Required roles (historical four-node lab):

| Host | Role |
|---|---|
| swift1 `10.0.0.1` | isolated rust data-plane + recon |
| swift2 | compile / evidence / this runbook |
| swift3 | optional build cache |
| swift4 `10.0.0.4` | G7 loadgen |

## 4. G2 locked build

```bash
export CARGO_HOME=/root/work/peregrine-cargo-home
cd /root/work/Peregrine/swift-rust
cargo build --offline --locked --release --features ec
install -m 0755 target/release/swift-proxy-server   /root/work/g6-rust-bin/
install -m 0755 target/release/swift-object-server  /root/work/g6-rust-bin/
# …account/container + daemons used by the isolated stack
sha256sum /root/work/g6-rust-bin/swift-*
```

Start isolated listeners with
`swift-rust/tools/test-lab/g7/g7-start-rust.sh` (must not bind `:8080`).

## 5. G3 native async

Drive real PUT/GET (and required S3 routes) at the isolated proxy.
Collect `/recon/concurrency` **deltas** with
`swift-rust/tools/test-lab/g3_counters.py`.
`/recon/concurrency` HTTP 200 alone is not a pass.

## 6. G4 / G5 / G6

Replay the frozen official lists on `$CANDIDATE` only:

- G4: Swift `test/functional` identity list, exact-name diff vs Python
- G5: Swift `test/s3api` + pinned Ceph `s3-tests`
- G6: 147 replication + 32 EC identities, merge **once** into the 179
  ledger. Score with `python3 swift-rust/tools/test-lab/g6_ledger.py LEDGER.json`.
  No auto-retry-to-PASS. Leftover timeout children stay TIMEOUT/FAIL,
  never PASS. The scorer unit tests encode those holes; do not bypass them.

Do not import W068/W069/W070 hashes from `17adf0b`.

## 7. G7 physical matrix

```bash
export G7_OUT=/root/work/g7-out-$CANDIDATE
export G7_TARGET_SSH=root@10.0.0.1
# Optional injectors — omit => honest NOT RUN (gate stays RED)
export G7_SSYNC_HOST=127.0.0.2
export G7_SSYNC_PORT=16210
export G7_SSYNC_DEVICE=d1
export G7_EC_POLICY=Policy-1
python3 swift-rust/tools/test-lab/g7/g7-run.py matrix
```

`verdict.json` must be GREEN with **zero** FAIL / NOT RUN / ENVIRONMENT
BLOCKED. A NOT RUN injector is not a pass.

## 8. Stop conditions

- opened < target → ENVIRONMENT BLOCKED, never PASS
- missing fault_armed / fault_hits → FAIL or NOT RUN, never PASS
- production port in use by the candidate → abort
- any earlier gate RED → do not declare a later gate GREEN
