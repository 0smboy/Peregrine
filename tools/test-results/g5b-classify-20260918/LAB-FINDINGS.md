# Lab findings from the 2026-09-18 takeover session (swift1 / swift2)

Read-only reconnaissance plus one bounded disk reclaim. Prod `:8080`, the live
tip binary, `/srv/node/d{1,2,3}`, the overseer, remint, and the g6-internal
config were not touched.

## 1. Prod `:8080` runs the Rust proxy, not Python

| Fact | Value |
|---|---|
| pid on `:8080` | 3114191, `ExecStart=/usr/local/bin/swift-proxy-server /etc/swift/proxy-server.conf` |
| unit description | `Swift proxy server (rust)` |
| binary | ELF 64-bit executable, sha256 `ab5cb95c5c3973db8336e4940711fba18ce3cabaae62e13da0865c07ad31622b` |
| Python deployments | pyswift `:8090` — Swift 2.38.0 on swift1 (loopback only), 2.33.0 on swift2/3/4 (network) |

The sha matches every published claim, so nothing has drifted; only the
implementation label in the predecessor's Drive handoff ("生产 Python
`ab5cb95c`") is wrong. The repo's `docs/fairness-lab/HANDOFF-20260822-ENV.md`
already recorded this correctly.

## 2. The lab Rust cluster's container/account replication is broken (G1)

`/var/log/messages` was **99.9 % one repeated line**:

```
db-replicator: container push to 10.0.4.2:6201 failed: database connection
error: connect 10.0.4.2:6201: Connection refused (os error 111)
```

8478 container-push failures and 116 account-push failures in the last 20 000
lines, continuously since the file was created on 2026-09-15 01:23 UTC.

Cause: the lab `g6-rust` rings place container/account replicas on
`10.0.4.2:6201/6202` (the production storage topology), while the lab's own
container/account servers bind `127.0.0.1:16211/16212` with
`devices = /srv/1/node`. Nothing listens where the ring points, so every push
retries forever.

Consequences:

- **Consistency.** `async_pending` backlog on the lab devices: `/srv/1` 5442,
  `/srv/2` 5638, `/srv/3` 4809 files — roughly 15 900 deferred container
  updates. Listing-dependent and atomicity-dependent identities can fail or
  flake for environment reasons, which is the most likely explanation for the
  4 `BucketNotEmpty`-on-PutObject records and plausibly for the
  `test_versioned_concurrent_object_create_and_remove` flake.
- **Gate order.** The G0–G8 directive requires G1 (suitable, isolated
  environment) before G4/G5 scoring is meaningful. A cluster whose container
  replication never succeeds does not meet that, so the 159 F+E should not be
  read as a pure product measurement until this is fixed or explicitly scoped.

Not fixed here: correcting the ring or the replicator's peer set changes lab
replication semantics, which is exactly what G6 scored. That needs an owner
decision, not a unilateral edit.

## 3. Disk: reclaimed 1.7 GiB and closed a latent disk-full

swift1 `/` was at **1.7 GiB free (96 %)**, below the 3 GiB tip/deploy floor,
and `/var/log/messages` was growing **~300 MiB/day** from the loop above.
`logrotate.conf` had `weekly`, `rotate 4`, and **no** `compress`, so the
projected steady state was four uncompressed ~2 GiB copies on a 40 GiB disk.

Actions (reversible; original config backed up to
`/etc/logrotate.d/rsyslog.bak-20260918T053326Z`):

1. Added `compress`, `maxsize 200M`, `rotate 4` to the rsyslog stanza.
2. Forced one rotation and compressed the rotated file: 1 189 815 131 B →
   32 617 665 B (36:1, consistent with a single repeated line).
3. `journalctl --rotate && journalctl --vacuum-size=150M`, freeing 56 MiB.

Result: **3.2 GiB free (93 %)**, above the floor. `/srv/node/d{1,2,3}` were not
touched. Note that the root filesystem also carries the lab rings
`/srv/1`, `/srv/2`, `/srv/3` (≈32 GiB), which is the structural reason this
host runs close to full.

## 4. swift1's Python oracle is running from a deleted virtualenv

The process serving swift1 `127.0.0.1:8090` was started from
`/root/work/pyswift-venv/bin/python3`, but that path no longer exists — an
earlier reclaim moved it. The service keeps running from unlinked files, so it
answers requests but **cannot be restarted** and its code cannot be inspected.
Do not restart it; if a Python oracle on swift1 is needed later, restore the
venv from a `reclaim-stash-*` first. This is why the 2026-09-18 baseline run
uses swift2's intact Python Swift instead.

## 5. Two Rust leniency divergences found while wiring the oracle

Both are engine-side and neither is inside a tip-ask NO wall:

| Request | Rust tip `9531eb62` | Python Swift s3api |
|---|---|---|
| SigV4 with an **empty** credential-scope region | accepted | `400 AuthorizationHeaderMalformed` |
| `ListObjectVersions` with empty `version-id-marker=` | accepted | `400 InvalidArgument: Invalid version id specified` |

The first explains why nobody had produced a Python baseline before: the
harness's `get_sts_client`/`get_iam_client` pass `region_name=''`, and the main
`get_client()` takes its region from the environment. The Rust engine's
tolerance let the census run without ever setting a region, while Python Swift
rejects it. Rust being *more* permissive than both Python Swift and AWS here is
a compatibility gap in the opposite direction from the census failures.

## 6. A small direct reproduction of §2, plus this session's residue

Cleaning up the G3 probe left two EC containers that will not delete:

```
DELETE /v1/AUTH_test/g3probe-ec-0b5c3a95/o  -> 404   (object is gone)
HEAD   /v1/AUTH_test/g3probe-ec-0b5c3a95    -> X-Container-Object-Count: 1
DELETE /v1/AUTH_test/g3probe-ec-0b5c3a95    -> 409   (not empty)
```

The container DB still carries a row for an object that no longer exists, so
the container is undeletable — the container layer and the object layer
disagree. A healthy cluster reconciles this through the container updater; with
~15 900 `async_pending` entries it is not reconciling. The second container
(`g3probe-ec-f3838ac4`) was in fact deleted but still appeared in the account
listing, which is the same lag from the account side.

Both are a few hundred bytes and were left in place: forcing container DBs back
into agreement is not something to do unilaterally on the cluster whose
replication semantics G6 scored.

Residue from this session, deliberately left:

| Where | What | Note |
|---|---|---|
| swift1 lab tip | 2 × `g3probe-ec-*` containers | undeletable per above; ≈526 B |
| swift1 | `/root/work/peregrine-probe-20260918/` | probe scripts and results |
| swift2 Python oracle | `pybase20260918-*` buckets from the baseline run | `/srv/node/d1` is at 10 % used with 46 GiB free, so no pressure; the suite's own teardown could not remove them because Python Swift rejects the empty `version-id-marker` the harness sends |
| swift1 | `/var/log/messages.1.gz` (32.6 MB) | the compressed replication-error log, kept as evidence |

19 other probe buckets were created and removed during the session.

## Evidence

- `PREFLIGHT-9531eb62.txt`, `SUMMARY-9531eb62.json`, `fail_error_names-9531eb62.txt`
  copied from `swift2:/root/work/peregrine-g0g7-logs/G5B-live-9531eb62/`
- Python baseline run: `swift2:/root/work/peregrine-g0g7-logs/G5B-pybaseline-20260918/`
  (`RUNINFO.txt`, `pybaseline.xml`, `run.log`), launched 2026-09-18T05:40:03Z
- Probe: `tools/s3-probe-sigv4.py`, run on swift1 and swift2
