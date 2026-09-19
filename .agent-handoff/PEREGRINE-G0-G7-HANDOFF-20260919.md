# Peregrine G0–G7 — current handoff

**Date:** 2026-09-19 (UTC)
**Supersedes:** the lab agent's Drive handoff `G5B-HANDOFF-9531eb62-20260915.md`
and `.agent-handoff/PEREGRINE-G0-G7-TAKEOVER-CHECK-20260918.md` (read the latter
only for its pre-access reasoning, which it marks as superseded).
**Target:** make G0–G7 all green.
**Status in one line:** G5-B is down to **1 unexpected identity and it is an
environment defect**, not a product one; **G4 and G7 have never been run** and
are now the largest untouched distance to the goal; the `9531eb62` tip line can
never satisfy G0.

Every number below names its evidence path. Nothing here upgrades a gate verdict.

---

## 1. What changed since 2026-09-15

The predecessor had parked the tip line as `tipable-exhausted`: 159 FAIL+ERROR on
the Ceph s3compat suite, read as "the owner's tip-ask NO walls make the residual
unreachable". That reading was wrong in an important way, and the correction is
the substance of this session.

| Step | Result | Evidence |
|---|---|---|
| Ran the Python Swift baseline the directive always required and nobody had run | 156 of the 159 fail on Python Swift too; the oracle itself fails 388 of the same 725 | `tools/test-results/g5b-oracle-diff-20260918/` |
| Exact-name diff | both-fail 156 · **rust-only 3** · python-only 231 · both-pass 253 · skipped-either 82 | same |
| Owner withdrew the "raw ~725 all green" override, took **option C** | G5 scored against a frozen known-failure policy, unexpected = 0 | `tools/g5-known-failures/`, `docs-site/src/content/docs/validation-gates.mdx` |
| Owner approved the lab `client_timeout` 600 → 60 | one identity closed for good | `tools/test-results/g5-score-20260918/` |
| Owner lifted the `BypassGovernanceRetention` wall; the dig found a designed invariant, not a bug | recorded as a divergence (**option A**), engine unchanged | `tools/test-results/g5-score-20260918/WALL-LIFT-OBJECT-LOCK-BYPASS.md` |
| Full 725 re-run under the new contract | **1 unexpected, environmental** | `tools/test-results/g5-score-20260919/` |
| First per-route G3 evidence ever collected | 12 route groups clean, `ssync` uncovered | `tools/test-results/g3-routes-20260918/` |

---

## 2. Gate board

| Gate | State | What actually closes it |
|---|---|---|
| **G0** | GREEN only for the G6 claim on `17adf0b`. **Impossible for the `9531eb62` tip line** | The tip's source tree is gone from the lab; the surviving tree matches only 76 of 270 files against the published commit by blob hash. Build the next candidate from a real commit in `0smboy/swift-rust` so the identity chain exists before any scoring. `tools/test-results/g5b-oracle-diff-20260918/SWIFT-RUST-PR1-REVIEW.md` |
| **G1** | **RED, and it gates G5-B** | Fix the lab container/account replication (§5). Three options with their cost to the G6 claim are in `tools/test-results/g5b-classify-20260918/LAB-FINDINGS.md` §2 |
| **G2** | GREEN for the G6 artifact only; **unproven between the Rust lab and the Python oracle** | Prove configuration-semantics parity between the two deployments. The 231 python-only results are the symptom. One concrete instance was already found and fixed: `client_timeout` 600 vs 60 |
| **G3** | Open, now with evidence | Cover `ssync` (object-server to object-server, no client can drive it) and re-run on a candidate that has a G0 identity. `tools/g3-route-probe.py` |
| **G4** | **NEVER RUN** | `tox -e func` / `func-ec` / `func-encryption` against a frozen `collected-tests.txt`, exact-name diff, unexpected = 0. No wall touches this |
| **G5** | NOT GREEN — 1 unexpected (environmental) | Fix G1, re-freeze the policy against the G0-pinned Python oracle commit `541a598…` instead of the swift2 deployment, prove G2 parity, and run **G5-A** (Swift in-tree `test/s3api`), which has never run on this tip |
| **G6** | GREEN on `17adf0b` (W068 + W069 + W070, 179/179) | Holds unless the candidate changes — and note any G1 repair touches the topology this was measured on |
| **G7** | **NEVER RUN / NOT ACCEPTED** | `swift-rust/tools/test-lab/g7/acceptance.yaml` scenarios: idle 10k/50k/100k, slow client, backpressure, fairness, cancellation, reload, shutdown, durability, fault injection, bounded memory. No wall touches this either |

**G0–G7 are not all green.** With G5-B reduced to one environmental identity,
the remaining work is concentrated in **G4, G7, G1 and G5-A**.

---

## 3. The G5 contract (option C) — how to score

The old override ("full ~725 all green before G0–G6") is withdrawn. It could not
be met by engine work: 156 of 159 failures are shared with the reference
implementation, so satisfying it literally would have required Rust to diverge
from Python Swift on 156 identities.

```bash
tools/g5-score.py RUN.xml \
  --policy       tools/g5-known-failures/g5b-ceph-s3compat-20260918.tsv \
  --divergences  tools/g5-known-failures/g5b-divergences-20260918.tsv
```

Three properties matter, and each is there on purpose:

1. **The policy is earned, not asserted.** An identity may be frozen
   expected-fail only if the Python oracle fails it too, or the harness cannot
   execute it. Generated by `tools/g5-freeze-known-failures.py`; never hand-edit.
2. **It is not a blanket excuse, and that is measured.** Scoring the Python
   baseline against this policy yields **231 unexpected**.
3. **Deliberate divergences are separate and visible.** Rust-only failures the
   engine chose on purpose live in the divergence file, are only counted with
   `--divergences`, and each entry must name its justifying document. Also run
   without the flag and report both numbers — that answers "what if we held
   ourselves to the suite exactly".

A frozen entry that starts passing is reported as a **stale entry and fails the
gate**, forcing a re-freeze. Re-freeze by re-running the pair, not by editing.

Policy contents: 238 entries — 82 expected-skip, 78 swift-family-gap, 40
harness-blocked, 38 not-applicable-rgw.

---

## 4. Current G5-B numbers

Full 725, tip `9531eb62` unchanged, `client_timeout = 60`, 2026-09-19
(`tools/test-results/g5-score-20260919/`):

```
passed 485 · expected 156 · accepted divergence 1 · unexpected 1
unexpected skip 0 · stale 0 · raw F+E 158
```

The one unexpected is `test_buckets_create_then_list`. Its `NameError` path is
reachable only when a just-created bucket is missing from ListBuckets:

| Run | Outcome |
|---|---|
| 2026-09-15 full 725 | fail |
| 2026-09-18, 10 isolated rounds × 5 buckets | pass |
| 2026-09-18 scoped 106-identity run | pass |
| 2026-09-19 full 725 | fail |

Fails under full-suite load, passes in isolation — the signature of §5. **No
engine change can close it.**

---

## 5. Lab state (facts a successor needs before touching anything)

### Topology on swift1

| Port | What it is | Notes |
|---|---|---|
| `:8080` | **production, Rust proxy** — `/usr/local/bin/swift-proxy-server`, ELF, sha256 `ab5cb95c…`, unit `Swift proxy server (rust)` | The 2026-09-15 Drive handoff called this "生产 Python" and that is **wrong**; the sha itself was always correct. Do not touch |
| `:18080` | lab tip, `/root/work/g6-rust-bin/swift-proxy-server` sha256 `9531eb62…` | Supervised by an overseer bash at `/etc/g6-rust/bin/swift-proxy-server` (pid 757796). Reload with `kill -USR1 757796`: it spawns a replacement from `SWIFT_RUST_BIN_DIR=/root/work/g6-rust-bin` with a bind/TCP readiness check, then drains the old worker. Never overwrite the overseer script |
| `:18082` | g6-internal | Still mapped to a `(deleted)` inode of the older `dd218530` tip. Bouncing it would move it to `9531eb62`; not done, still optional |
| `:8090` | Python Swift 2.38.0 oracle | **Running from a deleted virtualenv.** It answers requests but cannot be restarted and its code cannot be read. Do not restart it |

swift2/3/4 each run a network-reachable Python Swift **2.33.0** on `:8090`
(`/opt/pyswift-venv`, `location = us-east-1`). swift2 is the build/log node and
holds `/root/work/s3-tests-venv` (boto3 1.42.97 + nose) — the only place the
suite can run.

### The G1 defect

Every lab replicator push to `10.0.4.2:6201/6202` is refused: the lab rings carry
the **production** storage topology while the lab container/account servers bind
`127.0.0.1:16211/16212` with `devices = /srv/1/node`. Backlog **growing**: ≈15 900
`async_pending` entries across `/srv/{1,2,3}` on 2026-09-18, ≈**20 994** on
2026-09-19 after one more full suite run. It was also generating ~300 MiB/day
of identical syslog lines.

A direct small reproduction: an EC probe container whose object returns 404 while
`X-Container-Object-Count: 1`, so `DELETE` returns 409 forever. Two such
containers were left in place rather than force-fixed.

### Disk discipline

swift1 `/` is structurally tight: the lab rings `/srv/{1,2,3}` hold ~29 GiB **on
the root filesystem** (`/srv/node/d{1,2,3}` are separate production mounts).

- Logrotate had no `compress` and `rotate 4` weekly, i.e. four uncompressed
  ~2 GiB copies projected. Fixed (`compress`, `maxsize 200M`); original backed up
  to `/etc/logrotate.d/rsyslog.bak-20260918T053326Z`.
- A full 725 consumes ~3.5 GiB. Reclaim before running.
- Sanctioned reclaim: move object partitions older than a cutoff into
  `/srv/node/d1/reclaim-stash-<date>/lab-objects/...`, preserving paths. **Move
  the same partitions from all three devices**, otherwise the object replicator
  rebuilds them and re-consumes the space. 2026-09-19 moved 99 partitions
  (6.3 GiB): root 2.8 → 9.1 GiB, ended the run at 5.4 GiB. d1 has ~19 GiB left.
- Never touch `/srv/node/d{1,2,3}` production object data.

---

## 6. Access

Lab SSH is reachable from a cloud agent (port 22 open; only a key was ever
missing). One run from the owner's Mac provisions it:

```bash
bash tools/lab-agent-access-bootstrap.sh          # install + Drive handover
bash tools/lab-agent-access-bootstrap.sh --revoke # remove key + drop
```

It mints a dedicated ed25519 key commented `peregrine-cloud-agent-20260918`,
appends it to `root@swift1`/`root@swift2` `authorized_keys` (its only write),
pins host keys read off the nodes, proves the agent's exact dial path under
`StrictHostKeyChecking=yes`, prints a read-only plane snapshot, and hands the key
over through Drive folder `Peregrine-agent-access-20260918`
(`1HqCj1gZKPDe8nftoiVKLQnzXNRemXLeJ`) after matching a handshake token.

The tempauth key does **not** need handing over — read it on-node from
`/etc/g6-rust/proxy-server.conf` (lab) or `/etc/pyswift/proxy-server.conf`
(oracle). Never print it.

GitHub: `0smboy/swift-rust` is private. The 2026-09-18 fine-grained PAT is
**read-only for Contents** (`POST /git/blobs` → 403) and lacks Checks, so it can
read PRs and trees but cannot push and cannot see CI. See §7.

---

## 7. Open items awaiting the owner

| # | Item | Why it is blocked |
|---|---|---|
| 1 | **G1 repair** | All three options touch the topology the G6 GREEN claim was measured on. Decide what happens to that claim first. `LAB-FINDINGS.md` §2. This is the only thing between G5-B and 0 unexpected |
| 2 | **Push the PR #1 strip** | Prepared and verified: amended commit `e5752da` (was `94e401b6`), `rust/` blobs 465 → 395, diff is exactly 70 removals all matching `.bak-`, 0 added, 0 content changes. Needs **Contents: Write** on the token, or run the recorded `--force-with-lease` command locally. Adding **Checks: Read** would also let CI be confirmed before merge |
| 3 | **Option B** (owner-implicit governance bypass) | Optional. Would align with AWS/RGW/Python Swift and remove the accepted divergence; needs the owner predicate plumbed into `governance_bypass_context` and both pinned tests replaced. Land it on a candidate with a G0 identity, and delete the divergence entry in the same commit |
| 4 | Bounce `:18082` | Still on a `(deleted)` `dd218530` inode. Cosmetic unless something scores against it |

---

## 8. Tooling added this session

| Path | Purpose |
|---|---|
| `tools/g5-freeze-known-failures.py` | Generate the G5 known-failure policy from a paired Rust + Python run |
| `tools/g5-score.py` | Score a run by exact name: unexpected failures, unexpected skips and stale entries all fail |
| `tools/g5b-classify.py` | Re-attribute a census by root-cause signature (harness / swift-vs-rgw / engine) |
| `tools/g5b-oracle-diff.py` | Exact-name diff of a Rust census against a Python baseline |
| `tools/g3-route-probe.py` | Drive one real request per G3 route and record `/recon/concurrency` deltas; refuses to score a route whose request was rejected |
| `tools/s3-probe-sigv4.py` | Dependency-free SigV4 probe for one narrow question at a time (the lab nodes have no boto3) |
| `tools/g5b-rustonly-characterize.py` | Characterize the two non-wall rust-only identities |
| `tools/lab-agent-access-bootstrap.sh` | Provision/revoke cloud-agent lab access |

Evidence directories: `tools/test-results/g5b-classify-20260918/`,
`g5b-oracle-diff-20260918/`, `g3-routes-20260918/`, `g5-score-20260918/`,
`g5-score-20260919/`.

Lab-side evidence: `swift2:/root/work/peregrine-g0g7-logs/` —
`G5B-live-9531eb62/` (the 09-15 census), `G5B-pybaseline-20260918/`,
`G5B-headers-regress-clienttimeout60-20260918/`,
`G5B-full725-clienttimeout60-20260919/`.

---

## 9. Traps that have already misled people

1. **Raw PASS counts on the Ceph suite mean nothing on their own.** The suite
   asserts RGW behavior. Always diff against the Python oracle by exact name.
2. **Theme bins mislead.** `sts34` contains zero engine evidence (the config has
   no `[iam]`/`[webidentity]` section, so those abort before signing).
   `select29` never reaches S3 Select — every test hardcodes
   `bucket_name = "test"` and aborts in setup because same-owner re-create
   answers 409 on **both** Swift implementations.
3. **A route probe that only checks counters will pass a rejected request.** An
   earlier revision scored a mis-signed `403` MPU as PASS. Require a 2xx.
4. **Measure past the timeout before calling something a hang.** A 20 s wait
   "proved" a hang that was a 60 s vs 600 s `client_timeout` difference.
5. **Swift answers `Etag`, AWS answers `ETag`.** Case-sensitive header lookups
   silently break MPU completion.
6. **`/etc/pyswift/` on swift1 is not production.** Production is
   `/etc/swift/proxy-server.conf` on `:8080`, and it is the Rust binary.
7. **PR #1 carries 70 `.bak-*` scratch files** (28 copies of `iam.rs`, 19 of
   `middleware.rs`). It also *removes* seven stale `test-results/*.log` files,
   which is fine — an earlier draft of the review had that backwards.
8. **Rust is more lenient than Python Swift in two places**: it accepts an empty
   SigV4 credential-scope region and an empty `version-id-marker`. The first is
   why no Python baseline had ever been collected — the harness signs with the
   region from the environment, and only Rust tolerated its absence.

---

## 10. Suggested next actions, in order

1. **Decide the G1 repair** (§7 item 1). It closes the last G5-B unexpected and
   unblocks honest G4/G5 scoring, since the directive requires G1 first.
2. **Start G7.** It has never run, no wall touches it, and the harness is in-tree
   (`swift-rust/tools/test-lab/g7/`). It needs a build on swift2 and disk
   headroom; expect the `client_timeout` and bounded-resource scenarios to be
   informative given what §9 item 4 uncovered.
3. **Start G4.** Also never run, also unwalled: `tox -e func` family against a
   frozen collection list.
4. **Run G5-A** (`test/s3api`) on whatever candidate is current.
5. **Stand up a G0-capable candidate**: build from a real commit in
   `0smboy/swift-rust`, record the manifest at build time, and keep the source
   tree. The `9531eb62` line cannot be rescued.

---

## 11. Hard constraints (unchanged, carried forward)

- No G8, no C_FINAL, no production promotion.
- Do not touch prod `:8080`, do not TERM it, do not overwrite the overseer
  script, do not restart swift1's `:8090` oracle.
- Never wipe or reformat `/srv/node/d{1,2,3}`; no second Keepalived; no secrets
  or jars committed.
- No tip build/deploy with less than 3 GiB free on swift1 `/`.
- KEEP: remint · prod `:8080` · overseer · g6-internal config · live tip
  `9531eb62` · `bak-pre-h82-5fd37900` · `bak-pre-h89-dd218530` ·
  `reclaim-stash-*` (including the new `reclaim-stash-20260919`).
- Docs discipline: one commit updates every surface that states a fact; run
  `tools/docs-claim-audit.sh` (exit 0) and rebuild the docs site before claiming
  docs are done.
