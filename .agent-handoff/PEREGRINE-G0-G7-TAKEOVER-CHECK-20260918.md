# Peregrine G0–G7 takeover check (cloud agent)

Date: 2026-09-18 (UTC)  
Predecessor: lab agent `swift-master` (grok bot), last nudge 2026-09-15 ~20:08
("G5-B still parked tipable-exhausted @ 9531eb62 — 484 / F+E 159 unchanged;
PR #1 OPEN/MERGEABLE; plane tip MATCH; walls tip-ask NO until you lift. Not
G0–G7 green.")  
Successor: Cursor cloud agent on the Peregrine repo (no lab SSH, no
`swift-rust` repo access — see "Reach" below)  
Target: G0–G7 all green  
Verdict of this check: **G0–G7 are NOT all green, and the residual is not a
work backlog the lab agent can drain under the current owner policy.**

## 1. What was re-verified (three-way)

| Claim | Repo source | Live site | Evidence packet |
|---|---|---|---|
| G5-B census PASS=484 FAIL=47 ERROR=112 SKIP=83 F+E=159 conn=0 total=726 | `docs-site/src/content/docs/status-2026-09-15.mdx` | `https://peregrine-docs-ochre.vercel.app/status-2026-09-15/` (tokens present, 2026-09-18) | Drive `1MfW5eiLRwqYsflVIGZIok4hmhAU6fjJZ` → `g6-g5b-live-9531eb62-RESULT.txt` (harvest END 2026-09-15T00:58:55Z, `EXIT=1`) |
| Tip sha256 `9531eb621ee86c15dac050d883b68f097f775c67198947506ffc7dab806794e8` | same | same | same + `G5B-HANDOFF-9531eb62-20260915.md` §2.1 |
| Prod `:8080` untouched on `ab5cb95c…` | same | same | RESULT "prod :8080=200 UNTOUCHED"; verified on-node 2026-09-18 (see note below) |
| Theme bins sts34 select29 encrypt23 header14 other13 object_lock13 lifecycle9 policy8 append3 version3 atomic3 logging2 usage2 acl1 multipart1 tag1 | added to `status-2026-09-15.mdx` in this handoff | pending deploy | RESULT theme-bins line |
| G6 GREEN on `17adf0b`; G7 NOT ACCEPTED; G3 open; G4/G5 historical only | `status-2026-08-31.mdx`, `PEREGRINE-G6-GREEN-RELEASE-20260901.md` | `/status-2026-08-31/` | Swift1 `/var/log/g6-ec/`, Drive `Peregrine-G6-green-20260831-7883bbb/` |

All numbers agree. No claim was upgraded.

One label in the predecessor's Drive handoff is wrong and must not be copied
forward: it calls prod `:8080` "生产 Python `ab5cb95c`". On-node on 2026-09-18,
`:8080` is served by pid 3114191 = `/usr/local/bin/swift-proxy-server`, an ELF
executable whose sha256 is exactly `ab5cb95c5c3973db8336e4940711fba18ce3cabaae62e13da0865c07ad31622b`,
and its unit is `Description=Swift proxy server (rust)`. So prod `:8080` runs
the **Rust** proxy at that sha, which is what the repo's own
`docs/fairness-lab/HANDOFF-20260822-ENV.md` has said all along ("生产
`/usr/local/bin/swift-proxy-server`"). The Python deployments are the separate
pyswift ones on `:8090` (Python Swift 2.38.0 on swift1, loopback-only; 2.33.0
on swift2/3/4, network-reachable). The sha itself was never in doubt; only the
implementation label was.

Docs defect found and fixed in this handoff: `releases.mdx` aside had a stray
`[` ("[dated 2026-09-15; prior 2026-08-31") rendered literally on the live
page and conflated the 2026-09-15 lab snapshot with the accepted 2026-08-31
board. Rewritten to keep the two snapshots distinct.

## 2. Gate board for the G0–G7 target

| Gate | State | Why it is not green / what closes it |
|---|---|---|
| G0 | GREEN only for the G6 claim on `17adf0b` | Lab tip `9531eb62` has no git identity (lab tree `/root/work/src-60dd0f6/swift-rust` has no `.git`; source shipped as tarball release + PR branch `lab/tip-9531eb62-h89`). A G0 manifest for the tip line requires the tip tree to be a real clone/commit (handoff option F). |
| G1 | GREEN for the isolated G6 run | Re-run preflight for whichever candidate is scored next. |
| G2 | GREEN for the G6 artifact | Same as G1. |
| G3 | Open | Route matrix + `/recon/concurrency` counter deltas per required route (`swift-rust/tools/test-lab/g3_counters.py`, `s3_g3_live_probe.py`). Not accepted on any candidate (`status-2026-08-31.mdx`: "route matrix / runtime evidence still required"). |
| G4 | Historical only | `tox -e func` / `func-ec` / `func-encryption` on a frozen `collected-tests.txt`, full-name diff, unexpected = 0. No current-candidate acceptance record on `17adf0b`; no record on `9531eb62` in the 2026-09-15 packet. |
| G5 | **NOT GREEN** | G5-A (`test/s3api`): no record on the tip in the 2026-09-15 packet. G5-B: 159 F+E, see §3. |
| G6 | GREEN on `17adf0b` | Would need a rerun only if the accepted candidate changes (the tip line `9531eb62` is a different tree). |
| G7 | NOT ACCEPTED | `swift-rust/tools/test-lab/g7/acceptance.yaml` scenarios (idle 10k/50k/100k, slow client, backpressure, reload, shutdown, fault injection) never scored. |

The lab agent's loop was G5-B-only. Even a green G5-B leaves G3, G4, G5-A and
G7 open and G0 unscored for the tip line.

## 3. Superseded later the same day: the 159 were re-attributed

Sections 3 and 4 below were written before lab access arrived. They argue from
the census theme bins, which turned out to be misleading. Once the mandated
Python baseline was actually run
(`tools/test-results/g5b-oracle-diff-20260918/`), the exact-name diff came out
**156 both-fail, 3 rust-only, 231 python-only**, and characterizing the three
left **one** genuine Rust product gap (object-lock governance bypass, inside a
wall), one configuration difference (G2: lab `client_timeout = 600` vs the
oracle's 60s default — both answer `400 RequestTimeout`, just at their own
timeout), and one transient consistent with the degraded lab replication (G1).

The conclusion in §4 still holds and is in fact stronger: the "raw ~725 all
green" bar cannot be met by engine work, because 156 of the 159 failures are
shared with the reference implementation, which itself fails 388 of the same
725. What changes is the reason — not "the walls hide too much work" but "the
bar measures the wrong thing". Option C is now the evidence-backed choice.

Read §5 (reach), §6 (constraints) and the two evidence directories as current;
read §3 and §4 as the pre-access reasoning.

## 3a. Pre-access reasoning: why G5-B cannot reach 0 F+E under current policy

Owner override (2026-09-15): full Ceph s3compat ~725 must be all green before
G0–G6 are accepted. Owner walls (tip-ask NO, declined to lift twice): `sts`,
`select`, `encrypt`, `Restrict`, `BypassGovernanceRetention`, lifecycle
timing/count, header harness, AQPE→403, ctime, concurrent, Condition, UA/SDM
`create_bad`, policy IfExists/tenant/IAM.

From the RESULT theme bins: sts 34 + select 29 + encrypt 23 = **86** of 159
are entirely inside walls; header 14, lifecycle 9, policy 8 and most of
object_lock 13 are also wall-owned (~117 of 159). What remains outside walls is
`other` 13 (unbinned), append/version/atomic 3/3/3 (one is a known flake),
logging/usage 2/2, acl/multipart/tag 1/1/1, and the H90 soft leftover
(`unicode_metadata` `.decode` harness; PutObjectTagging after
PutObject-with-lock wiping the `.meta` lock).

So the two owner rules contradict each other: "all ~725 green" and "do not
touch sts/select/encrypt". The canonical G5 contract in
`docs-site/src/content/docs/validation-gates.mdx` (line 28) is
"capability/known-failure policy, exact-name diff, unexpected test names = 0",
which is satisfiable; "raw PASS on all ~725" is not, because the walls include
whole unimplemented capabilities (STS AssumeRole, S3 Select SQL engine,
SSE-C/KMS).

## 4. Decision required from the owner (pick one, in writing)

> Updated 2026-09-18 after the oracle diff: option C is the evidence-backed
> choice, and option B would mean deliberately diverging from Python Swift on
> identities the reference implementation also fails.

| # | Decision | Effect on G5-B |
|---|---|---|
| A | Keep override + keep walls | G5-B stays parked at 159 F+E forever; G0–G7 all-green is unreachable. |
| B | Lift walls (all or a named subset: sts / select / encrypt / header / lifecycle / policy / object_lock Bypass) | Opens product tips; each wall is a feature-size effort and needs a real lab loop (scoped isolate → full-725). |
| C | Replace the raw-725 override with the canonical G5 contract: frozen known-failures list per wall + Python baseline unexpected = 0 first, then Rust unexpected = 0 | G5-B becomes scorable; the 86+ wall cases become expected failures with named policy, not hidden. |
| D | Authorize H90 soft leftover only | Peels a handful of `object_lock`/`other` cases; does not change the wall picture. |

Also still open from the predecessor's list: bounce `:18082` (still maps a
`(deleted)` `dd218530` inode), merge `swift-rust` PR #1
(`lab/tip-9531eb62-h89` → `claude/object-replicator`), restore a real `.git`
on the lab tip tree (needed for G0 on the tip line).

## 5. Reach of this successor

> Resolved the same day. The owner ran `tools/lab-agent-access-bootstrap.sh`,
> which installed a dedicated key on swift1/swift2 and dropped it through the
> Drive folder, so lab work did happen: see
> `tools/test-results/g5b-oracle-diff-20260918/`,
> `tools/test-results/g3-routes-20260918/`, and
> `tools/test-results/g5b-classify-20260918/LAB-FINDINGS.md`.
> Still missing: read access to the private `0smboy/swift-rust` for PR #1 and
> the tip line's git identity.

Originally checked 2026-09-18 from the cloud agent VM, before access:

- `swift1` public `169.58.108.85:18080` and `:8080` — connection timeout /
  refused (firewalld public DROP except SSH, per `tools/CONTABO-CLUSTER.md`).
- SSH `root@169.58.108.85` — no key in the environment; the predecessor
  relayed through the owner's Mac (`MacBook-Air.local`).
- `github.com/0smboy/swift-rust` — private; the agent token only sees
  `0smboy/Peregrine`. PR #1, the tip release tarball and branch
  `lab/tip-9531eb62-h89` are not readable from here.
- `/workspace/swift-rust` in this repo is the G6 subtree
  `23b104245e52a7e01c421a052193beb0ad14760a` (source `17adf0b`); it does not
  contain H71–H89. Product tips written here would fork from the wrong tree
  and break G0 identity for the tip line, so none were attempted.

Port 22 on both public IPs *is* reachable from the agent VM: `ssh` reaches the
auth stage and fails only with `Permission denied (publickey)`, and
`ssh-keyscan` returns the ed25519 host keys of `169.58.108.85` and
`.86`. So the only missing piece for lab work is a key, not a network path.

`tools/lab-agent-access-bootstrap.sh` closes that gap in one run from the
owner's Mac: it mints a dedicated ed25519 key commented
`peregrine-cloud-agent-20260918`, appends it to `root@swift1` and
`root@swift2` `authorized_keys` (idempotent, the only write it makes), reads
the real host keys off the nodes into a pinned `known_hosts`, proves the
agent's exact dial path works, prints a read-only plane snapshot, and hands the
key over through Drive folder `Peregrine-agent-access-20260918`
(`1HqCj1gZKPDe8nftoiVKLQnzXNRemXLeJ`) after matching the handshake token that
the agent wrote there. `--print-blobs` falls back to pasting; `--revoke`
removes the key from both nodes and deletes the Drive drop.

The tempauth `test:tester` key does not need to be handed over: it is readable
as root from `/etc/swift/peregrine-lab.env` once SSH works. Still separately
required for `swift-rust` work: read access for the agent's GitHub identity to
`0smboy/swift-rust` (PR #1, tip branch, release tarball), which no script can
grant.

## 6. Constraints carried forward (unchanged)

- No G8 / C_FINAL; do not touch prod `:8080`; do not TERM prod; do not
  overwrite the overseer bash; no tip/deploy below 3 GiB free on swift1.
- KEEP: remint / prod `:8080` / overseer / g6-internal config; live tip
  `9531eb62`; `bak-pre-h82-5fd37900`, `bak-pre-h89-dd218530`,
  `reclaim-stash-*`.
- Never wipe `/srv/node`; no second Keepalived; no secrets in the repo.
