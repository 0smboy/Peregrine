# Peregrine G0–G7 active handoff — 2026-09-06

**This file is the current in-repo source of truth for G0–G7 acceptance.**
It supersedes the 2026-09-05 checkpoint narrative and the missing
`PEREGRINE-G0-G7-ACTIVE-HANDOFF-20260905.md` (that name was never committed
to this repository; the 2026-09-05 GitHub prerelease is the prior artifact).

Production `:8080`, VIP `10.0.0.10`, HAProxy, Keepalived, rings, and
swiftfuse were **not** touched. Do not deploy this candidate.

## Candidate identity

| Item | Value |
|---|---|
| Branch | `cursor/g0-g7-acceptance-1ad4` |
| Parent checkpoint | `885b57c38dcc60c2e263f23a109668718ebce785` (`codex/g0-g7-safety-20260905`) |
| Parent tag | `g0-g7-checkpoint-20260905` (prerelease, **unaccepted**) |
| This continuation | `aa2643dc8796c8ff28cd71e55011eb0c1394ca53` |
| Formal G0–G7 field replay | **NOT RUN** — **blocked on Swift2 SSH** from this cloud VM |

Freeze `candidate_commit` in
`swift-rust/tools/test-lab/g7/acceptance.yaml` and
`acceptance.json` to the SHA of the commit you actually build on Swift2
**before** the first scored G7 run. Until then the files say `PENDING_FREEZE`.

## Honest gate status (2026-09-06)

Vocabulary: **GREEN** only with complete evidence on one frozen commit.
Package/unit green is not field acceptance.

| Gate | Field acceptance | In-repo / package evidence | Why it is not GREEN |
|---|---|---|---|
| **G0** provenance | **NOT RUN** | Provenance schema + unit tests exist (`tools/test-lab/provenance.py`) | No live `/proc/exe` SHA, lockfile, or artifact digest recorded for this commit |
| **G1** environment | **NOT RUN** | Preflight unit tests exist | No Swift1–4 census from this VM |
| **G2** build / pipeline | **NOT RUN** | Offline build not executed here | No locked Linux artifact hashes for this commit |
| **G3** native async | **NOT RUN** | Counter parser + characterization tests exist | No live `:8081` / isolated `:18080` recon deltas on this commit |
| **G4** Swift functional | **RED** — `1f7c401`: **549/47**. Field replay on `5434983`: **556 pass / 40 fail / 54 skip** (staticweb HTML theme 16→8; index + `redirect_slash` closed). Not replayed after the listing±CSS Hyper follow-up | TempURL Hyper path. Staticweb `reassemble_async` index/301 + listing±CSS unit tests (`test_reassemble_listing_*_direct_*`) | Do **not** call G4 GREEN. Remaining field 40 includes the 8 listing±CSS identities until Swift2 replays `.functests` on the SHA that copies `make_env` headers onto listing GETs |
| **G5** S3 | **NOT RUN** | Same | Official s3api / Ceph lists not replayed on this SHA |
| **G6** probe / 179 ledger | **NOT RUN** | Historical W068/W069/W070 GREEN was on `17adf0b`, **not** transferable | Must replay 179 identities once, no retry-to-PASS |
| **G7** concurrency / faults | **NOT ACCEPTED** | Runner fail-closed unit tests + object-server SSYNC interrupt + proxy EC fragment-loss tests | No physical matrix on isolated G6 rust data-plane for this SHA |
| **G8** | **DEFERRED** | — | G0–G7 not all GREEN |

### What 2026-09-05 already proved (not transferable)

At `dda5927` on Swift2: object-server default 193 / EC 202 library tests;
proxy 119 library + 54 binary + 11 integration. At `885b57c`: runtime-storage
11, diskfile 48, metered-channel 9. Those results do **not** attach to later
SHAs.

Historical G6 w103 (175 OK + 4 skips) is **invalid** as current acceptance:
runner retry/timeout issues. Replay exactly 179 identities.

## Code closed in this continuation (unit/package only)

1. **Buffer metrics.** `IncomingBody::from_channel` no longer charges
   Content-Length as `request_body_buffer_bytes`. Production HTTP pumps
   (UTF-8 compat, SSYNC handoff, multiphase MIME PUT) and SSYNC UpdateStart
   now use `IncomingBody::metered_channel`. COPY adapters still use the
   legacy channel; their occupancy is uncounted, not falsely object-sized.
2. **Cancel / cleanup domain.** `StorageExecutor::submit_held` +
   `BlockingJob::detach` keep a must-run unlink on the POSIX domain.
   `WriterLease` holds the PUT tempfile; Drop submits `close()` with the
   device permit. Request cancel no longer unlinks on the reactor thread.
3. **G7 honesty.** Cases that only listed FDs, wrote a 1MiB fill, or
   blackholed without a PUT now return **NOT RUN** instead of looking
   executed. New fail-closed kinds: `ssync_interrupt`, `ec_fragment_loss`.
   In-repo proofs:
   - `async_ssync_does_not_ack_truncated_updates` (no success-ack, no tmp)
   - `test_ec_object_put_get_round_trip_and_fragment_loss`
4. **TempURL on the Hyper path.** Isolated `:18080` never calls
   `Middleware::handle()`. TempURL HMAC, incoming scrub, query rewrite, and
   `X-Backend-Authorize-Override` / `.wsgi.tempurl` now run in `prepare()`;
   Content-Disposition / outgoing scrub / staticweb container-root 401 run
   in `finish()`. Field G4 on `1f7c401`: TempURL→401 theme **79→1**.
   Leftover TempURL edges **not** fixed here (not the same hole):
   `GET_DLO_outside_container` (DLO segment container vs signed path) and
   remaining UTF-8 TempURL cases (beyond decoded PATH_INFO HMAC).
5. **Staticweb on the Hyper path (unit only).** `intercepts_response` +
   `reassemble_async` serve index, delimiter-`/` HTML listing, 301 slash
   redirect, CSS link, dir-prefix listing, TempURL query on listing hrefs,
   and Python `X-Web-Mode` / `.wsgi.tempurl` gating. `handle()` matches.
   Listing subrequests now copy Host / token / `X-Backend-Remote-User`
   (Python `make_env`), force `Accept: application/json`, and apply
   `delimiter=/` grouping to flat captured listings. Unit tests cover the
   8 remaining `listing_{anon,auth}_direct_{with,without}_css` identities
   (ascii + UTF-8), including dir-marker `GET` and `some sub%dir/` hrefs.
   Those 8 are **not** field-closed. Deferred vs Python: custom web-error
   documents, domain_remap Host listing titles.

## How to run full G0–G7

Follow `swift-rust/tools/test-lab/G0-G7-ACCEPTANCE-RUNBOOK.md` on Swift2.
Do not run G7/G8 against VIP `:8080` / `:8085`. Isolated rust data-plane
only (`acceptance.yaml` port `18080`, forbidden ports listed there).

## Blocked on Swift2 SSH

This cloud VM cannot open SSH to Swift2 / Swift1 / Swift4. No live
`/proc/exe` census, locked Linux artifact, official `.functests`, 179
ledger, or isolated `:18080` G7 matrix can be recorded from here. Package
and unit results below are **not** field GREEN.

In-repo helpers for the next Swift2 runner (still no production touch):

- `python3 swift-rust/tools/test-lab/freeze-candidate.py` — idempotent
  `PENDING_FREEZE` → SHA; prints G0 checklist fields the runbook requires.
- `python3 swift-rust/tools/test-lab/g6_ledger.py LEDGER.json` — fail-closed
  179-identity score. Retry-to-PASS and leftover timeout children cannot
  become PASS.

## Remaining blockers for the next runner

1. SSH to Swift2, checkout this branch, run `freeze-candidate.py`, offline
   locked build, record G0 identity.
2. Replay G4/G5/G6 on **that exact SHA** (179 identities). Score G6 with
   `g6_ledger.py`. No retry-to-PASS.
3. Replay G7 with injectors that actually hit (EIO mapper, ENOSPC loop
   device, fd ulimit, DurabilityBarrier probe). `NOT RUN` keeps the gate RED.
4. Do not mark production ACCEPT until every gate in the table is GREEN
   with evidence paths + dates.
