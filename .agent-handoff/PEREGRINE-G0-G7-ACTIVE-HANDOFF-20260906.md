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
| Latest in-repo SHA | see `git rev-parse HEAD` after push |
| Formal G0–G7 field replay | **NOT RUN** on HEAD — **blocked on Swift2 SSH** from this cloud VM |

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
| **G4** Swift functional | **RED** — `1f7c401`: **549/47**. `5434983` / `84751c9` / `668b948`: **556/40/54**. Field on **`93bd70c`**: 8 `listing_*_direct` (mode already Listing HTML). Field on **`b20f569`**: **565/31/54** — object `./` hrefs passed; leftover is **4× `listing_*_direct_with_css`**. Sample: expected `'<link rel="stylesheet" type="text/css" href="…" />'`, actual type-before-rel | In-repo now emits Python `rel` then `type` then `href`. Fail-then-pass: `test_listing_html_css_link_is_rel_then_type_then_href`. Listing `./` href work (`b20f569`) stays independent of this CSS-order follow-up | Do **not** call G4 GREEN. The 4 CSS identities stay field-open until Swift2 replays `.functests` on a SHA that actually moves them |
| **G5** S3 | **NOT RUN** | Same | Official s3api / Ceph lists not replayed on this SHA |
| **G6** probe / 179 ledger | **FAIL** | `1f7c401`: **114/32/29/4**. Field on **`3d662b1`: 123/32/20/4**. Field on **`ca2081b`: 124/30/21/4**. Field on **`57b7456`: 123/32/20/4** (worse than ca2081b). Overlay fires; `--features ec` reconstructor `1a0fa11b…`. Theme `test_reconstructor_rebuild` still **14 (Δ0)**. `rebuilt>0 = 0`. `reconstruct_fa` / `last_rebuild_error` never in syslog | Field 507/503 during rebuild: REPLICATE/SSYNC `Expected status 200; got 507` body Insufficient Storage **empty `Drive:`**; 503 lock timeout. Swift1 `/srv/{1..4}/node` all on `/dev/sda4` 40G **3.5G free (92%)**. In-repo now names Drive, detects same-FS bind mounts, implements Python percent `fallocate_reserve`, INFO-logs every reconstruct_fa/SSYNC line. **Not** a field replay. Do **not** call G6 GREEN |
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
   Listing subrequests copy Host / token / `X-Backend-Remote-User`
   (Python `make_env`) and force `Accept: application/json`. Field G4 on
   `84751c9` proved Host copy was **not** the remaining hole (score
   identical to `5434983`). The listing follow-up now also drops
   `X-Backend-Listing-Out-Content-Type` / `X-Backend-Listing-Can-Vary`,
   sets `X-Backend-Source: staticweb` (Python `swift.source = SW`), and
   `listing_formats` skips reformatting that source. `parse_listing`
   accepts `listing_formats` `text/plain` (`name\\n` / `subdir/\\n`) as
   well as JSON. Field-shaped tests: official container-always-anonymous
   + dir auth flag, uuid-hex names, `listing_formats.prepare` stash →
   inner convert to text/plain, remaining `listing_formats` wrap, CSS
   `quote(css)` / `../{css}`. Those 8 are **not** field-closed. Deferred
   vs Python: custom web-error documents, domain_remap Host listing titles.

   **Index vs listing (unit only, after `668b948`).** Official
   `_set_staticweb_headers` is XOR: `_test_index` sets web-index and
   removes listings; `_test_listing` sets listings and
   `X-Remove-Container-Meta-Web-Index`. Python `handle_container`
   (`swift/common/middleware/staticweb.py`): if no index → `_listing`;
   else GET `PATH_INFO + index` and serve those bytes (`index contents`
   from `('%s contents' % 'index')`). Hyper `reassemble_async` used the
   captured first `next()` as container config whenever it was HTTP 2xx.
   When that body was already the index object (no web-* meta),
   `enabled()` was false and rust `return first` leaked `index contents`
   — the exact `668b948` assertion. In-repo now always HEADs for
   container config (prefer HEAD when it enables web mode), and listing
   style wins when `listings` is true so leftover web-index cannot serve
   the index object. Index-style (`listings=false`) still serves the
   index. **Not** a field replay.

   **Listing href `./` (unit only, after `93bd70c`).** Field on `93bd70c`
   confirmed the index→listing mode flip: title and `<table id="listing">`
   exist. Official `_test_listing` still failed looking for
   `'<a href="./{quote(link)}">{link}</a>'` (OpenStack 45a303c / bug
   1884285). Rust emitted `href="{quote(shown)}"` with no `./`. In-repo
   now prefixes object and subdir hrefs with `./` and `%2E`-encodes `.`
   like Python. CSS stays `quote(css)` / `../{quote(css)}` (no `./`).
   Parent `../` is unchanged. Field on **`b20f569`**: **565/31/54** —
   object `./` hrefs passed. **Independent of rebuild work.**

   **Listing CSS attr order (unit only, after `b20f569`).** The 4 leftover
   `listing_*_direct_with_css` fails are attribute order only:
   official `'<link rel="stylesheet" type="text/css" href="…" />'` vs
   rust `type` then `rel`. In-repo now emits Python order. Fail-then-pass:
   `test_listing_html_css_link_is_rel_then_type_then_href`. **Not** a
   field replay. Do **not** call G4 GREEN.

### G4 listing±CSS hypotheses (`668b948` vs official `TestStaticWeb`)

Labelled as hypotheses. Official suite:
`test/functional/test_staticweb.py` `_test_listing_direct`.

| Hypothesis | Verdict |
|---|---|
| Field GETs skip `reassemble_async` / `intercepts_response` | **Unlikely.** Index + `redirect_slash` closed on `5434983` via the same Hyper path. |
| `listing_formats` text/plain stash | **Wrong primary (or secondary).** Field on `668b948` still 556/40; body is the index object (`index contents`), not an empty/text listing. |
| Captured first `next()` is the index object | **Primary hole for the sample.** `200` + `index contents` + no web-* meta → old rust returned first. Fail-then-pass: `test_reassemble_listing_direct_ignores_index_bytes_without_web_headers`. |
| Leftover web-index after `_test_index` | **Also sufficient.** Official listing tests remove web-index; if the captured GET still carries it, index-first serves `index contents`. Listing style now wins when listings is on; HEAD listings beats leftover index-only on first. |
| Auth/Host copy incomplete for TempAuth | **Not the field hole.** `84751c9` score identical to `5434983`. |
| CSS href vs unit fixtures | **Unlikely for ascii.** Official names are `uuid4().hex`. |
| staticweb not in isolated pipeline | **Unlikely.** Index/301 would also fail. |
| Object href missing `./` prefix | **Closed on field `b20f569` (unit shipped earlier).** Title/table exist; official assert is `'<a href="./{uuid}">'`. Independent of CSS-order and rebuild work. |
| Empty listing table / parse empty | **Unlikely after `b20f569`.** Object `./` hrefs passed; leftover fails are CSS-only. |
| CSS href form | **Unlikely for uuid.** Official container CSS is `quote(css)` without `./`; dir CSS is `../{css}`. |
| CSS `<link>` attr order | **Primary leftover on `b20f569`.** Expected `rel` then `type` then `href`. Fail-then-pass: `test_listing_html_css_link_is_rel_then_type_then_href`. |

Do **not** call the 8 identities closed until `.functests` on a SHA that moves the field score.
6. **G6 container-sync / reconstructor follow-up (unit only, not GREEN).**
   Field on `f84ac71` did **not** reduce the 13 `container_sync` or 14
   `reconstructor_rebuild` violations. HEAD/409 and post-ssync local
   `discover_jobs` were the wrong layers for those probes. See
   “G6 live themes (`f84ac71`)” below.

## G6 live themes (`f84ac71`) — do not upgrade by prose

This cloud VM cannot read `/var/log/g6-rust/f84ac71/w1-honest179/` on
Swift1. `gh` PR #10 comments and CI artifacts have no probe failure
strings. Reasoning is from official probe names + in-repo daemons.

### container_sync still 13: HttpSyncClient **is** the path

Official suite: OpenStack `test/probe/test_container_sync.py`.
`Manager(['container-sync']).once()` starts `swift-container-sync`.
The Rust binary always builds `HttpSyncClient` (HTTP PUT/DELETE to
`X-Container-Sync-To`). It is **not** rsync.

HEAD-before-PUT / PUT-409-as-success help **already-present dest**
objects (`test_sync_newer_remote`). First-time PUT needs
`ProxyObjectSource.get_object()` (public proxy GET + TempAuth) then dest
PUT. DELETE does **not** need a source GET — that is why only
`test_delete_propagate` moved PASS on `f84ac71`.

`Manager.once()` children often inherit `SWIFT_DIR` but **not** the
Python-module `PROXY_BASE_URL`. Historic default `http://127.0.0.1:8080`
then GETs production. In-repo now: `PROXY_BASE_URL` →
`[probe_test] proxy_base_url` → `{SWIFT_DIR}/proxy-server.conf`
`bind_ip`/`bind_port` (wildcard → `127.0.0.1`) → historic `:8080`.
`SwiftConfig::get("DEFAULT", …)` now reads the DEFAULT map (ConfigParser);
it previously returned `None`, so a bind-only `[DEFAULT]` file could not
feed this fallback. Do **not** hardcode a guessed `:18080` host
(`127.0.0.1` vs `10.0.0.1` both exist in lab scripts).

Field on `1e1c515` **had** `PROXY_BASE_URL=http://127.0.0.1:18080` and
still logged `container-sync: source GET transport failure` ×24 with
**no** `internal_url=` in the same files. That is not “env missing.”
`http_exchange` returned `None` and swallowed the URL / error kind
(connection refused, timeout, TLS/https, DNS, incomplete headers).
`internal_url=` was `logger.info` (syslog) while the failure is
`eprintln` (Manager file log). A copied `[container-sync]
internal_client_url` also used to win over the env. Realms cluster
URLs are dest-only (`X-Container-Sync-To`); they do not feed
`ProxyObjectSource.get_object`.

In-repo now (unit only): stderr
`container-sync: proxy_base=… internal_url=… auth_url=…`; transport
failures print `kind=… url=… detail=…`; env PROXY_BASE_URL overrides
stale conf URL; `/v1` is not doubled; connect uses `connect_timeout`
and retries `{SWIFT_DIR}` bind_ip when loopback refuses. **Do not**
call G6 GREEN until Swift2 replays 179 on this SHA.

### reconstructor_rebuild still 14: local `run_once` is **not** the heal path

Official suite: `test/probe/test_reconstructor_rebuild.py`
(`TestReconstructorRebuild`). `break_nodes(...)` **deletes** fragments
on failed primaries. Python heals via a **partner** SYNC job
(`reconstruct_fa` + ssync **to** the broken node).

Rust partner path is `EcSyncRebuilder` + `process_part_job`, **only**
with `--features ec`. The `f84ac71` post-ssync `discover_jobs` /
`reconstruct_missing` path also needs `ec`, and requires a remaining
hash dir with a non-empty durable fragment set that does **not** include
this node’s primary index. After `break_nodes` the victim hash dir is
gone or empty → `discover_jobs` correctly returns **no jobs**. Empty
fragment filtering is right for tombstones; do not “fix” it so those
dirs become rebuild jobs.

Field jobs therefore need partner SYNC. That sweep used to skip every
device when `servers_per_port=0` and conf `bind_port` (`16210` …) ≠
ring port (`6010`). In-repo now falls back to local IP + device name
(`resolve_ring_device_id`). Still requires a local interface address.

After identity fallback, REPLICATE / SSYNC / fragment GET still used
the **ring port**. Isolated listeners are `16210`…. Fail-then-pass:
`test_break_nodes_partner_sync_uses_listen_overlay_not_ring_port` and
`break_nodes_rmtree_suffix_delta_uses_listen_overlay`. Daemon loads
`ObjectListenOverlay` from `SWIFT_DIR/object-server/*.conf`. Log line:
`listen overlay from …`.

Field on **`ca2081b`**: overlay **is** firing (195× syslog;
`failed=['127.0.0.2:16220/sdb6#2']` already isolated). Pass lines
`suffix_syncs=1–3` and **`rebuilt=0`**. Official
`test_rebuild_missing_frags` then `proxy_get` 404. That is **not**
another port miss.

`EcSsyncStats.rebuilt` only counted local `reconstruct_missing`. After
`break_nodes` rmtree the victim hash dir is gone → `discover_jobs` is
correctly empty. Heal is partner `reconstruct_fa`. ca2081b compared
peer `X-Backend-Data-Timestamp` to the datafile `X-Timestamp` with
raw `!=` (official tests POST after PUT), did not seed the already-open
local fragment, and skipped the data PUT on `NotEnoughFragments` while
still incrementing `suffix_syncs`. In-repo now: `same_data_timestamp` +
version-key merge, `rebuild_with_local` seed, count reconstruct_fa PUTs
as `rebuilt`, log `last_rebuild_error`. Fail-then-pass:
`test_gather_merges_normalized_and_internal_timestamps`,
`test_reconstruct_fa_local_seed_reaches_ndata_without_self_http`,
`test_process_part_job_counts_reconstruct_fa_puts_as_rebuilt`,
`test_process_part_job_surfaces_reconstruct_fa_skip_when_rebuilt_stays_zero`.
**`--features ec` is still required.** This is not a field replay. Do
**not** call G6 GREEN. Keep this independent of G4 listing/CSS work.

Field on **`57b7456`**: seed/overlay/timestamp did **not** land fragments.
`reconstruct_fa` strings never appeared because SSYNC/REPLICATE failed
**before** updates (`got 503` / `got 507` with empty `Drive:`). Isolated
devices are dirs on the 92% full root FS. Rust `check_drive` 507s when
`mount_check=true` and the dir is not a mount (Python SAIO sets
`mount_check=false`; `.ismount` or `/proc/self/mountinfo` bind-mounts
also pass). Percent `fallocate_reserve=1%` was a **no-op** (no total
capacity); 8.75% free would **not** 507 a small fragment under Python
math. In-repo now: Drive: name + `X-Backend-No-Space-Reason`, bind-mount
detection, Python percent reserve, SSYNC error body snippet, INFO
`object-reconstructor:` for every skip/failure. Fail-then-pass:
`test_mountinfo_parser_finds_same_fs_bind_mount`,
`breach_math_matches_python_fallocate_reserve` (3.5G/40G/1%/1MiB),
`replicate_507_names_the_drive_when_mount_check_rejects_a_plain_dir`,
`tcp_wire_connect_includes_507_body_drive_in_error`,
`test_process_part_job_logs_ssync_connect_507`.
Do **not** re-fix listen overlay or CSS. Do **not** call G6 GREEN.

### Exact Swift2 / Swift1 checks (environmental — do not fake)

**container_sync**

1. `Manager.once()` PATH: `/root/work/g6-rust-bin/swift-container-sync`
   vs `/usr/local/bin` (production systemd install is `:8080` /
   `/etc/swift`).
2. Child env: `PROXY_BASE_URL`, `SWIFT_TEST_CONFIG_FILE`
   `[probe_test] proxy_base_url`, `SWIFT_DIR=/etc/g6-rust`.
3. Same file as the ×24 failures must now contain
   `container-sync: proxy_base=` / `internal_url=` (stderr). Syslog
   `internal_url=` alone is not enough — that is why `1e1c515` looked
   like the URL was never chosen.
4. `source GET transport failure kind=` must name
   `connection refused` / `timeout` / `tls` / `dns` / `incomplete headers`
   and the full URL. `G6_CONTAINER_SYNC_DEBUG=1` also prints
   `source GET url=` before the request.
5. `ss -lntp | grep 18080` vs URL host: if kind is connection refused
   on `127.0.0.1:18080` but proxy binds `10.0.0.1` only, the fallback
   retry log (`source GET fallback url=`) should fire.
6. Auth: `[container-sync] internal_client_auth_*` or `[func_test]`
   user/key. `auth transport failure kind=` is the same channel.
7. Realms `current` cluster URL is **dest** Sync-To, not the source GET.
8. DELETE-only PASS + PUT FAIL ⇒ source GET / proxy base, not HEAD/409.

**reconstructor**

1. `sha256sum` of live `swift-object-reconstructor`; confirm
   `--features ec` (`strings` / `nm` / log `rebuilt=`).
2. Conf `devices` + `bind_port` vs **EC ring** `ip/port/device`;
   `servers_per_port`.
3. Pass log: `suffix_syncs` / `rebuilt` / `failures`.
   Field on `ca2081b`: `suffix_syncs>0` and `rebuilt=0` — overlay
   connected; reconstruct_fa skipped. Field on `57b7456`: SSYNC/REPLICATE
   507/503 **before** reconstruct_fa; INFO `reconstruct_fa` never printed.
   After this SHA expect INFO `object-reconstructor: …` for every
   reconstruct_fa skip **and** `got 507 body='…Drive: sdb6…'`.
   `rebuilt>=1` only when a reconstruct_fa PUT lands.
4. After `break_nodes`, victim hash dir gone ⇒ local `discover_jobs`
   correctly empty; heal must be partner `reconstruct_fa`. Ports on
   `ca2081b` were already remapped (`16220/sdb6#2`).
5. Manager binary same isolated rust bin, conf under
   `/etc/g6-rust/object-server/*.conf`.
6. Swift1 disk: `df -h /srv/1/node /dev/sda4`. Confirm
   `mount_check` / `fallocate_reserve` in
   `/etc/g6-rust/object-server/*.conf`. Isolated dirs on a shared root
   need `mount_check=false` (SAIO) or a `.ismount` stub — do **not**
   set reserve to 0. After this SHA, `mount_check=true` without a mount
   logs a startup warning and 507s with `Drive: <device>` /
   `X-Backend-No-Space-Reason: unmounted`.

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
