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

- G4: Swift `test/functional` identity list, exact-name diff vs Python.
  Field on `5434983`, `84751c9`, and `668b948` is still 556/40/54
  (`index contents`). Field on **`93bd70c` still has 8 `listing_*_direct`
  fails**, but the body is Listing HTML (title + `<table id="listing">`),
  not the index object. Sample: `'<a href="./{uuid}">…</a>'` not found.
  Field on **`b20f569` is 565/31/54** — object `./` hrefs passed.
  Leftover listing fails are 4× `listing_*_direct_with_css` attribute
  order (`rel` then `type` then `href`). After this SHA, confirm the
  `<link>` tag matches that official order. Do **not** call G4 GREEN
  from unit tests.
- G5: Swift `test/s3api` + pinned Ceph `s3-tests`
- G6: 147 replication + 32 EC identities, merge **once** into the 179
  ledger. Score with `python3 swift-rust/tools/test-lab/g6_ledger.py LEDGER.json`.
  No auto-retry-to-PASS. Leftover timeout children stay TIMEOUT/FAIL,
  never PASS. The scorer unit tests encode those holes; do not bypass them.

Do not import W068/W069/W070 hashes from `17adf0b`.

Field G6 on **`3d662b1` is 123/32/20/4**. Field on **`ca2081b` is
124/30/21/4**. Field on **`57b7456` is 123/32/20/4**. Field on
**`1682fdb` is 125/30/20/4**. Overlay is firing; `--features ec`
verified; `mount_check=false` confirmed; in-window **507=0**. Theme
`test_reconstructor_rebuild` still 14 (Δ0). Field on **`7ee3f35`**:
single-test still `proxy_get` 404 / errors=6 after once; **503 in
window: NONE**; `rebuilt>0` with matching `reconstruct_fa_attempts`.
Connect-503 is closed. Do not re-guess listen overlay, CSS,
mount_check, or 503-connect. Field on **`9a95747`**: durable PUTs
now match `failed=` victims; still **404×6**. Leftover is GET
visibility (`X-Object-Sysmeta-Ec-Frag-Index` + DiskFile open) and
proxy async gather after POST-after-PUT. That is **FAIL**, not GREEN.
Field on **`4f7a82c`**: object-server GET 200 + Ec-Frag-Index for
0–5 and victim `#N#d.data` after once; proxy GET still **404×6**.
Sharper leftover: PRE-once 404 with **5** Ec-Frag 200s
`idxs=[0,2,3,4,5]` (ndata=4). Field **`2c64a89`**: still 404×6; Logger lines 0 in manager.log.
In-repo: `G6_DIAG proxy-server: EC GET` on every object GET
(`handle_async` + route + gather/404). Still **FAIL**, not GREEN.

Field **`988b81b` locked then flipped on rust HTTP**: official
`proxy_get` is Python `InternalClient` / `egg:swift#proxy`. After the
lab forced GET onto rust `:18080` via **swiftclient** (same `self.url` /
token as PUT/POST), `test_rebuild_missing_frags` **PASSED** (rc=0, ~10s,
30× `G6_DIAG proxy-server: EC GET status=200 reason=ok`). Do **not**
reopen gather-bucket chasing for this single-test.

IsolatedIdentity **must** launch G6 probes through the harness (not
bare `pytest` on official `proxy_get`). Evidence
`/workspace/rebuild-once-988b81b-httpget/` (2026-09-06). This single
identity is green on rust HTTP for `988b81b`; the G6 179 ledger is
still **FAIL**. Do not call G6 GREEN.

```bash
export PROXY_BASE_URL=http://127.0.0.1:18080
# Required IsolatedIdentity entry (apply lab proxy_get + fail closed):
swift-rust/tools/test-lab/g6_isolated_probe.sh pytest \
  test/probe/test_reconstructor_rebuild.py::TestReconstructorRebuild::test_rebuild_missing_frags -vv
# Equivalent pre-hook before any other IsolatedIdentity pytest:
#   python3 swift-rust/tools/test-lab/g6_rust_proxy_get.py --prepare
#   python3 swift-rust/tools/test-lab/g6_rust_proxy_get.py --check
```

Field `/workspace/g6-rebuild-988b81b-httpget/` (2026-09-06): rebuild
theme **6 green / 11 red** of 17 after rust HTTP `proxy_get`. Closed
on rust HTTP (do **not** reopen):

- `test_rebuild_missing_frags` — PASS `988b81b` (`/workspace/rebuild-once-988b81b-httpget/`, 2026-09-06).
- `test_rebuild_quarantines_lonely_frag` — PASS `3efec7d` + HEAD honesty (`/workspace/rebuild-lonely-3efec7d-headhttp/`, 2026-09-06).
- `test_rebuild_with_non_durable_newer_data` — PASS `176505e` proxy `faaeed18…` (`/workspace/rebuild-nondurable-176505e/`, 2026-09-06). BrokenPipe gone; prefs GET etag v2≠v1.
- `test_rebuild_reconciled_object_with_offset_timestamp` — ASCII PASS on the `176505e` theme replay (`/workspace/g6-rebuild-176505e/`, 2026-09-06). Do not reopen.

`:18080` public pipeline includes **gatekeeper**, which strips every
`X-Backend-*` (including `X-Backend-No-Commit`). Official IC
`upload_object` / `direct_get(..., require_durable=False)` need those
headers. Field PASS routed those IC PUTs and backend-header
`proxy_get` to rust **`:18082`** (no gatekeeper). Client
`proxy_get` / lonely-frag HEAD stay on `:18080` when they do not
carry `X-Backend-*`. Do not “fix” gatekeeper by allowing client
`X-Backend-*` on `:18080`.

Field `/workspace/g6-rebuild-176505e/` (2026-09-06) on tip `176505e`:
rebuild theme **ok=9 / FAILED=3 / ERROR=5** of 17 (was 6/11 on
`988b81b`+httpget). Newly green ASCII (do **not** reopen):
`lonely_frag`, `non_durable_newer_data`,
`test_rebuild_reconciled_object_with_offset_timestamp`, plus prior
`missing_frags` / `non_durable` / `partner_down` / `combo` /
`unexpired_meta`.

Field `/workspace/g6-rebuild-e650f12-utf8/` (2026-09-06) on adapter
`e650f12` / bins `176505e`: UnicodeEncodeError **GONE**. UTF8
`test_rebuild_non_durable_frags` **PASS**. Do not reopen that, or
any ASCII green.

Prior tip `cb712ff` closed leftover A (UTF8 `missing_frags` partner-GET
field-name abort). Do **not** reopen that.

Field `/workspace/g6-rebuild-6042407-utf8-lonely/` (2026-09-06) on
adapter `6042407` / bins `cb712ff`: UTF8
`test_rebuild_quarantines_lonely_frag` **FIELD PASS**. HEAD meta present
(`x-object-meta-Ãè-…`). UTF8 `missing_frags` smoke still PASS. Do
**not** reopen leftover B (UTF8 lonely / missing / non_durable) or
ASCII greens.

Honesty for leftover B: field kept lonely HEAD on
`int_client.make_request`. IsolatedIdentity owns latin-1 parse +
`WsgiHeaderDict`. `client.head_object` / urllib3 dropped UTF-8 meta
(the `Ãè` WSGI name). Do not move that HEAD onto urllib3.

Field `/workspace/g6-rebuild-982e86a-expire/` (2026-09-06) on tip
`982e86a`: ASCII + UTF8 `test_sync_expired_object` **PASS**. Do not
reopen expire.

Field `/workspace/g6-rebuild-982e86a-unified/` (2026-09-06) on the
same SHA: full `test.probe.test_reconstructor_rebuild` **17/17 PASS**
(~248s). Rebuild theme is **closed** for `982e86a`. This tip lands
that unified IsolatedIdentity harness so bare `g6_isolated_probe.sh`
reproduces it:

- Public `:18080` **gatekeeper** strips every `X-Backend-*`
  (`X-Backend-No-Commit`, Fragment-Preferences, …). Do not weaken
  gatekeeper.
- IsolatedIdentity GET (`rust_http_proxy_get`) and no-commit /
  backend-header PUTs hop rust **`:18082`** when
  `G6_INTERNAL_PROXY_URL` is set (`g6_isolated_probe.sh` defaults
  `http://127.0.0.1:18082` if IsolatedIdentity `:18080`).
- Keep IsolatedIdentity `proxy_get` on `rust_http_proxy_get`
  (expire `UnexpectedResponse` + `X-Delete-After` → `X-Delete-At`).
  Do **not** raw-replace IsolatedIdentity `proxy_get` with swiftclient.

```bash
export PROXY_BASE_URL=http://127.0.0.1:18080
# G6_INTERNAL_PROXY_URL defaults to http://127.0.0.1:18082
swift-rust/tools/test-lab/g6_isolated_probe.sh pytest \
  test/probe/test_reconstructor_rebuild.py -vv
```

Not G6 179 GREEN. Next leftovers are non-rebuild (container_merge,
sharder, expirer, …).

Field `/workspace/g6-merge-982e86a/` (2026-09-06) on `982e86a` +
unified harness: merge family **PASS=5 / FAIL=1 / ERROR=5 / SKIP=1**
(bad=6 vs historical 11). Rebuild stays 17/17. Primary ERROR was
IsolatedIdentity ``unexpected bytes after informational response head
(29 leftover)`` after ``100 Continue`` — IsolatedIdentity now keeps
those bytes as the next response. Do not claim merge GREEN from units.
Do not reopen rebuild / expire / `:18082` no-commit.

Field `/workspace/g6-merge-next-rootcause.txt` (2026-09-07) after
`4764ef1` (100-continue leftover gone): merge family **PASS=6 / bad=5**.
`rust_http_make_request` still sent caller `X-Backend-*` to public
`:18080`. Gatekeeper stripped `X-Backend-Allow-Reserved-Names`
(ReservedNamespace `put_container` → `check_utf8(..., internal=False)`
→ **412** on NULL reserved names, 4 ERROR) and
`X-Backend-Storage-Policy-Index` (`test_reconciler_move_object_twice`
HEAD found the object on the wrong policy → **200** where the test
expects 4xx before `reconciler.once()`). This tip hops
`rust_http_make_request` to `G6_INTERNAL_PROXY_URL` (default `:18082`)
when the caller sent any `X-Backend-*`. IsolatedIdentity still stamps
reserved-names *after* hop, so plain PUTs stay on `:18080`. Keep expire
`UnexpectedResponse` + `:18082` GET hop from `4764ef1`. Do not claim
merge GREEN. Do not reopen rebuild 17/17.

Field `/workspace/g6-merge-xbackend-18082/` (2026-09-07) after
`8353823` + wrap: merge family **PASS=9 / bad=2**. Brain
`put_container` only sends `X-Storage-Policy`. Egg
`InternalClient.make_request` `setdefault('X-Backend-Allow-Reserved-Names',
'true')` **before** the hop; pure `8353823` stamped after hop so those
PUTs stayed on `:18080` → **412**. Field wrap before hop cleared
ReservedNamespace 412 and `test_reconciler_move_object_twice` 200.
`_HttpResp.environ` is a minimal WSGI dict including `wsgi.url_scheme`
(empty `{}` was `KeyError` in brain translate on residual 404). Do
**not** chase residual ReservedNamespace `get_object` 404 in this tip.
Do not claim merge GREEN. Do not reopen rebuild 17/17.

Field `/workspace/g6-merge-404-rootcause.txt` (2026-09-07): residual
ReservedNamespace ERROR (merge `get_object` + `reconcile_symlink`) is
**not** a missing object after the Allow-Reserved hop. Official
`brain.translate_client_exception` needs `wsgi.url_scheme`,
`SERVER_NAME`, `SERVER_PORT`, `PATH_INFO`, `QUERY_STRING` from the
request URL plus `resp.explanation`. Incomplete environ KeyError'd:
symlink L406 expected broken-symlink 404 → ClientException; merge L137
`_get_object_patiently` must see ClientException(404) to retry.
Reserved GET 2xx already proven (`move_twice` PASS). This tip fills
`_HttpResp` from the request URL. Keep setdefault-Allow-Reserved-before-hop.
Do not chase `sync_expired` 503 (lab noise). Do not reopen rebuild 17/17.
Not G6 GREEN.

Field `/workspace/g6-merge-symlink-rootcause.txt` (2026-09-07): rust
container-reconciler dropped reserved-namespace symlinks on **EC →
replicated** moves. After `reconciler.once()` the symlink was gone from
both policies and the container listing (only the reserved target
remained). `wrong=silver/1 → Policy-0` PASS; `wrong=ec42/2 → 0` FAIL
100%. Official flake ~1/4 matches P(wrong=EC)≈1/3. Ledger residual is
`TestReservedNamespaceMergePolicyIndex.test_reconcile_symlink` L437
post-reconciler GET. `%2500` in ClientException is display-only. This
tip `775f752` stripped `X-Object-Sysmeta-Ec-*` and skipped dest write
only when dest HEAD was a raw symlink — field still **FAIL_404**
(forced `wrong=ec42/2`). Dest HEAD through IsolatedIdentity can 200
the EC *source* as `application/symlink`, so skip + source DELETE
leaves dest empty. This tip never skips dest write for a symlink
source: dest PUT is a client `X-Symlink-Target` empty
`application/symlink` (empty MD5, no Target-Etag) and source DELETE
waits until dest HEAD `?symlink=get` is GET-able. Keep Allow-Reserved /
`%00` NULL names. Do not reopen rebuild 17/17. Not G6 GREEN.

If leftover themes stay red after the 176505e theme replay, check
environment before another code guess:

```bash
# container-sync: which binary + which proxy
type -a swift-container-sync
# expect /root/work/g6-rust-bin/swift-container-sync, not /usr/local/bin
tr '\0' '\n' < /proc/$(pgrep -n swift-container-sync)/environ \
  | egrep '^(PROXY_BASE_URL|SWIFT_DIR|SWIFT_TEST_CONFIG_FILE)='
# stderr (same file as transport failures) — syslog-only internal_url= is not enough
grep -E 'proxy_base=|internal_url=|source GET transport failure' \
  /var/log/g6-rust/*/container-sync*.log | tail
# kind= must be connection refused | timeout | tls | dns | …
grep -E 'kind=' /var/log/g6-rust/*/container-sync*.log | tail
# IsolatedIdentity /etc/g6-rust/proxy-server.conf bind_port
awk '/bind_(ip|port)/' /etc/g6-rust/proxy-server.conf

# reconstructor: features ec + ring identity + listen overlay
strings /root/work/g6-rust-bin/swift-object-reconstructor | grep -E 'liberasure|reconstruct'
# bind_port vs EC ring port; servers_per_port
awk '/bind_port|servers_per_port|devices/' /etc/g6-rust/object-server/*.conf
# 9a95747 leftover: durable PUT matched victims; proxy_get still 404
pgrep -af swift-object-reconstructor
# kill leftover /usr/local/bin (Aug 9) processes — they pollute syslog
grep -E 'once start|once done|reconstruct_fa PUT|backend_index=|durable=|reconstruct_fa_attempts|got 503' \
  /var/log/g6-rust/*/object-reconstructor*.log | tail
# victim device after once (example failed= sdb7#2)
find /srv/*/node/sdb7 -name '*#2#d.data' -o -name '*#2.data' | head
# object-server GET harvest (expect Ec-Frag-Index=2 on the healed hash)
grep -E 'Ec-Frag-Index|GET .* 200|GET .* 404' /var/log/g6-rust/*/object-*.log | tail
awk '/mount_check|disable_fallocate|fallocate_reserve|devices|bind_port|^\[' \
  /etc/g6-rust/object-server/*.conf
# effective parse (not the file text): must show mount_check=false
grep -E 'swift-object-server: devices=|mount_check=' \
  /var/log/g6-rust/object-*.log | tail
df -h /srv/1/node /dev/sda4
grep -E 'reconstruct_fa|got 507|got 503|Drive:|Reason:|admission|unmounted|object-reconstructor:' \
  /var/log/g6-rust/*/object-reconstructor*.log | tail
```

Do not treat empty-fragment `discover_jobs` skips as a bug: probe
`break_nodes` deletes the victim hash dir; heal is partner SYNC +
`reconstruct_fa` (local seed + timestamp-coherent peer fragments),
which requires `--features ec`. Overlay on `ca2081b` already reached
isolated ports. Do **not** call G6 GREEN from unit tests.

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
