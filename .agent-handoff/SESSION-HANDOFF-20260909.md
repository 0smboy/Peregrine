# Peregrine — session handoff (2026-09-09)

**TL;DR（中文）**：本次会话完成两件事，均已提交并开 PR：
1. **搭好 Cloud Agent 开发环境**（[PR #18](https://github.com/0smboy/Peregrine/pull/18)）——`.cursor/environment.json` + `.cursor/install.sh`，全量组件可编译、SAIO 集群可跑通、`cosbench-rs` 可对活集群压测、docs-site 可启动；已用一次全新环境构建验证成功。
2. **推进 G0–G7 的“仓内（package/unit）绿”**（[PR #19](https://github.com/0smboy/Peregrine/pull/19)）——修好 3 个红：SLO heartbeat 404、`swift-ec` 线程安全崩溃（真实生产并发 bug）、`swift-core` 抖动测试。
**未完成**：G0–G7 的**现场（field）验收无法在本云 VM 完成**（需 SSH 到 Swift1/2/4 隔离实验室，本环境不可达）；另有 1 个仓内红被**有意保留**——G6 的 EC-GET-掉片 crux（详见第 3 节），因为修它会与已被单测钉死的“policy-0 隔离契约”冲突。**未声明任何 gate 为 GREEN**（遵守 evidence-alignment 规则）。

---

## 0. Identity / where things are

| Item | Value |
|---|---|
| Repo | `github.com/0smboy/Peregrine` |
| Base of this session's work | `cursor/isolated-hyper-filters-a7f8` (the active G0–G7 line; ahead of `cursor/g0-g7-acceptance-1ad4`) |
| Branch — dev environment | `cursor/dev-environment-setup-b1b8` → **[PR #18](https://github.com/0smboy/Peregrine/pull/18)** (draft) |
| Branch — G0–G7 in-repo fixes | `cursor/g0-g7-slo-ec-fixes-b1b8` → **[PR #19](https://github.com/0smboy/Peregrine/pull/19)** (draft, base `cursor/isolated-hyper-filters-a7f8`) |
| This handoff | committed on `cursor/dev-environment-setup-b1b8`; a copy is also at `/opt/cursor/artifacts/SESSION-HANDOFF-20260909.md` |

> Note: `cursor/g0-g7-slo-ec-fixes-b1b8` was cut from `83217ce`. Origin's
> `cursor/isolated-hyper-filters-a7f8` has since advanced (tip `a21e4fe` at time
> of writing), so rebase PR #19 onto the current base before merge if desired.

---

## 1. Dev environment (PR #18) — DONE, verified

The repo had **no linked Cloud Agent environment**. Added:

- `.cursor/environment.json` — `name`, `user: ubuntu`, `install: bash .cursor/install.sh`.
- `.cursor/install.sh` — idempotent bootstrap:
  1. apt: `build-essential pkg-config libssl-dev liberasurecode-dev libjerasure-dev sqlite3 libsqlite3-dev libxml2-dev`
  2. Rust `1.97.0` + `clippy`/`rustfmt`, set default (base image only had 1.83.0; the workspaces pin 1.97.0 via `rust-toolchain.toml`)
  3. `cargo fetch --locked` in each of `swift-rust`, `swift-deploy-rs`, `cosbench-rs`, `autocos`, `swift-console`
  4. `npm ci` in `docs-site`

**Verification evidence (all from actually running it):**
- Fresh draft environment build `bld-20260909-ed698bc5-0d36-4d2c-b4f0-917bb8b21eb3` **SUCCEEDED** from a clean checkout (`liberasurecode`/`libjerasure` installed, rustc 1.97.0, all cargo deps fetched, `npm ci` 500 pkgs, "Peregrine environment ready.").
- All 5 Rust workspaces build release; `swift-console` served the UI on `:9000` wired to a live SAIO cluster (login + Files API returned live data).
- SAIO one-command cluster (`swift-rust/deploy/`) came up (proxy `:8080`, 13 procs); `smoke.sh` = **`SMOKE: PASS`** (replication PUT/GET/DELETE + EC-4-2 6 durable frags + ranged GET).
- `cosbench-rs run --config examples/swift-tempauth.yaml` drove the live cluster: ~6.7k ops main stage, **99.99%** success.
- `docs-site` Astro dev server served HTTP 200.

**How to run locally / on a fresh agent:** the install script does everything.
To bring up the demo cluster and console by hand:
```sh
cd swift-rust && cargo build --release --features swift-proxy-server/ec,swift-object-server/ec
sudo install -m0755 target/release/swift-{account,container,object,proxy}-server target/release/swift-ring-builder /usr/local/bin/
cd deploy && sudo bash saio-setup.sh && sudo bash saio-start.sh &   # proxy :8080, tempauth test:tester/testing
sudo bash smoke.sh                                                  # end-to-end check
# console (needs a deploy-token file; conf/config.dev.json is a local, untracked dev config):
cd ../../swift-console && cargo build --release && printf dev > /tmp/ui-token
./target/release/swift-console conf/config.dev.json                 # :9000
```
> `swift-console/conf/config.dev.json` is intentionally **untracked** (a local
> dev config pointing the console at the SAIO proxy + `/tmp/ui-token`).

---

## 2. G0–G7 in-repo fixes (PR #19) — DONE, verified

Running the runbook's section-1 gates from this VM (`cargo test --workspace
--features ec` + `tools/test-lab` Python harness) surfaced several reds. Three
fixed, one per commit:

| Commit | Fix | Result |
|---|---|---|
| `74908b6` | **SLO heartbeat 404** (`swift-middleware/src/slo.rs`): the Swift 2.9 "etag/size keys required" check ran *before* the segment HEAD, so a non-existent heartbeat segment reported `missing keys` (empty `Errors:`) instead of `<path>, 404 Not Found`. Moved the key check to *after* a 2xx HEAD so existence (404) is reported first; an existing segment still 400s on missing keys. | `slo_put_validation` 36/36; official matrix still green |
| `8d30413` | **`swift-ec` thread-safety** (`swift-ec/src/lib.rs`): `cargo test --workspace --features ec` reproducibly `SIGSEGV`/`double free`d and **aborted the whole workspace run before most crates ran**. liberasurecode 1.6.x is only ever driven single-threaded upstream (PyECLib under eventlet), but the proxy/object servers build an `EcDriver` per request across worker threads. Fix: (a) serialize every FFI entry behind one `Mutex`; (b) `instance_destroy` tears down shared backend state (rs_vand Galois tables + backend `dlopen`) that live peers still use → cache one **resident** instance per `(k,m)` for the process lifetime (as Swift keeps one `ECDriver` per policy) and never destroy it; `EcDriver` is now a cheap handle with a no-op `Drop`. No call-site changes. | 30× parallel (16-thread) runs green; **real production concurrency bug** |
| `356de19` | **Flaky free-space test** (`swift-core/src/fsutil.rs`): `temp_dir_reports_free_space` compared two independent live `statvfs` reads for exact equality; they differed by one 4096-byte block on the shared FS. Now asserts within `max(1%, 64 MiB)`. | 3/3 |

**Verified green:** `swift-middleware` `slo_put_validation` 36/36 · `swift-ec`
30× parallel · `swift-core` `fsutil` 3/3 · `tools/test-lab` `run_unittests.sh`
136/136. Fix #2 **unblocked** the full `cargo test --workspace --features ec`
run so it now completes.

Re-run the in-repo gates:
```sh
cd swift-rust/tools/test-lab && ./run_unittests.sh                        # 136 python tests
cd ../../ && cargo test -p swift-middleware -p swift-core
cargo test -p swift-ec --lib                                             # now parallel-safe
cargo test -p swift-proxy-server --test ec_integration --features ec     # see §3: still 2 red
```

---

## 3. STILL OPEN — the G6 EC-GET crux (do NOT claim green)

`cargo test --workspace --features ec` now completes and reveals **two
pre-existing reds** in `swift-proxy-server/tests/ec_integration.rs`:
- `test_utf8_compat_get_after_post_and_single_frag_rmtree` — the real failure.
- `test_utf8_lonely_frag_head_keeps_post_user_meta` — **collateral**: it hits a
  `PoisonError` on the shared `EC_CLUSTER_LOCK` after the first test panics.
  Fixing the first should clear this one.

**Runtime root cause (captured via the in-test `G6_DIAG` logs):**
The GET carries `X-Backend-Storage-Policy-Index: 0` (the "leaked"/IsolatedIdentity
scenario) against an **EC policy-1** container. `resolve_object_storage_policy(Some(0), 1)`
returns `0` (header wins), so the proxy sends policy-index 0 to the object
servers; they look in the **policy-0 on-disk tree** while the fragments live in
the **policy-1 (EC) tree** → every backend GET 404s → gather sees
`200s=0 idxs=[]` → `reason=empty_buckets` → 404. Only one fragment hash dir was
`rmtree`'d, so 5 fragments remain and a correct GET should reconstruct → 200.

Diagnostic log line to reproduce/trace (proxy):
```
EC GET … reason=object_get_head_async header=Some(0) container_policy=1 policy=0 ec=1 ndata=4 replica=6
EC GET … reason=empty_buckets policy=0 ndata=4 200s=0 idxs=[] saw_404=true
```
Relevant code: `resolve_object_storage_policy` (`swift-proxy-server/src/lib.rs:778`),
`object_get_head_async` / `ec_get_async` / `ec_get_async_inner`
(`swift-proxy-server/src/async_fanout.rs:1201/1308/1387`; round-0 already strips
leaked `X-Backend-Fragment-Preferences`).

**Why it was left untouched (important):**
- The current behavior is **deliberately pinned** by
  `test_expirer_split_brain_ec42_policy0_isolation`
  (`swift-proxy-server/src/lib.rs:12589`), which asserts
  `resolve_object_storage_policy(Some(0), EC42) == 0` (policy-0 isolation /
  expirer split-brain contract). Naively making the container policy win would
  break that pinned test — a genuine design tension the maintainers deferred.
- The failing test was added in `95d58de` ("Piggyback EC GET 404 reason on
  utf8-compat completion") — i.e. as **diagnostics/WIP** for this still-open
  issue, not a regression.
- Per `PEREGRINE-G0-G7-ACTIVE-HANDOFF-20260906.md`, this is exactly the
  field-blocked G6 "proxy_get 404 after fragment loss / gather-decode" theme.

**Suggested next step:** reconcile the two contracts at the right layer — e.g.
keep policy resolution as-is for isolation, but in the EC-GET path detect that
the *container* is EC and locate/gather fragments from the container's policy
tree (or make the object server serve the shared-fragment set) — then confirm
BOTH `ec_integration` tests AND `test_expirer_split_brain_ec42_policy0_isolation`
stay green. This reproduces locally now (no lab SSH needed), so the debug
subagent + `cargo test -p swift-proxy-server --test ec_integration --features ec`
is a tight loop.

---

## 4. Field acceptance (G0–G7) — blocked from this environment

Per `.agent-handoff/PEREGRINE-G0-G7-ACTIVE-HANDOFF-20260906.md` and
`swift-rust/tools/test-lab/G0-G7-ACCEPTANCE-RUNBOOK.md`:
- **GREEN requires SSH to the isolated Swift1/Swift2/Swift4 lab** (isolated rust
  data-plane on `:18080`, `/etc/g6-rust`), which **this cloud VM cannot reach**.
- Only the **package/unit** layer runs here (runbook §1). Everything above is
  package/unit evidence — it does **not** close any gate.
- Do **not** upgrade any gate to GREEN by prose. Do **not** touch production
  `:8080` / VIP `10.0.0.10` / HAProxy / Keepalived / `/srv` mounts.
- Next runner (on Swift2): `freeze-candidate.py` → offline `--offline --locked
  --release --features ec` build → G0 provenance → replay G4/G5/G6 (179
  identities, score with `g6_ledger.py`, no retry-to-PASS) → G7 physical matrix.

---

## 5. Constraints / gotchas for the next agent

- **Honesty (evidence-alignment rule):** cite evidence paths+dates; WARN stays
  WARN; closed A/B levers stay closed; one atomic commit updates all surfaces of
  a claim; run `tools/docs-claim-audit.sh` before claiming 全量更新.
- **Banned terms** in commits/UI copy: the old automation product name, the old
  vendor hostname prefix, AI-marketing jargon in object-storage surfaces.
- **liberasurecode is now safe to call from multiple threads** via swift-ec's
  resident-instance cache — do not "optimize" it back to per-use
  create/destroy, and do not reintroduce `instance_destroy` (it corrupts the
  heap; see §2 / `EC_FFI_LOCK` doc comment).
- **Reporting:** there is **no agent-side timer/subscription** (checked
  `list_subscriptions` → empty); I create none and send no periodic reports. Any
  half-hourly report must be a **dashboard Automation** — disable it in the
  Cursor dashboard (agents can't modify automations from here).

## 6. Exact commit list

```
PR #18  cursor/dev-environment-setup-b1b8
  959debd  Add Cloud Agent dev environment (toolchain + system deps + dep caches)

PR #19  cursor/g0-g7-slo-ec-fixes-b1b8  (base cursor/isolated-hyper-filters-a7f8)
  74908b6  Report SLO segment 404 before the required-key check on the Hyper path
  8d30413  Make swift-ec thread-safe: serialize FFI and keep instances resident
  356de19  Stop free-space test from comparing two live statvfs reads for exact equality
```
