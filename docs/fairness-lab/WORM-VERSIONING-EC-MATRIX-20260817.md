# WORM clock-health wiring audit + EC × versioning × WORM/cold interaction matrix

Date: 2026-08-17 · Base: `main@fa6b1d1` · Branch: `codex/worm-fault-matrix-20260817`
Scope: hermetic only — tests and this document. No production code changed, no
live data plane touched. Cluster access was read-only (`chronyc tracking`,
`timedatectl`, `chronyc sources`).

All `file:line` references are against `main@fa6b1d1`. New tests land in the
same commit as this document; production line numbers are unchanged because
every addition sits inside `#[cfg(test)]` modules.

---

## 1. `clock_ok` wiring audit — authoritative answer

**Verdict: the clock-health bit is dead wiring.** There is no runtime clock
health source anywhere in the workspace. Every production call path reaches
the `_with_clock` decision functions through a wrapper or literal that pins
`clock_ok = true`. The `false` branch is reachable only from unit tests.

### 1.1 Decision layer (swift-s3api / object_lock_worm.rs)

| Entry | clock deny points | Wrapper pinning `true` |
|---|---|---|
| `evaluate_retention_update_with_clock` (`object_lock_worm.rs:471`) | requested COMPLIANCE (`:478-480`), existing COMPLIANCE (`:495-497`) | `evaluate_retention_update` (`:459-466`, literal `true` at `:465`) |
| `evaluate_object_version_worm_with_clock` (`:219`) | via `evaluate_lock_state` (`:244-246`) | `evaluate_object_version_worm` (`:208-214`, literal `true` at `:213`) |
| `evaluate_lock_state` (`:232`) | `:244-246` | (called by the two above) |
| `evaluate_object_version_worm_from_backend` (`:291`) | via `evaluate_lock_state` | **no production caller at all** (tests only; see §5 GD-3) |

### 1.2 Production entry points and what they pin

| Production entry | Path | clock source |
|---|---|---|
| `worm_guard` → `evaluate_object_version_worm` | `middleware.rs:2600-2610` | wrapper ⇒ `true` |
| — serves `worm_check_object` (unversioned DELETE / overwrite PUT / MPU complete) | `middleware.rs:2612-2624`, dispatch `:2253-2261`, MPU `:5286` | wrapper ⇒ `true` |
| — serves `?versionId` DELETE | `middleware.rs:4290` | wrapper ⇒ `true` |
| — serves suspended null-version overwrite / archived-null check | `middleware.rs:3924`, `:3740` | wrapper ⇒ `true` |
| `handle_retention` PUT → `evaluate_retention_update` | `middleware.rs:3039-3044` | wrapper ⇒ `true` |
| Native `/v1` gate `deny_locked_native_mutation` → `native_mutation_allowed_for` | `swift-object-server/src/lib.rs:437-443` (call sites `:988`, `:1388`, `:1680`) | **literal `true` at `lib.rs:442`**, comment at `:436`: "clock_ok stays true until a clock-health signal exists" |

`unix_now()` (`middleware.rs:2566-2572`) is a bare `SystemTime::now()` read;
`SystemTime` failure degrades to `0`, which would make every active retention
read as un-expired (fail-closed direction) — noted for completeness.

There is no config knob, no chrony/NTP probe, no adjtimex call, and no header
that can flip the bit (repo-wide grep for `chrony|ntp|timedatectl|clock_health`
matches only ops artifacts under `tools/test-results/` and Ansible plans).
The module docs say this honestly (`object_lock_worm.rs:4-5`,
`worm_native_gate.rs:6-8`); this audit confirms the code matches the docs.

### 1.3 Four-node NTP reality (read-only capture, 2026-08-17 ≈13:06 UTC)

| Node | chronyd | Stratum | System offset | RMS offset | Root dispersion | timedatectl |
|---|---|---|---|---|---|---|
| swift1 | active | 2 | 0.751 ms slow | 0.193 ms | 1.13 ms | `NTPSynchronized=yes` |
| swift2 | active | 2 | 0.023 ms slow | 0.059 ms | 1.46 ms | `NTPSynchronized=yes` |
| swift3 | active | 4 | 0.177 ms slow | 0.070 ms | 1.81 ms | `NTPSynchronized=yes` |
| swift4 | active | 2 | 0.341 ms fast | 0.268 ms | 8.34 ms | `NTPSynchronized=yes` |

All four nodes are chrony-synchronized with sub-millisecond offsets against
public pool servers (poll interval ~1024 s, reach 377). The fleet is healthy
today, but nothing feeds that fact into the WORM decision path, and nothing
would deny COMPLIANCE claims if a node drifted or chronyd died.

### 1.4 Design proposal — clock-health source (proposal only, not implemented)

1. **Probe.** A per-node poller (object-server and the s3api-carrying proxy)
   reads chrony via `chronyc -c tracking` (csv) or the refclock-agnostic
   `adjtimex()` `STA_UNSYNC` flag as fallback. Poll every 30–60 s.
2. **Health predicate.** `clock_ok := synchronized && |system_offset| ≤
   worm_clock_max_offset_ms && root_dispersion ≤ worm_clock_max_dispersion_ms
   && sample_age ≤ 2×poll_interval`. Suggested defaults: offset 500 ms,
   dispersion 1000 ms — generous against the observed sub-ms reality, tight
   enough to catch real drift. A stale or unreadable sample is **unhealthy**
   (fail-closed).
3. **Config.** `worm_clock_health = static-true | chrony` (default
   `static-true` preserves today's behavior bit-for-bit); thresholds as the
   two knobs above. Rollout: lab first with `chrony`, watch deny metrics.
4. **Wiring.** The poller exposes an `Arc<AtomicBool>` (plus a "last sample"
   timestamp). The three production entries switch to the `_with_clock`
   variants: `worm_guard` and `handle_retention` take the bit from S3Api
   state; `deny_locked_native_mutation` takes it from ObjectServer config
   state, replacing the literal at `lib.rs:442`.
5. **Semantics already settled by tests.** Unhealthy clock denies COMPLIANCE
   set/claim/expiry decisions and leaves GOVERNANCE and legal-hold behavior
   untouched — exactly the behavior locked by the unit tests in §2, so the
   future wiring change needs no semantic re-derivation.
6. **Non-goals.** No cross-node consensus (each node judges its own clock);
   no request-time chronyc exec (poller only); no attempt to "correct" time.

---

## 2. Fault-injection tests added (hermetic, additive only)

No existing test or assertion was modified. 24 always-on tests + 1 `#[ignore]`
bug-recording test.

### swift-s3api · `object_lock_worm.rs` (unit, decision layer)

| Test | Behavior locked |
|---|---|
| `clock_unhealthy_denies_updates_touching_existing_compliance` | Bad clock denies retention updates that touch an existing COMPLIANCE record: GOVERNANCE-over-COMPLIANCE, COMPLIANCE extension, and *apparently expired* COMPLIANCE (expiry cannot be trusted with a bad clock) — all `ClockUnhealthy` |
| `clock_unhealthy_leaves_governance_paths_intact` | Bad clock changes nothing for GOVERNANCE: new set allows, shorten-with-bypass allows, shorten-without-bypass still `GovernanceBypassRequired`, expired allows, active+bypass allows |
| `backend_eval_clock_unhealthy_denies_compliance_only` | `evaluate_object_version_worm_from_backend`: 200+COMPLIANCE+bad-clock ⇒ `ClockUnhealthy`; 200+GOVERNANCE ⇒ still `GovernanceRetention`; 404 ⇒ `Allow` |

### swift-object-server · `worm_native_gate.rs` (unit, native `/v1` gate)

| Test | Behavior locked |
|---|---|
| `native_clock_ok_false_expired_compliance_still_denied` | Expired COMPLIANCE + bad clock ⇒ deny (healthy clock ⇒ allow); GOVERNANCE + effective bypass unaffected by clock |
| `native_half_lock_fields_deny` | Retain-until-without-mode and unknown-mode-with-valid-date both deny on PUT/POST/DELETE |
| `native_gate_should_allow_tagging_only_post_on_locked_object` — **`#[ignore]`, records a real bug** | Asserts the DESIRED (AWS) behavior: tagging-only / restore-only metadata POST on a locked object should be allowed. Currently denied — see §5 BUG-1 |

### swift-s3api · `middleware.rs` (S3 dispatch level, mock Swift backend)

Malformed persisted lock state — fail-closed as `InternalError`, never
reinterpreted, destructive op never reaches the backend:

| Test | Behavior locked |
|---|---|
| `malformed_persisted_lock_delete_fails_closed_internal_error` | DELETE × {unknown mode, corrupt date, mode-only, date-only} ⇒ 500 `InternalError`, no backend DELETE |
| `malformed_legal_hold_value_blocks_delete_fail_closed` | `Legal-Hold: maybe` ⇒ 500, no backend DELETE |
| `malformed_persisted_lock_overwrite_put_fails_closed` | Overwrite PUT over corrupt lock ⇒ 500, no backend PUT |
| `retention_get_on_malformed_persisted_lock_is_internal_error` | GET `?retention` over corrupt lock ⇒ 500, corrupt state not echoed |
| `retention_put_on_malformed_persisted_lock_fails_closed` | PUT `?retention` over half-persisted record ⇒ 500, no sysmeta POST |

Persist-layer backend failures — 5xx is never "no lock":

| Test | Behavior locked |
|---|---|
| `delete_backend_head_5xx_fails_closed_without_delete` | Lock-state HEAD 503 ⇒ 500 `InternalError`, DELETE never forwarded |
| `retention_put_backend_failures_do_not_succeed` | Resolve HEAD 502 ⇒ 500 before evaluation; sysmeta POST 503 ⇒ 500, never reported as 200 |

Governance bypass matrix (header × IAM grant, both modes; complements the four
existing tests):

| Test | Behavior locked |
|---|---|
| `governance_bypass_header_without_iam_grant_denies_delete` | GOVERNANCE, header only ⇒ 403 |
| `governance_iam_grant_without_header_denies_delete` | GOVERNANCE, grant only ⇒ 403 |
| `compliance_bypass_partial_bits_deny_delete` | COMPLIANCE, header-only and grant-only ⇒ 403 |
| (existing) `governance_bypass_header_allows_delete`, `compliance_bypass_header_still_denies_delete`, `retention_future_blocks_delete`, `invalid_governance_bypass_header_is_rejected_before_delete` | GOVERNANCE both-bits allow; COMPLIANCE both-bits deny; neither-bit deny; malformed header value ⇒ 400 before any delete |

Versioning × WORM interactions:

| Test | Behavior locked |
|---|---|
| `versioned_put_over_compliance_locked_current_creates_new_version` | Enabled bucket: PUT over a COMPLIANCE-locked current version is allowed; the locked version is archived and retrievable; the new version inherits no lock and its exact-version delete promotes the locked version back |
| `versioned_delete_marker_allowed_over_legal_hold_version` | DELETE (no versionId) over a legal-hold version writes a delete marker only; the held version survives |
| `versioned_delete_compliance_version_denied_current_and_archived` | `DELETE ?versionId` on a COMPLIANCE version ⇒ 403 while current AND after archival (lock sysmeta survives `copy_version_payload_headers`, `middleware.rs:3654-3673`) |
| `versioned_governance_bypass_delete_removes_version` | `DELETE ?versionId` on GOVERNANCE: no header ⇒ 403 even with grant; header+grant ⇒ 204 and the version is gone |
| `versioning_suspend_on_lock_bucket_is_invalid_bucket_state` | PUT `?versioning` Suspended on a lock-configured bucket ⇒ 409 `InvalidBucketState` (`middleware.rs:3402-3427`) |
| `suspended_overwrite_and_delete_of_locked_null_version_denied` | Suspended bucket (defense-in-depth state): PUT and DELETE that would destroy a locked null version ⇒ 403; the null version survives |

MPU and cold-tier interactions:

| Test | Behavior locked |
|---|---|
| `mpu_complete_stamps_bucket_default_retention` | CompleteMultipartUpload into a default-retention bucket stamps `COMPLIANCE` + now+2d onto the manifest PUT (`middleware.rs:5297`) |
| `mpu_complete_over_locked_object_denied` | Complete landing on a COMPLIANCE-locked key (unversioned) ⇒ 403 before the manifest PUT (`middleware.rs:5286`) |
| `retention_ops_allowed_on_cold_transitioned_object` | Cold (transitioned GLACIER) object: GET `?retention` answers the record, PUT `?retention` extends it, while the data GET stays 400 `InvalidObjectState` |

---

## 3. Interaction matrix

Columns: **Expected semantics** (AWS S3 Object Lock user guide / API reference
semantics, adapted where Swift differs by design) · **Code today** ·
**Tests today** · **Gap class** (`OK` / `GAP-TESTABLE` / `GAP-DESIGN`).

| # | Scenario | Expected semantics (basis) | Code today | Tests today | Gap |
|---|---|---|---|---|---|
| R1 | Enabled-versioning bucket: PUT new version onto a key whose current version holds active retention | Allowed. Lock protects the *version*, not the key; overwrite mints a new version, prior version remains (AWS: "Object locks apply to individual object versions only") | `handle_versioned_put` archives the current version without a WORM check in Enabled mode (`middleware.rs:4035-4046`, `3896-3942`); lock sysmeta survives archival (`:3654-3673`) | NEW `versioned_put_over_compliance_locked_current_creates_new_version` | OK |
| R2 | Delete marker created over a version under legal hold | Allowed. A simple DELETE only adds a delete marker; it removes no version, so legal hold does not block it (AWS DELETE-on-versioned semantics) | `handle_versioned_delete` no-versionId path writes the marker after archiving current (`middleware.rs:4363-4462`); no WORM check on the non-destructive path | NEW `versioned_delete_marker_allowed_over_legal_hold_version` | OK |
| R3 | `DELETE ?versionId` on a COMPLIANCE-protected version (current or non-current) | Denied `AccessDenied` until retain-until passes; no bypass exists for COMPLIANCE | `worm_guard` on the resolved version before any index mutation (`middleware.rs:4280-4295`) | NEW `versioned_delete_compliance_version_denied_current_and_archived`; unversioned analogues pre-existing (`retention_future_blocks_delete`, `compliance_bypass_header_still_denies_delete`) | OK |
| R4 | `DELETE ?versionId` on a GOVERNANCE-protected version with `x-amz-bypass-governance-retention: true` + `s3:BypassGovernanceRetention` | Allowed with header AND permission; denied with either alone (AWS governance bypass contract) | `governance_bypass_context` requires explicit IAM allow (`middleware.rs:2673-2700`); `worm_guard(bypass)` at `:4290` | NEW `versioned_governance_bypass_delete_removes_version` + bypass matrix tests (§2); unversioned allow path pre-existing (`governance_bypass_header_allows_delete`) | OK |
| R5 | MPU complete into a bucket with default retention rule | Completed object gets the bucket default lock stamped at complete time (AWS: default retention applies to new objects incl. MPU) | Unversioned: `apply_bucket_default_retention` on the manifest PUT (`middleware.rs:5297`); versioned: same inside `handle_versioned_put` (`:4090`); explicit request headers win (`apply_default_retention_headers` no-op when retain-until present, `object_lock_worm.rs:686-688`) | NEW `mpu_complete_stamps_bucket_default_retention` (unversioned path); pre-existing `put_stamps_default_retention_from_bucket_object_lock` (plain PUT) | OK — versioned-MPU default-stamp wiring (`:4090`) not directly driven by a test; shared function tested. Residual: GAP-TESTABLE (recorded, low risk) |
| R6 | MPU complete landing on an existing locked key | Overwrite semantics: denied in an unversioned bucket while locked; in Enabled versioning it becomes a new version (R1) | `worm_check_object` before manifest PUT (`middleware.rs:5286`); versioned branch delegates to `handle_versioned_put` (`:5269-5284`) | NEW `mpu_complete_over_locked_object_denied` | OK |
| R7 | Retention/legal-hold subresources on a cold (transitioned) object | Allowed. `GetObjectRetention` / `PutObjectRetention` / legal-hold are metadata ops and work on archived storage classes; only data GET needs restore (AWS Glacier + Object Lock interplay) | `handle_retention` / `handle_legal_hold` never consult `transition_blocks_get`; data GET denial sits in the GET translation path only (`middleware.rs:1230-1237`, `:2465`, `:2546`) | NEW `retention_ops_allowed_on_cold_transitioned_object` | OK |
| R8 | Cold transition / restore of a locked object | Transition and restore do not alter lock state; restore-window stamps must not be blocked by the lock | s3api path: restore is a metadata POST, no WORM gate (correct). Native `/v1` gate wrongly denies restore/tagging sysmeta POSTs on locked objects — see BUG-1 | `#[ignore]` repro `native_gate_should_allow_tagging_only_post_on_locked_object` | **GAP-DESIGN / BUG-1** (recorded; fix belongs to a code window) |
| R9 | Suspended versioning × Object Lock | AWS forbids the *configuration*: suspending versioning on a lock bucket ⇒ 409 `InvalidBucketState`; lock config PUT force-enables versioning. If the state nevertheless exists, overwriting the null version is destructive and must honor the lock | Suspend guard `middleware.rs:3402-3427`; lock-config PUT atomically re-enables versioning (`:4992-4998`); null-version destruction WORM-checked (`:3924`, `:3740`, `:4382-4405`) | NEW `versioning_suspend_on_lock_bucket_is_invalid_bucket_state`, `suspended_overwrite_and_delete_of_locked_null_version_denied` | OK |
| R10 | Corrupt persisted lock metadata (any shape) on destructive or lock-subresource ops | Fail closed: surface an error, never treat as unlocked, never reinterpret (no AWS analogue — Swift-side durability contract) | `object_version_lock_state` / `persisted_retention` strict (`object_lock_worm.rs:190-205`, `:430-453`); `worm_guard` maps to `InternalError` (`middleware.rs:2603-2607`); `handle_retention` same (`:3046-3057`) | NEW: 5 middleware tests (§2); pre-existing unit `malformed_persisted_lock_fails_closed`, `persist_malformed_is_deny_not_unlocked` | OK |
| R11 | Backend HEAD/POST failure during lock evaluation or retention write | 5xx is not "no lock": abort the operation with an error; never let the destructive op proceed; never report success | `control_head_object` maps non-2xx/404 to error (`middleware.rs:2579-2598`); `worm_check_object` propagates (`:2612-2624`); retention POST result mapped (`:3074-3079`) | NEW `delete_backend_head_5xx_fails_closed_without_delete`, `retention_put_backend_failures_do_not_succeed`; unit `persist_backend_5xx_is_deny_not_unlocked` | OK |
| R12 | `clock_ok=false` behavior (all paths) | COMPLIANCE set/claim/expiry decisions deny; GOVERNANCE and legal-hold unaffected (in-repo contract; no AWS analogue) | Decision layer complete and correct (`object_lock_worm.rs:478-480`, `:495-497`, `:244-246`; `worm_native_gate.rs:100-102`) — but **no production path can ever pass `false`** (§1) | NEW: 3 unit + 2 native tests (§2); pre-existing `clock_ok_false_denies_compliance_claim`, `clock_ok_false_denies_compliance` | **GAP-DESIGN** (GD-1): enforcement exists, signal does not |
| R13 | EC-policy container × all rows above | EC must be transparent to Object Lock: policy selection changes placement/encoding, not S3 semantics | Verified by construction: every WORM decision input is method + lock sysmeta + time + bypass — no storage-policy parameter exists in `object_lock_worm.rs` or `worm_native_gate.rs` APIs; lock sysmeta rides ordinary object metadata, which EC engines persist unchanged; the mock-backend tests in §2 are policy-agnostic by the same argument. CI additionally runs the object-server/proxy EC slice (`.github/workflows/ci.yml` "EC slice": `--features swift-proxy-server/ec,swift-object-server/ec`), which includes every `worm_native_gate` test under EC features | Transparency argument + CI EC slice; no hermetic fixture drives S3 lock ops through a real EC pipeline end-to-end | OK for the s3api/gate layers (verification method documented). Residual live EC×WORM e2e: **GAP-DESIGN** (GD-4, needs a lab window) |
| R14 | Multi-delete (`POST ?delete`) entries hitting locked objects | Per-entry `AccessDenied` in the error list; unlocked entries in the same batch still delete; per-entry bypass honored | `handle_multi_delete` reuses `governance_bypass_context` + `worm_check_object` / `handle_versioned_delete` per entry (`middleware.rs:3103-3193`) | None dedicated (shared enforcement points tested individually) | GAP-TESTABLE (recorded; batch-shape assertions still unproven) |
| R15 | Copy (`X-Amz-Copy-Source`) onto a locked destination; copy + explicit lock headers | Destination overwrite obeys the same WORM rules; explicit lock headers and bucket defaults apply to the new object | Copy rides the PUT paths: unversioned `worm_check_object` `:2253`, versioned archive path `:4035-4046`; lock headers via `apply_request_object_lock_headers` `:2244`, `:4070` | None dedicated (shared paths tested via plain PUT) | GAP-TESTABLE (recorded) |

Tally: **OK 10** (R1–R7 minus R5 residual, R9, R10, R11) · **GAP-TESTABLE 3**
(R5 residual, R14, R15) · **GAP-DESIGN 2 rows** (R12/GD-1, R13 residual/GD-4)
plus **BUG-1** on R8. The §5 register expands GAP-DESIGN to 4 items because
GD-2/GD-3 are cross-cutting rather than row-specific.

---

## 4. Existing assertions vs AWS semantics — conflicts found

None that require changing an existing assertion. One deviation is recorded as
GD-2 below (behavior is *stricter* than AWS, existing tests assert the current
stricter behavior; no existing test contradicts AWS on an allow-path).

---

## 5. Gap register

### BUG-1 (real bug, recorded with `#[ignore]` repro)

Native `/v1` gate denies non-lock metadata POSTs on locked objects.
`is_s3_lock_control_plane_post` (`worm_native_gate.rs:122-143`) exempts only
lock-sysmeta POSTs; any other persistable header (`is_object_persistable_header`,
`:174-193`) classifies the POST as a data overwrite. Consequences wherever the
Rust object-server is deployed in the path: S3 `PutObjectTagging` /
`DeleteObjectTagging` (POST `X-Object-Sysmeta-S3-Tagging`,
`middleware.rs:4574-4605`) and `RestoreObject` (POST restore sysmeta) return
403 on WORM-locked objects. AWS allows all three: Object Lock protects data
and lock state, not tags or restore status; Swift-native POST is metadata-only
and never rewrites data. Mitigation today: the gate is documented experimental
/ not live-proven (`worm_native_gate.rs:2-8`), and the s3api-proxy path does
not WORM-gate these POSTs (correct). Repro:
`native_gate_should_allow_tagging_only_post_on_locked_object` (`#[ignore]`,
asserts desired behavior; un-ignore with the fix). Suggested fix direction
(code window, not this branch): teach the classifier a whitelist of
non-destructive sysmeta POST families (tagging, restore, ACL JSON), or exempt
metadata-only POST entirely on the native path and rely on lock-sysmeta
deny rules for the lock keys themselves.

### GAP-DESIGN

- **GD-1 · clock_ok dead wiring.** Full audit in §1; proposal in §1.4. The
  security bit exists, is correct, is tested — and can never fire in
  production today.
- **GD-2 · bypass-header early deny is stricter than AWS.** With
  `x-amz-bypass-governance-retention: true` and no
  `s3:BypassGovernanceRetention` grant, `governance_bypass_context`
  (`middleware.rs:2673-2700`, dispatch `:2165-2181`) returns 403 before the
  object's lock state is even read — including for unlocked objects. AWS
  defines the failure only for governance-locked targets; a stray header on
  an unlocked object is most likely ignored there. Fail-closed and defensible;
  recorded as a deviation, not changed.
- **GD-3 · experimental persist/CAS surface unwired.**
  `evaluate_object_version_worm_from_backend`, `lock_state_from_backend_status`,
  `persist_is_unlocked`, and the whole `lock_if_match_*` token family
  (`object_lock_worm.rs:257-341`) have no production callers;
  `HDR_LOCK_IF_MATCH` is minted nowhere and honored nowhere
  (`object_lock_worm.rs:28-29`, `worm_native_gate.rs:6-8`). Consequence:
  lock updates via `?retention`/`?legal-hold` POSTs are last-writer-wins; a
  concurrent shorten race has no CAS protection (COMPLIANCE shorten is still
  blocked by evaluation, but two racing GOVERNANCE writers can interleave).
  Recorded; the tested `worm_check_object` path covers today's actual 5xx
  fail-closed behavior (R11).
- **GD-4 · EC × WORM live end-to-end.** Hermetically unprovable that a real
  EC-policy container + reconstructor round-trip preserves lock sysmeta and
  enforcement under fragment loss. The layer argument + CI EC slice (R13)
  covers the decision code; the storage round-trip needs a lab window with an
  EC policy ring (out of scope for this task's hard boundaries).

### GAP-TESTABLE (recorded, not closed here)

- **GT-1 (R5 residual).** Versioned MPU complete default-retention stamping
  (`middleware.rs:4090`) — shared function tested elsewhere; the MPU→versioned
  wiring itself has no dedicated test.
- **GT-2 (R14).** Multi-delete batch shape: locked entries must come back as
  per-entry `AccessDenied` while unlocked siblings delete; per-entry bypass.
- **GT-3 (R15).** Copy onto locked destinations and copy-with-lock-headers /
  default-retention stamping on the copy path.

---

## 6. Verification

- Hermetic: all new tests run inside `cargo test --workspace` with the mock
  `NextFn` Swift backend / plain header dicts. No network, no cluster, no
  time mocking beyond explicit `now_unix` parameters.
- CI: `.github/workflows/ci.yml` gates `cargo test --workspace --locked` plus
  the EC slice on every PR; fmt/clippy are report-only there (pre-existing
  drift), unchanged by this branch.
- Cluster: read-only `chronyc tracking` / `chronyc sources` / `timedatectl`
  on swift1–4 only (§1.3). No writes, no daemon/VIP/HAProxy/pyswift changes,
  no AUTH_lab/AUTH_test/mytest data touched.
- Untouched as required: `tools/strict-s3-parity.py`, every existing test and
  assertion (additions only), all production code paths.
