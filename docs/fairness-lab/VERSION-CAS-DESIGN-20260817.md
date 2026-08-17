# Version-index cross-proxy CAS — design 2026-08-17

Wave 9 core engineering item: upgrade the S3 multi-version `index.json`
concurrency control from **in-process CAS** (a generation counter checked
inside one proxy) to a **cross-proxy backend conditional-write CAS**.

Status: implemented on branch `codex/version-cas-20260817` (draft PR, not
merged). Not deployed. Nothing here touches the live fleet.

## 1. The race window on main (before this change)

Every versioned write funnels through the same three steps
(`swift-rust/crates/swift-s3api/src/middleware.rs`):

1. `load_version_index_snapshot` — GET `{bucket}+versions/{hex(key)}/index.json`,
   remembering the Swift ETag and the in-body `generation`.
2. Data-plane work (archive the current object, PUT the new current /
   delete an archive / promote).
3. `cas_save_version_index` — PUT the whole rewritten `index.json`
   (`If-Match: <etag from step 1>` when it existed, else `If-None-Match: *`).

The in-process CAS (`VersionIndex::apply_if_match`, `check_index_generation`)
only compares the generation **a single proxy loaded itself**. Two proxies
each pass their own check. The backend `If-Match` belt on the mirror PUT is
a **silent no-op on the deployed object layer** (§2), so step 3 is
last-writer-wins.

Concrete interleaving (the one the red test pins deterministically):

| | Proxy A: `PUT obj` | Proxy B: `DELETE obj?versionId=v1` |
|---|---|---|
| t1 | loads index gen 2 `[v2, v1]`, etag E2 | |
| t2 | | loads index gen 2 `[v2, v1]`, etag E2 |
| t3 | archives v2, PUTs new current vA | |
| t4 | persists gen 3 `[vA, v2, v1]`, `If-Match: E2` → applied | |
| t5 | | deletes archive `{hex}/v1`, persists gen 3 `[v2]`, `If-Match: E2` → **also applied** |

Result: both clients get 2xx; the index ends at `[v2]`. **vA — a version
acknowledged 200 with `x-amz-version-id` — vanishes from ListVersions**, and
the current object (vA's body) diverges from the index's latest (v2). The
same shape loses a delete (resurrection) when A's write lands last.

PUT-vs-PUT is *partially* self-serialized today (both writers archive the
same old current under one name with `If-None-Match: *`, so one 412s), which
is why the loud losses come from pairs that touch **disjoint** data-plane
objects: PUT vs `DELETE ?versionId`, PUT vs delete-marker creation,
MultiDelete vs anything, MPU-complete (it re-enters `handle_versioned_put`)
vs any of them.

## 2. Conditional-write support, verified in code

What the backend actually enforces decides which CAS designs can work.
Verified on `main` (`fa6b1d1`):

| Semantics | Object-server | Proxy forwards on write | Since | On live Wave-2 object layer (`e1d4f1cc…`)? |
|---|---|---|---|---|
| PUT `If-None-Match: *` → 412 if exists, non-`*` → 400 | `swift-object-server/src/lib.rs` `if_none_match_has_star` (351), enforcement (906–912, 971–975) | `swift-proxy-server/src/lib.rs` `backend_headers` passthrough list (1464–1483, `"if-none-match"`); applied to PUT via `backend_headers(req, true, "object")` (3722) | monorepo import `6c7d91f` (2026-07-30) | **yes** — pre-Wave-2 code |
| PUT `If-Match` → 412 on mismatch/missing | `put_if_match_precondition` (453–470), wired at 982 | same list (`"if-match"`), same commit | `414b76e` (2026-08-16) | **no** — Wave-2 binary predates it; header is silently ignored |
| GET/HEAD conditionals | object-server evaluates | explicit read-header forward (3664–3682) | import | yes |

(Python Swift for reference: object PUT honors only `If-None-Match: *`;
`If-Match` on PUT is not a Python object-server precondition either. The
Rust `If-Match`-on-PUT is a Rust-side extra from the negatives alignment.)

Conclusion: **`If-None-Match: *` is the only conditional write the live
topology (Gate proxy `671bcbaf…` + Wave-2 object layer) enforces end to
end.** Anything built on `If-Match` needs an object-layer rollout first.

## 3. Options

### (A) `If-Match` conditional PUT on `index.json`

The code already sends it. Enforcement requires the object layer at
≥ `414b76e`. Rejected as the primary mechanism: the task criterion is a
scheme effective on today's topology, and the object layer is deliberately
frozen at Wave-2. Also `If-Match` compares the body MD5 per replica —
correct here only because the generation is serialized into the body (no
ABA), but still inert until a rollout. **Kept as a belt**: the mirror PUT
still stamps it, and it hardens automatically when the object layer rolls.

### (B) Generation-fenced create-only commits — chosen

Make the *commit* an object CREATE, which the live layer already makes
atomic per name:

* Fence object: `{hex(key)}/index.g{N:020}.json` (zero-padded so
  lexicographic = numeric), body = the **full index snapshot** at
  generation N. Created with `If-None-Match: *`, never overwritten, never
  deleted. Exactly one writer can own generation N.
* `index.json` stays as the **mirror**: same body, written after the fence,
  same conditional stamping as before. Readers (ListVersions, version
  resolution) keep reading it; old-generation proxies keep working against
  it unchanged.
* Snapshot loads walk fences forward from the mirror
  (`adopt_newer_generation_fences`): GET `g{M+1}`, adopt, repeat until 404
  (bounded by `MAX_GENERATION_PROBES = 100`, fail-closed beyond). If
  anything was adopted the loader heals the mirror best-effort
  (`heal_version_index_mirror`). Steady state is one extra 404 GET per
  write-path snapshot load; ListVersions is untouched (zero read
  amplification on listing).

### (C) Others considered

* Lock objects (create-only lease): needs expiry/cleanup, wedges on crashed
  writers — worse failure modes than immutable fences.
* Separate fence container (`{bucket}+versions+idx`): cleaner listings, but
  a second container to ensure/clean on every bucket lifecycle path.
  Deferred; fences sort in one contiguous block (`index.g…` > all hex
  archive names) and the ListVersions filter (`ends_with("index.json")`)
  skips them.

## 4. Why (B) is safe

* **No same-generation double-apply.** A committed generation is a
  successful create of `g{N}`; the backend 412s every second create.
  Winner semantics are decided at the fence, *before* the mirror write.
* **No forks from crashed writers.** A fence without a mirror write (crash
  between the two) is adopted by the next loader — the fence body is the
  whole snapshot, so recovery is self-contained. Fences are never deleted:
  deleting `g{K}` and re-creating it later would fork history, which is why
  GC needs its own safety proof (§7).
* **Mirror is advisory.** Mirror lag/regression is healed by the forward
  walk; the fence chain is the authority for writers. Readers accept the
  same staleness they already have on an eventually-consistent backend.
* **Reserved namespace.** `is_safe_version_id` now rejects the whole
  `index.*` family, so a poisoned index can never list a fence as a
  version-id and trick the exact-version DELETE into removing one
  (`versioning_store.rs`).

## 5. Client-visible behavior: zero change

* Winner flows are byte-identical (same requests on the mirror, same
  response surfaces, same headers).
* A fence conflict (412) or non-applied fence (202) surfaces
  `version_index_persist_conflict()` → `InternalError` "version index
  persist conflict" — the **same response class the mirror 412/202 path
  produces today**. No new error codes, no AWS-visible 412s.
* ListVersions XML unchanged; fences never leak into it (filter pinned by
  test `list_versions_skips_generation_fences`).
* `tools/strict-s3-parity.py` untouched; the dual-oracle 49/8 surface is a
  design constraint — post-deploy dual-oracle must reproduce 49/8, anything
  else is a regression of this change.
* Retry semantics on conflict: the client retries (standard S3 practice for
  5xx); the retry reloads the snapshot, adopts the winner's fence, and
  proceeds at the next generation. No automatic in-proxy retry is added —
  same as today's CAS-denied behavior.

## 6. Failure modes

| Failure | Behavior | Class |
|---|---|---|
| Fence create 412 (lost the race) | `InternalError` persist-conflict; mirror untouched; data-plane work already done may leave a repairable ghost (next writer repair-inserts the current vid) or a dangling record (exact-version delete already removed the archive) | same class as today's persist-conflict; was a **silent corruption** before |
| Fence create 202 (not Applied) | fail-closed `InternalError` — 202 is never success (same rule as `version_index_persist_202_is_not_success`) | unchanged rule, new call site |
| Mirror write fails after fence applied | client gets today's persist error; commit survives in the fence; next loader adopts + heals | ambiguous failure (client 5xx, effect visible later) — same class as today's "persist failed after data-plane succeeded" |
| Crash between fence and mirror | as above, minus the client error | self-healing |
| Mirror regressed by a slow old writer | forward walk re-adopts; heal rewrites | self-healing; `If-Match` belt eliminates it after object rollout |
| Mirror > 100 generations behind | fail-closed `InternalError` "generation probe overflow" | operator-visible wedge; requires a persistently failing mirror path while fences keep landing |
| Corrupt fence body | fail-closed `InternalError` "version index is invalid" — never commit over unreadable history | new, deliberate |

## 7. Residual risks and follow-up windows

1. **Replica-level races inside one quorum.** Swift evaluates
   `If-None-Match: *` per object-server against its local replica; two
   simultaneous creates can in principle both pass on disjoint quorum
   members. This is Swift-inherent (Python has the same property). The fence
   shrinks the race from "the whole multi-request write window" to "one
   backend create quorum". Not fixable at the proxy; documented, not
   claimed.
2. **Fence growth.** One index-sized JSON per committed write, same
   cardinality as the archives versioning already creates. They inflate
   `+versions` container listings (ListVersions already has a no-pagination
   cap debt at 10k names — pre-existing). Follow-up window: an offline
   compactor that deletes fences `≤ mirror_gen − margin` with an age guard,
   plus the proof that no reader can still probe that low. Until then: no
   GC, by design (deleting a fence re-opens the fork).
3. **Mixed proxy fleet during rollout.** Old-generation proxies write the
   mirror without fencing; they can still lose updates against each other
   and against new proxies. The CAS is effective once **all four proxies**
   run this build. Proxy-only rollout; object layer stays Wave-2.
4. **Dangling records on conflicted exact-version deletes.** The loser
   already deleted the archive object before losing the fence (operation
   order kept from main to avoid any client-visible reordering). The record
   stays listed; its data is gone; a retry of the delete converges (the
   record is removed from the index on the retry's commit). Follow-up
   hardening: commit-then-destroy ordering, taken separately because it
   changes failure-path op order.
5. **Never-acknowledged loser residue.** A writer that staged data-plane
   objects (its new current, or the repair-insert archive of a previous
   loser's ghost current) and then lost the fence leaves index-gated
   garbage: archive objects no committed index lists. They cannot
   resurrect (`resolve_object_version` requires the index record before
   touching archives — the pre-existing orphan rule) and cannot appear in
   ListVersions. Same residue class the mirror-412 path produces today on
   a ≥ `414b76e` object layer. Cleanup on conflict would itself race
   (another writer may already have observed the staged object), so the
   residue is accepted and left to the same follow-up compactor window as
   fence GC. The stress test pins the acknowledged-scope invariants: an
   acknowledged version's archive is always listed, an acknowledged delete
   leaves neither record nor object.

## 8. Activation prerequisites

**None for the fence CAS** — it rides `If-None-Match: *`, enforced by every
object-server generation since the monorepo import and forwarded by every
proxy generation. Ship = roll the four proxies to this build (normal
generation rollout + post-roll dual-oracle must stay 49/8).

The mirror `If-Match` belt (defense-in-depth against mirror regression)
activates by itself when the object layer eventually rolls to ≥ `414b76e`.
No coordination required; nothing depends on it.

## 9. Red → green proof

Hermetic harness in `swift-s3api` unit tests: several `S3Api` instances
(one per simulated proxy) share one `SharedSwiftBackend` store implementing
exactly the live semantics from §2 (`If-None-Match: *` enforced, `If-Match`
on PUT ignored). Deterministic interleavings use request gates parked
*inside the mock* — product code has no test hooks.

* **Red commit** (tests only, CI red on the PR): the §1 interleaving, plus
  an N-writer barrier stress. Failing assertion on main:
  `backend applied two index writes without cross-proxy CAS (generation
  sequence not strictly increasing): [1, 2, 3, 3]`.
* **Green commit**: fence protocol above; same invariants pass. The
  invariant was refined in the green commit to the precise CAS property:
  the heal path may legally re-write a generation with **identical**
  content; two **divergent** bodies for one generation are the lost update.
  Additional pins: fence-412 → conflict + mirror untouched, fence-202
  fail-closed, fences are create-only, crashed-fence adoption + heal,
  fences never leak into ListVersions.
