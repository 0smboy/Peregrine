# anonymous + versioned GET/HEAD cold archive-on-transition

**VERDICT: GREEN** (unit only; no fleet mutate)

| | |
|---|---|
| When | 2026-08-13 11:38 SGT (03:38 UTC) |
| Mac branch | `feat/cold-localdir-restore-77dd9f4` |
| Remote | swift3 `CARGO_HOME=/root/work/peregrine-cargo-home` |
| Tree | `/root/work/peregrine-anon-ver-cold/swift-rust` (rsync from Mac) |
| Suite | `cargo test -p swift-s3api --lib` → **247 passed** |

## Hook sites (middleware.rs)

1. **`maybe_stamp_due_cold_on_anonymous_get_head`** (sibling after auth `maybe_archive_due_cold_on_get_head`)
   - Meta/deny only. Does **not** `stamp_auth`, POST, backend-archive, or hot-delete.
   - Honesty: unsigned path has no Swift auth token; object POST would fail. Stamp due-cold headers in-memory; caller `deny_if_transition_blocks_get`.
2. **`dispatch_anonymous`** object GET/HEAD 2xx — calls (1) then existing transition deny.
3. **`finish_versioned_get_head`** — auth present: `maybe_archive_due_cold_on_get_head` (archive + POST + optional hot-delete) then `translate_object_get_head`.
4. **`handle_versioned_get_head`** success paths (latest, `versionId=null`, matching current, `{bucket}+versions` archive) all go through (3). Persist target is current object or versions-container archive name.

Did **not** edit the hot-delete body of `maybe_archive_due_cold_on_get_head` (POST/PUT empty). Versioned path passes `api.cold_delete_hot_after_archive` through.

## Tests added

- `anonymous_get_due_cold_transition_meta_deny_no_post`
- `anonymous_head_due_cold_transition_meta_deny_no_post`
- `anonymous_get_due_cold_with_backend_still_no_post_honesty`
- `versioned_get_due_cold_transition_archives_and_posts`
- `versioned_get_version_id_due_cold_archives_and_posts`

Focused filter: 9 passed (includes existing auth GET/HEAD archive tests). Full lib: 247/247.

## Claim boundary

Lab LocalDir/Memory only. Not tape/Glacier cloud. Not fleet-deployed.
Anonymous: deny consistent; **no persist**. Versioned: archive+POST when SigV4/V2 auth present.
