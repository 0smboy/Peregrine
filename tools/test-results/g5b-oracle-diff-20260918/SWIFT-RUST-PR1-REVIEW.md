# Review of `0smboy/swift-rust` PR #1 — 2026-09-18

Read with the fine-grained token the owner supplied on 2026-09-18. Nothing was
merged, closed, or commented on.

## What it is

| Field | Value |
|---|---|
| Title | `lab tip 9531eb62: H71–H89 DeferredTagging working-tree snapshot` |
| Branch | `lab/tip-9531eb62-h89` → `claude/object-replicator` |
| Head | `94e401b61c4479b078cbd4660bffda441cf0307c` (1 commit) |
| Base | `575b735ce015a967eb4a078981bb2f12c7fb350a` |
| State | open, `mergeable: true`, `mergeable_state: clean` |
| Size | 401 files, +1 129 631 / −20 421 |

The layout is right: the base branch already carries a `rust/` subtree
(`tree cb29ed9b…`) and the PR updates it to `tree 9aa4bf3d…`. It is a real diff
against the existing tree, not a duplicated second copy.

## Blocking hygiene problem: 70 lab scratch files

The snapshot was taken from a working tree, so it carries the per-tip backup
files the lab makes before each attempt:

| File | Backup copies in the PR |
|---|---:|
| `crates/swift-s3api/src/iam.rs` | 28 |
| `crates/swift-s3api/src/middleware.rs` | 19 |
| `crates/swift-s3api/src/acl_cors.rs` | 2 |
| `sigv4.rs`, `select.rs`, `response.rs`, `object_lock_worm.rs`, `bucket_config.rs` | 1 each |
| … 70 files total, e.g. `iam.rs.bak-h17-pre`, `middleware.rs.bak-h6c-pre` | **17 415 added lines** |

Per-file statuses over all 401 files: 214 added, 179 modified, 8 removed. The
seven `rust/tools/test-results/*.log` entries are among the **removals** — the
PR deletes stale logs, which is an improvement, not a problem. An earlier draft
of this note had that backwards.

Merging as-is would import 70 dead source copies into the engine repository,
where they would be indexed, greppable, and confusing forever — and they defeat
the purpose of G0's "one immutable source identity", since the tree would carry
eight historical variants of `iam.rs` alongside the real one.

### The strip is prepared and verified, but not pushed

The owner approved stripping them on 2026-09-18. The rewrite was prepared and
checked, then blocked on token scope:

- amended snapshot commit `e5752da` (was `94e401b6`), authorship preserved
- `rust/` blob count 465 → **395**
- diff against the published tree: **70 removed, all matching `.bak-`, 0 added,
  0 content changes among the kept files**

The supplied fine-grained PAT is read-only for Contents (`POST /git/blobs` →
`403 Resource not accessible by personal access token`), so neither `git push`
nor the API can publish it. Either add **Contents: Write** to the token and this
becomes one command, or run it locally:

```bash
git clone --branch lab/tip-9531eb62-h89 git@github.com:0smboy/swift-rust.git
cd swift-rust
git rm --cached $(find rust -name '*.bak-*')
find rust -name '*.bak-*' -delete
git commit --amend --no-edit
git push --force-with-lease origin lab/tip-9531eb62-h89
```

`--force-with-lease` is deliberate: it refuses if anyone else has moved the
branch since. Adding **Checks: Read** to the token would also let CI state be
confirmed before merge.

## CI status could not be read

`GET /commits/{sha}/check-runs` and `/status` both return
`403 Resource not accessible by personal access token`. The fine-grained token
covers contents/pull-requests/metadata but not Checks. If CI state matters
before merge, either add Checks: Read to the token or read it in the GitHub UI.

## The tip's source tree is gone from the lab — this is a G0 dead end

The 2026-09-15 handoff names `/root/work/src-60dd0f6/swift-rust` as the lab tip
source tree. **That path no longer exists on swift1.** The only surviving tree
is `/root/work/swift-rust`, and it is not the tip: comparing every file by
`git hash-object` against the PR's `rust/` tree gives

```
paths in both     : 270
  identical blob  :  76
  differing blob  : 194
only in PR        : 195
only in lab tree  :   0
```

So the tip binary `9531eb62` (still live on `:18080`) has no source tree on the
lab that produced it. Its source survives only as this PR commit and the release
tarball, whose published digest does verify:

```
peregrine-swift-rust-9531eb62-source.tar.gz
sha256:174ba5070c036eb50a8a84b8229607b58a80b36ed338e77c9a599144680409f2
```

which is exactly the sha256 the handoff claimed.

The consequence for G0 is worth stating plainly: G0 wants commit, tree,
lockfile, toolchain, features, artifact SHA and the live `/proc/exe` SHA to all
agree. For this tip line the chain can no longer be closed by inspection — it
could only be re-established by rebuilding from `94e401b6` and getting a binary
whose sha256 equals `9531eb62…`, and a release Rust build is not bit-reproducible
across environments by default. **Treat the `9531eb62` tip line as permanently
G0-incapable**, keep it as lab evidence, and build the next candidate from a
real commit in this repository from the start so the identity chain exists
before any scoring begins.
