# Peregrine G6 GREEN lab pre-release handoff

Date: 2026-09-01 (Asia/Singapore)  
Scope: Rust Swift, Swift Console, Swift Deploy, Cosbench-RS, and Autocos only  
Excluded: swiftfuse  
Production verdict: **NO-GO** (`G7 NOT ACCEPTED`, `G8 BLOCKED`)

## Release identity

- Canonical repository: `https://github.com/0smboy/Peregrine.git`
- Accepted Rust Swift source: `17adf0bfa78b30b2a7eed9f39836e0d63c715d2c`
- Canonical integration and auxiliary build commit:
  `7883bbb1d021277390215e18afeb414b5b612339`
- Final release commit: `b7062862ab348d17116a3338f0f11b20e29ea722`
- Release tag: `g6-green-20260831`
- Release class: GitHub **pre-release**, lab validation only
- GitHub release:
  `https://github.com/0smboy/Peregrine/releases/tag/g6-green-20260831`
- Drive archive:
  `gdrive:Peregrine/Peregrine-G6-green-20260831-7883bbb/`

The published tag also carries the documentation and release metadata commit.
The build commit above is named separately so every binary can be tied to the
exact source tree that produced it. The `swift-rust` subtree in that integration
commit is byte-for-byte identical to the accepted source subtree:
`23b104245e52a7e01c421a052193beb0ad14760a`.

## G6 evidence

| Record | Result |
|---|---|
| W068 replication | 147 identities: 143 pass + 4 expected Python-matching skips, 0 failure/error |
| W069 EC | 32/32 pass, 0 failure/error/skip |
| W070 scorer | exact 179 identities, all strict invariants true, violations empty |
| W070 `score.json` | `f1b88427636cb25a3a6fe40e6da269577457061e182dfc75555bc33c922c592c` |
| W070 merged ledger | `44a003859ab60792c52f47a164b3bf7031b57d560f3fdf092d314ced2067c84e` |
| v9 EC package | `5eb07c38ec1a37bd21d3a7afe744e37374f54bb3a92e352204df018aec293398` |

Original records remain on Swift1 under `/var/log/g6-ec/` and are copied to
the Drive archive without changing the source directories.

Drive verification completed directly from the Linux nodes, without routing
artifacts through the Mac:

| Drive subtree | Objects | Bytes | `rclone check --checksum` |
|---|---:|---:|---|
| Release files | 10 | 139,861,122 | 0 differences |
| W068/W069/W070 evidence | 69 | 6,195,655 | 0 differences in all three evidence checks |

The older
`gdrive:Peregrine/Peregrine-G6-candidate-20260831-64446f1/` archive remains
immutable. Rclone warned that its shared Google Drive client ID is being
retired during 2026; replacing it with a dedicated client ID is a maintenance
item, not a failure of this verified upload.

## Auxiliary Linux verification

All commands ran on Swift2/Linux with locked dependencies. No Rust build or
large artifact transfer used the Mac.

| Component | Test result | Release binary SHA-256 |
|---|---:|---|
| Swift Console 0.1.0 | 180 passed | `b889f94e7636cea0109a9b3eb8e18b499a2f647ddc2586c65105f8f3d4e32a49` |
| Swift Deploy 0.1.0 | 79 passed | `2cea2a0a2508822894c0aa5e5d16f257ee37b40f620b86f0d328fa182c50d95c` |
| Cosbench-RS 1.0.0 | 33 passed | `5497c52c9298589750232f8d10ba777ef8da222a5219045bef83fe9c99fcc2e3` |
| Autocos 1.0.0 | 4 passed | `f4b79e175e2de1c6437a0a2fd4d1b48a6c8453ccbb7a63a0bad7cd95ec4eef00` |

The combined auxiliary archive is
`peregrine-tools-g6-green-linux-x86_64.tar.gz`, SHA-256
`6b5212b262057b7d361cb04f822a3878a53273f57674aecc4079439e1637ce5a`.
The Swift Rust archive is
`peregrine-swift-rust-g6-green-linux-x86_64.tar.gz`, SHA-256
`5eb07c38ec1a37bd21d3a7afe744e37374f54bb3a92e352204df018aec293398`.

During release validation, one stale Swift Deploy assertion was corrected to
match the already-portable `/sys/class/net` plus `ip -o link show dev` preflight.
Swift Console gained functional `--help` and `--version` handling and three
regression tests; a duplicate unreachable translation key was removed. The
accepted `swift-rust` subtree was not changed by either fix.

Compiler versions:

- Rust Swift, Swift Console, Autocos: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Swift Deploy, Cosbench-RS: `rustc 1.97.0 (2d8144b78 2026-07-07)`

Lockfile SHA-256 values:

- `swift-rust/Cargo.lock`: `b5823e165e2864ca809425824834c2860d9b2bd904c36773b0db1c1da371db2d`
- `swift-console/Cargo.lock`: `9653912a896e3d4fee365886ff34017f8a62cf22529670b43b9209747d63fb38`
- `swift-deploy-rs/Cargo.lock`: `7ee50b0f6deb493fb41291b9879dd960bb1997971ce2b82d5e6c63c0d44d833e`
- `cosbench-rs/Cargo.lock`: `94d63913787d9b7146807fa96f34b3bbde6d83e1a9cdb26ba02a7c9cc89108b3`
- `autocos/Cargo.lock`: `181a5fcb8782f32f9054ab4c05664b51fd3fd12e48f92ac2b8187ac36dbea66b`

## Known limits

- `cargo fmt --check` exposes broad pre-existing Swift Console formatting debt;
  the release does not claim a clean formatting gate.
- Swift Console and Autocos still emit non-fatal dead-code warnings.
- G3, current-candidate G4/G5 acceptance, G7, and G8 are not closed by this
  publication.
- A lab pre-release is not a production rollout or a drop-in compatibility
  declaration.

## Documentation publication

The expanded 36-page documentation source passed type checking, the project
documentation linter, the claim audit, and a production build. Vercel built 38
routes and indexed 36 documentation pages.

- Production alias: `https://peregrine-docs-ochre.vercel.app`
- Immutable deployment:
  `https://peregrine-docs-m4cos7vlw-0smboys-projects.vercel.app`
- Vercel deployment ID: `dpl_FrkoA3xVBt1k4j2cG5eQp6GW81ka`

Live Markdown endpoints for status, releases, validation gates, concurrency,
and welcome were fetched after deployment. They preserve the required claim:
G6 is GREEN, G7 is NOT ACCEPTED, G8 is BLOCKED, and production remains NO-GO.

A final browser audit found and corrected two stale workspace-size labels: the
home page said 17 crates and the root README said 15, while the accepted
`Cargo.toml` has 16 workspace members. Desktop (1440 px) and mobile (390 px)
checks show no horizontal overflow, no hidden content, and no console warning
or error on the home and current-status pages.

## Swift1-Swift4 workspace cleanup

Only process-unreferenced, fully rebuildable Cargo `target` directories were
removed. Before deletion, every candidate passed an exact mount-point check and
a `/proc` scan covering cwd, executable, file descriptors, and mapped files;
there were no Cargo/rustc processes and both hosts returned
`REF_COUNT_FLAG=0`.

| Host | Removed | Reclaimed bytes | Root filesystem after cleanup |
|---|---:|---:|---:|
| Swift1 | 6 Cargo caches | 6,844,724,712 | 83% used, 7,513,640,960 bytes available |
| Swift2 | 4 Cargo caches | 9,989,777,230 | 67% used, 14,579,867,648 bytes available |

Removed from Swift1:

- `/root/work/swift-rust/target`
- `/root/work/swift-console/target`
- `/root/work/swift-deploy-rs/target`
- `/root/work/swift-deploy-rs-phase1/target`
- `/root/work/cosbench-rs/target`
- `/root/work/autocos/target`

Removed from Swift2:

- `/root/work/peregrine-aux-release-target`
- `/root/work/g6-ec-b6e36bf-target`
- `/root/work/codex-g6-build-20260826/swift-rust/target`
- `/root/work/g6-ctx-build/swift-rust/target`

These cache contents are not recoverable in place, but are reproducible from
the preserved source and lockfiles. The current v9 build cache
`/root/work/g6-17adf0b-v9-target` was deliberately retained for G7 work. No
historical source tree, release artifact, G6 binary, test evidence, production
path, or swiftfuse path was removed.

Stable navigation links now identify the retained mainline material:

- Swift1 `/root/work/PEREGRINE-G6-BIN-CURRENT`
- Swift1 `/root/work/PEREGRINE-G6-W070-CURRENT`
- Swift2 `/root/work/PEREGRINE-RELEASE-SOURCE-CURRENT`
- Swift2 `/root/work/PEREGRINE-RELEASE-ARTIFACTS-CURRENT`

## Production and rollback boundary

Production `:8080` remained on SHA-256
`ab5cb95c5c3973db8336e4940711fba18ce3cabaae62e13da0865c07ad31622b`.
This exact SHA was re-read from the executable behind the live `:8080`
listener on Swift1, Swift2, Swift3, and Swift4 after cleanup.
No VIP, HAProxy, Keepalived, production binary, ring, configuration, or Swift
data was changed. Any future rollout requires a separate authorization,
node-by-node executable provenance, health verification, and a tested rollback.
