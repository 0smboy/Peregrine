# Migration test summary — 2026-07-31T12:35:00Z

## Verdict: **ACCEPT** (with G8 WARN)

New PAYG 4-node cluster is ready for daily development. Object store bytes were intentionally not migrated (empty disks).

| Gate | Result | Evidence |
|------|--------|----------|
| A1 EC plugin libs | PASS | reconstructor active; ldd clean |
| A2 auditor.timer | PASS | enabled all 4 |
| A3 SAIO/lab tools | PASS | pyswift:8090=200 rsaio:8081=200; cabt/autocos; shadow; docs |
| A4 Object data | SKIP (intentional) | empty `/srv/node` vs ~22G on old |
| G0 Inventory | PASS | logs/01-* |
| G1 Func suite | PASS | 02-func-suite-*-retry FAIL=0 (54/54); EC bins restored from backup-20260730-112444 |
| G2 Edge/ACL | PASS | edge PROXY EC match=YES; ACL 200→401; meta 400/202 |
| G3 HA | PASS | swift2 down: repl+ec 20/20; recovered 10/10 |
| G4 EC heal | PASS | degraded+post-heal md5 match; recon failures=0 |
| G5 Observability | PASS | nodes_up=4; 12/12 targets up |
| G6 Console | PASS | pages/CRUD OK; content OK via absolute URLs (`console-test.sh` ckin uses relative URLs → 3 false FAILs) |
| G7 Toolchain | PASS | rustc 1.97.1; `cargo check -p swift-proxy-server` Finished; bins `bin_t` |
| G8 VIP | WARN | swift1 hairpin timeout; from swift3 VIP auth 92/100 (<95%); node `:8085` is hard path |

## Gap matrix

| Item | Status |
|------|--------|
| libnullcode + rs_vand.so.1.0.1 | FIXED |
| auditor.timer | FIXED |
| EC-enabled binaries (--features ec) | FIXED (was 501 Not Implemented) |
| Python/Rust SAIO | MIGRATED + started |
| cabt/autocos | MIGRATED |
| console shadow state | MIGRATED |
| Peregrine docs/tools | MIGRATED |
| Object data `/srv/node` | NOT MIGRATED (by design) |
| keepalived | N/A (Azure ILB) |

## Recommendation

ACCEPT cutover for daily dev on `swift1`–`swift4`. Prefer node HAProxy `http://10.42.30.1N:8085` or external VNet clients for VIP. Rebuild future installs with `--features ec`.
