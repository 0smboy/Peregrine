# STRICT VERIFY — item6 multi-primary auto-shrink

**Date:** 2026-08-08  
**Workspace:** `/Users/oboy/Downloads/Peregrine/swift-rust`  
**CARGO_HOME:** `/Users/oboy/Downloads/Peregrine/.cargo-home`

## VERDICT: KEEP

LAB-HARD-GREEN for unit multi-device (same-host) auto-shrink + short soak.  
**Not** PRODUCTION-GO-LIVE Contabo multi-node / multi-hour live shrink (cross-node HTTP residual; peer roots without live `shard_range` rows remain open per residual-wave-20260807).

## Commands

```bash
export CARGO_HOME=/Users/oboy/Downloads/Peregrine/.cargo-home
cd /Users/oboy/Downloads/Peregrine/swift-rust

# Required filter (user gate)
cargo test -p swift-container-server --lib -- shrinking

# Item6 product path (multi-device + auto_shrink opt)
cargo test -p swift-container-server --lib -- shrink

# Short soak
SOAK_SECONDS=30 INTERVAL=10 \
  /Users/oboy/Downloads/Peregrine/tools/soak/multi-primary-shrink-soak.sh
```

## Gate A — filter `shrinking`

| Metric | Count |
|--------|------:|
| passed | 1 |
| failed | 0 |
| ignored | 0 |
| filtered out | 53 |
| duration | 0.04s |

```
test sharder::tests::test_process_shrinking_donors_moves_objects_and_marks_shrunk ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 53 filtered out
```

Evidence: `cargo-shrinking.txt`

## Gate B — filter `shrink` (item6 multi-primary path)

| Metric | Count |
|--------|------:|
| passed | 3 |
| failed | 0 |
| ignored | 0 |
| filtered out | 51 |
| duration | 0.06s |

| Requirement | Test | Result |
|-------------|------|--------|
| Donor objects → acceptor + SHRUNK | `test_process_shrinking_donors_moves_objects_and_marks_shrunk` | ok |
| Multi-device sibling donor (d2→d1 root) | `test_multi_device_auto_shrink_finds_donor_sibling` | ok |
| `SharderRunOpts::auto_shrink` default true | `test_auto_shrink_opt_default_true` | ok |

Evidence: `cargo-shrink.txt`

## Gate C — short soak

| Param | Value |
|-------|------:|
| SOAK_SECONDS | 30 |
| INTERVAL | 10 |
| rounds | 3 |
| pass | 3 |
| fail | 0 |
| soak VERDICT | **KEEP** |

Each round: 3/3 shrink tests ok (same set as Gate B).  
Evidence: `multi-primary-shrink-soak.log`

```
SOAK_SUMMARY pass=3 fail=0 rounds=3 soak_seconds=30
VERDICT KEEP
```

## Code surface

| Path | Role |
|------|------|
| `swift-container-server/src/sharder.rs` | `find_shrinking_donors`, `process_shrinking_donors`, `auto_shrink`, multi-device sibling lookup |
| `swift-container-server/src/bin/container_sharder.rs` | daemon `auto_shrink: true` |
| `tools/soak/multi-primary-shrink-soak.sh` | repeated lib filter `shrink` soak |

## Claim boundary

| Claim | Status |
|-------|--------|
| Same-device process_shrinking_donors (SHRINKING→SHRUNK + object move) | **KEEP** unit |
| Multi-device same-host auto-shrink (donor on sibling device) | **KEEP** unit |
| `auto_shrink` default on | **KEEP** unit |
| Short unit soak (30s / 3 rounds) | **KEEP** |
| Contabo multi-primary live shrink (peer roots + remote donor only) | residual / not claimed |
| Multi-hour soak (SOAK_SECONDS=7200) | harness ready; not re-run this verify |
| PRODUCTION-GO-LIVE | **not claimed** |
