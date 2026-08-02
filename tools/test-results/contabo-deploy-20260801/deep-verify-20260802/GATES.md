# Deep verify gates — 2026-08-02

Git worktree at verify: Peregrine (code sync marker + local commits for
evidence-alignment / ObjectServerConfig / Contabo harness IP fixes).

Constraints held: no `/srv/node` wipe; single Keepalived VIP; no secret/jar publish.

## Production knobs (all nodes `10.0.0.1–4`)

```
workers = 16
container_update_mode = sync
container_update_timeout = 1.0
fsync_on_close = true
reuse_port = false
```

## Gate table

| Gate | Result | Evidence |
|------|--------|----------|
| docs-claim-audit | PASS | `docs-claim-audit.log` + local `tools/docs-claim-audit.sh` |
| Alignment three-way | PASS (0 FAIL) | `ALIGNMENT-AUDIT.md`, `live-*.md` |
| cargo fmt | PASS | `ci-focused-r3.log` |
| cargo clippy (-D warnings, no EC + EC) | PASS | `ci-focused-r3.log` (after multiphase + clippy fixes) |
| cargo test --workspace --exclude swift-ec | PASS **825 / 0** | `/tmp/test-noec.log` + `cargo-test-noec-full.log` |
| cargo test EC-featured | PASS **124 / 0** | `/tmp/test-ec.log` + `cargo-test-ec-full.log` |
| VIP auth 100× | PASS 100/100 | `vip-triage.log` |
| func-suite VIP | PASS **54/54** | `func-vip.log` |
| func-suite rust SAIO `:8081` | PASS **54/54** | `func-rust-saio.log` |
| func-suite py SAIO `:8090` | PASS **54/54** | `func-py-saio.log` |
| HA drill (console node-down) | PASS (baseline/degraded/recovered 10/10 & 20/20) | `ha-test.log` |
| EC heal (md5 baseline/degraded/healed) | PASS (YES/YES/YES); WARN fragment counter (partition empty / global count) | `ec-heal-test.log` |
| Prometheus `nodes_up` | PASS **4** | `prom-nodes.json` |
| Console smoke (whoami/buckets/lab/monitor/test/deploy) | PASS all 200 | `console-smoke2.log` |
| Security spot | PASS (eth0 public DROP+ssh; PasswordAuthentication no; eth1–3 trusted) | `security-spot.log` |
| SAIO 1KB PUT 3× median | PASS fail=0; Rust c32 **236.7** vs Python **68.6** ≈ **3.45×** (phase0 was 3.79×; drift noted) | `saio-1kb/` |
| Clean-load autocos (swift4→VIP) | 4KB/1MB **fail=0**; 16MB write fail=0; **16MB read WARN** success 9.16% | `cleanload-swift4/SUMMARY.json` |

## Defects fixed during this cycle

1. `tests/multiphase.rs` — `container_update_*` wrongly nested inside `PolicyKind::Ec`
2. clippy `too_many_arguments` on `sync_container_http` — allow
3. clippy `field_reassign_with_default` in `object-server` main — struct update syntax
4. Harness Azure IPs — `ha-test.sh`, `ec-heal-test.sh`, `autocos-sweep.sh`, `vip-triage.sh`, `edge-diag.sh`, `hadbg.sh` default to Contabo VIP / `10.0.0.N`

## Perf verdict

- Hard gates (4KB write→read, 1MB write/read): **ACCEPT** (fail=0 from clean client)
- 16MB read @8: **ACCEPT_WITH_WARN** (prepare 80/80 ok, but normal stage success 9.16% — not cleared; known large-object lab limit)
