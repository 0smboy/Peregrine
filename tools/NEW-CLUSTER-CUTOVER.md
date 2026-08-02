# New PAYG cluster cutover (2026-07-31) — RETIRED

> **Retired 2026-08-01.** Active lab is Contabo (`10.0.0.0/24` VIP
> `10.0.0.10`). See [`CONTABO-CLUSTER.md`](CONTABO-CLUSTER.md).
> Azure hosts remapped to `swift-old*` in SSH config; do not use for new work.

# New PAYG cluster cutover (2026-07-31)

## Endpoints
- SSH: `ssh swift1` … `swift4` (new). Old: `swift-old1` … `swift-old4`.
- Public: `swift1` = `52.176.126.60`
- API (node HAProxy): `http://<any-node>:8085` or Internal LB VIP `http://10.42.30.10:8085`
- Auth: `test:tester` / `azure-swift-2026.bench`
- Console (swift1 loopback): `ssh -L 9000:127.0.0.1:9000 swift1` → http://127.0.0.1:9000/

## Verified
- All four nodes: `swift-proxy`, object/account/container (+ replicators/updater/reconstructor), `haproxy`, `node_exporter` active
- Local `/healthcheck` on `:8080` and `:8085` → 200
- Auth + PUT/GET object on new cluster → 201/200
- Internal LB VIP `:8085/healthcheck` → 200 (may briefly time out while Azure probe settles)
- swift1: `swift-console`, `prometheus`, `loki`, `alloy`, `statsd_exporter` active
- Build host: `/root/work/swift-rust`, `/root/work/Peregrine`, rustc 1.97.1 under `/root/.cargo` + `/root/.rustup`

## Not migrated / notes
- Old cluster left untouched (still running)
- Object data was NOT copied (fresh empty disks); rings/IPs match so layout is identical
- `swift-object-auditor` is a oneshot sweep (inactive after run is expected)
- Peers have no outbound dnf; packages were offline-fanned from swift1
- SELinux: `haproxy_connect_any=1` + http_port_t for 8085/8404/8405/10000

## Build / redeploy
```bash
ssh swift1
sudo -i
export PATH=/usr/local/bin:/root/.cargo/bin:$PATH
cd /root/work/Peregrine/swift-console   # or /root/work/swift-rust
# build on the Linux host; install with restorecon so SELinux stays bin_t
```

## Tested (2026-07-31)

- Evidence: `tools/test-results/mig-test-20260731-SUMMARY.md` (and on-host `/root/mig-test-20260731/`)
- Verdict: **ACCEPT** (G8 VIP WARN — ILB hairpin / 92% auth from swift3)
- Gap-fill applied: EC plugin libs, auditor.timer, EC-enabled bins from `backup-20260730-112444`, SAIO (8090/8081), cabt/autocos, shadow corpus, docs
- Hard gates G0–G7 PASS including func-suite 54/54, HA drill, EC heal, nodes_up=4
- **R1 func** (empty-ish lab): `func-test-20260731-SUMMARY.md` — func-suite 54/54 ×4 nodes; ACL/meta; edge-diag; EC heal; Rust SAIO 54/54
- **R2 HA/console/recon** (plan-first): `func-test-r2-20260731T130611Z-SUMMARY.md` — ha-test swift2 degraded **20/20** repl+EC; console hard APIs OK (3 relative-URL false FAILs); recon failures=0 / part-871=0; py-saio SKIP/WARN (memcached installed; oracle still 503-heavy)
- **Perf full matrix** (plan-first): `perf-test-20260731T131513Z-SUMMARY.md` — **ACCEPT_WITH_WARN**; bench repl+EC err=0; cbench/wbench errs=0; autocos 60s (4KB read 83.94% success WARN); Drive `gdrive:Peregrine/2026-07-31-lab-456/perf-tests/20260731T131513Z/` (+ func-tests/ archive)
- **4KB read RCA + retune**: `perf-4kb-rerun-20260731T134021Z-SUMMARY.md` — root cause client TIME_WAIT/`ulimit -n=1024` (not Swift); sysctl+nofile+`ST_ENDPOINT`; rerun write/read **fail=0** (read ok=377121); Drive `.../perf-tests/20260731T134021Z-4kb-rca/`

- **Lab12 deep** (interrupted): `lab12-deep-20260731T142015Z` — overall **REJECT**; Shadow dual peer=Python:8090 **breaking=15**; Azure ReadOnlyDisabled stopped VMs mid-run; Drive `.../lab-tests/20260731T142015Z/`

## Destroy old VMs

See [`test-results/DESTROY-GO-NOGO-20260731.md`](test-results/DESTROY-GO-NOGO-20260731.md).
**Runtime env: GO. Object data on old `/srv/node`: lost forever if destroyed.**
Rollback EC bins: Mac `tools/test-results/pre-destroy-archive/` and new
`/root/archive-from-old/` (tarballs gitignored).

Long-form ops: [`docs/lab-cluster.md`](../docs/lab-cluster.md).
