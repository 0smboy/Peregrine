# Linux Contabo binary redeploy · 2026-08-06

**Scope (expected):** redeploy only these three Linux release bins on Contabo:

| Binary | Package / crate | Pre-redeploy lab state (anchors) |
|--------|-----------------|----------------------------------|
| `swift-manage-shard-ranges` | `swift-cli` | Contabo CLI only supported **`find`** (`l3b-keep-drill-20260806`) |
| `swift-container-sharder` | `swift-container-server` | unit **active ×4**; multi-node KEEP **not product-claimed** |
| `swift-container-sync` | `swift-container-server` | binary **absent** on Contabo (`sync-live-probe-20260806`) |

**Parity scorecard context** (`docs/fairness-lab/RUST-VS-PYTHON-PARITY.md` §8):

- Sharding L3b: CLI + daemon ring HTTP path + ×4 active → **multi-node KEEP product claim 未实现**
- container-sync: filter + daemon + HTTPS knobs → **multi-cluster live soak not claimed**
- VIP TLS: Contabo still **lab self-signed** (operator PEM not applied)

---

## Live verdict (main agent fills — leave blank until evidence)

| Field | Value |
|-------|--------|
| Overall pack | _pending_ |
| Binaries installed ×4 | _pending_ |
| L3b KEEP product claim | **do not set KEEP green** without PASS evidence files below |
| container-sync gate | _pending_ |
| TLS / PRODUCTION-GO-LIVE | still **LAB self-signed only** (not cleared by this pack) |

**Honesty rule:** partial / probe / daemon-active ≠ KEEP. Do not promote parity scorecard rows until PASS files exist.

---

## Build host

| Item | Fill |
|------|------|
| Build host | _e.g. swift1 `root@169.58.108.85` / `/usr/local/src/swift-rust`_ |
| Toolchain | _e.g. rustc/cargo versions from `01-build.log`_ |
| Source sync | _rsync path + exclude `target/`_ |
| Cargo command | _`cargo build --release -p swift-cli --bin swift-manage-shard-ranges -p swift-container-server --bin swift-container-sharder -p swift-container-server --bin swift-container-sync`_ |
| Build start / end (UTC) | _pending_ |
| Git / tree stamp | _pending (rev if recorded)_ |
| Build log | `01-build.log` |

---

## sha256 of bins

Record release artifacts **on build host** then **post-install on each node**. Leave empty until `sha256sum` output exists.

### Build host (`target/release/`)

| Binary | sha256 | size | mtime |
|--------|--------|------|-------|
| `swift-manage-shard-ranges` | _pending_ |  |  |
| `swift-container-sharder` | _pending_ |  |  |
| `swift-container-sync` | _pending_ |  |  |

### Post-install `/usr/local/bin/` (must match build host)

| Node | manage-shard-ranges | container-sharder | container-sync |
|------|---------------------|-------------------|----------------|
| swift1 | _pending_ | _pending_ | _pending_ |
| swift2 | _pending_ | _pending_ | _pending_ |
| swift3 | _pending_ | _pending_ | _pending_ |
| swift4 | _pending_ | _pending_ | _pending_ |

Evidence files (suggested): `02-sha256-build-host.txt`, `03-sha256-post-install-×4.txt`

---

## Deploy nodes

| Node | Public SSH | Storage IP | Actions expected |
|------|------------|------------|------------------|
| swift1 | `169.58.108.85` | `10.0.4.1` | build (+ install sharder/manage-shard/sync) |
| swift2 | `169.58.108.86` | `10.0.4.2` | install + restart units as needed |
| swift3 | `169.58.108.87` | `10.0.4.3` | install + restart units as needed |
| swift4 | `169.58.108.121` | `10.0.4.4` | install + restart units as needed |

| Step | Status | Evidence |
|------|--------|----------|
| Pre-install backup of old bins | _pending_ | _e.g. `00-backup.txt`_ |
| Install three bins → `/usr/local/bin` | _pending_ | |
| `swift-container-sharder` unit reload/restart ×4 | _pending_ | |
| `swift-container-sync` unit install/enable (if in scope) | _pending_ | |
| `manage-shard-ranges --help` shows find/show/info/enable/…/analyze/compact/repair | _pending_ | |

**Dual-guard:** no wipe of `/srv/node`; no ring rebuild required for this pack.

---

## L3b KEEP gate criteria

**Product KEEP is not claimed** unless all of the following are evidenced with **PASS** (or explicit measured OK) files in this directory or a linked drill pack.

| # | Criterion | Evidence required | Result |
|---|-----------|-------------------|--------|
| K1 | New CLI on Contabo supports subcommands beyond `find` (`info` / `enable` / `find_and_replace` / `analyze` at minimum) | CLI help or dry-run log | _blank_ |
| K2 | Target container exists with objects; DB replicas located on ring primaries | API + `find` DB paths × replica nodes | _blank_ |
| K3 | `find_and_replace` (or equivalent enable path) applied on **all** replica DBs; container enters SHARDING/SHARDED as designed | per-node CLI logs | _blank_ |
| K4 | Sharder run completes cleave / shard-range materialization with **no client-visible listing regression** | listing before/after; object_count stable | _blank_ |
| K5 | Multi-node quorum path exercised (not local-cleave-only probe); ring HTTP create path used if claimed | sharder logs + peer REPLICATE/HTTP | _blank_ |
| K6 | Under load or post-shard listing KEEP (lab gate: listing + CRUD still OK; no silent truncation) | func snippet or drill log with **PASS** | _blank_ |

**Not sufficient for KEEP:**

- `systemctl is-active swift-container-sharder` ×4 only  
- binary present / new sha256 only  
- single-node DB find without enable + cleave  

Pre-redeploy residual: `tools/test-results/l3b-keep-drill-20260806/` — **PARTIAL**, CLI blocked on old binary.

---

## Sync gate criteria

| # | Criterion | Evidence required | Result |
|---|-----------|-------------------|--------|
| S1 | `swift-container-sync` present on intended nodes (`/usr/local/bin`) | `which` / sha256 | _blank_ |
| S2 | Unit + conf path sane (`[container-sync]` / realm keys as designed) | unit status + conf excerpt | _blank_ |
| S3 | Same-cluster or dual-endpoint smoke: Sync-To + Sync-Key → object appears on peer | sync log + GET peer | _blank_ |
| S4 | HTTPS / `ssl_ca_file` / `insecure_skip_verify` knobs only if exercised | TLS-related conf + log | _blank_ |
| S5 | **Multi-cluster live soak** | dedicated soak pack | **not claimed by default** |

Pre-redeploy residual: `tools/test-results/sync-live-probe-20260806/` — **PATH NOT DEPLOYED** (binary absent).

---

## TLS status (still lab self-signed)

This redeploy **does not** change VIP TLS.

| Item | Status |
|------|--------|
| Contabo VIP HAProxy PEM | **LAB self-signed** (`CN=10.0.0.10, O=Contabo-LAB`) |
| Operator production PEM apply | **not in scope** / deferred |
| Clients | still need `curl -k` / trust lab CA for `https://10.0.0.10:8085` |
| Prior evidence | `residual-live-probe-20260806/`, `tls-dry-run-20260806/`, `p3-ops-tls-status-20260806/` |

Do **not** flip `RUST-VS-PYTHON-PARITY.md` Production go-live / VIP TLS rows to green from this pack alone.

---

## Suggested evidence file map (main agent)

| File | Purpose |
|------|---------|
| `01-build.log` | remote cargo build (may already be in progress) |
| `02-sha256-build-host.txt` | sha256 of three release bins |
| `03-install.log` | scp/install + unit actions ×4 |
| `04-sha256-post-install.txt` | post-install align ×4 |
| `05-cli-help.txt` | manage-shard-ranges subcommand smoke |
| `06-l3b-gate/` or linked drill | KEEP criteria K1–K6 |
| `07-sync-gate/` | sync criteria S1–S5 |
| `SUMMARY.md` | filled verdict after PASS/FAIL known |

---

## Doc update checklist (after live fill — do not invent)

When PASS/FAIL is real, main agent may update:

1. `docs/fairness-lab/RUST-VS-PYTHON-PARITY.md` §5 (daemons), §8 scorecard, §9 evidence anchors  
2. Only upgrade L3b KEEP / container-sync rows if criteria tables above have **PASS** evidence  
3. Leave TLS / PRODUCTION-GO-LIVE rows lab-self-signed until PEM apply pack

---

*Template only. Live cells intentionally blank. Created while expected Contabo build may still be running; no KEEP green claimed.*
