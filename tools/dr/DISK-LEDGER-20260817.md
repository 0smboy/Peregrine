# Four-node disk ledger -- 2026-08-17 (Wave 10 DR & capacity)

All numbers from `df -h /` and `du -x` taken 2026-08-17 13:05-13:21 UTC.
Every node: single 40G root filesystem `/dev/sda4` (Rocky Linux, Contabo).
Inode pressure: none anywhere (swift1 6% inodes used).

## 1. Before / after

| node | before | after | what changed |
|---|---|---|---|
| swift1 | **94%** (38G used, 2.5G free) | **74%** (30G used, 11G free) | SAFE cleanup (-8.2G): journal vacuum 3.9G->0.47G, dnf cache 170M->4M, four >7-day `/tmp` build trees/bench files removed (2.4G+1.1G+833M+256M) |
| swift2 | 43% (17G) | **34%** (14G) | journald 500M cap trimmed a 3.9G journal on restart |
| swift3 | 83% (33G) | **74%** (30G) | journald 500M cap trimmed a 4.0G journal on restart |
| swift4 | 45% (18G) | **36%** (15G) | journald 500M cap trimmed a 3.9G journal on restart |

journald cap: `/etc/systemd/journald.conf.d/size.conf` (`SystemMaxUse=500M`)
installed on all four nodes; `systemd-journald` restarted; post-restart journal
ingest verified on every node (live service lines visible). Prior
`journald.conf` saved as `/root/journald.conf.bak-20260817` on each node.

## 2. swift1 cleanup itemization

Removed (SAFE class only, each verified mtime >7 days + zero open handles):

| item | freed |
|---|---|
| `journalctl --vacuum-size=500M` | 3.5G |
| `dnf clean all` | 166M |
| `/tmp/swift-rs-build-syncfix` (build tree, 2026-08-06) | 2.4G |
| `/tmp/p0-swift-rust` (build tree, 2026-08-04) | 1.1G |
| `/tmp/p1b-swift-rust` (build tree, 2026-07-31) | 833M |
| `/tmp/b256.bin` (bench file, 2026-08-07) | 256M |
| **total** | **~8.2G** |

Untouched by hard boundary: `/root/work` (6.9G), `/usr/local/bin` (1.1G incl.
rollbacks), `/srv/node` (559M), Prometheus (2.0G) / Loki (398M) data,
`/var/lib/etcd` (2.1G), monitoring-stack staging in `/tmp` (~560M:
`prometheus-2.54.1` 260M, `alloy.zip` 102M, `p.tgz` 101M, `loki-linux-amd64`
74M, `loki.zip` 23M) -- left alone because a parallel task is working on
node_exporter/Prometheus on swift1.

ASK class on swift1 (listed, not touched -- user decision):

| item | size | note |
|---|---|---|
| `/root/swiftfuse-dev` | 3.6G | dev tree with build artifacts; `cargo clean` would recover most |
| `/var/log/messages-20260809` + `-20260816` | 2.5G | rotated syslogs; compress or drop? |
| `/opt/detect` | 1.9G | purpose unknown to this wave |
| `/root/.rustup` + `/root/.cargo` | 2.3G | toolchains; needed if on-node builds continue |
| `/opt/swiftfuse` | 645M | installed product tree |
| `/var/log/supervisor` | 410M | old supervisor logs |
| `/var/log/swiftfuse-debug.log` + `dbgA` | 351M | debug logs, possibly still appended |
| monitoring staging in `/tmp` | ~560M | deferred (parallel monitoring task) |
| `/root/seq-write.0.0` | 128M | bench artifact in /root (outside SAFE scope) |

## 3. Per-node top consumers (after)

- **swift1 (74%)**: `/root/work` 6.9G, `/root/swiftfuse-dev` 3.6G, rotated
  messages 2.5G, `/usr/local` 2.5G (bin 1.1G), `/var/lib/etcd` 2.1G,
  Prometheus 2.0G, `/opt/detect` 1.9G, rustup+cargo 2.3G, Loki 398M,
  `/srv/node` 559M.
- **swift2 (34%)**: rotated messages 3.8G, `/root/swiftfuse-dev` 1.4G,
  `/usr/local/bin` 577M, `/root/work` 200M. No Prometheus/Loki data dirs.
- **swift3 (74%)**: **`/root/work` 17G (fleet evidence root -- largest single
  consumer in the lab)**, rotated messages 3.7G, `/root/swiftfuse-dev` 945M,
  `/usr/local/bin` 586M, `/tmp` 377M.
- **swift4 (36%)**: **Loki 3.3G** (fleet log store), rotated messages 3.6G,
  Prometheus 1.3G, `/usr/local/bin` 806M, `/root/work` 188M.

## 4. Growth hotspots and rates

1. **journal**: was ~4G/node accumulated since provisioning; now hard-capped
   at 500M/node. Closed.
2. **rotated `/var/log/messages-*`**: 1.1-2.1G per node per weekly rotation
   (two generations present: -20260809, -20260816). At default logrotate
   retention this trends toward ~4-8G/node. Biggest *unbounded* log growth
   now that journald is capped. Candidate: `compress` + `rotate 2` in
   logrotate for `messages` (swift services log to journald + rsyslog both --
   double-writing is itself worth revisiting).
3. **swift3 `/root/work` evidence root**: 17G and grows every wave
   (per-wave evidence dirs, soak logs, bundles). See archival draft below.
4. **Prometheus TSDB**: swift1 2.0G + swift4 1.3G. Bounded by retention
   config; report-only this wave (parallel task owns the monitoring stack).
5. **Loki on swift4**: 3.3G chunk store; retention policy unverified this
   wave. Report-only.

## 5. Evidence archival / rotation policy draft (NOT executed)

Proposal for user review -- no archival action was taken this wave:

- **Wave evidence on swift3 `/root/work`**: after a wave is closed and its PR
  merged, tar.gz the wave's evidence dir, keep the tarball on swift3 AND copy
  to the operator Mac (`.agent-handoff/`), then delete the uncompressed dir on
  a 30-day delay. Expected recovery: 10G+ of the 17G.
- **Rotated syslogs**: enable compression (`xz` in logrotate) fleet-wide;
  2.5-3.8G/node of plain-text messages compresses ~10:1.
- **DR bundles** (`/root/dr-backups/`): keep last 8 weekly stamps per node
  (see DR-RESTORE.md section 5).
- **Rollback trees in `/root`** (~90M/node in `peregrine-*rollback-*`): keep
  as-is (cheap insurance, explicitly KEEP class).
- **swiftfuse-dev trees** (3.6G swift1 / 1.4G swift2 / 945M swift3 / 131M
  swift4): if swiftfuse development has a single canonical node, `cargo clean`
  the other copies. User call.
