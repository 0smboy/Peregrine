# Peregrine config-plane DR: backup & restore runbook (Wave 10)

Status: first backup generation 2026-08-17 (stamp `20260817T130925Z`).
Scope: **config plane only**. Object data has 3 replicas across nodes and is
NOT covered here; this runbook covers rings, confs, secrets, unit files -- the
things that previously had zero copies outside the cluster.

## 1. What a bundle contains

One bundle per node, produced by `tools/dr/dr-backup.sh` run as root on the
node itself:

| path in bundle | source | notes |
|---|---|---|
| `etc/swift/` | `/etc/swift/` | rings `.ring.gz`, builder JSONs, `swift.conf` (hash_path prefix/suffix -- SECRET), all server confs, `.hash.env`, `peregrine-lab.env` (SECRET), historical `.bak-*` |
| `etc/pyswift/` | `/etc/pyswift/` | python-oracle confs + rings (present on all 4 nodes) |
| `etc/haproxy/` | `/etc/haproxy/` | LB config |
| `etc/keepalived/` | `/etc/keepalived/` | VIP failover config (swift2 is VIP owner) |
| `etc/systemd/system/swift*`, `pyswift*` | same | unit files, timers, targets, drop-ins; includes `swiftfuse`, `swift-console`, `swift-deploy-ui` where present |
| `meta/crontab-root.txt` | `crontab -l` | root crontab capture (empty on all 4 as of 2026-08-17) |
| `meta/usr-local-bin.inventory.txt` | `ls -la /usr/local/bin` | inventory only |
| `meta/usr-local-bin.sha256` | per-file sha256 | binaries NOT packed (rebuildable from repo) |
| `MANIFEST.txt` | generated | node, UTC time, live `swift-proxy-server` sha256, per-file sha256 |

Defensive filter: any `*.so` or ELF-magic file is excluded and logged in
`meta/excluded-files.txt` (0 exclusions on all 4 nodes at first run -- the
config plane is clean).

## 2. Where bundles live (secret discipline)

Bundles contain `swift_hash_path_prefix`/`suffix` and tempauth credentials.

- **NEVER commit a bundle to git. NEVER upload to Google Drive or any cloud.**
- Storage locations (all verified by bundle-level sha256 against the
  generation-time sidecar `.sha256`):
  1. origin node: `/root/dr-backups/20260817/` (each node keeps its own)
  2. aggregation: swift3 `/root/work/dr-backups/20260817/` (all 4 bundles)
  3. cross copy: swift2 `/root/work/dr-backups/20260817/` (all 4 bundles)
  4. operator offline copy on the Mac workstation, outside any git worktree
- **PENDING (user decision required):** an off-site encrypted copy (e.g.
  `age`/`gpg` symmetric) is planned but waits for the user to supply a
  passphrase. Until then the newest bundles exist only on lab hosts + the
  operator's Mac.

## 3. Restore procedure (per node)

Read-only drill of steps 1-3 was performed on swift4 on 2026-08-17: MANIFEST
verified 91/91 hashes, 88/88 config files diffed clean against live paths,
zero differences. A destructive full-node restore has NOT been rehearsed.

1. **Verify the bundle before touching anything:**
   ```
   sha256sum -c dr-config-<node>-<stamp>.tar.gz.sha256
   mkdir -p /tmp/dr-restore && tar -C /tmp/dr-restore -xzf dr-config-<node>-<stamp>.tar.gz
   cd /tmp/dr-restore/dr-config-<node>-<stamp>
   awk '/^== per-file sha256 ==$/{f=1;next} f' MANIFEST.txt | sha256sum -c --quiet && echo BUNDLE-OK
   ```
2. **Stop writes into the config you are replacing** (skip for a fresh node):
   do not edit `/etc/swift` concurrently from another session.
3. **Copy files back** (preserve ownership/modes; `cp -a` from the extracted
   tree keeps both):
   ```
   cp -a etc/swift/.      /etc/swift/
   cp -a etc/pyswift/.    /etc/pyswift/
   cp -a etc/haproxy/.    /etc/haproxy/
   cp -a etc/keepalived/. /etc/keepalived/
   cp -a etc/systemd/system/. /etc/systemd/system/   # only swift*/pyswift* units are in the bundle
   ```
   Restore the crontab only if `meta/crontab-root.txt` is non-empty:
   `crontab meta/crontab-root.txt`.
4. **Reload systemd:** `systemctl daemon-reload`
5. **Restart order** (storage plane before proxy, LB last):
   1. `swift-account.service`, `swift-container.service`, `swift-object.service`
   2. consistency daemons: `swift-*-auditor`, `swift-*-replicator`,
      `swift-*-updater`, `swift-container-sharder`, `swift-container-reconciler`,
      `swift-object-reconstructor`, `swift-object-expirer` (only the ones
      enabled on that node -- check `systemctl list-unit-files 'swift-*'`)
   3. `pyswift-account/container/object/proxy` where present (swift2/3/4)
   4. `swift-proxy.service`
   5. `haproxy`, then `keepalived` (keepalived last so the VIP only returns
      once the backend is answering)
6. **Ring consistency check across the cluster** -- all nodes must serve
   identical rings:
   ```
   for h in swift1 swift2 swift3 swift4; do
     ssh root@$h 'sha256sum /etc/swift/*.ring.gz'
   done | sort | uniq -c   # every ring file must appear exactly 4x with one hash
   ```
   (equivalent to `swift-recon --md5` where the python swift CLI is available)
7. **Functional smoke:** `curl -sf http://<VIP>:8080/healthcheck` and one
   authenticated HEAD against a known container.

## 4. RPO / RTO (honest statement, 2026-08-17)

- **RPO = the manual backup timestamp.** There is no automation yet; the only
  guaranteed restore point is stamp `20260817T130925Z`. Config changes after a
  stamp are unprotected until the next manual run.
- **RTO = untested for a real restore.** Only the read-only drill (extract +
  verify + diff, zero differences) has been performed. A live restore
  additionally needs steps 4-7 (daemon-reload, ordered restarts, ring check,
  smoke), estimated minutes-not-hours for a single node, but **no measured
  number exists and none is claimed.**

## 5. Proposed weekly automation (NOT installed -- user decision)

Proposed crontab entry per node (root), if/when the user opts in. Install by
copying `tools/dr/dr-backup.sh` to `/usr/local/bin/dr-backup.sh` first:

```cron
# weekly config-plane DR backup, Mondays 03:17 UTC (proposed, not installed)
17 3 * * 1 /usr/local/bin/dr-backup.sh --outdir /root/dr-backups/$(date -u +\%Y\%m\%d) >> /var/log/dr-backup.log 2>&1
```

Companion suggestions (also not installed):
- retention: keep the last 8 weekly dirs under `/root/dr-backups/`
  (`ls -1d /root/dr-backups/2* | head -n -8 | xargs -r rm -rf` as a follow-up
  cron line, or manual).
- aggregation to swift3/swift2 requires inter-node ssh trust which does NOT
  currently exist (host-key verification fails node-to-node as of 2026-08-17);
  either provision `/root/.ssh/known_hosts` + keys, or keep pulling bundles
  from the operator workstation as done in this wave.
- the off-site encrypted copy (section 2) remains the standing pending item.

## 6. Evidence for this wave

Operator-side evidence (drill output, sha256 tables, df before/after, disk
surveys) is archived outside the repo under
`.agent-handoff/workflow-runs/20260817/dr-capacity/`. Bundles themselves live
under `.agent-handoff/dr-backups/20260817/` on the operator Mac -- also outside
any git worktree. The repo carries only this runbook, the backup script, and
the disk ledger (`tools/dr/DISK-LEDGER-20260817.md`).
