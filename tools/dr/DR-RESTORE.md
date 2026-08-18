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
  5. **off-site encrypted copy on Google Drive** -- ciphertext only, see
     section 6. Plaintext bundles still never leave the lab hosts + the
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

- **RPO = the newest weekly stamp (<= 7 days once the cron has run).** Weekly
  automation was installed 2026-08-17 (section 5); first automated run is
  Monday 2026-08-24. Until then the only guaranteed restore point remains the
  manual stamp `20260817T130925Z`. Config changes between weekly stamps are
  unprotected.
- **RTO = untested for a real restore.** Only the read-only drill (extract +
  verify + diff, zero differences) has been performed. A live restore
  additionally needs steps 4-7 (daemon-reload, ordered restarts, ring check,
  smoke), estimated minutes-not-hours for a single node, but **no measured
  number exists and none is claimed.**

## 5. Weekly backup cron (INSTALLED 2026-08-17)

`tools/dr/dr-backup.sh` is deployed on all four nodes as
`/usr/local/bin/peregrine-dr-backup.sh` (mode 0755). Each node carries
`/etc/cron.d/peregrine-dr-backup`; all nodes run in UTC. Runs are staggered
Mondays: swift1 03:05, swift2 03:10, swift3 03:15, swift4 03:20 UTC.
File content (only the minute differs per node):

```cron
# Peregrine DR weekly config-plane backup (installed 2026-08-17).
# Runs every Monday at 03:05 UTC (nodes staggered: swift1=03:05 ... swift4=03:20).
# Retention: after a successful backup, prune bundle dirs older than 35 days (~5 weeks kept).
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=""
5 3 * * 1 root { /usr/local/bin/peregrine-dr-backup.sh --outdir /root/dr-backups/$(date +\%Y\%m\%d) && find /root/dr-backups -mindepth 1 -maxdepth 1 -type d -mtime +35 -exec rm -rf {} + ; } >> /var/log/peregrine-dr-backup.log 2>&1
```

Retention policy: the `find ... -mtime +35 -exec rm -rf` prune runs only after
a **successful** backup (`&&`), keeping roughly the last 4-5 weekly dirs under
`/root/dr-backups/`. `-mindepth 1` protects the parent directory itself.

Still open (unchanged from the first wave):
- aggregation to swift3/swift2 requires inter-node ssh trust which does NOT
  currently exist (host-key verification fails node-to-node as of 2026-08-17);
  either provision `/root/.ssh/known_hosts` + keys, or keep pulling bundles
  from the operator workstation as done in this wave.

## 6. Offsite encrypted copy (INSTALLED 2026-08-17)

The 2026-08-17 bundles have an encrypted off-site copy on Google Drive.
**Only ciphertext goes to the cloud; plaintext bundles never do.**

- **Cipher:** `openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt`, one
  `.enc` per bundle plus a `.enc.sha256` sidecar (sha256 of the ciphertext).
- **Passphrase:** generated with `openssl rand -base64 32`, stored ONLY in the
  operator Mac's login Keychain. The value appears in no command line, log,
  file, or document.
  - Keychain entry: account `peregrine`, service **`peregrine-dr-backup`**
  - Retrieve (never echo): `security find-generic-password -a peregrine -s peregrine-dr-backup -w`
- **Offsite path:** `gdrive:Peregrine/dr-offsite/20260817/` (rclone remote on
  the operator Mac), holding the four `.enc` files + four `.enc.sha256`.
- **Decrypt template** (run on the operator Mac, or anywhere after fetching
  the `.enc` and reading the passphrase from Keychain):
  ```
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
    -in dr-config-<node>-<stamp>.tar.gz.enc \
    -out dr-config-<node>-<stamp>.tar.gz \
    -pass file:<(security find-generic-password -a peregrine -s peregrine-dr-backup -w)
  ```
  Then verify against the plaintext sidecar from section 2 storage
  (`sha256sum -c dr-config-<node>-<stamp>.tar.gz.sha256`) before restoring.
- **Loopback proven 2026-08-17:** swift1's `.enc` was decrypted to /tmp and
  its sha256 matched the original bundle exactly; the temp file was deleted.
- Losing the Keychain entry makes the offsite copies unreadable; the
  passphrase exists nowhere else. Treat Keychain backup as part of DR.

## 7. Evidence for this wave

Operator-side evidence (drill output, sha256 tables, df before/after, disk
surveys) is archived outside the repo under
`.agent-handoff/workflow-runs/20260817/dr-capacity/`. Evidence for the weekly
cron install, the encryption loopback, and the Drive offsite listing lives
under `.agent-handoff/workflow-runs/20260817/alerting-offsite/` (no passphrase
values anywhere). Bundles themselves live under
`.agent-handoff/dr-backups/20260817/` on the operator Mac -- also outside any
git worktree; their `.enc` ciphertext copies are the only cloud artifacts. The
repo carries only this runbook, the backup script, and the disk ledger
(`tools/dr/DISK-LEDGER-20260817.md`).
