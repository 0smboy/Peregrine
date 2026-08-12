# cold_backend_root lab canary runbook (swift3-only)

**Verdict:** `BLOCKED_NEED_CANARY_APPROVAL` — no fleet mutation performed.
**Date:** 2026-08-12 SGT · tip `c716103` on `feat/cold-localdir-restore-77dd9f4`
**Scope:** opt-in LocalDir cold + RestoreObject wiring only. Archive-on-transition still OPEN.

## Why blocked (not path A this turn)

1. Prior `canary-77dd9f4` pattern **does** authorize single-node **proxy binary** canaries on swift3.
2. That sealed deploy script contract is **binary-only** and explicitly never changes Swift config.
3. Enabling `cold_backend_root` **requires** a `[filter:s3api]` mutation on swift3 — outside that contract.
4. Full filecold restore E2E needs `SYS_COLD_BACKEND_URI` / transitioned object state; archive-on-transition is still OPEN, so live restore either stays meta-only or needs a manual sysmeta plant.
5. Prefer explicit operator OK before combining (new tip binary + config knob) on a live node.

Fleet VIP remains on stock **77dd9f4** binary `117d7b088e691be6826cca0fca067353bfc52c76f96b25aec1882f1d80d3052c` (all four nodes). Live configs have **no** `cold_backend_root`.

## Preconditions (already verified)

| Check | Result |
|-------|--------|
| Mac tip | `c716103` LocalDir + RestoreObject |
| On-node cold tree | `/root/work/peregrine-cold-physical-77dd9f4/swift-rust` MD5-matches Mac `cold_tier.rs` + `main.rs` |
| Units | GREEN — `tools/test-results/cold-physical-unit-77dd9f4-20260812T153251Z` |
| Live `[filter:s3api]` swift3/swift1 | `use` + `location=RegionOne` only |
| Live binary strings | no `cold_backend_root` / `filecold` |
| HAProxy proxy1–4 | UP; local `:8080` health 200 |
| Auth | `/etc/swift/peregrine-lab.env` (never print) |
| SSH | aliases `swift1`..`swift4`; `unfunction ssh; unalias ssh` |

## Config snippet (swift3 only — do NOT push to VIP peers)

Append under existing `[filter:s3api]` on **swift3** only:

```ini
[filter:s3api]
use = egg:swift#s3api
location = RegionOne
# lab LocalDir cold (NOT tape/Glacier). Opt-in; unset = stock behavior.
cold_backend_root = /var/cache/peregrine-cold
# optional policy map if restore stamps should remap hot/cold indices:
# cold_policy_map = GLACIER:2,DEEP_ARCHIVE:3,HOT:0
```

```bash
mkdir -p /var/cache/peregrine-cold
chmod 750 /var/cache/peregrine-cold
# keep ownership consistent with swift-proxy runtime user if non-root
```

Backup before edit:

```bash
cp -a /etc/swift/proxy-server.conf \
  /etc/swift/proxy-server.conf.bak-pre-cold-c716103-$(date -u +%Y%m%dT%H%M%SZ)
```

## Path A — when operator approves (swift3-direct only)

### A0. Evidence dir

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
EV=/root/work/peregrine-acceptance-20260810/canary-c716103-cold-${STAMP}
mkdir -p "$EV"
echo swift3 > "$EV/target-host.txt"
```

### A1. Build release proxy with EC on swift3

```bash
export CARGO_HOME=/root/work/peregrine-cargo-home
SRC=/root/work/peregrine-cold-physical-77dd9f4/swift-rust
cd "$SRC"
# confirm tip markers present
grep -n cold_backend_root crates/swift-proxy-server/src/main.rs | head
cargo build --release -p swift-proxy-server --features ec
BIN=$SRC/target/release/swift-proxy-server
sha256sum "$BIN" | tee "$EV/built.sha256"
strings "$BIN" | grep -E 'cold_backend_root|filecold' | head | tee "$EV/built.cold-strings.txt"
# seal like prior artifacts
STAGE=/root/work/peregrine-artifacts/peregrine-proxy-c716103-ec
rm -rf "$STAGE" && mkdir -p "$STAGE" && cp -a "$BIN" "$STAGE/swift-proxy-server"
( cd /root/work/peregrine-artifacts && tar -czf peregrine-proxy-c716103-ec.tar.gz -C peregrine-proxy-c716103-ec . )
sha256sum /root/work/peregrine-artifacts/peregrine-proxy-c716103-ec.tar.gz | tee "$EV/artifact-tar.sha256"
```

Adapt `deploy-peregrine-proxy-only-77dd9f4.sh` → `...-c716103.sh` (change `commit=c716103` only) **or** perform the same binary swap manually with identical evidence fields. Do **not** let the deploy script touch config.

### A2. Drain pattern (match canary-77dd9f4)

From Mac: `ssh swift3` (public). Inside lab VIP is fine from peers.

```bash
# stop proxy → HAProxy health checks fail → proxy3 DOWN (fall 3 × inter 5s)
systemctl stop swift-proxy.service
# wait inactive + health fail
for i in $(seq 1 60); do
  systemctl is-active swift-proxy.service 2>/dev/null | grep -qx inactive && break
  sleep 0.5
done
# read-only admin socket (no disable/enable write needed if stop+check is enough)
python3 - <<'PY'
import socket, time
s=socket.socket(socket.AF_UNIX); s.connect("/var/lib/haproxy/stats")
s.sendall(b"show stat\n"); time.sleep(0.3)
for line in s.recv(1<<20).decode().splitlines():
    if line.startswith("swift_proxy_back,proxy3,"):
        print("proxy3 status=", line.split(",")[17]); break
PY
# expect DOWN before binary replace
```

Do **not** change HAProxy/Keepalived config. Do **not** touch swift1/2/4 binaries or configs.

### A3. Install canary binary (swift3 only)

Use adapted deploy script against the sealed tar+sha, evidence under `$EV`, **or**:

```bash
cp -a /usr/local/bin/swift-proxy-server \
  /root/peregrine-proxy-rollback-c716103-swift3-${STAMP}/swift-proxy-server
# (mkdir rollback dir first)
install -o root -g root -m 0755 "$BIN" /usr/local/bin/swift-proxy-server
# restore SELinux context if enforcing
command -v restorecon >/dev/null && restorecon -v /usr/local/bin/swift-proxy-server
```

### A4. Apply config snippet (swift3 only) then start

```bash
# edit proxy-server.conf as in snippet above
systemctl start swift-proxy.service
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/healthcheck   # expect 200
# confirm wiring without printing secrets
grep -n cold_backend_root /etc/swift/proxy-server.conf
strings /usr/local/bin/swift-proxy-server | grep cold_backend_root | head
```

Keep proxy3 **out of VIP** until smoke passes (leave unit stopped from LB POV until health UP is intentional). When ready to rejoin VIP path: just leave `swift-proxy` healthy — checks will mark proxy3 UP. Prefer validating on **direct** `:8080` first.

### A5. Minimal restore canary (direct, not VIP)

Lab “direct” = hit **swift3** `http://10.0.0.3:8080` from inside lab (or SSH tunnel). Public Mac should use SSH to swift3 and curl localhost:8080. Path `/direct/...` is **not** a special HAProxy route here (local `/direct/healthcheck` → 403).

Source auth from env file **without printing**:

```bash
set -a
# shellcheck disable=SC1091
source /etc/swift/peregrine-lab.env
set +a
# use existing wave3/tempauth or EC2 SigV4 helpers; never echo keys
```

**Smoke A (wiring / negative path — always do):**
1. Auth + PUT/GET small object on account via S3 or Swift on `:8080` → 200.
2. `POST /bucket/key?restore` with `<RestoreRequest><Days>1</Days></RestoreRequest>` on a **warm** object → expect S3 `InvalidObjectState` (proves restore handler live, not 404 pipeline miss).
3. Proxy still healthy; no crash loops (`systemctl status`, journal).

**Smoke B (filecold restore — only if approved to plant sysmeta):**
1. `LocalDirColdBackend`-compatible plant under `/var/cache/peregrine-cold/{policy}/{account}/{container}/{key_hex}`.
2. Stamp object `X-Object-Sysmeta-S3-Transitioned: 1` and `X-Object-Sysmeta-S3-Cold-Backend-Uri: filecold://...` via Swift POST (sysmeta may require internal/reseller path — validate lab allows it).
3. `POST ?restore` → 202; `GET ?restore` shows restore status XML.
4. Without archive-on-transition this plant is **lab-only** and must be cleaned up.

Record redacted transcripts under `$EV/`.

### A6. Leave or roll back

Default after canary if not promoting: **rollback** (below). Leaving canary binary+config on swift3 while UP in VIP means ~25% of VIP traffic hits cold-wired binary (normal path should be unchanged when objects lack cold meta, but regression risk remains).

## Rollback (swift3)

```bash
systemctl stop swift-proxy.service
# wait proxy3 DOWN via stats socket (read-only show stat)
cp -a /etc/swift/proxy-server.conf.bak-pre-cold-c716103-* /etc/swift/proxy-server.conf
# pick the bak taken in A4
install -o root -g root -m 0755 \
  /root/peregrine-proxy-rollback-c716103-swift3-*/swift-proxy-server \
  /usr/local/bin/swift-proxy-server
# OR re-deploy sealed 77dd9f4 artifact:
#   /root/work/peregrine-artifacts/peregrine-proxy-77dd9f4-ec.tar.gz
#   sha 215f4d81a7bab1b373abc86c7e77f478f04b382878db01a8b00dde62c61825a2
#   live binary sha must return to 117d7b088e691be6826cca0fca067353bfc52c76f96b25aec1882f1d80d3052c
command -v restorecon >/dev/null && restorecon -v /usr/local/bin/swift-proxy-server
systemctl start swift-proxy.service
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/healthcheck
sha256sum /usr/local/bin/swift-proxy-server
grep cold_backend /etc/swift/proxy-server.conf || echo 'cold_backend absent OK'
# optional: rm -rf /var/cache/peregrine-cold
```

Prior 77dd9f4 rollback path evidence also exists at:
`/root/peregrine-proxy-rollback-77dd9f4-swift3-20260812T151839Z-NSGyC7`

## Non-goals / safety

- Do not commit.
- Do not print `/etc/swift/peregrine-lab.env` or HAProxy stats credentials.
- Do not change VIP / Keepalived / peer configs.
- Do not claim tape/Glacier; lab LocalDir only.
- Do not enable `cold_backend_root` fleet-wide until canary + archive story are accepted.
