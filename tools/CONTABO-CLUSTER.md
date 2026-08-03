# Contabo four-node Swift cluster (2026-08-01)

Greenfield Peregrine/Swift lab on Contabo. Replaces the Azure PAYG cutover
([`NEW-CLUSTER-CUTOVER.md`](NEW-CLUSTER-CUTOVER.md) — **retired**).

## Fairness lab (2026-08-03)

Contabo is a **hybrid** on `swift-deploy-rs` (`bundle-rust` + Keepalived /
monitoring / SAIO overlays) — **not** full Python ansible parity. Formal
experiments follow three modes (Compatibility / Performance / Chaos): see
[`docs/fairness-lab/`](../docs/fairness-lab/) and
[`tools/fairness-lab/`](fairness-lab/).

**R1–R7 (2026-08-03) fairness batch:** hub on **swift4**; dual SAIO on **swift3**
(`:8090`/`:8081` @ `10.0.0.3`); R3 compat GREEN; R4 DIRECT-4PROXY Rust formal
GREEN (16MB_read WARN); R5 HA-PATH ONLY 分册; R6 chaos/soak GREEN; R7 four
scorecards. Evidence: `test-results/fairness-lab-R{1..7}-20260803/` · batch
[`fairness-lab-R7-20260803/REPORT.html`](test-results/fairness-lab-R7-20260803/REPORT.html).
Old SAIO 3.45×/3.79× remain **NOISY**. VIP = **HA-PATH ONLY**; core throughput =
**DIRECT-4PROXY** (`10.0.0.1–4:8085`). Python Performance formal **FROZEN**.

## Endpoints

| Node | Public SSH | Proxy | Storage | Replication |
|------|------------|-------|---------|-------------|
| swift1 (VIP MASTER only) | `169.58.108.85` | `10.0.0.1` | `10.0.4.1` | `10.0.8.1` |
| swift2 | `169.58.108.86` | `10.0.0.2` | `10.0.4.2` | `10.0.8.2` |
| swift3 | `169.58.108.87` | `10.0.0.3` | `10.0.4.3` | `10.0.8.3` |
| swift4 (obs + console hub) | `169.58.108.121` | `10.0.0.4` | `10.0.4.4` | `10.0.8.4` |

- Keepalived VIP: **`10.0.0.10`** (swift1 MASTER)
- Client API (preferred): `http://10.0.0.10:8085` (HAProxy → local `127.0.0.1:8080`)
- Per-node HAProxy: `http://10.0.0.N:8085`
- Auth (tempauth): `test:tester` / `azure-swift-2026.bench` (name historical)
- Console / Prom / Loki (swift4 loopback):
  `ssh -L 9000:127.0.0.1:9000 -L 9090:127.0.0.1:9090 -L 3100:127.0.0.1:3100 swift4`
- Shadow peer: Python SAIO `@swift3` → `http://10.0.0.3:8090` (Rust SAIO `:8081`)
- Alloy → Loki: `http://10.0.0.4:3100/loki/api/v1/push` (all nodes)

## Devices

Each node: `/srv/node/{d1,d2,d3}` XFS (12 devices total). Rings use storage
`10.0.4.N` and replication `10.0.8.N`. **Do not format/wipe** these mounts.

Policies: `default` (replication) + `ec-2-1` (`liberasurecode_rs_vand`).

## Hub services (swift4 · post-R1)

- `swift-console` `:9000` — `swift_base=http://10.0.0.10:8085`,
  shadow peer → `http://10.0.0.3:8090` (Python SAIO @swift3)
- Deploy UI (loopback): `swift-deploy ui` on `127.0.0.1:8789` → console `/deploy`
- Prometheus `127.0.0.1:9090`; Loki `*:3100`; Alloy on all nodes → swift4 Loki
- `node_exporter` / `statsd_exporter` on all nodes
- `autocos` / `cabt` (cosbench-rs) remain where installed
- memcached on cluster nodes (cluster cache — not hub pollution)

## HAProxy note

Rust tempauth is per-process. HAProxy backends must stay **local-only**
(`127.0.0.1:8080`). Fan-out across peer proxies causes cross-node **401**.

HAProxy still strips `Content-Length` on HTTP 204 even when forced; Shadow
parity therefore compares side A via **local** `127.0.0.1:8080` (not VIP).
Ops/Files keep using VIP `10.0.0.10:8085`.

## Security (2026-08-01 hardening)

- firewalld: eth0 `public` **DROP** + ssh only; eth1/2/3 `trusted`
- SSH: `PasswordAuthentication no` (key-only); hosts `swift1–4`
- Bind lockdown: HAProxy/proxy/object on private/loopback — not on public eth0
- Evidence: `console-hardening/00-SECURITY.md`

## Build / redeploy

```bash
ssh swift1
export PATH=/usr/local/bin:/root/.cargo/bin:$PATH
cd /root/work/swift-rust
cargo build --release \
  --features swift-proxy-server/ec,swift-object-server/ec
install -m755 target/release/swift-proxy-server target/release/swift-object-server /usr/local/bin/
restorecon /usr/local/bin/swift-*server
# fan-out: stop → scp → start on swift2–4 (files busy if copied while running)
systemctl restart swift-proxy swift-object
```

## Verified (2026-08-01 Contabo)

Evidence root: `/root/contabo-deploy-20260801T125749Z/`  
Mac mirror: `tools/test-results/contabo-deploy-20260801/`  
Drive: `gdrive:Peregrine/2026-08-01-contabo/`

| Gate | Result |
|------|--------|
| G0–G8 install | PASS (VIP auth 100/100; func 54/54; HA; EC heal; prom 4/4) |
| R1 func ×4 + VIP + rust-saio | FAIL=0 |
| R2 HA / recon / py-saio | FAIL=0 |
| Perf matrix | ACCEPT_WITH_WARN; **4KB write→read fail=0** (see known limits) |
| Lab12 deep | **ACCEPT** — Shadow dual `breaking=0`; chaos×4; nodes HA 20/20; capsule/tombstone/warehouse PASS (`lab12-deep-wave3b`) |
| Console surface | **ACCEPT** — `CONSOLE-MATRIX.md` (Files/Deploy/Monitor/Lab/Test) |
| Security hardening | **ACCEPT** — `00-SECURITY.md` |

## Perf known limits (Wave 4 — document, not blocking)

From `61-PERF-SUMMARY.md` / ACCEPT_WITH_WARN:

| Workload | Limit / note |
|----------|----------------|
| 4KB write→read @128 | Hard gate: **fail=0** — PASS |
| 1MB write/read @32 | fail=0 |
| 16MB write @8 / 60s | Only ~184 ops seeded — prepare cannot fill large object sets in one minute |
| 16MB read @8 | WARN: prepare success ~14%; do not treat as client bug — raise runtime/object budget or lower concurrency for large-object sweeps |
| EC GET high concurrency | e.g. 1MB GET conc=32 saw err=4 — EC reconstruct under fan-out is the ceiling, not 4KB path |
| Client | `ulimit -n=65535`; prefer VIP or `10.0.0.1:8085`; sysctl tw_reuse/port_range |

Re-tune only if a product SLO requires sustained 16MB / high-conc EC; otherwise keep as known lab limits.
