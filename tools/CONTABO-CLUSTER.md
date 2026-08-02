# Contabo four-node Swift cluster (2026-08-01)

Greenfield Peregrine/Swift lab on Contabo. Replaces the Azure PAYG cutover
([`NEW-CLUSTER-CUTOVER.md`](NEW-CLUSTER-CUTOVER.md) — **retired**).

## Endpoints

| Node | Public SSH | Proxy | Storage | Replication |
|------|------------|-------|---------|-------------|
| swift1 (hub + VIP MASTER) | `169.58.108.85` | `10.0.0.1` | `10.0.4.1` | `10.0.8.1` |
| swift2 | `169.58.108.86` | `10.0.0.2` | `10.0.4.2` | `10.0.8.2` |
| swift3 | `169.58.108.87` | `10.0.0.3` | `10.0.4.3` | `10.0.8.3` |
| swift4 | `169.58.108.121` | `10.0.0.4` | `10.0.4.4` | `10.0.8.4` |

- Keepalived VIP: **`10.0.0.10`** (swift1 MASTER)
- Client API (preferred): `http://10.0.0.10:8085` (HAProxy → local `127.0.0.1:8080`)
- Per-node HAProxy: `http://10.0.0.N:8085`
- Auth (tempauth): `test:tester` / `azure-swift-2026.bench` (name historical)
- Console (swift1 loopback): `ssh -L 9000:127.0.0.1:9000 swift1` → http://127.0.0.1:9000/
- Shadow peer: Python SAIO `http://127.0.0.1:8090` (label **Python SAIO**; not Rust `:8081`)
- Rust SAIO: `http://127.0.0.1:8081`
- Prometheus: `http://127.0.0.1:9090` (ssh tunnel)

## Devices

Each node: `/srv/node/{d1,d2,d3}` XFS (12 devices total). Rings use storage
`10.0.4.N` and replication `10.0.8.N`. **Do not format/wipe** these mounts.

Policies: `default` (replication) + `ec-2-1` (`liberasurecode_rs_vand`).

## Hub services (swift1)

- `swift-console` `:9000` — `swift_base=http://10.0.0.10:8085`,
  `shadow_peer_base=http://127.0.0.1:8090`
- Deploy UI (loopback): `swift-deploy ui` on `127.0.0.1:8789` → console `/deploy`
- Prometheus `127.0.0.1:9090` + recording rules → `swift_request_total` from statsd;
  Loki `:3100`; Alloy on all nodes (journal → Loki)
- `node_exporter` / `statsd_exporter` on all nodes
- `autocos` / `cabt` (cosbench-rs)
- memcached (SAIO)

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
