# Contabo four-node Swift cluster (2026-08-01)

> **2026-08-05+ 交接（现行）：**  
> [`docs/fairness-lab/HANDOFF-20260805-PRODUCTION-REMAINING.md`](../docs/fairness-lab/HANDOFF-20260805-PRODUCTION-REMAINING.md)  
> 人话卷宗：[`test-results/PRODUCTION-REMAINING-ROLLUP-20260805/ROLLUP-REPORT.html`](test-results/PRODUCTION-REMAINING-ROLLUP-20260805/ROLLUP-REPORT.html)  
> VIP 现为 **HTTPS** `https://10.0.0.10:8085`（自签）；Python 三节点 **PRESENT**（swift2/3/4）。下文若干「HTTP:8085 / 阶段3 FROZEN」段落为历史基线，以交接文档为准。

Greenfield Peregrine/Swift lab on Contabo. Replaces the Azure PAYG cutover
([`NEW-CLUSTER-CUTOVER.md`](NEW-CLUSTER-CUTOVER.md) — **retired**).

## Fairness lab (authoritative)

**Formal plan:** [`docs/fairness-lab/USER-METHOD-PLAN.md`](../docs/fairness-lab/USER-METHOD-PLAN.md)
(three phases). R0–R8 (2026-08-03) = **historical baseline / informal** only —
see [`docs/fairness-lab/ROUNDS.md`](../docs/fairness-lab/ROUNDS.md).

**Deploy target (stage 2 gate):** `swift-deploy apply` with `stack=rust`,
`ingress.mode=keepalived`, HAProxy **roundrobin** over `10.0.0.1–4:8080`,
shared HMAC tempauth. Manual `install-cluster` HA is not the source of truth.

**Gate status 2026-08-04:** **PASS** — evidence
[`deploy-rs-rust-lb-20260804/`](test-results/deploy-rs-rust-lb-20260804/).
Ops evidence of mid-flight LB fix (pre-gate): [`HA-LB-CORRECT-20260804.md`](test-results/HA-LB-CORRECT-20260804.md).

**USER-METHOD-PLAN progress 2026-08-04:**
- Stage 1A/1B **PASS** — `phase-1a-20260804/`, `phase-1b-20260804/`
- Stage 2 **completed breadth** — VIP matrix PASS / DIRECT WARN / chaos PASS / soak in
  [`phase-2-20260804/`](test-results/phase-2-20260804/) (VIP @ swift2 nopreempt; SAIO off)
- Stage 3 **FROZEN** Python path (`PYTHON_CLUSTER_ABSENT`) —
  [`phase-3-20260804/`](test-results/phase-3-20260804/)

## Endpoints

| Node | Public SSH | Proxy | Storage | Replication |
|------|------------|-------|---------|-------------|
| swift1 (VIP MASTER only) | `169.58.108.85` | `10.0.0.1` | `10.0.4.1` | `10.0.8.1` |
| swift2 | `169.58.108.86` | `10.0.0.2` | `10.0.4.2` | `10.0.8.2` |
| swift3 | `169.58.108.87` | `10.0.0.3` | `10.0.4.3` | `10.0.8.3` |
| swift4 (obs + console hub) | `169.58.108.121` | `10.0.0.4` | `10.0.4.4` | `10.0.8.4` |

- Keepalived VIP: **`10.0.0.10`** (priority 140/130/120/110 → swift1 MASTER by default)
- Client API (preferred): `http://10.0.0.10:8085` (HAProxy → **round-robin** `10.0.0.1–4:8080`)
- Per-node HAProxy: `http://10.0.0.N:8085` (same four-proxy pool)
- Evidence of real LB + failover: [`HA-LB-CORRECT-20260804.md`](test-results/HA-LB-CORRECT-20260804.md)
- Auth (tempauth): user `test:tester`; key is operator-managed in the
  root-readable `/etc/swift/peregrine-lab.env` and is never committed
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

## HAProxy + Keepalived (corrected 2026-08-04)

**Was broken as “LB”:** backends were local-only (`127.0.0.1:8080`) because
old Rust tempauth tokens were per-process (cross-proxy → 401). VIP was
failover-only, not multi-proxy throughput. Only swift1 bound `10.0.0.10:8085`,
so VIP move left the new MASTER with nothing listening → connection refused.

**Now:**
1. tempauth tokens are HMAC-signed with `swift_hash_path_prefix:suffix`
   (shared across proxies) → one token accepted on all four `:8080`.
2. HAProxy `swift_back` = `s1..s4` → `10.0.0.1..4:8080` check, `balance roundrobin`.
3. Every node binds **both** `10.0.0.N:8085` and `10.0.0.10:8085`
   (`net.ipv4.ip_nonlocal_bind=1`) so VIP failover has a live listener.

Verified 2026-08-04 from swift4: VIP auth/PUT/GET OK; 60 GETs split
~15/16/15/15 across s1–s4; stop keepalived+haproxy on swift1 → VIP to swift2,
auth/IO still 200; restore → VIP back to swift1.

HAProxy still strips `Content-Length` on HTTP 204 even when forced; Shadow
parity that cares about empty-body headers should hit a proxy `:8080` directly
when needed. Ops/Files use VIP `10.0.0.10:8085`.

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
