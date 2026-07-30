# swift-console

The web console for a Peregrine (Rust Swift) cluster: a files browser, deploy
control, live monitoring, and a chaos/verification lab, served from a single
Rust binary. Built on `axum`; no Node.js, no external frontend service — HTML,
CSS, and JS are served directly and the pages render without client-side
frameworks.

## Surfaces

| Area | Routes | What it does |
|------|--------|--------------|
| **Files** | `/files`, `/files/api/*` | S3-style browser: buckets/containers, objects, upload, folders, trash + restore, TempURL and TempURL keys, search (+ reindex), user management, bulk ZIP download. |
| **Deploy** | `/deploy`, `/deploy/*` | Front end over `swift-deploy-rs`'s plan / validate / apply control API. |
| **Monitor** | `/monitor`, `/api/v1/query`, `/api/v1/query_range` | Live cluster metrics proxied from Prometheus, logs from Loki. |
| **Lab** | `/lab`, `/lab/ring`, `/lab/policy`, `/lab/capsule`, `/lab/tombstone`, `/lab/chaos`, `/lab/shadow`, `/lab/warehouse`, `/lab/api/*` | Chaos and verification tooling: ring what-if, policy compare, capsule, tombstone inspection, chaos runs, shadow corpus, warehouse jobs. |
| **Auth** | `/login`, `/auth/v1` | tempauth session login; issues a session cookie. |

## Module map (`src/`)

| Module | Role |
|--------|------|
| `main.rs` | axum router, session middleware, static assets |
| `session.rs` | login, session cookies |
| `pages.rs` | server-rendered HTML pages |
| `files_api.rs`, `search.rs`, `zipstream.rs` | the Files surface + bulk ZIP streaming |
| `swift.rs`, `proxy.rs` | talking to the Swift proxy over the storage API |
| `monitor.rs` | Prometheus / Loki metric + log queries |
| `nodes.rs`, `admin.rs`, `policyapi.rs` | cluster nodes, admin actions, storage-policy API |
| `ringscope.rs`, `ringlab.rs` | ring inspection and what-if simulation |
| `chaos.rs`, `shadow.rs`, `tombstone.rs`, `capsule.rs`, `warehouse.rs`, `economist.rs` | the Lab: fault injection, verification corpora, tombstone/capsule inspection, warehouse jobs, cost view |
| `lab.rs`, `testing.rs` | lab wiring and in-console test runners |
| `i18n.rs` | English / Chinese translations |
| `util.rs` | shared helpers |

## Build & run

```sh
cargo build --release
./target/release/swift-console conf/config.json
```

`conf/config.json` sets the bind address, the Swift proxy base URL and auth
endpoint, the deploy upstream + token file, the metrics/logs upstreams, the
TempURL default lifetime, the account roster, and per-cluster node metadata.
The service unit is in `conf/swift-console.service`.

## Configuration

Key `config.json` fields:

- `bind` — listen address (default loopback; front with the cluster LB).
- `swift_base`, `auth_url` — the Swift proxy and its `/auth/v1.0`.
- `deploy_upstream`, `deploy_token_file` — the `swift-deploy-rs` control API.
- `metrics_url`, `logs_url` — Prometheus and Loki.
- `tempurl_default_secs`, `max_upload_bytes`, `session_idle_hours`.
- `accounts`, `cluster_nodes`, `proxy_nodes` — the roster and topology.

## Security

The console holds an authenticated session and proxies privileged operations;
it is intended to listen on loopback (or a trusted network) behind the cluster
load balancer, not to be exposed directly. The deploy control API it fronts is
itself token-authenticated.
