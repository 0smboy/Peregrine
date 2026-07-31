//! Swift Console: unified Files / Deploy / Monitor management UI.
//!
//! One binary, bound to loopback. Files talks to the Swift cluster through
//! the LB with per-session tokens; Deploy and Monitor are reverse-proxied
//! with server-side credentials that never reach the browser.

mod admin;
mod capsule;
mod chaos;
mod debt;
mod economist;
mod expired;
mod genome;
mod profilemap;
mod files_api;
mod i18n;
mod lab;
mod monitor;
mod nodeops;
mod nodes;
mod pages;
mod policyapi;
mod proxy;
mod ringlab;
mod ringscope;
mod shadow;
mod search;
mod session;
mod swift;
mod testing;
mod tombstone;
mod warehouse;
mod util;
mod zipstream;

use axum::extract::DefaultBodyLimit;
use axum::routing::{any, delete, get, post, put};
use axum::Router;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize, Clone)]
pub struct AccountEntry {
    pub tenant: String,
    pub user: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Deserialize, Clone)]
pub struct Config {
    #[serde(default = "d_bind")]
    pub bind: String,
    pub auth_url: String,
    pub swift_base: String,
    pub deploy_upstream: String,
    #[serde(default = "d_deploy_user")]
    pub deploy_user: String,
    pub deploy_token_file: String,
    #[serde(default)]
    pub grafana_upstream: String,
    #[serde(default = "d_grafana_user")]
    pub grafana_user: String,
    /// Metrics backend (range/instant query API). Neutral name so the console
    /// never names the underlying technology, even in its own config.
    #[serde(default = "d_metrics")]
    pub metrics_url: String,
    /// Log backend (range/log query API).
    #[serde(default = "d_logs")]
    pub logs_url: String,
    #[serde(default = "d_cluster")]
    pub cluster_name: String,
    #[serde(default)]
    pub accounts: Vec<AccountEntry>,
    #[serde(default = "d_idle")]
    pub session_idle_hours: u64,
    #[serde(default = "d_max_upload")]
    pub max_upload_bytes: u64,
    #[serde(default = "d_tempurl_default")]
    pub tempurl_default_secs: u64,
    /// Proxy nodes whose tempauth config the Tenants & Users admin edits.
    /// Empty (the default) leaves account administration unavailable.
    #[serde(default)]
    pub proxy_nodes: Vec<String>,
    #[serde(default = "d_ssh_key")]
    pub ssh_key: String,
    #[serde(default = "d_proxy_conf")]
    pub proxy_conf: String,
    #[serde(default = "d_proxy_service")]
    pub proxy_service: String,
    #[serde(default = "d_proxy_port")]
    pub proxy_port: u16,
    /// Master switch for the Tenants & Users admin surface (off by default —
    /// it restarts live proxies, so it must be turned on deliberately).
    #[serde(default)]
    pub account_admin: bool,

    // ---- Lab surface (all default-off: an unchanged config keeps today's UI) ----
    #[serde(default)]
    pub lab_enabled: bool,
    /// Testing surface (runs real load against the cluster), off by default.
    #[serde(default)]
    pub test_enabled: bool,
    #[serde(default = "d_autocos_bin")]
    pub autocos_bin: String,
    #[serde(default = "d_autocos_home")]
    pub autocos_home: String,
    /// Credentials the benchmark authenticates with. Kept separate from the
    /// console session: a load test should not run as whoever is signed in.
    #[serde(default)]
    pub test_account: String,
    #[serde(default)]
    pub test_user: String,
    #[serde(default)]
    pub test_key: String,
    /// Cluster nodes across all three planes. Falls back to `proxy_nodes`.
    #[serde(default)]
    pub cluster_nodes: Vec<nodes::NodeCfg>,
    #[serde(default = "d_swift_dir")]
    pub swift_dir: String,
    #[serde(default = "d_node_root")]
    pub node_root: String,
    #[serde(default = "d_ringsim")]
    pub ringsim_bin: String,
    #[serde(default = "d_getnodes")]
    pub getnodes_bin: String,
    #[serde(default = "d_objinfo")]
    pub objinfo_bin: String,
    /// Chaos Arcade's write path. Off by default; when on, every mutation must
    /// stay under `lab_root` and carries an auto-expiring undo.
    #[serde(default)]
    pub lab_mutations: bool,
    #[serde(default)]
    pub lab_root: String,
}

fn d_autocos_bin() -> String {
    "/usr/local/bin/autocos".into()
}
fn d_autocos_home() -> String {
    "/root/.autocos".into()
}
fn d_swift_dir() -> String {
    "/etc/swift".into()
}
fn d_node_root() -> String {
    "/srv/node".into()
}
fn d_ringsim() -> String {
    "/usr/local/bin/swift-ring-sim".into()
}
fn d_getnodes() -> String {
    "/usr/local/bin/swift-get-nodes".into()
}
fn d_objinfo() -> String {
    "/usr/local/bin/swift-object-info".into()
}

fn d_bind() -> String {
    "127.0.0.1:9000".into()
}
fn d_deploy_user() -> String {
    "operator".into()
}
fn d_grafana_user() -> String {
    "admin".into()
}
fn d_metrics() -> String {
    "http://127.0.0.1:10904".into()
}
fn d_logs() -> String {
    "http://172.18.1.2:3100".into()
}
fn d_ssh_key() -> String {
    "/root/.ssh/id_cluster".into()
}
fn d_proxy_conf() -> String {
    "/etc/swift/proxy-server.conf".into()
}
fn d_proxy_service() -> String {
    "swift-proxy".into()
}
fn d_proxy_port() -> u16 {
    8080
}
fn d_cluster() -> String {
    "swift".into()
}
fn d_idle() -> u64 {
    24
}
fn d_max_upload() -> u64 {
    1024 * 1024 * 1024
}
fn d_tempurl_default() -> u64 {
    86400
}

pub struct AppState {
    pub cfg: Config,
    pub http: reqwest::Client,
    pub sessions: session::SessionStore,
    pub deploy_basic: String,
    pub search: search::IndexStore,
    /// Storage policies, re-read from swift.conf at most once a minute.
    pub policy_cache: std::sync::Mutex<Option<(std::time::Instant, Vec<ringlab::PolicyInfo>)>>,
    /// Pending guarded mutations, with their undo scripts.
    pub journal: nodes::Journal,
    /// At most one benchmark in flight.
    pub tests: testing::TestStore,
}

#[tokio::main]
async fn main() {
    let cfg_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/swift-console/config.json".into());
    let raw = std::fs::read_to_string(&cfg_path)
        .unwrap_or_else(|e| panic!("cannot read config {cfg_path}: {e}"));
    let cfg: Config =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("bad config {cfg_path}: {e}"));

    let token = std::fs::read_to_string(&cfg.deploy_token_file)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", cfg.deploy_token_file));
    let deploy_basic = format!(
        "Basic {}",
        util::b64(format!("{}:{}", cfg.deploy_user, token.trim()).as_bytes())
    );

    let http = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("http client");

    let bind = cfg.bind.clone();
    let max_body = cfg.max_upload_bytes as usize + 65536;
    let state = Arc::new(AppState {
        sessions: session::SessionStore::new(cfg.session_idle_hours),
        cfg,
        http,
        deploy_basic,
        search: search::new_store(),
        policy_cache: std::sync::Mutex::new(None),
        journal: nodes::new_journal(),
        tests: testing::new_store(),
    });

    // Any guarded lab mutation past its TTL is reverted, so a fault always
    // heals even if the operator walks away mid-experiment.
    if state.cfg.lab_mutations {
        let sweeper = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tick.tick().await;
                nodes::sweep(&sweeper).await;
            }
        });
    }

    let app = Router::new()
        .route("/", get(pages::root))
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/favicon.svg", get(pages::favicon))
        .route("/static/console.css", get(pages::css))
        .route("/static/console.js", get(pages::js))
        .route("/login", get(pages::login_page).post(pages::login_submit))
        .route("/logout", post(pages::logout))
        .route("/theme", post(pages::theme_set))
        .route("/lang", post(pages::lang_set))
        // Files surface: pages
        .route("/files", get(pages::buckets_page))
        .route("/files/b/{bucket}", get(pages::objects_page))
        .route("/files/trash", get(pages::trash_page))
        .route("/files/account", get(pages::account_page))
        .route("/files/users", get(pages::users_page))
        .route("/files/search", get(pages::search_page))
        .route(
            "/files/api/search",
            get(search::search),
        )
        .route("/files/api/search/reindex", post(search::reindex))
        // Tenants & Users admin API (admin-gated inside the handlers).
        .route(
            "/files/api/users",
            get(admin::list_accounts).post(admin::upsert_account),
        )
        .route("/files/api/users/delete", post(admin::delete_account))
        // Files surface: JSON API
        .route("/files/api/whoami", get(files_api::whoami))
        .route(
            "/files/api/buckets",
            get(files_api::buckets_list).post(files_api::bucket_create),
        )
        .route("/files/api/bucket/{bucket}", delete(files_api::bucket_delete))
        .route(
            "/files/api/bucket/{bucket}/meta",
            get(files_api::bucket_meta_get).post(files_api::bucket_meta_set),
        )
        .route(
            "/files/api/bucket/{bucket}/objects",
            get(files_api::objects_list),
        )
        .route(
            "/files/api/bucket/{bucket}/count",
            get(files_api::prefix_count),
        )
        .route(
            "/files/api/obj/{bucket}/{*path}",
            put(files_api::obj_put).delete(files_api::obj_delete),
        )
        .route(
            "/files/api/objmeta/{bucket}/{*path}",
            get(files_api::obj_meta_get).post(files_api::obj_meta_set),
        )
        .route("/files/api/folder", post(files_api::folder_create))
        .route("/files/api/delete-folder", post(files_api::folder_delete))
        .route(
            "/files/api/trash",
            get(files_api::trash_list).post(files_api::trash_move),
        )
        .route("/files/api/trash/restore", post(files_api::trash_restore))
        .route("/files/api/trash/delete", post(files_api::trash_delete))
        .route("/files/api/trash/empty", post(files_api::trash_empty))
        .route("/files/api/tempurl", post(files_api::tempurl_make))
        .route(
            "/files/api/tempurl-key",
            get(files_api::tempurl_key_get).post(files_api::tempurl_key_set),
        )
        .route(
            "/files/api/account",
            get(files_api::account_get).post(files_api::account_set),
        )
        .route("/files/download/{bucket}/{*path}", get(files_api::download))
        .route("/files/zip/{bucket}", get(files_api::zip_download))
        // Deploy surface: shell + proxy (the deploy UI uses absolute
        // /app.js, /app.css and /api/* paths, so those proxy too).
        .route("/deploy", get(pages::deploy_shell))
        .route("/deploy/", any(proxy::deploy))
        .route("/deploy/{*path}", any(proxy::deploy))
        .route("/app.js", any(proxy::deploy))
        .route("/app.css", any(proxy::deploy))
        .route("/api/{*path}", any(proxy::deploy))
        // Lab surface: tools that explain the cluster. Gated on lab_enabled.
        // Testing surface: real load against the cluster via autocos.
        .route("/test", get(pages::test_page))
        .route("/test/api/runs", get(testing::runs))
        .route("/test/api/run", post(testing::start))
        .route("/test/api/export.csv", get(testing::export))
        .route("/lab", get(pages::lab_index))
        // Node down/up — the HA drill (stops a whole node's swift services with
        // a journaled, TTL-auto-restart undo). Never touches the console itself.
        .route("/lab/nodes", get(nodeops::page))
        .route("/lab/api/node/status", get(nodeops::status))
        .route("/lab/api/node/down", post(nodeops::down))
        .route("/lab/api/node/up", post(nodeops::up))
        .route("/lab/debt", get(debt::page))
        .route("/lab/api/debt/snapshot", get(debt::snapshot))
        .route("/lab/expired", get(expired::page))
        .route("/lab/api/expired/run", post(expired::run))
        .route("/lab/api/expired/poll", post(expired::poll))
        .route("/lab/api/expired/status", get(expired::status))
        .route("/lab/profilemap", get(profilemap::page))
        .route("/lab/api/profilemap/pulse", post(profilemap::pulse))
        .route("/lab/api/profilemap/snapshot", get(profilemap::snapshot))
        .route("/lab/genome", get(genome::page))
        .route("/lab/api/genome/evolve", post(genome::evolve))
        .route("/lab/api/genome/result", get(genome::result))
        .route("/lab/ring", get(pages::lab_ring))
        .route("/lab/policy", get(pages::lab_policy))
        .route("/lab/api/policy/defaults", get(policyapi::defaults))
        .route("/lab/api/policy/compare", post(policyapi::compare))
        .route("/lab/api/ring/topology", get(ringscope::topology))
        .route("/lab/api/ring/simulate", post(ringscope::simulate))
        .route("/lab/api/ring/part", get(ringscope::part))
        .route("/lab/capsule", get(capsule::page))
        .route(
            "/lab/capsule/{account}/{container}/{*object}",
            get(capsule::page_obj),
        )
        .route("/lab/api/capsule", get(capsule::api))
        .route("/lab/tombstone", get(tombstone::page))
        .route(
            "/lab/tombstone/{account}/{container}/{*object}",
            get(tombstone::page_obj),
        )
        .route("/lab/api/tombstone", get(tombstone::api))
        .route("/lab/api/chaos/catalogue", get(chaos::catalogue))
        .route("/lab/api/chaos/recover", post(chaos::recover))
        // Reserved up front so four parallel agents never race main.rs.
        .route("/lab/chaos", get(chaos::page))
        .route("/lab/api/chaos/run", post(chaos::run))
        .route("/lab/api/chaos/status", get(chaos::status))
        .route("/lab/shadow", get(shadow::page))
        .route("/lab/api/shadow/run", post(shadow::run))
        .route("/lab/api/shadow/corpus", get(shadow::corpus))
        .route("/lab/api/shadow/replay", post(shadow::replay))
        .route("/lab/api/shadow/mutate", post(shadow::mutate))
        .route("/lab/warehouse", get(warehouse::page))
        .route("/lab/api/warehouse/jobs", get(warehouse::jobs))
        .route("/lab/api/warehouse/sample", get(warehouse::sample))
        .route("/lab/api/warehouse/job", post(warehouse::create_job))
        .route("/lab/api/warehouse/promote", post(warehouse::promote))
        .route("/mcp", post(warehouse::mcp))
        // Monitor surface: native, white-labeled dashboards. Queries run
        // server-side; no backend name, URL, or config reaches the browser.
        .route("/monitor", get(pages::monitor_page))
        .route("/monitor/api/dash", get(monitor::dash_catalog))
        .route("/monitor/api/panel", get(monitor::panel_data))
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {bind}: {e}"));
    eprintln!("swift-console {} listening on {}", pages::VERSION, bind);
    axum::serve(listener, app).await.expect("server");
}
