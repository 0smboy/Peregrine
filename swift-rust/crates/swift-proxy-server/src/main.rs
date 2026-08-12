// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `swift-proxy-server <config.conf>`: loads the account/container/object rings
//! from SWIFT_DIR (default /etc/swift) and serves the v1 REST API. Storage
//! policies (incl. erasure coding) come from SWIFT_CONF; a `[filter:tempauth]`
//! section with `user_*` records turns on tempauth, and a `[filter:ratelimit]`
//! section turns on account/container rate limiting.
//!
//! Operational behavior: logs through syslog (stderr fallback) at `log_level`,
//! emits statsd request metrics when `log_statsd_host` is set, exports one
//! OTLP trace span per client request when `trace_endpoint` is set, drains
//! and exits cleanly on SIGTERM/SIGINT, and hot-reloads any ring whose file
//! mtime changes (checked every 15s) without restarting.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use swift_core::config::{config_true_value, SwiftConfig};
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::otlp::{self, AttrValue, TraceExporter, TraceSpan};
use swift_core::statsd::StatsdClient;
use swift_core::storage_policy::{parse_storage_policies, StoragePolicyCollection};
use swift_proxy_server::{EcPolicyParams, ProxyApp, ProxyConfig, ProxyEndpointResolver};
use swift_ring::{Ring, RingData};

/// How often the reload thread re-stats the ring files (Python
/// `ring_check_interval`).
const RING_CHECK_INTERVAL: Duration = Duration::from_secs(15);

fn parse_conf_file(path: &str) -> Result<SwiftConfig, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    SwiftConfig::parse_lenient(&content, &[], false).map_err(|e| e.to_string())
}

/// Load and validate exactly one object ring for every configured storage
/// policy. Missing policy rings and EC replica-count mismatches are startup
/// errors: silently routing a non-default policy through `object.ring.gz`
/// can write objects to the wrong on-disk namespace.
fn build_policy_object_rings<F>(
    policies: &StoragePolicyCollection,
    hash_config: &HashPathConfig,
    mut load: F,
) -> Result<(Ring, std::collections::HashMap<i64, Ring>), String>
where
    F: FnMut(&str) -> Result<RingData, String>,
{
    let mut legacy_ring = None;
    let mut policy_rings = std::collections::HashMap::new();
    for policy in policies.iter() {
        let ring_name = policy.ring_name();
        let data = load(ring_name)?;
        policy
            .validate_ring_replica_count(data.replica_count())
            .map_err(|e| format!("invalid {ring_name}.ring.gz: {e}"))?;
        let ring = Ring::new(data, hash_config.clone());
        if policy.idx() == 0 {
            legacy_ring = Some(ring);
        } else {
            policy_rings.insert(policy.idx() as i64, ring);
        }
    }
    legacy_ring
        .map(|ring| (ring, policy_rings))
        .ok_or_else(|| "storage policy 0 has no object ring".to_string())
}

fn main() {
    let conf_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: swift-proxy-server <config.conf>");
        std::process::exit(1);
    });
    let conf = parse_conf_file(&conf_path).unwrap_or_else(|e| {
        eprintln!("could not read {conf_path}: {e}");
        std::process::exit(1);
    });
    let section = "app:proxy-server";
    let get = |key: &str, default: &str| -> String {
        conf.get(section, key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };

    // Observability first, so every later startup error reaches syslog: the
    // logger (with stderr fallback) and a statsd client that is a no-op
    // until log_statsd_host is configured.
    let options = server_options_from_conf(&conf);
    let level = options
        .log_level
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&options.log_name, level);
    let statsd = StatsdClient::new(
        &options.log_statsd_host,
        options.log_statsd_port,
        &options.log_statsd_metric_prefix,
    );
    let tracer = TraceExporter::new(
        &options.trace_endpoint,
        options.trace_sample_ratio,
        "swift-proxy",
        Arc::clone(&logger),
    );

    let swift_conf_path = std::env::var("SWIFT_CONF").unwrap_or_else(|_| {
        format!(
            "{}/swift.conf",
            std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string())
        )
    });
    let swift_conf = parse_conf_file(&swift_conf_path).unwrap_or_else(|e| {
        logger.error(&format!("could not read {swift_conf_path}: {e}"));
        std::process::exit(1);
    });
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });
    let policies = parse_storage_policies(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf storage policies: {e}"));
        std::process::exit(1);
    });

    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());

    // Storage policies from swift.conf: EC schemes (by index) and the
    // name→index table for resolving container X-Storage-Policy.
    let ec_policies = policies
        .iter()
        .filter_map(|p| {
            p.ec().map(|ec| {
                let ndata = ec.ec_ndata as usize;
                // Python EC quorum = ndata + min_parity (× dup_factor);
                // recover min_parity so a mis-set config can't silently
                // change the write quorum.
                let min_parity = (p.quorum(0.0) as usize).saturating_sub(ndata).max(1);
                (
                    p.idx() as i64,
                    EcPolicyParams {
                        ndata,
                        nparity: ec.ec_nparity as usize,
                        segment_size: ec.ec_segment_size as usize,
                        min_parity,
                    },
                )
            })
        })
        .collect();
    let policy_names: std::collections::HashMap<String, i64> = {
        let mut names = std::collections::HashMap::new();
        for p in policies.iter() {
            names.insert(p.name().to_string(), p.idx() as i64);
            for alias in p.alias_list() {
                names.insert(alias.clone(), p.idx() as i64);
            }
        }
        names
    };
    let policy_index_names: std::collections::HashMap<i64, String> = policies
        .iter()
        .map(|p| (p.idx() as i64, p.name().to_string()))
        .collect();

    // Build auth first: whether auth is in the pipeline decides whether the
    // proxy enforces ACLs (auth_enabled) — so a request path that forgets to
    // authorize cannot silently become world-accessible. TempAuth and
    // Keystone may coexist (different reseller tokens); Keystone authorize
    // wins when `X-Backend-Auth-Plugin: keystone` is stamped.
    let tempauth = build_tempauth(
        &conf,
        &swift_conf,
        &get("storage_url", "http://127.0.0.1:8080"),
    );
    let tempauth_on = tempauth.is_some() && configured_pipeline_has(&conf, "tempauth");
    let keystoneauth = build_keystoneauth(&conf);
    let keystone_on = keystoneauth.is_some() && configured_pipeline_has(&conf, "keystoneauth");
    let mut config = proxy_config_from_conf(&conf, tempauth_on || keystone_on);
    config.keystone_auth = keystoneauth.clone();
    let info_json = build_info_json(
        &swift_conf,
        &conf,
        config.account_autocreate,
        config.allow_account_management,
        tempauth_on,
    );

    // Clone policies for account_quotas before AppBuilder takes ownership.
    let policies_for_filters = policies.clone();

    // Everything a ProxyApp is built from lives in one struct, so startup and
    // the ring-reload thread share one build path. The object data plane must
    // use object.ring.gz, not the container ring — aliasing them mis-routes
    // every object to the wrong devices.
    let builder = AppBuilder {
        swift_dir,
        hash_config: hash_config.clone(),
        policies,
        ec_policies,
        policy_names,
        policy_index_names,
        info_json,
        config,
        memcache_servers: memcache_servers_csv(&conf),
    };
    let app = builder.build().unwrap_or_else(|e| {
        logger.error(&format!("could not load rings: {e}"));
        std::process::exit(1);
    });
    // The handler reads the current app on every request; the reload thread
    // swaps in a rebuilt one when a ring file changes on disk. Cloned into
    // tempurl's KeyProvider so signed URLs resolve live Temp-URL-Key meta.
    let app = Arc::new(RwLock::new(Arc::new(app)));

    let bind = format!("{}:{}", get("bind_ip", "0.0.0.0"), get("bind_port", "8080"));
    // Eventlet-like multi-process workers: `process_workers` (or numeric
    // `workers` when `worker_model=process`) forks after bind so each child
    // accepts on the shared socket (SO_REUSEADDR). Thread pool size remains
    // `worker_threads` / ServerConfig inside each process.
    let process_workers = process_workers_from_conf(&conf);
    let listener = std::net::TcpListener::bind(&bind).unwrap_or_else(|e| {
        logger.error(&format!("could not bind {bind}: {e}"));
        std::process::exit(1);
    });
    let _ = listener.set_nonblocking(false);
    if process_workers > 1 {
        prefork_workers(process_workers, &logger);
        logger.info(&format!(
            "swift-proxy-server process_workers={process_workers} (eventlet-like prefork)"
        ));
    }
    logger.info(&format!("swift-proxy-server listening on {bind}"));

    spawn_ring_reload_thread(builder, Arc::clone(&app), Arc::clone(&logger));

    // Graceful shutdown: SIGTERM/SIGINT set the flag, the accept loop stops
    // accepting, drains in-flight requests, and serve returns Ok.
    let shutdown = swift_http::install_sigterm_flag();

    // Swift access-log-ish line plus request metrics (and an OTLP span when
    // trace_endpoint is set), after every request:
    // client_ip method path status content-length elapsed-secs txn-id.
    // Must never panic — it runs on the server's request path.
    let access_logger = Arc::clone(&logger);
    let access_statsd = Arc::clone(&statsd);
    let access_tracer = Arc::clone(&tracer);
    let access_log: swift_http::AccessLog = Arc::new(
        move |req: &swift_http::Request, status: u16, elapsed: Duration| {
            let client_ip = req
                .headers
                .get("X-Forwarded-For")
                .and_then(|v| v.split(',').next())
                .map(str::trim)
                .filter(|ip| !ip.is_empty())
                .unwrap_or("-");
            let txn_id = req
                .headers
                .get("X-Trans-Id")
                .filter(|t| !t.is_empty())
                .unwrap_or("-");
            let path = if req.query_string.is_empty() {
                req.path.clone()
            } else {
                format!("{}?{}", req.path, req.query_string)
            };
            access_logger.info(&format!(
                "{client_ip} {} {path} {status} {} {:.4} {txn_id}",
                req.method,
                req.body.content_length().unwrap_or(0),
                elapsed.as_secs_f64(),
            ));
            access_statsd.increment(&format!("proxy-server.{}.{status}", req.method));
            access_statsd.timing("proxy-server.timing", elapsed.as_secs_f64() * 1000.0);
            if access_tracer.enabled() {
                let end_unix_nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let mut attributes = vec![
                    (
                        "http.request.method".to_string(),
                        AttrValue::Str(req.method.clone()),
                    ),
                    (
                        "http.response.status_code".to_string(),
                        AttrValue::Int(i64::from(status)),
                    ),
                    ("url.path".to_string(), AttrValue::Str(req.path.clone())),
                ];
                if txn_id != "-" {
                    attributes.push((
                        "swift.transaction_id".to_string(),
                        AttrValue::Str(txn_id.to_string()),
                    ));
                }
                access_tracer.submit(TraceSpan {
                    name: format!("swift.proxy {}", req.method),
                    trace_id: otlp::random_id(txn_id.as_bytes()),
                    span_id: otlp::random_id(&[]),
                    start_unix_nanos: end_unix_nanos.saturating_sub(elapsed.as_nanos()),
                    end_unix_nanos,
                    attributes,
                });
            }
        },
    );

    let mut server_config = swift_http::ServerConfig {
        connection_queue: options.max_clients,
        client_timeout_secs: options.client_timeout_secs,
        access_log: Some(access_log),
        shutdown: Some(shutdown),
        ..Default::default()
    };
    if let Some(workers) = options.workers {
        server_config.worker_threads = workers;
    }

    // Optional `[pipeline:main] pipeline = ...` orders the *implemented*
    // filters (P0–P1b). Always-on catch_errors / gatekeeper / healthcheck
    // stay in serve_with_filters_and_config. Absent pipeline → today's
    // default order. Unknown names fail startup by default. Operators may set
    // `strict_pipeline = false` to skip them or explicitly opt into a named
    // no-op with `plugin_default = passthrough`.
    let key_provider: Arc<dyn swift_middleware::KeyProvider> =
        Arc::new(ProxyTempUrlKeys::new(Arc::clone(&app)));
    let sync_key_provider: Arc<dyn swift_middleware::SyncKeyProvider> =
        Arc::new(ProxySyncKeys::new(Arc::clone(&app)));
    let endpoint_resolver: Arc<dyn swift_middleware::EndpointResolver> =
        Arc::new(ProxyEndpointResolver::new(Arc::clone(&app)));
    let (filters, notes, issues) = build_configured_filters_with_issues(
        &conf,
        tempauth,
        keystoneauth,
        Some(Arc::clone(&logger)),
        key_provider,
        sync_key_provider,
        endpoint_resolver,
        &policies_for_filters,
        hash_config.clone(),
    );
    let strict_pipeline = strict_pipeline_from_conf(&conf);
    for note in &notes {
        logger.info(note);
    }
    for issue in &issues {
        if strict_pipeline {
            logger.error(&format!("strict_pipeline: {issue}"));
        } else {
            logger.info(&format!("non-strict pipeline compatibility: {issue}"));
        }
    }
    if strict_pipeline_rejects(&conf, &issues) {
        logger.error(&format!(
            "strict_pipeline=true: refusing to start with {} unresolved pipeline filter(s)",
            issues.len()
        ));
        std::process::exit(1);
    }
    if let Err(e) =
        swift_proxy_server::serve_with_filters_and_config(listener, app, filters, server_config)
    {
        logger.error(&format!("server error: {e}"));
        std::process::exit(1);
    }
    logger.info("exiting");
}

/// Read the proxy data-plane tuning knobs from `[app:proxy-server]` (with
/// DEFAULT fallback, like `main`'s `get` closure) into a [`ProxyConfig`].
/// Parsing is lenient, matching this crate's conf handling elsewhere: a
/// missing or unusable value keeps its `proxy-server.conf` default.
fn proxy_config_from_conf(conf: &SwiftConfig, auth_enabled: bool) -> ProxyConfig {
    let get = |key: &str, default: &str| -> String {
        conf.get("app:proxy-server", key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };
    ProxyConfig {
        conn_timeout: conf_timeout_secs(&get("conn_timeout", ""), 0.5),
        node_timeout: conf_timeout_secs(&get("node_timeout", ""), 10.0),
        error_suppression_interval: get("error_suppression_interval", "")
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite())
            .unwrap_or(60.0),
        error_suppression_limit: get("error_suppression_limit", "")
            .trim()
            .parse::<u64>()
            .ok()
            .unwrap_or(10),
        account_autocreate: matches!(
            get("account_autocreate", "false").to_lowercase().as_str(),
            "true" | "1" | "yes" | "on" | "t" | "y"
        ),
        allow_account_management: matches!(
            get("allow_account_management", "false")
                .to_lowercase()
                .as_str(),
            "true" | "1" | "yes" | "on" | "t" | "y"
        ),
        strict_cors_mode: config_true_value(&get("strict_cors_mode", "true")),
        cors_allow_origin: get("cors_allow_origin", "")
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
        cors_expose_headers: get("cors_expose_headers", "")
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .collect(),
        // server.py:235-246: TTLs for the proxy's account/container info
        // cache (DEFAULT_RECHECK_{CONTAINER,ACCOUNT}_EXISTENCE = 60).
        recheck_container_existence: get("recheck_container_existence", "")
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite())
            .unwrap_or(60.0),
        recheck_account_existence: get("recheck_account_existence", "")
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite())
            .unwrap_or(60.0),
        auth_enabled,
        ..Default::default()
    }
}

/// Parse a conf timeout in (possibly fractional) seconds. A missing,
/// unparseable, non-finite, non-positive, or absurdly large (> 1e9 s) value
/// falls back to `default_secs`: `Duration::from_secs_f64` panics on the
/// garbage cases, and a zero timeout would fail every backend connect.
fn conf_timeout_secs(value: &str, default_secs: f64) -> Duration {
    let secs = value
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v > 0.0 && *v <= 1e9)
        .unwrap_or(default_secs);
    Duration::from_secs_f64(secs)
}

/// `[app:proxy-server]` HTTP-server and logging options (with DEFAULT
/// fallback), parsed leniently: a missing or unusable value falls back to
/// its `proxy-server.conf` default.
#[derive(Debug, PartialEq)]
struct ServerOptions {
    /// `workers`: HTTP worker threads. `None` (unset, `auto`, or `0`) keeps
    /// the server's CPU-scaled default.
    workers: Option<usize>,
    /// `max_clients`: bound on connections queued for a worker (default 1024).
    max_clients: usize,
    /// `client_timeout`: idle-client socket timeout, whole seconds
    /// (default 60; fractions round up).
    client_timeout_secs: u64,
    log_name: String,
    /// Raw `log_level` string; parsed into a `LogLevel` when the logger is
    /// built (unknown values fall back to Info there).
    log_level: String,
    /// `log_statsd_host`: empty leaves statsd disabled.
    log_statsd_host: String,
    log_statsd_port: u16,
    log_statsd_metric_prefix: String,
    /// `trace_endpoint`: `host:port` of an OTLP/HTTP collector; empty
    /// leaves trace export disabled.
    trace_endpoint: String,
    /// `trace_sample_ratio`: fraction of requests exported as spans,
    /// 0.0–1.0 (out-of-range or unparseable keeps the default 1.0).
    trace_sample_ratio: f64,
}

fn server_options_from_conf(conf: &SwiftConfig) -> ServerOptions {
    let get = |key: &str, default: &str| -> String {
        conf.get("app:proxy-server", key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };
    ServerOptions {
        workers: get("workers", "")
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|n| *n >= 1),
        max_clients: get("max_clients", "")
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|n| *n >= 1)
            .unwrap_or(1024),
        client_timeout_secs: get("client_timeout", "")
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite() && *v > 0.0 && *v <= 1e9)
            .map(|v| (v.ceil() as u64).max(1))
            .unwrap_or(60),
        log_name: get("log_name", "proxy-server"),
        log_level: get("log_level", "info"),
        log_statsd_host: get("log_statsd_host", ""),
        log_statsd_port: get("log_statsd_port", "")
            .trim()
            .parse::<u16>()
            .ok()
            .unwrap_or(8125),
        log_statsd_metric_prefix: get("log_statsd_metric_prefix", ""),
        trace_endpoint: get("trace_endpoint", ""),
        trace_sample_ratio: get("trace_sample_ratio", "")
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite() && (0.0..=1.0).contains(v))
            .unwrap_or(1.0),
    }
}

/// Build a `RateLimit` from a `[filter:ratelimit]` section, or `None` when
/// the conf has no such section. Presence is probed via the section's
/// `use =` line (the paste marker every real filter section carries), the
/// way `build_tempauth` keys off its section's `user_*` records.
fn build_ratelimit(conf: &SwiftConfig) -> Result<Option<swift_middleware::RateLimit>, String> {
    if conf
        .get("filter:ratelimit", "use")
        .map_err(|error| format!("could not read [filter:ratelimit] use: {error}"))?
        .is_none()
    {
        return Ok(None);
    }
    let mut options: std::collections::HashMap<String, String> = conf
        .items("filter:ratelimit")
        .map_err(|error| format!("could not read [filter:ratelimit]: {error}"))?
        .into_iter()
        .collect();
    options
        .entry("memcache_servers".to_string())
        .or_insert_with(|| memcache_servers_csv(conf));
    swift_middleware::RateLimit::try_from_conf(
        &options,
        Box::new(swift_middleware::SystemClock::new()),
    )
    .map(Some)
}

/// Resolve `memcache_servers` for `[filter:cache]`: section → app → DEFAULT
/// → Python default `127.0.0.1:11211`.
fn memcache_servers_csv(conf: &SwiftConfig) -> String {
    conf.get("filter:cache", "memcache_servers")
        .ok()
        .flatten()
        .or_else(|| {
            conf.get("app:proxy-server", "memcache_servers")
                .ok()
                .flatten()
        })
        .or_else(|| conf.get("DEFAULT", "memcache_servers").ok().flatten())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| swift_middleware::DEFAULT_MEMCACHE_SERVERS.to_string())
}

/// Build the `cache` filter (MemcacheClient holder). Always succeeds with
/// at least the default server list — connection is lazy on first op.
fn build_cache(conf: &SwiftConfig) -> Result<swift_middleware::Cache, String> {
    swift_middleware::Cache::from_servers_csv(&memcache_servers_csv(conf))
}

/// TempURL key lookup against the currently active proxy app. Ring reloads
/// replace the inner [`Arc<ProxyApp>`], so every lookup takes a fresh snapshot.
struct ProxyTempUrlKeys {
    app: Arc<RwLock<Arc<ProxyApp>>>,
}

impl ProxyTempUrlKeys {
    fn new(app: Arc<RwLock<Arc<ProxyApp>>>) -> Self {
        Self { app }
    }
}

impl swift_middleware::KeyProvider for ProxyTempUrlKeys {
    fn keys_for(&self, account: &str, container: &str) -> Vec<String> {
        let current = {
            let guard = self
                .app
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Arc::clone(&guard)
        };
        current.temp_url_keys(account, container)
    }
}

/// Container-sync user-key lookup against the live proxy app.
struct ProxySyncKeys {
    app: Arc<RwLock<Arc<ProxyApp>>>,
}

impl ProxySyncKeys {
    fn new(app: Arc<RwLock<Arc<ProxyApp>>>) -> Self {
        Self { app }
    }
}

impl swift_middleware::SyncKeyProvider for ProxySyncKeys {
    fn sync_key(&self, account: &str, container: &str) -> Option<String> {
        let current = {
            let guard = self
                .app
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Arc::clone(&guard)
        };
        current.container_sync_key(account, container)
    }
}

/// Build the bulk-delete half from `[filter:bulk]`. A missing or thin section
/// keeps Swift's `max_deletes_per_request = 10000` default.
fn build_bulk(conf: &SwiftConfig) -> swift_middleware::Bulk {
    let options: std::collections::HashMap<String, String> = conf
        .items("filter:bulk")
        .ok()
        .unwrap_or_default()
        .into_iter()
        .collect();
    swift_middleware::Bulk::from_conf(&options)
}

/// Build TempURL around the proxy-backed key provider. `methods` and
/// `allowed_digests` are optional; [`swift_middleware::TempUrl::new`] supplies
/// the Python defaults when either is absent.
fn build_tempurl(
    conf: &SwiftConfig,
    key_provider: Arc<dyn swift_middleware::KeyProvider>,
) -> swift_middleware::TempUrl {
    let mut tempurl = swift_middleware::TempUrl::new(key_provider);
    if let Some(methods) = conf
        .get("filter:tempurl", "methods")
        .ok()
        .flatten()
        .map(|value| {
            value
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty())
    {
        tempurl.methods = methods;
    }
    if let Some(allowed_digests) = conf
        .get("filter:tempurl", "allowed_digests")
        .ok()
        .flatten()
        .map(|value| {
            value
                .split_whitespace()
                .map(str::to_ascii_lowercase)
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty())
    {
        tempurl.allowed_digests = allowed_digests;
    }
    tempurl
}

/// Build `proxy_logging` from either hyphen or underscore section name.
fn build_proxy_logging(
    conf: &SwiftConfig,
    access_logger: Option<Arc<Logger>>,
) -> swift_middleware::ProxyLogging {
    let options: std::collections::HashMap<String, String> = conf
        .items("filter:proxy-logging")
        .ok()
        .or_else(|| conf.items("filter:proxy_logging").ok())
        .unwrap_or_default()
        .into_iter()
        .collect();
    let mut pl = swift_middleware::ProxyLogging::from_conf(&options);
    if let Some(logger) = access_logger {
        pl = pl.with_sink(Arc::new(move |line: &str| logger.info(line)));
    }
    pl
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SloOptions {
    concurrency: usize,
    yield_frequency: i64,
}

/// Read SLO options with the Python Swift 2.33 runtime defaults. PasteDeploy
/// merges `[DEFAULT]` into the filter's global configuration, so use it as a
/// fallback when the option is absent from `[filter:slo]`.
fn slo_options_from_conf(conf: &SwiftConfig) -> SloOptions {
    let get = |key: &str| -> Option<String> {
        conf.get("filter:slo", key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
    };
    let concurrency = get("concurrency")
        .and_then(|value| value.trim().parse::<i64>().ok())
        .map(|value| value.clamp(0, 1000) as usize)
        .unwrap_or(2);
    let yield_frequency = get("yield_frequency")
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or(10);

    SloOptions {
        concurrency,
        yield_frequency,
    }
}

fn build_slo(conf: &SwiftConfig, hash_config: HashPathConfig) -> swift_middleware::Slo {
    let options = slo_options_from_conf(conf);
    let mut slo = swift_middleware::Slo::with_hash_config(hash_config);
    slo.concurrent_gets = options.concurrency;
    slo.yield_frequency = options.yield_frequency as f64;
    slo
}

fn build_dlo(conf: &SwiftConfig) -> Result<swift_middleware::DynamicLargeObject, String> {
    // Python only reads `[filter:dlo]`. Do not inherit similarly-named knobs
    // from `[app:proxy-server]` / DEFAULT — that path caused live DLO
    // reassembly to diverge from the previously green DynamicLargeObject::new().
    let parse = |key: &str, default: i64| -> Result<i64, String> {
        conf.get("filter:dlo", key)
            .ok()
            .flatten()
            .map(|raw| {
                raw.trim()
                    .parse::<i64>()
                    .map_err(|_| format!("dlo: {key} has invalid integer {raw:?}"))
            })
            .unwrap_or(Ok(default))
    };
    Ok(swift_middleware::DynamicLargeObject::new()
        .with_max_get_time(parse("max_get_time", 86_400)?)
        .with_rate_limit_after_segment(parse("rate_limit_after_segment", 10)?)
        .with_rate_limit_segments_per_sec(parse("rate_limit_segments_per_sec", 1)?))
}

/// Names handled inside [`serve_with_filters_and_config`] (or the app itself).
/// Dropped when reading `pipeline =` so a Python-shaped line can be reused.
const ALWAYS_ON_OR_APP: &[&str] = &[
    "catch_errors",
    "catch-errors",
    "gatekeeper",
    "healthcheck",
    "health_check",
    "health-check",
    "proxy-server",
    "proxy_server",
];

/// Default order below the always-on front matter when no `pipeline =` is set.
const DEFAULT_CONFIGURED_FILTERS: &[&str] = &["ratelimit", "tempauth", "copy", "slo", "dlo"];

/// Whether the effective configured pipeline contains `name`. This reads the
/// pipeline independently of filter-section contents, so `/info` remains
/// accurate when a filter uses only its defaults and has a thin section.
fn configured_pipeline_has(conf: &SwiftConfig, name: &str) -> bool {
    conf.get("pipeline:main", "pipeline")
        .ok()
        .flatten()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            line.split_whitespace()
                .any(|candidate| candidate.eq_ignore_ascii_case(name))
        })
        .unwrap_or_else(|| DEFAULT_CONFIGURED_FILTERS.contains(&name))
}

/// Number of OS processes for eventlet-like worker model.
/// Prefer `[app:proxy-server] process_workers`; if `worker_model = process`
/// then numeric `workers` is treated as process count (threads use
/// `worker_threads` or default).
fn process_workers_from_conf(conf: &SwiftConfig) -> usize {
    let get = |key: &str| -> Option<String> {
        conf.get("app:proxy-server", key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
    };
    if let Some(pw) = get("process_workers") {
        if let Ok(n) = pw.trim().parse::<usize>() {
            return n.max(1);
        }
    }
    let model = get("worker_model")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if model == "process" || model == "prefork" || model == "eventlet" {
        if let Some(w) = get("workers") {
            if let Ok(n) = w.trim().parse::<usize>() {
                return n.max(1);
            }
        }
    }
    1
}

/// Fork `n-1` children; parent and children all continue to serve.
/// On Unix only; non-unix no-ops.
fn prefork_workers(n: usize, logger: &Logger) {
    #[cfg(unix)]
    {
        use std::io::Write;
        for i in 1..n {
            match unsafe { libc::fork() } {
                -1 => {
                    logger.error(&format!("prefork: fork failed at child {i}"));
                    break;
                }
                0 => {
                    // child
                    let _ = std::io::stderr().write_all(
                        format!("swift-proxy-server: worker process {i} started\n").as_bytes(),
                    );
                    return;
                }
                pid => {
                    logger.info(&format!("prefork: spawned worker pid={pid} index={i}"));
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (n, logger);
    }
}

/// `[app:proxy-server] strict_pipeline` (DEFAULT fallback). Default **true**
/// so an unknown security or auth filter cannot silently disappear.
fn strict_pipeline_from_conf(conf: &SwiftConfig) -> bool {
    let raw = conf
        .get("app:proxy-server", "strict_pipeline")
        .ok()
        .flatten()
        .or_else(|| conf.get("DEFAULT", "strict_pipeline").ok().flatten())
        .unwrap_or_else(|| "true".to_string());
    config_true_value(&raw)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PipelineBuildIssueKind {
    MissingConfiguration,
    BuildFailure,
    NotImplemented,
    UnknownFilter,
}

impl PipelineBuildIssueKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingConfiguration => "missing_configuration",
            Self::BuildFailure => "build_failure",
            Self::NotImplemented => "not_implemented",
            Self::UnknownFilter => "unknown_filter",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PipelineBuildIssue {
    filter: String,
    kind: PipelineBuildIssueKind,
    detail: String,
}

impl PipelineBuildIssue {
    fn new(
        filter: impl AsRef<str>,
        kind: PipelineBuildIssueKind,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            filter: filter.as_ref().to_string(),
            kind,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for PipelineBuildIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "filter={} kind={} detail={}",
            self.filter,
            self.kind.as_str(),
            self.detail
        )
    }
}

/// Fail closed on any configured filter that could not be built. The gate
/// consumes typed build issues only; human-readable startup notes are never
/// interpreted as policy.
fn strict_pipeline_rejects(conf: &SwiftConfig, issues: &[PipelineBuildIssue]) -> bool {
    strict_pipeline_from_conf(conf) && !issues.is_empty()
}

fn build_copy(conf: &SwiftConfig) -> Result<swift_middleware::Copy, String> {
    let raw = conf
        .get("filter:copy", "yield_frequency")
        .ok()
        .flatten()
        .or_else(|| conf.get("DEFAULT", "yield_frequency").ok().flatten())
        .unwrap_or_else(|| "10".to_string());
    let seconds = raw
        .trim()
        .parse::<i64>()
        .map_err(|_| format!("invalid copy yield_frequency {raw:?}: expected an integer"))?;
    Ok(swift_middleware::Copy::new().with_yield_frequency(seconds as f64))
}

/// Allowed, deprecated, and unsupported configured digest names.
type FormPostDigestOptions = (Vec<String>, Vec<String>, Vec<String>);

fn formpost_digest_options(conf: &SwiftConfig) -> Result<FormPostDigestOptions, String> {
    let configured = conf
        .get("filter:formpost", "allowed_digests")
        .ok()
        .flatten()
        .or_else(|| conf.get("DEFAULT", "allowed_digests").ok().flatten());
    let requested = configured
        .as_deref()
        .map(str::split_whitespace)
        .into_iter()
        .flatten()
        .map(str::to_ascii_lowercase)
        .collect::<std::collections::BTreeSet<_>>();
    let requested = if requested.is_empty() {
        ["sha1", "sha256", "sha512"]
            .into_iter()
            .map(str::to_string)
            .collect::<std::collections::BTreeSet<_>>()
    } else {
        requested
    };
    let supported = ["sha1", "sha256", "sha512"]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let allowed = requested
        .iter()
        .filter(|digest| supported.contains(digest.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let unsupported = requested
        .iter()
        .filter(|digest| !supported.contains(digest.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if allowed.is_empty() {
        return Err("No valid digest algorithms are configured".to_string());
    }
    let deprecated = allowed
        .iter()
        .filter(|digest| digest.as_str() == "sha1")
        .cloned()
        .collect();
    Ok((allowed, deprecated, unsupported))
}

/// Build `formpost` around the same Temp-URL key provider as tempurl.
fn build_formpost(
    conf: &SwiftConfig,
    key_provider: Arc<dyn swift_middleware::KeyProvider>,
) -> Result<(swift_middleware::FormPost, Vec<String>, Vec<String>), String> {
    let (allowed, deprecated, unsupported) = formpost_digest_options(conf)?;
    let mut fp = swift_middleware::FormPost::new(key_provider);
    fp.allowed_digests = allowed;
    Ok((fp, deprecated, unsupported))
}

fn build_versioned_writes(conf: &SwiftConfig) -> swift_middleware::VersionedWrites {
    let allow = conf
        .get("filter:versioned_writes", "allow_versioned_writes")
        .ok()
        .flatten()
        .or_else(|| {
            conf.get("filter:versioned-writes", "allow_versioned_writes")
                .ok()
                .flatten()
        });
    swift_middleware::VersionedWrites::from_conf(allow.as_deref()).with_authorization_probe(true)
}

fn build_symlink(conf: &SwiftConfig) -> Result<swift_middleware::Symlink, String> {
    let symloop = conf
        .get("filter:symlink", "symloop_max")
        .map_err(|error| format!("could not read [filter:symlink] symloop_max: {error}"))?;
    swift_middleware::Symlink::try_from_conf(symloop.as_deref())
}

fn build_read_only(conf: &SwiftConfig) -> swift_middleware::ReadOnly {
    let section = if conf.get("filter:read_only", "use").ok().flatten().is_some()
        || conf.items("filter:read_only").ok().is_some()
    {
        "filter:read_only"
    } else {
        "filter:read-only"
    };
    let read_only = conf.get(section, "read_only").ok().flatten();
    let allow_deletes = conf.get(section, "allow_deletes").ok().flatten();
    swift_middleware::ReadOnly::from_conf(read_only.as_deref(), allow_deletes.as_deref())
}

fn build_name_check(conf: &SwiftConfig) -> swift_middleware::NameCheck {
    let section = if conf.items("filter:name_check").ok().is_some() {
        "filter:name_check"
    } else {
        "filter:name-check"
    };
    let mut nc = swift_middleware::NameCheck::default();
    if let Some(chars) = conf.get(section, "forbidden_chars").ok().flatten() {
        nc.forbidden_chars = chars.chars().collect();
    }
    if let Some(max) = conf
        .get(section, "maximum_length")
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
    {
        nc.maximum_length = max;
    }
    if let Some(re) = conf.get(section, "forbidden_regexp").ok().flatten() {
        nc.forbidden_regexp = if re.is_empty() { None } else { Some(re) };
    }
    nc
}

fn build_etag_quoter(conf: &SwiftConfig) -> swift_middleware::EtagQuoter {
    let section = if conf.items("filter:etag_quoter").ok().is_some() {
        "filter:etag_quoter"
    } else {
        "filter:etag-quoter"
    };
    let enable = conf
        .get(section, "enable_by_default")
        .ok()
        .flatten()
        .as_deref()
        .map(swift_core::config::config_true_value)
        .unwrap_or(false);
    swift_middleware::EtagQuoter {
        enable_by_default: enable,
    }
}

/// Build [`KeyMaster`] from `[filter:keymaster]` (or `encryption_root_secret*`
/// on `[filter:encryption]` as a fallback).
///
/// Conf options (Python `KeyMaster` / `load_multikey_opts`):
/// * `encryption_root_secret` — default unlabeled root secret (base64 ≥32 raw bytes)
/// * `encryption_root_secret_<id>` — additional secrets for rotation
/// * `active_root_secret_id` — which secret new writes use (empty → default)
/// * `meta_version_to_write` — `"1"` / `"2"` / `"3"` (default `"2"`)
///
/// KMIP / KMS keymasters remain deferred.
fn build_keymaster(conf: &SwiftConfig) -> Result<swift_middleware::KeyMaster, String> {
    let items = conf
        .items("filter:keymaster")
        .ok()
        .filter(|i| !i.is_empty())
        .or_else(|| conf.items("filter:encryption").ok())
        .unwrap_or_default();
    swift_middleware::KeyMaster::from_conf_items(&items)
}

/// `disable_encryption` from `[filter:encryption]` or `[filter:encrypter]`.
fn encryption_disabled(conf: &SwiftConfig) -> bool {
    conf.get("filter:encryption", "disable_encryption")
        .ok()
        .flatten()
        .or_else(|| {
            conf.get("filter:encrypter", "disable_encryption")
                .ok()
                .flatten()
        })
        .as_deref()
        .map(swift_core::config::config_true_value)
        .unwrap_or(false)
}

fn build_crossdomain(conf: &SwiftConfig) -> swift_middleware::Crossdomain {
    let mut cd = swift_middleware::Crossdomain::default();
    if let Some(policy) = conf
        .get("filter:crossdomain", "cross_domain_policy")
        .ok()
        .flatten()
    {
        cd.policy = policy;
    }
    cd
}

fn build_domain_remap(conf: &SwiftConfig) -> swift_middleware::DomainRemap {
    let section = if conf.items("filter:domain_remap").ok().is_some() {
        "filter:domain_remap"
    } else {
        "filter:domain-remap"
    };
    swift_middleware::DomainRemap::from_conf(
        conf.get(section, "storage_domain")
            .ok()
            .flatten()
            .as_deref(),
        conf.get(section, "path_root").ok().flatten().as_deref(),
        conf.get(section, "reseller_prefixes")
            .ok()
            .flatten()
            .as_deref(),
        conf.get(section, "default_reseller_prefix")
            .ok()
            .flatten()
            .as_deref(),
        conf.get(section, "mangle_client_paths")
            .ok()
            .flatten()
            .as_deref(),
    )
}

/// CNAME resolver via `dig +short CNAME` (optional; empty → lookup miss).
struct DigCnameResolver;
impl swift_middleware::Resolver for DigCnameResolver {
    fn lookup_cname(&self, domain: &str) -> Option<String> {
        let out = std::process::Command::new("dig")
            .args(["+short", "CNAME", domain])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text.lines().next()?.trim().trim_end_matches('.');
        if line.is_empty() {
            None
        } else {
            Some(line.to_string())
        }
    }
}

fn build_cname_lookup(conf: &SwiftConfig) -> Option<swift_middleware::CnameLookup> {
    let section = if conf.items("filter:cname_lookup").ok().is_some() {
        "filter:cname_lookup"
    } else {
        "filter:cname-lookup"
    };
    let storage_domain = conf
        .get(section, "storage_domain")
        .ok()
        .flatten()
        .unwrap_or_default();
    if storage_domain.trim().is_empty() {
        return None;
    }
    let depth = conf
        .get(section, "lookup_depth")
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    Some(swift_middleware::CnameLookup::new(
        &storage_domain,
        depth,
        Arc::new(DigCnameResolver),
    ))
}

fn build_backend_ratelimit(conf: &SwiftConfig) -> swift_middleware::BackendRateLimit {
    let section = if conf.items("filter:backend_ratelimit").ok().is_some() {
        "filter:backend_ratelimit"
    } else {
        "filter:backend-ratelimit"
    };
    let mut brl = swift_middleware::BackendRateLimit::new();
    if let Some(rate) = conf
        .get(section, "requests_per_device_per_second")
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
    {
        brl = brl.with_device_rate(rate);
    }
    for method in [
        "GET",
        "HEAD",
        "PUT",
        "POST",
        "DELETE",
        "UPDATE",
        "REPLICATE",
    ] {
        let key = format!(
            "{}_requests_per_device_per_second",
            method.to_ascii_lowercase()
        );
        if let Some(rate) = conf
            .get(section, &key)
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
        {
            brl = brl.with_method_rate(method, rate);
        }
    }
    if let Some(buf) = conf
        .get(section, "rate_buffer")
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
    {
        brl = brl.with_rate_buffer(buf);
    }
    brl
}

/// Read optional `[pipeline:main] pipeline = ...` and assemble the
/// implemented configurable filters in that order. Returns the filter list,
/// human-readable startup notes, and typed issues for every configured filter
/// that could not be built faithfully.
///
/// P0–P1b wires: cache/listing_formats/proxy_logging/bulk/tempurl plus
/// formpost/staticweb/quotas/symlink/versioned_writes and the smaller L2
/// filters. P3-s3 wires `s3api` (ON-BY-CONFIG; not on default pipeline).
/// Unknown names skip with a typed issue; `strict_pipeline=true` hard-fails at
/// main without parsing log text.
#[expect(
    clippy::too_many_arguments,
    reason = "pipeline construction keeps each independently-built dependency explicit"
)]
fn build_configured_filters_with_issues(
    conf: &SwiftConfig,
    tempauth: Option<swift_middleware::TempAuth>,
    keystoneauth: Option<swift_middleware::KeystoneAuth>,
    access_logger: Option<Arc<Logger>>,
    key_provider: Arc<dyn swift_middleware::KeyProvider>,
    sync_key_provider: Arc<dyn swift_middleware::SyncKeyProvider>,
    endpoint_resolver: Arc<dyn swift_middleware::EndpointResolver>,
    policies: &StoragePolicyCollection,
    hash_config: HashPathConfig,
) -> (
    Vec<Arc<dyn swift_middleware::Middleware>>,
    Vec<String>,
    Vec<PipelineBuildIssue>,
) {
    let mut notes = Vec::new();
    let mut issues = Vec::new();
    let pipeline_line = conf
        .get("pipeline:main", "pipeline")
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty());
    let names: Vec<String> = match &pipeline_line {
        Some(line) => {
            notes.push(format!("pipeline from conf: {line}"));
            line.split_whitespace()
                .map(|s| s.to_ascii_lowercase())
                .filter(|s| !ALWAYS_ON_OR_APP.contains(&s.as_str()))
                .collect()
        }
        None => {
            notes.push("pipeline: using default order (no pipeline:main)".into());
            DEFAULT_CONFIGURED_FILTERS
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        }
    };

    let mut filters: Vec<Arc<dyn swift_middleware::Middleware>> = Vec::new();
    let mut tempauth = tempauth;
    let mut keystoneauth = keystoneauth;
    // Shared across keymaster / encrypter / decrypter / encryption filters.
    let mut keymaster_state: Option<Arc<swift_middleware::KeyMaster>> = None;

    for name in &names {
        match name.as_str() {
            "ratelimit" => match build_ratelimit(conf) {
                Ok(Some(rl)) => {
                    notes.push("ratelimit enabled".into());
                    filters.push(Arc::new(rl));
                }
                Ok(None) if pipeline_line.is_some() => {
                    notes.push(
                        "pipeline: ratelimit listed but [filter:ratelimit] absent; skip".into(),
                    );
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::MissingConfiguration,
                        "[filter:ratelimit] is absent",
                    ));
                }
                Ok(None) => {}
                Err(error) => {
                    notes.push(format!(
                        "pipeline: ratelimit listed but configuration failed validation ({error}); skip"
                    ));
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::BuildFailure,
                        error,
                    ));
                }
            },
            "tempauth" => {
                if let Some(auth) = tempauth.take() {
                    notes.push("tempauth enabled".into());
                    filters.push(Arc::new(auth));
                } else if pipeline_line.is_some() {
                    notes.push("pipeline: tempauth listed but no user_* credentials; skip".into());
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::MissingConfiguration,
                        "no TempAuth user_* credentials were built",
                    ));
                }
            }
            "copy" => match build_copy(conf) {
                Ok(copy) => {
                    notes.push(format!(
                        "copy enabled (yield_frequency={})",
                        copy.yield_frequency
                    ));
                    filters.push(Arc::new(copy));
                }
                Err(error) => {
                    notes.push(format!(
                        "pipeline: copy listed but configuration failed validation ({error}); skip"
                    ));
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::BuildFailure,
                        error,
                    ));
                }
            },
            "slo" => {
                let slo = build_slo(conf, hash_config.clone());
                notes.push(format!(
                    "slo enabled (concurrency={}, yield_frequency={})",
                    slo.concurrent_gets, slo.yield_frequency
                ));
                filters.push(Arc::new(slo));
            }
            "dlo" => match build_dlo(conf) {
                Ok(dlo) => {
                    notes.push("dlo enabled".into());
                    filters.push(Arc::new(dlo));
                }
                Err(error) => {
                    notes.push(format!(
                        "pipeline: dlo listed but configuration failed validation ({error}); skip"
                    ));
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::BuildFailure,
                        error,
                    ));
                }
            },
            "listing_formats" | "listing-formats" => {
                notes.push("listing_formats enabled".into());
                filters.push(Arc::new(swift_middleware::ListingFormats));
            }
            "proxy-logging" | "proxy_logging" => {
                let has_sink = access_logger.is_some();
                let pl = build_proxy_logging(conf, access_logger.clone());
                notes.push(if has_sink {
                    "proxy_logging enabled (logger sink)".into()
                } else {
                    "proxy_logging enabled (pass-through; no sink)".into()
                });
                filters.push(Arc::new(pl));
            }
            "cache" => match build_cache(conf) {
                Ok(cache) => {
                    notes.push(format!(
                        "cache enabled (memcache_servers={})",
                        cache.servers().join(",")
                    ));
                    filters.push(Arc::new(cache));
                }
                Err(e) => {
                    notes.push(format!(
                        "pipeline: cache listed but failed to build ({e}); skip"
                    ));
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::BuildFailure,
                        e,
                    ));
                }
            },
            "bulk" => {
                let bulk = build_bulk(conf);
                notes.push(format!(
                    "bulk enabled (delete; max_deletes_per_request={})",
                    bulk.max_deletes_per_request
                ));
                filters.push(Arc::new(bulk));
            }
            "tempurl" => {
                let tempurl = build_tempurl(conf, Arc::clone(&key_provider));
                notes.push("tempurl enabled".into());
                filters.push(Arc::new(tempurl));
            }
            "formpost" => match build_formpost(conf, Arc::clone(&key_provider)) {
                Ok((fp, deprecated, unsupported)) => {
                    if !unsupported.is_empty() {
                        notes.push(format!(
                            "formpost ignored unsupported digests: {}",
                            unsupported.join(", ")
                        ));
                    }
                    if !deprecated.is_empty() {
                        notes.push(format!(
                            "formpost deprecated digests configured: {}",
                            deprecated.join(", ")
                        ));
                    }
                    notes.push("formpost enabled".into());
                    filters.push(Arc::new(fp));
                }
                Err(error) => {
                    notes.push(format!(
                        "pipeline: formpost listed but configuration failed validation ({error}); skip"
                    ));
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::BuildFailure,
                        error,
                    ));
                }
            },
            "staticweb" => {
                notes.push("staticweb enabled".into());
                filters.push(Arc::new(swift_middleware::StaticWeb::new()));
            }
            "container_quotas" | "container-quotas" => {
                notes.push("container_quotas enabled".into());
                filters.push(Arc::new(swift_middleware::ContainerQuotas::new()));
            }
            "account_quotas" | "account-quotas" => {
                notes.push("account_quotas enabled".into());
                filters.push(Arc::new(swift_middleware::AccountQuotas::new(
                    policies.clone(),
                )));
            }
            "versioned_writes" | "versioned-writes" => {
                let vw = build_versioned_writes(conf);
                notes.push(format!(
                    "versioned_writes enabled (allow={:?})",
                    vw.allow_versioned_writes
                ));
                filters.push(Arc::new(vw));
            }
            "symlink" => match build_symlink(conf) {
                Ok(sl) => {
                    notes.push(format!("symlink enabled (symloop_max={})", sl.symloop_max));
                    filters.push(Arc::new(sl));
                }
                Err(error) => {
                    notes.push(format!(
                        "pipeline: symlink listed but configuration failed validation ({error}); skip"
                    ));
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::BuildFailure,
                        error,
                    ));
                }
            },
            "read_only" | "read-only" => {
                let ro = build_read_only(conf);
                notes.push(format!(
                    "read_only enabled (read_only={}, allow_deletes={})",
                    ro.read_only, ro.allow_deletes
                ));
                filters.push(Arc::new(ro));
            }
            "name_check" | "name-check" => {
                notes.push("name_check enabled".into());
                filters.push(Arc::new(build_name_check(conf)));
            }
            "etag_quoter" | "etag-quoter" => {
                let eq = build_etag_quoter(conf);
                notes.push(format!(
                    "etag_quoter enabled (enable_by_default={})",
                    eq.enable_by_default
                ));
                filters.push(Arc::new(eq));
            }
            "crossdomain" => {
                notes.push("crossdomain enabled".into());
                filters.push(Arc::new(build_crossdomain(conf)));
            }
            "domain_remap" | "domain-remap" => {
                notes.push("domain_remap enabled".into());
                filters.push(Arc::new(build_domain_remap(conf)));
            }
            "cname_lookup" | "cname-lookup" => match build_cname_lookup(conf) {
                Some(cl) => {
                    notes.push("cname_lookup enabled".into());
                    filters.push(Arc::new(cl));
                }
                None => {
                    notes.push(
                        "pipeline: cname_lookup listed but storage_domain empty; skip".into(),
                    );
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::MissingConfiguration,
                        "storage_domain is empty",
                    ));
                }
            },
            "backend_ratelimit" | "backend-ratelimit" => {
                notes.push("backend_ratelimit enabled".into());
                filters.push(Arc::new(build_backend_ratelimit(conf)));
            }
            "authtoken" => match build_authtoken(conf) {
                Ok(at) => {
                    notes.push(format!(
                        "authtoken enabled (delay_auth_decision={})",
                        at.delay_auth_decision
                    ));
                    filters.push(Arc::new(at));
                }
                Err(e) => {
                    notes.push(format!(
                        "pipeline: authtoken listed but failed to build ({e}); skip"
                    ));
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::BuildFailure,
                        e,
                    ));
                }
            },
            "keystoneauth" => {
                if let Some(ka) = keystoneauth.take() {
                    notes.push(format!(
                        "keystoneauth enabled (reseller_prefix={})",
                        ka.reseller_prefixes.join(",")
                    ));
                    filters.push(Arc::new(ka));
                } else if pipeline_line.is_some() {
                    notes.push(
                        "pipeline: keystoneauth listed but [filter:keystoneauth] absent; skip"
                            .into(),
                    );
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::MissingConfiguration,
                        "[filter:keystoneauth] is absent",
                    ));
                }
            }
            "s3api" => match build_s3api(conf) {
                Ok(Some(api)) => {
                    let defer = if api.s3token_client.is_some() {
                        " + EC2→s3token deferral"
                    } else {
                        ""
                    };
                    notes.push(format!(
                        "s3api enabled (SigV4+CRUD+list{defer}; not advertised on Swift /info)"
                    ));
                    filters.push(swift_s3api::as_middleware(api));
                }
                Ok(None) => {
                    notes.push(
                        "pipeline: s3api listed but no TempAuth or Keystone S3 credential source; skip"
                            .into(),
                    );
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::MissingConfiguration,
                        "no TempAuth user_* credentials or [filter:s3token] auth_uri are available",
                    ));
                }
                Err(e) => {
                    notes.push(format!(
                        "pipeline: s3api listed but configuration failed validation ({e}); skip"
                    ));
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::BuildFailure,
                        e,
                    ));
                }
            },
            "s3token" => {
                // Wave 3 hook: exchange S3 creds → Keystone token headers.
                // Requires [filter:s3token] auth_uri (or auth_url). Without it,
                // MapS3TokenClient cannot authenticate. It is retained only
                // for non-strict compatibility, with a typed startup issue.
                // EC2 unknown-key deferral is also injected into s3api via
                // build_s3api (inline /v3/s3tokens with base64 string-to-sign).
                let auth_uri = s3token_auth_uri(conf).unwrap_or_default();
                let reseller = conf
                    .get("filter:s3token", "reseller_prefix")
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "AUTH_".into());
                if auth_uri.is_empty() {
                    notes.push(
                        "pipeline: s3token listed but no auth_uri; compatibility Map client only"
                            .into(),
                    );
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::MissingConfiguration,
                        "auth_uri/auth_url is absent; Map client cannot authenticate S3 tokens",
                    ));
                    let client = std::sync::Arc::new(swift_middleware::MapS3TokenClient::new());
                    filters.push(std::sync::Arc::new(
                        swift_middleware::S3Token::new(client).with_reseller_prefix(reseller),
                    ));
                } else {
                    notes.push(format!("s3token enabled (auth_uri={auth_uri})"));
                    let client =
                        std::sync::Arc::new(swift_middleware::HttpS3TokenClient::new(auth_uri));
                    filters.push(std::sync::Arc::new(
                        swift_middleware::S3Token::new(client).with_reseller_prefix(reseller),
                    ));
                }
            }
            "container_sync" | "container-sync" => {
                match build_container_sync(conf, Arc::clone(&sync_key_provider)) {
                    Ok(cs) => {
                        notes.push(format!(
                            "container_sync enabled (allow_full_urls={}, realms={})",
                            cs.allow_full_urls,
                            cs.realms.realms.len()
                        ));
                        filters.push(Arc::new(cs));
                    }
                    Err(error) => {
                        notes.push(format!(
                            "pipeline: container_sync listed but realms configuration failed validation ({error}); skip"
                        ));
                        issues.push(PipelineBuildIssue::new(
                            name,
                            PipelineBuildIssueKind::BuildFailure,
                            error,
                        ));
                    }
                }
            }
            // At-rest crypto (ON-BY-CONFIG). Typical order:
            //   ... keymaster encryption ...  or
            //   ... keymaster decrypter encrypter ...
            // Python's egg name `encryption` = Decrypter(Encrypter(app)).
            "keymaster" => match build_keymaster(conf) {
                Ok(km) => {
                    let arc = Arc::new(km);
                    keymaster_state = Some(Arc::clone(&arc));
                    notes.push("keymaster enabled".into());
                    filters.push(Arc::new(swift_middleware::KeyMasterMw::new(arc)));
                }
                Err(e) => {
                    notes.push(format!(
                        "pipeline: keymaster listed but failed to build ({e}); skip"
                    ));
                    issues.push(PipelineBuildIssue::new(
                        name,
                        PipelineBuildIssueKind::BuildFailure,
                        e,
                    ));
                }
            },
            "encrypter" => {
                let km = keymaster_state
                    .clone()
                    .or_else(|| build_keymaster(conf).ok().map(Arc::new));
                match km {
                    Some(arc) => {
                        keymaster_state.get_or_insert_with(|| Arc::clone(&arc));
                        let disable = encryption_disabled(conf);
                        notes.push(format!("encrypter enabled (disable_encryption={disable})"));
                        filters.push(Arc::new(swift_middleware::Encrypter::new(arc, disable)));
                    }
                    None => {
                        notes.push(
                            "pipeline: encrypter listed but no encryption_root_secret; skip".into(),
                        );
                        issues.push(PipelineBuildIssue::new(
                            name,
                            PipelineBuildIssueKind::MissingConfiguration,
                            "no usable encryption_root_secret",
                        ));
                    }
                }
            }
            "decrypter" => {
                let km = keymaster_state
                    .clone()
                    .or_else(|| build_keymaster(conf).ok().map(Arc::new));
                match km {
                    Some(arc) => {
                        keymaster_state.get_or_insert_with(|| Arc::clone(&arc));
                        notes.push("decrypter enabled".into());
                        filters.push(Arc::new(swift_middleware::Decrypter::new(arc)));
                    }
                    None => {
                        notes.push(
                            "pipeline: decrypter listed but no encryption_root_secret; skip".into(),
                        );
                        issues.push(PipelineBuildIssue::new(
                            name,
                            PipelineBuildIssueKind::MissingConfiguration,
                            "no usable encryption_root_secret",
                        ));
                    }
                }
            }
            "encryption" => {
                // Python filter_factory: Decrypter(Encrypter(app)) — outer
                // decrypter, inner encrypter. Push in that order so
                // build_pipeline sees decrypter outermost of the pair.
                let km = keymaster_state
                    .clone()
                    .or_else(|| build_keymaster(conf).ok().map(Arc::new));
                match km {
                    Some(arc) => {
                        keymaster_state.get_or_insert_with(|| Arc::clone(&arc));
                        let disable = encryption_disabled(conf);
                        notes.push(format!(
                            "encryption enabled (decrypter+encrypter; disable_encryption={disable})"
                        ));
                        filters.push(Arc::new(swift_middleware::Decrypter::new(Arc::clone(&arc))));
                        filters.push(Arc::new(swift_middleware::Encrypter::new(arc, disable)));
                    }
                    None => {
                        notes.push(
                            "pipeline: encryption listed but no encryption_root_secret; skip"
                                .into(),
                        );
                        issues.push(PipelineBuildIssue::new(
                            name,
                            PipelineBuildIssueKind::MissingConfiguration,
                            "no usable encryption_root_secret",
                        ));
                    }
                }
            }
            "list_endpoints" | "list-endpoints" => {
                let le = build_list_endpoints(conf, Arc::clone(&endpoint_resolver));
                notes.push(format!(
                    "list_endpoints enabled (path_root={})",
                    le.path_root
                ));
                filters.push(Arc::new(le));
            }
            "xprofile" | "x-profile" => {
                let xp = build_xprofile(conf);
                notes.push(format!(
                    "xprofile enabled (enabled={}, profile_path={:?})",
                    xp.enabled, xp.profile_path
                ));
                filters.push(Arc::new(xp));
            }
            // These Python pipeline names do not have a Rust middleware
            // implementation. Never disguise them as a successful no-op.
            "memcache" | "mem_cache" | "swob" | "recon" => {
                notes.push(format!(
                    "pipeline: filter '{name}' is not implemented; omitted in non-strict compatibility mode"
                ));
                issues.push(PipelineBuildIssue::new(
                    name,
                    PipelineBuildIssueKind::NotImplemented,
                    "no Rust middleware implementation is registered",
                ));
            }
            other => {
                // Rust-native plugins: conf [filter:name] + PluginRegistry
                // (use=/plugin=). Unknown filters are skipped only when strict
                // mode is disabled; passthrough requires explicit opt-in.
                let section = format!("filter:{other}");
                let conf_items: std::collections::HashMap<String, String> =
                    conf.items(&section).ok().into_iter().flatten().collect();
                let allow_unknown_passthrough = conf
                    .get("app:proxy-server", "plugin_default")
                    .ok()
                    .flatten()
                    .or_else(|| conf.get("DEFAULT", "plugin_default").ok().flatten())
                    .map(|s| {
                        matches!(
                            s.trim().to_ascii_lowercase().as_str(),
                            "passthrough" | "true" | "1" | "yes" | "on"
                        )
                    })
                    .unwrap_or(false); // default: fail closed, no silent no-op
                match swift_middleware::global_registry().build(
                    other,
                    &conf_items,
                    allow_unknown_passthrough,
                ) {
                    Some((mw, note)) => {
                        notes.push(format!("pipeline: {note}"));
                        filters.push(mw);
                    }
                    None => {
                        notes.push(format!(
                            "pipeline: unknown filter '{other}'; skip (plugin_default=skip)"
                        ));
                        issues.push(PipelineBuildIssue::new(
                            other,
                            PipelineBuildIssueKind::UnknownFilter,
                            "no registered Rust plugin; passthrough was not explicitly enabled",
                        ));
                    }
                }
            }
        }
    }

    (filters, notes, issues)
}

/// Legacy two-part view retained for focused middleware-construction tests.
/// Production startup always consumes `build_configured_filters_with_issues`
/// so no unresolved filter can be lost before the strict gate.
#[cfg(test)]
#[expect(
    clippy::too_many_arguments,
    reason = "legacy test adapter mirrors the production pipeline builder signature"
)]
fn build_configured_filters(
    conf: &SwiftConfig,
    tempauth: Option<swift_middleware::TempAuth>,
    keystoneauth: Option<swift_middleware::KeystoneAuth>,
    access_logger: Option<Arc<Logger>>,
    key_provider: Arc<dyn swift_middleware::KeyProvider>,
    sync_key_provider: Arc<dyn swift_middleware::SyncKeyProvider>,
    policies: &StoragePolicyCollection,
    hash_config: HashPathConfig,
) -> (Vec<Arc<dyn swift_middleware::Middleware>>, Vec<String>) {
    let (filters, notes, _issues) = build_configured_filters_with_issues(
        conf,
        tempauth,
        keystoneauth,
        access_logger,
        key_provider,
        sync_key_provider,
        Arc::new(swift_middleware::StaticEndpoints(Vec::new())),
        policies,
        hash_config,
    );
    (filters, notes)
}

fn build_xprofile(conf: &SwiftConfig) -> swift_middleware::XProfile {
    let section = if conf.items("filter:xprofile").ok().is_some() {
        "filter:xprofile"
    } else {
        "filter:x-profile"
    };
    let enabled = conf
        .get(section, "enabled")
        .ok()
        .flatten()
        .map(|s| {
            let t = s.trim().to_ascii_lowercase();
            !(t == "false" || t == "no" || t == "0" || t == "off")
        })
        .unwrap_or(true);
    let profile_path = conf.get(section, "profile_path").ok().flatten();
    let log_filename = conf.get(section, "log_filename").ok().flatten();
    let mut xp = swift_middleware::XProfile::new();
    xp.enabled = enabled;
    xp.profile_path = profile_path;
    if let Some(path) = log_filename {
        if !path.is_empty() {
            match xp.with_log_file(&path) {
                Ok(with_log) => return with_log,
                Err(_) => {
                    // fall through without log file
                    let mut xp2 = swift_middleware::XProfile::new();
                    xp2.enabled = enabled;
                    return xp2;
                }
            }
        }
    }
    xp
}

fn build_list_endpoints(
    conf: &SwiftConfig,
    resolver: Arc<dyn swift_middleware::EndpointResolver>,
) -> swift_middleware::ListEndpoints {
    let section = if conf.items("filter:list_endpoints").ok().is_some() {
        "filter:list_endpoints"
    } else {
        "filter:list-endpoints"
    };
    let path_root = conf
        .get(section, "list_endpoints_path")
        .ok()
        .flatten()
        .or_else(|| conf.get(section, "path_root").ok().flatten())
        .or_else(|| conf.get("DEFAULT", "list_endpoints_path").ok().flatten())
        .unwrap_or_else(|| "/endpoints/".into());
    swift_middleware::ListEndpoints::new(resolver).with_path_root(path_root)
}

/// Ordered implemented filter names that [`build_configured_filters_with_issues`] would
/// wire (unit-test helper; does not construct middleware).
#[cfg(test)]
fn configured_filter_names(conf: &SwiftConfig, has_tempauth: bool) -> Vec<&'static str> {
    let pipeline_line = conf
        .get("pipeline:main", "pipeline")
        .ok()
        .flatten()
        .filter(|s| !s.trim().is_empty());
    let names: Vec<String> = match &pipeline_line {
        Some(line) => line
            .split_whitespace()
            .map(|s| s.to_ascii_lowercase())
            .filter(|s| !ALWAYS_ON_OR_APP.contains(&s.as_str()))
            .collect(),
        None => DEFAULT_CONFIGURED_FILTERS
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    };
    let mut out = Vec::new();
    for name in &names {
        match name.as_str() {
            "ratelimit" if matches!(build_ratelimit(conf), Ok(Some(_))) => out.push("ratelimit"),
            "tempauth" if has_tempauth => out.push("tempauth"),
            "copy" => out.push("copy"),
            "slo" => out.push("slo"),
            "dlo" if build_dlo(conf).is_ok() => out.push("dlo"),
            "listing_formats" | "listing-formats" => out.push("listing_formats"),
            "proxy-logging" | "proxy_logging" => out.push("proxy_logging"),
            "cache" if build_cache(conf).is_ok() => out.push("cache"),
            "bulk" => out.push("bulk"),
            "tempurl" => out.push("tempurl"),
            "formpost" => out.push("formpost"),
            "staticweb" => out.push("staticweb"),
            "container_quotas" | "container-quotas" => out.push("container_quotas"),
            "account_quotas" | "account-quotas" => out.push("account_quotas"),
            "versioned_writes" | "versioned-writes" => out.push("versioned_writes"),
            "symlink" => out.push("symlink"),
            "read_only" | "read-only" => out.push("read_only"),
            "name_check" | "name-check" => out.push("name_check"),
            "etag_quoter" | "etag-quoter" => out.push("etag_quoter"),
            "crossdomain" => out.push("crossdomain"),
            "domain_remap" | "domain-remap" => out.push("domain_remap"),
            "cname_lookup" | "cname-lookup" if build_cname_lookup(conf).is_some() => {
                out.push("cname_lookup")
            }
            "backend_ratelimit" | "backend-ratelimit" => out.push("backend_ratelimit"),
            "authtoken" if build_authtoken(conf).is_ok() => out.push("authtoken"),
            "keystoneauth" => out.push("keystoneauth"),
            "s3api" if matches!(build_s3api(conf), Ok(Some(_))) => out.push("s3api"),
            "container_sync" | "container-sync"
                if build_container_sync(
                    conf,
                    Arc::new(swift_middleware::ClosureSyncKeyProvider::new(|_, _| None)),
                )
                .is_ok() =>
            {
                out.push("container_sync")
            }
            "keymaster" if build_keymaster(conf).is_ok() => out.push("keymaster"),
            "encrypter" if build_keymaster(conf).is_ok() => out.push("encrypter"),
            "decrypter" if build_keymaster(conf).is_ok() => out.push("decrypter"),
            // Composite egg name expands to two filters at build time; report
            // the name as listed in the pipeline for test helpers.
            "encryption" if build_keymaster(conf).is_ok() => out.push("encryption"),
            _ => {}
        }
    }
    out
}

/// Build proxy `container_sync` middleware from `[filter:container_sync]`.
fn build_container_sync(
    conf: &SwiftConfig,
    sync_keys: Arc<dyn swift_middleware::SyncKeyProvider>,
) -> Result<swift_middleware::ContainerSync, String> {
    let swift_dir = conf
        .get("DEFAULT", "swift_dir")
        .ok()
        .flatten()
        .or_else(|| {
            conf.get("filter:container_sync", "swift_dir")
                .ok()
                .flatten()
        })
        .unwrap_or_else(|| std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string()));
    let allow_full = conf
        .get("filter:container_sync", "allow_full_urls")
        .ok()
        .flatten()
        .map(|v| config_true_value(&v))
        .unwrap_or(true);
    let current = conf.get("filter:container_sync", "current").ok().flatten();
    let realms_path = format!("{swift_dir}/container-sync-realms.conf");
    Ok(swift_middleware::ContainerSync::new(sync_keys)
        .try_with_realms_path(realms_path)?
        .with_allow_full_urls(allow_full)
        .with_current(current.as_deref()))
}

/// Every input a [`ProxyApp`] is constructed from — ring locations
/// (`swift_dir` plus the per-policy ring names), the hash-path config, the
/// storage-policy tables, and the tuning knobs — so startup and the
/// ring-reload thread share the one [`AppBuilder::build`] path.
struct AppBuilder {
    swift_dir: String,
    hash_config: HashPathConfig,
    policies: StoragePolicyCollection,
    ec_policies: std::collections::HashMap<i64, EcPolicyParams>,
    policy_names: std::collections::HashMap<String, i64>,
    policy_index_names: std::collections::HashMap<i64, String>,
    info_json: String,
    config: ProxyConfig,
    /// Comma-separated memcache servers for shared info-cache L2 (P1c).
    /// Empty → process-local L1 only.
    memcache_servers: String,
}

impl AppBuilder {
    fn ring_path(&self, name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(format!("{}/{name}.ring.gz", self.swift_dir))
    }

    /// Every ring file this proxy serves from: account, container, and one
    /// object ring per storage policy — the set the reload thread watches.
    fn ring_paths(&self) -> Vec<std::path::PathBuf> {
        ["account", "container"]
            .into_iter()
            .map(|name| self.ring_path(name))
            .chain(self.policies.iter().map(|p| self.ring_path(p.ring_name())))
            .collect()
    }

    /// Load every ring from disk and construct the `ProxyApp`, exactly as
    /// startup does. Any unreadable or invalid ring is an error: the caller
    /// exits at startup, or keeps serving on the previous rings on reload.
    fn build(&self) -> Result<ProxyApp, String> {
        let load = |name: &str| -> Result<RingData, String> {
            let path = self.ring_path(name);
            RingData::load(&path).map_err(|e| format!("could not load {}: {e}", path.display()))
        };
        let account_ring = Ring::new(load("account")?, self.hash_config.clone());
        let container_ring = Ring::new(load("container")?, self.hash_config.clone());
        let (object_ring, object_rings) =
            build_policy_object_rings(&self.policies, &self.hash_config, load)?;
        let mut app = ProxyApp::with_ec_policies(
            account_ring,
            container_ring,
            object_ring,
            object_rings,
            self.ec_policies.clone(),
            self.config.clone(),
        )
        .with_policy_names(self.policy_names.clone())
        .with_policy_index_names(self.policy_index_names.clone())
        .with_info_json(self.info_json.clone());
        let servers: Vec<String> = self
            .memcache_servers
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if !servers.is_empty() {
            // Dedicated client for info-cache L2 (same server list as
            // [filter:cache]; separate connection pool). Connect failure
            // keeps L1-only — request path never depends on memcache up.
            if let Ok(client) = swift_memcache::MemcacheClient::connect(
                servers,
                swift_memcache::MemcacheConfig::default(),
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(2),
            ) {
                app = app.with_info_memcache(client);
            }
        }
        Ok(app)
    }
}

/// Modification time of every ring file (`None` for one that cannot be
/// statted) — the reload thread's change signal.
fn ring_mtimes(paths: &[std::path::PathBuf]) -> Vec<Option<std::time::SystemTime>> {
    paths
        .iter()
        .map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
        .collect()
}

/// Every [`RING_CHECK_INTERVAL`], stat the loaded ring files; when any mtime
/// changed, rebuild the `ProxyApp` exactly as startup did and swap it in for
/// subsequent requests.
fn spawn_ring_reload_thread(
    builder: AppBuilder,
    app: Arc<RwLock<Arc<ProxyApp>>>,
    logger: Arc<Logger>,
) {
    std::thread::spawn(move || {
        let paths = builder.ring_paths();
        let mut mtimes = ring_mtimes(&paths);
        loop {
            std::thread::sleep(RING_CHECK_INTERVAL);
            let current = ring_mtimes(&paths);
            if current == mtimes {
                continue;
            }
            match builder.build() {
                Ok(rebuilt) => {
                    let mut slot = app.write().unwrap_or_else(|poisoned| poisoned.into_inner());
                    *slot = Arc::new(rebuilt);
                    drop(slot);
                    mtimes = current;
                    logger.info("ring change detected: reloaded rings");
                }
                // Keep the recorded mtimes, so a half-written ring file is
                // retried on the next tick; requests stay on the old rings.
                Err(e) => logger.error(&format!(
                    "ring reload failed (still serving on previous rings): {e}"
                )),
            }
        }
    });
}

/// Render the `GET /info` capabilities document, reporting ONLY what this proxy
/// actually serves. Advertise a filter capability only when it is in the
/// configured pipeline (and wired). `bulk_upload` is advertised when `bulk` is on.
fn build_info_json(
    swift_conf: &SwiftConfig,
    conf: &SwiftConfig,
    account_autocreate: bool,
    allow_account_management: bool,
    tempauth_on: bool,
) -> String {
    let swift_compat_version = conf
        .get("app:proxy-server", "swift_compat_version")
        .ok()
        .flatten()
        .or_else(|| conf.get("DEFAULT", "swift_compat_version").ok().flatten())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "2.33.0".to_string());
    let strict_cors_mode = conf
        .get("app:proxy-server", "strict_cors_mode")
        .ok()
        .flatten()
        .or_else(|| conf.get("DEFAULT", "strict_cors_mode").ok().flatten())
        .map(|value| config_true_value(&value))
        .unwrap_or(true);
    let allow_open_expired = conf
        .get("app:proxy-server", "allow_open_expired")
        .ok()
        .flatten()
        .or_else(|| conf.get("DEFAULT", "allow_open_expired").ok().flatten())
        .map(|value| config_true_value(&value))
        .unwrap_or(false);
    let slo_options = slo_options_from_conf(conf);
    let c = swift_core::constraints::Constraints::from_swift_conf(swift_conf).unwrap_or_default();
    let policies: Vec<serde_json::Value> = parse_storage_policies(swift_conf)
        .ok()
        .map(|coll| {
            let default_idx = coll.default_policy().idx();
            coll.iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.name(),
                        "aliases": p.aliases(),
                        "default": p.idx() == default_idx,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let mut info = serde_json::json!({
        "swift": {
            "version": swift_compat_version,
            "strict_cors_mode": strict_cors_mode,
            "account_autocreate": account_autocreate,
            "allow_account_management": allow_account_management,
            "allow_open_expired": allow_open_expired,
            "max_file_size": c.max_file_size,
            "max_request_line": c.max_request_line,
            "max_meta_name_length": c.max_meta_name_length,
            "max_meta_value_length": c.max_meta_value_length,
            "max_meta_count": c.max_meta_count,
            "max_meta_overall_size": c.max_meta_overall_size,
            "max_header_size": c.max_header_size,
            "max_object_name_length": c.max_object_name_length,
            "container_listing_limit": c.container_listing_limit,
            "account_listing_limit": c.account_listing_limit,
            "max_account_name_length": c.max_account_name_length,
            "max_container_name_length": c.max_container_name_length,
            "valid_api_versions": c.valid_api_versions,
            "extra_header_count": c.extra_header_count,
            "auto_create_account_prefix": c.auto_create_account_prefix,
            "policies": policies,
        },
    });
    if configured_pipeline_has(conf, "slo") {
        info["slo"] = serde_json::json!({
            "max_manifest_segments": 1000,
            "max_manifest_size": 8388608,
            "min_segment_size": 1,
            "yield_frequency": slo_options.yield_frequency,
            "allow_async_delete": true,
        });
    }
    if tempauth_on {
        // P1a: account ACL (X-Account-Access-Control) is enforced.
        info["tempauth"] = serde_json::json!({ "account_acls": true });
    }
    if configured_pipeline_has(conf, "keystoneauth")
        && configured_pipeline_has(conf, "authtoken")
        && build_authtoken(conf).is_ok()
    {
        let ka = build_keystoneauth(conf).unwrap_or_default();
        info["keystoneauth"] = serde_json::json!({
            "reseller_prefix": ka.reseller_prefixes,
            "operator_roles": ka
                .role_config_for_account(
                    &format!(
                        "{}x",
                        ka.reseller_prefixes.first().cloned().unwrap_or_else(|| "AUTH_".into())
                    )
                )
                .operator_roles,
        });
    }
    if configured_pipeline_has(conf, "ratelimit") {
        if let Ok(Some(ratelimit)) = build_ratelimit(conf) {
            let container_ratelimits: Vec<serde_json::Value> = ratelimit
                .container_ratelimits
                .iter()
                .map(|tier| serde_json::json!([tier.size, tier.rate]))
                .collect();
            let container_listing_ratelimits: Vec<serde_json::Value> = ratelimit
                .container_listing_ratelimits
                .iter()
                .map(|tier| serde_json::json!([tier.size, tier.rate]))
                .collect();
            info["ratelimit"] = serde_json::json!({
                "account_ratelimit": ratelimit.account_ratelimit,
                "max_sleep_time_seconds": ratelimit.max_sleep_time_seconds,
                "container_ratelimits": container_ratelimits,
                "container_listing_ratelimits": container_listing_ratelimits,
            });
        }
    }
    if configured_pipeline_has(conf, "bulk") {
        let max_deletes = build_bulk(conf).max_deletes_per_request;
        let max_failed = conf
            .get("filter:bulk", "max_failed_deletes")
            .ok()
            .flatten()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(1000);
        let bulk = build_bulk(conf);
        info["bulk_delete"] = serde_json::json!({
            "max_deletes_per_request": max_deletes,
            "max_failed_deletes": max_failed,
        });
        // extract-archive is implemented (tar / tar.gz / tar.bz2).
        info["bulk_upload"] = bulk.upload_info_dict();
    }
    if configured_pipeline_has(conf, "tempurl") {
        let no_keys: Arc<dyn swift_middleware::KeyProvider> =
            Arc::new(swift_middleware::ClosureKeyProvider::new(|_, _| Vec::new()));
        let tempurl = build_tempurl(conf, no_keys);
        let mut allowed_digests = tempurl.allowed_digests;
        allowed_digests.sort();
        info["tempurl"] = serde_json::json!({
            "methods": tempurl.methods,
            "allowed_digests": allowed_digests,
        });
    }
    if configured_pipeline_has(conf, "formpost") {
        let no_keys: Arc<dyn swift_middleware::KeyProvider> =
            Arc::new(swift_middleware::ClosureKeyProvider::new(|_, _| Vec::new()));
        if let Ok((fp, deprecated_digests, _)) = build_formpost(conf, no_keys) {
            let mut value = serde_json::json!({
                "allowed_digests": fp.allowed_digests,
            });
            if !deprecated_digests.is_empty() {
                value["deprecated_digests"] = serde_json::json!(deprecated_digests);
            }
            info["formpost"] = value;
        }
    }
    if configured_pipeline_has(conf, "staticweb") {
        info["staticweb"] = serde_json::json!({});
    }
    if configured_pipeline_has(conf, "container_quotas")
        || configured_pipeline_has(conf, "container-quotas")
    {
        info["container_quotas"] = serde_json::json!({});
    }
    if configured_pipeline_has(conf, "account_quotas")
        || configured_pipeline_has(conf, "account-quotas")
    {
        info["account_quotas"] = serde_json::json!({});
    }
    if configured_pipeline_has(conf, "symlink") {
        if let Ok(sl) = build_symlink(conf) {
            info["symlink"] = serde_json::json!({
                "symloop_max": sl.symloop_max,
                "static_links": true,
            });
        }
    }
    if configured_pipeline_has(conf, "versioned_writes")
        || configured_pipeline_has(conf, "versioned-writes")
    {
        let vw = build_versioned_writes(conf);
        let allow = vw.allow_versioned_writes.unwrap_or(false);
        let flags = if allow {
            serde_json::json!(["x-versions-location", "x-history-location"])
        } else {
            serde_json::json!([])
        };
        info["versioned_writes"] = serde_json::json!({
            "allowed_flags": flags,
        });
    }
    if configured_pipeline_has(conf, "name_check") || configured_pipeline_has(conf, "name-check") {
        let nc = build_name_check(conf);
        info["name_check"] = serde_json::json!({
            "forbidden_chars": nc.forbidden_chars.iter().collect::<String>(),
            "maximum_length": nc.maximum_length,
            "forbidden_regexp": nc.forbidden_regexp,
        });
    }
    if configured_pipeline_has(conf, "etag_quoter") || configured_pipeline_has(conf, "etag-quoter")
    {
        info["etag_quoter"] = serde_json::json!({
            "enable_by_default": build_etag_quoter(conf).enable_by_default,
        });
    }
    if configured_pipeline_has(conf, "crossdomain") {
        info["crossdomain"] = serde_json::json!({});
    }
    if configured_pipeline_has(conf, "domain_remap")
        || configured_pipeline_has(conf, "domain-remap")
    {
        let dr = build_domain_remap(conf);
        info["domain_remap"] = serde_json::json!({
            "default_reseller_prefix": dr.default_reseller_prefix,
        });
    }
    if configured_pipeline_has(conf, "cname_lookup")
        || configured_pipeline_has(conf, "cname-lookup")
    {
        if let Some(cl) = build_cname_lookup(conf) {
            info["cname_lookup"] = serde_json::json!({
                "lookup_depth": cl.lookup_depth,
            });
        }
    }
    // read_only: Python only registers when cluster-wide read_only=true.
    if configured_pipeline_has(conf, "read_only") || configured_pipeline_has(conf, "read-only") {
        let ro = build_read_only(conf);
        if ro.read_only {
            info["read_only"] = serde_json::json!({});
        }
    }
    // container_sync: Python registers realms when the filter is in the pipeline.
    if configured_pipeline_has(conf, "container_sync")
        || configured_pipeline_has(conf, "container-sync")
    {
        let empty_keys: Arc<dyn swift_middleware::SyncKeyProvider> =
            Arc::new(swift_middleware::ClosureSyncKeyProvider::new(|_, _| None));
        if let Ok(cs) = build_container_sync(conf, empty_keys) {
            info["container_sync"] = cs.info_json();
        }
    }
    // encryption: Python register_swift_info('encryption', admin=True,
    // enabled=not disable_encryption) when the encryption filter loads.
    // Advertise when encryption / encrypter / decrypter is in the pipeline and
    // a keymaster root secret is available (same enable gate as wiring).
    let crypto_in_pipeline = configured_pipeline_has(conf, "encryption")
        || configured_pipeline_has(conf, "encrypter")
        || configured_pipeline_has(conf, "decrypter");
    if crypto_in_pipeline && build_keymaster(conf).is_ok() {
        info["encryption"] = serde_json::json!({
            "enabled": !encryption_disabled(conf),
        });
    }
    // P3-s3: deliberately do NOT advertise `s3api` on Swift v1 `/info`.
    // S3 is a parallel API surface enabled by pipeline wiring; a v1 /info
    // key would falsely imply Swift-client capability discovery.
    serde_json::to_string(&info).unwrap_or_default()
}

/// Build `KeystoneAuth` from `[filter:keystoneauth]` (defaults when section empty).
fn build_keystoneauth(conf: &SwiftConfig) -> Option<swift_middleware::KeystoneAuth> {
    let items = conf.items("filter:keystoneauth").ok()?;
    Some(swift_middleware::KeystoneAuth::from_items(&items))
}

/// Build `AuthToken` from `[filter:authtoken]`.
///
/// Production: `auth_url` + service user password → [`HttpTokenValidator`].
/// Lab / unit (no Keystone), either:
/// - `static_token_<tok> = <user_id> <user_name> <project_id> <project_name> [roles…]`
/// - `static_tokens = tok=project:user:role,role;…`
fn build_authtoken(conf: &SwiftConfig) -> Result<swift_middleware::AuthToken, String> {
    let items = conf
        .items("filter:authtoken")
        .map_err(|e| format!("no [filter:authtoken]: {e}"))?;
    let get = |key: &str| -> Option<String> {
        items
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let true_val = |key: &str, default: bool| -> bool {
        get(key)
            .map(|v| {
                matches!(
                    v.to_ascii_lowercase().as_str(),
                    "true" | "1" | "yes" | "on" | "t" | "y"
                )
            })
            .unwrap_or(default)
    };

    let delay = true_val("delay_auth_decision", true);
    let www = get("www_authenticate_uri")
        .or_else(|| get("auth_uri"))
        .or_else(|| get("identity_uri"))
        .or_else(|| get("auth_url"))
        .unwrap_or_default();

    let mut map = swift_middleware::MapTokenValidator::new();
    let mut any_static = false;

    for (key, val) in &items {
        let Some(tok) = key
            .strip_prefix("static_token_")
            .or_else(|| key.strip_prefix("STATIC_TOKEN_"))
        else {
            continue;
        };
        let mut parts = val.split_whitespace();
        let user_id = parts.next().unwrap_or("").to_string();
        let user_name = parts.next().unwrap_or("").to_string();
        let project_id = parts.next().unwrap_or("").to_string();
        let project_name = parts.next().unwrap_or("").to_string();
        let roles: Vec<String> = parts
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if user_id.is_empty() || project_id.is_empty() {
            return Err(format!(
                "static_token_{tok}: need user_id user_name project_id project_name [roles…]"
            ));
        }
        map.insert(
            tok.to_string(),
            swift_middleware::ValidatedToken {
                identity: swift_middleware::Identity {
                    user_id,
                    user_name,
                    tenant_id: project_id,
                    tenant_name: project_name,
                    roles,
                    service_roles: vec![],
                },
                user_domain_id: "default".into(),
                user_domain_name: "Default".into(),
                project_domain_id: "default".into(),
                project_domain_name: "Default".into(),
            },
        );
        any_static = true;
    }

    if let Some(static_tokens) = get("static_tokens") {
        for entry in static_tokens.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (token, rest) = entry
                .split_once('=')
                .ok_or_else(|| format!("static_tokens bad entry: {entry}"))?;
            let mut parts = rest.split(':');
            let project = parts.next().unwrap_or("").to_string();
            let user = parts.next().unwrap_or("").to_string();
            let roles: Vec<String> = parts
                .next()
                .unwrap_or("")
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            map.insert(
                token.trim(),
                swift_middleware::ValidatedToken {
                    identity: swift_middleware::Identity {
                        user_id: user.clone(),
                        user_name: user,
                        tenant_id: project.clone(),
                        tenant_name: project,
                        roles,
                        service_roles: vec![],
                    },
                    user_domain_id: "default".into(),
                    user_domain_name: "Default".into(),
                    project_domain_id: "default".into(),
                    project_domain_name: "Default".into(),
                },
            );
            any_static = true;
        }
    }

    if any_static {
        return Ok(swift_middleware::AuthToken::new(std::sync::Arc::new(map))
            .with_delay(delay)
            .with_www_authenticate_uri(www));
    }

    let auth_url = get("auth_url")
        .or_else(|| get("identity_uri"))
        .or_else(|| get("auth_uri"))
        .ok_or_else(|| {
            "authtoken: auth_url (or identity_uri / static_token_* / static_tokens) required"
                .to_string()
        })?;
    let username = get("username")
        .or_else(|| get("admin_user"))
        .ok_or_else(|| "authtoken: username required".to_string())?;
    let password = get("password")
        .or_else(|| get("admin_password"))
        .ok_or_else(|| "authtoken: password required".to_string())?;
    let project = get("project_name")
        .or_else(|| get("admin_tenant_name"))
        .unwrap_or_else(|| "service".to_string());
    let user_domain = get("user_domain_name").unwrap_or_else(|| "Default".to_string());
    let project_domain = get("project_domain_name").unwrap_or_else(|| "Default".to_string());
    let timeout_secs = get("http_connect_timeout")
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(5.0);

    let validator =
        swift_middleware::HttpTokenValidator::new(auth_url, username, password, project)
            .with_domains(user_domain, project_domain)
            .with_timeout(std::time::Duration::from_secs_f64(timeout_secs));
    Ok(
        swift_middleware::AuthToken::new(std::sync::Arc::new(validator))
            .with_delay(delay)
            .with_www_authenticate_uri(www),
    )
}

fn s3token_auth_uri(conf: &SwiftConfig) -> Option<String> {
    conf.get("filter:s3token", "auth_uri")
        .ok()
        .flatten()
        .or_else(|| conf.get("filter:s3token", "auth_url").ok().flatten())
        .filter(|s| !s.trim().is_empty())
}

fn strict_config_bool(option: &str, raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" | "t" | "y" => Ok(true),
        "false" | "0" | "no" | "off" | "f" | "n" => Ok(false),
        _ => Err(format!("invalid {option} boolean {raw:?}")),
    }
}

/// Build the P3-s3 `s3api` filter from TempAuth `user_*` records plus optional
/// `[filter:s3api]` knobs. Credentials use access key `account:user` and the
/// TempAuth secret (Swift/tempauth + s3api convention). Returns `None` when
/// there are no users to map. Does **not** advertise on Swift v1 `/info`.
///
/// When `[filter:s3token] auth_uri` is set, attaches [`HttpS3TokenClient`] so
/// unknown EC2 access keys defer to Keystone `/v3/s3tokens` with a real
/// base64 string-to-sign (instead of immediate `InvalidAccessKeyId`).
fn build_s3api(conf: &SwiftConfig) -> Result<Option<swift_s3api::S3Api>, String> {
    let items = if conf.has_section("filter:tempauth") {
        conf.items("filter:tempauth")
            .map_err(|e| format!("could not read [filter:tempauth]: {e}"))?
    } else {
        Vec::new()
    };
    let mut users: Vec<(String, String, String, Vec<String>)> = Vec::new();
    for (key, val) in &items {
        let Some(rest) = key.strip_prefix("user_") else {
            continue;
        };
        let Some((account, user)) = rest.split_once('_') else {
            continue;
        };
        let mut toks = val.split_whitespace();
        let Some(secret) = toks.next() else { continue };
        let groups: Vec<String> = toks.map(str::to_string).collect();
        users.push((
            account.to_string(),
            user.to_string(),
            secret.to_string(),
            groups,
        ));
    }
    let external_s3token = s3token_auth_uri(conf);
    if users.is_empty() && external_s3token.is_none() {
        return Ok(None);
    }
    let reseller = conf
        .get("filter:tempauth", "reseller_prefix")
        .ok()
        .flatten()
        .unwrap_or_else(|| "AUTH_".to_string());
    let reseller = if reseller.ends_with('_') {
        reseller
    } else {
        format!("{reseller}_")
    };
    let creds = swift_s3api::credentials_from_tempauth_users(&users, &reseller);

    let location = conf
        .get("filter:s3api", "location")
        .ok()
        .flatten()
        .unwrap_or_else(|| "us-east-1".to_string());
    let dns = conf
        .get("filter:s3api", "dns_compliant_bucket_names")
        .ok()
        .flatten()
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "true" | "1" | "yes" | "on" | ""
            )
        })
        .unwrap_or(true);
    // Python Swift names this option `storage_domain` (singular) even though
    // it accepts a comma-separated list.  Keep the historical Rust plural as
    // a compatibility alias, but never let it override the Python spelling.
    let storage_domains = conf
        .get("filter:s3api", "storage_domain")
        .ok()
        .flatten()
        .or_else(|| conf.get("filter:s3api", "storage_domains").ok().flatten())
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let allowable_clock_skew = conf
        .get("filter:s3api", "allowable_clock_skew")
        .map_err(|e| e.to_string())?
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("invalid allowable_clock_skew {value:?}"))
        })
        .transpose()?
        .unwrap_or(15 * 60);
    let extended_subresources = conf
        .get("filter:s3api", "enable_extended_subresources")
        .map_err(|error| error.to_string())?
        .filter(|value| !value.trim().is_empty())
        .map(|value| strict_config_bool("enable_extended_subresources", &value))
        .transpose()?
        .unwrap_or(false);

    let s3_reseller = conf
        .get("filter:s3token", "reseller_prefix")
        .ok()
        .flatten()
        .unwrap_or_else(|| reseller.clone());

    let mut api = swift_s3api::S3Api::new(creds)
        .with_location(location)
        .with_dns_compliant(dns)
        .with_storage_domains(storage_domains)
        .with_allowable_clock_skew(allowable_clock_skew)
        .with_extended_subresources(extended_subresources)
        .with_reseller_prefix(s3_reseller);

    // IAM used to exist only as a library surface. Load it here so configured
    // identity maps, tenants, and policies participate in the live S3 request
    // path. Reject malformed input instead of silently dropping entries: an
    // operator must never believe a deny policy is active when it was ignored.
    let email_map = conf
        .get("filter:s3api", "iam_email_map")
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let mut email_keys = std::collections::HashSet::new();
    for entry in email_map
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let Some((email, principal)) = entry.split_once(':') else {
            return Err(format!("invalid iam_email_map entry {entry:?}"));
        };
        if email.trim().is_empty()
            || principal.trim().is_empty()
            || !email_keys.insert(email.trim().to_ascii_lowercase())
        {
            return Err(format!("invalid iam_email_map entry {entry:?}"));
        }
    }

    let access_key_map = conf
        .get("filter:s3api", "iam_access_key_map")
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let mut access_key_keys = std::collections::HashSet::new();
    for entry in access_key_map
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let pair = entry.split_once('=').or_else(|| entry.rsplit_once(':'));
        let Some((access_key, principal)) = pair else {
            return Err(format!("invalid iam_access_key_map entry {entry:?}"));
        };
        if access_key.trim().is_empty()
            || principal.trim().is_empty()
            || !access_key_keys.insert(access_key.trim().to_string())
        {
            return Err(format!("invalid iam_access_key_map entry {entry:?}"));
        }
    }

    let tenants = conf
        .get("filter:s3api", "iam_tenants")
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let mut tenant_keys = std::collections::HashSet::new();
    let mut tenant_members = std::collections::HashSet::new();
    for entry in tenants.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let Some((tenant, members)) = entry.split_once(':') else {
            return Err(format!("invalid iam_tenants entry {entry:?}"));
        };
        let member_list: Vec<&str> = members.split(',').map(str::trim).collect();
        if tenant.trim().is_empty()
            || !tenant_keys.insert(tenant.trim().to_string())
            || member_list.is_empty()
            || member_list.iter().any(|member| member.is_empty())
            || member_list
                .iter()
                .any(|member| !tenant_members.insert((*member).to_string()))
        {
            return Err(format!("invalid iam_tenants entry {entry:?}"));
        }
    }

    let identity = swift_s3api::iam::IdentityDirectory::new()
        .with_email_map_csv(&email_map)
        .with_access_key_map_csv(&access_key_map);
    let mut iam = swift_s3api::iam::IamService::new()
        .with_identity(identity)
        .with_tenants_csv(&tenants);

    let inline_policy = conf
        .get("filter:s3api", "iam_policy_json")
        .map_err(|e| e.to_string())?
        .filter(|value| !value.trim().is_empty());
    let policy_file = conf
        .get("filter:s3api", "iam_policy_file")
        .map_err(|e| e.to_string())?
        .filter(|value| !value.trim().is_empty());
    if inline_policy.is_some() && policy_file.is_some() {
        return Err("iam_policy_json and iam_policy_file are mutually exclusive".into());
    }
    let policy_json = match (inline_policy, policy_file) {
        (Some(json), None) => {
            if json.len() > 1_048_576 {
                return Err("iam_policy_json exceeds 1 MiB".into());
            }
            Some(json)
        }
        (None, Some(path)) => {
            let metadata = std::fs::metadata(&path)
                .map_err(|e| format!("could not stat iam_policy_file {path:?}: {e}"))?;
            if !metadata.is_file() {
                return Err(format!("iam_policy_file is not a regular file: {path:?}"));
            }
            if metadata.len() > 1_048_576 {
                return Err("iam_policy_file exceeds 1 MiB".into());
            }
            Some(
                std::fs::read_to_string(&path)
                    .map_err(|e| format!("could not read iam_policy_file {path:?}: {e}"))?,
            )
        }
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("mutual exclusion checked above"),
    };
    if let Some(json) = policy_json {
        let policy = swift_s3api::iam::IamService::parse_policy_json(&json)
            .filter(|doc| !doc.statements.is_empty())
            .ok_or_else(|| {
                "iam policy is invalid or contains no enforceable statements".to_string()
            })?;
        // A configured document is evaluated for every authenticated
        // principal. Its own Principal/Action/Resource fields select the
        // applicable requests, and explicit Deny wins inside IamService.
        iam.attach_policy("*", "configured", policy);
    }
    api = api.with_iam(iam);

    let cold_policy_map = conf
        .get("filter:s3api", "cold_policy_map")
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let mut cold_keys = std::collections::HashSet::new();
    for entry in cold_policy_map
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let Some((class, policy)) = entry.split_once(':') else {
            return Err(format!("invalid cold_policy_map entry {entry:?}"));
        };
        let class = class.trim().to_ascii_uppercase();
        let policy = policy
            .trim()
            .parse::<i64>()
            .map_err(|_| format!("invalid cold_policy_map policy index in {entry:?}"))?;
        if class.is_empty() || policy < 0 || !cold_keys.insert(class) {
            return Err(format!(
                "invalid or duplicate cold_policy_map entry {entry:?}"
            ));
        }
    }
    api = api.with_cold_map(swift_s3api::cold_tier::ColdPolicyMap::from_csv(
        &cold_policy_map,
    ));

    // EC2 deferral: inline /v3/s3tokens on s3api (does not wait for s3token filter).
    if let Some(uri) = external_s3token {
        api = api.with_s3token_client(std::sync::Arc::new(
            swift_middleware::HttpS3TokenClient::new(uri),
        ));
    }
    Ok(Some(api))
}

/// Build a `TempAuth` from a `[filter:tempauth]` section, or `None` if there are
/// no user records (auth stays off). Each `user_<account>_<user> = <key>
/// <group...>` line becomes one credential.
fn build_tempauth(
    conf: &SwiftConfig,
    swift_conf: &SwiftConfig,
    storage_url: &str,
) -> Option<swift_middleware::TempAuth> {
    let items = conf.items("filter:tempauth").ok()?;
    let mut auth = swift_middleware::TempAuth::new(storage_url.to_string());
    let mut any = false;
    for (key, val) in &items {
        let Some(rest) = key.strip_prefix("user_") else {
            continue;
        };
        // `user_<account>_<user>` — account/user must not contain underscores.
        let Some((account, user)) = rest.split_once('_') else {
            continue;
        };
        let mut toks = val.split_whitespace();
        let Some(secret) = toks.next() else { continue };
        let groups: Vec<&str> = toks.collect();
        auth.add_user(account, user, secret, &groups);
        any = true;
    }
    if !any {
        return None;
    }
    // Shared HMAC secret so HAProxy can fan out across proxies (tokens were
    // previously per-process and forced local-only backends).
    let prefix = swift_conf
        .get("swift-hash", "swift_hash_path_prefix")
        .ok()
        .flatten()
        .unwrap_or_default();
    let suffix = swift_conf
        .get("swift-hash", "swift_hash_path_suffix")
        .ok()
        .flatten()
        .unwrap_or_default();
    if !prefix.is_empty() || !suffix.is_empty() {
        auth.set_shared_secret(format!("{prefix}:{suffix}"));
    }
    Some(auth)
}

#[cfg(test)]
mod startup_policy_tests {
    use super::*;
    use swift_ring::RingDevice;

    fn no_tempurl_keys() -> Arc<dyn swift_middleware::KeyProvider> {
        Arc::new(swift_middleware::ClosureKeyProvider::new(|_, _| Vec::new()))
    }

    fn no_sync_keys() -> Arc<dyn swift_middleware::SyncKeyProvider> {
        Arc::new(swift_middleware::ClosureSyncKeyProvider::new(|_, _| None))
    }

    fn no_endpoints() -> Arc<dyn swift_middleware::EndpointResolver> {
        Arc::new(swift_middleware::StaticEndpoints(Vec::new()))
    }

    fn policies(conf: &str) -> StoragePolicyCollection {
        let parsed = SwiftConfig::parse_lenient(conf, &[], false).unwrap();
        parse_storage_policies(&parsed).unwrap()
    }

    fn ring_data(replicas: usize) -> RingData {
        let dev = RingDevice {
            id: 0,
            region: 1,
            zone: 1,
            ip: "127.0.0.1".to_string(),
            port: 6200,
            replication_ip: None,
            replication_port: None,
            device: "sda".to_string(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        };
        RingData::from_parts(
            vec![Some(dev)],
            32,
            (0..replicas).map(|_| vec![0]).collect(),
        )
    }

    #[test]
    fn every_configured_policy_requires_its_own_ring() {
        let policies = policies(
            "[storage-policy:0]\nname = replicated\ndefault = yes\n\
             [storage-policy:1]\nname = archive\n",
        );
        let hash_config = HashPathConfig::new("", "test").unwrap();
        let err = build_policy_object_rings(&policies, &hash_config, |name| {
            if name == "object" {
                Ok(ring_data(3))
            } else {
                Err(format!("missing {name}.ring.gz"))
            }
        })
        .unwrap_err();
        assert_eq!(err, "missing object-1.ring.gz");
    }

    #[test]
    fn ec_ring_replica_mismatch_is_rejected() {
        let policies = policies(
            "[storage-policy:0]\nname = replicated\ndefault = yes\n\
             [storage-policy:1]\nname = ec\npolicy_type = erasure_coding\n\
             ec_type = liberasurecode_rs_vand\nec_num_data_fragments = 2\n\
             ec_num_parity_fragments = 1\n",
        );
        let hash_config = HashPathConfig::new("", "test").unwrap();
        let err =
            build_policy_object_rings(&policies, &hash_config, |_| Ok(ring_data(1))).unwrap_err();
        assert!(err.contains("exactly 3 replicas"), "{err}");
    }

    #[test]
    fn proxy_config_reads_tuning_knobs_with_default_fallback() {
        let conf = SwiftConfig::parse_lenient(
            "[DEFAULT]\nnode_timeout = 30\n\
             [app:proxy-server]\nconn_timeout = 1.5\n\
             error_suppression_interval = 90\nerror_suppression_limit = 3\n\
             account_autocreate = yes\n\
             strict_cors_mode = no\n\
             cors_allow_origin = https://one.example, , https://two.example\n\
             cors_expose_headers = X-Trace, X-Custom\n\
             recheck_container_existence = 120\n\
             recheck_account_existence = 30\n",
            &[],
            false,
        )
        .unwrap();
        let config = proxy_config_from_conf(&conf, true);
        assert_eq!(config.conn_timeout, Duration::from_secs_f64(1.5));
        // node_timeout came from the DEFAULT section
        assert_eq!(config.node_timeout, Duration::from_secs(30));
        assert_eq!(config.error_suppression_interval, 90.0);
        assert_eq!(config.error_suppression_limit, 3);
        assert!(config.account_autocreate);
        assert!(!config.allow_account_management);
        assert!(!config.strict_cors_mode);
        assert_eq!(
            config.cors_allow_origin,
            ["https://one.example", "https://two.example"]
        );
        assert_eq!(config.cors_expose_headers, ["X-Trace", "X-Custom"]);
        assert!(config.auth_enabled);
        assert_eq!(config.recheck_container_existence, 120.0);
        assert_eq!(config.recheck_account_existence, 30.0);

        // Missing, garbage, and non-positive values keep the Python defaults
        // (conn_timeout 0.5, node_timeout 10, interval 60, limit 10).
        let conf = SwiftConfig::parse_lenient(
            "[app:proxy-server]\nconn_timeout = banana\nnode_timeout = -1\n\
             error_suppression_limit = many\n\
             recheck_container_existence = soon\n",
            &[],
            false,
        )
        .unwrap();
        let config = proxy_config_from_conf(&conf, false);
        assert_eq!(config.conn_timeout, Duration::from_millis(500));
        assert_eq!(config.node_timeout, Duration::from_secs(10));
        assert_eq!(config.error_suppression_interval, 60.0);
        assert_eq!(config.error_suppression_limit, 10);
        assert!(!config.account_autocreate);
        assert!(config.strict_cors_mode);
        assert!(config.cors_allow_origin.is_empty());
        assert!(config.cors_expose_headers.is_empty());
        assert!(!config.auth_enabled);
        // garbage / missing recheck values keep the Python default of 60
        assert_eq!(config.recheck_container_existence, 60.0);

        let conf = SwiftConfig::parse_lenient(
            "[app:proxy-server]\nallow_account_management = true\n",
            &[],
            false,
        )
        .unwrap();
        let config = proxy_config_from_conf(&conf, false);
        assert!(config.allow_account_management);
        assert_eq!(config.recheck_account_existence, 60.0);
    }

    #[test]
    fn server_options_read_workers_clients_timeout_and_log_conf() {
        let conf = SwiftConfig::parse_lenient(
            "[DEFAULT]\nlog_statsd_host = 127.0.0.1\n\
             [app:proxy-server]\nworkers = 8\nmax_clients = 512\n\
             client_timeout = 42\nlog_name = my-proxy\nlog_level = DEBUG\n\
             log_statsd_port = 9125\nlog_statsd_metric_prefix = saio\n\
             trace_endpoint = 172.18.1.2:4318\ntrace_sample_ratio = 0.25\n",
            &[],
            false,
        )
        .unwrap();
        let opts = server_options_from_conf(&conf);
        assert_eq!(opts.workers, Some(8));
        assert_eq!(opts.max_clients, 512);
        assert_eq!(opts.client_timeout_secs, 42);
        assert_eq!(opts.log_name, "my-proxy");
        assert_eq!(opts.log_level, "DEBUG");
        // log_statsd_host fell back to the DEFAULT section
        assert_eq!(opts.log_statsd_host, "127.0.0.1");
        assert_eq!(opts.log_statsd_port, 9125);
        assert_eq!(opts.log_statsd_metric_prefix, "saio");
        assert_eq!(opts.trace_endpoint, "172.18.1.2:4318");
        assert_eq!(opts.trace_sample_ratio, 0.25);

        // Absent (or `workers = auto`) conf keeps the Python defaults; None
        // workers means "use the server's CPU-scaled default". An
        // out-of-range trace_sample_ratio keeps the default of 1.0.
        let conf = SwiftConfig::parse_lenient(
            "[app:proxy-server]\nworkers = auto\ntrace_sample_ratio = 2.5\n",
            &[],
            false,
        )
        .unwrap();
        let opts = server_options_from_conf(&conf);
        assert_eq!(opts.workers, None);
        assert_eq!(opts.max_clients, 1024);
        assert_eq!(opts.client_timeout_secs, 60);
        assert_eq!(opts.log_name, "proxy-server");
        assert_eq!(opts.log_level, "info");
        assert_eq!(opts.log_statsd_host, "");
        assert_eq!(opts.log_statsd_port, 8125);
        assert_eq!(opts.log_statsd_metric_prefix, "");
        assert_eq!(opts.trace_endpoint, "");
        assert_eq!(opts.trace_sample_ratio, 1.0);
    }

    #[test]
    fn slo_runtime_options_match_python_2_33_defaults_and_filter_config() {
        let conf = SwiftConfig::parse_lenient("[app:proxy-server]\n", &[], false).unwrap();
        assert_eq!(
            slo_options_from_conf(&conf),
            SloOptions {
                concurrency: 2,
                yield_frequency: 10,
            }
        );

        let conf = SwiftConfig::parse_lenient(
            "[DEFAULT]\nconcurrency = 3\nyield_frequency = 11\n\
             [filter:slo]\nuse = egg:swift#slo\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            slo_options_from_conf(&conf),
            SloOptions {
                concurrency: 3,
                yield_frequency: 11,
            }
        );

        let conf = SwiftConfig::parse_lenient(
            "[filter:slo]\nuse = egg:swift#slo\nconcurrency = 7\nyield_frequency = 17\n",
            &[],
            false,
        )
        .unwrap();
        let hash_config = HashPathConfig::new("", "test").unwrap();
        let slo = build_slo(&conf, hash_config);
        assert_eq!(slo.concurrent_gets, 7);
        assert_eq!(slo.yield_frequency, 17.0);

        let conf = SwiftConfig::parse_lenient(
            "[filter:slo]\nconcurrency = -1\nyield_frequency = -2\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            slo_options_from_conf(&conf),
            SloOptions {
                concurrency: 0,
                yield_frequency: -2,
            },
            "Python clamps concurrency to 0..1000 but does not clamp yield_frequency"
        );
    }

    #[test]
    fn info_matches_python_2_33_version_and_slo_contract() {
        let conf = SwiftConfig::parse_lenient(
            "[DEFAULT]\nswift_compat_version = 2.33.1\n\
             [app:proxy-server]\nswift_compat_version = 2.33.7\n\
             [filter:slo]\nyield_frequency = 17\n",
            &[],
            false,
        )
        .unwrap();
        let info = build_info_json(&conf, &conf, true, false, false);
        let value: serde_json::Value = serde_json::from_str(&info).unwrap();
        assert_eq!(value["swift"]["version"], "2.33.7");
        assert_eq!(value["swift"]["strict_cors_mode"], true);
        assert_eq!(value["swift"]["allow_open_expired"], false);
        assert_eq!(value["swift"]["max_request_line"], 8192);
        assert!(
            value.get("dlo").is_none(),
            "Python Swift 2.33 DLO does not register a /info section"
        );
        assert_eq!(
            value["slo"],
            serde_json::json!({
                "allow_async_delete": true,
                "yield_frequency": 17,
                "max_manifest_segments": 1000,
                "max_manifest_size": 8388608,
                "min_segment_size": 1,
            })
        );
        assert!(value["slo"].get("max_get_time").is_none());

        let default_conf = SwiftConfig::parse_lenient("[app:proxy-server]\n", &[], false).unwrap();
        let default_info = build_info_json(&default_conf, &default_conf, true, false, false);
        let default_value: serde_json::Value = serde_json::from_str(&default_info).unwrap();
        assert_eq!(default_value["swift"]["version"], "2.33.0");
        assert_eq!(default_value["swift"]["strict_cors_mode"], true);
        assert_eq!(default_value["slo"]["yield_frequency"], 10);

        let fallback_conf = SwiftConfig::parse_lenient(
            "[DEFAULT]\nswift_compat_version = 2.33.1\n[app:proxy-server]\n",
            &[],
            false,
        )
        .unwrap();
        let fallback_info = build_info_json(&fallback_conf, &fallback_conf, true, false, false);
        let fallback_value: serde_json::Value = serde_json::from_str(&fallback_info).unwrap();
        assert_eq!(fallback_value["swift"]["version"], "2.33.1");

        let non_strict_conf = SwiftConfig::parse_lenient(
            "[DEFAULT]\nstrict_cors_mode = false\n[app:proxy-server]\n",
            &[],
            false,
        )
        .unwrap();
        let non_strict_info =
            build_info_json(&non_strict_conf, &non_strict_conf, true, false, false);
        let non_strict_value: serde_json::Value = serde_json::from_str(&non_strict_info).unwrap();
        assert_eq!(non_strict_value["swift"]["strict_cors_mode"], false);

        let without_slo = SwiftConfig::parse_lenient(
            "[pipeline:main]\npipeline = catch_errors gatekeeper proxy-server\n",
            &[],
            false,
        )
        .unwrap();
        let without_slo_info: serde_json::Value = serde_json::from_str(&build_info_json(
            &without_slo,
            &without_slo,
            true,
            false,
            false,
        ))
        .unwrap();
        assert!(without_slo_info.get("slo").is_none());
    }

    #[test]
    fn dlo_config_reads_filter_and_legacy_app_values_and_fails_closed() {
        let filter_conf = SwiftConfig::parse_lenient(
            "[filter:dlo]\nmax_get_time = 123\nrate_limit_after_segment = 4\n\
             rate_limit_segments_per_sec = 7\n",
            &[],
            false,
        )
        .unwrap();
        assert!(build_dlo(&filter_conf).is_ok());

        let legacy_conf = SwiftConfig::parse_lenient(
            "[app:proxy-server]\nmax_get_time = 321\nrate_limit_after_segment = -1\n\
             rate_limit_segments_per_sec = 0\n",
            &[],
            false,
        )
        .unwrap();
        assert!(build_dlo(&legacy_conf).is_ok());

        let invalid =
            SwiftConfig::parse_lenient("[filter:dlo]\nmax_get_time = forever\n", &[], false)
                .unwrap();
        let error = match build_dlo(&invalid) {
            Err(error) => error,
            Ok(_) => panic!("invalid DLO integer must fail closed"),
        };
        assert!(error.contains("max_get_time"), "{error}");
    }

    #[test]
    fn ratelimit_filter_is_built_only_when_configured() {
        let conf = SwiftConfig::parse_lenient("[app:proxy-server]\n", &[], false).unwrap();
        assert!(matches!(build_ratelimit(&conf), Ok(None)));

        let conf = SwiftConfig::parse_lenient(
            "[filter:ratelimit]\nuse = egg:swift#ratelimit\n\
             account_ratelimit = 5\nmax_sleep_time_seconds = 30\n\
             [filter:cache]\nmemcache_servers = 10.0.0.1:11211,10.0.0.2:11211\n",
            &[],
            false,
        )
        .unwrap();
        let rl = build_ratelimit(&conf)
            .expect("valid ratelimit configuration")
            .expect("ratelimit section builds the filter");
        assert_eq!(rl.account_ratelimit, 5.0);
        assert_eq!(rl.max_sleep_time_seconds, 30.0);
        assert_eq!(
            rl.memcache_servers(),
            &["10.0.0.1:11211".to_string(), "10.0.0.2:11211".to_string()]
        );

        let invalid = SwiftConfig::parse_lenient(
            "[filter:ratelimit]\nuse = egg:swift#ratelimit\naccount_ratelimit = nope\n",
            &[],
            false,
        )
        .unwrap();
        let error = match build_ratelimit(&invalid) {
            Err(error) => error,
            Ok(_) => panic!("invalid numeric configuration must fail closed"),
        };
        assert!(error.contains("account_ratelimit"), "{error}");
    }

    #[test]
    fn info_registers_only_built_ratelimit_with_python_shape() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper ratelimit proxy-server\n\
             [filter:cache]\nmemcache_servers = 10.0.0.1:11211,10.0.0.2:11211\n\
             [filter:ratelimit]\nuse = egg:swift#ratelimit\n\
             account_ratelimit = 5\nmax_sleep_time_seconds = 30\n\
             container_ratelimit_0 = 100\ncontainer_ratelimit_1000 = 50\n\
             container_listing_ratelimit_0 = 200\n",
            &[],
            false,
        )
        .unwrap();
        let info: serde_json::Value =
            serde_json::from_str(&build_info_json(&conf, &conf, true, false, false)).unwrap();
        assert_eq!(
            info["ratelimit"],
            serde_json::json!({
                "account_ratelimit": 5.0,
                "max_sleep_time_seconds": 30.0,
                "container_ratelimits": [[0, 100.0], [1000, 50.0]],
                "container_listing_ratelimits": [[0, 200.0]],
            })
        );

        let invalid = SwiftConfig::parse_lenient(
            "[pipeline:main]\npipeline = ratelimit proxy-server\n\
             [filter:ratelimit]\nuse = egg:swift#ratelimit\naccount_ratelimit = nope\n",
            &[],
            false,
        )
        .unwrap();
        let invalid_info: serde_json::Value =
            serde_json::from_str(&build_info_json(&invalid, &invalid, true, false, false)).unwrap();
        assert!(invalid_info.get("ratelimit").is_none());
    }

    #[test]
    fn no_pipeline_line_keeps_default_order() {
        let conf = SwiftConfig::parse_lenient(
            "[app:proxy-server]\n\
             [filter:ratelimit]\nuse = egg:swift#ratelimit\n\
             [filter:tempauth]\nuser_test_tester = secret .admin\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            configured_filter_names(&conf, true),
            vec!["ratelimit", "tempauth", "copy", "slo", "dlo"]
        );
        let conf_no_rl = SwiftConfig::parse_lenient(
            "[app:proxy-server]\n[filter:tempauth]\nuser_test_tester = secret .admin\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            configured_filter_names(&conf_no_rl, true),
            vec!["tempauth", "copy", "slo", "dlo"]
        );
    }

    #[test]
    fn pipeline_order_from_conf_reorders_implemented_filters() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck tempauth ratelimit copy slo dlo proxy-server\n\
             [filter:ratelimit]\nuse = egg:swift#ratelimit\n\
             [filter:tempauth]\nuser_test_tester = secret .admin\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            configured_filter_names(&conf, true),
            vec!["tempauth", "ratelimit", "copy", "slo", "dlo"]
        );
    }

    #[test]
    fn pipeline_container_sync_wires_and_info() {
        let conf = SwiftConfig::parse_lenient(
            "[DEFAULT]\nswift_dir = /nonexistent-peregrine-container-sync-test\n\
             [pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck container_sync tempauth proxy-server\n\
             [filter:tempauth]\nuser_test_tester = secret .admin\n\
             [filter:container_sync]\nallow_full_urls = true\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            configured_filter_names(&conf, true),
            vec!["container_sync", "tempauth"]
        );
        let ta = build_tempauth(&conf, &conf, "http://127.0.0.1:8081");
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes) = build_configured_filters(
            &conf,
            ta,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(
            notes.iter().any(|n| n.contains("container_sync enabled")),
            "{notes:?}"
        );
        assert_eq!(filters.len(), 2, "notes={notes:?}");
        let info = build_info_json(&conf, &conf, true, false, true);
        let v: serde_json::Value = serde_json::from_str(&info).unwrap();
        assert!(
            v.get("container_sync").is_some(),
            "must advertise container_sync on /info when filter is wired: {v}"
        );
        assert!(v["container_sync"].get("realms").is_some());
    }

    #[test]
    fn pipeline_container_sync_malformed_realms_is_typed_failure() {
        let serial = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let swift_dir = std::env::temp_dir().join(format!(
            "peregrine-proxy-container-sync-{}-{serial}",
            std::process::id()
        ));
        std::fs::create_dir(&swift_dir).unwrap();
        std::fs::write(
            swift_dir.join("container-sync-realms.conf"),
            "[LOCAL]\nkey = one\nkey = two\n",
        )
        .unwrap();
        let conf = SwiftConfig::parse_lenient(
            &format!(
                "[DEFAULT]\nswift_dir = {}\n\
                 [pipeline:main]\npipeline = container_sync tempauth proxy-server\n\
                 [filter:tempauth]\nuser_test_tester = secret .admin\n\
                 [filter:container_sync]\nallow_full_urls = false\n",
                swift_dir.display()
            ),
            &[],
            false,
        )
        .unwrap();
        let ta = build_tempauth(&conf, &conf, "http://127.0.0.1:8081");
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, _notes, issues) = build_configured_filters_with_issues(
            &conf,
            ta,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            no_endpoints(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        std::fs::remove_dir_all(&swift_dir).unwrap();
        assert_eq!(filters.len(), 1, "only tempauth may be built");
        assert!(issues.iter().any(|issue| {
            issue.filter == "container_sync"
                && issue.kind == PipelineBuildIssueKind::BuildFailure
                && issue.detail.contains("duplicate option")
        }));
        assert!(strict_pipeline_rejects(&conf, &issues));
    }

    #[test]
    fn pipeline_p1a_wires_bulk_tempurl() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck proxy-logging cache listing_formats bulk tempurl tempauth copy slo dlo proxy-logging proxy-server\n\
             [filter:cache]\nuse = egg:swift#memcache\nmemcache_servers = 127.0.0.1:11211\n\
             [filter:proxy-logging]\nuse = egg:swift#proxy_logging\n\
             [filter:tempauth]\nuser_test_tester = secret .admin\n\
             [filter:bulk]\nmax_deletes_per_request = 100\n\
             [filter:tempurl]\nmethods = GET HEAD\nallowed_digests = sha256 sha512\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            configured_filter_names(&conf, true),
            vec![
                "proxy_logging",
                "cache",
                "listing_formats",
                "bulk",
                "tempurl",
                "tempauth",
                "copy",
                "slo",
                "dlo",
                "proxy_logging",
            ]
        );
        let ta = build_tempauth(&conf, &conf, "http://127.0.0.1:8081");
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes) = build_configured_filters(
            &conf,
            ta,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(
            notes.iter().any(|n| n.contains("bulk enabled")),
            "{notes:?}"
        );
        assert!(notes.iter().any(|n| n == "tempurl enabled"), "{notes:?}");
        assert_eq!(filters.len(), 10, "notes={notes:?}");

        let info = build_info_json(&conf, &conf, true, false, true);
        let v: serde_json::Value = serde_json::from_str(&info).unwrap();
        assert_eq!(v["tempauth"]["account_acls"], true);
        assert_eq!(v["bulk_delete"]["max_deletes_per_request"], 100);
        assert!(
            v.get("bulk_upload").is_some(),
            "extract-archive is implemented; must advertise bulk_upload"
        );
        assert!(v.get("formpost").is_none());
    }

    #[test]
    fn pipeline_p1b_wires_formpost_staticweb_quotas_symlink_vw() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck formpost staticweb container_quotas account_quotas symlink versioned_writes name_check etag_quoter crossdomain tempauth copy proxy-server\n\
             [filter:tempauth]\nuser_test_tester = secret .admin\n\
             [filter:versioned_writes]\nallow_versioned_writes = true\n\
             [filter:formpost]\nallowed_digests = sha256 sha512\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            configured_filter_names(&conf, true),
            vec![
                "formpost",
                "staticweb",
                "container_quotas",
                "account_quotas",
                "symlink",
                "versioned_writes",
                "name_check",
                "etag_quoter",
                "crossdomain",
                "tempauth",
                "copy",
            ]
        );
        let ta = build_tempauth(&conf, &conf, "http://127.0.0.1:8081");
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes) = build_configured_filters(
            &conf,
            ta,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(notes.iter().any(|n| n == "formpost enabled"), "{notes:?}");
        assert!(notes.iter().any(|n| n == "staticweb enabled"), "{notes:?}");
        assert!(
            notes.iter().any(|n| n.contains("versioned_writes enabled")),
            "{notes:?}"
        );
        assert_eq!(filters.len(), 11, "notes={notes:?}");

        let info = build_info_json(&conf, &conf, true, false, true);
        let v: serde_json::Value = serde_json::from_str(&info).unwrap();
        assert!(v.get("formpost").is_some());
        assert_eq!(
            v["formpost"]["allowed_digests"],
            serde_json::json!(["sha256", "sha512"])
        );
        assert!(v.get("staticweb").is_some());
        assert!(v.get("container_quotas").is_some());
        assert!(v.get("account_quotas").is_some());
        assert!(v.get("symlink").is_some());
        assert_eq!(
            v["versioned_writes"]["allowed_flags"],
            serde_json::json!(["x-versions-location", "x-history-location"])
        );
        // bulk not in this pipeline → no bulk_upload
        assert!(v.get("bulk_upload").is_none());
    }

    #[test]
    fn copy_yield_frequency_is_strict_and_honors_filter_precedence() {
        let defaults = SwiftConfig::parse_lenient(
            "[DEFAULT]\nyield_frequency = 11\n[filter:copy]\nuse = egg:swift#copy\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(build_copy(&defaults).unwrap().yield_frequency, 11.0);

        let local = SwiftConfig::parse_lenient(
            "[DEFAULT]\nyield_frequency = 11\n[filter:copy]\nyield_frequency = -2\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(build_copy(&local).unwrap().yield_frequency, 0.0);

        let invalid =
            SwiftConfig::parse_lenient("[filter:copy]\nyield_frequency = 1.5\n", &[], false)
                .unwrap();
        assert!(build_copy(&invalid).is_err());
    }

    #[test]
    fn symlink_symloop_max_is_strict_and_invalid_config_is_not_advertised() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck symlink proxy-server\n\
             [app:proxy-server]\nstrict_pipeline = true\n\
             [filter:symlink]\nsymloop_max = not-an-integer\n",
            &[],
            false,
        )
        .unwrap();
        assert!(build_symlink(&conf).is_err());

        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes, issues) = build_configured_filters_with_issues(
            &conf,
            None,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            no_endpoints(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(filters.is_empty(), "notes={notes:?}");
        assert!(issues.iter().any(|issue| {
            issue.filter == "symlink" && issue.kind == PipelineBuildIssueKind::BuildFailure
        }));
        assert!(strict_pipeline_rejects(&conf, &issues));

        let info = build_info_json(&conf, &conf, false, false, true);
        let value: serde_json::Value = serde_json::from_str(&info).unwrap();
        assert!(value.get("symlink").is_none(), "{value}");
    }

    #[test]
    fn formpost_filters_digests_and_advertises_deprecation_exactly() {
        let defaults = SwiftConfig::parse_lenient("[filter:formpost]\n", &[], false).unwrap();
        let (allowed, deprecated, unsupported) = formpost_digest_options(&defaults).unwrap();
        assert_eq!(allowed, vec!["sha1", "sha256", "sha512"]);
        assert_eq!(deprecated, vec!["sha1"]);
        assert!(unsupported.is_empty());

        let mixed = SwiftConfig::parse_lenient(
            "[pipeline:main]\npipeline = formpost proxy-server\n\
             [filter:formpost]\nallowed_digests = sha1 sha512 md5 not-a-valid-digest\n",
            &[],
            false,
        )
        .unwrap();
        let (allowed, deprecated, unsupported) = formpost_digest_options(&mixed).unwrap();
        assert_eq!(allowed, vec!["sha1", "sha512"]);
        assert_eq!(deprecated, vec!["sha1"]);
        assert_eq!(unsupported, vec!["md5", "not-a-valid-digest"]);
        let info: serde_json::Value =
            serde_json::from_str(&build_info_json(&mixed, &mixed, true, false, true)).unwrap();
        assert_eq!(
            info["formpost"]["allowed_digests"],
            serde_json::json!(allowed)
        );
        assert_eq!(
            info["formpost"]["deprecated_digests"],
            serde_json::json!(deprecated)
        );

        let invalid = SwiftConfig::parse_lenient(
            "[pipeline:main]\npipeline = formpost proxy-server\n\
             [filter:formpost]\nallowed_digests = md4 md5\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            formpost_digest_options(&invalid).unwrap_err(),
            "No valid digest algorithms are configured"
        );
        let invalid_info: serde_json::Value =
            serde_json::from_str(&build_info_json(&invalid, &invalid, true, false, true)).unwrap();
        assert!(invalid_info.get("formpost").is_none());
    }

    #[test]
    fn pipeline_s3api_wires_without_info_pollution() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck s3api tempauth copy proxy-server\n\
             [filter:tempauth]\nuser_test_tester = testing .admin\n\
             [filter:s3api]\nlocation = us-east-1\n",
            &[],
            false,
        )
        .unwrap();
        let ta = build_tempauth(&conf, &conf, "http://127.0.0.1:8081");
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes) = build_configured_filters(
            &conf,
            ta,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(
            notes.iter().any(|n| n.contains("s3api enabled")),
            "{notes:?}"
        );
        assert!(
            notes.iter().all(|n| !n.contains("EC2→s3token deferral")),
            "without s3token auth_uri, deferral must stay OFF: {notes:?}"
        );
        assert!(filters.len() >= 2);
        assert_eq!(
            configured_filter_names(&conf, true)
                .iter()
                .filter(|n| **n == "s3api")
                .count(),
            1
        );
        // Honest /info: no s3api key even when the filter is wired.
        let info = build_info_json(&conf, &conf, true, false, true);
        let v: serde_json::Value = serde_json::from_str(&info).unwrap();
        assert!(
            v.get("s3api").is_none(),
            "must not advertise s3api on Swift /info: {v}"
        );
        assert_eq!(v["tempauth"]["account_acls"], true);
    }

    #[test]
    fn pipeline_s3api_wires_ec2_s3token_deferral_when_auth_uri_set() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck s3api s3token tempauth copy proxy-server\n\
             [filter:tempauth]\nuser_test_tester = testing .admin\n\
             [filter:s3api]\nlocation = RegionOne\n\
             [filter:s3token]\nauth_uri = http://127.0.0.1:5001\nreseller_prefix = AUTH_\n",
            &[],
            false,
        )
        .unwrap();
        let ta = build_tempauth(&conf, &conf, "http://127.0.0.1:8081");
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (_filters, notes) = build_configured_filters(
            &conf,
            ta,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(
            notes
                .iter()
                .any(|n| n.contains("s3api enabled") && n.contains("EC2→s3token deferral")),
            "expected EC2 deferral note when s3token auth_uri set: {notes:?}"
        );
        assert!(
            notes.iter().any(|n| n.contains("s3token enabled")),
            "{notes:?}"
        );
        let api = build_s3api(&conf)
            .expect("valid s3api configuration")
            .expect("s3api credentials");
        assert!(api.s3token_client.is_some());
    }

    #[test]
    fn pipeline_s3api_keystone_mode_does_not_require_tempauth_users() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck s3api s3token authtoken keystoneauth proxy-server\n\
             [filter:s3api]\nlocation = RegionOne\n\
             [filter:s3token]\nauth_uri = http://127.0.0.1:5001\nreseller_prefix = AUTH_\n",
            &[],
            false,
        )
        .unwrap();
        let api = build_s3api(&conf)
            .expect("valid Keystone-backed s3api configuration")
            .expect("external s3token is a usable credential source");
        assert!(api.s3token_client.is_some());
    }

    #[test]
    fn pipeline_s3api_uses_python_storage_domain_and_clock_skew_names() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck s3api tempauth copy proxy-server\n\
             [filter:tempauth]\nuser_test_tester = testing .admin\n\
             [filter:s3api]\n\
             storage_domain = s3.example.test, objects.example.test\n\
             storage_domains = ignored.compat.example\n\
             allowable_clock_skew = 37\n\
             enable_extended_subresources = true\n",
            &[],
            false,
        )
        .unwrap();
        let api = build_s3api(&conf)
            .expect("valid s3api configuration")
            .expect("s3api credentials");
        assert_eq!(
            api.storage_domains,
            vec!["s3.example.test", "objects.example.test"]
        );
        assert_eq!(api.allowable_clock_skew, 37);
        assert!(api.extended_subresources);
    }

    #[test]
    fn pipeline_s3api_invalid_clock_skew_fails_closed() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck s3api tempauth copy proxy-server\n\
             [filter:tempauth]\nuser_test_tester = testing .admin\n\
             [filter:s3api]\nallowable_clock_skew = -1\n",
            &[],
            false,
        )
        .unwrap();
        let error = match build_s3api(&conf) {
            Err(error) => error,
            Ok(_) => panic!("negative allowable_clock_skew must fail closed"),
        };
        assert!(error.contains("allowable_clock_skew"), "{error}");
    }

    #[test]
    fn pipeline_s3api_extended_subresources_default_off_and_invalid_fails_closed() {
        let default_conf = SwiftConfig::parse_lenient(
            "[filter:tempauth]\nuser_test_tester = testing .admin\n[filter:s3api]\n",
            &[],
            false,
        )
        .unwrap();
        let api = build_s3api(&default_conf)
            .expect("valid default s3api configuration")
            .expect("tempauth credentials");
        assert!(!api.extended_subresources);

        let invalid = SwiftConfig::parse_lenient(
            "[filter:tempauth]\nuser_test_tester = testing .admin\n\
             [filter:s3api]\nenable_extended_subresources = sometimes\n",
            &[],
            false,
        )
        .unwrap();
        let error = match build_s3api(&invalid) {
            Err(error) => error,
            Ok(_) => panic!("invalid extended-subresource boolean must fail closed"),
        };
        assert!(error.contains("enable_extended_subresources"), "{error}");
    }

    #[test]
    fn pipeline_s3api_wires_iam_identity_policy_and_cold_map() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck s3api tempauth copy proxy-server\n\
             [filter:tempauth]\nuser_test_tester = testing .admin\n\
             [filter:s3api]\n\
             iam_email_map = alice@example.com:alice\n\
             iam_access_key_map = test:tester=alice\n\
             iam_tenants = tenant-a:alice,bob\n\
             iam_policy_json = {\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::bucket/*\",\"Principal\":\"alice\"}]}\n\
             cold_policy_map = GLACIER:2,HOT:0\n",
            &[],
            false,
        )
        .unwrap();
        let api = build_s3api(&conf)
            .expect("valid s3api configuration")
            .expect("s3api credentials");
        assert_eq!(
            api.iam.identity.canonical_id_for_access_key("test:tester"),
            "alice"
        );
        assert_eq!(
            api.iam.identity.resolve_email("ALICE@example.com"),
            Some("alice".to_string())
        );
        assert_eq!(api.iam.tenant_of("alice"), Some("tenant-a"));
        assert_eq!(
            api.iam
                .evaluate("alice", "s3:GetObject", "arn:aws:s3:::bucket/object"),
            Some(true)
        );
        assert_eq!(api.cold_map.policy_for_class("GLACIER"), Some(2));
        assert_eq!(api.cold_map.default_hot_policy, 0);
    }

    #[test]
    fn pipeline_s3api_invalid_security_config_fails_closed() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck s3api tempauth copy proxy-server\n\
             [filter:tempauth]\nuser_test_tester = testing .admin\n\
             [filter:s3api]\niam_policy_json = definitely-not-json\n",
            &[],
            false,
        )
        .unwrap();
        let error = match build_s3api(&conf) {
            Err(error) => error,
            Ok(_) => panic!("invalid policy must fail closed"),
        };
        assert!(error.contains("invalid"), "{error}");
        assert!(
            !configured_filter_names(&conf, true).contains(&"s3api"),
            "invalid filter must not be reported as configured"
        );
    }

    #[test]
    fn pipeline_unknown_filter_registers_passthrough_when_explicitly_enabled() {
        // Operators may explicitly preserve an unknown name as a no-op.
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck tempauth not_a_real_filter copy proxy-server\n\
             [app:proxy-server]\nplugin_default = passthrough\n\
             [filter:tempauth]\nuser_test_tester = secret .admin\n",
            &[],
            false,
        )
        .unwrap();
        let ta = build_tempauth(&conf, &conf, "http://127.0.0.1:8081");
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes, issues) = build_configured_filters_with_issues(
            &conf,
            ta,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            no_endpoints(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        // tempauth + not_a_real_filter (passthrough) + copy
        assert_eq!(filters.len(), 3, "notes={notes:?}");
        assert!(
            notes
                .iter()
                .any(|n| { n.contains("not_a_real_filter") && n.contains("NamedPassthrough") }),
            "{notes:?}"
        );
        assert!(issues.is_empty(), "issues={issues:?}");
        assert!(strict_pipeline_from_conf(&conf));
        assert!(!strict_pipeline_rejects(&conf, &issues));
    }

    #[test]
    fn pipeline_unknown_filter_skips_when_plugin_default_skip() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck tempauth not_a_real_filter copy proxy-server\n\
             [app:proxy-server]\nplugin_default = skip\n\
             [filter:tempauth]\nuser_test_tester = secret .admin\n",
            &[],
            false,
        )
        .unwrap();
        let ta = build_tempauth(&conf, &conf, "http://127.0.0.1:8081");
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes) = build_configured_filters(
            &conf,
            ta,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert_eq!(filters.len(), 2, "notes={notes:?}");
        assert!(notes
            .iter()
            .any(|n| n.contains("not_a_real_filter") && n.contains("skip")));
    }

    #[test]
    fn pipeline_unknown_filter_invalid_plugin_default_fails_closed() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck tempauth not_a_real_filter copy proxy-server\n\
             [app:proxy-server]\nstrict_pipeline = false\nplugin_default = typo\n\
             [filter:tempauth]\nuser_test_tester = secret .admin\n",
            &[],
            false,
        )
        .unwrap();
        let ta = build_tempauth(&conf, &conf, "http://127.0.0.1:8081");
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes, issues) = build_configured_filters_with_issues(
            &conf,
            ta,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            no_endpoints(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert_eq!(filters.len(), 2, "notes={notes:?}");
        assert!(notes
            .iter()
            .any(|n| n.contains("not_a_real_filter") && n.contains("skip")));
        assert!(issues.iter().any(|issue| {
            issue.filter == "not_a_real_filter"
                && issue.kind == PipelineBuildIssueKind::UnknownFilter
        }));
    }

    #[test]
    fn pipeline_p3_auth_wires_authtoken_keystoneauth_and_info() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck authtoken keystoneauth tempauth copy proxy-server\n\
             [filter:tempauth]\nuser_test_tester = secret .admin\n\
             [filter:authtoken]\n\
             delay_auth_decision = true\n\
             static_token_good = u1 alice t1 proj admin\n\
             [filter:keystoneauth]\n\
             operator_roles = admin,swiftoperator\n\
             reseller_prefix = AUTH\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            configured_filter_names(&conf, true),
            vec!["authtoken", "keystoneauth", "tempauth", "copy"]
        );
        let ta = build_tempauth(&conf, &conf, "http://127.0.0.1:8081");
        let ka = build_keystoneauth(&conf);
        assert!(ka.is_some());
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes) = build_configured_filters(
            &conf,
            ta,
            ka,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(
            notes.iter().any(|n| n.contains("authtoken enabled")),
            "{notes:?}"
        );
        assert!(
            notes.iter().any(|n| n.contains("keystoneauth enabled")),
            "{notes:?}"
        );
        assert_eq!(filters.len(), 4, "notes={notes:?}");

        let info = build_info_json(&conf, &conf, true, false, true);
        let v: serde_json::Value = serde_json::from_str(&info).unwrap();
        assert_eq!(v["tempauth"]["account_acls"], true);
        assert!(v.get("keystoneauth").is_some(), "{v}");
        assert_eq!(v["keystoneauth"]["reseller_prefix"][0], "AUTH_");
    }

    #[test]
    fn pipeline_crypto_wires_keymaster_encryption_and_info() {
        // root_secret = base64(bytes(range(32)))
        let root_b64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let conf = SwiftConfig::parse_lenient(
            &format!(
                "[pipeline:main]\n\
                 pipeline = catch_errors gatekeeper healthcheck keymaster encryption tempauth copy proxy-server\n\
                 [filter:tempauth]\nuser_test_tester = secret .admin\n\
                 [filter:keymaster]\nencryption_root_secret = {root_b64}\n\
                 [filter:encryption]\ndisable_encryption = false\n"
            ),
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            configured_filter_names(&conf, true),
            vec!["keymaster", "encryption", "tempauth", "copy"]
        );
        let ta = build_tempauth(&conf, &conf, "http://127.0.0.1:8081");
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes) = build_configured_filters(
            &conf,
            ta,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(notes.iter().any(|n| n == "keymaster enabled"), "{notes:?}");
        assert!(
            notes
                .iter()
                .any(|n| n.contains("encryption enabled") && n.contains("disable_encryption=false")),
            "{notes:?}"
        );
        // keymaster + decrypter + encrypter + tempauth + copy = 5
        assert_eq!(filters.len(), 5, "notes={notes:?}");

        let info = build_info_json(&conf, &conf, true, false, true);
        let v: serde_json::Value = serde_json::from_str(&info).unwrap();
        assert_eq!(v["encryption"]["enabled"], true, "{v}");

        // Default pipeline (no crypto names) must not advertise encryption.
        let bare = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck tempauth copy proxy-server\n\
             [filter:tempauth]\nuser_test_tester = secret .admin\n",
            &[],
            false,
        )
        .unwrap();
        let bare_info = build_info_json(&bare, &bare, true, false, true);
        let bv: serde_json::Value = serde_json::from_str(&bare_info).unwrap();
        assert!(
            bv.get("encryption").is_none(),
            "default pipeline must not advertise encryption: {bv}"
        );
    }

    #[test]
    fn pipeline_crypto_skips_without_root_secret() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck keymaster encryption copy proxy-server\n",
            &[],
            false,
        )
        .unwrap();
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes) = build_configured_filters(
            &conf,
            None,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(
            notes
                .iter()
                .any(|n| n.contains("keymaster") && n.contains("skip")),
            "{notes:?}"
        );
        assert!(
            notes
                .iter()
                .any(|n| n.contains("encryption") && n.contains("skip")),
            "{notes:?}"
        );
        // only copy survives
        assert_eq!(filters.len(), 1, "notes={notes:?}");
    }

    #[test]
    fn pipeline_crypto_multi_root_secret_conf() {
        // default + named secret; active = named
        let root_a = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="; // bytes(range(32))
        let root_b = "//////////////////////////////////////////8="; // 32 x 0xff
        let conf = SwiftConfig::parse_lenient(
            &format!(
                "[pipeline:main]\n\
                 pipeline = catch_errors gatekeeper healthcheck keymaster encryption copy proxy-server\n\
                 [filter:keymaster]\n\
                 encryption_root_secret = {root_a}\n\
                 encryption_root_secret_rot1 = {root_b}\n\
                 active_root_secret_id = rot1\n\
                 [filter:encryption]\ndisable_encryption = false\n"
            ),
            &[],
            false,
        )
        .unwrap();
        let km = build_keymaster(&conf).expect("multi-root keymaster");
        assert_eq!(km.active_secret_id(), Some("rot1"));
        let keys = km.fetch_keys("a", Some("c"), Some("o"));
        assert_eq!(keys.id["secret_id"], "rot1");
        assert_eq!(km.root_secret_ids().len(), 2);

        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes) = build_configured_filters(
            &conf,
            None,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(notes.iter().any(|n| n == "keymaster enabled"), "{notes:?}");
        assert!(
            notes.iter().any(|n| n.contains("encryption enabled")),
            "{notes:?}"
        );
        // keymaster + decrypter + encrypter + copy
        assert_eq!(filters.len(), 4, "notes={notes:?}");
    }

    #[test]
    fn pipeline_unknown_filter_can_explicitly_use_passthrough() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck totally_fake_filter proxy-server\n\
             [app:proxy-server]\n\
             strict_pipeline = false\n\
             plugin_default = passthrough\n",
            &[],
            false,
        )
        .unwrap();
        assert!(!strict_pipeline_from_conf(&conf));
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes, issues) = build_configured_filters_with_issues(
            &conf,
            None,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            no_endpoints(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(
            notes
                .iter()
                .any(|n| n.contains("totally_fake_filter") && n.contains("NamedPassthrough")),
            "{notes:?}"
        );
        assert_eq!(filters.len(), 1, "passthrough plugin registered");
        // Explicit operator opt-in is a real compatibility decision, not an
        // unresolved build issue.
        assert!(issues.is_empty(), "issues={issues:?}");
        assert!(!strict_pipeline_from_conf(&conf));
    }

    #[test]
    fn pipeline_strict_true_surfaces_fatal_unknown_filter() {
        // Fail-closed defaults make an unknown filter fatal.
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck totally_fake_filter list_endpoints proxy-server\n\
             [app:proxy-server]\n",
            &[],
            false,
        )
        .unwrap();
        assert!(strict_pipeline_from_conf(&conf));
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (_filters, notes, issues) = build_configured_filters_with_issues(
            &conf,
            None,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            no_endpoints(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.filter == "totally_fake_filter"
                    && issue.kind == PipelineBuildIssueKind::UnknownFilter),
            "issues={issues:?}; notes={notes:?}"
        );
        // list_endpoints is now a wired filter (not a fatal residual).
        assert!(
            notes.iter().any(|n| n.contains("list_endpoints enabled")),
            "{notes:?}"
        );
        // Same gate main() uses before process::exit(1).
        assert!(strict_pipeline_rejects(&conf, &issues));
    }

    #[test]
    fn list_endpoints_pipeline_uses_supplied_resolver_and_configured_path() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck list_endpoints proxy-server\n\
             [filter:list_endpoints]\nlist_endpoints_path = /where\n",
            &[],
            false,
        )
        .unwrap();
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let resolver: Arc<dyn swift_middleware::EndpointResolver> =
            Arc::new(swift_middleware::StaticEndpoints(vec![
                "http://10.0.0.1:6200/sda/1/a".to_string(),
            ]));
        let (filters, notes, issues) = build_configured_filters_with_issues(
            &conf,
            None,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            resolver,
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert!(issues.is_empty(), "issues={issues:?}");
        assert!(
            notes.iter().any(|note| note.contains("path_root=/where/")),
            "notes={notes:?}"
        );
        assert_eq!(filters.len(), 1);

        let inner: swift_middleware::NextFn = Arc::new(|_| swift_http::Response::new(503));
        let pipeline = swift_middleware::build_pipeline(filters, inner);
        let mut response = pipeline(swift_http::Request {
            method: "GET".to_string(),
            path: "/where/v2/a".to_string(),
            query_string: String::new(),
            headers: swift_http::HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        });
        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("Content-Type"),
            Some("application/json")
        );
        let value: serde_json::Value =
            serde_json::from_slice(response.body.materialize(u64::MAX).unwrap()).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "endpoints": ["http://10.0.0.1:6200/sda/1/a"],
                "headers": {},
            })
        );
    }

    #[test]
    fn pipeline_strict_rejects_every_known_configured_but_unbuilt_filter() {
        let cases = [
            ("ratelimit", PipelineBuildIssueKind::MissingConfiguration),
            ("tempauth", PipelineBuildIssueKind::MissingConfiguration),
            ("cname_lookup", PipelineBuildIssueKind::MissingConfiguration),
            ("authtoken", PipelineBuildIssueKind::BuildFailure),
            ("keystoneauth", PipelineBuildIssueKind::MissingConfiguration),
            ("s3api", PipelineBuildIssueKind::MissingConfiguration),
            ("s3token", PipelineBuildIssueKind::MissingConfiguration),
            ("keymaster", PipelineBuildIssueKind::BuildFailure),
            ("encrypter", PipelineBuildIssueKind::MissingConfiguration),
            ("decrypter", PipelineBuildIssueKind::MissingConfiguration),
            ("encryption", PipelineBuildIssueKind::MissingConfiguration),
            ("memcache", PipelineBuildIssueKind::NotImplemented),
            ("recon", PipelineBuildIssueKind::NotImplemented),
            ("swob", PipelineBuildIssueKind::NotImplemented),
        ];
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");

        for (filter_name, expected_kind) in cases {
            let conf = SwiftConfig::parse_lenient(
                &format!(
                    "[pipeline:main]\npipeline = catch_errors gatekeeper healthcheck {filter_name} proxy-server\n\
                     [app:proxy-server]\n"
                ),
                &[],
                false,
            )
            .unwrap();
            let (_filters, notes, issues) = build_configured_filters_with_issues(
                &conf,
                None,
                None,
                None,
                no_tempurl_keys(),
                no_sync_keys(),
                no_endpoints(),
                &pols,
                HashPathConfig::new("", "test").unwrap(),
            );
            assert!(
                issues
                    .iter()
                    .any(|issue| { issue.filter == filter_name && issue.kind == expected_kind }),
                "filter={filter_name}; issues={issues:?}; notes={notes:?}"
            );
            assert!(
                strict_pipeline_rejects(&conf, &issues),
                "strict pipeline accepted unresolved filter={filter_name}; issues={issues:?}"
            );
        }
    }

    #[test]
    fn pipeline_non_strict_omits_unimplemented_builtin_without_passthrough() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck memcache recon swob copy proxy-server\n\
             [app:proxy-server]\nstrict_pipeline = false\n",
            &[],
            false,
        )
        .unwrap();
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes, issues) = build_configured_filters_with_issues(
            &conf,
            None,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            no_endpoints(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert_eq!(filters.len(), 1, "only copy may be instantiated: {notes:?}");
        assert_eq!(
            issues
                .iter()
                .filter(|issue| issue.kind == PipelineBuildIssueKind::NotImplemented)
                .count(),
            3,
            "issues={issues:?}"
        );
        assert!(notes.iter().all(|note| !note.contains("NamedPassthrough")));
        assert!(!strict_pipeline_rejects(&conf, &issues));
        let info: serde_json::Value =
            serde_json::from_str(&build_info_json(&conf, &conf, false, false, true)).unwrap();
        for name in ["memcache", "recon", "swob"] {
            assert!(
                info.get(name).is_none(),
                "unimplemented filter {name} must not be advertised: {info}"
            );
        }
    }

    #[test]
    fn pipeline_default_and_repository_live_pipeline_have_no_build_issues() {
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let default_conf = SwiftConfig::parse_lenient("[app:proxy-server]\n", &[], false).unwrap();
        let (default_filters, default_notes, default_issues) = build_configured_filters_with_issues(
            &default_conf,
            None,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            no_endpoints(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert_eq!(default_filters.len(), 3, "notes={default_notes:?}");
        assert!(default_issues.is_empty(), "issues={default_issues:?}");
        assert!(!strict_pipeline_rejects(&default_conf, &default_issues));

        // Keep this in lock-step with swift-rust/tools/py-saio-setup.sh.
        let live_conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck proxy-logging cache listing_formats tempauth copy slo dlo versioned_writes symlink proxy-server\n\
             [app:proxy-server]\n\
             [filter:cache]\nmemcache_servers = 127.0.0.1:11211\n\
             [filter:tempauth]\nuser_test_tester = secret .admin\n",
            &[],
            false,
        )
        .unwrap();
        let tempauth = build_tempauth(&live_conf, &live_conf, "http://127.0.0.1:8081");
        let (live_filters, live_notes, live_issues) = build_configured_filters_with_issues(
            &live_conf,
            tempauth,
            None,
            None,
            no_tempurl_keys(),
            no_sync_keys(),
            no_endpoints(),
            &pols,
            HashPathConfig::new("", "test").unwrap(),
        );
        assert_eq!(live_filters.len(), 9, "notes={live_notes:?}");
        assert!(live_issues.is_empty(), "issues={live_issues:?}");
        assert!(!strict_pipeline_rejects(&live_conf, &live_issues));
    }

    #[test]
    fn process_workers_conf_parses() {
        let conf =
            SwiftConfig::parse_lenient("[app:proxy-server]\nprocess_workers = 4\n", &[], false)
                .unwrap();
        assert_eq!(process_workers_from_conf(&conf), 4);
        let conf2 = SwiftConfig::parse_lenient(
            "[app:proxy-server]\nworker_model = process\nworkers = 3\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(process_workers_from_conf(&conf2), 3);
        let conf3 =
            SwiftConfig::parse_lenient("[app:proxy-server]\nworkers = 8\n", &[], false).unwrap();
        // thread model default: process_workers stays 1
        assert_eq!(process_workers_from_conf(&conf3), 1);
    }

    #[test]
    fn pipeline_strict_conf_parses_true() {
        for raw in ["true", "TRUE", "yes", "on", "1", "t", "y"] {
            let conf = SwiftConfig::parse_lenient(
                &format!("[app:proxy-server]\nstrict_pipeline = {raw}\n"),
                &[],
                false,
            )
            .unwrap();
            assert!(
                strict_pipeline_from_conf(&conf),
                "raw={raw} should enable strict_pipeline"
            );
        }
        for raw in ["false", "0", "no", "off"] {
            let body = format!("[app:proxy-server]\nstrict_pipeline = {raw}\n");
            let conf = SwiftConfig::parse_lenient(&body, &[], false).unwrap();
            assert!(
                !strict_pipeline_from_conf(&conf),
                "raw={raw:?} should explicitly disable strict mode"
            );
        }
        let default_conf = SwiftConfig::parse_lenient("[app:proxy-server]\n", &[], false).unwrap();
        assert!(strict_pipeline_from_conf(&default_conf));
        // DEFAULT section fallback
        let conf = SwiftConfig::parse_lenient(
            "[DEFAULT]\nstrict_pipeline = yes\n[app:proxy-server]\n",
            &[],
            false,
        )
        .unwrap();
        assert!(strict_pipeline_from_conf(&conf));
    }

    #[test]
    fn allow_account_management_defaults_false_and_can_enable() {
        let off = proxy_config_from_conf(
            &SwiftConfig::parse_lenient("[app:proxy-server]\n", &[], false).unwrap(),
            true,
        );
        assert!(!off.allow_account_management);
        let on = proxy_config_from_conf(
            &SwiftConfig::parse_lenient(
                "[app:proxy-server]\nallow_account_management = true\n",
                &[],
                false,
            )
            .unwrap(),
            true,
        );
        assert!(on.allow_account_management);
    }

    #[test]
    fn startup_and_reload_share_one_build_path() {
        let dir = std::env::temp_dir().join(format!("swift-proxy-rebuild-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["account", "container", "object", "object-1"] {
            ring_data(3)
                .save_v1(&dir.join(format!("{name}.ring.gz")))
                .unwrap();
        }
        let builder = AppBuilder {
            swift_dir: dir.to_string_lossy().into_owned(),
            hash_config: HashPathConfig::new("", "test").unwrap(),
            policies: policies(
                "[storage-policy:0]\nname = gold\ndefault = yes\n\
                 [storage-policy:1]\nname = silver\n",
            ),
            ec_policies: std::collections::HashMap::new(),
            policy_names: [("gold".to_string(), 0i64), ("silver".to_string(), 1)].into(),
            policy_index_names: [(0i64, "gold".to_string())].into(),
            info_json: "{}".to_string(),
            config: ProxyConfig::default(),
            memcache_servers: String::new(),
        };
        // The reload thread watches exactly the rings the build loads.
        let paths = builder.ring_paths();
        assert_eq!(paths.len(), 4);
        assert!(paths.iter().all(|p| p.exists()), "{paths:?}");
        // Build twice from the same inputs: the reload thread constructs the
        // same app startup did.
        let first = builder.build().expect("first build");
        let second = builder.build().expect("second build");
        assert_eq!(first.object_rings.len(), second.object_rings.len());
        assert!(second.object_ring_for(1).is_some());
        assert_eq!(second.policy_name_to_index.get("gold"), Some(&0));
        assert_eq!(
            second.policy_index_to_name.get(&0),
            Some(&"gold".to_string())
        );
        assert_eq!(second.info_json, "{}");
        assert_eq!(first.config.node_timeout, second.config.node_timeout);
        std::fs::remove_dir_all(&dir).ok();
    }
}
