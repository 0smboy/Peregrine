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

use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::otlp::{self, AttrValue, TraceExporter, TraceSpan};
use swift_core::statsd::StatsdClient;
use swift_core::storage_policy::{parse_storage_policies, StoragePolicyCollection};
use swift_proxy_server::{EcPolicyParams, ProxyApp, ProxyConfig};
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

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| {
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
        hash_config,
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
    let listener = std::net::TcpListener::bind(&bind).unwrap_or_else(|e| {
        logger.error(&format!("could not bind {bind}: {e}"));
        std::process::exit(1);
    });
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
    // default order. Unknown names are skipped (logged), never a startup
    // hard-fail — so a Python-shaped pipeline line can be pasted without
    // claiming full Paste parity.
    let key_provider: Arc<dyn swift_middleware::KeyProvider> =
        Arc::new(ProxyTempUrlKeys::new(Arc::clone(&app)));
    let (filters, notes) = build_configured_filters(
        &conf,
        tempauth,
        keystoneauth,
        Some(Arc::clone(&logger)),
        key_provider,
        &policies_for_filters,
    );
    for note in &notes {
        logger.info(note);
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
fn build_ratelimit(conf: &SwiftConfig) -> Option<swift_middleware::RateLimit> {
    conf.get("filter:ratelimit", "use").ok().flatten()?;
    let options: std::collections::HashMap<String, String> =
        conf.items("filter:ratelimit").ok()?.into_iter().collect();
    Some(swift_middleware::RateLimit::from_conf(
        &options,
        Box::new(swift_middleware::SystemClock::new()),
    ))
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

/// Names handled inside [`serve_with_filters_and_config`] (or the app itself).
/// Dropped when reading `pipeline =` so a Python-shaped line can be reused.
const ALWAYS_ON_OR_APP: &[&str] = &[
    "catch_errors",
    "gatekeeper",
    "healthcheck",
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

/// Build `formpost` around the same Temp-URL key provider as tempurl.
fn build_formpost(
    conf: &SwiftConfig,
    key_provider: Arc<dyn swift_middleware::KeyProvider>,
) -> swift_middleware::FormPost {
    let mut fp = swift_middleware::FormPost::new(key_provider);
    if let Some(allowed_digests) = conf
        .get("filter:formpost", "allowed_digests")
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
        fp.allowed_digests = allowed_digests;
    }
    fp
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
    swift_middleware::VersionedWrites::from_conf(allow.as_deref())
}

fn build_symlink(conf: &SwiftConfig) -> swift_middleware::Symlink {
    let symloop = conf
        .get("filter:symlink", "symloop_max")
        .ok()
        .flatten();
    swift_middleware::Symlink::from_conf(symloop.as_deref())
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
        conf.get(section, "storage_domain").ok().flatten().as_deref(),
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
    for method in ["GET", "HEAD", "PUT", "POST", "DELETE", "UPDATE", "REPLICATE"] {
        let key = format!("{}_requests_per_device_per_second", method.to_ascii_lowercase());
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
/// implemented configurable filters in that order. Returns the filter list
/// plus human-readable notes (enabled / skipped) for the startup log.
///
/// P0–P1b wires: cache/listing_formats/proxy_logging/bulk/tempurl plus
/// formpost/staticweb/quotas/symlink/versioned_writes and the smaller L2
/// filters. P3-s3 wires `s3api` (ON-BY-CONFIG; not on default pipeline).
/// Unknown names still skip with a note — not a hard fail.
fn build_configured_filters(
    conf: &SwiftConfig,
    tempauth: Option<swift_middleware::TempAuth>,
    keystoneauth: Option<swift_middleware::KeystoneAuth>,
    access_logger: Option<Arc<Logger>>,
    key_provider: Arc<dyn swift_middleware::KeyProvider>,
    policies: &StoragePolicyCollection,
) -> (Vec<Arc<dyn swift_middleware::Middleware>>, Vec<String>) {
    let mut notes = Vec::new();
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

    for name in &names {
        match name.as_str() {
            "ratelimit" => {
                if let Some(rl) = build_ratelimit(conf) {
                    notes.push("ratelimit enabled".into());
                    filters.push(Arc::new(rl));
                } else if pipeline_line.is_some() {
                    notes.push(
                        "pipeline: ratelimit listed but [filter:ratelimit] absent; skip".into(),
                    );
                }
            }
            "tempauth" => {
                if let Some(auth) = tempauth.take() {
                    notes.push("tempauth enabled".into());
                    filters.push(Arc::new(auth));
                } else if pipeline_line.is_some() {
                    notes.push(
                        "pipeline: tempauth listed but no user_* credentials; skip".into(),
                    );
                }
            }
            "copy" => {
                notes.push("copy enabled".into());
                filters.push(Arc::new(swift_middleware::Copy::new()));
            }
            "slo" => {
                notes.push("slo enabled".into());
                filters.push(Arc::new(swift_middleware::Slo::new()));
            }
            "dlo" => {
                notes.push("dlo enabled".into());
                filters.push(Arc::new(swift_middleware::DynamicLargeObject::new()));
            }
            "listing_formats" | "listing-formats" => {
                notes.push("listing_formats enabled".into());
                filters.push(Arc::new(swift_middleware::ListingFormats::default()));
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
                    notes.push(format!("pipeline: cache listed but failed to build ({e}); skip"));
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
            "formpost" => {
                let fp = build_formpost(conf, Arc::clone(&key_provider));
                notes.push("formpost enabled".into());
                filters.push(Arc::new(fp));
            }
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
            "symlink" => {
                let sl = build_symlink(conf);
                notes.push(format!("symlink enabled (symloop_max={})", sl.symloop_max));
                filters.push(Arc::new(sl));
            }
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
                }
            },
            "s3api" => match build_s3api(conf) {
                Some(api) => {
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
                None => {
                    notes.push(
                        "pipeline: s3api listed but no TempAuth user_* credentials; skip".into(),
                    );
                }
            },
            "s3token" => {
                // Wave 3 hook: exchange S3 creds → Keystone token headers.
                // Requires [filter:s3token] auth_uri (or auth_url). Without it,
                // MapS3TokenClient is empty → passthrough (honest ON-BY-CONFIG).
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
                        "pipeline: s3token listed but no auth_uri; wiring passthrough Map client"
                            .into(),
                    );
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
            // Known but not-wired this wave (ops / residual).
            "container_sync"
            | "container-sync"
            | "list_endpoints"
            | "list-endpoints" => {
                notes.push(format!(
                    "pipeline: filter '{name}' not implemented in proxy wiring; skip"
                ));
            }
            other => {
                notes.push(format!(
                    "pipeline: unknown filter '{other}'; skip (not a hard fail)"
                ));
            }
        }
    }

    (filters, notes)
}

/// Ordered implemented filter names that [`build_configured_filters`] would
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
            "ratelimit" if build_ratelimit(conf).is_some() => out.push("ratelimit"),
            "tempauth" if has_tempauth => out.push("tempauth"),
            "copy" => out.push("copy"),
            "slo" => out.push("slo"),
            "dlo" => out.push("dlo"),
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
            "s3api" if build_s3api(conf).is_some() => out.push("s3api"),
            _ => {}
        }
    }
    out
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
    tempauth_on: bool,
) -> String {
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
            "version": "2.35.0",
            // NOTE: strict_cors_mode deliberately absent — CORS is not
            // implemented, so cors tests skip ("cors mode is unknown").
            "account_autocreate": account_autocreate,
            "allow_account_management": false,
            "max_file_size": c.max_file_size,
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
        "slo": {
            "max_manifest_segments": 1000,
            "max_manifest_size": 8388608,
            "min_segment_size": 1,
            "max_get_time": 86400,
        },
        "dlo": {},
    });
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
        let no_keys: Arc<dyn swift_middleware::KeyProvider> = Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_, _| Vec::new()),
        );
        let tempurl = build_tempurl(conf, no_keys);
        let mut allowed_digests = tempurl.allowed_digests;
        allowed_digests.sort();
        info["tempurl"] = serde_json::json!({
            "methods": tempurl.methods,
            "allowed_digests": allowed_digests,
        });
    }
    if configured_pipeline_has(conf, "formpost") {
        let no_keys: Arc<dyn swift_middleware::KeyProvider> = Arc::new(
            swift_middleware::ClosureKeyProvider::new(|_, _| Vec::new()),
        );
        let fp = build_formpost(conf, no_keys);
        let mut allowed_digests = fp.allowed_digests;
        allowed_digests.sort();
        info["formpost"] = serde_json::json!({
            "allowed_digests": allowed_digests,
        });
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
        let sl = build_symlink(conf);
        info["symlink"] = serde_json::json!({
            "symloop_max": sl.symloop_max,
            "static_links": true,
        });
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
    if configured_pipeline_has(conf, "name_check")
        || configured_pipeline_has(conf, "name-check")
    {
        let nc = build_name_check(conf);
        info["name_check"] = serde_json::json!({
            "forbidden_chars": nc.forbidden_chars.iter().collect::<String>(),
            "maximum_length": nc.maximum_length,
            "forbidden_regexp": nc.forbidden_regexp,
        });
    }
    if configured_pipeline_has(conf, "etag_quoter")
        || configured_pipeline_has(conf, "etag-quoter")
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
    if configured_pipeline_has(conf, "read_only")
        || configured_pipeline_has(conf, "read-only")
    {
        let ro = build_read_only(conf);
        if ro.read_only {
            info["read_only"] = serde_json::json!({});
        }
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

    let validator = swift_middleware::HttpTokenValidator::new(auth_url, username, password, project)
        .with_domains(user_domain, project_domain)
        .with_timeout(std::time::Duration::from_secs_f64(timeout_secs));
    Ok(swift_middleware::AuthToken::new(std::sync::Arc::new(validator))
        .with_delay(delay)
        .with_www_authenticate_uri(www))
}

fn s3token_auth_uri(conf: &SwiftConfig) -> Option<String> {
    conf.get("filter:s3token", "auth_uri")
        .ok()
        .flatten()
        .or_else(|| conf.get("filter:s3token", "auth_url").ok().flatten())
        .filter(|s| !s.trim().is_empty())
}

/// Build the P3-s3 `s3api` filter from TempAuth `user_*` records plus optional
/// `[filter:s3api]` knobs. Credentials use access key `account:user` and the
/// TempAuth secret (Swift/tempauth + s3api convention). Returns `None` when
/// there are no users to map. Does **not** advertise on Swift v1 `/info`.
///
/// When `[filter:s3token] auth_uri` is set, attaches [`HttpS3TokenClient`] so
/// unknown EC2 access keys defer to Keystone `/v3/s3tokens` with a real
/// base64 string-to-sign (instead of immediate `InvalidAccessKeyId`).
fn build_s3api(conf: &SwiftConfig) -> Option<swift_s3api::S3Api> {
    let items = conf.items("filter:tempauth").ok()?;
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
        users.push((account.to_string(), user.to_string(), secret.to_string(), groups));
    }
    if users.is_empty() {
        return None;
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
    let storage_domains = conf
        .get("filter:s3api", "storage_domains")
        .ok()
        .flatten()
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let s3_reseller = conf
        .get("filter:s3token", "reseller_prefix")
        .ok()
        .flatten()
        .unwrap_or_else(|| reseller.clone());

    let mut api = swift_s3api::S3Api::new(creds)
        .with_location(location)
        .with_dns_compliant(dns)
        .with_storage_domains(storage_domains)
        .with_reseller_prefix(s3_reseller);
    // EC2 deferral: inline /v3/s3tokens on s3api (does not wait for s3token filter).
    if let Some(uri) = s3token_auth_uri(conf) {
        api = api.with_s3token_client(std::sync::Arc::new(
            swift_middleware::HttpS3TokenClient::new(uri),
        ));
    }
    Some(api)
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
        assert!(!config.auth_enabled);
        // garbage / missing recheck values keep the Python default of 60
        assert_eq!(config.recheck_container_existence, 60.0);
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
    fn ratelimit_filter_is_built_only_when_configured() {
        let conf = SwiftConfig::parse_lenient("[app:proxy-server]\n", &[], false).unwrap();
        assert!(build_ratelimit(&conf).is_none());

        let conf = SwiftConfig::parse_lenient(
            "[filter:ratelimit]\nuse = egg:swift#ratelimit\n\
             account_ratelimit = 5\nmax_sleep_time_seconds = 30\n",
            &[],
            false,
        )
        .unwrap();
        let rl = build_ratelimit(&conf).expect("ratelimit section builds the filter");
        assert_eq!(rl.account_ratelimit, 5.0);
        assert_eq!(rl.max_sleep_time_seconds, 30.0);
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
        let (filters, notes) =
            build_configured_filters(&conf, ta, None, None, no_tempurl_keys(), &pols);
        assert!(notes.iter().any(|n| n.contains("bulk enabled")), "{notes:?}");
        assert!(
            notes.iter().any(|n| n == "tempurl enabled"),
            "{notes:?}"
        );
        assert_eq!(filters.len(), 10, "notes={notes:?}");

        let info = build_info_json(&conf, &conf, true, true);
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
        let (filters, notes) =
            build_configured_filters(&conf, ta, None, None, no_tempurl_keys(), &pols);
        assert!(notes.iter().any(|n| n == "formpost enabled"), "{notes:?}");
        assert!(notes.iter().any(|n| n == "staticweb enabled"), "{notes:?}");
        assert!(
            notes.iter().any(|n| n.contains("versioned_writes enabled")),
            "{notes:?}"
        );
        assert_eq!(filters.len(), 11, "notes={notes:?}");

        let info = build_info_json(&conf, &conf, true, true);
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
        let (filters, notes) =
            build_configured_filters(&conf, ta, None, None, no_tempurl_keys(), &pols);
        assert!(notes.iter().any(|n| n.contains("s3api enabled")), "{notes:?}");
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
        let info = build_info_json(&conf, &conf, true, true);
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
        let (_filters, notes) =
            build_configured_filters(&conf, ta, None, None, no_tempurl_keys(), &pols);
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
        let api = build_s3api(&conf).expect("s3api");
        assert!(api.s3token_client.is_some());
    }

    #[test]
    fn pipeline_unknown_filter_still_skips() {
        let conf = SwiftConfig::parse_lenient(
            "[pipeline:main]\n\
             pipeline = catch_errors gatekeeper healthcheck tempauth not_a_real_filter copy proxy-server\n\
             [filter:tempauth]\nuser_test_tester = secret .admin\n",
            &[],
            false,
        )
        .unwrap();
        let ta = build_tempauth(&conf, &conf, "http://127.0.0.1:8081");
        let pols = policies("[swift-hash]\nswift_hash_path_suffix = test\n");
        let (filters, notes) =
            build_configured_filters(&conf, ta, None, None, no_tempurl_keys(), &pols);
        assert_eq!(filters.len(), 2);
        assert!(notes
            .iter()
            .any(|n| n.contains("not_a_real_filter") && n.contains("skip")));
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
        let (filters, notes) =
            build_configured_filters(&conf, ta, ka, None, no_tempurl_keys(), &pols);
        assert!(
            notes.iter().any(|n| n.contains("authtoken enabled")),
            "{notes:?}"
        );
        assert!(
            notes.iter().any(|n| n.contains("keystoneauth enabled")),
            "{notes:?}"
        );
        assert_eq!(filters.len(), 4, "notes={notes:?}");

        let info = build_info_json(&conf, &conf, true, true);
        let v: serde_json::Value = serde_json::from_str(&info).unwrap();
        assert_eq!(v["tempauth"]["account_acls"], true);
        assert!(v.get("keystoneauth").is_some(), "{v}");
        assert_eq!(v["keystoneauth"]["reseller_prefix"][0], "AUTH_");
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
