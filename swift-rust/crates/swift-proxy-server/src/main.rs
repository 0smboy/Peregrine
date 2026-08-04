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

    // Build tempauth first: whether auth is in the pipeline decides whether the
    // proxy enforces container ACLs (auth_enabled) — so a request path that
    // forgets to authorize cannot silently become world-accessible.
    let tempauth = build_tempauth(
        &conf,
        &swift_conf,
        &get("storage_url", "http://127.0.0.1:8080"),
    );
    let config = proxy_config_from_conf(&conf, tempauth.is_some());
    let info_json = build_info_json(&swift_conf, config.account_autocreate, config.auth_enabled);

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
    };
    let app = builder.build().unwrap_or_else(|e| {
        logger.error(&format!("could not load rings: {e}"));
        std::process::exit(1);
    });
    // The handler reads the current app on every request; the reload thread
    // swaps in a rebuilt one when a ring file changes on disk.
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

    // Pipeline below the always-on front matter, in the standard conf order
    // `... ratelimit <auth> copy slo dlo proxy-server`: ratelimit throttles
    // before authentication; tempauth (authenticate + stamp the group list)
    // then server-side copy, so copy's source-GET / dest-PUT subrequests are
    // ACL-checked.
    let mut filters: Vec<Arc<dyn swift_middleware::Middleware>> = Vec::new();
    if let Some(ratelimit) = build_ratelimit(&conf) {
        logger.info("ratelimit enabled");
        filters.push(Arc::new(ratelimit));
    }
    if let Some(auth) = tempauth {
        logger.info("tempauth enabled");
        filters.push(Arc::new(auth));
    }
    filters.push(Arc::new(swift_middleware::Copy::new()));
    // Large objects: reassemble SLO (X-Static-Large-Object) and DLO
    // (X-Object-Manifest) manifests on GET/HEAD. Below copy so their segment
    // subrequests are ACL-checked (they carry the authenticated identity).
    filters.push(Arc::new(swift_middleware::Slo::new()));
    filters.push(Arc::new(swift_middleware::DynamicLargeObject::new()));
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
        Ok(ProxyApp::with_ec_policies(
            account_ring,
            container_ring,
            object_ring,
            object_rings,
            self.ec_policies.clone(),
            self.config.clone(),
        )
        .with_policy_names(self.policy_names.clone())
        .with_policy_index_names(self.policy_index_names.clone())
        .with_info_json(self.info_json.clone()))
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
/// actually serves: the core `swift` constraints + storage policies, and the
/// large-object (`slo`/`dlo`) and `tempauth` middleware that are wired into the
/// pipeline. Unimplemented features (bulk, tempurl, formpost, quotas, staticweb,
/// symlink, versioned_writes, account ACLs, …) are deliberately OMITTED so the
/// functional suite skips them instead of running them against missing code.
fn build_info_json(
    swift_conf: &SwiftConfig,
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
        // NOTE: account_acls is intentionally absent — account-level ACLs
        // (X-Account-Access-Control) are not implemented, so those tests skip.
        info["tempauth"] = serde_json::json!({});
    }
    serde_json::to_string(&info).unwrap_or_default()
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
