//! Native Monitor surface.
//!
//! The console queries the metrics and log backends **server-side** and returns
//! neutral JSON. The browser only ever talks to `/monitor/api/*` on this origin
//! and never learns what powers the dashboards — no third-party product names,
//! backend URLs, query language, or configuration reach the client. This is the
//! production requirement: users must not be able to tell what the monitor is
//! built on. Only a curated set of dashboards is exposed; there is no datasource
//! picker, no explore, no settings.

use crate::session;
use crate::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ------------------------------------------------------------- panel registry

#[derive(Clone, Copy, PartialEq)]
enum Src {
    /// instant scalar/vector from the metrics backend
    Instant,
    /// range matrix from the metrics backend
    Range,
    /// range matrix (metric query) from the logs backend
    LogRange,
    /// raw log lines from the logs backend
    Logs,
    /// per-node × per-service health grid (probed over ssh, not the TSDB)
    SvcGrid,
}

#[derive(Clone, Copy)]
enum Unit {
    ReqS,
    PerS,
    Sec,
    Ratio,
    Pct,
    BytesS,
    Num,
}

impl Unit {
    fn tag(self) -> &'static str {
        match self {
            Unit::ReqS => "reqs",
            Unit::PerS => "pers",
            Unit::Sec => "sec",
            Unit::Ratio => "ratio",
            Unit::Pct => "pct",
            Unit::BytesS => "bytess",
            Unit::Num => "num",
        }
    }
}

/// One drawn tile. `series` pairs a series-name spec with a query; a spec
/// beginning with `@` splits the returned matrix by that label (one line per
/// label value; `@a,b` joins several labels), anything else is a fixed
/// single-series name.
///
/// `title` is an i18n key, not display text: the catalogue is data the browser
/// renders verbatim, so it has to leave the server already in the reader's
/// language.
///
/// A query may contain `{nf}` inside a label selector: with no node filter it
/// vanishes, with `?node=` it becomes a label match confining the query to
/// that node — which is what makes every panel openable per node.
struct Panel {
    id: &'static str,
    title: &'static str,
    src: Src,
    unit: Unit,
    /// stat tiles and small charts take one column; wide charts take two.
    wide: bool,
    series: &'static [(&'static str, &'static str)],
    /// stat tiles drill into this series panel when clicked.
    drill: &'static str,
}

struct Dash {
    id: &'static str,
    title: &'static str,
    panels: &'static [&'static str],
}

// `{iv}` is replaced with a range-appropriate rate interval, `{nf}` with the
// optional node filter, before querying.
const PANELS: &[Panel] = &[
    // ---- cluster overview ----
    // "Nodes up" means hosts with a live node_exporter scrape — not Swift units.
    Panel { id: "nodes_up", title: "mon.p.nodes_up", src: Src::Instant, unit: Unit::Num, wide: false, drill: "nodes_up_range",
        series: &[("", "count(up{job=\"node\"} == 1) OR on() vector(0)")] },
    Panel { id: "reqs", title: "mon.p.reqs", src: Src::Instant, unit: Unit::ReqS, wide: false, drill: "reqs_method",
        series: &[("", "sum(rate(swift_request_total{service=\"proxy-server\"}[{iv}]))")] },
    Panel { id: "err5xx", title: "mon.p.err5xx", src: Src::Instant, unit: Unit::Ratio, wide: false, drill: "err_ratio",
        series: &[("", "(sum(rate(swift_request_total{service=\"proxy-server\",status=~\"5..\"}[{iv}])) or on() vector(0)) / clamp_min(sum(rate(swift_request_total{service=\"proxy-server\"}[{iv}])), 0.001)")] },
    Panel { id: "p99", title: "mon.p.p99", src: Src::Instant, unit: Unit::Sec, wide: false, drill: "latency",
        series: &[("", "(sum(rate(swift_request_duration_seconds_sum{service=\"proxy-server\"}[{iv}])) or on() vector(0)) / clamp_min(sum(rate(swift_request_duration_seconds_count{service=\"proxy-server\"}[{iv}])), 0.001)")] },
    Panel { id: "reqs_method", title: "mon.p.reqs_method", src: Src::Range, unit: Unit::ReqS, wide: true, drill: "",
        series: &[("@method", "sum by (method) (rate(swift_request_total{service=\"proxy-server\"{nf}}[{iv}]))")] },
    Panel { id: "reqs_status", title: "mon.p.reqs_status", src: Src::Range, unit: Unit::ReqS, wide: true, drill: "",
        series: &[("@class", "sum by (class) (label_replace(rate(swift_request_total{service=\"proxy-server\"{nf}}[{iv}]), \"class\", \"$1xx\", \"status\", \"(.)..\"))")] },
    Panel { id: "latency", title: "mon.p.latency", src: Src::Range, unit: Unit::Sec, wide: true, drill: "",
        series: &[
            ("avg", "(sum(rate(swift_request_duration_seconds_sum{service=\"proxy-server\"{nf}}[{iv}])) or on() vector(0)) / clamp_min(sum(rate(swift_request_duration_seconds_count{service=\"proxy-server\"{nf}}[{iv}])), 0.001)"),
        ] },
    Panel { id: "err_ratio", title: "mon.p.err_ratio", src: Src::Range, unit: Unit::Ratio, wide: true, drill: "",
        series: &[
            ("5xx", "(sum(rate(swift_request_total{service=\"proxy-server\",status=~\"5..\"{nf}}[{iv}])) or on() vector(0)) / clamp_min(sum(rate(swift_request_total{service=\"proxy-server\"{nf}}[{iv}])), 0.001)"),
            ("4xx", "(sum(rate(swift_request_total{service=\"proxy-server\",status=~\"4..\"{nf}}[{iv}])) or on() vector(0)) / clamp_min(sum(rate(swift_request_total{service=\"proxy-server\"{nf}}[{iv}])), 0.001)"),
        ] },
    // Hidden drill target: per-node exporter liveness as a 0/1 step line.
    Panel { id: "nodes_up_range", title: "mon.p.nodes_up", src: Src::Range, unit: Unit::Num, wide: true, drill: "",
        series: &[("@instance", "up{job=\"node\"{nf}}")] },

    // ---- backend services ----
    Panel { id: "backend_reqs", title: "mon.p.backend_reqs", src: Src::Range, unit: Unit::ReqS, wide: true, drill: "",
        series: &[("@service", "sum by (service) (rate(swift_request_total{service!=\"proxy-server\"{nf}}[{iv}]))")] },
    Panel { id: "backend_p99", title: "mon.p.backend_p99", src: Src::Range, unit: Unit::Sec, wide: true, drill: "",
        series: &[("@service", "(sum by (service) (rate(swift_request_duration_seconds_sum{job=~\".+\"{nf}}[{iv}])) or on() vector(0)) / clamp_min(sum by (service) (rate(swift_request_duration_seconds_count{job=~\".+\"{nf}}[{iv}])), 0.001)")] },
    Panel { id: "backend_err", title: "mon.p.backend_err", src: Src::Range, unit: Unit::PerS, wide: true, drill: "",
        series: &[("@service", "sum by (service) (rate(swift_request_total{status=~\"5..\"{nf}}[{iv}])) or on() vector(0)")] },
    Panel { id: "backend_status", title: "mon.p.backend_status", src: Src::Range, unit: Unit::ReqS, wide: true, drill: "",
        series: &[("@class", "sum by (class) (label_replace(rate(swift_request_total{service!=\"proxy-server\"{nf}}[{iv}]), \"class\", \"$1xx\", \"status\", \"(.)..\"))")] },

    // ---- storage nodes ----
    Panel { id: "fs_used", title: "mon.p.fs_used", src: Src::Range, unit: Unit::Pct, wide: true, drill: "",
        series: &[("@instance", "max by (instance) (1 - node_filesystem_avail_bytes{job=\"node\",fstype!~\"tmpfs|overlay|squashfs|iso9660\"{nf}} / node_filesystem_size_bytes{job=\"node\",fstype!~\"tmpfs|overlay|squashfs|iso9660\"{nf}})")] },
    Panel { id: "cpu", title: "mon.p.cpu", src: Src::Range, unit: Unit::Pct, wide: true, drill: "",
        series: &[("@instance", "1 - avg by (instance) (rate(node_cpu_seconds_total{job=\"node\",mode=\"idle\"{nf}}[{iv}]))")] },
    Panel { id: "mem", title: "mon.p.mem", src: Src::Range, unit: Unit::Pct, wide: true, drill: "",
        series: &[("@instance", "1 - (node_memory_MemAvailable_bytes{job=\"node\"{nf}} / node_memory_MemTotal_bytes{job=\"node\"{nf}})")] },
    // Network panels select by the semantic `plane` label applied at scrape
    // time, not by interface name: NIC naming differs per host and per
    // environment, so hard-coded device names silently render empty panels.
    Panel { id: "net_storage", title: "mon.p.net_storage", src: Src::Range, unit: Unit::BytesS, wide: true, drill: "",
        series: &[
            ("rx", "sum(rate(node_network_receive_bytes_total{job=\"node\",plane=\"storage\"{nf}}[{iv}]))"),
            ("tx", "sum(rate(node_network_transmit_bytes_total{job=\"node\",plane=\"storage\"{nf}}[{iv}]))"),
        ] },
    Panel { id: "net_repl", title: "mon.p.net_repl", src: Src::Range, unit: Unit::BytesS, wide: true, drill: "",
        series: &[
            ("rx", "sum(rate(node_network_receive_bytes_total{job=\"node\",plane=\"replication\"{nf}}[{iv}]))"),
            ("tx", "sum(rate(node_network_transmit_bytes_total{job=\"node\",plane=\"replication\"{nf}}[{iv}]))"),
        ] },
    Panel { id: "net_public", title: "mon.p.net_public", src: Src::Range, unit: Unit::BytesS, wide: true, drill: "",
        series: &[
            ("rx", "sum(rate(node_network_receive_bytes_total{job=\"node\",plane=\"public\"{nf}}[{iv}]))"),
            ("tx", "sum(rate(node_network_transmit_bytes_total{job=\"node\",plane=\"public\"{nf}}[{iv}]))"),
        ] },
    Panel { id: "load", title: "mon.p.load", src: Src::Range, unit: Unit::Num, wide: true, drill: "",
        series: &[("@instance", "node_load1{job=\"node\"{nf}}")] },

    // ---- storage devices ----
    Panel { id: "dev_used", title: "mon.p.dev_used", src: Src::Range, unit: Unit::Pct, wide: true, drill: "",
        series: &[("@instance,mountpoint", "1 - node_filesystem_avail_bytes{job=\"node\",mountpoint=~\"/srv/node/.+\"{nf}} / node_filesystem_size_bytes{job=\"node\",mountpoint=~\"/srv/node/.+\"{nf}}")] },
    Panel { id: "dev_inodes", title: "mon.p.dev_inodes", src: Src::Range, unit: Unit::Pct, wide: true, drill: "",
        series: &[("@instance,mountpoint", "1 - node_filesystem_files_free{job=\"node\",mountpoint=~\"/srv/node/.+\"{nf}} / node_filesystem_files{job=\"node\",mountpoint=~\"/srv/node/.+\"{nf}}")] },
    Panel { id: "disk_read", title: "mon.p.disk_read", src: Src::Range, unit: Unit::BytesS, wide: true, drill: "",
        series: &[("@instance", "sum by (instance) (rate(node_disk_read_bytes_total{job=\"node\"{nf}}[{iv}]))")] },
    Panel { id: "disk_write", title: "mon.p.disk_write", src: Src::Range, unit: Unit::BytesS, wide: true, drill: "",
        series: &[("@instance", "sum by (instance) (rate(node_disk_written_bytes_total{job=\"node\"{nf}}[{iv}]))")] },
    Panel { id: "disk_iops", title: "mon.p.disk_iops", src: Src::Range, unit: Unit::PerS, wide: true, drill: "",
        series: &[("@instance", "sum by (instance) (rate(node_disk_reads_completed_total{job=\"node\"{nf}}[{iv}]) + rate(node_disk_writes_completed_total{job=\"node\"{nf}}[{iv}]))")] },
    Panel { id: "disk_util", title: "mon.p.disk_util", src: Src::Range, unit: Unit::Pct, wide: true, drill: "",
        series: &[("@instance", "max by (instance) (rate(node_disk_io_time_seconds_total{job=\"node\"{nf}}[{iv}]))")] },

    // ---- replication ----
    Panel { id: "repl_kind", title: "mon.p.repl_kind", src: Src::Range, unit: Unit::PerS, wide: true, drill: "",
        series: &[("@kind", "sum by (kind) (rate(swift_replicator_total{job=~\".+\"{nf}}[{iv}]))")] },
    Panel { id: "repl_sf", title: "mon.p.repl_sf", src: Src::Range, unit: Unit::PerS, wide: true, drill: "",
        series: &[("@kind", "sum by (kind) (rate(swift_replicator_total{kind=~\"successes|failures\"{nf}}[{iv}]))")] },
    Panel { id: "repl_fail_node", title: "mon.p.repl_fail_node", src: Src::Range, unit: Unit::PerS, wide: true, drill: "",
        series: &[("@instance", "sum by (instance) (rate(swift_replicator_total{kind=\"failures\"{nf}}[{iv}]))")] },
    Panel { id: "repl_node", title: "mon.p.repl_node", src: Src::Range, unit: Unit::PerS, wide: true, drill: "",
        series: &[("@instance", "sum by (instance) (rate(swift_replicator_total{job=~\".+\"{nf}}[{iv}]))")] },

    // ---- services ----
    Panel { id: "svc_grid", title: "mon.p.svc_grid", src: Src::SvcGrid, unit: Unit::Num, wide: true, drill: "",
        series: &[] },
    Panel { id: "svc_events", title: "mon.p.svc_events", src: Src::LogRange, unit: Unit::PerS, wide: true, drill: "",
        series: &[("@unit", "sum by (unit) (count_over_time({unit=~\"swift-.+\"{nf}} |~ `(Started|Stopped|Starting|Failed)` [{iv}]))")] },

    // ---- logs ----
    Panel { id: "log_vol", title: "mon.p.log_vol", src: Src::LogRange, unit: Unit::PerS, wide: true, drill: "",
        series: &[("@unit", "sum by (unit) (count_over_time({unit=~\"swift-.+|haproxy.service\"{nf}} [{iv}]))")] },
    // Match genuine error events, not benign "errors=0"/"failures=0" stat lines
    // (so "error:" and "error " qualify but "errors=0" does not).
    Panel { id: "log_err", title: "mon.p.log_err", src: Src::Logs, unit: Unit::Num, wide: true, drill: "",
        series: &[("", "{unit=~\"swift-.+\"{nf}} |~ `(?i)(error[: ]|traceback|critical|panic|exception)`")] },
];

const DASHES: &[Dash] = &[
    Dash { id: "overview", title: "mon.d.overview",
        panels: &["nodes_up", "reqs", "err5xx", "p99", "reqs_method", "latency", "reqs_status", "err_ratio"] },
    Dash { id: "backends", title: "mon.d.backends",
        panels: &["backend_reqs", "backend_p99", "backend_status", "backend_err"] },
    Dash { id: "nodes", title: "mon.d.nodes",
        panels: &["cpu", "mem", "load", "fs_used", "net_storage", "net_repl", "net_public", "disk_util"] },
    Dash { id: "storage", title: "mon.d.storage",
        panels: &["dev_used", "dev_inodes", "disk_read", "disk_write", "disk_iops"] },
    Dash { id: "replication", title: "mon.d.replication",
        panels: &["repl_kind", "repl_sf", "repl_node", "repl_fail_node"] },
    Dash { id: "services", title: "mon.d.services",
        panels: &["svc_grid", "svc_events", "log_vol", "log_err"] },
];

/// The panels shown when one node is opened. Everything here accepts `{nf}`.
const NODE_PANELS: &[&str] = &[
    "cpu", "mem", "load", "disk_util", "fs_used", "dev_used", "disk_read", "disk_write",
    "disk_iops", "net_storage", "net_repl", "net_public", "reqs_method", "latency",
    "backend_reqs", "backend_p99", "repl_kind", "repl_sf", "svc_events", "log_vol",
];

fn panel(id: &str) -> Option<&'static Panel> {
    PANELS.iter().find(|p| p.id == id)
}

// ------------------------------------------------------------- time + intervals

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// step and rate-interval derived from the requested window (seconds).
fn grid(range_s: i64) -> (i64, String) {
    let step = (range_s / 150).clamp(15, 3600);
    let iv = (step * 4).clamp(60, 900);
    (step, format!("{iv}s"))
}

// ------------------------------------------------------------- backend queries

fn finite(v: f64) -> Option<f64> {
    if v.is_finite() {
        Some(v)
    } else {
        None
    }
}

fn series_name(spec: &str, metric: &Value) -> String {
    if let Some(keys) = spec.strip_prefix('@') {
        // `@a,b` joins several labels ("swift2 · /srv/node/d1").
        let parts: Vec<String> = keys
            .split(',')
            .map(|key| {
                let raw = metric
                    .get(key)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                // Node targets carry an exporter port; drop it for a clean legend.
                match raw.split_once(':') {
                    Some((host, _port)) if key == "instance" => host.to_string(),
                    _ => raw,
                }
            })
            .filter(|s| !s.is_empty())
            .collect();
        if parts.is_empty() {
            "value".to_string()
        } else {
            parts.join(" · ")
        }
    } else {
        spec.to_string()
    }
}

// ------------------------------------------------------------- node identity

/// Cluster node names, in config order — the monitor's node picker.
fn node_names(state: &Arc<AppState>) -> Vec<String> {
    crate::nodes::all(state)
        .iter()
        .map(|n| n.name.clone())
        .collect()
}

/// `{nf}` substitution for a metrics (PromQL) query: match the node by name or
/// by any of its addresses, with or without an exporter port.
fn prom_node_filter(state: &Arc<AppState>, node: &str) -> Option<String> {
    let roster = crate::nodes::all(state);
    let n = roster.iter().find(|n| n.name == node)?;
    let mut alts: Vec<String> = vec![regex_escape(&n.name)];
    for ip in [&n.storage_ip, &n.replication_ip, &n.public_ip] {
        if !ip.is_empty() {
            alts.push(regex_escape(ip));
        }
    }
    Some(format!(
        ",instance=~\"^({})(:[0-9]+)?$\"",
        alts.join("|")
    ))
}

/// `{nf}` substitution for a logs (LogQL) query: streams are labeled with the
/// emitting host's name.
fn log_node_filter(node: &str) -> String {
    format!(",host=\"{}\"", node.replace('"', ""))
}

/// Escape a literal for a PromQL double-quoted regex. PromQL string literals
/// reject `\.` (`unknown escape sequence`); a literal dot has to be written
/// as `[.]`, and a real backslash as `\\`.
fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '.' => out.push_str("[.]"),
            '\\' => out.push_str("\\\\"),
            '^' | '$' | '|' | '?' | '*' | '+' | '(' | ')' | '[' | ']' | '{' | '}' => {
                // PromQL keeps one backslash only when the source has two.
                out.push('\\');
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Rename per-instance series to cluster node names (an IP means nothing to an
/// operator), and attach the node name as a `key` so the row can be opened.
fn attach_node_keys(state: &Arc<AppState>, series: &mut [Value]) {
    let roster = crate::nodes::all(state);
    for s in series.iter_mut() {
        let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        // "10.42.10.12" or "10.42.10.12 · /srv/node/d1" — map the address part.
        let (head, rest) = match name.split_once(" · ") {
            Some((h, r)) => (h.to_string(), Some(r.to_string())),
            None => (name.clone(), None),
        };
        if let Some(n) = roster.iter().find(|n| {
            n.name == head || n.storage_ip == head || n.replication_ip == head || n.public_ip == head
        }) {
            let display = match &rest {
                Some(r) => format!("{} · {}", n.name, r),
                None => n.name.clone(),
            };
            s["name"] = json!(display);
            s["key"] = json!(n.name);
        }
    }
}

pub(crate) fn parse_matrix(spec: &str, data: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    let empty = Vec::new();
    let results = data
        .get("data")
        .and_then(|d| d.get("result"))
        .and_then(|r| r.as_array())
        .unwrap_or(&empty);
    for r in results {
        let name = series_name(spec, r.get("metric").unwrap_or(&Value::Null));
        let mut points = Vec::new();
        if let Some(vals) = r.get("values").and_then(|v| v.as_array()) {
            for pair in vals {
                if let Some(p) = pair.as_array() {
                    let t = p.first().and_then(|x| x.as_f64()).unwrap_or(0.0);
                    let v = p
                        .get(1)
                        .and_then(|x| x.as_str())
                        .and_then(|s| s.parse::<f64>().ok());
                    match v.and_then(finite) {
                        Some(v) => points.push(json!([t, v])),
                        None => points.push(json!([t, Value::Null])),
                    }
                }
            }
        }
        out.push(json!({"name": name, "points": points}));
    }
    out
}

pub(crate) fn parse_instant(data: &Value) -> Option<f64> {
    let results = data.get("data")?.get("result")?.as_array()?;
    let first = results.first()?;
    let v = first.get("value")?.as_array()?;
    v.get(1)?.as_str()?.parse::<f64>().ok().and_then(finite)
}

pub(crate) async fn q_instant(state: &Arc<AppState>, promql: &str) -> Result<Value, String> {
    let url = format!("{}/api/v1/query", state.cfg.metrics_url);
    let t = now_secs().to_string();
    state
        .http
        .get(&url)
        .query(&[("query", promql), ("time", &t)])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Value>()
        .await
        .map_err(|e| e.to_string())
}

pub(crate) async fn q_range(
    state: &Arc<AppState>,
    promql: &str,
    start: i64,
    end: i64,
    step: i64,
) -> Result<Value, String> {
    let url = format!("{}/api/v1/query_range", state.cfg.metrics_url);
    let data: Value = state
        .http
        .get(&url)
        .query(&[
            ("query", promql),
            ("start", &start.to_string()),
            ("end", &end.to_string()),
            ("step", &step.to_string()),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Value>()
        .await
        .map_err(|e| e.to_string())?;
    if data.get("status").and_then(|s| s.as_str()) == Some("error") {
        return Err(data
            .get("error")
            .and_then(|e| e.as_str())
            .unwrap_or("query failed")
            .to_string());
    }
    Ok(data)
}

pub(crate) async fn q_log_range(
    state: &Arc<AppState>,
    logql: &str,
    start: i64,
    end: i64,
    step: i64,
) -> Result<Value, String> {
    let url = format!("{}/loki/api/v1/query_range", state.cfg.logs_url);
    let (sns, ens) = ((start as i128 * 1_000_000_000).to_string(), (end as i128 * 1_000_000_000).to_string());
    state
        .http
        .get(&url)
        .query(&[
            ("query", logql),
            ("start", &sns),
            ("end", &ens),
            ("step", &format!("{step}s")),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<Value>()
        .await
        .map_err(|e| e.to_string())
}

pub(crate) async fn q_logs(
    state: &Arc<AppState>,
    logql: &str,
    start: i64,
    end: i64,
    limit: u32,
) -> Result<Vec<Value>, String> {
    let url = format!("{}/loki/api/v1/query_range", state.cfg.logs_url);
    let (sns, ens) = ((start as i128 * 1_000_000_000).to_string(), (end as i128 * 1_000_000_000).to_string());
    let data: Value = state
        .http
        .get(&url)
        .query(&[
            ("query", logql),
            ("start", &sns),
            ("end", &ens),
            ("limit", &limit.to_string()),
            ("direction", &"backward".to_string()),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let mut lines = Vec::new();
    if let Some(streams) = data.get("data").and_then(|d| d.get("result")).and_then(|r| r.as_array()) {
        for s in streams {
            let unit = s
                .get("stream")
                .and_then(|st| st.get("unit"))
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            // Which machine emitted the line. The Logs panel does not use it,
            // but Tombstone Museum has to attribute every line to a node, and
            // the label is only available here where the stream is still whole.
            let host = s
                .get("stream")
                .and_then(|st| st.get("host"))
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            if let Some(vals) = s.get("values").and_then(|v| v.as_array()) {
                for pair in vals {
                    if let Some(p) = pair.as_array() {
                        let ts = p
                            .first()
                            .and_then(|x| x.as_str())
                            .and_then(|s| s.parse::<i128>().ok())
                            .map(|ns| (ns / 1_000_000_000) as i64)
                            .unwrap_or(0);
                        let line = p.get(1).and_then(|x| x.as_str()).unwrap_or("").to_string();
                        lines.push(json!({"t": ts, "unit": unit, "host": host, "line": line}));
                    }
                }
            }
        }
    }
    // newest first, capped
    lines.sort_by(|a, b| b["t"].as_i64().unwrap_or(0).cmp(&a["t"].as_i64().unwrap_or(0)));
    lines.truncate(limit as usize);
    Ok(lines)
}

// ------------------------------------------------------------- handlers

fn require_session(state: &Arc<AppState>, headers: &HeaderMap) -> bool {
    session::from_headers(&state.sessions, headers).is_some()
}

fn panel_meta(lang: &str, p: &Panel) -> Value {
    let kind = match p.src {
        Src::Instant => "stat",
        Src::Logs => "logs",
        Src::SvcGrid => "svcgrid",
        _ => "series",
    };
    let node_scoped =
        p.src == Src::SvcGrid || p.series.iter().any(|(_, q)| q.contains("{nf}"));
    json!({
        "id": p.id,
        "title": crate::i18n::t(lang, p.title),
        "kind": kind,
        "unit": p.unit.tag(),
        "wide": p.wide,
        "drill": p.drill,
        "node_scoped": node_scoped,
    })
}

/// Dashboard/panel catalogue (titles, kind, unit, layout), the node roster for
/// the per-node view, and the node-view panel set. Carries **no** queries or
/// backend hints — those never leave the server.
pub async fn dash_catalog(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !require_session(&state, &headers) {
        return unauth();
    }
    let lang = crate::i18n::lang(&headers);
    let dashes: Vec<Value> = DASHES
        .iter()
        .map(|d| {
            let panels: Vec<Value> = d
                .panels
                .iter()
                .filter_map(|pid| panel(pid))
                .map(|p| panel_meta(lang, p))
                .collect();
            json!({"id": d.id, "title": crate::i18n::t(lang, d.title), "panels": panels})
        })
        .collect();
    let node_panels: Vec<Value> = NODE_PANELS
        .iter()
        .filter_map(|pid| panel(pid))
        .map(|p| panel_meta(lang, p))
        .collect();
    Json(json!({
        "dashboards": dashes,
        "nodes": node_names(&state),
        "node_panels": node_panels,
        "node_title": crate::i18n::t(lang, "mon.d.node"),
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct PanelQuery {
    id: String,
    #[serde(default = "def_range")]
    range: i64,
    /// Confine the panel to one cluster node (by name).
    #[serde(default)]
    node: String,
}
fn def_range() -> i64 {
    3600
}

/// Per-node × per-service health, probed live. Read-only (`is-active`), so it
/// sits behind the ordinary session like every other monitor panel.
async fn svc_grid(state: &Arc<AppState>, node: &str) -> Value {
    let services: Vec<&str> = crate::nodeops::SERVICES.split_whitespace().collect();
    let probe = format!(
        "systemctl is-active {} 2>/dev/null | tr '\\n' ' '; echo",
        crate::nodeops::SERVICES
    );
    let results = if node.is_empty() {
        crate::nodes::fan_out(state, &probe).await
    } else {
        crate::nodes::fan_out_on(state, &[node.to_string()], &probe).await
    };
    let rows: Vec<Value> = results
        .into_iter()
        .map(|r| {
            let states: Vec<&str> = r.out.split_whitespace().collect();
            let cells: Vec<Value> = services
                .iter()
                .enumerate()
                .map(|(i, svc)| {
                    let st = if !r.ok { "unreachable" } else { states.get(i).copied().unwrap_or("unknown") };
                    json!({"service": svc, "state": st})
                })
                .collect();
            json!({"node": r.node, "reachable": r.ok, "cells": cells})
        })
        .collect();
    json!({"services": services, "rows": rows})
}

/// Run one panel's queries server-side and return neutral data.
pub async fn panel_data(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PanelQuery>,
) -> Response {
    if !require_session(&state, &headers) {
        return unauth();
    }
    let p = match panel(&q.id) {
        Some(p) => p,
        None => return Json(json!({"error": "unknown panel"})).into_response(),
    };
    let range_s = q.range.clamp(900, 86400 * 7);
    let end = now_secs();
    let start = end - range_s;
    let (step, iv) = grid(range_s);

    // Node confinement: substitute `{nf}` per backend dialect. An unknown node
    // name yields an impossible matcher rather than silently widening back to
    // the whole cluster.
    let node = q.node.trim();
    let prom_nf = if node.is_empty() {
        String::new()
    } else {
        prom_node_filter(&state, node).unwrap_or_else(|| ",instance=\"\"".to_string())
    };
    let log_nf = if node.is_empty() { String::new() } else { log_node_filter(node) };

    match p.src {
        Src::Instant => {
            let sub = p.series[0].1.replace("{iv}", &iv).replace("{nf}", &prom_nf);
            let val = match q_instant(&state, &sub).await {
                Ok(d) => parse_instant(&d),
                Err(e) => return err_json(&e),
            };
            Json(json!({"id": p.id, "kind": "stat", "unit": p.unit.tag(), "value": val}))
                .into_response()
        }
        Src::Logs => {
            let sub = p.series[0].1.replace("{nf}", &log_nf);
            match q_logs(&state, &sub, start, end, 60).await {
                Ok(lines) => Json(json!({"id": p.id, "kind": "logs", "lines": lines}))
                    .into_response(),
                Err(e) => err_json(&e),
            }
        }
        Src::SvcGrid => {
            let grid = svc_grid(&state, node).await;
            Json(json!({"id": p.id, "kind": "svcgrid", "grid": grid})).into_response()
        }
        Src::Range | Src::LogRange => {
            let mut all = Vec::new();
            for (spec, ql) in p.series {
                let sub = if p.src == Src::Range {
                    ql.replace("{iv}", &iv).replace("{nf}", &prom_nf)
                } else {
                    ql.replace("{iv}", &iv).replace("{nf}", &log_nf)
                };
                let data = if p.src == Src::Range {
                    q_range(&state, &sub, start, end, step).await
                } else {
                    q_log_range(&state, &sub, start, end, step).await
                };
                match data {
                    Ok(d) => all.extend(parse_matrix(spec, &d)),
                    Err(e) => return err_json(&e),
                }
            }
            attach_node_keys(&state, &mut all);
            Json(json!({"id": p.id, "kind": "series", "unit": p.unit.tag(), "series": all}))
                .into_response()
        }
    }
}

fn unauth() -> Response {
    (axum::http::StatusCode::UNAUTHORIZED, Json(json!({"error": "session required"})))
        .into_response()
}

fn err_json(e: &str) -> Response {
    // Never surface backend identity in an error; keep it generic.
    let _ = e;
    Json(json!({"error": "metrics temporarily unavailable"})).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promql_regex_escape_avoids_dot_backslash() {
        let s = regex_escape("10.42.10.11");
        assert!(!s.contains("\\."), "PromQL rejects \\. in double-quoted strings: {s}");
        assert!(s.contains("[.]"), "{s}");
        assert_eq!(regex_escape("swift1"), "swift1");
    }
}
