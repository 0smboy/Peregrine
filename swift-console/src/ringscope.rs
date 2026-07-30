//! RingScope: what the ring would do.
//!
//! A ring is the least visible thing in a Swift cluster and the most
//! consequential — it decides what survives a failure and what has to move when
//! hardware changes. This turns it into questions an operator can actually ask:
//! pull this disk, lose that zone, add a machine, and see which partitions
//! migrate, how many bytes cross the network, and what the cluster can still
//! tolerate.
//!
//! Simulation runs `swift-ring-sim` against a copy, so it uses the real
//! placement algorithm and cannot touch the live ring. The console adds the one
//! thing the ring does not know: how many *bytes* a moved replica slot is,
//! which comes from live per-device usage.
//!
//! The report is rendered here rather than in the browser. A change review gets
//! pasted into a ticket, so the scenario lives in the URL and the whole document
//! — verdict, partition map, device table — is in the first response. Nothing on
//! this page needs a script to exist.

use crate::i18n;
use crate::lab;
use crate::nodes;
use crate::ringlab;
use crate::util::{esc, fmt_bytes};
use crate::AppState;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

const MAX_OPS: usize = 32;

/// A ring with a large part power would otherwise emit one rect per partition
/// and turn a diagnostic page into a megabyte. Past this the map aggregates and
/// says so, rather than silently drawing a different thing.
const MAP_MAX_CELLS: usize = 4096;

/// Ops a scenario may contain. Anything else is refused rather than passed
/// through to the simulator.
const ALLOWED_OPS: &[&str] = &[
    "fail_device",
    "fail_node",
    "fail_zone",
    "remove_device",
    "set_weight",
    "add_device",
];

fn err(msg: &str) -> Response {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(json!({ "error": msg })),
    )
        .into_response()
}

fn gateway(msg: &str) -> Response {
    (
        axum::http::StatusCode::BAD_GATEWAY,
        Json(json!({ "error": msg })),
    )
        .into_response()
}

/// Split "the caller asked for something that does not exist" from "the thing
/// behind us broke". Both used to come back as 502, which told a client to
/// retry a request that will never succeed and pointed an operator at the
/// wrong layer.
fn upstream(msg: &str) -> Response {
    if msg.starts_with("no storage policy") {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({ "error": msg })),
        )
            .into_response();
    }
    gateway(msg)
}

#[derive(Deserialize)]
pub struct PolicyQ {
    #[serde(default)]
    pub policy: u32,
}

/// Baseline: the ring as it stands, with live device usage folded in.
pub async fn topology(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PolicyQ>,
) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let policies = match ringlab::policies(&state).await {
        Ok(p) => p,
        Err(e) => return gateway(&e),
    };
    let mut topo = match ringlab::topology(&state, q.policy).await {
        Ok(t) => t,
        Err(e) => return upstream(&e),
    };
    let usage = ringlab::device_usage(&state).await;
    decorate_devices(&state, &mut topo, &usage);
    Json(json!({
        "policies": policies,
        "policy": q.policy,
        "topology": topo,
    }))
    .into_response()
}

/// Attach the node name and live bytes to each ring device, so the UI can talk
/// about "swift2" and "3.4 GiB" rather than an IP and a slot count.
fn decorate_devices(state: &Arc<AppState>, topo: &mut Value, usage: &[ringlab::DeviceUsage]) {
    let Some(devs) = topo.get_mut("devices").and_then(|d| d.as_array_mut()) else {
        return;
    };
    for d in devs.iter_mut() {
        let ip = d.get("ip").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let dev = d
            .get("device")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let node = nodes::label(state, &ip);
        if let Some(o) = d.as_object_mut() {
            o.insert("node".into(), json!(node.clone()));
            if let Some(u) = usage.iter().find(|u| u.node == node && u.device == dev) {
                o.insert("used".into(), json!(u.used));
                o.insert("size".into(), json!(u.size));
            }
        }
    }
}

#[derive(Deserialize)]
pub struct SimReq {
    #[serde(default)]
    pub policy: u32,
    #[serde(default)]
    pub ops: Vec<Value>,
    #[serde(default = "yes")]
    pub rebalance: bool,
}
fn yes() -> bool {
    true
}

/// Validate before executing. The simulator is defensive too, but a scenario
/// that arrived over HTTP should never reach a subprocess unchecked.
fn validate(ops: &[Value]) -> Result<(), String> {
    if ops.len() > MAX_OPS {
        return Err(format!("too many operations (max {MAX_OPS})"));
    }
    for o in ops {
        let name = o.get("op").and_then(|v| v.as_str()).unwrap_or("");
        if !ALLOWED_OPS.contains(&name) {
            return Err(format!("unknown operation '{name}'"));
        }
        for numeric in ["dev_id", "port", "region", "zone", "replication_port"] {
            if let Some(v) = o.get(numeric) {
                if !v.is_u64() {
                    return Err(format!("{numeric} must be a number"));
                }
            }
        }
        if let Some(w) = o.get("weight") {
            let w = w.as_f64().ok_or("weight must be a number")?;
            if !(0.0..=10000.0).contains(&w) {
                return Err("weight must be between 0 and 10000".into());
            }
        }
        for text in ["ip", "device", "replication_ip"] {
            if let Some(v) = o.get(text) {
                let s = v.as_str().ok_or(format!("{text} must be a string"))?;
                if s.len() > 64 || s.contains(char::is_whitespace) {
                    return Err(format!("{text} is not a valid value"));
                }
            }
        }
    }
    Ok(())
}

pub async fn simulate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SimReq>,
) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    if let Err(e) = validate(&req.ops) {
        return err(&e);
    }
    let policy = match ringlab::policy(&state, req.policy).await {
        Ok(p) => p,
        Err(e) => return upstream(&e),
    };

    // The simulator sees a ring, not a policy, so both thresholds come from
    // here. Replication reads from one replica and writes to a majority; EC
    // reads from k fragments and writes to k + min_parity_needed — which on a
    // 2+1 policy is every fragment, so one node down stops writes entirely.
    let replicas = 3u64;
    let scenario = json!({
        "min_readable": policy.min_readable(replicas),
        "quorum": policy.write_quorum(replicas),
        "ops": req.ops,
        "rebalance": req.rebalance,
    });

    let mut out = match ringlab::simulate(&state, req.policy, &scenario).await {
        Ok(v) => v,
        Err(e) => return gateway(&e),
    };
    // One usage fan-out per request: both the device table and the byte
    // arithmetic need it, and ssh round-trips dominate this endpoint.
    let usage = ringlab::device_usage(&state).await;
    decorate_devices(&state, &mut out, &usage);
    let rate = replication_rate(&state).await;
    let tr = transfer(&usage, &out, rate);
    if let Some(o) = out.as_object_mut() {
        o.insert("transfer".into(), tr.as_json());
        o.insert(
            "policy_info".into(),
            serde_json::to_value(&policy).unwrap_or(Value::Null),
        );
    }
    Json(out).into_response()
}

/// Turn "replica slots moved" into bytes and a transfer estimate.
///
/// The ring counts slots; only the cluster knows what a slot weighs. Averaging
/// live usage over the assignment is an approximation — partitions are not
/// exactly equal — but it is derived from real data rather than assumed, and
/// it is the number an operator actually plans around.
#[derive(Clone, Debug, Default)]
pub struct Transfer {
    pub cluster_used_bytes: u64,
    pub bytes_per_slot: u64,
    pub bytes_moved: u64,
    /// The floor: what would have to move even with a perfect placement.
    pub necessary_slots: u64,
    pub necessary_bytes: u64,
    pub rate: f64,
    pub eta_secs: Option<u64>,
    /// "none" | "rate" | "idle" — why there is or is not an estimate. Rendered
    /// as a sentence rather than left as a silent blank.
    pub eta_reason: &'static str,
}

impl Transfer {
    fn as_json(&self) -> Value {
        json!({
            "cluster_used_bytes": self.cluster_used_bytes,
            "bytes_per_slot": self.bytes_per_slot,
            "bytes_moved": self.bytes_moved,
            "necessary_slots": self.necessary_slots,
            "necessary_bytes": self.necessary_bytes,
            "replication_bytes_per_sec": self.rate as u64,
            "eta_secs": self.eta_secs,
            "eta_reason": self.eta_reason,
        })
    }
}

/// An ETA is only offered when the replication plane is actually carrying
/// traffic. Extrapolating from an idle cluster's few bytes per second yields an
/// answer in years, which is worse than admitting we cannot say: the rate during
/// a real rebalance is set by what the link and disks will do, not by what an
/// idle cluster happens to be doing now.
const ETA_RATE_FLOOR: f64 = 1024.0 * 1024.0; // 1 MiB/s

/// The smallest number of replica slots that *could* have moved.
///
/// Every device that ends up owing more partitions than it started with has to
/// receive that difference no matter how good the placement is; nothing else is
/// forced. Comparing it with what the rebalance actually moves is the difference
/// between "this change is expensive" and "this change is expensive for no
/// reason", and the ring itself never says which one it is.
pub fn necessary_slots(devices: &[Value]) -> u64 {
    let mut need = 0.0f64;
    for d in devices {
        let before = d.get("parts_before").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let ideal = d.get("ideal_after").and_then(|v| v.as_f64()).unwrap_or(0.0);
        if ideal > before {
            need += ideal - before;
        }
    }
    need.round() as u64
}

fn transfer(usage: &[ringlab::DeviceUsage], out: &Value, rate: f64) -> Transfer {
    let total_used: u64 = usage.iter().map(|u| u.used).sum();
    let mv = out.get("movement");
    let slots_moved = mv
        .and_then(|m| m.get("slots_moved"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let replica_slots = mv
        .and_then(|m| m.get("replica_slots"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let per_slot = if replica_slots > 0 {
        total_used as f64 / replica_slots as f64
    } else {
        0.0
    };
    let bytes_moved = (per_slot * slots_moved as f64) as u64;
    let empty: Vec<Value> = Vec::new();
    let devs = out
        .get("devices")
        .and_then(|d| d.as_array())
        .unwrap_or(&empty);
    let need = necessary_slots(devs);
    let (eta_secs, eta_reason) = if bytes_moved == 0 {
        (None, "none")
    } else if rate >= ETA_RATE_FLOOR {
        (Some((bytes_moved as f64 / rate) as u64), "rate")
    } else {
        (None, "idle")
    };
    Transfer {
        cluster_used_bytes: total_used,
        bytes_per_slot: per_slot as u64,
        bytes_moved,
        necessary_slots: need,
        necessary_bytes: (per_slot * need as f64) as u64,
        rate,
        eta_secs,
        eta_reason,
    }
}

/// Current replication-plane transmit rate, reusing the Monitor query layer
/// rather than re-authoring the metric.
async fn replication_rate(state: &Arc<AppState>) -> f64 {
    let q = "sum(rate(node_network_transmit_bytes_total{job=\"node\",plane=\"replication\"}[5m]))";
    match crate::monitor::q_instant(state, q).await {
        Ok(v) => crate::monitor::parse_instant(&v).unwrap_or(0.0),
        Err(_) => 0.0,
    }
}

#[derive(Deserialize)]
pub struct PartQ {
    #[serde(default)]
    pub policy: u32,
    pub part: u32,
}

/// Where one partition lives right now: primaries first, then handoffs.
async fn part_placement(
    state: &Arc<AppState>,
    policy: &ringlab::PolicyInfo,
    part: u32,
) -> Result<Vec<(bool, String, String)>, String> {
    let path = format!(
        "{}/{}",
        state.cfg.swift_dir.trim_end_matches('/'),
        policy.ring_file
    );
    let out = nodes::local(
        &[
            &state.cfg.getnodes_bin,
            "--json",
            &path,
            "-p",
            &part.to_string(),
        ],
        None,
    )
    .await?;
    let v: Value = serde_json::from_str(&out).map_err(|e| format!("bad get-nodes output: {e}"))?;
    let mut rows = Vec::new();
    for n in v.get("nodes").and_then(|x| x.as_array()).unwrap_or(&vec![]) {
        let ip = n.get("ip").and_then(|x| x.as_str()).unwrap_or("");
        rows.push((
            n.get("handoff").and_then(|x| x.as_bool()).unwrap_or(false),
            nodes::label(state, ip),
            n.get("device")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        ));
    }
    rows.sort_by_key(|r| r.0);
    Ok(rows)
}

/// Drill-down for one partition: which devices hold it now.
pub async fn part(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PartQ>,
) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let p = match ringlab::policy(&state, q.policy).await {
        Ok(p) => p,
        Err(e) => return err(&e),
    };
    match part_placement(&state, &p, q.part).await {
        Ok(rows) => Json(json!({
            "partition": q.part,
            "nodes": rows.iter().map(|(h, n, d)| json!({
                "handoff": h, "node": n, "device": d
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => gateway(&e),
    }
}

// ------------------------------------------------------------- query strings

/// Percent-decoding for the scenario in the URL. The scenario has to survive a
/// copy-paste into a ticket, so it is carried in the query rather than posted.
fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn query_pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (urldecode(k), urldecode(v)),
            None => (urldecode(p), String::new()),
        })
        .collect()
}

// ------------------------------------------------------------- scenario ops

/// One staged change, in the compact form the URL carries.
#[derive(Clone, Debug)]
pub struct Op {
    /// `fail_node:10.42.10.12`, `set_weight:3:50`, `add_device:1,4,ip,d4,100`
    pub raw: String,
    pub kind: String,
    pub json: Value,
}

/// Decode one `op=` parameter. Returns `None` for anything malformed, which is
/// how a hand-edited URL degrades to "that change was dropped" rather than to a
/// subprocess argument.
pub fn parse_op(raw: &str) -> Option<Op> {
    let (kind, rest) = raw.split_once(':')?;
    if !ALLOWED_OPS.contains(&kind) {
        return None;
    }
    let json = match kind {
        "fail_node" => json!({ "op": kind, "ip": rest }),
        "fail_device" | "remove_device" => {
            json!({ "op": kind, "dev_id": rest.parse::<u64>().ok()? })
        }
        "fail_zone" => {
            let (r, z) = rest.split_once(':')?;
            json!({ "op": kind, "region": r.parse::<u64>().ok()?, "zone": z.parse::<u64>().ok()? })
        }
        "set_weight" => {
            let (d, w) = rest.split_once(':')?;
            let w: f64 = w.parse().ok()?;
            if !(0.0..=10000.0).contains(&w) {
                return None;
            }
            json!({ "op": kind, "dev_id": d.parse::<u64>().ok()?, "weight": w })
        }
        "add_device" => {
            let f: Vec<&str> = rest.split(',').map(|x| x.trim()).collect();
            if f.len() < 4 {
                return None;
            }
            let w: f64 = f.get(4).and_then(|x| x.parse().ok()).unwrap_or(100.0);
            if !(0.0..=10000.0).contains(&w) {
                return None;
            }
            json!({
                "op": kind,
                "region": f[0].parse::<u64>().ok()?,
                "zone": f[1].parse::<u64>().ok()?,
                "ip": f[2],
                "port": 6200,
                "device": f[3],
                "weight": w,
            })
        }
        _ => return None,
    };
    let op = Op {
        raw: raw.to_string(),
        kind: kind.to_string(),
        json,
    };
    validate(std::slice::from_ref(&op.json)).ok()?;
    Some(op)
}

/// Fold the form's three fields into the one compact op the URL carries.
///
/// `target` is either a device (`d:<dev_id>`) or a failure domain (`z:<r>:<z>`);
/// which one a change needs is decided here rather than in the browser, so the
/// form works with no script and a hand-written URL is checked the same way.
pub fn compose_op(kind: &str, target: &str, value: &str) -> Option<String> {
    // The device option carries both halves — `d:<dev_id>:<ip>` — because
    // pulling a disk is keyed by id and taking a node offline is keyed by
    // address, and only the form knows which disk the operator picked.
    let dev = target.strip_prefix("d:").and_then(|r| r.split_once(':'));
    let zone = target.strip_prefix("z:");
    match kind {
        "fail_device" | "remove_device" => Some(format!("{kind}:{}", dev?.0)),
        "fail_node" => Some(format!("fail_node:{}", dev?.1)),
        "fail_zone" => Some(format!("fail_zone:{}", zone?)),
        "set_weight" => {
            if value.is_empty() {
                return None;
            }
            Some(format!("set_weight:{}:{value}", dev?.0))
        }
        "add_device" => {
            if value.split(',').count() < 4 {
                return None;
            }
            Some(format!("add_device:{value}"))
        }
        _ => None,
    }
}

/// The words for one staged change, with the device named rather than numbered.
fn op_label(lang: &str, op: &Op, devices: &[Value]) -> String {
    let dev_name = |id: u64| -> String {
        devices
            .iter()
            .find(|d| d.get("dev_id").and_then(|v| v.as_u64()) == Some(id))
            .map(|d| {
                format!(
                    "{}/{}",
                    d.get("node")
                        .or_else(|| d.get("ip"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?"),
                    d.get("device").and_then(|v| v.as_str()).unwrap_or("?")
                )
            })
            .unwrap_or_else(|| format!("dev {id}"))
    };
    let id = op.json.get("dev_id").and_then(|v| v.as_u64()).unwrap_or(0);
    match op.kind.as_str() {
        "fail_node" => i18n::t(lang, "rsx.chip.fail_node").replace(
            "{node}",
            op.json.get("ip").and_then(|v| v.as_str()).unwrap_or("?"),
        ),
        "fail_device" => i18n::t(lang, "rsx.chip.fail_device").replace("{dev}", &dev_name(id)),
        "remove_device" => i18n::t(lang, "rsx.chip.remove_device").replace("{dev}", &dev_name(id)),
        "fail_zone" => i18n::t(lang, "rsx.chip.fail_zone")
            .replace(
                "{zone}",
                &format!(
                    "r{}z{}",
                    op.json.get("region").and_then(|v| v.as_u64()).unwrap_or(0),
                    op.json.get("zone").and_then(|v| v.as_u64()).unwrap_or(0)
                ),
            )
            .to_string(),
        "set_weight" => i18n::t(lang, "rsx.chip.set_weight")
            .replace("{dev}", &dev_name(id))
            .replace(
                "{w}",
                &format!(
                    "{}",
                    op.json.get("weight").and_then(|v| v.as_f64()).unwrap_or(0.0)
                ),
            ),
        "add_device" => i18n::t(lang, "rsx.chip.add_device")
            .replace(
                "{dev}",
                &format!(
                    "{}/{}",
                    op.json.get("ip").and_then(|v| v.as_str()).unwrap_or("?"),
                    op.json.get("device").and_then(|v| v.as_str()).unwrap_or("?")
                ),
            )
            .replace(
                "{zone}",
                &format!(
                    "r{}z{}",
                    op.json.get("region").and_then(|v| v.as_u64()).unwrap_or(0),
                    op.json.get("zone").and_then(|v| v.as_u64()).unwrap_or(0)
                ),
            ),
        _ => op.raw.clone(),
    }
}

// ------------------------------------------------------------- small helpers

/// Thousands separators. "2,352 of 3,072" is read at a glance; "2352 of 3072"
/// is counted digit by digit, and this page is full of four-digit numbers.
fn thou(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn pct1(v: f64) -> String {
    format!("{v:.1}%")
}

/// Standard base64 with padding, for the simulator's per-partition state array.
fn b64_decode(s: &str) -> Vec<u8> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    };
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for &c in s.as_bytes() {
        let Some(v) = val(c) else { continue };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn f(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0)
}
fn u(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(|x| x.as_u64()).unwrap_or(0)
}
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

fn stat_card(label: &str, value: &str, tone: &str, note: &str) -> String {
    format!(
        "<div class=\"mon-card mon-stat lab-stat\"><div class=\"mon-card-h\">\
         <span class=\"mon-t\">{label}</span></div><div class=\"mon-body\">\
         <span class=\"mon-stat-v {tone}\">{value}</span>\
         <span class=\"lab-b\">{note}</span></div></div>",
        label = esc(label),
        value = esc(value),
        note = esc(note),
    )
}

// ------------------------------------------------------------- the verdict

struct Verdict {
    tone: &'static str,
    headline: String,
    detail: String,
}

/// One sentence an operator can act on, then the arithmetic behind it.
///
/// Movement is scored against the floor rather than against zero: every
/// rebalance moves data, and the question a change review has to answer is
/// whether it moves *more than it had to*.
fn verdict(lang: &str, out: &Value, tr: &Transfer, has_ops: bool) -> Verdict {
    let sur = out.get("survival").cloned().unwrap_or(Value::Null);
    let mv = out.get("movement").cloned().unwrap_or(Value::Null);
    let ta = out.get("tolerance_after").cloned().unwrap_or(Value::Null);
    let disp = out
        .get("dispersion_after")
        .cloned()
        .unwrap_or(Value::Null);
    let total = u(&sur, "parts_total").max(1);
    let lost = u(&sur, "parts_lost");
    let noq = u(&sur, "parts_below_quorum");
    let degraded = u(&sur, "parts_degraded");
    let moved = u(&mv, "slots_moved");
    let slots = u(&mv, "replica_slots").max(1);

    if lost > 0 {
        return Verdict {
            tone: "bad",
            headline: i18n::t(lang, "rsx.v.lost.h")
                .replace("{n}", &thou(lost))
                .replace("{total}", &thou(total)),
            detail: i18n::t(lang, "rsx.v.lost.d")
                .replace("{n}", &thou(lost))
                .replace("{pct}", &pct1(lost as f64 / total as f64 * 100.0))
                .replace("{min}", &u(&sur, "min_readable").to_string()),
        };
    }
    if noq > 0 {
        return Verdict {
            tone: "bad",
            headline: i18n::t(lang, "rsx.v.noquorum.h")
                .replace("{n}", &thou(noq))
                .replace("{total}", &thou(total)),
            detail: i18n::t(lang, "rsx.v.noquorum.d")
                .replace("{q}", &u(&sur, "quorum").to_string())
                .replace("{n}", &thou(noq)),
        };
    }
    if degraded > 0 {
        return Verdict {
            tone: "warn",
            headline: i18n::t(lang, "rsx.v.degraded.h")
                .replace("{n}", &thou(degraded))
                .replace("{total}", &thou(total)),
            detail: i18n::t(lang, "rsx.v.degraded.d")
                .replace("{min}", &u(&sur, "min_surviving_replicas").to_string()),
        };
    }
    if has_ops && moved > 0 {
        let need = tr.necessary_slots.max(1);
        let ratio = moved as f64 / need as f64;
        let tone = if ratio >= 2.0 { "warn" } else { "ok" };
        let key = if ratio >= 2.0 {
            "rsx.v.churn.h"
        } else {
            "rsx.v.move.h"
        };
        return Verdict {
            tone,
            headline: i18n::t(lang, key)
                .replace("{moved}", &thou(moved))
                .replace("{slots}", &thou(slots))
                .replace("{pct}", &pct1(moved as f64 / slots as f64 * 100.0))
                .replace("{need}", &thou(tr.necessary_slots)),
            detail: i18n::t(lang, "rsx.v.move.d")
                .replace("{bytes}", &fmt_bytes(tr.bytes_moved))
                .replace("{floorbytes}", &fmt_bytes(tr.necessary_bytes))
                .replace("{x}", &format!("{ratio:.1}"))
                .replace("{tol}", &u(&ta, "node_loss").to_string()),
        };
    }
    if has_ops {
        return Verdict {
            tone: "ok",
            headline: i18n::t(lang, "rsx.v.nomove.h").to_string(),
            detail: i18n::t(lang, "rsx.v.nomove.d").to_string(),
        };
    }

    // No scenario: the report is about the ring as it stands.
    let overlaps = u(&disp, "zone_overlaps");
    if overlaps > 0 {
        return Verdict {
            tone: "warn",
            headline: i18n::t(lang, "rsx.v.overlap.h")
                .replace("{n}", &thou(overlaps))
                .replace("{total}", &thou(total)),
            detail: i18n::t(lang, "rsx.v.overlap.d").to_string(),
        };
    }
    let worst = out
        .get("devices")
        .and_then(|d| d.as_array())
        .map(|ds| {
            ds.iter()
                .map(|d| f(d, "balance_pct").abs())
                .fold(0.0f64, f64::max)
        })
        .unwrap_or(0.0);
    Verdict {
        tone: "ok",
        headline: i18n::t(lang, "rsx.v.base.h")
            .replace("{tol}", &u(&ta, "node_loss").to_string())
            .replace("{total}", &thou(total)),
        detail: i18n::t(lang, "rsx.v.base.d")
            .replace("{bal}", &pct1(worst))
            .replace("{zl}", &u(&ta, "zone_loss").to_string())
            .replace("{dom}", &tier_word(lang, s(&ta, "limiting_domain"))),
    }
}

fn tier_word(lang: &str, kind: &str) -> String {
    match kind {
        "region" => i18n::t(lang, "rsx.tier.region"),
        "zone" => i18n::t(lang, "rsx.tier.zone"),
        "node" => i18n::t(lang, "rsx.tier.node"),
        "device" => i18n::t(lang, "rsx.tier.device"),
        _ => i18n::t(lang, "rsx.tier.unknown"),
    }
    .to_string()
}

// ------------------------------------------------------------- the visuals

/// The partition map: one mark per partition, coloured by how much of it moved.
///
/// Same-class marks are drawn as one path rather than a thousand rects — the
/// document has to stay a document, not a megabyte of SVG.
fn partition_map(lang: &str, states: &[u8]) -> String {
    if states.is_empty() {
        return format!(
            "<p class=\"note\">{}</p>",
            esc(i18n::t(lang, "rsx.map.empty"))
        );
    }
    // Aggregate rather than draw a mark per partition on a large ring; the
    // worst state in a block wins so a single relocated partition never
    // disappears into an average.
    let per_cell = (states.len() + MAP_MAX_CELLS - 1) / MAP_MAX_CELLS;
    let cells: Vec<u8> = states
        .chunks(per_cell.max(1))
        .map(|c| *c.iter().max().unwrap_or(&0))
        .collect();
    let n = cells.len();
    let cols = (((n as f64).sqrt() * 2.0).ceil() as usize).clamp(16, 64);
    let rows = n.div_ceil(cols);
    let (cell, gap) = (12.0f64, 1.0f64);
    let mut paths = [String::new(), String::new(), String::new(), String::new()];
    for (i, st) in cells.iter().enumerate() {
        let idx = (*st as usize).min(3);
        let x = (i % cols) as f64 * cell;
        let y = (i / cols) as f64 * cell;
        let w = cell - gap;
        paths[idx].push_str(&format!("M{x} {y}h{w}v{w}h-{w}z"));
    }
    let mut body = String::new();
    for (i, d) in paths.iter().enumerate() {
        if !d.is_empty() {
            body.push_str(&format!("<path class=\"rs-p{i}\" d=\"{d}\"/>"));
        }
    }
    let legend: Vec<(&str, &str)> = vec![
        (i18n::t(lang, "rsx.map.k0"), "rs-p0"),
        (i18n::t(lang, "rsx.map.k1"), "rs-p1"),
        (i18n::t(lang, "rsx.map.k2"), "rs-p2"),
        (i18n::t(lang, "rsx.map.k3"), "rs-p3"),
    ];
    let leg = legend
        .iter()
        .map(|(t, c)| {
            format!("<span class=\"mon-leg-i\"><i class=\"{c}\"></i><b>{}</b></span>", esc(t))
        })
        .collect::<Vec<_>>()
        .join("");
    let scale = if per_cell > 1 {
        i18n::t(lang, "rsx.map.aggregated").replace("{n}", &thou(per_cell as u64))
    } else {
        i18n::t(lang, "rsx.map.exact").replace("{n}", &thou(states.len() as u64))
    };
    format!(
        "<div class=\"mon-card wide\"><div class=\"mon-card-h\"><span class=\"mon-t\">{title}</span>\
         <span class=\"mon-legend\">{leg}</span></div><div class=\"mon-body\">\
         <svg class=\"rs-map\" viewBox=\"0 0 {vw} {vh}\" width=\"100%\" role=\"img\" \
         aria-label=\"{title}\" preserveAspectRatio=\"xMidYMid meet\">{body}</svg>\
         <div class=\"lab-b\">{scale}</div></div></div>",
        title = esc(i18n::t(lang, "rsx.map.title")),
        vw = cols as f64 * cell,
        vh = rows as f64 * cell,
        scale = esc(&scale),
    )
}

/// The movement budget: how much of the ring the change touches, against how
/// much of it it had to touch. One bar, two marks, no interpretation needed.
fn movement_bar(lang: &str, moved: u64, need: u64, slots: u64, tr: &Transfer) -> String {
    let slots = slots.max(1);
    let (w, h) = (640.0f64, 66.0f64);
    let bar_y = 18.0;
    let bar_h = 16.0;
    let mx = (moved as f64 / slots as f64).clamp(0.0, 1.0) * w;
    let nx = (need as f64 / slots as f64).clamp(0.0, 1.0) * w;
    let flip = nx > w - 120.0;
    format!(
        "<div class=\"mon-card wide\"><div class=\"mon-card-h\"><span class=\"mon-t\">{title}</span></div>\
         <div class=\"mon-body\">\
         <svg class=\"rs-budget\" viewBox=\"0 0 {w} {h}\" width=\"100%\" role=\"img\" aria-label=\"{title}\">\
           <rect class=\"rs-bg\" x=\"0\" y=\"{bar_y}\" width=\"{w}\" height=\"{bar_h}\" rx=\"2\"/>\
           <rect class=\"rs-moved\" x=\"0\" y=\"{bar_y}\" width=\"{mx:.1}\" height=\"{bar_h}\" rx=\"2\"/>\
           <line class=\"rs-floor\" x1=\"{nx:.1}\" y1=\"{fy}\" x2=\"{nx:.1}\" y2=\"{fy2}\"/>\
           <text class=\"rs-lbl\" x=\"2\" y=\"12\">{moved_l}</text>\
           <text class=\"rs-lbl end\" x=\"{w}\" y=\"12\" text-anchor=\"end\">{total_l}</text>\
           <text class=\"rs-floor-l\" x=\"{lx:.1}\" y=\"{ly}\" text-anchor=\"{anchor}\">{floor_l}</text>\
         </svg></div></div>",
        title = esc(i18n::t(lang, "rsx.budget.title")),
        fy = bar_y - 5.0,
        fy2 = bar_y + bar_h + 5.0,
        lx = if flip { nx - 5.0 } else { nx + 5.0 },
        ly = h - 6.0,
        anchor = if flip { "end" } else { "start" },
        moved_l = esc(
            &i18n::t(lang, "rsx.budget.moved")
                .replace("{n}", &thou(moved))
                .replace("{b}", &fmt_bytes(tr.bytes_moved))
        ),
        total_l = esc(
            &i18n::t(lang, "rsx.budget.total").replace("{n}", &thou(slots))
        ),
        floor_l = esc(
            &i18n::t(lang, "rsx.budget.floor")
                .replace("{n}", &thou(need))
                .replace("{b}", &fmt_bytes(tr.necessary_bytes))
        ),
    )
}

/// Replica slots per zone, before and after. The ring's own tier table already
/// carries the ideal, so the bar can show where a zone sits against what it is
/// owed rather than only against its neighbours.
fn zone_bars(lang: &str, tiers: &[Value]) -> String {
    let zones: Vec<&Value> = tiers.iter().filter(|t| s(t, "kind") == "zone").collect();
    if zones.is_empty() {
        return String::new();
    }
    let max = zones
        .iter()
        .map(|t| f(t, "parts_after").max(f(t, "parts_before")).max(f(t, "ideal_after")))
        .fold(1.0f64, f64::max);
    let (w, row_h, pad_l, pad_r) = (640.0f64, 30.0f64, 58.0f64, 96.0f64);
    let h = zones.len() as f64 * row_h + 8.0;
    let track = w - pad_l - pad_r;
    let mut body = String::new();
    for (i, z) in zones.iter().enumerate() {
        let y = i as f64 * row_h + 8.0;
        let before = f(z, "parts_before");
        let after = f(z, "parts_after");
        let ideal = f(z, "ideal_after");
        let bw = after / max * track;
        let ix = pad_l + ideal / max * track;
        let delta = after - before;
        let tone = if delta.abs() < 0.5 {
            "rs-zone"
        } else if delta > 0.0 {
            "rs-zone gain"
        } else {
            "rs-zone loss"
        };
        body.push_str(&format!(
            "<text class=\"rs-zl\" x=\"{lx}\" y=\"{ty}\" text-anchor=\"end\">{name}</text>\
             <rect class=\"rs-zbg\" x=\"{pad_l}\" y=\"{by}\" width=\"{track}\" height=\"12\" rx=\"2\"/>\
             <rect class=\"{tone}\" x=\"{pad_l}\" y=\"{by}\" width=\"{bw:.1}\" height=\"12\" rx=\"2\"/>\
             <line class=\"rs-ideal\" x1=\"{ix:.1}\" y1=\"{iy}\" x2=\"{ix:.1}\" y2=\"{iy2}\"/>\
             <text class=\"rs-zv\" x=\"{vx}\" y=\"{ty}\">{val}</text>",
            lx = pad_l - 8.0,
            ty = y + 11.0,
            by = y + 1.0,
            iy = y - 2.0,
            iy2 = y + 15.0,
            vx = w - pad_r + 8.0,
            name = esc(s(z, "tier")),
            val = esc(&format!(
                "{} {}{}",
                thou(after as u64),
                if delta > 0.5 {
                    "+"
                } else if delta < -0.5 {
                    "-"
                } else {
                    "="
                },
                if delta.abs() >= 0.5 {
                    thou(delta.abs() as u64)
                } else {
                    String::new()
                }
            )),
        ));
    }
    format!(
        "<div class=\"mon-card wide\"><div class=\"mon-card-h\"><span class=\"mon-t\">{title}</span>\
         <span class=\"mon-legend\"><span class=\"mon-leg-i\"><i class=\"rs-ideal-sw\"></i>\
         <b>{ideal}</b></span></span></div><div class=\"mon-body\">\
         <svg class=\"rs-zones\" viewBox=\"0 0 {w} {h}\" width=\"100%\" role=\"img\" aria-label=\"{title}\">{body}</svg>\
         </div></div>",
        title = esc(i18n::t(lang, "rsx.zones.title")),
        ideal = esc(i18n::t(lang, "rsx.zones.ideal")),
    )
}

// ------------------------------------------------------------- the page

/// The whole report, rendered server-side.
///
/// Every number below comes from one `swift-ring-sim` run and one usage
/// fan-out; nothing here is cached and nothing is inferred from a previous
/// request, because a change review that quotes a stale ring is worse than no
/// change review.
pub async fn page_content(state: &Arc<AppState>, lang: &str, query: &str) -> String {
    let pairs = query_pairs(query);
    let get = |k: &str| -> Option<String> {
        pairs
            .iter()
            .find(|(a, _)| a == k)
            .map(|(_, v)| v.trim().to_string())
    };
    let policy_idx: u32 = get("policy").and_then(|v| v.parse().ok()).unwrap_or(0);
    let rebalance = pairs
        .iter()
        .rev()
        .find(|(k, _)| k == "rebalance")
        .map(|(_, v)| v != "0")
        .unwrap_or(true);
    let inspect: Option<u32> = get("part").and_then(|v| v.parse().ok());

    // A staged change that arrives malformed is dropped and counted, never
    // silently executed as something else.
    let raw_ops: Vec<String> = pairs
        .iter()
        .filter(|(k, _)| k == "op")
        .map(|(_, v)| v.clone())
        .collect();
    let mut ops: Vec<Op> = Vec::new();
    let mut dropped = 0usize;
    for r in raw_ops.iter().take(MAX_OPS) {
        match parse_op(r) {
            Some(o) => ops.push(o),
            None => dropped += 1,
        }
    }
    // A change just staged by the form arrives as kind/target/value and is
    // folded into the same op list, so the URL after the submit is the whole
    // scenario and nothing lives in a session.
    let mut form_err = String::new();
    if let Some(kind) = get("kind").filter(|k| !k.is_empty()) {
        match compose_op(&kind, get("target").unwrap_or_default().as_str(), get("value").unwrap_or_default().trim()) {
            // Staging the same change twice is meaningless, and refusing it is
            // also what stops a browser refresh from adding it again.
            Some(raw) if ops.iter().any(|x| x.raw == raw) => {}
            Some(raw) => match parse_op(&raw) {
                Some(o) if ops.len() < MAX_OPS => ops.push(o),
                Some(_) => {
                    form_err = i18n::t(lang, "rsx.err.toomany").replace("{n}", &MAX_OPS.to_string())
                }
                None => form_err = i18n::t(lang, "rsx.err.badop").to_string(),
            },
            None => form_err = i18n::t(lang, "rsx.err.badop").to_string(),
        }
    }

    let policies = match ringlab::policies(state).await {
        Ok(p) => p,
        Err(e) => return fail_page(lang, &e),
    };
    let policy = match policies.iter().find(|p| p.index == policy_idx) {
        Some(p) => p.clone(),
        None => match policies.first() {
            Some(p) => p.clone(),
            None => return fail_page(lang, i18n::t(lang, "rsx.err.nopolicies")),
        },
    };

    let replicas = 3u64;
    let scenario = json!({
        "min_readable": policy.min_readable(replicas),
        "quorum": policy.write_quorum(replicas),
        "ops": ops.iter().map(|o| o.json.clone()).collect::<Vec<_>>(),
        "rebalance": rebalance,
    });
    let mut out = match ringlab::simulate(state, policy.index, &scenario).await {
        Ok(v) => v,
        Err(e) => {
            // The scenario still renders, so the operator can correct it rather
            // than losing everything they staged to one bad change.
            let bare = i18n::t(lang, "rsx.summary.bare").replace("{policy}", &policy.name);
            return format!(
                "{}{}",
                head(lang, &policy, &policies, rebalance, &ops, &[], &bare),
                fail_page(lang, &e)
            );
        }
    };
    let usage = ringlab::device_usage(state).await;
    decorate_devices(state, &mut out, &usage);
    let rate = replication_rate(state).await;
    let tr = transfer(&usage, &out, rate);

    let empty: Vec<Value> = Vec::new();
    let devices = out
        .get("devices")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    let tiers = out
        .get("tiers")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default();
    let mv = out.get("movement").cloned().unwrap_or(Value::Null);
    let sur = out.get("survival").cloned().unwrap_or(Value::Null);
    let tb = out.get("tolerance_before").cloned().unwrap_or(Value::Null);
    let ta = out.get("tolerance_after").cloned().unwrap_or(Value::Null);
    let ring = out.get("ring").cloned().unwrap_or(Value::Null);
    let has_ops = !ops.is_empty();

    let v = verdict(lang, &out, &tr, has_ops);
    let total = u(&sur, "parts_total").max(1);
    let lost = u(&sur, "parts_lost");
    let noq = u(&sur, "parts_below_quorum");
    let moved = u(&mv, "slots_moved");
    let slots = u(&mv, "replica_slots").max(1);

    // ---- the five figures a review is actually argued over ----
    let cards = format!(
        "<div class=\"mon-grid mon-grid-5\">{}{}{}{}{}</div>",
        stat_card(
            i18n::t(lang, "rsx.card.readable"),
            &if lost > 0 {
                format!("{} / {}", thou(total - lost), thou(total))
            } else {
                i18n::t(lang, "rsx.card.all").replace("{n}", &thou(total))
            },
            if lost > 0 { "bad" } else { "ok" },
            &if lost > 0 {
                i18n::t(lang, "rsx.card.readable.bad").replace("{n}", &thou(lost))
            } else {
                i18n::t(lang, "rsx.card.readable.ok")
                    .replace("{n}", &u(&sur, "min_surviving_replicas").to_string())
            },
        ),
        stat_card(
            i18n::t(lang, "rsx.card.writable"),
            &if noq > 0 {
                format!("{} / {}", thou(total - noq), thou(total))
            } else {
                i18n::t(lang, "rsx.card.all").replace("{n}", &thou(total))
            },
            if noq > 0 { "bad" } else { "ok" },
            &if noq > 0 {
                i18n::t(lang, "rsx.card.writable.bad")
                    .replace("{q}", &u(&sur, "quorum").to_string())
            } else {
                i18n::t(lang, "rsx.card.writable.ok")
                    .replace("{q}", &u(&sur, "quorum").to_string())
            },
        ),
        stat_card(
            i18n::t(lang, "rsx.card.slots"),
            &thou(moved),
            if moved > 0 && moved as f64 / tr.necessary_slots.max(1) as f64 >= 2.0 {
                "warn"
            } else {
                ""
            },
            &i18n::t(lang, "rsx.card.slots.n")
                .replace("{pct}", &pct1(moved as f64 / slots as f64 * 100.0))
                .replace("{need}", &thou(tr.necessary_slots)),
        ),
        stat_card(
            i18n::t(lang, "rsx.card.bytes"),
            &fmt_bytes(tr.bytes_moved),
            "",
            &match tr.eta_reason {
                "rate" => i18n::t(lang, "rsx.eta.rate")
                    .replace("{t}", &fmt_dur(lang, tr.eta_secs.unwrap_or(0)))
                    .replace("{r}", &fmt_bytes(tr.rate as u64)),
                "idle" => i18n::t(lang, "rsx.eta.idle").to_string(),
                _ => i18n::t(lang, "rsx.eta.none").to_string(),
            },
        ),
        stat_card(
            i18n::t(lang, "rsx.card.tolerance"),
            &i18n::t(lang, "rsx.card.tolerance.v")
                .replace("{n}", &u(&ta, "node_loss").to_string()),
            if u(&ta, "node_loss") < u(&tb, "node_loss") {
                "bad"
            } else {
                ""
            },
            &i18n::t(lang, "rsx.card.tolerance.n")
                .replace("{zb}", &u(&tb, "zone_loss").to_string())
                .replace("{za}", &u(&ta, "zone_loss").to_string())
                .replace("{dom}", &tier_word(lang, s(&ta, "limiting_domain"))),
        ),
    );

    // ---- visuals ----
    let states = b64_decode(s(&mv, "part_states"));
    let map = partition_map(lang, &states);
    let budget = movement_bar(lang, moved, tr.necessary_slots, slots, &tr);
    let zones = zone_bars(lang, &tiers);

    // ---- device table ----
    let mut dev_rows = String::new();
    for d in &devices {
        let used = d.get("used").and_then(|v| v.as_u64());
        let size = d.get("size").and_then(|v| v.as_u64());
        let usage_cell = match (used, size) {
            (Some(us), Some(sz)) if sz > 0 => {
                let p = us as f64 / sz as f64 * 100.0;
                format!(
                    "<div class=\"rs-use\"><i style=\"width:{p:.1}%\"></i></div>\
                     <span class=\"rs-use-v\">{} / {}</span>",
                    esc(&fmt_bytes(us)),
                    esc(&fmt_bytes(sz))
                )
            }
            _ => format!("<span class=\"oc-faint\">{}</span>", esc(i18n::t(lang, "rsx.dev.nousage"))),
        };
        let before = u(d, "parts_before");
        let after = u(d, "parts_after");
        let delta = after as i64 - before as i64;
        let bal = f(d, "balance_pct");
        let state_word = match s(d, "state") {
            "ok" => i18n::t(lang, "rsx.dev.ok"),
            "down" => i18n::t(lang, "rsx.dev.down"),
            "removed" => i18n::t(lang, "rsx.dev.removed"),
            "added" => i18n::t(lang, "rsx.dev.added"),
            "" => i18n::t(lang, "rsx.dev.ok"),
            other => other,
        };
        dev_rows.push_str(&format!(
            "<tr class=\"{rowcls}\"><td>{node}</td><td>{zone}</td><td class=\"num\">{w}</td>\
             <td class=\"num\">{ideal}</td><td class=\"num\">{before}</td>\
             <td class=\"num\">{after}</td><td class=\"num {dcls}\">{delta}</td>\
             <td class=\"num {bcls}\">{bal}</td><td class=\"rs-use-c\">{usage_cell}</td>\
             <td>{state_word}</td></tr>",
            rowcls = if s(d, "state") == "down" || s(d, "state") == "removed" {
                "muted-row"
            } else {
                ""
            },
            node = esc(&format!(
                "{} / {}",
                s(d, "node"),
                s(d, "device")
            )),
            zone = esc(&format!("r{}z{}", u(d, "region"), u(d, "zone"))),
            w = f(d, "weight"),
            ideal = f(d, "ideal_after").round() as i64,
            before = thou(before),
            after = thou(after),
            dcls = if delta == 0 { "oc-faint" } else { "" },
            delta = if delta == 0 {
                "—".to_string()
            } else {
                format!("{delta:+}")
            },
            bcls = if bal.abs() > 5.0 { "oc-warn" } else { "" },
            bal = esc(&pct1(bal)),
            state_word = esc(state_word),
        ));
    }
    let dev_table = format!(
        "<div class=\"mon-card wide\"><div class=\"mon-card-h\"><span class=\"mon-t\">{title}</span>\
         <span class=\"lab-b\">{note}</span></div><div class=\"mon-body\">\
         <div class=\"tbl-wrap\"><table class=\"tbl\"><thead><tr>\
         <th>{c1}</th><th>{c2}</th><th class=\"num\">{c3}</th><th class=\"num\">{c4}</th>\
         <th class=\"num\">{c5}</th><th class=\"num\">{c6}</th><th class=\"num\">{c7}</th>\
         <th class=\"num\">{c8}</th><th>{c9}</th><th>{c10}</th></tr></thead>\
         <tbody>{dev_rows}</tbody></table></div></div></div>",
        title = esc(i18n::t(lang, "rsx.dev.title")),
        note = esc(i18n::t(lang, "rsx.dev.note")),
        c1 = esc(i18n::t(lang, "rsx.dev.c.device")),
        c2 = esc(i18n::t(lang, "rsx.dev.c.zone")),
        c3 = esc(i18n::t(lang, "rsx.dev.c.weight")),
        c4 = esc(i18n::t(lang, "rsx.dev.c.ideal")),
        c5 = esc(i18n::t(lang, "rsx.dev.c.before")),
        c6 = esc(i18n::t(lang, "rsx.dev.c.after")),
        c7 = esc(i18n::t(lang, "rsx.dev.c.delta")),
        c8 = esc(i18n::t(lang, "rsx.dev.c.balance")),
        c9 = esc(i18n::t(lang, "rsx.dev.c.disk")),
        c10 = esc(i18n::t(lang, "rsx.dev.c.state")),
    );

    // ---- where the data goes ----
    let flows = mv
        .get("flows")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let flow_sec = if flows.is_empty() {
        String::new()
    } else {
        let name = |id: u64| -> String {
            devices
                .iter()
                .find(|d| u(d, "dev_id") == id)
                .map(|d| format!("{} / {}", s(d, "node"), s(d, "device")))
                .unwrap_or_else(|| format!("dev {id}"))
        };
        let mut rows = String::new();
        let mut sorted = flows.clone();
        sorted.sort_by_key(|x| std::cmp::Reverse(u(x, "slots")));
        for x in sorted.iter().take(40) {
            rows.push_str(&format!(
                "<tr><td>{from}</td><td>{to}</td><td class=\"num\">{n}</td><td class=\"num\">{b}</td></tr>",
                from = esc(&name(u(x, "from"))),
                to = esc(&name(u(x, "to"))),
                n = thou(u(x, "slots")),
                b = esc(&fmt_bytes(tr.bytes_per_slot * u(x, "slots"))),
            ));
        }
        format!(
            "<div class=\"mon-card wide\"><div class=\"mon-card-h\"><span class=\"mon-t\">{title}</span>\
             <span class=\"lab-b\">{note}</span></div><div class=\"mon-body\">\
             <div class=\"tbl-wrap\"><table class=\"tbl\"><thead><tr><th>{c1}</th><th>{c2}</th>\
             <th class=\"num\">{c3}</th><th class=\"num\">{c4}</th></tr></thead><tbody>{rows}</tbody>\
             </table></div></div></div>",
            title = esc(i18n::t(lang, "rsx.flow.title")),
            note = esc(
                &i18n::t(lang, "rsx.flow.note").replace("{n}", &thou(flows.len() as u64))
            ),
            c1 = esc(i18n::t(lang, "rsx.flow.c.from")),
            c2 = esc(i18n::t(lang, "rsx.flow.c.to")),
            c3 = esc(i18n::t(lang, "rsx.flow.c.slots")),
            c4 = esc(i18n::t(lang, "rsx.flow.c.bytes")),
        )
    };

    // ---- partition drill-down ----
    let inspect_sec = inspect_section(state, lang, &policy, inspect, policy_idx, rebalance, &ops).await;

    // ---- what was and was not measured ----
    let warnings: Vec<String> = out
        .get("warnings")
        .and_then(|w| w.as_array())
        .unwrap_or(&empty)
        .iter()
        .filter_map(|w| w.as_str().map(|x| x.to_string()))
        .collect();
    let mut caveats = String::new();
    if !warnings.is_empty() {
        caveats.push_str(&format!(
            "<p class=\"err on\">{}</p>",
            esc(&warnings.join(" · "))
        ));
    }
    if dropped > 0 {
        caveats.push_str(&format!(
            "<p class=\"err on\">{}</p>",
            esc(&i18n::t(lang, "rsx.err.dropped").replace("{n}", &dropped.to_string()))
        ));
    }
    if !form_err.is_empty() {
        caveats.push_str(&format!("<p class=\"err on\">{}</p>", esc(&form_err)));
    }
    if out
        .get("fidelity")
        .and_then(|x| x.get("faithful"))
        .and_then(|x| x.as_bool())
        == Some(false)
    {
        caveats.push_str(&format!(
            "<p class=\"note oc-warn\">{}</p>",
            esc(i18n::t(lang, "rsx.note.unfaithful"))
        ));
    }
    let method = format!(
        "<div class=\"page-sec rs-method\"><h3>{h}</h3><p class=\"note\">{m1}</p>\
         <p class=\"note\">{m2}</p><p class=\"note\">{m3}</p></div>",
        h = esc(i18n::t(lang, "rsx.method.title")),
        m1 = esc(
            &i18n::t(lang, "rsx.method.slot")
                .replace("{b}", &fmt_bytes(tr.bytes_per_slot))
                .replace("{used}", &fmt_bytes(tr.cluster_used_bytes))
                .replace("{slots}", &thou(slots))
        ),
        m2 = esc(match tr.eta_reason {
            "rate" => i18n::t(lang, "rsx.method.eta.rate"),
            "idle" => i18n::t(lang, "rsx.method.eta.idle"),
            _ => i18n::t(lang, "rsx.method.eta.none"),
        }),
        m3 = esc(i18n::t(lang, "rsx.method.sim")),
    );

    let summary = ring_summary(lang, &policy, &ring);
    format!(
        "{head}\
<div class=\"oc-v rs-verdict\"><h2 class=\"{tone}\">{headline}</h2><p>{detail}</p></div>\
{caveats}{cards}\
<div class=\"mon-grid rs-grid\">{budget}{map}{zones}{dev_table}{flow_sec}</div>\
{inspect_sec}{method}",
        head = head(lang, &policy, &policies, rebalance, &ops, &devices, &summary),
        tone = match v.tone {
            "ok" => "oc-ok",
            "warn" => "oc-warn",
            _ => "oc-bad",
        },
        headline = esc(&v.headline),
        detail = esc(&v.detail),
    )
}

fn ring_summary(lang: &str, p: &ringlab::PolicyInfo, ring: &Value) -> String {
    let kind = if p.is_ec() {
        i18n::t(lang, "rsx.kind.ec")
            .replace("{k}", &p.ec_ndata.unwrap_or(0).to_string())
            .replace("{m}", &p.ec_nparity.unwrap_or(0).to_string())
    } else {
        i18n::t(lang, "rsx.kind.repl")
            .replace("{n}", &format!("{:.0}", f(ring, "replicas")))
    };
    i18n::t(lang, "rsx.summary")
        .replace("{policy}", &p.name)
        .replace("{kind}", &kind)
        .replace("{parts}", &thou(u(ring, "partitions")))
        .replace("{pp}", &u(ring, "part_power").to_string())
        .replace("{ver}", &u(ring, "version").to_string())
}

fn fmt_dur(lang: &str, secs: u64) -> String {
    if secs < 90 {
        i18n::t(lang, "rsx.dur.s").replace("{n}", &secs.to_string())
    } else if secs < 5400 {
        i18n::t(lang, "rsx.dur.m").replace("{n}", &(secs / 60).to_string())
    } else {
        i18n::t(lang, "rsx.dur.h").replace("{n}", &format!("{:.1}", secs as f64 / 3600.0))
    }
}

/// The scenario, as a link. A review is pasted into a ticket, so the URL has to
/// carry the whole thing.
fn qs(policy: u32, rebalance: bool, ops: &[Op], skip: Option<usize>, part: Option<u32>) -> String {
    let mut q = format!("policy={policy}");
    if !rebalance {
        q.push_str("&rebalance=0");
    }
    for (i, o) in ops.iter().enumerate() {
        if Some(i) == skip {
            continue;
        }
        q.push_str(&format!("&op={}", urlencode(&o.raw)));
    }
    if let Some(p) = part {
        q.push_str(&format!("&part={p}"));
    }
    q
}

fn fail_page(lang: &str, msg: &str) -> String {
    format!(
        "<div class=\"oc-v\"><h2 class=\"oc-bad\">{h}</h2><p>{d}</p></div>\
         <p class=\"err on\">{m}</p>",
        h = esc(i18n::t(lang, "rsx.err.h")),
        d = esc(i18n::t(lang, "rsx.err.d")),
        m = esc(msg),
    )
}

/// Page head: title, policy switch, the staged scenario, and the one form that
/// adds to it. Everything is a GET, so the back button is an undo and the URL
/// is the scenario.
fn head(
    lang: &str,
    policy: &ringlab::PolicyInfo,
    policies: &[ringlab::PolicyInfo],
    rebalance: bool,
    ops: &[Op],
    devices: &[Value],
    summary: &str,
) -> String {
    let mut opts = String::new();
    for p in policies {
        let tag = if p.is_ec() {
            format!(" (EC {}+{})", p.ec_ndata.unwrap_or(0), p.ec_nparity.unwrap_or(0))
        } else {
            String::new()
        };
        opts.push_str(&format!(
            "<option value=\"{i}\"{sel}>{n}{tag}</option>",
            i = p.index,
            sel = if p.index == policy.index { " selected" } else { "" },
            n = esc(&p.name),
        ));
    }

    let mut chips = String::new();
    for (i, o) in ops.iter().enumerate() {
        chips.push_str(&format!(
            "<span class=\"rs-chip\"><b>{label}</b>\
             <a class=\"ibtn danger\" href=\"/lab/ring?{q}\" title=\"{rm}\" aria-label=\"{rm}\">×</a></span>",
            label = esc(&op_label(lang, o, devices)),
            q = qs(policy.index, rebalance, ops, Some(i), None),
            rm = esc(i18n::t(lang, "rsx.chip.remove")),
        ));
    }

    // One select carries every target the six changes can take: a disk, or a
    // zone. Which one a change reads is decided server-side from the change
    // itself, so the form stays usable with no script at all.
    let mut targets = format!(
        "<option value=\"\">{}</option>",
        esc(i18n::t(lang, "rsx.f.notarget"))
    );
    let mut zones: Vec<(u64, u64)> = devices
        .iter()
        .map(|d| (u(d, "region"), u(d, "zone")))
        .collect();
    zones.sort_unstable();
    zones.dedup();
    for d in devices {
        targets.push_str(&format!(
            "<option value=\"d:{id}:{ip}\">{label}</option>",
            id = u(d, "dev_id"),
            ip = esc(s(d, "ip")),
            label = esc(&format!(
                "{} / {}  (r{}z{})",
                s(d, "node"),
                s(d, "device"),
                u(d, "region"),
                u(d, "zone")
            )),
        ));
    }
    for (r, z) in zones {
        targets.push_str(&format!(
            "<option value=\"z:{r}:{z}\">{}</option>",
            esc(&i18n::t(lang, "rsx.f.zoneopt").replace("{zone}", &format!("r{r}z{z}")))
        ));
    }
    let staged = if ops.is_empty() {
        i18n::t(lang, "rsx.staged.none").to_string()
    } else {
        i18n::t(lang, "rsx.staged.n").replace("{n}", &ops.len().to_string())
    };
    let reset = if ops.is_empty() {
        String::new()
    } else {
        format!(
            "<a class=\"btn sm\" href=\"/lab/ring?policy={p}\">{r}</a>",
            p = policy.index,
            r = esc(i18n::t(lang, "ring.reset"))
        )
    };

    let mut hidden = String::new();
    for o in ops {
        hidden.push_str(&format!(
            "<input type=\"hidden\" name=\"op\" value=\"{}\">",
            esc(&o.raw)
        ));
    }

    format!(
        r#"<div class="pagehead">
  <h1>{h1}</h1>
</div>
<p class="statline">{summary}</p>

<div class="rs-build">
  <form method="get" action="/lab/ring" class="rs-scen">
    <div class="rs-ops-head"><span>{scen}</span><span class="note">{staged}</span>{reset}</div>
    <div class="rs-ops">{chips}</div>
    {hidden}
    <div class="rs-add">
      <label class="rs-f"><span>{l_policy}</span>
        <select name="policy" class="filter">{opts}</select></label>
      <label class="rs-f"><span>{l_kind}</span>
        <select name="kind" class="filter">
          <option value="">{k_none}</option>
          <option value="fail_node">{k_fail_node}</option>
          <option value="fail_device">{k_fail_device}</option>
          <option value="fail_zone">{k_fail_zone}</option>
          <option value="remove_device">{k_remove_device}</option>
          <option value="set_weight">{k_set_weight}</option>
          <option value="add_device">{k_add_device}</option>
        </select></label>
      <label class="rs-f"><span>{l_target}</span>
        <select name="target" class="filter">{targets}</select></label>
      <label class="rs-f"><span>{l_value}</span>
        <input name="value" class="filter" type="text" placeholder="{ph}"></label>
      <input type="hidden" name="rebalance" value="0">
      <label class="check"><input type="checkbox" name="rebalance" value="1"{reb}> {l_reb}</label>
      <button class="btn-primary" type="submit">{run}</button>
    </div>
    <p class="note rs-hint">{hint}</p>
  </form>
</div>"#,
        h1 = esc(i18n::t(lang, "lab.tool.ring.title")),
        summary = esc(summary),
        scen = esc(i18n::t(lang, "ring.scenario")),
        staged = esc(&staged),
        l_policy = esc(i18n::t(lang, "ring.policy")),
        l_kind = esc(i18n::t(lang, "rsx.f.change")),
        l_target = esc(i18n::t(lang, "rsx.f.target")),
        l_value = esc(i18n::t(lang, "rsx.f.value")),
        l_reb = esc(i18n::t(lang, "ring.rebalance")),
        k_none = esc(i18n::t(lang, "rsx.f.nochange")),
        k_fail_node = esc(i18n::t(lang, "ring.op.fail_node")),
        k_fail_device = esc(i18n::t(lang, "ring.op.fail_device")),
        k_fail_zone = esc(i18n::t(lang, "ring.op.fail_zone")),
        k_remove_device = esc(i18n::t(lang, "ring.op.remove_device")),
        k_set_weight = esc(i18n::t(lang, "ring.op.set_weight")),
        k_add_device = esc(i18n::t(lang, "ring.op.add_device")),
        ph = esc(i18n::t(lang, "rsx.f.placeholder")),
        reb = if rebalance { " checked" } else { "" },
        run = esc(i18n::t(lang, "ring.simulate")),
        hint = esc(i18n::t(lang, "rsx.f.hint")),
    )
}

/// One partition, and the devices holding it. The map answers "how much moved";
/// this answers "moved where", which is the question that follows it.
async fn inspect_section(
    state: &Arc<AppState>,
    lang: &str,
    policy: &ringlab::PolicyInfo,
    part: Option<u32>,
    policy_idx: u32,
    rebalance: bool,
    ops: &[Op],
) -> String {
    let mut hidden = format!("<input type=\"hidden\" name=\"policy\" value=\"{policy_idx}\">");
    if !rebalance {
        hidden.push_str("<input type=\"hidden\" name=\"rebalance\" value=\"0\">");
    }
    for o in ops {
        hidden.push_str(&format!(
            "<input type=\"hidden\" name=\"op\" value=\"{}\">",
            esc(&o.raw)
        ));
    }
    let body = match part {
        None => format!(
            "<p class=\"note\">{}</p>",
            esc(i18n::t(lang, "rsx.part.empty"))
        ),
        Some(p) => match part_placement(state, policy, p).await {
            Err(e) => format!("<p class=\"err on\">{}</p>", esc(&e)),
            Ok(rows) if rows.is_empty() => format!(
                "<p class=\"note\">{}</p>",
                esc(&i18n::t(lang, "rsx.part.none").replace("{p}", &p.to_string()))
            ),
            Ok(rows) => {
                let mut body = String::new();
                for (handoff, node, dev) in &rows {
                    body.push_str(&format!(
                        "<tr><td>{role}</td><td>{node}</td><td>{dev}</td></tr>",
                        role = esc(if *handoff {
                            i18n::t(lang, "rsx.part.handoff")
                        } else {
                            i18n::t(lang, "rsx.part.primary")
                        }),
                        node = esc(node),
                        dev = esc(dev),
                    ));
                }
                format!(
                    "<p class=\"note\">{cap}</p><div class=\"tbl-wrap\"><table class=\"tbl\">\
                     <thead><tr><th>{c1}</th><th>{c2}</th><th>{c3}</th></tr></thead>\
                     <tbody>{body}</tbody></table></div>",
                    cap = esc(&i18n::t(lang, "rsx.part.cap").replace("{p}", &thou(p as u64))),
                    c1 = esc(i18n::t(lang, "rsx.part.c.role")),
                    c2 = esc(i18n::t(lang, "rsx.part.c.node")),
                    c3 = esc(i18n::t(lang, "rsx.part.c.device")),
                )
            }
        },
    };
    format!(
        "<div class=\"page-sec rs-inspect\"><h3>{title}</h3>\
         <form method=\"get\" action=\"/lab/ring\" class=\"rs-add\">{hidden}\
         <label class=\"rs-f\"><span>{label}</span>\
         <input class=\"filter\" type=\"number\" name=\"part\" min=\"0\" value=\"{v}\"></label>\
         <button class=\"btn sm\" type=\"submit\">{go}</button></form>{body}</div>",
        title = esc(i18n::t(lang, "rsx.part.title")),
        label = esc(i18n::t(lang, "rsx.part.label")),
        v = part.map(|p| p.to_string()).unwrap_or_default(),
        go = esc(i18n::t(lang, "rsx.part.go")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(v: Value) -> Vec<Value> {
        vec![v]
    }

    #[test]
    fn rejects_unknown_operations() {
        let e = validate(&op(json!({"op": "rm -rf"}))).unwrap_err();
        assert!(e.contains("unknown operation"), "{e}");
    }

    #[test]
    fn rejects_out_of_range_weight() {
        assert!(validate(&op(json!({"op":"set_weight","dev_id":0,"weight":-1}))).is_err());
        assert!(validate(&op(json!({"op":"set_weight","dev_id":0,"weight":99999}))).is_err());
        assert!(validate(&op(json!({"op":"set_weight","dev_id":0,"weight":50.0}))).is_ok());
    }

    #[test]
    fn rejects_non_numeric_identifiers() {
        let e = validate(&op(json!({"op":"fail_device","dev_id":"0; rm"}))).unwrap_err();
        assert!(e.contains("dev_id must be a number"), "{e}");
    }

    #[test]
    fn rejects_shell_ish_strings_in_text_fields() {
        assert!(validate(&op(json!({"op":"fail_node","ip":"10.0.0.1 && reboot"}))).is_err());
        assert!(validate(&op(json!({"op":"fail_node","ip":"10.0.0.1"}))).is_ok());
    }

    #[test]
    fn caps_the_number_of_operations() {
        let many: Vec<Value> = (0..40).map(|_| json!({"op":"fail_device","dev_id":0})).collect();
        assert!(validate(&many).is_err());
    }

    #[test]
    fn accepts_a_realistic_scenario() {
        let ops = vec![
            json!({"op":"fail_node","ip":"10.42.10.12"}),
            json!({"op":"add_device","region":1,"zone":4,"ip":"10.42.10.14",
                   "port":6200,"device":"d1","weight":100.0}),
        ];
        assert!(validate(&ops).is_ok());
    }

    #[test]
    fn scenario_ops_round_trip_through_the_url() {
        let o = parse_op("add_device:1,4,10.42.10.14,d4,100").expect("parses");
        assert_eq!(o.json["region"], 1);
        assert_eq!(o.json["zone"], 4);
        assert_eq!(o.json["device"], "d4");
        assert_eq!(o.json["weight"], 100.0);
        let w = parse_op("set_weight:3:50").expect("parses");
        assert_eq!(w.json["dev_id"], 3);
        assert_eq!(w.json["weight"], 50.0);
    }

    #[test]
    fn a_hand_edited_url_cannot_smuggle_an_operation() {
        assert!(parse_op("rm:-rf").is_none());
        assert!(parse_op("fail_node").is_none());
        assert!(parse_op("fail_device:not-a-number").is_none());
        assert!(parse_op("set_weight:1:99999").is_none(), "weight is bounded");
        // A shell-ish IP survives parsing only to be refused by validate().
        assert!(parse_op("fail_node:10.0.0.1 && reboot").is_none());
    }

    #[test]
    fn urldecode_handles_percent_and_plus() {
        assert_eq!(urldecode("a%2Cb"), "a,b");
        assert_eq!(urldecode("a+b"), "a b");
        assert_eq!(urldecode("%zz"), "%zz");
    }

    #[test]
    fn query_pairs_keeps_repeated_keys() {
        let p = query_pairs("policy=1&op=a%3Ab&op=c%3Ad");
        assert_eq!(p.len(), 3);
        assert_eq!(p[1], ("op".into(), "a:b".into()));
        assert_eq!(p[2], ("op".into(), "c:d".into()));
    }

    #[test]
    fn base64_decodes_the_partition_state_array() {
        // "AAAB" -> 0x00 0x00 0x01
        assert_eq!(b64_decode("AAAB"), vec![0, 0, 1]);
        assert_eq!(b64_decode("AwID"), vec![3, 2, 3]);
    }

    /// The floor is what makes a movement figure mean anything: a rebalance
    /// that moves ten times what it had to is a finding, and the ring never
    /// says so on its own.
    #[test]
    fn necessary_slots_is_what_growing_devices_must_receive() {
        let devs = vec![
            json!({"parts_before": 257.0, "ideal_after": 236.3}),
            json!({"parts_before": 256.0, "ideal_after": 236.3}),
            json!({"parts_before": 0.0, "ideal_after": 236.3}),
        ];
        // Only the empty device is owed anything; the two shrinking ones are
        // not forced to receive a single slot.
        assert_eq!(necessary_slots(&devs), 236);
    }

    #[test]
    fn necessary_slots_is_zero_for_an_untouched_ring() {
        let devs = vec![
            json!({"parts_before": 256.0, "ideal_after": 256.0}),
            json!({"parts_before": 256.0, "ideal_after": 256.0}),
        ];
        assert_eq!(necessary_slots(&devs), 0);
    }

    #[test]
    fn an_idle_replication_plane_yields_no_eta_rather_than_a_fantasy() {
        let usage = vec![ringlab::DeviceUsage {
            node: "swift1".into(),
            device: "d1".into(),
            used: 1_000_000_000,
            size: 2_000_000_000,
        }];
        let out = json!({
            "movement": {"slots_moved": 100, "replica_slots": 1000},
            "devices": [{"parts_before": 0.0, "ideal_after": 100.0}],
        });
        let t = transfer(&usage, &out, 1024.0);
        assert_eq!(t.eta_reason, "idle");
        assert!(t.eta_secs.is_none());
        // ...but a busy plane does get one.
        let t2 = transfer(&usage, &out, 100.0 * 1024.0 * 1024.0);
        assert_eq!(t2.eta_reason, "rate");
        assert!(t2.eta_secs.is_some());
    }

    /// Pulling a disk is keyed by device id and taking a node offline by
    /// address. Reading the wrong half of the target would fail the wrong
    /// hardware and report a scenario nobody asked for.
    #[test]
    fn the_form_composes_the_right_op_from_one_target() {
        assert_eq!(
            compose_op("fail_device", "d:3:10.42.10.12", ""),
            Some("fail_device:3".into())
        );
        assert_eq!(
            compose_op("fail_node", "d:3:10.42.10.12", ""),
            Some("fail_node:10.42.10.12".into())
        );
        assert_eq!(
            compose_op("fail_zone", "z:1:4", ""),
            Some("fail_zone:1:4".into())
        );
        assert_eq!(
            compose_op("set_weight", "d:3:10.42.10.12", "50"),
            Some("set_weight:3:50".into())
        );
        // A change that needs a value or a target and did not get one is
        // refused, not guessed at.
        assert!(compose_op("set_weight", "d:3:10.42.10.12", "").is_none());
        assert!(compose_op("fail_zone", "d:3:10.42.10.12", "").is_none());
        assert!(compose_op("add_device", "", "1,4,10.42.10.14").is_none());
    }

    /// An unchecked box submits nothing at all, so the hidden `rebalance=0`
    /// that precedes it is the only thing that can turn the option off. The
    /// last value wins, or a checked box would read as unchecked.
    #[test]
    fn the_rebalance_switch_can_actually_be_switched_off() {
        let last = |q: &str| -> bool {
            query_pairs(q)
                .iter()
                .rev()
                .find(|(k, _)| k == "rebalance")
                .map(|(_, v)| v != "0")
                .unwrap_or(true)
        };
        assert!(last("policy=0"), "absent means the default, which is on");
        assert!(last("rebalance=0&rebalance=1"), "box checked");
        assert!(!last("rebalance=0"), "box unchecked");
    }

    #[test]
    fn thousands_separators() {
        assert_eq!(thou(0), "0");
        assert_eq!(thou(999), "999");
        assert_eq!(thou(3072), "3,072");
        assert_eq!(thou(1234567), "1,234,567");
    }
}
