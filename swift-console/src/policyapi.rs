//! HTTP surface and report for Policy Economist.
//!
//! Defaults are read from the live cluster rather than invented, so the first
//! answer the page gives is about *this* cluster — including the uncomfortable
//! parts, like which schemes will not fit on it.
//!
//! The report is rendered here, not in the browser: a capacity decision gets
//! quoted in a plan, so the recommendation, the arithmetic behind it and the
//! trade-off chart all have to be in the first response.

use crate::economist::{self, Candidate, Inputs, Recommendation, Row};
use crate::i18n;
use crate::lab;
use crate::nodes;
use crate::ringlab;
use crate::util::{esc, ix_mount};
use crate::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::sync::Arc;

/// What the cluster actually looks like, measured rather than configured.
pub struct Cluster {
    pub node_count: u32,
    pub devices_total: u32,
    pub zone_count: u32,
    pub device_tb: f64,
    /// Total raw bytes across every device the rings reference.
    pub capacity_tb: f64,
    /// Logical data stored today, backed out of raw usage by the default
    /// policy's amplification.
    pub stored_tb: f64,
    pub policies: Vec<String>,
    /// True when no device answered `df`; every capacity figure below is then
    /// a guess, and the page says so instead of printing zeros.
    pub usage_unknown: bool,
}

pub async fn cluster_facts(state: &Arc<AppState>) -> Cluster {
    let nodes_list = nodes::all(state);
    let usage = ringlab::device_usage(state).await;
    // Count the devices the RING holds, not the ones the config file lists.
    // Summing the config made a 9-device cluster report 3, and the Economist
    // then refused EC schemes it could in fact accommodate — a wrong answer
    // delivered with full confidence, which is worse than no answer.
    let devices_total = ringlab::ring_devices(state).await.len() as u32;
    let zones: std::collections::BTreeSet<u64> = nodes_list.iter().map(|n| n.zone).collect();
    let device_tb = usage
        .iter()
        .map(|u| u.size as f64 / 1e12)
        .fold(0.0f64, f64::max);
    let capacity_tb: f64 = usage.iter().map(|u| u.size as f64 / 1e12).sum();
    let used_raw_tb: f64 = usage.iter().map(|u| u.used as f64 / 1e12).sum();
    let policies = ringlab::policies(state).await.unwrap_or_default();
    let replicas = 3.0;
    Cluster {
        node_count: nodes_list.len() as u32,
        devices_total,
        zone_count: zones.len() as u32,
        device_tb: (device_tb * 1000.0).round() / 1000.0,
        capacity_tb: (capacity_tb * 1000.0).round() / 1000.0,
        stored_tb: ((used_raw_tb / replicas) * 1000.0).round() / 1000.0,
        policies: policies.iter().map(|p| p.name.clone()).collect(),
        usage_unknown: usage.is_empty(),
    }
}

/// What the cluster actually looks like, for prefilling the form.
pub async fn defaults(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let c = cluster_facts(&state).await;
    Json(json!({
        "cluster": {
            "node_count": c.node_count,
            "devices_total": c.devices_total,
            "zone_count": c.zone_count,
            "device_tb": c.device_tb,
            "capacity_tb": c.capacity_tb,
            "stored_tb": c.stored_tb,
            "policies": c.policies,
            "usage_unknown": c.usage_unknown,
        },
        "suggested": {
            "raw_tb": suggested_raw_tb(&c),
            "disk_cost_per_tb_year": 20.0,
            "cross_rack_gbps": 10.0,
            "target_durability_nines": 11.0,
            "max_repair_hours": 8.0,
            "tolerate_node_loss": 1,
            "years": 5.0,
        }
    }))
    .into_response()
}

/// The default question: "what would it cost to fill this cluster?" A fixed
/// 1000 TB was the old default and it described somebody else's hardware, so
/// every figure on the first render was fiction.
fn suggested_raw_tb(c: &Cluster) -> f64 {
    let usable = c.capacity_tb / 3.0;
    if usable > 0.001 {
        (usable * 1000.0).round() / 1000.0
    } else {
        1.0
    }
}

#[derive(serde::Deserialize)]
pub struct CompareReq {
    #[serde(flatten)]
    pub inputs: Inputs,
}

pub async fn compare(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CompareReq>,
) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let inp = req.inputs;
    if inp.candidates.is_empty() || inp.candidates.len() > 12 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "between 1 and 12 candidates"})),
        )
            .into_response();
    }
    if !(inp.raw_tb.is_finite() && inp.raw_tb > 0.0) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "data volume must be a positive number"})),
        )
            .into_response();
    }
    let rows = economist::evaluate(&inp);
    let rec = economist::recommend(&rows);
    Json(json!({ "rows": rows, "recommendation": rec })).into_response()
}

/// The default candidate set: what an operator would actually weigh up.
pub fn default_candidates() -> Vec<Candidate> {
    vec![
        Candidate::Replication { replicas: 3 },
        Candidate::Replication { replicas: 2 },
        Candidate::Ec { k: 2, m: 1, ec_type: "liberasurecode_rs_vand".into() },
        Candidate::Ec { k: 4, m: 2, ec_type: "liberasurecode_rs_vand".into() },
        Candidate::Ec { k: 8, m: 3, ec_type: "liberasurecode_rs_vand".into() },
    ]
}

// ------------------------------------------------------------- rendering

fn qnum(pairs: &[(String, String)], key: &str, dflt: f64) -> f64 {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite())
        .unwrap_or(dflt)
}

fn query_pairs(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_string(), v.replace('+', " ")))
        .collect()
}

/// A candidate's name in the reader's language. "EC 2+1" stays as it is —
/// operators say it that way in both — but "3× replication" does not.
fn row_label(lang: &str, r: &Row) -> String {
    if r.kind == "erasure_coding" {
        format!("EC {}+{}", r.ec_k, r.ec_m)
    } else {
        i18n::t(lang, "pol.label.repl").replace("{n}", &r.replicas.to_string())
    }
}

fn money(v: f64) -> String {
    if v >= 1e9 {
        format!("{:.2}B", v / 1e9)
    } else if v >= 1e6 {
        format!("{:.2}M", v / 1e6)
    } else if v >= 1e3 {
        format!("{:.1}k", v / 1e3)
    } else {
        format!("{v:.0}")
    }
}

fn tb(v: f64) -> String {
    if v >= 1000.0 {
        format!("{:.2} PB", v / 1000.0)
    } else if v >= 1.0 {
        format!("{v:.1} TB")
    } else {
        format!("{:.0} GB", v * 1000.0)
    }
}

fn hours(lang: &str, v: f64) -> String {
    if !v.is_finite() {
        return i18n::t(lang, "pol.u.inf").to_string();
    }
    if v < 1.0 {
        i18n::t(lang, "pol.u.min").replace("{n}", &format!("{:.0}", v * 60.0))
    } else if v < 48.0 {
        i18n::t(lang, "pol.u.h").replace("{n}", &format!("{v:.1}"))
    } else {
        i18n::t(lang, "pol.u.d").replace("{n}", &format!("{:.1}", v / 24.0))
    }
}

/// What goes between two finished sentences. English needs a space; Chinese
/// sentences already end in a full-width stop, and a space after one reads as
/// a typo rather than as punctuation.
fn gap(lang: &str) -> &'static str {
    if lang == "zh" {
        ""
    } else {
        " "
    }
}

fn reason_text(lang: &str, r: &economist::Reason) -> String {
    match r {
        economist::Reason::NeedsDevices { need, have, .. } => i18n::t(lang, "pol.why.devices")
            .replace("{need}", &need.to_string())
            .replace("{have}", &have.to_string()),
        economist::Reason::FewerZones { need, zones, .. } => i18n::t(lang, "pol.why.zones")
            .replace("{need}", &need.to_string())
            .replace("{zones}", &zones.to_string()),
        economist::Reason::NoWriteMargin { .. } => i18n::t(lang, "pol.why.margin").to_string(),
    }
}

/// The trade-off, drawn: money along the bottom, durability up the side, and
/// the size of the mark is how much a single disk replacement has to read.
///
/// Those three are what actually argue with each other, and a table puts them
/// in three different rows where nobody compares them.
fn tradeoff(lang: &str, rows: &[Row], rec: &Recommendation, target_nines: f64) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let title = i18n::t(lang, "pol.chart.title");
    let points: Vec<serde_json::Value> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let state = if !r.feasible {
                "out"
            } else if r.meets_all() {
                "ok"
            } else {
                "miss"
            };
            json!({
                "label": row_label(lang, r),
                "x": r.tco,
                "y": r.durability_nines,
                "r": r.rebuild_read_tb,
                "state": state,
                "pick": rec.best == Some(i),
                "tip": format!(
                    "{} · {} · {} · {}",
                    row_label(lang, r),
                    money(r.tco),
                    i18n::t(lang, "pol.chart.nines").replace("{n}", &format!("{:.1}", r.durability_nines)),
                    i18n::t(lang, "pol.chart.rebuild").replace("{v}", &tb(r.rebuild_read_tb)),
                ),
            })
        })
        .collect();
    let data = json!({
        "title": title,
        "xLabel": i18n::t(lang, "pol.chart.axes"),
        "yLabel": "",
        "targetY": target_nines,
        "targetLabel": i18n::t(lang, "pol.chart.target").replace("{n}", &format!("{target_nines:.0}")),
        "legend": {
            "ok": i18n::t(lang, "pol.chart.k.ok"),
            "miss": i18n::t(lang, "pol.chart.k.miss"),
            "out": i18n::t(lang, "pol.chart.k.out"),
        },
        "points": points,
    });
    format!(
        "<div class=\"mon-card wide\"><div class=\"mon-card-h\"><span class=\"mon-t\">{title}</span></div>\
         <div class=\"mon-body\">{mount}<div class=\"lab-b\">{axes}</div></div></div>",
        title = esc(title),
        mount = ix_mount("scatter", &data),
        axes = esc(i18n::t(lang, "pol.chart.axes")),
    )
}

/// Repair time against the ceiling the operator set. Durability and cost are
/// the loud pair; rebuild time is the one that decides whether a bad week
/// becomes a bad month, so it gets its own row rather than a footnote.
fn repair_bars(lang: &str, rows: &[Row], limit: f64) -> String {
    let max = rows
        .iter()
        .map(|r| if r.repair_hours.is_finite() { r.repair_hours } else { 0.0 })
        .fold(limit, f64::max)
        * 1.1;
    if max <= 0.0 {
        return String::new();
    }
    let title = i18n::t(lang, "pol.repair.title");
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let v = if r.repair_hours.is_finite() {
                r.repair_hours
            } else {
                max
            };
            json!({
                "label": row_label(lang, r),
                "value": v,
                "display": hours(lang, r.repair_hours),
                "ok": r.meets_repair_time,
                "tip": row_label(lang, r),
            })
        })
        .collect();
    let data = json!({
        "title": title,
        "limit": limit,
        "limitLabel": i18n::t(lang, "pol.repair.limit").replace("{n}", &hours(lang, limit)),
        "items": items,
    });
    format!(
        "<div class=\"mon-card wide\"><div class=\"mon-card-h\"><span class=\"mon-t\">{title}</span></div>\
         <div class=\"mon-body\">{mount}<div class=\"lab-b\">{note}</div></div></div>",
        title = esc(title),
        mount = ix_mount("hbar", &data),
        note = esc(i18n::t(lang, "pol.repair.note")),
    )
}

/// The recommendation, in one sentence, then the reasoning under it.
fn recommendation_block(
    lang: &str,
    rows: &[Row],
    rec: &Recommendation,
    inp: &Inputs,
) -> String {
    let (tone, headline, detail) = match (rec.outcome, rec.best) {
        ("none", _) | (_, None) => (
            "oc-bad",
            i18n::t(lang, "pol.rec.none.h").to_string(),
            i18n::t(lang, "pol.rec.none.d")
                .replace("{devices}", &inp.devices_total.to_string())
                .replace("{zones}", &inp.zone_count.to_string()),
        ),
        (kind, Some(i)) => {
            let r = &rows[i];
            let label = row_label(lang, r);
            let head_key = if kind == "meets_all" {
                "pol.rec.pick.h"
            } else {
                "pol.rec.compromise.h"
            };
            let headline = i18n::t(lang, head_key)
                .replace("{name}", &label)
                .replace("{cost}", &money(r.tco))
                .replace("{years}", &format!("{:.0}", inp.years))
                .replace(
                    "{miss}",
                    &rec.unmet
                        .iter()
                        .map(|u| {
                            match *u {
                                "durability" => i18n::t(lang, "pol.unmet.durability"),
                                "repair" => i18n::t(lang, "pol.unmet.repair"),
                                _ => i18n::t(lang, "pol.unmet.loss"),
                            }
                            .to_string()
                        })
                        .collect::<Vec<_>>()
                        .join(i18n::t(lang, "pol.unmet.join")),
                );
            // Why, in the terms the decision is actually made in: what it
            // stores, what it survives, and what it costs against the
            // alternative somebody will ask about.
            let mut detail = i18n::t(lang, "pol.rec.why")
                .replace("{name}", &label)
                .replace("{amp}", &format!("{:.2}", r.amplification))
                .replace("{raw}", &tb(r.raw_needed_tb))
                .replace("{data}", &tb(inp.raw_tb))
                .replace("{loss}", &r.tolerates_loss.to_string())
                .replace("{nines}", &format!("{:.1}", r.durability_nines))
                .replace("{repair}", &hours(lang, r.repair_hours));
            if r.write_margin == 0 {
                detail.push_str(gap(lang));
                detail.push_str(
                    &i18n::t(lang, "pol.rec.nomargin")
                        .replace("{q}", &r.write_quorum.to_string())
                        .replace("{n}", &r.write_fanout.to_string()),
                );
            }
            // A recommendation that hides its own caveat is how a plan ends up
            // with eleven fragments spread over four zones. The write-margin
            // case already has its own sentence above; everything else the
            // model flagged about the winner is said here rather than left in
            // a table row nobody scrolls to.
            let rest: Vec<String> = r
                .reasons
                .iter()
                .filter(|x| !matches!(x, economist::Reason::NoWriteMargin { .. }))
                .map(|x| reason_text(lang, x))
                .collect();
            if !rest.is_empty() {
                detail.push_str(gap(lang));
                detail.push_str(
                    &i18n::t(lang, "pol.rec.caveat").replace("{why}", &rest.join("; ")),
                );
            }
            if let Some(j) = rec.runner_up {
                let o = &rows[j];
                let delta = o.tco - r.tco;
                let key = if delta > 0.0 {
                    "pol.rec.runner.dearer"
                } else {
                    "pol.rec.runner.cheaper"
                };
                detail.push_str(gap(lang));
                detail.push_str(
                    &i18n::t(lang, key)
                        .replace("{name}", &row_label(lang, o))
                        .replace("{delta}", &money(delta.abs()))
                        .replace("{margin}", &o.write_margin.to_string())
                        .replace("{loss}", &o.tolerates_loss.to_string()),
                );
            }
            (
                if kind == "meets_all" { "oc-ok" } else { "oc-warn" },
                headline,
                detail,
            )
        }
    };
    format!(
        "<div class=\"oc-v pe-rec\"><h2 class=\"{tone}\">{h}</h2><p>{d}</p></div>",
        h = esc(&headline),
        d = esc(&detail),
    )
}

/// Exact numbers for the fold-out table. Charts are the reading surface; this
/// is the audit trail for a change review that needs the same digits.
fn comparison_table(lang: &str, rows: &[Row], rec: &Recommendation) -> String {
    let head = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            format!(
                "<th class=\"num{x}{p}\">{l}</th>",
                x = if r.feasible { "" } else { " pe-x" },
                p = if rec.best == Some(i) { " pe-pick-col" } else { "" },
                l = esc(&row_label(lang, r)),
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let metrics: Vec<(&'static str, Box<dyn Fn(&Row) -> String>)> = vec![
        (
            "pol.m.amp",
            Box::new(|r: &Row| format!("{:.2}×", r.amplification)),
        ),
        ("pol.m.raw", Box::new(|r: &Row| tb(r.raw_needed_tb))),
        (
            "pol.m.devices",
            Box::new(|r: &Row| r.min_devices.to_string()),
        ),
        (
            "pol.m.fanout",
            Box::new(|r: &Row| r.write_fanout.to_string()),
        ),
        (
            "pol.m.quorum",
            Box::new(|r: &Row| r.write_quorum.to_string()),
        ),
        (
            "pol.m.margin",
            Box::new(|r: &Row| r.write_margin.to_string()),
        ),
        (
            "pol.m.readmin",
            Box::new(|r: &Row| r.read_min_devices.to_string()),
        ),
        (
            "pol.m.survives",
            Box::new(|r: &Row| r.tolerates_loss.to_string()),
        ),
        (
            "pol.m.rebuild",
            Box::new(|r: &Row| tb(r.rebuild_read_tb)),
        ),
        ("pol.m.repair", Box::new(move |r: &Row| hours(lang, r.repair_hours))),
        (
            "pol.m.nines",
            Box::new(|r: &Row| format!("{:.1}", r.durability_nines)),
        ),
        ("pol.m.cost", Box::new(|r: &Row| money(r.tco))),
    ];
    let mut body = String::new();
    for (key, f) in &metrics {
        body.push_str(&format!(
            "<tr><td>{k}</td>{cells}</tr>",
            k = esc(i18n::t(lang, *key)),
            cells = rows
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    format!(
                        "<td class=\"num{x}{p}\">{v}</td>",
                        x = if r.feasible { "" } else { " pe-x" },
                        p = if rec.best == Some(i) { " pe-pick-col" } else { "" },
                        v = esc(&f(r))
                    )
                })
                .collect::<Vec<_>>()
                .join(""),
        ));
    }
    for (key, get) in [
        ("pol.m.meets.dur", 0usize),
        ("pol.m.meets.repair", 1),
        ("pol.m.meets.loss", 2),
    ] {
        body.push_str(&format!(
            "<tr><td>{k}</td>{cells}</tr>",
            k = esc(i18n::t(lang, key)),
            cells = rows
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    let ok = match get {
                        0 => r.meets_durability,
                        1 => r.meets_repair_time,
                        _ => r.meets_node_loss,
                    };
                    format!(
                        "<td class=\"num {c}{x}{p}\">{v}</td>",
                        c = if ok { "pe-ok" } else { "pe-no" },
                        x = if r.feasible { "" } else { " pe-x" },
                        p = if rec.best == Some(i) { " pe-pick-col" } else { "" },
                        v = if ok {
                            esc(i18n::t(lang, "pol.yes"))
                        } else {
                            esc(i18n::t(lang, "pol.no"))
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join(""),
        ));
    }
    // The caveat sits in the column it belongs to. Dropping an infeasible
    // candidate, or exiling its reason to a footnote, is how a comparison ends
    // up looking like a choice nobody had.
    body.push_str(&format!(
        "<tr class=\"pe-why\"><td>{k}</td>{cells}</tr>",
        k = esc(i18n::t(lang, "pol.m.why")),
        cells = rows
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let txt = if r.reasons.is_empty() {
                    i18n::t(lang, "pol.why.none").to_string()
                } else {
                    r.reasons
                        .iter()
                        .map(|x| reason_text(lang, x))
                        .collect::<Vec<_>>()
                        .join(" · ")
                };
                format!(
                    "<td class=\"pe-why-c{p}\">{v}</td>",
                    p = if rec.best == Some(i) { " pe-pick-col" } else { "" },
                    v = esc(&txt)
                )
            })
            .collect::<Vec<_>>()
            .join(""),
    ));

    format!(
        "<div class=\"tbl-wrap\"><table class=\"tbl pe-tbl\">\
         <thead><tr><th>{metric}</th>{head}</tr></thead><tbody>{body}</tbody></table></div>",
        metric = esc(i18n::t(lang, "pol.table.metric")),
    )
}

/// One HTML bar chart per metric (CSS tracks, not SVG). Magnitudes only
/// compare within a metric; each bar keeps its exact formatted value.
fn comparison_charts(lang: &str, rows: &[Row], rec: &Recommendation) -> String {
    if rows.is_empty() {
        return String::new();
    }

    let mut legend = String::new();
    for (i, r) in rows.iter().enumerate() {
        let mark = if rec.best == Some(i) {
            format!(
                " <em class=\"pe-pick-mark\">{}</em>",
                esc(i18n::t(lang, "pol.chart.pick"))
            )
        } else {
            String::new()
        };
        let bad = if r.feasible {
            String::new()
        } else {
            format!(
                " <em class=\"pe-infeasible\">{}</em>",
                esc(i18n::t(lang, "pol.chart.infeasible"))
            )
        };
        legend.push_str(&format!(
            "<span class=\"mon-leg-i\"><i class=\"pe-sw mon-s{n}\"></i><b>{l}</b>{mark}{bad}</span>",
            n = (i % 6) + 1,
            l = esc(&row_label(lang, r)),
        ));
    }

    // dir: -1 lower better, +1 higher better, 0 no best mark
    let metrics: [(&str, i8, Box<dyn Fn(&Row) -> f64>, Box<dyn Fn(&Row) -> String>); 12] = [
        (
            "pol.m.amp",
            -1,
            Box::new(|r| r.amplification),
            Box::new(|r| format!("{:.2}×", r.amplification)),
        ),
        (
            "pol.m.raw",
            -1,
            Box::new(|r| r.raw_needed_tb),
            Box::new(|r| tb(r.raw_needed_tb)),
        ),
        (
            "pol.m.devices",
            -1,
            Box::new(|r| r.min_devices as f64),
            Box::new(|r| r.min_devices.to_string()),
        ),
        (
            "pol.m.fanout",
            -1,
            Box::new(|r| r.write_fanout as f64),
            Box::new(|r| r.write_fanout.to_string()),
        ),
        (
            "pol.m.quorum",
            0,
            Box::new(|r| r.write_quorum as f64),
            Box::new(|r| r.write_quorum.to_string()),
        ),
        (
            "pol.m.margin",
            1,
            Box::new(|r| r.write_margin as f64),
            Box::new(|r| r.write_margin.to_string()),
        ),
        (
            "pol.m.readmin",
            -1,
            Box::new(|r| r.read_min_devices as f64),
            Box::new(|r| r.read_min_devices.to_string()),
        ),
        (
            "pol.m.survives",
            1,
            Box::new(|r| r.tolerates_loss as f64),
            Box::new(|r| r.tolerates_loss.to_string()),
        ),
        (
            "pol.m.rebuild",
            -1,
            Box::new(|r| r.rebuild_read_tb),
            Box::new(|r| tb(r.rebuild_read_tb)),
        ),
        (
            "pol.m.repair",
            -1,
            Box::new(|r| r.repair_hours),
            Box::new(move |r| hours(lang, r.repair_hours)),
        ),
        (
            "pol.m.nines",
            1,
            Box::new(|r| r.durability_nines),
            Box::new(|r| format!("{:.1}", r.durability_nines)),
        ),
        (
            "pol.m.cost",
            -1,
            Box::new(|r| r.tco),
            Box::new(|r| money(r.tco)),
        ),
    ];

    let mut grid = String::new();
    for (key, dir, val, fmt) in &metrics {
        let max = rows
            .iter()
            .map(|r| val(r).abs())
            .fold(0.0_f64, f64::max);
        let mut best: Option<f64> = None;
        if *dir != 0 {
            for r in rows {
                if !r.feasible {
                    continue;
                }
                let v = val(r);
                best = Some(match best {
                    None => v,
                    Some(b) if *dir > 0 => b.max(v),
                    Some(b) => b.min(v),
                });
            }
        }
        let dir_l = match *dir {
            1 => format!(
                "<i class=\"pe-dir\">{}</i>",
                esc(i18n::t(lang, "pol.dir.higher"))
            ),
            -1 => format!(
                "<i class=\"pe-dir\">{}</i>",
                esc(i18n::t(lang, "pol.dir.lower"))
            ),
            _ => String::new(),
        };
        let mut brow = String::new();
        for (i, r) in rows.iter().enumerate() {
            let v = val(r);
            let pct = if max > 0.0 {
                ((v.abs() / max) * 100.0).max(2.0)
            } else {
                2.0
            };
            let is_best = r.feasible && best.is_some_and(|b| (v - b).abs() < 1e-12);
            brow.push_str(&format!(
                "<div class=\"pe-brow{dim}\" title=\"{tip}\">\
                   <span class=\"pe-blab\">{lab}</span>\
                   <div class=\"pe-btrack\" role=\"img\" aria-label=\"{aria}\">\
                     <div class=\"pe-bbar mon-s{n}\" style=\"width:{pct:.1}%\"></div>\
                   </div>\
                   <span class=\"pe-bval{best}\">{fv}{dot}</span>\
                 </div>",
                dim = if r.feasible { "" } else { " pe-dim" },
                tip = esc(&format!(
                    "{} · {}{}",
                    row_label(lang, r),
                    fmt(r),
                    if is_best {
                        format!(" · {}", i18n::t(lang, "pol.chart.best"))
                    } else {
                        String::new()
                    }
                )),
                lab = esc(&row_label(lang, r)),
                aria = esc(&format!("{}: {}", row_label(lang, r), fmt(r))),
                n = (i % 6) + 1,
                pct = pct,
                best = if is_best { " best" } else { "" },
                fv = esc(&fmt(r)),
                dot = if is_best { " ●" } else { "" },
            ));
        }
        grid.push_str(&format!(
            "<div class=\"pe-metric\"><div class=\"pe-metric-t\"><b>{t}</b>{dir}</div>{brow}</div>",
            t = esc(i18n::t(lang, key)),
            dir = dir_l,
        ));
    }

    let mut cons = String::new();
    for (key, get) in [
        ("pol.m.meets.dur", 0usize),
        ("pol.m.meets.repair", 1),
        ("pol.m.meets.loss", 2),
    ] {
        let mut chips = String::new();
        for r in rows {
            let ok = match get {
                0 => r.meets_durability,
                1 => r.meets_repair_time,
                _ => r.meets_node_loss,
            };
            chips.push_str(&format!(
                "<span class=\"pe-chip {c}{dim}\">{mark} {lab}</span>",
                c = if ok { "ok" } else { "no" },
                dim = if r.feasible { "" } else { " pe-dim" },
                mark = if ok { "✓" } else { "✗" },
                lab = esc(&row_label(lang, r)),
            ));
        }
        cons.push_str(&format!(
            "<div class=\"pe-conrow\"><span class=\"pe-blab\">{k}</span>\
             <div class=\"pe-chips\">{chips}</div></div>",
            k = esc(i18n::t(lang, key)),
        ));
    }

    format!(
        "<div class=\"pe-charts\">\
           <div class=\"pe-legend\">{legend}</div>\
           <div class=\"pe-mgrid\">{grid}</div>\
           <div class=\"pe-cons\">\
             <div class=\"pe-metric-t\"><b>{ct}</b></div>{cons}\
           </div>\
         </div>",
        legend = legend,
        grid = grid,
        ct = esc(i18n::t(lang, "pol.cons.title")),
        cons = cons,
    )
}

fn comparison(lang: &str, rows: &[Row], rec: &Recommendation) -> String {
    let charts = comparison_charts(lang, rows, rec);
    let table = comparison_table(lang, rows, rec);
    format!(
        "<div class=\"mon-card wide\"><div class=\"mon-card-h\"><span class=\"mon-t\">{title}</span>\
         </div><div class=\"mon-body\">{charts}\
         <details class=\"rs-det\"><summary>{toggle}</summary>{table}</details>\
         </div></div>",
        title = esc(i18n::t(lang, "pol.table.title")),
        toggle = esc(i18n::t(lang, "rsx.table.toggle")),
        charts = charts,
        table = table,
    )
}

pub async fn page_content(state: &Arc<AppState>, lang: &str, query: &str) -> String {
    let c = cluster_facts(state).await;
    let pairs = query_pairs(query);
    let raw_tb = qnum(&pairs, "data", suggested_raw_tb(&c)).max(0.001);
    let cost = qnum(&pairs, "cost", 20.0).max(0.0);
    let bw = qnum(&pairs, "bw", 10.0).max(0.1);
    let nines = qnum(&pairs, "nines", 11.0).clamp(1.0, 20.0);
    let repair = qnum(&pairs, "repair", 8.0).max(0.01);
    let loss = qnum(&pairs, "loss", 1.0).clamp(0.0, 10.0) as u32;
    let years = qnum(&pairs, "years", 5.0).clamp(1.0, 20.0);

    let inp = Inputs {
        raw_tb,
        disk_cost_per_tb_year: cost,
        cross_rack_gbps: bw,
        bandwidth_utilisation: 0.5,
        target_durability_nines: nines,
        max_repair_hours: repair,
        tolerate_node_loss: loss,
        annual_disk_afr: 0.02,
        node_count: c.node_count,
        devices_total: c.devices_total,
        zone_count: c.zone_count,
        device_tb: c.device_tb,
        years,
        candidates: default_candidates(),
    };
    let rows = economist::evaluate(&inp);
    let rec = economist::recommend(&rows);

    let statline = if c.usage_unknown {
        i18n::t(lang, "pol.cluster.unknown")
            .replace("{nodes}", &c.node_count.to_string())
            .replace("{devices}", &c.devices_total.to_string())
            .replace("{zones}", &c.zone_count.to_string())
    } else {
        i18n::t(lang, "pol.cluster")
            .replace("{nodes}", &c.node_count.to_string())
            .replace("{devices}", &c.devices_total.to_string())
            .replace("{zones}", &c.zone_count.to_string())
            .replace("{dev}", &tb(c.device_tb))
            .replace("{cap}", &tb(c.capacity_tb))
            .replace("{stored}", &tb(c.stored_tb))
    };

    let form = format!(
        r#"<div class="pagehead">
  <h1>{title}</h1>
</div>
<p class="statline">{statline}</p>

<form class="page-sec tt-form pe-form" method="get" action="/lab/policy">
  <div class="sx-grid">
    <label class="fld"><span>{l_data}</span><input name="data" type="number" min="0.001" step="any" value="{data}"></label>
    <label class="fld"><span>{l_cost}</span><input name="cost" type="number" min="0" step="any" value="{cost}"></label>
    <label class="fld"><span>{l_bw}</span><input name="bw" type="number" min="0.1" step="any" value="{bw}"></label>
    <label class="fld"><span>{l_nines}</span><input name="nines" type="number" min="1" max="20" step="any" value="{nines}"></label>
    <label class="fld"><span>{l_repair}</span><input name="repair" type="number" min="0.01" step="any" value="{repair}"></label>
    <label class="fld"><span>{l_loss}</span><input name="loss" type="number" min="0" max="10" value="{loss}"></label>
    <label class="fld"><span>{l_years}</span><input name="years" type="number" min="1" max="20" value="{years}"></label>
  </div>
  <div class="sx-actions"><button class="btn-primary" type="submit">{compare}</button></div>
</form>"#,
        title = esc(i18n::t(lang, "policy.title")),
        statline = esc(&statline),
        l_data = esc(i18n::t(lang, "pol.f.data")),
        l_cost = esc(i18n::t(lang, "pol.f.cost")),
        l_bw = esc(i18n::t(lang, "pol.f.bw")),
        l_nines = esc(i18n::t(lang, "pol.f.nines")),
        l_repair = esc(i18n::t(lang, "pol.f.repair")),
        l_loss = esc(i18n::t(lang, "pol.f.loss")),
        l_years = esc(i18n::t(lang, "pol.f.years")),
        compare = esc(i18n::t(lang, "pol.f.compare")),
        data = raw_tb,
        cost = cost,
        bw = bw,
        nines = nines,
        repair = repair,
        loss = loss,
        years = years,
    );

    let method = format!(
        "<div class=\"page-sec rs-method\"><h3>{h}</h3><p class=\"note\">{m1}</p>\
         <p class=\"note\">{m2}</p><p class=\"note\">{m3}</p><p class=\"note\">{m4}</p></div>",
        h = esc(i18n::t(lang, "pol.method.title")),
        m1 = esc(i18n::t(lang, "pol.method.model")),
        m2 = esc(
            &i18n::t(lang, "pol.method.afr")
                .replace("{afr}", "2")
                .replace("{util}", "50")
        ),
        m3 = esc(i18n::t(lang, "pol.method.quorum")),
        m4 = esc(i18n::t(lang, "pol.method.unknown")),
    );

    format!(
        "{form}{rec_block}<div class=\"mon-grid rs-grid\">{chart}{repair_bars}{table}</div>{method}",
        rec_block = recommendation_block(lang, &rows, &rec, &inp),
        chart = tradeoff(lang, &rows, &rec, nines),
        repair_bars = repair_bars(lang, &rows, repair),
        table = comparison(lang, &rows, &rec),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_values_come_from_the_query_and_fall_back_to_the_default() {
        let p = query_pairs("data=42.5&cost=&nines=9");
        assert_eq!(qnum(&p, "data", 1.0), 42.5);
        // An empty or missing field falls back rather than becoming zero.
        assert_eq!(qnum(&p, "cost", 20.0), 20.0);
        assert_eq!(qnum(&p, "bw", 10.0), 10.0);
        assert_eq!(qnum(&p, "nines", 11.0), 9.0);
    }

    #[test]
    fn a_junk_number_never_becomes_a_silent_zero() {
        let p = query_pairs("data=NaN&cost=abc");
        assert_eq!(qnum(&p, "data", 7.0), 7.0);
        assert_eq!(qnum(&p, "cost", 20.0), 20.0);
    }

    /// The old default described somebody else's hardware; the suggestion now
    /// has to be derived from what is actually installed.
    #[test]
    fn the_suggested_volume_is_this_clusters_own_capacity() {
        let c = Cluster {
            node_count: 4,
            devices_total: 12,
            zone_count: 4,
            device_tb: 0.27,
            capacity_tb: 3.24,
            stored_tb: 0.04,
            policies: vec![],
            usage_unknown: false,
        };
        assert!((suggested_raw_tb(&c) - 1.08).abs() < 1e-9);
        // With nothing measured it still offers something usable rather than 0.
        let empty = Cluster {
            capacity_tb: 0.0,
            ..c
        };
        assert_eq!(suggested_raw_tb(&empty), 1.0);
    }

    #[test]
    fn units_read_the_way_an_operator_says_them() {
        assert_eq!(tb(0.5), "500 GB");
        assert_eq!(tb(12.0), "12.0 TB");
        assert_eq!(tb(2500.0), "2.50 PB");
        assert_eq!(hours("en", 0.5), "30 min");
        assert_eq!(hours("en", 12.0), "12.0 h");
        assert_eq!(hours("en", 96.0), "4.0 d");
        assert_eq!(hours("zh", 12.0), "12.0 小时");
        assert_eq!(money(1500.0), "1.5k");
        assert_eq!(money(2_500_000.0), "2.50M");
    }
}
