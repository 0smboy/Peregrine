//! Repair Debt Index — compress scattered repair signals into one decision variable.
//!
//! Ordinary monitors list backlog, disk pressure and ring imbalance separately.
//! This answers the question those panels never do: is damage arriving faster
//! than the cluster can repay it?
//!
//! MVP inputs are auditable proxies (async_pending, quarantine, ring balance,
//! disk pressure, replicator rates, replication-plane bandwidth) — not a fake
//! Prom backlog gauge. The formula is pure and unit-tested; the page only
//! gathers feeds and renders the result.

use crate::util::esc;
use crate::{i18n, lab, monitor, nodes, ringlab, AppState};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Scale for tanh normalisation — chosen so healthy clusters sit low and a
/// severe multi-proxy pile-up approaches 100 without needing raw units.
const S0: f64 = 12.0;
const EPS: f64 = 1e-6;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Proxies {
    pub async_pending: f64,
    pub quarantine_objects: f64,
    /// Absolute ring balance percent (worst device).
    pub balance_pct: f64,
    /// Max device fill fraction 0..1.
    pub disk_used_max: f64,
    /// Cluster disk util 0..1 (io time rate, capped).
    pub disk_util: f64,
    /// Replicator failure rate (events/s).
    pub repl_fail_rate: f64,
    /// Replicator sync/success rate (events/s).
    pub repl_sync_rate: f64,
    /// Replication-plane bytes/s (rx+tx).
    pub net_repl_bps: f64,
    /// Zone co-location stress 0..1+ (parts concentrated in one zone).
    pub zone_corr: f64,
    /// Human hint for the hottest zone, if known.
    pub hottest_zone: String,
    pub hottest_zone_parts: u64,
    /// Fraction of cluster nodes whose Swift units are not fully active (0..1).
    pub unhealthy_frac: f64,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Contribution {
    pub id: &'static str,
    pub label_key: &'static str,
    pub stock: f64,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct DebtResult {
    pub debt: f64,
    pub interest_per_hour: f64,
    /// Hours to debt=100 when interest > 0; None means ∞ or already insolvent.
    pub tti_hours: Option<f64>,
    pub insolvent: bool,
    pub contributions: Vec<Contribution>,
    pub top_source_key: &'static str,
    pub top_source_detail: String,
}

#[derive(Clone, Debug)]
struct Sample {
    at: f64,
    async_pending: f64,
    quarantine: f64,
    debt: f64,
}

static HISTORY: LazyLock<Mutex<VecDeque<Sample>>> =
    LazyLock::new(|| Mutex::new(VecDeque::with_capacity(64)));

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Pure debt model. Interest uses optional short-window growth when history
/// deltas are supplied; otherwise rates alone drive flow_in / flow_out.
pub fn compute_debt(
    p: &Proxies,
    pending_growth_per_s: f64,
    quarantine_growth_per_s: f64,
    debt_slope_per_hour: Option<f64>,
) -> DebtResult {
    let backlog = p.async_pending + p.quarantine_objects;
    let backlog_stock = (backlog / 200.0) * (1.0 + p.zone_corr);
    let balance_stock = (p.balance_pct / 25.0).max(0.0);
    let disk_fill = ((p.disk_used_max - 0.80) / 0.20).clamp(0.0, 2.0);
    let disk_stock = disk_fill + p.disk_util.clamp(0.0, 1.5) * 0.5;
    let fail_stock = (p.repl_fail_rate * 30.0).min(8.0);
    let unhealthy_stock = (p.unhealthy_frac * 10.0).min(10.0);

    let contributions = vec![
        Contribution {
            id: "backlog",
            label_key: "debt.c.backlog",
            stock: backlog_stock,
        },
        Contribution {
            id: "balance",
            label_key: "debt.c.balance",
            stock: balance_stock,
        },
        Contribution {
            id: "disk",
            label_key: "debt.c.disk",
            stock: disk_stock,
        },
        Contribution {
            id: "failures",
            label_key: "debt.c.failures",
            stock: fail_stock,
        },
        Contribution {
            id: "unhealthy",
            label_key: "debt.c.unhealthy",
            stock: unhealthy_stock,
        },
    ];
    let sum: f64 = contributions.iter().map(|c| c.stock).sum();
    let debt = (100.0 * (sum / S0).tanh()).clamp(0.0, 100.0);

    // A downed Swift node is damage arriving even when Prom failure counters
    // have not yet moved — count it in the inflow so Interest turns positive
    // during HA drills.
    let flow_in = pending_growth_per_s.max(0.0)
        + quarantine_growth_per_s.max(0.0)
        + p.repl_fail_rate.max(0.0)
        + p.unhealthy_frac * 5.0;
    // Bandwidth saturation softens repair capacity when the plane is already hot.
    // A missing Swift node also removes repair workers — cut outflow accordingly.
    let sat = (p.net_repl_bps / (800.0 * 1024.0 * 1024.0)).clamp(0.15, 1.0);
    let capacity = (1.0 - p.unhealthy_frac * 0.9).clamp(0.05, 1.0);
    let flow_out = (p.repl_sync_rate.max(0.0) + EPS) * sat * capacity;
    let interest = (flow_in / flow_out.max(EPS)) - 1.0;

    let insolvent = debt >= 99.5;
    let tti_hours = if insolvent {
        Some(0.0)
    } else if interest > 0.02 {
        let slope = debt_slope_per_hour
            .filter(|s| *s > 0.05)
            .unwrap_or_else(|| (interest * 4.0).max(0.1));
        Some(((100.0 - debt) / slope).max(0.0))
    } else {
        None
    };

    let top = contributions
        .iter()
        .max_by(|a, b| a.stock.partial_cmp(&b.stock).unwrap_or(std::cmp::Ordering::Equal))
        .cloned()
        .unwrap_or(Contribution {
            id: "backlog",
            label_key: "debt.c.backlog",
            stock: 0.0,
        });

    let top_source_detail = if !p.hottest_zone.is_empty() && p.hottest_zone_parts > 0 {
        format!(
            "zone {} · {} partitions",
            p.hottest_zone, p.hottest_zone_parts
        )
    } else {
        format!("stock={:.2}", top.stock)
    };

    DebtResult {
        debt,
        interest_per_hour: interest * 100.0, // percent points / relative hour scale
        tti_hours,
        insolvent,
        contributions,
        top_source_key: top.label_key,
        top_source_detail,
    }
}

fn remember(sample: Sample) -> (f64, f64, Option<f64>) {
    let mut h = HISTORY.lock().unwrap();
    // Prefer a sample ~15 minutes ago for growth; else oldest.
    let target = sample.at - 900.0;
    let prev = h
        .iter()
        .rev()
        .find(|s| s.at <= target)
        .or_else(|| h.front())
        .cloned();
    h.push_back(sample.clone());
    while h.len() > 48 {
        h.pop_front();
    }
    match prev {
        Some(p) if sample.at > p.at + 1.0 => {
            let dt = sample.at - p.at;
            let pg = (sample.async_pending - p.async_pending) / dt;
            let qg = (sample.quarantine - p.quarantine) / dt;
            let slope = Some((sample.debt - p.debt) / (dt / 3600.0));
            (pg, qg, slope)
        }
        _ => (0.0, 0.0, None),
    }
}

async fn prom_scalar(state: &Arc<AppState>, q: &str) -> f64 {
    match monitor::q_instant(state, q).await {
        Ok(v) => monitor::parse_instant(&v).unwrap_or(0.0),
        Err(_) => 0.0,
    }
}

async fn collect_unhealthy_frac(state: &Arc<AppState>) -> f64 {
    let services = crate::nodeops::SERVICES;
    let total = services.split_whitespace().count().max(1);
    let probe = format!("systemctl is-active {services} 2>/dev/null | tr '\\n' ' '; echo");
    let results = nodes::fan_out(state, &probe).await;
    if results.is_empty() {
        return 0.0;
    }
    let bad = results
        .iter()
        .filter(|r| {
            if !r.ok {
                return true;
            }
            let active = r.out.split_whitespace().filter(|s| *s == "active").count();
            active < total
        })
        .count();
    bad as f64 / results.len() as f64
}

async fn collect_backlog(state: &Arc<AppState>) -> (f64, f64, Vec<(String, u64, u64)>) {
    let root = state.cfg.lab_root.trim_end_matches('/');
    let root = if root.is_empty() { "/srv/node" } else { root };
    // Count files under async_pending* and quarantined/objects* — same idea as
    // swift-recon helpers, without linking that crate into the console.
    let probe = format!(
        "python3 - <<'PY'\n\
import os\n\
root={root:?}\n\
ap=q=0\n\
try:\n\
  names=os.listdir(root)\n\
except Exception:\n\
  names=[]\n\
for d in names:\n\
  p=os.path.join(root,d)\n\
  if not os.path.isdir(p): continue\n\
  try: kids=os.listdir(p)\n\
  except Exception: continue\n\
  for name in kids:\n\
    if name.startswith('async_pending'):\n\
      for dp,_,fs in os.walk(os.path.join(p,name)):\n\
        ap+=len(fs)\n\
  qdir=os.path.join(p,'quarantined')\n\
  if os.path.isdir(qdir):\n\
    for dp,_,fs in os.walk(qdir):\n\
      q+=len(fs)\n\
print(ap,q)\n\
PY"
    );
    let results = nodes::fan_out(state, &probe).await;
    let mut total_ap = 0u64;
    let mut total_q = 0u64;
    let mut per = Vec::new();
    for r in results {
        if !r.ok {
            per.push((r.node, 0, 0));
            continue;
        }
        let mut it = r.out.split_whitespace();
        let ap: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let q: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        total_ap += ap;
        total_q += q;
        per.push((r.node, ap, q));
    }
    (total_ap as f64, total_q as f64, per)
}

async fn collect_ring(state: &Arc<AppState>) -> (f64, f64, String, u64) {
    let topo = match ringlab::default_policy(state).await {
        Ok(p) => ringlab::topology(state, p.index).await.ok(),
        Err(_) => None,
    };
    let Some(v) = topo else {
        return (0.0, 0.0, String::new(), 0);
    };
    let devices = v.get("devices").and_then(|d| d.as_array()).cloned().unwrap_or_default();
    let mut max_bal = 0.0_f64;
    let mut zone_parts: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    let mut total_parts = 0u64;
    for d in &devices {
        let bal = d
            .get("balance_pct")
            .and_then(|x| x.as_f64())
            .unwrap_or(0.0)
            .abs();
        if bal > max_bal {
            max_bal = bal;
        }
        let zone = d.get("zone").and_then(|x| x.as_u64()).unwrap_or(0);
        let parts = d
            .get("parts_after")
            .or_else(|| d.get("parts_before"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        *zone_parts.entry(zone).or_default() += parts;
        total_parts += parts;
    }
    let (hottest, hot_parts) = zone_parts
        .iter()
        .max_by_key(|(_, p)| *p)
        .map(|(z, p)| (*z, *p))
        .unwrap_or((0, 0));
    let ideal = if zone_parts.is_empty() {
        0.0
    } else {
        total_parts as f64 / zone_parts.len() as f64
    };
    let zone_corr = if ideal > 0.0 {
        ((hot_parts as f64 / ideal) - 1.0).max(0.0)
    } else {
        0.0
    };
    (max_bal, zone_corr, hottest.to_string(), hot_parts)
}

async fn gather(state: &Arc<AppState>) -> (Proxies, DebtResult, Value) {
    let (async_pending, quarantine_objects, per_node) = collect_backlog(state).await;
    let (balance_pct, zone_corr, hottest_zone, hottest_zone_parts) = collect_ring(state).await;
    let unhealthy_frac = collect_unhealthy_frac(state).await;

    let disk_used_max = prom_scalar(
        state,
        "max(1 - node_filesystem_avail_bytes{job=\"node\",mountpoint=~\"/srv/node/.+\"} / \
         node_filesystem_size_bytes{job=\"node\",mountpoint=~\"/srv/node/.+\"}) or on() vector(0)",
    )
    .await
    .clamp(0.0, 1.0);
    let disk_util = prom_scalar(
        state,
        "max(rate(node_disk_io_time_seconds_total{job=\"node\"}[5m])) or on() vector(0)",
    )
    .await
    .clamp(0.0, 2.0);
    let repl_fail_rate = prom_scalar(
        state,
        "sum(rate(swift_replicator_total{kind=\"failures\"}[5m])) or on() vector(0)",
    )
    .await;
    let repl_sync_rate = prom_scalar(
        state,
        "sum(rate(swift_replicator_total{kind=~\"suffix_syncs|successes|reverts\"}[5m])) or on() vector(0)",
    )
    .await;
    let net_repl_bps = prom_scalar(
        state,
        "(sum(rate(node_network_receive_bytes_total{job=\"node\",plane=\"replication\"}[5m])) or on() vector(0)) + \
         (sum(rate(node_network_transmit_bytes_total{job=\"node\",plane=\"replication\"}[5m])) or on() vector(0))",
    )
    .await;

    let proxies = Proxies {
        async_pending,
        quarantine_objects,
        balance_pct,
        disk_used_max,
        disk_util,
        repl_fail_rate,
        repl_sync_rate,
        net_repl_bps,
        zone_corr,
        hottest_zone,
        hottest_zone_parts,
        unhealthy_frac,
    };

    // First pass without history slope; then remember and refine interest.
    let draft = compute_debt(&proxies, 0.0, 0.0, None);
    let (pg, qg, slope) = remember(Sample {
        at: now_secs(),
        async_pending,
        quarantine: quarantine_objects,
        debt: draft.debt,
    });
    let result = compute_debt(&proxies, pg, qg, slope);

    let per = per_node
        .into_iter()
        .map(|(n, ap, q)| json!({"node": n, "async_pending": ap, "quarantine": q}))
        .collect::<Vec<_>>();

    let feed = json!({
        "async_pending": async_pending,
        "quarantine_objects": quarantine_objects,
        "balance_pct": balance_pct,
        "disk_used_max": disk_used_max,
        "disk_util": disk_util,
        "repl_fail_rate": repl_fail_rate,
        "repl_sync_rate": repl_sync_rate,
        "net_repl_bps": net_repl_bps,
        "zone_corr": zone_corr,
        "hottest_zone": proxies.hottest_zone,
        "hottest_zone_parts": hottest_zone_parts,
        "unhealthy_frac": unhealthy_frac,
        "pending_growth_per_s": pg,
        "quarantine_growth_per_s": qg,
        "per_node": per,
        "note": "Debt is computed from these proxies; there is no Prom backlog gauge.",
    });

    (proxies, result, feed)
}

fn fmt_tti(lang: &str, tti: Option<f64>, insolvent: bool) -> String {
    if insolvent {
        return i18n::t(lang, "debt.tti.insolvent").to_string();
    }
    match tti {
        None => i18n::t(lang, "debt.tti.none").to_string(),
        Some(h) if h < 1.0 => format!("{:.0} min", (h * 60.0).max(1.0)),
        Some(h) => format!("{:.1} h", h),
    }
}

fn render(lang: &str, result: &DebtResult, feed: &Value) -> String {
    let interest = result.interest_per_hour;
    let interest_cls = if interest > 2.0 {
        "debt-bad"
    } else if interest < -2.0 {
        "debt-good"
    } else {
        "debt-ok"
    };
    let debt_cls = if result.debt >= 70.0 {
        "debt-bad"
    } else if result.debt >= 40.0 {
        "debt-warn"
    } else {
        "debt-good"
    };
    let bars: String = result
        .contributions
        .iter()
        .map(|c| {
            let pct = ((c.stock / S0).tanh() * 100.0).clamp(0.0, 100.0);
            format!(
                "<div class=\"debt-bar\"><span>{}</span>\
                 <i style=\"--w:{pct:.1}%\"></i><em>{:.2}</em></div>",
                esc(i18n::t(lang, c.label_key)),
                c.stock,
                pct = pct,
            )
        })
        .collect();

    let top = format!(
        "{} — {}",
        i18n::t(lang, result.top_source_key),
        result.top_source_detail
    );

    let rows = feed
        .get("per_node")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut tbl = String::from(
        "<table class=\"tbl\"><thead><tr><th>Node</th><th>async_pending</th><th>quarantine</th></tr></thead><tbody>",
    );
    for r in rows {
        tbl.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(r.get("node").and_then(|x| x.as_str()).unwrap_or("")),
            r.get("async_pending").and_then(|x| x.as_u64()).unwrap_or(0),
            r.get("quarantine").and_then(|x| x.as_u64()).unwrap_or(0),
        ));
    }
    tbl.push_str("</tbody></table>");

    format!(
        r#"<div class="pagehead"><h1>{title}</h1></div>
<p class="statline">{blurb}</p>
<p class="note">{proxy_note}</p>
<div class="debt-hero">
  <div class="debt-tile {debt_cls}"><div class="debt-k">{k_debt}</div>
    <div class="debt-v">{debt:.0}</div><div class="debt-u">/ 100</div></div>
  <div class="debt-tile {interest_cls}"><div class="debt-k">{k_int}</div>
    <div class="debt-v">{sign}{interest:.1}%</div><div class="debt-u">/ hour</div></div>
  <div class="debt-tile"><div class="debt-k">{k_tti}</div>
    <div class="debt-v debt-tti">{tti}</div></div>
</div>
<div class="page-sec">
  <h2 class="wh-h">{h_top}</h2>
  <p class="statline">{top}</p>
</div>
<div class="page-sec">
  <h2 class="wh-h">{h_bars}</h2>
  <div class="debt-bars">{bars}</div>
</div>
<details class="wh-data"><summary>{h_feed}</summary>
  <pre class="wh-preview-body">{feed}</pre>
  {tbl}
</details>
<script>
(function(){{
  setTimeout(function(){{ location.reload(); }}, 60000);
}})();
</script>"#,
        title = esc(i18n::t(lang, "lab.tool.debt.title")),
        blurb = esc(i18n::t(lang, "lab.tool.debt.blurb")),
        proxy_note = esc(i18n::t(lang, "debt.proxy_note")),
        k_debt = esc(i18n::t(lang, "debt.k.debt")),
        k_int = esc(i18n::t(lang, "debt.k.interest")),
        k_tti = esc(i18n::t(lang, "debt.k.tti")),
        h_top = esc(i18n::t(lang, "debt.h.top")),
        h_bars = esc(i18n::t(lang, "debt.h.bars")),
        h_feed = esc(i18n::t(lang, "debt.h.feed")),
        debt = result.debt,
        interest = interest.abs(),
        sign = if interest >= 0.0 { "+" } else { "-" },
        tti = esc(&fmt_tti(lang, result.tti_hours, result.insolvent)),
        top = esc(&top),
        bars = bars,
        feed = esc(&serde_json::to_string_pretty(feed).unwrap_or_default()),
        tbl = tbl,
        debt_cls = debt_cls,
        interest_cls = interest_cls,
    )
}

/// GET /lab/debt
pub async fn page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (_, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let (_p, result, feed) = gather(&state).await;
    let body = render(lang, &result, &feed);
    crate::pages::lab_tool_shell(&state, &headers, &sess, "debt", body)
}

/// GET /lab/api/debt/snapshot — neutral JSON for calibration / agents.
pub async fn snapshot(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let (_p, result, feed) = gather(&state).await;
    Json(json!({
        "debt": result.debt,
        "interest_per_hour": result.interest_per_hour,
        "tti_hours": result.tti_hours,
        "insolvent": result.insolvent,
        "top_source": i18n::t(i18n::lang(&headers), result.top_source_key),
        "top_source_detail": result.top_source_detail,
        "contributions": result.contributions.iter().map(|c| json!({
            "id": c.id,
            "stock": c.stock,
            "label": i18n::t(i18n::lang(&headers), c.label_key),
        })).collect::<Vec<_>>(),
        "proxies": feed,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Proxies {
        Proxies {
            async_pending: 0.0,
            quarantine_objects: 0.0,
            balance_pct: 0.4,
            disk_used_max: 0.5,
            disk_util: 0.1,
            repl_fail_rate: 0.0,
            repl_sync_rate: 2.0,
            net_repl_bps: 10_000_000.0,
            zone_corr: 0.0,
            hottest_zone: "1".into(),
            hottest_zone_parts: 100,
            unhealthy_frac: 0.0,
        }
    }

    #[test]
    fn unhealthy_nodes_raise_interest() {
        let mut p = base();
        p.unhealthy_frac = 0.25;
        p.repl_sync_rate = 0.5;
        let r = compute_debt(&p, 0.0, 0.0, None);
        assert!(r.debt > 15.0, "debt={}", r.debt);
        assert!(r.interest_per_hour > 0.0, "interest={}", r.interest_per_hour);
    }

    #[test]
    fn healthy_cluster_stays_low() {
        let r = compute_debt(&base(), 0.0, 0.0, None);
        assert!(r.debt < 25.0, "debt={}", r.debt);
        assert!(r.interest_per_hour < 5.0, "interest={}", r.interest_per_hour);
        assert!(r.tti_hours.is_none());
        assert!(!r.insolvent);
    }

    #[test]
    fn backlog_and_failures_raise_debt() {
        let mut p = base();
        p.async_pending = 800.0;
        p.quarantine_objects = 200.0;
        p.repl_fail_rate = 0.5;
        p.zone_corr = 0.8;
        let r = compute_debt(&p, 0.2, 0.05, Some(3.0));
        assert!(r.debt > 50.0, "debt={}", r.debt);
        assert!(r.interest_per_hour > 0.0, "interest={}", r.interest_per_hour);
        assert!(r.tti_hours.is_some());
    }

    #[test]
    fn interest_positive_when_damage_outruns_repair() {
        let mut p = base();
        p.repl_sync_rate = 0.01;
        p.repl_fail_rate = 1.0;
        let r = compute_debt(&p, 0.5, 0.0, None);
        assert!(r.interest_per_hour > 10.0, "interest={}", r.interest_per_hour);
    }

    #[test]
    fn contributions_sum_drives_debt_monotone() {
        let low = compute_debt(&base(), 0.0, 0.0, None);
        let mut hi = base();
        hi.async_pending = 5000.0;
        let high = compute_debt(&hi, 0.0, 0.0, None);
        assert!(high.debt > low.debt);
    }
}
