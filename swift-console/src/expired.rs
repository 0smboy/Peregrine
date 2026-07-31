//! Expired-but-Alive Observatory — watch the grey zone between logical expiry
//! and physical reaping.
//!
//! An object past `X-Delete-At` returns 404 to ordinary clients while the
//! bytes may still sit on disk; with `X-Open-Expired: true` they remain
//! readable until the expirer removes them. This Lab seeds staggered TTLs,
//! polls both GET paths + disk presence, and reports ghost-period stats.

use crate::util::esc;
use crate::{i18n, lab, nodes, ringlab, swift, AppState};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GhostState {
    Alive,
    LogicallyExpired,
    RecoverableGhost,
    PhysicallyReaped,
}

impl GhostState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alive => "alive",
            Self::LogicallyExpired => "logically_expired",
            Self::RecoverableGhost => "recoverable_ghost",
            Self::PhysicallyReaped => "physically_reaped",
        }
    }
}

/// Pure classifier. Disk presence wins over open-expired HTTP when they disagree.
pub fn classify(
    now: f64,
    delete_at: f64,
    normal_status: u16,
    open_status: u16,
    disk_present: bool,
) -> GhostState {
    if now < delete_at {
        return GhostState::Alive;
    }
    if disk_present {
        if open_status == 200 || normal_status == 200 {
            return GhostState::RecoverableGhost;
        }
        // Past delete-at, still on disk, ordinary GET is 404 → ghost.
        return GhostState::RecoverableGhost;
    }
    if open_status == 200 {
        // Open-expired can still see it but our SSH scan missed — treat as ghost.
        return GhostState::RecoverableGhost;
    }
    if normal_status == 404 || normal_status == 0 {
        if open_status == 404 || open_status == 0 {
            return GhostState::PhysicallyReaped;
        }
    }
    GhostState::LogicallyExpired
}

pub fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let p = p.clamp(0.0, 100.0);
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    Some(sorted[idx.min(sorted.len() - 1)])
}

pub fn ghost_stats(durations: &[f64]) -> (Option<f64>, Option<f64>, Option<f64>) {
    let mut v: Vec<f64> = durations.iter().copied().filter(|x| x.is_finite() && *x >= 0.0).collect();
    if v.is_empty() {
        return (None, None, None);
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    (Some(mean), percentile(&v, 95.0), v.last().copied())
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Clone, Debug, Serialize)]
struct ObjRow {
    name: String,
    delete_at: f64,
    state: GhostState,
    normal_status: u16,
    open_status: u16,
    disk_nodes: Vec<String>,
    /// Seconds spent as RecoverableGhost (or still open if ongoing).
    ghost_secs: Option<f64>,
    expired_at: Option<f64>,
    reaped_at: Option<f64>,
    first_ghost_at: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
struct Run {
    id: String,
    container: String,
    started: f64,
    objects: Vec<ObjRow>,
    note: String,
}

static RUN: LazyLock<Mutex<Option<Run>>> = LazyLock::new(|| Mutex::new(None));

fn account_name(sess: &crate::session::Session) -> String {
    // Storage URL ends with /v1/AUTH_tenant — object paths are under that.
    format!("AUTH_{}", sess.tenant)
}

async fn disk_present(
    state: &Arc<AppState>,
    account: &str,
    container: &str,
    object: &str,
) -> (bool, Vec<String>) {
    let located = match ringlab::locate(state, 0, account, Some(container), Some(object)).await {
        Ok(l) => l,
        Err(_) => return (false, vec![]),
    };
    let hash = located.hash;
    if hash.len() != 32 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (false, vec![]);
    }
    let names: Vec<String> = located.primaries.iter().map(|p| p.node.clone()).collect();
    if names.is_empty() {
        return (false, vec![]);
    }
    let root = state.cfg.node_root.trim_end_matches('/');
    let suffix = &hash[29..];
    let part = located.partition;
    let remote = format!(
        "for d in {root}/*/objects/{part}/{suffix}/{hash}; do \
         [ -d \"$d\" ] || continue; \
         for f in \"$d\"/*.data; do [ -e \"$f\" ] && echo PRESENT; done; done"
    );
    let results = nodes::fan_out_on(state, &names, &remote).await;
    let mut present_on = Vec::new();
    for r in results {
        if r.ok && r.out.contains("PRESENT") {
            present_on.push(r.node);
        }
    }
    (!present_on.is_empty(), present_on)
}

async fn probe_one(
    state: &Arc<AppState>,
    sid: &str,
    account: &str,
    container: &str,
    obj: &mut ObjRow,
) {
    let sub = format!("/{}/{}", container, obj.name);
    let normal = swift::call(
        state,
        sid,
        reqwest::Method::GET,
        &sub,
        &[],
        &[],
        None,
    )
    .await;
    let open = swift::call(
        state,
        sid,
        reqwest::Method::GET,
        &sub,
        &[],
        &[("X-Open-Expired".into(), "true".into())],
        None,
    )
    .await;
    obj.normal_status = normal.as_ref().map(|r| r.status().as_u16()).unwrap_or(0);
    obj.open_status = open.as_ref().map(|r| r.status().as_u16()).unwrap_or(0);
    // Drain bodies so connections close cleanly.
    if let Ok(r) = normal {
        let _ = r.bytes().await;
    }
    if let Ok(r) = open {
        let _ = r.bytes().await;
    }
    let (on_disk, nodes_hit) = disk_present(state, account, container, &obj.name).await;
    obj.disk_nodes = nodes_hit;
    let now = now_secs();
    let prev = obj.state;
    obj.state = classify(
        now,
        obj.delete_at,
        obj.normal_status,
        obj.open_status,
        on_disk,
    );
    if obj.state != GhostState::Alive && obj.expired_at.is_none() && now >= obj.delete_at {
        obj.expired_at = Some(obj.delete_at);
    }
    if matches!(
        obj.state,
        GhostState::RecoverableGhost | GhostState::LogicallyExpired
    ) && obj.first_ghost_at.is_none()
    {
        obj.first_ghost_at = Some(now);
    }
    if obj.state == GhostState::PhysicallyReaped {
        if obj.reaped_at.is_none() {
            obj.reaped_at = Some(now);
        }
        if let (Some(g), Some(r)) = (obj.first_ghost_at, obj.reaped_at) {
            obj.ghost_secs = Some((r - g).max(0.0));
        } else if let Some(e) = obj.expired_at {
            obj.ghost_secs = Some((now - e).max(0.0));
        }
    } else if matches!(obj.state, GhostState::RecoverableGhost) {
        let start = obj.first_ghost_at.or(obj.expired_at).unwrap_or(obj.delete_at);
        obj.ghost_secs = Some((now - start).max(0.0));
    }
    let _ = prev;
}

fn summarize(run: &Run) -> Value {
    let mut durations = Vec::new();
    let mut anomalies = Vec::new();
    let now = now_secs();
    let mut counts: HashMap<&'static str, u64> = HashMap::new();
    for o in &run.objects {
        *counts.entry(o.state.as_str()).or_default() += 1;
        if let Some(g) = o.ghost_secs {
            if o.state == GhostState::PhysicallyReaped {
                durations.push(g);
            }
        }
        if o.state == GhostState::RecoverableGhost {
            let age = now - o.delete_at;
            if age > 600.0 && o.disk_nodes.len() >= 2 {
                anomalies.push(json!({
                    "object": o.name,
                    "detail": format!(
                        "expired {:.0}s ago, still on {} nodes",
                        age,
                        o.disk_nodes.len()
                    ),
                }));
            }
        }
    }
    let (mean, p95, max) = ghost_stats(&durations);
    json!({
        "id": run.id,
        "container": run.container,
        "started": run.started,
        "note": run.note,
        "counts": counts,
        "ghost_mean_secs": mean,
        "ghost_p95_secs": p95,
        "ghost_max_secs": max,
        "anomalies": anomalies,
        "objects": run.objects,
    })
}

#[derive(Deserialize)]
pub struct RunBody {
    #[serde(default = "d_n")]
    pub n: u32,
    #[serde(default = "d_base")]
    pub base_ttl_secs: u64,
    #[serde(default = "d_step")]
    pub step_secs: u64,
}

fn d_n() -> u32 {
    20
}
fn d_base() -> u64 {
    60
}
fn d_step() -> u64 {
    15
}

/// POST /lab/api/expired/run
pub async fn run(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RunBody>,
) -> Response {
    let (sid, sess) = match lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let n = body.n.clamp(1, 100) as usize;
    let base = body.base_ttl_secs.clamp(10, 3600);
    let step = body.step_secs.clamp(1, 600);
    let id = format!("e{:x}", now_secs() as u64);
    let container = format!("lab-expired-{id}");
    // Create container.
    match swift::call(
        &state,
        &sid,
        reqwest::Method::PUT,
        &format!("/{container}"),
        &[],
        &[],
        None,
    )
    .await
    {
        Ok(r) if r.status().as_u16() < 300 || r.status().as_u16() == 202 => {
            let _ = r.bytes().await;
        }
        Ok(r) => {
            return Json(json!({"ok": false, "error": format!("create container: {}", r.status())}))
                .into_response();
        }
        Err(e) => {
            return Json(json!({"ok": false, "error": e.msg()})).into_response();
        }
    }
    let now = now_secs();
    let mut objects = Vec::with_capacity(n);
    for i in 1..=n {
        let name = format!("object-{i:03}");
        let delete_at = now + base as f64 + (i as f64 - 1.0) * step as f64;
        let sub = format!("/{container}/{name}");
        let headers = vec![
            ("Content-Type".into(), "text/plain".into()),
            ("X-Delete-At".into(), format!("{}", delete_at as i64)),
        ];
        let body = Bytes::from(format!("ghost-probe-{name}\n"));
        match swift::call(
            &state,
            &sid,
            reqwest::Method::PUT,
            &sub,
            &[],
            &headers,
            Some(body),
        )
        .await
        {
            Ok(r) if r.status().as_u16() < 300 => {
                let _ = r.bytes().await;
            }
            Ok(r) => {
                return Json(json!({"ok": false, "error": format!("PUT {name}: {}", r.status())}))
                    .into_response();
            }
            Err(e) => {
                return Json(json!({"ok": false, "error": e.msg()})).into_response();
            }
        }
        objects.push(ObjRow {
            name,
            delete_at,
            state: GhostState::Alive,
            normal_status: 0,
            open_status: 0,
            disk_nodes: vec![],
            ghost_secs: None,
            expired_at: None,
            reaped_at: None,
            first_ghost_at: None,
        });
    }
    let note = if state.cfg.lab_mutations {
        "Seeded. Poll to watch Alive → Logically Expired → Recoverable Ghost → Physically Reaped. If the object-expirer is not running, objects stay Recoverable Ghost — that is a real finding."
            .into()
    } else {
        "Seeded. Object-expirer may be absent; ghost period can be unbounded.".into()
    };
    let run = Run {
        id: id.clone(),
        container,
        started: now,
        objects,
        note,
    };
    *RUN.lock().unwrap() = Some(run);
    // Initial probe.
    match poll_inner(&state, &sid, &sess).await {
        Ok(status) => Json(json!({"ok": true, "id": id, "status": status})).into_response(),
        Err(e) => Json(json!({"ok": true, "id": id, "warning": e})).into_response(),
    }
}

async fn poll_inner(
    state: &Arc<AppState>,
    sid: &str,
    sess: &crate::session::Session,
) -> Result<Value, String> {
    let account = account_name(sess);
    let (container, mut objs) = {
        let mut guard = RUN.lock().unwrap();
        let run = guard.as_mut().ok_or_else(|| "no active run".to_string())?;
        (run.container.clone(), std::mem::take(&mut run.objects))
    };
    for obj in &mut objs {
        probe_one(state, sid, &account, &container, obj).await;
    }
    {
        let mut guard = RUN.lock().unwrap();
        let run = guard.as_mut().ok_or_else(|| "run vanished".to_string())?;
        run.objects = objs;
        Ok(summarize(run))
    }
}

/// POST /lab/api/expired/poll
pub async fn poll(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, sess) = match lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match poll_inner(&state, &sid, &sess).await {
        Ok(v) => Json(json!({"ok": true, "status": v})).into_response(),
        Err(e) => Json(json!({"ok": false, "error": e})).into_response(),
    }
}

#[derive(Deserialize)]
pub struct StatusQ {
    #[serde(default)]
    pub refresh: bool,
}

/// GET /lab/api/expired/status
pub async fn status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<StatusQ>,
) -> Response {
    let (sid, sess) = match lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if q.refresh {
        if let Ok(v) = poll_inner(&state, &sid, &sess).await {
            return Json(json!({"ok": true, "status": v})).into_response();
        }
    }
    let guard = RUN.lock().unwrap();
    match guard.as_ref() {
        Some(r) => Json(json!({"ok": true, "status": summarize(r)})).into_response(),
        None => Json(json!({"ok": false, "error": "no active run"})).into_response(),
    }
}

fn fmt_secs(v: Option<f64>) -> String {
    match v {
        None => "—".into(),
        Some(s) if s < 90.0 => format!("{:.0}s", s),
        Some(s) if s < 3600.0 => format!("{:.1}m", s / 60.0),
        Some(s) => format!("{:.1}h", s / 3600.0),
    }
}

fn render(lang: &str, snap: Option<&Value>) -> String {
    let title = i18n::t(lang, "lab.tool.expired.title");
    let blurb = i18n::t(lang, "lab.tool.expired.blurb");
    let legend = format!(
        "<ol class=\"exp-legend\">\
         <li><b>Alive</b> — {}</li>\
         <li><b>Logically Expired</b> — {}</li>\
         <li><b>Recoverable Ghost</b> — {}</li>\
         <li><b>Physically Reaped</b> — {}</li>\
         </ol>",
        esc(i18n::t(lang, "exp.leg.alive")),
        esc(i18n::t(lang, "exp.leg.logical")),
        esc(i18n::t(lang, "exp.leg.ghost")),
        esc(i18n::t(lang, "exp.leg.reaped")),
    );
    let (mean, p95, max, note, rows_html, anomalies) = match snap {
        Some(s) => {
            let mean = fmt_secs(s.get("ghost_mean_secs").and_then(|x| x.as_f64()));
            let p95 = fmt_secs(s.get("ghost_p95_secs").and_then(|x| x.as_f64()));
            let max = fmt_secs(s.get("ghost_max_secs").and_then(|x| x.as_f64()));
            let note = s.get("note").and_then(|x| x.as_str()).unwrap_or("");
            let mut rows = String::from(
                "<table class=\"tbl\"><thead><tr><th>Object</th><th>State</th>\
                 <th>GET</th><th>Open-Expired</th><th>Disk</th><th>Ghost</th></tr></thead><tbody>",
            );
            for o in s.get("objects").and_then(|x| x.as_array()).cloned().unwrap_or_default() {
                let disk = o
                    .get("disk_nodes")
                    .and_then(|x| x.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                rows.push_str(&format!(
                    "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td>\
                     <td>{}</td><td>{}</td></tr>",
                    esc(o.get("name").and_then(|x| x.as_str()).unwrap_or("")),
                    esc(o.get("state").and_then(|x| x.as_str()).unwrap_or("")),
                    o.get("normal_status").and_then(|x| x.as_u64()).unwrap_or(0),
                    o.get("open_status").and_then(|x| x.as_u64()).unwrap_or(0),
                    esc(&disk),
                    esc(&fmt_secs(o.get("ghost_secs").and_then(|x| x.as_f64()))),
                ));
            }
            rows.push_str("</tbody></table>");
            let mut anom = String::new();
            for a in s.get("anomalies").and_then(|x| x.as_array()).cloned().unwrap_or_default() {
                anom.push_str(&format!(
                    "<li><code>{}</code> — {}</li>",
                    esc(a.get("object").and_then(|x| x.as_str()).unwrap_or("")),
                    esc(a.get("detail").and_then(|x| x.as_str()).unwrap_or("")),
                ));
            }
            if anom.is_empty() {
                anom = format!("<li class=\"note\">{}</li>", esc(i18n::t(lang, "exp.anom.none")));
            }
            (mean, p95, max, note.to_string(), rows, anom)
        }
        None => (
            "—".into(),
            "—".into(),
            "—".into(),
            i18n::t(lang, "exp.idle").to_string(),
            String::new(),
            format!("<li class=\"note\">{}</li>", esc(i18n::t(lang, "exp.anom.none"))),
        ),
    };

    format!(
        r#"<div class="pagehead"><h1>{title}</h1></div>
<p class="statline">{blurb}</p>
{legend}
<div class="debt-hero">
  <div class="debt-tile"><div class="debt-k">{k_mean}</div><div class="debt-v">{mean}</div></div>
  <div class="debt-tile"><div class="debt-k">{k_p95}</div><div class="debt-v">{p95}</div></div>
  <div class="debt-tile"><div class="debt-k">{k_max}</div><div class="debt-v">{max}</div></div>
</div>
<p class="note">{note}</p>
<div class="page-sec">
  <button type="button" class="btn" id="exp-run">{run}</button>
  <button type="button" class="btn ghost" id="exp-poll">{poll}</button>
</div>
<div class="page-sec"><h2 class="wh-h">{h_anom}</h2><ul>{anomalies}</ul></div>
<div class="page-sec">{rows}</div>
<script>
(function(){{
  async function j(url, opt){{
    const r = await fetch(url, Object.assign({{credentials:'same-origin'}}, opt||{{}}));
    return r.json();
  }}
  const runBtn = document.getElementById('exp-run');
  const pollBtn = document.getElementById('exp-poll');
  if (runBtn) runBtn.onclick = async () => {{
    runBtn.disabled = true;
    await j('/lab/api/expired/run', {{method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{n:20, base_ttl_secs:60, step_secs:15}})}});
    location.reload();
  }};
  if (pollBtn) pollBtn.onclick = async () => {{
    await j('/lab/api/expired/poll', {{method:'POST'}});
    location.reload();
  }};
  setTimeout(function(){{ location.reload(); }}, 30000);
}})();
</script>"#,
        title = esc(title),
        blurb = esc(blurb),
        legend = legend,
        k_mean = esc(i18n::t(lang, "exp.k.mean")),
        k_p95 = esc(i18n::t(lang, "exp.k.p95")),
        k_max = esc(i18n::t(lang, "exp.k.max")),
        mean = esc(&mean),
        p95 = esc(&p95),
        max = esc(&max),
        note = esc(&note),
        run = esc(i18n::t(lang, "exp.btn.run")),
        poll = esc(i18n::t(lang, "exp.btn.poll")),
        h_anom = esc(i18n::t(lang, "exp.h.anom")),
        anomalies = anomalies,
        rows = rows_html,
    )
}

/// GET /lab/expired
pub async fn page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (_, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let snap = RUN.lock().unwrap().as_ref().map(summarize);
    let body = render(lang, snap.as_ref());
    crate::pages::lab_tool_shell(&state, &headers, &sess, "expired", body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alive_before_deadline() {
        assert_eq!(
            classify(100.0, 200.0, 200, 200, true),
            GhostState::Alive
        );
    }

    #[test]
    fn ghost_when_disk_after_expiry() {
        assert_eq!(
            classify(300.0, 200.0, 404, 200, true),
            GhostState::RecoverableGhost
        );
        assert_eq!(
            classify(300.0, 200.0, 404, 404, true),
            GhostState::RecoverableGhost
        );
    }

    #[test]
    fn reaped_when_gone() {
        assert_eq!(
            classify(300.0, 200.0, 404, 404, false),
            GhostState::PhysicallyReaped
        );
    }

    #[test]
    fn percentiles() {
        let (m, p95, mx) = ghost_stats(&[10.0, 20.0, 30.0, 40.0, 200.0]);
        assert!((m.unwrap() - 60.0).abs() < 1e-6);
        assert!(p95.unwrap() >= 40.0);
        assert_eq!(mx, Some(200.0));
    }
}
