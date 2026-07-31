//! Profile Cartographer — turn stage timers into an architecture heat map.
//!
//! MVP sources: process-local `/recon/stage` scraped from proxy nodes, plus
//! optional Prometheus `swift_stage_*` if present. A Lab pulse drives PUT
//! traffic so the tree has something to show.

use crate::util::esc;
use crate::{i18n, lab, monitor, nodes, swift, AppState};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct StageSample {
    pub service: String,
    pub path: String,
    pub stage: String,
    pub sum_seconds: f64,
    pub count: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TreeNode {
    pub name: String,
    pub pct: f64,
    pub sum_seconds: f64,
    pub count: u64,
}

/// Normalize stage samples for one path into a service → stages tree with %.
pub fn build_tree(samples: &[StageSample], path: &str) -> Vec<(String, Vec<TreeNode>)> {
    let mut by_svc: HashMap<String, Vec<&StageSample>> = HashMap::new();
    for s in samples {
        if s.path != path {
            continue;
        }
        by_svc.entry(s.service.clone()).or_default().push(s);
    }
    let mut services: Vec<String> = by_svc.keys().cloned().collect();
    services.sort();
    let mut out = Vec::new();
    for svc in services {
        let stages = by_svc.get(&svc).cloned().unwrap_or_default();
        let total: f64 = stages.iter().map(|s| s.sum_seconds).sum();
        let mut nodes: Vec<TreeNode> = stages
            .iter()
            .map(|s| TreeNode {
                name: s.stage.clone(),
                pct: if total > 0.0 {
                    100.0 * s.sum_seconds / total
                } else {
                    0.0
                },
                sum_seconds: s.sum_seconds,
                count: s.count,
            })
            .collect();
        nodes.sort_by(|a, b| b.pct.partial_cmp(&a.pct).unwrap_or(std::cmp::Ordering::Equal));
        out.push((svc, nodes));
    }
    out
}

fn parse_stage_json(v: &Value) -> Vec<StageSample> {
    let mut out = Vec::new();
    let arr = v
        .get("stages")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    for s in arr {
        out.push(StageSample {
            service: s
                .get("service")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            path: s.get("path").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            stage: s
                .get("stage")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            sum_seconds: s.get("sum_seconds").and_then(|x| x.as_f64()).unwrap_or(0.0),
            count: s.get("count").and_then(|x| x.as_u64()).unwrap_or(0),
        });
    }
    out
}

async fn gather_recon(state: &Arc<AppState>) -> Vec<StageSample> {
    let mut samples = Vec::new();
    // Proxy nodes often expose the console's LB; scrape each configured proxy
    // storage IP on the proxy port for /recon/stage.
    let port = state.cfg.proxy_port;
    let mut ips: Vec<String> = state
        .cfg
        .proxy_nodes
        .iter()
        .cloned()
        .collect();
    if ips.is_empty() {
        for n in nodes::all(state) {
            ips.push(n.storage_ip.clone());
        }
    }
    ips.sort();
    ips.dedup();
    for ip in ips.into_iter().take(8) {
        let url = format!("http://{ip}:{port}/recon/stage");
        if let Ok(resp) = state.http.get(&url).send().await {
            if let Ok(v) = resp.json::<Value>().await {
                samples.extend(parse_stage_json(&v));
            }
        }
        // Object server default ports 6000 — best-effort.
        for op in [6000u16, 6200] {
            let url = format!("http://{ip}:{op}/recon/stage");
            if let Ok(resp) = state.http.get(&url).send().await {
                if let Ok(v) = resp.json::<Value>().await {
                    samples.extend(parse_stage_json(&v));
                }
            }
        }
    }
    // Merge identical keys.
    let mut map: HashMap<(String, String, String), StageSample> = HashMap::new();
    for s in samples {
        let e = map
            .entry((s.service.clone(), s.path.clone(), s.stage.clone()))
            .or_insert(StageSample {
                service: s.service.clone(),
                path: s.path.clone(),
                stage: s.stage.clone(),
                sum_seconds: 0.0,
                count: 0,
            });
        e.sum_seconds += s.sum_seconds;
        e.count = e.count.saturating_add(s.count);
    }
    map.into_values().collect()
}

async fn gather_prom(state: &Arc<AppState>, path: &str) -> Vec<StageSample> {
    // Optional: if a Prom histogram exists, prefer its sum/count.
    let q = format!(
        "sum by (service, stage) (swift_stage_duration_seconds_sum{{path=\"{path}\"}}) or \
         sum by (service, stage) (stage_sum{{path=\"{path}\"}})"
    );
    let Ok(v) = monitor::q_instant(state, &q).await else {
        return vec![];
    };
    let mut out = Vec::new();
    let results = v
        .pointer("/data/result")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    for r in results {
        let metric = r.get("metric").cloned().unwrap_or(json!({}));
        let val = r
            .get("value")
            .and_then(|x| x.as_array())
            .and_then(|a| a.get(1))
            .and_then(|x| x.as_str())
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);
        out.push(StageSample {
            service: metric
                .get("service")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string(),
            path: path.to_string(),
            stage: metric
                .get("stage")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string(),
            sum_seconds: val,
            count: 1,
        });
    }
    out
}

#[derive(Deserialize)]
pub struct PulseBody {
    #[serde(default = "d_n")]
    pub n: u32,
    #[serde(default = "d_bytes")]
    pub bytes: u32,
}

fn d_n() -> u32 {
    16
}
fn d_bytes() -> u32 {
    4096
}

/// POST /lab/api/profilemap/pulse
pub async fn pulse(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<PulseBody>,
) -> Response {
    let (sid, _sess) = match lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let n = body.n.clamp(1, 64);
    let nbytes = body.bytes.clamp(64, 1_048_576) as usize;
    let container = "lab-profilemap";
    let _ = swift::call(
        &state,
        &sid,
        reqwest::Method::PUT,
        &format!("/{container}"),
        &[],
        &[],
        None,
    )
    .await;
    let payload = Bytes::from(vec![b'P'; nbytes]);
    let mut ok = 0u32;
    for i in 0..n {
        let name = format!("pulse-{i}");
        match swift::call(
            &state,
            &sid,
            reqwest::Method::PUT,
            &format!("/{container}/{name}"),
            &[],
            &[("Content-Type".into(), "application/octet-stream".into())],
            Some(payload.clone()),
        )
        .await
        {
            Ok(r) if r.status().as_u16() < 300 => {
                let _ = r.bytes().await;
                ok += 1;
            }
            Ok(r) => {
                let _ = r.bytes().await;
            }
            Err(_) => {}
        }
    }
    Json(json!({"ok": true, "puts": ok, "requested": n})).into_response()
}

#[derive(Deserialize)]
pub struct SnapQ {
    #[serde(default = "d_path")]
    pub path: String,
}

fn d_path() -> String {
    "put".into()
}

/// GET /lab/api/profilemap/snapshot?path=put|replication
pub async fn snapshot(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<SnapQ>,
) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let path = match q.path.as_str() {
        "replication" | "get" => q.path.clone(),
        _ => "put".into(),
    };
    let mut samples = gather_prom(&state, &path).await;
    if samples.is_empty() {
        samples = gather_recon(&state).await;
    }
    let tree = build_tree(&samples, &path);
    let tree_json: Vec<Value> = tree
        .iter()
        .map(|(svc, stages)| {
            json!({
                "service": svc,
                "stages": stages.iter().map(|s| json!({
                    "name": s.name,
                    "pct": s.pct,
                    "sum_seconds": s.sum_seconds,
                    "count": s.count,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    Json(json!({
        "ok": true,
        "path": path,
        "source": if tree_json.is_empty() { "empty" } else { "recon_or_prom" },
        "tree": tree_json,
    }))
    .into_response()
}

fn render_tree(lang: &str, path: &str, tree: &[(String, Vec<TreeNode>)]) -> String {
    if tree.is_empty() {
        return format!(
            "<p class=\"note\">{}</p>",
            esc(i18n::t(lang, "pmap.empty"))
        );
    }
    let mut html = String::from("<div class=\"pmap-tree\">");
    for (svc, stages) in tree {
        html.push_str(&format!("<div class=\"pmap-svc\"><h3>{}</h3><ul>", esc(svc)));
        for s in stages {
            html.push_str(&format!(
                "<li><span class=\"pmap-name\">{}</span>\
                 <i class=\"pmap-bar\" style=\"--w:{:.1}%\"></i>\
                 <em>{:.1}%</em></li>",
                esc(&s.name),
                s.pct,
                s.pct
            ));
        }
        html.push_str("</ul></div>");
    }
    html.push_str(&format!(
        "<p class=\"note\">path=<code>{}</code></p></div>",
        esc(path)
    ));
    html
}

/// GET /lab/profilemap
pub async fn page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (_, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let samples = gather_recon(&state).await;
    let tree = build_tree(&samples, "put");
    let tree_html = render_tree(lang, "put", &tree);
    let body = format!(
        r#"<div class="pagehead"><h1>{title}</h1></div>
<p class="statline">{blurb}</p>
<p class="note">{note}</p>
<div class="page-sec">
  <button type="button" class="btn" id="pmap-pulse">{pulse}</button>
  <label class="pmap-path">{path_lbl}
    <select id="pmap-path">
      <option value="put" selected>PUT</option>
      <option value="replication">replication</option>
      <option value="get">GET</option>
    </select>
  </label>
</div>
<div class="page-sec" id="pmap-tree">{tree}</div>
<script>
(function(){{
  async function j(url, opt){{
    const r = await fetch(url, Object.assign({{credentials:'same-origin'}}, opt||{{}}));
    return r.json();
  }}
  function paint(tree, path){{
    const host = document.getElementById('pmap-tree');
    if (!tree || !tree.length) {{
      host.innerHTML = '<p class="note">{empty_js}</p>';
      return;
    }}
    let h = '<div class="pmap-tree">';
    for (const svc of tree) {{
      h += '<div class="pmap-svc"><h3>'+svc.service+'</h3><ul>';
      for (const s of (svc.stages||[])) {{
        h += '<li><span class="pmap-name">'+s.name+'</span>'+
             '<i class="pmap-bar" style="--w:'+s.pct.toFixed(1)+'%"></i>'+
             '<em>'+s.pct.toFixed(1)+'%</em></li>';
      }}
      h += '</ul></div>';
    }}
    h += '<p class="note">path=<code>'+path+'</code></p></div>';
    host.innerHTML = h;
  }}
  document.getElementById('pmap-pulse').onclick = async () => {{
    await j('/lab/api/profilemap/pulse', {{method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{n:16, bytes:4096}})}});
    const path = document.getElementById('pmap-path').value;
    const d = await j('/lab/api/profilemap/snapshot?path='+encodeURIComponent(path));
    paint(d.tree||[], path);
  }};
  document.getElementById('pmap-path').onchange = async (e) => {{
    const path = e.target.value;
    const d = await j('/lab/api/profilemap/snapshot?path='+encodeURIComponent(path));
    paint(d.tree||[], path);
  }};
}})();
</script>"#,
        title = esc(i18n::t(lang, "lab.tool.profilemap.title")),
        blurb = esc(i18n::t(lang, "lab.tool.profilemap.blurb")),
        note = esc(i18n::t(lang, "pmap.note")),
        pulse = esc(i18n::t(lang, "pmap.btn.pulse")),
        path_lbl = esc(i18n::t(lang, "pmap.path")),
        tree = tree_html,
        empty_js = esc(i18n::t(lang, "pmap.empty")),
    );
    crate::pages::lab_tool_shell(&state, &headers, &sess, "profilemap", body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percents_sum_near_100() {
        let samples = vec![
            StageSample {
                service: "proxy-server".into(),
                path: "put".into(),
                stage: "fan_out".into(),
                sum_seconds: 21.0,
                count: 10,
            },
            StageSample {
                service: "proxy-server".into(),
                path: "put".into(),
                stage: "ring_lookup".into(),
                sum_seconds: 7.0,
                count: 10,
            },
            StageSample {
                service: "proxy-server".into(),
                path: "put".into(),
                stage: "auth".into(),
                sum_seconds: 4.0,
                count: 10,
            },
        ];
        let tree = build_tree(&samples, "put");
        assert_eq!(tree.len(), 1);
        let sum: f64 = tree[0].1.iter().map(|n| n.pct).sum();
        assert!((sum - 100.0).abs() < 0.01, "sum={sum}");
    }
}
