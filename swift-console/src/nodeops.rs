//! Node down / up — the one Lab tool that stops a storage node, for an
//! honest high-availability drill.
//!
//! Everything else in Chaos Arcade is a data fault with a provable on-disk
//! undo and deliberately never stops a service. A real HA test needs the
//! opposite: take a whole node out of the cluster and watch the survivors
//! carry the load. That is riskier, so it rides the same guard as every other
//! mutation — [`nodes::mutate`] with `Scope::ServiceUnit`, which journals the
//! exact `systemctl start` undo *before* stopping anything and auto-restarts
//! the node when the TTL expires, so a node always comes back even if the
//! operator walks away.
//!
//! It stops the cluster's swift services by name and never touches
//! `swift-console` or `swift-deploy`, so the console cannot take itself down.

use crate::util::esc;
use crate::{i18n, lab, nodes, AppState};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::sync::Arc;

/// The swift cluster services a node runs. Deliberately explicit — a
/// `swift-*` glob would also match `swift-console`/`swift-deploy` and let the
/// console stop itself. Shared with the Monitor's service-health grid.
pub const SERVICES: &str = "swift-proxy swift-object swift-container swift-account \
swift-object-replicator swift-object-reconstructor swift-object-updater \
swift-container-updater swift-account-replicator swift-container-replicator";

const DEFAULT_TTL: u64 = 300;

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

/// Which nodes are currently held down by a pending journal entry.
fn down_nodes(state: &Arc<AppState>) -> Vec<(String, String, u64)> {
    nodes::pending(state)
        .into_iter()
        .filter(|e| e.scope == nodes::Scope::ServiceUnit)
        .map(|e| (e.node, e.id, e.expires))
        .collect()
}

/// GET /lab/api/node/status — per-node service health + which nodes are down.
pub async fn status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    // One cheap ssh per node: is-active for each service, plus a reachability
    // signal (an unreachable node is itself a "down" answer).
    let probe = format!("systemctl is-active {SERVICES} 2>/dev/null | tr '\\n' ' '; echo");
    let results = nodes::fan_out(&state, &probe).await;
    let held = down_nodes(&state);
    let rows: Vec<_> = results
        .into_iter()
        .map(|r| {
            let states: Vec<&str> = r.out.split_whitespace().collect();
            let active = states.iter().filter(|s| **s == "active").count();
            let total = SERVICES.split_whitespace().count();
            let hold = held.iter().find(|(n, _, _)| *n == r.node);
            json!({
                "node": r.node,
                "reachable": r.ok,
                "active_services": active,
                "total_services": total,
                "up": r.ok && active == total,
                "held_down": hold.is_some(),
                "journal_id": hold.map(|(_, id, _)| id.clone()),
                "expires": hold.map(|(_, _, e)| *e),
            })
        })
        .collect();
    Json(json!({ "nodes": rows, "services": SERVICES })).into_response()
}

#[derive(serde::Deserialize)]
struct DownReq {
    node: String,
    #[serde(default)]
    ttl_secs: u64,
}

/// POST /lab/api/node/down {node, ttl_secs?} — stop a node's swift services.
pub async fn down(State(state): State<Arc<AppState>>, headers: HeaderMap, body: String) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let req: DownReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    if nodes::by_name(&state, &req.node).is_none() {
        return err(StatusCode::BAD_REQUEST, &format!("unknown node {}", req.node));
    }
    let ttl = if req.ttl_secs == 0 { DEFAULT_TTL } else { req.ttl_secs };
    let stop = format!("systemctl stop {SERVICES}");
    let start = format!("systemctl start {SERVICES}");
    match nodes::mutate(
        &state,
        nodes::Mutation {
            node: &req.node,
            scope: nodes::Scope::ServiceUnit,
            script: &stop,
            undo: &start,
            reason: "HA drill: node down",
            ttl_secs: ttl,
        },
    )
    .await
    {
        Ok(entry) => Json(json!({
            "ok": true,
            "node": req.node,
            "journal_id": entry.id,
            "expires": entry.expires,
            "auto_restart_in_secs": ttl,
        }))
        .into_response(),
        Err(e) => err(StatusCode::CONFLICT, &e),
    }
}

#[derive(serde::Deserialize)]
struct UpReq {
    #[serde(default)]
    node: String,
    #[serde(default)]
    journal_id: String,
}

/// POST /lab/api/node/up {node|journal_id} — restart a node early (before TTL).
pub async fn up(State(state): State<Arc<AppState>>, headers: HeaderMap, body: String) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let req: UpReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, &format!("bad request: {e}")),
    };
    // Resolve to a pending ServiceUnit journal entry: by id, or the newest for
    // the named node.
    let id = if !req.journal_id.is_empty() {
        req.journal_id
    } else if !req.node.is_empty() {
        match down_nodes(&state).into_iter().find(|(n, _, _)| *n == req.node) {
            Some((_, id, _)) => id,
            None => return err(StatusCode::NOT_FOUND, "node is not held down"),
        }
    } else {
        return err(StatusCode::BAD_REQUEST, "node or journal_id required");
    };
    match nodes::undo(&state, &id).await {
        Ok(()) => Json(json!({ "ok": true, "restarted": true, "journal_id": id })).into_response(),
        Err(e) => err(StatusCode::CONFLICT, &e),
    }
}

/// GET /lab/nodes — the tool page: a node roster with a Down / Bring-up control.
pub async fn page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (_, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let title = esc(i18n::t(lang, "lab.tool.nodes.title"));
    let blurb = esc(i18n::t(lang, "lab.tool.nodes.blurb"));
    let mutations_on = state.cfg.lab_mutations;
    let warn = if mutations_on {
        String::new()
    } else {
        format!(
            "<p class=\"statline\">{}</p>",
            esc(i18n::t(lang, "nodes.disabled"))
        )
    };
    // Rows are filled by JS from /lab/api/node/status so the page reflects live
    // state on every load and after every action.
    let body = format!(
        r#"<div class="pagehead"><h1>{title}</h1></div>
<p class="statline">{blurb}</p>{warn}
<div class=" nodeops" data-nodeops="1">
  <table class="tbl"><thead><tr>
    <th>{h_node}</th><th>{h_state}</th><th>{h_svc}</th><th>{h_act}</th>
  </tr></thead><tbody id="nodeops-rows"><tr><td colspan="4">…</td></tr></tbody></table>
  <p class="hint" id="nodeops-msg"></p>
</div>
<script>
(function(){{
  var rows=document.getElementById('nodeops-rows');
  var msg=document.getElementById('nodeops-msg');
  function j(u,o){{return fetch(u,o).then(function(r){{return r.json();}});}}
  function refresh(){{
    j('/lab/api/node/status').then(function(d){{
      rows.innerHTML='';
      (d.nodes||[]).forEach(function(n){{
        var tr=document.createElement('tr');
        var st = n.held_down ? 'DOWN (drill)' : (n.up ? 'up' : (n.reachable?'degraded':'unreachable'));
        var act = n.held_down
          ? '<button data-up="'+n.node+'">Bring up</button>'
          : '<button data-down="'+n.node+'">Take down</button>';
        tr.innerHTML='<td>'+n.node+'</td><td>'+st+'</td><td>'+n.active_services+'/'+n.total_services+'</td><td>'+act+'</td>';
        rows.appendChild(tr);
      }});
    }});
  }}
  rows.addEventListener('click',function(e){{
    var d=e.target.getAttribute('data-down'), u=e.target.getAttribute('data-up');
    if(d){{ if(!confirm('Take '+d+' down? It auto-restarts after the TTL.'))return;
      msg.textContent='stopping '+d+'…';
      j('/lab/api/node/down',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{node:d}})}})
        .then(function(r){{msg.textContent=r.error?('error: '+r.error):(d+' down; auto-restart in '+r.auto_restart_in_secs+'s');refresh();}});
    }}
    if(u){{ msg.textContent='starting '+u+'…';
      j('/lab/api/node/up',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{node:u}})}})
        .then(function(r){{msg.textContent=r.error?('error: '+r.error):(u+' back up');refresh();}});
    }}
  }});
  refresh(); setInterval(refresh,5000);
}})();
</script>"#,
        h_node = esc(i18n::t(lang, "nodes.col.node")),
        h_state = esc(i18n::t(lang, "nodes.col.state")),
        h_svc = esc(i18n::t(lang, "nodes.col.services")),
        h_act = esc(i18n::t(lang, "nodes.col.action")),
    );
    crate::pages::lab_tool_shell(&state, &headers, &sess, "nodes", body)
}
