//! Tenants & Users administration.
//!
//! tempauth accounts live in each proxy's `proxy-server.conf` (`[filter:tempauth]`
//! `user_<account>_<user> = <key> [.admin|.reseller_admin|groups]`), not in the
//! Swift API. Managing them therefore means rewriting that block on every proxy
//! node and restarting swift-proxy. The apply is:
//!   - admin-gated (console config declares who may administer accounts),
//!   - strictly validated (no whitespace/control chars → no config injection),
//!   - rolling, one node at a time, each backed up and health-gated,
//!   - rolled back across all touched nodes on any failure,
//!   - guarded against deleting the account you are signed in as.
//!
//! Account-level properties that ARE API-mutable (quota, account metadata) are
//! handled on the Account page via the Swift API; this module owns identity.

use crate::session::{self, Session};
use crate::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Clone)]
pub struct Account {
    pub account: String,
    pub user: String,
    pub key: String,
    pub admin: bool,
    pub reseller: bool,
    pub groups: Vec<String>,
}

// ------------------------------------------------------------- parse / render

fn parse_user_line(line: &str) -> Option<Account> {
    let line = line.trim();
    if !line.starts_with("user_") {
        return None;
    }
    let (lhs, rhs) = line.split_once('=')?;
    let name = lhs.trim().strip_prefix("user_")?.trim();
    let (account, user) = name.split_once('_')?;
    if account.is_empty() || user.is_empty() {
        return None;
    }
    let mut toks = rhs.split_whitespace();
    let key = toks.next()?.to_string();
    let (mut admin, mut reseller, mut groups) = (false, false, Vec::new());
    for t in toks {
        match t {
            ".admin" => admin = true,
            ".reseller_admin" => reseller = true,
            _ if t.starts_with("http") => {} // storage-url override — leave alone
            _ => groups.push(t.to_string()),
        }
    }
    Some(Account {
        account: account.to_string(),
        user: user.to_string(),
        key,
        admin,
        reseller,
        groups,
    })
}

fn render_user_line(a: &Account) -> String {
    let mut s = format!("user_{}_{} = {}", a.account, a.user, a.key);
    if a.reseller {
        s.push_str(" .reseller_admin");
    }
    if a.admin {
        s.push_str(" .admin");
    }
    for g in &a.groups {
        s.push(' ');
        s.push_str(g);
    }
    s
}

fn parse_roster(conf: &str) -> Vec<Account> {
    conf.lines().filter_map(parse_user_line).collect()
}

/// Replace the `user_*` lines inside `[filter:tempauth]` with `roster`,
/// preserving every other line (including other tempauth options and every
/// other section). Returns None if the config doesn't have the expected
/// sections — a guard against writing a config that won't boot.
fn rewrite_conf(conf: &str, roster: &[Account]) -> Option<String> {
    let mut out: Vec<String> = Vec::new();
    let mut in_tempauth = false;
    let mut inserted = false;
    let (mut seen_app, mut seen_tempauth) = (false, false);
    for line in conf.lines() {
        let t = line.trim_start();
        if t.starts_with('[') {
            if in_tempauth && !inserted {
                for a in roster {
                    out.push(render_user_line(a));
                }
                inserted = true;
            }
            in_tempauth = t.starts_with("[filter:tempauth]");
            if in_tempauth {
                seen_tempauth = true;
                inserted = false;
            }
            if t.starts_with("[app:proxy-server]") {
                seen_app = true;
            }
            out.push(line.to_string());
            continue;
        }
        if in_tempauth && t.starts_with("user_") {
            continue; // drop old user lines
        }
        out.push(line.to_string());
    }
    if in_tempauth && !inserted {
        for a in roster {
            out.push(render_user_line(a));
        }
    }
    if !seen_app || !seen_tempauth {
        return None;
    }
    Some(out.join("\n") + "\n")
}

// ------------------------------------------------------------- validation

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().next().map_or(false, |c| c.is_ascii_alphanumeric())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !s.contains('_')
}

fn valid_key(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.chars().all(|c| !c.is_whitespace() && !c.is_control())
}

fn valid_group(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| !c.is_whitespace() && !c.is_control())
}

// ------------------------------------------------------------- ssh apply

// Transport lives in `nodes`: one ssh implementation for the whole console.
use crate::nodes::run as ssh_out;

async fn apply_node(state: &Arc<AppState>, node: &str, conf: &str) -> Result<(), String> {
    let p = &state.cfg.proxy_conf;
    let svc = &state.cfg.proxy_service;
    let remote = format!(
        "set -e; cp -a {p} {p}.consolebak; umask 077; cat > {p}.new && mv {p}.new {p}; systemctl restart {svc}"
    );
    crate::nodes::run_in(state, node, &remote, conf.as_bytes()).await?;
    // Health gate: the proxy must serve /healthcheck again before we move on.
    let hc = format!(
        "curl -s -o /dev/null -w %{{http_code}} http://127.0.0.1:{}/healthcheck",
        state.cfg.proxy_port
    );
    for i in 0..12 {
        tokio::time::sleep(std::time::Duration::from_millis(if i == 0 { 900 } else { 700 })).await;
        if ssh_out(state, node, &hc).await.unwrap_or_default().trim() == "200" {
            return Ok(());
        }
    }
    Err("proxy did not pass healthcheck after restart".into())
}

async fn rollback_node(state: &Arc<AppState>, node: &str) {
    let p = &state.cfg.proxy_conf;
    let svc = &state.cfg.proxy_service;
    let remote =
        format!("if [ -f {p}.consolebak ]; then mv {p}.consolebak {p}; systemctl restart {svc}; fi");
    let _ = ssh_out(state, node, &remote).await;
}

/// Read the current roster from the first reachable proxy node.
pub async fn fetch_roster(state: &Arc<AppState>) -> Result<Vec<Account>, String> {
    let mut last = "no proxy nodes configured".to_string();
    let proxies = crate::nodes::proxy_nodes(state);
    for node in &proxies {
        match ssh_out(state, node, &format!("cat {}", state.cfg.proxy_conf)).await {
            Ok(conf) => return Ok(parse_roster(&conf)),
            Err(e) => last = format!("{node}: {e}"),
        }
    }
    Err(last)
}

/// Write `roster` to every proxy node, rolling and health-gated. On any
/// failure, roll back every node already touched (including the failed one).
async fn apply_roster(state: &Arc<AppState>, roster: &[Account]) -> Result<usize, String> {
    if crate::nodes::proxy_nodes(state).is_empty() {
        return Err("no proxy nodes configured".into());
    }
    let mut done: Vec<&String> = Vec::new();
    let proxies = crate::nodes::proxy_nodes(state);
    for node in &proxies {
        let conf = ssh_out(state, node, &format!("cat {}", state.cfg.proxy_conf))
            .await
            .map_err(|e| format!("read {node}: {e}"))?;
        let newc = rewrite_conf(&conf, roster)
            .ok_or_else(|| format!("refusing to write a malformed config for {node}"))?;
        if let Err(e) = apply_node(state, node, &newc).await {
            rollback_node(state, node).await;
            for d in &done {
                rollback_node(state, d).await;
            }
            return Err(format!(
                "{node}: {e} — rolled back {} node(s), no change applied",
                done.len() + 1
            ));
        }
        done.push(node);
    }
    Ok(done.len())
}

// ------------------------------------------------------------- auth gate

/// A session that is allowed to administer accounts: the console config lists
/// this (tenant, user) with .admin or .reseller_admin, and the feature is on.
pub fn require_admin(state: &Arc<AppState>, headers: &HeaderMap) -> Result<Session, Response> {
    let (_, sess) = session::from_headers(&state.sessions, headers)
        .ok_or_else(|| (axum::http::StatusCode::UNAUTHORIZED, "session required").into_response())?;
    if !state.cfg.account_admin {
        return Err((axum::http::StatusCode::FORBIDDEN, "account administration is disabled").into_response());
    }
    let ok = state.cfg.accounts.iter().any(|a| {
        a.tenant == sess.tenant
            && a.user == sess.user
            && a.roles.iter().any(|r| r == ".admin" || r == ".reseller_admin")
    });
    if !ok {
        return Err((axum::http::StatusCode::FORBIDDEN, "admin role required").into_response());
    }
    Ok(sess)
}

pub fn is_console_admin(state: &Arc<AppState>, sess: &Session) -> bool {
    state.cfg.account_admin
        && state.cfg.accounts.iter().any(|a| {
            a.tenant == sess.tenant
                && a.user == sess.user
                && a.roles.iter().any(|r| r == ".admin" || r == ".reseller_admin")
        })
}

// ------------------------------------------------------------- handlers

fn account_json(a: &Account) -> Value {
    // Keys are write-only: never returned to the browser.
    json!({
        "account": a.account,
        "user": a.user,
        "admin": a.admin,
        "reseller": a.reseller,
        "groups": a.groups,
    })
}

pub async fn list_accounts(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let _ = match require_admin(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    match fetch_roster(&state).await {
        Ok(roster) => {
            let mut items: Vec<Value> = roster.iter().map(account_json).collect();
            items.sort_by(|a, b| {
                (a["account"].as_str(), a["user"].as_str())
                    .cmp(&(b["account"].as_str(), b["user"].as_str()))
            });
            Json(json!({ "accounts": items })).into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_GATEWAY, Json(json!({ "error": e }))).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpsertReq {
    account: String,
    user: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    admin: bool,
    #[serde(default)]
    reseller: bool,
    #[serde(default)]
    groups: Vec<String>,
}

fn bad(msg: &str) -> Response {
    (axum::http::StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
}

pub async fn upsert_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<UpsertReq>,
) -> Response {
    let _ = match require_admin(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let account = req.account.trim().to_string();
    let user = req.user.trim().to_string();
    if !valid_name(&account) {
        return bad("account must be alphanumeric/.-, no underscore, start with a letter or digit");
    }
    if !valid_name(&user) {
        return bad("user must be alphanumeric/.-, no underscore, start with a letter or digit");
    }
    let groups: Vec<String> = req.groups.iter().map(|g| g.trim().to_string()).filter(|g| !g.is_empty()).collect();
    if groups.iter().any(|g| !valid_group(g)) {
        return bad("groups must not contain whitespace or control characters");
    }

    let mut roster = match fetch_roster(&state).await {
        Ok(r) => r,
        Err(e) => return (axum::http::StatusCode::BAD_GATEWAY, Json(json!({ "error": e }))).into_response(),
    };
    let existing = roster.iter().position(|a| a.account == account && a.user == user);
    let key = if req.key.trim().is_empty() {
        match existing.map(|i| roster[i].key.clone()) {
            Some(k) => k,
            None => return bad("a key is required for a new user"),
        }
    } else {
        if !valid_key(req.key.trim()) {
            return bad("key must not contain whitespace or control characters");
        }
        req.key.trim().to_string()
    };
    let entry = Account { account, user, key, admin: req.admin, reseller: req.reseller, groups };
    match existing {
        Some(i) => roster[i] = entry,
        None => roster.push(entry),
    }
    match apply_roster(&state, &roster).await {
        Ok(n) => Json(json!({ "ok": true, "nodes": n })).into_response(),
        Err(e) => (axum::http::StatusCode::BAD_GATEWAY, Json(json!({ "error": e }))).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The live cluster's proxy-server.conf shape.
    const CONF: &str = "\
[app:proxy-server]
bind_ip = 0.0.0.0
bind_port = 8080
storage_url = http://172.18.1.3:8085

[filter:tempauth]

user_test_tester = rust-cluster-2026.bench .admin
";

    #[test]
    fn parse_existing() {
        let r = parse_roster(CONF);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].account, "test");
        assert_eq!(r[0].user, "tester");
        assert_eq!(r[0].key, "rust-cluster-2026.bench");
        assert!(r[0].admin && !r[0].reseller);
    }

    #[test]
    fn rewrite_adds_and_preserves() {
        let mut roster = parse_roster(CONF);
        roster.push(Account {
            account: "demo".into(), user: "alice".into(), key: "sekret".into(),
            admin: false, reseller: false, groups: vec!["readers".into()],
        });
        let out = rewrite_conf(CONF, &roster).expect("rewrite");
        // both sections preserved, node specifics preserved
        assert!(out.contains("[app:proxy-server]"));
        assert!(out.contains("storage_url = http://172.18.1.3:8085"));
        assert!(out.contains("[filter:tempauth]"));
        // both users present, exactly once each, no stale duplicate
        assert_eq!(out.matches("user_test_tester = rust-cluster-2026.bench .admin").count(), 1);
        assert!(out.contains("user_demo_alice = sekret readers"));
        // re-parsing the output round-trips to 2 accounts
        assert_eq!(parse_roster(&out).len(), 2);
    }

    #[test]
    fn rewrite_removes_user() {
        let roster: Vec<Account> = Vec::new();
        // an empty roster on a conf with sections drops all user lines
        let out = rewrite_conf(CONF, &roster).expect("rewrite");
        assert!(!out.contains("user_test_tester"));
        assert!(out.contains("[filter:tempauth]"));
    }

    #[test]
    fn rewrite_refuses_malformed() {
        assert!(rewrite_conf("just some text\nno sections", &[]).is_none());
    }

    #[test]
    fn validation() {
        assert!(valid_name("demo"));
        assert!(valid_name("acme-1.2"));
        assert!(!valid_name("has_underscore"));
        assert!(!valid_name(".hidden"));
        assert!(!valid_name(""));
        assert!(valid_key("rust-cluster-2026.bench"));
        assert!(!valid_key("has space"));
        assert!(!valid_key("has\nnewline"));
    }
}

#[derive(Deserialize)]
pub struct DeleteReq {
    account: String,
    user: String,
}

pub async fn delete_account(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DeleteReq>,
) -> Response {
    let sess = match require_admin(&state, &headers) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let account = req.account.trim();
    let user = req.user.trim();
    if account == sess.tenant && user == sess.user {
        return bad("you cannot delete the account you are signed in as");
    }
    let mut roster = match fetch_roster(&state).await {
        Ok(r) => r,
        Err(e) => return (axum::http::StatusCode::BAD_GATEWAY, Json(json!({ "error": e }))).into_response(),
    };
    let before = roster.len();
    roster.retain(|a| !(a.account == account && a.user == user));
    if roster.len() == before {
        return bad("no such user");
    }
    if roster.is_empty() {
        return bad("refusing to remove the last remaining account");
    }
    match apply_roster(&state, &roster).await {
        Ok(n) => Json(json!({ "ok": true, "nodes": n })).into_response(),
        Err(e) => (axum::http::StatusCode::BAD_GATEWAY, Json(json!({ "error": e }))).into_response(),
    }
}
