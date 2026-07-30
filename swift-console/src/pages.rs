//! Server-rendered HTML: unified shell, login, and the Files surface pages.
//! All data is rendered into the page (content is visible without JS); the
//! single JS file only wires interactions.

use crate::admin;
use crate::files_api;
use crate::i18n;
use crate::lab;
use crate::nodes;
use crate::search;
use crate::session;
use crate::swift;
use crate::testing;
use crate::util;
use crate::util::{enc_obj, enc_q, enc_seg, esc, fmt_bytes};
use crate::AppState;
use axum::extract::{Form, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The theme cookie. Not HttpOnly: the switch writes it client-side for an
/// instant, reload-free change, and it carries no security value.
pub const THEME_COOKIE: &str = "sc_theme";

/// The stored choice: "light" or "dark". There is no third "follow the OS"
/// option — the console states a theme rather than deferring one.
fn theme_choice(headers: &HeaderMap) -> &'static str {
    match util::cookie_value(headers, THEME_COOKIE).as_deref() {
        Some("light") => "light",
        // Dark is the default, not a fallback: the palette was designed
        // dark-first and the login page is fixed dark, so an unset cookie
        // lands on the console's own voice.
        _ => "dark",
    }
}

/// (the <html> attribute, the meta color-scheme content). The attribute is
/// rendered into the first bytes of the document, ahead of the render-blocking
/// stylesheet, so the first paint is already the right theme.
fn theme_attrs(choice: &str) -> (&'static str, &'static str) {
    match choice {
        "light" => (" data-theme=\"light\"", "light"),
        _ => (" data-theme=\"dark\"", "dark"),
    }
}

// ---------------------------------------------------------------- icons
// One hand-drawn set: 16px grid, 1.5px stroke, round caps and joins.

fn icon(paths: &str, class: &str) -> String {
    format!(
        "<svg class=\"ic {class}\" viewBox=\"0 0 16 16\" width=\"16\" height=\"16\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">{paths}</svg>"
    )
}

fn ic_folder() -> String {
    icon("<path d=\"M2 4.4c0-.7.5-1.2 1.2-1.2h2.9l1.6 1.8h5.1c.7 0 1.2.5 1.2 1.2v5.4c0 .7-.5 1.2-1.2 1.2H3.2c-.7 0-1.2-.5-1.2-1.2z\"/>", "")
}
fn ic_file() -> String {
    icon("<path d=\"M4 2.9c0-.5.4-.9.9-.9H9l3 3v8.1c0 .5-.4.9-.9.9H4.9c-.5 0-.9-.4-.9-.9z\"/><path d=\"M9 2.2V5h2.8\"/>", "")
}
fn ic_trash() -> String {
    icon("<path d=\"M3.2 4.6h9.6\"/><path d=\"M6.4 4.4V3.3c0-.4.3-.7.7-.7h1.8c.4 0 .7.3.7.7v1.1\"/><path d=\"M4.6 4.8l.6 7.9c0 .4.4.7.8.7h4c.4 0 .8-.3.8-.7l.6-7.9\"/>", "")
}
fn ic_download() -> String {
    icon("<path d=\"M8 2.6v6.8\"/><path d=\"M5.3 6.8L8 9.5l2.7-2.7\"/><path d=\"M3 11.6v1.2c0 .4.3.7.7.7h8.6c.4 0 .7-.3.7-.7v-1.2\"/>", "")
}
fn ic_upload() -> String {
    icon("<path d=\"M8 9.4V2.9\"/><path d=\"M5.3 5.3L8 2.6l2.7 2.7\"/><path d=\"M3 11.6v1.2c0 .4.3.7.7.7h8.6c.4 0 .7-.3.7-.7v-1.2\"/>", "")
}
fn ic_link() -> String {
    icon("<path d=\"M6.6 9.4l2.8-2.8\"/><path d=\"M7.6 5l1-1a2.26 2.26 0 0 1 3.2 3.2l-1 1\"/><path d=\"M8.4 11l-1 1a2.26 2.26 0 0 1-3.2-3.2l1-1\"/>", "")
}
fn ic_sliders() -> String {
    icon("<path d=\"M2.6 5.2h10.8\"/><path d=\"M2.6 10.8h10.8\"/><circle cx=\"6.2\" cy=\"5.2\" r=\"1.5\"/><circle cx=\"9.8\" cy=\"10.8\" r=\"1.5\"/>", "")
}
fn ic_x() -> String {
    icon("<path d=\"M4.6 4.6l6.8 6.8\"/><path d=\"M11.4 4.6l-6.8 6.8\"/>", "")
}
fn ic_bucket() -> String {
    icon("<path d=\"M3 5.4l1.2 7.2c.1.4.4.8.9.8h5.8c.5 0 .8-.4.9-.8L13 5.4\"/><ellipse cx=\"8\" cy=\"4.6\" rx=\"5.2\" ry=\"1.6\"/>", "")
}
fn ic_deploy() -> String {
    icon("<path d=\"M8 11.4V3.4\"/><path d=\"M4.9 6.5L8 3.4l3.1 3.1\"/><path d=\"M3.2 13.4h9.6\"/>", "")
}
fn ic_monitor() -> String {
    icon("<path d=\"M2 8.6h2.3l1.5-3.8 2.6 6.8 1.5-4.4H14\"/>", "")
}
fn ic_person() -> String {
    icon("<circle cx=\"8\" cy=\"5.4\" r=\"2.4\"/><path d=\"M3.4 13.4a4.7 4.7 0 0 1 9.2 0\"/>", "")
}
fn ic_plus() -> String {
    icon("<path d=\"M8 3.6v8.8\"/><path d=\"M3.6 8h8.8\"/>", "")
}
fn ic_search() -> String {
    icon("<circle cx=\"7\" cy=\"7\" r=\"3.6\"/><path d=\"M12.4 12.4l-2.6-2.6\"/>", "")
}
fn ic_users() -> String {
    icon(
        "<circle cx=\"6\" cy=\"5.6\" r=\"2.1\"/><path d=\"M2.3 12.8a3.9 3.9 0 0 1 7.4 0\"/><path d=\"M10.4 3.8a2.1 2.1 0 0 1 0 3.9\"/><path d=\"M11.2 12.8a3.9 3.9 0 0 0-1.5-3\"/>",
        "",
    )
}

fn ic_flask() -> String {
    icon("<path d=\"M6.4 2.4v3.6L3.1 11.7c-.4.7.1 1.6.9 1.6h8c.8 0 1.3-.9.9-1.6L9.6 6V2.4\"/><path d=\"M5.6 2.4h4.8\"/><path d=\"M4.9 9.4h6.2\"/>", "")
}

/// The single source of truth for the top nav: (key, href, i18n key). A new
/// surface is one row here, not an edit in three places.
const NAV: &[(&str, &str, &str)] = &[
    ("files", "/files", "nav.files"),
    ("deploy", "/deploy", "nav.deploy"),
    ("monitor", "/monitor", "nav.monitor"),
    ("lab", "/lab", "nav.lab"),
    ("test", "/test", "nav.test"),
];

fn ic_gauge() -> String {
    icon(
        "<path d=\"M2.8 11.6a6 6 0 1 1 10.4 0\"/><path d=\"M8 11.2L10.9 6.6\"/><circle cx=\"8\" cy=\"11.6\" r=\"1\"/>",
        "",
    )
}

fn nav_icon(key: &str) -> String {
    match key {
        "files" => ic_folder(),
        "deploy" => ic_deploy(),
        "monitor" => ic_monitor(),
        "test" => ic_gauge(),
        _ => ic_flask(),
    }
}

fn mark_svg() -> &'static str {
    // The two neutral bars inherit currentColor, so the mark takes the
    // sidebar's ink in the shell and the card's ink on the login page. Only
    // the accent bar is coloured, and it has to be a class because SVG
    // presentation attributes do not accept var().
    "<svg viewBox=\"0 0 16 16\" width=\"18\" height=\"18\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.1\" stroke-linecap=\"round\" aria-hidden=\"true\"><path d=\"M3 4.2h10\"/><path class=\"mk-a\" d=\"M3 8h10\"/><path d=\"M3 11.8h7\"/></svg>"
}

pub async fn favicon() -> Response {
    let svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 16 16\"><rect width=\"16\" height=\"16\" rx=\"3\" fill=\"#1b1b1b\"/><g fill=\"none\" stroke-width=\"2\" stroke-linecap=\"round\"><path d=\"M3.5 4.6h9\" stroke=\"#dcdcdc\"/><path d=\"M3.5 8h9\" stroke=\"#3ecf8e\"/><path d=\"M3.5 11.4h6.2\" stroke=\"#dcdcdc\"/></g></svg>";
    ([(header::CONTENT_TYPE, "image/svg+xml")], svg).into_response()
}

pub async fn css() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "max-age=300"),
        ],
        include_str!("../static/console.css"),
    )
        .into_response()
}

pub async fn js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "max-age=300"),
        ],
        include_str!("../static/console.js"),
    )
        .into_response()
}

// ---------------------------------------------------------------- shell

struct Shell<'a> {
    active: &'a str, // "files" | "deploy" | "monitor" | "lab"
    title: &'a str,
    tenant: &'a str,
    user: &'a str,
    /// Extra sidebar block (bucket list on files pages).
    side_extra: String,
    /// data attributes for <body>
    body_data: String,
    content: String,
    /// iframe pages get an unpadded, full-height main area
    frame_mode: bool,
}

fn shell(state: &Arc<AppState>, headers: &HeaderMap, s: Shell) -> Html<String> {
    let lang = i18n::lang(headers);
    let nav_item = |href: &str, label: &str, ic: String, key: &str| {
        let cls = if s.active == key { "navlink active" } else { "navlink" };
        format!("<a class=\"{cls}\" href=\"{href}\">{ic}<span>{label}</span></a>")
    };
    // Lab and Testing only appear once switched on, so an unchanged config
    // boots to exactly the three surfaces it had before.
    let nav = NAV
        .iter()
        .filter(|(k, _, _)| match *k {
            "lab" => state.cfg.lab_enabled,
            "test" => state.cfg.test_enabled,
            _ => true,
        })
        .map(|(k, href, key)| nav_item(href, i18n::t(lang, key), nav_icon(k), k))
        .collect::<Vec<_>>()
        .join("\n    ");
    let main_cls = if s.frame_mode { "main frame-mode" } else { "main" };
    let footer = format!(
        "<footer class=\"foot\">Swift Console {} &middot; cluster {} &middot; Swift LB {}</footer>",
        esc(VERSION),
        esc(&state.cfg.cluster_name),
        esc(state.cfg.swift_base.trim_start_matches("http://"))
    );
    let choice = theme_choice(headers);
    let (theme_attr, scheme) = theme_attrs(choice);
    let seg = |v: &str, label: &str| {
        let cls = if choice == v { "seg-b active" } else { "seg-b" };
        let pressed = if choice == v { "true" } else { "false" };
        format!("<button class=\"{cls}\" name=\"t\" value=\"{v}\" aria-pressed=\"{pressed}\">{label}</button>")
    };
    let theme_switch = format!(
        "<form class=\"seg theme-seg\" method=\"post\" action=\"/theme\" role=\"group\" aria-label=\"{}\">{}{}</form>",
        i18n::t(lang, "theme.label"),
        seg("light", i18n::t(lang, "theme.light")),
        seg("dark", i18n::t(lang, "theme.dark")),
    );
    // Language is a console-wide choice, sitting beside the theme rather than
    // hidden inside one pane.
    let lseg = |v: &str, label: &str| {
        let cls = if lang == v { "seg-b active" } else { "seg-b" };
        let pressed = if lang == v { "true" } else { "false" };
        format!("<button class=\"{cls}\" name=\"l\" value=\"{v}\" aria-pressed=\"{pressed}\">{label}</button>")
    };
    let lang_switch = format!(
        "<form class=\"seg theme-seg\" method=\"post\" action=\"/lang\" role=\"group\" aria-label=\"{}\">{}{}</form>",
        i18n::t(lang, "shell.language"),
        lseg("en", "EN"),
        lseg("zh", "中文"),
    );
    let html = format!(
        r#"<!doctype html>
<html lang="{html_lang}"{theme_attr}>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="{scheme}">
<title>{title} &middot; Swift Console</title>
<link rel="icon" href="/favicon.svg">
<link rel="stylesheet" href="/static/console.css">
</head>
<body{body_data}>
<div class="app">
<aside class="side">
  <a class="mark" href="/files">{mark}<span class="mark-t">Swift <em>Console</em></span></a>
  <nav class="nav">
    {nav}
  </nav>
  {side_extra}
  <div class="side-foot">
    {lang_switch}
    {theme_switch}
    <div class="side-foot-row">
      <div class="ident" title="{signedin}">{ident_icon}<span>{tenant}:{user}</span></div>
      <form method="post" action="/logout"><button class="btn-signout" type="submit">{signout}</button></form>
    </div>
  </div>
</aside>
<main class="{main_cls}">
{content}
{footer}
</main>
</div>
<script src="/static/console.js"></script>
</body>
</html>"#,
        title = esc(s.title),
        theme_attr = theme_attr,
        scheme = scheme,
        html_lang = i18n::html_lang(lang),
        theme_switch = theme_switch,
        lang_switch = lang_switch,
        signout = i18n::t(lang, "shell.signout"),
        signedin = i18n::t(lang, "shell.signedin"),
        body_data = s.body_data,
        mark = mark_svg(),
        nav = nav,
        side_extra = s.side_extra,
        ident_icon = ic_person(),
        tenant = esc(s.tenant),
        user = esc(s.user),
        content = s.content,
        footer = if s.frame_mode { String::new() } else { footer },
    );
    Html(html)
}

/// Sidebar bucket list for files pages.
async fn side_buckets(
    state: &Arc<AppState>,
    sid: &str,
    lang: &str,
    active_bucket: Option<&str>,
    active_page: &str,
) -> String {
    let buckets = swift::list_buckets(state, sid).await.unwrap_or_default();
    let mut items = String::new();
    for b in &buckets {
        if b.name == files_api::TRASH || b.name.ends_with("_segments") {
            continue;
        }
        let cls = if Some(b.name.as_str()) == active_bucket {
            "bkt active"
        } else {
            "bkt"
        };
        items.push_str(&format!(
            "<a class=\"{cls}\" href=\"/files/b/{href}\">{ic}<span class=\"bkt-n\">{name}</span><span class=\"bkt-m\">{count} &middot; {size}</span></a>",
            href = enc_seg(&b.name),
            ic = ic_bucket(),
            name = esc(&b.name),
            count = b.count,
            size = fmt_bytes(b.bytes),
        ));
    }
    if items.is_empty() {
        items = format!(
            "<div class=\"bkt-none\">{}</div>",
            i18n::t(lang, "files.nobuckets")
        );
    }
    let search_cls = if active_page == "search" { "bkt active" } else { "bkt" };
    let trash_cls = if active_page == "trash" { "bkt active" } else { "bkt" };
    let acct_cls = if active_page == "account" { "bkt active" } else { "bkt" };
    // Tenants & Users is an admin-only surface.
    let admin_link = {
        let is_admin = state
            .sessions
            .get(sid)
            .map(|s| admin::is_console_admin(state, &s))
            .unwrap_or(false);
        if is_admin {
            let cls = if active_page == "users" { "bkt active" } else { "bkt" };
            format!(
                "<a class=\"{cls}\" href=\"/files/users\">{ic}<span class=\"bkt-n\">{label}</span></a>",
                ic = ic_users(),
                label = i18n::t(lang, "files.users"),
            )
        } else {
            String::new()
        }
    };
    format!(
        r#"<div class="side-sec">
  <div class="side-h"><span>{buckets}</span><button class="btn-side-new" id="side-new-bucket" title="{newbucket}">{plus}</button></div>
  <div class="bkt-list">{items}</div>
  <div class="side-links">
    <a class="{search_cls}" href="/files/search">{search}<span class="bkt-n">{search_l}</span></a>
    <a class="{trash_cls}" href="/files/trash">{trash}<span class="bkt-n">{trash_l}</span></a>
    <a class="{acct_cls}" href="/files/account">{person}<span class="bkt-n">{acct_l}</span></a>
    {admin_link}
  </div>
</div>"#,
        buckets = i18n::t(lang, "files.buckets"),
        newbucket = i18n::t(lang, "files.newbucket"),
        plus = ic_plus(),
        items = items,
        search = ic_search(),
        search_l = i18n::t(lang, "files.search"),
        trash = ic_trash(),
        trash_l = i18n::t(lang, "files.trash"),
        person = ic_person(),
        acct_l = i18n::t(lang, "files.account"),
        admin_link = admin_link,
    )
}

fn new_bucket_dialog(lang: &str) -> String {
    format!(
        r#"<dialog id="dlg-new-bucket" class="dlg">
  <form method="dialog" class="dlg-in">
    <h2>{title}</h2>
    <label class="fld"><span>{name}</span><input id="nb-name" type="text" autocomplete="off" spellcheck="false" placeholder="my-bucket"></label>
    <p class="hint">{hint}</p>
    <div class="dlg-row"><button class="btn-plain" value="cancel">{cancel}</button><button class="btn-primary" id="nb-create" value="default">{create}</button></div>
    <p class="err" id="nb-err"></p>
  </form>
</dialog>"#,
        title = i18n::t(lang, "files.newbucket"),
        name = i18n::t(lang, "files.name"),
        hint = i18n::t(lang, "files.namehint"),
        cancel = i18n::t(lang, "common.cancel"),
        create = i18n::t(lang, "files.createbucket"),
    )
}

// ---------------------------------------------------------------- auth pages

pub async fn root(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if session::from_headers(&state.sessions, &headers).is_some() {
        Redirect::to("/files").into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

fn login_html(state: &Arc<AppState>, lang: &str, error: Option<&str>) -> Html<String> {
    let err = match error {
        Some(e) => format!("<p class=\"err on\">{}</p>", esc(e)),
        None => String::new(),
    };
    Html(format!(
        r#"<!doctype html>
<html lang="{html_lang}" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>{title} &middot; Swift Console</title>
<link rel="icon" href="/favicon.svg">
<link rel="stylesheet" href="/static/console.css">
</head>
<body class="login-body">
<main class="login-wrap">
  <form class="login-card" method="post" action="/login">
    <div class="login-mark">{mark}<span class="mark-t">Swift <em>Console</em></span></div>
    <label class="fld"><span>{tenant}</span><input name="tenant" type="text" autocomplete="username" spellcheck="false" required autofocus></label>
    <label class="fld"><span>{user}</span><input name="user" type="text" spellcheck="false" required></label>
    <label class="fld"><span>{key}</span><input name="key" type="password" autocomplete="current-password" required></label>
    <button class="btn-primary wide" type="submit">{submit}</button>
    {err}
    <p class="login-note">{note}</p>
  </form>
  <p class="login-foot">Swift Console {ver} &middot; {cluster_l} {cluster}</p>
</main>
</body>
</html>"#,
        html_lang = i18n::html_lang(lang),
        title = i18n::t(lang, "login.title"),
        mark = mark_svg(),
        tenant = i18n::t(lang, "login.tenant"),
        user = i18n::t(lang, "login.user"),
        key = i18n::t(lang, "login.key"),
        submit = i18n::t(lang, "login.submit"),
        note = i18n::t(lang, "login.note"),
        err = err,
        ver = esc(VERSION),
        cluster_l = i18n::t(lang, "shell.cluster"),
        cluster = esc(&state.cfg.cluster_name),
    ))
}

pub async fn login_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if session::from_headers(&state.sessions, &headers).is_some() {
        return Redirect::to("/files").into_response();
    }
    login_html(&state, i18n::lang(&headers), None).into_response()
}

#[derive(Deserialize)]
pub struct LoginForm {
    tenant: String,
    user: String,
    key: String,
}

pub async fn login_submit(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(f): Form<LoginForm>,
) -> Response {
    let lang = i18n::lang(&headers);
    let tenant = f.tenant.trim().to_string();
    let user = f.user.trim().to_string();
    match swift::auth(
        &state.http,
        &state.cfg.auth_url,
        &state.cfg.swift_base,
        &tenant,
        &user,
        &f.key,
    )
    .await
    {
        Ok((token, storage_url)) => {
            let sid = state.sessions.create(session::Session {
                token,
                storage_url,
                tenant,
                user,
                key: f.key,
                last_seen: std::time::Instant::now(),
                tempurl_default_secs: state.cfg.tempurl_default_secs,
            });
            let cookie = format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
                session::COOKIE,
                sid,
                state.cfg.session_idle_hours * 3600
            );
            (
                StatusCode::SEE_OTHER,
                [(header::SET_COOKIE, cookie), (header::LOCATION, "/files".into())],
            )
                .into_response()
        }
        Err(e) => login_html(
            &state,
            lang,
            Some(&i18n::t(lang, "login.failed").replace("{e}", &e)),
        )
        .into_response(),
    }
}

pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some((sid, _)) = session::from_headers(&state.sessions, &headers) {
        state.sessions.remove(&sid);
    }
    let cookie = format!(
        "{}=gone; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        session::COOKIE
    );
    (
        StatusCode::SEE_OTHER,
        [(header::SET_COOKIE, cookie), (header::LOCATION, "/login".into())],
    )
        .into_response()
}

fn page_session(
    state: &Arc<AppState>,
    headers: &HeaderMap,
) -> Result<(String, session::Session), Response> {
    session::from_headers(&state.sessions, headers)
        .ok_or_else(|| Redirect::to("/login").into_response())
}

#[derive(Deserialize)]
pub struct ThemeForm {
    t: String,
}

#[derive(Deserialize)]
pub struct LangForm {
    l: String,
}

/// No-JS fallback for the language switch, mirroring `theme_set`.
pub async fn lang_set(headers: HeaderMap, Form(f): Form<LangForm>) -> Response {
    let v = if f.l == "zh" { "zh" } else { "en" };
    let cookie = format!(
        "{}={v}; Path=/; SameSite=Lax; Max-Age=31536000",
        i18n::LANG_COOKIE
    );
    let back = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .and_then(|r| {
            r.split_once("://")
                .map(|(_, rest)| match rest.find('/') {
                    Some(i) => &rest[i..],
                    None => "/",
                })
                .filter(|p| p.starts_with('/'))
        })
        .unwrap_or("/files")
        .to_string();
    (
        StatusCode::SEE_OTHER,
        [(header::SET_COOKIE, cookie), (header::LOCATION, back)],
    )
        .into_response()
}

/// No-JS fallback for the theme switch. The client intercepts the form submit,
/// so this only runs when JS is off — but the control stays a real form so the
/// preference is never gated on scripting.
pub async fn theme_set(headers: HeaderMap, Form(f): Form<ThemeForm>) -> Response {
    let cookie = match f.t.as_str() {
        "light" => format!("{THEME_COOKIE}=light; Path=/; SameSite=Lax; Max-Age=31536000"),
        // Anything unrecognised is dark, matching theme_choice — a bad value
        // must never leave the switch showing no active segment.
        _ => format!("{THEME_COOKIE}=dark; Path=/; SameSite=Lax; Max-Age=31536000"),
    };
    // Only ever bounce back to a same-site path.
    let back = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .and_then(|r| {
            let path = r.split_once("://").map(|(_, rest)| match rest.find('/') {
                Some(i) => &rest[i..],
                None => "/",
            });
            path.filter(|p| p.starts_with('/'))
        })
        .unwrap_or("/files")
        .to_string();
    (
        StatusCode::SEE_OTHER,
        [(header::SET_COOKIE, cookie), (header::LOCATION, back)],
    )
        .into_response()
}

// ---------------------------------------------------------------- buckets page

pub async fn buckets_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, sess) = match page_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let buckets = match swift::list_buckets(&state, &sid).await {
        Ok(b) => b,
        Err(e) => return error_page(&state, &headers, &sess, "files", &e.msg()),
    };
    let (_, ah) = swift::head(&state, &sid, "").await.unwrap_or((0, Default::default()));
    let bytes_used: u64 = ah
        .get("x-account-bytes-used")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let quota = ah
        .get("x-account-meta-quota-bytes")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let quota_txt = match quota {
        Some(q) => i18n::t(lang, "files.quota").replace("{q}", &fmt_bytes(q)),
        None => i18n::t(lang, "files.noquota").to_string(),
    };
    let user_buckets: Vec<_> = buckets
        .iter()
        .filter(|b| b.name != files_api::TRASH && !b.name.ends_with("_segments"))
        .collect();
    let system_buckets: Vec<_> = buckets
        .iter()
        .filter(|b| b.name == files_api::TRASH || b.name.ends_with("_segments"))
        .collect();

    let mut rows = String::new();
    for b in &user_buckets {
        rows.push_str(&format!(
            r#"<tr data-bucket="{name_a}"><td><a class="cell-link" href="/files/b/{href}">{ic}<span>{name}</span></a></td><td class="num">{count}</td><td class="num">{size}</td><td class="acts"><button class="ibtn act-bucket-settings" data-bucket="{name_a}" title="{settings}">{sl}</button><button class="ibtn danger act-bucket-delete" data-bucket="{name_a}" title="{del}">{x}</button></td></tr>"#,
            name_a = esc(&b.name),
            href = enc_seg(&b.name),
            ic = ic_bucket(),
            name = esc(&b.name),
            count = b.count,
            size = fmt_bytes(b.bytes),
            settings = i18n::t(lang, "files.bucketsettings"),
            del = i18n::t(lang, "files.deletebucket"),
            sl = ic_sliders(),
            x = ic_x(),
        ));
    }
    for b in &system_buckets {
        rows.push_str(&format!(
            r#"<tr class="muted-row" data-bucket="{name_a}"><td><a class="cell-link" href="/files/b/{href}">{ic}<span>{name}</span></a><span class="sys-note">{sys}</span></td><td class="num">{count}</td><td class="num">{size}</td><td class="acts"></td></tr>"#,
            name_a = esc(&b.name),
            href = enc_seg(&b.name),
            ic = ic_bucket(),
            name = esc(&b.name),
            count = b.count,
            size = fmt_bytes(b.bytes),
            sys = i18n::t(lang, "files.system"),
        ));
    }
    let table = if rows.is_empty() {
        format!(
            "<p class=\"empty\">{}</p>",
            i18n::t(lang, "files.nobucketshint")
        )
    } else {
        format!(
            r#"<div class="tbl-wrap"><table class="tbl"><thead><tr><th>{bucket}</th><th class="num">{objects}</th><th class="num">{size}</th><th class="acts-h"></th></tr></thead><tbody>{rows}</tbody></table></div>"#,
            bucket = i18n::t(lang, "files.bucket"),
            objects = i18n::t(lang, "files.objects"),
            size = i18n::t(lang, "files.size"),
        )
    };
    let statline = i18n::t(lang, "files.stat")
        .replace("{n}", &user_buckets.len().to_string())
        .replace("{s}", if user_buckets.len() == 1 { "" } else { "s" })
        .replace("{used}", &fmt_bytes(bytes_used))
        .replace("{quota}", &esc(&quota_txt));
    let content = format!(
        r#"<div class="pagehead"><h1>{title}</h1><div class="actions"><button class="btn-primary" id="new-bucket-btn">{plus}{newbucket}</button></div></div>
<p class="statline">{statline}</p>
{table}
{nb_dlg}
{settings_dlg}"#,
        title = i18n::t(lang, "files.title"),
        plus = ic_plus(),
        newbucket = i18n::t(lang, "files.newbucket"),
        statline = statline,
        table = table,
        nb_dlg = new_bucket_dialog(lang),
        settings_dlg = bucket_settings_dialog(lang),
    );
    let side = side_buckets(&state, &sid, lang, None, "buckets").await;
    shell(
        &state,
        &headers,
        Shell {
            active: "files",
            title: i18n::t(lang, "files.title"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: side,
            body_data: " data-page=\"buckets\"".into(),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

fn bucket_settings_dialog(lang: &str) -> String {
    format!(
        r#"<dialog id="dlg-bucket-settings" class="dlg dlg-wide">
  <div class="dlg-in">
    <h2 id="bs-title">{title}</h2>
    <div class="dlg-scroll">
    <section class="dset">
      <h3>{access}</h3>
      <div class="radio-row">
        <label class="radio"><input type="radio" name="bs-access" id="bs-private" value="private"><span>{private}</span></label>
        <label class="radio"><input type="radio" name="bs-access" id="bs-public" value="public"><span>{public}</span></label>
      </div>
      <p class="hint">{aclhint}</p>
      <label class="fld"><span>{readacl}</span><input id="bs-read" type="text" spellcheck="false" placeholder="e.g. .r:*,.rlistings"></label>
      <label class="fld"><span>{writeacl}</span><input id="bs-write" type="text" spellcheck="false" placeholder="e.g. tenant:user"></label>
    </section>
    <section class="dset">
      <h3>{quota}</h3>
      <div class="two-col">
        <label class="fld"><span>{maxbytes}</span><input id="bs-quota-bytes" type="text" inputmode="numeric" placeholder="{none}"></label>
        <label class="fld"><span>{maxobjects}</span><input id="bs-quota-count" type="text" inputmode="numeric" placeholder="{none}"></label>
      </div>
    </section>
    <section class="dset">
      <h3>{metadata}</h3>
      <div class="meta-rows" id="bs-meta"></div>
      <button class="btn sm" id="bs-meta-add" type="button">{addrow}</button>
    </section>
    <p class="statline" id="bs-stats"></p>
    </div>
    <div class="dlg-row"><button class="btn-plain" id="bs-cancel" type="button">{cancel}</button><button class="btn-primary" id="bs-save" type="button">{save}</button></div>
    <p class="err" id="bs-err"></p>
  </div>
</dialog>"#,
        title = i18n::t(lang, "files.bucketsettings"),
        access = i18n::t(lang, "files.access"),
        private = i18n::t(lang, "files.private"),
        public = i18n::t(lang, "files.publicread"),
        aclhint = i18n::t(lang, "files.aclhint"),
        readacl = i18n::t(lang, "files.readacl"),
        writeacl = i18n::t(lang, "files.writeacl"),
        quota = i18n::t(lang, "files.quotasec"),
        maxbytes = i18n::t(lang, "files.maxbytes"),
        maxobjects = i18n::t(lang, "files.maxobjects"),
        none = i18n::t(lang, "files.emptynone"),
        metadata = i18n::t(lang, "files.metadata"),
        addrow = i18n::t(lang, "files.addrow"),
        cancel = i18n::t(lang, "common.cancel"),
        save = i18n::t(lang, "common.savechanges"),
    )
}

// ---------------------------------------------------------------- objects page

fn fmt_when(s: &Option<String>) -> String {
    // Listing gives e.g. 2026-07-24T06:09:31.123456 : keep date + hh:mm.
    match s {
        Some(v) => {
            let v = v.replace('T', " ");
            v.get(0..16).map(String::from).unwrap_or(v)
        }
        None => "-".into(),
    }
}

pub async fn objects_page(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let (sid, sess) = match page_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let prefix = q.get("prefix").cloned().unwrap_or_default();
    let listing = match swift::list_objects(&state, &sid, &bucket, &prefix, false, 10000).await {
        Ok(l) => l,
        Err(e) => return error_page(&state, &headers, &sess, "files", &e.msg()),
    };

    // Breadcrumbs.
    let mut crumbs = format!(
        "<a class=\"crumb\" href=\"/files/b/{}\">{}<span>{}</span></a>",
        enc_seg(&bucket),
        ic_bucket(),
        esc(&bucket)
    );
    let mut acc = String::new();
    for seg in prefix.split('/').filter(|s| !s.is_empty()) {
        acc.push_str(seg);
        acc.push('/');
        crumbs.push_str(&format!(
            "<span class=\"crumb-sep\">/</span><a class=\"crumb\" href=\"/files/b/{}?prefix={}\"><span>{}</span></a>",
            enc_seg(&bucket),
            enc_q(&acc),
            esc(seg)
        ));
    }

    let mut rows = String::new();
    for f in &listing.folders {
        let rel = f.strip_prefix(&prefix).unwrap_or(f);
        rows.push_str(&format!(
            r#"<tr class="row-folder" data-name="{full}"><td><a class="cell-link" href="/files/b/{b}?prefix={pq}">{ic}<span>{rel}</span></a></td><td class="num">-</td><td>{folder}</td><td>-</td><td class="acts"><a class="ibtn" href="/files/zip/{b}?prefix={pq}" title="{t_zip}">{dl}</a><button class="ibtn act-folder-trash" data-prefix="{full}" title="{t_trash}">{tr}</button><button class="ibtn danger act-folder-delete" data-prefix="{full}" title="{t_del}">{x}</button></td></tr>"#,
            full = esc(f),
            b = enc_seg(&bucket),
            pq = enc_q(f),
            ic = ic_folder(),
            rel = esc(rel),
            folder = i18n::t(lang, "files.folder"),
            t_zip = i18n::t(lang, "files.dlzip"),
            t_trash = i18n::t(lang, "files.trashfolder"),
            t_del = i18n::t(lang, "files.delfolder"),
            dl = ic_download(),
            tr = ic_trash(),
            x = ic_x(),
        ));
    }
    for f in &listing.files {
        let name = f.name.clone().unwrap_or_default();
        let rel = name.strip_prefix(&prefix).unwrap_or(&name);
        rows.push_str(&format!(
            r#"<tr class="row-file" data-name="{full}"><td><button class="cell-link act-details" data-name="{full}" title="{t_det}">{ic}<span>{rel}</span></button></td><td class="num">{size}</td><td class="ctype">{ctype}</td><td class="when">{when}</td><td class="acts"><a class="ibtn" href="/files/download/{b}/{op}" title="{t_dl}">{dl}</a><button class="ibtn act-share" data-name="{full}" title="{t_share}">{ln}</button><button class="ibtn act-obj-trash" data-name="{full}" title="{t_trash}">{tr}</button><button class="ibtn danger act-obj-delete" data-name="{full}" title="{t_del}">{x}</button></td></tr>"#,
            full = esc(&name),
            ic = ic_file(),
            rel = esc(rel),
            t_det = i18n::t(lang, "files.details"),
            t_dl = i18n::t(lang, "files.download"),
            t_share = i18n::t(lang, "files.share"),
            t_trash = i18n::t(lang, "files.trashobj"),
            t_del = i18n::t(lang, "common.delete"),
            size = fmt_bytes(f.bytes),
            ctype = esc(f.content_type.as_deref().unwrap_or("-")),
            when = fmt_when(&f.last_modified),
            b = enc_seg(&bucket),
            op = enc_obj(&name),
            dl = ic_download(),
            ln = ic_link(),
            tr = ic_trash(),
            x = ic_x(),
        ));
    }
    let body_table = if rows.is_empty() {
        format!(
            "<p class=\"empty\">{}</p>",
            i18n::t(lang, "files.emptyfolder")
        )
    } else {
        format!(
            r#"<div class="tbl-wrap"><table class="tbl" id="obj-table"><thead><tr><th>{name}</th><th class="num">{size}</th><th>{ctype}</th><th>{modified}</th><th class="acts-h"></th></tr></thead><tbody>{rows}</tbody></table></div>"#,
            name = i18n::t(lang, "files.name"),
            size = i18n::t(lang, "files.size"),
            ctype = i18n::t(lang, "files.type"),
            modified = i18n::t(lang, "files.modified"),
        )
    };
    let trunc = if listing.truncated {
        format!("<p class=\"note\">{}</p>", i18n::t(lang, "files.trunc"))
    } else {
        String::new()
    };
    let content = format!(
        r#"<div class="pagehead"><div class="crumbs">{crumbs}</div>
<div class="actions">
  <input id="filter" class="filter" type="search" placeholder="{filter}" autocomplete="off">
  <button class="btn" id="new-folder-btn">{newfolder}</button>
  <a class="btn" href="/files/zip/{b}?prefix={pq}" title="{ziptitle}">{zip}</a>
  <button class="btn" id="bucket-settings-btn" data-bucket="{ba}">{sl}{settings}</button>
  <button class="btn-primary" id="upload-btn">{up}{upload}</button>
</div></div>
{body_table}
{trunc}
{dialogs}"#,
        crumbs = crumbs,
        filter = i18n::t(lang, "files.filter"),
        newfolder = i18n::t(lang, "files.newfolder"),
        ziptitle = i18n::t(lang, "files.ziptitle"),
        zip = i18n::t(lang, "files.zip"),
        settings = i18n::t(lang, "files.settings"),
        upload = i18n::t(lang, "files.upload"),
        b = enc_seg(&bucket),
        pq = enc_q(&prefix),
        ba = esc(&bucket),
        sl = ic_sliders(),
        up = ic_upload(),
        body_table = body_table,
        trunc = trunc,
        dialogs = objects_dialogs(lang),
    );
    let side = side_buckets(&state, &sid, lang, Some(&bucket), "objects").await;
    shell(
        &state,
        &headers,
        Shell {
            active: "files",
            title: &format!("{} · {}", bucket, i18n::t(lang, "files.title")),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: side,
            body_data: format!(
                " data-page=\"objects\" data-bucket=\"{}\" data-prefix=\"{}\"",
                esc(&bucket),
                esc(&prefix)
            ),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

fn objects_dialogs(lang: &str) -> String {
    let upload = format!(
        r#"<dialog id="dlg-upload" class="dlg">
  <div class="dlg-in">
    <h2>{title}</h2>
    <p class="hint">{hint}</p>
    <input id="up-input" type="file" multiple>
    <div id="up-list" class="up-list"></div>
    <div class="dlg-row"><button class="btn-plain" id="up-close" type="button">{close}</button><button class="btn-primary" id="up-start" type="button">{start}</button></div>
  </div>
</dialog>"#,
        title = i18n::t(lang, "files.uploadfiles"),
        hint = i18n::t(lang, "files.uploadhint"),
        close = i18n::t(lang, "common.close"),
        start = i18n::t(lang, "files.startupload"),
    );
    let newfolder = format!(
        r#"<dialog id="dlg-new-folder" class="dlg">
  <form method="dialog" class="dlg-in">
    <h2>{title}</h2>
    <label class="fld"><span>{name}</span><input id="nf-name" type="text" spellcheck="false" placeholder="reports"></label>
    <div class="dlg-row"><button class="btn-plain" value="cancel">{cancel}</button><button class="btn-primary" id="nf-create" value="default">{create}</button></div>
    <p class="err" id="nf-err"></p>
  </form>
</dialog>"#,
        title = i18n::t(lang, "files.newfolder"),
        name = i18n::t(lang, "files.foldername"),
        cancel = i18n::t(lang, "common.cancel"),
        create = i18n::t(lang, "files.createfolder"),
    );
    let details = format!(
        r#"<dialog id="dlg-details" class="dlg dlg-wide">
  <div class="dlg-in">
    <h2 id="dt-title">{title}</h2>
    <div class="dlg-scroll">
    <dl class="kv" id="dt-kv"></dl>
    <section class="dset">
      <h3>{ctype}</h3>
      <label class="fld"><span>{mime}</span><input id="dt-ctype" type="text" spellcheck="false"></label>
    </section>
    <section class="dset">
      <h3>{metadata}</h3>
      <div class="meta-rows" id="dt-meta"></div>
      <button class="btn sm" id="dt-meta-add" type="button">{addrow}</button>
    </section>
    <section class="dset">
      <h3>{expiry}</h3>
      <div class="two-col">
        <label class="fld"><span>{deleteat}</span><input id="dt-expire" type="datetime-local"></label>
        <button class="btn sm" id="dt-expire-clear" type="button">{clear}</button>
      </div>
      <p class="hint">{exphint}</p>
    </section>
    <section class="dset" id="dt-public-sec" hidden>
      <h3>{publiclink}</h3>
      <div class="copy-row"><input id="dt-public-url" type="text" readonly><button class="btn sm act-copy" data-copy="dt-public-url" type="button">{copy}</button></div>
    </section>
    <section class="dset">
      <h3>{danger}</h3>
      <div class="danger-row">
        <label class="check" id="dt-slo-wrap" hidden><input type="checkbox" id="dt-slo-segments"><span>{segs}</span></label>
        <button class="btn danger-btn" id="dt-delete" type="button">{delperm}</button>
      </div>
    </section>
    </div>
    <div class="dlg-row"><button class="btn-plain" id="dt-close" type="button">{close}</button><button class="btn-primary" id="dt-save" type="button">{save}</button></div>
    <p class="err" id="dt-err"></p>
  </div>
</dialog>"#,
        title = i18n::t(lang, "files.object"),
        ctype = i18n::t(lang, "files.contenttype"),
        mime = i18n::t(lang, "files.mimetype"),
        metadata = i18n::t(lang, "files.metadata"),
        addrow = i18n::t(lang, "files.addrow"),
        expiry = i18n::t(lang, "files.expiry"),
        deleteat = i18n::t(lang, "files.deleteat"),
        clear = i18n::t(lang, "files.clearexpiry"),
        exphint = i18n::t(lang, "files.expiryhint"),
        publiclink = i18n::t(lang, "files.publiclink"),
        copy = i18n::t(lang, "common.copy"),
        danger = i18n::t(lang, "files.danger"),
        segs = i18n::t(lang, "files.delsegments"),
        delperm = i18n::t(lang, "files.delperm"),
        close = i18n::t(lang, "common.close"),
        save = i18n::t(lang, "common.savechanges"),
    );
    let share = format!(
        r#"<dialog id="dlg-share" class="dlg">
  <div class="dlg-in">
    <h2 id="sh-title">{title}</h2>
    <section class="dset">
      <h3>{templink}</h3>
      <div class="two-col">
        <label class="fld"><span>{validfor}</span>
          <select id="sh-expiry">
            <option value="3600">{h1}</option>
            <option value="86400">{d1}</option>
            <option value="604800">{d7}</option>
            <option value="custom">{custom}</option>
          </select>
        </label>
        <label class="fld" id="sh-custom-wrap" hidden><span>{seconds}</span><input id="sh-custom" type="number" min="60" step="60"></label>
      </div>
      <button class="btn-primary" id="sh-generate" type="button">{gen}</button>
      <div class="copy-row" id="sh-result-wrap" hidden><input id="sh-url" type="text" readonly><button class="btn sm act-copy" data-copy="sh-url" type="button">{copy}</button></div>
      <p class="hint">{linkhint}</p>
    </section>
    <section class="dset" id="sh-public-sec" hidden>
      <h3>{publiclink}</h3>
      <div class="copy-row"><input id="sh-public-url" type="text" readonly><button class="btn sm act-copy" data-copy="sh-public-url" type="button">{copy}</button></div>
      <p class="hint">{publichint}</p>
    </section>
    <div class="dlg-row"><button class="btn-plain" id="sh-close" type="button">{close}</button></div>
    <p class="err" id="sh-err"></p>
  </div>
</dialog>"#,
        title = i18n::t(lang, "files.share"),
        templink = i18n::t(lang, "files.templink"),
        validfor = i18n::t(lang, "files.validfor"),
        h1 = i18n::t(lang, "files.hour1"),
        d1 = i18n::t(lang, "files.day1"),
        d7 = i18n::t(lang, "files.day7"),
        custom = i18n::t(lang, "files.custom"),
        seconds = i18n::t(lang, "files.seconds"),
        gen = i18n::t(lang, "files.genlink"),
        copy = i18n::t(lang, "common.copy"),
        linkhint = i18n::t(lang, "files.linkhint"),
        publiclink = i18n::t(lang, "files.publiclink"),
        publichint = i18n::t(lang, "files.publichint"),
        close = i18n::t(lang, "common.close"),
    );
    format!(
        "{upload}{newfolder}{details}{share}{settings}{nb}",
        settings = bucket_settings_dialog(lang),
        nb = new_bucket_dialog(lang)
    )
}

// ---------------------------------------------------------------- trash page

pub async fn trash_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, sess) = match page_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let listing = match swift::list_objects(&state, &sid, files_api::TRASH, "", true, 100000).await
    {
        Ok(l) => l,
        Err(swift::SwiftError::Other(ref m)) if m.contains("not found") => swift::Listing {
            files: vec![],
            folders: vec![],
            truncated: false,
        },
        Err(e) => return error_page(&state, &headers, &sess, "files", &e.msg()),
    };

    // Group by original bucket, aggregate one folder level below the bucket.
    struct Agg {
        files: Vec<(String, u64, Option<String>)>, // rest, bytes, modified
        folders: BTreeMap<String, (u64, u64)>,     // subfolder -> (count, bytes)
    }
    let mut groups: BTreeMap<String, Agg> = BTreeMap::new();
    for f in &listing.files {
        let name = match &f.name {
            Some(n) => n,
            None => continue,
        };
        let (bucket, rest) = match name.split_once('/') {
            Some(v) => v,
            None => continue,
        };
        let g = groups.entry(bucket.to_string()).or_insert(Agg {
            files: Vec::new(),
            folders: BTreeMap::new(),
        });
        if let Some((sub, _)) = rest.split_once('/') {
            let e = g.folders.entry(format!("{sub}/")).or_insert((0, 0));
            e.0 += 1;
            e.1 += f.bytes;
        } else {
            g.files
                .push((rest.to_string(), f.bytes, f.last_modified.clone()));
        }
    }

    // One phrase, two grammars: the count and its noun are looked up together.
    let items = |n: u64| {
        i18n::t(lang, "files.items")
            .replace("{n}", &n.to_string())
            .replace("{s}", if n == 1 { "" } else { "s" })
    };
    let mut sections = String::new();
    for (bucket, agg) in &groups {
        let total = agg.files.len() + agg.folders.values().map(|v| v.0 as usize).sum::<usize>();
        let mut rows = String::new();
        for (sub, (count, bytes)) in &agg.folders {
            rows.push_str(&format!(
                r#"<tr class="row-folder"><td><span class="cell-plain">{ic}<span>{sub}</span></span><span class="sys-note">{items}</span></td><td class="num">{size}</td><td>-</td><td class="acts"><button class="btn sm act-trash-restore" data-prefix="{pfx}">{restore}</button><button class="ibtn danger act-trash-delete" data-prefix="{pfx}" title="{delperm}">{x}</button></td></tr>"#,
                ic = ic_folder(),
                sub = esc(sub),
                items = items(*count),
                size = fmt_bytes(*bytes),
                pfx = esc(&format!("{bucket}/{sub}")),
                restore = i18n::t(lang, "files.restore"),
                delperm = i18n::t(lang, "files.delperm"),
                x = ic_x(),
            ));
        }
        for (rest, bytes, modified) in &agg.files {
            rows.push_str(&format!(
                r#"<tr class="row-file"><td><span class="cell-plain">{ic}<span>{rest}</span></span></td><td class="num">{size}</td><td class="when">{when}</td><td class="acts"><button class="btn sm act-trash-restore" data-path="{path}">{restore}</button><button class="ibtn danger act-trash-delete" data-path="{path}" title="{delperm}">{x}</button></td></tr>"#,
                ic = ic_file(),
                rest = esc(rest),
                size = fmt_bytes(*bytes),
                when = fmt_when(modified),
                path = esc(&format!("{bucket}/{rest}")),
                restore = i18n::t(lang, "files.restore"),
                delperm = i18n::t(lang, "files.delperm"),
                x = ic_x(),
            ));
        }
        sections.push_str(&format!(
            r#"<section class="trash-group">
<div class="group-h">{ic}<h2>{bucket}</h2><span class="group-m">{items}</span><span class="group-sp"></span><button class="btn sm act-trash-restore" data-prefix="{bpfx}">{restoreall}</button><button class="btn sm danger-quiet act-trash-delete" data-prefix="{bpfx}">{deleteall}</button></div>
<div class="tbl-wrap"><table class="tbl"><thead><tr><th>{item}</th><th class="num">{size}</th><th>{deleted}</th><th class="acts-h"></th></tr></thead><tbody>{rows}</tbody></table></div>
</section>"#,
            ic = ic_bucket(),
            bucket = esc(bucket),
            items = items(total as u64),
            bpfx = esc(&format!("{bucket}/")),
            restoreall = i18n::t(lang, "files.restoreall"),
            deleteall = i18n::t(lang, "files.deleteall"),
            item = i18n::t(lang, "files.item"),
            size = i18n::t(lang, "files.size"),
            deleted = i18n::t(lang, "files.deleted"),
            rows = rows,
        ));
    }
    if sections.is_empty() {
        sections = format!("<p class=\"empty\">{}</p>", i18n::t(lang, "files.trashempty"));
    }
    let content = format!(
        r#"<div class="pagehead"><h1>{title}</h1><div class="actions"><button class="btn danger-quiet" id="empty-trash-btn">{empty}</button></div></div>
<p class="statline">{note}</p>
{sections}"#,
        title = i18n::t(lang, "files.trash"),
        empty = i18n::t(lang, "files.emptytrash"),
        note = i18n::t(lang, "files.trashnote"),
        sections = sections,
    );
    let side = side_buckets(&state, &sid, lang, None, "trash").await;
    shell(
        &state,
        &headers,
        Shell {
            active: "files",
            title: i18n::t(lang, "files.trash"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: side,
            body_data: " data-page=\"trash\"".into(),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

// ---------------------------------------------------------------- account page

pub async fn account_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, sess) = match page_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let (st, h) = match swift::head(&state, &sid, "").await {
        Ok(v) => v,
        Err(e) => return error_page(&state, &headers, &sess, "files", &e.msg()),
    };
    if st >= 300 {
        return error_page(&state, &headers, &sess, "files", &format!("account HEAD failed ({st})"));
    }
    let getv = |name: &str| {
        h.get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let bytes_used = getv("x-account-bytes-used").parse::<u64>().unwrap_or(0);
    let containers = getv("x-account-container-count");
    let objects = getv("x-account-object-count");
    let quota = getv("x-account-meta-quota-bytes");
    let temp_key_set = !getv("x-account-meta-temp-url-key").is_empty();

    let mut meta_rows = String::new();
    for (name, value) in h.iter() {
        let n = name.as_str().to_ascii_lowercase();
        if let Some(k) = n.strip_prefix("x-account-meta-") {
            if k == "quota-bytes" || k == "temp-url-key" || k == "temp-url-key-2" {
                continue;
            }
            if let Ok(v) = value.to_str() {
                meta_rows.push_str(&format!(
                    r#"<div class="meta-row"><input class="mk" value="{k}" spellcheck="false"><input class="mv" value="{v}" spellcheck="false"><button class="ibtn danger meta-del" title="{rm}">{x}</button></div>"#,
                    k = esc(k),
                    v = esc(v),
                    rm = i18n::t(lang, "common.remove"),
                    x = ic_x(),
                ));
            }
        }
    }
    if meta_rows.is_empty() {
        meta_rows = format!("<p class=\"hint\">{}</p>", i18n::t(lang, "acct.nometa"));
    }

    let mut user_rows = String::new();
    for a in &state.cfg.accounts {
        user_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&a.tenant),
            esc(&a.user),
            esc(&a.roles.join(", "))
        ));
    }
    if user_rows.is_empty() {
        user_rows = format!(
            "<tr><td colspan=\"3\">{}</td></tr>",
            i18n::t(lang, "acct.noaccounts")
        );
    }

    let statline = i18n::t(lang, "acct.stat")
        .replace("{who}", &esc(&format!("{}:{}", sess.tenant, sess.user)))
        .replace("{used}", &fmt_bytes(bytes_used))
        .replace("{containers}", &esc(&containers))
        .replace("{objects}", &esc(&objects));
    let content = format!(
        r#"<div class="pagehead"><h1>{title}</h1></div>
<p class="statline">{statline}</p>

<section class="dset page-sec">
  <h3>{quota_h}</h3>
  <div class="inline-form">
    <label class="fld"><span>{quotabytes}</span><input id="aq-bytes" type="text" inputmode="numeric" value="{quota}" placeholder="{none}"></label>
    <button class="btn" id="aq-save" type="button">{savequota}</button>
  </div>
  <p class="hint">{quotahint}</p>
  <p class="err" id="aq-err"></p>
</section>

<section class="dset page-sec">
  <h3>{tempkey}</h3>
  <p class="statline">{keystate}</p>
  <div class="inline-form">
    <label class="fld"><span>{newkey}</span><input id="tk-key" type="text" spellcheck="false" placeholder="{keyrandom}"></label>
    <button class="btn" id="tk-set" type="button">{setkey}</button>
  </div>
  <div class="inline-form">
    <label class="fld"><span>{defexp_l}</span><input id="tk-expiry" type="number" min="60" step="60" value="{defexp}"></label>
    <button class="btn" id="tk-expiry-save" type="button">{savedefault}</button>
  </div>
  <p class="hint">{keyhint}</p>
  <p class="err" id="tk-err"></p>
</section>

<section class="dset page-sec">
  <h3>{meta_h}</h3>
  <div class="meta-rows" id="am-meta">{meta_rows}</div>
  <div class="inline-form">
    <button class="btn sm" id="am-add" type="button">{addrow}</button>
    <button class="btn" id="am-save" type="button">{savemeta}</button>
  </div>
  <p class="err" id="am-err"></p>
</section>

<section class="dset page-sec">
  <h3>{users_h}</h3>
  <div class="tbl-wrap"><table class="tbl"><thead><tr><th>{tenant_h}</th><th>{user_h}</th><th>{roles_h}</th></tr></thead><tbody>{user_rows}</tbody></table></div>
  <p class="hint">{usershint}</p>
</section>

<section class="dset page-sec">
  <h3>{rate_h}</h3>
  <p class="hint">{ratehint}</p>
</section>"#,
        title = i18n::t(lang, "files.account"),
        statline = statline,
        quota_h = i18n::t(lang, "acct.quota"),
        quotabytes = i18n::t(lang, "acct.quotabytes"),
        none = i18n::t(lang, "files.emptynone"),
        savequota = i18n::t(lang, "acct.savequota"),
        quotahint = i18n::t(lang, "acct.quotahint"),
        tempkey = i18n::t(lang, "acct.tempkey"),
        newkey = i18n::t(lang, "acct.newkey"),
        keyrandom = i18n::t(lang, "acct.keyrandom"),
        setkey = i18n::t(lang, "acct.setkey"),
        defexp_l = i18n::t(lang, "acct.defexp"),
        savedefault = i18n::t(lang, "acct.savedefault"),
        keyhint = i18n::t(lang, "acct.keyhint"),
        meta_h = i18n::t(lang, "acct.meta"),
        addrow = i18n::t(lang, "files.addrow"),
        savemeta = i18n::t(lang, "acct.savemeta"),
        users_h = i18n::t(lang, "acct.users"),
        tenant_h = i18n::t(lang, "users.tenant"),
        user_h = i18n::t(lang, "users.user"),
        roles_h = i18n::t(lang, "users.roles"),
        usershint = i18n::t(lang, "acct.usershint"),
        rate_h = i18n::t(lang, "acct.ratelimits"),
        ratehint = i18n::t(lang, "acct.ratehint"),
        quota = esc(&quota),
        keystate = if temp_key_set {
            i18n::t(lang, "acct.keyset")
        } else {
            i18n::t(lang, "acct.keynone")
        },
        defexp = sess.tempurl_default_secs,
        meta_rows = meta_rows,
        user_rows = user_rows,
    );
    let side = side_buckets(&state, &sid, lang, None, "account").await;
    shell(
        &state,
        &headers,
        Shell {
            active: "files",
            title: i18n::t(lang, "files.account"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: side,
            body_data: " data-page=\"account\"".into(),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

// ---------------------------------------------------------------- tenants & users

pub async fn users_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, sess) = match page_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    if !admin::is_console_admin(&state, &sess) {
        return error_page(&state, &headers, &sess, "files", i18n::t(lang, "users.noaccess"));
    }
    let side = side_buckets(&state, &sid, lang, None, "users").await;

    let (rows, load_err) = match admin::fetch_roster(&state).await {
        Ok(roster) => {
            let mut r = String::new();
            for a in &roster {
                let mut roles = Vec::new();
                if a.reseller {
                    roles.push(i18n::t(lang, "users.reseller"));
                }
                if a.admin {
                    roles.push(i18n::t(lang, "users.admin"));
                }
                let roles_s = if roles.is_empty() {
                    format!("<span class=\"note\">{}</span>", i18n::t(lang, "users.member"))
                } else {
                    esc(&roles.join(", "))
                };
                let groups_s = if a.groups.is_empty() {
                    "<span class=\"note\">—</span>".to_string()
                } else {
                    esc(&a.groups.join(" "))
                };
                r.push_str(&format!(
                    r#"<tr data-account="{acc}" data-user="{usr}" data-admin="{adm}" data-reseller="{res}" data-groups="{grp}">
  <td>{acc_d}</td><td>{usr_d}</td><td>{roles}</td><td class="ctype">{groups}</td>
  <td class="acts"><button class="ibtn u-edit" title="{t_edit}">{edit}</button><button class="ibtn danger u-del" title="{t_del}">{del}</button></td>
</tr>"#,
                    acc = esc(&a.account),
                    usr = esc(&a.user),
                    adm = a.admin,
                    res = a.reseller,
                    grp = esc(&a.groups.join(" ")),
                    acc_d = esc(&a.account),
                    usr_d = esc(&a.user),
                    roles = roles_s,
                    groups = groups_s,
                    t_edit = i18n::t(lang, "common.edit"),
                    t_del = i18n::t(lang, "common.delete"),
                    edit = ic_sliders(),
                    del = ic_trash(),
                ));
            }
            (r, String::new())
        }
        Err(e) => (String::new(), e),
    };

    let table = if !load_err.is_empty() {
        format!(
            "<p class=\"err on\">{}</p>",
            i18n::t(lang, "users.rostererr").replace("{e}", &esc(&load_err))
        )
    } else if rows.is_empty() {
        format!("<div class=\"empty\">{}</div>", i18n::t(lang, "users.none"))
    } else {
        format!(
            "<div class=\"tbl-wrap\"><table class=\"tbl\"><thead><tr><th>{tenant}</th><th>{user}</th><th>{roles}</th><th>{groups}</th><th class=\"acts-h\"></th></tr></thead><tbody>{rows}</tbody></table></div>",
            tenant = i18n::t(lang, "users.tenant"),
            user = i18n::t(lang, "users.user"),
            roles = i18n::t(lang, "users.roles"),
            groups = i18n::t(lang, "users.groups"),
        )
    };

    let content = format!(
        r#"<div class="pagehead">
  <h1>{title}</h1>
  <div class="actions"><button class="btn-primary" id="add-user-btn" type="button">{plus}<span>{add}</span></button></div>
</div>
<p class="statline">{intro}</p>
{table}
<dialog id="dlg-user" class="dlg">
  <form method="dialog" class="dlg-in">
    <h2 id="du-title">{add}</h2>
    <div class="two-col">
      <label class="fld"><span>{tenant}</span><input id="du-account" type="text" autocomplete="off" spellcheck="false" placeholder="acme"></label>
      <label class="fld"><span>{user}</span><input id="du-user" type="text" autocomplete="off" spellcheck="false" placeholder="alice"></label>
    </div>
    <label class="fld"><span>{key}</span><input id="du-key" type="password" autocomplete="new-password" placeholder="{keyph}"></label>
    <p class="hint" id="du-key-hint">{keyhint}</p>
    <div class="radio-row">
      <label class="check"><input type="checkbox" id="du-admin"> {adminrole}</label>
      <label class="check"><input type="checkbox" id="du-reseller"> {resellerrole}</label>
    </div>
    <label class="fld"><span>{groupsfld}</span><input id="du-groups" type="text" autocomplete="off" spellcheck="false" placeholder="ops readers"></label>
    <div class="dlg-row"><button class="btn-plain" value="cancel">{cancel}</button><button class="btn-primary" id="du-save" value="default">{save}</button></div>
    <p class="err" id="du-err"></p>
    <p class="hint" id="du-busy" hidden>{busy}</p>
  </form>
</dialog>"#,
        title = i18n::t(lang, "files.users"),
        plus = ic_plus(),
        add = i18n::t(lang, "users.add"),
        intro = i18n::t(lang, "users.intro").replace("{cluster}", &esc(&state.cfg.cluster_name)),
        tenant = i18n::t(lang, "users.tenant"),
        user = i18n::t(lang, "users.user"),
        key = i18n::t(lang, "users.key"),
        keyph = i18n::t(lang, "users.keyph"),
        keyhint = i18n::t(lang, "users.keyhint"),
        adminrole = i18n::t(lang, "users.adminrole"),
        resellerrole = i18n::t(lang, "users.resellerrole"),
        groupsfld = i18n::t(lang, "users.groupsfld"),
        cancel = i18n::t(lang, "common.cancel"),
        save = i18n::t(lang, "users.save"),
        busy = i18n::t(lang, "users.busy"),
        table = table,
    );

    shell(
        &state,
        &headers,
        Shell {
            active: "files",
            title: i18n::t(lang, "files.users"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: side,
            body_data: " data-page=\"users\"".into(),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

// ---------------------------------------------------------------- search

pub async fn search_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, sess) = match page_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let side = side_buckets(&state, &sid, lang, None, "search").await;

    // Container dropdown from the account listing.
    let buckets = swift::list_buckets(&state, &sid).await.unwrap_or_default();
    let mut opts = format!(
        "<option value=\"\">{}</option>",
        i18n::t(lang, "search.allcontainers")
    );
    for b in &buckets {
        if b.name == files_api::TRASH || b.name.ends_with("_segments") {
            continue;
        }
        opts.push_str(&format!(
            "<option value=\"{v}\">{n}</option>",
            v = esc(&b.name),
            n = esc(&b.name)
        ));
    }

    // The client re-runs the search on load only when an index exists; it reads
    // that from the flag, not from the status text, which is now translated.
    let (status, indexed) = match search::index_status(&state, &sess.tenant) {
        Some(s) => {
            let count = s["count"].as_u64().unwrap_or(0);
            let ago = s["built_secs_ago"].as_u64().unwrap_or(0);
            let deep = s["deep"].as_bool().unwrap_or(false);
            let trunc = s["truncated"].as_bool().unwrap_or(false);
            let txt = format!(
                "{head}{deep}{trunc}",
                head = i18n::t(lang, "search.indexed")
                    .replace("{n}", &count.to_string())
                    .replace("{s}", if count == 1 { "" } else { "s" })
                    .replace("{ago}", &ago.to_string()),
                deep = if deep { i18n::t(lang, "search.deepnote") } else { "" },
                trunc = if trunc { i18n::t(lang, "search.truncnote") } else { "" },
            );
            (txt, "1")
        }
        None => (i18n::t(lang, "search.noindex").to_string(), "0"),
    };

    let content = format!(
        r#"<div class="pagehead">
  <h1>{title}</h1>
  <div class="actions">
    <label class="check"><input type="checkbox" id="sx-deep"> {deep}</label>
    <button class="btn sm" id="sx-reindex" type="button">{reindex}</button>
  </div>
</div>
<p class="statline" id="sx-status" data-indexed="{indexed}">{status}</p>
<div class="page-sec sx-form">
  <div class="sx-grid">
    <label class="fld"><span>{name}</span><input id="sx-q" type="text" autocomplete="off" spellcheck="false" placeholder="report"></label>
    <label class="fld"><span>{container}</span><select id="sx-container" class="fld-sel">{opts}</select></label>
    <label class="fld"><span>{ctype}</span><input id="sx-ctype" type="text" autocomplete="off" spellcheck="false" placeholder="image/"></label>
    <label class="fld"><span>{metakey}</span><input id="sx-metakey" type="text" autocomplete="off" spellcheck="false" placeholder="owner"></label>
    <label class="fld"><span>{metaval}</span><input id="sx-metaval" type="text" autocomplete="off" spellcheck="false" placeholder="alice"></label>
    <label class="fld"><span>{minsize}</span><input id="sx-min" type="number" min="0" placeholder="0"></label>
    <label class="fld"><span>{maxsize}</span><input id="sx-max" type="number" min="0" placeholder="—"></label>
  </div>
  <div class="sx-actions"><button class="btn-primary" id="sx-run" type="button">{search} <span>{search_l}</span></button></div>
</div>
<div id="sx-results"></div>"#,
        title = i18n::t(lang, "files.search"),
        deep = i18n::t(lang, "search.deep"),
        reindex = i18n::t(lang, "search.reindex"),
        indexed = indexed,
        status = status,
        name = i18n::t(lang, "search.name"),
        container = i18n::t(lang, "search.container"),
        ctype = i18n::t(lang, "search.ctype"),
        metakey = i18n::t(lang, "search.metakey"),
        metaval = i18n::t(lang, "search.metaval"),
        minsize = i18n::t(lang, "search.minsize"),
        maxsize = i18n::t(lang, "search.maxsize"),
        opts = opts,
        search = ic_search(),
        search_l = i18n::t(lang, "files.search"),
    );

    shell(
        &state,
        &headers,
        Shell {
            active: "files",
            title: i18n::t(lang, "files.search"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: side,
            body_data: " data-page=\"search\"".into(),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

// ---------------------------------------------------------------- lab

pub async fn lab_index(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (_, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let mut cards = String::new();
    for t in lab::TOOLS {
        let (cls, tail) = if t.ready {
            ("lab-card", String::new())
        } else {
            ("lab-card soon", format!("<span class=\"lab-soon\">{}</span>", i18n::t(lang, "lab.notbuilt")))
        };
        cards.push_str(&format!(
            "<a class=\"{cls}\" href=\"{href}\"><span class=\"lab-t\">{title}</span>\
             <span class=\"lab-b\">{blurb}</span>{tail}</a>",
            href = t.href,
            title = esc(i18n::t(lang, t.title)),
            blurb = esc(i18n::t(lang, t.blurb)),
        ));
    }
    // Every Lab tool reaches the nodes over ssh, so say up front whether that
    // works — a tool failing later is a worse way to learn it does not.
    let probe = nodes::fan_out(&state, "hostname").await;
    let up = probe.iter().filter(|r| r.ok).count();
    let slowest = probe.iter().map(|r| r.ms).max().unwrap_or(0);
    let reach = if probe.is_empty() {
        format!("<span class=\"err on\">{}</span>", i18n::t(lang, "lab.nonodes"))
    } else if up == probe.len() {
        format!(
            "{up} / {n} {reachable} ({slowest} ms {slowest_w})",
            n = probe.len(),
            reachable = i18n::t(lang, "lab.reachable"),
            slowest_w = i18n::t(lang, "lab.slowest")
        )
    } else {
        let down: Vec<String> = probe
            .iter()
            .filter(|r| !r.ok)
            .map(|r| esc(&r.node))
            .collect();
        format!(
            "<span class=\"err on\">{up} of {n} nodes reachable — no answer from {list}</span>",
            n = probe.len(),
            list = down.join(", ")
        )
    };
    let content = format!(
        r#"<div class="pagehead"><h1>{h1}</h1></div>
<p class="statline">{intro}<br>{reach}</p>
<div class="lab-grid">{cards}</div>"#,
        h1 = i18n::t(lang, "lab.title"),
        intro = i18n::t(lang, "lab.intro")
    );
    shell(
        &state,
        &headers,
        Shell {
            active: "lab",
            title: i18n::t(lang, "lab.title"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: lab::side_lab(lang, ""),
            body_data: " data-page=\"lab\"".into(),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

pub async fn lab_ring(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let (_, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    // The report is rendered server-side and the scenario lives in the query
    // string, so a change review arrives complete in one response and can be
    // pasted into a ticket as a link.
    let content = crate::ringscope::page_content(&state, lang, uri.query().unwrap_or("")).await;
    shell(
        &state,
        &headers,
        Shell {
            active: "lab",
            title: i18n::t(lang, "lab.tool.ring.title"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: lab::side_lab(lang, "ring"),
            body_data: " data-page=\"lab-ringscope\"".into(),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

pub async fn lab_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let (_, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let content = crate::policyapi::page_content(&state, lang, uri.query().unwrap_or("")).await;
    shell(
        &state,
        &headers,
        Shell {
            active: "lab",
            title: i18n::t(lang, "policy.title"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: lab::side_lab(lang, "policy"),
            body_data: " data-page=\"lab-economist\"".into(),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

/// Tombstone Museum renders its own body — the report has to be complete HTML
/// before any script runs — so it borrows the shell rather than describing its
/// page here twice.
/// Shell for any Lab tool, keyed by its registry id.
///
/// The per-tool helpers that came before this each hard-coded one title and one
/// side-nav id, so every new tool meant another near-identical function. This
/// takes the id and reads the rest from the registry, which is also what keeps
/// the title translated.
pub fn lab_tool_shell(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    sess: &session::Session,
    id: &str,
    content: String,
) -> Response {
    let lang = i18n::lang(headers);
    let title = lab::tool(id).map(|t| i18n::t(lang, t.title)).unwrap_or("Lab");
    shell(
        state,
        headers,
        Shell {
            active: "lab",
            title,
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: lab::side_lab(lang, id),
            body_data: format!(" data-page=\"lab-{id}\""),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

pub fn lab_capsule_shell(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    sess: &session::Session,
    content: String,
) -> Response {
    let lang = i18n::lang(headers);
    shell(
        state,
        headers,
        Shell {
            active: "lab",
            title: i18n::t(lang, "lab.tool.capsule.title"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: lab::side_lab(lang, "capsule"),
            body_data: " data-page=\"lab-capsule\"".into(),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

pub fn lab_tombstone_shell(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    sess: &session::Session,
    content: String,
) -> Response {
    let lang = i18n::lang(headers);
    shell(
        state,
        headers,
        Shell {
            active: "lab",
            title: i18n::t(lang, "lab.tool.tombstone.title"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: lab::side_lab(lang, "tombstone"),
            body_data: " data-page=\"lab-tombstone\"".into(),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

pub async fn test_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (_, sess) = match testing::require_test(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    shell(
        &state,
        &headers,
        Shell {
            active: "test",
            title: i18n::t(lang, "test.title"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: String::new(),
            body_data: " data-page=\"test\"".into(),
            content: testing::page_content(lang),
            frame_mode: false,
        },
    )
    .into_response()
}

// ---------------------------------------------------------------- iframe shells

pub async fn deploy_shell(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (_, sess) = match page_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    shell(
        &state,
        &headers,
        Shell {
            active: "deploy",
            title: i18n::t(lang, "nav.deploy"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: String::new(),
            body_data: " data-page=\"deploy\"".into(),
            content: r#"<div class="frame-wrap"><iframe src="/deploy/" title="Swift deploy workspace"></iframe></div>"#.into(),
            frame_mode: true,
        },
    )
    .into_response()
}

pub async fn monitor_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (_, sess) = match page_session(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    // Native, white-labeled dashboards. The grid is populated by the client
    // from /monitor/api/*, which carries only neutral data — nothing here or
    // downstream names or hints at the backend technology.
    let content = format!(
        r#"<div class="pagehead">
  <h1>{title}</h1>
  <div class="actions">
    <div class="seg" id="mon-tabs" role="tablist"></div>
    <select id="mon-range" class="filter mon-range" aria-label="{rangelabel}">
      <option value="900">{r15}</option>
      <option value="3600" selected>{r1h}</option>
      <option value="21600">{r6h}</option>
      <option value="86400">{r24h}</option>
    </select>
    <button class="btn sm" id="mon-refresh" type="button">{refresh}</button>
  </div>
</div>
<div class="mon-grid" id="mon-grid" aria-live="polite"></div>"#,
        title = i18n::t(lang, "mon.title"),
        rangelabel = i18n::t(lang, "mon.rangelabel"),
        r15 = i18n::t(lang, "mon.range15"),
        r1h = i18n::t(lang, "mon.range1h"),
        r6h = i18n::t(lang, "mon.range6h"),
        r24h = i18n::t(lang, "mon.range24h"),
        refresh = i18n::t(lang, "common.refresh"),
    );
    shell(
        &state,
        &headers,
        Shell {
            active: "monitor",
            title: i18n::t(lang, "mon.title"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: String::new(),
            body_data: " data-page=\"monitor\"".into(),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}

fn error_page(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    sess: &session::Session,
    active: &str,
    msg: &str,
) -> Response {
    let lang = i18n::lang(headers);
    let content = format!(
        "<div class=\"pagehead\"><h1>{title}</h1></div><p class=\"err on\">{msg}</p><p class=\"note\"><a class=\"plain-link\" href=\"/files\">{back}</a></p>",
        title = i18n::t(lang, "common.error"),
        msg = esc(msg),
        back = i18n::t(lang, "common.back"),
    );
    shell(
        state,
        headers,
        Shell {
            active,
            title: i18n::t(lang, "common.error"),
            tenant: &sess.tenant,
            user: &sess.user,
            side_extra: String::new(),
            body_data: String::new(),
            content,
            frame_mode: false,
        },
    )
    .into_response()
}
