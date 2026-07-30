//! Reverse proxy for the embedded Deploy workspace: the swift-deploy UI, with
//! Basic auth injected server-side (the token never reaches the browser). The
//! Deploy UI's CSS is themed on the way through so it shares the console
//! palette. Requires a console session. Monitor is served natively (see
//! `monitor.rs`) — nothing here reveals what powers it.

use crate::session;
use crate::AppState;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use std::sync::Arc;

const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

fn is_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// Console-token override appended to the Deploy UI's app.css so the embedded
/// Deploy workspace shares one palette with Files and Monitor.
const DEPLOY_THEME_CSS: &str = include_str!("../static/deploy-theme.css");

fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false)
}

fn no_session(headers: &HeaderMap) -> Response {
    if wants_html(headers) {
        Redirect::to("/login").into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "console session required\n").into_response()
    }
}

pub async fn deploy(State(state): State<Arc<AppState>>, req: Request) -> Response {
    if session::from_headers(&state.sessions, req.headers()).is_none() {
        return no_session(req.headers());
    }

    // Captured before into_body() consumes the request: the iframe's first
    // paint must already carry the console's theme.
    let theme = crate::util::cookie_value(req.headers(), crate::pages::THEME_COOKIE);

    let path_q = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".into());

    // Strip the /deploy prefix; top-level asset/api paths pass unchanged.
    let rest = path_q.strip_prefix("/deploy").unwrap_or(&path_q);
    let rest = if rest.is_empty() { "/" } else { rest };
    let target = format!("{}{}", state.cfg.deploy_upstream, rest);

    let method = req.method().clone();
    let mut out_headers = reqwest::header::HeaderMap::new();
    for (name, value) in req.headers() {
        let n = name.as_str();
        if is_hop(n)
            || n.eq_ignore_ascii_case("host")
            || n.eq_ignore_ascii_case("content-length")
            || n.eq_ignore_ascii_case("authorization")
            // Deploy CSS is buffered and appended to for theming, so ask the
            // upstream for an identity (uncompressed) body we can safely edit.
            || n.eq_ignore_ascii_case("accept-encoding")
        {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            reqwest::header::HeaderName::from_bytes(n.as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            out_headers.append(hn, hv);
        }
    }
    out_headers.insert(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&state.deploy_basic).expect("basic header"),
    );

    let body_stream = req.into_body().into_data_stream();
    let out_body = reqwest::Body::wrap_stream(body_stream);

    let resp = match state
        .http
        .request(method, &target)
        .headers(out_headers)
        .body(out_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("deploy workspace unreachable: {e}\n"),
            )
                .into_response()
        }
    };

    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    // Theme the embedded Deploy UI. CSS responses are buffered so the console
    // token override can be appended (its :root wins, being last); HTML is
    // buffered so `data-theme` can be set on <html> before first paint.
    let ctype = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let inject_css = ctype.contains("css");
    let inject_html = ctype.contains("html");
    let inject_theme = inject_css || inject_html;

    let mut builder = Response::builder().status(status);
    {
        let headers = builder.headers_mut().expect("builder headers");
        for (name, value) in resp.headers() {
            let n = name.as_str();
            if is_hop(n) {
                continue;
            }
            // Length changes after we append the theme; let the body set it.
            if inject_theme && n.eq_ignore_ascii_case("content-length") {
                continue;
            }
            // The Deploy UI is embedded same-origin in the console shell: drop
            // frame denials and relax frame-ancestors to self.
            if n.eq_ignore_ascii_case("x-frame-options") {
                continue;
            }
            if n.eq_ignore_ascii_case("content-security-policy") {
                if let Ok(csp) = value.to_str() {
                    let fixed = csp.replace("frame-ancestors 'none'", "frame-ancestors 'self'");
                    if let Ok(hv) = HeaderValue::from_str(&fixed) {
                        headers.append(header::CONTENT_SECURITY_POLICY, hv);
                    }
                    continue;
                }
            }
            if let (Ok(hn), Ok(hv)) = (
                header::HeaderName::from_bytes(n.as_bytes()),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                headers.append(hn, hv);
            }
        }
    }

    if inject_theme {
        let raw = match resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("deploy workspace body error: {e}\n"),
                )
                    .into_response()
            }
        };
        let body: Vec<u8> = if inject_css {
            let mut b = raw.to_vec();
            b.extend_from_slice(DEPLOY_THEME_CSS.as_bytes());
            b
        } else {
            // Mirror the console's own theme decision into the iframe document:
            // an explicit choice becomes data-theme, no choice follows the OS.
            // The upstream ships a hard-coded `color-scheme: dark` meta, which
            // would otherwise pin the iframe's native chrome to dark.
            let html = String::from_utf8_lossy(&raw);
            let scheme = theme.as_deref().unwrap_or("light dark");
            let html = match theme.as_deref() {
                Some(t) => html.replacen("<html", &format!("<html data-theme=\"{t}\""), 1),
                None => html.into_owned(),
            };
            html.replace(
                "name=\"color-scheme\" content=\"dark\"",
                &format!("name=\"color-scheme\" content=\"{scheme}\""),
            )
            .into_bytes()
        };
        return builder
            .body(Body::from(body))
            .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response());
    }

    builder
        .body(Body::from_stream(resp.bytes_stream()))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}
