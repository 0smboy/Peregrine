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
use futures_util::StreamExt;
use std::sync::Arc;

/// swift-deploy reads a POST body only when `Content-Length` is set, and it
/// caps that body at 1 MiB. A streamed body becomes chunked and the upstream
/// parses zero bytes (`EOF while parsing`).
const DEPLOY_BODY_MAX: usize = 1024 * 1024;

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

async fn read_deploy_body(body: Body) -> Result<Vec<u8>, Response> {
    let mut stream = body.into_data_stream();
    let mut buf = Vec::new();
    while let Some(next) = stream.next().await {
        let chunk = match next {
            Ok(chunk) => chunk,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("deploy request body: {e}\n"),
                )
                    .into_response());
            }
        };
        if buf.len().saturating_add(chunk.len()) > DEPLOY_BODY_MAX {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "deploy request body exceeds 1 MiB\n",
            )
                .into_response());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
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

    let body_bytes = match read_deploy_body(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(resp) => return resp,
    };
    let body_len = body_bytes.len();
    out_headers.insert(
        reqwest::header::CONTENT_LENGTH,
        reqwest::header::HeaderValue::from_str(&body_len.to_string()).expect("length"),
    );
    // Unsized stream: reqwest will not invent Content-Length. The header
    // inserted above is what swift-deploy reads. Removing it makes this POST
    // chunked and the upstream body length no longer matches.
    let payload = bytes::Bytes::from(body_bytes);
    let out_body = reqwest::Body::wrap_stream(futures_util::stream::once(async move {
        Ok::<bytes::Bytes, std::convert::Infallible>(payload)
    }));

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

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::time::Duration;

    #[tokio::test]
    async fn json_body_through_deploy_proxy_sets_content_length_to_byte_length() {
        let body = r#"{"note":"计划"}"#.as_bytes().to_vec();
        assert!(
            body.len() != r#"{"note":"计划"}"#.chars().count(),
            "fixture must differ in bytes and chars"
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let expected = body.clone();
        let server = std::thread::spawn(move || {
            listener.set_nonblocking(false).unwrap();
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 2048];
            loop {
                match sock.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        raw.extend_from_slice(&buf[..n]);
                        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                            let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                            let head = String::from_utf8_lossy(&raw[..split]).to_string();
                            let have = raw.len() - (split + 4);
                            let declared = head.lines().find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                if name.eq_ignore_ascii_case("content-length") {
                                    value.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            });
                            let need = declared.unwrap_or(0);
                            if have >= need {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            let head = String::from_utf8_lossy(&raw[..split]).to_string();
            let got = raw[split + 4..].to_vec();
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            (head, got)
        });

        let cfg: crate::Config = serde_json::from_str(&format!(
            r#"{{"auth_url":"http://127.0.0.1:1","swift_base":"http://127.0.0.1:1","deploy_upstream":"http://{addr}","deploy_token_file":"/dev/null"}}"#
        ))
        .unwrap();
        let state = Arc::new(crate::AppState {
            cfg,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            sessions: session::SessionStore::new(1),
            deploy_basic: "Basic dGVzdDp0b2tlbg==".into(),
            search: crate::search::new_store(),
            policy_cache: std::sync::Mutex::new(None),
            journal: crate::nodes::new_journal(),
            tests: crate::testing::new_store(),
        });
        let sid = state.sessions.create(session::Session {
            token: "t".into(),
            storage_url: "http://127.0.0.1/v1/AUTH_test".into(),
            tenant: "test".into(),
            user: "tester".into(),
            key: "k".into(),
            last_seen: std::time::Instant::now(),
            tempurl_default_secs: 60,
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/plan")
            .header("cookie", format!("sc_session={sid}"))
            .header("content-type", "application/json")
            .body(Body::from(body.clone()))
            .unwrap();
        let _ = deploy(State(state), req).await;
        let (head, got) = server.join().unwrap();
        let declared = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        });
        assert_eq!(declared, Some(expected.len()), "upstream headers:\n{head}");
        assert_eq!(got, expected);
    }
}
