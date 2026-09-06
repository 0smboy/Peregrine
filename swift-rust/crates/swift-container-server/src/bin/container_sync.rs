// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `swift-container-sync <config.conf> [once]`: container-sync daemon.
//!
//! Walks containers registered in each device's `sync_containers/` index,
//! ships object-row PUT/DELETE to the remote `X-Container-Sync-To` endpoint,
//! and advances `x_container_sync_point1` / `point2`. Auth uses realm HMAC
//! when `//realm/cluster/...` is configured, else the legacy sync-key header.
//!
//! PUT bodies require a local object source. This binary uses a proxy HTTP
//! GET via `internal_client_url`. The default base is `PROXY_BASE_URL`, then
//! `[probe_test] proxy_base_url`, then `{SWIFT_DIR}/proxy-server.conf`
//! `bind_ip`/`bind_port` (isolated `/etc/g6-rust` → `:18080`), else Python's
//! historic `http://127.0.0.1:8080`. Without a reachable proxy, DELETE still
//! works; PUT rows fail and are retried next pass.

use std::path::Path;

use swift_container_server::sync::{
    run_once, run_once_for_ring, ContainerSyncConfig, ContainerSyncLocality, ContainerSyncRealms,
    EmptyObjectSource, HttpSyncClient, ObjectSource,
};
use swift_core::config::SwiftConfig;
use swift_core::daemon;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_ring::{Ring, RingData};

/// Probe/G6: prefer `PROXY_BASE_URL`, then `[probe_test] proxy_base_url`
/// from `SWIFT_TEST_CONFIG_FILE`, then `{SWIFT_DIR}/proxy-server.conf`
/// listen address, else Python's historic `:8080`.
///
/// `Manager.once()` children often inherit `SWIFT_DIR=/etc/g6-rust` but not
/// the Python-module `PROXY_BASE_URL`. Hardcoding `:8080` then GETs
/// production objects; dest PUTs never leave the node. DELETE rows do not
/// need a source GET — that is why `test_delete_propagate` can PASS while
/// the rest of `container_sync` stays FAIL.
fn resolve_proxy_base(
    env_proxy: Option<&str>,
    test_conf: Option<&SwiftConfig>,
    proxy_server_conf: Option<&SwiftConfig>,
) -> String {
    if let Some(u) = env_proxy.map(str::trim).filter(|s| !s.is_empty()) {
        return u.trim_end_matches('/').to_string();
    }
    if let Some(conf) = test_conf {
        if let Ok(Some(u)) = conf.get("probe_test", "proxy_base_url") {
            let u = u.trim().trim_end_matches('/');
            if !u.is_empty() {
                return u.to_string();
            }
        }
    }
    if let Some(conf) = proxy_server_conf {
        if let Some(base) = proxy_base_from_proxy_server_conf(conf) {
            return base;
        }
    }
    "http://127.0.0.1:8080".to_string()
}

/// Listen URL from proxy-server.conf (`[DEFAULT]` or `[app:proxy-server]`).
///
/// Wildcard `0.0.0.0` / `::` become `127.0.0.1` so a Manager child on the
/// isolated stack talks to the local proxy, not a VIP guess.
fn proxy_base_from_proxy_server_conf(conf: &SwiftConfig) -> Option<String> {
    let bind_port = conf
        .get("DEFAULT", "bind_port")
        .ok()
        .flatten()
        .or_else(|| conf.get("app:proxy-server", "bind_port").ok().flatten())?;
    let bind_port = bind_port.trim();
    if bind_port.is_empty() {
        return None;
    }
    let bind_ip = conf
        .get("DEFAULT", "bind_ip")
        .ok()
        .flatten()
        .or_else(|| conf.get("app:proxy-server", "bind_ip").ok().flatten())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    Some(format!(
        "http://{}:{bind_port}",
        listen_host_for_proxy_base(&bind_ip)
    ))
}

fn listen_host_for_proxy_base(bind_ip: &str) -> String {
    match bind_ip.trim() {
        "" | "0.0.0.0" | "*" | "::" | "[::]" => "127.0.0.1".to_string(),
        ip if ip.starts_with('[') => ip.to_string(),
        ip if ip.contains(':') => format!("[{ip}]"),
        ip => ip.to_string(),
    }
}

/// Copied SAIO samples hardcode `:8080`; a probe base on another port wins.
/// Also matches `http://127.0.0.1:8080` with no trailing slash (the old
/// `://127.0.0.1:8080/` needle missed that form).
fn rewrite_loopback_8080(url: &str, replacement: &str) -> String {
    if replacement.contains("://127.0.0.1:8080") {
        return url.to_string();
    }
    const STALE: &[&str] = &["://127.0.0.1:8080", "://localhost:8080", "://[::1]:8080"];
    if STALE.iter().any(|needle| url.contains(needle)) {
        replacement.to_string()
    } else {
        url.to_string()
    }
}

fn strip_swift_v1(proxy_base: &str) -> String {
    let base = proxy_base.trim().trim_end_matches('/');
    base.strip_suffix("/v1").unwrap_or(base).to_string()
}

/// `{proxy_base}/v1` without doubling when PROXY_BASE_URL already ends in `/v1`.
fn proxy_base_to_internal_url(proxy_base: &str) -> String {
    let base = proxy_base.trim().trim_end_matches('/');
    if base.ends_with("/v1") {
        base.to_string()
    } else {
        format!("{base}/v1")
    }
}

fn proxy_base_to_auth_url(proxy_base: &str) -> String {
    format!("{}/auth/v1.0", strip_swift_v1(proxy_base))
}

/// Source GET / TempAuth base. Realms cluster URLs are dest-only
/// (`X-Container-Sync-To` → `HttpSyncClient`); they never feed this path.
///
/// IsolatedIdentity sets `PROXY_BASE_URL`. A copied
/// `[container-sync] internal_client_url` (SAIO `:8080` or a production
/// host) used to win via `get()` and ignore the env — field on `1e1c515`
/// had `PROXY_BASE_URL=http://127.0.0.1:18080` and still transport-failed.
fn resolve_internal_client_url(
    env_proxy_set: bool,
    conf_internal_url: Option<&str>,
    default_internal: &str,
) -> String {
    if env_proxy_set {
        return default_internal.to_string();
    }
    match conf_internal_url.map(str::trim).filter(|s| !s.is_empty()) {
        Some(conf_url) => rewrite_loopback_8080(conf_url, default_internal),
        None => default_internal.to_string(),
    }
}

fn resolve_internal_auth_url(
    env_proxy_set: bool,
    conf_auth_url: Option<&str>,
    default_auth: &str,
) -> String {
    if env_proxy_set {
        return default_auth.to_string();
    }
    match conf_auth_url.map(str::trim).filter(|s| !s.is_empty()) {
        Some(conf_url) => rewrite_loopback_8080(conf_url, default_auth),
        None => default_auth.to_string(),
    }
}

/// If PROXY_BASE_URL is loopback but `{SWIFT_DIR}/proxy-server.conf` binds a
/// specific IP, retry that host after connection refused / timeout / DNS.
fn fallback_listen_addr(
    url_host: &str,
    bind_ip: Option<&str>,
    bind_port: Option<u16>,
) -> Option<(String, u16)> {
    let bind_host = listen_host_for_proxy_base(bind_ip?);
    let port = bind_port?;
    if bind_host == url_host {
        return None;
    }
    Some((bind_host, port))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpErrorKind {
    UnsupportedScheme,
    InvalidUrl,
    Dns,
    ConnectionRefused,
    Timeout,
    Tls,
    Reset,
    IncompleteHeaders,
    BadStatus,
    Io,
}

impl HttpErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedScheme => "unsupported scheme",
            Self::InvalidUrl => "invalid url",
            Self::Dns => "dns",
            Self::ConnectionRefused => "connection refused",
            Self::Timeout => "timeout",
            Self::Tls => "tls",
            Self::Reset => "reset",
            Self::IncompleteHeaders => "incomplete headers",
            Self::BadStatus => "bad status line",
            Self::Io => "io",
        }
    }

    fn is_connect(self) -> bool {
        matches!(
            self,
            Self::ConnectionRefused | Self::Timeout | Self::Dns | Self::Reset
        )
    }
}

#[derive(Debug)]
struct HttpExchangeError {
    url: String,
    kind: HttpErrorKind,
    detail: String,
}

impl HttpExchangeError {
    fn new(url: impl Into<String>, kind: HttpErrorKind, detail: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            kind,
            detail: detail.into(),
        }
    }

    fn kind(&self) -> &'static str {
        self.kind.as_str()
    }
}

impl std::fmt::Display for HttpExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "kind={} url={} detail={}",
            self.kind.as_str(),
            self.url,
            self.detail
        )
    }
}

fn io_error_kind(err: &std::io::Error) -> HttpErrorKind {
    use std::io::ErrorKind::*;
    match err.kind() {
        ConnectionRefused => HttpErrorKind::ConnectionRefused,
        TimedOut | WouldBlock => HttpErrorKind::Timeout,
        ConnectionReset | ConnectionAborted | BrokenPipe => HttpErrorKind::Reset,
        NotFound | AddrNotAvailable => HttpErrorKind::Dns,
        _ => {
            let msg = err.to_string().to_ascii_lowercase();
            if msg.contains("failed to lookup")
                || msg.contains("name or service")
                || msg.contains("nodename nor servname")
                || msg.contains("no address associated")
            {
                HttpErrorKind::Dns
            } else if msg.contains("timed out") {
                HttpErrorKind::Timeout
            } else if msg.contains("connection refused") {
                HttpErrorKind::ConnectionRefused
            } else {
                HttpErrorKind::Io
            }
        }
    }
}

#[derive(Debug)]
struct ParsedHttpUrl {
    scheme: String,
    host: String,
    hostport: String,
    port: u16,
    path: String,
}

fn parse_http_url(url: &str) -> Result<ParsedHttpUrl, HttpExchangeError> {
    let raw = url.trim();
    let (scheme, rest) = if let Some(rest) = raw.strip_prefix("http://") {
        ("http", rest)
    } else if raw.starts_with("https://") {
        return Err(HttpExchangeError::new(
            raw,
            HttpErrorKind::Tls,
            "https source GET is not implemented; use http:// PROXY_BASE_URL",
        ));
    } else if let Some((scheme, _)) = raw.split_once("://") {
        return Err(HttpExchangeError::new(
            raw,
            HttpErrorKind::UnsupportedScheme,
            scheme,
        ));
    } else {
        return Err(HttpExchangeError::new(
            raw,
            HttpErrorKind::InvalidUrl,
            "missing http:// scheme",
        ));
    };
    let rest = rest.rsplit_once('@').map(|(_, host)| host).unwrap_or(rest);
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    if hostport.is_empty() {
        return Err(HttpExchangeError::new(
            raw,
            HttpErrorKind::InvalidUrl,
            "empty host",
        ));
    }
    let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let (ip, after) = rest.split_once(']').ok_or_else(|| {
            HttpExchangeError::new(raw, HttpErrorKind::InvalidUrl, "unclosed IPv6 bracket")
        })?;
        let port = if after.is_empty() {
            80
        } else if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>().map_err(|_| {
                HttpExchangeError::new(raw, HttpErrorKind::InvalidUrl, "invalid IPv6 port")
            })?
        } else {
            return Err(HttpExchangeError::new(
                raw,
                HttpErrorKind::InvalidUrl,
                "junk after IPv6 address",
            ));
        };
        (ip.to_string(), port)
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        let port = p
            .parse::<u16>()
            .map_err(|_| HttpExchangeError::new(raw, HttpErrorKind::InvalidUrl, "invalid port"))?;
        (h.to_string(), port)
    } else {
        (hostport.to_string(), 80)
    };
    if host.is_empty() {
        return Err(HttpExchangeError::new(
            raw,
            HttpErrorKind::InvalidUrl,
            "empty host",
        ));
    }
    Ok(ParsedHttpUrl {
        scheme: scheme.to_string(),
        host,
        hostport: hostport.to_string(),
        port,
        path,
    })
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    for i in 0..buf.len().saturating_sub(1) {
        if &buf[i..i + 2] == b"\n\n" {
            return Some(i);
        }
    }
    None
}

fn replace_url_host_port(url: &str, host: &str, port: u16) -> Result<String, HttpExchangeError> {
    let parsed = parse_http_url(url)?;
    let hostport = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok(format!("{}://{hostport}{}", parsed.scheme, parsed.path))
}

fn parse_conf_file(path: &str) -> SwiftConfig {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    SwiftConfig::parse_lenient(&content, &[], false).unwrap_or_else(|e| {
        eprintln!("could not parse {path}: {e}");
        std::process::exit(1);
    })
}

/// GET objects through the local proxy (InternalClient stand-in).
///
/// Lab TempAuth clusters require `X-Auth-Token` on proxy GETs (unauth → 401).
/// Credentials come from `[container-sync] internal_client_auth_user/key` or a
/// static `internal_client_auth_token`. Python's InternalClient uses a private
/// pipeline (often no auth); we approximate with TempAuth token refresh.
struct ProxyObjectSource {
    base: String,
    /// e.g. `http://127.0.0.1:8080/auth/v1.0` — empty if token is static.
    auth_url: String,
    auth_user: String,
    auth_key: String,
    /// Cached token (Mutex so ObjectSource stays Sync via interior mutability).
    token: std::sync::Mutex<Option<String>>,
    timeout: std::time::Duration,
    /// `{SWIFT_DIR}/proxy-server.conf` bind when it differs from `base`.
    fallback: Option<(String, u16)>,
}

impl ProxyObjectSource {
    fn ensure_token(&self) -> Option<String> {
        {
            let guard = self.token.lock().ok()?;
            if let Some(t) = guard.as_ref() {
                if !t.is_empty() {
                    return Some(t.clone());
                }
            }
        }
        if self.auth_user.is_empty() || self.auth_key.is_empty() || self.auth_url.is_empty() {
            return None;
        }
        // TempAuth: GET auth_url with X-Auth-User / X-Auth-Key → X-Auth-Token
        let headers = vec![
            ("X-Auth-User".into(), self.auth_user.clone()),
            ("X-Auth-Key".into(), self.auth_key.clone()),
            ("Connection".into(), "close".into()),
        ];
        let (status, resp_headers, _) = match http_exchange_with_fallback(
            "GET",
            &self.auth_url,
            &headers,
            &[],
            self.timeout,
            self.fallback.as_ref(),
        ) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("container-sync: auth transport failure {e}");
                return None;
            }
        };
        if !(200..300).contains(&status) {
            eprintln!("container-sync: auth status={status}");
            return None;
        }
        let tok = resp_headers
            .iter()
            .find(|(k, _)| {
                k.eq_ignore_ascii_case("X-Auth-Token") || k.eq_ignore_ascii_case("X-Storage-Token")
            })
            .map(|(_, v)| v.clone());
        let Some(tok) = tok else {
            eprintln!("container-sync: auth response missing token");
            return None;
        };
        if let Ok(mut guard) = self.token.lock() {
            *guard = Some(tok.clone());
        }
        Some(tok)
    }

    fn invalidate_token(&self) {
        if let Ok(mut guard) = self.token.lock() {
            *guard = None;
        }
    }
}

fn object_source_url(base: &str, account: &str, container: &str, name: &str) -> String {
    // Python's container-sync InternalClient always asks symlink middleware
    // for the link object itself.  Without this query a dynamic link is
    // dereferenced and the target body is copied as an ordinary object.
    format!(
        "{}/{}/{}/{}?symlink=get",
        base.trim_end_matches('/'),
        pe(account),
        pe(container),
        pe(name)
    )
}

fn debug_object_source(name: &str, headers: &[(String, String)], body: &[u8]) {
    if std::env::var("G6_CONTAINER_SYNC_DEBUG").as_deref() != Ok("1") {
        return;
    }
    let header = |wanted: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.as_str())
            .unwrap_or("")
    };
    eprintln!(
        "container-sync-debug: source name={name:?} etag={:?} slo={:?} \
         symlink_target={:?} symlink_account={:?} symlink_etag={:?} \
         symlink_bytes={:?} content_length={:?} body_len={} body={:?}",
        header("etag"),
        header("x-static-large-object"),
        header("x-symlink-target"),
        header("x-symlink-target-account"),
        header("x-symlink-target-etag"),
        header("x-symlink-target-bytes"),
        header("content-length"),
        body.len(),
        String::from_utf8_lossy(body),
    );
}

impl ObjectSource for ProxyObjectSource {
    fn get_object(
        &self,
        account: &str,
        container: &str,
        name: &str,
        _storage_policy_index: i64,
    ) -> Option<(Vec<(String, String)>, Vec<u8>)> {
        let url = object_source_url(&self.base, account, container, name);
        if std::env::var("G6_CONTAINER_SYNC_DEBUG").as_deref() == Ok("1") {
            eprintln!("container-sync-debug: source GET url={url}");
        }
        let mut headers = vec![
            ("X-Newest".into(), "True".into()),
            ("Connection".into(), "close".into()),
        ];
        if let Some(tok) = self.ensure_token() {
            headers.push(("X-Auth-Token".into(), tok));
        }
        let (status, resp_headers, body) = match http_exchange_with_fallback(
            "GET",
            &url,
            &headers,
            &[],
            self.timeout,
            self.fallback.as_ref(),
        ) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("container-sync: source GET transport failure {e}");
                return None;
            }
        };
        // One retry on 401 with a fresh token (expired / first static miss).
        if status == 401 && !self.auth_user.is_empty() {
            self.invalidate_token();
            let mut headers = vec![
                ("X-Newest".into(), "True".into()),
                ("Connection".into(), "close".into()),
            ];
            if let Some(tok) = self.ensure_token() {
                headers.push(("X-Auth-Token".into(), tok));
            }
            let (status, resp_headers, body) = match http_exchange_with_fallback(
                "GET",
                &url,
                &headers,
                &[],
                self.timeout,
                self.fallback.as_ref(),
            ) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("container-sync: source GET retry transport failure {e}");
                    return None;
                }
            };
            if !(200..300).contains(&status) {
                eprintln!("container-sync: source GET retry status={status}");
                return None;
            }
            debug_object_source(name, &resp_headers, &body);
            return Some((resp_headers, body));
        }
        if !(200..300).contains(&status) {
            eprintln!("container-sync: source GET status={status}");
            return None;
        }
        debug_object_source(name, &resp_headers, &body);
        Some((resp_headers, body))
    }
}

fn pe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn http_exchange_with_fallback(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    timeout: std::time::Duration,
    fallback: Option<&(String, u16)>,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), HttpExchangeError> {
    match http_exchange(method, url, headers, body, timeout) {
        Err(e) if e.kind.is_connect() => {
            let Some((host, port)) = fallback else {
                return Err(e);
            };
            let Ok(retry_url) = replace_url_host_port(url, host, *port) else {
                return Err(e);
            };
            if retry_url == url {
                return Err(e);
            }
            eprintln!(
                "container-sync: source GET fallback url={retry_url} after {}",
                e.kind()
            );
            http_exchange(method, &retry_url, headers, body, timeout)
        }
        other => other,
    }
}

/// HTTP/1.1 request; returns (status, headers, body). HTTP only (lab proxy).
fn http_exchange(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
    timeout: std::time::Duration,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), HttpExchangeError> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};

    let parsed = parse_http_url(url)?;
    // Omit Content-Length on empty GET/HEAD — some front-ends mishandle
    // `GET … Content-Length: 0` and TempAuth token headers never appear.
    let mut req = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        parsed.path, parsed.hostport
    );
    if !body.is_empty() || matches!(method, "PUT" | "POST" | "PATCH") {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("Connection") || k.eq_ignore_ascii_case("Content-Length") {
            continue;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    let connect_host = if parsed.host.contains(':') {
        format!("[{}]:{}", parsed.host, parsed.port)
    } else {
        format!("{}:{}", parsed.host, parsed.port)
    };
    let addrs = connect_host.to_socket_addrs().map_err(|e| {
        HttpExchangeError::new(
            url,
            io_error_kind(&e),
            format!("resolve {connect_host}: {e}"),
        )
    })?;
    let mut last_err = HttpExchangeError::new(
        url,
        HttpErrorKind::Dns,
        format!("no addresses for {connect_host}"),
    );
    let mut conn = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                conn = Some(s);
                break;
            }
            Err(e) => {
                last_err =
                    HttpExchangeError::new(url, io_error_kind(&e), format!("connect {addr}: {e}"));
            }
        }
    }
    let mut conn = conn.ok_or(last_err)?;
    let _ = conn.set_read_timeout(Some(timeout));
    let _ = conn.set_write_timeout(Some(timeout));
    conn.write_all(req.as_bytes()).map_err(|e| {
        HttpExchangeError::new(url, io_error_kind(&e), format!("write request: {e}"))
    })?;
    if !body.is_empty() {
        conn.write_all(body).map_err(|e| {
            HttpExchangeError::new(url, io_error_kind(&e), format!("write body: {e}"))
        })?;
    }
    // Read until end-of-headers. Do NOT read_to_end: HAProxy/proxy often
    // answers with Connection: keep-alive, so EOF never arrives and the
    // TempAuth token headers are truncated mid-line under a short timeout.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut headers_end = None;
    while headers_end.is_none() {
        let n = match conn.read(&mut tmp) {
            Ok(n) => n,
            Err(e) => {
                return Err(HttpExchangeError::new(
                    url,
                    io_error_kind(&e),
                    format!("read headers: {e}"),
                ));
            }
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        headers_end = find_headers_end(&buf);
        if buf.len() > 1024 * 1024 {
            break;
        }
    }
    let end = headers_end.ok_or_else(|| {
        HttpExchangeError::new(
            url,
            HttpErrorKind::IncompleteHeaders,
            format!("buffered {} bytes without header terminator", buf.len()),
        )
    })?;
    let head = String::from_utf8_lossy(&buf[..end]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            HttpExchangeError::new(
                url,
                HttpErrorKind::BadStatus,
                head.lines().next().unwrap_or(""),
            )
        })?;
    let mut resp_headers = Vec::new();
    for line in head.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if let Some((k, v)) = line.split_once(':') {
            resp_headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let te_chunked = resp_headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("Transfer-Encoding") && v.to_ascii_lowercase().contains("chunked")
    });
    let content_len = resp_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, v)| v.parse::<usize>().ok());

    // Finish body: Content-Length exact, or chunked until 0-chunk, or
    // whatever already buffered when neither is present.
    let header_term = if end + 4 <= buf.len() && &buf[end..end + 4] == b"\r\n\r\n" {
        4
    } else {
        2
    };
    let mut body_buf = buf[end + header_term..].to_vec();
    if let Some(cl) = content_len {
        while body_buf.len() < cl {
            let n = match conn.read(&mut tmp) {
                Ok(n) => n,
                Err(e) => {
                    return Err(HttpExchangeError::new(
                        url,
                        io_error_kind(&e),
                        format!("read body: {e}"),
                    ));
                }
            };
            if n == 0 {
                break;
            }
            body_buf.extend_from_slice(&tmp[..n]);
        }
        body_buf.truncate(cl);
    } else if te_chunked {
        // Read until dechunk succeeds or stream ends.
        loop {
            if dechunk(&body_buf).is_some() {
                break;
            }
            let n = match conn.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            body_buf.extend_from_slice(&tmp[..n]);
            if body_buf.len() > 64 * 1024 * 1024 {
                break;
            }
        }
    }

    let body = if te_chunked {
        dechunk(&body_buf).unwrap_or(body_buf)
    } else {
        body_buf
    };
    Ok((status, resp_headers, body))
}

/// Decode HTTP/1.1 chunked body; returns None if the framing is corrupt.
fn dechunk(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        let line_end = raw[i..].iter().position(|&b| b == b'\n')? + i;
        let hex = std::str::from_utf8(&raw[i..line_end])
            .ok()?
            .trim()
            .trim_end_matches('\r')
            .split(';')
            .next()?;
        let size = usize::from_str_radix(hex, 16).ok()?;
        i = line_end + 1;
        if size == 0 {
            // A complete chunked message ends with the empty trailer line
            // after the zero-size chunk.  Returning merely because all bytes
            // received so far happen to form whole data chunks truncates a
            // response whenever the next TCP read has not arrived yet.
            let trailer = &raw[i..];
            if trailer.starts_with(b"\r\n") || trailer.starts_with(b"\n") {
                return Some(out);
            }
            if trailer.windows(4).any(|window| window == b"\r\n\r\n")
                || trailer.windows(2).any(|window| window == b"\n\n")
            {
                return Some(out);
            }
            return None;
        }
        if i + size > raw.len() {
            return None;
        }
        out.extend_from_slice(&raw[i..i + size]);
        i += size;
        // trailing CRLF
        if i + 1 < raw.len() && &raw[i..i + 2] == b"\r\n" {
            i += 2;
        } else if i < raw.len() && raw[i] == b'\n' {
            i += 1;
        } else {
            return None;
        }
    }
}

fn main() {
    let conf_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/swift/container-server.conf".to_string());
    let run_once_only = std::env::args().nth(2).as_deref() == Some("once");
    let conf = parse_conf_file(&conf_path);
    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    let cfg = ContainerSyncConfig::from_swift_conf(&conf, &swift_dir);

    let get = |section: &str, key: &str, default: &str| -> String {
        conf.get(section, key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };
    let log_name = get("container-sync", "log_name", "container-sync");
    let log_level = get("container-sync", "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let statsd = StatsdClient::new(
        &get("container-sync", "log_statsd_host", ""),
        get("container-sync", "log_statsd_port", "8125")
            .parse()
            .unwrap_or(8125),
        &daemon::statsd_prefix(
            &get("container-sync", "log_statsd_metric_prefix", ""),
            "container-sync",
        ),
    );
    let recon_cache_path = get("container-sync", "recon_cache_path", "/var/cache/swift");
    // Probe IsolatedIdentity exports PROXY_BASE_URL (G6 :18080). A hardcoded
    // :8080 default fetched production objects and dest GETs 404'd.
    // SWIFT_TEST_CONFIG_FILE [probe_test] proxy_base_url is the same source
    // Python test.probe uses; honor it when the env var is missing (Manager
    // children do not always inherit a Python module global).
    // When both are absent, `{SWIFT_DIR}/proxy-server.conf` bind is the
    // isolated stack's listen address — not a guessed :18080 host.
    let test_conf_for_base = std::env::var("SWIFT_TEST_CONFIG_FILE")
        .ok()
        .map(|p| parse_conf_file(&p));
    let proxy_server_conf = {
        let path = format!("{swift_dir}/proxy-server.conf");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|content| SwiftConfig::parse_lenient(&content, &[], false).ok())
    };
    let env_proxy = std::env::var("PROXY_BASE_URL").ok();
    let env_proxy_set = env_proxy
        .as_deref()
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());
    let proxy_base = resolve_proxy_base(
        env_proxy.as_deref(),
        test_conf_for_base.as_ref(),
        proxy_server_conf.as_ref(),
    );
    let default_internal = proxy_base_to_internal_url(&proxy_base);
    let default_auth = proxy_base_to_auth_url(&proxy_base);
    let conf_internal = get("container-sync", "internal_client_url", "");
    let conf_auth = get("container-sync", "internal_client_auth_url", "");
    // IsolatedIdentity PROXY_BASE_URL wins over a stale conf URL. Realms
    // cluster endpoints are dest-only and never used here.
    let internal_url = resolve_internal_client_url(
        env_proxy_set,
        Some(conf_internal.as_str()),
        &default_internal,
    );
    let auth_url =
        resolve_internal_auth_url(env_proxy_set, Some(conf_auth.as_str()), &default_auth);
    let mut auth_user = get("container-sync", "internal_client_auth_user", "");
    let mut auth_key = get("container-sync", "internal_client_auth_key", "");
    let auth_token = get("container-sync", "internal_client_auth_token", "");
    if auth_user.is_empty() || auth_key.is_empty() {
        if let Ok(test_conf_path) = std::env::var("SWIFT_TEST_CONFIG_FILE") {
            let test_conf = parse_conf_file(&test_conf_path);
            let acct = test_conf
                .get("func_test", "account")
                .ok()
                .flatten()
                .unwrap_or_else(|| "test".to_string());
            let user = test_conf
                .get("func_test", "username")
                .ok()
                .flatten()
                .unwrap_or_else(|| "tester".to_string());
            let key = test_conf
                .get("func_test", "password")
                .ok()
                .flatten()
                .unwrap_or_else(|| "testing".to_string());
            if auth_user.is_empty() {
                auth_user = format!("{acct}:{user}");
            }
            if auth_key.is_empty() {
                auth_key = key;
            }
        }
    }

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| format!("{swift_dir}/swift.conf"));
    let swift_conf = parse_conf_file(&swift_conf_path);
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });

    let ring_path = format!("{swift_dir}/container.ring.gz");
    let mut container_ring = match RingData::load(Path::new(&ring_path)) {
        Ok(data) => Some(Ring::new(data, hash_config.clone())),
        Err(e) => {
            logger.warning(&format!(
                "could not load {ring_path}: {e}; ordinal defaults to 0/1"
            ));
            None
        }
    };

    let realms = ContainerSyncRealms::load(&cfg.realms_conf_path);
    let object_source: Box<dyn ObjectSource> = if internal_url.is_empty() {
        Box::new(EmptyObjectSource)
    } else {
        let initial = if auth_token.is_empty() {
            None
        } else {
            Some(auth_token.clone())
        };
        if auth_user.is_empty() && initial.is_none() {
            logger.warning(
                "internal_client_url set but no internal_client_auth_user/key or \
                 internal_client_auth_token — object GET will 401 under TempAuth",
            );
        }
        let fallback = parse_http_url(&internal_url).ok().and_then(|parsed| {
            fallback_listen_addr(
                &parsed.host,
                proxy_server_conf
                    .as_ref()
                    .and_then(|c| {
                        c.get("DEFAULT", "bind_ip")
                            .ok()
                            .flatten()
                            .or_else(|| c.get("app:proxy-server", "bind_ip").ok().flatten())
                    })
                    .as_deref(),
                proxy_server_conf.as_ref().and_then(|c| {
                    c.get("DEFAULT", "bind_port")
                        .ok()
                        .flatten()
                        .or_else(|| c.get("app:proxy-server", "bind_port").ok().flatten())
                        .and_then(|p| p.parse().ok())
                }),
            )
        });
        Box::new(ProxyObjectSource {
            base: internal_url.clone(),
            auth_url: auth_url.clone(),
            auth_user: auth_user.clone(),
            auth_key: auth_key.clone(),
            token: std::sync::Mutex::new(initial),
            timeout: std::time::Duration::from_secs_f64(cfg.conn_timeout.max(0.1)),
            fallback,
        })
    };
    let client = HttpSyncClient::with_tls(object_source, cfg.conn_timeout, cfg.tls_options());
    let stop = swift_http::install_sigterm_flag();

    // Local bind identity for primary-node ordinal (Python is_local_device).
    // Prefer the container-server listen identity; [container-sync] may override.
    let bind_ip = get(
        "container-sync",
        "bind_ip",
        &get("app:container-server", "bind_ip", "0.0.0.0"),
    );
    let bind_port: u32 = get(
        "container-sync",
        "bind_port",
        &get("app:container-server", "bind_port", "6201"),
    )
    .parse()
    .unwrap_or(6201);
    let local_ips = swift_core::localdev::ips_for_ring_lookup(&bind_ip);

    // eprintln so IsolatedIdentity file logs see the URL. logger.info
    // is syslog-only — field on `1e1c515` grepped container-sync*.log
    // for `internal_url=` and found none next to the transport failures.
    eprintln!(
        "container-sync: proxy_base={proxy_base} internal_url={internal_url} auth_url={auth_url}"
    );
    logger.info(&format!(
        "swift-container-sync: devices={} bind={bind_ip}:{bind_port} interval={}s container_time={} once={run_once_only} internal_url={internal_url}",
        cfg.devices.display(),
        cfg.interval,
        cfg.container_time,
    ));

    loop {
        let sweep_start = std::time::Instant::now();
        let stats = if let Some(ring) = container_ring.as_ref() {
            if local_ips.is_empty() {
                logger.warning(
                    "no local interface addresses for container-sync ordinal; \
                     falling back to ordinal 0 / replica_count 1",
                );
                run_once(
                    &cfg.devices,
                    &client,
                    &realms,
                    &cfg.allowed_sync_hosts,
                    &hash_config,
                    0,
                    1,
                    cfg.container_time,
                )
            } else {
                let locality = ContainerSyncLocality {
                    ring,
                    local_ips: &local_ips,
                    bind_port,
                };
                run_once_for_ring(
                    &cfg.devices,
                    &client,
                    &realms,
                    &cfg.allowed_sync_hosts,
                    &hash_config,
                    &locality,
                    cfg.container_time,
                )
            }
        } else {
            run_once(
                &cfg.devices,
                &client,
                &realms,
                &cfg.allowed_sync_hosts,
                &hash_config,
                0,
                1,
                cfg.container_time,
            )
        };
        logger.info(&format!(
            "container-sync pass: syncs={} puts={} deletes={} skips={} failures={}",
            stats.syncs, stats.puts, stats.deletes, stats.skips, stats.failures
        ));
        statsd.update_stats("syncs", stats.syncs as i64);
        statsd.update_stats("puts", stats.puts as i64);
        statsd.update_stats("deletes", stats.deletes as i64);
        statsd.update_stats("skips", stats.skips as i64);
        statsd.update_stats("failures", stats.failures as i64);

        let update = serde_json::json!({
            "container_syncs": stats.syncs,
            "container_puts": stats.puts,
            "container_deletes": stats.deletes,
            "container_skips": stats.skips,
            "container_failures": stats.failures,
            "container_sync_last": daemon::epoch_secs_now(),
            "container_sync_duration": sweep_start.elapsed().as_secs_f64(),
        });
        if let Err(e) = daemon::dump_recon(&recon_cache_path, "container.recon", &update) {
            logger.warning(&format!(
                "could not dump recon cache to {recon_cache_path}/container.recon: {e}"
            ));
        }

        if run_once_only {
            break;
        }
        if daemon::sleep_unless_stopped(cfg.interval, &stop) {
            logger.info("exiting on SIGTERM");
            break;
        }
        match RingData::load(Path::new(&ring_path)) {
            Ok(data) => container_ring = Some(Ring::new(data, hash_config.clone())),
            Err(e) => logger.warning(&format!(
                "could not reload {ring_path}: {e}; reusing previous ring"
            )),
        }
    }
}

#[cfg(test)]
mod proxy_base_tests {
    use super::{
        fallback_listen_addr, find_headers_end, http_exchange, listen_host_for_proxy_base,
        object_source_url, parse_http_url, proxy_base_from_proxy_server_conf,
        proxy_base_to_auth_url, proxy_base_to_internal_url, replace_url_host_port,
        resolve_internal_client_url, resolve_proxy_base, rewrite_loopback_8080, HttpErrorKind,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;
    use swift_core::config::SwiftConfig;

    #[test]
    fn env_proxy_base_url_wins_over_test_conf_and_default() {
        let conf = SwiftConfig::parse_lenient(
            "[probe_test]\nproxy_base_url = http://127.0.0.1:18080\n",
            &[],
            false,
        )
        .unwrap();
        let proxy =
            SwiftConfig::parse_lenient("[DEFAULT]\nbind_port = 18080\n", &[], false).unwrap();
        assert_eq!(
            resolve_proxy_base(Some("http://127.0.0.1:19999/"), Some(&conf), Some(&proxy)),
            "http://127.0.0.1:19999"
        );
    }

    #[test]
    fn probe_test_proxy_base_url_used_when_env_missing() {
        let conf = SwiftConfig::parse_lenient(
            "[probe_test]\nproxy_base_url = http://127.0.0.1:18080\n",
            &[],
            false,
        )
        .unwrap();
        let proxy =
            SwiftConfig::parse_lenient("[DEFAULT]\nbind_port = 19999\n", &[], false).unwrap();
        assert_eq!(
            resolve_proxy_base(None, Some(&conf), Some(&proxy)),
            "http://127.0.0.1:18080"
        );
        assert_eq!(
            resolve_proxy_base(Some("  "), Some(&conf), Some(&proxy)),
            "http://127.0.0.1:18080"
        );
    }

    #[test]
    fn isolated_swift_dir_proxy_bind_used_when_env_and_probe_url_missing() {
        // Failed first: resolve_proxy_base ignored SWIFT_DIR/proxy-server.conf
        // and returned historic :8080, so Manager children on IsolatedIdentity
        // GETs production while dest PUTs never fire.
        let proxy = SwiftConfig::parse_lenient(
            "[DEFAULT]\nbind_ip = 0.0.0.0\nbind_port = 18080\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            resolve_proxy_base(None, None, Some(&proxy)),
            "http://127.0.0.1:18080"
        );
        let named = SwiftConfig::parse_lenient(
            "[DEFAULT]\nbind_ip = 10.0.0.1\nbind_port = 18080\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            resolve_proxy_base(None, None, Some(&named)),
            "http://10.0.0.1:18080"
        );
        let app_section = SwiftConfig::parse_lenient(
            "[app:proxy-server]\nbind_ip = 0.0.0.0\nbind_port = 18080\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            proxy_base_from_proxy_server_conf(&app_section).as_deref(),
            Some("http://127.0.0.1:18080")
        );
    }

    #[test]
    fn default_is_python_historic_8080() {
        assert_eq!(
            resolve_proxy_base(None, None, None),
            "http://127.0.0.1:8080"
        );
        let empty_proxy =
            SwiftConfig::parse_lenient("[DEFAULT]\nlog_name = proxy\n", &[], false).unwrap();
        assert_eq!(
            resolve_proxy_base(None, None, Some(&empty_proxy)),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn listen_host_maps_wildcards_to_loopback() {
        assert_eq!(listen_host_for_proxy_base("0.0.0.0"), "127.0.0.1");
        assert_eq!(listen_host_for_proxy_base("::"), "127.0.0.1");
        assert_eq!(listen_host_for_proxy_base("10.0.0.1"), "10.0.0.1");
        assert_eq!(listen_host_for_proxy_base("2001:db8::1"), "[2001:db8::1]");
    }

    #[test]
    fn rewrite_replaces_copied_saio_8080_when_probe_base_differs() {
        assert_eq!(
            rewrite_loopback_8080("http://127.0.0.1:8080/v1", "http://127.0.0.1:18080/v1"),
            "http://127.0.0.1:18080/v1"
        );
        // Failed first: needle required `://127.0.0.1:8080/` and missed
        // the no-path SAIO form.
        assert_eq!(
            rewrite_loopback_8080("http://127.0.0.1:8080", "http://127.0.0.1:18080/v1"),
            "http://127.0.0.1:18080/v1"
        );
        assert_eq!(
            rewrite_loopback_8080("http://10.0.0.1:18080/v1", "http://127.0.0.1:18080/v1"),
            "http://10.0.0.1:18080/v1"
        );
        assert_eq!(
            rewrite_loopback_8080("http://127.0.0.1:8080/v1", "http://127.0.0.1:8080"),
            "http://127.0.0.1:8080/v1"
        );
    }

    #[test]
    fn env_proxy_overrides_stale_conf_internal_client_url() {
        // Failed first: get(conf) + rewrite left http://10.0.0.1:8080/v1
        // even when IsolatedIdentity exported PROXY_BASE_URL=:18080.
        assert_eq!(
            resolve_internal_client_url(
                true,
                Some("http://10.0.0.1:8080/v1"),
                "http://127.0.0.1:18080/v1"
            ),
            "http://127.0.0.1:18080/v1"
        );
        assert_eq!(
            resolve_internal_client_url(
                false,
                Some("http://10.0.0.1:18080/v1"),
                "http://127.0.0.1:18080/v1"
            ),
            "http://10.0.0.1:18080/v1"
        );
        assert_eq!(
            resolve_internal_client_url(false, Some("  "), "http://127.0.0.1:18080/v1"),
            "http://127.0.0.1:18080/v1"
        );
    }

    #[test]
    fn proxy_base_with_v1_suffix_does_not_double() {
        assert_eq!(
            proxy_base_to_internal_url("http://127.0.0.1:18080/v1/"),
            "http://127.0.0.1:18080/v1"
        );
        assert_eq!(
            proxy_base_to_internal_url("http://127.0.0.1:18080"),
            "http://127.0.0.1:18080/v1"
        );
        assert_eq!(
            proxy_base_to_auth_url("http://127.0.0.1:18080/v1"),
            "http://127.0.0.1:18080/auth/v1.0"
        );
    }

    #[test]
    fn fallback_listen_uses_proxy_bind_when_url_is_loopback() {
        assert_eq!(
            fallback_listen_addr("127.0.0.1", Some("10.0.0.1"), Some(18080)),
            Some(("10.0.0.1".into(), 18080))
        );
        assert_eq!(
            fallback_listen_addr("127.0.0.1", Some("0.0.0.0"), Some(18080)),
            None
        );
        assert_eq!(
            fallback_listen_addr("10.0.0.1", Some("10.0.0.1"), Some(18080)),
            None
        );
    }

    #[test]
    fn parse_http_url_ipv6_and_https_tls_kind() {
        let p = parse_http_url("http://[::1]:18080/v1/AUTH_a/c/o?symlink=get").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 18080);
        assert_eq!(p.path, "/v1/AUTH_a/c/o?symlink=get");
        let err = parse_http_url("https://127.0.0.1:18080/v1/a/c/o").unwrap_err();
        assert_eq!(err.kind, HttpErrorKind::Tls);
        assert_eq!(err.kind(), "tls");
        assert!(err.url.contains("https://127.0.0.1:18080"), "{}", err.url);
    }

    #[test]
    fn http_exchange_reports_connection_refused_url() {
        // Failed first: http_exchange returned None with no URL / kind.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = format!("http://127.0.0.1:{port}/v1/AUTH_a/c/o?symlink=get");
        let err = http_exchange("GET", &url, &[], &[], Duration::from_secs(1)).unwrap_err();
        assert_eq!(err.kind(), "connection refused", "{err}");
        assert_eq!(err.url, url);
        let msg = err.to_string();
        assert!(msg.contains("kind=connection refused"), "{msg}");
        assert!(msg.contains(&url), "{msg}");
    }

    #[test]
    fn http_exchange_reports_timeout_when_peer_sends_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/v1/AUTH_a/c/o");
        let err = http_exchange("GET", &url, &[], &[], Duration::from_millis(80)).unwrap_err();
        assert_eq!(err.kind(), "timeout", "{err}");
        assert_eq!(err.url, url);
        drop(listener);
    }

    #[test]
    fn lf_only_headers_are_not_incomplete() {
        // Failed first: only `\r\n\r\n` counted as end-of-headers, so an
        // LF-only peer became "source GET transport failure".
        assert_eq!(find_headers_end(b"HTTP/1.1 200 OK\n\nbody"), Some(15));
        assert_eq!(find_headers_end(b"HTTP/1.1 200 OK\r\n\r\nbody"), Some(15));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 512];
            let _ = sock.read(&mut buf);
            sock.write_all(b"HTTP/1.1 200 OK\nContent-Length: 4\n\nabcd")
                .unwrap();
        });
        let url = format!("http://127.0.0.1:{}/v1/a/c/o", addr.port());
        let (status, _, body) =
            http_exchange("GET", &url, &[], &[], Duration::from_secs(2)).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"abcd");
        server.join().unwrap();
    }

    #[test]
    fn replace_url_host_port_keeps_path_and_query() {
        assert_eq!(
            replace_url_host_port(
                "http://127.0.0.1:18080/v1/AUTH_a/c/o?symlink=get",
                "10.0.0.1",
                18080
            )
            .unwrap(),
            "http://10.0.0.1:18080/v1/AUTH_a/c/o?symlink=get"
        );
    }

    #[test]
    fn internal_object_get_preserves_symlink_objects() {
        assert_eq!(
            object_source_url(
                "http://127.0.0.1:18082/v1/",
                "AUTH_a",
                "source container",
                "link/name"
            ),
            "http://127.0.0.1:18082/v1/AUTH_a/source%20container/link%2Fname?symlink=get"
        );
    }

    #[test]
    fn chunked_decoder_requires_terminal_zero_chunk() {
        assert_eq!(super::dechunk(b""), None);
        assert_eq!(super::dechunk(b"3\r\nabc\r\n"), None);
        assert_eq!(
            super::dechunk(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"),
            Some(b"abcde".to_vec())
        );
    }

    #[test]
    fn chunked_decoder_accepts_extensions_and_complete_trailers() {
        assert_eq!(
            super::dechunk(b"3;foo=bar\r\nabc\r\n0\r\nX-Check: yes\r\n\r\n"),
            Some(b"abc".to_vec())
        );
        assert_eq!(super::dechunk(b"0\r\nX-Check: yes\r\n"), None);
    }
}
