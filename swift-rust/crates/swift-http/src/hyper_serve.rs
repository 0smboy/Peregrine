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

//! Production HTTP/1.1 connection runtime: Tokio + Hyper (AGENTS.md §6).
//!
//! HTTP/2 is not enabled. Idle keep-alive is a Hyper connection Future.
//! `header_read_timeout` is the slowloris bound. Title-case response
//! headers match Swift/S3 wire casing.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::Frame;
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper::{Request as HyperRequest, Response as HyperResponse, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use swift_runtime::{
    AdmissionController, BodyIdleDeadline, CancelReason, ConcurrencyMetrics, DeadlineKind,
    ShutdownDeadline, TrafficClass, UploadLifetimeDeadline,
};

use crate::body::Body;
use crate::dates::http_date;
use crate::headers::HeaderKeyDict;
use crate::request::{decoded_path_is_utf8, reason_phrase, unquote, Response};
use crate::server::{
    AsyncInterimCommand, AsyncRequest, AsyncService, IncomingBody, IncomingBodySender, ServerConfig,
};

/// Decode a Hyper header value the way WSGI/Swift does: UTF-8 when the
/// octets are valid UTF-8 (Python `str_to_wsgi` puts UTF-8 on the wire),
/// otherwise latin-1 so a non-ASCII header is not dropped. `HeaderValue::to_str`
/// requires visible ASCII and would silently discard TestFileUTF8 metadata.
fn header_value_to_string(value: &HeaderValue) -> String {
    let bytes = value.as_bytes();
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes.iter().map(|&b| char::from(b)).collect(),
    }
}

pub async fn serve_http1_connection(
    mut stream: tokio::net::TcpStream,
    service: Arc<dyn AsyncService>,
    config: ServerConfig,
    shutdown: Arc<AtomicBool>,
    admission: AdmissionController,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let peer_ip = stream.peer_addr().ok().map(|a| a.ip().to_string());

    // SSYNC is full-duplex (ssync_sender.py:264-272: getresponse() before
    // the request body). Peek the request line; if it is SSYNC, take the
    // socket back from Hyper (AGENTS.md Phase 9 IO hand-back) and drive
    // the session on async halves + StorageExecutor. Not a blocking hijack.
    let head_deadline = if config.head_deadline_secs > 0 {
        Duration::from_secs(config.head_deadline_secs)
    } else {
        Duration::from_secs(30)
    };
    let max_head = config
        .max_header_bytes
        .saturating_add(config.max_request_line_bytes)
        .max(8192);
    let peeked = match read_until_marker(&mut stream, b"\r\n", max_head, head_deadline).await {
        Ok(buf) => buf,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            ConcurrencyMetrics::record_timeout_current(DeadlineKind::Header);
            return Err(e);
        }
        Err(e) => return Err(e),
    };
    if let Some(body) = request_line_precondition(&peeked) {
        return write_precondition_failed(&mut stream, body).await;
    }
    // Hyper deliberately enforces RFC token syntax for field names, while
    // Python Swift's WSGI contract also accepts UTF-8 object-metadata names
    // (python-swiftclient puts those octets directly on HTTP/1.1). Read the
    // complete first head so that the narrow compatibility lane below can
    // recognize that legacy Swift wire shape before Hyper rejects it.
    let more = if peeked.windows(4).any(|w| w == b"\r\n\r\n") {
        peeked
    } else {
        // Preserve the bytes already consumed while peeking the request line.
        // The terminating CRLFCRLF may straddle the peek/read boundary (for
        // example, the peek can end in CR and the next packet begin with LF).
        // Starting a fresh buffer here loses that prefix and waits until the
        // header deadline even though a complete head is already on the wire.
        read_until_marker_with_prefix(&mut stream, peeked, b"\r\n\r\n", max_head, head_deadline)
            .await?
    };
    if let Some((status, message)) = request_head_limit_error(&more, &config) {
        return write_handoff_error(&mut stream, status, message).await;
    }
    if request_line_is_ssync(&more) {
        return serve_ssync_handoff(stream, more, service, config, shutdown, admission, peer_ip)
            .await;
    }
    if service.supports_object_mime_interim() && request_is_object_mime_continue_put(&more) {
        return serve_object_mime_handoff(
            stream, more, service, config, shutdown, admission, peer_ip,
        )
        .await;
    }
    if request_needs_swift_utf8_handoff(&more) {
        return serve_swift_utf8_handoff(
            stream, more, service, config, shutdown, admission, peer_ip,
        )
        .await;
    }
    let io = TokioIo::new(PrefixedIo {
        prefix: more,
        seen: 0,
        inner: stream,
    });
    let metrics = config
        .metrics
        .clone()
        .unwrap_or_else(ConcurrencyMetrics::new);
    let requests = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let read_only_in_flight = Arc::new(AtomicUsize::new(0));
    // A shutdown can race with a request head that is already being read on
    // an established keep-alive connection but has not reached Service::call
    // yet. Preserve exactly one such request per accepted connection. The
    // allowance is finite, and Hyper graceful shutdown closes the connection
    // as soon as that request becomes visible as in-flight.
    let shutdown_raced_request_admitted = Arc::new(AtomicBool::new(false));
    let conn_shields = Arc::new(AtomicUsize::new(0));
    let svc = HyperToSwift {
        inner: service,
        config: config.clone(),
        admission,
        peer_ip,
        requests: Arc::clone(&requests),
        in_flight: Arc::clone(&in_flight),
        read_only_in_flight: Arc::clone(&read_only_in_flight),
        shutdown_raced_request_admitted: Arc::clone(&shutdown_raced_request_admitted),
        shutdown: Arc::clone(&shutdown),
        metrics: metrics.clone(),
    };

    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .keep_alive(true)
        .title_case_headers(true)
        .auto_date_header(false)
        .max_headers(config.max_header_count.max(1));
    // Hyper's header_read_timeout also covers the idle keep-alive wait for
    // the *next* request. A timer per idle conn (50k Sleeps) made health
    // HEAD p50 ~140ms. Idle wait is a pending read (L1). First-line peek
    // waits for the first byte without a timer (new-conn idle occupancy);
    // HeaderDeadline still bounds a dripping request line after that byte.
    builder.header_read_timeout(None);
    let max_buf = config
        .max_header_bytes
        .saturating_add(config.max_request_line_bytes)
        .max(8192);
    builder.max_buf_size(max_buf);

    let conn = builder.serve_connection(io, svc).with_upgrades();
    tokio::pin!(conn);
    let mut shutting = false;
    let mut graceful_requested = false;
    let mut drain = None::<ShutdownDeadline>;
    ConcurrencyMetrics::with_conn_shields(Arc::clone(&conn_shields), async {
        loop {
            tokio::select! {
                r = &mut conn => {
                    return r.map_err(|e| std::io::Error::other(e.to_string()));
                }
                _ = crate::server::wait_shutdown(&config, &shutdown), if !shutting => {
                    shutting = true;
                    // A historical request count does not mean this socket is
                    // idle: Hyper may be parsing the next head. Stop at the
                    // boundary only when a request is currently in-flight.
                    // Otherwise wait for one bounded raced request or the
                    // shutdown deadline.
                    if in_flight.load(Ordering::SeqCst) > 0 {
                        conn.as_mut().graceful_shutdown();
                        graceful_requested = true;
                    }
                    let secs = if config.shutdown_deadline_secs > 0 {
                        config.shutdown_deadline_secs
                    } else {
                        5
                    };
                    drain = Some(ShutdownDeadline::from_timeout(Duration::from_secs(secs)));
                }
                _ = tokio::time::sleep(Duration::from_millis(5)), if shutting => {
                    if !graceful_requested
                        && (in_flight.load(Ordering::SeqCst) > 0
                            || shutdown_raced_request_admitted.load(Ordering::SeqCst))
                    {
                        conn.as_mut().graceful_shutdown();
                        graceful_requested = true;
                    }
                    let inflight = in_flight.load(Ordering::SeqCst);
                    let read_only = read_only_in_flight.load(Ordering::SeqCst);
                    let conn_commits = conn_shields.load(Ordering::SeqCst);
                    let global_commits = metrics.snapshot().commit_shield_active;
                    metrics.set_shutdown_waiting_requests(inflight);
                    metrics.set_shutdown_waiting_commits(global_commits as usize);
                    // Accepted mutating requests get the bounded graceful
                    // drain used by reload and delayed-body PUT. Read-only
                    // work cannot cross a durability barrier, so keeping a
                    // parked GET alive until ShutdownDeadline only delays
                    // termination and defeats structured cancellation.
                    if read_only > 0 && conn_commits == 0 {
                        metrics.record_cancellation(CancelReason::Shutdown);
                        return Ok(());
                    }
                    if drain.as_ref().is_some_and(|d| d.is_expired()) {
                        metrics.record_timeout(DeadlineKind::Shutdown);
                        if inflight > 0 || conn_commits > 0 {
                            metrics.record_cancellation(CancelReason::Shutdown);
                        }
                        // HTTP is now forced off. Global durability shields
                        // are still joined by the accept loop after every
                        // connection task has returned.
                        return Ok(());
                    }
                }
            }
        }
    })
    .await
}

pub async fn reject_overloaded(mut stream: tokio::net::TcpStream) {
    // Field `1682fdb` SSYNC `got 503` had no body token. Name admission so
    // reconstructor syslog can tell this apart from a partition lock.
    let body = b"Service Unavailable (admission)";
    let msg = format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\n\
         X-Backend-Unavailable-Reason: admission\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(msg.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

/// Bytes already read from `inner` are replayed before the live socket.
/// Used so Hyper still sees a complete HTTP/1.1 request after the SSYNC peek.
struct PrefixedIo {
    prefix: Vec<u8>,
    seen: usize,
    inner: tokio::net::TcpStream,
}

impl AsyncRead for PrefixedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.seen < self.prefix.len() {
            let rest = &self.prefix[self.seen..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            self.seen += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn request_line_is_ssync(buf: &[u8]) -> bool {
    let line = buf
        .split(|&b| b == b'\r' || b == b'\n')
        .next()
        .unwrap_or(buf);
    line.len() >= 6 && line[..6].eq_ignore_ascii_case(b"SSYNC ")
}

fn ascii_config_true(value: &[u8]) -> bool {
    let value = trim_ascii_bytes(value);
    value.eq_ignore_ascii_case(b"true")
        || value.eq_ignore_ascii_case(b"yes")
        || value.eq_ignore_ascii_case(b"on")
        || value == b"1"
}

/// Hyper can emit only its standard, bare `100 Continue`. Swift's EC
/// backend protocol needs capability headers on the first informational
/// response and a second informational response before the commit phase, so
/// this narrow wire shape must be handed to the native async socket driver.
fn request_is_object_mime_continue_put(buf: &[u8]) -> bool {
    let mut lines = buf.split(|&byte| byte == b'\n');
    let request_line = lines
        .next()
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .unwrap_or_default();
    if !request_line
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"PUT "))
    {
        return false;
    }
    let mut mime_feature = false;
    let mut expect_continue = false;
    for raw_line in lines {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            continue;
        };
        let name = trim_ascii_bytes(&line[..colon]);
        let value = trim_ascii_bytes(&line[colon + 1..]);
        if (name.eq_ignore_ascii_case(b"X-Backend-Obj-Multiphase-Commit")
            || name.eq_ignore_ascii_case(b"X-Backend-Obj-Metadata-Footer"))
            && ascii_config_true(value)
        {
            mime_feature = true;
        }
        if name.eq_ignore_ascii_case(b"Expect")
            && value
                .split(|&byte| byte == b',')
                .any(|token| trim_ascii_bytes(token).eq_ignore_ascii_case(b"100-continue"))
        {
            expect_continue = true;
        }
    }
    mime_feature && expect_continue
}

/// Python proxy `check_utf8(PATH_INFO)` / `get_controller is None` → 412.
/// Hyper rejects a space in the request-target (`GET /info asdf`) as 404 and
/// lossy-unquote hides invalid UTF-8 as 400; catch both on the peeked line.
fn request_line_precondition(buf: &[u8]) -> Option<&'static str> {
    let line = buf
        .split(|&b| b == b'\r' || b == b'\n')
        .next()
        .unwrap_or(buf);
    if request_line_is_ssync(line) {
        return None;
    }
    let mut parts = line.split(|&b| b == b' ');
    let Some(method) = parts.next() else {
        return Some("Bad URL");
    };
    if method.is_empty() {
        return Some("Bad URL");
    }
    let Some(target) = parts.next() else {
        return Some("Bad URL");
    };
    let Some(version) = parts.next() else {
        return Some("Bad URL");
    };
    if parts.next().is_some() || !version.starts_with(b"HTTP/") {
        return Some("Bad URL");
    }
    let path = target.split(|&b| b == b'?').next().unwrap_or(target);
    if !decoded_path_is_utf8(path) {
        return Some("Invalid UTF8 or contains NULL");
    }
    None
}

fn request_head_limit_error(buf: &[u8], config: &ServerConfig) -> Option<(u16, &'static str)> {
    let head_end = buf
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .unwrap_or(buf.len());
    let mut lines = buf[..head_end].split_inclusive(|byte| *byte == b'\n');
    let request_line = lines.next().unwrap_or_default();
    // Python's eventlet limits are exclusive: a request/header line whose
    // wire length is exactly the configured maximum is already too large.
    if request_line.len() >= config.max_request_line_bytes {
        return Some((414, "Request URI Too Long"));
    }

    let mut header_bytes = 0usize;
    for line in lines {
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        if line.len() >= config.max_header_line_bytes {
            return Some((400, "Header Line Too Long"));
        }
        header_bytes = header_bytes.saturating_add(line.len());
        if header_bytes > config.max_header_bytes {
            return Some((400, "Request Headers Too Large"));
        }
    }
    None
}

fn trim_ascii_bytes(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn ascii_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Python Swift permits the reserved-name marker in `X-Symlink-Target` so a
/// user may create a dynamic symlink that points at an internal reserved
/// object. Keep this compatibility exception narrower than the generic HTTP
/// field-value parser: NUL remains forbidden in every other request header,
/// and CR/LF are always rejected.
fn header_allows_reserved_nul(name: &str) -> bool {
    name.eq_ignore_ascii_case("X-Symlink-Target")
}

/// Eventlet/WSGI accepts `x-amz-meta-*` / `x-object-meta-*` field names whose
/// suffix is not an RFC 7230 token (official test_put_object_weird_metadata).
/// Colon, controls and whitespace stay forbidden. s3api still drops the
/// Python-dropped token set; this only lets the request reach s3api.
fn swift_s3_lenient_meta_name(raw: &[u8]) -> Option<&str> {
    if !raw.is_ascii() {
        return None;
    }
    let name = std::str::from_utf8(raw).ok()?;
    let lower = name.to_ascii_lowercase();
    let prefix = ["x-amz-meta-", "x-object-meta-"]
        .into_iter()
        .find(|prefix| lower.starts_with(prefix))?;
    if name.len() == prefix.len() {
        return None;
    }
    if raw.iter().copied().all(ascii_header_name_byte) {
        return None;
    }
    if name
        .as_bytes()
        .iter()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || *byte == b':')
    {
        return None;
    }
    Some(name)
}

/// Accept only Swift's metadata-name extension to HTTP field-name syntax.
/// The prefix stays ASCII and the suffix must be valid UTF-8 with no control,
/// whitespace, or colon characters. Other malformed field names remain
/// Hyper 400s rather than widening the parser surface.
fn swift_utf8_metadata_name(raw: &[u8]) -> Option<&str> {
    if raw.is_ascii() || !raw.iter().any(|byte| !byte.is_ascii()) {
        return None;
    }
    let name = std::str::from_utf8(raw).ok()?;
    let lower = name.to_lowercase();
    let prefix = [
        "x-object-meta-",
        "x-object-sysmeta-",
        "x-object-transient-sysmeta-",
    ]
    .into_iter()
    .find(|prefix| lower.starts_with(prefix))?;
    if name.len() == prefix.len()
        || name.chars().any(|character| {
            character == ':' || character.is_control() || character.is_whitespace()
        })
    {
        return None;
    }
    Some(name)
}

fn request_target_has_non_ascii_path(buf: &[u8]) -> bool {
    let line = buf
        .split(|&byte| byte == b'\r' || byte == b'\n')
        .next()
        .unwrap_or(buf);
    let Some(target) = line.split(|&byte| byte == b' ').nth(1) else {
        return false;
    };
    let path = target.split(|&byte| byte == b'?').next().unwrap_or(target);
    let mut index = 0usize;
    while index < path.len() {
        if path[index] >= 0x80 {
            return true;
        }
        if path[index] == b'%' && index + 2 < path.len() {
            let hex = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            if let (Some(high), Some(low)) = (hex(path[index + 1]), hex(path[index + 2])) {
                if (high << 4 | low) >= 0x80 {
                    return true;
                }
                index += 3;
                continue;
            }
        }
        index += 1;
    }
    false
}

fn header_is_s3_authorization(name: &[u8], value: &[u8]) -> bool {
    // SigV2 `AWS ...` and SigV4 `AWS4-HMAC-SHA256 ...`. TempAuth tokens
    // are not AWS-prefixed and must stay on the Hyper keep-alive path.
    name.eq_ignore_ascii_case(b"Authorization") && trim_ascii_bytes(value).starts_with(b"AWS")
}

fn request_needs_swift_utf8_handoff(buf: &[u8]) -> bool {
    if request_target_has_non_ascii_path(buf) {
        return true;
    }
    let (head, _) = split_head_body(buf.to_vec());
    head.split(|&byte| byte == b'\n')
        .skip(1)
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .take_while(|line| !line.is_empty())
        .filter_map(|line| {
            line.iter()
                .position(|&byte| byte == b':')
                .map(|pos| (&line[..pos], &line[pos + 1..]))
        })
        .any(|(name, value)| {
            let name = trim_ascii_bytes(name);
            swift_utf8_metadata_name(name).is_some()
                || swift_s3_lenient_meta_name(name).is_some()
                || header_is_s3_authorization(name, value)
                || (name.eq_ignore_ascii_case(b"X-Symlink-Target")
                    && trim_ascii_bytes(value).contains(&b'\0'))
        })
}

fn fresh_trans_id() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("tx{n:x}")
}

async fn write_precondition_failed(
    stream: &mut tokio::net::TcpStream,
    body: &str,
) -> std::io::Result<()> {
    let trans = fresh_trans_id();
    let msg = format!(
        "HTTP/1.1 412 Precondition Failed\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         X-Trans-Id: {trans}\r\n\
         X-Openstack-Request-Id: {trans}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(msg.as_bytes()).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn read_until_marker(
    stream: &mut tokio::net::TcpStream,
    marker: &[u8],
    max: usize,
    deadline: Duration,
) -> std::io::Result<Vec<u8>> {
    read_until_marker_with_prefix(stream, Vec::new(), marker, max, deadline).await
}

async fn read_until_marker_with_prefix(
    stream: &mut tokio::net::TcpStream,
    mut buf: Vec<u8>,
    marker: &[u8],
    max: usize,
    deadline: Duration,
) -> std::io::Result<Vec<u8>> {
    if buf.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP head too large",
        ));
    }
    if buf.windows(marker.len()).any(|w| w == marker) {
        return Ok(buf);
    }
    let mut tmp = [0u8; 512];
    // First byte is a pending read with no timer (L1). A silent accepted
    // socket is idle occupancy, bounded by max_connections — not slowloris.
    // Arming HeaderDeadline at accept() installed one Sleep per new conn
    // and killed 100k-open clients whose first poll lagged the 30s clock.
    let n = stream.read(&mut tmp).await?;
    if n == 0 {
        return Ok(buf);
    }
    buf.extend_from_slice(&tmp[..n]);
    if buf.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP head too large",
        ));
    }
    if buf.windows(marker.len()).any(|w| w == marker) {
        return Ok(buf);
    }
    let rest = async {
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > max {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP head too large",
                ));
            }
            if buf.windows(marker.len()).any(|w| w == marker) {
                return Ok(());
            }
        }
    };
    match tokio::time::timeout(deadline, rest).await {
        Ok(Ok(())) => Ok(buf),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "header read timeout",
        )),
    }
}

fn split_head_body(buf: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        let mut body = buf;
        let rest = body.split_off(pos + 4);
        (body, rest)
    } else {
        (buf, Vec::new())
    }
}

fn parse_ssync_head(head: &[u8]) -> std::io::Result<(String, String, String, HeaderKeyDict)> {
    let text = std::str::from_utf8(head)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    let mut lines = text.split("\r\n");
    let reqline = lines.next().unwrap_or("");
    let mut sp = reqline.splitn(3, ' ');
    let method = sp.next().unwrap_or("").to_string();
    let uri = sp.next().unwrap_or("/");
    let (path_raw, query) = match uri.split_once('?') {
        Some((p, q)) => (p, q.to_string()),
        None => (uri, String::new()),
    };
    let path = unquote(path_raw);
    let mut headers = HeaderKeyDict::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.set(k.trim(), v.trim());
        }
    }
    Ok((method, path, query, headers))
}

fn parse_swift_utf8_head(
    head: &[u8],
    max_headers: usize,
) -> std::io::Result<(String, String, String, HeaderKeyDict)> {
    let mut lines = head.split(|&byte| byte == b'\n');
    let request_line = lines
        .next()
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .unwrap_or_default();
    let request_line = std::str::from_utf8(request_line).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid request line")
    })?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if method.is_empty()
        || target.is_empty()
        || parts.next().is_some()
        || !version.starts_with("HTTP/")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid request line",
        ));
    }
    let (path_raw, query_string) = match target.split_once('?') {
        Some((path, query)) => (path, query.to_string()),
        None => (target, String::new()),
    };
    let mut headers = HeaderKeyDict::new();
    let mut count = 0usize;
    for raw_line in lines {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            break;
        }
        count += 1;
        if count > max_headers.max(1) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "too many headers",
            ));
        }
        let Some(colon) = line.iter().position(|&byte| byte == b':') else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid header line",
            ));
        };
        let raw_name = trim_ascii_bytes(&line[..colon]);
        let name = if raw_name.is_ascii() {
            if raw_name.is_empty() {
                continue;
            }
            if raw_name.iter().copied().all(ascii_header_name_byte) {
                std::str::from_utf8(raw_name).unwrap()
            } else if let Some(name) = swift_s3_lenient_meta_name(raw_name) {
                name
            } else {
                // Eventlet drops illegal field names instead of 400ing the PUT.
                continue;
            }
        } else if let Some(name) = swift_utf8_metadata_name(raw_name) {
            name
        } else {
            continue;
        };
        let raw_value = trim_ascii_bytes(&line[colon + 1..]);
        if raw_value.iter().any(|byte| matches!(byte, b'\r' | b'\n'))
            || (raw_value.contains(&b'\0') && !header_allows_reserved_nul(name))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid header value",
            ));
        }
        let value = match std::str::from_utf8(raw_value) {
            Ok(value) => value.to_string(),
            Err(_) => raw_value.iter().map(|&byte| char::from(byte)).collect(),
        };
        headers.set(name, value);
    }
    Ok((method.to_string(), unquote(path_raw), query_string, headers))
}

fn te_is_chunked(headers: &HeaderKeyDict) -> bool {
    headers
        .get("Transfer-Encoding")
        .map(|te| {
            te.split(',')
                .next_back()
                .map(|t| t.trim().eq_ignore_ascii_case("chunked"))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn header_config_true(headers: &HeaderKeyDict, name: &str) -> bool {
    headers
        .get(name)
        .is_some_and(|value| ascii_config_true(value.as_bytes()))
}

async fn write_handoff_error(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &str,
) -> std::io::Result<()> {
    let reason = reason_phrase(status);
    let bytes = body.as_bytes();
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

/// Native async Swift MIME object PUT. Each `send_continue()` requested by the
/// object service writes one informational response and then unlocks exactly
/// one independently chunked request phase. Multiphase EC uses the same body
/// channel for its second commit document; a zero-length item marks each phase
/// boundary without closing that channel.
async fn serve_object_mime_handoff(
    mut stream: tokio::net::TcpStream,
    peeked: Vec<u8>,
    service: Arc<dyn AsyncService>,
    config: ServerConfig,
    shutdown: Arc<AtomicBool>,
    admission: AdmissionController,
    peer_ip: Option<String>,
) -> std::io::Result<()> {
    if shutdown.load(Ordering::SeqCst) {
        reject_overloaded(stream).await;
        return Ok(());
    }
    if !service.supports_object_mime_interim() {
        return write_handoff_error(
            &mut stream,
            500,
            "Swift MIME PUT requires a native async service",
        )
        .await;
    }
    let _request_permit = match admission.try_acquire_request(TrafficClass::Foreground) {
        Ok(permit) => permit,
        Err(_) => {
            reject_overloaded(stream).await;
            return Ok(());
        }
    };
    let (head, leftover) = split_head_body(peeked);
    let (method, path, query_string, mut headers) =
        match parse_swift_utf8_head(&head, config.max_header_count) {
            Ok(parsed) => parsed,
            Err(_) => return write_handoff_error(&mut stream, 400, "Bad Request").await,
        };
    let expect_continue = headers.get("Expect").is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("100-continue"))
    });
    if method != "PUT"
        || !(header_config_true(&headers, "X-Backend-Obj-Multiphase-Commit")
            || header_config_true(&headers, "X-Backend-Obj-Metadata-Footer"))
        || !te_is_chunked(&headers)
        || !expect_continue
        || headers.contains_key("Content-Length")
    {
        return write_handoff_error(&mut stream, 400, "Invalid Swift MIME PUT framing").await;
    }
    if let Some(ref ip) = peer_ip {
        if !headers.contains_key("X-Backend-Remote-Addr") {
            headers.set("X-Backend-Remote-Addr", ip);
        }
    }

    let (read_half, write_half) = stream.into_split();
    let (interim_tx, interim_rx) = tokio::sync::mpsc::channel::<AsyncInterimCommand>(2);
    let scope = swift_runtime::TaskScope::bounded(1);
    let (body_tx, mut body) = IncomingBody::metered_channel(
        8,
        crate::body::STREAM_CHUNK,
        None,
        Some(scope.clone()),
        config.max_body_bytes,
    )
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    let wire_task = scope
        .spawn(drive_object_multiphase_wire(
            leftover,
            read_half,
            write_half,
            body_tx,
            interim_rx,
            config.max_body_bytes,
        ))
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    body.attach_async_interim(interim_tx);
    let idle_secs = if config.body_idle_timeout_secs > 0 {
        config.body_idle_timeout_secs
    } else {
        config.client_timeout_secs
    };
    if idle_secs > 0 {
        body.set_body_idle(BodyIdleDeadline::from_timeout(Duration::from_secs(
            idle_secs,
        )));
    }
    if config.max_upload_time_secs > 0 {
        body.set_upload_lifetime(UploadLifetimeDeadline::from_timeout(Duration::from_secs(
            config.max_upload_time_secs,
        )));
    }

    let metrics = config
        .metrics
        .clone()
        .unwrap_or_else(ConcurrencyMetrics::new);
    metrics.record_http_request_hyper();
    metrics.record_native_async_request();
    let response = service
        .call(AsyncRequest {
            method,
            path,
            query_string,
            headers,
            body,
        })
        .await;
    let (mut write_half, wire_result) = wire_task
        .join()
        .await
        .map_err(|_| std::io::Error::other("multiphase wire task cancelled"))?;
    scope
        .join()
        .await
        .map_err(|_| std::io::Error::other("multiphase wire task panicked"))?;
    if let Err(error) = &wire_result {
        if !matches!(
            error.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
        ) {
            eprintln!("multiphase request wire error: {error}");
        }
    }
    write_swift_compat_response(&mut write_half, response, false).await
}

async fn write_async_continue(
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
    headers: &[(String, String)],
) -> std::io::Result<()> {
    let mut head = String::from("HTTP/1.1 100 Continue\r\n");
    for (name, value) in headers {
        if name.is_empty()
            || !name.is_ascii()
            || !name.as_bytes().iter().copied().all(ascii_header_name_byte)
            || value.contains(['\r', '\n'])
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid informational response header",
            ));
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    write_half.write_all(head.as_bytes()).await?;
    write_half.flush().await
}

fn duplicate_io_error(error: &std::io::Error) -> std::io::Error {
    std::io::Error::new(error.kind(), error.to_string())
}

async fn drive_object_multiphase_wire(
    leftover: Vec<u8>,
    read_half: tokio::net::tcp::OwnedReadHalf,
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    mut body_tx: IncomingBodySender,
    mut interim_rx: tokio::sync::mpsc::Receiver<AsyncInterimCommand>,
    max_body: u64,
) -> (tokio::net::tcp::OwnedWriteHalf, std::io::Result<()>) {
    let mut source = ByteSrc {
        buf: leftover,
        pos: 0,
        rh: read_half,
    };
    let mut phases = 0usize;
    while let Some(command) = interim_rx.recv().await {
        phases += 1;
        if phases > 2 {
            let error = std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "multiphase PUT requested more than two request phases",
            );
            let _ = command.ack.send(Err(duplicate_io_error(&error)));
            return (write_half, Err(error));
        }
        if let Err(error) = write_async_continue(&mut write_half, &command.headers).await {
            let _ = command.ack.send(Err(duplicate_io_error(&error)));
            return (write_half, Err(error));
        }
        let _ = command.ack.send(Ok(()));
        let pump_result = tokio::select! {
            result = pump_chunked(&mut source, &mut body_tx, max_body) => result,
            early = interim_rx.recv() => {
                let Some(early) = early else {
                    // The service returned or timed out and dropped the body.
                    // Cancel the socket read so the final response is not held
                    // hostage by a stalled sender.
                    return (write_half, Ok(()));
                };
                let error = std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "next request phase requested before the current phase ended",
                );
                let _ = early.ack.send(Err(duplicate_io_error(&error)));
                Err(error)
            }
        };
        if let Err(error) = pump_result {
            let _ = body_tx.send(Err(duplicate_io_error(&error))).await;
            return (write_half, Err(error));
        }
        // Logical EOF for this chunked phase. `IncomingBody::Channel` treats
        // an empty item as `None` but remains open for the next phase.
        if body_tx.send(Ok(Vec::new())).await.is_err() {
            return (write_half, Ok(()));
        }
    }
    (write_half, Ok(()))
}

/// Async Swift-wire compatibility for valid UTF-8 metadata field names.
/// This is intentionally a one-request, connection-close lane: it preserves
/// Python Swift's non-RFC header octets without weakening Hyper's parser for
/// ordinary traffic or turning the exceptional connection into a bespoke
/// keep-alive implementation.
async fn serve_swift_utf8_handoff(
    mut stream: tokio::net::TcpStream,
    peeked: Vec<u8>,
    service: Arc<dyn AsyncService>,
    config: ServerConfig,
    shutdown: Arc<AtomicBool>,
    admission: AdmissionController,
    peer_ip: Option<String>,
) -> std::io::Result<()> {
    eprintln!("G6_DIAG utf8-compat stage=handoff-start");
    if shutdown.load(Ordering::SeqCst) {
        reject_overloaded(stream).await;
        return Ok(());
    }
    let _request_permit = match admission.try_acquire_request(TrafficClass::Foreground) {
        Ok(permit) => permit,
        Err(_) => {
            reject_overloaded(stream).await;
            return Ok(());
        }
    };
    let (head, leftover) = split_head_body(peeked);
    let (method, path, query_string, mut headers) = match parse_swift_utf8_head(
        &head,
        config.max_header_count,
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("G6_DIAG utf8-compat stage=parse-error error={error}");
            let body = b"Bad Request";
            stream
                    .write_all(
                        format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
            stream.write_all(body).await?;
            stream.flush().await?;
            return Ok(());
        }
    };
    if let Some(ref ip) = peer_ip {
        if !headers.contains_key("X-Backend-Remote-Addr") {
            headers.set("X-Backend-Remote-Addr", ip);
        }
    }
    let chunked = te_is_chunked(&headers);
    let content_length = headers
        .get("Content-Length")
        .and_then(|value| value.parse::<u64>().ok());
    if content_length.is_some_and(|length| length > config.max_body_bytes) {
        let body = b"Request Entity Too Large";
        stream
            .write_all(
                format!(
                    "HTTP/1.1 413 Payload Too Large\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await?;
        stream.write_all(body).await?;
        stream.flush().await?;
        return Ok(());
    }
    if headers
        .get("Expect")
        .is_some_and(|value| value.eq_ignore_ascii_case("100-continue"))
    {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        stream.flush().await?;
    }
    let (read_half, mut write_half) = stream.into_split();
    let scope = swift_runtime::TaskScope::bounded(1);
    let max_body = config.max_body_bytes;
    let (tx, mut body) = IncomingBody::metered_channel(
        8,
        crate::body::STREAM_CHUNK,
        content_length,
        Some(scope.clone()),
        max_body,
    )
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    let _ = scope.spawn(async move {
        pump_swift_compat_request_body(leftover, read_half, tx, chunked, content_length, max_body)
            .await;
    });
    let idle_secs = if config.body_idle_timeout_secs > 0 {
        config.body_idle_timeout_secs
    } else {
        config.client_timeout_secs
    };
    if idle_secs > 0 {
        body.set_body_idle(BodyIdleDeadline::from_timeout(Duration::from_secs(
            idle_secs,
        )));
    }
    if config.max_upload_time_secs > 0 {
        body.set_upload_lifetime(UploadLifetimeDeadline::from_timeout(Duration::from_secs(
            config.max_upload_time_secs,
        )));
    }
    let metrics = config
        .metrics
        .clone()
        .unwrap_or_else(ConcurrencyMetrics::new);
    // The compatibility lane is still the production Tokio HTTP/1 runtime;
    // it never invokes a blocking/legacy handler unless the configured
    // service itself is legacy.
    metrics.record_http_request_hyper();
    if service.is_legacy_sync_handler() {
        metrics.record_legacy_sync_handler_request();
    } else {
        metrics.record_native_async_request();
    }
    let head_request = method == "HEAD";
    let diagnostic_method = method.clone();
    let diagnostic_started = std::time::Instant::now();
    eprintln!("G6_DIAG utf8-compat method={diagnostic_method} stage=service-start");
    let response = service
        .call(AsyncRequest {
            method,
            path,
            query_string,
            headers,
            body,
        })
        .await;
    eprintln!(
        "G6_DIAG utf8-compat method={} stage=service-complete status={} elapsed_ms={}",
        diagnostic_method,
        response.status,
        diagnostic_started.elapsed().as_millis()
    );
    let write_result = write_swift_compat_response(&mut write_half, response, head_request).await;
    if let Err(error) = &write_result {
        eprintln!(
            "G6_DIAG utf8-compat method={} stage=response-error error={}",
            diagnostic_method, error
        );
    }
    write_result
}

async fn pump_swift_compat_request_body(
    leftover: Vec<u8>,
    read_half: tokio::net::tcp::OwnedReadHalf,
    mut tx: IncomingBodySender,
    chunked: bool,
    content_length: Option<u64>,
    max_body: u64,
) {
    let mut source = ByteSrc {
        buf: leftover,
        pos: 0,
        rh: read_half,
    };
    let result = if chunked {
        pump_chunked(&mut source, &mut tx, max_body).await
    } else {
        pump_length(&mut source, &mut tx, content_length.unwrap_or(0), max_body).await
    };
    if let Err(error) = result {
        let _ = tx.send(Err(error)).await;
    }
}

/// Full-duplex SSYNC on the async socket after Hyper header peek (not
/// `Body::hijack` on a blocking thread).
async fn serve_ssync_handoff(
    stream: tokio::net::TcpStream,
    peeked: Vec<u8>,
    service: Arc<dyn AsyncService>,
    config: ServerConfig,
    shutdown: Arc<AtomicBool>,
    admission: AdmissionController,
    peer_ip: Option<String>,
) -> std::io::Result<()> {
    if shutdown.load(Ordering::SeqCst) {
        reject_overloaded(stream).await;
        return Ok(());
    }
    let _req_permit = match admission
        .try_acquire_request(TrafficClass::Replication)
        .or_else(|_| admission.try_acquire_request(TrafficClass::Foreground))
    {
        Ok(p) => p,
        Err(_) => {
            reject_overloaded(stream).await;
            return Ok(());
        }
    };
    let (head, leftover) = split_head_body(peeked);
    let (method, path, query_string, mut headers) = parse_ssync_head(&head)?;
    if let Some(ref ip) = peer_ip {
        if !headers.contains_key("X-Backend-Remote-Addr") {
            headers.set("X-Backend-Remote-Addr", ip);
        }
    }
    let chunked = te_is_chunked(&headers);
    let content_length = headers
        .get("Content-Length")
        .and_then(|s| s.parse::<u64>().ok());
    let (rh, mut wh) = stream.into_split();
    let scope = swift_runtime::TaskScope::bounded(1);
    let max_body = config.max_body_bytes;
    let (tx, mut body) = IncomingBody::metered_channel(
        8,
        crate::body::STREAM_CHUNK,
        content_length,
        Some(scope.clone()),
        max_body,
    )
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    let _ = scope.spawn(async move {
        pump_ssync_request_body(leftover, rh, tx, chunked, content_length, max_body).await;
    });
    let idle_secs = if config.body_idle_timeout_secs > 0 {
        config.body_idle_timeout_secs
    } else {
        config.client_timeout_secs
    };
    if idle_secs > 0 {
        body.set_body_idle(BodyIdleDeadline::from_timeout(Duration::from_secs(
            idle_secs,
        )));
    }
    if config.max_upload_time_secs > 0 {
        body.set_upload_lifetime(UploadLifetimeDeadline::from_timeout(Duration::from_secs(
            config.max_upload_time_secs,
        )));
    }
    let trans_id = {
        if let Some(id) = headers.get("X-Trans-Id").filter(|s| !s.is_empty()) {
            id.to_string()
        } else {
            let id = format!(
                "tx-ssync-{:016x}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0)
            );
            headers.set("X-Trans-Id", &id);
            id
        }
    };
    let metrics = config
        .metrics
        .clone()
        .unwrap_or_else(ConcurrencyMetrics::new);
    metrics.record_http_request_hyper();
    if service.is_legacy_sync_handler() {
        metrics.record_legacy_sync_handler_request();
    } else {
        metrics.record_native_async_request();
    }
    let areq = AsyncRequest {
        method,
        path,
        query_string,
        headers,
        body,
    };
    let mut response = service.call(areq).await;
    if response.headers.get("X-Trans-Id").is_none() {
        response.headers.set("X-Trans-Id", trans_id);
    }
    write_chunked_http_response(&mut wh, response).await
}

async fn pump_ssync_request_body(
    leftover: Vec<u8>,
    rh: tokio::net::tcp::OwnedReadHalf,
    mut tx: IncomingBodySender,
    chunked: bool,
    content_length: Option<u64>,
    max_body: u64,
) {
    let mut src = ByteSrc {
        buf: leftover,
        pos: 0,
        rh,
    };
    let result = if chunked {
        pump_chunked(&mut src, &mut tx, max_body).await
    } else {
        pump_length(&mut src, &mut tx, content_length.unwrap_or(0), max_body).await
    };
    if let Err(e) = result {
        let _ = tx.send(Err(e)).await;
    }
}

struct ByteSrc {
    buf: Vec<u8>,
    pos: usize,
    rh: tokio::net::tcp::OwnedReadHalf,
}

impl ByteSrc {
    async fn fill(&mut self) -> std::io::Result<bool> {
        if self.pos < self.buf.len() {
            return Ok(true);
        }
        self.buf.clear();
        self.pos = 0;
        let mut tmp = [0u8; 8192];
        let n = self.rh.read(&mut tmp).await?;
        if n == 0 {
            return Ok(false);
        }
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(true)
    }

    async fn read_exact(&mut self, n: usize) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            if !self.fill().await? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "request body truncated",
                ));
            }
            let take = (n - out.len()).min(self.buf.len() - self.pos);
            out.extend_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
        }
        Ok(out)
    }

    async fn read_line(&mut self) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            if !self.fill().await? {
                return Ok(out);
            }
            while self.pos < self.buf.len() {
                let b = self.buf[self.pos];
                self.pos += 1;
                out.push(b);
                if out.len() >= 2 && out[out.len() - 2] == b'\r' && out[out.len() - 1] == b'\n' {
                    return Ok(out);
                }
                if out.len() > 64 * 1024 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "ssync chunk line too long",
                    ));
                }
            }
        }
    }
}

async fn pump_chunked(
    src: &mut ByteSrc,
    tx: &mut IncomingBodySender,
    max_body: u64,
) -> std::io::Result<()> {
    let mut decoded = 0u64;
    loop {
        let line = src.read_line().await?;
        if line.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "chunked request phase ended before its terminator",
            ));
        }
        let hex = std::str::from_utf8(&line)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
            .trim()
            .split(';')
            .next()
            .unwrap_or("");
        let size = usize::from_str_radix(hex, 16)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk size"))?;
        if size == 0 {
            let _ = src.read_line().await;
            return Ok(());
        }
        decoded = decoded.saturating_add(size as u64);
        if decoded > max_body {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "chunked request body too large",
            ));
        }
        let mut remaining = size;
        while remaining > 0 {
            if !src.fill().await? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "request body truncated",
                ));
            }
            let take = remaining.min(src.buf.len() - src.pos);
            let data = src.buf[src.pos..src.pos + take].to_vec();
            src.pos += take;
            remaining -= take;
            if tx.send(Ok(data)).await.is_err() {
                return Ok(());
            }
        }
        let crlf = src.read_exact(2).await?;
        if crlf != b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "chunk missing CRLF",
            ));
        }
    }
}

async fn pump_length(
    src: &mut ByteSrc,
    tx: &mut IncomingBodySender,
    length: u64,
    max_body: u64,
) -> std::io::Result<()> {
    let want = length.min(max_body) as usize;
    let mut sent = 0usize;
    while sent < want {
        if !src.fill().await? {
            break;
        }
        let take = (want - sent).min(src.buf.len() - src.pos);
        let chunk = src.buf[src.pos..src.pos + take].to_vec();
        src.pos += take;
        sent += take;
        if tx.send(Ok(chunk)).await.is_err() {
            return Ok(());
        }
    }
    if sent == want {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("request body ended after {sent} of {want} bytes"),
        ))
    }
}

async fn write_swift_compat_response(
    write: &mut tokio::net::tcp::OwnedWriteHalf,
    mut response: Response,
    head_request: bool,
) -> std::io::Result<()> {
    let reason = if response.reason.contains(['\r', '\n']) || response.reason.is_empty() {
        reason_phrase(response.status).to_string()
    } else {
        response.reason.clone()
    };
    if response.headers.get("Date").is_none() {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        response.headers.set("Date", http_date(seconds));
    }
    if response.headers.get("Content-Length").is_none() {
        if let Some(length) = response.body.content_length() {
            response.headers.set("Content-Length", length);
        }
    }
    let content_length = response
        .headers
        .get("Content-Length")
        .and_then(|value| value.parse::<u64>().ok());
    let chunked = content_length.is_none();
    let mut head = format!("HTTP/1.1 {} {}\r\n", response.status, reason);
    for (name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("Connection")
            || name.eq_ignore_ascii_case("Transfer-Encoding")
            || (chunked && name.eq_ignore_ascii_case("Content-Length"))
        {
            continue;
        }
        if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            continue;
        }
        let valid_name = if name.is_ascii() {
            name.as_bytes().iter().copied().all(ascii_header_name_byte)
                || swift_s3_lenient_meta_name(name.as_bytes()).is_some()
        } else {
            swift_utf8_metadata_name(name.as_bytes()).is_some()
        };
        if !valid_name {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    if chunked {
        head.push_str("Transfer-Encoding: chunked\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    write.write_all(head.as_bytes()).await?;
    if head_request {
        write.flush().await?;
        return Ok(());
    }

    let write_chunk = |bytes: &[u8]| {
        let framed = if chunked {
            let mut framed = format!("{:x}\r\n", bytes.len()).into_bytes();
            framed.extend_from_slice(bytes);
            framed.extend_from_slice(b"\r\n");
            framed
        } else {
            bytes.to_vec()
        };
        framed
    };
    match response.body.take() {
        Body::Buffered(bytes) if !bytes.is_empty() => {
            write.write_all(&write_chunk(&bytes)).await?;
        }
        Body::Channel(channel) => {
            let (mut receiver, _scope, _) = channel.into_rx();
            while let Some(chunk) = receiver.recv().await {
                let bytes = chunk?;
                if !bytes.is_empty() {
                    write.write_all(&write_chunk(&bytes)).await?;
                }
            }
        }
        Body::Streamed(_) => {
            return Err(std::io::Error::other(
                "blocking response body is forbidden on Swift UTF-8 async compatibility lane",
            ));
        }
        Body::Buffered(_) => {}
    }
    if chunked {
        write.write_all(b"0\r\n\r\n").await?;
    }
    write.flush().await
}

async fn write_chunked_http_response(
    write: &mut tokio::net::tcp::OwnedWriteHalf,
    mut response: Response,
) -> std::io::Result<()> {
    let reason = if response.reason.contains(['\r', '\n']) {
        reason_phrase(response.status).to_string()
    } else if response.reason.is_empty() {
        reason_phrase(response.status).to_string()
    } else {
        response.reason.clone()
    };
    let mut head = format!("HTTP/1.1 {} {}\r\n", response.status, reason);
    for (name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("Connection")
            || name.eq_ignore_ascii_case("Transfer-Encoding")
            || name.eq_ignore_ascii_case("Content-Length")
        {
            continue;
        }
        if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    // SSYNC is deliberately full duplex: Python's sender calls
    // HTTPConnection.getresponse() before it writes MISSING_CHECK. Advertising
    // `Connection: close` makes http.client detach the socket from the
    // connection, so its subsequent `send()` no longer uses this session.
    // HTTP/1.1 persistence is the protocol default; the handoff drops the
    // split socket naturally after the terminal response chunk.
    head.push_str("Transfer-Encoding: chunked\r\n\r\n");
    write.write_all(head.as_bytes()).await?;
    match response.body.take() {
        Body::Channel(ch) => {
            let (mut rx, _scope, _) = ch.into_rx();
            while let Some(chunk) = rx.recv().await {
                let buf = chunk?;
                if buf.is_empty() {
                    continue;
                }
                let hdr = format!("{:x}\r\n", buf.len());
                write.write_all(hdr.as_bytes()).await?;
                write.write_all(&buf).await?;
                write.write_all(b"\r\n").await?;
            }
        }
        Body::Buffered(buf) if !buf.is_empty() => {
            let hdr = format!("{:x}\r\n", buf.len());
            write.write_all(hdr.as_bytes()).await?;
            write.write_all(&buf).await?;
            write.write_all(b"\r\n").await?;
        }
        _ => {}
    }
    write.write_all(b"0\r\n\r\n").await?;
    write.flush().await
}

struct HyperToSwift {
    inner: Arc<dyn AsyncService>,
    config: ServerConfig,
    admission: AdmissionController,
    peer_ip: Option<String>,
    requests: Arc<AtomicUsize>,
    in_flight: Arc<AtomicUsize>,
    read_only_in_flight: Arc<AtomicUsize>,
    shutdown_raced_request_admitted: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    metrics: ConcurrencyMetrics,
}

impl Service<HyperRequest<Incoming>> for HyperToSwift {
    type Response = HyperResponse<SwiftHttpBody>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, mut req: HyperRequest<Incoming>) -> Self::Future {
        let inner = Arc::clone(&self.inner);
        let config = self.config.clone();
        let admission = self.admission.clone();
        let peer_ip = self.peer_ip.clone();
        let requests = Arc::clone(&self.requests);
        let in_flight = Arc::clone(&self.in_flight);
        let read_only_in_flight = Arc::clone(&self.read_only_in_flight);
        let shutdown_raced_request_admitted = Arc::clone(&self.shutdown_raced_request_admitted);
        let shutdown = Arc::clone(&self.shutdown);
        let metrics = self.metrics.clone();
        Box::pin(async move {
            let n = requests.fetch_add(1, Ordering::SeqCst);
            // A request whose head is already in an established connection's
            // parser can reach this call just after the signal flag flips.
            // Admit exactly one such raced request per connection, regardless
            // of whether it is the first request or follows completed
            // keep-alive traffic. Later post-shutdown requests fail closed.
            if shutdown.load(Ordering::SeqCst)
                && shutdown_raced_request_admitted.swap(true, Ordering::SeqCst)
            {
                metrics.set_graceful_shutdown_requests(metrics.snapshot().runtime_tasks.max(1));
                return Ok(error_hyper(503, "Service Unavailable", false));
            }
            struct InFlight(Arc<AtomicUsize>);
            impl Drop for InFlight {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            in_flight.fetch_add(1, Ordering::SeqCst);
            let _inflight = InFlight(in_flight);
            let _req_permit = match admission.try_acquire_request(TrafficClass::Foreground) {
                Ok(p) => p,
                Err(_) => return Ok(error_hyper(503, "Service Unavailable", false)),
            };

            let on_upgrade = hyper::upgrade::on(&mut req);
            let (parts, incoming) = req.into_parts();
            let mut headers = HeaderKeyDict::new();
            for (name, value) in parts.headers.iter() {
                headers.set(name.as_str(), header_value_to_string(value));
            }
            if let Some(ref ip) = peer_ip {
                if !headers.contains_key("X-Backend-Remote-Addr") {
                    headers.set("X-Backend-Remote-Addr", ip);
                }
            }
            let method = parts.method.as_str().to_string();
            struct ReadOnlyInFlight(Option<Arc<AtomicUsize>>);
            impl Drop for ReadOnlyInFlight {
                fn drop(&mut self) {
                    if let Some(counter) = self.0.as_ref() {
                        counter.fetch_sub(1, Ordering::SeqCst);
                    }
                }
            }
            let _read_only = if matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
                read_only_in_flight.fetch_add(1, Ordering::SeqCst);
                ReadOnlyInFlight(Some(read_only_in_flight))
            } else {
                ReadOnlyInFlight(None)
            };
            let path = unquote(parts.uri.path());
            let query_string = parts.uri.query().unwrap_or("").to_string();
            let head_request = method == "HEAD";
            let client_connection = headers.get("Connection").map(str::to_string);
            // Keep-alive Hyper cannot parse Eventlet-lenient S3 meta names
            // (`x-amz-meta-(`). Close after each signed S3 request so the
            // next PUT is a new TCP connection and the first-head UTF-8
            // compatibility lane can accept those names.
            let s3_signed = headers.get("Authorization").is_some_and(|value| {
                value.starts_with("AWS") || value.starts_with("AWS4-HMAC-SHA256")
            });
            let close_after = s3_signed || n + 1 >= config.max_requests_per_connection.max(1);
            if matches!(method.as_str(), "GET" | "HEAD") && path == "/recon/concurrency" {
                let body = metrics.render();
                return Ok(to_hyper_response(
                    crate::request::Response::with_body(200, body),
                    !close_after,
                    head_request,
                    client_connection.as_deref(),
                ));
            }

            // G3 activation: count application requests only (recon is excluded).
            metrics.record_http_request_hyper();
            if inner.is_legacy_sync_handler() {
                metrics.record_legacy_sync_handler_request();
            } else {
                metrics.record_native_async_request();
            }

            let mut body = IncomingBody::from_hyper(incoming, config.max_body_bytes);
            body.set_upgrade(on_upgrade);

            let idle_secs = if config.body_idle_timeout_secs > 0 {
                config.body_idle_timeout_secs
            } else {
                config.client_timeout_secs
            };
            if idle_secs > 0 {
                body.set_body_idle(BodyIdleDeadline::from_timeout(Duration::from_secs(
                    idle_secs,
                )));
            }
            if config.max_upload_time_secs > 0 {
                body.set_upload_lifetime(UploadLifetimeDeadline::from_timeout(
                    Duration::from_secs(config.max_upload_time_secs),
                ));
            }

            let areq = AsyncRequest {
                method,
                path,
                query_string,
                headers,
                body,
            };
            let response = inner.call(areq).await;
            Ok(to_hyper_response(
                response,
                !close_after,
                head_request,
                client_connection.as_deref(),
            ))
        })
    }
}

fn error_hyper(status: u16, message: &str, keep_alive: bool) -> HyperResponse<SwiftHttpBody> {
    to_hyper_response(Response::error(status, message), keep_alive, false, None)
}

fn to_hyper_response(
    mut response: Response,
    keep_alive: bool,
    head_request: bool,
    client_connection: Option<&str>,
) -> HyperResponse<SwiftHttpBody> {
    if response.reason.contains(['\r', '\n']) {
        response.reason = reason_phrase(response.status).to_string();
    }
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if response.headers.get("Content-Length").is_none() {
        if let Some(n) = response.body.content_length() {
            response.headers.set("Content-Length", n);
        }
    }
    if response.headers.get("Date").is_none() {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        response.headers.set("Date", http_date(secs));
    }
    let mut builder = HyperResponse::builder().status(status);
    for (name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("Connection") || name.eq_ignore_ascii_case("Transfer-Encoding")
        {
            continue;
        }
        if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            continue;
        }
        // HTTP/1.1 field values are octets. Python WSGI smuggles UTF-8
        // through latin-1; `HeaderValue::from_str` rejects non-ASCII and
        // would drop unicode Content-Type / metadata on the way out.
        let Ok(hv) = HeaderValue::from_bytes(value.as_bytes()) else {
            continue;
        };
        // Invalid field-names (`x-amz-meta-(`) must not poison the Hyper
        // builder: that previously collapsed the response to 14-byte
        // "Internal Error" (official test_put_object_weird_metadata HEAD).
        // Eventlet-lenient S3 names are emitted on the utf8-compat write
        // path instead (S3-signed Authorization → handoff).
        let Ok(hn) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        builder = builder.header(hn, hv);
    }
    // HTTP/1.1 keep-alive is the default; TestFile.testGetResponseHeaders
    // treats an unsolicited `Connection: keep-alive` as unexpected.
    let client_ka = client_connection.is_some_and(|v| {
        v.split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("keep-alive"))
    });
    if !keep_alive {
        builder = builder.header("Connection", "close");
    } else if client_ka {
        builder = builder.header("Connection", "keep-alive");
    }
    let body = if head_request {
        SwiftHttpBody::empty()
    } else {
        SwiftHttpBody::from_swift(response.body.take())
    };
    builder.body(body).unwrap_or_else(|_| {
        HyperResponse::new(SwiftHttpBody::from_bytes(b"Internal Error".to_vec()))
    })
}

pub struct SwiftHttpBody {
    inner: SwiftBodyInner,
    metrics: Option<ConcurrencyMetrics>,
    held: usize,
}

enum SwiftBodyInner {
    Once(Option<Bytes>),
    Channel {
        rx: tokio::sync::mpsc::Receiver<Result<Vec<u8>, std::io::Error>>,
        _scope: Option<swift_runtime::TaskScope>,
    },
}

impl SwiftHttpBody {
    fn empty() -> Self {
        Self {
            inner: SwiftBodyInner::Once(None),
            metrics: None,
            held: 0,
        }
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        let held = bytes.len();
        let metrics = ConcurrencyMetrics::current();
        if let Some(ref m) = metrics {
            m.add_response_body_buffer(held as i64);
        }
        Self {
            inner: SwiftBodyInner::Once(if bytes.is_empty() {
                None
            } else {
                Some(Bytes::from(bytes))
            }),
            metrics,
            held,
        }
    }

    fn from_swift(body: Body) -> Self {
        match body {
            Body::Buffered(bytes) => Self::from_bytes(bytes),
            Body::Channel(ch) => {
                let (rx, scope, _) = ch.into_rx();
                Self {
                    inner: SwiftBodyInner::Channel { rx, _scope: scope },
                    metrics: ConcurrencyMetrics::current(),
                    held: 0,
                }
            }
            Body::Streamed(s) => {
                let (tx, rx) = tokio::sync::mpsc::channel(1);
                let mut reader = s.reader;
                let scope = swift_runtime::TaskScope::bounded(1);
                let _ = scope.spawn(async move {
                    let mut buf = vec![0u8; crate::body::STREAM_CHUNK];
                    loop {
                        let n = match std::io::Read::read(&mut reader, &mut buf) {
                            Ok(0) => break,
                            Ok(n) => n,
                            Err(e) => {
                                let _ = tx.send(Err(e)).await;
                                break;
                            }
                        };
                        if tx.send(Ok(buf[..n].to_vec())).await.is_err() {
                            break;
                        }
                    }
                });
                Self {
                    inner: SwiftBodyInner::Channel {
                        rx,
                        _scope: Some(scope),
                    },
                    metrics: ConcurrencyMetrics::current(),
                    held: 0,
                }
            }
        }
    }
}

impl Drop for SwiftHttpBody {
    fn drop(&mut self) {
        if self.held > 0 {
            if let Some(ref m) = self.metrics {
                m.add_response_body_buffer(-(self.held as i64));
            }
            self.held = 0;
        }
    }
}

impl http_body::Body for SwiftHttpBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match &mut this.inner {
            SwiftBodyInner::Once(data) => match data.take() {
                Some(bytes) => {
                    if this.held > 0 {
                        if let Some(ref m) = this.metrics {
                            m.add_response_body_buffer(-(this.held as i64));
                        }
                        this.held = 0;
                    }
                    Poll::Ready(Some(Ok(Frame::data(bytes))))
                }
                None => Poll::Ready(None),
            },
            SwiftBodyInner::Channel { rx, .. } => match rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(v))) => {
                    if let Some(ref m) = this.metrics {
                        m.add_response_body_buffer(-(v.len() as i64));
                    }
                    Poll::Ready(Some(Ok(Frame::data(Bytes::from(v)))))
                }
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.inner {
            SwiftBodyInner::Once(Some(b)) => http_body::SizeHint::with_exact(b.len() as u64),
            SwiftBodyInner::Once(None) => http_body::SizeHint::with_exact(0),
            SwiftBodyInner::Channel { .. } => http_body::SizeHint::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_value_to_string_keeps_utf8_and_latin1() {
        let utf8 = HeaderValue::from_bytes("café".as_bytes()).unwrap();
        assert_eq!(header_value_to_string(&utf8), "café");
        let latin1 = HeaderValue::from_bytes(&[0xfc]).unwrap();
        assert_eq!(header_value_to_string(&latin1), "ü");
    }

    #[test]
    fn to_hyper_response_emits_non_ascii_metadata() {
        let mut resp = Response::new(200);
        resp.headers.set("X-Object-Meta-Color", "красный");
        resp.headers.set("Content-Type", "text/Ω");
        let hyper = to_hyper_response(resp, true, true, None);
        let color = hyper.headers().get("X-Object-Meta-Color").unwrap();
        assert_eq!(color.as_bytes(), "красный".as_bytes());
        let ct = hyper.headers().get("Content-Type").unwrap();
        assert_eq!(ct.as_bytes(), "text/Ω".as_bytes());
        assert!(hyper.headers().get("Date").is_some());
        assert!(hyper.headers().get("Connection").is_none());
    }

    #[test]
    fn to_hyper_response_skips_invalid_s3_meta_name_without_internal_error() {
        let mut resp = Response::with_body(200, b"abcdefghij".to_vec());
        resp.headers.set("ETag", "abc");
        resp.headers.set("x-amz-meta-!", "!");
        resp.headers.set("x-amz-meta-(", "(");
        let hyper = to_hyper_response(resp, false, true, None);
        assert_eq!(hyper.status(), StatusCode::OK);
        assert_eq!(hyper.headers().get("etag").unwrap().as_bytes(), b"abc");
        assert_eq!(
            hyper.headers().get("x-amz-meta-!").unwrap().as_bytes(),
            b"!"
        );
        assert!(hyper.headers().get("x-amz-meta-(").is_none());
        let cl = hyper.headers().get("content-length").map(|v| v.as_bytes());
        assert_ne!(cl, Some(&b"14"[..]));
    }

    #[test]
    fn to_hyper_response_connection_only_when_client_asked() {
        let resp = Response::new(200);
        let hyper = to_hyper_response(resp, true, true, Some("keep-alive"));
        assert_eq!(
            hyper.headers().get("Connection").unwrap().as_bytes(),
            b"keep-alive"
        );
        let resp = Response::new(200);
        let hyper = to_hyper_response(resp, false, true, None);
        assert_eq!(
            hyper.headers().get("Connection").unwrap().as_bytes(),
            b"close"
        );
    }

    #[test]
    fn request_line_precondition_info_space_and_invalid_utf8() {
        assert_eq!(
            request_line_precondition(b"GET /info asdf HTTP/1.1\r\n"),
            Some("Bad URL")
        );
        assert_eq!(
            request_line_precondition(b"GET /v1/AUTH_test/%FF HTTP/1.1\r\n"),
            Some("Invalid UTF8 or contains NULL")
        );
        assert_eq!(
            request_line_precondition(b"GET /v1/AUTH_test/c/o HTTP/1.1\r\n"),
            None
        );
        assert_eq!(
            request_line_precondition(b"GET /v1/AUTH_test/%00reserved HTTP/1.1\r\n"),
            None
        );
        assert_eq!(request_line_precondition(b"GET /info HTTP/1.1\r\n"), None);
    }

    #[test]
    fn request_head_limits_are_exclusive_and_cover_each_header_line() {
        let config = ServerConfig {
            max_request_line_bytes: 16,
            max_header_line_bytes: 8,
            max_header_bytes: 64,
            ..ServerConfig::default()
        };
        assert_eq!(
            request_head_limit_error(b"GET / HTTP/1.1\r\nX: 1\r\n\r\n", &config),
            Some((414, "Request URI Too Long"))
        );
        let config = ServerConfig {
            max_request_line_bytes: 32,
            max_header_line_bytes: 8,
            max_header_bytes: 64,
            ..ServerConfig::default()
        };
        assert_eq!(
            request_head_limit_error(b"GET /x HTTP/1.0\r\nX: 123\r\n\r\n", &config),
            Some((400, "Header Line Too Long"))
        );

        let config = ServerConfig {
            max_request_line_bytes: 17,
            max_header_line_bytes: 9,
            max_header_bytes: 64,
            ..ServerConfig::default()
        };
        assert_eq!(
            request_head_limit_error(b"GET / HTTP/1.1\r\nX: 123\r\n\r\n", &config),
            None
        );
    }

    #[test]
    fn swift_utf8_head_allows_reserved_nul_only_in_symlink_target() {
        let symlink_request = b"PUT /v1/AUTH_test/c/link HTTP/1.1\r\n\
              X-Symlink-Target: \0reserved-container/\0reserved-object\r\n\
              Content-Length: 0\r\n\r\n";
        assert!(request_needs_swift_utf8_handoff(symlink_request));
        let weird = b"PUT /v1/AUTH_test/c/o HTTP/1.1\r\nX-Amz-Meta-(: (\r\n\r\n";
        assert!(request_needs_swift_utf8_handoff(weird));
        let s3_head = b"HEAD /bucket/object HTTP/1.1\r\nAuthorization: AWS test:tester:sig\r\n\r\n";
        assert!(request_needs_swift_utf8_handoff(s3_head));
        let tempauth = b"GET /v1/AUTH_test/c/o HTTP/1.1\r\nX-Auth-Token: AUTH_tk\r\n\r\n";
        assert!(!request_needs_swift_utf8_handoff(tempauth));
        assert_eq!(
            swift_s3_lenient_meta_name(b"x-amz-meta-("),
            Some("x-amz-meta-(")
        );

        let (_, _, _, headers) = parse_swift_utf8_head(symlink_request, 32)
            .expect("reserved symlink target must reach Swift middleware");
        assert_eq!(
            headers.get("X-Symlink-Target"),
            Some("\0reserved-container/\0reserved-object")
        );

        let ordinary_nul = parse_swift_utf8_head(
            b"PUT /v1/AUTH_test/c/o HTTP/1.1\r\n\
              X-Object-Meta-Unsafe: value\0suffix\r\n\r\n",
            32,
        );
        assert!(!request_needs_swift_utf8_handoff(
            b"PUT /v1/AUTH_test/c/o HTTP/1.1\r\n\
              X-Object-Meta-Unsafe: value\0suffix\r\n\r\n"
        ));
        assert_eq!(
            ordinary_nul.unwrap_err().to_string(),
            "invalid header value"
        );

        let symlink_cr = parse_swift_utf8_head(
            b"PUT /v1/AUTH_test/c/link HTTP/1.1\r\n\
              X-Symlink-Target: container/object\runsafe\r\n\r\n",
            32,
        );
        assert_eq!(symlink_cr.unwrap_err().to_string(), "invalid header value");
    }
}
