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
use crate::headers::HeaderKeyDict;
use crate::request::{reason_phrase, unquote, Response};
use crate::server::{AsyncRequest, AsyncService, IncomingBody, ServerConfig};

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
    if request_line_is_ssync(&peeked) {
        let more = if peeked.windows(4).any(|w| w == b"\r\n\r\n") {
            peeked
        } else {
            let rest =
                read_until_marker(&mut stream, b"\r\n\r\n", max_head, head_deadline).await?;
            let mut all = peeked;
            all.extend_from_slice(&rest);
            all
        };
        return serve_ssync_handoff(
            stream,
            more,
            service,
            config,
            shutdown,
            admission,
            peer_ip,
        )
        .await;
    }
    let io = TokioIo::new(PrefixedIo {
        prefix: peeked,
        seen: 0,
        inner: stream,
    });
    let metrics = config
        .metrics
        .clone()
        .unwrap_or_else(ConcurrencyMetrics::new);
    let in_flight = Arc::new(AtomicUsize::new(0));
    let conn_shields = Arc::new(AtomicUsize::new(0));
    let svc = HyperToSwift {
        inner: service,
        config: config.clone(),
        admission,
        peer_ip,
        requests: Arc::new(AtomicUsize::new(0)),
        in_flight: Arc::clone(&in_flight),
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
    if config.head_deadline_secs > 0 {
        builder.header_read_timeout(Duration::from_secs(config.head_deadline_secs));
    } else {
        builder.header_read_timeout(None);
    }
    let max_buf = config
        .max_header_bytes
        .saturating_add(config.max_request_line_bytes)
        .max(8192);
    builder.max_buf_size(max_buf);

    let conn = builder.serve_connection(io, svc).with_upgrades();
    tokio::pin!(conn);
    let mut shutting = false;
    let mut drain = None::<ShutdownDeadline>;
    let mut saw_conn_shield = false;
    ConcurrencyMetrics::with_conn_shields(Arc::clone(&conn_shields), async {
        loop {
            tokio::select! {
                r = &mut conn => {
                    return r.map_err(|e| std::io::Error::other(e.to_string()));
                }
                _ = crate::server::wait_flag(&shutdown), if !shutting => {
                    shutting = true;
                    let secs = if config.shutdown_deadline_secs > 0 {
                        config.shutdown_deadline_secs
                    } else {
                        5
                    };
                    drain = Some(ShutdownDeadline::from_timeout(Duration::from_secs(secs)));
                }
                _ = tokio::time::sleep(Duration::from_millis(5)), if shutting => {
                    let inflight = in_flight.load(Ordering::SeqCst);
                    let conn_commits = conn_shields.load(Ordering::SeqCst);
                    let global_commits = metrics.snapshot().commit_shield_active;
                    if conn_commits > 0 {
                        saw_conn_shield = true;
                    }
                    metrics.set_shutdown_waiting_requests(inflight);
                    metrics.set_shutdown_waiting_commits(global_commits as usize);
                    if inflight == 0 && conn_commits == 0 {
                        return Ok(());
                    }
                    // After DurabilityBarrier::complete the global/conn
                    // counters drop, but the HTTP task still has to write
                    // 201. Dropping the connection in that window is the
                    // cancellable-request path, and it loses the response.
                    // Drain this connection until inflight==0 or the
                    // ShutdownDeadline forces HTTP off (L7: shields are
                    // never aborted).
                    if conn_commits > 0 || saw_conn_shield {
                        if drain.as_ref().is_some_and(|d| d.is_expired()) {
                            metrics.record_timeout(DeadlineKind::Shutdown);
                            return Ok(());
                        }
                        continue;
                    }
                    metrics.record_cancellation(CancelReason::Shutdown);
                    return Ok(());
                }
            }
        }
    })
    .await
}

pub async fn reject_overloaded(mut stream: tokio::net::TcpStream) {
    let body = b"Service Unavailable";
    let msg = format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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
    let line = buf.split(|&b| b == b'\r' || b == b'\n').next().unwrap_or(buf);
    line.len() >= 6 && line[..6].eq_ignore_ascii_case(b"SSYNC ")
}

async fn read_until_marker(
    stream: &mut tokio::net::TcpStream,
    marker: &[u8],
    max: usize,
    deadline: Duration,
) -> std::io::Result<Vec<u8>> {
    let read = async {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 512];
        loop {
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
        }
    };
    match tokio::time::timeout(deadline, read).await {
        Ok(r) => r,
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

fn parse_ssync_head(
    head: &[u8],
) -> std::io::Result<(String, String, String, HeaderKeyDict)> {
    let text = std::str::from_utf8(head).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;
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
    let _req_permit = match admission.try_acquire_request(TrafficClass::Replication)
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
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(8);
    let scope = swift_runtime::TaskScope::bounded(1);
    let max_body = config.max_body_bytes;
    let _ = scope.spawn(async move {
        pump_ssync_request_body(leftover, rh, tx, chunked, content_length, max_body).await;
    });
    let mut body = IncomingBody::from_channel(rx, content_length, Some(scope), max_body);
    let idle_secs = if config.body_idle_timeout_secs > 0 {
        config.body_idle_timeout_secs
    } else {
        config.client_timeout_secs
    };
    if idle_secs > 0 {
        body.set_body_idle(BodyIdleDeadline::from_timeout(Duration::from_secs(idle_secs)));
    }
    if config.max_upload_time_secs > 0 {
        body.set_upload_lifetime(UploadLifetimeDeadline::from_timeout(
            Duration::from_secs(config.max_upload_time_secs),
        ));
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
    tx: tokio::sync::mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
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
        pump_chunked(&mut src, &tx, max_body).await
    } else {
        pump_length(&mut src, &tx, content_length.unwrap_or(0), max_body).await
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
                    "ssync body truncated",
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
    tx: &tokio::sync::mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
    max_body: u64,
) -> std::io::Result<()> {
    let mut decoded = 0u64;
    loop {
        let line = src.read_line().await?;
        if line.is_empty() {
            return Ok(());
        }
        let hex = std::str::from_utf8(&line)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
            .trim()
            .split(';')
            .next()
            .unwrap_or("");
        let size = usize::from_str_radix(hex, 16).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk size")
        })?;
        if size == 0 {
            let _ = src.read_line().await;
            return Ok(());
        }
        decoded = decoded.saturating_add(size as u64);
        if decoded > max_body {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ssync body too large",
            ));
        }
        let data = src.read_exact(size).await?;
        let crlf = src.read_exact(2).await?;
        if crlf != b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "chunk missing CRLF",
            ));
        }
        if tx.send(Ok(data)).await.is_err() {
            return Ok(());
        }
    }
}

async fn pump_length(
    src: &mut ByteSrc,
    tx: &tokio::sync::mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
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
    Ok(())
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
    head.push_str("Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
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
    shutdown: Arc<AtomicBool>,
    metrics: ConcurrencyMetrics,
}

impl Service<HyperRequest<Incoming>> for HyperToSwift {
    type Response = HyperResponse<SwiftHttpBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, mut req: HyperRequest<Incoming>) -> Self::Future {
        let inner = Arc::clone(&self.inner);
        let config = self.config.clone();
        let admission = self.admission.clone();
        let peer_ip = self.peer_ip.clone();
        let requests = Arc::clone(&self.requests);
        let in_flight = Arc::clone(&self.in_flight);
        let shutdown = Arc::clone(&self.shutdown);
        let metrics = self.metrics.clone();
        Box::pin(async move {
            if shutdown.load(Ordering::SeqCst) {
                metrics.set_graceful_shutdown_requests(
                    metrics.snapshot().runtime_tasks.max(1),
                );
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
            let n = requests.fetch_add(1, Ordering::SeqCst);
            let _req_permit = match admission.try_acquire_request(TrafficClass::Foreground) {
                Ok(p) => p,
                Err(_) => return Ok(error_hyper(503, "Service Unavailable", false)),
            };

            let on_upgrade = hyper::upgrade::on(&mut req);
            let (parts, incoming) = req.into_parts();
            let mut headers = HeaderKeyDict::new();
            for (name, value) in parts.headers.iter() {
                let Ok(v) = value.to_str() else { continue };
                headers.set(name.as_str(), v);
            }
            if let Some(ref ip) = peer_ip {
                if !headers.contains_key("X-Backend-Remote-Addr") {
                    headers.set("X-Backend-Remote-Addr", ip);
                }
            }
            let method = parts.method.as_str().to_string();
            let path = unquote(parts.uri.path());
            let query_string = parts.uri.query().unwrap_or("").to_string();
            let head_request = method == "HEAD";
            let close_after = n + 1 >= config.max_requests_per_connection.max(1);
            if matches!(method.as_str(), "GET" | "HEAD") && path == "/recon/concurrency" {
                let body = metrics.render();
                return Ok(to_hyper_response(
                    crate::request::Response::with_body(200, body),
                    !close_after,
                    head_request,
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
                body.set_body_idle(BodyIdleDeadline::from_timeout(Duration::from_secs(idle_secs)));
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
            Ok(to_hyper_response(response, !close_after, head_request))
        })
    }
}

fn error_hyper(status: u16, message: &str, keep_alive: bool) -> HyperResponse<SwiftHttpBody> {
    to_hyper_response(Response::error(status, message), keep_alive, false)
}

fn to_hyper_response(
    mut response: Response,
    keep_alive: bool,
    head_request: bool,
) -> HyperResponse<SwiftHttpBody> {
    if response.reason.contains(['\r', '\n']) {
        response.reason = reason_phrase(response.status).to_string();
    }
    let status =
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if response.headers.get("Content-Length").is_none() {
        if let Some(n) = response.body.content_length() {
            response.headers.set("Content-Length", n);
        }
    }
    let mut builder = HyperResponse::builder().status(status);
    for (name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("Connection")
            || name.eq_ignore_ascii_case("Transfer-Encoding")
        {
            continue;
        }
        if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder = builder.header(
        "Connection",
        if keep_alive { "keep-alive" } else { "close" },
    );
    let body = if head_request {
        SwiftHttpBody::empty()
    } else {
        SwiftHttpBody::from_swift(response.body.take())
    };
    builder.body(body).unwrap_or_else(|_| {
        HyperResponse::new(SwiftHttpBody::from_bytes(
            b"Internal Error".to_vec(),
        ))
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
