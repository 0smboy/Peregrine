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

//! Async replica fan-out (AGENTS.md §16–§17).
//!
//! Tokio sockets, [`FanoutGroup`] + [`QuorumTracker`], per-backend
//! [`SharedWindow`]. A stalled replica is dropped when its window is full
//! rather than buffering without bound. If no live backend can take the next
//! chunk, the client body is not read (end-to-end backpressure).

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use swift_http::{Body, HeaderKeyDict, IncomingBody, Response, STREAM_CHUNK};
use swift_runtime::{CancellationToken, FanoutGroup, QuorumTracker, SharedWindow, TaskScope};

use swift_core::config::config_true_value;
use swift_core::storage_policy::quorum_size;
use swift_core::timestamp::Timestamp;

/// Python `container.py` GET/HEAD: `resp.last_modified = Timestamp(x-put-timestamp)`.
pub(crate) fn stamp_container_last_modified(resp: &mut Response) {
    if resp
        .headers
        .get("Last-Modified")
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        return;
    }
    let put = resp
        .headers
        .get("X-PUT-Timestamp")
        .or_else(|| resp.headers.get("X-Timestamp"))
        .unwrap_or("");
    if let Ok(ts) = put.parse::<Timestamp>() {
        resp.headers
            .set("Last-Modified", swift_http::http_date(ts.ceil()));
    }
}

use super::{
    account_info_from_response, backend_404_timestamp, fill_container_info_from_head,
    info_cache_time, is_good_source, percent_encode, post_existence_proof_guard, resp_header,
    ring_nodes, source_timestamp, swob_response, AccountInfo, BackendResponse, ContainerInfo, Node,
    ProxyApp,
};

/// Per-backend pending bytes: one stream chunk. A replica that does not
/// consume is dropped instead of growing memory.
pub const BACKEND_WINDOW_BYTES: usize = STREAM_CHUNK;

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_status_head(head: &[u8]) -> io::Result<(u16, String, Vec<(String, String)>)> {
    let head_text = String::from_utf8_lossy(head);
    let mut lines = head_text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let _proto = parts.next();
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other("bad status line"))?;
    let reason = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if headers.len() >= 128 {
            return Err(io::Error::other("too many backend headers"));
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, reason, headers))
}

async fn read_http_head(
    stream: &mut TcpStream,
    leftover: &mut Vec<u8>,
    idle: Duration,
) -> io::Result<(u16, String, Vec<(String, String)>)> {
    let deadline = tokio::time::Instant::now() + idle;
    loop {
        if let Some(end) = find_header_end(leftover) {
            let head = leftover[..end].to_vec();
            leftover.drain(..end);
            return parse_status_head(&head);
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "backend read timeout",
            ));
        }
        let mut tmp = [0u8; 512];
        let n = tokio::time::timeout(left, stream.read(&mut tmp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend read timeout"))??;
        if n == 0 {
            return Err(io::Error::other("backend closed"));
        }
        leftover.extend_from_slice(&tmp[..n]);
        if leftover.len() > 64 * 1024 {
            return Err(io::Error::other("backend headers too large"));
        }
    }
}

async fn connect_node_async(node: &Node, conn_timeout: Duration) -> io::Result<TcpStream> {
    let addr = format!("{}:{}", node.ip, node.port);
    let stream = tokio::time::timeout(conn_timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend connect timeout"))??;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

async fn read_backend_line_async(
    reader: &mut BufReader<TcpStream>,
    idle: Duration,
) -> io::Result<String> {
    let mut line = Vec::new();
    let n = tokio::time::timeout(idle, reader.read_until(b'\n', &mut line))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend read timeout"))??;
    if n == 0 || line.len() > 8 * 1024 || !line.ends_with(b"\n") {
        return Err(io::Error::other("bad backend response line"));
    }
    while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| io::Error::other("non-UTF-8 backend header"))
}

async fn read_backend_head_async(
    reader: &mut BufReader<TcpStream>,
    idle: Duration,
) -> io::Result<(u16, String, Vec<(String, String)>)> {
    let status_line = read_backend_line_async(reader, idle).await?;
    let mut parts = status_line.splitn(3, ' ');
    let _proto = parts.next();
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other("bad status line"))?;
    let reason = parts.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    loop {
        let line = read_backend_line_async(reader, idle).await?;
        if line.is_empty() {
            break;
        }
        if headers.len() >= 128 {
            return Err(io::Error::other("too many backend headers"));
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, reason, headers))
}

async fn read_body_capped(
    reader: &mut BufReader<TcpStream>,
    content_length: Option<u64>,
    cap: u64,
    idle: Duration,
) -> io::Result<Vec<u8>> {
    match content_length {
        Some(n) => {
            if n > cap {
                return Err(io::Error::other("backend body exceeds buffer cap"));
            }
            let mut body = vec![0u8; n as usize];
            tokio::time::timeout(idle, reader.read_exact(&mut body))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend body timeout"))??;
            Ok(body)
        }
        None => {
            let mut body = Vec::new();
            tokio::time::timeout(idle, reader.take(cap).read_to_end(&mut body))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend body timeout"))??;
            Ok(body)
        }
    }
}

pub(crate) async fn backend_request_async(
    node: &Node,
    part: u32,
    method: &str,
    path: &str,
    query: &str,
    headers: &swift_http::HeaderKeyDict,
    body: &[u8],
    conn_timeout: Duration,
    node_timeout: Duration,
) -> io::Result<BackendResponse> {
    let mut stream = connect_node_async(node, conn_timeout).await?;
    let addr = format!("{}:{}", node.ip, node.port);
    let target = if query.is_empty() {
        format!("/{}/{}{}", node.device, part, path)
    } else {
        format!("/{}/{}{}?{}", node.device, part, path, query)
    };
    let mut out = format!("{method} {target} HTTP/1.1\r\nHost: {addr}\r\n");
    for (k, v) in headers.iter() {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    tokio::time::timeout(node_timeout, stream.write_all(out.as_bytes()))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend write timeout"))??;
    if !body.is_empty() {
        tokio::time::timeout(node_timeout, stream.write_all(body))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend write timeout"))??;
    }
    let mut reader = BufReader::new(stream);
    let (status, reason, resp_headers) = read_backend_head_async(&mut reader, node_timeout).await?;
    let content_length =
        resp_header(&resp_headers, "content-length").and_then(|v| v.parse::<u64>().ok());
    let body = if method != "HEAD" {
        read_body_capped(
            &mut reader,
            content_length,
            swift_http::MAX_CONTROL_BODY,
            node_timeout,
        )
        .await?
    } else {
        Vec::new()
    };
    Ok(BackendResponse {
        status,
        reason,
        headers: resp_headers,
        body,
    })
}

struct AsyncPutter {
    node: Node,
    stream: TcpStream,
    window: SharedWindow,
    leftover: Vec<u8>,
}

enum AsyncPutterOutcome {
    Live(AsyncPutter),
    EarlyFinal(BackendResponse),
}

async fn connect_putter_async(
    node: &Node,
    part: u32,
    path: &str,
    query: &str,
    headers: &swift_http::HeaderKeyDict,
    content_length: Option<u64>,
    conn_timeout: Duration,
    node_timeout: Duration,
) -> io::Result<AsyncPutterOutcome> {
    let mut stream = connect_node_async(node, conn_timeout).await?;
    let addr = format!("{}:{}", node.ip, node.port);
    let target = if query.is_empty() {
        format!("/{}/{}{}", node.device, part, path)
    } else {
        format!("/{}/{}{}?{}", node.device, part, path, query)
    };
    let mut out = format!("PUT {target} HTTP/1.1\r\nHost: {addr}\r\n");
    for (k, v) in headers.iter() {
        if [
            "content-length",
            "transfer-encoding",
            "connection",
            "expect",
        ]
        .contains(&k.to_ascii_lowercase().as_str())
        {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("Expect: 100-continue\r\n");
    match content_length {
        Some(n) => out.push_str(&format!("Content-Length: {n}\r\n")),
        None => out.push_str("Transfer-Encoding: chunked\r\n"),
    }
    out.push_str("Connection: close\r\n\r\n");
    tokio::time::timeout(node_timeout, stream.write_all(out.as_bytes()))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend write timeout"))??;
    tokio::time::timeout(node_timeout, stream.flush())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend flush timeout"))??;
    let mut leftover = Vec::new();
    let (status, reason, resp_headers) =
        read_http_head(&mut stream, &mut leftover, node_timeout).await?;
    if status == 100 {
        return Ok(AsyncPutterOutcome::Live(AsyncPutter {
            node: node.clone(),
            stream,
            window: SharedWindow::new(BACKEND_WINDOW_BYTES),
            leftover,
        }));
    }
    let content_length =
        resp_header(&resp_headers, "content-length").and_then(|v| v.parse::<u64>().ok());
    let mut reader = BufReader::new(stream);
    let body = read_body_capped(
        &mut reader,
        content_length,
        swift_http::MAX_CONTROL_BODY,
        node_timeout,
    )
    .await
    .unwrap_or_default();
    Ok(AsyncPutterOutcome::EarlyFinal(BackendResponse {
        status,
        reason,
        headers: resp_headers,
        body,
    }))
}

async fn write_chunk_framed_async(stream: &mut TcpStream, chunk: &[u8]) -> io::Result<()> {
    let head = format!("{:x}\r\n", chunk.len());
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(chunk).await?;
    stream.write_all(b"\r\n").await?;
    Ok(())
}

#[cfg(feature = "ec")]
struct AsyncMimePutter {
    #[allow(dead_code)]
    node: Node,
    stream: TcpStream,
    leftover: Vec<u8>,
    boundary: String,
    frag_index: usize,
    frag_hasher: md5::Md5,
    started_data: bool,
}

#[cfg(feature = "ec")]
enum AsyncMimeOutcome {
    Live(AsyncMimePutter),
    EarlyFinal(u16),
}

#[cfg(feature = "ec")]
impl AsyncMimePutter {
    fn frag_md5(&self) -> String {
        use md5::Digest;
        format!("{:x}", self.frag_hasher.clone().finalize())
    }

    async fn start_object_data(&mut self) -> io::Result<()> {
        if !self.started_data {
            let preamble = format!("--{}\r\nX-Document: object body\r\n\r\n", self.boundary);
            write_chunk_framed_async(&mut self.stream, preamble.as_bytes()).await?;
            self.started_data = true;
        }
        Ok(())
    }

    async fn send_data_chunk(&mut self, fragment: &[u8]) -> io::Result<()> {
        if fragment.is_empty() {
            return Ok(());
        }
        self.start_object_data().await?;
        {
            use md5::Digest;
            self.frag_hasher.update(fragment);
        }
        write_chunk_framed_async(&mut self.stream, fragment).await
    }

    async fn end_of_object_data(&mut self, footers_json: &str) -> io::Result<()> {
        use md5::Digest;
        self.start_object_data().await?;
        let footer_md5 = format!("{:x}", md5::Md5::digest(footers_json.as_bytes()));
        let message = format!(
            "\r\n--{b}\r\nX-Document: object metadata\r\nContent-MD5: {footer_md5}\r\n\r\n{footers_json}\r\n--{b}\r\n",
            b = self.boundary
        );
        write_chunk_framed_async(&mut self.stream, message.as_bytes()).await?;
        self.stream.write_all(b"0\r\n\r\n").await?;
        self.stream.flush().await
    }

    async fn read_final(mut self, idle: Duration) -> io::Result<u16> {
        let (status, _, _) = read_http_head(&mut self.stream, &mut self.leftover, idle).await?;
        Ok(status)
    }
}

#[cfg(feature = "ec")]
async fn connect_mime_putter_async(
    node: &Node,
    part: u32,
    path: &str,
    headers: &HeaderKeyDict,
    boundary: &str,
    obj_content_length: Option<u64>,
    conn_timeout: Duration,
    node_timeout: Duration,
) -> io::Result<AsyncMimeOutcome> {
    let mut stream = connect_node_async(node, conn_timeout).await?;
    let addr = format!("{}:{}", node.ip, node.port);
    let target = format!("/{}/{}{}", node.device, part, path);
    let mut out = format!("PUT {target} HTTP/1.1\r\nHost: {addr}\r\n");
    for (k, v) in headers.iter() {
        if [
            "content-length",
            "transfer-encoding",
            "connection",
            "expect",
        ]
        .contains(&k.to_ascii_lowercase().as_str())
        {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "X-Backend-Obj-Multipart-Mime-Boundary: {boundary}\r\n"
    ));
    out.push_str("X-Backend-Obj-Metadata-Footer: yes\r\n");
    if let Some(n) = obj_content_length {
        out.push_str(&format!("X-Backend-Obj-Content-Length: {n}\r\n"));
    }
    out.push_str("Transfer-Encoding: chunked\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n");
    tokio::time::timeout(node_timeout, stream.write_all(out.as_bytes()))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend write timeout"))??;
    tokio::time::timeout(node_timeout, stream.flush())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend flush timeout"))??;
    let mut leftover = Vec::new();
    let (status, _, _) = read_http_head(&mut stream, &mut leftover, node_timeout).await?;
    if status == 100 {
        use md5::Digest;
        return Ok(AsyncMimeOutcome::Live(AsyncMimePutter {
            node: node.clone(),
            stream,
            leftover,
            boundary: boundary.to_string(),
            frag_index: 0,
            frag_hasher: md5::Md5::new(),
            started_data: false,
        }));
    }
    Ok(AsyncMimeOutcome::EarlyFinal(status))
}

#[cfg(feature = "ec")]
async fn tee_ec_segment(
    putters: &mut Vec<AsyncMimePutter>,
    driver: &swift_ec::EcDriver,
    segment: &[u8],
    node_timeout: Duration,
) -> Result<(), Response> {
    let frags = match driver.encode(segment) {
        Ok(f) => f,
        Err(e) => {
            return Err(Response::with_body(
                500,
                format!("EC encode failed: {e:?}").into_bytes(),
            ))
        }
    };
    let mut live = Vec::new();
    for mut p in putters.drain(..) {
        let frag = frags.get(p.frag_index).cloned().unwrap_or_default();
        match tokio::time::timeout(node_timeout, p.send_data_chunk(&frag)).await {
            Ok(Ok(())) => live.push(p),
            _ => {}
        }
    }
    *putters = live;
    Ok(())
}

/// Write one object chunk to every live replica concurrently. A replica whose
/// window is full or whose write times out is dropped (bounded pending bytes).
async fn tee_one_chunk(
    putters: Vec<AsyncPutter>,
    chunk: Vec<u8>,
    chunked: bool,
    node_timeout: Duration,
) -> Vec<AsyncPutter> {
    let n = putters.len();
    if n == 0 {
        return putters;
    }
    let mut group: FanoutGroup<Option<AsyncPutter>> = match FanoutGroup::new(n, n) {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };
    for mut p in putters {
        let piece = chunk.clone();
        if group
            .spawn(move |tx, cancel| async move {
                if cancel.is_cancelled() {
                    let _ = tx.send(None).await;
                    return;
                }
                if p.window.try_push(piece.len()).is_err() {
                    let _ = tx.send(None).await;
                    return;
                }
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => Err(()),
                    r = async {
                        if chunked {
                            tokio::time::timeout(
                                node_timeout,
                                write_chunk_framed_async(&mut p.stream, &piece),
                            )
                            .await
                            .map_err(|_| ())
                            .and_then(|r| r.map_err(|_| ()))
                        } else {
                            tokio::time::timeout(node_timeout, p.stream.write_all(&piece))
                                .await
                                .map_err(|_| ())
                                .and_then(|r| r.map_err(|_| ()))
                        }
                    } => r,
                };
                p.window.pop(piece.len());
                let _ = tx.send(if result.is_ok() { Some(p) } else { None }).await;
            })
            .is_err()
        {
            group.cancel_unused();
            break;
        }
    }
    let expected = group.spawned();
    let mut live = Vec::new();
    let wait = node_timeout + Duration::from_millis(50);
    for _ in 0..expected {
        match tokio::time::timeout(wait, group.recv()).await {
            Ok(Some(Some(p))) => live.push(p),
            Ok(Some(None)) | Ok(None) | Err(_) => {}
        }
    }
    group.cancel_unused();
    group.join().await;
    live
}

/// How remaining replica slots are treated once write quorum is decided.
///
/// Object-style fan-out cancels unused backends immediately (a blackhole
/// replica must not pin the client). Account/container writes carry an
/// account-update side channel on every replica: Python's `_make_requests`
/// does `pile.waitall(post_quorum_timeout)` without killing those
/// greenthreads. Cancelling at quorum here leaves one account replica stale,
/// and account GET is first-good-source — so a container PUT 201 can miss
/// the subsequent account listing (G4 testCreate/testDelete leftovers).
#[derive(Clone, Copy)]
enum QuorumDrain {
    CancelUnused,
    PostQuorumTimeout,
}

impl ProxyApp {
    /// Bounded async replica fan-out. Unused backends are cancelled once
    /// quorum is reached.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn make_requests_async(
        self: &Arc<Self>,
        nodes: Vec<Node>,
        node_number: usize,
        part: u32,
        method: &str,
        path: &str,
        query: &str,
        per_node_headers: Vec<swift_http::HeaderKeyDict>,
        body: Vec<u8>,
    ) -> Response {
        self.make_requests_async_drain(
            nodes,
            node_number,
            part,
            method,
            path,
            query,
            per_node_headers,
            body,
            QuorumDrain::CancelUnused,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn make_requests_async_drain(
        self: &Arc<Self>,
        nodes: Vec<Node>,
        node_number: usize,
        part: u32,
        method: &str,
        path: &str,
        query: &str,
        per_node_headers: Vec<swift_http::HeaderKeyDict>,
        body: Vec<u8>,
        drain: QuorumDrain,
    ) -> Response {
        let slots = per_node_headers.len().max(1);
        let mut group: FanoutGroup<Option<BackendResponse>> = match FanoutGroup::new(slots, slots) {
            Ok(g) => g,
            Err(_) => return swob_response(503),
        };
        let node_pool = Arc::new(Mutex::new(nodes.into_iter().collect::<VecDeque<_>>()));
        for headers in per_node_headers.into_iter() {
            let app = Arc::clone(self);
            let node_pool = Arc::clone(&node_pool);
            let method = method.to_string();
            let path = path.to_string();
            let query = query.to_string();
            let body = body.clone();
            if group
                .spawn(move |tx, cancel| async move {
                    replica_try_nodes(
                        app, node_pool, part, method, path, query, headers, body, tx, cancel,
                    )
                    .await;
                })
                .is_err()
            {
                return swob_response(503);
            }
        }
        let needed = quorum_size(node_number.max(1) as f64) as usize;
        let mut tracker = QuorumTracker::new(needed);
        let mut results: Vec<BackendResponse> = Vec::new();
        let expected = group.spawned();
        let mut finished = 0usize;
        let wait = self.config.conn_timeout + self.config.node_timeout;
        for _ in 0..expected {
            match tokio::time::timeout(wait, group.recv()).await {
                Ok(Some(Some(resp))) => {
                    finished += 1;
                    if (200..500).contains(&resp.status) {
                        tracker.record_success();
                    } else {
                        tracker.record_failure();
                    }
                    results.push(resp);
                    if tracker.has_quorum() {
                        if matches!(drain, QuorumDrain::CancelUnused) {
                            group.cancel_unused();
                        }
                        break;
                    }
                }
                Ok(Some(None)) => finished += 1,
                Ok(None) | Err(_) => {}
            }
        }
        if matches!(drain, QuorumDrain::PostQuorumTimeout) {
            // Python base.py `_make_requests`: after quorum, waitall(post_quorum_timeout)
            // so the remaining replica's account_update can finish. Return as
            // soon as every slot has reported; then cancel stragglers — L6
            // forbids detaching them.
            let deadline = Instant::now() + self.config.post_quorum_timeout;
            while finished < expected {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match tokio::time::timeout(remaining, group.recv()).await {
                    Ok(Some(Some(resp))) => {
                        finished += 1;
                        results.push(resp);
                    }
                    Ok(Some(None)) => finished += 1,
                    Ok(None) | Err(_) => break,
                }
            }
        }
        group.cancel_unused();
        group.join().await;
        while results.len() < slots.max(node_number) {
            results.push(BackendResponse {
                status: 503,
                reason: "Service Unavailable".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            });
        }
        self.best_response(&results, node_number)
    }

    /// Async object PUT tee: one client chunk, bounded per-backend window,
    /// stalled replica dropped, client not read when nobody can consume.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn stream_put_async(
        self: &Arc<Self>,
        nodes: Vec<Node>,
        node_number: usize,
        part: u32,
        path: &str,
        query: &str,
        per_node_headers: Vec<swift_http::HeaderKeyDict>,
        body: &mut IncomingBody,
    ) -> Response {
        let content_length =
            super::backend_put_content_length(body.content_length(), &per_node_headers);
        let slots = per_node_headers.len().max(1);
        let quorum = quorum_size(node_number.max(1) as f64) as usize;
        let mut group: FanoutGroup<AsyncPutterOutcome> = match FanoutGroup::new(slots, slots) {
            Ok(g) => g,
            Err(_) => return swob_response(503),
        };
        let node_pool = Arc::new(Mutex::new(nodes.into_iter().collect::<VecDeque<_>>()));
        for headers in per_node_headers {
            let app = Arc::clone(self);
            let node_pool = Arc::clone(&node_pool);
            let path = path.to_string();
            let query = query.to_string();
            if group
                .spawn(move |tx, cancel| async move {
                    connect_slot(
                        app,
                        node_pool,
                        part,
                        path,
                        query,
                        headers,
                        content_length,
                        tx,
                        cancel,
                    )
                    .await;
                })
                .is_err()
            {
                return swob_response(503);
            }
        }
        let wait = self.config.conn_timeout + self.config.node_timeout;
        let expected = group.spawned();
        let mut earlies: Vec<BackendResponse> = Vec::new();
        let mut putters: Vec<AsyncPutter> = Vec::new();
        for _ in 0..expected {
            match tokio::time::timeout(wait, group.recv()).await {
                Ok(Some(AsyncPutterOutcome::Live(p))) => putters.push(p),
                Ok(Some(AsyncPutterOutcome::EarlyFinal(r))) => earlies.push(r),
                Ok(None) | Err(_) => {}
            }
        }
        group.cancel_unused();
        group.join().await;
        if earlies.iter().any(|r| r.status == 412) {
            return swob_response(412);
        }
        if earlies.iter().any(|r| r.status == 409) {
            return swob_response(202);
        }
        if putters.len() < quorum {
            let mut results = earlies;
            while results.len() < slots.max(node_number) {
                results.push(BackendResponse {
                    status: 503,
                    reason: "Service Unavailable".to_string(),
                    headers: Vec::new(),
                    body: Vec::new(),
                });
            }
            return self.best_response(&results, node_number);
        }
        let chunked = content_length.is_none();
        let node_timeout = self.config.node_timeout;
        loop {
            if !putters.is_empty()
                && putters
                    .iter()
                    .all(|p| p.window.pending() >= p.window.limit())
            {
                // Every live replica is at its window: do not read the client.
                putters.retain(|p| p.window.pending() < p.window.limit());
                if putters.len() < quorum {
                    return swob_response(503);
                }
                continue;
            }
            let chunk = match body.next_chunk().await {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) if swift_http::body_too_large(&e) => return swob_response(413),
                Err(_) => return swob_response(499),
            };
            for piece in chunk.chunks(BACKEND_WINDOW_BYTES) {
                putters = tee_one_chunk(putters, piece.to_vec(), chunked, node_timeout).await;
                if putters.len() < quorum {
                    return swob_response(503);
                }
            }
        }
        if chunked {
            putters = tee_one_chunk(putters, Vec::new(), true, node_timeout).await;
            // Empty chunked write sends "0\r\n\r\n" via write_chunk_framed_async
            // which is the terminator. write_chunk_framed of empty is "0\r\n\r\n".
        }
        let mut results = earlies;
        for mut p in putters {
            let _ = p.stream.flush().await;
            let mut leftover = std::mem::take(&mut p.leftover);
            let mut stream = p.stream;
            match read_http_head(&mut stream, &mut leftover, node_timeout).await {
                Ok((status, reason, headers)) => {
                    let content_length =
                        resp_header(&headers, "content-length").and_then(|v| v.parse::<u64>().ok());
                    let mut reader = BufReader::new(stream);
                    let saved = leftover.clone();
                    let body = leftover_then_read(
                        &mut leftover,
                        &mut reader,
                        content_length,
                        node_timeout,
                    )
                    .await
                    .unwrap_or(saved);
                    results.push(BackendResponse {
                        status,
                        reason,
                        headers,
                        body,
                    });
                }
                Err(_) => self.error_limiter.increment(&p.node),
            }
        }
        while results.len() < slots.max(node_number) {
            results.push(BackendResponse {
                status: 503,
                reason: "Service Unavailable".to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            });
        }
        self.best_response(&results, node_number)
    }

    /// Async `GETorHEAD_base`. Object GET bodies are a bounded channel
    /// (capacity 1): a slow client does not pin a blocking worker or
    /// unbounded-buffer the object.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn get_or_head_async(
        self: &Arc<Self>,
        server_type: &str,
        nodes: Vec<Node>,
        part: u32,
        method: &str,
        path: &str,
        query: &str,
        headers: &HeaderKeyDict,
    ) -> Option<Response> {
        let is_object = server_type == "object";
        let is_head = method == "HEAD";
        let newest = headers
            .get("X-Newest")
            .map(config_true_value)
            .unwrap_or(false);
        let idle = self.config.node_timeout;
        let conn_timeout = self.config.conn_timeout;
        let build = |resp: BackendResponse| -> Response {
            let mut out = Response::with_body(resp.status, resp.body);
            out.reason = resp.reason;
            for (k, v) in &resp.headers {
                let kl = k.to_lowercase();
                if kl == "connection" || (kl == "content-length" && !is_head) {
                    continue;
                }
                if is_object && kl == "etag" {
                    out.headers.set(k, v.trim_matches('"'));
                    continue;
                }
                out.headers.set(k, v);
            }
            if (200..300).contains(&out.status) {
                out.headers.set("Accept-Ranges", "bytes");
            }
            if is_head
                && (200..300).contains(&out.status)
                && out.headers.get("Content-Length").is_none()
            {
                out.headers.set("Content-Length", 0);
            }
            out
        };
        let build_streamed = |head: AsyncBackendHead| -> Response {
            let mut out = Response::new(head.status);
            out.reason = head.reason.clone();
            for (k, v) in &head.headers {
                let kl = k.to_lowercase();
                if kl == "connection" || kl == "content-length" {
                    continue;
                }
                if is_object && kl == "etag" {
                    out.headers.set(k, v.trim_matches('"'));
                    continue;
                }
                out.headers.set(k, v);
            }
            if (200..300).contains(&out.status) {
                out.headers.set("Accept-Ranges", "bytes");
            }
            let len = head.content_length;
            out.body = stream_backend_body(head, idle);
            if out.headers.get("Content-Length").is_none() {
                if let Some(n) = len {
                    out.headers.set("Content-Length", n);
                }
            }
            out
        };
        let mut recorded_404: Option<Response> = None;
        let mut latest_404_timestamp = Timestamp::zero();
        let mut newest_candidates: Vec<(Timestamp, AsyncBackendHead)> = Vec::new();
        for node in nodes {
            match backend_request_head_async(
                &node,
                part,
                method,
                path,
                query,
                headers,
                b"",
                conn_timeout,
                idle,
            )
            .await
            {
                Ok(head) if head.status == 507 => self.error_limiter.limit(&node),
                Ok(head) if head.status >= 500 => self.error_limiter.increment(&node),
                Ok(head) if head.status == 404 => {
                    let ts = backend_404_timestamp(&head.headers);
                    if !node.handoff || ts.is_truthy() {
                        // Same watermark as sync get_or_head: container
                        // DELETE tombstones beat a stale handoff 200
                        // (probe L2095 / listing-w214).
                        if ts > latest_404_timestamp {
                            latest_404_timestamp = ts;
                        }
                        if recorded_404.is_none() {
                            match buffer_backend_body(
                                head,
                                swift_http::MAX_CONTROL_BODY,
                                !is_head,
                                idle,
                            )
                            .await
                            {
                                Ok(resp) => recorded_404 = Some(build(resp)),
                                Err(_) => self.error_limiter.increment(&node),
                            }
                        }
                    }
                }
                Ok(head) if is_good_source(head.status, is_object) => {
                    let ts = source_timestamp(&head.headers);
                    if ts >= latest_404_timestamp {
                        if newest {
                            newest_candidates.push((ts, head));
                            continue;
                        }
                        if is_object && !is_head {
                            return Some(build_streamed(head));
                        }
                        match buffer_backend_body(
                            head,
                            swift_http::MAX_CONTROL_BODY,
                            !is_head,
                            idle,
                        )
                        .await
                        {
                            Ok(resp) => return Some(build(resp)),
                            Err(_) => {
                                self.error_limiter.increment(&node);
                                continue;
                            }
                        }
                    }
                }
                Ok(head) => {
                    match buffer_backend_body(head, swift_http::MAX_CONTROL_BODY, !is_head, idle)
                        .await
                    {
                        Ok(resp) => return Some(build(resp)),
                        Err(_) => self.error_limiter.increment(&node),
                    }
                }
                Err(_) => self.error_limiter.increment(&node),
            }
        }
        if newest {
            newest_candidates.retain(|(ts, _)| *ts >= latest_404_timestamp);
            if let Some((_, head)) = newest_candidates
                .into_iter()
                .max_by(|(a, _), (b, _)| a.cmp(b))
            {
                if is_object && !is_head {
                    return Some(build_streamed(head));
                }
                return match buffer_backend_body(head, swift_http::MAX_CONTROL_BODY, !is_head, idle)
                    .await
                {
                    Ok(resp) => Some(build(resp)),
                    Err(_) => recorded_404,
                };
            }
        }
        recorded_404
    }

    pub(crate) async fn container_info_async(
        self: &Arc<Self>,
        account: &str,
        container: &str,
    ) -> ContainerInfo {
        let cache_key = format!("{account}/{container}");
        if let Some(info) = self.info_cache.get_container(&cache_key) {
            return info;
        }
        let mut info = ContainerInfo {
            status: 0,
            policy_index: self.config.default_policy_index,
            read_acl: None,
            write_acl: None,
            temp_url_keys: Vec::new(),
            sync_key: None,
            rfc_compliant_etags: None,
            cors: super::CorsInfo::default(),
            db_state: String::new(),
        };
        let Ok((part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return info;
        };
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        let nodes = self.iter_nodes(&self.container_ring, part);
        let headers = HeaderKeyDict::new();
        if let Some(resp) = self
            .get_or_head_async("container", nodes, part, "HEAD", &path, "", &headers)
            .await
        {
            fill_container_info_from_head(&mut info, &resp);
            if let Some(ttl) = info_cache_time(
                resp.status,
                resp.headers.get("X-Backend-Recheck-Container-Existence"),
                self.config.recheck_container_existence,
            ) {
                self.info_cache.set_container(cache_key, info.clone(), ttl);
            }
        }
        info
    }

    pub(crate) async fn account_info_async(self: &Arc<Self>, account: &str) -> AccountInfo {
        if let Some(info) = self.info_cache.get_account(account) {
            return info;
        }
        let mut info = AccountInfo::default();
        let Ok((part, _)) = self.account_ring.get_nodes(account, None, None) else {
            info.status = 503;
            return info;
        };
        let path = format!("/{}", percent_encode(account));
        let nodes = self.iter_nodes(&self.account_ring, part);
        let headers = HeaderKeyDict::new();
        if let Some(resp) = self
            .get_or_head_async("account", nodes, part, "HEAD", &path, "", &headers)
            .await
        {
            info = account_info_from_response(&resp);
            self.cache_account_from_response(account, &resp);
        } else {
            info.status = 503;
        }
        info
    }

    pub(crate) async fn resolve_updating_shard_async(
        self: &Arc<Self>,
        account: &str,
        container: &str,
        object: &str,
    ) -> Option<(String, String)> {
        let info = self.container_info_async(account, container).await;
        let db_state = self.effective_root_db_state(account, container, info.root_db_state());
        if !super::cached_state_allows_shard_update(&db_state) {
            return None;
        }

        let Ok((part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return None;
        };
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        let nodes = self.iter_nodes(&self.container_ring, part);
        let head_headers = HeaderKeyDict::new();
        let head = self
            .get_or_head_async(
                "container",
                nodes.clone(),
                part,
                "HEAD",
                &path,
                "",
                &head_headers,
            )
            .await?;
        if !(200..300).contains(&head.status) {
            return None;
        }
        let state = head
            .headers
            .get("X-Backend-Sharding-State")
            .unwrap_or("unsharded")
            .to_ascii_lowercase();
        if state != "sharding" && state != "sharded" {
            return None;
        }
        let mut shard_headers = HeaderKeyDict::new();
        shard_headers.set("X-Backend-Record-Type", "shard");
        // Longest nonempty, same `states=updating` query (probe L631).
        // listing-w137/w138: do not add includes= here until concat is proven.
        let updating = self
            .fetch_json_array_longest_nonempty_async(
                &nodes,
                part,
                &path,
                "states=updating&format=json",
                &shard_headers,
            )
            .await
            .filter(|a| !a.is_empty());
        let root_path = format!("{account}/{container}");
        let name = match updating
            .as_ref()
            .and_then(|arr| super::pick_updating_shard_name(arr, object, &root_path))
        {
            Some(n) => n,
            None => {
                // Lagging replica may return a non-empty updating set that
                // still lacks nested children; fall back to listing states
                // without changing the updating query (probe L1435).
                let listing = self
                    .fetch_listing_shard_ranges_async(nodes, part, &path, &shard_headers)
                    .await?;
                super::pick_updating_shard_name(&listing, object, &root_path)?
            }
        };
        let (a, c) = name.split_once('/')?;
        Some((a.to_string(), c.to_string()))
    }

    pub(crate) async fn object_get_head_async(
        self: &Arc<Self>,
        req: &mut swift_http::Request,
        account: &str,
        container: &str,
        object: &str,
    ) -> Response {
        let header_policy: Option<i64> = req
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|v| v.parse().ok());
        let container_policy = self
            .container_info_async(account, container)
            .await
            .policy_index;
        // InternalClient may send policy 0. Do not let that hide an EC
        // container (field 2c64a89: Ec-Frag 200s exist, gather never ran).
        let policy_index: i64 = match header_policy {
            Some(0) if self.ec_policies.contains_key(&container_policy) => container_policy,
            Some(p) => p,
            None => container_policy,
        };
        let Some(object_ring) = self.object_ring_for(policy_index) else {
            return super::with_g6_diag(
                Response::with_body(
                    503,
                    format!("No object ring configured for storage policy {policy_index}")
                        .into_bytes(),
                ),
                format!("reason=no_object_ring policy={policy_index} ec=0"),
            );
        };
        let Ok((object_part, _)) = object_ring.get_nodes(account, Some(container), Some(object))
        else {
            return super::with_g6_diag(
                swob_response(503),
                format!("reason=get_nodes_failed policy={policy_index} ec=0"),
            );
        };
        let path = format!(
            "/{}/{}/{}",
            percent_encode(account),
            percent_encode(container),
            percent_encode(object)
        );
        let mut headers = self.backend_headers(req, false, "object");
        headers.set("X-Backend-Storage-Policy-Index", policy_index);
        super::stamp_next_part_power(&mut headers, object_ring);
        for h in [
            "Range",
            "If-Match",
            "If-None-Match",
            "If-Modified-Since",
            "If-Unmodified-Since",
            "X-Newest",
            "X-Backend-Ignore-Range-If-Metadata-Present",
            "X-Backend-Etag-Is-At",
        ] {
            if let Some(v) = req.headers.get(h) {
                headers.set(h, v.to_string());
            }
        }
        self.forward_open_expired(req, &mut headers);
        let ec_params = self.ec_params_for_object_ring(policy_index, object_ring);
        self.emit_proxy_log(
            false,
            &format!(
                "proxy-server: EC GET {path} status=route reason=object_get_head_async \
                 header={header_policy:?} container_policy={container_policy} \
                 policy={policy_index} ec={} ndata={} replica={}",
                ec_params.is_some() as u8,
                ec_params.map(|e| e.ndata).unwrap_or(0),
                object_ring.replica_count()
            ),
        );
        if ec_params.is_some() {
            return self
                .ec_get_async(req, &path, policy_index, object_ring, object_part)
                .await;
        }
        let nodes = self.iter_nodes(object_ring, object_part);
        let mut resp = self
            .get_or_head_async(
                "object",
                nodes,
                object_part,
                &req.method,
                &path,
                &req.query_string,
                &headers,
            )
            .await
            .unwrap_or_else(|| swob_response(503));
        if resp.status == 404 {
            self.emit_proxy_log(
                true,
                &format!(
                    "proxy-server: EC GET {path} status=404 reason=replica_get_or_head \
                     policy={policy_index}"
                ),
            );
        }
        resp.set_g6_diag(format!(
            "reason=replica_get_or_head policy={policy_index} ec=0 ndata=0 idxs=[] status={}",
            resp.status
        ));
        resp
    }

    pub(crate) async fn ec_get_async(
        self: &Arc<Self>,
        req: &mut swift_http::Request,
        path: &str,
        policy_index: i64,
        object_ring: &swift_ring::Ring,
        object_part: u32,
    ) -> Response {
        let Some(ec) = self.ec_params_for_object_ring(policy_index, object_ring) else {
            return super::with_g6_diag(
                swob_response(503),
                format!("reason=ec_params_missing policy={policy_index} ec=0"),
            );
        };
        #[cfg(not(feature = "ec"))]
        {
            let _ = (req, path, object_ring, object_part, ec);
            return super::with_g6_diag(
                Response::with_body(
                    501,
                    b"erasure coding not built (compile with --features ec)".to_vec(),
                ),
                format!("reason=ec_not_built policy={policy_index} ec=0"),
            );
        }
        #[cfg(feature = "ec")]
        {
            // `&Request` is not Send (`Body` holds `dyn Read + Send`, not
            // Sync). Extract what the EC GET needs so the Hyper service
            // future stays Send under `--features ec`.
            let is_head = req.method == "HEAD";
            let mut headers = self.backend_headers(req, false, "object");
            headers.set("X-Backend-Storage-Policy-Index", policy_index);
            super::stamp_next_part_power(&mut headers, object_ring);
            // Never forward client Range or If-* to fragment archives: those
            // files are EC-sized and carry fragment etags, not the original
            // object. Range and conditionals are applied after decode against
            // the reconstructed ETag / Last-Modified. Ignore-Range is
            // evaluated against fragment sysmeta locally.
            for h in ["X-Newest"] {
                if let Some(v) = req.headers.get(h) {
                    headers.set(h, v.to_string());
                }
            }
            self.forward_open_expired(req, &mut headers);
            let range_hdr = req.headers.get("Range").map(str::to_string);
            let ignore_hdr = req
                .headers
                .get("X-Backend-Ignore-Range-If-Metadata-Present")
                .map(str::to_string);
            let mut cond_headers = HeaderKeyDict::new();
            for h in [
                "If-Match",
                "If-None-Match",
                "If-Modified-Since",
                "If-Unmodified-Since",
                "X-Backend-Etag-Is-At",
            ] {
                if let Some(v) = req.headers.get(h) {
                    cond_headers.set(h, v.to_string());
                }
            }
            self.ec_get_async_inner(
                is_head,
                headers,
                path,
                policy_index,
                object_ring,
                object_part,
                ec,
                range_hdr,
                ignore_hdr,
                cond_headers,
            )
            .await
        }
    }

    #[cfg(feature = "ec")]
    async fn ec_get_async_inner(
        self: &Arc<Self>,
        is_head: bool,
        mut headers: HeaderKeyDict,
        path: &str,
        policy_index: i64,
        object_ring: &swift_ring::Ring,
        object_part: u32,
        ec: super::EcPolicyParams,
        range_hdr: Option<String>,
        ignore_hdr: Option<String>,
        cond_headers: HeaderKeyDict,
    ) -> Response {
        use swift_ec::EcDriver;
        struct EcResponseBucket {
            etag: String,
            meta: Vec<(String, String)>,
            sources: std::collections::HashMap<i32, AsyncBackendHead>,
            durable: bool,
        }

        let nodes = self.iter_nodes(object_ring, object_part);
        let required = if is_head { 1 } else { ec.ndata };
        // InternalClient / copy_backend_control_headers forwards every
        // X-Backend-* header. A leaked Fragment-Preferences on the client
        // GET would make rust DiskFile treat `[]` as newest-including-
        // non-durable, or exclude the remaining durable indexes. Round 0
        // must be prefs-less regardless of what the client sent.
        headers.remove("X-Backend-Fragment-Preferences");
        self.emit_proxy_log(
            false,
            &format!(
                "proxy-server: EC GET {path} status=start reason=gather \
                 policy={policy_index} ndata={} nodes={} prefs=omitted",
                ec.ndata,
                nodes.len()
            ),
        );
        let mut buckets: std::collections::HashMap<String, EcResponseBucket> =
            std::collections::HashMap::new();
        let mut saw_404 = false;
        let mut latest_404_timestamp = Timestamp::zero();
        let mut n200 = 0usize;
        let mut seen_idxs: Vec<i32> = Vec::new();
        let mut skipped_no_ts = 0usize;
        let mut skipped_no_fi = 0usize;
        let mut skipped_etag = 0usize;
        // Two rounds, Python ECFragGetter-shaped. Round 0 must *omit*
        // X-Backend-Fragment-Preferences: rust DiskFile treats `[]` as
        // "newest, including non-durable". Official
        // `test_rebuild_missing_frags` POSTs after PUT then deletes 1–2
        // hash dirs. A first-node `[]` 200 that we fail to mark durable
        // (or that is a different generation) then excludes that index on
        // every later primary; with ndata=4 a single-frag hole still 404s
        // even though five `#d.data` archives remain. Prefs-less GET is
        // the durable-only contract, so remaining primaries return the
        // same PUT generation. Round 1 still sends prefs so a newer
        // no-commit generation can be skipped in favor of the older
        // durable set.
        'request_rounds: for round in 0..2 {
            for node in &nodes {
                let mut request_headers = headers.clone();
                if send_ec_fragment_preferences(round) {
                    let preferences = encode_ec_fragment_preferences(
                        buckets.iter().map(|(timestamp, bucket)| {
                            (
                                timestamp.as_str(),
                                bucket.durable,
                                bucket.sources.keys().copied().collect(),
                            )
                        }),
                        required,
                    );
                    request_headers.set("X-Backend-Fragment-Preferences", preferences);
                }
                match backend_request_head_async(
                    node,
                    object_part,
                    "GET",
                    path,
                    "",
                    &request_headers,
                    b"",
                    self.config.conn_timeout,
                    self.config.node_timeout,
                )
                .await
                {
                    Ok(head) if head.status == 200 => {
                        n200 += 1;
                        let explicit_data_timestamp =
                            resp_header(&head.headers, "X-Backend-Data-Timestamp");
                        let data_timestamp = explicit_data_timestamp
                            .or_else(|| resp_header(&head.headers, "X-Backend-Timestamp"))
                            .or_else(|| resp_header(&head.headers, "X-Timestamp"))
                            .map(str::to_string);
                        // Field 4f7a82c: five Ec-Frag 200s (idxs 0,2,3,4,5)
                        // still 404'd. A prefs-less 200 is the durable
                        // generation — do not drop it for a missing ts.
                        let data_timestamp = match data_timestamp {
                            Some(ts) => ts,
                            None if round == 0 => "0".to_string(),
                            None => {
                                skipped_no_ts += 1;
                                continue;
                            }
                        };
                        let durable = if round == 0 {
                            // Prefs-less object-server GET only opens the
                            // durable set. Count it even when POST moved
                            // X-Timestamp / durable_ts off the data file.
                            true
                        } else {
                            ec_source_is_durable(
                                &data_timestamp,
                                resp_header(&head.headers, "X-Backend-Durable-Timestamp"),
                                explicit_data_timestamp.is_some(),
                            )
                        };
                        let fi = ec_frag_index(&head.headers).or(node.backend_index);
                        let Some(fi) = fi else {
                            skipped_no_fi += 1;
                            continue;
                        };
                        seen_idxs.push(fi);
                        let etag = resp_header(&head.headers, "X-Object-Sysmeta-Ec-Etag")
                            .unwrap_or_default()
                            .to_string();
                        // Round 0 is one durable generation. Join every
                        // unique index even when POST/PUT timestamps or
                        // fragment ETags disagree (field: 5×200 → 404).
                        let data_key = if round == 0 {
                            ec_round0_bucket_key(
                                buckets.keys().next().map(String::as_str),
                                &data_timestamp,
                            )
                        } else {
                            version_timestamp_key(&data_timestamp)
                        };
                        let bucket = buckets.entry(data_key).or_insert_with(|| EcResponseBucket {
                            etag: etag.clone(),
                            meta: head.headers.clone(),
                            sources: std::collections::HashMap::new(),
                            durable,
                        });
                        bucket.durable |= durable;
                        if bucket.etag.is_empty() && !etag.is_empty() {
                            bucket.etag = etag.clone();
                            bucket.meta = head.headers.clone();
                        }
                        if round == 0 || ec_etag_compatible(&bucket.etag, &etag) {
                            bucket.sources.entry(fi).or_insert(head);
                        } else {
                            skipped_etag += 1;
                        }
                    }
                    Ok(head) if head.status == 404 => {
                        saw_404 = true;
                        let ts = super::backend_404_timestamp(&head.headers);
                        if !node.handoff || ts.is_truthy() {
                            if ts > latest_404_timestamp {
                                latest_404_timestamp = ts;
                            }
                        }
                    }
                    Ok(head) if head.status == 507 => self.error_limiter.limit(node),
                    Ok(head) if head.status >= 500 => self.error_limiter.increment(node),
                    Ok(_) => {}
                    Err(_) => self.error_limiter.increment(node),
                }
                if buckets
                    .values()
                    .any(|bucket| bucket.durable && bucket.sources.len() >= required)
                {
                    break 'request_rounds;
                }
            }
        }
        let tombstone_trumps = |timestamp: &str| -> bool {
            timestamp
                .parse::<Timestamp>()
                .ok()
                .map(|ts| ts < latest_404_timestamp)
                .unwrap_or(false)
        };
        let chosen_timestamp = buckets
            .iter()
            .filter(|(timestamp, bucket)| {
                !tombstone_trumps(timestamp) && bucket.durable && bucket.sources.len() >= required
            })
            .map(|(timestamp, _)| timestamp)
            .max()
            .cloned();
        let chosen_timestamp = match chosen_timestamp {
            Some(ts) => ts,
            None => {
                // Field `4f7a82c` single-frag 404: ndata remaining 200s
                // were collected then classified non-durable, so
                // ec_no_durable_status pretended they were 404. If a
                // complete generation survived tombstones, serve it —
                // that is the official probe's "remaining ndata must
                // decode" case, including after once.
                if let Some(ts) = buckets
                    .iter()
                    .filter(|(timestamp, bucket)| {
                        !tombstone_trumps(timestamp) && bucket.sources.len() >= required
                    })
                    .map(|(timestamp, _)| timestamp.clone())
                    .max()
                {
                    ts
                } else {
                    let has_reconstructable_nondurable_bucket =
                        buckets.iter().any(|(timestamp, bucket)| {
                            !tombstone_trumps(timestamp) && bucket.sources.len() >= required
                        });
                    let all_good_older_than_tombstone = latest_404_timestamp.is_truthy()
                        && buckets.keys().all(|timestamp| tombstone_trumps(timestamp));
                    let bucket_summary = buckets
                        .iter()
                        .map(|(key, bucket)| {
                            format!(
                                "{}:{}:{}:{}",
                                key,
                                bucket.sources.len(),
                                if bucket.durable { "d" } else { "n" },
                                bucket.etag
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    // Field f4051f4: 5 unique-index 200s still 404'd when
                    // they sat in split generation buckets. Merge every
                    // unique index that is not older than a truthy tombstone
                    // — that is the official probe contract (ndata of 6).
                    let mut flat = std::collections::HashMap::new();
                    for bucket in buckets.values_mut() {
                        for (fi, head) in std::mem::take(&mut bucket.sources) {
                            let src_ts = super::source_timestamp(&head.headers);
                            if latest_404_timestamp.is_truthy() && src_ts < latest_404_timestamp {
                                continue;
                            }
                            flat.entry(fi).or_insert(head);
                        }
                    }
                    if flat.len() >= required {
                        let flat_key = "flat".to_string();
                        let merged = EcResponseBucket {
                            etag: String::new(),
                            meta: flat
                                .values()
                                .next()
                                .map(|head| head.headers.clone())
                                .unwrap_or_default(),
                            sources: flat,
                            durable: true,
                        };
                        buckets.insert(flat_key.clone(), merged);
                        flat_key
                    } else if all_good_older_than_tombstone {
                        log_ec_gather_miss(
                            self,
                            path,
                            404,
                            "tombstone_trumps",
                            policy_index,
                            ec.ndata,
                            n200,
                            &seen_idxs,
                            skipped_no_ts,
                            skipped_no_fi,
                            skipped_etag,
                            &bucket_summary,
                            &latest_404_timestamp.internal(),
                            saw_404,
                        );
                        return super::with_g6_diag(
                            swob_response(404),
                            g6_ec_diag(
                                "tombstone_trumps",
                                404,
                                policy_index,
                                ec.ndata,
                                &seen_idxs,
                                n200,
                            ),
                        );
                    } else {
                        // Official test_rebuild_quarantines_lonely_frag:
                        // some durable frags but fewer than ndata cannot
                        // decode → 503 Service Unavailable. An empty
                        // collection plus an explicit 404 (every hash dir
                        // gone) is the known-missing 404. Do not treat
                        // `saw_404 && flat.len() < ndata` as 404 — that
                        // hid the lonely-frag pre-quarantine GET
                        // (`fd53360` field `/workspace/rebuild-lonely-fd53360/`).
                        // ≥ndata remaining still decodes above
                        // (`test_rebuild_missing_frags`).
                        let status = ec_no_durable_status(
                            has_reconstructable_nondurable_bucket,
                            saw_404,
                            buckets.is_empty() || flat.is_empty(),
                        );
                        let miss_reason = if buckets.is_empty() {
                            "empty_buckets"
                        } else {
                            "no_complete_bucket"
                        };
                        log_ec_gather_miss(
                            self,
                            path,
                            status,
                            miss_reason,
                            policy_index,
                            ec.ndata,
                            n200,
                            &seen_idxs,
                            skipped_no_ts,
                            skipped_no_fi,
                            skipped_etag,
                            &bucket_summary,
                            &latest_404_timestamp.internal(),
                            saw_404,
                        );
                        return super::with_g6_diag(
                            swob_response(status),
                            g6_ec_diag(
                                miss_reason,
                                status,
                                policy_index,
                                ec.ndata,
                                &seen_idxs,
                                n200,
                            ),
                        );
                    }
                }
            }
        };
        let chosen = buckets
            .remove(&chosen_timestamp)
            .expect("chosen EC response bucket must exist");
        self.emit_proxy_log(
            false,
            &format_ec_gather_miss(
                path,
                200,
                "ok",
                policy_index,
                ec.ndata,
                n200,
                &seen_idxs,
                skipped_no_ts,
                skipped_no_fi,
                skipped_etag,
                &format!(
                    "{}:{}:{}:{}",
                    chosen_timestamp,
                    chosen.sources.len(),
                    if chosen.durable { "d" } else { "n" },
                    chosen.etag
                ),
                &latest_404_timestamp.internal(),
                saw_404,
            ),
        );
        let sources = chosen.sources;
        let meta = chosen.meta;
        let ec_etag = resp_header(&meta, "X-Object-Sysmeta-Ec-Etag")
            .unwrap_or_default()
            .to_string();
        let orig_size: usize = resp_header(&meta, "X-Object-Sysmeta-Ec-Content-Length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let content_type = resp_header(&meta, "Content-Type")
            .unwrap_or("application/octet-stream")
            .to_string();
        let mut resp = Response::new(200);
        resp.set_g6_diag(g6_ec_diag(
            "ok",
            200,
            policy_index,
            ec.ndata,
            &seen_idxs,
            n200,
        ));
        for (k, v) in &meta {
            if super::keep_ec_client_metadata(&k.to_lowercase()) {
                resp.headers.set(k, v);
            }
        }
        if !ec_etag.is_empty() {
            resp.headers.set("ETag", &ec_etag);
        }
        resp.headers.set("Accept-Ranges", "bytes");
        let ignore_range = ignore_hdr
            .as_deref()
            .map(|names| {
                names
                    .split(',')
                    .any(|name| resp_header(&meta, name.trim()).is_some())
            })
            .unwrap_or(false);
        let resolved_ranges: Option<Vec<(u64, u64)>> = if is_head || ignore_range {
            None
        } else {
            range_hdr
                .as_deref()
                .and_then(|h| swift_http::Range::parse(h).ok())
                .and_then(|r| r.ranges_for_length(Some(orig_size as u64)))
        };
        if let Some(ranges) = resolved_ranges.as_deref() {
            if ranges.is_empty() {
                let body = concat!(
                    "<html><h1>Requested Range Not Satisfiable</h1>",
                    "<p>The Range requested is not available.</p></html>"
                );
                let mut r416 = Response::with_body(416, body.as_bytes().to_vec());
                r416.headers
                    .set("Content-Range", format!("bytes */{orig_size}"));
                r416.headers.set("Content-Type", "text/html; charset=UTF-8");
                r416.headers.set("Accept-Ranges", "bytes");
                if !ec_etag.is_empty() {
                    r416.headers.set("ETag", &ec_etag);
                }
                return r416;
            }
        }
        let byte_range = match resolved_ranges.as_deref() {
            Some([(a, b)]) if *a < *b => Some((*a, *b)),
            _ => None,
        };
        let multi_ranges: Option<Vec<(u64, u64)>> = match resolved_ranges.as_deref() {
            Some(r) if r.len() > 1 => Some(r.to_vec()),
            _ => None,
        };
        if let Some((start, end)) = byte_range {
            resp.status = 206;
            resp.headers.set(
                "Content-Range",
                format!("bytes {start}-{}/{orig_size}", end.saturating_sub(1)),
            );
            resp.headers
                .set("Content-Length", end.saturating_sub(start));
        } else if multi_ranges.is_none() {
            resp.headers.set("Content-Length", orig_size);
        }
        // Conditionals against the reconstructed object, not fragment etags.
        let cond_req = swift_http::Request {
            method: if is_head { "HEAD".into() } else { "GET".into() },
            path: path.to_string(),
            query_string: String::new(),
            headers: cond_headers,
            body: Body::empty(),
        };
        resp = swift_http::apply_conditional(&cond_req, resp);
        if is_head || !(200..300).contains(&resp.status) {
            return resp;
        }
        let driver = match EcDriver::new(ec.ndata, ec.nparity) {
            Ok(d) => d,
            Err(e) => {
                return Response::with_body(500, format!("EC init failed: {e:?}").into_bytes())
            }
        };
        let idle = self.config.node_timeout;
        let mut heads: Vec<AsyncBackendHead> = sources.into_values().take(ec.ndata).collect();
        let seg_sizes = super::ec_segment_sizes(orig_size, ec.segment_size);
        let (skip, take) = byte_range
            .map(|(s, e)| (s, e.saturating_sub(s)))
            .unwrap_or((0, u64::MAX));
        let multipart = if let Some(ranges) = multi_ranges {
            use md5::{Digest, Md5};
            let mut h = Md5::new();
            h.update(ec_etag.as_bytes());
            for (s, e) in &ranges {
                h.update(s.to_le_bytes());
                h.update(e.to_le_bytes());
            }
            let boundary = h
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let mp_len: u64 = {
                let size = orig_size as u64;
                let mut n = format!("--{boundary}--").len() as u64;
                for &(start, stop) in &ranges {
                    n += format!("--{boundary}\r\n").len() as u64;
                    n += format!("Content-Type: {content_type}\r\n").len() as u64;
                    n += format!(
                        "Content-Range: {}\r\n\r\n",
                        swift_http::content_range_header_value(start, stop, size)
                    )
                    .len() as u64;
                    n += stop.saturating_sub(start);
                    n += 2;
                }
                n
            };
            resp.status = 206;
            resp.headers.set(
                "Content-Type",
                swift_http::multipart_byteranges_content_type(&boundary),
            );
            resp.headers.set("Content-Length", mp_len);
            Some((boundary, ranges, content_type.clone(), mp_len))
        } else {
            None
        };
        let response_len = if let Some((_, _, _, mp_len)) = &multipart {
            *mp_len
        } else {
            byte_range
                .map(|(s, e)| e.saturating_sub(s))
                .unwrap_or(orig_size as u64)
        };
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let scope = TaskScope::bounded(1);
        let _ = scope.spawn(async move {
            let mut skipped = 0u64;
            let mut sent = 0u64;
            let mut assembled: Option<Vec<u8>> =
                multipart.as_ref().map(|_| Vec::with_capacity(orig_size));
            for seg_len in seg_sizes {
                if assembled.is_none() && sent >= take {
                    break;
                }
                let frag_len = driver.fragment_size(seg_len);
                let mut frags: Vec<Vec<u8>> = Vec::with_capacity(heads.len());
                for head in &mut heads {
                    match read_exact_from_head(head, frag_len, idle).await {
                        Ok(buf) => frags.push(buf),
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            return;
                        }
                    }
                }
                match driver.decode(&frags) {
                    Ok(mut decoded) => {
                        decoded.truncate(seg_len);
                        if let Some(buf) = assembled.as_mut() {
                            buf.extend_from_slice(&decoded);
                            continue;
                        }
                        let mut slice = decoded;
                        if skipped < skip {
                            let drop = (skip - skipped).min(slice.len() as u64) as usize;
                            skipped += drop as u64;
                            if drop >= slice.len() {
                                continue;
                            }
                            slice = slice[drop..].to_vec();
                        }
                        if sent + slice.len() as u64 > take {
                            slice.truncate((take - sent) as usize);
                        }
                        sent += slice.len() as u64;
                        if tx.send(Ok(slice)).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(std::io::Error::other(format!("EC decode: {e:?}"))))
                            .await;
                        return;
                    }
                }
            }
            if let (Some(buf), Some((boundary, ranges, ctype, _))) = (assembled, multipart) {
                let mp = swift_http::multipart_byteranges(
                    &boundary,
                    &ranges,
                    &buf,
                    &ctype,
                    orig_size as u64,
                );
                let _ = tx.send(Ok(mp)).await;
            }
        });
        resp.body = Body::from_channel(rx, Some(response_len), scope);
        resp
    }

    /// EC object PUT: encode client bytes into fragment archives, MIME-PUT
    /// each fragment with a metadata footer (no multiphase). Hyper object
    /// servers auto-100-continue; we treat any 100 as live.
    pub(crate) async fn ec_put_async(
        self: &Arc<Self>,
        req: &mut swift_http::Request,
        account: &str,
        container: &str,
        _object: &str,
        path: &str,
        policy_index: i64,
        object_ring: &swift_ring::Ring,
        object_part: u32,
        body: &mut IncomingBody,
    ) -> Response {
        #[cfg(not(feature = "ec"))]
        {
            let _ = (
                req,
                account,
                container,
                path,
                policy_index,
                object_ring,
                object_part,
                body,
            );
            return Response::with_body(
                501,
                b"erasure coding not built (compile with --features ec)".to_vec(),
            );
        }
        #[cfg(feature = "ec")]
        {
            self.ec_put_async_inner(
                req,
                account,
                container,
                path,
                policy_index,
                object_ring,
                object_part,
                body,
            )
            .await
        }
    }

    #[cfg(feature = "ec")]
    async fn ec_put_async_inner(
        self: &Arc<Self>,
        req: &mut swift_http::Request,
        account: &str,
        container: &str,
        path: &str,
        policy_index: i64,
        object_ring: &swift_ring::Ring,
        object_part: u32,
        body: &mut IncomingBody,
    ) -> Response {
        use md5::{Digest, Md5};
        use swift_ec::EcDriver;
        let Some(&ec) = self.ec_policies.get(&policy_index) else {
            return swob_response(503);
        };
        let driver = match EcDriver::new(ec.ndata, ec.nparity) {
            Ok(d) => d,
            Err(e) => {
                return Response::with_body(500, format!("EC init failed: {e:?}").into_bytes())
            }
        };
        let n = ec.n_unique();
        let client_len = body.content_length();
        let archive_len =
            client_len.map(|total| super::ec_archive_size(&driver, ec.segment_size, total));
        let put_ts = super::object_write_timestamp(req);
        let ts = put_ts.internal();
        super::apply_content_type_guess(req);
        let content_type = req
            .headers
            .get("Content-Type")
            .unwrap_or("application/octet-stream")
            .to_string();
        let Ok((container_part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return swob_response(503);
        };
        let container_nodes = self.iter_nodes(&self.container_ring, container_part);
        let mut base = self.backend_headers(req, true, "object");
        base.set("X-Timestamp", &ts);
        base.set("Content-Type", &content_type);
        base.set("X-Backend-Storage-Policy-Index", policy_index);
        super::stamp_next_part_power(&mut base, object_ring);
        self.stamp_root_db_state(account, container, &mut base);
        let mut per_node = Vec::with_capacity(n);
        for i in 0..n {
            let mut h = base.clone();
            if !container_nodes.is_empty() {
                let cont = &container_nodes[i % container_nodes.len()];
                h.set("X-Container-Host", format!("{}:{}", cont.ip, cont.port));
                h.set("X-Container-Partition", container_part);
                h.set("X-Container-Device", &cont.device);
            }
            per_node.push(h);
        }
        let boundary = {
            let a = format!("{path}:{ts}:head");
            let b = format!("{path}:{ts}:tail");
            format!(
                "{:x}{:x}",
                Md5::digest(a.as_bytes()),
                Md5::digest(b.as_bytes())
            )
        };
        // Preserve the primary slot as the fragment index. `iter_nodes()` is
        // unsuitable here: it removes error-limited primaries and then a
        // plain enumerate shifts every later fragment index; its `.take(n)`
        // also prevents a failed primary from consuming a handoff. Python's
        // EC putter keeps one slot per primary and fills that same slot from
        // the next handoff when necessary.
        let primaries = ring_nodes(object_ring.get_part_nodes(object_part).unwrap_or_default());
        if primaries.len() != n {
            return Response::with_body(
                500,
                format!("EC ring replica count {} != k+m {}", primaries.len(), n).into_bytes(),
            );
        }
        let mut handoffs: VecDeque<Node> = object_ring
            .get_more_nodes(object_part)
            .map(|more| {
                more.into_iter()
                    .map(|h| Node {
                        ip: h.dev.ip.clone(),
                        port: h.dev.port,
                        device: h.dev.device.clone(),
                        handoff: true,
                        backend_index: None,
                    })
                    .filter(|node| !self.error_limiter.is_limited(node))
                    .collect()
            })
            .unwrap_or_default();
        let mut putters: Vec<AsyncMimePutter> = Vec::new();
        let mut earlies: Vec<u16> = Vec::new();
        let wait = self.config.conn_timeout + self.config.node_timeout;
        let node_timeout = self.config.node_timeout;
        let conn_timeout = self.config.conn_timeout;
        for (i, primary) in primaries.into_iter().enumerate() {
            let mut candidate = Some(primary);
            loop {
                let node = match candidate.take() {
                    Some(node) if !self.error_limiter.is_limited(&node) => node,
                    Some(_) | None => match handoffs.pop_front() {
                        Some(node) => node,
                        None => break,
                    },
                };
                match connect_mime_putter_async(
                    &node,
                    object_part,
                    path,
                    &per_node[i],
                    &boundary,
                    archive_len,
                    conn_timeout,
                    node_timeout,
                )
                .await
                {
                    Ok(AsyncMimeOutcome::Live(mut p)) => {
                        p.frag_index = i;
                        putters.push(p);
                        break;
                    }
                    Ok(AsyncMimeOutcome::EarlyFinal(507)) => {
                        self.error_limiter.limit(&node);
                    }
                    Ok(AsyncMimeOutcome::EarlyFinal(status)) if status >= 500 => {
                        self.error_limiter.increment(&node);
                    }
                    Ok(AsyncMimeOutcome::EarlyFinal(status)) => {
                        earlies.push(status);
                        break;
                    }
                    Err(_) => self.error_limiter.increment(&node),
                }
            }
        }
        if earlies.contains(&412) {
            return swob_response(412);
        }
        if earlies.contains(&409) {
            return swob_response(202);
        }
        // Object-server 4xx on the MIME PUT (If-None-Match not `*`, missing
        // Content-Length, etag mismatch, ENOSPC, …) must surface to the
        // client. Mapping them to 503 made `retry()` spin until timeout.
        if let Some(&client_err) = [400u16, 411, 413, 422, 507]
            .iter()
            .find(|s| earlies.contains(s))
        {
            return swob_response(client_err);
        }
        if putters.len() < ec.write_quorum() {
            return swob_response(503);
        }
        let mut etag_hasher = Md5::new();
        let mut seg_buf: Vec<u8> = Vec::with_capacity(ec.segment_size);
        let mut total: u64 = 0;
        let quorum = ec.write_quorum();
        loop {
            let chunk = match body.next_chunk().await {
                Ok(Some(c)) => c,
                Ok(None) => break,
                Err(e) if swift_http::body_too_large(&e) => return swob_response(413),
                Err(_) => return swob_response(499),
            };
            etag_hasher.update(&chunk);
            total += chunk.len() as u64;
            if total > swift_core::constraints::MAX_FILE_SIZE as u64 {
                return swob_response(413);
            }
            seg_buf.extend_from_slice(&chunk);
            while seg_buf.len() >= ec.segment_size {
                let rest = seg_buf.split_off(ec.segment_size);
                let segment = std::mem::replace(&mut seg_buf, rest);
                if let Err(resp) =
                    tee_ec_segment(&mut putters, &driver, &segment, node_timeout).await
                {
                    return resp;
                }
                if putters.len() < quorum {
                    return swob_response(503);
                }
            }
        }
        if client_len.is_some_and(|declared| declared != total) {
            return swob_response(499);
        }
        if !seg_buf.is_empty() {
            if let Err(resp) = tee_ec_segment(&mut putters, &driver, &seg_buf, node_timeout).await {
                return resp;
            }
        }
        let _ = wait;
        let ec_etag = format!("{:x}", etag_hasher.finalize());
        if let Some(client_etag) = req.headers.get("ETag") {
            let norm = client_etag.trim_matches('"');
            if !norm.is_empty() && !norm.eq_ignore_ascii_case(&ec_etag) {
                let mut resp = swob_response(422);
                resp.headers
                    .set("Last-Modified", swift_http::http_date(put_ts.ceil()));
                return resp;
            }
        }
        let mut successes = 0usize;
        for mut p in putters {
            let footers = serde_json::json!({
                "X-Object-Sysmeta-Ec-Etag": ec_etag,
                "X-Object-Sysmeta-Ec-Content-Length": total.to_string(),
                "X-Backend-Container-Update-Override-Etag": ec_etag,
                "X-Backend-Container-Update-Override-Size": total.to_string(),
                "X-Object-Sysmeta-Ec-Frag-Index": p.frag_index.to_string(),
                "X-Object-Sysmeta-Ec-Scheme": format!("{}+{}", ec.ndata, ec.nparity),
                "X-Object-Sysmeta-Ec-Segment-Size": ec.segment_size.to_string(),
                "Etag": p.frag_md5(),
            })
            .to_string();
            if p.end_of_object_data(&footers).await.is_err() {
                continue;
            }
            match p.read_final(node_timeout).await {
                Ok(status) if (200..300).contains(&status) => successes += 1,
                _ => {}
            }
        }
        if successes >= ec.write_quorum() {
            let mut resp = Response::new(201);
            resp.headers.set("ETag", &ec_etag);
            resp.headers.set("Content-Type", &content_type);
            resp.headers.set("X-Timestamp", &ts);
            resp.headers.set("Content-Length", 0);
            resp.headers
                .set("Last-Modified", swift_http::http_date(put_ts.ceil()));
            resp
        } else {
            swob_response(503)
        }
    }

    pub(crate) async fn object_post_async(
        self: &Arc<Self>,
        req: &mut swift_http::Request,
        account: &str,
        container: &str,
        object: &str,
    ) -> Response {
        if let Err(resp) = super::apply_check_delete_headers(req, Timestamp::now().as_secs_f64()) {
            return resp;
        }
        let header_policy: Option<i64> = req
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|v| v.parse().ok());
        let info = self
            .container_info_for_write_async(account, container)
            .await;
        if !info.exists() {
            return swob_response(404);
        }
        let policy_index: i64 = header_policy.unwrap_or(info.policy_index);
        let Some(object_ring) = self.object_ring_for(policy_index) else {
            return swob_response(503);
        };
        let Ok((object_part, _)) = object_ring.get_nodes(account, Some(container), Some(object))
        else {
            return swob_response(503);
        };
        if let Err(e) = swift_core::constraints::check_metadata(req.headers.iter(), "object") {
            let mut r = Response::with_body(400, e.0);
            r.headers.set("Content-Type", "text/html; charset=UTF-8");
            return r;
        }
        let (upd_account, upd_container) = self
            .resolve_updating_shard_async(account, container, object)
            .await
            .unwrap_or_else(|| (account.to_string(), container.to_string()));
        let Ok((container_part, _)) =
            self.container_ring
                .get_nodes(&upd_account, Some(&upd_container), None)
        else {
            return swob_response(503);
        };
        let mut base = self.backend_headers(req, true, "object");
        base.set("X-Timestamp", super::object_write_timestamp(req).internal());
        base.set("X-Backend-Storage-Policy-Index", policy_index);
        super::stamp_next_part_power(&mut base, object_ring);
        self.stamp_root_db_state(account, container, &mut base);
        super::stamp_shard_container_path(
            &mut base,
            &upd_account,
            &upd_container,
            account,
            container,
        );
        let node_number = object_ring
            .get_part_nodes(object_part)
            .map(|n| n.len())
            .unwrap_or(1);
        let per_node = self.object_container_update_headers(
            &base,
            container_part,
            node_number,
            account,
            container,
            object,
        );
        self.post_object_async(
            object_ring,
            object_part,
            &format!(
                "/{}/{}/{}",
                percent_encode(account),
                percent_encode(container),
                percent_encode(object)
            ),
            &req.query_string,
            per_node,
            node_number,
        )
        .await
    }

    async fn post_object_async(
        self: &Arc<Self>,
        ring: &swift_ring::Ring,
        part: u32,
        path: &str,
        query: &str,
        per_node_headers: Vec<HeaderKeyDict>,
        replica_count: usize,
    ) -> Response {
        let node_pool = Arc::new(Mutex::new(
            self.iter_nodes(ring, part)
                .into_iter()
                .collect::<VecDeque<_>>(),
        ));
        let mut slots = self
            .post_fan_out_async(&node_pool, part, path, query, per_node_headers.clone())
            .await;
        let count_real = |slots: &[Option<BackendResponse>], status: u16| -> usize {
            slots
                .iter()
                .flatten()
                .filter(|r| r.status == status)
                .count()
        };
        let mut quorum = quorum_size(slots.len().max(1) as f64) as usize;
        let found_count = count_real(&slots, 202);
        if found_count > 0 && found_count < quorum {
            quorum = quorum_size(replica_count.max(1) as f64) as usize;
            let extra_requests = count_real(&slots, 404);
            let handoff_nodes: Vec<Node> = {
                let mut pool = node_pool.lock().await;
                let mut taken = Vec::new();
                while taken.len() < extra_requests {
                    match pool.iter().position(|n| n.handoff) {
                        Some(idx) => taken.push(pool.remove(idx).unwrap()),
                        None => break,
                    }
                }
                taken
            };
            if !handoff_nodes.is_empty() {
                let missing_headers: Vec<HeaderKeyDict> = per_node_headers
                    .iter()
                    .zip(slots.iter())
                    .filter(|(_, slot)| !matches!(slot, Some(r) if r.status == 202))
                    .map(|(h, _)| h.clone())
                    .take(handoff_nodes.len())
                    .collect();
                let handoff_pool = Arc::new(Mutex::new(handoff_nodes.into_iter().collect()));
                let handoff_slots = self
                    .post_fan_out_async(&handoff_pool, part, path, query, missing_headers)
                    .await;
                slots.extend(handoff_slots);
            }
        }
        let results: Vec<BackendResponse> = slots
            .into_iter()
            .map(|slot| {
                slot.unwrap_or(BackendResponse {
                    status: 503,
                    reason: "Service Unavailable".to_string(),
                    headers: Vec::new(),
                    body: Vec::new(),
                })
            })
            .collect();
        let resp = self.best_response_with_quorum(&results, quorum);
        post_existence_proof_guard(resp, found_count)
    }

    async fn post_fan_out_async(
        self: &Arc<Self>,
        node_pool: &Arc<Mutex<VecDeque<Node>>>,
        part: u32,
        path: &str,
        query: &str,
        per_node_headers: Vec<HeaderKeyDict>,
    ) -> Vec<Option<BackendResponse>> {
        let slots = per_node_headers.len().max(1);
        let mut group: FanoutGroup<(usize, Option<BackendResponse>)> =
            match FanoutGroup::new(slots, slots) {
                Ok(g) => g,
                Err(_) => return (0..per_node_headers.len()).map(|_| None).collect(),
            };
        for (i, headers) in per_node_headers.into_iter().enumerate() {
            let app = Arc::clone(self);
            let node_pool = Arc::clone(node_pool);
            let path = path.to_string();
            let query = query.to_string();
            let _ = group.spawn(move |tx, cancel| async move {
                loop {
                    if cancel.is_cancelled() {
                        let _ = tx.send((i, None)).await;
                        return;
                    }
                    let node = {
                        let mut pool = node_pool.lock().await;
                        match pool.pop_front() {
                            Some(n) => n,
                            None => {
                                let _ = tx.send((i, None)).await;
                                return;
                            }
                        }
                    };
                    let backend_result = backend_request_async(
                        &node,
                        part,
                        "POST",
                        &path,
                        &query,
                        &headers,
                        &[],
                        app.config.conn_timeout,
                        app.config.node_timeout,
                    )
                    .await;
                    match backend_result {
                        Ok(resp) if resp.status == 507 => app.error_limiter.limit(&node),
                        Ok(resp) if resp.status >= 500 => app.error_limiter.increment(&node),
                        Ok(resp) => {
                            if !(node.handoff
                                && resp.status == 404
                                && resp_header(&resp.headers, "x-backend-timestamp").is_none())
                            {
                                let _ = tx.send((i, Some(resp))).await;
                            } else {
                                continue;
                            }
                            return;
                        }
                        Err(_) => app.error_limiter.increment(&node),
                    }
                }
            });
        }
        let expected = group.spawned();
        let wait = self.config.conn_timeout + self.config.node_timeout;
        let mut out: Vec<Option<BackendResponse>> = (0..expected).map(|_| None).collect();
        for _ in 0..expected {
            match tokio::time::timeout(wait, group.recv()).await {
                Ok(Some((i, resp))) if i < out.len() => out[i] = resp,
                _ => {}
            }
        }
        group.cancel_unused();
        group.join().await;
        out
    }

    pub(crate) async fn account_get_head_async(
        self: &Arc<Self>,
        req: swift_http::Request,
        account: &str,
    ) -> Response {
        let Ok((part, _)) = self.account_ring.get_nodes(account, None, None) else {
            return swob_response(503);
        };
        let path = format!("/{}", percent_encode(account));
        let method = req.method.clone();
        let query = req.query_string.clone();
        let headers = self.backend_headers(&req, false, "account");
        let nodes = self.iter_nodes(&self.account_ring, part);
        match self
            .get_or_head_async("account", nodes, part, &method, &path, &query, &headers)
            .await
        {
            Some(resp) if resp.status == 404 && self.config.account_autocreate => {
                let mut fake = super::synthesized_account_listing(&req);
                fake.headers.set(
                    "X-Backend-Recheck-Account-Existence",
                    format!("{}", self.config.recheck_account_existence as i64),
                );
                self.cache_account_from_response(account, &fake);
                fake
            }
            Some(resp) => resp,
            None => swob_response(503),
        }
    }

    pub(crate) async fn container_get_head_async(
        self: &Arc<Self>,
        req: swift_http::Request,
        account: &str,
        container: &str,
    ) -> Response {
        let Ok((container_part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return swob_response(503);
        };
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        // Python `validate_container_params` (probe test_sharding_listing
        // delimiter=%ff → 400 "not valid UTF-8").
        if let Some(name) = swift_http::listing_query_invalid_utf8_param(&req.query_string) {
            let mut resp = Response::with_body(
                400,
                format!("\"{name}\" parameter not valid UTF-8").into_bytes(),
            );
            resp.headers.set("Content-Type", "text/plain");
            return resp;
        }
        if let Err(resp) = super::constrain_listing_limit(&req) {
            return resp;
        }
        let record_type = req
            .headers
            .get("X-Backend-Record-Type")
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_head = req.method == "HEAD";
        if record_type != "object"
            && record_type != "shard"
            && !req.query_string.contains("states=")
        {
            if let Some(mut fan) = self
                .maybe_sharded_container_listing_async(req.clone_head(), account, container)
                .await
            {
                if is_head {
                    let count = fan
                        .headers
                        .get("X-Container-Object-Count")
                        .unwrap_or("0")
                        .to_string();
                    let bytes = fan
                        .headers
                        .get("X-Container-Bytes-Used")
                        .unwrap_or("0")
                        .to_string();
                    fan.status = 204;
                    fan.body = Body::empty();
                    fan.headers.set("Content-Length", "0");
                    fan.headers.set("X-Container-Object-Count", count);
                    fan.headers.set("X-Container-Bytes-Used", bytes);
                }
                super::finalize_container_listing_headers(&req, &mut fan);
                return fan;
            }
        }
        let method = req.method.clone();
        let query = req.query_string.clone();
        let headers = self.backend_headers(&req, false, "container");
        let nodes = self.iter_nodes(&self.container_ring, container_part);
        let mut resp = self
            .get_or_head_async(
                "container",
                nodes,
                container_part,
                &method,
                &path,
                &query,
                &headers,
            )
            .await
            .unwrap_or_else(|| swob_response(503));
        if (200..300).contains(&resp.status) {
            if let Some(name) = resp
                .headers
                .get("X-Backend-Storage-Policy-Index")
                .and_then(|v| v.parse::<i64>().ok())
                .and_then(|idx| self.policy_index_to_name.get(&idx))
            {
                resp.headers.set("X-Storage-Policy", name);
            }
            stamp_container_last_modified(&mut resp);
        }
        super::finalize_container_listing_headers(&req, &mut resp);
        resp
    }

    pub(crate) async fn make_write_async(
        self: &Arc<Self>,
        nodes: Vec<Node>,
        node_number: usize,
        part: u32,
        method: &str,
        path: &str,
        query: &str,
        per_node: Vec<HeaderKeyDict>,
    ) -> Response {
        // Account/container PUT/DELETE (and object DELETE) stamp the
        // next-ring side channel on every replica. Do not cancel at quorum.
        self.make_requests_async_drain(
            nodes,
            node_number,
            part,
            method,
            path,
            query,
            per_node,
            Vec::new(),
            QuorumDrain::PostQuorumTimeout,
        )
        .await
    }

    pub(crate) async fn account_post_async(
        self: &Arc<Self>,
        req: swift_http::Request,
        account: &str,
    ) -> Response {
        // Python account.py POST is always allowed; allow_account_management
        // only removes PUT/DELETE from the method set.
        if let Err(e) = swift_core::constraints::check_metadata(req.headers.iter(), "account") {
            let mut r = Response::with_body(400, e.0);
            r.headers.set("Content-Type", "text/plain");
            return r;
        }
        let Ok((part, _)) = self.account_ring.get_nodes(account, None, None) else {
            return swob_response(503);
        };
        self.info_cache.clear_account(account);
        let mut headers = self.backend_headers(&req, true, "account");
        headers.set("X-Timestamp", Timestamp::now().internal());
        let node_count = self
            .account_ring
            .get_part_nodes(part)
            .map(|n| n.len())
            .unwrap_or(1);
        let nodes = self.iter_nodes(&self.account_ring, part);
        let per_node: Vec<HeaderKeyDict> = (0..node_count).map(|_| headers.clone()).collect();
        let path = format!("/{}", percent_encode(account));
        let method = req.method.clone();
        let query = req.query_string.clone();
        let resp = self
            .make_write_async(
                nodes,
                node_count,
                part,
                &method,
                &path,
                &query,
                per_node.clone(),
            )
            .await;
        if resp.status == 404 && self.config.account_autocreate {
            let _ = self.autocreate_account(account);
            let nodes = self.iter_nodes(&self.account_ring, part);
            return self
                .make_write_async(nodes, node_count, part, &method, &path, &query, per_node)
                .await;
        }
        resp
    }

    pub(crate) async fn container_post_async(
        self: &Arc<Self>,
        req: swift_http::Request,
        account: &str,
        container: &str,
    ) -> Response {
        if let Err(e) = swift_core::constraints::check_metadata(req.headers.iter(), "container") {
            let mut r = Response::with_body(400, e.0);
            r.headers.set("Content-Type", "text/plain");
            return r;
        }
        let Ok((container_part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return swob_response(503);
        };
        let acct_status = self.account_info_async(account).await;
        if !acct_status.exists() {
            return swob_response(404);
        }
        let mut base = self.backend_headers(&req, true, "container");
        base.set("X-Timestamp", Timestamp::now().internal());
        let node_number = self
            .container_ring
            .get_part_nodes(container_part)
            .map(|n| n.len())
            .unwrap_or(1);
        let per_node: Vec<HeaderKeyDict> = (0..node_number).map(|_| base.clone()).collect();
        let cache_key = format!("{account}/{container}");
        self.info_cache.clear_container_metadata(&cache_key);
        let cont_nodes = self.iter_nodes(&self.container_ring, container_part);
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        let method = req.method.clone();
        let query = req.query_string.clone();
        self.make_write_async(
            cont_nodes,
            node_number,
            container_part,
            &method,
            &path,
            &query,
            per_node,
        )
        .await
    }

    /// Async counterpart of Python's private `ContainerController.UPDATE`.
    /// The public/private method gate and authorization override are enforced
    /// by `ProxyApp::handle_async`; this function only performs the bounded
    /// container-ring fan-out of the supplied JSON merge body.
    pub(crate) async fn container_update_async(
        self: &Arc<Self>,
        mut req: swift_http::Request,
        account: &str,
        container: &str,
    ) -> Response {
        let Some(policy_index) = req
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|value| value.parse::<i64>().ok())
        else {
            return Response::error(400, "Missing or invalid X-Backend-Storage-Policy-Index");
        };
        let body = match req.body.materialize(swift_http::MAX_CONTROL_BODY) {
            Ok(bytes) => bytes.to_vec(),
            Err(error) if swift_http::body_too_large(&error) => {
                return Response::error(413, "Your request is too large.")
            }
            Err(_) => return swob_response(499),
        };
        let Ok((part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return swob_response(503);
        };
        let mut headers = self.backend_headers(&req, true, "container");
        headers.set("X-Backend-Storage-Policy-Index", policy_index);
        if !headers.contains_key("X-Timestamp") {
            headers.set("X-Timestamp", Timestamp::now().internal());
        }
        let node_count = self
            .container_ring
            .get_part_nodes(part)
            .map(|nodes| nodes.len())
            .unwrap_or(1);
        let per_node = (0..node_count).map(|_| headers.clone()).collect();
        self.make_requests_async(
            self.iter_nodes(&self.container_ring, part),
            node_count,
            part,
            "UPDATE",
            &format!("/{}/{}", percent_encode(account), percent_encode(container)),
            &req.query_string,
            per_node,
            body,
        )
        .await
    }

    pub(crate) async fn container_put_async(
        self: &Arc<Self>,
        req: swift_http::Request,
        account: &str,
        container: &str,
    ) -> Response {
        if let Err(e) = swift_core::constraints::check_metadata(req.headers.iter(), "container") {
            let mut r = Response::with_body(400, e.0);
            r.headers.set("Content-Type", "text/plain");
            return r;
        }
        let Ok((container_part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return swob_response(503);
        };
        let Ok((account_part, _)) = self.account_ring.get_nodes(account, None, None) else {
            return swob_response(503);
        };
        let acct_status = self.account_info_async(account).await;
        if !acct_status.exists() {
            if self.config.account_autocreate {
                if !self.autocreate_account(account) {
                    return swob_response(503);
                }
                let refreshed = self.account_info_async(account).await;
                if !refreshed.exists() {
                    return swob_response(404);
                }
            } else {
                return swob_response(404);
            }
        }
        let mut base = self.backend_headers(&req, true, "container");
        base.set("X-Timestamp", Timestamp::now().internal());
        base.set(
            "X-Backend-Storage-Policy-Default",
            self.config.default_policy_index,
        );
        if let Some(name) = req.headers.get("X-Storage-Policy") {
            if !name.trim().is_empty() {
                match self.policy_name_to_index.get(&name.to_lowercase()) {
                    Some(&idx) => base.set("X-Backend-Storage-Policy-Index", idx),
                    None => return swob_response(400),
                }
            }
        }
        let (node_number, per_node) =
            self.container_write_headers(&base, container_part, account_part, true);
        let cache_key = format!("{account}/{container}");
        let cont_nodes = self.iter_nodes(&self.container_ring, container_part);
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        let query = req.query_string.clone();
        let resp = self
            .make_write_async(
                cont_nodes,
                node_number,
                container_part,
                "PUT",
                &path,
                &query,
                per_node,
            )
            .await;
        self.info_cache.clear_container(&cache_key);
        resp
    }

    pub(crate) async fn account_put_async(
        self: &Arc<Self>,
        req: swift_http::Request,
        account: &str,
    ) -> Response {
        if !self.config.allow_account_management {
            return swob_response(405);
        }
        let Ok((part, _)) = self.account_ring.get_nodes(account, None, None) else {
            return swob_response(503);
        };
        self.info_cache.clear_account(account);
        let mut headers = self.backend_headers(&req, true, "account");
        headers.set("X-Timestamp", Timestamp::now().internal());
        let node_count = self
            .account_ring
            .get_part_nodes(part)
            .map(|n| n.len())
            .unwrap_or(1);
        let nodes = self.iter_nodes(&self.account_ring, part);
        let per_node: Vec<HeaderKeyDict> = (0..node_count).map(|_| headers.clone()).collect();
        let path = format!("/{}", percent_encode(account));
        let query = req.query_string.clone();
        self.make_write_async(nodes, node_count, part, "PUT", &path, &query, per_node)
            .await
    }

    async fn fetch_json_array_first_nonempty_async(
        self: &Arc<Self>,
        nodes: &[Node],
        part: u32,
        path: &str,
        query: &str,
        headers: &HeaderKeyDict,
    ) -> Option<Vec<serde_json::Value>> {
        // Shard-range fetch: first nonempty array, never union (L1306).
        let mut last_empty: Option<Vec<serde_json::Value>> = None;
        for node in nodes {
            let Some(resp) = self
                .get_or_head_async(
                    "container",
                    vec![node.clone()],
                    part,
                    "GET",
                    path,
                    query,
                    headers,
                )
                .await
            else {
                continue;
            };
            if !(200..300).contains(&resp.status) {
                continue;
            }
            let body = match resp.body.collect_async().await {
                Ok(b) => b,
                Err(_) => continue,
            };
            let val: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let arr = val.as_array().cloned().unwrap_or_default();
            if !arr.is_empty() {
                return Some(arr);
            }
            last_empty = Some(arr);
        }
        last_empty
    }

    async fn fetch_json_array_merged_async(
        self: &Arc<Self>,
        nodes: &[Node],
        part: u32,
        path: &str,
        query: &str,
        headers: &HeaderKeyDict,
        empty_wins: bool,
    ) -> Option<Vec<serde_json::Value>> {
        // Always walk replicas. Unsettled union (L1321 extra PUTs); settled
        // empty-wins (L1418). 404 is not empty.
        // Do not short-circuit on X-Newest (listing-w151 UTF8 L692 FAIL).
        let mut replies: Vec<Option<Vec<serde_json::Value>>> = Vec::new();
        let mut timestamps: Vec<swift_core::timestamp::Timestamp> = Vec::new();
        for node in nodes {
            let Some(resp) = self
                .get_or_head_async(
                    "container",
                    vec![node.clone()],
                    part,
                    "GET",
                    path,
                    query,
                    headers,
                )
                .await
            else {
                replies.push(None);
                timestamps.push(swift_core::timestamp::Timestamp::zero());
                continue;
            };
            if !(200..300).contains(&resp.status) {
                replies.push(None);
                timestamps.push(swift_core::timestamp::Timestamp::zero());
                continue;
            }
            let ts = super::listing_resp_timestamp(&resp.headers);
            let body = match resp.body.collect_async().await {
                Ok(b) => b,
                Err(_) => {
                    replies.push(None);
                    timestamps.push(swift_core::timestamp::Timestamp::zero());
                    continue;
                }
            };
            if resp.status == 204 || body.is_empty() {
                replies.push(Some(Vec::new()));
                timestamps.push(ts);
                continue;
            }
            let val: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => {
                    replies.push(None);
                    timestamps.push(swift_core::timestamp::Timestamp::zero());
                    continue;
                }
            };
            let arr = val.as_array().cloned().unwrap_or_default();
            replies.push(Some(arr));
            timestamps.push(ts);
        }
        super::fold_replica_listings_dated(&replies, empty_wins, &timestamps)
    }

    async fn fetch_json_arrays_nonempty_async(
        self: &Arc<Self>,
        nodes: &[Node],
        part: u32,
        path: &str,
        query: &str,
        headers: &HeaderKeyDict,
    ) -> Vec<Vec<serde_json::Value>> {
        let mut arrays: Vec<Vec<serde_json::Value>> = Vec::new();
        for node in nodes {
            let Some(resp) = self
                .get_or_head_async(
                    "container",
                    vec![node.clone()],
                    part,
                    "GET",
                    path,
                    query,
                    headers,
                )
                .await
            else {
                continue;
            };
            if !(200..300).contains(&resp.status) {
                continue;
            }
            let body = match resp.body.collect_async().await {
                Ok(b) => b,
                Err(_) => continue,
            };
            if resp.status == 204 || body.is_empty() {
                continue;
            }
            let val: serde_json::Value = match serde_json::from_slice(&body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let arr = val.as_array().cloned().unwrap_or_default();
            if !arr.is_empty() {
                arrays.push(arr);
            }
        }
        arrays
    }

    async fn fetch_json_array_longest_nonempty_async(
        self: &Arc<Self>,
        nodes: &[Node],
        part: u32,
        path: &str,
        query: &str,
        headers: &HeaderKeyDict,
    ) -> Option<Vec<serde_json::Value>> {
        super::prefer_longest_nonempty_arrays(
            &self
                .fetch_json_arrays_nonempty_async(nodes, part, path, query, headers)
                .await,
        )
    }

    async fn fetch_listing_shard_ranges_async(
        self: &Arc<Self>,
        nodes: Vec<Node>,
        part: u32,
        path: &str,
        shard_headers: &HeaderKeyDict,
    ) -> Option<Vec<serde_json::Value>> {
        if let Some(arr) = super::prefer_quorum_consistent_listing_arrays(
            &self
                .fetch_json_arrays_nonempty_async(
                    &nodes,
                    part,
                    path,
                    "states=listing&format=json",
                    shard_headers,
                )
                .await,
        ) {
            if !arr.is_empty() {
                return Some(arr);
            }
        }
        let broad = super::prefer_quorum_consistent_listing_arrays(
            &self
                .fetch_json_arrays_nonempty_async(&nodes, part, path, "format=json", shard_headers)
                .await,
        )?;
        Some(super::prefer_listing_state_ranges(&broad))
    }

    pub(crate) async fn maybe_sharded_container_listing_async(
        self: &Arc<Self>,
        req: swift_http::Request,
        account: &str,
        container: &str,
    ) -> Option<Response> {
        let marker = req.param("marker").unwrap_or_default();
        let end_marker = req.param("end_marker").unwrap_or_default();
        let prefix = req.param("prefix").unwrap_or_default();
        let delimiter = req.param("delimiter").unwrap_or_default();
        let reverse = config_true_value(req.param("reverse").as_deref().unwrap_or(""));
        let limit: usize = req
            .param("limit")
            .and_then(|v| v.parse().ok())
            .unwrap_or(10000);
        let head_headers = self.backend_headers(&req, false, "container");
        let mut shard_headers = self.backend_headers(&req, false, "container");
        shard_headers.set("X-Backend-Record-Type", "shard");
        shard_headers.set("X-Backend-Allow-Reserved-Names", "true");
        let mut root_headers = self.backend_headers(&req, false, "container");
        root_headers.set("X-Backend-Record-Type", "object");
        let mut listing_headers = self.backend_headers(&req, false, "container");
        listing_headers.set("X-Backend-Allow-Reserved-Names", "true");
        listing_headers.set("X-Backend-Record-Type", "object");
        let Ok((part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return None;
        };
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        let nodes = self.iter_nodes(&self.container_ring, part);
        let mut head = self
            .get_or_head_async(
                "container",
                nodes.clone(),
                part,
                "HEAD",
                &path,
                "",
                &head_headers,
            )
            .await?;
        if !(200..300).contains(&head.status) {
            return None;
        }
        // The root container's current policy selects which object rows a
        // shard container returns. Preserve an explicit trusted backend
        // override, otherwise forward the policy learned from root HEAD.
        if !listing_headers.contains_key("X-Backend-Storage-Policy-Index") {
            if let Some(policy_index) = head
                .headers
                .get("X-Backend-Storage-Policy-Index")
                .map(str::to_string)
            {
                listing_headers.set("X-Backend-Storage-Policy-Index", policy_index);
            }
        }
        // Python HEAD uses root `get_shard_usage` (ACTIVE/SHARDING/SHRINKING
        // range stats). Max of replica HEAD counts is wrong on the way down:
        // after reclaim PUT_shard, lagging replicas still say 100 and
        // `best=max` fails probe L1979 (`51 != 100`).
        if req.method.eq_ignore_ascii_case("HEAD") {
            let arrays = self
                .fetch_json_arrays_nonempty_async(
                    &nodes,
                    part,
                    &path,
                    "states=listing&format=json",
                    &shard_headers,
                )
                .await;
            if let Some((usage_count, usage_bytes)) = super::lowest_shard_usage(&arrays) {
                head.headers
                    .set("X-Container-Object-Count", usage_count.to_string());
                head.headers
                    .set("X-Container-Bytes-Used", usage_bytes.to_string());
            }
        }
        let state = head
            .headers
            .get("X-Backend-Sharding-State")
            .unwrap_or("unsharded")
            .to_ascii_lowercase();
        let object_count = head
            .headers
            .get("X-Container-Object-Count")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        if req.method.eq_ignore_ascii_case("HEAD") {
            // Python HEAD is `_GETorHEAD_from_backend`, not listing fan-out.
            // Rebuilding from the listing dropped X-Container-Meta-*
            // (probe test_sharding_listing L613 assert_container_post_ok).
            head.status = 204;
            head.body = swift_http::Body::empty();
            head.headers.set("Content-Length", "0");
            if let Some(name) = head
                .headers
                .get("X-Backend-Storage-Policy-Index")
                .and_then(|v| v.parse::<i64>().ok())
                .and_then(|idx| self.policy_index_to_name.get(&idx))
            {
                head.headers.set("X-Storage-Policy", name.clone());
            }
            stamp_container_last_modified(&mut head);
            return Some(head);
        }
        let arr = self
            .fetch_listing_shard_ranges_async(nodes.clone(), part, &path, &shard_headers)
            .await
            .unwrap_or_default();
        if !super::should_fanout_sharded_listing(&state, object_count, !arr.is_empty()) {
            if !super::should_fold_root_objects_without_ranges(&state) {
                return None;
            }
            let qs_parts = super::shard_listing_query_parts(
                &marker,
                &end_marker,
                &prefix,
                &delimiter,
                reverse,
                limit,
            );
            let mut scored: Vec<(i64, bool, Node)> = Vec::new();
            for node in &nodes {
                let Some(h) = self
                    .get_or_head_async(
                        "container",
                        vec![node.clone()],
                        part,
                        "HEAD",
                        &path,
                        "",
                        &head_headers,
                    )
                    .await
                else {
                    continue;
                };
                if !(200..300).contains(&h.status) {
                    continue;
                }
                let st = h
                    .headers
                    .get("X-Backend-Sharding-State")
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let oc = h
                    .headers
                    .get("X-Container-Object-Count")
                    .and_then(|v| v.parse::<i64>().ok())
                    .unwrap_or(0);
                scored.push((oc, st == "collapsed", node.clone()));
            }
            scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
            let order: Vec<Node> = if scored.is_empty() {
                nodes.clone()
            } else {
                scored.into_iter().map(|(_, _, n)| n).collect()
            };
            let qs_plain = "format=json";
            let qs_full = qs_parts.join("&");
            let items = match self
                .fetch_json_array_first_nonempty_async(&order, part, &path, qs_plain, &root_headers)
                .await
            {
                Some(a) if !a.is_empty() => a,
                _ => match self
                    .fetch_json_array_first_nonempty_async(
                        &order,
                        part,
                        &path,
                        &qs_full,
                        &root_headers,
                    )
                    .await
                {
                    Some(a) if !a.is_empty() => a,
                    _ => {
                        self.fetch_json_array_merged_async(
                            &order,
                            part,
                            &path,
                            qs_plain,
                            &root_headers,
                            false,
                        )
                        .await?
                    }
                },
            };
            let bytes = serde_json::to_vec(&items).unwrap_or_else(|_| b"[]".to_vec());
            let mut out = Response::with_body(200, bytes);
            out.headers
                .set("Content-Type", "application/json; charset=utf-8");
            out.headers.set("X-Backend-Sharding-State", state);
            out.headers.set("X-Backend-Record-Type", "object");
            super::stamp_sharded_listing_stats(
                &mut out,
                &head,
                &items,
                &marker,
                &end_marker,
                &prefix,
                &delimiter,
                limit,
            );
            if let Some(name) = head
                .headers
                .get("X-Backend-Storage-Policy-Index")
                .and_then(|v| v.parse::<i64>().ok())
                .and_then(|idx| self.policy_index_to_name.get(&idx))
            {
                out.headers.set("X-Storage-Policy", name);
            }
            super::copy_root_listing_headers(&head, &mut out);
            return Some(out);
        }
        let selected =
            super::select_listing_shard_ranges(&arr, &marker, &end_marker, &prefix, reverse);
        let all_ranges: Vec<&serde_json::Value> = arr.iter().collect();
        let root_path = format!("{account}/{container}");
        if state == "sharded" || super::listing_ranges_prove_sharded(&all_ranges, &root_path) {
            self.remember_proven_container_db_state(account, container, "sharded");
        }
        let empty_wins = super::listing_ranges_are_settled_active(&all_ranges);
        let mut feeds: Vec<super::ListingFeed> = Vec::new();
        let newest = req
            .headers
            .get("X-Newest")
            .map(config_true_value)
            .unwrap_or(false);
        // Residual: SHARDING always (L1483). SHARDED only with X-Newest so a
        // just-cleaved replica's retiring rows appear (L1517) without a
        // lagging replica resurrecting L692 leftovers.
        let has_shrinking = all_ranges
            .iter()
            .any(|sr| sr.get("state").and_then(|v| v.as_i64()).unwrap_or(0) == 50);
        if super::include_root_residual_for_listing_ex(
            &state,
            newest,
            empty_wins,
            has_shrinking,
            !arr.is_empty(),
            super::listing_has_full_active_cover(&all_ranges),
            super::listing_has_full_shrinking_cover(&all_ranges),
        ) {
            let qs_parts = super::shard_listing_query_parts(
                &marker,
                &end_marker,
                &prefix,
                &delimiter,
                reverse,
                limit,
            );
            let qs = qs_parts.join("&");
            let items = if newest {
                if let Some(resp) = self
                    .get_or_head_async(
                        "container",
                        nodes.clone(),
                        part,
                        "GET",
                        &path,
                        &qs,
                        &root_headers,
                    )
                    .await
                {
                    if (200..300).contains(&resp.status) {
                        let body = resp.body.collect_async().await.ok().unwrap_or_default();
                        if resp.status == 204 || body.is_empty() {
                            Some(Vec::new())
                        } else {
                            serde_json::from_slice::<serde_json::Value>(&body)
                                .ok()
                                .map(|v| v.as_array().cloned().unwrap_or_default())
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                self.fetch_json_array_first_nonempty_async(&nodes, part, &path, &qs, &root_headers)
                    .await
            };
            if let Some(items) = items {
                if !items.is_empty() {
                    feeds.push(super::ListingFeed {
                        lower: String::new(),
                        upper: String::new(),
                        timestamp: String::new(),
                        items,
                    });
                }
            }
        }
        for sr in &selected {
            let name = sr.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let (shard_account, shard_container) = match name.split_once('/') {
                Some((a, c)) => (a, c),
                None => continue,
            };
            if shard_account == account && shard_container == container {
                continue;
            }
            let Ok((spart, _)) =
                self.container_ring
                    .get_nodes(shard_account, Some(shard_container), None)
            else {
                continue;
            };
            let spath = format!(
                "/{}/{}",
                percent_encode(shard_account),
                percent_encode(shard_container)
            );
            let snodes = self.iter_nodes(&self.container_ring, spart);
            let mut qs_parts = super::shard_listing_query_parts(
                &marker,
                &end_marker,
                &prefix,
                &delimiter,
                reverse,
                limit,
            );
            if empty_wins {
                qs_parts.retain(|p| !p.starts_with("limit="));
            }
            let Some(items) = self
                .fetch_json_array_merged_async(
                    &snodes,
                    spart,
                    &spath,
                    &qs_parts.join("&"),
                    &listing_headers,
                    empty_wins,
                )
                .await
            else {
                continue;
            };
            if items.is_empty() && !empty_wins {
                continue;
            }
            feeds.push(super::ListingFeed {
                lower: sr
                    .get("lower")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                upper: sr
                    .get("upper")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                timestamp: super::listing_feed_timestamp(sr),
                items,
            });
        }
        let merged = super::merge_listings_newest_covering(&feeds, limit, reverse);
        let bytes = serde_json::to_vec(&merged).unwrap_or_else(|_| b"[]".to_vec());
        let mut out = Response::with_body(200, bytes);
        out.headers
            .set("Content-Type", "application/json; charset=utf-8");
        out.headers.set("X-Backend-Sharding-State", state);
        out.headers.set("X-Backend-Record-Type", "object");
        // GET listing: count matches the returned listing (Python GET after
        // extra PUTs is 200). HEAD: keep the root's stale count until sharders
        // update it (Python HEAD is still 100). Mixing these fails
        // `_test_sharded_listing` either at listing or at HEAD.
        if req.method.eq_ignore_ascii_case("HEAD") {
            if let Some(c) = head
                .headers
                .get("X-Container-Object-Count")
                .filter(|s| !s.is_empty())
            {
                out.headers.set("X-Container-Object-Count", c);
            } else {
                out.headers
                    .set("X-Container-Object-Count", merged.len().to_string());
            }
            if let Some(bytes_used) = head.headers.get("X-Container-Bytes-Used") {
                out.headers.set("X-Container-Bytes-Used", bytes_used);
            }
        } else {
            super::stamp_sharded_listing_stats(
                &mut out,
                &head,
                &merged,
                &marker,
                &end_marker,
                &prefix,
                &delimiter,
                limit,
            );
        }
        super::copy_root_listing_headers(&head, &mut out);
        stamp_container_last_modified(&mut out);
        if let Some(name) = head
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|v| v.parse::<i64>().ok())
            .and_then(|idx| self.policy_index_to_name.get(&idx))
        {
            out.headers.set("X-Storage-Policy", name);
        }
        Some(out)
    }

    pub(crate) async fn object_delete_async(
        self: &Arc<Self>,
        req: &mut swift_http::Request,
        account: &str,
        container: &str,
        object: &str,
    ) -> Response {
        let header_policy: Option<i64> = req
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|v| v.parse().ok());
        let info = self
            .container_info_for_write_async(account, container)
            .await;
        if !info.exists() {
            return swob_response(404);
        }
        let policy_index: i64 = header_policy.unwrap_or(info.policy_index);
        let Some(object_ring) = self.object_ring_for(policy_index) else {
            return swob_response(503);
        };
        let Ok((object_part, _)) = object_ring.get_nodes(account, Some(container), Some(object))
        else {
            return swob_response(503);
        };
        let (upd_account, upd_container) = self
            .resolve_updating_shard_async(account, container, object)
            .await
            .unwrap_or_else(|| (account.to_string(), container.to_string()));
        let Ok((container_part, _)) =
            self.container_ring
                .get_nodes(&upd_account, Some(&upd_container), None)
        else {
            return swob_response(503);
        };
        let mut base = self.backend_headers(req, true, "object");
        base.set("X-Timestamp", super::object_write_timestamp(req).internal());
        base.set("X-Backend-Storage-Policy-Index", policy_index);
        super::stamp_next_part_power(&mut base, object_ring);
        self.stamp_root_db_state(account, container, &mut base);
        super::stamp_shard_container_path(
            &mut base,
            &upd_account,
            &upd_container,
            account,
            container,
        );
        let node_number = object_ring
            .get_part_nodes(object_part)
            .map(|n| n.len())
            .unwrap_or(1);
        let per_node = self.object_container_update_headers(
            &base,
            container_part,
            node_number,
            account,
            container,
            object,
        );
        let object_nodes = self.iter_nodes(object_ring, object_part);
        let path = format!(
            "/{}/{}/{}",
            percent_encode(account),
            percent_encode(container),
            percent_encode(object)
        );
        self.make_write_async(
            object_nodes,
            node_number,
            object_part,
            "DELETE",
            &path,
            &req.query_string,
            per_node,
        )
        .await
    }

    pub(crate) async fn container_delete_async(
        self: &Arc<Self>,
        req: swift_http::Request,
        account: &str,
        container: &str,
    ) -> Response {
        let Ok((container_part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return swob_response(503);
        };
        let Ok((account_part, _)) = self.account_ring.get_nodes(account, None, None) else {
            return swob_response(503);
        };
        let acct_status = self.account_info_async(account).await;
        if !acct_status.exists() {
            return swob_response(404);
        }
        let mut base = self.backend_headers(&req, true, "container");
        base.set("X-Timestamp", Timestamp::now().internal());
        let (node_number, per_node) =
            self.container_write_headers(&base, container_part, account_part, true);
        let cache_key = format!("{account}/{container}");
        self.info_cache.clear_container(&cache_key);
        let cont_nodes = self.iter_nodes(&self.container_ring, container_part);
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        let query = req.query_string.clone();
        self.make_write_async(
            cont_nodes,
            node_number,
            container_part,
            "DELETE",
            &path,
            &query,
            per_node,
        )
        .await
    }

    pub(crate) async fn account_delete_async(
        self: &Arc<Self>,
        req: swift_http::Request,
        account: &str,
    ) -> Response {
        if !self.config.allow_account_management {
            return swob_response(405);
        }
        let Ok((part, _)) = self.account_ring.get_nodes(account, None, None) else {
            return swob_response(503);
        };
        self.info_cache.clear_account(account);
        let mut headers = self.backend_headers(&req, true, "account");
        headers.set("X-Timestamp", Timestamp::now().internal());
        let node_count = self
            .account_ring
            .get_part_nodes(part)
            .map(|n| n.len())
            .unwrap_or(1);
        let nodes = self.iter_nodes(&self.account_ring, part);
        let per_node: Vec<HeaderKeyDict> = (0..node_count).map(|_| headers.clone()).collect();
        let path = format!("/{}", percent_encode(account));
        let query = req.query_string.clone();
        self.make_write_async(nodes, node_count, part, "DELETE", &path, &query, per_node)
            .await
    }

    /// Server-side copy (`copy.py` do_copy): GET source then stream PUT dest.
    /// The object is never materialized.
    pub(crate) async fn object_copy_async(
        self: &Arc<Self>,
        mut req: swift_http::Request,
        dst_account: &str,
        dst_container: &str,
        dst_object: &str,
    ) -> Response {
        let copy_from = req.headers.get("X-Copy-From").unwrap_or("").to_string();
        let Some((src_container, src_object)) = parse_copy_from(&copy_from) else {
            return Response::error(
                412,
                "X-Copy-From header must be of the form /container/object",
            );
        };
        let src_account = req
            .headers
            .get("X-Copy-From-Account")
            .map(|s| s.to_string())
            .unwrap_or_else(|| dst_account.to_string());
        let fresh_metadata = req
            .headers
            .get("X-Fresh-Metadata")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let mut get_req = swift_http::Request {
            method: "GET".into(),
            path: format!("/v1/{}/{}/{}", src_account, src_container, src_object),
            // Python copy.py `req.copy_get()` keeps `?symlink=get`.
            query_string: req.query_string.clone(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        get_req.headers.set("X-Newest", "true");
        for h in [
            "X-Backend-Remote-User",
            "Referer",
            "Range",
            "If-Match",
            "If-None-Match",
            "If-Modified-Since",
            "If-Unmodified-Since",
        ] {
            if let Some(v) = req.headers.get(h) {
                get_req.headers.set(h, v.to_string());
            }
        }
        if let Some(denied) = self.authorize(
            &mut get_req,
            &src_account,
            Some(&src_container),
            Some(&src_object),
        ) {
            return denied;
        }
        let mut source = self
            .object_get_head_async(&mut get_req, &src_account, &src_container, &src_object)
            .await;
        if !(200..300).contains(&source.status) {
            return source;
        }
        let mut put_headers = HeaderKeyDict::new();
        if !fresh_metadata {
            for (k, v) in source.headers.iter() {
                if is_copied_source_header(k) {
                    put_headers.set(k, v);
                }
            }
        }
        for (k, v) in req.headers.iter() {
            let lk = k.to_ascii_lowercase();
            if lk == "x-copy-from"
                || lk == "x-copy-from-account"
                || lk == "x-fresh-metadata"
                || lk == "content-length"
            {
                continue;
            }
            put_headers.set(k, v);
        }
        if let Some(len) = source.body.content_length() {
            put_headers.set("Content-Length", len.to_string());
        }
        put_headers.set("X-Copied-From", format!("{src_container}/{src_object}"));
        put_headers.set("X-Copied-From-Account", src_account.clone());
        req.method = "PUT".into();
        req.headers = put_headers;
        let mut incoming = body_to_incoming(source.body.take());
        let mut resp = self
            .object_put_async(
                &mut req,
                dst_account,
                dst_container,
                dst_object,
                &mut incoming,
            )
            .await;
        resp.headers
            .set("X-Copied-From", format!("{src_container}/{src_object}"));
        resp.headers.set("X-Copied-From-Account", src_account);
        resp
    }
}

#[cfg(feature = "ec")]
fn ec_sources_sufficient(is_head: bool, available: usize, ndata: usize) -> bool {
    available >= if is_head { 1 } else { ndata }
}

/// Bucket key so `1751500123.45678` and `000001751500123.45678` join.
#[cfg(feature = "ec")]
fn version_timestamp_key(ts: &str) -> String {
    ts.parse::<Timestamp>()
        .map(|t| t.internal())
        .unwrap_or_else(|_| ts.to_string())
}

#[cfg(feature = "ec")]
fn same_data_timestamp(left: &str, right: &str) -> bool {
    match (left.parse::<Timestamp>(), right.parse::<Timestamp>()) {
        (Ok(a), Ok(b)) => a.internal() == b.internal(),
        _ => left == right,
    }
}

#[cfg(feature = "ec")]
fn timestamp_ge(left: &str, right: &str) -> bool {
    match (left.parse::<Timestamp>(), right.parse::<Timestamp>()) {
        (Ok(a), Ok(b)) => a >= b,
        _ => left >= right,
    }
}

/// Official probe POSTs after PUT. The data file stays at PUT ts; the
/// durable marker / X-Timestamp may be the later POST. A 200 is durable
/// when durable_ts is absent on an old server, equals the data ts, or is
/// a later generation of the same object.
#[cfg(feature = "ec")]
fn ec_source_is_durable(
    data_timestamp: &str,
    durable_timestamp: Option<&str>,
    explicit_data_timestamp: bool,
) -> bool {
    match durable_timestamp {
        Some(dts) => same_data_timestamp(dts, data_timestamp) || timestamp_ge(dts, data_timestamp),
        None => !explicit_data_timestamp,
    }
}

#[cfg(feature = "ec")]
fn ec_etag_compatible(bucket_etag: &str, incoming: &str) -> bool {
    bucket_etag.is_empty() || incoming.is_empty() || bucket_etag == incoming
}

/// Match Python's EC GET classification when no durable generation can be
/// selected.  A reconstructable generation made entirely from non-durable
/// fragments is a known-missing object (404), not a backend availability
/// failure.  Incomplete fragment sets remain 503 even when another backend
/// returned 404: they do not prove that reconstruction was possible.
#[cfg(feature = "ec")]
fn ec_no_durable_status(
    has_reconstructable_nondurable_bucket: bool,
    saw_404: bool,
    buckets_empty: bool,
) -> u16 {
    if has_reconstructable_nondurable_bucket || (saw_404 && buckets_empty) {
        404
    } else {
        503
    }
}

/// Round 0 of proxy EC GET omits the header (durable-only DiskFile open).
/// Later rounds send prefs, including `[]`, so a no-commit generation can
/// be skipped in favor of the older durable set.
#[cfg(feature = "ec")]
fn send_ec_fragment_preferences(round: u32) -> bool {
    round > 0
}

/// Prefs-less round 0 is one durable generation. Reuse the first bucket
/// key so POST-after-PUT timestamp noise cannot split ndata successes.
#[cfg(feature = "ec")]
fn ec_round0_bucket_key(existing: Option<&str>, data_timestamp: &str) -> String {
    existing
        .map(str::to_string)
        .unwrap_or_else(|| version_timestamp_key(data_timestamp))
}

/// Stamp piggybacked onto `G6_DIAG utf8-compat … service-complete`.
#[cfg(feature = "ec")]
fn g6_ec_diag(
    reason: &str,
    status: u16,
    policy_index: i64,
    ndata: usize,
    idxs: &[i32],
    n200: usize,
) -> String {
    format!(
        "reason={reason} status={status} ndata={ndata} idxs={idxs:?} ec=1 policy={policy_index} 200s={n200}"
    )
}

/// Field harvest greps proxy manager.log / syslog for `EC GET` / `reason=`.
/// Must go through `Logger` (`proxy-server:` INFO/ERROR), not `eprintln!`.
#[cfg(feature = "ec")]
fn format_ec_gather_miss(
    path: &str,
    status: u16,
    reason: &str,
    policy_index: i64,
    ndata: usize,
    n200: usize,
    idxs: &[i32],
    skipped_no_ts: usize,
    skipped_no_fi: usize,
    skipped_etag: usize,
    buckets: &str,
    tombstone: &str,
    saw_404: bool,
) -> String {
    format!(
        "proxy-server: EC GET {path} status={status} reason={reason} \
         policy={policy_index} ndata={ndata} 200s={n200} idxs={idxs:?} \
         skipped_no_ts={skipped_no_ts} skipped_no_fi={skipped_no_fi} \
         skipped_etag={skipped_etag} buckets={buckets} \
         tombstone={tombstone} saw_404={saw_404}"
    )
}

#[cfg(feature = "ec")]
fn ec_frag_index(headers: &[(String, String)]) -> Option<i32> {
    for key in [
        "X-Object-Sysmeta-Ec-Frag-Index",
        "X-Backend-Ec-Frag-Index",
        "Ec-Frag-Index",
    ] {
        if let Some(fi) = resp_header(headers, key).and_then(|value| value.parse::<i32>().ok()) {
            return Some(fi);
        }
    }
    None
}

#[cfg(feature = "ec")]
fn log_ec_gather_miss(
    app: &ProxyApp,
    path: &str,
    status: u16,
    reason: &str,
    policy_index: i64,
    ndata: usize,
    n200: usize,
    idxs: &[i32],
    skipped_no_ts: usize,
    skipped_no_fi: usize,
    skipped_etag: usize,
    buckets: &str,
    tombstone: &str,
    saw_404: bool,
) {
    app.emit_proxy_log(
        status >= 400,
        &format_ec_gather_miss(
            path,
            status,
            reason,
            policy_index,
            ndata,
            n200,
            idxs,
            skipped_no_ts,
            skipped_no_fi,
            skipped_etag,
            buckets,
            tombstone,
            saw_404,
        ),
    );
}

/// Encode Python `ECGetResponseCollection._get_frag_prefs`. Each later
/// request names the data generations already observed and excludes fragment
/// indexes already held for that generation. An empty collection deliberately
/// serializes as `[]`: that is the object-server contract which makes a
/// non-durable fragment eligible for EC reconstruction.
#[cfg(feature = "ec")]
fn encode_ec_fragment_preferences<'a>(
    buckets: impl IntoIterator<Item = (&'a str, bool, Vec<i32>)>,
    required: usize,
) -> String {
    let mut buckets: Vec<(&str, bool, Vec<i32>)> = buckets.into_iter().collect();
    for (_, _, fragments) in &mut buckets {
        fragments.sort_unstable();
        fragments.dedup();
    }
    buckets.sort_by(|left, right| {
        let left_score = (left.1, left.2.len() >= required, left.2.len(), left.0);
        let right_score = (right.1, right.2.len() >= required, right.2.len(), right.0);
        right_score.cmp(&left_score)
    });
    let preferences: Vec<serde_json::Value> = buckets
        .into_iter()
        .map(|(timestamp, _, exclude)| {
            serde_json::json!({"timestamp": timestamp, "exclude": exclude})
        })
        .collect();
    serde_json::to_string(&preferences).expect("EC fragment preferences are JSON-safe")
}

pub(crate) fn parse_copy_from(value: &str) -> Option<(String, String)> {
    let decoded = percent_decode_copy_from(value);
    let v = decoded.strip_prefix('/').unwrap_or(decoded.as_str());
    let (container, object) = v.split_once('/')?;
    if container.is_empty() || object.is_empty() {
        return None;
    }
    Some((container.to_string(), object.to_string()))
}

fn percent_decode_copy_from(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(value) = u8::from_str_radix(hex, 16) {
                    out.push(value);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_copied_source_header(name: &str) -> bool {
    let lname = name.to_ascii_lowercase();
    if lname == "x-static-large-object" || lname == "x-object-manifest" {
        return false;
    }
    lname == "content-type"
        || lname == "content-encoding"
        || lname == "content-disposition"
        || lname == "x-delete-at"
        || lname.starts_with("x-object-meta-")
        || lname.starts_with("x-object-sysmeta-")
        || lname.starts_with("x-symlink-")
}

fn body_to_incoming(body: Body) -> IncomingBody {
    match body {
        Body::Buffered(b) => IncomingBody::from_bytes(b, u64::MAX),
        Body::Channel(ch) => {
            let (rx, scope, len) = ch.into_rx();
            IncomingBody::from_channel(rx, len, scope, u64::MAX)
        }
        Body::Streamed(_) => IncomingBody::from_bytes(Vec::new(), u64::MAX),
    }
}

#[cfg(feature = "ec")]
async fn read_exact_from_head(
    head: &mut AsyncBackendHead,
    n: usize,
    idle: Duration,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    if !head.leftover.is_empty() {
        let take = head.leftover.len().min(n);
        out.extend(head.leftover.drain(..take));
    }
    while out.len() < n {
        let mut buf = vec![0u8; n - out.len()];
        let got = tokio::time::timeout(idle, head.stream.read(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend body timeout"))??;
        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "ec fragment truncated",
            ));
        }
        out.extend_from_slice(&buf[..got]);
    }
    Ok(out)
}

struct AsyncBackendHead {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    stream: TcpStream,
    leftover: Vec<u8>,
    content_length: Option<u64>,
}

#[allow(clippy::too_many_arguments)]
async fn backend_request_head_async(
    node: &Node,
    part: u32,
    method: &str,
    path: &str,
    query: &str,
    headers: &HeaderKeyDict,
    body: &[u8],
    conn_timeout: Duration,
    node_timeout: Duration,
) -> io::Result<AsyncBackendHead> {
    let mut stream = connect_node_async(node, conn_timeout).await?;
    let addr = format!("{}:{}", node.ip, node.port);
    let target = if query.is_empty() {
        format!("/{}/{}{}", node.device, part, path)
    } else {
        format!("/{}/{}{}?{}", node.device, part, path, query)
    };
    let mut out = format!("{method} {target} HTTP/1.1\r\nHost: {addr}\r\n");
    for (k, v) in headers.iter() {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    tokio::time::timeout(node_timeout, stream.write_all(out.as_bytes()))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend write timeout"))??;
    if !body.is_empty() {
        tokio::time::timeout(node_timeout, stream.write_all(body))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend write timeout"))??;
    }
    tokio::time::timeout(node_timeout, stream.flush())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend flush timeout"))??;
    let mut leftover = Vec::new();
    let (status, reason, resp_headers) =
        read_http_head(&mut stream, &mut leftover, node_timeout).await?;
    let content_length =
        resp_header(&resp_headers, "content-length").and_then(|v| v.parse::<u64>().ok());
    Ok(AsyncBackendHead {
        status,
        reason,
        headers: resp_headers,
        stream,
        leftover,
        content_length,
    })
}

fn stream_backend_body(mut head: AsyncBackendHead, idle: Duration) -> Body {
    let content_length = head.content_length;
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    let scope = TaskScope::bounded(1);
    let _ = scope.spawn(async move {
        let mut remaining = content_length;
        if !head.leftover.is_empty() {
            let n = match remaining {
                Some(r) => head.leftover.len().min(r as usize),
                None => head.leftover.len(),
            };
            let piece: Vec<u8> = head.leftover.drain(..n).collect();
            if let Some(r) = remaining.as_mut() {
                *r = r.saturating_sub(n as u64);
            }
            if tx.send(Ok(piece)).await.is_err() {
                return;
            }
        }
        let mut buf = vec![0u8; STREAM_CHUNK];
        loop {
            if remaining == Some(0) {
                break;
            }
            let take = match remaining {
                Some(r) => buf.len().min(r as usize),
                None => buf.len(),
            };
            match tokio::time::timeout(idle, head.stream.read(&mut buf[..take])).await {
                Ok(Ok(0)) => {
                    if remaining.is_some_and(|r| r > 0) {
                        let _ = tx
                            .send(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "backend disconnected mid-body",
                            )))
                            .await;
                    }
                    break;
                }
                Ok(Ok(n)) => {
                    if let Some(r) = remaining.as_mut() {
                        *r = r.saturating_sub(n as u64);
                    }
                    if tx.send(Ok(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    let _ = tx.send(Err(e)).await;
                    break;
                }
                Err(_) => {
                    let _ = tx
                        .send(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "backend body timeout",
                        )))
                        .await;
                    break;
                }
            }
        }
    });
    Body::from_channel(rx, content_length, scope)
}

async fn buffer_backend_body(
    mut head: AsyncBackendHead,
    cap: u64,
    has_body: bool,
    idle: Duration,
) -> io::Result<BackendResponse> {
    if let Some(n) = head.content_length {
        if has_body && n > cap {
            return Err(io::Error::other("backend body exceeds buffer cap"));
        }
    }
    let body = if has_body {
        let mut reader = BufReader::new(head.stream);
        leftover_then_read(&mut head.leftover, &mut reader, head.content_length, idle).await?
    } else {
        Vec::new()
    };
    Ok(BackendResponse {
        status: head.status,
        reason: head.reason,
        headers: head.headers,
        body,
    })
}

async fn leftover_then_read(
    leftover: &mut Vec<u8>,
    reader: &mut BufReader<TcpStream>,
    content_length: Option<u64>,
    idle: Duration,
) -> io::Result<Vec<u8>> {
    if leftover.is_empty() {
        return read_body_capped(reader, content_length, swift_http::MAX_CONTROL_BODY, idle).await;
    }
    match content_length {
        Some(n) => {
            let n = n as usize;
            if leftover.len() >= n {
                let body = leftover.drain(..n).collect();
                return Ok(body);
            }
            let mut body = std::mem::take(leftover);
            let mut rest = vec![0u8; n - body.len()];
            tokio::time::timeout(idle, reader.read_exact(&mut rest))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend body timeout"))??;
            body.extend_from_slice(&rest);
            Ok(body)
        }
        None => {
            let mut body = std::mem::take(leftover);
            tokio::time::timeout(
                idle,
                reader
                    .take(swift_http::MAX_CONTROL_BODY)
                    .read_to_end(&mut body),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend body timeout"))??;
            Ok(body)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn replica_try_nodes(
    app: Arc<ProxyApp>,
    node_pool: Arc<Mutex<VecDeque<Node>>>,
    part: u32,
    method: String,
    path: String,
    query: String,
    headers: swift_http::HeaderKeyDict,
    body: Vec<u8>,
    tx: tokio::sync::mpsc::Sender<Option<BackendResponse>>,
    cancel: CancellationToken,
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let node = {
            let mut pool = node_pool.lock().await;
            match pool.pop_front() {
                Some(n) => n,
                None => {
                    let _ = tx.send(None).await;
                    return;
                }
            }
        };
        match backend_request_async(
            &node,
            part,
            &method,
            &path,
            &query,
            &headers,
            &body,
            app.config.conn_timeout,
            app.config.node_timeout,
        )
        .await
        {
            Ok(resp) if resp.status == 507 => app.error_limiter.limit(&node),
            Ok(resp) if resp.status >= 500 => app.error_limiter.increment(&node),
            Ok(resp) => {
                let _ = tx.send(Some(resp)).await;
                return;
            }
            Err(_) => app.error_limiter.increment(&node),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn connect_slot(
    app: Arc<ProxyApp>,
    node_pool: Arc<Mutex<VecDeque<Node>>>,
    part: u32,
    path: String,
    query: String,
    headers: swift_http::HeaderKeyDict,
    content_length: Option<u64>,
    tx: tokio::sync::mpsc::Sender<AsyncPutterOutcome>,
    cancel: CancellationToken,
) {
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let node = {
            let mut pool = node_pool.lock().await;
            match pool.pop_front() {
                Some(n) => n,
                None => return,
            }
        };
        match connect_putter_async(
            &node,
            part,
            &path,
            &query,
            &headers,
            content_length,
            app.config.conn_timeout,
            app.config.node_timeout,
        )
        .await
        {
            Ok(AsyncPutterOutcome::EarlyFinal(resp)) if resp.status == 507 => {
                app.error_limiter.limit(&node);
            }
            Ok(AsyncPutterOutcome::EarlyFinal(resp)) if resp.status >= 500 => {
                app.error_limiter.increment(&node);
            }
            Ok(outcome) => {
                let _ = tx.send(outcome).await;
                return;
            }
            Err(_) => app.error_limiter.increment(&node),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProxyApp, ProxyConfig};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;
    use swift_core::hashing::HashPathConfig;
    use swift_http::{HeaderKeyDict, IncomingBody};
    use swift_ring::{Ring, RingData, RingDevice};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[cfg(feature = "ec")]
    #[test]
    fn ec_head_needs_metadata_source_but_get_still_needs_ndata() {
        assert!(ec_sources_sufficient(true, 1, 4));
        assert!(!ec_sources_sufficient(true, 0, 4));
        assert!(!ec_sources_sufficient(false, 1, 4));
        assert!(ec_sources_sufficient(false, 4, 4));
    }

    #[cfg(feature = "ec")]
    #[test]
    fn ec_no_durable_generation_distinguishes_missing_from_unavailable() {
        assert_eq!(
            ec_no_durable_status(true, false, false),
            404,
            "a reconstructable but entirely non-durable generation is missing"
        );
        assert_eq!(
            ec_no_durable_status(true, true, false),
            404,
            "an explicit 404 does not change a reconstructable non-durable generation"
        );
        assert_eq!(
            ec_no_durable_status(false, true, true),
            404,
            "an empty response collection with an explicit 404 is missing"
        );
        assert_eq!(
            ec_no_durable_status(false, true, false),
            503,
            "incomplete durable set (lonely frag) + sibling 404s is 503, not 404"
        );
        assert_eq!(
            ec_no_durable_status(false, false, true),
            503,
            "transport failures without a 404 are unavailable"
        );
        assert_eq!(
            ec_no_durable_status(false, false, false),
            503,
            "an incomplete bucket without a 404 is unavailable"
        );
    }

    #[cfg(feature = "ec")]
    #[test]
    fn lonely_frag_below_ndata_is_503_not_404() {
        // Official test_rebuild_quarantines_lonely_frag early client GET:
        // 1 durable + 5 reclaimed 404s (no X-Backend-Timestamp). Python
        // returns 503 so the probe can assert before quarantine once.
        // Empty collection + 404 remains 404 (object gone).
        assert_eq!(ec_no_durable_status(false, true, false), 503);
        assert_eq!(ec_no_durable_status(false, true, true), 404);
        assert_eq!(ec_no_durable_status(false, false, false), 503);
    }

    #[cfg(feature = "ec")]
    #[test]
    fn post_after_put_durable_header_still_counts_the_data_generation() {
        // Field 9a95747: remaining+healed GET 200s with data_ts=PUT and
        // durable_ts=POST must form one durable bucket. The old gather
        // required durable_timestamps.contains(data_ts) and 404'd.
        assert!(ec_source_is_durable(
            "000001700000900.00000",
            Some("000001700000901.00000"),
            true
        ));
        assert!(ec_source_is_durable(
            "1700000900.00000",
            Some("000001700000900.00000"),
            true
        ));
        assert!(!ec_source_is_durable(
            "000001700000901.00000",
            Some("000001700000900.00000"),
            true
        ));
        assert!(!ec_source_is_durable("000001700000900.00000", None, true));
        assert!(ec_source_is_durable("000001700000900.00000", None, false));
        assert_eq!(
            version_timestamp_key("1700000900.00000"),
            version_timestamp_key("000001700000900.00000")
        );
        assert!(ec_etag_compatible("", "deadbeef"));
        assert!(ec_etag_compatible("deadbeef", ""));
        assert!(ec_etag_compatible("deadbeef", "deadbeef"));
        assert!(!ec_etag_compatible("deadbeef", "cafebabe"));
        // Field 4f7a82c: idxs=[0,2,3,4,5] 200s with POST X-Timestamp and
        // PUT data_ts must stay one generation on prefs-less gather.
        let put = version_timestamp_key("1788720311.82508");
        assert_eq!(ec_round0_bucket_key(None, "1788720311.82508"), put);
        assert_eq!(
            ec_round0_bucket_key(Some(&put), "000001788720312.00000"),
            put,
            "later POST timestamp must not open a second round-0 bucket"
        );
        let line = format_ec_gather_miss(
            "/a/c/o",
            404,
            "no_complete_bucket",
            2,
            4,
            5,
            &[0, 2, 3, 4, 5],
            0,
            0,
            0,
            "1788720311:5:d:abc",
            "0",
            true,
        );
        assert!(
            line.contains("proxy-server: EC GET /a/c/o status=404 reason=no_complete_bucket"),
            "{line}"
        );
        assert!(
            line.contains("policy=2 ndata=4 200s=5 idxs=[0, 2, 3, 4, 5]"),
            "{line}"
        );
        assert!(ec_frag_index(&[("X-Object-Sysmeta-Ec-Frag-Index".into(), "3".into())]) == Some(3));
        assert!(ec_frag_index(&[("Ec-Frag-Index".into(), "5".into())]) == Some(5));
    }

    #[cfg(feature = "ec")]
    #[test]
    fn ec_fragment_preferences_expose_non_durable_then_prioritize_durable_bucket() {
        assert!(
            !send_ec_fragment_preferences(0),
            "round 0 must omit prefs so rust DiskFile opens the durable set"
        );
        assert!(
            send_ec_fragment_preferences(1),
            "round 1 may send [] to expose a non-durable generation"
        );
        assert_eq!(
            encode_ec_fragment_preferences(std::iter::empty(), 4),
            "[]",
            "an empty collection still serializes as [] for a later pass"
        );
        let encoded = encode_ec_fragment_preferences(
            [
                ("0000006001.00000", false, vec![3, 1, 3]),
                ("0000006000.00000", true, vec![2]),
            ],
            4,
        );
        let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded[0]["timestamp"], "0000006000.00000");
        assert_eq!(decoded[0]["exclude"], serde_json::json!([2]));
        assert_eq!(decoded[1]["timestamp"], "0000006001.00000");
        assert_eq!(decoded[1]["exclude"], serde_json::json!([1, 3]));
    }

    #[test]
    fn parse_copy_from_unquotes_percent_encoded_object() {
        let (c, o) = parse_copy_from("/srcc/object%20name%20%F0%9F%99%82").unwrap();
        assert_eq!(c, "srcc");
        assert_eq!(o, "object name 🙂");
    }

    fn ring_unused() -> Ring {
        let dev = RingDevice {
            id: 1,
            region: 1,
            zone: 1,
            ip: "127.0.0.1".into(),
            port: 1,
            replication_ip: None,
            replication_port: None,
            device: "sda".into(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        };
        let data = RingData::from_parts(vec![Some(dev)], 32, vec![vec![0]]);
        Ring::new(data, HashPathConfig::new("", "changeme").unwrap())
    }

    fn test_app() -> StdArc<ProxyApp> {
        StdArc::new(ProxyApp::new(
            ring_unused(),
            ring_unused(),
            ProxyConfig {
                conn_timeout: Duration::from_millis(200),
                node_timeout: Duration::from_millis(400),
                ..ProxyConfig::default()
            },
        ))
    }

    fn node(port: u16) -> Node {
        Node {
            ip: "127.0.0.1".into(),
            port: port as u32,
            device: "sda".into(),
            handoff: false,
            backend_index: None,
        }
    }

    async fn spawn_ok_backend() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0u8; 16 * 1024];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
        });
        (port, h)
    }

    async fn spawn_put_ok_backend(
        reads: StdArc<AtomicUsize>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut head = Vec::new();
            let mut tmp = [0u8; 512];
            loop {
                let n = match stream.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                head.extend_from_slice(&tmp[..n]);
                if find_header_end(&head).is_some() {
                    break;
                }
            }
            let end = find_header_end(&head).unwrap();
            let header_text = String::from_utf8_lossy(&head[..end]).to_ascii_lowercase();
            let mut leftover = head[end..].to_vec();
            let content_length = header_text
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok());
            let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
            let _ = stream.flush().await;
            let need = content_length.unwrap_or(0);
            while leftover.len() < need {
                let n = match stream.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                leftover.extend_from_slice(&tmp[..n]);
            }
            leftover.truncate(need);
            reads.fetch_add(leftover.len(), Ordering::SeqCst);
            let _ = stream
                .write_all(b"HTTP/1.1 201 Created\r\nETag: \"x\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = stream.flush().await;
        });
        (port, h)
    }

    /// Sends 100 Continue after the request head, then never reads the body
    /// so the replica write times out and is dropped.
    async fn spawn_continue_then_stall() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut head = Vec::new();
            let mut tmp = [0u8; 512];
            loop {
                let n = match stream.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                head.extend_from_slice(&tmp[..n]);
                if find_header_end(&head).is_some() {
                    break;
                }
            }
            let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
            let _ = stream.flush().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });
        (port, h)
    }

    async fn spawn_blackhole() -> (u16, tokio::task::JoinHandle<()>, StdArc<AtomicUsize>) {
        let accepted = StdArc::new(AtomicUsize::new(0));
        let flag = StdArc::clone(&accepted);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            flag.fetch_add(1, Ordering::SeqCst);
            // Never read: TCP window fills; we hold the fd so the peer
            // write eventually blocks / times out.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });
        (port, h, accepted)
    }

    async fn spawn_delayed_ok_backend(delay: Duration) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 16 * 1024];
            let _ = stream.read(&mut buf).await;
            tokio::time::sleep(delay).await;
            let _ = stream
                .write_all(
                    b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        });
        (port, h)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn make_requests_async_quorum_cancels_blackhole() {
        let (ok_a, ha) = spawn_ok_backend().await;
        let (ok_b, hb) = spawn_ok_backend().await;
        let (hole, hh, accepted) = spawn_blackhole().await;
        let app = test_app();
        let nodes = vec![node(hole), node(ok_a), node(ok_b)];
        let headers = vec![HeaderKeyDict::new(); 3];
        let started = std::time::Instant::now();
        let resp = app
            .make_requests_async(nodes, 3, 0, "POST", "/a/c", "", headers, Vec::new())
            .await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "blackhole must not hold the fan-out: {:?}",
            started.elapsed()
        );
        assert_eq!(resp.status, 201, "{}", resp.reason);
        assert!(accepted.load(Ordering::SeqCst) <= 1);
        ha.abort();
        hb.abort();
        hh.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn make_write_async_waits_post_quorum_for_slow_replica() {
        let (ok_a, ha) = spawn_ok_backend().await;
        let (ok_b, hb) = spawn_ok_backend().await;
        let (slow, hs) = spawn_delayed_ok_backend(Duration::from_millis(150)).await;
        let app = test_app();
        let nodes = vec![node(slow), node(ok_a), node(ok_b)];
        let headers = vec![HeaderKeyDict::new(); 3];
        let started = std::time::Instant::now();
        let resp = app
            .make_write_async(nodes, 3, 0, "PUT", "/a/c", "", headers)
            .await;
        let elapsed = started.elapsed();
        assert_eq!(resp.status, 201, "{}", resp.reason);
        assert!(
            elapsed >= Duration::from_millis(120),
            "container write must wait for the slow replica's account-update: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "must not wait the full node_timeout: {elapsed:?}"
        );
        ha.abort();
        hb.abort();
        hs.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_putter_async_sees_continue() {
        let reads = StdArc::new(AtomicUsize::new(0));
        let (port, h) = spawn_put_ok_backend(reads).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        let n = node(port);
        let hdr = HeaderKeyDict::new();
        let r = connect_putter_async(
            &n,
            0,
            "/AUTH/c/o",
            "",
            &hdr,
            Some(4),
            Duration::from_millis(500),
            Duration::from_millis(500),
        )
        .await;
        match r {
            Ok(AsyncPutterOutcome::Live(_)) => {}
            Ok(AsyncPutterOutcome::EarlyFinal(resp)) => {
                panic!("early final {}", resp.status)
            }
            Err(e) => panic!("connect_putter_async failed: {e}"),
        }
        h.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stream_put_async_two_live_backends() {
        let reads = StdArc::new(AtomicUsize::new(0));
        let (ok_a, ha) = spawn_put_ok_backend(StdArc::clone(&reads)).await;
        let (ok_b, hb) = spawn_put_ok_backend(StdArc::clone(&reads)).await;
        let app = test_app();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let payload = vec![b'y'; 4096];
        let mut incoming = IncomingBody::from_bytes(payload, u64::MAX);
        let mut hdr = HeaderKeyDict::new();
        hdr.set("Content-Type", "application/octet-stream");
        let resp = app
            .stream_put_async(
                vec![node(ok_a), node(ok_b)],
                2,
                0,
                "/AUTH/c/o",
                "",
                vec![hdr.clone(), hdr],
                &mut incoming,
            )
            .await;
        let mut resp = resp;
        let msg = String::from_utf8_lossy(resp.body.materialize(4096).unwrap_or(&[])).into_owned();
        assert_eq!(resp.status, 201, "reason={} body={}", resp.reason, msg);
        ha.abort();
        hb.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stream_put_async_drops_stalled_replica_and_keeps_window_bounded() {
        let reads = StdArc::new(AtomicUsize::new(0));
        let (ok_a, ha) = spawn_put_ok_backend(StdArc::clone(&reads)).await;
        let (ok_b, hb) = spawn_put_ok_backend(StdArc::clone(&reads)).await;
        let (hole, hh) = spawn_continue_then_stall().await;
        let app = test_app();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let payload = vec![b'y'; STREAM_CHUNK * 3];
        let mut incoming = IncomingBody::from_bytes(payload, u64::MAX);
        let mut hdr = HeaderKeyDict::new();
        hdr.set("Content-Type", "application/octet-stream");
        let headers = vec![hdr.clone(), hdr.clone(), hdr];
        let started = std::time::Instant::now();
        let resp = app
            .stream_put_async(
                vec![node(hole), node(ok_a), node(ok_b)],
                3,
                0,
                "/AUTH/c/o",
                "",
                headers,
                &mut incoming,
            )
            .await;
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "stalled replica must be dropped: {:?}",
            started.elapsed()
        );
        assert_eq!(resp.status, 201, "{}", resp.reason);
        assert!(
            reads.load(Ordering::SeqCst) > STREAM_CHUNK,
            "live backends must receive object bytes"
        );
        ha.abort();
        hb.abort();
        hh.abort();
    }

    async fn spawn_get_backend(
        body: Vec<u8>,
        pause_after: Option<usize>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut head = Vec::new();
            let mut tmp = [0u8; 512];
            loop {
                let n = match stream.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                head.extend_from_slice(&tmp[..n]);
                if find_header_end(&head).is_some() {
                    break;
                }
            }
            let hdr = format!(
                "HTTP/1.1 200 OK\r\nETag: \"abc\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(hdr.as_bytes()).await;
            if let Some(n) = pause_after.filter(|n| *n < body.len()) {
                let _ = stream.write_all(&body[..n]).await;
                let _ = stream.flush().await;
                tokio::time::sleep(Duration::from_millis(250)).await;
                let _ = stream.write_all(&body[n..]).await;
            } else {
                let _ = stream.write_all(&body).await;
            }
            let _ = stream.flush().await;
        });
        (port, h)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_or_head_async_streams_object_get_before_slow_backend_tail() {
        let payload = vec![b'g'; STREAM_CHUNK + 1024];
        let (port, h) = spawn_get_backend(payload.clone(), Some(STREAM_CHUNK)).await;
        let app = test_app();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let started = std::time::Instant::now();
        let resp = app
            .get_or_head_async(
                "object",
                vec![node(port)],
                0,
                "GET",
                "/AUTH/c/o",
                "",
                &HeaderKeyDict::new(),
            )
            .await
            .expect("GET source");
        assert!(
            started.elapsed() < Duration::from_millis(120),
            "streaming GET must return headers without waiting for the backend tail: {:?}",
            started.elapsed()
        );
        assert_eq!(resp.status, 200, "{}", resp.reason);
        assert!(
            matches!(resp.body, Body::Channel(_)),
            "object GET must be Body::Channel"
        );
        let got = resp.body.collect_async().await.expect("channel drain");
        assert_eq!(got, payload);
        h.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_or_head_async_head_does_not_stream_body() {
        let payload = vec![b'h'; 32];
        let (port, h) = spawn_get_backend(payload, None).await;
        let app = test_app();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let resp = app
            .get_or_head_async(
                "object",
                vec![node(port)],
                0,
                "HEAD",
                "/AUTH/c/o",
                "",
                &HeaderKeyDict::new(),
            )
            .await
            .expect("HEAD source");
        assert_eq!(resp.status, 200);
        assert!(
            matches!(resp.body, Body::Buffered(_)),
            "HEAD must stay buffered"
        );
        h.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn post_fan_out_async_quorum_on_two_live() {
        let (ok_a, ha) = spawn_ok_backend().await;
        let (ok_b, hb) = spawn_ok_backend().await;
        let app = test_app();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let headers = vec![HeaderKeyDict::new(), HeaderKeyDict::new()];
        let resp = app
            .make_requests_async(
                vec![node(ok_a), node(ok_b)],
                2,
                0,
                "POST",
                "/AUTH/c/o",
                "",
                headers,
                Vec::new(),
            )
            .await;
        assert_eq!(resp.status, 201, "{}", resp.reason);
        ha.abort();
        hb.abort();
    }

    async fn spawn_loop_object_backend(
        payload: Vec<u8>,
        put_reads: StdArc<AtomicUsize>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let payload = payload.clone();
                let put_reads = StdArc::clone(&put_reads);
                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut stream = stream;
                    let mut head = Vec::new();
                    let mut tmp = [0u8; 512];
                    loop {
                        let n = match stream.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        head.extend_from_slice(&tmp[..n]);
                        if find_header_end(&head).is_some() {
                            break;
                        }
                    }
                    let end = find_header_end(&head).unwrap();
                    let header_text = String::from_utf8_lossy(&head[..end]);
                    let method = header_text
                        .lines()
                        .next()
                        .unwrap_or("")
                        .split_whitespace()
                        .next()
                        .unwrap_or("");
                    if method.eq_ignore_ascii_case("HEAD") {
                        let _ = stream
                            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                        return;
                    }
                    if method.eq_ignore_ascii_case("GET") {
                        let hdr = format!(
                            "HTTP/1.1 200 OK\r\nETag: \"abc\"\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            payload.len()
                        );
                        let _ = stream.write_all(hdr.as_bytes()).await;
                        let _ = stream.write_all(&payload).await;
                        return;
                    }
                    if method.eq_ignore_ascii_case("PUT") {
                        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
                        let _ = stream.flush().await;
                        let mut leftover = head[end..].to_vec();
                        let clen = header_text.to_ascii_lowercase().lines().find_map(|l| {
                            l.strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        });
                        let need = clen.unwrap_or(0);
                        while leftover.len() < need {
                            let n = match stream.read(&mut tmp).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            leftover.extend_from_slice(&tmp[..n]);
                        }
                        leftover.truncate(need);
                        put_reads.fetch_add(leftover.len(), Ordering::SeqCst);
                        let _ = stream
                            .write_all(b"HTTP/1.1 201 Created\r\nETag: \"x\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                        let _ = stream.flush().await;
                    }
                });
            }
        });
        (port, h)
    }

    fn ring_on(port: u16) -> Ring {
        let dev = RingDevice {
            id: 1,
            region: 1,
            zone: 1,
            ip: "127.0.0.1".into(),
            port: port as u32,
            replication_ip: None,
            replication_port: None,
            device: "sda".into(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        };
        let data = RingData::from_parts(vec![Some(dev)], 32, vec![vec![0]]);
        Ring::new(data, HashPathConfig::new("", "changeme").unwrap())
    }

    /// copy.py:49-65 (wire: COPY + Destination) and copy.py:320-347
    /// (`handle_COPY` rewrites to PUT + X-Copy-From, then GET source).
    /// Shipped `handle_async` / `object_copy_async` then Hyper
    /// `serve_with_filters_and_config`. Not VerbService. Destination PUT
    /// must receive the source bytes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hyper_serve_copy_is_get_then_put_on_shipped_proxy() {
        let payload = vec![b'c'; 4096];
        let reads = StdArc::new(AtomicUsize::new(0));
        let (port, h) = spawn_loop_object_backend(payload.clone(), StdArc::clone(&reads)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let app = StdArc::new(ProxyApp::with_object_ring(
            ring_on(port),
            ring_on(port),
            ring_on(port),
            ProxyConfig {
                conn_timeout: Duration::from_millis(400),
                node_timeout: Duration::from_millis(800),
                request_node_count_factor: 1,
                ..Default::default()
            },
        ));
        app.info_cache.set_container(
            "AUTH/srcc".into(),
            ContainerInfo {
                status: 204,
                policy_index: 0,
                ..Default::default()
            },
            60.0,
        );
        app.info_cache.set_container(
            "AUTH/dstc".into(),
            ContainerInfo {
                status: 204,
                policy_index: 0,
                ..Default::default()
            },
            60.0,
        );
        let mut headers = HeaderKeyDict::new();
        headers.set("Destination", "/dstc/dsto");
        let resp = app
            .handle_async(swift_http::AsyncRequest {
                method: "COPY".into(),
                path: "/v1/AUTH/srcc/srco".into(),
                query_string: String::new(),
                headers,
                body: IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            resp.status,
            201,
            "handle_async COPY {} put_reads={}",
            resp.reason,
            reads.load(Ordering::SeqCst)
        );
        assert_eq!(
            reads.load(Ordering::SeqCst),
            payload.len(),
            "destination PUT must receive source bytes"
        );
        assert!(
            resp.headers
                .get("X-Copied-From")
                .is_some_and(|v| v.eq_ignore_ascii_case("srcc/srco")),
            "copy.py Destination COPY stamps X-Copied-From, got {:?}",
            resp.headers
        );
        reads.store(0, Ordering::SeqCst);

        // Same app on shipped Hyper HTTP/1.1 (`serve_with_filters_and_config`).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let cfg = swift_http::ServerConfig {
            worker_threads: 2,
            shutdown: Some(StdArc::clone(&shutdown)),
            ..swift_http::ServerConfig::default()
        };
        let app_http = StdArc::clone(&app);
        std::thread::spawn(move || {
            crate::serve_with_filters_and_config(
                listener,
                StdArc::new(std::sync::RwLock::new(app_http)),
                Vec::new(),
                cfg,
            )
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(20)).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
        let mut c =
            std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(400)).unwrap();
        use std::io::{Read, Write};
        c.set_read_timeout(Some(Duration::from_millis(2500)))
            .unwrap();
        c.write_all(
            b"COPY /v1/AUTH/srcc/srco HTTP/1.1\r\nHost: 127.0.0.1\r\nDestination: /dstc/dsto\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        let _ = c.flush();
        let mut raw = Vec::new();
        let _ = c.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw);
        assert!(
            text.contains("201"),
            "shipped Hyper COPY must be 201 via object_copy_async, got {text:?}"
        );
        assert!(
            text.to_ascii_lowercase()
                .contains("x-copied-from: srcc/srco"),
            "copy.py Destination COPY stamps X-Copied-From on the wire, got {text:?}"
        );
        assert_eq!(
            reads.load(Ordering::SeqCst),
            payload.len(),
            "Hyper COPY destination PUT must receive source bytes (not a stub 201)"
        );
        shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
        h.abort();
    }

    /// copy.py:49-65 — PUT + X-Copy-From / COPY + Destination is GET source
    /// then PUT dest without downloading to the client.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn copy_tees_source_get_channel_into_dest_put() {
        let payload = vec![b'c'; 8192];
        let (src, hs) = spawn_get_backend(payload.clone(), None).await;
        let reads = StdArc::new(AtomicUsize::new(0));
        let (ok_a, ha) = spawn_put_ok_backend(StdArc::clone(&reads)).await;
        let (ok_b, hb) = spawn_put_ok_backend(StdArc::clone(&reads)).await;
        let app = test_app();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut source = app
            .get_or_head_async(
                "object",
                vec![node(src)],
                0,
                "GET",
                "/AUTH/srcc/srco",
                "",
                &HeaderKeyDict::new(),
            )
            .await
            .expect("source GET");
        assert_eq!(source.status, 200);
        assert!(
            matches!(source.body, Body::Channel(_)),
            "COPY source GET must stay a Channel"
        );
        let mut incoming = body_to_incoming(source.body.take());
        let mut hdr = HeaderKeyDict::new();
        hdr.set("Content-Type", "application/octet-stream");
        let resp = app
            .stream_put_async(
                vec![node(ok_a), node(ok_b)],
                2,
                0,
                "/AUTH/dstc/dsto",
                "",
                vec![hdr.clone(), hdr],
                &mut incoming,
            )
            .await;
        assert_eq!(resp.status, 201, "{}", resp.reason);
        assert!(
            reads.load(Ordering::SeqCst) >= payload.len(),
            "destination backends must receive copied bytes"
        );
        hs.abort();
        ha.abort();
        hb.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delete_async_quorum_on_two_live() {
        let (ok_a, ha) = spawn_ok_backend().await;
        let (ok_b, hb) = spawn_ok_backend().await;
        let app = test_app();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let headers = vec![HeaderKeyDict::new(), HeaderKeyDict::new()];
        let resp = app
            .make_requests_async(
                vec![node(ok_a), node(ok_b)],
                2,
                0,
                "DELETE",
                "/AUTH/c/o",
                "",
                headers,
                Vec::new(),
            )
            .await;
        assert_eq!(resp.status, 201, "{}", resp.reason);
        ha.abort();
        hb.abort();
    }

    fn ring_on_port(port: u16) -> Ring {
        let dev = RingDevice {
            id: 1,
            region: 1,
            zone: 1,
            ip: "127.0.0.1".into(),
            port: port as u32,
            replication_ip: None,
            replication_port: None,
            device: "sda".into(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        };
        let data = RingData::from_parts(vec![Some(dev)], 32, vec![vec![0]]);
        Ring::new(data, HashPathConfig::new("", "changeme").unwrap())
    }

    async fn spawn_sharded_listing_backend() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut head = Vec::new();
                let mut tmp = [0u8; 512];
                loop {
                    let n = match stream.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    head.extend_from_slice(&tmp[..n]);
                    if find_header_end(&head).is_some() {
                        break;
                    }
                }
                if head.is_empty() {
                    continue;
                }
                let line = String::from_utf8_lossy(&head);
                let first = line.lines().next().unwrap_or("");
                if first.starts_with("HEAD ") {
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nX-Backend-Sharding-State: sharded\r\nX-Backend-Storage-Policy-Index: 1\r\nX-Container-Object-Count: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await;
                } else if first.contains("states=listing") {
                    let body = br#"[{"name":"AUTH_test/shardc","lower":"","upper":"","state":30}]"#;
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(hdr.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                } else {
                    let policy_one = line.lines().any(|value| {
                        value.eq_ignore_ascii_case("X-Backend-Storage-Policy-Index: 1")
                    });
                    let body: &[u8] = if !policy_one {
                        br#"[]"#
                    } else if first.contains("reverse=on") {
                        br#"[{"name":"obj-b"},{"name":"obj-a"}]"#
                    } else {
                        br#"[{"name":"obj-a"},{"name":"obj-b"}]"#
                    };
                    let hdr = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(hdr.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                }
                let _ = stream.flush().await;
            }
        });
        (port, h)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sharded_listing_async_uses_get_or_head_async() {
        let (port, h) = spawn_sharded_listing_backend().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let app = StdArc::new(ProxyApp::new(
            ring_on_port(port),
            ring_on_port(port),
            ProxyConfig {
                conn_timeout: Duration::from_millis(200),
                node_timeout: Duration::from_millis(400),
                ..ProxyConfig::default()
            },
        ));
        let req = swift_http::Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let resp = app
            .maybe_sharded_container_listing_async(req, "AUTH_test", "c")
            .await
            .expect("sharded fan-out");
        assert_eq!(resp.status, 200, "{}", resp.reason);
        assert_eq!(
            resp.headers.get("X-Container-Object-Count").as_deref(),
            Some("2"),
            "GET listing count matches returned objects"
        );
        let body = resp.body.collect_async().await.expect("listing body");
        let listing: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(listing[0]["name"], "obj-a");
        assert_eq!(listing[1]["name"], "obj-b");
        let head_req = swift_http::Request {
            method: "HEAD".into(),
            path: "/v1/AUTH_test/c".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let head_resp = app
            .maybe_sharded_container_listing_async(head_req, "AUTH_test", "c")
            .await
            .expect("sharded head");
        assert_eq!(
            head_resp.headers.get("X-Container-Object-Count").as_deref(),
            Some("0"),
            "HEAD keeps root count, not listing length"
        );
        h.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sharded_listing_async_preserves_explicit_backend_policy() {
        let (port, h) = spawn_sharded_listing_backend().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let app = StdArc::new(ProxyApp::new(
            ring_on_port(port),
            ring_on_port(port),
            ProxyConfig {
                conn_timeout: Duration::from_millis(200),
                node_timeout: Duration::from_millis(400),
                ..ProxyConfig::default()
            },
        ));
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Backend-Storage-Policy-Index", "0");
        let req = swift_http::Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let resp = app
            .maybe_sharded_container_listing_async(req, "AUTH_test", "c")
            .await
            .expect("sharded fan-out");
        let body = resp.body.collect_async().await.expect("listing body");
        let listing: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(listing, serde_json::json!([]));
        h.abort();
    }

    async fn spawn_record_header_backend() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut head = Vec::new();
                let mut buffer = [0u8; 1024];
                while find_header_end(&head).is_none() {
                    let count = stream.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        return;
                    }
                    head.extend_from_slice(&buffer[..count]);
                    assert!(head.len() <= 64 * 1024);
                }
                let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
                let is_head = head.starts_with("head ");
                let record_type = if head
                    .lines()
                    .any(|line| line == "x-backend-record-type: shard")
                {
                    "shard"
                } else {
                    "object"
                };
                let body = if is_head { "" } else { "[]" };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nX-Backend-Sharding-State: unsharded\r\nX-Container-Object-Count: 0\r\nX-Backend-Record-Type: {record_type}\r\nX-Backend-Record-Shard-Format: namespace\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (port, handle)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn container_get_async_record_headers_match_python_direct_backend_contract() {
        let (port, handle) = spawn_record_header_backend().await;
        let app = StdArc::new(ProxyApp::new(
            ring_on_port(port),
            ring_on_port(port),
            ProxyConfig {
                conn_timeout: Duration::from_millis(200),
                node_timeout: Duration::from_millis(400),
                ..ProxyConfig::default()
            },
        ));
        for record_type in [
            None,
            Some("auto"),
            Some("banana"),
            Some("object"),
            Some("OBJECT"),
            Some("shard"),
            Some("SHARD"),
        ] {
            let mut headers = HeaderKeyDict::new();
            if let Some(kind) = record_type {
                headers.set("X-Backend-Record-Type", kind);
            }
            let req = swift_http::Request {
                method: "GET".into(),
                path: "/v1/AUTH_test/c".into(),
                query_string: "format=json".into(),
                headers,
                body: Body::empty(),
            };
            let resp = app.container_get_head_async(req, "AUTH_test", "c").await;
            assert_eq!(resp.status, 200, "record_type={record_type:?}");
            let explicit = record_type.is_some_and(|kind| {
                kind.eq_ignore_ascii_case("object") || kind.eq_ignore_ascii_case("shard")
            });
            let expected = record_type
                .filter(|_| explicit)
                .map(str::to_ascii_lowercase);
            assert_eq!(
                resp.headers.get("X-Backend-Record-Type"),
                expected.as_deref(),
                "record_type={record_type:?}"
            );
            assert_eq!(
                resp.headers.get("X-Backend-Record-Shard-Format"),
                explicit.then_some("namespace"),
                "record_type={record_type:?}"
            );
            assert_eq!(
                resp.headers.get("X-Backend-Sharding-State"),
                Some("unsharded")
            );
            assert_eq!(resp.body.collect_async().await.unwrap().as_slice(), b"[]");
        }
        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn container_get_async_record_headers_are_removed_after_shard_fanout() {
        let (port, handle) = spawn_sharded_listing_backend().await;
        let app = StdArc::new(ProxyApp::new(
            ring_on_port(port),
            ring_on_port(port),
            ProxyConfig {
                conn_timeout: Duration::from_millis(200),
                node_timeout: Duration::from_millis(400),
                ..ProxyConfig::default()
            },
        ));
        for record_type in [None, Some("auto"), Some("banana")] {
            let mut headers = HeaderKeyDict::new();
            if let Some(kind) = record_type {
                headers.set("X-Backend-Record-Type", kind);
            }
            let req = swift_http::Request {
                method: "GET".into(),
                path: "/v1/AUTH_test/c".into(),
                query_string: "format=json".into(),
                headers,
                body: Body::empty(),
            };
            let resp = app.container_get_head_async(req, "AUTH_test", "c").await;
            assert_eq!(resp.status, 200, "record_type={record_type:?}");
            assert!(!resp.headers.contains_key("X-Backend-Record-Type"));
            assert!(!resp.headers.contains_key("X-Backend-Record-Shard-Format"));
            let body = resp.body.collect_async().await.unwrap();
            let listing: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                listing,
                serde_json::json!([{"name": "obj-a"}, {"name": "obj-b"}])
            );
        }
        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn container_get_async_explicit_object_bypasses_shard_fanout() {
        let (port, h) = spawn_sharded_listing_backend().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let app = StdArc::new(ProxyApp::new(
            ring_on_port(port),
            ring_on_port(port),
            ProxyConfig {
                conn_timeout: Duration::from_millis(200),
                node_timeout: Duration::from_millis(400),
                ..ProxyConfig::default()
            },
        ));
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Backend-Record-Type", "object");
        let req = swift_http::Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let resp = app.container_get_head_async(req, "AUTH_test", "c").await;
        let body = resp.body.collect_async().await.expect("listing body");
        let listing: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(listing, serde_json::json!([]));
        h.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sharded_listing_async_honors_reverse_on() {
        let (port, h) = spawn_sharded_listing_backend().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let app = StdArc::new(ProxyApp::new(
            ring_on_port(port),
            ring_on_port(port),
            ProxyConfig {
                conn_timeout: Duration::from_millis(200),
                node_timeout: Duration::from_millis(400),
                ..ProxyConfig::default()
            },
        ));
        let req = swift_http::Request {
            method: "GET".into(),
            path: "/v1/AUTH_test/c".into(),
            query_string: "reverse=on".into(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        };
        let resp = app
            .maybe_sharded_container_listing_async(req, "AUTH_test", "c")
            .await
            .expect("sharded fan-out");
        assert_eq!(resp.status, 200, "{}", resp.reason);
        let body = resp.body.collect_async().await.expect("listing body");
        let listing: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(listing[0]["name"], "obj-b", "{listing:?}");
        assert_eq!(listing[1]["name"], "obj-a", "{listing:?}");
        h.abort();
    }
}
