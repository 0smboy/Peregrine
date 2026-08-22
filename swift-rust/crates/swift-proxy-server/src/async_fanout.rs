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
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use swift_http::{Body, HeaderKeyDict, IncomingBody, Response, STREAM_CHUNK};
use swift_runtime::{
    CancellationToken, FanoutGroup, QuorumTracker, SharedWindow, TaskScope,
};

use swift_core::config::config_true_value;
use swift_core::storage_policy::quorum_size;
use swift_core::timestamp::Timestamp;

use super::{
    account_info_from_response, backend_404_timestamp, fill_container_info_from_head,
    info_cache_time, is_good_source, percent_encode, post_existence_proof_guard, resp_header,
    source_timestamp, swob_response, AccountInfo, BackendResponse, ContainerInfo, Node, ProxyApp,
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
            return Err(io::Error::new(io::ErrorKind::TimedOut, "backend read timeout"));
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
        let slots = per_node_headers.len().max(1);
        let mut group: FanoutGroup<Option<BackendResponse>> =
            match FanoutGroup::new(slots, slots) {
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
        let wait = self.config.conn_timeout + self.config.node_timeout;
        for _ in 0..expected {
            match tokio::time::timeout(wait, group.recv()).await {
                Ok(Some(Some(resp))) => {
                    if (200..500).contains(&resp.status) {
                        tracker.record_success();
                    } else {
                        tracker.record_failure();
                    }
                    results.push(resp);
                    if tracker.has_quorum() {
                        group.cancel_unused();
                        break;
                    }
                }
                Ok(Some(None)) | Ok(None) | Err(_) => {}
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
        let content_length = body.content_length();
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
                putters = tee_one_chunk(
                    putters,
                    piece.to_vec(),
                    chunked,
                    node_timeout,
                )
                .await;
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
                    let body = leftover_then_read(
                        &mut leftover,
                        &mut reader,
                        content_length,
                        node_timeout,
                    )
                    .await
                    .unwrap_or_default();
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
                        if is_object && ts > latest_404_timestamp {
                            latest_404_timestamp = ts;
                        }
                        if recorded_404.is_none() {
                            match buffer_backend_body(head, swift_http::MAX_CONTROL_BODY, !is_head, idle)
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
                        match buffer_backend_body(head, swift_http::MAX_CONTROL_BODY, !is_head, idle)
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
            cors: super::CorsInfo::default(),
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
            if let Some(ttl) = info_cache_time(
                resp.status,
                resp.headers.get("X-Backend-Recheck-Account-Existence"),
                self.config.recheck_account_existence,
            ) {
                self.info_cache
                    .set_account(account.to_string(), info.clone(), ttl);
            }
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
        let arr = if let Some(a) = self
            .fetch_json_array_first_nonempty_async(
                &nodes,
                part,
                &path,
                "states=updating&format=json",
                &shard_headers,
            )
            .await
            .filter(|a| !a.is_empty())
        {
            a
        } else {
            self.fetch_listing_shard_ranges_async(nodes, part, &path, &shard_headers)
                .await?
        };
        let mut best: Option<&serde_json::Value> = None;
        for sr in &arr {
            let name = sr.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if !name.contains('/') {
                continue;
            }
            if name == format!("{account}/{container}") {
                continue;
            }
            let lower = sr.get("lower").and_then(|v| v.as_str()).unwrap_or("");
            let upper = sr.get("upper").and_then(|v| v.as_str()).unwrap_or("");
            if !lower.is_empty() && object <= lower {
                continue;
            }
            if !upper.is_empty() && object > upper {
                continue;
            }
            best = Some(sr);
            break;
        }
        let name = best?.get("name")?.as_str()?;
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
        let policy_index: i64 = match header_policy {
            Some(p) => p,
            None => {
                self.container_info_async(account, container)
                    .await
                    .policy_index
            }
        };
        let Some(object_ring) = self.object_ring_for(policy_index) else {
            return Response::with_body(
                503,
                format!("No object ring configured for storage policy {policy_index}").into_bytes(),
            );
        };
        let Ok((object_part, _)) = object_ring.get_nodes(account, Some(container), Some(object))
        else {
            return swob_response(503);
        };
        let path = format!(
            "/{}/{}/{}",
            percent_encode(account),
            percent_encode(container),
            percent_encode(object)
        );
        let mut headers = self.backend_headers(req, false, "object");
        headers.set("X-Backend-Storage-Policy-Index", policy_index);
        for h in [
            "Range",
            "If-Match",
            "If-None-Match",
            "If-Modified-Since",
            "If-Unmodified-Since",
            "X-Newest",
            "X-Open-Expired",
            "X-Backend-Ignore-Range-If-Metadata-Present",
        ] {
            if let Some(v) = req.headers.get(h) {
                headers.set(h, v.to_string());
            }
        }
        if self.ec_policies.contains_key(&policy_index) {
            return self
                .ec_get_async(req, &path, policy_index, object_ring, object_part)
                .await;
        }
        let nodes = self.iter_nodes(object_ring, object_part);
        self.get_or_head_async(
            "object",
            nodes,
            object_part,
            &req.method,
            &path,
            &req.query_string,
            &headers,
        )
        .await
        .unwrap_or_else(|| swob_response(503))
    }

    pub(crate) async fn ec_get_async(
        self: &Arc<Self>,
        req: &mut swift_http::Request,
        path: &str,
        policy_index: i64,
        object_ring: &swift_ring::Ring,
        object_part: u32,
    ) -> Response {
        let Some(&ec) = self.ec_policies.get(&policy_index) else {
            return swob_response(503);
        };
        #[cfg(not(feature = "ec"))]
        {
            let _ = (req, path, object_ring, object_part, ec);
            return Response::with_body(
                501,
                b"erasure coding not built (compile with --features ec)".to_vec(),
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
            if let Some(v) = req.headers.get("X-Open-Expired") {
                headers.set("X-Open-Expired", v.to_string());
            }
            self.ec_get_async_inner(
                is_head,
                headers,
                path,
                policy_index,
                object_ring,
                object_part,
                ec,
            )
            .await
        }
    }

    #[cfg(feature = "ec")]
    async fn ec_get_async_inner(
        self: &Arc<Self>,
        is_head: bool,
        headers: HeaderKeyDict,
        path: &str,
        _policy_index: i64,
        object_ring: &swift_ring::Ring,
        object_part: u32,
        ec: super::EcPolicyParams,
    ) -> Response {
        use swift_ec::EcDriver;
        let nodes = self.iter_nodes(object_ring, object_part);
        let mut sources: std::collections::HashMap<i32, AsyncBackendHead> =
            std::collections::HashMap::new();
        let mut meta: Option<Vec<(String, String)>> = None;
        let mut saw_404 = false;
        for node in nodes {
            match backend_request_head_async(
                &node,
                object_part,
                "GET",
                path,
                "",
                &headers,
                b"",
                self.config.conn_timeout,
                self.config.node_timeout,
            )
            .await
            {
                Ok(head) if head.status == 200 => {
                    let fi = resp_header(&head.headers, "X-Object-Sysmeta-Ec-Frag-Index")
                        .and_then(|v| v.parse::<i32>().ok());
                    if let Some(fi) = fi {
                        if sources.len() >= ec.ndata && !sources.contains_key(&fi) {
                            continue;
                        }
                        if meta.is_none() {
                            meta = Some(head.headers.clone());
                        }
                        sources.entry(fi).or_insert(head);
                    }
                }
                Ok(head) if head.status == 404 => saw_404 = true,
                Ok(head) if head.status == 507 => self.error_limiter.limit(&node),
                Ok(head) if head.status >= 500 => self.error_limiter.increment(&node),
                Ok(_) => {}
                Err(_) => self.error_limiter.increment(&node),
            }
        }
        if sources.len() < ec.ndata {
            return if saw_404 && sources.is_empty() {
                swob_response(404)
            } else {
                swob_response(503)
            };
        }
        let meta = meta.unwrap_or_default();
        let ec_etag = resp_header(&meta, "X-Object-Sysmeta-Ec-Etag")
            .unwrap_or_default()
            .to_string();
        let orig_size: usize = resp_header(&meta, "X-Object-Sysmeta-Ec-Content-Length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let _content_type = resp_header(&meta, "Content-Type")
            .unwrap_or("application/octet-stream")
            .to_string();
        let mut resp = Response::new(200);
        for (k, v) in &meta {
            let kl = k.to_lowercase();
            let keep = kl == "content-type"
                || kl == "x-timestamp"
                || kl == "last-modified"
                || (kl.starts_with("x-object-meta-") && kl.len() > "x-object-meta-".len());
            if keep {
                resp.headers.set(k, v);
            }
        }
        if !ec_etag.is_empty() {
            resp.headers.set("ETag", &ec_etag);
        }
        resp.headers.set("Content-Length", orig_size);
        resp.headers.set("Accept-Ranges", "bytes");
        if is_head {
            return resp;
        }
        let driver = match EcDriver::new(ec.ndata, ec.nparity) {
            Ok(d) => d,
            Err(e) => return Response::with_body(500, format!("EC init failed: {e:?}").into_bytes()),
        };
        let idle = self.config.node_timeout;
        let mut heads: Vec<AsyncBackendHead> = sources.into_values().take(ec.ndata).collect();
        let seg_sizes = super::ec_segment_sizes(orig_size, ec.segment_size);
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let scope = TaskScope::bounded(1);
        let _ = scope.spawn(async move {
            for seg_len in seg_sizes {
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
                        if tx.send(Ok(decoded)).await.is_err() {
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
        });
        resp.body = Body::from_channel(rx, Some(orig_size as u64), scope);
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
            let _ = (req, account, container, path, policy_index, object_ring, object_part, body);
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
        let archive_len = client_len.map(|total| super::ec_archive_size(&driver, ec.segment_size, total));
        let put_ts = Timestamp::now();
        let ts = put_ts.internal();
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
        let nodes = self.iter_nodes(object_ring, object_part);
        let mut putters: Vec<AsyncMimePutter> = Vec::new();
        let mut earlies: Vec<u16> = Vec::new();
        let wait = self.config.conn_timeout + self.config.node_timeout;
        let node_timeout = self.config.node_timeout;
        let conn_timeout = self.config.conn_timeout;
        for (i, node) in nodes.into_iter().take(n).enumerate() {
            match connect_mime_putter_async(
                &node,
                object_part,
                path,
                &per_node[i.min(per_node.len().saturating_sub(1))],
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
                }
                Ok(AsyncMimeOutcome::EarlyFinal(status)) => earlies.push(status),
                Err(_) => self.error_limiter.increment(&node),
            }
        }
        if earlies.contains(&412) {
            return swob_response(412);
        }
        if earlies.contains(&409) {
            return swob_response(202);
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
                if let Err(resp) = tee_ec_segment(&mut putters, &driver, &segment, node_timeout).await
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
            if let Err(resp) = tee_ec_segment(&mut putters, &driver, &seg_buf, node_timeout).await
            {
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
        let header_policy: Option<i64> = req
            .headers
            .get("X-Backend-Storage-Policy-Index")
            .and_then(|v| v.parse().ok());
        let info = self.container_info_async(account, container).await;
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
        let container_nodes = self.iter_nodes(&self.container_ring, container_part);
        let mut base = self.backend_headers(req, true, "object");
        base.set("X-Timestamp", Timestamp::now().internal());
        base.set("X-Backend-Storage-Policy-Index", policy_index);
        if upd_account != account || upd_container != container {
            base.set(
                "X-Backend-Container-Path",
                format!("{upd_account}/{upd_container}"),
            );
            base.set("X-Backend-Allow-Reserved-Names", "true");
        }
        let node_number = object_ring
            .get_part_nodes(object_part)
            .map(|n| n.len())
            .unwrap_or(1);
        let mut per_node = Vec::with_capacity(node_number);
        for i in 0..node_number {
            let mut headers = base.clone();
            if !container_nodes.is_empty() {
                let cont = &container_nodes[i % container_nodes.len()];
                headers.set("X-Container-Host", format!("{}:{}", cont.ip, cont.port));
                headers.set("X-Container-Partition", container_part);
                headers.set("X-Container-Device", &cont.device);
            }
            per_node.push(headers);
        }
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
            self.iter_nodes(ring, part).into_iter().collect::<VecDeque<_>>(),
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
                    match backend_request_async(
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
                    .await
                    {
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
            .get_or_head_async(
                "account",
                nodes,
                part,
                &method,
                &path,
                &query,
                &headers,
            )
            .await
        {
            Some(resp) if resp.status == 404 && self.config.account_autocreate => {
                super::synthesized_account_listing(&req)
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
        let record_type = req
            .headers
            .get("X-Backend-Record-Type")
            .unwrap_or("")
            .to_ascii_lowercase();
        let is_head = req.method == "HEAD";
        if record_type != "shard" && !req.query_string.contains("states=") {
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
        }
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
        self.make_requests_async(nodes, node_number, part, method, path, query, per_node, Vec::new())
            .await
    }

    pub(crate) async fn account_post_async(
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
                .make_write_async(
                    nodes,
                    node_count,
                    part,
                    &method,
                    &path,
                    &query,
                    per_node,
                )
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
        let Ok((container_part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return swob_response(503);
        };
        let acct_status = self.account_info_async(account).await.status;
        if !(200..300).contains(&acct_status) {
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
        self.info_cache.clear_container(&cache_key);
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

    pub(crate) async fn container_put_async(
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
        let acct_status = self.account_info_async(account).await.status;
        if !(200..300).contains(&acct_status) {
            if self.config.account_autocreate {
                if !self.autocreate_account(account) {
                    return swob_response(503);
                }
                let refreshed = self.account_info_async(account).await.status;
                if !(200..300).contains(&refreshed) {
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
        let account_nodes = self.iter_nodes(&self.account_ring, account_part);
        let node_number = self
            .container_ring
            .get_part_nodes(container_part)
            .map(|n| n.len())
            .unwrap_or(1);
        let mut per_node = Vec::with_capacity(node_number);
        for i in 0..node_number {
            let mut headers = base.clone();
            if !account_nodes.is_empty() {
                let acct = &account_nodes[i % account_nodes.len()];
                headers.set("X-Account-Host", format!("{}:{}", acct.ip, acct.port));
                headers.set("X-Account-Partition", account_part);
                headers.set("X-Account-Device", &acct.device);
            }
            per_node.push(headers);
        }
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

    async fn fetch_listing_shard_ranges_async(
        self: &Arc<Self>,
        nodes: Vec<Node>,
        part: u32,
        path: &str,
        shard_headers: &HeaderKeyDict,
    ) -> Option<Vec<serde_json::Value>> {
        if let Some(arr) = self
            .fetch_json_array_first_nonempty_async(
                &nodes,
                part,
                path,
                "states=listing&format=json",
                shard_headers,
            )
            .await
        {
            if !arr.is_empty() {
                return Some(arr);
            }
        }
        let broad = self
            .fetch_json_array_first_nonempty_async(&nodes, part, path, "format=json", shard_headers)
            .await?;
        Some(super::prefer_listing_state_ranges(&broad))
    }

    pub(crate) async fn maybe_sharded_container_listing_async(
        self: &Arc<Self>,
        req: swift_http::Request,
        account: &str,
        container: &str,
    ) -> Option<Response> {
        let marker = req.param("marker").unwrap_or_default();
        let prefix = req.param("prefix").unwrap_or_default();
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
        let Ok((part, _)) = self
            .container_ring
            .get_nodes(account, Some(container), None)
        else {
            return None;
        };
        let path = format!("/{}/{}", percent_encode(account), percent_encode(container));
        let nodes = self.iter_nodes(&self.container_ring, part);
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
        let object_count = head
            .headers
            .get("X-Container-Object-Count")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        if !super::should_probe_sharded_listing(&state, object_count) {
            return None;
        }
        let arr = self
            .fetch_listing_shard_ranges_async(nodes.clone(), part, &path, &shard_headers)
            .await?;
        if !super::should_fanout_sharded_listing(&state, object_count, !arr.is_empty()) {
            return None;
        }
        let selected = super::select_listing_shard_ranges(&arr, &marker, &prefix);
        let mut shard_listings: Vec<Vec<serde_json::Value>> = Vec::new();
        if object_count > 0 {
            let mut qs_parts = vec!["format=json".to_string()];
            if !marker.is_empty() {
                qs_parts.push(format!("marker={}", percent_encode(&marker)));
            }
            if !prefix.is_empty() {
                qs_parts.push(format!("prefix={}", percent_encode(&prefix)));
            }
            qs_parts.push(format!("limit={limit}"));
            if let Some(items) = self
                .fetch_json_array_first_nonempty_async(
                    &nodes,
                    part,
                    &path,
                    &qs_parts.join("&"),
                    &root_headers,
                )
                .await
            {
                if !items.is_empty() {
                    shard_listings.push(items);
                }
            }
        }
        for sr in &selected {
            let name = sr.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let (shard_account, shard_container) = match name.split_once('/') {
                Some((a, c)) => (a, c),
                None => continue,
            };
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
            let remaining =
                limit.saturating_sub(shard_listings.iter().map(|v| v.len()).sum::<usize>());
            if remaining == 0 {
                break;
            }
            let mut qs_parts = vec!["format=json".to_string()];
            if !marker.is_empty() {
                qs_parts.push(format!("marker={}", percent_encode(&marker)));
            }
            if !prefix.is_empty() {
                qs_parts.push(format!("prefix={}", percent_encode(&prefix)));
            }
            qs_parts.push(format!("limit={remaining}"));
            let Some(items) = self
                .fetch_json_array_first_nonempty_async(
                    &snodes,
                    spart,
                    &spath,
                    &qs_parts.join("&"),
                    &listing_headers,
                )
                .await
            else {
                continue;
            };
            if !items.is_empty() {
                shard_listings.push(items);
            }
        }
        let merged = super::merge_sharded_object_listings(&shard_listings, limit);
        let bytes = serde_json::to_vec(&merged).unwrap_or_else(|_| b"[]".to_vec());
        let mut out = Response::with_body(200, bytes);
        out.headers
            .set("Content-Type", "application/json; charset=utf-8");
        out.headers.set("X-Backend-Sharding-State", state);
        out.headers.set("X-Backend-Record-Type", "object");
        out.headers
            .set("X-Container-Object-Count", merged.len().to_string());
        if let Some(bytes_used) = head.headers.get("X-Container-Bytes-Used") {
            out.headers.set("X-Container-Bytes-Used", bytes_used);
        }
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
        let info = self.container_info_async(account, container).await;
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
        let container_nodes = self.iter_nodes(&self.container_ring, container_part);
        let mut base = self.backend_headers(req, true, "object");
        base.set("X-Timestamp", Timestamp::now().internal());
        base.set("X-Backend-Storage-Policy-Index", policy_index);
        if upd_account != account || upd_container != container {
            base.set(
                "X-Backend-Container-Path",
                format!("{upd_account}/{upd_container}"),
            );
            base.set("X-Backend-Allow-Reserved-Names", "true");
        }
        let node_number = object_ring
            .get_part_nodes(object_part)
            .map(|n| n.len())
            .unwrap_or(1);
        let mut per_node = Vec::with_capacity(node_number);
        for i in 0..node_number {
            let mut headers = base.clone();
            if !container_nodes.is_empty() {
                let cont = &container_nodes[i % container_nodes.len()];
                headers.set("X-Container-Host", format!("{}:{}", cont.ip, cont.port));
                headers.set("X-Container-Partition", container_part);
                headers.set("X-Container-Device", &cont.device);
            }
            per_node.push(headers);
        }
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
        let acct_status = self.account_info_async(account).await.status;
        if !(200..300).contains(&acct_status) {
            return swob_response(404);
        }
        let mut base = self.backend_headers(&req, true, "container");
        base.set("X-Timestamp", Timestamp::now().internal());
        let account_nodes = self.iter_nodes(&self.account_ring, account_part);
        let node_number = self
            .container_ring
            .get_part_nodes(container_part)
            .map(|n| n.len())
            .unwrap_or(1);
        let mut per_node = Vec::with_capacity(node_number);
        for i in 0..node_number {
            let mut headers = base.clone();
            if !account_nodes.is_empty() {
                let acct = &account_nodes[i % account_nodes.len()];
                headers.set("X-Account-Host", format!("{}:{}", acct.ip, acct.port));
                headers.set("X-Account-Partition", account_part);
                headers.set("X-Account-Device", &acct.device);
            }
            per_node.push(headers);
        }
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
            path: format!(
                "/v1/{}/{}/{}",
                src_account, src_container, src_object
            ),
            query_string: String::new(),
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
        put_headers.set(
            "X-Copied-From",
            format!("{src_container}/{src_object}"),
        );
        put_headers.set("X-Copied-From-Account", src_account.clone());
        req.method = "PUT".into();
        req.headers = put_headers;
        let mut incoming = body_to_incoming(source.body.take());
        let mut resp = self
            .object_put_async(&mut req, dst_account, dst_container, dst_object, &mut incoming)
            .await;
        resp.headers
            .set("X-Copied-From", format!("{src_container}/{src_object}"));
        resp.headers
            .set("X-Copied-From-Account", src_account);
        resp
    }
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
        || lname.starts_with("x-object-meta-")
        || lname.starts_with("x-object-sysmeta-")
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
            tokio::time::timeout(idle, reader.take(swift_http::MAX_CONTROL_BODY).read_to_end(&mut body))
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
    use swift_core::hashing::HashPathConfig;
    use swift_http::{HeaderKeyDict, IncomingBody};
    use swift_ring::{Ring, RingData, RingDevice};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
                    .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        });
        (port, h)
    }

    async fn spawn_put_ok_backend(reads: StdArc<AtomicUsize>) -> (u16, tokio::task::JoinHandle<()>) {
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
            resp.status, 201,
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
        let mut c = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(400)).unwrap();
        use std::io::{Read, Write};
        c.set_read_timeout(Some(Duration::from_millis(2500))).unwrap();
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
            text.to_ascii_lowercase().contains("x-copied-from: srcc/srco"),
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
                        .write_all(b"HTTP/1.1 200 OK\r\nX-Backend-Sharding-State: sharded\r\nX-Container-Object-Count: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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
                    let body = br#"[{"name":"obj-a"}]"#;
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
        let body = resp.body.collect_async().await.expect("listing body");
        let listing: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(listing[0]["name"], "obj-a");
        h.abort();
    }
}
