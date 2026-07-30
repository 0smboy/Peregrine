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

//! Fire-and-forget OTLP/HTTP trace export (one [`TraceSpan`] per request).
//!
//! Hand-rolled rather than the opentelemetry SDK: that stack drags an async
//! runtime and an HTTP client into every server binary, when all this needs
//! is a bounded queue, one background thread that batches spans (64 max or a
//! 1s flush) and POSTs each batch as OTLP JSON to `/v1/traces` over a plain
//! `TcpStream`. An empty endpoint disables the exporter entirely (every
//! method is a no-op), matching how an empty `log_statsd_host` disables
//! statsd. The request path never blocks or errors: a full queue drops the
//! span, and drops / unreachable-collector failures are logged at most once
//! a minute.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::obslog::Logger;

const MAX_BATCH: usize = 64;
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
const QUEUE_CAPACITY: usize = 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const WARN_INTERVAL_SECS: u64 = 60;

/// An attribute value in the two OTLP encodings this exporter emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    Str(String),
    Int(i64),
}

/// One finished span, ready to export.
#[derive(Debug, Clone)]
pub struct TraceSpan {
    pub name: String,
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub start_unix_nanos: u128,
    pub end_unix_nanos: u128,
    pub attributes: Vec<(String, AttrValue)>,
}

/// `N` random-ish id bytes. std has no RNG and `rand` is not worth a new
/// dependency for two ids per request: SipHash keyed by `RandomState`
/// (OS-seeded, distinct keys per call) over the clock, a global counter,
/// and caller-supplied entropy (e.g. the transaction id) gives
/// well-distributed non-cryptographic ids, which is all OTLP asks of them.
pub fn random_id<const N: usize>(entropy: &[u8]) -> [u8; N] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut out = [0u8; N];
    for (round, block) in out.chunks_mut(8).enumerate() {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u128(nanos);
        hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
        hasher.write_usize(round);
        hasher.write(entropy);
        let word = hasher.finish().to_be_bytes();
        block.copy_from_slice(&word[..block.len()]);
    }
    if out == [0u8; N] {
        // an all-zero trace/span id is "absent" in OTLP
        out[N - 1] = 1;
    }
    out
}

/// TraceIdRatioBased sampling: the id's first 8 bytes as a u64 against
/// `ratio * 2^64`, so the decision is deterministic per trace id.
pub fn sampled(trace_id: &[u8; 16], ratio: f64) -> bool {
    if ratio >= 1.0 {
        return true;
    }
    if ratio <= 0.0 {
        return false;
    }
    let word = u64::from_be_bytes(trace_id[..8].try_into().unwrap());
    (word as f64) < ratio * (u64::MAX as f64)
}

/// A background OTLP/HTTP span exporter. Disabled (every method is a
/// no-op) when constructed with an empty endpoint.
#[derive(Debug)]
pub struct TraceExporter {
    sender: Option<SyncSender<TraceSpan>>,
    sample_ratio: f64,
    dropped: AtomicU64,
    last_drop_warn: AtomicU64,
    logger: Arc<Logger>,
}

impl TraceExporter {
    /// Spawn the export thread for `endpoint` (`host:port` of an OTLP/HTTP
    /// collector). An empty `endpoint` yields a disabled exporter with no
    /// thread and no queue.
    pub fn new(
        endpoint: &str,
        sample_ratio: f64,
        service_name: &str,
        logger: Arc<Logger>,
    ) -> Arc<TraceExporter> {
        let sender = (!endpoint.is_empty()).then(|| {
            let (sender, receiver) = std::sync::mpsc::sync_channel(QUEUE_CAPACITY);
            let endpoint = endpoint.to_string();
            let service_name = service_name.to_string();
            let thread_logger = Arc::clone(&logger);
            std::thread::spawn(move || {
                export_loop(receiver, &endpoint, &service_name, &thread_logger)
            });
            sender
        });
        Arc::new(TraceExporter {
            sender,
            sample_ratio,
            dropped: AtomicU64::new(0),
            last_drop_warn: AtomicU64::new(0),
            logger,
        })
    }

    pub fn enabled(&self) -> bool {
        self.sender.is_some()
    }

    /// Queue a span for export; never blocks. Unsampled spans are discarded
    /// here, and a full queue drops the span (counted, warned at most once
    /// a minute) rather than slow the request path.
    pub fn submit(&self, span: TraceSpan) {
        let Some(sender) = &self.sender else { return };
        if !sampled(&span.trace_id, self.sample_ratio) {
            return;
        }
        if sender.try_send(span).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            if warn_due(&self.last_drop_warn) {
                let count = self.dropped.swap(0, Ordering::Relaxed);
                self.logger.warning(&format!(
                    "trace exporter: dropped {count} span(s), queue full"
                ));
            }
        }
    }
}

/// Lock-free once-a-minute limiter: claim the warn slot by CASing the
/// stored unix-seconds timestamp forward.
fn warn_due(last_warn_epoch_secs: &AtomicU64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let last = last_warn_epoch_secs.load(Ordering::Relaxed);
    now >= last.saturating_add(WARN_INTERVAL_SECS)
        && last_warn_epoch_secs
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

/// Batch spans off the queue (up to [`MAX_BATCH`], flushing [`FLUSH_INTERVAL`]
/// after the first) and POST each batch. A failed POST drops the batch with a
/// rate-limited warning — no retries, so an unreachable collector costs one
/// connect attempt per batch at most.
fn export_loop(receiver: Receiver<TraceSpan>, endpoint: &str, service_name: &str, logger: &Logger) {
    let last_post_warn = AtomicU64::new(0);
    loop {
        let Ok(first) = receiver.recv() else { return };
        let mut batch = vec![first];
        let deadline = Instant::now() + FLUSH_INTERVAL;
        let mut disconnected = false;
        while batch.len() < MAX_BATCH && !disconnected {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match receiver.recv_timeout(left) {
                Ok(span) => batch.push(span),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => disconnected = true,
            }
        }
        if let Err(e) = post_batch(endpoint, service_name, &batch) {
            if warn_due(&last_post_warn) {
                logger.warning(&format!(
                    "trace exporter: dropping batch, {endpoint} unreachable: {e}"
                ));
            }
        }
        if disconnected {
            return;
        }
    }
}

fn post_batch(endpoint: &str, service_name: &str, spans: &[TraceSpan]) -> std::io::Result<()> {
    let body = encode_batch(service_name, spans).to_string();
    let addr = endpoint.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "endpoint resolved to no address",
        )
    })?;
    let mut stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT)?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(
        format!(
            "POST /v1/traces HTTP/1.1\r\nHost: {endpoint}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )?;
    stream.write_all(body.as_bytes())?;
    // Drain the response (status is irrelevant — fire and forget) so closing
    // our end cannot RST the collector before it reads the whole request.
    let mut sink = [0u8; 1024];
    while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
    Ok(())
}

/// The OTLP JSON request body: `resourceSpans[].scopeSpans[].spans[]`, ids as
/// lowercase hex, and — per the proto3 JSON mapping of int64/fixed64 — nano
/// timestamps and `intValue` attributes as decimal strings.
fn encode_batch(service_name: &str, spans: &[TraceSpan]) -> serde_json::Value {
    let spans: Vec<serde_json::Value> = spans
        .iter()
        .map(|span| {
            let attributes: Vec<serde_json::Value> = span
                .attributes
                .iter()
                .map(|(key, value)| serde_json::json!({"key": key, "value": attr_value(value)}))
                .collect();
            serde_json::json!({
                "traceId": hex(&span.trace_id),
                "spanId": hex(&span.span_id),
                "name": span.name,
                // SPAN_KIND_SERVER: the span covers handling one inbound request
                "kind": 2,
                "startTimeUnixNano": span.start_unix_nanos.to_string(),
                "endTimeUnixNano": span.end_unix_nanos.to_string(),
                "attributes": attributes,
            })
        })
        .collect();
    serde_json::json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": service_name}},
                ],
            },
            "scopeSpans": [{
                "scope": {"name": "swift-otlp"},
                "spans": spans,
            }],
        }],
    })
}

fn attr_value(value: &AttrValue) -> serde_json::Value {
    match value {
        AttrValue::Str(s) => serde_json::json!({"stringValue": s}),
        AttrValue::Int(i) => serde_json::json!({"intValue": i.to_string()}),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obslog::LogLevel;
    use std::net::TcpListener;

    fn span(name: &str) -> TraceSpan {
        TraceSpan {
            name: name.to_string(),
            trace_id: random_id::<16>(b"txtest"),
            span_id: random_id::<8>(&[]),
            start_unix_nanos: 1_700_000_000_000_000_000,
            end_unix_nanos: 1_700_000_000_250_000_000,
            attributes: vec![
                (
                    "http.request.method".to_string(),
                    AttrValue::Str("PUT".to_string()),
                ),
                ("http.response.status_code".to_string(), AttrValue::Int(201)),
            ],
        }
    }

    #[test]
    fn otlp_json_encoding_matches_the_wire_format() {
        let fixed = TraceSpan {
            name: "swift.proxy GET".to_string(),
            trace_id: *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            span_id: *b"\x10\x11\x12\x13\x14\x15\x16\x17",
            start_unix_nanos: 1_700_000_000_000_000_000,
            end_unix_nanos: 1_700_000_000_250_000_000,
            attributes: vec![
                (
                    "http.request.method".to_string(),
                    AttrValue::Str("GET".to_string()),
                ),
                ("http.response.status_code".to_string(), AttrValue::Int(200)),
                (
                    "url.path".to_string(),
                    AttrValue::Str("/v1/AUTH_test/c/o".to_string()),
                ),
            ],
        };
        let body = encode_batch("swift-proxy", &[fixed]);

        let resource_attr = &body["resourceSpans"][0]["resource"]["attributes"][0];
        assert_eq!(resource_attr["key"], "service.name");
        assert_eq!(resource_attr["value"]["stringValue"], "swift-proxy");

        let span = &body["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["traceId"], "000102030405060708090a0b0c0d0e0f");
        assert_eq!(span["spanId"], "1011121314151617");
        assert_eq!(span["name"], "swift.proxy GET");
        assert_eq!(span["kind"], 2);
        // proto3 JSON renders fixed64 nanos and int64 values as strings
        assert_eq!(span["startTimeUnixNano"], "1700000000000000000");
        assert_eq!(span["endTimeUnixNano"], "1700000000250000000");
        assert_eq!(span["attributes"][0]["key"], "http.request.method");
        assert_eq!(span["attributes"][0]["value"]["stringValue"], "GET");
        assert_eq!(span["attributes"][1]["key"], "http.response.status_code");
        assert_eq!(span["attributes"][1]["value"]["intValue"], "200");
        assert_eq!(
            span["attributes"][2]["value"]["stringValue"],
            "/v1/AUTH_test/c/o"
        );
    }

    #[test]
    fn random_ids_are_distinct_and_nonzero() {
        let a = random_id::<16>(b"tx1");
        let b = random_id::<16>(b"tx1");
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 16]);
        assert_ne!(random_id::<8>(&[]), [0u8; 8]);
    }

    #[test]
    fn sampling_ratio_bounds_and_determinism() {
        for i in 0..64u8 {
            let id = random_id::<16>(&[i]);
            assert!(!sampled(&id, 0.0));
            assert!(sampled(&id, 1.0));
        }
        let id = random_id::<16>(b"x");
        assert_eq!(sampled(&id, 0.5), sampled(&id, 0.5));
    }

    #[test]
    fn empty_endpoint_disables_the_exporter() {
        let exporter = TraceExporter::new("", 1.0, "swift-proxy", Logger::new("t", LogLevel::Info));
        assert!(!exporter.enabled());
        // No panic, no queue, no thread: fire and forget on a disabled exporter.
        exporter.submit(span("swift.proxy GET"));
    }

    /// Everything up to `\r\n\r\n` plus a Content-Length body has arrived.
    fn request_complete(raw: &[u8]) -> bool {
        let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&raw[..head_end]);
        let content_length = head
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        raw.len() >= head_end + 4 + content_length
    }

    /// A one-request collector stub: accept (polling, bounded), read one full
    /// request, answer 200, and hand the raw request back.
    fn collector_stub(listener: TcpListener) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "exporter never connected");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept failed: {e}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            while !request_complete(&raw) {
                let n = stream.read(&mut buf).expect("read request");
                assert!(n > 0, "peer closed mid-request");
                raw.extend_from_slice(&buf[..n]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            String::from_utf8(raw).unwrap()
        })
    }

    #[test]
    fn exporter_posts_spans_to_the_collector() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stub = collector_stub(listener);

        let exporter = TraceExporter::new(
            &format!("127.0.0.1:{port}"),
            1.0,
            "swift-proxy",
            Logger::new("t", LogLevel::Info),
        );
        assert!(exporter.enabled());
        let sent = span("swift.proxy PUT");
        let expected_trace_id = hex(&sent.trace_id);
        exporter.submit(sent);

        let request = stub.join().unwrap();
        let (head, body) = request.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("POST /v1/traces HTTP/1.1\r\n"), "{head}");
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: application/json"),
            "{head}"
        );
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        let span = &parsed["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(span["name"], "swift.proxy PUT");
        let trace_id = span["traceId"].as_str().unwrap();
        let span_id = span["spanId"].as_str().unwrap();
        assert_eq!(trace_id.len(), 32);
        assert_eq!(span_id.len(), 16);
        assert!(trace_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(span_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(trace_id, expected_trace_id);
    }

    #[test]
    fn ratio_zero_never_contacts_the_collector() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let exporter = TraceExporter::new(
            &format!("127.0.0.1:{port}"),
            0.0,
            "swift-proxy",
            Logger::new("t", LogLevel::Info),
        );
        for _ in 0..8 {
            exporter.submit(span("swift.proxy GET"));
        }
        // Past the flush interval: had anything been enqueued, the export
        // thread would have connected by now.
        std::thread::sleep(FLUSH_INTERVAL + Duration::from_millis(500));
        match listener.accept() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("collector was contacted: {other:?}"),
        }
    }
}
