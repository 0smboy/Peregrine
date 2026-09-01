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

//! Request/response bodies that are either fully in memory or a lazily
//! consumed stream, plus the reader combinators the data path is built
//! from. This is what lets a 5GB object flow proxy->object-server->disk
//! through 64KB buffers instead of being materialized at every hop.

use std::io::{Cursor, Read};
use std::sync::Arc;

/// Cap for materializing control-plane bodies (auth requests, REPLICATE
/// args, listings, manifests). Object data must never be materialized
/// against this - stream it instead.
pub const MAX_CONTROL_BODY: u64 = 64 * 1024 * 1024;

/// The copy-loop chunk size used across the streaming data path.
pub const STREAM_CHUNK: usize = 64 * 1024;

/// A body: fully buffered, a blocking stream, or a bounded async channel
/// (GET disk chunks pulled independently of the client write).
pub enum Body {
    Buffered(Vec<u8>),
    Streamed(StreamedBody),
    /// Producer is a [`swift_runtime::TaskScope`] child; capacity is 1 chunk.
    Channel(ChannelBody),
}

/// Bounded response-body channel. The producer reads the next disk chunk
/// only after the previous chunk is taken (slow client does not pin a
/// storage worker).
pub struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Result<Vec<u8>, std::io::Error>>,
    content_length: Option<u64>,
    _scope: Option<swift_runtime::TaskScope>,
}

impl ChannelBody {
    pub fn new(
        rx: tokio::sync::mpsc::Receiver<Result<Vec<u8>, std::io::Error>>,
        content_length: Option<u64>,
        scope: swift_runtime::TaskScope,
    ) -> Self {
        Self {
            rx,
            content_length,
            _scope: Some(scope),
        }
    }

    pub fn into_rx(
        self,
    ) -> (
        tokio::sync::mpsc::Receiver<Result<Vec<u8>, std::io::Error>>,
        Option<swift_runtime::TaskScope>,
        Option<u64>,
    ) {
        (self.rx, self._scope, self.content_length)
    }

    #[allow(dead_code)]
    pub(crate) fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Vec<u8>, std::io::Error>>> {
        self.rx.poll_recv(cx)
    }
}

/// A streaming body: a reader plus the declared length (`None` when the
/// length is unknown until EOF, e.g. chunked transfer encoding).
pub struct StreamedBody {
    pub(crate) reader: Box<dyn Read + Send>,
    content_length: Option<u64>,
    pub(crate) interim: Option<InterimResponder>,
}

/// A handle for sending interim `100 Continue` responses mid-request —
/// the backend multiphase-PUT handshake (Python Swift's
/// `send_hundred_continue_response` with optional headers). Sending one
/// also re-arms a finished chunked request body so a NEW chunked
/// sequence can follow (Python swob semantics: it reinitializes
/// `chunk_length` on every send, which is how the commit phase of a
/// two-phase PUT travels after the data phase's 0-chunk terminator).
#[derive(Clone)]
pub struct InterimResponder {
    shared: Arc<std::sync::Mutex<InterimShared>>,
}

pub(crate) struct InterimShared {
    /// `None` when the client did not send `Expect: 100-continue`
    /// (writes become no-ops, matching Python Swift's absent `wfile`).
    writer: Option<Box<dyn std::io::Write + Send>>,
    sent_any: bool,
    resume_chunked: bool,
    /// The connection's write half, always present on real connections —
    /// what [`Body::hijack`] hands out for full-duplex protocols (SSYNC).
    hijack_writer: Option<Box<dyn std::io::Write + Send>>,
    hijacked: bool,
}

impl InterimResponder {
    /// Build a responder; `writer` is the connection's write half, or
    /// `None` to make sends no-ops (still re-arms chunked reading).
    pub fn new(writer: Option<Box<dyn std::io::Write + Send>>) -> InterimResponder {
        Self::with_hijack(writer, None)
    }

    /// [`InterimResponder::new`] plus the always-available write half
    /// that a handler may take over via [`Body::hijack`].
    pub fn with_hijack(
        writer: Option<Box<dyn std::io::Write + Send>>,
        hijack_writer: Option<Box<dyn std::io::Write + Send>>,
    ) -> InterimResponder {
        InterimResponder {
            shared: Arc::new(std::sync::Mutex::new(InterimShared {
                writer,
                sent_any: false,
                resume_chunked: false,
                hijack_writer,
                hijacked: false,
            })),
        }
    }

    /// Take the connection's write half for a full-duplex exchange. The
    /// server writes NO response afterwards (the handler owns the wire,
    /// including the response head) and never reuses the connection.
    pub(crate) fn take_hijack(&self) -> Option<Box<dyn std::io::Write + Send>> {
        let mut shared = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        let writer = shared.hijack_writer.take();
        if writer.is_some() {
            shared.hijacked = true;
        }
        writer
    }

    pub(crate) fn hijacked(&self) -> bool {
        self.shared
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .hijacked
    }

    /// Send `HTTP/1.1 100 Continue` plus the given headers. A REPEAT
    /// send re-arms the request body for another chunked sequence after
    /// its current terminator; the first send precedes body reading, so
    /// it arms nothing (eventlet resets `chunk_length` on every send,
    /// but before the body starts that reset is a no-op).
    pub fn send_continue(&self, headers: &[(&str, &str)]) -> std::io::Result<()> {
        let mut shared = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        if shared.sent_any {
            shared.resume_chunked = true;
        }
        shared.sent_any = true;
        if let Some(writer) = shared.writer.as_mut() {
            let mut out = b"HTTP/1.1 100 Continue\r\n".to_vec();
            for (name, value) in headers {
                out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
            }
            out.extend_from_slice(b"\r\n");
            writer.write_all(&out)?;
            writer.flush()?;
        }
        Ok(())
    }

    /// The connection's lazy auto-continue: a bare 100, only if nothing
    /// interim was sent yet. No chunked re-arm (this is the pre-body 100).
    pub(crate) fn send_bare_if_unsent(&self) -> std::io::Result<()> {
        let mut shared = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        if shared.sent_any {
            return Ok(());
        }
        shared.sent_any = true;
        if let Some(writer) = shared.writer.as_mut() {
            writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
            writer.flush()?;
        }
        Ok(())
    }

    pub(crate) fn sent_any(&self) -> bool {
        self.shared
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .sent_any
    }

    /// Consume a pending chunked re-arm signal.
    pub(crate) fn take_resume(&self) -> bool {
        let mut shared = self.shared.lock().unwrap_or_else(|p| p.into_inner());
        std::mem::take(&mut shared.resume_chunked)
    }
}

/// Marker payload inside the `std::io::Error` returned when
/// [`Body::materialize`] would exceed its cap; detect with
/// [`body_too_large`].
#[derive(Debug)]
pub struct BodyTooLarge;

impl std::fmt::Display for BodyTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "body exceeds the materialize cap")
    }
}

impl std::error::Error for BodyTooLarge {}

/// True when `err` is the [`Body::materialize`] over-cap error (map it
/// to 413 on a request path).
pub fn body_too_large(err: &std::io::Error) -> bool {
    err.get_ref().is_some_and(|e| e.is::<BodyTooLarge>())
}

pub(crate) fn too_large_error() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, BodyTooLarge)
}

impl Body {
    pub fn empty() -> Body {
        Body::Buffered(Vec::new())
    }

    /// Wrap a reader; `content_length: None` means "unknown until EOF".
    pub fn from_reader(reader: Box<dyn Read + Send>, content_length: Option<u64>) -> Body {
        Body::Streamed(StreamedBody {
            reader,
            content_length,
            interim: None,
        })
    }

    /// Bounded async body. `scope` retains the producer task.
    pub fn from_channel(
        rx: tokio::sync::mpsc::Receiver<Result<Vec<u8>, std::io::Error>>,
        content_length: Option<u64>,
        scope: swift_runtime::TaskScope,
    ) -> Body {
        Body::Channel(ChannelBody::new(rx, content_length, scope))
    }

    /// Drain a [`Body::Channel`] without `blocking_recv` (Gate 2: caller is
    /// a Tokio task). Buffered bodies return as-is. Streamed bodies still
    /// use the blocking reader.
    pub async fn collect_async(self) -> std::io::Result<Vec<u8>> {
        match self {
            Body::Buffered(b) => Ok(b),
            Body::Channel(ch) => {
                let (mut rx, _scope, _) = ch.into_rx();
                let mut out = Vec::new();
                while let Some(chunk) = rx.recv().await {
                    out.extend_from_slice(&chunk?);
                }
                Ok(out)
            }
            Body::Streamed(s) => Body::Streamed(s).into_vec(u64::MAX),
        }
    }

    /// Attach an interim-response handle (the server does this for real
    /// connections; tests may too).
    pub fn attach_interim(&mut self, interim: InterimResponder) {
        if let Body::Streamed(s) = self {
            s.interim = Some(interim);
        }
    }

    /// The handle for sending `100 Continue` interim responses, when
    /// this body came off a real server connection.
    pub fn interim_responder(&self) -> Option<InterimResponder> {
        match self {
            Body::Buffered(_) | Body::Channel(_) => None,
            Body::Streamed(s) => s.interim.clone(),
        }
    }

    /// Take over the connection for a full-duplex exchange (SSYNC): the
    /// returned writer is the raw connection write half — the handler
    /// writes the entire response (status line included) itself, while
    /// still reading this body. After a hijack the server writes nothing
    /// and closes the connection when the handler returns; the handler's
    /// `Response` value is discarded. `None` on synthetic bodies or if
    /// already hijacked.
    pub fn hijack(&self) -> Option<Box<dyn std::io::Write + Send>> {
        match self {
            Body::Buffered(_) | Body::Channel(_) => None,
            Body::Streamed(s) => s.interim.as_ref().and_then(|i| i.take_hijack()),
        }
    }

    /// The known or declared length: `Buffered` -> its exact length,
    /// `Streamed` -> the declared Content-Length (`None` if unknown).
    pub fn content_length(&self) -> Option<u64> {
        match self {
            Body::Buffered(b) => Some(b.len() as u64),
            Body::Streamed(s) => s.content_length,
            Body::Channel(c) => c.content_length,
        }
    }

    /// True only when the body is certainly empty (buffered empty, or a
    /// stream that declared zero length).
    pub fn is_definitely_empty(&self) -> bool {
        self.content_length() == Some(0)
    }

    /// Drain one Channel chunk. `Receiver::blocking_recv` panics on a
    /// Tokio worker; wrap it in `block_in_place` when a runtime is
    /// present (RSAIO proxy is multi-thread).
    fn recv_channel_chunk(
        rx: &mut tokio::sync::mpsc::Receiver<Result<Vec<u8>, std::io::Error>>,
    ) -> Option<Result<Vec<u8>, std::io::Error>> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Some(Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Body::Channel must be drained with collect_async on the Tokio runtime",
            )));
        } else {
            rx.blocking_recv()
        }
    }

    /// Read a streamed body fully into memory (idempotent), erroring with
    /// the [`body_too_large`] error if more than `cap` bytes arrive. A
    /// body that is ALREADY buffered is returned whole regardless of
    /// `cap` - the cap bounds the read, it is not a validator.
    pub fn materialize(&mut self, cap: u64) -> std::io::Result<&[u8]> {
        if let Body::Streamed(s) = self {
            let mut out: Vec<u8> = Vec::new();
            if let Some(len) = s.content_length {
                if len > cap {
                    return Err(too_large_error());
                }
            }
            let mut buf = [0u8; STREAM_CHUNK];
            loop {
                let n = s.reader.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                if out.len() as u64 + n as u64 > cap {
                    return Err(too_large_error());
                }
                out.try_reserve(n).map_err(std::io::Error::other)?;
                out.extend_from_slice(&buf[..n]);
            }
            *self = Body::Buffered(out);
        } else if let Body::Channel(ch) = self {
            let mut out: Vec<u8> = Vec::new();
            while let Some(chunk) = Self::recv_channel_chunk(&mut ch.rx) {
                let bytes = chunk?;
                if out.len() as u64 + bytes.len() as u64 > cap {
                    return Err(too_large_error());
                }
                out.extend_from_slice(&bytes);
            }
            *self = Body::Buffered(out);
        }
        match self {
            Body::Buffered(b) => Ok(b),
            Body::Streamed(_) | Body::Channel(_) => unreachable!(),
        }
    }

    /// Consuming [`Body::materialize`].
    pub fn into_vec(mut self, cap: u64) -> std::io::Result<Vec<u8>> {
        self.materialize(cap)?;
        match self {
            Body::Buffered(b) => Ok(b),
            Body::Streamed(_) | Body::Channel(_) => unreachable!(),
        }
    }

    /// Turn the body into a reader plus its known/declared length.
    pub fn into_reader(self) -> (Box<dyn Read + Send>, Option<u64>) {
        match self {
            Body::Buffered(b) => {
                let len = b.len() as u64;
                (Box::new(Cursor::new(b)), Some(len))
            }
            Body::Streamed(s) => (s.reader, s.content_length),
            Body::Channel(mut ch) => {
                let mut out = Vec::new();
                while let Some(chunk) = Self::recv_channel_chunk(&mut ch.rx) {
                    if let Ok(bytes) = chunk {
                        out.extend_from_slice(&bytes);
                    }
                }
                let len = out.len() as u64;
                (Box::new(Cursor::new(out)), Some(len))
            }
        }
    }

    /// Take the body out, leaving an empty one behind.
    pub fn take(&mut self) -> Body {
        std::mem::replace(self, Body::empty())
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Body::Buffered(b) => write!(f, "Body::Buffered({} bytes)", b.len()),
            Body::Streamed(s) => {
                write!(f, "Body::Streamed(content_length: {:?})", s.content_length)
            }
            Body::Channel(c) => {
                write!(f, "Body::Channel(content_length: {:?})", c.content_length)
            }
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(value: Vec<u8>) -> Self {
        Body::Buffered(value)
    }
}

impl From<&[u8]> for Body {
    fn from(value: &[u8]) -> Self {
        Body::Buffered(value.to_vec())
    }
}

impl From<String> for Body {
    fn from(value: String) -> Self {
        Body::Buffered(value.into_bytes())
    }
}

impl From<&str> for Body {
    fn from(value: &str) -> Self {
        Body::Buffered(value.as_bytes().to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for Body {
    fn from(value: &[u8; N]) -> Self {
        Body::Buffered(value.to_vec())
    }
}

/// Read a fixed list of parts in order.
pub struct ChainReader {
    parts: std::collections::VecDeque<Box<dyn Read + Send>>,
}

impl ChainReader {
    pub fn new(parts: Vec<Box<dyn Read + Send>>) -> ChainReader {
        ChainReader {
            parts: parts.into(),
        }
    }
}

impl Read for ChainReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while let Some(front) = self.parts.front_mut() {
            let n = front.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
            self.parts.pop_front();
        }
        Ok(0)
    }
}

/// A pull-based lazy chain: the closure is invoked only when the
/// previous part is exhausted (`None` = EOF). This is what SLO/DLO use
/// to fetch each segment only when the client stream reaches it.
pub struct FnReader<F> {
    next: F,
    current: Option<Box<dyn Read + Send>>,
    finished: bool,
}

impl<F> FnReader<F>
where
    F: FnMut() -> Option<std::io::Result<Box<dyn Read + Send>>> + Send,
{
    pub fn new(next: F) -> FnReader<F> {
        FnReader {
            next,
            current: None,
            finished: false,
        }
    }
}

impl<F> Read for FnReader<F>
where
    F: FnMut() -> Option<std::io::Result<Box<dyn Read + Send>>> + Send,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.finished {
                return Ok(0);
            }
            if let Some(current) = self.current.as_mut() {
                let n = current.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
                self.current = None;
            }
            match (self.next)() {
                Some(Ok(reader)) => self.current = Some(reader),
                Some(Err(e)) => {
                    self.finished = true;
                    return Err(e);
                }
                None => self.finished = true,
            }
        }
    }
}

/// A reader that hands back `Arc`-shared bytes without copying; useful
/// for fanning one buffered payload out to several consumers.
pub struct SharedBytesReader {
    bytes: Arc<Vec<u8>>,
    pos: usize,
}

impl SharedBytesReader {
    pub fn new(bytes: Arc<Vec<u8>>) -> SharedBytesReader {
        SharedBytesReader { bytes, pos: 0 }
    }
}

impl Read for SharedBytesReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = &self.bytes[self.pos..];
        let n = remaining.len().min(buf.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffered_basics() {
        let mut b: Body = b"hello".into();
        assert_eq!(b.content_length(), Some(5));
        assert!(!b.is_definitely_empty());
        assert_eq!(b.materialize(1).unwrap(), b"hello"); // cap ignores buffered
        assert!(Body::empty().is_definitely_empty());
    }

    #[test]
    fn streamed_materialize_and_cap() {
        let mut b = Body::from_reader(Box::new(Cursor::new(vec![7u8; 100])), Some(100));
        assert_eq!(b.content_length(), Some(100));
        assert_eq!(b.materialize(100).unwrap().len(), 100);
        // idempotent after materialize
        assert_eq!(b.materialize(0).unwrap().len(), 100);

        let mut b = Body::from_reader(Box::new(Cursor::new(vec![7u8; 100])), None);
        let err = b.materialize(99).unwrap_err();
        assert!(body_too_large(&err));
        // declared length over the cap fails before reading
        let mut b = Body::from_reader(Box::new(Cursor::new(vec![7u8; 10])), Some(1000));
        assert!(body_too_large(&b.materialize(100).unwrap_err()));
    }

    #[test]
    fn into_reader_round_trip() {
        let (mut r, len) = Body::from(b"abc".as_slice()).into_reader();
        assert_eq!(len, Some(3));
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"abc");
    }

    #[test]
    fn channel_on_tokio_runtime_uses_collect_async_not_block_in_place() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("multi-thread runtime");
        rt.block_on(async {
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            let scope = swift_runtime::TaskScope::bounded(1);
            tx.try_send(Ok(b"xyz".to_vec())).unwrap();
            drop(tx);
            let mut body = Body::from_channel(rx, Some(3), scope);
            let err = body.materialize(u64::MAX).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
            let (tx2, rx2) = tokio::sync::mpsc::channel(4);
            tx2.try_send(Ok(b"xyz".to_vec())).unwrap();
            drop(tx2);
            let body2 = Body::from_channel(rx2, Some(3), swift_runtime::TaskScope::bounded(1));
            let got = body2.collect_async().await.expect("collect_async");
            assert_eq!(got, b"xyz");
        });
    }

    #[test]
    fn chain_reader_orders_parts() {
        let mut r = ChainReader::new(vec![
            Box::new(Cursor::new(b"ab".to_vec())),
            Box::new(Cursor::new(b"".to_vec())),
            Box::new(Cursor::new(b"cd".to_vec())),
        ]);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"abcd");
    }

    #[test]
    fn fn_reader_is_lazy_and_terminates() {
        let mut served = 0;
        let mut r = FnReader::new(move || {
            served += 1;
            if served <= 3 {
                Some(Ok(
                    Box::new(Cursor::new(format!("part{served}").into_bytes()))
                        as Box<dyn Read + Send>,
                ))
            } else {
                None
            }
        });
        let mut out = String::new();
        r.read_to_string(&mut out).unwrap();
        assert_eq!(out, "part1part2part3");
        // after EOF it stays at EOF
        let mut buf = [0u8; 4];
        assert_eq!(r.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn fn_reader_propagates_errors_once() {
        let mut sent = false;
        let mut r = FnReader::new(move || {
            if sent {
                None
            } else {
                sent = true;
                Some(Err(std::io::Error::other("segment failed")))
            }
        });
        let mut buf = [0u8; 4];
        assert!(r.read(&mut buf).is_err());
        assert_eq!(r.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn shared_bytes_reader_reads_all() {
        let bytes = Arc::new(vec![1u8, 2, 3, 4, 5]);
        let mut r = SharedBytesReader::new(Arc::clone(&bytes));
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, *bytes);
    }
}
