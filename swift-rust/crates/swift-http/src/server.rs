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

//! A bounded synchronous HTTP/1.1 server for Swift's proxy and storage
//! services. Connections are handled by a fixed worker pool, and every
//! request-line, header, and socket wait has an explicit limit.
//!
//! Bodies STREAM: a request body is handed to the handler as a lazily
//! consumed reader over the connection (Content-Length-framed or
//! chunked-decoded), and a response body may be a reader the server
//! copies to the socket in 64KB chunks. Nothing object-sized is
//! buffered here.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use crossbeam_channel::{bounded, Sender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::body::{too_large_error, Body, InterimResponder, STREAM_CHUNK};
use crate::headers::HeaderKeyDict;
use crate::request::{reason_phrase, unquote, Request, Response};

/// A request handler shared across connection workers.
pub type Handler = Arc<dyn Fn(Request) -> Response + Send + Sync>;

/// Called after every parsed request with the request head, the response
/// status, and the time spent handling and writing the response.
pub type AccessLog = Arc<dyn Fn(&Request, u16, Duration) + Send + Sync>;

/// How often the accept loop wakes when the listener is idle. This doubles as
/// the shutdown-flag poll AND the worst-case accept latency for a freshly
/// arriving connection, so it must stay small: at 100ms every new connection
/// (client->proxy and each internal proxy->backend / object->container hop,
/// which are `Connection: close`) waited up to ~100ms to be accepted, adding
/// ~100ms per hop end to end. 1ms keeps shutdown responsive with negligible
/// idle cost. (A blocking accept with SO_RCVTIMEO would remove the poll
/// entirely; this is the dependency-free form.)
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// After the handler, an unconsumed request-body remainder up to this
/// size is drained to keep the connection reusable; larger remainders
/// close the connection instead.
const KEEPALIVE_DRAIN_CAP: u64 = 64 * 1024;

/// Resource and protocol limits for the synchronous HTTP server.
#[derive(Clone)]
pub struct ServerConfig {
    /// Maximum number of connections executing concurrently.
    pub worker_threads: usize,
    /// Connections waiting for a worker before they are rejected with 503.
    pub connection_queue: usize,
    /// Client socket inactivity timeout in seconds, Swift's `client_timeout`
    /// (both read and write, applied per chunk like Python's
    /// ChunkReadTimeout). `0` disables the timeout.
    pub client_timeout_secs: u64,
    /// Total wall-clock budget for reading one request line + headers
    /// (the slowloris guard: a client dripping header bytes cannot hold a
    /// worker past this). `0` disables the deadline. Body reads are NOT
    /// covered - they keep the per-chunk `client_timeout` semantics.
    pub head_deadline_secs: u64,
    /// Prevent one keep-alive connection from monopolizing a worker forever.
    pub max_requests_per_connection: usize,
    pub max_request_line_bytes: usize,
    pub max_header_line_bytes: usize,
    pub max_header_bytes: usize,
    pub max_header_count: usize,
    /// Maximum decoded request body. Enforced at header-parse time for
    /// Content-Length and during decode for chunked bodies.
    pub max_body_bytes: u64,
    /// Invoked after every request with `(request, response_status, elapsed)`.
    /// The request passed to the callback carries the original method, path,
    /// query string, and headers, but not the body. Must not panic (a panic
    /// is caught and discarded rather than tearing down the worker).
    pub access_log: Option<AccessLog>,
    /// When set, the accept loop polls this flag instead of blocking forever:
    /// once the flag is true it stops accepting, drains queued and in-flight
    /// requests, and `serve_forever_with_config` returns `Ok(())`. Pair with
    /// [`install_sigterm_flag`] for graceful daemon shutdown.
    pub shutdown: Option<Arc<AtomicBool>>,
    /// Bind with `SO_REUSEPORT` when using [`bind_listener`] (L4). No effect on
    /// an already-bound `TcpListener` passed to `serve_*`.
    pub reuse_port: bool,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("worker_threads", &self.worker_threads)
            .field("connection_queue", &self.connection_queue)
            .field("client_timeout_secs", &self.client_timeout_secs)
            .field("head_deadline_secs", &self.head_deadline_secs)
            .field(
                "max_requests_per_connection",
                &self.max_requests_per_connection,
            )
            .field("max_request_line_bytes", &self.max_request_line_bytes)
            .field("max_header_line_bytes", &self.max_header_line_bytes)
            .field("max_header_bytes", &self.max_header_bytes)
            .field("max_header_count", &self.max_header_count)
            .field("max_body_bytes", &self.max_body_bytes)
            .field(
                "access_log",
                &self.access_log.as_ref().map(|_| "<callback>"),
            )
            .field("shutdown", &self.shutdown)
            .field("reuse_port", &self.reuse_port)
            .finish()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        let cpus = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(4);
        Self {
            worker_threads: cpus.saturating_mul(16).clamp(16, 128),
            connection_queue: 256,
            client_timeout_secs: 60,
            head_deadline_secs: 30,
            max_requests_per_connection: 100,
            max_request_line_bytes: 8 * 1024,
            max_header_line_bytes: 8 * 1024,
            max_header_bytes: 64 * 1024,
            max_header_count: 128,
            max_body_bytes: swift_core::constraints::MAX_FILE_SIZE as u64,
            access_log: None,
            shutdown: None,
            reuse_port: false,
        }
    }
}

/// Bind `addr` (`ip:port`) as a `TcpListener`, optionally with `SO_REUSEPORT`
/// so multiple acceptors can share the port (L4).
pub fn bind_listener(addr: &str, reuse_port: bool) -> std::io::Result<TcpListener> {
    use std::net::SocketAddr;
    use std::os::fd::FromRawFd;

    if !reuse_port {
        return TcpListener::bind(addr);
    }

    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    fn set_bool_sockopt(fd: libc::c_int, opt: libc::c_int) -> std::io::Result<()> {
        let v: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &v as *const _ as *const libc::c_void,
                std::mem::size_of_val(&v) as libc::socklen_t,
            )
        };
        if rc != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    let fd = unsafe { libc::socket(
        match sock_addr {
            SocketAddr::V4(_) => libc::AF_INET,
            SocketAddr::V6(_) => libc::AF_INET6,
        },
        libc::SOCK_STREAM,
        0,
    )};
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if let Err(e) = set_bool_sockopt(fd, libc::SO_REUSEADDR) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if let Err(e) = set_bool_sockopt(fd, libc::SO_REUSEPORT) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    let bind_rc = unsafe {
        match sock_addr {
            SocketAddr::V4(a) => {
                let mut sa: libc::sockaddr_in = std::mem::zeroed();
                sa.sin_family = libc::AF_INET as _;
                sa.sin_port = u16::to_be(a.port());
                sa.sin_addr = libc::in_addr {
                    s_addr: u32::from(*a.ip()).to_be(),
                };
                libc::bind(
                    fd,
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&sa) as libc::socklen_t,
                )
            }
            SocketAddr::V6(a) => {
                let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                sa.sin6_family = libc::AF_INET6 as _;
                sa.sin6_port = u16::to_be(a.port());
                sa.sin6_addr = libc::in6_addr {
                    s6_addr: a.ip().octets(),
                };
                libc::bind(
                    fd,
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&sa) as libc::socklen_t,
                )
            }
        }
    };
    if bind_rc != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    if unsafe { libc::listen(fd, 1024) } != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(unsafe { TcpListener::from_raw_fd(fd) })
}

fn socket_timeout(config: &ServerConfig) -> Option<Duration> {
    (config.client_timeout_secs > 0).then(|| Duration::from_secs(config.client_timeout_secs))
}

/// The flag [`install_sigterm_flag`] hands out; a `OnceLock` so the signal
/// handler only ever performs an atomic load + store (async-signal-safe).
static SIGNAL_SHUTDOWN_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

extern "C" fn record_shutdown_signal(_signal: libc::c_int) {
    if let Some(flag) = SIGNAL_SHUTDOWN_FLAG.get() {
        flag.store(true, Ordering::SeqCst);
    }
}

/// Register a SIGTERM + SIGINT handler that flips a shared shutdown flag,
/// and return that flag. Give the same flag to [`ServerConfig::shutdown`]
/// so the daemon finishes in-flight requests and exits cleanly on signal.
/// Safe to call more than once; every call returns the same flag.
pub fn install_sigterm_flag() -> Arc<AtomicBool> {
    let flag = SIGNAL_SHUTDOWN_FLAG.get_or_init(|| Arc::new(AtomicBool::new(false)));
    let handler = record_shutdown_signal as extern "C" fn(libc::c_int);
    unsafe {
        libc::signal(libc::SIGTERM, handler as libc::sighandler_t);
        libc::signal(libc::SIGINT, handler as libc::sighandler_t);
    }
    Arc::clone(flag)
}

/// Accept connections forever using conservative production defaults.
pub fn serve_forever(listener: TcpListener, handler: Handler) -> std::io::Result<()> {
    serve_forever_with_config(listener, handler, ServerConfig::default())
}

/// Accept connections using a bounded worker pool and explicit limits.
///
/// With `config.shutdown` unset this accepts forever (only an accept error
/// returns). With it set, the accept loop polls the flag and, once true,
/// stops accepting, drains queued and in-flight requests, and returns
/// `Ok(())`.
pub fn serve_forever_with_config(
    listener: TcpListener,
    handler: Handler,
    config: ServerConfig,
) -> std::io::Result<()> {
    serve_forever_multi(vec![listener], handler, config)
}

/// Like [`serve_forever_with_config`], but accept from multiple listeners
/// into one shared worker pool (`servers_per_port` / multi-port topology).
pub fn serve_forever_multi(
    listeners: Vec<TcpListener>,
    handler: Handler,
    config: ServerConfig,
) -> std::io::Result<()> {
    if listeners.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "serve_forever_multi requires at least one listener",
        ));
    }
    let worker_count = config.worker_threads.max(1);
    // Lock-free MPMC work queue: each worker holds its own Receiver clone and
    // recv()s directly, so the accept dispatch never serializes workers on a
    // shared Mutex<Receiver>. That mutex contention capped write concurrency
    // once the worker pool was raised past a handful of threads.
    let (sender, receiver) = bounded::<TcpStream>(config.connection_queue.max(1));

    let mut workers = Vec::with_capacity(worker_count);
    for worker_id in 0..worker_count {
        let receiver = receiver.clone();
        let handler = Arc::clone(&handler);
        let config = config.clone();
        let worker = std::thread::Builder::new()
            .name(format!("swift-http-{worker_id}"))
            .spawn(move || loop {
                let stream = match receiver.recv() {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                // A handler panic must only terminate the affected request,
                // never permanently reduce the worker pool.
                let _ = catch_unwind(AssertUnwindSafe(|| {
                    let _ = handle_connection(stream, Arc::clone(&handler), &config);
                }));
            })?;
        workers.push(worker);
    }

    let Some(shutdown) = config.shutdown.clone() else {
        if listeners.len() == 1 {
            let mut listeners = listeners;
            let listener = listeners.pop().unwrap();
            for stream in listener.incoming() {
                let stream = stream?;
                dispatch_connection(stream, &sender, &config)?;
            }
            return Ok(());
        }
        // Multiple listeners, no shutdown: one blocking accept thread each;
        // this thread joins them (they run until process exit / accept err).
        let mut acceptors = Vec::with_capacity(listeners.len());
        for (idx, listener) in listeners.into_iter().enumerate() {
            let sender = sender.clone();
            let config = config.clone();
            let acceptor = std::thread::Builder::new()
                .name(format!("swift-http-accept-{idx}"))
                .spawn(move || -> std::io::Result<()> {
                    for stream in listener.incoming() {
                        let stream = stream?;
                        dispatch_connection(stream, &sender, &config)?;
                    }
                    Ok(())
                })?;
            acceptors.push(acceptor);
        }
        let mut first_err = None;
        for acceptor in acceptors {
            match acceptor.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) if first_err.is_none() => first_err = Some(e),
                Ok(Err(_)) => {}
                Err(_) if first_err.is_none() => {
                    first_err = Some(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "accept thread panicked",
                    ));
                }
                Err(_) => {}
            }
        }
        return match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        };
    };

    // Shutdown path: non-blocking accept on each listener from dedicated
    // threads; main waits until the flag flips, then joins and drains.
    let mut acceptors = Vec::with_capacity(listeners.len());
    for (idx, listener) in listeners.into_iter().enumerate() {
        listener.set_nonblocking(true)?;
        let sender = sender.clone();
        let config = config.clone();
        let shutdown = Arc::clone(&shutdown);
        let acceptor = std::thread::Builder::new()
            .name(format!("swift-http-accept-{idx}"))
            .spawn(move || -> std::io::Result<()> {
                while !shutdown.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _peer)) => {
                            // On BSD-derived platforms accepted sockets inherit
                            // the listener's O_NONBLOCK; the connection handler
                            // needs blocking reads with timeouts.
                            stream.set_nonblocking(false).ok();
                            dispatch_connection(stream, &sender, &config)?;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(())
            })?;
        acceptors.push(acceptor);
    }

    while !shutdown.load(Ordering::SeqCst) {
        std::thread::sleep(SHUTDOWN_POLL_INTERVAL);
    }
    let mut first_err = None;
    for acceptor in acceptors {
        match acceptor.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) if first_err.is_none() => first_err = Some(e),
            Ok(Err(_)) => {}
            Err(_) if first_err.is_none() => {
                first_err = Some(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "accept thread panicked",
                ));
            }
            Err(_) => {}
        }
    }

    // Stop accepting. Dropping the sender closes the channel once the
    // already-queued connections are received, so each worker drains its
    // share and exits; joining then waits out the in-flight requests.
    drop(sender);
    for worker in workers {
        let _ = worker.join();
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn dispatch_connection(
    stream: TcpStream,
    sender: &Sender<TcpStream>,
    config: &ServerConfig,
) -> std::io::Result<()> {
    match sender.try_send(stream) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(stream)) => {
            reject_overloaded(stream, socket_timeout(config));
            Ok(())
        }
        Err(TrySendError::Disconnected(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "all HTTP workers exited",
        )),
    }
}

fn reject_overloaded(mut stream: TcpStream, timeout: Option<Duration>) {
    let _ = stream.set_write_timeout(timeout);
    let body = b"Service Unavailable";
    let _ = write!(
        stream,
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

#[derive(Debug)]
enum ProtocolError {
    Io(std::io::Error),
    Http(u16, &'static str),
}

impl From<std::io::Error> for ProtocolError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

// ============================ connection plumbing ============================

/// The head-phase deadline shared between the connection loop and the
/// socket reader; `None` outside the head phase.
type DeadlineCell = Arc<Mutex<Option<Instant>>>;

/// A `TcpStream` reader that, while a head deadline is armed, bounds each
/// `read` by the time remaining (so a client dripping header bytes cannot
/// stretch one line past the budget). With the deadline disarmed, reads
/// carry the plain per-chunk `client_timeout`.
struct TimedStream {
    stream: TcpStream,
    deadline: DeadlineCell,
    client_timeout: Option<Duration>,
}

impl Read for TimedStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let armed = *self.deadline.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(deadline) = armed {
            let now = Instant::now();
            let Some(remaining) = deadline.checked_duration_since(now).filter(|d| !d.is_zero())
            else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "request head deadline exceeded",
                ));
            };
            let per_read = match self.client_timeout {
                Some(ct) => ct.min(remaining),
                None => remaining,
            };
            self.stream.set_read_timeout(Some(per_read)).ok();
            let result = self.stream.read(buf);
            self.stream.set_read_timeout(self.client_timeout).ok();
            return result;
        }
        self.stream.read(buf)
    }
}

type ConnReader = BufReader<TimedStream>;

/// How the request body is framed on the wire.
enum Framing {
    /// Content-Length: exactly this many bytes remain.
    Sized { remaining: u64 },
    /// Transfer-Encoding: chunked; `total` counts decoded bytes against
    /// `max_body`.
    Chunked { state: ChunkState, total: u64 },
}

enum ChunkState {
    Size,
    Data { remaining: u64 },
    Terminator,
    Finished,
}

impl Framing {
    fn fully_consumed(&self) -> bool {
        match self {
            Framing::Sized { remaining } => *remaining == 0,
            Framing::Chunked { state, .. } => matches!(state, ChunkState::Finished),
        }
    }
}

/// What the body reader gives back to the connection loop when dropped.
struct ReclaimedConn {
    reader: ConnReader,
    fully_consumed: bool,
    /// Bytes left on the wire when known (`Sized` framing); `None` for an
    /// unfinished chunked body (unbounded, never drained).
    remaining: Option<u64>,
    /// `Expect: 100-continue` was requested but never answered - the
    /// client has not sent the body, so there is nothing to drain and the
    /// connection must close.
    continue_pending: bool,
}

type ReclaimSlot = Arc<Mutex<Option<ReclaimedConn>>>;

/// Body-decode limits copied out of `ServerConfig` (the reader outlives
/// the borrow of the config).
#[derive(Clone, Copy)]
struct BodyLimits {
    max_body_bytes: u64,
    max_header_line_bytes: usize,
    max_header_bytes: usize,
    max_header_count: usize,
}

/// The streaming request body: a framed reader over the connection that
/// answers `Expect: 100-continue` lazily on first read and returns the
/// connection to the loop (via the reclaim slot) when dropped. The
/// shared [`InterimResponder`] lets the handler send its own interim
/// responses (with headers, and repeatedly — the multiphase-PUT
/// handshake) before or between body reads.
struct ConnBodyReader {
    reader: Option<ConnReader>,
    framing: Framing,
    limits: BodyLimits,
    interim: InterimResponder,
    expect_continue: bool,
    slot: ReclaimSlot,
}

impl ConnBodyReader {
    fn maybe_send_continue(&mut self) -> std::io::Result<()> {
        if self.expect_continue {
            self.interim.send_bare_if_unsent()?;
        }
        Ok(())
    }
}

impl Read for ConnBodyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.maybe_send_continue()?;
        let reader = self
            .reader
            .as_mut()
            .expect("connection reader present until drop");
        match &mut self.framing {
            Framing::Sized { remaining } => {
                if *remaining == 0 {
                    return Ok(0);
                }
                let take = (buf.len() as u64).min(*remaining) as usize;
                let n = reader.read(&mut buf[..take])?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "client disconnected mid-body",
                    ));
                }
                *remaining -= n as u64;
                Ok(n)
            }
            Framing::Chunked { state, total } => loop {
                match state {
                    ChunkState::Finished => {
                        // An interim response re-arms the body: a fresh
                        // chunked sequence follows the previous terminator
                        // (eventlet's multiphase-PUT semantics).
                        if self.interim.take_resume() {
                            *state = ChunkState::Size;
                            continue;
                        }
                        return Ok(0);
                    }
                    ChunkState::Size => {
                        let line = read_bounded_line(reader, 128)
                            .map_err(protocol_to_io)?
                            .ok_or_else(|| {
                                std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "truncated chunk size",
                                )
                            })?;
                        let text = line_text(&line).map_err(protocol_to_io)?;
                        let size_hex = text.split_once(';').map_or(text, |(size, _)| size);
                        if size_hex.is_empty()
                            || !size_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                        {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid chunk size",
                            ));
                        }
                        let size = u64::from_str_radix(size_hex, 16).map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid chunk size",
                            )
                        })?;
                        if size == 0 {
                            read_chunk_trailers_limits(reader, &self.limits)
                                .map_err(protocol_to_io)?;
                            *state = ChunkState::Finished;
                            // A pending re-arm (an interim response sent
                            // mid-sequence) means another chunked sequence
                            // follows this terminator — resume instead of
                            // reporting EOF.
                            if self.interim.take_resume() {
                                *state = ChunkState::Size;
                                continue;
                            }
                            return Ok(0);
                        }
                        if total.saturating_add(size) > self.limits.max_body_bytes {
                            return Err(too_large_error());
                        }
                        *state = ChunkState::Data { remaining: size };
                    }
                    ChunkState::Data { remaining } => {
                        let take = (buf.len() as u64).min(*remaining) as usize;
                        let n = reader.read(&mut buf[..take])?;
                        if n == 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "client disconnected mid-chunk",
                            ));
                        }
                        *remaining -= n as u64;
                        *total += n as u64;
                        if *remaining == 0 {
                            *state = ChunkState::Terminator;
                        }
                        return Ok(n);
                    }
                    ChunkState::Terminator => {
                        let mut terminator = [0u8; 2];
                        reader.read_exact(&mut terminator)?;
                        if terminator != *b"\r\n" {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid chunk terminator",
                            ));
                        }
                        *state = ChunkState::Size;
                    }
                }
            },
        }
    }
}

impl Drop for ConnBodyReader {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            // A pending (never-consumed) re-arm means the handler promised
            // another chunked sequence that was never read — the wire is
            // not at a request boundary, so the connection cannot be
            // reused.
            let armed_but_unread = self.interim.take_resume();
            let fully_consumed = self.framing.fully_consumed() && !armed_but_unread;
            let remaining = match &self.framing {
                Framing::Sized { remaining } if !armed_but_unread => Some(*remaining),
                _ => None,
            };
            let reclaimed = ReclaimedConn {
                reader,
                fully_consumed,
                remaining,
                continue_pending: self.expect_continue && !self.interim.sent_any(),
            };
            if let Ok(mut slot) = self.slot.lock() {
                *slot = Some(reclaimed);
            }
        }
    }
}

fn protocol_to_io(e: ProtocolError) -> std::io::Error {
    match e {
        ProtocolError::Io(io) => io,
        ProtocolError::Http(status, message) => std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{status}: {message}"),
        ),
    }
}

/// The parsed head of one request, before any body bytes are read.
struct RequestHead {
    method: String,
    raw_path: String,
    query_string: String,
    headers: HeaderKeyDict,
    keep_alive: bool,
    content_length: Option<u64>,
    chunked: bool,
    expect_continue: bool,
}

fn handle_connection(
    stream: TcpStream,
    handler: Handler,
    config: &ServerConfig,
) -> std::io::Result<()> {
    stream.set_nodelay(true).ok();
    // REMOTE_ADDR equivalent for middleware (TempURL ip_range, logging).
    let peer_ip = stream
        .peer_addr()
        .ok()
        .map(|a| a.ip().to_string());
    let timeout = socket_timeout(config);
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;
    let deadline: DeadlineCell = Arc::new(Mutex::new(None));
    let timed = TimedStream {
        stream: stream.try_clone()?,
        deadline: Arc::clone(&deadline),
        client_timeout: timeout,
    };
    let mut reader_opt: Option<ConnReader> = Some(BufReader::new(timed));
    let mut stream = stream;
    let slot: ReclaimSlot = Arc::new(Mutex::new(None));

    for request_number in 0..config.max_requests_per_connection.max(1) {
        let mut reader = reader_opt
            .take()
            .expect("connection reader available at loop top");

        // Arm the slowloris deadline for the head phase only.
        if config.head_deadline_secs > 0 {
            *deadline.lock().unwrap_or_else(|p| p.into_inner()) =
                Some(Instant::now() + Duration::from_secs(config.head_deadline_secs));
        }
        let head = match read_head(&mut reader, config) {
            Ok(Some(head)) => head,
            Ok(None) => return Ok(()),
            Err(ProtocolError::Http(status, message)) => {
                write_error_response(&mut stream, status, message)?;
                return Ok(());
            }
            Err(ProtocolError::Io(error)) => return Err(error),
        };
        *deadline.lock().unwrap_or_else(|p| p.into_inner()) = None;

        // Build the body: empty, or a framed stream over the connection.
        let has_body = head.chunked || head.content_length.is_some_and(|n| n > 0);
        let mut conn_interim: Option<InterimResponder> = None;
        let body = if has_body {
            let framing = if head.chunked {
                Framing::Chunked {
                    state: ChunkState::Size,
                    total: 0,
                }
            } else {
                Framing::Sized {
                    remaining: head.content_length.unwrap_or(0),
                }
            };
            // Interim (`100 Continue`) writes go out only when the client
            // asked for them; otherwise the handle's sends are no-ops
            // (eventlet parity). The hijack half is always available — a
            // full-duplex handler (SSYNC) may take the wire over.
            let interim = InterimResponder::with_hijack(
                if head.expect_continue {
                    Some(Box::new(stream.try_clone()?))
                } else {
                    None
                },
                Some(Box::new(stream.try_clone()?)),
            );
            let conn_body = ConnBodyReader {
                reader: Some(reader),
                framing,
                limits: BodyLimits {
                    max_body_bytes: config.max_body_bytes,
                    max_header_line_bytes: config.max_header_line_bytes,
                    max_header_bytes: config.max_header_bytes,
                    max_header_count: config.max_header_count,
                },
                interim: interim.clone(),
                expect_continue: head.expect_continue,
                slot: Arc::clone(&slot),
            };
            let mut body = Body::from_reader(Box::new(conn_body), head.content_length);
            body.attach_interim(interim.clone());
            conn_interim = Some(interim);
            body
        } else {
            reader_opt = Some(reader);
            Body::empty()
        };

        let mut headers = head.headers;
        // Unspoofable peer: only set if client did not already supply a
        // backend-stamped address (proxies may set X-Forwarded-For later).
        if let Some(ref ip) = peer_ip {
            if !headers.contains_key("X-Backend-Remote-Addr") {
                headers.set("X-Backend-Remote-Addr", ip);
            }
        }
        let request = Request {
            method: head.method,
            path: unquote(&head.raw_path),
            query_string: head.query_string,
            headers,
            body,
        };

        let head_request = request.method == "HEAD";
        // The handler consumes the request, so keep a body-less copy of its
        // head for the access log.
        let logged_request = config.access_log.as_ref().map(|_| Request {
            method: request.method.clone(),
            path: request.path.clone(),
            query_string: request.query_string.clone(),
            headers: request.headers.clone(),
            body: Body::empty(),
        });
        let started = Instant::now();
        let (response, handler_panicked) = match catch_unwind(AssertUnwindSafe(|| handler(request)))
        {
            Ok(response) => (response, false),
            Err(_) => (Response::error(500, "request handler panicked"), true),
        };
        let response_status = response.status;
        // A hijacked connection belongs to the handler: it wrote the whole
        // exchange itself (SSYNC). Nothing more to write, never reused.
        if conn_interim.as_ref().is_some_and(|i| i.hijacked()) {
            if let (Some(callback), Some(logged)) = (&config.access_log, &logged_request) {
                let elapsed = started.elapsed();
                let _ = catch_unwind(AssertUnwindSafe(|| {
                    callback(logged, response_status, elapsed)
                }));
            }
            return Ok(());
        }
        let mut keep_alive = !handler_panicked
            && head.keep_alive
            && request_number + 1 < config.max_requests_per_connection.max(1);
        // If the body reader has already come back unusable for reuse,
        // announce the close in the response instead of surprising the
        // client afterwards.
        if keep_alive && reader_opt.is_none() {
            if let Ok(guard) = slot.lock() {
                if let Some(r) = guard.as_ref() {
                    let reusable = r.fully_consumed
                        || (!r.continue_pending
                            && r.remaining.is_some_and(|n| n <= KEEPALIVE_DRAIN_CAP));
                    if !reusable {
                        keep_alive = false;
                    }
                }
            }
        }
        let write_result = write_response(
            &mut stream,
            response,
            keep_alive,
            head_request && !handler_panicked,
        );
        let keep_alive = match &write_result {
            Ok(wrote_keep_alive) => *wrote_keep_alive,
            Err(_) => false,
        };
        if let (Some(callback), Some(logged)) = (&config.access_log, &logged_request) {
            let elapsed = started.elapsed();
            // The callback must not panic; if it does anyway, contain it.
            let _ = catch_unwind(AssertUnwindSafe(|| {
                callback(logged, response_status, elapsed)
            }));
        }
        write_result?;
        if !keep_alive {
            // Closing with unread request bytes in the kernel buffer makes
            // the close an RST, which can destroy the response before the
            // client reads it (a 422/500 answered mid-body). Send FIN
            // first, then briefly drain what the client already sent so
            // the teardown is graceful.
            let _ = stream.shutdown(std::net::Shutdown::Write);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
            let mut sink = [0u8; STREAM_CHUNK];
            let mut drained: u64 = 0;
            while drained < 1024 * 1024 {
                match stream.read(&mut sink) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => drained += n as u64,
                }
            }
            return Ok(());
        }

        // Reclaim the connection reader if the body reader took it.
        if reader_opt.is_none() {
            let reclaimed = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
            let Some(mut reclaimed) = reclaimed else {
                // The handler leaked the body reader (e.g. into a thread);
                // the connection cannot be reused.
                return Ok(());
            };
            if reclaimed.continue_pending {
                // 100-continue was never sent: the client has not sent the
                // body, so the wire is not at a request boundary.
                return Ok(());
            }
            if !reclaimed.fully_consumed {
                match reclaimed.remaining {
                    Some(n) if n <= KEEPALIVE_DRAIN_CAP => {
                        let mut sink = [0u8; STREAM_CHUNK];
                        let mut left = n;
                        while left > 0 {
                            let take = (sink.len() as u64).min(left) as usize;
                            reclaimed.reader.read_exact(&mut sink[..take])?;
                            left -= take as u64;
                        }
                    }
                    _ => return Ok(()),
                }
            }
            reader_opt = Some(reclaimed.reader);
        }
    }
    Ok(())
}

/// Parse one request line + headers. Does NOT read any body bytes.
fn read_head(
    reader: &mut ConnReader,
    config: &ServerConfig,
) -> Result<Option<RequestHead>, ProtocolError> {
    let request_line = loop {
        let Some(line) = read_bounded_line(reader, config.max_request_line_bytes)? else {
            return Ok(None);
        };
        let line = line_text(&line)?.to_owned();
        if !line.is_empty() {
            break line;
        }
    };

    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ProtocolError::Http(400, "malformed request line"));
    };
    if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
    {
        return Err(ProtocolError::Http(400, "invalid HTTP method"));
    }
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(ProtocolError::Http(400, "unsupported HTTP version"));
    }
    let (raw_path, query_string) = match target.split_once('?') {
        Some((path, query)) => (path, query.to_string()),
        None => (target, String::new()),
    };
    if raw_path.is_empty() {
        return Err(ProtocolError::Http(400, "empty request path"));
    }

    let mut headers = HeaderKeyDict::new();
    let mut header_bytes = 0usize;
    let mut header_count = 0usize;
    let mut saw_content_length = false;
    let mut saw_transfer_encoding = false;
    loop {
        let Some(line) = read_bounded_line(reader, config.max_header_line_bytes)? else {
            return Err(ProtocolError::Http(400, "truncated request headers"));
        };
        header_bytes = header_bytes
            .checked_add(line.len())
            .ok_or(ProtocolError::Http(400, "request headers too large"))?;
        if header_bytes > config.max_header_bytes {
            return Err(ProtocolError::Http(400, "request headers too large"));
        }
        let line = line_text(&line)?;
        if line.is_empty() {
            break;
        }
        header_count += 1;
        if header_count > config.max_header_count {
            return Err(ProtocolError::Http(400, "too many request headers"));
        }
        if line.starts_with([' ', '\t']) {
            return Err(ProtocolError::Http(400, "folded headers are not accepted"));
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ProtocolError::Http(400, "malformed request header"));
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProtocolError::Http(400, "invalid request header name"));
        }
        if name.eq_ignore_ascii_case("Content-Length") {
            if saw_content_length {
                return Err(ProtocolError::Http(400, "duplicate Content-Length"));
            }
            saw_content_length = true;
        }
        if name.eq_ignore_ascii_case("Transfer-Encoding") {
            if saw_transfer_encoding {
                return Err(ProtocolError::Http(400, "duplicate Transfer-Encoding"));
            }
            saw_transfer_encoding = true;
        }
        headers.set(name, value);
    }

    if saw_content_length && saw_transfer_encoding {
        return Err(ProtocolError::Http(
            400,
            "Content-Length and Transfer-Encoding cannot be combined",
        ));
    }

    let content_length = if let Some(value) = headers.get("Content-Length") {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ProtocolError::Http(400, "invalid Content-Length"));
        }
        let value = value
            .parse::<u64>()
            .map_err(|_| ProtocolError::Http(400, "invalid Content-Length"))?;
        if value > config.max_body_bytes {
            return Err(ProtocolError::Http(
                413,
                "request body exceeds configured limit",
            ));
        }
        Some(value)
    } else {
        None
    };
    let chunked = if let Some(value) = headers.get("Transfer-Encoding") {
        if !value.eq_ignore_ascii_case("chunked") {
            return Err(ProtocolError::Http(400, "unsupported Transfer-Encoding"));
        }
        true
    } else {
        false
    };

    let expect_continue = if let Some(expectation) = headers.get("Expect") {
        if !expectation.eq_ignore_ascii_case("100-continue") {
            return Err(ProtocolError::Http(417, "unsupported expectation"));
        }
        // Answered lazily by the body reader on first read, so a handler
        // that rejects without reading never triggers the client upload.
        true
    } else {
        false
    };

    let keep_alive = match version {
        "HTTP/1.0" => headers
            .get("Connection")
            .is_some_and(|value| value.eq_ignore_ascii_case("keep-alive")),
        _ => !headers
            .get("Connection")
            .is_some_and(|value| value.eq_ignore_ascii_case("close")),
    };

    Ok(Some(RequestHead {
        method: method.to_string(),
        raw_path: raw_path.to_string(),
        query_string,
        headers,
        keep_alive,
        content_length,
        chunked,
        expect_continue,
    }))
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut line = Vec::with_capacity(max_bytes.min(1024));
    let read = reader.take(limit).read_until(b'\n', &mut line)?;
    if read == 0 {
        return Ok(None);
    }
    if line.len() > max_bytes || !line.ends_with(b"\n") {
        return Err(ProtocolError::Http(
            400,
            "HTTP line exceeds configured limit",
        ));
    }
    Ok(Some(line))
}

fn line_text(line: &[u8]) -> Result<&str, ProtocolError> {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    std::str::from_utf8(line)
        .map_err(|_| ProtocolError::Http(400, "request line or header is not UTF-8"))
}

fn read_chunk_trailers_limits<R: BufRead>(
    reader: &mut R,
    limits: &BodyLimits,
) -> Result<(), ProtocolError> {
    let mut trailer_bytes = 0usize;
    let mut trailer_count = 0usize;
    loop {
        let Some(line) = read_bounded_line(reader, limits.max_header_line_bytes)? else {
            return Err(ProtocolError::Http(400, "truncated chunk trailers"));
        };
        trailer_bytes = trailer_bytes
            .checked_add(line.len())
            .ok_or(ProtocolError::Http(400, "chunk trailers too large"))?;
        if trailer_bytes > limits.max_header_bytes {
            return Err(ProtocolError::Http(400, "chunk trailers too large"));
        }
        let line = line_text(&line)?;
        if line.is_empty() {
            return Ok(());
        }
        trailer_count += 1;
        if trailer_count > limits.max_header_count || !line.contains(':') {
            return Err(ProtocolError::Http(400, "invalid chunk trailers"));
        }
    }
}

fn write_error_response<W: Write>(
    writer: &mut W,
    status: u16,
    message: &str,
) -> std::io::Result<()> {
    write_response(writer, Response::error(status, message), false, false).map(|_| ())
}

/// Serialize a response. Returns the keep-alive value actually written
/// (a streamed body with unknown length forces `Connection: close` - the
/// EOF is the framing).
fn write_response<W: Write>(
    writer: &mut W,
    mut response: Response,
    keep_alive: bool,
    head_request: bool,
) -> std::io::Result<bool> {
    if response.reason.contains(['\r', '\n']) {
        response.reason = reason_phrase(response.status).to_string();
    }
    let body = response.body.take();
    let close_delimited = if response.headers.get("Content-Length").is_none() {
        match body.content_length() {
            Some(n) => {
                response.headers.set("Content-Length", n);
                false
            }
            None => true,
        }
    } else {
        false
    };
    let keep_alive = keep_alive && !close_delimited;
    for (name, value) in response.headers.iter() {
        if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response header contains a newline",
            ));
        }
    }
    write!(
        writer,
        "HTTP/1.1 {} {}\r\n",
        response.status, response.reason
    )?;
    for (name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("Connection") || name.eq_ignore_ascii_case("Transfer-Encoding")
        {
            continue;
        }
        write!(writer, "{name}: {value}\r\n")?;
    }
    writer.write_all(if keep_alive {
        b"Connection: keep-alive\r\n\r\n"
    } else {
        b"Connection: close\r\n\r\n"
    })?;
    if !head_request {
        match body {
            Body::Buffered(bytes) => writer.write_all(&bytes)?,
            Body::Streamed(_) => {
                let (mut reader, _) = body.into_reader();
                let mut buf = [0u8; STREAM_CHUNK];
                loop {
                    let n = reader.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    writer.write_all(&buf[..n])?;
                }
            }
        }
    }
    // A HEAD response's streamed body is dropped without being read.
    writer.flush()?;
    Ok(keep_alive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::body_too_large;
    use std::net::Shutdown;

    /// Echo handler used by most round trips: materializes the body the
    /// way a real control-plane handler would, mapping the too-large
    /// error to 413.
    fn echo_handler() -> Handler {
        Arc::new(|mut request: Request| match request.body.materialize(u64::MAX) {
            Ok(_) => {
                let bytes = request.body.into_vec(u64::MAX).unwrap();
                Response::with_body(200, bytes)
            }
            Err(e) if body_too_large(&e) => Response::error(413, "body too large"),
            Err(e) => Response::error(500, &e.to_string()),
        })
    }

    fn round_trip(config: ServerConfig, request: &[u8]) -> Vec<u8> {
        round_trip_with(config, echo_handler(), request)
    }

    fn round_trip_with(config: ServerConfig, handler: Handler, request: &[u8]) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = handle_connection(stream, handler, &config);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(request).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        server.join().unwrap();
        response
    }

    fn status(response: &[u8]) -> u16 {
        String::from_utf8_lossy(response)
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    }

    fn response_body(response: &[u8]) -> &[u8] {
        let split = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        &response[split + 4..]
    }

    #[test]
    fn defaults_are_finite_and_keep_swifts_object_size_limit() {
        let config = ServerConfig::default();
        assert!((16..=128).contains(&config.worker_threads));
        assert!(config.connection_queue > 0);
        assert!(config.client_timeout_secs > 0);
        assert!(config.head_deadline_secs > 0);
        assert!(config.access_log.is_none());
        assert!(config.shutdown.is_none());
        assert_eq!(
            config.max_body_bytes,
            swift_core::constraints::MAX_FILE_SIZE as u64
        );
    }

    #[test]
    fn client_timeout_zero_disables_socket_timeouts() {
        assert_eq!(
            socket_timeout(&ServerConfig::default()),
            Some(Duration::from_secs(60))
        );
        let config = ServerConfig {
            client_timeout_secs: 0,
            ..ServerConfig::default()
        };
        assert_eq!(socket_timeout(&config), None);
    }

    #[test]
    fn body_at_limit_is_accepted() {
        let config = ServerConfig {
            max_body_bytes: 4,
            ..ServerConfig::default()
        };
        let response = round_trip(
            config,
            b"PUT /v1/a/c/o HTTP/1.1\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest",
        );
        assert_eq!(status(&response), 200);
        assert_eq!(response_body(&response), b"test");
    }

    #[test]
    fn oversized_content_length_is_rejected_before_body_read() {
        let config = ServerConfig {
            max_body_bytes: 4,
            ..ServerConfig::default()
        };
        let response = round_trip(
            config,
            b"PUT /v1/a/c/o HTTP/1.1\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status(&response), 413);
    }

    #[test]
    fn handler_sees_a_streamed_body_with_declared_length() {
        let handler: Handler = Arc::new(|mut request: Request| {
            assert!(matches!(request.body, Body::Streamed(_)));
            assert_eq!(request.body.content_length(), Some(4));
            let bytes = request.body.materialize(u64::MAX).unwrap().to_vec();
            Response::with_body(200, bytes)
        });
        let response = round_trip_with(
            ServerConfig::default(),
            handler,
            b"PUT / HTTP/1.1\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest",
        );
        assert_eq!(status(&response), 200);
        assert_eq!(response_body(&response), b"test");
    }

    #[test]
    fn streamed_response_with_known_length_gets_content_length() {
        let handler: Handler = Arc::new(|_request: Request| {
            let payload = vec![b'x'; 200_000];
            let mut resp = Response::new(200);
            resp.body = Body::from_reader(
                Box::new(std::io::Cursor::new(payload)),
                Some(200_000),
            );
            resp
        });
        let response = round_trip_with(
            ServerConfig::default(),
            handler,
            b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status(&response), 200);
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("Content-Length: 200000"), "{text}");
        assert_eq!(response_body(&response).len(), 200_000);
    }

    #[test]
    fn streamed_response_with_unknown_length_is_close_delimited() {
        let handler: Handler = Arc::new(|_request: Request| {
            let mut resp = Response::new(200);
            resp.body =
                Body::from_reader(Box::new(std::io::Cursor::new(b"stream".to_vec())), None);
            resp
        });
        let response = round_trip_with(
            ServerConfig::default(),
            handler,
            b"GET / HTTP/1.1\r\n\r\n", // asks for keep-alive; server must close
        );
        assert_eq!(status(&response), 200);
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("Connection: close"), "{text}");
        assert!(!text.contains("Content-Length"), "{text}");
        assert_eq!(response_body(&response), b"stream");
    }

    #[test]
    fn head_streamed_body_is_dropped_unread() {
        let handler: Handler = Arc::new(|_request: Request| {
            struct Explodes;
            impl Read for Explodes {
                fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                    panic!("HEAD must not read the response body");
                }
            }
            let mut resp = Response::new(200);
            resp.headers.set("Content-Length", "10");
            resp.body = Body::from_reader(Box::new(Explodes), Some(10));
            resp
        });
        let response = round_trip_with(
            ServerConfig::default(),
            handler,
            b"HEAD / HTTP/1.1\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status(&response), 200);
        assert_eq!(response_body(&response), b"");
    }

    #[test]
    fn conflicting_or_duplicate_body_framing_is_rejected() {
        for headers in [
            "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
            "Content-Length: 0\r\nContent-Length: 0\r\n",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        ] {
            let request = format!("PUT / HTTP/1.1\r\n{headers}Connection: close\r\n\r\n");
            assert_eq!(
                status(&round_trip(ServerConfig::default(), request.as_bytes())),
                400
            );
        }
    }

    #[test]
    fn chunked_body_and_trailers_are_bounded_and_decoded() {
        let config = ServerConfig {
            max_body_bytes: 4,
            ..ServerConfig::default()
        };
        let response = round_trip(
            config.clone(),
            b"PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\ntest\r\n0\r\nX-Checksum: ok\r\n\r\n",
        );
        assert_eq!(status(&response), 200);
        assert_eq!(response_body(&response), b"test");

        // Over the limit: the decoder raises the too-large error while the
        // handler materializes, and the handler answers 413.
        let response = round_trip(
            config,
            b"PUT / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        );
        assert_eq!(status(&response), 413);
    }

    #[test]
    fn request_line_and_header_limits_are_enforced() {
        let config = ServerConfig {
            max_request_line_bytes: 16,
            ..ServerConfig::default()
        };
        let response = round_trip(
            config,
            b"GET /this-is-too-long HTTP/1.1\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status(&response), 400);

        let config = ServerConfig {
            max_header_bytes: 10,
            ..ServerConfig::default()
        };
        let response = round_trip(
            config,
            b"GET / HTTP/1.1\r\nX-Long: abcdef\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status(&response), 400);
    }

    #[test]
    fn unsupported_expectation_is_rejected_without_continue() {
        let response = round_trip(
            ServerConfig::default(),
            b"PUT / HTTP/1.1\r\nExpect: kittens\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status(&response), 417);
        assert!(!String::from_utf8_lossy(&response).contains("100 Continue"));
    }

    #[test]
    fn expect_continue_is_sent_only_when_the_body_is_read() {
        // Handler that reads: the client sees "100 Continue" then the echo.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let config = ServerConfig::default();
        let handler = echo_handler();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = handle_connection(stream, handler, &config);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(
                b"PUT / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        // Read until the interim response terminator.
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        while !seen.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).unwrap();
            seen.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 100 Continue"));
        client.write_all(b"test").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).unwrap();
        server.join().unwrap();
        assert_eq!(status(&rest), 200);
        assert_eq!(response_body(&rest), b"test");
    }

    #[test]
    fn expect_continue_is_withheld_when_the_handler_rejects_unread() {
        let handler: Handler =
            Arc::new(|_request: Request| Response::error(403, "rejected before body read"));
        let response = round_trip_with(
            ServerConfig::default(),
            handler,
            b"PUT / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n",
        );
        let text = String::from_utf8_lossy(&response);
        assert!(!text.contains("100 Continue"), "{text}");
        assert_eq!(status(&response), 403);
    }

    #[test]
    fn multiphase_interim_responses_rearm_chunked_reading() {
        // The backend two-phase PUT wire shape: the handler advertises
        // capabilities on the first 100, reads chunked sequence #1
        // (data), sends a second 100, then reads the commit from a NEW
        // chunked sequence (eventlet's chunk_length reset).
        let handler: Handler = Arc::new(|mut request: Request| {
            let interim = request.body.interim_responder().expect("interim handle");
            interim
                .send_continue(&[("X-Obj-Multiphase-Commit", "yes")])
                .unwrap();
            let (mut reader, _) = request.body.take().into_reader();
            let mut phase1 = vec![0u8; 4];
            reader.read_exact(&mut phase1).unwrap();
            // sequence #1 is exhausted here...
            let mut probe = [0u8; 1];
            assert_eq!(reader.read(&mut probe).unwrap(), 0);
            // ...until the second interim response re-arms it.
            interim.send_continue(&[]).unwrap();
            let mut phase2 = Vec::new();
            reader.read_to_end(&mut phase2).unwrap();
            assert_eq!(phase2, b"commit");
            Response::with_body(200, [&phase1[..], &phase2[..]].concat())
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let config = ServerConfig::default();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = handle_connection(stream, handler, &config);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(
                b"PUT / HTTP/1.1\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .unwrap();
        // First interim response, with the capability header.
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        while !seen.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).unwrap();
            seen.push(byte[0]);
        }
        let first = String::from_utf8_lossy(&seen);
        assert!(first.starts_with("HTTP/1.1 100 Continue"), "{first}");
        assert!(first.contains("X-Obj-Multiphase-Commit: yes"), "{first}");
        // Chunked sequence #1, terminated.
        client.write_all(b"4\r\ndata\r\n0\r\n\r\n").unwrap();
        // Second interim response.
        seen.clear();
        while !seen.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut byte).unwrap();
            seen.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 100 Continue"));
        // Chunked sequence #2 with the commit.
        client.write_all(b"6\r\ncommit\r\n0\r\n\r\n").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).unwrap();
        server.join().unwrap();
        assert_eq!(status(&rest), 200);
        assert_eq!(response_body(&rest), b"datacommit");
    }

    #[test]
    fn hijacked_connection_is_full_duplex_and_server_writes_nothing() {
        // The SSYNC shape: the handler takes the wire, answers the first
        // request-body line BEFORE the body is complete, then answers the
        // second — a mid-request response round trip in each direction.
        let handler: Handler = Arc::new(|mut request: Request| {
            let mut wire = request.body.hijack().expect("hijackable connection");
            let (mut reader, _) = request.body.take().into_reader();
            wire.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
            let read_line = |r: &mut Box<dyn Read + Send>| {
                let mut line = Vec::new();
                let mut byte = [0u8; 1];
                while r.read(&mut byte).unwrap() == 1 {
                    if byte[0] == b'\n' {
                        break;
                    }
                    line.push(byte[0]);
                }
                line
            };
            let first = read_line(&mut reader);
            wire.write_all(format!("got:{}\n", String::from_utf8_lossy(&first)).as_bytes())
                .unwrap();
            wire.flush().unwrap();
            let second = read_line(&mut reader);
            wire.write_all(format!("got:{}\n", String::from_utf8_lossy(&second)).as_bytes())
                .unwrap();
            wire.flush().unwrap();
            // The returned response is a discarded sentinel.
            Response::error(500, "must never reach the wire")
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let config = ServerConfig::default();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = handle_connection(stream, handler, &config);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(b"SSYNC / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
            .unwrap();
        // First body line as a chunk; the response head + first echo must
        // arrive BEFORE we send the second line (true duplex).
        client.write_all(b"6\r\nalpha\n\r\n").unwrap();
        let mut seen = Vec::new();
        let mut byte = [0u8; 1];
        while !seen.ends_with(b"got:alpha\n") {
            client.read_exact(&mut byte).unwrap();
            seen.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&seen).starts_with("HTTP/1.1 200 OK"));
        client.write_all(b"5\r\nbeta\n\r\n0\r\n\r\n").unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).unwrap();
        server.join().unwrap();
        let text = String::from_utf8_lossy(&rest);
        assert_eq!(text, "got:beta\n", "server must write nothing after the handler");
    }

    #[test]
    fn keep_alive_works_after_a_fully_consumed_streamed_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let config = ServerConfig::default();
        let handler = echo_handler();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = handle_connection(stream, handler, &config);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(b"PUT /one HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc")
            .unwrap();
        client
            .write_all(b"PUT /two HTTP/1.1\r\nContent-Length: 3\r\nConnection: close\r\n\r\ndef")
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut all = Vec::new();
        client.read_to_end(&mut all).unwrap();
        server.join().unwrap();
        let text = String::from_utf8_lossy(&all);
        assert_eq!(text.matches("HTTP/1.1 200").count(), 2, "{text}");
        assert!(text.contains("abc") && text.contains("def"), "{text}");
    }

    #[test]
    fn small_unconsumed_body_is_drained_for_keep_alive() {
        // Handler ignores the body entirely.
        let handler: Handler = Arc::new(|_request: Request| Response::with_body(200, "ok"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let config = ServerConfig::default();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = handle_connection(stream, handler, &config);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(b"PUT /one HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello")
            .unwrap();
        client
            .write_all(b"GET /two HTTP/1.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut all = Vec::new();
        client.read_to_end(&mut all).unwrap();
        server.join().unwrap();
        let text = String::from_utf8_lossy(&all);
        assert_eq!(text.matches("HTTP/1.1 200").count(), 2, "{text}");
    }

    #[test]
    fn large_unconsumed_body_closes_the_connection() {
        let handler: Handler = Arc::new(|_request: Request| Response::with_body(200, "ok"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let config = ServerConfig::default();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = handle_connection(stream, handler, &config);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let big = vec![b'x'; 200_000];
        let mut req = b"PUT /one HTTP/1.1\r\nContent-Length: 200000\r\n\r\n".to_vec();
        req.extend_from_slice(&big);
        req.extend_from_slice(b"GET /two HTTP/1.1\r\nConnection: close\r\n\r\n");
        // The server may close while we are still writing; ignore the error.
        let _ = client.write_all(&req);
        let _ = client.shutdown(Shutdown::Write);
        let mut all = Vec::new();
        let _ = client.read_to_end(&mut all);
        server.join().unwrap();
        let text = String::from_utf8_lossy(&all);
        // Exactly one response: the connection was not reused, and the
        // response itself already announced the close.
        assert_eq!(text.matches("HTTP/1.1 200").count(), 1, "{text}");
        assert!(text.contains("Connection: close"), "{text}");
    }

    #[test]
    fn head_deadline_defeats_slow_header_drip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let config = ServerConfig {
            head_deadline_secs: 1,
            client_timeout_secs: 60,
            ..ServerConfig::default()
        };
        let handler = echo_handler();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = handle_connection(stream, handler, &config);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let started = Instant::now();
        client.write_all(b"GET / HT").unwrap(); // stall mid-request-line
        let mut buf = Vec::new();
        let _ = client.read_to_end(&mut buf); // returns on server close
        server.join().unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "server held the slow connection for {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn response_header_newlines_are_not_serialized() {
        let mut response = Response::new(200);
        response.headers.set("X-Test", "ok\r\nInjected: true");
        let mut bytes = Vec::new();
        let error = write_response(&mut bytes, response, false, false).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!String::from_utf8_lossy(&bytes).contains("Injected: true"));
    }

    #[test]
    fn access_log_sees_the_request_head_and_response_status() {
        type Seen = Arc<Mutex<Vec<(String, String, String, u16)>>>;
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let config = ServerConfig {
            access_log: Some(Arc::new(
                move |request: &Request, status: u16, _elapsed: Duration| {
                    sink.lock().unwrap().push((
                        request.method.clone(),
                        request.path.clone(),
                        request.headers.get("X-Trans-Id").unwrap_or("").to_string(),
                        status,
                    ));
                },
            )),
            ..ServerConfig::default()
        };
        let response = round_trip(
            config,
            b"PUT /v1/a/c/o HTTP/1.1\r\nX-Trans-Id: tx123\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest",
        );
        assert_eq!(status(&response), 200);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0],
            (
                "PUT".to_string(),
                "/v1/a/c/o".to_string(),
                "tx123".to_string(),
                200
            )
        );
    }

    #[test]
    fn access_log_reports_handler_panics_as_500() {
        let seen: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let config = ServerConfig {
            access_log: Some(Arc::new(
                move |request: &Request, status: u16, _elapsed: Duration| {
                    sink.lock().unwrap().push((request.path.clone(), status));
                },
            )),
            ..ServerConfig::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handler: Handler = Arc::new(|_request| panic!("boom"));
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ = handle_connection(stream, handler, &config);
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .write_all(b"GET /boom HTTP/1.1\r\nConnection: close\r\n\r\n")
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        server.join().unwrap();
        assert_eq!(status(&response), 500);
        assert_eq!(*seen.lock().unwrap(), vec![("/boom".to_string(), 500)]);
    }

    #[test]
    fn shutdown_flag_stops_the_accept_loop_after_draining() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let config = ServerConfig {
            worker_threads: 2,
            shutdown: Some(Arc::clone(&shutdown)),
            ..ServerConfig::default()
        };
        let handler = echo_handler();
        let server =
            std::thread::spawn(move || serve_forever_with_config(listener, handler, config));

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(b"PUT / HTTP/1.1\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest")
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(status(&response), 200);
        assert_eq!(response_body(&response), b"test");

        shutdown.store(true, Ordering::SeqCst);
        // The accept loop notices the flag within one poll interval, drains
        // the workers, and returns cleanly.
        server.join().unwrap().unwrap();
    }

    #[test]
    fn install_sigterm_flag_flips_on_signal() {
        let flag = install_sigterm_flag();
        // Calling again returns the same flag rather than a fresh one.
        assert!(Arc::ptr_eq(&flag, &install_sigterm_flag()));
        // raise() delivers the signal to this thread before returning.
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        assert!(flag.load(Ordering::SeqCst));
    }
}
