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

//! Bounded HTTP/1.1 server for Swift's proxy and storage services.
//!
//! Production serve (`serve_forever*`) is a Tokio multi-thread runtime:
//! each accepted connection is a task. Idle keep-alive is a pending
//! Future on the reactor (no OS thread blocked in `read_head`).
//! `worker_threads` sizes that runtime, not one-thread-per-connection.
//!
//! [`handle_connection`] remains the synchronous unit-test path (one
//! `TcpStream`, blocking reads). It is not the production accept loop.
//!
//! Bodies STREAM: a request body is a lazily consumed reader
//! (Content-Length or chunked). Nothing object-sized is buffered here.

use std::future::Future;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWriteExt, ReadBuf};
use tokio::task::JoinSet;

use swift_runtime::{
    AdmissionController, AdmissionLimits, CancelReason, ConcurrencyMetrics, DeadlineKind,
    RuntimeTaskGuard,
};

use crate::body::{too_large_error, Body, InterimResponder, STREAM_CHUNK};
use crate::headers::HeaderKeyDict;
use crate::request::{reason_phrase, unquote, Request, Response};

/// Production HTTP/1.1 engine (AGENTS.md Phase 2). Not a custom reactor.
pub const PRODUCTION_HTTP1_ENGINE: &str = "hyper/http1";

/// Production serve is async HTTP/1.1 only (AGENTS.md §31).
///
/// `None` / empty / `async` / `hyper` / `hyper/http1` are accepted.
/// `legacy` / `sync` / `blocking` is a hard error — there is no dual-mode
/// production engine.
pub fn reject_legacy_server_runtime(raw: Option<&str>) -> Result<(), String> {
    let v = raw.map(str::trim).filter(|s| !s.is_empty());
    let Some(v) = v else {
        return Ok(());
    };
    match v.to_ascii_lowercase().as_str() {
        "async" | "hyper" | "hyper/http1" | "http1" => Ok(()),
        "legacy" | "sync" | "blocking" | "eventlet" => Err(
            "server_runtime=legacy has been removed; production serve is async HTTP/1.1 (hyper/http1)"
                .into(),
        ),
        other => Err(format!(
            "unknown server_runtime={other:?}; production serve is async HTTP/1.1 (hyper/http1)"
        )),
    }
}

/// A request handler shared across connection workers.
pub type Handler = Arc<dyn Fn(Request) -> Response + Send + Sync>;

/// Phase 3 async request: body wait is a Future, not a blocking `Read`.
pub struct AsyncRequest {
    pub method: String,
    pub path: String,
    pub query_string: String,
    pub headers: HeaderKeyDict,
    pub body: IncomingBody,
}

/// Production service ABI (AGENTS.md §8). Implementors must not `Read` the
/// client socket on a blocking worker.
pub trait AsyncService: Send + Sync + 'static {
    fn call(&self, req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>>;

    /// G3: true only for [`LegacyService`]. Native proxy/object/account/container
    /// services leave this false so `/recon/concurrency` can prove the path.
    fn is_legacy_sync_handler(&self) -> bool {
        false
    }

    /// True only for the native object service that understands Swift's
    /// metadata-footer and multiphase request-body handshake. Backend-shaped
    /// headers received by proxy/account/container services must remain on
    /// Hyper's ordinary request path instead of waiting for an interim command
    /// those services will never issue.
    fn supports_object_mime_interim(&self) -> bool {
        false
    }
}

/// Adapter: async-materialize the body, then run the sync [`Handler`] on
/// the Tokio task. Not `BlockingDomain::submit(handler)`.
pub struct LegacyService {
    handler: Handler,
}

impl LegacyService {
    pub fn new(handler: Handler) -> Self {
        Self { handler }
    }
}

impl AsyncService for LegacyService {
    fn is_legacy_sync_handler(&self) -> bool {
        true
    }

    fn call(&self, mut req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let handler = Arc::clone(&self.handler);
        Box::pin(async move {
            let max = req
                .body
                .content_length()
                .unwrap_or(u64::MAX)
                .min(crate::MAX_CONTROL_BODY)
                .min(req.body.max_body_bytes());
            if req
                .body
                .content_length()
                .is_some_and(|n| n > crate::MAX_CONTROL_BODY)
            {
                return Response::error(413, "Your request is too large.");
            }
            let body = match req.body.materialize(max).await {
                Ok(bytes) => Body::Buffered(bytes),
                Err(e) if crate::body::body_too_large(&e) => {
                    return Response::error(413, "Your request is too large.");
                }
                Err(_) => return Response::error(499, "Client Disconnect"),
            };
            let request = Request {
                method: req.method,
                path: req.path,
                query_string: req.query_string,
                headers: req.headers,
                body,
            };
            match catch_unwind(AssertUnwindSafe(|| handler(request))) {
                Ok(response) => response,
                Err(_) => Response::error(500, "request handler panicked"),
            }
        })
    }
}

/// Called after every parsed request with the request head, the response
/// status, and the time spent handling and writing the response.
pub type AccessLog = Arc<dyn Fn(&Request, u16, Duration) + Send + Sync>;

/// Fallback poll used only when a connection has no [`ServerConfig::shutdown_watch`].
/// Production accept installs a single watch poller; do not call this per conn.
const SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// After the handler, an unconsumed request-body remainder up to this
/// size is drained to keep the connection reusable; larger remainders
/// close the connection instead.
const KEEPALIVE_DRAIN_CAP: u64 = 64 * 1024;

/// Resource and protocol limits for the synchronous HTTP server.
#[derive(Clone)]
pub struct ServerConfig {
    /// Tokio multi-thread runtime size. Idle keep-alive is a pending task,
    /// not a dedicated OS worker. Not one-thread-per-connection.
    pub worker_threads: usize,
    /// Extra connection slots on top of `worker_threads`. Admission cap is
    /// `worker_threads + connection_queue`; overflow is 503.
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
    /// Fan-in for [`Self::shutdown`]. The accept loop owns one poller and
    /// publishes here; idle keep-alives wait on this receiver. They must
    /// not call [`wait_flag`] (a 1ms Sleep per conn: 100k timers drowned
    /// G7 health p99).
    pub shutdown_watch: Option<tokio::sync::watch::Receiver<bool>>,
    /// Bind with `SO_REUSEPORT` when using [`bind_listener`] (L4). No effect on
    /// an already-bound `TcpListener` passed to `serve_*`.
    pub reuse_port: bool,
    /// Independent connection admission cap. `0` derives
    /// `worker_threads + connection_queue` (does not change worker defaults).
    pub max_connections: usize,
    /// Independent in-flight request cap (legacy `max_clients` alias).
    /// `0` derives the same number as [`Self::max_connections`].
    pub max_active_requests: usize,
    /// Foreground traffic-class cap. `0` derives [`Self::max_active_requests`].
    pub max_foreground: usize,
    /// Replication traffic-class cap. `0` derives [`Self::max_active_requests`].
    pub max_replication: usize,
    /// Reconstruction traffic-class cap. `0` derives [`Self::max_active_requests`].
    pub max_reconstruction: usize,
    /// Auditor traffic-class cap. `0` derives [`Self::max_active_requests`].
    pub max_auditor: usize,
    /// Progress-aware body idle timeout in seconds. `0` uses
    /// [`Self::client_timeout_secs`]. Distinct from [`Self::max_upload_time_secs`].
    pub body_idle_timeout_secs: u64,
    /// Total upload lifetime in seconds. `0` disables. Not refreshed by chunks.
    pub max_upload_time_secs: u64,
    /// Phase 11 concurrency snapshot. `None` creates one at accept.
    pub metrics: Option<ConcurrencyMetrics>,
    /// Graceful-shutdown drain budget in seconds ([`swift_runtime::ShutdownDeadline`]).
    /// `0` means 5s. After this, HTTP connections are forced off; commit-shield
    /// tasks are still joined (never aborted).
    pub shutdown_deadline_secs: u64,
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
            .field(
                "shutdown_watch",
                &self.shutdown_watch.as_ref().map(|_| "<watch>"),
            )
            .field("reuse_port", &self.reuse_port)
            .field("max_connections", &self.max_connections)
            .field("max_active_requests", &self.max_active_requests)
            .field("max_foreground", &self.max_foreground)
            .field("max_replication", &self.max_replication)
            .field("max_reconstruction", &self.max_reconstruction)
            .field("max_auditor", &self.max_auditor)
            .field("body_idle_timeout_secs", &self.body_idle_timeout_secs)
            .field("max_upload_time_secs", &self.max_upload_time_secs)
            .field(
                "metrics",
                &self.metrics.as_ref().map(|_| "<concurrency-metrics>"),
            )
            .field("shutdown_deadline_secs", &self.shutdown_deadline_secs)
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
            // High enough that `check_metadata` can 400 "Too many metadata
            // items" (Python Eventlet has no tight parser cap). 128 431s
            // TestFile.testMetadataNumberLimit before the app sees the PUT.
            max_header_count: 1024,
            max_body_bytes: swift_core::constraints::MAX_FILE_SIZE as u64,
            access_log: None,
            shutdown: None,
            shutdown_watch: None,
            reuse_port: false,
            max_connections: 0,
            max_active_requests: 0,
            max_foreground: 0,
            max_replication: 0,
            max_reconstruction: 0,
            max_auditor: 0,
            body_idle_timeout_secs: 0,
            max_upload_time_secs: 0,
            metrics: None,
            shutdown_deadline_secs: 0,
        }
    }
}

/// Bind `addr` (`ip:port`) as a `TcpListener` with `SO_REUSEADDR`, optionally
/// adding `SO_REUSEPORT` so multiple acceptors can share the port (L4).
///
/// `SO_REUSEADDR` is unconditional: a graceful restart must be able to bind
/// while accepted sockets from the previous process are still in `TIME_WAIT`.
pub fn bind_listener(addr: &str, reuse_port: bool) -> std::io::Result<TcpListener> {
    use std::os::fd::FromRawFd;

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

    let fd = unsafe {
        libc::socket(
            match sock_addr {
                SocketAddr::V4(_) => libc::AF_INET,
                SocketAddr::V6(_) => libc::AF_INET6,
            },
            libc::SOCK_STREAM,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if let Err(e) = set_bool_sockopt(fd, libc::SO_REUSEADDR) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if reuse_port {
        if let Err(e) = set_bool_sockopt(fd, libc::SO_REUSEPORT) {
            unsafe { libc::close(fd) };
            return Err(e);
        }
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

/// Raise the listen backlog on an already-bound listener (std bind is 128
/// on Linux). `backlog` is clamped to at least 1. Idempotent.
pub fn set_listen_backlog(listener: &TcpListener, backlog: i32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let n = backlog.max(1);
    let rc = unsafe { libc::listen(listener.as_raw_fd(), n) };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
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

/// Register the process-lifecycle signals that ask a Swift worker to stop
/// accepting and drain in-flight requests. `SIGUSR1` is the Swift manager's
/// child/seamless-reload signal; treating it as an immediate Unix default
/// exit corrupts in-flight PUTs and leaves the overseer with no drain window.
/// Give the returned flag to [`ServerConfig::shutdown`]. Safe to call more
/// than once; every call returns the same flag.
pub fn install_sigterm_flag() -> Arc<AtomicBool> {
    let flag = SIGNAL_SHUTDOWN_FLAG.get_or_init(|| Arc::new(AtomicBool::new(false)));
    let handler = record_shutdown_signal as extern "C" fn(libc::c_int);
    unsafe {
        libc::signal(libc::SIGTERM, handler as libc::sighandler_t);
        libc::signal(libc::SIGINT, handler as libc::sighandler_t);
        libc::signal(libc::SIGUSR1, handler as libc::sighandler_t);
    }
    Arc::clone(flag)
}

/// Accept connections forever using conservative production defaults.
pub fn serve_forever(listener: TcpListener, handler: Handler) -> std::io::Result<()> {
    serve_forever_with_config(listener, handler, ServerConfig::default())
}

/// Accept connections with a Tokio multi-thread runtime and explicit limits.
///
/// Each connection is a task. Idle keep-alive waits as a pending Future.
/// `worker_threads` sizes the runtime, not a thread-per-connection pool.
///
/// With `config.shutdown` unset this accepts forever (only an accept error
/// returns). With it set, the accept loop polls the flag and, once true,
/// stops accepting, drains in-flight connection tasks, and returns `Ok(())`.
pub fn serve_forever_with_config(
    listener: TcpListener,
    handler: Handler,
    config: ServerConfig,
) -> std::io::Result<()> {
    serve_forever_multi(vec![listener], handler, config)
}

/// Like [`serve_forever_with_config`], but accept from multiple listeners
/// (`servers_per_port` / multi-port topology).
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
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_count)
        .thread_name("swift-http")
        .enable_io()
        .enable_time()
        .build()?;
    let service: Arc<dyn AsyncService> = Arc::new(LegacyService::new(handler));
    rt.block_on(accept_loop_async(listeners, service, config))
}

/// Production serve with an [`AsyncService`] (Phase 3 ABI). Socket wait is a
/// Future. The whole legacy `Handler` is not one `BlockingDomain` job.
pub fn serve_forever_multi_service(
    listeners: Vec<TcpListener>,
    service: Arc<dyn AsyncService>,
    config: ServerConfig,
) -> std::io::Result<()> {
    if listeners.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "serve_forever_multi requires at least one listener",
        ));
    }
    let worker_count = config.worker_threads.max(1);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_count)
        .thread_name("swift-http")
        .enable_io()
        .enable_time()
        .build()?;
    rt.block_on(accept_loop_async(listeners, service, config))
}

fn derived_connection_cap(config: &ServerConfig) -> usize {
    if config.max_connections > 0 {
        config.max_connections
    } else {
        config
            .worker_threads
            .max(1)
            .saturating_add(config.connection_queue)
            .max(1)
    }
}

fn derived_request_cap(config: &ServerConfig) -> usize {
    if config.max_active_requests > 0 {
        config.max_active_requests
    } else {
        derived_connection_cap(config)
    }
}

fn class_cap(explicit: usize, requests: usize) -> usize {
    if explicit > 0 {
        explicit
    } else {
        requests
    }
}

async fn accept_loop_async(
    listeners: Vec<TcpListener>,
    service: Arc<dyn AsyncService>,
    mut config: ServerConfig,
) -> std::io::Result<()> {
    let mut tokio_listeners = Vec::with_capacity(listeners.len());
    for listener in listeners {
        listener.set_nonblocking(true)?;
        tokio_listeners.push(tokio::net::TcpListener::from_std(listener)?);
    }

    let max_conn = derived_connection_cap(&config);
    let max_req = derived_request_cap(&config);
    let admission = AdmissionController::new(AdmissionLimits::new(
        max_conn,
        max_req,
        class_cap(config.max_foreground, max_req),
        class_cap(config.max_replication, max_req),
        class_cap(config.max_reconstruction, max_req),
        class_cap(config.max_auditor, max_req),
    ));
    let metrics = config
        .metrics
        .clone()
        .unwrap_or_else(ConcurrencyMetrics::new);
    metrics.attach_admission(admission.clone());
    metrics.set_worker_threads(config.worker_threads);
    config.metrics = Some(metrics.clone());
    let shutdown = config
        .shutdown
        .clone()
        .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    // One poller watches the signal-safe AtomicBool and publishes to a
    // watch channel. Idle keep-alives wait on the receiver (no timer).
    let (sd_tx, sd_rx) = tokio::sync::watch::channel(shutdown.load(Ordering::SeqCst));
    {
        let flag = Arc::clone(&shutdown);
        tokio::spawn(async move {
            loop {
                if flag.load(Ordering::SeqCst) {
                    let _ = sd_tx.send(true);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }
    config.shutdown_watch = Some(sd_rx.clone());

    // Spawn each connection from the acceptor. A JoinSet of every live
    // connection made accept O(live) under 50k idle keep-alives and
    // delayed health HEAD past the G7 p99 bound.
    let live = Arc::new(AtomicUsize::new(0));
    struct LiveGuard(Arc<AtomicUsize>);
    impl Drop for LiveGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let mut acceptors = JoinSet::new();
    for listener in tokio_listeners {
        let shutdown = Arc::clone(&shutdown);
        let admission = admission.clone();
        let service = Arc::clone(&service);
        let config = config.clone();
        let metrics = metrics.clone();
        let live = Arc::clone(&live);
        let mut sd_rx = sd_rx.clone();
        acceptors.spawn(async move {
            let spawn_connection = |stream: tokio::net::TcpStream| {
                match admission.try_acquire_connection() {
                    Ok(permit) => {
                        let service = Arc::clone(&service);
                        let config = config.clone();
                        let shutdown = Arc::clone(&shutdown);
                        let admission = admission.clone();
                        let metrics = metrics.clone();
                        let live = Arc::clone(&live);
                        live.fetch_add(1, Ordering::SeqCst);
                        metrics.runtime_tasks_inc();
                        let scheduled = Instant::now();
                        tokio::spawn(async move {
                            let _live = LiveGuard(live);
                            metrics.observe_scheduler_lag(scheduled.elapsed());
                            let _task = RuntimeTaskGuard(Some(metrics.clone()));
                            let _permit = permit;
                            let connection_result = metrics
                                .bind(handle_connection_async(
                                    stream, service, config, shutdown, admission,
                                ))
                                .await;
                            if let Err(error) = connection_result {
                                eprintln!(
                                    "G6_DIAG swift-http stage=connection-error error={error}"
                                );
                            }
                        });
                    }
                    Err(_) => {
                        // Never block accept on a 503 write.
                        tokio::spawn(async move {
                            crate::hyper_serve::reject_overloaded(stream).await;
                        });
                    }
                }
            };
            loop {
                tokio::select! {
                    biased;
                    _ = wait_watch(&mut sd_rx) => {
                        break;
                    },
                    acc = listener.accept() => {
                        match acc {
                            Ok((stream, _)) => spawn_connection(stream),
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(e) if matches!(e.raw_os_error(), Some(23) | Some(24)) => {
                                // ENFILE/EMFILE: keep accepting when fds return.
                                tokio::time::sleep(Duration::from_millis(1)).await;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
            }

            // A TCP handshake and request head may already be in the kernel
            // accept backlog when shutdown wins the select. Convert back to
            // the nonblocking std listener so accept() performs the syscall
            // immediately instead of waiting for Tokio reactor readiness;
            // drain only what is queued, then drop the listener.
            let listener = listener.into_std()?;
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(true)?;
                        spawn_connection(tokio::net::TcpStream::from_std(stream)?);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if matches!(e.raw_os_error(), Some(23) | Some(24)) => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        });
    }

    let mut accept_err = None;
    let mut sd_rx = sd_rx;
    loop {
        tokio::select! {
            _ = wait_watch(&mut sd_rx) => {
                let snap = metrics.snapshot();
                metrics.set_graceful_shutdown_requests(snap.runtime_tasks.max(1));
                metrics.set_shutdown_waiting_requests(admission.requests_active());
                metrics.set_shutdown_waiting_commits(snap.commit_shield_active as usize);
                break;
            }
            acc = acceptors.join_next(), if !acceptors.is_empty() => {
                match acc {
                    Some(Ok(Err(e))) => {
                        accept_err = Some(e);
                        shutdown.store(true, Ordering::SeqCst);
                        break;
                    }
                    Some(Err(_)) => {
                        accept_err = Some(std::io::Error::other("accept task panicked"));
                        shutdown.store(true, Ordering::SeqCst);
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    while acceptors.join_next().await.is_some() {}
    let drain_secs = if config.shutdown_deadline_secs > 0 {
        config.shutdown_deadline_secs
    } else {
        5
    };
    let drain_until = Instant::now() + Duration::from_secs(drain_secs);
    while live.load(Ordering::SeqCst) > 0 {
        metrics.set_shutdown_waiting_requests(live.load(Ordering::SeqCst));
        if Instant::now() >= drain_until {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // L7: HTTP may already be forced off; commit-shield tasks still finish.
    metrics.join_remaining_shields().await;
    match accept_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

pub(crate) async fn wait_flag(flag: &AtomicBool) {
    loop {
        if flag.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(SHUTDOWN_POLL_INTERVAL).await;
    }
}

/// `watch::wait_for` holds a `RwLockReadGuard` across `.await` and is `!Send`.
/// `changed()` + a dropped `borrow()` is Send and has no per-conn timer.
pub(crate) async fn wait_watch(rx: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Idle keep-alive shutdown wait: watch receiver (no timer) when the accept
/// loop installed one; otherwise the 1ms fallback (tests without accept).
pub(crate) async fn wait_shutdown(config: &ServerConfig, flag: &AtomicBool) {
    if flag.load(Ordering::SeqCst) {
        return;
    }
    if let Some(mut rx) = config.shutdown_watch.clone() {
        wait_watch(&mut rx).await;
        return;
    }
    wait_flag(flag).await;
}



/// Buffered async read half. Leftover from a request body can be prepended
/// so the next keep-alive head parse sees the next request, not a hole.
#[allow(dead_code)]
struct ConnRead {
    io: tokio::net::tcp::OwnedReadHalf,
    buf: Vec<u8>,
    pos: usize,
}

#[allow(dead_code)]
impl ConnRead {
    fn new(io: tokio::net::tcp::OwnedReadHalf) -> Self {
        Self {
            io,
            buf: Vec::with_capacity(8192),
            pos: 0,
        }
    }

    fn prepend(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let rest = self.buf[self.pos..].to_vec();
        self.buf.clear();
        self.pos = 0;
        self.buf.extend_from_slice(data);
        self.buf.extend_from_slice(&rest);
    }
}

#[allow(dead_code)]
impl AsyncRead for ConnRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.buf.len() {
            let avail = &this.buf[this.pos..];
            let n = avail.len().min(buf.remaining());
            buf.put_slice(&avail[..n]);
            this.pos += n;
            if this.pos >= this.buf.len() {
                this.buf.clear();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.io).poll_read(cx, buf)
    }
}

#[allow(dead_code)]
impl AsyncBufRead for ConnRead {
    fn poll_fill_buf(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        let this = self.get_mut();
        if this.pos < this.buf.len() {
            return Poll::Ready(Ok(&this.buf[this.pos..]));
        }
        this.buf.clear();
        this.pos = 0;
        this.buf.resize(8192, 0);
        let mut rb = ReadBuf::new(&mut this.buf);
        match Pin::new(&mut this.io).poll_read(cx, &mut rb) {
            Poll::Pending => {
                this.buf.clear();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => {
                this.buf.clear();
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                this.buf.truncate(n);
                Poll::Ready(Ok(&this.buf[..]))
            }
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let this = self.get_mut();
        this.pos = this.pos.saturating_add(amt);
        if this.pos >= this.buf.len() {
            this.buf.clear();
            this.pos = 0;
        }
    }
}

/// Pull-based wire-to-payload transform (S3 aws-chunked, etc.).
///
/// `push(Some(bytes))` consumes a source chunk. `push(None)` is source EOF.
/// Return payload bytes (possibly empty if more wire is needed). Memory must
/// not grow with total object size — only with the current transform window.
pub trait BodyTransform: Send {
    fn push(&mut self, input: Option<&[u8]>) -> std::io::Result<Vec<u8>>;
}

/// Async incoming body. `next_chunk` awaits the client socket (L1).
/// Owned so Hyper can hand the body to the service without borrowing the
/// connection task.
pub struct IncomingBody {
    inner: IncomingInner,
    max_body: u64,
    decoded: u64,
    body_idle: Option<swift_runtime::BodyIdleDeadline>,
    upload_lifetime: Option<swift_runtime::UploadLifetimeDeadline>,
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    metrics: Option<ConcurrencyMetrics>,
    buffered: usize,
    async_interim: Option<tokio::sync::mpsc::Sender<AsyncInterimCommand>>,
}

/// One capability-bearing informational response requested by a native async
/// service. The HTTP runtime owns the socket write half; the service only
/// requests the response and waits for an acknowledgement that it reached the
/// wire. This keeps the object-server multiphase PUT handshake off blocking
/// compatibility paths.
pub(crate) struct AsyncInterimCommand {
    pub headers: Vec<(String, String)>,
    pub ack: tokio::sync::oneshot::Sender<std::io::Result<()>>,
}

enum IncomingInner {
    Hyper(hyper::body::Incoming),
    Memory { data: Vec<u8>, pos: usize },
    Channel {
        rx: tokio::sync::mpsc::Receiver<Result<Vec<u8>, std::io::Error>>,
        _scope: Option<swift_runtime::TaskScope>,
        content_length: Option<u64>,
    },
    Transform {
        source: Box<IncomingBody>,
        xform: Box<dyn BodyTransform>,
        pending: Vec<u8>,
        source_eof: bool,
        decoded_len: Option<u64>,
    },
}

impl IncomingBody {
    pub fn from_hyper(incoming: hyper::body::Incoming, max_body: u64) -> Self {
        Self {
            inner: IncomingInner::Hyper(incoming),
            max_body,
            decoded: 0,
            body_idle: None,
            upload_lifetime: None,
            on_upgrade: None,
            metrics: ConcurrencyMetrics::current(),
            buffered: 0,
            async_interim: None,
        }
    }

    pub fn from_bytes(data: Vec<u8>, max_body: u64) -> Self {
        let buffered = data.len();
        let metrics = ConcurrencyMetrics::current();
        if let Some(ref m) = metrics {
            m.add_request_body_buffer(buffered as i64);
        }
        Self {
            inner: IncomingInner::Memory { data, pos: 0 },
            max_body,
            decoded: 0,
            body_idle: None,
            upload_lifetime: None,
            on_upgrade: None,
            metrics,
            buffered,
            async_interim: None,
        }
    }

    /// Drive a [`crate::Body::Channel`] as a request body (COPY source GET
    /// teed into a destination PUT without materializing the object).
    pub fn from_channel(
        rx: tokio::sync::mpsc::Receiver<Result<Vec<u8>, std::io::Error>>,
        content_length: Option<u64>,
        scope: Option<swift_runtime::TaskScope>,
        max_body: u64,
    ) -> Self {
        let buffered = content_length.unwrap_or(0) as usize;
        let metrics = ConcurrencyMetrics::current();
        if let Some(ref m) = metrics {
            m.add_request_body_buffer(buffered as i64);
        }
        Self {
            inner: IncomingInner::Channel {
                rx,
                _scope: scope,
                content_length,
            },
            max_body,
            decoded: 0,
            body_idle: None,
            upload_lifetime: None,
            on_upgrade: None,
            metrics,
            buffered,
            async_interim: None,
        }
    }

    pub(crate) fn attach_async_interim(
        &mut self,
        sender: tokio::sync::mpsc::Sender<AsyncInterimCommand>,
    ) {
        self.async_interim = Some(sender);
    }

    /// Send a `100 Continue` through the async connection owner. The method
    /// completes only after the informational response has been flushed, so
    /// the caller may safely begin awaiting the corresponding request phase.
    pub async fn send_continue(&mut self, headers: &[(&str, &str)]) -> std::io::Result<()> {
        let Some(sender) = &self.async_interim else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "async interim responder is unavailable",
            ));
        };
        let (ack, received) = tokio::sync::oneshot::channel();
        sender
            .send(AsyncInterimCommand {
                headers: headers
                    .iter()
                    .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                    .collect(),
                ack,
            })
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "async interim connection closed",
                )
            })?;
        received.await.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "async interim acknowledgement dropped",
            )
        })?
    }

    /// Decode/transform `self` as `next_chunk` is pulled. Does not spawn a
    /// task: backpressure is the consumer, and the transform window is owned
    /// by [`BodyTransform`].
    pub fn with_transform(
        mut self,
        xform: Box<dyn BodyTransform>,
        decoded_len: Option<u64>,
    ) -> Self {
        let max_body = decoded_len.unwrap_or(self.max_body);
        let metrics = self.metrics.clone();
        let async_interim = self.async_interim.take();
        Self {
            inner: IncomingInner::Transform {
                source: Box::new(self),
                xform,
                pending: Vec::new(),
                source_eof: false,
                decoded_len,
            },
            max_body,
            decoded: 0,
            body_idle: None,
            upload_lifetime: None,
            on_upgrade: None,
            metrics,
            buffered: 0,
            async_interim,
        }
    }

    pub fn set_upgrade(&mut self, on_upgrade: hyper::upgrade::OnUpgrade) {
        self.on_upgrade = Some(on_upgrade);
    }

    pub fn take_upgrade(&mut self) -> Option<hyper::upgrade::OnUpgrade> {
        self.on_upgrade.take()
    }

    pub fn set_body_idle(&mut self, deadline: swift_runtime::BodyIdleDeadline) {
        self.body_idle = Some(deadline);
    }

    pub fn set_upload_lifetime(&mut self, deadline: swift_runtime::UploadLifetimeDeadline) {
        self.upload_lifetime = Some(deadline);
    }

    pub fn max_body_bytes(&self) -> u64 {
        self.max_body
    }

    pub fn content_length(&self) -> Option<u64> {
        match &self.inner {
            IncomingInner::Memory { data, pos } => Some((data.len().saturating_sub(*pos)) as u64),
            IncomingInner::Hyper(incoming) => http_body::Body::size_hint(incoming).exact(),
            IncomingInner::Channel { content_length, .. } => *content_length,
            IncomingInner::Transform { decoded_len, .. } => *decoded_len,
        }
    }

    pub async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self
            .upload_lifetime
            .as_ref()
            .is_some_and(|d| d.is_expired())
        {
            self.record_timeout(DeadlineKind::UploadLifetime);
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "upload lifetime exceeded",
            ));
        }
        let idle = self.body_idle.map(|d| d.remaining());
        let idle_expired = self.body_idle.is_some() && idle == Some(Duration::ZERO);
        if idle_expired {
            self.record_timeout(DeadlineKind::BodyIdle);
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "body idle timeout",
            ));
        }
        let result = if let Some(idle) = idle.filter(|d| !d.is_zero()) {
            match tokio::time::timeout(idle, self.next_chunk_inner()).await {
                Ok(r) => r,
                Err(_) => {
                    self.record_timeout(DeadlineKind::BodyIdle);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "body idle timeout",
                    ))
                }
            }
        } else {
            self.next_chunk_inner().await
        };
        if let Ok(Some(chunk)) = &result {
            if let Some(idle) = self.body_idle.as_mut() {
                idle.refresh_on_progress();
            }
            let n = chunk.len().min(self.buffered);
            self.buffered = self.buffered.saturating_sub(n);
            if n > 0 {
                if let Some(ref m) = self.metrics {
                    m.add_request_body_buffer(-(n as i64));
                }
            }
        }
        result
    }

    fn record_timeout(&self, kind: DeadlineKind) {
        if let Some(ref m) = self.metrics {
            m.record_timeout(kind);
            m.record_cancellation(CancelReason::Timeout);
        } else {
            ConcurrencyMetrics::record_timeout_current(kind);
            ConcurrencyMetrics::record_cancellation_current(CancelReason::Timeout);
        }
    }

    async fn next_chunk_inner(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        match &mut self.inner {
            IncomingInner::Memory { data, pos } => {
                if *pos >= data.len() {
                    return Ok(None);
                }
                let end = (*pos + STREAM_CHUNK).min(data.len());
                let chunk = data[*pos..end].to_vec();
                *pos = end;
                self.decoded = self.decoded.saturating_add(chunk.len() as u64);
                if self.decoded > self.max_body {
                    return Err(too_large_error());
                }
                Ok(Some(chunk))
            }
            IncomingInner::Hyper(incoming) => {
                use http_body_util::BodyExt;
                loop {
                    match incoming.frame().await {
                        Some(Ok(frame)) => {
                            let Ok(data) = frame.into_data() else {
                                continue;
                            };
                            if data.is_empty() {
                                continue;
                            }
                            self.decoded = self.decoded.saturating_add(data.len() as u64);
                            if self.decoded > self.max_body {
                                return Err(too_large_error());
                            }
                            return Ok(Some(data.to_vec()));
                        }
                        Some(Err(e)) => {
                            return Err(std::io::Error::other(e.to_string()));
                        }
                        None => return Ok(None),
                    }
                }
            }
            IncomingInner::Channel { rx, .. } => match rx.recv().await {
                Some(Ok(chunk)) => {
                    if chunk.is_empty() {
                        return Ok(None);
                    }
                    self.decoded = self.decoded.saturating_add(chunk.len() as u64);
                    if self.decoded > self.max_body {
                        return Err(too_large_error());
                    }
                    Ok(Some(chunk))
                }
                Some(Err(e)) => Err(e),
                None => Ok(None),
            },
            IncomingInner::Transform {
                source,
                xform,
                pending,
                source_eof,
                decoded_len: _,
            } => loop {
                if !pending.is_empty() {
                    let n = pending.len().min(STREAM_CHUNK);
                    let chunk: Vec<u8> = pending.drain(..n).collect();
                    self.decoded = self.decoded.saturating_add(chunk.len() as u64);
                    if self.decoded > self.max_body {
                        return Err(too_large_error());
                    }
                    return Ok(Some(chunk));
                }
                if *source_eof {
                    return Ok(None);
                }
                match Box::pin(source.next_chunk()).await? {
                    Some(wire) => {
                        let out = xform.push(Some(&wire))?;
                        if out.is_empty() {
                            continue;
                        }
                        *pending = out;
                    }
                    None => {
                        *source_eof = true;
                        let out = xform.push(None)?;
                        if out.is_empty() {
                            return Ok(None);
                        }
                        *pending = out;
                    }
                }
            },
        }
    }

    pub async fn materialize(&mut self, max: u64) -> std::io::Result<Vec<u8>> {
        let cap = max.min(self.max_body);
        let mut out = Vec::new();
        while let Some(chunk) = self.next_chunk().await? {
            if out.len() as u64 + chunk.len() as u64 > cap {
                return Err(too_large_error());
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

impl Drop for IncomingBody {
    fn drop(&mut self) {
        if self.buffered > 0 {
            if let Some(ref m) = self.metrics {
                m.add_request_body_buffer(-(self.buffered as i64));
            }
            self.buffered = 0;
        }
    }
}

async fn handle_connection_async(
    stream: tokio::net::TcpStream,
    service: Arc<dyn AsyncService>,
    config: ServerConfig,
    shutdown: Arc<AtomicBool>,
    admission: AdmissionController,
) -> std::io::Result<()> {
    crate::hyper_serve::serve_http1_connection(stream, service, config, shutdown, admission).await
}

#[allow(dead_code)]
async fn read_head_async(
    reader: &mut ConnRead,
    config: &ServerConfig,
    keepalive: bool,
) -> Result<Option<RequestHead>, ProtocolError> {
    let idle = socket_timeout(config);
    if keepalive {
        let wait = idle.unwrap_or(Duration::from_secs(24 * 3600));
        match tokio::time::timeout(wait, reader.fill_buf()).await {
            Err(_) => return Ok(None),
            Ok(Ok([])) => return Ok(None),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(ProtocolError::Io(e)),
        }
    }

    let deadline = (config.head_deadline_secs > 0)
        .then(|| Instant::now() + Duration::from_secs(config.head_deadline_secs));

    let mut acc = Vec::new();
    // Skip leading blank lines, then request-line + headers until the
    // terminator. Limits are re-checked by [`read_head`].
    loop {
        let timeout = match deadline {
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(ProtocolError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "request head deadline exceeded",
                    )));
                }
                Some(left)
            }
            None => idle,
        };
        let max = if acc.is_empty() {
            config.max_request_line_bytes
        } else {
            config.max_header_line_bytes
        };
        let Some(line) = read_line_async(reader, max, timeout).await? else {
            return if acc.is_empty() {
                Ok(None)
            } else {
                Err(ProtocolError::Http(400, "truncated request headers"))
            };
        };
        let empty = line_text(&line)?.is_empty();
        if acc.is_empty() && empty {
            continue;
        }
        acc.extend_from_slice(&line);
        if empty {
            break;
        }
        if acc.len() > config.max_header_bytes.saturating_add(config.max_request_line_bytes) {
            return Err(ProtocolError::Http(400, "request headers too large"));
        }
    }
    let mut cursor = BufReader::new(Cursor::new(acc));
    read_head(&mut cursor, config)
}

#[allow(dead_code)]
async fn read_line_async(
    reader: &mut ConnRead,
    max_bytes: usize,
    timeout: Option<Duration>,
) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut line = Vec::with_capacity(max_bytes.min(1024));
    let fut = reader.read_until(b'\n', &mut line);
    let read = match timeout {
        Some(t) => match tokio::time::timeout(t, fut).await {
            Err(_) => {
                return Err(ProtocolError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "request head deadline exceeded",
                )));
            }
            Ok(r) => r?,
        },
        None => fut.await?,
    };
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

#[allow(dead_code)]
async fn write_error_response_async(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    status: u16,
    message: &str,
) -> std::io::Result<()> {
    write_response_async(writer, Response::error(status, message), false, false)
        .await
        .map(|_| ())
}

#[allow(dead_code)]
async fn write_response_async(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
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
    let mut head = format!("HTTP/1.1 {} {}\r\n", response.status, response.reason);
    for (name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("Connection") || name.eq_ignore_ascii_case("Transfer-Encoding")
        {
            continue;
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(if keep_alive {
        "Connection: keep-alive\r\n\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    writer.write_all(head.as_bytes()).await?;
    if !head_request {
        match body {
            Body::Buffered(bytes) => {
                writer.write_all(&bytes).await?;
            }
            Body::Streamed(_) | Body::Channel(_) => {
                let (mut src, _) = body.into_reader();
                let mut buf = [0u8; STREAM_CHUNK];
                loop {
                    let n = src.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    writer.write_all(&buf[..n]).await?;
                }
            }
        }
    }
    writer.flush().await?;
    Ok(keep_alive)
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
#[allow(dead_code)]
type DeadlineCell = Arc<Mutex<Option<Instant>>>;

/// A `TcpStream` reader that, while a head deadline is armed, bounds each
/// `read` by the time remaining (so a client dripping header bytes cannot
/// stretch one line past the budget). With the deadline disarmed, reads
/// carry the plain per-chunk `client_timeout`.
#[allow(dead_code)]
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
            let Some(remaining) = deadline
                .checked_duration_since(now)
                .filter(|d| !d.is_zero())
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

#[allow(dead_code)]
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
struct ReclaimedConn<R> {
    reader: R,
    fully_consumed: bool,
    /// Bytes left on the wire when known (`Sized` framing); `None` for an
    /// unfinished chunked body (unbounded, never drained).
    remaining: Option<u64>,
    /// `Expect: 100-continue` was requested but never answered - the
    /// client has not sent the body, so there is nothing to drain and the
    /// connection must close.
    continue_pending: bool,
}

type ReclaimSlot<R> = Arc<Mutex<Option<ReclaimedConn<R>>>>;

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
struct ConnBodyReader<R> {
    reader: Option<R>,
    framing: Framing,
    limits: BodyLimits,
    interim: InterimResponder,
    expect_continue: bool,
    slot: ReclaimSlot<R>,
}

impl<R> ConnBodyReader<R> {
    fn maybe_send_continue(&mut self) -> std::io::Result<()> {
        if self.expect_continue {
            self.interim.send_bare_if_unsent()?;
        }
        Ok(())
    }
}

impl<R: BufRead> Read for ConnBodyReader<R> {
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
                        // (Python Swift's multiphase-PUT semantics).
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

impl<R> Drop for ConnBodyReader<R> {
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

#[allow(dead_code)]
fn handle_connection(
    stream: TcpStream,
    handler: Handler,
    config: &ServerConfig,
) -> std::io::Result<()> {
    stream.set_nodelay(true).ok();
    // REMOTE_ADDR equivalent for middleware (TempURL ip_range, logging).
    let peer_ip = stream.peer_addr().ok().map(|a| a.ip().to_string());
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
    let slot: ReclaimSlot<ConnReader> = Arc::new(Mutex::new(None));

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
            // (Python swob semantics). The hijack half is always available — a
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
            let _ = stream.shutdown(Shutdown::Write);
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
fn read_head<R: BufRead>(
    reader: &mut R,
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

#[allow(dead_code)]
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
#[allow(dead_code)]
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
            Body::Streamed(_) | Body::Channel(_) => {
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
    use std::os::fd::AsRawFd;

    #[test]
    fn bind_listener_always_enables_reuseaddr() {
        let listener = bind_listener("127.0.0.1:0", false).unwrap();
        let mut enabled: libc::c_int = 0;
        let mut len = std::mem::size_of_val(&enabled) as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &mut enabled as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        assert_eq!(
            rc,
            0,
            "getsockopt(SO_REUSEADDR) failed: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(enabled, 1);
    }

    #[test]
    fn production_engine_is_hyper_http1() {
        assert_eq!(PRODUCTION_HTTP1_ENGINE, "hyper/http1");
        assert!(!PRODUCTION_HTTP1_ENGINE.contains("http2"));
    }

    #[test]
    fn reject_legacy_server_runtime_is_the_only_production_choice() {
        assert!(reject_legacy_server_runtime(None).is_ok());
        assert!(reject_legacy_server_runtime(Some("")).is_ok());
        assert!(reject_legacy_server_runtime(Some("async")).is_ok());
        assert!(reject_legacy_server_runtime(Some("hyper/http1")).is_ok());
        let err = reject_legacy_server_runtime(Some("legacy")).unwrap_err();
        assert!(err.contains("removed"), "{err}");
        assert!(reject_legacy_server_runtime(Some("sync")).is_err());
        assert!(reject_legacy_server_runtime(Some("blocking")).is_err());
    }

    /// Echo handler used by most round trips: materializes the body the
    /// way a real control-plane handler would, mapping the too-large
    /// error to 413.
    fn echo_handler() -> Handler {
        Arc::new(
            |mut request: Request| match request.body.materialize(u64::MAX) {
                Ok(_) => {
                    let bytes = request.body.into_vec(u64::MAX).unwrap();
                    Response::with_body(200, bytes)
                }
                Err(e) if body_too_large(&e) => Response::error(413, "body too large"),
                Err(e) => Response::error(500, &e.to_string()),
            },
        )
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

    fn read_one_http_response(stream: &mut TcpStream) -> Vec<u8> {
        let mut response = Vec::new();
        let mut byte = [0u8; 1];
        while !response.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            response.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&response);
        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("Content-Length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let mut body = vec![0u8; content_length];
        stream.read_exact(&mut body).unwrap();
        response.extend_from_slice(&body);
        response
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
            resp.body = Body::from_reader(Box::new(std::io::Cursor::new(payload)), Some(200_000));
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
            resp.body = Body::from_reader(Box::new(std::io::Cursor::new(b"stream".to_vec())), None);
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
        // chunked sequence (Python Swift's chunk_length reset).
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
            .write_all(
                b"SSYNC / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
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
        assert_eq!(
            text, "got:beta\n",
            "server must write nothing after the handler"
        );
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

    struct DelayedBodyEcho {
        started: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    }

    impl AsyncService for DelayedBodyEcho {
        fn call(
            &self,
            mut request: AsyncRequest,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            let started = self.started.lock().unwrap().take();
            Box::pin(async move {
                if let Some(started) = started {
                    let _ = started.send(());
                }
                match request.body.materialize(1024).await {
                    Ok(body) => Response::with_body(200, body),
                    Err(error) => Response::error(500, &error.to_string()),
                }
            })
        }
    }

    struct SecondRequestDelayedBodyEcho {
        calls: AtomicUsize,
        second_started: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    }

    impl AsyncService for SecondRequestDelayedBodyEcho {
        fn call(
            &self,
            mut request: AsyncRequest,
        ) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let second_started = if call == 1 {
                self.second_started.lock().unwrap().take()
            } else {
                None
            };
            Box::pin(async move {
                if let Some(second_started) = second_started {
                    let _ = second_started.send(());
                }
                match request.body.materialize(1024).await {
                    Ok(body) => Response::with_body(200, body),
                    Err(error) => Response::error(500, &error.to_string()),
                }
            })
        }
    }

    #[test]
    fn graceful_shutdown_drains_delayed_body_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let config = ServerConfig {
            worker_threads: 2,
            shutdown: Some(Arc::clone(&shutdown)),
            shutdown_deadline_secs: 2,
            ..ServerConfig::default()
        };
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let service: Arc<dyn AsyncService> = Arc::new(DelayedBodyEcho {
            started: std::sync::Mutex::new(Some(started_tx)),
        });
        let server = std::thread::spawn(move || {
            serve_forever_multi_service(vec![listener], service, config)
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(b"PUT / HTTP/1.1\r\nContent-Length: 4\r\n\r\n")
            .unwrap();
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("server accepted the request head");

        shutdown.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(50));
        client.write_all(b"test").unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        assert_eq!(status(&response), 200);
        assert_eq!(response_body(&response), b"test");
        server.join().unwrap().unwrap();
    }

    #[test]
    fn graceful_shutdown_keeps_first_request_on_accepted_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let metrics = ConcurrencyMetrics::new();
        let config = ServerConfig {
            worker_threads: 2,
            shutdown: Some(Arc::clone(&shutdown)),
            shutdown_deadline_secs: 2,
            metrics: Some(metrics.clone()),
            ..ServerConfig::default()
        };
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let service: Arc<dyn AsyncService> = Arc::new(DelayedBodyEcho {
            started: std::sync::Mutex::new(Some(started_tx)),
        });
        let server = std::thread::spawn(move || {
            serve_forever_multi_service(vec![listener], service, config)
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let accepted_deadline = Instant::now() + Duration::from_secs(2);
        while metrics.snapshot().runtime_tasks == 0 {
            assert!(Instant::now() < accepted_deadline, "connection was not accepted");
            std::thread::sleep(Duration::from_millis(5));
        }

        shutdown.store(true, Ordering::SeqCst);
        client
            .write_all(b"PUT / HTTP/1.1\r\nContent-Length: 4\r\n\r\n")
            .unwrap();
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first request on accepted socket survived shutdown");
        client.write_all(b"test").unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        assert_eq!(status(&response), 200);
        assert_eq!(response_body(&response), b"test");
        server.join().unwrap().unwrap();
    }

    #[test]
    fn graceful_shutdown_drains_raced_second_request_on_keepalive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let config = ServerConfig {
            worker_threads: 2,
            shutdown: Some(Arc::clone(&shutdown)),
            shutdown_deadline_secs: 2,
            ..ServerConfig::default()
        };
        let (second_started_tx, second_started_rx) = std::sync::mpsc::channel();
        let service: Arc<dyn AsyncService> = Arc::new(SecondRequestDelayedBodyEcho {
            calls: AtomicUsize::new(0),
            second_started: std::sync::Mutex::new(Some(second_started_tx)),
        });
        let server = std::thread::spawn(move || {
            serve_forever_multi_service(vec![listener], service, config)
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(b"PUT /sanity HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
        let first = read_one_http_response(&mut client);
        assert_eq!(status(&first), 200);

        // Hyper has completed one request on this persistent connection and
        // has started reading the next head, but Service::call cannot run
        // until the terminator arrives. This is the deterministic form of
        // Python Swift's old-reload race.
        client
            .write_all(b"PUT /across-reload HTTP/1.1\r\nContent-Length: 4\r\n")
            .unwrap();
        shutdown.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(50));
        client.write_all(b"\r\n").unwrap();
        second_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("raced second request head must survive graceful shutdown");
        client.write_all(b"test").unwrap();
        let second = read_one_http_response(&mut client);

        assert_eq!(status(&second), 200);
        assert_eq!(response_body(&second), b"test");
        server.join().unwrap().unwrap();
    }

    #[test]
    fn graceful_shutdown_drains_request_already_in_accept_backlog() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let config = ServerConfig {
            worker_threads: 2,
            shutdown: Some(Arc::clone(&shutdown)),
            shutdown_deadline_secs: 2,
            ..ServerConfig::default()
        };
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let service: Arc<dyn AsyncService> = Arc::new(DelayedBodyEcho {
            started: std::sync::Mutex::new(Some(started_tx)),
        });

        // Complete the TCP handshake and queue the request head before the
        // runtime gets a chance to accept it. This is the old-reload race:
        // the manager's shutdown signal and Hyper's first accept cross.
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .write_all(b"PUT / HTTP/1.1\r\nContent-Length: 4\r\n\r\n")
            .unwrap();
        shutdown.store(true, Ordering::SeqCst);

        let server = std::thread::spawn(move || {
            serve_forever_multi_service(vec![listener], service, config)
        });
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("request queued before shutdown must be accepted and drained");
        client.write_all(b"test").unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();

        assert_eq!(status(&response), 200);
        assert_eq!(response_body(&response), b"test");
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
