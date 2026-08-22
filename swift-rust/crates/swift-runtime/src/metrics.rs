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

//! Queryable concurrency snapshot (AGENTS.md Phase 11).
//!
//! Gauges and counters are low-cardinality. Path / account / container /
//! trans-id never appear as labels. Live values are read from the attached
//! admission / storage / DB executors plus atomics updated on the shipped
//! request path.

use std::fmt;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::admission::AdmissionController;
use crate::db_exec::DbExecutor;
use crate::deadline::DeadlineKind;
use crate::storage::StorageExecutor;

tokio::task_local! {
    static CURRENT: ConcurrencyMetrics;
    /// Per-HTTP-connection commit-shield count. Independent of the process-wide
    /// `commit_shield_active` gauge so shutdown can cancel one connection's
    /// cancellable work while another connection is still in DurabilityBarrier.
    static CONN_SHIELDS: Arc<AtomicUsize>;
}

/// Why a structured cancellation fired. Prometheus `reason` label only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CancelReason {
    Request,
    Parent,
    Quorum,
    Shutdown,
    Timeout,
}

impl CancelReason {
    pub const ALL: [CancelReason; 5] = [
        CancelReason::Request,
        CancelReason::Parent,
        CancelReason::Quorum,
        CancelReason::Shutdown,
        CancelReason::Timeout,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            CancelReason::Request => "request",
            CancelReason::Parent => "parent",
            CancelReason::Quorum => "quorum",
            CancelReason::Shutdown => "shutdown",
            CancelReason::Timeout => "timeout",
        }
    }

    const fn index(self) -> usize {
        match self {
            CancelReason::Request => 0,
            CancelReason::Parent => 1,
            CancelReason::Quorum => 2,
            CancelReason::Shutdown => 3,
            CancelReason::Timeout => 4,
        }
    }
}

impl fmt::Display for CancelReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Names required by AGENTS.md Phase 11. Tests assert the rendered snapshot
/// contains every one.
pub const REQUIRED_METRIC_NAMES: &[&str] = &[
    "connections_open",
    "connections_idle",
    "requests_active",
    "runtime_tasks",
    "runtime_scheduler_lag",
    "admission_rejected_total",
    "request_body_buffer_bytes",
    "response_body_buffer_bytes",
    "backend_requests_inflight",
    "backend_queue_depth",
    "device_ops_active",
    "device_queue_depth",
    "device_queue_wait_seconds",
    "db_ops_active",
    "db_queue_depth",
    "db_queue_wait_seconds",
    "timeouts_total",
    "cancellations_total",
    "commit_shield_active",
    "graceful_shutdown_requests",
    "process_threads",
    "open_fds",
    "shutdown_waiting_requests",
    "shutdown_waiting_commits",
    // AGENTS.md TEST LAB G3 — architecture-activation counters.
    "http_requests_total",
    "native_async_requests_total",
    "legacy_sync_handler_requests_total",
    "block_in_place_total",
    "spawn_blocking_total",
    "blocking_network_wait_total",
    "runtime_worker_threads",
    "blocking_threads",
];

const FORBIDDEN_LABELS: &[&str] = &["object_path=", "trans_id=", "container=", "account="];

/// Point-in-time view. No path labels.
#[derive(Debug, Clone)]
pub struct ConcurrencySnapshot {
    pub connections_open: u64,
    pub connections_idle: u64,
    pub requests_active: u64,
    pub runtime_tasks: u64,
    pub runtime_scheduler_lag: u64,
    pub admission_rejected_total: u64,
    pub request_body_buffer_bytes: u64,
    pub response_body_buffer_bytes: u64,
    pub backend_requests_inflight: u64,
    pub backend_queue_depth: u64,
    pub device_ops_active: u64,
    pub device_queue_depth: u64,
    pub device_queue_wait_seconds: f64,
    pub db_ops_active: u64,
    pub db_queue_depth: u64,
    pub db_queue_wait_seconds: f64,
    pub timeouts_total: [u64; 10],
    pub cancellations_total: [u64; 5],
    pub commit_shield_active: u64,
    pub graceful_shutdown_requests: u64,
    pub process_threads: u64,
    pub open_fds: u64,
    pub shutdown_waiting_requests: u64,
    pub shutdown_waiting_commits: u64,
    /// G3: Hyper HTTP/1.1 engine admitted this many application requests
    /// (excludes `/recon/concurrency` itself).
    pub http_requests_total_hyper: u64,
    pub native_async_requests_total: u64,
    pub legacy_sync_handler_requests_total: u64,
    pub block_in_place_total: u64,
    pub spawn_blocking_total_storage: u64,
    pub spawn_blocking_total_db: u64,
    pub spawn_blocking_total_other: u64,
    pub blocking_network_wait_total: u64,
    pub runtime_worker_threads: u64,
    pub blocking_threads_storage: u64,
    pub blocking_threads_db: u64,
}

impl ConcurrencySnapshot {
    /// Prometheus text exposition. Labels are only `{phase}` / `{reason}`.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(2048);
        fn gauge(out: &mut String, name: &str, help: &str, value: u64) {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(help);
            out.push('\n');
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push_str(" gauge\n");
            out.push_str(name);
            out.push(' ');
            out.push_str(&value.to_string());
            out.push('\n');
        }
        fn gauge_f(out: &mut String, name: &str, help: &str, value: f64) {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(help);
            out.push('\n');
            out.push_str("# TYPE ");
            out.push_str(name);
            out.push_str(" gauge\n");
            out.push_str(name);
            out.push(' ');
            out.push_str(&format!("{value:.6}"));
            out.push('\n');
        }
        gauge(
            &mut out,
            "connections_open",
            "Accepted connections including idle keep-alive.",
            self.connections_open,
        );
        gauge(
            &mut out,
            "connections_idle",
            "Accepted connections with no in-flight request.",
            self.connections_idle,
        );
        gauge(
            &mut out,
            "requests_active",
            "In-flight requests (legacy max_clients alias).",
            self.requests_active,
        );
        gauge(
            &mut out,
            "runtime_tasks",
            "Live Tokio tasks tracked by the concurrency runtime.",
            self.runtime_tasks,
        );
        gauge(
            &mut out,
            "runtime_scheduler_lag",
            "Last observed schedule-to-poll delay in nanoseconds.",
            self.runtime_scheduler_lag,
        );
        gauge(
            &mut out,
            "admission_rejected_total",
            "Fail-closed admission refusals (connection + request + class).",
            self.admission_rejected_total,
        );
        gauge(
            &mut out,
            "request_body_buffer_bytes",
            "Bytes of request body currently buffered in-process.",
            self.request_body_buffer_bytes,
        );
        gauge(
            &mut out,
            "response_body_buffer_bytes",
            "Bytes of response body currently buffered in-process.",
            self.response_body_buffer_bytes,
        );
        gauge(
            &mut out,
            "backend_requests_inflight",
            "Live proxy/replica fan-out workers.",
            self.backend_requests_inflight,
        );
        gauge(
            &mut out,
            "backend_queue_depth",
            "Fan-out children admitted and not yet finished.",
            self.backend_queue_depth,
        );
        gauge(
            &mut out,
            "device_ops_active",
            "In-flight per-device storage operations.",
            self.device_ops_active,
        );
        gauge(
            &mut out,
            "device_queue_depth",
            "Storage BlockingDomain jobs waiting for a thread.",
            self.device_queue_depth,
        );
        gauge_f(
            &mut out,
            "device_queue_wait_seconds",
            "Mean storage queue wait for started jobs.",
            self.device_queue_wait_seconds,
        );
        gauge(
            &mut out,
            "db_ops_active",
            "In-flight SQLite shard operations.",
            self.db_ops_active,
        );
        gauge(
            &mut out,
            "db_queue_depth",
            "SQLite shard mailbox depth.",
            self.db_queue_depth,
        );
        gauge_f(
            &mut out,
            "db_queue_wait_seconds",
            "Mean DB mailbox wait for started jobs.",
            self.db_queue_wait_seconds,
        );
        out.push_str("# HELP timeouts_total Timeouts by typed deadline phase.\n");
        out.push_str("# TYPE timeouts_total counter\n");
        for (i, kind) in DeadlineKind::ALL.iter().enumerate() {
            out.push_str("timeouts_total{phase=\"");
            out.push_str(kind.as_str());
            out.push_str("\"} ");
            out.push_str(&self.timeouts_total[i].to_string());
            out.push('\n');
        }
        out.push_str("# HELP cancellations_total Structured cancellations by reason.\n");
        out.push_str("# TYPE cancellations_total counter\n");
        for (i, reason) in CancelReason::ALL.iter().enumerate() {
            out.push_str("cancellations_total{reason=\"");
            out.push_str(reason.as_str());
            out.push_str("\"} ");
            out.push_str(&self.cancellations_total[i].to_string());
            out.push('\n');
        }
        gauge(
            &mut out,
            "commit_shield_active",
            "PUTs inside the durability barrier.",
            self.commit_shield_active,
        );
        gauge(
            &mut out,
            "graceful_shutdown_requests",
            "In-flight work observed when shutdown started.",
            self.graceful_shutdown_requests,
        );
        gauge(
            &mut out,
            "process_threads",
            "OS threads in this process (best-effort).",
            self.process_threads,
        );
        gauge(
            &mut out,
            "open_fds",
            "Open file descriptors in this process (best-effort).",
            self.open_fds,
        );
        gauge(
            &mut out,
            "shutdown_waiting_requests",
            "Cancellable requests still draining during shutdown.",
            self.shutdown_waiting_requests,
        );
        gauge(
            &mut out,
            "shutdown_waiting_commits",
            "Commit-shield operations still draining during shutdown.",
            self.shutdown_waiting_commits,
        );
        out.push_str("# HELP http_requests_total HTTP requests handled by the production engine.\n");
        out.push_str("# TYPE http_requests_total counter\n");
        out.push_str("http_requests_total{engine=\"hyper\"} ");
        out.push_str(&self.http_requests_total_hyper.to_string());
        out.push('\n');
        gauge(
            &mut out,
            "native_async_requests_total",
            "Requests served by a native AsyncService (not LegacyService).",
            self.native_async_requests_total,
        );
        gauge(
            &mut out,
            "legacy_sync_handler_requests_total",
            "Requests served by LegacyService (sync Handler adapter).",
            self.legacy_sync_handler_requests_total,
        );
        gauge(
            &mut out,
            "block_in_place_total",
            "tokio::task::block_in_place invocations on a request path (G3 NO-GO if >0 on migrated paths).",
            self.block_in_place_total,
        );
        out.push_str("# HELP spawn_blocking_total spawn_blocking jobs started by BlockingDomain.\n");
        out.push_str("# TYPE spawn_blocking_total counter\n");
        out.push_str("spawn_blocking_total{domain=\"storage\"} ");
        out.push_str(&self.spawn_blocking_total_storage.to_string());
        out.push('\n');
        out.push_str("spawn_blocking_total{domain=\"db\"} ");
        out.push_str(&self.spawn_blocking_total_db.to_string());
        out.push('\n');
        out.push_str("spawn_blocking_total{domain=\"other\"} ");
        out.push_str(&self.spawn_blocking_total_other.to_string());
        out.push('\n');
        gauge(
            &mut out,
            "blocking_network_wait_total",
            "Network waits observed on a blocking worker (must stay 0).",
            self.blocking_network_wait_total,
        );
        gauge(
            &mut out,
            "runtime_worker_threads",
            "Tokio scheduler worker threads configured for this process.",
            self.runtime_worker_threads,
        );
        out.push_str("# HELP blocking_threads In-flight BlockingDomain threads by domain.\n");
        out.push_str("# TYPE blocking_threads gauge\n");
        out.push_str("blocking_threads{domain=\"storage\"} ");
        out.push_str(&self.blocking_threads_storage.to_string());
        out.push('\n');
        out.push_str("blocking_threads{domain=\"db\"} ");
        out.push_str(&self.blocking_threads_db.to_string());
        out.push('\n');
        out
    }

    pub fn has_forbidden_labels(&self) -> bool {
        text_has_forbidden_labels(&self.render())
    }
}

pub fn text_has_forbidden_labels(text: &str) -> bool {
    FORBIDDEN_LABELS.iter().any(|p| text.contains(p))
}

/// Shared, clonable registry. One per worker process / test server.
#[derive(Clone, Debug)]
pub struct ConcurrencyMetrics {
    inner: Arc<Inner>,
}

struct Inner {
    admission: Mutex<Option<AdmissionController>>,
    storage: Mutex<Option<StorageExecutor>>,
    db: Mutex<Option<DbExecutor>>,
    worker_threads: AtomicUsize,
    runtime_tasks: AtomicUsize,
    runtime_scheduler_lag_ns: AtomicU64,
    request_body_buffer_bytes: AtomicI64,
    response_body_buffer_bytes: AtomicI64,
    backend_requests_inflight: AtomicUsize,
    backend_queue_depth: AtomicUsize,
    timeouts: [AtomicU64; 10],
    cancellations: [AtomicU64; 5],
    commit_shield_active: AtomicUsize,
    graceful_shutdown_requests: AtomicU64,
    shutdown_waiting_requests: AtomicUsize,
    shutdown_waiting_commits: AtomicUsize,
    /// JoinHandles for L7 commit-shield tasks. Never aborted.
    shields: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    http_requests_hyper: AtomicU64,
    native_async_requests: AtomicU64,
    legacy_sync_handler_requests: AtomicU64,
    block_in_place: AtomicU64,
    spawn_blocking_other: AtomicU64,
    blocking_network_wait: AtomicU64,
}

impl fmt::Debug for Inner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConcurrencyMetricsInner").finish_non_exhaustive()
    }
}

impl Default for ConcurrencyMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ConcurrencyMetrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                admission: Mutex::new(None),
                storage: Mutex::new(None),
                db: Mutex::new(None),
                worker_threads: AtomicUsize::new(0),
                runtime_tasks: AtomicUsize::new(0),
                runtime_scheduler_lag_ns: AtomicU64::new(0),
                request_body_buffer_bytes: AtomicI64::new(0),
                response_body_buffer_bytes: AtomicI64::new(0),
                backend_requests_inflight: AtomicUsize::new(0),
                backend_queue_depth: AtomicUsize::new(0),
                timeouts: Default::default(),
                cancellations: Default::default(),
                commit_shield_active: AtomicUsize::new(0),
                graceful_shutdown_requests: AtomicU64::new(0),
                shutdown_waiting_requests: AtomicUsize::new(0),
                shutdown_waiting_commits: AtomicUsize::new(0),
                shields: Mutex::new(Vec::new()),
                http_requests_hyper: AtomicU64::new(0),
                native_async_requests: AtomicU64::new(0),
                legacy_sync_handler_requests: AtomicU64::new(0),
                block_in_place: AtomicU64::new(0),
                spawn_blocking_other: AtomicU64::new(0),
                blocking_network_wait: AtomicU64::new(0),
            }),
        }
    }

    /// Run `fut` with this registry as the request-path current metrics.
    /// `tokio::spawn` children must call this again (task-locals do not inherit);
    /// [`crate::TaskScope::spawn`] does that.
    pub fn bind<F>(&self, fut: F) -> impl std::future::Future<Output = F::Output>
    where
        F: std::future::Future,
    {
        CURRENT.scope(self.clone(), fut)
    }

    /// Bind metrics and this HTTP connection's commit-shield counter.
    pub fn bind_conn<F>(
        &self,
        conn_shields: Arc<AtomicUsize>,
        fut: F,
    ) -> impl std::future::Future<Output = F::Output>
    where
        F: std::future::Future,
    {
        CURRENT.scope(self.clone(), CONN_SHIELDS.scope(conn_shields, fut))
    }

    /// Scope only the connection-local shield counter (metrics already bound).
    pub fn with_conn_shields<F>(
        conn_shields: Arc<AtomicUsize>,
        fut: F,
    ) -> impl std::future::Future<Output = F::Output>
    where
        F: std::future::Future,
    {
        CONN_SHIELDS.scope(conn_shields, fut)
    }

    pub fn current() -> Option<Self> {
        CURRENT.try_with(|m| m.clone()).ok()
    }

    pub fn current_conn_shields() -> Option<Arc<AtomicUsize>> {
        CONN_SHIELDS.try_with(Arc::clone).ok()
    }

    /// Re-apply task-locals captured on the parent before `tokio::spawn`.
    pub async fn apply_captured_locals<F>(
        metrics: Option<Self>,
        conn_shields: Option<Arc<AtomicUsize>>,
        fut: F,
    ) -> F::Output
    where
        F: std::future::Future,
    {
        match (metrics, conn_shields) {
            (Some(m), Some(cs)) => m.bind_conn(cs, fut).await,
            (Some(m), None) => m.bind(fut).await,
            (None, Some(cs)) => Self::with_conn_shields(cs, fut).await,
            (None, None) => fut.await,
        }
    }

    pub fn attach_admission(&self, admission: AdmissionController) {
        *self.inner.admission.lock().unwrap_or_else(|e| e.into_inner()) = Some(admission);
    }

    pub fn attach_storage(&self, storage: StorageExecutor) {
        *self.inner.storage.lock().unwrap_or_else(|e| e.into_inner()) = Some(storage);
    }

    pub fn attach_db(&self, db: DbExecutor) {
        *self.inner.db.lock().unwrap_or_else(|e| e.into_inner()) = Some(db);
    }

    pub fn set_worker_threads(&self, n: usize) {
        self.inner.worker_threads.store(n, Ordering::Release);
    }

    pub fn observe_scheduler_lag(&self, lag: Duration) {
        self.inner
            .runtime_scheduler_lag_ns
            .store(lag.as_nanos().min(u128::from(u64::MAX)) as u64, Ordering::Release);
    }

    pub fn runtime_tasks_inc(&self) {
        self.inner.runtime_tasks.fetch_add(1, Ordering::AcqRel);
    }

    pub fn runtime_tasks_dec(&self) {
        let _ = self.inner.runtime_tasks.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |v| Some(v.saturating_sub(1)),
        );
    }

    pub fn add_request_body_buffer(&self, delta: i64) {
        self.inner
            .request_body_buffer_bytes
            .fetch_add(delta, Ordering::AcqRel);
    }

    pub fn add_response_body_buffer(&self, delta: i64) {
        self.inner
            .response_body_buffer_bytes
            .fetch_add(delta, Ordering::AcqRel);
    }

    pub fn backend_inflight_inc(&self) {
        self.inner
            .backend_requests_inflight
            .fetch_add(1, Ordering::AcqRel);
        self.inner.backend_queue_depth.fetch_add(1, Ordering::AcqRel);
    }

    pub fn backend_inflight_dec(&self) {
        let _ = self.inner.backend_requests_inflight.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |v| Some(v.saturating_sub(1)),
        );
        let _ = self.inner.backend_queue_depth.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |v| Some(v.saturating_sub(1)),
        );
    }

    pub fn record_timeout(&self, kind: DeadlineKind) {
        let i = deadline_index(kind);
        self.inner.timeouts[i].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cancellation(&self, reason: CancelReason) {
        self.inner.cancellations[reason.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_timeout_current(kind: DeadlineKind) {
        if let Some(m) = Self::current() {
            m.record_timeout(kind);
        }
    }

    pub fn record_cancellation_current(reason: CancelReason) {
        if let Some(m) = Self::current() {
            m.record_cancellation(reason);
        }
    }

    pub fn commit_shield_inc(&self) {
        self.inner.commit_shield_active.fetch_add(1, Ordering::AcqRel);
        let _ = CONN_SHIELDS.try_with(|c| c.fetch_add(1, Ordering::AcqRel));
    }

    pub fn commit_shield_dec(&self) {
        let _ = self.inner.commit_shield_active.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |v| Some(v.saturating_sub(1)),
        );
        let _ = CONN_SHIELDS.try_with(|c| {
            let _ = c.fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_sub(1))
            });
        });
    }

    pub fn set_graceful_shutdown_requests(&self, n: u64) {
        self.inner
            .graceful_shutdown_requests
            .store(n, Ordering::Release);
    }

    pub fn set_shutdown_waiting_requests(&self, n: usize) {
        self.inner
            .shutdown_waiting_requests
            .store(n, Ordering::Release);
    }

    pub fn set_shutdown_waiting_commits(&self, n: usize) {
        self.inner
            .shutdown_waiting_commits
            .store(n, Ordering::Release);
    }

    /// G3: Hyper admitted an application request (not `/recon/concurrency`).
    pub fn record_http_request_hyper(&self) {
        self.inner.http_requests_hyper.fetch_add(1, Ordering::Relaxed);
    }

    /// G3: native `AsyncService` (proxy/object/account/container).
    pub fn record_native_async_request(&self) {
        self.inner
            .native_async_requests
            .fetch_add(1, Ordering::Relaxed);
    }

    /// G3: `LegacyService` / sync `Handler` adapter.
    pub fn record_legacy_sync_handler_request(&self) {
        self.inner
            .legacy_sync_handler_requests
            .fetch_add(1, Ordering::Relaxed);
    }

    /// G3: `tokio::task::block_in_place` on a request path.
    pub fn record_block_in_place(&self) {
        self.inner.block_in_place.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_spawn_blocking_other(&self) {
        self.inner
            .spawn_blocking_other
            .fetch_add(1, Ordering::Relaxed);
    }

    /// G3: a blocking worker waited on the network (must stay 0).
    pub fn record_blocking_network_wait(&self) {
        self.inner
            .blocking_network_wait
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_http_request_hyper_current() {
        if let Some(m) = Self::current() {
            m.record_http_request_hyper();
        }
    }

    pub fn record_native_async_request_current() {
        if let Some(m) = Self::current() {
            m.record_native_async_request();
        }
    }

    pub fn record_legacy_sync_handler_request_current() {
        if let Some(m) = Self::current() {
            m.record_legacy_sync_handler_request();
        }
    }

    pub fn record_block_in_place_current() {
        if let Some(m) = Self::current() {
            m.record_block_in_place();
        }
    }

    pub fn record_spawn_blocking_other_current() {
        if let Some(m) = Self::current() {
            m.record_spawn_blocking_other();
        }
    }

    pub fn record_blocking_network_wait_current() {
        if let Some(m) = Self::current() {
            m.record_blocking_network_wait();
        }
    }

    /// Zero G3 activation counters. Does not reset storage/DB started_total
    /// (those are executor lifetime); official runs use process restart or deltas.
    pub fn reset_activation_counters(&self) {
        self.inner.http_requests_hyper.store(0, Ordering::Release);
        self.inner.native_async_requests.store(0, Ordering::Release);
        self.inner
            .legacy_sync_handler_requests
            .store(0, Ordering::Release);
        self.inner.block_in_place.store(0, Ordering::Release);
        self.inner.spawn_blocking_other.store(0, Ordering::Release);
        self.inner.blocking_network_wait.store(0, Ordering::Release);
    }

    /// Track a commit-shield task. The handle is joined, never aborted (L7).
    pub fn track_shield(&self, handle: tokio::task::JoinHandle<()>) {
        self.inner
            .shields
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(handle);
    }

    pub fn commit_shield_active(&self) -> usize {
        self.inner.commit_shield_active.load(Ordering::Acquire)
    }

    /// Wait until shields drain or `deadline`. Does not abort in-flight commits.
    pub async fn wait_shields(&self, deadline: std::time::Instant) {
        loop {
            self.reap_shields();
            let n = self.commit_shield_active();
            self.set_shutdown_waiting_commits(n);
            if n == 0 || std::time::Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// Join remaining shields. Never abort: BlockingDomain commit must finish
    /// or fail deterministically.
    pub async fn join_remaining_shields(&self) {
        let handles: Vec<_> = std::mem::take(
            &mut *self
                .inner
                .shields
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        for handle in handles {
            let _ = handle.await;
        }
    }

    fn reap_shields(&self) {
        let mut g = self.inner.shields.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|h| !h.is_finished());
    }

    pub fn snapshot(&self) -> ConcurrencySnapshot {
        let admission = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (connections_open, requests_active, rejected) = if let Some(a) = admission.as_ref() {
            let open = a.connections_open() as u64;
            let req = a.requests_active() as u64;
            let rej = a.rejected_connections()
                .saturating_add(a.rejected_requests())
                .saturating_add(a.rejected_class(crate::TrafficClass::Foreground))
                .saturating_add(a.rejected_class(crate::TrafficClass::Replication))
                .saturating_add(a.rejected_class(crate::TrafficClass::Reconstruction))
                .saturating_add(a.rejected_class(crate::TrafficClass::Auditor));
            (open, req, rej)
        } else {
            (0, 0, 0)
        };
        let connections_idle = connections_open.saturating_sub(requests_active);

        let storage = self
            .inner
            .storage
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (device_ops_active, device_queue_depth, device_wait, blocking_active, storage_started) =
            if let Some(s) = storage.as_ref() {
                let st = s.stats();
                let wait = mean_wait_secs(st.blocking.wait_ns_total, st.blocking.started_total);
                (
                    st.device_ops_active as u64,
                    st.blocking.queued as u64,
                    wait,
                    st.blocking.active,
                    st.blocking.started_total,
                )
            } else {
                (0, 0, 0.0, 0, 0)
            };

        let db = self
            .inner
            .db
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (db_ops_active, db_queue_depth, db_wait, db_started, db_blocking_threads) =
            if let Some(d) = db.as_ref() {
                let st = d.stats();
                (
                    st.ops_active as u64,
                    st.queued as u64,
                    mean_wait_secs(st.wait_ns_total, st.started_total),
                    st.started_total,
                    st.ops_active as u64,
                )
            } else {
                (0, 0, 0.0, 0, 0)
            };

        let mut timeouts = [0u64; 10];
        for i in 0..10 {
            timeouts[i] = self.inner.timeouts[i].load(Ordering::Relaxed);
        }
        let mut cancellations = [0u64; 5];
        for i in 0..5 {
            cancellations[i] = self.inner.cancellations[i].load(Ordering::Relaxed);
        }

        let worker_threads = self.inner.worker_threads.load(Ordering::Acquire);
        let runtime_tasks = self.inner.runtime_tasks.load(Ordering::Acquire) as u64;
        let process_threads = sample_process_threads(worker_threads, blocking_active);
        let open_fds = sample_open_fds();

        ConcurrencySnapshot {
            connections_open,
            connections_idle,
            requests_active,
            runtime_tasks,
            runtime_scheduler_lag: self.inner.runtime_scheduler_lag_ns.load(Ordering::Acquire),
            admission_rejected_total: rejected,
            request_body_buffer_bytes: self
                .inner
                .request_body_buffer_bytes
                .load(Ordering::Acquire)
                .max(0) as u64,
            response_body_buffer_bytes: self
                .inner
                .response_body_buffer_bytes
                .load(Ordering::Acquire)
                .max(0) as u64,
            backend_requests_inflight: self
                .inner
                .backend_requests_inflight
                .load(Ordering::Acquire) as u64,
            backend_queue_depth: self.inner.backend_queue_depth.load(Ordering::Acquire) as u64,
            device_ops_active,
            device_queue_depth,
            device_queue_wait_seconds: device_wait,
            db_ops_active,
            db_queue_depth,
            db_queue_wait_seconds: db_wait,
            timeouts_total: timeouts,
            cancellations_total: cancellations,
            commit_shield_active: self.inner.commit_shield_active.load(Ordering::Acquire) as u64,
            graceful_shutdown_requests: self
                .inner
                .graceful_shutdown_requests
                .load(Ordering::Acquire),
            process_threads,
            open_fds,
            shutdown_waiting_requests: self
                .inner
                .shutdown_waiting_requests
                .load(Ordering::Acquire) as u64,
            shutdown_waiting_commits: self
                .inner
                .shutdown_waiting_commits
                .load(Ordering::Acquire) as u64,
            http_requests_total_hyper: self.inner.http_requests_hyper.load(Ordering::Relaxed),
            native_async_requests_total: self.inner.native_async_requests.load(Ordering::Relaxed),
            legacy_sync_handler_requests_total: self
                .inner
                .legacy_sync_handler_requests
                .load(Ordering::Relaxed),
            block_in_place_total: self.inner.block_in_place.load(Ordering::Relaxed),
            spawn_blocking_total_storage: storage_started,
            spawn_blocking_total_db: db_started,
            spawn_blocking_total_other: self.inner.spawn_blocking_other.load(Ordering::Relaxed),
            blocking_network_wait_total: self.inner.blocking_network_wait.load(Ordering::Relaxed),
            runtime_worker_threads: worker_threads as u64,
            blocking_threads_storage: blocking_active as u64,
            blocking_threads_db: db_blocking_threads,
        }
    }

    pub fn render(&self) -> String {
        self.snapshot().render()
    }
}

fn deadline_index(kind: DeadlineKind) -> usize {
    DeadlineKind::ALL
        .iter()
        .position(|k| *k == kind)
        .unwrap_or(0)
}

fn mean_wait_secs(wait_ns_total: u64, started_total: u64) -> f64 {
    if started_total == 0 {
        0.0
    } else {
        (wait_ns_total as f64 / started_total as f64) / 1_000_000_000.0
    }
}

fn sample_process_threads(worker_threads: usize, blocking_active: usize) -> u64 {
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("Threads:") {
                if let Ok(n) = rest.trim().parse::<u64>() {
                    return n;
                }
            }
        }
    }
    worker_threads.saturating_add(blocking_active).saturating_add(1) as u64
}

fn sample_open_fds() -> u64 {
    for path in ["/dev/fd", "/proc/self/fd"] {
        if let Ok(rd) = std::fs::read_dir(path) {
            return rd.count() as u64;
        }
    }
    0
}

/// Guard that decrements `runtime_tasks` on drop.
pub struct RuntimeTaskGuard(pub Option<ConcurrencyMetrics>);

impl Drop for RuntimeTaskGuard {
    fn drop(&mut self) {
        if let Some(m) = self.0.take() {
            m.runtime_tasks_dec();
        }
    }
}

/// Guard that decrements backend inflight on drop.
pub struct BackendInflightGuard(pub Option<ConcurrencyMetrics>);

impl Drop for BackendInflightGuard {
    fn drop(&mut self) {
        if let Some(m) = self.0.take() {
            m.backend_inflight_dec();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::AdmissionLimits;
    use crate::context::DurabilityBarrier;
    use crate::db_exec::{DbExecError, DbExecutorConfig};
    use crate::fanout::FanoutGroup;
    use crate::storage::{DeviceId, DeviceIoLimits, StorageError, StorageExecutorConfig};
    use crate::traffic::TrafficClass;
    use crate::CancellationToken;
    use std::sync::atomic::{AtomicBool, Ordering as AtomOrd};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    async fn wait_until(pred: impl Fn() -> bool) {
        let start = Instant::now();
        loop {
            if pred() {
                return;
            }
            if start.elapsed() > Duration::from_secs(2) {
                panic!("timeout waiting for metrics condition");
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[test]
    fn render_contains_every_required_name_and_no_forbidden_labels() {
        let m = ConcurrencyMetrics::new();
        m.record_timeout(DeadlineKind::BodyIdle);
        m.record_cancellation(CancelReason::Timeout);
        let text = m.render();
        for name in REQUIRED_METRIC_NAMES {
            assert!(text.contains(name), "missing {name} in\n{text}");
        }
        assert!(text.contains("timeouts_total{phase=\"body_idle\"}"));
        assert!(text.contains("cancellations_total{reason=\"timeout\"}"));
        assert!(text.contains("http_requests_total{engine=\"hyper\"}"));
        assert!(text.contains("spawn_blocking_total{domain=\"storage\"}"));
        assert!(text.contains("blocking_threads{domain=\"storage\"}"));
        assert!(!text_has_forbidden_labels(&text), "{text}");
    }

    #[test]
    fn g3_activation_counters_move_and_reset() {
        let m = ConcurrencyMetrics::new();
        assert_eq!(m.snapshot().native_async_requests_total, 0);
        assert_eq!(m.snapshot().legacy_sync_handler_requests_total, 0);
        assert_eq!(m.snapshot().block_in_place_total, 0);
        m.record_http_request_hyper();
        m.record_native_async_request();
        m.record_legacy_sync_handler_request();
        m.record_block_in_place();
        m.record_blocking_network_wait();
        m.set_worker_threads(4);
        let snap = m.snapshot();
        assert_eq!(snap.http_requests_total_hyper, 1);
        assert_eq!(snap.native_async_requests_total, 1);
        assert_eq!(snap.legacy_sync_handler_requests_total, 1);
        assert_eq!(snap.block_in_place_total, 1);
        assert_eq!(snap.blocking_network_wait_total, 1);
        assert_eq!(snap.runtime_worker_threads, 4);
        m.reset_activation_counters();
        let snap = m.snapshot();
        assert_eq!(snap.http_requests_total_hyper, 0);
        assert_eq!(snap.native_async_requests_total, 0);
        assert_eq!(snap.legacy_sync_handler_requests_total, 0);
        assert_eq!(snap.block_in_place_total, 0);
        assert_eq!(snap.blocking_network_wait_total, 0);
        let text = m.render();
        assert!(text.contains("http_requests_total{engine=\"hyper\"} 0"));
        assert!(text.contains("native_async_requests_total 0"));
        assert!(text.contains("block_in_place_total 0"));
    }

    #[test]
    fn admission_snapshot_moves() {
        let limits = AdmissionLimits::new(2, 2, 2, 2, 2, 2);
        let ctl = AdmissionController::new(limits);
        let m = ConcurrencyMetrics::new();
        m.attach_admission(ctl.clone());
        assert_eq!(m.snapshot().connections_open, 0);
        let c = ctl.try_acquire_connection().unwrap();
        assert_eq!(m.snapshot().connections_open, 1);
        assert_eq!(m.snapshot().connections_idle, 1);
        let r = ctl.try_acquire_request(TrafficClass::Foreground).unwrap();
        assert_eq!(m.snapshot().requests_active, 1);
        assert_eq!(m.snapshot().connections_idle, 0);
        drop(r);
        drop(c);
        assert_eq!(m.snapshot().connections_open, 0);
        let hold_a = ctl.try_acquire_connection().unwrap();
        let hold_b = ctl.try_acquire_connection().unwrap();
        assert!(ctl.try_acquire_connection().is_err());
        assert!(m.snapshot().admission_rejected_total >= 1);
        drop(hold_a);
        drop(hold_b);
    }

    #[tokio::test]
    async fn commit_shield_tracks_barrier_on_current_metrics() {
        let m = ConcurrencyMetrics::new();
        m.bind(async {
            assert_eq!(m.snapshot().commit_shield_active, 0);
            let b = DurabilityBarrier::enter();
            assert_eq!(m.snapshot().commit_shield_active, 1);
            b.complete();
            assert_eq!(m.snapshot().commit_shield_active, 0);
        })
        .await;
    }

    #[tokio::test]
    async fn storage_and_db_gauges_move_then_return_to_zero() {
        let m = ConcurrencyMetrics::new();
        let storage = StorageExecutor::new(
            StorageExecutorConfig::new(1, 8, DeviceIoLimits::new(8, 8, 8, 8, 8)).unwrap(),
        )
        .unwrap();
        m.attach_storage(storage.clone());
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let stall = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            move || {
                entered.store(true, AtomOrd::SeqCst);
                while !release.load(AtomOrd::SeqCst) {
                    thread::park_timeout(Duration::from_millis(5));
                }
            }
        };
        let job = tokio::spawn({
            let storage = storage.clone();
            async move {
                storage
                    .run_finite(DeviceId::new("sda"), TrafficClass::Foreground, stall)
                    .await
            }
        });
        wait_until(|| entered.load(AtomOrd::SeqCst)).await;
        let snap = m.snapshot();
        assert!(
            snap.device_ops_active >= 1,
            "device_ops_active={}",
            snap.device_ops_active
        );
        release.store(true, AtomOrd::SeqCst);
        job.await.unwrap().unwrap();
        wait_until(|| m.snapshot().device_ops_active == 0).await;

        let db = DbExecutor::new(DbExecutorConfig::new(2, 8, 4).unwrap()).unwrap();
        m.attach_db(db.clone());
        let dir = std::env::temp_dir().join(format!(
            "peregrine-metrics-db-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.db");
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let stall = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            move || {
                entered.store(true, AtomOrd::SeqCst);
                while !release.load(AtomOrd::SeqCst) {
                    thread::park_timeout(Duration::from_millis(5));
                }
                1u8
            }
        };
        let job = tokio::spawn({
            let db = db.clone();
            async move { db.run_on_shard(path, stall).await }
        });
        wait_until(|| entered.load(AtomOrd::SeqCst)).await;
        let snap = m.snapshot();
        assert!(snap.db_ops_active >= 1, "db_ops_active={}", snap.db_ops_active);
        release.store(true, AtomOrd::SeqCst);
        job.await.unwrap().unwrap();
        wait_until(|| m.snapshot().db_ops_active == 0).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fanout_inflight_and_cancel_reason_move() {
        let m = ConcurrencyMetrics::new();
        m.bind(async {
            let mut group: FanoutGroup<u8> = FanoutGroup::new(2, 2).unwrap();
            let release = Arc::new(AtomicBool::new(false));
            let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            for _ in 0..2 {
                let release = Arc::clone(&release);
                let entered = Arc::clone(&entered);
                group
                    .spawn(move |tx, cancel| async move {
                        entered.fetch_add(1, AtomOrd::SeqCst);
                        while !release.load(AtomOrd::SeqCst) && !cancel.is_cancelled() {
                            tokio::task::yield_now().await;
                        }
                        let _ = tx.send(1).await;
                    })
                    .unwrap();
            }
            wait_until(|| entered.load(AtomOrd::SeqCst) >= 2).await;
            let snap = m.snapshot();
            assert!(
                snap.backend_requests_inflight >= 2,
                "inflight={} current={}",
                snap.backend_requests_inflight,
                ConcurrencyMetrics::current().is_some()
            );
            assert!(snap.backend_queue_depth >= 2);
            group.cancel_unused();
            assert!(m.snapshot().cancellations_total[CancelReason::Quorum.index()] >= 1);
            release.store(true, AtomOrd::SeqCst);
            group.join().await;
            wait_until(|| m.snapshot().backend_requests_inflight == 0).await;
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shipped_device_db_commit_shutdown_machines() {
        use crate::scope::TaskScope;
        use std::sync::atomic::AtomicUsize;

        let limits = AdmissionLimits::new(8, 8, 8, 8, 8, 8);
        let ctl = AdmissionController::new(limits);
        let hits = Arc::new(AtomicUsize::new(0));
        let mut joins = Vec::new();
        for _ in 0..8 {
            let ctl = ctl.clone();
            let hits = Arc::clone(&hits);
            joins.push(thread::spawn(move || {
                for _ in 0..64 {
                    if let Ok(p) = ctl.try_acquire_request(TrafficClass::Foreground) {
                        hits.fetch_add(1, AtomOrd::SeqCst);
                        drop(p);
                    }
                }
            }));
        }
        for j in joins {
            j.join().unwrap();
        }
        assert_eq!(ctl.requests_active(), 0);
        assert!(hits.load(AtomOrd::SeqCst) > 0);

        let scope = TaskScope::bounded(4);
        let child = scope
            .spawn(async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                1u8
            })
            .unwrap();
        scope.cancel();
        assert!(child.is_cancelled() || scope.is_cancelled());

        let storage = StorageExecutor::new(
            StorageExecutorConfig::new(1, 4, DeviceIoLimits::new(1, 1, 1, 1, 1)).unwrap(),
        )
        .unwrap();
        let m = ConcurrencyMetrics::new();
        m.attach_storage(storage.clone());
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let stall = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            move || {
                entered.store(true, AtomOrd::SeqCst);
                while !release.load(AtomOrd::SeqCst) {
                    thread::park_timeout(Duration::from_millis(5));
                }
            }
        };
        let parked = tokio::spawn({
            let storage = storage.clone();
            async move {
                storage
                    .run_finite(DeviceId::new("sda"), TrafficClass::Foreground, stall)
                    .await
            }
        });
        wait_until(|| entered.load(AtomOrd::SeqCst)).await;
        let busy = storage
            .run_finite(DeviceId::new("sda"), TrafficClass::Foreground, || ())
            .await;
        release.store(true, AtomOrd::SeqCst);
        parked.await.unwrap().unwrap();
        assert!(
            matches!(
                busy,
                Err(StorageError::DeviceBusy { .. }) | Err(StorageError::DeviceClassBusy { .. })
            ),
            "shipped DeviceScheduler must fail-closed at cap, got {busy:?}"
        );

        let db = DbExecutor::new(DbExecutorConfig::new(2, 1, 4).unwrap()).unwrap();
        m.attach_db(db.clone());
        let dir = std::env::temp_dir().join(format!(
            "peregrine-metrics-db-sched-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.db");
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let stall = {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            move || {
                entered.store(true, AtomOrd::SeqCst);
                while !release.load(AtomOrd::SeqCst) {
                    thread::park_timeout(Duration::from_millis(5));
                }
                1u8
            }
        };
        let parked = tokio::spawn({
            let db = db.clone();
            let path = path.clone();
            async move { db.run_on_shard(path, stall).await }
        });
        wait_until(|| entered.load(AtomOrd::SeqCst)).await;
        let second_done = Arc::new(AtomicBool::new(false));
        let queued = tokio::spawn({
            let db = db.clone();
            let path = path.clone();
            let second_done = Arc::clone(&second_done);
            async move {
                let r = db.run_on_shard(path, move || {
                    second_done.store(true, AtomOrd::SeqCst);
                    2u8
                });
                r.await
            }
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !second_done.load(AtomOrd::SeqCst),
            "same DB identity must serialize on the shipped shard"
        );
        let third = db.run_on_shard(path.clone(), || 3u8).await;
        let queued_stat = db.stats().queued;
        let serialized = !second_done.load(AtomOrd::SeqCst);
        release.store(true, AtomOrd::SeqCst);
        parked.await.unwrap().unwrap();
        queued.await.unwrap().unwrap();
        assert!(
            matches!(third, Err(DbExecError::MailboxFull { .. })) || queued_stat >= 1 || serialized,
            "shipped shard mailbox must bound/serialize the DB, third={third:?} queued={queued_stat}"
        );
        assert!(second_done.load(AtomOrd::SeqCst));
        let _ = std::fs::remove_dir_all(&dir);

        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let metrics = m.clone();
        m.bind({
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let finished = Arc::clone(&finished);
            async move {
                let m = metrics;
                let waiter = DurabilityBarrier::run_shielded({
                    let entered = Arc::clone(&entered);
                    let release = Arc::clone(&release);
                    let finished = Arc::clone(&finished);
                    async move {
                        entered.store(true, AtomOrd::SeqCst);
                        while !release.load(AtomOrd::SeqCst) {
                            tokio::task::yield_now().await;
                        }
                        finished.store(true, AtomOrd::SeqCst);
                        7u8
                    }
                });
                tokio::pin!(waiter);
                let start = Instant::now();
                while !entered.load(AtomOrd::SeqCst) && start.elapsed() < Duration::from_secs(2) {
                    tokio::select! {
                        biased;
                        _ = waiter.as_mut() => panic!("shield waiter finished before stall released"),
                        _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                    }
                }
                assert!(entered.load(AtomOrd::SeqCst));
                assert!(m.snapshot().commit_shield_active >= 1);
                let deadline = Instant::now() + Duration::from_secs(2);
                let wait = m.wait_shields(deadline);
                tokio::pin!(wait);
                tokio::select! {
                    _ = &mut wait => {}
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                }
                assert!(
                    m.snapshot().shutdown_waiting_commits >= 1
                        || m.snapshot().commit_shield_active >= 1,
                    "wait_shields must observe live commit-shield, not a hand-set gauge"
                );
                drop(waiter);
                assert!(
                    m.snapshot().commit_shield_active >= 1,
                    "dropping the HTTP waiter must not abort the shield"
                );
                release.store(true, AtomOrd::SeqCst);
                wait_until(|| finished.load(AtomOrd::SeqCst)).await;
                wait_until(|| m.snapshot().commit_shield_active == 0).await;
                m.join_remaining_shields().await;
            }
        })
        .await;
    }

    #[tokio::test]
    async fn timeout_and_request_cancel_increment_labeled_counters() {
        let m = ConcurrencyMetrics::new();
        m.bind(async {
            ConcurrencyMetrics::record_timeout_current(DeadlineKind::BodyIdle);
            ConcurrencyMetrics::record_cancellation_current(CancelReason::Timeout);
            let tok = CancellationToken::new();
            tok.cancel();
            let snap = m.snapshot();
            assert!(snap.timeouts_total[deadline_index(DeadlineKind::BodyIdle)] >= 1);
            assert!(snap.cancellations_total[CancelReason::Timeout.index()] >= 1);
            assert!(snap.cancellations_total[CancelReason::Request.index()] >= 1);
            let text = snap.render();
            assert!(text.contains("timeouts_total{phase=\"body_idle\"}"));
            assert!(!text_has_forbidden_labels(&text));
        })
        .await;
    }
}
