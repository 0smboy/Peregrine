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

//! Bounded blocking execution domain (Eventlet `tpool.execute` replacement).
//!
//! This module is the **only** place in the `swift-rust` workspace that may
//! call [`tokio::task::spawn_blocking`]. Callers submit a finite job through
//! [`BlockingDomain::submit`]; they do not hold a Tokio blocking thread
//! while waiting on the network (L1) and they do not run filesystem / SQLite
//! / FFI work on a reactor thread (L2).
//!
//! # Bounds (L3, L4)
//!
//! * `thread_cap` — maximum concurrent `spawn_blocking` invocations.
//! * `queue_bound` — maximum jobs waiting for a thread.
//!
//! [`BlockingDomain::submit`] is fail-closed: a full queue returns
//! [`BlockingError::QueueFull`] immediately. The domain never grows the
//! queue, never waits for a slot on the submit path, and never uses Tokio's
//! process-wide blocking-pool expansion as overload control.
//!
//! # Cancellation
//!
//! [`BlockingJob::abort`] cancels the **job** if it has not yet entered
//! `spawn_blocking`. **In-flight blocking work cannot abort.** Tokio's
//! blocking pool will run a started closure to completion even if the
//! corresponding [`tokio::task::JoinHandle`] is dropped or aborted. Join
//! still waits for that result. Dropping [`BlockingJob`] is equivalent to
//! `abort`: a queued job is skipped; a started job keeps running.

use std::collections::VecDeque;
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

const STATE_QUEUED: u8 = 0;
const STATE_STARTED: u8 = 1;
const STATE_CANCELLED: u8 = 2;

type JobFn = Box<dyn FnOnce() + Send + 'static>;

/// Finite caps required to construct a [`BlockingDomain`].
///
/// There is no `Default`: a missing cap must not silently become Tokio's
/// large blocking-thread ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockingDomainConfig {
    /// Maximum concurrent blocking threads (`spawn_blocking` in flight).
    pub thread_cap: usize,
    /// Maximum jobs waiting for a free thread.
    pub queue_bound: usize,
}

impl BlockingDomainConfig {
    /// Both bounds must be ≥ 1. Zero is rejected rather than treated as
    /// "unbounded" or "use Tokio defaults".
    pub const fn new(thread_cap: usize, queue_bound: usize) -> Result<Self, BlockingError> {
        if thread_cap == 0 {
            return Err(BlockingError::InvalidConfig {
                reason: "thread_cap must be >= 1",
            });
        }
        if queue_bound == 0 {
            return Err(BlockingError::InvalidConfig {
                reason: "queue_bound must be >= 1",
            });
        }
        Ok(Self {
            thread_cap,
            queue_bound,
        })
    }
}

/// Why submit / construction / join failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockingError {
    InvalidConfig {
        reason: &'static str,
    },
    /// [`BlockingDomain::new`] was not called from a Tokio runtime.
    NoRuntime,
    /// Queue is at `queue_bound` and every thread is busy (or the bound is
    /// already filled with waiting jobs). Fail closed: the closure did not
    /// run and will not run.
    QueueFull {
        thread_cap: usize,
        queue_bound: usize,
        queued: usize,
        active: usize,
    },
    /// Domain is shutting down; no new jobs are admitted.
    Shutdown,
}

impl fmt::Display for BlockingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockingError::InvalidConfig { reason } => {
                write!(f, "invalid BlockingDomain config: {reason}")
            }
            BlockingError::NoRuntime => {
                f.write_str("BlockingDomain::new requires a Tokio runtime")
            }
            BlockingError::QueueFull {
                thread_cap,
                queue_bound,
                queued,
                active,
            } => write!(
                f,
                "blocking domain queue full (thread_cap={thread_cap}, queue_bound={queue_bound}, queued={queued}, active={active})"
            ),
            BlockingError::Shutdown => f.write_str("blocking domain shutdown"),
        }
    }
}

impl std::error::Error for BlockingError {}

/// Outcome of [`BlockingJob::join`] when the closure did not produce a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockingJoinError {
    /// Job was cancelled before `spawn_blocking` started.
    Cancelled,
    /// Closure panicked on the blocking thread.
    Panicked,
    /// Domain dropped the job before it started.
    Shutdown,
}

impl fmt::Display for BlockingJoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockingJoinError::Cancelled => f.write_str("blocking job cancelled before start"),
            BlockingJoinError::Panicked => f.write_str("blocking job panicked"),
            BlockingJoinError::Shutdown => {
                f.write_str("blocking job dropped during domain shutdown")
            }
        }
    }
}

impl std::error::Error for BlockingJoinError {}

/// Snapshot of domain counters. Labels stay low-cardinality (no path / txn).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockingDomainStats {
    pub thread_cap: usize,
    pub queue_bound: usize,
    pub active: usize,
    pub queued: usize,
    pub rejected_total: u64,
    pub completed_total: u64,
    pub cancelled_total: u64,
    pub started_total: u64,
    /// Sum of queue-wait nanoseconds for jobs that reached `spawn_blocking`.
    pub wait_ns_total: u64,
}

impl BlockingDomainStats {
    /// Mean queue wait for started jobs, if any have started.
    pub fn mean_wait(self) -> Option<Duration> {
        if self.started_total == 0 {
            None
        } else {
            Some(Duration::from_nanos(
                self.wait_ns_total / self.started_total,
            ))
        }
    }
}

/// Bounded pool that runs `FnOnce` work on Tokio blocking threads.
///
/// Clone shares the same threads and queue. The last clone drops the worker
/// tasks; in-flight `spawn_blocking` closures still run to completion.
#[derive(Clone)]
pub struct BlockingDomain {
    inner: Arc<Inner>,
    /// Kept alive so [`WorkerSet::drop`] aborts worker tasks on last clone.
    workers: Arc<WorkerSet>,
}

struct WorkerSet {
    inner: Arc<Inner>,
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl Drop for WorkerSet {
    fn drop(&mut self) {
        self.inner.shutdown.store(true, Ordering::Release);
        self.inner.fail_queued();
        self.inner.notify.notify_waiters();
        let mut handles = self.handles.lock().unwrap_or_else(|e| e.into_inner());
        for handle in handles.drain(..) {
            // Aborts the worker *task*. Does not abort in-flight spawn_blocking.
            handle.abort();
        }
    }
}

struct Inner {
    thread_cap: usize,
    queue_bound: usize,
    queue: Mutex<VecDeque<Job>>,
    notify: Notify,
    shutdown: AtomicBool,
    active: AtomicUsize,
    rejected_total: AtomicU64,
    completed_total: AtomicU64,
    cancelled_total: AtomicU64,
    started_total: AtomicU64,
    wait_ns_total: AtomicU64,
}

struct Job {
    state: Arc<AtomicU8>,
    queued_at: Instant,
    run: Option<JobFn>,
    skip: Option<JobFn>,
}

impl Drop for Job {
    fn drop(&mut self) {
        if self
            .state
            .compare_exchange(
                STATE_QUEUED,
                STATE_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            if let Some(skip) = self.skip.take() {
                skip();
            }
        }
    }
}

impl Inner {
    fn pop_job(&self) -> Option<Job> {
        self.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
    }

    fn fail_queued(&self) {
        let mut queue = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        for mut job in queue.drain(..) {
            if job
                .state
                .compare_exchange(
                    STATE_QUEUED,
                    STATE_CANCELLED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                self.cancelled_total.fetch_add(1, Ordering::Relaxed);
                if let Some(skip) = job.skip.take() {
                    skip();
                }
            }
        }
    }

    fn snapshot(&self) -> BlockingDomainStats {
        let queued = self.queue.lock().unwrap_or_else(|e| e.into_inner()).len();
        BlockingDomainStats {
            thread_cap: self.thread_cap,
            queue_bound: self.queue_bound,
            active: self.active.load(Ordering::Acquire),
            queued,
            rejected_total: self.rejected_total.load(Ordering::Relaxed),
            completed_total: self.completed_total.load(Ordering::Relaxed),
            cancelled_total: self.cancelled_total.load(Ordering::Relaxed),
            started_total: self.started_total.load(Ordering::Relaxed),
            wait_ns_total: self.wait_ns_total.load(Ordering::Relaxed),
        }
    }
}

/// Handle for one submitted job. Join waits; abort cancels only if queued.
///
/// Dropping this handle cancels a queued job. If `spawn_blocking` has
/// already started, drop does **not** stop the closure.
#[derive(Debug)]
#[must_use = "dropping BlockingJob cancels the job if it has not started; in-flight work still runs"]
pub struct BlockingJob<T> {
    state: Arc<AtomicU8>,
    rx: mpsc::Receiver<Result<T, BlockingJoinError>>,
    detach: bool,
}

impl<T> BlockingJob<T> {
    /// Wait for the job to finish or be skipped.
    ///
    /// If the job had already entered `spawn_blocking`, this waits for the
    /// closure to return even after [`Self::abort`].
    pub async fn join(mut self) -> Result<T, BlockingJoinError> {
        match self.rx.recv().await {
            Some(Ok(value)) => Ok(value),
            Some(Err(err)) => Err(err),
            None => {
                if self.state.load(Ordering::Acquire) == STATE_CANCELLED {
                    Err(BlockingJoinError::Cancelled)
                } else {
                    Err(BlockingJoinError::Panicked)
                }
            }
        }
    }

    /// Cancel the job if it is still queued.
    ///
    /// Returns `true` when the job was still queued and will not run.
    /// Returns `false` if `spawn_blocking` has started (or the job already
    /// finished / was cancelled). In the `false` / started case the closure
    /// **cannot abort**; [`Self::join`] still waits for its result.
    pub fn abort(&self) -> bool {
        self.state
            .compare_exchange(
                STATE_QUEUED,
                STATE_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// `true` once the job has entered `spawn_blocking`.
    pub fn is_started(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_STARTED
    }

    /// Drop this handle without cancelling a still-queued job.
    ///
    /// Cleanup and other must-run finite work use this so request
    /// cancellation cannot skip a queued unlink. The receiver is dropped;
    /// the closure still runs to completion (or until domain shutdown).
    pub fn detach(mut self) {
        self.detach = true;
    }
}

impl<T> Drop for BlockingJob<T> {
    fn drop(&mut self) {
        if self.detach {
            return;
        }
        let _ = self.state.compare_exchange(
            STATE_QUEUED,
            STATE_CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

impl BlockingDomain {
    /// Spawn `thread_cap` worker tasks on the current Tokio runtime.
    ///
    /// Workers pull from the bounded queue and run each job with
    /// `tokio::task::spawn_blocking`. Must be called from inside a runtime.
    pub fn new(config: BlockingDomainConfig) -> Result<Self, BlockingError> {
        let config = BlockingDomainConfig::new(config.thread_cap, config.queue_bound)?;
        let rt = tokio::runtime::Handle::try_current().map_err(|_| BlockingError::NoRuntime)?;
        let inner = Arc::new(Inner {
            thread_cap: config.thread_cap,
            queue_bound: config.queue_bound,
            queue: Mutex::new(VecDeque::with_capacity(config.queue_bound)),
            notify: Notify::new(),
            shutdown: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            rejected_total: AtomicU64::new(0),
            completed_total: AtomicU64::new(0),
            cancelled_total: AtomicU64::new(0),
            started_total: AtomicU64::new(0),
            wait_ns_total: AtomicU64::new(0),
        });
        let mut handles = Vec::with_capacity(config.thread_cap);
        for _ in 0..config.thread_cap {
            let inner = Arc::clone(&inner);
            handles.push(rt.spawn(worker_loop(inner)));
        }
        Ok(Self {
            inner: Arc::clone(&inner),
            workers: Arc::new(WorkerSet {
                inner,
                handles: Mutex::new(handles),
            }),
        })
    }

    /// Convenience constructor. See [`BlockingDomainConfig::new`].
    pub fn with_bounds(thread_cap: usize, queue_bound: usize) -> Result<Self, BlockingError> {
        Self::new(BlockingDomainConfig::new(thread_cap, queue_bound)?)
    }

    pub fn thread_cap(&self) -> usize {
        self.inner.thread_cap
    }

    pub fn queue_bound(&self) -> usize {
        self.inner.queue_bound
    }

    pub fn stats(&self) -> BlockingDomainStats {
        self.inner.snapshot()
    }

    /// Enqueue `f` or fail closed. Never waits. Never grows the queue.
    ///
    /// The returned [`BlockingJob`] must be joined or explicitly aborted.
    /// Dropping it cancels a queued job only.
    #[must_use = "dropping BlockingJob cancels the job if it has not started; in-flight work still runs"]
    pub fn submit<F, R>(&self, f: F) -> Result<BlockingJob<R>, BlockingError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        if self.inner.shutdown.load(Ordering::Acquire) {
            return Err(BlockingError::Shutdown);
        }

        let (tx, rx) = mpsc::channel(1);
        let tx_run = tx.clone();
        let state = Arc::new(AtomicU8::new(STATE_QUEUED));
        let completed = Arc::clone(&self.inner);
        let job = Job {
            state: Arc::clone(&state),
            queued_at: Instant::now(),
            run: Some(Box::new(move || {
                let outcome = panic::catch_unwind(AssertUnwindSafe(f));
                let msg = match outcome {
                    Ok(value) => Ok(value),
                    Err(_) => Err(BlockingJoinError::Panicked),
                };
                completed.completed_total.fetch_add(1, Ordering::Release);
                let _ = tx_run.try_send(msg);
            })),
            skip: Some(Box::new(move || {
                let _ = tx.try_send(Err(BlockingJoinError::Cancelled));
            })),
        };

        {
            let mut queue = self.inner.queue.lock().unwrap_or_else(|e| e.into_inner());
            if self.inner.shutdown.load(Ordering::Acquire) {
                return Err(BlockingError::Shutdown);
            }
            if queue.len() >= self.inner.queue_bound {
                self.inner.rejected_total.fetch_add(1, Ordering::Relaxed);
                let queued = queue.len();
                let active = self.inner.active.load(Ordering::Acquire);
                return Err(BlockingError::QueueFull {
                    thread_cap: self.inner.thread_cap,
                    queue_bound: self.inner.queue_bound,
                    queued,
                    active,
                });
            }
            queue.push_back(job);
        }
        self.inner.notify.notify_one();
        Ok(BlockingJob {
            state,
            rx,
            detach: false,
        })
    }

    /// Submit and join. Fail-closed on a full queue (does not wait for a slot).
    pub async fn run<F, R>(&self, f: F) -> Result<R, BlockingRunError>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        match self.submit(f) {
            Ok(job) => match job.join().await {
                Ok(value) => Ok(value),
                Err(err) => Err(BlockingRunError::Join(err)),
            },
            Err(err) => Err(BlockingRunError::Submit(err)),
        }
    }
}

/// Error from [`BlockingDomain::run`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockingRunError {
    Submit(BlockingError),
    Join(BlockingJoinError),
}

impl fmt::Display for BlockingRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockingRunError::Submit(err) => write!(f, "{err}"),
            BlockingRunError::Join(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for BlockingRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BlockingRunError::Submit(err) => Some(err),
            BlockingRunError::Join(err) => Some(err),
        }
    }
}

async fn worker_loop(inner: Arc<Inner>) {
    loop {
        if inner.shutdown.load(Ordering::Acquire) {
            return;
        }

        let mut notified = std::pin::pin!(inner.notify.notified());
        let already = notified.as_mut().enable();

        if let Some(job) = inner.pop_job() {
            execute_job(&inner, job).await;
            continue;
        }

        if inner.shutdown.load(Ordering::Acquire) {
            return;
        }

        if already {
            continue;
        }

        notified.await;
    }
}

async fn execute_job(inner: &Inner, mut job: Job) {
    if job
        .state
        .compare_exchange(
            STATE_QUEUED,
            STATE_STARTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        inner.cancelled_total.fetch_add(1, Ordering::Relaxed);
        if let Some(skip) = job.skip.take() {
            skip();
        }
        return;
    }

    let wait_ns = job.queued_at.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    inner.wait_ns_total.fetch_add(wait_ns, Ordering::Relaxed);
    inner.started_total.fetch_add(1, Ordering::Relaxed);

    let run = job.run.take().expect("queued job missing run closure");
    // Drop skip without sending: the run path owns the result channel.
    drop(job.skip.take());
    drop(job);

    inner.active.fetch_add(1, Ordering::AcqRel);

    // Unique workspace `spawn_blocking` site. Aborting the worker task or
    // the returned JoinHandle does not stop `run` once this call has
    // started executing on the blocking pool.
    let join = tokio::task::spawn_blocking(run);
    match join.await {
        Ok(()) => {}
        Err(_) => {
            // Closure panicked after catch_unwind (or the blocking task was
            // cancelled by runtime shutdown). Result channel is already closed
            // or populated by catch_unwind.
        }
    }

    inner.active.fetch_sub(1, Ordering::AcqRel);
}

impl fmt::Debug for BlockingDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let worker_tasks = self.workers.handles.lock().map(|h| h.len()).unwrap_or(0);
        f.debug_struct("BlockingDomain")
            .field("stats", &self.inner.snapshot())
            .field("worker_tasks", &worker_tasks)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc as std_mpsc;
    use std::sync::Barrier;
    use std::thread;

    async fn wait_until(pred: impl Fn() -> bool) {
        let start = Instant::now();
        loop {
            if pred() {
                return;
            }
            if start.elapsed() > Duration::from_secs(2) {
                panic!("timeout waiting for blocking-domain condition");
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    #[test]
    fn rejects_zero_bounds() {
        assert!(matches!(
            BlockingDomainConfig::new(0, 1),
            Err(BlockingError::InvalidConfig { .. })
        ));
        assert!(matches!(
            BlockingDomainConfig::new(1, 0),
            Err(BlockingError::InvalidConfig { .. })
        ));
    }

    #[tokio::test]
    async fn job_runs() {
        let domain = BlockingDomain::with_bounds(1, 1).unwrap();
        let value = domain.submit(|| 7).unwrap().join().await.unwrap();
        assert_eq!(value, 7);
        let via_run = domain.run(|| 41).await.unwrap();
        assert_eq!(via_run, 41);
        let stats = domain.stats();
        assert_eq!(stats.thread_cap, 1);
        assert_eq!(stats.queue_bound, 1);
        assert_eq!(stats.completed_total, 2);
        assert_eq!(stats.rejected_total, 0);
        assert!(stats.mean_wait().is_some());
    }

    #[tokio::test]
    async fn reject_when_queue_full() {
        let domain = BlockingDomain::with_bounds(1, 1).unwrap();
        let (entered_tx, entered_rx) = std_mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std_mpsc::sync_channel::<()>(1);
        let ran_rejected = Arc::new(AtomicBool::new(false));

        let job1 = domain
            .submit(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                1u32
            })
            .unwrap();

        wait_until(|| entered_rx.try_recv().is_ok()).await;
        wait_until(|| domain.stats().active == 1).await;

        let job2 = domain.submit(|| 2u32).unwrap();
        wait_until(|| domain.stats().queued == 1).await;

        let rejected_flag = Arc::clone(&ran_rejected);
        let err = domain
            .submit(move || {
                rejected_flag.store(true, Ordering::SeqCst);
                3u32
            })
            .unwrap_err();
        assert!(
            matches!(
                err,
                BlockingError::QueueFull {
                    thread_cap: 1,
                    queue_bound: 1,
                    queued: 1,
                    active: 1,
                }
            ),
            "unexpected reject: {err:?}"
        );
        assert!(
            !ran_rejected.load(Ordering::SeqCst),
            "rejected closure must not run"
        );
        assert_eq!(domain.stats().rejected_total, 1);

        release_tx.send(()).unwrap();
        assert_eq!(job1.join().await.unwrap(), 1);
        assert_eq!(job2.join().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn thread_cap_is_respected() {
        const CAP: usize = 2;
        let domain = BlockingDomain::with_bounds(CAP, 16).unwrap();
        let current = Arc::new(AtomicUsize::new(0));
        let max = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(CAP));

        let mut jobs = Vec::new();
        for _ in 0..8 {
            let current = Arc::clone(&current);
            let max = Arc::clone(&max);
            let barrier = Arc::clone(&barrier);
            jobs.push(
                domain
                    .submit(move || {
                        let n = current.fetch_add(1, Ordering::SeqCst) + 1;
                        max.fetch_max(n, Ordering::SeqCst);
                        barrier.wait();
                        thread::sleep(Duration::from_millis(5));
                        current.fetch_sub(1, Ordering::SeqCst);
                    })
                    .unwrap(),
            );
        }

        tokio::time::timeout(Duration::from_secs(5), async {
            for job in jobs {
                job.join().await.unwrap();
            }
        })
        .await
        .expect("jobs should finish under thread_cap (barrier deadlock means cap < 2)");

        let observed = max.load(Ordering::SeqCst);
        assert!(
            observed <= CAP,
            "concurrent blocking threads {observed} exceeded cap {CAP}"
        );
        assert_eq!(
            observed, CAP,
            "barrier of {CAP} should force {CAP} concurrent blocking threads"
        );
        assert_eq!(domain.stats().completed_total, 8);
        wait_until(|| {
            let s = domain.stats();
            s.active == 0 && s.queued == 0
        })
        .await;
    }

    #[tokio::test]
    async fn abort_queued_job_does_not_stop_in_flight() {
        let domain = BlockingDomain::with_bounds(1, 4).unwrap();
        let (entered_tx, entered_rx) = std_mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std_mpsc::sync_channel::<()>(1);
        let ran_queued = Arc::new(AtomicBool::new(false));

        let in_flight = domain
            .submit(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                11u32
            })
            .unwrap();
        wait_until(|| entered_rx.try_recv().is_ok()).await;

        let ran = Arc::clone(&ran_queued);
        let queued = domain
            .submit(move || {
                ran.store(true, Ordering::SeqCst);
                12u32
            })
            .unwrap();
        assert!(queued.abort());
        assert!(!in_flight.abort(), "in-flight spawn_blocking cannot abort");

        release_tx.send(()).unwrap();
        assert_eq!(in_flight.join().await.unwrap(), 11);
        assert_eq!(
            queued.join().await.unwrap_err(),
            BlockingJoinError::Cancelled
        );
        assert!(
            !ran_queued.load(Ordering::SeqCst),
            "aborted queued job must not run"
        );
    }
}
