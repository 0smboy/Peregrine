// Copyright (c) 2026 OpenStack Foundation
//! OS-thread / prefork concurrency **adapter** (lab helpers).
//!
//! # Honesty
//!
//! This module is **not** eventlet, **not** greenlet, and is **not** wired into
//! the HTTP serve path as an eventlet substitute. Python Swift may use eventlet
//! greenthreads; Rust Swift serves with a threaded HTTP server plus optional
//! OS-process prefork (`process_workers`). The helpers here exist for:
//!
//! * computing prefork × thread-pool sizing from conf-like inputs
//! * a small OS-thread job pool for lab / unit tests
//! * explicit yield counters for tests that want sched-point accounting
//!
//! Historical type names (`EventletConcurrency`, `GreenthreadPool`, …) are kept
//! for low API churn; they describe OS threads, not greenlets.
//!
//! # Mapping (conceptual only)
//!
//! | Conf / concept            | Rust meaning                                      |
//! |---------------------------|---------------------------------------------------|
//! | `process_workers`         | OS-level prefork (shared listen socket)           |
//! | `worker_threads`          | threads per process (thread pool capacity)        |
//! | `max_clients`             | connection queue / accept backlog per worker      |
//! | cooperative yield helper  | [`cooperative_yield`] — `thread::yield_now` only  |
//! | job pool                  | [`GreenthreadPool`] — OS threads, despite the name|
//!
//! Do **not** claim eventlet parity for production serving from this module.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

type Job = Box<dyn FnOnce() + Send + 'static>;
type JobQueue = Arc<(Mutex<VecDeque<Job>>, Condvar)>;

/// Global cooperative yield counter (tests assert yield frequency).
static YIELD_COUNT: AtomicU64 = AtomicU64::new(0);

/// Reset yield counter (tests only).
pub fn reset_yield_count() {
    YIELD_COUNT.store(0, Ordering::SeqCst);
}

pub fn yield_count() -> u64 {
    YIELD_COUNT.load(Ordering::SeqCst)
}

/// Explicit sched yield for tests — records a counter then `thread::yield_now`.
///
/// Does **not** emulate eventlet hubs or greenlet switching.
pub fn cooperative_yield() {
    YIELD_COUNT.fetch_add(1, Ordering::SeqCst);
    thread::yield_now();
}

/// Timed sleep with yield accounting (lab helper; not an eventlet sleep).
pub fn green_sleep(secs: f64) {
    YIELD_COUNT.fetch_add(1, Ordering::SeqCst);
    if secs <= 0.0 {
        thread::yield_now();
        return;
    }
    let dur = Duration::from_secs_f64(secs);
    thread::sleep(dur);
}

/// Effective concurrency formula for prefork + per-process thread pool.
///
/// * `process_workers` OS processes (prefork)
/// * each process: `worker_threads` OS threads (capped)
/// * `max_clients` bounds accept queue
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventletConcurrency {
    pub process_workers: usize,
    pub worker_threads: usize,
    pub max_clients: usize,
    pub connection_queue: usize,
    pub aggregate_threads: usize,
    pub formula: String,
}

/// Cap matching existing Swift-Rust servers (avoid unbounded thread spawn).
pub const WORKER_THREADS_CAP: usize = 128;

/// Compute concurrency from conf-like inputs (prefork / thread adapter).
pub fn compute_concurrency(
    process_workers: usize,
    workers: usize,
    max_clients: usize,
    worker_model: &str,
) -> EventletConcurrency {
    let process_workers = process_workers.max(1);
    let max_clients = max_clients.max(1);
    let model = worker_model.trim().to_ascii_lowercase();
    let (worker_threads, formula) = if model == "process"
        || model == "prefork"
        || model == "eventlet"
        || process_workers > 1
    {
        // Per-process thread pool sized from max_clients (prefork model).
        // `worker_model=eventlet` is accepted as an alias for prefork sizing only.
        let wt = max_clients.clamp(1, WORKER_THREADS_CAP);
        (
            wt,
            format!(
                "prefork: process_workers={process_workers} × max_clients→threads={wt} (cap {WORKER_THREADS_CAP})"
            ),
        )
    } else {
        // Thread-only model: workers * max_clients → threads (legacy Rust map).
        let product = workers
            .saturating_mul(max_clients)
            .clamp(1, WORKER_THREADS_CAP);
        (
            product,
            format!("thread: workers×max_clients={product} (cap {WORKER_THREADS_CAP})"),
        )
    };
    let aggregate = process_workers.saturating_mul(worker_threads);
    EventletConcurrency {
        process_workers,
        worker_threads,
        max_clients,
        connection_queue: max_clients,
        aggregate_threads: aggregate,
        formula,
    }
}

/// Bounded OS-thread job pool (name is historical; not greenlets).
///
/// Each finished job calls [`cooperative_yield`] for test accounting only.
pub struct GreenthreadPool {
    jobs: JobQueue,
    shutdown: Arc<Mutex<bool>>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl GreenthreadPool {
    pub fn new(size: usize) -> Self {
        let size = size.clamp(1, WORKER_THREADS_CAP);
        let jobs: JobQueue = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
        let shutdown = Arc::new(Mutex::new(false));
        let mut handles = Vec::with_capacity(size);
        for _ in 0..size {
            let jobs = Arc::clone(&jobs);
            let shutdown = Arc::clone(&shutdown);
            handles.push(thread::spawn(move || loop {
                let job = {
                    let (lock, cv) = &*jobs;
                    let mut q = lock.lock().unwrap();
                    loop {
                        if *shutdown.lock().unwrap() && q.is_empty() {
                            return;
                        }
                        if let Some(job) = q.pop_front() {
                            break job;
                        }
                        q = cv.wait(q).unwrap();
                    }
                };
                job();
                cooperative_yield();
            }));
        }
        Self {
            jobs,
            shutdown,
            handles,
        }
    }

    /// Queue a job onto the OS-thread pool.
    pub fn spawn<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let (lock, cv) = &*self.jobs;
        lock.lock().unwrap().push_back(Box::new(f));
        cv.notify_one();
    }

    /// Wait until queue drains (best-effort lab join).
    pub fn join_idle(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let empty = self.jobs.0.lock().unwrap().is_empty();
            if empty {
                // brief settle for in-flight
                thread::sleep(Duration::from_millis(5));
                if self.jobs.0.lock().unwrap().is_empty() {
                    return true;
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
        false
    }
}

impl Drop for GreenthreadPool {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        self.jobs.1.notify_all();
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

/// Thread-local-ish map keyed by OS thread id (name is historical).
#[derive(Debug, Default)]
pub struct GreenLocal<T: Clone + Send> {
    map: Mutex<std::collections::HashMap<thread::ThreadId, T>>,
}

impl<T: Clone + Send> GreenLocal<T> {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn get(&self) -> Option<T> {
        let id = thread::current().id();
        self.map.lock().ok()?.get(&id).cloned()
    }

    pub fn set(&self, val: T) {
        let id = thread::current().id();
        if let Ok(mut g) = self.map.lock() {
            g.insert(id, val);
        }
    }
}

/// Heartbeat yield policy matching SLO `yield_frequency` semantics.
///
/// Returns true when a yield should occur given elapsed time and frequency.
pub fn should_yield_heartbeat(
    elapsed_secs: f64,
    yield_frequency: f64,
    last_yield_secs: f64,
) -> bool {
    if yield_frequency <= 0.0 {
        return false; // 0 = no throttle yield (emit every time caller decides)
    }
    (elapsed_secs - last_yield_secs) >= yield_frequency
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn concurrency_eventlet_model() {
        let c = compute_concurrency(4, 8, 1024, "eventlet");
        assert_eq!(c.process_workers, 4);
        assert_eq!(c.worker_threads, WORKER_THREADS_CAP); // 1024 capped
        assert_eq!(c.connection_queue, 1024);
        assert!(c.formula.contains("prefork"));
    }

    #[test]
    fn concurrency_thread_model() {
        let c = compute_concurrency(1, 2, 10, "thread");
        assert_eq!(c.worker_threads, 20);
    }

    #[test]
    fn greenthread_pool_runs_jobs() {
        reset_yield_count();
        let pool = GreenthreadPool::new(2);
        let counter = Arc::new(AtomicUsize::new(0));
        for _ in 0..20 {
            let c = Arc::clone(&counter);
            pool.spawn(move || {
                c.fetch_add(1, Ordering::SeqCst);
            });
        }
        assert!(pool.join_idle(Duration::from_secs(2)));
        assert_eq!(counter.load(Ordering::SeqCst), 20);
        assert!(yield_count() >= 20);
    }

    #[test]
    fn green_local_is_thread_scoped() {
        let local = Arc::new(GreenLocal::new());
        local.set(1i32);
        assert_eq!(local.get(), Some(1));
        let local2 = Arc::clone(&local);
        let h = thread::spawn(move || {
            assert!(local2.get().is_none());
            local2.set(2);
            assert_eq!(local2.get(), Some(2));
        });
        h.join().unwrap();
        assert_eq!(local.get(), Some(1));
    }

    #[test]
    fn heartbeat_yield_frequency() {
        assert!(!should_yield_heartbeat(1.0, 0.0, 0.0));
        assert!(should_yield_heartbeat(1.0, 0.5, 0.0));
        assert!(!should_yield_heartbeat(0.4, 0.5, 0.0));
    }
}
