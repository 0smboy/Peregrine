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

//! Bounded replica fan-out (AGENTS.md §16–§17).
//!
//! Per-backend pending bytes are finite. A stalled replica does not grow an
//! unbounded buffer. If every live backend is at its window, the producer
//! must stop (end-to-end backpressure). Unused backends are cancelled via
//! the parent [`crate::TaskScope`].

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::scope::{SpawnError, TaskScope};
use crate::CancellationToken;

/// Per-backend pending-byte window. Fail-closed: [`Self::try_push`] never
/// waits and never grows past `limit`.
#[derive(Debug)]
pub struct BackpressureWindow {
    pending: AtomicUsize,
    limit: usize,
}

impl BackpressureWindow {
    pub fn new(limit: usize) -> Self {
        Self {
            pending: AtomicUsize::new(0),
            limit,
        }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    pub fn pending(&self) -> usize {
        self.pending.load(Ordering::SeqCst)
    }

    /// Reserve `n` bytes. `n == 0` always succeeds.
    pub fn try_push(&self, n: usize) -> Result<(), FanoutError> {
        if n == 0 {
            return Ok(());
        }
        if n > self.limit {
            return Err(FanoutError::WindowExceeded {
                pending: self.pending(),
                limit: self.limit,
            });
        }
        let mut cur = self.pending.load(Ordering::SeqCst);
        loop {
            let Some(next) = cur.checked_add(n) else {
                return Err(FanoutError::WindowExceeded {
                    pending: cur,
                    limit: self.limit,
                });
            };
            if next > self.limit {
                return Err(FanoutError::WindowExceeded {
                    pending: cur,
                    limit: self.limit,
                });
            }
            match self
                .pending
                .compare_exchange_weak(cur, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Ok(()),
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn pop(&self, n: usize) {
        let mut cur = self.pending.load(Ordering::SeqCst);
        loop {
            let next = cur.saturating_sub(n);
            match self
                .pending
                .compare_exchange_weak(cur, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }
}

/// Quorum tracker. Successes and failures are independent counters.
#[derive(Debug, Clone)]
pub struct QuorumTracker {
    needed: usize,
    successes: usize,
    failures: usize,
}

impl QuorumTracker {
    pub fn new(needed: usize) -> Self {
        Self {
            needed: needed.max(1),
            successes: 0,
            failures: 0,
        }
    }

    pub fn needed(&self) -> usize {
        self.needed
    }

    pub fn record_success(&mut self) {
        self.successes = self.successes.saturating_add(1);
    }

    pub fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
    }

    pub fn successes(&self) -> usize {
        self.successes
    }

    pub fn failures(&self) -> usize {
        self.failures
    }

    pub fn has_quorum(&self) -> bool {
        self.successes >= self.needed
    }
}

/// Why a fan-out slot or window refused work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutError {
    WindowExceeded { pending: usize, limit: usize },
    QueueFull { bound: usize },
    Spawn(SpawnError),
    Cancelled,
}

impl fmt::Display for FanoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FanoutError::WindowExceeded { pending, limit } => {
                write!(f, "backend window full ({pending}/{limit})")
            }
            FanoutError::QueueFull { bound } => {
                write!(f, "fan-out result queue full (bound {bound})")
            }
            FanoutError::Spawn(e) => write!(f, "{e}"),
            FanoutError::Cancelled => f.write_str("fan-out cancelled"),
        }
    }
}

impl std::error::Error for FanoutError {}

/// Bounded result stream for replica fan-out.
pub struct FanoutGroup<T> {
    scope: TaskScope,
    tx: mpsc::Sender<T>,
    rx: mpsc::Receiver<T>,
    bound: usize,
    spawned: usize,
    cancel: CancellationToken,
}

impl<T: Send + 'static> FanoutGroup<T> {
    pub fn new(result_bound: usize, child_bound: usize) -> Result<Self, FanoutError> {
        let bound = result_bound.max(1);
        let (tx, rx) = mpsc::channel(bound);
        let scope = TaskScope::bounded(child_bound.max(1));
        let cancel = scope.cancellation_token().clone();
        Ok(Self {
            scope,
            tx,
            rx,
            bound,
            spawned: 0,
            cancel,
        })
    }

    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.cancel
    }

    pub fn spawned(&self) -> usize {
        self.spawned
    }

    /// Spawn one replica worker. The worker receives a clone of the result
    /// sender and a child cancellation token.
    pub fn spawn<F, Fut>(&mut self, f: F) -> Result<(), FanoutError>
    where
        F: FnOnce(mpsc::Sender<T>, CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let tx = self.tx.clone();
        let token = self.cancel.child_token();
        let metrics = crate::metrics::ConcurrencyMetrics::current();
        if let Some(ref m) = metrics {
            m.backend_inflight_inc();
        }
        let metrics_for_child = metrics.clone();
        let _child = self
            .scope
            .spawn(async move {
                let _g = crate::metrics::BackendInflightGuard(metrics_for_child);
                f(tx, token).await
            })
            .map_err(|e| {
                if let Some(m) = metrics {
                    m.backend_inflight_dec();
                }
                FanoutError::Spawn(e)
            })?;
        let _ = _child;
        self.spawned += 1;
        Ok(())
    }

    /// Fail-closed try-send from the owner (not from a child).
    pub fn try_send(&self, value: T) -> Result<(), FanoutError> {
        self.tx
            .try_send(value)
            .map_err(|_| FanoutError::QueueFull { bound: self.bound })
    }

    pub async fn recv(&mut self) -> Option<T> {
        self.rx.recv().await
    }

    /// Cancel unused children after quorum. In-flight workers see the token.
    pub fn cancel_unused(&self) {
        self.cancel
            .cancel_with(crate::metrics::CancelReason::Quorum);
    }

    pub async fn join(self) {
        drop(self.tx);
        self.scope.join().await.ok();
    }
}

/// Shared per-replica window used when teeing a PUT body.
#[derive(Clone, Debug)]
pub struct SharedWindow {
    inner: Arc<BackpressureWindow>,
}

impl SharedWindow {
    pub fn new(limit: usize) -> Self {
        Self {
            inner: Arc::new(BackpressureWindow::new(limit)),
        }
    }

    pub fn try_push(&self, n: usize) -> Result<(), FanoutError> {
        self.inner.try_push(n)?;
        if let Some(m) = crate::metrics::ConcurrencyMetrics::current() {
            m.add_request_body_buffer(n as i64);
        }
        Ok(())
    }

    pub fn pop(&self, n: usize) {
        self.inner.pop(n);
        if let Some(m) = crate::metrics::ConcurrencyMetrics::current() {
            m.add_request_body_buffer(-(n as i64));
        }
    }

    pub fn pending(&self) -> usize {
        self.inner.pending()
    }

    pub fn limit(&self) -> usize {
        self.inner.limit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn window_is_fail_closed() {
        let w = BackpressureWindow::new(8);
        w.try_push(8).unwrap();
        assert_eq!(
            w.try_push(1),
            Err(FanoutError::WindowExceeded {
                pending: 8,
                limit: 8
            })
        );
        w.pop(3);
        w.try_push(3).unwrap();
        assert_eq!(w.pending(), 8);
    }

    #[test]
    fn quorum_is_independent_of_failures() {
        let mut q = QuorumTracker::new(2);
        q.record_failure();
        assert!(!q.has_quorum());
        q.record_success();
        q.record_success();
        assert!(q.has_quorum());
        assert_eq!(q.failures(), 1);
    }

    #[tokio::test]
    async fn fanout_cancels_unused_and_stays_bounded() {
        let mut group: FanoutGroup<&'static str> = FanoutGroup::new(2, 4).unwrap();
        group
            .spawn(|tx, cancel| async move {
                let _ = tx.send("ok-a").await;
                cancel.cancelled().await;
            })
            .unwrap();
        group
            .spawn(|tx, cancel| async move {
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {
                        let _ = tx.send("late").await;
                    }
                }
            })
            .unwrap();
        let first = group.recv().await;
        assert_eq!(first, Some("ok-a"));
        group.cancel_unused();
        let late = tokio::time::timeout(Duration::from_millis(200), group.recv()).await;
        assert_ne!(late.ok().flatten(), Some("late"));
        group.join().await;
    }
}
