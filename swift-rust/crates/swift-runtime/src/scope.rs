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

//! Structured task scopes and hierarchical cancellation (AGENTS.md L6, §18).
//!
//! [`TaskScope::spawn`] is the only spawn path in this crate: the `JoinHandle`
//! is retained. Dropping a scope aborts remaining children; it does not detach
//! them. Child cancellation does not cancel the parent.
//!
//! This module does not enter the blocking execution domain.

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::{oneshot, Notify};
use tokio::task::{AbortHandle, JoinHandle};

/// Default child-task bound (Eventlet `RestrictedGreenPool` / `max_clients`
/// analog for **one request's child tasks**, not `max_connections`).
pub const DEFAULT_SCOPE_BOUND: usize = 1024;

/// Hierarchical cancellation token.
///
/// [`CancellationToken::cancel`] notifies this token and its descendants.
/// It does not cancel the parent. [`CancellationToken::child_token`] creates
/// a descendant.
#[derive(Clone)]
pub struct CancellationToken {
    inner: Arc<CancelInner>,
}

struct CancelInner {
    cancelled: AtomicBool,
    notify: Notify,
    parent: Option<CancellationToken>,
    children: Mutex<Vec<Weak<CancelInner>>>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CancelInner {
                cancelled: AtomicBool::new(false),
                notify: Notify::new(),
                parent: None,
                children: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Child token: parent cancel is visible here; this cancel is not visible
    /// on the parent.
    pub fn child_token(&self) -> Self {
        let child = Self {
            inner: Arc::new(CancelInner {
                cancelled: AtomicBool::new(false),
                notify: Notify::new(),
                parent: Some(self.clone()),
                children: Mutex::new(Vec::new()),
            }),
        };
        {
            let mut kids = lock_weaks(&self.inner.children);
            kids.retain(|w| w.upgrade().is_some());
            kids.push(Arc::downgrade(&child.inner));
        }
        if self.is_cancelled() {
            child.cancel();
        }
        child
    }

    pub fn cancel(&self) {
        self.cancel_with(crate::metrics::CancelReason::Request);
    }

    /// Cancel with an explicit low-cardinality reason (Phase 11).
    pub fn cancel_with(&self, reason: crate::metrics::CancelReason) {
        if !self.is_cancelled() {
            crate::metrics::ConcurrencyMetrics::record_cancellation_current(reason);
        }
        self.cancel_tree();
    }

    fn cancel_tree(&self) {
        if self.inner.cancelled.swap(true, Ordering::SeqCst) {
            return;
        }
        self.inner.notify.notify_waiters();
        let kids: Vec<Arc<CancelInner>> = {
            let mut children = lock_weaks(&self.inner.children);
            children.retain(|w| w.upgrade().is_some());
            children.iter().filter_map(|w| w.upgrade()).collect()
        };
        for kid in kids {
            CancellationToken { inner: kid }.cancel_tree();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        let mut cur = Some(self);
        while let Some(token) = cur {
            if token.inner.cancelled.load(Ordering::SeqCst) {
                return true;
            }
            cur = token.inner.parent.as_ref();
        }
        false
    }

    /// Completes when this token or an ancestor is cancelled.
    pub async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

fn lock_weaks(
    m: &Mutex<Vec<Weak<CancelInner>>>,
) -> std::sync::MutexGuard<'_, Vec<Weak<CancelInner>>> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Why [`TaskScope::spawn`] refused a child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    /// [`TaskScope`] child-task bound (L3).
    BoundExceeded { bound: usize },
    /// [`TaskScope::join`] has already closed the scope.
    Closed,
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpawnError::BoundExceeded { bound } => {
                write!(f, "task scope bound {bound} exceeded")
            }
            SpawnError::Closed => f.write_str("task scope is closed"),
        }
    }
}

impl std::error::Error for SpawnError {}

/// A child was cancelled or the oneshot sender was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskCancelled;

impl fmt::Display for TaskCancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("scoped task cancelled")
    }
}

impl std::error::Error for TaskCancelled {}

/// A child task panicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeJoinError;

impl fmt::Display for ScopeJoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("scoped task panicked")
    }
}

impl std::error::Error for ScopeJoinError {}

/// Handle for one child of a [`TaskScope`]. Dropping this does **not** detach
/// the task: the scope retains the `JoinHandle`. [`ScopedTask::cancel`]
/// cancels this child only.
#[derive(Debug)]
#[must_use = "dropping ScopedTask does not detach; join the TaskScope"]
pub struct ScopedTask<T> {
    rx: oneshot::Receiver<T>,
    cancel: CancellationToken,
    abort: AbortHandle,
}

impl<T> ScopedTask<T> {
    pub async fn join(self) -> Result<T, TaskCancelled> {
        self.rx.await.map_err(|_| TaskCancelled)
    }

    /// Cancel this child. Does not cancel the parent scope or siblings.
    pub fn cancel(&self) {
        self.cancel.cancel();
        self.abort.abort();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.cancel
    }
}

struct ScopeInner {
    cancel: CancellationToken,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    bound: usize,
    closed: AtomicBool,
}

impl Drop for ScopeInner {
    fn drop(&mut self) {
        self.cancel.cancel();
        let mut tasks = self.tasks.lock().unwrap_or_else(|p| p.into_inner());
        for handle in tasks.drain(..) {
            handle.abort();
        }
    }
}

/// Bounded nursery for child tasks. No detached fire-and-forget.
#[derive(Clone)]
#[must_use = "dropping TaskScope aborts remaining children; call join"]
pub struct TaskScope {
    inner: Arc<ScopeInner>,
}

impl TaskScope {
    pub fn new() -> Self {
        Self::bounded(DEFAULT_SCOPE_BOUND)
    }

    pub fn bounded(max_children: usize) -> Self {
        Self::from_token(CancellationToken::new(), max_children)
    }

    pub fn from_token(cancel: CancellationToken, max_children: usize) -> Self {
        Self {
            inner: Arc::new(ScopeInner {
                cancel,
                tasks: Mutex::new(Vec::new()),
                bound: max_children,
                closed: AtomicBool::new(false),
            }),
        }
    }

    pub fn bound(&self) -> usize {
        self.inner.bound
    }

    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.inner.cancel
    }

    pub fn cancel(&self) {
        self.inner
            .cancel
            .cancel_with(crate::metrics::CancelReason::Request);
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancel.is_cancelled()
    }

    /// Nested scope: parent cancel notifies the child; child cancel does not
    /// notify the parent. Own join-set, same bound.
    pub fn child_scope(&self) -> TaskScope {
        Self::from_token(self.inner.cancel.child_token(), self.inner.bound)
    }

    /// Spawn a cancellable child. The `JoinHandle` is stored on the scope.
    ///
    /// The child is wrapped so parent/child-token cancel drops the future.
    /// Commit-shield work must not use this path (see [`crate::DurabilityBarrier`]).
    pub fn spawn<F, T>(&self, fut: F) -> Result<ScopedTask<T>, SpawnError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let mut tasks = self.lock_tasks();
        if self.inner.closed.load(Ordering::SeqCst) {
            return Err(SpawnError::Closed);
        }
        if tasks.len() >= self.inner.bound {
            return Err(SpawnError::BoundExceeded {
                bound: self.inner.bound,
            });
        }
        let child_cancel = self.inner.cancel.child_token();
        let wait_cancel = child_cancel.clone();
        let (tx, rx) = oneshot::channel();
        let metrics = crate::metrics::ConcurrencyMetrics::current();
        if let Some(ref m) = metrics {
            m.runtime_tasks_inc();
        }
        let metrics_for_task = metrics.clone();
        let conn_shields = crate::metrics::ConcurrencyMetrics::current_conn_shields();
        let handle = tokio::spawn(async move {
            let _guard = crate::metrics::RuntimeTaskGuard(metrics_for_task.clone());
            let work = async {
                tokio::select! {
                    biased;
                    _ = wait_cancel.cancelled() => {}
                    result = fut => {
                        let _ = tx.send(result);
                    }
                }
            };
            crate::metrics::ConcurrencyMetrics::apply_captured_locals(
                metrics_for_task,
                conn_shields,
                work,
            )
            .await;
        });
        let abort = handle.abort_handle();
        tasks.push(handle);
        Ok(ScopedTask {
            rx,
            cancel: child_cancel,
            abort,
        })
    }

    /// Wait for every stored child. Cancels nothing by itself.
    pub async fn join(&self) -> Result<(), ScopeJoinError> {
        let mut panicked = false;
        loop {
            let batch = {
                let mut tasks = self.lock_tasks();
                if tasks.is_empty() {
                    self.inner.closed.store(true, Ordering::SeqCst);
                    if tasks.is_empty() {
                        Vec::new()
                    } else {
                        std::mem::take(&mut *tasks)
                    }
                } else {
                    std::mem::take(&mut *tasks)
                }
            };
            if batch.is_empty() {
                break;
            }
            for handle in batch {
                match handle.await {
                    Ok(()) => {}
                    Err(err) if err.is_cancelled() => {}
                    Err(_) => panicked = true,
                }
            }
        }
        if panicked {
            Err(ScopeJoinError)
        } else {
            Ok(())
        }
    }

    pub fn child_count(&self) -> usize {
        self.lock_tasks().len()
    }

    fn lock_tasks(&self) -> std::sync::MutexGuard<'_, Vec<JoinHandle<()>>> {
        self.inner.tasks.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Default for TaskScope {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TaskScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskScope")
            .field("cancelled", &self.is_cancelled())
            .field("bound", &self.inner.bound)
            .field("children", &self.child_count())
            .field("closed", &self.inner.closed.load(Ordering::SeqCst))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn parent_cancels_child() {
        let parent = CancellationToken::new();
        let child = parent.child_token();
        let grandchild = child.child_token();
        assert!(!parent.is_cancelled());
        assert!(!child.is_cancelled());
        assert!(!grandchild.is_cancelled());

        parent.cancel();

        assert!(parent.is_cancelled());
        assert!(child.is_cancelled());
        assert!(grandchild.is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), child.cancelled())
            .await
            .expect("child cancelled() must complete when parent cancels");
    }

    #[tokio::test]
    async fn child_does_not_cancel_parent() {
        let parent = CancellationToken::new();
        let child = parent.child_token();
        let sibling = parent.child_token();
        child.cancel();
        assert!(child.is_cancelled());
        assert!(!parent.is_cancelled());
        assert!(!sibling.is_cancelled());
        let late = parent.child_token();
        assert!(!late.is_cancelled());
    }

    #[tokio::test]
    async fn parent_scope_cancels_spawned_child_task() {
        let scope = TaskScope::bounded(8);
        let started = Arc::new(Notify::new());
        let started_task = started.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_flag = dropped.clone();

        struct FlagOnDrop(Arc<AtomicBool>);
        impl Drop for FlagOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let _task = scope
            .spawn(async move {
                let _guard = FlagOnDrop(dropped_flag);
                started_task.notify_one();
                std::future::pending::<()>().await;
            })
            .unwrap();

        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .unwrap();
        scope.cancel();
        tokio::time::timeout(Duration::from_secs(1), scope.join())
            .await
            .expect("join must not hang after parent cancel")
            .unwrap();
        assert!(dropped.load(Ordering::SeqCst));
        assert!(scope.is_cancelled());
    }

    #[tokio::test]
    async fn child_cancel_does_not_cancel_sibling_or_parent() {
        let scope = TaskScope::bounded(8);
        let first = scope.spawn(std::future::pending::<u32>()).unwrap();
        let (tx, rx) = oneshot::channel();
        let _second = scope
            .spawn(async move {
                tx.send(7u32).unwrap();
                7u32
            })
            .unwrap();
        first.cancel();
        assert!(first.is_cancelled());
        assert!(!scope.is_cancelled());
        assert_eq!(rx.await.unwrap(), 7);
        scope.cancel();
        scope.join().await.unwrap();
    }

    #[tokio::test]
    async fn join_waits_for_children() {
        let scope = TaskScope::bounded(4);
        let hits = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let hits = hits.clone();
            let _task = scope
                .spawn(async move {
                    tokio::time::sleep(Duration::from_millis(15)).await;
                    hits.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
        }
        scope.join().await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 3);
        assert!(matches!(scope.spawn(async {}), Err(SpawnError::Closed)));
    }

    #[tokio::test]
    async fn spawn_respects_finite_bound() {
        let scope = TaskScope::bounded(1);
        let child = scope.spawn(std::future::pending::<()>()).unwrap();
        assert_eq!(
            scope.spawn(async {}).unwrap_err(),
            SpawnError::BoundExceeded { bound: 1 }
        );
        child.cancel();
        scope.join().await.unwrap();
    }

    #[tokio::test]
    async fn drop_aborts_children_no_detach() {
        let dropped = Arc::new(AtomicBool::new(false));
        struct FlagOnDrop(Arc<AtomicBool>);
        impl Drop for FlagOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let flag = dropped.clone();
        {
            let scope = TaskScope::bounded(4);
            // Construct the guard as a captured local so abort-before-poll
            // still drops it (the async block body has not run yet).
            let guard = FlagOnDrop(flag);
            let _task = scope
                .spawn(async move {
                    let _guard = guard;
                    std::future::pending::<()>().await;
                })
                .unwrap();
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while !dropped.load(Ordering::SeqCst) {
            if tokio::time::Instant::now() >= deadline {
                panic!("scope drop must abort children; future was detached");
            }
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn child_scope_cancel_is_hierarchical() {
        let parent = TaskScope::bounded(4);
        let child = parent.child_scope();
        parent.cancel();
        assert!(child.is_cancelled());
        assert!(parent.is_cancelled());

        let parent = TaskScope::bounded(4);
        let child = parent.child_scope();
        child.cancel();
        assert!(child.is_cancelled());
        assert!(!parent.is_cancelled());
    }
}
