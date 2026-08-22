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

//! Per-request context: cancellation, deadline budget, traffic class, trans
//! id, and a child [`TaskScope`] (AGENTS.md §18).
//!
//! [`DurabilityBarrier`] marks commit-shield. Dropping an unfinished barrier
//! is forbidden (L7): cancellation is control flow, not transaction rollback.

use std::fmt;
use std::future::Future;
use std::sync::Arc;

use crate::deadline::DeadlineBudget;
use crate::scope::{
    CancellationToken, ScopeJoinError, ScopedTask, SpawnError, TaskScope, DEFAULT_SCOPE_BOUND,
};
use crate::traffic::TrafficClass;

/// Swift `X-Trans-Id` / `tx…` identifier. Cheap to clone.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TransId(Arc<str>);

impl TransId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(Arc::from(id.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TransId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for TransId {
    fn from(id: String) -> Self {
        Self::new(id)
    }
}

impl AsRef<str> for TransId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Request-scoped structured-concurrency root.
pub struct RequestContext {
    cancel: CancellationToken,
    deadlines: DeadlineBudget,
    traffic_class: TrafficClass,
    trans_id: TransId,
    scope: TaskScope,
}

impl RequestContext {
    pub fn new(trans_id: TransId, traffic_class: TrafficClass) -> Self {
        Self::with_bound(trans_id, traffic_class, DEFAULT_SCOPE_BOUND)
    }

    pub fn with_bound(trans_id: TransId, traffic_class: TrafficClass, max_children: usize) -> Self {
        let cancel = CancellationToken::new();
        Self {
            scope: TaskScope::from_token(cancel.clone(), max_children),
            cancel,
            deadlines: DeadlineBudget::new(),
            traffic_class,
            trans_id,
        }
    }

    pub fn trans_id(&self) -> &TransId {
        &self.trans_id
    }

    pub fn traffic_class(&self) -> TrafficClass {
        self.traffic_class
    }

    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.cancel
    }

    pub fn deadlines(&self) -> &DeadlineBudget {
        &self.deadlines
    }

    pub fn deadlines_mut(&mut self) -> &mut DeadlineBudget {
        &mut self.deadlines
    }

    pub fn scope(&self) -> &TaskScope {
        &self.scope
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Cancel this request. Children see it; this does not cancel a parent
    /// context.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Refresh BodyIdle because a chunk arrived. Does not touch UploadLifetime.
    pub fn refresh_body_idle(&mut self) {
        self.deadlines.refresh_body_idle();
    }

    /// Child context: parent cancel notifies the child; child cancel does not
    /// notify the parent. Own [`TaskScope`] join-set.
    pub fn child(&self) -> RequestContext {
        let cancel = self.cancel.child_token();
        RequestContext {
            scope: TaskScope::from_token(cancel.clone(), self.scope.bound()),
            cancel,
            deadlines: self.deadlines.clone(),
            traffic_class: self.traffic_class,
            trans_id: self.trans_id.clone(),
        }
    }

    pub fn spawn<F, T>(&self, fut: F) -> Result<ScopedTask<T>, SpawnError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.scope.spawn(fut)
    }

    pub async fn join(self) -> Result<(), ScopeJoinError> {
        self.scope.join().await
    }
}

impl fmt::Debug for RequestContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestContext")
            .field("trans_id", &self.trans_id)
            .field("traffic_class", &self.traffic_class)
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Guard for the durability commit-shield (L7, AGENTS.md §13).
///
/// After a PUT reaches DurabilityBarrier, cancellation is **not** transaction
/// rollback. The commit-shield task must finish the commit or a deterministic
/// failure. Dropping this guard (or the Future it protects) is **forbidden**:
/// it would leave object durability ambiguous.
///
/// Call [`DurabilityBarrier::complete`] (committed or failed) to disarm.
#[must_use = "dropping an unfinished DurabilityBarrier is forbidden (L7 commit-shield)"]
pub struct DurabilityBarrier {
    disarmed: bool,
    metrics: Option<crate::metrics::ConcurrencyMetrics>,
}

impl DurabilityBarrier {
    /// Enter the commit-shield region. Must [`Self::complete`] before drop.
    pub fn enter() -> Self {
        let metrics = crate::metrics::ConcurrencyMetrics::current();
        if let Some(ref m) = metrics {
            m.commit_shield_inc();
        }
        Self {
            disarmed: false,
            metrics,
        }
    }

    /// Disarm after a deterministic commit or failure. Safe to drop afterward.
    pub fn complete(mut self) {
        self.disarmed = true;
        if let Some(m) = self.metrics.take() {
            m.commit_shield_dec();
        }
    }

    pub fn is_disarmed(&self) -> bool {
        self.disarmed
    }

    /// Run `fut` on a task that is **not** cancelled when the caller is
    /// dropped (L7). The barrier lives on that task and is completed after
    /// `fut` returns — success or deterministic error. Dropping the returned
    /// future only detaches the waiter; commit still finishes.
    pub async fn run_shielded<F, T>(fut: F) -> T
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let metrics = crate::metrics::ConcurrencyMetrics::current();
        let conn_shields = crate::metrics::ConcurrencyMetrics::current_conn_shields();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let metrics_for_task = metrics.clone();
        let handle = tokio::spawn(async move {
            let work = async {
                let barrier = DurabilityBarrier::enter();
                let value = fut.await;
                barrier.complete();
                value
            };
            // tokio::spawn does not inherit task-locals. Re-bind both the
            // process metrics and this HTTP connection's shield counter so
            // shutdown can drain *this* connection after commit (L7) without
            // waiting on some other connection's barrier.
            let value = crate::metrics::ConcurrencyMetrics::apply_captured_locals(
                metrics_for_task,
                conn_shields,
                work,
            )
            .await;
            let _ = tx.send(value);
        });
        if let Some(ref m) = metrics {
            m.track_shield(handle);
        }
        match rx.await {
            Ok(value) => value,
            Err(_) => panic!("commit-shield task ended without a result (L7)"),
        }
    }
}

impl Drop for DurabilityBarrier {
    fn drop(&mut self) {
        if !self.disarmed {
            if let Some(m) = self.metrics.take() {
                m.commit_shield_dec();
            }
            panic!(
                "DurabilityBarrier dropped without complete(); \
                 dropping a commit-shield leaves object durability ambiguous (L7)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deadline::{BodyIdleDeadline, UploadLifetimeDeadline};
    use crate::metrics::ConcurrencyMetrics;
    use std::any::TypeId;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn durability_barrier_type_exists() {
        assert_eq!(
            TypeId::of::<DurabilityBarrier>(),
            TypeId::of::<DurabilityBarrier>()
        );
        let name = std::any::type_name::<DurabilityBarrier>();
        assert!(name.contains("DurabilityBarrier"));
        let barrier = DurabilityBarrier::enter();
        assert!(!barrier.is_disarmed());
        barrier.complete();
    }

    #[test]
    #[should_panic(expected = "DurabilityBarrier")]
    fn durability_barrier_drop_without_complete_is_forbidden() {
        let _barrier = DurabilityBarrier::enter();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_shielded_survives_drop_of_waiter() {
        let m = ConcurrencyMetrics::new();
        m.bind(async {
            let entered = Arc::new(AtomicBool::new(false));
            let release = Arc::new(AtomicBool::new(false));
            let finished = Arc::new(AtomicBool::new(false));
            let waiter = DurabilityBarrier::run_shielded({
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                let finished = Arc::clone(&finished);
                async move {
                    entered.store(true, Ordering::SeqCst);
                    while !release.load(Ordering::SeqCst) {
                        tokio::task::yield_now().await;
                    }
                    finished.store(true, Ordering::SeqCst);
                    11u8
                }
            });
            tokio::pin!(waiter);
            let start = Instant::now();
            while !entered.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(2) {
                tokio::select! {
                    biased;
                    _ = waiter.as_mut() => panic!("shield waiter finished before stall released"),
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                }
            }
            assert!(entered.load(Ordering::SeqCst));
            assert!(m.snapshot().commit_shield_active >= 1);
            drop(waiter);
            assert!(
                m.snapshot().commit_shield_active >= 1,
                "HTTP waiter drop must not complete/abort the shield"
            );
            release.store(true, Ordering::SeqCst);
            while !finished.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(2) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert!(
                finished.load(Ordering::SeqCst),
                "shielded work must finish after the waiter is dropped"
            );
            while m.snapshot().commit_shield_active != 0 && start.elapsed() < Duration::from_secs(2)
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(m.snapshot().commit_shield_active, 0);
            m.join_remaining_shields().await;
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_shielded_increments_connection_local_counter() {
        let m = ConcurrencyMetrics::new();
        let cs = Arc::new(AtomicUsize::new(0));
        m.bind_conn(Arc::clone(&cs), async {
            let entered = Arc::new(AtomicBool::new(false));
            let release = Arc::new(AtomicBool::new(false));
            let waiter = DurabilityBarrier::run_shielded({
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                async move {
                    entered.store(true, Ordering::SeqCst);
                    while !release.load(Ordering::SeqCst) {
                        tokio::task::yield_now().await;
                    }
                    3u8
                }
            });
            tokio::pin!(waiter);
            let start = Instant::now();
            while !entered.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(2) {
                tokio::select! {
                    biased;
                    _ = waiter.as_mut() => panic!("shield waiter finished before stall released"),
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {}
                }
            }
            assert!(entered.load(Ordering::SeqCst));
            assert!(
                cs.load(Ordering::SeqCst) >= 1,
                "spawned shield task must bump this connection's counter, not only the process gauge"
            );
            release.store(true, Ordering::SeqCst);
            assert_eq!(waiter.await, 3);
            assert_eq!(cs.load(Ordering::SeqCst), 0);
            m.join_remaining_shields().await;
        })
        .await;
    }

    #[test]
    fn request_context_holds_required_fields() {
        let mut ctx = RequestContext::new(TransId::new("tx-test"), TrafficClass::Foreground);
        assert_eq!(ctx.trans_id().as_str(), "tx-test");
        assert_eq!(ctx.traffic_class(), TrafficClass::Foreground);
        assert!(!ctx.is_cancelled());
        ctx.deadlines_mut().body_idle =
            Some(BodyIdleDeadline::from_timeout(Duration::from_secs(5)));
        ctx.deadlines_mut().upload_lifetime = Some(UploadLifetimeDeadline::from_timeout(
            Duration::from_secs(60),
        ));
        assert!(ctx.deadlines().body_idle.is_some());
        assert!(ctx.deadlines().upload_lifetime.is_some());
        assert_ne!(
            ctx.deadlines().body_idle.unwrap().kind(),
            ctx.deadlines().upload_lifetime.unwrap().kind()
        );
    }

    #[tokio::test]
    async fn parent_cancels_child() {
        let parent = RequestContext::new(TransId::new("tx-p"), TrafficClass::Replication);
        let child = parent.child();
        let grandchild = child.child();
        assert_eq!(child.trans_id().as_str(), "tx-p");
        assert_eq!(child.traffic_class(), TrafficClass::Replication);

        parent.cancel();

        assert!(parent.is_cancelled());
        assert!(child.is_cancelled());
        assert!(grandchild.is_cancelled());
        tokio::time::timeout(
            Duration::from_secs(1),
            child.cancellation_token().cancelled(),
        )
        .await
        .expect("child token wait must complete when parent cancels");
    }

    #[tokio::test]
    async fn child_context_cancel_does_not_cancel_parent() {
        let parent = RequestContext::new(TransId::new("tx-p"), TrafficClass::Auditor);
        let child = parent.child();
        child.cancel();
        assert!(child.is_cancelled());
        assert!(!parent.is_cancelled());
    }

    #[tokio::test]
    async fn parent_cancel_stops_child_spawned_task() {
        let ctx = RequestContext::with_bound(TransId::new("tx-s"), TrafficClass::Foreground, 8);
        let _task = ctx.spawn(std::future::pending::<()>()).unwrap();
        ctx.cancel();
        tokio::time::timeout(Duration::from_secs(1), ctx.join())
            .await
            .expect("request join after cancel must not hang")
            .unwrap();
    }
}
