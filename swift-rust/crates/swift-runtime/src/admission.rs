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

//! Independent admission budgets for connections, in-flight requests, and
//! traffic classes.
//!
//! This is not one global semaphore. Connection concurrency, request
//! concurrency, and each [`TrafficClass`] are separate finite resources
//! (AGENTS.md L3, L5, L8, §7). Overload is fail-closed: [`AdmissionController::try_acquire_connection`]
//! and [`AdmissionController::try_acquire_request`] never wait, never grow
//! an unbounded queue, and never invent a default cap.
//!
//! # Legacy `max_clients`
//!
//! Python Swift `max_clients` (Eventlet `RestrictedGreenPool` size; sample
//! default 1024) is a **deprecated compatibility alias for
//! `max_active_requests`**. It is **not** `max_connections` and this module
//! does not apply 1024 (or any other figure) as a hidden default. Callers
//! that still read `max_clients` from conf must pass that configured value
//! through [`AdmissionLimits::from_legacy_max_clients`] together with an
//! explicit `max_connections` and the four class caps.

use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::traffic::TrafficClass;

/// Finite caps required to construct an [`AdmissionController`].
///
/// Every field is mandatory. There is no `Default` impl so a missing cap
/// cannot silently become `max_clients` or 1024.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionLimits {
    /// Concurrent accepted connections (idle keep-alive included).
    pub max_connections: usize,
    /// Concurrent in-flight requests (the legacy `max_clients` alias).
    pub max_active_requests: usize,
    /// Concurrent [`TrafficClass::Foreground`] requests.
    pub max_foreground: usize,
    /// Concurrent [`TrafficClass::Replication`] requests.
    pub max_replication: usize,
    /// Concurrent [`TrafficClass::Reconstruction`] requests.
    pub max_reconstruction: usize,
    /// Concurrent [`TrafficClass::Auditor`] requests.
    pub max_auditor: usize,
}

impl AdmissionLimits {
    /// All six caps are required. A cap of `0` is finite and fail-closed
    /// (that budget never admits).
    pub const fn new(
        max_connections: usize,
        max_active_requests: usize,
        max_foreground: usize,
        max_replication: usize,
        max_reconstruction: usize,
        max_auditor: usize,
    ) -> Self {
        Self {
            max_connections,
            max_active_requests,
            max_foreground,
            max_replication,
            max_reconstruction,
            max_auditor,
        }
    }

    /// Map a legacy Swift `max_clients` setting onto `max_active_requests`.
    ///
    /// `max_connections` and the four class caps stay independent: this does
    /// not copy `max_clients` onto `max_connections` and does not substitute
    /// a built-in default.
    pub const fn from_legacy_max_clients(
        max_connections: usize,
        max_clients: usize,
        max_foreground: usize,
        max_replication: usize,
        max_reconstruction: usize,
        max_auditor: usize,
    ) -> Self {
        Self::new(
            max_connections,
            max_clients,
            max_foreground,
            max_replication,
            max_reconstruction,
            max_auditor,
        )
    }

    /// Deprecated name for [`Self::max_active_requests`].
    ///
    /// Not [`Self::max_connections`].
    #[deprecated(
        note = "max_clients is a compatibility alias for max_active_requests; it is not max_connections"
    )]
    pub const fn max_clients(&self) -> usize {
        self.max_active_requests
    }

    /// Per-class cap. Exhaustive over [`TrafficClass`] (no FIFO fallback).
    pub const fn class_limit(&self, class: TrafficClass) -> usize {
        match class {
            TrafficClass::Foreground => self.max_foreground,
            TrafficClass::Replication => self.max_replication,
            TrafficClass::Reconstruction => self.max_reconstruction,
            TrafficClass::Auditor => self.max_auditor,
        }
    }
}

/// Why a try-acquire was rejected. Fail closed: no wait, no overflow slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// [`AdmissionLimits::max_connections`] is exhausted.
    ConnectionsFull,
    /// [`AdmissionLimits::max_active_requests`] is exhausted.
    RequestsFull,
    /// The named class cap is exhausted; other classes are unaffected.
    TrafficClassFull(TrafficClass),
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdmissionError::ConnectionsFull => f.write_str("max_connections reached"),
            AdmissionError::RequestsFull => f.write_str("max_active_requests reached"),
            AdmissionError::TrafficClassFull(class) => {
                write!(f, "{class} traffic class budget reached")
            }
        }
    }
}

impl std::error::Error for AdmissionError {}

/// Independent bounded admission counters.
///
/// Clone shares the same counters (typically one controller per worker
/// process). Try-acquire is lock-free and fail-closed.
#[derive(Clone, Debug)]
pub struct AdmissionController {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    limits: AdmissionLimits,
    connections: Slot,
    requests: Slot,
    classes: [Slot; 4],
}

#[derive(Debug)]
struct Slot {
    max: usize,
    in_use: AtomicUsize,
    rejected: AtomicU64,
}

impl Slot {
    fn new(max: usize) -> Self {
        Self {
            max,
            in_use: AtomicUsize::new(0),
            rejected: AtomicU64::new(0),
        }
    }

    /// Returns false at cap (including a cap of 0). Never blocks.
    fn try_acquire(&self) -> bool {
        let max = self.max;
        if max == 0 {
            return false;
        }
        let mut cur = self.in_use.load(Ordering::Acquire);
        loop {
            if cur >= max {
                return false;
            }
            match self.in_use.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(seen) => cur = seen,
            }
        }
    }

    fn release(&self) {
        let prev = self.in_use.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(prev > 0, "admission slot underflow");
        let _ = prev;
    }

    fn reject(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Acquire)
    }

    fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
}

/// Held connection slot. Drop releases it.
#[derive(Debug)]
#[must_use = "dropping the permit releases the connection slot"]
pub struct ConnectionPermit {
    inner: Option<Arc<Inner>>,
}

/// Held request slot (global active-request counter + one traffic class).
/// Drop releases both.
#[derive(Debug)]
#[must_use = "dropping the permit releases the request and class slots"]
pub struct RequestPermit {
    inner: Option<(Arc<Inner>, TrafficClass)>,
}

impl AdmissionController {
    /// Construct from explicit finite caps. No defaulted budget.
    pub fn new(limits: AdmissionLimits) -> Self {
        Self {
            inner: Arc::new(Inner {
                connections: Slot::new(limits.max_connections),
                requests: Slot::new(limits.max_active_requests),
                classes: [
                    Slot::new(limits.max_foreground),
                    Slot::new(limits.max_replication),
                    Slot::new(limits.max_reconstruction),
                    Slot::new(limits.max_auditor),
                ],
                limits,
            }),
        }
    }

    pub fn limits(&self) -> AdmissionLimits {
        self.inner.limits
    }

    /// Admit one connection. Independent of request / class budgets.
    pub fn try_acquire_connection(&self) -> Result<ConnectionPermit, AdmissionError> {
        if self.inner.connections.try_acquire() {
            Ok(ConnectionPermit {
                inner: Some(Arc::clone(&self.inner)),
            })
        } else {
            self.inner.connections.reject();
            Err(AdmissionError::ConnectionsFull)
        }
    }

    /// Admit one request of `class`.
    ///
    /// Consumes one `max_active_requests` slot and one per-class slot.
    /// Independent of `max_connections`. Either budget full → fail closed
    /// without occupying the other.
    pub fn try_acquire_request(
        &self,
        class: TrafficClass,
    ) -> Result<RequestPermit, AdmissionError> {
        let slot = &self.inner.classes[class.index()];
        if !slot.try_acquire() {
            slot.reject();
            return Err(AdmissionError::TrafficClassFull(class));
        }
        if !self.inner.requests.try_acquire() {
            slot.release();
            self.inner.requests.reject();
            return Err(AdmissionError::RequestsFull);
        }
        Ok(RequestPermit {
            inner: Some((Arc::clone(&self.inner), class)),
        })
    }

    pub fn connections_open(&self) -> usize {
        self.inner.connections.in_use()
    }

    pub fn requests_active(&self) -> usize {
        self.inner.requests.in_use()
    }

    pub fn class_active(&self, class: TrafficClass) -> usize {
        self.inner.classes[class.index()].in_use()
    }

    pub fn rejected_connections(&self) -> u64 {
        self.inner.connections.rejected()
    }

    pub fn rejected_requests(&self) -> u64 {
        self.inner.requests.rejected()
    }

    pub fn rejected_class(&self, class: TrafficClass) -> u64 {
        self.inner.classes[class.index()].rejected()
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.connections.release();
        }
    }
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        if let Some((inner, class)) = self.inner.take() {
            inner.classes[class.index()].release();
            inner.requests.release();
        }
    }
}

impl RequestPermit {
    pub fn class(&self) -> Option<TrafficClass> {
        self.inner.as_ref().map(|(_, class)| *class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread;

    fn limits_independent() -> AdmissionLimits {
        AdmissionLimits::new(
            /* max_connections */ 4, /* max_active_requests */ 4,
            /* foreground */ 2, /* replication */ 2, /* reconstruction */ 2,
            /* auditor */ 2,
        )
    }

    fn controller() -> AdmissionController {
        AdmissionController::new(limits_independent())
    }

    #[test]
    fn construction_requires_all_caps_and_has_no_default() {
        let limits = AdmissionLimits::new(3, 5, 7, 9, 11, 13);
        assert_eq!(limits.max_connections, 3);
        assert_eq!(limits.max_active_requests, 5);
        assert_eq!(limits.class_limit(TrafficClass::Foreground), 7);
        assert_eq!(limits.class_limit(TrafficClass::Replication), 9);
        assert_eq!(limits.class_limit(TrafficClass::Reconstruction), 11);
        assert_eq!(limits.class_limit(TrafficClass::Auditor), 13);
        let ctl = AdmissionController::new(limits);
        assert_eq!(ctl.limits(), limits);
    }

    #[test]
    fn legacy_max_clients_aliases_active_requests_not_connections() {
        // Configured max_clients=1024 is the historical Eventlet default;
        // it must not be copied onto max_connections, and this constructor
        // does not invent 1024 when the caller passes a different value.
        let mapped = AdmissionLimits::from_legacy_max_clients(50, 1024, 8, 4, 4, 2);
        assert_eq!(mapped.max_connections, 50);
        assert_eq!(mapped.max_active_requests, 1024);
        let custom = AdmissionLimits::from_legacy_max_clients(8, 16, 4, 4, 4, 4);
        assert_eq!(custom.max_active_requests, 16);
        assert_ne!(custom.max_connections, custom.max_active_requests);
        #[allow(deprecated)]
        {
            assert_eq!(custom.max_clients(), custom.max_active_requests);
            assert_ne!(custom.max_clients(), custom.max_connections);
        }
    }

    #[test]
    fn reject_when_connections_full() {
        let ctl = controller();
        let a = ctl.try_acquire_connection().unwrap();
        let b = ctl.try_acquire_connection().unwrap();
        let c = ctl.try_acquire_connection().unwrap();
        let d = ctl.try_acquire_connection().unwrap();
        assert_eq!(ctl.connections_open(), 4);
        assert_eq!(
            ctl.try_acquire_connection().unwrap_err(),
            AdmissionError::ConnectionsFull
        );
        assert_eq!(ctl.rejected_connections(), 1);
        drop(d);
        let e = ctl.try_acquire_connection().unwrap();
        assert_eq!(ctl.connections_open(), 4);
        drop((a, b, c, e));
        assert_eq!(ctl.connections_open(), 0);
    }

    #[test]
    fn reject_when_requests_full() {
        let ctl = AdmissionController::new(AdmissionLimits::new(8, 2, 8, 8, 8, 8));
        let a = ctl.try_acquire_request(TrafficClass::Foreground).unwrap();
        let b = ctl.try_acquire_request(TrafficClass::Replication).unwrap();
        assert_eq!(ctl.requests_active(), 2);
        assert_eq!(
            ctl.try_acquire_request(TrafficClass::Auditor).unwrap_err(),
            AdmissionError::RequestsFull
        );
        assert_eq!(ctl.rejected_requests(), 1);
        assert_eq!(ctl.class_active(TrafficClass::Auditor), 0);
        drop((a, b));
        assert_eq!(ctl.requests_active(), 0);
        let _ok = ctl.try_acquire_request(TrafficClass::Auditor).unwrap();
        assert_eq!(ctl.requests_active(), 1);
    }

    #[test]
    fn reject_when_class_full_does_not_consume_global_request() {
        let ctl = controller();
        let a = ctl.try_acquire_request(TrafficClass::Foreground).unwrap();
        let b = ctl.try_acquire_request(TrafficClass::Foreground).unwrap();
        assert_eq!(
            ctl.try_acquire_request(TrafficClass::Foreground)
                .unwrap_err(),
            AdmissionError::TrafficClassFull(TrafficClass::Foreground)
        );
        assert_eq!(ctl.rejected_class(TrafficClass::Foreground), 1);
        assert_eq!(ctl.requests_active(), 2);
        assert_eq!(ctl.class_active(TrafficClass::Foreground), 2);
        drop((a, b));
        assert_eq!(ctl.class_active(TrafficClass::Foreground), 0);
        assert_eq!(ctl.requests_active(), 0);
    }

    #[test]
    fn class_budgets_are_independent_not_shared_fifo() {
        // Global request cap is high enough that only per-class caps bind.
        let ctl = AdmissionController::new(AdmissionLimits::new(16, 16, 2, 2, 2, 2));
        let _fg = [
            ctl.try_acquire_request(TrafficClass::Foreground).unwrap(),
            ctl.try_acquire_request(TrafficClass::Foreground).unwrap(),
        ];
        assert_eq!(
            ctl.try_acquire_request(TrafficClass::Foreground)
                .unwrap_err(),
            AdmissionError::TrafficClassFull(TrafficClass::Foreground)
        );
        // Other classes still admit: filling Foreground is not a global FIFO.
        let repl = ctl.try_acquire_request(TrafficClass::Replication).unwrap();
        let recon = ctl
            .try_acquire_request(TrafficClass::Reconstruction)
            .unwrap();
        let aud = ctl.try_acquire_request(TrafficClass::Auditor).unwrap();
        assert_eq!(ctl.class_active(TrafficClass::Replication), 1);
        assert_eq!(ctl.class_active(TrafficClass::Reconstruction), 1);
        assert_eq!(ctl.class_active(TrafficClass::Auditor), 1);
        assert_eq!(ctl.requests_active(), 5);
        drop((repl, recon, aud));
        assert_eq!(ctl.class_active(TrafficClass::Foreground), 2);
        assert_eq!(ctl.requests_active(), 2);
    }

    #[test]
    fn connections_and_requests_are_independent() {
        let ctl = AdmissionController::new(AdmissionLimits::new(1, 3, 3, 3, 3, 3));
        let conn = ctl.try_acquire_connection().unwrap();
        assert_eq!(
            ctl.try_acquire_connection().unwrap_err(),
            AdmissionError::ConnectionsFull
        );
        // Request budget is a different resource: still admits.
        let req = ctl.try_acquire_request(TrafficClass::Foreground).unwrap();
        assert_eq!(ctl.connections_open(), 1);
        assert_eq!(ctl.requests_active(), 1);
        drop(req);
        let _r1 = ctl.try_acquire_request(TrafficClass::Replication).unwrap();
        let _r2 = ctl
            .try_acquire_request(TrafficClass::Reconstruction)
            .unwrap();
        let _r3 = ctl.try_acquire_request(TrafficClass::Auditor).unwrap();
        assert_eq!(
            ctl.try_acquire_request(TrafficClass::Foreground)
                .unwrap_err(),
            AdmissionError::RequestsFull
        );
        // Connection budget is still the original one slot, not the request cap.
        assert_eq!(ctl.connections_open(), 1);
        drop(conn);
        assert_eq!(ctl.connections_open(), 0);
        let _conn2 = ctl.try_acquire_connection().unwrap();
        assert_eq!(ctl.connections_open(), 1);
        assert_eq!(ctl.requests_active(), 3);
    }

    #[test]
    fn zero_cap_fails_closed() {
        let ctl = AdmissionController::new(AdmissionLimits::new(0, 0, 0, 1, 0, 0));
        assert_eq!(
            ctl.try_acquire_connection().unwrap_err(),
            AdmissionError::ConnectionsFull
        );
        assert_eq!(
            ctl.try_acquire_request(TrafficClass::Foreground)
                .unwrap_err(),
            AdmissionError::TrafficClassFull(TrafficClass::Foreground)
        );
        assert_eq!(
            ctl.try_acquire_request(TrafficClass::Reconstruction)
                .unwrap_err(),
            AdmissionError::TrafficClassFull(TrafficClass::Reconstruction)
        );
        // Replication has cap 1; global requests is 0, so class would take
        // then roll back on the global request budget.
        assert_eq!(
            ctl.try_acquire_request(TrafficClass::Replication)
                .unwrap_err(),
            AdmissionError::RequestsFull
        );
        assert_eq!(ctl.class_active(TrafficClass::Replication), 0);
        assert_eq!(ctl.requests_active(), 0);
    }

    #[test]
    fn drop_releases_both_request_and_class_slots() {
        let ctl = controller();
        {
            let p = ctl.try_acquire_request(TrafficClass::Auditor).unwrap();
            assert_eq!(p.class(), Some(TrafficClass::Auditor));
            assert_eq!(ctl.class_active(TrafficClass::Auditor), 1);
            assert_eq!(ctl.requests_active(), 1);
        }
        assert_eq!(ctl.class_active(TrafficClass::Auditor), 0);
        assert_eq!(ctl.requests_active(), 0);
        let _ok = ctl.try_acquire_request(TrafficClass::Auditor).unwrap();
        assert_eq!(ctl.class_active(TrafficClass::Auditor), 1);
    }

    #[test]
    fn concurrent_try_acquire_never_exceeds_connection_cap() {
        let ctl = AdmissionController::new(AdmissionLimits::new(4, 32, 32, 32, 32, 32));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut joins = Vec::new();
        for _ in 0..8 {
            let ctl = ctl.clone();
            let peak = Arc::clone(&peak);
            joins.push(thread::spawn(move || {
                let mut held = Vec::new();
                for _ in 0..32 {
                    match ctl.try_acquire_connection() {
                        Ok(permit) => {
                            let n = ctl.connections_open();
                            peak.fetch_max(n, Ordering::SeqCst);
                            assert!(n <= 4);
                            held.push(permit);
                        }
                        Err(AdmissionError::ConnectionsFull) => {}
                        Err(other) => panic!("unexpected {other:?}"),
                    }
                }
                drop(held);
            }));
        }
        for join in joins {
            join.join().unwrap();
        }
        assert!(peak.load(Ordering::SeqCst) <= 4);
        assert_eq!(ctl.connections_open(), 0);
        assert!(ctl.rejected_connections() > 0);
    }

    #[test]
    fn concurrent_class_caps_stay_isolated() {
        let ctl = AdmissionController::new(AdmissionLimits::new(64, 64, 3, 5, 1, 2));
        let mut joins = Vec::new();
        for class in TrafficClass::ALL {
            let ctl = ctl.clone();
            joins.push(thread::spawn(move || {
                let mut held = Vec::new();
                for _ in 0..40 {
                    match ctl.try_acquire_request(class) {
                        Ok(p) => held.push(p),
                        Err(AdmissionError::TrafficClassFull(c)) => assert_eq!(c, class),
                        Err(other) => panic!("unexpected {other:?} for {class}"),
                    }
                    assert!(ctl.class_active(class) <= ctl.limits().class_limit(class));
                }
                held
            }));
        }
        let mut all_held = Vec::new();
        for join in joins {
            all_held.extend(join.join().unwrap());
        }
        assert_eq!(ctl.class_active(TrafficClass::Foreground), 3);
        assert_eq!(ctl.class_active(TrafficClass::Replication), 5);
        assert_eq!(ctl.class_active(TrafficClass::Reconstruction), 1);
        assert_eq!(ctl.class_active(TrafficClass::Auditor), 2);
        assert_eq!(ctl.requests_active(), 3 + 5 + 1 + 2);
        drop(all_held);
        assert_eq!(ctl.requests_active(), 0);
    }
}
