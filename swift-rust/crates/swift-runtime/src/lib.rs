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

//! Peregrine concurrency runtime substrate.
//!
//! Connection, request, and traffic-class budgets are independent finite
//! resources — not one global semaphore. Tokio is sealed behind this crate.
//! Filesystem work goes through [`StorageExecutor`] / [`ThreadedPosixIo`].
//! SQLite work goes through [`DbExecutor`]. Both submit finite jobs through
//! [`BlockingDomain`]. Application code must not use `tokio::fs`.
//!
//! This crate does not serve HTTP and does not wrap request handlers.

#![forbid(unsafe_code)]

pub mod admission;
pub mod blocking;
pub mod context;
pub mod db_exec;
pub mod deadline;
pub mod fanout;
pub mod metrics;
pub mod scope;
pub mod storage;
pub mod traffic;

pub use admission::{
    AdmissionController, AdmissionError, AdmissionLimits, ConnectionPermit, RequestPermit,
};
pub use blocking::{
    BlockingDomain, BlockingDomainConfig, BlockingDomainStats, BlockingError, BlockingJob,
    BlockingJoinError, BlockingRunError,
};
pub use context::{DurabilityBarrier, RequestContext, TransId};
pub use db_exec::{DbExecError, DbExecutor, DbExecutorConfig, DbExecutorStats};
pub use deadline::{
    BackendConnectDeadline, BackendReadDeadline, BackendWriteDeadline, BodyIdleDeadline,
    ClientWriteDeadline, DeadlineBudget, DeadlineKind, HeaderDeadline, KeepAliveIdleDeadline,
    ReplicationDeadline, ShutdownDeadline, UploadLifetimeDeadline,
};
pub use fanout::{BackpressureWindow, FanoutError, FanoutGroup, QuorumTracker, SharedWindow};
pub use metrics::{
    text_has_forbidden_labels, CancelReason, ConcurrencyMetrics, ConcurrencySnapshot,
    RuntimeTaskGuard, REQUIRED_METRIC_NAMES,
};
pub use scope::{
    CancellationToken, ScopeJoinError, ScopedTask, SpawnError, TaskCancelled, TaskScope,
    DEFAULT_SCOPE_BOUND,
};
pub use storage::{
    DeviceId, DeviceIoLimits, DeviceIoPermit, StorageError, StorageExecutor, StorageExecutorConfig,
    StorageStats, ThreadedPosixIo,
};
pub use traffic::TrafficClass;
