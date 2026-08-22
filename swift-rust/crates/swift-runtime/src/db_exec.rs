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

//! SQLite execution domain (AGENTS.md §15, L2, L3).
//!
//! Account/container work does not share the object [`crate::storage::StorageExecutor`]
//! pool. Each shard has `thread_cap = 1` and a bounded mailbox, so the same
//! DB identity is serialized and rusqlite runs on the executor, not on an
//! HTTP task. Different DBs hash to different shards and run in parallel.
//!
//! Connections are owned by the shard (finite cap). This module does not
//! use `tokio::fs` and does not wrap an HTTP handler.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::blocking::{
    BlockingDomain, BlockingDomainStats, BlockingError, BlockingJoinError, BlockingRunError,
};

/// Caps required to construct a [`DbExecutor`].
///
/// `shard_count` and `mailbox_bound` must be ≥ 1. `max_connections_per_shard`
/// of `0` is fail-closed (no connection is opened). There is no `Default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbExecutorConfig {
    pub shard_count: usize,
    pub mailbox_bound: usize,
    pub max_connections_per_shard: usize,
}

impl DbExecutorConfig {
    pub const fn new(
        shard_count: usize,
        mailbox_bound: usize,
        max_connections_per_shard: usize,
    ) -> Result<Self, DbExecError> {
        if shard_count == 0 {
            return Err(DbExecError::InvalidConfig {
                reason: "shard_count must be >= 1",
            });
        }
        if mailbox_bound == 0 {
            return Err(DbExecError::InvalidConfig {
                reason: "mailbox_bound must be >= 1",
            });
        }
        Ok(Self {
            shard_count,
            mailbox_bound,
            max_connections_per_shard,
        })
    }
}

/// Why submit / construction / connection open failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbExecError {
    InvalidConfig {
        reason: &'static str,
    },
    NoRuntime,
    /// Shard mailbox is at `mailbox_bound`. The closure did not run.
    MailboxFull {
        shard: usize,
        mailbox_bound: usize,
        queued: usize,
        active: usize,
    },
    /// Opening another distinct DB on this shard would exceed the finite
    /// connection cap. Existing identities still run.
    ConnectionCap {
        shard: usize,
        max_connections: usize,
    },
    Shutdown,
    OpenFailed {
        message: String,
    },
    Join(BlockingJoinError),
}

impl fmt::Display for DbExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbExecError::InvalidConfig { reason } => {
                write!(f, "invalid DbExecutor config: {reason}")
            }
            DbExecError::NoRuntime => f.write_str("DbExecutor requires a Tokio runtime"),
            DbExecError::MailboxFull {
                shard,
                mailbox_bound,
                queued,
                active,
            } => write!(
                f,
                "db executor mailbox full (shard={shard}, mailbox_bound={mailbox_bound}, queued={queued}, active={active})"
            ),
            DbExecError::ConnectionCap {
                shard,
                max_connections,
            } => write!(
                f,
                "db executor connection cap reached (shard={shard}, max_connections={max_connections})"
            ),
            DbExecError::Shutdown => f.write_str("db executor shutdown"),
            DbExecError::OpenFailed { message } => {
                write!(f, "db executor failed to open sqlite: {message}")
            }
            DbExecError::Join(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for DbExecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DbExecError::Join(err) => Some(err),
            _ => None,
        }
    }
}

impl From<BlockingError> for DbExecError {
    fn from(err: BlockingError) -> Self {
        match err {
            BlockingError::InvalidConfig { reason } => DbExecError::InvalidConfig { reason },
            BlockingError::NoRuntime => DbExecError::NoRuntime,
            BlockingError::QueueFull {
                queue_bound,
                queued,
                active,
                ..
            } => DbExecError::MailboxFull {
                shard: 0,
                mailbox_bound: queue_bound,
                queued,
                active,
            },
            BlockingError::Shutdown => DbExecError::Shutdown,
        }
    }
}

/// Aggregated counters across shards. No db-path labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbExecutorStats {
    pub shard_count: usize,
    pub mailbox_bound: usize,
    pub max_connections_per_shard: usize,
    pub ops_active: usize,
    pub queued: usize,
    pub rejected_total: u64,
    pub completed_total: u64,
    pub connections_open: usize,
    /// Sum of shard BlockingDomain queue-wait nanoseconds for started jobs.
    pub wait_ns_total: u64,
    pub started_total: u64,
}

enum ShardJob<T> {
    Done(T),
    OpenFailed(String),
    ConnectionCap,
}

struct Shard {
    domain: BlockingDomain,
    connections: Arc<Mutex<HashMap<PathBuf, Connection>>>,
    max_connections: usize,
}

/// Sharded rusqlite executor. Same path → same shard → serial. Distinct
/// paths may run in parallel on different shards.
#[derive(Clone)]
pub struct DbExecutor {
    shards: Arc<Vec<Shard>>,
    mailbox_bound: usize,
    max_connections_per_shard: usize,
}

impl DbExecutor {
    pub fn new(config: DbExecutorConfig) -> Result<Self, DbExecError> {
        let config = DbExecutorConfig::new(
            config.shard_count,
            config.mailbox_bound,
            config.max_connections_per_shard,
        )?;
        let mut shards = Vec::with_capacity(config.shard_count);
        for _ in 0..config.shard_count {
            // thread_cap = 1: same DB identity is serialized on this mailbox.
            let domain = BlockingDomain::with_bounds(1, config.mailbox_bound)?;
            shards.push(Shard {
                domain,
                connections: Arc::new(Mutex::new(HashMap::new())),
                max_connections: config.max_connections_per_shard,
            });
        }
        Ok(Self {
            shards: Arc::new(shards),
            mailbox_bound: config.mailbox_bound,
            max_connections_per_shard: config.max_connections_per_shard,
        })
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    pub fn mailbox_bound(&self) -> usize {
        self.mailbox_bound
    }

    /// `hash(path) % shard_count`. Identity is the path as given (not
    /// canonicalized).
    pub fn shard_index(&self, db_path: impl AsRef<Path>) -> usize {
        shard_index(db_path.as_ref(), self.shards.len())
    }

    pub fn stats(&self) -> DbExecutorStats {
        let mut ops_active = 0usize;
        let mut queued = 0usize;
        let mut rejected_total = 0u64;
        let mut completed_total = 0u64;
        let mut connections_open = 0usize;
        let mut wait_ns_total = 0u64;
        let mut started_total = 0u64;
        for shard in self.shards.iter() {
            let s: BlockingDomainStats = shard.domain.stats();
            ops_active = ops_active.saturating_add(s.active);
            queued = queued.saturating_add(s.queued);
            rejected_total = rejected_total.saturating_add(s.rejected_total);
            completed_total = completed_total.saturating_add(s.completed_total);
            wait_ns_total = wait_ns_total.saturating_add(s.wait_ns_total);
            started_total = started_total.saturating_add(s.started_total);
            connections_open = connections_open.saturating_add(
                shard
                    .connections
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .len(),
            );
        }
        DbExecutorStats {
            shard_count: self.shards.len(),
            mailbox_bound: self.mailbox_bound,
            max_connections_per_shard: self.max_connections_per_shard,
            ops_active,
            queued,
            rejected_total,
            completed_total,
            connections_open,
            wait_ns_total,
            started_total,
        }
    }

    /// Run rusqlite `work` on the shard that owns `db_path`.
    ///
    /// The shard opens (or reuses) a [`Connection`] for that identity. Work
    /// runs on the blocking executor, never on the caller's HTTP/reactor
    /// task.
    pub async fn run<F, T>(&self, db_path: impl AsRef<Path>, work: F) -> Result<T, DbExecError>
    where
        F: FnOnce(&mut Connection) -> T + Send + 'static,
        T: Send + 'static,
    {
        let path = db_path.as_ref().to_path_buf();
        let shard_i = self.shard_index(&path);
        let shard = &self.shards[shard_i];
        let connections = Arc::clone(&shard.connections);
        let max_connections = shard.max_connections;
        let job = shard.domain.run(move || {
            // Take the connection out of the map so rusqlite work does not
            // hold the shard mutex (stats / other identities must not block
            // on a long SQL op). thread_cap=1 keeps this exclusive.
            let mut conn = {
                let mut map = connections.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(conn) = map.remove(&path) {
                    conn
                } else if map.len() >= max_connections {
                    return ShardJob::ConnectionCap;
                } else {
                    match Connection::open(&path) {
                        Ok(conn) => conn,
                        Err(err) => return ShardJob::OpenFailed(err.to_string()),
                    }
                }
            };
            let value = work(&mut conn);
            connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(path, conn);
            ShardJob::Done(value)
        });
        match job.await {
            Ok(ShardJob::Done(value)) => Ok(value),
            Ok(ShardJob::OpenFailed(message)) => Err(DbExecError::OpenFailed { message }),
            Ok(ShardJob::ConnectionCap) => Err(DbExecError::ConnectionCap {
                shard: shard_i,
                max_connections,
            }),
            Err(BlockingRunError::Submit(BlockingError::QueueFull {
                queue_bound,
                queued,
                active,
                ..
            })) => Err(DbExecError::MailboxFull {
                shard: shard_i,
                mailbox_bound: queue_bound,
                queued,
                active,
            }),
            Err(BlockingRunError::Submit(err)) => Err(err.into()),
            Err(BlockingRunError::Join(err)) => Err(DbExecError::Join(err)),
        }
    }

    /// Run a finite closure on the shard mailbox **without** using the
    /// shard-owned [`Connection`].
    ///
    /// Production brokers (`AccountBroker`, `ContainerBroker`) open their
    /// own rusqlite connection. They still must execute on this domain so
    /// SQLite is not on an HTTP/reactor task. Same path → same shard →
    /// serial with [`Self::run`].
    pub async fn run_on_shard<F, T>(
        &self,
        db_path: impl AsRef<Path>,
        work: F,
    ) -> Result<T, DbExecError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let shard_i = self.shard_index(db_path.as_ref());
        let shard = &self.shards[shard_i];
        match shard.domain.run(work).await {
            Ok(value) => Ok(value),
            Err(BlockingRunError::Submit(BlockingError::QueueFull {
                queue_bound,
                queued,
                active,
                ..
            })) => Err(DbExecError::MailboxFull {
                shard: shard_i,
                mailbox_bound: queue_bound,
                queued,
                active,
            }),
            Err(BlockingRunError::Submit(err)) => Err(err.into()),
            Err(BlockingRunError::Join(err)) => Err(DbExecError::Join(err)),
        }
    }
}

fn shard_index(path: &Path, n: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    (hasher.finish() as usize) % n
}

impl fmt::Debug for DbExecutor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbExecutor")
            .field("stats", &self.stats())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::mpsc as std_mpsc;
    use std::sync::Barrier;
    use std::time::{Duration, Instant};

    async fn wait_until(pred: impl Fn() -> bool) {
        let start = Instant::now();
        loop {
            if pred() {
                return;
            }
            if start.elapsed() > Duration::from_secs(2) {
                panic!("timeout waiting for db-executor condition");
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    fn tmpdir() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "peregrine-dbexec-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn paths_distinct_shards(exec: &DbExecutor, dir: &Path) -> (PathBuf, PathBuf) {
        let a = dir.join("a.db");
        let sa = exec.shard_index(&a);
        for i in 0..10_000u32 {
            let b = dir.join(format!("b{i}.db"));
            if exec.shard_index(&b) != sa {
                return (a, b);
            }
        }
        panic!("could not find two paths on different shards");
    }

    #[test]
    fn rejects_zero_shard_or_mailbox() {
        assert!(matches!(
            DbExecutorConfig::new(0, 1, 1),
            Err(DbExecError::InvalidConfig { .. })
        ));
        assert!(matches!(
            DbExecutorConfig::new(1, 0, 1),
            Err(DbExecError::InvalidConfig { .. })
        ));
    }

    #[tokio::test]
    async fn same_path_same_shard() {
        let exec = DbExecutor::new(DbExecutorConfig::new(4, 8, 8).unwrap()).unwrap();
        let p = PathBuf::from("/tmp/a.db");
        assert_eq!(exec.shard_index(&p), exec.shard_index(&p));
        assert_eq!(exec.shard_index(&p), shard_index(&p, 4));
    }

    #[tokio::test]
    async fn rusqlite_runs_on_executor_not_caller() {
        let exec = DbExecutor::new(DbExecutorConfig::new(2, 8, 8).unwrap()).unwrap();
        let dir = tmpdir();
        let path = dir.join("acct.db");
        let caller = std::thread::current().id();
        let io_thread = exec
            .run(path, move |conn| {
                conn.execute_batch("CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (7);")
                    .unwrap();
                let v: i64 = conn
                    .query_row("SELECT v FROM t", [], |row| row.get(0))
                    .unwrap();
                (std::thread::current().id(), v)
            })
            .await
            .unwrap();
        assert_ne!(
            io_thread.0, caller,
            "rusqlite must not run on the HTTP/reactor task"
        );
        assert_eq!(io_thread.1, 7);
        assert_eq!(exec.stats().completed_total, 1);
        assert_eq!(exec.stats().connections_open, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn shard_owns_connection_state() {
        let exec = DbExecutor::new(DbExecutorConfig::new(1, 4, 4).unwrap()).unwrap();
        let dir = tmpdir();
        let path = dir.join("owned.db");
        exec.run(path.clone(), |conn| {
            conn.execute_batch(
                "CREATE TABLE t (v INTEGER); \
                 CREATE TEMP TABLE mem (v INTEGER); \
                 INSERT INTO mem VALUES (42);",
            )
            .unwrap();
        })
        .await
        .unwrap();
        let v = exec
            .run(path, |conn| {
                conn.query_row("SELECT v FROM mem", [], |row| row.get::<_, i64>(0))
                    .unwrap()
            })
            .await
            .unwrap();
        assert_eq!(
            v, 42,
            "TEMP table survives only if the shard owns the Connection"
        );
        assert_eq!(exec.stats().connections_open, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn same_db_is_serialized() {
        let exec = DbExecutor::new(DbExecutorConfig::new(1, 8, 4).unwrap()).unwrap();
        let dir = tmpdir();
        let path = dir.join("serial.db");
        let current = Arc::new(AtomicUsize::new(0));
        let max = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = std_mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std_mpsc::sync_channel::<()>(1);

        let exec1 = exec.clone();
        let path1 = path.clone();
        let current1 = Arc::clone(&current);
        let max1 = Arc::clone(&max);
        let job1 = tokio::spawn(async move {
            exec1
                .run(path1, move |conn| {
                    conn.execute_batch("CREATE TABLE IF NOT EXISTS t (v INTEGER)")
                        .unwrap();
                    let n = current1.fetch_add(1, Ordering::SeqCst) + 1;
                    max1.fetch_max(n, Ordering::SeqCst);
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    current1.fetch_sub(1, Ordering::SeqCst);
                    1i32
                })
                .await
        });
        wait_until(|| entered_rx.try_recv().is_ok()).await;

        let started = Arc::new(AtomicBool::new(false));
        let started2 = Arc::clone(&started);
        let current2 = Arc::clone(&current);
        let max2 = Arc::clone(&max);
        let exec2 = exec.clone();
        let job2 = tokio::spawn(async move {
            exec2
                .run(path, move |conn| {
                    started2.store(true, Ordering::SeqCst);
                    let n = current2.fetch_add(1, Ordering::SeqCst) + 1;
                    max2.fetch_max(n, Ordering::SeqCst);
                    conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
                    current2.fetch_sub(1, Ordering::SeqCst);
                    2i32
                })
                .await
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !started.load(Ordering::SeqCst),
            "second op on the same DB must wait for the shard mailbox"
        );

        tokio::time::timeout(
            Duration::from_millis(200),
            tokio::time::sleep(Duration::from_millis(5)),
        )
        .await
        .expect("reactor must progress while sqlite work occupies the shard");

        release_tx.send(()).unwrap();
        assert_eq!(job1.await.unwrap().unwrap(), 1);
        assert_eq!(job2.await.unwrap().unwrap(), 2);
        assert_eq!(max.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn different_shards_run_in_parallel() {
        let exec = DbExecutor::new(DbExecutorConfig::new(8, 8, 8).unwrap()).unwrap();
        let dir = tmpdir();
        let (p1, p2) = paths_distinct_shards(&exec, &dir);
        assert_ne!(exec.shard_index(&p1), exec.shard_index(&p2));
        let barrier = Arc::new(Barrier::new(2));

        let exec_a = exec.clone();
        let bar_a = Arc::clone(&barrier);
        let a = tokio::spawn(async move {
            exec_a
                .run(p1, move |conn| {
                    conn.execute_batch("CREATE TABLE t (v INTEGER)").unwrap();
                    bar_a.wait();
                    1i32
                })
                .await
        });
        let exec_b = exec.clone();
        let bar_b = Arc::clone(&barrier);
        let b = tokio::spawn(async move {
            exec_b
                .run(p2, move |conn| {
                    conn.execute_batch("CREATE TABLE t (v INTEGER)").unwrap();
                    bar_b.wait();
                    2i32
                })
                .await
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            assert_eq!(a.await.unwrap().unwrap(), 1);
            assert_eq!(b.await.unwrap().unwrap(), 2);
        })
        .await
        .expect("distinct shards must not serialize (barrier deadlock means one mailbox)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn mailbox_full_fails_closed() {
        let exec = DbExecutor::new(DbExecutorConfig::new(1, 1, 4).unwrap()).unwrap();
        let dir = tmpdir();
        let path = dir.join("q.db");
        let (entered_tx, entered_rx) = std_mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std_mpsc::sync_channel::<()>(1);

        let exec1 = exec.clone();
        let path1 = path.clone();
        let job1 = tokio::spawn(async move {
            exec1
                .run(path1, move |conn| {
                    conn.execute_batch("CREATE TABLE t (v INTEGER)").unwrap();
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    1i32
                })
                .await
        });
        wait_until(|| entered_rx.try_recv().is_ok()).await;
        wait_until(|| exec.stats().ops_active == 1).await;

        let exec2 = exec.clone();
        let path2 = path.clone();
        let job2 = tokio::spawn(async move { exec2.run(path2, |_conn| 2i32).await });
        wait_until(|| exec.stats().queued == 1).await;

        let ran = Arc::new(AtomicBool::new(false));
        let ran_flag = Arc::clone(&ran);
        let err = exec
            .run(path, move |_conn| {
                ran_flag.store(true, Ordering::SeqCst);
                3i32
            })
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                DbExecError::MailboxFull {
                    shard: 0,
                    mailbox_bound: 1,
                    queued: 1,
                    active: 1,
                }
            ),
            "unexpected reject: {err:?}"
        );
        assert!(
            !ran.load(Ordering::SeqCst),
            "rejected rusqlite work must not run"
        );
        assert_eq!(exec.stats().rejected_total, 1);

        release_tx.send(()).unwrap();
        assert_eq!(job1.await.unwrap().unwrap(), 1);
        assert_eq!(job2.await.unwrap().unwrap(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn connection_cap_fails_closed_on_new_identity() {
        let exec = DbExecutor::new(DbExecutorConfig::new(1, 4, 1).unwrap()).unwrap();
        let dir = tmpdir();
        let a = dir.join("a.db");
        let b = dir.join("b.db");
        exec.run(a.clone(), |conn| {
            conn.execute_batch("CREATE TABLE t (v INTEGER)").unwrap();
        })
        .await
        .unwrap();
        let err = exec.run(b, |_conn| ()).await.unwrap_err();
        assert!(
            matches!(
                err,
                DbExecError::ConnectionCap {
                    shard: 0,
                    max_connections: 1,
                }
            ),
            "unexpected: {err:?}"
        );
        exec.run(a, |conn| {
            conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
        })
        .await
        .unwrap();
        assert_eq!(exec.stats().connections_open, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn zero_connection_cap_never_opens() {
        let exec = DbExecutor::new(DbExecutorConfig::new(1, 1, 0).unwrap()).unwrap();
        let dir = tmpdir();
        let err = exec.run(dir.join("x.db"), |_conn| ()).await.unwrap_err();
        assert!(matches!(
            err,
            DbExecError::ConnectionCap {
                max_connections: 0,
                ..
            }
        ));
        assert_eq!(exec.stats().connections_open, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
