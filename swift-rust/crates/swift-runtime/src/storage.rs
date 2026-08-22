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

//! Object storage execution domain (AGENTS.md §10–§12, L2, L3, L7).
//!
//! Production backend is [`ThreadedPosixIo`]: each `write` / `write_at` /
//! `sync_all` / `rename` is one finite POSIX operation submitted through
//! [`BlockingDomain`]. The domain queue is fail-closed. This module does
//! not wrap an HTTP handler and does not use `tokio::fs`.
//!
//! [`StorageExecutor`] adds independent global and per-device budgets,
//! split by [`TrafficClass`]. A PUT is a sequence of these ops, never one
//! blocking task that also waits on the client.

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::blocking::{
    BlockingDomain, BlockingDomainConfig, BlockingDomainStats, BlockingError, BlockingJoinError,
    BlockingRunError,
};
use crate::traffic::TrafficClass;

/// Disk identity for per-device IO budget (e.g. `sda`). Not a path.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceId(Arc<str>);

impl DeviceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(Arc::from(id.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for DeviceId {
    fn from(id: &str) -> Self {
        Self::new(id)
    }
}

impl From<String> for DeviceId {
    fn from(id: String) -> Self {
        Self::new(id)
    }
}

/// Per-device inflight caps. Independent of [`BlockingDomain`] width.
///
/// `max_ops` is the device total. The four class caps are not a shared FIFO
/// (AGENTS.md L8, §12). A cap of `0` is fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceIoLimits {
    pub max_ops: usize,
    pub max_foreground: usize,
    pub max_replication: usize,
    pub max_reconstruction: usize,
    pub max_auditor: usize,
}

impl DeviceIoLimits {
    pub const fn new(
        max_ops: usize,
        max_foreground: usize,
        max_replication: usize,
        max_reconstruction: usize,
        max_auditor: usize,
    ) -> Self {
        Self {
            max_ops,
            max_foreground,
            max_replication,
            max_reconstruction,
            max_auditor,
        }
    }

    pub const fn class_limit(self, class: TrafficClass) -> usize {
        match class {
            TrafficClass::Foreground => self.max_foreground,
            TrafficClass::Replication => self.max_replication,
            TrafficClass::Reconstruction => self.max_reconstruction,
            TrafficClass::Auditor => self.max_auditor,
        }
    }
}

/// Caps required to construct a [`StorageExecutor`].
///
/// `thread_cap` and `queue_bound` are the [`BlockingDomain`] bounds. There
/// is no `Default`: a missing cap must not become Tokio's blocking-pool
/// ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageExecutorConfig {
    pub thread_cap: usize,
    pub queue_bound: usize,
    pub device: DeviceIoLimits,
}

impl StorageExecutorConfig {
    pub const fn new(
        thread_cap: usize,
        queue_bound: usize,
        device: DeviceIoLimits,
    ) -> Result<Self, StorageError> {
        if thread_cap == 0 {
            return Err(StorageError::InvalidConfig {
                reason: "thread_cap must be >= 1",
            });
        }
        if queue_bound == 0 {
            return Err(StorageError::InvalidConfig {
                reason: "queue_bound must be >= 1",
            });
        }
        Ok(Self {
            thread_cap,
            queue_bound,
            device,
        })
    }
}

/// Why a storage op failed. Fail-closed variants mean the POSIX op did not
/// run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    InvalidConfig {
        reason: &'static str,
    },
    NoRuntime,
    QueueFull {
        thread_cap: usize,
        queue_bound: usize,
        queued: usize,
        active: usize,
    },
    /// Per-device total inflight cap exhausted.
    DeviceBusy {
        device: DeviceId,
        active: usize,
        cap: usize,
    },
    /// Per-device class cap exhausted; other classes on the device are
    /// unaffected.
    DeviceClassBusy {
        device: DeviceId,
        class: TrafficClass,
        active: usize,
        cap: usize,
    },
    Shutdown,
    Io {
        kind: io::ErrorKind,
        message: String,
    },
    Join(BlockingJoinError),
}

impl StorageError {
    fn from_io(err: io::Error) -> Self {
        Self::Io {
            kind: err.kind(),
            message: err.to_string(),
        }
    }
}

impl From<BlockingError> for StorageError {
    fn from(err: BlockingError) -> Self {
        match err {
            BlockingError::InvalidConfig { reason } => StorageError::InvalidConfig { reason },
            BlockingError::NoRuntime => StorageError::NoRuntime,
            BlockingError::QueueFull {
                thread_cap,
                queue_bound,
                queued,
                active,
            } => StorageError::QueueFull {
                thread_cap,
                queue_bound,
                queued,
                active,
            },
            BlockingError::Shutdown => StorageError::Shutdown,
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::InvalidConfig { reason } => {
                write!(f, "invalid StorageExecutor config: {reason}")
            }
            StorageError::NoRuntime => f.write_str("StorageExecutor requires a Tokio runtime"),
            StorageError::QueueFull {
                thread_cap,
                queue_bound,
                queued,
                active,
            } => write!(
                f,
                "storage executor queue full (thread_cap={thread_cap}, queue_bound={queue_bound}, queued={queued}, active={active})"
            ),
            StorageError::DeviceBusy {
                device,
                active,
                cap,
            } => write!(f, "device {device} busy (active={active}, cap={cap})"),
            StorageError::DeviceClassBusy {
                device,
                class,
                active,
                cap,
            } => write!(
                f,
                "device {device} {class} busy (active={active}, cap={cap})"
            ),
            StorageError::Shutdown => f.write_str("storage executor shutdown"),
            StorageError::Io { kind, message } => write!(f, "storage io error ({kind:?}): {message}"),
            StorageError::Join(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Join(err) => Some(err),
            _ => None,
        }
    }
}

/// Snapshot of executor + domain counters. No path / trans-id labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageStats {
    pub blocking: BlockingDomainStats,
    pub device_ops_active: usize,
    pub device_rejected_total: u64,
}

/// Production POSIX backend. Each method is one finite op on
/// [`BlockingDomain`] (AGENTS.md §10, §22). Not `tokio::fs`.
#[derive(Clone)]
pub struct ThreadedPosixIo {
    domain: BlockingDomain,
}

impl ThreadedPosixIo {
    pub fn new(config: BlockingDomainConfig) -> Result<Self, StorageError> {
        Ok(Self {
            domain: BlockingDomain::new(config)?,
        })
    }

    pub fn with_bounds(thread_cap: usize, queue_bound: usize) -> Result<Self, StorageError> {
        Ok(Self {
            domain: BlockingDomain::with_bounds(thread_cap, queue_bound)?,
        })
    }

    pub fn from_domain(domain: BlockingDomain) -> Self {
        Self { domain }
    }

    pub fn stats(&self) -> BlockingDomainStats {
        self.domain.stats()
    }

    /// Create/truncate `path` and write `bytes`. Does not `sync_all`.
    pub async fn write(&self, path: PathBuf, bytes: Vec<u8>) -> Result<(), StorageError> {
        self.run_op(move || posix_write(&path, &bytes)).await
    }

    /// `pwrite`-style chunk. Creates the file if missing; does not truncate
    /// and does not `sync_all`.
    pub async fn write_at(
        &self,
        path: PathBuf,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<usize, StorageError> {
        self.run_op(move || posix_write_at(&path, offset, &bytes))
            .await
    }

    /// `fsync` data + metadata for `path` (file or directory).
    pub async fn sync_all(&self, path: PathBuf) -> Result<(), StorageError> {
        self.run_op(move || posix_sync_all(&path)).await
    }

    /// POSIX `rename`. Directory durability is a separate [`Self::sync_all`].
    pub async fn rename(&self, from: PathBuf, to: PathBuf) -> Result<(), StorageError> {
        self.run_op(move || posix_rename(&from, &to)).await
    }

    /// One finite durability closure (xattr + `sync_all` + rename).
    ///
    /// For `DiskFileWriter::put` / commit-shield work. Not a client-socket
    /// wait and not a whole HTTP `Handler`.
    pub async fn run_finite<F, T>(&self, f: F) -> Result<T, StorageError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        match self.domain.run(f).await {
            Ok(value) => Ok(value),
            Err(BlockingRunError::Submit(err)) => Err(err.into()),
            Err(BlockingRunError::Join(err)) => Err(StorageError::Join(err)),
        }
    }

    async fn run_op<T, F>(&self, f: F) -> Result<T, StorageError>
    where
        F: FnOnce() -> io::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        match self.domain.run(f).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(StorageError::from_io(err)),
            Err(BlockingRunError::Submit(err)) => Err(err.into()),
            Err(BlockingRunError::Join(err)) => Err(StorageError::Join(err)),
        }
    }
}

fn posix_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    std::fs::write(path, bytes)
}

fn posix_write_at(path: &Path, offset: u64, bytes: &[u8]) -> io::Result<usize> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    Ok(bytes.len())
}

fn posix_sync_all(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn posix_rename(from: &Path, to: &Path) -> io::Result<()> {
    std::fs::rename(from, to)
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
        debug_assert!(prev > 0, "device IO slot underflow");
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

#[derive(Debug)]
struct DeviceSlots {
    total: Slot,
    classes: [Slot; 4],
}

impl DeviceSlots {
    fn new(limits: DeviceIoLimits) -> Self {
        Self {
            total: Slot::new(limits.max_ops),
            classes: [
                Slot::new(limits.max_foreground),
                Slot::new(limits.max_replication),
                Slot::new(limits.max_reconstruction),
                Slot::new(limits.max_auditor),
            ],
        }
    }
}

/// Held per-device inflight slot (device total + one traffic class).
///
/// Drop releases both. Production ops hold this across the POSIX job.
#[derive(Debug)]
#[must_use = "dropping the permit releases the device IO slot"]
pub struct DeviceIoPermit {
    slots: Option<(Arc<DeviceSlots>, TrafficClass)>,
}

impl DeviceIoPermit {
    pub fn class(&self) -> Option<TrafficClass> {
        self.slots.as_ref().map(|(_, class)| *class)
    }
}

impl Drop for DeviceIoPermit {
    fn drop(&mut self) {
        if let Some((slots, class)) = self.slots.take() {
            slots.classes[class.index()].release();
            slots.total.release();
        }
    }
}

/// Device-scheduled facade over [`ThreadedPosixIo`].
///
/// Global bound = BlockingDomain `thread_cap` + `queue_bound`. Device bound
/// is independent. Fail closed on either.
#[derive(Clone)]
pub struct StorageExecutor {
    io: ThreadedPosixIo,
    devices: Arc<Mutex<HashMap<DeviceId, Arc<DeviceSlots>>>>,
    limits: DeviceIoLimits,
}

impl StorageExecutor {
    pub fn new(config: StorageExecutorConfig) -> Result<Self, StorageError> {
        let config =
            StorageExecutorConfig::new(config.thread_cap, config.queue_bound, config.device)?;
        let io = ThreadedPosixIo::with_bounds(config.thread_cap, config.queue_bound)?;
        Ok(Self::with_posix(io, config.device))
    }

    pub fn with_posix(io: ThreadedPosixIo, device: DeviceIoLimits) -> Self {
        Self {
            io,
            devices: Arc::new(Mutex::new(HashMap::new())),
            limits: device,
        }
    }

    pub fn posix(&self) -> &ThreadedPosixIo {
        &self.io
    }

    pub fn limits(&self) -> DeviceIoLimits {
        self.limits
    }

    pub fn stats(&self) -> StorageStats {
        let blocking = self.io.stats();
        let devices = self.devices.lock().unwrap_or_else(|e| e.into_inner());
        let mut device_ops_active = 0usize;
        let mut device_rejected_total = 0u64;
        for slots in devices.values() {
            device_ops_active = device_ops_active.saturating_add(slots.total.in_use());
            device_rejected_total = device_rejected_total
                .saturating_add(slots.total.rejected())
                .saturating_add(slots.classes.iter().map(|s| s.rejected()).sum::<u64>());
        }
        StorageStats {
            blocking,
            device_ops_active,
            device_rejected_total,
        }
    }

    /// Admit one in-flight op on `device` for `class`. Never waits.
    pub fn try_acquire_device(
        &self,
        device: DeviceId,
        class: TrafficClass,
    ) -> Result<DeviceIoPermit, StorageError> {
        let slots = {
            let mut map = self.devices.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(
                map.entry(device.clone())
                    .or_insert_with(|| Arc::new(DeviceSlots::new(self.limits))),
            )
        };
        let class_slot = &slots.classes[class.index()];
        if !class_slot.try_acquire() {
            class_slot.reject();
            return Err(StorageError::DeviceClassBusy {
                device,
                class,
                active: class_slot.in_use(),
                cap: self.limits.class_limit(class),
            });
        }
        if !slots.total.try_acquire() {
            class_slot.release();
            slots.total.reject();
            return Err(StorageError::DeviceBusy {
                device,
                active: slots.total.in_use(),
                cap: self.limits.max_ops,
            });
        }
        Ok(DeviceIoPermit {
            slots: Some((slots, class)),
        })
    }

    pub async fn write(
        &self,
        device: DeviceId,
        class: TrafficClass,
        path: PathBuf,
        bytes: Vec<u8>,
    ) -> Result<(), StorageError> {
        let _permit = self.try_acquire_device(device, class)?;
        self.io.write(path, bytes).await
    }

    pub async fn write_at(
        &self,
        device: DeviceId,
        class: TrafficClass,
        path: PathBuf,
        offset: u64,
        bytes: Vec<u8>,
    ) -> Result<usize, StorageError> {
        let _permit = self.try_acquire_device(device, class)?;
        self.io.write_at(path, offset, bytes).await
    }

    pub async fn sync_all(
        &self,
        device: DeviceId,
        class: TrafficClass,
        path: PathBuf,
    ) -> Result<(), StorageError> {
        let _permit = self.try_acquire_device(device, class)?;
        self.io.sync_all(path).await
    }

    pub async fn rename(
        &self,
        device: DeviceId,
        class: TrafficClass,
        from: PathBuf,
        to: PathBuf,
    ) -> Result<(), StorageError> {
        let _permit = self.try_acquire_device(device, class)?;
        self.io.rename(from, to).await
    }

    /// Device-admitted durability closure. The permit is held until `f`
    /// returns on the blocking domain.
    pub async fn run_finite<F, T>(
        &self,
        device: DeviceId,
        class: TrafficClass,
        f: F,
    ) -> Result<T, StorageError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let _permit = self.try_acquire_device(device, class)?;
        self.io.run_finite(f).await
    }
}

impl fmt::Debug for StorageExecutor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageExecutor")
            .field("stats", &self.stats())
            .field("device_limits", &self.limits)
            .finish()
    }
}

impl fmt::Debug for ThreadedPosixIo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreadedPosixIo")
            .field("stats", &self.stats())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc as std_mpsc;
    use std::time::{Duration, Instant};

    async fn wait_until(pred: impl Fn() -> bool) {
        let start = Instant::now();
        loop {
            if pred() {
                return;
            }
            if start.elapsed() > Duration::from_secs(2) {
                panic!("timeout waiting for storage-executor condition");
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    fn tmpdir() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "peregrine-storage-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn limits_open() -> DeviceIoLimits {
        DeviceIoLimits::new(8, 8, 8, 8, 8)
    }

    fn exec_open() -> StorageExecutor {
        StorageExecutor::new(StorageExecutorConfig::new(2, 8, limits_open()).unwrap()).unwrap()
    }

    fn sda() -> DeviceId {
        DeviceId::new("sda")
    }

    fn sdb() -> DeviceId {
        DeviceId::new("sdb")
    }

    #[test]
    fn rejects_zero_domain_bounds() {
        assert!(matches!(
            StorageExecutorConfig::new(0, 1, limits_open()),
            Err(StorageError::InvalidConfig { .. })
        ));
        assert!(matches!(
            StorageExecutorConfig::new(1, 0, limits_open()),
            Err(StorageError::InvalidConfig { .. })
        ));
    }

    #[tokio::test]
    async fn write_sync_all_rename_are_separate_posix_ops() {
        let exec = exec_open();
        let dir = tmpdir();
        let src = dir.join("tmp.data");
        let dst = dir.join("final.data");
        let class = TrafficClass::Foreground;

        exec.write(sda(), class, src.clone(), b"hello".to_vec())
            .await
            .unwrap();
        exec.sync_all(sda(), class, src.clone()).await.unwrap();
        exec.rename(sda(), class, src.clone(), dst.clone())
            .await
            .unwrap();

        assert_eq!(std::fs::read(&dst).unwrap(), b"hello");
        assert!(!src.exists());
        assert_eq!(exec.stats().blocking.started_total, 3);
        assert_eq!(exec.stats().blocking.completed_total, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn write_at_is_a_chunk_not_a_whole_put() {
        let exec = exec_open();
        let dir = tmpdir();
        let path = dir.join("obj");
        let class = TrafficClass::Foreground;

        let n = exec
            .write_at(sda(), class, path.clone(), 0, b"aa".to_vec())
            .await
            .unwrap();
        assert_eq!(n, 2);
        let n = exec
            .write_at(sda(), class, path.clone(), 2, b"bb".to_vec())
            .await
            .unwrap();
        assert_eq!(n, 2);
        exec.sync_all(sda(), class, path.clone()).await.unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"aabb");
        assert_eq!(exec.stats().blocking.started_total, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn write_at_does_not_truncate() {
        let exec = exec_open();
        let dir = tmpdir();
        let path = dir.join("keep");
        exec.write(
            sda(),
            TrafficClass::Foreground,
            path.clone(),
            b"xxxx".to_vec(),
        )
        .await
        .unwrap();
        exec.write_at(
            sda(),
            TrafficClass::Foreground,
            path.clone(),
            1,
            b"yz".to_vec(),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"xyzx");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn queue_full_fails_closed_and_does_not_write() {
        let domain = BlockingDomain::with_bounds(1, 1).unwrap();
        let exec = StorageExecutor::with_posix(
            ThreadedPosixIo::from_domain(domain.clone()),
            limits_open(),
        );
        let dir = tmpdir();
        let should_not = dir.join("should-not-exist");

        let (entered_tx, entered_rx) = std_mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std_mpsc::sync_channel::<()>(1);
        let blocker = domain
            .submit(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
            .unwrap();
        wait_until(|| entered_rx.try_recv().is_ok()).await;
        wait_until(|| domain.stats().active == 1).await;

        let queued = domain.submit(|| ()).unwrap();
        wait_until(|| domain.stats().queued == 1).await;

        let err = exec
            .write(
                sda(),
                TrafficClass::Foreground,
                should_not.clone(),
                b"nope".to_vec(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                StorageError::QueueFull {
                    thread_cap: 1,
                    queue_bound: 1,
                    queued: 1,
                    active: 1,
                }
            ),
            "unexpected reject: {err:?}"
        );
        assert!(!should_not.exists(), "rejected write must not run");
        assert_eq!(domain.stats().rejected_total, 1);

        tokio::time::timeout(
            Duration::from_millis(200),
            tokio::time::sleep(Duration::from_millis(5)),
        )
        .await
        .expect("reactor must progress while a POSIX domain thread is occupied");

        release_tx.send(()).unwrap();
        blocker.join().await.unwrap();
        queued.join().await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn device_and_class_budgets_are_independent() {
        let exec = StorageExecutor::with_posix(
            ThreadedPosixIo::from_domain(BlockingDomain::with_bounds(4, 4).unwrap()),
            DeviceIoLimits::new(2, 1, 1, 1, 1),
        );

        let fg_a = exec
            .try_acquire_device(sda(), TrafficClass::Foreground)
            .unwrap();
        assert_eq!(
            exec.try_acquire_device(sda(), TrafficClass::Foreground)
                .unwrap_err(),
            StorageError::DeviceClassBusy {
                device: sda(),
                class: TrafficClass::Foreground,
                active: 1,
                cap: 1,
            }
        );
        let repl = exec
            .try_acquire_device(sda(), TrafficClass::Replication)
            .unwrap();
        assert_eq!(
            exec.try_acquire_device(sda(), TrafficClass::Auditor)
                .unwrap_err(),
            StorageError::DeviceBusy {
                device: sda(),
                active: 2,
                cap: 2,
            }
        );
        let sdb_fg = exec
            .try_acquire_device(sdb(), TrafficClass::Foreground)
            .unwrap();
        assert_eq!(exec.stats().device_ops_active, 3);
        drop((fg_a, repl, sdb_fg));
        assert_eq!(exec.stats().device_ops_active, 0);
        let _ok = exec
            .try_acquire_device(sda(), TrafficClass::Foreground)
            .unwrap();
    }

    #[tokio::test]
    async fn zero_device_cap_fails_closed() {
        let exec = StorageExecutor::with_posix(
            ThreadedPosixIo::from_domain(BlockingDomain::with_bounds(1, 1).unwrap()),
            DeviceIoLimits::new(0, 8, 8, 8, 8),
        );
        assert!(matches!(
            exec.try_acquire_device(sda(), TrafficClass::Foreground)
                .unwrap_err(),
            StorageError::DeviceBusy { cap: 0, .. }
        ));
    }

    #[tokio::test]
    async fn device_busy_does_not_submit_posix_work() {
        let exec = StorageExecutor::new(
            StorageExecutorConfig::new(2, 8, DeviceIoLimits::new(1, 1, 1, 1, 1)).unwrap(),
        )
        .unwrap();
        let dir = tmpdir();
        let path = dir.join("blocked");
        let _permit = exec
            .try_acquire_device(sda(), TrafficClass::Foreground)
            .unwrap();
        let before = exec.stats().blocking.started_total;
        let err = exec
            .write(sda(), TrafficClass::Foreground, path.clone(), b"x".to_vec())
            .await
            .unwrap_err();
        assert!(matches!(err, StorageError::DeviceClassBusy { .. }));
        assert!(!path.exists());
        assert_eq!(exec.stats().blocking.started_total, before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn threaded_posix_io_runs_on_blocking_domain() {
        let io = ThreadedPosixIo::with_bounds(1, 4).unwrap();
        let dir = tmpdir();
        let path = dir.join("only-posix");
        io.write(path.clone(), b"z".to_vec()).await.unwrap();
        io.sync_all(path.clone()).await.unwrap();
        let renamed = dir.join("renamed");
        io.rename(path, renamed.clone()).await.unwrap();
        assert_eq!(std::fs::read(&renamed).unwrap(), b"z");
        assert_eq!(io.stats().started_total, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn run_finite_holds_device_permit_and_does_not_block_reactor() {
        let exec = StorageExecutor::new(
            StorageExecutorConfig::new(1, 4, DeviceIoLimits::new(1, 1, 1, 1, 1)).unwrap(),
        )
        .unwrap();
        let (entered_tx, entered_rx) = std_mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std_mpsc::sync_channel::<()>(1);
        let job = tokio::spawn({
            let exec = exec.clone();
            async move {
                exec.run_finite(sda(), TrafficClass::Foreground, move || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    9u8
                })
                .await
            }
        });
        wait_until(|| entered_rx.try_recv().is_ok()).await;
        assert!(matches!(
            exec.try_acquire_device(sda(), TrafficClass::Foreground)
                .unwrap_err(),
            StorageError::DeviceClassBusy { .. }
        ));
        tokio::time::timeout(
            Duration::from_millis(200),
            tokio::time::sleep(Duration::from_millis(5)),
        )
        .await
        .expect("reactor must progress while run_finite occupies a storage thread");
        release_tx.send(()).unwrap();
        assert_eq!(job.await.unwrap().unwrap(), 9);
        assert_eq!(exec.stats().device_ops_active, 0);
    }
}
