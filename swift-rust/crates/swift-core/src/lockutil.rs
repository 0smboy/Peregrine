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

//! Python-compatible directory locking (`swift.common.utils.lock_path`).
//!
//! The lock is an exclusive `flock` on a hidden file inside the directory:
//! `<directory>/.lock`, or `<directory>/.lock-<name>` for a named lock
//! (Python's `limit=1` file naming, byte-for-byte, so Rust and Python
//! daemons on the same node exclude each other). The file is created if
//! missing and never unlinked; only the flock is released on drop, exactly
//! as Python's context manager behaves.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// `swift.common.exceptions.LockTimeout` (and its `PartitionLockTimeout` /
/// `ReplicationLockTimeout` subclasses): the lock on `lockpath` could not be
/// acquired within `timeout` seconds. `io` is set when acquisition failed on
/// an I/O error rather than the clock (Python would raise `OSError` there).
#[derive(Debug)]
pub struct LockTimeout {
    pub timeout: f64,
    pub lockpath: PathBuf,
    pub io: Option<std::io::Error>,
}

impl std::fmt::Display for LockTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.io {
            Some(e) => write!(f, "{} lock error: {e}", self.lockpath.display()),
            None => write!(f, "{} seconds: {}", self.timeout, self.lockpath.display()),
        }
    }
}

impl std::error::Error for LockTimeout {}

/// Guard for a held [`lock_path`] lock. Dropping releases the flock and
/// closes the fd; the lock file itself is left in place (Python's
/// `lock_path` does not unlink either — unlinking would race other waiters).
#[derive(Debug)]
pub struct PathLock {
    file: File,
}

impl Drop for PathLock {
    fn drop(&mut self) {
        // LOCK_UN before close so the release is explicit; closing the fd
        // would drop the flock anyway.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Port of `swift.common.utils.lock_path` with `limit=1`: acquire an
/// exclusive lock on `directory`, blocking up to `timeout` seconds.
///
/// The lock file is `<directory>/.lock`, with `-<name>` appended when `name`
/// is given (`get_zero_indexed_base_string(lockpath, 0)` is the identity, so
/// the `limit=1` file name matches Python byte-for-byte). The directory is
/// created if missing (Python `mkdirs`). Acquisition polls
/// `flock(LOCK_EX | LOCK_NB)` sleeping 0.01s between attempts, slowing to
/// `max(timeout * 0.01, 0.01)` once `timeout * 0.01` seconds have passed —
/// the same backoff schedule as Python.
pub fn lock_path(
    directory: &Path,
    timeout: f64,
    name: Option<&str>,
) -> Result<PathLock, LockTimeout> {
    let file_name = match name {
        Some(name) => format!(".lock-{name}"),
        None => ".lock".to_string(),
    };
    let lockpath = directory.join(file_name);
    let fail = |io: Option<std::io::Error>| LockTimeout {
        timeout,
        lockpath: lockpath.clone(),
        io,
    };
    std::fs::create_dir_all(directory).map_err(|e| fail(Some(e)))?;
    // O_WRONLY | O_CREAT, no truncation — the file's contents are never
    // touched, only its flock.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lockpath)
        .map_err(|e| fail(Some(e)))?;
    let start = Instant::now();
    let mut sleep_time = 0.01f64;
    let slower_sleep_time = (timeout * 0.01).max(0.01);
    let slowdown_at = timeout * 0.01;
    loop {
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(PathLock { file });
        }
        let err = std::io::Error::last_os_error();
        // Python `_get_any_lock` re-raises anything but EAGAIN/EWOULDBLOCK.
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(fail(Some(err)));
        }
        if start.elapsed().as_secs_f64() > timeout {
            return Err(fail(None));
        }
        if start.elapsed().as_secs_f64() > slowdown_at {
            sleep_time = slower_sleep_time;
        }
        std::thread::sleep(Duration::from_secs_f64(sleep_time));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TMP: AtomicU64 = AtomicU64::new(0);

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "swift-lockutil-{tag}-{}-{}",
            std::process::id(),
            NEXT_TMP.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_second_holder_blocks_until_first_drops() {
        let dir = tmp_dir("blocks");
        let first = lock_path(&dir, 5.0, None).expect("first lock");
        assert!(dir.join(".lock").exists());

        let dir2 = dir.clone();
        let waiter = std::thread::spawn(move || {
            let begin = Instant::now();
            let lock = lock_path(&dir2, 5.0, None);
            (begin.elapsed(), lock.is_ok())
        });
        std::thread::sleep(Duration::from_millis(150));
        drop(first);
        let (waited, acquired) = waiter.join().unwrap();
        assert!(acquired, "second holder acquires after the first drops");
        assert!(
            waited >= Duration::from_millis(100),
            "second holder actually blocked: {waited:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_times_out_while_held() {
        let dir = tmp_dir("timeout");
        let _held = lock_path(&dir, 5.0, None).expect("first lock");
        let begin = Instant::now();
        let err = lock_path(&dir, 0.15, None).expect_err("must time out");
        assert!(err.io.is_none(), "a timeout, not an I/O error: {err}");
        assert_eq!(err.lockpath, dir.join(".lock"));
        assert!(begin.elapsed() >= Duration::from_millis(150));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_name_variant_uses_a_distinct_file() {
        let dir = tmp_dir("named");
        let _plain = lock_path(&dir, 1.0, None).expect("unnamed lock");
        // A named lock on the same directory does not contend: distinct file.
        let _named = lock_path(&dir, 0.2, Some("replication")).expect("named lock");
        assert!(dir.join(".lock").exists());
        assert!(
            dir.join(".lock-replication").exists(),
            "Python's `.lock-<name>` file name"
        );
        // But a second holder of the same name does contend.
        let err = lock_path(&dir, 0.1, Some("replication")).expect_err("held");
        assert!(err.io.is_none());
        assert_eq!(err.lockpath, dir.join(".lock-replication"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_lock_file_survives_release() {
        let dir = tmp_dir("survives");
        drop(lock_path(&dir, 1.0, None).expect("lock"));
        assert!(
            dir.join(".lock").exists(),
            "released lock file is not unlinked (Python keeps it)"
        );
        // And it can be re-acquired immediately.
        let again = lock_path(&dir, 0.2, None);
        assert!(again.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
