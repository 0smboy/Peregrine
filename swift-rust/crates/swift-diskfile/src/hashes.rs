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

//! `hashes.pkl` / `hashes.invalid` handling: `read_hashes`,
//! `write_hashes`, `invalidate_hash` and `consolidate_hashes`, plus the
//! `lock_path` directory lock they share with the Python implementation
//! (an `flock` on `<partition>/.lock`).

use std::io::Write;
use std::path::Path;

use swift_core::pickle::{self, Value};

use crate::error::DiskFileError;
use crate::layout::renamer;
use crate::{HASH_FILE, HASH_INVALIDATIONS_FILE};

/// The contents of a partition's `hashes.pkl` as insertion-ordered pairs.
/// Values are pickle values: `None` (invalidated), a hex digest string
/// (replication), a `{frag_index: hex}` dict (EC), plus the bookkeeping
/// `valid` (bool) and `updated` (float, or int `-1`) keys.
#[derive(Debug, Clone, Default)]
pub struct Hashes {
    pub pairs: Vec<(String, Value)>,
}

impl Hashes {
    /// The `{'valid': False}` sentinel.
    pub fn invalid() -> Self {
        Hashes {
            pairs: vec![("valid".to_string(), Value::Bool(false))],
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Replace in place, or append — matching Python dict assignment
    /// semantics for ordering.
    pub fn set(&mut self, key: &str, value: Value) {
        match self.pairs.iter_mut().find(|(k, _)| k == key) {
            Some((_, v)) => *v = value,
            None => self.pairs.push((key.to_string(), value)),
        }
    }

    pub fn setdefault(&mut self, key: &str, value: Value) {
        if self.get(key).is_none() {
            self.pairs.push((key.to_string(), value));
        }
    }

    pub fn remove(&mut self, key: &str) {
        self.pairs.retain(|(k, _)| k != key);
    }

    pub fn is_valid(&self) -> bool {
        matches!(self.get("valid"), Some(Value::Bool(true)))
    }

    pub fn to_value(&self) -> Value {
        Value::Dict(
            self.pairs
                .iter()
                .map(|(k, v)| (Value::Str(k.clone()), v.clone()))
                .collect(),
        )
    }

    /// Python `dict ==`: order-insensitive, numeric types compare by
    /// value.
    pub fn semantic_eq(&self, other: &Hashes) -> bool {
        if self.pairs.len() != other.pairs.len() {
            return false;
        }
        self.pairs.iter().all(|(k, v)| {
            other
                .get(k)
                .map(|ov| value_semantic_eq(v, ov))
                .unwrap_or(false)
        })
    }
}

fn value_semantic_eq(a: &Value, b: &Value) -> bool {
    fn as_num(v: &Value) -> Option<f64> {
        match v {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            Value::Bool(b) => Some(*b as u8 as f64),
            _ => None,
        }
    }
    if let (Some(x), Some(y)) = (as_num(a), as_num(b)) {
        return x == y;
    }
    match (a, b) {
        (Value::Dict(pa), Value::Dict(pb)) => {
            pa.len() == pb.len()
                && pa.iter().all(|(k, v)| {
                    pb.iter()
                        .find(|(ok, _)| value_semantic_eq(k, ok))
                        .map(|(_, ov)| value_semantic_eq(v, ov))
                        .unwrap_or(false)
                })
        }
        _ => a == b,
    }
}

/// Guard for the partition directory lock; dropping releases it.
pub struct PathLock {
    _file: std::fs::File,
}

const DEFAULT_LOCK_TIMEOUT: f64 = 10.0;

/// Port of `swift.common.utils.lock_path`: an exclusive `flock` on
/// `<directory>/.lock`, polled non-blocking until `timeout`.
pub fn lock_path(directory: &Path, timeout: f64) -> Result<PathLock, DiskFileError> {
    std::fs::create_dir_all(directory)?;
    let lockpath = directory.join(".lock");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lockpath)?;
    let start = std::time::Instant::now();
    let mut sleep_time = 0.01f64;
    let slowdown_at = timeout * 0.01;
    let slower_sleep_time = (timeout * 0.01).max(0.01);
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(PathLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(e)) => return Err(DiskFileError::Io(e)),
        }
        if start.elapsed().as_secs_f64() > timeout {
            return Err(DiskFileError::LockTimeout(
                lockpath.to_string_lossy().into_owned(),
            ));
        }
        if start.elapsed().as_secs_f64() > slowdown_at {
            sleep_time = slower_sleep_time;
        }
        std::thread::sleep(std::time::Duration::from_secs_f64(sleep_time));
    }
}

/// Port of `swift.common.utils.pickle.write_pickle`: write to a temp file
/// in `tmp_dir`, fsync, then rename into place (fsyncing the directory).
pub fn write_pickle(blob: &[u8], dest: &Path, tmp_dir: &Path) -> Result<(), DiskFileError> {
    std::fs::create_dir_all(tmp_dir)?;
    let tmppath = tmp_dir.join(format!(
        ".pickle-{}-{:x}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    {
        let mut f = std::fs::File::create(&tmppath)?;
        f.write_all(blob)?;
        f.sync_all()?;
    }
    renamer(&tmppath, dest, true)?;
    Ok(())
}

/// Port of `read_hashes`. Never errors: corrupt or unreadable state comes
/// back as `{'valid': False}`.
pub fn read_hashes(partition_dir: &Path) -> Hashes {
    let mut hashes = Hashes::invalid();
    if let Ok(raw) = std::fs::read(partition_dir.join(HASH_FILE)) {
        if let Ok(Value::Dict(pairs)) = pickle::loads(&raw) {
            // Check for corrupted keys that could break os.listdir():
            // any non-string or non-suffix key makes the whole pkl
            // invalid, *without* the valid/updated defaulting below
            let keys_ok = pairs.iter().all(|(k, _)| {
                matches!(&k, Value::Str(s)
                    if crate::layout::valid_suffix(s) || s == "valid" || s == "updated")
            });
            if !keys_ok {
                return Hashes::invalid();
            }
            hashes = Hashes {
                pairs: pairs
                    .into_iter()
                    .map(|(k, v)| match k {
                        Value::Str(s) => (s, v),
                        _ => unreachable!(),
                    })
                    .collect(),
            };
        }
    }

    // hashes.pkl without a valid/updated key is "valid" but "forever old"
    hashes.setdefault("valid", Value::Bool(true));
    hashes.setdefault("updated", Value::Int(-1));
    hashes
}

/// Serialize as `write_hashes` does, with an explicit clock for
/// deterministic tests.
pub fn hashes_to_pickle(hashes: &mut Hashes, now: f64) -> Result<Vec<u8>, DiskFileError> {
    hashes.setdefault("valid", Value::Bool(false));
    hashes.set("updated", Value::Float(now));
    Ok(pickle::dumps(&hashes.to_value())?)
}

/// Port of `write_hashes`: stamp `updated`, pickle, and write atomically
/// into the partition dir.
pub fn write_hashes(partition_dir: &Path, hashes: &mut Hashes) -> Result<(), DiskFileError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let blob = hashes_to_pickle(hashes, now)?;
    write_pickle(&blob, &partition_dir.join(HASH_FILE), partition_dir)
}

/// Port of `invalidate_hash`: append the suffix to the partition's
/// `hashes.invalid` under the partition lock.
pub fn invalidate_hash(suffix_dir: &Path) -> Result<(), DiskFileError> {
    let suffix = suffix_dir
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let partition_dir = match suffix_dir.parent() {
        Some(p) => p.to_path_buf(),
        None => return Ok(()),
    };
    let _lock = lock_path(&partition_dir, DEFAULT_LOCK_TIMEOUT)?;
    let invalidations = partition_dir.join(HASH_INVALIDATIONS_FILE);
    match std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&invalidations)
    {
        Ok(mut f) => {
            f.write_all(suffix.as_bytes())?;
            f.write_all(b"\n")?;
            Ok(())
        }
        // partition deleted out from under us — same shrug as Python
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(DiskFileError::Io(e)),
    }
}

/// Port of `consolidate_hashes`: fold `hashes.invalid` into `hashes.pkl`
/// and truncate the invalidations file, all under the partition lock.
pub fn consolidate_hashes(partition_dir: &Path) -> Result<Hashes, DiskFileError> {
    let invalidations_file = partition_dir.join(HASH_INVALIDATIONS_FILE);
    let _lock = lock_path(partition_dir, DEFAULT_LOCK_TIMEOUT)?;
    let mut hashes = read_hashes(partition_dir);

    let mut found_invalidation_entry = false;
    let mut hashes_updated = false;
    match std::fs::read_to_string(&invalidations_file) {
        Ok(contents) => {
            for line in contents.lines() {
                found_invalidation_entry = true;
                let suffix = line.trim();
                if !crate::layout::valid_suffix(suffix) {
                    continue;
                }
                hashes_updated = true;
                hashes.set(suffix, Value::None);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(DiskFileError::Io(e)),
    }

    if hashes_updated {
        write_hashes(partition_dir, &mut hashes)?;
    }
    if found_invalidation_entry {
        std::fs::write(&invalidations_file, b"")?;
    }
    Ok(hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "swift-diskfile-hashes-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_invalidate_consolidate_cycle() {
        let part = tmpdir("cycle");
        let suffix_dir = part.join("abc");
        invalidate_hash(&suffix_dir).unwrap();
        let raw = std::fs::read_to_string(part.join(HASH_INVALIDATIONS_FILE)).unwrap();
        assert_eq!(raw, "abc\n");

        let hashes = consolidate_hashes(&part).unwrap();
        assert_eq!(hashes.get("abc"), Some(&Value::None));
        // invalidations were folded in and the file truncated
        let raw = std::fs::read_to_string(part.join(HASH_INVALIDATIONS_FILE)).unwrap();
        assert_eq!(raw, "");
        // hashes.pkl round-trips through our own reader; consolidation on
        // a missing pkl stays invalid (only a full rehash makes it valid),
        // matching Python
        let read_back = read_hashes(&part);
        assert!(!read_back.is_valid());
        assert_eq!(read_back.get("abc"), Some(&Value::None));
        std::fs::remove_dir_all(&part).unwrap();
    }

    #[test]
    fn test_read_missing_is_invalid() {
        let part = tmpdir("missing");
        let hashes = read_hashes(&part);
        assert!(!hashes.is_valid());
        assert_eq!(hashes.get("updated"), Some(&Value::Int(-1)));
        std::fs::remove_dir_all(&part).unwrap();
    }

    #[test]
    fn test_semantic_eq_numeric() {
        let mut a = Hashes::default();
        a.set("updated", Value::Int(-1));
        let mut b = Hashes::default();
        b.set("updated", Value::Float(-1.0));
        assert!(a.semantic_eq(&b));
    }
}
