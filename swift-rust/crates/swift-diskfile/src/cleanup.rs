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

//! Cleanup and suffix hashing: `cleanup_ondisk_files`,
//! `_hash_suffix_dir`/`_hash_suffix` and the partition-level
//! `__get_hashes` consolidation flow.

use std::path::Path;

use md5::{Digest, Md5};
use swift_core::pickle::Value;

use crate::error::DiskFileError;
use crate::hashes::{consolidate_hashes, lock_path, read_hashes, write_hashes, Hashes};
use crate::layout::quarantine_renamer;
use crate::naming::PolicyKind;
use crate::ondisk::{get_ondisk_files, OndiskFiles};
use crate::{DEFAULT_COMMIT_WINDOW, DEFAULT_RECLAIM_AGE};

/// Reclaim tunables (`reclaim_age`, `commit_window` from the conf).
#[derive(Debug, Clone, Copy)]
pub struct CleanupConfig {
    pub reclaim_age: f64,
    pub commit_window: f64,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        CleanupConfig {
            reclaim_age: DEFAULT_RECLAIM_AGE,
            commit_window: DEFAULT_COMMIT_WINDOW,
        }
    }
}

/// Result of [`cleanup_ondisk_files`]: the surviving directory listing
/// (reverse-sorted) plus the file-selection results.
#[derive(Debug)]
pub struct CleanupResult {
    pub ondisk: OndiskFiles,
    pub files: Vec<String>,
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Port of `swift.common.utils.is_file_older`.
pub(crate) fn is_file_older(path: &Path, age: f64) -> bool {
    if age <= 0.0 {
        return true;
    }
    match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(mtime) => {
            let mtime_secs = mtime
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(f64::MAX);
            now_secs() - age > mtime_secs
        }
        Err(_) => false,
    }
}

/// `swift.common.utils.remove_file`: quiet unlink.
fn remove_file(path: &Path) {
    let _ = std::fs::remove_file(path);
}

fn listdir(path: &Path) -> std::io::Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(path)? {
        out.push(entry?.file_name().to_string_lossy().into_owned());
    }
    Ok(out)
}

/// Port of `cleanup_ondisk_files`: remove obsolete and reclaimable files
/// from an object hash dir and report what remains.
pub fn cleanup_ondisk_files(
    hsh_path: &Path,
    policy: PolicyKind,
    cfg: &CleanupConfig,
) -> Result<CleanupResult, DiskFileError> {
    let is_reclaimable = |ts: &swift_core::Timestamp| now_secs() - ts.as_secs_f64() > cfg.reclaim_age;

    let mut files = match listdir(hsh_path) {
        Ok(files) => files,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let ondisk = get_ondisk_files(&[], hsh_path, false, policy, None, None)?;
            return Ok(CleanupResult {
                ondisk,
                files: Vec::new(),
            });
        }
        Err(e) => return Err(DiskFileError::Io(e)),
    };
    files.sort_by(|a, b| b.cmp(a));

    let mut results = get_ondisk_files(&files, hsh_path, false, policy, None, None)?;
    if let Some(ts_info) = &results.ts_info {
        if is_reclaimable(&ts_info.timestamp) {
            remove_file(&hsh_path.join(&ts_info.filename));
            let filename = ts_info.filename.clone();
            files.retain(|f| *f != filename);
            results.ts_info = None;
        }
    }
    let mut obsolete = std::mem::take(&mut results.obsolete);
    for info in &results.possible_reclaim {
        // stray files are not deleted until reclaim-age; non-durable data
        // files are not deleted unless written before commit_window
        let filepath = hsh_path.join(&info.filename);
        if is_reclaimable(&info.timestamp)
            && (info.durable.unwrap_or(true)
                || cfg.commit_window <= 0.0
                || is_file_older(&filepath, cfg.commit_window))
        {
            obsolete.push(info.clone());
        }
    }
    for info in &obsolete {
        remove_file(&hsh_path.join(&info.filename));
        files.retain(|f| *f != info.filename);
    }
    results.obsolete = obsolete;
    if files.is_empty() {
        // everything got unlinked; failure to rmdir is no real harm
        let _ = std::fs::remove_dir(hsh_path);
    }
    Ok(CleanupResult {
        ondisk: results,
        files,
    })
}

enum SuffixError {
    /// `PathNotDir`: the suffix vanished or was never a directory; its
    /// key must be dropped from the partition hashes.
    PathNotDir,
    Io(std::io::Error),
}

/// Running md5s per fragment index (`None` bucket for non-frag updates),
/// in first-touch order like Python's `defaultdict`.
struct SuffixHashers {
    buckets: Vec<(Option<i64>, Md5)>,
}

impl SuffixHashers {
    fn update(&mut self, key: Option<i64>, data: &str) {
        match self.buckets.iter_mut().find(|(k, _)| *k == key) {
            Some((_, md5)) => md5.update(data.as_bytes()),
            None => {
                let mut md5 = Md5::new();
                md5.update(data.as_bytes());
                self.buckets.push((key, md5));
            }
        }
    }
}

/// Per-suffix hash result: one hex digest for replication policies, a
/// per-fragment-index map for EC.
#[derive(Debug, Clone, PartialEq)]
pub enum SuffixHashes {
    Repl(String),
    Ec(Vec<(Option<i64>, String)>),
}

impl SuffixHashes {
    fn to_value(&self) -> Value {
        match self {
            SuffixHashes::Repl(hex) => Value::Str(hex.clone()),
            SuffixHashes::Ec(map) => Value::Dict(
                map.iter()
                    .map(|(fi, hex)| {
                        let key = match fi {
                            Some(i) => Value::Int(*i),
                            None => Value::None,
                        };
                        (key, Value::Str(hex.clone()))
                    })
                    .collect(),
            ),
        }
    }
}

/// Port of `_hash_suffix_dir` + the policy-specific `_hash_suffix` and
/// `_update_suffix_hashes`: reclaims as it goes, then digests the state
/// of every object dir in the suffix.
fn hash_suffix_dir(
    suffix_path: &Path,
    policy: PolicyKind,
    cfg: &CleanupConfig,
) -> Result<SuffixHashers, SuffixError> {
    let mut hashers = SuffixHashers {
        buckets: Vec::new(),
    };
    let mut entries = match listdir(suffix_path) {
        Ok(entries) => entries,
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.kind() == std::io::ErrorKind::NotADirectory =>
        {
            return Err(SuffixError::PathNotDir)
        }
        Err(e) => return Err(SuffixError::Io(e)),
    };
    entries.sort();

    // partition/objects/device, for quarantine destinations
    let device_path = suffix_path
        .ancestors()
        .nth(3)
        .unwrap_or(suffix_path)
        .to_path_buf();

    for hsh in entries {
        let hsh_path = suffix_path.join(&hsh);
        let ondisk_info = match cleanup_ondisk_files(&hsh_path, policy, cfg) {
            Ok(result) => result,
            Err(DiskFileError::Io(e))
                if e.kind() == std::io::ErrorKind::NotADirectory =>
            {
                // an object dir that is somehow a file: quarantine it
                let _ = quarantine_renamer(&device_path, &hsh_path.join("made-up-filename"));
                continue;
            }
            Err(DiskFileError::Io(e)) => return Err(SuffixError::Io(e)),
            Err(_) => continue,
        };
        if ondisk_info.files.is_empty() {
            continue;
        }
        let ondisk = &ondisk_info.ondisk;
        for info in [&ondisk.meta_info, &ondisk.ts_info].into_iter().flatten() {
            hashers.update(None, &format!("{}{}", info.timestamp.internal(), info.ext));
        }
        match policy {
            PolicyKind::Replication => {
                if let Some(info) = &ondisk.data_info {
                    hashers.update(None, &format!("{}{}", info.timestamp.internal(), info.ext));
                }
            }
            PolicyKind::Ec { .. } => {
                for (_ts, frag_set) in &ondisk.frag_sets {
                    for info in frag_set {
                        hashers.update(info.frag_index, &info.timestamp.internal());
                    }
                }
                if let Some(durable_ts) = &ondisk.durable_frag_set_ts {
                    // a consistent representation of durability regardless
                    // of legacy .durable vs #d marker
                    hashers.update(None, &format!("{}.durable", durable_ts.internal()));
                }
            }
        }
        if let Some(info) = &ondisk.ctype_info {
            if let Some(ctype_ts) = &info.ctype_timestamp {
                hashers.update(None, &format!("{}_ctype", ctype_ts.internal()));
            }
        }
    }

    match std::fs::remove_dir(suffix_path) {
        // removed (was empty) or already gone: treat the suffix as absent
        Ok(()) => Err(SuffixError::PathNotDir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(SuffixError::PathNotDir),
        Err(_) => Ok(hashers),
    }
}

/// `DiskFileManager._hash_suffix` (replication): single md5 across the
/// suffix.
pub fn hash_suffix_repl(
    suffix_path: &Path,
    cfg: &CleanupConfig,
) -> Result<Option<String>, DiskFileError> {
    match hash_suffix_dir(suffix_path, PolicyKind::Replication, cfg) {
        Ok(mut hashers) => {
            let digest = match hashers
                .buckets
                .iter_mut()
                .find(|(k, _)| k.is_none())
            {
                Some((_, md5)) => format!("{:x}", md5.clone().finalize()),
                None => format!("{:x}", Md5::new().finalize()),
            };
            Ok(Some(digest))
        }
        Err(SuffixError::PathNotDir) => Ok(None),
        Err(SuffixError::Io(e)) => Err(DiskFileError::Io(e)),
    }
}

fn hash_suffix(
    suffix_path: &Path,
    policy: PolicyKind,
    cfg: &CleanupConfig,
) -> Result<Option<SuffixHashes>, DiskFileError> {
    match hash_suffix_dir(suffix_path, policy, cfg) {
        Ok(hashers) => Ok(Some(match policy {
            PolicyKind::Replication => {
                let digest = hashers
                    .buckets
                    .into_iter()
                    .find(|(k, _)| k.is_none())
                    .map(|(_, md5)| format!("{:x}", md5.finalize()))
                    .unwrap_or_else(|| format!("{:x}", Md5::new().finalize()));
                SuffixHashes::Repl(digest)
            }
            PolicyKind::Ec { .. } => SuffixHashes::Ec(
                hashers
                    .buckets
                    .into_iter()
                    .map(|(fi, md5)| (fi, format!("{:x}", md5.finalize())))
                    .collect(),
            ),
        })),
        Err(SuffixError::PathNotDir) => Ok(None),
        Err(SuffixError::Io(e)) => Err(DiskFileError::Io(e)),
    }
}

fn value_is_falsy(v: &Value) -> bool {
    match v {
        Value::None => true,
        Value::Bool(b) => !*b,
        Value::Int(i) => *i == 0,
        Value::Float(f) => *f == 0.0,
        Value::Str(s) => s.is_empty(),
        Value::Bytes(b) => b.is_empty(),
        Value::Dict(d) => d.is_empty(),
        Value::List(l) => l.is_empty(),
        Value::Tuple(t) => t.is_empty(),
        Value::Global(..) => false,
    }
}

/// Port of `BaseDiskFileManager.__get_hashes` + `_get_hashes`: get (and
/// repair) the hashes for every suffix dir in a partition. Returns the
/// number of suffixes hashed and the hashes with the `valid`/`updated`
/// bookkeeping keys removed.
pub fn get_partition_hashes(
    partition_path: &Path,
    policy: PolicyKind,
    recalculate: &[String],
    do_listdir: bool,
    cfg: &CleanupConfig,
) -> Result<(u64, Hashes), DiskFileError> {
    let mut do_listdir = do_listdir;
    loop {
        let mut hashed = 0u64;
        let mut modified = false;

        let mut orig_hashes = consolidate_hashes(partition_path).unwrap_or_else(|_| {
            // matches Python's warning-and-continue on unreadable pkl
            Hashes::invalid()
        });

        let mut hashes;
        if !orig_hashes.is_valid() {
            // the only path to valid hashes from an invalid read; the
            // rewrite must observe this same invalid state or we retry
            do_listdir = true;
            hashes = Hashes::default();
            hashes.set("valid", Value::Bool(true));
            orig_hashes = read_hashes(partition_path);
        } else {
            hashes = orig_hashes.clone();
        }

        if do_listdir {
            match listdir(partition_path) {
                Ok(entries) => {
                    for suff in entries {
                        if suff.len() == 3 {
                            hashes.setdefault(&suff, Value::None);
                        }
                    }
                }
                Err(e) => return Err(DiskFileError::Io(e)),
            }
            modified = true;
        }
        for suffix in recalculate {
            hashes.set(suffix, Value::None);
        }

        let snapshot: Vec<(String, Value)> = hashes.pairs.clone();
        for (suffix, hash_value) in snapshot {
            if suffix == "valid" || suffix == "updated" {
                continue;
            }
            if !value_is_falsy(&hash_value) {
                continue;
            }
            let suffix_dir = partition_path.join(&suffix);
            match hash_suffix(&suffix_dir, policy, cfg) {
                Ok(Some(suffix_hashes)) => {
                    hashes.set(&suffix, suffix_hashes.to_value());
                    hashed += 1;
                }
                Ok(None) => hashes.remove(&suffix),
                Err(_) => { /* "Error hashing suffix": skip, stay invalid */ }
            }
            modified = true;
        }

        if modified {
            let lock = lock_path(partition_path, 10.0)?;
            if read_hashes(partition_path).semantic_eq(&orig_hashes) {
                write_hashes(partition_path, &mut hashes)?;
                drop(lock);
                hashes.remove("updated");
                hashes.remove("valid");
                return Ok((hashed, hashes));
            }
            drop(lock);
            // raced with another writer: take it from the top
            continue;
        }
        hashes.remove("updated");
        hashes.remove("valid");
        return Ok((hashed, hashes));
    }
}
