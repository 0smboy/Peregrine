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

//! Storage directory layout helpers: policy-suffixed data dirs, partition
//! paths, hash-dir paths and quarantine moves.

use std::path::{Path, PathBuf};

use swift_core::storage_policy::get_zero_indexed_base_string;

use crate::error::DiskFileError;
use crate::hashes::invalidate_hash;

pub const DATADIR_BASE: &str = "objects";
pub const ASYNCDIR_BASE: &str = "async_pending";
pub const TMP_BASE: &str = "tmp";

/// `objects` or `objects-<N>` for the policy index.
pub fn get_data_dir(policy_index: u32) -> String {
    get_zero_indexed_base_string(DATADIR_BASE, policy_index)
}

/// `async_pending` or `async_pending-<N>`.
pub fn get_async_dir(policy_index: u32) -> String {
    get_zero_indexed_base_string(ASYNCDIR_BASE, policy_index)
}

/// `tmp` or `tmp-<N>`.
pub fn get_tmp_dir(policy_index: u32) -> String {
    get_zero_indexed_base_string(TMP_BASE, policy_index)
}

/// Port of `get_part_path`.
pub fn get_part_path(dev_path: &Path, policy_index: u32, partition: u64) -> PathBuf {
    dev_path
        .join(get_data_dir(policy_index))
        .join(partition.to_string())
}

/// Port of `swift.common.utils.storage_directory`:
/// `<datadir>/<partition>/<hash[-3:]>/<hash>`.
pub fn storage_directory(datadir: &Path, partition: u64, name_hash: &str) -> PathBuf {
    let suffix = &name_hash[name_hash.len().saturating_sub(3)..];
    datadir
        .join(partition.to_string())
        .join(suffix)
        .join(name_hash)
}

/// Port of `valid_suffix`.
pub fn valid_suffix(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Port of `extract_policy`, returning the policy index parsed from the
/// `objects[-N]` component of an object path (`None` if malformed).
pub fn extract_policy_index(obj_path: &str) -> Option<u32> {
    let start = obj_path.rfind(DATADIR_BASE)?;
    let rest = &obj_path[start..];
    let dirname = &rest[..rest.find('/')?];
    if dirname == DATADIR_BASE {
        return Some(0);
    }
    let suffix = dirname.strip_prefix(DATADIR_BASE)?.strip_prefix('-')?;
    // reject leading zeros / empty / non-digits, as split_policy_string
    // does via PolicyError
    if suffix.is_empty() || suffix.starts_with('0') || !suffix.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    suffix.parse().ok()
}

/// Port of `swift.common.utils.makedirs_count` (utils/__init__.py:806-833):
/// same as `create_dir_all` except it returns the number of new directories
/// that had to be created, and it tolerates directories that already exist.
pub fn makedirs_count(path: &Path) -> std::io::Result<u32> {
    let mut count = 0;
    if let Some(head) = path.parent() {
        // walk up from the destination parent to the first existing
        // directory, creating (and counting) the missing levels
        if !head.as_os_str().is_empty() && !head.exists() {
            count = makedirs_count(head)?;
        }
    }
    match std::fs::create_dir(path) {
        Ok(()) => count += 1,
        // EEXIST may also be raised if path exists as a file; do not let
        // that pass (utils/__init__.py:826-829)
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {}
        Err(e) => return Err(e),
    }
    Ok(count)
}

/// Port of `swift.common.utils.renamer` (utils/__init__.py:836-865):
/// create the destination's missing ancestors, rename, then fsync the
/// containing directory of `new` *and* every newly created ancestor
/// (count + 1 fsyncs walking up), so a power loss cannot drop the new
/// suffix/hash dir entries even though the leaf was durable.
///
/// On a makedirs/rename error the whole sequence is retried once, to
/// hide races like empty object directories being removed by backend
/// processes during uploads (utils/__init__.py:837-839).
pub fn renamer(old: &Path, new: &Path, fsync: bool) -> std::io::Result<()> {
    renamer_impl(old, new, fsync, |_| {})
}

/// Inner body of [`renamer`] with a test-only seam: `before_first_rename`
/// runs between makedirs and rename on the first attempt only, letting
/// tests simulate the concurrent-rmdir race deterministically.
fn renamer_impl(
    old: &Path,
    new: &Path,
    fsync: bool,
    before_first_rename: impl FnOnce(&Path),
) -> std::io::Result<()> {
    let dirpath = match new.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        // destination has no containing directory component: nothing to
        // create or fsync
        _ => return std::fs::rename(old, new),
    };
    let count = {
        let first_try = (|| {
            let count = makedirs_count(dirpath)?;
            before_first_rename(dirpath);
            std::fs::rename(old, new)?;
            Ok::<u32, std::io::Error>(count)
        })();
        match first_try {
            Ok(count) => count,
            Err(_) => {
                // retry makedirs + rename once (utils/__init__.py:851-854)
                let count = makedirs_count(dirpath)?;
                std::fs::rename(old, new)?;
                count
            }
        }
    };
    if fsync {
        // If count == 0, no new directories were created, but we still
        // need to fsync the leaf dir after the rename. If count > 0,
        // starting from the leaf dir, fsync the parent dirs of all
        // directories created by makedirs_count()
        // (utils/__init__.py:856-864)
        let mut dirpath = dirpath;
        for _ in 0..=count {
            std::fs::File::open(dirpath)?.sync_all()?;
            match dirpath.parent() {
                Some(p) if !p.as_os_str().is_empty() => dirpath = p,
                _ => break,
            }
        }
    }
    Ok(())
}

/// Port of `quarantine_renamer`: move a corrupted object dir (or stray
/// file) into `<device>/quarantined/objects[-N]/<basename>`, invalidating
/// the suffix hash on the way out.
pub fn quarantine_renamer(
    device_path: &Path,
    corrupted_file_path: &Path,
) -> Result<PathBuf, DiskFileError> {
    let policy_index =
        extract_policy_index(&corrupted_file_path.to_string_lossy()).unwrap_or(0);
    let from_dir = corrupted_file_path
        .parent()
        .ok_or_else(|| DiskFileError::InvalidFilename("no parent".into()))?;
    let basename = from_dir
        .file_name()
        .ok_or_else(|| DiskFileError::InvalidFilename("no basename".into()))?;
    let mut to_dir = device_path
        .join("quarantined")
        .join(get_data_dir(policy_index))
        .join(basename);
    if basename.to_string_lossy().len() == 3 {
        // quarantining a whole suffix
        invalidate_hash(from_dir)?;
    } else if let Some(suffix_dir) = from_dir.parent() {
        invalidate_hash(suffix_dir)?;
    }
    match renamer(from_dir, &to_dir, false) {
        Ok(()) => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::AlreadyExists
                || e.raw_os_error() == Some(66)
                || e.raw_os_error() == Some(39) =>
        {
            // EEXIST / ENOTEMPTY (66 macOS, 39 Linux): add a unique suffix
            let unique = format!(
                "{}-{:x}{:x}",
                to_dir.to_string_lossy(),
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0)
            );
            to_dir = PathBuf::from(unique);
            renamer(from_dir, &to_dir, false)?;
        }
        Err(e) => return Err(DiskFileError::Io(e)),
    }
    Ok(to_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dirs() {
        assert_eq!(get_data_dir(0), "objects");
        assert_eq!(get_data_dir(2), "objects-2");
        assert_eq!(get_async_dir(1), "async_pending-1");
        assert_eq!(get_tmp_dir(0), "tmp");
    }

    #[test]
    fn test_storage_directory() {
        assert_eq!(
            storage_directory(Path::new("objects"), 1234, "abcdef0123456789abcdef0123456789"),
            PathBuf::from("objects/1234/789/abcdef0123456789abcdef0123456789")
        );
    }

    #[test]
    fn test_valid_suffix() {
        assert!(valid_suffix("abc"));
        assert!(valid_suffix("07f"));
        assert!(!valid_suffix("ABC"));
        assert!(!valid_suffix("ab"));
        assert!(!valid_suffix("xyz"));
    }

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "swift-diskfile-layout-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_makedirs_count() {
        let base = tmpdir("makedirs-count");
        // parent chain fully exists: nothing created
        assert_eq!(makedirs_count(&base).unwrap(), 0);
        // two missing levels
        assert_eq!(makedirs_count(&base.join("one/two")).unwrap(), 2);
        assert!(base.join("one/two").is_dir());
        // now it exists: idempotent, count 0
        assert_eq!(makedirs_count(&base.join("one/two")).unwrap(), 0);
        // EEXIST on a plain file must not pass (utils/__init__.py:826-829)
        std::fs::write(base.join("plainfile"), b"x").unwrap();
        assert!(makedirs_count(&base.join("plainfile")).is_err());
    }

    #[test]
    fn test_renamer_creates_deep_destination() {
        let base = tmpdir("renamer-deep");
        let src = base.join("src.data");
        std::fs::write(&src, b"payload").unwrap();
        // destination 3 levels deep under a fresh tree; fsync=true also
        // exercises the count+1 fsync walk up the new ancestors
        let dest = base.join("part/abc/hash/1.data");
        renamer(&src, &dest, true).unwrap();
        assert!(!src.exists());
        assert_eq!(std::fs::read(&dest).unwrap(), b"payload");
    }

    #[test]
    fn test_renamer_retries_after_concurrent_rmdir() {
        let base = tmpdir("renamer-retry");
        let src = base.join("src.data");
        std::fs::write(&src, b"payload").unwrap();
        let dest = base.join("part/abc/hash/1.data");
        // simulate the documented race (utils/__init__.py:837-839): a
        // background process rmdirs the freshly created empty dirs
        // between makedirs and rename, so the first rename fails and
        // the retry must recreate them
        renamer_impl(&src, &dest, true, |_| {
            std::fs::remove_dir_all(base.join("part")).unwrap();
        })
        .unwrap();
        assert!(!src.exists());
        assert_eq!(std::fs::read(&dest).unwrap(), b"payload");
    }

    #[test]
    fn test_extract_policy_index() {
        assert_eq!(
            extract_policy_index("objects-5/30/179/485d…/1401811134.873649.data"),
            Some(5)
        );
        assert_eq!(
            extract_policy_index("/srv/node/d42/objects/30/179/x/1.data"),
            Some(0)
        );
        assert_eq!(extract_policy_index("objects-0/30/x"), None);
        assert_eq!(extract_policy_index("objects-foo/30/x"), None);
        assert_eq!(extract_policy_index("no-datadir-here"), None);
    }
}
