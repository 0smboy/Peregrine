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

//! Filesystem capacity helpers, the Rust counterpart of the
//! `os.statvfs` usage in `swift.common.utils.fs_has_free_space`.

use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// `statvfs` capacity on the filesystem holding `path`.
///
/// `free_bytes` is `f_bavail * f_frsize` (unprivileged available).
/// `total_bytes` is `f_blocks * f_frsize` — Python `fallocate()` percent
/// reserve divides remaining free by this total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsSpace {
    pub free_bytes: u64,
    pub total_bytes: u64,
}

/// Bytes available to unprivileged callers on the filesystem holding
/// `path`: `statvfs.f_bavail * statvfs.f_frsize`, exactly what Python's
/// `fs_has_free_space` compares against.
pub fn free_bytes(path: &Path) -> std::io::Result<u64> {
    Ok(fs_space(path)?.free_bytes)
}

/// Free and total bytes from `statvfs` (Python `os.statvfs` / `fallocate`).
pub fn fs_space(path: &Path) -> std::io::Result<FsSpace> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path contains an interior NUL byte",
        )
    })?;
    let mut stats = MaybeUninit::<libc::statvfs>::uninit();
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stats = unsafe { stats.assume_init() };
    #[allow(clippy::unnecessary_cast)] // types differ per libc target
    Ok(FsSpace {
        free_bytes: (stats.f_bavail as u64) * (stats.f_frsize as u64),
        total_bytes: (stats.f_blocks as u64) * (stats.f_frsize as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_dir_reports_free_space() {
        let space = fs_space(&std::env::temp_dir()).unwrap();
        assert!(
            space.free_bytes > 0,
            "temp dir should have free space, got {space:?}"
        );
        assert!(
            space.total_bytes >= space.free_bytes,
            "total must cover free: {space:?}"
        );
        assert_eq!(free_bytes(&std::env::temp_dir()).unwrap(), space.free_bytes);
    }

    #[test]
    fn missing_path_is_an_error() {
        let missing = std::env::temp_dir().join(format!(
            "swift-fsutil-missing-{}-does-not-exist",
            std::process::id()
        ));
        assert!(free_bytes(&missing).is_err());
    }

    #[test]
    fn interior_nul_is_invalid_input() {
        use std::ffi::OsStr;
        let path = Path::new(OsStr::from_bytes(b"/tmp/bad\0path"));
        let error = free_bytes(path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
