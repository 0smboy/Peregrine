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

//! SQLite space observability and optional VACUUM for account/container DBs.
//!
//! DELETE of rows does not shrink the on-disk file; free pages accumulate in
//! the freelist. Production VACUUM must be explicit and off the hot write path
//! (see docs/fairness-lab/TOMBSTONE-VACUUM.md).

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::auditor::db_locations;
use crate::util::DbError;

/// Snapshot of one SQLite DB's on-disk / freelist state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbSpaceSample {
    pub path: PathBuf,
    pub kind: &'static str,
    pub file_bytes: u64,
    pub page_count: i64,
    pub freelist_count: i64,
    pub page_size: i64,
}

impl DbSpaceSample {
    /// Approximate reclaimable bytes from freelist pages.
    pub fn freelist_bytes(&self) -> u64 {
        if self.freelist_count <= 0 || self.page_size <= 0 {
            return 0;
        }
        (self.freelist_count as u64).saturating_mul(self.page_size as u64)
    }
}

/// Read `PRAGMA page_count` / `freelist_count` / `page_size` plus `metadata().len()`.
pub fn sample_db_space(path: &Path, kind: &'static str) -> Result<DbSpaceSample, DbError> {
    let file_bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let conn = Connection::open(path)
        .map_err(|e| DbError::Connection(format!("open {}: {e}", path.display())))?;
    let page_count: i64 = conn
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .map_err(|e| DbError::Connection(format!("page_count: {e}")))?;
    let freelist_count: i64 = conn
        .query_row("PRAGMA freelist_count", [], |r| r.get(0))
        .map_err(|e| DbError::Connection(format!("freelist_count: {e}")))?;
    let page_size: i64 = conn
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .map_err(|e| DbError::Connection(format!("page_size: {e}")))?;
    Ok(DbSpaceSample {
        path: path.to_path_buf(),
        kind,
        file_bytes,
        page_count,
        freelist_count,
        page_size,
    })
}

/// Run `VACUUM` on a single DB file. Caller must ensure no writers hold the DB.
pub fn vacuum_db(path: &Path) -> Result<DbSpaceSample, DbError> {
    {
        let conn = Connection::open(path)
            .map_err(|e| DbError::Connection(format!("open {}: {e}", path.display())))?;
        conn.execute_batch("VACUUM;")
            .map_err(|e| DbError::Connection(format!("VACUUM {}: {e}", path.display())))?;
    }
    // Re-sample after close so file size reflects the compacted file.
    sample_db_space(path, guess_kind(path))
}

fn guess_kind(path: &Path) -> &'static str {
    let s = path.to_string_lossy();
    if s.contains("/accounts/") {
        "account"
    } else if s.contains("/containers/") {
        "container"
    } else {
        "unknown"
    }
}

/// Sample every account and container DB under a device root.
pub fn sample_device_db_space(device_path: &Path) -> Vec<Result<DbSpaceSample, DbError>> {
    let mut out = Vec::new();
    for db in db_locations(device_path, "accounts") {
        out.push(sample_db_space(&db, "account"));
    }
    for db in db_locations(device_path, "containers") {
        out.push(sample_db_space(&db, "container"));
    }
    out
}

/// VACUUM every DB on a device. Returns before/after pairs for each path.
pub fn vacuum_device_dbs(
    device_path: &Path,
) -> Vec<(
    PathBuf,
    Result<DbSpaceSample, DbError>,
    Result<DbSpaceSample, DbError>,
)> {
    let mut paths = db_locations(device_path, "accounts");
    paths.extend(db_locations(device_path, "containers"));
    let mut out = Vec::new();
    for path in paths {
        let before = sample_db_space(&path, guess_kind(&path));
        let after = match &before {
            Ok(_) => vacuum_db(&path),
            Err(e) => Err(DbError::Connection(e.to_string())),
        };
        out.push((path, before, after));
    }
    out
}

/// Aggregate counters for Prometheus / textfile export.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DbSpaceTotals {
    pub files: u64,
    pub file_bytes: u64,
    pub freelist_count: u64,
    pub freelist_bytes: u64,
    pub errors: u64,
}

impl DbSpaceTotals {
    pub fn absorb(&mut self, sample: &DbSpaceSample) {
        self.files += 1;
        self.file_bytes += sample.file_bytes;
        self.freelist_count += sample.freelist_count.max(0) as u64;
        self.freelist_bytes += sample.freelist_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_db() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "swift-db-vacuum-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("test.db")
    }

    #[test]
    fn freelist_grows_on_delete_and_shrinks_after_vacuum() {
        let path = tmp_db();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE t(id INTEGER PRIMARY KEY, blob BLOB);
             INSERT INTO t(blob) VALUES (zeroblob(65536));
             INSERT INTO t(blob) VALUES (zeroblob(65536));
             INSERT INTO t(blob) VALUES (zeroblob(65536));
             INSERT INTO t(blob) VALUES (zeroblob(65536));",
        )
        .unwrap();
        drop(conn);

        let filled = sample_db_space(&path, "container").unwrap();
        assert!(filled.file_bytes > 0);
        assert_eq!(filled.freelist_count, 0);

        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("DELETE FROM t;").unwrap();
        drop(conn);

        let after_delete = sample_db_space(&path, "container").unwrap();
        assert!(
            after_delete.freelist_count > 0,
            "DELETE should leave freelist pages"
        );
        assert!(
            after_delete.file_bytes >= filled.file_bytes,
            "file size must not shrink on DELETE alone"
        );

        let after_vacuum = vacuum_db(&path).unwrap();
        assert_eq!(after_vacuum.freelist_count, 0);
        assert!(
            after_vacuum.file_bytes < after_delete.file_bytes,
            "VACUUM must shrink file: before={} after={}",
            after_delete.file_bytes,
            after_vacuum.file_bytes
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }
}
