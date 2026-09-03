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

//! Shared helpers: the `chexor` rolling hash, base64 for pending
//! entries, and the parent-directory flock shared with Python brokers.

use std::fmt;
use std::path::Path;

use md5::{Digest, Md5};

/// Errors from the database layer.
#[derive(Debug)]
pub enum DbError {
    /// `DatabaseConnectionError`
    Connection(String),
    /// `DatabaseAlreadyExists`
    AlreadyExists(String),
    /// `LockTimeout`
    LockTimeout(String),
    Sqlite(rusqlite::Error),
    Pickle(swift_core::pickle::PickleError),
    Io(std::io::Error),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::Connection(s) => write!(f, "database connection error: {s}"),
            DbError::AlreadyExists(s) => write!(f, "database already exists: {s}"),
            DbError::LockTimeout(s) => write!(f, "lock timeout: {s}"),
            DbError::Sqlite(e) => write!(f, "{e}"),
            DbError::Pickle(e) => write!(f, "{e}"),
            DbError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        DbError::Sqlite(e)
    }
}

impl From<swift_core::pickle::PickleError> for DbError {
    fn from(e: swift_core::pickle::PickleError) -> Self {
        DbError::Pickle(e)
    }
}

impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self {
        DbError::Io(e)
    }
}

/// SQLite `SQLITE_READONLY_DBMOVED` (extended 1032) or any Readonly.
/// The cached connection's path was replaced (rsync/complete_rsync) while
/// still open; the next write must reopen `current_db_file()`.
pub fn is_readonly_dbmoved(err: &DbError) -> bool {
    match err {
        DbError::Sqlite(rusqlite::Error::SqliteFailure(e, _)) => {
            e.extended_code == 1032 || e.code == rusqlite::ErrorCode::ReadOnly
        }
        _ => false,
    }
}

/// Port of `swift.common.db.chexor`: XOR the 128-bit md5 of
/// `"<name>-<timestamp>"` into the running hex hash.
pub fn chexor(old: &str, name: &str, timestamp: &str) -> Result<String, DbError> {
    let old_val = u128::from_str_radix(old, 16)
        .map_err(|e| DbError::Connection(format!("bad chexor hash {old:?}: {e}")))?;
    let digest = Md5::digest(format!("{name}-{timestamp}").as_bytes());
    let new_val = u128::from_be_bytes(digest.into());
    Ok(format!("{:032x}", old_val ^ new_val))
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard padded base64, as `base64.b64encode` produces.
pub fn b64encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(B64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(B64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

pub fn b64decode(data: &[u8]) -> Result<Vec<u8>, DbError> {
    fn val(c: u8) -> Result<u32, DbError> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(DbError::Connection(format!("bad base64 byte {c}"))),
        }
    }
    let data: Vec<u8> = data
        .iter()
        .copied()
        .filter(|&c| c != b'\n' && c != b'\r')
        .collect();
    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    for chunk in data.chunks(4) {
        if chunk.len() < 4 {
            return Err(DbError::Connection("truncated base64".to_string()));
        }
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' { 0 } else { val(c)? };
            n |= v << (18 - 6 * i as u32);
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// Guard for the parent-directory flock; dropping releases it.
pub struct DirLock {
    _file: std::fs::File,
}

/// Port of `swift.common.utils.lock_parent_directory`: exclusive flock on
/// `<parent>/.lock`, the same file Python brokers lock.
pub fn lock_parent_directory(filename: &Path, timeout: f64) -> Result<DirLock, DbError> {
    let directory = filename
        .parent()
        .ok_or_else(|| DbError::Connection("no parent directory".to_string()))?;
    std::fs::create_dir_all(directory)?;
    let lockpath = directory.join(".lock");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lockpath)?;
    let start = std::time::Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(DirLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(e)) => return Err(DbError::Io(e)),
        }
        if start.elapsed().as_secs_f64() > timeout {
            return Err(DbError::LockTimeout(
                lockpath.to_string_lossy().into_owned(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Register the `chexor` SQL function on a connection (both brokers'
/// stat triggers call it).
pub(crate) fn register_chexor(conn: &rusqlite::Connection) -> Result<(), DbError> {
    conn.create_scalar_function(
        "chexor",
        3,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8
            | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let old: String = ctx.get(0)?;
            let name: String = ctx.get(1)?;
            let timestamp: String = ctx.get(2)?;
            chexor(&old, &name, &timestamp)
                .map_err(|e| rusqlite::Error::UserFunctionError(format!("chexor: {e}").into()))
        },
    )?;
    Ok(())
}

/// `get_db_connection` pragmas for a normal (post-initialize) connection.
///
/// `busy_timeout(0)` disables SQLite's busy handler so `SQLITE_BUSY` /
/// `SQLITE_LOCKED` returns immediately. Python's `GreenDBCursor` waits
/// cooperatively up to `BROKER_TIMEOUT`; a Peregrine `DbExecutor` shard
/// is a single blocking thread — waiting here pins every other DB that
/// hashes to the same shard (G6 `test_locked_container_dbs`).
pub(crate) fn configure_connection(conn: &rusqlite::Connection) -> Result<(), DbError> {
    conn.busy_timeout(std::time::Duration::from_millis(0))?;
    conn.execute_batch(
        "PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;
         PRAGMA journal_mode = DELETE;",
    )?;
    register_chexor(conn)?;
    Ok(())
}

/// Port of `makedirs_count` (swift/common/utils/__init__.py:806-833):
/// how many missing directory levels of `path` (itself included) would
/// have to be created, walking up to the first existing ancestor.
fn count_missing_levels(path: &Path) -> usize {
    let mut missing = 0;
    let mut cur = Some(path);
    while let Some(p) = cur {
        if p.as_os_str().is_empty() || p.exists() {
            break;
        }
        missing += 1;
        cur = p.parent();
    }
    missing
}

/// The `DatabaseBroker.initialize` scaffolding: build the DB in a temp
/// file with fast pragmas and the shared sync tables, run the
/// broker-specific `init` body, fsync, then rename into place under the
/// parent lock.
pub(crate) fn initialize_database(
    db_file: &Path,
    lock_timeout: f64,
    init: impl FnOnce(&rusqlite::Connection) -> Result<(), DbError>,
) -> Result<(), DbError> {
    const SYNC_TABLE_SCRIPT: &str = "
            CREATE TABLE outgoing_sync (
                remote_id TEXT UNIQUE,
                sync_point INTEGER,
                updated_at TEXT DEFAULT 0
            );
            CREATE TABLE incoming_sync (
                remote_id TEXT UNIQUE,
                sync_point INTEGER,
                updated_at TEXT DEFAULT 0
            );
            CREATE TRIGGER outgoing_sync_insert AFTER INSERT ON outgoing_sync
            BEGIN
                UPDATE outgoing_sync
                SET updated_at = STRFTIME('%s', 'NOW')
                WHERE ROWID = new.ROWID;
            END;
            CREATE TRIGGER outgoing_sync_update AFTER UPDATE ON outgoing_sync
            BEGIN
                UPDATE outgoing_sync
                SET updated_at = STRFTIME('%s', 'NOW')
                WHERE ROWID = new.ROWID;
            END;
            CREATE TRIGGER incoming_sync_insert AFTER INSERT ON incoming_sync
            BEGIN
                UPDATE incoming_sync
                SET updated_at = STRFTIME('%s', 'NOW')
                WHERE ROWID = new.ROWID;
            END;
            CREATE TRIGGER incoming_sync_update AFTER UPDATE ON incoming_sync
            BEGIN
                UPDATE incoming_sync
                SET updated_at = STRFTIME('%s', 'NOW')
                WHERE ROWID = new.ROWID;
            END;
        ";
    let db_dir = db_file
        .parent()
        .ok_or_else(|| DbError::Connection("db_file has no parent".to_string()))?;
    // swift/common/utils/__init__.py:836-865 `renamer`: the containing
    // directory of the new file AND every newly created ancestor are
    // fsync'd after the rename. Count the missing levels before creating
    // them so we know how far up the tree to fsync.
    let missing_levels = count_missing_levels(db_dir);
    std::fs::create_dir_all(db_dir)?;
    let tmp_db_file = db_dir.join(format!(
        ".create-{}-{:x}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    {
        let conn = rusqlite::Connection::open(&tmp_db_file)?;
        conn.execute_batch(
            "PRAGMA synchronous = OFF;
             PRAGMA temp_store = MEMORY;
             PRAGMA journal_mode = MEMORY;",
        )?;
        register_chexor(&conn)?;
        conn.execute_batch(SYNC_TABLE_SCRIPT)?;
        init(&conn)?;
    }
    {
        let f = std::fs::File::open(&tmp_db_file)?;
        f.sync_all()?;
    }
    let _lock = lock_parent_directory(db_file, lock_timeout)?;
    if db_file.exists() {
        return Err(DbError::AlreadyExists(
            db_file.to_string_lossy().into_owned(),
        ));
    }
    std::fs::rename(&tmp_db_file, db_file)?;
    // renamer's `for i in range(0, count + 1)` loop: fsync the leaf
    // directory, then each newly created parent walking upward.
    let mut dir = db_file.parent();
    for _ in 0..=missing_levels {
        let Some(d) = dir else { break };
        std::fs::File::open(d)?.sync_all()?;
        dir = d.parent();
    }
    Ok(())
}

/// Port of `renamer` (swift/common/utils/__init__.py:836-865): create any
/// missing ancestors of `new`'s directory (`makedirs_count`,
/// utils/__init__.py:806-833), rename `old` onto `new` (replacing an
/// existing file), then fsync the containing directory and every newly
/// created ancestor so the rename is durable. Used by the REPLICATE
/// `complete_rsync` / `rsync_then_merge` ops to move a staged DB into its
/// final hash-dir path (db_replicator.py:1095, 1129).
pub fn renamer(old: &Path, new: &Path) -> Result<(), DbError> {
    let new_dir = new
        .parent()
        .ok_or_else(|| DbError::Connection("rename target has no parent".to_string()))?;
    let missing_levels = count_missing_levels(new_dir);
    std::fs::create_dir_all(new_dir)?;
    std::fs::rename(old, new)?;
    // renamer's `for i in range(0, count + 1)` loop: fsync the leaf
    // directory, then each newly created parent walking upward (the same
    // loop `initialize_database` runs after its rename).
    let mut dir = new.parent();
    for _ in 0..=missing_levels {
        let Some(d) = dir else { break };
        std::fs::File::open(d)?.sync_all()?;
        dir = d.parent();
    }
    Ok(())
}

/// Port of the corruption detection in `possibly_quarantine`
/// (swift/common/db.py:502-522): true when a SQLite error message says
/// the database file itself is broken ('database disk image is
/// malformed', 'malformed database schema', 'file is not a database' /
/// '... is not a database'). Non-SQLite errors never quarantine.
pub fn is_corruption_error(err: &DbError) -> bool {
    let DbError::Sqlite(e) = err else {
        return false;
    };
    let msg = e.to_string();
    msg.contains("malformed") || msg.contains("not a database")
}

/// True when the broker could not proceed because another connection
/// holds the SQLite lock or the parent-directory flock timed out.
/// HTTP handlers must answer 503 and release the `DbExecutor` shard.
pub fn is_lock_contention(err: &DbError) -> bool {
    match err {
        DbError::LockTimeout(_) => true,
        DbError::Sqlite(rusqlite::Error::SqliteFailure(e, msg)) => {
            e.code == rusqlite::ErrorCode::DatabaseBusy
                || e.code == rusqlite::ErrorCode::DatabaseLocked
                || msg
                    .as_deref()
                    .is_some_and(|m| m.contains("database is locked") || m.contains("database is busy"))
        }
        _ => false,
    }
}

/// Port of `DatabaseBroker.quarantine` + `get_device_path`
/// (swift/common/db.py:473-500): move the DB's hash directory to
/// `<device>/quarantined/<server_type_datadir>/<hash-dir-name>`, where
/// the device root is four levels above the hash dir
/// (`<device>/<datadir>/<partition>/<suffix>/<hash>/<hash>.db`).
/// On a name collision Python retries with a `-<uuid4().hex>` suffix;
/// here the unique suffix is pid + nanos + a process counter (no uuid
/// dependency). Returns the quarantine destination.
pub fn quarantine_db(
    db_path: &Path,
    server_type_datadir: &str,
) -> Result<std::path::PathBuf, std::io::Error> {
    use std::io::{Error, ErrorKind};
    let db_dir = db_path
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "db path has no parent"))?;
    let device_path = db_dir
        .ancestors()
        .nth(4)
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "no device root above db dir"))?;
    let name = db_dir
        .file_name()
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "db dir has no name"))?
        .to_string_lossy()
        .into_owned();
    let quar_root = device_path.join("quarantined").join(server_type_datadir);
    std::fs::create_dir_all(&quar_root)?;
    let quar_path = quar_root.join(&name);
    match std::fs::rename(db_dir, &quar_path) {
        Ok(()) => Ok(quar_path),
        // Python retries with a unique suffix only on EEXIST / ENOTEMPTY
        // (db.py:490-494) and re-raises anything else.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            static QUAR_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let unique = format!(
                "{:x}{nanos:x}{:x}",
                std::process::id(),
                QUAR_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            );
            let quar_path = quar_root.join(format!("{name}-{unique}"));
            std::fs::rename(db_dir, &quar_path)?;
            Ok(quar_path)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chexor() {
        // seeded from the python implementation
        let h = chexor(
            "00000000000000000000000000000000",
            "obj1",
            "1751500001.00000",
        )
        .unwrap();
        let h = chexor(&h, "obj2", "1751500002.00000").unwrap();
        let back = chexor(&h, "obj2", "1751500002.00000").unwrap();
        assert_eq!(
            back,
            chexor(
                "00000000000000000000000000000000",
                "obj1",
                "1751500001.00000"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_count_missing_levels() {
        let dir = std::env::temp_dir().join(format!("swift-misslvl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // existing dir: nothing to create
        assert_eq!(count_missing_levels(&dir), 0);
        // one missing level
        assert_eq!(count_missing_levels(&dir.join("a")), 1);
        // three missing levels
        assert_eq!(count_missing_levels(&dir.join("a").join("b").join("c")), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_initialize_database_creates_ancestors() {
        // The db lives two missing levels below a fresh tree; initialize
        // must create (and fsync) every new ancestor and succeed.
        let dir = std::env::temp_dir().join(format!("swift-initdb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_file = dir.join("suffix").join("hash").join("hash.db");
        initialize_database(&db_file, 10.0, |_conn| Ok(())).unwrap();
        assert!(db_file.exists());
        // a second initialize must report AlreadyExists
        assert!(matches!(
            initialize_database(&db_file, 10.0, |_conn| Ok(())),
            Err(DbError::AlreadyExists(_))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_renamer_creates_parents_and_replaces() {
        let dir = std::env::temp_dir().join(format!("swift-renamer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = dir.join("staged");
        std::fs::write(&old, b"new contents").unwrap();
        // two missing parent levels are created
        let new = dir.join("suffix").join("hash").join("hash.db");
        renamer(&old, &new).unwrap();
        assert!(!old.exists());
        assert_eq!(std::fs::read(&new).unwrap(), b"new contents");
        // renaming over an existing file replaces it (rsync_then_merge
        // renames the staged db over the live one)
        std::fs::write(&old, b"newer").unwrap();
        renamer(&old, &new).unwrap();
        assert_eq!(std::fs::read(&new).unwrap(), b"newer");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_quarantine_db_moves_hash_dir() {
        let root = std::env::temp_dir().join(format!("swift-quar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // <device>/containers/<part>/<suffix>/<hash>/<hash>.db with garbage
        let db_dir = root
            .join("sda1")
            .join("containers")
            .join("0")
            .join("abc")
            .join("hash");
        std::fs::create_dir_all(&db_dir).unwrap();
        let db_path = db_dir.join("hash.db");
        std::fs::write(&db_path, b"this is not a sqlite database").unwrap();
        let quar_path = quarantine_db(&db_path, "containers").unwrap();
        // moved under device-root/quarantined/containers/, preserving the
        // hash dir name, and the original dir is gone
        assert_eq!(
            quar_path,
            root.join("sda1")
                .join("quarantined")
                .join("containers")
                .join("hash")
        );
        assert!(quar_path.join("hash.db").exists());
        assert!(!db_dir.exists());
        // a second DB with the same hash-dir name gets a unique suffix
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::write(&db_path, b"more garbage").unwrap();
        let quar_path2 = quarantine_db(&db_path, "containers").unwrap();
        assert_ne!(quar_path2, quar_path);
        assert!(quar_path2
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("hash-"));
        assert!(quar_path2.join("hash.db").exists());
        assert!(!db_dir.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn test_is_corruption_error() {
        let corrupt = DbError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
            Some("database disk image is malformed".to_string()),
        ));
        assert!(is_corruption_error(&corrupt));
        let notadb = DbError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOTADB),
            Some("file is not a database".to_string()),
        ));
        assert!(is_corruption_error(&notadb));
        let other = DbError::Connection("malformed database schema".to_string());
        assert!(!is_corruption_error(&other));
        let plain = DbError::Sqlite(rusqlite::Error::QueryReturnedNoRows);
        assert!(!is_corruption_error(&plain));
        let busy = DbError::Sqlite(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("database is locked".to_string()),
        ));
        assert!(is_lock_contention(&busy));
        assert!(!is_lock_contention(&plain));
        assert!(is_lock_contention(&DbError::LockTimeout("/tmp/x".into())));
    }

    #[test]
    fn test_busy_timeout_is_immediate() {
        let dir = std::env::temp_dir().join(format!(
            "peregrine-busy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (1);")
                .unwrap();
        }
        let locker = rusqlite::Connection::open(&path).unwrap();
        locker.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let t0 = std::time::Instant::now();
        let reader = rusqlite::Connection::open(&path).unwrap();
        let cfg = configure_connection(&reader);
        let sel = reader.query_row("SELECT x FROM t", [], |r| r.get::<_, i64>(0));
        let dt = t0.elapsed();
        drop(locker);
        let _ = std::fs::remove_dir_all(&dir);
        match (cfg, sel) {
            (Err(e), _) => assert!(is_lock_contention(&e), "{e}"),
            (_, Err(e)) => assert!(is_lock_contention(&DbError::from(e)), "select err"),
            (Ok(_), Ok(v)) => panic!("exclusive lock should surface SQLITE_BUSY, got {v:?}"),
        }
        assert!(
            dt.as_millis() < 250,
            "sqlite wait pinned the thread for {dt:?}"
        );
    }

    #[test]
    fn test_base64_round_trip() {
        for data in [
            b"".as_slice(),
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"\xff\x00\x80",
        ] {
            let enc = b64encode(data);
            assert_eq!(b64decode(enc.as_bytes()).unwrap(), data, "{enc}");
        }
        assert_eq!(b64encode(b"foob"), "Zm9vYg==");
    }
}
