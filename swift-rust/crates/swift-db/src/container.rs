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

//! The container broker: schema creation, pending-file puts and
//! `merge_items`, ported from `swift/container/backend.py` and the
//! `DatabaseBroker` base in `swift/common/db.py`.
//!
//! Every SQL string below is copied *character for character* from the
//! Python source: sqlite stores the original statement text in
//! `sqlite_master`, and the golden tests compare those dumps against a
//! Python-created database.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static FRESH_DB_ID_SEQ: AtomicU64 = AtomicU64::new(1);

use rusqlite::Connection;
use swift_core::pickle::{self, Value};
use swift_core::timestamp::{decode_timestamps, encode_timestamps, Timestamp};

use crate::util::{
    b64decode, b64encode, configure_connection, initialize_database, lock_parent_directory, DbError,
};
use crate::PENDING_CAP;

const SQLITE_ARG_LIMIT: usize = 999;

/// Current time as a Swift internal timestamp string (production clock).
pub(crate) fn now_internal() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    swift_core::timestamp::Timestamp::from_secs(secs)
        .map(|t| t.internal())
        .unwrap_or_else(|_| "0000000000.00000".to_string())
}
const PENDING_TIMEOUT: f64 = 10.0;

// ---- SQL scripts, verbatim from the Python source ----

const POLICY_STAT_TABLE_CREATE: &str = "
    CREATE TABLE policy_stat (
        storage_policy_index INTEGER PRIMARY KEY,
        object_count INTEGER DEFAULT 0,
        bytes_used INTEGER DEFAULT 0
    );
";

const POLICY_STAT_TRIGGER_SCRIPT: &str = "
    CREATE TRIGGER object_insert_policy_stat AFTER INSERT ON object
    BEGIN
        UPDATE policy_stat
        SET object_count = object_count + (1 - new.deleted),
            bytes_used = bytes_used + new.size
        WHERE storage_policy_index = new.storage_policy_index;
        INSERT INTO policy_stat (
            storage_policy_index, object_count, bytes_used)
        SELECT new.storage_policy_index,
               (1 - new.deleted),
               new.size
        WHERE NOT EXISTS(
            SELECT changes() as change
            FROM policy_stat
            WHERE change <> 0
        );
        UPDATE container_info
        SET hash = chexor(hash, new.name, new.created_at);
    END;

    CREATE TRIGGER object_delete_policy_stat AFTER DELETE ON object
    BEGIN
        UPDATE policy_stat
        SET object_count = object_count - (1 - old.deleted),
            bytes_used = bytes_used - old.size
        WHERE storage_policy_index = old.storage_policy_index;
        UPDATE container_info
        SET hash = chexor(hash, old.name, old.created_at);
    END;
";

const CONTAINER_INFO_TABLE_SCRIPT: &str = "
    CREATE TABLE container_info (
        account TEXT,
        container TEXT,
        created_at TEXT,
        put_timestamp TEXT DEFAULT '0',
        delete_timestamp TEXT DEFAULT '0',
        reported_put_timestamp TEXT DEFAULT '0',
        reported_delete_timestamp TEXT DEFAULT '0',
        reported_object_count INTEGER DEFAULT 0,
        reported_bytes_used INTEGER DEFAULT 0,
        hash TEXT default '00000000000000000000000000000000',
        id TEXT,
        status TEXT DEFAULT '',
        status_changed_at TEXT DEFAULT '0',
        metadata TEXT DEFAULT '',
        x_container_sync_point1 INTEGER DEFAULT -1,
        x_container_sync_point2 INTEGER DEFAULT -1,
        storage_policy_index INTEGER DEFAULT 0,
        reconciler_sync_point INTEGER DEFAULT -1
    );
";

const CONTAINER_STAT_VIEW_SCRIPT: &str = "
    CREATE VIEW container_stat
    AS SELECT ci.account, ci.container, ci.created_at,
        ci.put_timestamp, ci.delete_timestamp,
        ci.reported_put_timestamp, ci.reported_delete_timestamp,
        ci.reported_object_count, ci.reported_bytes_used, ci.hash,
        ci.id, ci.status, ci.status_changed_at, ci.metadata,
        ci.x_container_sync_point1, ci.x_container_sync_point2,
        ci.reconciler_sync_point,
        ci.storage_policy_index,
        coalesce(ps.object_count, 0) AS object_count,
        coalesce(ps.bytes_used, 0) AS bytes_used
    FROM container_info ci LEFT JOIN policy_stat ps
    ON ci.storage_policy_index = ps.storage_policy_index;

    CREATE TRIGGER container_stat_update
    INSTEAD OF UPDATE ON container_stat
    BEGIN
        UPDATE container_info
        SET account = NEW.account,
            container = NEW.container,
            created_at = NEW.created_at,
            put_timestamp = NEW.put_timestamp,
            delete_timestamp = NEW.delete_timestamp,
            reported_put_timestamp = NEW.reported_put_timestamp,
            reported_delete_timestamp = NEW.reported_delete_timestamp,
            reported_object_count = NEW.reported_object_count,
            reported_bytes_used = NEW.reported_bytes_used,
            hash = NEW.hash,
            id = NEW.id,
            status = NEW.status,
            status_changed_at = NEW.status_changed_at,
            metadata = NEW.metadata,
            x_container_sync_point1 = NEW.x_container_sync_point1,
            x_container_sync_point2 = NEW.x_container_sync_point2,
            storage_policy_index = NEW.storage_policy_index,
            reconciler_sync_point = NEW.reconciler_sync_point;
    END;
";

const OBJECT_TABLE_SCRIPT: &str = "
            CREATE TABLE object (
                ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                created_at TEXT,
                size INTEGER,
                content_type TEXT,
                etag TEXT,
                deleted INTEGER DEFAULT 0,
                storage_policy_index INTEGER DEFAULT 0
            );

            CREATE INDEX ix_object_deleted_name ON object (deleted, name);

            CREATE TRIGGER object_update BEFORE UPDATE ON object
            BEGIN
                SELECT RAISE(FAIL, 'UPDATE not allowed; DELETE and INSERT');
            END;

        ";

const SHARD_RANGE_TABLE_SCRIPT: &str = "
            CREATE TABLE shard_range (
                ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                timestamp TEXT,
                lower TEXT,
                upper TEXT,
                object_count INTEGER DEFAULT 0,
                bytes_used INTEGER DEFAULT 0,
                meta_timestamp TEXT,
                deleted INTEGER DEFAULT 0,
                state INTEGER,
                state_timestamp TEXT,
                epoch TEXT,
                reported INTEGER DEFAULT 0,
                tombstones INTEGER DEFAULT -1
            );
        ";

const SHARD_RANGE_TRIGGER_SCRIPT: &str = "
            CREATE TRIGGER shard_range_update BEFORE UPDATE ON shard_range
            BEGIN
                SELECT RAISE(FAIL, 'UPDATE not allowed; DELETE and INSERT');
            END;
        ";

/// A value read from the database, JSON-comparable.
#[derive(Debug, Clone, PartialEq)]
pub enum DbValue {
    Null,
    Int(i64),
    Text(String),
}

impl DbValue {
    /// The integer value, coercing a numeric text field.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            DbValue::Int(i) => Some(*i),
            DbValue::Text(t) => t.parse().ok(),
            DbValue::Null => None,
        }
    }

    /// The text value (an integer is rendered decimally).
    pub fn as_text(&self) -> Option<String> {
        match self {
            DbValue::Text(t) => Some(t.clone()),
            DbValue::Int(i) => Some(i.to_string()),
            DbValue::Null => None,
        }
    }

    pub(crate) fn from_sql(v: rusqlite::types::ValueRef<'_>) -> Self {
        match v {
            rusqlite::types::ValueRef::Null => DbValue::Null,
            rusqlite::types::ValueRef::Integer(i) => DbValue::Int(i),
            rusqlite::types::ValueRef::Text(t) => {
                DbValue::Text(String::from_utf8_lossy(t).into_owned())
            }
            rusqlite::types::ValueRef::Real(f) => DbValue::Text(f.to_string()),
            rusqlite::types::ValueRef::Blob(b) => {
                DbValue::Text(String::from_utf8_lossy(b).into_owned())
            }
        }
    }
}

/// `ShardName.hash_container_name`: the plain MD5 hexdigest of a container
/// name (no swift-hash prefix/suffix), used to keep shard names short and
/// stable across shard generations.
pub fn hash_container_name(container_name: &str) -> String {
    use md5::{Digest, Md5};
    let digest = Md5::digest(container_name.as_bytes());
    let mut out = String::with_capacity(32);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The hidden account holding an account's shard containers
/// (`.shards_<account>`).
pub fn shards_account_name(account: &str) -> String {
    format!(".shards_{account}")
}

fn set_info_i64(info: &mut Vec<(String, DbValue)>, key: &str, value: i64) {
    if let Some((_, v)) = info.iter_mut().find(|(k, _)| k == key) {
        *v = DbValue::Int(value);
    } else {
        info.push((key.to_string(), DbValue::Int(value)));
    }
}

fn set_info_text(info: &mut Vec<(String, DbValue)>, key: &str, value: &str) {
    if let Some((_, v)) = info.iter_mut().find(|(k, _)| k == key) {
        *v = DbValue::Text(value.to_string());
    } else {
        info.push((key.to_string(), DbValue::Text(value.to_string())));
    }
}

/// The on-disk state of a container's DB files (Python `get_db_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbState {
    /// No DB files exist.
    NotFound,
    /// A single, non-epoch DB — never sharded.
    Unsharded,
    /// Two DB files (retiring + fresh) — sharding in progress.
    Sharding,
    /// A single epoch DB whose epoch matches the own shard range, with other
    /// shard ranges present.
    Sharded,
    /// A single epoch DB but no other shard ranges (a shrunk-away container).
    Collapsed,
}

impl DbState {
    /// The lowercase name Python uses (`unsharded`/`sharding`/…).
    pub fn as_str(&self) -> &'static str {
        match self {
            DbState::NotFound => "not_found",
            DbState::Unsharded => "unsharded",
            DbState::Sharding => "sharding",
            DbState::Sharded => "sharded",
            DbState::Collapsed => "collapsed",
        }
    }
}

/// `parse_db_filename`: split a db path into `(hash, epoch, ext)`. The epoch is
/// the part after the first `_` in the name (or `None`); the extension is
/// everything from the last `.`.
pub fn parse_db_filename(path: &Path) -> (String, Option<String>, String) {
    let fname = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (name, ext) = match fname.rfind('.') {
        Some(i) => (fname[..i].to_string(), fname[i..].to_string()),
        None => (fname.clone(), String::new()),
    };
    let mut parts = name.splitn(2, '_');
    let hash = parts.next().unwrap_or("").to_string();
    let epoch = parts.next().map(|s| s.to_string());
    (hash, epoch, ext)
}

/// `make_db_file_path`: rewrite a db path's filename with the given epoch
/// (normalized to a Timestamp's `.normal` form), or drop the epoch if `None`.
pub fn make_db_file_path(db_path: &Path, epoch: Option<&str>) -> Result<PathBuf, DbError> {
    let (hash, _, ext) = parse_db_filename(db_path);
    let dir = db_path.parent().unwrap_or_else(|| Path::new(""));
    match epoch {
        None => Ok(dir.join(format!("{hash}{ext}"))),
        Some(e) => {
            let normal = e
                .parse::<Timestamp>()
                .map_err(|_| DbError::Connection(format!("invalid epoch {e}")))?
                .normal();
            Ok(dir.join(format!("{hash}_{normal}{ext}")))
        }
    }
}

/// `get_db_files`: the sorted (ascending) list of `<hash>[_<epoch>].db` files
/// that actually exist in `db_path`'s directory and match its hash.
pub fn get_db_files(db_path: &Path) -> Vec<PathBuf> {
    let dir = db_path.parent().unwrap_or_else(|| Path::new("."));
    let (match_hash, _, _) = parse_db_filename(db_path);
    let mut results: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            let (hash, _, ext) = parse_db_filename(&p);
            if ext == ".db" && hash == match_hash {
                results.push(p);
            }
        }
    }
    results.sort();
    results
}

/// `ShardName` / `ShardRange.make_path`: the path used as a shard container's
/// name, `"<shards_account>/<root>-<md5(parent)>-<ts>-<index>"`. `timestamp`
/// is the internal-form timestamp.
pub fn make_shard_name(
    shards_account: &str,
    root_container: &str,
    parent_container: &str,
    timestamp: &str,
    index: u64,
) -> String {
    format!(
        "{shards_account}/{root_container}-{}-{timestamp}-{index}",
        hash_container_name(parent_container)
    )
}

/// A shard boundary found by [`ContainerBroker::find_shard_ranges`], the Rust
/// form of Python's `{'index','lower','upper','object_count'}` dict.
#[derive(Debug, Clone, PartialEq)]
pub struct FoundShardRange {
    pub index: usize,
    pub lower: String,
    pub upper: String,
    pub object_count: i64,
}

/// One row-shaped object update record, the Rust form of the dicts fed to
/// `merge_items`.
#[derive(Debug, Clone)]
pub struct ObjectRecord {
    pub name: String,
    pub created_at: String,
    pub size: i64,
    pub content_type: String,
    pub etag: String,
    pub deleted: i64,
    pub storage_policy_index: i64,
    pub ctype_timestamp: Option<String>,
    pub meta_timestamp: Option<String>,
}

/// The Rust `ContainerBroker`.
pub struct ContainerBroker {
    db_file: PathBuf,
    account: String,
    container: String,
    conn: Option<Connection>,
    /// When set, always open exactly this DB file instead of resolving the
    /// freshest epoch DB (Python's `force_db_file`). Used to read the retiring
    /// DB during cleaving.
    force_db_file: Option<PathBuf>,
}

impl ContainerBroker {
    pub fn new(db_file: &Path, account: &str, container: &str) -> Self {
        ContainerBroker {
            db_file: db_file.to_path_buf(),
            account: account.to_string(),
            container: container.to_string(),
            conn: None,
            force_db_file: None,
        }
    }

    /// Fill `account`/`container` from `container_stat` when the constructor
    /// was given empty strings (REPLICATE RPC opens `/device/part/hash` with
    /// no path identity). Without this, `get_own_shard_range` misses the own
    /// row and `get_db_state` reports `unsharded` on a SHARDED epoch DB, so
    /// object usync is not skipped (probe L2311).
    pub fn hydrate_account_container(&mut self) -> Result<(), DbError> {
        if !self.account.is_empty() && !self.container.is_empty() {
            return Ok(());
        }
        self.commit_pending()?;
        let (acct, cont): (String, String) = {
            let conn = self.conn()?;
            conn.query_row(
                "SELECT account, container FROM container_stat",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?
        };
        if self.account.is_empty() {
            self.account = acct;
        }
        if self.container.is_empty() {
            self.container = cont;
        }
        Ok(())
    }

    /// A broker that always operates on exactly `db_file` (never re-resolves to
    /// a fresher epoch DB). Used to read the retiring DB while cleaving.
    pub fn new_forced(db_file: &Path, account: &str, container: &str) -> Self {
        let mut b = ContainerBroker::new(db_file, account, container);
        b.force_db_file = Some(db_file.to_path_buf());
        b
    }

    /// A forced broker over this broker's retiring DB (the lower-epoch file),
    /// or `None` when there is no separate retiring DB (not sharding).
    pub fn retiring_broker(&self) -> Option<ContainerBroker> {
        let files = self.db_files();
        if files.len() < 2 {
            return None;
        }
        Some(ContainerBroker::new_forced(
            &files[files.len() - 2],
            &self.account,
            &self.container,
        ))
    }

    pub fn db_file(&self) -> &Path {
        &self.db_file
    }

    /// Whether any epoch/hash DB for this container exists. Python
    /// `ContainerBroker.db_file` is the freshest epoch file; after
    /// `set_sharded_state` the constructor `<hash>.db` path is unlinked, so
    /// existence checks must not use [`Self::db_file`].
    pub fn db_exists(&self) -> bool {
        !self.db_files().is_empty()
    }

    pub fn pending_file(&self) -> PathBuf {
        PathBuf::from(format!("{}.pending", self.current_db_file().display()))
    }

    fn conn(&mut self) -> Result<&Connection, DbError> {
        if self.conn.is_none() {
            // Open the freshest (highest-epoch) DB file, so a container that
            // has been moved to the sharding/sharded state reads and writes the
            // fresh DB, not the retiring one (DatabaseBroker.db_file).
            let dbf = self.current_db_file();
            if !dbf.exists() {
                return Err(DbError::Connection(format!(
                    "{}: DB doesn't exist",
                    dbf.display()
                )));
            }
            let conn = Connection::open(&dbf)?;
            configure_connection(&conn)?;
            self.conn = Some(conn);
        }
        Ok(self.conn.as_ref().unwrap())
    }

    /// The db files that exist on disk for this broker's hash, ascending by
    /// epoch (`DatabaseBroker.db_files`).
    pub fn db_files(&self) -> Vec<PathBuf> {
        get_db_files(&self.db_file)
    }

    /// The primary (freshest, highest-epoch) db file, or the constructor path
    /// if none exist. A forced broker always returns its explicit db file
    /// (`DatabaseBroker.db_file` with `force_db_file`).
    pub fn current_db_file(&self) -> PathBuf {
        if let Some(forced) = &self.force_db_file {
            return forced.clone();
        }
        self.db_files()
            .last()
            .cloned()
            .unwrap_or_else(|| self.db_file.clone())
    }

    /// The epoch of the primary db file, if any (`DatabaseBroker.db_epoch`).
    pub fn db_epoch(&self) -> Option<String> {
        parse_db_filename(&self.current_db_file()).1
    }

    /// Drop the cached connection so the next access re-resolves the primary
    /// db file (`DatabaseBroker.reload_db_files`).
    pub fn reload_db_files(&mut self) {
        self.conn = None;
    }

    /// Whether any non-own, non-deleted shard range exists
    /// (`has_other_shard_ranges`).
    pub fn has_other_shard_ranges(&mut self) -> Result<bool, DbError> {
        use rusqlite::OptionalExtension;
        let path = self.path();
        let conn = self.conn()?;
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM shard_range WHERE deleted = 0 AND name != ?1 LIMIT 1",
                [path],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// The on-disk sharding state (`get_db_state`).
    pub fn get_db_state(&mut self) -> Result<DbState, DbError> {
        let files = self.db_files();
        if files.is_empty() {
            return Ok(DbState::NotFound);
        }
        if files.len() > 1 {
            return Ok(DbState::Sharding);
        }
        let Some(db_epoch) = self.db_epoch() else {
            return Ok(DbState::Unsharded);
        };
        let own = self.get_own_shard_range(false)?.expect("default own range");
        // compare normalized epochs (filename epoch is Timestamp.normal)
        let own_epoch_normal = own
            .epoch
            .as_deref()
            .and_then(|e| e.parse::<Timestamp>().ok())
            .map(|t| t.normal());
        let db_epoch_normal = db_epoch.parse::<Timestamp>().ok().map(|t| t.normal());
        if db_epoch_normal != own_epoch_normal {
            // A newer-timestamp merge can drop own.epoch onto an epoch file
            // (shrink-to-root compactible). If own is already an acceptor,
            // the filename epoch is authoritative: HEAD must not report
            // unsharded with object_count 1 (probe test_shrinking L2088).
            // A SHARDING own still mismatches so the first cleave starts.
            let acceptor = !crate::shard::CLEAVING_STATES.contains(&own.state);
            if !(acceptor && own_epoch_normal.is_none() && db_epoch_normal.is_some()) {
                return Ok(DbState::Unsharded);
            }
        }
        if !self.has_other_shard_ranges()? {
            return Ok(DbState::Collapsed);
        }
        Ok(DbState::Sharded)
    }

    /// All shard range records, including own and deleted
    /// (`get_all_shard_range_data`).
    pub fn get_all_shard_range_data(&mut self) -> Result<Vec<crate::shard::ShardRange>, DbError> {
        self.get_shard_ranges(&GetShardRangesArgs {
            include_own: true,
            include_deleted: true,
            ..Default::default()
        })
    }

    /// `enable_sharding`: set the own shard range to SHARDING with the given
    /// epoch and persist it, returning the updated range.
    pub fn enable_sharding(&mut self, epoch: &str) -> Result<crate::shard::ShardRange, DbError> {
        let mut own = self.get_own_shard_range(false)?.expect("default own range");
        // update_state(SHARDING, epoch): state, state_timestamp, reported=0
        own.state = crate::shard::state::SHARDING;
        own.state_timestamp = epoch.to_string();
        own.reported = 0;
        own.epoch = Some(epoch.to_string());
        self.merge_shard_ranges(vec![own.clone()])?;
        Ok(own)
    }

    /// `set_sharding_state`: UNSHARDED → SHARDING. Creates a fresh DB named
    /// `<hash>_<epoch>.db` seeded from the retiring DB (container_stat,
    /// metadata, shard ranges, and a continued max ROWID), then reloads so the
    /// broker uses the fresh DB. Returns whether the transition succeeded.
    ///
    /// Deferred vs Python: copying replication sync points into the fresh DB
    /// (a replication-convergence optimisation, not required for correctness).
    pub fn set_sharding_state(&mut self) -> Result<bool, DbError> {
        let Some(epoch) = self.get_own_shard_range(false)?.and_then(|sr| sr.epoch) else {
            return Ok(false); // missing epoch
        };
        if self.get_db_state()? != DbState::Unsharded {
            return Ok(false);
        }
        let info = self.get_info()?;
        let get = |k: &str| {
            info.iter()
                .find(|(n, _)| n == k)
                .and_then(|(_, v)| v.as_text())
                .unwrap_or_default()
        };
        let put_timestamp = get("put_timestamp");
        let storage_policy_index = info
            .iter()
            .find(|(n, _)| n == "storage_policy_index")
            .and_then(|(_, v)| v.as_i64())
            .unwrap_or(0);
        let created_at = get("created_at");
        let delete_timestamp = get("delete_timestamp");
        let status = get("status");
        let status_changed_at = get("status_changed_at");
        let max_row = self.get_max_row()?.unwrap_or(-1);
        let metadata = self.metadata()?;
        let all_ranges = self.get_all_shard_range_data()?;

        // Build the fresh DB in a temp file.
        let dir = self.db_file.parent().unwrap_or_else(|| Path::new("."));
        let tmp = dir.join(format!("fresh-{}.db.tmp", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        {
            let mut fresh = ContainerBroker::new(&tmp, &self.account, &self.container);
            // Python `initialize()` assigns a new UUID. A hardcoded id made
            // every replica's fresh DB share `id=shardid`, so cleaving
            // contexts collapsed to one sysmeta key on replicate.
            let fresh_id = format!(
                "{}-{}-{}",
                now_internal(),
                std::process::id(),
                FRESH_DB_ID_SEQ.fetch_add(1, Ordering::Relaxed)
            );
            fresh.initialize(&put_timestamp, storage_policy_index, &created_at, &fresh_id)?;
            fresh.update_metadata(&metadata)?;
            if !all_ranges.is_empty() {
                fresh.merge_shard_ranges(all_ranges)?;
            }
            let conn = fresh.conn()?;
            // Continue the ROWID from where the retiring DB ended so a peer in
            // sync with the retiring DB is in sync with the fresh DB.
            if max_row >= 0 {
                conn.execute(
                    "INSERT INTO object (ROWID, name, created_at, size, content_type, etag) \
                     VALUES (?1, 'tmp_sharding', ?2, 0, '', ?3)",
                    rusqlite::params![
                        max_row,
                        Timestamp::now().internal(),
                        "d41d8cd98f00b204e9800998ecf8427e"
                    ],
                )?;
                conn.execute("DELETE FROM object WHERE ROWID = ?1", [max_row])?;
            }
            // Sync the parts of container_stat the broker API won't regenerate.
            conn.execute(
                "UPDATE container_stat SET created_at=?1, delete_timestamp=?2, \
                 status=?3, status_changed_at=?4",
                rusqlite::params![created_at, delete_timestamp, status, status_changed_at],
            )?;
        }

        // Rename into place as the fresh epoch DB and reload.
        let fresh_path = make_db_file_path(&self.db_file, Some(&epoch))?;
        std::fs::rename(&tmp, &fresh_path)
            .map_err(|e| DbError::Connection(format!("rename fresh db: {e}")))?;
        self.reload_db_files();
        Ok(true)
    }

    /// `set_sharded_state`: SHARDING → SHARDED. Unlinks the retiring (lower-
    /// epoch) DB, leaving only the fresh epoch DB. Also bumps the own shard
    /// range row to `SHARDED` so `info`/`show` match `get_db_state`.
    /// Returns whether it succeeded.
    pub fn set_sharded_state(&mut self) -> Result<bool, DbError> {
        if self.get_db_state()? != DbState::Sharding {
            return Ok(false);
        }
        self.reload_db_files();
        let files = self.db_files();
        if files.len() < 2 {
            return Ok(false);
        }
        let retiring = &files[files.len() - 2];
        match std::fs::remove_file(retiring) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(DbError::Connection(format!("unlink retiring db: {e}"))),
        }
        self.reload_db_files();
        if self.db_files().len() >= 2 {
            return Ok(false);
        }
        // Align own-range state text with on-disk SHARDED for a *sharding*
        // root. Python `set_sharded_state` does not rewrite own state;
        // shrinking donors are already SHRUNK and must stay SHRUNK (probe
        // L2031 `assertEqual(SHRUNK, own_sr.state)` — 80 != 70).
        if let Some(mut own) = self.get_own_shard_range(false)? {
            if own.state != crate::shard::state::SHARDED
                && own.state != crate::shard::state::SHRUNK
                && own.state != crate::shard::state::SHRINKING
            {
                own.state = crate::shard::state::SHARDED;
                let ts = Timestamp::now().internal();
                own.state_timestamp = ts.clone();
                own.meta_timestamp = ts;
                self.merge_shard_ranges(vec![own])?;
            }
        }
        Ok(true)
    }

    /// Port of `DatabaseBroker.initialize` + `ContainerBroker._initialize`:
    /// build the DB in a temp file with fast pragmas, fsync, then rename
    /// into place under the parent lock.
    ///
    /// `created_at` and `db_id` are explicit for deterministic testing;
    /// production callers pass `Timestamp::now().internal()` and a UUID.
    pub fn initialize(
        &mut self,
        put_timestamp: &str,
        storage_policy_index: i64,
        created_at: &str,
        db_id: &str,
    ) -> Result<(), DbError> {
        let account = self.account.clone();
        let container = self.container.clone();
        let created_at = created_at.to_string();
        let db_id = db_id.to_string();
        let put_timestamp = put_timestamp.to_string();
        initialize_database(&self.db_file, PENDING_TIMEOUT, move |conn| {
            // _initialize: object table, policy_stat, container_info +
            // view, shard ranges
            conn.execute_batch(&format!(
                "{OBJECT_TABLE_SCRIPT}{POLICY_STAT_TRIGGER_SCRIPT}"
            ))?;
            conn.execute_batch(POLICY_STAT_TABLE_CREATE)?;
            conn.execute(
                "\n            INSERT INTO policy_stat (storage_policy_index)\n            VALUES (?)\n        ",
                [storage_policy_index],
            )?;
            conn.execute_batch(&format!(
                "{CONTAINER_INFO_TABLE_SCRIPT}{CONTAINER_STAT_VIEW_SCRIPT}"
            ))?;
            conn.execute(
                "\n            INSERT INTO container_info (account, container, created_at, id,\n                put_timestamp, status_changed_at, storage_policy_index)\n            VALUES (?, ?, ?, ?, ?, ?, ?);\n        ",
                rusqlite::params![
                    account,
                    container,
                    created_at,
                    db_id,
                    put_timestamp,
                    put_timestamp,
                    storage_policy_index
                ],
            )?;
            conn.execute_batch(SHARD_RANGE_TABLE_SCRIPT)?;
            conn.execute_batch(SHARD_RANGE_TRIGGER_SCRIPT)?;
            Ok(())
        })
    }

    /// Port of `ContainerBroker.put_object`.
    #[allow(clippy::too_many_arguments)]
    pub fn put_object(
        &mut self,
        name: &str,
        timestamp: &str,
        size: i64,
        content_type: &str,
        etag: &str,
        deleted: i64,
        storage_policy_index: i64,
        ctype_timestamp: Option<&str>,
        meta_timestamp: Option<&str>,
    ) -> Result<(), DbError> {
        let record = ObjectRecord {
            name: name.to_string(),
            created_at: timestamp.to_string(),
            size,
            content_type: content_type.to_string(),
            etag: etag.to_string(),
            deleted,
            storage_policy_index,
            ctype_timestamp: ctype_timestamp.map(str::to_string),
            meta_timestamp: meta_timestamp.map(str::to_string),
        };
        self.put_record(record)
    }

    /// Port of `ContainerBroker.delete_object`.
    pub fn delete_object(
        &mut self,
        name: &str,
        timestamp: &str,
        storage_policy_index: i64,
    ) -> Result<(), DbError> {
        // Probe L2094: collapsed roots live on `<hash>_<epoch>.db`. Writing
        // only the pending file and returning lets a subsequent DELETE
        // container race a replica whose GET never commit_pending()d. Merge
        // the tombstone into the freshest epoch immediately (same row as
        // Python after `_commit_puts`).
        let ts = if timestamp.is_empty() {
            swift_core::timestamp::Timestamp::now().internal()
        } else {
            timestamp.to_string()
        };
        let record = ObjectRecord {
            name: name.to_string(),
            created_at: ts,
            size: 0,
            content_type: "application/deleted".to_string(),
            etag: "noetag".to_string(),
            deleted: 1,
            storage_policy_index,
            ctype_timestamp: None,
            meta_timestamp: None,
        };
        // Pending PUTs must be merged before the tombstone. Otherwise a
        // later read commits the stale pending record after this DELETE and
        // resurrects the object.
        self.commit_pending()?;
        self.merge_items(vec![record])
    }

    /// Port of `ContainerBroker.remove_objects`: hard-DELETE object rows in
    /// `(lower, upper]` (empty bounds = -inf / +inf), optionally limited by
    /// max ROWID. Used after a successful misplaced-object move so the source
    /// no longer carries the rows (not a tombstone write).
    pub fn remove_objects(
        &mut self,
        lower: &str,
        upper: &str,
        max_row: Option<i64>,
    ) -> Result<u64, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let mut sql = String::from("DELETE FROM object WHERE deleted IN (0, 1)");
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(mr) = max_row {
            sql.push_str(" AND ROWID <= ?");
            params.push(Box::new(mr));
        }
        if !lower.is_empty() {
            sql.push_str(" AND name > ?");
            params.push(Box::new(lower.to_string()));
        }
        if !upper.is_empty() {
            sql.push_str(" AND name <= ?");
            params.push(Box::new(upper.to_string()));
        }
        let n = conn.execute(&sql, rusqlite::params_from_iter(params.iter()))?;
        Ok(n as u64)
    }

    /// Hard-DELETE every row for a single object name (all policies).
    pub fn remove_object_named(&mut self, name: &str) -> Result<u64, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let n = conn.execute(
            "DELETE FROM object WHERE deleted IN (0, 1) AND name = ?",
            [name],
        )?;
        Ok(n as u64)
    }

    /// `make_tuple_for_pickle` for a container record.
    fn record_to_pickle_value(record: &ObjectRecord) -> Value {
        let opt = |o: &Option<String>| match o {
            Some(s) => Value::Str(s.clone()),
            None => Value::None,
        };
        Value::Tuple(vec![
            Value::Str(record.name.clone()),
            Value::Str(record.created_at.clone()),
            Value::Int(record.size),
            Value::Str(record.content_type.clone()),
            Value::Str(record.etag.clone()),
            Value::Int(record.deleted),
            Value::Int(record.storage_policy_index),
            opt(&record.ctype_timestamp),
            opt(&record.meta_timestamp),
        ])
    }

    /// `_commit_puts_load` for one pending tuple.
    fn record_from_pickle_value(value: &Value) -> Result<ObjectRecord, DbError> {
        let items = match value {
            Value::Tuple(items) | Value::List(items) => items,
            other => return Err(DbError::Connection(format!("bad pending entry: {other:?}"))),
        };
        if items.len() < 6 {
            return Err(DbError::Connection("short pending entry".to_string()));
        }
        fn s(v: &Value) -> Result<String, DbError> {
            match v {
                Value::Str(s) => Ok(s.clone()),
                Value::Bytes(b) => Ok(String::from_utf8_lossy(b).into_owned()),
                other => Err(DbError::Connection(format!("bad string value {other:?}"))),
            }
        }
        fn i(v: &Value) -> Result<i64, DbError> {
            match v {
                Value::Int(i) => Ok(*i),
                other => Err(DbError::Connection(format!("bad int value {other:?}"))),
            }
        }
        fn opt_s(v: Option<&Value>) -> Result<Option<String>, DbError> {
            match v {
                None | Some(Value::None) => Ok(None),
                Some(other) => Ok(Some(s(other)?)),
            }
        }
        Ok(ObjectRecord {
            name: s(&items[0])?,
            created_at: s(&items[1])?,
            size: i(&items[2])?,
            content_type: s(&items[3])?,
            etag: s(&items[4])?,
            deleted: i(&items[5])?,
            storage_policy_index: if items.len() > 6 { i(&items[6])? } else { 0 },
            ctype_timestamp: opt_s(items.get(7))?,
            meta_timestamp: opt_s(items.get(8))?,
        })
    }

    /// Port of `DatabaseBroker.put_record`: append to the pending file
    /// under the parent lock, or merge immediately when the pending file
    /// is over `PENDING_CAP`.
    pub fn put_record(&mut self, record: ObjectRecord) -> Result<(), DbError> {
        // Python `broker.db_file` is the freshest epoch. After
        // `set_sharded_state` the constructor `<hash>.db` is unlinked
        // (probe L2094 DELETE on a collapsed root).
        if !self.db_exists() {
            return Err(DbError::Connection(format!(
                "{}: DB doesn't exist",
                self.current_db_file().display()
            )));
        }
        let pending = self.pending_file();
        let _lock = lock_parent_directory(&pending, PENDING_TIMEOUT)?;
        let pending_size = std::fs::metadata(&pending)
            .map(|m| m.len())
            .unwrap_or(0);
        if pending_size > PENDING_CAP {
            self.commit_puts(vec![record])
        } else {
            let blob = pickle::dumps(&Self::record_to_pickle_value(&record))?;
            let mut fp = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&pending)?;
            fp.write_all(b":")?;
            fp.write_all(b64encode(&blob).as_bytes())?;
            fp.flush()?;
            Ok(())
        }
    }

    /// Port of `_commit_puts` (lock assumed held by the caller path):
    /// fold the pending file plus `extra` into the object table.
    fn commit_puts(&mut self, extra: Vec<ObjectRecord>) -> Result<(), DbError> {
        let pending = self.pending_file();
        let mut item_list = Vec::new();
        let raw = match std::fs::read(&pending) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(DbError::Io(e)),
        };
        for entry in raw.split(|&b| b == b':') {
            if entry.is_empty() {
                continue;
            }
            // invalid entries are skipped with a log in Python
            if let Ok(blob) = b64decode(entry) {
                if let Ok(value) = pickle::loads(&blob) {
                    if let Ok(record) = Self::record_from_pickle_value(&value) {
                        item_list.push(record);
                    }
                }
            }
        }
        item_list.extend(extra);
        if !item_list.is_empty() {
            self.merge_items(item_list)?;
        }
        if !raw.is_empty() {
            std::fs::write(&pending, b"")?;
        }
        Ok(())
    }

    /// `_commit_puts_stale_ok` equivalent used before reads.
    pub fn commit_pending(&mut self) -> Result<(), DbError> {
        let pending = self.pending_file();
        if !pending.exists() {
            return Ok(());
        }
        let _lock = lock_parent_directory(&pending, PENDING_TIMEOUT)?;
        self.commit_puts(Vec::new())
    }

    /// Port of `ContainerBroker.merge_items`.
    pub fn merge_items(&mut self, mut item_list: Vec<ObjectRecord>) -> Result<(), DbError> {
        let conn = self.conn()?;
        // fresh schemas always have ix_object_deleted_name (db version 1)
        let has_index: bool = conn
            .prepare("SELECT name FROM sqlite_master WHERE name = 'ix_object_deleted_name'")?
            .exists([])?;
        let query_mod = if has_index {
            " deleted IN (0, 1) AND "
        } else {
            ""
        };

        conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| -> Result<(), DbError> {
            // fetch existing records for the incoming names
            let mut records: Vec<((String, i64), ObjectRecord)> = Vec::new();
            for chunk in item_list.chunks(SQLITE_ARG_LIMIT) {
                let placeholders = vec!["?"; chunk.len()].join(",");
                let sql = format!(
                    "SELECT name, created_at, size, content_type,\
                     etag, deleted, storage_policy_index \
                     FROM object WHERE {query_mod} name IN ({placeholders})"
                );
                let mut stmt = conn.prepare(&sql)?;
                let names: Vec<&str> = chunk.iter().map(|r| r.name.as_str()).collect();
                let rows = stmt.query_map(rusqlite::params_from_iter(names), |row| {
                    Ok(ObjectRecord {
                        name: row.get(0)?,
                        created_at: row.get(1)?,
                        size: row.get(2)?,
                        content_type: row.get(3)?,
                        etag: row.get(4)?,
                        deleted: row.get(5)?,
                        storage_policy_index: row.get(6)?,
                        ctype_timestamp: None,
                        meta_timestamp: None,
                    })
                })?;
                for row in rows {
                    let rec = row?;
                    records.retain(|((n, spi), _)| {
                        !(n == &rec.name && *spi == rec.storage_policy_index)
                    });
                    records.push(((rec.name.clone(), rec.storage_policy_index), rec));
                }
            }
            let lookup = |records: &[((String, i64), ObjectRecord)],
                          ident: &(String, i64)|
             -> Option<ObjectRecord> {
                records
                    .iter()
                    .find(|(k, _)| k == ident)
                    .map(|(_, r)| r.clone())
            };

            // sort into deletes and adds, newest attributes winning
            let mut to_delete: Vec<(String, i64)> = Vec::new();
            let mut to_add: Vec<((String, i64), ObjectRecord)> = Vec::new();
            for mut item in std::mem::take(&mut item_list) {
                let ident = (item.name.clone(), item.storage_policy_index);
                let existing = lookup(&records, &ident);
                if update_new_item_from_existing(&mut item, existing.as_ref()) {
                    if lookup(&records, &ident).is_some() && !to_delete.contains(&ident) {
                        to_delete.push(ident.clone());
                    }
                    // Python's `to_add` is an insertion-ordered dict: a
                    // duplicate name in the batch keeps its FIRST-appearance
                    // position with a merged value. Update in place rather than
                    // remove+push (which would move it to the end and assign a
                    // different ROWID than Python -> replication order skew).
                    if let Some(pos) = to_add.iter().position(|(k, _)| k == &ident) {
                        let prior = to_add[pos].1.clone();
                        update_new_item_from_existing(&mut item, Some(&prior));
                        to_add[pos].1 = item;
                    } else {
                        to_add.push((ident, item));
                    }
                }
            }
            for (name, spi) in &to_delete {
                conn.execute(
                    &format!(
                        "DELETE FROM object WHERE {query_mod}name=? AND storage_policy_index=?"
                    ),
                    rusqlite::params![name, spi],
                )?;
            }
            for (_, rec) in &to_add {
                conn.execute(
                    "INSERT INTO object (name, created_at, size, content_type,\
                     etag, deleted, storage_policy_index) \
                     VALUES (?, ?, ?, ?, ?, ?, ?)",
                    rusqlite::params![
                        rec.name,
                        rec.created_at,
                        rec.size,
                        rec.content_type,
                        rec.etag,
                        rec.deleted,
                        rec.storage_policy_index
                    ],
                )?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                conn.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Port of `_do_get_info_query` + the `db_state` decoration from
    /// `get_info` (always `unsharded` at this stage).
    pub fn get_info(&mut self) -> Result<Vec<(String, DbValue)>, DbError> {
        self.commit_pending()?;
        let mut out = {
            let conn = self.conn()?;
            let sql = "
                    SELECT account, container, created_at, put_timestamp,
                        delete_timestamp, status, status_changed_at,
                        object_count, bytes_used,
                        reported_put_timestamp, reported_delete_timestamp,
                        reported_object_count, reported_bytes_used, hash,
                        id, x_container_sync_point1, x_container_sync_point2, storage_policy_index
                        FROM container_stat
                ";
            let mut stmt = conn.prepare(sql)?;
            let names: Vec<String> = stmt
                .column_names()
                .into_iter()
                .map(str::to_string)
                .collect();
            let mut rows = stmt.query([])?;
            let row = rows
                .next()?
                .ok_or_else(|| DbError::Connection("no container_stat row".to_string()))?;
            let mut out = Vec::with_capacity(names.len() + 1);
            for (i, name) in names.iter().enumerate() {
                out.push((name.clone(), DbValue::from_sql(row.get_ref(i)?)));
            }
            out
        };
        // Python `_get_alternate_object_stats` + `db_state`.
        let state = self.get_db_state()?;
        match state {
            DbState::Sharding => {
                if let Some(mut retiring) = self.retiring_broker() {
                    retiring.commit_pending()?;
                    let (oc, bu) = {
                        let conn = retiring.conn()?;
                        let oc: i64 = conn.query_row(
                            "SELECT object_count FROM container_stat",
                            [],
                            |r| r.get(0),
                        )?;
                        let bu: i64 = conn.query_row(
                            "SELECT bytes_used FROM container_stat",
                            [],
                            |r| r.get(0),
                        )?;
                        (oc, bu)
                    };
                    set_info_i64(&mut out, "object_count", oc);
                    set_info_i64(&mut out, "bytes_used", bu);
                }
            }
            DbState::Sharded if self.is_root_container()? => {
                let (bytes, count) = self.get_shard_usage()?;
                set_info_i64(&mut out, "object_count", count);
                set_info_i64(&mut out, "bytes_used", bytes);
            }
            _ => {}
        }
        set_info_text(&mut out, "db_state", state.as_str());
        Ok(out)
    }

    /// Update the reported_* stats after a successful account update, so the
    /// next updater sweep sees no change (Python `ContainerBroker.reported`).
    pub fn reported(
        &mut self,
        put_timestamp: &str,
        delete_timestamp: &str,
        object_count: i64,
        bytes_used: i64,
    ) -> Result<(), DbError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE container_stat
                SET reported_put_timestamp = ?1, reported_delete_timestamp = ?2,
                    reported_object_count = ?3, reported_bytes_used = ?4",
            rusqlite::params![put_timestamp, delete_timestamp, object_count, bytes_used],
        )?;
        Ok(())
    }

    /// `_get_next_shard_range_upper`: the name of the `shard_size`-th live
    /// object strictly after `last_upper` (the next shard boundary), or `None`
    /// if fewer than `shard_size` objects remain. `last_upper == ""` means the
    /// namespace minimum, so `name > ''` selects every object.
    fn next_shard_range_upper(
        &mut self,
        shard_size: i64,
        last_upper: &str,
    ) -> Result<Option<String>, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT name FROM object WHERE name > ?1 AND deleted = 0 \
             ORDER BY name LIMIT 1 OFFSET ?2",
        )?;
        let offset = (shard_size - 1).max(0);
        let mut rows = stmt.query(rusqlite::params![last_upper, offset])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get::<_, String>(0)?)),
            None => Ok(None),
        }
    }

    /// `ContainerBroker.find_shard_ranges`: scan the object table for shard
    /// boundaries of roughly `shard_size` objects each, extending the final
    /// shard to absorb a tail smaller than `minimum_shard_size`. Returns the
    /// found ranges (ascending) and whether the last range reaches the
    /// namespace end (the "done" flag). Does not modify the DB.
    ///
    /// A range's `lower`/`upper` are object names, with `""` denoting the
    /// namespace minimum (first range's lower) or maximum (final range's
    /// upper). Deferred vs Python: `existing_ranges` continuation and the
    /// `own_shard_range` sub-namespace (this assumes a root container spanning
    /// the whole namespace).
    /// The broker's own namespace path, `"account/container"` — the name of
    /// its own shard range.
    pub fn path(&self) -> String {
        format!("{}/{}", self.account, self.container)
    }

    /// `merge_shard_ranges`: merge shard ranges into the `shard_range` table
    /// with newest-wins semantics (`sift_shard_ranges`/`merge_shards`). Existing
    /// rows that are superseded are deleted and the winning rows inserted.
    pub fn merge_shard_ranges(
        &mut self,
        ranges: Vec<crate::shard::ShardRange>,
    ) -> Result<(), DbError> {
        if ranges.is_empty() {
            return Ok(());
        }
        let conn = self.conn()?;
        // fetch existing rows for the incoming names
        let names: Vec<String> = ranges.iter().map(|r| r.name.clone()).collect();
        let mut existing: HashMap<String, crate::shard::ShardRange> = HashMap::new();
        for chunk in names.chunks(SQLITE_ARG_LIMIT) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "SELECT {} FROM shard_range WHERE deleted IN (0, 1) AND name IN ({placeholders})",
                crate::shard::SHARD_RANGE_KEYS.join(", ")
            );
            let mut stmt = conn.prepare(&sql)?;
            let params = rusqlite::params_from_iter(chunk.iter());
            let mut rows = stmt.query(params)?;
            while let Some(row) = rows.next()? {
                let sr = shard_range_from_row(row)?;
                existing.insert(sr.name.clone(), sr);
            }
        }
        let (to_add, to_delete) = crate::shard::sift_shard_ranges(ranges, &existing);

        conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| -> Result<(), DbError> {
            for name in &to_delete {
                conn.execute(
                    "DELETE FROM shard_range WHERE deleted in (0, 1) AND name = ?1",
                    [name],
                )?;
            }
            for sr in &to_add {
                conn.execute(
                    "INSERT INTO shard_range (name, timestamp, lower, upper, object_count, \
                     bytes_used, meta_timestamp, deleted, state, state_timestamp, epoch, \
                     reported, tombstones) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                    rusqlite::params![
                        sr.name,
                        sr.timestamp,
                        sr.lower,
                        sr.upper,
                        sr.object_count,
                        sr.bytes_used,
                        sr.meta_timestamp,
                        sr.deleted,
                        sr.state,
                        sr.state_timestamp,
                        sr.epoch,
                        sr.reported,
                        sr.tombstones,
                    ],
                )?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                conn.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// `get_shard_ranges`: query persisted shard ranges with the same filters
    /// as Python (states, deleted, marker/end_marker or includes, own/others),
    /// sorted by `ShardRange.sort_key`. `fill_gaps` synthesises a copy of the
    /// own shard range to fill a trailing gap (Python listing/updating).
    pub fn get_shard_ranges(
        &mut self,
        args: &GetShardRangesArgs,
    ) -> Result<Vec<crate::shard::ShardRange>, DbError> {
        // marker/end_marker sanity (Namespace ordering)
        let mut marker = args.marker.clone();
        let mut end_marker = args.end_marker.clone();
        if args.reverse {
            std::mem::swap(&mut marker, &mut end_marker);
        }
        if let (Some(m), Some(e)) = (&marker, &end_marker) {
            if m >= e {
                return Ok(Vec::new());
            }
        }

        let path = self.path();
        let mut conditions: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if !args.include_deleted {
            conditions.push("deleted=0".to_string());
        }
        if let Some(states) = &args.states {
            if !states.is_empty() {
                let ph = vec!["?"; states.len()].join(",");
                conditions.push(format!("state in ({ph})"));
                for s in states {
                    params.push(Box::new(*s));
                }
            }
        }
        if !args.include_own {
            conditions.push("name != ?".to_string());
            params.push(Box::new(path.clone()));
        }
        if args.exclude_others {
            conditions.push("name = ?".to_string());
            params.push(Box::new(path.clone()));
        }
        match &args.includes {
            Some(inc) => {
                conditions.push("lower < ?".to_string());
                params.push(Box::new(inc.clone()));
                conditions.push("(upper = '' OR upper >= ?)".to_string());
                params.push(Box::new(inc.clone()));
            }
            None => {
                if let Some(e) = &end_marker {
                    conditions.push("lower < ?".to_string());
                    params.push(Box::new(e.clone()));
                }
                if let Some(m) = &marker {
                    conditions.push("(upper = '' OR upper > ?)".to_string());
                    params.push(Box::new(m.clone()));
                }
            }
        }
        // exclude_others with no include_own can never match own AND others
        if args.exclude_others && !args.include_own {
            return Ok(Vec::new());
        }
        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        };
        let sql = format!(
            "SELECT {} FROM shard_range{where_clause}",
            crate::shard::SHARD_RANGE_KEYS.join(", ")
        );
        let mut out = {
            let conn = self.conn()?;
            let mut stmt = conn.prepare(&sql)?;
            let mut rows = stmt.query(rusqlite::params_from_iter(params.iter()))?;
            let mut collected = Vec::new();
            while let Some(row) = rows.next()? {
                collected.push(shard_range_from_row(row)?);
            }
            collected
        };
        out.sort_by_key(|r| r.sort_key());
        if args.includes.is_some() {
            out.truncate(1);
            return Ok(out);
        }
        if args.fill_gaps {
            if let Some(filler) = self.make_filler_shard_range(
                &out,
                args.marker.as_deref(),
                args.end_marker.as_deref(),
            )? {
                out.push(filler);
            }
        }
        if args.reverse {
            out.reverse();
        }
        Ok(out)
    }

    /// Python `_make_filler_shard_range`: own range covering
    /// (last_found.upper, own.upper] when listing/updating states omit
    /// CREATED children (probe test_sharding_listing L631).
    fn make_filler_shard_range(
        &mut self,
        found: &[crate::shard::ShardRange],
        marker: Option<&str>,
        end_marker: Option<&str>,
    ) -> Result<Option<crate::shard::ShardRange>, DbError> {
        if found.last().is_some_and(|r| r.upper.is_empty()) {
            return Ok(None);
        }
        let Some(mut own) = self.get_own_shard_range(false)? else {
            return Ok(None);
        };
        let last_upper = match found.last() {
            Some(r) => r.upper.clone(),
            None => {
                let m = marker.unwrap_or("");
                if !own.lower.is_empty() && (m.is_empty() || m < own.lower.as_str()) {
                    own.lower.clone()
                } else {
                    m.to_string()
                }
            }
        };
        // empty upper = Namespace.MAX, greater than any finite bound.
        let required_upper = match (end_marker.unwrap_or(""), own.upper.as_str()) {
            ("", o) => o.to_string(),
            (e, "") => e.to_string(),
            (e, o) if e.is_empty() || (!o.is_empty() && o < e) => o.to_string(),
            (e, _) => e.to_string(),
        };
        let gap = match (last_upper.is_empty(), required_upper.is_empty()) {
            (true, _) => false,
            (false, true) => true,
            (false, false) => required_upper > last_upper,
        };
        if !gap {
            return Ok(None);
        }
        own.lower = last_upper;
        own.upper = required_upper;
        Ok(Some(own))
    }

    /// `get_own_shard_range`: the broker's own shard range from the table, or
    /// (unless `no_default`) a default range spanning the whole namespace in
    /// the ACTIVE state. Counts on the default are NOT authoritative — use
    /// `get_info` for live stats.
    pub fn get_own_shard_range(
        &mut self,
        no_default: bool,
    ) -> Result<Option<crate::shard::ShardRange>, DbError> {
        let rows = self.get_shard_ranges(&GetShardRangesArgs {
            include_own: true,
            include_deleted: true,
            exclude_others: true,
            ..Default::default()
        })?;
        if let Some(sr) = rows.into_iter().next() {
            Ok(Some(sr))
        } else if no_default {
            Ok(None)
        } else {
            let now = Timestamp::now().internal();
            Ok(Some(crate::shard::ShardRange {
                state: crate::shard::state::ACTIVE,
                ..crate::shard::ShardRange::new(&self.path(), &now, "", "")
            }))
        }
    }

    /// `is_root_container`: whether this container is a root (not a shard of
    /// another container). A shard carries `X-Container-Sysmeta-Shard-Root`
    /// (or `-Quoted-Root`) naming its root; absent it, or when that root is
    /// this container itself, this is a root container.
    pub fn is_root_container(&mut self) -> Result<bool, DbError> {
        let md = self.metadata()?;
        let get = |k: &str| {
            md.iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(k))
                .map(|(_, (v, _))| v.clone())
                .filter(|v| !v.is_empty())
        };
        let root_path = get("X-Container-Sysmeta-Shard-Quoted-Root")
            .map(|p| pct_decode(&p))
            .or_else(|| get("X-Container-Sysmeta-Shard-Root"));
        match root_path {
            Some(rp) => Ok(self.path() == rp),
            None => Ok(true),
        }
    }

    pub fn find_shard_ranges(
        &mut self,
        shard_size: i64,
        minimum_shard_size: i64,
    ) -> Result<(Vec<FoundShardRange>, bool), DbError> {
        let minimum_shard_size = minimum_shard_size.max(1);
        let object_count = self
            .get_info()?
            .iter()
            .find(|(k, _)| k == "object_count")
            .and_then(|(_, v)| v.as_i64())
            .unwrap_or(0);
        if shard_size + minimum_shard_size > object_count {
            // container not big enough to shard
            return Ok((Vec::new(), false));
        }

        // Python: the last found range is capped at own.upper (a shard of a
        // shard must not extend to namespace MAX).
        let own_upper = self
            .get_own_shard_range(false)?
            .map(|o| o.upper)
            .unwrap_or_default();
        let past_own = |upper: &str| {
            !own_upper.is_empty() && (upper.is_empty() || upper > own_upper.as_str())
        };

        let mut found = Vec::new();
        let mut progress: i64 = 0;
        let mut last_upper = String::new(); // namespace MIN
        let mut index = 0usize;
        loop {
            let next_upper = if progress + shard_size + minimum_shard_size > object_count {
                // tail within minimum_shard_size of the end: final shard
                None
            } else {
                self.next_shard_range_upper(shard_size, &last_upper)?
            };
            match next_upper {
                Some(upper) if !past_own(&upper) => {
                    found.push(FoundShardRange {
                        index,
                        lower: last_upper.clone(),
                        upper: upper.clone(),
                        object_count: shard_size,
                    });
                    progress += shard_size;
                    last_upper = upper;
                    index += 1;
                }
                Some(_) | None => {
                    // final range up to own.upper (MAX when this is a root)
                    found.push(FoundShardRange {
                        index,
                        lower: last_upper,
                        upper: own_upper,
                        object_count: object_count - progress,
                    });
                    return Ok((found, true));
                }
            }
        }
    }

    /// Test/tooling helper: `SELECT name, sql FROM sqlite_master`.
    pub fn schema_dump(&mut self) -> Result<Vec<(String, Option<String>)>, DbError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT name, sql FROM sqlite_master ORDER BY name")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Object records whose names fall in the `(lower, upper]` namespace
    /// (empty bounds = -inf / +inf), both live and deleted, in name order.
    /// Used by the sharder to cleave a shard range's objects into its shard
    /// container. The raw `created_at` is preserved (ctype/meta timestamps are
    /// encoded within it), so re-merging into the shard copies rows exactly.
    /// Live `deleted=1` row count (Python sharder tombstone estimate).
    pub fn tombstone_count(&mut self) -> Result<i64, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let n: i64 = conn.query_row(
            "SELECT count(*) FROM object WHERE deleted = 1",
            [],
            |r| r.get(0),
        )?;
        Ok(n)
    }

    pub fn object_records_in_range(
        &mut self,
        lower: &str,
        upper: &str,
    ) -> Result<Vec<ObjectRecord>, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT name, created_at, size, content_type, etag, deleted, \
             storage_policy_index FROM object \
             WHERE (?1 = '' OR name > ?1) AND (?2 = '' OR name <= ?2) \
             ORDER BY name",
        )?;
        let rows = stmt.query_map(rusqlite::params![lower, upper], |row| {
            Ok(ObjectRecord {
                name: row.get(0)?,
                created_at: row.get(1)?,
                size: row.get(2)?,
                content_type: row.get(3)?,
                etag: row.get(4)?,
                deleted: row.get(5)?,
                storage_policy_index: row.get(6)?,
                ctype_timestamp: None,
                meta_timestamp: None,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Object rows in `(lower, upper]` whose local ROWID is newer than
    /// `since_row`.  Container sharding uses this to resume a cleave without
    /// replaying rows that were copied during an earlier pass.
    ///
    /// This is the bounded-by-high-water-mark form of Python Swift's
    /// `yield_objects(..., since_row=...)`.  Both live rows and tombstones are
    /// returned because either may be the newest version of an object.
    pub fn object_records_in_range_since(
        &mut self,
        lower: &str,
        upper: &str,
        since_row: i64,
    ) -> Result<Vec<ObjectRecord>, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT name, created_at, size, content_type, etag, deleted, \
             storage_policy_index FROM object \
             WHERE ROWID > ?3 \
               AND (?1 = '' OR name > ?1) \
               AND (?2 = '' OR name <= ?2) \
             ORDER BY ROWID",
        )?;
        let rows = stmt.query_map(rusqlite::params![lower, upper, since_row], |row| {
            Ok(ObjectRecord {
                name: row.get(0)?,
                created_at: row.get(1)?,
                size: row.get(2)?,
                content_type: row.get(3)?,
                etag: row.get(4)?,
                deleted: row.get(5)?,
                storage_policy_index: row.get(6)?,
                ctype_timestamp: None,
                meta_timestamp: None,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Test/tooling helper: full object table dump in ROWID order.
    pub fn object_rows(&mut self) -> Result<Vec<Vec<DbValue>>, DbError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT ROWID, name, created_at, size, content_type, etag,\
             deleted, storage_policy_index FROM object ORDER BY ROWID",
        )?;
        let rows = stmt.query_map([], |row| {
            let mut out = Vec::with_capacity(8);
            for i in 0..8 {
                out.push(DbValue::from_sql(row.get_ref(i)?));
            }
            Ok(out)
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

/// Simplified `parse_content_type` sufficient for the unquoted parameter
/// tokens Swift writes (`;swift_bytes=N`); quoted-string parameters are
/// passed through verbatim.
fn extract_swift_bytes(content_type: &str) -> (String, Option<String>) {
    match content_type.split_once(';') {
        None => (content_type.to_string(), None),
        Some((ct, params)) => {
            let mut out = ct.to_string();
            let mut swift_bytes = None;
            for param in params.split(';') {
                let (k, v) = param.split_once('=').unwrap_or((param, ""));
                let (k, v) = (k.trim(), v.trim());
                if k == "swift_bytes" {
                    swift_bytes = Some(v.to_string());
                } else if !k.is_empty() {
                    out.push_str(&format!(";{k}={v}"));
                }
            }
            (out, swift_bytes)
        }
    }
}

/// Port of `update_new_item_from_existing`: merge data/content-type/meta
/// attributes by their independent timestamps, encoding the result into
/// the `created_at` column value.
fn update_new_item_from_existing(
    new_item: &mut ObjectRecord,
    existing: Option<&ObjectRecord>,
) -> bool {
    let data_timestamp = new_item.created_at.clone();
    let (mut item_ts_data, ts_ctype, ts_meta) = match decode_timestamps(&data_timestamp, false) {
        Ok(parts) => parts,
        Err(_) => return true, // unparseable: treat as new (unreachable)
    };
    let mut item_ts_ctype = ts_ctype.unwrap_or(item_ts_data);
    let mut item_ts_meta = ts_meta.unwrap_or(item_ts_data);

    if let Some(ts) = &new_item.ctype_timestamp {
        if let Ok(t) = ts.parse::<Timestamp>() {
            item_ts_ctype = t;
            item_ts_meta = t;
        }
    }
    if let Some(ts) = &new_item.meta_timestamp {
        if let Ok(t) = ts.parse::<Timestamp>() {
            item_ts_meta = t;
        }
    }

    let Some(existing) = existing else {
        new_item.created_at = encode_timestamps(
            &item_ts_data,
            Some(&item_ts_ctype),
            Some(&item_ts_meta),
            false,
        );
        return true;
    };

    let (rec_ts_data, rec_ts_ctype, rec_ts_meta) =
        match decode_timestamps(&existing.created_at, false) {
            Ok(parts) => parts,
            Err(_) => return true,
        };
    let rec_ts_ctype = rec_ts_ctype.unwrap_or(rec_ts_data);
    let rec_ts_meta = rec_ts_meta.unwrap_or(rec_ts_data);

    // swift_bytes rides with the data timestamp; content-type with the
    // content-type timestamp
    let (mut new_ct, new_swift_bytes) = extract_swift_bytes(&new_item.content_type);
    let (existing_ct, existing_swift_bytes) = extract_swift_bytes(&existing.content_type);
    let mut swift_bytes = new_swift_bytes;

    let mut newer_than_existing = [true, true, true];
    if rec_ts_data >= item_ts_data {
        // apply data attributes from the existing record
        new_item.size = existing.size;
        new_item.etag = existing.etag.clone();
        new_item.deleted = existing.deleted;
        swift_bytes = existing_swift_bytes;
        item_ts_data = rec_ts_data;
        newer_than_existing[0] = false;
    }
    if rec_ts_ctype >= item_ts_ctype {
        new_ct = existing_ct;
        item_ts_ctype = rec_ts_ctype;
        newer_than_existing[1] = false;
    }
    if rec_ts_meta >= item_ts_meta {
        item_ts_meta = rec_ts_meta;
        newer_than_existing[2] = false;
    }

    new_item.created_at = encode_timestamps(
        &item_ts_data,
        Some(&item_ts_ctype),
        Some(&item_ts_meta),
        false,
    );
    if let Some(bytes) = &swift_bytes {
        new_ct.push_str(&format!(";swift_bytes={bytes}"));
    }
    new_item.content_type = new_ct;

    newer_than_existing.iter().any(|&b| b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misplaced_rows_and_reconciler_sync_are_resumable() {
        let dir = std::env::temp_dir().join(format!(
            "swift-misplaced-{}-{}",
            std::process::id(),
            Timestamp::now().raw()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut broker = ContainerBroker::new(&dir.join("hash.db"), "AUTH_test", "c");
        broker
            .initialize("1751500001.00000", 2, "1751500001.00000", "id")
            .unwrap();
        broker
            .put_object(
                "wrong-policy",
                "1751500002.00000",
                1,
                "text/plain",
                "etag",
                0,
                0,
                None,
                None,
            )
            .unwrap();
        assert!(broker.has_multiple_policies().unwrap());
        let rows = broker.get_misplaced_since(-1, 1000).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.name, "wrong-policy");
        assert_eq!(rows[0].1.storage_policy_index, 0);
        assert_eq!(broker.get_reconciler_sync().unwrap(), -1);
        broker.update_reconciler_sync(rows[0].0).unwrap();
        assert_eq!(broker.get_reconciler_sync().unwrap(), rows[0].0);
        let point = broker.get_reconciler_sync().unwrap();
        assert!(broker.get_misplaced_since(point, 1000).unwrap().is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_extract_swift_bytes() {
        assert_eq!(
            extract_swift_bytes("text/plain;swift_bytes=10"),
            ("text/plain".to_string(), Some("10".to_string()))
        );
        assert_eq!(
            extract_swift_bytes("text/plain; charset=UTF-8;swift_bytes=1"),
            (
                "text/plain;charset=UTF-8".to_string(),
                Some("1".to_string())
            )
        );
        assert_eq!(
            extract_swift_bytes("text/plain"),
            ("text/plain".to_string(), None)
        );
    }

    #[test]
    fn test_update_new_item_fresh() {
        let mut item = ObjectRecord {
            name: "o".into(),
            created_at: "1751500001.00000".into(),
            size: 1,
            content_type: "text/plain".into(),
            etag: "e".into(),
            deleted: 0,
            storage_policy_index: 0,
            ctype_timestamp: Some("1751500002.00000".into()),
            meta_timestamp: Some("1751500003.00000".into()),
        };
        assert!(update_new_item_from_existing(&mut item, None));
        assert_eq!(item.created_at, "1751500001.00000+186a0+186a0");
    }

    fn shard_broker(dir: &std::path::Path, n: usize) -> ContainerBroker {
        let hd = dir.join("containers/0/abc/00000000000000000000000000000abc");
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join("00000000000000000000000000000abc.db");
        let mut b = ContainerBroker::new(&db, "AUTH_test", "c");
        b.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        for i in 0..n {
            // zero-padded names so lexical order == numeric order
            b.put_object(
                &format!("o{i:04}"),
                "1751500001.00000",
                1,
                "text/plain",
                "etag",
                0,
                0,
                None,
                None,
            )
            .unwrap();
        }
        b
    }

    #[test]
    fn test_newid_changes_id_and_records_sync_point() {
        // db.py:608-627: newid re-ids the DB and records the incoming
        // high-water mark for the remote id at the object table's max ROWID.
        let dir = std::env::temp_dir().join(format!("swift-newid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = shard_broker(&dir, 2);
        b.commit_pending().unwrap();
        b.reported("1751500002.00000", "0", 2, 2).unwrap();
        let id_of = |b: &mut ContainerBroker| {
            b.get_replication_info()
                .unwrap()
                .into_iter()
                .find(|(k, _)| k == "id")
                .and_then(|(_, v)| v.as_text())
                .unwrap()
        };
        assert_eq!(id_of(&mut b), "id");
        b.newid("remote-abc").unwrap();
        let new_id = id_of(&mut b);
        assert_ne!(new_id, "id");
        // (max_row, remote_id) landed in the incoming sync table
        assert_eq!(b.get_sync("remote-abc", true).unwrap(), 2);
        assert_eq!(
            b.get_syncs(true).unwrap(),
            vec![(2, "remote-abc".to_string())]
        );
        assert_eq!(b.get_syncs(false).unwrap(), vec![]);
        // ContainerBroker._newid (container/backend.py:684-688) reset the
        // reported_* stats
        let info = b.get_info().unwrap();
        let reported = info
            .iter()
            .find(|(k, _)| k == "reported_object_count")
            .and_then(|(_, v)| v.as_i64());
        assert_eq!(reported, Some(0));
        // a second newid picks yet another unique id
        b.newid("remote-abc").unwrap();
        assert_ne!(id_of(&mut b), new_id);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_newid_empty_table_records_minus_one() {
        // db.py:618-622: with no data rows the sync point is -1
        let dir = std::env::temp_dir().join(format!("swift-newid0-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = shard_broker(&dir, 0);
        b.newid("remote-x").unwrap();
        assert_eq!(b.get_sync("remote-x", true).unwrap(), -1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_sharding_required_while_sharding() {
        let dir = std::env::temp_dir().join(format!(
            "swift-sharding-required-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut broker = shard_broker(&dir, 0);
        assert!(!broker.sharding_required().unwrap());
        let epoch = "1751500099.00000";
        broker.enable_sharding(epoch).unwrap();
        let mut first = crate::shard::ShardRange::new(".shards_AUTH_test/c-0", epoch, "", "m");
        first.state = crate::shard::state::ACTIVE;
        let mut second = crate::shard::ShardRange::new(".shards_AUTH_test/c-1", epoch, "m", "");
        second.state = crate::shard::state::ACTIVE;
        broker.merge_shard_ranges(vec![first, second]).unwrap();
        assert!(broker.set_sharding_state().unwrap());
        assert_eq!(broker.get_db_state().unwrap(), DbState::Sharding);
        assert!(broker.sharding_required().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_sharding_required_after_ranges_replicate_to_unsharded_handoff() {
        let dir = std::env::temp_dir().join(format!(
            "swift-sharding-required-unsharded-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut broker = shard_broker(&dir, 4);
        let epoch = "1751500099.00000";
        let mut own = broker.get_own_shard_range(false).unwrap().unwrap();
        own.state = crate::shard::state::SHARDED;
        own.epoch = Some(epoch.to_string());
        let mut first = crate::shard::ShardRange::new(".shards_AUTH_test/c-0", epoch, "", "m");
        first.state = crate::shard::state::ACTIVE;
        let mut second = crate::shard::ShardRange::new(".shards_AUTH_test/c-1", epoch, "m", "");
        second.state = crate::shard::state::ACTIVE;
        broker.merge_shard_ranges(vec![own, first, second]).unwrap();
        assert_eq!(broker.get_db_state().unwrap(), DbState::Unsharded);
        assert!(broker.sharding_required().unwrap());

        // REPLICATE opens by hash and initially has no path-derived account
        // or container. The predicate must still hydrate the own range.
        let path = broker.db_file().to_path_buf();
        let mut blind = ContainerBroker::new(&path, "", "");
        assert_eq!(blind.get_db_state().unwrap(), DbState::Unsharded);
        assert!(blind.sharding_required().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_empty_uses_shard_usage_on_sharded_root() {
        // Probe test_sharded_delete: Python DELETE 409s while shards still
        // hold objects. policy_stat on the SHARDED root is 0.
        let dir = std::env::temp_dir().join(format!("swift-empty-shard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = shard_broker(&dir, 0);
        assert!(b.empty().unwrap(), "no objects, no shards");
        let epoch = "1751500010.00000";
        b.enable_sharding(epoch).unwrap();
        let mut s1 = crate::shard::ShardRange::new(".shards_AUTH_test/c-0", epoch, "", "m");
        s1.state = crate::shard::state::ACTIVE;
        s1.object_count = 50;
        let mut s2 = crate::shard::ShardRange::new(".shards_AUTH_test/c-1", epoch, "m", "");
        s2.state = crate::shard::state::ACTIVE;
        s2.object_count = 50;
        b.merge_shard_ranges(vec![s1, s2]).unwrap();
        assert!(b.set_sharding_state().unwrap());
        assert!(b.set_sharded_state().unwrap());
        assert_eq!(b.get_db_state().unwrap(), DbState::Sharded);
        assert!(
            b.db_exists(),
            "SHARDED root still exists via epoch file even if <hash>.db is gone"
        );
        assert!(b.sharding_initiated().unwrap());
        assert_eq!(b.get_shard_usage().unwrap(), (0, 100));
        assert!(
            !b.empty().unwrap(),
            "ACTIVE shard object_count must keep DELETE at 409"
        );
        let info = b.get_info().unwrap();
        let oc = info
            .iter()
            .find(|(k, _)| k == "object_count")
            .and_then(|(_, v)| v.as_i64());
        let st = info
            .iter()
            .find(|(k, _)| k == "db_state")
            .and_then(|(_, v)| v.as_text());
        assert_eq!(oc, Some(100), "{info:?}");
        assert_eq!(st.as_deref(), Some("sharded"), "{info:?}");

        // Probe `_test_sharded_listing` after extra PUTs + run_sharders:
        // same created timestamp, newer meta_timestamp, object_count 150
        // on the first range. HEAD must become 200.
        let mut s1b = crate::shard::ShardRange::new(".shards_AUTH_test/c-0", epoch, "", "m");
        s1b.state = crate::shard::state::ACTIVE;
        s1b.object_count = 150;
        s1b.bytes_used = 150;
        s1b.meta_timestamp = "1751500099.00000".into();
        s1b.reported = 0;
        b.merge_shard_ranges(vec![s1b]).unwrap();
        assert_eq!(b.get_shard_usage().unwrap(), (150, 200), "first-range stats");
        let info = b.get_info().unwrap();
        let oc = info
            .iter()
            .find(|(k, _)| k == "object_count")
            .and_then(|(_, v)| v.as_i64());
        assert_eq!(oc, Some(200), "{info:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_get_db_state_acceptor_without_own_epoch_is_collapsed() {
        // Probe L2088: epoch file + wiped own.epoch + no other ranges +
        // alpha still in the live table. Must be collapsed, not unsharded.
        let dir = std::env::temp_dir().join(format!(
            "swift-db-l2088-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let unsuffixed = dir.join("hash.db");
        let epoch = "1751500010.00000";
        let epoch_path = make_db_file_path(&unsuffixed, Some(epoch)).unwrap();
        let mut root = ContainerBroker::new(&epoch_path, "AUTH_test", "c");
        root.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        root.put_object(
            "alpha-1",
            "1751500001.00000",
            1,
            "text/plain",
            "e",
            0,
            0,
            None,
            None,
        )
        .unwrap();
        let mut own = root.get_own_shard_range(false).unwrap().unwrap();
        own.epoch = None;
        own.state = crate::shard::state::ACTIVE;
        root.merge_shard_ranges(vec![own]).unwrap();
        assert_eq!(root.get_db_state().unwrap(), DbState::Collapsed);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_sharded_root_revive_uses_shard_usage_for_is_deleted() {
        // Probe test_sharded_delete L2506 vs shrink-to-root L2095:
        // SHARDED + shard usage > 0 revives; COLLAPSED leftover rows do not.
        let dir = std::env::temp_dir().join(format!(
            "swift-revive-shard-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = shard_broker(&dir, 0);
        let epoch = "1751500010.00000";
        b.enable_sharding(epoch).unwrap();
        let mut s1 = crate::shard::ShardRange::new(".shards_AUTH_test/c-0", epoch, "", "m");
        s1.state = crate::shard::state::ACTIVE;
        s1.object_count = 1;
        let mut s2 = crate::shard::ShardRange::new(".shards_AUTH_test/c-1", epoch, "m", "");
        s2.state = crate::shard::state::ACTIVE;
        s2.object_count = 0;
        b.merge_shard_ranges(vec![s1, s2]).unwrap();
        assert!(b.set_sharding_state().unwrap());
        assert!(b.set_sharded_state().unwrap());
        assert_eq!(b.get_db_state().unwrap(), DbState::Sharded);
        b.delete_db("1751500200.00000").unwrap();
        assert!(
            !b.is_deleted().unwrap(),
            "SHARDED root with shard usage > 0 must revive"
        );
        let (_, del) = b.get_info_is_deleted().unwrap();
        assert!(!del, "get_info_is_deleted must follow shard usage");

        // L2095: shrink-to-root leaves a COLLAPSED root with no other
        // live shard ranges. delete_timestamp > put_timestamp and
        // container_stat object_count stay decisive.
        let dir2 = std::env::temp_dir().join(format!(
            "swift-revive-coll-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir2);
        let mut c = shard_broker(&dir2, 0);
        c.enable_sharding(epoch).unwrap();
        assert!(c.set_sharding_state().unwrap());
        assert!(c.set_sharded_state().unwrap());
        assert_eq!(c.get_db_state().unwrap(), DbState::Collapsed);
        let mut leftover = crate::shard::ShardRange::new(".shards_AUTH_test/c-x", epoch, "", "");
        leftover.state = crate::shard::state::SHRUNK;
        leftover.deleted = 1;
        leftover.object_count = 1;
        c.merge_shard_ranges(vec![leftover]).unwrap();
        assert_eq!(c.get_db_state().unwrap(), DbState::Collapsed);
        c.delete_db("1751500200.00000").unwrap();
        assert!(
            c.is_deleted().unwrap(),
            "COLLAPSED + deleted SHRUNK leftover must not revive L2095"
        );
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&dir2).unwrap();
    }

    #[test]
    fn test_collapsed_root_delete_object_makes_empty() {
        // Probe L2094: shrink-to-root leaves a COLLAPSED epoch DB with the
        // last live row. DELETE that object must make empty() true so
        // DELETE_container is 204, not 409.
        let dir = std::env::temp_dir().join(format!(
            "swift-empty-coll-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = shard_broker(&dir, 0);
        b.put_object(
            "alpha",
            "1751500001.00000",
            1,
            "text/plain",
            "e",
            0,
            0,
            None,
            None,
        )
        .unwrap();
        let epoch = "1751500010.00000";
        b.enable_sharding(epoch).unwrap();
        assert!(b.set_sharding_state().unwrap());
        b.reload_db_files();
        b.put_object(
            "alpha",
            "1751500001.00000",
            1,
            "text/plain",
            "e",
            0,
            0,
            None,
            None,
        )
        .unwrap();
        assert!(b.set_sharded_state().unwrap());
        assert_eq!(b.get_db_state().unwrap(), DbState::Collapsed);
        assert!(!b.empty().unwrap(), "live alpha on collapsed root");
        b.delete_object("alpha", "1751500099.00000", 0).unwrap();
        assert!(
            b.empty().unwrap(),
            "tombstone must empty collapsed root for DELETE container"
        );
        b.delete_db("1751500100.00000").unwrap();
        assert!(b.is_deleted().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_find_shard_ranges_caps_last_upper_at_own() {
        // Nested sharding: a shard's last sub-range must end at own.upper,
        // not namespace MAX (probe assert_shard_ranges_contiguous last_upper).
        let dir = std::env::temp_dir().join(format!(
            "swift-find-own-upper-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = shard_broker(&dir, 0);
        for i in 0..150 {
            b.put_object(
                &format!("j{i:04}"),
                "1751500001.00000",
                1,
                "text/plain",
                "etag",
                0,
                0,
                None,
                None,
            )
            .unwrap();
        }
        let ts = "1751500010.00000";
        let mut own = crate::shard::ShardRange::new(&b.path(), ts, "", "m");
        own.state = crate::shard::state::SHARDING;
        own.epoch = Some(ts.into());
        b.merge_shard_ranges(vec![own]).unwrap();
        let (found, done) = b.find_shard_ranges(50, 1).unwrap();
        assert!(done);
        assert_eq!(found.len(), 3, "{found:?}");
        assert_eq!(found[0].lower, "");
        assert_eq!(found.last().unwrap().upper, "m", "{found:?}");
        assert!(
            found.iter().all(|f| f.upper != "" || f.lower == "m"),
            "no sub-range may use namespace MAX: {found:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_merge_and_get_shard_ranges() {
        use crate::shard::{state, ShardRange};
        let dir = std::env::temp_dir().join(format!("swift-shardmerge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = shard_broker(&dir, 0);

        // three shards + the container's own range
        let own = ShardRange::new(&b.path(), "1751500000.00000", "", "");
        let s1 = ShardRange::new(".shards_a/c-1", "1751500001.00000", "", "m");
        let s2 = ShardRange::new(".shards_a/c-2", "1751500001.00000", "m", "t");
        let s3 = ShardRange::new(".shards_a/c-3", "1751500001.00000", "t", "");
        b.merge_shard_ranges(vec![own.clone(), s1.clone(), s2.clone(), s3.clone()])
            .unwrap();

        // get_shard_ranges (others only) returns the three shards sorted by upper
        let all = b.get_shard_ranges(&GetShardRangesArgs::default()).unwrap();
        assert_eq!(all.len(), 3, "{all:?}");
        assert_eq!(all[0].upper, "m");
        assert_eq!(all[1].upper, "t");
        assert_eq!(all[2].upper, ""); // MAX sorts last

        // include_own returns all four
        let with_own = b
            .get_shard_ranges(&GetShardRangesArgs {
                include_own: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(with_own.len(), 4);

        // includes=... returns the single covering shard
        let covering = b
            .get_shard_ranges(&GetShardRangesArgs {
                includes: Some("p".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(covering.len(), 1);
        assert_eq!(covering[0].name, ".shards_a/c-2"); // (m, t] contains p

        // states filter
        let mut s2_active = s2.clone();
        s2_active.state = state::ACTIVE;
        s2_active.state_timestamp = "1751500002.00000".into();
        b.merge_shard_ranges(vec![s2_active]).unwrap();
        let active = b
            .get_shard_ranges(&GetShardRangesArgs {
                states: Some(vec![state::ACTIVE]),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].name, ".shards_a/c-2");
        assert_eq!(active[0].state, state::ACTIVE);

        // newest-wins: a newer-timestamp update replaces the record
        let mut s1_new = ShardRange::new(".shards_a/c-1", "1751500005.00000", "", "m");
        s1_new.object_count = 42;
        b.merge_shard_ranges(vec![s1_new]).unwrap();
        let got = b
            .get_shard_ranges(&GetShardRangesArgs {
                includes: Some("a".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(got[0].object_count, 42);

        // own_shard_range: the persisted own range is returned
        let own_got = b.get_own_shard_range(false).unwrap().unwrap();
        assert_eq!(own_got.name, "AUTH_test/c");
        // a normal container (no Shard-Root sysmeta) is a root container
        assert!(b.is_root_container().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_get_shard_ranges_listing_includes_cleaved() {
        use crate::shard::{resolve_shard_range_states, state, ShardRange, SHARD_LISTING_STATES};

        let dir = std::env::temp_dir().join(format!(
            "swift-shard-listing-cleaved-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = shard_broker(&dir, 0);

        let mut cleaved = ShardRange::new(".shards_a/c-1", "1751500001.00000", "", "m");
        cleaved.state = state::CLEAVED;
        cleaved.state_timestamp = "1751500002.00000".into();
        let mut found = ShardRange::new(".shards_a/c-2", "1751500001.00000", "m", "");
        found.state = state::FOUND;
        found.state_timestamp = "1751500002.00000".into();
        b.merge_shard_ranges(vec![cleaved, found]).unwrap();

        let listing_states = resolve_shard_range_states(&["listing".into()])
            .unwrap()
            .unwrap();
        assert_eq!(
            listing_states.len(),
            SHARD_LISTING_STATES.len(),
            "{listing_states:?}"
        );
        assert!(listing_states.contains(&state::CLEAVED));

        let got = b
            .get_shard_ranges(&GetShardRangesArgs {
                states: Some(listing_states),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            got.len(),
            1,
            "FOUND must be excluded from states=listing: {got:?}"
        );
        assert_eq!(got[0].name, ".shards_a/c-1");
        assert_eq!(got[0].state, state::CLEAVED);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_fill_gaps_appends_own_range_after_cleaved() {
        use crate::shard::{resolve_shard_range_states, state, ShardRange};

        let dir = std::env::temp_dir().join(format!(
            "swift-shard-fill-gaps-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = shard_broker(&dir, 0);
        b.enable_sharding("1751500010.00000").unwrap();

        let mut c0 = ShardRange::new(".shards_a/c-0", "1751500001.00000", "", "m");
        c0.state = state::CLEAVED;
        let mut c1 = ShardRange::new(".shards_a/c-1", "1751500001.00000", "m", "s");
        c1.state = state::CLEAVED;
        let mut cr = ShardRange::new(".shards_a/c-2", "1751500001.00000", "s", "");
        cr.state = state::CREATED;
        b.merge_shard_ranges(vec![c0, c1, cr]).unwrap();

        let listing_states = resolve_shard_range_states(&["listing".into()])
            .unwrap()
            .unwrap();
        let got = b
            .get_shard_ranges(&GetShardRangesArgs {
                states: Some(listing_states),
                fill_gaps: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(got.len(), 3, "2 CLEAVED + own filler, not CREATED: {got:?}");
        assert_eq!(got[0].state, state::CLEAVED);
        assert_eq!(got[1].state, state::CLEAVED);
        assert_eq!(got[2].lower, "s");
        assert!(got[2].upper.is_empty(), "filler to MAX");
        assert_eq!(got[2].name, b.path());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_db_filename_helpers() {
        let p = std::path::Path::new("/x/ab2134.db");
        assert_eq!(parse_db_filename(p), ("ab2134".into(), None, ".db".into()));
        let p2 = std::path::Path::new("/x/ab2134_1234567890.12345.db");
        assert_eq!(
            parse_db_filename(p2),
            (
                "ab2134".into(),
                Some("1234567890.12345".into()),
                ".db".into()
            )
        );
        // make_db_file_path normalizes the epoch to Timestamp.normal
        let made = make_db_file_path(p, Some("1234567890.12345")).unwrap();
        assert_eq!(made, std::path::Path::new("/x/ab2134_1234567890.12345.db"));
        assert_eq!(
            make_db_file_path(p2, None).unwrap(),
            std::path::Path::new("/x/ab2134.db")
        );
    }

    #[test]
    fn test_sharding_state_machine() {
        use crate::shard::ShardRange;
        let dir = std::env::temp_dir().join(format!("swift-shardsm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hd = dir.join("containers/0/abc/00000000000000000000000000000abc");
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join("00000000000000000000000000000abc.db");
        let mut b = ContainerBroker::new(&db, "AUTH_test", "c");
        b.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        // put a couple of objects so max_row > 0
        for i in 0..3 {
            b.put_object(
                &format!("o{i}"),
                "1751500001.00000",
                1,
                "text/plain",
                "e",
                0,
                0,
                None,
                None,
            )
            .unwrap();
        }
        assert_eq!(b.get_db_state().unwrap(), DbState::Unsharded);

        // enable sharding at an epoch, and merge some shard ranges
        let epoch = "1751500010.00000";
        b.enable_sharding(epoch).unwrap();
        b.merge_shard_ranges(vec![
            ShardRange::new(".shards_a/c-1", "1751500010.00000", "", "m"),
            ShardRange::new(".shards_a/c-2", "1751500010.00000", "m", ""),
        ])
        .unwrap();
        // still unsharded on disk (one db file) until set_sharding_state
        assert_eq!(b.get_db_state().unwrap(), DbState::Unsharded);

        // UNSHARDED -> SHARDING: creates the fresh epoch DB
        assert!(b.set_sharding_state().unwrap());
        assert_eq!(b.db_files().len(), 2, "retiring + fresh");
        assert_eq!(b.get_db_state().unwrap(), DbState::Sharding);
        // the fresh DB carries the shard ranges + own range (epoch must survive
        // so get_db_state can reach SHARDED after set_sharded_state)
        let ranges = b.get_shard_ranges(&GetShardRangesArgs::default()).unwrap();
        assert_eq!(ranges.len(), 2, "{ranges:?}");
        let own = b.get_own_shard_range(true).unwrap();
        assert!(
            own.as_ref().and_then(|o| o.epoch.as_ref()).is_some(),
            "own range with epoch must be copied into the fresh DB: {own:?}"
        );

        // SHARDING -> SHARDED: retires the old DB
        assert!(b.set_sharded_state().unwrap());
        assert_eq!(b.db_files().len(), 1);
        assert_eq!(b.get_db_state().unwrap(), DbState::Sharded);
        let own_after = b.get_own_shard_range(false).unwrap().unwrap();
        assert_eq!(
            own_after.state,
            crate::shard::state::SHARDED,
            "own range state_text should be sharded after set_sharded_state"
        );
        // Epoch-only path: constructor `<hash>.db` is gone; is_deleted /
        // get_info_is_deleted must still see the container (listing fan-out).
        assert!(!b.db_file().exists(), "retiring base path unlinked");
        assert!(
            !b.is_deleted().unwrap(),
            "SHARDED epoch-only DB must not look deleted"
        );
        let (info, del) = b.get_info_is_deleted().unwrap();
        assert!(!del, "get_info_is_deleted must be false for SHARDED");
        assert!(!info.is_empty());
        // re-open with identity and confirm SHARDED sticks
        let mut b2 = ContainerBroker::new(&db, "AUTH_test", "c");
        assert_eq!(b2.get_db_state().unwrap(), DbState::Sharded);
        assert!(!b2.is_deleted().unwrap());
        let (_, del2) = b2.get_info_is_deleted().unwrap();
        assert!(!del2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_own_shard_range_default_when_absent() {
        let dir = std::env::temp_dir().join(format!("swift-ownsr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = shard_broker(&dir, 0);
        // no own range persisted -> default whole-namespace ACTIVE range
        let own = b.get_own_shard_range(false).unwrap().unwrap();
        assert_eq!(own.name, "AUTH_test/c");
        assert_eq!(own.lower, "");
        assert_eq!(own.upper, "");
        assert_eq!(own.state, crate::shard::state::ACTIVE);
        // no_default returns None when absent
        assert!(b.get_own_shard_range(true).unwrap().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_find_shard_ranges_pivots() {
        let dir = std::env::temp_dir().join(format!("swift-shard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = shard_broker(&dir, 10);
        // shard_size 3, min 1 over 10 objects o0000..o0009
        let (ranges, done) = b.find_shard_ranges(3, 1).unwrap();
        assert!(done, "reached namespace end");
        // ranges: ("","o0002",3) ("o0002","o0005",3) ("o0005","o0008",3) ("o0008","",1)
        assert_eq!(ranges.len(), 4, "{ranges:?}");
        assert_eq!(ranges[0].lower, "");
        assert_eq!(ranges[0].upper, "o0002");
        assert_eq!(ranges[1].upper, "o0005");
        assert_eq!(ranges[2].upper, "o0008");
        assert_eq!(ranges[3].lower, "o0008");
        assert_eq!(ranges[3].upper, "", "final range extends to MAX");
        // object counts sum to the container total
        let total: i64 = ranges.iter().map(|r| r.object_count).sum();
        assert_eq!(total, 10);
        assert_eq!(ranges[3].object_count, 1, "tail shard holds the remainder");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_shard_name_matches_python() {
        assert_eq!(
            hash_container_name("mycontainer"),
            "9204f397c83d6ce9f5983cad6d672c6d"
        );
        assert_eq!(shards_account_name("AUTH_test"), ".shards_AUTH_test");
        assert_eq!(
            make_shard_name(
                ".shards_AUTH_test",
                "mycontainer",
                "mycontainer",
                "1751500000.00000",
                3
            ),
            ".shards_AUTH_test/mycontainer-9204f397c83d6ce9f5983cad6d672c6d-1751500000.00000-3"
        );
    }

    #[test]
    fn test_find_shard_ranges_too_small() {
        let dir = std::env::temp_dir().join(format!("swift-shard-s-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = shard_broker(&dir, 3);
        // shard_size 3 + min 1 = 4 > 3 objects -> not shardable
        let (ranges, done) = b.find_shard_ranges(3, 1).unwrap();
        assert!(ranges.is_empty());
        assert!(!done);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn info_count(b: &mut ContainerBroker) -> i64 {
        b.get_info()
            .unwrap()
            .into_iter()
            .find(|(k, _)| k == "object_count")
            .and_then(|(_, v)| match v {
                DbValue::Int(i) => Some(i),
                DbValue::Text(s) => s.parse().ok(),
                _ => None,
            })
            .unwrap_or(-1)
    }

    #[test]
    fn test_usync_tombstones_zero_peer_object_count() {
        // Probe L1435: a replica that has deleted=1 rows must be able to
        // merge_items those tombstones onto a peer that still lists the
        // objects. Restarting usync from -1 is not enough if the rows are
        // missing or merge_items drops deleted=1.
        let dir = std::env::temp_dir().join(format!(
            "swift-tombstone-usync-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut src = shard_broker(&dir.join("src"), 50);
        let mut dst = shard_broker(&dir.join("dst"), 50);
        src.commit_pending().unwrap();
        dst.commit_pending().unwrap();
        assert_eq!(info_count(&mut src), 50);
        assert_eq!(info_count(&mut dst), 50);
        let before = src.get_max_row().unwrap().unwrap_or(-1);
        for i in 0..50 {
            src.delete_object(&format!("o{i:04}"), "1751500099.00000", 0)
                .unwrap();
        }
        src.commit_pending().unwrap();
        assert_eq!(info_count(&mut src), 0, "source empty after delete");
        let after = src.get_max_row().unwrap().unwrap_or(-1);
        let items = src.get_items_since(-1, 1000).unwrap();
        assert!(
            !items.is_empty(),
            "tombstones must exist as rows to usync; max_row {before}->{after}"
        );
        assert!(
            items.iter().all(|(_, r)| r.deleted == 1),
            "usync rows must be tombstones"
        );
        let recs: Vec<_> = items.into_iter().map(|(_, r)| r).collect();
        dst.merge_items(recs).unwrap();
        assert_eq!(
            info_count(&mut dst),
            0,
            "peer object_count must drop to 0 after tombstone merge"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Arguments to [`ContainerBroker::get_shard_ranges`], mirroring the Python
/// keyword arguments. `None` marker/end_marker/includes/states mean "not
/// specified".
#[derive(Debug, Clone, Default)]
pub struct GetShardRangesArgs {
    pub marker: Option<String>,
    pub end_marker: Option<String>,
    pub includes: Option<String>,
    pub reverse: bool,
    pub include_deleted: bool,
    pub states: Option<Vec<i64>>,
    pub include_own: bool,
    pub exclude_others: bool,
    /// Python `fill_gaps`: for `states=listing` / `states=updating`, insert a
    /// copy of the own range covering (last_found.upper, own.upper].
    pub fill_gaps: bool,
}

/// Minimal percent-decode for the Quoted-Root sysmeta (utf-8 lossy).
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            ) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Read a [`crate::shard::ShardRange`] from a `shard_range` row selected in
/// `SHARD_RANGE_KEYS` order.
fn shard_range_from_row(row: &rusqlite::Row<'_>) -> Result<crate::shard::ShardRange, DbError> {
    Ok(crate::shard::ShardRange {
        name: row.get(0)?,
        timestamp: row.get(1)?,
        lower: row.get(2)?,
        upper: row.get(3)?,
        object_count: row.get(4)?,
        bytes_used: row.get(5)?,
        meta_timestamp: row.get(6)?,
        deleted: row.get(7)?,
        state: row.get(8)?,
        state_timestamp: row.get(9)?,
        epoch: row.get(10)?,
        reported: row.get(11)?,
        tombstones: row.get(12)?,
    })
}

/// Arguments to [`ContainerBroker::list_objects_iter`], mirroring the
/// Python keyword arguments.
#[derive(Debug, Clone, Default)]
pub struct ListObjectsArgs {
    pub limit: i64,
    pub marker: String,
    pub end_marker: String,
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub path: Option<String>,
    pub storage_policy_index: i64,
    pub reverse: bool,
    /// `Some(true)` deleted only, `Some(false)` live only (default),
    /// `None` both.
    pub include_deleted: Option<bool>,
    pub allow_reserved: bool,
}

impl ContainerBroker {
    pub fn get_raw_metadata(&mut self) -> Result<String, DbError> {
        crate::broker::get_raw_metadata(self.conn()?, "container")
    }

    pub fn metadata(&mut self) -> Result<crate::broker::BrokerMetadata, DbError> {
        crate::broker::get_metadata(self.conn()?, "container")
    }

    pub fn update_metadata(
        &mut self,
        updates: &crate::broker::BrokerMetadata,
    ) -> Result<(), DbError> {
        crate::broker::update_metadata(self.conn()?, "container", updates)
    }

    /// `DatabaseBroker.delete_db` with the container whitelist.
    pub fn delete_db(&mut self, timestamp: &str) -> Result<(), DbError> {
        crate::broker::delete_db(
            self.conn()?,
            "container",
            timestamp,
            &[
                "x-container-sysmeta-shard-quoted-root",
                "x-container-sysmeta-shard-root",
                "x-container-sysmeta-sharding",
            ],
        )
    }

    /// `ContainerBroker.is_deleted`: no objects and delete after put.
    /// (Unlike accounts, the status column is not consulted.)
    ///
    /// Existence uses [`Self::db_files`] (Python `DatabaseBroker.db_file`
    /// resolves to the freshest epoch DB). After `set_sharded_state` only
    /// `<hash>_<epoch>.db` remains — checking the constructor `<hash>.db`
    /// path would falsely treat SHARDED containers as deleted (404).
    fn info_shows_deleted(info: &[(String, DbValue)]) -> bool {
        let get = |k: &str| {
            info.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
                .unwrap_or(DbValue::Null)
        };
        let object_count = get("object_count");
        let delete_ts = get("delete_timestamp");
        let put_ts = get("put_timestamp");
        let zero = match &object_count {
            DbValue::Int(i) => *i == 0,
            DbValue::Text(s) => s.is_empty() || s == "0",
            DbValue::Null => true,
        };
        let parse = |v: &DbValue| match v {
            DbValue::Text(s) => s.parse::<Timestamp>().ok(),
            DbValue::Int(i) => Timestamp::from_secs(*i as f64).ok(),
            DbValue::Null => None,
        };
        zero
            && matches!(
                (parse(&delete_ts), parse(&put_ts)),
                (Some(d), Some(p)) if d > p
            )
    }

    pub fn is_deleted(&mut self) -> Result<bool, DbError> {
        if self.db_files().is_empty() {
            return Ok(true);
        }
        // Python `_is_deleted`: use the same object_count `get_info` exposes
        // (shard usage on SHARDED roots). container_stat alone leaves a
        // deleted SHARDED root 404 after shards report objects
        // (probe test_sharded_delete L2506).
        let info = self.get_info()?;
        Ok(Self::info_shows_deleted(&info))
    }

    /// `DatabaseBroker.reclaim`: commit pending, purge old tombstone
    /// rows, stale sync rows and empty metadata. Returns rows reclaimed.
    pub fn reclaim(&mut self, age_timestamp: f64, sync_timestamp: f64) -> Result<u64, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let reclaimed =
            crate::broker::reclaim_tombstones(conn, "object", "created_at", age_timestamp)?;
        crate::broker::reclaim_other_stuff(conn, "container", age_timestamp, sync_timestamp)?;
        Ok(reclaimed)
    }

    pub fn get_max_row(&mut self) -> Result<Option<i64>, DbError> {
        crate::broker::get_max_row(self.conn()?, "object")
    }

    /// `ContainerBroker.set_x_container_sync_points`: advance one or both
    /// container-sync ROWID watermarks. `None` leaves that point unchanged.
    pub fn set_x_container_sync_points(
        &mut self,
        sync_point1: Option<i64>,
        sync_point2: Option<i64>,
    ) -> Result<(), DbError> {
        let conn = self.conn()?;
        match (sync_point1, sync_point2) {
            (Some(p1), Some(p2)) => {
                conn.execute(
                    "UPDATE container_stat SET x_container_sync_point1 = ?, \
                     x_container_sync_point2 = ?",
                    rusqlite::params![p1, p2],
                )?;
            }
            (Some(p1), None) => {
                conn.execute(
                    "UPDATE container_stat SET x_container_sync_point1 = ?",
                    rusqlite::params![p1],
                )?;
            }
            (None, Some(p2)) => {
                conn.execute(
                    "UPDATE container_stat SET x_container_sync_point2 = ?",
                    rusqlite::params![p2],
                )?;
            }
            (None, None) => {}
        }
        Ok(())
    }

    /// Port of `ContainerBroker.list_objects_iter`, including the
    /// delimiter/prefix/path subdir machinery. Returns listing rows:
    /// `[name, last_modified, size, content_type, etag]` with subdir
    /// entries carrying a null content type.
    pub fn list_objects_iter(
        &mut self,
        args: &ListObjectsArgs,
    ) -> Result<Vec<Vec<DbValue>>, DbError> {
        self.commit_pending()?;
        let deleted_arg = match args.include_deleted {
            Some(true) => " = 1",
            Some(false) => " = 0",
            None => " in (0, 1)",
        };
        let mut marker = args.marker.clone();
        let mut end_marker = args.end_marker.clone();
        if args.reverse {
            std::mem::swap(&mut marker, &mut end_marker);
        }
        let mut prefix = args.prefix.clone();
        let mut delimiter = args.delimiter.clone();
        let mut path = args.path.clone();
        if let Some(p) = &args.path {
            if p.is_empty() {
                prefix = Some(String::new());
            } else {
                let stripped = format!("{}/", p.trim_end_matches('/'));
                prefix = Some(stripped.clone());
                path = Some(stripped);
            }
            delimiter = Some("/".to_string());
        } else if delimiter.as_deref().is_some_and(|d| !d.is_empty()) && prefix.is_none() {
            prefix = Some(String::new());
        }
        let end_prefix = prefix.as_deref().filter(|p| !p.is_empty()).map(|p| {
            let mut chars: Vec<char> = p.chars().collect();
            let last = chars.pop().unwrap();
            let bumped = char::from_u32(last as u32 + 1).unwrap_or(last);
            chars.push(bumped);
            chars.into_iter().collect::<String>()
        });
        let orig_marker = marker.clone();
        let mut delim_force_gte = false;
        let has_delimiter = delimiter.as_deref().is_some_and(|d| !d.is_empty());

        let conn = self.conn()?;
        let mut results: Vec<Vec<DbValue>> = Vec::new();
        loop {
            if results.len() as i64 >= args.limit {
                return Ok(results);
            }
            let mut conditions: Vec<String> = Vec::new();
            let mut params: Vec<rusqlite::types::Value> = Vec::new();
            let prefix_nonempty = prefix.as_deref().is_some_and(|p| !p.is_empty());
            if !end_marker.is_empty()
                && (!prefix_nonempty || end_marker.as_str() < end_prefix.as_deref().unwrap_or(""))
            {
                conditions.push("name < ?".into());
                params.push(end_marker.clone().into());
            } else if let Some(ep) = &end_prefix {
                conditions.push("name < ?".into());
                params.push(ep.clone().into());
            }
            if delim_force_gte {
                conditions.push("name >= ?".into());
                params.push(marker.clone().into());
                delim_force_gte = false;
            } else if !marker.is_empty()
                && (!prefix_nonempty || marker.as_str() >= prefix.as_deref().unwrap_or(""))
            {
                conditions.push("name > ?".into());
                params.push(marker.clone().into());
            } else if prefix_nonempty {
                conditions.push("name >= ?".into());
                params.push(prefix.clone().unwrap().into());
            }
            if !args.allow_reserved {
                conditions.push("name >= ?".into());
                params.push("\u{01}".to_string().into());
            }
            conditions.push(format!("deleted{deleted_arg}"));
            conditions.push("storage_policy_index = ?".into());
            params.push(args.storage_policy_index.into());

            let query = format!(
                "SELECT name, created_at, size, content_type, etag, deleted, \
                 storage_policy_index FROM object WHERE {} \
                        ORDER BY name {} LIMIT ?",
                conditions.join(" AND "),
                if args.reverse { "DESC" } else { "" },
            );
            params.push((args.limit - results.len() as i64).into());
            let mut stmt = conn.prepare(&query)?;
            let rows: Vec<(String, String, i64, Option<String>, String)> = stmt
                .query_map(rusqlite::params_from_iter(params), |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })?
                .collect::<Result<_, _>>()?;

            let transform = |r: &(String, String, i64, Option<String>, String)| {
                let (_, _, t_meta) = swift_core::timestamp::decode_timestamps(&r.1, false)
                    .unwrap_or_else(|_| {
                        let zero = "0".parse().unwrap();
                        (zero, Some(zero), Some(zero))
                    });
                vec![
                    DbValue::Text(r.0.clone()),
                    DbValue::Text(t_meta.map(|t| t.internal()).unwrap_or_default()),
                    DbValue::Int(r.2),
                    r.3.clone().map(DbValue::Text).unwrap_or(DbValue::Null),
                    DbValue::Text(r.4.clone()),
                ]
            };

            if prefix.is_none() || !has_delimiter {
                results.extend(rows.iter().map(transform));
                return Ok(results);
            }
            let delimiter = delimiter.clone().unwrap();
            let prefix_str = prefix.clone().unwrap();

            let mut rowcount = 0usize;
            let mut broke = false;
            for row in &rows {
                rowcount += 1;
                let name = row.0.clone();
                if args.reverse {
                    end_marker = name.clone();
                } else {
                    marker = name.clone();
                }
                if results.len() as i64 >= args.limit {
                    return Ok(results);
                }
                let end = name[prefix_str.len().min(name.len())..]
                    .find(&delimiter)
                    .map(|i| i + prefix_str.len().min(name.len()));
                if let Some(p) = &path {
                    if &name == p {
                        continue;
                    }
                    if let Some(end) = end {
                        if name.len() > end + delimiter.len() {
                            if args.reverse {
                                end_marker = name[..end + delimiter.len()].to_string();
                            } else {
                                marker = bump_delimiter_marker(&name, end, &delimiter);
                            }
                            broke = true;
                            break;
                        }
                    }
                } else if let Some(end) = end {
                    if args.reverse {
                        end_marker = name[..end + delimiter.len()].to_string();
                    } else {
                        marker = bump_delimiter_marker(&name, end, &delimiter);
                        delim_force_gte = true;
                    }
                    let dir_name = name[..end + delimiter.len()].to_string();
                    if dir_name != orig_marker {
                        results.push(vec![
                            DbValue::Text(dir_name),
                            DbValue::Text("0".into()),
                            DbValue::Int(0),
                            DbValue::Null,
                            DbValue::Text(String::new()),
                        ]);
                    }
                    broke = true;
                    break;
                }
                results.push(transform(row));
            }
            let _ = broke;
            if rowcount == 0 {
                return Ok(results);
            }
        }
    }
}

/// Python's `name[:end] + delimiter[:-1] + chr(ord(delimiter[-1]) + 1)`.
pub(crate) fn bump_delimiter_marker(name: &str, end: usize, delimiter: &str) -> String {
    let mut delim_chars: Vec<char> = delimiter.chars().collect();
    let last = delim_chars.pop().unwrap();
    let bumped = char::from_u32(last as u32 + 1).unwrap_or(last);
    let mut out = String::with_capacity(end + delimiter.len() + 4);
    out.push_str(&name[..end]);
    out.extend(delim_chars);
    out.push(bumped);
    out
}

impl ContainerBroker {
    /// `DatabaseBroker.update_put_timestamp`.
    pub fn update_put_timestamp(&mut self, timestamp: &str) -> Result<(), DbError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE container_stat SET put_timestamp = ? WHERE put_timestamp < ?",
            rusqlite::params![timestamp, timestamp],
        )?;
        Ok(())
    }
}

impl ContainerBroker {
    /// `ContainerBroker._empty`: no live objects in any policy on *this* DB
    /// file (not retiring, not shard-range rollup).
    fn policy_stat_empty(&mut self) -> Result<bool, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let max_count: Option<i64> =
            conn.query_row("SELECT max(object_count) from policy_stat", [], |row| {
                row.get(0)
            })?;
        Ok(matches!(max_count, None | Some(0)))
    }

    /// Python `get_shard_usage`: sum of `object_count`/`bytes_used` across
    /// other-ranges in `SHARD_STATS_STATES` (ACTIVE/SHARDING/SHRINKING).
    pub fn get_shard_usage(&mut self) -> Result<(i64, i64), DbError> {
        let path = self.path();
        let states = crate::shard::SHARD_STATS_STATES
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT COALESCE(SUM(bytes_used), 0), COALESCE(SUM(object_count), 0)
             FROM shard_range
             WHERE deleted = 0 AND name != ?1
               AND state IN ({states})"
        );
        let conn = self.conn()?;
        let row: (i64, i64) = conn.query_row(&sql, [path], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(row)
    }

    /// Python `sharding_initiated`: own range is in CLEAVING_STATES and
    /// at least one other shard range exists.
    pub fn sharding_initiated(&mut self) -> Result<bool, DbError> {
        let own = match self.get_own_shard_range(false)? {
            Some(o) => o,
            None => return Ok(false),
        };
        if crate::shard::CLEAVING_STATES.contains(&own.state) {
            self.has_other_shard_ranges()
        } else {
            Ok(false)
        }
    }

    /// Python `ContainerReplicator.cleanup_post_replicate`: a handoff must
    /// remain on disk while it is SHARDING, or while an UNSHARDED copy has
    /// learned shard ranges and still needs the sharder to cleave them.
    pub fn sharding_required(&mut self) -> Result<bool, DbError> {
        match self.get_db_state()? {
            DbState::Sharding => Ok(true),
            DbState::Unsharded => {
                Ok(self.sharding_initiated()? || self.has_other_shard_ranges()?)
            }
            _ => Ok(false),
        }
    }

    /// Live `deleted=0` rows in *this* DB file (pending committed).
    /// policy_stat can lag a tombstone merge; DELETE container (probe L2094)
    /// must follow actual live rows, matching Python empty() intent.
    fn live_object_rows_empty(&mut self) -> Result<bool, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let n: i64 = conn.query_row(
            "SELECT count(*) FROM object WHERE deleted = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(n == 0)
    }

    /// Python `ContainerBroker.empty`: retiring + fresh `_empty`, then for a
    /// root that has started sharding, shard-range usage (so a SHARDED root
    /// with objects in ACTIVE shards is not empty → DELETE 409, not 404).
    pub fn empty(&mut self) -> Result<bool, DbError> {
        // Prefer live rows over policy_stat: a tombstone that merged but did
        // not tick the trigger would 409 forever on collapsed roots.
        if !self.live_object_rows_empty()? {
            return Ok(false);
        }
        if let Some(mut retiring) = self.retiring_broker() {
            if !retiring.live_object_rows_empty()? {
                return Ok(false);
            }
        }
        if self.is_root_container()? && self.sharding_initiated()? {
            let (_, count) = self.get_shard_usage()?;
            return Ok(count <= 0);
        }
        Ok(true)
    }

    /// `get_info_is_deleted`: `({}, true)` when no DB file (including
    /// epoch-suffixed) exists under the hash dir.
    ///
    /// Must use [`Self::db_files`], not the constructor `<hash>.db` path —
    /// SHARDED roots keep only `<hash>_<epoch>.db` after retiring is unlinked.
    pub fn get_info_is_deleted(&mut self) -> Result<(Vec<(String, DbValue)>, bool), DbError> {
        if self.db_files().is_empty() {
            return Ok((Vec::new(), true));
        }
        let info = self.get_info()?;
        let get = |k: &str| {
            info.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
                .unwrap_or(DbValue::Null)
        };
        let zero = |v: &DbValue| match v {
            DbValue::Int(i) => *i == 0,
            DbValue::Text(s) => s.is_empty() || s == "0",
            DbValue::Null => true,
        };
        let newer = |a: &DbValue, b: &DbValue| -> bool {
            let parse = |v: &DbValue| match v {
                DbValue::Text(s) => s.parse::<Timestamp>().ok(),
                DbValue::Int(i) => Timestamp::from_secs(*i as f64).ok(),
                DbValue::Null => None,
            };
            matches!((parse(a), parse(b)), (Some(x), Some(y)) if x > y)
        };
        // Python get_info_is_deleted: deleted follows get_info object_count
        // (shard usage on SHARDED roots). Collapsed roots do not substitute
        // shard usage, so leftover shrink-to-root rows cannot revive L2095.
        let deleted = Self::info_shows_deleted(&info);
        let _ = (zero(&get("object_count")), newer(&get("delete_timestamp"), &get("put_timestamp")));
        Ok((info, deleted))
    }

    /// `ContainerBroker.storage_policy_index`.
    pub fn storage_policy_index(&mut self) -> Result<i64, DbError> {
        let conn = self.conn()?;
        Ok(conn.query_row(
            "SELECT storage_policy_index FROM container_stat",
            [],
            |row| row.get(0),
        )?)
    }

    /// `ContainerBroker.set_storage_policy_index`.
    pub fn set_storage_policy_index(
        &mut self,
        policy_index: i64,
        timestamp: &str,
    ) -> Result<(), DbError> {
        let conn = self.conn()?;
        conn.execute(
            "\n                INSERT OR IGNORE INTO policy_stat (storage_policy_index)\n                VALUES (?)\n             ",
            [policy_index],
        )?;
        conn.execute(
            "\n                UPDATE container_stat\n                SET storage_policy_index = ?,\n                    status_changed_at = MAX(?, status_changed_at)\n                WHERE storage_policy_index <> ?\n            ",
            rusqlite::params![policy_index, timestamp, policy_index],
        )?;
        Ok(())
    }

    /// `DatabaseBroker.update_status_changed_at`.
    pub fn update_status_changed_at(&mut self, timestamp: &str) -> Result<(), DbError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE container_stat SET status_changed_at = ? WHERE status_changed_at < ?",
            rusqlite::params![timestamp, timestamp],
        )?;
        Ok(())
    }
}

impl ContainerBroker {
    /// Whether object rows exist under more than one storage policy.
    pub fn has_multiple_policies(&mut self) -> Result<bool, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let count: i64 = conn.query_row(
            "SELECT count(storage_policy_index) FROM policy_stat",
            [],
            |row| row.get(0),
        )?;
        Ok(count > 1)
    }

    /// Last object ROWID successfully handed to the reconciler queue.
    pub fn get_reconciler_sync(&mut self) -> Result<i64, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        Ok(conn.query_row(
            "SELECT reconciler_sync_point FROM container_stat",
            [],
            |row| row.get(0),
        )?)
    }

    /// Advance the reconciler high-water mark after queue durability is
    /// protected by a successful replication majority.
    pub fn update_reconciler_sync(&mut self, point: i64) -> Result<(), DbError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE container_stat SET reconciler_sync_point = ?",
            [point],
        )?;
        Ok(())
    }

    /// Object rows whose policy differs from the authoritative container
    /// policy, ordered by ROWID for resumable queue feeding.
    pub fn get_misplaced_since(
        &mut self,
        start: i64,
        count: i64,
    ) -> Result<Vec<(i64, ObjectRecord)>, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT ROWID, name, created_at, size, content_type, etag, \
             deleted, storage_policy_index FROM object \
             WHERE ROWID > ? AND storage_policy_index != ( \
                 SELECT storage_policy_index FROM container_stat LIMIT 1) \
             ORDER BY ROWID ASC LIMIT ?",
        )?;
        let rows = stmt.query_map(rusqlite::params![start, count], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                ObjectRecord {
                    name: row.get(1)?,
                    created_at: row.get(2)?,
                    size: row.get(3)?,
                    content_type: row.get(4)?,
                    etag: row.get(5)?,
                    deleted: row.get(6)?,
                    storage_policy_index: row.get(7)?,
                    ctype_timestamp: None,
                    meta_timestamp: None,
                },
            ))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// `get_items_since`: object rows with ROWID > `start`, oldest
    /// first, up to `count` — the push-side query for usync replication.
    pub fn get_items_since(
        &mut self,
        start: i64,
        count: i64,
    ) -> Result<Vec<(i64, ObjectRecord)>, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT ROWID, name, created_at, size, content_type, etag, \
             deleted, storage_policy_index FROM object \
             WHERE ROWID > ? ORDER BY ROWID ASC LIMIT ?",
        )?;
        let rows = stmt.query_map(rusqlite::params![start, count], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                ObjectRecord {
                    name: row.get(1)?,
                    created_at: row.get(2)?,
                    size: row.get(3)?,
                    content_type: row.get(4)?,
                    etag: row.get(5)?,
                    deleted: row.get(6)?,
                    storage_policy_index: row.get(7)?,
                    ctype_timestamp: None,
                    meta_timestamp: None,
                },
            ))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// `get_sync`: the last sync point recorded for a remote id in the
    /// incoming (or outgoing) sync table, or -1.
    pub fn get_sync(&mut self, remote_id: &str, incoming: bool) -> Result<i64, DbError> {
        let table = if incoming {
            "incoming_sync"
        } else {
            "outgoing_sync"
        };
        let conn = self.conn()?;
        conn.query_row(
            &format!("SELECT sync_point FROM {table} WHERE remote_id=?"),
            [remote_id],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map(|v| v.unwrap_or(-1))
        .map_err(Into::into)
    }

    /// `merge_syncs`: upsert `(sync_point, remote_id)` rows keeping the
    /// max sync point.
    pub fn merge_syncs(
        &mut self,
        sync_points: &[(i64, String)],
        incoming: bool,
    ) -> Result<(), DbError> {
        let table = if incoming {
            "incoming_sync"
        } else {
            "outgoing_sync"
        };
        let conn = self.conn()?;
        for (sync_point, remote_id) in sync_points {
            let inserted = conn.execute(
                &format!("INSERT OR IGNORE INTO {table} (sync_point, remote_id) VALUES (?, ?)"),
                rusqlite::params![sync_point, remote_id],
            )?;
            if inserted == 0 {
                conn.execute(
                    &format!("UPDATE {table} SET sync_point=max(?, sync_point) WHERE remote_id=?"),
                    rusqlite::params![sync_point, remote_id],
                )?;
            }
        }
        Ok(())
    }

    /// `get_syncs` (db.py:726-745): the whole incoming (or outgoing) sync
    /// table, as the `(sync_point, remote_id)` pairs `merge_syncs` accepts.
    pub fn get_syncs(&mut self, incoming: bool) -> Result<Vec<(i64, String)>, DbError> {
        let table = if incoming {
            "incoming_sync"
        } else {
            "outgoing_sync"
        };
        let conn = self.conn()?;
        let mut stmt = conn.prepare(&format!("SELECT sync_point, remote_id FROM {table}"))?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// `DatabaseBroker.newid` (db.py:608-627) + `ContainerBroker._newid`
    /// (container/backend.py:684-688): re-id the database after an rsync.
    /// Sets a fresh unique id, records the incoming high-water mark for
    /// `remote_id` at the object table's max ROWID (`INSERT OR REPLACE`,
    /// not the max-merge upsert), and resets the reported_* stats so the
    /// adopted DB reports fresh numbers to the account.
    pub fn newid(&mut self, remote_id: &str) -> Result<(), DbError> {
        use rusqlite::OptionalExtension;
        let new_id = crate::broker::new_db_id();
        let conn = self.conn()?;
        conn.execute("UPDATE container_stat SET id=?", [new_id])?;
        let row: Option<i64> = conn
            .query_row(
                "SELECT ROWID FROM object ORDER BY ROWID DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let sync_point = row.unwrap_or(-1);
        conn.execute(
            "INSERT OR REPLACE INTO incoming_sync (sync_point, remote_id) VALUES (?, ?)",
            rusqlite::params![sync_point, remote_id],
        )?;
        // ContainerBroker._newid (container/backend.py:684-688)
        conn.execute(
            "UPDATE container_stat
             SET reported_put_timestamp = 0, reported_delete_timestamp = 0,
                 reported_object_count = 0, reported_bytes_used = 0",
            [],
        )?;
        Ok(())
    }

    /// `merge_timestamps`: MIN created_at / MAX put/delete, updating
    /// status_changed_at if the deleted-ness flips.
    pub fn merge_timestamps(
        &mut self,
        created_at: &str,
        put_timestamp: &str,
        delete_timestamp: &str,
    ) -> Result<(), DbError> {
        let before = self.is_deleted()?;
        {
            let conn = self.conn()?;
            conn.execute(
                "UPDATE container_stat SET created_at=MIN(?, created_at),\
                 put_timestamp=MAX(?, put_timestamp),\
                 delete_timestamp=MAX(?, delete_timestamp)",
                rusqlite::params![created_at, put_timestamp, delete_timestamp],
            )?;
        }
        if before != self.is_deleted()? {
            let info = self.get_info()?;
            let now = info
                .iter()
                .find(|(k, _)| k == "put_timestamp")
                .map(|(_, v)| match v {
                    DbValue::Text(s) => s.clone(),
                    DbValue::Int(i) => i.to_string(),
                    DbValue::Null => String::new(),
                })
                .unwrap_or_default();
            self.update_status_changed_at(&now)?;
        }
        Ok(())
    }

    /// `get_replication_info`: the info dict plus hash/max_row/metadata
    /// as the RPC returns them (count = object_count).
    pub fn get_replication_info(&mut self) -> Result<Vec<(String, DbValue)>, DbError> {
        let mut info = self.get_info()?;
        let object_count = info
            .iter()
            .find(|(k, _)| k == "object_count")
            .map(|(_, v)| v.clone())
            .unwrap_or(DbValue::Int(0));
        info.push(("count".to_string(), object_count));
        info.push((
            "max_row".to_string(),
            DbValue::Int(self.get_max_row()?.unwrap_or(-1)),
        ));
        info.push((
            "metadata".to_string(),
            DbValue::Text(self.get_raw_metadata()?),
        ));
        // Python ContainerBroker.get_replication_info includes shard_max_row
        // so peers know to run merge_shard_ranges / get_shard_ranges.
        info.push((
            "shard_max_row".to_string(),
            DbValue::Int(self.shard_max_row()?),
        ));
        Ok(info)
    }

    /// MAX(ROWID) of `shard_range`, or -1 when the table is empty/missing.
    pub fn shard_max_row(&mut self) -> Result<i64, DbError> {
        let conn = self.conn()?;
        let n: Option<i64> = conn
            .query_row("SELECT MAX(ROWID) FROM shard_range", [], |row| row.get(0))
            .unwrap_or(None);
        Ok(n.unwrap_or(-1))
    }
}
