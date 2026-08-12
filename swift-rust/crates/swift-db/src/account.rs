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

//! The account broker, ported from `swift/account/backend.py`. As with
//! the container broker, every SQL string is copied character for
//! character from the Python source so `sqlite_master` dumps compare
//! equal.

use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use swift_core::pickle::{self, Value};
use swift_core::timestamp::Timestamp;

use crate::container::DbValue;
use crate::util::{
    b64decode, b64encode, configure_connection, initialize_database, lock_parent_directory, DbError,
};
use crate::PENDING_CAP;

const PENDING_TIMEOUT: f64 = 10.0;

// ---- SQL scripts, verbatim from the Python source ----

const CONTAINER_TABLE_SCRIPT: &str = "
            CREATE TABLE container (
                ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                put_timestamp TEXT,
                delete_timestamp TEXT,
                object_count INTEGER,
                bytes_used INTEGER,
                deleted INTEGER DEFAULT 0,
                storage_policy_index INTEGER DEFAULT 0
            );

            CREATE INDEX ix_container_deleted_name ON
                container (deleted, name);

            CREATE TRIGGER container_insert AFTER INSERT ON container
            BEGIN
                UPDATE account_stat
                SET container_count = container_count + (1 - new.deleted),
                    object_count = object_count + new.object_count,
                    bytes_used = bytes_used + new.bytes_used,
                    hash = chexor(hash, new.name,
                                  new.put_timestamp || '-' ||
                                    new.delete_timestamp || '-' ||
                                    new.object_count || '-' || new.bytes_used);
            END;

            CREATE TRIGGER container_update BEFORE UPDATE ON container
            BEGIN
                SELECT RAISE(FAIL, 'UPDATE not allowed; DELETE and INSERT');
            END;


            CREATE TRIGGER container_delete AFTER DELETE ON container
            BEGIN
                UPDATE account_stat
                SET container_count = container_count - (1 - old.deleted),
                    object_count = object_count - old.object_count,
                    bytes_used = bytes_used - old.bytes_used,
                    hash = chexor(hash, old.name,
                                  old.put_timestamp || '-' ||
                                    old.delete_timestamp || '-' ||
                                    old.object_count || '-' || old.bytes_used);
            END;
        ";

const POLICY_STAT_TRIGGER_SCRIPT: &str = "
    CREATE TRIGGER container_insert_ps AFTER INSERT ON container
    BEGIN
        INSERT OR IGNORE INTO policy_stat
            (storage_policy_index, container_count, object_count, bytes_used)
            VALUES (new.storage_policy_index, 0, 0, 0);
        UPDATE policy_stat
        SET container_count = container_count + (1 - new.deleted),
            object_count = object_count + new.object_count,
            bytes_used = bytes_used + new.bytes_used
        WHERE storage_policy_index = new.storage_policy_index;
    END;
    CREATE TRIGGER container_delete_ps AFTER DELETE ON container
    BEGIN
        UPDATE policy_stat
        SET container_count = container_count - (1 - old.deleted),
            object_count = object_count - old.object_count,
            bytes_used = bytes_used - old.bytes_used
        WHERE storage_policy_index = old.storage_policy_index;
    END;

";

const ACCOUNT_STAT_TABLE_SCRIPT: &str = "
            CREATE TABLE account_stat (
                account TEXT,
                created_at TEXT,
                put_timestamp TEXT DEFAULT '0',
                delete_timestamp TEXT DEFAULT '0',
                container_count INTEGER,
                object_count INTEGER DEFAULT 0,
                bytes_used INTEGER DEFAULT 0,
                hash TEXT default '00000000000000000000000000000000',
                id TEXT,
                status TEXT DEFAULT '',
                status_changed_at TEXT DEFAULT '0',
                metadata TEXT DEFAULT ''
            );

            INSERT INTO account_stat (container_count) VALUES (0);
        ";

const POLICY_STAT_TABLE_SCRIPT: &str = "
            CREATE TABLE policy_stat (
                storage_policy_index INTEGER PRIMARY KEY,
                container_count INTEGER DEFAULT 0,
                object_count INTEGER DEFAULT 0,
                bytes_used INTEGER DEFAULT 0
            );
            INSERT OR IGNORE INTO policy_stat (
                storage_policy_index, container_count, object_count,
                bytes_used
            )
            SELECT 0, container_count, object_count, bytes_used
            FROM account_stat
            WHERE container_count > 0;
        ";

/// Python `swift.common.db.zero_like`: tolerant zero test over the
/// value shapes legacy producers wrote.
pub fn zero_like(v: &Value) -> bool {
    match v {
        Value::None => true,
        Value::Int(i) => *i == 0,
        Value::Str(s) => s.is_empty() || s == "0",
        Value::Bytes(b) => b.is_empty() || b == b"0",
        Value::Bool(b) => !b,
        _ => false,
    }
}

/// One container update record (`put_container`/pending file shape).
/// `object_count`/`bytes_used` stay as pickle values so the pending file
/// preserves the caller's str-vs-int choice byte for byte, exactly as
/// Python does; SQLite's INTEGER affinity coerces them on insert.
#[derive(Debug, Clone)]
pub struct ContainerRecord {
    pub name: String,
    pub put_timestamp: String,
    pub delete_timestamp: String,
    pub object_count: Value,
    pub bytes_used: Value,
    pub deleted: i64,
    pub storage_policy_index: i64,
}

fn value_to_sql(v: &Value) -> rusqlite::types::Value {
    match v {
        Value::None => rusqlite::types::Value::Null,
        Value::Int(i) => rusqlite::types::Value::Integer(*i),
        Value::Str(s) => rusqlite::types::Value::Text(s.clone()),
        Value::Float(f) => rusqlite::types::Value::Real(*f),
        Value::Bytes(b) => rusqlite::types::Value::Text(String::from_utf8_lossy(b).into_owned()),
        other => rusqlite::types::Value::Text(format!("{other:?}")),
    }
}

pub(crate) fn sql_value(v: rusqlite::types::ValueRef<'_>) -> Value {
    match v {
        rusqlite::types::ValueRef::Null => Value::None,
        rusqlite::types::ValueRef::Integer(i) => Value::Int(i),
        rusqlite::types::ValueRef::Real(f) => Value::Float(f),
        rusqlite::types::ValueRef::Text(t) => Value::Str(String::from_utf8_lossy(t).into_owned()),
        rusqlite::types::ValueRef::Blob(b) => Value::Bytes(b.to_vec()),
    }
}

/// The Rust `AccountBroker`.
pub struct AccountBroker {
    db_file: PathBuf,
    pending_file: PathBuf,
    account: String,
    conn: Option<Connection>,
}

impl AccountBroker {
    pub fn new(db_file: &Path, account: &str) -> Self {
        AccountBroker {
            db_file: db_file.to_path_buf(),
            pending_file: PathBuf::from(format!("{}.pending", db_file.display())),
            account: account.to_string(),
            conn: None,
        }
    }

    pub fn db_file(&self) -> &Path {
        &self.db_file
    }

    pub fn pending_file(&self) -> &Path {
        &self.pending_file
    }

    fn conn(&mut self) -> Result<&Connection, DbError> {
        if self.conn.is_none() {
            if !self.db_file.exists() {
                return Err(DbError::Connection(format!(
                    "{}: DB doesn't exist",
                    self.db_file.display()
                )));
            }
            let conn = Connection::open(&self.db_file)?;
            configure_connection(&conn)?;
            self.conn = Some(conn);
        }
        Ok(self.conn.as_ref().unwrap())
    }

    /// `DatabaseBroker.initialize` + `AccountBroker._initialize`.
    pub fn initialize(
        &mut self,
        put_timestamp: &str,
        created_at: &str,
        db_id: &str,
    ) -> Result<(), DbError> {
        let account = self.account.clone();
        let created_at = created_at.to_string();
        let db_id = db_id.to_string();
        let put_timestamp = put_timestamp.to_string();
        initialize_database(&self.db_file, PENDING_TIMEOUT, move |conn| {
            conn.execute_batch(&format!(
                "{CONTAINER_TABLE_SCRIPT}{POLICY_STAT_TRIGGER_SCRIPT}"
            ))?;
            conn.execute_batch(ACCOUNT_STAT_TABLE_SCRIPT)?;
            conn.execute(
                "\n            UPDATE account_stat SET account = ?, created_at = ?, id = ?,\n                   put_timestamp = ?, status_changed_at = ?\n            ",
                rusqlite::params![account, created_at, db_id, put_timestamp, put_timestamp],
            )?;
            conn.execute_batch(POLICY_STAT_TABLE_SCRIPT)?;
            Ok(())
        })
    }

    /// Port of `AccountBroker.put_container`.
    pub fn put_container(
        &mut self,
        name: &str,
        put_timestamp: &str,
        delete_timestamp: &str,
        object_count: Value,
        bytes_used: Value,
        storage_policy_index: i64,
    ) -> Result<(), DbError> {
        let deleted = match (
            delete_timestamp.parse::<Timestamp>(),
            put_timestamp.parse::<Timestamp>(),
        ) {
            (Ok(d), Ok(p)) if d > p && zero_like(&object_count) => 1,
            _ => 0,
        };
        let record = ContainerRecord {
            name: name.to_string(),
            put_timestamp: put_timestamp.to_string(),
            delete_timestamp: delete_timestamp.to_string(),
            object_count,
            bytes_used,
            deleted,
            storage_policy_index,
        };
        self.put_record(record)
    }

    /// `make_tuple_for_pickle` for an account record.
    fn record_to_pickle_value(record: &ContainerRecord) -> Value {
        Value::Tuple(vec![
            Value::Str(record.name.clone()),
            Value::Str(record.put_timestamp.clone()),
            Value::Str(record.delete_timestamp.clone()),
            record.object_count.clone(),
            record.bytes_used.clone(),
            Value::Int(record.deleted),
            Value::Int(record.storage_policy_index),
        ])
    }

    /// `_commit_puts_load` for one pending tuple.
    fn record_from_pickle_value(value: &Value) -> Result<ContainerRecord, DbError> {
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
        Ok(ContainerRecord {
            name: s(&items[0])?,
            put_timestamp: s(&items[1])?,
            delete_timestamp: s(&items[2])?,
            object_count: items[3].clone(),
            bytes_used: items[4].clone(),
            deleted: i(&items[5])?,
            storage_policy_index: if items.len() > 6 { i(&items[6])? } else { 0 },
        })
    }

    /// Port of `DatabaseBroker.put_record` (see the container broker).
    pub fn put_record(&mut self, record: ContainerRecord) -> Result<(), DbError> {
        if !self.db_file.exists() {
            return Err(DbError::Connection(format!(
                "{}: DB doesn't exist",
                self.db_file.display()
            )));
        }
        let _lock = lock_parent_directory(&self.pending_file, PENDING_TIMEOUT)?;
        let pending_size = std::fs::metadata(&self.pending_file)
            .map(|m| m.len())
            .unwrap_or(0);
        if pending_size > PENDING_CAP {
            self.commit_puts(vec![record])
        } else {
            let blob = pickle::dumps(&Self::record_to_pickle_value(&record))?;
            let mut fp = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&self.pending_file)?;
            fp.write_all(b":")?;
            fp.write_all(b64encode(&blob).as_bytes())?;
            fp.flush()?;
            Ok(())
        }
    }

    fn commit_puts(&mut self, extra: Vec<ContainerRecord>) -> Result<(), DbError> {
        let mut item_list = Vec::new();
        let raw = match std::fs::read(&self.pending_file) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(DbError::Io(e)),
        };
        for entry in raw.split(|&b| b == b':') {
            if entry.is_empty() {
                continue;
            }
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
            std::fs::write(&self.pending_file, b"")?;
        }
        Ok(())
    }

    pub fn commit_pending(&mut self) -> Result<(), DbError> {
        if !self.pending_file.exists() {
            return Ok(());
        }
        let _lock = lock_parent_directory(&self.pending_file, PENDING_TIMEOUT)?;
        self.commit_puts(Vec::new())
    }

    /// Port of `AccountBroker.merge_items`: per-record newest-timestamp
    /// merge with the deleted flag recomputed against the merged state.
    pub fn merge_items(&mut self, item_list: Vec<ContainerRecord>) -> Result<(), DbError> {
        let conn = self.conn()?;
        let has_index: bool = conn
            .prepare("SELECT name FROM sqlite_master WHERE name = 'ix_container_deleted_name'")?
            .exists([])?;

        for mut rec in item_list {
            let mut query = String::from(
                "\n                    SELECT name, put_timestamp, delete_timestamp,\n                           object_count, bytes_used, deleted,\n                           storage_policy_index\n                    FROM container WHERE name = ?\n                ",
            );
            if has_index {
                query.push_str(" AND deleted IN (0, 1)");
            }
            let row: Option<(String, String, String, Value, Value, i64, i64)> = conn
                .query_row(&query, [&rec.name], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        sql_value(row.get_ref(3)?),
                        sql_value(row.get_ref(4)?),
                        row.get(5)?,
                        row.get(6)?,
                    ))
                })
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })?;

            if let Some((_, row_put, row_delete, row_oc, row_bu, _, _)) = row {
                // None-filled fields take the existing row's values
                if matches!(rec.object_count, Value::None) && !matches!(row_oc, Value::None) {
                    rec.object_count = row_oc;
                }
                if matches!(rec.bytes_used, Value::None) && !matches!(row_bu, Value::None) {
                    rec.bytes_used = row_bu;
                }
                // keep newest put/delete timestamps
                if let (Ok(a), Ok(b)) = (
                    row_put.parse::<Timestamp>(),
                    rec.put_timestamp.parse::<Timestamp>(),
                ) {
                    if a > b {
                        rec.put_timestamp = row_put;
                    }
                }
                if let (Ok(a), Ok(b)) = (
                    row_delete.parse::<Timestamp>(),
                    rec.delete_timestamp.parse::<Timestamp>(),
                ) {
                    if a > b {
                        rec.delete_timestamp = row_delete;
                    }
                }
                // if deleted, mark as such
                rec.deleted = match (
                    rec.delete_timestamp.parse::<Timestamp>(),
                    rec.put_timestamp.parse::<Timestamp>(),
                ) {
                    (Ok(d), Ok(p)) if d > p && zero_like(&rec.object_count) => 1,
                    _ => 0,
                };
            }
            conn.execute(
                "\n                    DELETE FROM container WHERE name = ? AND\n                                                deleted IN (0, 1)\n                ",
                [&rec.name],
            )?;
            conn.execute(
                "\n                    INSERT INTO container (name, put_timestamp,\n                        delete_timestamp, object_count, bytes_used,\n                        deleted, storage_policy_index)\n                    VALUES (?, ?, ?, ?, ?, ?, ?)\n                ",
                rusqlite::params![
                    rec.name,
                    rec.put_timestamp,
                    rec.delete_timestamp,
                    value_to_sql(&rec.object_count),
                    value_to_sql(&rec.bytes_used),
                    rec.deleted,
                    rec.storage_policy_index
                ],
            )?;
        }
        Ok(())
    }

    /// Port of `AccountBroker.get_info`.
    pub fn get_info(&mut self) -> Result<Vec<(String, DbValue)>, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let sql = "
                SELECT account, created_at,  put_timestamp, delete_timestamp,
                       status_changed_at, container_count, object_count,
                       bytes_used, hash, id
                FROM account_stat
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
            .ok_or_else(|| DbError::Connection("no account_stat row".to_string()))?;
        let mut out = Vec::with_capacity(names.len());
        for (i, name) in names.iter().enumerate() {
            out.push((name.clone(), DbValue::from_sql(row.get_ref(i)?)));
        }
        Ok(out)
    }

    /// Test/tooling helper: `SELECT name, sql FROM sqlite_master`.
    pub fn schema_dump(&mut self) -> Result<Vec<(String, Option<String>)>, DbError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT name, sql FROM sqlite_master ORDER BY name")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Test/tooling helper: full container table dump in ROWID order.
    pub fn container_rows(&mut self) -> Result<Vec<Vec<DbValue>>, DbError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT ROWID, name, put_timestamp, delete_timestamp, \
             object_count, bytes_used, deleted, storage_policy_index \
             FROM container ORDER BY ROWID",
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

    /// Test/tooling helper: policy_stat dump ordered by policy index.
    pub fn policy_stat_rows(&mut self) -> Result<Vec<Vec<DbValue>>, DbError> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT storage_policy_index, container_count, object_count,\
             bytes_used FROM policy_stat ORDER BY storage_policy_index",
        )?;
        let rows = stmt.query_map([], |row| {
            let mut out = Vec::with_capacity(4);
            for i in 0..4 {
                out.push(DbValue::from_sql(row.get_ref(i)?));
            }
            Ok(out)
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_like() {
        assert!(zero_like(&Value::None));
        assert!(zero_like(&Value::Int(0)));
        assert!(zero_like(&Value::Str("0".into())));
        assert!(zero_like(&Value::Str("".into())));
        assert!(!zero_like(&Value::Int(3)));
        assert!(!zero_like(&Value::Str("3".into())));
    }

    #[test]
    fn test_newid_changes_id_and_records_sync_point() {
        // db.py:608-627: newid re-ids the DB and records the incoming
        // high-water mark for the remote id at the container table's max
        // ROWID (-1 while the table is empty).
        let dir = std::env::temp_dir().join(format!("swift-acct-newid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut b = AccountBroker::new(&dir.join("hash.db"), "a");
        b.initialize("1751500000.00000", "1751500000.00000", "orig-id")
            .unwrap();
        b.newid("remote-empty").unwrap();
        assert_eq!(b.get_sync("remote-empty", true).unwrap(), -1);
        for i in 0..2 {
            b.put_container(
                &format!("c{i}"),
                "1751500001.00000",
                "0",
                Value::Int(0),
                Value::Int(0),
                0,
            )
            .unwrap();
        }
        b.commit_pending().unwrap();
        let id_of = |b: &mut AccountBroker| {
            b.get_replication_info()
                .unwrap()
                .into_iter()
                .find(|(k, _)| k == "id")
                .and_then(|(_, v)| v.as_text())
                .unwrap()
        };
        let before = id_of(&mut b);
        b.newid("remote-abc").unwrap();
        assert_ne!(id_of(&mut b), before);
        assert_eq!(b.get_sync("remote-abc", true).unwrap(), 2);
        let syncs = b.get_syncs(true).unwrap();
        assert!(syncs.contains(&(2, "remote-abc".to_string())), "{syncs:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Arguments to [`AccountBroker::list_containers_iter`].
#[derive(Debug, Clone, Default)]
pub struct ListContainersArgs {
    pub limit: i64,
    pub marker: String,
    pub end_marker: String,
    pub prefix: Option<String>,
    pub delimiter: Option<String>,
    pub reverse: bool,
    pub allow_reserved: bool,
}

impl AccountBroker {
    pub fn get_raw_metadata(&mut self) -> Result<String, DbError> {
        crate::broker::get_raw_metadata(self.conn()?, "account")
    }

    pub fn metadata(&mut self) -> Result<crate::broker::BrokerMetadata, DbError> {
        crate::broker::get_metadata(self.conn()?, "account")
    }

    pub fn update_metadata(
        &mut self,
        updates: &crate::broker::BrokerMetadata,
    ) -> Result<(), DbError> {
        crate::broker::update_metadata(self.conn()?, "account", updates)
    }

    pub fn delete_db(&mut self, timestamp: &str) -> Result<(), DbError> {
        crate::broker::delete_db(self.conn()?, "account", timestamp, &[])
    }

    /// `AccountBroker.is_status_deleted` + `_is_deleted`: the status
    /// column counts for accounts.
    pub fn is_deleted(&mut self) -> Result<bool, DbError> {
        if !self.db_file().exists() {
            return Ok(true);
        }
        self.commit_pending()?;
        let conn = self.conn()?;
        let (put_ts, delete_ts, container_count, status): (String, String, Value, String) =
            conn.query_row(
                "\n            SELECT put_timestamp, delete_timestamp, container_count, status\n            FROM account_stat",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        sql_value(row.get_ref(2)?),
                        row.get(3)?,
                    ))
                },
            )?;
        Ok(status == "DELETED"
            || zero_like(&container_count)
                && matches!(
                    (delete_ts.parse::<Timestamp>(), put_ts.parse::<Timestamp>()),
                    (Ok(d), Ok(p)) if d > p
                ))
    }

    pub fn reclaim(&mut self, age_timestamp: f64, sync_timestamp: f64) -> Result<u64, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let reclaimed = crate::broker::reclaim_tombstones(
            conn,
            "container",
            "delete_timestamp",
            age_timestamp,
        )?;
        crate::broker::reclaim_other_stuff(conn, "account", age_timestamp, sync_timestamp)?;
        Ok(reclaimed)
    }

    pub fn get_max_row(&mut self) -> Result<Option<i64>, DbError> {
        crate::broker::get_max_row(self.conn()?, "container")
    }

    /// Container rows with `ROWID > start`, in ROWID order, for the
    /// db_replicator usync push (the account analogue of
    /// [`crate::ContainerBroker::get_items_since`]).
    pub fn get_items_since(
        &mut self,
        start: i64,
        count: i64,
    ) -> Result<Vec<(i64, ContainerRecord)>, DbError> {
        self.commit_pending()?;
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT ROWID, name, put_timestamp, delete_timestamp, \
             object_count, bytes_used, deleted, storage_policy_index FROM container \
             WHERE ROWID > ? ORDER BY ROWID ASC LIMIT ?",
        )?;
        let rows = stmt.query_map(rusqlite::params![start, count], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                ContainerRecord {
                    name: row.get(1)?,
                    put_timestamp: row.get(2)?,
                    delete_timestamp: row.get(3)?,
                    object_count: sql_value(row.get_ref(4)?),
                    bytes_used: sql_value(row.get_ref(5)?),
                    deleted: row.get(6)?,
                    storage_policy_index: row.get(7)?,
                },
            ))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Port of `AccountBroker.list_containers_iter`. Rows are
    /// `[name, object_count, bytes_used, put_timestamp,
    /// storage_policy_index, is_subdir]`; subdir entries are
    /// `[name, 0, 0, '0', -1, 1]`.
    pub fn list_containers_iter(
        &mut self,
        args: &ListContainersArgs,
    ) -> Result<Vec<Vec<DbValue>>, DbError> {
        self.commit_pending()?;
        let mut marker = args.marker.clone();
        let mut end_marker = args.end_marker.clone();
        if args.reverse {
            std::mem::swap(&mut marker, &mut end_marker);
        }
        let mut prefix = args.prefix.clone();
        let delimiter = args.delimiter.clone();
        let has_delimiter = delimiter.as_deref().is_some_and(|d| !d.is_empty());
        if has_delimiter && prefix.is_none() {
            prefix = Some(String::new());
        }
        let end_prefix = prefix.as_deref().filter(|p| !p.is_empty()).map(|p| {
            let mut chars: Vec<char> = p.chars().collect();
            let last = chars.pop().unwrap();
            chars.push(char::from_u32(last as u32 + 1).unwrap_or(last));
            chars.into_iter().collect::<String>()
        });
        let orig_marker = marker.clone();
        let mut delim_force_gte = false;

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
            conditions.push("deleted = 0".into());
            let query = format!(
                "SELECT name, object_count, bytes_used, put_timestamp, \
                 storage_policy_index, 0 FROM container WHERE {} \
                 ORDER BY name {} LIMIT ?",
                conditions.join(" AND "),
                if args.reverse { "DESC" } else { "" },
            );
            params.push((args.limit - results.len() as i64).into());
            let mut stmt = conn.prepare(&query)?;
            let rows: Vec<Vec<DbValue>> = stmt
                .query_map(rusqlite::params_from_iter(params), |row| {
                    let mut out = Vec::with_capacity(6);
                    for i in 0..6 {
                        out.push(DbValue::from_sql(row.get_ref(i)?));
                    }
                    Ok(out)
                })?
                .collect::<Result<_, _>>()?;

            if prefix.is_none() || !has_delimiter {
                results.extend(rows);
                return Ok(results);
            }
            let delimiter = delimiter.clone().unwrap();
            let prefix_str = prefix.clone().unwrap();

            let mut rowcount = 0usize;
            for row in &rows {
                rowcount += 1;
                let DbValue::Text(name) = &row[0] else {
                    continue;
                };
                let name = name.clone();
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
                if let Some(end) = end {
                    if args.reverse {
                        end_marker = name[..end + delimiter.len()].to_string();
                    } else {
                        marker = crate::container::bump_delimiter_marker(&name, end, &delimiter);
                        delim_force_gte = true;
                    }
                    let dir_name = name[..end + delimiter.len()].to_string();
                    if dir_name != orig_marker {
                        results.push(vec![
                            DbValue::Text(dir_name),
                            DbValue::Int(0),
                            DbValue::Int(0),
                            DbValue::Text("0".into()),
                            DbValue::Int(-1),
                            DbValue::Int(1),
                        ]);
                    }
                    break;
                }
                results.push(row.clone());
            }
            if rowcount == 0 {
                return Ok(results);
            }
        }
    }
}

impl AccountBroker {
    /// `AccountBroker.is_status_deleted`: status column or raw string
    /// timestamp comparison.
    pub fn is_status_deleted(&mut self) -> Result<bool, DbError> {
        let conn = self.conn()?;
        let (put_ts, delete_ts, status): (String, String, String) = conn.query_row(
            "\n                SELECT put_timestamp, delete_timestamp, status\n                FROM account_stat",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok(status == "DELETED" || delete_ts > put_ts)
    }

    /// `DatabaseBroker.update_put_timestamp`.
    pub fn update_put_timestamp(&mut self, timestamp: &str) -> Result<(), DbError> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE account_stat SET put_timestamp = ? WHERE put_timestamp < ?",
            rusqlite::params![timestamp, timestamp],
        )?;
        Ok(())
    }
}

impl AccountBroker {
    /// `get_sync`: last incoming/outgoing sync point for a remote id.
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

    /// `merge_syncs`: max-sync-point upsert.
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

    /// `DatabaseBroker.newid` (db.py:608-627): re-id the database after an
    /// rsync. Sets a fresh unique id and records the incoming high-water
    /// mark for `remote_id` at the container table's max ROWID
    /// (`INSERT OR REPLACE`, not the max-merge upsert). AccountBroker has
    /// no `_newid` override (db.py:629-631 is a no-op).
    pub fn newid(&mut self, remote_id: &str) -> Result<(), DbError> {
        use rusqlite::OptionalExtension;
        let new_id = crate::broker::new_db_id();
        let conn = self.conn()?;
        conn.execute("UPDATE account_stat SET id=?", [new_id])?;
        let row: Option<i64> = conn
            .query_row(
                "SELECT ROWID FROM container ORDER BY ROWID DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let sync_point = row.unwrap_or(-1);
        conn.execute(
            "INSERT OR REPLACE INTO incoming_sync (sync_point, remote_id) VALUES (?, ?)",
            rusqlite::params![sync_point, remote_id],
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
                "UPDATE account_stat SET created_at=MIN(?, created_at),\
                 put_timestamp=MAX(?, put_timestamp),\
                 delete_timestamp=MAX(?, delete_timestamp)",
                rusqlite::params![created_at, put_timestamp, delete_timestamp],
            )?;
        }
        if before != self.is_deleted()? {
            let now = crate::container::now_internal();
            let conn = self.conn()?;
            conn.execute(
                "UPDATE account_stat SET status_changed_at = ? WHERE status_changed_at < ?",
                rusqlite::params![now, now],
            )?;
        }
        Ok(())
    }

    /// `get_replication_info`: info + count (container_count) + max_row +
    /// raw metadata.
    pub fn get_replication_info(&mut self) -> Result<Vec<(String, DbValue)>, DbError> {
        let mut info = self.get_info()?;
        let count = info
            .iter()
            .find(|(k, _)| k == "container_count")
            .map(|(_, v)| v.clone())
            .unwrap_or(DbValue::Int(0));
        info.push(("count".to_string(), count));
        info.push((
            "max_row".to_string(),
            DbValue::Int(self.get_max_row()?.unwrap_or(-1)),
        ));
        info.push((
            "metadata".to_string(),
            DbValue::Text(self.get_raw_metadata()?),
        ));
        Ok(info)
    }
}
