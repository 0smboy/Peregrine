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

//! Shared `DatabaseBroker` behavior: the JSON metadata column,
//! `update_metadata` timestamp merging, `delete_db`, and row/metadata
//! reclamation (`TombstoneReclaimer`, `_reclaim_metadata`,
//! `_reclaim_sync`).
//!
//! The metadata column is written with a Python-compatible `json.dumps`
//! (`ensure_ascii`, `', '`/`': '` separators, insertion order) so the
//! raw column bytes compare equal against the Python oracle.

use rusqlite::Connection;
use swift_core::timestamp::Timestamp;

use crate::util::DbError;

pub const RECLAIM_PAGE_SIZE: i64 = 10000;

/// Metadata is insertion-ordered `key -> (value, timestamp)`.
pub type BrokerMetadata = Vec<(String, (String, String))>;

// ---- Python-compatible JSON for the metadata column ----

fn escape_json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) > 0x7e => {
                // ensure_ascii: BMP chars one escape, astral chars as a
                // surrogate pair
                let cp = c as u32;
                if cp > 0xffff {
                    let v = cp - 0x10000;
                    out.push_str(&format!("\\u{:04x}", 0xd800 + (v >> 10)));
                    out.push_str(&format!("\\u{:04x}", 0xdc00 + (v & 0x3ff)));
                } else {
                    out.push_str(&format!("\\u{cp:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `json.dumps(md)` for the metadata dict shape.
pub fn py_json_dumps_metadata(md: &BrokerMetadata) -> String {
    if md.is_empty() {
        return "{}".to_string();
    }
    let mut out = String::from("{");
    for (i, (key, (value, timestamp))) in md.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        escape_json_str(key, &mut out);
        out.push_str(": [");
        escape_json_str(value, &mut out);
        out.push_str(", ");
        escape_json_str(timestamp, &mut out);
        out.push(']');
    }
    out.push('}');
    out
}

struct JsonParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl JsonParser<'_> {
    fn skip_ws(&mut self) {
        while self.pos < self.data.len()
            && matches!(self.data[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), DbError> {
        self.skip_ws();
        if self.pos < self.data.len() && self.data[self.pos] == b {
            self.pos += 1;
            Ok(())
        } else {
            Err(DbError::Connection(format!(
                "bad metadata JSON at offset {}",
                self.pos
            )))
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_ws();
        self.data.get(self.pos).copied()
    }

    fn parse_string(&mut self) -> Result<String, DbError> {
        self.expect(b'"')?;
        let mut out = String::new();
        let mut pending_surrogate: Option<u32> = None;
        loop {
            let b = *self
                .data
                .get(self.pos)
                .ok_or_else(|| DbError::Connection("truncated JSON string".into()))?;
            self.pos += 1;
            match b {
                b'"' => break,
                b'\\' => {
                    let esc = *self
                        .data
                        .get(self.pos)
                        .ok_or_else(|| DbError::Connection("truncated escape".into()))?;
                    self.pos += 1;
                    let simple = match esc {
                        b'"' => Some('"'),
                        b'\\' => Some('\\'),
                        b'/' => Some('/'),
                        b'n' => Some('\n'),
                        b'r' => Some('\r'),
                        b't' => Some('\t'),
                        b'b' => Some('\u{08}'),
                        b'f' => Some('\u{0c}'),
                        b'u' => None,
                        other => {
                            return Err(DbError::Connection(format!(
                                "bad escape \\{}",
                                other as char
                            )))
                        }
                    };
                    if let Some(c) = simple {
                        pending_surrogate = None;
                        out.push(c);
                        continue;
                    }
                    let hex = self
                        .data
                        .get(self.pos..self.pos + 4)
                        .ok_or_else(|| DbError::Connection("truncated \\u".into()))?;
                    self.pos += 4;
                    let cp = u32::from_str_radix(std::str::from_utf8(hex).unwrap_or(""), 16)
                        .map_err(|_| DbError::Connection("bad \\u escape".into()))?;
                    if let Some(high) = pending_surrogate.take() {
                        if (0xdc00..=0xdfff).contains(&cp) {
                            let combined = 0x10000 + ((high - 0xd800) << 10) + (cp - 0xdc00);
                            out.push(char::from_u32(combined).unwrap_or('\u{fffd}'));
                            continue;
                        }
                        out.push('\u{fffd}');
                    }
                    if (0xd800..=0xdbff).contains(&cp) {
                        pending_surrogate = Some(cp);
                    } else {
                        out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                    }
                }
                b => {
                    pending_surrogate = None;
                    // collect the full utf-8 sequence
                    let len = match b {
                        0x00..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    let start = self.pos - 1;
                    self.pos = start + len;
                    let raw = self
                        .data
                        .get(start..self.pos)
                        .ok_or_else(|| DbError::Connection("truncated utf-8".into()))?;
                    out.push_str(&String::from_utf8_lossy(raw));
                }
            }
        }
        Ok(out)
    }
}

/// Parse the metadata column: `{"key": ["value", "timestamp"], ...}`,
/// preserving insertion order.
pub fn py_json_parse_metadata(raw: &str) -> Result<BrokerMetadata, DbError> {
    let mut out = BrokerMetadata::new();
    let mut p = JsonParser {
        data: raw.as_bytes(),
        pos: 0,
    };
    p.expect(b'{')?;
    if p.peek() == Some(b'}') {
        return Ok(out);
    }
    loop {
        let key = p.parse_string()?;
        p.expect(b':')?;
        p.expect(b'[')?;
        let value = p.parse_string()?;
        p.expect(b',')?;
        let timestamp = p.parse_string()?;
        p.expect(b']')?;
        out.push((key, (value, timestamp)));
        match p.peek() {
            Some(b',') => {
                p.pos += 1;
            }
            Some(b'}') => break,
            _ => return Err(DbError::Connection("bad metadata JSON object".into())),
        }
    }
    Ok(out)
}

// ---- shared broker operations ----

/// `DatabaseBroker._new_db_id` (db.py:604-606): a fresh unique id for a
/// re-id'd database. Python uses `str(uuid4())-<device_name>`; only the
/// uniqueness matters, so this is nanos + pid + a process counter (no
/// uuid dependency, the same approach as `quarantine_db`).
pub(crate) fn new_db_id() -> String {
    static DB_ID_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{nanos:x}-{:x}-{:x}",
        std::process::id(),
        DB_ID_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    )
}

pub(crate) fn get_raw_metadata(conn: &Connection, db_type: &str) -> Result<String, DbError> {
    let raw: String =
        conn.query_row(&format!("SELECT metadata FROM {db_type}_stat"), [], |row| {
            row.get(0)
        })?;
    Ok(raw)
}

pub(crate) fn get_metadata(conn: &Connection, db_type: &str) -> Result<BrokerMetadata, DbError> {
    let raw = get_raw_metadata(conn, db_type)?;
    if raw.is_empty() {
        Ok(BrokerMetadata::new())
    } else {
        py_json_parse_metadata(&raw)
    }
}

/// Port of `DatabaseBroker.update_metadata`: keys are overwritten only
/// by newer timestamps; deletions are empty values awaiting reclaim.
pub(crate) fn update_metadata(
    conn: &Connection,
    db_type: &str,
    updates: &BrokerMetadata,
) -> Result<(), DbError> {
    let mut md = get_metadata(conn, db_type)?;
    // fast path: all updates older than what we have
    let all_known = updates.iter().all(|(k, (_, t))| {
        md.iter()
            .any(|(mk, (_, mt))| mk == k && t.as_str() <= mt.as_str())
    });
    if all_known {
        return Ok(());
    }
    for (key, (value, timestamp)) in updates {
        match md.iter_mut().find(|(k, _)| k == key) {
            Some((_, existing)) => {
                if timestamp.as_str() > existing.1.as_str() {
                    *existing = (value.clone(), timestamp.clone());
                }
            }
            None => md.push((key.clone(), (value.clone(), timestamp.clone()))),
        }
    }
    conn.execute(
        &format!("UPDATE {db_type}_stat SET metadata = ?"),
        [py_json_dumps_metadata(&md)],
    )?;
    Ok(())
}

/// Port of `DatabaseBroker.delete_db`: clear metadata (except the
/// whitelist), then mark the stat row DELETED.
pub(crate) fn delete_db(
    conn: &Connection,
    db_type: &str,
    timestamp: &str,
    delete_meta_whitelist: &[&str],
) -> Result<(), DbError> {
    let md = get_metadata(conn, db_type)?;
    let cleared: BrokerMetadata = md
        .iter()
        .filter(|(k, _)| !delete_meta_whitelist.contains(&k.to_lowercase().as_str()))
        .map(|(k, _)| (k.clone(), (String::new(), timestamp.to_string())))
        .collect();
    update_metadata(conn, db_type, &cleared)?;
    conn.execute(
        &format!(
            "\n                UPDATE {db_type}_stat\n                SET delete_timestamp = ?,\n                    status = 'DELETED',\n                    status_changed_at = ?\n                WHERE delete_timestamp < ? "
        ),
        rusqlite::params![timestamp, timestamp, timestamp],
    )?;
    Ok(())
}

/// Python `str(float)` for the values reclaim interpolates into SQL.
pub(crate) fn py_float_repr(f: f64) -> String {
    let s = format!("{f}");
    if s.contains('.') || s.contains('e') || s.contains("inf") || s.contains("nan") {
        s
    } else {
        format!("{s}.0")
    }
}

/// Port of `TombstoneReclaimer`: batched deletion of tombstone rows
/// older than `age_timestamp`. Returns the number of reclaimed rows.
pub(crate) fn reclaim_tombstones(
    conn: &Connection,
    contains_type: &str,
    reclaim_timestamp_col: &str,
    age_timestamp: f64,
) -> Result<u64, DbError> {
    let age = py_float_repr(age_timestamp);
    let batch_query = format!(
        "\n            SELECT name FROM {contains_type} WHERE deleted = 1\n            AND name >= ?\n            ORDER BY NAME LIMIT 1 OFFSET ?\n        "
    );
    let clean_batch_query = format!(
        "\n            DELETE FROM {contains_type} WHERE deleted = 1\n            AND name >= ? AND {reclaim_timestamp_col} < '{age}'\n        "
    );
    let mut marker = String::new();
    let mut reclaimed = 0u64;
    loop {
        let end_marker: Option<String> = conn
            .query_row(
                &batch_query,
                rusqlite::params![marker, RECLAIM_PAGE_SIZE],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        match end_marker {
            Some(end_marker) => {
                let n = conn.execute(
                    &format!("{clean_batch_query} AND name < ?"),
                    rusqlite::params![marker, end_marker],
                )?;
                reclaimed += n as u64;
                marker = end_marker;
            }
            None => {
                let n = conn.execute(&clean_batch_query, rusqlite::params![marker])?;
                reclaimed += n as u64;
                return Ok(reclaimed);
            }
        }
    }
}

/// `_reclaim_sync` + `_reclaim_metadata`.
pub(crate) fn reclaim_other_stuff(
    conn: &Connection,
    db_type: &str,
    age_timestamp: f64,
    sync_timestamp: f64,
) -> Result<(), DbError> {
    conn.execute(
        "\n                DELETE FROM outgoing_sync WHERE updated_at < ?\n            ",
        [sync_timestamp],
    )?;
    conn.execute(
        "\n                DELETE FROM incoming_sync WHERE updated_at < ?\n            ",
        [sync_timestamp],
    )?;
    // metadata: drop empty values last set before age_timestamp
    let age = Timestamp::from_secs(age_timestamp)
        .map_err(|e| DbError::Connection(format!("bad age timestamp: {e}")))?;
    let md = get_metadata(conn, db_type)?;
    let kept: BrokerMetadata = md
        .iter()
        .filter(|(_, (value, ts))| {
            !(value.is_empty() && ts.parse::<Timestamp>().map(|t| t < age).unwrap_or(false))
        })
        .cloned()
        .collect();
    if kept.len() != md.len() {
        conn.execute(
            &format!("UPDATE {db_type}_stat SET metadata = ?"),
            [py_json_dumps_metadata(&kept)],
        )?;
    }
    Ok(())
}

/// `get_max_row`: the highest ROWID ever assigned to `table`, from
/// `SQLITE_SEQUENCE.seq` (Python `DatabaseBroker.get_max_row`). Unlike
/// `max(ROWID)`, this does not regress when the top rows are deleted/reclaimed,
/// so the replication high-water mark stays consistent with Python across a
/// mixed cluster. `None` (mapped to -1 by callers) when the table has never
/// been inserted into.
pub(crate) fn get_max_row(conn: &Connection, table: &str) -> Result<Option<i64>, DbError> {
    use rusqlite::OptionalExtension;
    let row: Option<i64> = conn
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name = ?1 LIMIT 1",
            [table],
            |row| row.get(0),
        )
        .optional()?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_py_json_round_trip() {
        let md: BrokerMetadata = vec![
            (
                "X-Container-Meta-中文".to_string(),
                ("值\u{1}\"x\"".to_string(), "1751500001.00000".to_string()),
            ),
            (
                "X-Container-Meta-Emoji".to_string(),
                ("😀".to_string(), "1751500002.00000".to_string()),
            ),
        ];
        let raw = py_json_dumps_metadata(&md);
        assert!(raw.contains("\\u4e2d\\u6587"), "{raw}");
        assert!(raw.contains("\\ud83d\\ude00"), "{raw}");
        assert_eq!(py_json_parse_metadata(&raw).unwrap(), md);
        assert_eq!(py_json_dumps_metadata(&BrokerMetadata::new()), "{}");
    }

    #[test]
    fn test_py_float_repr() {
        assert_eq!(py_float_repr(1500000000.5), "1500000000.5");
        assert_eq!(py_float_repr(1500000000.0), "1500000000.0");
    }
}
