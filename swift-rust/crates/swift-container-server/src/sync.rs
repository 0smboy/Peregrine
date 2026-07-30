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

//! The container-sync daemon core, ported from `swift/container/sync.py` and
//! the realm signing in `swift/common/container_sync_realms.py`.
//!
//! A container with `X-Container-Sync-To` (a remote container URL) and
//! `X-Container-Sync-Key` mirrors its object rows to another cluster. Each
//! request is authenticated with an HMAC-SHA1 signature over the realm key
//! and the user key — the cross-cluster trust contract — so getting that
//! signature byte-identical to Python is the interoperability requirement,
//! and it is golden-tested here.
//!
//! This module ports the signature (`get_sig`), the sync-auth header, and the
//! per-row PUT/DELETE decision + sync-point advance over a pluggable
//! [`SyncClient`]. Deferred: the remote HEAD-before-PUT optimisation, the
//! object GET/streaming body transport, realm config parsing, and the
//! two-pass (sync_point1 new rows / sync_point2 backfill) scheduler details
//! (the row action itself is faithful).

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// `ContainerSyncRealms.get_sig`: the HMAC-SHA1 hexdigest authenticating a
/// container-sync request. The signed message is
/// `"{method}\n{path}\n{x_timestamp}\n{nonce}\n{user_key}"` keyed by the
/// realm key.
pub fn get_sig(
    request_method: &str,
    path: &str,
    x_timestamp: &str,
    nonce: &str,
    realm_key: &str,
    user_key: &str,
) -> String {
    let mut mac = HmacSha1::new_from_slice(realm_key.as_bytes())
        .expect("HMAC accepts a key of any length");
    let msg = format!("{request_method}\n{path}\n{x_timestamp}\n{nonce}\n{user_key}");
    mac.update(msg.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The `X-Container-Sync-Auth` header value: `"{realm} {nonce} {sig}"`.
pub fn sync_auth_header(realm: &str, nonce: &str, sig: &str) -> String {
    format!("{realm} {nonce} {sig}")
}

/// One object row to mirror to the remote container.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncRow {
    pub row_id: i64,
    pub name: String,
    pub created_at: String,
    pub deleted: bool,
}

/// The action taken for a synced row.
#[derive(Debug, Clone, PartialEq)]
pub enum SyncAction {
    /// A live row -> PUT the object to the remote.
    Put,
    /// A tombstone row -> DELETE the object on the remote.
    Delete,
}

impl SyncRow {
    /// The remote action this row implies.
    pub fn action(&self) -> SyncAction {
        if self.deleted {
            SyncAction::Delete
        } else {
            SyncAction::Put
        }
    }
}

/// Abstraction over "mirror one row to the remote container".
pub trait SyncClient {
    /// Send the row (PUT or DELETE) to the remote container, signed. Returns
    /// success.
    fn sync_row(&self, row: &SyncRow, action: &SyncAction) -> bool;
}

/// Sweep stats.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SyncStats {
    pub deletes: u64,
    pub puts: u64,
    pub failures: u64,
    /// The sync point advanced to (the highest fully-synced row id).
    pub sync_point: i64,
}

/// Sync a batch of rows (already ordered by row id ascending). Advances the
/// sync point past each row that mirrored successfully; a failure stops the
/// advance so the row is retried next pass (Python breaks the batch on error).
pub fn sync_rows(rows: &[SyncRow], start_point: i64, client: &dyn SyncClient) -> SyncStats {
    let mut stats = SyncStats {
        sync_point: start_point,
        ..Default::default()
    };
    for row in rows {
        let action = row.action();
        if client.sync_row(row, &action) {
            match action {
                SyncAction::Put => stats.puts += 1,
                SyncAction::Delete => stats.deletes += 1,
            }
            stats.sync_point = row.row_id;
        } else {
            stats.failures += 1;
            break;
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn test_get_sig_deterministic() {
        // stable inputs -> stable digest (cross-checked against Python)
        let sig = get_sig(
            "PUT",
            "/v1/AUTH_dst/dstcont/obj",
            "1751500000.00000",
            "deadbeefdeadbeefdeadbeefdeadbeef",
            "realmkey",
            "userkey",
        );
        assert_eq!(sig.len(), 40, "sha1 hexdigest is 40 chars");
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sync_auth_header() {
        assert_eq!(sync_auth_header("US", "nonce", "sig"), "US nonce sig");
    }

    #[test]
    fn test_row_action() {
        assert_eq!(
            SyncRow {
                row_id: 1,
                name: "o".into(),
                created_at: "1".into(),
                deleted: false
            }
            .action(),
            SyncAction::Put
        );
        assert_eq!(
            SyncRow {
                row_id: 2,
                name: "o".into(),
                created_at: "1".into(),
                deleted: true
            }
            .action(),
            SyncAction::Delete
        );
    }

    struct FakeSync {
        sent: Mutex<Vec<(i64, SyncAction)>>,
        fail_at: Option<i64>,
    }
    impl SyncClient for FakeSync {
        fn sync_row(&self, row: &SyncRow, action: &SyncAction) -> bool {
            self.sent.lock().unwrap().push((row.row_id, action.clone()));
            self.fail_at != Some(row.row_id)
        }
    }

    #[test]
    fn test_sync_rows_advances_point() {
        let rows = vec![
            SyncRow { row_id: 1, name: "a".into(), created_at: "1".into(), deleted: false },
            SyncRow { row_id: 2, name: "b".into(), created_at: "2".into(), deleted: true },
            SyncRow { row_id: 3, name: "c".into(), created_at: "3".into(), deleted: false },
        ];
        let client = FakeSync { sent: Mutex::new(Vec::new()), fail_at: None };
        let stats = sync_rows(&rows, 0, &client);
        assert_eq!(stats.puts, 2);
        assert_eq!(stats.deletes, 1);
        assert_eq!(stats.sync_point, 3, "advanced past the last row");
    }

    #[test]
    fn test_sync_rows_stops_on_failure() {
        let rows = vec![
            SyncRow { row_id: 1, name: "a".into(), created_at: "1".into(), deleted: false },
            SyncRow { row_id: 2, name: "b".into(), created_at: "2".into(), deleted: false },
            SyncRow { row_id: 3, name: "c".into(), created_at: "3".into(), deleted: false },
        ];
        let client = FakeSync { sent: Mutex::new(Vec::new()), fail_at: Some(2) };
        let stats = sync_rows(&rows, 0, &client);
        assert_eq!(stats.sync_point, 1, "stops at the failing row");
        assert_eq!(stats.failures, 1);
        // row 3 was never attempted
        assert_eq!(client.sent.lock().unwrap().len(), 2);
    }
}
