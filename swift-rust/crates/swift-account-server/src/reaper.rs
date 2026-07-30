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

//! The account reaper daemon core, ported from `swift/account/reaper.py`.
//!
//! When an account is deleted its DB row is only *marked* `status=DELETED`
//! (delete_timestamp advanced past put_timestamp). After `delay_reaping`
//! elapses, this daemon actually purges the account's data: for every
//! container it lists and DELETEs each object across the object ring, DELETEs
//! the container across the container ring (updating the account), and tallies
//! what was removed vs what remains for a later pass.
//!
//! The orchestration here is ring/transport-agnostic: object and container
//! deletes and the object listing go through a pluggable [`ReaperClient`], so
//! the sweep logic is unit-tested without a live cluster. Deferred: the
//! direct-client HTTP transport, per-device sharding of container work, the
//! reap-not-done warning, and concurrency.

use swift_db::{AccountBroker, DbError, DbValue, ListContainersArgs};

/// Running tally over a reap pass (Python `stats_*`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReaperStats {
    pub containers_deleted: u64,
    pub containers_remaining: u64,
    pub objects_deleted: u64,
    pub objects_remaining: u64,
}

/// Abstraction over the reaper's backend deletes + object listing. All ring
/// lookups and HTTP happen behind this trait.
pub trait ReaperClient {
    /// List the object names in a container (None => listing failed; the
    /// container is left for a later pass).
    fn list_objects(&self, account: &str, container: &str, policy_index: i64) -> Option<Vec<String>>;
    /// DELETE one object across the object ring. Returns success.
    fn reap_object(
        &self,
        account: &str,
        container: &str,
        obj: &str,
        policy_index: i64,
        timestamp: &str,
    ) -> bool;
    /// DELETE the container across the container ring (also updates the
    /// account). Returns success.
    fn reap_container(&self, account: &str, container: &str, timestamp: &str) -> bool;
}

/// Whether an account is eligible to reap: it is status=DELETED and the
/// reaping delay has elapsed since its delete_timestamp.
pub fn is_reapable(delete_ts: f64, put_ts: f64, now: f64, delay_reaping: f64) -> bool {
    delete_ts > put_ts && now - delete_ts > delay_reaping
}

fn info_value(info: &[(String, DbValue)], key: &str) -> Option<String> {
    info.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| v.as_text())
}

fn ts_value(s: &str) -> f64 {
    s.split('_').next().unwrap_or("0").parse().unwrap_or(0.0)
}

/// Reap one container: delete every object, then the container itself. The
/// container is only deleted once every object was reaped. Returns whether
/// the container was fully reaped.
pub fn reap_container(
    account: &str,
    container: &str,
    policy_index: i64,
    timestamp: &str,
    client: &dyn ReaperClient,
    stats: &mut ReaperStats,
) -> bool {
    let Some(objects) = client.list_objects(account, container, policy_index) else {
        // couldn't list -> leave the container for next time
        stats.containers_remaining += 1;
        return false;
    };
    let mut all_objects_gone = true;
    for obj in &objects {
        if client.reap_object(account, container, obj, policy_index, timestamp) {
            stats.objects_deleted += 1;
        } else {
            stats.objects_remaining += 1;
            all_objects_gone = false;
        }
    }
    if all_objects_gone && client.reap_container(account, container, timestamp) {
        stats.containers_deleted += 1;
        true
    } else {
        stats.containers_remaining += 1;
        false
    }
}

/// One reap pass over an account. Returns `Ok(None)` if the account is not
/// yet reapable, else `Ok(Some(stats))`.
pub fn reap_account(
    broker: &mut AccountBroker,
    now: f64,
    delay_reaping: f64,
    timestamp: &str,
    client: &dyn ReaperClient,
) -> Result<Option<ReaperStats>, DbError> {
    let info = broker.get_info()?;
    let account = info_value(&info, "account").unwrap_or_default();
    let delete_ts = ts_value(&info_value(&info, "delete_timestamp").unwrap_or_default());
    let put_ts = ts_value(&info_value(&info, "put_timestamp").unwrap_or_default());
    if !is_reapable(delete_ts, put_ts, now, delay_reaping) {
        return Ok(None);
    }

    let mut stats = ReaperStats::default();
    let mut marker = String::new();
    loop {
        let args = ListContainersArgs {
            limit: 1000,
            marker: marker.clone(),
            end_marker: String::new(),
            prefix: None,
            delimiter: None,
            reverse: false,
            allow_reserved: true,
        };
        let rows = broker.list_containers_iter(&args)?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            let name = row.first().and_then(|v| v.as_text()).unwrap_or_default();
            let policy_index = row.get(4).and_then(|v| v.as_i64()).unwrap_or(0);
            reap_container(&account, &name, policy_index, timestamp, client, &mut stats);
        }
        marker = rows
            .last()
            .and_then(|r| r.first())
            .and_then(|v| v.as_text())
            .unwrap_or_default();
        if marker.is_empty() {
            break;
        }
    }
    Ok(Some(stats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn test_is_reapable() {
        // deleted 2 days ago, delay 1 day -> reapable
        assert!(is_reapable(100.0, 50.0, 100.0 + 2.0 * 86400.0, 86400.0));
        // not status-deleted (delete <= put)
        assert!(!is_reapable(50.0, 100.0, 1e12, 0.0));
        // deleted but within delay
        assert!(!is_reapable(100.0, 50.0, 100.0 + 10.0, 86400.0));
    }

    struct FakeReaper {
        objects: HashMap<String, Vec<String>>,
        deleted_objects: Mutex<Vec<String>>,
        deleted_containers: Mutex<Vec<String>>,
        fail_object: Option<String>,
    }
    impl ReaperClient for FakeReaper {
        fn list_objects(&self, _a: &str, container: &str, _pi: i64) -> Option<Vec<String>> {
            self.objects.get(container).cloned()
        }
        fn reap_object(&self, _a: &str, _c: &str, obj: &str, _pi: i64, _ts: &str) -> bool {
            if self.fail_object.as_deref() == Some(obj) {
                return false;
            }
            self.deleted_objects.lock().unwrap().push(obj.to_string());
            true
        }
        fn reap_container(&self, _a: &str, container: &str, _ts: &str) -> bool {
            self.deleted_containers.lock().unwrap().push(container.to_string());
            true
        }
    }

    fn make_deleted_account(dir: &std::path::Path) -> AccountBroker {
        use swift_core::pickle::Value as PV;
        let h = "0000000000000000000000000000dead";
        let hd = dir.join(format!("accounts/0/ead/{h}"));
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join(format!("{h}.db"));
        let mut b = AccountBroker::new(&db, "AUTH_gone");
        // account put at t=100, two live containers, then marked deleted at t=200
        b.initialize("0000000100.00000", "0000000100.00000", "id").unwrap();
        b.put_container("c1", "0000000050.00000", "0", PV::Int(0), PV::Int(0), 0)
            .unwrap();
        b.put_container("c2", "0000000050.00000", "0", PV::Int(0), PV::Int(0), 0)
            .unwrap();
        b.delete_db("0000000200.00000").unwrap();
        b
    }

    #[test]
    fn test_reap_account_end_to_end() {
        let dir = std::env::temp_dir().join(format!("swift-reap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut broker = make_deleted_account(&dir);
        let client = FakeReaper {
            objects: HashMap::from([
                ("c1".to_string(), vec!["a".to_string(), "b".to_string()]),
                ("c2".to_string(), vec!["x".to_string()]),
            ]),
            deleted_objects: Mutex::new(Vec::new()),
            deleted_containers: Mutex::new(Vec::new()),
            fail_object: None,
        };
        // now well past the delete_timestamp, delay 0 -> reapable
        let stats = reap_account(&mut broker, 1e12, 0.0, "0000000200.00000", &client)
            .unwrap()
            .expect("account is reapable");
        assert_eq!(stats.containers_deleted, 2, "{stats:?}");
        assert_eq!(stats.objects_deleted, 3, "{stats:?}");
        assert_eq!(client.deleted_containers.lock().unwrap().len(), 2);

        // a fresh (non-deleted) account is not reapable
        let db2 = dir.join("live.db");
        let mut live = AccountBroker::new(&db2, "AUTH_live");
        live.initialize("0000000100.00000", "0000000100.00000", "id").unwrap();
        assert!(reap_account(&mut live, 1e12, 0.0, "0", &client).unwrap().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_reap_container_deletes_objects_then_container() {
        let client = FakeReaper {
            objects: HashMap::from([("c".to_string(), vec!["o1".to_string(), "o2".to_string()])]),
            deleted_objects: Mutex::new(Vec::new()),
            deleted_containers: Mutex::new(Vec::new()),
            fail_object: None,
        };
        let mut stats = ReaperStats::default();
        let done = reap_container("a", "c", 0, "0000000200.00000", &client, &mut stats);
        assert!(done);
        assert_eq!(stats.objects_deleted, 2);
        assert_eq!(stats.containers_deleted, 1);
        assert_eq!(client.deleted_containers.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_reap_container_keeps_container_if_object_fails() {
        let client = FakeReaper {
            objects: HashMap::from([("c".to_string(), vec!["o1".to_string(), "o2".to_string()])]),
            deleted_objects: Mutex::new(Vec::new()),
            deleted_containers: Mutex::new(Vec::new()),
            fail_object: Some("o2".to_string()),
        };
        let mut stats = ReaperStats::default();
        let done = reap_container("a", "c", 0, "0000000200.00000", &client, &mut stats);
        assert!(!done, "container kept when an object couldn't be reaped");
        assert_eq!(stats.objects_deleted, 1);
        assert_eq!(stats.objects_remaining, 1);
        assert_eq!(stats.containers_remaining, 1);
        assert!(client.deleted_containers.lock().unwrap().is_empty());
    }
}
