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
//! the sweep logic is unit-tested without a live cluster. Production uses
//! [`HttpReaperClient`] (ring-direct HTTP on the replication network) and
//! [`run_once`] over local account DBs. Deferred: per-device sharding of
//! container work, the reap-not-done warning, and concurrency.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use swift_db::{db_locations, AccountBroker, DbError, DbValue, ListContainersArgs};
use swift_ring::Ring;

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

fn pe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn http_status(buf: &[u8]) -> u16 {
    String::from_utf8_lossy(buf)
        .split("\r\n")
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(500)
}

fn http_body(buf: &[u8]) -> &[u8] {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        &buf[pos + 4..]
    } else {
        &[]
    }
}

fn node_host(node: &swift_ring::RingDevice) -> String {
    let ip = node
        .replication_ip
        .clone()
        .unwrap_or_else(|| node.ip.clone());
    let port = node.replication_port.unwrap_or(node.port);
    format!("{ip}:{port}")
}

fn raw_request(
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Option<(u16, Vec<u8>)> {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    let Ok(mut conn) = TcpStream::connect(host) else {
        return None;
    };
    conn.set_nodelay(true).ok();
    let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(15)));
    if conn.write_all(request.as_bytes()).is_err() {
        return None;
    }
    let mut buf = Vec::new();
    if conn.read_to_end(&mut buf).is_err() {
        return None;
    }
    Some((http_status(&buf), buf))
}

/// Ring-direct reaper client (Python `direct_get_container` /
/// `direct_delete_object` / container DELETE).
pub struct HttpReaperClient<'a> {
    pub object_ring: &'a Ring,
    pub container_ring: &'a Ring,
}

impl ReaperClient for HttpReaperClient<'_> {
    fn list_objects(&self, account: &str, container: &str, policy_index: i64) -> Option<Vec<String>> {
        let (part, nodes) = self
            .container_ring
            .get_nodes(account, Some(container), None)
            .ok()?;
        let pi = policy_index.to_string();
        for node in &nodes {
            let host = node_host(node.dev);
            let path = format!(
                "/{}/{part}/{}/{}?format=json&limit=10000",
                node.dev.device,
                pe(account),
                pe(container)
            );
            let Some((status, buf)) = raw_request(
                &host,
                "GET",
                &path,
                &[
                    ("Accept", "application/json"),
                    ("X-Backend-Storage-Policy-Index", pi.as_str()),
                ],
            ) else {
                continue;
            };
            if status == 404 {
                return Some(Vec::new());
            }
            if !(200..300).contains(&status) {
                continue;
            }
            let body = http_body(&buf);
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
                continue;
            };
            let Some(arr) = v.as_array() else {
                continue;
            };
            let mut names = Vec::new();
            for item in arr {
                if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                    names.push(name.to_string());
                }
            }
            return Some(names);
        }
        None
    }

    fn reap_object(
        &self,
        account: &str,
        container: &str,
        obj: &str,
        policy_index: i64,
        timestamp: &str,
    ) -> bool {
        let Ok((part, nodes)) = self
            .object_ring
            .get_nodes(account, Some(container), Some(obj))
        else {
            return false;
        };
        let pi = policy_index.to_string();
        let mut ok = 0usize;
        for node in &nodes {
            let host = format!("{}:{}", node.dev.ip, node.dev.port);
            let path = format!(
                "/{}/{part}/{}/{}/{}",
                node.dev.device,
                pe(account),
                pe(container),
                pe(obj)
            );
            let Some((status, _)) = raw_request(
                &host,
                "DELETE",
                &path,
                &[
                    ("X-Timestamp", timestamp),
                    ("X-Backend-Storage-Policy-Index", pi.as_str()),
                ],
            ) else {
                continue;
            };
            if (200..300).contains(&status) || status == 404 {
                ok += 1;
            }
        }
        ok * 2 > nodes.len()
    }

    fn reap_container(&self, account: &str, container: &str, timestamp: &str) -> bool {
        let Ok((part, nodes)) = self.container_ring.get_nodes(account, Some(container), None)
        else {
            return false;
        };
        let mut ok = 0usize;
        for node in &nodes {
            let host = node_host(node.dev);
            let path = format!(
                "/{}/{part}/{}/{}",
                node.dev.device,
                pe(account),
                pe(container)
            );
            let Some((status, _)) = raw_request(
                &host,
                "DELETE",
                &path,
                &[
                    ("X-Timestamp", timestamp),
                    ("X-Backend-Storage-Policy-Index", "0"),
                ],
            ) else {
                continue;
            };
            if (200..300).contains(&status) || status == 404 {
                ok += 1;
            }
        }
        ok * 2 > nodes.len()
    }
}

/// Aggregated pass stats across every account DB on a device.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReaperPassStats {
    pub accounts_reaped: u64,
    pub accounts_skipped: u64,
    pub containers_deleted: u64,
    pub containers_remaining: u64,
    pub objects_deleted: u64,
    pub objects_remaining: u64,
    pub errors: u64,
}

/// Sweep every account DB on `device`; reap those past `delay_reaping`.
pub fn run_once(
    device: &Path,
    now: f64,
    delay_reaping: f64,
    object_ring: &Ring,
    container_ring: &Ring,
) -> ReaperPassStats {
    let mut pass = ReaperPassStats::default();
    let client = HttpReaperClient {
        object_ring,
        container_ring,
    };
    let timestamp = format!(
        "{:.5}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0)
    );
    for db in db_locations(device, "accounts") {
        let mut broker = AccountBroker::new(&db, "");
        match reap_account(&mut broker, now, delay_reaping, &timestamp, &client) {
            Ok(None) => pass.accounts_skipped += 1,
            Ok(Some(s)) => {
                pass.accounts_reaped += 1;
                pass.containers_deleted += s.containers_deleted;
                pass.containers_remaining += s.containers_remaining;
                pass.objects_deleted += s.objects_deleted;
                pass.objects_remaining += s.objects_remaining;
            }
            Err(_) => pass.errors += 1,
        }
    }
    pass
}

/// Recon-cache update for the account reaper.
pub fn recon_update(elapsed: std::time::Duration, pass: &ReaperPassStats) -> serde_json::Value {
    serde_json::json!({
        "account_reaper_pass": elapsed.as_secs_f64(),
        "accounts_reaped": pass.accounts_reaped,
        "containers_deleted": pass.containers_deleted,
        "objects_deleted": pass.objects_deleted,
    })
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
