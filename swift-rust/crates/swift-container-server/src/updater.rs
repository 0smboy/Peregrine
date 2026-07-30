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

//! The container updater daemon core, ported from
//! `swift/container/updater.py`.
//!
//! Each container DB carries the container's current object/byte totals plus
//! the `reported_*` copy that was last pushed to the account. This daemon
//! walks every container DB on a device, and when the live stats differ from
//! the reported ones (or the put/delete timestamps advanced) it PUTs a report
//! to the container's account replicas (via the account ring); on a majority
//! success it stamps `reported_*` so the next sweep sees no change.
//!
//! Non-root (shard) containers have their object/byte stats zeroed before
//! reporting (via `broker.is_root_container()`) so they don't double-count
//! into the account. Deferred: account suppression on repeated failure,
//! `quarantine('no account replicas')` on all-404, and recon/timing.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

use swift_db::{db_locations, ContainerBroker, DbError};
use swift_ring::Ring;

/// The subset of `get_info` the updater compares and reports.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerStat {
    pub account: String,
    pub container: String,
    pub put_timestamp: String,
    pub delete_timestamp: String,
    pub object_count: i64,
    pub bytes_used: i64,
    pub reported_put_timestamp: String,
    pub reported_delete_timestamp: String,
    pub reported_object_count: i64,
    pub reported_bytes_used: i64,
    pub storage_policy_index: i64,
}

impl ContainerStat {
    fn from_info(info: &[(String, swift_db::DbValue)]) -> Option<ContainerStat> {
        let get = |k: &str| info.iter().find(|(n, _)| n == k).map(|(_, v)| v);
        let text = |k: &str| get(k).and_then(|v| v.as_text()).unwrap_or_default();
        let int = |k: &str| get(k).and_then(|v| v.as_i64()).unwrap_or(0);
        Some(ContainerStat {
            account: get("account")?.as_text()?,
            container: get("container")?.as_text()?,
            put_timestamp: text("put_timestamp"),
            delete_timestamp: text("delete_timestamp"),
            object_count: int("object_count"),
            bytes_used: int("bytes_used"),
            reported_put_timestamp: text("reported_put_timestamp"),
            reported_delete_timestamp: text("reported_delete_timestamp"),
            reported_object_count: int("reported_object_count"),
            reported_bytes_used: int("reported_bytes_used"),
            storage_policy_index: int("storage_policy_index"),
        })
    }

    /// Whether an account report is due (Python's four-way OR).
    pub fn needs_report(&self) -> bool {
        ts_gt(&self.put_timestamp, &self.reported_put_timestamp)
            || ts_gt(&self.delete_timestamp, &self.reported_delete_timestamp)
            || self.object_count != self.reported_object_count
            || self.bytes_used != self.reported_bytes_used
    }
}

/// Parse the numeric value of a Swift timestamp (`<float>` or `<float>_<off>`).
fn ts_value(ts: &str) -> f64 {
    ts.split('_').next().unwrap_or("0").parse().unwrap_or(0.0)
}

/// Timestamp string comparison, Python `info['a'] > info['b']` on the
/// zero-padded internal form (lexical == numeric for that form, but we
/// compare numerically to be safe against unpadded values).
fn ts_gt(a: &str, b: &str) -> bool {
    ts_value(a) > ts_value(b)
}

/// A single account-node report result: the HTTP status, or `None` on a
/// connection error (treated as 500).
pub type ReportStatus = u16;

/// Abstraction over "PUT one container report to one account node".
pub trait AccountNodeClient {
    fn report(
        &self,
        node: &swift_ring::RingDevice,
        part: u32,
        account: &str,
        container: &str,
        stat: &ContainerStat,
    ) -> ReportStatus;
}

/// The real client: a blocking HTTP/1.1 PUT to the account server's
/// replication endpoint.
pub struct HttpAccountClient;

impl AccountNodeClient for HttpAccountClient {
    fn report(
        &self,
        node: &swift_ring::RingDevice,
        part: u32,
        account: &str,
        container: &str,
        stat: &ContainerStat,
    ) -> ReportStatus {
        let rep_ip = node.replication_ip.clone().unwrap_or_else(|| node.ip.clone());
        let rep_port = node.replication_port.unwrap_or(node.port);
        let host = format!("{rep_ip}:{rep_port}");
        let path = format!("/{}/{}", pe(account), pe(container));
        let request = format!(
            "PUT /{}/{part}{path} HTTP/1.1\r\nHost: {host}\r\n\
             X-Put-Timestamp: {}\r\nX-Delete-Timestamp: {}\r\n\
             X-Object-Count: {}\r\nX-Bytes-Used: {}\r\n\
             X-Account-Override-Deleted: yes\r\n\
             X-Backend-Storage-Policy-Index: {}\r\n\
             User-Agent: container-updater\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n",
            node.device,
            stat.put_timestamp,
            stat.delete_timestamp,
            stat.object_count,
            stat.bytes_used,
            stat.storage_policy_index,
        );
        let Ok(mut conn) = TcpStream::connect(&host) else {
            return 500;
        };
        conn.set_nodelay(true).ok();
        let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(15)));
        if conn.write_all(request.as_bytes()).is_err() {
            return 500;
        }
        let mut buf = Vec::new();
        if conn.read_to_end(&mut buf).is_err() {
            return 500;
        }
        String::from_utf8_lossy(&buf)
            .split("\r\n")
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(500)
    }
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

fn majority(n: usize) -> usize {
    n / 2 + 1
}

/// Sweep stats.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ContainerUpdaterStats {
    pub successes: u64,
    pub failures: u64,
    pub no_changes: u64,
}

/// The recon-cache update Python's container updater dumps after a sweep
/// (`swift/container/updater.py run_forever`, the key `swift-recon` reads).
/// `container_updater_last` mirrors the object updater's `object_updater_last`
/// so `swift-recon` can age a container sweep the same way.
///
/// This lives next to the stats it summarises rather than in `swift-core`,
/// because the *shape* of a recon update is a statement about the counters one
/// particular daemon keeps; only the generic plumbing is shared.
pub fn recon_update(elapsed: std::time::Duration, end_epoch_secs: f64) -> serde_json::Value {
    serde_json::json!({
        "container_updater_sweep": elapsed.as_secs_f64(),
        "container_updater_last": end_epoch_secs,
    })
}

/// The outcome of processing one container.
#[derive(Debug, Clone, PartialEq)]
pub enum ContainerOutcome {
    /// Auto-created / never-PUT container, skipped.
    Skipped,
    /// Stats matched the reported copy, nothing sent.
    NoChange,
    /// Report accepted by a majority; reported_* stamped.
    Reported,
    /// Report failed to reach a majority.
    Failed,
}

/// Process one container broker: report to the account if stats changed.
pub fn process_container(
    broker: &mut ContainerBroker,
    account_ring: &Ring,
    client: &dyn AccountNodeClient,
    stats: &mut ContainerUpdaterStats,
) -> Result<ContainerOutcome, DbError> {
    let info = broker.get_info()?;
    let mut stat = match ContainerStat::from_info(&info) {
        Some(s) => s,
        None => return Ok(ContainerOutcome::Skipped),
    };
    // Auto-created containers have a zero put_timestamp and unreliable stats.
    if ts_value(&stat.put_timestamp) <= 0.0 {
        return Ok(ContainerOutcome::Skipped);
    }
    // A shard (non-root) container must not double-count its stats into the
    // account — the sharder rolls those up to the root, whose updater reports
    // them. Zero them here (Python container/updater.py).
    if !broker.is_root_container().unwrap_or(true) {
        stat.object_count = 0;
        stat.bytes_used = 0;
    }
    if !stat.needs_report() {
        stats.no_changes += 1;
        return Ok(ContainerOutcome::NoChange);
    }
    let (part, nodes) = match account_ring.get_nodes(&stat.account, None, None) {
        Ok(pn) => pn,
        Err(_) => {
            stats.failures += 1;
            return Ok(ContainerOutcome::Failed);
        }
    };
    let mut successes = 0usize;
    for node in &nodes {
        let status = client.report(node.dev, part, &stat.account, &stat.container, &stat);
        if (200..300).contains(&status) {
            successes += 1;
        }
    }
    if successes >= majority(nodes.len()) {
        broker.reported(
            &stat.put_timestamp,
            &stat.delete_timestamp,
            stat.object_count,
            stat.bytes_used,
        )?;
        stats.successes += 1;
        Ok(ContainerOutcome::Reported)
    } else {
        stats.failures += 1;
        Ok(ContainerOutcome::Failed)
    }
}

/// One full sweep of a device's container DBs.
pub fn run_once(
    device: &Path,
    account_ring: &Ring,
    client: &dyn AccountNodeClient,
) -> ContainerUpdaterStats {
    let mut stats = ContainerUpdaterStats::default();
    for db in db_locations(device, "containers") {
        let mut broker = ContainerBroker::new(&db, "", "");
        let _ = process_container(&mut broker, account_ring, client, &mut stats);
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use swift_core::hashing::HashPathConfig;
    use swift_ring::{Ring, RingData, RingDevice};

    fn dev(id: u64) -> RingDevice {
        RingDevice {
            id,
            region: 1,
            zone: 1,
            ip: "127.0.0.1".into(),
            port: 6202,
            replication_ip: None,
            replication_port: None,
            device: format!("sd{id}"),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        }
    }

    /// A one-partition, 3-replica ring over 3 devices.
    fn ring3() -> Ring {
        let devs = vec![Some(dev(0)), Some(dev(1)), Some(dev(2))];
        let r2p2d = vec![vec![0u32], vec![1u32], vec![2u32]];
        // part_power 0 => 1 partition => part_shift 32, so get_part yields 0
        let data = RingData::from_parts(devs, 32, r2p2d);
        Ring::new(data, HashPathConfig::new("", "changeme").unwrap())
    }

    struct FakeAccount {
        calls: Mutex<Vec<(u64, String)>>,
        status: u16,
    }
    impl AccountNodeClient for FakeAccount {
        fn report(
            &self,
            node: &RingDevice,
            _part: u32,
            account: &str,
            container: &str,
            _s: &ContainerStat,
        ) -> ReportStatus {
            self.calls
                .lock()
                .unwrap()
                .push((node.id, format!("/{account}/{container}")));
            self.status
        }
    }

    fn make_container(dir: &Path, account: &str, container: &str) -> ContainerBroker {
        let h = "0000000000000000000000000000abcd";
        let hd = dir.join(format!("containers/0/bcd/{h}"));
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join(format!("{h}.db"));
        let mut b = ContainerBroker::new(&db, account, container);
        b.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        b
    }

    #[test]
    fn test_needs_report_detects_change() {
        let stat = ContainerStat {
            account: "a".into(),
            container: "c".into(),
            put_timestamp: "1751500000.00000".into(),
            delete_timestamp: "0".into(),
            object_count: 5,
            bytes_used: 100,
            reported_put_timestamp: "1751500000.00000".into(),
            reported_delete_timestamp: "0".into(),
            reported_object_count: 0,
            reported_bytes_used: 0,
            storage_policy_index: 0,
        };
        assert!(stat.needs_report(), "count differs from reported");
    }

    #[test]
    fn test_report_majority_stamps_reported() {
        let dir = std::env::temp_dir().join(format!("swift-cupd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        let mut broker = make_container(&device, "AUTH_test", "c");
        // put_timestamp advanced over reported (initialize sets reported to 0)
        let stat = ContainerStat::from_info(&broker.get_info().unwrap()).unwrap();
        assert!(stat.needs_report(), "fresh container needs its first report");

        let client = FakeAccount {
            calls: Mutex::new(Vec::new()),
            status: 204,
        };
        let mut stats = ContainerUpdaterStats::default();
        let out =
            process_container(&mut broker, &ring3(), &client, &mut stats).unwrap();
        assert_eq!(out, ContainerOutcome::Reported);
        assert_eq!(client.calls.lock().unwrap().len(), 3);
        assert_eq!(stats.successes, 1);

        // after reporting, stats now match -> no change on the next pass
        let out2 =
            process_container(&mut broker, &ring3(), &client, &mut stats).unwrap();
        assert_eq!(out2, ContainerOutcome::NoChange);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_report_failure_not_stamped() {
        let dir = std::env::temp_dir().join(format!("swift-cupd-f-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        let mut broker = make_container(&device, "AUTH_test", "c");
        let client = FakeAccount {
            calls: Mutex::new(Vec::new()),
            status: 500,
        };
        let mut stats = ContainerUpdaterStats::default();
        let out =
            process_container(&mut broker, &ring3(), &client, &mut stats).unwrap();
        assert_eq!(out, ContainerOutcome::Failed);
        assert_eq!(stats.failures, 1);
        // still needs report next time (reported_* untouched)
        let stat = ContainerStat::from_info(&broker.get_info().unwrap()).unwrap();
        assert!(stat.needs_report());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
