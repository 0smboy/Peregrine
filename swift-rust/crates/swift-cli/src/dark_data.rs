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

//! Object-auditor dark-data watcher (`swift#dark_data`).
//!
//! Python: `swift/obj/watchers/dark_data.py`. After a successful object
//! audit, leftover `.data` whose container listing is empty on every
//! reachable container-ring node is dark. `action=delete` rmtree's the
//! hash directory and must **not** create `quarantined/`.
//! `action=quarantine` raises Python `QuarantineRequest` (auditor moves
//! the hash dir). Unknown action defaults to `log`.

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_diskfile::{Metadata, ObjectAuditWatcher, WatcherDecision};
use swift_http::split_path;
use swift_ring::{Ring, RingDevice};

const WATCHER_NAME: &str = "swift#dark_data";
const WATCHER_SECTION: &str = "object-auditor:watcher:swift#dark_data";
const DEFAULT_GRACE_AGE: f64 = 604800.0;
const CONTAINER_TIMEOUT: Duration = Duration::from_secs(5);

/// Python `DarkDataWatcher.dark_data_policy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DarkDataAction {
    Log,
    Delete,
    Quarantine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerError;

/// Result of asking container servers whether an object is listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectPresence {
    /// All reachable nodes agree the object is missing (dark).
    Dark,
    /// At least one node listed the object.
    Present,
    /// Any node errored — Python `ContainerError`; do not delete/quarantine.
    Unknown,
}

/// Parsed `[object-auditor]` / watcher subsection.
#[derive(Debug, Clone, PartialEq)]
pub struct DarkDataConfig {
    pub action: DarkDataAction,
    pub grace_age: f64,
}

impl DarkDataConfig {
    pub fn from_auditor_conf(conf: &SwiftConfig) -> Option<Self> {
        let watchers = conf
            .get("object-auditor", "watchers")
            .ok()
            .flatten()
            .unwrap_or_default();
        if !watchers_include_dark_data(&watchers) {
            return None;
        }
        Some(Self::from_watcher_section(conf))
    }

    pub fn from_watcher_section(conf: &SwiftConfig) -> Self {
        let action = parse_action(
            conf.get(WATCHER_SECTION, "action")
                .ok()
                .flatten()
                .as_deref(),
        );
        let grace_age = conf
            .get(WATCHER_SECTION, "grace_age")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(DEFAULT_GRACE_AGE);
        Self { action, grace_age }
    }
}

pub fn watchers_include_dark_data(watchers: &str) -> bool {
    watchers
        .split(',')
        .map(str::trim)
        .any(|name| name == WATCHER_NAME)
}

pub fn parse_action(raw: Option<&str>) -> DarkDataAction {
    match raw.map(str::trim) {
        Some("delete") => DarkDataAction::Delete,
        Some("quarantine") => DarkDataAction::Quarantine,
        Some("log") | None => DarkDataAction::Log,
        Some(_) => DarkDataAction::Log,
    }
}

/// Container-ring listing used by [`DarkDataWatcher`].
pub trait ContainerPresence {
    fn presence(&self, account: &str, container: &str, obj: &str) -> ObjectPresence;
}

/// Always-dark lookup for unit tests (probe leftover `.data` after
/// container rows are gone).
pub struct AlwaysDark;

impl ContainerPresence for AlwaysDark {
    fn presence(&self, _account: &str, _container: &str, _obj: &str) -> ObjectPresence {
        ObjectPresence::Dark
    }
}

pub struct AlwaysPresent;

impl ContainerPresence for AlwaysPresent {
    fn presence(&self, _account: &str, _container: &str, _obj: &str) -> ObjectPresence {
        ObjectPresence::Present
    }
}

pub struct AlwaysUnknown;

impl ContainerPresence for AlwaysUnknown {
    fn presence(&self, _account: &str, _container: &str, _obj: &str) -> ObjectPresence {
        ObjectPresence::Unknown
    }
}

/// Ring-direct listing (Python `get_info_1` / `direct_get_container`).
pub struct RingContainerPresence {
    ring: Ring,
    overlay: ListenOverlay,
}

impl RingContainerPresence {
    pub fn load(hash_config: HashPathConfig) -> Option<Self> {
        let ring_path = resolve_container_ring_path()?;
        let ring = Ring::load(&ring_path, hash_config).ok()?;
        let overlay = ListenOverlay::from_swift_dir(
            ring_path.parent().unwrap_or_else(|| Path::new("/")),
            "container-server",
        );
        Some(Self { ring, overlay })
    }
}

impl ContainerPresence for RingContainerPresence {
    fn presence(&self, account: &str, container: &str, obj: &str) -> ObjectPresence {
        match get_info_1(&self.ring, &self.overlay, account, container, obj) {
            Ok(Some(_)) => ObjectPresence::Present,
            Ok(None) => ObjectPresence::Dark,
            Err(ContainerError) => ObjectPresence::Unknown,
        }
    }
}

pub struct DarkDataWatcher<P> {
    pub config: DarkDataConfig,
    presence: P,
}

impl<P: ContainerPresence> DarkDataWatcher<P> {
    pub fn new(config: DarkDataConfig, presence: P) -> Self {
        Self { config, presence }
    }

    pub fn see_object(&self, metadata: &Metadata, data_file_path: &Path) -> WatcherDecision {
        if within_grace(metadata, self.config.grace_age) {
            return WatcherDecision::Keep;
        }
        let Some((account, container, obj)) = object_path_parts(metadata) else {
            return WatcherDecision::Keep;
        };
        match self.presence.presence(&account, &container, &obj) {
            ObjectPresence::Present | ObjectPresence::Unknown => WatcherDecision::Keep,
            ObjectPresence::Dark => self.apply_action(data_file_path),
        }
    }

    fn apply_action(&self, data_file_path: &Path) -> WatcherDecision {
        match self.config.action {
            DarkDataAction::Log => WatcherDecision::Keep,
            DarkDataAction::Quarantine => WatcherDecision::Quarantine,
            DarkDataAction::Delete => {
                // Python `shutil.rmtree(os.path.dirname(data_file_path))`.
                // Must not call quarantine_renamer.
                if let Some(hash_dir) = data_file_path.parent() {
                    let _ = std::fs::remove_dir_all(hash_dir);
                }
                WatcherDecision::Keep
            }
        }
    }
}

impl<P: ContainerPresence> ObjectAuditWatcher for DarkDataWatcher<P> {
    fn see_object(&mut self, metadata: &Metadata, data_file_path: &Path) -> WatcherDecision {
        DarkDataWatcher::see_object(self, metadata, data_file_path)
    }
}

/// Prefer a real `container.ring.gz`. Probe remaps `SWIFT_DIR` to a temp
/// conf dir that has no rings — fall through to Isolated `/etc/g6-rust`
/// then Python's `/etc/swift`. Do not invent those paths.
pub fn resolve_container_ring_path() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(dir) = std::env::var("SWIFT_DIR") {
        candidates.push(PathBuf::from(dir).join("container.ring.gz"));
    }
    if let Ok(conf) = std::env::var("SWIFT_CONF") {
        if let Some(parent) = Path::new(&conf).parent() {
            candidates.push(parent.join("container.ring.gz"));
        }
    }
    candidates.push(PathBuf::from("/etc/g6-rust/container.ring.gz"));
    candidates.push(PathBuf::from("/etc/swift/container.ring.gz"));
    candidates.into_iter().find(|p| p.is_file())
}

fn within_grace(metadata: &Metadata, grace_age: f64) -> bool {
    let Some(ts) = meta_str(metadata, "X-Timestamp") else {
        return true;
    };
    let Ok(put_ts) = ts.parse::<f64>() else {
        return true;
    };
    put_ts + grace_age >= unix_now()
}

fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn object_path_parts(metadata: &Metadata) -> Option<(String, String, String)> {
    let name = meta_str(metadata, "name")?;
    let segs = split_path(&name, 1, 3, true).ok()?;
    let account = segs.first().and_then(|s| s.clone())?;
    let container = segs.get(1).and_then(|s| s.clone())?;
    let obj = segs.get(2).and_then(|s| s.clone())?;
    if account.is_empty() || container.is_empty() || obj.is_empty() {
        return None;
    }
    Some((account, container, obj))
}

fn meta_str(metadata: &Metadata, key: &str) -> Option<String> {
    for (k, v) in metadata {
        if k.as_str() == Some(key) {
            return v.as_str().map(str::to_string);
        }
    }
    None
}

/// Isolated container-server listen-port remap (same idea as object
/// `ObjectListenOverlay`, local so swift-cli does not depend on
/// swift-object-server).
#[derive(Debug, Clone, Default)]
struct ListenOverlay {
    by_device: BTreeMap<String, u32>,
    default_port: Option<u32>,
}

impl ListenOverlay {
    fn listen_port(&self, device: &str, ring_port: u32) -> u32 {
        self.by_device
            .get(device)
            .copied()
            .or(self.default_port)
            .unwrap_or(ring_port)
    }

    fn from_swift_dir(swift_dir: &Path, server_dir: &str) -> Self {
        let mut overlay = Self::default();
        let mut confs: Vec<PathBuf> = Vec::new();
        let root = swift_dir.join(format!("{server_dir}.conf"));
        if root.is_file() {
            confs.push(root);
        }
        let dir = swift_dir.join(server_dir);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("conf") && path.is_file() {
                    confs.push(path);
                }
            }
        }
        for path in confs {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(conf) = SwiftConfig::parse_lenient(&text, &[], false) else {
                continue;
            };
            let Some(port) = conf_bind_port(&conf) else {
                continue;
            };
            let mut mapped = false;
            if let Some(devices) = conf_devices(&conf) {
                if let Ok(entries) = std::fs::read_dir(&devices) {
                    for entry in entries.flatten() {
                        if entry.path().is_dir() {
                            if let Some(name) = entry.file_name().to_str() {
                                if !name.starts_with('.') {
                                    overlay.by_device.insert(name.to_string(), port);
                                    mapped = true;
                                }
                            }
                        }
                    }
                }
                if !mapped {
                    if let Some(name) = devices.file_name().and_then(|s| s.to_str()) {
                        if name != "node" && name != "srv" {
                            overlay.by_device.insert(name.to_string(), port);
                        }
                    }
                }
            }
            match overlay.default_port {
                None => overlay.default_port = Some(port),
                Some(existing) if existing != port => overlay.default_port = None,
                Some(_) => {}
            }
        }
        let unique: HashSet<u32> = overlay.by_device.values().copied().collect();
        if unique.len() == 1 {
            overlay.default_port = unique.into_iter().next();
        } else if unique.len() > 1 {
            overlay.default_port = None;
        }
        overlay
    }
}

fn conf_get(conf: &SwiftConfig, key: &str) -> Option<String> {
    for section in ["DEFAULT", "app:container-server", "container-server"] {
        if let Ok(Some(v)) = conf.get(section, key) {
            return Some(v);
        }
    }
    None
}

fn conf_bind_port(conf: &SwiftConfig) -> Option<u32> {
    conf_get(conf, "bind_port")?.parse().ok()
}

fn conf_devices(conf: &SwiftConfig) -> Option<PathBuf> {
    conf_get(conf, "devices").map(PathBuf::from)
}

fn get_info_1(
    ring: &Ring,
    overlay: &ListenOverlay,
    account: &str,
    container: &str,
    obj: &str,
) -> Result<Option<String>, ContainerError> {
    let mut visited = HashSet::new();
    check_container(ring, overlay, account, container, obj, &mut visited, "auto")
}

fn check_container(
    ring: &Ring,
    overlay: &ListenOverlay,
    account: &str,
    container: &str,
    obj: &str,
    visited: &mut HashSet<(String, String)>,
    record_type: &str,
) -> Result<Option<String>, ContainerError> {
    let key = (account.to_string(), container.to_string());
    let record_type = if visited.contains(&key) {
        "object"
    } else {
        visited.insert(key);
        record_type
    };
    let (part, nodes) = ring
        .get_nodes(account, Some(container), None)
        .map_err(|_| ContainerError)?;
    if nodes.is_empty() {
        return Err(ContainerError);
    }
    let mut err_flag = 0u32;
    let mut shards: HashSet<(String, String)> = HashSet::new();
    for node in &nodes {
        match query_container_node(
            node.dev,
            overlay,
            part,
            account,
            container,
            obj,
            record_type,
        ) {
            Ok(NodeListing::Present(name)) => return Ok(Some(name)),
            Ok(NodeListing::Missing) => {}
            Ok(NodeListing::Shards(found)) => {
                for pair in found {
                    shards.insert(pair);
                }
            }
            Err(ContainerError) => err_flag += 1,
        }
    }
    for (shard_acct, shard_cont) in shards {
        if let Some(found) = check_container(
            ring,
            overlay,
            &shard_acct,
            &shard_cont,
            obj,
            visited,
            "auto",
        )? {
            return Ok(Some(found));
        }
    }
    if err_flag > 0 {
        return Err(ContainerError);
    }
    Ok(None)
}

enum NodeListing {
    Present(String),
    Missing,
    Shards(Vec<(String, String)>),
}

fn query_container_node(
    dev: &RingDevice,
    overlay: &ListenOverlay,
    part: u32,
    account: &str,
    container: &str,
    obj: &str,
    record_type: &str,
) -> Result<NodeListing, ContainerError> {
    let host = node_host(dev, overlay);
    let path = format!(
        "/{}/{part}/{}/{}?prefix={}&format=json&limit=1&includes={}&states=listing",
        pe(&dev.device),
        pe(account),
        pe(container),
        pe(obj),
        pe(obj)
    );
    let Some((status, buf)) = raw_request(
        &host,
        "GET",
        &path,
        &[
            ("Accept", "application/json"),
            ("X-Backend-Record-Type", record_type),
            ("X-Backend-Allow-Reserved-Names", "true"),
        ],
    ) else {
        return Err(ContainerError);
    };
    if status == 404 {
        return Ok(NodeListing::Missing);
    }
    if !(200..300).contains(&status) {
        return Err(ContainerError);
    }
    let body = http_body(&buf);
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| ContainerError)?;
    let arr = v.as_array().ok_or(ContainerError)?;
    let record = header_value(&buf, "X-Backend-Record-Type");
    if record.as_deref() == Some("shard") {
        let mut shards = Vec::new();
        if let Some(first) = arr.first() {
            if let Some(pair) = shard_account_container(first) {
                shards.push(pair);
            }
        }
        return Ok(if shards.is_empty() {
            NodeListing::Missing
        } else {
            NodeListing::Shards(shards)
        });
    }
    if let Some(name) = arr
        .first()
        .and_then(|item| item.get("name"))
        .and_then(|n| n.as_str())
    {
        if name == obj {
            return Ok(NodeListing::Present(name.to_string()));
        }
    }
    Ok(NodeListing::Missing)
}

fn shard_account_container(item: &serde_json::Value) -> Option<(String, String)> {
    if let (Some(account), Some(container)) = (
        item.get("account").and_then(|v| v.as_str()),
        item.get("container").and_then(|v| v.as_str()),
    ) {
        return Some((account.to_string(), container.to_string()));
    }
    let name = item.get("name")?.as_str()?;
    let (account, container) = name.split_once('/')?;
    if account.is_empty() || container.is_empty() {
        return None;
    }
    Some((account.to_string(), container.to_string()))
}

fn node_host(dev: &RingDevice, overlay: &ListenOverlay) -> String {
    let ip = dev.replication_ip.as_deref().unwrap_or(dev.ip.as_str());
    let ring_port = dev.replication_port.unwrap_or(dev.port);
    let port = overlay.listen_port(&dev.device, ring_port);
    if ip.contains(':') && !ip.starts_with('[') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
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
    let _ = conn.set_read_timeout(Some(CONTAINER_TIMEOUT));
    let _ = conn.set_write_timeout(Some(CONTAINER_TIMEOUT));
    if conn.write_all(request.as_bytes()).is_err() {
        return None;
    }
    let mut buf = Vec::new();
    if conn.read_to_end(&mut buf).is_err() {
        return None;
    }
    Some((http_status(&buf), buf))
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

fn header_value(buf: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(buf);
    for line in text.split("\r\n") {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(name) {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// Build a live watcher from object-auditor conf, or `None` when
/// `watchers` does not include `swift#dark_data`. Missing container ring
/// → unknown presence (do not delete).
pub fn watcher_from_conf(
    conf: &SwiftConfig,
    hash_config: HashPathConfig,
) -> Option<DarkDataWatcher<Box<dyn ContainerPresence + Send>>> {
    let config = DarkDataConfig::from_auditor_conf(conf)?;
    let presence: Box<dyn ContainerPresence + Send> = match RingContainerPresence::load(hash_config)
    {
        Some(ring) => Box::new(ring),
        None => Box::new(AlwaysUnknown),
    };
    Some(DarkDataWatcher::new(config, presence))
}

impl ContainerPresence for Box<dyn ContainerPresence + Send> {
    fn presence(&self, account: &str, container: &str, obj: &str) -> ObjectPresence {
        (**self).presence(account, container, obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use swift_core::hashing::HashPathConfig;
    use swift_diskfile::{
        audit_device_with_watcher, audit_locations, DiskFile, DiskFileConfig, MetaValue, PolicyKind,
    };
    use swift_ring::{RingData, RingDevice};

    fn hc() -> HashPathConfig {
        HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap()
    }

    fn meta(name: &str, ts: &str) -> Metadata {
        vec![
            ("name".into(), MetaValue::Str(name.into())),
            ("X-Timestamp".into(), MetaValue::Str(ts.into())),
        ]
    }

    fn parse_conf(text: &str) -> SwiftConfig {
        SwiftConfig::parse_lenient(text, &[], false).unwrap()
    }

    #[test]
    fn parses_delete_and_quarantine_and_unknown_defaults_log() {
        let delete = parse_conf(
            "[object-auditor]\nwatchers = swift#dark_data\n\n\
             [object-auditor:watcher:swift#dark_data]\naction = delete\ngrace_age = 0\n",
        );
        let cfg = DarkDataConfig::from_auditor_conf(&delete).unwrap();
        assert_eq!(cfg.action, DarkDataAction::Delete);
        assert_eq!(cfg.grace_age, 0.0);

        let quarantine = parse_conf(
            "[object-auditor]\nwatchers = foo, swift#dark_data\n\n\
             [object-auditor:watcher:swift#dark_data]\naction = quarantine\n",
        );
        assert_eq!(
            DarkDataConfig::from_auditor_conf(&quarantine)
                .unwrap()
                .action,
            DarkDataAction::Quarantine
        );

        let unknown = parse_conf(
            "[object-auditor]\nwatchers = swift#dark_data\n\n\
             [object-auditor:watcher:swift#dark_data]\naction = explode\n",
        );
        assert_eq!(
            DarkDataConfig::from_auditor_conf(&unknown).unwrap().action,
            DarkDataAction::Log
        );
        assert!(DarkDataConfig::from_auditor_conf(&parse_conf(
            "[object-auditor]\ninterval = 30\n"
        ))
        .is_none());
    }

    #[test]
    fn grace_age_skips_recent_objects() {
        let watcher = DarkDataWatcher::new(
            DarkDataConfig {
                action: DarkDataAction::Delete,
                grace_age: 604800.0,
            },
            AlwaysDark,
        );
        let dir = std::env::temp_dir().join(format!(
            "swift-dark-grace-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data = dir.join("hash").join("1.data");
        std::fs::create_dir_all(data.parent().unwrap()).unwrap();
        std::fs::write(&data, b"x").unwrap();
        let now = format!("{:.5}", unix_now());
        assert_eq!(
            watcher.see_object(&meta("/a/c/o", &now), &data),
            WatcherDecision::Keep
        );
        assert!(data.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn write_object(device: &Path, name: &str, ts: &str, body: &[u8]) {
        let df = DiskFile::new(
            device,
            0,
            "a",
            "c",
            name,
            PolicyKind::Replication,
            0,
            &hc(),
            DiskFileConfig::default(),
        )
        .unwrap();
        let etag = {
            use md5::{Digest, Md5};
            format!("{:x}", Md5::digest(body))
        };
        let metadata: Metadata = vec![
            ("X-Timestamp".into(), MetaValue::Str(ts.into())),
            ("Content-Type".into(), "text/plain".into()),
            ("ETag".into(), MetaValue::Str(etag)),
            (
                "Content-Length".into(),
                MetaValue::Str(body.len().to_string()),
            ),
        ];
        let mut w = df.create(".data").unwrap();
        w.write(body).unwrap();
        w.put(metadata).unwrap();
        w.close();
    }

    #[test]
    fn delete_removes_hash_dir_without_quarantined() {
        let root =
            std::env::temp_dir().join(format!("swift-dark-del-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&root);
        let device = root.join("sdb1");
        std::fs::create_dir_all(&device).unwrap();
        write_object(&device, "leftover", "1000000000.00000", b"dark-bytes");
        assert_eq!(audit_locations(&device, 0).len(), 1);

        let mut watcher = DarkDataWatcher::new(
            DarkDataConfig {
                action: DarkDataAction::Delete,
                grace_age: 0.0,
            },
            AlwaysDark,
        );
        let report = audit_device_with_watcher(
            &device,
            PolicyKind::Replication,
            0,
            &hc(),
            &DiskFileConfig::default(),
            Some(&mut watcher),
        );
        assert_eq!(report.quarantined, 0, "{report:?}");
        assert!(audit_locations(&device, 0).is_empty());
        assert!(
            !device.join("quarantined").exists(),
            "TestDarkDataDeletion: quarantined/ must not exist after action=delete"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn quarantine_still_creates_quarantined() {
        let root =
            std::env::temp_dir().join(format!("swift-dark-q-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&root);
        let device = root.join("sdb1");
        std::fs::create_dir_all(&device).unwrap();
        write_object(&device, "leftover", "1000000000.00000", b"dark-bytes");

        let mut watcher = DarkDataWatcher::new(
            DarkDataConfig {
                action: DarkDataAction::Quarantine,
                grace_age: 0.0,
            },
            AlwaysDark,
        );
        let report = audit_device_with_watcher(
            &device,
            PolicyKind::Replication,
            0,
            &hc(),
            &DiskFileConfig::default(),
            Some(&mut watcher),
        );
        assert_eq!(report.quarantined, 1, "{report:?}");
        assert!(audit_locations(&device, 0).is_empty());
        assert!(device.join("quarantined").is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn container_error_and_present_leave_files() {
        for presence in [ObjectPresence::Unknown, ObjectPresence::Present] {
            let root = std::env::temp_dir().join(format!(
                "swift-dark-skip-{}-{}-{}",
                std::process::id(),
                line!(),
                presence as u8
            ));
            let _ = std::fs::remove_dir_all(&root);
            let device = root.join("sdb1");
            std::fs::create_dir_all(&device).unwrap();
            write_object(&device, "keep", "1000000000.00000", b"keep-me");
            let boxed: Box<dyn ContainerPresence + Send> = match presence {
                ObjectPresence::Unknown => Box::new(AlwaysUnknown),
                ObjectPresence::Present => Box::new(AlwaysPresent),
                ObjectPresence::Dark => unreachable!(),
            };
            let mut watcher = DarkDataWatcher::new(
                DarkDataConfig {
                    action: DarkDataAction::Delete,
                    grace_age: 0.0,
                },
                boxed,
            );
            let report = audit_device_with_watcher(
                &device,
                PolicyKind::Replication,
                0,
                &hc(),
                &DiskFileConfig::default(),
                Some(&mut watcher),
            );
            assert_eq!(report.quarantined, 0);
            assert_eq!(audit_locations(&device, 0).len(), 1);
            assert!(!device.join("quarantined").exists());
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    fn test_dev(id: u64, ip: &str, port: u32, device: &str) -> RingDevice {
        RingDevice {
            id,
            region: 1,
            zone: 1,
            ip: ip.to_string(),
            port,
            replication_ip: None,
            replication_port: None,
            device: device.to_string(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        }
    }

    fn one_node_ring(port: impl Into<u32>) -> Ring {
        let port = port.into();
        Ring::new(
            RingData::from_parts(
                vec![Some(test_dev(0, "127.0.0.1", port, "sdb1"))],
                32,
                vec![vec![0]],
            ),
            hc(),
        )
    }

    fn spawn_listing_server(
        status_line: &'static str,
        extra_headers: &'static str,
        body: &'static str,
        seen: Arc<Mutex<Vec<String>>>,
    ) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).unwrap_or(0);
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let resp = format!(
                    "{status_line}\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{extra_headers}Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes());
            }
        });
        (port, handle)
    }

    #[test]
    fn empty_listing_is_dark_and_object_row_is_present() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (port, handle) = spawn_listing_server(
            "HTTP/1.1 200 OK",
            "X-Backend-Record-Type: object\r\n",
            "[]",
            Arc::clone(&seen),
        );
        let ring = one_node_ring(port);
        let overlay = ListenOverlay::default();
        assert_eq!(
            get_info_1(&ring, &overlay, "a", "c", "o").unwrap(),
            None,
            "empty listing is dark"
        );
        handle.join().unwrap();
        let req = seen.lock().unwrap()[0].clone();
        assert!(req.contains("prefix=o"), "{req}");
        assert!(req.contains("includes=o"), "{req}");
        assert!(req.contains("states=listing"), "{req}");
        assert!(req.contains("X-Backend-Record-Type: auto"), "{req}");

        let seen = Arc::new(Mutex::new(Vec::new()));
        let (port, handle) = spawn_listing_server(
            "HTTP/1.1 200 OK",
            "X-Backend-Record-Type: object\r\n",
            r#"[{"name":"o","hash":"abc"}]"#,
            seen,
        );
        let ring = one_node_ring(port);
        assert_eq!(
            get_info_1(&ring, &ListenOverlay::default(), "a", "c", "o").unwrap(),
            Some("o".into())
        );
        handle.join().unwrap();
    }

    #[test]
    fn node_error_is_unknown_not_dark() {
        let ring = one_node_ring(1u32); // closed port
        assert!(get_info_1(&ring, &ListenOverlay::default(), "a", "c", "o").is_err());
    }

    #[test]
    fn overlay_remaps_container_bind_port() {
        let root =
            std::env::temp_dir().join(format!("swift-dark-ov-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&root);
        let devices = root.join("srv").join("node");
        std::fs::create_dir_all(devices.join("sdb1")).unwrap();
        let conf_dir = root.join("container-server");
        std::fs::create_dir_all(&conf_dir).unwrap();
        std::fs::write(
            conf_dir.join("1.conf"),
            format!(
                "[DEFAULT]\nbind_port = 16001\ndevices = {}\n",
                devices.display()
            ),
        )
        .unwrap();
        let overlay = ListenOverlay::from_swift_dir(&root, "container-server");
        assert_eq!(overlay.listen_port("sdb1", 6011), 16001);
        let _ = std::fs::remove_dir_all(&root);
    }
}
