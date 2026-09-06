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

//! "Which ring device am I?" — answered by address, not by name.
//!
//! Every replication daemon has to map a directory under `devices/` onto the
//! ring entry it represents. Matching on `(port, device_name)` alone looks
//! sufficient and is not: every node in a cluster names its first disk `d1` and
//! serves it on the same port, so a lookup that ignores the address returns the
//! lowest-id match on *every* node. The first node in the ring gets the right
//! answer by luck and every other node silently adopts its identity.
//!
//! The consequences are not subtle. A reconstructor that thinks it is another
//! node fails to recognise its own fragments as belonging where they are, so it
//! builds relocation jobs whose destination is the device it is already reading
//! from; sender and receiver then contend for the same partition flock and the
//! push dies on a 15 s timeout, every pass, forever.
//!
//! Swift solves this in Python with `whataremyips()`, which enumerates the
//! host's interfaces, and so does this: the addresses configured on this host
//! are read from `getifaddrs(3)` and the ring's address is looked up in them.
//!
//! Bindability is NOT a usable proxy for "this address is mine", however
//! plausible it looks. `net.ipv4.ip_nonlocal_bind=1` — which every host running
//! a load balancer in front of a floating VIP sets, and which this cluster sets
//! on all four nodes — makes *every* address bindable, so a bind probe answers
//! "yes, that is me" for the whole ring and hands the identity of the
//! lowest-numbered device to every node in it.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use swift_core::config::SwiftConfig;
use swift_ring::{Ring, RingDevice};

/// The addresses configured on this host (Python `whataremyips()` with no arg).
pub fn local_addrs() -> Vec<IpAddr> {
    let mut addrs = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills in a list it owns until freeifaddrs; every
    // pointer is null-checked before it is dereferenced, and each sockaddr is
    // only read as the type its sa_family declares.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return addrs;
        }
        let mut entry = head;
        while !entry.is_null() {
            let addr = (*entry).ifa_addr;
            if !addr.is_null() {
                match i32::from((*addr).sa_family) {
                    libc::AF_INET => {
                        let sin = addr.cast::<libc::sockaddr_in>();
                        addrs.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                            (*sin).sin_addr.s_addr,
                        ))));
                    }
                    libc::AF_INET6 => {
                        let sin6 = addr.cast::<libc::sockaddr_in6>();
                        addrs.push(IpAddr::V6(Ipv6Addr::from((*sin6).sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            entry = (*entry).ifa_next;
        }
        libc::freeifaddrs(head);
    }
    addrs
}

/// True when `ip` is configured on this host.
pub fn is_local_addr(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(addr) => local_addrs().contains(&addr),
        // A hostname in the ring is not something we can resolve to an
        // interface; treat it as "cannot confirm" rather than claiming it is
        // ours.
        Err(_) => false,
    }
}

/// IP set used for ring port lookup (Python `whataremyips(ring_ip)`).
///
/// A concrete non-wildcard `ring_ip` returns just that address. Wildcard /
/// empty / unparseable values expand to every address on this host (including
/// loopback), matching Python when `bind_ip` is `0.0.0.0` / `::`.
pub fn ips_for_ring_lookup(ring_ip: &str) -> std::collections::BTreeSet<String> {
    let trimmed = ring_ip.trim();
    if !trimmed.is_empty() {
        if let Ok(addr) = trimmed.parse::<IpAddr>() {
            if !addr.is_unspecified() {
                let mut set = std::collections::BTreeSet::new();
                set.insert(trimmed.to_string());
                return set;
            }
        }
    }
    local_addrs().into_iter().map(|a| a.to_string()).collect()
}

/// The id of the ring device this host serves at `(bind_port, dev_name)`.
///
/// Candidates are narrowed by port and device name, then disambiguated by
/// address. Returns `None` when the directory does not correspond to a local
/// ring device — the caller should skip it, which is the safe outcome: doing
/// nothing is always better than acting as another node.
///
/// A device's `ip` and `replication_ip` are both accepted, because a node may
/// legitimately be addressed on either plane.
///
/// When `servers_per_port` / `object_port_per_device` is in use, conf
/// `bind_port` is only a discovery base (e.g. 6210) while ring entries carry
/// the real per-device ports (6211, 6212, …). In that case pass
/// [`ring_device_id_local_name`] instead — matching on the conf base port
/// yields **no** candidates and every partition is silently skipped
/// (`suffix_syncs=0` forever).
pub fn ring_device_id(ring: &Ring, bind_port: u32, dev_name: &str) -> Option<u64> {
    let candidates: Vec<&swift_ring::RingDevice> = ring
        .devs()
        .iter()
        .flatten()
        .filter(|d| d.port == bind_port && d.device == dev_name)
        .collect();

    // Unambiguous: one device in the whole ring answers to this name and port,
    // so no address probe is needed (and none should be required — a
    // single-node or test ring may use a loopback or placeholder address).
    if candidates.len() == 1 {
        return Some(candidates[0].id);
    }

    candidates
        .iter()
        .find(|d| is_local_addr(&d.ip) || d.replication_ip.as_deref().is_some_and(is_local_addr))
        .map(|d| d.id)
}

/// Ring device id for a local directory when conf `bind_port` is **not** the
/// ring listen port (multi-port / `servers_per_port` topology).
///
/// Narrow by device name, then require a local `ip` / `replication_ip`. If
/// several ring entries share the name on this host (should not happen for a
/// single device dir), pick the lowest id for stability.
pub fn ring_device_id_local_name(ring: &Ring, dev_name: &str) -> Option<u64> {
    let mut local: Vec<&swift_ring::RingDevice> = ring
        .devs()
        .iter()
        .flatten()
        .filter(|d| {
            d.device == dev_name
                && (is_local_addr(&d.ip) || d.replication_ip.as_deref().is_some_and(is_local_addr))
        })
        .collect();
    if local.is_empty() {
        return None;
    }
    local.sort_by_key(|d| d.id);
    Some(local[0].id)
}

/// Ring device id for a local `devices/` directory.
///
/// Isolated G6 remaps object-server listen ports (`16210` …) while EC rings
/// often still list `6010` / `6200`. With `servers_per_port=0` a strict
/// `(bind_port, name)` match returns `None` and the reconstructor skips every
/// device (`suffix_syncs=0`) — partner SYNC and the post-ssync local rebuild
/// never run. Fall back to local IP + device name. Still requires a local
/// interface address so a multi-node `d1` cannot be stolen.
pub fn resolve_ring_device_id(
    ring: &Ring,
    bind_port: u32,
    servers_per_port: u32,
    dev_name: &str,
) -> Option<u64> {
    if servers_per_port > 0 {
        return ring_device_id_local_name(ring, dev_name);
    }
    ring_device_id(ring, bind_port, dev_name).or_else(|| ring_device_id_local_name(ring, dev_name))
}

/// Isolated G6 keeps EC ring ports at `6010` / `6200` while object servers
/// listen on `16210`…. Identity fallback already finds the local device;
/// partner REPLICATE / SSYNC / fragment GET still dialed the ring port and
/// got connection refused, so `break_nodes` never healed.
///
/// Built from `SWIFT_DIR/object-server/*.conf` (+ `object-server.conf`):
/// each conf's `devices` children map to that conf's `bind_port`. When every
/// parsed conf shares one bind port (one object server per host, same remap
/// on every node), that port is also the default for unmapped remote devices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectListenOverlay {
    by_device: BTreeMap<String, u32>,
    default_port: Option<u32>,
}

impl ObjectListenOverlay {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, device: impl Into<String>, port: u32) {
        self.by_device.insert(device.into(), port);
        self.refresh_default();
    }

    pub fn set_default_port(&mut self, port: u32) {
        self.default_port = Some(port);
    }

    pub fn is_empty(&self) -> bool {
        self.by_device.is_empty() && self.default_port.is_none()
    }

    pub fn listen_port(&self, device: &str, ring_port: u32) -> u32 {
        self.by_device
            .get(device)
            .copied()
            .or(self.default_port)
            .unwrap_or(ring_port)
    }

    /// Rewrite a ring device so fragment GET / REPLICATE hit the listen port.
    pub fn remap_device(&self, dev: &RingDevice) -> RingDevice {
        let mut out = dev.clone();
        let ring_port = out.replication_port.unwrap_or(out.port);
        let listen = self.listen_port(&out.device, ring_port);
        out.port = listen;
        out.replication_port = Some(listen);
        out
    }

    pub fn from_swift_dir(swift_dir: &Path) -> Self {
        let mut overlay = Self::empty();
        let mut confs: Vec<PathBuf> = Vec::new();
        let root_conf = swift_dir.join("object-server.conf");
        if root_conf.is_file() {
            confs.push(root_conf);
        }
        let dir = swift_dir.join("object-server");
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
            let devices = conf_devices(&conf);
            let mut mapped = false;
            if let Some(root) = devices.as_ref() {
                if let Ok(entries) = std::fs::read_dir(root) {
                    for entry in entries.flatten() {
                        if entry.path().is_dir() {
                            if let Some(name) = entry.file_name().to_str() {
                                if !name.starts_with('.') {
                                    overlay.insert(name.to_string(), port);
                                    mapped = true;
                                }
                            }
                        }
                    }
                }
                if !mapped {
                    if let Some(name) = root.file_name().and_then(|s| s.to_str()) {
                        if name != "node" && name != "srv" {
                            overlay.insert(name.to_string(), port);
                        }
                    }
                }
            }
            // Remember every parsed listen port so a single-port isolated
            // node can remap remote partners (same bind_port on every host).
            overlay.note_parsed_port(port);
        }
        overlay.refresh_default();
        overlay
    }

    fn note_parsed_port(&mut self, port: u32) {
        match self.default_port {
            None => self.default_port = Some(port),
            Some(existing) if existing != port => self.default_port = None,
            Some(_) => {}
        }
    }

    fn refresh_default(&mut self) {
        let mut unique = BTreeMap::new();
        for port in self.by_device.values().copied() {
            unique.insert(port, ());
        }
        if unique.len() == 1 {
            self.default_port = unique.keys().next().copied();
        } else if unique.len() > 1 {
            // Per-device ports (SAIO 16210/16220/…). Keep by_device only.
            self.default_port = None;
        }
    }
}

fn conf_get(conf: &SwiftConfig, key: &str) -> Option<String> {
    crate::object_server_conf::object_server_conf_get(conf, key)
}

fn conf_bind_port(conf: &SwiftConfig) -> Option<u32> {
    conf_get(conf, "bind_port")?.parse().ok()
}

fn conf_devices(conf: &SwiftConfig) -> Option<PathBuf> {
    conf_get(conf, "devices").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use swift_core::hashing::HashPathConfig;
    use swift_ring::{RingData, RingDevice};

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

    fn test_ring(devs: Vec<Option<RingDevice>>) -> Ring {
        let assigned: Vec<u32> = devs.iter().flatten().map(|d| d.id as u32).collect();
        let parts = if assigned.is_empty() {
            vec![0]
        } else {
            assigned
        };
        Ring::new(
            RingData::from_parts(devs, 32, vec![parts]),
            HashPathConfig::new("", "changeme").unwrap(),
        )
    }

    #[test]
    fn loopback_is_local_and_a_documentation_address_is_not() {
        assert!(is_local_addr("127.0.0.1"));
        // TEST-NET-1 (RFC 5737) is guaranteed not to be configured anywhere.
        assert!(!is_local_addr("192.0.2.1"));
    }

    #[test]
    fn a_bindable_address_that_is_not_an_interface_address_is_not_local() {
        // The wildcard binds on every host and belongs to none of them: the
        // exact class of answer a bind probe gets wrong. In production the
        // same wrong answer came from ip_nonlocal_bind, which cannot be
        // toggled from a test but makes every address look like this one.
        assert!(!is_local_addr("0.0.0.0"));
        assert!(!is_local_addr("::"));
    }

    #[test]
    fn every_enumerated_address_answers_local() {
        let addrs = local_addrs();
        assert!(!addrs.is_empty(), "a host always has at least a loopback");
        for addr in addrs {
            assert!(
                is_local_addr(&addr.to_string()),
                "{addr} is on an interface"
            );
        }
    }

    #[test]
    fn a_hostname_is_never_claimed_as_local() {
        // Guessing here is what the whole module exists to prevent.
        assert!(!is_local_addr("swift1"));
        assert!(!is_local_addr(""));
    }

    #[test]
    fn ips_for_ring_lookup_exact_vs_wildcard() {
        let exact = ips_for_ring_lookup("10.0.4.1");
        assert_eq!(exact.len(), 1);
        assert!(exact.contains("10.0.4.1"));
        let wild = ips_for_ring_lookup("0.0.0.0");
        assert!(wild.contains(&"127.0.0.1".to_string()) || !wild.is_empty());
    }

    #[test]
    fn remapped_bind_port_falls_back_to_local_name() {
        // Failed first: spp=0 + bind_port 16210 vs ring port 6010 returned
        // None, so reconstructor skipped the only local device.
        let ring = test_ring(vec![Some(test_dev(3, "127.0.0.1", 6010, "d1"))]);
        assert_eq!(
            resolve_ring_device_id(&ring, 16210, 0, "d1"),
            Some(3),
            "isolated remapped listen port must still find the local device"
        );
        assert_eq!(resolve_ring_device_id(&ring, 6010, 0, "d1"), Some(3));
    }

    #[test]
    fn remapped_bind_port_does_not_steal_a_remote_d1() {
        let ring = test_ring(vec![Some(test_dev(3, "192.0.2.1", 6010, "d1"))]);
        assert_eq!(
            resolve_ring_device_id(&ring, 16210, 0, "d1"),
            None,
            "TEST-NET-1 is never a local interface"
        );
        assert_eq!(resolve_ring_device_id(&ring, 6010, 0, "d1"), Some(3));
    }

    #[test]
    fn servers_per_port_still_matches_local_name() {
        let ring = test_ring(vec![Some(test_dev(7, "127.0.0.1", 6217, "sda1"))]);
        assert_eq!(resolve_ring_device_id(&ring, 6210, 1, "sda1"), Some(7));
        assert_eq!(resolve_ring_device_id(&ring, 6210, 0, "sda1"), Some(7));
    }

    fn write_object_conf(dir: &Path, name: &str, bind_port: u32, devices: &Path) {
        std::fs::create_dir_all(dir.join("object-server")).unwrap();
        std::fs::write(
            dir.join("object-server").join(name),
            format!(
                "[DEFAULT]\nbind_port = {bind_port}\ndevices = {}\n",
                devices.display()
            ),
        )
        .unwrap();
    }

    #[test]
    fn empty_overlay_keeps_the_ring_port() {
        // Failed first: partner SYNC used ring 6010 after identity fallback.
        let overlay = ObjectListenOverlay::empty();
        assert_eq!(overlay.listen_port("d1", 6010), 6010);
        assert!(overlay.is_empty());
    }

    #[test]
    fn overlay_from_swift_dir_maps_device_dirs_to_bind_port() {
        let root = std::env::temp_dir().join(format!(
            "swift-listen-overlay-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let devices = root.join("srv/node");
        std::fs::create_dir_all(devices.join("d1")).unwrap();
        std::fs::create_dir_all(devices.join("d2")).unwrap();
        write_object_conf(&root, "1.conf", 16210, &devices);
        write_object_conf(&root, "2.conf", 16220, &root.join("srv/node-missing"));

        let overlay = ObjectListenOverlay::from_swift_dir(&root);
        assert_eq!(
            overlay.listen_port("d1", 6010),
            16210,
            "isolated listen port must replace the ring port"
        );
        assert_eq!(overlay.listen_port("d2", 6020), 16210);
        // Two bind ports, one mapped: no cluster-wide default.
        assert_eq!(
            overlay.listen_port("remote-d3", 6030),
            6030,
            "unmapped device keeps the ring port when listen ports are not unique"
        );
        let remapped = overlay.remap_device(&test_dev(3, "10.0.0.2", 6010, "d1"));
        assert_eq!(remapped.port, 16210);
        assert_eq!(remapped.replication_port, Some(16210));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn single_bind_port_conf_remaps_unmapped_remote_partners() {
        // Multi-node isolated: each host has one object-server.conf at 16210
        // while rings still say 6010. Remote partners use the same listen port.
        let root = std::env::temp_dir().join(format!(
            "swift-listen-overlay-oneport-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let devices = root.join("srv/node");
        std::fs::create_dir_all(devices.join("d1")).unwrap();
        write_object_conf(&root, "1.conf", 16210, &devices);
        let overlay = ObjectListenOverlay::from_swift_dir(&root);
        assert_eq!(overlay.listen_port("d1", 6010), 16210);
        assert_eq!(
            overlay.listen_port("d2", 6010),
            16210,
            "same remapped bind_port on every host"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
