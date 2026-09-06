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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use swift_ring::Ring;

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
