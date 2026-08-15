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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Local interface discovery shared by ring-aware daemons.
//!
//! Swift's Python daemons use `whataremyips()` before deciding whether a ring
//! device belongs to the current host. A bind probe is not equivalent:
//! `net.ipv4.ip_nonlocal_bind=1` makes every address appear bindable on HA
//! nodes. These helpers enumerate addresses with `getifaddrs(3)` instead.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// The addresses configured on this host (Python `whataremyips()` with no
/// argument).
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
    let local: BTreeSet<String> = local_addrs()
        .into_iter()
        .map(|address| address.to_string())
        .collect();
    ring_address_is_local(ip, 0, &local, None)
}

/// Python `swift.common.ring.utils.is_local_device`.
///
/// Ring daemons identify a device using its *replication* address. Hostnames
/// are resolved before comparison, IPv6 text is normalized through
/// [`IpAddr`], and `local_port=None` is the `servers_per_port` contract where
/// only the address determines locality.
pub fn ring_address_is_local(
    device_ip: &str,
    device_port: u32,
    local_ips: &BTreeSet<String>,
    local_port: Option<u32>,
) -> bool {
    if local_port.is_some_and(|port| port != device_port) {
        return false;
    }
    let local: BTreeSet<IpAddr> = local_ips
        .iter()
        .filter_map(|candidate| candidate.parse::<IpAddr>().ok())
        .collect();
    if local.is_empty() {
        return false;
    }

    if let Ok(address) = device_ip.parse::<IpAddr>() {
        return local.contains(&address);
    }
    let Ok(port) = u16::try_from(device_port) else {
        return false;
    };
    (device_ip, port)
        .to_socket_addrs()
        .map(|addresses| {
            addresses
                .into_iter()
                .any(|address| local.contains(&address.ip()))
        })
        .unwrap_or(false)
}

/// IP set used for ring locality lookup (Python `whataremyips(ring_ip)`).
///
/// A concrete non-wildcard `ring_ip` returns just that address. Wildcard,
/// empty, and non-numeric values expand to every address on this host.
pub fn ips_for_ring_lookup(ring_ip: &str) -> BTreeSet<String> {
    let trimmed = ring_ip.trim();
    if !trimmed.is_empty() {
        if let Ok(addr) = trimmed.parse::<IpAddr>() {
            if !addr.is_unspecified() {
                let mut set = BTreeSet::new();
                set.insert(trimmed.to_string());
                return set;
            }
        }
    }
    local_addrs()
        .into_iter()
        .map(|address| address.to_string())
        .collect()
}

/// Interface-backed IP set for fail-closed ring identity lookup.
///
/// This is stricter than [`ips_for_ring_lookup`]: a concrete configured IP is
/// returned only when it is actually assigned to an interface on this host.
/// Hostnames are resolved and intersected with the interface set. Empty or
/// wildcard input selects every local interface address.
///
/// The distinction matters on HA nodes with `ip_nonlocal_bind=1`: accepting a
/// configured but non-local address would let a daemon claim another ring
/// device merely because the kernel permits binding it.
pub fn verified_ips_for_ring_lookup(ring_ip: &str) -> BTreeSet<String> {
    let interfaces: BTreeSet<IpAddr> = local_addrs().into_iter().collect();
    let trimmed = ring_ip.trim();
    if trimmed.is_empty() {
        return interfaces
            .into_iter()
            .map(|address| address.to_string())
            .collect();
    }

    if let Ok(address) = trimmed.parse::<IpAddr>() {
        if address.is_unspecified() {
            return interfaces
                .into_iter()
                .map(|candidate| candidate.to_string())
                .collect();
        }
        return if interfaces.contains(&address) {
            BTreeSet::from([address.to_string()])
        } else {
            BTreeSet::new()
        };
    }

    (trimmed, 0)
        .to_socket_addrs()
        .map(|addresses| {
            addresses
                .map(|address| address.ip())
                .filter(|address| interfaces.contains(address))
                .map(|address| address.to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_local_and_a_documentation_address_is_not() {
        assert!(is_local_addr("127.0.0.1"));
        assert!(!is_local_addr("192.0.2.1"));
    }

    #[test]
    fn wildcard_addresses_are_not_claimed_as_local_devices() {
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
    fn hostname_is_resolved_before_locality_is_decided() {
        assert!(is_local_addr("localhost"));
        assert!(!is_local_addr("definitely-not-a-real-swift-host.invalid"));
        assert!(!is_local_addr(""));
    }

    #[test]
    fn replication_port_is_part_of_locality_unless_servers_per_port_is_used() {
        let local = BTreeSet::from(["127.0.0.1".to_string()]);
        assert!(ring_address_is_local("localhost", 6211, &local, Some(6211)));
        assert!(!ring_address_is_local(
            "127.0.0.1",
            6212,
            &local,
            Some(6211)
        ));
        assert!(ring_address_is_local("127.0.0.1", 6212, &local, None));
    }

    #[test]
    fn ring_lookup_uses_exact_or_enumerated_addresses() {
        let exact = ips_for_ring_lookup("10.0.4.1");
        assert_eq!(exact.len(), 1);
        assert!(exact.contains("10.0.4.1"));

        let wildcard = ips_for_ring_lookup("0.0.0.0");
        assert!(wildcard.contains("127.0.0.1") || !wildcard.is_empty());
    }

    #[test]
    fn verified_ring_lookup_rejects_non_interface_addresses() {
        let local = verified_ips_for_ring_lookup("127.0.0.1");
        assert_eq!(local, BTreeSet::from(["127.0.0.1".to_string()]));
        assert!(verified_ips_for_ring_lookup("192.0.2.1").is_empty());
    }

    #[test]
    fn verified_ring_lookup_handles_wildcards_and_local_hostnames() {
        let wildcard = verified_ips_for_ring_lookup("0.0.0.0");
        assert!(wildcard.contains("127.0.0.1") || !wildcard.is_empty());

        let localhost = verified_ips_for_ring_lookup("localhost");
        assert!(localhost.contains("127.0.0.1") || localhost.contains("::1"));
    }
}
