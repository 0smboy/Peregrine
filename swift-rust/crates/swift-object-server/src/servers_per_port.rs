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

//! `servers_per_port` topology + workers → effective concurrency.
//!
//! Python `ServersPerPortStrategy` discovers unique local object-ring ports and
//! forks `servers_per_port` workers **per port** (one OS process per acceptor).
//!
//! Rust Wave 2 (full): when `servers_per_port>0`, the parent process supervises
//! one child OS process per `(port, worker_index)` via re-exec. Each child binds
//! a single port (REUSEPORT when multiple children share a port). This is
//! process-isolated like Python, not a shared pool across ports.
//!
//! Ring contract: `object_port_per_device` in `build_rings.sh.j2` assigns
//! d1→`object_bind_port`, d2→+1, d3→+2. Contabo live rebuild is a separate
//! ops ticket (no wipe). See `docs/fairness-lab/WORKERS-SEMANTICS.md`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::SystemTime;

use swift_ring::RingData;

use crate::localdev::ips_for_ring_lookup;

/// Hard cap on HTTP worker threads (matches `swift-http` ServerConfig clamp).
pub const WORKER_THREADS_CAP: usize = 128;

/// Child re-exec env: bind this single object-server port.
pub const CHILD_BIND_PORT_ENV: &str = "SWIFT_OBJECT_SERVER_BIND_PORT";

/// Cached ring → local bind-port sets (Python `BindPortsCache`).
#[derive(Debug, Default)]
pub struct BindPortsCache {
    swift_dir: PathBuf,
    my_ips: BTreeSet<String>,
    mtimes_by_ring_path: std::collections::HashMap<PathBuf, SystemTime>,
    portsets_by_ring_path: std::collections::HashMap<PathBuf, BTreeSet<u16>>,
}

impl BindPortsCache {
    pub fn new(swift_dir: impl Into<PathBuf>, ring_ip: &str) -> Self {
        Self {
            swift_dir: swift_dir.into(),
            my_ips: ips_for_ring_lookup(ring_ip),
            mtimes_by_ring_path: Default::default(),
            portsets_by_ring_path: Default::default(),
        }
    }

    pub fn all_bind_ports_for_node(&mut self) -> BTreeSet<u16> {
        self.refresh();
        let mut res = BTreeSet::new();
        for ports in self.portsets_by_ring_path.values() {
            res.extend(ports.iter().copied());
        }
        res
    }

    fn refresh(&mut self) {
        for path in object_ring_paths(&self.swift_dir) {
            let new_mtime = match std::fs::metadata(&path).and_then(|m| m.modified()) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let stale = match self.mtimes_by_ring_path.get(&path) {
                Some(old) => *old != new_mtime,
                None => true,
            };
            if !stale {
                continue;
            }
            let ports = match RingData::load_metadata_only(&path) {
                Ok(data) => ports_for_local_devs(&data, &self.my_ips),
                Err(_) => continue,
            };
            self.portsets_by_ring_path.insert(path.clone(), ports);
            self.mtimes_by_ring_path.insert(path, new_mtime);
        }
    }
}

pub fn object_ring_paths(swift_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(swift_dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.starts_with("object") && name.ends_with(".ring.gz")
        })
        .collect();
    paths.sort();
    paths
}

pub fn ports_for_local_devs(data: &RingData, my_ips: &BTreeSet<String>) -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for dev in data.devs.iter().flatten() {
        if my_ips.contains(&dev.ip) {
            if let Ok(p) = u16::try_from(dev.port) {
                if p > 0 {
                    ports.insert(p);
                }
            }
        }
    }
    ports
}

pub fn discover_servers_per_port_binds(swift_dir: &Path, ring_ip: &str) -> BTreeSet<u16> {
    let mut cache = BindPortsCache::new(swift_dir, ring_ip);
    cache.all_bind_ports_for_node()
}

/// Listen ports: ring discovery, else fallback to conf `bind_port`.
pub fn listen_ports(swift_dir: &Path, ring_ip: &str, bind_port: u16) -> Vec<u16> {
    let discovered = discover_servers_per_port_binds(swift_dir, ring_ip);
    if discovered.is_empty() {
        vec![bind_port]
    } else {
        discovered.into_iter().collect()
    }
}

/// If this process is a supervised child, return the single port it must bind.
pub fn child_bind_port_from_env() -> Option<u16> {
    std::env::var(CHILD_BIND_PORT_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&p| p > 0)
}

/// Plan of `(port, worker_index)` children the supervisor will spawn.
pub fn port_worker_plan(ports: &[u16], servers_per_port: usize) -> Vec<(u16, usize)> {
    let n = servers_per_port.max(1);
    let mut out = Vec::with_capacity(ports.len().saturating_mul(n));
    for &port in ports {
        for idx in 0..n {
            out.push((port, idx));
        }
    }
    out
}

/// Spawn one OS child per `(port, worker_index)` and wait for all to exit.
///
/// Returns `Ok(exit_code)` when this process was the supervisor (caller should
/// exit with that code). Returns `Ok(None)` when this process is a child (or
/// `servers_per_port==0`) and should continue into the listen loop.
pub fn maybe_supervise_port_workers(
    servers_per_port: usize,
    ports: &[u16],
    conf_argv: &[String],
) -> std::io::Result<Option<i32>> {
    if servers_per_port == 0 {
        return Ok(None);
    }
    if child_bind_port_from_env().is_some() {
        return Ok(None);
    }
    let plan = port_worker_plan(ports, servers_per_port);
    if plan.is_empty() {
        return Ok(None);
    }
    let exe = std::env::current_exe()?;
    let mut children: Vec<Child> = Vec::with_capacity(plan.len());
    for (port, idx) in &plan {
        let mut cmd = Command::new(&exe);
        for a in conf_argv {
            cmd.arg(a);
        }
        cmd.env(CHILD_BIND_PORT_ENV, port.to_string());
        cmd.env("SWIFT_OBJECT_SERVER_PORT_WORKER", idx.to_string());
        // Inherit SWIFT_CONF / RUST_LOG / etc. from the parent environment.
        children.push(cmd.spawn()?);
    }
    let mut worst = 0i32;
    for mut child in children {
        match child.wait() {
            Ok(status) => {
                let code = status.code().unwrap_or(1);
                if code != 0 && worst == 0 {
                    worst = code;
                }
            }
            Err(_) => {
                if worst == 0 {
                    worst = 1;
                }
            }
        }
    }
    Ok(Some(worst))
}

/// Bind `servers_per_port` listeners per port (REUSEPORT when N>1).
/// Used by children (N=1) and by unit tests of the bind helper.
pub fn bind_acceptors(
    bind_ip: &str,
    ports: &[u16],
    servers_per_port: usize,
) -> std::io::Result<Vec<std::net::TcpListener>> {
    let n = servers_per_port.max(1);
    let reuse = n > 1;
    let mut out = Vec::with_capacity(ports.len().saturating_mul(n));
    for &port in ports {
        for _ in 0..n {
            let addr = format!("{bind_ip}:{port}");
            out.push(swift_http::bind_listener(&addr, reuse)?);
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConcurrencyInputs {
    pub workers: usize,
    pub max_clients: usize,
    pub servers_per_port: usize,
    pub bind_ports: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveConcurrency {
    pub worker_threads: usize,
    pub connection_queue: usize,
    pub acceptors: usize,
    pub formula: &'static str,
    pub notes: Vec<&'static str>,
}

/// Map conf knobs → Rust `ServerConfig` sizing.
///
/// When `servers_per_port>0`, each OS child owns one acceptor; per-process
/// `worker_threads` = `max_clients` (clamped). Aggregate concurrency across
/// children ≈ `servers_per_port * n_ports * max_clients` (Python parity).
pub fn effective_concurrency(input: ConcurrencyInputs) -> EffectiveConcurrency {
    let max_clients = input.max_clients.max(1);
    let mut notes = Vec::new();

    if input.servers_per_port > 0 {
        let n_ports = input.bind_ports.max(1);
        let acceptors = input.servers_per_port.saturating_mul(n_ports).max(1);
        notes.push("servers_per_port>0: workers knob ignored (Python parity)");
        notes.push("Rust Wave2: one OS process per (port, worker) — process-isolated");
        // Per-process pool: max_clients threads (cap 128). Aggregate across
        // children matches Python green concurrency product.
        let worker_threads = max_clients.clamp(1, WORKER_THREADS_CAP);
        if max_clients > WORKER_THREADS_CAP {
            notes.push("per-process worker_threads clamped to 128");
        }
        notes.push("aggregate ≈ servers_per_port * n_ports * max_clients across children");
        return EffectiveConcurrency {
            worker_threads,
            connection_queue: max_clients,
            acceptors,
            formula: "per-process: max_clients → worker_threads; children = spp * n_ports",
            notes,
        };
    }

    if input.workers > 0 {
        notes.push("Rust maps workers*max_clients → worker_threads (NOT prefork processes)");
        let product = input.workers.saturating_mul(max_clients);
        let worker_threads = product.clamp(1, WORKER_THREADS_CAP);
        if product > WORKER_THREADS_CAP {
            notes.push("worker_threads clamped to 128");
        }
        return EffectiveConcurrency {
            worker_threads,
            connection_queue: max_clients,
            acceptors: 1,
            formula: "workers * max_clients → worker_threads (cap 128)",
            notes,
        };
    }

    let cpus = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4);
    let worker_threads = cpus.saturating_mul(16).clamp(16, WORKER_THREADS_CAP);
    notes.push("workers=0: use ServerConfig default (cpus*16, clamp 16..128)");
    EffectiveConcurrency {
        worker_threads,
        connection_queue: max_clients,
        acceptors: 1,
        formula: "default: cpus*16 → worker_threads (clamp 16..128)",
        notes,
    }
}

/// Compact JSON for calibration tooling (no serde dep).
pub fn effective_concurrency_json(input: ConcurrencyInputs) -> String {
    let e = effective_concurrency(input);
    let notes = e
        .notes
        .iter()
        .map(|n| format!("\"{}\"", n.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\n  \"workers\": {},\n  \"max_clients\": {},\n  \"servers_per_port\": {},\n  \"bind_ports\": {},\n  \"worker_threads\": {},\n  \"connection_queue\": {},\n  \"acceptors\": {},\n  \"formula\": \"{}\",\n  \"notes\": [{}]\n}}\n",
        input.workers,
        input.max_clients,
        input.servers_per_port,
        input.bind_ports,
        e.worker_threads,
        e.connection_queue,
        e.acceptors,
        e.formula,
        notes
    )
}

pub fn default_swift_dir() -> PathBuf {
    std::env::var("SWIFT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/swift"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use swift_ring::{RingBuilder, RingDevice};

    #[test]
    fn ports_for_local_devs_filters_by_ip() {
        let data = RingData::from_parts(
            vec![
                Some(RingDevice {
                    id: 0,
                    region: 1,
                    zone: 1,
                    ip: "127.0.0.1".into(),
                    port: 6200,
                    replication_ip: None,
                    replication_port: None,
                    device: "d1".into(),
                    weight: 100.0,
                    meta: String::new(),
                    extra: Default::default(),
                }),
                Some(RingDevice {
                    id: 1,
                    region: 1,
                    zone: 1,
                    ip: "127.0.0.1".into(),
                    port: 6201,
                    replication_ip: None,
                    replication_port: None,
                    device: "d2".into(),
                    weight: 100.0,
                    meta: String::new(),
                    extra: Default::default(),
                }),
                Some(RingDevice {
                    id: 2,
                    region: 1,
                    zone: 2,
                    ip: "192.0.2.9".into(),
                    port: 6200,
                    replication_ip: None,
                    replication_port: None,
                    device: "d1".into(),
                    weight: 100.0,
                    meta: String::new(),
                    extra: Default::default(),
                }),
            ],
            28,
            vec![vec![0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0]],
        );
        let mut mine = BTreeSet::new();
        mine.insert("127.0.0.1".into());
        assert_eq!(
            ports_for_local_devs(&data, &mine),
            BTreeSet::from([6200, 6201])
        );
    }

    #[test]
    fn discover_reads_ports_from_ring_files() {
        let dir = tempfile_dir();
        let mut b = RingBuilder::new(4, 1.0);
        b.add_dev(1, 1, "127.0.0.1", 16200, "d1", 100.0);
        b.add_dev(1, 1, "127.0.0.1", 16201, "d2", 100.0);
        b.rebalance().unwrap();
        b.to_ring_data()
            .save_v1(&dir.join("object.ring.gz"))
            .unwrap();
        let ports = discover_servers_per_port_binds(&dir, "127.0.0.1");
        assert_eq!(ports, BTreeSet::from([16200, 16201]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn listen_ports_fallback_when_empty() {
        let dir = tempfile_dir();
        assert_eq!(listen_ports(&dir, "127.0.0.1", 6200), vec![6200]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn effective_concurrency_workers_times_max_clients_clamps_at_128() {
        let e = effective_concurrency(ConcurrencyInputs {
            workers: 4,
            max_clients: 1024,
            servers_per_port: 0,
            bind_ports: 1,
        });
        assert_eq!(e.worker_threads, 128);
        assert_eq!(e.acceptors, 1);
        assert!(e.notes.iter().any(|n| n.contains("NOT prefork")));
        assert!(e.notes.iter().any(|n| n.contains("clamped to 128")));
    }

    #[test]
    fn effective_concurrency_workers_product_uncapped_when_small() {
        let e = effective_concurrency(ConcurrencyInputs {
            workers: 2,
            max_clients: 32,
            servers_per_port: 0,
            bind_ports: 1,
        });
        assert_eq!(e.worker_threads, 64);
        assert_eq!(e.connection_queue, 32);
        assert_eq!(e.acceptors, 1);
        assert_eq!(e.formula, "workers * max_clients → worker_threads (cap 128)");
        assert!(e.notes.iter().any(|n| n.contains("NOT prefork")));
    }

    #[test]
    fn effective_concurrency_workers_zero_uses_cpu_default() {
        let e = effective_concurrency(ConcurrencyInputs {
            workers: 0,
            max_clients: 1024,
            servers_per_port: 0,
            bind_ports: 1,
        });
        let cpus = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(4);
        let expect = cpus.saturating_mul(16).clamp(16, WORKER_THREADS_CAP);
        assert_eq!(e.worker_threads, expect);
        assert_eq!(e.acceptors, 1);
        assert_eq!(e.connection_queue, 1024);
        assert!(e.notes.iter().any(|n| n.contains("workers=0")));
        assert!(e.formula.contains("cpus*16"));
    }

    #[test]
    fn effective_concurrency_spp_gt_zero_ignores_workers() {
        let e = effective_concurrency(ConcurrencyInputs {
            workers: 99,
            max_clients: 8,
            servers_per_port: 2,
            bind_ports: 3,
        });
        assert_eq!(e.acceptors, 6);
        // Per-process pool sized to max_clients (not product).
        assert_eq!(e.worker_threads, 8);
        assert_eq!(e.connection_queue, 8);
        assert!(e.notes.iter().any(|n| n.contains("workers knob ignored")));
        assert!(e.notes.iter().any(|n| n.contains("process-isolated")));
        assert!(e.formula.contains("spp * n_ports"));
    }

    #[test]
    fn effective_concurrency_spp_one_clamps_max_clients() {
        // Contabo-like: spp=1, max_clients=1024 → per-process 128 (clamped).
        let e = effective_concurrency(ConcurrencyInputs {
            workers: 0,
            max_clients: 1024,
            servers_per_port: 1,
            bind_ports: 1,
        });
        assert_eq!(e.worker_threads, 128);
        assert_eq!(e.acceptors, 1);
        assert!(e.notes.iter().any(|n| n.contains("clamped to 128")));
    }

    #[test]
    fn effective_concurrency_max_clients_zero_treated_as_one() {
        let e = effective_concurrency(ConcurrencyInputs {
            workers: 3,
            max_clients: 0,
            servers_per_port: 0,
            bind_ports: 1,
        });
        assert_eq!(e.worker_threads, 3);
        assert_eq!(e.connection_queue, 1);
    }

    #[test]
    fn port_worker_plan_covers_ports_times_spp() {
        assert_eq!(
            port_worker_plan(&[6200, 6201, 6202], 2),
            vec![
                (6200, 0),
                (6200, 1),
                (6201, 0),
                (6201, 1),
                (6202, 0),
                (6202, 1),
            ]
        );
    }

    #[test]
    fn bind_acceptors_reuseport_when_n_gt_1() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let listeners = bind_acceptors("127.0.0.1", &[port], 2).expect("bind");
        assert_eq!(listeners.len(), 2);
    }

    #[test]
    fn json_shape() {
        let s = effective_concurrency_json(ConcurrencyInputs {
            workers: 1,
            max_clients: 16,
            servers_per_port: 0,
            bind_ports: 1,
        });
        assert!(s.contains("\"worker_threads\": 16"));
    }

    fn tempfile_dir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "swift-spp-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
