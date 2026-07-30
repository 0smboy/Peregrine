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

//! `swift-ring-builder <ring.gz> create <part_power> <replicas>`
//! `swift-ring-builder <ring.gz> add r<R>z<Z>-<ip>:<port>[R<rip>:<rport>]/<dev> <weight>`
//! `swift-ring-builder <ring.gz> rebalance`
//!
//! The optional `R<rip>:<rport>` sets the device's replication-network
//! endpoint (Python swift-ring-builder's replication syntax); without it
//! replication falls back to ip:port.
//!
//! A minimal builder CLI over swift_ring::RingBuilder. The builder state
//! is kept as a sidecar JSON next to the ring file (the Python .builder
//! is a pickle; ours is JSON — not interchangeable, documented).

use std::path::Path;

use swift_ring::RingBuilder;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: swift-ring-builder <ring.gz> <create|add|rebalance> ...");
        std::process::exit(1);
    }
    let ring_path = &args[0];
    let cmd = &args[1];
    let state_path = format!("{ring_path}.builder.json");

    match cmd.as_str() {
        "create" => {
            let part_power: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10);
            let replicas: f64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3.0);
            let state = BuilderState {
                part_power,
                replicas,
                devices: Vec::new(),
            };
            state.save(&state_path);
            println!("created builder: part_power={part_power} replicas={replicas}");
        }
        "add" => {
            // r<R>z<Z>-<ip>:<port>/<dev>  <weight>
            let spec = args.get(2).cloned().unwrap_or_default();
            let weight: f64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(100.0);
            let mut state = BuilderState::load(&state_path);
            let dev = parse_device_spec(&spec, weight).unwrap_or_else(|| {
                eprintln!("bad device spec: {spec} (expected r1z1-10.0.0.1:6200/sda)");
                std::process::exit(1);
            });
            println!("added device {}", state.devices.len());
            state.devices.push(dev);
            state.save(&state_path);
        }
        "rebalance" => {
            let state = BuilderState::load(&state_path);
            let mut builder = RingBuilder::new(state.part_power, state.replicas);
            for d in &state.devices {
                builder.add_dev_full(
                    d.region,
                    d.zone,
                    &d.ip,
                    d.port,
                    d.replication_ip.as_deref(),
                    d.replication_port,
                    &d.device,
                    d.weight,
                );
            }
            match builder.rebalance() {
                Ok(()) => {
                    builder
                        .to_ring_data()
                        .save_v1(Path::new(ring_path))
                        .unwrap_or_else(|e| {
                            eprintln!("save failed: {e}");
                            std::process::exit(1);
                        });
                    println!("rebalanced and wrote {ring_path}");
                }
                Err(e) => {
                    eprintln!("rebalance failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("unknown command {other}");
            std::process::exit(1);
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DevSpec {
    region: u64,
    zone: u64,
    ip: String,
    port: u32,
    #[serde(default)]
    replication_ip: Option<String>,
    #[serde(default)]
    replication_port: Option<u32>,
    device: String,
    weight: f64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct BuilderState {
    part_power: u32,
    replicas: f64,
    devices: Vec<DevSpec>,
}

impl BuilderState {
    fn load(path: &str) -> Self {
        serde_json::from_slice(&std::fs::read(path).unwrap_or_else(|_| {
            eprintln!("no builder state at {path}; run create first");
            std::process::exit(1);
        }))
        .unwrap()
    }
    fn save(&self, path: &str) {
        std::fs::write(path, serde_json::to_vec_pretty(self).unwrap()).unwrap();
    }
}

fn parse_device_spec(spec: &str, weight: f64) -> Option<DevSpec> {
    // r1z1-10.0.0.1:6200/sda  or  r1z1-10.0.0.1:6200R172.19.1.1:6200/sda
    let (rz, rest) = spec.split_once('-')?;
    let rz = rz.strip_prefix('r')?;
    let (region, zone) = rz.split_once('z')?;
    let (hostport, device) = rest.split_once('/')?;
    let (hostport, replication) = match hostport.split_once('R') {
        Some((main, repl)) => (main, Some(repl)),
        None => (hostport, None),
    };
    let (ip, port) = hostport.rsplit_once(':')?;
    let (replication_ip, replication_port) = match replication {
        Some(r) => {
            let (rip, rport) = r.rsplit_once(':')?;
            (Some(rip.to_string()), Some(rport.parse().ok()?))
        }
        None => (None, None),
    };
    Some(DevSpec {
        region: region.parse().ok()?,
        zone: zone.parse().ok()?,
        ip: ip.to_string(),
        port: port.parse().ok()?,
        replication_ip,
        replication_port,
        device: device.to_string(),
        weight,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_and_replication_specs() {
        let d = parse_device_spec("r1z2-172.18.1.3:6200/sdb1", 100.0).unwrap();
        assert_eq!((d.region, d.zone), (1, 2));
        assert_eq!((d.ip.as_str(), d.port), ("172.18.1.3", 6200));
        assert_eq!(d.replication_ip, None);

        let d = parse_device_spec("r1z2-172.18.1.3:6200R172.19.1.3:6200/d1", 100.0).unwrap();
        assert_eq!((d.ip.as_str(), d.port), ("172.18.1.3", 6200));
        assert_eq!(d.replication_ip.as_deref(), Some("172.19.1.3"));
        assert_eq!(d.replication_port, Some(6200));
        assert_eq!(d.device, "d1");
    }
}
