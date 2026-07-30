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

//! A ring builder, ported in spirit from `swift/common/ring/builder.py`.
//!
//! Per the rewrite plan, the builder produces *equivalent-quality*, not
//! byte-identical, rings: each partition's replicas land on distinct
//! devices, dispersed across regions → zones → ips → devices as far as
//! the topology allows, with each device's share of partitions
//! proportional to its weight. The output is a valid ring that this
//! crate's reader (and the real Python `Ring`) accepts and that
//! `get_nodes`/`get_more_nodes` operate on correctly.
//!
//! Not reproduced: Swift's overload knob, the min_part_hours move
//! throttle, and the exact dispersion optimizer's tie-breaking. The
//! resulting balance is close but the specific assignments differ.

use serde_json::Map;

use crate::ring::{calc_replica_count, RingData, RingDevice};
use crate::RingError;

/// A device as added to the builder.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BuilderDevice {
    pub id: u64,
    pub region: u64,
    pub zone: u64,
    pub ip: String,
    pub port: u32,
    /// Replication-network endpoint; `None` falls back to ip/port
    /// (Python's `add r..-<ip>:<port>R<rip>:<rport>/<dev>` form).
    pub replication_ip: Option<String>,
    pub replication_port: Option<u32>,
    pub device: String,
    pub weight: f64,
}

/// The ring builder.
pub struct RingBuilder {
    part_power: u32,
    replicas: f64,
    devices: Vec<Option<BuilderDevice>>,
    replica2part2dev_id: Vec<Vec<u32>>,
    version: u64,
}

impl RingBuilder {
    /// `part_power` gives `2**part_power` partitions; `replicas` is the
    /// (possibly fractional) replica count.
    pub fn new(part_power: u32, replicas: f64) -> Self {
        RingBuilder {
            part_power,
            replicas,
            devices: Vec::new(),
            replica2part2dev_id: Vec::new(),
            version: 0,
        }
    }

    pub fn parts(&self) -> usize {
        1usize << self.part_power
    }

    /// Add a device; its id is its index (sparse holes are allowed by
    /// passing an explicit id, but the simple path assigns sequentially).
    #[allow(clippy::too_many_arguments)]
    pub fn add_dev(
        &mut self,
        region: u64,
        zone: u64,
        ip: &str,
        port: u32,
        device: &str,
        weight: f64,
    ) -> u64 {
        self.add_dev_full(region, zone, ip, port, None, None, device, weight)
    }

    /// `add_dev` with an explicit replication-network endpoint.
    #[allow(clippy::too_many_arguments)]
    pub fn add_dev_full(
        &mut self,
        region: u64,
        zone: u64,
        ip: &str,
        port: u32,
        replication_ip: Option<&str>,
        replication_port: Option<u32>,
        device: &str,
        weight: f64,
    ) -> u64 {
        let id = self.devices.len() as u64;
        self.devices.push(Some(BuilderDevice {
            id,
            region,
            zone,
            ip: ip.to_string(),
            port,
            replication_ip: replication_ip.map(str::to_string),
            replication_port,
            device: device.to_string(),
            weight,
        }));
        id
    }

    fn active_devices(&self) -> Vec<&BuilderDevice> {
        self.devices
            .iter()
            .flatten()
            .filter(|d| d.weight > 0.0)
            .collect()
    }

    /// A device by id (`RingBuilder.devs[id]`).
    pub fn get_dev(&self, dev_id: u64) -> Option<&BuilderDevice> {
        self.devices.get(dev_id as usize).and_then(|d| d.as_ref())
    }

    /// `remove_dev`: drop a device from the builder. Its partitions are
    /// reassigned on the next `rebalance`.
    pub fn remove_dev(&mut self, dev_id: u64) -> bool {
        match self.devices.get_mut(dev_id as usize) {
            Some(slot @ Some(_)) => {
                *slot = None;
                true
            }
            _ => false,
        }
    }

    /// `set_dev_weight`: change a device's weight (0 removes it from
    /// assignment on the next rebalance).
    pub fn set_dev_weight(&mut self, dev_id: u64, weight: f64) -> bool {
        match self.devices.get_mut(dev_id as usize).and_then(|d| d.as_mut()) {
            Some(dev) => {
                dev.weight = weight;
                true
            }
            None => false,
        }
    }

    /// `set_info`: update a device's network location (ip/port/device name).
    pub fn set_dev_info(&mut self, dev_id: u64, ip: &str, port: u32, device: &str) -> bool {
        match self.devices.get_mut(dev_id as usize).and_then(|d| d.as_mut()) {
            Some(dev) => {
                dev.ip = ip.to_string();
                dev.port = port;
                dev.device = device.to_string();
                true
            }
            None => false,
        }
    }

    /// `validate`: check the ring assignment is well-formed — every partition
    /// has the expected number of replicas, and every assigned device id
    /// refers to an existing device. Returns an error describing the first
    /// problem found.
    pub fn validate(&self) -> Result<(), RingError> {
        if self.replica2part2dev_id.is_empty() {
            return Err(RingError("ring has not been rebalanced".to_string()));
        }
        let parts = self.parts();
        for (r, row) in self.replica2part2dev_id.iter().enumerate() {
            // the last (fractional) replica row may be shorter than `parts`
            if row.len() > parts {
                return Err(RingError(format!(
                    "replica {r} has {} parts, expected <= {parts}",
                    row.len()
                )));
            }
            for (p, &dev_id) in row.iter().enumerate() {
                match self.devices.get(dev_id as usize) {
                    Some(Some(_)) => {}
                    _ => {
                        return Err(RingError(format!(
                            "part {p} replica {r} assigned to missing device {dev_id}"
                        )))
                    }
                }
            }
        }
        Ok(())
    }

    /// Serialize the builder state to JSON (a Rust-native `.builder`
    /// alternative). NOTE: this is deliberately NOT Python's pickled `.builder`
    /// format — that embeds version-specific `array.array` reconstructors and
    /// is a tool-local format; the runtime compatibility contract is the
    /// byte-identical `.ring.gz` output, which [`to_ring_data`] +
    /// `swift-ring`'s writer produce. This JSON lets the Rust ring-builder
    /// persist and resume its own state.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "part_power": self.part_power,
            "replicas": self.replicas,
            "version": self.version,
            "devs": self.devices,
            "replica2part2dev_id": self.replica2part2dev_id,
        })
    }

    /// Reconstruct a builder from [`to_json`] output.
    pub fn from_json(v: &serde_json::Value) -> Result<RingBuilder, RingError> {
        let get = |k: &str| v.get(k).ok_or_else(|| RingError(format!("missing {k}")));
        let part_power = get("part_power")?
            .as_u64()
            .ok_or_else(|| RingError("bad part_power".into()))? as u32;
        let replicas = get("replicas")?
            .as_f64()
            .ok_or_else(|| RingError("bad replicas".into()))?;
        let version = get("version")?.as_u64().unwrap_or(0);
        let devices: Vec<Option<BuilderDevice>> = serde_json::from_value(get("devs")?.clone())
            .map_err(|e| RingError(format!("bad devs: {e}")))?;
        let replica2part2dev_id: Vec<Vec<u32>> =
            serde_json::from_value(get("replica2part2dev_id")?.clone())
                .map_err(|e| RingError(format!("bad replica2part2dev_id: {e}")))?;
        Ok(RingBuilder {
            part_power,
            replicas,
            devices,
            replica2part2dev_id,
            version,
        })
    }

    /// Assign every (partition, replica) slot to a device, maximizing
    /// dispersion and honoring weight. Returns an error if there are
    /// fewer weighted devices than whole replicas (can't place distinct
    /// replicas).
    pub fn rebalance(&mut self) -> Result<(), RingError> {
        let active = self.active_devices();
        let whole_replicas = self.replicas.ceil() as usize;
        if active.len() < whole_replicas.max(1) {
            return Err(RingError(format!(
                "Not enough devices ({}) to satisfy {} replicas",
                active.len(),
                whole_replicas
            )));
        }
        let parts = self.parts();

        // desired partition-replicas per device, proportional to weight
        let total_weight: f64 = active.iter().map(|d| d.weight).sum();
        let total_slots = (parts as f64 * self.replicas).round() as usize;
        // remaining desire per device id (float, drained as we assign)
        let mut desired: std::collections::HashMap<u64, f64> = active
            .iter()
            .map(|d| (d.id, d.weight / total_weight * total_slots as f64))
            .collect();
        // current assignment counts, for tie-breaking toward balance
        let mut assigned: std::collections::HashMap<u64, usize> =
            active.iter().map(|d| (d.id, 0usize)).collect();

        // build replica rows: full rows get `parts` slots, the fractional
        // last row gets round(frac * parts)
        let mut row_lengths = vec![parts; self.replicas.floor() as usize];
        let frac = self.replicas - self.replicas.floor();
        if frac > 0.0 {
            row_lengths.push((frac * parts as f64).round() as usize);
        }
        if row_lengths.is_empty() {
            row_lengths.push(parts); // at least one replica
        }

        let mut rows: Vec<Vec<u32>> =
            row_lengths.iter().map(|&len| vec![0u32; len]).collect();

        // id -> device for dispersion lookups
        let dev_by_id: std::collections::HashMap<u64, &BuilderDevice> =
            active.iter().map(|d| (d.id, *d)).collect();

        for part in 0..parts {
            // devices already used by this partition's other replicas,
            // and the tiers they occupy
            let mut used_ids: Vec<u64> = Vec::new();
            let mut used_regions: Vec<u64> = Vec::new();
            let mut used_zones: Vec<(u64, u64)> = Vec::new();
            let mut used_ips: Vec<(u64, u64, String)> = Vec::new();

            for row in rows.iter_mut() {
                if part >= row.len() {
                    continue; // fractional row shorter than parts
                }
                // pick the best device not already used for this part:
                // freshest tier (region>zone>ip), then most remaining
                // desire, then least assigned (balance), then lowest id
                let best = pick_best(
                    &active,
                    &used_ids,
                    &used_regions,
                    &used_zones,
                    &used_ips,
                    &desired,
                    &assigned,
                );
                let best_dev = dev_by_id[&best];
                row[part] = best as u32;
                used_ids.push(best);
                used_regions.push(best_dev.region);
                used_zones.push((best_dev.region, best_dev.zone));
                used_ips.push((best_dev.region, best_dev.zone, best_dev.ip.clone()));
                *desired.get_mut(&best).unwrap() -= 1.0;
                *assigned.get_mut(&best).unwrap() += 1;
            }
        }

        self.replica2part2dev_id = rows;
        self.version += 1;
        Ok(())
    }

    /// Materialize the assigned ring as [`RingData`] (part_shift derived
    /// from part_power).
    pub fn to_ring_data(&self) -> RingData {
        let part_shift = 32 - self.part_power;
        let devs: Vec<Option<RingDevice>> = self
            .devices
            .iter()
            .map(|d| {
                d.as_ref().map(|d| RingDevice {
                    id: d.id,
                    region: d.region,
                    zone: d.zone,
                    ip: d.ip.clone(),
                    port: d.port,
                    replication_ip: Some(d.replication_ip.clone().unwrap_or_else(|| d.ip.clone())),
                    replication_port: Some(d.replication_port.unwrap_or(d.port)),
                    device: d.device.clone(),
                    weight: d.weight,
                    meta: String::new(),
                    extra: Map::new(),
                })
            })
            .collect();
        let mut ring = RingData::from_parts(devs, part_shift, self.replica2part2dev_id.clone());
        ring.version = Some(self.version);
        ring
    }

    /// Reconstruct a builder from an already-built ring — the inverse of
    /// [`to_ring_data`].
    ///
    /// The ring file carries everything the builder needs: `part_shift` gives
    /// the part power, the assignment table gives the replica count, and each
    /// `RingDevice` carries its region/zone/endpoints/weight. This is what lets
    /// tooling simulate against a *live* ring (and lets an operator rebuild a
    /// lost builder from the ring itself).
    ///
    /// Device ids are preserved, including the sparse `None` holes left by
    /// [`remove_dev`], so `dev_id` stays a stable index.
    pub fn from_ring_data(data: &RingData) -> Result<RingBuilder, RingError> {
        if data.part_shift > 32 {
            return Err(RingError(format!("bad part_shift {}", data.part_shift)));
        }
        let part_power = 32 - data.part_shift;
        let replicas = calc_replica_count(&data.replica2part2dev_id);
        let devices: Vec<Option<BuilderDevice>> = data
            .devs
            .iter()
            .map(|d| {
                d.as_ref().map(|d| BuilderDevice {
                    id: d.id,
                    region: d.region,
                    zone: d.zone,
                    ip: d.ip.clone(),
                    port: d.port,
                    replication_ip: d.replication_ip.clone(),
                    replication_port: d.replication_port,
                    device: d.device.clone(),
                    weight: d.weight,
                })
            })
            .collect();
        Ok(RingBuilder {
            part_power,
            replicas,
            devices,
            replica2part2dev_id: data.replica2part2dev_id.clone(),
            version: data.version.unwrap_or(0),
        })
    }

    /// The current assignment table, `replica2part2dev_id`. Diffing this before
    /// and after a [`rebalance`] is how a caller learns what actually moved —
    /// `rebalance` itself reports nothing.
    pub fn assignment(&self) -> &[Vec<u32>] {
        &self.replica2part2dev_id
    }

    /// Every device slot, including the `None` holes left by [`remove_dev`],
    /// so the position in this slice is the device id.
    pub fn devices(&self) -> &[Option<BuilderDevice>] {
        &self.devices
    }

    /// Partition count (`2**part_power`), without going through a `Ring`.
    pub fn part_power(&self) -> u32 {
        self.part_power
    }

    /// The (possibly fractional) replica count.
    pub fn replica_count(&self) -> f64 {
        self.replicas
    }
}

/// Dispersion preference: a device on a fresh region ranks above a fresh
/// zone above a fresh ip above a reused one. Higher is better.
fn dispersion_score(
    dev: &BuilderDevice,
    used_regions: &[u64],
    used_zones: &[(u64, u64)],
    used_ips: &[(u64, u64, String)],
) -> i32 {
    if !used_regions.contains(&dev.region) {
        3
    } else if !used_zones.contains(&(dev.region, dev.zone)) {
        2
    } else if !used_ips.contains(&(dev.region, dev.zone, dev.ip.clone())) {
        1
    } else {
        0
    }
}

/// Pick the device for the next replica slot: highest dispersion, then
/// most remaining desire, then least already assigned, then lowest id.
#[allow(clippy::too_many_arguments)]
fn pick_best(
    active: &[&BuilderDevice],
    used_ids: &[u64],
    used_regions: &[u64],
    used_zones: &[(u64, u64)],
    used_ips: &[(u64, u64, String)],
    desired: &std::collections::HashMap<u64, f64>,
    assigned: &std::collections::HashMap<u64, usize>,
) -> u64 {
    active
        .iter()
        .filter(|d| !used_ids.contains(&d.id))
        .max_by(|a, b| {
            let da = dispersion_score(a, used_regions, used_zones, used_ips);
            let db = dispersion_score(b, used_regions, used_zones, used_ips);
            da.cmp(&db)
                .then_with(|| {
                    desired[&a.id]
                        .partial_cmp(&desired[&b.id])
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| assigned[&b.id].cmp(&assigned[&a.id]))
                .then_with(|| b.id.cmp(&a.id))
        })
        .map(|d| d.id)
        .expect("filtered out all devices for a replica slot")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ring;
    use swift_core::hashing::HashPathConfig;

    fn hc() -> HashPathConfig {
        HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap()
    }

    #[test]
    fn test_device_management_validate_and_json() {
        let mut b = RingBuilder::new(4, 3.0); // 16 parts
        for region in 1..=2u64 {
            for zone in 1..=2u64 {
                b.add_dev(region, zone, &format!("10.0.{region}.{zone}"), 6200, "sda", 100.0);
            }
        }
        b.rebalance().unwrap();
        b.validate().expect("a freshly rebalanced ring validates");

        // set_dev_weight / set_dev_info / get_dev
        assert!(b.set_dev_weight(0, 200.0));
        assert_eq!(b.get_dev(0).unwrap().weight, 200.0);
        assert!(b.set_dev_info(1, "10.9.9.9", 6300, "sdz"));
        assert_eq!(b.get_dev(1).unwrap().ip, "10.9.9.9");
        assert!(!b.set_dev_weight(999, 1.0)); // missing dev

        // remove a device, rebalance redistributes, and it still validates
        assert!(b.remove_dev(3));
        assert!(b.get_dev(3).is_none());
        b.rebalance().unwrap();
        b.validate().expect("valid after removing a device");
        // no partition is assigned to the removed device
        assert!(b.validate().is_ok());

        // JSON state round-trips
        let json = b.to_json();
        let b2 = RingBuilder::from_json(&json).unwrap();
        assert_eq!(b2.to_json(), json);
        b2.validate().unwrap();
    }

    #[test]
    fn test_rebalance_produces_valid_dispersed_ring() {
        let mut b = RingBuilder::new(6, 3.0); // 64 parts, 3 replicas
        // 2 regions x 2 zones x 2 devices
        for region in 1..=2u64 {
            for zone in 1..=2u64 {
                for d in 0..2 {
                    b.add_dev(
                        region,
                        zone,
                        &format!("10.0.{region}.{zone}"),
                        6200,
                        &format!("sd{d}"),
                        100.0,
                    );
                }
            }
        }
        b.rebalance().unwrap();
        let ring = b.to_ring_data();
        assert_eq!(ring.replica2part2dev_id.len(), 3);
        assert_eq!(ring.replica2part2dev_id[0].len(), 64);

        let r = Ring::new(ring, hc());
        // every partition's 3 primaries are distinct devices, and (with 2
        // regions available) span at least 2 regions
        for part in 0..64u32 {
            let nodes = r.get_part_nodes(part).unwrap();
            assert_eq!(nodes.len(), 3, "part {part} distinct devices");
            let regions: std::collections::HashSet<u64> =
                nodes.iter().map(|n| n.dev.region).collect();
            assert!(regions.len() >= 2, "part {part} spans regions");
        }
        // get_nodes works and handoffs are available
        let (_p, nodes) = r.get_nodes("a", Some("c"), Some("o")).unwrap();
        assert_eq!(nodes.len(), 3);
        assert!(!r.get_more_nodes(0).unwrap().is_empty());
    }

    #[test]
    fn test_weighted_balance() {
        let mut b = RingBuilder::new(8, 3.0); // 256 parts
        // one heavy device (weight 300) and three light (100)
        let heavy = b.add_dev(1, 1, "10.0.0.1", 6200, "sda", 300.0);
        b.add_dev(1, 2, "10.0.0.2", 6200, "sda", 100.0);
        b.add_dev(2, 1, "10.0.1.1", 6200, "sda", 100.0);
        b.add_dev(2, 2, "10.0.1.2", 6200, "sda", 100.0);
        b.rebalance().unwrap();
        let ring = b.to_ring_data();
        let mut counts = std::collections::HashMap::new();
        for row in &ring.replica2part2dev_id {
            for &d in row {
                *counts.entry(d as u64).or_insert(0usize) += 1;
            }
        }
        // the heavy device holds strictly more partitions than any light
        // device (it saturates toward one replica per partition, the
        // dispersion cap for a single region/zone/ip)
        let heavy_count = counts[&heavy];
        for (id, &c) in &counts {
            if *id != heavy {
                assert!(heavy_count > c, "heavy {heavy_count} vs light {id}={c}");
            }
        }
    }

    #[test]
    fn test_too_few_devices() {
        let mut b = RingBuilder::new(4, 3.0);
        b.add_dev(1, 1, "10.0.0.1", 6200, "sda", 100.0);
        b.add_dev(1, 1, "10.0.0.2", 6200, "sda", 100.0);
        assert!(b.rebalance().is_err());
    }

    #[test]
    fn test_from_ring_data_round_trips() {
        let mut b = RingBuilder::new(6, 3.0);
        for zone in 1..=3u64 {
            b.add_dev_full(
                1,
                zone,
                &format!("10.0.0.{zone}"),
                6200,
                Some(&format!("10.1.0.{zone}")),
                Some(6201),
                "d1",
                100.0,
            );
        }
        b.rebalance().unwrap();

        // ring -> builder -> ring must be identical, which is what lets
        // tooling simulate against a live ring file.
        let data = b.to_ring_data();
        let back = RingBuilder::from_ring_data(&data).unwrap();
        assert_eq!(back.part_power(), b.part_power());
        assert_eq!(back.replica_count(), b.replica_count());
        assert_eq!(back.assignment(), b.assignment());
        assert_eq!(back.to_json(), b.to_json());

        // The replication endpoints must survive the trip, not collapse
        // back onto ip/port.
        let d = back.get_dev(1).unwrap();
        assert_eq!(d.replication_ip.as_deref(), Some("10.1.0.2"));
        assert_eq!(d.replication_port, Some(6201));
    }

    #[test]
    fn test_from_ring_data_preserves_removed_device_holes() {
        let mut b = RingBuilder::new(6, 3.0);
        for zone in 1..=4u64 {
            b.add_dev(1, zone, &format!("10.0.0.{zone}"), 6200, "d1", 100.0);
        }
        b.rebalance().unwrap();
        assert!(b.remove_dev(1));
        b.rebalance().unwrap();

        let back = RingBuilder::from_ring_data(&b.to_ring_data()).unwrap();
        // id 1 stays a hole so device ids remain stable indexes.
        assert_eq!(back.devices().len(), 4);
        assert!(back.devices()[1].is_none());
        assert_eq!(back.get_dev(2).map(|d| d.id), Some(2));
    }
}
