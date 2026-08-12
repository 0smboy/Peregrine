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

//! Ring data structures and lookup, ported from
//! `swift/common/ring/ring.py`.

use std::collections::HashSet;
use std::path::Path;

use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::io::{be_u32, RingFile};
use crate::RingError;
use swift_core::hashing::HashPathConfig;

/// A device in the ring. Unknown JSON keys are preserved in `extra` so
/// that round-tripping does not lose information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RingDevice {
    pub id: u64,
    pub region: u64,
    pub zone: u64,
    pub ip: String,
    pub port: u32,
    #[serde(default)]
    pub replication_ip: Option<String>,
    #[serde(default)]
    pub replication_port: Option<u32>,
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub weight: f64,
    #[serde(default)]
    pub meta: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Number of replicas (full or partial) represented by a
/// replica-to-part-to-device table (Python `calc_replica_count`).
pub fn calc_replica_count(replica2part2dev_id: &[Vec<u32>]) -> f64 {
    if replica2part2dev_id.is_empty() {
        return 0.0;
    }
    let base = (replica2part2dev_id.len() - 1) as f64;
    let extra = replica2part2dev_id[replica2part2dev_id.len() - 1].len() as f64
        / replica2part2dev_id[0].len() as f64;
    base + extra
}

/// Partitioned consistent hashing ring data (Python `RingData`).
#[derive(Debug, Clone)]
pub struct RingData {
    /// Devices, indexed by device id; unused ids are `None`.
    pub devs: Vec<Option<RingDevice>>,
    pub part_shift: u32,
    /// One row per (whole or partial) replica mapping partition to
    /// device id. Stored widened to u32 regardless of on-disk width.
    pub replica2part2dev_id: Vec<Vec<u32>>,
    pub next_part_power: Option<u32>,
    /// The ring *builder* version (monotonic counter), not the format.
    pub version: Option<u64>,
    /// The on-disk format version this was loaded from (1 or 2).
    pub format_version: u16,
    /// On-disk width of device ids in bytes (2 or 4).
    pub dev_id_bytes: u8,
    /// Compressed file size in bytes.
    pub size: u64,
    /// Uncompressed stream size in bytes.
    pub raw_size: u64,
    /// Replica count from metadata (used when loaded metadata-only).
    replica_count_meta: f64,
}

/// Set missing replication_ip/replication_port from ip/port (Python
/// `normalize_devices`).
fn normalize_devices(devs: &mut [Option<RingDevice>]) {
    for dev in devs.iter_mut().flatten() {
        if dev.replication_ip.is_none() {
            dev.replication_ip = Some(dev.ip.clone());
        }
        if dev.replication_port.is_none() {
            dev.replication_port = Some(dev.port);
        }
    }
}

impl RingData {
    /// Construct in-memory ring data (tests and tooling; file loading is
    /// the production path).
    pub fn from_parts(
        devs: Vec<Option<RingDevice>>,
        part_shift: u32,
        replica2part2dev_id: Vec<Vec<u32>>,
    ) -> Self {
        let mut devs = devs;
        normalize_devices(&mut devs);
        RingData {
            devs,
            part_shift,
            replica2part2dev_id,
            next_part_power: None,
            version: None,
            format_version: 2,
            dev_id_bytes: 2,
            size: 0,
            raw_size: 0,
            replica_count_meta: 0.0,
        }
    }

    /// Load ring data from a `.ring.gz` file (either format version).
    pub fn load(path: &Path) -> Result<Self, RingError> {
        Self::load_opts(path, false)
    }

    /// Load only device and metadata information, skipping the (large)
    /// assignment table (Python `metadata_only=True`).
    pub fn load_metadata_only(path: &Path) -> Result<Self, RingError> {
        Self::load_opts(path, true)
    }

    fn load_opts(path: &Path, metadata_only: bool) -> Result<Self, RingError> {
        let file = RingFile::open(path)?;
        let mut ring_data = match file.version {
            1 => Self::deserialize_v1(&file, metadata_only)?,
            2 => Self::deserialize_v2(&file, metadata_only)?,
            v => return Err(RingError(format!("Unknown ring format version {v}"))),
        };
        ring_data.format_version = file.version;
        ring_data.size = file.size;
        ring_data.raw_size = file.raw_size;
        normalize_devices(&mut ring_data.devs);
        Ok(ring_data)
    }

    fn parse_devs(devs_json: &Value) -> Result<Vec<Option<RingDevice>>, RingError> {
        let arr = devs_json
            .as_array()
            .ok_or_else(|| RingError("ring devs must be a list".to_string()))?;
        arr.iter()
            .map(|v| {
                if v.is_null() {
                    Ok(None)
                } else {
                    serde_json::from_value(v.clone())
                        .map(Some)
                        .map_err(|e| RingError(format!("Invalid ring device: {e}")))
                }
            })
            .collect()
    }

    /// Deserialize a v1 ring (Python `RingData.deserialize_v1`).
    fn deserialize_v1(file: &RingFile, metadata_only: bool) -> Result<Self, RingError> {
        let data = &file.data;
        if data.len() < 6 || &data[..6] != b"R1NG\x00\x01" {
            return Err(RingError(format!(
                "unexpected magic: {:?}",
                &data[..data.len().min(6)]
            )));
        }
        let json_len = be_u32(&data[6..10]) as usize;
        let meta: Value = serde_json::from_slice(&data[10..10 + json_len])?;
        let part_shift = meta["part_shift"]
            .as_u64()
            .ok_or_else(|| RingError("missing part_shift".to_string()))?
            as u32;
        let replica_count = meta["replica_count"]
            .as_u64()
            .ok_or_else(|| RingError("missing replica_count".to_string()))?;
        // v1 rows are written in the *builder's* native byte order,
        // recorded in the metadata; absent means "assume native", which
        // in practice means little-endian.
        let big_endian = meta
            .get("byteorder")
            .and_then(|v| v.as_str())
            .unwrap_or("little")
            == "big";

        let mut ring = RingData {
            devs: Self::parse_devs(&meta["devs"])?,
            part_shift,
            replica2part2dev_id: Vec::new(),
            next_part_power: meta
                .get("next_part_power")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            version: meta.get("version").and_then(|v| v.as_u64()),
            format_version: 1,
            dev_id_bytes: 2,
            size: 0,
            raw_size: 0,
            replica_count_meta: replica_count as f64,
        };
        if metadata_only {
            return Ok(ring);
        }

        let partition_count = 1usize << (32 - part_shift);
        let mut offset = 10 + json_len;
        for _ in 0..replica_count {
            // like Python's read(), a short final row is allowed
            let end = (offset + 2 * partition_count).min(data.len());
            let row_bytes = &data[offset..end];
            offset = end;
            let row: Vec<u32> = row_bytes
                .chunks_exact(2)
                .map(|c| {
                    let v = if big_endian {
                        u16::from_be_bytes([c[0], c[1]])
                    } else {
                        u16::from_le_bytes([c[0], c[1]])
                    };
                    v as u32
                })
                .collect();
            ring.replica2part2dev_id.push(row);
        }
        Ok(ring)
    }

    /// Deserialize a v2 ring (Python `RingData.deserialize_v2`).
    fn deserialize_v2(file: &RingFile, metadata_only: bool) -> Result<Self, RingError> {
        let meta: Value = serde_json::from_slice(file.read_section("swift/ring/metadata")?)?;
        let part_shift = meta["part_shift"]
            .as_u64()
            .ok_or_else(|| RingError("missing part_shift".to_string()))?
            as u32;
        let dev_id_bytes = meta["dev_id_bytes"]
            .as_u64()
            .ok_or_else(|| RingError("missing dev_id_bytes".to_string()))?
            as u8;
        if !matches!(dev_id_bytes, 2 | 4) {
            return Err(RingError(format!(
                "unsupported dev_id_bytes: {dev_id_bytes}"
            )));
        }

        let mut ring = RingData {
            devs: Self::parse_devs(&serde_json::from_slice(
                file.read_section("swift/ring/devices")?,
            )?)?,
            part_shift,
            replica2part2dev_id: Vec::new(),
            next_part_power: meta
                .get("next_part_power")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            version: meta.get("version").and_then(|v| v.as_u64()),
            format_version: 2,
            dev_id_bytes,
            size: 0,
            raw_size: 0,
            replica_count_meta: meta
                .get("replica_count")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0),
        };
        if metadata_only {
            return Ok(ring);
        }

        let partition_count = 1usize << (32 - part_shift);
        let table = file.read_section("swift/ring/assignments")?;
        // rows of dev_id_bytes * partition_count bytes, big-endian; the
        // final row may be short (fractional replicas)
        let max_row_len = dev_id_bytes as usize * partition_count;
        let mut offset = 0;
        while offset < table.len() {
            let end = (offset + max_row_len).min(table.len());
            let row_bytes = &table[offset..end];
            offset = end;
            let row: Vec<u32> = match dev_id_bytes {
                2 => row_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]) as u32)
                    .collect(),
                4 => row_bytes.chunks_exact(4).map(be_u32).collect(),
                _ => unreachable!(),
            };
            ring.replica2part2dev_id.push(row);
        }
        Ok(ring)
    }

    /// Number of replicas (full or partial) used in the ring.
    pub fn replica_count(&self) -> f64 {
        if self.replica2part2dev_id.is_empty() {
            self.replica_count_meta
        } else {
            calc_replica_count(&self.replica2part2dev_id)
        }
    }

    pub fn part_power(&self) -> u32 {
        32 - self.part_shift
    }
}

/// A primary node for a partition: the device plus its offset into the
/// primary node list (the `index` key Python merges into the node dict).
#[derive(Debug, Clone, PartialEq)]
pub struct PartNode<'a> {
    pub index: usize,
    pub dev: &'a RingDevice,
}

/// A handoff node from [`Ring::get_more_nodes`], with its position in
/// the handoff sequence (the `handoff_index` key in Python).
#[derive(Debug, Clone, PartialEq)]
pub struct HandoffNode<'a> {
    pub handoff_index: usize,
    pub dev: &'a RingDevice,
}

/// Partitioned consistent hashing ring (Python `Ring`).
///
/// Unlike Python's `Ring`, this does not auto-reload from disk; callers
/// should watch the file mtime and construct a new `Ring` when it
/// changes.
#[derive(Debug, Clone)]
pub struct Ring {
    data: RingData,
    hash_config: HashPathConfig,
    num_devs: usize,
    num_weighted_devs: usize,
    num_assigned_devs: usize,
    num_regions: usize,
    num_zones: usize,
    num_ips: usize,
}

impl Ring {
    /// Build a ring from loaded data and the cluster hash configuration.
    pub fn new(data: RingData, hash_config: HashPathConfig) -> Self {
        // bookkeeping over devices with at least one partition assigned,
        // to keep the early bailouts in get_more_nodes() working
        let mut dev_ids_with_parts: HashSet<u32> = HashSet::new();
        for row in &data.replica2part2dev_id {
            dev_ids_with_parts.extend(row.iter().copied());
        }
        let mut regions = HashSet::new();
        let mut zones = HashSet::new();
        let mut ips = HashSet::new();
        let mut num_devs = 0;
        let mut num_weighted_devs = 0;
        let mut num_assigned_devs = 0;
        for dev in data.devs.iter().flatten() {
            num_devs += 1;
            if dev.weight > 0.0 {
                num_weighted_devs += 1;
            }
            if dev_ids_with_parts.contains(&(dev.id as u32)) {
                regions.insert(dev.region);
                zones.insert((dev.region, dev.zone));
                ips.insert((dev.region, dev.zone, dev.ip.clone()));
                num_assigned_devs += 1;
            }
        }
        Ring {
            data,
            hash_config,
            num_devs,
            num_weighted_devs,
            num_assigned_devs,
            num_regions: regions.len(),
            num_zones: zones.len(),
            num_ips: ips.len(),
        }
    }

    /// Load a ring file and build the ring.
    pub fn load(path: &Path, hash_config: HashPathConfig) -> Result<Self, RingError> {
        Ok(Self::new(RingData::load(path)?, hash_config))
    }

    pub fn data(&self) -> &RingData {
        &self.data
    }

    pub fn replica_count(&self) -> f64 {
        self.data.replica_count()
    }

    /// Number of partitions in the ring.
    pub fn partition_count(&self) -> usize {
        self.data.replica2part2dev_id[0].len()
    }

    pub fn device_count(&self) -> usize {
        self.num_devs
    }

    pub fn weighted_device_count(&self) -> usize {
        self.num_weighted_devs
    }

    pub fn assigned_device_count(&self) -> usize {
        self.num_assigned_devs
    }

    pub fn devs(&self) -> &[Option<RingDevice>] {
        &self.data.devs
    }

    pub fn next_part_power(&self) -> Option<u32> {
        self.data.next_part_power
    }

    pub fn part_power(&self) -> u32 {
        self.data.part_power()
    }

    pub fn version(&self) -> Option<u64> {
        self.data.version
    }

    fn dev(&self, dev_id: u32) -> Result<&RingDevice, RingError> {
        self.data
            .devs
            .get(dev_id as usize)
            .and_then(|d| d.as_ref())
            .ok_or_else(|| RingError(format!("No device with id {dev_id} in ring")))
    }

    /// Get the partition for an account/container/object (Python
    /// `get_part`).
    pub fn get_part(
        &self,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
    ) -> Result<u32, RingError> {
        let key = self
            .hash_config
            .hash_path_raw(account, container, object)
            .map_err(|e| RingError(e.to_string()))?;
        // Python shifts an arbitrary-precision int, so a part_shift of
        // 32 (part_power 0, a single partition) yields 0; a bare
        // `u32 >> 32` would panic, hence the widened shift.
        Ok(((be_u32(&key) as u64) >> self.data.part_shift) as u32)
    }

    /// Get the nodes responsible for a partition; a device responsible
    /// for multiple replicas appears only once (Python
    /// `get_part_nodes`).
    pub fn get_part_nodes(&self, part: u32) -> Result<Vec<PartNode<'_>>, RingError> {
        let part = part as usize;
        let mut nodes = Vec::new();
        let mut seen: HashSet<u32> = HashSet::new();
        for row in &self.data.replica2part2dev_id {
            if part < row.len() {
                let dev_id = row[part];
                if seen.insert(dev_id) {
                    nodes.push(self.dev(dev_id)?);
                }
            }
        }
        Ok(nodes
            .into_iter()
            .enumerate()
            .map(|(index, dev)| PartNode { index, dev })
            .collect())
    }

    /// Get the partition and primary nodes for an
    /// account/container/object (Python `get_nodes`).
    pub fn get_nodes(
        &self,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
    ) -> Result<(u32, Vec<PartNode<'_>>), RingError> {
        let part = self.get_part(account, container, object)?;
        Ok((part, self.get_part_nodes(part)?))
    }

    /// The sequence of handoff partitions probed by `get_more_nodes`.
    fn handoff_parts(&self, part: u32) -> impl Iterator<Item = usize> {
        let parts = self.partition_count();
        let part_hash = Md5::digest(part.to_string().as_bytes());
        // Widen to u64 before shifting: part_shift is 32 for a part_power-0
        // ring and `u32 >> 32` panics (shift >= bit width).
        let start = ((be_u32(&part_hash) as u64) >> self.data.part_shift) as usize;
        let inc = std::cmp::max(parts / 65536, 1);
        handoff_sequence(start, parts, inc)
    }

    /// Get the full ordered list of extra ("handoff") nodes for a
    /// partition (Python's `get_more_nodes` generator, evaluated
    /// eagerly).
    ///
    /// Handoffs prefer regions, then zones, then IPs not already used by
    /// the primary nodes, and keep stable sequences across ring changes.
    pub fn get_more_nodes(&self, part: u32) -> Result<Vec<HandoffNode<'_>>, RingError> {
        let primary_nodes = self.get_part_nodes(part)?;
        let mut used: HashSet<u32> = primary_nodes.iter().map(|n| n.dev.id as u32).collect();
        let mut same_regions: HashSet<u64> = primary_nodes.iter().map(|n| n.dev.region).collect();
        let mut same_zones: HashSet<(u64, u64)> = primary_nodes
            .iter()
            .map(|n| (n.dev.region, n.dev.zone))
            .collect();
        let mut same_ips: HashSet<(u64, u64, &str)> = primary_nodes
            .iter()
            .map(|n| (n.dev.region, n.dev.zone, n.dev.ip.as_str()))
            .collect();

        let mut result: Vec<HandoffNode<'_>> = Vec::new();
        let mut index = 0usize;

        // Pass 1: devices in regions not yet represented
        if same_regions.len() != self.num_regions {
            'outer: for handoff_part in self.handoff_parts(part) {
                for row in &self.data.replica2part2dev_id {
                    if handoff_part < row.len() {
                        let dev_id = row[handoff_part];
                        let dev = self.dev(dev_id)?;
                        if !used.contains(&dev_id) && !same_regions.contains(&dev.region) {
                            result.push(HandoffNode {
                                handoff_index: index,
                                dev,
                            });
                            index += 1;
                            used.insert(dev_id);
                            same_regions.insert(dev.region);
                            same_zones.insert((dev.region, dev.zone));
                            same_ips.insert((dev.region, dev.zone, dev.ip.as_str()));
                            if same_regions.len() == self.num_regions {
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }

        // Pass 2: devices in zones not yet represented
        if same_zones.len() != self.num_zones {
            'outer: for handoff_part in self.handoff_parts(part) {
                for row in &self.data.replica2part2dev_id {
                    if handoff_part < row.len() {
                        let dev_id = row[handoff_part];
                        let dev = self.dev(dev_id)?;
                        let zone = (dev.region, dev.zone);
                        if !used.contains(&dev_id) && !same_zones.contains(&zone) {
                            result.push(HandoffNode {
                                handoff_index: index,
                                dev,
                            });
                            index += 1;
                            used.insert(dev_id);
                            same_zones.insert(zone);
                            same_ips.insert((dev.region, dev.zone, dev.ip.as_str()));
                            if same_zones.len() == self.num_zones {
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }

        // Pass 3: devices on IPs not yet represented
        if same_ips.len() != self.num_ips {
            'outer: for handoff_part in self.handoff_parts(part) {
                for row in &self.data.replica2part2dev_id {
                    if handoff_part < row.len() {
                        let dev_id = row[handoff_part];
                        let dev = self.dev(dev_id)?;
                        let ip = (dev.region, dev.zone, dev.ip.as_str());
                        if !used.contains(&dev_id) && !same_ips.contains(&ip) {
                            result.push(HandoffNode {
                                handoff_index: index,
                                dev,
                            });
                            index += 1;
                            used.insert(dev_id);
                            same_ips.insert(ip);
                            if same_ips.len() == self.num_ips {
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }

        // Pass 4: any remaining unused devices
        if used.len() != self.num_assigned_devs {
            'outer: for handoff_part in self.handoff_parts(part) {
                for row in &self.data.replica2part2dev_id {
                    if handoff_part < row.len() {
                        let dev_id = row[handoff_part];
                        if !used.contains(&dev_id) {
                            let dev = self.dev(dev_id)?;
                            result.push(HandoffNode {
                                handoff_index: index,
                                dev,
                            });
                            index += 1;
                            used.insert(dev_id);
                            if used.len() == self.num_assigned_devs {
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }

        Ok(result)
    }
}

/// The partition probe order used for handoff selection (Python:
/// `chain(range(start, parts, inc), range(inc - ((parts - start) % inc),
/// start, inc))`). Wraps around, but by a quirk of the arithmetic never
/// revisits offsets below `inc - ((parts - start) % inc)`.
fn handoff_sequence(start: usize, parts: usize, inc: usize) -> impl Iterator<Item = usize> {
    let second_start = inc - ((parts - start) % inc);
    (start..parts)
        .step_by(inc)
        .chain((second_start..start).step_by(inc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handoff_sequence_matches_python() {
        // expected sequences computed with the Python expression
        let cases: &[(usize, usize, usize, &[usize])] = &[
            (
                5,
                16,
                1,
                &[5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 2, 3, 4],
            ),
            (0, 8, 1, &[0, 1, 2, 3, 4, 5, 6, 7]),
            (7, 32, 4, &[7, 11, 15, 19, 23, 27, 31, 3]),
            (0, 32, 4, &[0, 4, 8, 12, 16, 20, 24, 28]),
            (30, 32, 4, &[30, 2, 6, 10, 14, 18, 22, 26]),
            (3, 30, 7, &[3, 10, 17, 24, 1]),
        ];
        for &(start, parts, inc, want) in cases {
            let got: Vec<usize> = handoff_sequence(start, parts, inc).collect();
            assert_eq!(got, want, "start={start} parts={parts} inc={inc}");
        }
    }

    #[test]
    fn test_calc_replica_count() {
        assert_eq!(calc_replica_count(&[]), 0.0);
        assert_eq!(calc_replica_count(&[vec![0; 4]]), 1.0);
        assert_eq!(
            calc_replica_count(&[vec![0; 4], vec![0; 4], vec![0; 4]]),
            3.0
        );
        // fractional final replica
        assert_eq!(
            calc_replica_count(&[vec![0; 4], vec![0; 4], vec![0; 2]]),
            2.5
        );
    }
}
