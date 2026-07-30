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

//! Ring dispersion analysis, the local (no-cluster) half of what
//! `swift-dispersion-report` and `swift-ring-builder`'s dispersion metric
//! report: how well each partition's replicas are spread across failure
//! domains. A partition is poorly dispersed when two of its replicas share a
//! region (or a zone) — losing that domain would lose two copies at once.
//!
//! (The `swift-dispersion-report` tool proper also probes a live cluster for
//! placed dispersion objects; that transport is separate. This is the ring
//! coverage computation, which is deterministic and unit-testable.)

use swift_ring::Ring;

/// The dispersion of a ring's partitions across failure domains.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DispersionReport {
    pub partitions: usize,
    /// Partitions with two or more replicas in the same region.
    pub region_overlaps: usize,
    /// Partitions with two or more replicas in the same zone.
    pub zone_overlaps: usize,
}

impl DispersionReport {
    /// The percentage of partitions whose replicas are fully region-dispersed.
    pub fn region_dispersion_pct(&self) -> f64 {
        if self.partitions == 0 {
            return 100.0;
        }
        100.0 * (self.partitions - self.region_overlaps) as f64 / self.partitions as f64
    }
}

/// True if any value appears more than once.
fn has_duplicate<T: PartialEq>(vals: &[T]) -> bool {
    for i in 0..vals.len() {
        for j in (i + 1)..vals.len() {
            if vals[i] == vals[j] {
                return true;
            }
        }
    }
    false
}

/// Compute the region/zone dispersion of a ring: for each partition, whether
/// two of its (distinct) replica devices share a region or zone.
pub fn dispersion_report(ring: &Ring) -> DispersionReport {
    let partitions = ring.partition_count();
    let mut report = DispersionReport {
        partitions,
        ..Default::default()
    };
    for part in 0..partitions as u32 {
        let Ok(nodes) = ring.get_part_nodes(part) else {
            continue;
        };
        let regions: Vec<u64> = nodes.iter().map(|n| n.dev.region).collect();
        let zones: Vec<(u64, u64)> = nodes.iter().map(|n| (n.dev.region, n.dev.zone)).collect();
        if has_duplicate(&regions) {
            report.region_overlaps += 1;
        }
        if has_duplicate(&zones) {
            report.zone_overlaps += 1;
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use swift_core::hashing::HashPathConfig;
    use swift_ring::{RingData, RingDevice};

    fn dev(id: u64, region: u64, zone: u64) -> RingDevice {
        RingDevice {
            id,
            region,
            zone,
            ip: format!("10.0.0.{id}"),
            port: 6200,
            replication_ip: None,
            replication_port: None,
            device: "sda".into(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        }
    }

    /// One partition, 3 replicas over the given device ids.
    fn ring(devs: Vec<Option<RingDevice>>, assignment: Vec<u32>) -> Ring {
        let r2p2d = assignment.into_iter().map(|d| vec![d]).collect();
        let data = RingData::from_parts(devs, 32, r2p2d);
        Ring::new(data, HashPathConfig::new("", "changeme").unwrap())
    }

    #[test]
    fn test_well_dispersed_no_overlaps() {
        // 3 replicas in 3 distinct regions
        let devs = vec![Some(dev(0, 1, 1)), Some(dev(1, 2, 1)), Some(dev(2, 3, 1))];
        let r = ring(devs, vec![0, 1, 2]);
        let report = dispersion_report(&r);
        assert_eq!(report.partitions, 1);
        assert_eq!(report.region_overlaps, 0);
        assert_eq!(report.zone_overlaps, 0);
        assert_eq!(report.region_dispersion_pct(), 100.0);
    }

    #[test]
    fn test_region_overlap_detected() {
        // two replicas in region 1 -> a region overlap
        let devs = vec![Some(dev(0, 1, 1)), Some(dev(1, 1, 2)), Some(dev(2, 2, 1))];
        let r = ring(devs, vec![0, 1, 2]);
        let report = dispersion_report(&r);
        assert_eq!(report.region_overlaps, 1);
        // distinct zones (region1/zone1, region1/zone2, region2/zone1) -> no zone overlap
        assert_eq!(report.zone_overlaps, 0);
        assert_eq!(report.region_dispersion_pct(), 0.0);
    }

    #[test]
    fn test_zone_overlap_detected() {
        // two replicas in region 1 zone 1 -> region AND zone overlap
        let devs = vec![Some(dev(0, 1, 1)), Some(dev(1, 1, 1)), Some(dev(2, 2, 1))];
        let r = ring(devs, vec![0, 1, 2]);
        let report = dispersion_report(&r);
        assert_eq!(report.region_overlaps, 1);
        assert_eq!(report.zone_overlaps, 1);
    }
}
