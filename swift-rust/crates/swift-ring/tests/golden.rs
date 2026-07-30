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

//! Differential tests against golden ring files produced by the real
//! Python implementation (see `fixtures/generate.py`). Every lookup the
//! Rust ring performs must match Python byte-for-byte.

use std::path::PathBuf;

use serde_json::Value;
use swift_core::hashing::HashPathConfig;
use swift_ring::{Ring, RingData};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn expectations() -> Value {
    let raw = std::fs::read(fixture("expectations.json")).expect(
        "missing fixtures; run rust/crates/swift-ring/tests/fixtures/generate.py",
    );
    serde_json::from_slice(&raw).unwrap()
}

fn check_ring(name: &str, expected: &Value, hash_config: &HashPathConfig) {
    let path = fixture(name);
    let data = RingData::load(&path).unwrap();

    assert_eq!(
        data.replica_count(),
        expected["replica_count"].as_f64().unwrap(),
        "{name}: replica_count"
    );
    assert_eq!(
        data.part_shift as u64,
        expected["part_shift"].as_u64().unwrap(),
        "{name}: part_shift"
    );
    assert_eq!(
        data.dev_id_bytes as u64,
        expected["dev_id_bytes"].as_u64().unwrap(),
        "{name}: dev_id_bytes"
    );
    assert_eq!(
        data.next_part_power.map(u64::from),
        expected["next_part_power"].as_u64(),
        "{name}: next_part_power"
    );
    assert_eq!(
        data.version,
        expected["builder_version"].as_u64(),
        "{name}: builder version"
    );
    // normalize_devices ran: replication ip/port filled from ip/port
    for dev in data.devs.iter().flatten() {
        assert_eq!(dev.replication_ip.as_deref(), Some(dev.ip.as_str()));
        assert_eq!(dev.replication_port, Some(dev.port));
    }

    let ring = Ring::new(data, hash_config.clone());
    assert_eq!(
        ring.partition_count() as u64,
        expected["partition_count"].as_u64().unwrap(),
        "{name}: partition_count"
    );
    assert_eq!(
        ring.device_count() as u64,
        expected["device_count"].as_u64().unwrap(),
        "{name}: device_count"
    );
    assert_eq!(
        ring.weighted_device_count() as u64,
        expected["weighted_device_count"].as_u64().unwrap(),
        "{name}: weighted_device_count"
    );
    assert_eq!(
        ring.assigned_device_count() as u64,
        expected["assigned_device_count"].as_u64().unwrap(),
        "{name}: assigned_device_count"
    );

    // get_nodes for each sampled path
    for get in expected["gets"].as_array().unwrap() {
        let account = get["account"].as_str().unwrap();
        let container = get["container"].as_str();
        let obj = get["obj"].as_str();
        let (part, nodes) = ring.get_nodes(account, container, obj).unwrap();
        assert_eq!(
            part as u64,
            get["part"].as_u64().unwrap(),
            "{name}: part for {account:?}/{container:?}/{obj:?}"
        );
        let ids: Vec<u64> = nodes.iter().map(|n| n.dev.id).collect();
        let expected_ids: Vec<u64> = get["node_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        assert_eq!(ids, expected_ids, "{name}: node ids for part {part}");
        let indexes: Vec<u64> = nodes.iter().map(|n| n.index as u64).collect();
        let expected_indexes: Vec<u64> = get["node_indexes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        assert_eq!(indexes, expected_indexes, "{name}: node indexes");
    }

    // full handoff orderings
    for (part_str, ids) in expected["more_nodes"].as_object().unwrap() {
        let part: u32 = part_str.parse().unwrap();
        let handoffs = ring.get_more_nodes(part).unwrap();
        let got: Vec<u64> = handoffs.iter().map(|n| n.dev.id).collect();
        let want: Vec<u64> = ids
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        assert_eq!(got, want, "{name}: handoffs for part {part}");
        // handoff_index is the position in the sequence
        for (i, h) in handoffs.iter().enumerate() {
            assert_eq!(h.handoff_index, i);
        }
        // handoffs never overlap primaries
        let primary_ids: Vec<u64> = ring
            .get_part_nodes(part)
            .unwrap()
            .iter()
            .map(|n| n.dev.id)
            .collect();
        assert!(got.iter().all(|id| !primary_ids.contains(id)));
    }
}

#[test]
fn test_golden_rings_match_python() {
    let exp = expectations();
    let hash_config = HashPathConfig::new(
        exp["hash_prefix"].as_str().unwrap().as_bytes().to_vec(),
        exp["hash_suffix"].as_str().unwrap().as_bytes().to_vec(),
    )
    .unwrap();
    let rings = exp["rings"].as_object().unwrap();
    assert!(!rings.is_empty());
    for (name, expected) in rings {
        check_ring(name, expected, &hash_config);
    }
}

#[test]
fn test_v1_v2_load_identically() {
    let v1 = RingData::load(&fixture("v1.ring.gz")).unwrap();
    let v2 = RingData::load(&fixture("v2.ring.gz")).unwrap();
    assert_eq!(v1.replica2part2dev_id, v2.replica2part2dev_id);
    assert_eq!(v1.part_shift, v2.part_shift);
    assert_eq!(v1.devs, v2.devs);
    assert_eq!(v1.format_version, 1);
    assert_eq!(v2.format_version, 2);
}

#[test]
fn test_metadata_only() {
    let md = RingData::load_metadata_only(&fixture("v2.ring.gz")).unwrap();
    assert!(md.replica2part2dev_id.is_empty());
    assert_eq!(md.replica_count(), 3.0);
    assert_eq!(md.devs.iter().flatten().count(), 8);

    let md = RingData::load_metadata_only(&fixture("v1.ring.gz")).unwrap();
    assert!(md.replica2part2dev_id.is_empty());
    assert_eq!(md.replica_count(), 3.0);
}

#[test]
fn test_corrupt_section_checksum_detected() {
    // flip a byte inside the v2 devices section and confirm the checksum
    // verification catches it
    let compressed = std::fs::read(fixture("v2.ring.gz")).unwrap();
    let file = swift_ring::RingFile::from_compressed_bytes(&compressed).unwrap();
    let mut data = file.data.clone();
    let entry = &file.index["swift/ring/devices"];
    // corrupt one payload byte
    data[entry.uncompressed_start as usize + 9] ^= 0xff;
    let corrupted = swift_ring::RingFile {
        version: file.version,
        data,
        size: file.size,
        raw_size: file.raw_size,
        index: file.index.clone(),
    };
    let err = corrupted.read_section("swift/ring/devices").unwrap_err();
    assert!(err.0.contains("Hash mismatch"), "{}", err.0);
    // the untouched file passes
    assert!(file.read_section("swift/ring/devices").is_ok());
}
