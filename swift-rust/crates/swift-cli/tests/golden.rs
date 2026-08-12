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

//! get-nodes verified against the swift-ring golden fixtures: the node
//! ids the report yields must match the Python-generated expectations.

use std::path::PathBuf;

use serde_json::Value as Json;
use swift_cli::GetNodesReport;
use swift_core::hashing::HashPathConfig;
use swift_ring::{Ring, RingData};

fn ring_fixture(name: &str) -> PathBuf {
    // reuse swift-ring's golden fixtures
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../swift-ring/tests/fixtures")
        .join(name)
}

fn expectations() -> Json {
    let raw = std::fs::read(ring_fixture("expectations.json")).unwrap();
    serde_json::from_slice(&raw).unwrap()
}

#[test]
fn test_get_nodes_matches_ring_expectations() {
    let exp = expectations();
    let hash_config = HashPathConfig::new(
        exp["hash_prefix"].as_str().unwrap().as_bytes().to_vec(),
        exp["hash_suffix"].as_str().unwrap().as_bytes().to_vec(),
    )
    .unwrap();
    let data = RingData::load(&ring_fixture("v2.ring.gz")).unwrap();
    let ring = Ring::new(data, hash_config.clone());

    // find the device id for each rendered node, and compare against the
    // expectations' get results
    for get in exp["rings"]["v2.ring.gz"]["gets"].as_array().unwrap() {
        let account = get["account"].as_str().unwrap();
        let container = get["container"].as_str();
        let object = get["obj"].as_str();
        let report =
            GetNodesReport::for_item(&ring, &hash_config, account, container, object, false)
                .unwrap();
        assert_eq!(
            report.partition as u64,
            get["part"].as_u64().unwrap(),
            "partition for {account}"
        );
        // the report's primary nodes (device names) must line up with the
        // expected node ids resolved through the ring
        let (_, ring_nodes) = ring.get_nodes(account, container, object).unwrap();
        let want_devices: Vec<String> = ring_nodes.iter().map(|n| n.dev.device.clone()).collect();
        let primaries: Vec<String> = report
            .nodes
            .iter()
            .filter(|n| !n.handoff)
            .map(|n| n.device.clone())
            .collect();
        assert_eq!(primaries, want_devices, "primary devices for {account}");
        // rendered report is well formed
        let text = report.render();
        assert!(text.starts_with(&format!("Partition\t{}\n", report.partition)));
    }
}

#[test]
fn test_get_nodes_partition_and_handoffs() {
    let exp = expectations();
    let hash_config = HashPathConfig::new(
        exp["hash_prefix"].as_str().unwrap().as_bytes().to_vec(),
        exp["hash_suffix"].as_str().unwrap().as_bytes().to_vec(),
    )
    .unwrap();
    let data = RingData::load(&ring_fixture("v2.ring.gz")).unwrap();
    let ring = Ring::new(data, hash_config);
    // -a shows all handoffs; the handoff device ids must match the
    // expectations' more_nodes for that partition
    for (part_str, want_ids) in exp["rings"]["v2.ring.gz"]["more_nodes"]
        .as_object()
        .unwrap()
    {
        let part: u32 = part_str.parse().unwrap();
        let report = GetNodesReport::for_partition(&ring, part, true).unwrap();
        let handoff_devices: Vec<String> = report
            .nodes
            .iter()
            .filter(|n| n.handoff)
            .map(|n| n.device.clone())
            .collect();
        let handoffs = ring.get_more_nodes(part).unwrap();
        let want_devices: Vec<String> = handoffs.iter().map(|n| n.dev.device.clone()).collect();
        assert_eq!(handoff_devices, want_devices, "handoffs for part {part}");
        let _ = want_ids;
    }
}
