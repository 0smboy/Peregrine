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

//! The builder + writer round-trip: build a ring, serialize it to the v1
//! format, load it back, and confirm the assignments survive and the
//! reader/get_nodes agree. A companion Python cross-check lives in
//! tests/fixtures/verify.py (run manually) to prove the real Python
//! `RingData` also reads our written ring.

use std::path::PathBuf;

use swift_core::hashing::HashPathConfig;
use swift_ring::{Ring, RingBuilder, RingData};

fn build_sample() -> RingBuilder {
    let mut b = RingBuilder::new(6, 3.0);
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
    b
}

#[test]
fn test_v1_write_read_roundtrip() {
    let b = build_sample();
    let ring_data = b.to_ring_data();
    let bytes = ring_data.serialize_v1().unwrap();
    assert!(bytes.starts_with(&[0x1f, 0x8b]), "gzip magic");

    let dir = std::env::temp_dir().join(format!("swift-ring-build-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("object.ring.gz");
    ring_data.save_v1(&path).unwrap();

    // reload with the reader and confirm the assignment table survived
    let reloaded = RingData::load(&path).unwrap();
    assert_eq!(reloaded.format_version, 1);
    assert_eq!(
        reloaded.replica2part2dev_id,
        ring_data.replica2part2dev_id,
        "assignment table round-trips"
    );
    assert_eq!(reloaded.part_shift, ring_data.part_shift);
    assert_eq!(reloaded.devs.len(), ring_data.devs.len());

    // and get_nodes works on the reloaded ring
    let hc = HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap();
    let ring = Ring::new(reloaded, hc);
    let (_p, nodes) = ring.get_nodes("a", Some("c"), Some("o")).unwrap();
    assert_eq!(nodes.len(), 3);
    for part in [0u32, 17, 63] {
        let n = ring.get_part_nodes(part).unwrap();
        assert_eq!(n.len(), 3);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_written_ring_is_deterministic() {
    // identical builder input -> identical bytes (fixed gzip mtime)
    let a = build_sample().to_ring_data().serialize_v1().unwrap();
    let b = build_sample().to_ring_data().serialize_v1().unwrap();
    assert_eq!(a, b, "same ring data serializes to identical bytes");
    // mtime field (gzip header bytes 4..8) is the fixed RING_MTIME
    assert_eq!(&a[4..8], &1300507380u32.to_le_bytes());
}

/// Written where the Python cross-check can find it (see verify.py).
#[test]
fn test_emit_ring_for_python_crosscheck() {
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rust_built.ring.gz");
    build_sample().to_ring_data().save_v1(&out).unwrap();
    assert!(out.exists());
}
