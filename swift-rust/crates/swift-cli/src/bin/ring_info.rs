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

//! `swift-ring-info <ring.gz>`: summarize a ring file.

use std::path::Path;

use swift_core::hashing::HashPathConfig;
use swift_ring::{Ring, RingData};

fn main() {
    let ring_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: swift-ring-info <ring.gz>");
        std::process::exit(1);
    });
    let data = RingData::load(Path::new(&ring_path)).unwrap_or_else(|e| {
        eprintln!("could not load {ring_path}: {e}");
        std::process::exit(1);
    });
    // A ring summary is pure ring metadata: no account/container/object path is
    // ever hashed here, so the cluster hash config is irrelevant. Use the empty
    // default rather than `new("", "")`, which validates and would always fail.
    let ring = Ring::new(data, HashPathConfig::default());
    println!("partitions\t{}", ring.partition_count());
    println!("replicas\t{}", ring.replica_count());
    println!("devices\t{}", ring.device_count());
}
