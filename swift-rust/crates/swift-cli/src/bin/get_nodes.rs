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

//! `swift-get-nodes <ring.gz> <account> [container [object]]`
//! `swift-get-nodes -a <ring.gz> -p <partition>`

use std::path::Path;

use swift_cli::GetNodesReport;
use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_ring::{Ring, RingData};

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let all_handoffs = args.iter().any(|a| a == "-a" || a == "--all");
    let as_json = args.iter().any(|a| a == "--json");
    args.retain(|a| a != "-a" && a != "--all" && a != "--json");
    let part_flag = args.iter().position(|a| a == "-p");

    if args.is_empty() {
        eprintln!("usage: swift-get-nodes [-a] [--json] <ring.gz> <account> [container [object]]");
        eprintln!("   or: swift-get-nodes [-a] [--json] <ring.gz> -p <partition>");
        std::process::exit(1);
    }
    let ring_path = args.remove(0);
    let data = RingData::load(Path::new(&ring_path)).unwrap_or_else(|e| {
        eprintln!("could not load {ring_path}: {e}");
        std::process::exit(1);
    });
    let swift_conf = std::env::var("SWIFT_CONF").unwrap_or_else(|_| "/etc/swift/swift.conf".into());
    let hash_config = SwiftConfig::parse_lenient(
        &std::fs::read_to_string(&swift_conf).unwrap_or_default(),
        &[],
        false,
    )
    .ok()
    .and_then(|c| HashPathConfig::from_swift_conf(&c).ok());
    // Partition lookups (-p) are pure ring math and work without swift.conf;
    // item lookups hash the path, where a wrong (empty) config would silently
    // report the wrong nodes, so those fail loudly below instead.
    let ring = Ring::new(data, hash_config.clone().unwrap_or_default());

    let report = if let Some(pos) = part_flag {
        let part: u32 = args
            .get(pos.saturating_sub(0))
            .and_then(|_| args.iter().skip_while(|a| *a != "-p").nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                eprintln!("bad partition");
                std::process::exit(1);
            });
        GetNodesReport::for_partition(&ring, part, all_handoffs)
    } else {
        let Some(hash_config) = hash_config.as_ref() else {
            eprintln!(
                "could not read {swift_conf}: a valid [swift-hash] section is required \
                 to locate an account/container/object (set SWIFT_CONF, or use -p \
                 to look up a partition without it)"
            );
            std::process::exit(1);
        };
        let account = args.first().cloned().unwrap_or_default();
        let container = args.get(1).map(String::as_str);
        let object = args.get(2).map(String::as_str);
        GetNodesReport::for_item(
            &ring,
            hash_config,
            &account,
            container,
            object,
            all_handoffs,
        )
    };
    match report {
        Ok(r) if as_json => println!("{}", r.to_json()),
        Ok(r) => print!("{}", r.render()),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
