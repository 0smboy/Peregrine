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

//! `swift-object-auditor <device_path> [policy_index]`: one audit pass
//! over a device, quarantining objects whose data no longer matches
//! their metadata (size / ETag).

use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_core::storage_policy::parse_storage_policies;
use swift_diskfile::{audit_device, DiskFileConfig, PolicyKind};

fn main() {
    let device = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: swift-object-auditor <device_path> [policy_index]");
        std::process::exit(1);
    });
    let policy_index: u32 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let swift_conf = std::env::var("SWIFT_CONF").unwrap_or_else(|_| "/etc/swift/swift.conf".into());
    let conf = SwiftConfig::parse_lenient(
        &std::fs::read_to_string(&swift_conf).unwrap_or_default(),
        &[],
        false,
    )
    .ok();
    // The auditor validates on-disk hash paths, so running it with the wrong
    // (empty) cluster hash config would flag healthy objects as corrupt. Fail
    // loudly on an unreadable swift.conf rather than auditing against a
    // fabricated config.
    let hash_config = conf
        .as_ref()
        .and_then(|c| HashPathConfig::from_swift_conf(c).ok())
        .unwrap_or_else(|| {
            eprintln!(
                "object-auditor: could not read a valid [swift-hash] section from \
                 {swift_conf}; refusing to audit against an empty hash config"
            );
            std::process::exit(1);
        });

    // Pick the right filename grammar for this policy: EC .data files carry a
    // `#frag_index#durable` suffix the replication parser rejects.
    let policy = conf
        .as_ref()
        .and_then(|c| parse_storage_policies(c).ok())
        .and_then(|policies| {
            policies.get_by_index_num(policy_index).map(|p| match p.ec() {
                Some(ec) => PolicyKind::Ec {
                    n_unique_fragments: Some(ec.ec_n_unique_fragments() as u32),
                },
                None => PolicyKind::Replication,
            })
        })
        .unwrap_or(PolicyKind::Replication);

    let report = audit_device(
        std::path::Path::new(&device),
        policy,
        policy_index,
        &hash_config,
        &DiskFileConfig::default(),
    );
    println!("passed\t{}", report.passed);
    println!("quarantined\t{}", report.quarantined);
    println!("errors\t{}", report.errors);
    for p in &report.quarantined_paths {
        println!("quarantined-path\t{}", p.display());
    }
    if report.quarantined > 0 || report.errors > 0 {
        std::process::exit(1);
    }
}
