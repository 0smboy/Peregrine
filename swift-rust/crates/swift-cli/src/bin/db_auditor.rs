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

//! `swift-db-auditor <device_path> <account|container>`: audit account
//! or container DBs on a device (each broker must open and query).

use swift_db::{audit_account_dbs, audit_container_dbs, DbAuditReport};

fn main() {
    let device = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: swift-db-auditor <device_path> <account|container>");
        std::process::exit(1);
    });
    let kind = std::env::args().nth(2).unwrap_or_else(|| "container".to_string());
    let report: DbAuditReport = match kind.as_str() {
        "account" => audit_account_dbs(std::path::Path::new(&device)),
        _ => audit_container_dbs(std::path::Path::new(&device)),
    };
    println!("passed\t{}", report.passed);
    println!("failed\t{}", report.failed);
    for p in &report.failed_paths {
        println!("failed-path\t{}", p.display());
    }
    if report.failed > 0 {
        std::process::exit(1);
    }
}
