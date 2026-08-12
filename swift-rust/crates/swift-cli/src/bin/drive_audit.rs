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

//! `swift-drive-audit <logfile> [error_limit]`: scan a kernel log for drive
//! I/O errors and report devices at/over the error threshold. (Reports only;
//! the unmount/fstab side effects are left to the operator.)

use swift_cli::drive_audit::{count_drive_errors, devices_over_limit};

fn main() {
    let logfile = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: swift-drive-audit <logfile> [error_limit]");
        std::process::exit(1);
    });
    let limit: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let contents = std::fs::read_to_string(&logfile).unwrap_or_else(|e| {
        eprintln!("cannot read {logfile}: {e}");
        std::process::exit(1);
    });
    let tally = count_drive_errors(contents.lines());
    for (dev, count) in &tally {
        println!("{dev}\t{count}");
    }
    let over = devices_over_limit(&tally, limit);
    if !over.is_empty() {
        eprintln!("devices at/over limit {limit}: {}", over.join(", "));
        std::process::exit(2);
    }
}
