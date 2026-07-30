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

//! `swift-manage-shard-ranges <container.db> find [shard_size]`: scan a
//! container DB and report the shard ranges it would be split into
//! (the read-only `find` subcommand; persisting/repairing is deferred).

use std::path::Path;

use swift_db::ContainerBroker;

fn main() {
    let db = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: swift-manage-shard-ranges <container.db> find [shard_size]");
        std::process::exit(1);
    });
    let cmd = std::env::args().nth(2).unwrap_or_else(|| "find".to_string());
    let shard_size: i64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(500000);

    if cmd != "find" {
        eprintln!("only the 'find' subcommand is supported");
        std::process::exit(1);
    }

    let mut broker = ContainerBroker::new(Path::new(&db), "", "");
    match broker.find_shard_ranges(shard_size, 1) {
        Ok((ranges, done)) => {
            println!("Found {} ranges (complete: {done})", ranges.len());
            for r in &ranges {
                let lower = if r.lower.is_empty() { "-inf" } else { &r.lower };
                let upper = if r.upper.is_empty() { "+inf" } else { &r.upper };
                println!("  [{}] {lower} .. {upper}  ({} objects)", r.index, r.object_count);
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
