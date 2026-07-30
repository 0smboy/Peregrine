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

//! `swift-recon <check> [path]`: node-local recon collectors.
//!
//!   swift-recon ringmd5 <swift_dir>   — MD5 of every *.ring.gz
//!   swift-recon async <device>        — async_pending backlog count
//!   swift-recon quarantined <device>  — quarantine tallies

use std::path::Path;

use swift_cli::recon::{async_pending_count, quarantine_counts, ring_md5};

fn main() {
    let check = std::env::args().nth(1).unwrap_or_default();
    let path = std::env::args().nth(2).unwrap_or_else(|| ".".to_string());
    let p = Path::new(&path);
    match check.as_str() {
        "ringmd5" => match ring_md5(p) {
            Ok(rings) => {
                for (name, md5) in rings {
                    println!("{md5}\t{name}");
                }
            }
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        },
        "async" => println!("async_pending\t{}", async_pending_count(p)),
        "quarantined" => {
            let q = quarantine_counts(p);
            println!("accounts\t{}", q.accounts);
            println!("containers\t{}", q.containers);
            println!("objects\t{}", q.objects);
        }
        _ => {
            eprintln!("usage: swift-recon <ringmd5|async|quarantined> <path>");
            std::process::exit(1);
        }
    }
}
