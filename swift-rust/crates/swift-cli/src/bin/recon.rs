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
//!   swift-recon tombstones <devices>  — .ts counts (+ optional --prometheus)
//!   swift-recon dbspace <devices>     — SQLite file/freelist (+ --prometheus)
//!   swift-recon vacuum <device>       — VACUUM account/container DBs on one device

use std::path::Path;

use swift_cli::recon::{async_pending_count, quarantine_counts, ring_md5};
use swift_cli::space_metrics::{
    db_space_prometheus, scan_db_space, scan_tombstones, tombstones_prometheus,
};
use swift_db::vacuum_device_dbs;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let prometheus = args.iter().any(|a| a == "--prometheus");
    args.retain(|a| a != "--prometheus");
    let check = args.first().cloned().unwrap_or_default();
    let path = args.get(1).cloned().unwrap_or_else(|| ".".to_string());
    let p = Path::new(&path);
    let node = hostname();
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
        "tombstones" => {
            let report = scan_tombstones(p);
            if prometheus {
                print!("{}", tombstones_prometheus(&report, &node));
            } else {
                println!("total_count\t{}", report.total_count);
                println!("total_bytes\t{}", report.total_bytes);
                for b in &report.buckets {
                    println!(
                        "device={}\tpolicy={}\tcount={}\tbytes={}",
                        b.device, b.policy, b.count, b.bytes
                    );
                }
            }
        }
        "dbspace" => {
            let report = scan_db_space(p);
            if prometheus {
                print!("{}", db_space_prometheus(&report, &node));
            } else {
                for (kind, t) in &report.by_kind {
                    println!(
                        "kind={kind}\tfiles={}\tfile_bytes={}\tfreelist_count={}\tfreelist_bytes={}\terrors={}",
                        t.files, t.file_bytes, t.freelist_count, t.freelist_bytes, t.errors
                    );
                }
                if !report.errors.is_empty() {
                    eprintln!("sample errors: {}", report.errors.len());
                    for (path, err) in report.errors.iter().take(5) {
                        eprintln!("  {}: {err}", path.display());
                    }
                }
            }
        }
        "vacuum" => {
            // path is a single device, e.g. /srv/node/d1
            let results = vacuum_device_dbs(p);
            let mut ok = 0u64;
            let mut fail = 0u64;
            let mut bytes_before = 0u64;
            let mut bytes_after = 0u64;
            for (path, before, after) in &results {
                match (before, after) {
                    (Ok(b), Ok(a)) => {
                        ok += 1;
                        bytes_before += b.file_bytes;
                        bytes_after += a.file_bytes;
                        println!(
                            "ok\t{}\tbefore={}\tafter={}\tfreelist_before={}\tfreelist_after={}",
                            path.display(),
                            b.file_bytes,
                            a.file_bytes,
                            b.freelist_count,
                            a.freelist_count
                        );
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        fail += 1;
                        println!("fail\t{}\t{e}", path.display());
                    }
                }
            }
            println!(
                "summary\tok={ok}\tfail={fail}\tbytes_before={bytes_before}\tbytes_after={bytes_after}\tbytes_reclaimed={}",
                bytes_before.saturating_sub(bytes_after)
            );
            if fail > 0 {
                std::process::exit(2);
            }
        }
        _ => {
            eprintln!(
                "usage: swift-recon <ringmd5|async|quarantined|tombstones|dbspace|vacuum> <path> [--prometheus]"
            );
            std::process::exit(1);
        }
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| {
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".into())
        })
}
