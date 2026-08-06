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

//! Calibrate Rust effective concurrency from Swift conf knobs.
//!
//! Usage:
//!   swift-effective-concurrency --workers 2 --max-clients 64
//!   swift-effective-concurrency --servers-per-port 4 --max-clients 1024 --ports 1
//!
//! See docs/fairness-lab/WORKERS-SEMANTICS.md.

use swift_object_server::servers_per_port::{
    effective_concurrency_json, ConcurrencyInputs,
};

fn usage() -> ! {
    eprintln!(
        "usage: swift-effective-concurrency \
         [--workers N] [--max-clients N] [--servers-per-port N] [--ports N]\n\
         Prints JSON for ISO-CONFIG effective concurrency (Rust mapping)."
    );
    std::process::exit(2);
}

fn main() {
    let mut workers: usize = 0;
    let mut max_clients: usize = 1024;
    let mut servers_per_port: usize = 0;
    let mut ports: usize = 1;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => usage(),
            "--workers" => {
                workers = args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())
            }
            "--max-clients" => {
                max_clients = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--servers-per-port" => {
                servers_per_port = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--ports" => {
                ports = args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())
            }
            _ => usage(),
        }
    }

    print!(
        "{}",
        effective_concurrency_json(ConcurrencyInputs {
            workers,
            max_clients,
            servers_per_port,
            bind_ports: ports.max(1),
        })
    );
}
