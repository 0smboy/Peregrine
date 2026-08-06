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

//! Object auditor — two invocation modes:
//!
//! * Continuous daemon (Python `ObjectAuditor` parity):
//!   `swift-object-auditor <object-server.conf> [once]`
//!   Reads `[object-auditor]` (`interval` default 30s, `devices`,
//!   `mount_check`) and loops full-device passes.
//! * One-shot (ops / manual):
//!   `swift-object-auditor <device_path> [policy_index]`

use std::path::{Path, PathBuf};

use swift_cli::auditor_daemon::object_auditor_recon_update;
use swift_core::config::SwiftConfig;
use swift_core::daemon::{dump_recon, epoch_secs_now, sleep_unless_stopped};
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::storage_policy::parse_storage_policies;
use swift_diskfile::{audit_device, audit_devices, DiskFileConfig, PolicyKind};

fn parse_conf_file(path: &str) -> SwiftConfig {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    SwiftConfig::parse_lenient(&content, &[], false).unwrap_or_else(|e| {
        eprintln!("could not parse {path}: {e}");
        std::process::exit(1);
    })
}

fn conf_get(conf: &SwiftConfig, section: &str, key: &str, default: &str) -> String {
    conf.get(section, key)
        .ok()
        .flatten()
        .or_else(|| conf.get("DEFAULT", key).ok().flatten())
        .or_else(|| conf.get("app:object-server", key).ok().flatten())
        .unwrap_or_else(|| default.to_string())
}

fn policy_kinds(swift_conf: &SwiftConfig) -> Vec<(u32, PolicyKind)> {
    match parse_storage_policies(swift_conf) {
        Ok(policies) => {
            let mut out = Vec::new();
            for p in policies.iter() {
                let kind = match p.ec() {
                    Some(ec) => PolicyKind::Ec {
                        n_unique_fragments: Some(ec.ec_n_unique_fragments() as u32),
                    },
                    None => PolicyKind::Replication,
                };
                out.push((p.idx(), kind));
            }
            if out.is_empty() {
                out.push((0, PolicyKind::Replication));
            }
            out
        }
        Err(_) => vec![(0, PolicyKind::Replication)],
    }
}

fn run_oneshot(device: &str, policy_index: u32) {
    let swift_conf = std::env::var("SWIFT_CONF").unwrap_or_else(|_| "/etc/swift/swift.conf".into());
    let conf = SwiftConfig::parse_lenient(
        &std::fs::read_to_string(&swift_conf).unwrap_or_default(),
        &[],
        false,
    )
    .ok();
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
        Path::new(device),
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

fn run_daemon(conf_path: &str, run_once_only: bool) {
    let conf = parse_conf_file(conf_path);
    let interval: u64 = conf_get(&conf, "object-auditor", "interval", "30")
        .parse()
        .unwrap_or(30);
    let devices = conf_get(&conf, "object-auditor", "devices", "/srv/node");
    let mount_check = matches!(
        conf_get(&conf, "object-auditor", "mount_check", "true").to_ascii_lowercase().as_str(),
        "true" | "yes" | "1" | "on"
    );
    let recon_cache_path = conf_get(&conf, "object-auditor", "recon_cache_path", "/var/cache/swift");
    let log_name = conf_get(&conf, "object-auditor", "log_name", "object-auditor");
    let log_level = conf_get(&conf, "object-auditor", "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| "/etc/swift/swift.conf".into());
    let swift_conf = parse_conf_file(&swift_conf_path);
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });
    let policies = policy_kinds(&swift_conf);
    let stop = swift_http::install_sigterm_flag();

    logger.info(&format!(
        "swift-object-auditor: devices={devices} mount_check={mount_check} \
         interval={interval}s policies={} once={run_once_only}",
        policies.len()
    ));

    loop {
        let start = epoch_secs_now();
        let report = audit_devices(
            Path::new(&devices),
            mount_check,
            &policies,
            &hash_config,
            &DiskFileConfig::default(),
        );
        let end = epoch_secs_now();
        logger.info(&format!(
            "object-auditor pass: passed={} quarantined={} errors={} duration={:.1}s",
            report.passed,
            report.quarantined,
            report.errors,
            end - start
        ));
        let _ = dump_recon(
            &recon_cache_path,
            "object.recon",
            &object_auditor_recon_update(
                end - start,
                report.passed,
                report.quarantined,
                report.errors,
                start,
            ),
        );
        if run_once_only || sleep_unless_stopped(interval, &stop) {
            break;
        }
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!(
            "usage:\n  swift-object-auditor <object-server.conf> [once]\n  \
             swift-object-auditor <device_path> [policy_index]"
        );
        std::process::exit(1);
    }
    let first = args.remove(0);
    if Path::new(&first).is_dir() {
        let policy_index: u32 = args
            .first()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        run_oneshot(&first, policy_index);
        return;
    }
    // Daemon mode: conf path (or default), optional "once".
    let conf_path = if Path::new(&first).is_file() || first.ends_with(".conf") {
        first
    } else {
        args.insert(0, first);
        "/etc/swift/object-server.conf".to_string()
    };
    let conf_path = if Path::new(&conf_path).exists() {
        conf_path
    } else {
        "/etc/swift/object-server.conf".to_string()
    };
    let run_once_only = args.first().map(|s| s.as_str()) == Some("once");
    let _ = PathBuf::from(&conf_path);
    run_daemon(&conf_path, run_once_only);
}
