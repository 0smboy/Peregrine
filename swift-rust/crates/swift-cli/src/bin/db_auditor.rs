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

//! Account/container DB auditor — two invocation modes:
//!
//! * Continuous daemon (Python `DatabaseAuditor` parity):
//!   `swift-db-auditor <account|container> <*-server.conf> [once]`
//!   Reads `[account-auditor]` / `[container-auditor]` (`interval`
//!   default 1800s).
//! * One-shot (ops / manual):
//!   `swift-db-auditor <device_path> <account|container>`

use std::path::Path;

use swift_core::config::SwiftConfig;
use swift_core::daemon::{dump_recon, epoch_secs_now, sleep_unless_stopped};
use swift_core::obslog::{LogLevel, Logger};
use swift_db::{audit_account_dbs, audit_container_dbs, audit_dbs_on_devices, DbAuditReport};

fn parse_conf_file(path: &str) -> SwiftConfig {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    SwiftConfig::parse_lenient(&content, &[], false).unwrap_or_else(|e| {
        eprintln!("could not parse {path}: {e}");
        std::process::exit(1);
    })
}

fn conf_get(conf: &SwiftConfig, section: &str, app_section: &str, key: &str, default: &str) -> String {
    conf.get(section, key)
        .ok()
        .flatten()
        .or_else(|| conf.get("DEFAULT", key).ok().flatten())
        .or_else(|| conf.get(app_section, key).ok().flatten())
        .unwrap_or_else(|| default.to_string())
}

fn print_report(report: &DbAuditReport) {
    println!("passed\t{}", report.passed);
    println!("failed\t{}", report.failed);
    for p in &report.failed_paths {
        println!("failed-path\t{}", p.display());
    }
}

fn run_oneshot(device: &str, kind: &str) {
    let report: DbAuditReport = match kind {
        "account" => audit_account_dbs(Path::new(device)),
        _ => audit_container_dbs(Path::new(device)),
    };
    print_report(&report);
    if report.failed > 0 {
        std::process::exit(1);
    }
}

fn run_daemon(kind: &str, conf_path: &str, run_once_only: bool) {
    let conf = parse_conf_file(conf_path);
    let (section, app_section, recon_file, default_interval) = match kind {
        "account" => (
            "account-auditor",
            "app:account-server",
            "account.recon",
            "1800",
        ),
        _ => (
            "container-auditor",
            "app:container-server",
            "container.recon",
            "1800",
        ),
    };
    let interval: u64 = conf_get(&conf, section, app_section, "interval", default_interval)
        .parse()
        .unwrap_or(1800);
    let devices = conf_get(&conf, section, app_section, "devices", "/srv/node");
    let mount_check = matches!(
        conf_get(&conf, section, app_section, "mount_check", "true")
            .to_ascii_lowercase()
            .as_str(),
        "true" | "yes" | "1" | "on"
    );
    let recon_cache_path =
        conf_get(&conf, section, app_section, "recon_cache_path", "/var/cache/swift");
    let log_name = conf_get(&conf, section, app_section, "log_name", section);
    let log_level = conf_get(&conf, section, app_section, "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let stop = swift_http::install_sigterm_flag();

    logger.info(&format!(
        "swift-db-auditor[{kind}]: devices={devices} mount_check={mount_check} \
         interval={interval}s once={run_once_only}"
    ));

    loop {
        let start = epoch_secs_now();
        let report = audit_dbs_on_devices(Path::new(&devices), mount_check, kind);
        let end = epoch_secs_now();
        logger.info(&format!(
            "{kind}-auditor pass: passed={} failed={} duration={:.1}s",
            report.passed,
            report.failed,
            end - start
        ));
        let mut recon = serde_json::Map::new();
        recon.insert(
            format!("{kind}_auditor_pass"),
            serde_json::json!(report.passed),
        );
        recon.insert(
            format!("{kind}_auditor_failure"),
            serde_json::json!(report.failed),
        );
        recon.insert(
            format!("{}_audits_since", kind),
            serde_json::json!(end - start),
        );
        recon.insert(format!("{kind}_auditor_last"), serde_json::json!(end));
        let _ = dump_recon(
            &recon_cache_path,
            recon_file,
            &serde_json::Value::Object(recon),
        );
        if run_once_only || sleep_unless_stopped(interval, &stop) {
            break;
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!(
            "usage:\n  swift-db-auditor <account|container> <*-server.conf> [once]\n  \
             swift-db-auditor <device_path> <account|container>"
        );
        std::process::exit(1);
    }
    let first = &args[0];
    if Path::new(first).is_dir() {
        let kind = args.get(1).map(|s| s.as_str()).unwrap_or("container");
        if kind != "account" && kind != "container" {
            eprintln!("kind must be account or container");
            std::process::exit(1);
        }
        run_oneshot(first, kind);
        return;
    }
    if first != "account" && first != "container" {
        eprintln!(
            "usage:\n  swift-db-auditor <account|container> <*-server.conf> [once]\n  \
             swift-db-auditor <device_path> <account|container>"
        );
        std::process::exit(1);
    }
    let kind = first.as_str();
    let conf_path = args.get(1).cloned().unwrap_or_else(|| {
        format!(
            "/etc/swift/{}-server.conf",
            if kind == "account" {
                "account"
            } else {
                "container"
            }
        )
    });
    let run_once_only = args.get(2).map(|s| s.as_str()) == Some("once")
        || args.get(1).map(|s| s.as_str()) == Some("once");
    let conf_path = if Path::new(&conf_path).exists() && conf_path != "once" {
        conf_path
    } else {
        format!(
            "/etc/swift/{}-server.conf",
            if kind == "account" {
                "account"
            } else {
                "container"
            }
        )
    };
    run_daemon(kind, &conf_path, run_once_only);
}
