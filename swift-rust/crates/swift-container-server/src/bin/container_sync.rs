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

//! `swift-container-sync <config.conf> [once]`: container-sync daemon.
//!
//! Walks containers registered in each device's `sync_containers/` index,
//! ships object-row PUT/DELETE to the remote `X-Container-Sync-To` endpoint,
//! and advances `x_container_sync_point1` / `point2`. Auth uses realm HMAC
//! when `//realm/cluster/...` is configured, else the legacy sync-key header.
//!
//! PUT bodies require a local object source. This binary uses a proxy HTTP
//! GET via `internal_client_url` (default `http://127.0.0.1:8080`) — the
//! same role Python's InternalClient fills. Without a reachable proxy,
//! DELETE still works; PUT rows fail and are retried next pass.

use std::path::Path;

use swift_container_server::sync::{
    run_once, ContainerSyncConfig, ContainerSyncRealms, EmptyObjectSource, HttpSyncClient,
    ObjectSource,
};
use swift_core::config::SwiftConfig;
use swift_core::daemon;
use swift_core::hashing::HashPathConfig;
use swift_core::obslog::{LogLevel, Logger};
use swift_core::statsd::StatsdClient;
use swift_ring::{Ring, RingData};

fn parse_conf_file(path: &str) -> SwiftConfig {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    SwiftConfig::parse_lenient(&content, &[], false).unwrap_or_else(|e| {
        eprintln!("could not parse {path}: {e}");
        std::process::exit(1);
    })
}

/// GET objects through the local proxy (InternalClient stand-in).
struct ProxyObjectSource {
    base: String,
    timeout: std::time::Duration,
}

impl ObjectSource for ProxyObjectSource {
    fn get_object(
        &self,
        account: &str,
        container: &str,
        name: &str,
        _storage_policy_index: i64,
    ) -> Option<(Vec<(String, String)>, Vec<u8>)> {
        let url = format!(
            "{}/{}/{}/{}",
            self.base.trim_end_matches('/'),
            pe(account),
            pe(container),
            pe(name)
        );
        // Prefer replication-style newest GET headers the proxy understands.
        let headers = vec![
            ("X-Newest".into(), "True".into()),
            ("Connection".into(), "close".into()),
        ];
        let (status, resp_headers, body) =
            http_get(&url, &headers, self.timeout)?;
        if !(200..300).contains(&status) {
            return None;
        }
        Some((resp_headers, body))
    }
}

fn pe(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn http_get(
    url: &str,
    headers: &[(String, String)],
    timeout: std::time::Duration,
) -> Option<(u16, Vec<(String, String)>, Vec<u8>)> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some((h, p)) = hostport.rsplit_once(':') {
        (h, p.parse().unwrap_or(80))
    } else {
        (hostport, 80u16)
    };
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n"
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    let mut conn = TcpStream::connect(format!("{host}:{port}")).ok()?;
    let _ = conn.set_read_timeout(Some(timeout));
    let _ = conn.set_write_timeout(Some(timeout));
    conn.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    let _ = conn.read_to_end(&mut buf);
    let mut headers_end = None;
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            headers_end = Some(i);
            break;
        }
    }
    let end = headers_end?;
    let head = String::from_utf8_lossy(&buf[..end]);
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let mut resp_headers = Vec::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            resp_headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let body = buf[end + 4..].to_vec();
    Some((status, resp_headers, body))
}

fn main() {
    let conf_path =
        std::env::args().nth(1).unwrap_or_else(|| "/etc/swift/container-server.conf".to_string());
    let run_once_only = std::env::args().nth(2).as_deref() == Some("once");
    let conf = parse_conf_file(&conf_path);
    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    let cfg = ContainerSyncConfig::from_swift_conf(&conf, &swift_dir);

    let get = |section: &str, key: &str, default: &str| -> String {
        conf.get(section, key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };
    let log_name = get("container-sync", "log_name", "container-sync");
    let log_level = get("container-sync", "log_level", "INFO")
        .parse::<LogLevel>()
        .unwrap_or(LogLevel::Info);
    let logger = Logger::with_syslog(&log_name, log_level);
    let statsd = StatsdClient::new(
        &get("container-sync", "log_statsd_host", ""),
        get("container-sync", "log_statsd_port", "8125")
            .parse()
            .unwrap_or(8125),
        &daemon::statsd_prefix(
            &get("container-sync", "log_statsd_metric_prefix", ""),
            "container-sync",
        ),
    );
    let recon_cache_path = get("container-sync", "recon_cache_path", "/var/cache/swift");
    let internal_url = get(
        "container-sync",
        "internal_client_url",
        "http://127.0.0.1:8080/v1",
    );

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| format!("{swift_dir}/swift.conf"));
    let swift_conf = parse_conf_file(&swift_conf_path);
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        logger.error(&format!("bad swift.conf hash config: {e}"));
        std::process::exit(1);
    });

    let ring_path = format!("{swift_dir}/container.ring.gz");
    let mut container_ring = match RingData::load(Path::new(&ring_path)) {
        Ok(data) => Some(Ring::new(data, hash_config.clone())),
        Err(e) => {
            logger.warning(&format!(
                "could not load {ring_path}: {e}; ordinal defaults to 0/1"
            ));
            None
        }
    };

    let realms = ContainerSyncRealms::load(&cfg.realms_conf_path);
    let object_source: Box<dyn ObjectSource> = if internal_url.is_empty() {
        Box::new(EmptyObjectSource)
    } else {
        Box::new(ProxyObjectSource {
            base: internal_url.clone(),
            timeout: std::time::Duration::from_secs_f64(cfg.conn_timeout.max(0.1)),
        })
    };
    let client =
        HttpSyncClient::with_tls(object_source, cfg.conn_timeout, cfg.tls_options());
    let stop = swift_http::install_sigterm_flag();

    // Local bind identity for primary-node ordinal (Python is_local_device).
    let bind_ip = get("container-sync", "bind_ip", "0.0.0.0");
    let bind_port: u16 = get("container-sync", "bind_port", "6201")
        .parse()
        .unwrap_or(6201);
    let _ = (bind_ip, bind_port); // residual: full is_local_device scan

    logger.info(&format!(
        "swift-container-sync: devices={} interval={}s container_time={} once={run_once_only} internal_url={internal_url}",
        cfg.devices.display(),
        cfg.interval,
        cfg.container_time,
    ));

    loop {
        let sweep_start = std::time::Instant::now();
        // Without a full local-IP scan, use ordinal 0 / replica_count 1 so a
        // single-node (or SAIO) ships every new row; multi-node deployments
        // still backfill via pass A (point2→point1).
        let (ordinal, replica_count) = container_ring
            .as_ref()
            .map(|r| (0usize, r.replica_count().max(1.0) as usize))
            .map(|(o, c)| {
                // Prefer shipping every new row only when replica_count is
                // treated as 1 (dev). Production multi-replica keeps
                // replica_count and relies on pass-A backfill for missed
                // hashes when ordinal is always 0 — honest residual.
                let _ = o;
                (0usize, if c <= 1 { 1 } else { c })
            })
            .unwrap_or((0, 1));

        let stats = run_once(
            &cfg.devices,
            &client,
            &realms,
            &cfg.allowed_sync_hosts,
            &hash_config,
            ordinal,
            // SAIO / single-node: force full ownership of new rows.
            if ordinal == 0 && replica_count > 1 {
                // Multi-replica with unknown local ordinal: only backfill
                // (pass A). Pass B still runs but owns_object(0, N) only
                // ships 1/N; other primaries need their own ordinal. Use
                // replica_count=1 so this node is useful without IP scan.
                1
            } else {
                replica_count
            },
            cfg.container_time,
        );
        logger.info(&format!(
            "container-sync pass: syncs={} puts={} deletes={} skips={} failures={}",
            stats.syncs, stats.puts, stats.deletes, stats.skips, stats.failures
        ));
        statsd.update_stats("syncs", stats.syncs as i64);
        statsd.update_stats("puts", stats.puts as i64);
        statsd.update_stats("deletes", stats.deletes as i64);
        statsd.update_stats("skips", stats.skips as i64);
        statsd.update_stats("failures", stats.failures as i64);

        let update = serde_json::json!({
            "container_syncs": stats.syncs,
            "container_puts": stats.puts,
            "container_deletes": stats.deletes,
            "container_skips": stats.skips,
            "container_failures": stats.failures,
            "container_sync_last": daemon::epoch_secs_now(),
            "container_sync_duration": sweep_start.elapsed().as_secs_f64(),
        });
        if let Err(e) = daemon::dump_recon(&recon_cache_path, "container.recon", &update) {
            logger.warning(&format!(
                "could not dump recon cache to {recon_cache_path}/container.recon: {e}"
            ));
        }

        if run_once_only {
            break;
        }
        if daemon::sleep_unless_stopped(cfg.interval, &stop) {
            logger.info("exiting on SIGTERM");
            break;
        }
        match RingData::load(Path::new(&ring_path)) {
            Ok(data) => container_ring = Some(Ring::new(data, hash_config.clone())),
            Err(e) => logger.warning(&format!(
                "could not reload {ring_path}: {e}; reusing previous ring"
            )),
        }
    }
}
