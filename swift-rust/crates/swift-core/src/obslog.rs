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

//! Operational logging for Swift daemons, the Rust counterpart of
//! `swift.common.utils.logs.get_logger`.
//!
//! Messages go to syslog over the `/dev/log` unix datagram socket as
//! RFC 3164 lines (`<PRI>Mmm dd HH:MM:SS name[pid]: LEVEL msg`, facility
//! `LOG_LOCAL0`) when the socket is available, and to stderr otherwise.
//! A send failure falls back to stderr for that message; nothing here
//! ever panics or returns an error to the caller.

use std::os::unix::net::UnixDatagram;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// The syslog socket every Linux syslog daemon listens on.
const SYSLOG_PATH: &str = "/dev/log";

/// `LOG_LOCAL0`, the facility Swift's default `log_facility` selects.
const LOG_LOCAL0: u8 = 16;

/// RFC 3164 month abbreviations, indexed by `month - 1`.
const MONTH_ABBREVIATIONS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Log severity, ordered so that `Debug < Info < Warning < Error`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warning,
    Error,
}

impl FromStr for LogLevel {
    type Err = std::convert::Infallible;

    /// Accepts `debug` / `info` / `warning` / `error` case-insensitively;
    /// anything else (including Swift's other `log_level` spellings) falls
    /// back to the default, `Info`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "debug" => LogLevel::Debug,
            "warning" => LogLevel::Warning,
            "error" => LogLevel::Error,
            _ => LogLevel::Info,
        })
    }
}

/// RFC 3164 severity code for a level (`LOG_DEBUG`, `LOG_INFO`,
/// `LOG_WARNING`, `LOG_ERR`).
fn severity(level: LogLevel) -> u8 {
    match level {
        LogLevel::Debug => 7,
        LogLevel::Info => 6,
        LogLevel::Warning => 4,
        LogLevel::Error => 3,
    }
}

/// RFC 3164 PRI value: `facility * 8 + severity`.
fn pri(level: LogLevel) -> u8 {
    LOG_LOCAL0 * 8 + severity(level)
}

fn level_label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "DEBUG",
        LogLevel::Info => "INFO",
        LogLevel::Warning => "WARNING",
        LogLevel::Error => "ERROR",
    }
}

/// Proleptic-Gregorian civil date from days since 1970-01-01 (Howard
/// Hinnant's `civil_from_days`). Returns `(year, month 1-12, day 1-31)`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (year + i64::from(month <= 2), month as u32, day as u32)
}

/// RFC 3164 `TIMESTAMP` (UTC): `Mmm dd HH:MM:SS` with a space-padded day
/// (`Jul  2`, `Jul 22`).
fn format_timestamp(time: SystemTime) -> String {
    let secs = match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs() as i64,
        Err(before_epoch) => -(before_epoch.duration().as_secs() as i64),
    };
    let (_, month, day) = civil_from_days(secs.div_euclid(86_400));
    let time_of_day = secs.rem_euclid(86_400);
    format!(
        "{} {:2} {:02}:{:02}:{:02}",
        MONTH_ABBREVIATIONS[(month - 1) as usize],
        day,
        time_of_day / 3_600,
        (time_of_day % 3_600) / 60,
        time_of_day % 60
    )
}

/// A leveled logger writing RFC 3164 datagrams to `/dev/log` when
/// connected, and lines to stderr otherwise.
#[derive(Debug)]
pub struct Logger {
    name: String,
    level: LogLevel,
    pid: u32,
    syslog: Option<UnixDatagram>,
}

impl Logger {
    /// A stderr-only logger (the fallback Python uses when syslog is not
    /// reachable, and the right choice for tests and one-shot tools).
    pub fn new(name: &str, level: LogLevel) -> Arc<Logger> {
        Arc::new(Logger {
            name: name.to_string(),
            level,
            pid: std::process::id(),
            syslog: None,
        })
    }

    /// Try to connect a unix datagram socket to `/dev/log` once; fall back
    /// to stderr silently when the socket is missing (as on macOS) or the
    /// connect fails.
    pub fn with_syslog(name: &str, level: LogLevel) -> Arc<Logger> {
        let syslog = UnixDatagram::unbound()
            .ok()
            .and_then(|socket| socket.connect(SYSLOG_PATH).ok().map(|()| socket));
        Arc::new(Logger {
            name: name.to_string(),
            level,
            pid: std::process::id(),
            syslog,
        })
    }

    fn enabled(&self, level: LogLevel) -> bool {
        level >= self.level
    }

    fn log(&self, level: LogLevel, msg: &str) {
        if !self.enabled(level) {
            return;
        }
        let timestamp = format_timestamp(SystemTime::now());
        let label = level_label(level);
        if let Some(socket) = &self.syslog {
            let line = format!(
                "<{}>{} {}[{}]: {} {}",
                pri(level),
                timestamp,
                self.name,
                self.pid,
                label,
                msg
            );
            if socket.send(line.as_bytes()).is_ok() {
                return;
            }
        }
        eprintln!(
            "{} {}[{}]: {} {}",
            timestamp, self.name, self.pid, label, msg
        );
    }

    pub fn debug(&self, msg: &str) {
        self.log(LogLevel::Debug, msg);
    }

    pub fn info(&self, msg: &str) {
        self.log(LogLevel::Info, msg);
    }

    pub fn warning(&self, msg: &str) {
        self.log(LogLevel::Warning, msg);
    }

    pub fn error(&self, msg: &str) {
        self.log(LogLevel::Error, msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn from_str_is_case_insensitive_and_defaults_to_info() {
        for (text, level) in [
            ("debug", LogLevel::Debug),
            ("DEBUG", LogLevel::Debug),
            ("info", LogLevel::Info),
            ("Info", LogLevel::Info),
            ("warning", LogLevel::Warning),
            ("WaRnInG", LogLevel::Warning),
            ("error", LogLevel::Error),
            ("ERROR", LogLevel::Error),
            (" info ", LogLevel::Info),
            ("notice", LogLevel::Info),
            ("", LogLevel::Info),
        ] {
            assert_eq!(text.parse::<LogLevel>(), Ok(level), "parsing {text:?}");
        }
        assert_eq!(LogLevel::default(), LogLevel::Info);
    }

    #[test]
    fn pri_is_local0_times_eight_plus_severity() {
        assert_eq!(pri(LogLevel::Debug), 135);
        assert_eq!(pri(LogLevel::Info), 134);
        assert_eq!(pri(LogLevel::Warning), 132);
        assert_eq!(pri(LogLevel::Error), 131);
    }

    #[test]
    fn timestamps_match_known_utc_instants() {
        for (secs, expected) in [
            (0u64, "Jan  1 00:00:00"),
            (951_782_400, "Feb 29 00:00:00"), // 2000 leap day
            (1_000_000_000, "Sep  9 01:46:40"),
            (1_609_459_200, "Jan  1 00:00:00"), // 2021-01-01
        ] {
            assert_eq!(
                format_timestamp(UNIX_EPOCH + Duration::from_secs(secs)),
                expected,
                "epoch seconds {secs}"
            );
        }
    }

    #[test]
    fn month_abbreviation_table_covers_all_twelve_months() {
        // The 15th of each month of 2023, 00:00:00 UTC.
        let month_starts: [(u64, &str); 12] = [
            (1_673_740_800, "Jan"),
            (1_676_419_200, "Feb"),
            (1_678_838_400, "Mar"),
            (1_681_516_800, "Apr"),
            (1_684_108_800, "May"),
            (1_686_787_200, "Jun"),
            (1_689_379_200, "Jul"),
            (1_692_057_600, "Aug"),
            (1_694_736_000, "Sep"),
            (1_697_328_000, "Oct"),
            (1_700_006_400, "Nov"),
            (1_702_598_400, "Dec"),
        ];
        for (secs, month) in month_starts {
            let formatted = format_timestamp(UNIX_EPOCH + Duration::from_secs(secs));
            assert_eq!(formatted, format!("{month} 15 00:00:00"));
        }
    }

    #[test]
    fn civil_from_days_handles_pre_epoch_days() {
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn level_filter_gates_each_method() {
        let logger = Logger::new("srv", LogLevel::Warning);
        assert!(!logger.enabled(LogLevel::Debug));
        assert!(!logger.enabled(LogLevel::Info));
        assert!(logger.enabled(LogLevel::Warning));
        assert!(logger.enabled(LogLevel::Error));
        let verbose = Logger::new("srv", LogLevel::Debug);
        assert!(verbose.enabled(LogLevel::Debug));
    }

    #[test]
    fn syslog_datagrams_carry_pri_tag_pid_and_level() {
        let path = std::env::temp_dir().join(format!("swift-obslog-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let sender = UnixDatagram::unbound().unwrap();
        sender.connect(&path).unwrap();
        let logger = Logger {
            name: "object-replicator".to_string(),
            level: LogLevel::Info,
            pid: 42,
            syslog: Some(sender),
        };

        logger.debug("filtered out"); // below Info: no datagram
        logger.warning("disk full");

        let mut buffer = [0u8; 1024];
        let read = receiver.recv(&mut buffer).unwrap();
        let line = std::str::from_utf8(&buffer[..read]).unwrap();
        assert!(line.starts_with("<132>"), "line: {line}");
        assert!(
            line.ends_with(" object-replicator[42]: WARNING disk full"),
            "line: {line}"
        );
        // "<132>Mmm dd HH:MM:SS ..." carries a space-padded RFC 3164 date.
        let timestamp = &line[5..20];
        assert!(
            MONTH_ABBREVIATIONS.contains(&&timestamp[..3]),
            "timestamp: {timestamp}"
        );

        // The filtered debug message never arrived: the warning line was the
        // first datagram, and nothing else is queued behind it.
        receiver.set_nonblocking(true).unwrap();
        assert_eq!(
            receiver.recv(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(receiver);
        let _ = std::fs::remove_file(&path);
    }
}
