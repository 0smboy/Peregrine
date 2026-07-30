//! Parse cabt task names: 64KB_write_100

use anyhow::{bail, Context, Result};
use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct TaskSpec {
    pub name: String,
    pub size_bytes: u64,
    pub size_label: String,
    pub method: Method,
    pub workers: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Read,
    Write,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Read => "read",
            Method::Write => "write",
        }
    }
}

fn re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(\d+)([kmg]b)_(write|read)_(\d+)$").expect("task regex")
    })
}

pub fn parse_task(name: &str) -> Result<TaskSpec> {
    let caps = re()
        .captures(name)
        .with_context(|| format!("invalid task name `{name}`, expected like 64KB_write_100"))?;
    let num: u64 = caps[1].parse()?;
    let unit = caps[2].to_ascii_uppercase();
    let size_bytes = match unit.as_str() {
        "KB" => num * 1024,
        "MB" => num * 1024 * 1024,
        "GB" => num * 1024 * 1024 * 1024,
        _ => bail!("unknown size unit {unit}"),
    };
    let method = match caps[3].to_ascii_lowercase().as_str() {
        "read" => Method::Read,
        "write" => Method::Write,
        _ => bail!("method must be read or write"),
    };
    let workers: u32 = caps[4].parse()?;
    Ok(TaskSpec {
        name: name.to_string(),
        size_bytes,
        size_label: format!("{num}{unit}"),
        method,
        workers,
    })
}

/// Default prepare knobs from original cabt README / fool_job.
pub fn fool_defaults(size_label: &str) -> (u64, u32) {
    // (object_count, prepare_workers)
    let s = size_label.to_ascii_uppercase();
    if s.starts_with("100MB") {
        (500, 100)
    } else if s.starts_with("10MB") {
        (5000, 300)
    } else {
        // 64KB default
        (10000, 1500)
    }
}

pub const FOOL_SUITE: &[&str] = &[
    "64KB_read_1",
    "10MB_read_1",
    "100MB_read_1",
    "64KB_write_1",
    "10MB_write_1",
    "100MB_write_1",
    "64KB_read_100",
    "64KB_read_500",
    "64KB_read_1000",
    "64KB_read_1500",
    "64KB_read_2000",
    "64KB_write_100",
    "64KB_write_500",
    "64KB_write_1000",
    "64KB_write_1500",
    "64KB_write_2000",
    "10MB_read_50",
    "10MB_read_100",
    "10MB_read_200",
    "10MB_read_500",
    "10MB_read_1000",
    "10MB_write_50",
    "10MB_write_100",
    "10MB_write_200",
    "10MB_write_500",
    "10MB_write_1000",
    "100MB_read_15",
    "100MB_read_20",
    "100MB_read_30",
    "100MB_read_50",
    "100MB_read_100",
    "100MB_write_15",
    "100MB_write_20",
    "100MB_write_30",
    "100MB_write_50",
    "100MB_write_100",
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_ok() {
        let t = parse_task("64KB_write_100").unwrap();
        assert_eq!(t.size_bytes, 64 * 1024);
        assert_eq!(t.workers, 100);
        assert_eq!(t.method, Method::Write);
    }
}
