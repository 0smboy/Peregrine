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

//! Coarse request-path stage timers for the Profile Cartographer.
//!
//! Each call records wall time against `(service, path, stage)`. Totals are
//! process-local so a Lab can scrape `/recon/stage` without depending on a
//! Prometheus histogram exporter. StatsD timings are optional.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use crate::StatsdClient;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct Key {
    service: &'static str,
    path: &'static str,
    stage: &'static str,
}

#[derive(Clone, Debug, Default)]
struct Acc {
    sum_secs: f64,
    count: u64,
}

static REG: OnceLock<Mutex<HashMap<Key, Acc>>> = OnceLock::new();

fn reg() -> &'static Mutex<HashMap<Key, Acc>> {
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record one stage observation.
pub fn observe(service: &'static str, path: &'static str, stage: &'static str, secs: f64) {
    if secs < 0.0 || !secs.is_finite() {
        return;
    }
    if let Ok(mut g) = reg().lock() {
        let e = g.entry(Key {
            service,
            path,
            stage,
        }).or_default();
        e.sum_secs += secs;
        e.count = e.count.saturating_add(1);
    }
}

/// Record + emit a StatsD timing (milliseconds).
pub fn observe_statsd(
    statsd: &StatsdClient,
    service: &'static str,
    path: &'static str,
    stage: &'static str,
    secs: f64,
) {
    observe(service, path, stage, secs);
    statsd.timing(
        &format!("stage.{service}.{path}.{stage}"),
        secs * 1000.0,
    );
}

/// RAII timer that calls [`observe`] on drop.
pub struct StageTimer {
    service: &'static str,
    path: &'static str,
    stage: &'static str,
    start: Instant,
}

impl StageTimer {
    pub fn start(service: &'static str, path: &'static str, stage: &'static str) -> Self {
        Self {
            service,
            path,
            stage,
            start: Instant::now(),
        }
    }
}

impl Drop for StageTimer {
    fn drop(&mut self) {
        observe(
            self.service,
            self.path,
            self.stage,
            self.start.elapsed().as_secs_f64(),
        );
    }
}

/// Snapshot for `/recon/stage` and Lab gather.
pub fn snapshot() -> Vec<serde_json::Value> {
    let g = match reg().lock() {
        Ok(g) => g,
        Err(_) => return vec![],
    };
    let mut out: Vec<serde_json::Value> = g
        .iter()
        .map(|(k, a)| {
            serde_json::json!({
                "service": k.service,
                "path": k.path,
                "stage": k.stage,
                "sum_seconds": a.sum_secs,
                "count": a.count,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        let sa = a.get("service").and_then(|x| x.as_str()).unwrap_or("");
        let sb = b.get("service").and_then(|x| x.as_str()).unwrap_or("");
        sa.cmp(sb)
            .then_with(|| {
                a.get("path")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .cmp(b.get("path").and_then(|x| x.as_str()).unwrap_or(""))
            })
            .then_with(|| {
                a.get("stage")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .cmp(b.get("stage").and_then(|x| x.as_str()).unwrap_or(""))
            })
    });
    out
}

pub fn snapshot_json() -> String {
    serde_json::to_string(&serde_json::json!({ "stages": snapshot() })).unwrap_or_else(|_| {
        "{\"stages\":[]}".into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_accumulates() {
        observe("proxy-server", "put", "test_stage_unit", 0.01);
        observe("proxy-server", "put", "test_stage_unit", 0.02);
        let hit = snapshot().into_iter().find(|v| {
            v.get("stage").and_then(|x| x.as_str()) == Some("test_stage_unit")
        });
        let hit = hit.expect("stage present");
        assert_eq!(hit.get("count").and_then(|x| x.as_u64()), Some(2));
        let sum = hit.get("sum_seconds").and_then(|x| x.as_f64()).unwrap();
        assert!((sum - 0.03).abs() < 1e-9);
    }
}
