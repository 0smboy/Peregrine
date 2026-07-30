//! Tombstone Museum: one object's life and death, read back off the disks.
//!
//! Every file Swift lays down carries two independent clocks. The FILENAME
//! timestamp is the client's write — the same on every node that ever holds
//! that version, so it is cluster-wide truth. The file's CTIME is when *this*
//! node actually took it. On a healthy cluster the two agree to the second;
//! the gap between them is the story. A copy that landed an hour late is a node
//! that was behind, and a tombstone that never landed at all is a delete that
//! did not finish.
//!
//! It has to be ctime and not mtime. Replication copies a file with its
//! modification time intact, so a replica pulled across an hour later still
//! carries the original write's mtime and looks perfectly punctual — the very
//! case this page exists to catch. Ctime is stamped by the local filesystem
//! when the inode is written and cannot be carried over the wire, so it is the
//! only honest answer to "when did THIS node get it". Both are reported; only
//! ctime is believed.
//!
//! Nothing here writes. Forensics are `stat` over ssh, node availability comes
//! from the metrics backend as *intervals* rather than instants (a delete only
//! makes sense against the window a node was gone for, not against a point),
//! and the log backend is consulted last and reported as empty when it has
//! nothing — an invented source is worse than a missing one.

use crate::i18n;
use crate::lab;
use crate::monitor;
use crate::nodes;
use crate::ringlab::{self, PolicyInfo};
use crate::session;
use crate::util::{enc_obj, enc_seg, esc, fmt_bytes};
use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A filename-to-mtime gap this wide means the copy did not land with the
/// write; below it, clock skew and fsync latency dominate and there is nothing
/// to report.
const LAG_WARN_SECS: f64 = 60.0;

/// How long after a tombstone an outage still counts as "after the delete".
const DELETE_WINDOW_SECS: f64 = 300.0;

/// Window padding around the object's own events, and the ceiling on it. A very
/// old object would otherwise ask the metrics backend for months of samples to
/// answer a question about one minute.
const WINDOW_LEAD: i64 = 600;
const WINDOW_TRAIL: i64 = 1800;
const WINDOW_MAX: i64 = 24 * 3600;

const MAX_LOG_LINES: u32 = 120;

// ------------------------------------------------------------- file grammar

/// One on-disk filename decoded. Kind is the extension; EC data additionally
/// carries `#<fragment index>` and, once committed, `#d`.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Parsed {
    pub ts: String,
    pub ts_secs: f64,
    /// "data" | "tombstone" | "meta" | "durable"
    pub kind: String,
    pub frag_index: Option<u32>,
    pub durable: bool,
}

/// Decode `<ts>.data`, `<ts>#<fi>#d.data`, `<ts>.ts`, `<ts>.meta`. Returns
/// `None` for anything else, which is how partial writes (`.tmp`) and stray
/// files stay out of the timeline instead of becoming fictional events.
pub fn parse_name(name: &str) -> Option<Parsed> {
    let (stem, ext) = name.rsplit_once('.')?;
    let kind = match ext {
        "data" => "data",
        "ts" => "tombstone",
        "meta" => "meta",
        "durable" => "durable",
        _ => return None,
    };
    let mut frag = None;
    // A plain replica is durable by existing; an EC fragment only once it
    // carries the commit marker.
    let mut durable = true;
    let mut ts = stem;
    if let Some((head, rest)) = stem.split_once('#') {
        ts = head;
        let mut parts = rest.split('#');
        frag = parts.next().and_then(|s| s.parse::<u32>().ok());
        frag?;
        durable = parts.next() == Some("d");
    }
    // A .meta may carry an `_<offset>` suffix that is not part of the clock.
    let ts = ts.split('_').next().unwrap_or(ts);
    let ts_secs: f64 = ts.parse().ok()?;
    Some(Parsed {
        ts: ts.to_string(),
        ts_secs,
        kind: kind.to_string(),
        frag_index: frag,
        durable,
    })
}

// ------------------------------------------------------------- shapes

#[derive(Serialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot {
    pub node: String,
    pub device: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct DiskFile {
    pub node: String,
    pub device: String,
    pub name: String,
    pub kind: String,
    /// The client's write, from the filename.
    pub ts: String,
    pub ts_secs: f64,
    /// The file's modification time. Preserved across replication, so it
    /// normally just echoes the filename and is kept for the record only.
    pub mtime: i64,
    /// When this node's copy came into being. The one that is believed.
    pub received: i64,
    pub lag_secs: f64,
    pub size: u64,
    pub frag_index: Option<u32>,
    pub durable: bool,
    pub handoff: bool,
}

impl DiskFile {
    fn slot(&self) -> Slot {
        Slot {
            node: self.node.clone(),
            device: self.device.clone(),
        }
    }
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct OfflineSpan {
    pub node: String,
    pub from: i64,
    pub to: i64,
    pub secs: i64,
}

#[derive(Serialize, Clone, Debug)]
pub struct LogLine {
    pub t: i64,
    pub node: String,
    pub unit: String,
    pub line: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Anomaly {
    pub rule: &'static str,
    /// "bad" | "warn"
    pub severity: &'static str,
    pub headline: String,
    pub detail: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct Lane {
    pub id: String,
    pub label: String,
    /// "client" | "node"
    pub role: &'static str,
    pub primary: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct Event {
    pub lane: String,
    pub t: f64,
    /// "write" | "delete" | "meta" | "durable"
    pub kind: String,
    pub label: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct PolicyBrief {
    pub index: u32,
    pub name: String,
    pub kind: String,
    pub ndata: Option<u32>,
    pub nparity: Option<u32>,
    pub replicas: u32,
}

#[derive(Serialize, Clone, Debug)]
pub struct Window {
    pub start: i64,
    pub end: i64,
    /// Set when the object's own history is older than the ceiling, so a reader
    /// knows an absent outage may simply be out of view.
    pub truncated: bool,
}

#[derive(Serialize, Clone)]
pub struct Report {
    pub account: String,
    pub container: String,
    pub object: String,
    pub policy: PolicyBrief,
    pub partition: u32,
    pub hash: String,
    pub primaries: Vec<Slot>,
    pub files: Vec<DiskFile>,
    pub offline: Vec<OfflineSpan>,
    pub logs: Vec<LogLine>,
    pub logs_note: String,
    pub anomalies: Vec<Anomaly>,
    pub final_state: &'static str,
    pub delete_ts: Option<f64>,
    pub lanes: Vec<Lane>,
    pub events: Vec<Event>,
    pub window: Window,
    /// Nodes that did not answer the disk probe: their files are unknown, not
    /// absent, and every count below is a lower bound because of it.
    pub unreachable: Vec<String>,
}

// ------------------------------------------------------------- formatting

fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Civil UTC. The report is read beside `journalctl`, which is UTC on these
/// hosts, so rendering local time would silently misalign the two.
pub fn fmt_utc(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil(days);
    format!(
        "{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}Z",
        h = rem / 3600,
        mi = (rem % 3600) / 60,
        s = rem % 60
    )
}

/// A duration in the words an operator would use out loud.
pub fn fmt_dur(lang: &str, secs: f64) -> String {
    let s = secs.max(0.0);
    if s < 90.0 {
        return i18n::t(lang, "tmb.dur.s").replace("{n}", &(s.round() as i64).to_string());
    }
    if s < 5400.0 {
        return i18n::t(lang, "tmb.dur.m").replace("{n}", &((s / 60.0).round() as i64).to_string());
    }
    i18n::t(lang, "tmb.dur.h").replace("{n}", &format!("{:.1}", s / 3600.0))
}

// ------------------------------------------------------------- disk forensics

/// Which nodes to probe: every configured node, plus any node the ring places
/// this object on. The two are normally the same set, but a device added to the
/// ring before the console's config caught up would otherwise be skipped — and
/// skipped silently, which is the failure mode that makes a forensic tool lie.
fn probe_nodes(state: &Arc<AppState>, placed: &[ringlab::PlacedNode]) -> Vec<String> {
    let mut names: Vec<String> = nodes::all(state).into_iter().map(|n| n.name).collect();
    for p in placed {
        if !names.contains(&p.node) {
            names.push(p.node.clone());
        }
    }
    names
}

/// `stat` every file in the object's hash directory, on every device of every
/// node. The path is fixed once the partition and hash are known, so this is
/// one glob per node rather than a walk — and the glob covers devices the
/// console was never told about, which is how a copy stranded on a handoff is
/// found at all.
async fn scan(
    state: &Arc<AppState>,
    policy: &PolicyInfo,
    part: u32,
    hash: &str,
    names: &[String],
) -> Result<(Vec<DiskFile>, Vec<String>), String> {
    // Everything interpolated below is derived, not supplied: the hash comes
    // from the ring CLI and the data directory from swift.conf. Checked anyway,
    // because a shell command assembled from values that "cannot" be wrong is
    // exactly the one that eventually is.
    if hash.len() != 32 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("unexpected object hash".into());
    }
    if !policy
        .data_dir
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("unexpected policy data directory".into());
    }
    let root = state.cfg.node_root.trim_end_matches('/');
    let suffix = &hash[29..];
    let remote = format!(
        "for f in {root}/*/{dir}/{part}/{suffix}/{hash}/*; do [ -e \"$f\" ] || continue; \
         stat -c '%n|%Y|%Z|%s' \"$f\"; done",
        dir = policy.data_dir
    );
    let results = nodes::fan_out_on(state, names, &remote).await;
    let mut files = Vec::new();
    let mut unreachable = Vec::new();
    for r in results {
        if !r.ok {
            unreachable.push(r.node);
            continue;
        }
        for line in r.out.lines() {
            let mut parts = line.trim().splitn(4, '|');
            let (Some(path), Some(mtime), Some(ctime), Some(size)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let rel = match path.strip_prefix(root).and_then(|p| p.strip_prefix('/')) {
                Some(v) => v,
                None => continue,
            };
            let device = rel.split('/').next().unwrap_or("").to_string();
            let name = path.rsplit('/').next().unwrap_or("").to_string();
            let Some(p) = parse_name(&name) else { continue };
            let mtime: i64 = mtime.parse().unwrap_or(0);
            let received: i64 = ctime.parse().unwrap_or(0);
            files.push(DiskFile {
                node: r.node.clone(),
                device,
                name,
                kind: p.kind,
                ts: p.ts,
                ts_secs: p.ts_secs,
                mtime,
                received,
                lag_secs: received as f64 - p.ts_secs,
                size: size.parse().unwrap_or(0),
                frag_index: p.frag_index,
                durable: p.durable,
                handoff: false,
            });
        }
    }
    files.sort_by(|a, b| {
        a.ts_secs
            .partial_cmp(&b.ts_secs)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.node.cmp(&b.node))
            .then_with(|| a.device.cmp(&b.device))
    });
    Ok((files, unreachable))
}

// ------------------------------------------------------------- availability

/// Contiguous stretches where a node reported down.
///
/// A node counts as offline only when *nothing* on it answered — one exporter
/// missing is a service gap, not an outage, and calling it one would put a node
/// in the dock for a delete it actually took. The caller therefore hands in the
/// per-timestamp maximum across that node's targets. A lone missed scrape is
/// noise as well, so a span needs at least two consecutive down samples; the
/// end is carried one step past the last of them, which is the honest bound
/// given the sampling resolution.
pub fn offline_spans(node: &str, samples: &[(i64, Option<f64>)], step: i64) -> Vec<OfflineSpan> {
    let mut out: Vec<OfflineSpan> = Vec::new();
    let mut run: Vec<i64> = Vec::new();
    let flush = |run: &mut Vec<i64>, out: &mut Vec<OfflineSpan>| {
        if run.len() >= 2 {
            let from = run[0];
            let to = run[run.len() - 1] + step;
            out.push(OfflineSpan {
                node: node.to_string(),
                from,
                to,
                secs: to - from,
            });
        }
        run.clear();
    };
    for (t, v) in samples {
        match v {
            Some(v) if *v == 0.0 => run.push(*t),
            _ => flush(&mut run, &mut out),
        }
    }
    flush(&mut run, &mut out);
    out
}

/// Every node's up/down history over the window, folded into intervals.
async fn availability(state: &Arc<AppState>, w: &Window, step: i64) -> Vec<OfflineSpan> {
    let data = match monitor::q_range(state, "max by (instance) (up)", w.start, w.end, step).await {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    // One series per scrape target; the label carries the host, so several
    // series fold onto one node and the node is down only where all of them are.
    let mut merged: BTreeMap<String, BTreeMap<i64, f64>> = BTreeMap::new();
    for s in monitor::parse_matrix("@instance", &data) {
        let host = s.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let node = nodes::label(state, host);
        let by_t = merged.entry(node).or_default();
        for p in s.get("points").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
            let (Some(t), Some(v)) = (
                p.get(0).and_then(|x| x.as_f64()),
                p.get(1).and_then(|x| x.as_f64()),
            ) else {
                continue;
            };
            let e = by_t.entry(t as i64).or_insert(0.0);
            *e = e.max(v);
        }
    }
    let mut out = Vec::new();
    for (node, by_t) in merged {
        let samples: Vec<(i64, Option<f64>)> = by_t.into_iter().map(|(t, v)| (t, Some(v))).collect();
        out.extend(offline_spans(&node, &samples, step));
    }
    out.sort_by_key(|s| s.from);
    out
}

// ------------------------------------------------------------- logs

fn log_needle(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Object-server, replicator and reconstructor lines that name this object, and
/// failing that its partition. Returns an empty list and a plain note when
/// nothing matched, rather than dressing unrelated lines up as evidence.
async fn fetch_logs(
    state: &Arc<AppState>,
    lang: &str,
    account: &str,
    container: &str,
    object: &str,
    part: u32,
    w: &Window,
) -> (Vec<LogLine>, String) {
    let by_path = format!(
        "{{unit=~\"swift-object.*\"}} |= \"{}\"",
        log_needle(&format!("{account}/{container}/{object}"))
    );
    let mut note = String::new();
    let mut lines = collect_logs(state, &by_path, w).await;
    if lines.is_empty() {
        let by_part = format!("{{unit=~\"swift-object.*\"}} |= \"/{part}/\"");
        lines = collect_logs(state, &by_part, w).await;
        note = if lines.is_empty() {
            i18n::t(lang, "tmb.logs.none").to_string()
        } else {
            i18n::t(lang, "tmb.logs.bypart").replace("{p}", &part.to_string())
        };
    }
    (lines, note)
}

async fn collect_logs(state: &Arc<AppState>, query: &str, w: &Window) -> Vec<LogLine> {
    let raw = match monitor::q_logs(state, query, w.start, w.end, MAX_LOG_LINES).await {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<LogLine> = raw
        .iter()
        .map(|v| LogLine {
            t: v.get("t").and_then(|x| x.as_i64()).unwrap_or(0),
            node: nodes::label(state, v.get("host").and_then(|x| x.as_str()).unwrap_or("")),
            unit: v
                .get("unit")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim_end_matches(".service")
                .to_string(),
            line: v.get("line").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        })
        .collect();
    out.sort_by_key(|l| l.t);
    out
}

// ------------------------------------------------------------- autopsy

pub struct Facts<'a> {
    pub files: &'a [DiskFile],
    pub primaries: &'a [Slot],
    pub offline: &'a [OfflineSpan],
    pub is_ec: bool,
    pub ndata: u32,
    pub nparity: u32,
    pub replicas: u32,
}

fn newest(files: &[DiskFile], kind: &str) -> Option<f64> {
    files
        .iter()
        .filter(|f| f.kind == kind)
        .map(|f| f.ts_secs)
        .fold(None, |acc: Option<f64>, v| Some(acc.map_or(v, |a| a.max(v))))
}

/// What goes between two finished sentences. English needs a space; Chinese
/// sentences already end in a full-width stop, and a space after one reads as
/// a typo rather than as punctuation.
fn gap(lang: &str) -> &'static str {
    if lang == "zh" {
        ""
    } else {
        " "
    }
}

fn slot_list(slots: &[Slot]) -> String {
    slots
        .iter()
        .map(|s| format!("{}/{}", s.node, s.device))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The rules, the one-word verdict on the object, and the sentence that names
/// what killed it.
///
/// Each rule answers a question an operator would otherwise reconstruct by
/// hand from four `ls -l` outputs and a `journalctl`; the sentence matters as
/// much as the flag, because a rule name nobody can read is a rule nobody acts
/// on. Every string comes from the key table, so the finding is the same in
/// both languages and only the words change.
pub fn autopsy(lang: &str, f: &Facts) -> (Vec<Anomaly>, &'static str) {
    let mut out: Vec<Anomaly> = Vec::new();
    let delete_ts = newest(f.files, "tombstone");
    let newest_data = newest(f.files, "data");
    let unit = if f.is_ec {
        i18n::t(lang, "tmb.unit.frag")
    } else {
        i18n::t(lang, "tmb.unit.copy")
    };

    // ---- the delete did not reach every primary ----
    if let Some(d) = delete_ts {
        let missing: Vec<Slot> = f
            .primaries
            .iter()
            .filter(|s| {
                !f.files
                    .iter()
                    .any(|x| x.kind == "tombstone" && x.ts_secs >= d && &x.slot() == *s)
            })
            .cloned()
            .collect();
        if !missing.is_empty() {
            out.push(Anomaly {
                rule: "tombstone_incomplete",
                severity: "bad",
                headline: i18n::t(lang, "tmb.a.incomplete.h")
                    .replace("{got}", &(f.primaries.len() - missing.len()).to_string())
                    .replace("{want}", &f.primaries.len().to_string()),
                detail: i18n::t(lang, "tmb.a.incomplete.d")
                    .replace("{t}", &fmt_utc(d as i64))
                    .replace("{where}", &slot_list(&missing)),
            });
        }
    }

    // ---- data newer than a tombstone ----
    if let (Some(d), Some(n)) = (delete_ts, newest_data) {
        if n > d {
            let where_: Vec<Slot> = f
                .files
                .iter()
                .filter(|x| x.kind == "data" && x.ts_secs > d)
                .map(|x| x.slot())
                .collect();
            out.push(Anomaly {
                rule: "resurrection",
                severity: "bad",
                headline: i18n::t(lang, "tmb.a.resurrection.h").to_string(),
                detail: i18n::t(lang, "tmb.a.resurrection.d")
                    .replace("{del}", &fmt_utc(d as i64))
                    .replace("{wrote}", &fmt_utc(n as i64))
                    .replace("{where}", &slot_list(&where_)),
            });
        }
    }

    // ---- a copy that landed long after the write ----
    let mut lagging: Vec<&DiskFile> = f
        .files
        .iter()
        .filter(|x| x.lag_secs > LAG_WARN_SECS)
        .collect();
    lagging.sort_by(|a, b| {
        b.lag_secs
            .partial_cmp(&a.lag_secs)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if let Some(worst) = lagging.first() {
        let rest = if lagging.len() > 1 {
            format!(
                "{}{}",
                gap(lang),
                i18n::t(lang, "tmb.a.lag.rest").replace("{n}", &lagging.len().to_string())
            )
        } else {
            String::new()
        };
        out.push(Anomaly {
            rule: "replica_lag",
            severity: "warn",
            headline: i18n::t(lang, "tmb.a.lag.h")
                .replace("{node}", &worst.node)
                .replace("{unit}", unit)
                .replace("{dur}", &fmt_dur(lang, worst.lag_secs)),
            detail: format!(
                "{}{rest}",
                i18n::t(lang, "tmb.a.lag.d")
                    .replace("{wrote}", &fmt_utc(worst.ts_secs as i64))
                    .replace("{node}", &worst.node)
                    .replace("{dev}", &worst.device)
                    .replace("{got}", &fmt_utc(worst.received))
            ),
        });
    }

    // ---- a primary that was gone when the delete happened ----
    if let Some(d) = delete_ts {
        for s in f.offline {
            if !f.primaries.iter().any(|p| p.node == s.node) {
                continue;
            }
            if (s.to as f64) < d || s.from as f64 > d + DELETE_WINDOW_SECS {
                continue;
            }
            let has_ts = f
                .files
                .iter()
                .any(|x| x.kind == "tombstone" && x.node == s.node && x.ts_secs >= d);
            let head_key = if (s.from as f64) < d {
                "tmb.a.offline.during.h"
            } else {
                "tmb.a.offline.after.h"
            };
            out.push(Anomaly {
                rule: "node_offline_after_delete",
                severity: if has_ts { "warn" } else { "bad" },
                headline: i18n::t(lang, head_key)
                    .replace("{node}", &s.node)
                    .replace("{dur}", &fmt_dur(lang, s.secs as f64)),
                detail: format!(
                    "{}{}{}",
                    i18n::t(lang, "tmb.a.offline.d")
                        .replace("{from}", &fmt_utc(s.from))
                        .replace("{to}", &fmt_utc(s.to))
                        .replace("{del}", &fmt_utc(d as i64)),
                    gap(lang),
                    i18n::t(
                        lang,
                        if has_ts {
                            "tmb.a.offline.caught"
                        } else {
                            "tmb.a.offline.missed"
                        }
                    )
                ),
            });
        }
    }

    // ---- data on a node the ring does not place it on ----
    let stray_files: Vec<&DiskFile> = f.files.iter().filter(|x| x.handoff).collect();
    if !stray_files.is_empty() {
        // A stray tombstone and a stray replica mean opposite things — one is a
        // delete still trying to land, the other is data that outlived its home
        // — so the sentence has to say which it found.
        let all_ts = stray_files.iter().all(|x| x.kind == "tombstone");
        let strays: Vec<Slot> = stray_files.iter().map(|x| x.slot()).collect();
        out.push(Anomaly {
            rule: "on_handoff",
            severity: "warn",
            headline: i18n::t(
                lang,
                if all_ts {
                    "tmb.a.handoff.ts.h"
                } else {
                    "tmb.a.handoff.data.h"
                },
            )
            .to_string(),
            detail: format!(
                "{}{}{}",
                i18n::t(lang, "tmb.a.handoff.d").replace("{where}", &slot_list(&strays)),
                gap(lang),
                i18n::t(
                    lang,
                    if all_ts {
                        "tmb.a.handoff.tail.ts"
                    } else {
                        "tmb.a.handoff.tail.plain"
                    }
                )
            ),
        });
    }

    // ---- too few copies, or too few distinct fragments ----
    let deleted = matches!(delete_ts, Some(d) if newest_data.map_or(true, |n| n <= d));
    if !deleted {
        if let Some(n) = newest_data {
            let live: Vec<&DiskFile> = f
                .files
                .iter()
                .filter(|x| x.kind == "data" && x.ts_secs == n)
                .collect();
            if f.is_ec {
                let mut frags: Vec<u32> = live.iter().filter_map(|x| x.frag_index).collect();
                frags.sort_unstable();
                frags.dedup();
                let want = f.ndata + f.nparity;
                if (frags.len() as u32) < want {
                    let readable = frags.len() as u32 >= f.ndata;
                    out.push(Anomaly {
                        rule: "frag_deficit",
                        severity: if readable { "warn" } else { "bad" },
                        headline: i18n::t(lang, "tmb.a.frag.h")
                            .replace("{got}", &frags.len().to_string())
                            .replace("{want}", &want.to_string()),
                        detail: format!(
                            "{}{}{}",
                            i18n::t(lang, "tmb.a.frag.d")
                                .replace("{k}", &f.ndata.to_string())
                                .replace("{m}", &f.nparity.to_string())
                                .replace("{got}", &frags.len().to_string()),
                            gap(lang),
                            i18n::t(
                                lang,
                                if readable {
                                    "tmb.a.frag.readable"
                                } else {
                                    "tmb.a.frag.unreadable"
                                }
                            )
                        ),
                    });
                }
            } else {
                let mut slots: Vec<Slot> = live.iter().map(|x| x.slot()).collect();
                slots.sort();
                slots.dedup();
                if (slots.len() as u32) < f.replicas {
                    let quorum = f.replicas / 2 + 1;
                    out.push(Anomaly {
                        rule: "under_replicated",
                        severity: if (slots.len() as u32) < quorum { "bad" } else { "warn" },
                        headline: i18n::t(lang, "tmb.a.under.h")
                            .replace("{got}", &slots.len().to_string())
                            .replace("{want}", &f.replicas.to_string()),
                        detail: i18n::t(lang, "tmb.a.under.d")
                            .replace("{t}", &fmt_utc(n as i64))
                            .replace("{where}", &slot_list(&slots)),
                    });
                }
            }
        }
    }

    // Worst first: an operator reads the top of this list and stops.
    out.sort_by_key(|a| if a.severity == "bad" { 0 } else { 1 });

    let state = if f.files.is_empty() {
        "lost"
    } else if let Some(d) = delete_ts {
        if newest_data.is_some_and(|n| n > d) {
            "resurrected"
        } else if newest_data.is_none()
            && f.primaries.iter().all(|s| {
                f.files
                    .iter()
                    .any(|x| x.kind == "tombstone" && x.ts_secs >= d && &x.slot() == s)
            })
        {
            "deleted_clean"
        } else {
            "deleted_incomplete"
        }
    } else {
        "present"
    };
    (out, state)
}

/// The one-line verdict: the i18n key for the state word, and its tone.
pub fn state_words(state: &str) -> (&'static str, &'static str) {
    match state {
        "present" => ("tmb.state.present", "ok"),
        "deleted_clean" => ("tmb.state.deleted_clean", "ok"),
        "deleted_incomplete" => ("tmb.state.deleted_incomplete", "bad"),
        "resurrected" => ("tmb.state.resurrected", "bad"),
        _ => ("tmb.state.lost", "bad"),
    }
}

/// The cause of death, named out loud.
///
/// A museum full of exhibits and no label is the failure this replaces: the
/// tables below say what is on each disk, and this says what happened to the
/// object — a delete that landed, a delete that half-landed, a write that
/// outlived its own tombstone, or no explanation at all.
pub fn cause_of_death(lang: &str, r: &Report) -> String {
    let primaries = r.primaries.len();
    let took = |d: f64| -> usize {
        r.primaries
            .iter()
            .filter(|s| {
                r.files
                    .iter()
                    .any(|x| x.kind == "tombstone" && x.ts_secs >= d && &x.slot() == *s)
            })
            .count()
    };
    let live_copies = |ts: f64| -> Vec<Slot> {
        let mut v: Vec<Slot> = r
            .files
            .iter()
            .filter(|x| x.kind == "data" && x.ts_secs >= ts)
            .map(|x| x.slot())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    // What outlived a delete is the data on a placement the tombstone never
    // reached — and that data is OLDER than the tombstone, so filtering by
    // timestamp finds nothing. The survivor is defined by the missing
    // tombstone, not by its own clock.
    let survivors = |d: f64| -> Vec<Slot> {
        let mut v: Vec<Slot> = r
            .files
            .iter()
            .filter(|x| x.kind == "data")
            .filter(|x| {
                !r.files
                    .iter()
                    .any(|y| y.kind == "tombstone" && y.ts_secs >= d && y.slot() == x.slot())
            })
            .map(|x| x.slot())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    match (r.final_state, r.delete_ts) {
        ("deleted_clean", Some(d)) => i18n::t(lang, "tmb.cod.clean")
            .replace("{t}", &fmt_utc(d as i64))
            .replace("{n}", &primaries.to_string())
            .replace("{spread}", &fmt_dur(lang, tombstone_spread(r, d))),
        ("deleted_incomplete", Some(d)) => i18n::t(lang, "tmb.cod.incomplete")
            .replace("{t}", &fmt_utc(d as i64))
            .replace("{got}", &took(d).to_string())
            .replace("{want}", &primaries.to_string())
            .replace(
                "{where}",
                &{
                    let s = slot_list(&survivors(d));
                    if s.is_empty() {
                        i18n::t(lang, "tmb.cod.nowhere").to_string()
                    } else {
                        s
                    }
                },
            ),
        ("resurrected", Some(d)) => i18n::t(lang, "tmb.cod.resurrected")
            .replace("{t}", &fmt_utc(d as i64))
            .replace(
                "{wrote}",
                &newest(&r.files, "data")
                    .map(|n| fmt_utc(n as i64))
                    .unwrap_or_else(|| i18n::t(lang, "tmb.cod.unknown").to_string()),
            ),
        ("lost", _) => i18n::t(lang, "tmb.cod.lost")
            .replace("{n}", &r.primaries.len().to_string())
            .to_string(),
        _ => {
            let n = newest(&r.files, "data");
            i18n::t(lang, "tmb.cod.alive")
                .replace(
                    "{t}",
                    &n.map(|v| fmt_utc(v as i64))
                        .unwrap_or_else(|| i18n::t(lang, "tmb.cod.unknown").to_string()),
                )
                .replace(
                    "{n}",
                    &n.map(|v| live_copies(v).len()).unwrap_or(0).to_string(),
                )
        }
    }
}

/// How long the delete took to reach every primary that took it. Zero when it
/// landed inside one second, which is the healthy case.
fn tombstone_spread(r: &Report, d: f64) -> f64 {
    let times: Vec<i64> = r
        .files
        .iter()
        .filter(|x| x.kind == "tombstone" && x.ts_secs >= d)
        .map(|x| x.received)
        .collect();
    match (times.iter().min(), times.iter().max()) {
        (Some(a), Some(b)) => (b - a) as f64,
        _ => 0.0,
    }
}

// ------------------------------------------------------------- policy

/// The container's policy, asked of the cluster rather than assumed.
///
/// The signed-in session is tried first; when the museum is pointed at an
/// account that session cannot read, the container server itself is asked
/// directly, which is the same answer from one layer lower down.
async fn container_policy(
    state: &Arc<AppState>,
    sid: &str,
    account: &str,
    container: &str,
) -> Result<PolicyInfo, String> {
    if let Some(sess) = state.sessions.get(sid) {
        let url = format!(
            "{}/v1/{}/{}",
            state.cfg.swift_base.trim_end_matches('/'),
            enc_seg(account),
            enc_seg(container)
        );
        if let Ok(resp) = state
            .http
            .head(&url)
            .header("X-Auth-Token", &sess.token)
            .send()
            .await
        {
            if resp.status().is_success() {
                let name = resp
                    .headers()
                    .get("x-storage-policy")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                if let Some(p) = ringlab::policy_by_name(state, &name).await {
                    return Ok(p);
                }
            }
        }
    }
    let located = ringlab::locate_container(state, account, container).await?;
    let node = located
        .primaries
        .first()
        .ok_or("the ring places this container nowhere")?;
    let url = format!(
        "http://{}:{}/{}/{}/{}/{}",
        node.ip,
        node.port,
        node.device,
        located.partition,
        enc_seg(account),
        enc_seg(container)
    );
    let resp = state
        .http
        .head(&url)
        .send()
        .await
        .map_err(|_| "could not reach the container".to_string())?;
    if resp.status().as_u16() == 404 {
        return Err("no such container".into());
    }
    let idx = resp
        .headers()
        .get("x-backend-storage-policy-index")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u32>().ok())
        .ok_or("the container did not report a storage policy")?;
    ringlab::policy(state, idx).await
}

// ------------------------------------------------------------- the report

pub async fn build(
    state: &Arc<AppState>,
    sid: &str,
    lang: &str,
    account: &str,
    container: &str,
    object: &str,
) -> Result<Report, String> {
    if account.is_empty() || container.is_empty() || object.is_empty() {
        return Err(i18n::t(lang, "tmb.err.required").to_string());
    }
    let policy = container_policy(state, sid, account, container).await?;
    let located = ringlab::locate(
        state,
        policy.index,
        account,
        Some(container),
        Some(object),
    )
    .await?;

    let primaries: Vec<Slot> = located
        .primaries
        .iter()
        .map(|p| Slot {
            node: p.node.clone(),
            device: p.device.clone(),
        })
        .collect();

    let mut placed = located.primaries.clone();
    placed.extend(located.handoffs.clone());
    let names = probe_nodes(state, &placed);
    let (mut files, unreachable) =
        scan(state, &policy, located.partition, &located.hash, &names).await?;
    for f in files.iter_mut() {
        f.handoff = !primaries.contains(&f.slot());
    }

    let window = window_for(&files);
    let step = ((window.end - window.start) / 400).clamp(15, 300);
    let offline = availability(state, &window, step).await;
    let (logs, logs_note) = fetch_logs(
        state,
        lang,
        account,
        container,
        object,
        located.partition,
        &window,
    )
    .await;

    let replicas = 3;
    let facts = Facts {
        files: &files,
        primaries: &primaries,
        offline: &offline,
        is_ec: policy.is_ec(),
        ndata: policy.ec_ndata.unwrap_or(0),
        nparity: policy.ec_nparity.unwrap_or(0),
        replicas,
    };
    let (anomalies, final_state) = autopsy(lang, &facts);
    let delete_ts = newest(&files, "tombstone");
    let (lanes, events) = swimlanes(lang, &files, &primaries);

    Ok(Report {
        account: account.to_string(),
        container: container.to_string(),
        object: object.to_string(),
        policy: PolicyBrief {
            index: policy.index,
            name: policy.name.clone(),
            kind: policy.kind.clone(),
            ndata: policy.ec_ndata,
            nparity: policy.ec_nparity,
            replicas,
        },
        partition: located.partition,
        hash: located.hash.clone(),
        primaries,
        files,
        offline,
        logs,
        logs_note,
        anomalies,
        final_state,
        delete_ts,
        lanes,
        events,
        window,
        unreachable,
    })
}

/// The span worth asking the metrics backend about: the object's own history,
/// padded either side and capped, so a page about one minute never asks for a
/// year of samples.
fn window_for(files: &[DiskFile]) -> Window {
    let now = crate::util::now_secs() as i64;
    let mut lo = i64::MAX;
    let mut hi = i64::MIN;
    for f in files {
        lo = lo.min(f.ts_secs as i64).min(f.received);
        hi = hi.max(f.ts_secs as i64).max(f.received);
    }
    if lo == i64::MAX {
        return Window {
            start: now - 3600,
            end: now,
            truncated: false,
        };
    }
    let end = (hi + WINDOW_TRAIL).min(now);
    let start = lo - WINDOW_LEAD;
    let truncated = end - start > WINDOW_MAX;
    Window {
        start: if truncated { end - WINDOW_MAX } else { start },
        end: end.max(start + 600),
        truncated,
    }
}

/// One lane for the client and one per node, and every file as two events: the
/// write the client asked for, and the moment this node actually had it. Those
/// two are the whole point of the page, so they are separate marks rather than
/// one averaged position.
fn swimlanes(lang: &str, files: &[DiskFile], primaries: &[Slot]) -> (Vec<Lane>, Vec<Event>) {
    let mut lanes = vec![Lane {
        id: "client".into(),
        label: i18n::t(lang, "tmb.lane.client").to_string(),
        role: "client",
        primary: false,
    }];
    let mut seen: Vec<String> = Vec::new();
    for f in files {
        if !seen.contains(&f.node) {
            seen.push(f.node.clone());
        }
    }
    for p in primaries {
        if !seen.contains(&p.node) {
            seen.push(p.node.clone());
        }
    }
    seen.sort();
    for n in seen {
        let primary = primaries.iter().any(|p| p.node == n);
        lanes.push(Lane {
            id: n.clone(),
            label: n,
            role: "node",
            primary,
        });
    }

    let mut events = Vec::new();
    let mut client_seen: Vec<String> = Vec::new();
    for f in files {
        let key = format!("{}:{}", f.kind, f.ts);
        if !client_seen.contains(&key) {
            client_seen.push(key);
            events.push(Event {
                lane: "client".into(),
                t: f.ts_secs,
                kind: f.kind.clone(),
                label: i18n::t(
                    lang,
                    match f.kind.as_str() {
                        "tombstone" => "tmb.ev.delete",
                        "meta" => "tmb.ev.meta",
                        _ => "tmb.ev.write",
                    },
                )
                .to_string(),
            });
        }
        events.push(Event {
            lane: f.node.clone(),
            t: f.received as f64,
            kind: f.kind.clone(),
            label: format!("{} on {}", f.name, f.device),
        });
    }
    events.sort_by(|a, b| a.t.partial_cmp(&b.t).unwrap_or(std::cmp::Ordering::Equal));
    (lanes, events)
}

// ------------------------------------------------------------- handlers

#[derive(Deserialize)]
pub struct ObjQ {
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub container: String,
    #[serde(default)]
    pub object: String,
}

fn bad(msg: &str) -> Response {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(json!({ "error": msg })),
    )
        .into_response()
}

pub async fn api(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ObjQ>,
) -> Response {
    let (sid, _) = match lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    match build(&state, &sid, lang, &q.account, &q.container, &q.object).await {
        Ok(rep) => Json(rep).into_response(),
        Err(e) => bad(&e),
    }
}

/// The account a session can actually read, for prefilling the form.
pub fn session_account(sess: &session::Session) -> String {
    sess.storage_url
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_string()
}

/// The form, or a redirect to the shareable path form once it is filled in.
pub async fn page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ObjQ>,
) -> Response {
    let (_, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if !q.container.is_empty() && !q.object.is_empty() {
        let account = if q.account.is_empty() {
            session_account(&sess)
        } else {
            q.account.clone()
        };
        return Redirect::to(&format!(
            "/lab/tombstone/{}/{}/{}",
            enc_seg(&account),
            enc_seg(&q.container),
            enc_obj(&q.object)
        ))
        .into_response();
    }
    let lang = i18n::lang(&headers);
    crate::pages::lab_tombstone_shell(
        &state,
        &headers,
        &sess,
        form_content(lang, &session_account(&sess), None),
    )
}

pub async fn page_obj(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((account, container, object)): Path<(String, String, String)>,
) -> Response {
    let (sid, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let content = match build(&state, &sid, lang, &account, &container, &object).await {
        Ok(rep) => format!(
            "{}{}",
            form_content(lang, &account, Some((&container, &object))),
            report_content(lang, &rep)
        ),
        // The form keeps the failed input, so the next try is a correction.
        Err(e) => format!(
            "{}<div class=\"oc-v\"><h2 class=\"oc-bad\">{h}</h2><p>{m}</p></div>",
            form_content(lang, &account, Some((&container, &object))),
            h = esc(i18n::t(lang, "tmb.err.h")),
            m = esc(&e)
        ),
    };
    crate::pages::lab_tombstone_shell(&state, &headers, &sess, content)
}

// ------------------------------------------------------------- rendering

pub fn form_content(lang: &str, account: &str, filled: Option<(&str, &str)>) -> String {
    let (container, object) = filled.unwrap_or(("", ""));
    format!(
        r#"<div class="pagehead">
  <h1>{title}</h1>
</div>
<p class="statline">{intro}</p>
<form class="page-sec tm-form" method="get" action="/lab/tombstone">
  <div class="sx-grid">
    <label class="fld"><span>{l_account}</span><input name="account" value="{account}" autocomplete="off"></label>
    <label class="fld"><span>{l_container}</span><input name="container" value="{container}" autocomplete="off" required></label>
    <label class="fld"><span>{l_object}</span><input name="object" value="{object}" autocomplete="off" required></label>
  </div>
  <div class="sx-actions"><button class="btn-primary" type="submit">{open}</button></div>
</form>"#,
        title = esc(i18n::t(lang, "lab.tool.tombstone.title")),
        intro = esc(i18n::t(lang, "tmb.intro")),
        l_account = esc(i18n::t(lang, "tmb.f.account")),
        l_container = esc(i18n::t(lang, "tmb.f.container")),
        l_object = esc(i18n::t(lang, "tmb.f.object")),
        open = esc(i18n::t(lang, "tmb.f.open")),
        account = esc(account),
        container = esc(container),
        object = esc(object),
    )
}

fn tbl(cols: &[String], rows: Vec<String>) -> String {
    let head = cols
        .iter()
        .map(|c| format!("<th>{}</th>", esc(c)))
        .collect::<Vec<_>>()
        .join("");
    format!(
        "<div class=\"tbl-wrap\"><table class=\"tbl\"><thead><tr>{head}</tr></thead><tbody>{}</tbody></table></div>",
        rows.join("")
    )
}

fn section(title: &str, body: String) -> String {
    format!("<h2 class=\"tm-h\">{}</h2>{body}", esc(title))
}

fn cols(lang: &str, keys: &[&'static str]) -> Vec<String> {
    keys.iter().map(|k| i18n::t(lang, k).to_string()).collect()
}

/// UTC clock for the axis and the marks, matching the tables underneath. The
/// storage nodes and the service log are both UTC, and an axis on local time
/// would put the delete an hour away from the same delete in the row below it.
fn clock(secs: f64, span: f64) -> String {
    let s = secs.round() as i64;
    let rem = s.rem_euclid(86400);
    if span < 5400.0 {
        format!(
            "{:02}:{:02}:{:02}",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        )
    } else {
        format!("{:02}:{:02}", rem / 3600, (rem % 3600) / 60)
    }
}

/// The swimlane: one lane for the client's clock, one per node, on a shared
/// time axis, with every outage drawn as a band and the delete as a rule
/// through all of them.
///
/// The gap between a mark on the client lane and the same file's mark on a node
/// lane IS the diagnosis, so the two are never folded into one row. Drawn
/// server-side and sized by viewBox, so it is in the document and scales with
/// the column without a script.
fn swimlane_svg(lang: &str, r: &Report) -> String {
    if r.lanes.is_empty() || r.events.is_empty() {
        return format!(
            "<p class=\"note\">{}</p>",
            esc(i18n::t(lang, "tmb.lane.empty"))
        );
    }
    let known: Vec<&str> = r.lanes.iter().map(|l| l.id.as_str()).collect();
    let mut lo = f64::INFINITY;
    let mut hi = f64::NEG_INFINITY;
    for e in &r.events {
        lo = lo.min(e.t);
        hi = hi.max(e.t);
    }
    // Only outages that touch this object's own history belong on this axis;
    // one from yesterday would squash everything that matters into a pixel.
    let bands: Vec<&OfflineSpan> = r
        .offline
        .iter()
        .filter(|b| {
            known.contains(&b.node.as_str())
                && b.to as f64 >= lo - 60.0
                && b.from as f64 <= hi + 60.0
        })
        .collect();
    for b in &bands {
        lo = lo.min(b.from as f64);
        hi = hi.max(b.to as f64);
    }
    if hi - lo < 120.0 {
        let mid = (hi + lo) / 2.0;
        lo = mid - 60.0;
        hi = mid + 60.0;
    }
    let mut span = hi - lo;
    lo -= span * 0.04;
    hi += span * 0.04;
    span = hi - lo;

    let (w, row_h, pad_t, pad_b, pad_r) = (720.0f64, 26.0f64, 14.0f64, 28.0f64, 16.0f64);
    let widest = r.lanes.iter().map(|l| l.label.chars().count()).max().unwrap_or(6);
    let pad_l = (widest as f64 * 7.4 + 16.0).clamp(56.0, 180.0);
    let h = pad_t + r.lanes.len() as f64 * row_h + pad_b;
    let x = |t: f64| pad_l + (t - lo) / span * (w - pad_l - pad_r);
    let row = |i: usize| pad_t + i as f64 * row_h + row_h / 2.0;

    let mut body = String::new();
    for (i, l) in r.lanes.iter().enumerate() {
        let y = row(i);
        body.push_str(&format!(
            "<line class=\"tm-track{c}\" x1=\"{pad_l}\" y1=\"{y:.1}\" x2=\"{x2}\" y2=\"{y:.1}\"/>\
             <text class=\"tm-lane-l{lc}\" x=\"{lx:.1}\" y=\"{ly:.1}\" text-anchor=\"end\">{lab}</text>",
            c = if l.role == "client" { " client" } else { "" },
            x2 = w - pad_r,
            lc = if l.role == "client" {
                " client"
            } else if l.primary {
                ""
            } else {
                " handoff"
            },
            lx = pad_l - 8.0,
            ly = y + 3.5,
            lab = esc(if l.role == "client" {
                i18n::t(lang, "tmb.lane.client")
            } else {
                &l.label
            }),
        ));
    }

    // Outages first, so every mark reads on top of the band it happened inside.
    for b in &bands {
        let Some(i) = r.lanes.iter().position(|l| l.id == b.node) else {
            continue;
        };
        let y = row(i) - row_h / 2.0 + 2.0;
        let x1 = x(b.from as f64).max(pad_l);
        let x2 = x(b.to as f64).min(w - pad_r);
        body.push_str(&format!(
            "<g><rect class=\"tm-band\" x=\"{x1:.1}\" y=\"{y:.1}\" width=\"{bw:.1}\" height=\"{bh}\"/>\
             <line class=\"tm-band-e\" x1=\"{x1:.1}\" y1=\"{y:.1}\" x2=\"{x1:.1}\" y2=\"{y2:.1}\"/>\
             <line class=\"tm-band-e\" x1=\"{x2:.1}\" y1=\"{y:.1}\" x2=\"{x2:.1}\" y2=\"{y2:.1}\"/>\
             <title>{tip}</title></g>",
            bw = (x2 - x1).max(1.0),
            bh = row_h - 4.0,
            y2 = y + row_h - 4.0,
            tip = esc(
                &i18n::t(lang, "tmb.lane.offline")
                    .replace("{node}", &b.node)
                    .replace("{from}", &clock(b.from as f64, span))
                    .replace("{to}", &clock(b.to as f64, span))
            ),
        ));
    }

    if let Some(d) = r.delete_ts {
        let dx = x(d);
        // Flip the label inside the frame when the delete lands near the right
        // edge, so the word is never shaved off by the viewBox.
        let flip = dx > w - pad_r - 60.0;
        body.push_str(&format!(
            "<line class=\"tm-rule\" x1=\"{dx:.1}\" y1=\"{y1}\" x2=\"{dx:.1}\" y2=\"{y2}\"/>\
             <text class=\"tm-rule-l\" x=\"{lx:.1}\" y=\"{ly}\" text-anchor=\"{a}\">{lbl}</text>",
            y1 = pad_t - 4.0,
            y2 = h - pad_b + 2.0,
            lx = if flip { dx - 5.0 } else { dx + 5.0 },
            ly = pad_t + 3.0,
            a = if flip { "end" } else { "start" },
            lbl = esc(i18n::t(lang, "tmb.lane.delete")),
        ));
    }

    for e in &r.events {
        let Some(i) = r.lanes.iter().position(|l| l.id == e.lane) else {
            continue;
        };
        let (cx, cy) = (x(e.t), row(i));
        let tip = esc(&format!("{}  {}", clock(e.t, span), e.label));
        if e.kind == "tombstone" {
            // A delete is struck out, not just recoloured: the shape carries it.
            body.push_str(&format!(
                "<path class=\"tm-ev-tombstone\" d=\"M{a:.1} {b:.1}L{c:.1} {d:.1}M{c:.1} {b:.1}L{a:.1} {d:.1}\">\
                 <title>{tip}</title></path>",
                a = cx - 4.0,
                b = cy - 4.0,
                c = cx + 4.0,
                d = cy + 4.0,
            ));
        } else {
            body.push_str(&format!(
                "<circle class=\"tm-ev-{k}\" cx=\"{cx:.1}\" cy=\"{cy:.1}\" r=\"{rr}\">\
                 <title>{tip}</title></circle>",
                k = esc(&e.kind),
                rr = if e.kind == "meta" { 3.5 } else { 4.0 },
            ));
        }
    }

    for i in 0..=3 {
        let t = lo + span * (i as f64 / 3.0);
        body.push_str(&format!(
            "<text class=\"tm-axis\" x=\"{tx:.1}\" y=\"{ty}\" text-anchor=\"{a}\">{v}</text>",
            tx = x(t),
            ty = h - 8.0,
            a = if i == 0 {
                "start"
            } else if i == 3 {
                "end"
            } else {
                "middle"
            },
            v = esc(&clock(t, span)),
        ));
    }

    let legend = [
        ("tm-ev-data", "tmb.lane.k.write"),
        ("tm-ev-tombstone", "tmb.lane.k.delete"),
        ("tm-ev-meta", "tmb.lane.k.meta"),
        ("tm-band", "tmb.lane.k.offline"),
    ]
    .iter()
    .map(|(c, k)| {
        format!(
            "<span class=\"mon-leg-i\"><i class=\"{c}\"></i><b>{}</b></span>",
            esc(i18n::t(lang, k))
        )
    })
    .collect::<Vec<_>>()
    .join("");

    format!(
        "<div class=\"mon-card wide\"><div class=\"mon-card-h\"><span class=\"mon-t\">{title}</span>\
         <span class=\"mon-legend\">{legend}</span></div><div class=\"mon-body\">\
         <svg class=\"tm-svg\" viewBox=\"0 0 {w} {h}\" width=\"100%\" role=\"img\" aria-label=\"{title}\">{body}</svg>\
         <div class=\"lab-b\">{note}</div></div></div>",
        title = esc(i18n::t(lang, "tmb.lane.title")),
        note = esc(i18n::t(lang, "tmb.lane.note")),
    )
}

/// The report as HTML. Everything the swimlane draws is also a table here, so
/// the page is complete before a single byte of script runs.
pub fn report_content(lang: &str, r: &Report) -> String {
    let (verdict_key, tone) = state_words(r.final_state);
    let verdict = i18n::t(lang, verdict_key);
    let ec = r.policy.kind == "erasure_coding";
    let policy_line = if ec {
        format!(
            "{} · {}",
            esc(&r.policy.name),
            esc(
                &i18n::t(lang, "tmb.policy.ec")
                    .replace("{k}", &r.policy.ndata.unwrap_or(0).to_string())
                    .replace("{m}", &r.policy.nparity.unwrap_or(0).to_string())
            )
        )
    } else {
        format!(
            "{} · {}",
            esc(&r.policy.name),
            esc(&i18n::t(lang, "tmb.policy.repl").replace("{n}", &r.policy.replicas.to_string()))
        )
    };

    let mut anomalies = String::new();
    if r.anomalies.is_empty() {
        anomalies.push_str(&format!(
            "<p class=\"note\">{}</p>",
            esc(i18n::t(lang, "tmb.find.none"))
        ));
    }
    for a in &r.anomalies {
        anomalies.push_str(&format!(
            "<div class=\"tm-find {sev}\"><div class=\"tm-find-h\">{head}</div>\
             <div class=\"tm-find-d\">{detail}</div><div class=\"tm-find-r\">{rule}</div></div>",
            sev = a.severity,
            head = esc(&a.headline),
            detail = esc(&a.detail),
            rule = esc(a.rule),
        ));
    }

    let file_rows: Vec<String> = r
        .files
        .iter()
        .map(|f| {
            let frag = match f.frag_index {
                Some(i) => format!(
                    "#{i}{}",
                    if f.durable {
                        String::new()
                    } else {
                        format!(" ({})", i18n::t(lang, "tmb.uncommitted"))
                    }
                ),
                None => "-".into(),
            };
            let lag = if f.lag_secs > LAG_WARN_SECS {
                format!("<span class=\"tm-bad\">{}</span>", esc(&fmt_dur(lang, f.lag_secs)))
            } else if f.lag_secs >= 1.0 {
                esc(&fmt_dur(lang, f.lag_secs))
            } else {
                esc(i18n::t(lang, "tmb.samesecond"))
            };
            format!(
                "<tr><td>{node}{ho}</td><td>{dev}</td><td>{kind}</td><td class=\"when\">{ts}</td>\
                 <td class=\"when\">{rc}</td><td class=\"num\">{lag}</td><td class=\"num\">{size}</td><td>{frag}</td></tr>",
                node = esc(&f.node),
                ho = if f.handoff {
                    format!(" <span class=\"sys-note\">{}</span>", esc(i18n::t(lang, "tmb.handoff")))
                } else {
                    String::new()
                },
                dev = esc(&f.device),
                kind = esc(&kind_word(lang, &f.kind)),
                ts = esc(&fmt_utc(f.ts_secs as i64)),
                rc = esc(&fmt_utc(f.received)),
                size = esc(&fmt_bytes(f.size)),
                frag = esc(&frag),
            )
        })
        .collect();
    let files = if file_rows.is_empty() {
        format!("<p class=\"note\">{}</p>", esc(i18n::t(lang, "tmb.files.none")))
    } else {
        tbl(
            &cols(
                lang,
                &[
                    "tmb.c.node",
                    "tmb.c.device",
                    "tmb.c.kind",
                    "tmb.c.wrote",
                    "tmb.c.took",
                    "tmb.c.gap",
                    "tmb.c.size",
                    "tmb.c.fragment",
                ],
            ),
            file_rows,
        )
    };

    let off_rows: Vec<String> = r
        .offline
        .iter()
        .map(|s| {
            format!(
                "<tr><td>{node}</td><td class=\"when\">{from}</td><td class=\"when\">{to}</td><td class=\"num\">{dur}</td></tr>",
                node = esc(&s.node),
                from = esc(&fmt_utc(s.from)),
                to = esc(&fmt_utc(s.to)),
                dur = esc(&fmt_dur(lang, s.secs as f64)),
            )
        })
        .collect();
    let offline = if off_rows.is_empty() {
        format!("<p class=\"note\">{}</p>", esc(i18n::t(lang, "tmb.offline.none")))
    } else {
        tbl(
            &cols(lang, &["tmb.c.node", "tmb.c.from", "tmb.c.to", "tmb.c.downfor"]),
            off_rows,
        )
    };

    let ev_rows: Vec<String> = r
        .events
        .iter()
        .map(|e| {
            format!(
                "<tr><td class=\"when\">{t}</td><td>{lane}</td><td>{kind}</td><td>{label}</td></tr>",
                t = esc(&fmt_utc(e.t as i64)),
                lane = esc(if e.lane == "client" {
                    i18n::t(lang, "tmb.lane.client")
                } else {
                    &e.lane
                }),
                kind = esc(&kind_word(lang, &e.kind)),
                label = esc(&e.label),
            )
        })
        .collect();

    let log_rows: Vec<String> = r
        .logs
        .iter()
        .map(|l| {
            format!(
                "<tr><td class=\"when\">{t}</td><td>{node}</td><td>{unit}</td><td class=\"tm-line\">{line}</td></tr>",
                t = esc(&fmt_utc(l.t)),
                node = esc(&l.node),
                unit = esc(&l.unit),
                line = esc(&l.line),
            )
        })
        .collect();
    let logs = if log_rows.is_empty() {
        format!("<p class=\"note\">{}</p>", esc(&r.logs_note))
    } else {
        let note = if r.logs_note.is_empty() {
            String::new()
        } else {
            format!("<p class=\"note\">{}</p>", esc(&r.logs_note))
        };
        format!(
            "{note}{}",
            tbl(
                &cols(lang, &["tmb.c.when", "tmb.c.node", "tmb.c.service", "tmb.c.line"]),
                log_rows
            )
        )
    };

    let unreachable = if r.unreachable.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"err on\">{}</p>",
            esc(&i18n::t(lang, "tmb.unreachable").replace("{n}", &r.unreachable.join(", ")))
        )
    };
    let truncated = if r.window.truncated {
        format!(
            "<p class=\"note\">{}</p>",
            esc(i18n::t(lang, "tmb.truncated"))
        )
    } else {
        String::new()
    };

    format!(
        r#"<div class="tm-head">
  <div class="tm-verdict {tone}">{verdict}</div>
  <div class="tm-sub">{path}</div>
  <div class="tm-meta">{policy_line} · {partline}</div>
</div>
<div class="oc-v tm-cod"><p>{cod}</p></div>
{unreachable}{truncated}
{findings}
{lanes}
{files_sec}
{offline_sec}
{logs_sec}"#,
        tone = tone,
        verdict = esc(verdict),
        path = esc(&format!("{}/{}/{}", r.account, r.container, r.object)),
        policy_line = policy_line,
        partline = esc(
            &i18n::t(lang, "tmb.partline")
                .replace("{p}", &r.partition.to_string())
                .replace("{h}", &r.hash)
        ),
        cod = esc(&cause_of_death(lang, r)),
        findings = section(i18n::t(lang, "tmb.h.what"), anomalies),
        lanes = section(
            i18n::t(lang, "tmb.h.timeline"),
            format!(
                "{}{}",
                swimlane_svg(lang, r),
                if ev_rows.is_empty() {
                    format!("<p class=\"note\">{}</p>", esc(i18n::t(lang, "tmb.events.none")))
                } else {
                    tbl(
                        &cols(lang, &["tmb.c.when", "tmb.c.lane", "tmb.c.kind", "tmb.c.what"]),
                        ev_rows,
                    )
                }
            )
        ),
        files_sec = section(i18n::t(lang, "tmb.h.ondisk"), files),
        offline_sec = section(i18n::t(lang, "tmb.h.offline"), offline),
        logs_sec = section(i18n::t(lang, "tmb.h.logs"), logs),
    )
}

fn kind_word(lang: &str, kind: &str) -> String {
    match kind {
        "data" => i18n::t(lang, "tmb.k.data"),
        "tombstone" => i18n::t(lang, "tmb.k.tombstone"),
        "meta" => i18n::t(lang, "tmb.k.meta"),
        "durable" => i18n::t(lang, "tmb.k.durable"),
        other => other,
    }
    .to_string()
}


#[cfg(test)]
mod tests {
    use super::*;

    fn df(node: &str, dev: &str, name: &str, received: i64) -> DiskFile {
        let p = parse_name(name).expect("name parses");
        DiskFile {
            node: node.into(),
            device: dev.into(),
            name: name.into(),
            kind: p.kind,
            ts: p.ts,
            ts_secs: p.ts_secs,
            // A replicated copy keeps the original write's mtime; only ctime
            // moves, which is exactly the case these rules have to catch.
            mtime: p.ts_secs as i64,
            received,
            lag_secs: received as f64 - p.ts_secs,
            size: 1024,
            frag_index: p.frag_index,
            durable: p.durable,
            handoff: false,
        }
    }

    fn slots(v: &[(&str, &str)]) -> Vec<Slot> {
        v.iter()
            .map(|(n, d)| Slot {
                node: (*n).into(),
                device: (*d).into(),
            })
            .collect()
    }

    fn facts<'a>(files: &'a [DiskFile], primaries: &'a [Slot], offline: &'a [OfflineSpan]) -> Facts<'a> {
        Facts {
            files,
            primaries,
            offline,
            is_ec: false,
            ndata: 0,
            nparity: 0,
            replicas: 3,
        }
    }

    #[test]
    fn parses_every_filename_the_object_server_writes() {
        let d = parse_name("1785065677.50035.data").unwrap();
        assert_eq!(d.kind, "data");
        assert_eq!(d.ts, "1785065677.50035");
        assert_eq!(d.frag_index, None);
        assert!(d.durable);

        let f = parse_name("1785074616.77422#2#d.data").unwrap();
        assert_eq!(f.kind, "data");
        assert_eq!(f.ts, "1785074616.77422");
        assert_eq!(f.frag_index, Some(2));
        assert!(f.durable, "#d is the commit marker");

        // A fragment written but not yet committed must not be counted as one.
        assert!(!parse_name("1785074616.77422#2.data").unwrap().durable);

        assert_eq!(parse_name("1785116690.12102.ts").unwrap().kind, "tombstone");
        let m = parse_name("1785065677.50035_0000000000000000.meta").unwrap();
        assert_eq!(m.kind, "meta");
        assert_eq!(m.ts, "1785065677.50035", "the offset is not part of the clock");

        // Anything else is not an event and must not become one.
        assert!(parse_name("1785065677.50035.tmp").is_none());
        assert!(parse_name("hashes.pkl").is_none());
        assert!(parse_name("1785074616.77422#x#d.data").is_none());
    }

    #[test]
    fn utc_and_durations_read_the_way_an_operator_says_them() {
        // The container HEAD that produced this timestamp reported
        // "Sun, 26 Jul 2026 14:44:24 GMT".
        assert_eq!(fmt_utc(1785077064), "2026-07-26 14:44:24Z");
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00Z");
        assert_eq!(fmt_dur("en", 45.0), "45 seconds");
        assert_eq!(fmt_dur("en", 2220.0), "37 minutes");
        assert_eq!(fmt_dur("en", 7200.0), "2.0 hours");
        // The same duration, said in Chinese rather than translated word by word.
        assert_eq!(fmt_dur("zh", 2220.0), "37 分钟");
    }

    #[test]
    fn offline_spans_need_two_samples_and_carry_one_step_past_the_last() {
        let s: Vec<(i64, Option<f64>)> = vec![
            (0, Some(1.0)),
            (30, Some(0.0)),
            (60, Some(0.0)),
            (90, Some(0.0)),
            (120, Some(1.0)),
        ];
        let out = offline_spans("swift3", &s, 30);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].from, 30);
        assert_eq!(out[0].to, 120);
        assert_eq!(out[0].secs, 90);

        // One missed scrape is noise, not an outage.
        let blip: Vec<(i64, Option<f64>)> =
            vec![(0, Some(1.0)), (30, Some(0.0)), (60, Some(1.0))];
        assert!(offline_spans("swift3", &blip, 30).is_empty());

        // A gap in the series is not evidence of anything.
        let gap: Vec<(i64, Option<f64>)> =
            vec![(0, Some(0.0)), (30, None), (60, Some(0.0))];
        assert!(offline_spans("swift3", &gap, 30).is_empty());
    }

    #[test]
    fn a_delete_that_reached_two_of_three_is_incomplete_not_clean() {
        let p = slots(&[("swift1", "d1"), ("swift2", "d1"), ("swift3", "d1")]);
        let files = vec![
            df("swift1", "d1", "100.00000.ts", 100),
            df("swift2", "d1", "100.00000.ts", 100),
            df("swift3", "d1", "90.00000.data", 90),
        ];
        let (a, state) = autopsy("en", &facts(&files, &p, &[]));
        assert_eq!(state, "deleted_incomplete");
        let inc = a.iter().find(|x| x.rule == "tombstone_incomplete").unwrap();
        assert!(inc.headline.contains("2 of 3"), "{}", inc.headline);
        assert!(inc.detail.contains("swift3/d1"), "{}", inc.detail);
    }

    #[test]
    fn a_clean_delete_reports_nothing() {
        let p = slots(&[("swift1", "d1"), ("swift2", "d1"), ("swift3", "d1")]);
        let files = vec![
            df("swift1", "d1", "100.00000.ts", 100),
            df("swift2", "d1", "100.00000.ts", 100),
            df("swift3", "d1", "100.00000.ts", 100),
        ];
        let (a, state) = autopsy("en", &facts(&files, &p, &[]));
        assert_eq!(state, "deleted_clean");
        assert!(a.is_empty(), "{a:?}");
    }

    #[test]
    fn data_newer_than_a_tombstone_is_a_resurrection() {
        let p = slots(&[("swift1", "d1"), ("swift2", "d1"), ("swift3", "d1")]);
        let files = vec![
            df("swift1", "d1", "100.00000.ts", 100),
            df("swift2", "d1", "100.00000.ts", 100),
            df("swift3", "d1", "110.00000.data", 110),
        ];
        let (a, state) = autopsy("en", &facts(&files, &p, &[]));
        assert_eq!(state, "resurrected");
        assert!(a.iter().any(|x| x.rule == "resurrection"));
    }

    #[test]
    fn an_outage_straddling_the_delete_names_the_node_and_the_duration() {
        let p = slots(&[("swift1", "d1"), ("swift2", "d1"), ("swift3", "d1")]);
        let files = vec![
            df("swift1", "d1", "1000.00000.ts", 1000),
            df("swift2", "d1", "1000.00000.ts", 1000),
            df("swift3", "d1", "900.00000.data", 900),
        ];
        // Down from just before the delete for 37 minutes.
        let off = vec![OfflineSpan {
            node: "swift3".into(),
            from: 990,
            to: 990 + 2220,
            secs: 2220,
        }];
        let (a, _) = autopsy("en", &facts(&files, &p, &off));
        let hit = a
            .iter()
            .find(|x| x.rule == "node_offline_after_delete")
            .expect("the rule fires");
        assert_eq!(hit.severity, "bad", "it never saw the delete");
        assert!(hit.headline.contains("swift3"), "{}", hit.headline);
        assert!(hit.headline.contains("37 minutes"), "{}", hit.headline);

        // An outage nowhere near the delete is not this rule's business.
        let far = vec![OfflineSpan {
            node: "swift3".into(),
            from: 100,
            to: 200,
            secs: 100,
        }];
        let (b, _) = autopsy("en", &facts(&files, &p, &far));
        assert!(!b.iter().any(|x| x.rule == "node_offline_after_delete"));
    }

    #[test]
    fn a_late_copy_is_caught_by_ctime_even_though_its_mtime_looks_punctual() {
        let p = slots(&[("swift1", "d1"), ("swift2", "d1"), ("swift3", "d1")]);
        let files = vec![
            df("swift1", "d1", "1000.00000.data", 1000),
            df("swift2", "d1", "1000.00000.data", 1000),
            df("swift3", "d1", "1000.00000.data", 1000 + 2220),
        ];
        // The whole reason ctime is the clock: replication hands the file over
        // with the original mtime, so mtime alone says this copy was on time.
        assert_eq!(files[2].mtime, 1000);
        let (a, state) = autopsy("en", &facts(&files, &p, &[]));
        assert_eq!(state, "present");
        let lag = a.iter().find(|x| x.rule == "replica_lag").unwrap();
        assert!(lag.headline.contains("swift3"), "{}", lag.headline);
        assert!(lag.headline.contains("37 minutes"), "{}", lag.headline);
    }

    #[test]
    fn missing_copies_and_missing_fragments_are_counted_against_the_policy() {
        let p = slots(&[("swift1", "d1"), ("swift2", "d1"), ("swift3", "d1")]);
        let files = vec![df("swift1", "d1", "1000.00000.data", 1000)];
        let (a, _) = autopsy("en", &facts(&files, &p, &[]));
        let u = a.iter().find(|x| x.rule == "under_replicated").unwrap();
        assert_eq!(u.severity, "bad", "one of three is below quorum");
        assert!(u.headline.contains("1 of 3"), "{}", u.headline);

        let ecf = vec![
            df("swift1", "d1", "1000.00000#0#d.data", 1000),
            df("swift2", "d1", "1000.00000#1#d.data", 1000),
        ];
        let mut fa = facts(&ecf, &p, &[]);
        fa.is_ec = true;
        fa.ndata = 2;
        fa.nparity = 1;
        let (b, _) = autopsy("en", &fa);
        let d = b.iter().find(|x| x.rule == "frag_deficit").unwrap();
        assert_eq!(d.severity, "warn", "k fragments still read");
        assert!(d.headline.contains("2 of 3"), "{}", d.headline);
    }

    #[test]
    fn a_copy_on_a_handoff_is_called_out() {
        let p = slots(&[("swift1", "d1"), ("swift2", "d1"), ("swift3", "d1")]);
        let mut files = vec![
            df("swift1", "d1", "1000.00000.data", 1000),
            df("swift2", "d1", "1000.00000.data", 1000),
            df("swift3", "d1", "1000.00000.data", 1000),
            df("swift4", "d2", "1000.00000.data", 1000),
        ];
        files[3].handoff = true;
        let (a, _) = autopsy("en", &facts(&files, &p, &[]));
        let h = a.iter().find(|x| x.rule == "on_handoff").unwrap();
        assert!(h.detail.contains("swift4/d2"), "{}", h.detail);
        assert!(h.headline.contains("copy"), "a stray replica is a copy");

        // The same rule on a stray tombstone has to say something different.
        let mut ts = vec![
            df("swift1", "d1", "1000.00000.ts", 1000),
            df("swift4", "d2", "1000.00000.ts", 1000),
        ];
        ts[1].handoff = true;
        let (b, _) = autopsy("en", &facts(&ts, &p, &[]));
        let hb = b.iter().find(|x| x.rule == "on_handoff").unwrap();
        assert!(hb.headline.contains("delete"), "{}", hb.headline);
    }

    #[test]
    fn nothing_on_disk_at_all_is_lost_rather_than_deleted() {
        let p = slots(&[("swift1", "d1")]);
        let (a, state) = autopsy("en", &facts(&[], &p, &[]));
        assert_eq!(state, "lost");
        assert!(a.is_empty(), "no rule can say anything about nothing");
    }

    #[test]
    fn swimlanes_separate_the_clients_clock_from_each_nodes() {
        let p = slots(&[("swift1", "d1"), ("swift2", "d1")]);
        let files = vec![
            df("swift1", "d1", "1000.00000.data", 1000),
            df("swift2", "d1", "1000.00000.data", 1600),
        ];
        let (lanes, events) = swimlanes("en", &files, &p);
        assert_eq!(lanes[0].id, "client");
        assert_eq!(lanes.len(), 3);
        // One client event for the single write, plus one landing per node.
        assert_eq!(events.iter().filter(|e| e.lane == "client").count(), 1);
        let landed: Vec<f64> = events
            .iter()
            .filter(|e| e.lane == "swift2")
            .map(|e| e.t)
            .collect();
        assert_eq!(landed, vec![1600.0]);
    }

    /// The findings must be the same in both languages and the words must not
    /// be. A rule that hard-codes English wraps a Chinese page around an
    /// English autopsy, which is the exact defect this round is fixing.
    #[test]
    fn the_autopsy_is_written_in_the_readers_language() {
        let p = slots(&[("swift1", "d1"), ("swift2", "d1"), ("swift3", "d1")]);
        let files = vec![
            df("swift1", "d1", "100.00000.ts", 100),
            df("swift2", "d1", "100.00000.ts", 100),
            df("swift3", "d1", "90.00000.data", 90),
        ];
        let (en, s_en) = autopsy("en", &facts(&files, &p, &[]));
        let (zh, s_zh) = autopsy("zh", &facts(&files, &p, &[]));
        assert_eq!(s_en, s_zh, "only the words change, never the finding");
        assert_eq!(en.len(), zh.len());
        for (a, b) in en.iter().zip(zh.iter()) {
            assert_eq!(a.rule, b.rule);
            assert_eq!(a.severity, b.severity);
            assert_ne!(a.headline, b.headline, "{} was not translated", a.rule);
            assert!(
                b.headline.chars().any(|c| c as u32 > 0x2E80),
                "{} has no Chinese in it: {}",
                b.rule,
                b.headline
            );
        }
    }

    /// The museum used to open with a one-word label. An autopsy has to name
    /// the cause of death in a sentence, with the time and the survivors in it.
    #[test]
    fn the_report_opens_by_naming_the_cause_of_death() {
        let p = slots(&[("swift1", "d1"), ("swift2", "d1"), ("swift3", "d1")]);
        let files = vec![
            df("swift1", "d1", "100.00000.ts", 100),
            df("swift2", "d1", "100.00000.ts", 100),
            df("swift3", "d1", "90.00000.data", 90),
        ];
        let (anomalies, final_state) = autopsy("en", &facts(&files, &p, &[]));
        let r = Report {
            account: "AUTH_test".into(),
            container: "c".into(),
            object: "o".into(),
            policy: PolicyBrief {
                index: 0,
                name: "default".into(),
                kind: "replication".into(),
                ndata: None,
                nparity: None,
                replicas: 3,
            },
            partition: 1,
            hash: "abc".into(),
            primaries: p.clone(),
            files: files.clone(),
            offline: vec![],
            logs: vec![],
            logs_note: String::new(),
            anomalies,
            final_state,
            delete_ts: newest(&files, "tombstone"),
            lanes: vec![],
            events: vec![],
            window: Window { start: 0, end: 1, truncated: false },
            unreachable: vec![],
        };
        let cod = cause_of_death("en", &r);
        assert!(cod.contains("2 of 3"), "{cod}");
        assert!(cod.contains("swift3/d1"), "the survivor is named: {cod}");
        assert!(cod.contains("1970-01-01"), "the time is in it: {cod}");
        assert_ne!(cause_of_death("zh", &r), cod);
    }
}
