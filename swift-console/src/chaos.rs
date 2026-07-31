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

//! Chaos Arcade: predict what a fault will do, then watch the cluster do it.
//!
//! Every other Lab tool explains the cluster from the outside. This one changes
//! it, which makes the safety design the substance rather than a precaution:
//!
//! * The blast radius is an object **this tool created**, in a container it
//!   owns. Ownership is checked by resolving the object's on-disk hash from the
//!   ring and refusing any file whose hash does not belong to a chaos object —
//!   a path prefix alone is not enough here, because every replica in the
//!   cluster lives under the same `/srv/node` root.
//! * The undo is written before the fault is applied and handed to
//!   [`nodes::mutate`], which journals it with a TTL. The existing 30 s sweeper
//!   auto-undoes anything past its deadline, so a console that crashes
//!   mid-experiment cannot leave a damaged replica behind.
//! * Nothing here stops a storage service. A fault whose undo cannot be proven
//!   is not a fault this tool offers.
//!
//! The output is the point. An experiment that only says "it recovered" teaches
//! nothing; this records what the operator predicted, what actually happened
//! with real timestamps, which daemon did the repair, and how long convergence
//! took — so the disagreement between belief and cluster is the finding.
//!
//! Attribution is measured, never assumed. A daemon logs its pass line when the
//! pass *ends*, so the line carrying the repair can appear seconds after the
//! copy is already back; the runner therefore keeps reading pass lines for a
//! grace window after convergence, and if none of them ever shows work it says
//! "not attributed" rather than naming the daemon the policy would suggest.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use bytes::Bytes;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::util::{enc_seg, esc, fmt_bytes, ix_mount};
use crate::{capsule, i18n, lab, nodes, ringlab, swift, AppState};

/// The container every experiment writes into. Nothing outside it is ever a
/// legal target, which is what keeps a fault away from real data.
pub const ARENA: &str = "chaos-arcade";

/// How long a fault may live before the sweeper undoes it. Deliberately longer
/// than a reconstructor pass (~60 s) so a repair has room to happen, and far
/// shorter than a shift, so a forgotten experiment cleans itself up.
const FAULT_TTL_SECS: u64 = 900;

/// The arena object. One megabyte is enough to become three real EC fragments
/// at the configured segment size and small enough that reading it back on
/// every poll costs nothing worth measuring.
const ARENA_BYTES: usize = 1024 * 1024;
const ARENA_OBJECT: &str = "probe.bin";

/// Poll cadence and bounds. Each tick is one ssh per node, so five seconds is
/// the floor at which the measurement does not perturb what it measures.
const POLL_SECS: u64 = 5;
const DEADLINE_MIN: u64 = 60;
const DEADLINE_MAX: u64 = 600;
const DEADLINE_DEFAULT: u64 = 150;
/// After convergence, keep reading pass lines this long. A daemon logs its pass
/// when the pass finishes, so the line that proves who did the work routinely
/// lands after the work is visible on disk.
const EVIDENCE_GRACE_SECS: u64 = 90;

// ------------------------------------------------------------------ faults

/// A fault the arcade knows how to inject *and* undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    /// Remove one replica or fragment from a primary.
    DropCopy,
    /// Flip bytes inside one copy, leaving its name and size intact — the case
    /// a size check misses and only a checksum catches.
    CorruptCopy,
    /// Remove the durability marker so a fragment looks unfinished.
    DropDurable,
    /// Rename a copy to a timestamp far in the past, so a newer version exists
    /// elsewhere and the old one must lose.
    StaleTimestamp,
}

impl Fault {
    pub fn id(self) -> &'static str {
        match self {
            Fault::DropCopy => "drop_copy",
            Fault::CorruptCopy => "corrupt_copy",
            Fault::DropDurable => "drop_durable",
            Fault::StaleTimestamp => "stale_timestamp",
        }
    }

    pub fn parse(s: &str) -> Option<Fault> {
        Some(match s {
            "drop_copy" => Fault::DropCopy,
            "corrupt_copy" => Fault::CorruptCopy,
            "drop_durable" => Fault::DropDurable,
            "stale_timestamp" => Fault::StaleTimestamp,
            _ => return None,
        })
    }

    /// The i18n key for the one-line question this fault poses.
    pub fn question_key(self) -> &'static str {
        match self {
            Fault::DropCopy => "chaos.q.drop_copy",
            Fault::CorruptCopy => "chaos.q.corrupt_copy",
            Fault::DropDurable => "chaos.q.drop_durable",
            Fault::StaleTimestamp => "chaos.q.stale_timestamp",
        }
    }

    /// The i18n key for the fault's short name.
    pub fn name_key(self) -> &'static str {
        match self {
            Fault::DropCopy => "chaos.f.drop_copy",
            Fault::CorruptCopy => "chaos.f.corrupt_copy",
            Fault::DropDurable => "chaos.f.drop_durable",
            Fault::StaleTimestamp => "chaos.f.stale_timestamp",
        }
    }

    /// Only erasure coding has a durability marker to remove; asking a
    /// replicated policy for one would silently test nothing.
    pub fn ec_only(self) -> bool {
        matches!(self, Fault::DropDurable)
    }

    pub fn all() -> &'static [Fault] {
        &[
            Fault::DropCopy,
            Fault::CorruptCopy,
            Fault::DropDurable,
            Fault::StaleTimestamp,
        ]
    }
}

/// What the operator thinks will happen, recorded before the fault lands so it
/// cannot be revised once the answer is visible.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Prediction {
    /// Will a GET still return the object?
    pub readable: bool,
    /// Which daemon repairs it: "replicator" | "reconstructor" | "none".
    pub repaired_by: String,
    /// Expected convergence, in seconds. Scored against the measurement with a
    /// tolerance, because "about a minute" and "62 s" are the same answer.
    pub converge_secs: u64,
}

/// What actually happened.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Outcome {
    pub readable: bool,
    pub read_status: u16,
    pub etag_matched: Option<bool>,
    pub repaired: bool,
    pub repaired_by: String,
    pub converge_secs: Option<u64>,
    /// Copies present before, immediately after, and at the end.
    pub copies_before: usize,
    pub copies_after_fault: usize,
    pub copies_final: usize,
}

/// One scored line of the report.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Scored {
    pub what: &'static str,
    pub predicted: String,
    pub actual: String,
    pub right: bool,
}

/// Score a prediction against reality.
///
/// Convergence is scored with a tolerance rather than exactly: an operator who
/// says "a minute" and a cluster that takes 62 seconds agree, and pretending
/// otherwise would make the scoreboard punish correct intuition.
pub fn score(p: &Prediction, o: &Outcome) -> Vec<Scored> {
    let mut out = Vec::new();
    out.push(Scored {
        what: "readable",
        predicted: yes_no(p.readable),
        actual: format!("{} (HTTP {})", yes_no(o.readable), o.read_status),
        right: p.readable == o.readable,
    });
    out.push(Scored {
        what: "repaired_by",
        predicted: p.repaired_by.clone(),
        actual: o.repaired_by.clone(),
        right: p.repaired_by == o.repaired_by,
    });
    let conv = match o.converge_secs {
        Some(secs) => {
            // Within a factor of two, or within 30 s on short intervals.
            let lo = p.converge_secs.saturating_sub(30).min(p.converge_secs / 2);
            let hi = (p.converge_secs + 30).max(p.converge_secs * 2);
            Scored {
                what: "converge_secs",
                predicted: format!("~{}s", p.converge_secs),
                actual: format!("{secs}s"),
                right: secs >= lo && secs <= hi,
            }
        }
        None => Scored {
            what: "converge_secs",
            predicted: format!("~{}s", p.converge_secs),
            actual: "did not converge".into(),
            right: false,
        },
    };
    out.push(conv);
    out
}

fn yes_no(b: bool) -> String {
    if b { "yes".into() } else { "no".into() }
}

/// How many of the scored lines the operator got right.
pub fn tally(rows: &[Scored]) -> (usize, usize) {
    (rows.iter().filter(|r| r.right).count(), rows.len())
}

// ------------------------------------------------------------------ guards

/// A target file the arcade is allowed to damage.
#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub node: String,
    pub device: String,
    pub path: String,
    pub file: String,
}

/// Refuse anything that is not a plain on-disk copy inside the arena.
///
/// The path prefix is necessary and nowhere near sufficient: every replica in
/// the cluster lives under the same node root, so a prefix check alone would
/// happily authorise deleting a customer's only copy. The real guard is that
/// the hash directory in the path must be the hash the ring computes for an
/// object in [`ARENA`] — proven by the caller before this is reached.
pub fn check_target(path: &str, expect_hash: &str, node_root: &str) -> Result<(), String> {
    if node_root.is_empty() {
        return Err("no node root configured".into());
    }
    if !path.starts_with(node_root) {
        return Err(format!("{path} is outside the node root"));
    }
    if path.contains("..") {
        return Err("path traversal refused".into());
    }
    if !path.split('/').any(|seg| seg == expect_hash) {
        return Err(format!(
            "{path} does not belong to the arena object being tested"
        ));
    }
    // A data/meta/durable file, never a directory or a lock.
    let last = path.rsplit('/').next().unwrap_or("");
    if !(last.ends_with(".data") || last.ends_with(".meta") || last.ends_with(".durable")) {
        return Err(format!("{last} is not an object file"));
    }
    Ok(())
}

// ------------------------------------------------------------------ record

/// Where an experiment is. Kept coarse on purpose: the report is the product,
/// and a progress bar with ten states is not more honest than four.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Seeding,
    Running,
    Done,
    Failed,
}

/// One thing that happened, with the wall clock and the offset from the fault.
/// Both are kept: the wall clock is what an operator correlates against their
/// own logs, the offset is what makes the timeline readable.
#[derive(Debug, Clone, Serialize)]
pub struct Mark {
    pub at: u64,
    pub off: i64,
    /// Node name, or empty for the client lane.
    pub lane: String,
    pub kind: &'static str,
    pub detail: String,
}

/// One poll: what the client saw and what the disks held at the same instant.
#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub at: u64,
    pub off: i64,
    pub copies: usize,
    pub status: u16,
    pub md5_ok: bool,
    pub holders: Vec<String>,
}

/// One copy of the arena object as it sat on one device at one instant.
#[derive(Debug, Clone, Serialize)]
pub struct CopyRow {
    pub node: String,
    pub device: String,
    /// "primary" | "handoff"
    pub role: &'static str,
    pub index: usize,
    pub file: String,
    pub size: u64,
    pub version: String,
    pub frag: Option<u32>,
    pub durable: bool,
}

/// The whole cluster's answer at one instant.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Census {
    pub at: u64,
    pub off: i64,
    pub rows: Vec<CopyRow>,
    /// Copies of the *current* version sitting on primaries. Older versions are
    /// copies of a previous object and counting them would overstate durability.
    pub current: usize,
    pub unreachable: Vec<String>,
    /// Which nodes held a current copy, for the per-node presence track.
    pub holders: Vec<String>,
    /// Suffixes each node has marked invalid for this partition. Empty is the
    /// interesting case: it is why a removed file can go unnoticed.
    pub invalid: BTreeMap<String, String>,
}

/// A daemon pass line, parsed. `suffix_syncs` and `reverts` are the only
/// counters that mean work was done, so they are what attribution reads.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PassLine {
    pub node: String,
    /// "replicator" | "reconstructor"
    pub daemon: String,
    pub at: u64,
    pub suffix_syncs: u64,
    pub reverts: u64,
    pub failures: u64,
}

impl PassLine {
    fn worked(&self) -> bool {
        self.suffix_syncs > 0 || self.reverts > 0
    }
}

/// One line of the safety drill: a path the tool tried to damage and the reason
/// the guard refused it.
#[derive(Debug, Clone, Serialize)]
pub struct DrillLine {
    pub what: String,
    pub path: String,
    pub refused: bool,
    pub reason: String,
}

/// One experiment, start to finish. Cloned out of the store for rendering, so
/// the page never holds the lock across a render.
#[derive(Debug, Clone, Serialize)]
pub struct Run {
    pub id: String,
    pub started: u64,
    pub finished: Option<u64>,
    pub phase: Phase,
    /// A one-line "what is happening now", for the in-flight page.
    pub step: String,
    pub error: String,

    pub fault: Fault,
    pub prediction: Prediction,
    pub deadline: u64,
    /// Prove the guard and touch nothing.
    pub drill_only: bool,

    pub policy_index: u32,
    pub policy_name: String,
    pub policy_ec: Option<(u32, u32)>,
    pub data_dir: String,
    pub container: String,
    pub object: String,
    pub md5: String,
    pub size: u64,
    pub partition: u32,
    pub hash: String,
    pub wanted: usize,

    pub target: Option<Target>,
    /// The damaged file's own checksum, before the fault and at the end. A
    /// corrupted copy keeps its name and its size, so a directory listing is
    /// blind to it and only this can say whether the bytes came back.
    pub digest_before: String,
    pub digest_after: String,
    pub fault_at: Option<u64>,
    pub converged_at: Option<u64>,
    pub undone_at: Option<u64>,

    pub before: Census,
    pub worst: Census,
    pub after: Census,
    pub samples: Vec<Sample>,
    pub marks: Vec<Mark>,
    pub passes_before: Vec<PassLine>,
    pub passes_after: Vec<PassLine>,
    /// The pass lines that actually show work inside the fault window.
    pub evidence: Vec<PassLine>,
    /// node -> systemd's answer about the object auditor.
    pub auditors: Vec<(String, String)>,
    pub drill: Vec<DrillLine>,

    pub journal_id: Option<String>,
    pub undo_script: String,
    pub undo_ok: bool,
    pub outcome: Option<Outcome>,
}

impl Run {
    fn mark(&mut self, at: u64, lane: &str, kind: &'static str, detail: String) {
        let off = match self.fault_at {
            Some(f) => at as i64 - f as i64,
            None => 0,
        };
        self.marks.push(Mark {
            at,
            off,
            lane: lane.to_string(),
            kind,
            detail,
        });
    }
    fn is_live(&self) -> bool {
        matches!(self.phase, Phase::Seeding | Phase::Running)
    }
}

/// At most a handful of runs are kept: the arcade is a scoreboard, not an
/// archive, and a report whose cluster has since changed is misleading.
const KEEP_RUNS: usize = 6;

fn store() -> &'static std::sync::Mutex<Vec<Run>> {
    static S: std::sync::OnceLock<std::sync::Mutex<Vec<Run>>> = std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

fn push_run(r: Run) {
    let mut s = store().lock().unwrap();
    s.insert(0, r);
    s.truncate(KEEP_RUNS);
}

fn edit<R>(id: &str, f: impl FnOnce(&mut Run) -> R) -> Option<R> {
    let mut s = store().lock().unwrap();
    s.iter_mut().find(|r| r.id == id).map(f)
}

fn latest() -> Option<Run> {
    store().lock().unwrap().first().cloned()
}

fn history() -> Vec<Run> {
    store().lock().unwrap().clone()
}

fn in_flight() -> Option<String> {
    store()
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.is_live())
        .map(|r| r.id.clone())
}

// ------------------------------------------------------------------ time

/// UTC wall clock from a unix timestamp, with no date library. The report
/// promises real timestamps, so they have to be ones an operator can grep their
/// own logs for.
pub fn iso(t: u64) -> String {
    let days = (t / 86400) as i64;
    let secs = t % 86400;
    // Howard Hinnant's civil-from-days, on the 0000-03-01 era.
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Just the clock, for dense cells where the date is already on the page.
pub fn clock(t: u64) -> String {
    let s = t % 86400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

fn now() -> u64 {
    crate::util::now_secs()
}

// ------------------------------------------------------------------ arena

/// One container per policy: a container carries exactly one policy, so an
/// arcade that offers both needs two. The name is derived, never supplied.
pub fn arena_container(index: u32) -> String {
    if index == 0 {
        ARENA.to_string()
    } else {
        format!("{ARENA}-p{index}")
    }
}

fn is_arena(name: &str) -> bool {
    name == ARENA || name.starts_with(&format!("{ARENA}-p"))
}

/// The root every guard measures against: the mutation sandbox when one is
/// configured, otherwise the node root, so the read-only drill still has
/// something real to refuse against on an unarmed console.
fn guard_root(state: &Arc<AppState>) -> String {
    if state.cfg.lab_root.is_empty() {
        state.cfg.node_root.trim_end_matches('/').to_string()
    } else {
        state.cfg.lab_root.trim_end_matches('/').to_string()
    }
}

/// Deterministic, incompressible filler. Deterministic so a report can be
/// reproduced; incompressible so the on-disk sizes are the real thing.
fn arena_bytes(seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    let mut v = Vec::with_capacity(ARENA_BYTES);
    while v.len() < ARENA_BYTES {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        v.extend_from_slice(&s.to_le_bytes());
    }
    v.truncate(ARENA_BYTES);
    v
}

fn suffix3(hash: &str) -> &str {
    if hash.len() >= 3 {
        &hash[hash.len() - 3..]
    } else {
        hash
    }
}

fn hash_dir(root: &str, device: &str, data_dir: &str, part: u32, hash: &str) -> String {
    format!(
        "{}/{}/{}/{}/{}/{}",
        root.trim_end_matches('/'),
        device,
        data_dir,
        part,
        suffix3(hash),
        hash
    )
}

fn part_dir(root: &str, device: &str, data_dir: &str, part: u32) -> String {
    format!(
        "{}/{}/{}/{}",
        root.trim_end_matches('/'),
        device,
        data_dir,
        part
    )
}

/// Names that reach a remote command line are matched against a strict set
/// first. They come from the ring and from config rather than from a caller,
/// but a probe that cannot prove that is refused instead of trusted.
fn safe_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 40
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Split an object filename into version, fragment index and durability.
/// Replication writes `<ts>.data`; erasure coding writes `<ts>#<frag>#d.data`,
/// where the trailing `#d` *is* the durability marker — this cluster keeps no
/// separate `.durable` file, so a fault that looked for one would test nothing.
pub fn split_name(name: &str) -> (String, Option<u32>, bool) {
    let stem = name
        .strip_suffix(".data")
        .or_else(|| name.strip_suffix(".meta"))
        .or_else(|| name.strip_suffix(".ts"))
        .unwrap_or(name);
    let mut parts = stem.split('#');
    let ts = parts.next().unwrap_or("").to_string();
    let frag = parts.next().and_then(|f| f.parse().ok());
    let durable = stem.ends_with("#d");
    (ts, frag, durable)
}

// ------------------------------------------------------------------ probing

/// One command per node that answers everything a poll needs: what is in the
/// hash directory on each of that node's devices, which suffixes the node has
/// marked invalid for this partition, the recent daemon pass lines, and whether
/// an object auditor exists at all.
///
/// It is one command rather than four because each extra ssh is a round trip
/// inside a five-second poll, and a probe that takes longer than its own
/// interval stops measuring the cluster and starts measuring itself.
fn probe_cmd(
    root: &str,
    data_dir: &str,
    part: u32,
    hash: &str,
    devices: &[String],
) -> Option<String> {
    if !is_hex(hash) || !safe_name(data_dir) || devices.iter().any(|d| !safe_name(d)) {
        return None;
    }
    let mut cmd = String::new();
    for d in devices {
        cmd.push_str(&format!(
            "echo '@d {d}'; find {dir} -maxdepth 1 -type f -printf '%s %f\\n' 2>/dev/null; \
             echo '@i {d}'; cat {pdir}/hashes.invalid 2>/dev/null | tr '\\n' ' '; echo; ",
            dir = hash_dir(root, d, data_dir, part, hash),
            pdir = part_dir(root, d, data_dir, part),
        ));
    }
    cmd.push_str(
        "echo '@p '; journalctl -u swift-object-replicator -u swift-object-reconstructor \
         --no-pager -o short-unix --since '-8min' 2>/dev/null | grep -F 'pass:' | tail -40; \
         echo '@a '; systemctl show -p LoadState -p ActiveState --value swift-object-auditor \
         2>/dev/null | tr '\\n' '/'; echo; exit 0",
    );
    Some(cmd)
}

#[derive(Default)]
struct NodeProbe {
    files: BTreeMap<String, Vec<(u64, String)>>,
    invalid: BTreeMap<String, String>,
    passes: Vec<PassLine>,
    auditor: String,
}

/// `INFO object-replicator pass: partitions=344 suffix_syncs=0 reverts=0 failures=0`,
/// prefixed by a unix timestamp because the probe asks for `short-unix`.
fn parse_pass(node: &str, line: &str) -> Option<PassLine> {
    if !line.contains("pass:") {
        return None;
    }
    let at = line
        .split_whitespace()
        .next()
        .and_then(|t| t.split('.').next())
        .and_then(|t| t.parse::<u64>().ok())?;
    let daemon = if line.contains("object-reconstructor") {
        "reconstructor"
    } else if line.contains("object-replicator") {
        "replicator"
    } else {
        return None;
    };
    let num = |k: &str| -> u64 {
        line.split_whitespace()
            .find_map(|t| t.strip_prefix(k))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    Some(PassLine {
        node: node.to_string(),
        daemon: daemon.to_string(),
        at,
        suffix_syncs: num("suffix_syncs="),
        reverts: num("reverts="),
        failures: num("failures="),
    })
}

fn parse_probe(node: &str, out: &str) -> NodeProbe {
    let mut p = NodeProbe::default();
    let mut sec = "";
    let mut dev = String::new();
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix('@') {
            let (tag, arg) = rest.split_at(1.min(rest.len()));
            sec = match tag {
                "d" => "d",
                "i" => "i",
                "p" => "p",
                "a" => "a",
                _ => "",
            };
            dev = arg.trim().to_string();
            if sec == "d" {
                p.files.entry(dev.clone()).or_default();
            }
            continue;
        }
        match sec {
            "d" => {
                if let Some((size, name)) = line.trim().split_once(' ') {
                    if let Ok(size) = size.parse::<u64>() {
                        p.files
                            .entry(dev.clone())
                            .or_default()
                            .push((size, name.trim().to_string()));
                    }
                }
            }
            "i" => {
                let v = line.trim();
                if !v.is_empty() {
                    p.invalid.insert(dev.clone(), v.to_string());
                }
            }
            "p" => {
                if let Some(pl) = parse_pass(node, line) {
                    p.passes.push(pl);
                }
            }
            "a" => {
                if !line.trim().is_empty() && p.auditor.is_empty() {
                    p.auditor = line.trim().trim_end_matches('/').to_string();
                }
            }
            _ => {}
        }
    }
    p
}

/// Every (node, device, role) the ring placed this object on, primaries first.
struct Placement {
    slots: Vec<(String, String, &'static str, usize)>,
}

impl Placement {
    fn of(loc: &ringlab::Located) -> Placement {
        let mut slots = Vec::new();
        for n in &loc.primaries {
            slots.push((n.node.clone(), n.device.clone(), "primary", n.index));
        }
        for n in &loc.handoffs {
            slots.push((n.node.clone(), n.device.clone(), "handoff", n.index));
        }
        Placement { slots }
    }
    fn nodes(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for (n, _, _, _) in &self.slots {
            if !v.contains(n) {
                v.push(n.clone());
            }
        }
        v
    }
    fn devices_on(&self, node: &str) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for (n, d, _, _) in &self.slots {
            if n == node && !v.contains(d) {
                v.push(d.clone());
            }
        }
        v
    }
    fn role_of(&self, node: &str, dev: &str) -> (&'static str, usize) {
        self.slots
            .iter()
            .find(|(n, d, _, _)| n == node && d == dev)
            .map(|(_, _, r, i)| (*r, *i))
            .unwrap_or(("handoff", 0))
    }
}

/// One full sweep of the cluster: a census, plus whatever the daemons have
/// logged since.
async fn sweep_cluster(
    state: &Arc<AppState>,
    place: &Placement,
    data_dir: &str,
    part: u32,
    hash: &str,
) -> (Census, Vec<PassLine>, Vec<(String, String)>) {
    let root = state.cfg.node_root.trim_end_matches('/').to_string();
    let mut jobs: Vec<(String, String)> = Vec::new();
    for node in place.nodes() {
        let devs = place.devices_on(&node);
        if let Some(cmd) = probe_cmd(&root, data_dir, part, hash, &devs) {
            jobs.push((node, cmd));
        }
    }
    let results = nodes::fan_out_each(state, jobs).await;
    let at = now();
    let mut c = Census {
        at,
        ..Default::default()
    };
    let mut passes = Vec::new();
    let mut auditors = Vec::new();
    for r in results {
        if !r.ok {
            c.unreachable.push(r.node.clone());
            continue;
        }
        let p = parse_probe(&r.node, &r.out);
        passes.extend(p.passes);
        auditors.push((r.node.clone(), p.auditor));
        for (dev, files) in &p.invalid {
            c.invalid
                .insert(format!("{}/{}", r.node, dev), files.clone());
        }
        for (dev, files) in p.files {
            let (role, index) = place.role_of(&r.node, &dev);
            for (size, name) in files {
                let (version, frag, durable) = split_name(&name);
                c.rows.push(CopyRow {
                    node: r.node.clone(),
                    device: dev.clone(),
                    role,
                    index,
                    file: name,
                    size,
                    version,
                    frag,
                    durable,
                });
            }
        }
    }
    c.rows
        .sort_by(|a, b| (a.role, &a.node, &a.device).cmp(&(b.role, &b.node, &b.device)));
    (c, passes, auditors)
}

/// Count copies of one version that are current, durable and on a primary.
/// Anything else is not a copy of the object the API serves today, and counting
/// it would overstate what the cluster actually has.
pub fn tally_census(c: &mut Census, version: &str) {
    let mut holders: Vec<String> = Vec::new();
    let mut n = 0usize;
    for r in &c.rows {
        if r.role == "primary"
            && r.version == version
            && r.file.ends_with(".data")
            && (r.frag.is_none() || r.durable)
        {
            n += 1;
            if !holders.contains(&r.node) {
                holders.push(r.node.clone());
            }
        }
    }
    c.current = n;
    c.holders = holders;
}

pub fn newest_version(c: &Census) -> String {
    c.rows
        .iter()
        .filter(|r| r.file.ends_with(".data"))
        .map(|r| r.version.clone())
        .max_by(|a, b| {
            a.parse::<f64>()
                .unwrap_or(0.0)
                .partial_cmp(&b.parse::<f64>().unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap_or_default()
}

// ------------------------------------------------------------------ the read

struct ReadResult {
    status: u16,
    md5_ok: Option<bool>,
}

/// Read the arena object back and checksum what came out. The console's session
/// storage URL is already rebased onto a real node address rather than the
/// load-balancer VIP, which is the only address reachable from a cluster node.
async fn read_object(
    state: &Arc<AppState>,
    sid: &str,
    container: &str,
    object: &str,
    md5: &str,
) -> ReadResult {
    let sub = format!("/{}/{}", enc_seg(container), enc_seg(object));
    let resp = match swift::call(state, sid, reqwest::Method::GET, &sub, &[], &[], None).await {
        Ok(r) => r,
        Err(_) => {
            return ReadResult {
                status: 0,
                md5_ok: None,
            }
        }
    };
    let status = resp.status().as_u16();
    if status >= 300 {
        return ReadResult {
            status,
            md5_ok: None,
        };
    }
    match resp.bytes().await {
        Ok(b) => {
            let mut h = Md5::new();
            h.update(&b);
            ReadResult {
                status,
                md5_ok: Some(hex::encode(h.finalize()) == md5),
            }
        }
        // A body that breaks off mid-stream is the interesting corruption case:
        // the status line already promised 200.
        Err(_) => ReadResult {
            status,
            md5_ok: Some(false),
        },
    }
}

/// Checksum one file on one node. Only the corruption fault needs it, and only
/// for the single file it damaged, so it is a separate one-node round trip
/// rather than something every poll pays for.
async fn on_disk_digest(state: &Arc<AppState>, node: &str, path: &str) -> String {
    let out = nodes::run(
        state,
        node,
        &format!("md5sum {path} 2>/dev/null | cut -d' ' -f1; exit 0"),
    )
    .await
    .unwrap_or_default();
    let d = out.trim().to_string();
    if d.len() == 32 && is_hex(&d) {
        d
    } else {
        String::new()
    }
}

// ------------------------------------------------------------------ faults

/// The apply/undo pair for one fault, built from a target the guard already
/// approved.
///
/// Both scripts are written with every path as a bare absolute token, because
/// [`nodes::mutate`] validates the literal script text against the lab root —
/// hiding a path inside a shell variable would slip past that check, which is
/// exactly the kind of clever a mutation path must not be.
#[derive(Debug)]
pub struct Scripts {
    pub apply: String,
    pub undo: String,
    /// What the fault did, for the timeline.
    pub detail: String,
}

fn park_root(root: &str, device: &str) -> String {
    format!("{}/{}/chaos-park", root.trim_end_matches('/'), device)
}

fn park_dir(root: &str, device: &str, run: &str) -> String {
    format!("{}/{}", park_root(root, device), run)
}

pub fn build_scripts(
    fault: Fault,
    root: &str,
    device: &str,
    dir: &str,
    file: &str,
    run: &str,
) -> Result<Scripts, String> {
    let src = format!("{dir}/{file}");
    let park = park_dir(root, device, run);
    let parked = format!("{park}/{file}");
    // Both rmdirs fail harmlessly while anything is still parked, so a second
    // experiment in flight cannot have its sandbox pulled out from under it.
    let sweep = format!("rmdir {park} 2>/dev/null; rmdir {} 2>/dev/null; exit 0", park_root(root, device));
    Ok(match fault {
        // Parked outside every objects tree rather than renamed in place: a
        // stray file inside a hash directory is something the daemons are
        // entitled to clean up, and an undo that races a cleanup is not an undo.
        Fault::DropCopy => Scripts {
            apply: format!("mkdir -p {park} && mv -f {src} {parked}"),
            undo: format!(
                "if [ -e {src} ]; then rm -f {parked}; else mv -f {parked} {src}; fi; {sweep}"
            ),
            detail: format!("{file} moved off {device}"),
        },
        // The original is copied out first, so the undo restores bytes rather
        // than trying to reconstruct them.
        Fault::CorruptCopy => Scripts {
            apply: format!(
                "mkdir -p {park} && cp -p {src} {parked} && dd if=/dev/urandom \
                 of={src} bs=1 seek=4096 count=512 conv=notrunc status=none"
            ),
            undo: format!(
                "if [ -e {parked} ]; then mkdir -p {dir} && cp -p {parked} {src} && rm -f {parked}; fi; {sweep}"
            ),
            detail: format!("512 bytes overwritten inside {file} on {device}"),
        },
        Fault::DropDurable => {
            let stripped = file
                .strip_suffix("#d.data")
                .map(|s| format!("{s}.data"))
                .ok_or_else(|| format!("{file} carries no durability marker to remove"))?;
            let dst = format!("{dir}/{stripped}");
            Scripts {
                // If the reconstructor rebuilt a durable fragment while the
                // marker was off, the rebuilt file wins and the stripped one is
                // the leftover to remove.
                apply: format!("mv -f {src} {dst}"),
                undo: format!("if [ -e {src} ]; then rm -f {dst}; else mv -f {dst} {src}; fi; exit 0"),
                detail: format!("durability marker removed from {file} on {device}"),
            }
        }
        Fault::StaleTimestamp => {
            let (ts, _, _) = split_name(file);
            let whole: u64 = ts
                .split('.')
                .next()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("{file} has no readable version stamp"))?;
            let frac = ts
                .split_once('.')
                .map(|(_, f)| f.to_string())
                .unwrap_or_default();
            let older = format!("{}.{}", whole.saturating_sub(86400), frac);
            let stale = file.replacen(&ts, &older, 1);
            if stale == *file {
                return Err(format!("{file} could not be restamped"));
            }
            let dst = format!("{dir}/{stale}");
            Scripts {
                apply: format!("mv -f {src} {dst}"),
                undo: format!("if [ -e {src} ]; then rm -f {dst}; else mv -f {dst} {src}; fi; exit 0"),
                detail: format!("{file} restamped a day into the past on {device}"),
            }
        }
    })
}

// ------------------------------------------------------------------ drill

/// Prove the guard, on this cluster, against a real file that belongs to
/// somebody else.
///
/// This is the single most important thing the tool can show, so it runs on
/// every experiment rather than on request. Three attempts: a genuine on-disk
/// copy of an object outside the arena, resolved through the ring exactly the
/// way a target would be; a config file; and a traversal. Nothing is touched —
/// the guard is asked, and its refusal is quoted verbatim.
async fn safety_drill(
    state: &Arc<AppState>,
    sid: &str,
    account: &str,
    arena_hash: &str,
) -> Vec<DrillLine> {
    let root = guard_root(state);
    let mut out = Vec::new();

    match outside_copy(state, sid, account).await {
        Ok((label, path)) => {
            let r = check_target(&path, arena_hash, &root);
            out.push(DrillLine {
                what: label,
                path,
                refused: r.is_err(),
                reason: r.err().unwrap_or_else(|| "ALLOWED".into()),
            });
        }
        Err(e) => out.push(DrillLine {
            what: "chaos.drill.outside".into(),
            path: String::new(),
            refused: false,
            reason: e,
        }),
    }

    let conf = format!("{}/swift.conf", state.cfg.swift_dir.trim_end_matches('/'));
    let r = check_target(&conf, arena_hash, &root);
    out.push(DrillLine {
        what: "chaos.drill.conf".into(),
        path: conf,
        refused: r.is_err(),
        reason: r.err().unwrap_or_else(|| "ALLOWED".into()),
    });

    let traversal = format!("{root}/d1/../../etc/shadow/{arena_hash}/x.data");
    let r = check_target(&traversal, arena_hash, &root);
    out.push(DrillLine {
        what: "chaos.drill.traversal".into(),
        path: traversal,
        refused: r.is_err(),
        reason: r.err().unwrap_or_else(|| "ALLOWED".into()),
    });
    out
}

/// Resolve a real on-disk copy of some object that is not the arena's, so the
/// drill runs against the cluster rather than against a string someone made up.
async fn outside_copy(
    state: &Arc<AppState>,
    sid: &str,
    account: &str,
) -> Result<(String, String), String> {
    let buckets = swift::list_buckets(state, sid).await.map_err(|e| e.msg())?;
    let cand = buckets
        .iter()
        .find(|b| b.count > 0 && !is_arena(&b.name))
        .ok_or("no container outside the arena holds an object to test against")?;
    let listing = swift::list_objects(state, sid, &cand.name, "", true, 1)
        .await
        .map_err(|e| e.msg())?;
    let obj = listing
        .files
        .first()
        .and_then(|f| f.name.clone())
        .ok_or_else(|| format!("{} listed no object", cand.name))?;

    let (_, h) = swift::head(state, sid, &format!("/{}", enc_seg(&cand.name)))
        .await
        .map_err(|e| e.msg())?;
    let pname = h
        .get("x-storage-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let pol = ringlab::policy_by_name(state, pname)
        .await
        .ok_or("could not resolve that container's storage policy")?;
    let loc = ringlab::locate(state, pol.index, account, Some(&cand.name), Some(&obj)).await?;
    let slot = loc.primaries.first().ok_or("the ring placed it nowhere")?;
    if !safe_name(&slot.device) {
        return Err("unsafe device name from the ring".into());
    }
    let root = state.cfg.node_root.trim_end_matches('/');
    let dir = hash_dir(root, &slot.device, &pol.data_dir, loc.partition, &loc.hash);
    let listing = nodes::run(
        state,
        &slot.node,
        &format!(
            "find {dir} -maxdepth 1 -type f -name '*.data' -printf '%f\\n' 2>/dev/null; exit 0"
        ),
    )
    .await?;
    let file = listing
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .ok_or("that object has no copy on its first primary right now")?;
    Ok((format!("{}/{}", cand.name, obj), format!("{dir}/{file}")))
}

// ------------------------------------------------------------- the experiment

/// Drive one experiment to the end, then put the cluster back.
///
/// The undo runs in the outer function so that every early return — a refused
/// target, a node that stopped answering, a bad request that got this far —
/// still leaves the cluster the way it was found. The TTL sweeper is the second
/// net, not the first.
async fn experiment(state: Arc<AppState>, sid: String, id: String) {
    if let Err(e) = drive(&state, &sid, &id).await {
        edit(&id, |run| {
            run.error = e;
            run.phase = Phase::Failed;
        });
    }
    let jid = edit(&id, |r| r.journal_id.clone()).flatten();
    if let Some(jid) = jid {
        let ok = nodes::undo(&state, &jid).await.is_ok();
        let at = now();
        edit(&id, |r| {
            r.undo_ok = ok;
            r.undone_at = Some(at);
            let node = r.target.as_ref().map(|t| t.node.clone()).unwrap_or_default();
            r.mark(at, &node, "undo", String::new());
        });
    }
    edit(&id, |r| {
        if r.phase != Phase::Failed {
            r.phase = Phase::Done;
        }
        r.step.clear();
        r.finished = Some(now());
    });
}

async fn drive(state: &Arc<AppState>, sid: &str, id: &str) -> Result<(), String> {
    let (fault, policy, deadline, drill_only) =
        edit(id, |r| (r.fault, r.policy_index, r.deadline, r.drill_only))
            .ok_or("run disappeared")?;
    let sess = state
        .sessions
        .get(sid)
        .ok_or("the console session expired before the experiment could start")?;
    let account = capsule::session_account(&sess);
    let pol = ringlab::policy(state, policy).await?;
    let container = arena_container(policy);

    // The hash is a function of the path, so the guard can be proven before an
    // object exists — which is what makes a drill genuinely read-only.
    let loc = ringlab::locate(state, policy, &account, Some(&container), Some(ARENA_OBJECT)).await?;
    edit(id, |r| {
        r.policy_name = pol.name.clone();
        r.policy_ec = match (pol.ec_ndata, pol.ec_nparity) {
            (Some(k), Some(m)) => Some((k, m)),
            _ => None,
        };
        r.data_dir = pol.data_dir.clone();
        r.partition = loc.partition;
        r.hash = loc.hash.clone();
        r.wanted = loc.primaries.len();
    });

    edit(id, |r| r.step = "drill".into());
    let drill = safety_drill(state, sid, &account, &loc.hash).await;
    let all_refused = !drill.is_empty() && drill.iter().all(|d| d.refused);
    edit(id, |r| r.drill = drill);
    if drill_only {
        return Ok(());
    }
    if !all_refused {
        return Err(
            "the ownership guard did not refuse a path outside the arena, so no fault was applied"
                .into(),
        );
    }
    if fault.ec_only() && !pol.is_ec() {
        return Err(format!(
            "{} keeps no durability marker to remove — run this fault against an erasure-coded policy",
            pol.name
        ));
    }

    // --- seed -------------------------------------------------------------
    edit(id, |r| r.step = "seeding".into());
    let resp = swift::call(
        state,
        sid,
        reqwest::Method::PUT,
        &format!("/{}", enc_seg(&container)),
        &[],
        &[("X-Storage-Policy".to_string(), pol.name.clone())],
        None,
    )
    .await
    .map_err(|e| e.msg())?;
    if !resp.status().is_success() {
        return Err(format!(
            "the arena container could not be created ({})",
            resp.status().as_u16()
        ));
    }
    let data = arena_bytes(now() ^ 0x9e37_79b9_7f4a_7c15);
    let mut h = Md5::new();
    h.update(&data);
    let md5 = hex::encode(h.finalize());
    let resp = swift::call(
        state,
        sid,
        reqwest::Method::PUT,
        &format!("/{}/{}", enc_seg(&container), enc_seg(ARENA_OBJECT)),
        &[],
        &[(
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        )],
        Some(Bytes::from(data)),
    )
    .await
    .map_err(|e| e.msg())?;
    if !resp.status().is_success() {
        return Err(format!(
            "the arena object could not be written ({})",
            resp.status().as_u16()
        ));
    }
    let seeded = now();
    let place = Placement::of(&loc);
    edit(id, |r| {
        r.container = container.clone();
        r.md5 = md5.clone();
        r.size = ARENA_BYTES as u64;
        r.mark(seeded, "", "seed", format!("{container}/{ARENA_OBJECT}"));
    });

    // --- before -----------------------------------------------------------
    edit(id, |r| r.step = "census".into());
    let (mut before, passes0, auditors) =
        sweep_cluster(state, &place, &pol.data_dir, loc.partition, &loc.hash).await;
    let version = newest_version(&before);
    tally_census(&mut before, &version);
    before.off = before.at as i64 - seeded as i64;
    if before.current == 0 {
        return Err(
            "the arena object was written but no primary holds it — refusing to injure an object \
             that is already broken"
                .into(),
        );
    }
    let copies_before = before.current;
    edit(id, |r| {
        r.before = before.clone();
        r.passes_before = passes0.clone();
        r.auditors = auditors.clone();
    });

    // --- pick a target ----------------------------------------------------
    let target_row = before
        .rows
        .iter()
        .find(|r| {
            r.role == "primary"
                && r.version == version
                && r.file.ends_with(".data")
                && (!fault.ec_only() || r.durable)
        })
        .cloned()
        .ok_or("no primary holds a copy this fault can be applied to")?;

    let root = state.cfg.node_root.trim_end_matches('/').to_string();
    let dir = hash_dir(
        &root,
        &target_row.device,
        &pol.data_dir,
        loc.partition,
        &loc.hash,
    );
    let path = format!("{dir}/{}", target_row.file);
    // The guard, on the real path, before anything is written.
    check_target(&path, &loc.hash, &guard_root(state))?;
    let target = Target {
        node: target_row.node.clone(),
        device: target_row.device.clone(),
        path: path.clone(),
        file: target_row.file.clone(),
    };
    let scripts = build_scripts(fault, &root, &target_row.device, &dir, &target_row.file, id)?;
    let digest_before = on_disk_digest(state, &target.node, &path).await;
    edit(id, |r| {
        r.target = Some(target.clone());
        r.undo_script = scripts.undo.clone();
        r.digest_before = digest_before.clone();
    });

    // --- apply ------------------------------------------------------------
    edit(id, |r| r.step = "applying".into());
    let entry = nodes::mutate(
        state,
        nodes::Mutation {
            node: &target.node,
            scope: nodes::Scope::LabContainer,
            script: &scripts.apply,
            undo: &scripts.undo,
            reason: &format!("chaos:{}:{}", fault.id(), id),
            ttl_secs: FAULT_TTL_SECS,
        },
    )
    .await?;
    let fault_at = now();
    edit(id, |r| {
        r.journal_id = Some(entry.id.clone());
        r.fault_at = Some(fault_at);
        r.phase = Phase::Running;
        r.step = "watching".into();
        r.mark(fault_at, &target.node, "fault", scripts.detail.clone());
    });

    // --- watch ------------------------------------------------------------
    let mut worst: Option<Census> = None;
    let mut converged_at: Option<u64> = None;
    let mut copies_after_fault: Option<usize> = None;
    let mut evidence: Vec<PassLine> = Vec::new();
    let mut passes_after: Vec<PassLine> = Vec::new();
    let mut prev_holders = before.holders.clone();
    let mut prev_read_ok: Option<bool> = None;
    let mut digest_now = digest_before.clone();
    // Both are written on the first pass of the loop below, before either break.
    let last: Census;
    let last_read: ReadResult;

    loop {
        let read = read_object(state, sid, &container, ARENA_OBJECT, &md5).await;
        let (mut c, passes, _) =
            sweep_cluster(state, &place, &pol.data_dir, loc.partition, &loc.hash).await;
        tally_census(&mut c, &version);
        c.off = c.at as i64 - fault_at as i64;

        let at = c.at;
        let off = c.off;
        let holders = c.holders.clone();
        let current = c.current;
        let read_ok = read.status == 200 && read.md5_ok == Some(true);
        let elapsed = at.saturating_sub(fault_at);
        // Three of the four faults remove a copy from the count. Corruption does
        // not: the file keeps its name and its size, so the census cannot see it
        // and only the file's own checksum can say whether the bytes came back.
        let healed = if fault == Fault::CorruptCopy {
            digest_now = on_disk_digest(state, &target.node, &target.path).await;
            !digest_before.is_empty() && digest_now == digest_before
        } else {
            current >= copies_before
        };

        if copies_after_fault.is_none() {
            copies_after_fault = Some(current);
        }
        if worst.as_ref().map(|w| w.current).unwrap_or(usize::MAX) > current {
            worst = Some(c.clone());
        }
        merge_passes(&mut passes_after, passes);
        for p in passes_after.iter() {
            if p.at >= fault_at && p.worked() && !evidence.contains(p) {
                evidence.push(p.clone());
            }
        }

        let sample = Sample {
            at,
            off,
            copies: current,
            status: read.status,
            md5_ok: read.md5_ok == Some(true),
            holders: holders.clone(),
        };
        let gone: Vec<String> = prev_holders
            .iter()
            .filter(|n| !holders.contains(n))
            .cloned()
            .collect();
        let back: Vec<String> = holders
            .iter()
            .filter(|n| !prev_holders.contains(n))
            .cloned()
            .collect();
        // Only a change of client-visible state earns a row: ninety seconds of
        // identical successful reads is one fact, not eighteen. Every individual
        // read is still a mark on the timeline.
        let read_changed = prev_read_ok != Some(read_ok);
        prev_read_ok = Some(read_ok);
        edit(id, |r| {
            r.samples.push(sample);
            for n in &gone {
                r.mark(at, n, "gone", String::new());
            }
            for n in &back {
                r.mark(at, n, "back", String::new());
            }
            if read_changed {
                r.mark(
                    at,
                    "",
                    if read_ok { "read_ok" } else { "read_bad" },
                    format!("HTTP {}", read.status),
                );
            }
            r.passes_after = passes_after.clone();
            r.evidence = evidence.clone();
            r.worst = worst.clone().unwrap_or_default();
            r.step = format!("watching · {elapsed}s");
        });
        prev_holders = holders;

        if healed && read.md5_ok == Some(true) {
            converged_at = Some(at);
            edit(id, |r| {
                r.converged_at = Some(at);
                r.mark(at, "", "converged", String::new());
            });
            last = c;
            last_read = read;
            break;
        }
        if elapsed >= deadline {
            last = c;
            last_read = read;
            break;
        }
        edit(id, |r| r.digest_after = digest_now.clone());
        tokio::time::sleep(std::time::Duration::from_secs(POLL_SECS)).await;
    }

    // --- who did it -------------------------------------------------------
    // A pass line is written when the pass ends, so the one that proves the
    // repair usually lands after the copy is already back. Waiting for it is the
    // difference between naming a daemon and guessing one.
    if converged_at.is_some() && evidence.is_empty() {
        edit(id, |r| r.step = "waiting for a daemon to log its pass".into());
        let until = now() + EVIDENCE_GRACE_SECS;
        while now() < until && evidence.is_empty() {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let (_, passes, _) =
                sweep_cluster(state, &place, &pol.data_dir, loc.partition, &loc.hash).await;
            merge_passes(&mut passes_after, passes);
            for p in passes_after.iter() {
                if p.at >= fault_at && p.worked() && !evidence.contains(p) {
                    evidence.push(p.clone());
                }
            }
            edit(id, |r| {
                r.passes_after = passes_after.clone();
                r.evidence = evidence.clone();
            });
        }
    }

    let repaired = if fault == Fault::CorruptCopy {
        !digest_before.is_empty() && digest_now == digest_before
    } else {
        last.current >= copies_before
    };
    let repaired_by = if !repaired {
        "none".to_string()
    } else if let Some(p) = evidence.first() {
        p.daemon.clone()
    } else {
        // Measured nothing, so claim nothing. Naming the daemon the policy
        // implies would be a guess wearing a measurement's clothes.
        "unattributed".to_string()
    };

    let outcome = Outcome {
        readable: last_read.status == 200,
        read_status: last_read.status,
        etag_matched: last_read.md5_ok,
        repaired,
        repaired_by,
        converge_secs: converged_at.map(|t| t.saturating_sub(fault_at)),
        copies_before,
        copies_after_fault: copies_after_fault.unwrap_or(copies_before),
        copies_final: last.current,
    };
    edit(id, |r| {
        r.after = last.clone();
        r.digest_after = digest_now.clone();
        r.outcome = Some(outcome.clone());
        if r.worst.rows.is_empty() {
            r.worst = last.clone();
        }
    });
    Ok(())
}

/// Journal lines repeat across polls; keep one entry per (node, daemon, pass).
fn merge_passes(into: &mut Vec<PassLine>, more: Vec<PassLine>) {
    for p in more {
        if !into
            .iter()
            .any(|q| q.node == p.node && q.daemon == p.daemon && q.at == p.at)
        {
            into.push(p);
        }
    }
    into.sort_by_key(|p| p.at);
}

// ------------------------------------------------------------------ verdict

/// The one sentence an operator can act on, plus the evidence that lets them
/// check it rather than trust it.
///
/// Composed at render time rather than at measurement time, because a verdict
/// is prose and prose has a language; the measurement does not.
pub struct Verdict {
    pub level: &'static str,
    pub headline: String,
    pub clauses: Vec<String>,
}

fn fill(tpl: &str, kv: &[(&str, String)]) -> String {
    let mut s = tpl.to_string();
    for (k, v) in kv {
        s = s.replace(k, v);
    }
    s
}

fn daemon_label(lang: &str, who: &str) -> String {
    match who {
        "replicator" => i18n::t(lang, "chaos.by.replicator"),
        "reconstructor" => i18n::t(lang, "chaos.by.reconstructor"),
        "none" => i18n::t(lang, "chaos.by.none"),
        _ => i18n::t(lang, "chaos.by.unknown"),
    }
    .to_string()
}

pub fn verdict(lang: &str, run: &Run) -> Verdict {
    let unit = i18n::t(
        lang,
        if run.policy_ec.is_some() {
            "chaos.u.fragment"
        } else {
            "chaos.u.replica"
        },
    );
    if run.phase == Phase::Failed {
        return Verdict {
            level: "bad",
            headline: i18n::t(lang, "chaos.v.failed").to_string(),
            clauses: vec![run.error.clone()],
        };
    }
    if run.drill_only {
        let refused = run.drill.iter().filter(|d| d.refused).count();
        return Verdict {
            level: if refused == run.drill.len() && !run.drill.is_empty() {
                "ok"
            } else {
                "bad"
            },
            headline: fill(
                i18n::t(lang, "chaos.v.drill"),
                &[
                    ("{n}", refused.to_string()),
                    ("{m}", run.drill.len().to_string()),
                ],
            ),
            clauses: vec![i18n::t(lang, "chaos.d.drillwhy").to_string()],
        };
    }
    let Some(o) = &run.outcome else {
        return Verdict {
            level: "warn",
            headline: i18n::t(lang, "chaos.v.running").to_string(),
            clauses: vec![i18n::t(lang, "chaos.d.running").to_string()],
        };
    };

    let need = run
        .policy_ec
        .map(|(k, _)| k as usize)
        .unwrap_or(1)
        .min(run.wanted.max(1));
    let headline = if !o.readable {
        fill(
            i18n::t(lang, "chaos.v.dark"),
            &[
                ("{status}", o.read_status.to_string()),
                ("{left}", o.copies_final.to_string()),
                ("{need}", need.to_string()),
                ("{unit}", unit.to_string()),
            ],
        )
    } else if o.repaired && run.fault == Fault::CorruptCopy {
        fill(
            i18n::t(lang, "chaos.v.scrubbed"),
            &[
                (
                    "{secs}",
                    o.converge_secs
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "?".into()),
                ),
                ("{unit}", unit.to_string()),
            ],
        )
    } else if run.fault == Fault::CorruptCopy {
        fill(
            i18n::t(lang, "chaos.v.rotten"),
            &[
                ("{wanted}", run.wanted.to_string()),
                ("{unit}", unit.to_string()),
                ("{secs}", run.deadline.to_string()),
            ],
        )
    } else if o.repaired {
        // An unattributed repair gets its own sentence rather than dropping
        // "not attributed" into the slot where a daemon's name belongs.
        fill(
            i18n::t(
                lang,
                if o.repaired_by == "unattributed" {
                    "chaos.v.repaired_un"
                } else {
                    "chaos.v.repaired"
                },
            ),
            &[
                (
                    "{secs}",
                    o.converge_secs
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "?".into()),
                ),
                ("{copies}", o.copies_final.to_string()),
                ("{wanted}", run.wanted.to_string()),
                ("{unit}", unit.to_string()),
                ("{who}", daemon_label(lang, &o.repaired_by)),
            ],
        )
    } else {
        fill(
            i18n::t(lang, "chaos.v.stuck"),
            &[
                ("{left}", o.copies_final.to_string()),
                ("{wanted}", run.wanted.to_string()),
                ("{unit}", unit.to_string()),
                ("{secs}", run.deadline.to_string()),
                ("{spare}", o.copies_final.saturating_sub(need).to_string()),
            ],
        )
    };

    // Evidence, strongest first. Every clause is a measurement; nothing here is
    // inferred from what the policy "should" do.
    let mut clauses = Vec::new();
    let reads = run.samples.len();
    let good = run
        .samples
        .iter()
        .filter(|s| s.status == 200 && s.md5_ok)
        .count();
    clauses.push(fill(
        i18n::t(lang, "chaos.d.reads"),
        &[
            ("{ok}", good.to_string()),
            ("{n}", reads.to_string()),
            ("{size}", fmt_bytes(run.size)),
        ],
    ));
    clauses.push(fill(
        i18n::t(lang, "chaos.d.margin"),
        &[
            ("{left}", o.copies_final.to_string()),
            ("{wanted}", run.wanted.to_string()),
            ("{unit}", unit.to_string()),
            ("{need}", need.to_string()),
        ],
    ));

    if o.repaired && !run.evidence.is_empty() {
        let e = &run.evidence[0];
        clauses.push(fill(
            i18n::t(lang, "chaos.d.attributed"),
            &[
                ("{who}", daemon_label(lang, &e.daemon)),
                ("{node}", e.node.clone()),
                ("{at}", clock(e.at)),
                ("{syncs}", e.suffix_syncs.to_string()),
                ("{reverts}", e.reverts.to_string()),
            ],
        ));
    } else if o.repaired {
        clauses.push(i18n::t(lang, "chaos.d.unattributed").to_string());
    } else {
        clauses.push(fill(
            i18n::t(lang, "chaos.d.silent"),
            &[
                ("{passes}", run.passes_after.len().to_string()),
                ("{nodes}", run.auditors.len().to_string()),
            ],
        ));
    }

    // Whether the partition's suffix was already flagged when the fault landed
    // decides whether a replicator pass can even see the damage, so it is
    // reported in both directions rather than only when nothing happened.
    if let Some(t) = &run.target {
        let key = format!("{}/{}", t.node, t.device);
        let sfx = suffix3(&run.hash);
        let marked = run
            .before
            .invalid
            .get(&key)
            .map(|v| v.split_whitespace().any(|x| x == sfx))
            .unwrap_or(false);
        clauses.push(fill(
            i18n::t(lang, if marked { "chaos.d.marked" } else { "chaos.d.nomark" }),
            &[
                ("{node}", t.node.clone()),
                ("{device}", t.device.clone()),
                ("{suffix}", sfx.to_string()),
            ],
        ));
    }

    if run.fault == Fault::CorruptCopy {
        clauses.push(i18n::t(lang, "chaos.d.censusblind").to_string());
        clauses.push(fill(
            i18n::t(lang, "chaos.d.digest"),
            &[
                (
                    "{before}",
                    if run.digest_before.is_empty() {
                        i18n::t(lang, "chaos.unknown").to_string()
                    } else {
                        run.digest_before.clone()
                    },
                ),
                (
                    "{after}",
                    if run.digest_after.is_empty() {
                        i18n::t(lang, "chaos.unknown").to_string()
                    } else {
                        run.digest_after.clone()
                    },
                ),
            ],
        ));
    }

    let auditor_off = !run.auditors.is_empty()
        && run
            .auditors
            .iter()
            .all(|(_, s)| s.starts_with("not-found") || s.contains("inactive"));
    if auditor_off && !o.repaired {
        clauses.push(fill(
            i18n::t(lang, "chaos.d.noauditor"),
            &[(
                "{state}",
                run.auditors
                    .first()
                    .map(|(_, s)| s.clone())
                    .unwrap_or_default(),
            )],
        ));
    }

    Verdict {
        level: if !o.readable {
            "bad"
        } else if o.repaired {
            "ok"
        } else {
            "warn"
        },
        headline,
        clauses,
    }
}

// ------------------------------------------------------------------ visuals

/// The timeline: one track per node showing whether that node held a current
/// copy at every poll, a client track showing what a reader got, a step line
/// for the copy count, and the daemon passes that did work.
fn timeline_mount(lang: &str, run: &Run) -> String {
    let Some(fault_at) = run.fault_at else {
        return String::new();
    };
    if run.samples.is_empty() {
        return String::new();
    }
    let mut lanes: Vec<String> = Vec::new();
    for c in [&run.before, &run.worst, &run.after] {
        for r in &c.rows {
            if !lanes.contains(&r.node) {
                lanes.push(r.node.clone());
            }
        }
    }
    for s in &run.samples {
        for n in &s.holders {
            if !lanes.contains(n) {
                lanes.push(n.clone());
            }
        }
    }
    if let Some(t) = &run.target {
        if !lanes.contains(&t.node) {
            lanes.push(t.node.clone());
        }
    }
    lanes.sort();

    let t0 = run.samples.iter().map(|s| s.off).min().unwrap_or(0).min(-8);
    let t1 = run
        .samples
        .iter()
        .map(|s| s.off)
        .max()
        .unwrap_or(60)
        .max(t0 + 40)
        + 6;
    let target_node = run.target.as_ref().map(|t| t.node.clone());
    let healed_at = run
        .converged_at
        .map(|c| c as i64 - fault_at as i64)
        .unwrap_or(i64::MAX);

    let mut segments: Vec<serde_json::Value> = Vec::new();
    for node in &lanes {
        let is_target = target_node.as_deref() == Some(node.as_str());
        let mut prev: Option<&Sample> = None;
        for p in &run.samples {
            if let Some(q) = prev {
                let cls = segment_cls(run, q, node, is_target, healed_at);
                segments.push(json!({"lane": node, "from": q.off, "to": p.off, "cls": cls}));
            }
            prev = Some(p);
        }
        if let Some(q) = prev {
            let cls = segment_cls(run, q, node, is_target, healed_at);
            segments.push(json!({"lane": node, "from": q.off, "to": t1, "cls": cls}));
        }
    }

    let lane_labels: Vec<serde_json::Value> = lanes
        .iter()
        .map(|node| {
            let label = match &run.target {
                Some(t) if t.node == *node => format!("{} · {}", node, t.device),
                _ => node.clone(),
            };
            json!({
                "id": node,
                "label": label,
                "target": target_node.as_deref() == Some(node.as_str()),
            })
        })
        .collect();

    let evidence: Vec<serde_json::Value> = run
        .evidence
        .iter()
        .map(|e| {
            json!({
                "node": e.node,
                "off": e.at as i64 - fault_at as i64,
                "tip": format!(
                    "{} {} suffix_syncs={} reverts={}",
                    clock(e.at),
                    e.daemon,
                    e.suffix_syncs,
                    e.reverts
                ),
            })
        })
        .collect();

    let mut rules = vec![json!({"off": 0i64, "cls": "fault", "label": i18n::t(lang, "chaos.mark.fault")})];
    if let Some(c) = run.converged_at {
        rules.push(json!({
            "off": c as i64 - fault_at as i64,
            "cls": "ok",
            "label": i18n::t(lang, "chaos.mark.converged"),
        }));
    }
    if let Some(u) = run.undone_at {
        let off = u as i64 - fault_at as i64;
        if off <= t1 {
            rules.push(json!({
                "off": off,
                "cls": "undo",
                "label": i18n::t(lang, "chaos.mark.undo"),
            }));
        }
    }

    let data = json!({
        "title": i18n::t(lang, "chaos.rep.timeline"),
        "variant": "chaos",
        "t0": t0,
        "t1": t1,
        "faultAt": fault_at,
        "faultClock": clock(fault_at),
        "wanted": run.wanted,
        "clientLabel": i18n::t(lang, "chaos.lane.client"),
        "copiesLabel": i18n::t(lang, "chaos.lane.copies"),
        "wantedLabel": i18n::t(lang, "chaos.lane.wanted"),
        "lanes": lane_labels,
        "samples": run.samples,
        "segments": segments,
        "evidence": evidence,
        "rules": rules,
    });
    ix_mount("timeline", &data)
}

fn segment_cls(run: &Run, q: &Sample, node: &str, is_target: bool, healed_at: i64) -> &'static str {
    if !q.holders.contains(&node.to_string()) {
        "miss"
    } else if is_target && run.fault == Fault::CorruptCopy && q.off >= 0 && q.off < healed_at {
        "rot"
    } else {
        "hold"
    }
}

/// Predicted convergence against measured convergence, on one scale. Two bars
/// answer "how far out was I" in a way a pair of numbers does not.
fn compare_bars(lang: &str, run: &Run) -> String {
    let Some(o) = &run.outcome else {
        return String::new();
    };
    let p = run.prediction.converge_secs;
    let a = o.converge_secs;
    let max = p.max(a.unwrap_or(run.deadline)).max(run.deadline).max(1) as f64;
    let row = |label: &str, v: Option<u64>, cls: &str, note: String| -> String {
        let pct = v.map(|x| x as f64 / max * 100.0).unwrap_or(100.0);
        format!(
            "<div class=\"ca-cmp-row\"><span class=\"ca-cmp-l\">{label}</span>\
             <span class=\"ca-cmp-t\"><i class=\"{cls}\" style=\"width:{pct:.1}%\"></i></span>\
             <span class=\"ca-cmp-v\">{note}</span></div>",
            label = esc(label),
            note = esc(&note)
        )
    };
    format!(
        "<div class=\"ca-cmp\">{}{}</div>",
        row(
            i18n::t(lang, "chaos.cmp.predicted"),
            Some(p),
            "pred",
            format!("~{p} s")
        ),
        row(
            i18n::t(lang, "chaos.cmp.actual"),
            a,
            if a.is_some() { "act" } else { "act none" },
            match a {
                Some(v) => format!("{v} s"),
                None => fill(
                    i18n::t(lang, "chaos.cmp.never"),
                    &[("{secs}", run.deadline.to_string())]
                ),
            }
        )
    )
}

// ------------------------------------------------------------------ tables

fn census_table(lang: &str, c: &Census) -> String {
    if c.rows.is_empty() {
        return format!(
            "<p class=\"note\">{}</p>",
            esc(i18n::t(lang, "chaos.empty.census"))
        );
    }
    let newest = newest_version(c);
    let mut rows = String::new();
    for r in &c.rows {
        let state: &'static str = if !r.file.ends_with(".data") {
            "chaos.st.other"
        } else if r.version != newest {
            "chaos.st.stale"
        } else if r.frag.is_some() && !r.durable {
            "chaos.st.nondurable"
        } else if r.role == "handoff" {
            "chaos.st.handoff"
        } else {
            "chaos.st.current"
        };
        rows.push_str(&format!(
            "<tr><td>{role}</td><td>{node}</td><td>{dev}</td><td class=\"ca-file\">{file}</td>\
             <td class=\"num\">{size}</td><td class=\"when\">{ver}</td><td>{frag}</td>\
             <td class=\"{cls}\">{st}</td></tr>",
            role = esc(i18n::t(
                lang,
                if r.role == "primary" {
                    "chaos.role.primary"
                } else {
                    "chaos.role.handoff"
                }
            )),
            node = esc(&r.node),
            dev = esc(&r.device),
            file = esc(&r.file),
            size = esc(&fmt_bytes(r.size)),
            ver = esc(&r.version),
            frag = r
                .frag
                .map(|i| format!("#{i}{}", if r.durable { " ·d" } else { "" }))
                .unwrap_or_else(|| "—".into()),
            cls = if state == "chaos.st.current" {
                "ca-ok"
            } else if state == "chaos.st.other" {
                ""
            } else {
                "ca-warn"
            },
            st = esc(i18n::t(lang, state)),
        ));
    }
    let extra = if c.unreachable.is_empty() {
        String::new()
    } else {
        format!(
            "<p class=\"note ca-warn\">{}</p>",
            esc(&fill(
                i18n::t(lang, "chaos.rep.unreachable"),
                &[("{nodes}", c.unreachable.join(", "))]
            ))
        )
    };
    format!(
        "<div class=\"tbl-wrap\"><table class=\"tbl\"><thead><tr>\
         <th>{role}</th><th>{node}</th><th>{dev}</th><th>{file}</th><th class=\"num\">{size}</th>\
         <th>{ver}</th><th>{frag}</th><th>{state}</th></tr></thead><tbody>{rows}</tbody></table>\
         </div>{extra}",
        role = esc(i18n::t(lang, "chaos.col.role")),
        node = esc(i18n::t(lang, "chaos.col.node")),
        dev = esc(i18n::t(lang, "chaos.col.device")),
        file = esc(i18n::t(lang, "chaos.col.file")),
        size = esc(i18n::t(lang, "chaos.col.size")),
        ver = esc(i18n::t(lang, "chaos.col.version")),
        frag = esc(i18n::t(lang, "chaos.col.frag")),
        state = esc(i18n::t(lang, "chaos.col.state")),
    )
}

/// Every pass at or after the fault, plus the last one each daemon logged
/// before it. Those baseline lines are what "the pass line that changed" is
/// measured against; forty rows of idle passes would bury it.
fn kept_passes(run: &Run) -> Vec<PassLine> {
    let mut all: Vec<PassLine> = run.passes_before.clone();
    merge_passes(&mut all, run.passes_after.clone());
    if all.is_empty() {
        return Vec::new();
    }
    let fault_at = run.fault_at.unwrap_or(run.started);
    let mut keep: Vec<PassLine> = all.iter().filter(|p| p.at >= fault_at).cloned().collect();
    let mut seen: Vec<(String, String)> = Vec::new();
    for p in all.iter().rev().filter(|p| p.at < fault_at) {
        let k = (p.node.clone(), p.daemon.clone());
        if !seen.contains(&k) {
            seen.push(k);
            keep.push(p.clone());
        }
    }
    keep.sort_by_key(|p| std::cmp::Reverse(p.at));
    keep
}

/// The daemon passes: one lane per node × daemon, a mark per pass on a shared clock.
fn pass_mount(lang: &str, run: &Run) -> String {
    let keep = kept_passes(run);
    if keep.is_empty() {
        return String::new();
    }
    let fault_at = run.fault_at.unwrap_or(run.started);
    let mut lanes: Vec<(String, String)> = Vec::new();
    for p in &keep {
        let k = (p.node.clone(), p.daemon.clone());
        if !lanes.contains(&k) {
            lanes.push(k);
        }
    }
    lanes.sort();
    let lane_json: Vec<serde_json::Value> = lanes
        .iter()
        .map(|(n, d)| {
            json!({
                "id": format!("{n}·{d}"),
                "node": n,
                "daemon": daemon_label(lang, d),
            })
        })
        .collect();
    let passes: Vec<serde_json::Value> = keep
        .iter()
        .map(|p| {
            let after = p.at >= fault_at;
            json!({
                "at": p.at,
                "lane": format!("{}·{}", p.node, p.daemon),
                "suffix_syncs": p.suffix_syncs,
                "reverts": p.reverts,
                "failures": p.failures,
                "after": after,
                "worked": p.worked() && after,
                "tip": format!(
                    "{} · {} · {} · suffix_syncs {} · reverts {} · failures {}",
                    clock(p.at),
                    p.node,
                    daemon_label(lang, &p.daemon),
                    p.suffix_syncs,
                    p.reverts,
                    p.failures,
                ),
            })
        })
        .collect();
    let data = json!({
        "title": i18n::t(lang, "chaos.rep.daemon"),
        "variant": "pass",
        "faultAt": fault_at,
        "faultLabel": i18n::t(lang, "chaos.mark.fault"),
        "lanes": lane_json,
        "passes": passes,
        "legend": {
            "size": i18n::t(lang, "chaos.pc.size"),
            "worked": i18n::t(lang, "chaos.pc.worked"),
            "fail": i18n::t(lang, "chaos.pc.fail"),
            "base": i18n::t(lang, "chaos.pc.base"),
        },
    });
    format!("<div class=\"ca-lane\">{}</div>", ix_mount("timeline", &data))
}

fn pass_table(lang: &str, run: &Run) -> String {
    let keep = kept_passes(run);
    if keep.is_empty() {
        return format!(
            "<p class=\"note\">{}</p>",
            esc(i18n::t(lang, "chaos.empty.pass"))
        );
    }
    let fault_at = run.fault_at.unwrap_or(run.started);
    let mut rows = String::new();
    for p in keep.iter() {
        let after = p.at >= fault_at;
        let worked = p.worked() && after;
        rows.push_str(&format!(
            "<tr class=\"{cls}\"><td class=\"when\">{at}</td><td>{node}</td><td>{daemon}</td>\
             <td class=\"num\">{syncs}</td><td class=\"num\">{reverts}</td>\
             <td class=\"num\">{fails}</td><td>{when}</td></tr>",
            cls = if worked { "ca-hit" } else { "" },
            at = esc(&clock(p.at)),
            node = esc(&p.node),
            daemon = esc(&daemon_label(lang, &p.daemon)),
            syncs = p.suffix_syncs,
            reverts = p.reverts,
            fails = p.failures,
            when = esc(i18n::t(
                lang,
                if after {
                    "chaos.pass.after"
                } else {
                    "chaos.pass.before"
                }
            )),
        ));
    }
    format!(
        "<div class=\"tbl-wrap\"><table class=\"tbl\"><thead><tr>\
         <th>{at}</th><th>{node}</th><th>{daemon}</th><th class=\"num\">suffix_syncs</th>\
         <th class=\"num\">reverts</th><th class=\"num\">failures</th><th>{when}</th>\
         </tr></thead><tbody>{rows}</tbody></table></div>",
        at = esc(i18n::t(lang, "chaos.col.at")),
        node = esc(i18n::t(lang, "chaos.col.node")),
        daemon = esc(i18n::t(lang, "chaos.col.daemon")),
        when = esc(i18n::t(lang, "chaos.col.window")),
    )
}

fn event_table(lang: &str, run: &Run) -> String {
    if run.marks.is_empty() {
        return String::new();
    }
    // The offset is recomputed here rather than trusted from the mark: the seed
    // is recorded before there is a fault to be relative to.
    let fault_at = run.fault_at.unwrap_or(run.started) as i64;
    let mut rows = String::new();
    for m in &run.marks {
        let off = m.at as i64 - fault_at;
        let what: &'static str = match m.kind {
            "seed" => "chaos.mark.seed",
            "fault" => "chaos.mark.fault",
            "gone" => "chaos.mark.gone",
            "back" => "chaos.mark.back",
            "read_ok" => "chaos.mark.read_ok",
            "read_bad" => "chaos.mark.read_bad",
            "converged" => "chaos.mark.converged",
            "undo" => "chaos.mark.undo",
            _ => "chaos.mark.other",
        };
        rows.push_str(&format!(
            "<tr><td class=\"when\">{at}</td><td class=\"num\">{off}</td><td>{lane}</td>\
             <td class=\"{cls}\">{what}</td><td>{detail}</td></tr>",
            at = esc(&clock(m.at)),
            off = if off > 0 {
                format!("+{off}")
            } else {
                off.to_string()
            },
            lane = esc(if m.lane.is_empty() {
                i18n::t(lang, "chaos.lane.client")
            } else {
                &m.lane
            }),
            cls = match m.kind {
                "fault" | "gone" | "read_bad" => "ca-bad",
                "back" | "converged" | "read_ok" => "ca-ok",
                _ => "",
            },
            what = esc(i18n::t(lang, what)),
            detail = esc(&m.detail),
        ));
    }
    format!(
        "<div class=\"tbl-wrap ca-events\"><table class=\"tbl\"><thead><tr>\
         <th>{at}</th><th class=\"num\">{off}</th><th>{lane}</th><th>{what}</th><th>{detail}</th>\
         </tr></thead><tbody>{rows}</tbody></table></div>",
        at = esc(i18n::t(lang, "chaos.col.at")),
        off = esc(i18n::t(lang, "chaos.col.off")),
        lane = esc(i18n::t(lang, "chaos.col.lane")),
        what = esc(i18n::t(lang, "chaos.col.what")),
        detail = esc(i18n::t(lang, "chaos.col.detail")),
    )
}

fn score_table(lang: &str, run: &Run) -> String {
    let Some(o) = &run.outcome else {
        return String::new();
    };
    let rows_s = score(&run.prediction, o);
    let (right, total) = tally(&rows_s);
    // The scorer speaks machine words so its unit tests can pin them; the report
    // shows them in the operator's language.
    let pretty = |v: &str| -> String {
        match v {
            "yes" => i18n::t(lang, "chaos.yes").to_string(),
            "no" => i18n::t(lang, "chaos.no").to_string(),
            "replicator" | "reconstructor" | "none" | "unattributed" => daemon_label(lang, v),
            "did not converge" => i18n::t(lang, "chaos.cmp.notconverged").to_string(),
            other => {
                if let Some(rest) = other.strip_prefix("yes ") {
                    format!("{} {rest}", i18n::t(lang, "chaos.yes"))
                } else if let Some(rest) = other.strip_prefix("no ") {
                    format!("{} {rest}", i18n::t(lang, "chaos.no"))
                } else {
                    other.to_string()
                }
            }
        }
    };
    let mut rows = String::new();
    for r in &rows_s {
        let what: &'static str = match r.what {
            "readable" => "chaos.what.readable",
            "repaired_by" => "chaos.what.repaired_by",
            _ => "chaos.what.converge",
        };
        rows.push_str(&format!(
            "<tr><td>{what}</td><td>{pred}</td><td>{act}</td><td class=\"{cls}\">{v}</td></tr>",
            what = esc(i18n::t(lang, what)),
            pred = esc(&pretty(&r.predicted)),
            act = esc(&pretty(&r.actual)),
            cls = if r.right { "ca-ok" } else { "ca-bad" },
            v = esc(i18n::t(
                lang,
                if r.right { "chaos.right" } else { "chaos.wrong" }
            )),
        ));
    }
    format!(
        "<div class=\"ca-scorehead\"><span class=\"ca-score\">{right}<span class=\"ca-score-s\"> / {total}</span></span>\
         <span class=\"ca-score-l\">{tally}</span></div>\
         <div class=\"tbl-wrap ca-narrow\"><table class=\"tbl\"><thead><tr>\
         <th>{q}</th><th>{p}</th><th>{a}</th><th>{v}</th></tr></thead><tbody>{rows}</tbody></table>\
         </div>{bars}",
        tally = esc(i18n::t(lang, "chaos.rep.tally")),
        q = esc(i18n::t(lang, "chaos.col.question")),
        p = esc(i18n::t(lang, "chaos.col.predicted")),
        a = esc(i18n::t(lang, "chaos.col.actual")),
        v = esc(i18n::t(lang, "chaos.col.verdict")),
        bars = compare_bars(lang, run),
    )
}

fn safety_panel(lang: &str, run: &Run) -> String {
    let mut rows = String::new();
    for d in &run.drill {
        let what = match d.what.as_str() {
            "chaos.drill.conf" => i18n::t(lang, "chaos.drill.conf").to_string(),
            "chaos.drill.traversal" => i18n::t(lang, "chaos.drill.traversal").to_string(),
            "chaos.drill.outside" => i18n::t(lang, "chaos.drill.outside").to_string(),
            other => fill(
                i18n::t(lang, "chaos.drill.object"),
                &[("{obj}", other.to_string())],
            ),
        };
        rows.push_str(&format!(
            "<tr><td>{what}</td><td class=\"ca-file\">{path}</td>\
             <td class=\"{cls}\">{outcome}</td><td class=\"ca-reason\">{reason}</td></tr>",
            what = esc(&what),
            path = esc(if d.path.is_empty() { "—" } else { &d.path }),
            cls = if d.refused { "ca-ok" } else { "ca-bad" },
            outcome = esc(i18n::t(
                lang,
                if d.refused {
                    "chaos.drill.refused"
                } else {
                    "chaos.drill.allowed"
                }
            )),
            reason = esc(&d.reason),
        ));
    }
    let drill = if rows.is_empty() {
        format!(
            "<p class=\"note\">{}</p>",
            esc(i18n::t(lang, "chaos.empty.drill"))
        )
    } else {
        format!(
            "<div class=\"tbl-wrap\"><table class=\"tbl\"><thead><tr><th>{a}</th><th>{b}</th>\
             <th>{c}</th><th>{d}</th></tr></thead><tbody>{rows}</tbody></table></div>",
            a = esc(i18n::t(lang, "chaos.col.attempt")),
            b = esc(i18n::t(lang, "chaos.col.path")),
            c = esc(i18n::t(lang, "chaos.col.guard")),
            d = esc(i18n::t(lang, "chaos.col.reason")),
        )
    };
    let undo = if run.undo_script.is_empty() {
        String::new()
    } else {
        format!(
            "<dl class=\"kv ca-kv\">\
             <div><dt>{lbl_n}</dt><dd>{node}</dd></div>\
             <div><dt>{lbl_t}</dt><dd>{ttl} s</dd></div>\
             <div><dt>{lbl_s}</dt><dd class=\"ca-file\">{script}</dd></div>\
             <div><dt>{lbl_d}</dt><dd class=\"{ucls}\">{done}</dd></div></dl>",
            lbl_n = esc(i18n::t(lang, "chaos.undo.node")),
            node = esc(run.target.as_ref().map(|t| t.node.as_str()).unwrap_or("—")),
            lbl_t = esc(i18n::t(lang, "chaos.undo.ttl")),
            ttl = FAULT_TTL_SECS,
            lbl_s = esc(i18n::t(lang, "chaos.undo.script")),
            script = esc(&run.undo_script),
            lbl_d = esc(i18n::t(lang, "chaos.undo.state")),
            ucls = if run.undo_ok { "ca-ok" } else { "ca-bad" },
            done = esc(i18n::t(
                lang,
                if run.undo_ok {
                    "chaos.undo.done"
                } else {
                    "chaos.undo.pending"
                }
            )),
        )
    };
    format!(
        "<h3 class=\"ca-h\">{h}</h3><p class=\"note ca-wide\">{why}</p>{drill}{undo}",
        h = esc(i18n::t(lang, "chaos.rep.safety")),
        why = esc(i18n::t(lang, "chaos.note.labroot")),
    )
}

fn auditor_panel(lang: &str, run: &Run) -> String {
    if run.auditors.is_empty() {
        return String::new();
    }
    let mut items = String::new();
    for (node, st) in &run.auditors {
        let missing = st.starts_with("not-found") || st.is_empty();
        items.push_str(&format!(
            "<li><b>{node}</b> <span class=\"{cls}\">{st}</span></li>",
            node = esc(node),
            cls = if missing { "ca-warn" } else { "ca-ok" },
            st = esc(if st.is_empty() {
                i18n::t(lang, "chaos.unknown")
            } else {
                st
            }),
        ));
    }
    format!(
        "<h3 class=\"ca-h\">{h}</h3><p class=\"note ca-wide\">{p}</p><ul class=\"ca-list\">{items}</ul>",
        h = esc(i18n::t(lang, "chaos.rep.auditor")),
        p = esc(i18n::t(lang, "chaos.rep.auditorwhy")),
    )
}

// ------------------------------------------------------------------ the page

fn armed(state: &Arc<AppState>) -> bool {
    state.cfg.lab_mutations && !state.cfg.lab_root.is_empty()
}

fn opt(value: &str, label: &str, sel: bool) -> String {
    format!(
        "<option value=\"{v}\"{s}>{l}</option>",
        v = esc(value),
        s = if sel { " selected" } else { "" },
        l = esc(label)
    )
}

async fn form_content(state: &Arc<AppState>, lang: &str, last: Option<&Run>) -> String {
    let is_armed = armed(state);
    let policies = ringlab::policies(state).await.unwrap_or_default();
    let prev = last.filter(|r| !r.drill_only);
    let sel_fault = prev.map(|r| r.fault).unwrap_or(Fault::DropCopy);
    let sel_pol = prev.map(|r| r.policy_index).unwrap_or_else(|| {
        policies
            .iter()
            .find(|p| p.is_ec())
            .map(|p| p.index)
            .unwrap_or(0)
    });

    let mut faults = String::new();
    for f in Fault::all() {
        faults.push_str(&opt(
            f.id(),
            &format!(
                "{} — {}",
                i18n::t(lang, f.name_key()),
                i18n::t(lang, f.question_key())
            ),
            *f == sel_fault,
        ));
    }
    let mut pols = String::new();
    for p in &policies {
        let label = match (p.ec_ndata, p.ec_nparity) {
            (Some(k), Some(m)) => format!("{} · EC {k}+{m}", p.name),
            _ => format!("{} · {}", p.name, i18n::t(lang, "chaos.pol.replicated")),
        };
        pols.push_str(&opt(&p.index.to_string(), &label, p.index == sel_pol));
    }
    let mut whos = String::new();
    for w in ["reconstructor", "replicator", "none"] {
        whos.push_str(&opt(
            w,
            &daemon_label(lang, w),
            prev.map(|r| r.prediction.repaired_by == w)
                .unwrap_or(w == "reconstructor"),
        ));
    }
    let mut yesno = String::new();
    for (v, k) in [("true", "chaos.yes"), ("false", "chaos.no")] {
        yesno.push_str(&opt(
            v,
            i18n::t(lang, k),
            prev.map(|r| r.prediction.readable == (v == "true"))
                .unwrap_or(v == "true"),
        ));
    }
    let mut dls = String::new();
    for d in [90u64, 150, 300] {
        dls.push_str(&opt(
            &d.to_string(),
            &fill(i18n::t(lang, "chaos.form.secs_n"), &[("{n}", d.to_string())]),
            prev.map(|r| r.deadline == d).unwrap_or(d == DEADLINE_DEFAULT),
        ));
    }
    let secs = prev.map(|r| r.prediction.converge_secs).unwrap_or(60);

    let disabled = if is_armed { "" } else { " disabled" };
    let banner = if is_armed {
        format!(
            "<p class=\"note ca-armed\">{}</p>",
            esc(&fill(
                i18n::t(lang, "chaos.armed"),
                &[
                    ("{root}", state.cfg.lab_root.clone()),
                    ("{ttl}", FAULT_TTL_SECS.to_string()),
                ]
            ))
        )
    } else {
        format!(
            "<p class=\"err on\">{}</p>",
            esc(i18n::t(lang, "chaos.disarmed"))
        )
    };
    let busy = if in_flight().is_some() {
        format!(
            "<p class=\"note ca-warn\">{}</p>",
            esc(i18n::t(lang, "chaos.busy"))
        )
    } else {
        String::new()
    };

    format!(
        r#"{banner}{busy}
<form class="page-sec ca-form" method="post" action="/lab/api/chaos/run">
  <h3>{h}</h3>
  <p class="note ca-wide">{intro}</p>
  <div class="sx-grid">
    <label class="fld"><span>{l_fault}</span><select name="fault"{disabled}>{faults}</select></label>
    <label class="fld"><span>{l_pol}</span><select name="policy"{disabled}>{pols}</select></label>
  </div>
  <div class="ca-pred">
    <div class="ca-pred-h">{predh}</div>
    <div class="sx-grid">
      <label class="fld"><span>{l_read}</span><select name="readable"{disabled}>{yesno}</select></label>
      <label class="fld"><span>{l_by}</span><select name="repaired_by"{disabled}>{whos}</select></label>
      <label class="fld"><span>{l_secs}</span><input type="number" name="converge_secs" min="1" max="3600" value="{secs}"{disabled}></label>
      <label class="fld"><span>{l_dl}</span><select name="deadline"{disabled}>{dls}</select></label>
    </div>
  </div>
  <div class="sx-actions ca-actions">
    <button class="btn-primary" type="submit"{disabled}>{go}</button>
    <button class="btn" type="submit" name="drill" value="1">{drill}</button>
  </div>
</form>"#,
        h = esc(i18n::t(lang, "chaos.form.h")),
        intro = esc(i18n::t(lang, "chaos.form.intro")),
        predh = esc(i18n::t(lang, "chaos.form.predh")),
        l_fault = esc(i18n::t(lang, "chaos.form.fault")),
        l_pol = esc(i18n::t(lang, "chaos.form.policy")),
        l_read = esc(i18n::t(lang, "chaos.form.readable")),
        l_by = esc(i18n::t(lang, "chaos.form.by")),
        l_secs = esc(i18n::t(lang, "chaos.form.secs")),
        l_dl = esc(i18n::t(lang, "chaos.form.deadline")),
        go = esc(i18n::t(lang, "chaos.form.submit")),
        drill = esc(i18n::t(lang, "chaos.form.drillonly")),
    )
}

/// What the page says before anything has been run. Not "no data": a sentence
/// naming the control that would produce data, and what the report will hold
/// once it does.
fn empty_state(lang: &str) -> String {
    let mut qs = String::new();
    for f in Fault::all() {
        qs.push_str(&format!(
            "<li><b>{n}</b><span>{q}</span></li>",
            n = esc(i18n::t(lang, f.name_key())),
            q = esc(i18n::t(lang, f.question_key())),
        ));
    }
    format!(
        "<div class=\"page-sec ca-empty\"><h3>{h}</h3><p class=\"note ca-wide\">{p}</p>\
         <ul class=\"ca-qs\">{qs}</ul></div>",
        h = esc(i18n::t(lang, "chaos.empty.h")),
        p = esc(i18n::t(lang, "chaos.empty.p")),
    )
}

fn scoreboard(lang: &str, runs: &[Run]) -> String {
    let scored: Vec<&Run> = runs
        .iter()
        .filter(|r| r.outcome.is_some() && !r.drill_only)
        .collect();
    if scored.len() < 2 {
        return String::new();
    }
    let mut rows = String::new();
    let (mut hit, mut tot) = (0usize, 0usize);
    for r in &scored {
        let o = r.outcome.as_ref().unwrap();
        let s = score(&r.prediction, o);
        let (a, b) = tally(&s);
        hit += a;
        tot += b;
        rows.push_str(&format!(
            "<tr><td class=\"when\">{at}</td><td>{fault}</td><td>{pol}</td>\
             <td class=\"num\">{a} / {b}</td><td>{conv}</td></tr>",
            at = esc(&clock(r.started)),
            fault = esc(i18n::t(lang, r.fault.name_key())),
            pol = esc(&r.policy_name),
            conv = esc(&match o.converge_secs {
                Some(v) => format!("{v} s"),
                None => i18n::t(lang, "chaos.cmp.notconverged").to_string(),
            }),
        ));
    }
    format!(
        "<h3 class=\"ca-h\">{h}</h3><p class=\"note ca-wide\">{p}</p>\
         <div class=\"tbl-wrap ca-narrow\"><table class=\"tbl\"><thead><tr>\
         <th>{c1}</th><th>{c2}</th><th>{c3}</th><th class=\"num\">{c4}</th><th>{c5}</th>\
         </tr></thead><tbody>{rows}</tbody></table></div>",
        h = esc(i18n::t(lang, "chaos.rep.board")),
        p = esc(&fill(
            i18n::t(lang, "chaos.rep.boardp"),
            &[("{n}", hit.to_string()), ("{m}", tot.to_string())]
        )),
        c1 = esc(i18n::t(lang, "chaos.col.at")),
        c2 = esc(i18n::t(lang, "chaos.form.fault")),
        c3 = esc(i18n::t(lang, "chaos.form.policy")),
        c4 = esc(i18n::t(lang, "chaos.col.rightof")),
        c5 = esc(i18n::t(lang, "chaos.what.converge")),
    )
}

fn report(lang: &str, run: &Run) -> String {
    let v = verdict(lang, run);
    let mut clauses = String::new();
    for c in &v.clauses {
        clauses.push_str(&format!("<li>{}</li>", esc(c)));
    }
    let sub = if run.drill_only {
        fill(
            i18n::t(lang, "chaos.rep.subdrill"),
            &[("{arena}", run.container.clone())],
        )
    } else {
        fill(
            i18n::t(lang, "chaos.rep.sub"),
            &[
                ("{fault}", i18n::t(lang, run.fault.name_key()).to_string()),
                ("{policy}", run.policy_name.clone()),
                ("{obj}", format!("{}/{}", run.container, run.object)),
                ("{part}", run.partition.to_string()),
                ("{hash}", run.hash.clone()),
            ],
        )
    };
    let meta = fill(
        i18n::t(lang, "chaos.rep.meta"),
        &[
            ("{start}", iso(run.started)),
            ("{end}", run.finished.map(iso).unwrap_or_else(|| "—".into())),
            ("{id}", run.id.clone()),
        ],
    );
    let live = if run.is_live() {
        format!(
            "<p class=\"note ca-live\">{txt} <a class=\"plain-link\" href=\"/lab/chaos\">{r}</a>\
             <noscript> {ns}</noscript></p>",
            txt = esc(&fill(
                i18n::t(lang, "chaos.live"),
                &[("{step}", run.step.clone())]
            )),
            r = esc(i18n::t(lang, "common.refresh")),
            ns = esc(i18n::t(lang, "chaos.live.noscript")),
        )
    } else {
        String::new()
    };

    let mut body = format!(
        "<div class=\"ca-head\">\
         <div class=\"ca-verdict {level}\">{headline}</div>\
         <div class=\"ca-sub\">{sub}</div>\
         <div class=\"ca-meta\">{meta}</div></div>{live}\
         <ul class=\"ca-clauses\">{clauses}</ul>",
        level = v.level,
        headline = esc(&v.headline),
        sub = esc(&sub),
        meta = esc(&meta),
    );

    if run.drill_only {
        body.push_str(&safety_panel(lang, run));
        return body;
    }

    body.push_str(&format!(
        "<h3 class=\"ca-h\">{}</h3>{}",
        esc(i18n::t(lang, "chaos.rep.score")),
        score_table(lang, run)
    ));

    let tl = timeline_mount(lang, run);
    if !tl.is_empty() {
        body.push_str(&format!(
            "<h3 class=\"ca-h\">{}</h3><p class=\"note ca-wide\">{}</p>\
             <div class=\"ca-lane\">{}</div>",
            esc(i18n::t(lang, "chaos.rep.timeline")),
            esc(i18n::t(lang, "chaos.rep.timelinep")),
            tl
        ));
    }
    body.push_str(&event_table(lang, run));

    body.push_str(&format!(
        "<h3 class=\"ca-h\">{h}</h3><p class=\"note ca-wide\">{p}</p>\
         <h4 class=\"ca-h4\">{b}</h4>{tb}<h4 class=\"ca-h4\">{w}</h4>{tw}<h4 class=\"ca-h4\">{a}</h4>{ta}",
        h = esc(i18n::t(lang, "chaos.rep.census")),
        p = esc(&fill(
            i18n::t(lang, "chaos.rep.censusp"),
            &[(
                "{dir}",
                format!("…/{}/{}/{}", run.data_dir, run.partition, run.hash)
            )]
        )),
        b = esc(i18n::t(lang, "chaos.rep.before")),
        tb = census_table(lang, &run.before),
        w = esc(&fill(
            i18n::t(lang, "chaos.rep.worst"),
            &[("{off}", run.worst.off.to_string())]
        )),
        tw = census_table(lang, &run.worst),
        a = esc(i18n::t(lang, "chaos.rep.after")),
        ta = census_table(lang, &run.after),
    ));

    body.push_str(&format!(
        "<h3 class=\"ca-h\">{h}</h3><p class=\"note ca-wide\">{p}</p>{chart}\
         <details class=\"rs-det\"><summary>{det}</summary>{t}</details>",
        h = esc(i18n::t(lang, "chaos.rep.daemon")),
        p = esc(i18n::t(lang, "chaos.rep.daemonp")),
        chart = pass_mount(lang, run),
        det = esc(i18n::t(lang, "chaos.pc.table")),
        t = pass_table(lang, run),
    ));
    body.push_str(&auditor_panel(lang, run));
    body.push_str(&safety_panel(lang, run));
    body
}

/// The arcade page. Server-rendered so the fault catalogue, the safety state
/// and the whole last report are readable with no JavaScript at all.
pub async fn page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (_, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let runs = history();
    let last = runs.first();
    let live = last.map(|r| r.is_live()).unwrap_or(false);

    let inner = format!(
        r#"{form}
{report}
{board}
<form class="ca-recover" method="post" action="/lab/api/chaos/recover">
  <button class="btn" type="submit">{rec}</button>
  <span class="hint">{rech}</span>
</form>"#,
        form = form_content(&state, lang, last).await,
        report = match last {
            Some(r) => report(lang, r),
            None => empty_state(lang),
        },
        board = scoreboard(lang, &runs),
        rec = esc(i18n::t(lang, "chaos.recover")),
        rech = esc(i18n::t(lang, "chaos.recoverh")),
    );
    let body = format!(
        "<div class=\"pagehead\"><h1>{title}</h1></div>\
         <p class=\"statline\">{blurb}</p>\
         <div class=\"ca-page\"{liveattr}>{inner}</div>",
        title = esc(i18n::t(lang, "lab.tool.chaos.title")),
        blurb = esc(i18n::t(lang, "lab.tool.chaos.blurb")),
        liveattr = if live { " data-chaos-live=\"1\"" } else { "" },
    );
    crate::pages::lab_tool_shell(&state, &headers, &sess, "chaos", body)
}

// ------------------------------------------------------------------ http

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

#[derive(Deserialize)]
pub struct RunReq {
    pub fault: String,
    pub prediction: Prediction,
    /// Which policy to run the experiment in: 0 replication, 1 EC.
    #[serde(default)]
    pub policy: u32,
    #[serde(default)]
    pub deadline: u64,
    /// Prove the guard and touch nothing.
    #[serde(default)]
    pub drill: bool,
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hx = |c: u8| (c as char).to_digit(16);
                match (hx(b[i + 1]), hx(b[i + 2])) {
                    (Some(a), Some(c)) => {
                        out.push((a * 16 + c) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(b[i]);
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The form posts urlencoded and the JSON API posts JSON. Both are accepted,
/// because a control that only works with scripting on would quietly break the
/// promise that this page is usable with JavaScript switched off.
pub fn parse_run_req(content_type: &str, body: &str) -> Result<RunReq, String> {
    if content_type.contains("json") || body.trim_start().starts_with('{') {
        return serde_json::from_str(body).map_err(|e| format!("bad request body: {e}"));
    }
    let mut m: BTreeMap<String, String> = BTreeMap::new();
    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        m.insert(pct_decode(k), pct_decode(v));
    }
    let get = |k: &str| m.get(k).cloned().unwrap_or_default();
    Ok(RunReq {
        fault: get("fault"),
        prediction: Prediction {
            readable: get("readable") != "false",
            repaired_by: {
                let v = get("repaired_by");
                if v.is_empty() {
                    "none".into()
                } else {
                    v
                }
            },
            converge_secs: get("converge_secs").parse().unwrap_or(60),
        },
        policy: get("policy").parse().unwrap_or(0),
        deadline: get("deadline").parse().unwrap_or(DEADLINE_DEFAULT),
        drill: matches!(get("drill").as_str(), "1" | "true" | "on"),
    })
}

fn new_run(id: String, fault: Fault, req: &RunReq, deadline: u64) -> Run {
    Run {
        id,
        started: now(),
        finished: None,
        phase: Phase::Seeding,
        step: "starting".into(),
        error: String::new(),
        fault,
        prediction: req.prediction.clone(),
        deadline,
        drill_only: req.drill,
        policy_index: req.policy,
        policy_name: String::new(),
        policy_ec: None,
        data_dir: String::new(),
        container: arena_container(req.policy),
        object: ARENA_OBJECT.into(),
        md5: String::new(),
        size: 0,
        partition: 0,
        hash: String::new(),
        wanted: 0,
        target: None,
        digest_before: String::new(),
        digest_after: String::new(),
        fault_at: None,
        converged_at: None,
        undone_at: None,
        before: Census::default(),
        worst: Census::default(),
        after: Census::default(),
        samples: Vec::new(),
        marks: Vec::new(),
        passes_before: Vec::new(),
        passes_after: Vec::new(),
        evidence: Vec::new(),
        auditors: Vec::new(),
        drill: Vec::new(),
        journal_id: None,
        undo_script: String::new(),
        undo_ok: false,
        outcome: None,
    }
}

/// Start an experiment. Returns immediately: a fault worth watching outlives
/// any request timeout, and a report that exists only inside one HTTP response
/// is a report nobody can reload.
pub async fn run(State(state): State<Arc<AppState>>, headers: HeaderMap, body: String) -> Response {
    let (sid, _) = match lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let req = match parse_run_req(&ct, &body) {
        Ok(r) => r,
        Err(e) => {
            return if wants_html {
                Redirect::to("/lab/chaos").into_response()
            } else {
                err(StatusCode::BAD_REQUEST, &e)
            }
        }
    };
    // A drill writes nothing, so it is allowed on an unarmed console: proving
    // the guard before switching the write path on is the right order.
    if !req.drill && !armed(&state) {
        return if wants_html {
            Redirect::to("/lab/chaos").into_response()
        } else {
            err(StatusCode::CONFLICT, i18n::t(lang, "chaos.disarmed"))
        };
    }
    let Some(fault) = Fault::parse(&req.fault) else {
        return if wants_html {
            Redirect::to("/lab/chaos").into_response()
        } else {
            err(
                StatusCode::BAD_REQUEST,
                &format!("{} is not a fault this tool knows", req.fault),
            )
        };
    };
    if let Some(id) = in_flight() {
        return if wants_html {
            Redirect::to("/lab/chaos").into_response()
        } else {
            err(
                StatusCode::CONFLICT,
                &format!("experiment {id} is still running"),
            )
        };
    }

    let deadline = req.deadline.clamp(DEADLINE_MIN, DEADLINE_MAX);
    let id = crate::util::rand_hex(6);
    push_run(new_run(id.clone(), fault, &req, deadline));
    let st = state.clone();
    let rid = id.clone();
    tokio::spawn(async move {
        experiment(st, sid, rid).await;
    });

    if wants_html {
        Redirect::to("/lab/chaos").into_response()
    } else {
        Json(json!({ "run": id, "deadline": deadline })).into_response()
    }
}

/// Where the current experiment is, for a page that wants to follow along
/// without reloading. Deliberately thin: the report is server-rendered, so all
/// a poller needs to know is whether to fetch it again.
pub async fn status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    match latest() {
        None => Json(json!({ "phase": "idle", "live": false })).into_response(),
        Some(r) => Json(json!({
            "run": r.id,
            "phase": r.phase,
            "step": r.step,
            "live": r.is_live(),
            "elapsed": now().saturating_sub(r.started),
            "samples": r.samples.len(),
            "copies": r.samples.last().map(|s| s.copies).unwrap_or(r.after.current),
            "wanted": r.wanted,
        }))
        .into_response(),
    }
}

/// Catalogue for the form: which faults exist and what each asks.
pub async fn catalogue(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let lang = i18n::lang(&headers);
    let is_armed = armed(&state);
    let policies = ringlab::policies(&state).await.unwrap_or_default();
    Json(json!({
        "armed": is_armed,
        "arena": ARENA,
        "ttl_secs": FAULT_TTL_SECS,
        "deadline_default": DEADLINE_DEFAULT,
        "why_disarmed": if is_armed { serde_json::Value::Null }
            else { json!(i18n::t(lang, "chaos.disarmed")) },
        "policies": policies.iter().map(|p| json!({
            "index": p.index, "name": p.name, "kind": p.kind,
            "container": arena_container(p.index),
        })).collect::<Vec<_>>(),
        "faults": Fault::all().iter().map(|f| json!({
            "id": f.id(),
            "name": i18n::t(lang, f.name_key()),
            "question": i18n::t(lang, f.question_key()),
            "ec_only": f.ec_only(),
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// Undo every fault this tool still has outstanding. The sweeper does this on a
/// TTL, but an operator who wants the cluster clean *now* should not have to
/// wait for it.
pub async fn recover(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);
    let pending: Vec<String> = {
        let j = state.journal.lock().unwrap();
        j.iter()
            .filter(|e| !e.undone && e.reason.starts_with("chaos:"))
            .map(|e| e.id.clone())
            .collect()
    };
    let mut undone = 0usize;
    let mut failed: Vec<String> = Vec::new();
    for id in &pending {
        match nodes::undo(&state, id).await {
            Ok(()) => undone += 1,
            Err(e) => failed.push(format!("{id}: {e}")),
        }
    }
    if failed.is_empty() {
        let at = now();
        let mut s = store().lock().unwrap();
        for r in s.iter_mut() {
            if r.journal_id.is_some() && !r.undo_ok {
                r.undo_ok = true;
                r.undone_at = Some(at);
            }
        }
    }
    if wants_html {
        return Redirect::to("/lab/chaos").into_response();
    }
    Json(json!({ "undone": undone, "failed": failed })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pred(readable: bool, by: &str, secs: u64) -> Prediction {
        Prediction {
            readable,
            repaired_by: by.into(),
            converge_secs: secs,
        }
    }

    fn out(readable: bool, by: &str, secs: Option<u64>) -> Outcome {
        Outcome {
            readable,
            read_status: if readable { 200 } else { 503 },
            etag_matched: Some(readable),
            repaired: secs.is_some(),
            repaired_by: by.into(),
            converge_secs: secs,
            copies_before: 3,
            copies_after_fault: 2,
            copies_final: if secs.is_some() { 3 } else { 2 },
        }
    }

    #[test]
    fn a_correct_prediction_scores_three_of_three() {
        let rows = score(
            &pred(true, "reconstructor", 60),
            &out(true, "reconstructor", Some(62)),
        );
        assert_eq!(tally(&rows), (3, 3), "{rows:?}");
    }

    #[test]
    fn convergence_is_scored_with_tolerance_not_equality() {
        // "about a minute" against 62 s is the same answer; scoring it wrong
        // would punish correct intuition.
        let rows = score(
            &pred(true, "reconstructor", 60),
            &out(true, "reconstructor", Some(62)),
        );
        assert!(rows[2].right);
        // An order of magnitude out is genuinely wrong.
        let rows = score(
            &pred(true, "reconstructor", 5),
            &out(true, "reconstructor", Some(600)),
        );
        assert!(!rows[2].right);
    }

    #[test]
    fn never_converging_is_always_wrong_however_it_was_predicted() {
        let rows = score(
            &pred(true, "reconstructor", 60),
            &out(true, "reconstructor", None),
        );
        assert!(!rows[2].right);
        assert_eq!(rows[2].actual, "did not converge");
    }

    #[test]
    fn a_wrong_readability_call_is_caught() {
        let rows = score(
            &pred(false, "reconstructor", 60),
            &out(true, "reconstructor", Some(60)),
        );
        assert!(!rows[0].right);
        assert_eq!(tally(&rows).0, 2);
    }

    // ---- the guard ----

    const ROOT: &str = "/srv/node";
    const H: &str = "6cf7fe7daf537b4c310241943375f509";

    #[test]
    fn a_file_belonging_to_the_arena_object_is_allowed() {
        let p = format!("{ROOT}/d1/objects-1/435/509/{H}/1785077136.55756#0#d.data");
        assert!(check_target(&p, H, ROOT).is_ok());
    }

    #[test]
    fn another_objects_copy_is_refused_even_under_the_right_root() {
        // The whole cluster lives under this root, which is exactly why the
        // prefix cannot be the guard.
        let other = "aaaabbbbccccddddeeeeffff00001111";
        let p = format!("{ROOT}/d1/objects/191/111/{other}/1785077092.42302.data");
        let e = check_target(&p, H, ROOT).unwrap_err();
        assert!(e.contains("does not belong"), "{e}");
    }

    #[test]
    fn paths_outside_the_root_and_traversals_are_refused() {
        assert!(check_target("/etc/swift/swift.conf", H, ROOT).is_err());
        let p = format!("{ROOT}/d1/../../etc/passwd/{H}/x.data");
        assert!(check_target(&p, H, ROOT).is_err());
    }

    #[test]
    fn a_lock_or_directory_is_not_an_object_file() {
        let p = format!("{ROOT}/d1/objects/435/509/{H}/.lock");
        assert!(check_target(&p, H, ROOT).is_err());
        let p = format!("{ROOT}/d1/objects/435/509/{H}");
        assert!(check_target(&p, H, ROOT).is_err());
    }

    #[test]
    fn an_unset_root_refuses_everything() {
        let p = format!("/srv/node/d1/objects/435/509/{H}/x.data");
        assert!(check_target(&p, H, "").is_err());
    }

    #[test]
    fn every_fault_round_trips_its_id_and_has_a_question() {
        for f in Fault::all() {
            assert_eq!(Fault::parse(f.id()), Some(*f));
            assert!(!f.question_key().is_empty());
            assert!(!f.name_key().is_empty());
        }
        assert_eq!(Fault::parse("rm -rf"), None);
    }

    // ---- the fault scripts ----

    /// Every absolute path in an apply or undo script has to be a bare token
    /// under the lab root, because that is the literal text `nodes::mutate`
    /// checks. A path tucked inside a shell variable would pass the guard while
    /// pointing anywhere, so this is the test that keeps the sandbox real.
    #[test]
    fn every_absolute_path_in_a_script_is_a_bare_token_under_the_root() {
        let dir = format!("{ROOT}/d2/objects-1/453/dcd/{H}");
        for f in Fault::all() {
            let file = if f.ec_only() || *f == Fault::StaleTimestamp {
                "1785322220.82633#2#d.data"
            } else {
                "1785322220.59831.data"
            };
            let s = build_scripts(*f, ROOT, "d2", &dir, file, "abc123").unwrap();
            for script in [&s.apply, &s.undo] {
                let mut saw_root = false;
                for tok in script.split_whitespace() {
                    if tok.starts_with('/') {
                        assert!(
                            tok.starts_with(ROOT),
                            "{} leaks {tok} outside {ROOT}",
                            f.id()
                        );
                        saw_root = true;
                    }
                }
                assert!(saw_root, "{} has no guarded path at all", f.id());
            }
        }
    }

    #[test]
    fn dropping_a_copy_parks_it_and_the_undo_puts_it_back() {
        let dir = format!("{ROOT}/d2/objects/923/e47/{H}");
        let s = build_scripts(
            Fault::DropCopy,
            ROOT,
            "d2",
            &dir,
            "1785322220.59831.data",
            "run7",
        )
        .unwrap();
        // Parked outside every objects tree, so no daemon can tidy it away.
        assert!(s.apply.contains("/srv/node/d2/chaos-park/run7"));
        assert!(!s.apply.contains("chaos-park/run7/objects"));
        // And the sandbox directory itself is swept, so a finished experiment
        // leaves nothing at all behind — not even an empty directory.
        assert!(s.undo.contains("rmdir /srv/node/d2/chaos-park/run7"));
        assert!(s.undo.contains("rmdir /srv/node/d2/chaos-park "));
        // The undo has to cope with the copy already being back: overwriting a
        // freshly rebuilt file with a stale parked one would be a second fault.
        assert!(s.undo.contains("if [ -e"));
        assert!(s.undo.contains("rm -f"));
        assert!(s.undo.trim_end().ends_with("exit 0"));
    }

    #[test]
    fn stripping_durability_only_renames_and_only_applies_to_a_fragment() {
        let dir = format!("{ROOT}/d3/objects-1/453/dcd/{H}");
        let s = build_scripts(
            Fault::DropDurable,
            ROOT,
            "d3",
            &dir,
            "1785322220.82633#2#d.data",
            "r",
        )
        .unwrap();
        assert!(s.apply.contains("1785322220.82633#2.data"), "{}", s.apply);
        assert!(s.apply.starts_with("mv -f"));
        // A replicated copy has no marker, so the fault must refuse rather than
        // silently do nothing.
        let e = build_scripts(
            Fault::DropDurable,
            ROOT,
            "d3",
            &dir,
            "1785322220.59831.data",
            "r",
        )
        .unwrap_err();
        assert!(e.contains("durability marker"), "{e}");
    }

    #[test]
    fn a_stale_timestamp_moves_a_whole_day_back_and_keeps_the_fraction() {
        let dir = format!("{ROOT}/d1/objects/923/e47/{H}");
        let s = build_scripts(
            Fault::StaleTimestamp,
            ROOT,
            "d1",
            &dir,
            "1785322220.59831.data",
            "r",
        )
        .unwrap();
        assert!(s.apply.contains("1785235820.59831.data"), "{}", s.apply);
    }

    // ---- reading the cluster back ----

    #[test]
    fn a_pass_line_is_parsed_into_the_counters_attribution_uses() {
        let l = "1785322617.112286 swift1 object-replicator[957393]: INFO object-replicator \
                 pass: partitions=344 suffix_syncs=2 reverts=1 failures=0";
        let p = parse_pass("swift1", l).unwrap();
        assert_eq!(p.daemon, "replicator");
        assert_eq!(p.at, 1785322617);
        assert_eq!((p.suffix_syncs, p.reverts, p.failures), (2, 1, 0));
        assert!(p.worked());

        // The reconstructor line carries no partitions= field at all.
        let l = "1785322628.521687 swift1 object-reconstructor[833032]: INFO \
                 object-reconstructor pass: suffix_syncs=0 reverts=0 failures=0";
        let p = parse_pass("swift1", l).unwrap();
        assert_eq!(p.daemon, "reconstructor");
        assert!(!p.worked(), "a zero pass is not evidence of a repair");

        assert!(parse_pass("swift1", "some unrelated log line").is_none());
    }

    #[test]
    fn the_probe_output_splits_into_files_invalid_suffixes_passes_and_auditor() {
        let out = "@d d1\n1048576 1785322220.59831.data\n@i d1\ne47 \n@d d2\n@i d2\n\n\
                   @p \n1785322617.1 swift1 object-replicator[1]: INFO object-replicator pass: \
                   partitions=1 suffix_syncs=1 reverts=0 failures=0\n@a \nnot-found/inactive\n";
        let p = parse_probe("swift1", out);
        assert_eq!(p.files.get("d1").unwrap().len(), 1);
        assert!(p.files.get("d2").unwrap().is_empty(), "an empty device is not a missing one");
        assert_eq!(p.invalid.get("d1").map(String::as_str), Some("e47"));
        assert!(p.invalid.get("d2").is_none());
        assert_eq!(p.passes.len(), 1);
        assert_eq!(p.auditor, "not-found/inactive");
    }

    #[test]
    fn a_filename_yields_its_version_fragment_and_durability() {
        assert_eq!(
            split_name("1785322220.82633#2#d.data"),
            ("1785322220.82633".into(), Some(2), true)
        );
        assert_eq!(
            split_name("1785322220.82633#2.data"),
            ("1785322220.82633".into(), Some(2), false)
        );
        assert_eq!(
            split_name("1785322220.59831.data"),
            ("1785322220.59831".into(), None, false)
        );
    }

    fn row(node: &str, role: &'static str, ver: &str, file: &str, frag: Option<u32>, durable: bool) -> CopyRow {
        CopyRow {
            node: node.into(),
            device: "d1".into(),
            role,
            index: 0,
            file: file.into(),
            size: 1,
            version: ver.into(),
            frag,
            durable,
        }
    }

    #[test]
    fn the_census_counts_only_current_durable_copies_on_primaries() {
        let mut c = Census::default();
        c.rows = vec![
            row("swift1", "primary", "200", "200#0#d.data", Some(0), true),
            // An older version is a copy of a previous object, not of this one.
            row("swift2", "primary", "100", "100#1#d.data", Some(1), true),
            // A fragment without its durability marker does not count.
            row("swift3", "primary", "200", "200#2.data", Some(2), false),
            // A handoff is a backlog, not a placement.
            row("swift4", "handoff", "200", "200#0#d.data", Some(0), true),
        ];
        let newest = newest_version(&c);
        assert_eq!(newest, "200");
        tally_census(&mut c, &newest);
        assert_eq!(c.current, 1);
        assert_eq!(c.holders, vec!["swift1".to_string()]);
    }

    #[test]
    fn utc_timestamps_are_real_ones() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(1785322220), "2026-07-29T10:50:20Z");
        assert_eq!(clock(1785322220), "10:50:20");
        // A leap day, because that is where a hand-rolled calendar goes wrong.
        assert_eq!(iso(1709164800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn arena_containers_are_derived_per_policy_and_recognised_again() {
        assert_eq!(arena_container(0), "chaos-arcade");
        assert_eq!(arena_container(1), "chaos-arcade-p1");
        assert!(is_arena("chaos-arcade"));
        assert!(is_arena("chaos-arcade-p1"));
        assert!(!is_arena("chaos-arcade-backup"));
        assert!(!is_arena("expand-ec"));
    }

    #[test]
    fn a_browser_form_and_the_json_api_reach_the_same_request() {
        let form = parse_run_req(
            "application/x-www-form-urlencoded",
            "fault=drop_copy&policy=1&readable=true&repaired_by=reconstructor&converge_secs=45&deadline=150",
        )
        .unwrap();
        assert_eq!(form.fault, "drop_copy");
        assert_eq!(form.policy, 1);
        assert_eq!(form.prediction.converge_secs, 45);
        assert!(form.prediction.readable);
        assert!(!form.drill);

        let json = parse_run_req(
            "application/json",
            r#"{"fault":"drop_copy","policy":1,"deadline":150,
                "prediction":{"readable":true,"repaired_by":"reconstructor","converge_secs":45}}"#,
        )
        .unwrap();
        assert_eq!(json.fault, form.fault);
        assert_eq!(json.policy, form.policy);
        assert_eq!(json.prediction, form.prediction);

        // The drill button is a second submit on the same form.
        let d = parse_run_req("application/x-www-form-urlencoded", "fault=drop_copy&drill=1")
            .unwrap();
        assert!(d.drill);
    }

    #[test]
    fn percent_and_plus_encoding_survive_the_form_parser() {
        let r = parse_run_req(
            "application/x-www-form-urlencoded",
            "fault=drop_copy&repaired_by=re%63onstructor&converge_secs=60",
        )
        .unwrap();
        assert_eq!(r.prediction.repaired_by, "reconstructor");
    }

    #[test]
    fn the_probe_command_refuses_names_it_cannot_vouch_for() {
        let devs = vec!["d1".to_string()];
        assert!(probe_cmd("/srv/node", "objects", 1, H, &devs).is_some());
        assert!(probe_cmd("/srv/node", "objects; rm -rf /", 1, H, &devs).is_none());
        assert!(probe_cmd("/srv/node", "objects", 1, "not-hex", &devs).is_none());
        let bad = vec!["d1 ; reboot".to_string()];
        assert!(probe_cmd("/srv/node", "objects", 1, H, &bad).is_none());
    }
}
