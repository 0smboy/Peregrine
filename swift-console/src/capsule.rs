//! Object Capsule: where one object actually lives, and whether it is healthy.
//!
//! The first question is which storage policy the container uses, and it is
//! answered by asking the container — never by assuming policy 0. A tool that
//! assumes reads the wrong ring, probes the wrong directory on every node, and
//! then reports a healthy erasure-coded object as entirely missing. Confidently
//! wrong is the worst thing a diagnostic can be, so the policy is read first
//! and every later step is derived from it.
//!
//! Everything here is observation — a container HEAD, a ring lookup, one
//! directory listing per placement, an object HEAD, and a single capped read.
//! Nothing is written, no ring is touched, no service is restarted.

use crate::i18n;
use crate::nodes;
use crate::ringlab::{self, PolicyInfo};
use crate::session::Session;
use crate::swift;
use crate::util::{enc_obj, enc_seg, esc, fmt_bytes, ix_mount};
use crate::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A diagnostic must not pull a 5 GB object to prove it is readable. Past
/// either bound the read is abandoned and reported as a sample, which still
/// answers "does the cluster serve this" without the cost.
const READ_CAP_BYTES: u64 = 64 * 1024 * 1024;
const READ_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Deserialize, Default)]
pub struct CapQ {
    #[serde(default)]
    pub account: String,
    #[serde(default)]
    pub container: String,
    #[serde(default)]
    pub object: String,
}

pub struct CapErr {
    pub status: StatusCode,
    pub msg: String,
}

fn bad(msg: impl Into<String>) -> CapErr {
    CapErr { status: StatusCode::BAD_REQUEST, msg: msg.into() }
}
fn missing(msg: impl Into<String>) -> CapErr {
    CapErr { status: StatusCode::NOT_FOUND, msg: msg.into() }
}
fn upstream(msg: impl Into<String>) -> CapErr {
    CapErr { status: StatusCode::BAD_GATEWAY, msg: msg.into() }
}

// ------------------------------------------------------------- on-disk truth

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct DiskFile {
    pub name: String,
    pub size: u64,
    /// Swift's own timestamp, taken from the filename rather than the inode:
    /// mtime changes when a file is copied between nodes, the encoded
    /// timestamp is the version and does not.
    pub timestamp: String,
    /// "data" | "tombstone" | "meta" | "durable" | "other"
    pub kind: &'static str,
    /// EC fragment index; absent under replication.
    pub frag_index: Option<u32>,
}

impl DiskFile {
    fn ts(&self) -> f64 {
        self.timestamp.parse().unwrap_or(0.0)
    }
}

/// Split an object filename into version, kind and fragment index.
/// Replication writes `<ts>.data` and `<ts>.ts`; erasure coding writes
/// `<ts>#<frag>#d.data`, and older clusters `<ts>#<frag>.data` beside a
/// separate `.durable` marker, so both fragment spellings are read.
pub fn parse_disk_file(name: &str, size: u64) -> DiskFile {
    let (stem, kind) = match name.rsplit_once('.') {
        Some((s, "data")) => (s, "data"),
        Some((s, "ts")) => (s, "tombstone"),
        Some((s, "meta")) => (s, "meta"),
        Some((s, "durable")) => (s, "durable"),
        _ => (name, "other"),
    };
    let mut parts = stem.split('#');
    let timestamp = parts.next().unwrap_or("").to_string();
    let frag_index = parts.next().and_then(|f| f.parse().ok());
    DiskFile {
        name: name.to_string(),
        size,
        timestamp: if kind == "other" { String::new() } else { timestamp },
        kind,
        frag_index,
    }
}

/// One ring placement, plus what that disk actually holds.
#[derive(Serialize, Clone, Debug)]
pub struct Slot {
    /// "primary" | "handoff"
    pub role: &'static str,
    pub index: usize,
    pub node: String,
    pub device: String,
    pub region: u64,
    pub zone: u64,
    pub dir: String,
    /// False when the node did not answer — its contents are unknown, which is
    /// not the same as empty and is never counted as either.
    pub reachable: bool,
    pub error: String,
    pub files: Vec<DiskFile>,
}

/// Device and directory names are matched against a strict character set
/// before they are interpolated into a remote command. They come from the ring
/// and from config rather than from a caller, but a probe that cannot prove
/// that is refused instead of trusted.
fn safe_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 40
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The last three characters of the hash: the suffix directory Swift shards
/// hash directories under.
fn suffix(hash: &str) -> &str {
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
        suffix(hash),
        hash
    )
}

/// List this object's hash directory for every device the ring placed on one
/// node. One command per node rather than one per placement: a node commonly
/// holds two of them, and each extra ssh is a round trip against a diagnostic
/// an operator is waiting on.
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
            "echo '@ {d}'; find {dir} -maxdepth 1 -type f -printf '%s %f\\n' 2>/dev/null; ",
            dir = hash_dir(root, d, data_dir, part, hash)
        ));
    }
    // A missing directory is the normal answer, not a failure, so the exit
    // status is forced to zero and absence is read from the empty output.
    cmd.push_str("exit 0");
    Some(cmd)
}

/// Read the probe output back into files per device.
fn parse_probe(out: &str) -> BTreeMap<String, Vec<DiskFile>> {
    let mut found: BTreeMap<String, Vec<DiskFile>> = BTreeMap::new();
    let mut device = String::new();
    for line in out.lines() {
        if let Some(d) = line.strip_prefix("@ ") {
            device = d.trim().to_string();
            found.entry(device.clone()).or_default();
            continue;
        }
        let Some((size, name)) = line.trim().split_once(' ') else {
            continue;
        };
        let Ok(size) = size.parse::<u64>() else {
            continue;
        };
        found
            .entry(device.clone())
            .or_default()
            .push(parse_disk_file(name.trim(), size));
    }
    found
}

// ------------------------------------------------------------- verdict

/// The policy reduced to the numbers a verdict needs.
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    pub is_ec: bool,
    pub k: u32,
    pub m: u32,
    pub replicas: usize,
}

/// What the disks turned up, counted against the newest version on disk. An
/// older fragment or replica is not a copy of this object; it is a copy of a
/// previous one, and counting it would overstate durability.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Census {
    pub copies: usize,
    pub frags: Vec<u32>,
    pub stale: usize,
    pub tombstones: usize,
    pub on_handoff: usize,
    pub unknown: usize,
    pub newest: String,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Health {
    /// "ok" | "degraded" | "at_risk" | "critical" | "deleted"
    pub level: &'static str,
    pub headline: String,
    pub detail: String,
}

fn census(slots: &[Slot]) -> Census {
    let mut c = Census::default();
    let newest = slots
        .iter()
        .flat_map(|s| s.files.iter())
        .filter(|f| f.kind == "data")
        .map(|f| f.ts())
        .fold(0.0f64, f64::max);
    for s in slots {
        if !s.reachable {
            c.unknown += 1;
            continue;
        }
        let mut holds_data = false;
        for f in &s.files {
            match f.kind {
                "tombstone" => c.tombstones += 1,
                "data" if f.ts() >= newest => {
                    holds_data = true;
                    c.newest = f.timestamp.clone();
                    match f.frag_index {
                        Some(i) if !c.frags.contains(&i) => c.frags.push(i),
                        Some(_) => {}
                        None => c.copies += 1,
                    }
                }
                "data" => c.stale += 1,
                _ => {}
            }
        }
        if holds_data && s.role == "handoff" {
            c.on_handoff += 1;
        }
    }
    c.frags.sort_unstable();
    c
}

/// The whole point of the tool: a sentence an operator can act on, in the
/// language they are reading the rest of the console in.
pub fn verdict(lang: &str, s: &Shape, c: &Census) -> Health {
    let present = if s.is_ec { c.frags.len() } else { c.copies };
    // An unreadable placement is not an empty one. Every count below is a floor
    // while one is outstanding, and the sentence has to carry that or the page
    // reports a durability level it did not measure.
    let unknown = if c.unknown == 0 {
        String::new()
    } else {
        let key = if c.unknown == 1 {
            "cap.v.unknown1"
        } else {
            "cap.v.unknownN"
        };
        // English needs a space between sentences; a Chinese sentence already
        // ends in a full-width stop and a space after one reads as a typo.
        let sep = if lang == "zh" { "" } else { " " };
        format!("{sep}{}", i18n::t(lang, key).replace("{n}", &c.unknown.to_string()))
    };
    let fill = |key: &'static str, present: usize, want: usize| -> String {
        let idx = c
            .frags
            .iter()
            .map(|i| format!("#{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{}{unknown}",
            i18n::t(lang, key)
                .replace("{present}", &present.to_string())
                .replace("{want}", &want.to_string())
                .replace("{k}", &s.k.to_string())
                .replace("{m}", &s.m.to_string())
                .replace("{gone}", &want.saturating_sub(present).to_string())
                .replace("{n}", &want.saturating_sub(1).to_string())
                .replace("{idx}", &idx)
        )
    };
    let head = |key: &'static str, present: usize, want: usize| -> String {
        i18n::t(lang, key)
            .replace("{present}", &present.to_string())
            .replace("{want}", &want.to_string())
            .replace("{k}", &s.k.to_string())
            .replace("{m}", &s.m.to_string())
    };

    if present == 0 {
        return if c.tombstones > 0 {
            Health {
                level: "deleted",
                headline: head("cap.v.deleted.h", 0, 0),
                detail: fill("cap.v.deleted.d", 0, 0),
            }
        } else {
            Health {
                level: "critical",
                headline: head("cap.v.gone.h", 0, 0),
                detail: fill("cap.v.gone.d", 0, 0),
            }
        };
    }
    if s.is_ec {
        let (k, want) = (s.k as usize, (s.k + s.m) as usize);
        if present < k {
            Health {
                level: "critical",
                headline: head("cap.v.ec.below.h", present, want),
                detail: fill("cap.v.ec.below.d", present, want),
            }
        } else if present == k {
            Health {
                level: "at_risk",
                headline: head("cap.v.ec.exact.h", present, want),
                detail: fill("cap.v.ec.exact.d", present, want),
            }
        } else if present < want {
            Health {
                level: "degraded",
                headline: head("cap.v.ec.short.h", present, want),
                detail: fill("cap.v.ec.short.d", present, want),
            }
        } else {
            Health {
                level: "ok",
                headline: head("cap.v.ec.full.h", present, want),
                detail: fill("cap.v.ec.full.d", present, want),
            }
        }
    } else {
        let want = s.replicas.max(1);
        if present >= want {
            Health {
                level: "ok",
                headline: head("cap.v.rep.full.h", present, want),
                detail: fill("cap.v.rep.full.d", present, want),
            }
        } else if present == 1 {
            Health {
                level: "at_risk",
                headline: head("cap.v.rep.one.h", present, want),
                detail: fill("cap.v.rep.one.d", present, want),
            }
        } else {
            Health {
                level: "degraded",
                headline: head("cap.v.rep.short.h", present, want),
                detail: fill("cap.v.rep.short.d", present, want),
            }
        }
    }
}

/// Reconcile what the disks say with what the cluster actually did.
///
/// The disk verdict is about durability and the read is about service, and
/// they can disagree: fragments enough to reconstruct, and a 503 anyway. A
/// page that says "the object still reads" directly above a failed read is
/// worse than useless, and the disagreement is itself the finding — it says
/// the data is fine and the path to it is not, which is a different problem
/// with a different owner.
pub fn reconcile(lang: &str, disk: Health, s: &Shape, c: &Census, read: &ReadProbe) -> Health {
    if read.etag_matched == Some(false) {
        return Health {
            level: "critical",
            headline: i18n::t(lang, "cap.v.corrupt.h").to_string(),
            detail: i18n::t(lang, "cap.v.corrupt.d")
                .replace("{n}", &fmt_bytes(read.bytes)),
        };
    }
    // Nothing to reconcile when the read agrees, was never attempted, or the
    // disks already tell the worse story.
    if read.status == 0 || read.status < 300 || disk.level == "critical" || disk.level == "deleted"
    {
        return disk;
    }
    let (present, unit, need) = if s.is_ec {
        (
            c.frags.len(),
            i18n::t(lang, "cap.unit.frag"),
            s.k as usize,
        )
    } else {
        (c.copies, i18n::t(lang, "cap.unit.rep"), 1)
    };
    Health {
        level: "critical",
        headline: i18n::t(lang, "cap.v.service.h").replace("{status}", &read.status.to_string()),
        detail: i18n::t(lang, "cap.v.service.d")
            .replace("{present}", &present.to_string())
            .replace("{unit}", unit)
            .replace("{need}", &need.to_string()),
    }
}

// ------------------------------------------------------------- api probes

#[derive(Serialize, Clone, Debug, Default)]
pub struct MetaProbe {
    pub status: u16,
    pub content_length: Option<u64>,
    pub etag: Option<String>,
    pub content_type: Option<String>,
    pub last_modified: Option<String>,
    pub timestamp: Option<String>,
    pub meta: BTreeMap<String, String>,
    pub error: String,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ReadProbe {
    pub status: u16,
    pub bytes: u64,
    pub ms: u64,
    /// True when the read was cut short at the size or time cap, which is why
    /// `etag_matched` is then unanswerable rather than false.
    pub sampled: bool,
    pub etag_matched: Option<bool>,
    pub note: String,
}

fn header_str(h: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    h.get(name).and_then(|v| v.to_str().ok()).map(String::from)
}

async fn meta_probe(state: &Arc<AppState>, sid: &str, sub: &str) -> MetaProbe {
    let (status, h) = match swift::head(state, sid, sub).await {
        Ok(v) => v,
        Err(e) => {
            return MetaProbe {
                error: e.msg(),
                ..Default::default()
            }
        }
    };
    // A refusal carries its own content-length and content-type — 118 bytes of
    // text/html — and reading those as the object's would put a plausible,
    // entirely wrong size on the page. Only a 2xx describes the object.
    if status >= 300 {
        return MetaProbe {
            status,
            ..Default::default()
        };
    }
    let mut meta = BTreeMap::new();
    for (k, v) in h.iter() {
        let k = k.as_str().to_ascii_lowercase();
        if let Some(name) = k.strip_prefix("x-object-meta-") {
            meta.insert(name.to_string(), v.to_str().unwrap_or("").to_string());
        }
    }
    MetaProbe {
        status,
        content_length: header_str(&h, "content-length").and_then(|v| v.parse().ok()),
        etag: header_str(&h, "etag").map(|v| v.trim_matches('"').to_string()),
        content_type: header_str(&h, "content-type"),
        last_modified: header_str(&h, "last-modified"),
        timestamp: header_str(&h, "x-timestamp"),
        meta,
        error: String::new(),
    }
}

/// Read the object back through the API and check what came out against the
/// ETag. Capped in both bytes and seconds: proving a 5 GB object is readable
/// does not require moving 5 GB.
async fn read_probe(
    state: &Arc<AppState>,
    sid: &str,
    lang: &str,
    sub: &str,
    etag: Option<&str>,
) -> ReadProbe {
    let t0 = Instant::now();
    let mut resp = match swift::call(
        state,
        sid,
        reqwest::Method::GET,
        sub,
        &[],
        &[],
        None,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return ReadProbe {
                note: e.msg(),
                ms: t0.elapsed().as_millis() as u64,
                ..Default::default()
            }
        }
    };
    let status = resp.status().as_u16();
    if status >= 300 {
        return ReadProbe {
            status,
            ms: t0.elapsed().as_millis() as u64,
            note: i18n::t(lang, "cap.read.refused").replace("{s}", &status.to_string()),
            ..Default::default()
        };
    }
    let mut hash = Md5::new();
    let mut bytes = 0u64;
    let mut sampled = false;
    let mut note = String::new();
    loop {
        let Some(left) = READ_DEADLINE.checked_sub(t0.elapsed()) else {
            sampled = true;
            break;
        };
        match tokio::time::timeout(left, resp.chunk()).await {
            Err(_) => {
                sampled = true;
                break;
            }
            Ok(Err(e)) => {
                note = i18n::t(lang, "cap.read.broke")
                    .replace("{n}", &fmt_bytes(bytes))
                    .replace("{e}", &e.to_string());
                break;
            }
            Ok(Ok(None)) => break,
            Ok(Ok(Some(chunk))) => {
                bytes += chunk.len() as u64;
                hash.update(&chunk);
                if bytes >= READ_CAP_BYTES {
                    sampled = true;
                    break;
                }
            }
        }
    }
    // An ETag can only be checked against a complete read, and only when it is
    // a digest at all — a large-object manifest carries a digest of its
    // segment list, which will never match the bytes served.
    let plain = etag.filter(|e| e.len() == 32 && is_hex(e));
    let etag_matched = match (sampled, plain) {
        (false, Some(want)) => Some(hex::encode(hash.finalize()) == want),
        _ => None,
    };
    if note.is_empty() {
        let key = if sampled {
            "cap.read.sampled"
        } else if etag_matched == Some(true) {
            "cap.read.match"
        } else if etag_matched == Some(false) {
            "cap.read.mismatch"
        } else {
            "cap.read.noetag"
        };
        note = i18n::t(lang, key).replace("{n}", &fmt_bytes(bytes));
    }
    ReadProbe {
        status,
        bytes,
        ms: t0.elapsed().as_millis() as u64,
        sampled,
        etag_matched,
        note,
    }
}

// ------------------------------------------------------------- gather

#[derive(Serialize, Clone, Debug)]
pub struct Report {
    pub account: String,
    pub container: String,
    pub object: String,
    pub policy: PolicyInfo,
    /// How the policy was determined, as an i18n key rather than prose:
    /// recorded because assuming it is the classic way this kind of tool goes
    /// wrong, and rendered in whichever language the report is read in.
    pub policy_source: &'static str,
    pub partition: u32,
    pub hash: String,
    pub dir: String,
    pub slots: Vec<Slot>,
    /// The newest version any disk holds. Anything older is a previous object,
    /// not a copy of this one.
    pub newest: String,
    pub present: usize,
    pub wanted: usize,
    pub on_handoff: usize,
    pub stale: usize,
    pub unreachable: usize,
    pub health: Health,
    pub meta: MetaProbe,
    pub read: ReadProbe,
    pub took_ms: u64,
}

/// The account this console session speaks for, from its storage URL.
pub fn session_account(sess: &Session) -> String {
    sess.storage_url
        .rsplit_once("/v1/")
        .map(|(_, a)| a.trim_end_matches('/').to_string())
        .unwrap_or_default()
}

fn check_name(
    lang: &str,
    what: &'static str,
    s: &str,
    max: usize,
    allow_slash: bool,
) -> Result<(), CapErr> {
    let name = i18n::t(lang, what);
    let say = |key: &'static str| -> CapErr { bad(i18n::t(lang, key).replace("{what}", name)) };
    if s.is_empty() {
        return Err(say("cap.err.required"));
    }
    if s.len() > max {
        return Err(say("cap.err.toolong"));
    }
    if s.chars().any(|c| c.is_control()) {
        return Err(say("cap.err.control"));
    }
    if !allow_slash && s.contains('/') {
        return Err(say("cap.err.slash"));
    }
    Ok(())
}

pub async fn gather(
    state: &Arc<AppState>,
    sid: &str,
    sess: &Session,
    lang: &str,
    q: &CapQ,
) -> Result<Report, CapErr> {
    let t0 = Instant::now();
    let mine = session_account(sess);
    let account = if q.account.is_empty() { mine.clone() } else { q.account.clone() };
    check_name(lang, "cap.f.account", &account, 256, false)?;
    check_name(lang, "cap.f.container", &q.container, 256, false)?;
    check_name(lang, "cap.f.object", &q.object, 1024, true)?;
    // Every probe below the ring lookup runs as this session, and a tempauth
    // token only ever speaks for its own account. Refusing is the honest
    // answer; the alternative is a report whose policy, and therefore whose
    // ring and directories, were guessed.
    if account != mine {
        return Err(CapErr {
            status: StatusCode::FORBIDDEN,
            msg: i18n::t(lang, "cap.err.otheraccount")
                .replace("{mine}", &mine)
                .replace("{other}", &account),
        });
    }

    // 1. The policy, from the container itself.
    let csub = format!("/{}", enc_seg(&q.container));
    let (cstatus, chead) = swift::head(state, sid, &csub)
        .await
        .map_err(|e| upstream(e.msg()))?;
    if cstatus == 404 {
        return Err(missing(
            i18n::t(lang, "cap.err.nocontainer").replace("{c}", &q.container),
        ));
    }
    if cstatus >= 300 {
        return Err(upstream(
            i18n::t(lang, "cap.err.container").replace("{s}", &cstatus.to_string()),
        ));
    }
    let policies = ringlab::policies(state).await.map_err(upstream)?;
    let named = header_str(&chead, "x-storage-policy");
    let (policy, policy_source) = match named
        .as_deref()
        .and_then(|n| policies.iter().find(|p| p.name.eq_ignore_ascii_case(n)))
    {
        Some(p) => (p.clone(), "cap.src.container"),
        None => (
            ringlab::default_policy(state).await.map_err(upstream)?,
            "cap.src.default",
        ),
    };

    // 2. Placement, from that policy's ring.
    let placed = ringlab::locate(
        state,
        policy.index,
        &account,
        Some(&q.container),
        Some(&q.object),
    )
    .await
    .map_err(upstream)?;

    // 3. On-disk truth, one listing per node.
    let mut slots: Vec<Slot> = Vec::new();
    for (role, list) in [("primary", &placed.primaries), ("handoff", &placed.handoffs)] {
        for n in list.iter() {
            slots.push(Slot {
                role,
                index: n.index,
                node: n.node.clone(),
                device: n.device.clone(),
                region: n.region,
                zone: n.zone,
                dir: hash_dir(
                    &state.cfg.node_root,
                    &n.device,
                    &policy.data_dir,
                    placed.partition,
                    &placed.hash,
                ),
                reachable: false,
                error: String::new(),
                files: Vec::new(),
            });
        }
    }
    let mut by_node: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for s in &slots {
        by_node.entry(s.node.clone()).or_default().push(s.device.clone());
    }
    let mut jobs: Vec<(String, String)> = Vec::new();
    for (node, devices) in &by_node {
        let Some(cmd) = probe_cmd(
            &state.cfg.node_root,
            &policy.data_dir,
            placed.partition,
            &placed.hash,
            devices,
        ) else {
            return Err(upstream(i18n::t(lang, "cap.err.baddevice")));
        };
        jobs.push((node.clone(), cmd));
    }
    for r in nodes::fan_out_each(state, jobs).await {
        let found = parse_probe(&r.out);
        for s in slots.iter_mut().filter(|s| s.node == r.node) {
            s.reachable = r.ok;
            s.error = r.err.clone();
            if let Some(files) = found.get(&s.device) {
                s.files = files.clone();
            }
        }
    }

    // 4 and 5. What the API says, and whether it will actually hand it back.
    let osub = swift::obj_subpath(&q.container, &q.object);
    let meta = meta_probe(state, sid, &osub).await;
    let anything = slots.iter().any(|s| !s.files.is_empty());
    if meta.status == 404 && !anything {
        return Err(missing(
            i18n::t(lang, "cap.err.noobject")
                .replace("{o}", &q.object)
                .replace("{c}", &q.container)
                .replace("{n}", &slots.len().to_string()),
        ));
    }
    // Only a 404 makes the read pointless. A metadata request that failed for
    // any other reason is precisely when "can this actually be read" is the
    // question, so the read is still attempted — skipping it there would hide
    // the answer behind the symptom.
    let read = if meta.status == 404 {
        ReadProbe {
            status: 404,
            note: i18n::t(lang, "cap.read.skipped").to_string(),
            ..Default::default()
        }
    } else {
        read_probe(state, sid, lang, &osub, meta.etag.as_deref()).await
    };

    let c = census(&slots);
    let shape = Shape {
        is_ec: policy.is_ec(),
        k: policy.ec_ndata.unwrap_or(0),
        m: policy.ec_nparity.unwrap_or(0),
        replicas: placed.primaries.len(),
    };
    let health = reconcile(lang, verdict(lang, &shape, &c), &shape, &c, &read);
    let present = if shape.is_ec { c.frags.len() } else { c.copies };
    let wanted = if shape.is_ec {
        (shape.k + shape.m) as usize
    } else {
        shape.replicas
    };
    Ok(Report {
        account,
        container: q.container.clone(),
        object: q.object.clone(),
        dir: hash_dir(
            &state.cfg.node_root,
            "<device>",
            &policy.data_dir,
            placed.partition,
            &placed.hash,
        ),
        policy,
        policy_source,
        partition: placed.partition,
        hash: placed.hash,
        slots,
        newest: c.newest.clone(),
        present,
        wanted,
        on_handoff: c.on_handoff,
        stale: c.stale,
        unreachable: c.unknown,
        health,
        meta,
        read,
        took_ms: t0.elapsed().as_millis() as u64,
    })
}
// ------------------------------------------------------------- rendering

pub fn form_content(lang: &str, account: &str, filled: Option<(&str, &str)>) -> String {
    let (container, object) = filled.unwrap_or(("", ""));
    format!(
        r#"<div class="pagehead">
  <h1>{title}</h1>
</div>
<p class="statline">{intro}</p>
<form class="page-sec oc-form" method="get" action="/lab/capsule">
  <div class="sx-grid">
    <label class="fld"><span>{l_account}</span><input name="account" value="{account}" autocomplete="off"></label>
    <label class="fld"><span>{l_container}</span><input name="container" value="{container}" autocomplete="off" required></label>
    <label class="fld"><span>{l_object}</span><input name="object" value="{object}" autocomplete="off" required></label>
  </div>
  <div class="sx-actions"><button class="btn-primary" type="submit">{open}</button></div>
</form>"#,
        title = esc(i18n::t(lang, "lab.tool.capsule.title")),
        intro = esc(i18n::t(lang, "cap.intro")),
        l_account = esc(i18n::t(lang, "cap.f.account")),
        l_container = esc(i18n::t(lang, "cap.f.container")),
        l_object = esc(i18n::t(lang, "cap.f.object")),
        open = esc(i18n::t(lang, "cap.f.open")),
        account = esc(account),
        container = esc(container),
        object = esc(object),
    )
}

/// What one file on one disk is, relative to the newest version anything holds.
fn state_of(f: &DiskFile, slot: &Slot, newest: &str) -> &'static str {
    match f.kind {
        "tombstone" => "tombstone",
        "data" if !newest.is_empty() && f.timestamp != newest => "stale",
        "data" if slot.role == "handoff" => "leftover",
        "data" => "current",
        k => k,
    }
}

fn state_word(lang: &str, state: &str) -> String {
    match state {
        "current" => i18n::t(lang, "cap.st.current"),
        "stale" => i18n::t(lang, "cap.st.stale"),
        "leftover" => i18n::t(lang, "cap.st.leftover"),
        "tombstone" => i18n::t(lang, "cap.st.tombstone"),
        "meta" => i18n::t(lang, "cap.st.meta"),
        "durable" => i18n::t(lang, "cap.st.durable"),
        _ => i18n::t(lang, "cap.st.other"),
    }
    .to_string()
}

fn state_class(state: &str) -> &'static str {
    match state {
        "current" => "oc-ok",
        "stale" | "leftover" | "tombstone" => "oc-warn",
        _ => "",
    }
}

fn stat_card(label: &str, value: &str, cls: &str, note: &str) -> String {
    format!(
        "<div class=\"mon-card mon-stat lab-stat\"><div class=\"mon-card-h\"><span class=\"mon-t\">{label}</span></div>\
         <div class=\"mon-body\"><span class=\"mon-stat-v {cls}\">{value}</span><span class=\"lab-b\">{note}</span></div></div>",
        label = esc(label),
        value = esc(value),
        note = esc(note),
    )
}

/// What one placement holds, reduced to the single thing the matrix draws.
#[derive(Clone, Copy, PartialEq)]
enum CellState {
    Current,
    Stale,
    Tombstone,
    Empty,
    Unknown,
}

impl CellState {
    fn class(self) -> &'static str {
        match self {
            CellState::Current => "oc-c-cur",
            CellState::Stale => "oc-c-stale",
            CellState::Tombstone => "oc-c-ts",
            CellState::Empty => "oc-c-empty",
            CellState::Unknown => "oc-c-unk",
        }
    }
    fn key(self) -> &'static str {
        match self {
            CellState::Current => "cap.cell.current",
            CellState::Stale => "cap.cell.stale",
            CellState::Tombstone => "cap.cell.tombstone",
            CellState::Empty => "cap.cell.empty",
            CellState::Unknown => "cap.cell.unknown",
        }
    }
}

fn cell_state(s: &Slot, newest: &str) -> CellState {
    if !s.reachable {
        return CellState::Unknown;
    }
    let mut stale = false;
    let mut ts = false;
    for f in &s.files {
        match f.kind {
            "data" if newest.is_empty() || f.timestamp == newest => return CellState::Current,
            "data" => stale = true,
            "tombstone" => ts = true,
            _ => {}
        }
    }
    if ts {
        CellState::Tombstone
    } else if stale {
        CellState::Stale
    } else {
        CellState::Empty
    }
}

/// The placement matrix: every node the ring touched down one side, every
/// device across the top, and one mark per cell saying what is actually there.
///
/// The table below carries the same facts, but a table cannot show a *hole* —
/// and a hole in the row of a primary is exactly the shape of an object that is
/// one failure from gone. The matrix is drawn server-side, so it is in the
/// document whether or not a script ever runs.
fn placement_matrix(lang: &str, rep: &Report) -> String {
    let mut nodes: Vec<String> = Vec::new();
    let mut devices: Vec<String> = Vec::new();
    for s in &rep.slots {
        if !nodes.contains(&s.node) {
            nodes.push(s.node.clone());
        }
        if !devices.contains(&s.device) {
            devices.push(s.device.clone());
        }
    }
    nodes.sort();
    devices.sort();
    if nodes.is_empty() || devices.is_empty() {
        return format!(
            "<p class=\"note\">{}</p>",
            esc(i18n::t(lang, "cap.matrix.empty"))
        );
    }

    let mut cell_data: Vec<serde_json::Value> = Vec::new();
    for (ri, n) in nodes.iter().enumerate() {
        for (ci, d) in devices.iter().enumerate() {
            let slot = rep.slots.iter().find(|s| &s.node == n && &s.device == d);
            let Some(slot) = slot else {
                cell_data.push(json!({
                    "row": ri, "col": ci, "node": n, "device": d,
                    "cls": "oc-c-none", "label": "", "role": "", "tip": "",
                }));
                continue;
            };
            let st = cell_state(slot, &rep.newest);
            let frag = slot
                .files
                .iter()
                .filter(|f| f.kind == "data" && (rep.newest.is_empty() || f.timestamp == rep.newest))
                .find_map(|f| f.frag_index)
                .map(|i| format!("#{i}"));
            let role = if slot.role == "primary" {
                i18n::t(lang, "cap.matrix.primary")
            } else {
                i18n::t(lang, "cap.matrix.handoff")
            };
            let label = frag.unwrap_or_else(|| i18n::t(lang, st.key()).to_string());
            cell_data.push(json!({
                "row": ri, "col": ci, "node": n, "device": d,
                "cls": format!("{}{}", st.class(), if slot.role == "handoff" { " ho" } else { "" }),
                "label": label,
                "role": role,
                "tip": format!("{}/{} · {} · {}", n, d, role, i18n::t(lang, st.key())),
            }));
        }
    }

    let legend: Vec<serde_json::Value> = [
        CellState::Current,
        CellState::Stale,
        CellState::Tombstone,
        CellState::Empty,
        CellState::Unknown,
    ]
    .iter()
    .map(|c| json!({"cls": c.class(), "label": i18n::t(lang, c.key())}))
    .collect();

    let data = json!({
        "title": i18n::t(lang, "cap.matrix.title"),
        "note": i18n::t(lang, "cap.matrix.note"),
        "nodes": nodes,
        "devices": devices,
        "cells": cell_data,
        "legend": legend,
    });

    format!(
        "<div class=\"mon-card wide\"><div class=\"mon-card-h\"><span class=\"mon-t\">{title}</span></div>\
         <div class=\"mon-body\">{mount}<div class=\"lab-b\">{note}</div></div></div>",
        title = esc(i18n::t(lang, "cap.matrix.title")),
        mount = ix_mount("matrix", &data),
        note = esc(i18n::t(lang, "cap.matrix.note")),
    )
}

/// The two verdicts, side by side.
///
/// Durability is what the disks hold; service is whether the cluster will hand
/// it back. They fail independently and they have different owners, so folding
/// them into one line sends somebody to restore an object that was never lost.
fn verdicts(lang: &str, rep: &Report) -> String {
    let vcls = match rep.health.level {
        "ok" => "oc-ok",
        "degraded" | "at_risk" => "oc-warn",
        _ => "oc-bad",
    };
    let read_ok = rep.read.status == 200 && rep.read.etag_matched != Some(false);
    let (rcls, rhead) = if rep.read.status == 0 {
        ("oc-faint", i18n::t(lang, "cap.svc.none").to_string())
    } else if read_ok {
        (
            "oc-ok",
            i18n::t(lang, "cap.svc.ok")
                .replace("{n}", &fmt_bytes(rep.read.bytes))
                .replace("{ms}", &rep.read.ms.to_string()),
        )
    } else {
        (
            "oc-bad",
            i18n::t(lang, "cap.svc.bad").replace("{s}", &rep.read.status.to_string()),
        )
    };
    format!(
        "<div class=\"oc-verdicts\">\
           <div class=\"oc-v\"><div class=\"oc-v-k\">{k1}</div>\
             <h2 class=\"{vcls}\">{h1}</h2><p>{d1}</p></div>\
           <div class=\"oc-v\"><div class=\"oc-v-k\">{k2}</div>\
             <h2 class=\"{rcls}\">{h2}</h2><p>{d2}</p></div>\
         </div>",
        k1 = esc(i18n::t(lang, "cap.k.durability")),
        k2 = esc(i18n::t(lang, "cap.k.service")),
        h1 = esc(&rep.health.headline),
        d1 = esc(&rep.health.detail),
        h2 = esc(&rhead),
        d2 = esc(&rep.read.note),
    )
}

fn report_content(lang: &str, rep: &Report) -> String {
    let mut rows = String::new();
    for s in &rep.slots {
        let place = format!(
            "<td>{role}</td><td>{node}</td><td>{dev}</td><td class=\"num\">{zone}</td>",
            role = esc(if s.role == "primary" {
                i18n::t(lang, "cap.matrix.primary")
            } else {
                i18n::t(lang, "cap.matrix.handoff")
            }),
            node = esc(&s.node),
            dev = esc(&s.device),
            zone = s.zone,
        );
        if !s.reachable {
            rows.push_str(&format!(
                "<tr class=\"muted-row\">{place}<td>—</td><td class=\"num\">—</td><td>—</td><td>—</td>\
                 <td class=\"oc-bad\" title=\"{err}\">{noanswer}</td></tr>",
                err = esc(&s.error),
                noanswer = esc(i18n::t(lang, "cap.row.noanswer")),
            ));
            continue;
        }
        if s.files.is_empty() {
            rows.push_str(&format!(
                "<tr class=\"muted-row\">{place}<td>—</td><td class=\"num\">—</td><td>—</td><td>—</td>\
                 <td class=\"oc-faint\">{empty}</td></tr>",
                empty = esc(i18n::t(lang, "cap.row.empty")),
            ));
            continue;
        }
        for file in &s.files {
            let st = state_of(file, s, &rep.newest);
            rows.push_str(&format!(
                "<tr>{place}<td class=\"oc-file\">{name}</td><td class=\"num\">{size}</td>\
                 <td class=\"when\">{ts}</td><td>{frag}</td><td class=\"{cls}\">{st}</td></tr>",
                name = esc(&file.name),
                size = fmt_bytes(file.size),
                ts = esc(&file.timestamp),
                frag = file
                    .frag_index
                    .map(|i| format!("#{i}"))
                    .unwrap_or_else(|| "—".into()),
                cls = state_class(st),
                st = esc(&state_word(lang, st)),
            ));
        }
    }

    let ptag = if rep.policy.is_ec() {
        format!(
            "{} (EC {}+{})",
            rep.policy.name,
            rep.policy.ec_ndata.unwrap_or(0),
            rep.policy.ec_nparity.unwrap_or(0)
        )
    } else {
        format!(
            "{} ({})",
            rep.policy.name,
            i18n::t(lang, "cap.policy.repl").replace("{n}", &rep.wanted.to_string())
        )
    };
    let vcls = match rep.health.level {
        "ok" => "oc-ok",
        "degraded" | "at_risk" => "oc-warn",
        _ => "oc-bad",
    };
    let read_ok = rep.read.status == 200 && rep.read.etag_matched != Some(false);
    let cards = format!(
        "<div class=\"mon-grid mon-grid-5\">{}{}{}{}{}</div>",
        stat_card(
            i18n::t(lang, "cap.card.policy"),
            &ptag,
            "",
            &i18n::t(lang, "cap.card.policy.n")
                .replace("{i}", &rep.policy.index.to_string())
                .replace("{src}", i18n::t(lang, rep.policy_source))
        ),
        stat_card(
            i18n::t(lang, "cap.card.partition"),
            &rep.partition.to_string(),
            "",
            &i18n::t(lang, "cap.card.partition.n").replace("{h}", &rep.hash)
        ),
        stat_card(
            if rep.policy.is_ec() {
                i18n::t(lang, "cap.card.frags")
            } else {
                i18n::t(lang, "cap.card.reps")
            },
            &format!("{} / {}", rep.present, rep.wanted),
            vcls,
            &if rep.newest.is_empty() {
                i18n::t(lang, "cap.card.nothing").to_string()
            } else {
                i18n::t(lang, "cap.card.version").replace("{v}", &rep.newest)
            }
        ),
        stat_card(
            i18n::t(lang, "cap.card.readable"),
            &if rep.read.status == 0 {
                "—".into()
            } else {
                rep.read.status.to_string()
            },
            if read_ok { "oc-ok" } else { "oc-bad" },
            &i18n::t(lang, "cap.card.readable.n")
                .replace("{n}", &fmt_bytes(rep.read.bytes))
                .replace("{ms}", &rep.read.ms.to_string())
        ),
        stat_card(
            i18n::t(lang, "cap.card.leftovers"),
            &rep.on_handoff.to_string(),
            if rep.on_handoff > 0 { "oc-warn" } else { "" },
            i18n::t(lang, "cap.card.leftovers.n")
        ),
    );

    let mut meta_rows = format!(
        "<div><dt>{l_size}</dt><dd>{size}</dd></div>\
         <div><dt>{l_etag}</dt><dd>{etag}</dd></div>\
         <div><dt>{l_type}</dt><dd>{ctype}</dd></div>\
         <div><dt>{l_mod}</dt><dd>{modified}</dd></div>\
         <div><dt>{l_ver}</dt><dd>{ts}</dd></div>",
        l_size = esc(i18n::t(lang, "cap.meta.size")),
        l_etag = esc(i18n::t(lang, "cap.meta.etag")),
        l_type = esc(i18n::t(lang, "cap.meta.type")),
        l_mod = esc(i18n::t(lang, "cap.meta.modified")),
        l_ver = esc(i18n::t(lang, "cap.meta.version")),
        size = rep
            .meta
            .content_length
            .map(fmt_bytes)
            .unwrap_or_else(|| "—".into()),
        etag = esc(rep.meta.etag.as_deref().unwrap_or("—")),
        ctype = esc(rep.meta.content_type.as_deref().unwrap_or("—")),
        modified = esc(rep.meta.last_modified.as_deref().unwrap_or("—")),
        ts = esc(rep.meta.timestamp.as_deref().unwrap_or("—")),
    );
    if rep.meta.meta.is_empty() {
        meta_rows.push_str(&format!(
            "<div><dt>{}</dt><dd>{}</dd></div>",
            esc(i18n::t(lang, "cap.meta.custom")),
            esc(i18n::t(lang, "cap.meta.nocustom"))
        ));
    }
    // Dashes in every field could mean an object with no metadata or a request
    // that never got an answer, and those call for different actions.
    if rep.meta.status != 200 {
        meta_rows.push_str(&format!(
            "<div><dt>{}</dt><dd class=\"oc-bad\">{}</dd></div>",
            esc(i18n::t(lang, "cap.meta.request")),
            esc(&if rep.meta.error.is_empty() {
                i18n::t(lang, "cap.meta.badstatus").replace("{s}", &rep.meta.status.to_string())
            } else {
                rep.meta.error.clone()
            })
        ));
    }
    for (k, v) in &rep.meta.meta {
        meta_rows.push_str(&format!(
            "<div><dt>{}</dt><dd>{}</dd></div>",
            esc(k),
            esc(v)
        ));
    }

    // A handoff holding data is not a placement, it is a backlog: the
    // replicator has not yet moved it home and deleted it. Worth saying out
    // loud, because nothing else on the page reads as wrong.
    let leftovers = if rep.on_handoff == 0 {
        String::new()
    } else {
        format!(
            "<p class=\"note oc-warn\">{}</p>",
            esc(
                &i18n::t(
                    lang,
                    if rep.on_handoff == 1 {
                        "cap.leftover1"
                    } else {
                        "cap.leftoverN"
                    }
                )
                .replace("{n}", &rep.on_handoff.to_string())
            )
        )
    };
    let stale = if rep.stale == 0 {
        String::new()
    } else {
        format!(
            "<p class=\"note oc-warn\">{}</p>",
            esc(
                &i18n::t(
                    lang,
                    if rep.stale == 1 {
                        "cap.stale1"
                    } else {
                        "cap.staleN"
                    }
                )
                .replace("{n}", &rep.stale.to_string())
            )
        )
    };
    let unreachable = if rep.unreachable == 0 {
        String::new()
    } else {
        format!(
            "<p class=\"err on\">{}</p>",
            esc(
                &i18n::t(lang, "cap.unreachable")
                    .replace("{n}", &rep.unreachable.to_string())
            )
        )
    };

    format!(
        r#"<p class="statline">{acct} / <b>{container}</b> / {object} &middot; {ptag} &middot; {took}</p>

{verdicts}

{unreachable}{cards}

<div class="mon-grid rs-grid">{matrix}</div>

<div class="page-sec oc-wide">
  <h3>{h_where}</h3>
  <p class="note">{dirnote}</p>
</div>
<div class="tbl-wrap oc-wide"><table class="tbl"><thead><tr>
  <th>{c_role}</th><th>{c_node}</th><th>{c_dev}</th><th class="num">{c_zone}</th>
  <th>{c_file}</th><th class="num">{c_size}</th><th>{c_ver}</th><th>{c_frag}</th><th>{c_state}</th>
</tr></thead><tbody>{rows}</tbody></table></div>
{leftovers}{stale}

<div class="oc-cols">
  <div class="page-sec">
    <h3>{h_meta}</h3>
    <dl class="kv">{meta_rows}</dl>
  </div>
  <div class="page-sec">
    <h3>{h_read}</h3>
    <dl class="kv">
      <div><dt>{l_status}</dt><dd>{r_status}</dd></div>
      <div><dt>{l_read}</dt><dd>{r_bytes}</dd></div>
      <div><dt>{l_took}</dt><dd>{r_ms} ms</dd></div>
      <div><dt>{l_sampled}</dt><dd>{r_sampled}</dd></div>
      <div><dt>{l_etag}</dt><dd>{r_etag}</dd></div>
    </dl>
    <p class="note">{r_note}</p>
  </div>
</div>"#,
        acct = esc(&rep.account),
        container = esc(&rep.container),
        object = esc(&rep.object),
        ptag = esc(&ptag),
        took = esc(&i18n::t(lang, "cap.took").replace("{ms}", &rep.took_ms.to_string())),
        verdicts = verdicts(lang, rep),
        unreachable = unreachable,
        cards = cards,
        matrix = placement_matrix(lang, rep),
        h_where = esc(i18n::t(lang, "cap.h.where")),
        dirnote = esc(&i18n::t(lang, "cap.dirnote").replace("{dir}", &rep.dir)),
        c_role = esc(i18n::t(lang, "cap.c.role")),
        c_node = esc(i18n::t(lang, "cap.c.node")),
        c_dev = esc(i18n::t(lang, "cap.c.device")),
        c_zone = esc(i18n::t(lang, "cap.c.zone")),
        c_file = esc(i18n::t(lang, "cap.c.file")),
        c_size = esc(i18n::t(lang, "cap.c.size")),
        c_ver = esc(i18n::t(lang, "cap.c.version")),
        c_frag = esc(i18n::t(lang, "cap.c.fragment")),
        c_state = esc(i18n::t(lang, "cap.c.state")),
        rows = rows,
        leftovers = leftovers,
        stale = stale,
        h_meta = esc(i18n::t(lang, "cap.h.meta")),
        h_read = esc(i18n::t(lang, "cap.h.read")),
        meta_rows = meta_rows,
        l_status = esc(i18n::t(lang, "cap.r.status")),
        l_read = esc(i18n::t(lang, "cap.r.read")),
        l_took = esc(i18n::t(lang, "cap.r.took")),
        l_sampled = esc(i18n::t(lang, "cap.r.sampled")),
        l_etag = esc(i18n::t(lang, "cap.meta.etag")),
        r_status = if rep.read.status == 0 {
            "—".to_string()
        } else {
            rep.read.status.to_string()
        },
        r_bytes = fmt_bytes(rep.read.bytes),
        r_ms = rep.read.ms,
        r_sampled = esc(i18n::t(
            lang,
            if rep.read.sampled {
                "cap.r.sampled.yes"
            } else {
                "cap.r.sampled.no"
            }
        )),
        r_etag = esc(i18n::t(
            lang,
            match rep.read.etag_matched {
                Some(true) => "cap.r.etag.ok",
                Some(false) => "cap.r.etag.bad",
                None => "cap.r.etag.unchecked",
            }
        )),
        r_note = esc(&rep.read.note),
    )
}

// ------------------------------------------------------------- http

pub async fn api(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<CapQ>,
) -> Response {
    let (sid, sess) = match crate::lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    match gather(&state, &sid, &sess, lang, &q).await {
        Ok(rep) => Json(rep).into_response(),
        Err(e) => (e.status, Json(json!({ "error": e.msg }))).into_response(),
    }
}

/// The form, or a redirect to the path form once it is filled in, so every
/// report an operator is looking at is already a link they can paste.
pub async fn page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<CapQ>,
) -> Response {
    let (_, sess) = match crate::lab::require_lab(&state, &headers) {
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
            "/lab/capsule/{}/{}/{}",
            enc_seg(&account),
            enc_seg(&q.container),
            enc_obj(&q.object)
        ))
        .into_response();
    }
    let lang = i18n::lang(&headers);
    crate::pages::lab_capsule_shell(
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
    let (sid, sess) = match crate::lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let q = CapQ { account, container, object };
    let form = form_content(lang, &q.account, Some((&q.container, &q.object)));
    let content = match gather(&state, &sid, &sess, lang, &q).await {
        Ok(rep) => format!("{form}{}", report_content(lang, &rep)),
        // The form stays on the page with the failed input still in it, so the
        // next attempt is a correction rather than a retype.
        Err(e) => format!(
            "{form}<div class=\"oc-v\"><h2 class=\"oc-bad\">{h}</h2><p>{m}</p></div>",
            h = esc(i18n::t(lang, "cap.err.h")),
            m = esc(&e.msg)
        ),
    };
    crate::pages::lab_capsule_shell(&state, &headers, &sess, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(role: &'static str, node: &str, device: &str, files: Vec<DiskFile>) -> Slot {
        Slot {
            role,
            index: 0,
            node: node.into(),
            device: device.into(),
            region: 1,
            zone: 1,
            dir: String::new(),
            reachable: true,
            error: String::new(),
            files,
        }
    }

    #[test]
    fn reads_replication_and_ec_filenames() {
        let r = parse_disk_file("1785077092.42302.data", 50331648);
        assert_eq!(r.kind, "data");
        assert_eq!(r.timestamp, "1785077092.42302");
        assert_eq!(r.frag_index, None);

        let e = parse_disk_file("1785077136.55756#1#d.data", 25169664);
        assert_eq!(e.kind, "data");
        assert_eq!(e.timestamp, "1785077136.55756");
        assert_eq!(e.frag_index, Some(1), "the fragment index is the whole point");

        // Pre-durable-suffix clusters wrote the index without the #d.
        assert_eq!(parse_disk_file("1785.1#2.data", 1).frag_index, Some(2));
        assert_eq!(parse_disk_file("1785077092.42302.ts", 0).kind, "tombstone");
        assert_eq!(parse_disk_file("1785077092.42302.meta", 0).kind, "meta");
        assert_eq!(parse_disk_file("hashes.pkl", 140).kind, "other");
    }

    #[test]
    fn probe_command_covers_every_device_and_refuses_odd_names() {
        let cmd = probe_cmd(
            "/srv/node",
            "objects-1",
            435,
            "6cf7fe7daf537b4c310241943375f509",
            &["d1".into(), "d3".into()],
        )
        .expect("valid");
        assert!(cmd.contains("/srv/node/d1/objects-1/435/509/6cf7fe7daf537b4c310241943375f509"));
        assert!(cmd.contains("/srv/node/d3/objects-1/435/509/6cf7fe7daf537b4c310241943375f509"));
        // A missing directory is the normal case and must not fail the probe.
        assert!(cmd.ends_with("exit 0"));

        assert!(probe_cmd("/srv/node", "objects", 1, "abc", &["d1; rm -rf /".into()]).is_none());
        assert!(probe_cmd("/srv/node", "objects; rm", 1, "abc", &["d1".into()]).is_none());
        assert!(probe_cmd("/srv/node", "objects", 1, "not-hex", &["d1".into()]).is_none());
    }

    #[test]
    fn parses_a_probe_reply_per_device() {
        let out = "@ d1\n25169664 1785077136.55756#1#d.data\n@ d2\n@ d3\n0 1785077136.55756.ts\n";
        let got = parse_probe(out);
        assert_eq!(got["d1"].len(), 1);
        assert_eq!(got["d1"][0].frag_index, Some(1));
        assert!(got["d2"].is_empty(), "a listed but empty device is not absent");
        assert_eq!(got["d3"][0].kind, "tombstone");
    }

    #[test]
    fn ec_at_exactly_k_is_called_out_as_zero_redundancy() {
        // The live case: 2+1 with one fragment missing still reads, and an
        // operator who is told only "readable" will not act on it.
        let slots = vec![
            slot("primary", "swift4", "d1", vec![parse_disk_file("1785.1#0#d.data", 9)]),
            slot("primary", "swift1", "d1", vec![parse_disk_file("1785.1#1#d.data", 9)]),
            slot("primary", "swift2", "d1", vec![]),
        ];
        let c = census(&slots);
        assert_eq!(c.frags, vec![0, 1]);
        let h = verdict("en", &Shape { is_ec: true, k: 2, m: 1, replicas: 3 }, &c);
        assert_eq!(h.level, "at_risk");
        assert!(h.headline.contains("2 of 3"), "{}", h.headline);
    }

    #[test]
    fn ec_below_k_is_unreadable_not_merely_degraded() {
        let slots = vec![slot(
            "primary",
            "swift1",
            "d1",
            vec![parse_disk_file("1785.1#1#d.data", 9)],
        )];
        let h = verdict(
            "en",
            &Shape { is_ec: true, k: 2, m: 1, replicas: 3 },
            &census(&slots),
        );
        assert_eq!(h.level, "critical");
    }

    #[test]
    fn duplicate_fragment_indexes_do_not_inflate_the_count() {
        // Two nodes holding fragment #0 is one fragment, not two, and reading
        // it as two would report an unreadable object as healthy.
        let slots = vec![
            slot("primary", "swift1", "d1", vec![parse_disk_file("1785.1#0#d.data", 9)]),
            slot("handoff", "swift2", "d3", vec![parse_disk_file("1785.1#0#d.data", 9)]),
        ];
        let c = census(&slots);
        assert_eq!(c.frags, vec![0]);
        assert_eq!(c.on_handoff, 1);
        assert_eq!(
            verdict("en", &Shape { is_ec: true, k: 2, m: 1, replicas: 3 }, &c).level,
            "critical"
        );
    }

    #[test]
    fn an_older_version_is_not_a_copy_of_this_one() {
        let slots = vec![
            slot("primary", "swift1", "d1", vec![parse_disk_file("2000.0.data", 9)]),
            slot("primary", "swift3", "d3", vec![parse_disk_file("2000.0.data", 9)]),
            slot("primary", "swift4", "d2", vec![parse_disk_file("1000.0.data", 9)]),
        ];
        let c = census(&slots);
        assert_eq!(c.copies, 2);
        assert_eq!(c.stale, 1);
        assert_eq!(
            verdict("en", &Shape { is_ec: false, k: 0, m: 0, replicas: 3 }, &c).level,
            "degraded"
        );
    }

    #[test]
    fn all_three_replicas_present_is_the_healthy_case() {
        let slots = vec![
            slot("primary", "swift1", "d1", vec![parse_disk_file("2000.0.data", 9)]),
            slot("primary", "swift3", "d3", vec![parse_disk_file("2000.0.data", 9)]),
            slot("primary", "swift4", "d2", vec![parse_disk_file("2000.0.data", 9)]),
        ];
        let h = verdict(
            "en",
            &Shape { is_ec: false, k: 0, m: 0, replicas: 3 },
            &census(&slots),
        );
        assert_eq!(h.level, "ok");
    }

    #[test]
    fn one_replica_left_is_not_reported_as_merely_degraded() {
        let slots = vec![slot(
            "primary",
            "swift1",
            "d1",
            vec![parse_disk_file("2000.0.data", 9)],
        )];
        let h = verdict(
            "en",
            &Shape { is_ec: false, k: 0, m: 0, replicas: 3 },
            &census(&slots),
        );
        assert_eq!(h.level, "at_risk");
    }

    #[test]
    fn a_tombstone_reads_as_deleted_rather_than_lost() {
        let slots = vec![slot(
            "primary",
            "swift1",
            "d1",
            vec![parse_disk_file("2000.0.ts", 0)],
        )];
        let c = census(&slots);
        assert_eq!(c.tombstones, 1);
        assert_eq!(
            verdict("en", &Shape { is_ec: false, k: 0, m: 0, replicas: 3 }, &c).level,
            "deleted"
        );
    }

    #[test]
    fn an_unreachable_node_is_unknown_rather_than_empty() {
        let mut s = slot("primary", "swift2", "d1", vec![]);
        s.reachable = false;
        let slots = vec![
            slot("primary", "swift1", "d1", vec![parse_disk_file("2000.0.data", 9)]),
            slot("primary", "swift3", "d3", vec![parse_disk_file("2000.0.data", 9)]),
            s,
        ];
        let c = census(&slots);
        assert_eq!(c.unknown, 1);
        let h = verdict("en", &Shape { is_ec: false, k: 0, m: 0, replicas: 3 }, &c);
        assert!(h.detail.contains("floor"), "{}", h.detail);
    }

    fn read(status: u16, etag_matched: Option<bool>) -> ReadProbe {
        ReadProbe { status, etag_matched, ..Default::default() }
    }

    #[test]
    fn data_on_disk_plus_a_refused_read_is_a_service_fault_not_data_loss() {
        // The live EC case: k fragments present, and the cluster 503s anyway.
        // Saying "the object still reads" over that is the failure to avoid.
        let slots = vec![
            slot("primary", "swift4", "d1", vec![parse_disk_file("1785.1#0#d.data", 9)]),
            slot("primary", "swift1", "d1", vec![parse_disk_file("1785.1#1#d.data", 9)]),
        ];
        let (shape, c) = (Shape { is_ec: true, k: 2, m: 1, replicas: 3 }, census(&slots));
        let h = reconcile("en", verdict("en", &shape, &c), &shape, &c, &read(503, None));
        assert_eq!(h.level, "critical");
        assert!(h.headline.contains("503"), "{}", h.headline);
        assert!(h.detail.contains("service fault"), "{}", h.detail);
    }

    #[test]
    fn a_successful_read_leaves_the_disk_verdict_alone() {
        let slots = vec![
            slot("primary", "swift4", "d1", vec![parse_disk_file("1785.1#0#d.data", 9)]),
            slot("primary", "swift1", "d1", vec![parse_disk_file("1785.1#1#d.data", 9)]),
        ];
        let (shape, c) = (Shape { is_ec: true, k: 2, m: 1, replicas: 3 }, census(&slots));
        let h = reconcile("en", verdict("en", &shape, &c), &shape, &c, &read(200, Some(true)));
        assert_eq!(h.level, "at_risk", "a 200 must not paper over missing redundancy");
    }

    #[test]
    fn a_deleted_object_is_not_relabelled_by_its_own_404() {
        let slots = vec![slot("primary", "swift1", "d1", vec![parse_disk_file("2000.0.ts", 0)])];
        let (shape, c) = (Shape { is_ec: false, k: 0, m: 0, replicas: 3 }, census(&slots));
        let h = reconcile("en", verdict("en", &shape, &c), &shape, &c, &read(404, None));
        assert_eq!(h.level, "deleted");
    }

    #[test]
    fn a_digest_that_does_not_match_outranks_every_other_verdict() {
        let slots = vec![
            slot("primary", "swift1", "d1", vec![parse_disk_file("2000.0.data", 9)]),
            slot("primary", "swift3", "d3", vec![parse_disk_file("2000.0.data", 9)]),
            slot("primary", "swift4", "d2", vec![parse_disk_file("2000.0.data", 9)]),
        ];
        let (shape, c) = (Shape { is_ec: false, k: 0, m: 0, replicas: 3 }, census(&slots));
        let h = reconcile("en", verdict("en", &shape, &c), &shape, &c, &read(200, Some(false)));
        assert_eq!(h.level, "critical");
        assert!(h.headline.contains("ETag"), "{}", h.headline);
    }

    #[test]
    fn hash_directory_shards_on_the_last_three_characters() {
        assert_eq!(
            hash_dir("/srv/node/", "d2", "objects", 191, "2ff13b8c8cef5911465aef654828fa0f"),
            "/srv/node/d2/objects/191/a0f/2ff13b8c8cef5911465aef654828fa0f"
        );
    }

    #[test]
    fn the_session_account_comes_from_its_storage_url() {
        let sess = Session {
            token: String::new(),
            storage_url: "http://10.42.30.11:8085/v1/AUTH_test".into(),
            tenant: "test".into(),
            user: "tester".into(),
            key: String::new(),
            last_seen: Instant::now(),
            tempurl_default_secs: 0,
        };
        assert_eq!(session_account(&sess), "AUTH_test");
    }

    /// A reader on the Chinese console must not get an English verdict wrapped
    /// in a Chinese page. The sentences come from the key table, so this is the
    /// cheapest place to catch a hard-coded one.
    #[test]
    fn the_verdict_is_written_in_the_readers_language() {
        let slots = vec![
            slot("primary", "swift4", "d1", vec![parse_disk_file("1785.1#0#d.data", 9)]),
            slot("primary", "swift1", "d1", vec![parse_disk_file("1785.1#1#d.data", 9)]),
        ];
        let shape = Shape { is_ec: true, k: 2, m: 1, replicas: 3 };
        let c = census(&slots);
        let en = verdict("en", &shape, &c);
        let zh = verdict("zh", &shape, &c);
        assert_ne!(en.headline, zh.headline);
        assert_ne!(en.detail, zh.detail);
        assert_eq!(en.level, zh.level, "only the words change, never the finding");
        assert!(zh.headline.chars().any(|ch| ch as u32 > 0x2E80), "{}", zh.headline);
        assert!(
            !zh.detail.contains("fragment"),
            "an English word leaked into the Chinese verdict: {}",
            zh.detail
        );
    }
}
