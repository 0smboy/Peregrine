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

//! Agent-Native Object Warehouse: a per-job object workspace, exposed over MCP.
//!
//! A bucket answers "what is stored". A warehouse has to answer "where did this
//! come from" months after the run, from a machine that never saw this console.
//! So every fact the tool reports lives in object metadata beside the bytes —
//! the job that produced a file, the inputs it was derived from and their
//! ETags, the moment a scratch file is scheduled to vanish. Nothing here is
//! recoverable only from a console log, because a console log is exactly what
//! will not be there.
//!
//! Expiry is likewise delegated to the cluster (`X-Delete-After` on PUT) rather
//! than to a sweeper in this process: a tool that promises cleanup it performs
//! itself stops cleaning up the moment it is restarted.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use bytes::Bytes;
use serde_json::{json, Value};

use crate::util::{enc_obj, enc_seg, esc, fmt_bytes, now_secs, rand_hex};
use crate::{i18n, lab, search, swift, AppState};

/// One container holds the whole warehouse: jobs are a prefix, not a container
/// each. A container per job would put job count on the container ring and make
/// "list every job" an account listing that grows without bound.
pub const CONTAINER: &str = "warehouse";
const JOB_ROOT: &str = "jobs/";
const ROLES: [&str; 4] = ["inputs", "working", "artifacts", "report"];

const DEFAULT_TTL: u64 = 21_600; // 6h
const MIN_TTL: u64 = 60;
const MAX_TTL: u64 = 604_800; // 7d

/// Lineage needs one HEAD per object; past this the page would out-wait the
/// operator. Whatever is not headed is reported as unknown, never as absent.
const HEAD_CAP: usize = 200;
const GRAPH_JOBS: usize = 5;
const GRAPH_NODES: usize = 4;
const SAMPLE_CAP: u64 = 65_536;

const MCP_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

// ------------------------------------------------------------ tiny codecs

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Metadata values ride in HTTP headers, so a goal written in Chinese cannot go
/// in raw. Everything the warehouse stores is percent-encoded on the way in and
/// decoded on the way out; a plain ASCII value round-trips unchanged.
fn pct_dec(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hexval(b[i + 1]), hexval(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn pct_enc(s: &str) -> String {
    enc_seg(s)
}

/// A lineage list is one header, so the separator must be a byte that
/// percent-encoding guarantees never appears inside an element.
fn join_list(v: &[String]) -> String {
    v.iter().map(|s| pct_enc(s)).collect::<Vec<_>>().join("|")
}

fn split_list(s: &str) -> Vec<String> {
    if s.trim().is_empty() {
        return Vec::new();
    }
    s.split('|').filter(|p| !p.is_empty()).map(pct_dec).collect()
}

// ------------------------------------------------------------ time

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn fmt_utc(secs: u64) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let r = secs % 86_400;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        r / 3600,
        (r % 3600) / 60,
        r % 60
    )
}

/// A duration an operator would say out loud. Two units at most: "3 天 4 小时"
/// carries the decision, "3d 4h 12m 6s" carries arithmetic.
fn fmt_dur(lang: &str, secs: u64) -> String {
    let u = |k: &'static str| i18n::t(lang, k);
    let zh = lang == "zh";
    let sp = if zh { " " } else { "" };
    let (d, h, m, s) = (
        secs / 86_400,
        (secs % 86_400) / 3600,
        (secs % 3600) / 60,
        secs % 60,
    );
    let one = |n: u64, k: &'static str| format!("{}{}{}", n, sp, u(k));
    if d > 0 {
        if h > 0 {
            return format!("{} {}", one(d, "wh.u.d"), one(h, "wh.u.h"));
        }
        return one(d, "wh.u.d");
    }
    if h > 0 {
        if m > 0 {
            return format!("{} {}", one(h, "wh.u.h"), one(m, "wh.u.m"));
        }
        return one(h, "wh.u.h");
    }
    if m > 0 {
        return one(m, "wh.u.m");
    }
    one(s, "wh.u.s")
}

// ------------------------------------------------------------ model

#[derive(Clone)]
pub struct WhObj {
    pub path: String,
    pub name: String,
    pub job: String,
    pub role: String,
    pub bytes: u64,
    pub etag: String,
    pub content_type: String,
    pub last_modified: String,
    pub created: u64,
    pub producer: String,
    pub inputs: Vec<String>,
    pub input_etags: Vec<String>,
    pub promoted_from: String,
    pub promoted_at: u64,
    pub delete_at: Option<u64>,
    /// False when the scan hit its HEAD budget: the lineage fields below are
    /// then unknown, not empty, and the report has to say so.
    pub headed: bool,
}

#[derive(Clone, Default)]
pub struct Job {
    pub id: String,
    pub created: u64,
    pub goal: String,
    pub agent: String,
    pub ttl: u64,
    pub inputs: Vec<WhObj>,
    pub working: Vec<WhObj>,
    pub artifacts: Vec<WhObj>,
    pub reports: Vec<WhObj>,
    pub bytes: u64,
    pub layout_dirs: usize,
    pub manifest: bool,
}

impl Job {
    fn state(&self) -> &'static str {
        if !self.artifacts.is_empty() {
            "published"
        } else if !self.working.is_empty() {
            "working"
        } else if !self.inputs.is_empty() {
            "staged"
        } else {
            "empty"
        }
    }
    fn objects(&self) -> usize {
        self.inputs.len() + self.working.len() + self.artifacts.len() + self.reports.len()
    }
}

pub struct Report {
    pub exists: bool,
    pub policy: String,
    pub jobs: Vec<Job>,
    pub total_bytes: u64,
    pub total_objects: usize,
    pub head_capped: bool,
    pub scanned_at: u64,
    pub error: Option<String>,
}

/// `jobs/<job>/<role>/<name>`; a trailing empty segment is one of the layout
/// marker objects rather than a file.
fn parse_path(p: &str) -> Option<(String, String, String)> {
    let rest = p.strip_prefix(JOB_ROOT)?;
    let mut it = rest.splitn(3, '/');
    let job = it.next()?.to_string();
    if job.is_empty() {
        return None;
    }
    let role = it.next().unwrap_or("").to_string();
    let name = it.next().unwrap_or("").to_string();
    Some((job, role, name))
}

fn job_dir(job: &str) -> String {
    format!("{}{}/", JOB_ROOT, job)
}

fn obj_path(job: &str, role: &str, name: &str) -> String {
    format!("{}{}/{}/{}", JOB_ROOT, job, role, name)
}

fn valid_leaf(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 200
        && !name.contains('/')
        && !name.starts_with('.')
        && name.chars().all(|c| !c.is_control())
}

fn valid_job_id(id: &str) -> bool {
    id.starts_with("job-")
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn clamp_ttl(v: u64) -> u64 {
    v.clamp(MIN_TTL, MAX_TTL)
}

// ------------------------------------------------------------ swift helpers

fn hv(h: &reqwest::header::HeaderMap, k: &str) -> String {
    h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

fn meta(h: &reqwest::header::HeaderMap, k: &str) -> String {
    pct_dec(&hv(h, &format!("x-object-meta-{k}")))
}

fn meta_u64(h: &reqwest::header::HeaderMap, k: &str) -> u64 {
    meta(h, k).parse().unwrap_or(0)
}

/// Lineage headers for a warehouse write. Every writer goes through this, so a
/// file can never land carrying half a provenance record.
fn lineage_headers(
    job: &str,
    role: &str,
    producer: &str,
    inputs: &[String],
    input_etags: &[String],
) -> Vec<(String, String)> {
    let mut hs = vec![
        ("X-Object-Meta-Wh-Job".to_string(), pct_enc(job)),
        ("X-Object-Meta-Wh-Role".to_string(), role.to_string()),
        ("X-Object-Meta-Wh-Created".to_string(), now_secs().to_string()),
        ("X-Object-Meta-Wh-Producer".to_string(), pct_enc(producer)),
    ];
    if !inputs.is_empty() {
        hs.push(("X-Object-Meta-Wh-Inputs".into(), join_list(inputs)));
    }
    if !input_etags.is_empty() {
        hs.push(("X-Object-Meta-Wh-Input-Etags".into(), join_list(input_etags)));
    }
    hs
}

async fn ensure_container(state: &Arc<AppState>, sid: &str) -> Result<u16, String> {
    let sub = format!("/{}", enc_seg(CONTAINER));
    match swift::call(state, sid, reqwest::Method::PUT, &sub, &[], &[], None).await {
        Ok(r) => Ok(r.status().as_u16()),
        Err(e) => Err(e.msg()),
    }
}

async fn put_obj(
    state: &Arc<AppState>,
    sid: &str,
    path: &str,
    ctype: &str,
    extra: Vec<(String, String)>,
    body: Bytes,
) -> Result<u16, String> {
    let sub = swift::obj_subpath(CONTAINER, path);
    let mut hs = extra;
    hs.push(("Content-Type".into(), ctype.into()));
    match swift::call(state, sid, reqwest::Method::PUT, &sub, &[], &hs, Some(body)).await {
        Ok(r) => {
            let st = r.status().as_u16();
            if st < 300 {
                Ok(st)
            } else {
                Err(format!("PUT {path} -> {st}"))
            }
        }
        Err(e) => Err(e.msg()),
    }
}

async fn head_obj(
    state: &Arc<AppState>,
    sid: &str,
    path: &str,
) -> Result<(u16, reqwest::header::HeaderMap), String> {
    swift::head(state, sid, &swift::obj_subpath(CONTAINER, path))
        .await
        .map_err(|e| e.msg())
}

async fn get_range(
    state: &Arc<AppState>,
    sid: &str,
    path: &str,
    upto: u64,
) -> Result<(u16, reqwest::header::HeaderMap, Bytes), String> {
    let sub = swift::obj_subpath(CONTAINER, path);
    let hs = vec![("Range".to_string(), format!("bytes=0-{}", upto.saturating_sub(1)))];
    match swift::call(state, sid, reqwest::Method::GET, &sub, &[], &hs, None).await {
        Ok(r) => {
            let st = r.status().as_u16();
            let h = r.headers().clone();
            let b = r.bytes().await.unwrap_or_default();
            Ok((st, h, b))
        }
        Err(e) => Err(e.msg()),
    }
}

/// Read an object's lineage back out of the store. This is the function that
/// proves the design claim: it takes a path and nothing else, and it never
/// consults console state.
fn obj_from_head(path: &str, h: &reqwest::header::HeaderMap) -> WhObj {
    let (job, role, name) = parse_path(path)
        .unwrap_or_else(|| (String::new(), String::new(), path.to_string()));
    WhObj {
        path: path.to_string(),
        name,
        job: {
            let m = meta(h, "wh-job");
            if m.is_empty() { job } else { m }
        },
        role: {
            let m = meta(h, "wh-role");
            if m.is_empty() { role } else { m }
        },
        bytes: hv(h, "content-length").parse().unwrap_or(0),
        etag: hv(h, "etag").trim_matches('"').to_string(),
        content_type: hv(h, "content-type"),
        last_modified: hv(h, "last-modified"),
        created: meta_u64(h, "wh-created"),
        producer: meta(h, "wh-producer"),
        inputs: split_list(&hv(h, "x-object-meta-wh-inputs")),
        input_etags: split_list(&hv(h, "x-object-meta-wh-input-etags")),
        promoted_from: meta(h, "wh-promoted-from"),
        promoted_at: meta_u64(h, "wh-promoted-at"),
        delete_at: hv(h, "x-delete-at").parse().ok(),
        headed: true,
    }
}

// ------------------------------------------------------------ scan

/// Build the whole report from the store: one container listing plus a bounded
/// number of HEADs. No console-side bookkeeping is consulted anywhere in here,
/// which is the point — restart the console, or run this against a warehouse
/// some other agent wrote, and the answer is the same.
pub async fn scan(state: &Arc<AppState>, sid: &str) -> Report {
    let mut rep = Report {
        exists: false,
        policy: String::new(),
        jobs: Vec::new(),
        total_bytes: 0,
        total_objects: 0,
        head_capped: false,
        scanned_at: now_secs(),
        error: None,
    };

    match swift::head(state, sid, &format!("/{}", enc_seg(CONTAINER))).await {
        Ok((st, h)) if st < 300 => {
            rep.exists = true;
            rep.policy = hv(&h, "x-storage-policy");
        }
        Ok(_) => return rep,
        Err(e) => {
            rep.error = Some(e.msg());
            return rep;
        }
    }

    let listing = match swift::list_objects(state, sid, CONTAINER, JOB_ROOT, true, 20_000).await {
        Ok(l) => l,
        Err(e) => {
            rep.error = Some(e.msg());
            return rep;
        }
    };

    // Listing first, HEADs second: the listing is one request and already
    // carries size and ETag, so the HEAD budget is spent only on lineage.
    let mut order: Vec<String> = Vec::new();
    let mut jobs: HashMap<String, Job> = HashMap::new();
    let mut pending: Vec<(String, String, String, WhObj)> = Vec::new();

    for f in &listing.files {
        let path = match &f.name {
            Some(n) => n.clone(),
            None => continue,
        };
        let (job_id, role, name) = match parse_path(&path) {
            Some(v) => v,
            None => continue,
        };
        let j = jobs.entry(job_id.clone()).or_insert_with(|| {
            order.push(job_id.clone());
            Job {
                id: job_id.clone(),
                ttl: DEFAULT_TTL,
                ..Default::default()
            }
        });
        if name.is_empty() {
            // A layout marker, not a file. Counting these as content would make
            // an empty job look populated.
            if !role.is_empty() && ROLES.contains(&role.as_str()) {
                j.layout_dirs += 1;
            }
            continue;
        }
        let o = WhObj {
            path: path.clone(),
            name: name.clone(),
            job: job_id.clone(),
            role: role.clone(),
            bytes: f.bytes,
            etag: f.hash.clone().unwrap_or_default(),
            content_type: f.content_type.clone().unwrap_or_default(),
            last_modified: f.last_modified.clone().unwrap_or_default(),
            created: 0,
            producer: String::new(),
            inputs: Vec::new(),
            input_etags: Vec::new(),
            promoted_from: String::new(),
            promoted_at: 0,
            delete_at: None,
            headed: false,
        };
        j.bytes += f.bytes;
        rep.total_bytes += f.bytes;
        rep.total_objects += 1;
        pending.push((job_id, role, name, o));
    }

    // Newest job first, and the HEAD budget spent on the newest — those are the
    // rows an operator is actually looking at.
    order.sort();
    order.reverse();
    let rank: HashMap<&String, usize> = order.iter().enumerate().map(|(i, s)| (s, i)).collect();
    pending.sort_by_key(|(j, ..)| *rank.get(j).unwrap_or(&usize::MAX));

    let mut headed = 0usize;
    for (job_id, role, _name, mut o) in pending {
        if headed < HEAD_CAP {
            headed += 1;
            if let Ok((st, h)) = head_obj(state, sid, &o.path).await {
                if st < 300 {
                    let listed_bytes = o.bytes;
                    o = obj_from_head(&o.path, &h);
                    // The listing is authoritative for size; a HEAD of a
                    // just-written object can race the container update.
                    if o.bytes == 0 && listed_bytes > 0 {
                        o.bytes = listed_bytes;
                    }
                }
            }
        } else {
            rep.head_capped = true;
        }
        if let Some(j) = jobs.get_mut(&job_id) {
            match role.as_str() {
                "inputs" => j.inputs.push(o),
                "working" => j.working.push(o),
                "artifacts" => j.artifacts.push(o),
                "report" => j.reports.push(o),
                _ => {}
            }
        }
    }

    // Job-level facts live on the manifest, which is a report/ object like any
    // other, so they survive exactly as long as the job's own data does.
    for id in &order {
        if let Some(j) = jobs.get_mut(id) {
            j.created = id
                .split('-')
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            for r in &j.reports {
                if r.name == "manifest.json" && r.headed {
                    j.manifest = true;
                }
            }
            j.inputs.sort_by(|a, b| a.name.cmp(&b.name));
            j.working.sort_by(|a, b| a.name.cmp(&b.name));
            j.artifacts.sort_by(|a, b| a.name.cmp(&b.name));
            j.reports.sort_by(|a, b| a.name.cmp(&b.name));
        }
    }

    // The manifest body carries goal/agent/ttl. One extra GET per job, only for
    // the jobs the graph and the table actually show.
    for id in order.iter().take(GRAPH_JOBS.max(12)) {
        let path = obj_path(id, "report", "manifest.json");
        let has = jobs.get(id).map(|j| j.manifest).unwrap_or(false);
        if !has {
            continue;
        }
        if let Ok((st, _h, b)) = get_range(state, sid, &path, 8192).await {
            if st < 300 {
                if let Ok(v) = serde_json::from_slice::<Value>(&b) {
                    if let Some(j) = jobs.get_mut(id) {
                        j.goal = v.get("goal").and_then(|x| x.as_str()).unwrap_or("").to_string();
                        j.agent = v.get("agent").and_then(|x| x.as_str()).unwrap_or("").to_string();
                        j.ttl = v.get("ttl_seconds").and_then(|x| x.as_u64()).unwrap_or(DEFAULT_TTL);
                    }
                }
            }
        }
    }

    rep.jobs = order.into_iter().filter_map(|id| jobs.remove(&id)).collect();
    rep
}

// ------------------------------------------------------------ mutations

struct CreateArgs {
    goal: String,
    agent: String,
    ttl: u64,
    inputs: Vec<(String, String)>,
}

/// Create the job layout for real: the four directories exist as objects, the
/// manifest is written, and both are read back before this returns. A layout
/// that is only a naming convention is a layout that the next tool gets wrong.
async fn do_create(
    state: &Arc<AppState>,
    sid: &str,
    a: CreateArgs,
) -> Result<Value, String> {
    let container_status = ensure_container(state, sid).await?;
    let id = format!("job-{}-{}", now_secs(), rand_hex(3));
    let ttl = clamp_ttl(a.ttl);

    let mut dirs = Vec::new();
    for role in ROLES {
        let p = format!("{}{}/", job_dir(&id), role);
        let hs = lineage_headers(&id, "layout", &a.agent, &[], &[]);
        put_obj(state, sid, &p, "application/directory", hs, Bytes::new()).await?;
        dirs.push(p);
    }

    let manifest = json!({
        "job": id,
        "created": now_secs(),
        "created_utc": fmt_utc(now_secs()),
        "goal": a.goal,
        "agent": a.agent,
        "ttl_seconds": ttl,
        "layout": {
            "inputs": obj_path(&id, "inputs", ""),
            "working": obj_path(&id, "working", ""),
            "artifacts": obj_path(&id, "artifacts", ""),
            "report": obj_path(&id, "report", ""),
        },
        "rules": {
            "working": "expires via X-Delete-At set by the cluster",
            "artifacts": "persists; carries the inputs it was derived from",
            "report": "persists",
        }
    });
    let mpath = obj_path(&id, "report", "manifest.json");
    let mut mh = lineage_headers(&id, "manifest", &a.agent, &[], &[]);
    mh.push(("X-Object-Meta-Wh-Goal".into(), pct_enc(&a.goal)));
    mh.push(("X-Object-Meta-Wh-Agent".into(), pct_enc(&a.agent)));
    mh.push(("X-Object-Meta-Wh-Ttl".into(), ttl.to_string()));
    put_obj(
        state,
        sid,
        &mpath,
        "application/json",
        mh,
        Bytes::from(serde_json::to_vec(&manifest).unwrap_or_default()),
    )
    .await?;

    let mut seeded = Vec::new();
    for (name, content) in &a.inputs {
        if !valid_leaf(name) {
            return Err(format!("bad input name: {name}"));
        }
        let p = obj_path(&id, "inputs", name);
        let hs = lineage_headers(&id, "input", &a.agent, &[], &[]);
        put_obj(state, sid, &p, guess_ctype(name), hs, Bytes::from(content.clone().into_bytes())).await?;
        let (_st, h) = head_obj(state, sid, &p).await?;
        seeded.push(json!({
            "path": p,
            "bytes": hv(&h, "content-length").parse::<u64>().unwrap_or(0),
            "etag": hv(&h, "etag").trim_matches('"'),
        }));
    }

    // Read back rather than assume: the evidence returned here is what the
    // cluster says exists, not what this function believes it wrote.
    let (mst, mh2) = head_obj(state, sid, &mpath).await?;
    let (dst, dh2) = head_obj(state, sid, &format!("{}working/", job_dir(&id))).await?;

    Ok(json!({
        "job": id,
        "created_utc": fmt_utc(now_secs()),
        "ttl_seconds": ttl,
        "container": CONTAINER,
        "container_status": container_status,
        "layout": dirs,
        "verified": {
            "manifest_status": mst,
            "manifest_job_meta": meta(&mh2, "wh-job"),
            "working_dir_status": dst,
            "working_dir_content_type": hv(&dh2, "content-type"),
        },
        "inputs": seeded,
    }))
}

fn guess_ctype(name: &str) -> &'static str {
    let n = name.to_ascii_lowercase();
    if n.ends_with(".json") {
        "application/json"
    } else if n.ends_with(".csv") {
        "text/csv"
    } else if n.ends_with(".ndjson") || n.ends_with(".jsonl") {
        "application/x-ndjson"
    } else if n.ends_with(".txt") || n.ends_with(".md") || n.ends_with(".log") {
        "text/plain"
    } else {
        "application/octet-stream"
    }
}

struct WriteArgs {
    job: String,
    name: String,
    content: String,
    inputs: Vec<String>,
    producer: String,
    ttl: u64,
}

/// A working file is scratch by construction: the expiry is set on the write,
/// and then read back. If the cluster did not honour it the caller is told so
/// in the same response, because a TTL nobody checked is a TTL nobody has.
async fn do_write_working(
    state: &Arc<AppState>,
    sid: &str,
    a: WriteArgs,
) -> Result<Value, String> {
    if !valid_job_id(&a.job) {
        return Err("bad job id".into());
    }
    if !valid_leaf(&a.name) {
        return Err("bad file name".into());
    }
    let ttl = clamp_ttl(a.ttl);

    // Inputs are recorded with the ETag they had at derivation time, so a later
    // reader can tell "derived from this file" from "derived from what this
    // file used to be".
    let mut etags = Vec::new();
    for i in &a.inputs {
        match head_obj(state, sid, i).await {
            Ok((st, h)) if st < 300 => etags.push(hv(&h, "etag").trim_matches('"').to_string()),
            _ => etags.push("unknown".into()),
        }
    }

    let path = obj_path(&a.job, "working", &a.name);
    let mut hs = lineage_headers(&a.job, "working", &a.producer, &a.inputs, &etags);
    hs.push(("X-Delete-After".into(), ttl.to_string()));
    let st = put_obj(
        state,
        sid,
        &path,
        guess_ctype(&a.name),
        hs,
        Bytes::from(a.content.into_bytes()),
    )
    .await?;

    let (_hst, h) = head_obj(state, sid, &path).await?;
    let delete_at: Option<u64> = hv(&h, "x-delete-at").parse().ok();
    Ok(json!({
        "path": path,
        "status": st,
        "bytes": hv(&h, "content-length").parse::<u64>().unwrap_or(0),
        "etag": hv(&h, "etag").trim_matches('"'),
        "requested_ttl_seconds": ttl,
        "expiry_verified": delete_at.is_some(),
        "expires_at": delete_at,
        "expires_at_utc": delete_at.map(fmt_utc),
        "expiry_note": if delete_at.is_some() {
            "read back from the stored object, not assumed"
        } else {
            "the cluster returned no expiry for this object; treat it as permanent"
        },
        "lineage": {
            "job": meta(&h, "wh-job"),
            "role": meta(&h, "wh-role"),
            "producer": meta(&h, "wh-producer"),
            "inputs": split_list(&hv(&h, "x-object-meta-wh-inputs")),
            "input_etags": split_list(&hv(&h, "x-object-meta-wh-input-etags")),
        }
    }))
}

struct PromoteArgs {
    job: String,
    name: String,
    dest: String,
    ttl: Option<u64>,
}

/// Promotion is a server-side copy with a rewritten metadata set: the bytes
/// never travel through this process, the expiry is dropped, and the lineage is
/// re-stated explicitly rather than inherited, so a promoted artifact is
/// readable on its own terms.
async fn do_promote(
    state: &Arc<AppState>,
    sid: &str,
    a: PromoteArgs,
) -> Result<Value, String> {
    if !valid_job_id(&a.job) {
        return Err("bad job id".into());
    }
    if !valid_leaf(&a.name) {
        return Err("bad file name".into());
    }
    let dest = if a.dest.trim().is_empty() { a.name.clone() } else { a.dest.clone() };
    if !valid_leaf(&dest) {
        return Err("bad destination name".into());
    }

    let src = obj_path(&a.job, "working", &a.name);
    let dst = obj_path(&a.job, "artifacts", &dest);
    let (sst, sh) = head_obj(state, sid, &src).await?;
    if sst >= 300 {
        return Err(format!("no working file at {src} ({sst})"));
    }
    let src_obj = obj_from_head(&src, &sh);

    let mut hs = lineage_headers(
        &a.job,
        "artifact",
        &src_obj.producer,
        &src_obj.inputs,
        &src_obj.input_etags,
    );
    hs.push(("X-Object-Meta-Wh-Promoted-From".into(), pct_enc(&src)));
    hs.push(("X-Object-Meta-Wh-Promoted-At".into(), now_secs().to_string()));
    hs.push(("X-Object-Meta-Wh-Source-Etag".into(), src_obj.etag.clone()));
    if let Some(t) = a.ttl {
        hs.push(("X-Delete-After".into(), clamp_ttl(t).to_string()));
    }

    let mut copy_hs = hs.clone();
    copy_hs.push((
        "X-Copy-From".into(),
        format!("/{}/{}", CONTAINER, enc_obj(&src)),
    ));
    // Fresh metadata is what drops the source's expiry; without it a promoted
    // artifact would inherit the countdown it was promoted to escape.
    copy_hs.push(("X-Fresh-Metadata".into(), "true".into()));
    let ctype = if src_obj.content_type.is_empty() {
        guess_ctype(&dest).to_string()
    } else {
        src_obj.content_type.clone()
    };

    let mut mode = "server-side copy";
    if put_obj(state, sid, &dst, &ctype, copy_hs, Bytes::new()).await.is_err() {
        // Fall back to reading the bytes back through the console. Slower and
        // it moves the data twice, so the caller is told which path ran.
        mode = "read-back copy";
        let (gst, _gh, body) = get_range(state, sid, &src, src_obj.bytes.max(1)).await?;
        if gst >= 300 {
            return Err(format!("cannot read {src} ({gst})"));
        }
        put_obj(state, sid, &dst, &ctype, hs, body).await?;
    }

    let (dst_st, dh) = head_obj(state, sid, &dst).await?;
    let art = obj_from_head(&dst, &dh);
    let record = json!({
        "artifact": dst,
        "promoted_from": src,
        "promoted_at": now_secs(),
        "promoted_at_utc": fmt_utc(now_secs()),
        "etag": art.etag,
        "bytes": art.bytes,
        "inputs": art.inputs,
        "input_etags": art.input_etags,
        "producer": art.producer,
        "copy_mode": mode,
    });
    let lineage_file = append_lineage(state, sid, &a.job, &record).await;

    Ok(json!({
        "artifact": dst,
        "status": dst_st,
        "copy_mode": mode,
        "bytes_moved_through_console": if mode == "server-side copy" { 0 } else { src_obj.bytes },
        "integrity": {
            "source_etag": src_obj.etag,
            "artifact_etag": art.etag,
            "etag_match": !art.etag.is_empty() && art.etag == src_obj.etag,
        },
        "expiry": {
            "source_expires_at": src_obj.delete_at,
            "artifact_expires_at": art.delete_at,
            "artifact_expires_at_utc": art.delete_at.map(fmt_utc),
            "note": if art.delete_at.is_some() {
                "this artifact was published with a TTL and will be removed by the cluster"
            } else {
                "no expiry on the artifact: it persists until deleted"
            },
        },
        "lineage": {
            "job": art.job,
            "role": art.role,
            "producer": art.producer,
            "inputs": art.inputs,
            "input_etags": art.input_etags,
            "promoted_from": art.promoted_from,
            "promoted_at_utc": fmt_utc(art.promoted_at),
        },
        "lineage_record": lineage_file,
    }))
}

/// A second, human-readable home for provenance inside the job's own report/.
/// The metadata on the object is authoritative; this is the copy someone can
/// read without a HEAD request.
async fn append_lineage(
    state: &Arc<AppState>,
    sid: &str,
    job: &str,
    record: &Value,
) -> Value {
    let path = obj_path(job, "report", "lineage.json");
    let mut arr: Vec<Value> = match get_range(state, sid, &path, 262_144).await {
        Ok((st, _h, b)) if st < 300 => serde_json::from_slice(&b).unwrap_or_default(),
        _ => Vec::new(),
    };
    arr.push(record.clone());
    let hs = lineage_headers(job, "report", "warehouse", &[], &[]);
    match put_obj(
        state,
        sid,
        &path,
        "application/json",
        hs,
        Bytes::from(serde_json::to_vec_pretty(&arr).unwrap_or_default()),
    )
    .await
    {
        Ok(_) => json!({ "path": path, "entries": arr.len() }),
        Err(e) => json!({ "path": path, "error": e }),
    }
}

// ------------------------------------------------------------ MCP

/// The tool table is declared once and read twice: by `tools/list` for the
/// agent, and by the page for the operator wiring the agent up. Two lists would
/// drift, and the page would start documenting tools that no longer exist.
pub const MCP_TOOLS: [(&str, &str); 7] = [
    ("datasets_list", "wh.t.datasets"),
    ("object_describe", "wh.t.describe"),
    ("metadata_search", "wh.t.search"),
    ("object_sample", "wh.t.sample"),
    ("job_create", "wh.t.job"),
    ("result_write", "wh.t.result"),
    ("artifact_publish", "wh.t.publish"),
];

fn prop(ty: &str, desc: &str) -> Value {
    json!({ "type": ty, "description": desc })
}

fn tool_schema(name: &str) -> Value {
    match name {
        "datasets_list" => json!({
            "type": "object",
            "properties": {
                "include_jobs": prop("boolean", "Also list warehouse jobs and what each produced."),
            },
            "required": [],
        }),
        "object_describe" => json!({
            "type": "object",
            "properties": {
                "container": prop("string", "Dataset (container) name."),
                "object": prop("string", "Object path inside the dataset."),
            },
            "required": ["container", "object"],
        }),
        "metadata_search" => json!({
            "type": "object",
            "properties": {
                "query": prop("string", "Substring matched against the object name."),
                "container": prop("string", "Restrict to one dataset."),
                "content_type": prop("string", "Substring matched against the content type."),
                "meta_key": prop("string", "Custom metadata key to match (without the vendor prefix)."),
                "meta_value": prop("string", "Value the metadata must contain."),
                "min_bytes": prop("integer", "Smallest object size to return."),
                "max_bytes": prop("integer", "Largest object size to return."),
                "limit": prop("integer", "Maximum hits to return (default 50, cap 200)."),
                "rebuild_index": prop("boolean", "Force a fresh crawl before searching."),
            },
            "required": [],
        }),
        "object_sample" => json!({
            "type": "object",
            "properties": {
                "container": prop("string", "Dataset (container) name."),
                "object": prop("string", "Object path inside the dataset."),
                "bytes": prop("integer", "How many leading bytes to read (default 4096, cap 65536)."),
                "lines": prop("integer", "Return at most this many lines from the sampled bytes."),
            },
            "required": ["container", "object"],
        }),
        "job_create" => json!({
            "type": "object",
            "properties": {
                "goal": prop("string", "What this job is for, in one sentence."),
                "agent": prop("string", "Which agent is running it."),
                "ttl_seconds": prop("integer", "How long working files live (60..604800, default 21600)."),
                "inputs": json!({
                    "type": "array",
                    "description": "Optional input files to stage into inputs/.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": prop("string", "File name inside inputs/."),
                            "content": prop("string", "File body as text."),
                        },
                        "required": ["name", "content"],
                    }
                }),
            },
            "required": ["goal"],
        }),
        "result_write" => json!({
            "type": "object",
            "properties": {
                "job": prop("string", "Job id returned by job_create."),
                "name": prop("string", "File name inside working/."),
                "content": prop("string", "File body as text."),
                "inputs": json!({
                    "type": "array",
                    "description": "Warehouse paths this result was derived from; their ETags are recorded.",
                    "items": { "type": "string" }
                }),
                "producer": prop("string", "What produced it (agent, model, step name)."),
                "ttl_seconds": prop("integer", "Override the job's working TTL."),
            },
            "required": ["job", "name", "content"],
        }),
        "artifact_publish" => json!({
            "type": "object",
            "properties": {
                "job": prop("string", "Job id."),
                "name": prop("string", "Working file to publish."),
                "dest_name": prop("string", "Name under artifacts/ (defaults to the working name)."),
                "ttl_seconds": prop("integer", "Optional expiry for the artifact; omit to keep it permanent."),
            },
            "required": ["job", "name"],
        }),
        _ => json!({ "type": "object", "properties": {}, "required": [] }),
    }
}

fn mcp_tool_list(lang: &str) -> Vec<Value> {
    MCP_TOOLS
        .iter()
        .map(|(name, key)| {
            json!({
                "name": name,
                "description": i18n::t(lang, key),
                "inputSchema": tool_schema(name),
            })
        })
        .collect()
}

fn rpc_ok(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_err(id: &Value, code: i32, msg: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": msg } })
}

/// A tool that failed is a result, not a transport error: the agent has to be
/// able to read what went wrong and try something else.
fn tool_result(text: String, structured: Option<Value>, is_error: bool) -> Value {
    let mut v = json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error,
    });
    if let Some(s) = structured {
        v["structuredContent"] = s;
    }
    v
}

fn tool_ok(structured: Value) -> Value {
    let text = serde_json::to_string_pretty(&structured).unwrap_or_default();
    tool_result(text, Some(structured), false)
}

fn tool_fail(msg: &str) -> Value {
    tool_result(msg.to_string(), None, true)
}

fn arg_str(a: &Value, k: &str) -> String {
    a.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn arg_u64(a: &Value, k: &str) -> Option<u64> {
    match a.get(k) {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.parse().ok(),
        _ => None,
    }
}

fn arg_bool(a: &Value, k: &str) -> bool {
    match a.get(k) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => matches!(s.as_str(), "1" | "true" | "yes" | "on"),
        _ => false,
    }
}

fn arg_strs(a: &Value, k: &str) -> Vec<String> {
    match a.get(k) {
        Some(Value::Array(v)) => v
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
        Some(Value::String(s)) if !s.trim().is_empty() => {
            s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect()
        }
        _ => Vec::new(),
    }
}

/// Column names and a guessed type per column, read from the first few KiB.
/// Explicitly a guess: it is labelled as one in the payload so an agent does
/// not plan a join on an inference this made from two rows.
fn sniff_schema(name: &str, ctype: &str, body: &[u8]) -> Value {
    let text = String::from_utf8_lossy(body);
    let lower = format!("{} {}", name.to_ascii_lowercase(), ctype.to_ascii_lowercase());
    let type_of = |s: &str| -> &'static str {
        let t = s.trim().trim_matches('"');
        if t.is_empty() {
            "empty"
        } else if t.parse::<i64>().is_ok() {
            "integer"
        } else if t.parse::<f64>().is_ok() {
            "number"
        } else if matches!(t.to_ascii_lowercase().as_str(), "true" | "false") {
            "boolean"
        } else {
            "text"
        }
    };
    if lower.contains("csv") {
        let mut lines = text.lines();
        let header: Vec<&str> = match lines.next() {
            Some(h) => h.split(',').map(|s| s.trim()).collect(),
            None => return json!({ "kind": "csv", "columns": [], "note": "the file is empty" }),
        };
        let sample: Vec<&str> = lines.next().map(|l| l.split(',').collect()).unwrap_or_default();
        let cols: Vec<Value> = header
            .iter()
            .enumerate()
            .map(|(i, h)| {
                json!({
                    "name": h,
                    "type_guess": sample.get(i).map(|s| type_of(s)).unwrap_or("unknown"),
                })
            })
            .collect();
        return json!({
            "kind": "csv",
            "columns": cols,
            "rows_in_sample": text.lines().count().saturating_sub(1),
            "note": "types are inferred from the first data row of the sampled bytes, not from the whole object",
        });
    }
    if lower.contains("ndjson") || lower.contains("jsonl") {
        if let Some(first) = text.lines().next() {
            if let Ok(v) = serde_json::from_str::<Value>(first) {
                if let Some(o) = v.as_object() {
                    let cols: Vec<Value> = o
                        .iter()
                        .map(|(k, x)| json!({ "name": k, "type_guess": json_kind(x) }))
                        .collect();
                    return json!({ "kind": "ndjson", "columns": cols, "note": "read from the first record only" });
                }
            }
        }
        return json!({ "kind": "ndjson", "columns": [], "note": "the first line did not parse as an object" });
    }
    if lower.contains("json") {
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            return json!({ "kind": "json", "top_level": json_kind(&v), "keys": json_keys(&v) });
        }
        return json!({
            "kind": "json",
            "note": "the sampled prefix is not a complete JSON document, so no schema was read",
        });
    }
    json!({
        "kind": if text.chars().any(|c| c == '\u{fffd}') { "binary" } else { "text" },
        "note": "no schema is inferred for this content type",
    })
}

fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                "integer"
            } else {
                "number"
            }
        }
        Value::String(_) => "text",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn json_keys(v: &Value) -> Vec<String> {
    match v {
        Value::Object(o) => o.keys().cloned().collect(),
        Value::Array(a) => a
            .first()
            .and_then(|f| f.as_object())
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

async fn call_tool(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    sid: &str,
    tenant: &str,
    name: &str,
    a: &Value,
) -> Value {
    match name {
        "datasets_list" => {
            let buckets = match swift::list_buckets(state, sid).await {
                Ok(b) => b,
                Err(e) => return tool_fail(&e.msg()),
            };
            let sets: Vec<Value> = buckets
                .iter()
                .filter(|b| !b.name.ends_with("_segments"))
                .map(|b| json!({ "dataset": b.name, "objects": b.count, "bytes": b.bytes, "bytes_human": fmt_bytes(b.bytes) }))
                .collect();
            let mut out = json!({ "datasets": sets, "warehouse_container": CONTAINER });
            if arg_bool(a, "include_jobs") {
                let rep = scan(state, sid).await;
                let jobs: Vec<Value> = rep
                    .jobs
                    .iter()
                    .map(|j| {
                        json!({
                            "job": j.id,
                            "state": j.state(),
                            "goal": j.goal,
                            "created_utc": fmt_utc(j.created),
                            "inputs": j.inputs.iter().map(|o| &o.path).collect::<Vec<_>>(),
                            "working": j.working.len(),
                            "artifacts": j.artifacts.iter().map(|o| &o.path).collect::<Vec<_>>(),
                            "bytes": j.bytes,
                        })
                    })
                    .collect();
                out["jobs"] = Value::Array(jobs);
            }
            tool_ok(out)
        }
        "object_describe" => {
            let (c, o) = (arg_str(a, "container"), arg_str(a, "object"));
            if c.is_empty() || o.is_empty() {
                return tool_fail("container and object are both required");
            }
            let sub = swift::obj_subpath(&c, &o);
            let (st, h) = match swift::head(state, sid, &sub).await {
                Ok(v) => v,
                Err(e) => return tool_fail(&e.msg()),
            };
            if st >= 300 {
                return tool_fail(&format!("{c}/{o} is not readable ({st})"));
            }
            let bytes: u64 = hv(&h, "content-length").parse().unwrap_or(0);
            let ctype = hv(&h, "content-type");
            let mut custom = BTreeMap::new();
            for (k, v) in h.iter() {
                let kn = k.as_str().to_ascii_lowercase();
                if let Some(mk) = kn.strip_prefix("x-object-meta-") {
                    custom.insert(mk.to_string(), pct_dec(v.to_str().unwrap_or("")));
                }
            }
            // A schema read must never cost the whole object: 8 KiB off the
            // front is enough for a header row and the first record.
            let sample_n = bytes.clamp(1, 8192);
            let rhs = vec![("Range".to_string(), format!("bytes=0-{}", sample_n - 1))];
            let schema = match swift::call(state, sid, reqwest::Method::GET, &sub, &[], &rhs, None).await {
                Ok(r) => {
                    let b = r.bytes().await.unwrap_or_default();
                    sniff_schema(&o, &ctype, &b)
                }
                Err(e) => json!({ "kind": "unknown", "note": e.msg() }),
            };
            let delete_at: Option<u64> = hv(&h, "x-delete-at").parse().ok();
            tool_ok(json!({
                "dataset": c,
                "object": o,
                "bytes": bytes,
                "bytes_human": fmt_bytes(bytes),
                "content_type": ctype,
                "etag": hv(&h, "etag").trim_matches('"'),
                "last_modified": hv(&h, "last-modified"),
                "expires_at_utc": delete_at.map(fmt_utc),
                "lineage": {
                    "job": custom.get("wh-job").cloned().unwrap_or_default(),
                    "role": custom.get("wh-role").cloned().unwrap_or_default(),
                    "producer": custom.get("wh-producer").cloned().unwrap_or_default(),
                    "inputs": split_list(&hv(&h, "x-object-meta-wh-inputs")),
                    "input_etags": split_list(&hv(&h, "x-object-meta-wh-input-etags")),
                    "promoted_from": custom.get("wh-promoted-from").cloned().unwrap_or_default(),
                    "recorded": custom.contains_key("wh-job"),
                },
                "metadata": custom,
                "schema": schema,
            }))
        }
        "metadata_search" => {
            let want_rebuild = arg_bool(a, "rebuild_index");
            let have = state.search.lock().unwrap().contains_key(tenant);
            if want_rebuild || !have {
                // The console already keeps one metadata index per account; this
                // tool drives that one rather than standing up a second.
                let q: search::ReindexQ = match serde_json::from_value(json!({ "deep": "1" })) {
                    Ok(v) => v,
                    Err(e) => return tool_fail(&e.to_string()),
                };
                let _ = search::reindex(State(state.clone()), headers.clone(), Query(q)).await;
            }
            let store = state.search.lock().unwrap();
            let idx = match store.get(tenant) {
                Some(i) => i,
                None => return tool_fail("the metadata index could not be built for this account"),
            };
            let limit = arg_u64(a, "limit").unwrap_or(50).clamp(1, 200) as usize;
            let (q, cont, ct) = (
                arg_str(a, "query").to_lowercase(),
                arg_str(a, "container"),
                arg_str(a, "content_type").to_lowercase(),
            );
            let mk = arg_str(a, "meta_key").to_lowercase();
            let mv = arg_str(a, "meta_value").to_lowercase();
            let (minb, maxb) = (arg_u64(a, "min_bytes"), arg_u64(a, "max_bytes"));
            let mut hits = Vec::new();
            let mut total = 0usize;
            for e in &idx.entries {
                if !q.is_empty() && !e.name.to_lowercase().contains(&q) {
                    continue;
                }
                if !cont.is_empty() && e.container != cont {
                    continue;
                }
                if !ct.is_empty() && !e.content_type.to_lowercase().contains(&ct) {
                    continue;
                }
                if let Some(m) = minb {
                    if e.bytes < m {
                        continue;
                    }
                }
                if let Some(m) = maxb {
                    if e.bytes > m {
                        continue;
                    }
                }
                if !mk.is_empty() {
                    match e.meta.get(&mk) {
                        Some(v) if mv.is_empty() || v.to_lowercase().contains(&mv) => {}
                        _ => continue,
                    }
                } else if !mv.is_empty() && !e.meta.values().any(|v| v.to_lowercase().contains(&mv)) {
                    continue;
                }
                total += 1;
                if hits.len() < limit {
                    let decoded: BTreeMap<String, String> =
                        e.meta.iter().map(|(k, v)| (k.clone(), pct_dec(v))).collect();
                    hits.push(json!({
                        "dataset": e.container,
                        "object": e.name,
                        "bytes": e.bytes,
                        "content_type": e.content_type,
                        "last_modified": e.last_modified,
                        "etag": e.etag,
                        "metadata": decoded,
                    }));
                }
            }
            tool_ok(json!({
                "hits": hits,
                "matched": total,
                "returned": hits.len(),
                "index": {
                    "objects": idx.entries.len(),
                    "built_seconds_ago": idx.built.elapsed().as_secs(),
                    "includes_custom_metadata": idx.deep,
                    "truncated": idx.truncated,
                },
            }))
        }
        "object_sample" => {
            let (c, o) = (arg_str(a, "container"), arg_str(a, "object"));
            if c.is_empty() || o.is_empty() {
                return tool_fail("container and object are both required");
            }
            let n = arg_u64(a, "bytes").unwrap_or(4096).clamp(1, SAMPLE_CAP);
            let sub = swift::obj_subpath(&c, &o);
            let hs = vec![("Range".to_string(), format!("bytes=0-{}", n - 1))];
            let resp = match swift::call(state, sid, reqwest::Method::GET, &sub, &[], &hs, None).await {
                Ok(r) => r,
                Err(e) => return tool_fail(&e.msg()),
            };
            let st = resp.status().as_u16();
            if st >= 300 {
                return tool_fail(&format!("{c}/{o} is not readable ({st})"));
            }
            let rh = resp.headers().clone();
            let body = resp.bytes().await.unwrap_or_default();
            let total: u64 = hv(&rh, "content-range")
                .rsplit('/')
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| hv(&rh, "content-length").parse().unwrap_or(0));
            let text = String::from_utf8_lossy(&body).into_owned();
            let text = match arg_u64(a, "lines") {
                Some(l) if l > 0 => text
                    .lines()
                    .take(l as usize)
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => text,
            };
            tool_ok(json!({
                "dataset": c,
                "object": o,
                "bytes_read": body.len(),
                "bytes_total": total,
                "complete": total > 0 && body.len() as u64 >= total,
                "partial_status": st,
                "sample": text,
            }))
        }
        "job_create" => {
            let goal = arg_str(a, "goal");
            if goal.trim().is_empty() {
                return tool_fail("goal is required: a job with no stated purpose cannot be audited later");
            }
            let inputs: Vec<(String, String)> = match a.get("inputs") {
                Some(Value::Array(v)) => v
                    .iter()
                    .filter_map(|x| {
                        Some((
                            x.get("name")?.as_str()?.to_string(),
                            x.get("content")?.as_str()?.to_string(),
                        ))
                    })
                    .collect(),
                _ => Vec::new(),
            };
            let args = CreateArgs {
                goal,
                agent: {
                    let g = arg_str(a, "agent");
                    if g.is_empty() { "mcp-agent".into() } else { g }
                },
                ttl: arg_u64(a, "ttl_seconds").unwrap_or(DEFAULT_TTL),
                inputs,
            };
            match do_create(state, sid, args).await {
                Ok(v) => tool_ok(v),
                Err(e) => tool_fail(&e),
            }
        }
        "result_write" => {
            let args = WriteArgs {
                job: arg_str(a, "job"),
                name: arg_str(a, "name"),
                content: arg_str(a, "content"),
                inputs: arg_strs(a, "inputs"),
                producer: {
                    let p = arg_str(a, "producer");
                    if p.is_empty() { "mcp-agent".into() } else { p }
                },
                ttl: arg_u64(a, "ttl_seconds").unwrap_or(DEFAULT_TTL),
            };
            match do_write_working(state, sid, args).await {
                Ok(v) => tool_ok(v),
                Err(e) => tool_fail(&e),
            }
        }
        "artifact_publish" => {
            let args = PromoteArgs {
                job: arg_str(a, "job"),
                name: arg_str(a, "name"),
                dest: arg_str(a, "dest_name"),
                ttl: arg_u64(a, "ttl_seconds"),
            };
            match do_promote(state, sid, args).await {
                Ok(v) => tool_ok(v),
                Err(e) => tool_fail(&e),
            }
        }
        _ => tool_fail(&format!("unknown tool: {name}")),
    }
}

/// JSON-RPC framing, kept pure so the routing rules are unit-testable without a
/// cluster behind them.
pub enum Rpc {
    Call { id: Value, method: String, params: Value },
    Notify,
    Bad { id: Value, code: i32, msg: &'static str },
}

pub fn parse_rpc(raw: &[u8]) -> Rpc {
    let v: Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(_) => {
            return Rpc::Bad { id: Value::Null, code: -32700, msg: "parse error" };
        }
    };
    if v.is_array() {
        // Batching was removed from the protocol; answering half a batch is
        // worse than refusing it.
        return Rpc::Bad { id: Value::Null, code: -32600, msg: "batched requests are not supported" };
    }
    let obj = match v.as_object() {
        Some(o) => o,
        None => return Rpc::Bad { id: Value::Null, code: -32600, msg: "invalid request" },
    };
    let method = match obj.get("method").and_then(|m| m.as_str()) {
        Some(m) => m.to_string(),
        None => {
            return Rpc::Bad {
                id: obj.get("id").cloned().unwrap_or(Value::Null),
                code: -32600,
                msg: "invalid request: no method",
            }
        }
    };
    let params = obj.get("params").cloned().unwrap_or_else(|| json!({}));
    match obj.get("id") {
        // A notification is never answered, so its method is not carried.
        None | Some(Value::Null) => Rpc::Notify,
        Some(id) => Rpc::Call { id: id.clone(), method, params },
    }
}

pub fn negotiate_version(asked: &str) -> &'static str {
    MCP_VERSIONS
        .iter()
        .find(|v| **v == asked)
        .copied()
        .unwrap_or(MCP_VERSIONS[0])
}

// ------------------------------------------------------------ judgement

pub struct Judgement {
    pub tone: &'static str,
    pub lines: Vec<String>,
    /// (severity, title, detail, evidence)
    pub findings: Vec<(&'static str, String, String, String)>,
}

fn tr(lang: &str, key: &'static str, subs: &[(&str, &str)]) -> String {
    let mut s = i18n::t(lang, key).to_string();
    for (k, v) in subs {
        s = s.replace(k, v);
    }
    s
}

/// Everything an operator should conclude, stated once, in order of what would
/// hurt. The numbers behind each sentence are in the tables below it.
pub fn judge(lang: &str, r: &Report, now: u64) -> Judgement {
    let mut j = Judgement { tone: "ok", lines: Vec::new(), findings: Vec::new() };
    let jobs = r.jobs.len();
    let arts: Vec<&WhObj> = r.jobs.iter().flat_map(|x| x.artifacts.iter()).collect();
    let works: Vec<&WhObj> = r.jobs.iter().flat_map(|x| x.working.iter()).collect();

    j.lines.push(tr(
        lang,
        "wh.v.scale",
        &[
            ("{jobs}", &jobs.to_string()),
            ("{objects}", &r.total_objects.to_string()),
            ("{bytes}", &fmt_bytes(r.total_bytes)),
        ],
    ));

    // Lineage. An artifact that cannot name its inputs is the failure this
    // whole tool exists to prevent, so it is stated before anything else.
    let checked: Vec<&WhObj> = arts.iter().copied().filter(|a| a.headed).collect();
    let blind = arts.len() - checked.len();
    let orphans: Vec<&WhObj> = checked.iter().copied().filter(|a| a.inputs.is_empty()).collect();
    if arts.is_empty() {
        j.lines.push(i18n::t(lang, "wh.v.lineage.none").to_string());
    } else if checked.is_empty() {
        // Every artifact fell outside the HEAD budget. Reporting them as
        // clean would be claiming a measurement that was never taken.
        j.lines.push(tr(lang, "wh.v.lineage.unread", &[("{n}", &arts.len().to_string())]));
    } else if orphans.is_empty() {
        j.lines.push(tr(lang, "wh.v.lineage.ok", &[("{n}", &checked.len().to_string())]));
    } else {
        j.tone = "bad";
        j.lines.push(tr(lang, "wh.v.lineage.gap", &[("{n}", &orphans.len().to_string())]));
        j.findings.push((
            "bad",
            i18n::t(lang, "wh.f.nolineage.t").to_string(),
            i18n::t(lang, "wh.f.nolineage.d").to_string(),
            orphans.iter().map(|a| a.path.clone()).collect::<Vec<_>>().join("  "),
        ));
    }

    // Expiry.
    let mut timed: Vec<&WhObj> = works.iter().copied().filter(|w| w.delete_at.is_some()).collect();
    timed.sort_by_key(|w| w.delete_at.unwrap_or(0));
    let untimed: Vec<&WhObj> = works
        .iter()
        .copied()
        .filter(|w| w.headed && w.delete_at.is_none())
        .collect();
    if works.is_empty() {
        j.lines.push(i18n::t(lang, "wh.v.expiry.none").to_string());
    } else if let Some(first) = timed.first() {
        let at = first.delete_at.unwrap_or(0);
        let left = at.saturating_sub(now);
        j.lines.push(tr(
            lang,
            "wh.v.expiry.ok",
            &[
                ("{n}", &timed.len().to_string()),
                ("{when}", &fmt_utc(at)),
                ("{in}", &fmt_dur(lang, left)),
            ],
        ));
    }
    if !untimed.is_empty() {
        if j.tone == "ok" {
            j.tone = "warn";
        }
        j.lines.push(tr(lang, "wh.v.expiry.bad", &[("{n}", &untimed.len().to_string())]));
        j.findings.push((
            "warn",
            i18n::t(lang, "wh.f.noexpiry.t").to_string(),
            i18n::t(lang, "wh.f.noexpiry.d").to_string(),
            untimed.iter().map(|w| w.path.clone()).collect::<Vec<_>>().join("  "),
        ));
    }

    // Already past its delete-at but still listed: the reaper has not caught up.
    let stale: Vec<&WhObj> = timed
        .iter()
        .copied()
        .filter(|w| w.delete_at.unwrap_or(u64::MAX) <= now)
        .collect();
    if !stale.is_empty() {
        j.findings.push((
            "warn",
            i18n::t(lang, "wh.f.overdue.t").to_string(),
            i18n::t(lang, "wh.f.overdue.d").to_string(),
            stale
                .iter()
                .map(|w| format!("{} @ {}", w.path, fmt_utc(w.delete_at.unwrap_or(0))))
                .collect::<Vec<_>>()
                .join("  "),
        ));
    }

    // Layout that is only half there is a layout the next writer will guess at.
    let broken: Vec<&Job> = r.jobs.iter().filter(|x| x.layout_dirs < ROLES.len()).collect();
    if !broken.is_empty() {
        j.findings.push((
            "warn",
            i18n::t(lang, "wh.f.layout.t").to_string(),
            i18n::t(lang, "wh.f.layout.d").to_string(),
            broken
                .iter()
                .map(|x| format!("{} ({}/4)", x.id, x.layout_dirs))
                .collect::<Vec<_>>()
                .join("  "),
        ));
    }

    if r.head_capped || blind > 0 {
        j.findings.push((
            "warn",
            i18n::t(lang, "wh.f.capped.t").to_string(),
            tr(lang, "wh.f.capped.d", &[("{n}", &HEAD_CAP.to_string())]),
            format!("{} objects, {} unread", r.total_objects, blind),
        ));
    }
    j
}

// ------------------------------------------------------------ lineage graph

fn trunc_tail(s: &str, n: usize) -> String {
    let ch: Vec<char> = s.chars().collect();
    if ch.len() <= n {
        return s.to_string();
    }
    format!("{}…", ch[..n.saturating_sub(1)].iter().collect::<String>())
}

fn trunc(s: &str, n: usize) -> String {
    let ch: Vec<char> = s.chars().collect();
    if ch.len() <= n {
        return s.to_string();
    }
    if n <= 3 {
        return ch[..n].iter().collect();
    }
    let head = (n - 1) / 2;
    let tail = n - 1 - head;
    format!(
        "{}…{}",
        ch[..head].iter().collect::<String>(),
        ch[ch.len() - tail..].iter().collect::<String>()
    )
}

struct GNode {
    label: String,
    sub: String,
    title: String,
    cls: &'static str,
}

/// Inputs on the left, the job in the middle, what it produced on the right.
/// Rendered on the server: a lineage graph that only appears once a script has
/// run is a lineage graph that is missing exactly when someone is debugging.
pub fn lineage_svg(lang: &str, r: &Report, now: u64) -> String {
    const W: i32 = 1080;
    const NW: i32 = 300;
    const NH: i32 = 30;
    const JH: i32 = 48;
    const PITCH: i32 = 40;
    const C1: i32 = 6;
    const C2: i32 = 390;
    const C3: i32 = 774;
    const GAP: i32 = 26;
    const PADT: i32 = 10;

    // Empty layout-only jobs make a sparse graph of "no input / no output"
    // boxes; those belong in the job cards, not here.
    let shown: Vec<&Job> = r
        .jobs
        .iter()
        .filter(|j| !j.inputs.is_empty() || !j.working.is_empty() || !j.artifacts.is_empty())
        .take(GRAPH_JOBS)
        .collect();
    if shown.is_empty() {
        return String::new();
    }

    let mut bands: Vec<(Vec<GNode>, GNode, Vec<GNode>, i32)> = Vec::new();
    for j in &shown {
        let mut ins: Vec<GNode> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for o in j.inputs.iter().take(GRAPH_NODES) {
            seen.push(o.path.clone());
            ins.push(GNode {
                label: trunc(&o.name, 40),
                sub: fmt_bytes(o.bytes),
                title: format!("{} · {}", o.path, fmt_bytes(o.bytes)),
                cls: "wh-n-in",
            });
        }
        // An input named by an artifact but no longer in inputs/ still belongs
        // on the graph: it is the part of the provenance that has gone missing.
        for a in &j.artifacts {
            for p in &a.inputs {
                if !seen.contains(p) && ins.len() < GRAPH_NODES {
                    seen.push(p.clone());
                    let gone = !j.inputs.iter().any(|o| &o.path == p);
                    ins.push(GNode {
                        label: trunc(p.rsplit('/').next().unwrap_or(p), 40),
                        sub: i18n::t(lang, if gone { "wh.g.gone" } else { "wh.g.ref" }).to_string(),
                        title: p.clone(),
                        cls: if gone { "wh-n-gone" } else { "wh-n-in" },
                    });
                }
            }
        }
        if j.inputs.len() > GRAPH_NODES {
            ins.push(GNode {
                label: tr(lang, "wh.g.more", &[("{n}", &(j.inputs.len() - GRAPH_NODES).to_string())]),
                sub: String::new(),
                title: String::new(),
                cls: "wh-n-more",
            });
        }

        let job = GNode {
            label: trunc(&j.id, 40),
            sub: trunc_tail(
                if j.goal.is_empty() { i18n::t(lang, "wh.g.nogoal") } else { j.goal.as_str() },
                46,
            ),
            title: format!("{} · {}", j.id, j.goal),
            cls: "wh-n-job",
        };

        let mut outs: Vec<GNode> = Vec::new();
        for a in j.artifacts.iter().take(GRAPH_NODES) {
            outs.push(GNode {
                label: trunc(&a.name, 40),
                sub: format!(
                    "{} · {}",
                    fmt_bytes(a.bytes),
                    i18n::t(lang, "wh.g.persist")
                ),
                title: format!("{} · etag {}", a.path, a.etag),
                cls: "wh-n-art",
            });
        }
        for w in j.working.iter().take(GRAPH_NODES.saturating_sub(outs.len().min(GRAPH_NODES))) {
            if outs.len() >= GRAPH_NODES + 2 {
                break;
            }
            let sub = match w.delete_at {
                Some(t) if t > now => tr(lang, "wh.g.expires", &[("{in}", &fmt_dur(lang, t - now))]),
                Some(_) => i18n::t(lang, "wh.g.overdue").to_string(),
                None => i18n::t(lang, "wh.g.noexp").to_string(),
            };
            outs.push(GNode {
                label: trunc(&w.name, 40),
                sub,
                title: format!("{} · {}", w.path, fmt_bytes(w.bytes)),
                cls: "wh-n-work",
            });
        }
        let rows = ins.len().max(outs.len()).max(1) as i32;
        let band_h = (rows * PITCH - (PITCH - NH)).max(JH);
        bands.push((ins, job, outs, band_h));
    }

    let total_h: i32 = PADT * 2 + bands.iter().map(|b| b.3 + GAP).sum::<i32>() - GAP + 26;
    let mut out = String::new();
    out.push_str(&format!(
        "<svg class=\"wh-svg\" viewBox=\"0 0 {W} {total_h}\" width=\"{W}\" height=\"{total_h}\" role=\"img\" aria-label=\"{}\">",
        esc(i18n::t(lang, "wh.g.alt"))
    ));

    let node = |x: i32, y: i32, n: &GNode, h: i32| -> String {
        let mut s = format!(
            "<g class=\"{cls}\"><rect x=\"{x}\" y=\"{y}\" width=\"{NW}\" height=\"{h}\" rx=\"3\"/>",
            cls = n.cls
        );
        if !n.title.is_empty() {
            s.push_str(&format!("<title>{}</title>", esc(&n.title)));
        }
        if n.sub.is_empty() {
            s.push_str(&format!(
                "<text class=\"wh-t\" x=\"{}\" y=\"{}\">{}</text>",
                x + 10,
                y + h / 2 + 4,
                esc(&n.label)
            ));
        } else {
            // Two baselines whose optical centre lands on the node's, with the
            // lower one's descenders clear of the border by 3px.
            s.push_str(&format!(
                "<text class=\"wh-t\" x=\"{}\" y=\"{}\">{}</text>\
                 <text class=\"wh-s\" x=\"{}\" y=\"{}\">{}</text>",
                x + 10,
                y + h / 2 - 2,
                esc(&n.label),
                x + 10,
                y + h / 2 + 11,
                esc(&n.sub)
            ));
        }
        s.push_str("</g>");
        s
    };
    let edge = |x1: i32, y1: i32, x2: i32, y2: i32, cls: &str| -> String {
        let d = ((x2 - x1).abs() / 3).max(6);
        format!(
            "<path class=\"wh-e {cls}\" d=\"M{x1} {y1} C{c1} {y1}, {c2} {y2}, {x2} {y2}\"/>",
            c1 = x1 + d,
            c2 = x2 - d
        )
    };

    let mut y = PADT;
    for (ins, jn, outs, band_h) in &bands {
        let by = y;
        let jy = by + (band_h - JH) / 2;
        let jcy = jy + JH / 2;
        let stack = |n: usize| -> i32 {
            let hh = n as i32 * PITCH - (PITCH - NH);
            by + (band_h - hh.max(NH)) / 2
        };

        let iy0 = stack(ins.len().max(1));
        for (i, n) in ins.iter().enumerate() {
            let ny = iy0 + i as i32 * PITCH;
            out.push_str(&edge(C1 + NW, ny + NH / 2, C2, jcy, ""));
            out.push_str(&node(C1, ny, n, NH));
        }
        if ins.is_empty() {
            out.push_str(&format!(
                "<text class=\"wh-s\" x=\"{}\" y=\"{}\">{}</text>",
                C1 + 2,
                jcy + 4,
                esc(i18n::t(lang, "wh.g.noinputs"))
            ));
        }

        let oy0 = stack(outs.len().max(1));
        for (i, n) in outs.iter().enumerate() {
            let ny = oy0 + i as i32 * PITCH;
            let cls = if n.cls == "wh-n-work" { "work" } else { "" };
            out.push_str(&edge(C2 + NW, jcy, C3, ny + NH / 2, cls));
            out.push_str(&node(C3, ny, n, NH));
        }
        if outs.is_empty() {
            out.push_str(&format!(
                "<text class=\"wh-s\" x=\"{}\" y=\"{}\">{}</text>",
                C3 + 2,
                jcy + 4,
                esc(i18n::t(lang, "wh.g.nooutputs"))
            ));
        }

        out.push_str(&node(C2, jy, jn, JH));
        y += band_h + GAP;
    }

    // Legend, on the same baseline as the last band's floor.
    let ly = total_h - 8;
    let mut lx = C1 + 2;
    for (cls, key) in [
        ("wh-n-in", "wh.g.l.input"),
        ("wh-n-job", "wh.g.l.job"),
        ("wh-n-art", "wh.g.l.art"),
        ("wh-n-work", "wh.g.l.work"),
    ] {
        let label = i18n::t(lang, key);
        out.push_str(&format!(
            "<g class=\"{cls}\"><rect x=\"{lx}\" y=\"{}\" width=\"13\" height=\"11\" rx=\"2\"/></g>\
             <text class=\"wh-s\" x=\"{}\" y=\"{ly}\">{}</text>",
            ly - 10,
            lx + 18,
            esc(label)
        ));
        lx += 22 + (label.chars().count() as i32 * 9).max(52);
    }
    out.push_str("</svg>");
    out
}

// ------------------------------------------------------------ page

fn sec(title: &str, body: String) -> String {
    format!(
        "<h2 class=\"wh-h\">{}</h2>{}",
        esc(title),
        body
    )
}

// `wh-tbl`: warehouse rows carry long object paths — those cells wrap instead
// of forcing the whole table into a sideways scroll that hides the action
// column (the promote input lives in one).
fn tbl(heads: &[&str], rows: Vec<String>) -> String {
    let th: String = heads
        .iter()
        .map(|h| format!("<th>{}</th>", esc(h)))
        .collect();
    format!(
        "<div class=\"tbl-wrap\"><table class=\"tbl wh-tbl\"><thead><tr>{th}</tr></thead><tbody>{}</tbody></table></div>",
        rows.join("")
    )
}

fn empty(msg: &str) -> String {
    format!("<p class=\"empty\">{}</p>", esc(msg))
}

fn state_label(lang: &str, s: &str) -> &'static str {
    match s {
        "published" => i18n::t(lang, "wh.st.published"),
        "working" => i18n::t(lang, "wh.st.working"),
        "staged" => i18n::t(lang, "wh.st.staged"),
        _ => i18n::t(lang, "wh.st.empty"),
    }
}

fn render(lang: &str, r: &Report, note: &str, err: &str) -> String {
    let now = r.scanned_at;
    let mut out = String::new();

    out.push_str(&format!(
        "<div class=\"pagehead\"><h1>{}</h1></div>",
        esc(i18n::t(lang, "lab.tool.warehouse.title"))
    ));
    out.push_str(&format!(
        "<p class=\"statline\">{}</p>",
        esc(i18n::t(lang, "lab.tool.warehouse.blurb"))
    ));
    if !err.is_empty() {
        out.push_str(&format!(
            "<div class=\"wh-find bad\"><div class=\"wh-find-h\">{}</div><div class=\"wh-find-r\">{}</div></div>",
            esc(i18n::t(lang, "wh.msg.failed")),
            esc(err)
        ));
    }
    if !note.is_empty() {
        out.push_str(&format!(
            "<div class=\"wh-find ok\"><div class=\"wh-find-h\">{}</div><div class=\"wh-find-r\">{}</div></div>",
            esc(i18n::t(lang, "wh.msg.done")),
            esc(note)
        ));
    }

    if let Some(e) = &r.error {
        out.push_str(&format!(
            "<div class=\"wh-head\"><div class=\"wh-verdict bad\">{}</div><div class=\"wh-meta\">{}</div></div>",
            esc(i18n::t(lang, "wh.v.unreadable")),
            esc(e)
        ));
        out.push_str(&sec(i18n::t(lang, "wh.sec.mcp"), mcp_section(lang)));
        return out;
    }

    if !r.exists || r.jobs.is_empty() {
        let key = if r.exists { "wh.v.nojobs" } else { "wh.v.nowarehouse" };
        out.push_str(&format!(
            "<div class=\"wh-head\"><div class=\"wh-verdict\">{}</div><div class=\"wh-meta\">{}</div></div>",
            esc(i18n::t(lang, key)),
            esc(&tr(
                lang,
                "wh.head.scanned",
                &[("{when}", &fmt_utc(now)), ("{policy}", if r.policy.is_empty() { i18n::t(lang, "wh.unknown") } else { r.policy.as_str() })]
            ))
        ));
        out.push_str(&sec(
            i18n::t(lang, "wh.sec.actions"),
            format!("{}{}", empty(i18n::t(lang, "wh.empty.nojobs")), create_form(lang)),
        ));
        out.push_str(&sec(i18n::t(lang, "wh.sec.mcp"), mcp_section(lang)));
        return out;
    }

    // ---- verdict
    let j = judge(lang, r, now);
    let mut lines = j.lines.iter();
    let first = lines.next().cloned().unwrap_or_default();
    out.push_str(&format!(
        "<div class=\"wh-head\"><div class=\"wh-verdict {tone}\">{first}</div>",
        tone = j.tone,
        first = esc(&first)
    ));
    for l in lines {
        out.push_str(&format!("<div class=\"wh-say\">{}</div>", esc(l)));
    }
    out.push_str(&format!(
        "<div class=\"wh-meta\">{}</div></div>",
        esc(&tr(
            lang,
            "wh.head.scanned",
            &[("{when}", &fmt_utc(now)), ("{policy}", if r.policy.is_empty() { i18n::t(lang, "wh.unknown") } else { r.policy.as_str() })]
        ))
    ));

    for (sev, title, detail, evidence) in &j.findings {
        out.push_str(&format!(
            "<div class=\"wh-find {sev}\"><div class=\"wh-find-h\">{}</div><div class=\"wh-find-d\">{}</div><div class=\"wh-find-r\">{}</div></div>",
            esc(title),
            esc(detail),
            esc(evidence)
        ));
    }

    // ---- what this is (before the data dump)
    out.push_str(&how_it_works(lang));

    // ---- jobs as cards (the primary index)
    out.push_str(&sec(i18n::t(lang, "wh.sec.jobs"), job_cards(lang, r)));

    // ---- lineage graph (only jobs with objects) + table under details
    let graph = lineage_svg(lang, r, now);
    let graph_block = if graph.is_empty() {
        empty(i18n::t(lang, "wh.empty.nolineage"))
    } else {
        format!(
            "<p class=\"note wh-note\">{}</p>\
             <div class=\"wh-graph\">{}</div>\
             <details class=\"wh-data\"><summary>{}</summary>{}</details>",
            esc(i18n::t(lang, "wh.graph.note")),
            graph,
            esc(if lang == "zh" { "血缘数据表" } else { "Lineage data table" }),
            lineage_table(lang, r),
        )
    };
    out.push_str(&sec(i18n::t(lang, "wh.sec.lineage"), graph_block));

    // ---- expiry
    out.push_str(&sec(i18n::t(lang, "wh.sec.expiry"), expiry_block(lang, r, now)));

    // ---- actions
    out.push_str(&sec(
        i18n::t(lang, "wh.sec.actions"),
        format!("{}{}", create_form(lang), promote_block(lang, r)),
    ));

    // ---- MCP (reference; people don't need it to use the page)
    out.push_str(&format!(
        "<details class=\"wh-mcp\"><summary class=\"wh-h\">{}</summary>\
         <p class=\"note wh-note\">{}</p>{}</details>",
        esc(i18n::t(lang, "wh.sec.mcp")),
        esc(i18n::t(lang, "wh.sec.mcp.sum")),
        mcp_section(lang),
    ));
    out
}

fn how_it_works(lang: &str) -> String {
    format!(
        "<div class=\"wh-how\">\
           <div class=\"wh-how-t\">{}</div>\
           <div class=\"wh-how-grid\">\
             <div class=\"wh-how-i\"><b>{}</b><p>{}</p></div>\
             <div class=\"wh-how-i\"><b>{}</b><p>{}</p></div>\
             <div class=\"wh-how-i\"><b>{}</b><p>{}</p></div>\
           </div>\
         </div>",
        esc(i18n::t(lang, "wh.how.title")),
        esc(i18n::t(lang, "wh.how.1.t")),
        esc(i18n::t(lang, "wh.how.1.d")),
        esc(i18n::t(lang, "wh.how.2.t")),
        esc(i18n::t(lang, "wh.how.2.d")),
        esc(i18n::t(lang, "wh.how.3.t")),
        esc(i18n::t(lang, "wh.how.3.d")),
    )
}

fn job_cards(lang: &str, r: &Report) -> String {
    let mut cards = String::from("<div class=\"wh-jobs\">");
    for j in &r.jobs {
        let goal = if j.goal.is_empty() {
            i18n::t(lang, "wh.g.nogoal")
        } else {
            j.goal.as_str()
        };
        cards.push_str(&format!(
            "<article class=\"wh-job\">\
               <header class=\"wh-job-h\">\
                 <span class=\"wh-job-st\">{st}</span>\
                 <code class=\"wh-job-id\">{id}</code>\
               </header>\
               <div class=\"wh-job-goal\">{goal}</div>\
               <div class=\"wh-job-m\">\
                 <span><b>{i}</b> {il}</span>\
                 <span><b>{w}</b> {wl}</span>\
                 <span><b>{a}</b> {al}</span>\
                 <span>{b}</span>\
               </div>\
               <div class=\"wh-job-when\">{when}</div>\
             </article>",
            st = esc(state_label(lang, j.state())),
            id = esc(&j.id),
            goal = esc(&trunc(goal, 80)),
            i = j.inputs.len(),
            w = j.working.len(),
            a = j.artifacts.len(),
            il = esc(i18n::t(lang, "wh.card.inputs")),
            wl = esc(i18n::t(lang, "wh.card.working")),
            al = esc(i18n::t(lang, "wh.card.arts")),
            b = esc(&fmt_bytes(j.bytes)),
            when = esc(&fmt_utc(j.created)),
        ));
    }
    cards.push_str("</div>");
    // Full table kept for export-grade scanning, not as the first read.
    let rows: Vec<String> = r
        .jobs
        .iter()
        .map(|x| {
            format!(
                "<tr><td class=\"wh-mono\">{id}</td><td>{st}</td><td class=\"when\">{when}</td>\
                 <td>{goal}</td><td class=\"num\">{i}</td><td class=\"num\">{w}</td>\
                 <td class=\"num\">{a}</td><td class=\"num\">{b}</td></tr>",
                id = esc(&x.id),
                st = esc(state_label(lang, x.state())),
                when = esc(&fmt_utc(x.created)),
                goal = esc(&trunc(
                    if x.goal.is_empty() {
                        i18n::t(lang, "wh.g.nogoal")
                    } else {
                        x.goal.as_str()
                    },
                    60
                )),
                i = x.inputs.len(),
                w = x.working.len(),
                a = x.artifacts.len(),
                b = esc(&fmt_bytes(x.bytes)),
            )
        })
        .collect();
    format!(
        "{cards}<details class=\"wh-data\"><summary>{}</summary>{}</details>",
        esc(if lang == "zh" { "任务数据表" } else { "Jobs data table" }),
        tbl(
            &[
                i18n::t(lang, "wh.th.job"),
                i18n::t(lang, "wh.th.state"),
                i18n::t(lang, "wh.th.created"),
                i18n::t(lang, "wh.th.goal"),
                i18n::t(lang, "wh.th.inputs"),
                i18n::t(lang, "wh.th.working"),
                i18n::t(lang, "wh.th.artifacts"),
                i18n::t(lang, "wh.th.bytes"),
            ],
            rows,
        )
    )
}

/// The evidence behind the lineage sentence: every artifact, what it came from,
/// and whether the input it names still exists.
fn lineage_table(lang: &str, r: &Report) -> String {
    let mut rows = Vec::new();
    for j in &r.jobs {
        for a in &j.artifacts {
            let from = if !a.headed {
                format!("<span class=\"wh-unk\">{}</span>", esc(i18n::t(lang, "wh.unknown")))
            } else if a.inputs.is_empty() {
                format!("<span class=\"wh-bad\">{}</span>", esc(i18n::t(lang, "wh.lin.none")))
            } else {
                a.inputs
                    .iter()
                    .enumerate()
                    .map(|(i, p)| {
                        let live = r
                            .jobs
                            .iter()
                            .any(|jj| jj.inputs.iter().chain(jj.working.iter()).any(|o| &o.path == p));
                        format!(
                            "<div class=\"wh-mono\">{}{}<span class=\"wh-tag\">{}</span></div>",
                            esc(p),
                            if a.input_etags.get(i).map(|e| e.as_str()).unwrap_or("").is_empty() {
                                String::new()
                            } else {
                                format!(" <span class=\"wh-etag\">{}</span>", esc(&a.input_etags[i][..8.min(a.input_etags[i].len())]))
                            },
                            esc(i18n::t(lang, if live { "wh.lin.live" } else { "wh.lin.gone" }))
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("")
            };
            rows.push(format!(
                "<tr><td class=\"wh-mono\">{p}</td><td>{from}</td><td class=\"wh-mono\">{prod}</td>\
                 <td class=\"num\">{b}</td><td class=\"when\">{when}</td></tr>",
                p = esc(&a.path),
                from = from,
                prod = esc(if a.producer.is_empty() { i18n::t(lang, "common.none") } else { a.producer.as_str() }),
                b = esc(&fmt_bytes(a.bytes)),
                when = esc(&if a.promoted_at > 0 { fmt_utc(a.promoted_at) } else { a.last_modified.clone() }),
            ));
        }
    }
    if rows.is_empty() {
        return empty(i18n::t(lang, "wh.empty.nolineage"));
    }
    tbl(
        &[
            i18n::t(lang, "wh.th.artifact"),
            i18n::t(lang, "wh.th.from"),
            i18n::t(lang, "wh.th.producer"),
            i18n::t(lang, "wh.th.size"),
            i18n::t(lang, "wh.th.when"),
        ],
        rows,
    )
}

fn expiry_block(lang: &str, r: &Report, now: u64) -> String {
    let mut items: Vec<&WhObj> = r.jobs.iter().flat_map(|j| j.working.iter()).collect();
    items.sort_by_key(|w| w.delete_at.unwrap_or(u64::MAX));
    if items.is_empty() {
        return empty(i18n::t(lang, "wh.empty.noexpiry"));
    }
    let payload: Vec<Value> = items
        .iter()
        .filter(|w| w.delete_at.is_some())
        .map(|w| {
            json!({
                "name": w.name,
                "path": w.path,
                "at": w.delete_at,
                "bytes": w.bytes,
            })
        })
        .collect();
    let data = serde_json::to_string(&payload)
        .unwrap_or_else(|_| "[]".into())
        .replace('<', "\\u003c");

    let rows: Vec<String> = items
        .iter()
        .map(|w| {
            let (when, left) = match w.delete_at {
                Some(t) if t > now => (fmt_utc(t), fmt_dur(lang, t - now)),
                Some(t) => (fmt_utc(t), i18n::t(lang, "wh.g.overdue").to_string()),
                None => (
                    i18n::t(lang, if w.headed { "wh.exp.never" } else { "wh.unknown" }).to_string(),
                    String::new(),
                ),
            };
            format!(
                "<tr><td class=\"wh-mono\">{p}</td><td class=\"num\">{b}</td><td class=\"when\">{when}</td><td>{left}</td></tr>",
                p = esc(&w.path),
                b = esc(&fmt_bytes(w.bytes)),
                when = esc(&when),
                left = esc(&left),
            )
        })
        .collect();

    format!(
        "<p class=\"note wh-note\">{}</p>\
         <script type=\"application/json\" id=\"wh-exp-data\">{data}</script>\
         <div class=\"wh-lane\" id=\"wh-exp-lane\"></div>{}",
        esc(i18n::t(lang, "wh.exp.intro")),
        tbl(
            &[
                i18n::t(lang, "wh.th.object"),
                i18n::t(lang, "wh.th.size"),
                i18n::t(lang, "wh.th.expires"),
                i18n::t(lang, "wh.th.left"),
            ],
            rows,
        )
    )
}

fn create_form(lang: &str) -> String {
    format!(
        r#"<form class="page-sec wh-form" method="post" action="/lab/api/warehouse/job">
  <div class="sx-grid">
    <label class="fld"><span>{goal}</span><input name="goal" required autocomplete="off" placeholder="{goalp}"></label>
    <label class="fld"><span>{agent}</span><input name="agent" value="console-operator" autocomplete="off"></label>
    <label class="fld"><span>{ttl}</span><select name="ttl_seconds">
      <option value="3600">{h1}</option>
      <option value="21600" selected>{h6}</option>
      <option value="86400">{d1}</option>
      <option value="604800">{d7}</option>
    </select></label>
  </div>
  <div class="sx-actions"><button class="btn-primary" type="submit">{go}</button></div>
</form>"#,
        goal = esc(i18n::t(lang, "wh.act.goal")),
        goalp = esc(i18n::t(lang, "wh.act.goalp")),
        agent = esc(i18n::t(lang, "wh.act.agent")),
        ttl = esc(i18n::t(lang, "wh.act.ttl")),
        h1 = esc(&fmt_dur(lang, 3600)),
        h6 = esc(&fmt_dur(lang, 21600)),
        d1 = esc(&fmt_dur(lang, 86400)),
        d7 = esc(&fmt_dur(lang, 604800)),
        go = esc(i18n::t(lang, "wh.act.create")),
    )
}

/// One promote form per working file: the operator picks a row, not a path
/// typed from memory, and it posts without a line of script.
fn promote_block(lang: &str, r: &Report) -> String {
    let mut rows = Vec::new();
    for j in &r.jobs {
        for w in &j.working {
            rows.push(format!(
                "<tr><td class=\"wh-mono\">{p}</td><td class=\"num\">{b}</td><td>\
                 <form class=\"wh-inline\" method=\"post\" action=\"/lab/api/warehouse/promote\">\
                 <input type=\"hidden\" name=\"job\" value=\"{job}\">\
                 <input type=\"hidden\" name=\"name\" value=\"{name}\">\
                 <input name=\"dest_name\" value=\"{name}\" autocomplete=\"off\" aria-label=\"{dl}\">\
                 <button class=\"btn\" type=\"submit\">{go}</button></form></td></tr>",
                p = esc(&w.path),
                b = esc(&fmt_bytes(w.bytes)),
                job = esc(&j.id),
                name = esc(&w.name),
                dl = esc(i18n::t(lang, "wh.act.dest")),
                go = esc(i18n::t(lang, "wh.act.promote")),
            ));
        }
    }
    if rows.is_empty() {
        return empty(i18n::t(lang, "wh.empty.nopromote"));
    }
    format!(
        "<p class=\"note wh-note\">{}</p>{}",
        esc(i18n::t(lang, "wh.act.promotehint")),
        tbl(
            &[
                i18n::t(lang, "wh.th.object"),
                i18n::t(lang, "wh.th.size"),
                i18n::t(lang, "wh.th.promote"),
            ],
            rows,
        )
    )
}

fn mcp_section(lang: &str) -> String {
    let tools: Vec<String> = mcp_tool_list(lang)
        .iter()
        .map(|t| {
            let name = t["name"].as_str().unwrap_or("");
            let desc = t["description"].as_str().unwrap_or("");
            let props: Vec<String> = t["inputSchema"]["properties"]
                .as_object()
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default();
            let req: Vec<String> = t["inputSchema"]["required"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            format!(
                "<tr><td class=\"wh-mono\">{n}</td><td>{d}</td><td class=\"wh-mono wh-args\">{a}</td></tr>",
                n = esc(name),
                d = esc(desc),
                a = props
                    .iter()
                    .map(|p| if req.contains(p) {
                        format!("<b>{}</b>", esc(p))
                    } else {
                        esc(p)
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        })
        .collect();
    format!(
        "<p class=\"note wh-note\">{intro}</p>\
         <dl class=\"kv wh-kv\">\
         <div><dt>{ep}</dt><dd>POST /mcp</dd></div>\
         <div><dt>{pr}</dt><dd>JSON-RPC 2.0 · MCP {ver}</dd></div>\
         <div><dt>{au}</dt><dd>{auv}</dd></div>\
         <div><dt>{im}</dt><dd>initialize · notifications/initialized · ping · tools/list · tools/call</dd></div>\
         <div><dt>{ni}</dt><dd>{niv}</dd></div>\
         </dl>{tbl}",
        intro = esc(i18n::t(lang, "wh.mcp.intro")),
        ep = esc(i18n::t(lang, "wh.mcp.endpoint")),
        pr = esc(i18n::t(lang, "wh.mcp.protocol")),
        ver = esc(MCP_VERSIONS[0]),
        au = esc(i18n::t(lang, "wh.mcp.auth")),
        auv = esc(i18n::t(lang, "wh.mcp.authv")),
        im = esc(i18n::t(lang, "wh.mcp.impl")),
        ni = esc(i18n::t(lang, "wh.mcp.notimpl")),
        niv = esc(i18n::t(lang, "wh.mcp.notimplv")),
        tbl = tbl(
            &[
                i18n::t(lang, "wh.th.tool"),
                i18n::t(lang, "wh.th.does"),
                i18n::t(lang, "wh.th.args"),
            ],
            tools
        ),
    )
}

// ------------------------------------------------------------ handlers

fn is_form(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(false)
}

fn form_to_json(raw: &str) -> Value {
    let mut m = serde_json::Map::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.find('=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, ""),
        };
        m.insert(
            pct_dec(&k.replace('+', " ")),
            Value::String(pct_dec(&v.replace('+', " "))),
        );
    }
    Value::Object(m)
}

fn body_json(headers: &HeaderMap, body: &Bytes) -> Value {
    if is_form(headers) {
        form_to_json(&String::from_utf8_lossy(body))
    } else {
        serde_json::from_slice(body).unwrap_or_else(|_| json!({}))
    }
}

/// A form post gets a redirect back to the report (so the browser reloads real
/// state instead of trusting a JSON echo); an API caller gets the evidence.
fn short_note(v: &Value) -> String {
    for k in ["artifact", "job"] {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()) {
            return s.to_string();
        }
    }
    String::new()
}

fn respond(headers: &HeaderMap, out: Result<Value, String>) -> Response {
    if is_form(headers) {
        return match out {
            Ok(v) => {
                Redirect::to(&format!("/lab/warehouse?note={}", enc_seg(&short_note(&v)))).into_response()
            }
            Err(e) => Redirect::to(&format!("/lab/warehouse?err={}", enc_seg(&e))).into_response(),
        };
    }
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(json!({ "error": e }))).into_response(),
    }
}

pub async fn page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let (sid, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let rep = scan(&state, &sid).await;
    let body = render(
        lang,
        &rep,
        q.get("note").map(|s| s.as_str()).unwrap_or(""),
        q.get("err").map(|s| s.as_str()).unwrap_or(""),
    );
    crate::pages::lab_tool_shell(&state, &headers, &sess, "warehouse", body)
}

pub async fn jobs(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, _) = match lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let rep = scan(&state, &sid).await;
    let j = judge(lang, &rep, rep.scanned_at);
    let jobs: Vec<Value> = rep
        .jobs
        .iter()
        .map(|x| {
            let obj = |o: &WhObj| {
                json!({
                    "path": o.path,
                    "name": o.name,
                    "written_at_utc": if o.created > 0 { Some(fmt_utc(o.created)) } else { None },
                    "bytes": o.bytes,
                    "etag": o.etag,
                    "producer": o.producer,
                    "inputs": o.inputs,
                    "input_etags": o.input_etags,
                    "promoted_from": o.promoted_from,
                    "expires_at": o.delete_at,
                    "expires_at_utc": o.delete_at.map(fmt_utc),
                    "lineage_read": o.headed,
                })
            };
            json!({
                "job": x.id,
                "state": x.state(),
                "created": x.created,
                "created_utc": fmt_utc(x.created),
                "goal": x.goal,
                "agent": x.agent,
                "ttl_seconds": x.ttl,
                "layout_dirs_present": x.layout_dirs,
                "bytes": x.bytes,
                "objects": x.objects(),
                "inputs": x.inputs.iter().map(obj).collect::<Vec<_>>(),
                "working": x.working.iter().map(obj).collect::<Vec<_>>(),
                "artifacts": x.artifacts.iter().map(obj).collect::<Vec<_>>(),
                "report": x.reports.iter().map(obj).collect::<Vec<_>>(),
            })
        })
        .collect();
    Json(json!({
        "container": CONTAINER,
        "exists": rep.exists,
        "policy": rep.policy,
        "scanned_at_utc": fmt_utc(rep.scanned_at),
        "total_objects": rep.total_objects,
        "total_bytes": rep.total_bytes,
        "lineage_read_capped_at": if rep.head_capped { Some(HEAD_CAP) } else { None },
        "verdict": j.lines,
        "tone": j.tone,
        "findings": j.findings.iter().map(|(s, t, d, e)| json!({
            "severity": s, "title": t, "detail": d, "evidence": e
        })).collect::<Vec<_>>(),
        "jobs": jobs,
        "error": rep.error,
    }))
    .into_response()
}

pub async fn create_job(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (sid, _) = match lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let a = body_json(&headers, &body);
    let goal = arg_str(&a, "goal");
    if goal.trim().is_empty() {
        return respond(&headers, Err("goal is required".into()));
    }
    let inputs = match a.get("inputs") {
        Some(Value::Array(v)) => v
            .iter()
            .filter_map(|x| {
                Some((
                    x.get("name")?.as_str()?.to_string(),
                    x.get("content")?.as_str()?.to_string(),
                ))
            })
            .collect(),
        _ => Vec::new(),
    };
    let args = CreateArgs {
        goal,
        agent: {
            let g = arg_str(&a, "agent");
            if g.is_empty() { "console-operator".into() } else { g }
        },
        ttl: arg_u64(&a, "ttl_seconds").unwrap_or(DEFAULT_TTL),
        inputs,
    };
    respond(&headers, do_create(&state, &sid, args).await)
}

pub async fn promote(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (sid, _) = match lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let a = body_json(&headers, &body);
    let args = PromoteArgs {
        job: arg_str(&a, "job"),
        name: arg_str(&a, "name"),
        dest: arg_str(&a, "dest_name"),
        ttl: arg_u64(&a, "ttl_seconds"),
    };
    respond(&headers, do_promote(&state, &sid, args).await)
}

pub async fn mcp(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let lang = i18n::lang(&headers);
    let req = parse_rpc(&body);
    let (id, method, params) = match req {
        Rpc::Bad { id, code, msg } => {
            return (StatusCode::BAD_REQUEST, Json(rpc_err(&id, code, msg))).into_response()
        }
        // A notification has no id, so there is nothing to answer to.
        Rpc::Notify => return StatusCode::ACCEPTED.into_response(),
        Rpc::Call { id, method, params } => (id, method, params),
    };

    let (sid, sess) = match lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => {
            let st = r.status();
            return (
                st,
                Json(rpc_err(&id, -32001, "no console session: this endpoint requires a signed-in session")),
            )
                .into_response();
        }
    };

    let result = match method.as_str() {
        "initialize" => {
            let asked = params
                .get("protocolVersion")
                .and_then(|v| v.as_str())
                .unwrap_or(MCP_VERSIONS[0]);
            rpc_ok(
                &id,
                json!({
                    "protocolVersion": negotiate_version(asked),
                    "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": {
                        "name": "object-warehouse",
                        "title": i18n::t(lang, "lab.tool.warehouse.title"),
                        "version": crate::pages::VERSION,
                    },
                    "instructions": i18n::t(lang, "wh.mcp.instructions"),
                }),
            )
        }
        "ping" => rpc_ok(&id, json!({})),
        "tools/list" => rpc_ok(&id, json!({ "tools": mcp_tool_list(lang) })),
        "tools/call" => {
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if !MCP_TOOLS.iter().any(|(n, _)| *n == name) {
                rpc_err(&id, -32602, "unknown tool")
            } else {
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                let out = call_tool(&state, &headers, &sid, &sess.tenant, name, &args).await;
                rpc_ok(&id, out)
            }
        }
        _ => rpc_err(&id, -32601, "method not found"),
    };
    Json(result).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(path: &str, role: &str, bytes: u64) -> WhObj {
        let (job, _r, name) = parse_path(path).unwrap();
        WhObj {
            path: path.into(),
            name,
            job,
            role: role.into(),
            bytes,
            etag: "d41d8cd98f00b204e9800998ecf8427e".into(),
            content_type: "text/csv".into(),
            last_modified: "2026-07-29T10:00:00.000000".into(),
            created: 1_785_322_045,
            producer: "agent-a".into(),
            inputs: Vec::new(),
            input_etags: Vec::new(),
            promoted_from: String::new(),
            promoted_at: 0,
            delete_at: None,
            headed: true,
        }
    }

    fn report(jobs: Vec<Job>) -> Report {
        let total_bytes = jobs.iter().map(|j| j.bytes).sum();
        let total_objects = jobs.iter().map(|j| j.objects()).sum();
        Report {
            exists: true,
            policy: "default".into(),
            jobs,
            total_bytes,
            total_objects,
            head_capped: false,
            scanned_at: 1_785_400_000,
            error: None,
        }
    }

    #[test]
    fn layout_paths_round_trip_through_the_parser() {
        assert_eq!(
            parse_path("jobs/job-1785322045-a3f19c/inputs/orders.csv"),
            Some((
                "job-1785322045-a3f19c".into(),
                "inputs".into(),
                "orders.csv".into()
            ))
        );
        // The four directory markers are the layout, not content.
        assert_eq!(
            parse_path("jobs/job-1-a/working/"),
            Some(("job-1-a".into(), "working".into(), String::new()))
        );
        assert_eq!(
            parse_path("jobs/job-1-a/"),
            Some(("job-1-a".into(), String::new(), String::new()))
        );
        // A nested name keeps its slashes rather than becoming a fifth role.
        assert_eq!(
            parse_path("jobs/job-1-a/artifacts/x/y.json").map(|t| t.2),
            Some("x/y.json".into())
        );
        assert_eq!(parse_path("other/thing"), None);
        assert_eq!(parse_path("jobs/"), None);
    }

    #[test]
    fn lineage_values_survive_a_header_round_trip() {
        // A goal in Chinese has to come back out of an HTTP header intact, or
        // the provenance record is only readable for English jobs.
        for s in [
            "把订单按天聚合",
            "plain ascii",
            "spaces and | pipes",
            "%not-an-escape",
            "",
        ] {
            assert_eq!(pct_dec(&pct_enc(s)), s, "round trip {s}");
        }
        let paths = vec![
            "jobs/job-1-a/inputs/orders.csv".to_string(),
            "jobs/job-1-a/inputs/名称.csv".to_string(),
        ];
        assert_eq!(split_list(&join_list(&paths)), paths);
        assert!(!join_list(&paths).contains('/'), "a path separator would break the list");
        assert!(split_list("").is_empty());
    }

    #[test]
    fn timestamps_read_the_way_an_operator_says_them() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00:00Z");
        // The cluster returned exactly this delete-at during the live run.
        assert_eq!(fmt_utc(1_785_325_645), "2026-07-29 11:47:25Z");
        assert_eq!(fmt_dur("en", 45), "45s");
        assert_eq!(fmt_dur("zh", 45), "45 秒");
        assert_eq!(fmt_dur("en", 5_400), "1h 30m");
        assert_eq!(fmt_dur("zh", 5_400), "1 小时 30 分");
        assert_eq!(fmt_dur("en", 604_800), "7d");
    }

    #[test]
    fn names_that_would_escape_the_job_are_refused() {
        assert!(valid_leaf("orders.csv"));
        assert!(!valid_leaf("../escape"));
        assert!(!valid_leaf(""));
        assert!(!valid_leaf(".hidden"));
        assert!(valid_job_id("job-1785322045-a3f19c"));
        assert!(!valid_job_id("job-1/../x"));
        assert!(!valid_job_id("1785322045"));
        // A TTL is clamped rather than rejected: an agent asking for 10 years
        // gets a week, not an error it has to handle.
        assert_eq!(clamp_ttl(1), MIN_TTL);
        assert_eq!(clamp_ttl(31_536_000), MAX_TTL);
        assert_eq!(clamp_ttl(3_600), 3_600);
    }

    #[test]
    fn an_artifact_with_no_recorded_inputs_is_called_out_by_name() {
        let mut j = Job { id: "job-1785322045-a3f19c".into(), ..Default::default() };
        j.inputs.push(obj("jobs/job-1785322045-a3f19c/inputs/orders.csv", "inputs", 100));
        let mut good = obj("jobs/job-1785322045-a3f19c/artifacts/daily.csv", "artifacts", 40);
        good.inputs = vec!["jobs/job-1785322045-a3f19c/inputs/orders.csv".into()];
        let bad = obj("jobs/job-1785322045-a3f19c/artifacts/mystery.csv", "artifacts", 20);
        j.artifacts.push(good);
        j.artifacts.push(bad);
        j.bytes = 160;

        let r = report(vec![j]);
        for lang in ["en", "zh"] {
            let v = judge(lang, &r, r.scanned_at);
            assert_eq!(v.tone, "bad");
            assert!(
                v.findings.iter().any(|f| f.3.contains("mystery.csv")),
                "the evidence must name the file, {lang}"
            );
            assert!(
                !v.findings.iter().any(|f| f.3.contains("daily.csv")),
                "the artifact that does record its inputs is not a finding, {lang}"
            );
            assert!(v.lines.iter().any(|l| l.contains('3')), "3 objects, {lang}: {:?}", v.lines);
        }
    }

    #[test]
    fn a_working_file_with_no_expiry_is_never_reported_as_expiring() {
        let mut j = Job { id: "job-1785322045-a3f19c".into(), ..Default::default() };
        let mut timed = obj("jobs/job-1785322045-a3f19c/working/part.csv", "working", 10);
        timed.delete_at = Some(1_785_403_600);
        let untimed = obj("jobs/job-1785322045-a3f19c/working/loose.csv", "working", 10);
        j.working.push(timed);
        j.working.push(untimed);
        let r = report(vec![j]);
        let v = judge("en", &r, r.scanned_at);
        assert_eq!(v.tone, "warn");
        assert!(v.findings.iter().any(|f| f.3.contains("loose.csv")));
        // The soonest expiry is stated with its real clock time, not "soon".
        assert!(
            v.lines.iter().any(|l| l.contains("2026-07-30 09:26:40Z")),
            "{:?}",
            v.lines
        );
    }

    #[test]
    fn unmeasured_lineage_is_unknown_rather_than_absent() {
        let mut j = Job { id: "job-1785322045-a3f19c".into(), ..Default::default() };
        let mut a = obj("jobs/job-1785322045-a3f19c/artifacts/x.csv", "artifacts", 1);
        a.headed = false;
        j.artifacts.push(a);
        let mut r = report(vec![j]);
        r.head_capped = true;
        let v = judge("en", &r, r.scanned_at);
        // An object the scan never read must not be counted as an artifact
        // missing its lineage; that would be a measurement we did not take.
        assert!(!v.findings.iter().any(|f| f.1 == i18n::t("en", "wh.f.nolineage.t")));
        assert!(v.findings.iter().any(|f| f.1 == i18n::t("en", "wh.f.capped.t")));
    }

    #[test]
    fn the_lineage_graph_draws_every_column_and_closes_its_svg() {
        let mut j = Job {
            id: "job-1785322045-a3f19c".into(),
            goal: "aggregate orders by day".into(),
            ..Default::default()
        };
        j.inputs.push(obj("jobs/job-1785322045-a3f19c/inputs/orders.csv", "inputs", 100));
        let mut a = obj("jobs/job-1785322045-a3f19c/artifacts/daily.csv", "artifacts", 40);
        a.inputs = vec!["jobs/job-1785322045-a3f19c/inputs/orders.csv".into()];
        j.artifacts.push(a);
        let r = report(vec![j]);
        let s = lineage_svg("en", &r, r.scanned_at);
        assert!(s.starts_with("<svg") && s.ends_with("</svg>"));
        assert!(s.contains("orders.csv") && s.contains("job-1785322045-a3f19c") && s.contains("daily.csv"));
        // One edge in, one edge out.
        assert_eq!(s.matches("class=\"wh-e").count(), 2, "{s}");
        assert!(lineage_svg("en", &report(vec![]), 0).is_empty());
    }

    #[test]
    fn an_input_an_artifact_names_but_that_is_gone_still_appears() {
        let mut j = Job { id: "job-1785322045-a3f19c".into(), ..Default::default() };
        let mut a = obj("jobs/job-1785322045-a3f19c/artifacts/daily.csv", "artifacts", 40);
        a.inputs = vec!["jobs/job-1785322045-a3f19c/inputs/vanished.csv".into()];
        j.artifacts.push(a);
        let r = report(vec![j]);
        let s = lineage_svg("en", &r, r.scanned_at);
        assert!(s.contains("vanished.csv"));
        assert!(s.contains("wh-n-gone"), "a missing input reads differently from a present one");
    }

    #[test]
    fn json_rpc_framing_is_routed_by_shape_not_by_guesswork() {
        match parse_rpc(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#) {
            Rpc::Call { id, method, .. } => {
                assert_eq!(method, "tools/list");
                assert_eq!(id, json!(1));
            }
            _ => panic!("a request with an id is a call"),
        }
        // A notification gets no response body at all, so it must not be
        // mistaken for a call with a null id.
        assert!(matches!(
            parse_rpc(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Rpc::Notify
        ));
        assert!(matches!(
            parse_rpc(br#"{"jsonrpc":"2.0","id":null,"method":"x"}"#),
            Rpc::Notify
        ));
        assert!(matches!(parse_rpc(b"not json"), Rpc::Bad { code: -32700, .. }));
        assert!(matches!(parse_rpc(b"[{\"method\":\"a\"}]"), Rpc::Bad { code: -32600, .. }));
        assert!(matches!(parse_rpc(br#"{"id":1}"#), Rpc::Bad { code: -32600, .. }));
    }

    #[test]
    fn protocol_version_falls_back_instead_of_echoing_anything_asked_for() {
        assert_eq!(negotiate_version("2024-11-05"), "2024-11-05");
        assert_eq!(negotiate_version("2025-06-18"), "2025-06-18");
        assert_eq!(negotiate_version("1999-01-01"), MCP_VERSIONS[0]);
    }

    #[test]
    fn every_advertised_tool_has_a_schema_and_a_translated_description() {
        for lang in ["en", "zh"] {
            let tools = mcp_tool_list(lang);
            assert_eq!(tools.len(), MCP_TOOLS.len());
            for t in &tools {
                let name = t["name"].as_str().unwrap();
                let desc = t["description"].as_str().unwrap();
                assert_ne!(desc, "", "{name} has no description in {lang}");
                assert!(!desc.contains('.') || !desc.starts_with("wh."), "{name} leaked a key in {lang}");
                assert_eq!(t["inputSchema"]["type"], "object", "{name}");
                assert!(t["inputSchema"]["properties"].is_object(), "{name}");
                assert!(t["inputSchema"]["required"].is_array(), "{name}");
            }
        }
    }

    #[test]
    fn a_sniffed_schema_says_it_is_a_guess() {
        let s = sniff_schema("orders.csv", "text/csv", b"id,day,total\n7,2026-07-29,10.5\n");
        assert_eq!(s["kind"], "csv");
        assert_eq!(s["columns"][0]["name"], "id");
        assert_eq!(s["columns"][0]["type_guess"], "integer");
        assert_eq!(s["columns"][1]["type_guess"], "text");
        assert_eq!(s["columns"][2]["type_guess"], "number");
        assert!(s["note"].as_str().unwrap().contains("inferred"));

        let j = sniff_schema("x.json", "application/json", br#"{"a":1,"b":"z"}"#);
        assert_eq!(j["keys"], json!(["a", "b"]));

        // A prefix that is not a whole document must not be reported as one.
        let cut = sniff_schema("x.json", "application/json", br#"{"a":1,"b":"#);
        assert!(cut["note"].as_str().unwrap().contains("not a complete"));
    }

    #[test]
    fn a_posted_form_and_a_posted_document_produce_the_same_arguments() {
        let f = form_to_json("goal=aggregate+orders&agent=console-operator&ttl_seconds=3600");
        assert_eq!(arg_str(&f, "goal"), "aggregate orders");
        assert_eq!(arg_u64(&f, "ttl_seconds"), Some(3600));
        let j = json!({ "goal": "aggregate orders", "ttl_seconds": 3600 });
        assert_eq!(arg_str(&j, "goal"), arg_str(&f, "goal"));
        assert_eq!(arg_u64(&j, "ttl_seconds"), arg_u64(&f, "ttl_seconds"));
        // A Chinese goal typed into the form survives the encoding.
        let z = form_to_json("goal=%E6%8C%89%E5%A4%A9%E8%81%9A%E5%90%88");
        assert_eq!(arg_str(&z, "goal"), "按天聚合");
    }

    #[test]
    fn long_names_are_shortened_in_the_middle_so_the_extension_survives() {
        assert_eq!(trunc("short.csv", 26), "short.csv");
        let t = trunc("a-very-long-artifact-name-indeed.csv", 20);
        assert_eq!(t.chars().count(), 20);
        assert!(t.ends_with(".csv"), "{t}");
        assert!(t.contains('…'));
    }

    #[test]
    fn an_empty_warehouse_explains_what_would_fill_it() {
        let mut r = report(vec![]);
        r.exists = false;
        for lang in ["en", "zh"] {
            let h = render(lang, &r, "", "");
            assert!(h.contains(i18n::t(lang, "wh.v.nowarehouse")), "{lang}");
            // An empty state has to say what would put data here, and offer it.
            assert!(h.contains(i18n::t(lang, "wh.empty.nojobs")), "{lang}");
            assert!(h.contains("action=\"/lab/api/warehouse/job\""), "{lang}");
            // The endpoint is documented even with nothing stored, because
            // wiring an agent up is exactly what you do first.
            assert!(h.contains("artifact_publish"), "{lang}");
        }
    }

    #[test]
    fn an_unreadable_warehouse_says_so_rather_than_rendering_zeroes() {
        let mut r = report(vec![]);
        r.error = Some("listing failed (503)".into());
        let h = render("en", &r, "", "");
        assert!(h.contains(i18n::t("en", "wh.v.unreadable")));
        assert!(h.contains("listing failed (503)"), "the reason is shown, not swallowed");
        assert!(!h.contains("0 jobs hold"), "a failed read must not be reported as an empty warehouse");
    }

    #[test]
    fn no_untranslated_key_reaches_the_rendered_page() {
        let mut j = Job {
            id: "job-1785322045-a3f19c".into(),
            goal: "aggregate orders".into(),
            layout_dirs: 4,
            ..Default::default()
        };
        j.inputs.push(obj("jobs/job-1785322045-a3f19c/inputs/orders.csv", "inputs", 100));
        let mut w = obj("jobs/job-1785322045-a3f19c/working/part.csv", "working", 10);
        w.delete_at = Some(1_785_403_600);
        j.working.push(w);
        let mut a = obj("jobs/job-1785322045-a3f19c/artifacts/daily.csv", "artifacts", 40);
        a.inputs = vec!["jobs/job-1785322045-a3f19c/inputs/orders.csv".into()];
        j.artifacts.push(a);
        let r = report(vec![j]);
        for lang in ["en", "zh"] {
            let h = render(lang, &r, "", "");
            // A key that never got a translation renders as the key itself.
            for cap in ["wh.v.", "wh.th.", "wh.sec.", "wh.g.", "wh.act.", "wh.mcp.", "wh.t.", "wh.st."] {
                assert!(!h.contains(cap), "{lang} leaked {cap}");
            }
            assert!(h.contains("<svg class=\"wh-svg\""), "{lang} lost the lineage graph");
            assert!(h.contains("id=\"wh-exp-data\""), "{lang} lost the expiry payload");
        }
    }

    #[test]
    fn job_state_follows_what_is_actually_in_the_job() {
        let mut j = Job { id: "job-1-a".into(), ..Default::default() };
        assert_eq!(j.state(), "empty");
        j.inputs.push(obj("jobs/job-1-a/inputs/x.csv", "inputs", 1));
        assert_eq!(j.state(), "staged");
        j.working.push(obj("jobs/job-1-a/working/y.csv", "working", 1));
        assert_eq!(j.state(), "working");
        j.artifacts.push(obj("jobs/job-1-a/artifacts/z.csv", "artifacts", 1));
        assert_eq!(j.state(), "published");
        assert_eq!(j.objects(), 3);
    }
}
