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

//! Swift Shadow: one request, two implementations, a field-by-field diff.
//!
//! The ground truth on this cluster is that there is exactly ONE implementation.
//! A second one is not installed, so nothing here is compared to anything and
//! the tool says so on every surface. What it does produce today is the durable
//! half of the asset: a corpus of real requests and the exact answers this
//! cluster gives, replayable against the cluster as it is now. That already
//! catches one implementation drifting from itself, and the day a second
//! endpoint is configured the same records become a two-sided diff with no
//! change to the corpus format.
//!
//! The diff core is deliberately pure and independent of where the two answers
//! came from — it takes two captured responses and classifies the difference.
//! Its most load-bearing piece is the noise list: `Date` and `X-Trans-Id` MUST
//! differ between two servers, and a tool that reports them cries wolf until
//! nobody reads it. Every noise entry is written down with the reason it is
//! there, and the reason is rendered in the UI rather than buried here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::util::{esc, fmt_bytes};
use crate::{i18n, lab, session, swift, AppState};

// ------------------------------------------------------------------ config

/// Shadow's own settings, read from the console config file rather than added
/// to the shared `Config` struct. A second implementation is a deployment
/// fact; wiring one in should not mean editing the type every other surface
/// depends on. The main parse ignores unknown keys, so both views of the same
/// file coexist.
pub struct ShadowCfg {
    pub root: PathBuf,
    /// Storage base of the second implementation, "" when there is none.
    pub peer_base: String,
    pub peer_auth: String,
    pub peer_label: String,
}

fn cfg() -> &'static ShadowCfg {
    static C: OnceLock<ShadowCfg> = OnceLock::new();
    C.get_or_init(|| {
        let path = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "/etc/swift-console/config.json".into());
        let v: serde_json::Value = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_else(|| json!({}));
        let s = |k: &str| {
            v.get(k)
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let root = match s("shadow_root") {
            r if r.is_empty() => "/var/lib/swift-console/shadow".to_string(),
            r => r,
        };
        let peer_base = s("shadow_peer_base");
        let peer_auth = match s("shadow_peer_auth") {
            a if a.is_empty() && !peer_base.is_empty() => {
                format!("{}/auth/v1.0", peer_base.trim_end_matches('/'))
            }
            a => a,
        };
        let peer_label = match s("shadow_peer_label") {
            l if l.is_empty() => "peer".to_string(),
            l => l,
        };
        ShadowCfg {
            root: PathBuf::from(root),
            peer_base,
            peer_auth,
            peer_label,
        }
    })
}

pub fn peer_configured() -> bool {
    !cfg().peer_base.is_empty()
}

// ------------------------------------------------------------------- model

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct ReqSpec {
    pub method: String,
    /// Path under the account: "" for the account itself, "/c", "/c/o".
    pub sub: String,
    #[serde(default)]
    pub query: Vec<(String, String)>,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Option<String>,
    /// Send a token that cannot be valid, to observe the refusal path.
    #[serde(default)]
    pub bad_token: bool,
}

impl ReqSpec {
    /// One line an operator can read and re-issue by hand. Protocol text, so
    /// it is the same in both languages and needs no translation.
    pub fn line(&self) -> String {
        let mut s = format!(
            "{} {}",
            self.method,
            if self.sub.is_empty() { "/" } else { &self.sub }
        );
        if !self.query.is_empty() {
            s.push('?');
            s.push_str(
                &self
                    .query
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        }
        for (k, v) in &self.headers {
            s.push_str(&format!("   {k}: {v}"));
        }
        if self.bad_token {
            s.push_str("   X-Auth-Token: <invalid>");
        }
        s
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct CapturedResp {
    pub status: u16,
    /// Original name case is preserved: the case IS one of the things compared.
    pub headers: Vec<(String, String)>,
    pub len: u64,
    pub md5: String,
    #[serde(default)]
    pub text: Option<String>,
    /// First bytes as hex when the body is not text, so a range boundary is
    /// still checkable by eye rather than only by digest.
    #[serde(default)]
    pub hex: Option<String>,
    #[serde(default)]
    pub truncated: bool,
    pub ms: u64,
}

impl CapturedResp {
    pub fn hdr(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn ctype(&self) -> &str {
        self.hdr("content-type").unwrap_or("")
    }
    pub fn body_preview(&self) -> String {
        if let Some(t) = &self.text {
            return t.clone();
        }
        if let Some(h) = &self.hex {
            return h.clone();
        }
        String::new()
    }
}

// -------------------------------------------------------------- diff model

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    Identical,
    Cosmetic,
    Semantic,
    Breaking,
}

impl Class {
    pub fn id(self) -> &'static str {
        match self {
            Class::Identical => "identical",
            Class::Cosmetic => "cosmetic",
            Class::Semantic => "semantic",
            Class::Breaking => "breaking",
        }
    }
    /// Severity drives the tonal edge on a finding; it is not a second axis.
    pub fn sev(self) -> &'static str {
        match self {
            Class::Identical => "ok",
            Class::Cosmetic => "info",
            Class::Semantic => "warn",
            Class::Breaking => "bad",
        }
    }
    pub fn key(self) -> &'static str {
        match self {
            Class::Identical => "shadow.class.identical",
            Class::Cosmetic => "shadow.class.cosmetic",
            Class::Semantic => "shadow.class.semantic",
            Class::Breaking => "shadow.class.breaking",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule id; also the i18n key suffix for the impact sentence.
    pub rule: String,
    pub field: String,
    pub class: Class,
    /// Substituted into the impact sentence in order, so each language keeps
    /// its own word order instead of an English sentence with holes in it.
    pub args: Vec<String>,
}

impl Finding {
    fn new(rule: &str, field: &str, class: Class, args: Vec<String>) -> Finding {
        Finding {
            rule: rule.into(),
            field: field.into(),
            class,
            args,
        }
    }
}

/// How much of the answer was actually comparable. Reported because the honest
/// denominator of a compatibility claim is "fields compared", not "requests
/// sent" — and because it makes the noise list visible instead of implicit.
#[derive(Clone, Copy, Serialize, Deserialize, Default)]
pub struct HdrStats {
    pub comparable: usize,
    pub suppressed: usize,
    pub differing: usize,
}

/// Which pair is being compared. The two sides of a peer diff answer at the
/// same instant; the two sides of a replay answer months apart, so a further
/// set of fields is legitimately allowed to move.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Peer,
    Replay,
}

// -------------------------------------------------------------- noise list

pub struct NoiseEntry {
    pub name: &'static str,
    /// Match `name` as a prefix rather than the whole field name.
    pub prefix: bool,
    /// i18n key for the reason this field is allowed to differ.
    pub why: &'static str,
}

/// Fields two implementations MUST differ on. Reporting these is what turns a
/// compatibility tool into noise nobody reads, so the list is explicit, short,
/// and every entry carries its justification into the UI.
pub const NOISE: &[NoiseEntry] = &[
    NoiseEntry { name: "date", prefix: false, why: "shadow.why.date" },
    NoiseEntry { name: "x-trans-id", prefix: false, why: "shadow.why.transid" },
    NoiseEntry { name: "x-openstack-request-id", prefix: false, why: "shadow.why.reqid" },
    NoiseEntry { name: "x-trans-id-extra", prefix: false, why: "shadow.why.transidextra" },
    NoiseEntry { name: "server", prefix: false, why: "shadow.why.server" },
    NoiseEntry { name: "connection", prefix: false, why: "shadow.why.hopbyhop" },
    NoiseEntry { name: "keep-alive", prefix: false, why: "shadow.why.hopbyhop" },
    NoiseEntry { name: "transfer-encoding", prefix: false, why: "shadow.why.hopbyhop" },
    NoiseEntry { name: "te", prefix: false, why: "shadow.why.hopbyhop" },
    NoiseEntry { name: "upgrade", prefix: false, why: "shadow.why.hopbyhop" },
    NoiseEntry { name: "via", prefix: false, why: "shadow.why.via" },
    NoiseEntry { name: "x-backend-", prefix: true, why: "shadow.why.backend" },
    NoiseEntry { name: "x-auth-token", prefix: false, why: "shadow.why.token" },
    NoiseEntry { name: "x-storage-token", prefix: false, why: "shadow.why.token" },
];

/// Additional fields a replay of the SAME implementation is allowed to move on,
/// because a replay re-creates its fixture and is therefore describing a newer
/// object. These are NOT noise in a peer diff: two implementations holding the
/// same object should agree on when it was written.
pub const NOISE_REPLAY: &[NoiseEntry] = &[
    NoiseEntry { name: "x-timestamp", prefix: false, why: "shadow.why.replayts" },
    NoiseEntry { name: "x-put-timestamp", prefix: false, why: "shadow.why.replayts" },
    NoiseEntry { name: "last-modified", prefix: false, why: "shadow.why.replaymod" },
    // Account totals are named one by one rather than by an `x-account-`
    // prefix, so that `x-account-meta-*` stays comparable: user metadata that
    // stopped round-tripping is the whole point of the tool.
    NoiseEntry { name: "x-account-object-count", prefix: false, why: "shadow.why.replayacct" },
    NoiseEntry { name: "x-account-bytes-used", prefix: false, why: "shadow.why.replayacct" },
    NoiseEntry { name: "x-account-container-count", prefix: false, why: "shadow.why.replayacct" },
    NoiseEntry { name: "x-account-storage-policy-", prefix: true, why: "shadow.why.replayacct" },
];

pub fn noise_reason(name: &str, mode: Mode) -> Option<&'static str> {
    let n = name.trim().to_ascii_lowercase();
    let extra: &[NoiseEntry] = if mode == Mode::Replay { NOISE_REPLAY } else { &[] };
    for e in NOISE.iter().chain(extra.iter()) {
        let hit = if e.prefix {
            n.starts_with(e.name)
        } else {
            n == e.name
        };
        if hit {
            return Some(e.why);
        }
    }
    None
}

/// Headers a client is entitled to rely on; losing one entirely is worse than
/// disagreeing about its value.
const CONTRACT_HDRS: &[&str] = &[
    "etag",
    "content-type",
    "content-length",
    "content-range",
    "accept-ranges",
    "x-timestamp",
    "last-modified",
    "x-container-object-count",
    "x-container-bytes-used",
    "x-account-container-count",
    "x-account-object-count",
    "x-account-bytes-used",
    "x-static-large-object",
    "x-object-manifest",
    "x-delete-at",
    "allow",
    "retry-after",
    "www-authenticate",
];

fn is_meta(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("x-object-meta-")
        || n.starts_with("x-container-meta-")
        || n.starts_with("x-account-meta-")
}

fn meta_suffix(name: &str) -> &str {
    for p in ["x-object-meta-", "x-container-meta-", "x-account-meta-"] {
        if name.len() > p.len() && name[..p.len()].eq_ignore_ascii_case(p) {
            return &name[p.len()..];
        }
    }
    name
}

/// ETag comparison ignores the weak marker and the quotes only when deciding
/// WHICH finding to raise — the quoting difference is still reported, just as
/// cosmetic rather than as two different digests.
fn etag_core(v: &str) -> &str {
    v.trim().trim_start_matches("W/").trim_matches('"')
}


// --------------------------------------------------------------- diff core

pub fn diff_status(a: u16, b: u16, out: &mut Vec<Finding>) {
    if a == b {
        return;
    }
    let rule = if a / 100 == b / 100 {
        "status.code"
    } else {
        "status.class"
    };
    let class = if a / 100 == b / 100 {
        Class::Semantic
    } else {
        Class::Breaking
    };
    out.push(Finding::new(
        rule,
        "status",
        class,
        vec![a.to_string(), b.to_string()],
    ));
}

/// Header-by-header, with the noise list applied first so a suppressed field
/// never even counts toward the comparable surface.
pub fn diff_headers(
    a: &[(String, String)],
    b: &[(String, String)],
    mode: Mode,
    out: &mut Vec<Finding>,
) -> HdrStats {
    diff_headers_skipping(a, b, mode, &[], out)
}

/// `skip` names fields this case has already compared by another route.
/// Reporting them again would state the same fact twice — and would raise a
/// finding even where the structural comparison found nothing, which is the
/// exact failure the noise list exists to prevent.
pub fn diff_headers_skipping(
    a: &[(String, String)],
    b: &[(String, String)],
    mode: Mode,
    skip: &[&str],
    out: &mut Vec<Finding>,
) -> HdrStats {
    // Lower-cased key -> (original name, value). Duplicate sends of the same
    // field are joined the way a client library would see them.
    let index = |hs: &[(String, String)]| -> BTreeMap<String, (String, String)> {
        let mut m: BTreeMap<String, (String, String)> = BTreeMap::new();
        for (k, v) in hs {
            let lk = k.to_ascii_lowercase();
            match m.get_mut(&lk) {
                Some(slot) => {
                    slot.1.push_str(", ");
                    slot.1.push_str(v);
                }
                None => {
                    m.insert(lk, (k.clone(), v.clone()));
                }
            }
        }
        m
    };
    let (ma, mb) = (index(a), index(b));
    let keys: BTreeSet<&String> = ma.keys().chain(mb.keys()).collect();

    let mut st = HdrStats::default();
    for k in keys {
        if noise_reason(k, mode).is_some() || skip.contains(&k.as_str()) {
            st.suppressed += 1;
            continue;
        }
        st.comparable += 1;
        let before = out.len();
        match (ma.get(k), mb.get(k)) {
            (Some((na, va)), Some((nb, vb))) => {
                if na != nb {
                    let (rule, class) = if is_meta(k) {
                        ("meta.key_case", Class::Semantic)
                    } else {
                        ("hdr.case", Class::Cosmetic)
                    };
                    out.push(Finding::new(rule, na, class, vec![na.clone(), nb.clone()]));
                }
                if va != vb {
                    diff_header_value(k, na, va, vb, out);
                }
            }
            (Some((na, _)), None) | (None, Some((na, _))) => {
                let class = if is_meta(k) || CONTRACT_HDRS.contains(&k.as_str()) {
                    Class::Breaking
                } else {
                    Class::Semantic
                };
                let rule = if is_meta(k) { "meta.missing" } else { "hdr.missing" };
                let side = if ma.contains_key(k) { "A" } else { "B" };
                out.push(Finding::new(
                    rule,
                    na,
                    class,
                    vec![na.clone(), side.to_string()],
                ));
            }
            (None, None) => {}
        }
        if out.len() > before {
            st.differing += 1;
        }
    }
    st
}

fn diff_header_value(lk: &str, name: &str, va: &str, vb: &str, out: &mut Vec<Finding>) {
    if lk == "etag" {
        if etag_core(va) == etag_core(vb) {
            out.push(Finding::new(
                "etag.quoting",
                name,
                Class::Cosmetic,
                vec![va.into(), vb.into()],
            ));
        } else {
            out.push(Finding::new(
                "etag.value",
                name,
                Class::Breaking,
                vec![va.into(), vb.into()],
            ));
        }
        return;
    }
    if lk == "content-type" {
        out.push(Finding::new(
            "ctype.value",
            name,
            Class::Semantic,
            vec![va.into(), vb.into()],
        ));
        return;
    }
    if lk == "content-range" {
        out.push(Finding::new(
            "range.boundary",
            name,
            Class::Breaking,
            vec!["?".into(), "?".into(), va.into(), vb.into()],
        ));
        return;
    }
    if is_meta(lk) {
        out.push(Finding::new(
            "meta.value",
            name,
            Class::Breaking,
            vec![meta_suffix(name).into(), va.into(), vb.into()],
        ));
        return;
    }
    out.push(Finding::new(
        "hdr.value",
        name,
        Class::Semantic,
        vec![name.into(), va.into(), vb.into()],
    ));
}

// ------------------------------------------------------------ listing diff

#[derive(Clone, Debug, PartialEq)]
pub struct ListEntry {
    pub name: String,
    pub fields: BTreeMap<String, String>,
}

/// A container listing, in whichever of its two shapes came back. Returns None
/// when the body is not a listing at all, so an error body is never silently
/// diffed as if it were one.
pub fn parse_listing(ctype: &str, body: &str) -> Option<Vec<ListEntry>> {
    let t = body.trim();
    if ctype.contains("json") || t.starts_with('[') {
        let v: serde_json::Value = serde_json::from_str(t).ok()?;
        let arr = v.as_array()?;
        let mut out = Vec::new();
        for it in arr {
            let obj = it.as_object()?;
            let name = obj
                .get("name")
                .or_else(|| obj.get("subdir"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let mut fields = BTreeMap::new();
            for (k, v) in obj {
                if k == "name" || k == "subdir" {
                    continue;
                }
                fields.insert(
                    k.clone(),
                    match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    },
                );
            }
            out.push(ListEntry { name, fields });
        }
        return Some(out);
    }
    if ctype.starts_with("text/plain") {
        if t.is_empty() {
            return Some(Vec::new());
        }
        return Some(
            t.lines()
                .map(|l| ListEntry {
                    name: l.to_string(),
                    fields: BTreeMap::new(),
                })
                .collect(),
        );
    }
    None
}

/// Fields inside a listing that a replay is allowed to move on, for the same
/// reason `NOISE_REPLAY` exists: the fixture was re-created.
const LIST_VOLATILE_REPLAY: &[&str] = &["last_modified"];

/// Aggregates on a container row of an ACCOUNT listing. The same field name on
/// an object row means the object's own size, which is never volatile — the
/// row's shape is what tells the two apart.
const LIST_VOLATILE_REPLAY_CONTAINER: &[&str] = &["bytes", "count", "last_modified"];

fn is_container_row(e: &ListEntry) -> bool {
    e.fields.contains_key("count")
}

/// Membership and order are separate findings on purpose. A listing that is
/// merely out of order breaks marker pagination; one that is missing an entry
/// loses data. Collapsing them into "the listing differs" throws away the only
/// distinction an integrator cares about.
pub fn diff_listing(a: &[ListEntry], b: &[ListEntry], mode: Mode, out: &mut Vec<Finding>) {
    let sa: BTreeSet<&str> = a.iter().map(|e| e.name.as_str()).collect();
    let sb: BTreeSet<&str> = b.iter().map(|e| e.name.as_str()).collect();

    let only: Vec<String> = sa
        .symmetric_difference(&sb)
        .map(|s| (*s).to_string())
        .collect();
    if !only.is_empty() {
        let shown: Vec<String> = only.iter().take(6).cloned().collect();
        let mut label = shown.join(", ");
        if only.len() > shown.len() {
            label.push_str(&format!(", +{}", only.len() - shown.len()));
        }
        out.push(Finding::new(
            "listing.membership",
            "listing",
            Class::Breaking,
            vec![only.len().to_string(), label],
        ));
    } else if a.len() != b.len() {
        // Same names, different counts: a duplicate entry on one side.
        out.push(Finding::new(
            "listing.count",
            "listing",
            Class::Breaking,
            vec![a.len().to_string(), b.len().to_string()],
        ));
    } else {
        // Order is only meaningful once membership matches; otherwise the first
        // divergence is just the missing entry reported a second time.
        if let Some(i) = a.iter().zip(b.iter()).position(|(x, y)| x.name != y.name) {
            out.push(Finding::new(
                "listing.order",
                "listing",
                Class::Semantic,
                vec![a.len().to_string(), (i + 1).to_string()],
            ));
        }
    }

    let bi: BTreeMap<&str, &ListEntry> = b.iter().map(|e| (e.name.as_str(), e)).collect();
    for ea in a {
        let Some(eb) = bi.get(ea.name.as_str()) else {
            continue;
        };
        let keys: BTreeSet<&String> = ea.fields.keys().chain(eb.fields.keys()).collect();
        for k in keys {
            let volatile = if is_container_row(ea) {
                LIST_VOLATILE_REPLAY_CONTAINER
            } else {
                LIST_VOLATILE_REPLAY
            };
            if mode == Mode::Replay && volatile.contains(&k.as_str()) {
                continue;
            }
            let va = ea.fields.get(k).map(|s| s.as_str()).unwrap_or("");
            let vb = eb.fields.get(k).map(|s| s.as_str()).unwrap_or("");
            if va != vb {
                out.push(Finding::new(
                    "listing.field",
                    k,
                    Class::Semantic,
                    vec![k.clone(), ea.name.clone(), va.into(), vb.into()],
                ));
            }
        }
    }
}

// -------------------------------------------------------------- body/range

/// Range answers are judged on the three things a resumable download depends
/// on: the status, the declared window, and how many bytes actually arrived.
pub fn diff_range(a: &CapturedResp, b: &CapturedResp, out: &mut Vec<Finding>) {
    if a.status != b.status {
        out.push(Finding::new(
            "range.status",
            "status",
            Class::Breaking,
            vec![a.status.to_string(), b.status.to_string()],
        ));
    }
    let ra = a.hdr("content-range").unwrap_or("-").to_string();
    let rb = b.hdr("content-range").unwrap_or("-").to_string();
    if a.len != b.len || ra != rb {
        out.push(Finding::new(
            "range.boundary",
            "range",
            Class::Breaking,
            vec![a.len.to_string(), b.len.to_string(), ra, rb],
        ));
    }
}

pub fn diff_body(a: &CapturedResp, b: &CapturedResp, out: &mut Vec<Finding>) {
    if a.md5 == b.md5 && a.len == b.len {
        return;
    }
    // Two refusals are allowed to word themselves differently: that is a
    // wording difference, not different content. When the codes also differ,
    // the status finding already carries the real defect and calling the body
    // breaking as well would count the same problem twice.
    if a.status >= 400 && b.status >= 400 {
        let (ta, tb) = (a.body_preview(), b.body_preview());
        out.push(Finding::new(
            "body.error",
            "body",
            Class::Cosmetic,
            vec![clip(&ta, 120), clip(&tb, 120)],
        ));
        return;
    }
    out.push(Finding::new(
        "body.bytes",
        "body",
        Class::Breaking,
        vec![
            a.len.to_string(),
            b.len.to_string(),
            clip(&a.md5, 12),
            clip(&b.md5, 12),
        ],
    ));
}

fn clip(s: &str, n: usize) -> String {
    let t: String = s.chars().filter(|c| *c != '\n' && *c != '\r').collect();
    if t.chars().count() <= n {
        return t;
    }
    let head: String = t.chars().take(n).collect();
    format!("{head}…")
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CaseDiff {
    pub class: Class,
    pub findings: Vec<Finding>,
    pub hdr: HdrStats,
}

/// The whole comparison for one request. `family` selects which body-shaped
/// comparison applies, because "the bodies differ" means something different
/// for a listing, a byte range and an error page.
pub fn diff_case(family: &str, a: &CapturedResp, b: &CapturedResp, mode: Mode) -> CaseDiff {
    let mut f: Vec<Finding> = Vec::new();
    if family == "range" {
        diff_range(a, b, &mut f);
    } else {
        diff_status(a.status, b.status, &mut f);
    }

    let la = parse_listing(a.ctype(), &a.body_preview());
    let lb = parse_listing(b.ctype(), &b.body_preview());
    let structural = (family == "listing" || family == "convergence")
        && la.is_some()
        && lb.is_some();
    // Two fields get compared by a route of their own, so the header pass must
    // leave them alone: Content-Length restates a listing body that is about to
    // be walked entry by entry, and Content-Range is the window `diff_range`
    // already judged. Comparing either twice turns one difference into two.
    let skip: &[&str] = if structural {
        &["content-length"]
    } else if family == "range" {
        &["content-range"]
    } else {
        &[]
    };
    let hdr = diff_headers_skipping(&a.headers, &b.headers, mode, skip, &mut f);

    match (la, lb) {
        (Some(la), Some(lb)) if structural => diff_listing(&la, &lb, mode, &mut f),
        _ if family == "range" => {
            // Content already judged by the window and the digest above; a
            // second body finding would report the same byte twice.
            if a.md5 != b.md5 && a.len == b.len {
                diff_body(a, b, &mut f);
            }
        }
        _ => diff_body(a, b, &mut f),
    }

    // A Content-Range finding raised from the header pass has no lengths in it;
    // fill them from the responses so the sentence carries real numbers.
    for x in f.iter_mut() {
        if x.rule == "range.boundary" && x.args.len() == 4 && x.args[0] == "?" {
            x.args[0] = a.len.to_string();
            x.args[1] = b.len.to_string();
        }
    }
    // The same range disagreement can surface from both passes; keep one.
    dedup(&mut f);

    let class = f.iter().map(|x| x.class).max().unwrap_or(Class::Identical);
    CaseDiff {
        class,
        findings: f,
        hdr,
    }
}

fn dedup(f: &mut Vec<Finding>) {
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    f.retain(|x| seen.insert((x.rule.clone(), x.field.to_ascii_lowercase())));
}


// ------------------------------------------------------------ request set

/// Scratch containers this tool owns outright. Nothing else is ever written
/// to, and both are removed when a run finishes.
const C_MAIN: &str = "shadow-probe";
const C_EMPTY: &str = "shadow-probe-empty";
const C_ABSENT: &str = "shadow-probe-absent";
const O_BIN: &str = "probe.bin";
const O_META: &str = "meta-case.txt";
const O_EPH: &str = "ephemeral.txt";
const PROBE_LEN: u64 = 4096;

/// A readable, deterministic body: `bytes=0-0` returns "0" and `bytes=-1`
/// returns "f", so a boundary finding is evidence a human can check rather
/// than two digests to take on trust.
fn probe_body() -> String {
    "0123456789abcdef".repeat(256)
}

pub struct Case {
    pub id: &'static str,
    pub family: &'static str,
    pub spec: ReqSpec,
}

fn q(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn get(sub: String, query: Vec<(String, String)>, headers: Vec<(String, String)>) -> ReqSpec {
    ReqSpec {
        method: "GET".into(),
        sub,
        query,
        headers,
        body: None,
        bad_token: false,
    }
}

/// The shipped request set. Every case is a behaviour an integrator has
/// actually been bitten by; the families are the ones named in the brief.
pub fn request_set() -> Vec<Case> {
    let main = format!("/{C_MAIN}");
    let bin = format!("/{C_MAIN}/{O_BIN}");
    let meta = format!("/{C_MAIN}/{O_META}");
    vec![
        // ---- listings, including the empty-container content type ----
        Case { id: "listing.empty.json", family: "listing",
            spec: get(format!("/{C_EMPTY}"), q(&[("format", "json")]), vec![]) },
        Case { id: "listing.empty.plain", family: "listing",
            spec: get(format!("/{C_EMPTY}"), vec![], vec![]) },
        Case { id: "listing.json", family: "listing",
            spec: get(main.clone(), q(&[("format", "json")]), vec![]) },
        Case { id: "listing.plain", family: "listing",
            spec: get(main.clone(), vec![], vec![]) },
        Case { id: "listing.limit", family: "listing",
            spec: get(main.clone(), q(&[("format", "json"), ("limit", "1")]), vec![]) },
        Case { id: "listing.marker", family: "listing",
            spec: get(main.clone(), q(&[("format", "json"), ("marker", O_BIN)]), vec![]) },
        Case { id: "listing.prefix", family: "listing",
            spec: get(main.clone(), q(&[("format", "json"), ("prefix", "probe")]), vec![]) },
        Case { id: "listing.delimiter", family: "listing",
            spec: get(main.clone(), q(&[("format", "json"), ("delimiter", "/")]), vec![]) },
        Case { id: "listing.account", family: "listing",
            spec: get(String::new(), q(&[("format", "json"), ("prefix", "shadow-probe")]), vec![]) },
        // ---- metadata, and the case of the key ----
        Case { id: "meta.object.head", family: "meta",
            spec: ReqSpec { method: "HEAD".into(), sub: meta.clone(), ..Default::default() } },
        Case { id: "meta.object.get", family: "meta",
            spec: get(meta.clone(), vec![], vec![]) },
        Case { id: "meta.container.head", family: "meta",
            spec: ReqSpec { method: "HEAD".into(), sub: main.clone(), ..Default::default() } },
        Case { id: "meta.account.head", family: "meta",
            spec: ReqSpec { method: "HEAD".into(), sub: String::new(), ..Default::default() } },
        // ---- ETag ----
        Case { id: "etag.object.get", family: "etag",
            spec: get(bin.clone(), vec![], vec![]) },
        Case { id: "etag.object.head", family: "etag",
            spec: ReqSpec { method: "HEAD".into(), sub: bin.clone(), ..Default::default() } },
        Case { id: "etag.if.none.match", family: "etag",
            spec: get(bin.clone(), vec![], h(&[("If-None-Match", "\"0f\"")])) },
        // ---- byte-range boundaries ----
        Case { id: "range.first.byte", family: "range",
            spec: get(bin.clone(), vec![], h(&[("Range", "bytes=0-0")])) },
        Case { id: "range.last.byte", family: "range",
            spec: get(bin.clone(), vec![], h(&[("Range", "bytes=-1")])) },
        Case { id: "range.tail", family: "range",
            spec: get(bin.clone(), vec![], h(&[("Range", "bytes=4090-")])) },
        Case { id: "range.whole", family: "range",
            spec: get(bin.clone(), vec![], h(&[("Range", "bytes=0-4095")])) },
        Case { id: "range.past.end", family: "range",
            spec: get(bin.clone(), vec![], h(&[("Range", "bytes=4000-99999")])) },
        Case { id: "range.unsatisfiable", family: "range",
            spec: get(bin.clone(), vec![], h(&[("Range", "bytes=99999-100000")])) },
        Case { id: "range.multi", family: "range",
            spec: get(bin.clone(), vec![], h(&[("Range", "bytes=0-9,4086-4095")])) },
        Case { id: "range.malformed", family: "range",
            spec: get(bin.clone(), vec![], h(&[("Range", "widgets=0-1")])) },
        // ---- refusals ----
        Case { id: "error.object.missing", family: "error",
            spec: get(format!("/{C_MAIN}/nothing-here"), vec![], vec![]) },
        Case { id: "error.container.missing", family: "error",
            spec: get(format!("/{C_ABSENT}"), q(&[("format", "json")]), vec![]) },
        Case { id: "error.put.no.container", family: "error",
            spec: ReqSpec { method: "PUT".into(), sub: format!("/{C_ABSENT}/x"),
                body: Some("x".into()), ..Default::default() } },
        Case { id: "error.etag.mismatch", family: "error",
            spec: ReqSpec { method: "PUT".into(), sub: format!("/{C_MAIN}/etag-mismatch.txt"),
                headers: h(&[("ETag", "00000000000000000000000000000000")]),
                body: Some("mismatch".into()), ..Default::default() } },
        Case { id: "error.container.not.empty", family: "error",
            spec: ReqSpec { method: "DELETE".into(), sub: main.clone(), ..Default::default() } },
        Case { id: "error.unauthorized", family: "error",
            spec: ReqSpec { method: "GET".into(), sub: main.clone(),
                query: q(&[("format", "json")]), bad_token: true, ..Default::default() } },
    ]
}

// ------------------------------------------------------------- corpus file

#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub v: u32,
    pub run: String,
    pub ts: u64,
    #[serde(rename = "case")]
    pub case_id: String,
    pub family: String,
    /// "single" until a second endpoint exists. Never inferred at render time:
    /// a record must carry, forever, whether it was ever compared to anything.
    pub mode: String,
    pub req: ReqSpec,
    pub a: CapturedResp,
    #[serde(default)]
    pub b: Option<CapturedResp>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub class: Option<Class>,
    #[serde(default)]
    pub hdr: HdrStats,
    #[serde(default)]
    pub converge_ms: Option<u64>,
    #[serde(default)]
    pub converged: Option<bool>,
    #[serde(default)]
    pub polls: Option<u32>,
}

fn corpus_path() -> PathBuf {
    cfg().root.join("corpus.jsonl")
}
fn replay_path() -> PathBuf {
    cfg().root.join("replay.jsonl")
}

fn append_line(path: &PathBuf, line: &str) -> Result<(), String> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("corpus directory: {e}"))?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("corpus open: {e}"))?;
    writeln!(f, "{line}").map_err(|e| format!("corpus write: {e}"))
}

fn read_lines(path: &PathBuf) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect()
}

pub struct RunView {
    pub run: String,
    pub ts: u64,
    pub mode: String,
    pub records: Vec<Record>,
}

pub struct Corpus {
    /// Newest first.
    pub runs: Vec<RunView>,
    pub records_total: usize,
    pub bytes: u64,
    pub first_ts: u64,
    pub last_ts: u64,
    pub replays: Vec<ReplayRun>,
}

pub fn load_corpus() -> Corpus {
    let path = corpus_path();
    let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let mut by_run: BTreeMap<String, RunView> = BTreeMap::new();
    let mut total = 0usize;
    let (mut first, mut last) = (0u64, 0u64);
    for line in read_lines(&path) {
        let Ok(r) = serde_json::from_str::<Record>(&line) else {
            continue;
        };
        total += 1;
        if first == 0 || r.ts < first {
            first = r.ts;
        }
        if r.ts > last {
            last = r.ts;
        }
        let e = by_run.entry(r.run.clone()).or_insert_with(|| RunView {
            run: r.run.clone(),
            ts: r.ts,
            mode: r.mode.clone(),
            records: Vec::new(),
        });
        if r.ts < e.ts {
            e.ts = r.ts;
        }
        e.records.push(r);
    }
    let mut runs: Vec<RunView> = by_run.into_values().collect();
    runs.sort_by(|a, b| b.ts.cmp(&a.ts));

    let mut replays: Vec<ReplayRun> = read_lines(&replay_path())
        .iter()
        .filter_map(|l| serde_json::from_str::<ReplayRun>(l).ok())
        .collect();
    replays.sort_by(|a, b| b.ts.cmp(&a.ts));

    Corpus {
        runs,
        records_total: total,
        bytes,
        first_ts: first,
        last_ts: last,
        replays,
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ReplayItem {
    #[serde(rename = "case")]
    pub case_id: String,
    pub family: String,
    /// "holds" | "drifted" | "error"
    pub verdict: String,
    pub class: Class,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ReplayRun {
    pub v: u32,
    pub run: String,
    pub base: String,
    pub ts: u64,
    pub total: usize,
    pub holds: usize,
    pub drifted: usize,
    pub errors: usize,
    pub items: Vec<ReplayItem>,
}

// ---------------------------------------------------------------- execution

/// One request, one recorded answer. Both sides go through this same function
/// so neither gets a retry, a redirect follow or a header the other did not:
/// a differential tester that is asymmetric measures itself.
async fn exec(
    http: &reqwest::Client,
    base: &str,
    token: &str,
    spec: &ReqSpec,
) -> Result<CapturedResp, String> {
    use md5::{Digest, Md5};
    let method = reqwest::Method::from_bytes(spec.method.as_bytes())
        .map_err(|_| format!("bad method {}", spec.method))?;
    let url = format!("{}{}", base.trim_end_matches('/'), spec.sub);
    let mut req = http.request(method, &url).timeout(std::time::Duration::from_secs(30));
    if !spec.query.is_empty() {
        req = req.query(&spec.query);
    }
    req = req.header(
        "X-Auth-Token",
        if spec.bad_token {
            "shadow-probe-deliberately-invalid"
        } else {
            token
        },
    );
    for (k, v) in &spec.headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some(b) = &spec.body {
        req = req.body(b.clone());
    }
    let t0 = std::time::Instant::now();
    let resp = req.send().await.map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or("<binary>").to_string(),
            )
        })
        .collect();
    let body = resp
        .bytes()
        .await
        .map_err(|e| format!("body read failed: {e}"))?;
    let ms = t0.elapsed().as_millis() as u64;

    let md5 = hex::encode(Md5::digest(&body));
    let ctype = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.to_ascii_lowercase())
        .unwrap_or_default();
    let textish = ctype.starts_with("text/")
        || ctype.contains("json")
        || ctype.contains("xml")
        || ctype.is_empty();
    const CAP: usize = 2048;
    let (text, hex_head, truncated) = if textish {
        match std::str::from_utf8(&body) {
            Ok(s) if s.len() <= CAP => (Some(s.to_string()), None, false),
            Ok(s) => {
                let cut = s
                    .char_indices()
                    .map(|(i, _)| i)
                    .take_while(|i| *i <= CAP)
                    .last()
                    .unwrap_or(0);
                (Some(s[..cut].to_string()), None, true)
            }
            Err(_) => (None, Some(hex::encode(&body[..body.len().min(64)])), body.len() > 64),
        }
    } else {
        (None, Some(hex::encode(&body[..body.len().min(64)])), body.len() > 64)
    };

    Ok(CapturedResp {
        status,
        headers,
        len: body.len() as u64,
        md5,
        text,
        hex: hex_head,
        truncated,
        ms,
    })
}

/// Both endpoints, side by side. `None` for B whenever no peer is configured —
/// never a synthesised second answer.
struct Sides {
    a_base: String,
    a_token: String,
    b: Option<(String, String)>,
}

async fn sides(state: &Arc<AppState>, sid: &str, sess: &session::Session) -> Result<Sides, String> {
    // One real call first, so an expired token is refreshed before the run
    // rather than turning the first case into a spurious 401 finding.
    let _ = swift::call(state, sid, reqwest::Method::HEAD, "", &[], &[], None).await;
    let live = state
        .sessions
        .get(sid)
        .ok_or_else(|| "session expired".to_string())?;
    let b = if peer_configured() {
        let c = cfg();
        match swift::auth(
            &state.http,
            &c.peer_auth,
            &c.peer_base,
            &sess.tenant,
            &sess.user,
            &sess.key,
        )
        .await
        {
            Ok((tok, url)) => Some((url, tok)),
            Err(e) => return Err(format!("second endpoint refused the login: {e}")),
        }
    } else {
        None
    };
    Ok(Sides {
        a_base: live.storage_url,
        a_token: live.token,
        b,
    })
}

async fn setup(http: &reqwest::Client, base: &str, token: &str) -> Result<(), String> {
    let put = |sub: String, hdrs: Vec<(String, String)>, body: Option<String>| ReqSpec {
        method: "PUT".into(),
        sub,
        query: vec![],
        headers: hdrs,
        body,
        bad_token: false,
    };
    // Leftovers from an interrupted run would change what the listings say.
    teardown(http, base, token).await;
    for spec in [
        put(format!("/{C_MAIN}"), vec![], None),
        put(format!("/{C_EMPTY}"), vec![], None),
        put(
            format!("/{C_MAIN}/{O_BIN}"),
            h(&[("Content-Type", "application/octet-stream")]),
            Some(probe_body()),
        ),
        put(
            format!("/{C_MAIN}/{O_META}"),
            h(&[
                ("Content-Type", "text/plain"),
                ("X-Object-Meta-CamelCase", "MixedValue"),
                ("X-Object-Meta-lower", "plain"),
                ("X-Object-Meta-UPPER", "SHOUT"),
            ]),
            Some("case\n".into()),
        ),
        put(format!("/{C_MAIN}/{O_EPH}"), vec![], Some("ephemeral\n".into())),
    ] {
        let r = exec(http, base, token, &spec).await?;
        if r.status >= 300 {
            return Err(format!("fixture {} answered {}", spec.sub, r.status));
        }
    }
    Ok(())
}

async fn teardown(http: &reqwest::Client, base: &str, token: &str) {
    let del = |sub: String| ReqSpec {
        method: "DELETE".into(),
        sub,
        ..Default::default()
    };
    for sub in [
        format!("/{C_MAIN}/{O_BIN}"),
        format!("/{C_MAIN}/{O_META}"),
        format!("/{C_MAIN}/{O_EPH}"),
        format!("/{C_MAIN}/etag-mismatch.txt"),
        format!("/{C_MAIN}"),
        format!("/{C_EMPTY}"),
    ] {
        let _ = exec(http, base, token, &del(sub)).await;
    }
}

/// How long after a DELETE the container listing stops naming the object.
/// Measured, not assumed: the poll count and the wall time both go into the
/// record so the number can be checked rather than believed.
async fn converge_probe(
    http: &reqwest::Client,
    base: &str,
    token: &str,
) -> Result<(CapturedResp, u64, u32, bool), String> {
    let del = ReqSpec {
        method: "DELETE".into(),
        sub: format!("/{C_MAIN}/{O_EPH}"),
        ..Default::default()
    };
    exec(http, base, token, &del).await?;
    let listing = get(
        format!("/{C_MAIN}"),
        q(&[("format", "json")]),
        vec![],
    );
    let t0 = std::time::Instant::now();
    let mut polls = 0u32;
    let mut last = exec(http, base, token, &listing).await?;
    loop {
        polls += 1;
        let gone = parse_listing(last.ctype(), &last.body_preview())
            .map(|es| !es.iter().any(|e| e.name == O_EPH))
            .unwrap_or(false);
        let ms = t0.elapsed().as_millis() as u64;
        if gone {
            return Ok((last, ms, polls, true));
        }
        if ms > 8000 {
            return Ok((last, ms, polls, false));
        }
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        last = exec(http, base, token, &listing).await?;
    }
}


// ------------------------------------------------------- capture / replay

/// One run at a time. Two captures interleaving would each see the other's
/// fixture and record listings that never existed.
static BUSY: AtomicBool = AtomicBool::new(false);

struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::SeqCst);
    }
}

pub struct RunSummary {
    pub run: String,
    pub mode: String,
    pub cases: usize,
    pub breaking: usize,
    pub semantic: usize,
    pub cosmetic: usize,
}

async fn capture(
    state: &Arc<AppState>,
    sid: &str,
    sess: &session::Session,
) -> Result<RunSummary, String> {
    let s = sides(state, sid, sess).await?;
    let http = &state.http;
    let mode = if s.b.is_some() { "dual" } else { "single" };
    let run = format!("r{}-{}", crate::util::now_secs(), crate::util::rand_hex(3));
    let ts = crate::util::now_secs();

    setup(http, &s.a_base, &s.a_token).await?;
    if let Some((bb, bt)) = &s.b {
        setup(http, bb, bt).await?;
    }

    let mut summary = RunSummary {
        run: run.clone(),
        mode: mode.into(),
        cases: 0,
        breaking: 0,
        semantic: 0,
        cosmetic: 0,
    };

    for c in request_set() {
        let a = match exec(http, &s.a_base, &s.a_token, &c.spec).await {
            Ok(r) => r,
            Err(e) => return Err(format!("{}: {e}", c.id)),
        };
        let b = match &s.b {
            Some((bb, bt)) => Some(exec(http, bb, bt, &c.spec).await?),
            None => None,
        };
        // With one side only there is nothing to compare, but the comparable
        // surface is still a real, countable property of what was captured.
        let (findings, class, hdr) = match b.as_ref() {
            Some(bb) => {
                let d = diff_case(c.family, &a, bb, Mode::Peer);
                (d.findings, Some(d.class), d.hdr)
            }
            None => (Vec::new(), None, unpaired_stats(&a)),
        };
        match class {
            Some(Class::Breaking) => summary.breaking += 1,
            Some(Class::Semantic) => summary.semantic += 1,
            Some(Class::Cosmetic) => summary.cosmetic += 1,
            _ => {}
        }
        summary.cases += 1;
        let rec = Record {
            v: 1,
            run: run.clone(),
            ts,
            case_id: c.id.into(),
            family: c.family.into(),
            mode: mode.into(),
            req: c.spec,
            a,
            b,
            findings,
            class,
            hdr,
            converge_ms: None,
            converged: None,
            polls: None,
        };
        append_line(&corpus_path(), &serde_json::to_string(&rec).unwrap_or_default())?;
    }

    // Convergence is measured last: it consumes the ephemeral object.
    let (a_list, a_ms, a_polls, a_ok) = converge_probe(http, &s.a_base, &s.a_token).await?;
    let mut findings: Vec<Finding> = Vec::new();
    let mut class = None;
    let mut hdr = unpaired_stats(&a_list);
    let b_list = match &s.b {
        Some((bb, bt)) => {
            let (bl, b_ms, _, b_ok) = converge_probe(http, bb, bt).await?;
            let d = diff_case("convergence", &a_list, &bl, Mode::Peer);
            findings = d.findings;
            hdr = d.hdr;
            if !a_ok || !b_ok {
                findings.push(Finding::new(
                    "conv.stuck",
                    "listing",
                    Class::Breaking,
                    vec!["8 s".into()],
                ));
            } else if a_ms.max(b_ms) > 500 && a_ms.max(b_ms) > 3 * a_ms.min(b_ms).max(1) {
                findings.push(Finding::new(
                    "conv.gap",
                    "listing",
                    Class::Semantic,
                    vec![format!("{a_ms} ms"), format!("{b_ms} ms")],
                ));
            }
            class = Some(findings.iter().map(|f| f.class).max().unwrap_or(Class::Identical));
            Some(bl)
        }
        None => None,
    };
    match class {
        Some(Class::Breaking) => summary.breaking += 1,
        Some(Class::Semantic) => summary.semantic += 1,
        Some(Class::Cosmetic) => summary.cosmetic += 1,
        _ => {}
    }
    summary.cases += 1;
    let rec = Record {
        v: 1,
        run: run.clone(),
        ts,
        case_id: "convergence.post.delete".into(),
        family: "convergence".into(),
        mode: mode.into(),
        req: get(format!("/{C_MAIN}"), q(&[("format", "json")]), vec![]),
        a: a_list,
        b: b_list,
        findings,
        class,
        hdr,
        converge_ms: Some(a_ms),
        converged: Some(a_ok),
        polls: Some(a_polls),
    };
    append_line(&corpus_path(), &serde_json::to_string(&rec).unwrap_or_default())?;

    teardown(http, &s.a_base, &s.a_token).await;
    if let Some((bb, bt)) = &s.b {
        teardown(http, bb, bt).await;
    }
    Ok(summary)
}

/// With one side there is nothing to compare, but "how much of this answer
/// would ever be comparable" is still a fact worth recording — it is the
/// honest denominator the day a second implementation shows up.
fn unpaired_stats(a: &CapturedResp) -> HdrStats {
    let mut st = HdrStats::default();
    for (k, _) in &a.headers {
        if noise_reason(k, Mode::Peer).is_some() {
            st.suppressed += 1;
        } else {
            st.comparable += 1;
        }
    }
    st
}

/// Re-issue every stored request against the cluster as it is now and report
/// which recorded answers still hold. This is the step that makes the corpus a
/// regression suite rather than a log.
async fn replay_run(
    state: &Arc<AppState>,
    sid: &str,
    sess: &session::Session,
    base_run: &str,
) -> Result<ReplayRun, String> {
    let corpus = load_corpus();
    let rv = corpus
        .runs
        .iter()
        .find(|r| base_run.is_empty() || r.run == base_run)
        .ok_or_else(|| "no stored run to replay".to_string())?;

    let s = sides(state, sid, sess).await?;
    let http = &state.http;
    setup(http, &s.a_base, &s.a_token).await?;

    let mut out = ReplayRun {
        v: 1,
        run: format!("p{}-{}", crate::util::now_secs(), crate::util::rand_hex(3)),
        base: rv.run.clone(),
        ts: crate::util::now_secs(),
        total: 0,
        holds: 0,
        drifted: 0,
        errors: 0,
        items: Vec::new(),
    };

    for rec in &rv.records {
        out.total += 1;
        if rec.family == "convergence" {
            let (fresh, ms, _, ok) = match converge_probe(http, &s.a_base, &s.a_token).await {
                Ok(v) => v,
                Err(e) => {
                    out.errors += 1;
                    out.items.push(ReplayItem {
                        case_id: rec.case_id.clone(),
                        family: rec.family.clone(),
                        verdict: "error".into(),
                        class: Class::Identical,
                        findings: vec![],
                        error: Some(e),
                    });
                    continue;
                }
            };
            let mut d = diff_case("convergence", &rec.a, &fresh, Mode::Replay);
            let was = rec.converge_ms.unwrap_or(0);
            if !ok {
                d.findings.push(Finding::new(
                    "conv.stuck",
                    "listing",
                    Class::Breaking,
                    vec!["8 s".into()],
                ));
            } else if ms > 500 && ms > 3 * was.max(1) {
                d.findings.push(Finding::new(
                    "conv.gap",
                    "listing",
                    Class::Semantic,
                    vec![format!("{was} ms"), format!("{ms} ms")],
                ));
            }
            let class = d.findings.iter().map(|f| f.class).max().unwrap_or(Class::Identical);
            push_replay(&mut out, rec, class, d.findings);
            continue;
        }
        let fresh = match exec(http, &s.a_base, &s.a_token, &rec.req).await {
            Ok(v) => v,
            Err(e) => {
                out.errors += 1;
                out.items.push(ReplayItem {
                    case_id: rec.case_id.clone(),
                    family: rec.family.clone(),
                    verdict: "error".into(),
                    class: Class::Identical,
                    findings: vec![],
                    error: Some(e),
                });
                continue;
            }
        };
        let d = diff_case(&rec.family, &rec.a, &fresh, Mode::Replay);
        push_replay(&mut out, rec, d.class, d.findings);
    }

    teardown(http, &s.a_base, &s.a_token).await;
    append_line(&replay_path(), &serde_json::to_string(&out).unwrap_or_default())?;
    Ok(out)
}

fn push_replay(out: &mut ReplayRun, rec: &Record, class: Class, findings: Vec<Finding>) {
    // A cosmetic wording change is not a broken promise; anything at or above
    // semantic is the recorded behaviour no longer holding.
    let holds = class <= Class::Cosmetic;
    if holds {
        out.holds += 1;
    } else {
        out.drifted += 1;
    }
    out.items.push(ReplayItem {
        case_id: rec.case_id.clone(),
        family: rec.family.clone(),
        verdict: if holds { "holds".into() } else { "drifted".into() },
        class,
        findings,
        error: None,
    });
}

// ----------------------------------------------------------------- handlers

#[derive(Deserialize, Default)]
pub struct RunQ {
    #[serde(default)]
    pub run: String,
}

/// A browser form submit gets the page back; a script gets JSON. Both work,
/// which is what keeps the two buttons on this page from being decoration
/// with JavaScript switched off.
fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false)
}

// No body extractor: the page's plain form posts urlencoded, scripts may post
// anything or nothing — the run takes no parameters, so read none. (An
// `Option<Json<_>>` here made axum 0.8 reject form posts outright with
// "Expected request with Content-Type: application/json".)
pub async fn run(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (sid, sess) = match lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if BUSY.swap(true, Ordering::SeqCst) {
        return (
            axum::http::StatusCode::CONFLICT,
            Json(json!({ "error": "a shadow run is already in flight" })),
        )
            .into_response();
    }
    let _g = Guard;
    match capture(&state, &sid, &sess).await {
        Ok(s) => {
            if wants_html(&headers) {
                return Redirect::to(&format!("/lab/shadow?run={}", s.run)).into_response();
            }
            Json(json!({
                "run": s.run, "mode": s.mode, "cases": s.cases,
                "breaking": s.breaking, "semantic": s.semantic, "cosmetic": s.cosmetic,
                "peer": peer_configured(),
            }))
            .into_response()
        }
        Err(e) => fail(&headers, &e),
    }
}

pub async fn replay(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<RunQ>,
) -> Response {
    let (sid, sess) = match lab::require_lab_api(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if BUSY.swap(true, Ordering::SeqCst) {
        return (
            axum::http::StatusCode::CONFLICT,
            Json(json!({ "error": "a shadow run is already in flight" })),
        )
            .into_response();
    }
    let _g = Guard;
    match replay_run(&state, &sid, &sess, &q.run).await {
        Ok(r) => {
            if wants_html(&headers) {
                return Redirect::to("/lab/shadow").into_response();
            }
            Json(json!({
                "replay": r.run, "base": r.base, "total": r.total,
                "holds": r.holds, "drifted": r.drifted, "errors": r.errors,
            }))
            .into_response()
        }
        Err(e) => fail(&headers, &e),
    }
}

fn fail(headers: &HeaderMap, e: &str) -> Response {
    if wants_html(headers) {
        return Redirect::to(&format!("/lab/shadow?err={}", crate::util::enc_q(e))).into_response();
    }
    (
        axum::http::StatusCode::BAD_GATEWAY,
        Json(json!({ "error": e })),
    )
        .into_response()
}

pub async fn corpus(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let c = load_corpus();
    Json(json!({
        "peer": peer_configured(),
        "records": c.records_total,
        "bytes": c.bytes,
        "first": c.first_ts,
        "last": c.last_ts,
        "runs": c.runs.iter().map(|r| json!({
            "run": r.run, "ts": r.ts, "mode": r.mode, "cases": r.records.len(),
        })).collect::<Vec<_>>(),
        "replays": c.replays.iter().map(|r| json!({
            "replay": r.run, "base": r.base, "ts": r.ts,
            "total": r.total, "holds": r.holds, "drifted": r.drifted, "errors": r.errors,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}


// ----------------------------------------------------------------- render

/// Substitute evidence into a translated sentence. Arguments are escaped
/// first; the template is our own text, so it stays live markup-free HTML.
fn fill(tpl: &str, args: &[String]) -> String {
    let mut s = tpl.to_string();
    for (i, a) in args.iter().enumerate() {
        s = s.replace(&format!("{{{i}}}"), &esc(a));
    }
    s
}

fn tbl(cols: &[&str], rows: Vec<String>) -> String {
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

fn sec(title: &str, body: String) -> String {
    format!("<h2 class=\"sh-h\">{}</h2>{body}", esc(title))
}

const FAMILIES: &[&str] = &["listing", "meta", "etag", "range", "error", "convergence"];

fn fam_name(lang: &str, f: &str) -> &'static str {
    match f {
        "listing" => i18n::t(lang, "shadow.fam.listing"),
        "meta" => i18n::t(lang, "shadow.fam.meta"),
        "etag" => i18n::t(lang, "shadow.fam.etag"),
        "range" => i18n::t(lang, "shadow.fam.range"),
        "error" => i18n::t(lang, "shadow.fam.error"),
        _ => i18n::t(lang, "shadow.fam.convergence"),
    }
}

fn fam_desc(lang: &str, f: &str) -> &'static str {
    match f {
        "listing" => i18n::t(lang, "shadow.famd.listing"),
        "meta" => i18n::t(lang, "shadow.famd.meta"),
        "etag" => i18n::t(lang, "shadow.famd.etag"),
        "range" => i18n::t(lang, "shadow.famd.range"),
        "error" => i18n::t(lang, "shadow.famd.error"),
        _ => i18n::t(lang, "shadow.famd.convergence"),
    }
}

fn rule_sentence(lang: &str, f: &Finding) -> String {
    let key: &'static str = match f.rule.as_str() {
        "status.class" => "shadow.rule.status.class",
        "status.code" => "shadow.rule.status.code",
        "hdr.missing" => "shadow.rule.hdr.missing",
        "hdr.value" => "shadow.rule.hdr.value",
        "hdr.case" => "shadow.rule.hdr.case",
        "ctype.value" => "shadow.rule.ctype.value",
        "etag.value" => "shadow.rule.etag.value",
        "etag.quoting" => "shadow.rule.etag.quoting",
        "meta.key_case" => "shadow.rule.meta.keycase",
        "meta.missing" => "shadow.rule.meta.missing",
        "meta.value" => "shadow.rule.meta.value",
        "listing.membership" => "shadow.rule.listing.membership",
        "listing.order" => "shadow.rule.listing.order",
        "listing.field" => "shadow.rule.listing.field",
        "listing.count" => "shadow.rule.listing.count",
        "range.status" => "shadow.rule.range.status",
        "range.boundary" => "shadow.rule.range.boundary",
        "body.error" => "shadow.rule.body.error",
        "body.bytes" => "shadow.rule.body.bytes",
        "conv.gap" => "shadow.rule.conv.gap",
        _ => "shadow.rule.conv.stuck",
    };
    fill(i18n::t(lang, key), &f.args)
}

fn finding_block(lang: &str, f: &Finding) -> String {
    format!(
        "<div class=\"sh-find {sev}\"><div class=\"sh-find-h\">{sentence}</div>\
         <div class=\"sh-find-r\">{rule} · {field}</div></div>",
        sev = f.class.sev(),
        sentence = rule_sentence(lang, f),
        rule = esc(&f.rule),
        field = esc(&f.field),
    )
}

/// The matrix: request family down, diff class across. In single-sided mode
/// every case lands in the last column, which is the point — the grid shows
/// exactly how much of the corpus has ever been compared to anything.
fn matrix(lang: &str, rv: &RunView) -> String {
    let classes = [
        Class::Identical,
        Class::Cosmetic,
        Class::Semantic,
        Class::Breaking,
    ];
    let mut head = format!("<th>{}</th>", esc(i18n::t(lang, "shadow.col.family")));
    for c in classes {
        head.push_str(&format!(
            "<th class=\"sh-mx-h {id}\">{n}</th>",
            id = c.id(),
            n = esc(i18n::t(lang, c.key()))
        ));
    }
    head.push_str(&format!(
        "<th class=\"sh-mx-h unpaired\">{}</th>",
        esc(i18n::t(lang, "shadow.class.unpaired"))
    ));

    let mut rows = String::new();
    for fam in FAMILIES {
        let recs: Vec<&Record> = rv.records.iter().filter(|r| r.family == *fam).collect();
        if recs.is_empty() {
            continue;
        }
        let mut cells = String::new();
        for c in classes {
            let n = recs.iter().filter(|r| r.class == Some(c)).count();
            cells.push_str(&cell(n, c.id()));
        }
        let n = recs.iter().filter(|r| r.class.is_none()).count();
        cells.push_str(&cell(n, "unpaired"));
        rows.push_str(&format!(
            "<tr><th class=\"sh-mx-r\"><span>{name}</span><em>{desc}</em></th>{cells}</tr>",
            name = esc(fam_name(lang, fam)),
            desc = esc(fam_desc(lang, fam)),
        ));
    }
    format!(
        "<div class=\"tbl-wrap\"><table class=\"tbl sh-mx\"><thead><tr>{head}</tr></thead>\
         <tbody>{rows}</tbody></table></div>"
    )
}

fn cell(n: usize, id: &str) -> String {
    if n == 0 {
        return "<td class=\"sh-mx-c\"><span class=\"sh-mx-0\">·</span></td>".to_string();
    }
    format!("<td class=\"sh-mx-c {id}\"><span class=\"sh-mx-n\">{n}</span></td>")
}

/// The comparable surface, per family: how many header fields would ever be
/// compared, how many the noise list sets aside, and how many actually differ.
/// It is the same number the compatibility claim rests on, drawn once so the
/// noise list is visible instead of implicit.
fn surface(lang: &str, rv: &RunView) -> String {
    let mut rows = Vec::new();
    let mut data = Vec::new();
    for fam in FAMILIES {
        let recs: Vec<&Record> = rv.records.iter().filter(|r| r.family == *fam).collect();
        if recs.is_empty() {
            continue;
        }
        let comparable: usize = recs.iter().map(|r| r.hdr.comparable).sum();
        let suppressed: usize = recs.iter().map(|r| r.hdr.suppressed).sum();
        let differing: usize = recs.iter().map(|r| r.hdr.differing).sum();
        rows.push(format!(
            "<tr><td>{name}</td><td class=\"num\">{comparable}</td>\
             <td class=\"num\">{suppressed}</td><td class=\"num\">{differing}</td></tr>",
            name = esc(fam_name(lang, fam)),
        ));
        data.push(json!({
            "id": fam, "label": fam_name(lang, fam),
            "comparable": comparable, "suppressed": suppressed, "differing": differing,
        }));
    }
    let payload = serde_json::to_string(&json!({
        "families": data,
        "labels": {
            "compared": i18n::t(lang, "shadow.surface.compared"),
            "suppressed": i18n::t(lang, "shadow.surface.suppressed"),
            "differing": i18n::t(lang, "shadow.surface.differing"),
        }
    }))
    .unwrap_or_else(|_| "{}".into())
    .replace('<', "\\u003c");

    let legend = format!(
        "<div class=\"sh-leg\"><span class=\"sh-leg-i\"><i class=\"ok\"></i>{c}</span>\
         <span class=\"sh-leg-i\"><i class=\"diff\"></i>{d}</span>\
         <span class=\"sh-leg-i\"><i class=\"sup\"></i>{s}</span></div>",
        c = esc(i18n::t(lang, "shadow.surface.compared")),
        d = esc(i18n::t(lang, "shadow.surface.differing")),
        s = esc(i18n::t(lang, "shadow.surface.suppressed")),
    );
    let table = tbl(
        &[
            i18n::t(lang, "shadow.col.family"),
            i18n::t(lang, "shadow.surface.compared"),
            i18n::t(lang, "shadow.surface.suppressed"),
            i18n::t(lang, "shadow.surface.differing"),
        ],
        rows,
    );
    format!(
        "<script type=\"application/json\" id=\"sh-data\">{payload}</script>\
         <div class=\"sh-bars\" id=\"sh-bars\"></div>{legend}{table}"
    )
}

fn raw_block(lang: &str, label: &str, r: &CapturedResp) -> String {
    let mut s = format!("HTTP {}\n", r.status);
    for (k, v) in &r.headers {
        s.push_str(&format!("{k}: {v}\n"));
    }
    s.push('\n');
    let body = r.body_preview();
    if body.is_empty() {
        s.push_str(&format!("({} bytes)\n", r.len));
    } else {
        s.push_str(&body);
        if r.truncated {
            s.push_str(&format!(
                "\n… {}\n",
                i18n::t(lang, "shadow.cases.trunc")
            ));
        }
    }
    format!(
        "<div class=\"sh-raw-h\">{label} · {ms} ms · {bytes} · md5 {md5}</div>\
         <pre class=\"sh-raw\">{body}</pre>",
        label = esc(label),
        ms = r.ms,
        bytes = esc(&fmt_bytes(r.len)),
        md5 = esc(&clip(&r.md5, 12)),
        body = esc(&s),
    )
}

fn case_rows(lang: &str, rv: &RunView) -> String {
    let mut rows = Vec::new();
    for r in &rv.records {
        let cls = match r.class {
            Some(c) => format!(
                "<span class=\"sh-cl {id}\">{n}</span>",
                id = c.id(),
                n = esc(i18n::t(lang, c.key()))
            ),
            None => format!(
                "<span class=\"sh-cl unpaired\">{}</span>",
                esc(i18n::t(lang, "shadow.class.unpaired"))
            ),
        };
        let mut detail = raw_block(lang, i18n::t(lang, "shadow.cases.rawa"), &r.a);
        match &r.b {
            Some(b) => {
                detail.push_str(&raw_block(lang, &peer_label(), b));
            }
            None => detail.push_str(&format!(
                "<p class=\"note\">{}</p>",
                esc(i18n::t(lang, "shadow.cases.nob"))
            )),
        }
        for f in &r.findings {
            detail.push_str(&finding_block(lang, f));
        }
        let extra = match (r.converge_ms, r.converged) {
            (Some(ms), Some(true)) => format!(
                "<div class=\"sh-conv\">{}</div>",
                fill(
                    i18n::t(lang, "shadow.conv.ok"),
                    &[ms.to_string(), r.polls.unwrap_or(0).to_string()]
                )
            ),
            (Some(_), Some(false)) => format!(
                "<div class=\"sh-conv bad\">{}</div>",
                esc(i18n::t(lang, "shadow.conv.stuck"))
            ),
            _ => String::new(),
        };
        rows.push(format!(
            "<tr><td><details><summary><code class=\"sh-cid\">{id}</code></summary>\
             <div class=\"sh-detail\"><div class=\"sh-req\">{line}</div>{extra}{detail}</div>\
             </details></td><td>{fam}</td><td class=\"num\">{status}</td>\
             <td class=\"num\">{ms}</td><td class=\"num\">{n}</td><td>{cls}</td></tr>",
            id = esc(&r.case_id),
            line = esc(&r.req.line()),
            fam = esc(fam_name(lang, &r.family)),
            status = r.a.status,
            ms = r.a.ms,
            n = r.findings.len(),
        ));
    }
    tbl(
        &[
            i18n::t(lang, "shadow.col.case"),
            i18n::t(lang, "shadow.col.family"),
            i18n::t(lang, "shadow.col.status"),
            i18n::t(lang, "shadow.col.ms"),
            i18n::t(lang, "shadow.col.findings"),
            i18n::t(lang, "shadow.col.class"),
        ],
        rows,
    )
}

fn peer_label() -> String {
    cfg().peer_label.clone()
}

fn noise_table(lang: &str) -> String {
    let mut rows = Vec::new();
    for e in NOISE.iter().chain(NOISE_REPLAY.iter()) {
        let scope = if NOISE_REPLAY.iter().any(|x| x.name == e.name && x.why == e.why) {
            i18n::t(lang, "shadow.noise.replayonly")
        } else {
            i18n::t(lang, "shadow.noise.always")
        };
        rows.push(format!(
            "<tr><td><code>{n}{star}</code></td><td>{scope}</td><td>{why}</td></tr>",
            n = esc(e.name),
            star = if e.prefix { "*" } else { "" },
            scope = esc(scope),
            why = esc(i18n::t(lang, e.why)),
        ));
    }
    rows.push(format!(
        "<tr><td><code>content-range</code></td><td>{scope}</td><td>{why}</td></tr>",
        scope = esc(i18n::t(lang, "shadow.noise.rangeonly")),
        why = esc(i18n::t(lang, "shadow.why.crange")),
    ));
    rows.push(format!(
        "<tr><td><code>content-length</code></td><td>{scope}</td><td>{why}</td></tr>",
        scope = esc(i18n::t(lang, "shadow.noise.listingonly")),
        why = esc(i18n::t(lang, "shadow.why.clen")),
    ));
    tbl(
        &[
            i18n::t(lang, "shadow.col.header"),
            i18n::t(lang, "shadow.col.scope"),
            i18n::t(lang, "shadow.col.why"),
        ],
        rows,
    )
}


/// The unknowns, said out loud. A capture path has blind spots, and a report
/// that lists what it measured without listing what it could not is the kind
/// of report that gets believed further than it deserves.
fn limits_section(lang: &str) -> String {
    let mut items = String::new();
    for k in [
        "shadow.limits.case",
        "shadow.limits.order",
        "shadow.limits.dup",
        "shadow.limits.body",
        "shadow.limits.window",
        "shadow.limits.scope",
    ] {
        items.push_str(&format!("<li>{}</li>", esc(i18n::t(lang, k))));
    }
    format!(
        "<p class=\"sh-note\">{}</p><ul class=\"sh-lim\">{items}</ul>",
        esc(i18n::t(lang, "shadow.limits.d"))
    )
}

/// The verdict: one sentence an operator can act on, with the denominator it
/// rests on spelled out underneath rather than implied by a percentage.
fn verdict(lang: &str, rv: &RunView) -> (String, String, &'static str) {
    let total = rv.records.len();
    let fams = FAMILIES
        .iter()
        .filter(|f| rv.records.iter().any(|r| r.family == **f))
        .count();
    if rv.mode != "dual" {
        return (
            fill(
                i18n::t(lang, "shadow.verdict.single"),
                &[total.to_string(), fams.to_string()],
            ),
            i18n::t(lang, "shadow.denom.single").to_string(),
            "flat",
        );
    }
    let n = |c: Class| rv.records.iter().filter(|r| r.class == Some(c)).count();
    let (br, se, co) = (n(Class::Breaking), n(Class::Semantic), n(Class::Cosmetic));
    let denom = fill(
        i18n::t(lang, "shadow.denom.dual"),
        &[total.to_string(), peer_label()],
    );
    if br + se + co == 0 {
        return (
            fill(i18n::t(lang, "shadow.verdict.clean"), &[total.to_string()]),
            denom,
            "ok",
        );
    }
    let tone = if br > 0 { "bad" } else { "warn" };
    (
        fill(
            i18n::t(lang, "shadow.verdict.diff"),
            &[
                br.to_string(),
                se.to_string(),
                co.to_string(),
                total.to_string(),
            ],
        ),
        denom,
        tone,
    )
}

fn mode_banner(lang: &str) -> String {
    if peer_configured() {
        return format!(
            "<div class=\"sh-banner ok\"><div class=\"sh-banner-h\">{h}</div></div>",
            h = fill(i18n::t(lang, "shadow.mode.dual.h"), &[peer_label()]),
        );
    }
    format!(
        "<div class=\"sh-banner\"><div class=\"sh-banner-h\">{h}</div>\
         <div class=\"sh-banner-d\">{d}</div></div>",
        h = esc(i18n::t(lang, "shadow.mode.single.h")),
        d = esc(i18n::t(lang, "shadow.mode.single.d")),
    )
}

fn findings_section(lang: &str, rv: &RunView) -> String {
    let mut out = String::new();
    let mut any = false;
    for c in [Class::Breaking, Class::Semantic, Class::Cosmetic] {
        let hits: Vec<(&Record, &Finding)> = rv
            .records
            .iter()
            .flat_map(|r| r.findings.iter().filter(move |f| f.class == c).map(move |f| (r, f)))
            .collect();
        if hits.is_empty() {
            continue;
        }
        any = true;
        out.push_str(&format!(
            "<div class=\"sh-grp\"><div class=\"sh-grp-h {id}\">{name} · {n}</div>",
            id = c.id(),
            name = esc(i18n::t(lang, c.key())),
            n = hits.len(),
        ));
        for (r, f) in hits {
            out.push_str(&format!(
                "<div class=\"sh-find {sev}\"><div class=\"sh-find-h\">{sentence}</div>\
                 <div class=\"sh-find-d\"><code>{case}</code> — {line}</div>\
                 <div class=\"sh-find-r\">{rule} · {field}</div></div>",
                sev = f.class.sev(),
                sentence = rule_sentence(lang, f),
                case = esc(&r.case_id),
                line = esc(&r.req.line()),
                rule = esc(&f.rule),
                field = esc(&f.field),
            ));
        }
        out.push_str("</div>");
    }
    if !any {
        let key = if rv.mode == "dual" {
            "shadow.findings.none"
        } else {
            "shadow.findings.none.single"
        };
        out.push_str(&format!("<p class=\"note\">{}</p>", esc(i18n::t(lang, key))));
    }
    out
}

fn replay_section(lang: &str, c: &Corpus) -> String {
    let Some(p) = c.replays.first() else {
        return format!("<p class=\"empty\">{}</p>", esc(i18n::t(lang, "shadow.replay.none")));
    };
    let tone = if p.drifted > 0 || p.errors > 0 { "bad" } else { "ok" };
    let head = format!(
        "<div class=\"sh-sub {tone}\">{v}</div>",
        v = fill(
            i18n::t(lang, "shadow.replay.verdict"),
            &[
                p.holds.to_string(),
                p.total.to_string(),
                p.drifted.to_string(),
                crate::tombstone::fmt_utc(p.ts as i64),
            ],
        ),
    );
    let mut rows = Vec::new();
    for it in &p.items {
        let v = match it.verdict.as_str() {
            "holds" => format!(
                "<span class=\"sh-cl identical\">{}</span>",
                esc(i18n::t(lang, "shadow.replay.holds"))
            ),
            "drifted" => format!(
                "<span class=\"sh-cl breaking\">{}</span>",
                esc(i18n::t(lang, "shadow.replay.drifted"))
            ),
            _ => format!(
                "<span class=\"sh-cl unpaired\">{}</span>",
                esc(i18n::t(lang, "shadow.replay.error"))
            ),
        };
        let why = if let Some(e) = &it.error {
            esc(e)
        } else if it.findings.is_empty() {
            esc(i18n::t(lang, "shadow.replay.same"))
        } else {
            it.findings
                .iter()
                .map(|f| rule_sentence(lang, f))
                .collect::<Vec<_>>()
                .join(" ")
        };
        rows.push(format!(
            "<tr><td><code class=\"sh-cid\">{id}</code></td><td>{fam}</td><td>{v}</td><td>{why}</td></tr>",
            id = esc(&it.case_id),
            fam = esc(fam_name(lang, &it.family)),
        ));
    }
    format!(
        "{head}{}",
        tbl(
            &[
                i18n::t(lang, "shadow.col.case"),
                i18n::t(lang, "shadow.col.family"),
                i18n::t(lang, "shadow.col.verdict"),
                i18n::t(lang, "shadow.col.evidence"),
            ],
            rows
        )
    )
}

fn corpus_section(lang: &str, c: &Corpus) -> String {
    let line = fill(
        i18n::t(lang, "shadow.corpus.d"),
        &[
            c.records_total.to_string(),
            c.runs.len().to_string(),
            fmt_bytes(c.bytes),
        ],
    );
    let span = if c.first_ts == 0 {
        String::new()
    } else {
        fill(
            i18n::t(lang, "shadow.corpus.span"),
            &[
                crate::tombstone::fmt_utc(c.first_ts as i64),
                crate::tombstone::fmt_utc(c.last_ts as i64),
            ],
        )
    };
    let mut rows = Vec::new();
    for r in c.runs.iter().take(12) {
        rows.push(format!(
            "<tr><td><a class=\"plain-link\" href=\"/lab/shadow?run={id}\"><code class=\"sh-cid\">{id}</code></a></td>\
             <td class=\"when\">{when}</td><td>{mode}</td><td class=\"num\">{n}</td></tr>",
            id = esc(&r.run),
            when = esc(&crate::tombstone::fmt_utc(r.ts as i64)),
            mode = esc(i18n::t(
                lang,
                if r.mode == "dual" { "shadow.mode.dual" } else { "shadow.mode.single" }
            )),
            n = r.records.len(),
        ));
    }
    format!(
        "<p class=\"sh-note\">{line} {span}</p>{}",
        tbl(
            &[
                i18n::t(lang, "shadow.col.run"),
                i18n::t(lang, "shadow.col.when"),
                i18n::t(lang, "shadow.col.mode"),
                i18n::t(lang, "shadow.col.cases"),
            ],
            rows
        )
    )
}

fn head_block(lang: &str, err: &str) -> String {
    let e = if err.is_empty() {
        String::new()
    } else {
        format!("<p class=\"err on\">{}</p>", esc(err))
    };
    format!(
        r#"<div class="pagehead"><h1>{title}</h1></div>
<p class="statline">{intro}</p>
{e}<div class="sh-acts">
  <form method="post" action="/lab/api/shadow/run"><button class="btn-primary" type="submit">{cap}</button></form>
  <form method="post" action="/lab/api/shadow/replay"><button class="btn" type="submit">{rep}</button></form>
  <span class="hint">{hint}</span>
</div>"#,
        title = esc(i18n::t(lang, "lab.tool.shadow.title")),
        intro = esc(i18n::t(lang, "shadow.intro")),
        cap = esc(i18n::t(lang, "shadow.act.capture")),
        rep = esc(i18n::t(lang, "shadow.act.replay")),
        hint = esc(i18n::t(lang, "shadow.act.hint")),
    )
}

pub fn page_content(lang: &str, want_run: &str, err: &str) -> String {
    let c = load_corpus();
    let head = head_block(lang, err);
    let banner = mode_banner(lang);

    let Some(rv) = c
        .runs
        .iter()
        .find(|r| want_run.is_empty() || r.run == want_run)
    else {
        // Designed empty state: what would put data here, and what it would be.
        return format!(
            "{head}{banner}<div class=\"page-sec sh-empty\"><div class=\"sh-empty-h\">{h}</div>\
             <p class=\"sh-empty-d\">{d}</p>{families}</div>",
            h = esc(i18n::t(lang, "shadow.empty.h")),
            d = esc(i18n::t(lang, "shadow.empty.d")),
            families = tbl(
                &[
                    i18n::t(lang, "shadow.col.family"),
                    i18n::t(lang, "shadow.col.probes"),
                ],
                FAMILIES
                    .iter()
                    .map(|f| format!(
                        "<tr><td>{n}</td><td>{d}</td></tr>",
                        n = esc(fam_name(lang, f)),
                        d = esc(fam_desc(lang, f))
                    ))
                    .collect()
            ),
        );
    };

    let (v, denom, tone) = verdict(lang, rv);
    let stale = if want_run.is_empty() || c.runs.first().map(|r| r.run.as_str()) == Some(&rv.run) {
        String::new()
    } else {
        format!(
            "<p class=\"note\">{}</p>",
            esc(i18n::t(lang, "shadow.olderrun"))
        )
    };

    format!(
        r#"{head}{banner}
<div class="sh-head">
  <div class="sh-verdict {tone}">{v}</div>
  <div class="sh-denom">{denom}</div>
  <div class="sh-meta"><code>{run}</code> · {when} · {n} {cases}</div>
</div>
{stale}
{matrix_sec}
{surface_sec}
{limits_sec}
{findings_sec}
{cases_sec}
{replay_sec}
{noise_sec}
{corpus_sec}"#,
        run = esc(&rv.run),
        when = esc(&crate::tombstone::fmt_utc(rv.ts as i64)),
        n = rv.records.len(),
        cases = esc(i18n::t(lang, "shadow.col.cases")),
        matrix_sec = sec(
            i18n::t(lang, "shadow.h.matrix"),
            format!(
                "<p class=\"sh-note\">{}</p>{}",
                esc(i18n::t(lang, "shadow.matrix.d")),
                matrix(lang, rv)
            )
        ),
        surface_sec = sec(
            i18n::t(lang, "shadow.h.surface"),
            format!(
                "<p class=\"sh-note\">{}</p>{}",
                esc(i18n::t(lang, "shadow.surface.d")),
                surface(lang, rv)
            )
        ),
        limits_sec = sec(i18n::t(lang, "shadow.h.limits"), limits_section(lang)),
        findings_sec = sec(i18n::t(lang, "shadow.h.findings"), findings_section(lang, rv)),
        cases_sec = sec(i18n::t(lang, "shadow.h.cases"), case_rows(lang, rv)),
        replay_sec = sec(i18n::t(lang, "shadow.h.replay"), replay_section(lang, &c)),
        noise_sec = sec(
            i18n::t(lang, "shadow.h.noise"),
            format!(
                "<p class=\"sh-note\">{}</p>{}",
                esc(i18n::t(lang, "shadow.noise.d")),
                noise_table(lang)
            )
        ),
        corpus_sec = sec(i18n::t(lang, "shadow.h.corpus"), corpus_section(lang, &c)),
    )
}

#[derive(Deserialize, Default)]
pub struct PageQ {
    #[serde(default)]
    pub run: String,
    #[serde(default)]
    pub err: String,
}

pub async fn page(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PageQ>,
) -> Response {
    let (_, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let body = page_content(lang, &q.run, &q.err);
    crate::pages::lab_tool_shell(&state, &headers, &sess, "shadow", body)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn hs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> CapturedResp {
        use md5::{Digest, Md5};
        CapturedResp {
            status,
            headers: hs(headers),
            len: body.len() as u64,
            md5: hex::encode(Md5::digest(body.as_bytes())),
            text: Some(body.to_string()),
            hex: None,
            truncated: false,
            ms: 1,
        }
    }

    fn rules(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|x| x.rule.as_str()).collect()
    }

    // ---- the noise list is the difference between a tool people read and one
    // they mute, so it gets the most tests.

    #[test]
    fn noise_covers_the_fields_two_servers_must_disagree_on() {
        for name in [
            "Date",
            "X-Trans-Id",
            "x-openstack-request-id",
            "Server",
            "Connection",
            "X-Backend-Timestamp",
        ] {
            assert!(
                noise_reason(name, Mode::Peer).is_some(),
                "{name} should be noise"
            );
        }
    }

    #[test]
    fn noise_does_not_swallow_fields_that_carry_meaning() {
        for name in ["ETag", "X-Timestamp", "Content-Type", "Content-Range", "Last-Modified"] {
            assert!(
                noise_reason(name, Mode::Peer).is_none(),
                "{name} must stay comparable"
            );
        }
    }

    #[test]
    fn a_replay_may_move_timestamps_a_peer_diff_may_not() {
        assert!(noise_reason("X-Timestamp", Mode::Peer).is_none());
        assert!(noise_reason("X-Timestamp", Mode::Replay).is_some());
        assert!(noise_reason("Last-Modified", Mode::Replay).is_some());
        // Still not a licence to ignore content.
        assert!(noise_reason("ETag", Mode::Replay).is_none());
    }

    #[test]
    fn every_noise_entry_carries_a_reason() {
        for e in NOISE.iter().chain(NOISE_REPLAY.iter()) {
            assert!(e.why.starts_with("shadow.why."), "{} has no reason", e.name);
        }
    }

    // ---- status

    #[test]
    fn a_different_status_class_outranks_a_different_code() {
        let mut f = Vec::new();
        diff_status(200, 404, &mut f);
        assert_eq!(f[0].class, Class::Breaking);
        let mut f = Vec::new();
        diff_status(500, 503, &mut f);
        assert_eq!(f[0].class, Class::Semantic);
        let mut f = Vec::new();
        diff_status(204, 204, &mut f);
        assert!(f.is_empty());
    }

    // ---- headers

    #[test]
    fn suppressed_headers_never_reach_the_comparable_surface() {
        let a = hs(&[("Date", "Mon"), ("X-Trans-Id", "aaa"), ("ETag", "\"x\"")]);
        let b = hs(&[("Date", "Tue"), ("X-Trans-Id", "bbb"), ("ETag", "\"x\"")]);
        let mut f = Vec::new();
        let st = diff_headers(&a, &b, Mode::Peer, &mut f);
        assert!(f.is_empty(), "{:?}", rules(&f));
        assert_eq!(st.suppressed, 2);
        assert_eq!(st.comparable, 1);
        assert_eq!(st.differing, 0);
    }

    #[test]
    fn etag_quoting_is_cosmetic_but_a_different_digest_is_breaking() {
        let mut f = Vec::new();
        diff_headers(
            &hs(&[("ETag", "\"abc\"")]),
            &hs(&[("ETag", "abc")]),
            Mode::Peer,
            &mut f,
        );
        assert_eq!(rules(&f), vec!["etag.quoting"]);
        assert_eq!(f[0].class, Class::Cosmetic);

        let mut f = Vec::new();
        diff_headers(
            &hs(&[("ETag", "\"abc\"")]),
            &hs(&[("ETag", "\"def\"")]),
            Mode::Peer,
            &mut f,
        );
        assert_eq!(rules(&f), vec!["etag.value"]);
        assert_eq!(f[0].class, Class::Breaking);
    }

    #[test]
    fn metadata_key_case_is_reported_separately_from_its_value() {
        let mut f = Vec::new();
        diff_headers(
            &hs(&[("X-Object-Meta-CamelCase", "v")]),
            &hs(&[("X-Object-Meta-Camelcase", "v")]),
            Mode::Peer,
            &mut f,
        );
        assert_eq!(rules(&f), vec!["meta.key_case"]);
        assert_eq!(f[0].class, Class::Semantic);

        // A plain header name differing in case is only cosmetic: the wire is
        // case-insensitive and no metadata dictionary is involved.
        let mut f = Vec::new();
        diff_headers(
            &hs(&[("Accept-Ranges", "bytes")]),
            &hs(&[("accept-ranges", "bytes")]),
            Mode::Peer,
            &mut f,
        );
        assert_eq!(rules(&f), vec!["hdr.case"]);
        assert_eq!(f[0].class, Class::Cosmetic);
    }

    #[test]
    fn a_dropped_metadata_key_is_breaking_and_a_dropped_extra_is_not() {
        let mut f = Vec::new();
        diff_headers(
            &hs(&[("X-Object-Meta-Owner", "u1")]),
            &hs(&[]),
            Mode::Peer,
            &mut f,
        );
        assert_eq!(rules(&f), vec!["meta.missing"]);
        assert_eq!(f[0].class, Class::Breaking);

        let mut f = Vec::new();
        diff_headers(&hs(&[("X-Whatever", "1")]), &hs(&[]), Mode::Peer, &mut f);
        assert_eq!(f[0].class, Class::Semantic);
    }

    // ---- listings: membership and order are different defects

    fn entries(names: &[&str]) -> Vec<ListEntry> {
        names
            .iter()
            .map(|n| ListEntry {
                name: (*n).to_string(),
                fields: BTreeMap::new(),
            })
            .collect()
    }

    #[test]
    fn a_listing_that_differs_only_in_order_is_not_a_missing_entry() {
        let mut f = Vec::new();
        diff_listing(&entries(&["a", "b", "c"]), &entries(&["a", "c", "b"]), Mode::Peer, &mut f);
        assert_eq!(rules(&f), vec!["listing.order"]);
        assert_eq!(f[0].class, Class::Semantic);
        // The evidence names where it first diverges, not just that it did.
        assert_eq!(f[0].args[1], "2");
    }

    #[test]
    fn a_missing_entry_is_breaking_and_is_not_reported_twice_as_order() {
        let mut f = Vec::new();
        diff_listing(&entries(&["a", "b", "c"]), &entries(&["a", "c"]), Mode::Peer, &mut f);
        assert_eq!(rules(&f), vec!["listing.membership"]);
        assert_eq!(f[0].class, Class::Breaking);
        assert_eq!(f[0].args[0], "1");
    }

    #[test]
    fn identical_listings_produce_nothing() {
        let mut f = Vec::new();
        diff_listing(&entries(&["a", "b"]), &entries(&["a", "b"]), Mode::Peer, &mut f);
        assert!(f.is_empty(), "{:?}", rules(&f));
    }

    #[test]
    fn listing_fields_differ_per_entry_and_last_modified_is_volatile_on_replay() {
        let mk = |lm: &str, bytes: &str| {
            let mut m = BTreeMap::new();
            m.insert("last_modified".to_string(), lm.to_string());
            m.insert("bytes".to_string(), bytes.to_string());
            vec![ListEntry { name: "o".into(), fields: m }]
        };
        let mut f = Vec::new();
        diff_listing(&mk("t1", "10"), &mk("t2", "10"), Mode::Peer, &mut f);
        assert_eq!(rules(&f), vec!["listing.field"]);

        let mut f = Vec::new();
        diff_listing(&mk("t1", "10"), &mk("t2", "10"), Mode::Replay, &mut f);
        assert!(f.is_empty(), "{:?}", rules(&f));

        // Size is never volatile, in either mode.
        let mut f = Vec::new();
        diff_listing(&mk("t1", "10"), &mk("t1", "11"), Mode::Replay, &mut f);
        assert_eq!(rules(&f), vec!["listing.field"]);
    }

    #[test]
    fn listings_parse_in_both_shapes_and_refuse_anything_else() {
        let j = parse_listing("application/json", r#"[{"name":"a","bytes":1}]"#).unwrap();
        assert_eq!(j[0].name, "a");
        assert_eq!(j[0].fields.get("bytes").map(|s| s.as_str()), Some("1"));
        let p = parse_listing("text/plain; charset=utf-8", "a\nb\n").unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(parse_listing("text/plain", "").unwrap().len(), 0);
        assert!(parse_listing("text/html", "<h1>nope</h1>").is_none());
    }

    // ---- ranges

    #[test]
    fn a_range_that_returns_different_bytes_is_breaking() {
        let a = resp(206, &[("Content-Range", "bytes 0-0/4096")], "0");
        let b = resp(206, &[("Content-Range", "bytes 0-1/4096")], "01");
        let d = diff_case("range", &a, &b, Mode::Peer);
        assert_eq!(d.class, Class::Breaking);
        assert!(rules(&d.findings).contains(&"range.boundary"));
        // The sentence carries the real lengths, not a placeholder.
        let bd = d.findings.iter().find(|f| f.rule == "range.boundary").unwrap();
        assert_eq!(bd.args[0], "1");
        assert_eq!(bd.args[1], "2");
    }

    #[test]
    fn one_range_disagreement_is_reported_once() {
        let a = resp(206, &[("Content-Range", "bytes 0-0/4096")], "0");
        let b = resp(200, &[], "0123456789abcdef");
        let d = diff_case("range", &a, &b, Mode::Peer);
        assert_eq!(
            rules(&d.findings)
                .iter()
                .filter(|r| **r == "range.boundary")
                .count(),
            1
        );
        assert!(rules(&d.findings).contains(&"range.status"));
    }

    #[test]
    fn a_range_window_that_moved_is_one_finding_not_two() {
        // Both sides carry Content-Range, so the header pass would raise its own
        // copy of a difference `diff_range` has already judged.
        let a = resp(206, &[("Content-Range", "bytes 0-1/4096")], "01");
        let b = resp(206, &[("Content-Range", "bytes 0-0/4096")], "0");
        let d = diff_case("range", &a, &b, Mode::Replay);
        assert_eq!(rules(&d.findings), vec!["range.boundary"], "{:?}", rules(&d.findings));
        assert_eq!(d.class, Class::Breaking);
    }

    #[test]
    fn an_identical_range_answer_produces_nothing() {
        let a = resp(206, &[("Content-Range", "bytes 4095-4095/4096")], "f");
        let b = resp(206, &[("Content-Range", "bytes 4095-4095/4096")], "f");
        let d = diff_case("range", &a, &b, Mode::Peer);
        assert_eq!(d.class, Class::Identical);
        assert!(d.findings.is_empty(), "{:?}", rules(&d.findings));
    }

    // ---- error bodies

    #[test]
    fn the_same_refusal_worded_differently_is_cosmetic() {
        let a = resp(404, &[("Content-Type", "text/html")], "<h1>Not Found</h1>");
        let b = resp(404, &[("Content-Type", "text/html")], "Object not found");
        let d = diff_case("error", &a, &b, Mode::Peer);
        assert_eq!(d.class, Class::Cosmetic);
        assert_eq!(rules(&d.findings), vec!["body.error"]);
    }

    #[test]
    fn a_refusal_with_a_different_code_outranks_the_wording() {
        let a = resp(404, &[("Content-Type", "text/html")], "gone");
        let b = resp(400, &[("Content-Type", "text/html")], "bad");
        let d = diff_case("error", &a, &b, Mode::Peer);
        assert_eq!(d.class, Class::Semantic);
        assert!(rules(&d.findings).contains(&"status.code"));
    }

    // ---- whole-case behaviour

    #[test]
    fn the_case_class_is_the_worst_finding_not_the_first() {
        let a = resp(
            200,
            &[("ETag", "\"abc\""), ("Content-Type", "application/json"), ("Date", "Mon")],
            "[]",
        );
        let b = resp(
            200,
            &[("ETag", "\"zzz\""), ("Content-Type", "application/json"), ("Date", "Tue")],
            "[]",
        );
        let d = diff_case("listing", &a, &b, Mode::Peer);
        assert_eq!(d.class, Class::Breaking);
        assert_eq!(d.hdr.suppressed, 1);
    }

    #[test]
    fn two_identical_answers_are_identical_even_with_noisy_headers() {
        let a = resp(
            200,
            &[("Date", "Mon"), ("X-Trans-Id", "tx1"), ("Content-Type", "application/json")],
            r#"[{"name":"a"}]"#,
        );
        let b = resp(
            200,
            &[("Date", "Tue"), ("X-Trans-Id", "tx2"), ("Content-Type", "application/json")],
            r#"[{"name":"a"}]"#,
        );
        let d = diff_case("listing", &a, &b, Mode::Peer);
        assert_eq!(d.class, Class::Identical);
        assert!(d.findings.is_empty(), "{:?}", rules(&d.findings));
    }

    #[test]
    fn an_empty_container_answering_two_ways_is_a_content_type_finding() {
        let a = resp(200, &[("Content-Type", "application/json")], "[]");
        let b = resp(204, &[("Content-Type", "text/plain; charset=utf-8")], "");
        let d = diff_case("listing", &a, &b, Mode::Peer);
        let r = rules(&d.findings);
        assert!(r.contains(&"status.code"), "{r:?}");
        assert!(r.contains(&"ctype.value"), "{r:?}");
        assert_eq!(d.class, Class::Semantic);
    }

    // ---- the shipped request set is the product, so it is asserted too

    #[test]
    fn the_request_set_covers_every_family_named_in_the_brief() {
        let set = request_set();
        for fam in ["listing", "meta", "etag", "range", "error"] {
            assert!(
                set.iter().any(|c| c.family == fam),
                "no case for family {fam}"
            );
        }
        // Case ids are corpus keys: a duplicate would silently overwrite a
        // behaviour on replay.
        let mut seen = BTreeSet::new();
        for c in &set {
            assert!(seen.insert(c.id), "duplicate case id {}", c.id);
        }
    }

    #[test]
    fn every_probe_stays_inside_the_containers_this_tool_owns() {
        for c in request_set() {
            if c.spec.sub.is_empty() {
                continue; // account-level reads touch nothing
            }
            let owned = [C_MAIN, C_EMPTY, C_ABSENT]
                .iter()
                .any(|c2| c.spec.sub.starts_with(&format!("/{c2}")));
            assert!(owned, "{} escapes the scratch containers", c.spec.sub);
        }
    }

    #[test]
    fn the_probe_body_makes_range_boundaries_readable() {
        let b = probe_body();
        assert_eq!(b.len() as u64, PROBE_LEN);
        assert_eq!(&b[0..1], "0");
        assert_eq!(&b[b.len() - 1..], "f");
    }

    #[test]
    fn a_findings_sentence_has_no_unfilled_holes() {
        // Every rule the diff core can raise must resolve to a sentence with
        // all of its evidence substituted, in both languages.
        let cases: Vec<Finding> = vec![
            Finding::new("status.class", "status", Class::Breaking, vec!["200".into(), "404".into()]),
            Finding::new("status.code", "status", Class::Semantic, vec!["500".into(), "503".into()]),
            Finding::new("hdr.missing", "ETag", Class::Breaking, vec!["ETag".into(), "A".into()]),
            Finding::new("hdr.value", "Allow", Class::Semantic, vec!["Allow".into(), "a".into(), "b".into()]),
            Finding::new("hdr.case", "Accept-Ranges", Class::Cosmetic, vec!["A".into(), "a".into()]),
            Finding::new("ctype.value", "Content-Type", Class::Semantic, vec!["a".into(), "b".into()]),
            Finding::new("etag.value", "ETag", Class::Breaking, vec!["a".into(), "b".into()]),
            Finding::new("etag.quoting", "ETag", Class::Cosmetic, vec!["a".into(), "b".into()]),
            Finding::new("meta.key_case", "X-Object-Meta-A", Class::Semantic, vec!["A".into(), "a".into()]),
            Finding::new("meta.missing", "X-Object-Meta-A", Class::Breaking, vec!["A".into(), "B".into()]),
            Finding::new("meta.value", "X-Object-Meta-A", Class::Breaking, vec!["A".into(), "a".into(), "b".into()]),
            Finding::new("listing.membership", "listing", Class::Breaking, vec!["1".into(), "a".into()]),
            Finding::new("listing.order", "listing", Class::Semantic, vec!["3".into(), "2".into()]),
            Finding::new("listing.field", "bytes", Class::Semantic, vec!["bytes".into(), "o".into(), "1".into(), "2".into()]),
            Finding::new("listing.count", "listing", Class::Breaking, vec!["2".into(), "3".into()]),
            Finding::new("range.status", "status", Class::Breaking, vec!["206".into(), "200".into()]),
            Finding::new("range.boundary", "range", Class::Breaking, vec!["1".into(), "2".into(), "a".into(), "b".into()]),
            Finding::new("body.error", "body", Class::Cosmetic, vec!["a".into(), "b".into()]),
            Finding::new("body.bytes", "body", Class::Breaking, vec!["1".into(), "2".into(), "a".into(), "b".into()]),
            Finding::new("conv.gap", "listing", Class::Semantic, vec!["1 ms".into(), "2 ms".into()]),
            Finding::new("conv.stuck", "listing", Class::Breaking, vec!["8 s".into()]),
        ];
        for f in &cases {
            for l in ["en", "zh"] {
                let s = rule_sentence(l, f);
                assert!(!s.contains("{0}"), "{} left a hole in {l}: {s}", f.rule);
                assert!(!s.contains("{1}"), "{} left a hole in {l}: {s}", f.rule);
                assert!(!s.starts_with("shadow.rule."), "{} has no {l} sentence", f.rule);
            }
        }
    }

    #[test]
    fn account_totals_move_on_a_replay_but_account_metadata_must_not() {
        for n in [
            "X-Account-Object-Count",
            "X-Account-Bytes-Used",
            "X-Account-Container-Count",
            "X-Account-Storage-Policy-Default-Bytes-Used",
        ] {
            assert!(noise_reason(n, Mode::Peer).is_none(), "{n} is comparable between peers");
            assert!(noise_reason(n, Mode::Replay).is_some(), "{n} moves on a replay");
        }
        // The prefix must not swallow user metadata in either mode.
        assert!(noise_reason("X-Account-Meta-Owner", Mode::Replay).is_none());
    }

    #[test]
    fn a_container_rows_totals_are_volatile_on_replay_but_an_objects_size_is_not() {
        let container = |b: &str, c: &str| {
            let mut m = BTreeMap::new();
            m.insert("bytes".to_string(), b.to_string());
            m.insert("count".to_string(), c.to_string());
            vec![ListEntry { name: "c".into(), fields: m }]
        };
        let object = |b: &str| {
            let mut m = BTreeMap::new();
            m.insert("bytes".to_string(), b.to_string());
            m.insert("hash".to_string(), "d41d8".to_string());
            vec![ListEntry { name: "o".into(), fields: m }]
        };
        let mut f = Vec::new();
        diff_listing(&container("0", "0"), &container("4111", "3"), Mode::Replay, &mut f);
        assert!(f.is_empty(), "{:?}", rules(&f));

        let mut f = Vec::new();
        diff_listing(&object("10"), &object("11"), Mode::Replay, &mut f);
        assert_eq!(rules(&f), vec!["listing.field"], "an object's size never moves on its own");

        // Between two implementations the aggregates are comparable again.
        let mut f = Vec::new();
        diff_listing(&container("0", "0"), &container("4111", "3"), Mode::Peer, &mut f);
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn content_length_is_not_reported_alongside_the_listing_it_restates() {
        let a = resp(
            200,
            &[("Content-Type", "application/json"), ("Content-Length", "258")],
            r#"[{"name":"a","bytes":1}]"#,
        );
        let b = resp(
            200,
            &[("Content-Type", "application/json"), ("Content-Length", "261")],
            r#"[{"name":"a","bytes":2}]"#,
        );
        let d = diff_case("listing", &a, &b, Mode::Peer);
        assert_eq!(rules(&d.findings), vec!["listing.field"]);
        assert_eq!(d.hdr.suppressed, 1, "content-length is set aside, not silently dropped");

        // On a body that is not compared structurally it stays a real finding.
        let a = resp(200, &[("Content-Type", "text/html"), ("Content-Length", "3")], "abc");
        let b = resp(200, &[("Content-Type", "text/html"), ("Content-Length", "4")], "abcd");
        let d = diff_case("error", &a, &b, Mode::Peer);
        assert!(rules(&d.findings).contains(&"hdr.value"), "{:?}", rules(&d.findings));
    }

    #[test]
    fn the_corpus_record_survives_a_round_trip() {
        let rec = Record {
            v: 1,
            run: "r1".into(),
            ts: 100,
            case_id: "range.first.byte".into(),
            family: "range".into(),
            mode: "single".into(),
            req: get(format!("/{C_MAIN}/{O_BIN}"), vec![], h(&[("Range", "bytes=0-0")])),
            a: resp(206, &[("Content-Range", "bytes 0-0/4096")], "0"),
            b: None,
            findings: vec![],
            class: None,
            hdr: HdrStats { comparable: 4, suppressed: 2, differing: 0 },
            converge_ms: None,
            converged: None,
            polls: None,
        };
        let line = serde_json::to_string(&rec).unwrap();
        assert!(!line.contains('\n'), "a record must stay one appendable line");
        let back: Record = serde_json::from_str(&line).unwrap();
        assert_eq!(back.case_id, "range.first.byte");
        assert!(back.class.is_none(), "an unpaired record must stay unpaired");
        assert_eq!(back.req.line(), rec.req.line());
        assert_eq!(back.hdr.suppressed, 2);
    }

    #[test]
    fn an_unpaired_capture_still_counts_its_comparable_surface() {
        let a = resp(
            200,
            &[("Date", "Mon"), ("X-Trans-Id", "t"), ("ETag", "\"x\""), ("Content-Type", "text/plain")],
            "x",
        );
        let st = unpaired_stats(&a);
        assert_eq!(st.suppressed, 2);
        assert_eq!(st.comparable, 2);
        assert_eq!(st.differing, 0, "nothing was compared, so nothing differs");
    }
}
