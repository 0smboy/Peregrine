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

//! The on-disk file selection state machine: a faithful port of
//! `BaseDiskFileManager.get_ondisk_files` and the replication/EC
//! `_process_ondisk_files` / `_verify_ondisk_files` overrides.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use swift_core::timestamp::Timestamp;

use crate::error::DiskFileError;
use crate::naming::{parse_ondisk_filename, FileInfo, PolicyKind};

/// One per-timestamp fragment preference, as passed by the EC proxy
/// (`frag_prefs`).
#[derive(Debug, Clone)]
pub struct FragPref {
    pub timestamp: Timestamp,
    pub exclude: Vec<i64>,
}

/// The result of [`get_ondisk_files`]: which files constitute the state
/// of the object, which are obsolete, and which were unrecognized.
#[derive(Debug, Clone, Default)]
pub struct OndiskFiles {
    pub data_info: Option<FileInfo>,
    pub meta_info: Option<FileInfo>,
    pub ts_info: Option<FileInfo>,
    pub ctype_info: Option<FileInfo>,
    pub data_file: Option<PathBuf>,
    pub meta_file: Option<PathBuf>,
    pub ts_file: Option<PathBuf>,
    pub ctype_file: Option<PathBuf>,
    pub obsolete: Vec<FileInfo>,
    pub unexpected: Vec<PathBuf>,
    pub possible_reclaim: Vec<FileInfo>,
    /// EC only: every fragment set keyed by timestamp, ascending
    /// frag_index within each set.
    pub frag_sets: Vec<(Timestamp, Vec<FileInfo>)>,
    pub durable_frag_set_ts: Option<Timestamp>,
    pub chosen_frag_set_ts: Option<Timestamp>,
}

/// Split reverse-time-ordered `list` at the first item not newer than
/// `timestamp` (`_split_gt_timestamp`).
fn split_gt(list: Vec<FileInfo>, timestamp: &Timestamp) -> (Vec<FileInfo>, Vec<FileInfo>) {
    split_at_condition(list, |info| info.timestamp > *timestamp)
}

/// Split reverse-time-ordered `list` at the first item older than
/// `timestamp` (`_split_gte_timestamp`).
fn split_gte(list: Vec<FileInfo>, timestamp: &Timestamp) -> (Vec<FileInfo>, Vec<FileInfo>) {
    split_at_condition(list, |info| info.timestamp >= *timestamp)
}

fn split_at_condition(
    mut list: Vec<FileInfo>,
    condition: impl Fn(&FileInfo) -> bool,
) -> (Vec<FileInfo>, Vec<FileInfo>) {
    let split = list
        .iter()
        .position(|item| !condition(item))
        .unwrap_or(list.len());
    let rest = list.split_off(split);
    (list, rest)
}

struct Exts {
    map: HashMap<String, Vec<FileInfo>>,
}

impl Exts {
    fn take(&mut self, ext: &str) -> Vec<FileInfo> {
        self.map.remove(ext).unwrap_or_default()
    }

    fn put(&mut self, ext: &str, list: Vec<FileInfo>) {
        if list.is_empty() {
            // keep map keys tidy; emptiness checks use get()
            self.map.remove(ext);
        } else {
            self.map.insert(ext.to_string(), list);
        }
    }

    fn get(&self, ext: &str) -> &[FileInfo] {
        self.map.get(ext).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Apply `f` to every extension list (Python's `for ext in exts`).
    fn for_each_ext(&mut self, mut f: impl FnMut(&str, Vec<FileInfo>) -> Vec<FileInfo>) {
        let keys: Vec<String> = self.map.keys().cloned().collect();
        for key in keys {
            let list = self.map.remove(&key).unwrap();
            let kept = f(&key, list);
            if !kept.is_empty() {
                self.map.insert(key, kept);
            }
        }
    }
}

/// Port of `get_ondisk_files`. `files` is the directory listing;
/// `datadir` is used only to construct returned paths. `frag_index` and
/// `frag_prefs` apply to EC policies only.
pub fn get_ondisk_files(
    files: &[String],
    datadir: &Path,
    verify: bool,
    policy: PolicyKind,
    frag_index: Option<i64>,
    frag_prefs: Option<&[FragPref]>,
) -> Result<OndiskFiles, DiskFileError> {
    let mut results = OndiskFiles::default();
    let mut exts = Exts {
        map: HashMap::new(),
    };

    for afile in files {
        match parse_ondisk_filename(afile, policy) {
            Ok(info) => {
                let list = exts.map.entry(info.ext.clone()).or_default();
                list.push(info);
            }
            Err(_) => results.unexpected.push(datadir.join(afile)),
        }
    }
    // reverse chronological order per extension; Rust's stable sort with a
    // reversed comparator preserves original order among equal timestamps,
    // matching Python's stable `sorted(..., reverse=True)`
    for list in exts.map.values_mut() {
        list.sort_by_key(|f| std::cmp::Reverse(f.timestamp));
    }

    if !exts.get(".ts").is_empty() {
        let latest_ts = exts.get(".ts")[0].timestamp;
        exts.for_each_ext(|ext, list| {
            if ext == ".ts" {
                return list;
            }
            let (kept, older) = split_gt(list, &latest_ts);
            results.obsolete.extend(older);
            kept
        });
        let mut ts_list = exts.take(".ts");
        results.obsolete.extend(ts_list.split_off(1));
        exts.put(".ts", ts_list);
    }

    if !exts.get(".meta").is_empty() {
        let mut metas = exts.take(".meta");
        let mut retain = 1;
        if metas.len() > 1 {
            // find the older meta with the newest ctype_timestamp
            metas[1..].sort_by_key(|m| std::cmp::Reverse(m.ctype_timestamp));
            if metas[1].ctype_timestamp > metas[0].ctype_timestamp {
                if metas[1].timestamp == metas[0].timestamp {
                    metas.swap(0, 1);
                } else {
                    retain = 2;
                }
            }
        }
        results.obsolete.extend(metas.split_off(retain));
        exts.put(".meta", metas);
    }

    match policy {
        PolicyKind::Replication => {
            process_repl(&mut exts, &mut results);
        }
        PolicyKind::Ec { .. } => {
            process_ec(&mut exts, &mut results, frag_index, frag_prefs);
        }
    }

    // set final choice of files
    if results.data_info.is_some() {
        let mut metas = exts.take(".meta");
        if !metas.is_empty() {
            results.meta_info = Some(metas[0].clone());
            let ctype_info = metas.pop().unwrap();
            if ctype_info.ctype_timestamp > results.data_info.as_ref().map(|i| i.timestamp) {
                results.ctype_info = Some(ctype_info.clone());
            }
            metas.push(ctype_info);
            exts.put(".meta", metas);
        }
    } else if !exts.get(".ts").is_empty() {
        results.ts_info = Some(exts.get(".ts")[0].clone());
    }

    results.data_file = results
        .data_info
        .as_ref()
        .map(|i| datadir.join(&i.filename));
    results.meta_file = results
        .meta_info
        .as_ref()
        .map(|i| datadir.join(&i.filename));
    results.ts_file = results.ts_info.as_ref().map(|i| datadir.join(&i.filename));
    results.ctype_file = results
        .ctype_info
        .as_ref()
        .map(|i| datadir.join(&i.filename));

    if verify && !verify_ondisk_files(&results, policy, frag_prefs) {
        return Err(DiskFileError::ContractBroken(format!("{results:?}")));
    }
    Ok(results)
}

/// `DiskFileManager._process_ondisk_files` (replication policy).
fn process_repl(exts: &mut Exts, results: &mut OndiskFiles) {
    if !exts.get(".data").is_empty() {
        let newest_data_ts = exts.get(".data")[0].timestamp;
        exts.for_each_ext(|ext, list| {
            let (kept, obsolete) = if ext == ".data" {
                split_gte(list, &newest_data_ts)
            } else {
                split_gt(list, &newest_data_ts)
            };
            results.obsolete.extend(obsolete);
            kept
        });
        results.data_info = Some(exts.get(".data")[0].clone());
    }
    if !exts.get(".meta").is_empty() && exts.get(".data").is_empty() {
        results
            .possible_reclaim
            .extend(exts.get(".meta").iter().cloned());
    }
}

/// `ECDiskFileManager._process_ondisk_files`.
fn process_ec(
    exts: &mut Exts,
    results: &mut OndiskFiles,
    mut frag_index: Option<i64>,
    frag_prefs: Option<&[FragPref]>,
) {
    // in older versions, separate .durable files were used to indicate
    // the durability of data files having the same timestamp
    let mut durable_ts: Option<Timestamp> = exts.get(".durable").first().map(|i| i.timestamp);

    // Split the .data files into per-timestamp frag sets, identifying the
    // durable and newest sets as we go.
    let mut frag_sets: Vec<(Timestamp, Vec<FileInfo>)> = Vec::new();
    let mut durable_frag_set_ts: Option<Timestamp> = None;
    let mut all_frags = exts.get(".data").to_vec();
    while !all_frags.is_empty() {
        let first_ts = all_frags[0].timestamp;
        let (mut frag_set, rest) = split_gte(all_frags, &first_ts);
        all_frags = rest;
        // ascending frag_index order (stable)
        frag_set.sort_by_key(|f| f.frag_index);
        let timestamp = frag_set[0].timestamp;
        for frag in &frag_set {
            if frag.durable == Some(true) {
                if durable_ts.is_none() || durable_ts.unwrap() < timestamp {
                    durable_ts = Some(timestamp);
                }
                break;
            }
        }
        let is_durable_set = durable_ts == Some(timestamp);
        if is_durable_set {
            // a frag filename may lack the #d marker when durability comes
            // from a legacy .durable, so mark the whole set durable
            for frag in &mut frag_set {
                frag.durable = Some(true);
            }
        }
        frag_sets.push((timestamp, frag_set));
        if is_durable_set {
            durable_frag_set_ts = Some(timestamp);
            break; // ignore frags older than the durable timestamp
        }
    }

    // Choose which frag set to use
    let mut chosen_frag_set_ts: Option<Timestamp> = None;
    if let Some(prefs) = frag_prefs {
        let mut candidates: Vec<Timestamp> = frag_sets.iter().map(|(ts, _)| *ts).collect();
        let applicable: Vec<&FragPref> = prefs
            .iter()
            .filter(|p| candidates.contains(&p.timestamp))
            .collect();
        let mut found = false;
        for pref in applicable {
            let set = frag_sets
                .iter()
                .find(|(ts, _)| *ts == pref.timestamp)
                .map(|(_, set)| set)
                .unwrap();
            let mut acceptable: Vec<i64> = set
                .iter()
                .filter_map(|info| info.frag_index)
                .filter(|fi| !pref.exclude.contains(fi))
                .collect();
            // Python takes list(set(available) - set(exclude)) and uses the
            // last (highest) element; dedupe and order ascending
            acceptable.sort_unstable();
            acceptable.dedup();
            if let Some(&highest) = acceptable.last() {
                chosen_frag_set_ts = Some(pref.timestamp);
                frag_index = Some(highest);
                found = true;
                break;
            } else {
                candidates.retain(|ts| *ts != pref.timestamp);
            }
        }
        if !found {
            // no acceptable frag index at any preferred timestamp: newest
            // remaining candidate
            chosen_frag_set_ts = candidates.iter().max().copied();
        }
    } else {
        chosen_frag_set_ts = durable_frag_set_ts;
    }

    // Select a single frag from the chosen set: exact frag_index match, or
    // the highest index
    let mut chosen_frag: Option<FileInfo> = None;
    if let Some(chosen_ts) = chosen_frag_set_ts {
        if let Some((_, set)) = frag_sets.iter().find(|(ts, _)| *ts == chosen_ts) {
            chosen_frag = match frag_index {
                Some(fi) => set.iter().find(|info| info.frag_index == Some(fi)).cloned(),
                None => set.last().cloned(),
            };
        }
    }

    if let Some(chosen) = chosen_frag {
        let chosen_ts = chosen.timestamp;
        results.data_info = Some(chosen);
        results.durable_frag_set_ts = durable_frag_set_ts;
        results.chosen_frag_set_ts = chosen_frag_set_ts;
        if chosen_frag_set_ts != durable_frag_set_ts {
            // hide meta files older than the chosen data but newer than the
            // durable file so they aren't marked obsolete
            let (kept, _hidden) = split_gt(exts.take(".meta"), &chosen_ts);
            exts.put(".meta", kept);
        }
    } else {
        // durable/chosen set info is only reported when a frag was chosen,
        // mirroring Python (the verify contract depends on this)
        results.durable_frag_set_ts = None;
        results.chosen_frag_set_ts = None;
    }
    results.frag_sets = frag_sets.clone();

    // Everything older than the most recent durable data is obsolete
    if let Some(durable_ts) = durable_ts {
        exts.for_each_ext(|_ext, list| {
            let (kept, older) = split_gte(list, &durable_ts);
            results.obsolete.extend(older);
            kept
        });
    }

    // an isolated legacy .durable is obsolete
    if !exts.get(".durable").is_empty() && durable_frag_set_ts.is_none() {
        let durables = exts.take(".durable");
        results.obsolete.extend(durables);
    }

    // Fragments *may* be ready for reclaim, unless they are the most
    // recent durable or chosen set
    for (ts, set) in &frag_sets {
        if Some(*ts) == durable_frag_set_ts || Some(*ts) == chosen_frag_set_ts {
            continue;
        }
        results.possible_reclaim.extend(set.iter().cloned());
    }

    // .meta files *may* be ready for reclaim when there is no durable data
    if !exts.get(".meta").is_empty() && durable_frag_set_ts.is_none() {
        results
            .possible_reclaim
            .extend(exts.get(".meta").iter().cloned());
    }
}

/// `_verify_ondisk_files`, base plus the EC override.
fn verify_ondisk_files(
    results: &OndiskFiles,
    policy: PolicyKind,
    frag_prefs: Option<&[FragPref]>,
) -> bool {
    let data = results.data_file.is_some();
    let meta = results.meta_file.is_some();
    let ts = results.ts_file.is_some();
    // equivalent to Python's three clauses: nothing at all, a tombstone
    // alone, or data without a tombstone (meta requires data)
    let base_ok = (!ts || !data) && (!meta || data);
    match policy {
        PolicyKind::Replication => base_ok,
        PolicyKind::Ec { .. } => {
            if !base_ok {
                return false;
            }
            let have_durable =
                results.durable_frag_set_ts.is_some() || (data && frag_prefs.is_some());
            data == have_durable
        }
    }
}
