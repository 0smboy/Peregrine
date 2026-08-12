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

//! The `ShardRange` model and merge semantics, ported from
//! `swift/common/utils/__init__.py` (`ShardRange`, `merge_shards`,
//! `sift_shard_ranges`) and `swift/container/backend.py`.
//!
//! A shard range is a persisted record describing one shard of a container's
//! namespace: its `[lower, upper)` bounds, object/byte counts, sharding
//! `state`, and the timestamps that govern conflict resolution. Because shard
//! ranges replicate between container DBs, the merge rule that decides which
//! version of a range wins — [`merge_shards`] — is a compatibility contract
//! and is ported field-for-field from Python.

/// The 13 persisted shard-range columns, in `SHARD_RANGE_KEYS` order.
pub const SHARD_RANGE_KEYS: [&str; 13] = [
    "name",
    "timestamp",
    "lower",
    "upper",
    "object_count",
    "bytes_used",
    "meta_timestamp",
    "deleted",
    "state",
    "state_timestamp",
    "epoch",
    "reported",
    "tombstones",
];

/// Shard-range lifecycle states (`ShardRange.FOUND` … `SHRUNK`).
pub mod state {
    pub const FOUND: i64 = 10;
    pub const CREATED: i64 = 20;
    pub const CLEAVED: i64 = 30;
    pub const ACTIVE: i64 = 40;
    pub const SHRINKING: i64 = 50;
    pub const SHARDING: i64 = 60;
    pub const SHARDED: i64 = 70;
    pub const SHRUNK: i64 = 80;

    /// State name -> number (`ShardRange.resolve_state` for a name).
    pub fn from_name(name: &str) -> Option<i64> {
        match name.to_ascii_lowercase().as_str() {
            "found" => Some(FOUND),
            "created" => Some(CREATED),
            "cleaved" => Some(CLEAVED),
            "active" => Some(ACTIVE),
            "shrinking" => Some(SHRINKING),
            "sharding" => Some(SHARDING),
            "sharded" => Some(SHARDED),
            "shrunk" => Some(SHRUNK),
            _ => None,
        }
    }
}

/// `SHARD_UPDATE_STATES`: states valid for redirecting an object update.
pub const SHARD_UPDATE_STATES: [i64; 4] = [
    state::CREATED,
    state::CLEAVED,
    state::ACTIVE,
    state::SHARDING,
];

/// `SHARD_LISTING_STATES`: states valid when listing objects.
pub const SHARD_LISTING_STATES: [i64; 4] = [
    state::ACTIVE,
    state::SHARDING,
    state::SHRINKING,
    state::CLEAVED,
];

/// `SHARD_AUDITING_STATES`: every state except FOUND.
pub const SHARD_AUDITING_STATES: [i64; 7] = [
    state::CREATED,
    state::CLEAVED,
    state::ACTIVE,
    state::SHARDING,
    state::SHARDED,
    state::SHRINKING,
    state::SHRUNK,
];

/// `resolve_shard_range_states`: turn a list of state names / numbers /
/// aliases (`listing`/`updating`/`auditing`) into the set of state numbers, or
/// `None` if the list is empty. An unrecognised value yields `Err`.
pub fn resolve_shard_range_states(states: &[String]) -> Result<Option<Vec<i64>>, String> {
    if states.is_empty() {
        return Ok(None);
    }
    let mut out: Vec<i64> = Vec::new();
    for s in states {
        let vals: Vec<i64> = match s.as_str() {
            "listing" => SHARD_LISTING_STATES.to_vec(),
            "updating" => SHARD_UPDATE_STATES.to_vec(),
            "auditing" => SHARD_AUDITING_STATES.to_vec(),
            other => vec![other
                .parse::<i64>()
                .ok()
                .or_else(|| state::from_name(other))
                .ok_or_else(|| format!("Invalid state {other:?}"))?],
        };
        for v in vals {
            if !out.contains(&v) {
                out.push(v);
            }
        }
    }
    Ok(Some(out))
}

/// A persisted shard range, the Rust form of a `ShardRange` / a row of the
/// `shard_range` table (in `SHARD_RANGE_KEYS` field order).
#[derive(Debug, Clone, PartialEq)]
pub struct ShardRange {
    pub name: String,
    pub timestamp: String,
    /// Lower bound, `""` = namespace minimum.
    pub lower: String,
    /// Upper bound, `""` = namespace maximum.
    pub upper: String,
    pub object_count: i64,
    pub bytes_used: i64,
    pub meta_timestamp: String,
    pub deleted: i64,
    pub state: i64,
    pub state_timestamp: String,
    /// The epoch timestamp (nullable).
    pub epoch: Option<String>,
    pub reported: i64,
    pub tombstones: i64,
}

impl ShardRange {
    /// A newly-found shard range with sensible defaults (state FOUND).
    pub fn new(name: &str, timestamp: &str, lower: &str, upper: &str) -> ShardRange {
        ShardRange {
            name: name.to_string(),
            timestamp: timestamp.to_string(),
            lower: lower.to_string(),
            upper: upper.to_string(),
            object_count: 0,
            bytes_used: 0,
            meta_timestamp: timestamp.to_string(),
            deleted: 0,
            state: state::FOUND,
            state_timestamp: timestamp.to_string(),
            epoch: None,
            reported: 0,
            tombstones: -1,
        }
    }

    /// `ShardRange.sort_key_order`: `(upper-or-MAX, state, lower, name)`.
    /// The empty upper (`""`, the namespace maximum) sorts after every real
    /// bound, so it is represented here as `(true, "")` which orders last.
    pub fn sort_key(&self) -> (bool, String, i64, String, String) {
        (
            self.upper.is_empty(),
            self.upper.clone(),
            self.state,
            self.lower.clone(),
            self.name.clone(),
        )
    }

    /// Serialize to the JSON dict shape Python `dict(ShardRange)` produces
    /// (the `SHARD_RANGE_KEYS`), used in shard-range listings and PUTs.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "timestamp": self.timestamp,
            "lower": self.lower,
            "upper": self.upper,
            "object_count": self.object_count,
            "bytes_used": self.bytes_used,
            "meta_timestamp": self.meta_timestamp,
            "deleted": self.deleted,
            "state": self.state,
            "state_timestamp": self.state_timestamp,
            "epoch": self.epoch,
            "reported": self.reported,
            "tombstones": self.tombstones,
        })
    }

    /// Parse a shard range from a JSON dict (`ShardRange.from_dict`). Missing
    /// `reported`/`tombstones` default to 0/-1; `state` defaults to FOUND.
    pub fn from_json(v: &serde_json::Value) -> Option<ShardRange> {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let i = |k: &str, d: i64| v.get(k).and_then(|x| x.as_i64()).unwrap_or(d);
        let timestamp = s("timestamp")?;
        Some(ShardRange {
            name: s("name")?,
            lower: s("lower").unwrap_or_default(),
            upper: s("upper").unwrap_or_default(),
            object_count: i("object_count", 0),
            bytes_used: i("bytes_used", 0),
            meta_timestamp: s("meta_timestamp").unwrap_or_else(|| timestamp.clone()),
            deleted: i("deleted", 0),
            state: i("state", state::FOUND),
            state_timestamp: s("state_timestamp").unwrap_or_else(|| timestamp.clone()),
            epoch: v.get("epoch").and_then(|x| x.as_str()).map(str::to_string),
            reported: i("reported", 0),
            tombstones: i("tombstones", -1),
            timestamp,
        })
    }

    /// Whether `value` falls in this range's `[lower, upper)` namespace
    /// (`Namespace.__contains__`): `lower < value <= upper` with empty bounds
    /// as -inf / +inf.
    pub fn includes(&self, value: &str) -> bool {
        let above_lower = self.lower.is_empty() || value > self.lower.as_str();
        let below_upper = self.upper.is_empty() || value <= self.upper.as_str();
        above_lower && below_upper
    }

    /// `ShardRange.row_count`: object_count + max(tombstones, 0).
    pub fn row_count(&self) -> i64 {
        self.object_count + self.tombstones.max(0)
    }

    /// Compare two lower bounds where `""` is namespace minimum (-inf).
    pub fn lower_cmp(a: &str, b: &str) -> std::cmp::Ordering {
        match (a.is_empty(), b.is_empty()) {
            (true, true) => std::cmp::Ordering::Equal,
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (false, false) => a.cmp(b),
        }
    }

    /// Compare two upper bounds where `""` is namespace maximum (+inf).
    pub fn upper_cmp(a: &str, b: &str) -> std::cmp::Ordering {
        match (a.is_empty(), b.is_empty()) {
            (true, true) => std::cmp::Ordering::Equal,
            (true, false) => std::cmp::Ordering::Greater, // MAX > real
            (false, true) => std::cmp::Ordering::Less,
            (false, false) => a.cmp(b),
        }
    }

    /// True if this range's lower is strictly less than `upper` (empty upper = MAX).
    fn lower_lt_upper(lower: &str, upper: &str) -> bool {
        // Empty bounds are MIN/MAX sentinels: either empty ⇒ strictly less.
        upper.is_empty() || lower.is_empty() || lower < upper
    }

    /// `Namespace.overlaps`: `max(lower) < min(upper)` with empty = MIN/MAX.
    pub fn overlaps(&self, other: &ShardRange) -> bool {
        // max of lowers (empty = MIN)
        let max_lo = match Self::lower_cmp(&self.lower, &other.lower) {
            std::cmp::Ordering::Less => other.lower.as_str(),
            _ => self.lower.as_str(),
        };
        // min of uppers (empty = MAX)
        let min_hi = match Self::upper_cmp(&self.upper, &other.upper) {
            std::cmp::Ordering::Greater => other.upper.as_str(),
            _ => self.upper.as_str(),
        };
        Self::lower_lt_upper(max_lo, min_hi)
    }

    /// Whether this range includes the whole of `other` (`Namespace.includes`).
    pub fn includes_range(&self, other: &ShardRange) -> bool {
        Self::lower_cmp(&self.lower, &other.lower) != std::cmp::Ordering::Greater
            && Self::upper_cmp(&other.upper, &self.upper) != std::cmp::Ordering::Greater
    }

    /// `Namespace.expand`: widen bounds to cover all donors. Returns true if
    /// bounds changed.
    pub fn expand(&mut self, donors: &[ShardRange]) -> bool {
        let mut new_lower = self.lower.clone();
        let mut new_upper = self.upper.clone();
        for d in donors {
            if Self::lower_cmp(&d.lower, &new_lower) == std::cmp::Ordering::Less {
                new_lower = d.lower.clone();
            }
            if Self::upper_cmp(&d.upper, &new_upper) == std::cmp::Ordering::Greater {
                new_upper = d.upper.clone();
            }
        }
        if new_lower != self.lower || new_upper != self.upper {
            self.lower = new_lower;
            self.upper = new_upper;
            true
        } else {
            false
        }
    }

    /// Update state if different; bumps `state_timestamp` when set. Returns
    /// whether the state changed (`ShardRange.update_state`).
    pub fn update_state(&mut self, new_state: i64, state_timestamp: Option<&str>) -> bool {
        if self.state == new_state {
            return false;
        }
        self.state = new_state;
        if let Some(ts) = state_timestamp {
            self.state_timestamp = ts.to_string();
        }
        true
    }
}

/// Pairwise overlapping groups among non-deleted ranges (excluding self-pairs).
/// Each group is sorted by [`ShardRange::sort_key`].
pub fn find_overlapping_ranges(shard_ranges: &[ShardRange]) -> Vec<Vec<ShardRange>> {
    let mut result: Vec<Vec<ShardRange>> = Vec::new();
    for i in 0..shard_ranges.len() {
        let mut overlapping: Vec<ShardRange> = Vec::new();
        for j in (i + 1)..shard_ranges.len() {
            if shard_ranges[i].name != shard_ranges[j].name
                && shard_ranges[i].overlaps(&shard_ranges[j])
            {
                overlapping.push(shard_ranges[j].clone());
            }
        }
        if !overlapping.is_empty() {
            overlapping.push(shard_ranges[i].clone());
            overlapping.sort_by_key(|r| r.sort_key());
            // Dedup by sorted name-set so the same clique isn't reported twice
            // when found from different seeds (best-effort).
            let key: Vec<String> = overlapping.iter().map(|r| r.name.clone()).collect();
            let already = result.iter().any(|g| {
                let mut gk: Vec<String> = g.iter().map(|r| r.name.clone()).collect();
                gk.sort();
                let mut kk = key.clone();
                kk.sort();
                gk == kk
            });
            if !already {
                result.push(overlapping);
            }
        }
    }
    result
}

/// Gaps between contiguous sorted (by lower) non-SHRINKING ranges.
/// Each gap is `(lower, upper)` of the missing namespace interval.
pub fn find_namespace_gaps(shard_ranges: &[ShardRange]) -> Vec<(String, String)> {
    let mut ranges: Vec<&ShardRange> = shard_ranges
        .iter()
        .filter(|r| r.deleted == 0 && r.state != state::SHRINKING)
        .collect();
    ranges.sort_by(|a, b| {
        ShardRange::lower_cmp(&a.lower, &b.lower)
            .then_with(|| ShardRange::upper_cmp(&a.upper, &b.upper))
    });
    let mut gaps = Vec::new();
    if ranges.is_empty() {
        // entire namespace is a gap
        gaps.push((String::new(), String::new()));
        return gaps;
    }
    // gap before first
    if !ranges[0].lower.is_empty() {
        gaps.push((String::new(), ranges[0].lower.clone()));
    }
    let mut cursor_upper = ranges[0].upper.clone();
    for r in ranges.iter().skip(1) {
        // if r.lower > cursor_upper → gap (cursor_upper, r.lower)
        // empty cursor_upper = MAX → no further gap possible
        if cursor_upper.is_empty() {
            break;
        }
        match ShardRange::lower_cmp(&r.lower, &cursor_upper) {
            std::cmp::Ordering::Greater => {
                gaps.push((cursor_upper.clone(), r.lower.clone()));
                cursor_upper = r.upper.clone();
            }
            std::cmp::Ordering::Equal => {
                // contiguous: advance cursor if this range extends further
                if ShardRange::upper_cmp(&r.upper, &cursor_upper) == std::cmp::Ordering::Greater {
                    cursor_upper = r.upper.clone();
                }
            }
            std::cmp::Ordering::Less => {
                // overlap or nested: extend cursor if needed
                if ShardRange::upper_cmp(&r.upper, &cursor_upper) == std::cmp::Ordering::Greater {
                    cursor_upper = r.upper.clone();
                }
            }
        }
    }
    if !cursor_upper.is_empty() {
        gaps.push((cursor_upper, String::new()));
    }
    gaps
}

/// `merge_shards`: compare `new` against `existing`, folding any items of
/// `existing` that take precedence into `new`, and return whether `new` has
/// content that supersedes `existing` (i.e. should be persisted). Ported
/// field-for-field from Python.
pub fn merge_shards(new: &mut ShardRange, existing: Option<&ShardRange>) -> bool {
    let Some(existing) = existing else {
        return true;
    };
    if existing.timestamp < new.timestamp {
        // newer created-time trumps entirely; reset the reported latch
        new.reported = 0;
        return true;
    } else if existing.timestamp > new.timestamp {
        return false;
    }

    let mut new_content = false;
    // same created timestamp: preserve existing bounds and deleted flag
    new.lower = existing.lower.clone();
    new.upper = existing.upper.clone();
    new.deleted = existing.deleted;

    // meta data: the newer meta_timestamp's counts win
    if existing.meta_timestamp >= new.meta_timestamp {
        new.object_count = existing.object_count;
        new.bytes_used = existing.bytes_used;
        new.meta_timestamp = existing.meta_timestamp.clone();
        new.tombstones = existing.tombstones;
    } else {
        new_content = true;
    }

    // latch the reported flag
    if existing.reported != 0
        && existing.object_count == new.object_count
        && existing.bytes_used == new.bytes_used
        && existing.tombstones == new.tombstones
        && existing.state == new.state
        && existing.epoch == new.epoch
    {
        new.reported = 1;
    } else if new.reported != 0 && existing.reported == 0 {
        new_content = true;
    }

    // state: the newer state_timestamp wins; on a tie a higher state wins
    if existing.state_timestamp == new.state_timestamp && new.state > existing.state {
        new_content = true;
    } else if existing.state_timestamp >= new.state_timestamp {
        new.state = existing.state;
        new.state_timestamp = existing.state_timestamp.clone();
        new.epoch = existing.epoch.clone();
    } else {
        new_content = true;
    }
    new_content
}

/// `sift_shard_ranges`: fold new ranges against the existing rows, returning
/// `(to_add, to_delete)` — the ranges that carry new/updated state and the
/// names whose old rows they supersede.
pub fn sift_shard_ranges(
    new_ranges: Vec<ShardRange>,
    existing: &std::collections::HashMap<String, ShardRange>,
) -> (Vec<ShardRange>, Vec<String>) {
    let mut to_delete: Vec<String> = Vec::new();
    // insertion-ordered accumulator keyed by name
    let mut to_add: Vec<(String, ShardRange)> = Vec::new();
    for mut item in new_ranges {
        let name = item.name.clone();
        let ex = existing.get(&name);
        if merge_shards(&mut item, ex) {
            if ex.is_some() && !to_delete.contains(&name) {
                to_delete.push(name.clone());
            }
            // duplicate entries within this batch: newest-wins in place
            if let Some(pos) = to_add.iter().position(|(n, _)| n == &name) {
                let prior = to_add[pos].1.clone();
                if merge_shards(&mut item, Some(&prior)) {
                    to_add[pos].1 = item;
                }
            } else {
                to_add.push((name, item));
            }
        }
    }
    (to_add.into_iter().map(|(_, sr)| sr).collect(), to_delete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sr(name: &str, ts: &str) -> ShardRange {
        ShardRange::new(name, ts, "", "")
    }

    #[test]
    fn listing_alias_includes_cleaved() {
        // states=listing must return CLEAVED (30) ranges after L3b cleave.
        let resolved = resolve_shard_range_states(&["listing".into()])
            .unwrap()
            .expect("listing expands to a state set");
        assert!(
            resolved.contains(&state::CLEAVED),
            "CLEAVED missing from listing states: {resolved:?}"
        );
        for s in SHARD_LISTING_STATES {
            assert!(resolved.contains(&s), "missing {s} in {resolved:?}");
        }
    }

    #[test]
    fn test_merge_no_existing_adds() {
        let mut new = sr("a", "1751500000.00000");
        assert!(merge_shards(&mut new, None));
    }

    #[test]
    fn test_merge_newer_timestamp_wins() {
        let mut new = sr("a", "1751500002.00000");
        let existing = sr("a", "1751500001.00000");
        assert!(merge_shards(&mut new, Some(&existing)));
        // older existing does not roll forward the reported latch
        assert_eq!(new.reported, 0);
    }

    #[test]
    fn test_merge_older_timestamp_loses() {
        let mut new = sr("a", "1751500001.00000");
        let existing = sr("a", "1751500002.00000");
        assert!(!merge_shards(&mut new, Some(&existing)));
    }

    #[test]
    fn test_merge_same_ts_preserves_bounds_takes_newer_meta() {
        let ts = "1751500001.00000";
        let mut new = ShardRange {
            lower: "m".into(),
            upper: "z".into(),
            object_count: 5,
            bytes_used: 50,
            meta_timestamp: "1751500000.00000".into(), // OLDER meta
            ..ShardRange::new("a", ts, "m", "z")
        };
        let existing = ShardRange {
            lower: "a".into(),
            upper: "b".into(),
            object_count: 9,
            bytes_used: 90,
            meta_timestamp: "1751500003.00000".into(), // NEWER meta
            ..ShardRange::new("a", ts, "a", "b")
        };
        let has_new = merge_shards(&mut new, Some(&existing));
        // bounds come from existing (same created ts)
        assert_eq!(new.lower, "a");
        assert_eq!(new.upper, "b");
        // counts come from the newer meta
        assert_eq!(new.object_count, 9);
        assert_eq!(new.bytes_used, 90);
        assert_eq!(new.meta_timestamp, "1751500003.00000");
        assert!(
            !has_new,
            "existing had newer meta and equal state -> no new content"
        );
    }

    #[test]
    fn test_merge_higher_state_on_state_ts_tie_is_new() {
        let ts = "1751500001.00000";
        let mut new = ShardRange {
            state: state::CLEAVED,
            ..ShardRange::new("a", ts, "", "")
        };
        let existing = ShardRange {
            state: state::CREATED,
            ..ShardRange::new("a", ts, "", "")
        };
        assert!(merge_shards(&mut new, Some(&existing)));
        assert_eq!(new.state, state::CLEAVED);
    }

    #[test]
    fn test_sift_supersedes() {
        let mut existing = HashMap::new();
        existing.insert("a".to_string(), sr("a", "1751500001.00000"));
        let (to_add, to_delete) = sift_shard_ranges(vec![sr("a", "1751500002.00000")], &existing);
        assert_eq!(to_add.len(), 1);
        assert_eq!(to_delete, vec!["a".to_string()]);
        // an older range against a newer existing is dropped
        let (to_add2, to_delete2) = sift_shard_ranges(vec![sr("a", "1751500000.00000")], &existing);
        assert!(to_add2.is_empty());
        assert!(to_delete2.is_empty());
    }

    #[test]
    fn test_sort_key_empty_upper_last() {
        let mut ranges = [
            ShardRange::new("z", "1", "m", ""),
            ShardRange::new("a", "1", "", "m"),
        ];
        ranges.sort_by_key(|r| r.sort_key());
        // the range with upper "m" sorts before the one with upper "" (MAX)
        assert_eq!(ranges[0].upper, "m");
        assert_eq!(ranges[1].upper, "");
    }

    #[test]
    fn test_includes() {
        let r = ShardRange::new("a", "1", "d", "m"); // (d, m]
        assert!(!r.includes("d"));
        assert!(r.includes("e"));
        assert!(r.includes("m"));
        assert!(!r.includes("n"));
        let whole = ShardRange::new("a", "1", "", ""); // (-inf, +inf]
        assert!(whole.includes("anything"));
    }

    #[test]
    fn test_overlaps_and_expand() {
        let a = ShardRange::new("a", "1", "", "m");
        let b = ShardRange::new("b", "1", "m", "");
        let c = ShardRange::new("c", "1", "g", "z");
        assert!(!a.overlaps(&b), "contiguous abutting ranges do not overlap");
        assert!(a.overlaps(&c));
        assert!(b.overlaps(&c));
        let mut acc = b.clone();
        assert!(acc.expand(std::slice::from_ref(&a)));
        assert_eq!(acc.lower, "");
        assert_eq!(acc.upper, "");
        assert_eq!(a.row_count(), 0);
        let mut with_tomb = a.clone();
        with_tomb.object_count = 3;
        with_tomb.tombstones = 2;
        assert_eq!(with_tomb.row_count(), 5);
    }

    #[test]
    fn test_find_gaps_and_overlaps() {
        let ranges = vec![
            ShardRange::new("lo", "1", "", "m"),
            ShardRange::new("hi", "1", "z", ""),
        ];
        let gaps = find_namespace_gaps(&ranges);
        assert_eq!(gaps, vec![("m".into(), "z".into())]);
        let ok = vec![
            ShardRange::new("lo", "1", "", "m"),
            ShardRange::new("hi", "1", "m", ""),
        ];
        assert!(find_namespace_gaps(&ok).is_empty());
        let ov = vec![
            ShardRange::new("a", "1", "", "z"),
            ShardRange::new("b", "1", "m", ""),
        ];
        assert!(!find_overlapping_ranges(&ov).is_empty());
    }
}
