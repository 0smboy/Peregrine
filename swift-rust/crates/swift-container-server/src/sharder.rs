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

//! The container sharder daemon core, ported from `swift/container/sharder.py`.
//!
//! The sharder drives a large container through sharding: it finds shard
//! ranges, creates the shard containers, moves this container into the
//! `sharding` state, then *cleaves* — copies each shard range's objects out of
//! the retiring DB into that shard's container — advancing a cleave cursor,
//! and finally moves to the `sharded` state. This module ports the cleave
//! orchestration on top of the sharding primitives already in `swift-db`
//! (`find_shard_ranges`, `merge_shard_ranges`, `make_shard_name`,
//! `set_sharding_state`/`set_sharded_state`).
//!
//! The transport that creates a shard container on its ring nodes and
//! replicates the cleaved shard DB is abstracted behind the caller-supplied
//! "shard broker" (a local DB for the shard); this keeps the cleave logic —
//! the compatibility-relevant part — unit-testable. Deferred: the
//! `.misplaced_objects` move pass, the cleave-context persistence in the DB,
//! and the multi-node replication of shard DBs.

use swift_db::{
    make_shard_name, shard_state, shards_account_name, ContainerBroker, DbError, ShardRange,
};

/// `CleavingContext`: the sharder's progress through a container's shard
/// ranges (a simplified, in-memory form of Python's stored context).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CleavingContext {
    /// The upper bound of the last shard range cleaved (`""` = not started /
    /// namespace minimum).
    pub cursor: String,
    pub ranges_done: usize,
    pub ranges_todo: usize,
    /// True once the cursor reaches the namespace maximum (all ranges cleaved).
    pub cleaving_done: bool,
}

/// `_find_shard_ranges` + `_create_shard_containers` (naming part): scan the
/// container for shard ranges, build FOUND `ShardRange` records named with
/// `make_shard_name`, and merge them into the container's shard-range table.
/// Returns the found ranges (ascending by upper).
pub fn find_and_merge_found_ranges(
    broker: &mut ContainerBroker,
    account: &str,
    container: &str,
    shard_size: i64,
    minimum_shard_size: i64,
    timestamp: &str,
) -> Result<Vec<ShardRange>, DbError> {
    let (found, _done) = broker.find_shard_ranges(shard_size, minimum_shard_size)?;
    let shards_account = shards_account_name(account);
    let mut ranges = Vec::with_capacity(found.len());
    for f in &found {
        // first-generation shards: parent == root == this container
        let name = make_shard_name(&shards_account, container, container, timestamp, f.index as u64);
        let mut sr = ShardRange::new(&name, timestamp, &f.lower, &f.upper);
        sr.object_count = f.object_count;
        ranges.push(sr);
    }
    if !ranges.is_empty() {
        broker.merge_shard_ranges(ranges.clone())?;
    }
    Ok(ranges)
}

/// `_cleave_shard_range`: copy `range`'s objects out of the `retiring` DB into
/// its `shard` container, update the range's stats from the shard, and mark it
/// CLEAVED. The updated range is persisted into both the shard container (as
/// its own range) and the `source` container (so the root records progress).
pub fn cleave_shard_range(
    retiring: &mut ContainerBroker,
    shard: &mut ContainerBroker,
    source: &mut ContainerBroker,
    range: &mut ShardRange,
) -> Result<(), DbError> {
    let records = retiring.object_records_in_range(&range.lower, &range.upper)?;
    if !records.is_empty() {
        shard.merge_items(records)?;
    }
    // Update the range's object/byte counts from the cleaved shard.
    let info = shard.get_info()?;
    let get = |k: &str| {
        info.iter()
            .find(|(n, _)| n == k)
            .and_then(|(_, v)| v.as_i64())
            .unwrap_or(0)
    };
    range.object_count = get("object_count");
    range.bytes_used = get("bytes_used");
    range.state = shard_state::CLEAVED;
    // bump the meta timestamp so the CLEAVED/count update wins on merge
    range.meta_timestamp = range.timestamp.clone();
    shard.merge_shard_ranges(vec![range.clone()])?;
    source.merge_shard_ranges(vec![range.clone()])?;
    Ok(())
}

/// `_cleave`: cleave up to `batch_size` not-yet-cleaved ranges, advancing the
/// cleave cursor. Objects are read from the container's retiring DB (the
/// broker must be in the SHARDING state, i.e. have a separate retiring DB).
/// `shard_for` yields a (local) broker for a shard range's container. When the
/// cursor reaches the namespace maximum the context is marked `cleaving_done`.
pub fn cleave(
    source: &mut ContainerBroker,
    ranges: &mut [ShardRange],
    shard_for: &mut dyn FnMut(&ShardRange) -> ContainerBroker,
    ctx: &mut CleavingContext,
    batch_size: usize,
) -> Result<(), DbError> {
    let Some(mut retiring) = source.retiring_broker() else {
        // not in the sharding state; nothing to cleave from a retiring DB
        return Ok(());
    };
    ctx.ranges_todo = ranges
        .iter()
        .filter(|r| r.upper.is_empty() || r.upper.as_str() > ctx.cursor.as_str())
        .count();
    let mut done_this_batch = 0usize;
    for range in ranges.iter_mut() {
        if ctx.cleaving_done || done_this_batch >= batch_size {
            break;
        }
        // skip ranges already behind the cursor
        if !range.upper.is_empty() && range.upper.as_str() <= ctx.cursor.as_str() {
            continue;
        }
        let mut shard = shard_for(range);
        cleave_shard_range(&mut retiring, &mut shard, source, range)?;
        ctx.cursor = range.upper.clone();
        ctx.ranges_done += 1;
        done_this_batch += 1;
        if range.upper.is_empty() {
            // reached the namespace maximum -> all ranges cleaved
            ctx.cleaving_done = true;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container_broker(dir: &std::path::Path, name: &str, n: usize) -> ContainerBroker {
        let h = format!("{:0>32}", name.replace(['/', '.'], ""));
        let h = &h[h.len() - 32..];
        let hd = dir.join(format!("c/0/{}/{h}", &h[h.len() - 3..]));
        std::fs::create_dir_all(&hd).unwrap();
        let db = hd.join(format!("{h}.db"));
        let mut b = ContainerBroker::new(&db, "AUTH_test", name);
        b.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        for i in 0..n {
            b.put_object(&format!("o{i:04}"), "1751500001.00000", 1, "text/plain", "e", 0, 0, None, None)
                .unwrap();
        }
        b
    }

    #[test]
    fn test_find_create_and_cleave() {
        let dir = std::env::temp_dir().join(format!("swift-sharder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // a source container with 10 objects
        let mut source = container_broker(&dir, "c", 10);

        // find + merge shard ranges (shard_size 3, min 1 -> 4 ranges)
        let epoch = "1751500010.00000";
        let mut ranges =
            find_and_merge_found_ranges(&mut source, "AUTH_test", "c", 3, 1, epoch).unwrap();
        assert_eq!(ranges.len(), 4, "{ranges:?}");
        assert!(ranges.iter().all(|r| r.state == shard_state::FOUND));

        // move to sharding state
        source.enable_sharding(epoch).unwrap();
        assert!(source.set_sharding_state().unwrap());

        // cleave all ranges (batch big enough to finish)
        let shard_dir = dir.join("shards");
        let mut shard_for = |sr: &ShardRange| {
            let safe = sr.name.replace(['/', '.', '-'], "_");
            let hd = shard_dir.join(&safe);
            std::fs::create_dir_all(&hd).unwrap();
            let db = hd.join("shard.db");
            let mut b = ContainerBroker::new(&db, ".shards_AUTH_test", &sr.name);
            let _ = b.initialize("1751500010.00000", 0, "1751500010.00000", "sid");
            b
        };
        let mut ctx = CleavingContext::default();
        cleave(&mut source, &mut ranges, &mut shard_for, &mut ctx, 10).unwrap();

        assert!(ctx.cleaving_done, "reached namespace max");
        assert_eq!(ctx.ranges_done, 4);
        assert!(ranges.iter().all(|r| r.state == shard_state::CLEAVED));
        // every object accounted for across the shards
        let total: i64 = ranges.iter().map(|r| r.object_count).sum();
        assert_eq!(total, 10, "{ranges:?}");
        // the first shard (upper o0002) got exactly its 3 objects
        assert_eq!(ranges[0].object_count, 3);

        // finish: move to sharded state
        assert!(source.set_sharded_state().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_cleave_is_batched() {
        let dir = std::env::temp_dir().join(format!("swift-sharder-b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut source = container_broker(&dir, "c", 10);
        let epoch = "1751500010.00000";
        let mut ranges =
            find_and_merge_found_ranges(&mut source, "AUTH_test", "c", 3, 1, epoch).unwrap();
        source.enable_sharding(epoch).unwrap();
        source.set_sharding_state().unwrap();

        let shard_dir = dir.join("shards");
        let mut shard_for = |sr: &ShardRange| {
            let safe = sr.name.replace(['/', '.', '-'], "_");
            let hd = shard_dir.join(&safe);
            std::fs::create_dir_all(&hd).unwrap();
            let mut b = ContainerBroker::new(&hd.join("s.db"), ".shards_AUTH_test", &sr.name);
            let _ = b.initialize("1751500010.00000", 0, "1751500010.00000", "sid");
            b
        };
        // first batch of 2
        let mut ctx = CleavingContext::default();
        cleave(&mut source, &mut ranges, &mut shard_for, &mut ctx, 2).unwrap();
        assert_eq!(ctx.ranges_done, 2);
        assert!(!ctx.cleaving_done);
        assert_eq!(ctx.cursor, ranges[1].upper);
        // second batch finishes
        cleave(&mut source, &mut ranges, &mut shard_for, &mut ctx, 2).unwrap();
        assert_eq!(ctx.ranges_done, 4);
        assert!(ctx.cleaving_done);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
