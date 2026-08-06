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

//! `swift-manage-shard-ranges` — ops CLI ported from
//! `swift/cli/manage_shard_ranges.py`.
//!
//! **Implemented:** `find`, `show`, `info`, `enable`, `delete`, `merge`,
//! `find_and_replace` (force/no-prompt), `analyze` (read-only report),
//! `compact` (identify + optional `--force` apply compactible sequences),
//! `repair` (gaps/overlaps report + optional `--force` apply).
//!
//! **Still deferred:** interactive prompts (use `--force` / `--yes`), full
//! Python path-ranking repair (parent/child age filters, multi-path rank),
//! shrink/expand driven by the sharder daemon after compact marks donors.
//!
//! Multi-node KEEP claim still blocked by live Contabo quorum drill + ring-
//! directed HTTP create on all primaries (see sharder residuals).

use std::env;
use std::path::Path;
use std::process;

use swift_core::timestamp::Timestamp;
use swift_db::{
    find_namespace_gaps, find_overlapping_ranges, make_shard_name, shard_state,
    shards_account_name, ContainerBroker, DbState, GetShardRangesArgs, ShardRange,
};

const EXIT_OK: i32 = 0;
const EXIT_ERROR: i32 = 1;
const EXIT_INVALID: i32 = 2;

fn usage() -> ! {
    eprintln!(
        "usage: swift-manage-shard-ranges <container.db> <subcommand> [options]\n\
         \n\
         subcommands:\n\
           find [shard_size] [min_shard_size]   Find ranges (JSON)\n\
           show [--include-deleted] [--brief]  Print stored shard ranges\n\
           info                                Print container db sharding info\n\
           enable                              Enable sharding on own range\n\
           delete --force                      Soft-delete all other shard ranges\n\
           merge --force <ranges.json>         Merge ranges from JSON array file\n\
           find_and_replace [shard_size] [--enable] [--force]\n\
                                               Find, soft-delete old, inject new\n\
           analyze                             Read-only shard state report\n\
           compact [--force] [--shrink-threshold N] [--expansion-limit N]\n\
                                               Find (and optionally apply) compactible sequences\n\
           repair [--gaps] [--force]           Report/fix gaps or overlaps\n\
         \n\
         Multi-node KEEP / live quorum: not claimed here; local DB ops only."
    );
    process::exit(EXIT_INVALID);
}

fn state_text(state: i64) -> &'static str {
    match state {
        shard_state::FOUND => "found",
        shard_state::CREATED => "created",
        shard_state::CLEAVED => "cleaved",
        shard_state::ACTIVE => "active",
        shard_state::SHRINKING => "shrinking",
        shard_state::SHARDING => "sharding",
        shard_state::SHARDED => "sharded",
        shard_state::SHRUNK => "shrunk",
        _ => "unknown",
    }
}

fn shard_to_show_json(sr: &ShardRange) -> serde_json::Value {
    let mut v = sr.to_json();
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "state_text".into(),
            serde_json::Value::String(state_text(sr.state).into()),
        );
    }
    v
}

fn open_broker(db: &str) -> ContainerBroker {
    let path = Path::new(db);
    if !path.exists() {
        eprintln!("error: database not found: {db}");
        process::exit(EXIT_ERROR);
    }
    // Account/container are re-read from the DB after open for ops that need them.
    ContainerBroker::new(path, "", "")
}

fn info_i64(broker: &mut ContainerBroker, key: &str) -> i64 {
    broker
        .get_info()
        .ok()
        .and_then(|info| {
            info.into_iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| v.as_i64())
        })
        .unwrap_or(0)
}

fn info_text(broker: &mut ContainerBroker, key: &str) -> String {
    broker
        .get_info()
        .ok()
        .and_then(|info| {
            info.into_iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| v.as_text())
        })
        .unwrap_or_default()
}

fn sharding_enabled(broker: &mut ContainerBroker) -> bool {
    broker
        .metadata()
        .ok()
        .and_then(|md| {
            md.into_iter().find(|(k, _)| {
                k.eq_ignore_ascii_case("X-Container-Sysmeta-Sharding")
            })
        })
        .map(|(_, (v, _))| {
            matches!(
                v.to_ascii_lowercase().as_str(),
                "true" | "yes" | "1" | "on"
            )
        })
        .unwrap_or(false)
}

fn cmd_find(broker: &mut ContainerBroker, shard_size: i64, min_size: i64) -> i32 {
    match broker.find_shard_ranges(shard_size, min_size) {
        Ok((ranges, done)) => {
            let data: Vec<serde_json::Value> = ranges
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "index": r.index,
                        "lower": r.lower,
                        "upper": r.upper,
                        "object_count": r.object_count,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
            let total: i64 = ranges.iter().map(|r| r.object_count).sum();
            eprintln!(
                "Found {} ranges (complete: {done}, total object count {total})",
                ranges.len()
            );
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_ERROR
        }
    }
}

fn cmd_show(broker: &mut ContainerBroker, include_deleted: bool, brief: bool) -> i32 {
    let ranges = match broker.get_shard_ranges(&GetShardRangesArgs {
        include_deleted,
        include_own: false,
        ..GetShardRangesArgs::default()
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    };
    if ranges.is_empty() {
        eprintln!("No shard data found.");
        return EXIT_OK;
    }
    eprintln!("Existing shard ranges:");
    if brief {
        let bounds: Vec<(String, String)> = ranges
            .iter()
            .map(|r| (r.lower.clone(), r.upper.clone()))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&bounds).unwrap_or_default()
        );
    } else {
        let data: Vec<serde_json::Value> = ranges.iter().map(shard_to_show_json).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
    }
    EXIT_OK
}

fn cmd_info(broker: &mut ContainerBroker) -> i32 {
    println!("Sharding enabled = {}", sharding_enabled(broker));
    match broker.get_own_shard_range(true) {
        Ok(Some(own)) => {
            println!(
                "Own shard range: {}",
                serde_json::to_string_pretty(&shard_to_show_json(&own)).unwrap_or_default()
            );
        }
        Ok(None) => println!("Own shard range: null"),
        Err(e) => {
            eprintln!("error reading own shard range: {e}");
            return EXIT_ERROR;
        }
    }
    match broker.get_db_state() {
        Ok(st) => println!("db_state = {}", st.as_str()),
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    }
    println!("object_count = {}", info_i64(broker, "object_count"));
    println!("bytes_used = {}", info_i64(broker, "bytes_used"));
    if matches!(broker.get_db_state().ok(), Some(DbState::Sharding)) {
        // Cleaving context is optional sysmeta; print if present.
        if let Ok(md) = broker.metadata() {
            for (k, (v, _)) in md {
                if k.eq_ignore_ascii_case("X-Container-Sysmeta-Shard-Cleaving-Context") {
                    println!("Cleaving context: {v}");
                }
            }
        }
    }
    println!("Metadata:");
    if let Ok(md) = broker.metadata() {
        for (k, (v, _)) in md {
            println!("  {k} = {v}");
        }
    }
    EXIT_OK
}

fn cmd_enable(broker: &mut ContainerBroker) -> i32 {
    let epoch = Timestamp::now().internal();
    // Ensure account/container names are present for path/own-range.
    let account = info_text(broker, "account");
    let container = info_text(broker, "container");
    if account.is_empty() || container.is_empty() {
        eprintln!("error: container db missing account/container in container_stat");
        return EXIT_ERROR;
    }
    // Re-open with identity so path() matches stored own range.
    let db_path = broker.db_file().to_path_buf();
    let mut broker = ContainerBroker::new(&db_path, &account, &container);

    let own = match broker.get_own_shard_range(false) {
        Ok(Some(o)) => o,
        Ok(None) => {
            eprintln!("error: no own shard range");
            return EXIT_ERROR;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    };
    if own.state != shard_state::ACTIVE && own.state != shard_state::SHARDING {
        eprintln!(
            "WARNING: container own range in state {} (should be active or sharding).",
            state_text(own.state)
        );
        eprintln!("Aborting.");
        return EXIT_ERROR;
    }
    if own.state == shard_state::SHARDING && own.epoch.is_some() {
        println!(
            "Container already in state '{}' with epoch {}.",
            state_text(own.state),
            own.epoch.as_deref().unwrap_or("")
        );
        println!("No action required.");
        return EXIT_OK;
    }

    match broker.enable_sharding(&epoch) {
        Ok(updated) => {
            // Python enable_sharding is followed by set_sharding_state when the
            // sharder starts, but ops also need an epoch DB file so get_db_state
            // reports SHARDING (single non-epoch file always looks UNSHARDED).
            match broker.set_sharding_state() {
                Ok(true) => {
                    println!("Created epoch DB for SHARDING state (set_sharding_state).");
                }
                Ok(false) => {
                    eprintln!(
                        "warning: set_sharding_state returned false (missing epoch?); \
                         sharder may not pick this container until epoch file exists"
                    );
                }
                Err(e) => {
                    eprintln!("warning: set_sharding_state failed: {e}");
                }
            }
            let ts = Timestamp::now().normal();
            if let Err(e) = broker.update_metadata(&vec![(
                "X-Container-Sysmeta-Sharding".into(),
                ("True".into(), ts),
            )]) {
                eprintln!("warning: failed to set sharding sysmeta: {e}");
            }
            println!(
                "Container moved to state '{}' with epoch {}.",
                state_text(updated.state),
                updated.epoch.as_deref().unwrap_or(&epoch)
            );
            println!("Run container-sharder on all nodes to shard the container.");
            // Note: set_sharding_state (UNSHARDED→two-db) is the sharder daemon's job.
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_ERROR
        }
    }
}

fn cmd_delete(broker: &mut ContainerBroker, force: bool) -> i32 {
    if !force {
        eprintln!("delete requires --force (interactive prompt deferred)");
        return EXIT_INVALID;
    }
    let ranges = match broker.get_shard_ranges(&GetShardRangesArgs {
        include_own: false,
        include_deleted: false,
        ..GetShardRangesArgs::default()
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    };
    if ranges.is_empty() {
        println!("No shard ranges found to delete.");
        return EXIT_OK;
    }
    let now = Timestamp::now().internal();
    let mut doomed = ranges;
    for sr in &mut doomed {
        sr.deleted = 1;
        sr.timestamp = now.clone();
    }
    match broker.merge_shard_ranges(doomed.clone()) {
        Ok(()) => {
            println!("Deleted {} existing shard ranges.", doomed.len());
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_ERROR
        }
    }
}

fn load_ranges_json(path: &str) -> Result<Vec<ShardRange>, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("invalid json: {e}"))?;
    let arr = value
        .as_array()
        .ok_or_else(|| "expected JSON array of shard ranges".to_string())?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, v) in arr.iter().enumerate() {
        let sr = ShardRange::from_json(v)
            .ok_or_else(|| format!("index {i}: missing name/timestamp or invalid range"))?;
        out.push(sr);
    }
    Ok(out)
}

fn cmd_merge(broker: &mut ContainerBroker, force: bool, input: &str) -> i32 {
    if !force {
        eprintln!("merge requires --force (interactive prompt deferred)");
        return EXIT_INVALID;
    }
    let ranges = match load_ranges_json(input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    };
    if ranges.is_empty() {
        println!("Injected 0 shard ranges.");
        return EXIT_OK;
    }
    match broker.merge_shard_ranges(ranges.clone()) {
        Ok(()) => {
            println!("Injected {} shard ranges.", ranges.len());
            println!("Run container-replicator to replicate them to other nodes.");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_ERROR
        }
    }
}

fn cmd_find_and_replace(
    broker: &mut ContainerBroker,
    shard_size: i64,
    min_size: i64,
    enable: bool,
    force: bool,
) -> i32 {
    if !force {
        eprintln!("find_and_replace requires --force (interactive delete prompt deferred)");
        return EXIT_INVALID;
    }
    let account = info_text(broker, "account");
    let container = info_text(broker, "container");
    if account.is_empty() || container.is_empty() {
        eprintln!("error: container db missing account/container");
        return EXIT_ERROR;
    }
    let db_path = broker.db_file().to_path_buf();
    let mut broker = ContainerBroker::new(&db_path, &account, &container);

    let (found, _done) = match broker.find_shard_ranges(shard_size, min_size) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    };
    if found.is_empty() {
        eprintln!("No ranges found (container may be below shard threshold).");
        return EXIT_OK;
    }

    // Soft-delete existing other ranges.
    if cmd_delete(&mut broker, true) == EXIT_ERROR {
        return EXIT_ERROR;
    }

    let epoch = Timestamp::now().internal();
    let shards_account = shards_account_name(&account);
    let mut ranges = Vec::with_capacity(found.len());
    for f in &found {
        let name = make_shard_name(
            &shards_account,
            &container,
            &container,
            &epoch,
            f.index as u64,
        );
        let mut sr = ShardRange::new(&name, &epoch, &f.lower, &f.upper);
        sr.object_count = f.object_count;
        ranges.push(sr);
    }
    match broker.merge_shard_ranges(ranges.clone()) {
        Ok(()) => {
            println!("Injected {} shard ranges.", ranges.len());
            println!("Run container-replicator to replicate them to other nodes.");
        }
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    }
    if enable {
        return cmd_enable(&mut broker);
    }
    println!("Use the enable sub-command to enable sharding.");
    EXIT_OK
}

/// Sort key for lower bound (empty = MIN).
fn sort_by_lower(ranges: &mut [ShardRange]) {
    ranges.sort_by(|a, b| {
        ShardRange::lower_cmp(&a.lower, &b.lower)
            .then_with(|| ShardRange::upper_cmp(&a.upper, &b.upper))
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// Read-only report of stored shard ranges: states, gaps, overlaps, coverage.
fn cmd_analyze(broker: &mut ContainerBroker) -> i32 {
    let ranges = match broker.get_shard_ranges(&GetShardRangesArgs {
        include_own: false,
        include_deleted: false,
        ..GetShardRangesArgs::default()
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    };
    let db_state = broker.get_db_state().ok();
    let own = broker.get_own_shard_range(true).ok().flatten();
    let root = broker.is_root_container().unwrap_or(true);

    println!("analyze: root_container = {root}");
    if let Some(st) = db_state {
        println!("analyze: db_state = {}", st.as_str());
    }
    println!("analyze: sharding_enabled = {}", sharding_enabled(broker));
    if let Some(own) = &own {
        println!(
            "analyze: own_range state={} lower={:?} upper={:?} epoch={:?}",
            state_text(own.state),
            own.lower,
            own.upper,
            own.epoch
        );
    } else {
        println!("analyze: own_range = null");
    }
    println!("analyze: shard_range_count = {}", ranges.len());

    if ranges.is_empty() {
        println!("analyze: no shard ranges stored");
        return EXIT_OK;
    }

    // State histogram
    let mut by_state: Vec<(i64, usize)> = Vec::new();
    for r in &ranges {
        if let Some(e) = by_state.iter_mut().find(|(s, _)| *s == r.state) {
            e.1 += 1;
        } else {
            by_state.push((r.state, 1));
        }
    }
    by_state.sort_by_key(|(s, _)| *s);
    print!("analyze: states =");
    for (s, n) in &by_state {
        print!(" {}={}", state_text(*s), n);
    }
    println!();

    let total_objects: i64 = ranges.iter().map(|r| r.object_count).sum();
    let total_rows: i64 = ranges.iter().map(|r| r.row_count()).sum();
    println!("analyze: total object_count = {total_objects}");
    println!("analyze: total row_count = {total_rows}");

    let non_shrinking: Vec<ShardRange> = ranges
        .iter()
        .filter(|r| r.state != shard_state::SHRINKING)
        .cloned()
        .collect();
    let overlaps = find_overlapping_ranges(&non_shrinking);
    if overlaps.is_empty() {
        println!("analyze: overlapping_groups = 0");
    } else {
        println!("analyze: overlapping_groups = {}", overlaps.len());
        for (i, group) in overlaps.iter().enumerate() {
            let names: Vec<&str> = group.iter().map(|r| r.name.as_str()).collect();
            println!("  overlap[{i}]: {}", names.join(", "));
        }
    }

    let gaps = find_namespace_gaps(&ranges);
    if gaps.is_empty() {
        println!("analyze: gaps = 0 (continuous coverage of namespace)");
    } else {
        println!("analyze: gaps = {}", gaps.len());
        for (i, (lo, hi)) in gaps.iter().enumerate() {
            let lo_s = if lo.is_empty() { "MIN" } else { lo.as_str() };
            let hi_s = if hi.is_empty() { "MAX" } else { hi.as_str() };
            println!("  gap[{i}]: ({lo_s}, {hi_s}]");
        }
    }

    // Compactible preview (defaults matching common Python conf)
    let sequences = find_compactible_sequences(&ranges, 100_000, 500_000, 1, -1);
    println!(
        "analyze: compactible_sequences (shrink_threshold=100000 expansion_limit=500000) = {}",
        sequences.len()
    );
    for (i, seq) in sequences.iter().enumerate() {
        let donors = &seq[..seq.len() - 1];
        let acceptor = &seq[seq.len() - 1];
        let donor_rows: i64 = donors.iter().map(|r| r.row_count()).sum();
        println!(
            "  compact[{i}]: {} donor(s) rows={donor_rows} → acceptor {}",
            donors.len(),
            acceptor.name
        );
    }

    // Exit 0 even when issues found — analyze is a report, not a gate.
    EXIT_OK
}

/// Neighbour sequences that can be compacted: donors + final acceptor.
/// Port of `find_compactible_shard_sequences` (simplified: no include_shrinking
/// already-in-progress filter beyond state checks).
fn find_compactible_sequences(
    shard_ranges: &[ShardRange],
    shrink_threshold: i64,
    expansion_limit: i64,
    max_shrinking: i64,
    max_expanding: i64,
) -> Vec<Vec<ShardRange>> {
    let mut ranges = shard_ranges.to_vec();
    sort_by_lower(&mut ranges);

    let is_shrinking_candidate = |sr: &ShardRange| {
        matches!(sr.state, shard_state::ACTIVE | shard_state::SHRINKING)
            && sr.row_count() < shrink_threshold
            && sr.row_count() <= expansion_limit
    };

    let sequence_complete = |sequence: &[ShardRange]| {
        if sequence.is_empty() {
            return false;
        }
        let last = &sequence[sequence.len() - 1];
        let seq_rows: i64 = sequence.iter().map(|r| r.row_count()).sum();
        !is_shrinking_candidate(last)
            || (max_shrinking > 0 && sequence.len() as i64 > max_shrinking)
            || seq_rows >= expansion_limit
    };

    let mut compactible = Vec::new();
    let mut index = 0usize;
    let mut expanding = 0i64;
    while (max_expanding < 0 || expanding < max_expanding) && index < ranges.len() {
        if !is_shrinking_candidate(&ranges[index]) {
            index += 1;
            continue;
        }
        let mut sequence = vec![ranges[index].clone()];
        for shard_range in ranges.iter().skip(index + 1) {
            let seq_upper = &sequence[sequence.len() - 1].upper;
            // gap: sequence.upper < shard_range.lower
            if !seq_upper.is_empty()
                && ShardRange::lower_cmp(&shard_range.lower, seq_upper)
                    == std::cmp::Ordering::Greater
            {
                break;
            }
            if !matches!(
                shard_range.state,
                shard_state::ACTIVE | shard_state::SHRINKING
            ) {
                break;
            }
            if shard_range.state == shard_state::SHRINKING {
                sequence.push(shard_range.clone());
            } else {
                let seq_rows: i64 = sequence.iter().map(|r| r.row_count()).sum();
                if seq_rows + shard_range.row_count() <= expansion_limit {
                    sequence.push(shard_range.clone());
                    if sequence_complete(&sequence) {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        index += sequence.len();
        if sequence.len() < 2 {
            continue;
        }
        let last_state = sequence[sequence.len() - 1].state;
        if last_state != shard_state::ACTIVE && last_state != shard_state::SHARDED {
            continue;
        }
        // already-in-progress sequences (include_shrinking=false): skip
        if sequence.iter().any(|sr| sr.state == shard_state::SHRINKING) {
            continue;
        }
        expanding += 1;
        compactible.push(sequence);
    }
    compactible
}

fn cmd_compact(
    broker: &mut ContainerBroker,
    force: bool,
    shrink_threshold: i64,
    expansion_limit: i64,
    max_shrinking: i64,
    max_expanding: i64,
) -> i32 {
    match broker.is_root_container() {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("WARNING: Shard containers cannot be compacted.");
            eprintln!("This command should be used on a root container.");
            return EXIT_ERROR;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    }
    match broker.get_db_state() {
        Ok(DbState::Sharded) => {}
        Ok(st) => {
            eprintln!(
                "WARNING: Container is not yet sharded (db_state={}) so cannot be compacted.",
                st.as_str()
            );
            return EXIT_ERROR;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    }

    let ranges = match broker.get_shard_ranges(&GetShardRangesArgs {
        include_own: false,
        include_deleted: false,
        ..GetShardRangesArgs::default()
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    };

    let non_shrinking: Vec<ShardRange> = ranges
        .iter()
        .filter(|r| r.state != shard_state::SHRINKING)
        .cloned()
        .collect();
    if !find_overlapping_ranges(&non_shrinking).is_empty() {
        eprintln!("WARNING: Container has overlapping shard ranges so cannot be compacted.");
        return EXIT_ERROR;
    }

    let compactible = find_compactible_sequences(
        &ranges,
        shrink_threshold,
        expansion_limit,
        max_shrinking,
        max_expanding,
    );
    if compactible.is_empty() {
        println!("No shards identified for compaction.");
        return EXIT_OK;
    }

    for sequence in &compactible {
        let acceptor = &sequence[sequence.len() - 1];
        let donors = &sequence[..sequence.len() - 1];
        let donor_rows: i64 = donors.iter().map(|r| r.row_count()).sum();
        println!(
            "Donor shard range(s) with total of {donor_rows} rows → acceptor {}:",
            acceptor.name
        );
        for d in donors {
            println!(
                "  donor {} ({:?}, {:?}] rows={} state={}",
                d.name,
                d.lower,
                d.upper,
                d.row_count(),
                state_text(d.state)
            );
        }
        println!(
            "  acceptor {} ({:?}, {:?}] rows={} state={}",
            acceptor.name,
            acceptor.lower,
            acceptor.upper,
            acceptor.row_count(),
            state_text(acceptor.state)
        );
    }
    println!(
        "Total of {} shard sequences identified for compaction.",
        compactible.len()
    );

    if !force {
        println!("Dry-run only. Re-run with --force to apply SHRINKING donors + expand acceptors.");
        return EXIT_OK;
    }

    let ts = Timestamp::now().internal();
    let mut to_merge = Vec::new();
    for sequence in &compactible {
        let donors = &sequence[..sequence.len() - 1];
        let mut acceptor = sequence[sequence.len() - 1].clone();
        if acceptor.expand(donors) {
            acceptor.timestamp = ts.clone();
        }
        if acceptor.update_state(shard_state::ACTIVE, Some(&ts)) {
            // state_timestamp already set by update_state
        }
        for d in donors {
            let mut donor = d.clone();
            if donor.update_state(shard_state::SHRINKING, Some(&ts)) {
                donor.epoch = Some(ts.clone());
            }
            to_merge.push(donor);
        }
        to_merge.push(acceptor);
    }
    match broker.merge_shard_ranges(to_merge) {
        Ok(()) => {
            println!(
                "Updated {} shard sequences for compaction.",
                compactible.len()
            );
            println!("Run container-replicator to replicate the changes to other nodes.");
            println!("Run container-sharder on all nodes to compact shards.");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_ERROR
        }
    }
}

fn cmd_repair(broker: &mut ContainerBroker, gaps_mode: bool, force: bool) -> i32 {
    match broker.is_root_container() {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("WARNING: Shard containers cannot be repaired.");
            eprintln!("This command should be used on a root container.");
            return EXIT_ERROR;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    }

    let ranges = match broker.get_shard_ranges(&GetShardRangesArgs {
        include_own: false,
        include_deleted: false,
        ..GetShardRangesArgs::default()
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_ERROR;
        }
    };

    if ranges.is_empty() {
        println!("No shards found, nothing to do.");
        return EXIT_OK;
    }

    if gaps_mode {
        return repair_gaps(broker, &ranges, force);
    }
    repair_overlaps(broker, &ranges, force)
}

fn repair_gaps(broker: &mut ContainerBroker, ranges: &[ShardRange], force: bool) -> i32 {
    let gaps = find_namespace_gaps(ranges);
    if gaps.is_empty() {
        println!(
            "Found one continuous span of {} shard ranges with no gaps.",
            ranges.len()
        );
        println!("No repairs necessary.");
        return EXIT_OK;
    }

    println!("Found {} gap(s):", gaps.len());
    let mut expansions: Vec<ShardRange> = Vec::new();
    let ts = Timestamp::now().internal();

    for (lo, hi) in &gaps {
        let lo_s = if lo.is_empty() { "MIN" } else { lo.as_str() };
        let hi_s = if hi.is_empty() { "MAX" } else { hi.as_str() };
        println!("  gap: ({lo_s}, {hi_s}]");

        // Prefer expanding the lower ACTIVE neighbour (upper bound = gap lower),
        // else the upper ACTIVE neighbour (lower bound = gap upper).
        let mut sorted = ranges.to_vec();
        sort_by_lower(&mut sorted);
        let lower_neighbor = sorted
            .iter()
            .filter(|r| r.state == shard_state::ACTIVE && r.upper == *lo)
            .last()
            .cloned();
        let upper_neighbor = sorted
            .iter()
            .find(|r| r.state == shard_state::ACTIVE && r.lower == *hi)
            .cloned();

        if let Some(mut n) = lower_neighbor {
            let donor = ShardRange::new("gap", &ts, lo, hi);
            if n.expand(std::slice::from_ref(&donor)) {
                n.timestamp = ts.clone();
                println!("    expand lower neighbor {} → upper {:?}", n.name, n.upper);
                expansions.push(n);
            }
        } else if let Some(mut n) = upper_neighbor {
            let donor = ShardRange::new("gap", &ts, lo, hi);
            if n.expand(std::slice::from_ref(&donor)) {
                n.timestamp = ts.clone();
                println!("    expand upper neighbor {} → lower {:?}", n.name, n.lower);
                expansions.push(n);
            }
        } else {
            println!("    WARNING: cannot fix gap: no ACTIVE neighbour");
        }
    }

    if expansions.is_empty() {
        eprintln!("No gap repairs could be planned.");
        return EXIT_ERROR;
    }

    if !force {
        println!(
            "Planned {} expansion(s). Re-run with --force to apply.",
            expansions.len()
        );
        return EXIT_OK;
    }

    match broker.merge_shard_ranges(expansions.clone()) {
        Ok(()) => {
            println!("Applied {} expanded shard range(s).", expansions.len());
            println!("Run container-replicator to replicate the changes to other nodes.");
            println!("Run container-sharder on all nodes to fill gaps.");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_ERROR
        }
    }
}

fn repair_overlaps(broker: &mut ContainerBroker, ranges: &[ShardRange], force: bool) -> i32 {
    if ranges
        .iter()
        .any(|r| r.state == shard_state::SHARDING || r.state == shard_state::SHRINKING)
    {
        eprintln!(
            "WARNING: Found shard ranges in sharding/shrinking state; \
             re-try repair after those complete."
        );
        return EXIT_ERROR;
    }

    let overlaps = find_overlapping_ranges(ranges);
    if overlaps.is_empty() {
        let gaps = find_namespace_gaps(ranges);
        if !gaps.is_empty() {
            println!("Found no overlapping shard ranges but {} gap(s).", gaps.len());
            println!("Use: … repair --gaps  to plan gap fills.");
            return EXIT_OK;
        }
        println!(
            "Found one complete sequence of {} shard ranges and no overlapping shard ranges.",
            ranges.len()
        );
        println!("No repairs necessary.");
        return EXIT_OK;
    }

    // Keep the highest-ranked range in each overlapping group as acceptor;
    // all other members of the group become donors. Rank: ACTIVE first,
    // then object_count, then name (stable).
    let mut donor_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut acceptor_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for group in &overlaps {
        let best = group
            .iter()
            .max_by(|a, b| {
                (a.state == shard_state::ACTIVE)
                    .cmp(&(b.state == shard_state::ACTIVE))
                    .then(a.object_count.cmp(&b.object_count))
                    .then(a.name.cmp(&b.name))
            })
            .expect("non-empty overlap group");
        acceptor_names.insert(best.name.clone());
        for r in group {
            if r.name != best.name {
                donor_names.insert(r.name.clone());
            }
        }
    }
    // A name chosen as acceptor in one group may still be a donor in another;
    // prefer acceptor.
    donor_names.retain(|n| !acceptor_names.contains(n));

    let donors: Vec<ShardRange> = ranges
        .iter()
        .filter(|r| donor_names.contains(&r.name))
        .cloned()
        .collect();
    let acceptors: Vec<ShardRange> = ranges
        .iter()
        .filter(|r| !donor_names.contains(&r.name))
        .cloned()
        .collect();

    println!("Repairs necessary to remove overlapping shard ranges.");
    println!(
        "Chosen {} acceptor range(s); {} donor range(s) will be set SHRINKING.",
        acceptors.len(),
        donors.len()
    );
    for d in &donors {
        println!(
            "  donor {} ({:?}, {:?}] objects={}",
            d.name, d.lower, d.upper, d.object_count
        );
    }
    for a in &acceptors {
        println!(
            "  acceptor {} ({:?}, {:?}] objects={}",
            a.name, a.lower, a.upper, a.object_count
        );
    }

    if donors.is_empty() {
        println!("No donor ranges to shrink.");
        return EXIT_OK;
    }

    if !force {
        println!("Dry-run only. Re-run with --force to mark donors SHRINKING.");
        return EXIT_OK;
    }

    let ts = Timestamp::now().internal();
    let mut to_merge = Vec::new();
    for d in &donors {
        let mut donor = d.clone();
        if donor.update_state(shard_state::SHRINKING, Some(&ts)) {
            donor.epoch = Some(ts.clone());
        }
        to_merge.push(donor);
    }
    match broker.merge_shard_ranges(to_merge) {
        Ok(()) => {
            println!("Updated {} donor shard ranges.", donors.len());
            println!("Run container-replicator to replicate the changes to other nodes.");
            println!("Run container-sharder on all nodes to repair shards.");
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_ERROR
        }
    }
}

fn parse_flag_i64(args: &[String], name: &str, default: i64) -> i64 {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let db = args.remove(0);
    if args.is_empty() {
        usage();
    }
    let cmd = args.remove(0);
    let mut broker = open_broker(&db);

    let code = match cmd.as_str() {
        "find" => {
            let shard_size: i64 = args
                .first()
                .and_then(|s| s.parse().ok())
                .unwrap_or(500_000);
            let min_size: i64 = args
                .get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(shard_size / 5)
                .max(1);
            cmd_find(&mut broker, shard_size, min_size)
        }
        "show" => {
            let include_deleted = args.iter().any(|a| a == "--include-deleted" || a == "-d");
            let brief = args.iter().any(|a| a == "--brief" || a == "-b");
            cmd_show(&mut broker, include_deleted, brief)
        }
        "info" => cmd_info(&mut broker),
        "enable" => cmd_enable(&mut broker),
        "delete" => {
            let force = args.iter().any(|a| a == "--force" || a == "-f");
            cmd_delete(&mut broker, force)
        }
        "merge" => {
            let force = args.iter().any(|a| a == "--force" || a == "-f");
            let input = args
                .iter()
                .find(|a| !a.starts_with('-'))
                .cloned()
                .unwrap_or_default();
            if input.is_empty() {
                eprintln!("usage: … merge --force <ranges.json>");
                EXIT_INVALID
            } else {
                cmd_merge(&mut broker, force, &input)
            }
        }
        "find_and_replace" => {
            let force = args.iter().any(|a| a == "--force" || a == "-f");
            let enable = args.iter().any(|a| a == "--enable");
            let nums: Vec<i64> = args
                .iter()
                .filter(|a| !a.starts_with('-'))
                .filter_map(|s| s.parse().ok())
                .collect();
            let shard_size = nums.first().copied().unwrap_or(500_000);
            let min_size = nums.get(1).copied().unwrap_or(shard_size / 5).max(1);
            cmd_find_and_replace(&mut broker, shard_size, min_size, enable, force)
        }
        "analyze" => cmd_analyze(&mut broker),
        "compact" => {
            let force = args.iter().any(|a| a == "--force" || a == "-f" || a == "--yes" || a == "-y");
            let shrink_threshold = parse_flag_i64(&args, "--shrink-threshold", 100_000);
            let expansion_limit = parse_flag_i64(&args, "--expansion-limit", 500_000);
            let max_shrinking = parse_flag_i64(&args, "--max-shrinking", 1);
            let max_expanding = parse_flag_i64(&args, "--max-expanding", -1);
            cmd_compact(
                &mut broker,
                force,
                shrink_threshold,
                expansion_limit,
                max_shrinking,
                max_expanding,
            )
        }
        "repair" => {
            let force = args.iter().any(|a| a == "--force" || a == "-f" || a == "--yes" || a == "-y");
            let gaps_mode = args.iter().any(|a| a == "--gaps");
            cmd_repair(&mut broker, gaps_mode, force)
        }
        "replace" => {
            eprintln!(
                "subcommand 'replace' is Deferred: use find_and_replace --force \
                 or merge --force <ranges.json> after delete --force."
            );
            EXIT_INVALID
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            usage();
        }
    };
    process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_db(tag: &str) -> (PathBuf, ContainerBroker) {
        let dir = std::env::temp_dir().join(format!(
            "msr-{}-{}-{}",
            tag,
            std::process::id(),
            Timestamp::now().internal().replace('.', "")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("c.db");
        let mut b = ContainerBroker::new(&db, "AUTH_test", "big");
        b.initialize("1751500000.00000", 0, "1751500000.00000", "id")
            .unwrap();
        for i in 0..10 {
            b.put_object(
                &format!("o{i:04}"),
                "1751500001.00000",
                1,
                "text/plain",
                "e",
                0,
                0,
                None,
                None,
            )
            .unwrap();
        }
        (dir, b)
    }

    #[test]
    fn find_returns_ranges_for_large_enough_container() {
        let (dir, mut b) = tmp_db("find");
        let (ranges, done) = b.find_shard_ranges(3, 1).unwrap();
        assert!(done);
        assert_eq!(ranges.len(), 4);
        assert_eq!(cmd_find(&mut b, 3, 1), EXIT_OK);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn show_and_info_after_merge() {
        let (dir, mut b) = tmp_db("show");
        let epoch = "1751500010.00000";
        let mut sr = ShardRange::new(".shards_AUTH_test/big-0", epoch, "", "o0004");
        sr.object_count = 5;
        b.merge_shard_ranges(vec![sr]).unwrap();
        assert_eq!(cmd_show(&mut b, false, true), EXIT_OK);
        assert_eq!(cmd_info(&mut b), EXIT_OK);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn enable_sets_sharding_sysmeta() {
        let (dir, mut b) = tmp_db("en");
        // Seed a FOUND range so enable is meaningful for ops.
        let epoch = "1751500010.00000";
        let ranges = vec![
            ShardRange::new(".shards_AUTH_test/big-0", epoch, "", "m"),
            ShardRange::new(".shards_AUTH_test/big-1", epoch, "m", ""),
        ];
        b.merge_shard_ranges(ranges).unwrap();
        assert_eq!(cmd_enable(&mut b), EXIT_OK);
        // Re-open with identity.
        let db = dir.join("c.db");
        let mut check = ContainerBroker::new(&db, "AUTH_test", "big");
        assert!(sharding_enabled(&mut check));
        let own = check.get_own_shard_range(false).unwrap().unwrap();
        assert_eq!(own.state, shard_state::SHARDING);
        assert!(own.epoch.is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn delete_force_soft_deletes() {
        let (dir, mut b) = tmp_db("del");
        let epoch = "1751500010.00000";
        b.merge_shard_ranges(vec![ShardRange::new(
            ".shards_AUTH_test/big-0",
            epoch,
            "",
            "",
        )])
        .unwrap();
        assert_eq!(cmd_delete(&mut b, false), EXIT_INVALID);
        assert_eq!(cmd_delete(&mut b, true), EXIT_OK);
        let left = b
            .get_shard_ranges(&GetShardRangesArgs {
                include_deleted: false,
                include_own: false,
                ..Default::default()
            })
            .unwrap();
        assert!(left.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn find_and_replace_injects_and_optionally_enables() {
        let (dir, mut b) = tmp_db("far");
        assert_eq!(
            cmd_find_and_replace(&mut b, 3, 1, true, true),
            EXIT_OK
        );
        let db = dir.join("c.db");
        let mut check = ContainerBroker::new(&db, "AUTH_test", "big");
        let ranges = check
            .get_shard_ranges(&GetShardRangesArgs::default())
            .unwrap();
        assert!(!ranges.is_empty());
        assert!(sharding_enabled(&mut check));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn state_text_known() {
        assert_eq!(state_text(shard_state::ACTIVE), "active");
        assert_eq!(state_text(shard_state::FOUND), "found");
    }

    #[test]
    fn analyze_reports_gaps_and_overlaps() {
        let (dir, mut b) = tmp_db("an");
        let epoch = "1751500010.00000";
        // gap between m and z, plus overlap on the high side
        let mut lo = ShardRange::new(".shards_AUTH_test/big-0", epoch, "", "m");
        lo.state = shard_state::ACTIVE;
        lo.object_count = 2;
        let mut mid = ShardRange::new(".shards_AUTH_test/big-1", epoch, "m", "z");
        mid.state = shard_state::ACTIVE;
        mid.object_count = 1;
        let mut ov = ShardRange::new(".shards_AUTH_test/big-ov", epoch, "p", "");
        ov.state = shard_state::ACTIVE;
        ov.object_count = 5;
        let mut hi = ShardRange::new(".shards_AUTH_test/big-2", epoch, "z", "");
        hi.state = shard_state::ACTIVE;
        b.merge_shard_ranges(vec![lo, mid, ov, hi]).unwrap();
        assert_eq!(cmd_analyze(&mut b), EXIT_OK);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn find_compactible_sequences_small_donor() {
        let mut a = ShardRange::new("a/c-0", "1", "", "m");
        a.state = shard_state::ACTIVE;
        a.object_count = 10; // below shrink_threshold
        let mut b = ShardRange::new("a/c-1", "1", "m", "");
        b.state = shard_state::ACTIVE;
        b.object_count = 50;
        let seqs = find_compactible_sequences(&[a, b], 20, 100, 1, -1);
        assert_eq!(seqs.len(), 1);
        assert_eq!(seqs[0].len(), 2);
        assert_eq!(seqs[0][1].name, "a/c-1");
    }

    fn force_sharded(b: &mut ContainerBroker) {
        let epoch = Timestamp::now().internal();
        b.enable_sharding(&epoch).unwrap();
        assert!(b.set_sharding_state().unwrap());
        assert!(b.set_sharded_state().unwrap());
        assert_eq!(b.get_db_state().unwrap(), DbState::Sharded);
    }

    #[test]
    fn compact_dry_run_and_force() {
        let (dir, mut b) = tmp_db("cp");
        let epoch = "1751500010.00000";
        let mut donor = ShardRange::new(".shards_AUTH_test/big-0", epoch, "", "m");
        donor.state = shard_state::ACTIVE;
        donor.object_count = 5;
        let mut acc = ShardRange::new(".shards_AUTH_test/big-1", epoch, "m", "");
        acc.state = shard_state::ACTIVE;
        acc.object_count = 50;
        b.merge_shard_ranges(vec![donor, acc]).unwrap();
        force_sharded(&mut b);
        // dry-run
        assert_eq!(cmd_compact(&mut b, false, 20, 100, 1, -1), EXIT_OK);
        let before = b
            .get_shard_ranges(&GetShardRangesArgs::default())
            .unwrap();
        assert!(before.iter().all(|r| r.state == shard_state::ACTIVE));
        // apply
        assert_eq!(cmd_compact(&mut b, true, 20, 100, 1, -1), EXIT_OK);
        let after = b
            .get_shard_ranges(&GetShardRangesArgs {
                include_deleted: false,
                include_own: false,
                ..Default::default()
            })
            .unwrap();
        assert!(
            after.iter().any(|r| r.state == shard_state::SHRINKING),
            "{after:?}"
        );
        let acceptor = after
            .iter()
            .find(|r| r.name.contains("big-1"))
            .expect("acceptor");
        assert_eq!(acceptor.lower, "");
        assert_eq!(acceptor.upper, "");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn repair_gaps_and_overlaps_force() {
        let (dir, mut b) = tmp_db("rp");
        let epoch = "1751500010.00000";
        // gap: m..z missing
        let mut lo = ShardRange::new(".shards_AUTH_test/g0", epoch, "", "m");
        lo.state = shard_state::ACTIVE;
        let mut hi = ShardRange::new(".shards_AUTH_test/g1", epoch, "z", "");
        hi.state = shard_state::ACTIVE;
        b.merge_shard_ranges(vec![lo, hi]).unwrap();
        assert_eq!(cmd_repair(&mut b, true, false), EXIT_OK);
        assert_eq!(cmd_repair(&mut b, true, true), EXIT_OK);
        let fixed = b
            .get_shard_ranges(&GetShardRangesArgs::default())
            .unwrap();
        assert!(
            find_namespace_gaps(&fixed).is_empty(),
            "gaps remain: {:?}",
            find_namespace_gaps(&fixed)
        );

        // Overlap case on a fresh set of names
        let mut a = ShardRange::new(".shards_AUTH_test/o0", epoch, "", "z");
        a.state = shard_state::ACTIVE;
        a.object_count = 1;
        let mut c = ShardRange::new(".shards_AUTH_test/o1", epoch, "m", "");
        c.state = shard_state::ACTIVE;
        c.object_count = 9;
        b.merge_shard_ranges(vec![a, c]).unwrap();
        assert_eq!(cmd_repair(&mut b, false, true), EXIT_OK);
        let after = b
            .get_shard_ranges(&GetShardRangesArgs::default())
            .unwrap();
        assert!(
            after.iter().any(|r| r.state == shard_state::SHRINKING),
            "{after:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
