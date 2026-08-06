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
//! `find_and_replace` (force/no-prompt mode).
//!
//! **Deferred (explicit exit 2):** `compact`, `repair`, `analyze`, interactive
//! replace prompts, shrink/expand sequences — need compactible-sequence /
//! overlap-repair helpers not yet in `swift-db`.
//!
//! Multi-node KEEP claim still blocked by live Contabo quorum drill + ring-
//! directed HTTP create on all primaries (see sharder residuals).

use std::env;
use std::path::Path;
use std::process;

use swift_core::timestamp::Timestamp;
use swift_db::{
    make_shard_name, shard_state, shards_account_name, ContainerBroker, DbState,
    GetShardRangesArgs, ShardRange,
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
           compact | repair | analyze          Deferred (exit 2)\n\
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

fn deferred(cmd: &str) -> i32 {
    eprintln!(
        "subcommand '{cmd}' is Deferred: needs shrink/expand/repair helpers \
         not yet in swift-db (see manage_shard_ranges.py compact/repair/analyze)."
    );
    EXIT_INVALID
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
        "compact" | "repair" | "analyze" | "replace" => deferred(&cmd),
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
}
