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

//! Differential tests against golden container-DB fixtures produced by
//! the real Python `ContainerBroker` (see `fixtures/generate.py`). The
//! Rust broker replays the same operation sequences and must produce
//! identical schemas (character for character), rows, info dicts and
//! pending-file bytes; it must also read a Python-created database
//! directly.

use std::path::{Path, PathBuf};

use serde_json::Value as Json;
use swift_db::{ContainerBroker, DbValue, ListContainersArgs, ListObjectsArgs};

fn json_str_list(value: &Json) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

const T0: &str = "1751500000.00000";
const T1: &str = "1751500001.00000";
const T2: &str = "1751500002.00000";
const T3: &str = "1751500003.00000";
const T4: &str = "1751500004.00000";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn expectations() -> Json {
    let raw = std::fs::read(fixture("expectations.json"))
        .expect("missing fixtures; run rust/crates/swift-db/tests/fixtures/generate.py");
    let root: Json = serde_json::from_slice(&raw).unwrap();
    root["container"].clone()
}

fn account_expectations() -> Json {
    let raw = std::fs::read(fixture("expectations.json")).unwrap();
    let root: Json = serde_json::from_slice(&raw).unwrap();
    root["account"].clone()
}

fn tmpdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("swift-db-golden-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn broker_in(tmp: &Path, exp: &Json) -> ContainerBroker {
    let mut broker = ContainerBroker::new(&tmp.join("containers").join("ctest.db"), "a", "c");
    broker
        .initialize(
            exp["put_timestamp"].as_str().unwrap(),
            0,
            exp["created_at"].as_str().unwrap(),
            exp["db_id"].as_str().unwrap(),
        )
        .unwrap();
    broker
}

fn scenario<'e>(exp: &'e Json, desc: &str) -> &'e Json {
    exp["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["desc"] == desc)
        .unwrap_or_else(|| panic!("missing scenario {desc}"))
}

fn assert_info_matches(desc: &str, got: &[(String, DbValue)], want: &Json) {
    let want = want.as_object().unwrap();
    assert_eq!(got.len(), want.len(), "{desc}: info key count {got:?}");
    for (key, value) in want {
        let got_value = got
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .unwrap_or_else(|| panic!("{desc}: info missing {key}"));
        match (value, got_value) {
            (Json::String(s), DbValue::Text(g)) => assert_eq!(g, s, "{desc}: info[{key}]"),
            (Json::Number(n), DbValue::Int(g)) => {
                assert_eq!(*g, n.as_i64().unwrap(), "{desc}: info[{key}]")
            }
            (Json::Null, DbValue::Null) => {}
            other => panic!("{desc}: info[{key}] mismatch {other:?}"),
        }
    }
}

fn assert_objects_match(desc: &str, got: &[Vec<DbValue>], want: &Json) {
    let want = want.as_array().unwrap();
    assert_eq!(got.len(), want.len(), "{desc}: row count {got:?}");
    for (row_index, (got_row, want_row)) in got.iter().zip(want).enumerate() {
        let want_row = want_row.as_array().unwrap();
        assert_eq!(
            got_row.len(),
            want_row.len(),
            "{desc}: row {row_index} width"
        );
        for (col, (g, w)) in got_row.iter().zip(want_row).enumerate() {
            match (w, g) {
                (Json::String(s), DbValue::Text(t)) => {
                    assert_eq!(t, s, "{desc}: row {row_index} col {col}")
                }
                (Json::Number(n), DbValue::Int(i)) => {
                    assert_eq!(*i, n.as_i64().unwrap(), "{desc}: row {row_index} col {col}")
                }
                (Json::Null, DbValue::Null) => {}
                other => panic!("{desc}: row {row_index} col {col}: {other:?}"),
            }
        }
    }
}

#[test]
fn test_schema_matches_python() {
    let exp = expectations();
    let case = scenario(&exp, "init-only");
    let tmp = tmpdir("schema");
    let mut broker = broker_in(&tmp, &exp);
    let got = broker.schema_dump().unwrap();
    let want = case["schema"].as_array().unwrap();
    assert_eq!(got.len(), want.len(), "schema entry count: {got:#?}");
    for ((got_name, got_sql), want_entry) in got.iter().zip(want) {
        assert_eq!(got_name, want_entry[0].as_str().unwrap(), "schema names");
        assert_eq!(
            got_sql.as_deref(),
            want_entry[1].as_str(),
            "schema sql for {got_name}"
        );
    }
    assert_info_matches("init-only", &broker.get_info().unwrap(), &case["info"]);
    assert!(broker.object_rows().unwrap().is_empty());
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_pending_file_and_merge_match_python() {
    let exp = expectations();
    let case = scenario(&exp, "puts-and-merge");
    let tmp = tmpdir("pending");
    let mut broker = broker_in(&tmp, &exp);
    for put in case["puts"].as_array().unwrap() {
        broker
            .put_object(
                put[0].as_str().unwrap(),
                put[1].as_str().unwrap(),
                put[2].as_i64().unwrap(),
                put[3].as_str().unwrap(),
                put[4].as_str().unwrap(),
                put[5].as_i64().unwrap(),
                0,
                None,
                None,
            )
            .unwrap();
    }
    // the pending file must be byte-identical with Python's
    let pending = std::fs::read(broker.pending_file()).unwrap();
    let pending_hex: String = pending.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        pending_hex,
        case["pending_hex"].as_str().unwrap(),
        "pending bytes"
    );

    let info = broker.get_info().unwrap(); // commits pending
    assert_info_matches("puts-and-merge", &info, &case["info"]);
    assert_eq!(
        std::fs::metadata(broker.pending_file()).unwrap().len(),
        case["pending_size_after_commit"].as_u64().unwrap(),
        "pending truncated"
    );
    assert_objects_match(
        "puts-and-merge",
        &broker.object_rows().unwrap(),
        &case["objects"],
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_overwrite_and_delete_matches_python() {
    let exp = expectations();
    let case = scenario(&exp, "overwrite-and-delete");
    let tmp = tmpdir("overwrite");
    let mut broker = broker_in(&tmp, &exp);
    broker
        .put_object("o", T1, 5, "text/plain", "e1", 0, 0, None, None)
        .unwrap();
    broker
        .put_object("o", T0, 99, "stale/ct", "e0", 0, 0, None, None)
        .unwrap();
    broker.delete_object("gone", T2, 0).unwrap();
    broker
        .put_object(
            "o2",
            T1,
            7,
            "text/plain;swift_bytes=3",
            "e2",
            0,
            0,
            None,
            None,
        )
        .unwrap();
    broker.get_info().unwrap();
    broker.delete_object("o", T4, 0).unwrap();
    let info = broker.get_info().unwrap();
    assert_info_matches("overwrite-and-delete", &info, &case["info"]);
    assert_objects_match(
        "overwrite-and-delete",
        &broker.object_rows().unwrap(),
        &case["objects"],
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_ctype_meta_merge_matches_python() {
    let exp = expectations();
    let case = scenario(&exp, "ctype-meta-merge");
    let tmp = tmpdir("ctype");
    let mut broker = broker_in(&tmp, &exp);
    broker
        .put_object(
            "x",
            T1,
            10,
            "text/plain;swift_bytes=99",
            "ex",
            0,
            0,
            None,
            None,
        )
        .unwrap();
    broker.get_info().unwrap();
    broker
        .put_object("x", T1, 10, "text/updated", "ex", 0, 0, Some(T2), Some(T3))
        .unwrap();
    broker.get_info().unwrap();
    broker
        .put_object("x", T1, 10, "text/ignored", "ex", 0, 0, Some(T0), None)
        .unwrap();
    let info = broker.get_info().unwrap();
    assert_info_matches("ctype-meta-merge", &info, &case["info"]);
    assert_objects_match(
        "ctype-meta-merge",
        &broker.object_rows().unwrap(),
        &case["objects"],
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_batch_duplicates_match_python() {
    let exp = expectations();
    let case = scenario(&exp, "batch-duplicates");
    let tmp = tmpdir("dups");
    let mut broker = broker_in(&tmp, &exp);
    broker
        .put_object("dup", T2, 2, "ct/2", "e2", 0, 0, None, None)
        .unwrap();
    broker
        .put_object("dup", T1, 1, "ct/1", "e1", 0, 0, None, None)
        .unwrap();
    broker
        .put_object("dup", T3, 3, "ct/3", "e3", 0, 0, None, None)
        .unwrap();
    let info = broker.get_info().unwrap();
    assert_info_matches("batch-duplicates", &info, &case["info"]);
    assert_objects_match(
        "batch-duplicates",
        &broker.object_rows().unwrap(),
        &case["objects"],
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_reads_python_created_database() {
    let exp = expectations();
    let case = scenario(&exp, "puts-and-merge");
    let init_case = scenario(&exp, "init-only");
    // copy so pending/.lock artifacts don't pollute the fixture dir
    let tmp = tmpdir("python-db");
    let db_path = tmp.join("ctest.db");
    std::fs::copy(fixture("container_sc2.db"), &db_path).unwrap();

    let mut broker = ContainerBroker::new(&db_path, "a", "c");
    assert_info_matches("python-db info", &broker.get_info().unwrap(), &case["info"]);
    assert_objects_match(
        "python-db objects",
        &broker.object_rows().unwrap(),
        &case["objects"],
    );
    // the schema Python created must read back identically through the
    // Rust dump (proves both sides execute the same DDL text)
    let got = broker.schema_dump().unwrap();
    let want = init_case["schema"].as_array().unwrap();
    assert_eq!(got.len(), want.len(), "python-db schema count");
    for ((name, sql), want_entry) in got.iter().zip(want) {
        assert_eq!(name, want_entry[0].as_str().unwrap());
        assert_eq!(sql.as_deref(), want_entry[1].as_str(), "sql for {name}");
    }

    // and the Rust broker can keep writing to a Python-created DB
    broker
        .put_object("added-by-rust", T4, 1, "x/y", "er", 0, 0, None, None)
        .unwrap();
    broker.get_info().unwrap();
    assert_eq!(broker.object_rows().unwrap().len(), 4);
    std::fs::remove_dir_all(&tmp).unwrap();
}

// ---------------------------------------------------------------------------
// Account broker goldens
// ---------------------------------------------------------------------------

use swift_core::pickle::Value as PValue;
use swift_db::AccountBroker;

fn account_broker_in(tmp: &Path, exp: &Json) -> AccountBroker {
    let mut broker = AccountBroker::new(&tmp.join("accounts").join("atest.db"), "AUTH_test");
    broker
        .initialize(
            exp["put_timestamp"].as_str().unwrap(),
            exp["created_at"].as_str().unwrap(),
            exp["db_id"].as_str().unwrap(),
        )
        .unwrap();
    broker
}

/// Preserve the generator's str-vs-int choice for counts.
fn count_value(v: &Json) -> PValue {
    match v {
        Json::String(s) => PValue::Str(s.clone()),
        Json::Number(n) => PValue::Int(n.as_i64().unwrap()),
        other => panic!("unexpected count value {other:?}"),
    }
}

#[test]
fn test_account_schema_matches_python() {
    let exp = account_expectations();
    let case = scenario(&exp, "a-init-only");
    let tmp = tmpdir("a-schema");
    let mut broker = account_broker_in(&tmp, &exp);
    let got = broker.schema_dump().unwrap();
    let want = case["schema"].as_array().unwrap();
    assert_eq!(got.len(), want.len(), "schema entry count: {got:#?}");
    for ((got_name, got_sql), want_entry) in got.iter().zip(want) {
        assert_eq!(got_name, want_entry[0].as_str().unwrap(), "schema names");
        assert_eq!(
            got_sql.as_deref(),
            want_entry[1].as_str(),
            "schema sql for {got_name}"
        );
    }
    assert_info_matches("a-init-only", &broker.get_info().unwrap(), &case["info"]);
    assert!(broker.container_rows().unwrap().is_empty());
    // fresh account DBs have an EMPTY policy_stat (unlike containers)
    assert!(broker.policy_stat_rows().unwrap().is_empty());
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_account_pending_and_merge_match_python() {
    let exp = account_expectations();
    let case = scenario(&exp, "a-puts-and-merge");
    let tmp = tmpdir("a-pending");
    let mut broker = account_broker_in(&tmp, &exp);
    for put in case["puts"].as_array().unwrap() {
        broker
            .put_container(
                put[0].as_str().unwrap(),
                put[1].as_str().unwrap(),
                put[2].as_str().unwrap(),
                count_value(&put[3]),
                count_value(&put[4]),
                put[5].as_i64().unwrap(),
            )
            .unwrap();
    }
    let pending = std::fs::read(broker.pending_file()).unwrap();
    let pending_hex: String = pending.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        pending_hex,
        case["pending_hex"].as_str().unwrap(),
        "account pending bytes"
    );
    let info = broker.get_info().unwrap();
    assert_info_matches("a-puts-and-merge", &info, &case["info"]);
    assert_objects_match(
        "a-puts-and-merge containers",
        &broker.container_rows().unwrap(),
        &case["containers"],
    );
    assert_objects_match(
        "a-puts-and-merge policy_stat",
        &broker.policy_stat_rows().unwrap(),
        &case["policy_stat"],
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_account_merge_semantics_match_python() {
    let exp = account_expectations();
    let case = scenario(&exp, "a-merge-semantics");
    let tmp = tmpdir("a-merge");
    let mut broker = account_broker_in(&tmp, &exp);
    broker
        .put_container("c", T1, "0", PValue::Int(5), PValue::Int(50), 0)
        .unwrap();
    broker.get_info().unwrap();
    // older put with newer delete: counts zero-like -> deleted
    broker
        .put_container("c", T0, T2, PValue::Int(0), PValue::Int(0), 0)
        .unwrap();
    broker.get_info().unwrap();
    // resurrect with a newer put (str counts)
    broker
        .put_container(
            "c",
            T3,
            "0",
            PValue::Str("7".into()),
            PValue::Str("70".into()),
            0,
        )
        .unwrap();
    let info = broker.get_info().unwrap();
    assert_info_matches("a-merge-semantics", &info, &case["info"]);
    assert_objects_match(
        "a-merge-semantics containers",
        &broker.container_rows().unwrap(),
        &case["containers"],
    );
    assert_objects_match(
        "a-merge-semantics policy_stat",
        &broker.policy_stat_rows().unwrap(),
        &case["policy_stat"],
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_account_reads_python_created_database() {
    let exp = account_expectations();
    let case = scenario(&exp, "a-puts-and-merge");
    let tmp = tmpdir("a-python-db");
    let db_path = tmp.join("atest.db");
    std::fs::copy(fixture("account_a2.db"), &db_path).unwrap();

    let mut broker = AccountBroker::new(&db_path, "AUTH_test");
    assert_info_matches(
        "a-python-db info",
        &broker.get_info().unwrap(),
        &case["info"],
    );
    assert_objects_match(
        "a-python-db containers",
        &broker.container_rows().unwrap(),
        &case["containers"],
    );
    assert_objects_match(
        "a-python-db policy_stat",
        &broker.policy_stat_rows().unwrap(),
        &case["policy_stat"],
    );
    // and keep writing to it
    broker
        .put_container("added-by-rust", T4, "0", PValue::Int(1), PValue::Int(2), 0)
        .unwrap();
    broker.get_info().unwrap();
    assert_eq!(broker.container_rows().unwrap().len(), 4);
    std::fs::remove_dir_all(&tmp).unwrap();
}

// ---------------------------------------------------------------------------
// Batch A: metadata / reclaim / delete_db / listings
// ---------------------------------------------------------------------------

fn list_objects_args(call: &Json) -> ListObjectsArgs {
    ListObjectsArgs {
        limit: call["limit"].as_i64().unwrap(),
        marker: call["marker"].as_str().unwrap_or("").to_string(),
        end_marker: call["end_marker"].as_str().unwrap_or("").to_string(),
        prefix: call["prefix"].as_str().map(str::to_string),
        delimiter: call["delimiter"].as_str().map(str::to_string),
        path: call
            .get("path")
            .and_then(|p| p.as_str())
            .map(str::to_string),
        storage_policy_index: 0,
        reverse: call["reverse"].as_bool().unwrap_or(false),
        include_deleted: Some(call["include_deleted"].as_bool().unwrap_or(false)),
        allow_reserved: false,
    }
}

#[test]
fn test_container_listings_match_python() {
    let exp = expectations();
    let listings = &exp["listings"];
    let tmp = tmpdir("listings");
    let mut broker = broker_in(&tmp, &exp);
    for obj in listings["objects"].as_array().unwrap() {
        broker
            .put_object(
                obj[0].as_str().unwrap(),
                obj[1].as_str().unwrap(),
                obj[2].as_i64().unwrap(),
                obj[3].as_str().unwrap(),
                obj[4].as_str().unwrap(),
                obj[5].as_i64().unwrap(),
                0,
                None,
                None,
            )
            .unwrap();
    }
    broker.get_info().unwrap();
    for (index, case) in listings["cases"].as_array().unwrap().iter().enumerate() {
        let rows = broker
            .list_objects_iter(&list_objects_args(&case["call"]))
            .unwrap();
        assert_objects_match(
            &format!("container listing case {index} {}", case["call"]),
            &rows,
            &case["rows"],
        );
    }
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_container_metadata_reclaim_delete_match_python() {
    let exp = expectations();
    let meta_case = &exp["metadata"];
    let tmp = tmpdir("meta");
    let mut broker = broker_in(&tmp, &exp);
    let steps = meta_case["steps"].as_array().unwrap();
    let raw_for = |steps: &[Json], name: &str| -> String {
        steps.iter().find(|s| s[0] == name).unwrap()[1]
            .as_str()
            .unwrap()
            .to_string()
    };

    broker
        .update_metadata(&vec![(
            "X-Container-Meta-Color".to_string(),
            ("blue".to_string(), T1.to_string()),
        )])
        .unwrap();
    assert_eq!(
        broker.get_raw_metadata().unwrap(),
        raw_for(steps, "set-color")
    );

    broker
        .update_metadata(&vec![
            (
                "X-Container-Meta-Color".to_string(),
                ("red".to_string(), T3.to_string()),
            ),
            (
                "X-Container-Sysmeta-S".to_string(),
                ("sv".to_string(), T1.to_string()),
            ),
            (
                "X-Container-Meta-中文".to_string(),
                ("值\u{1}\"x\"".to_string(), T1.to_string()),
            ),
        ])
        .unwrap();
    assert_eq!(
        broker.get_raw_metadata().unwrap(),
        raw_for(steps, "newer-and-more"),
        "raw metadata bytes after mixed update"
    );

    broker
        .update_metadata(&vec![(
            "X-Container-Meta-Color".to_string(),
            ("green".to_string(), T2.to_string()),
        )])
        .unwrap();
    assert_eq!(
        broker.get_raw_metadata().unwrap(),
        raw_for(steps, "older-ignored")
    );

    broker
        .update_metadata(&vec![(
            "X-Container-Meta-中文".to_string(),
            (String::new(), T2.to_string()),
        )])
        .unwrap();
    assert_eq!(
        broker.get_raw_metadata().unwrap(),
        raw_for(steps, "delete-key")
    );

    broker
        .put_object(
            "old-tomb",
            "1000000000.00000",
            0,
            "application/deleted",
            "noetag",
            1,
            0,
            None,
            None,
        )
        .unwrap();
    broker
        .put_object(
            "new-tomb",
            T2,
            0,
            "application/deleted",
            "noetag",
            1,
            0,
            None,
            None,
        )
        .unwrap();
    broker
        .put_object("live", T2, 5, "text/x", "el", 0, 0, None, None)
        .unwrap();
    broker.get_info().unwrap();

    let age = meta_case["reclaim_age_timestamp"].as_f64().unwrap();
    let reclaimed = broker.reclaim(age, age).unwrap();
    assert_eq!(
        reclaimed,
        meta_case["reclaimed"].as_u64().unwrap(),
        "reclaimed count"
    );
    assert_eq!(
        broker.get_raw_metadata().unwrap(),
        raw_for(steps, "post-reclaim-metadata")
    );
    let names: Vec<String> = broker
        .object_rows()
        .unwrap()
        .iter()
        .map(|row| match &row[1] {
            DbValue::Text(name) => name.clone(),
            other => panic!("{other:?}"),
        })
        .collect();
    let mut names = names;
    names.sort();
    assert_eq!(names, json_str_list(&meta_case["post_reclaim_names"]));

    broker.delete_db(T4).unwrap();
    assert_eq!(
        broker.get_raw_metadata().unwrap(),
        meta_case["post_delete_metadata"].as_str().unwrap(),
        "metadata after delete_db"
    );
    assert_info_matches(
        "post-delete info",
        &broker.get_info().unwrap(),
        &meta_case["post_delete_info"],
    );
    assert_eq!(
        broker.is_deleted().unwrap(),
        meta_case["is_deleted"].as_bool().unwrap(),
        "is_deleted (live object keeps the container un-deleted)"
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_account_listings_match_python() {
    let exp = account_expectations();
    let listings = &exp["listings"];
    let tmp = tmpdir("a-listings");
    let mut broker = account_broker_in(&tmp, &exp);
    for c in listings["containers"].as_array().unwrap() {
        broker
            .put_container(
                c[0].as_str().unwrap(),
                c[1].as_str().unwrap(),
                c[2].as_str().unwrap(),
                count_value(&c[3]),
                count_value(&c[4]),
                c[5].as_i64().unwrap(),
            )
            .unwrap();
    }
    broker.get_info().unwrap();
    for (index, case) in listings["cases"].as_array().unwrap().iter().enumerate() {
        let call = &case["call"];
        let rows = broker
            .list_containers_iter(&ListContainersArgs {
                limit: call["limit"].as_i64().unwrap(),
                marker: call["marker"].as_str().unwrap_or("").to_string(),
                end_marker: call["end_marker"].as_str().unwrap_or("").to_string(),
                prefix: call["prefix"].as_str().map(str::to_string),
                delimiter: call["delimiter"].as_str().map(str::to_string),
                reverse: call["reverse"].as_bool().unwrap_or(false),
                allow_reserved: false,
            })
            .unwrap();
        assert_objects_match(
            &format!("account listing case {index} {call}"),
            &rows,
            &case["rows"],
        );
    }
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn test_account_metadata_reclaim_delete_match_python() {
    let exp = account_expectations();
    let case = &exp["metadata"];
    let tmp = tmpdir("a-meta");
    let mut broker = account_broker_in(&tmp, &exp);
    broker
        .update_metadata(&vec![
            (
                "X-Account-Meta-Temp".to_string(),
                ("1".to_string(), T1.to_string()),
            ),
            (
                "X-Account-Meta-Gone".to_string(),
                (String::new(), "1000000000.00000".to_string()),
            ),
        ])
        .unwrap();
    assert_eq!(
        broker.get_raw_metadata().unwrap(),
        case["raw_before"].as_str().unwrap()
    );
    broker.reclaim(1500000000.5, 1500000000.5).unwrap();
    assert_eq!(
        broker.get_raw_metadata().unwrap(),
        case["raw_after"].as_str().unwrap()
    );
    broker.delete_db(T4).unwrap();
    assert_eq!(
        broker.get_raw_metadata().unwrap(),
        case["post_delete_metadata"].as_str().unwrap()
    );
    assert_info_matches(
        "a-post-delete info",
        &broker.get_info().unwrap(),
        &case["post_delete_info"],
    );
    assert_eq!(
        broker.is_deleted().unwrap(),
        case["is_deleted"].as_bool().unwrap(),
        "account is_deleted (status counts)"
    );
    std::fs::remove_dir_all(&tmp).unwrap();
}
