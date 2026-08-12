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

//! Fast-POST content-type timestamp semantics (server.py POST 697-777),
//! mirroring the probe scenarios: (a) a POST without a Content-Type must NOT
//! fabricate a content-type timestamp — the original content-type keeps its
//! original timestamp; (b) a POST with a newer Content-Type wins and is
//! carried forward by later POSTs; (c) 409 only when BOTH the metadata and
//! the content-type timestamps are older-or-equal.

use swift_diskfile::{DiskFileConfig, MetaValue, Metadata, PolicyKind};
use swift_http::{HeaderKeyDict, Request, Response};
use swift_object_server::{
    iter_async_pendings, AsyncUpdate, ContainerUpdateMode, ObjectServer, ObjectServerConfig,
    UpdaterStats,
};

const T0: &str = "1751500000.00000";
const T1: &str = "1751500001.00000";
const T2: &str = "1751500002.00000";
const T3: &str = "1751500003.00000";

fn config(devices: &std::path::Path) -> ObjectServerConfig {
    ObjectServerConfig {
        devices: devices.to_path_buf(),
        mount_check: false,
        hash_config: swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec())
            .unwrap(),
        diskfile: swift_diskfile::DiskFileConfig::default(),
        policies: std::collections::HashMap::from([(0, swift_diskfile::PolicyKind::Replication)]),
        container_update_timeout: std::time::Duration::from_secs(1),
        container_update_mode: ContainerUpdateMode::Sync,
    }
}

fn put(server: &ObjectServer, ts: &str, ctype: &str) {
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", ts);
    headers.set("Content-Length", "5");
    headers.set("Content-Type", ctype);
    let resp = server.handle(Request {
        method: "PUT".into(),
        path: "/sda1/0/AUTH_test/c/o".into(),
        query_string: String::new(),
        headers,
        body: b"hello".to_vec().into(),
    });
    assert_eq!(resp.status, 201);
}

fn post(server: &ObjectServer, ts: &str, extra: &[(&str, &str)]) -> Response {
    let mut headers = HeaderKeyDict::new();
    headers.set("X-Timestamp", ts);
    for (k, v) in extra {
        headers.set(k, v);
    }
    server.handle(Request {
        method: "POST".into(),
        path: "/sda1/0/AUTH_test/c/o".into(),
        query_string: String::new(),
        headers,
        body: swift_http::Body::empty(),
    })
}

/// A fresh DiskFile over the same object the requests target.
fn open_df(device: &std::path::Path) -> swift_diskfile::DiskFile {
    swift_diskfile::DiskFile::new(
        device,
        0,
        "AUTH_test",
        "c",
        "o",
        PolicyKind::Replication,
        0,
        &swift_core::hashing::HashPathConfig::new(b"".to_vec(), b"changeme".to_vec()).unwrap(),
        DiskFileConfig::default(),
    )
    .unwrap()
}

fn datadir_files(df: &swift_diskfile::DiskFile) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(df.datadir())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn meta<'m>(m: &'m Metadata, key: &str) -> Option<&'m str> {
    m.iter()
        .find(|(k, _)| matches!(k, MetaValue::Str(s) if s.eq_ignore_ascii_case(key)))
        .and_then(|(_, v)| v.as_str())
}

fn header<'a>(u: &'a AsyncUpdate, key: &str) -> &'a str {
    u.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

/// The single async_pending on the device (POSTs overwrite the PUT's file:
/// both are keyed by the object hash and the DATA timestamp).
fn only_async_update(device: &std::path::Path) -> AsyncUpdate {
    let mut stats = UpdaterStats::default();
    let updates = iter_async_pendings(device, &mut stats);
    assert_eq!(stats.errors, 0);
    assert_eq!(updates.len(), 1, "exactly one async_pending expected");
    updates.into_iter().next().unwrap()
}

#[test]
fn test_post_without_content_type_keeps_original_ctype_timestamp() {
    let dir = std::env::temp_dir().join(format!("swift-os-fastpost-a-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();
    let server = ObjectServer::new(config(&dir));

    put(&server, T0, "text/plain");
    let resp = post(&server, T2, &[("X-Object-Meta-Color", "red")]);
    assert_eq!(resp.status, 202);

    // the .meta name is the bare metadata timestamp — no forged content-type
    // timestamp encoding — and it carries NO content-type, because the
    // current one comes from the .data file (server.py 742-748)
    let mut df = open_df(&device);
    assert!(
        datadir_files(&df).contains(&format!("{T2}.meta")),
        "expected {T2}.meta in {:?}",
        datadir_files(&df)
    );
    let o = df.open(None).unwrap();
    assert_eq!(o.timestamp().unwrap().internal(), T2);
    assert_eq!(o.content_type().unwrap(), Some("text/plain"));
    assert_eq!(o.content_type_timestamp().unwrap().internal(), T0);
    assert_eq!(
        meta(o.get_metadata().unwrap(), "X-Object-Meta-Color"),
        Some("red")
    );
    assert_eq!(
        meta(o.get_metafile_metadata().unwrap().unwrap(), "Content-Type"),
        None,
        "the node-local content-type must not be copied into the .meta"
    );

    // container update: x-timestamp is the DATA timestamp, x-meta-timestamp
    // the POST's, and the content-type rides with its ORIGINAL timestamp
    let u = only_async_update(&device);
    assert_eq!(header(&u, "x-timestamp"), T0);
    assert_eq!(header(&u, "x-meta-timestamp"), T2);
    assert_eq!(header(&u, "x-content-type"), "text/plain");
    assert_eq!(header(&u, "x-content-type-timestamp"), T0);
    assert_eq!(header(&u, "x-size"), "5");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_post_with_newer_content_type_wins_and_is_carried_forward() {
    let dir = std::env::temp_dir().join(format!("swift-os-fastpost-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();
    let server = ObjectServer::new(config(&dir));

    put(&server, T0, "text/plain");
    assert_eq!(
        post(&server, T2, &[("Content-Type", "application/x-new")]).status,
        202
    );
    {
        let mut df = open_df(&device);
        // the .meta filename encodes (meta ts, ctype ts): equal timestamps
        // encode as an explicit +0 delta
        assert!(
            datadir_files(&df).contains(&format!("{T2}+0.meta")),
            "expected {T2}+0.meta in {:?}",
            datadir_files(&df)
        );
        let o = df.open(None).unwrap();
        assert_eq!(o.content_type().unwrap(), Some("application/x-new"));
        assert_eq!(o.content_type_timestamp().unwrap().internal(), T2);
    }
    let u = only_async_update(&device);
    assert_eq!(header(&u, "x-content-type"), "application/x-new");
    assert_eq!(header(&u, "x-content-type-timestamp"), T2);

    // a later POST WITHOUT a content-type must carry the t2 content-type —
    // with its t2 timestamp — forward into the new .meta, because that
    // content-type does NOT come from the .data file (server.py 742-748)
    assert_eq!(post(&server, T3, &[]).status, 202);
    let mut df = open_df(&device);
    // delta t2-t3 is -1s = -0x186a0
    assert!(
        datadir_files(&df).contains(&format!("{T3}-186a0.meta")),
        "expected {T3}-186a0.meta in {:?}",
        datadir_files(&df)
    );
    let o = df.open(None).unwrap();
    assert_eq!(o.timestamp().unwrap().internal(), T3);
    assert_eq!(o.content_type().unwrap(), Some("application/x-new"));
    assert_eq!(o.content_type_timestamp().unwrap().internal(), T2);

    let u = only_async_update(&device);
    assert_eq!(header(&u, "x-timestamp"), T0);
    assert_eq!(header(&u, "x-meta-timestamp"), T3);
    assert_eq!(header(&u, "x-content-type"), "application/x-new");
    assert_eq!(header(&u, "x-content-type-timestamp"), T2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_409_only_when_both_timestamps_are_stale() {
    let dir = std::env::temp_dir().join(format!("swift-os-fastpost-c-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let device = dir.join("sda1");
    std::fs::create_dir_all(&device).unwrap();
    let server = ObjectServer::new(config(&dir));

    put(&server, T0, "text/plain");
    // equal meta timestamp, no content-type (ctype timestamp zero): both
    // comparisons stale -> 409 with X-Backend-Timestamp
    let resp = post(&server, T0, &[]);
    assert_eq!(resp.status, 409);
    assert_eq!(resp.headers.get("X-Backend-Timestamp"), Some(T0));
    // equal meta timestamp and a content-type implicitly stamped with that
    // same timestamp: still both older-or-equal -> 409
    assert_eq!(
        post(&server, T0, &[("Content-Type", "text/x-any")]).status,
        409
    );

    // set up a .meta at t1
    assert_eq!(
        post(&server, T1, &[("X-Object-Meta-Color", "red")]).status,
        202
    );
    // equal meta timestamp BUT a newer explicit content-type timestamp: NOT a
    // conflict — only the content-type is applied, the .meta metadata is
    // preserved verbatim (server.py 703-707, 731-748)
    let resp = post(
        &server,
        T1,
        &[
            ("Content-Type", "text/x-new"),
            ("Content-Type-Timestamp", T2),
        ],
    );
    assert_eq!(resp.status, 202);

    let mut df = open_df(&device);
    assert!(
        datadir_files(&df).contains(&format!("{T1}+186a0.meta")),
        "expected {T1}+186a0.meta in {:?}",
        datadir_files(&df)
    );
    let o = df.open(None).unwrap();
    assert_eq!(
        o.timestamp().unwrap().internal(),
        T1,
        "the original metadata timestamp is preserved"
    );
    assert_eq!(o.content_type().unwrap(), Some("text/x-new"));
    assert_eq!(o.content_type_timestamp().unwrap().internal(), T2);
    assert_eq!(
        meta(o.get_metadata().unwrap(), "X-Object-Meta-Color"),
        Some("red"),
        "existing .meta user metadata is preserved verbatim"
    );

    let u = only_async_update(&device);
    assert_eq!(header(&u, "x-timestamp"), T0);
    assert_eq!(header(&u, "x-meta-timestamp"), T1);
    assert_eq!(header(&u, "x-content-type"), "text/x-new");
    assert_eq!(header(&u, "x-content-type-timestamp"), T2);
    std::fs::remove_dir_all(&dir).unwrap();
}
