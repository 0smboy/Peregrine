//! S3-1/S3-2 construction fences (PEREGRINE-FOUR-NODE-G0-G8-EXECUTION-DIRECTIVE).
//!
//! S3-1 tests must PASS after the streaming ABI lands. Remaining S3-2/S3-3
//! fences assert the leftover control-path defects so `cargo test` stays
//! honest: they pass *while the defect exists* and must be inverted in the
//! slice that removes it. A skip or `#[ignore]` is not allowed.

use std::fs;
use std::path::PathBuf;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    fs::read_to_string(crate_dir().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn streaming_fn_src() -> String {
    let mw = read("src/middleware.rs");
    let start = mw
        .find("async fn put_object_streaming")
        .expect("put_object_streaming missing");
    let rest = &mw[start..];
    let end = rest
        .find("async fn put_object_versioned_buffered")
        .expect("put_object_versioned_buffered missing");
    rest[..end].to_string()
}

#[test]
fn max_control_body_is_64_mib() {
    assert_eq!(
        swift_http::MAX_CONTROL_BODY,
        64 * 1024 * 1024,
        "control-plane materialize cap must stay visible so >64MiB tests stay honest"
    );
}

#[test]
fn s3_1_proxy_streams_request_before_materialize() {
    let proxy = read("../swift-proxy-server/src/lib.rs");
    let start = proxy
        .find("impl AsyncService for ProxyAsyncService")
        .expect("ProxyAsyncService missing");
    let src = &proxy[start..];
    let stream_at = src
        .find("if filters.iter().any(|f| f.streams_request(&head))")
        .expect("proxy must branch on streams_request");
    let mat_at = src
        .find("materialize(swift_http::MAX_CONTROL_BODY)")
        .expect("control-plane materialize must remain for SLO/XML");
    assert!(
        stream_at < mat_at,
        "G3 S3-1 FAIL: streams_request must run before intercept materialize(MAX_CONTROL_BODY)"
    );
}

#[test]
fn s3_1_put_object_streaming_has_no_block_in_place() {
    let src = streaming_fn_src();
    assert!(
        !src.contains("tokio::task::block_in_place"),
        "G3 S3-1 FAIL: put_object_streaming still uses block_in_place"
    );
    assert!(
        !src.contains("block_on("),
        "G3 S3-1 FAIL: put_object_streaming still uses block_on"
    );
    assert!(
        !src.contains("self.handle("),
        "G3 S3-1 FAIL: streaming PUT still calls sync handle()"
    );
}

#[test]
fn s3_1_handle_streaming_request_takes_incoming_body() {
    let mw = read("src/middleware.rs");
    assert!(
        mw.contains("fn handle_streaming_request")
            && mw.contains("req: AsyncRequest")
            && mw.contains("IncomingBody"),
        "G3 S3-1 FAIL: streaming ABI must take AsyncRequest/IncomingBody"
    );
}

#[test]
fn s3_1_aws_chunked_excluded_from_streaming_put() {
    let mw = read("src/middleware.rs");
    let start = mw
        .find("fn is_s3_streaming_object_put")
        .expect("is_s3_streaming_object_put missing");
    let src = &mw[start..];
    let end = src.find("/// Paths that are never unsigned S3").unwrap_or(src.len());
    let src = &src[..end];
    assert!(
        src.contains("is_aws_chunked_request"),
        "G3 S3-1 FAIL: streaming PUT must refuse aws-chunked (S3-2)"
    );
}

#[test]
fn s3_2_remaining_aws_chunked_decode_is_still_buffered() {
    let mw = read("src/middleware.rs");
    let still = mw.contains("decode_and_fix_aws_chunked") && mw.contains("block_in_place");
    assert!(
        still,
        "S3-2 tracker inverted: aws-chunked left the sync adapter; convert this test to assert absence"
    );
}

#[test]
fn s3_3_remaining_control_path_still_uses_sync_handle() {
    let mw = read("src/middleware.rs");
    let still = mw.contains("self.handle(req, &next_sync)")
        && mw.contains("tokio::task::block_in_place");
    assert!(
        still,
        "S3-3 tracker inverted: control handle_request_async is native async; convert this test to assert absence"
    );
}
