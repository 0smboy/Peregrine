//! S3-0 characterization (PEREGRINE-NEXT-EXECUTION-DIRECTIVE-20260822).
//!
//! These tests encode required architecture. They MUST fail on the current
//! intercept+materialize+block_in_place path. A skip or `#[ignore]` is not
//! allowed: environment-unavailable-but-PASS is forbidden.

use std::fs;
use std::path::PathBuf;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    fs::read_to_string(crate_dir().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
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
fn signed_s3_put_must_not_be_fully_buffered_at_control_cap() {
    let proxy = read("../swift-proxy-server/src/lib.rs");
    let intercept_then_materialize = proxy.contains("if filters.iter().any(|f| f.intercepts_request(&head))")
        && proxy.contains("materialize(swift_http::MAX_CONTROL_BODY)");
    assert!(
        !intercept_then_materialize,
        "G3 S3-0 FAIL: proxy still materializes MAX_CONTROL_BODY (64 MiB) for every intercepting filter, including signed S3 PutObject/UploadPart"
    );
}

#[test]
fn s3_handle_request_async_must_not_block_in_place_or_block_on() {
    let mw = read("src/middleware.rs");
    let uses_bip = mw.contains("tokio::task::block_in_place");
    let uses_block_on = mw.contains("block_on(next");
    assert!(
        !uses_bip && !uses_block_on,
        "G3 S3-0 FAIL: handle_request_async still uses block_in_place={uses_bip} block_on={uses_block_on}"
    );
}

#[test]
fn s3_handle_request_async_must_take_streaming_incoming_body() {
    let mw = read("src/middleware.rs");
    let still_sync_request = mw.contains("fn handle_request_async")
        && mw.contains("req: Request")
        && !mw.contains("IncomingBody");
    assert!(
        !still_sync_request,
        "G3 S3-1 FAIL: handle_request_async still takes sync Request instead of AsyncRequest/IncomingBody"
    );
}

#[test]
fn aws_chunked_must_not_require_fully_buffered_body() {
    let mw = read("src/middleware.rs");
    let decode_after_buffer = mw.contains("decode_and_fix_aws_chunked")
        && mw.contains("block_in_place");
    assert!(
        !decode_after_buffer,
        "G3 S3-2 FAIL: aws-chunked decode still sits behind the sync/block_in_place adapter (needs incremental dechunk on IncomingBody)"
    );
}

#[test]
fn s3_client_cancel_must_not_run_sync_handle_to_completion() {
    let mw = read("src/middleware.rs");
    let sync_handle_on_async = mw.contains("self.handle(req, &next_sync)");
    assert!(
        !sync_handle_on_async,
        "G3 S3-0 FAIL: async intercept still calls sync handle(); client cancellation cannot abort a running sync dispatch"
    );
}
