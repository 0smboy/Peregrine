//! Gate 1 (AGENTS.md §26.A / §35): idle keep-alive must not occupy a worker.
//!
//! Phase 0: this test encodes the *target* property and is expected **RED**
//! on the current sync server (`workers=2` + two idle keep-alives starve a
//! third request until `head_deadline`).

#[path = "harness.rs"]
mod harness;

use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn idle_keepalive_does_not_starve_a_third_request() {
    let server = harness::spawn_server(2, Arc::new(harness::tiny_ok));
    let _idle_a = harness::get_keepalive(server.addr).expect("keepalive a");
    let _idle_b = harness::get_keepalive(server.addr).expect("keepalive b");
    thread::sleep(Duration::from_millis(80));

    let (status, elapsed) = harness::get_close_timed(server.addr, Duration::from_millis(400))
        .expect("third request must complete without waiting for an idle keep-alive deadline");
    assert_eq!(status, 200, "third request status");
    assert!(
        elapsed < Duration::from_millis(400),
        "third request took {elapsed:?}; idle keep-alive is occupying workers (L1)"
    );
}
