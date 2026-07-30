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

//! The container reconciler core, ported from `swift/container/reconciler.py`.
//!
//! When an object is written under the wrong storage policy (e.g. during a
//! policy change race), the container server enqueues a *misplaced object*
//! entry into the hidden `.misplaced_objects` account. The reconciler daemon
//! later drains that queue, moving each object to the container's correct
//! policy (newest-timestamp wins) and removing the misplaced copy.
//!
//! The queue naming is the interoperability contract with the Python container
//! server that writes it, so it is golden-tested byte-for-byte:
//!
//! * queue container = `str(int(meta_ts) // 3600 * 3600)` (the object's
//!   last-modified hour bucket),
//! * queue object    = `"{policy_index}:/{account}/{container}/{object}"`,
//! * content-type    = `application/x-put` | `application/x-delete`.
//!
//! Deferred: the `cmp_policy_info` container-recreation tie-break, the
//! per-node direct GET/PUT/DELETE move transport, and the two-phase enqueue.
//! The move *decision* (which policy is authoritative, whether a queue entry
//! is still actionable) is ported and unit-tested over a pluggable client.

use swift_core::timestamp::decode_timestamps;
use swift_http::split_path;

/// The hidden account holding the misplaced-object queue.
pub const MISPLACED_OBJECTS_ACCOUNT: &str = ".misplaced_objects";

/// Queue containers bucket objects by the hour of their last modification.
pub const MISPLACED_OBJECTS_CONTAINER_DIVISOR: i64 = 3600;

/// `get_reconciler_container_name`: the queue container an object's misplaced
/// entry belongs in — its meta timestamp floored to the hour, as a plain
/// (non-zero-padded) integer string.
pub fn reconciler_container_name(obj_timestamp: &str) -> Option<String> {
    let (data, _ctype, meta) = decode_timestamps(obj_timestamp, false).ok()?;
    // non-explicit decode yields Some(data) when the meta part is absent
    let meta = meta.unwrap_or(data);
    let secs = meta.as_secs_f64() as i64; // int(Timestamp)
    let bucket = secs.div_euclid(MISPLACED_OBJECTS_CONTAINER_DIVISOR)
        * MISPLACED_OBJECTS_CONTAINER_DIVISOR;
    Some(bucket.to_string())
}

/// `get_reconciler_obj_name`: the queue object name encoding the misplaced
/// object's (wrong) policy index and full path.
pub fn reconciler_obj_name(policy_index: i64, account: &str, container: &str, obj: &str) -> String {
    format!("{policy_index}:/{account}/{container}/{obj}")
}

/// `get_reconciler_content_type`: the content-type marking the queued op.
pub fn reconciler_content_type(op: &str) -> Option<&'static str> {
    match op.to_ascii_lowercase().as_str() {
        "put" => Some("application/x-put"),
        "delete" => Some("application/x-delete"),
        _ => None,
    }
}

/// A parsed misplaced-object queue entry.
#[derive(Debug, Clone, PartialEq)]
pub struct QueueEntry {
    pub policy_index: i64,
    pub account: String,
    pub container: String,
    pub obj: String,
}

/// `parse_raw_obj` (name portion): split `"{pi}:/{account}/{container}/{obj}"`
/// back into its parts.
pub fn parse_reconciler_obj_name(raw: &str) -> Option<QueueEntry> {
    let (pi, rest) = raw.split_once(':')?;
    let policy_index: i64 = pi.parse().ok()?;
    // rest is "/account/container/object"
    let parts = split_path(rest, 3, 3, true).ok()?;
    Some(QueueEntry {
        policy_index,
        account: parts[0].clone()?,
        container: parts[1].clone()?,
        obj: parts[2].clone()?,
    })
}

/// The op a queue entry represents.
#[derive(Debug, Clone, PartialEq)]
pub enum QueueOp {
    Put,
    Delete,
}

/// Recover the op from a queue entry's content-type.
pub fn op_from_content_type(content_type: &str) -> Option<QueueOp> {
    match content_type {
        "application/x-put" => Some(QueueOp::Put),
        "application/x-delete" => Some(QueueOp::Delete),
        _ => None,
    }
}

/// The reconcile decision for one queue entry, given the container's current
/// (authoritative) storage policy index.
#[derive(Debug, Clone, PartialEq)]
pub enum ReconcileDecision {
    /// The queued policy is already the authoritative one; the object is not
    /// misplaced (any more) — just clean up the queue entry.
    AlreadyCorrect,
    /// Move the object from `from_policy` to `to_policy`.
    Move { from_policy: i64, to_policy: i64 },
}

/// Decide what to do with a misplaced-object queue entry. If the queued
/// (wrong) policy equals the container's current policy, the object is no
/// longer misplaced; otherwise it must be moved to the current policy.
pub fn decide(entry: &QueueEntry, current_policy_index: i64) -> ReconcileDecision {
    if entry.policy_index == current_policy_index {
        ReconcileDecision::AlreadyCorrect
    } else {
        ReconcileDecision::Move {
            from_policy: entry.policy_index,
            to_policy: current_policy_index,
        }
    }
}

/// The outcome of reconciling one misplaced-object queue entry.
#[derive(Debug, Clone, PartialEq)]
pub enum ReconcileOutcome {
    /// The object was moved to the correct policy and the queue entry popped.
    Moved,
    /// The object was already in the correct policy; the queue entry popped.
    AlreadyCorrect,
    /// The move failed; the queue entry is left for a later pass.
    Failed,
}

/// The reconciler's backend actions, so the move orchestration is testable
/// without a live cluster. `move_object` performs the GET-from-wrong-policy →
/// PUT-to-right-policy → DELETE-from-wrong-policy sequence; `pop_queue` removes
/// the queue entry.
pub trait ReconcileClient {
    /// Move the object from `from_policy` to `to_policy`. Returns success.
    fn move_object(&self, entry: &QueueEntry, from_policy: i64, to_policy: i64) -> bool;
    /// Remove the misplaced-object queue entry.
    fn pop_queue(&self, entry: &QueueEntry) -> bool;
}

/// Reconcile one misplaced-object queue entry against the container's current
/// (authoritative) storage policy: move the object to the right policy if
/// needed, then pop the queue entry (Python `container/reconciler.py`
/// `process_queue_item`).
pub fn reconcile(
    entry: &QueueEntry,
    current_policy_index: i64,
    client: &dyn ReconcileClient,
) -> ReconcileOutcome {
    match decide(entry, current_policy_index) {
        ReconcileDecision::AlreadyCorrect => {
            client.pop_queue(entry);
            ReconcileOutcome::AlreadyCorrect
        }
        ReconcileDecision::Move {
            from_policy,
            to_policy,
        } => {
            if client.move_object(entry, from_policy, to_policy) {
                client.pop_queue(entry);
                ReconcileOutcome::Moved
            } else {
                ReconcileOutcome::Failed
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct FakeReconcile {
        moves: Mutex<Vec<(i64, i64)>>,
        popped: Mutex<Vec<String>>,
        move_ok: bool,
    }
    impl ReconcileClient for FakeReconcile {
        fn move_object(&self, _e: &QueueEntry, from: i64, to: i64) -> bool {
            self.moves.lock().unwrap().push((from, to));
            self.move_ok
        }
        fn pop_queue(&self, e: &QueueEntry) -> bool {
            self.popped.lock().unwrap().push(e.obj.clone());
            true
        }
    }

    #[test]
    fn test_reconcile_moves_then_pops() {
        let e = QueueEntry {
            policy_index: 1,
            account: "a".into(),
            container: "c".into(),
            obj: "o".into(),
        };
        let client = FakeReconcile {
            moves: Mutex::new(Vec::new()),
            popped: Mutex::new(Vec::new()),
            move_ok: true,
        };
        assert_eq!(reconcile(&e, 0, &client), ReconcileOutcome::Moved);
        assert_eq!(*client.moves.lock().unwrap(), vec![(1, 0)]);
        assert_eq!(client.popped.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_reconcile_already_correct_just_pops() {
        let e = QueueEntry {
            policy_index: 0,
            account: "a".into(),
            container: "c".into(),
            obj: "o".into(),
        };
        let client = FakeReconcile {
            moves: Mutex::new(Vec::new()),
            popped: Mutex::new(Vec::new()),
            move_ok: true,
        };
        assert_eq!(reconcile(&e, 0, &client), ReconcileOutcome::AlreadyCorrect);
        assert!(client.moves.lock().unwrap().is_empty());
        assert_eq!(client.popped.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_reconcile_failed_move_keeps_entry() {
        let e = QueueEntry {
            policy_index: 2,
            account: "a".into(),
            container: "c".into(),
            obj: "o".into(),
        };
        let client = FakeReconcile {
            moves: Mutex::new(Vec::new()),
            popped: Mutex::new(Vec::new()),
            move_ok: false,
        };
        assert_eq!(reconcile(&e, 0, &client), ReconcileOutcome::Failed);
        assert!(client.popped.lock().unwrap().is_empty());
    }


    #[test]
    fn test_reconciler_obj_name_and_parse() {
        let name = reconciler_obj_name(1, "AUTH_test", "c", "o/deep");
        assert_eq!(name, "1:/AUTH_test/c/o/deep");
        let e = parse_reconciler_obj_name(&name).unwrap();
        assert_eq!(e.policy_index, 1);
        assert_eq!(e.account, "AUTH_test");
        assert_eq!(e.container, "c");
        assert_eq!(e.obj, "o/deep");
    }

    #[test]
    fn test_content_type_roundtrip() {
        assert_eq!(reconciler_content_type("put"), Some("application/x-put"));
        assert_eq!(reconciler_content_type("DELETE"), Some("application/x-delete"));
        assert_eq!(reconciler_content_type("bogus"), None);
        assert_eq!(op_from_content_type("application/x-put"), Some(QueueOp::Put));
        assert_eq!(
            op_from_content_type("application/x-delete"),
            Some(QueueOp::Delete)
        );
    }

    #[test]
    fn test_container_name_hour_bucket() {
        // 1751500000 // 3600 * 3600 = 1751497200
        let name = reconciler_container_name("1751500000.00000").unwrap();
        assert_eq!(name, "1751497200");
        // not zero-padded (unlike the expirer's queue)
        assert!(!name.starts_with('0'));
    }

    #[test]
    fn test_decide_move_vs_correct() {
        let e = QueueEntry {
            policy_index: 1,
            account: "a".into(),
            container: "c".into(),
            obj: "o".into(),
        };
        assert_eq!(decide(&e, 0), ReconcileDecision::Move { from_policy: 1, to_policy: 0 });
        assert_eq!(decide(&e, 1), ReconcileDecision::AlreadyCorrect);
    }
}
