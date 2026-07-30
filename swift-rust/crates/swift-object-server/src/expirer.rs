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

//! The object expirer daemon core, ported from `swift/obj/expirer.py`.
//!
//! Objects with an `X-Delete-At` are enqueued into the hidden
//! `.expiring_objects` account: a task object named
//! `"<delete_at>-<account>/<container>/<object>"` inside a task container
//! bucketed by `delete_at // divisor * divisor`. This daemon lists due task
//! containers, and for each task whose delete time has passed it DELETEs the
//! real object (guarded by `X-If-Delete-At`) and then pops the queue entry.
//!
//! This module ports the pure task-name / bucket arithmetic (byte-identical
//! to Python, golden-tested) plus the due-task iteration and the
//! delete-then-pop flow over a pluggable [`ExpiryClient`]. Deferred: the
//! InternalClient listing transport, process-sharding (`hash_mod`), delay
//! reaping, and async-delete content-type bookkeeping (modelled as a flag).

use swift_http::split_path;

/// Default `expiring_objects_container_divisor` (one bucket per day).
pub const EXPIRER_CONTAINER_DIVISOR: i64 = 86400;

/// The hidden account holding the expiry queue.
pub const EXPIRER_ACCOUNT_NAME: &str = ".expiring_objects";

/// Content-type marking an async (best-effort) delete task.
pub const ASYNC_DELETE_TYPE: &str = "application/async-deleted";

/// `normalize_delete_at_timestamp`: a delete-at time as Swift stores it, a
/// zero-padded 10-digit integer second count (or `%016.5f` high precision).
pub fn normalize_delete_at_timestamp(timestamp: i64) -> String {
    format!("{timestamp:010}")
}

/// High-precision form (`%016.5f`), used for sub-second task objects.
pub fn normalize_delete_at_timestamp_hp(timestamp: f64) -> String {
    format!("{timestamp:016.5}")
}

/// `build_task_obj`: the task object name for a queued expiry.
pub fn build_task_obj(delete_at: i64, account: &str, container: &str, obj: &str) -> String {
    format!(
        "{}-{}/{}/{}",
        normalize_delete_at_timestamp(delete_at),
        account,
        container,
        obj
    )
}

/// `parse_task_obj`: split `"<ts>-<account>/<container>/<object>"` back into
/// its parts. Returns `None` on a malformed name.
pub fn parse_task_obj(task_obj: &str) -> Option<(i64, String, String, String)> {
    let (timestamp, target_path) = task_obj.split_once('-')?;
    let delete_at = ts_seconds(timestamp)?;
    let parts = split_path(&format!("/{target_path}"), 3, 3, true).ok()?;
    let account = parts[0].clone()?;
    let container = parts[1].clone()?;
    let object = parts[2].clone()?;
    Some((delete_at, account, container, object))
}

/// `get_expirer_container`: the task container bucket a delete-at falls in.
pub fn get_expirer_container(x_delete_at: i64, divisor: i64) -> String {
    // Python: int(x_delete_at) // divisor * divisor, floor division
    let bucket = x_delete_at.div_euclid(divisor) * divisor;
    normalize_delete_at_timestamp(bucket)
}

/// `is_expected_task_container`: whether a bucket int is a legal task
/// container for this divisor (guards against stray containers).
pub fn is_expected_task_container(task_container_int: i64, divisor: i64, per_divisor: i64) -> bool {
    let r = (task_container_int - 1).rem_euclid(divisor);
    divisor - r <= per_divisor
}

/// Parse the integer-seconds value of a Swift timestamp string.
fn ts_seconds(ts: &str) -> Option<i64> {
    let head = ts.split('_').next().unwrap_or("0");
    // integer or float form; truncate toward the second like Timestamp
    head.parse::<f64>().ok().map(|f| f as i64)
}

/// A due expiry task.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskInfo {
    pub task_account: String,
    pub task_container: String,
    pub task_object: String,
    pub target_account: String,
    pub target_container: String,
    pub target_object: String,
    pub delete_timestamp: i64,
    pub is_async_delete: bool,
}

impl TaskInfo {
    /// `/<account>/<container>/<object>` of the real object to delete.
    pub fn target_path(&self) -> String {
        format!(
            "{}/{}/{}",
            self.target_account, self.target_container, self.target_object
        )
    }
}

/// Iterate the task-container listing, yielding tasks whose delete time has
/// passed. Mirrors `_iter_task_container`: the listing is name-sorted (so
/// timestamp-ascending); the first not-yet-due task stops iteration.
///
/// `objects` is the container listing as `(name, content_type)` pairs.
pub fn iter_due_tasks(
    task_account: &str,
    task_container: &str,
    objects: &[(String, String)],
    now: i64,
) -> Vec<TaskInfo> {
    let mut out = Vec::new();
    for (name, content_type) in objects {
        let Some((delete_timestamp, ta, tc, to)) = parse_task_obj(name) else {
            continue;
        };
        if delete_timestamp > now {
            // nothing later can be due yet
            break;
        }
        out.push(TaskInfo {
            task_account: task_account.to_string(),
            task_container: task_container.to_string(),
            task_object: name.clone(),
            target_account: ta,
            target_container: tc,
            target_object: to,
            delete_timestamp,
            is_async_delete: content_type == ASYNC_DELETE_TYPE,
        });
    }
    out
}

/// The result of attempting to delete the real object.
#[derive(Debug, Clone, PartialEq)]
pub enum DeleteResult {
    /// 2xx (or an accepted 409/404 for async) — the object is gone.
    Deleted,
    /// 404/412 for a non-async delete: the X-Delete-At no longer matches or
    /// the object vanished; only safe to pop once it is older than reclaim.
    Stale,
    /// Any other failure; retry on a later pass.
    Error,
}

/// Abstraction over the expirer's two backend actions.
pub trait ExpiryClient {
    /// DELETE the real object with `X-If-Delete-At: <ts>`.
    fn delete_actual_object(&self, task: &TaskInfo) -> DeleteResult;
    /// Remove the queue entry (DELETE the task object from its container).
    fn pop_queue(&self, task: &TaskInfo) -> bool;
}

/// Sweep stats.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExpirerStats {
    pub objects: u64,
    pub errors: u64,
    pub skipped_retained: u64,
}

/// Process one due task: delete the object, then pop the queue on success
/// (or on a stale delete older than `reclaim_age`). `now` and `reclaim_age`
/// are seconds. Returns whether the queue entry was popped.
pub fn process_task(
    task: &TaskInfo,
    now: i64,
    reclaim_age: i64,
    client: &dyn ExpiryClient,
    stats: &mut ExpirerStats,
) -> bool {
    match client.delete_actual_object(task) {
        DeleteResult::Deleted => {
            let popped = client.pop_queue(task);
            stats.objects += 1;
            popped
        }
        DeleteResult::Stale => {
            // Retry later unless the task is older than the reclaim age, in
            // which case the real object is presumed gone for good.
            if task.delete_timestamp <= now - reclaim_age {
                let popped = client.pop_queue(task);
                stats.objects += 1;
                popped
            } else {
                stats.skipped_retained += 1;
                false
            }
        }
        DeleteResult::Error => {
            stats.errors += 1;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn test_build_and_parse_roundtrip() {
        let name = build_task_obj(1751500000, "AUTH_test", "c", "o/deep");
        assert_eq!(name, "1751500000-AUTH_test/c/o/deep");
        let (ts, a, c, o) = parse_task_obj(&name).unwrap();
        assert_eq!(ts, 1751500000);
        assert_eq!(a, "AUTH_test");
        assert_eq!(c, "c");
        assert_eq!(o, "o/deep", "object keeps its slashes");
    }

    #[test]
    fn test_normalize_matches_python_format() {
        assert_eq!(normalize_delete_at_timestamp(0), "0000000000");
        assert_eq!(normalize_delete_at_timestamp(1751500000), "1751500000");
    }

    #[test]
    fn test_expirer_container_bucket() {
        // divisor 86400: everything in the same day maps to the day's floor
        let day = 1751500000 / 86400 * 86400;
        assert_eq!(
            get_expirer_container(1751500000, 86400),
            normalize_delete_at_timestamp(day)
        );
        assert_eq!(
            get_expirer_container(1751500000 + 5, 86400),
            get_expirer_container(1751500000, 86400)
        );
    }

    #[test]
    fn test_iter_due_stops_at_future() {
        let now = 1751500000;
        let objs = vec![
            (
                build_task_obj(now - 100, "a", "c", "past1"),
                String::new(),
            ),
            (build_task_obj(now, "a", "c", "now"), String::new()),
            (
                build_task_obj(now + 100, "a", "c", "future"),
                String::new(),
            ),
            (build_task_obj(now + 200, "a", "c", "later"), String::new()),
        ];
        let due = iter_due_tasks(".expiring_objects", "0000000000", &objs, now);
        // the two <= now are due; iteration stops at the first future task
        assert_eq!(due.len(), 2);
        assert_eq!(due[0].target_object, "past1");
        assert_eq!(due[1].target_object, "now");
    }

    struct FakeExpiry {
        delete_result: DeleteResult,
        popped: Mutex<Vec<String>>,
    }
    impl ExpiryClient for FakeExpiry {
        fn delete_actual_object(&self, _task: &TaskInfo) -> DeleteResult {
            self.delete_result.clone()
        }
        fn pop_queue(&self, task: &TaskInfo) -> bool {
            self.popped.lock().unwrap().push(task.task_object.clone());
            true
        }
    }

    #[test]
    fn test_process_deletes_then_pops() {
        let now = 1751500000;
        let objs = vec![(build_task_obj(now - 10, "AUTH_x", "c", "o"), String::new())];
        let due = iter_due_tasks(".expiring_objects", "0000000000", &objs, now);
        let client = FakeExpiry {
            delete_result: DeleteResult::Deleted,
            popped: Mutex::new(Vec::new()),
        };
        let mut stats = ExpirerStats::default();
        let popped = process_task(&due[0], now, 604800, &client, &mut stats);
        assert!(popped);
        assert_eq!(stats.objects, 1);
        assert_eq!(client.popped.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_stale_recent_retained_old_popped() {
        let now = 1751500000;
        let reclaim = 604800;
        let client = FakeExpiry {
            delete_result: DeleteResult::Stale,
            popped: Mutex::new(Vec::new()),
        };
        // recent stale -> retained, not popped
        let recent = TaskInfo {
            task_account: ".expiring_objects".into(),
            task_container: "0".into(),
            task_object: "t1".into(),
            target_account: "a".into(),
            target_container: "c".into(),
            target_object: "o".into(),
            delete_timestamp: now - 10,
            is_async_delete: false,
        };
        let mut stats = ExpirerStats::default();
        assert!(!process_task(&recent, now, reclaim, &client, &mut stats));
        assert_eq!(stats.skipped_retained, 1);

        // old stale -> popped
        let old = TaskInfo {
            delete_timestamp: now - reclaim - 1,
            task_object: "t2".into(),
            ..recent.clone()
        };
        assert!(process_task(&old, now, reclaim, &client, &mut stats));
        assert_eq!(*client.popped.lock().unwrap(), vec!["t2".to_string()]);
    }
}
