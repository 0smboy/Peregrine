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

//! Account/container database backends, ported from `swift/common/db.py`
//! and `swift/container/backend.py`.
//!
//! Everything here is a compatibility contract: the SQLite schemas
//! (including trigger and view SQL, byte-for-byte), the `chexor` rolling
//! hash, the `.pending` file format (`:`-separated base64 pickles) and
//! the `merge_items` newest-wins semantics must match the Python
//! implementation exactly, so Rust and Python brokers can share and
//! replicate the same database files.
//!
//! This increment covers the container broker's core write/read path.
//! Deferred: account backend, `db_replicator` protocol, sharding state
//! machine, metadata column handling, reclaim.

mod account;
mod auditor;
mod broker;
mod container;
mod repl_loop;
mod replicator;
mod shard;
mod util;
mod vacuum;

pub use account::{zero_like, AccountBroker, ContainerRecord, ListContainersArgs};
pub use auditor::{
    audit_account_dbs, audit_container_dbs, audit_dbs_on_devices, db_locations, list_db_devices,
    DbAuditReport,
};
pub use broker::{py_json_dumps_metadata, py_json_parse_metadata, BrokerMetadata};
pub use container::{
    check_merge_own_shard_range, get_db_files, hash_container_name, make_db_file_path,
    make_shard_name, parse_db_filename, shards_account_name, ContainerBroker, DbState, DbValue,
    FoundShardRange, GetShardRangesArgs, ListObjectsArgs, ObjectRecord,
};
pub use repl_loop::{
    iter_db_partitions, remove_replicated_handoff_db, repl_peers, run_once as replicator_run_once,
    DbPartition, DbReplicateClient, ReplLoopStats,
};
pub use replicator::{
    incorrect_policy_index, replicate_account_db, replicate_completion_rpc, replicate_container_db,
    replicate_container_db_role, rsync_db, rsync_dest_db_name, rsync_would_recreate_retiring,
    sync_shard_ranges_to_peer, ReplicateOutcome, RsyncTransport,
};
pub use shard::{
    find_namespace_gaps, find_overlapping_ranges, merge_shards, resolve_shard_range_states,
    sift_shard_ranges, state as shard_state, ShardRange, CLEAVING_STATES, SHARD_RANGE_KEYS,
    SHARD_STATS_STATES, SHARD_UPDATE_STATES,
};
pub use util::{chexor, is_corruption_error, is_readonly_dbmoved, quarantine_db, renamer, DbError};
pub use vacuum::{
    sample_db_space, sample_device_db_space, vacuum_db, vacuum_device_dbs, DbSpaceSample,
    DbSpaceTotals,
};

/// Max size of a `.pending` file before puts are applied directly
/// (`swift.common.db.PENDING_CAP`).
pub const PENDING_CAP: u64 = 131072;
pub const PICKLE_PROTOCOL: u8 = 2;
