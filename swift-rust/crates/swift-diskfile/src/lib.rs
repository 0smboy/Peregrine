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

//! Object on-disk layout, ported from `swift/obj/diskfile.py`.
//!
//! Everything here is a *compatibility contract* with the Python
//! implementation: directory layout, filename encoding, xattr pickled
//! metadata, `hashes.pkl`/`hashes.invalid` consistency machinery and the
//! on-disk file-selection state machine must behave identically so Rust
//! and Python object servers can share disks in one cluster.
//!
//! This crate covers the format layer: filename parsing and construction,
//! `get_ondisk_files` for both replication and EC policies, metadata
//! read/write, suffix hashing with cleanup/reclaim, and partition hash
//! consolidation.
//!
//! Deferred to the object-server milestone: `DiskFile` open/read/write
//! object lifecycle, async pendings, auditing walk generators, ssync
//! helpers, and splice/zero-copy I/O.

mod auditor;
mod cleanup;
mod diskfile;
mod error;
mod hashes;
mod layout;
mod metadata;
mod naming;
mod ondisk;
mod relinker;

pub use auditor::{
    audit_device, audit_device_with_watcher, audit_devices, audit_devices_with_watcher,
    audit_locations, audit_object, audit_object_with_watcher, list_devices, AuditOutcome,
    AuditReport, ObjectAuditWatcher, WatcherDecision,
};
pub use cleanup::{
    cleanup_ondisk_files, get_partition_hashes, hash_suffix_repl, CleanupConfig, CleanupResult,
    SuffixHashes,
};
pub use diskfile::{
    DiskFile, DiskFileConfig, DiskFileRangeReader, DiskFileReader, DiskFileStreamReader,
    DiskFileWriter, DurablePut,
};
pub use error::DiskFileError;
pub use hashes::{
    consolidate_hashes, hashes_to_pickle, invalidate_hash, lock_path, read_hashes, write_hashes,
    write_pickle, Hashes, PathLock,
};
pub use layout::{
    extract_policy_index, get_async_dir, get_data_dir, get_part_path, get_tmp_dir,
    quarantine_renamer, storage_directory, valid_suffix, ASYNCDIR_BASE, DATADIR_BASE, TMP_BASE,
};
pub use metadata::{
    decode_metadata, encode_metadata, metadata_from_pickle, metadata_to_pickle, read_metadata,
    write_metadata, MetaValue, Metadata, DEFAULT_XATTR_SIZE, METADATA_CHECKSUM_KEY, METADATA_KEY,
};
pub use naming::{
    make_ec_ondisk_filename, make_ondisk_filename, parse_ondisk_filename, splitext, FileInfo,
    PolicyKind,
};
pub use ondisk::{get_ondisk_files, FragPref, OndiskFiles};
pub use relinker::{partition_for_hash, relink_device, RelinkReport};

/// Default `reclaim_age` (one week), from the Python implementation.
pub const DEFAULT_RECLAIM_AGE: f64 = 604800.0;
/// Default `commit_window` in seconds.
pub const DEFAULT_COMMIT_WINDOW: f64 = 60.0;
pub const HASH_FILE: &str = "hashes.pkl";
pub const HASH_INVALIDATIONS_FILE: &str = "hashes.invalid";
pub const PICKLE_PROTOCOL: u8 = 2;
