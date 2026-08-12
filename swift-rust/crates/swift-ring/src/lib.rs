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

//! Partitioned consistent hashing ring, ported from `swift/common/ring/`.
//!
//! Reads both ring file formats (v1 and v2, `ring/io.py`) and provides
//! node lookup with byte-identical semantics to the Python `Ring` class
//! (`ring/ring.py`): `get_part`, `get_part_nodes`, `get_nodes` and the
//! four-pass `get_more_nodes` handoff ordering.
//!
//! Deferred: ring *writing*, the ring builder, composite rings, and
//! automatic mtime-based reloading (callers should watch the file mtime
//! and rebuild the [`Ring`], as Python does internally).

mod builder;
mod io;
mod ring;
mod writer;

use std::fmt;

pub use crate::builder::{BuilderDevice, RingBuilder};
pub use crate::io::{IndexEntry, RingFile};
pub use crate::ring::{calc_replica_count, HandoffNode, PartNode, Ring, RingData, RingDevice};

/// Error loading or querying a ring.
#[derive(Debug)]
pub struct RingError(pub String);

impl fmt::Display for RingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for RingError {}

impl From<std::io::Error> for RingError {
    fn from(e: std::io::Error) -> Self {
        RingError(e.to_string())
    }
}

impl From<serde_json::Error> for RingError {
    fn from(e: serde_json::Error) -> Self {
        RingError(format!("Invalid JSON in ring file: {e}"))
    }
}
