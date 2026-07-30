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

//! Error type, mirroring the style of `swift-db`'s `DbError` and the
//! `swift.common.exceptions` memcache exceptions.

use std::fmt;

/// Errors raised by the memcache client.
///
/// The variants map onto the Python exceptions in
/// `swift.common.exceptions`:
///
/// * [`MemcacheError::Connection`] -> `MemcacheConnectionError`
/// * [`MemcacheError::IncrNotFound`] -> `MemcacheIncrNotFoundError`
/// * [`MemcacheError::NoServers`] -> the `"No memcached connections
///   succeeded."` `MemcacheConnectionError` raised when every server in the
///   ring has been tried and failed.
#[derive(Debug)]
pub enum MemcacheError {
    /// A server returned an unexpected/failed protocol response
    /// (`MemcacheConnectionError`).
    Connection(String),
    /// An `incr`/`decr` raced with expiry so the key vanished between the
    /// failed increment and the fallback `add` (`MemcacheIncrNotFoundError`).
    /// Unlike other errors this does *not* error-limit the server.
    IncrNotFound(String),
    /// No candidate server could even be attempted because every one is
    /// currently error-limited. (When a server *is* attempted and fails, the
    /// underlying [`MemcacheError::Io`] / [`MemcacheError::Connection`] is
    /// returned instead, so the real cause is not hidden.)
    NoServers,
    /// Transport error talking to a server.
    Io(std::io::Error),
    /// A value could not be (de)serialized as JSON.
    Json(serde_json::Error),
}

impl fmt::Display for MemcacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemcacheError::Connection(s) => write!(f, "memcache connection error: {s}"),
            MemcacheError::IncrNotFound(s) => write!(f, "memcache incr not found: {s}"),
            MemcacheError::NoServers => write!(f, "No memcached connections succeeded."),
            MemcacheError::Io(e) => write!(f, "{e}"),
            MemcacheError::Json(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MemcacheError {}

impl From<std::io::Error> for MemcacheError {
    fn from(e: std::io::Error) -> Self {
        MemcacheError::Io(e)
    }
}

impl From<serde_json::Error> for MemcacheError {
    fn from(e: serde_json::Error) -> Self {
        MemcacheError::Json(e)
    }
}
