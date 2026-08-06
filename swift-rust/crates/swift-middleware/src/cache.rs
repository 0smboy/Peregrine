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

//! `cache` / `[filter:cache]` (egg:swift#memcache): holds a live
//! [`MemcacheClient`] for the proxy pipeline, porting
//! `swift/common/middleware/memcache.py`.
//!
//! Python injects `env['swift.cache'] = self.memcache` and otherwise
//! passes through. Rust [`Request`](swift_http::Request) has no WSGI
//! environ, so this filter keeps the client alive (shared across
//! workers via process-local state) for TempAuth / info-cache callers
//! that opt in later. The handle path is a pure pass-through — matching
//! Python's `__call__` — so listing the filter in `[pipeline:main]` is
//! no longer a silent skip.
//!
//! The proxy also opens its own MemcacheClient from the same
//! `memcache_servers` list for shared account/container info-cache L2
//! (P1c). This filter remains the pipeline pass-through holder.

use std::sync::Mutex;
use std::time::Duration;

use swift_http::{Request, Response};
use swift_memcache::{MemcacheClient, MemcacheConfig, TcpConn};

use crate::{Middleware, NextFn};

/// Default when neither `[filter:cache]` nor `memcache.conf` supplies
/// servers (Python `MemcacheRing` default).
pub const DEFAULT_MEMCACHE_SERVERS: &str = "127.0.0.1:11211";

/// Pipeline filter named `cache` (Paste: `egg:swift#memcache`).
pub struct Cache {
    client: Mutex<MemcacheClient<TcpConn>>,
    servers: Vec<String>,
}

impl Cache {
    /// Build from an explicit server list (`host:port` strings).
    pub fn from_servers(servers: Vec<String>) -> Result<Self, String> {
        if servers.is_empty() {
            return Err("cache: at least one memcache server is required".into());
        }
        let client = MemcacheClient::connect(
            servers.clone(),
            MemcacheConfig::default(),
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .map_err(|e| format!("cache: memcache connect setup failed: {e}"))?;
        Ok(Cache {
            client: Mutex::new(client),
            servers,
        })
    }

    /// Parse `memcache_servers` (comma-separated) into a [`Cache`].
    pub fn from_servers_csv(csv: &str) -> Result<Self, String> {
        let servers: Vec<String> = csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        Self::from_servers(servers)
    }

    /// Configured servers, in order.
    pub fn servers(&self) -> &[String] {
        &self.servers
    }

    /// Borrow the underlying client (ops need `&mut`).
    pub fn with_client<R>(
        &self,
        f: impl FnOnce(&mut MemcacheClient<TcpConn>) -> R,
    ) -> Result<R, String> {
        let mut guard = self
            .client
            .lock()
            .map_err(|_| "cache: memcache client lock poisoned".to_string())?;
        Ok(f(&mut guard))
    }
}

impl Middleware for Cache {
    fn handle(&self, req: Request, next: &NextFn) -> Response {
        // Python: env['swift.cache'] = self.memcache; return self.app(...)
        next(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn from_servers_csv_parses_list() {
        let c = Cache::from_servers_csv("127.0.0.1:11211, 10.0.0.2:11211").unwrap();
        assert_eq!(
            c.servers(),
            &["127.0.0.1:11211".to_string(), "10.0.0.2:11211".to_string()]
        );
    }

    #[test]
    fn empty_csv_is_error() {
        assert!(Cache::from_servers_csv("  ,  ").is_err());
    }

    #[test]
    fn pass_through_preserves_status() {
        let c = Cache::from_servers_csv(DEFAULT_MEMCACHE_SERVERS).unwrap();
        let next: NextFn = Arc::new(|_r| Response::new(204));
        let req = Request {
            method: "GET".into(),
            path: "/v1/a".into(),
            query_string: String::new(),
            headers: swift_http::HeaderKeyDict::new(),
            body: swift_http::Body::empty(),
        };
        assert_eq!(c.handle(req, &next).status, 204);
    }
}
