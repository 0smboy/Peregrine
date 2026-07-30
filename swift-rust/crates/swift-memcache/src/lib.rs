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

//! A simple, consistent-hashed memcache client, ported from
//! `swift.common.memcached` (the `MemcacheRing` class).
//!
//! Why Swift ships its own client is explained at length in the Python
//! module: python-memcached does not use consistent hashing, so adding or
//! removing a server invalidates most cached items. This port keeps the same
//! wire behaviour so a Rust daemon and a Python daemon can share a memcached
//! pool:
//!
//! * Keys are md5-hashed to hex (`md5hash`) before being placed on the ring
//!   *and* before being sent as the actual memcached key.
//! * Each server is spread across the ring with [`NODE_WEIGHT`] virtual nodes
//!   at `md5hash("<server>-<i>")`, and a key is routed by an md5 consistent
//!   hash (`bisect` over the sorted virtual nodes).
//! * A server that errors [`error_limit_count`](MemcacheConfig) times within
//!   [`error_limit_time`](MemcacheConfig) seconds is skipped for
//!   [`error_limit_duration`](MemcacheConfig) seconds.
//! * Values serialized with JSON carry the [`JSON_FLAG`] flag byte, exactly
//!   as Python's `set(..., serialize=True)` does.
//!
//! The connection layer is injectable through the [`MemcacheConn`] trait, so
//! tests drive an in-memory fake and production uses [`TcpConn`].

mod conn;
mod error;

pub use conn::{MemcacheConn, TcpConn};
pub use error::MemcacheError;

use std::collections::BTreeMap;

use md5::{Digest, Md5};

/// Default memcached port.
pub const DEFAULT_MEMCACHED_PORT: u16 = 11211;

/// Serialization flag for pickled values. This client never *writes* pickles
/// (a security regression), and treats a pickle-flagged value on read as a
/// miss, matching the Python client.
pub const PICKLE_FLAG: u32 = 1;
/// Serialization flag for JSON values.
pub const JSON_FLAG: u32 = 2;

/// Virtual nodes per server on the ring.
pub const NODE_WEIGHT: usize = 50;

/// Default number of distinct servers to try per operation.
pub const TRY_COUNT: usize = 3;

/// If `ERROR_LIMIT_COUNT` errors occur within `ERROR_LIMIT_TIME` seconds, the
/// server is skipped for `ERROR_LIMIT_DURATION` seconds.
pub const ERROR_LIMIT_COUNT: usize = 10;
/// Window and suppression duration for error-limiting (seconds).
pub const ERROR_LIMIT_TIME: f64 = 60.0;

/// The max value of a delta expiration time. Larger `time` values are treated
/// as absolute unix timestamps by the server, so we convert them.
pub const EXPTIME_MAXDELTA: i64 = 30 * 24 * 60 * 60;

/// md5 hex digest of `key`, as ASCII bytes.
///
/// Port of `swift.common.memcached.md5hash`. This is used both as the ring
/// position of a key and as the literal memcached key on the wire.
pub fn md5hash(key: &[u8]) -> Vec<u8> {
    let digest = Md5::digest(key);
    let mut out = Vec::with_capacity(32);
    for b in digest {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Tuning knobs, matching the `MemcacheRing.__init__` parameters that affect
/// server selection and error-limiting.
#[derive(Debug, Clone)]
pub struct MemcacheConfig {
    /// Distinct servers to try before giving up (clamped to the server count).
    pub tries: usize,
    /// Errors within `error_limit_time` needed to suppress a server.
    pub error_limit_count: usize,
    /// Sliding window over which errors are counted (seconds).
    pub error_limit_time: f64,
    /// How long a suppressed server stays suppressed (seconds).
    pub error_limit_duration: f64,
}

impl Default for MemcacheConfig {
    fn default() -> Self {
        MemcacheConfig {
            tries: TRY_COUNT,
            error_limit_count: ERROR_LIMIT_COUNT,
            error_limit_time: ERROR_LIMIT_TIME,
            error_limit_duration: ERROR_LIMIT_TIME,
        }
    }
}

/// One entry of the consistent-hash ring: a virtual node hash and the index
/// of the server it belongs to.
struct RingEntry {
    hash: Vec<u8>,
    server: usize,
}

#[derive(Default)]
struct ServerErrors {
    /// Timestamps of recent errors (seconds).
    times: Vec<f64>,
    /// Suppressed until this timestamp (0.0 means not suppressed).
    limited_until: f64,
}

/// Outcome of one attempt against a single connection.
enum OpError {
    /// A real failure: error-limit the server and try the next one.
    Failed(MemcacheError),
    /// An `incr`/`decr`-vs-expiry race: try the next server but do *not*
    /// error-limit (mirrors `MemcacheIncrNotFoundError`).
    IncrNotFound(String),
}

impl From<std::io::Error> for OpError {
    fn from(e: std::io::Error) -> Self {
        OpError::Failed(MemcacheError::Io(e))
    }
}

impl From<MemcacheError> for OpError {
    fn from(e: MemcacheError) -> Self {
        OpError::Failed(e)
    }
}

type ConnFactory<C> = Box<dyn Fn(&str) -> std::io::Result<C>>;
type Clock = Box<dyn Fn() -> f64>;

/// A consistent-hashed memcache client over the text protocol.
///
/// Generic over the [`MemcacheConn`] implementation so tests can swap in an
/// in-memory backend. Use [`MemcacheClient::connect`] for the real TCP
/// client, or [`MemcacheClient::new`] with a custom connection factory.
pub struct MemcacheClient<C: MemcacheConn> {
    servers: Vec<String>,
    ring: Vec<RingEntry>,
    tries: usize,
    conns: Vec<Option<C>>,
    factory: ConnFactory<C>,
    errors: Vec<ServerErrors>,
    error_limit_count: usize,
    error_limit_time: f64,
    error_limit_duration: f64,
    clock: Clock,
}

impl MemcacheClient<TcpConn> {
    /// Build a client that connects to each server over TCP.
    ///
    /// `connect_timeout` bounds each TCP handshake and `io_timeout` bounds
    /// each read/write, matching `CONN_TIMEOUT` / `IO_TIMEOUT`.
    pub fn connect(
        servers: Vec<String>,
        config: MemcacheConfig,
        connect_timeout: std::time::Duration,
        io_timeout: std::time::Duration,
    ) -> Result<MemcacheClient<TcpConn>, MemcacheError> {
        MemcacheClient::new(servers, config, move |server| {
            TcpConn::connect(server, connect_timeout, io_timeout)
        })
    }
}

impl<C: MemcacheConn> MemcacheClient<C> {
    /// Build a client from an explicit connection factory.
    ///
    /// `factory` is called lazily, once per server, and again after a
    /// connection is dropped following an error (mirroring the Python pool
    /// returning `None` and reconnecting on next use).
    pub fn new<F>(
        servers: Vec<String>,
        config: MemcacheConfig,
        factory: F,
    ) -> Result<MemcacheClient<C>, MemcacheError>
    where
        F: Fn(&str) -> std::io::Result<C> + 'static,
    {
        if servers.is_empty() {
            return Err(MemcacheError::Connection(
                "at least one memcache server is required".to_string(),
            ));
        }

        // Build the ring: NODE_WEIGHT virtual nodes per server. A BTreeMap
        // gives us sorted-by-hash order and dedups the (astronomically
        // unlikely) hash collision the same way Python's dict + sorted does.
        let mut ordered: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
        for (idx, server) in servers.iter().enumerate() {
            for i in 0..NODE_WEIGHT {
                let vnode = md5hash(format!("{server}-{i}").as_bytes());
                ordered.insert(vnode, idx);
            }
        }
        let ring: Vec<RingEntry> = ordered
            .into_iter()
            .map(|(hash, server)| RingEntry { hash, server })
            .collect();

        let tries = config.tries.clamp(1, servers.len());
        let errors = (0..servers.len()).map(|_| ServerErrors::default()).collect();
        let conns = (0..servers.len()).map(|_| None).collect();

        Ok(MemcacheClient {
            servers,
            ring,
            tries,
            conns,
            factory: Box::new(factory),
            errors,
            error_limit_count: config.error_limit_count,
            error_limit_time: config.error_limit_time,
            error_limit_duration: config.error_limit_duration,
            clock: Box::new(default_clock),
        })
    }

    /// Override the clock used for error-limiting and timeout sanitization.
    /// Intended for tests; production uses the wall clock.
    pub fn set_clock<F: Fn() -> f64 + 'static>(&mut self, clock: F) {
        self.clock = Box::new(clock);
    }

    /// The configured servers, in the order they were supplied.
    pub fn servers(&self) -> &[String] {
        &self.servers
    }

    /// The ordered list of distinct servers a key would be tried against.
    ///
    /// The first element is the primary; the rest are failover targets, up to
    /// `tries`. This is the exact selection `_get_conns` walks.
    pub fn server_candidates(&self, key: &str) -> Vec<String> {
        self.candidate_indices(&md5hash(key.as_bytes()))
            .into_iter()
            .map(|i| self.servers[i].clone())
            .collect()
    }

    /// The primary server a key routes to.
    pub fn primary_server(&self, key: &str) -> String {
        self.server_candidates(key)
            .into_iter()
            .next()
            .expect("ring is never empty")
    }

    /// Whether `server` is currently error-limited (skipped for routing).
    pub fn is_error_limited(&self, server: &str) -> bool {
        match self.servers.iter().position(|s| s == server) {
            Some(idx) => self.errors[idx].limited_until > (self.clock)(),
            None => false,
        }
    }

    // -- public operations --------------------------------------------------

    /// Set `key` to raw `value` with an explicit flag byte and TTL.
    ///
    /// This is the general form of `MemcacheRing.set`; `flags` is stored
    /// verbatim and surfaced again by [`MemcacheClient::get_with_flags`].
    pub fn set_raw(
        &mut self,
        key: &str,
        value: &[u8],
        flags: u32,
        time: i64,
    ) -> Result<(), MemcacheError> {
        let hash_key = md5hash(key.as_bytes());
        let timeout = self.sanitize_timeout(time);
        let msg = store_msg(b"set", &hash_key, flags, timeout, value);
        self.with_conns(&hash_key, |conn| {
            let resp = conn.request(&msg)?;
            let line = first_line(&resp);
            if line == b"STORED" {
                Ok(())
            } else {
                Err(OpError::Failed(MemcacheError::Connection(format!(
                    "failed set: {}",
                    String::from_utf8_lossy(line)
                ))))
            }
        })
    }

    /// Set `key` to raw `value` with flags `0` and TTL `time`.
    pub fn set(&mut self, key: &str, value: &[u8], time: i64) -> Result<(), MemcacheError> {
        self.set_raw(key, value, 0, time)
    }

    /// Serialize `value` to JSON and store it with [`JSON_FLAG`], matching
    /// `MemcacheRing.set(..., serialize=True)`.
    pub fn set_json(
        &mut self,
        key: &str,
        value: &serde_json::Value,
        time: i64,
    ) -> Result<(), MemcacheError> {
        let data = serde_json::to_vec(value)?;
        self.set_raw(key, &data, JSON_FLAG, time)
    }

    /// `add` a raw value: store only if `key` is not already present.
    /// Returns `true` if stored, `false` if the key already existed.
    pub fn add(
        &mut self,
        key: &str,
        value: &[u8],
        flags: u32,
        time: i64,
    ) -> Result<bool, MemcacheError> {
        let hash_key = md5hash(key.as_bytes());
        let timeout = self.sanitize_timeout(time);
        let msg = store_msg(b"add", &hash_key, flags, timeout, value);
        self.with_conns(&hash_key, |conn| {
            let resp = conn.request(&msg)?;
            let line = first_line(&resp).to_ascii_uppercase();
            match line.as_slice() {
                b"STORED" => Ok(true),
                b"NOT_STORED" => Ok(false),
                _ => Err(OpError::Failed(MemcacheError::Connection(format!(
                    "failed add: {}",
                    String::from_utf8_lossy(&line)
                )))),
            }
        })
    }

    /// Get the raw value and its flag byte, or `None` on a miss. A
    /// pickle-flagged value reads as a miss (this client never handles
    /// pickles), matching the Python client.
    pub fn get_with_flags(&mut self, key: &str) -> Result<Option<(u32, Vec<u8>)>, MemcacheError> {
        let hash_key = md5hash(key.as_bytes());
        let mut msg = Vec::with_capacity(4 + hash_key.len() + 2);
        msg.extend_from_slice(b"get ");
        msg.extend_from_slice(&hash_key);
        msg.extend_from_slice(b"\r\n");
        self.with_conns(&hash_key, |conn| {
            let resp = conn.request(&msg)?;
            Ok(parse_get(&resp, &hash_key)?)
        })
    }

    /// Get the raw value bytes for `key`, or `None` on a miss.
    pub fn get(&mut self, key: &str) -> Result<Option<Vec<u8>>, MemcacheError> {
        Ok(self.get_with_flags(key)?.map(|(_flags, data)| data))
    }

    /// Get a JSON value for `key`. Returns `None` on a miss, or when the
    /// stored value is not JSON-flagged (use [`MemcacheClient::get`] for raw
    /// values). A parse failure surfaces as [`MemcacheError::Json`].
    pub fn get_json(&mut self, key: &str) -> Result<Option<serde_json::Value>, MemcacheError> {
        match self.get_with_flags(key)? {
            Some((flags, data)) if flags & JSON_FLAG != 0 => {
                Ok(Some(serde_json::from_slice(&data)?))
            }
            _ => Ok(None),
        }
    }

    /// Delete `key`. `server_key`, if given, selects the ring server (so a set
    /// of related keys can be co-located), while the deleted key is always
    /// `key`. Port of `MemcacheRing.delete`.
    pub fn delete_with_server_key(
        &mut self,
        key: &str,
        server_key: Option<&str>,
    ) -> Result<(), MemcacheError> {
        let hash_key = md5hash(key.as_bytes());
        let route_key = match server_key {
            Some(sk) => md5hash(sk.as_bytes()),
            None => hash_key.clone(),
        };
        let mut msg = Vec::with_capacity(7 + hash_key.len() + 2);
        msg.extend_from_slice(b"delete ");
        msg.extend_from_slice(&hash_key);
        msg.extend_from_slice(b"\r\n");
        self.with_conns(&route_key, |conn| {
            // Python ignores the response body (DELETED / NOT_FOUND); any
            // successful round-trip counts as done.
            conn.request(&msg)?;
            Ok(())
        })
    }

    /// Delete `key`.
    pub fn delete(&mut self, key: &str) -> Result<(), MemcacheError> {
        self.delete_with_server_key(key, None)
    }

    /// Increment `key` by `delta`, creating it if missing. A negative `delta`
    /// increments in the decrement direction (as Python's `incr` does). The
    /// stored value is an unsigned integer; decrements floor at 0. Port of
    /// `MemcacheRing.incr`.
    pub fn incr(&mut self, key: &str, delta: i64, time: i64) -> Result<u64, MemcacheError> {
        let is_decr = delta < 0;
        let command: &[u8] = if is_decr { b"decr" } else { b"incr" };
        let delta_val = delta.unsigned_abs().to_string().into_bytes();
        let timeout = self.sanitize_timeout(time);
        let hash_key = md5hash(key.as_bytes());

        // incr/decr on the wire: "<command> <key> <delta>\r\n"
        let mut step_msg = Vec::new();
        step_msg.extend_from_slice(command);
        step_msg.push(b' ');
        step_msg.extend_from_slice(&hash_key);
        step_msg.push(b' ');
        step_msg.extend_from_slice(&delta_val);
        step_msg.extend_from_slice(b"\r\n");

        self.with_conns(&hash_key, |conn| {
            if let Some(v) = parse_incr(&conn.request(&step_msg)?)? {
                return Ok(v);
            }
            // NOT_FOUND: try to create the counter with `add`.
            let add_val: &[u8] = if is_decr { b"0" } else { &delta_val };
            let add_msg = store_msg(b"add", &hash_key, 0, timeout, add_val);
            let add_resp = conn.request(&add_msg)?;
            if first_line(&add_resp).eq_ignore_ascii_case(b"NOT_STORED") {
                // Someone else created it first; increment that instead.
                match parse_incr(&conn.request(&step_msg)?)? {
                    Some(v) => Ok(v),
                    None => Err(OpError::IncrNotFound(format!("expired ttl={time}"))),
                }
            } else {
                // Stored: the value is exactly add_val.
                Ok(ascii_u64(add_val).map_err(OpError::Failed)?)
            }
        })
    }

    /// Decrement `key` by `delta` (floored at 0), creating it at 0 if missing.
    /// Equivalent to `incr(key, -delta, time)`.
    pub fn decr(&mut self, key: &str, delta: i64, time: i64) -> Result<u64, MemcacheError> {
        self.incr(key, -delta, time)
    }

    // -- internals ----------------------------------------------------------

    /// Absolute-timestamp conversion, port of `sanitize_timeout`.
    fn sanitize_timeout(&self, timeout: i64) -> i64 {
        if timeout > EXPTIME_MAXDELTA {
            timeout + (self.clock)() as i64
        } else {
            timeout
        }
    }

    /// The distinct servers to try for `hash_key`, in order. Port of the
    /// `bisect` + walk in `_get_conns` (without the connection I/O).
    fn candidate_indices(&self, hash_key: &[u8]) -> Vec<usize> {
        let n = self.ring.len();
        // bisect_right: number of ring entries whose hash <= hash_key.
        let mut pos = self
            .ring
            .partition_point(|e| e.hash.as_slice() <= hash_key);
        let mut served: Vec<usize> = Vec::with_capacity(self.tries);
        while served.len() < self.tries {
            pos = (pos + 1) % n;
            let server = self.ring[pos].server;
            if !served.contains(&server) {
                served.push(server);
            }
        }
        served
    }

    /// Walk the candidate servers, running `op` against the first one that is
    /// not error-limited and yields a connection. On failure the connection is
    /// dropped (forcing a reconnect) and, unless the failure was an
    /// incr-not-found race, the server is error-limited. Port of the
    /// `_get_conns` / `_exception_occurred` loop shared by every operation.
    fn with_conns<T>(
        &mut self,
        hash_key: &[u8],
        mut op: impl FnMut(&mut C) -> Result<T, OpError>,
    ) -> Result<T, MemcacheError> {
        // The most recent failure, surfaced if no server ultimately succeeds.
        // Stays `None` only when every candidate was skipped (error-limited),
        // in which case we report `NoServers`.
        let mut last_failure: Option<MemcacheError> = None;
        for server in self.candidate_indices(hash_key) {
            let now = (self.clock)();
            if self.errors[server].limited_until > now {
                continue;
            }
            // Take the cached connection or create a fresh one. A failure to
            // connect is itself an error-limitable event.
            let taken = self.conns[server].take();
            let mut conn = match taken {
                Some(c) => c,
                None => match (self.factory)(&self.servers[server]) {
                    Ok(c) => c,
                    Err(e) => {
                        self.record_error(server, now);
                        last_failure = Some(MemcacheError::Io(e));
                        continue;
                    }
                },
            };
            match op(&mut conn) {
                Ok(value) => {
                    self.conns[server] = Some(conn);
                    return Ok(value);
                }
                Err(OpError::IncrNotFound(msg)) => {
                    // Drop the connection but do not error-limit; try next.
                    last_failure = Some(MemcacheError::IncrNotFound(msg));
                }
                Err(OpError::Failed(e)) => {
                    self.record_error(server, now);
                    last_failure = Some(e);
                    // Drop the connection so it is recreated next time.
                }
            }
        }
        Err(last_failure.unwrap_or(MemcacheError::NoServers))
    }

    /// Record an error against a server and suppress it if it has failed too
    /// often. Port of the tail of `_exception_occurred`.
    fn record_error(&mut self, server: usize, now: f64) {
        if self.error_limit_time <= 0.0 || self.error_limit_duration <= 0.0 {
            return;
        }
        let errs = &mut self.errors[server];
        errs.times.push(now);
        if errs.times.len() > self.error_limit_count {
            let cutoff = now - self.error_limit_time;
            errs.times.retain(|&t| t > cutoff);
            if errs.times.len() > self.error_limit_count {
                errs.limited_until = now + self.error_limit_duration;
            }
        }
    }
}

fn default_clock() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Build a `set`/`add` command: `<command> <key> <flags> <exptime> <bytes>\r\n<value>\r\n`.
/// Port of `set_msg` (generalised over the command word).
fn store_msg(command: &[u8], key: &[u8], flags: u32, exptime: i64, value: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(command.len() + key.len() + value.len() + 32);
    m.extend_from_slice(command);
    m.push(b' ');
    m.extend_from_slice(key);
    m.push(b' ');
    m.extend_from_slice(flags.to_string().as_bytes());
    m.push(b' ');
    m.extend_from_slice(exptime.to_string().as_bytes());
    m.push(b' ');
    m.extend_from_slice(value.len().to_string().as_bytes());
    m.extend_from_slice(b"\r\n");
    m.extend_from_slice(value);
    m.extend_from_slice(b"\r\n");
    m
}

/// The first `\r\n`/`\n`-terminated line of a response, without the terminator.
fn first_line(resp: &[u8]) -> &[u8] {
    let end = resp
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(resp.len());
    &resp[..end]
}

/// Parse a `get` response, returning `(flags, data)` for the requested key.
///
/// Mirrors `MemcacheRing.get`: scans `VALUE`/data blocks until `END`, returns
/// the block matching `hash_key`, and treats a pickle-flagged value as a miss.
fn parse_get(resp: &[u8], hash_key: &[u8]) -> Result<Option<(u32, Vec<u8>)>, MemcacheError> {
    let incomplete = || MemcacheError::Connection("incomplete read".to_string());
    let mut pos = 0usize;
    loop {
        let rel = resp[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(incomplete)?;
        let line_end = pos + rel;
        let line = trim_crlf(&resp[pos..line_end]);
        pos = line_end + 1;

        let fields: Vec<&[u8]> = line.split(|&b| b == b' ').filter(|f| !f.is_empty()).collect();
        if fields.is_empty() {
            return Err(incomplete());
        }
        if fields[0].eq_ignore_ascii_case(b"END") {
            return Ok(None);
        }
        if fields[0].eq_ignore_ascii_case(b"VALUE") {
            if fields.len() < 4 {
                return Err(MemcacheError::Connection("malformed VALUE header".to_string()));
            }
            let flags = ascii_u64(fields[2])? as u32;
            let size = ascii_u64(fields[3])? as usize;
            if pos + size > resp.len() {
                return Err(incomplete());
            }
            let data = resp[pos..pos + size].to_vec();
            pos += size;
            // Skip the trailing CRLF after the data block.
            if resp[pos..].starts_with(b"\r\n") {
                pos += 2;
            } else if resp[pos..].starts_with(b"\n") {
                pos += 1;
            }
            if fields[1] == hash_key {
                if flags & PICKLE_FLAG != 0 {
                    return Ok(None);
                }
                return Ok(Some((flags, data)));
            }
            // A block for some other key; keep scanning.
        }
        // Any other line: keep scanning until END.
    }
}

/// Parse an `incr`/`decr` reply: `Some(value)` for a number, `None` for
/// `NOT_FOUND`. Port of `_incr_or_decr`.
fn parse_incr(resp: &[u8]) -> Result<Option<u64>, OpError> {
    let line = first_line(resp);
    let token = line
        .split(|&b| b == b' ')
        .find(|t| !t.is_empty())
        .ok_or_else(|| OpError::Failed(MemcacheError::Connection("incomplete read".to_string())))?;
    if token.eq_ignore_ascii_case(b"NOT_FOUND") {
        return Ok(None);
    }
    ascii_u64(token).map(Some).map_err(OpError::Failed)
}

fn ascii_u64(bytes: &[u8]) -> Result<u64, MemcacheError> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| {
            MemcacheError::Connection(format!(
                "unexpected response: {}",
                String::from_utf8_lossy(bytes)
            ))
        })
}

fn trim_crlf(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::rc::Rc;

    // ---- an in-memory memcached, used as the injected backend ------------

    struct FakeItem {
        flags: u32,
        exptime: i64,
        data: Vec<u8>,
    }

    #[derive(Default)]
    struct FakeStore {
        items: HashMap<Vec<u8>, FakeItem>,
        dead: bool,
        connects: usize,
    }

    /// A connection to one shared `FakeStore`. Cloning the `Rc` models
    /// reconnecting to the same server.
    struct FakeConn {
        store: Rc<RefCell<FakeStore>>,
    }

    impl MemcacheConn for FakeConn {
        fn request(&mut self, cmd: &[u8]) -> std::io::Result<Vec<u8>> {
            let mut store = self.store.borrow_mut();
            if store.dead {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "dead server",
                ));
            }
            let nl = cmd
                .iter()
                .position(|&b| b == b'\n')
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no newline"))?;
            let line = trim_crlf(&cmd[..nl]);
            let f: Vec<&[u8]> = line.split(|&b| b == b' ').filter(|p| !p.is_empty()).collect();
            let data_start = nl + 1;

            let out = match f[0] {
                b"set" | b"add" => {
                    let key = f[1].to_vec();
                    let flags: u32 = parse(f[2]);
                    let exptime: i64 = parse(f[3]);
                    let len: usize = parse(f[4]);
                    let data = cmd[data_start..data_start + len].to_vec();
                    if f[0] == b"add" && store.items.contains_key(&key) {
                        b"NOT_STORED\r\n".to_vec()
                    } else {
                        store.items.insert(
                            key,
                            FakeItem {
                                flags,
                                exptime,
                                data,
                            },
                        );
                        b"STORED\r\n".to_vec()
                    }
                }
                b"get" => {
                    let mut out = Vec::new();
                    for key in &f[1..] {
                        if let Some(item) = store.items.get(*key) {
                            out.extend_from_slice(b"VALUE ");
                            out.extend_from_slice(key);
                            out.push(b' ');
                            out.extend_from_slice(item.flags.to_string().as_bytes());
                            out.push(b' ');
                            out.extend_from_slice(item.data.len().to_string().as_bytes());
                            out.extend_from_slice(b"\r\n");
                            out.extend_from_slice(&item.data);
                            out.extend_from_slice(b"\r\n");
                        }
                    }
                    out.extend_from_slice(b"END\r\n");
                    out
                }
                b"delete" => {
                    if store.items.remove(f[1]).is_some() {
                        b"DELETED\r\n".to_vec()
                    } else {
                        b"NOT_FOUND\r\n".to_vec()
                    }
                }
                b"incr" | b"decr" => {
                    let key = f[1].to_vec();
                    let delta: u64 = parse(f[2]);
                    match store.items.get_mut(&key) {
                        None => b"NOT_FOUND\r\n".to_vec(),
                        Some(item) => {
                            let cur: u64 = std::str::from_utf8(&item.data)
                                .ok()
                                .and_then(|s| s.trim().parse().ok())
                                .unwrap_or(0);
                            let new = if f[0] == b"incr" {
                                cur.wrapping_add(delta)
                            } else {
                                cur.saturating_sub(delta)
                            };
                            item.data = new.to_string().into_bytes();
                            let mut r = new.to_string().into_bytes();
                            r.extend_from_slice(b"\r\n");
                            r
                        }
                    }
                }
                _ => b"ERROR\r\n".to_vec(),
            };
            Ok(out)
        }
    }

    fn parse<T: std::str::FromStr>(bytes: &[u8]) -> T
    where
        T::Err: std::fmt::Debug,
    {
        std::str::from_utf8(bytes).unwrap().parse().unwrap()
    }

    /// A set of fake servers plus a client wired to them.
    struct Harness {
        client: MemcacheClient<FakeConn>,
        stores: HashMap<String, Rc<RefCell<FakeStore>>>,
    }

    fn harness(servers: &[&str], config: MemcacheConfig) -> Harness {
        let servers: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
        let stores: HashMap<String, Rc<RefCell<FakeStore>>> = servers
            .iter()
            .map(|s| (s.clone(), Rc::new(RefCell::new(FakeStore::default()))))
            .collect();
        let factory_stores = stores.clone();
        let client = MemcacheClient::new(servers, config, move |server| {
            let store = factory_stores.get(server).unwrap().clone();
            store.borrow_mut().connects += 1;
            Ok(FakeConn { store })
        })
        .unwrap();
        Harness { client, stores }
    }

    fn single_server() -> Harness {
        harness(&["10.0.0.1:11211"], MemcacheConfig::default())
    }

    #[test]
    fn md5hash_matches_python() {
        // python: md5(b'', usedforsecurity=False).hexdigest()
        assert_eq!(md5hash(b""), b"d41d8cd98f00b204e9800998ecf8427e".to_vec());
        // python: md5(b'foo').hexdigest()
        assert_eq!(
            md5hash(b"foo"),
            b"acbd18db4cc2f85cedef654fccc4a4d8".to_vec()
        );
    }

    #[test]
    fn set_get_round_trip() {
        let mut h = single_server();
        h.client.set_raw("greeting", b"hello world", 0, 0).unwrap();
        assert_eq!(
            h.client.get("greeting").unwrap(),
            Some(b"hello world".to_vec())
        );
        // Missing key is a miss, not an error.
        assert_eq!(h.client.get("absent").unwrap(), None);
    }

    #[test]
    fn json_round_trip_sets_json_flag() {
        let mut h = single_server();
        let value = serde_json::json!({"a": 1, "b": [1, 2, 3], "c": "x"});
        h.client.set_json("doc", &value, 0).unwrap();
        assert_eq!(h.client.get_json("doc").unwrap(), Some(value));

        // The stored item carries JSON_FLAG (2), like Python's serialize=True.
        let key = md5hash(b"doc");
        assert_eq!(
            h.stores["10.0.0.1:11211"].borrow().items[&key].flags,
            JSON_FLAG
        );

        // get() on a JSON value returns the raw JSON bytes; get_json on a raw
        // value returns None.
        h.client.set_raw("raw", b"plain", 0, 0).unwrap();
        assert_eq!(h.client.get_json("raw").unwrap(), None);
    }

    #[test]
    fn incr_decr_create_and_step() {
        let mut h = single_server();
        // incr on a missing key creates it at delta.
        assert_eq!(h.client.incr("counter", 5, 0).unwrap(), 5);
        assert_eq!(h.client.incr("counter", 3, 0).unwrap(), 8);
        assert_eq!(h.client.decr("counter", 2, 0).unwrap(), 6);
        // decr floors at zero.
        assert_eq!(h.client.decr("counter", 100, 0).unwrap(), 0);
        // decr on a missing key creates it at 0.
        assert_eq!(h.client.decr("fresh", 4, 0).unwrap(), 0);
    }

    #[test]
    fn delete_removes_key() {
        let mut h = single_server();
        h.client.set_raw("k", b"v", 0, 0).unwrap();
        assert_eq!(h.client.get("k").unwrap(), Some(b"v".to_vec()));
        h.client.delete("k").unwrap();
        assert_eq!(h.client.get("k").unwrap(), None);
    }

    #[test]
    fn expiry_is_sent_and_sanitized() {
        let mut h = single_server();
        // A small TTL is passed through verbatim into the set command.
        h.client.set_raw("ttl", b"v", 0, 120).unwrap();
        let key = md5hash(b"ttl");
        assert_eq!(h.stores["10.0.0.1:11211"].borrow().items[&key].exptime, 120);

        // A TTL beyond 30 days is converted to an absolute time using the
        // clock (sanitize_timeout).
        h.client.set_clock(|| 1_000.0);
        let big = EXPTIME_MAXDELTA + 10;
        h.client.set_raw("ttl", b"v", 0, big).unwrap();
        assert_eq!(
            h.stores["10.0.0.1:11211"].borrow().items[&key].exptime,
            big + 1_000
        );
    }

    #[test]
    fn server_selection_partitions_keys_deterministically() {
        let mut h = harness(
            &["10.0.0.1:11211", "10.0.0.2:11211"],
            MemcacheConfig::default(),
        );
        let mut on_a = 0;
        let mut on_b = 0;
        for i in 0..200 {
            let key = format!("key-{i}");
            // Routing is stable across calls.
            assert_eq!(h.client.primary_server(&key), h.client.primary_server(&key));
            let primary = h.client.primary_server(&key);
            h.client.set_raw(&key, format!("v{i}").as_bytes(), 0, 0).unwrap();
            let hk = md5hash(key.as_bytes());
            // The value lands in exactly the primary's store.
            let in_a = h.stores["10.0.0.1:11211"].borrow().items.contains_key(&hk);
            let in_b = h.stores["10.0.0.2:11211"].borrow().items.contains_key(&hk);
            assert_ne!(in_a, in_b, "key must live on exactly one server");
            if primary == "10.0.0.1:11211" {
                assert!(in_a);
                on_a += 1;
            } else {
                assert!(in_b);
                on_b += 1;
            }
        }
        // Both servers should get a healthy share (consistent hashing spreads
        // keys); this is a sanity bound, not an exact split.
        assert!(on_a > 40, "server A got too few keys: {on_a}");
        assert!(on_b > 40, "server B got too few keys: {on_b}");
    }

    #[test]
    fn error_limiting_skips_a_dead_server() {
        let now = Rc::new(Cell::new(1_000.0f64));
        let config = MemcacheConfig {
            tries: 2,
            error_limit_count: 2,
            error_limit_time: 60.0,
            error_limit_duration: 60.0,
        };
        let mut h = harness(&["10.0.0.1:11211", "10.0.0.2:11211"], config);
        let now_clock = now.clone();
        h.client.set_clock(move || now_clock.get());

        // Pick a key whose PRIMARY is server A, then kill server A. Every set
        // should still succeed by failing over to server B.
        let dead = "10.0.0.1:11211";
        let key = (0..)
            .map(|i| format!("route-{i}"))
            .find(|k| h.client.primary_server(k) == dead)
            .unwrap();
        assert_eq!(h.client.server_candidates(&key).len(), 2);
        h.stores[dead].borrow_mut().dead = true;

        // Errors accumulate on A until it trips the limit (count=2 -> the 3rd
        // error suppresses it). Each op reconnects to A first, so `connects`
        // grows once per op while A is still tried.
        for _ in 0..3 {
            h.client.set_raw(&key, b"v", 0, 0).unwrap(); // succeeds via B
        }
        assert!(h.client.is_error_limited(dead));
        assert!(!h.client.is_error_limited("10.0.0.2:11211"));
        let connects_when_limited = h.stores[dead].borrow().connects;
        assert_eq!(connects_when_limited, 3);

        // Now A is skipped entirely: further ops do not even try to connect.
        for _ in 0..5 {
            h.client.set_raw(&key, b"v", 0, 0).unwrap();
        }
        assert_eq!(h.stores[dead].borrow().connects, connects_when_limited);

        // Suppression expires once the clock passes limited_until.
        now.set(1_000.0 + 61.0);
        assert!(!h.client.is_error_limited(dead));
    }

    #[test]
    fn all_servers_failing_surfaces_error_then_no_servers() {
        let now = Rc::new(Cell::new(500.0f64));
        let config = MemcacheConfig {
            tries: 1,
            error_limit_count: 2,
            error_limit_time: 60.0,
            error_limit_duration: 60.0,
        };
        let mut h = harness(&["10.0.0.1:11211"], config);
        let nc = now.clone();
        h.client.set_clock(move || nc.get());
        h.stores["10.0.0.1:11211"].borrow_mut().dead = true;

        // While the only server is still being tried, the underlying transport
        // error surfaces rather than a generic message.
        for _ in 0..3 {
            assert!(matches!(h.client.get("k"), Err(MemcacheError::Io(_))));
        }
        // After enough failures it is error-limited, so it is skipped entirely
        // and there is nothing left to try: NoServers.
        assert!(h.client.is_error_limited("10.0.0.1:11211"));
        assert!(matches!(h.client.get("k"), Err(MemcacheError::NoServers)));
    }
}
