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
// implied. See the License for the specific language governing permissions
// and limitations under the License.

//! The SSYNC sender, ported from `swift/obj/ssync_sender.py` for a single
//! job: connect to a receiving object server, offer the local objects in the
//! missing-check phase, then stream PUT/POST/DELETE subrequests for whatever
//! the receiver wants.
//!
//! The wire is behind [`SsyncWire`] so the protocol core is unit-testable
//! against a scripted receiver; [`TcpSsyncWire`] is the real TCP adapter
//! (request head, chunked request framing, de-chunked response reads).

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use swift_core::config::config_true_value;
use swift_core::hashing::HashPathConfig;
use swift_core::timestamp::Timestamp;
use swift_diskfile::{
    get_data_dir, get_ondisk_files, storage_directory, DiskFile, DiskFileConfig, DiskFileError,
    FragPref, MetaValue, Metadata, PolicyKind,
};

use crate::percent_encode;
use crate::ssync::encode_missing;

const MAX_SSYNC_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_SSYNC_RESPONSE_LINE_BYTES: usize = 64 * 1024;
const MAX_SSYNC_RESPONSE_HEAD_BYTES: usize = 64 * 1024;
const MAX_SSYNC_CHUNK_SIZE_LINE_BYTES: usize = 128;
const MAX_SSYNC_TRAILER_LINE_BYTES: usize = 8 * 1024;
const MAX_SSYNC_TRAILER_BYTES: usize = 64 * 1024;

/// One ssync job: which local partition/frag index to sync from (the shape of
/// the Python reconstructor/replicator job dicts that `Sender` consumes).
#[derive(Debug, Clone)]
pub struct SsyncJob {
    /// Local device name.
    pub device: String,
    pub partition: u64,
    pub policy_index: u32,
    pub policy: PolicyKind,
    /// The fragment index of the local diskfiles to offer (EC); the
    /// `job['frag_index']` passed to `yield_hashes`.
    pub frag_index: Option<i64>,
}

/// The remote node, as `Sender.connect` needs it.
#[derive(Debug, Clone)]
pub struct SsyncNode {
    pub replication_ip: String,
    pub replication_port: u32,
    pub device: String,
    /// `node['backend_index']`: the frag index the RECEIVER stores under
    /// (`X-Backend-Ssync-Frag-Index`); `None` for replication policies.
    pub backend_index: Option<i64>,
}

/// The timestamps yielded per object hash (Python `yield_hashes` timestamps
/// dict / the sender's `available_map` values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectTimestamps {
    /// Data or tombstone timestamp.
    pub ts_data: Timestamp,
    pub ts_meta: Option<Timestamp>,
    pub ts_ctype: Option<Timestamp>,
    /// `Some` only for EC data files (whether the file is durable).
    pub durable: Option<bool>,
}

/// Read one hash directory and derive the exact logical timestamp tuple used
/// by missing-check. Keeping this as the single implementation lets handoff
/// deletion validate the same state the sender actually offered.
pub(crate) fn object_timestamps_from_hash_dir(
    hash_dir: &Path,
    policy: PolicyKind,
    frag_index: Option<i64>,
    frag_prefs: Option<&[FragPref]>,
) -> Option<ObjectTimestamps> {
    object_timestamps_from_hash_dir_strict(hash_dir, policy, frag_index, frag_prefs)
        .ok()
        .flatten()
}

/// Strict form used by deletion-authorizing maintenance paths. `Ok(None)`
/// means this hash directory legitimately has no state offerable for the
/// selected EC fragment index; directory I/O and malformed on-disk filenames
/// remain errors rather than being collapsed into an empty page.
pub(crate) fn object_timestamps_from_hash_dir_strict(
    hash_dir: &Path,
    policy: PolicyKind,
    frag_index: Option<i64>,
    frag_prefs: Option<&[FragPref]>,
) -> Result<Option<ObjectTimestamps>, DiskFileError> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(hash_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(DiskFileError::ContractBroken(format!(
                "non-regular diskfile entry in {}",
                hash_dir.display()
            )));
        }
        let filename = entry
            .file_name()
            .to_str()
            .map(str::to_string)
            .ok_or_else(|| DiskFileError::InvalidFilename("non-UTF8 diskfile name".to_string()))?;
        // rsync may leave .<valid diskfile>.<six random characters> beside
        // a committed generation. It has no logical timestamp, but remains
        // in the physical snapshot used to authorize handoff cleanup.
        if !is_rsync_temporary_diskfile(&filename, policy) {
            files.push(filename);
        }
    }
    files.sort();
    let ondisk = get_ondisk_files(&files, hash_dir, true, policy, frag_index, frag_prefs)?;
    if !ondisk.unexpected.is_empty() {
        return Err(DiskFileError::ContractBroken(format!(
            "unexpected files in {}: {:?}",
            hash_dir.display(),
            ondisk.unexpected
        )));
    }
    Ok(if let Some(data_info) = &ondisk.data_info {
        Some(ObjectTimestamps {
            ts_data: data_info.timestamp,
            ts_meta: ondisk.meta_info.as_ref().map(|info| info.timestamp),
            ts_ctype: ondisk
                .ctype_info
                .as_ref()
                .and_then(|info| info.ctype_timestamp),
            durable: data_info.durable,
        })
    } else {
        ondisk.ts_info.as_ref().map(|ts_info| ObjectTimestamps {
            ts_data: ts_info.timestamp,
            ts_meta: None,
            ts_ctype: None,
            durable: None,
        })
    })
}

fn is_rsync_temporary_diskfile(filename: &str, policy: PolicyKind) -> bool {
    let Some((target, random)) = filename
        .strip_prefix('.')
        .and_then(|name| name.rsplit_once('.'))
    else {
        return false;
    };
    random.len() == 6
        && random.bytes().all(|byte| byte.is_ascii_alphanumeric())
        && swift_diskfile::parse_ondisk_filename(target, policy)
            .is_ok_and(|info| matches!(info.ext.as_str(), ".data" | ".meta" | ".ts" | ".durable"))
}

/// Which parts the receiver asked for (`decode_wanted`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Wanted {
    pub data: bool,
    pub meta: bool,
}

/// `ssync_sender.decode_wanted`: parse the parts token of a wanted line.
pub fn decode_wanted(parts: &[&str]) -> Wanted {
    let mut wanted = Wanted::default();
    if let Some(first) = parts.first() {
        if first.contains('d') {
            wanted.data = true;
        }
        if first.contains('m') {
            wanted.meta = true;
        }
    }
    if !wanted.data && !wanted.meta {
        // assume legacy receiver which will only accept PUTs
        wanted.data = true;
    }
    wanted
}

#[derive(Debug)]
pub struct SsyncSenderError {
    message: String,
}

impl SsyncSenderError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for SsyncSenderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SsyncSenderError {}

impl From<std::io::Error> for SsyncSenderError {
    fn from(error: std::io::Error) -> Self {
        SsyncSenderError::new(error.to_string())
    }
}

/// The sender's view of an established SSYNC exchange: raw sends into the
/// chunked request body, de-chunked line reads from the response body.
pub trait SsyncWire {
    /// Send one already-chunk-framed piece of the request body.
    fn send(&mut self, data: &[u8]) -> std::io::Result<()>;
    /// Read one line from the response body (empty = EOF / disconnect).
    fn readline(&mut self) -> std::io::Result<Vec<u8>>;
    /// Start a bounded wait for one receiver response phase.
    fn begin_response_phase(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    /// Prove that the response body ended with a valid terminal chunk after
    /// the final protocol marker. A protocol marker without the enclosing
    /// HTTP message terminator is not a successful SSYNC exchange.
    fn finish_response(&mut self) -> std::io::Result<()> {
        let trailing = self.readline()?;
        if trailing.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected data after SSYNC response",
            ))
        }
    }
    /// Whether the receiver advertised `X-Backend-Accept-No-Commit` (drives
    /// `include_non_durable`); scripted test wires may hardcode it.
    fn accept_no_commit(&self) -> bool {
        true
    }
}

/// Frame one payload as an HTTP chunk, exactly as the Python sender's
/// `connection.send(b'%x\r\n%s\r\n' % (len(msg), msg))`.
fn chunk_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out.extend_from_slice(b"\r\n");
    out
}

/// The real TCP wire: request head on connect, then chunked request body
/// writes and de-chunked response body reads (the Rust
/// `SsyncBufferedHTTPConnection`/`Response`).
pub struct TcpSsyncWire {
    write: TcpStream,
    read: BufReader<TcpStream>,
    /// Bytes left in the current response chunk.
    chunk_left: usize,
    /// Set only after a syntactically complete zero chunk and trailers.
    response_complete: bool,
    response_payload_bytes: usize,
    response_timeout: Duration,
    response_deadline: Option<Instant>,
    session_deadline: Instant,
    accept_no_commit: bool,
}

fn write_all_before(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    idle_timeout: Duration,
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "SSYNC session deadline")
            })?;
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SSYNC session deadline",
            ));
        }
        stream.set_write_timeout(Some(
            remaining.min(idle_timeout).max(Duration::from_millis(1)),
        ))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "SSYNC peer stopped accepting bytes",
                ))
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_exact_before(
    read: &mut BufReader<TcpStream>,
    mut out: &mut [u8],
    idle_timeout: Duration,
    deadline: Instant,
) -> std::io::Result<()> {
    while !out.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "SSYNC response deadline")
            })?;
        if read.buffer().is_empty() {
            read.get_ref()
                .set_read_timeout(Some(remaining.min(idle_timeout)))?;
        }
        match read.read(out) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "short SSYNC response",
                ))
            }
            Ok(count) => out = &mut out[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read_crlf_line_before(
    read: &mut BufReader<TcpStream>,
    idle_timeout: Duration,
    deadline: Instant,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        if line.len() >= max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SSYNC line exceeds configured limit",
            ));
        }
        let mut byte = [0u8; 1];
        read_exact_before(read, &mut byte, idle_timeout, deadline)?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
}

impl TcpSsyncWire {
    /// `Sender.connect`: establish the connection, start the SSYNC request
    /// and read the response head (must be `200`).
    pub fn connect(
        node: &SsyncNode,
        job: &SsyncJob,
        conn_timeout: Duration,
        node_timeout: Duration,
    ) -> Result<TcpSsyncWire, SsyncSenderError> {
        if conn_timeout.is_zero() || node_timeout.is_zero() {
            return Err(SsyncSenderError::new("SSYNC timeouts must be positive"));
        }
        let ip = node
            .replication_ip
            .parse::<std::net::IpAddr>()
            .map_err(|_| {
                SsyncSenderError::new(format!("bad node address {}", node.replication_ip))
            })?;
        let port = u16::try_from(node.replication_port).map_err(|_| {
            SsyncSenderError::new(format!("bad node port {}", node.replication_port))
        })?;
        let sock_addr = std::net::SocketAddr::new(ip, port);
        let addr = sock_addr.to_string();
        let stream = TcpStream::connect_timeout(&sock_addr, conn_timeout)?;
        let session_timeout = node_timeout.saturating_mul(10);
        let session_deadline = Instant::now()
            .checked_add(session_timeout)
            .ok_or_else(|| SsyncSenderError::new("invalid SSYNC session deadline"))?;
        stream.set_read_timeout(Some(node_timeout))?;
        stream.set_write_timeout(Some(node_timeout))?;
        let mut head = format!(
            "SSYNC /{}/{} HTTP/1.1\r\nHost: {addr}\r\nTransfer-Encoding: chunked\r\n\
             X-Backend-Storage-Policy-Index: {}\r\n",
            node.device, job.partition, job.policy_index
        );
        // a sync job must use the node's backend_index for the frag_index
        // of the rebuilt fragments instead of the frag_index from the job
        if let Some(frag_index) = node.backend_index {
            head.push_str(&format!("X-Backend-Ssync-Frag-Index: {frag_index}\r\n"));
            // Node-Index header is for backwards compat 2.4.0-2.20.0
            head.push_str(&format!("X-Backend-Ssync-Node-Index: {frag_index}\r\n"));
        }
        head.push_str("\r\n");
        let mut write = stream;
        write_all_before(&mut write, head.as_bytes(), node_timeout, session_deadline)?;
        let mut read = BufReader::new(write.try_clone()?);
        let response_head_deadline = Instant::now()
            .checked_add(node_timeout)
            .ok_or_else(|| SsyncSenderError::new("invalid SSYNC response deadline"))?
            .min(session_deadline);
        // Response head: status line + headers until the blank line.
        let status_line_bytes = read_crlf_line_before(
            &mut read,
            node_timeout,
            response_head_deadline,
            MAX_SSYNC_RESPONSE_HEAD_BYTES,
        )?;
        let status_line = std::str::from_utf8(&status_line_bytes)
            .map_err(|_| SsyncSenderError::new("non-UTF8 SSYNC response status line"))?;
        let mut status_parts = status_line.split_whitespace();
        if status_parts.next() != Some("HTTP/1.1") {
            return Err(SsyncSenderError::new("SSYNC requires an HTTP/1.1 response"));
        }
        let status: u16 = status_parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| {
                SsyncSenderError::new(format!("bad SSYNC response line {status_line:?}"))
            })?;
        let mut accept_no_commit = false;
        let mut transfer_encoding: Option<String> = None;
        let mut content_length_seen = false;
        let mut response_head_bytes = status_line_bytes.len();
        loop {
            let line_bytes = read_crlf_line_before(
                &mut read,
                node_timeout,
                response_head_deadline,
                MAX_SSYNC_RESPONSE_HEAD_BYTES,
            )?;
            response_head_bytes = response_head_bytes.saturating_add(line_bytes.len());
            if response_head_bytes > MAX_SSYNC_RESPONSE_HEAD_BYTES {
                return Err(SsyncSenderError::new("SSYNC response head exceeds limit"));
            }
            let line = std::str::from_utf8(&line_bytes)
                .map_err(|_| SsyncSenderError::new("non-UTF8 SSYNC response header"))?;
            let line = line.strip_suffix("\r\n").unwrap_or(line);
            if line.is_empty() {
                break;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| SsyncSenderError::new("malformed SSYNC response header"))?;
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
                || value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() && byte != b'\t')
            {
                return Err(SsyncSenderError::new(
                    "malformed SSYNC response header name",
                ));
            }
            if name.eq_ignore_ascii_case("x-backend-accept-no-commit") {
                accept_no_commit = config_true_value(value.trim());
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                if transfer_encoding
                    .replace(value.trim().to_string())
                    .is_some()
                {
                    return Err(SsyncSenderError::new("duplicate SSYNC Transfer-Encoding"));
                }
            } else if name.eq_ignore_ascii_case("content-length") {
                if content_length_seen {
                    return Err(SsyncSenderError::new("duplicate SSYNC Content-Length"));
                }
                content_length_seen = true;
            }
        }
        if status != 200 {
            return Err(SsyncSenderError::new(format!(
                "Expected status 200; got {status}"
            )));
        }
        if content_length_seen
            || !transfer_encoding
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
        {
            return Err(SsyncSenderError::new(
                "SSYNC response must use only Transfer-Encoding: chunked",
            ));
        }
        Ok(TcpSsyncWire {
            write,
            read,
            chunk_left: 0,
            response_complete: false,
            response_payload_bytes: 0,
            response_timeout: node_timeout,
            response_deadline: None,
            session_deadline,
            accept_no_commit,
        })
    }

    /// `Sender.disconnect`: terminate the chunked request body; failures are
    /// fine (the receiver may already have closed).
    pub fn disconnect(mut self) {
        let _ = write_all_before(
            &mut self.write,
            b"0\r\n\r\n",
            self.response_timeout,
            self.session_deadline,
        );
        let _ = self.write.flush();
    }
}

impl SsyncWire for TcpSsyncWire {
    fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        write_all_before(
            &mut self.write,
            data,
            self.response_timeout,
            self.session_deadline,
        )
    }

    /// A line from the de-chunked response body, the Rust
    /// `SsyncBufferedHTTPResponse.readline`.
    fn readline(&mut self) -> std::io::Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            if self.response_complete {
                if line.is_empty() {
                    return Ok(line);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "terminal chunk inside partial SSYNC response line",
                ));
            }
            if self.chunk_left == 0 {
                // Production Sender callers explicitly start each response
                // phase.  The wire also supports a full-duplex caller that
                // writes the request protocol directly before reading the
                // response (used by the real-socket compatibility path).  In
                // that case the immutable session deadline remains the
                // safety boundary; never fall back to an unbounded read.
                let deadline = self.response_deadline.unwrap_or(self.session_deadline);
                let size_line = read_crlf_line_before(
                    &mut self.read,
                    self.response_timeout,
                    deadline,
                    MAX_SSYNC_CHUNK_SIZE_LINE_BYTES,
                )?;
                let text =
                    std::str::from_utf8(&size_line[..size_line.len() - 2]).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "SSYNC chunk size is not ASCII",
                        )
                    })?;
                let text = text.split(';').next().unwrap_or("").trim();
                let size = usize::from_str_radix(text, 16).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "bad SSYNC chunk size")
                })?;
                if size == 0 {
                    if !line.is_empty() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "terminal chunk inside partial SSYNC response line",
                        ));
                    }
                    // Consume optional trailer fields and the final empty
                    // CRLF-terminated line. EOF is never an implicit
                    // terminator.
                    let mut trailer_bytes = 0usize;
                    loop {
                        let trailer = read_crlf_line_before(
                            &mut self.read,
                            self.response_timeout,
                            deadline,
                            MAX_SSYNC_TRAILER_LINE_BYTES,
                        )?;
                        trailer_bytes += trailer.len();
                        if trailer_bytes > MAX_SSYNC_TRAILER_BYTES {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "SSYNC trailers exceed limit",
                            ));
                        }
                        if trailer == b"\r\n" {
                            break;
                        }
                        if !trailer.contains(&b':') {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid SSYNC trailer field",
                            ));
                        }
                    }
                    self.response_complete = true;
                    return Ok(Vec::new());
                }
                if self.response_payload_bytes.saturating_add(size) > MAX_SSYNC_RESPONSE_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "SSYNC response body exceeds limit",
                    ));
                }
                self.response_payload_bytes += size;
                self.chunk_left = size;
            }
            let deadline = self.response_deadline.unwrap_or(self.session_deadline);
            let mut byte = [0u8; 1];
            read_exact_before(&mut self.read, &mut byte, self.response_timeout, deadline)?;
            self.chunk_left -= 1;
            if self.chunk_left == 0 {
                // A complete chunk always has a literal trailing CRLF.
                let mut crlf = [0u8; 2];
                read_exact_before(&mut self.read, &mut crlf, self.response_timeout, deadline)?;
                if crlf != *b"\r\n" {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "SSYNC chunk payload lacks trailing CRLF",
                    ));
                }
            }
            if byte[0] == b'\n' {
                line.push(b'\n');
                return Ok(line);
            }
            line.push(byte[0]);
            if line.len() > MAX_SSYNC_RESPONSE_LINE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "SSYNC response line exceeds limit",
                ));
            }
        }
    }

    fn begin_response_phase(&mut self) -> std::io::Result<()> {
        self.response_deadline = Instant::now()
            .checked_add(self.response_timeout)
            .map(|deadline| deadline.min(self.session_deadline));
        if self.response_deadline.is_some() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid SSYNC response deadline",
            ))
        }
    }

    fn accept_no_commit(&self) -> bool {
        self.accept_no_commit
    }

    fn finish_response(&mut self) -> std::io::Result<()> {
        if !self.response_complete {
            let trailing = self.readline()?;
            if !trailing.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unexpected data after SSYNC response",
                ));
            }
        }
        if self.response_complete {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "SSYNC response ended before terminal chunk",
            ))
        }
    }
}

/// The result of a successful sender run.
#[derive(Debug, Default)]
pub struct SenderReport {
    /// hash -> timestamps of every object offered (in sync with the receiver
    /// after a successful run, hence deletable by a revert job).
    pub can_delete_objs: BTreeMap<String, ObjectTimestamps>,
    /// `hash -> wanted` for what the receiver requested.
    pub send_map: Vec<(String, Wanted)>,
    pub limited_by_max_objects: bool,
    /// Number of object hashes offered in this session.
    pub offered_count: usize,
    /// Deterministic `(suffix, object_hash)` cursor of the last offered item.
    /// Callers may start another bounded session strictly after it.
    pub last_offered: Option<(String, String)>,
    /// Successful `reconstruct_fa` data PUTs (local index ≠ receiver index).
    /// Official `break_nodes` heals here; `EcSsyncStats.rebuilt` must count it.
    pub rebuilt: u64,
    /// Last non-retryable `reconstruct_fa` skip (no builder, not enough
    /// fragments, timestamp mismatch). SSYNC can still complete.
    pub last_rebuild_error: Option<String>,
}

/// `ssync_sender.Sender` for one node+job.
pub struct Sender<'a> {
    pub devices: &'a Path,
    pub hash_config: &'a HashPathConfig,
    pub diskfile_config: &'a DiskFileConfig,
    pub job: &'a SsyncJob,
    /// Suffix directories to offer; `None` offers the whole partition
    /// (Python passes an explicit list; `None` mirrors `suffixes=None` in
    /// `yield_hashes`).
    pub suffixes: Option<&'a [String]>,
    pub include_non_durable: bool,
    pub max_objects: usize,
    /// Resume strictly after this `(suffix, object_hash)` in the sender's
    /// deterministic suffix/hash traversal order.
    pub start_after: Option<(String, String)>,
    /// SYNC-job rebuild target: when set, a wanted data PUT must carry the
    /// fragment at this index (the receiver's backend index). A local
    /// fragment already at the target index is sent as-is; otherwise the
    /// [`Sender::diskfile_builder`] rebuilds it on the fly (Python's
    /// `sync_diskfile_builder`/`reconstruct_fa`), and with no builder — or a
    /// failed rebuild — the object is skipped, exactly like Python's
    /// `DiskFileError` from `reconstruct_fa`. `None` sends data
    /// unconditionally (replication and revert jobs).
    pub sync_frag_target: Option<i64>,
    /// Rebuilds the fragment archive at [`Sender::sync_frag_target`] from
    /// peer fragments when the local fragment has a different index.
    pub diskfile_builder: Option<&'a dyn SyncDiskfileBuilder>,
}

/// `job['sync_diskfile_builder']` (obj.py `reconstruct_fa`): given the
/// local participating fragment's datafile metadata, produce the metadata
/// and bytes of the fragment archive rebuilt at the receiver's index —
/// with the frag-index sysmeta swapped and ETag REMOVED (the receiving
/// object server recomputes it, `RebuildingECDiskFileStream`).
pub trait SyncDiskfileBuilder {
    fn rebuild(
        &self,
        object_hash: &str,
        datafile_metadata: &Metadata,
        target_frag_index: i64,
    ) -> Result<(Metadata, crate::reconstruction_spool::ArchiveBody), String>;

    /// Same as [`Self::rebuild`], with the already-open local fragment so
    /// `reconstruct_fa` does not depend on an HTTP GET back to this node.
    fn rebuild_with_local(
        &self,
        object_hash: &str,
        datafile_metadata: &Metadata,
        target_frag_index: i64,
        _local: Option<crate::reconstructor::FetchedFragment>,
    ) -> Result<(Metadata, crate::reconstruction_spool::ArchiveBody), String> {
        self.rebuild(object_hash, datafile_metadata, target_frag_index)
    }
}

fn meta_str(metadata: &Metadata, name: &str) -> Option<String> {
    metadata.iter().find_map(|(k, v)| match (k, v) {
        (MetaValue::Str(k), MetaValue::Str(v)) if k == name => Some(v.clone()),
        (MetaValue::Str(k), MetaValue::Int(i)) if k == name => Some(i.to_string()),
        _ => None,
    })
}

fn local_rebuild_fragment(
    df: &mut DiskFile,
    local_frag: Option<i64>,
) -> Option<crate::reconstructor::FetchedFragment> {
    let frag_index = i32::try_from(local_frag?).ok()?;
    let metadata = df.get_datafile_metadata().ok()?;
    let ec_etag = meta_str(metadata, "X-Object-Sysmeta-Ec-Etag")?;
    let ec_content_length = meta_str(metadata, "X-Object-Sysmeta-Ec-Content-Length")?
        .parse()
        .ok()?;
    let timestamp = meta_str(metadata, "X-Timestamp")?;
    let timestamp = timestamp
        .parse::<Timestamp>()
        .map(|ts| ts.internal())
        .unwrap_or(timestamp);
    let content_type =
        meta_str(metadata, "Content-Type").unwrap_or_else(|| "application/octet-stream".into());
    let mut reader = df.reader().ok()?;
    let archive = reader.read_all().ok()?;
    let _ = reader.close();
    Some(crate::reconstructor::FetchedFragment {
        frag_index,
        archive: archive.into(),
        ec_etag,
        ec_content_length,
        timestamp,
        content_type,
    })
}

impl Sender<'_> {
    /// Run the exchange over an established wire; the caller handles
    /// connect/disconnect. Mirrors `Sender.__call__`'s success path;
    /// protocol errors return `Err` (Python logs and returns `(False, {})`).
    pub fn run(&self, wire: &mut dyn SsyncWire) -> Result<SenderReport, SsyncSenderError> {
        let include_non_durable = self.include_non_durable && wire.accept_no_commit();
        let mut report = SenderReport::default();
        self.missing_check(wire, include_non_durable, &mut report)?;
        let completed_updates = self.updates(wire, include_non_durable, &mut report)?;
        let wanted: BTreeSet<&str> = report
            .send_map
            .iter()
            .map(|(object_hash, _)| object_hash.as_str())
            .collect();
        // An offered object is safe for handoff deletion only when the receiver
        // either requested nothing (it already had the state) or every wanted
        // subrequest was actually emitted and the receiver accepted the update
        // document. Local open/rebuild failures are per-object skips, not
        // permission to delete that source generation.
        report.can_delete_objs.retain(|object_hash, _| {
            !wanted.contains(object_hash.as_str()) || completed_updates.contains(object_hash)
        });
        Ok(report)
    }

    fn partition_path(&self) -> PathBuf {
        self.devices
            .join(&self.job.device)
            .join(get_data_dir(self.job.policy_index))
            .join(self.job.partition.to_string())
    }

    fn frag_prefs(&self, include_non_durable: bool) -> Option<Vec<FragPref>> {
        // an empty frag_prefs list is sufficient to get non-durable frags
        // yielded, in which case an older durable frag will not be yielded
        if include_non_durable {
            Some(Vec::new())
        } else {
            None
        }
    }

    /// `DiskFileManager.yield_hashes`: (hash, timestamps) for each object in
    /// the given suffixes that matches the job's frag index.
    pub(crate) fn yield_local_hashes(
        &self,
        include_non_durable: bool,
    ) -> Result<Vec<(String, String, ObjectTimestamps)>, SsyncSenderError> {
        let partition_path = self.partition_path();
        let mut suffixes: Vec<String> = match self.suffixes {
            Some(list) => {
                if list.iter().any(|suffix| {
                    suffix.len() != 3
                        || !suffix
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                }) {
                    return Err(SsyncSenderError::new(
                        "refusing malformed suffix in SSYNC sender request",
                    ));
                }
                list.to_vec()
            }
            None => {
                let mut found: Vec<String> = Vec::new();
                let entries = match std::fs::read_dir(&partition_path) {
                    Ok(entries) => entries,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(Vec::new());
                    }
                    Err(error) => {
                        return Err(SsyncSenderError::new(format!(
                            "could not enumerate SSYNC partition: {error}"
                        )))
                    }
                };
                for entry in entries {
                    let entry = entry.map_err(|error| {
                        SsyncSenderError::new(format!(
                            "could not enumerate SSYNC partition entry: {error}"
                        ))
                    })?;
                    let name = entry
                        .file_name()
                        .to_str()
                        .map(str::to_string)
                        .ok_or_else(|| {
                            SsyncSenderError::new("non-UTF8 entry in SSYNC partition")
                        })?;
                    let metadata = entry.path().symlink_metadata().map_err(|error| {
                        SsyncSenderError::new(format!(
                            "could not inspect SSYNC partition entry {name}: {error}"
                        ))
                    })?;
                    if metadata.file_type().is_dir()
                        && name.len() == 3
                        && name
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        found.push(name);
                    } else if metadata.file_type().is_file()
                        && matches!(
                            name.as_str(),
                            ".lock" | ".lock-replication" | "hashes.pkl" | "hashes.invalid"
                        )
                    {
                        continue;
                    } else {
                        return Err(SsyncSenderError::new(format!(
                            "refusing unknown SSYNC partition entry {name}"
                        )));
                    }
                }
                found.sort();
                found
            }
        };
        suffixes.sort();
        suffixes.dedup();
        let frag_prefs = self.frag_prefs(include_non_durable);
        let mut out = Vec::new();
        for suffix in suffixes {
            let suffix_path = partition_path.join(&suffix);
            let suffix_metadata = match suffix_path.symlink_metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(SsyncSenderError::new(format!(
                        "could not inspect SSYNC suffix {suffix}: {error}"
                    )))
                }
            };
            if !suffix_metadata.file_type().is_dir() {
                return Err(SsyncSenderError::new(format!(
                    "refusing non-directory SSYNC suffix {suffix}"
                )));
            }
            let entries = std::fs::read_dir(&suffix_path).map_err(|error| {
                SsyncSenderError::new(format!(
                    "could not enumerate SSYNC suffix {suffix}: {error}"
                ))
            })?;
            // Keep at most limit+1 offerable objects. The fragment-index
            // filter must precede this bound: taking the first N directory
            // names and then filtering could hide a later matching fragment
            // and incorrectly report that this was the final page.
            let remaining_bound = if self.max_objects == 0 {
                usize::MAX
            } else {
                self.max_objects.saturating_add(1).saturating_sub(out.len())
            };
            let mut bounded_hashes: BTreeMap<String, ObjectTimestamps> = BTreeMap::new();
            for entry in entries {
                let entry = entry.map_err(|error| {
                    SsyncSenderError::new(format!(
                        "could not enumerate SSYNC hash in suffix {suffix}: {error}"
                    ))
                })?;
                let name = entry
                    .file_name()
                    .to_str()
                    .map(str::to_string)
                    .ok_or_else(|| {
                        SsyncSenderError::new(format!("non-UTF8 object hash in suffix {suffix}"))
                    })?;
                let metadata = entry.path().symlink_metadata().map_err(|error| {
                    SsyncSenderError::new(format!(
                        "could not inspect SSYNC object {suffix}/{name}: {error}"
                    ))
                })?;
                if !metadata.file_type().is_dir()
                    || name.len() != 32
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    || !name.ends_with(suffix.as_str())
                {
                    return Err(SsyncSenderError::new(format!(
                        "refusing malformed SSYNC object entry {suffix}/{name}"
                    )));
                }
                if self
                    .start_after
                    .as_ref()
                    .is_some_and(|(cursor_suffix, cursor_hash)| {
                        suffix.as_str() < cursor_suffix.as_str()
                            || (suffix.as_str() == cursor_suffix.as_str()
                                && name.as_str() <= cursor_hash.as_str())
                    })
                {
                    continue;
                }
                if bounded_hashes.len() >= remaining_bound
                    && bounded_hashes
                        .last_key_value()
                        .is_some_and(|(largest, _)| name.as_str() >= largest.as_str())
                {
                    continue;
                }
                let timestamps = object_timestamps_from_hash_dir_strict(
                    &entry.path(),
                    self.job.policy,
                    self.job.frag_index,
                    frag_prefs.as_deref(),
                )
                .map_err(|error| {
                    SsyncSenderError::new(format!(
                        "could not inspect SSYNC object {suffix}/{name}: {error}"
                    ))
                })?;
                let Some(timestamps) = timestamps else {
                    // A suffix may contain several EC fragment indexes. This
                    // hash is valid but belongs to another job's frag index.
                    continue;
                };
                bounded_hashes.insert(name, timestamps);
                if bounded_hashes.len() > remaining_bound {
                    bounded_hashes.pop_last();
                }
            }
            for (object_hash, timestamps) in bounded_hashes {
                out.push((suffix.clone(), object_hash, timestamps));
                if self.max_objects > 0 && out.len() > self.max_objects {
                    return Ok(out);
                }
            }
        }
        Ok(out)
    }

    /// `Sender.missing_check`: send our offers, read the receiver's wanted
    /// list into `report.send_map`.
    fn missing_check(
        &self,
        wire: &mut dyn SsyncWire,
        include_non_durable: bool,
        report: &mut SenderReport,
    ) -> Result<(), SsyncSenderError> {
        wire.send(&chunk_frame(b":MISSING_CHECK: START\r\n"))?;
        let available = self.yield_local_hashes(include_non_durable)?;
        for (index, (suffix, object_hash, timestamps)) in available.iter().enumerate() {
            if self.max_objects > 0 && index >= self.max_objects {
                // reached only when a further hash exists, i.e. the offer
                // list was truncated (Python's second-loop probe).
                report.limited_by_max_objects = true;
                break;
            }
            report
                .can_delete_objs
                .insert(object_hash.clone(), timestamps.clone());
            report.offered_count += 1;
            report.last_offered = Some((suffix.clone(), object_hash.clone()));
            let line = format!(
                "{}\r\n",
                encode_missing(
                    object_hash,
                    timestamps.ts_data,
                    timestamps.ts_meta,
                    timestamps.ts_ctype,
                    timestamps.durable,
                )
            );
            wire.send(&chunk_frame(line.as_bytes()))?;
        }
        wire.send(&chunk_frame(b":MISSING_CHECK: END\r\n"))?;
        // Now, retrieve the list of what they want.
        wire.begin_response_phase()?;
        loop {
            let line = wire.readline()?;
            if line.is_empty() {
                return Err(SsyncSenderError::new("Early disconnect"));
            }
            let line = trim_ascii(&line);
            if line == b":MISSING_CHECK: START" {
                break;
            } else if !line.is_empty() {
                return Err(SsyncSenderError::new(format!(
                    "Unexpected response: {:?}",
                    String::from_utf8_lossy(&line[..line.len().min(1024)])
                )));
            }
        }
        loop {
            let line = wire.readline()?;
            if line.is_empty() {
                return Err(SsyncSenderError::new("Early disconnect"));
            }
            let line = trim_ascii(&line);
            if line == b":MISSING_CHECK: END" {
                break;
            }
            let text = String::from_utf8_lossy(&line).into_owned();
            let parts: Vec<&str> = text.split_whitespace().collect();
            if let Some((hash, rest)) = parts.split_first() {
                if !report.can_delete_objs.contains_key(*hash) {
                    return Err(SsyncSenderError::new(format!(
                        "receiver requested unoffered object hash {hash:?}"
                    )));
                }
                if report.send_map.iter().any(|(existing, _)| existing == hash) {
                    return Err(SsyncSenderError::new(format!(
                        "receiver requested duplicate object hash {hash:?}"
                    )));
                }
                report
                    .send_map
                    .push((hash.to_string(), decode_wanted(rest)));
            }
        }
        Ok(())
    }

    /// `Sender.updates`: send the wanted subrequests, then read the final
    /// `:UPDATES:` frames.
    fn updates(
        &self,
        wire: &mut dyn SsyncWire,
        include_non_durable: bool,
        report: &mut SenderReport,
    ) -> Result<BTreeSet<String>, SsyncSenderError> {
        wire.send(&chunk_frame(b":UPDATES: START\r\n"))?;
        let frag_prefs = self.frag_prefs(include_non_durable);
        let mut completed = BTreeSet::new();
        let send_map = report.send_map.clone();
        'objects: for (object_hash, want) in &send_map {
            let device_path = self.devices.join(&self.job.device);
            let hash_dir = device_path.join(storage_directory(
                Path::new(&get_data_dir(self.job.policy_index)),
                self.job.partition,
                object_hash,
            ));
            let mut df = DiskFile::from_hash_dir(
                &device_path,
                &hash_dir,
                self.job.policy,
                self.job.policy_index,
                self.hash_config,
                self.diskfile_config.clone(),
            )
            .with_frag_index(self.job.frag_index)
            .with_frag_prefs(frag_prefs.clone())
            .with_open_expired(true);
            match df.open(None) {
                Ok(_) => {
                    let name = df
                        .get_metadata()
                        .ok()
                        .and_then(|meta| {
                            meta.iter().find_map(|(k, v)| match (k, v) {
                                (MetaValue::Str(k), MetaValue::Str(v)) if k == "name" => {
                                    Some(v.clone())
                                }
                                _ => None,
                            })
                        })
                        .ok_or_else(|| SsyncSenderError::new("diskfile has no name"))?;
                    let url_path = percent_encode(&name);
                    // On a SYNC job the receiver stores fragments at ITS
                    // backend index: a local fragment at a different index
                    // must be rebuilt on the fly (reconstruct_fa); with no
                    // builder or a failed rebuild the object is skipped,
                    // like Python's DiskFileError from reconstruct_fa.
                    let mut rebuilt: Option<(Metadata, crate::reconstruction_spool::ArchiveBody)> =
                        None;
                    if let (true, Some(target)) = (want.data, self.sync_frag_target) {
                        let local_frag = df.get_datafile_metadata().ok().and_then(|meta| {
                            meta.iter().find_map(|(k, v)| match (k, v) {
                                (MetaValue::Str(k), value)
                                    if k == "X-Object-Sysmeta-Ec-Frag-Index" =>
                                {
                                    match value {
                                        MetaValue::Int(i) => Some(*i),
                                        MetaValue::Str(s) => s.trim().parse().ok(),
                                        MetaValue::Bytes(_) => None,
                                    }
                                }
                                _ => None,
                            })
                        });
                        if local_frag != Some(target) {
                            let Some(builder) = self.diskfile_builder else {
                                report.last_rebuild_error = Some(
                                    "reconstruct_fa skipped: no sync_diskfile_builder \
                                     (need --features ec)"
                                        .into(),
                                );
                                continue 'objects;
                            };
                            let Ok(datafile_metadata) = df.get_datafile_metadata().cloned() else {
                                continue 'objects;
                            };
                            let local = local_rebuild_fragment(&mut df, local_frag);
                            match builder.rebuild_with_local(
                                object_hash,
                                &datafile_metadata,
                                target,
                                local,
                            ) {
                                Ok(built) => rebuilt = Some(built),
                                Err(error) if error.contains("(retryable)") => {
                                    // Resource admission is a failed attempt,
                                    // not a successful-but-empty SYNC page.
                                    // Abort without END/ack and keep sources
                                    // available for the next reconstructor pass.
                                    return Err(SsyncSenderError::new(format!(
                                        "rebuild resource refusal: {error}"
                                    )));
                                }
                                Err(error) => {
                                    report.last_rebuild_error = Some(error);
                                    continue 'objects;
                                }
                            }
                        }
                    }
                    if want.data {
                        let is_durable = df
                            .durable_timestamp()
                            .ok()
                            .flatten()
                            .is_some_and(|durable_ts| df.data_timestamp().ok() == Some(durable_ts));
                        match &rebuilt {
                            Some((metadata, body)) => {
                                self.send_put_rebuilt(wire, &url_path, metadata, body, is_durable)?;
                                report.rebuilt += 1;
                            }
                            None => self.send_put(wire, &url_path, &mut df, is_durable)?,
                        }
                    }
                    if want.meta {
                        if df.data_timestamp().ok() != df.timestamp().ok() {
                            if !self.send_post(wire, &url_path, &df)? {
                                continue 'objects;
                            }
                        } else if !want.data {
                            // There is no independent meta generation to POST,
                            // and this request did not send the data document
                            // that carries its metadata.
                            continue 'objects;
                        }
                    }
                }
                Err(DiskFileError::Deleted {
                    timestamp,
                    metadata,
                }) => {
                    if want.meta {
                        continue 'objects;
                    }
                    if want.data {
                        // The tombstone carries no name metadata we can trust
                        // for the path; Python reads df.account/container/obj
                        // which get_diskfile_from_hash resolved from the
                        // quarantine-safe metadata. Use the tombstone's name.
                        let name = metadata.iter().find_map(|(k, v)| match (k, v) {
                            (MetaValue::Str(k), MetaValue::Str(v)) if k == "name" => {
                                Some(v.clone())
                            }
                            _ => None,
                        });
                        let Some(name) = name else {
                            continue 'objects;
                        };
                        let name_hash = self
                            .hash_config
                            .hash_path(name.trim_start_matches('/'), None, None)
                            .ok();
                        if name_hash.as_deref() != Some(object_hash.as_str()) {
                            // A tombstone is looked up by hash and therefore
                            // has not passed DiskFile::open's normal
                            // metadata-name collision check. Never let a
                            // corrupt/misplaced tombstone issue a DELETE for a
                            // different receiver object or authorize source
                            // handoff deletion.
                            continue 'objects;
                        }
                        self.send_delete(wire, &percent_encode(&name), &timestamp)?;
                    }
                }
                // DiskFileErrors are expected while opening the diskfile;
                // there is no partial state on the receiver, so skip it.
                Err(_) => continue 'objects,
            }
            completed.insert(object_hash.clone());
        }
        wire.send(&chunk_frame(b":UPDATES: END\r\n"))?;
        // Now, read their response for any issues.
        wire.begin_response_phase()?;
        loop {
            let line = wire.readline()?;
            if line.is_empty() {
                return Err(SsyncSenderError::new("Early disconnect"));
            }
            let line = trim_ascii(&line);
            if line == b":UPDATES: START" {
                break;
            } else if !line.is_empty() {
                return Err(SsyncSenderError::new(format!(
                    "Unexpected response: {:?}",
                    String::from_utf8_lossy(&line[..line.len().min(1024)])
                )));
            }
        }
        loop {
            let line = wire.readline()?;
            if line.is_empty() {
                return Err(SsyncSenderError::new("Early disconnect"));
            }
            let line = trim_ascii(&line);
            if line == b":UPDATES: END" {
                break;
            } else if !line.is_empty() {
                return Err(SsyncSenderError::new(format!(
                    "Unexpected response: {:?}",
                    String::from_utf8_lossy(&line[..line.len().min(1024)])
                )));
            }
        }
        wire.finish_response()?;
        Ok(completed)
    }

    /// `Sender.send_subrequest`: the header document as one chunk.
    fn send_subrequest_head(
        &self,
        wire: &mut dyn SsyncWire,
        method: &str,
        url_path: &str,
        headers: &[(String, String)],
    ) -> Result<(), SsyncSenderError> {
        let mut lines = vec![format!("{method} {url_path}")];
        let mut sorted: Vec<&(String, String)> = headers.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, value) in sorted {
            lines.push(format!("{key}: {value}"));
        }
        let msg = format!("{}\r\n\r\n", lines.join("\r\n"));
        wire.send(&chunk_frame(msg.as_bytes()))?;
        Ok(())
    }

    /// `send_put` over a rebuilt fragment archive held by an owned reader
    /// — the `RebuildingECDiskFileStream` path: the builder supplied the
    /// metadata (frag index swapped, ETag dropped so the receiver
    /// recomputes it) and the rebuilt bytes.
    fn send_put_rebuilt(
        &self,
        wire: &mut dyn SsyncWire,
        url_path: &str,
        metadata: &Metadata,
        body: &crate::reconstruction_spool::ArchiveBody,
        durable: bool,
    ) -> Result<(), SsyncSenderError> {
        let mut headers: Vec<(String, String)> =
            vec![("Content-Length".to_string(), body.len().to_string())];
        if !durable {
            headers.push(("X-Backend-No-Commit".to_string(), "True".to_string()));
        }
        for (key, value) in metadata {
            let MetaValue::Str(key) = key else { continue };
            if key == "name" || key == "Content-Length" {
                continue;
            }
            let value = match value {
                MetaValue::Str(s) => s.clone(),
                MetaValue::Int(i) => i.to_string(),
                MetaValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            };
            headers.push((key.clone(), value));
        }
        self.send_subrequest_head(wire, "PUT", url_path, &headers)?;
        let mut reader = body.reader();
        let mut buffer = [0u8; swift_http::STREAM_CHUNK];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|error| SsyncSenderError::new(format!("rebuilt archive read: {error}")))?;
            if read == 0 {
                break;
            }
            wire.send(&chunk_frame(&buffer[..read]))?;
        }
        Ok(())
    }

    /// `Sender.send_put`: PUT subrequest with the datafile metadata as
    /// headers and the fragment/object bytes streamed as chunks.
    fn send_put(
        &self,
        wire: &mut dyn SsyncWire,
        url_path: &str,
        df: &mut DiskFile,
        durable: bool,
    ) -> Result<(), SsyncSenderError> {
        let content_length = df
            .content_length()
            .map_err(|e| SsyncSenderError::new(e.to_string()))?;
        let mut headers: Vec<(String, String)> =
            vec![("Content-Length".to_string(), content_length.to_string())];
        if !durable {
            // only send this header for the less common case; without this
            // header object servers assume default commit behaviour
            headers.push(("X-Backend-No-Commit".to_string(), "True".to_string()));
        }
        let datafile_metadata = df
            .get_datafile_metadata()
            .map_err(|e| SsyncSenderError::new(e.to_string()))?
            .clone();
        for (key, value) in &datafile_metadata {
            let MetaValue::Str(key) = key else { continue };
            if key == "name" || key == "Content-Length" {
                continue;
            }
            let value = match value {
                MetaValue::Str(s) => s.clone(),
                MetaValue::Int(i) => i.to_string(),
                MetaValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            };
            headers.push((key.clone(), value));
        }
        self.send_subrequest_head(wire, "PUT", url_path, &headers)?;
        let mut reader = df
            .reader()
            .map_err(|e| SsyncSenderError::new(e.to_string()))?;
        let mut bytes_read: u64 = 0;
        loop {
            match reader.next_chunk() {
                Ok(Some(chunk)) => {
                    bytes_read += chunk.len() as u64;
                    wire.send(&chunk_frame(&chunk))?;
                }
                Ok(None) => break,
                Err(e) => return Err(SsyncSenderError::new(e.to_string())),
            }
        }
        let _ = reader.close();
        if bytes_read != content_length {
            // Prevent the receiver finalising a bad or partially written
            // diskfile: pull the plug on this ssync session.
            return Err(SsyncSenderError::new(
                "Sent data length does not match content-length",
            ));
        }
        Ok(())
    }

    /// `Sender.send_post`: fast-POST metadata from the newest .meta file.
    fn send_post(
        &self,
        wire: &mut dyn SsyncWire,
        url_path: &str,
        df: &DiskFile,
    ) -> Result<bool, SsyncSenderError> {
        let Some(metafile_metadata) = df
            .get_metafile_metadata()
            .map_err(|e| SsyncSenderError::new(e.to_string()))?
            .cloned()
        else {
            return Ok(false);
        };
        let mut headers: Vec<(String, String)> = Vec::new();
        for (key, value) in &metafile_metadata {
            let MetaValue::Str(key) = key else { continue };
            let value = match value {
                MetaValue::Str(s) => s.clone(),
                MetaValue::Int(i) => i.to_string(),
                MetaValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            };
            headers.push((key.clone(), value));
        }
        self.send_subrequest_head(wire, "POST", url_path, &headers)?;
        Ok(true)
    }

    /// `Sender.send_delete`: a tombstone subrequest.
    fn send_delete(
        &self,
        wire: &mut dyn SsyncWire,
        url_path: &str,
        timestamp: &Timestamp,
    ) -> Result<(), SsyncSenderError> {
        let headers = vec![("X-Timestamp".to_string(), timestamp.internal())];
        self.send_subrequest_head(wire, "DELETE", url_path, &headers)
    }
}

fn trim_ascii(mut bytes: &[u8]) -> Vec<u8> {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::{Shutdown, TcpListener};
    use swift_diskfile::{write_metadata, DEFAULT_XATTR_SIZE};

    /// A scripted receiver: captures sends, replays canned response lines.
    struct FakeWire {
        sent: Vec<u8>,
        lines: VecDeque<Vec<u8>>,
    }

    impl FakeWire {
        fn new(lines: &[&str]) -> Self {
            FakeWire {
                sent: Vec::new(),
                lines: lines
                    .iter()
                    .map(|l| format!("{l}\r\n").into_bytes())
                    .collect(),
            }
        }

        /// De-chunk what the sender wrote.
        fn sent_payload(&self) -> Vec<u8> {
            let mut raw: &[u8] = &self.sent;
            let mut out = Vec::new();
            while !raw.is_empty() {
                let line_end = raw.windows(2).position(|w| w == b"\r\n").unwrap();
                let size =
                    usize::from_str_radix(std::str::from_utf8(&raw[..line_end]).unwrap(), 16)
                        .unwrap();
                raw = &raw[line_end + 2..];
                out.extend_from_slice(&raw[..size]);
                assert_eq!(&raw[size..size + 2], b"\r\n");
                raw = &raw[size + 2..];
            }
            out
        }
    }

    impl SsyncWire for FakeWire {
        fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
            self.sent.extend_from_slice(data);
            Ok(())
        }

        fn readline(&mut self) -> std::io::Result<Vec<u8>> {
            Ok(self.lines.pop_front().unwrap_or_default())
        }
    }

    fn tcp_wire_with_response_body(body: &[u8]) -> TcpSsyncWire {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server.write_all(body).unwrap();
        server.shutdown(Shutdown::Write).unwrap();
        TcpSsyncWire {
            write: client.try_clone().unwrap(),
            read: BufReader::new(client),
            chunk_left: 0,
            response_complete: false,
            response_payload_bytes: 0,
            response_timeout: Duration::from_secs(1),
            response_deadline: None,
            session_deadline: Instant::now() + Duration::from_secs(10),
            accept_no_commit: false,
        }
    }

    #[test]
    fn tcp_wire_requires_terminal_chunk_after_final_protocol_line() {
        let payload = b":UPDATES: END\r\n";
        let body = format!("{:x}\r\n", payload.len()).into_bytes();
        let mut body_with_payload = body;
        body_with_payload.extend_from_slice(payload);
        body_with_payload.extend_from_slice(b"\r\n");
        let mut wire = tcp_wire_with_response_body(&body_with_payload);
        wire.begin_response_phase().unwrap();
        assert_eq!(wire.readline().unwrap(), payload);
        let error = wire.finish_response().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn tcp_wire_rejects_missing_or_invalid_chunk_payload_crlf() {
        let payload = b":UPDATES: END\r\n";

        let mut missing = format!("{:x}\r\n", payload.len()).into_bytes();
        missing.extend_from_slice(payload);
        let mut wire = tcp_wire_with_response_body(&missing);
        wire.begin_response_phase().unwrap();
        assert_eq!(
            wire.readline().unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );

        let mut invalid = format!("{:x}\r\n", payload.len()).into_bytes();
        invalid.extend_from_slice(payload);
        invalid.extend_from_slice(b"xx");
        let mut wire = tcp_wire_with_response_body(&invalid);
        wire.begin_response_phase().unwrap();
        assert_eq!(
            wire.readline().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn tcp_wire_accepts_complete_chunked_response_with_trailers() {
        let payload = b":UPDATES: END\r\n";
        let mut body = format!("{:x}\r\n", payload.len()).into_bytes();
        body.extend_from_slice(payload);
        body.extend_from_slice(b"\r\n0\r\nX-Test: complete\r\n\r\n");
        let mut wire = tcp_wire_with_response_body(&body);
        wire.begin_response_phase().unwrap();
        assert_eq!(wire.readline().unwrap(), payload);
        wire.finish_response().unwrap();
    }

    fn connect_with_test_head(head: &[u8]) -> Result<TcpSsyncWire, SsyncSenderError> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let response = head.to_vec();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
                assert!(head.len() <= 64 * 1024);
            }
            socket.write_all(&response).unwrap();
        });
        let result = TcpSsyncWire::connect(
            &SsyncNode {
                replication_ip: "127.0.0.1".into(),
                replication_port: addr.port().into(),
                device: "sda1".into(),
                backend_index: None,
            },
            &SsyncJob {
                device: "sda1".into(),
                partition: 3,
                policy_index: 0,
                policy: PolicyKind::Replication,
                frag_index: None,
            },
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        peer.join().unwrap();
        result
    }

    #[test]
    fn tcp_wire_connect_requires_unambiguous_chunked_response() {
        assert!(
            connect_with_test_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .is_ok()
        );
        for headers in [
            "",
            "Content-Length: 0\r\n",
            "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: gzip, chunked\r\n",
            "Transfer-Encoding : chunked\r\n",
            "Transfer-Encoding: chunked\r\nBad Header: x\r\n",
        ] {
            let response = format!("HTTP/1.1 200 OK\r\n{headers}\r\n");
            assert!(
                connect_with_test_head(response.as_bytes()).is_err(),
                "{headers:?}"
            );
        }
    }

    #[test]
    fn tcp_wire_phase_restart_cannot_extend_session_deadline() {
        let mut wire = tcp_wire_with_response_body(b"1\r\nx\r\n0\r\n\r\n");
        wire.response_timeout = Duration::from_secs(60);
        wire.session_deadline = Instant::now() - Duration::from_millis(1);
        wire.begin_response_phase().unwrap();
        assert_eq!(wire.response_deadline, Some(wire.session_deadline));
        assert_eq!(
            wire.readline().unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert_eq!(
            wire.send(b"1\r\nx\r\n").unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn tcp_wire_payload_crlf_uses_remaining_phase_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server.write_all(b"1\r\n\n").unwrap();
        let mut wire = TcpSsyncWire {
            write: client.try_clone().unwrap(),
            read: BufReader::new(client),
            chunk_left: 0,
            response_complete: false,
            response_payload_bytes: 0,
            response_timeout: Duration::from_secs(5),
            response_deadline: Some(Instant::now() + Duration::from_millis(120)),
            session_deadline: Instant::now() + Duration::from_secs(10),
            accept_no_commit: false,
        };
        let started = Instant::now();
        let error = wire.readline().unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn tcp_wire_rejects_unbounded_trailer_sequence() {
        let mut body = b"0\r\n".to_vec();
        for _ in 0..(MAX_SSYNC_TRAILER_BYTES / 6 + 1) {
            body.extend_from_slice(b"X: y\r\n");
        }
        body.extend_from_slice(b"\r\n");
        let mut wire = tcp_wire_with_response_body(&body);
        wire.begin_response_phase().unwrap();
        assert_eq!(
            wire.readline().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn logical_snapshot_accepts_only_recognized_rsync_temporary_names() {
        let policy = PolicyKind::Replication;
        assert!(is_rsync_temporary_diskfile(
            ".1700000000.00000.data.6MbL6r",
            policy
        ));
        for invalid in [
            ".1700000000.00000.data",
            ".1700000000.00000.data.abc",
            ".1700000000.00000.data.abcdefg",
            ".1700000000.00000.unknown.abcdef",
            ".not-a-timestamp.data.abcdef",
            ".1700000000.00000.data.ab!def",
        ] {
            assert!(!is_rsync_temporary_diskfile(invalid, policy), "{invalid}");
        }
        let dir = std::env::temp_dir().join(format!("ssync-logical-rsync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("1700000000.00000.data"), b"committed").unwrap();
        std::fs::write(dir.join(".1700000000.00000.data.6MbL6r"), b"partial").unwrap();
        assert!(
            object_timestamps_from_hash_dir_strict(&dir, policy, None, None)
                .unwrap()
                .is_some()
        );
        std::fs::write(dir.join("unrecognized-state"), b"preserve").unwrap();
        assert!(object_timestamps_from_hash_dir_strict(&dir, policy, None, None).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_decode_wanted() {
        assert_eq!(
            decode_wanted(&["dm"]),
            Wanted {
                data: true,
                meta: true
            }
        );
        assert_eq!(
            decode_wanted(&["d"]),
            Wanted {
                data: true,
                meta: false
            }
        );
        assert_eq!(
            decode_wanted(&["m"]),
            Wanted {
                data: false,
                meta: true
            }
        );
        // legacy receiver: no parts token means data only
        assert_eq!(
            decode_wanted(&[]),
            Wanted {
                data: true,
                meta: false
            }
        );
        assert_eq!(
            decode_wanted(&["x"]),
            Wanted {
                data: true,
                meta: false
            }
        );
    }

    #[test]
    fn test_sender_empty_partition_round_trip() {
        let dir = std::env::temp_dir().join(format!("ssync-sender-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let job = SsyncJob {
            device: "sda1".to_string(),
            partition: 3,
            policy_index: 0,
            policy: PolicyKind::Replication,
            frag_index: None,
        };
        let sender = Sender {
            devices: &dir,
            hash_config: &hc,
            diskfile_config: &cfg,
            job: &job,
            suffixes: None,
            include_non_durable: false,
            max_objects: 0,
            start_after: None,
            sync_frag_target: None,
            diskfile_builder: None,
        };
        let mut wire = FakeWire::new(&[
            ":MISSING_CHECK: START",
            ":MISSING_CHECK: END",
            ":UPDATES: START",
            ":UPDATES: END",
        ]);
        let report = sender.run(&mut wire).expect("clean run");
        assert!(report.can_delete_objs.is_empty());
        assert!(report.send_map.is_empty());
        assert_eq!(
            wire.sent_payload(),
            b":MISSING_CHECK: START\r\n:MISSING_CHECK: END\r\n\
              :UPDATES: START\r\n:UPDATES: END\r\n"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_sender_unexpected_response_line_is_an_error() {
        let dir = std::env::temp_dir().join(format!("ssync-sender-err-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let job = SsyncJob {
            device: "sda1".to_string(),
            partition: 0,
            policy_index: 0,
            policy: PolicyKind::Replication,
            frag_index: None,
        };
        let sender = Sender {
            devices: &dir,
            hash_config: &hc,
            diskfile_config: &cfg,
            job: &job,
            suffixes: None,
            include_non_durable: false,
            max_objects: 0,
            start_after: None,
            sync_frag_target: None,
            diskfile_builder: None,
        };
        let mut wire = FakeWire::new(&[":ERROR: 0 'insufficient storage'"]);
        let err = sender.run(&mut wire).unwrap_err();
        assert!(err.message().contains("Unexpected response"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_sender_does_not_confirm_wanted_object_skipped_during_updates() {
        let dir = std::env::temp_dir().join(format!(
            "ssync-sender-skipped-update-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let object_hash = "00000000000000000000000000000abc";
        let hash_dir = dir.join("sda1/objects/3/abc").join(object_hash);
        std::fs::create_dir_all(&hash_dir).unwrap();
        // The filename is offerable during missing-check, but the absent xattr
        // metadata makes DiskFile::open fail in updates. A successful protocol
        // envelope must not turn that per-object skip into deletion authority.
        std::fs::write(hash_dir.join("1700000000.00000.data"), b"not-openable").unwrap();
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let job = SsyncJob {
            device: "sda1".to_string(),
            partition: 3,
            policy_index: 0,
            policy: PolicyKind::Replication,
            frag_index: None,
        };
        let suffixes = ["abc".to_string()];
        let sender = Sender {
            devices: &dir,
            hash_config: &hc,
            diskfile_config: &cfg,
            job: &job,
            suffixes: Some(&suffixes),
            include_non_durable: false,
            max_objects: 0,
            start_after: None,
            sync_frag_target: None,
            diskfile_builder: None,
        };
        let wanted = format!("{object_hash} d");
        let mut wire = FakeWire::new(&[
            ":MISSING_CHECK: START",
            &wanted,
            ":MISSING_CHECK: END",
            ":UPDATES: START",
            ":UPDATES: END",
        ]);
        let report = sender.run(&mut wire).expect("protocol envelope succeeds");
        assert_eq!(report.send_map.len(), 1);
        assert!(
            !report.can_delete_objs.contains_key(object_hash),
            "a wanted object skipped locally is not receiver-confirmed"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_sender_rejects_receiver_request_for_unoffered_hash() {
        let dir = std::env::temp_dir().join(format!(
            "ssync-sender-unoffered-request-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1/objects/3")).unwrap();
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let job = SsyncJob {
            device: "sda1".to_string(),
            partition: 3,
            policy_index: 0,
            policy: PolicyKind::Replication,
            frag_index: None,
        };
        let sender = Sender {
            devices: &dir,
            hash_config: &hc,
            diskfile_config: &cfg,
            job: &job,
            suffixes: None,
            include_non_durable: false,
            max_objects: 0,
            start_after: None,
            sync_frag_target: None,
            diskfile_builder: None,
        };
        let mut wire = FakeWire::new(&[
            ":MISSING_CHECK: START",
            "00000000000000000000000000000abc d",
        ]);
        let error = sender.run(&mut wire).unwrap_err();
        assert!(error.message().contains("unoffered object hash"), "{error}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_sender_never_deletes_from_misnamed_tombstone_or_confirms_it() {
        let dir = std::env::temp_dir().join(format!(
            "ssync-sender-misnamed-tombstone-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let object_hash = hc.hash_path("a/c/intended", None, None).unwrap();
        let suffix = &object_hash[object_hash.len() - 3..];
        let hash_dir = dir.join("sda1/objects/3").join(suffix).join(&object_hash);
        std::fs::create_dir_all(&hash_dir).unwrap();
        let tombstone = hash_dir.join("1700000000.00000.ts");
        std::fs::write(&tombstone, b"").unwrap();
        let metadata = vec![
            (
                MetaValue::Str("name".to_string()),
                MetaValue::Str("/a/c/different-object".to_string()),
            ),
            (
                MetaValue::Str("X-Timestamp".to_string()),
                MetaValue::Str("1700000000.00000".to_string()),
            ),
        ];
        write_metadata(&tombstone, &metadata, DEFAULT_XATTR_SIZE).unwrap();
        let cfg = DiskFileConfig::default();
        let job = SsyncJob {
            device: "sda1".to_string(),
            partition: 3,
            policy_index: 0,
            policy: PolicyKind::Replication,
            frag_index: None,
        };
        let suffixes = [suffix.to_string()];
        let sender = Sender {
            devices: &dir,
            hash_config: &hc,
            diskfile_config: &cfg,
            job: &job,
            suffixes: Some(&suffixes),
            include_non_durable: false,
            max_objects: 0,
            start_after: None,
            sync_frag_target: None,
            diskfile_builder: None,
        };
        let wanted = format!("{object_hash} d");
        let mut wire = FakeWire::new(&[
            ":MISSING_CHECK: START",
            &wanted,
            ":MISSING_CHECK: END",
            ":UPDATES: START",
            ":UPDATES: END",
        ]);
        let report = sender.run(&mut wire).expect("envelope remains usable");
        assert!(
            !report.can_delete_objs.contains_key(&object_hash),
            "misnamed tombstone must not authorize local handoff deletion"
        );
        let payload = String::from_utf8(wire.sent_payload()).unwrap();
        assert!(
            !payload.contains("DELETE /a/c/different-object"),
            "misnamed tombstone must not delete an unrelated receiver object"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_sender_bounded_cursor_pages_without_reoffering_objects() {
        let dir =
            std::env::temp_dir().join(format!("ssync-sender-pagination-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hashes: Vec<String> = (1..=3).map(|n| format!("{n:029x}aaa")).collect();
        for object_hash in &hashes {
            let hash_dir = dir.join("sda1/objects/3/aaa").join(object_hash);
            std::fs::create_dir_all(&hash_dir).unwrap();
            std::fs::write(hash_dir.join("1700000000.00000.data"), b"x").unwrap();
        }
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let job = SsyncJob {
            device: "sda1".to_string(),
            partition: 3,
            policy_index: 0,
            policy: PolicyKind::Replication,
            frag_index: None,
        };
        let suffixes = ["aaa".to_string()];
        let run_page = |start_after: Option<(String, String)>| {
            let sender = Sender {
                devices: &dir,
                hash_config: &hc,
                diskfile_config: &cfg,
                job: &job,
                suffixes: Some(&suffixes),
                include_non_durable: false,
                max_objects: 2,
                start_after,
                sync_frag_target: None,
                diskfile_builder: None,
            };
            let mut wire = FakeWire::new(&[
                ":MISSING_CHECK: START",
                ":MISSING_CHECK: END",
                ":UPDATES: START",
                ":UPDATES: END",
            ]);
            sender.run(&mut wire).unwrap()
        };
        let first = run_page(None);
        assert_eq!(first.offered_count, 2);
        assert!(first.limited_by_max_objects);
        assert_eq!(
            first.can_delete_objs.keys().cloned().collect::<Vec<_>>(),
            hashes[..2]
        );
        let second = run_page(first.last_offered.clone());
        assert_eq!(second.offered_count, 1);
        assert!(!second.limited_by_max_objects);
        assert_eq!(
            second.can_delete_objs.keys().cloned().collect::<Vec<_>>(),
            hashes[2..]
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
