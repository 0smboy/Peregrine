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

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use swift_core::config::config_true_value;
use swift_core::hashing::HashPathConfig;
use swift_core::timestamp::Timestamp;
use swift_diskfile::{
    get_data_dir, get_ondisk_files, storage_directory, DiskFile, DiskFileConfig, DiskFileError,
    FragPref, MetaValue, Metadata, PolicyKind,
};

use crate::percent_encode;
use crate::ssync::encode_missing;

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
    /// Bytes left in the current response chunk; -1 marks EOF.
    chunk_left: i64,
    accept_no_commit: bool,
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
        let addr = format!("{}:{}", node.replication_ip, node.replication_port);
        let sock_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|_| SsyncSenderError::new(format!("bad node address {addr}")))?;
        let stream = TcpStream::connect_timeout(&sock_addr, conn_timeout)?;
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
        write.write_all(head.as_bytes())?;
        let mut read = BufReader::new(write.try_clone()?);
        // Response head: status line + headers until the blank line.
        let mut status_line = String::new();
        read.read_line(&mut status_line)?;
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| {
                SsyncSenderError::new(format!("bad SSYNC response line {status_line:?}"))
            })?;
        let mut accept_no_commit = false;
        loop {
            let mut line = String::new();
            if read.read_line(&mut line)? == 0 {
                return Err(SsyncSenderError::new("Early disconnect"));
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name
                    .trim()
                    .eq_ignore_ascii_case("x-backend-accept-no-commit")
                {
                    accept_no_commit = config_true_value(value.trim());
                }
            }
        }
        if status != 200 {
            return Err(SsyncSenderError::new(format!(
                "Expected status 200; got {status}"
            )));
        }
        Ok(TcpSsyncWire {
            write,
            read,
            chunk_left: 0,
            accept_no_commit,
        })
    }

    /// `Sender.disconnect`: terminate the chunked request body; failures are
    /// fine (the receiver may already have closed).
    pub fn disconnect(mut self) {
        let _ = self.write.write_all(b"0\r\n\r\n");
        let _ = self.write.flush();
    }
}

impl SsyncWire for TcpSsyncWire {
    fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.write.write_all(data)
    }

    /// A line from the de-chunked response body, the Rust
    /// `SsyncBufferedHTTPResponse.readline`.
    fn readline(&mut self) -> std::io::Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            if self.chunk_left == -1 {
                return Ok(line); // EOF (possibly a partial line)
            }
            if self.chunk_left == 0 {
                let mut size_line = Vec::new();
                self.read.read_until(b'\n', &mut size_line)?;
                if size_line.is_empty() {
                    self.chunk_left = -1;
                    return Ok(line);
                }
                let text = String::from_utf8_lossy(&size_line);
                let text = text.split(';').next().unwrap_or("").trim();
                let size = i64::from_str_radix(text, 16).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Early disconnect: bad chunk size",
                    )
                })?;
                if size == 0 {
                    self.chunk_left = -1;
                    return Ok(line);
                }
                self.chunk_left = size;
            }
            let mut byte = [0u8; 1];
            if self.read.read(&mut byte)? == 0 {
                self.chunk_left = -1;
                return Ok(line);
            }
            self.chunk_left -= 1;
            if self.chunk_left == 0 {
                // discard the chunk's trailing \r\n
                let mut crlf = [0u8; 2];
                let _ = self.read.read_exact(&mut crlf);
            }
            if byte[0] == b'\n' {
                line.push(b'\n');
                return Ok(line);
            }
            line.push(byte[0]);
        }
    }

    fn accept_no_commit(&self) -> bool {
        self.accept_no_commit
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
    ) -> Result<(Metadata, Vec<u8>), String>;
}

impl Sender<'_> {
    /// Run the exchange over an established wire; the caller handles
    /// connect/disconnect. Mirrors `Sender.__call__`'s success path;
    /// protocol errors return `Err` (Python logs and returns `(False, {})`).
    pub fn run(&self, wire: &mut dyn SsyncWire) -> Result<SenderReport, SsyncSenderError> {
        let include_non_durable = self.include_non_durable && wire.accept_no_commit();
        let mut report = SenderReport::default();
        self.missing_check(wire, include_non_durable, &mut report)?;
        self.updates(wire, include_non_durable, &report.send_map)?;
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
    fn yield_local_hashes(&self, include_non_durable: bool) -> Vec<(String, ObjectTimestamps)> {
        let partition_path = self.partition_path();
        let suffixes: Vec<String> = match self.suffixes {
            Some(list) => list.to_vec(),
            None => {
                let mut found = Vec::new();
                if let Ok(entries) = std::fs::read_dir(&partition_path) {
                    for entry in entries.flatten() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if name.len() == 3
                            && name.bytes().all(|b| b.is_ascii_hexdigit())
                            && entry.path().is_dir()
                        {
                            found.push(name);
                        }
                    }
                }
                found.sort();
                found
            }
        };
        let frag_prefs = self.frag_prefs(include_non_durable);
        let mut out = Vec::new();
        for suffix in suffixes {
            let suffix_path = partition_path.join(&suffix);
            let mut hash_dirs: Vec<String> = std::fs::read_dir(&suffix_path)
                .map(|entries| {
                    entries
                        .flatten()
                        .filter(|e| e.path().is_dir())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .filter(|name| {
                            name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                        .collect()
                })
                .unwrap_or_default();
            hash_dirs.sort();
            for object_hash in hash_dirs {
                let hash_dir = suffix_path.join(&object_hash);
                let files: Vec<String> = match std::fs::read_dir(&hash_dir) {
                    Ok(entries) => entries
                        .filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect(),
                    Err(_) => continue,
                };
                let Ok(ondisk) = get_ondisk_files(
                    &files,
                    &hash_dir,
                    true,
                    self.job.policy,
                    self.job.frag_index,
                    frag_prefs.as_deref(),
                ) else {
                    continue;
                };
                // Python's key_map: ts_data from ts_info (tombstone) or
                // data_info; ts_meta from meta_info; ts_ctype from
                // ctype_info.ctype_timestamp; durable from data_info (EC).
                let timestamps = if let Some(data_info) = &ondisk.data_info {
                    ObjectTimestamps {
                        ts_data: data_info.timestamp,
                        ts_meta: ondisk.meta_info.as_ref().map(|info| info.timestamp),
                        ts_ctype: ondisk
                            .ctype_info
                            .as_ref()
                            .and_then(|info| info.ctype_timestamp),
                        durable: data_info.durable,
                    }
                } else if let Some(ts_info) = &ondisk.ts_info {
                    ObjectTimestamps {
                        ts_data: ts_info.timestamp,
                        ts_meta: None,
                        ts_ctype: None,
                        durable: None,
                    }
                } else {
                    continue;
                };
                out.push((object_hash, timestamps));
            }
        }
        out
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
        let available = self.yield_local_hashes(include_non_durable);
        for (index, (object_hash, timestamps)) in available.iter().enumerate() {
            if self.max_objects > 0 && index >= self.max_objects {
                // reached only when a further hash exists, i.e. the offer
                // list was truncated (Python's second-loop probe).
                report.limited_by_max_objects = true;
                break;
            }
            report
                .can_delete_objs
                .insert(object_hash.clone(), timestamps.clone());
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
        send_map: &[(String, Wanted)],
    ) -> Result<(), SsyncSenderError> {
        wire.send(&chunk_frame(b":UPDATES: START\r\n"))?;
        let frag_prefs = self.frag_prefs(include_non_durable);
        for (object_hash, want) in send_map {
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
                    let mut rebuilt: Option<(Metadata, Vec<u8>)> = None;
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
                                continue;
                            };
                            let Ok(datafile_metadata) = df.get_datafile_metadata() else {
                                continue;
                            };
                            match builder.rebuild(object_hash, datafile_metadata, target) {
                                Ok(built) => rebuilt = Some(built),
                                Err(_) => continue,
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
                                self.send_put_rebuilt(wire, &url_path, metadata, body, is_durable)?
                            }
                            None => self.send_put(wire, &url_path, &mut df, is_durable)?,
                        }
                    }
                    if want.meta && df.data_timestamp().ok() != df.timestamp().ok() {
                        self.send_post(wire, &url_path, &df)?;
                    }
                }
                Err(DiskFileError::Deleted {
                    timestamp,
                    metadata,
                }) => {
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
                            continue;
                        };
                        self.send_delete(wire, &percent_encode(&name), &timestamp)?;
                    }
                }
                // DiskFileErrors are expected while opening the diskfile;
                // there is no partial state on the receiver, so skip it.
                Err(_) => continue,
            }
        }
        wire.send(&chunk_frame(b":UPDATES: END\r\n"))?;
        // Now, read their response for any issues.
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
        Ok(())
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

    /// `send_put` over an already-materialized (rebuilt) fragment archive
    /// — the `RebuildingECDiskFileStream` path: the builder supplied the
    /// metadata (frag index swapped, ETag dropped so the receiver
    /// recomputes it) and the rebuilt bytes.
    fn send_put_rebuilt(
        &self,
        wire: &mut dyn SsyncWire,
        url_path: &str,
        metadata: &Metadata,
        body: &[u8],
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
        for chunk in body.chunks(swift_http::STREAM_CHUNK) {
            wire.send(&chunk_frame(chunk))?;
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
    ) -> Result<(), SsyncSenderError> {
        let Some(metafile_metadata) = df
            .get_metafile_metadata()
            .map_err(|e| SsyncSenderError::new(e.to_string()))?
            .cloned()
        else {
            return Ok(());
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
        self.send_subrequest_head(wire, "POST", url_path, &headers)
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
            sync_frag_target: None,
            diskfile_builder: None,
        };
        let mut wire = FakeWire::new(&[":ERROR: 0 'insufficient storage'"]);
        let err = sender.run(&mut wire).unwrap_err();
        assert!(err.message().contains("Unexpected response"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
