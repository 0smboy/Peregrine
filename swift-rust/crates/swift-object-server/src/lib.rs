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

//! The object server, ported from `swift/obj/server.py` for the
//! replication policy: PUT (write + commit), GET/HEAD (with Range),
//! POST (fast-POST metadata + content-type merge), DELETE (tombstone),
//! each driving `swift-diskfile` and the container-update side channel.
//!
//! Deviations tracked for later: EC policy paths (frag index, ssync),
//! multi-stage MIME PUT (SLO
//! footers), delete-at reaping (X-Delete-At enqueue), keep-cache/zero-copy.
//! The async_pending fallback (writing a pickle the object-updater replays
//! when a container update can't be applied synchronously) IS implemented.

use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;

pub mod daemonutil;
pub mod expirer;
pub mod localdev;
pub mod reconstruction_spool;
/// The EC object reconstructor: ssync-driven SYNC/REVERT partition jobs
/// (feature-independent) plus the fragment rebuild path, which links
/// liberasurecode and is behind the `ec` feature.
pub mod reconstructor;
pub mod replicator;
pub mod servers_per_port;
pub mod ssync;
pub mod ssync_sender;
pub mod updater;
/// Experimental native `/v1` lock gate. Wired on PUT/POST/DELETE of an
/// existing object (not REPLICATE/SSYNC). Not live-proven, not deployed,
/// not a compliance claim.
pub mod worm_native_gate;
pub use expirer::{
    build_task_obj, get_expirer_container, get_expirer_container_for_object_hash, iter_due_tasks,
    parse_task_obj, process_task, recon_update as expirer_recon_update,
    run_once as expirer_run_once, DeleteResult, ExpirerStats, ExpiryClient, HttpExpiryClient,
    TaskInfo, ASYNC_DELETE_TYPE, EXPIRER_ACCOUNT_NAME, EXPIRER_CONTAINER_DIVISOR,
    EXPIRER_CONTAINER_PER_DIVISOR,
};
pub use updater::{
    iter_async_pendings, process_update, run_once, run_once_with_concurrency, AsyncUpdate,
    ContainerNodeClient, HttpContainerClient, NodeResult, UpdateOutcome, UpdaterStats,
};
pub use worm_native_gate::{
    is_s3_lock_control_plane_post, native_mutation_allowed, native_mutation_allowed_for,
    NativeGovernanceBypass,
};

use swift_core::config::{config_true_value, FallocateReserve};
use swift_core::constraints::{AUTO_CREATE_ACCOUNT_PREFIX, RESERVED_STR};
use swift_core::hashing::HashPathConfig;
use swift_core::pickle::{self, Value as PickleValue};
use swift_core::timestamp::{normalize_delete_at_timestamp, Timestamp};
use swift_diskfile::{
    get_data_dir, get_partition_hashes, invalidate_hash, make_ec_ondisk_filename,
    storage_directory, valid_suffix, DiskFile, DiskFileConfig, DiskFileError, FragPref, MetaValue,
    Metadata, PolicyKind,
};
use swift_http::{
    http_date, split_path, unquote, AsyncRequest, AsyncService, Body, ChainReader, ClockHealth,
    HeaderKeyDict, IncomingBodySender, Match, MimeDocs, Range, Request, Response, STREAM_CHUNK,
};
use swift_runtime::{
    ConcurrencyMetrics, DeviceId, DeviceIoLimits, DurabilityBarrier, StorageExecutor,
    StorageExecutorConfig, TaskScope, TrafficClass,
};

use crate::ssync::{MissingOffer, SsyncEvent, SsyncParser, SsyncSubrequest};

pub const MAX_FILE_SIZE: i64 = 5_368_709_122;
const MISPLACED_OBJECTS_ACCOUNT: &str = ".misplaced_objects";
const OBJECT_MUTATION_LOCK_TIMEOUT: f64 = 15.0;
const EXPECTED_S3_VERSION_ID_HEADER: &str = "X-Backend-Expected-S3-Version-Id";
const S3_VERSION_ID_SYSMETA: &str = "X-Object-Sysmeta-S3-Version-Id";

fn validate_internal_name(name: &str, type_: &str) -> Result<(), Response> {
    if name.contains(RESERVED_STR) && !name.starts_with(RESERVED_STR) {
        return Err(plain_response(
            400,
            &format!("Invalid reserved-namespace {type_}"),
        ));
    }
    Ok(())
}

/// Storage-server half of Python `validate_internal_obj`.
///
/// Gatekeeper decides whether a client may use the reserved byte at all. The
/// object server still enforces namespace pairing: a reserved container only
/// contains reserved objects, and a user container only contains user
/// objects. Auto-created system accounts are the upstream exception because
/// reconciler queue object names intentionally embed source paths.
fn validate_internal_obj(account: &str, container: &str, obj: &str) -> Result<(), Response> {
    validate_internal_name(account, "account")?;
    validate_internal_name(container, "container")?;
    if !obj.is_empty()
        && !account.starts_with(AUTO_CREATE_ACCOUNT_PREFIX)
        && account != MISPLACED_OBJECTS_ACCOUNT
    {
        validate_internal_name(obj, "object")?;
        if container.starts_with(RESERVED_STR) && !obj.starts_with(RESERVED_STR) {
            return Err(plain_response(
                400,
                "Invalid user-namespace object in reserved-namespace container",
            ));
        }
        if obj.starts_with(RESERVED_STR) && !container.starts_with(RESERVED_STR) {
            return Err(plain_response(
                400,
                "Invalid reserved-namespace object in user-namespace container",
            ));
        }
    }
    Ok(())
}

fn put_is_mime(headers: &HeaderKeyDict) -> bool {
    use swift_core::config::config_true_value;
    headers
        .get("X-Backend-Obj-Metadata-Footer")
        .is_some_and(config_true_value)
        || headers
            .get("X-Backend-Obj-Multiphase-Commit")
            .is_some_and(config_true_value)
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn async_body_read_error(error: &std::io::Error) -> Response {
    if swift_http::body_too_large(error) {
        plain_response(413, "Your request is too large.")
    } else if error.kind() == std::io::ErrorKind::TimedOut {
        swob_response(408)
    } else {
        swob_response(499)
    }
}

/// Open PUT writer whose unlink cannot run on the reactor thread.
///
/// Drop submits `close()` onto the storage domain and keeps the device
/// permit until the physical cleanup returns. `take()` yields the writer
/// for a later storage-bound put/commit without running Drop cleanup.
struct WriterLease {
    writer: Option<swift_diskfile::DiskFileWriter>,
    storage: StorageExecutor,
    device: DeviceId,
    class: TrafficClass,
}

impl WriterLease {
    fn new(
        storage: StorageExecutor,
        device: DeviceId,
        class: TrafficClass,
        writer: swift_diskfile::DiskFileWriter,
    ) -> Self {
        Self {
            writer: Some(writer),
            storage,
            device,
            class,
        }
    }

    fn writer(&self) -> &swift_diskfile::DiskFileWriter {
        self.writer.as_ref().expect("writer lease empty")
    }

    async fn write_chunk(&mut self, chunk: Vec<u8>) -> Result<(), Response> {
        if chunk.is_empty() {
            return Ok(());
        }
        let writer = self.writer.take().expect("writer lease empty");
        match self
            .storage
            .run_finite(self.device.clone(), self.class, move || {
                let mut writer = writer;
                writer.write(&chunk)?;
                Ok::<_, DiskFileError>(writer)
            })
            .await
        {
            Ok(Ok(writer)) => {
                self.writer = Some(writer);
                Ok(())
            }
            Ok(Err(DiskFileError::NoSpace)) => Err(swob_response(507)),
            Ok(Err(DiskFileError::Io(error))) if error.raw_os_error() == Some(28) => {
                Err(swob_response(507))
            }
            Ok(Err(DiskFileError::Io(_))) => Err(plain_response(500, "disk I/O error")),
            Ok(Err(error)) => Err(plain_response(500, &error.to_string())),
            Err(error) => Err(plain_response(500, &error.to_string())),
        }
    }

    fn take(mut self) -> swift_diskfile::DiskFileWriter {
        let writer = self.writer.take().expect("writer lease empty");
        std::mem::forget(self);
        writer
    }
}

impl Drop for WriterLease {
    fn drop(&mut self) {
        if let Some(mut writer) = self.writer.take() {
            let _ = self
                .storage
                .submit_held(self.device.clone(), self.class, move || {
                    writer.close();
                });
        }
    }
}

async fn ingest_mime_object_async(
    lease: &mut WriterLease,
    body: &mut swift_http::IncomingBody,
    boundary: &[u8],
) -> Result<Vec<u8>, Response> {
    let mut delim = b"\r\n--".to_vec();
    delim.extend_from_slice(boundary);
    let start = delim[2..].to_vec();
    let mut buf = Vec::new();
    let mut phase = 0u8; // 0 preamble, 1 headers, 2 body
    loop {
        match body.next_chunk().await {
            Ok(Some(c)) => buf.extend_from_slice(&c),
            Ok(None) => break,
            Err(error) => return Err(async_body_read_error(&error)),
        }
        if phase == 0 {
            if let Some(i) = find_bytes(&buf, &start) {
                buf.drain(..i + start.len());
                phase = 1;
            } else if buf.len() > 64 * 1024 {
                return Err(plain_response(400, "invalid starting boundary"));
            }
        }
        if phase == 1 {
            if let Some(i) = find_bytes(&buf, b"\r\n\r\n") {
                buf.drain(..i + 4);
                phase = 2;
            } else if buf.len() > 64 * 1024 {
                return Err(plain_response(400, "mime headers too large"));
            }
        }
        if phase == 2 {
            if let Some(i) = find_bytes(&buf, &delim) {
                let piece = buf[..i].to_vec();
                let leftover = buf[i + delim.len()..].to_vec();
                lease.write_chunk(piece).await?;
                return Ok(leftover);
            }
            if buf.len() > delim.len() {
                let keep = delim.len() - 1;
                let piece = buf[..buf.len() - keep].to_vec();
                buf.drain(..buf.len() - keep);
                lease.write_chunk(piece).await?;
            }
        }
    }
    if phase == 2 {
        lease.write_chunk(buf).await?;
        return Ok(Vec::new());
    }
    Err(plain_response(400, "no object body MIME doc"))
}

async fn ingest_mime_footer_async(
    body: &mut swift_http::IncomingBody,
    mut buf: Vec<u8>,
    boundary: &[u8],
) -> Result<(Vec<(String, String)>, Vec<u8>), Response> {
    let mut delim = b"\r\n--".to_vec();
    delim.extend_from_slice(boundary);
    loop {
        if let Some(hdr_end) = find_bytes(&buf, b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&buf[..hdr_end]).into_owned();
            buf.drain(..hdr_end + 4);
            let expected_md5 = headers.lines().find_map(|line| {
                let (k, v) = line.split_once(':')?;
                k.eq_ignore_ascii_case("Content-MD5")
                    .then(|| v.trim().to_string())
            });
            loop {
                if let Some(i) = find_bytes(&buf, &delim) {
                    let json_body = buf[..i].to_vec();
                    if let Some(expected) = expected_md5 {
                        let computed = {
                            use md5::{Digest, Md5};
                            format!("{:x}", Md5::digest(&json_body))
                        };
                        if computed != expected {
                            return Err(plain_response(422, "footer MD5 mismatch"));
                        }
                    }
                    let trailing = buf[i + delim.len()..].to_vec();
                    return parse_footer_json(&json_body).map(|footers| (footers, trailing));
                }
                match body.next_chunk().await {
                    Ok(Some(c)) => buf.extend_from_slice(&c),
                    Ok(None) => {
                        return if buf.is_empty() {
                            Ok((Vec::new(), Vec::new()))
                        } else {
                            parse_footer_json(&buf).map(|footers| (footers, Vec::new()))
                        };
                    }
                    Err(error) => return Err(async_body_read_error(&error)),
                }
                if buf.len() > 1024 * 1024 {
                    return Err(plain_response(400, "footer too large"));
                }
            }
        }
        match body.next_chunk().await {
            Ok(Some(c)) => buf.extend_from_slice(&c),
            Ok(None) => return Ok((Vec::new(), Vec::new())),
            Err(error) => return Err(async_body_read_error(&error)),
        }
        if buf.len() > 64 * 1024 {
            return Err(plain_response(400, "mime headers too large"));
        }
    }
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

/// Consume the remainder of one independently chunked MIME phase. The footer
/// parser returns as soon as it sees the boundary; the HTTP handoff then
/// supplies a logical EOF sentinel for that phase while keeping the channel
/// open for the commit phase.
async fn drain_mime_phase(
    body: &mut swift_http::IncomingBody,
    mut trailing: Vec<u8>,
) -> Result<(), Response> {
    const MAX_TRAILING: usize = 64 * 1024;
    loop {
        if trailing.len() > MAX_TRAILING {
            return Err(plain_response(400, "MIME phase trailer too large"));
        }
        match body.next_chunk().await {
            Ok(Some(chunk)) => trailing.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(error) => return Err(async_body_read_error(&error)),
        }
    }
    let trailing = trim_ascii_whitespace(&trailing);
    if trailing.is_empty() || trailing == b"--" {
        Ok(())
    } else {
        Err(plain_response(400, "invalid MIME phase trailer"))
    }
}

/// Validate and consume the first phase-two document through its MIME
/// boundary. Python Swift treats the body as opaque: the durable transition is
/// authorized by a complete document whose header is `X-Document: put commit`.
/// Only a bounded header and boundary-sized scan window are retained.
async fn ingest_mime_commit_async(
    body: &mut swift_http::IncomingBody,
    boundary: &[u8],
) -> Result<Vec<u8>, Response> {
    const MAX_COMMIT_HEADERS: usize = 64 * 1024;
    let mut delimiter = b"\r\n--".to_vec();
    delimiter.extend_from_slice(boundary);
    let mut buffer = Vec::new();
    let mut validated = false;
    loop {
        if !validated {
            if let Some(header_end) = find_bytes(&buffer, b"\r\n\r\n") {
                let header_text = String::from_utf8_lossy(&buffer[..header_end]);
                let is_commit = header_text.lines().any(|line| {
                    line.split_once(':').is_some_and(|(name, value)| {
                        name.trim().eq_ignore_ascii_case("X-Document")
                            && value.trim().eq_ignore_ascii_case("put commit")
                    })
                });
                if !is_commit {
                    return Err(plain_response(500, "expected put commit MIME doc"));
                }
                buffer.drain(..header_end + 4);
                validated = true;
            } else if buffer.len() > MAX_COMMIT_HEADERS {
                return Err(plain_response(400, "PUT commit MIME headers too large"));
            }
        }
        if validated {
            let mut partial_delimiter = false;
            if let Some(index) = find_bytes(&buffer, &delimiter) {
                let suffix = index + delimiter.len();
                if buffer.len() < suffix + 2 {
                    if index > 0 {
                        buffer.drain(..index);
                    }
                    partial_delimiter = true;
                } else if matches!(&buffer[suffix..suffix + 2], b"--" | b"\r\n") {
                    return Ok(buffer[suffix..].to_vec());
                } else {
                    // A boundary-like byte sequence inside the opaque body is
                    // not a MIME delimiter unless its legal suffix follows.
                    buffer.drain(..index + 1);
                    continue;
                }
            }
            if !partial_delimiter && buffer.len() > delimiter.len() {
                let keep = delimiter.len().saturating_sub(1);
                buffer.drain(..buffer.len() - keep);
            }
        }
        match body.next_chunk().await {
            Ok(Some(chunk)) => buffer.extend_from_slice(&chunk),
            Ok(None) => {
                if !validated && buffer.is_empty() {
                    return Err(plain_response(400, "couldn't find PUT commit MIME doc"));
                }
                if !validated {
                    return Err(plain_response(400, "invalid PUT commit MIME headers"));
                }
                return Err(swob_response(499));
            }
            Err(error) => return Err(async_body_read_error(&error)),
        }
    }
}

/// Drain bytes after the first commit document. This deliberately happens
/// after the durability barrier, matching Python Swift's `_drain_mime_request`.
async fn drain_mime_commit_remainder(
    body: &mut swift_http::IncomingBody,
    _trailing: Vec<u8>,
) -> Result<(), Response> {
    loop {
        match body.next_chunk().await {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(()),
            Err(error) => return Err(async_body_read_error(&error)),
        }
    }
}

fn parse_footer_json(body: &[u8]) -> Result<Vec<(String, String)>, Response> {
    let trimmed = body
        .iter()
        .copied()
        .skip_while(|b| b.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(&trimmed)
    else {
        return Err(plain_response(400, "invalid JSON for footer doc"));
    };
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let value = match v {
            serde_json::Value::String(s) => s,
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => return Err(plain_response(400, "invalid JSON for footer doc")),
        };
        out.push((k, value));
    }
    Ok(out)
}

fn ssync_check_missing_owned(
    devices: PathBuf,
    hash_config: HashPathConfig,
    diskfile: DiskFileConfig,
    device: String,
    partition: String,
    policy_index: u32,
    policy: PolicyKind,
    frag_index: Option<i64>,
    offer: &MissingOffer,
) -> Option<String> {
    let server = ObjectServer::new(ObjectServerConfig {
        devices,
        mount_check: false,
        hash_config,
        diskfile,
        policies: std::collections::HashMap::from([(policy_index, policy)]),
        container_update_timeout: std::time::Duration::from_secs(1),
        container_update_mode: ContainerUpdateMode::Sync,
    });
    SsyncSession {
        server: &server,
        device,
        partition,
        policy_index,
        policy,
        frag_index,
    }
    .check_missing(offer)
}

/// Full-duplex SSYNC session (Python `ssync_receiver.Receiver.__call__`).
/// Network wait is `IncomingBody::next_chunk` (async socket via Hyper).
/// Disk work is a finite `StorageExecutor` job (`TrafficClass::Replication`).
/// The HTTP 200 head is already on the wire before this future runs.
async fn acquire_replication_session_lock(
    storage: &StorageExecutor,
    device: DeviceId,
    part_path: PathBuf,
    timeout: f64,
) -> Result<swift_core::lockutil::PathLock, Response> {
    match storage
        .run_finite(device, TrafficClass::Replication, move || {
            swift_core::lockutil::lock_path(&part_path, timeout, Some("replication"))
        })
        .await
    {
        Ok(Ok(guard)) => Ok(guard),
        Ok(Err(_)) => Err(swob_response(503)),
        Err(_) => Err(swob_response(503)),
    }
}

/// Keep parser input/event batches bounded even when an in-memory adapter
/// supplies a large frame. Network waits remain on this async task.
struct SsyncInput {
    body: swift_http::IncomingBody,
    frame: Vec<u8>,
    offset: usize,
}

impl SsyncInput {
    async fn next_events(
        &mut self,
        parser: &mut SsyncParser,
    ) -> Result<Option<Vec<SsyncEvent>>, String> {
        while self.offset == self.frame.len() {
            self.frame = match self.body.next_chunk().await {
                Ok(Some(frame)) => frame,
                Ok(None) => return Ok(None),
                Err(error) => return Err(error.to_string()),
            };
            self.offset = 0;
        }
        let end = self
            .offset
            .saturating_add(ssync::STREAM_CHUNK_BYTES)
            .min(self.frame.len());
        let events = parser
            .push(&self.frame[self.offset..end])
            .map_err(|e| e.to_string())?;
        self.offset = end;
        if self.offset == self.frame.len() {
            self.frame = Vec::new();
            self.offset = 0;
        }
        Ok(Some(events))
    }
}

#[allow(clippy::too_many_arguments)]
async fn drive_ssync_session(
    body: swift_http::IncomingBody,
    tx: tokio::sync::mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
    storage: StorageExecutor,
    server: ObjectServer,
    device: String,
    partition: String,
    policy_index: u32,
    policy: PolicyKind,
    frag_index: Option<i64>,
    replication_lock: std::sync::Arc<swift_core::lockutil::PathLock>,
) {
    let config = server.config.clone();
    // Python's first yield: a bare b'\r\n' so WSGI/Hyper flushes the 200
    // head before the sender writes `:MISSING_CHECK:` (ssync_receiver.py:294-296).
    let _ = tx.send(Ok(b"\r\n".to_vec())).await;
    let device_id = DeviceId::new(device.clone());
    let mut input = SsyncInput {
        body,
        frame: Vec::new(),
        offset: 0,
    };
    let max_object = MAX_FILE_SIZE as usize;
    let max_wire = max_object
        .saturating_add(ssync::MAX_HEADER_BYTES)
        .saturating_mul(ssync::MAX_UPDATES)
        .saturating_add(ssync::MAX_MISSING_OFFERS.saturating_mul(ssync::MAX_LINE_LENGTH));
    let mut parser = SsyncParser::streaming(max_object, max_wire);
    let mut wanted: Vec<String> = Vec::new();
    let mut missing_done = false;
    while !missing_done {
        let events = match input.next_events(&mut parser).await {
            Ok(Some(events)) => events,
            Ok(None) => return,
            Err(error) => {
                let _ = tx
                    .send(Ok(
                        format!(":ERROR: 0 {}\n", python_repr(&error)).into_bytes()
                    ))
                    .await;
                return;
            }
        };
        for event in events {
            match event {
                SsyncEvent::Missing(offer) => {
                    let line = match storage
                        .run_finite(device_id.clone(), TrafficClass::Replication, {
                            let offer = offer.clone();
                            let device = device.clone();
                            let partition = partition.clone();
                            let devices = config.devices.clone();
                            let hash_config = config.hash_config.clone();
                            let diskfile_cfg = config.diskfile.clone();
                            let replication_lock = std::sync::Arc::clone(&replication_lock);
                            move || {
                                let _replication_lock = replication_lock;
                                ssync_check_missing_owned(
                                    devices,
                                    hash_config,
                                    diskfile_cfg,
                                    device,
                                    partition,
                                    policy_index,
                                    policy,
                                    frag_index,
                                    &offer,
                                )
                            }
                        })
                        .await
                    {
                        Ok(line) => line,
                        Err(error) => {
                            let _ = tx
                                .send(Ok(format!(
                                    ":ERROR: 0 {}\n",
                                    python_repr(&error.to_string())
                                )
                                .into_bytes()))
                                .await;
                            return;
                        }
                    };
                    if let Some(line) = line {
                        wanted.push(line);
                    }
                }
                SsyncEvent::MissingEnd => {
                    missing_done = true;
                }
                _ => {}
            }
        }
        if let Some(message) = parser.failure().map(|error| error.message().to_string()) {
            let _ = tx
                .send(Ok(
                    format!(":ERROR: 0 {}\n", python_repr(&message)).into_bytes()
                ))
                .await;
            return;
        }
    }
    let _ = tx.send(Ok(b":MISSING_CHECK: START\r\n".to_vec())).await;
    if !wanted.is_empty() {
        let _ = tx.send(Ok(wanted.join("\r\n").into_bytes())).await;
    }
    let _ = tx.send(Ok(b"\r\n".to_vec())).await;
    let _ = tx.send(Ok(b":MISSING_CHECK: END\r\n".to_vec())).await;
    let mut updates_done = false;
    let mut events = match parser.start_updates() {
        Ok(e) => e,
        Err(error) => {
            let _ = tx
                .send(Ok(
                    format!(":ERROR: 0 {}\n", python_repr(error.message())).into_bytes()
                ))
                .await;
            return;
        }
    };
    let mut successes = 0usize;
    let mut failures = 0usize;
    let mut update_scope: Option<TaskScope> = None;
    let mut update_tx: Option<IncomingBodySender> = None;
    let mut update_task = None;
    async {
        loop {
            for event in events {
                match event {
                    SsyncEvent::UpdateStart(update) => {
                        if update_task.is_some() {
                            let _ = tx
                                .send(Ok(b":ERROR: 0 'overlapping SSYNC updates'\n".to_vec()))
                                .await;
                            return;
                        }
                        let mut headers = update.headers;
                        headers.set("X-Backend-Storage-Policy-Index", policy_index);
                        headers.set("X-Backend-Replication", "True");
                        if let Some(frag_index) = frag_index {
                            headers.set("X-Backend-Ssync-Frag-Index", frag_index);
                        }
                        if !update.replication_headers.is_empty() {
                            headers.set(
                                "X-Backend-Replication-Headers",
                                update.replication_headers.join(" "),
                            );
                        }
                        let content_length = headers
                            .get("Content-Length")
                            .and_then(|value| value.parse().ok());
                        let (body_tx, body) = match swift_http::IncomingBody::metered_channel(
                            2,
                            STREAM_CHUNK,
                            content_length,
                            None,
                            max_object as u64,
                        ) {
                            Ok(pair) => pair,
                            Err(error) => {
                                let _ = tx
                                    .send(Ok(format!(
                                        ":ERROR: 0 {}\n",
                                        python_repr(&error.to_string())
                                    )
                                    .into_bytes()))
                                    .await;
                                return;
                            }
                        };
                        let request = AsyncRequest {
                            method: update.method,
                            path: format!("/{device}/{partition}{}", unquote(&update.path)),
                            query_string: String::new(),
                            headers,
                            body,
                        };
                        let mut child_server = server.clone_execution_context();
                        child_server.replication_session_lock =
                            Some(std::sync::Arc::clone(&replication_lock));
                        let scope = TaskScope::bounded(1);
                        update_task = match scope
                            .spawn(async move { child_server.put_streaming_async(request).await })
                        {
                            Ok(task) => Some(task),
                            Err(error) => {
                                let _ = tx
                                    .send(Ok(format!(
                                        ":ERROR: 0 {}\n",
                                        python_repr(&error.to_string())
                                    )
                                    .into_bytes()))
                                    .await;
                                return;
                            }
                        };
                        update_scope = Some(scope);
                        update_tx = Some(body_tx);
                    }
                    SsyncEvent::UpdateChunk(bytes) => {
                        // An early HTTP rejection may close its receiver. Continue
                        // draining the bounded wire body and count that response at
                        // UpdateEnd; never retain the rest of a rejected object.
                        if let Some(sender) = update_tx.as_mut() {
                            if sender.send(Ok(bytes)).await.is_err() {
                                update_tx = None;
                            }
                        }
                    }
                    SsyncEvent::UpdateEnd => {
                        drop(update_tx.take());
                        let Some(task) = update_task.take() else {
                            let _ = tx
                                .send(Ok(b":ERROR: 0 'missing SSYNC update task'\n".to_vec()))
                                .await;
                            return;
                        };
                        match task.join().await {
                            Ok(response)
                                if (200..300).contains(&response.status)
                                    || response.status == 404 =>
                            {
                                successes += 1
                            }
                            _ => failures += 1,
                        }
                        if let Some(scope) = update_scope.take() {
                            if scope.join().await.is_err() {
                                failures += 1;
                            }
                        }
                        if failures >= REPLICATION_FAILURE_THRESHOLD
                            && (successes == 0
                                || failures as f64 / successes as f64 > REPLICATION_FAILURE_RATIO)
                        {
                            let message =
                                format!("Too many {failures} failures to {successes} successes");
                            let _ = tx
                                .send(Ok(
                                    format!(":ERROR: 0 {}\n", python_repr(&message)).into_bytes()
                                ))
                                .await;
                            return;
                        }
                    }
                    SsyncEvent::Update(update) => {
                        let child_server = server.clone_execution_context();
                        let device = device.clone();
                        let partition = partition.clone();
                        let replication_lock = std::sync::Arc::clone(&replication_lock);
                        let result = storage
                            .run_finite(device_id.clone(), TrafficClass::Replication, move || {
                                let _replication_lock = replication_lock;
                                child_server.apply_ssync_update(
                                    &device,
                                    &partition,
                                    policy_index,
                                    frag_index,
                                    update,
                                )
                            })
                            .await;
                        match result {
                            Ok(response)
                                if (200..300).contains(&response.status)
                                    || response.status == 404 =>
                            {
                                successes += 1;
                            }
                            Ok(_) | Err(_) => failures += 1,
                        }
                        if failures >= REPLICATION_FAILURE_THRESHOLD
                            && (successes == 0
                                || failures as f64 / successes as f64 > REPLICATION_FAILURE_RATIO)
                        {
                            let message =
                                format!("Too many {failures} failures to {successes} successes");
                            let _ = tx
                                .send(Ok(
                                    format!(":ERROR: 0 {}\n", python_repr(&message)).into_bytes()
                                ))
                                .await;
                            return;
                        }
                    }
                    SsyncEvent::UpdatesEnd => updates_done = true,
                    _ => {}
                }
            }
            if let Some(message) = parser.failure().map(|error| error.message().to_string()) {
                let _ = tx
                    .send(Ok(
                        format!(":ERROR: 0 {}\n", python_repr(&message)).into_bytes()
                    ))
                    .await;
                return;
            }
            if updates_done {
                break;
            }
            events = match input.next_events(&mut parser).await {
                Ok(Some(events)) => events,
                Ok(None) => {
                    let _ = tx
                        .send(Ok(
                            b":ERROR: 0 'Unexpected EOF before :UPDATES: END'\n".to_vec()
                        ))
                        .await;
                    return;
                }
                Err(error) => {
                    let _ = tx
                        .send(Ok(format!(
                            ":ERROR: 0 {}\n",
                            python_repr(&format!(
                                "Request body failed before :UPDATES: END: {error}"
                            ))
                        )
                        .into_bytes()))
                        .await;
                    return;
                }
            };
        }
        if failures != 0 {
            let body =
                format!("ERROR: With :UPDATES: {failures} failures to {successes} successes");
            let _ = tx
                .send(Ok(
                    format!(":ERROR: 500 b{}\n", python_repr(&body)).into_bytes()
                ))
                .await;
            return;
        }
        let _ = tx
            .send(Ok(b":UPDATES: START\r\n:UPDATES: END\r\n".to_vec()))
            .await;
    }
    .await;
    // EOF/error must close and join the partial PUT before releasing the
    // session lease. A cancelled channel cannot leave an unobserved child
    // holding the next session's replication lock.
    drop(update_tx.take());
    if let Some(task) = update_task.take() {
        let _ = task.join().await;
    }
    if let Some(scope) = update_scope.take() {
        let _ = scope.join().await;
    }
}

/// How the object server applies the container-listing side channel after a
/// durable object PUT/DELETE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContainerUpdateMode {
    /// Contact container replicas in parallel under `container_update_timeout`;
    /// fall back to `async_pending` on any miss (L1a / Python default).
    #[default]
    Sync,
    /// Always enqueue `async_pending` and return; the object-updater drains
    /// the listing update off the write path (L1b).
    Async,
}

#[derive(Clone)]
pub struct ObjectServerConfig {
    pub devices: PathBuf,
    pub mount_check: bool,
    pub hash_config: HashPathConfig,
    pub diskfile: DiskFileConfig,
    /// Every configured storage-policy index and its diskfile kind. Keeping the
    /// complete registry lets request handling distinguish a replication policy
    /// from an unknown index instead of treating every map miss as replication.
    pub policies: std::collections::HashMap<u32, PolicyKind>,
    /// Per-replica budget for the synchronous container update on the object
    /// PUT/DELETE path (Python `container_update_timeout`, default 1.0s).
    /// Replicas are contacted in parallel; any that miss this budget fall
    /// through to `async_pending`.
    pub container_update_timeout: std::time::Duration,
    /// `sync` (default) or `async` — see [`ContainerUpdateMode`].
    pub container_update_mode: ContainerUpdateMode,
}

pub struct ObjectServer {
    pub config: ObjectServerConfig,
    /// Directory containing Python-compatible `object.recon` daemon output.
    /// The default matches Swift's recon middleware; the server binary
    /// overrides it from `recon_cache_path`.
    pub recon_cache_path: PathBuf,
    /// `fallocate_reserve`: the free-space floor a PUT may not take the
    /// device below. Python enforces it inside `fallocate()`
    /// (`swift/common/utils`), surfacing as DiskFileNoSpace -> 507; the
    /// config default is `1%`.
    pub fallocate_reserve: FallocateReserve,
    /// WORM clock-health source for the native lock gate
    /// (`worm_clock_max_offset_ms`). Default disabled: the gate sees
    /// `clock_ok=true` exactly as before. Enabled (>0) it is fail-closed —
    /// see [`swift_http::clock_health`].
    pub worm_clock: std::sync::Arc<ClockHealth>,
    storage: std::sync::OnceLock<StorageExecutor>,
    /// Invoked on the storage thread immediately before durability commit
    /// (xattr/fsync/rename). Production is `None`. Tests use it to occupy
    /// the executor during finalize without a dummy `run_finite`.
    commit_stall: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    /// Streaming SSYNC commit jobs keep the partition lease alive even if
    /// the response future is cancelled during a protected durable commit.
    replication_session_lock: Option<std::sync::Arc<swift_core::lockutil::PathLock>>,
}

struct PendingDurable {
    durable: swift_diskfile::DurablePut,
    metadata: Metadata,
    completion: PutCompletion,
}

struct PutCompletion {
    drive: String,
    part: u64,
    etag: String,
    upload_size: u64,
    content_type: String,
    req_timestamp: Timestamp,
    footers: Vec<(String, String)>,
    resolved_delete_at: Option<String>,
    account: String,
    container: String,
    obj: String,
    policy_index: u32,
    policy: PolicyKind,
    headers: HeaderKeyDict,
    path: String,
}

fn meta_get<'m>(meta: &'m Metadata, key: &str) -> Option<&'m str> {
    meta.iter()
        .find(|(k, _)| matches!(k, MetaValue::Str(s) if s.eq_ignore_ascii_case(key)))
        .and_then(|(_, v)| v.as_str())
}

/// Parse Python's `X-Backend-Fragment-Preferences` JSON while preserving the
/// semantically important empty list: `[]` means a non-durable EC fragment is
/// acceptable, whereas an absent header requires the durable set.
fn parse_fragment_preferences(
    headers: &HeaderKeyDict,
    policy: PolicyKind,
) -> Result<Option<Vec<FragPref>>, Response> {
    let Some(raw) = headers.get("X-Backend-Fragment-Preferences") else {
        return Ok(None);
    };
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| plain_response(500, "Bad fragment preferences"))?;
    let items = value
        .as_array()
        .ok_or_else(|| plain_response(500, "Bad fragment preferences"))?;
    let max_frag = match policy {
        PolicyKind::Ec { n_unique_fragments } => n_unique_fragments.map(i64::from),
        PolicyKind::Replication => None,
    };
    let mut prefs = Vec::with_capacity(items.len());
    for item in items {
        let object = item
            .as_object()
            .ok_or_else(|| plain_response(500, "Bad fragment preferences"))?;
        let timestamp = object
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<Timestamp>().ok())
            .ok_or_else(|| plain_response(500, "Bad fragment preferences"))?;
        let exclude_values = object
            .get("exclude")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| plain_response(500, "Bad fragment preferences"))?;
        let mut exclude = Vec::with_capacity(exclude_values.len());
        for value in exclude_values {
            let frag = value
                .as_i64()
                .ok_or_else(|| plain_response(500, "Bad fragment preferences"))?;
            if frag < 0 || max_frag.is_some_and(|limit| frag >= limit) {
                return Err(plain_response(500, "Bad fragment preferences"));
            }
            exclude.push(frag);
        }
        prefs.push(FragPref { timestamp, exclude });
    }
    Ok(Some(prefs))
}

/// Stored object ETag used by GET/HEAD and PUT `If-Match`.
fn object_etag(meta: &Metadata) -> &str {
    meta_get(meta, "ETag").unwrap_or("")
}

/// Python `dict.update` semantics on the ordered metadata pairs: replace the
/// value in place when the key already exists (matched case-insensitively,
/// as [`meta_get`] does), else append.
fn meta_upsert(meta: &mut Metadata, key: &str, value: String) {
    match meta
        .iter_mut()
        .find(|(k, _)| matches!(k, MetaValue::Str(s) if s.eq_ignore_ascii_case(key)))
    {
        Some(slot) => slot.1 = MetaValue::Str(value),
        None => meta.push((MetaValue::Str(key.to_string()), MetaValue::Str(value))),
    }
}

/// Simplified `swift.common.utils.extract_swift_bytes`, sufficient for the
/// unquoted parameter tokens Swift itself writes (`;swift_bytes=N`): return
/// the content-type minus any `swift_bytes` param, plus that param's value.
fn extract_swift_bytes(content_type: &str) -> (String, Option<String>) {
    match content_type.split_once(';') {
        None => (content_type.to_string(), None),
        Some((ct, params)) => {
            let mut out = ct.to_string();
            let mut swift_bytes = None;
            for param in params.split(';') {
                let (k, v) = param.split_once('=').unwrap_or((param, ""));
                let (k, v) = (k.trim(), v.trim());
                if k == "swift_bytes" {
                    swift_bytes = Some(v.to_string());
                } else if !k.is_empty() {
                    out.push_str(&format!(";{k}={v}"));
                }
            }
            (out, swift_bytes)
        }
    }
}

fn swob_response(status: u16) -> Response {
    let explanation = match status {
        404 => "The resource could not be found.",
        409 => "There was a conflict when trying to complete your request.",
        422 => "Unable to process the contained instructions",
        503 => "The server is currently unavailable. Please try again at a later time.",
        507 => "There was not enough space to save the resource. Drive: ",
        _ => "",
    };
    let mut resp = if explanation.is_empty() {
        Response::new(status)
    } else {
        Response::with_body(
            status,
            format!(
                "<html><h1>{}</h1><p>{explanation}</p></html>",
                Response::new(status).reason
            ),
        )
    };
    resp.headers.set("Content-Type", "text/html; charset=UTF-8");
    resp
}

fn plain_response(status: u16, body: &str) -> Response {
    let mut resp = Response::with_body(status, body.as_bytes().to_vec());
    resp.headers.set("Content-Type", "text/plain");
    resp
}

/// Map a MIME-stream read error to the response Python's exception
/// translation produces: decoder over-cap -> 413, malformed multipart ->
/// 400, disconnect/timeout -> 499.
fn mime_read_error(e: &std::io::Error) -> Response {
    if swift_http::body_too_large(e) {
        plain_response(413, "Your request is too large.")
    } else if e.kind() == std::io::ErrorKind::InvalidData {
        plain_response(400, &e.to_string())
    } else {
        swob_response(499)
    }
}

/// Parse the metadata-footer document (server.py `_read_metadata_footer` +
/// `_parse_footer`): headers must carry `Content-MD5` over the JSON body.
fn read_footer_metadata(docs: &mut MimeDocs) -> Result<Vec<(String, String)>, Response> {
    let headers = match docs.next_document() {
        Ok(Some(h)) => h,
        Ok(None) => return Err(plain_response(400, "couldn't find footer MIME doc")),
        Err(e) => return Err(mime_read_error(&e)),
    };
    let Some(expected_md5) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-MD5"))
        .map(|(_, v)| v.clone())
    else {
        return Err(plain_response(400, "no Content-MD5 in footer"));
    };
    let mut body = Vec::new();
    if let Err(e) = std::io::Read::take(&mut *docs, 1024 * 1024).read_to_end(&mut body) {
        return Err(mime_read_error(&e));
    }
    let computed = {
        use md5::{Digest, Md5};
        format!("{:x}", Md5::digest(&body))
    };
    if computed != expected_md5 {
        return Err(plain_response(422, "footer MD5 mismatch"));
    }
    let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(&body)
    else {
        return Err(plain_response(400, "invalid JSON for footer doc"));
    };
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let value = match v {
            serde_json::Value::String(s) => s,
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => return Err(plain_response(400, "invalid JSON for footer doc")),
        };
        out.push((k, value));
    }
    Ok(out)
}

/// `_check_container_override` (server.py:606-645): rewrite container
/// update headers from `*-container-update-override-*` request headers
/// and footers. Prefix order is significant (sysmeta overrides backend);
/// within each prefix, footers override headers.
fn apply_container_override(
    update: &mut HeaderKeyDict,
    headers: &HeaderKeyDict,
    footers: &[(String, String)],
) {
    for prefix in [
        "x-backend-container-update-override-",
        "x-object-sysmeta-container-update-override-",
    ] {
        for (k, v) in headers.iter() {
            let kl = k.to_ascii_lowercase();
            if let Some(rest) = kl.strip_prefix(prefix) {
                update.set(&format!("x-{rest}"), v);
            }
        }
        for (k, v) in footers {
            let kl = k.to_ascii_lowercase();
            if let Some(rest) = kl.strip_prefix(prefix) {
                update.set(&format!("x-{rest}"), v);
            }
        }
    }
}

fn is_sys_or_user_meta(key: &str) -> bool {
    let l = key.to_ascii_lowercase();
    (l.starts_with("x-object-meta-") && l.len() > "x-object-meta-".len())
        || (l.starts_with("x-object-sysmeta-") && l.len() > "x-object-sysmeta-".len())
}

fn is_object_transient_sysmeta(key: &str) -> bool {
    let l = key.to_ascii_lowercase();
    l.starts_with("x-object-transient-sysmeta-") && l.len() > "x-object-transient-sysmeta-".len()
}

/// Swift's default object-server `allowed_headers` (plus the always-persisted
/// large-object headers): non-meta request headers the object server stores
/// with the object and echoes on GET/HEAD — notably `X-Object-Manifest` (DLO)
/// and `X-Static-Large-Object` (SLO), without which manifest reassembly can
/// never trigger.
fn is_allowed_header(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "x-object-manifest"
            | "x-static-large-object"
            | "content-disposition"
            | "content-encoding"
            | "content-language"
            | "cache-control"
            | "expires"
            | "x-robots-tag"
            | "x-delete-at"
    )
}

fn is_replication_header(req: &Request, key: &str) -> bool {
    req.headers
        .get("X-Backend-Replication-Headers")
        .is_some_and(|headers| {
            headers
                .split_ascii_whitespace()
                .any(|header| header.eq_ignore_ascii_case(key))
        })
}

fn should_persist_header(req: &Request, key: &str) -> bool {
    is_sys_or_user_meta(key)
        || is_object_transient_sysmeta(key)
        || is_allowed_header(key)
        || is_replication_header(req, key)
}

#[derive(Debug, Default)]
struct LocalSsyncTimestamps {
    data: Option<Timestamp>,
    meta: Option<Timestamp>,
    ctype: Option<Timestamp>,
}

/// True if a header value parses the way Python's `int()` accepts a base-10
/// integer: optional surrounding whitespace, an optional sign, then one or
/// more ASCII digits. Used to reproduce the `Non-integer X-Delete-*`
/// distinction (`'*'` is rejected, `'1' * 100` is accepted even though it
/// overflows i64).
fn parse_int_like(s: &str) -> Option<f64> {
    let t = s.trim();
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // f64 has ample range for any realistic X-Delete-At; overflow past f64 is
    // clamped by normalize_delete_at_timestamp anyway.
    t.parse::<f64>().ok()
}

/// Whether an `If-None-Match` header value carries the `*` wildcard token.
fn if_none_match_has_star(value: &str) -> bool {
    value.split(',').any(|tok| tok.trim() == "*")
}

/// Port of `swift.common.constraints.check_delete_headers`: validate the
/// `X-Delete-After` / `X-Delete-At` headers against the request timestamp
/// `now` (float seconds) and return the resolved, normalized `X-Delete-At`
/// string (or `None` when neither header is present). `X-Delete-After` takes
/// precedence and is converted to an `X-Delete-At`. On any invalid value the
/// error carries the exact 400 response Python would emit.
fn check_delete_headers(req: &Request, now: f64) -> Result<Option<String>, Response> {
    // X-Delete-After is converted into an X-Delete-At and takes precedence.
    let raw_delete_at: Option<String> = if let Some(raw) = req.headers.get("X-Delete-After") {
        let Some(after) = parse_int_like(raw) else {
            return Err(plain_response(400, "Non-integer X-Delete-After"));
        };
        let actual = normalize_delete_at_timestamp(now + after, false);
        if actual.parse::<i64>().unwrap_or(0) as f64 <= now {
            return Err(plain_response(400, "X-Delete-After in past"));
        }
        Some(actual)
    } else {
        req.headers.get("X-Delete-At").map(str::to_string)
    };

    let Some(raw) = raw_delete_at else {
        return Ok(None);
    };

    let Some(value) = parse_int_like(&raw) else {
        return Err(plain_response(400, "Non-integer X-Delete-At"));
    };
    let normalized = normalize_delete_at_timestamp(value, false);
    let x_delete_at = normalized.parse::<i64>().unwrap_or(0);
    let backend_replication = req
        .headers
        .get("X-Backend-Replication")
        .is_some_and(config_true_value);
    if (x_delete_at as f64) <= now && !backend_replication {
        return Err(plain_response(400, "X-Delete-At in past"));
    }
    Ok(Some(normalized))
}

/// Copy on-disk object metadata into request-style headers for the native
/// lock gate. Only string pairs are needed (lock sysmeta is stored as text).
fn metadata_as_headers(meta: &Metadata) -> HeaderKeyDict {
    let mut headers = HeaderKeyDict::new();
    for (k, v) in meta {
        if let (Some(key), Some(value)) = (k.as_str(), v.as_str()) {
            headers.set(key, value);
        }
    }
    headers
}

/// Experimental native lock gate on PUT/POST/DELETE of an existing object.
/// Not live-proven, not deployed, not a compliance claim.
///
/// Missing object → allow (PUT create). Replicate/ssync
/// (`X-Backend-Replication`) skip this gate. Lock-sysmeta-only POST is not
/// a data overwrite and is not denied. Malformed lock headers deny
/// inside [`native_mutation_allowed`]. A live object whose metadata cannot
/// be read fails closed (500) instead of treating the object as unlocked.
///
/// `clock_ok` comes from the server's [`ClockHealth`] source
/// (`worm_clock_max_offset_ms`); with the knob at its default 0 it is
/// constant `true`, the historical behavior.
fn deny_locked_native_mutation(
    req: &Request,
    existing: Option<Result<&Metadata, DiskFileError>>,
    clock_ok: bool,
) -> Option<Response> {
    if req
        .headers
        .get("X-Backend-Replication")
        .is_some_and(config_true_value)
    {
        return None;
    }
    let meta = match existing {
        None => return None,
        Some(Ok(meta)) => meta,
        Some(Err(e)) => return Some(plain_response(500, &e.to_string())),
    };
    let headers = metadata_as_headers(meta);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if native_mutation_allowed_for(
        &req.method,
        &headers,
        Some(&req.headers),
        now_unix,
        clock_ok,
        NativeGovernanceBypass::NONE,
    ) {
        None
    } else {
        Some(plain_response(403, "object is locked"))
    }
}

/// PUT `If-Match` against the current object ETag (same value GET emits).
/// Missing object or mismatch → 412. Header absent → no precondition.
fn put_if_match_precondition(
    req: &Request,
    orig_exists: bool,
    orig_metadata: Option<&Metadata>,
) -> Option<Response> {
    let Some(if_match) = req.headers.get("If-Match") else {
        return None;
    };
    if !orig_exists {
        return Some(swob_response(412));
    }
    let etag = orig_metadata.map(object_etag).unwrap_or("");
    if Match::parse(if_match).matches(etag) {
        None
    } else {
        Some(swob_response(412))
    }
}

/// Internal ABA guard used by the S3 versioning layer.  An ETag alone is not
/// a generation identifier: two different versions may legitimately contain
/// identical bytes.  When the proxy names the version it observed, the object
/// server verifies that sysmeta under the same mutation lock as the write.
fn expected_s3_version_precondition(
    req: &Request,
    orig_exists: bool,
    orig_metadata: Option<&Metadata>,
) -> Option<Response> {
    let Some(expected) = req.headers.get(EXPECTED_S3_VERSION_ID_HEADER) else {
        return None;
    };
    let actual = orig_metadata.and_then(|metadata| meta_get(metadata, S3_VERSION_ID_SYSMETA));
    if orig_exists && actual == Some(expected) {
        None
    } else {
        Some(swob_response(412))
    }
}

/// Shared PUT pre-body checks (If-None-Match, X-Delete-*, timestamp, lock).
fn evaluate_put_preconditions(
    req: &Request,
    req_timestamp: &Timestamp,
    orig_exists: bool,
    orig_timestamp: Timestamp,
    orig_metadata: Option<&Metadata>,
    clock_ok: bool,
) -> Result<Option<String>, Response> {
    if let Some(inm) = req.headers.get("If-None-Match") {
        if !if_none_match_has_star(inm) {
            return Err(plain_response(400, "If-None-Match only supports *"));
        }
    }
    let resolved_delete_at = check_delete_headers(req, req_timestamp.as_secs_f64())?;
    if orig_exists && req.headers.get("If-None-Match").is_some() {
        return Err(swob_response(412));
    }
    if orig_timestamp >= *req_timestamp {
        let mut resp = swob_response(409);
        resp.headers
            .set("X-Backend-Timestamp", orig_timestamp.internal());
        return Err(resp);
    }
    if let Some(resp) = put_if_match_precondition(req, orig_exists, orig_metadata) {
        return Err(resp);
    }
    if let Some(resp) = expected_s3_version_precondition(req, orig_exists, orig_metadata) {
        return Err(resp);
    }
    if orig_exists || orig_metadata.is_some() {
        if let Some(resp) = deny_locked_native_mutation(
            req,
            orig_metadata.map(|meta| Ok::<_, DiskFileError>(meta)),
            clock_ok,
        ) {
            return Err(resp);
        }
    }
    Ok(resolved_delete_at)
}

fn open_put_original(
    df: DiskFile,
    ssync_frag_index: Option<i64>,
) -> Result<(bool, Timestamp, Option<Metadata>), Response> {
    let mut pre = df.with_frag_index(ssync_frag_index);
    match pre.open(None) {
        Ok(opened) => {
            let ts = opened
                .data_timestamp()
                .unwrap_or_else(|_| "0".parse().unwrap());
            match opened.get_metadata() {
                Ok(meta) => Ok((true, ts, Some(meta.clone()))),
                Err(e) => Err(plain_response(500, &e.to_string())),
            }
        }
        Err(DiskFileError::Deleted { timestamp, .. }) => Ok((false, timestamp, None)),
        Err(DiskFileError::Expired { metadata }) => {
            let ts = meta_get(&metadata, "X-Timestamp")
                .and_then(|s| s.parse::<Timestamp>().ok())
                .unwrap_or_else(|| "0".parse().unwrap());
            Ok((false, ts, Some(metadata)))
        }
        Err(DiskFileError::NotExist) | Err(DiskFileError::Quarantined(_)) => {
            Ok((false, "0".parse().unwrap(), None))
        }
        Err(e) => Err(plain_response(500, &e.to_string())),
    }
}

fn mutation_lock_error_response(error: DiskFileError) -> Response {
    match error {
        DiskFileError::LockTimeout(_) => swob_response(503),
        DiskFileError::NoSpace | DiskFileError::XattrNotSupported => swob_response(507),
        other => plain_response(500, &other.to_string()),
    }
}

/// Acquire the object's fixed mutation stripe, then re-open and re-evaluate
/// every PUT condition while that stripe is held.  Returning the guard makes
/// the lock lifetime explicit at each durability barrier.
fn acquire_checked_put_guard(
    df: DiskFile,
    req: &Request,
    req_timestamp: &Timestamp,
    ssync_frag_index: Option<i64>,
    clock_ok: bool,
) -> Result<swift_core::lockutil::PathLock, Response> {
    let guard = df
        .acquire_mutation_lock(OBJECT_MUTATION_LOCK_TIMEOUT)
        .map_err(mutation_lock_error_response)?;
    let (exists, orig_ts, orig_meta) = open_put_original(df, ssync_frag_index)?;
    evaluate_put_preconditions(
        req,
        req_timestamp,
        exists,
        orig_ts,
        orig_meta.as_ref(),
        clock_ok,
    )?;
    Ok(guard)
}

/// Reacquire the stripe for an EC multiphase durable transition. The first
/// phase already published this request's nondurable fragment, so equality
/// with the request timestamp is expected and the original If-* generation
/// guard must not be applied a second time. A strictly newer on-disk
/// generation still wins and prevents a late commit from reviving stale data.
fn acquire_ec_commit_guard(
    df: DiskFile,
    req_timestamp: &Timestamp,
    ssync_frag_index: Option<i64>,
) -> Result<swift_core::lockutil::PathLock, Response> {
    let guard = df
        .acquire_mutation_lock(OBJECT_MUTATION_LOCK_TIMEOUT)
        .map_err(mutation_lock_error_response)?;
    let (_, current_timestamp, _) = open_put_original(df, ssync_frag_index)?;
    if current_timestamp > *req_timestamp {
        let mut response = swob_response(409);
        response
            .headers
            .set("X-Backend-Timestamp", current_timestamp.internal());
        return Err(response);
    }
    Ok(guard)
}

/// Python `fallocate()`'s FALLOCATE_RESERVE check, absolute-bytes mode: would
/// writing `size` bytes leave the device's filesystem with `free` bytes
/// available at or below the reserve? Zero-length writes never trip the
/// reserve (Python skips the check when `size` is falsy) and a non-positive
/// reserve disables it. Percent reserves compare against the device's TOTAL
/// capacity, which the shared `fsutil` contract does not expose, so percent
/// mode is not enforced here yet.
fn fallocate_reserve_breached(free: u64, size: u64, reserve: &FallocateReserve) -> bool {
    if size == 0 {
        return false;
    }
    match reserve {
        FallocateReserve::Bytes(reserve) if *reserve > 0 => {
            (free as i128) - (size as i128) <= (*reserve as i128)
        }
        _ => false,
    }
}

/// The proxy stamps the object ring's pending partition power on every
/// backend object request.  DiskFile consumes it only for mutations, where
/// Python Swift keeps the current and next layouts linked to the same inode.
fn backend_next_part_power(req: &Request) -> Option<u32> {
    req.headers
        .get("X-Backend-Next-Part-Power")
        .and_then(|raw| raw.trim().parse().ok())
}

impl ObjectServer {
    /// An internal request keeps the parent's operational settings and
    /// execution domain. Constructing it with `new(config)` would silently
    /// reset reserve, clock-health and commit hooks.
    fn clone_execution_context(&self) -> Self {
        ObjectServer {
            config: self.config.clone(),
            recon_cache_path: self.recon_cache_path.clone(),
            fallocate_reserve: self.fallocate_reserve,
            worm_clock: self.worm_clock.clone(),
            storage: std::sync::OnceLock::from(self.storage().clone()),
            commit_stall: self.commit_stall.clone(),
            replication_session_lock: self.replication_session_lock.clone(),
        }
    }

    pub fn new(config: ObjectServerConfig) -> Self {
        ObjectServer {
            config,
            recon_cache_path: PathBuf::from("/var/cache/swift"),
            // swift.common.utils: fallocate_reserve defaults to "1%".
            fallocate_reserve: FallocateReserve::Percent(1.0),
            worm_clock: std::sync::Arc::new(ClockHealth::disabled()),
            storage: std::sync::OnceLock::new(),
            commit_stall: None,
            replication_session_lock: None,
        }
    }

    /// Builder-style override for the `fallocate_reserve` parsed by
    /// `swift_core::config::config_fallocate_value`.
    pub fn with_fallocate_reserve(mut self, reserve: FallocateReserve) -> Self {
        self.fallocate_reserve = reserve;
        self
    }

    pub fn with_recon_cache_path(mut self, path: PathBuf) -> Self {
        self.recon_cache_path = path;
        self
    }

    /// Wire a WORM clock-health source for the native lock gate
    /// (default: disabled, `clock_ok=true`).
    pub fn with_worm_clock(mut self, clock: std::sync::Arc<ClockHealth>) -> Self {
        self.worm_clock = clock;
        self
    }

    /// Inject the storage executor (tests: `thread_cap = 1` so a stalled
    /// commit occupies the only blocking worker).
    pub fn with_storage(self, exec: StorageExecutor) -> Self {
        let _ = self.storage.set(exec);
        self
    }

    /// `f` runs on the storage thread inside the PUT commit `run_finite`.
    pub fn with_commit_stall(mut self, f: std::sync::Arc<dyn Fn() + Send + Sync>) -> Self {
        self.commit_stall = Some(f);
        self
    }

    pub fn storage(&self) -> &StorageExecutor {
        self.storage.get_or_init(|| {
            StorageExecutor::new(
                StorageExecutorConfig::new(8, 32, DeviceIoLimits::new(32, 32, 32, 32, 32))
                    .expect("storage executor config"),
            )
            .expect("storage executor")
        })
    }

    /// Phase 3/4 entry: body wait is already a Future on [`IncomingBody`].
    /// Replication PUT finalize runs on [`StorageExecutor`], not this task.
    pub async fn handle_async(&self, mut areq: AsyncRequest) -> Response {
        if let Some(m) = ConcurrencyMetrics::current() {
            m.attach_storage(self.storage().clone());
        }
        if areq.path == "/recon/updater/object" && matches!(areq.method.as_str(), "GET" | "HEAD") {
            let req = Request {
                method: areq.method,
                path: areq.path,
                query_string: areq.query_string,
                headers: areq.headers,
                body: Body::empty(),
            };
            return self
                .recon_response(&req)
                .expect("matched updater recon route");
        }
        if areq.method == "PUT" {
            return self.put_streaming_async(areq).await;
        }
        if matches!(areq.method.as_str(), "GET" | "HEAD") {
            let include_body = areq.method == "GET";
            let req = Request {
                method: areq.method,
                path: areq.path,
                query_string: areq.query_string,
                headers: areq.headers,
                body: Body::empty(),
            };
            return self.get_streaming_async(req, include_body).await;
        }
        if areq.method == "DELETE" {
            return self.delete_async(areq).await;
        }
        if areq.method == "SSYNC" {
            return self.ssync_async(areq).await;
        }
        let max = areq.body.max_body_bytes();
        let body = match areq.body.materialize(max).await {
            Ok(bytes) => Body::Buffered(bytes),
            Err(error) => return async_body_read_error(&error),
        };
        let req = Request {
            method: areq.method,
            path: areq.path,
            query_string: areq.query_string,
            headers: areq.headers,
            body,
        };
        if req.method == "OPTIONS" {
            let mut resp = Response::new(200);
            resp.headers.set(
                "Allow",
                "DELETE, GET, HEAD, OPTIONS, POST, PUT, REPLICATE, SSYNC",
            );
            resp.headers
                .setdefault("Content-Type", "text/html; charset=UTF-8");
            return resp;
        }
        // POST/REPLICATE run on StorageExecutor. DELETE is `delete_async`
        // (disk on storage, container-update on the network runtime).
        // SSYNC never reaches here.
        self.dispatch_fs_on_storage(req).await
    }

    /// Disk tombstone on the storage executor, then container-update on Tokio
    /// so a sharded DELETE can follow 301 / ring-lookup the shard (probe L692).
    async fn delete_async(&self, areq: AsyncRequest) -> Response {
        let req = Request {
            method: areq.method,
            path: areq.path,
            query_string: areq.query_string,
            headers: areq.headers,
            body: Body::empty(),
        };
        let (drive, part, account, container, obj, policy_index, policy) = match self.obj_path(&req)
        {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let req_timestamp = match Self::valid_timestamp(&req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        let replication = req
            .headers
            .get("X-Backend-Replication")
            .is_some_and(config_true_value);
        let container_host = req
            .headers
            .get("X-Container-Host")
            .unwrap_or("")
            .to_string();
        let container_device = req
            .headers
            .get("X-Container-Device")
            .unwrap_or("")
            .to_string();
        let container_partition = req
            .headers
            .get("X-Container-Partition")
            .unwrap_or("")
            .to_string();
        let backend_container_path =
            shard_update_account_container(&req.headers).map(|(a, c)| format!("{a}/{c}"));
        let db_state = req
            .headers
            .get("X-Container-Root-Db-State")
            .map(str::to_string);
        let exec = self.storage().clone();
        let config = self.config.clone();
        let recon_cache_path = self.recon_cache_path.clone();
        let fallocate_reserve = self.fallocate_reserve;
        let worm_clock = std::sync::Arc::clone(&self.worm_clock);
        let req_for_disk = Request {
            method: req.method.clone(),
            path: req.path.clone(),
            query_string: req.query_string.clone(),
            headers: req.headers.clone(),
            body: Body::empty(),
        };
        // Clone path parts the storage closure owns so container-update can
        // still borrow them after `.await` (probe L692).
        let drive_disk = drive.clone();
        let account_disk = account.clone();
        let container_disk = container.clone();
        let obj_disk = obj.clone();
        let disk = exec
            .run_finite(
                DeviceId::new(drive.clone()),
                TrafficClass::Foreground,
                move || {
                    ObjectServer {
                        config,
                        recon_cache_path,
                        fallocate_reserve,
                        worm_clock,
                        storage: std::sync::OnceLock::new(),
                        commit_stall: None,
                        replication_session_lock: None,
                    }
                    .delete_apply_tombstone(
                        &req_for_disk,
                        &drive_disk,
                        part,
                        &account_disk,
                        &container_disk,
                        &obj_disk,
                        policy_index,
                        policy,
                    )
                },
            )
            .await;
        let (resp, do_cu) = match disk {
            Ok(pair) => pair,
            Err(e) => return plain_response(500, &e.to_string()),
        };
        if do_cu {
            let mut update = HeaderKeyDict::new();
            update.set("x-timestamp", req_timestamp.internal());
            self.container_update_async(
                "DELETE",
                &drive,
                &account,
                &container,
                &obj,
                replication,
                container_host,
                container_device,
                container_partition,
                backend_container_path,
                &update,
                policy_index,
                db_state,
            )
            .await;
        }
        resp
    }

    /// Disk work for POST/DELETE/REPLICATE: one finite storage job, not the
    /// Tokio/Hyper worker. Reconstructs a server so `handle()` does not
    /// borrow `self` across the executor. SSYNC is refused (use `ssync_async`).
    async fn dispatch_fs_on_storage(&self, req: Request) -> Response {
        if req.method == "SSYNC" {
            return plain_response(500, "SSYNC requires handle_async / ssync_async");
        }
        let drive = req
            .path
            .trim_start_matches('/')
            .split('/')
            .next()
            .unwrap_or("sda1")
            .to_string();
        let exec = self.storage().clone();
        let config = self.config.clone();
        let recon_cache_path = self.recon_cache_path.clone();
        let fallocate_reserve = self.fallocate_reserve;
        let worm_clock = std::sync::Arc::clone(&self.worm_clock);
        match exec
            .run_finite(DeviceId::new(drive), TrafficClass::Foreground, move || {
                ObjectServer {
                    config,
                    recon_cache_path,
                    fallocate_reserve,
                    worm_clock,
                    storage: std::sync::OnceLock::new(),
                    commit_stall: None,
                    replication_session_lock: None,
                }
                .handle(req)
            })
            .await
        {
            Ok(resp) => resp,
            Err(e) => plain_response(500, &e.to_string()),
        }
    }

    async fn put_streaming_async(&self, mut areq: AsyncRequest) -> Response {
        let traffic_class = if self.replication_session_lock.is_some() {
            TrafficClass::Replication
        } else {
            TrafficClass::Foreground
        };
        let req = Request {
            method: areq.method.clone(),
            path: areq.path.clone(),
            query_string: areq.query_string.clone(),
            headers: areq.headers.clone(),
            body: Body::empty(),
        };
        let (drive, part, account, container, obj, policy_index, policy) = match self.obj_path(&req)
        {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let req_timestamp = match Self::valid_timestamp(&req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive_async(&drive, traffic_class).await {
            return resp;
        }
        let Some(content_type) = req.headers.get("Content-Type").map(str::to_string) else {
            return plain_response(400, "No content type");
        };
        if req.headers.get("Content-Length").is_none()
            && !req
                .headers
                .get("Transfer-Encoding")
                .is_some_and(|te| te.eq_ignore_ascii_case("chunked"))
        {
            return plain_response(411, "Missing Content-Length header.");
        }
        let have_footer = req
            .headers
            .get("X-Backend-Obj-Metadata-Footer")
            .is_some_and(config_true_value);
        let multiphase = req
            .headers
            .get("X-Backend-Obj-Multiphase-Commit")
            .is_some_and(config_true_value);
        let mime = put_is_mime(&req.headers);
        let expect_continue = req.headers.get("Expect").is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("100-continue"))
        });
        if multiphase && !expect_continue {
            return plain_response(400, "multiphase PUT requires Expect: 100-continue");
        }
        let declared_len: Option<u64> = if mime {
            req.headers
                .get("X-Backend-Obj-Content-Length")
                .and_then(|s| s.trim().parse().ok())
        } else {
            req.headers
                .get("Content-Length")
                .and_then(|s| s.trim().parse().ok())
        };
        if declared_len.is_some_and(|len| len > MAX_FILE_SIZE as u64) {
            return plain_response(413, "Your request is too large.");
        }
        if let Some(inm) = req.headers.get("If-None-Match") {
            if !if_none_match_has_star(inm) {
                return plain_response(400, "If-None-Match only supports *");
            }
        }
        let device_path = self.config.devices.join(&drive);
        let free = match self
            .storage()
            .run_finite(DeviceId::new(drive.clone()), traffic_class, move || {
                swift_core::fsutil::free_bytes(&device_path)
            })
            .await
        {
            Ok(free) => free,
            Err(error) => return plain_response(500, &error.to_string()),
        };
        if let Ok(free) = free {
            if fallocate_reserve_breached(free, declared_len.unwrap_or(0), &self.fallocate_reserve)
            {
                return swob_response(507);
            }
        }
        let device = DeviceId::new(drive.clone());
        let pre_df = match self.diskfile_for(
            &drive,
            part,
            &account,
            &container,
            &obj,
            (policy_index, policy),
        ) {
            Ok(df) => df,
            Err(e) => return plain_response(500, &e.to_string()),
        };
        let ssync_frag_index: Option<i64> = req
            .headers
            .get("X-Backend-Ssync-Frag-Index")
            .and_then(|raw| raw.trim().parse().ok());
        let clock_ok = self.worm_clock.clock_ok();
        let headers_for_pre = req.headers.clone();
        let ts_for_pre = req_timestamp.clone();
        let resolved_delete_at = match self
            .storage()
            .run_finite(device.clone(), traffic_class, move || {
                let (exists, orig_ts, orig_meta) = open_put_original(pre_df, ssync_frag_index)?;
                let pre_req = Request {
                    method: "PUT".into(),
                    path: String::new(),
                    query_string: String::new(),
                    headers: headers_for_pre,
                    body: Body::empty(),
                };
                evaluate_put_preconditions(
                    &pre_req,
                    &ts_for_pre,
                    exists,
                    orig_ts,
                    orig_meta.as_ref(),
                    clock_ok,
                )
            })
            .await
        {
            Ok(Ok(v)) => v,
            Ok(Err(resp)) => return resp,
            Err(e) => return plain_response(500, &e.to_string()),
        };
        let df = match self.diskfile_for(
            &drive,
            part,
            &account,
            &container,
            &obj,
            (policy_index, policy),
        ) {
            Ok(df) => df.with_next_part_power(backend_next_part_power(&req)),
            Err(e) => return plain_response(500, &e.to_string()),
        };
        let writer = match self
            .storage()
            .run_finite(device.clone(), traffic_class, move || df.create(".data"))
            .await
        {
            Ok(Ok(w)) => w,
            Ok(Err(DiskFileError::NoSpace)) => return swob_response(507),
            Ok(Err(e)) => return plain_response(500, &e.to_string()),
            Err(e) => return plain_response(500, &e.to_string()),
        };
        let mut lease = WriterLease::new(
            self.storage().clone(),
            device.clone(),
            traffic_class,
            writer,
        );
        let mut footers: Vec<(String, String)> = Vec::new();
        let mut mime_boundary: Option<String> = None;
        if mime {
            let Some(boundary) = req
                .headers
                .get("X-Backend-Obj-Multipart-Mime-Boundary")
                .map(str::to_string)
            else {
                return plain_response(400, "no MIME boundary");
            };
            if expect_continue {
                let mut adverts: Vec<(&str, &str)> = Vec::new();
                if multiphase {
                    adverts.push(("X-Obj-Multiphase-Commit", "yes"));
                }
                if have_footer {
                    adverts.push(("X-Obj-Metadata-Footer", "yes"));
                }
                if areq.body.send_continue(&adverts).await.is_err() {
                    return swob_response(499);
                }
            }
            let leftover =
                match ingest_mime_object_async(&mut lease, &mut areq.body, boundary.as_bytes())
                    .await
                {
                    Ok(leftover) => leftover,
                    Err(resp) => return resp,
                };
            let trailing = if have_footer {
                match ingest_mime_footer_async(&mut areq.body, leftover, boundary.as_bytes()).await
                {
                    Ok((found, trailing)) => {
                        footers = found;
                        trailing
                    }
                    Err(resp) => return resp,
                }
            } else {
                leftover
            };
            if let Err(resp) = drain_mime_phase(&mut areq.body, trailing).await {
                return resp;
            }
            mime_boundary = Some(boundary);
        } else {
            loop {
                let chunk = match areq.body.next_chunk().await {
                    Ok(Some(c)) => c,
                    Ok(None) => break,
                    Err(error) => return async_body_read_error(&error),
                };
                if let Err(resp) = lease.write_chunk(chunk).await {
                    return resp;
                }
            }
        }
        let (upload_size, etag) = lease.writer().chunks_finished();
        if declared_len.is_some_and(|declared| declared != upload_size) {
            return swob_response(499);
        }
        let received_etag = footers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
            .map(|(_, v)| v.as_str())
            .or_else(|| req.headers.get("ETag"))
            .unwrap_or("");
        let normalized = received_etag.trim_matches('"');
        if !normalized.is_empty() && !normalized.eq_ignore_ascii_case(&etag) {
            return swob_response(422);
        }
        let mut metadata: Metadata = vec![
            (
                "X-Timestamp".into(),
                MetaValue::Str(req_timestamp.internal()),
            ),
            ("Content-Type".into(), MetaValue::Str(content_type.clone())),
            (
                "Content-Length".into(),
                MetaValue::Str(upload_size.to_string()),
            ),
            ("ETag".into(), MetaValue::Str(etag.clone())),
        ];
        for (k, v) in req.headers.iter() {
            let lower = k.to_ascii_lowercase();
            let is_core = matches!(
                lower.as_str(),
                "x-timestamp"
                    | "content-type"
                    | "content-length"
                    | "etag"
                    | "x-delete-at"
                    | "x-delete-after"
            );
            if should_persist_header(&req, k) && !is_core {
                metadata.push((MetaValue::Str(k.to_string()), MetaValue::Str(v.to_string())));
            }
        }
        for (k, v) in &footers {
            if is_sys_or_user_meta(k) || is_object_transient_sysmeta(k) {
                meta_upsert(&mut metadata, k, v.clone());
            }
        }
        if let Some(delete_at) = &resolved_delete_at {
            metadata.push((
                MetaValue::Str("X-Delete-At".into()),
                MetaValue::Str(delete_at.clone()),
            ));
        }
        let completion = PutCompletion {
            drive,
            part,
            etag,
            upload_size,
            content_type,
            req_timestamp,
            footers,
            resolved_delete_at,
            account,
            container,
            obj,
            policy_index,
            policy,
            headers: req.headers.clone(),
            path: req.path.clone(),
        };
        let mut writer = lease.take();
        let mut resp = if multiphase {
            let Some(boundary) = mime_boundary else {
                return plain_response(400, "multiphase commit requires a MIME body");
            };
            let pre_df = match self.diskfile_for(
                &completion.drive,
                completion.part,
                &completion.account,
                &completion.container,
                &completion.obj,
                (completion.policy_index, completion.policy),
            ) {
                Ok(df) => df.with_next_part_power(backend_next_part_power(&req)),
                Err(error) => return plain_response(500, &error.to_string()),
            };
            let pre_req = Request {
                method: "PUT".into(),
                path: completion.path.clone(),
                query_string: String::new(),
                headers: completion.headers.clone(),
                body: Body::empty(),
            };
            let pre_timestamp = completion.req_timestamp.clone();
            let ssync_frag_index = completion
                .headers
                .get("X-Backend-Ssync-Frag-Index")
                .and_then(|raw| raw.trim().parse().ok());
            let clock_ok = self.worm_clock.clock_ok();
            let replication_session_lock = self.replication_session_lock.clone();
            writer = match self
                .storage()
                .run_finite(device.clone(), traffic_class, move || {
                    let _replication_session_lock = replication_session_lock;
                    let _guard = acquire_checked_put_guard(
                        pre_df,
                        &pre_req,
                        &pre_timestamp,
                        ssync_frag_index,
                        clock_ok,
                    )?;
                    writer.put(metadata).map_err(mutation_lock_error_response)?;
                    Ok::<_, Response>(writer)
                })
                .await
            {
                Ok(Ok(writer)) => writer,
                Ok(Err(response)) => return response,
                Err(error) => return plain_response(500, &error.to_string()),
            };
            if areq.body.send_continue(&[]).await.is_err() {
                drop(WriterLease::new(
                    self.storage().clone(),
                    device.clone(),
                    traffic_class,
                    writer,
                ));
                return swob_response(499);
            }
            let commit_trailing =
                match ingest_mime_commit_async(&mut areq.body, boundary.as_bytes()).await {
                    Ok(trailing) => trailing,
                    Err(response) => {
                        drop(WriterLease::new(
                            self.storage().clone(),
                            device.clone(),
                            traffic_class,
                            writer,
                        ));
                        return response;
                    }
                };
            let no_commit = completion
                .headers
                .get("X-Backend-No-Commit")
                .is_some_and(config_true_value);
            if !no_commit {
                let req_timestamp = completion.req_timestamp.clone();
                let commit_df = match self.diskfile_for(
                    &completion.drive,
                    completion.part,
                    &completion.account,
                    &completion.container,
                    &completion.obj,
                    (completion.policy_index, completion.policy),
                ) {
                    Ok(df) => df.with_next_part_power(backend_next_part_power(&req)),
                    Err(error) => return plain_response(500, &error.to_string()),
                };
                let commit_pre_timestamp = completion.req_timestamp.clone();
                let commit_ssync_frag_index = completion
                    .headers
                    .get("X-Backend-Ssync-Frag-Index")
                    .and_then(|raw| raw.trim().parse().ok());
                let stall = self.commit_stall.clone();
                let replication_session_lock = self.replication_session_lock.clone();
                let exec = self.storage().clone();
                let commit_device = device.clone();
                let commit = DurabilityBarrier::run_shielded(async move {
                    exec.run_finite(commit_device, traffic_class, move || {
                        let _replication_session_lock = replication_session_lock;
                        let _guard = acquire_ec_commit_guard(
                            commit_df,
                            &commit_pre_timestamp,
                            commit_ssync_frag_index,
                        )?;
                        if let Some(stall) = stall.as_ref() {
                            stall();
                        }
                        writer
                            .commit(&req_timestamp)
                            .map_err(mutation_lock_error_response)?;
                        writer.close();
                        Ok::<(), Response>(())
                    })
                    .await
                })
                .await;
                match commit {
                    Ok(Ok(())) => {}
                    Ok(Err(response)) => return response,
                    Err(error) => return plain_response(500, &error.to_string()),
                }
            }
            if let Err(response) =
                drain_mime_commit_remainder(&mut areq.body, commit_trailing).await
            {
                return response;
            }
            self.finish_put_completion(completion).await
        } else {
            let durable = match writer.into_durable() {
                Ok(durable) => durable,
                Err(error) => return plain_response(500, &error.to_string()),
            };
            self.finish_pending_put(PendingDurable {
                durable,
                metadata,
                completion,
            })
            .await
        };
        resp.headers
            .setdefault("Content-Type", "text/html; charset=UTF-8");
        resp
    }

    async fn get_streaming_async(&self, req: Request, include_body: bool) -> Response {
        if let Err(resp) = self.obj_path(&req) {
            return resp;
        }
        let drive = req
            .path
            .trim_start_matches('/')
            .split('/')
            .next()
            .unwrap_or("sda1")
            .to_string();
        let exec = self.storage().clone();
        let device = DeviceId::new(drive.clone());
        let config = self.config.clone();
        let recon_cache_path = self.recon_cache_path.clone();
        let fallocate_reserve = self.fallocate_reserve;
        let worm_clock = std::sync::Arc::clone(&self.worm_clock);
        let method = req.method.clone();
        let path = req.path.clone();
        let query_string = req.query_string.clone();
        let headers = req.headers.clone();
        let mut resp = match exec
            .run_finite(device, TrafficClass::Foreground, move || {
                let tmp = ObjectServer {
                    config,
                    recon_cache_path,
                    fallocate_reserve,
                    worm_clock,
                    storage: std::sync::OnceLock::new(),
                    commit_stall: None,
                    replication_session_lock: None,
                };
                tmp.get(
                    &Request {
                        method,
                        path,
                        query_string,
                        headers,
                        body: Body::empty(),
                    },
                    include_body,
                )
            })
            .await
        {
            Ok(r) => r,
            Err(e) => return plain_response(500, &e.to_string()),
        };
        resp = swift_http::apply_conditional(&req, resp);
        if !include_body || !matches!(resp.status, 200 | 206) {
            return resp;
        }
        if !matches!(resp.body, Body::Streamed(_) | Body::Channel(_)) {
            return resp;
        }
        let content_length = resp.body.content_length();
        let (mut reader, _) = resp.body.take().into_reader();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let scope = TaskScope::bounded(1);
        let exec = self.storage().clone();
        let device = DeviceId::new(drive);
        let _ = scope.spawn(async move {
            loop {
                let read = exec
                    .run_finite(device.clone(), TrafficClass::Foreground, move || {
                        let mut buf = vec![0u8; STREAM_CHUNK];
                        let n = reader.read(&mut buf).map(|n| {
                            buf.truncate(n);
                            buf
                        });
                        (reader, n)
                    })
                    .await;
                let (next_reader, n) = match read {
                    Ok((r, Ok(buf))) => (r, Ok(buf)),
                    Ok((r, Err(e))) => (r, Err(e)),
                    Err(e) => {
                        let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                        break;
                    }
                };
                reader = next_reader;
                match n {
                    Ok(buf) if buf.is_empty() => break,
                    Ok(buf) => {
                        let n = buf.len();
                        if tx.send(Ok(buf)).await.is_err() {
                            break;
                        }
                        if let Some(m) = ConcurrencyMetrics::current() {
                            m.add_response_body_buffer(n as i64);
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        });
        resp.body = Body::from_channel(rx, content_length, scope);
        resp
    }

    async fn ssync_async(&self, areq: AsyncRequest) -> Response {
        self.ssync_async_with_lock_timeout(areq, Self::REPLICATION_LOCK_TIMEOUT)
            .await
    }

    async fn ssync_async_with_lock_timeout(
        &self,
        areq: AsyncRequest,
        lock_timeout: f64,
    ) -> Response {
        // Validation matches Python `Receiver.initialize_request`: it runs
        // before start_response, so 400/507 never become a 200 hijack.
        let req = Request {
            method: areq.method.clone(),
            path: areq.path.clone(),
            query_string: areq.query_string.clone(),
            headers: areq.headers.clone(),
            body: Body::empty(),
        };
        let segments = match split_path(&req.path, 2, 2, false) {
            Ok(s) => s,
            Err(e) => return plain_response(400, &e),
        };
        let device = segments[0].clone().unwrap_or_default();
        let partition = segments[1].clone().unwrap_or_default();
        if device.is_empty() || matches!(device.as_str(), "." | "..") {
            return plain_response(400, &format!("Invalid device: {device}"));
        }
        if partition.parse::<u64>().is_err() {
            return plain_response(400, &format!("Invalid partition: {partition}"));
        }
        let (policy_index, policy) = match self.storage_policy(&req) {
            Ok(p) => p,
            Err(resp) => return resp,
        };
        if let Err(resp) = self
            .check_drive_async(&device, TrafficClass::Replication)
            .await
        {
            return resp;
        }
        let frag_index: Option<i64> = match req.headers.get("X-Backend-Ssync-Frag-Index") {
            None | Some("") => None,
            Some(raw) => match raw.trim().parse::<i64>() {
                Ok(i) => Some(i),
                Err(_) => {
                    return plain_response(
                        400,
                        &format!("Invalid X-Backend-Ssync-Frag-Index {raw:?}"),
                    )
                }
            },
        };
        // Python `ssync_sender.connect` calls `getresponse()` after
        // `endheaders()` and *before* writing `:MISSING_CHECK:`
        // (`ssync_sender.py:264-272`). swob calls `start_response` before
        // iterating `app_iter` (`swob.py:1548-1549`). Return 200 + Channel
        // now; drive the session on a scoped task so Hyper can write the
        // head while IncomingBody still awaits the sender.
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(8);
        let scope = TaskScope::bounded(1);
        let storage = self.storage().clone();
        let part_path = self
            .config
            .devices
            .join(&device)
            .join(get_data_dir(policy_index))
            .join(&partition);
        let replication_lock = match acquire_replication_session_lock(
            &storage,
            DeviceId::new(device.clone()),
            part_path,
            lock_timeout,
        )
        .await
        {
            Ok(guard) => guard,
            Err(response) => return response,
        };
        let body = areq.body;
        let _ = scope.spawn(drive_ssync_session(
            body,
            tx,
            storage,
            self.clone_execution_context(),
            device,
            partition,
            policy_index,
            policy,
            frag_index,
            std::sync::Arc::new(replication_lock),
        ));
        let mut resp = Response::new(200);
        resp.headers.set("X-Backend-Accept-No-Commit", "True");
        resp.headers.set("Content-Type", "text/plain");
        resp.body = Body::from_channel(rx, None, scope);
        resp
    }

    pub async fn handle_buffered_async(&self, mut req: Request) -> Response {
        if req.method == "SSYNC" {
            return plain_response(500, "SSYNC requires handle_async / ssync_async");
        }
        if req.method != "PUT" {
            return self.dispatch_fs_on_storage(req).await;
        }
        let mut pending: Option<PendingDurable> = None;
        let early = self.put(&mut req, Some(&mut pending));
        if let Some(pending) = pending {
            let mut resp = self.finish_pending_put(pending).await;
            resp.headers
                .setdefault("Content-Type", "text/html; charset=UTF-8");
            resp
        } else {
            let mut resp = early;
            resp.headers
                .setdefault("Content-Type", "text/html; charset=UTF-8");
            resp
        }
    }

    async fn finish_pending_put(&self, pending: PendingDurable) -> Response {
        let PendingDurable {
            durable,
            metadata,
            completion,
        } = pending;
        let no_commit = completion
            .headers
            .get("X-Backend-No-Commit")
            .is_some_and(config_true_value);
        let drive = completion.drive.clone();
        let pre_df = match self.diskfile_for(
            &completion.drive,
            completion.part,
            &completion.account,
            &completion.container,
            &completion.obj,
            (completion.policy_index, completion.policy),
        ) {
            Ok(df) => df.with_next_part_power(backend_next_part_power(&Request {
                method: "PUT".into(),
                path: completion.path.clone(),
                query_string: String::new(),
                headers: completion.headers.clone(),
                body: Body::empty(),
            })),
            Err(error) => return plain_response(500, &error.to_string()),
        };
        let pre_req = Request {
            method: "PUT".into(),
            path: completion.path.clone(),
            query_string: String::new(),
            headers: completion.headers.clone(),
            body: Body::empty(),
        };
        let pre_timestamp = completion.req_timestamp.clone();
        let ssync_frag_index = completion
            .headers
            .get("X-Backend-Ssync-Frag-Index")
            .and_then(|raw| raw.trim().parse().ok());
        let clock_ok = self.worm_clock.clock_ok();
        let stall = self.commit_stall.clone();
        let replication_session_lock = self.replication_session_lock.clone();
        let traffic_class = if replication_session_lock.is_some() {
            TrafficClass::Replication
        } else {
            TrafficClass::Foreground
        };
        let exec = self.storage().clone();
        let device = DeviceId::new(drive);
        // Barrier lives on a non-cancelled shield task (L7). Dropping this
        // HTTP future does not abort commit or panic-drop the guard.
        let commit = DurabilityBarrier::run_shielded(async move {
            exec.run_finite(device, traffic_class, move || {
                let _replication_session_lock = replication_session_lock;
                let _guard = acquire_checked_put_guard(
                    pre_df,
                    &pre_req,
                    &pre_timestamp,
                    ssync_frag_index,
                    clock_ok,
                )?;
                if let Some(stall) = stall.as_ref() {
                    stall();
                }
                let committed = if no_commit {
                    durable.commit_nondurable(metadata)
                } else {
                    durable.commit(metadata)
                };
                committed.map_err(mutation_lock_error_response)
            })
            .await
        })
        .await;
        match commit {
            Ok(Ok(())) => {}
            Ok(Err(response)) => return response,
            Err(e) => return plain_response(500, &e.to_string()),
        }
        self.finish_put_completion(completion).await
    }

    async fn finish_put_completion(&self, completion: PutCompletion) -> Response {
        let PutCompletion {
            drive,
            part: _,
            etag,
            upload_size,
            content_type,
            req_timestamp,
            footers,
            resolved_delete_at,
            account,
            container,
            obj,
            policy_index,
            policy: _,
            headers,
            path,
        } = completion;
        let req = Request {
            method: "PUT".into(),
            path,
            query_string: String::new(),
            headers,
            body: Body::empty(),
        };
        let mut update = HeaderKeyDict::new();
        update.set("x-size", upload_size);
        update.set("x-content-type", &content_type);
        update.set("x-timestamp", req_timestamp.internal());
        update.set("x-etag", &etag);
        apply_container_override(&mut update, &req.headers, &footers);
        let replication = req
            .headers
            .get("X-Backend-Replication")
            .is_some_and(config_true_value);
        let container_host = req
            .headers
            .get("X-Container-Host")
            .unwrap_or("")
            .to_string();
        let container_device = req
            .headers
            .get("X-Container-Device")
            .unwrap_or("")
            .to_string();
        let container_partition = req
            .headers
            .get("X-Container-Partition")
            .unwrap_or("")
            .to_string();
        let backend_container_path =
            shard_update_account_container(&req.headers).map(|(a, c)| format!("{a}/{c}"));
        let db_state = req
            .headers
            .get("X-Container-Root-Db-State")
            .map(str::to_string);
        self.container_update_async(
            "PUT",
            &drive,
            &account,
            &container,
            &obj,
            replication,
            container_host,
            container_device,
            container_partition,
            backend_container_path,
            &update,
            policy_index,
            db_state,
        )
        .await;
        if let Some(delete_at) = resolved_delete_at
            .as_deref()
            .and_then(|v| v.parse::<i64>().ok())
        {
            self.delete_at_update(
                "PUT",
                delete_at,
                &drive,
                &account,
                &container,
                &obj,
                &req,
                policy_index,
                Some(upload_size),
                Some(req_timestamp.internal()),
            );
        }
        let mut resp = Response::new(201);
        resp.headers.set("ETag", format!("\"{etag}\""));
        resp
    }

    async fn check_drive_async(
        &self,
        drive: &str,
        traffic_class: TrafficClass,
    ) -> Result<(), Response> {
        let devices = self.config.devices.clone();
        let mount_check = self.config.mount_check;
        let drive = drive.to_string();
        self.storage()
            .run_finite(DeviceId::new(drive.clone()), traffic_class, move || {
                swift_core::constraints::check_drive(&devices, &drive, mount_check)
                    .map(|_| ())
                    .map_err(|_| swob_response(507))
            })
            .await
            .map_err(|error| plain_response(500, &error.to_string()))?
    }

    fn check_drive(&self, drive: &str) -> Result<(), Response> {
        // Use the same drive-name and mount semantics as the account and
        // container servers. In production, mount_check prevents a lost mount
        // from redirecting object I/O into the underlying root filesystem;
        // SAIO may explicitly disable it and use a plain device directory.
        swift_core::constraints::check_drive(&self.config.devices, drive, self.config.mount_check)
            .map(|_| ())
            .map_err(|_| swob_response(507))
    }

    #[allow(clippy::type_complexity)]
    fn obj_path(
        &self,
        req: &Request,
    ) -> Result<(String, u64, String, String, String, u32, PolicyKind), Response> {
        let (policy_index, policy) = self.storage_policy(req)?;
        let segs = split_path(&req.path, 5, 5, true).map_err(|e| plain_response(400, &e))?;
        let drive = segs[0].clone().unwrap_or_default();
        let part: u64 = segs[1]
            .clone()
            .unwrap_or_default()
            .parse()
            .map_err(|_| plain_response(400, "bad partition"))?;
        let account = segs[2].clone().unwrap_or_default();
        let container = segs[3].clone().unwrap_or_default();
        let obj = segs[4].clone().unwrap_or_default();
        validate_internal_obj(&account, &container, &obj)?;
        Ok((drive, part, account, container, obj, policy_index, policy))
    }

    fn diskfile_for(
        &self,
        drive: &str,
        part: u64,
        account: &str,
        container: &str,
        obj: &str,
        policy: (u32, PolicyKind),
    ) -> Result<DiskFile, DiskFileError> {
        let (policy_index, policy) = policy;
        DiskFile::new(
            &self.config.devices.join(drive),
            part,
            account,
            container,
            obj,
            policy,
            policy_index,
            &self.config.hash_config,
            self.config.diskfile.clone(),
        )
    }

    fn storage_policy(&self, req: &Request) -> Result<(u32, PolicyKind), Response> {
        let raw = req.headers.get("X-Backend-Storage-Policy-Index");
        let policy_index = match raw {
            None => 0,
            Some(raw) => {
                let trimmed = raw.trim();
                let digits = trimmed.strip_prefix('+').unwrap_or(trimmed);
                if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(plain_response(503, &format!("No policy with index {raw}")));
                }
                match digits.parse::<u32>() {
                    Ok(index) => index,
                    Err(_) => {
                        return Err(plain_response(503, &format!("No policy with index {raw}")))
                    }
                }
            }
        };
        let Some(policy) = self.config.policies.get(&policy_index).copied() else {
            return Err(plain_response(
                503,
                &format!("No policy with index {}", raw.unwrap_or("0")),
            ));
        };
        Ok((policy_index, policy))
    }

    /// Python-compatible object-server REPLICATE hash endpoint.
    ///
    /// A request without suffixes returns the partition's replication or EC
    /// suffix-hash dictionary. A request carrying suffixes only marks valid
    /// three-hex suffixes dirty and returns pickled `None`; the following
    /// no-suffix request performs the rehash. Both forms use pickle protocol 2
    /// for compatibility with older Swift nodes.
    fn replicate(&self, req: &Request) -> Response {
        let segments = match split_path(&req.path, 2, 3, true) {
            Ok(segments) => segments,
            Err(error) => return plain_response(400, &error),
        };
        let device = segments[0].clone().unwrap_or_default();
        let partition = segments[1].clone().unwrap_or_default();
        if device.is_empty() || matches!(device.as_str(), "." | "..") {
            return plain_response(400, &format!("Invalid device: {device}"));
        }
        if partition.is_empty() || matches!(partition.as_str(), "." | "..") {
            return plain_response(400, &format!("Invalid partition: {partition}"));
        }
        let (policy_index, policy) = match self.storage_policy(req) {
            Ok(policy) => policy,
            Err(response) => return response,
        };
        if let Err(response) = self.check_drive(&device) {
            return response;
        }

        let partition_path = self
            .config
            .devices
            .join(&device)
            .join(get_data_dir(policy_index))
            .join(&partition);
        let suffix_parts = segments[2]
            .as_deref()
            .filter(|suffixes| !suffixes.is_empty());
        let value = if let Some(suffix_parts) = suffix_parts {
            for suffix in suffix_parts
                .split('-')
                .filter(|suffix| valid_suffix(suffix))
            {
                if let Err(error) = invalidate_hash(&partition_path.join(suffix)) {
                    return plain_response(500, &error.to_string());
                }
            }
            PickleValue::None
        } else if !partition_path.exists() {
            PickleValue::Dict(Vec::new())
        } else {
            match get_partition_hashes(
                &partition_path,
                policy,
                &[],
                false,
                &self.config.diskfile.cleanup,
            ) {
                Ok((_hashed, hashes)) => hashes.to_value(),
                Err(error) => return plain_response(500, &error.to_string()),
            }
        };

        match pickle::dumps(&value) {
            Ok(body) => Response::with_body(200, body),
            Err(error) => plain_response(500, &error.to_string()),
        }
    }

    /// SSYNC receiver (`ssync_receiver.Receiver`), replication and EC.
    ///
    /// Validation failures before the exchange begins return ordinary HTTP
    /// error responses (Python raises them from `initialize_request`). Once
    /// validation passes, the handler hijacks the connection and speaks the
    /// full-duplex protocol itself: it writes the `200 OK` head (declaring
    /// `Transfer-Encoding: chunked` and framing every payload by hand, as
    /// eventlet does), reads the sender's missing-check section, answers with
    /// the wanted list, applies each updates-phase subrequest as it arrives,
    /// and reports the final `:UPDATES:` frame. In-session errors are conveyed
    /// in-band as Python does: an `:ERROR: <status> <repr>\n` line inside the
    /// 200 body.
    /// `DiskFileManager.replication_lock_timeout` default (seconds).
    const REPLICATION_LOCK_TIMEOUT: f64 = 15.0;

    fn ssync(&self, req: &mut Request) -> Response {
        let segments = match split_path(&req.path, 2, 2, false) {
            Ok(segments) => segments,
            Err(error) => return plain_response(400, &error),
        };
        let device = segments[0].clone().unwrap_or_default();
        let raw_partition = segments[1].clone().unwrap_or_default();
        if device.is_empty() || matches!(device.as_str(), "." | "..") {
            return plain_response(400, &format!("Invalid device: {device}"));
        }
        if raw_partition.parse::<u64>().is_err() {
            return plain_response(400, &format!("Invalid partition: {raw_partition}"));
        }
        let (policy_index, policy) = match self.storage_policy(req) {
            Ok(policy) => policy,
            Err(response) => return response,
        };
        // Python parses X-Backend-Ssync-Frag-Index for any policy; it only
        // has an effect on EC diskfiles.
        let frag_index: Option<i64> = match req.headers.get("X-Backend-Ssync-Frag-Index") {
            None | Some("") => None,
            Some(raw) => match raw.trim().parse::<i64>() {
                Ok(frag_index) => Some(frag_index),
                Err(_) => {
                    return plain_response(
                        400,
                        &format!("Invalid X-Backend-Ssync-Frag-Index {raw:?}"),
                    )
                }
            },
        };
        if let Err(response) = self.check_drive(&device) {
            return response;
        }
        // Python's receiver holds the partition 'replication' lock for the
        // whole exchange (Receiver.__call__ via DiskFileManager
        // .replication_lock) — the same flock the reconstructor's revert and
        // the replicator take, so cross-replication (Rust OR Python daemons
        // on this node) cannot race this session. Timeout -> 503, before the
        // connection is hijacked.
        let part_path = self
            .config
            .devices
            .join(&device)
            .join(get_data_dir(policy_index))
            .join(&raw_partition);
        let Ok(_replication_lock) = swift_core::lockutil::lock_path(
            &part_path,
            Self::REPLICATION_LOCK_TIMEOUT,
            Some("replication"),
        ) else {
            return swob_response(503);
        };

        let Some(mut wire) = req.body.hijack() else {
            // Should not happen on a real connection; refuse rather than
            // half-speak the protocol.
            return plain_response(500, "SSYNC requires a hijackable connection");
        };
        let (mut reader, _) = req.body.take().into_reader();
        let session = SsyncSession {
            server: self,
            device,
            partition: raw_partition,
            policy_index,
            policy,
            frag_index,
        };
        // The sender may see a broken pipe rather than this sentinel; every
        // write after the hijack belongs to the handler and IO errors simply
        // end the exchange (the server closes the connection afterwards).
        let head = b"HTTP/1.1 200 OK\r\n\
             X-Backend-Accept-No-Commit: True\r\n\
             Content-Type: text/plain\r\n\
             Transfer-Encoding: chunked\r\n\r\n";
        if wire.write_all(head).is_ok() {
            let _ = session.run(&mut *reader, &mut *wire);
        }
        // The connection was hijacked: this response never reaches the wire.
        Response::new(499)
    }

    fn apply_ssync_update(
        &self,
        device: &str,
        partition: &str,
        policy_index: u32,
        frag_index: Option<i64>,
        update: SsyncSubrequest,
    ) -> Response {
        let mut headers = update.headers;
        headers.set("X-Backend-Storage-Policy-Index", policy_index);
        headers.set("X-Backend-Replication", "True");
        if let Some(frag_index) = frag_index {
            // primary node should not 409 if it has a non-primary fragment
            headers.set("X-Backend-Ssync-Frag-Index", frag_index);
        }
        if !update.replication_headers.is_empty() {
            headers.set(
                "X-Backend-Replication-Headers",
                update.replication_headers.join(" "),
            );
        }
        let decoded_path = unquote(&update.path);
        self.handle(Request {
            method: update.method,
            path: format!("/{device}/{partition}{decoded_path}"),
            query_string: String::new(),
            headers,
            body: update.body.into(),
        })
    }

    fn valid_timestamp(req: &Request) -> Result<Timestamp, Response> {
        req.headers
            .get("X-Timestamp")
            .ok_or_else(|| plain_response(400, "Missing X-Timestamp header"))
            .and_then(|raw| {
                raw.parse()
                    .map_err(|_| plain_response(400, "Invalid X-Timestamp header"))
            })
    }

    fn recon_response(&self, req: &Request) -> Option<Response> {
        if !matches!(req.method.as_str(), "GET" | "HEAD") {
            return None;
        }
        let keys: &[&str] = match req.path.as_str() {
            "/recon/updater/object" => &[
                "object_updater_sweep",
                "object_updater_stats",
                "object_updater_last",
            ],
            _ => return None,
        };
        let cached = std::fs::read(self.recon_cache_path.join("object.recon"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        let mut selected = serde_json::Map::new();
        for key in keys {
            selected.insert(
                (*key).to_string(),
                cached.get(*key).cloned().unwrap_or(serde_json::Value::Null),
            );
        }
        let body = serde_json::to_vec(&serde_json::Value::Object(selected)).unwrap_or_default();
        let content_length = body.len();
        let mut resp = Response::with_body(
            200,
            if req.method == "HEAD" {
                Vec::new()
            } else {
                body
            },
        );
        resp.headers.set("Content-Type", "application/json");
        resp.headers.set("Content-Length", content_length);
        Some(resp)
    }

    pub fn handle(&self, mut req: Request) -> Response {
        if let Some(resp) = self.recon_response(&req) {
            return resp;
        }
        if req.path == "/recon/stage" && matches!(req.method.as_str(), "GET" | "HEAD") {
            let body = swift_core::stage::snapshot_json();
            let mut resp = Response::with_body(
                200,
                if req.method == "HEAD" {
                    Vec::new()
                } else {
                    body.clone().into_bytes()
                },
            );
            resp.headers
                .set("Content-Type", "application/json; charset=utf-8");
            resp.headers.set("Content-Length", body.len());
            return resp;
        }
        let mut resp = match req.method.as_str() {
            // GET/HEAD are conditional responses: an otherwise-2xx result may be
            // reduced to a 304/412 by If-[None-]Match / If-[Un]Modified-Since.
            "GET" => swift_http::apply_conditional(&req, self.get(&req, true)),
            "HEAD" => swift_http::apply_conditional(&req, self.get(&req, false)),
            "PUT" => self.put(&mut req, None),
            "POST" => self.post(&req),
            "DELETE" => self.delete(&req),
            "REPLICATE" => self.replicate(&req),
            "SSYNC" => self.ssync(&mut req),
            "OPTIONS" => {
                let mut resp = Response::new(200);
                resp.headers.set(
                    "Allow",
                    "DELETE, GET, HEAD, OPTIONS, POST, PUT, REPLICATE, SSYNC",
                );
                resp
            }
            _ => {
                let mut resp = swob_response(405);
                resp.headers.set(
                    "Allow",
                    "DELETE, GET, HEAD, OPTIONS, POST, PUT, REPLICATE, SSYNC",
                );
                resp
            }
        };
        resp.headers
            .setdefault("Content-Type", "text/html; charset=UTF-8");
        resp
    }

    fn put(
        &self,
        req: &mut Request,
        executor_commit: Option<&mut Option<PendingDurable>>,
    ) -> Response {
        let _meta_stage =
            swift_core::stage::StageTimer::start("object-server", "put", "metadata_parse");
        let (drive, part, account, container, obj, policy_index, policy) = match self.obj_path(req)
        {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let req_timestamp = match Self::valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        // check_object_creation: content-type + content-length required
        let Some(content_type) = req.headers.get("Content-Type") else {
            return plain_response(400, "No content type");
        };
        let content_type = content_type.to_string();
        if req.headers.get("Content-Length").is_none()
            && !req
                .headers
                .get("Transfer-Encoding")
                .is_some_and(|te| te.eq_ignore_ascii_case("chunked"))
        {
            return plain_response(411, "Missing Content-Length header.");
        }
        // The multipart-MIME backend PUT (X-Backend-Obj-* headers): the
        // request body is MIME documents — object data, then a metadata
        // footer, then (multiphase) a commit confirmation after a second
        // 100 Continue. server.py:881-918.
        use swift_core::config::config_true_value;
        let have_footer = req
            .headers
            .get("X-Backend-Obj-Metadata-Footer")
            .is_some_and(config_true_value);
        let multiphase = req
            .headers
            .get("X-Backend-Obj-Multiphase-Commit")
            .is_some_and(config_true_value);
        let mime_mode = have_footer || multiphase;
        // The declared object length (None when unknown) drives the
        // MAX_FILE_SIZE pre-check and the fallocate reserve; the streamed
        // byte count is verified against it at EOF. In MIME mode the
        // request Content-Length describes the whole MIME body, so the
        // object length travels in X-Backend-Obj-Content-Length.
        let declared_len: Option<u64> = if mime_mode {
            req.headers
                .get("X-Backend-Obj-Content-Length")
                .and_then(|s| s.trim().parse::<u64>().ok())
        } else {
            req.headers
                .get("Content-Length")
                .and_then(|s| s.trim().parse::<u64>().ok())
                .or_else(|| req.body.content_length())
        };
        if declared_len.is_some_and(|len| len > MAX_FILE_SIZE as u64) {
            return plain_response(413, "Your request is too large.");
        }
        // Only `If-None-Match: *` is supported on a write; anything else is a
        // 400 (the proxy's `If-None-Match only supports *`).
        if let Some(inm) = req.headers.get("If-None-Match") {
            if !if_none_match_has_star(inm) {
                return plain_response(400, "If-None-Match only supports *");
            }
        }
        // Validate/normalize X-Delete-After / X-Delete-At (check_delete_headers).
        let resolved_delete_at = match check_delete_headers(req, req_timestamp.as_secs_f64()) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

        // Pre-create checks against any existing object: If-None-Match,
        // If-Match, the timestamp-conflict guard, and the experimental native
        // lock gate. A live object yields its metadata (sysmeta included); an
        // expired object is absent for If-* but still carries lock sysmeta.
        // A tombstone/missing object yields no metadata but still carries a
        // timestamp for the conflict guard.
        // SSYNC subrequests carry a Frag-Index header, in which case the
        // pre-open ignores non-matching on-disk data files so a primary
        // holding a different fragment does not 409 (server.py:833).
        let ssync_frag_index: Option<i64> = req
            .headers
            .get("X-Backend-Ssync-Frag-Index")
            .and_then(|raw| raw.trim().parse().ok());
        let (orig_exists, orig_timestamp, orig_metadata) = match self
            .diskfile_for(
                &drive,
                part,
                &account,
                &container,
                &obj,
                (policy_index, policy),
            )
            .map(|df| df.with_frag_index(ssync_frag_index))
        {
            Ok(mut pre) => match pre.open(None) {
                Ok(opened) => {
                    let ts = opened
                        .data_timestamp()
                        .unwrap_or_else(|_| "0".parse().unwrap());
                    // Live object: metadata read failure is not "unlocked".
                    match opened.get_metadata() {
                        Ok(meta) => (true, ts, Some(meta.clone())),
                        Err(e) => return plain_response(500, &e.to_string()),
                    }
                }
                Err(DiskFileError::Deleted { timestamp, .. }) => (false, timestamp, None),
                // An expired object counts as absent for If-None-Match / If-Match,
                // but its timestamp still guards against an out-of-order
                // overwrite and its lock sysmeta still feeds the lock gate.
                Err(DiskFileError::Expired { metadata }) => {
                    let ts = meta_get(&metadata, "X-Timestamp")
                        .and_then(|s| s.parse::<Timestamp>().ok())
                        .unwrap_or_else(|| "0".parse().unwrap());
                    (false, ts, Some(metadata))
                }
                Err(DiskFileError::NotExist) | Err(DiskFileError::Quarantined(_)) => {
                    (false, "0".parse().unwrap(), None)
                }
                Err(e) => return plain_response(500, &e.to_string()),
            },
            Err(e) => return plain_response(500, &e.to_string()),
        };
        // If-None-Match only reaches here as `*` (non-`*` rejected above): a
        // wildcard match against an existing object is a 412.
        if orig_exists && req.headers.get("If-None-Match").is_some() {
            return swob_response(412);
        }
        if orig_timestamp >= req_timestamp {
            let mut resp = swob_response(409);
            resp.headers
                .set("X-Backend-Timestamp", orig_timestamp.internal());
            return resp;
        }
        if let Some(resp) = put_if_match_precondition(req, orig_exists, orig_metadata.as_ref()) {
            return resp;
        }
        // Experimental native lock: live or expired metadata bag. No object →
        // allow PUT. Replicate/ssync skip inside the helper. Not live-proven.
        if orig_exists || orig_metadata.is_some() {
            if let Some(resp) = deny_locked_native_mutation(
                req,
                orig_metadata
                    .as_ref()
                    .map(|meta| Ok::<_, DiskFileError>(meta)),
                self.worm_clock.clock_ok(),
            ) {
                return resp;
            }
        }

        // fallocate_reserve: refuse the write before any data lands when it
        // would drop the device's free space to or below the configured
        // reserve — the point where Python's DiskFileWriter raises
        // DiskFileNoSpace out of fallocate() and server.py answers 507. A
        // statvfs failure fails open; the write itself still ENOSPCs.
        // Chunked transfers declare no length, so (as in Python, which
        // fallocates only when a size is known) they cannot pre-reserve.
        if let Ok(free) = swift_core::fsutil::free_bytes(&self.config.devices.join(&drive)) {
            if fallocate_reserve_breached(free, declared_len.unwrap_or(0), &self.fallocate_reserve)
            {
                return swob_response(507);
            }
        }

        let df = match self.diskfile_for(
            &drive,
            part,
            &account,
            &container,
            &obj,
            (policy_index, policy),
        ) {
            Ok(df) => df.with_next_part_power(backend_next_part_power(req)),
            Err(e) => return plain_response(500, &e.to_string()),
        };

        let mut writer = match df.create(".data") {
            Ok(w) => w,
            Err(DiskFileError::NoSpace) => return swob_response(507),
            Err(e) => return plain_response(500, &e.to_string()),
        };
        // MIME mode: advertise the capabilities on the first 100 Continue
        // (server.py:884-900) and position the parser at the object-body
        // document. The interim handle is a no-op when the proxy did not
        // send Expect (eventlet parity).
        let interim = req.body.interim_responder();
        let mut mime_docs: Option<MimeDocs> = if mime_mode {
            let Some(boundary) = req
                .headers
                .get("X-Backend-Obj-Multipart-Mime-Boundary")
                .map(str::to_string)
            else {
                return plain_response(400, "no MIME boundary");
            };
            let mut adverts: Vec<(&str, &str)> = Vec::new();
            if multiphase {
                adverts.push(("X-Obj-Multiphase-Commit", "yes"));
            }
            if have_footer {
                adverts.push(("X-Obj-Metadata-Footer", "yes"));
            }
            if let Some(i) = &interim {
                if i.send_continue(&adverts).is_err() {
                    return swob_response(499);
                }
            }
            let (reader, _) = req.body.take().into_reader();
            let mut docs = MimeDocs::new(reader, boundary.as_bytes());
            match docs.next_document() {
                Ok(Some(_object_body_headers)) => {}
                Ok(None) => return plain_response(400, "no object body MIME doc"),
                Err(e) => return mime_read_error(&e),
            }
            Some(docs)
        } else {
            None
        };
        let mut plain_reader = if mime_docs.is_none() {
            Some(req.body.take().into_reader().0)
        } else {
            None
        };
        // Consume the object data as a stream: 64KB chunks into the
        // writer, which keeps the incremental md5 and byte count. All
        // abort paths below return without `put()`, so the writer's drop
        // removes the temp file (Python: the `with diskfile.create()`
        // block unwinding without a put).
        drop(_meta_stage);
        let _write_stage =
            swift_core::stage::StageTimer::start("object-server", "put", "disk_write");
        let mut buf = [0u8; STREAM_CHUNK];
        let mut upload_size: u64 = 0;
        loop {
            let read = match (&mut mime_docs, &mut plain_reader) {
                (Some(docs), _) => docs.read(&mut buf),
                (None, Some(reader)) => reader.read(&mut buf),
                (None, None) => unreachable!(),
            };
            let n = match read {
                Ok(0) => break,
                Ok(n) => n,
                // The chunked decoder's body cap surfaces mid-read as the
                // too-large error (Python: wsgi input raising on an
                // oversized chunked body -> 413).
                Err(e) if swift_http::body_too_large(&e) => {
                    return plain_response(413, "Your request is too large.")
                }
                // ChunkReadError: client hung up / short body -> 499, no
                // commit.
                Err(_) => return swob_response(499),
            };
            upload_size += n as u64;
            if upload_size > MAX_FILE_SIZE as u64 {
                return plain_response(413, "Your request is too large.");
            }
            if let Err(e) = writer.write(&buf[..n]) {
                return plain_response(500, &e.to_string());
            }
        }
        // Python raises ChunkReadError when the body ends short of the
        // declared Content-Length: 499, nothing committed.
        if declared_len.is_some_and(|declared| declared != upload_size) {
            return swob_response(499);
        }
        // The metadata footer document (server.py:571-604, 979-994).
        let footers: Vec<(String, String)> = match (&mut mime_docs, have_footer) {
            (Some(docs), true) => match read_footer_metadata(docs) {
                Ok(f) => f,
                Err(resp) => return resp,
            },
            _ => Vec::new(),
        };
        let footer_get = |name: &str| {
            footers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        drop(_write_stage);
        let (upload_size, etag) = {
            let _hash = swift_core::stage::StageTimer::start("object-server", "put", "hash");
            writer.chunks_finished()
        };
        // The received etag — footer first, else the request header — must
        // match the streamed md5 (server.py:996-1007; the body is already
        // consumed at this point, as in Python).
        let received_etag = footer_get("etag")
            .or_else(|| req.headers.get("ETag"))
            .unwrap_or("");
        let normalized = received_etag.trim_matches('"');
        if !normalized.is_empty() && !normalized.eq_ignore_ascii_case(&etag) {
            return swob_response(422);
        }
        let mut metadata: Metadata = vec![
            (
                "X-Timestamp".into(),
                MetaValue::Str(req_timestamp.internal()),
            ),
            ("Content-Type".into(), MetaValue::Str(content_type.clone())),
            (
                "Content-Length".into(),
                MetaValue::Str(upload_size.to_string()),
            ),
            ("ETag".into(), MetaValue::Str(etag.clone())),
        ];
        // user/sysmeta and transient sysmeta from the request headers
        for (k, v) in req.headers.iter() {
            let lower = k.to_ascii_lowercase();
            let is_core = matches!(
                lower.as_str(),
                "x-timestamp"
                    | "content-type"
                    | "content-length"
                    | "etag"
                    | "x-delete-at"
                    | "x-delete-after"
            );
            if should_persist_header(req, k) && !is_core {
                metadata.push((MetaValue::Str(k.to_string()), MetaValue::Str(v.to_string())));
            }
        }
        // Footer sysmeta/user-meta overrides header-sourced entries
        // (server.py:996-1002: metadata.update(footers sys/user meta)).
        for (k, v) in &footers {
            if is_sys_or_user_meta(k) || is_object_transient_sysmeta(k) {
                meta_upsert(&mut metadata, k, v.clone());
            }
        }
        // Persist the normalized X-Delete-At as datafile metadata (Python
        // stores it via `allowed_headers`); this is what HEAD/GET echoes and
        // the expirer reads.
        if let Some(delete_at) = &resolved_delete_at {
            metadata.push((
                MetaValue::Str("X-Delete-At".into()),
                MetaValue::Str(delete_at.clone()),
            ));
        }

        let _commit_stage = swift_core::stage::StageTimer::start("object-server", "put", "commit");
        let defer =
            executor_commit.is_some() && !multiphase && !matches!(policy, PolicyKind::Ec { .. });
        if defer {
            let durable = match writer.into_durable() {
                Ok(d) => d,
                Err(e) => return plain_response(500, &e.to_string()),
            };
            if let Some(slot) = executor_commit {
                *slot = Some(PendingDurable {
                    durable,
                    metadata,
                    completion: PutCompletion {
                        drive: drive.clone(),
                        part,
                        etag: etag.clone(),
                        upload_size,
                        content_type: content_type.clone(),
                        req_timestamp: req_timestamp.clone(),
                        footers: footers.clone(),
                        resolved_delete_at: resolved_delete_at.clone(),
                        account: account.clone(),
                        container: container.clone(),
                        obj: obj.clone(),
                        policy_index,
                        policy,
                        headers: req.headers.clone(),
                        path: req.path.clone(),
                    },
                });
            }
            // Caller (`handle_buffered_async`) commits this request's
            // PendingDurable on StorageExecutor. Not a process-wide slot.
            return Response::new(201);
        }
        let commit_df = match self.diskfile_for(
            &drive,
            part,
            &account,
            &container,
            &obj,
            (policy_index, policy),
        ) {
            Ok(df) => df.with_next_part_power(backend_next_part_power(req)),
            Err(error) => return plain_response(500, &error.to_string()),
        };
        let mut mutation_guard = match acquire_checked_put_guard(
            commit_df,
            req,
            &req_timestamp,
            ssync_frag_index,
            self.worm_clock.clock_ok(),
        ) {
            Ok(guard) => Some(guard),
            Err(response) => return response,
        };
        if let Err(e) = writer.put(metadata) {
            writer.close();
            return match e {
                DiskFileError::NoSpace | DiskFileError::XattrNotSupported => swob_response(507),
                other => plain_response(500, &other.to_string()),
            };
        }
        drop(_commit_stage);
        // Two-phase commit (server.py:1009-1021): the fragment is on disk
        // but NOT durable; tell the proxy with a second 100 Continue (which
        // also re-arms the chunked body for the commit sequence), then
        // require the commit confirmation document before making it
        // durable.
        if multiphase {
            // Never hold an object stripe while waiting on the proxy's
            // second phase. The durable transition reacquires and rechecks.
            drop(mutation_guard.take());
            let Some(docs) = &mut mime_docs else {
                writer.close();
                return plain_response(400, "multiphase commit requires a MIME body");
            };
            if let Some(i) = &interim {
                if i.send_continue(&[]).is_err() {
                    writer.close();
                    return swob_response(499);
                }
            }
            match docs.next_document() {
                Ok(Some(headers)) => {
                    let is_commit = headers
                        .iter()
                        .any(|(k, v)| k.eq_ignore_ascii_case("X-Document") && v == "put commit");
                    if !is_commit {
                        writer.close();
                        return plain_response(500, "expected put commit MIME doc");
                    }
                }
                Ok(None) => {
                    writer.close();
                    return plain_response(400, "couldn't find PUT commit MIME doc");
                }
                Err(_) => {
                    writer.close();
                    return swob_response(499);
                }
            }
        }
        // The ssync sender marks a non-durable EC fragment PUT with
        // X-Backend-No-Commit; legacy default is to commit (server.py:1095).
        if !req
            .headers
            .get("X-Backend-No-Commit")
            .is_some_and(config_true_value)
        {
            let second_phase_guard = if multiphase {
                let commit_df = match self.diskfile_for(
                    &drive,
                    part,
                    &account,
                    &container,
                    &obj,
                    (policy_index, policy),
                ) {
                    Ok(df) => df.with_next_part_power(backend_next_part_power(req)),
                    Err(error) => return plain_response(500, &error.to_string()),
                };
                match acquire_ec_commit_guard(commit_df, &req_timestamp, ssync_frag_index) {
                    Ok(guard) => Some(guard),
                    Err(response) => return response,
                }
            } else {
                None
            };
            if let Err(e) = writer.commit(&req_timestamp) {
                writer.close();
                return plain_response(500, &e.to_string());
            }
            drop(second_phase_guard);
        }
        if !multiphase {
            drop(mutation_guard.take());
        }
        writer.close();
        // Drain any remaining MIME docs (there should be none, but the
        // whole request body must be read; server.py:1023-1033, bounded).
        if let Some(docs) = &mut mime_docs {
            for _ in 0..16 {
                match docs.next_document() {
                    Ok(Some(_)) => continue,
                    _ => break,
                }
            }
        }

        // container update side channel: the actually-written byte count
        // and streamed md5, not the declared header values — unless the
        // request/footers carry container-update overrides (EC PUTs
        // override with the whole-object etag/size so listings show the
        // object, not the fragment archive; server.py:606-645).
        let mut update = HeaderKeyDict::new();
        update.set("x-size", upload_size);
        update.set("x-content-type", &content_type);
        update.set("x-timestamp", req_timestamp.internal());
        update.set("x-etag", &etag);
        apply_container_override(&mut update, &req.headers, &footers);
        self.container_update(
            "PUT",
            &drive,
            &account,
            &container,
            &obj,
            req,
            &update,
            policy_index,
        );
        // enqueue expiry if the object has an X-Delete-At
        if let Some(delete_at) = resolved_delete_at
            .as_deref()
            .and_then(|v| v.parse::<i64>().ok())
        {
            self.delete_at_update(
                "PUT",
                delete_at,
                &drive,
                &account,
                &container,
                &obj,
                req,
                policy_index,
                Some(upload_size),
                Some(req_timestamp.internal()),
            );
        }

        let mut resp = Response::new(201);
        resp.headers.set("ETag", format!("\"{etag}\""));
        resp
    }

    fn post(&self, req: &Request) -> Response {
        let (drive, part, account, container, obj, policy_index, policy) = match self.obj_path(req)
        {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let req_timestamp = match Self::valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        // POST rejects an X-Delete-At already in the past (Python server.py POST
        // uses a plain `new_delete_at < req_timestamp` guard, not the normalizing
        // check_delete_headers used on PUT).
        if let Some(raw) = req.headers.get("X-Delete-At") {
            if let Some(v) = parse_int_like(raw) {
                if v != 0.0 && v < req_timestamp.as_secs_f64() {
                    return plain_response(400, "X-Delete-At in past");
                }
            }
        }
        let mut df = match self.diskfile_for(
            &drive,
            part,
            &account,
            &container,
            &obj,
            (policy_index, policy),
        ) {
            Ok(df) => df.with_next_part_power(backend_next_part_power(req)),
            Err(e) => return plain_response(500, &e.to_string()),
        };
        // Python object-server POST constructs its DiskFile with
        // `open_expired=is_backend_open_expired(request)`.  SSYNC marks every
        // subrequest as backend replication, and must therefore be able to
        // apply a newer .meta file that removes an already-expired
        // X-Delete-At.  Opening with the normal client semantics here made
        // the receiver return 404 before the replication POST could repair
        // the missed metadata update.
        if req
            .headers
            .get("X-Backend-Open-Expired")
            .is_some_and(config_true_value)
            || req
                .headers
                .get("X-Backend-Replication")
                .is_some_and(config_true_value)
        {
            df = df.with_open_expired(true);
        }
        let mutation_guard = match df.acquire_mutation_lock(OBJECT_MUTATION_LOCK_TIMEOUT) {
            Ok(guard) => guard,
            Err(error) => return mutation_lock_error_response(error),
        };
        let orig = match df.open(None) {
            Ok(opened) => opened,
            Err(DiskFileError::NotExist) | Err(DiskFileError::Deleted { .. }) => {
                return swob_response(404)
            }
            // Python DiskFileExpired subclasses DiskFileNotExist, so
            // server.py POST (690-691) turns an expired object into the
            // same 404.
            Err(DiskFileError::Expired { .. }) => return swob_response(404),
            Err(DiskFileError::Quarantined(_)) => return swob_response(404),
            Err(e) => return plain_response(500, &e.to_string()),
        };
        let orig_timestamp = orig
            .get_metadata()
            .ok()
            .and_then(|m| meta_get(m, "X-Timestamp"))
            .and_then(|s| s.parse::<Timestamp>().ok())
            .unwrap_or_else(|| "0".parse().unwrap());
        // server.py 696: the timestamp the current content-type carries — the
        // one encoded in the newest .meta, else the datafile's X-Timestamp.
        let orig_ctype_timestamp = orig
            .content_type_timestamp()
            .unwrap_or_else(|_| "0".parse().unwrap());
        // server.py 697-702: a request Content-Type is stamped with the
        // explicit Content-Type-Timestamp header when one is supplied
        // (replication), else with the request timestamp; a POST carrying NO
        // Content-Type gets Timestamp zero so it can never displace the
        // on-disk content-type. (Python truthiness: an empty Content-Type
        // counts as absent.)
        let req_ctype_timestamp: Timestamp = if req
            .headers
            .get("Content-Type")
            .is_some_and(|c| !c.is_empty())
        {
            match req.headers.get("Content-Type-Timestamp") {
                Some(raw) => match raw.parse() {
                    Ok(t) => t,
                    // Python's Timestamp() raises out of the handler: 500.
                    Err(_) => return plain_response(500, "invalid Content-Type-Timestamp"),
                },
                None => req_timestamp,
            }
        } else {
            "0".parse().unwrap()
        };
        // server.py 703-707: conflict only when BOTH the metadata timestamp
        // and the content-type timestamp are older-or-equal; a POST that lost
        // the metadata race may still deliver a newer content-type.
        if orig_timestamp >= req_timestamp && orig_ctype_timestamp >= req_ctype_timestamp {
            let mut resp = swob_response(409);
            resp.headers
                .set("X-Backend-Timestamp", orig_timestamp.internal());
            return resp;
        }
        // Experimental native lock on existing-object POST. Replicate/ssync
        // skip. Lock-sysmeta-only POST is not denied. Unreadable metadata
        // fails closed (500).
        if let Some(resp) =
            deny_locked_native_mutation(req, Some(orig.get_metadata()), self.worm_clock.clock_ok())
        {
            return resp;
        }
        let orig_metadata = match orig.get_metadata() {
            Ok(metadata) => metadata.clone(),
            Err(e) => return plain_response(500, &e.to_string()),
        };
        if let Some(response) = put_if_match_precondition(req, true, Some(&orig_metadata)) {
            return response;
        }
        if let Some(response) = expected_s3_version_precondition(req, true, Some(&orig_metadata)) {
            return response;
        }
        let content_length = meta_get(&orig_metadata, "Content-Length")
            .unwrap_or("0")
            .to_string();
        let etag = meta_get(&orig_metadata, "ETag").unwrap_or("").to_string();
        let orig_sysmeta: Vec<(String, String)> = orig_metadata
            .iter()
            .filter_map(|(k, v)| match (k, v) {
                (MetaValue::Str(key), MetaValue::Str(value))
                    if key.to_ascii_lowercase().starts_with("x-object-sysmeta-") =>
                {
                    Some((key.clone(), value.clone()))
                }
                _ => None,
            })
            .collect();
        let data_timestamp = orig
            .data_timestamp()
            .unwrap_or_else(|_| "0".parse().unwrap());
        // the merged current content-type (from the newest .meta carrying one,
        // else the datafile)
        let orig_content_type = orig.content_type().ok().flatten().unwrap_or("").to_string();
        // the datafile's own content-type, for the swift_bytes carry-over on
        // the container update below
        let datafile_content_type = orig
            .get_datafile_metadata()
            .ok()
            .and_then(|m| meta_get(m, "Content-Type"))
            .unwrap_or("")
            .to_string();
        let metafile_metadata: Option<Metadata> =
            orig.get_metafile_metadata().ok().flatten().cloned();

        // server.py 709-732: a POST newer than the current metadata replaces
        // the whole .meta with fresh user meta from the request; an older POST
        // (alive only because its content-type is newer) preserves the
        // existing .meta metadata verbatim — only the content-type may change.
        let mut metadata: Metadata = if req_timestamp > orig_timestamp {
            let mut m: Metadata = vec![(
                "X-Timestamp".into(),
                MetaValue::Str(req_timestamp.internal()),
            )];
            for (k, v) in req.headers.iter() {
                let is_core = matches!(
                    k.to_ascii_lowercase().as_str(),
                    "x-timestamp" | "content-type" | "content-type-timestamp"
                );
                if should_persist_header(req, k) && !is_core {
                    m.push((MetaValue::Str(k.to_string()), MetaValue::Str(v.to_string())));
                }
            }
            m
        } else {
            // server.py 731-732: `metadata = dict(disk_file.get_metafile_metadata())`.
            // With no .meta on disk Python raises (dict(None)) into a 500; no
            // well-formed request reaches this, since a request content-type
            // timestamp never exceeds a metadata timestamp that itself does
            // not exceed the datafile timestamp.
            match metafile_metadata {
                Some(m) => m,
                None => return plain_response(500, "POST preserving absent .meta metadata"),
            }
        };
        // Save the expirer side effects, but do not issue network/container
        // updates while the object stripe is held. The metadata publish below
        // is the transaction's durability boundary.
        let pending_delete_at_update = if req_timestamp > orig_timestamp {
            let orig_delete_at = orig
                .get_metadata()
                .ok()
                .and_then(|m| meta_get(m, "X-Delete-At"))
                .and_then(|raw| parse_int_like(raw))
                .map(|value| value as i64)
                .unwrap_or(0);
            let new_delete_at = req
                .headers
                .get("X-Delete-At")
                .and_then(parse_int_like)
                .map(|value| value as i64)
                .unwrap_or(0);
            let expirer_bytes = content_length.parse::<u64>().unwrap_or(0);
            Some((
                orig_delete_at,
                new_delete_at,
                expirer_bytes,
                data_timestamp.internal(),
            ))
        } else {
            None
        };

        // server.py 733-748: resolve which content-type wins. A newer request
        // content-type goes into the .meta stamped with its own timestamp;
        // otherwise the ORIGINAL content-type keeps its ORIGINAL timestamp and
        // is written into the .meta only when it did not come from the .data
        // file (a datafile content-type is implicit in any .meta without one).
        let (resolved_ctype, resolved_ctype_timestamp) =
            if req_ctype_timestamp > orig_ctype_timestamp {
                let new_ctype = req.headers.get("Content-Type").unwrap_or("").to_string();
                meta_upsert(&mut metadata, "Content-Type", new_ctype.clone());
                meta_upsert(
                    &mut metadata,
                    "Content-Type-Timestamp",
                    req_ctype_timestamp.internal(),
                );
                (new_ctype, req_ctype_timestamp)
            } else {
                if orig_ctype_timestamp != data_timestamp {
                    meta_upsert(&mut metadata, "Content-Type", orig_content_type.clone());
                    meta_upsert(
                        &mut metadata,
                        "Content-Type-Timestamp",
                        orig_ctype_timestamp.internal(),
                    );
                }
                (orig_content_type.clone(), orig_ctype_timestamp)
            };
        // server.py 775-776: x-meta-timestamp is metadata['X-Timestamp'] — the
        // PRESERVED original .meta timestamp when this POST lost the meta race.
        let meta_timestamp = meta_get(&metadata, "X-Timestamp")
            .unwrap_or("0")
            .to_string();

        // The .meta filename encodes (metadata timestamp, content-type
        // timestamp): write_metadata → finalize_put → make_ondisk_filename
        // appends the ctype delta exactly when Content-Type-Timestamp is
        // present in the metadata, as decided above.
        if let Err(e) = df.write_metadata(&metadata) {
            return match e {
                DiskFileError::NoSpace | DiskFileError::XattrNotSupported => swob_response(507),
                other => plain_response(500, &other.to_string()),
            };
        }
        drop(mutation_guard);

        // Python server.py:_conditional_delete_at_update. A metadata POST may
        // create a new expiry task and must remove the old task when the
        // delete-at changes or is cleared. These side effects happen only
        // after the object metadata is durably published.
        if let Some((orig_delete_at, new_delete_at, expirer_bytes, data_timestamp)) =
            pending_delete_at_update
        {
            if new_delete_at != 0 {
                self.delete_at_update(
                    "PUT",
                    new_delete_at,
                    &drive,
                    &account,
                    &container,
                    &obj,
                    req,
                    policy_index,
                    Some(expirer_bytes),
                    Some(data_timestamp),
                );
            }
            if orig_delete_at != 0 && orig_delete_at != new_delete_at {
                self.delete_at_update(
                    "DELETE",
                    orig_delete_at,
                    &drive,
                    &account,
                    &container,
                    &obj,
                    req,
                    policy_index,
                    None,
                    None,
                );
            }
        }

        // server.py 755-768: when the winning content-type is not the
        // datafile's, the datafile content-type may carry a swift_bytes param
        // (appended by SLO) that must continue to ride the container update.
        let mut update_ctype = resolved_ctype.clone();
        if resolved_ctype_timestamp != data_timestamp {
            let (_, swift_bytes) = extract_swift_bytes(&datafile_content_type);
            if let Some(swift_bytes) = swift_bytes {
                update_ctype.push_str(&format!(";swift_bytes={swift_bytes}"));
            }
        }

        // server.py 770-777: the container update carries the object's
        // ORIGINAL data timestamp as x-timestamp (so the container row's
        // created_at stays at the PUT time), the RESOLVED content-type and
        // content-type timestamp (orig or new, whichever won), and the .meta
        // timestamp as x-meta-timestamp. Object POST updates are PUT to the
        // container.
        let mut update = HeaderKeyDict::new();
        update.set("x-size", content_length);
        update.set("x-content-type", &update_ctype);
        update.set("x-timestamp", data_timestamp.internal());
        update.set(
            "x-content-type-timestamp",
            resolved_ctype_timestamp.internal(),
        );
        update.set("x-meta-timestamp", &meta_timestamp);
        update.set("x-etag", &etag);
        // Python object-server POST restores whole-object listing metadata
        // for EC fragments.  The datafile's Content-Length/ETag describe the
        // fragment archive, while container rows must continue to describe
        // the original object.  Generic persisted container-update overrides
        // are applied after this EC compatibility override, matching
        // server.py `_check_container_override` ordering.
        if let Some(value) = meta_get(&orig_metadata, "X-Object-Sysmeta-Ec-Content-Length") {
            update.set("x-size", value);
        }
        if let Some(value) = meta_get(&orig_metadata, "X-Object-Sysmeta-Ec-Etag") {
            update.set("x-etag", value);
        }
        let mut persisted_headers = HeaderKeyDict::new();
        for (key, value) in &orig_metadata {
            if let (MetaValue::Str(key), MetaValue::Str(value)) = (key, value) {
                persisted_headers.set(key, value);
            }
        }
        apply_container_override(&mut update, &persisted_headers, &[]);
        self.container_update(
            "PUT",
            &drive,
            &account,
            &container,
            &obj,
            req,
            &update,
            policy_index,
        );

        // Python server.py POST: HTTPAccepted plus orig_metadata sysmeta so
        // symlink middleware can see X-Object-Sysmeta-Symlink-* and 307.
        let mut resp = Response::with_body(
            202,
            b"<html><h1>Accepted</h1><p>The request is accepted for processing.</p></html>"
                .to_vec(),
        );
        resp.headers.set("Content-Type", "text/html; charset=UTF-8");
        if !resolved_ctype.is_empty() {
            resp.headers
                .set("X-Backend-Content-Type", resolved_ctype.as_str());
        }
        for (key, value) in orig_sysmeta {
            resp.headers.set(&key, value);
        }
        resp
    }

    fn delete(&self, req: &Request) -> Response {
        let (drive, part, account, container, obj, policy_index, policy) = match self.obj_path(req)
        {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let (resp, do_cu) = self.delete_apply_tombstone(
            req,
            &drive,
            part,
            &account,
            &container,
            &obj,
            policy_index,
            policy,
        );
        if do_cu {
            let req_timestamp = match Self::valid_timestamp(req) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let mut update = HeaderKeyDict::new();
            update.set("x-timestamp", req_timestamp.internal());
            self.container_update(
                "DELETE",
                &drive,
                &account,
                &container,
                &obj,
                req,
                &update,
                policy_index,
            );
        }
        resp
    }

    /// Disk-only half of DELETE. `true` means a tombstone was written and a
    /// container-update must follow (Python `orig_timestamp < req_timestamp`).
    #[allow(clippy::too_many_arguments)]
    fn delete_apply_tombstone(
        &self,
        req: &Request,
        drive: &str,
        part: u64,
        account: &str,
        container: &str,
        obj: &str,
        policy_index: u32,
        policy: PolicyKind,
    ) -> (Response, bool) {
        let req_timestamp = match Self::valid_timestamp(req) {
            Ok(t) => t,
            Err(resp) => return (resp, false),
        };
        if let Err(resp) = self.check_drive(drive) {
            return (resp, false);
        }
        let if_delete_at: Option<Timestamp> = match req.headers.get("X-If-Delete-At") {
            None => None,
            Some(raw) => match raw.parse::<Timestamp>() {
                Ok(t) => Some(t),
                Err(_) => {
                    return (
                        plain_response(400, "Bad X-If-Delete-At header value"),
                        false,
                    )
                }
            },
        };
        let mut df =
            match self.diskfile_for(drive, part, account, container, obj, (policy_index, policy)) {
                Ok(df) => df,
                Err(e) => return (plain_response(500, &e.to_string()), false),
            };
        if if_delete_at.is_some() {
            df = df.with_open_expired(true);
        }
        let mutation_guard = match df.acquire_mutation_lock(OBJECT_MUTATION_LOCK_TIMEOUT) {
            Ok(guard) => guard,
            Err(error) => return (mutation_lock_error_response(error), false),
        };
        let (orig_timestamp, was_live, orig_delete_at, orig_metadata) = match df.open(None) {
            Ok(_) => {
                let ts = df.data_timestamp().unwrap_or_else(|_| "0".parse().unwrap());
                let metadata = match df.get_metadata() {
                    Ok(m) => Some(m.clone()),
                    Err(e) => return (plain_response(500, &e.to_string()), false),
                };
                let delete_at = metadata
                    .as_ref()
                    .and_then(|m| {
                        m.iter().find_map(|(k, v)| {
                            if k.as_str() != Some("X-Delete-At") {
                                return None;
                            }
                            match v {
                                MetaValue::Str(s) => s.parse::<Timestamp>().ok(),
                                MetaValue::Int(i) => i.to_string().parse::<Timestamp>().ok(),
                                _ => None,
                            }
                        })
                    })
                    .unwrap_or_else(|| "0".parse().unwrap());
                (ts, true, delete_at, metadata)
            }
            Err(DiskFileError::Deleted { timestamp, .. }) => {
                (timestamp, false, "0".parse().unwrap(), None)
            }
            Err(DiskFileError::NotExist) | Err(DiskFileError::Quarantined(_)) => {
                ("0".parse().unwrap(), false, "0".parse().unwrap(), None)
            }
            Err(DiskFileError::Expired { metadata }) => {
                let ts = metadata
                    .iter()
                    .find_map(|(k, v)| {
                        if k.as_str() == Some("X-Timestamp") {
                            v.as_str().and_then(|s| s.parse().ok())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| "0".parse().unwrap());
                let delete_at = metadata
                    .iter()
                    .find_map(|(k, v)| {
                        if k.as_str() != Some("X-Delete-At") {
                            return None;
                        }
                        match v {
                            MetaValue::Str(s) => s.parse::<Timestamp>().ok(),
                            MetaValue::Int(i) => i.to_string().parse::<Timestamp>().ok(),
                            _ => None,
                        }
                    })
                    .unwrap_or_else(|| "0".parse().unwrap());
                (ts, true, delete_at, Some(metadata))
            }
            Err(e) => return (plain_response(500, &e.to_string()), false),
        };
        if let Some(response) = put_if_match_precondition(req, was_live, orig_metadata.as_ref()) {
            return (response, false);
        }
        if let Some(response) =
            expected_s3_version_precondition(req, was_live, orig_metadata.as_ref())
        {
            return (response, false);
        }
        if let Some(req_if) = if_delete_at {
            if !was_live {
                let mut resp = swob_response(404);
                resp.headers.set(
                    "X-Backend-Timestamp",
                    orig_timestamp.max(req_timestamp).internal(),
                );
                return (resp, false);
            }
            if orig_timestamp >= req_timestamp {
                let mut resp = swob_response(409);
                resp.headers.set(
                    "X-Backend-Timestamp",
                    orig_timestamp.max(req_timestamp).internal(),
                );
                return (resp, false);
            }
            if orig_delete_at != req_if {
                return (
                    plain_response(412, "X-If-Delete-At and X-Delete-At do not match"),
                    false,
                );
            }
        }
        let response_timestamp = orig_timestamp.max(req_timestamp);
        let response_class = if !was_live {
            404
        } else if orig_timestamp < req_timestamp {
            204
        } else {
            409
        };
        if was_live && orig_timestamp < req_timestamp {
            if let Some(resp) = deny_locked_native_mutation(
                req,
                orig_metadata
                    .as_ref()
                    .map(|meta| Ok::<_, DiskFileError>(meta)),
                self.worm_clock.clock_ok(),
            ) {
                return (resp, false);
            }
        }
        let mut did_cu = false;
        if orig_timestamp < req_timestamp {
            let fresh = match self.diskfile_for(
                drive,
                part,
                account,
                container,
                obj,
                (policy_index, policy),
            ) {
                Ok(df) => df.with_next_part_power(backend_next_part_power(req)),
                Err(e) => return (plain_response(500, &e.to_string()), false),
            };
            if let Err(e) = fresh.delete(&req_timestamp) {
                return (mutation_lock_error_response(e), false);
            }
            did_cu = true;
        }
        drop(mutation_guard);
        let mut resp = match response_class {
            // Swift's swob response keeps the default HTML content type even
            // for an empty successful DELETE body. The Python golden oracle
            // asserts this header on 204 responses.
            204 => swob_response(204),
            404 => swob_response(404),
            _ => swob_response(409),
        };
        resp.headers
            .set("X-Backend-Timestamp", response_timestamp.internal());
        (resp, did_cu)
    }

    fn get(&self, req: &Request, include_body: bool) -> Response {
        let (drive, part, account, container, obj, policy_index, policy) = match self.obj_path(req)
        {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        if let Err(resp) = self.check_drive(&drive) {
            return resp;
        }
        let mut df = match self.diskfile_for(
            &drive,
            part,
            &account,
            &container,
            &obj,
            (policy_index, policy),
        ) {
            Ok(df) => df,
            Err(e) => return plain_response(500, &e.to_string()),
        };
        // Python `allow_open_expired` / `X-Open-Expired: true`: open a file that
        // is past X-Delete-At but has not been reaped yet. Default remains 404.
        let open_expired = req
            .headers
            .get("X-Backend-Open-Expired")
            .is_some_and(config_true_value)
            || req
                .headers
                .get("X-Backend-Replication")
                .is_some_and(config_true_value)
            || req
                .headers
                .get("X-Open-Expired")
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false);
        let frag_prefs = match parse_fragment_preferences(&req.headers, policy) {
            Ok(value) => value,
            Err(resp) => return resp,
        };
        df = df
            .with_frag_prefs(frag_prefs)
            .with_open_expired(open_expired);
        let opened = match df.open(None) {
            Ok(df) => df,
            Err(DiskFileError::Deleted { timestamp, .. }) => {
                let mut resp = swob_response(404);
                resp.headers
                    .set("X-Backend-Timestamp", timestamp.internal());
                return resp;
            }
            // An object past its X-Delete-At reads as expired: Python treats
            // DiskFileExpired as a DiskFileNotExist -> 404 with the object's
            // timestamp echoed back.
            Err(DiskFileError::Expired { metadata }) => {
                let mut resp = swob_response(404);
                if let Some(ts) =
                    meta_get(&metadata, "X-Timestamp").and_then(|s| s.parse::<Timestamp>().ok())
                {
                    resp.headers.set("X-Backend-Timestamp", ts.internal());
                }
                return resp;
            }
            Err(DiskFileError::NotExist) | Err(DiskFileError::Quarantined(_)) => {
                return swob_response(404)
            }
            Err(e) => return plain_response(500, &e.to_string()),
        };

        let metadata = opened.get_metadata().unwrap().clone();
        let obj_size: u64 = meta_get(&metadata, "Content-Length")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let x_ts: Timestamp = meta_get(&metadata, "X-Timestamp")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "0".parse().unwrap());
        let etag = object_etag(&metadata).to_string();
        let content_type = meta_get(&metadata, "Content-Type")
            .unwrap_or("application/octet-stream")
            .to_string();
        let data_ts = opened
            .data_timestamp()
            .map(|t| t.internal())
            .unwrap_or_default();
        let durable_ts = opened.durable_timestamp().ok().flatten();

        // Range handling
        // `X-Backend-Ignore-Range-If-Metadata-Present` (set by the SLO/DLO
        // middlewares): drop the Range when the object carries any of the named
        // metadata — a manifest must always be served whole so the middleware
        // can reassemble, applying the client Range to the assembled object.
        let ignore_range = req
            .headers
            .get("X-Backend-Ignore-Range-If-Metadata-Present")
            .map(|names| {
                names
                    .split(',')
                    .any(|name| meta_get(&metadata, name.trim()).is_some())
            })
            .unwrap_or(false);
        let range_header = if ignore_range {
            None
        } else {
            req.headers.get("Range").map(str::to_string)
        };
        // The response is served from metadata alone; the data file's
        // contents are only opened for a body that will actually stream, so
        // HEAD never reads object data. A GET streams from disk, meaning a
        // corrupt file is detected during/after the stream (quarantine on
        // the reader's EOF/drop) rather than before the response — Python
        // parity.
        let open_reader = |df: &mut DiskFile| match df.reader() {
            Ok(r) => Ok(r),
            Err(e) => Err(plain_response(500, &e.to_string())),
        };
        let (status, body, content_range): (u16, Body, Option<String>) = match range_header
            .as_deref()
            .and_then(|h| Range::parse(h).ok())
            .map(|range| range.ranges_for_length(Some(obj_size)))
        {
            Some(Some(ranges)) if ranges.is_empty() => {
                // Python object 416 keeps identifying headers + Accept-Ranges
                // and returns a short HTML body (swob).
                let body = concat!(
                    "<html><h1>Requested Range Not Satisfiable</h1>",
                    "<p>The Range requested is not available.</p></html>"
                );
                let mut resp = Response::with_body(416, body.as_bytes().to_vec());
                resp.headers
                    .set("Content-Range", format!("bytes */{obj_size}"));
                resp.headers.set("Content-Type", &content_type);
                resp.headers.set("Accept-Ranges", "bytes");
                resp.headers.set("ETag", format!("\"{etag}\""));
                resp.headers.set("Last-Modified", http_date(x_ts.ceil()));
                resp.headers.set("X-Timestamp", x_ts.normal());
                // Python 416 keeps identifying headers so SLO/DLO can see
                // X-Static-Large-Object and retry without Range.
                for (k, v) in &metadata {
                    if let (MetaValue::Str(key), MetaValue::Str(value)) = (k, v) {
                        if is_sys_or_user_meta(key)
                            || is_object_transient_sysmeta(key)
                            || is_allowed_header(key)
                            || key.eq_ignore_ascii_case("X-Delete-At")
                        {
                            resp.headers.set(key, value);
                        }
                    }
                }
                return resp;
            }
            Some(Some(ranges)) if ranges.len() == 1 => {
                let (start, stop) = ranges[0];
                let body = if include_body {
                    let reader = match open_reader(&mut df) {
                        Ok(r) => r,
                        Err(resp) => return resp,
                    };
                    // Python verifies a ranged read when it starts at zero
                    // and reaches EOF. This is observably important for a
                    // range that extends past the object: after normalisation
                    // it is a complete read and must quarantine a bad ETag
                    // before the next request. Partial ranges remain
                    // unverified, matching BaseDiskFileReader.close().
                    let reader: Box<dyn Read + Send> = if start == 0 && stop == obj_size {
                        Box::new(reader.into_stream())
                    } else {
                        Box::new(reader.range_window(start, stop))
                    };
                    Body::from_reader(reader, Some(stop - start))
                } else {
                    Body::empty()
                };
                (
                    206,
                    body,
                    Some(swift_http::content_range_header_value(
                        start, stop, obj_size,
                    )),
                )
            }
            // multiple ranges -> a multipart/byteranges 206 body
            Some(Some(ranges)) => {
                // deterministic 32-hex boundary derived from the object's
                // etag + the requested ranges (unique per response, stable)
                let boundary = {
                    use md5::{Digest, Md5};
                    let mut h = Md5::new();
                    h.update(etag.as_bytes());
                    for (s, e) in &ranges {
                        h.update(s.to_le_bytes());
                        h.update(e.to_le_bytes());
                    }
                    h.finalize()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                };
                // per-part headers byte-identical to
                // swift_http::multipart_byteranges; the exact body length is
                // computed up front from the part sizes so the multipart
                // stream carries a Content-Length
                let part_head = |start: u64, stop: u64| {
                    format!(
                        "--{boundary}\r\nContent-Type: {content_type}\r\nContent-Range: {}\r\n\r\n",
                        swift_http::content_range_header_value(start, stop, obj_size)
                    )
                };
                let terminator = format!("--{boundary}--");
                let total: u64 = ranges
                    .iter()
                    .map(|&(start, stop)| part_head(start, stop).len() as u64 + (stop - start) + 2)
                    .sum::<u64>()
                    + terminator.len() as u64;
                let body = if include_body {
                    let reader = match open_reader(&mut df) {
                        Ok(r) => r,
                        Err(resp) => return resp,
                    };
                    let mut parts: Vec<Box<dyn Read + Send>> = Vec::new();
                    for &(start, stop) in &ranges {
                        parts.push(Box::new(std::io::Cursor::new(
                            part_head(start, stop).into_bytes(),
                        )));
                        parts.push(Box::new(reader.range_window(start, stop)));
                        parts.push(Box::new(std::io::Cursor::new(b"\r\n".to_vec())));
                    }
                    parts.push(Box::new(std::io::Cursor::new(terminator.into_bytes())));
                    Body::from_reader(Box::new(ChainReader::new(parts)), Some(total))
                } else {
                    Body::empty()
                };
                let mut resp = Response::new(206);
                resp.body = body;
                resp.headers.set(
                    "Content-Type",
                    swift_http::multipart_byteranges_content_type(&boundary),
                );
                resp.headers.set("Content-Length", total);
                resp.headers.set("ETag", format!("\"{etag}\""));
                resp.headers.set("Last-Modified", http_date(x_ts.ceil()));
                resp.headers.set("X-Timestamp", x_ts.normal());
                resp.headers.set("Accept-Ranges", "bytes");
                return resp;
            }
            // an unparseable/unsatisfiable-for-length Range is ignored
            _ => {
                let body = if include_body {
                    let reader = match open_reader(&mut df) {
                        Ok(r) => r,
                        Err(resp) => return resp,
                    };
                    Body::from_reader(Box::new(reader.into_stream()), Some(obj_size))
                } else {
                    Body::empty()
                };
                (200, body, None)
            }
        };

        let mut resp = Response::new(status);
        resp.body = body;
        resp.headers.set("Content-Type", &content_type);
        for (k, v) in &metadata {
            if let (MetaValue::Str(key), MetaValue::Str(value)) = (k, v) {
                if is_sys_or_user_meta(key)
                    || is_object_transient_sysmeta(key)
                    || is_allowed_header(key)
                    || key.eq_ignore_ascii_case("X-Delete-At")
                {
                    resp.headers.set(key, value);
                }
            }
        }
        resp.headers.set("ETag", format!("\"{etag}\""));
        resp.headers.set("Last-Modified", http_date(x_ts.ceil()));
        resp.headers.set("X-Timestamp", x_ts.normal());
        resp.headers.set("X-Backend-Timestamp", x_ts.internal());
        resp.headers.set("X-Backend-Data-Timestamp", &data_ts);
        if let Some(durable) = durable_ts {
            resp.headers
                .set("X-Backend-Durable-Timestamp", durable.internal());
        }
        resp.headers.set("Accept-Ranges", "bytes");
        if let Some(cr) = content_range {
            resp.headers.set("Content-Range", cr);
            resp.headers
                .set("Content-Length", resp.body.content_length().unwrap_or(0));
        } else {
            resp.headers.set("Content-Length", obj_size);
        }
        resp
    }

    /// `container_update`: synchronous PUT/DELETE to the container servers
    /// named by X-Container-Host/Partition/Device. Replicas are contacted in
    /// parallel under `container_update_timeout`; any node that cannot be
    /// updated synchronously (unreachable, non-2xx, timeout, or none supplied)
    /// causes an async_pending write so the object-updater daemon replays the
    /// update later — without this, a container listing permanently misses the
    /// object when a container node is down.
    #[allow(clippy::too_many_arguments)]
    fn container_update(
        &self,
        op: &str,
        drive: &str,
        account: &str,
        container: &str,
        obj: &str,
        req: &Request,
        update: &HeaderKeyDict,
        policy_index: u32,
    ) {
        if req
            .headers
            .get("X-Backend-Replication")
            .is_some_and(config_true_value)
        {
            return;
        }
        // L1b: take the container update fully off the PUT/DELETE critical
        // path. Listing lag is bounded by object-updater drain.
        if self.config.container_update_mode == ContainerUpdateMode::Async {
            let pending_path =
                shard_update_account_container(&req.headers).map(|(a, c)| format!("{a}/{c}"));
            self.write_async_pending(
                op,
                drive,
                account,
                container,
                obj,
                update,
                policy_index,
                req.headers.get("X-Container-Root-Db-State"),
                pending_path.as_deref(),
            );
            return;
        }
        let hosts: Vec<&str> = req
            .headers
            .get("X-Container-Host")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let devices: Vec<&str> = req
            .headers
            .get("X-Container-Device")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let partition = req.headers.get("X-Container-Partition").unwrap_or("");
        // Sharded roots: proxy sets X-Backend-Quoted-Container-Path (preferred)
        // or X-Backend-Container-Path to the owning shard so the update hits
        // the shard DB, not the root (Python object-server container_update).
        let shard = shard_update_account_container(&req.headers);
        let (upd_account, upd_container) = shard
            .as_ref()
            .map(|(a, c)| (a.as_str(), c.as_str()))
            .unwrap_or((account, container));
        let path = format!(
            "/{}/{}/{}",
            percent_encode(upd_account),
            percent_encode(upd_container),
            percent_encode(obj)
        );
        let pending_container_path = shard.map(|(a, c)| format!("{a}/{c}"));
        // A well-formed side channel gives matching host/device lists and a
        // partition; otherwise there is nothing to update synchronously and the
        // whole update goes async.
        let well_formed =
            !hosts.is_empty() && hosts.len() == devices.len() && !partition.is_empty();
        let all_ok = if well_formed {
            fanout_container_http(
                op,
                &hosts,
                &devices,
                partition,
                &path,
                update,
                policy_index,
                self.config.container_update_timeout,
                Some(&self.config.hash_config),
            )
        } else {
            false
        };
        if !all_ok {
            self.write_async_pending(
                op,
                drive,
                account,
                container,
                obj,
                update,
                policy_index,
                req.headers.get("X-Container-Root-Db-State"),
                pending_container_path.as_deref(),
            );
        }
    }

    /// Same as [`Self::container_update`] but container HTTP is awaited as
    /// Tokio I/O so a blackhole replica does not pin the network runtime.
    #[allow(clippy::too_many_arguments)]
    async fn container_update_async(
        &self,
        op: &str,
        drive: &str,
        account: &str,
        container: &str,
        obj: &str,
        replication: bool,
        container_host: String,
        container_device: String,
        container_partition: String,
        backend_container_path: Option<String>,
        update: &HeaderKeyDict,
        policy_index: u32,
        db_state: Option<String>,
    ) {
        if replication {
            return;
        }
        if self.config.container_update_mode == ContainerUpdateMode::Async {
            self.write_async_pending(
                op,
                drive,
                account,
                container,
                obj,
                update,
                policy_index,
                db_state.as_deref(),
                backend_container_path.as_deref(),
            );
            return;
        }
        let hosts: Vec<String> = container_host
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let devices: Vec<String> = container_device
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        let partition = container_partition;
        let (upd_account, upd_container) =
            match parse_backend_container_path(backend_container_path.as_deref()) {
                Some((a, c)) => (a.to_string(), c.to_string()),
                None => (account.to_string(), container.to_string()),
            };
        let pending_container_path = backend_container_path.clone();
        let path = format!(
            "/{}/{}/{}",
            percent_encode(&upd_account),
            percent_encode(&upd_container),
            percent_encode(obj)
        );
        let timeout = self.config.container_update_timeout;
        let update = update.clone();
        let op_owned = op.to_string();
        let drive = drive.to_string();
        let account = account.to_string();
        let container = container.to_string();
        let obj = obj.to_string();
        let well_formed =
            !hosts.is_empty() && hosts.len() == devices.len() && !partition.is_empty();
        // Python: one container replica per object replica. Replacing hosts
        // with every shard primary (3×3 CU per DELETE) timed out after shard 0
        // (probe L692 leftover obj-0100+). Trust the proxy host first; ring-
        // lookup the shard only when that fanout fails (path/host mismatch).
        let mut all_ok = if well_formed {
            fanout_container_http_async(
                op_owned.clone(),
                hosts.clone(),
                devices.clone(),
                partition.clone(),
                path.clone(),
                update.clone(),
                policy_index,
                timeout,
                Some(self.config.hash_config.clone()),
            )
            .await
        } else {
            false
        };
        if !all_ok && backend_container_path.is_some() {
            if let Some((part, ring_hosts, ring_devs)) =
                shard_container_ring_targets(&upd_account, &upd_container, &self.config.hash_config)
            {
                if ring_hosts != hosts || part.to_string() != partition {
                    all_ok = fanout_container_http_async(
                        op_owned.clone(),
                        ring_hosts,
                        ring_devs,
                        part.to_string(),
                        path,
                        update.clone(),
                        policy_index,
                        timeout,
                        Some(self.config.hash_config.clone()),
                    )
                    .await;
                }
            }
        }
        if !all_ok {
            self.write_async_pending(
                &op_owned,
                &drive,
                &account,
                &container,
                &obj,
                &update,
                policy_index,
                db_state.as_deref(),
                pending_container_path.as_deref(),
            );
        }
    }

    /// `delete_at_update`: enqueue or remove a task object in the hidden
    /// `.expiring_objects` account as an object's `X-Delete-At` changes. The
    /// task object is
    /// `build_task_obj(delete_at, account, container, obj)` in the hour-bucket
    /// container `get_expirer_container(delete_at)`; it is sent to the expirer
    /// container replicas named by `X-Delete-At-Host/Partition/Device`, falling
    /// back to an async_pending like any other container update.
    #[allow(clippy::too_many_arguments)]
    fn delete_at_update(
        &self,
        op: &str,
        delete_at: i64,
        drive: &str,
        account: &str,
        container: &str,
        obj: &str,
        req: &Request,
        _policy_index: u32,
        expirer_bytes: Option<u64>,
        content_type_timestamp: Option<String>,
    ) {
        if req
            .headers
            .get("X-Backend-Replication")
            .is_some_and(config_true_value)
        {
            return;
        }
        let task_account = crate::expirer::EXPIRER_ACCOUNT_NAME;
        let expected_task_container = self
            .config
            .hash_config
            .hash_path(account, Some(container), Some(obj))
            .ok()
            .map(|object_hash| {
                crate::expirer::get_expirer_container_for_object_hash(
                    delete_at,
                    &object_hash,
                    crate::expirer::EXPIRER_CONTAINER_DIVISOR,
                    crate::expirer::EXPIRER_CONTAINER_PER_DIVISOR,
                )
            })
            .unwrap_or_else(|| {
                crate::expirer::get_expirer_container(
                    delete_at,
                    crate::expirer::EXPIRER_CONTAINER_DIVISOR,
                )
            });
        // For PUT, the proxy's container name and partition/device headers
        // are one routing tuple and must never be mixed with our fallback.
        // DELETE cleanup is intentionally recomputed from the old delete-at,
        // matching Python's direct-to-async_pending branch.
        let task_container = if op != "DELETE" {
            req.headers
                .get("X-Delete-At-Container")
                .and_then(parse_int_like)
                .map(|value| crate::expirer::normalize_delete_at_timestamp(value as i64))
                .unwrap_or(expected_task_container)
        } else {
            expected_task_container
        };
        let task_obj = crate::expirer::build_task_obj(delete_at, account, container, obj);

        if op == "DELETE"
            && req
                .headers
                .get("X-Backend-Clean-Expiring-Object-Queue")
                .is_some_and(|value| !config_true_value(value))
        {
            return;
        }

        let mut update = HeaderKeyDict::new();
        update.set("x-timestamp", req.headers.get("X-Timestamp").unwrap_or("0"));
        if op != "DELETE" {
            // The expiry queue entry is an empty marker object, while the
            // content-type carries the size of the real object for expirer
            // accounting (expirer.embed_expirer_bytes_in_ctype).
            update.set("x-size", "0");
            update.set(
                "x-content-type",
                format!(
                    "text/plain;swift_expirer_bytes={}",
                    expirer_bytes.unwrap_or(0)
                ),
            );
            update.set("x-etag", "d41d8cd98f00b204e9800998ecf8427e"); // md5("")
            if let Some(timestamp) = content_type_timestamp.as_deref() {
                update.set("x-content-type-timestamp", timestamp);
            }
        }

        let hosts: Vec<&str> = req
            .headers
            .get("X-Delete-At-Host")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let devices: Vec<&str> = req
            .headers
            .get("X-Delete-At-Device")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let partition = req.headers.get("X-Delete-At-Partition").unwrap_or("");
        let path = format!(
            "/{}/{}/{}",
            percent_encode(task_account),
            percent_encode(&task_container),
            percent_encode(&task_obj)
        );
        // Python sends DELETE cleanup through async_pending unconditionally;
        // only a PUT may fan out directly to proxy-selected container nodes.
        let well_formed = op != "DELETE"
            && !hosts.is_empty()
            && hosts.len() == devices.len()
            && !partition.is_empty();
        let all_ok = if well_formed {
            fanout_container_http(
                op,
                &hosts,
                &devices,
                partition,
                &path,
                &update,
                0,
                self.config.container_update_timeout,
                None,
            )
        } else {
            false
        };
        if !all_ok {
            // enqueue via async_pending against the object's own device;
            // storage policy 0 is the expirer account's policy.
            self.write_async_pending(
                op,
                drive,
                task_account,
                &task_container,
                &task_obj,
                &update,
                0,
                None,
                None,
            );
        }
    }

    /// Write an async_pending pickle for a container update that could not be
    /// applied synchronously, byte-compatible with Python `pickle_async_update`
    /// and with what `updater::AsyncUpdate::parse` consumes:
    /// `{'op','account','container','obj','headers'}` at
    /// `<device>/async_pending[-<policy>]/<suffix>/<ohash>-<timestamp>`.
    ///
    /// Durability mirrors `diskfile.pickle_async_update` (diskfile.py
    /// 1468-1492) + `swift.common.utils.pickle.write_pickle`: the pickle is
    /// staged in the DEVICE tmp dir (the same tmp dir diskfile `create` uses,
    /// never inside the scanned async dir), fsynced before the rename, and the
    /// rename fsyncs the destination's parent dir. Failures are never silent:
    /// a dropped async_pending permanently desyncs the container listing.
    #[allow(clippy::too_many_arguments)]
    fn write_async_pending(
        &self,
        op: &str,
        drive: &str,
        account: &str,
        container: &str,
        obj: &str,
        update: &HeaderKeyDict,
        policy_index: u32,
        db_state: Option<&str>,
        container_path: Option<&str>,
    ) {
        use swift_core::pickle::{dumps, Value};
        let ohash = match self
            .config
            .hash_config
            .hash_path(account, Some(container), Some(obj))
        {
            Ok(ohash) => ohash,
            Err(e) => {
                eprintln!(
                    "ERROR async_pending: hash_path failed for /{account}/{container}/{obj}: {e}"
                );
                return;
            }
        };
        // Python normalizes the filename timestamp: Timestamp(timestamp).internal
        let timestamp = match update
            .get("x-timestamp")
            .unwrap_or("0")
            .parse::<Timestamp>()
        {
            Ok(t) => t.internal(),
            Err(_) => {
                eprintln!(
                    "ERROR async_pending: bad x-timestamp {:?}, dropping update for \
                     /{account}/{container}/{obj}",
                    update.get("x-timestamp")
                );
                return;
            }
        };
        let mut headers: Vec<(Value, Value)> = update
            .iter()
            .map(|(k, v)| (Value::Str(k.to_string()), Value::Str(v.to_string())))
            .collect();
        headers.push((
            Value::Str("X-Backend-Storage-Policy-Index".into()),
            Value::Str(policy_index.to_string()),
        ));
        let mut pairs = vec![
            (Value::Str("op".into()), Value::Str(op.to_string())),
            (
                Value::Str("account".into()),
                Value::Str(account.to_string()),
            ),
            (
                Value::Str("container".into()),
                Value::Str(container.to_string()),
            ),
            (Value::Str("obj".into()), Value::Str(obj.to_string())),
            (Value::Str("headers".into()), Value::Dict(headers)),
        ];
        // Python pickle_async_update always stores db_state (obj.py async_update).
        // Probe test_async_pendings asserts the key exists with the container's
        // X-Container-Root-Db-State (`unsharded` until the sharder runs).
        if let Some(state) = db_state {
            pairs.push((Value::Str("db_state".into()), Value::Str(state.to_string())));
        }
        // Python pickle_async_update stores container_path so the updater
        // talks to the shard, not the root (probe L1435 nested DELETE).
        if let Some(path) = container_path.filter(|p| !p.is_empty()) {
            pairs.push((
                Value::Str("container_path".into()),
                Value::Str(path.to_string()),
            ));
        }
        let data = Value::Dict(pairs);
        let bytes = match dumps(&data) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!(
                    "ERROR async_pending: pickle failed for /{account}/{container}/{obj}: {e}"
                );
                return;
            }
        };
        let device_path = self.config.devices.join(drive);
        let async_dir = device_path.join(swift_diskfile::get_async_dir(policy_index));
        let tmp_dir = device_path.join(swift_diskfile::get_tmp_dir(policy_index));
        let suffix = &ohash[ohash.len().saturating_sub(3)..];
        let dest = async_dir.join(suffix).join(format!("{ohash}-{timestamp}"));
        // write_pickle stages in tmp_dir, fsyncs the file, then renames into
        // place (creating the suffix dir and fsyncing it).
        if let Err(e) = swift_diskfile::write_pickle(&bytes, &dest, &tmp_dir) {
            eprintln!(
                "ERROR async_pending: write failed for {}: {e}",
                dest.display()
            );
        }
    }
}

/// Parse `X-Backend-Container-Path` as `account/container` or `/account/container`.
fn parse_backend_container_path(raw: Option<&str>) -> Option<(&str, &str)> {
    let s = raw?.trim().trim_start_matches('/');
    if s.is_empty() {
        return None;
    }
    let (a, c) = s.split_once('/')?;
    if a.is_empty() || c.is_empty() {
        return None;
    }
    Some((a, c))
}

/// Python object-server prefers `X-Backend-Quoted-Container-Path` (unquoted)
/// then `X-Backend-Container-Path`.
fn shard_update_account_container(headers: &HeaderKeyDict) -> Option<(String, String)> {
    let decoded;
    let raw = if let Some(quoted) = headers.get("X-Backend-Quoted-Container-Path") {
        decoded = percent_decode(quoted);
        Some(decoded.as_str())
    } else {
        headers.get("X-Backend-Container-Path")
    };
    parse_backend_container_path(raw).map(|(a, c)| (a.to_string(), c.to_string()))
}

#[derive(Debug)]
enum CuHostResult {
    Ok,
    Redirect(String),
    Fail,
}

/// Fire one container-server update over a fresh TCP connection, honouring
/// `timeout` for connect + read (Python `container_update_timeout`).
#[allow(clippy::too_many_arguments)]
/// Python object-server `container_update` / `async_update` does **not**
/// stamp `X-Backend-Accept-Redirect`. Only the object-updater does. Sending
/// it here 301s sync DELETEs off a still-unsharded root (which already has
/// CREATED shard ranges) into those shards, so `is_deleted()` stays false
/// (probe unsharded_deleted_root L4095).
fn sync_container_http(
    op: &str,
    host: &str,
    device: &str,
    partition: &str,
    path: &str,
    update: &HeaderKeyDict,
    policy_index: u32,
    timeout: std::time::Duration,
) -> CuHostResult {
    let Ok(addr) = host.parse::<std::net::SocketAddr>() else {
        return CuHostResult::Fail;
    };
    let mut request = format!(
        "{op} /{device}/{partition}{path} HTTP/1.1\r\nHost: {host}\r\n\
         X-Backend-Storage-Policy-Index: {policy_index}\r\n\
         X-Backend-Allow-Reserved-Names: true\r\n"
    );
    for (k, v) in update.iter() {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    match std::net::TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut conn) => {
            conn.set_nodelay(true).ok();
            let _ = conn.set_read_timeout(Some(timeout));
            let _ = conn.set_write_timeout(Some(timeout));
            let mut buf = Vec::new();
            if conn.write_all(request.as_bytes()).is_err() || conn.read_to_end(&mut buf).is_err() {
                return CuHostResult::Fail;
            }
            cu_host_result(&buf)
        }
        Err(_) => CuHostResult::Fail,
    }
}

fn cu_host_result(buf: &[u8]) -> CuHostResult {
    let text = String::from_utf8_lossy(buf);
    let mut lines = text.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    if (200..300).contains(&status) {
        return CuHostResult::Ok;
    }
    if status == 301 {
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                if k.eq_ignore_ascii_case("location") {
                    let loc = v.trim();
                    if !loc.is_empty() {
                        return CuHostResult::Redirect(loc.to_string());
                    }
                }
            }
        }
    }
    CuHostResult::Fail
}

/// Parse a container-server 301 `Location` `/account/container/obj`.
fn parse_shard_redirect_location(location: &str) -> Option<(String, String, String)> {
    let decoded = percent_decode(location.trim());
    let s = decoded.trim_start_matches('/');
    let (acct, rest) = s.split_once('/')?;
    let (cont, obj) = rest.split_once('/')?;
    if acct.is_empty() || cont.is_empty() || obj.is_empty() {
        return None;
    }
    Some((acct.to_string(), cont.to_string(), obj.to_string()))
}

fn load_container_ring(hash_config: &HashPathConfig) -> Option<swift_ring::Ring> {
    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    let data = swift_ring::RingData::load(std::path::Path::new(&format!(
        "{swift_dir}/container.ring.gz"
    )))
    .ok()?;
    Some(swift_ring::Ring::new(data, hash_config.clone()))
}

/// Primary container-ring nodes for a resolved shard account/container.
fn shard_container_ring_targets(
    account: &str,
    container: &str,
    hash_config: &HashPathConfig,
) -> Option<(u32, Vec<String>, Vec<String>)> {
    let ring = load_container_ring(hash_config)?;
    let (part, nodes) = ring.get_nodes(account, Some(container), None).ok()?;
    if nodes.is_empty() {
        return None;
    }
    let hosts: Vec<String> = nodes
        .iter()
        .map(|n| format!("{}:{}", n.dev.ip, n.dev.port))
        .collect();
    let devices: Vec<String> = nodes.iter().map(|n| n.dev.device.clone()).collect();
    Some((part, hosts, devices))
}

/// Python updater applies 301 `Location` `/account/container/obj` via the
/// container ring. Do it synchronously so probe L1435 does not wait for the
/// updater interval.
fn follow_shard_redirect(
    location: &str,
    op: &str,
    update: &HeaderKeyDict,
    policy_index: u32,
    timeout: std::time::Duration,
    hash_config: &HashPathConfig,
) -> bool {
    let Some((acct, cont, obj)) = parse_shard_redirect_location(location) else {
        return false;
    };
    let Some(ring) = load_container_ring(hash_config) else {
        return false;
    };
    let Ok((part, nodes)) = ring.get_nodes(&acct, Some(&cont), None) else {
        return false;
    };
    if nodes.is_empty() {
        return false;
    }
    let path = format!(
        "/{}/{}/{}",
        percent_encode(&acct),
        percent_encode(&cont),
        percent_encode(&obj)
    );
    let hosts: Vec<String> = nodes
        .iter()
        .map(|n| format!("{}:{}", n.dev.ip, n.dev.port))
        .collect();
    let devices: Vec<String> = nodes.iter().map(|n| n.dev.device.clone()).collect();
    let host_refs: Vec<&str> = hosts.iter().map(|s| s.as_str()).collect();
    let dev_refs: Vec<&str> = devices.iter().map(|s| s.as_str()).collect();
    fanout_container_http(
        op,
        &host_refs,
        &dev_refs,
        &part.to_string(),
        &path,
        update,
        policy_index,
        timeout,
        None,
    )
}

/// Async twin of [`follow_shard_redirect`]: live Hyper PUT uses
/// `container_update_async`, so a CLEAVED-root 301 must be followed on the
/// Tokio path (probe test_sharding_listing L631).
async fn follow_shard_redirect_async(
    location: &str,
    op: String,
    update: HeaderKeyDict,
    policy_index: u32,
    timeout: std::time::Duration,
    hash_config: &HashPathConfig,
) -> bool {
    let Some((acct, cont, obj)) = parse_shard_redirect_location(location) else {
        return false;
    };
    let Some(ring) = load_container_ring(hash_config) else {
        return false;
    };
    let Ok((part, nodes)) = ring.get_nodes(&acct, Some(&cont), None) else {
        return false;
    };
    if nodes.is_empty() {
        return false;
    }
    let path = format!(
        "/{}/{}/{}",
        percent_encode(&acct),
        percent_encode(&cont),
        percent_encode(&obj)
    );
    let hosts: Vec<String> = nodes
        .iter()
        .map(|n| format!("{}:{}", n.dev.ip, n.dev.port))
        .collect();
    let devices: Vec<String> = nodes.iter().map(|n| n.dev.device.clone()).collect();
    fanout_container_http_async_once(
        op,
        hosts,
        devices,
        part.to_string(),
        path,
        update,
        policy_index,
        timeout,
    )
    .await
    .iter()
    .all(|r| matches!(r, CuHostResult::Ok))
}

/// Contact every container replica in parallel. Returns true only when every
/// replica accepts the update inside `timeout`. A 301 from a SHARDED root is
/// followed once via the container ring (`hash_config` set).
#[allow(clippy::too_many_arguments)]
fn fanout_container_http(
    op: &str,
    hosts: &[&str],
    devices: &[&str],
    partition: &str,
    path: &str,
    update: &HeaderKeyDict,
    policy_index: u32,
    timeout: std::time::Duration,
    hash_config: Option<&HashPathConfig>,
) -> bool {
    if hosts.is_empty() || hosts.len() != devices.len() {
        return false;
    }
    // Owned copies so worker threads do not borrow the request-scoped strs
    // across a join that outlives the loop body.
    let jobs: Vec<(String, String)> = hosts
        .iter()
        .zip(devices.iter())
        .map(|(h, d)| ((*h).to_string(), (*d).to_string()))
        .collect();
    let op = op.to_string();
    let partition = partition.to_string();
    let path = path.to_string();
    // HeaderKeyDict is not Sync-cloned cheaply; rebuild the wire headers once
    // and share the rendered pairs.
    let header_pairs: Vec<(String, String)> = update
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let results: Vec<CuHostResult> = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(jobs.len());
        for (host, device) in &jobs {
            let op = op.as_str();
            let partition = partition.as_str();
            let path = path.as_str();
            let header_pairs = &header_pairs;
            handles.push(scope.spawn(move || {
                let mut hdrs = HeaderKeyDict::new();
                for (k, v) in header_pairs {
                    hdrs.set(k, v);
                }
                sync_container_http(
                    op,
                    host,
                    device,
                    partition,
                    path,
                    &hdrs,
                    policy_index,
                    timeout,
                )
            }));
        }
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or(CuHostResult::Fail))
            .collect()
    });
    // Python object-server contacts each container replica independently.
    // One 301 must not skip the still-unsharded root (L4095 live rows).
    if op == "DELETE" {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/log/g6-rust/w254-cu.log")
        {
            use std::io::Write;
            let _ = writeln!(
                f,
                "sync {op} hosts={hosts:?} devices={devices:?} results={results:?}"
            );
        }
    }
    if results.iter().all(|r| matches!(r, CuHostResult::Ok)) {
        return true;
    }
    let mut all_ok = true;
    for r in &results {
        match r {
            CuHostResult::Ok => {}
            CuHostResult::Redirect(loc) => {
                if let Some(cfg) = hash_config {
                    if !follow_shard_redirect(loc, &op, update, policy_index, timeout, cfg) {
                        all_ok = false;
                    }
                } else {
                    all_ok = false;
                }
            }
            CuHostResult::Fail => all_ok = false,
        }
    }
    all_ok
}

async fn fanout_container_http_async(
    op: String,
    hosts: Vec<String>,
    devices: Vec<String>,
    partition: String,
    path: String,
    update: HeaderKeyDict,
    policy_index: u32,
    timeout: std::time::Duration,
    hash_config: Option<HashPathConfig>,
) -> bool {
    if hosts.is_empty() || hosts.len() != devices.len() {
        return false;
    }
    let results = fanout_container_http_async_once(
        op.clone(),
        hosts.clone(),
        devices.clone(),
        partition,
        path.clone(),
        update.clone(),
        policy_index,
        timeout,
    )
    .await;
    if op == "DELETE" {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/log/g6-rust/w254-cu.log")
        {
            use std::io::Write;
            let _ = writeln!(
                f,
                "async {op} hosts={hosts:?} devices={devices:?} results={results:?}"
            );
        }
    }
    if results.iter().all(|r| matches!(r, CuHostResult::Ok)) {
        return true;
    }
    let mut all_ok = true;
    for r in &results {
        match r {
            CuHostResult::Ok => {}
            CuHostResult::Redirect(loc) => {
                if let Some(cfg) = hash_config.as_ref() {
                    if !follow_shard_redirect_async(
                        loc,
                        op.clone(),
                        update.clone(),
                        policy_index,
                        timeout,
                        cfg,
                    )
                    .await
                    {
                        all_ok = false;
                    }
                } else {
                    all_ok = false;
                }
            }
            CuHostResult::Fail => all_ok = false,
        }
    }
    all_ok
}

async fn fanout_container_http_async_once(
    op: String,
    hosts: Vec<String>,
    devices: Vec<String>,
    partition: String,
    path: String,
    update: HeaderKeyDict,
    policy_index: u32,
    timeout: std::time::Duration,
) -> Vec<CuHostResult> {
    if hosts.is_empty() || hosts.len() != devices.len() {
        return vec![CuHostResult::Fail];
    }
    let mut join = tokio::task::JoinSet::new();
    for (host, device) in hosts.into_iter().zip(devices) {
        let op = op.clone();
        let partition = partition.clone();
        let path = path.clone();
        let update = update.clone();
        join.spawn(async move {
            async_container_http(
                &op,
                &host,
                &device,
                &partition,
                &path,
                &update,
                policy_index,
                timeout,
            )
            .await
        });
    }
    let mut results: Vec<CuHostResult> = Vec::new();
    while let Some(r) = join.join_next().await {
        results.push(r.unwrap_or(CuHostResult::Fail));
    }
    results
}

async fn async_container_http(
    op: &str,
    host: &str,
    device: &str,
    partition: &str,
    path: &str,
    update: &HeaderKeyDict,
    policy_index: u32,
    timeout: std::time::Duration,
) -> CuHostResult {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Ok(addr) = host.parse::<std::net::SocketAddr>() else {
        return CuHostResult::Fail;
    };
    let mut request = format!(
        "{op} /{device}/{partition}{path} HTTP/1.1\r\nHost: {host}\r\n\
         X-Backend-Storage-Policy-Index: {policy_index}\r\n\
         X-Backend-Allow-Reserved-Names: true\r\n"
    );
    for (k, v) in update.iter() {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    let Ok(Ok(mut stream)) =
        tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await
    else {
        return CuHostResult::Fail;
    };
    let _ = stream.set_nodelay(true);
    if tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
        .await
        .ok()
        .and_then(Result::ok)
        .is_none()
    {
        return CuHostResult::Fail;
    }
    let _ = tokio::time::timeout(timeout, stream.flush()).await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(timeout, stream.read_to_end(&mut buf)).await;
    cu_host_result(&buf)
}

pub(crate) fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(b as char)
            }
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            ) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Python object-server defaults `replication_failure_threshold` /
/// `replication_failure_ratio`: hang up the updates phase early once failures
/// pass the threshold and the failure:success ratio.
const REPLICATION_FAILURE_THRESHOLD: usize = 100;
const REPLICATION_FAILURE_RATIO: f64 = 1.0;

/// One HTTP chunk (`<len hex>\r\n<payload>\r\n`), flushed — the receiver
/// declares `Transfer-Encoding: chunked` and eventlet frames every yield as
/// its own chunk. An empty payload writes the `0\r\n\r\n` terminator.
fn write_chunk(wire: &mut dyn Write, payload: &[u8]) -> std::io::Result<()> {
    write!(wire, "{:x}\r\n", payload.len())?;
    wire.write_all(payload)?;
    wire.write_all(b"\r\n")?;
    wire.flush()
}

/// Close enough to Python `repr()` of an ASCII str for the ssync `:ERROR:`
/// lines: single-quoted, backslash escapes for the quote, backslash and
/// control bytes.
fn python_repr(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

/// `ssync_receiver.encode_wanted`: compare the remote offer against the
/// local diskfile state and produce the `<hash> <parts>` wanted line
/// (`parts` from 'd'/'m', sorted), or `None` when in sync.
fn encode_wanted(remote: &MissingOffer, local: &LocalSsyncTimestamps) -> Option<String> {
    let mut want_data = false;
    let mut want_meta = false;
    match local.data {
        Some(local_data) => {
            // we have something, let's get just the right stuff
            if remote.ts_data > local_data {
                want_data = true;
            }
            if local
                .meta
                .is_some_and(|local_meta| remote.ts_meta > local_meta)
            {
                want_meta = true;
            }
            if local.ctype.is_some_and(|local_ctype| {
                remote.ts_ctype > local_ctype && remote.ts_ctype > remote.ts_data
            }) {
                want_meta = true;
            }
        }
        None => {
            // we got nothing, so we'll take whatever the remote has
            want_data = true;
            want_meta = true;
        }
    }
    let parts = match (want_data, want_meta) {
        (true, true) => "dm",
        (true, false) => "d",
        (false, true) => "m",
        (false, false) => return None,
    };
    Some(format!("{} {parts}", remote.object_hash))
}

/// One hijacked SSYNC exchange (`ssync_receiver.Receiver.__call__` after
/// `initialize_request`): all validation already passed, the response head is
/// on the wire, and this drives the chunked body in both directions.
struct SsyncSession<'a> {
    server: &'a ObjectServer,
    device: String,
    /// Partition path segment (already validated as an integer).
    partition: String,
    policy_index: u32,
    policy: PolicyKind,
    frag_index: Option<i64>,
}

impl SsyncSession<'_> {
    fn run(&self, reader: &mut dyn Read, wire: &mut dyn Write) -> std::io::Result<()> {
        // Python's first yield: a bare b'\r\n' to kick wsgi into sending the
        // response head before the exchange starts.
        write_chunk(wire, b"\r\n")?;
        let mut parser = SsyncParser::new();
        let mut wanted: Vec<String> = Vec::new();
        let mut buf = vec![0u8; STREAM_CHUNK];
        // ---- missing check: read offers, compare against local state ----
        let mut missing_done = false;
        while !missing_done {
            let n = match reader.read(&mut buf) {
                // The client hung up mid-request: drop the connection without
                // an in-band error, like Python's SsyncClientDisconnected /
                // ChunkReadError paths.
                Ok(0) | Err(_) => return Ok(()),
                Ok(n) => n,
            };
            let events = match parser.push(&buf[..n]) {
                Ok(events) => events,
                Err(error) => return self.in_band_error(wire, 0, error.message()),
            };
            for event in events {
                match event {
                    SsyncEvent::Missing(offer) => {
                        if let Some(line) = self.check_missing(&offer) {
                            wanted.push(line);
                        }
                    }
                    SsyncEvent::MissingEnd => missing_done = true,
                    // The parser pauses at MissingEnd until start_updates().
                    _ => unreachable!("update event before start_updates"),
                }
            }
            if let Some(error) = parser.failure() {
                let message = error.message().to_string();
                return self.in_band_error(wire, 0, &message);
            }
        }
        // The exact frames Python yields from missing_check().
        write_chunk(wire, b":MISSING_CHECK: START\r\n")?;
        if !wanted.is_empty() {
            write_chunk(wire, wanted.join("\r\n").as_bytes())?;
        }
        write_chunk(wire, b"\r\n")?;
        write_chunk(wire, b":MISSING_CHECK: END\r\n")?;
        // ---- updates: apply each subrequest as it arrives ----
        let mut successes = 0usize;
        let mut failures = 0usize;
        let mut updates_done = false;
        let mut events = match parser.start_updates() {
            Ok(events) => events,
            Err(error) => return self.in_band_error(wire, 0, error.message()),
        };
        loop {
            for event in events {
                match event {
                    SsyncEvent::Update(update) => {
                        let response = self.server.apply_ssync_update(
                            &self.device,
                            &self.partition,
                            self.policy_index,
                            self.frag_index,
                            update,
                        );
                        if (200..300).contains(&response.status) || response.status == 404 {
                            successes += 1;
                        } else {
                            failures += 1;
                        }
                        if failures >= REPLICATION_FAILURE_THRESHOLD
                            && (successes == 0
                                || failures as f64 / successes as f64 > REPLICATION_FAILURE_RATIO)
                        {
                            return self.in_band_error(
                                wire,
                                0,
                                &format!("Too many {failures} failures to {successes} successes"),
                            );
                        }
                    }
                    SsyncEvent::UpdatesEnd => updates_done = true,
                    _ => unreachable!("missing event after start_updates"),
                }
            }
            if let Some(error) = parser.failure() {
                // Subrequests parsed before the bad line were already applied
                // (Python routes each as it arrives); now convey the error.
                let message = error.message().to_string();
                return self.in_band_error(wire, 0, &message);
            }
            if updates_done {
                break;
            }
            let n = match reader.read(&mut buf) {
                Ok(0) | Err(_) => return Ok(()),
                Ok(n) => n,
            };
            events = match parser.push(&buf[..n]) {
                Ok(events) => events,
                Err(error) => return self.in_band_error(wire, 0, error.message()),
            };
        }
        if failures != 0 {
            // Python raises HTTPInternalServerError; __call__ formats the
            // response's *byte* body with %r, hence the b'...' repr.
            let body =
                format!("ERROR: With :UPDATES: {failures} failures to {successes} successes");
            write_chunk(
                wire,
                format!(":ERROR: 500 b{}\n", python_repr(&body)).as_bytes(),
            )?;
            write_chunk(wire, b"")?;
            return Ok(());
        }
        write_chunk(wire, b":UPDATES: START\r\n")?;
        write_chunk(wire, b":UPDATES: END\r\n")?;
        write_chunk(wire, b"")?;
        // Read out what remains of the request body (normally just the
        // sender's terminal chunk, sent after it reads the frames above), so
        // closing does not RST the final frames off the sender's socket.
        let mut drained = 0usize;
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            drained += n;
            if drained > 64 * 1024 {
                break;
            }
        }
        Ok(())
    }

    /// `Receiver._check_missing`: decode was done by the parser; compare and
    /// encode the wanted line.
    fn check_missing(&self, remote: &MissingOffer) -> Option<String> {
        let local = self.check_local(remote, true);
        encode_wanted(remote, &local)
    }

    /// `Receiver._check_local`: local diskfile state for one offer, with the
    /// EC non-durable fix-ups (commit a local non-durable frag the remote has
    /// durably, or mask an offer we already hold non-durably).
    fn check_local(&self, remote: &MissingOffer, make_durable: bool) -> LocalSsyncTimestamps {
        let device_path = self.server.config.devices.join(&self.device);
        let partition: u64 = self.partition.parse().unwrap_or(0);
        let hash_dir = device_path.join(storage_directory(
            Path::new(&get_data_dir(self.policy_index)),
            partition,
            &remote.object_hash,
        ));
        let mut diskfile = DiskFile::from_hash_dir(
            &device_path,
            &hash_dir,
            self.policy,
            self.policy_index,
            &self.server.config.hash_config,
            self.server.config.diskfile.clone(),
        )
        .with_frag_index(self.frag_index)
        .with_open_expired(true);
        let mut result = match diskfile.open(None) {
            Ok(opened) => LocalSsyncTimestamps {
                data: opened.data_timestamp().ok(),
                meta: opened.timestamp().ok(),
                ctype: opened.content_type_timestamp().ok(),
            },
            Err(DiskFileError::Deleted { timestamp, .. }) => LocalSsyncTimestamps {
                data: Some(timestamp),
                ..LocalSsyncTimestamps::default()
            },
            // e.g. a non-durable EC frag; Python treats any other diskfile
            // error as an absent local object.
            Err(_) => LocalSsyncTimestamps::default(),
        };
        // The EC durable fix-up. Python evaluates this via df.fragments /
        // df.durable_timestamp, which survive an open() exception; Rust's
        // DiskFile drops its state on failure, so recompute the on-disk info
        // directly. Replication diskfiles have no fragment sets (df.fragments
        // is None in Python), so this is EC-only either way.
        let Some(frag_index) = self.frag_index else {
            return result;
        };
        if !matches!(self.policy, PolicyKind::Ec { .. }) {
            return result;
        }
        let files: Vec<String> = match std::fs::read_dir(&hash_dir) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => return result,
        };
        let Ok(ondisk) = swift_diskfile::get_ondisk_files(
            &files,
            &hash_dir,
            true,
            self.policy,
            Some(frag_index),
            None,
        ) else {
            return result;
        };
        let durable_older = match ondisk.durable_frag_set_ts {
            None => true,
            Some(durable_ts) => durable_ts < remote.ts_data,
        };
        let have_offered_frag = ondisk.frag_sets.iter().any(|(ts, set)| {
            *ts == remote.ts_data && set.iter().any(|info| info.frag_index == Some(frag_index))
        });
        if durable_older && have_offered_frag {
            // The remote is offering a fragment that we already have but is
            // *newer* than anything *durable* that we have
            if remote.durable {
                // We have the frag, just missing durable state, so make the
                // frag durable now. Try this just once to avoid looping.
                if make_durable
                    && self.commit_frag(&diskfile, &hash_dir, &remote.ts_data, frag_index)
                {
                    return self.check_local(remote, false);
                }
                // commit failed: fall back to wanting a full update
            } else {
                // We have the non-durable frag that is on offer, but our
                // ts_data may currently be an older durable frag; bump it so
                // the remote frag is not wanted.
                result.data = Some(remote.ts_data);
            }
        }
        result
    }

    /// `ECDiskFileWriter.commit` for a fragment that is already on disk:
    /// rename `<ts>#<fi>.data` to its durable `#d` name, fsync the hash dir,
    /// clean up obsolete files.
    fn commit_frag(
        &self,
        diskfile: &DiskFile,
        hash_dir: &Path,
        timestamp: &Timestamp,
        frag_index: i64,
    ) -> bool {
        // The enclosing SSYNC session already holds the partition's
        // `.lock-replication`.  Keep the global lock order here:
        // replication -> object mutation stripe -> partition hash lock.
        // This prevents a missing-check durable promotion from racing a
        // foreground PUT/POST/DELETE for the same object while still allowing
        // unrelated objects in the partition to proceed.
        let Ok(_mutation_guard) = diskfile.acquire_mutation_lock(OBJECT_MUTATION_LOCK_TIMEOUT)
        else {
            return false;
        };
        let (Ok(src), Ok(dst)) = (
            make_ec_ondisk_filename(timestamp, frag_index, false),
            make_ec_ondisk_filename(timestamp, frag_index, true),
        ) else {
            return false;
        };
        if std::fs::rename(hash_dir.join(&src), hash_dir.join(&dst)).is_err() {
            return false;
        }
        if let Ok(dir) = std::fs::File::open(hash_dir) {
            let _ = dir.sync_all();
        }
        let Some(suffix_dir) = hash_dir.parent() else {
            return false;
        };
        if invalidate_hash(suffix_dir).is_err() {
            return false;
        }
        let _ = swift_diskfile::cleanup_ondisk_files(
            hash_dir,
            self.policy,
            &self.server.config.diskfile.cleanup,
        );
        true
    }

    /// Python `Receiver.__call__`'s exception-to-body translation: an
    /// `:ERROR: <status> <repr>\n` line inside the 200 body, then the chunked
    /// terminator.
    fn in_band_error(
        &self,
        wire: &mut dyn Write,
        status: u16,
        message: &str,
    ) -> std::io::Result<()> {
        write_chunk(
            wire,
            format!(":ERROR: {status} {}\n", python_repr(message)).as_bytes(),
        )?;
        write_chunk(wire, b"")
    }
}

struct ObjectAsyncService(std::sync::Arc<ObjectServer>);

impl AsyncService for ObjectAsyncService {
    fn supports_object_mime_interim(&self) -> bool {
        true
    }

    fn call(&self, req: AsyncRequest) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move { self.0.handle_async(req).await })
    }
}

pub fn serve(listener: std::net::TcpListener, config: ObjectServerConfig) -> std::io::Result<()> {
    serve_with_config(
        listener,
        ObjectServer::new(config),
        swift_http::ServerConfig::default(),
    )
}

/// Like [`serve`], but with a caller-built server (carrying e.g. a
/// `fallocate_reserve`) and an explicit HTTP server config (worker sizing,
/// client timeout, access log, shutdown flag).
pub fn serve_with_config(
    listener: std::net::TcpListener,
    server: ObjectServer,
    http_config: swift_http::ServerConfig,
) -> std::io::Result<()> {
    serve_with_config_multi(vec![listener], server, http_config)
}

/// Serve across multiple listen sockets (`servers_per_port` topology).
/// All listeners share one worker pool ([`swift_http::serve_forever_multi`]).
pub fn serve_with_config_multi(
    listeners: Vec<std::net::TcpListener>,
    server: ObjectServer,
    mut http_config: swift_http::ServerConfig,
) -> std::io::Result<()> {
    let metrics = http_config
        .metrics
        .clone()
        .unwrap_or_else(ConcurrencyMetrics::new);
    metrics.set_worker_threads(http_config.worker_threads);
    http_config.metrics = Some(metrics);
    let server = std::sync::Arc::new(server);
    swift_http::server::serve_forever_multi_service(
        listeners,
        std::sync::Arc::new(ObjectAsyncService(server)),
        http_config,
    )
}

#[cfg(test)]
mod delete_header_tests {
    use super::*;

    fn req_with(headers: &[(&str, &str)]) -> Request {
        let mut h = HeaderKeyDict::new();
        for (k, v) in headers {
            h.set(k, *v);
        }
        Request {
            method: "PUT".into(),
            path: "/sda1/0/a/c/o".into(),
            query_string: String::new(),
            headers: h,
            body: Body::empty(),
        }
    }

    #[test]
    fn internal_reserved_object_names_require_matching_container_namespace() {
        assert!(validate_internal_obj("AUTH_test", "\0reserved", "\0object").is_ok());
        assert!(validate_internal_obj("AUTH_test", "user", "object").is_ok());

        let user_in_reserved =
            validate_internal_obj("AUTH_test", "\0reserved", "object").unwrap_err();
        assert_eq!(user_in_reserved.status, 400);
        let reserved_in_user = validate_internal_obj("AUTH_test", "user", "\0object").unwrap_err();
        assert_eq!(reserved_in_user.status, 400);
    }

    #[test]
    fn internal_reserved_object_names_reject_embedded_marker_but_allow_system_queue() {
        let embedded = validate_internal_obj("AUTH_test", "user", "bad\0object").unwrap_err();
        assert_eq!(embedded.status, 400);
        assert!(validate_internal_obj(
            ".misplaced_objects",
            "3600",
            "AUTH_test\0container\0object",
        )
        .is_ok());
    }

    #[test]
    fn test_parse_int_like() {
        assert!(parse_int_like("*").is_none());
        assert!(parse_int_like("").is_none());
        assert!(parse_int_like(" 12 ").is_some());
        assert_eq!(parse_int_like("-5"), Some(-5.0));
        // a 100-digit integer overflows i64 but is still a valid int string
        assert!(parse_int_like(&"1".repeat(100)).is_some());
    }

    #[test]
    fn test_if_none_match_has_star() {
        assert!(if_none_match_has_star("*"));
        assert!(if_none_match_has_star("\"abc\", *"));
        assert!(!if_none_match_has_star("\"abc\""));
    }

    #[test]
    fn test_check_delete_headers() {
        let now = 1_000_000.0_f64;
        // no headers -> None
        assert_eq!(check_delete_headers(&req_with(&[]), now).unwrap(), None);
        // non-integer X-Delete-At -> 400 with exact body
        let mut err = check_delete_headers(&req_with(&[("X-Delete-At", "*")]), now).unwrap_err();
        assert_eq!(err.status, 400);
        assert_eq!(
            String::from_utf8_lossy(err.body.materialize(u64::MAX).unwrap()),
            "Non-integer X-Delete-At"
        );
        // past X-Delete-At -> 400
        let mut err = check_delete_headers(&req_with(&[("X-Delete-At", "0")]), now).unwrap_err();
        assert_eq!(
            String::from_utf8_lossy(err.body.materialize(u64::MAX).unwrap()),
            "X-Delete-At in past"
        );
        // far-future X-Delete-At clamps to 9999999999
        let val = check_delete_headers(&req_with(&[("X-Delete-At", &"1".repeat(100))]), now)
            .unwrap()
            .unwrap();
        assert_eq!(val, "9999999999");
        // non-integer X-Delete-After -> 400 with exact body
        let mut err = check_delete_headers(&req_with(&[("X-Delete-After", "*")]), now).unwrap_err();
        assert_eq!(
            String::from_utf8_lossy(err.body.materialize(u64::MAX).unwrap()),
            "Non-integer X-Delete-After"
        );
        // valid X-Delete-After -> now + after
        let val = check_delete_headers(&req_with(&[("X-Delete-After", "2")]), now)
            .unwrap()
            .unwrap();
        assert_eq!(val, format!("{:010}", 1_000_002));
    }
}

#[cfg(test)]
mod fast_post_helper_tests {
    use super::*;

    #[test]
    fn test_shard_update_account_container_prefers_quoted() {
        let mut h = HeaderKeyDict::new();
        h.set("X-Backend-Quoted-Container-Path", ".shards_AUTH_test/c%2D0");
        h.set("X-Backend-Container-Path", "AUTH_test/root");
        let got = shard_update_account_container(&h).unwrap();
        assert_eq!(got.0, ".shards_AUTH_test");
        assert_eq!(got.1, "c-0");
        let mut h2 = HeaderKeyDict::new();
        h2.set("X-Backend-Container-Path", ".shards_AUTH_test/shard-cont");
        let got2 = shard_update_account_container(&h2).unwrap();
        assert_eq!(got2, (".shards_AUTH_test".into(), "shard-cont".into()));
    }

    #[test]
    fn test_extract_swift_bytes() {
        assert_eq!(
            extract_swift_bytes("text/plain"),
            ("text/plain".into(), None)
        );
        assert_eq!(
            extract_swift_bytes("text/plain;swift_bytes=123"),
            ("text/plain".into(), Some("123".into()))
        );
        // other params are preserved, in order, minus swift_bytes
        assert_eq!(
            extract_swift_bytes("text/plain;charset=utf-8;swift_bytes=9;a=b"),
            ("text/plain;charset=utf-8;a=b".into(), Some("9".into()))
        );
    }

    #[test]
    fn test_meta_upsert_replaces_in_place_or_appends() {
        let mut meta: Metadata = vec![
            ("X-Timestamp".into(), MetaValue::Str("1".into())),
            ("Content-Type".into(), MetaValue::Str("a/b".into())),
        ];
        meta_upsert(&mut meta, "content-type", "c/d".into());
        assert_eq!(meta.len(), 2, "existing key replaced, not duplicated");
        assert_eq!(meta_get(&meta, "Content-Type"), Some("c/d"));
        meta_upsert(&mut meta, "Content-Type-Timestamp", "2".into());
        assert_eq!(meta.len(), 3);
        assert_eq!(meta_get(&meta, "Content-Type-Timestamp"), Some("2"));
    }
}

#[cfg(test)]
mod fallocate_reserve_tests {
    use super::*;

    // `SWIFT_DIR` is process-global; serialize tests that load container.ring.gz.
    static SWIFT_DIR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn breach_math_matches_python_fallocate_reserve() {
        let reserve = FallocateReserve::Bytes(100);
        assert!(
            fallocate_reserve_breached(150, 50, &reserve),
            "free-after-write equal to the reserve fails (Python: free <= reserve)"
        );
        assert!(fallocate_reserve_breached(120, 50, &reserve));
        assert!(
            fallocate_reserve_breached(10, 50, &reserve),
            "write larger than free"
        );
        assert!(!fallocate_reserve_breached(151, 50, &reserve));
        assert!(
            !fallocate_reserve_breached(0, 0, &reserve),
            "zero-length writes skip the check"
        );
        assert!(!fallocate_reserve_breached(
            0,
            10,
            &FallocateReserve::Bytes(0)
        ));
        // percent mode needs the device's total capacity; not enforced yet
        assert!(!fallocate_reserve_breached(
            1,
            1,
            &FallocateReserve::Percent(99.0)
        ));
    }

    fn tiny_server(devices: &Path, reserve: FallocateReserve) -> ObjectServer {
        ObjectServer::new(ObjectServerConfig {
            devices: devices.to_path_buf(),
            mount_check: false,
            hash_config: HashPathConfig::new(Vec::new(), b"reserve-tests".to_vec()).unwrap(),
            diskfile: DiskFileConfig::default(),
            policies: std::collections::HashMap::from([(0, PolicyKind::Replication)]),
            container_update_timeout: std::time::Duration::from_secs(1),
            container_update_mode: ContainerUpdateMode::Sync,
        })
        .with_fallocate_reserve(reserve)
    }

    #[tokio::test]
    async fn recon_updater_object_reads_python_cache_shape() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-recon-updater-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = dir.join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(
            cache.join("object.recon"),
            br#"{"object_updater_sweep": 1.5, "object_updater_stats": {"failures_account_container_count": 2}, "object_updater_last": 1700000000.0, "unrelated": true}"#,
        )
        .unwrap();
        let server =
            tiny_server(&dir, FallocateReserve::Bytes(1)).with_recon_cache_path(cache.clone());
        let resp = server
            .handle_async(AsyncRequest {
                method: "GET".into(),
                path: "/recon/updater/object".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), 0),
            })
            .await;
        assert_eq!(resp.status, 200, "{}", resp.reason);
        assert_eq!(resp.headers.get("Content-Type"), Some("application/json"));
        let body = resp.body.collect_async().await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["object_updater_sweep"], 1.5);
        assert_eq!(
            json["object_updater_stats"]["failures_account_container_count"],
            2
        );
        assert_eq!(json["object_updater_last"], 1_700_000_000.0);
        assert!(json.get("unrelated").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn async_ssync_reports_failed_subrequest_in_band() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-async-ssync-error-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let storage = server.storage().clone();
        let body = b":MISSING_CHECK: START\r\n\
                     :MISSING_CHECK: END\r\n\
                     :UPDATES: START\r\n\
                     PUT /a/c/o\r\n\
                     Content-Length: 0\r\n\r\n\
                     :UPDATES: END\r\n"
            .to_vec();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let replication_lock = std::sync::Arc::new(
            swift_core::lockutil::lock_path(
                &dir.join("sda1").join(get_data_dir(0)).join("0"),
                1.0,
                Some("replication"),
            )
            .unwrap(),
        );

        drive_ssync_session(
            swift_http::IncomingBody::from_bytes(body, u64::MAX),
            tx,
            storage,
            server.clone_execution_context(),
            "sda1".to_string(),
            "0".to_string(),
            0,
            PolicyKind::Replication,
            None,
            replication_lock,
        )
        .await;

        let mut output = Vec::new();
        while let Some(chunk) = rx.recv().await {
            output.extend_from_slice(&chunk.unwrap());
        }
        let output = String::from_utf8_lossy(&output);
        assert!(
            output.contains(":ERROR: 500 b'ERROR: With :UPDATES: 1 failures to 0 successes'"),
            "async receiver falsely reported success: {output:?}"
        );
        assert!(
            !output.contains(":UPDATES: START"),
            "failed update must not receive success frames: {output:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn async_ssync_does_not_ack_truncated_updates() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-async-ssync-truncated-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        for tail in [
            "",
            ":UPDATES: START\r\n",
            ":UPDATES: START\r\nPUT /AUTH_test/c/incomplete\r\nContent-Length:",
            ":UPDATES: START\r\nPUT /AUTH_test/c/incomplete\r\nContent-Length: 10\r\nX-Timestamp: 1700000000.00000\r\n\r\nabc",
        ] {
            for transport_error in [false, true] {
                let prefix = format!(":MISSING_CHECK: START\r\n:MISSING_CHECK: END\r\n{tail}");
                let (body_tx, body_rx) = tokio::sync::mpsc::channel(2);
                body_tx.send(Ok(prefix.into_bytes())).await.unwrap();
                if transport_error {
                    body_tx.send(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset, "peer reset during updates"
                    ))).await.unwrap();
                }
                drop(body_tx);
                let (tx, mut rx) = tokio::sync::mpsc::channel(8);
                let replication_lock = std::sync::Arc::new(
                    swift_core::lockutil::lock_path(
                        &dir.join("sda1").join(get_data_dir(0)).join("0"),
                        1.0, Some("replication"),
                    ).unwrap(),
                );
                drive_ssync_session(
                    swift_http::IncomingBody::from_channel(body_rx, None, None, u64::MAX),
                    tx, server.storage().clone(), server.clone_execution_context(),
                    "sda1".into(), "0".into(), 0, PolicyKind::Replication, None,
                    replication_lock,
                ).await;
                let mut output = Vec::new();
                while let Some(chunk) = rx.recv().await {
                    output.extend_from_slice(&chunk.unwrap());
                }
                let output = String::from_utf8_lossy(&output);
                assert!(output.contains(":ERROR:"), "truncated tail={tail:?}, reset={transport_error}: {output:?}");
                assert!(!output.contains(":UPDATES: START"), "incomplete session was acknowledged: {output:?}");
                assert_eq!(server.handle(get_named("incomplete")).status, 404);
                assert!(
                    tmp_files(&dir).is_empty(),
                    "interrupted SSYNC must not leave tmp: {:?}",
                    tmp_files(&dir)
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn async_ssync_preserves_runtime_settings() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-ssync-settings-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        for (name, reserve, expected_commit) in [
            ("denied", FallocateReserve::Bytes(i64::MAX), 0),
            ("allowed", FallocateReserve::Bytes(1), 1),
        ] {
            let commits = std::sync::Arc::new(AtomicUsize::new(0));
            let server = tiny_server(&dir, reserve).with_commit_stall({
                let commits = commits.clone();
                std::sync::Arc::new(move || {
                    commits.fetch_add(1, Ordering::SeqCst);
                })
            });
            let cloned = server.clone_execution_context();
            assert!(std::sync::Arc::ptr_eq(
                &server.worm_clock,
                &cloned.worm_clock
            ));
            let wire = format!(
                ":MISSING_CHECK: START\r\n:MISSING_CHECK: END\r\n:UPDATES: START\r\n\
                 PUT /AUTH_test/c/{name}\r\nContent-Length: 1\r\n\
                 Content-Type: text/plain\r\nX-Timestamp: 1700000000.00000\r\n\r\nx:UPDATES: END\r\n"
            );
            let response = server
                .handle_async(AsyncRequest {
                    method: "SSYNC".into(),
                    path: "/sda1/0".into(),
                    query_string: String::new(),
                    headers: HeaderKeyDict::new(),
                    body: swift_http::IncomingBody::from_bytes(wire.into_bytes(), u64::MAX),
                })
                .await;
            assert_eq!(response.status, 200);
            let bytes = response.body.collect_async().await.unwrap();
            let output = String::from_utf8_lossy(&bytes);
            assert_eq!(
                output.contains(":ERROR:"),
                expected_commit == 0,
                "{name}: {output}"
            );
            assert_eq!(commits.load(Ordering::SeqCst), expected_commit, "{name}");
            assert_eq!(
                server.handle(get_named(name)).status,
                if expected_commit == 0 { 404 } else { 200 }
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn async_ssync_streams_large_put_and_next_update() {
        use md5::{Digest, Md5};
        use std::io::Read;
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-ssync-large-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let total = 65 * 1024 * 1024 + 17;
        let (body_tx, body_rx) = tokio::sync::mpsc::channel(2);
        let producer_scope = TaskScope::bounded(1);
        let producer = producer_scope.spawn(async move {
            body_tx.send(Ok(format!(
                ":MISSING_CHECK: START\r\n:MISSING_CHECK: END\r\n:UPDATES: START\r\n\
                 PUT /AUTH_test/c/large-ssync\r\nContent-Length: {total}\r\n\
                 Content-Type: application/octet-stream\r\nX-Timestamp: 1700000000.00000\r\n\r\n"
            ).into_bytes())).await.unwrap();
            let mut hash = Md5::new();
            let mut sent = 0;
            while sent < total {
                let size = ssync::STREAM_CHUNK_BYTES.min(total - sent);
                let chunk = vec![((sent / ssync::STREAM_CHUNK_BYTES) % 251) as u8; size];
                hash.update(&chunk);
                body_tx.send(Ok(chunk)).await.unwrap();
                sent += size;
            }
            body_tx.send(Ok(b"PUT /AUTH_test/c/empty-ssync\r\nContent-Length: 0\r\nContent-Type: text/plain\r\nX-Timestamp: 1700000000.00000\r\n\r\n:UPDATES: END\r\n".to_vec())).await.unwrap();
            format!("{:x}", hash.finalize())
        }).unwrap();
        let before = server.storage().stats().blocking.started_total;
        let response = server
            .handle_async(AsyncRequest {
                method: "SSYNC".into(),
                path: "/sda1/0".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_channel(body_rx, None, None, u64::MAX),
            })
            .await;
        assert_eq!(response.status, 200);
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            response.body.collect_async(),
        )
        .await
        .expect("streaming SSYNC must finish")
        .unwrap();
        let output = String::from_utf8_lossy(&output);
        assert!(
            output.contains(":UPDATES: END") && !output.contains(":ERROR:"),
            "{output}"
        );
        let expected_etag = producer.join().await.unwrap();
        producer_scope.join().await.unwrap();
        assert!(
            server.storage().stats().blocking.started_total - before
                >= (total / ssync::STREAM_CHUNK_BYTES) as u64
        );
        let got = server.handle(get_named("large-ssync"));
        assert_eq!(got.status, 200);
        let quoted_etag = format!("\"{expected_etag}\"");
        assert_eq!(got.headers.get("Etag"), Some(quoted_etag.as_str()));
        let (mut reader, length) = got.body.into_reader();
        assert_eq!(length, Some(total as u64));
        let mut buffer = vec![0; ssync::STREAM_CHUNK_BYTES];
        let mut received = 0;
        loop {
            let n = reader.read(&mut buffer).unwrap();
            if n == 0 {
                break;
            }
            for (i, byte) in buffer[..n].iter().enumerate() {
                assert_eq!(
                    *byte,
                    (((received + i) / ssync::STREAM_CHUNK_BYTES) % 251) as u8
                );
            }
            received += n;
        }
        assert_eq!(received, total);
        drop(reader);
        assert_eq!(server.handle(get_named("empty-ssync")).status, 200);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn put_request(body: &[u8]) -> Request {
        put_named("o", "1", body)
    }

    fn put_named(name: &str, ts: &str, body: &[u8]) -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", ts);
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Content-Length", body.len());
        Request {
            method: "PUT".into(),
            path: format!("/sda1/0/AUTH_test/c/{name}"),
            query_string: String::new(),
            headers,
            body: body.to_vec().into(),
        }
    }

    fn get_named(name: &str) -> Request {
        Request {
            method: "GET".into(),
            path: format!("/sda1/0/AUTH_test/c/{name}"),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        }
    }

    #[test]
    fn delete_container_update_uses_backend_container_path() {
        // Probe L1435: DELETE of a sharded object must update the nested
        // shard DB (`X-Backend-Container-Path`), not the root listing.
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        let seen = Arc::new(Mutex::new(String::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen_t = Arc::clone(&seen);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                *seen_t.lock().unwrap() = req.lines().next().unwrap_or("").to_string();
                let _ = stream.write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-cu-del-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        assert_eq!(server.handle(put_named("obj-0000", "1", b"x")).status, 201);
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "2");
        headers.set("X-Container-Host", format!("{addr}"));
        headers.set("X-Container-Device", "sda1");
        headers.set("X-Container-Partition", "7");
        headers.set("X-Backend-Container-Path", ".shards_AUTH_test/shard-cont");
        let resp = server.handle(Request {
            method: "DELETE".into(),
            path: "/sda1/0/AUTH_test/c/obj-0000".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        });
        assert_eq!(resp.status, 204, "{}", resp.reason);
        let line = seen.lock().unwrap().clone();
        assert!(
            line.contains("DELETE /sda1/7/.shards_AUTH_test/shard-cont/obj-0000"),
            "container update must target the shard, got {line:?}"
        );
        assert!(
            !line.contains("/AUTH_test/c/obj-0000"),
            "must not update the root listing, got {line:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handle_async_delete_container_update_uses_backend_container_path() {
        // Hyper DELETE must use the same shard path as sync handle() (L692).
        // Empty SWIFT_DIR so we do not pick up a host container.ring.gz.
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        let _guard = SWIFT_DIR_LOCK.lock().unwrap();
        let empty_swift = std::env::temp_dir().join(format!(
            "swift-obj-cu-del-async-noswift-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&empty_swift);
        std::fs::create_dir_all(&empty_swift).unwrap();
        std::env::set_var("SWIFT_DIR", &empty_swift);
        let seen = Arc::new(Mutex::new(String::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen_t = Arc::clone(&seen);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                *seen_t.lock().unwrap() = req.lines().next().unwrap_or("").to_string();
                let _ = stream.write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-cu-del-async-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        assert_eq!(server.handle(put_named("obj-0000", "1", b"x")).status, 201);
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "2");
        headers.set("X-Container-Host", format!("{addr}"));
        headers.set("X-Container-Device", "sda1");
        headers.set("X-Container-Partition", "7");
        headers.set("X-Backend-Container-Path", ".shards_AUTH_test/shard-cont");
        let resp = server
            .handle_async(AsyncRequest {
                method: "DELETE".into(),
                path: "/sda1/0/AUTH_test/c/obj-0000".into(),
                query_string: String::new(),
                headers,
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        let _ = std::env::remove_var("SWIFT_DIR");
        let _ = std::fs::remove_dir_all(&empty_swift);
        assert_eq!(resp.status, 204, "{}", resp.reason);
        let line = seen.lock().unwrap().clone();
        assert!(
            line.contains("DELETE /sda1/7/.shards_AUTH_test/shard-cont/obj-0000"),
            "async DELETE container update must target the shard, got {line:?}"
        );
        assert!(
            !line.contains("/AUTH_test/c/obj-0000"),
            "must not update the root listing, got {line:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handle_async_delete_ring_looks_up_shard_not_root_host() {
        // X-Container-Host names the root; X-Backend-Container-Path names the
        // shard. Ring lookup must send the tombstone to the shard nodes.
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        let _guard = SWIFT_DIR_LOCK.lock().unwrap();
        let root = TcpListener::bind("127.0.0.1:0").unwrap();
        let shard = TcpListener::bind("127.0.0.1:0").unwrap();
        let root_addr = root.local_addr().unwrap();
        let shard_addr = shard.local_addr().unwrap();
        let seen_root = Arc::new(Mutex::new(String::new()));
        let seen_shard = Arc::new(Mutex::new(String::new()));
        let seen_root_t = Arc::clone(&seen_root);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = root.accept() {
                let mut buf = vec![0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                *seen_root_t.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let seen_shard_t = Arc::clone(&seen_shard);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = shard.accept() {
                let mut buf = vec![0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                *seen_shard_t.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = stream.write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let data = swift_ring::RingData::from_parts(
            vec![Some(swift_ring::RingDevice {
                id: 0,
                region: 1,
                zone: 1,
                ip: shard_addr.ip().to_string(),
                port: shard_addr.port() as u32,
                replication_ip: None,
                replication_port: None,
                device: "sdb1".into(),
                weight: 100.0,
                meta: String::new(),
                extra: Default::default(),
            })],
            32,
            vec![vec![0]],
        );
        let swift_dir = std::env::temp_dir().join(format!(
            "swift-obj-cu-del-ring-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&swift_dir);
        std::fs::create_dir_all(&swift_dir).unwrap();
        data.save_v1(&swift_dir.join("container.ring.gz")).unwrap();
        std::env::set_var("SWIFT_DIR", &swift_dir);
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-cu-del-ring-dev-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        assert_eq!(server.handle(put_named("obj-0000", "1", b"x")).status, 201);
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "2");
        headers.set("X-Container-Host", format!("{root_addr}"));
        headers.set("X-Container-Device", "sda1");
        headers.set("X-Container-Partition", "7");
        headers.set("X-Backend-Container-Path", ".shards_AUTH_test/shard-cont");
        let resp = server
            .handle_async(AsyncRequest {
                method: "DELETE".into(),
                path: "/sda1/0/AUTH_test/c/obj-0000".into(),
                query_string: String::new(),
                headers,
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        let _ = std::env::remove_var("SWIFT_DIR");
        let _ = std::fs::remove_dir_all(&swift_dir);
        assert_eq!(resp.status, 204, "{}", resp.reason);
        let shard_req = seen_shard.lock().unwrap().clone();
        assert!(
            shard_req.contains("DELETE /sdb1/0/.shards_AUTH_test/shard-cont/obj-0000"),
            "ring lookup must tombstone the shard, got {shard_req:?}"
        );
        let root_req = seen_root.lock().unwrap().clone();
        assert!(
            root_req.contains("DELETE"),
            "root host is tried first and 404s, got {root_req:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cu_host_result_parses_301_location() {
        let buf = b"HTTP/1.1 301 Moved Permanently\r\n\
                    Location: /.shards_AUTH_test/shard-cont/obj-0001\r\n\
                    Content-Length: 0\r\n\r\n";
        match cu_host_result(buf) {
            CuHostResult::Redirect(loc) => {
                assert_eq!(loc, "/.shards_AUTH_test/shard-cont/obj-0001");
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn async_container_http_reports_301_redirect() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 301 Moved Permanently\r\n\
                      Location: /.shards_AUTH_test/shard-cont/obj-0001\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let got = async_container_http(
            "PUT",
            &addr.to_string(),
            "sda1",
            "7",
            "/AUTH_test/c/obj-0001",
            &HeaderKeyDict::new(),
            0,
            std::time::Duration::from_secs(2),
        )
        .await;
        match got {
            CuHostResult::Redirect(loc) => {
                assert_eq!(loc, "/.shards_AUTH_test/shard-cont/obj-0001");
            }
            _ => panic!("expected Redirect, got {got:?}"),
        }
    }

    #[test]
    fn sync_container_http_omits_accept_redirect() {
        // Python object-server never stamps Accept-Redirect on the sync
        // path. Only the updater does. W254 / L4095.
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = stream.write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                req
            } else {
                String::new()
            }
        });
        let got = sync_container_http(
            "DELETE",
            &addr.to_string(),
            "sda1",
            "7",
            "/AUTH_test/c/obj-0001",
            &HeaderKeyDict::new(),
            0,
            std::time::Duration::from_secs(2),
        );
        let req = handle.join().expect("listener thread");
        assert!(
            matches!(got, CuHostResult::Ok),
            "expected Ok, got {got:?}; req={req:?}"
        );
        let lower = req.to_ascii_lowercase();
        assert!(
            !lower.contains("x-backend-accept-redirect"),
            "object-server sync must not stamp Accept-Redirect, got {req:?}"
        );
        assert!(
            !lower.contains("x-backend-accept-quoted-location"),
            "object-server sync must not stamp Accept-Quoted-Location, got {req:?}"
        );
        assert!(
            lower.contains("x-backend-allow-reserved-names"),
            "reserved-names header stays, got {req:?}"
        );
    }

    #[tokio::test]
    async fn async_container_http_omits_accept_redirect() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = stream.write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                req
            } else {
                String::new()
            }
        });
        let got = async_container_http(
            "DELETE",
            &addr.to_string(),
            "sda1",
            "7",
            "/AUTH_test/c/obj-0001",
            &HeaderKeyDict::new(),
            0,
            std::time::Duration::from_secs(2),
        )
        .await;
        let req = handle.join().expect("listener thread");
        assert!(
            matches!(got, CuHostResult::Ok),
            "expected Ok, got {got:?}; req={req:?}"
        );
        let lower = req.to_ascii_lowercase();
        assert!(
            !lower.contains("x-backend-accept-redirect"),
            "object-server async must not stamp Accept-Redirect, got {req:?}"
        );
        assert!(
            !lower.contains("x-backend-accept-quoted-location"),
            "object-server async must not stamp Accept-Quoted-Location, got {req:?}"
        );
    }

    #[tokio::test]
    async fn fanout_async_follows_301_via_container_ring() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        let _guard = SWIFT_DIR_LOCK.lock().unwrap();
        let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
        let dest = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_addr = redirect.local_addr().unwrap();
        let dest_addr = dest.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(String::new()));
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = redirect.accept() {
                let mut buf = vec![0u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 301 Moved Permanently\r\n\
                      Location: /.shards_AUTH_test/shard-cont/obj-0001\r\n\
                      Content-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let seen_t = Arc::clone(&seen);
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = dest.accept() {
                let mut buf = vec![0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                *seen_t.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = stream.write_all(
                    b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        let hash = HashPathConfig::new(Vec::new(), b"cu-301-follow".to_vec()).unwrap();
        let data = swift_ring::RingData::from_parts(
            vec![Some(swift_ring::RingDevice {
                id: 0,
                region: 1,
                zone: 1,
                ip: dest_addr.ip().to_string(),
                port: dest_addr.port() as u32,
                replication_ip: None,
                replication_port: None,
                device: "sdb1".into(),
                weight: 100.0,
                meta: String::new(),
                extra: Default::default(),
            })],
            32,
            vec![vec![0]],
        );
        let swift_dir = std::env::temp_dir().join(format!(
            "swift-obj-cu-ring-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&swift_dir);
        std::fs::create_dir_all(&swift_dir).unwrap();
        data.save_v1(&swift_dir.join("container.ring.gz")).unwrap();
        std::env::set_var("SWIFT_DIR", &swift_dir);
        let ok = fanout_container_http_async(
            "PUT".into(),
            vec![redirect_addr.to_string()],
            vec!["sda1".into()],
            "7".into(),
            "/AUTH_test/c/obj-0001".into(),
            HeaderKeyDict::new(),
            0,
            std::time::Duration::from_secs(2),
            Some(hash),
        )
        .await;
        let _ = std::env::remove_var("SWIFT_DIR");
        let _ = std::fs::remove_dir_all(&swift_dir);
        assert!(ok, "301 must be followed onto the shard ring");
        let req = seen.lock().unwrap().clone();
        assert!(
            req.contains("PUT /sdb1/0/.shards_AUTH_test/shard-cont/obj-0001"),
            "follow must rewrite path+device, got {req:?}"
        );
    }

    #[test]
    fn put_honors_the_fallocate_reserve_against_a_temp_device() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-reserve-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        // an unsatisfiable reserve: any write leaves free <= reserve -> 507
        let full = tiny_server(&dir, FallocateReserve::Bytes(i64::MAX));
        assert_eq!(full.handle(put_request(b"body")).status, 507);
        // a tiny reserve passes and the object lands
        let ok = tiny_server(&dir, FallocateReserve::Bytes(1));
        assert_eq!(ok.handle(put_request(b"body")).status, 201);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn shipped_put_finalize_runs_on_storage_executor() {
        let dir =
            std::env::temp_dir().join(format!("swift-obj-exec-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let before = server.storage().stats().blocking.started_total;
        let resp = server
            .handle_buffered_async(put_request(b"executor-body"))
            .await;
        assert_eq!(resp.status, 201, "{}", resp.reason);
        assert!(
            server.storage().stats().blocking.started_total > before,
            "replication PUT finalize must run on StorageExecutor"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handle_async_delete_post_replicate_run_on_storage_executor() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-fs-dispatch-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let mut put_h = HeaderKeyDict::new();
        put_h.set("X-Timestamp", "3000");
        put_h.set("Content-Type", "application/octet-stream");
        put_h.set("Content-Length", 4);
        assert_eq!(
            server
                .handle_async(AsyncRequest {
                    method: "PUT".into(),
                    path: "/sda1/0/AUTH_test/c/o".into(),
                    query_string: String::new(),
                    headers: put_h,
                    body: swift_http::IncomingBody::from_bytes(b"abcd".to_vec(), u64::MAX),
                })
                .await
                .status,
            201
        );

        let before_del = server.storage().stats().blocking.started_total;
        let mut del_h = HeaderKeyDict::new();
        del_h.set("X-Timestamp", "3001");
        let del = server
            .handle_async(AsyncRequest {
                method: "DELETE".into(),
                path: "/sda1/0/AUTH_test/c/o".into(),
                query_string: String::new(),
                headers: del_h,
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            del.status, 204,
            "DELETE tombstone obj/server.py:1311-1369 {}",
            del.reason
        );
        assert!(
            server.storage().stats().blocking.started_total > before_del,
            "DELETE FS must run on StorageExecutor, not Tokio"
        );

        let before_post = server.storage().stats().blocking.started_total;
        let mut post_h = HeaderKeyDict::new();
        post_h.set("X-Timestamp", "3002");
        post_h.set("Content-Type", "application/octet-stream");
        let post = server
            .handle_async(AsyncRequest {
                method: "POST".into(),
                path: "/sda1/0/AUTH_test/c/o".into(),
                query_string: String::new(),
                headers: post_h,
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        // Tombstoned object: POST is 404, but the open/stat is still FS on the executor.
        assert!(
            server.storage().stats().blocking.started_total > before_post,
            "POST FS must run on StorageExecutor, got status {}",
            post.status
        );

        let before_rep = server.storage().stats().blocking.started_total;
        let rep = server
            .handle_async(AsyncRequest {
                method: "REPLICATE".into(),
                path: "/sda1/0".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(rep.status, 200, "REPLICATE {}", rep.reason);
        assert!(
            server.storage().stats().blocking.started_total > before_rep,
            "REPLICATE hashes must run on StorageExecutor"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn two_concurrent_puts_both_commit_distinct_objects() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-exec-conc-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = std::sync::Arc::new(tiny_server(&dir, FallocateReserve::Bytes(1)));
        let before = server.storage().stats().blocking.started_total;
        let a = put_named("o-alpha", "1001", b"alpha-payload");
        let b = put_named("o-beta", "1002", b"beta-payload!!");
        let s1 = std::sync::Arc::clone(&server);
        let s2 = std::sync::Arc::clone(&server);
        let (r1, r2) = tokio::join!(s1.handle_buffered_async(a), s2.handle_buffered_async(b),);
        assert_eq!(r1.status, 201, "alpha PUT {}", r1.reason);
        assert_eq!(r2.status, 201, "beta PUT {}", r2.reason);
        assert!(
            server.storage().stats().blocking.started_total >= before + 2,
            "each concurrent PUT must run its own StorageExecutor commit"
        );
        let mut g1 = server.handle(get_named("o-alpha"));
        let mut g2 = server.handle(get_named("o-beta"));
        assert_eq!(g1.status, 200, "alpha GET {}", g1.reason);
        assert_eq!(g2.status, 200, "beta GET {}", g2.reason);
        let b1 = g1.body.materialize(u64::MAX).unwrap().to_vec();
        let b2 = g2.body.materialize(u64::MAX).unwrap().to_vec();
        assert_eq!(b1, b"alpha-payload");
        assert_eq!(b2, b"beta-payload!!");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_object_if_none_match_is_rechecked_under_mutation_lock() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-cas-create-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_server = tiny_server(&dir, FallocateReserve::Bytes(1)).with_commit_stall({
            let entered = std::sync::Arc::clone(&entered);
            let release = std::sync::Arc::clone(&release);
            std::sync::Arc::new(move || {
                entered.store(true, std::sync::atomic::Ordering::SeqCst);
                while !release.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            })
        });
        let second_server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let observer = tiny_server(&dir, FallocateReserve::Bytes(1));
        let mut first = put_named("cas-create", "7001", b"first");
        first.headers.set("If-None-Match", "*");
        let first_task =
            tokio::spawn(async move { first_server.handle_buffered_async(first).await });
        let start = std::time::Instant::now();
        while !entered.load(std::sync::atomic::Ordering::SeqCst)
            && start.elapsed() < std::time::Duration::from_secs(2)
        {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
        let mut second = put_named("cas-create", "7002", b"second");
        second.headers.set("If-None-Match", "*");
        let second_task =
            tokio::spawn(async move { second_server.handle_buffered_async(second).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        release.store(true, std::sync::atomic::Ordering::SeqCst);
        let first_response = first_task.await.unwrap();
        let second_response = second_task.await.unwrap();
        assert_eq!(first_response.status, 201, "{}", first_response.reason);
        assert_eq!(second_response.status, 412, "{}", second_response.reason);
        let mut get = observer.handle(get_named("cas-create"));
        assert_eq!(get.status, 200);
        assert_eq!(get.body.materialize(u64::MAX).unwrap(), b"first");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_object_if_match_is_rechecked_under_mutation_lock() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-cas-update-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let observer = tiny_server(&dir, FallocateReserve::Bytes(1));
        let seed = observer.handle(put_named("cas-update", "7100", b"seed"));
        assert_eq!(seed.status, 201);
        let old_etag = seed.headers.get("ETag").unwrap().to_string();
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_server = tiny_server(&dir, FallocateReserve::Bytes(1)).with_commit_stall({
            let entered = std::sync::Arc::clone(&entered);
            let release = std::sync::Arc::clone(&release);
            std::sync::Arc::new(move || {
                entered.store(true, std::sync::atomic::Ordering::SeqCst);
                while !release.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            })
        });
        let second_server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let mut first = put_named("cas-update", "7101", b"first-wins");
        first.headers.set("If-Match", &old_etag);
        let first_task =
            tokio::spawn(async move { first_server.handle_buffered_async(first).await });
        let start = std::time::Instant::now();
        while !entered.load(std::sync::atomic::Ordering::SeqCst)
            && start.elapsed() < std::time::Duration::from_secs(2)
        {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
        let mut second = put_named("cas-update", "7102", b"must-lose");
        second.headers.set("If-Match", &old_etag);
        let second_task =
            tokio::spawn(async move { second_server.handle_buffered_async(second).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        release.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(first_task.await.unwrap().status, 201);
        assert_eq!(second_task.await.unwrap().status, 412);
        let mut get = observer.handle(get_named("cas-update"));
        assert_eq!(get.status, 200);
        assert_eq!(get.body.materialize(u64::MAX).unwrap(), b"first-wins");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn same_etag_s3_version_aba_is_rejected_under_mutation_lock() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-version-aba-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let observer = tiny_server(&dir, FallocateReserve::Bytes(1));
        let mut seed = put_named("version-aba", "7200", b"same-bytes");
        seed.headers.set(S3_VERSION_ID_SYSMETA, "version-1");
        assert_eq!(observer.handle(seed).status, 201);
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_server = tiny_server(&dir, FallocateReserve::Bytes(1)).with_commit_stall({
            let entered = std::sync::Arc::clone(&entered);
            let release = std::sync::Arc::clone(&release);
            std::sync::Arc::new(move || {
                entered.store(true, std::sync::atomic::Ordering::SeqCst);
                while !release.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            })
        });
        let second_server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let mut first = put_named("version-aba", "7201", b"same-bytes");
        first.headers.set(S3_VERSION_ID_SYSMETA, "version-2");
        first
            .headers
            .set(EXPECTED_S3_VERSION_ID_HEADER, "version-1");
        let first_task =
            tokio::spawn(async move { first_server.handle_buffered_async(first).await });
        let start = std::time::Instant::now();
        while !entered.load(std::sync::atomic::Ordering::SeqCst)
            && start.elapsed() < std::time::Duration::from_secs(2)
        {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
        let mut second = put_named("version-aba", "7202", b"same-bytes");
        second.headers.set(S3_VERSION_ID_SYSMETA, "version-3");
        second
            .headers
            .set(EXPECTED_S3_VERSION_ID_HEADER, "version-1");
        let second_task =
            tokio::spawn(async move { second_server.handle_buffered_async(second).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        release.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(first_task.await.unwrap().status, 201);
        assert_eq!(second_task.await.unwrap().status, 412);
        let head = observer.handle(Request {
            method: "HEAD".into(),
            path: "/sda1/0/AUTH_test/c/version-aba".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: Body::empty(),
        });
        assert_eq!(head.headers.get(S3_VERSION_ID_SYSMETA), Some("version-2"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handle_async_put_writes_chunks_on_storage_executor() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-stream-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let before = server.storage().stats().blocking.started_total;
        let payload = vec![b'z'; 128 * 1024];
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "2001");
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Content-Length", payload.len());
        let areq = AsyncRequest {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/stream-o".into(),
            query_string: String::new(),
            headers,
            body: swift_http::IncomingBody::from_bytes(payload.clone(), u64::MAX),
        };
        let resp = server.handle_async(areq).await;
        assert_eq!(resp.status, 201, "{}", resp.reason);
        assert!(
            server.storage().stats().blocking.started_total > before,
            "chunk writes and commit must run on StorageExecutor"
        );
        let mut got = server.handle(get_named("stream-o"));
        assert_eq!(got.status, 200);
        assert_eq!(got.body.materialize(u64::MAX).unwrap(), &payload[..]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn async_ec_no_commit_is_visible_only_with_fragment_preferences() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-ec-nondurable-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = ObjectServer::new(ObjectServerConfig {
            devices: dir.clone(),
            mount_check: false,
            hash_config: HashPathConfig::new(Vec::new(), b"ec-nondurable-tests".to_vec()).unwrap(),
            diskfile: DiskFileConfig::default(),
            policies: std::collections::HashMap::from([(
                2,
                PolicyKind::Ec {
                    n_unique_fragments: Some(6),
                },
            )]),
            container_update_timeout: std::time::Duration::from_millis(10),
            container_update_mode: ContainerUpdateMode::Async,
        });
        // Match the probe's harder case: a newer non-durable fragment must
        // coexist with an older durable fragment.  A normal GET selects the
        // durable generation; an explicit empty fragment-preferences list
        // selects the newest generation.
        let durable_body = b"older-durable-fragment".to_vec();
        let mut durable_headers = HeaderKeyDict::new();
        durable_headers.set("X-Timestamp", "6000.00000");
        durable_headers.set("Content-Type", "application/octet-stream");
        durable_headers.set("Content-Length", durable_body.len());
        durable_headers.set("X-Backend-Storage-Policy-Index", "2");
        durable_headers.set("X-Object-Sysmeta-Ec-Frag-Index", "0");
        durable_headers.set("X-Object-Sysmeta-Ec-Etag", "whole-object-etag-old");
        durable_headers.set("X-Object-Sysmeta-Ec-Content-Length", durable_body.len());
        let durable_put = server
            .handle_async(AsyncRequest {
                method: "PUT".into(),
                path: "/sda1/0/AUTH_test/c/o".into(),
                query_string: String::new(),
                headers: durable_headers,
                body: swift_http::IncomingBody::from_bytes(durable_body.clone(), u64::MAX),
            })
            .await;
        assert_eq!(durable_put.status, 201, "{}", durable_put.reason);

        let body = b"newer-non-durable-fragment".to_vec();
        let mut put_headers = HeaderKeyDict::new();
        put_headers.set("X-Timestamp", "6001.00000");
        put_headers.set("Content-Type", "application/octet-stream");
        put_headers.set("Content-Length", body.len());
        put_headers.set("X-Backend-Storage-Policy-Index", "2");
        put_headers.set("X-Backend-No-Commit", "true");
        put_headers.set("X-Object-Sysmeta-Ec-Frag-Index", "0");
        put_headers.set("X-Object-Sysmeta-Ec-Etag", "whole-object-etag");
        put_headers.set("X-Object-Sysmeta-Ec-Content-Length", body.len());
        let put = server
            .handle_async(AsyncRequest {
                method: "PUT".into(),
                path: "/sda1/0/AUTH_test/c/o".into(),
                query_string: String::new(),
                headers: put_headers,
                body: swift_http::IncomingBody::from_bytes(body.clone(), u64::MAX),
            })
            .await;
        assert_eq!(put.status, 201, "{}", put.reason);

        let mut default_headers = HeaderKeyDict::new();
        default_headers.set("X-Backend-Storage-Policy-Index", "2");
        let mut default_get = server.handle(Request {
            method: "GET".into(),
            path: "/sda1/0/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers: default_headers.clone(),
            body: Body::empty(),
        });
        assert_eq!(
            default_get.status, 200,
            "a normal GET requires durable data"
        );
        assert_eq!(
            default_get.body.materialize(u64::MAX).unwrap(),
            &durable_body[..],
            "normal GET must stay on the older durable generation"
        );

        default_headers.set("X-Backend-Fragment-Preferences", "[]");
        let mut nondurable_get = server.handle(Request {
            method: "GET".into(),
            path: "/sda1/0/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers: default_headers,
            body: Body::empty(),
        });
        assert_eq!(nondurable_get.status, 200, "{}", nondurable_get.reason);
        assert_eq!(
            nondurable_get.headers.get("X-Backend-Durable-Timestamp"),
            Some("0000006000.00000"),
            "the response reports the older durable generation separately"
        );
        assert_eq!(
            nondurable_get.body.materialize(u64::MAX).unwrap(),
            &body[..]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tmp_files_recursive(devices: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        fn walk(dir: &Path, acc: &mut Vec<PathBuf>) {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for ent in rd.flatten() {
                let p = ent.path();
                if p.is_dir() {
                    walk(&p, acc);
                } else if p.is_file() {
                    acc.push(p);
                }
            }
        }
        walk(devices, &mut out);
        out
    }

    fn tmp_files(devices: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let walk = |dir: &Path, acc: &mut Vec<PathBuf>| {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for ent in rd.flatten() {
                let p = ent.path();
                if p.is_dir() {
                    // recurse one extra level for objects/tmp
                    if let Ok(rd2) = std::fs::read_dir(&p) {
                        for e2 in rd2.flatten() {
                            let p2 = e2.path();
                            if p2.is_file()
                                && p2
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .is_some_and(|n| n.contains(".data") || n.starts_with('.'))
                            {
                                acc.push(p2);
                            }
                        }
                    }
                }
            }
        };
        if let Ok(rd) = std::fs::read_dir(devices) {
            for ent in rd.flatten() {
                walk(&ent.path(), &mut out);
            }
        }
        out
    }

    fn async_put(
        ts: &str,
        name: &str,
        body: swift_http::IncomingBody,
        content_length: Option<u64>,
    ) -> AsyncRequest {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", ts);
        headers.set("Content-Type", "application/octet-stream");
        if let Some(n) = content_length {
            headers.set("Content-Length", n);
        }
        AsyncRequest {
            method: "PUT".into(),
            path: format!("/sda1/0/AUTH_test/c/{name}"),
            query_string: String::new(),
            headers,
            body,
        }
    }

    #[tokio::test]
    async fn streaming_put_client_disconnect_is_499_and_leaves_no_object() {
        let dir =
            std::env::temp_dir().join(format!("swift-obj-disc-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(4);
        let put = tokio::spawn({
            let server = ObjectServer::new(server.config.clone());
            async move {
                server
                    .handle_async(async_put(
                        "4001",
                        "disc-o",
                        swift_http::IncomingBody::from_channel(rx, Some(1_048_576), None, u64::MAX),
                        Some(1_048_576),
                    ))
                    .await
            }
        });
        tx.send(Ok(b"partial".to_vec())).await.unwrap();
        drop(tx);
        let resp = put.await.unwrap();
        assert_eq!(resp.status, 499, "disconnect must not 2xx {}", resp.status);
        assert_eq!(server.handle(get_named("disc-o")).status, 404);
        assert!(
            tmp_files(&dir).is_empty(),
            "disconnect must not leave tmp: {:?}",
            tmp_files(&dir)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn streaming_put_future_cancel_unlinks_tmp_on_storage_domain() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-cancel-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let before = server.storage().stats().blocking.started_total;
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(4);
        let put = tokio::spawn({
            let server = server.clone_execution_context();
            async move {
                server
                    .handle_async(async_put(
                        "4002",
                        "cancel-o",
                        swift_http::IncomingBody::from_channel(rx, Some(1_048_576), None, u64::MAX),
                        Some(1_048_576),
                    ))
                    .await
            }
        });
        tx.send(Ok(vec![b'x'; 4096])).await.unwrap();
        let start = std::time::Instant::now();
        while server.storage().stats().blocking.started_total == before
            && start.elapsed() < std::time::Duration::from_secs(2)
        {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            server.storage().stats().blocking.started_total > before,
            "first chunk must reach the POSIX write before cancel"
        );
        put.abort();
        let _ = put.await;
        drop(tx);
        let start = std::time::Instant::now();
        while !tmp_files_recursive(&dir).is_empty()
            && start.elapsed() < std::time::Duration::from_secs(2)
        {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            tmp_files_recursive(&dir).is_empty(),
            "cancelled PUT must unlink tmp via submit_held: {:?}",
            tmp_files_recursive(&dir)
        );
        assert_eq!(server.handle(get_named("cancel-o")).status, 404);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn streaming_put_retry_overwrites_same_key() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-retry-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        for (ts, body) in [
            ("5001", b"first".as_slice()),
            ("5002", b"second-wins".as_slice()),
        ] {
            let resp = server
                .handle_async(async_put(
                    ts,
                    "retry-o",
                    swift_http::IncomingBody::from_bytes(body.to_vec(), u64::MAX),
                    Some(body.len() as u64),
                ))
                .await;
            assert_eq!(resp.status, 201, "{}", resp.reason);
        }
        let mut got = server.handle(get_named("retry-o"));
        assert_eq!(got.status, 200);
        assert_eq!(got.body.materialize(u64::MAX).unwrap(), b"second-wins");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn streaming_put_partial_content_length_is_499_no_commit() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-partial-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let resp = server
            .handle_async(async_put(
                "5003",
                "partial-o",
                swift_http::IncomingBody::from_bytes(b"short".to_vec(), u64::MAX),
                Some(64),
            ))
            .await;
        assert_eq!(resp.status, 499, "short body vs Content-Length must 499");
        assert_eq!(server.handle(get_named("partial-o")).status, 404);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn streaming_put_enospc_reserve_is_507_no_object() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-enospc-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let full = tiny_server(&dir, FallocateReserve::Bytes(i64::MAX));
        let resp = full
            .handle_async(async_put(
                "5004",
                "full-o",
                swift_http::IncomingBody::from_bytes(b"body".to_vec(), u64::MAX),
                Some(4),
            ))
            .await;
        assert_eq!(
            resp.status, 507,
            "ENOSPC reserve must 507, got {}",
            resp.status
        );
        assert_eq!(full.handle(get_named("full-o")).status, 404);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn streaming_put_commit_survives_http_waiter_drop() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-barrier-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server = tiny_server(&dir, FallocateReserve::Bytes(1)).with_commit_stall({
            let entered = std::sync::Arc::clone(&entered);
            let release = std::sync::Arc::clone(&release);
            std::sync::Arc::new(move || {
                entered.store(true, std::sync::atomic::Ordering::SeqCst);
                while !release.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            })
        });
        let put = tokio::spawn({
            let server = ObjectServer::new(server.config.clone()).with_commit_stall({
                let entered = std::sync::Arc::clone(&entered);
                let release = std::sync::Arc::clone(&release);
                std::sync::Arc::new(move || {
                    entered.store(true, std::sync::atomic::Ordering::SeqCst);
                    while !release.load(std::sync::atomic::Ordering::SeqCst) {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                })
            });
            async move {
                server
                    .handle_async(async_put(
                        "5005",
                        "barrier-o",
                        swift_http::IncomingBody::from_bytes(b"shielded".to_vec(), u64::MAX),
                        Some(8),
                    ))
                    .await
            }
        });
        let start = std::time::Instant::now();
        while !entered.load(std::sync::atomic::Ordering::SeqCst)
            && start.elapsed() < std::time::Duration::from_secs(2)
        {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            entered.load(std::sync::atomic::Ordering::SeqCst),
            "commit stall must run"
        );
        put.abort();
        release.store(true, std::sync::atomic::Ordering::SeqCst);
        while start.elapsed() < std::time::Duration::from_secs(3) {
            if server.handle(get_named("barrier-o")).status == 200 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let got = server.handle(get_named("barrier-o"));
        assert_eq!(
            got.status, 200,
            "DurabilityBarrier must finish commit after HTTP waiter drop"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Range: swob `Range.ranges_for_length` (tests/golden.rs vs Python).
    /// If-None-Match 304: swob `_get_conditional_response_status` order.
    #[tokio::test]
    async fn handle_async_get_range_and_if_none_match() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-range-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let payload = b"abcdefghij".to_vec();
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "2003");
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Content-Length", payload.len());
        let put = AsyncRequest {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/range-o".into(),
            query_string: String::new(),
            headers,
            body: swift_http::IncomingBody::from_bytes(payload.clone(), u64::MAX),
        };
        assert_eq!(server.handle_async(put).await.status, 201);
        let mut rh = HeaderKeyDict::new();
        rh.set("Range", "bytes=2-5");
        let got = server
            .handle_async(AsyncRequest {
                method: "GET".into(),
                path: "/sda1/0/AUTH_test/c/range-o".into(),
                query_string: String::new(),
                headers: rh,
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(got.status, 206, "{}", got.reason);
        let slice = got.body.collect_async().await.unwrap_or_default();
        assert_eq!(slice, b"cdef");
        let full = server
            .handle_async(AsyncRequest {
                method: "GET".into(),
                path: "/sda1/0/AUTH_test/c/range-o".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(full.status, 200, "{}", full.reason);
        let etag = full.headers.get("ETag").unwrap_or("").to_string();
        assert!(!etag.is_empty(), "object GET must expose ETag");
        let mut inm = HeaderKeyDict::new();
        inm.set("If-None-Match", etag);
        let cond = server
            .handle_async(AsyncRequest {
                method: "GET".into(),
                path: "/sda1/0/AUTH_test/c/range-o".into(),
                query_string: String::new(),
                headers: inm,
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(cond.status, 304, "If-None-Match must 304, {}", cond.reason);
        let del = server
            .handle_async(AsyncRequest {
                method: "DELETE".into(),
                path: "/sda1/0/AUTH_test/c/range-o".into(),
                query_string: String::new(),
                headers: {
                    let mut h = HeaderKeyDict::new();
                    h.set("X-Timestamp", "2004");
                    h
                },
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert!(
            matches!(del.status, 204 | 200),
            "DELETE status {}",
            del.status
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn post_echoes_object_sysmeta_for_symlink() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-post-sysmeta-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let mut put_h = HeaderKeyDict::new();
        put_h.set("X-Timestamp", "4001");
        put_h.set("Content-Type", "application/symlink");
        put_h.set("Content-Length", 0);
        put_h.set("X-Object-Sysmeta-Symlink-Target", "c2/obj");
        let put = server.handle(Request {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/link".into(),
            query_string: String::new(),
            headers: put_h,
            body: Body::empty(),
        });
        assert_eq!(put.status, 201, "{}", put.reason);
        let mut post_h = HeaderKeyDict::new();
        post_h.set("X-Timestamp", "4002");
        post_h.set("Content-Type", "application/foo");
        let post = server.handle(Request {
            method: "POST".into(),
            path: "/sda1/0/AUTH_test/c/link".into(),
            query_string: String::new(),
            headers: post_h,
            body: Body::empty(),
        });
        assert_eq!(post.status, 202, "{}", post.reason);
        assert_eq!(
            post.headers.get("X-Object-Sysmeta-Symlink-Target"),
            Some("c2/obj"),
            "POST must echo symlink sysmeta so the proxy can 307"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ec_post_container_update_uses_whole_object_size_and_etag() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-post-ec-listing-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = ObjectServer::new(ObjectServerConfig {
            devices: dir.clone(),
            mount_check: false,
            hash_config: HashPathConfig::new(Vec::new(), b"post-ec-tests".to_vec()).unwrap(),
            diskfile: DiskFileConfig::default(),
            policies: std::collections::HashMap::from([(
                2,
                PolicyKind::Ec {
                    n_unique_fragments: Some(6),
                },
            )]),
            container_update_timeout: std::time::Duration::from_millis(10),
            container_update_mode: ContainerUpdateMode::Async,
        });

        let fragment = vec![b'f'; 82];
        let mut put_h = HeaderKeyDict::new();
        put_h.set("X-Timestamp", "4001");
        put_h.set("Content-Type", "application/octet-stream");
        put_h.set("Content-Length", fragment.len());
        put_h.set("X-Backend-Storage-Policy-Index", "2");
        put_h.set("X-Object-Sysmeta-Ec-Frag-Index", "0");
        put_h.set("X-Object-Sysmeta-Ec-Etag", "whole-object-etag");
        put_h.set("X-Object-Sysmeta-Ec-Content-Length", "5");
        let put = server.handle(Request {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers: put_h,
            body: fragment.clone().into(),
        });
        assert_eq!(put.status, 201, "{}", put.reason);

        let mut post_h = HeaderKeyDict::new();
        post_h.set("X-Timestamp", "4002");
        post_h.set("X-Backend-Storage-Policy-Index", "2");
        post_h.set("X-Object-Meta-Fruit", "Tomato");
        let post = server.handle(Request {
            method: "POST".into(),
            path: "/sda1/0/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers: post_h,
            body: Body::empty(),
        });
        assert_eq!(post.status, 202, "{}", post.reason);

        let mut stats = UpdaterStats::default();
        let pending = iter_async_pendings(&dir.join("sda1"), &mut stats);
        let update = pending
            .iter()
            .find(|update| update.account == "AUTH_test" && update.obj == "o")
            .expect("POST must leave a container async update");
        let header = |name: &str| {
            update
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(header("x-size"), Some("5"));
        assert_eq!(header("x-etag"), Some("whole-object-etag"));

        // Persisted generic container-update overrides must win after the EC
        // whole-object fallback, matching Python's prefix ordering.
        let mut override_put_h = HeaderKeyDict::new();
        override_put_h.set("X-Timestamp", "5001");
        override_put_h.set("Content-Type", "application/octet-stream");
        override_put_h.set("Content-Length", fragment.len());
        override_put_h.set("X-Backend-Storage-Policy-Index", "2");
        override_put_h.set("X-Object-Sysmeta-Ec-Frag-Index", "1");
        override_put_h.set("X-Object-Sysmeta-Ec-Etag", "unexpected-ec-etag");
        override_put_h.set("X-Object-Sysmeta-Ec-Content-Length", "99");
        override_put_h.set("X-Object-Sysmeta-Container-Update-Override-Size", "7");
        override_put_h.set(
            "X-Object-Sysmeta-Container-Update-Override-Etag",
            "override-etag",
        );
        let override_put = server.handle(Request {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/o-override".into(),
            query_string: String::new(),
            headers: override_put_h,
            body: fragment.into(),
        });
        assert_eq!(override_put.status, 201, "{}", override_put.reason);

        let mut override_post_h = HeaderKeyDict::new();
        override_post_h.set("X-Timestamp", "5002");
        override_post_h.set("X-Backend-Storage-Policy-Index", "2");
        let override_post = server.handle(Request {
            method: "POST".into(),
            path: "/sda1/0/AUTH_test/c/o-override".into(),
            query_string: String::new(),
            headers: override_post_h,
            body: Body::empty(),
        });
        assert_eq!(override_post.status, 202, "{}", override_post.reason);

        let mut override_stats = UpdaterStats::default();
        let override_pending = iter_async_pendings(&dir.join("sda1"), &mut override_stats);
        let override_update = override_pending
            .iter()
            .find(|update| update.account == "AUTH_test" && update.obj == "o-override")
            .expect("override POST must leave a container async update");
        let override_header = |name: &str| {
            override_update
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(override_header("x-size"), Some("7"));
        assert_eq!(override_header("x-etag"), Some("override-etag"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn post_delete_at_enqueues_expirer_task_with_object_bytes() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-post-expirer-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));

        let mut put_h = HeaderKeyDict::new();
        put_h.set("X-Timestamp", "4001");
        put_h.set("Content-Type", "application/octet-stream");
        put_h.set("Content-Length", 24);
        let put = server.handle(Request {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers: put_h,
            body: vec![b'x'; 24].into(),
        });
        assert_eq!(put.status, 201, "{}", put.reason);

        let mut post_h = HeaderKeyDict::new();
        post_h.set("X-Timestamp", "4002");
        post_h.set("X-Delete-At", "9999999999");
        // Force the direct update to fail quickly so the behavior is
        // inspectable in the same durable async_pending format used live.
        post_h.set("X-Delete-At-Host", "127.0.0.1:1");
        post_h.set("X-Delete-At-Device", "sdb1");
        post_h.set("X-Delete-At-Partition", "1");
        // Modern Swift spreads one day's tasks across 100 adjacent container
        // names; the proxy-provided container is therefore often offset from
        // the raw day boundary and its partition is tied to that exact name.
        let object_hash = server
            .config
            .hash_config
            .hash_path("AUTH_test", Some("c"), Some("o"))
            .unwrap();
        let task_container = get_expirer_container_for_object_hash(
            9_999_999_999,
            &object_hash,
            EXPIRER_CONTAINER_DIVISOR,
            EXPIRER_CONTAINER_PER_DIVISOR,
        );
        assert_ne!(
            task_container, "9999936000",
            "test must exercise a non-zero shard offset"
        );
        post_h.set("X-Delete-At-Container", &task_container);
        let post = server.handle(Request {
            method: "POST".into(),
            path: "/sda1/0/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers: post_h,
            body: Body::empty(),
        });
        assert_eq!(post.status, 202, "{}", post.reason);

        let mut stats = UpdaterStats::default();
        let pending = iter_async_pendings(&dir.join("sda1"), &mut stats);
        let expiry = pending
            .iter()
            .find(|update| update.account == EXPIRER_ACCOUNT_NAME)
            .expect("POST X-Delete-At must enqueue an expirer task");
        assert_eq!(expiry.op, "PUT");
        assert_eq!(expiry.container, task_container);
        assert_eq!(
            expiry
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("x-content-type"))
                .map(|(_, value)| value.as_str()),
            Some("text/plain;swift_expirer_bytes=24")
        );
        assert!(expiry
            .headers
            .iter()
            .any(|(key, _)| { key.eq_ignore_ascii_case("x-content-type-timestamp") }));

        let mut clear_h = HeaderKeyDict::new();
        clear_h.set("X-Timestamp", "4003");
        let clear = server.handle(Request {
            method: "POST".into(),
            path: "/sda1/0/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers: clear_h,
            body: Body::empty(),
        });
        assert_eq!(clear.status, 202, "{}", clear.reason);
        let mut stats = UpdaterStats::default();
        let pending = iter_async_pendings(&dir.join("sda1"), &mut stats);
        let cleanup = pending
            .iter()
            .find(|update| update.account == EXPIRER_ACCOUNT_NAME)
            .expect("clearing X-Delete-At must enqueue queue cleanup");
        assert_eq!(cleanup.op, "DELETE");
        assert_eq!(cleanup.container, task_container);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handle_async_put_if_none_match_and_delete_at() {
        let dir =
            std::env::temp_dir().join(format!("swift-obj-inm-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let put = |ts: &str, name: &str, extra: &[(&str, &str)]| {
            let mut headers = HeaderKeyDict::new();
            headers.set("X-Timestamp", ts);
            headers.set("Content-Type", "application/octet-stream");
            headers.set("Content-Length", 0);
            for (k, v) in extra {
                headers.set(*k, *v);
            }
            AsyncRequest {
                method: "PUT".into(),
                path: format!("/sda1/0/AUTH_test/c/{name}"),
                query_string: String::new(),
                headers,
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            }
        };
        let first = server
            .handle_async(put("3001", "inm-o", &[("If-None-Match", "*")]))
            .await;
        assert_eq!(first.status, 201, "{}", first.reason);
        let second = server
            .handle_async(put("3002", "inm-o", &[("If-None-Match", "*")]))
            .await;
        assert_eq!(second.status, 412, "existing object must 412");
        let bad = server
            .handle_async(put("3003", "inm-o", &[("If-None-Match", "abc")]))
            .await;
        assert_eq!(bad.status, 400);
        let past = server
            .handle_async(put("3004", "past-o", &[("X-Delete-At", "1")]))
            .await;
        assert_eq!(past.status, 400, "past X-Delete-At must 400");
        let non_int = server
            .handle_async(put("3005", "ni-o", &[("X-Delete-At", "*")]))
            .await;
        assert_eq!(non_int.status, 400);
        let soon = server
            .handle_async(put("3006", "exp-o", &[("X-Delete-At", "1")]))
            .await;
        // timestamp 3006 > delete-at 1 → still 400 (delete-at in the past vs req ts)
        assert_eq!(soon.status, 400);
        let future = server
            .handle_async(put("3007", "exp-o", &[("X-Delete-At", "9999999999")]))
            .await;
        assert_eq!(future.status, 201, "{}", future.reason);
        let head = server
            .handle_async(AsyncRequest {
                method: "HEAD".into(),
                path: "/sda1/0/AUTH_test/c/exp-o".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(head.status, 200);
        assert_eq!(head.headers.get("X-Delete-At"), Some("9999999999"));
        let expired_put = server
            .handle_async(put("1000", "gone-o", &[("X-Delete-At", "1001")]))
            .await;
        assert_eq!(expired_put.status, 201, "{}", expired_put.reason);
        let expired_get = server
            .handle_async(AsyncRequest {
                method: "GET".into(),
                path: "/sda1/0/AUTH_test/c/gone-o".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(expired_get.status, 404, "past X-Delete-At must 404 on GET");
        let mut replication_headers = HeaderKeyDict::new();
        replication_headers.set("X-Backend-Replication", "True");
        let replication_get = server
            .handle_async(AsyncRequest {
                method: "GET".into(),
                path: "/sda1/0/AUTH_test/c/gone-o".into(),
                query_string: String::new(),
                headers: replication_headers,
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(
            replication_get.status, 200,
            "backend replication must read an expired-but-unreaped object"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handle_async_mime_put_ingests_without_whole_object_buffer() {
        let dir =
            std::env::temp_dir().join(format!("swift-obj-mime-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let before = server.storage().stats().blocking.started_total;
        let payload = vec![b'm'; 96 * 1024];
        let boundary = "mimebound";
        let mut mime = Vec::new();
        mime.extend_from_slice(
            format!("--{boundary}\r\nX-Document: object body\r\n\r\n").as_bytes(),
        );
        mime.extend_from_slice(&payload);
        let footer_json = b"{}";
        let footer_md5 = {
            use md5::{Digest, Md5};
            format!("{:x}", Md5::digest(footer_json))
        };
        mime.extend_from_slice(
            format!(
                "\r\n--{boundary}\r\nX-Document: object metadata\r\nContent-MD5: {footer_md5}\r\n\r\n"
            )
            .as_bytes(),
        );
        mime.extend_from_slice(footer_json);
        mime.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "2002");
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Transfer-Encoding", "chunked");
        headers.set("X-Backend-Obj-Metadata-Footer", "yes");
        headers.set("X-Backend-Obj-Multipart-Mime-Boundary", boundary);
        headers.set("X-Backend-Obj-Content-Length", payload.len());
        let areq = AsyncRequest {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/mime-o".into(),
            query_string: String::new(),
            headers,
            body: swift_http::IncomingBody::from_bytes(mime, u64::MAX),
        };
        let resp = server.handle_async(areq).await;
        assert_eq!(resp.status, 201, "{}", resp.reason);
        assert!(
            server.storage().stats().blocking.started_total > before,
            "MIME object bytes must be written on StorageExecutor"
        );
        let mut got = server.handle(get_named("mime-o"));
        assert_eq!(got.status, 200);
        assert_eq!(got.body.materialize(u64::MAX).unwrap(), &payload[..]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handle_async_ssync_missing_check_uses_storage_executor() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-ssync-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let before = server.storage().stats().blocking.started_total;
        let offer = crate::ssync::encode_missing(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Timestamp::now(),
            None,
            None,
            None,
        );
        let wire = format!(
            ":MISSING_CHECK: START\r\n{offer}\r\n:MISSING_CHECK: END\r\n:UPDATES: START\r\n:UPDATES: END\r\n"
        );
        let mut headers = HeaderKeyDict::new();
        headers.set("Content-Length", wire.len());
        let areq = AsyncRequest {
            method: "SSYNC".into(),
            path: "/sda1/0".into(),
            query_string: String::new(),
            headers,
            body: swift_http::IncomingBody::from_bytes(wire.into_bytes(), u64::MAX),
        };
        let resp = server.handle_async(areq).await;
        assert_eq!(resp.status, 200, "{}", resp.reason);
        assert_eq!(
            resp.headers.get("X-Backend-Accept-No-Commit").unwrap_or(""),
            "True"
        );
        let body = resp.body.collect_async().await.expect("ssync channel");
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains(":MISSING_CHECK: START"),
            "ssync body {text:?}"
        );
        assert!(
            server.storage().stats().blocking.started_total > before,
            "SSYNC missing-check must run on StorageExecutor"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handle_async_ssync_returns_200_before_sender_body() {
        // Python ssync_sender.py:264-272: getresponse() after endheaders(),
        // before any :MISSING_CHECK: bytes. A session that waits for Incoming
        // EOF before 200 deadlocks the sender.
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-ssync-early-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, std::io::Error>>(8);
        let areq = AsyncRequest {
            method: "SSYNC".into(),
            path: "/sda1/0".into(),
            query_string: String::new(),
            headers: HeaderKeyDict::new(),
            body: swift_http::IncomingBody::from_channel(body_rx, None, None, u64::MAX),
        };
        let resp = tokio::time::timeout(
            std::time::Duration::from_millis(400),
            server.handle_async(areq),
        )
        .await
        .expect("SSYNC 200 must not wait for the sender body (ssync_sender.py:264-272)");
        assert_eq!(resp.status, 200, "{}", resp.reason);
        assert_eq!(
            resp.headers.get("X-Backend-Accept-No-Commit").unwrap_or(""),
            "True"
        );
        let part_path = dir.join("sda1").join(get_data_dir(0)).join("0");
        let busy = acquire_replication_session_lock(
            server.storage(),
            DeviceId::new("sda1"),
            part_path.clone(),
            0.05,
        )
        .await;
        assert!(
            matches!(busy, Err(response) if response.status == 503),
            "the partition replication lock must remain held after the 200 head"
        );
        let before = server.storage().stats().blocking.started_total;
        let offer = crate::ssync::encode_missing(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Timestamp::now(),
            None,
            None,
            None,
        );
        let wire = format!(
            ":MISSING_CHECK: START\r\n{offer}\r\n:MISSING_CHECK: END\r\n:UPDATES: START\r\n:UPDATES: END\r\n"
        );
        body_tx.send(Ok(wire.into_bytes())).await.unwrap();
        drop(body_tx);
        let body = resp
            .body
            .collect_async()
            .await
            .expect("ssync channel after body");
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains(":MISSING_CHECK: START") && text.contains(":MISSING_CHECK: END"),
            "ssync body {text:?}"
        );
        assert!(
            server.storage().stats().blocking.started_total > before,
            "missing-check FS must run on StorageExecutor after 200"
        );
        let released = acquire_replication_session_lock(
            server.storage(),
            DeviceId::new("sda1"),
            part_path,
            0.2,
        )
        .await;
        assert!(
            released.is_ok(),
            "the replication lock must be released when the SSYNC session ends"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn async_ssync_busy_replication_lock_is_503_before_channel() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-ssync-busy-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let part_path = dir.join("sda1").join(get_data_dir(0)).join("0");
        let held = swift_core::lockutil::lock_path(&part_path, 1.0, Some("replication")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let response = server
            .ssync_async_with_lock_timeout(
                AsyncRequest {
                    method: "SSYNC".into(),
                    path: "/sda1/0".into(),
                    query_string: String::new(),
                    headers: HeaderKeyDict::new(),
                    body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
                },
                0.05,
            )
            .await;
        assert_eq!(response.status, 503);
        assert!(response.headers.get("X-Backend-Accept-No-Commit").is_none());
        assert!(
            !matches!(response.body, Body::Channel(_)),
            "a busy partition must fail before constructing the SSYNC channel"
        );
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handle_async_get_does_not_pin_storage_on_slow_client() {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-slowget-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let payload = vec![b'g'; STREAM_CHUNK * 3];
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", "2010");
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Content-Length", payload.len());
        let put = AsyncRequest {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/slow-get".into(),
            query_string: String::new(),
            headers,
            body: swift_http::IncomingBody::from_bytes(payload, u64::MAX),
        };
        assert_eq!(server.handle_async(put).await.status, 201);
        let got = server
            .handle_async(AsyncRequest {
                method: "GET".into(),
                path: "/sda1/0/AUTH_test/c/slow-get".into(),
                query_string: String::new(),
                headers: HeaderKeyDict::new(),
                body: swift_http::IncomingBody::from_bytes(Vec::new(), u64::MAX),
            })
            .await;
        assert_eq!(got.status, 200, "{}", got.reason);
        let Body::Channel(ch) = got.body else {
            panic!("shipped GET must be Body::Channel, got {:?}", got.body);
        };
        let (rx, _scope, _) = ch.into_rx();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let started = server.storage().stats().blocking.started_total;
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        assert_eq!(
            server.storage().stats().blocking.started_total,
            started,
            "slow client must not issue further disk reads while the channel is full"
        );
        assert_eq!(
            server.storage().stats().device_ops_active,
            0,
            "storage workers must not stay pinned waiting for the client"
        );
        drop(rx);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blackhole_sync_container_update_does_not_starve_health_get() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;
        use swift_http::ServerConfig;

        let hole = TcpListener::bind("127.0.0.1:0").unwrap();
        let hole_addr = hole.local_addr().unwrap();
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-blackhole-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let mut server = tiny_server(&dir, FallocateReserve::Bytes(1));
        server.config.container_update_timeout = std::time::Duration::from_secs(2);
        server.config.container_update_mode = ContainerUpdateMode::Sync;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let cfg = ServerConfig {
            worker_threads: 2,
            shutdown: Some(std::sync::Arc::clone(&shutdown)),
            ..ServerConfig::default()
        };
        thread::spawn(move || serve_with_config(listener, server, cfg));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(20)).is_ok() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(5));
        }
        thread::spawn(move || {
            let mut c =
                TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(400)).unwrap();
            let host = format!("{hole_addr}");
            let req = format!(
                "PUT /sda1/0/AUTH_test/c/o HTTP/1.1\r\nHost: t\r\nX-Timestamp: 4000\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nX-Container-Host: {host}\r\nX-Container-Device: sda1\r\nX-Container-Partition: 0\r\nConnection: close\r\n\r\nabcd"
            );
            let _ = c.write_all(req.as_bytes());
            let mut buf = Vec::new();
            let _ = c.read_to_end(&mut buf);
        });
        thread::sleep(std::time::Duration::from_millis(30));
        let started = std::time::Instant::now();
        let mut g =
            TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(400)).unwrap();
        g.set_read_timeout(Some(std::time::Duration::from_millis(400)))
            .unwrap();
        g.write_all(b"GET /health HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut buf = Vec::new();
        let _ = g.read_to_end(&mut buf);
        let elapsed = started.elapsed();
        assert!(!buf.is_empty(), "health GET got no response");
        assert!(
            elapsed < std::time::Duration::from_millis(400),
            "health GET took {elapsed:?} during blackhole container update"
        );
        shutdown.store(true, Ordering::SeqCst);
        drop(hole);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Python `obj/server.py:1311-1369` DELETE of a live object with a newer
    /// timestamp is `HTTPNoContent` (204) after `disk_file.delete` tombstone.
    /// SSYNC: `obj/server.py:1406-1415` returns 200 with
    /// `X-Backend-Accept-No-Commit: True`; missing-check is
    /// `ssync_receiver.py:451-513` (`:MISSING_CHECK: START`/`END`).
    #[test]
    fn hyper_serve_shipped_put_delete_ssync_wire() {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;
        use swift_http::ServerConfig;

        let dir = std::env::temp_dir().join(format!(
            "swift-obj-hyper-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let cfg = ServerConfig {
            worker_threads: 2,
            shutdown: Some(std::sync::Arc::clone(&shutdown)),
            ..ServerConfig::default()
        };
        thread::spawn(move || serve_with_config(listener, server, cfg));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(20)).is_ok() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(5));
        }

        let mut c =
            TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(400)).unwrap();
        c.set_read_timeout(Some(std::time::Duration::from_millis(800)))
            .unwrap();
        c.write_all(
            b"PUT /sda1/0/AUTH_test/c/o HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Timestamp: 3000\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd",
        )
        .unwrap();
        let mut buf = Vec::new();
        let _ = c.read_to_end(&mut buf);
        let put = String::from_utf8_lossy(&buf);
        assert!(put.contains("201"), "PUT {put:?}");

        let mut c =
            TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(400)).unwrap();
        c.set_read_timeout(Some(std::time::Duration::from_millis(800)))
            .unwrap();
        c.write_all(
            b"DELETE /sda1/0/AUTH_test/c/o HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Timestamp: 3001\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        buf.clear();
        let _ = c.read_to_end(&mut buf);
        let del = String::from_utf8_lossy(&buf);
        assert!(
            del.contains("204"),
            "DELETE tombstone must be 204 HTTPNoContent (obj/server.py:1311-1369), got {del:?}"
        );

        let mut c =
            TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(400)).unwrap();
        c.set_read_timeout(Some(std::time::Duration::from_millis(800)))
            .unwrap();
        let ssync =
            b":MISSING_CHECK: START\r\n:MISSING_CHECK: END\r\n:UPDATES: START\r\n:UPDATES: END\r\n";
        let head = format!(
            "SSYNC /sda1/0 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            ssync.len()
        );
        c.write_all(head.as_bytes()).unwrap();
        c.write_all(ssync).unwrap();
        buf.clear();
        let _ = c.read_to_end(&mut buf);
        let ss = String::from_utf8_lossy(&buf);
        assert!(
            ss.contains("200"),
            "SSYNC status (obj/server.py:1406-1415) {ss:?}"
        );
        assert!(
            ss.to_ascii_lowercase()
                .contains("x-backend-accept-no-commit: true"),
            "SSYNC must advertise X-Backend-Accept-No-Commit (obj/server.py:1412), got {ss:?}"
        );

        shutdown.store(true, Ordering::SeqCst);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Python sender (`ssync_sender.py:240-373`): SSYNC + `Transfer-Encoding:
    /// chunked`, `getresponse()` **before** `:MISSING_CHECK:`, then missing
    /// check, then updates. FS stays on StorageExecutor — the client fd is
    /// not owned by a blocking thread for the session.
    #[test]
    fn hyper_serve_ssync_full_duplex_async_socket() {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;
        use swift_http::ServerConfig;

        let dir = std::env::temp_dir().join(format!(
            "swift-obj-ssync-duplex-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let server = tiny_server(&dir, FallocateReserve::Bytes(1));
        let metrics = swift_runtime::ConcurrencyMetrics::new();
        let cfg = ServerConfig {
            worker_threads: 2,
            shutdown: Some(std::sync::Arc::clone(&shutdown)),
            metrics: Some(metrics.clone()),
            ..ServerConfig::default()
        };
        thread::spawn(move || serve_with_config(listener, server, cfg));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(20)).is_ok() {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(5));
        }

        let mut c =
            TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(400)).unwrap();
        c.set_nodelay(true).ok();
        c.set_read_timeout(Some(std::time::Duration::from_millis(800)))
            .unwrap();
        c.set_write_timeout(Some(std::time::Duration::from_millis(800)))
            .unwrap();
        // Sender endheaders() — no body yet (ssync_sender.py:251-264).
        c.write_all(
            b"SSYNC /sda1/0 HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap();
        c.flush().ok();

        let mut head = Vec::new();
        let mut one = [0u8; 1];
        let head_deadline = std::time::Instant::now() + std::time::Duration::from_millis(800);
        while std::time::Instant::now() < head_deadline && head.len() < 8192 {
            match c.read(&mut one) {
                Ok(0) => break,
                Ok(_) => {
                    head.push(one[0]);
                    if head.len() >= 4 && &head[head.len() - 4..] == b"\r\n\r\n" {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let head_s = String::from_utf8_lossy(&head);
        assert!(
            head_s.contains("200"),
            "Python sender getresponse() after SSYNC headers must see 200 before the body (ssync_sender.py:264-272), got {head_s:?}"
        );
        assert!(
            head_s
                .to_ascii_lowercase()
                .contains("x-backend-accept-no-commit: true"),
            "obj/server.py:1406-1415 {head_s:?}"
        );
        assert!(
            head_s.to_ascii_lowercase().contains("x-trans-id:"),
            "SSYNC response must carry X-Trans-Id for G3 traces, got {head_s:?}"
        );
        assert!(
            !head_s.to_ascii_lowercase().contains("connection: close"),
            "Python http.client must retain the SSYNC socket after getresponse(), got {head_s:?}"
        );
        let snap = metrics.snapshot();
        assert!(
            snap.native_async_requests_total >= 1,
            "SSYNC handoff must increment native_async, got {}",
            snap.native_async_requests_total
        );
        assert_eq!(snap.legacy_sync_handler_requests_total, 0);
        assert_eq!(snap.block_in_place_total, 0);
        assert_eq!(snap.blocking_network_wait_total, 0);

        // Same listener, 2 workers: a health GET must complete while this
        // SSYNC session still holds the client fd waiting for MISSING_CHECK.
        let health = thread::spawn(move || {
            let mut g =
                TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(400)).unwrap();
            g.set_read_timeout(Some(std::time::Duration::from_millis(400)))
                .unwrap();
            g.write_all(b"GET /health HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut buf = Vec::new();
            let _ = g.read_to_end(&mut buf);
            buf
        });
        let health_buf = health.join().expect("health thread");
        let health_s = String::from_utf8_lossy(&health_buf);
        assert!(
            health_s.contains("HTTP/1.1"),
            "health GET must complete while SSYNC holds the async socket, got {health_s:?}"
        );

        fn write_http_chunk(c: &mut TcpStream, data: &[u8]) {
            // Python's SsyncBufferedHTTPConnection.send() writes one complete
            // HTTP chunk frame per call. Mirror that exact wire boundary.
            let mut frame = format!("{:x}\r\n", data.len()).into_bytes();
            frame.extend_from_slice(data);
            frame.extend_from_slice(b"\r\n");
            c.write_all(&frame).unwrap();
        }
        write_http_chunk(&mut c, b":MISSING_CHECK: START\r\n:MISSING_CHECK: END\r\n");
        c.flush().ok();

        let mut rest = Vec::new();
        let miss_deadline = std::time::Instant::now() + std::time::Duration::from_millis(800);
        while std::time::Instant::now() < miss_deadline {
            let mut tmp = [0u8; 512];
            match c.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    rest.extend_from_slice(&tmp[..n]);
                    if String::from_utf8_lossy(&rest).contains(":MISSING_CHECK: END") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let miss = String::from_utf8_lossy(&rest);
        assert!(
            miss.contains(":MISSING_CHECK: START") && miss.contains(":MISSING_CHECK: END"),
            "receiver missing_check yield (ssync_receiver.py:509-513) {miss:?}"
        );

        write_http_chunk(&mut c, b":UPDATES: START\r\n:UPDATES: END\r\n");
        write_http_chunk(&mut c, b"");
        c.flush().ok();
        let upd_deadline = std::time::Instant::now() + std::time::Duration::from_millis(800);
        while std::time::Instant::now() < upd_deadline {
            let mut tmp = [0u8; 512];
            match c.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    rest.extend_from_slice(&tmp[..n]);
                    if String::from_utf8_lossy(&rest).contains(":UPDATES: END") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let all = String::from_utf8_lossy(&rest);
        assert!(
            all.contains(":UPDATES: END"),
            "receiver updates (ssync_receiver.py) {all:?}"
        );

        shutdown.store(true, Ordering::SeqCst);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod native_worm_gate_wiring_tests {
    use super::*;
    use crate::worm_native_gate::{
        SYS_LEGAL_HOLD, SYS_LOCK_MODE, SYS_LOCK_REVISION, SYS_RETAIN_UNTIL,
    };

    fn server(devices: &Path) -> ObjectServer {
        ObjectServer::new(ObjectServerConfig {
            devices: devices.to_path_buf(),
            mount_check: false,
            hash_config: HashPathConfig::new(Vec::new(), b"worm-gate-tests".to_vec()).unwrap(),
            diskfile: DiskFileConfig::default(),
            policies: std::collections::HashMap::from([(0, PolicyKind::Replication)]),
            container_update_timeout: std::time::Duration::from_secs(1),
            container_update_mode: ContainerUpdateMode::Sync,
        })
    }

    fn temp_devices() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "swift-obj-worm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sda1")).unwrap();
        dir
    }

    fn put_req(ts: &str, extra: &[(&str, &str)], body: &[u8]) -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", ts);
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Content-Length", body.len());
        for (k, v) in extra {
            headers.set(k, *v);
        }
        Request {
            method: "PUT".into(),
            path: "/sda1/0/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers,
            body: body.to_vec().into(),
        }
    }

    fn method_req(method: &str, ts: &str) -> Request {
        method_req_headers(method, ts, &[])
    }

    fn method_req_headers(method: &str, ts: &str, extra: &[(&str, &str)]) -> Request {
        let mut headers = HeaderKeyDict::new();
        headers.set("X-Timestamp", ts);
        for (k, v) in extra {
            headers.set(k, *v);
        }
        Request {
            method: method.into(),
            path: "/sda1/0/AUTH_test/c/o".into(),
            query_string: String::new(),
            headers,
            body: Body::empty(),
        }
    }

    #[test]
    fn unlocked_put_and_missing_headers_allow() {
        let dir = temp_devices();
        let srv = server(&dir);
        assert_eq!(srv.handle(put_req("1", &[], b"a")).status, 201);
        assert_eq!(srv.handle(put_req("2", &[], b"b")).status, 201);
        assert_eq!(srv.handle(method_req("DELETE", "3")).status, 204);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legal_hold_and_compliance_deny_existing_mutations() {
        let dir = temp_devices();
        let srv = server(&dir);
        assert_eq!(
            srv.handle(put_req("1", &[(SYS_LEGAL_HOLD, "ON")], b"held"))
                .status,
            201
        );
        let mut overwrite = srv.handle(put_req("2", &[], b"nope"));
        assert_eq!(overwrite.status, 403);
        assert_eq!(
            String::from_utf8_lossy(overwrite.body.materialize(u64::MAX).unwrap()),
            "object is locked"
        );
        assert_eq!(srv.handle(method_req("POST", "3")).status, 403);
        assert_eq!(srv.handle(method_req("DELETE", "4")).status, 403);
        assert_eq!(srv.handle(method_req("GET", "5")).status, 200);

        let dir2 = temp_devices();
        let srv2 = server(&dir2);
        assert_eq!(
            srv2.handle(put_req(
                "1",
                &[
                    (SYS_LOCK_MODE, "COMPLIANCE"),
                    (SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z"),
                ],
                b"locked"
            ))
            .status,
            201
        );
        assert_eq!(srv2.handle(method_req("DELETE", "2")).status, 403);
        let mut repl = put_req("3", &[], b"replica");
        repl.headers.set("X-Backend-Replication", "True");
        assert_eq!(srv2.handle(repl).status, 201);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn lock_sysmeta_post_allowed_overwrite_put_still_403() {
        let dir = temp_devices();
        let srv = server(&dir);
        assert_eq!(srv.handle(put_req("1", &[], b"plain")).status, 201);
        let lock_post = method_req_headers(
            "POST",
            "2",
            &[
                (SYS_LEGAL_HOLD, "ON"),
                (SYS_LOCK_MODE, "COMPLIANCE"),
                (SYS_RETAIN_UNTIL, "2033-05-18T03:33:20Z"),
                (SYS_LOCK_REVISION, "1"),
            ],
        );
        assert_eq!(srv.handle(lock_post).status, 202);
        assert_eq!(srv.handle(put_req("3", &[], b"nope")).status, 403);
        assert_eq!(srv.handle(method_req("POST", "4")).status, 403);
        assert_eq!(
            srv.handle(method_req_headers(
                "POST",
                "5",
                &[(SYS_LEGAL_HOLD, "ON"), ("X-Object-Meta-Color", "blue")]
            ))
            .status,
            403
        );
        let mut repl = put_req("6", &[], b"replica");
        repl.headers.set("X-Backend-Replication", "True");
        assert_eq!(srv.handle(repl).status, 201);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_if_match_mismatch_412_match_allows() {
        let dir = temp_devices();
        let srv = server(&dir);
        let mut missing = put_req("1", &[], b"abc");
        missing.headers.set("If-Match", "\"deadbeef\"");
        assert_eq!(srv.handle(missing).status, 412);

        let created = srv.handle(put_req("1", &[], b"abc"));
        assert_eq!(created.status, 201);
        let etag = created
            .headers
            .get("ETag")
            .expect("PUT 201 carries ETag")
            .to_string();

        let mut star = put_req("2", &[], b"star");
        star.headers.set("If-None-Match", "*");
        assert_eq!(srv.handle(star).status, 412);

        let mut mismatch = put_req("2", &[], b"nope");
        mismatch.headers.set("If-Match", "\"deadbeef\"");
        assert_eq!(srv.handle(mismatch).status, 412);

        let mut matched = put_req("2", &[], b"ok");
        matched.headers.set("If-Match", &etag);
        assert_eq!(srv.handle(matched).status, 201);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_locked_put_overwrite_still_denied() {
        let dir = temp_devices();
        let srv = server(&dir);
        assert_eq!(
            srv.handle(put_req(
                "1",
                &[
                    (SYS_LEGAL_HOLD, "ON"),
                    ("X-Delete-At", "1"),
                    ("X-Backend-Replication", "True"),
                ],
                b"held"
            ))
            .status,
            201
        );
        assert_eq!(srv.handle(put_req("2", &[], b"nope")).status, 403);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replication_post_can_remove_expiry_after_delete_at_has_passed() {
        let dir = temp_devices();
        let srv = server(&dir);
        assert_eq!(
            srv.handle(put_req(
                "1",
                &[("X-Delete-At", "1"), ("X-Backend-Replication", "True"),],
                b"repair-me"
            ))
            .status,
            201
        );
        assert_eq!(srv.handle(method_req("HEAD", "1")).status, 404);

        let replicated_post = method_req_headers("POST", "2", &[("X-Backend-Replication", "True")]);
        assert_eq!(srv.handle(replicated_post).status, 202);

        let repaired = srv.handle(method_req("HEAD", "2"));
        assert_eq!(repaired.status, 200);
        assert_eq!(repaired.headers.get("X-Delete-At"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
