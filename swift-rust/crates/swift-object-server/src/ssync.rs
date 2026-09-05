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

//! Bounded, incremental parser for the replication-policy SSYNC wire format.
//!
//! The parser deliberately stops after `:MISSING_CHECK: END`. A streaming
//! HTTP adapter can therefore send the wanted response before permitting the
//! sender to transmit updates. The current object-server adapter also uses
//! this boundary even though `swift-http` still buffers complete request
//! bodies.

use std::fmt;

use swift_core::timestamp::Timestamp;
use swift_http::HeaderKeyDict;

pub const MAX_SESSION_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_LINE_LENGTH: usize = 64 * 1024;
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_HEADERS: usize = 128;
pub const MAX_SUBREQUEST_BODY: usize = 64 * 1024 * 1024;
pub const MAX_MISSING_OFFERS: usize = 100_000;
pub const MAX_UPDATES: usize = 10_000;
pub const STREAM_CHUNK_BYTES: usize = 64 * 1024;
const MAX_STREAM_BUFFER_BYTES: usize = 2 * MAX_HEADER_BYTES + STREAM_CHUNK_BYTES;

const MISSING_START: &[u8] = b":MISSING_CHECK: START";
const MISSING_END: &[u8] = b":MISSING_CHECK: END";
const UPDATES_START: &[u8] = b":UPDATES: START";
const UPDATES_END: &[u8] = b":UPDATES: END";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingOffer {
    pub object_hash: String,
    pub ts_data: Timestamp,
    pub ts_meta: Timestamp,
    pub ts_ctype: Timestamp,
    pub durable: bool,
}

/// Sender-side encoder for one missing-check line, the exact port of
/// `ssync_sender.encode_missing`:
/// `<hash> <ts_data> [m:<hex delta>[__<hex offset>][,t:<hex delta>[__<hex
/// offset>]][,durable:False]`. The decoder is [`SsyncParser`]'s
/// missing-offer parser (`ssync_receiver.decode_missing`).
pub fn encode_missing(
    object_hash: &str,
    ts_data: Timestamp,
    ts_meta: Option<Timestamp>,
    ts_ctype: Option<Timestamp>,
    durable: Option<bool>,
) -> String {
    // Swift object hashes and internal timestamps are already URL-safe;
    // Python's quote() is an identity transform on them.
    // Python's '%x' renders a negative int as '-<hex>'; Rust's {:x} would
    // render two's complement, so sign is handled explicitly.
    fn signed_hex(value: i64) -> String {
        if value < 0 {
            format!("-{:x}", value.unsigned_abs())
        } else {
            format!("{value:x}")
        }
    }
    let mut msg = format!("{object_hash} {}", ts_data.internal());
    let mut extra_parts: Vec<String> = Vec::new();
    if let Some(ts_meta) = ts_meta {
        if ts_meta != ts_data {
            let delta = ts_meta.raw() - ts_data.raw();
            let mut part = format!("m:{}", signed_hex(delta));
            if ts_meta.offset() != 0 {
                part.push_str(&format!("__{:x}", ts_meta.offset()));
            }
            extra_parts.push(part);
            if let Some(ts_ctype) = ts_ctype {
                if ts_ctype != ts_data {
                    let delta = ts_ctype.raw() - ts_data.raw();
                    let mut part = format!("t:{}", signed_hex(delta));
                    if ts_ctype.offset() != 0 {
                        part.push_str(&format!("__{:x}", ts_ctype.offset()));
                    }
                    extra_parts.push(part);
                }
            }
        }
    }
    if durable == Some(false) {
        // only send durable in the less common case that it is False
        extra_parts.push("durable:False".to_string());
    }
    if !extra_parts.is_empty() {
        msg = format!("{msg} {}", extra_parts.join(","));
    }
    msg
}

#[derive(Debug, Clone, PartialEq)]
pub struct SsyncSubrequest {
    pub method: String,
    pub path: String,
    pub headers: HeaderKeyDict,
    pub body: Vec<u8>,
    /// Lower-case incoming header names, excluding `etag` and
    /// `x-backend-no-commit`, as expected by the object-server replication
    /// header contract.
    pub replication_headers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SsyncEvent {
    Missing(MissingOffer),
    MissingEnd,
    Update(SsyncSubrequest),
    /// Streaming PUT metadata, followed by bounded chunks and UpdateEnd.
    /// Its body is empty; only the legacy parser emits a materialized Update.
    UpdateStart(SsyncSubrequest),
    UpdateChunk(Vec<u8>),
    UpdateEnd,
    UpdatesEnd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsyncError {
    message: String,
}

impl SsyncError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SsyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SsyncError {}

#[derive(Debug)]
struct PendingUpdate {
    method: String,
    path: String,
    headers: HeaderKeyDict,
    replication_headers: Vec<String>,
    header_count: usize,
    header_bytes: usize,
}

#[derive(Debug)]
enum ParserState {
    MissingStart,
    MissingLines,
    AwaitUpdatesPermission,
    UpdatesStart,
    UpdateLine,
    UpdateHeaders(PendingUpdate),
    UpdateBody(PendingUpdate, usize),
    StreamingBody(usize),
    Done,
    Transition,
    Failed,
}

/// Incremental SSYNC protocol parser.
///
/// [`push`](Self::push) accepts arbitrarily-sized chunks. Once it emits
/// [`SsyncEvent::MissingEnd`], it buffers but does not parse any later bytes
/// until [`start_updates`](Self::start_updates) is called.
#[derive(Debug)]
pub struct SsyncParser {
    state: ParserState,
    buffer: Vec<u8>,
    cursor: usize,
    total_bytes: usize,
    missing_offers: usize,
    updates: usize,
    failure: Option<SsyncError>,
    stream_puts: bool,
    max_subrequest_body: usize,
    max_session_bytes: usize,
}

impl Default for SsyncParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SsyncParser {
    pub fn new() -> Self {
        Self {
            state: ParserState::MissingStart,
            buffer: Vec::new(),
            cursor: 0,
            total_bytes: 0,
            missing_offers: 0,
            updates: 0,
            failure: None,
            stream_puts: false,
            max_subrequest_body: MAX_SUBREQUEST_BODY,
            max_session_bytes: MAX_SESSION_BYTES,
        }
    }

    /// Async receiver mode: no complete PUT body is retained. Callers feed
    /// at most STREAM_CHUNK_BYTES per push and consume events with backpressure.
    /// Session wire and individual object sizes remain independently bounded.
    pub fn streaming(max_subrequest_body: usize, max_session_bytes: usize) -> Self {
        Self {
            stream_puts: true,
            max_subrequest_body,
            max_session_bytes,
            ..Self::new()
        }
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<SsyncEvent>, SsyncError> {
        self.ensure_healthy()?;
        self.total_bytes = match self.total_bytes.checked_add(bytes.len()) {
            Some(total_bytes) => total_bytes,
            None => return self.record_error(SsyncError::new("SSYNC session too large")),
        };
        if self.total_bytes > self.max_session_bytes {
            return self.record_error(SsyncError::new("SSYNC session too large"));
        }
        if self.stream_puts
            && (bytes.len() > STREAM_CHUNK_BYTES
                || self.available().saturating_add(bytes.len()) > MAX_STREAM_BUFFER_BYTES)
        {
            return self.record_error(SsyncError::new("SSYNC streaming input buffer too large"));
        }
        self.buffer.extend_from_slice(bytes);
        self.process()
    }

    /// Permit parsing of the updates phase after the caller has processed the
    /// missing offers and made the wanted response available to the sender.
    pub fn start_updates(&mut self) -> Result<Vec<SsyncEvent>, SsyncError> {
        self.ensure_healthy()?;
        if !matches!(self.state, ParserState::AwaitUpdatesPermission) {
            return self.record_error(SsyncError::new("missing-check phase is not complete"));
        }
        self.state = ParserState::UpdatesStart;
        self.process()
    }

    /// Signal end-of-input and verify that the complete session was received.
    pub fn finish(&mut self) -> Result<(), SsyncError> {
        self.ensure_healthy()?;
        // Process any final complete line/body already buffered.
        self.process()?;
        let error = match self.state {
            ParserState::Done if self.available() == 0 => return Ok(()),
            ParserState::MissingStart | ParserState::MissingLines => "missing-check ended early",
            ParserState::AwaitUpdatesPermission => "updates phase was not started",
            ParserState::UpdatesStart | ParserState::UpdateLine | ParserState::UpdateHeaders(_) => {
                "updates ended early"
            }
            ParserState::UpdateBody(_, _) => "subrequest body truncated",
            ParserState::StreamingBody(_) => "subrequest body truncated",
            ParserState::Done => "trailing data after updates end",
            ParserState::Transition => "invalid parser state",
            ParserState::Failed => return Err(self.failure.clone().unwrap()),
        };
        self.record_error(SsyncError::new(error))
    }

    fn ensure_healthy(&self) -> Result<(), SsyncError> {
        match &self.failure {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn record_error<T>(&mut self, error: SsyncError) -> Result<T, SsyncError> {
        self.failure = Some(error.clone());
        self.state = ParserState::Failed;
        Err(error)
    }

    /// The stored failure, if the parser has already broken. Events emitted
    /// by the same [`push`](Self::push) that hit the error are still
    /// delivered (the receiver applies subrequests as they arrive, like
    /// Python's sequential receiver), so callers must check this after
    /// draining events.
    pub fn failure(&self) -> Option<&SsyncError> {
        self.failure.as_ref()
    }

    fn process(&mut self) -> Result<Vec<SsyncEvent>, SsyncError> {
        let mut events = Vec::new();
        match self.process_inner(&mut events) {
            Ok(()) => {
                self.compact();
                Ok(events)
            }
            Err(error) => {
                self.failure = Some(error.clone());
                self.state = ParserState::Failed;
                // Deliver the events parsed before the error; the stored
                // failure surfaces via failure() and every later call.
                if events.is_empty() {
                    Err(error)
                } else {
                    Ok(events)
                }
            }
        }
    }

    fn process_inner(&mut self, events: &mut Vec<SsyncEvent>) -> Result<(), SsyncError> {
        loop {
            let state = std::mem::replace(&mut self.state, ParserState::Transition);
            match state {
                ParserState::MissingStart => {
                    let Some(line) = self.take_line()? else {
                        self.state = ParserState::MissingStart;
                        break;
                    };
                    if trim_ascii(&line) != MISSING_START {
                        return Err(SsyncError::new("expected :MISSING_CHECK: START"));
                    }
                    self.state = ParserState::MissingLines;
                }
                ParserState::MissingLines => {
                    let Some(line) = self.take_line()? else {
                        self.state = ParserState::MissingLines;
                        break;
                    };
                    if trim_ascii(&line) == MISSING_END {
                        self.state = ParserState::AwaitUpdatesPermission;
                        events.push(SsyncEvent::MissingEnd);
                        // This pause is a protocol boundary, not just a parser
                        // implementation detail.
                        break;
                    }
                    self.missing_offers += 1;
                    if self.missing_offers > MAX_MISSING_OFFERS {
                        return Err(SsyncError::new("too many missing-check offers"));
                    }
                    events.push(SsyncEvent::Missing(parse_missing_offer(&line)?));
                    self.state = ParserState::MissingLines;
                }
                ParserState::AwaitUpdatesPermission => {
                    self.state = ParserState::AwaitUpdatesPermission;
                    break;
                }
                ParserState::UpdatesStart => {
                    let Some(line) = self.take_line()? else {
                        self.state = ParserState::UpdatesStart;
                        break;
                    };
                    if trim_ascii(&line) != UPDATES_START {
                        return Err(SsyncError::new("expected :UPDATES: START"));
                    }
                    self.state = ParserState::UpdateLine;
                }
                ParserState::UpdateLine => {
                    let Some(line) = self.take_line()? else {
                        self.state = ParserState::UpdateLine;
                        break;
                    };
                    if trim_ascii(&line) == UPDATES_END {
                        self.state = ParserState::Done;
                        events.push(SsyncEvent::UpdatesEnd);
                        continue;
                    }
                    self.updates += 1;
                    if self.updates > MAX_UPDATES {
                        return Err(SsyncError::new("too many SSYNC updates"));
                    }
                    let (method, path) = parse_request_line(&line)?;
                    self.state = ParserState::UpdateHeaders(PendingUpdate {
                        method,
                        path,
                        headers: HeaderKeyDict::new(),
                        replication_headers: Vec::new(),
                        header_count: 0,
                        header_bytes: 0,
                    });
                }
                ParserState::UpdateHeaders(mut pending) => {
                    let Some(line) = self.take_line()? else {
                        self.state = ParserState::UpdateHeaders(pending);
                        break;
                    };
                    if line.is_empty() {
                        let content_length =
                            validate_content_length(&pending, self.max_subrequest_body)?;
                        if self.stream_puts && pending.method == "PUT" {
                            events
                                .push(SsyncEvent::UpdateStart(finish_update(pending, Vec::new())));
                            if content_length == 0 {
                                events.push(SsyncEvent::UpdateEnd);
                                self.state = ParserState::UpdateLine;
                            } else {
                                self.state = ParserState::StreamingBody(content_length);
                            }
                        } else if content_length == 0 {
                            events.push(SsyncEvent::Update(finish_update(pending, Vec::new())));
                            self.state = ParserState::UpdateLine;
                        } else {
                            self.state = ParserState::UpdateBody(pending, content_length);
                        }
                        continue;
                    }
                    pending.header_count += 1;
                    if pending.header_count > MAX_HEADERS {
                        return Err(SsyncError::new("too many headers"));
                    }
                    pending.header_bytes = pending
                        .header_bytes
                        .checked_add(line.len())
                        .ok_or_else(|| SsyncError::new("headers too large"))?;
                    if pending.header_bytes > MAX_HEADER_BYTES {
                        return Err(SsyncError::new("headers too large"));
                    }
                    let (name, value) = parse_header(&line)?;
                    let lower_name = name.to_ascii_lowercase();
                    pending.headers.set(&name, value);
                    if lower_name != "etag" && lower_name != "x-backend-no-commit" {
                        pending.replication_headers.push(lower_name);
                    }
                    self.state = ParserState::UpdateHeaders(pending);
                }
                ParserState::UpdateBody(pending, content_length) => {
                    if self.available() < content_length {
                        self.state = ParserState::UpdateBody(pending, content_length);
                        break;
                    }
                    let body = self.take_bytes(content_length);
                    events.push(SsyncEvent::Update(finish_update(pending, body)));
                    self.state = ParserState::UpdateLine;
                }
                ParserState::StreamingBody(remaining) => {
                    let available = self.available().min(remaining).min(STREAM_CHUNK_BYTES);
                    if available == 0 {
                        self.state = ParserState::StreamingBody(remaining);
                        break;
                    }
                    events.push(SsyncEvent::UpdateChunk(self.take_bytes(available)));
                    if available == remaining {
                        events.push(SsyncEvent::UpdateEnd);
                        self.state = ParserState::UpdateLine;
                    } else {
                        self.state = ParserState::StreamingBody(remaining - available);
                    }
                }
                ParserState::Done => {
                    self.state = ParserState::Done;
                    if self.available() != 0 {
                        return Err(SsyncError::new("trailing data after updates end"));
                    }
                    break;
                }
                ParserState::Transition => {
                    return Err(SsyncError::new("invalid parser state"));
                }
                ParserState::Failed => {
                    self.state = ParserState::Failed;
                    return Err(self
                        .failure
                        .clone()
                        .unwrap_or_else(|| SsyncError::new("SSYNC parser failed")));
                }
            }
        }
        Ok(())
    }

    fn take_line(&mut self) -> Result<Option<Vec<u8>>, SsyncError> {
        let unread = &self.buffer[self.cursor..];
        let Some(relative_end) = unread.iter().position(|byte| *byte == b'\n') else {
            if unread.len() > MAX_LINE_LENGTH {
                return Err(SsyncError::new("line too long"));
            }
            return Ok(None);
        };
        if relative_end > MAX_LINE_LENGTH {
            return Err(SsyncError::new("line too long"));
        }
        let start = self.cursor;
        let mut end = start + relative_end;
        self.cursor = end + 1;
        if end > start && self.buffer[end - 1] == b'\r' {
            end -= 1;
        }
        Ok(Some(self.buffer[start..end].to_vec()))
    }

    fn take_bytes(&mut self, length: usize) -> Vec<u8> {
        let end = self.cursor + length;
        let bytes = self.buffer[self.cursor..end].to_vec();
        self.cursor = end;
        bytes
    }

    fn available(&self) -> usize {
        self.buffer.len() - self.cursor
    }

    fn compact(&mut self) {
        if self.cursor == self.buffer.len() {
            self.buffer.clear();
            self.cursor = 0;
        } else if self.cursor >= 64 * 1024 && self.cursor >= self.buffer.len() / 2 {
            self.buffer.drain(..self.cursor);
            self.cursor = 0;
        }
    }
}

fn finish_update(pending: PendingUpdate, body: Vec<u8>) -> SsyncSubrequest {
    SsyncSubrequest {
        method: pending.method,
        path: pending.path,
        headers: pending.headers,
        body,
        replication_headers: pending.replication_headers,
    }
}

fn validate_content_length(pending: &PendingUpdate, max_body: usize) -> Result<usize, SsyncError> {
    let raw = pending.headers.get("Content-Length");
    let content_length = match raw {
        None if pending.method == "PUT" => {
            return Err(SsyncError::new("missing content-length for PUT subrequest"));
        }
        None => 0,
        Some(value) => parse_content_length(value)?,
    };
    if content_length > max_body {
        return Err(SsyncError::new("subrequest body too large"));
    }
    if pending.method != "PUT" && content_length != 0 {
        return Err(SsyncError::new(format!(
            "{} subrequest with non-zero content-length",
            pending.method
        )));
    }
    Ok(content_length)
}

fn parse_content_length(value: &str) -> Result<usize, SsyncError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SsyncError::new("invalid content-length"));
    }
    trimmed
        .parse::<usize>()
        .map_err(|_| SsyncError::new("invalid content-length"))
}

fn parse_request_line(line: &[u8]) -> Result<(String, String), SsyncError> {
    if !line.is_ascii() {
        return Err(SsyncError::new("non-ASCII subrequest line"));
    }
    let line = std::str::from_utf8(line).map_err(|_| SsyncError::new("bad subrequest line"))?;
    let Some((method, path)) = line.split_once(' ') else {
        return Err(SsyncError::new("bad subrequest line"));
    };
    if !matches!(method, "PUT" | "POST" | "DELETE") {
        return Err(SsyncError::new(format!(
            "invalid subrequest method {method}"
        )));
    }
    if !path.starts_with('/')
        || path.len() == 1
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(SsyncError::new("invalid subrequest path"));
    }
    Ok((method.to_string(), path.to_string()))
}

fn parse_header(line: &[u8]) -> Result<(String, String), SsyncError> {
    let line = std::str::from_utf8(line).map_err(|_| SsyncError::new("bad header"))?;
    let Some((raw_name, raw_value)) = line.split_once(':') else {
        return Err(SsyncError::new("malformed header"));
    };
    let name = raw_name.trim();
    let value = raw_value.trim();
    let ascii_name = !name.is_empty() && name.bytes().all(is_header_name_byte);
    let swift_metadata_name = is_swift_metadata_header_name(name);
    if !ascii_name && !swift_metadata_name {
        return Err(SsyncError::new("invalid header name"));
    }
    // Python's SSYNC sender serializes WSGI metadata with wsgi_to_bytes(),
    // and its receiver reconstructs it with bytes_to_wsgi().  Consequently,
    // valid UTF-8 bytes may occur in Swift metadata names and values even
    // though they are not legal RFC HTTP field bytes.  This is an internal
    // SSYNC subrequest document, not an HTTP head; keep the exception narrow
    // to the three object-metadata namespaces instead of relaxing every
    // header accepted by the object server.
    if !line.is_ascii() && !swift_metadata_name {
        return Err(SsyncError::new(
            "non-ASCII data outside Swift metadata header",
        ));
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() && byte != b'\t')
    {
        return Err(SsyncError::new("invalid header value"));
    }
    Ok((name.to_string(), value.to_string()))
}

fn is_swift_metadata_header_name(name: &str) -> bool {
    const PREFIXES: [&str; 3] = [
        "x-object-meta-",
        "x-object-sysmeta-",
        "x-object-transient-sysmeta-",
    ];
    let lower = name.to_ascii_lowercase();
    let Some(prefix) = PREFIXES.iter().find(|prefix| lower.starts_with(**prefix)) else {
        return false;
    };
    let suffix = &name[prefix.len()..];
    !suffix.is_empty()
        && suffix.chars().all(|character| {
            if character.is_ascii() {
                is_header_name_byte(character as u8)
            } else {
                !character.is_control() && !character.is_whitespace()
            }
        })
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn parse_missing_offer(line: &[u8]) -> Result<MissingOffer, SsyncError> {
    if !line.is_ascii() {
        return Err(SsyncError::new("non-ASCII missing-check line"));
    }
    let mut parts = line.split(|byte| byte.is_ascii_whitespace());
    let object_hash =
        next_nonempty(&mut parts).ok_or_else(|| SsyncError::new("invalid missing-check line"))?;
    let ts_data =
        next_nonempty(&mut parts).ok_or_else(|| SsyncError::new("invalid missing-check line"))?;
    let options = next_nonempty(&mut parts);
    if next_nonempty(&mut parts).is_some() {
        return Err(SsyncError::new("invalid missing-check line"));
    }

    let object_hash = percent_decode_ascii(object_hash)?;
    if object_hash.len() != 32
        || !object_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SsyncError::new("invalid object hash"));
    }
    let raw_ts_data = percent_decode_ascii(ts_data)?;
    let ts_data = raw_ts_data
        .parse::<Timestamp>()
        .map_err(|_| SsyncError::new("invalid data timestamp"))?;
    let mut offer = MissingOffer {
        object_hash,
        ts_data,
        ts_meta: ts_data,
        ts_ctype: ts_data,
        durable: true,
    };

    if let Some(options) = options {
        let options = percent_decode_ascii(options)?;
        for option in options.split(',').filter(|option| option.contains(':')) {
            let Some((key, value)) = option.split_once(':') else {
                continue;
            };
            match key {
                "m" => offer.ts_meta = parse_delta_timestamp(ts_data, value)?,
                "t" => offer.ts_ctype = parse_delta_timestamp(ts_data, value)?,
                "durable" => offer.durable = config_true_value(value),
                _ => {}
            }
        }
    }
    Ok(offer)
}

fn next_nonempty<'a, I>(parts: &mut I) -> Option<&'a [u8]>
where
    I: Iterator<Item = &'a [u8]>,
{
    parts.find(|part| !part.is_empty())
}

fn parse_delta_timestamp(base: Timestamp, encoded: &str) -> Result<Timestamp, SsyncError> {
    let (delta, offset) = match encoded.split_once("__") {
        Some((delta, offset)) if !offset.contains("__") => (delta, offset),
        Some(_) => return Err(SsyncError::new("invalid timestamp delta")),
        None => (encoded, "0"),
    };
    if delta.is_empty() || offset.is_empty() {
        return Err(SsyncError::new("invalid timestamp delta"));
    }
    let delta =
        i64::from_str_radix(delta, 16).map_err(|_| SsyncError::new("invalid timestamp delta"))?;
    let offset =
        u64::from_str_radix(offset, 16).map_err(|_| SsyncError::new("invalid timestamp offset"))?;
    let raw = base
        .raw()
        .checked_add(delta)
        .ok_or_else(|| SsyncError::new("timestamp delta overflow"))?;
    Timestamp::from_parts(raw, offset).map_err(|_| SsyncError::new("timestamp delta out of range"))
}

fn percent_decode_ascii(input: &[u8]) -> Result<String, SsyncError> {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%' {
            if index + 2 >= input.len() {
                return Err(SsyncError::new("invalid percent escape"));
            }
            let high = hex_value(input[index + 1])
                .ok_or_else(|| SsyncError::new("invalid percent escape"))?;
            let low = hex_value(input[index + 2])
                .ok_or_else(|| SsyncError::new("invalid percent escape"))?;
            output.push((high << 4) | low);
            index += 3;
        } else {
            output.push(input[index]);
            index += 1;
        }
    }
    if !output.is_ascii() {
        return Err(SsyncError::new("percent-decoded value is not ASCII"));
    }
    String::from_utf8(output).map_err(|_| SsyncError::new("invalid ASCII value"))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn config_true_value(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on" | "t" | "y"
    )
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(test)]
mod streaming_tests {
    use super::*;

    fn begin(length: usize, max_body: usize, max_session: usize) -> SsyncParser {
        let mut parser = SsyncParser::streaming(max_body, max_session);
        let events = parser
            .push(b":MISSING_CHECK: START\r\n:MISSING_CHECK: END\r\n")
            .unwrap();
        assert_eq!(events, vec![SsyncEvent::MissingEnd]);
        assert!(parser.start_updates().unwrap().is_empty());
        let head = format!(":UPDATES: START\r\nPUT /a/c/o\r\nContent-Length: {length}\r\n\r\n");
        let events = parser.push(head.as_bytes()).unwrap();
        assert!(matches!(&events[0], SsyncEvent::UpdateStart(update) if update.body.is_empty()));
        parser
    }

    #[test]
    fn streaming_body_exceeds_legacy_limits_with_constant_buffer() {
        let length = MAX_SESSION_BYTES + 17;
        let mut parser = begin(length, length, length + 1024);
        let chunk = vec![b'x'; STREAM_CHUNK_BYTES];
        let mut sent = 0;
        let mut received = 0;
        let mut ended = 0;
        while sent < length {
            let take = chunk.len().min(length - sent);
            for event in parser.push(&chunk[..take]).unwrap() {
                match event {
                    SsyncEvent::UpdateChunk(bytes) => {
                        assert!(bytes.len() <= STREAM_CHUNK_BYTES);
                        assert!(bytes.iter().all(|b| *b == b'x'));
                        received += bytes.len();
                    }
                    SsyncEvent::UpdateEnd => ended += 1,
                    _ => panic!("streaming body emitted a materialized update"),
                }
            }
            sent += take;
            assert!(parser.buffer.capacity() <= MAX_STREAM_BUFFER_BYTES);
        }
        assert_eq!(received, length);
        assert_eq!(ended, 1);
        assert_eq!(
            parser.push(b":UPDATES: END\r\n").unwrap(),
            vec![SsyncEvent::UpdatesEnd]
        );
        parser.finish().unwrap();
    }

    #[test]
    fn streaming_truncation_and_input_batch_limits_are_errors() {
        let mut parser = begin(10, 10, 1024);
        assert_eq!(
            parser.push(b"abc").unwrap(),
            vec![SsyncEvent::UpdateChunk(b"abc".to_vec())]
        );
        assert!(parser.finish().unwrap_err().message().contains("truncated"));
        let mut parser = SsyncParser::streaming(10, 10_000_000);
        assert!(parser.push(&vec![0; STREAM_CHUNK_BYTES + 1]).is_err());
        assert_eq!(
            parser.buffer.capacity(),
            0,
            "reject oversized input before copying it"
        );
    }

    #[test]
    fn streaming_size_and_session_budgets_still_apply() {
        let mut parser = SsyncParser::streaming(9, 1024);
        parser
            .push(b":MISSING_CHECK: START\r\n:MISSING_CHECK: END\r\n")
            .unwrap();
        parser.start_updates().unwrap();
        let _ = parser.push(b":UPDATES: START\r\nPUT /a/c/o\r\nContent-Length: 10\r\n\r\n");
        assert!(parser.failure().is_some());
        let mut parser = begin(10, 10, 140);
        assert!(parser.push(&[0; 100]).is_err());
    }
}
