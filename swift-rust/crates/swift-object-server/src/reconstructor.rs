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

//! The EC object reconstructor (`swift/obj/reconstructor.py`).
//!
//! Two independent halves:
//!
//! 1. The ssync-driven partition jobs (`_get_part_jobs` / `process_job`):
//!    SYNC jobs push a primary's fragment state to its ring partners, REVERT
//!    jobs push misplaced (handoff) fragments to their proper primary and
//!    purge the local copies on success. These move existing fragment
//!    archives as opaque bytes and are feature-independent.
//!
//! 2. The fragment REBUILD path ([`EcDriver::reconstruct_object`]): given
//!    `ndata` peer fragment archives it rebuilds the archive for a specific
//!    fragment index, byte-identical to what the original PUT stored. This
//!    links liberasurecode, so it is behind the `ec` feature (Linux-only).

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use swift_core::hashing::HashPathConfig;
#[cfg(feature = "ec")]
use swift_core::timestamp::Timestamp;
use swift_diskfile::{DiskFile, DiskFileConfig, MetaValue, Metadata, PolicyKind};
use swift_ring::{Ring, RingDevice};

#[cfg(feature = "ec")]
use swift_ec::EcDriver;

/// A policy's erasure-coding scheme (the reconstructor's slice of it).
#[derive(Debug, Clone, Copy)]
pub struct EcScheme {
    pub ndata: usize,
    pub nparity: usize,
    pub segment_size: usize,
}

impl EcScheme {
    pub fn n_unique(&self) -> usize {
        self.ndata + self.nparity
    }
}

#[cfg(feature = "ec")]
pub fn fragment_archive_size_bound(scheme: EcScheme, original_size: usize) -> Option<usize> {
    if scheme.ndata == 0 || scheme.segment_size == 0 {
        return None;
    }
    let driver = EcDriver::new(scheme.ndata, scheme.nparity).ok()?;
    let mut total = 0usize;
    let mut remaining = original_size;
    while remaining > 0 {
        let segment = remaining.min(scheme.segment_size);
        total = total.checked_add(driver.fragment_size(segment))?;
        remaining -= segment;
    }
    Some(total)
}

/// A fragment archive fetched from a peer node, with the EC sysmeta needed to
/// rebuild and persist the local fragment.
#[derive(Debug, Clone)]
pub struct FetchedFragment {
    pub frag_index: i32,
    pub archive: Vec<u8>,
    pub ec_etag: String,
    pub ec_content_length: usize,
    /// The object's data timestamp (internal form), so the rebuilt fragment
    /// joins the same durable set.
    pub timestamp: String,
    pub content_type: String,
}

/// Fetches a peer's fragment archive for an object. Pluggable so the rebuild
/// logic is unit-tested without a live cluster.
pub trait FragmentFetcher {
    fn fetch(
        &self,
        node: &RingDevice,
        partition: u64,
        account: &str,
        container: &str,
        object: &str,
    ) -> Option<FetchedFragment>;

    /// Fetch a specific data timestamp when reconstructing from a local
    /// durable fragment while newer non-durable data may coexist on peers.
    /// Test fetchers that model a single version can use the default.
    fn fetch_at(
        &self,
        node: &RingDevice,
        partition: u64,
        account: &str,
        container: &str,
        object: &str,
        _preferred_timestamp: Option<&str>,
    ) -> Option<FetchedFragment> {
        self.fetch(node, partition, account, container, object)
    }
}

/// One object whose local fragment must be rebuilt.
#[derive(Debug, Clone)]
pub struct ReconstructJob {
    pub partition: u64,
    pub account: String,
    pub container: String,
    pub object: String,
    /// The fragment index this node is responsible for.
    pub destination_index: usize,
    /// The other nodes for this partition (fragment sources).
    pub peers: Vec<RingDevice>,
}

#[derive(Debug, PartialEq)]
pub enum ReconstructError {
    Ec(String),
    NotEnoughFragments,
    DiskFile(String),
    BadTimestamp(String),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconstructorStats {
    pub rebuilt: u64,
    pub failed: u64,
}

#[cfg(feature = "ec")]
fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    format!("{:x}", Md5::digest(data))
}

/// This node's fragment index for a partition: its position in the ordered
/// primary node list (Python `local_dev`'s index), or `None` if this node is
/// not a primary for the partition.
pub fn local_frag_index(
    ring: &Ring,
    part: u32,
    my_ip: &str,
    my_port: u32,
    my_device: &str,
) -> Option<usize> {
    let nodes = ring.get_part_nodes(part).ok()?;
    nodes
        .iter()
        .position(|pn| pn.dev.ip == my_ip && pn.dev.port == my_port && pn.dev.device == my_device)
}

/// Gather `ndata` fragment archives for one object from its peers. Keeps
/// only unique fragment indexes that agree on the object's EC etag, original
/// length, and data timestamp. A stale first peer must not anchor the entire
/// attempt when a later coherent quorum exists.
#[cfg(feature = "ec")]
fn gather_coherent_archives(
    peers: &[RingDevice],
    partition: u64,
    account: &str,
    container: &str,
    object: &str,
    ndata: usize,
    fetcher: &dyn FragmentFetcher,
    preferred_timestamp: Option<&str>,
) -> Result<(FetchedFragment, Vec<Vec<u8>>), ReconstructError> {
    type VersionKey = (String, String, usize);
    let mut versions: BTreeMap<VersionKey, BTreeMap<i32, FetchedFragment>> = BTreeMap::new();
    for node in peers {
        let Some(frag) = fetcher.fetch_at(
            node,
            partition,
            account,
            container,
            object,
            preferred_timestamp,
        ) else {
            continue;
        };
        if frag.frag_index < 0
            || preferred_timestamp.is_some_and(|expected| frag.timestamp != expected)
        {
            continue;
        }
        let key = (
            frag.timestamp.clone(),
            frag.ec_etag.clone(),
            frag.ec_content_length,
        );
        versions
            .entry(key)
            .or_default()
            .entry(frag.frag_index)
            .or_insert(frag);
    }
    let Some((_key, coherent)) = versions
        .into_iter()
        .rev()
        .find(|(_key, fragments)| fragments.len() >= ndata)
    else {
        return Err(ReconstructError::NotEnoughFragments);
    };
    let mut fragments = coherent.into_values().take(ndata);
    let first = fragments
        .next()
        .ok_or(ReconstructError::NotEnoughFragments)?;
    let chosen = FetchedFragment {
        frag_index: first.frag_index,
        archive: Vec::new(),
        ec_etag: first.ec_etag.clone(),
        ec_content_length: first.ec_content_length,
        timestamp: first.timestamp.clone(),
        content_type: first.content_type.clone(),
    };
    let mut archives = Vec::with_capacity(ndata);
    archives.push(first.archive);
    archives.extend(fragments.map(|fragment| fragment.archive));
    Ok((chosen, archives))
}

/// `reconstruct_fa` for the ssync SYNC path (`sync_diskfile_builder`): the
/// receiver stores fragments at ITS backend index, so a local fragment at a
/// different index is rebuilt on the fly from `ndata` coherent peer
/// fragments. The returned metadata is the LOCAL datafile metadata with the
/// frag-index sysmeta swapped and ETag removed (the receiving object server
/// recomputes it — `RebuildingECDiskFileStream`).
#[cfg(feature = "ec")]
pub struct EcSyncRebuilder<'a> {
    pub scheme: EcScheme,
    pub partition: u64,
    /// Fragment sources: the partition's primaries excluding the node being
    /// rebuilt to (Python `_make_fragment_requests`' source set).
    pub peers: Vec<RingDevice>,
    pub fetcher: &'a dyn FragmentFetcher,
}

#[cfg(feature = "ec")]
impl crate::ssync_sender::SyncDiskfileBuilder for EcSyncRebuilder<'_> {
    fn rebuild(
        &self,
        _object_hash: &str,
        datafile_metadata: &Metadata,
        target_frag_index: i64,
    ) -> Result<(Metadata, Vec<u8>), String> {
        let get = |name: &str| {
            datafile_metadata.iter().find_map(|(k, v)| match (k, v) {
                (MetaValue::Str(k), MetaValue::Str(v)) if k == name => Some(v.clone()),
                _ => None,
            })
        };
        let name = get("name").ok_or("datafile has no name")?;
        let mut parts = name.splitn(4, '/');
        let (_, account, container, object) = (
            parts.next(),
            parts.next().ok_or("bad name")?,
            parts.next().ok_or("bad name")?,
            parts.next().ok_or("bad name")?,
        );
        let local_ts = get("X-Timestamp").ok_or("datafile has no X-Timestamp")?;
        let (chosen, archives) = gather_coherent_archives(
            &self.peers,
            self.partition,
            account,
            container,
            object,
            self.scheme.ndata,
            self.fetcher,
            Some(&local_ts),
        )
        .map_err(|e| format!("{e:?}"))?;
        // The rebuilt bytes must belong to the SAME version the sender is
        // offering: peers serving a different timestamp would be labelled
        // with this datafile's metadata and corrupt the receiver's view.
        if chosen.timestamp != local_ts {
            return Err(format!(
                "peers serve timestamp {} but the local fragment is {local_ts}",
                chosen.timestamp
            ));
        }
        let driver =
            EcDriver::new(self.scheme.ndata, self.scheme.nparity).map_err(|e| format!("{e:?}"))?;
        let rebuilt = driver
            .reconstruct_object(
                &archives,
                chosen.ec_content_length,
                self.scheme.segment_size,
                target_frag_index as usize,
            )
            .map_err(|e| format!("{e:?}"))?;
        let mut metadata: Metadata = Vec::with_capacity(datafile_metadata.len());
        for (k, v) in datafile_metadata {
            if let MetaValue::Str(key) = k {
                // update the FI and delete the ETag, the obj server will
                // recalc on the other side (RebuildingECDiskFileStream)
                if key.eq_ignore_ascii_case("ETag") {
                    continue;
                }
                if key == "X-Object-Sysmeta-Ec-Frag-Index" {
                    metadata.push((k.clone(), MetaValue::Int(target_frag_index)));
                    continue;
                }
            }
            metadata.push((k.clone(), v.clone()));
        }
        Ok((metadata, rebuilt))
    }
}

/// Rebuild one job's fragment archive from its peers and persist it durably.
/// Fetches until `ndata` archives are gathered, reconstructs the destination
/// fragment, and writes it through the diskfile (durable `#<idx>#d.data`).
#[cfg(feature = "ec")]
#[allow(clippy::too_many_arguments)]
pub fn rebuild_job(
    device_path: &Path,
    policy_index: u32,
    scheme: EcScheme,
    hash_config: &HashPathConfig,
    cfg: &DiskFileConfig,
    job: &ReconstructJob,
    fetcher: &dyn FragmentFetcher,
) -> Result<(), ReconstructError> {
    let driver = EcDriver::new(scheme.ndata, scheme.nparity)
        .map_err(|e| ReconstructError::Ec(format!("{e:?}")))?;

    let (chosen, archives) = gather_coherent_archives(
        &job.peers,
        job.partition,
        &job.account,
        &job.container,
        &job.object,
        scheme.ndata,
        fetcher,
        None,
    )?;

    let rebuilt = driver
        .reconstruct_object(
            &archives,
            chosen.ec_content_length,
            scheme.segment_size,
            job.destination_index,
        )
        .map_err(|e| ReconstructError::Ec(format!("{e:?}")))?;

    let ts: Timestamp = chosen
        .timestamp
        .parse()
        .map_err(|_| ReconstructError::BadTimestamp(chosen.timestamp.clone()))?;

    let df = DiskFile::new(
        device_path,
        job.partition,
        &job.account,
        &job.container,
        &job.object,
        PolicyKind::Ec {
            n_unique_fragments: Some(scheme.n_unique() as u32),
        },
        policy_index,
        hash_config,
        cfg.clone(),
    )
    .map_err(|e| ReconstructError::DiskFile(e.to_string()))?;

    let metadata: Metadata = vec![
        (
            MetaValue::Str("name".into()),
            MetaValue::Str(format!("/{}/{}/{}", job.account, job.container, job.object)),
        ),
        (
            MetaValue::Str("X-Timestamp".into()),
            MetaValue::Str(ts.internal()),
        ),
        (
            MetaValue::Str("Content-Type".into()),
            MetaValue::Str(chosen.content_type.clone()),
        ),
        (
            MetaValue::Str("Content-Length".into()),
            MetaValue::Str(rebuilt.len().to_string()),
        ),
        (
            MetaValue::Str("ETag".into()),
            MetaValue::Str(md5_hex(&rebuilt)),
        ),
        (
            MetaValue::Str("X-Object-Sysmeta-Ec-Etag".into()),
            MetaValue::Str(chosen.ec_etag.clone()),
        ),
        (
            MetaValue::Str("X-Object-Sysmeta-Ec-Content-Length".into()),
            MetaValue::Str(chosen.ec_content_length.to_string()),
        ),
        (
            MetaValue::Str("X-Object-Sysmeta-Ec-Frag-Index".into()),
            MetaValue::Int(job.destination_index as i64),
        ),
    ];

    // Rebuild publication is a maintenance mutation of the same hash directory
    // used by foreground PUT/DELETE and EC revert purge. Serialize the entire
    // create/write/metadata/commit transition on the shared object stripe so a
    // purge or newer foreground generation cannot interleave with durability.
    let _mutation_guard = df
        .acquire_mutation_lock(OBJECT_MUTATION_LOCK_TIMEOUT)
        .map_err(|error| ReconstructError::DiskFile(error.to_string()))?;
    let mut writer = df
        .create(".data")
        .map_err(|e| ReconstructError::DiskFile(e.to_string()))?;
    writer
        .write(&rebuilt)
        .map_err(|e| ReconstructError::DiskFile(e.to_string()))?;
    writer
        .put(metadata)
        .map_err(|e| ReconstructError::DiskFile(e.to_string()))?;
    writer
        .commit(&ts)
        .map_err(|e| ReconstructError::DiskFile(e.to_string()))?;
    writer.close();
    Ok(())
}

/// Process a list of rebuild jobs, tallying successes and failures.
#[cfg(feature = "ec")]
#[allow(clippy::too_many_arguments)]
pub fn run_jobs(
    device_path: &Path,
    policy_index: u32,
    scheme: EcScheme,
    hash_config: &HashPathConfig,
    cfg: &DiskFileConfig,
    jobs: &[ReconstructJob],
    fetcher: &dyn FragmentFetcher,
) -> ReconstructorStats {
    let mut stats = ReconstructorStats::default();
    for job in jobs {
        match rebuild_job(
            device_path,
            policy_index,
            scheme,
            hash_config,
            cfg,
            job,
            fetcher,
        ) {
            Ok(()) => stats.rebuilt += 1,
            Err(_) => stats.failed += 1,
        }
    }
    stats
}

/// Scan a device's EC partitions and build a job for every object whose local
/// (this node's) fragment is missing from the durable set.
#[allow(clippy::too_many_arguments)]
pub fn discover_jobs(
    device_path: &Path,
    policy_index: u32,
    scheme: EcScheme,
    ring: &Ring,
    my_ip: &str,
    my_port: u32,
    my_device: &str,
    hash_config: &HashPathConfig,
    cfg: &DiskFileConfig,
) -> Vec<ReconstructJob> {
    let mut jobs = Vec::new();
    for hash_dir in swift_diskfile::audit_locations(device_path, policy_index) {
        let Some(part) = partition_of(&hash_dir, policy_index) else {
            continue;
        };
        let Some(dest_index) = local_frag_index(ring, part as u32, my_ip, my_port, my_device)
        else {
            continue; // not a primary for this partition
        };
        let mut df = DiskFile::from_hash_dir(
            device_path,
            &hash_dir,
            PolicyKind::Ec {
                n_unique_fragments: Some(scheme.n_unique() as u32),
            },
            policy_index,
            hash_config,
            cfg.clone(),
        );
        if df.open(None).is_err() {
            continue;
        }
        // The local fragment is present iff dest_index is in the newest durable
        // fragment set.
        let have_local = df
            .fragments()
            .ok()
            .and_then(|sets| sets.into_iter().max_by_key(|(ts, _)| *ts))
            .map(|(_, idxs)| idxs.contains(&(dest_index as i64)))
            .unwrap_or(false);
        if have_local {
            continue;
        }
        let Some((account, container, object)) = df.get_metadata().ok().and_then(object_name)
        else {
            continue;
        };
        let peers: Vec<RingDevice> = ring
            .get_part_nodes(part as u32)
            .map(|nodes| {
                nodes
                    .iter()
                    .filter(|pn| {
                        !(pn.dev.ip == my_ip
                            && pn.dev.port == my_port
                            && pn.dev.device == my_device)
                    })
                    .map(|pn| pn.dev.clone())
                    .collect()
            })
            .unwrap_or_default();
        jobs.push(ReconstructJob {
            partition: part,
            account,
            container,
            object,
            destination_index: dest_index,
            peers,
        });
    }
    jobs
}

/// Discover missing-fragment jobs on a device and rebuild them.
#[cfg(feature = "ec")]
#[allow(clippy::too_many_arguments)]
pub fn run_once(
    device_path: &Path,
    policy_index: u32,
    scheme: EcScheme,
    ring: &Ring,
    my_ip: &str,
    my_port: u32,
    my_device: &str,
    hash_config: &HashPathConfig,
    cfg: &DiskFileConfig,
    fetcher: &dyn FragmentFetcher,
) -> ReconstructorStats {
    let jobs = discover_jobs(
        device_path,
        policy_index,
        scheme,
        ring,
        my_ip,
        my_port,
        my_device,
        hash_config,
        cfg,
    );
    run_jobs(
        device_path,
        policy_index,
        scheme,
        hash_config,
        cfg,
        &jobs,
        fetcher,
    )
}

/// Parse `/{account}/{container}/{object}` out of the diskfile `name` metadata.
fn object_name(meta: &Metadata) -> Option<(String, String, String)> {
    let name = meta.iter().find_map(|(k, v)| match (k, v) {
        (MetaValue::Str(k), MetaValue::Str(v)) if k == "name" => Some(v.clone()),
        _ => None,
    })?;
    let rest = name.strip_prefix('/')?;
    let mut parts = rest.splitn(3, '/');
    let account = parts.next()?.to_string();
    let container = parts.next()?.to_string();
    let object = parts.next()?.to_string();
    if account.is_empty() || container.is_empty() || object.is_empty() {
        return None;
    }
    Some((account, container, object))
}

/// The partition number from a hash dir path
/// (`.../objects-<policy>/<part>/<suffix>/<hash>`).
fn partition_of(hash_dir: &Path, _policy_index: u32) -> Option<u64> {
    // hash_dir = <device>/<datadir>/<part>/<suffix>/<hash>
    let mut comps: Vec<_> = hash_dir.components().collect();
    comps.pop()?; // hash
    comps.pop()?; // suffix
    let part = comps.pop()?; // part
    part.as_os_str().to_str()?.parse().ok()
}

/// A real HTTP fragment fetcher: a backend GET to the peer object server,
/// reading the fragment archive body plus its EC sysmeta headers.
const INTERNAL_HTTP_HEAD_LIMIT: usize = 64 * 1024;
const INTERNAL_HTTP_LINE_LIMIT: usize = 16 * 1024;
const INTERNAL_HTTP_TRAILER_LIMIT: usize = 64 * 1024;
const INTERNAL_HTTP_TRAILER_LINE_LIMIT: usize = 8 * 1024;
const DEFAULT_FRAGMENT_RESPONSE_LIMIT: usize = 512 * 1024 * 1024;
const DEFAULT_SUFFIX_RESPONSE_LIMIT: usize = 16 * 1024 * 1024;

fn socket_addr(ip: &str, port: u32) -> Result<std::net::SocketAddr, String> {
    let ip: std::net::IpAddr = ip
        .parse()
        .map_err(|_| format!("invalid replication IP {ip:?}"))?;
    let port = u16::try_from(port).map_err(|_| format!("invalid replication port {port}"))?;
    Ok(std::net::SocketAddr::new(ip, port))
}

fn remaining_socket_timeout(deadline: Instant, idle: Duration) -> std::io::Result<Duration> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "request deadline"))?;
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "request deadline",
        ));
    }
    Ok(remaining.min(idle).max(Duration::from_millis(1)))
}

fn write_all_before(
    stream: &mut std::net::TcpStream,
    mut bytes: &[u8],
    idle: Duration,
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining_socket_timeout(deadline, idle)?))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "peer stopped accepting request bytes",
                ))
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

struct DeadlineSocketReader<'a> {
    stream: &'a mut std::net::TcpStream,
    idle: Duration,
    deadline: Instant,
    buffer: [u8; 8192],
    start: usize,
    end: usize,
}

impl<'a> DeadlineSocketReader<'a> {
    fn new(stream: &'a mut std::net::TcpStream, idle: Duration, deadline: Instant) -> Self {
        Self {
            stream,
            idle,
            deadline,
            buffer: [0; 8192],
            start: 0,
            end: 0,
        }
    }

    fn read_byte(&mut self) -> std::io::Result<u8> {
        if self.start == self.end {
            self.stream
                .set_read_timeout(Some(remaining_socket_timeout(self.deadline, self.idle)?))?;
            loop {
                match self.stream.read(&mut self.buffer) {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "peer closed response",
                        ))
                    }
                    Ok(read) => {
                        self.start = 0;
                        self.end = read;
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
        }
        let byte = self.buffer[self.start];
        self.start += 1;
        Ok(byte)
    }

    fn read_exact_vec(&mut self, len: usize) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        out.try_reserve_exact(len)
            .map_err(|_| format!("could not reserve {len} response bytes"))?;
        while out.len() < len {
            out.push(self.read_byte().map_err(|error| error.to_string())?);
        }
        Ok(out)
    }

    fn read_crlf_line(&mut self, limit: usize) -> Result<Vec<u8>, String> {
        let mut line = Vec::new();
        loop {
            let byte = self.read_byte().map_err(|error| error.to_string())?;
            if byte == b'\n' {
                if line.pop() != Some(b'\r') {
                    return Err("HTTP line ended without CRLF".to_string());
                }
                return Ok(line);
            }
            line.push(byte);
            if line.len() > limit.saturating_add(1) {
                return Err(format!("HTTP line exceeds {limit} bytes"));
            }
        }
    }
}

#[derive(Debug)]
struct InternalHttpHead {
    status: u16,
    headers: BTreeMap<String, String>,
}

fn read_internal_http_head(
    reader: &mut DeadlineSocketReader<'_>,
) -> Result<InternalHttpHead, String> {
    let status_line = reader.read_crlf_line(INTERNAL_HTTP_LINE_LIMIT)?;
    let status_line =
        std::str::from_utf8(&status_line).map_err(|_| "non-UTF8 HTTP status line".to_string())?;
    let mut status_parts = status_line.split_whitespace();
    let version = status_parts
        .next()
        .ok_or_else(|| "missing HTTP version".to_string())?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(format!("unsupported HTTP version {version:?}"));
    }
    let status = status_parts
        .next()
        .ok_or_else(|| "missing HTTP status".to_string())?
        .parse::<u16>()
        .map_err(|_| "invalid HTTP status".to_string())?;
    let mut total = status_line.len() + 2;
    let mut headers = BTreeMap::new();
    loop {
        let raw = reader.read_crlf_line(INTERNAL_HTTP_LINE_LIMIT)?;
        total = total
            .checked_add(raw.len() + 2)
            .ok_or_else(|| "HTTP response head length overflow".to_string())?;
        if total > INTERNAL_HTTP_HEAD_LIMIT {
            return Err(format!(
                "HTTP response head exceeds {INTERNAL_HTTP_HEAD_LIMIT} bytes"
            ));
        }
        if raw.is_empty() {
            break;
        }
        if raw.first().is_some_and(u8::is_ascii_whitespace) {
            return Err("folded HTTP response headers are not supported".to_string());
        }
        let line =
            std::str::from_utf8(&raw).map_err(|_| "non-UTF8 HTTP response header".to_string())?;
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "malformed HTTP response header".to_string())?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!("invalid HTTP response header name {name:?}"));
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim().to_string();
        if headers.insert(name.clone(), value).is_some() {
            return Err(format!("duplicate HTTP response header {name}"));
        }
    }
    Ok(InternalHttpHead { status, headers })
}

fn read_internal_http_body(
    reader: &mut DeadlineSocketReader<'_>,
    headers: &BTreeMap<String, String>,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let content_length = headers.get("content-length");
    let transfer_encoding = headers.get("transfer-encoding");
    if content_length.is_some() && transfer_encoding.is_some() {
        return Err("response contains both Content-Length and Transfer-Encoding".to_string());
    }
    if let Some(value) = content_length {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("invalid response Content-Length".to_string());
        }
        let len = value
            .parse::<usize>()
            .map_err(|_| "response Content-Length overflow".to_string())?;
        if len > limit {
            return Err(format!("response body exceeds {limit} bytes"));
        }
        return reader.read_exact_vec(len);
    }
    if let Some(value) = transfer_encoding {
        if !value.eq_ignore_ascii_case("chunked") {
            return Err(format!("unsupported response Transfer-Encoding {value:?}"));
        }
        let mut body = Vec::new();
        loop {
            let line = reader.read_crlf_line(128)?;
            let text =
                std::str::from_utf8(&line).map_err(|_| "non-ASCII HTTP chunk size".to_string())?;
            let size_text = text.split(';').next().unwrap_or_default().trim();
            if size_text.is_empty() || !size_text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err("invalid HTTP chunk size".to_string());
            }
            let size = usize::from_str_radix(size_text, 16)
                .map_err(|_| "HTTP chunk size overflow".to_string())?;
            if size == 0 {
                let mut trailer_bytes = 0usize;
                loop {
                    let trailer = reader.read_crlf_line(INTERNAL_HTTP_TRAILER_LINE_LIMIT)?;
                    trailer_bytes = trailer_bytes
                        .checked_add(trailer.len() + 2)
                        .ok_or_else(|| "HTTP trailers length overflow".to_string())?;
                    if trailer_bytes > INTERNAL_HTTP_TRAILER_LIMIT {
                        return Err("HTTP trailers exceed aggregate limit".to_string());
                    }
                    if trailer.is_empty() {
                        return Ok(body);
                    }
                    if !trailer.contains(&b':') {
                        return Err("malformed HTTP trailer".to_string());
                    }
                }
            }
            let next_len = body
                .len()
                .checked_add(size)
                .ok_or_else(|| "decoded HTTP body length overflow".to_string())?;
            if next_len > limit {
                return Err(format!("decoded response body exceeds {limit} bytes"));
            }
            body.try_reserve_exact(size)
                .map_err(|_| format!("could not reserve {size} response bytes"))?;
            body.extend_from_slice(&reader.read_exact_vec(size)?);
            if reader.read_exact_vec(2)? != b"\r\n" {
                return Err("HTTP chunk payload missing CRLF".to_string());
            }
        }
    }
    Err("response has no explicit body framing".to_string())
}

pub struct HttpFragmentFetcher {
    pub policy_index: u32,
    pub conn_timeout: Duration,
    pub node_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
    pub max_original_size: usize,
    pub scheme: Option<EcScheme>,
}

impl Default for HttpFragmentFetcher {
    fn default() -> Self {
        HttpFragmentFetcher {
            policy_index: 0,
            conn_timeout: Duration::from_millis(500),
            node_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(120),
            max_response_bytes: DEFAULT_FRAGMENT_RESPONSE_LIMIT,
            max_original_size: swift_core::constraints::MAX_FILE_SIZE as usize,
            scheme: None,
        }
    }
}

impl FragmentFetcher for HttpFragmentFetcher {
    fn fetch(
        &self,
        node: &RingDevice,
        partition: u64,
        account: &str,
        container: &str,
        object: &str,
    ) -> Option<FetchedFragment> {
        self.fetch_with_preference(node, partition, account, container, object, None)
    }

    fn fetch_at(
        &self,
        node: &RingDevice,
        partition: u64,
        account: &str,
        container: &str,
        object: &str,
        preferred_timestamp: Option<&str>,
    ) -> Option<FetchedFragment> {
        self.fetch_with_preference(
            node,
            partition,
            account,
            container,
            object,
            preferred_timestamp,
        )
    }
}

impl HttpFragmentFetcher {
    fn request_target(
        node: &RingDevice,
        partition: u64,
        account: &str,
        container: &str,
        object: &str,
    ) -> String {
        // Swift direct-client and ssync paths percent-encode UTF-8 octets.
        // Sending raw Unicode in an HTTP/1.1 request-target makes the peer's
        // URI parser reject or misroute non-ASCII objects, so reconstruction
        // silently gathers fewer than ndata archives while ASCII probes pass.
        let swift_path = format!("/{account}/{container}/{object}");
        format!(
            "/{}/{partition}{}",
            crate::percent_encode(&node.device),
            crate::percent_encode(&swift_path)
        )
    }

    fn fetch_with_preference(
        &self,
        node: &RingDevice,
        partition: u64,
        account: &str,
        container: &str,
        object: &str,
        preferred_timestamp: Option<&str>,
    ) -> Option<FetchedFragment> {
        let replication_ip = node.replication_ip.as_deref().unwrap_or(&node.ip);
        let replication_port = node.replication_port.unwrap_or(node.port);
        let sock = socket_addr(replication_ip, replication_port).ok()?;
        let mut conn = std::net::TcpStream::connect_timeout(&sock, self.conn_timeout).ok()?;
        let deadline = Instant::now().checked_add(self.request_timeout)?;
        let target = Self::request_target(node, partition, account, container, object);
        let preference_header = preferred_timestamp
            .map(|timestamp| {
                format!(
                    "X-Backend-Fragment-Preferences: {}\r\n",
                    serde_json::json!([{"timestamp": timestamp, "exclude": []}])
                )
            })
            .unwrap_or_default();
        let req = format!(
            "GET {target} HTTP/1.1\r\nHost: {addr}\r\n\
             X-Backend-Storage-Policy-Index: {}\r\n\
             X-Backend-Replication: True\r\n\
             {preference_header}\
            Content-Length: 0\r\nConnection: close\r\n\r\n",
            self.policy_index,
            addr = sock
        );
        write_all_before(&mut conn, req.as_bytes(), self.node_timeout, deadline).ok()?;
        let mut reader = DeadlineSocketReader::new(&mut conn, self.node_timeout, deadline);
        let head = read_internal_http_head(&mut reader).ok()?;
        if head.status != 200 {
            return None;
        }
        let ec_etag = head.headers.get("x-object-sysmeta-ec-etag")?.clone();
        if ec_etag.len() != 32 || !ec_etag.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let ec_content_length = head
            .headers
            .get("x-object-sysmeta-ec-content-length")?
            .parse::<usize>()
            .ok()?;
        if ec_content_length > self.max_original_size {
            return None;
        }
        let frag_index = head
            .headers
            .get("x-object-sysmeta-ec-frag-index")?
            .parse::<i32>()
            .ok()?;
        if frag_index < 0 {
            return None;
        }
        // Fast-POST objects carry both timestamps.  The data timestamp names
        // the fragment archive/durable set; the backend timestamp may instead
        // be the newer metadata timestamp.  Header order is not a contract, so
        // collect them independently and prefer the data timestamp explicitly.
        let timestamp = head
            .headers
            .get("x-backend-data-timestamp")
            .or_else(|| head.headers.get("x-backend-timestamp"))?
            .clone();
        timestamp.parse::<swift_core::timestamp::Timestamp>().ok()?;
        let content_type = head
            .headers
            .get("content-type")
            .cloned()
            .unwrap_or_else(|| "application/octet-stream".to_string());
        #[cfg(not(feature = "ec"))]
        let body_limit = self.max_response_bytes;
        #[cfg(feature = "ec")]
        let mut body_limit = self.max_response_bytes;
        #[cfg(feature = "ec")]
        if let Some(scheme) = self.scheme {
            if frag_index as usize >= scheme.n_unique() {
                return None;
            }
            let expected = fragment_archive_size_bound(scheme, ec_content_length)?;
            if expected > self.max_response_bytes {
                return None;
            }
            body_limit = expected;
        }
        let body = read_internal_http_body(&mut reader, &head.headers, body_limit).ok()?;
        #[cfg(feature = "ec")]
        if let Some(scheme) = self.scheme {
            let expected = fragment_archive_size_bound(scheme, ec_content_length)?;
            if body.len() != expected
                || (!body.is_empty() && EcDriver::fragment_index(&body) != Some(frag_index))
            {
                return None;
            }
        }
        Some(FetchedFragment {
            frag_index,
            archive: body,
            ec_etag,
            ec_content_length,
            timestamp,
            content_type,
        })
    }
}

// ---------------------------------------------------------------------------
// ssync-driven partition jobs (`_get_part_jobs` / `process_job`): SYNC pushes
// a primary's fragment state to its ring partners, REVERT pushes misplaced
// fragments to their proper primary and purges local copies on success.
// Feature-independent: fragment archives move as opaque bytes.
// ---------------------------------------------------------------------------

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use swift_core::pickle::{self, Value};
use swift_diskfile::{get_partition_hashes, CleanupConfig, Hashes};
use swift_ring::{HandoffNode, PartNode};

use crate::ssync_sender::{
    object_timestamps_from_hash_dir_strict, ObjectTimestamps, Sender, SenderReport, SsyncJob,
    SsyncNode, SsyncSenderError, TcpSsyncWire,
};

/// `reconstructor.SYNC` / `reconstructor.REVERT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcJobType {
    Sync,
    Revert,
}

/// One partition job (the Python `build_job` dict).
#[derive(Debug, Clone)]
pub struct EcPartJob {
    pub job_type: EcJobType,
    /// The fragment index whose suffixes this job moves (`None` for the
    /// tombstone-only revert job).
    pub frag_index: Option<i64>,
    pub suffixes: Vec<String>,
    pub sync_to: Vec<SsyncNode>,
    /// Ordered handoff candidates for SYNC targets that answer REPLICATE
    /// with 507. Each candidate carries the backend fragment index it stands
    /// in for, matching Python `_iter_nodes_for_frag`.
    pub sync_handoffs: Vec<SsyncNode>,
    pub partition: u64,
    /// Full path to the partition directory.
    pub path: PathBuf,
    pub device: String,
    /// This node's own frag index when it is a primary for the partition.
    pub primary_frag_index: Option<i64>,
}

/// `reconstructor._get_partners`: the left, right and far partners of the
/// primary at `node_index` (indices into the primary node list, duplicates
/// preserved exactly as in Python).
pub fn get_partners(node_index: usize, num_nodes: usize) -> Vec<usize> {
    vec![
        (node_index + num_nodes - 1) % num_nodes,
        (node_index + 1) % num_nodes,
        (node_index + num_nodes / 2) % num_nodes,
    ]
}

/// The suffixes whose cached hashes claim a data fragment at `frag_index`.
fn suffixes_claiming_frag(hashes: &Hashes, frag_index: i64) -> Vec<String> {
    let Value::Dict(suffix_map) = hashes.to_value() else {
        return Vec::new();
    };
    suffix_map
        .iter()
        .filter_map(|(suffix, fi_hash)| match (suffix, fi_hash) {
            (Value::Str(suffix), Value::Dict(fi_hash))
                if fi_hash.iter().any(|(fi, _)| *fi == Value::Int(frag_index)) =>
            {
                Some(suffix.clone())
            }
            _ => None,
        })
        .collect()
}

fn ssync_node(dev: &RingDevice, backend_index: i64) -> SsyncNode {
    SsyncNode {
        replication_ip: dev.replication_ip.clone().unwrap_or_else(|| dev.ip.clone()),
        replication_port: dev.replication_port.unwrap_or(dev.port),
        device: dev.device.clone(),
        backend_index: Some(backend_index),
    }
}

/// `reconstructor._get_part_jobs`: read the partition's per-frag-index suffix
/// hashes and build one SYNC job (if this node is a primary) plus REVERT jobs
/// for every other frag index found. With no EC duplication,
/// `get_backend_index(index) == index`.
///
/// Tombstone-only revert jobs sample `nparity + 1` distinct primaries on each
/// pass, matching Python's `random.sample`. Varying the subset is required for
/// liveness: repeatedly selecting the same unavailable primaries can otherwise
/// leave a handoff tombstone forever.
#[allow(clippy::too_many_arguments)]
pub fn build_part_jobs(
    part_path: &Path,
    partition: u64,
    device: &str,
    policy: PolicyKind,
    cleanup: &CleanupConfig,
    part_nodes: &[PartNode<'_>],
    handoff_nodes: &[HandoffNode<'_>],
    rebuild_handoff_node_count: i64,
    local_dev_id: u64,
    scheme: Option<EcScheme>,
) -> Vec<EcPartJob> {
    // this node's seat in the partition's primary list, if it has one
    let local_node = part_nodes.iter().find(|node| node.dev.id == local_dev_id);
    let primary_frag_index: Option<i64> = local_node.map(|node| node.index as i64);

    let Ok((_hashed, hashes)) = get_partition_hashes(part_path, policy, &[], true, cleanup) else {
        return Vec::new();
    };
    // The suffix hash cache is only ever refreshed by what goes through the
    // diskfile API, so a fragment that disappears behind its back — an
    // operator `rm`, a filesystem repair, a device restored from an older
    // snapshot — leaves this node advertising it over REPLICATE for good. No
    // partner can catch that: an EC suffix hash is an md5 over timestamps
    // alone, so the partner's entry for ITS frag index hashes to exactly the
    // value we still claim for ours, `get_suffix_delta` reads "in sync", and
    // the object stays at k fragments with nobody pushing a rebuild. This node
    // is the only one that can see the hole, and only by reading the
    // directory, so re-hash the suffixes we claim to hold our own fragment in
    // before anyone relies on them.
    let hashes = match primary_frag_index {
        Some(frag_index) => {
            let claimed = suffixes_claiming_frag(&hashes, frag_index);
            if claimed.is_empty() {
                hashes
            } else {
                let Ok((_hashed, verified)) =
                    get_partition_hashes(part_path, policy, &claimed, false, cleanup)
                else {
                    return Vec::new();
                };
                verified
            }
        }
        None => hashes,
    };
    let Value::Dict(suffix_map) = hashes.to_value() else {
        return Vec::new();
    };
    // find all the fi's in the part, and which suffixes have them
    let mut non_data_suffixes: Vec<String> = Vec::new();
    let mut data_fi_to_suffixes: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    for (suffix, fi_hash) in &suffix_map {
        let Value::Str(suffix) = suffix else { continue };
        let Value::Dict(fi_hash) = fi_hash else {
            continue;
        };
        if fi_hash.is_empty() {
            // normally an empty suffix is removed from the hashes; an OSError
            // during rehash can leave it empty (Python's sanity check)
            continue;
        }
        let data_fis: Vec<i64> = fi_hash
            .iter()
            .filter_map(|(key, _)| match key {
                Value::Int(fi) => Some(*fi),
                _ => None,
            })
            .collect();
        if data_fis.is_empty() {
            non_data_suffixes.push(suffix.clone());
        } else {
            for fi in data_fis {
                data_fi_to_suffixes
                    .entry(fi)
                    .or_default()
                    .push(suffix.clone());
            }
        }
    }

    let mut jobs: Vec<EcPartJob> = Vec::new();
    // check the primary nodes - to see if the part belongs here
    if let (Some(node), Some(pfi)) = (local_node, primary_frag_index) {
        let suffixes = data_fi_to_suffixes.remove(&pfi).unwrap_or_default();
        let sync_to = get_partners(node.index, part_nodes.len())
            .into_iter()
            .map(|i| ssync_node(part_nodes[i].dev, part_nodes[i].index as i64))
            .collect();
        let n_unique = scheme
            .map(|value| value.ndata + value.nparity)
            .unwrap_or(part_nodes.len())
            .max(1);
        let mut handoffs_per_index: BTreeMap<i64, usize> = BTreeMap::new();
        let sync_handoffs = handoff_nodes
            .iter()
            .filter_map(|handoff| {
                let backend_index = (handoff.handoff_index % n_unique) as i64;
                let count = handoffs_per_index.entry(backend_index).or_default();
                if rebuild_handoff_node_count >= 0 && *count >= rebuild_handoff_node_count as usize
                {
                    return None;
                }
                *count += 1;
                Some(ssync_node(handoff.dev, backend_index))
            })
            .collect();
        jobs.push(EcPartJob {
            job_type: EcJobType::Sync,
            frag_index: Some(pfi),
            suffixes,
            sync_to,
            sync_handoffs,
            partition,
            path: part_path.to_path_buf(),
            device: device.to_string(),
            primary_frag_index,
        });
    }

    // assign remaining data fragment suffixes to revert jobs
    let mut ordered_fis: Vec<(usize, i64)> = data_fi_to_suffixes
        .iter()
        .map(|(fi, suffixes)| (suffixes.len(), *fi))
        .collect();
    ordered_fis.sort_unstable();
    for (_count, fi) in ordered_fis {
        if fi < 0 || fi as usize >= part_nodes.len() {
            continue; // bad fragment index for these suffixes
        }
        let node = &part_nodes[fi as usize];
        jobs.push(EcPartJob {
            job_type: EcJobType::Revert,
            frag_index: Some(fi),
            suffixes: data_fi_to_suffixes[&fi].clone(),
            sync_to: vec![ssync_node(node.dev, fi)],
            sync_handoffs: Vec::new(),
            partition,
            path: part_path.to_path_buf(),
            device: device.to_string(),
            primary_frag_index,
        });
    }

    // now we need to assign suffixes that have no data fragments
    if !non_data_suffixes.is_empty() {
        if let Some(first) = jobs.first_mut() {
            first.suffixes.extend(non_data_suffixes);
        } else {
            // enough primaries that the tombstones are not lost, fewer than
            // all replicas: nparity + 1 (Python: n_unique - ndata + 1)
            let nsample = scheme
                .map(|s| s.nparity + 1)
                .unwrap_or(part_nodes.len())
                .min(part_nodes.len());
            let sync_to =
                tombstone_sample_indices(part_nodes.len(), nsample, partition, local_dev_id)
                    .into_iter()
                    .map(|index| {
                        let node = &part_nodes[index];
                        ssync_node(node.dev, node.index as i64)
                    })
                    .collect();
            jobs.push(EcPartJob {
                job_type: EcJobType::Revert,
                frag_index: None,
                suffixes: non_data_suffixes,
                sync_to,
                sync_handoffs: Vec::new(),
                partition,
                path: part_path.to_path_buf(),
                device: device.to_string(),
                primary_frag_index,
            });
        }
    }
    jobs
}

static TOMBSTONE_SAMPLE_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Partial Fisher-Yates sample without replacement. The generator need not be
/// cryptographic; it must provide an unbiased-enough, changing retry order as
/// Python's Mersenne-Twister-backed `random.sample` does.
fn sample_indices(total: usize, count: usize, mut seed: u64) -> Vec<usize> {
    let count = count.min(total);
    let mut indices: Vec<usize> = (0..total).collect();
    for selected in 0..count {
        let remaining = total - selected;
        let swap_with = selected + (splitmix64(&mut seed) as usize % remaining);
        indices.swap(selected, swap_with);
    }
    indices.truncate(count);
    indices
}

fn tombstone_sample_indices(
    total: usize,
    count: usize,
    partition: u64,
    local_dev_id: u64,
) -> Vec<usize> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let nonce = TOMBSTONE_SAMPLE_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let seed = (nanos as u64)
        ^ ((nanos >> 64) as u64)
        ^ partition.rotate_left(17)
        ^ local_dev_id.rotate_left(37)
        ^ (std::process::id() as u64).rotate_left(49)
        ^ nonce;
    sample_indices(total, count, seed)
}

/// Runs one ssync exchange against a node; pluggable so job processing is
/// testable without TCP (the real pusher dials [`TcpSsyncWire`]).
pub trait SsyncPusher {
    fn push(&self, sender: &Sender<'_>, node: &SsyncNode)
        -> Result<SenderReport, SsyncSenderError>;
}

/// The real TCP pusher: connect, run the exchange, terminate the request.
pub struct TcpSsyncPusher {
    pub conn_timeout: Duration,
    pub node_timeout: Duration,
}

impl Default for TcpSsyncPusher {
    fn default() -> Self {
        TcpSsyncPusher {
            conn_timeout: Duration::from_millis(500),
            node_timeout: Duration::from_secs(30),
        }
    }
}

impl SsyncPusher for TcpSsyncPusher {
    fn push(
        &self,
        sender: &Sender<'_>,
        node: &SsyncNode,
    ) -> Result<SenderReport, SsyncSenderError> {
        let mut wire =
            TcpSsyncWire::connect(node, sender.job, self.conn_timeout, self.node_timeout)?;
        let report = sender.run(&mut wire)?;
        wire.disconnect();
        Ok(report)
    }
}

/// Python `SuffixSyncError`: the REPLICATE exchange with a partner failed, so
/// the sync to that node is skipped (never a fall back to a whole-partition
/// ssync).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuffixSyncError {
    /// The target returned 507, so Python retries a matching handoff node.
    InsufficientStorage,
    /// Transport, other HTTP status, pickle, or local hash failure.
    Failed,
}

/// `reconstructor.get_suffix_delta`: compare local and remote EC per-suffix
/// hash dicts (`{suffix: {None | frag_index: md5hex}}` as pickle [`Value`]s)
/// and return the suffixes that should be synced.
///
/// Exact Python semantics: a local suffix syncs when the remote's entry under
/// the `None` key (tombstones/durables) differs from the local `None` entry,
/// or the remote's entry for `remote_backend_index` differs from the local
/// entry for `local_frag_index` — where "absent" on both sides compares equal
/// (Python `dict.get` returning `None` twice). Only local suffixes are
/// considered; remote-only suffixes are the remote's own job to push.
pub fn get_suffix_delta(
    local_hashes: &Value,
    local_frag_index: Option<i64>,
    remote_hashes: &Value,
    remote_backend_index: Option<i64>,
) -> Vec<String> {
    const EMPTY: &[(Value, Value)] = &[];
    fn frag_entry(sub: &[(Value, Value)], fi: Option<i64>) -> Option<&Value> {
        let key = match fi {
            Some(i) => Value::Int(i),
            None => Value::None,
        };
        sub.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }
    let Value::Dict(local) = local_hashes else {
        return Vec::new();
    };
    let remote = match remote_hashes {
        Value::Dict(pairs) => pairs.as_slice(),
        _ => EMPTY,
    };
    let mut suffixes = Vec::new();
    for (suffix, sub_local) in local {
        let Value::Str(suffix) = suffix else { continue };
        let Value::Dict(sub_local) = sub_local else {
            continue;
        };
        // Python `remote_suff.get(suffix, {})`.
        let sub_remote = remote
            .iter()
            .find(|(k, _)| matches!(k, Value::Str(s) if s == suffix))
            .and_then(|(_, v)| v.as_dict())
            .unwrap_or(EMPTY);
        if frag_entry(sub_local, None) != frag_entry(sub_remote, None)
            || frag_entry(sub_local, local_frag_index)
                != frag_entry(sub_remote, remote_backend_index)
        {
            suffixes.push(suffix.clone());
        }
    }
    suffixes
}

/// Fetches a partner's per-suffix hash dict over REPLICATE; pluggable so
/// SYNC-job narrowing is testable without a live peer (the real client is
/// [`HttpSuffixHashFetcher`]).
pub trait SuffixHashFetcher {
    /// REPLICATE `/<device>/<partition>`: the partner's pickled per-suffix
    /// hash dict, decoded; `None` on any transport/HTTP/parse failure.
    fn fetch_hashes(&self, node: &SsyncNode, partition: u64, policy_index: u32) -> Option<Value>;

    /// Status-preserving form used by the 507 handoff fallback. Existing test
    /// fetchers retain the old contract and map `None` to a generic failure.
    fn fetch_hashes_with_status(
        &self,
        node: &SsyncNode,
        partition: u64,
        policy_index: u32,
    ) -> Result<Value, SuffixSyncError> {
        self.fetch_hashes(node, partition, policy_index)
            .ok_or(SuffixSyncError::Failed)
    }
}

/// Real REPLICATE-verb client (the request shape of the object replicator's
/// `replicate_rpc`, aimed at the node's replication ip/port).
pub struct HttpSuffixHashFetcher {
    pub conn_timeout: Duration,
    pub node_timeout: Duration,
    pub request_timeout: Duration,
    pub max_response_bytes: usize,
}

impl Default for HttpSuffixHashFetcher {
    fn default() -> Self {
        HttpSuffixHashFetcher {
            conn_timeout: Duration::from_millis(500),
            node_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(30),
            max_response_bytes: DEFAULT_SUFFIX_RESPONSE_LIMIT,
        }
    }
}

impl HttpSuffixHashFetcher {
    fn fetch_result(
        &self,
        node: &SsyncNode,
        partition: u64,
        policy_index: u32,
    ) -> Result<Value, SuffixSyncError> {
        let sock = socket_addr(&node.replication_ip, node.replication_port)
            .map_err(|_| SuffixSyncError::Failed)?;
        let mut conn = std::net::TcpStream::connect_timeout(&sock, self.conn_timeout)
            .map_err(|_| SuffixSyncError::Failed)?;
        let deadline = Instant::now()
            .checked_add(self.request_timeout)
            .ok_or(SuffixSyncError::Failed)?;
        let req = format!(
            "REPLICATE /{}/{partition} HTTP/1.1\r\nHost: {addr}\r\n\
             X-Backend-Storage-Policy-Index: {policy_index}\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n",
            node.device,
            addr = sock
        );
        write_all_before(&mut conn, req.as_bytes(), self.node_timeout, deadline)
            .map_err(|_| SuffixSyncError::Failed)?;
        let mut reader = DeadlineSocketReader::new(&mut conn, self.node_timeout, deadline);
        let head = read_internal_http_head(&mut reader).map_err(|_| SuffixSyncError::Failed)?;
        if head.status == 507 {
            return Err(SuffixSyncError::InsufficientStorage);
        }
        if head.status != 200 {
            return Err(SuffixSyncError::Failed);
        }
        let body = read_internal_http_body(&mut reader, &head.headers, self.max_response_bytes)
            .map_err(|_| SuffixSyncError::Failed)?;
        pickle::loads(&body).map_err(|_| SuffixSyncError::Failed)
    }
}

impl SuffixHashFetcher for HttpSuffixHashFetcher {
    fn fetch_hashes(&self, node: &SsyncNode, partition: u64, policy_index: u32) -> Option<Value> {
        self.fetch_result(node, partition, policy_index).ok()
    }

    fn fetch_hashes_with_status(
        &self,
        node: &SsyncNode,
        partition: u64,
        policy_index: u32,
    ) -> Result<Value, SuffixSyncError> {
        self.fetch_result(node, partition, policy_index)
    }
}

/// `reconstructor._get_suffixes_to_sync`: REPLICATE to the partner for its
/// per-suffix hashes, diff against the local hashes, recalculate the local
/// hashes for the mismatched suffixes (Python's `recalculate=`, which
/// invalidates and rehashes each) and diff again so the comparison is
/// against the latest local state.
///
/// Any non-507 REPLICATE failure is Python's `SuffixSyncError`: the caller
/// skips the sync to this node. A 507 remains distinguishable so the caller
/// can retry a handoff with the same backend fragment index.
#[allow(clippy::too_many_arguments)]
pub fn get_suffixes_to_sync(
    part_path: &Path,
    partition: u64,
    policy: PolicyKind,
    policy_index: u32,
    cleanup: &CleanupConfig,
    local_frag_index: Option<i64>,
    node: &SsyncNode,
    fetcher: &dyn SuffixHashFetcher,
) -> Result<Vec<String>, SuffixSyncError> {
    let remote = fetcher.fetch_hashes_with_status(node, partition, policy_index)?;
    let (_hashed, local) = get_partition_hashes(part_path, policy, &[], false, cleanup)
        .map_err(|_| SuffixSyncError::Failed)?;
    let suffixes = get_suffix_delta(
        &local.to_value(),
        local_frag_index,
        &remote,
        node.backend_index,
    );
    // now recalculate local hashes for suffixes that don't match so we're
    // comparing the latest
    let (_hashed, local) = get_partition_hashes(part_path, policy, &suffixes, false, cleanup)
        .map_err(|_| SuffixSyncError::Failed)?;
    Ok(get_suffix_delta(
        &local.to_value(),
        local_frag_index,
        &remote,
        node.backend_index,
    ))
}

/// The revert-job partition lock timeout: Python's `_revert` passes an
/// explicit `timeout=0.2` to `partition_lock` (not the 15s
/// `replication_lock_timeout` default the replicator uses) — a busy receiver
/// means the partition is being handled, so give up fast.
const REVERT_LOCK_TIMEOUT: f64 = 0.2;

/// Foreground object mutations and maintenance purges share the same
/// cross-process stripe. A revert already owns `.lock-replication`, so this
/// is always acquired second; `DiskFile::purge` acquires the partition hash
/// lock only after it, preserving replication -> object -> hash ordering.
/// Reverts are maintenance work, so a busy object is left for the next pass
/// instead of stalling the partition for the foreground 15-second budget.
const OBJECT_MUTATION_LOCK_TIMEOUT: f64 = 0.2;

/// Keep every EC SSYNC exchange finite. A job may make bounded progress over
/// several pages, but it never materializes an entire dense partition in one
/// request or lets a peer's receiver limits decide our memory ceiling.
const EC_SSYNC_PAGE_OBJECTS: usize = 10_000;
const EC_SSYNC_PASS_OBJECTS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RevertFileIdentity {
    name: String,
    device: u64,
    inode: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RevertHashDirIdentity {
    device: u64,
    inode: u64,
    files: Vec<RevertFileIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RevertObjectSnapshot {
    suffix: String,
    timestamps: ObjectTimestamps,
    identity: RevertHashDirIdentity,
}

#[derive(Debug, Default)]
struct RevertPageSnapshot {
    objects: BTreeMap<String, RevertObjectSnapshot>,
    last_offered: Option<(String, String)>,
    limited_by_max_objects: bool,
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn snapshot_revert_hash_dir(hash_dir: &Path) -> Option<RevertHashDirIdentity> {
    let dir_metadata = hash_dir.symlink_metadata().ok()?;
    if !dir_metadata.file_type().is_dir() {
        return None;
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(hash_dir).ok()? {
        let entry = entry.ok()?;
        let metadata = entry.path().symlink_metadata().ok()?;
        if !metadata.file_type().is_file() {
            return None;
        }
        files.push(RevertFileIdentity {
            name: entry.file_name().to_str()?.to_string(),
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        });
    }
    files.sort_by(|left, right| left.name.cmp(&right.name));
    Some(RevertHashDirIdentity {
        device: dir_metadata.dev(),
        inode: dir_metadata.ino(),
        files,
    })
}

/// Freeze the exact logical and physical source generations that the next
/// bounded sender page is expected to offer. The remote reports are useful
/// only if their cursor/count shape still matches this snapshot.
fn snapshot_revert_page(
    job: &EcPartJob,
    sender: &Sender<'_>,
) -> Result<RevertPageSnapshot, String> {
    if sender.max_objects == 0 {
        return Err("EC revert sender page must have a finite object bound".to_string());
    }
    let available = sender
        .yield_local_hashes(true)
        .map_err(|error| error.to_string())?;
    let limited_by_max_objects = available.len() > sender.max_objects;
    let mut page = RevertPageSnapshot {
        limited_by_max_objects,
        ..RevertPageSnapshot::default()
    };
    for (suffix, object_hash, timestamps) in available.into_iter().take(sender.max_objects) {
        if !lower_hex(&suffix, 3) || !lower_hex(&object_hash, 32) || !object_hash.ends_with(&suffix)
        {
            return Err(format!(
                "revert part {} encountered malformed object path {suffix}/{object_hash}",
                job.partition
            ));
        }
        let hash_dir = job.path.join(&suffix).join(&object_hash);
        let device_path = sender.devices.join(&job.device);
        let df = DiskFile::from_hash_dir(
            &device_path,
            &hash_dir,
            sender.job.policy,
            sender.job.policy_index,
            sender.hash_config,
            sender.diskfile_config.clone(),
        );
        let _mutation_guard = df
            .acquire_mutation_lock(OBJECT_MUTATION_LOCK_TIMEOUT)
            .map_err(|error| {
                format!(
                    "revert part {} could not snapshot locked object {object_hash}: {error}",
                    job.partition
                )
            })?;
        let locked_timestamps = object_timestamps_from_hash_dir_strict(
            &hash_dir,
            sender.job.policy,
            sender.job.frag_index,
            Some(&[]),
        )
        .map_err(|error| {
            format!(
                "revert part {} could not inspect locked object {object_hash}: {error}",
                job.partition
            )
        })?;
        if locked_timestamps.as_ref() != Some(&timestamps) {
            return Err(format!(
                "revert part {} object {object_hash} changed while its transfer snapshot was being frozen",
                job.partition
            ));
        }
        let identity = snapshot_revert_hash_dir(&hash_dir).ok_or_else(|| {
            format!(
                "revert part {} could not snapshot object {object_hash}",
                job.partition
            )
        })?;
        page.last_offered = Some((suffix.clone(), object_hash.clone()));
        if page
            .objects
            .insert(
                object_hash.clone(),
                RevertObjectSnapshot {
                    suffix,
                    timestamps,
                    identity,
                },
            )
            .is_some()
        {
            return Err(format!(
                "revert part {} offered duplicate object hash {object_hash}",
                job.partition
            ));
        }
    }
    Ok(page)
}

fn valid_revert_report(report: &SenderReport, page: &RevertPageSnapshot) -> bool {
    report.offered_count == page.objects.len()
        && report.last_offered == page.last_offered
        && report.limited_by_max_objects == page.limited_by_max_objects
        && report
            .can_delete_objs
            .iter()
            .all(|(object_hash, timestamps)| {
                page.objects
                    .get(object_hash)
                    .is_some_and(|snapshot| &snapshot.timestamps == timestamps)
            })
}

fn intersect_revert_confirmations(
    reports: &[BTreeMap<String, ObjectTimestamps>],
) -> BTreeMap<String, ObjectTimestamps> {
    let Some((first, rest)) = reports.split_first() else {
        return BTreeMap::new();
    };
    let mut confirmed = first.clone();
    for report in rest {
        confirmed.retain(|object_hash, timestamps| report.get(object_hash) == Some(timestamps));
    }
    confirmed
}

/// Per-pass ssync-job stats.
///
/// `last_error` exists because a bare `failures` counter is undiagnosable: a
/// pass that reports `failures=2` every cycle tells an operator that
/// reconstruction is stuck but nothing about why, and the error was being
/// dropped on the floor at the push site. Keeping the most recent message
/// costs one allocation per failing pass and turns "it is broken" into a
/// reason.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EcSsyncStats {
    pub suffix_syncs: u64,
    pub reverts: u64,
    pub failures: u64,
    pub last_error: Option<String>,
}

/// `reconstructor.process_job`: run one partition job.
///
/// SYNC (`reconstructor._sync`): ssync the job's suffixes to each partner.
/// v1 scope notes — Python first narrows suffixes per partner with a
/// REPLICATE hash comparison (`_get_suffixes_to_sync`); this version ssyncs
/// the whole suffix list each pass (the missing-check keeps it cheap for
/// in-sync objects). Python also rebuilds wanted data fragments on the fly at
/// the partner's frag index (`sync_diskfile_builder`/`reconstruct_fa`); this
/// version has no rebuilder, so the sender skips data PUTs whose local
/// fragment does not match the partner's index (exactly what Python does when
/// the rebuild fails) — tombstones and meta still propagate.
///
/// REVERT (`reconstructor._revert`): ssync everything (including non-durable
/// fragments) to every proper primary; when all of them succeed, purge the
/// reverted objects locally (`delete_reverted_objs`).
#[allow(clippy::too_many_arguments)]
pub fn process_part_job(
    devices: &Path,
    hash_config: &HashPathConfig,
    cfg: &DiskFileConfig,
    policy_index: u32,
    policy: PolicyKind,
    job: &EcPartJob,
    pusher: &dyn SsyncPusher,
    hash_fetcher: &dyn SuffixHashFetcher,
    diskfile_builder: Option<&dyn crate::ssync_sender::SyncDiskfileBuilder>,
    stats: &mut EcSsyncStats,
) {
    let ssync_job = SsyncJob {
        device: job.device.clone(),
        partition: job.partition,
        policy_index,
        policy,
        frag_index: job.frag_index,
    };
    match job.job_type {
        EcJobType::Sync => {
            for primary in &job.sync_to {
                let mut candidates = Vec::with_capacity(1 + job.sync_handoffs.len());
                candidates.push(primary);
                candidates.extend(
                    job.sync_handoffs
                        .iter()
                        .filter(|node| node.backend_index == primary.backend_index),
                );
                // Python `_get_suffixes_to_sync`: a REPLICATE hash comparison
                // narrows the ssync to the out-of-sync suffixes. Only a 507
                // advances to a same-index handoff; every other failure skips
                // this primary target exactly as Python does.
                for node in candidates {
                    let suffixes = match get_suffixes_to_sync(
                        &job.path,
                        job.partition,
                        policy,
                        policy_index,
                        &cfg.cleanup,
                        job.frag_index,
                        node,
                        hash_fetcher,
                    ) {
                        Ok(suffixes) => suffixes,
                        Err(SuffixSyncError::InsufficientStorage) => continue,
                        Err(SuffixSyncError::Failed) => break,
                    };
                    if suffixes.is_empty() {
                        break;
                    }
                    let mut start_after: Option<(String, String)> = None;
                    let mut processed_objects = 0usize;
                    let mut complete = false;
                    loop {
                        let remaining = EC_SSYNC_PASS_OBJECTS.saturating_sub(processed_objects);
                        if remaining == 0 {
                            stats.failures += 1;
                            stats.last_error = Some(format!(
                                "sync part {} frag {:?} reached the bounded {}-object pass limit",
                                job.partition, job.frag_index, EC_SSYNC_PASS_OBJECTS
                            ));
                            break;
                        }
                        let page_limit = EC_SSYNC_PAGE_OBJECTS.min(remaining);
                        let sender = Sender {
                            devices,
                            hash_config,
                            diskfile_config: cfg,
                            job: &ssync_job,
                            suffixes: Some(&suffixes),
                            include_non_durable: false,
                            max_objects: page_limit,
                            start_after: start_after.clone(),
                            sync_frag_target: node.backend_index,
                            diskfile_builder,
                        };
                        let report = match pusher.push(&sender, node) {
                            Ok(report) => report,
                            Err(e) => {
                                stats.failures += 1;
                                stats.last_error = Some(format!(
                                    "sync part {} frag {:?} -> {}:{}/{}: {e}",
                                    job.partition,
                                    job.frag_index,
                                    node.replication_ip,
                                    node.replication_port,
                                    node.device
                                ));
                                break;
                            }
                        };
                        if report.offered_count > page_limit
                            || (report.offered_count > 0 && report.last_offered.is_none())
                        {
                            stats.failures += 1;
                            stats.last_error = Some(format!(
                                "sync part {} frag {:?} -> {}:{}/{} returned an invalid bounded page",
                                job.partition,
                                job.frag_index,
                                node.replication_ip,
                                node.replication_port,
                                node.device
                            ));
                            break;
                        }
                        processed_objects =
                            match processed_objects.checked_add(report.offered_count) {
                                Some(total) => total,
                                None => {
                                    stats.failures += 1;
                                    stats.last_error = Some(format!(
                                        "sync part {} object count overflow",
                                        job.partition
                                    ));
                                    break;
                                }
                            };
                        if !report.limited_by_max_objects {
                            complete = true;
                            break;
                        }
                        let Some(next_cursor) = report.last_offered else {
                            stats.failures += 1;
                            stats.last_error = Some(format!(
                                "sync part {} returned a truncated page without a cursor",
                                job.partition
                            ));
                            break;
                        };
                        if start_after
                            .as_ref()
                            .is_some_and(|cursor| &next_cursor <= cursor)
                        {
                            stats.failures += 1;
                            stats.last_error = Some(format!(
                                "sync part {} returned a non-progressing page cursor",
                                job.partition
                            ));
                            break;
                        }
                        start_after = Some(next_cursor);
                    }
                    if complete {
                        stats.suffix_syncs += suffixes.len() as u64;
                    }
                    break;
                }
            }
        }
        EcJobType::Revert => {
            // Python `_revert` takes the partition's 'replication' lock (the
            // one an incoming SSYNC receiver holds) so two nodes cannot
            // cross-revert the same partition and both delete it. On
            // PartitionLockTimeout the job is skipped — not an error.
            let Ok(_lock) = swift_core::lockutil::lock_path(
                &job.path,
                REVERT_LOCK_TIMEOUT,
                Some("replication"),
            ) else {
                return;
            };
            if job.sync_to.is_empty() {
                return;
            }

            let mut start_after: Option<(String, String)> = None;
            let mut processed_objects = 0usize;
            let mut processed_any = false;
            loop {
                let remaining = EC_SSYNC_PASS_OBJECTS.saturating_sub(processed_objects);
                if remaining == 0 {
                    stats.failures += 1;
                    stats.last_error = Some(format!(
                        "revert part {} reached the bounded {}-object pass limit",
                        job.partition, EC_SSYNC_PASS_OBJECTS
                    ));
                    return;
                }
                let page_limit = EC_SSYNC_PAGE_OBJECTS.min(remaining);
                let page_sender = Sender {
                    devices,
                    hash_config,
                    diskfile_config: cfg,
                    job: &ssync_job,
                    suffixes: Some(&job.suffixes),
                    include_non_durable: true,
                    max_objects: page_limit,
                    start_after: start_after.clone(),
                    sync_frag_target: None,
                    diskfile_builder: None,
                };
                let page = match snapshot_revert_page(job, &page_sender) {
                    Ok(page) => page,
                    Err(error) => {
                        stats.failures += 1;
                        stats.last_error = Some(error);
                        return;
                    }
                };
                if page.objects.is_empty() {
                    if processed_any {
                        stats.reverts += 1;
                    }
                    return;
                }

                let mut confirmations = Vec::with_capacity(job.sync_to.len());
                for node in &job.sync_to {
                    let sender = Sender {
                        devices,
                        hash_config,
                        diskfile_config: cfg,
                        job: &ssync_job,
                        suffixes: Some(&job.suffixes),
                        include_non_durable: true,
                        max_objects: page_limit,
                        start_after: start_after.clone(),
                        sync_frag_target: None,
                        diskfile_builder: None,
                    };
                    match pusher.push(&sender, node) {
                        Ok(report) if valid_revert_report(&report, &page) => {
                            confirmations.push(report.can_delete_objs);
                        }
                        Ok(_) => {
                            stats.failures += 1;
                            stats.last_error = Some(format!(
                                "revert part {} -> {}:{}/{} returned a stale, malformed, or truncated confirmation page",
                                job.partition,
                                node.replication_ip,
                                node.replication_port,
                                node.device
                            ));
                            return;
                        }
                        Err(e) => {
                            stats.failures += 1;
                            stats.last_error = Some(format!(
                                "revert part {} -> {}:{}/{}: {e}",
                                job.partition,
                                node.replication_ip,
                                node.replication_port,
                                node.device
                            ));
                            return;
                        }
                    }
                }

                let confirmed = intersect_revert_confirmations(&confirmations);
                let confirmed_snapshots: BTreeMap<String, RevertObjectSnapshot> = confirmed
                    .iter()
                    .filter_map(|(object_hash, timestamps)| {
                        page.objects.get(object_hash).and_then(|snapshot| {
                            (snapshot.timestamps == *timestamps)
                                .then(|| (object_hash.clone(), snapshot.clone()))
                        })
                    })
                    .collect();
                if let Err(error) = delete_reverted_objs(
                    devices,
                    hash_config,
                    cfg,
                    policy_index,
                    policy,
                    job,
                    &confirmed_snapshots,
                ) {
                    stats.failures += 1;
                    stats.last_error = Some(error);
                    return;
                }
                if confirmed_snapshots.len() != page.objects.len() {
                    stats.failures += 1;
                    stats.last_error = Some(format!(
                        "revert part {} did not receive identical confirmation from every target for all {} offered objects",
                        job.partition,
                        page.objects.len()
                    ));
                    return;
                }

                processed_any = true;
                processed_objects += page.objects.len();
                if !page.limited_by_max_objects {
                    stats.reverts += 1;
                    return;
                }
                start_after = page.last_offered;
            }
        }
    }
}

/// `reconstructor.delete_reverted_objs`: purge the frag-index files of every
/// object that is now in sync with the primary, then remove any emptied
/// suffix dirs.
#[allow(clippy::too_many_arguments)]
fn delete_reverted_objs(
    devices: &Path,
    hash_config: &HashPathConfig,
    cfg: &DiskFileConfig,
    policy_index: u32,
    policy: PolicyKind,
    job: &EcPartJob,
    objects: &BTreeMap<String, RevertObjectSnapshot>,
) -> Result<(), String> {
    let device_path = devices.join(&job.device);
    let mut suffixes_to_delete: BTreeSet<String> = BTreeSet::new();
    for (object_hash, snapshot) in objects {
        if !lower_hex(object_hash, 32) || !object_hash.ends_with(&snapshot.suffix) {
            return Err(format!(
                "revert part {} refused malformed object hash {object_hash}",
                job.partition
            ));
        }
        let suffix = snapshot.suffix.clone();
        let hash_dir = job.path.join(&suffix).join(object_hash);
        let df = DiskFile::from_hash_dir(
            &device_path,
            &hash_dir,
            policy,
            policy_index,
            hash_config,
            cfg.clone(),
        );
        let _mutation_guard = df
            .acquire_mutation_lock(OBJECT_MUTATION_LOCK_TIMEOUT)
            .map_err(|error| {
                format!(
                    "revert part {} could not lock object {object_hash}: {error}",
                    job.partition
                )
            })?;
        // Re-read only after acquiring the object stripe. The pre-transfer
        // logical state, the exact all-target report, and the physical inode
        // snapshot must all still describe the same source generation.
        let current_timestamps =
            object_timestamps_from_hash_dir_strict(&hash_dir, policy, job.frag_index, Some(&[]))
                .map_err(|error| {
                    format!(
                        "revert part {} could not inspect object {object_hash}: {error}",
                        job.partition
                    )
                })?;
        if current_timestamps.as_ref() != Some(&snapshot.timestamps) {
            return Err(format!(
                "revert part {} source generation changed for object {object_hash}",
                job.partition
            ));
        }
        if snapshot_revert_hash_dir(&hash_dir).as_ref() != Some(&snapshot.identity) {
            return Err(format!(
                "revert part {} source files changed for object {object_hash}",
                job.partition
            ));
        }
        let filenames: Vec<String> = std::fs::read_dir(&hash_dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        // legacy durable data files look like modern nondurable data files;
        // override nondurable_purge_delay when we know the file is durable
        let nondurable_purge_delay = if snapshot.timestamps.durable == Some(true) {
            0.0
        } else {
            cfg.cleanup.commit_window
        };
        let data_files: Vec<&String> = filenames.iter().filter(|f| f.ends_with(".data")).collect();
        let purgable: Vec<&&String> = data_files
            .iter()
            .filter(|f| f.starts_with(&snapshot.timestamps.ts_data.internal()))
            .collect();
        let meta_timestamp = if job.primary_frag_index.is_none()
            && purgable.len() == data_files.len()
            && data_files.len() <= 1
        {
            // pure handoff node purging its last .data file: any reverted
            // meta file can go too
            snapshot.timestamps.ts_meta
        } else {
            None
        };
        df.purge(
            &snapshot.timestamps.ts_data,
            job.frag_index,
            nondurable_purge_delay,
            meta_timestamp.as_ref(),
        )
        .map_err(|error| {
            format!(
                "revert part {} could not purge object {object_hash}: {error}",
                job.partition
            )
        })?;
        suffixes_to_delete.insert(suffix);
    }
    for suffix in suffixes_to_delete {
        // Python remove_directory: rmdir, ignoring ENOENT/ENOTEMPTY
        let _ = std::fs::remove_dir(job.path.join(suffix));
    }
    Ok(())
}

#[cfg(test)]
mod suffix_sync_tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TMP: AtomicU64 = AtomicU64::new(0);

    fn tmp_root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "swift-recon-suffix-{tag}-{}-{}",
            std::process::id(),
            NEXT_TMP.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        root
    }

    fn read_test_http_response(
        response: Vec<u8>,
        body_limit: usize,
        idle_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<(InternalHttpHead, Vec<u8>), String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.write_all(&response);
        });
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        let deadline = Instant::now().checked_add(request_timeout).unwrap();
        let mut reader = DeadlineSocketReader::new(&mut stream, idle_timeout, deadline);
        let head = read_internal_http_head(&mut reader)?;
        let body = read_internal_http_body(&mut reader, &head.headers, body_limit)?;
        server.join().unwrap();
        Ok((head, body))
    }

    #[test]
    fn bounded_http_reader_enforces_framing_and_body_caps() {
        let valid = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_vec();
        let (head, body) =
            read_test_http_response(valid, 3, Duration::from_secs(1), Duration::from_secs(2))
                .unwrap();
        assert_eq!(head.status, 200);
        assert_eq!(body, b"abc");

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Proof: yes\r\n\r\n".to_vec();
        let (_, body) =
            read_test_http_response(chunked, 3, Duration::from_secs(1), Duration::from_secs(2))
                .unwrap();
        assert_eq!(body, b"abc");

        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc"
                .to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\n\r\nabc".to_vec(),
        ] {
            assert!(
                read_test_http_response(
                    response,
                    3,
                    Duration::from_millis(100),
                    Duration::from_millis(250),
                )
                .is_err(),
                "malformed or truncated framing must fail"
            );
        }

        let oversized = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd".to_vec();
        assert!(read_test_http_response(
            oversized,
            3,
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .is_err());
    }

    #[test]
    fn bounded_http_reader_absolute_deadline_stops_slow_drip() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n");
            for byte in b"12345678" {
                std::thread::sleep(Duration::from_millis(35));
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
            }
        });
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        let started = Instant::now();
        let deadline = started + Duration::from_millis(120);
        let mut reader = DeadlineSocketReader::new(&mut stream, Duration::from_secs(1), deadline);
        let head = read_internal_http_head(&mut reader).unwrap();
        assert!(read_internal_http_body(&mut reader, &head.headers, 8).is_err());
        assert!(started.elapsed() < Duration::from_millis(400));
        server.join().unwrap();
    }

    #[test]
    fn suffix_hash_fetcher_is_bounded_and_does_not_drain_507() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = u32::from(listener.local_addr().unwrap().port());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.write_all(
                b"HTTP/1.1 507 Insufficient Storage\r\nContent-Length: 99999999\r\n\r\n",
            );
            std::thread::sleep(Duration::from_millis(300));
        });
        let fetcher = HttpSuffixHashFetcher {
            conn_timeout: Duration::from_secs(1),
            node_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(1),
            max_response_bytes: 32,
        };
        let started = Instant::now();
        assert_eq!(
            fetcher.fetch_result(&node(port, 0), 1, 0),
            Err(SuffixSyncError::InsufficientStorage)
        );
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "507 must be classified from its bounded head without draining a hostile body"
        );
        server.join().unwrap();

        let value = hashes_value(&[("abc", &[(None, "hash")])]);
        let body = pickle::dumps(&value).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = u32::from(listener.local_addr().unwrap().port());
        let oversized = body.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                oversized.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&oversized);
        });
        let fetcher = HttpSuffixHashFetcher {
            max_response_bytes: body.len().saturating_sub(1),
            ..Default::default()
        };
        assert_eq!(
            fetcher.fetch_result(&node(port, 0), 1, 0),
            Err(SuffixSyncError::Failed)
        );
        server.join().unwrap();
    }

    /// One suffix's `{None | Int(fi): hash}` entries.
    type FiHashes<'a> = &'a [(Option<i64>, &'a str)];

    /// `{suffix: {None | Int(fi): hash}}` as the pickle Value both
    /// `get_partition_hashes` and a REPLICATE response produce.
    fn hashes_value(suffixes: &[(&str, FiHashes<'_>)]) -> Value {
        Value::Dict(
            suffixes
                .iter()
                .map(|(suffix, fi_hash)| {
                    (
                        Value::Str(suffix.to_string()),
                        Value::Dict(
                            fi_hash
                                .iter()
                                .map(|(fi, hex)| {
                                    let key = match fi {
                                        Some(i) => Value::Int(*i),
                                        None => Value::None,
                                    };
                                    (key, Value::Str(hex.to_string()))
                                })
                                .collect(),
                        ),
                    )
                })
                .collect(),
        )
    }

    #[test]
    fn tombstone_sample_changes_subset_without_duplicates() {
        let first = sample_indices(6, 3, 7);
        assert_eq!(
            first,
            sample_indices(6, 3, 7),
            "seeded sample must be reproducible"
        );
        assert_eq!(first.len(), 3);
        assert_eq!(
            first
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3,
            "sample is without replacement"
        );

        let subsets: std::collections::BTreeSet<Vec<usize>> = (1..=32)
            .map(|seed| {
                let mut subset = sample_indices(6, 3, seed);
                subset.sort_unstable();
                subset
            })
            .collect();
        assert!(
            subsets.len() > 1,
            "reconstructor retries must not keep choosing the same primaries"
        );
        let seen: std::collections::BTreeSet<usize> = subsets
            .iter()
            .flat_map(|subset| subset.iter().copied())
            .collect();
        assert_eq!(
            seen,
            (0..6).collect(),
            "retry samples must reach every primary"
        );

        let mut all = sample_indices(4, 4, 11);
        all.sort_unstable();
        assert_eq!(all, [0, 1, 2, 3]);
    }

    // ---- get_suffix_delta: the Python test table -------------------------

    #[test]
    fn test_get_suffix_delta_in_sync() {
        let local = hashes_value(&[("123", &[(None, "abc"), (Some(0), "def")])]);
        let remote = hashes_value(&[("123", &[(None, "abc"), (Some(0), "def")])]);
        assert_eq!(
            get_suffix_delta(&local, Some(0), &remote, Some(0)),
            Vec::<String>::new()
        );
    }

    #[test]
    fn test_get_suffix_delta_remote_missing_suffix() {
        let local = hashes_value(&[("123", &[(None, "abc"), (Some(0), "def")])]);
        let remote = hashes_value(&[("456", &[(None, "ghi"), (Some(0), "jkl")])]);
        assert_eq!(get_suffix_delta(&local, Some(0), &remote, Some(0)), ["123"]);
        // remote-only suffixes are never the local node's to push
        let empty = hashes_value(&[]);
        assert_eq!(
            get_suffix_delta(&empty, Some(0), &remote, Some(0)),
            Vec::<String>::new()
        );
    }

    #[test]
    fn test_get_suffix_delta_differing_data_hash() {
        let local = hashes_value(&[("123", &[(None, "abc"), (Some(0), "def")])]);
        let remote = hashes_value(&[("123", &[(None, "abc"), (Some(0), "XYZ")])]);
        assert_eq!(get_suffix_delta(&local, Some(0), &remote, Some(0)), ["123"]);
        // ...and the frag entries are compared at each side's own index
        let remote = hashes_value(&[("123", &[(None, "abc"), (Some(2), "def")])]);
        assert_eq!(
            get_suffix_delta(&local, Some(0), &remote, Some(2)),
            Vec::<String>::new()
        );
        assert_eq!(get_suffix_delta(&local, Some(0), &remote, Some(0)), ["123"]);
    }

    #[test]
    fn test_get_suffix_delta_none_key_tombstones() {
        // mismatched None key (missing durable / tombstone difference)
        let local = hashes_value(&[("123", &[(None, "abc"), (Some(0), "def")])]);
        let remote = hashes_value(&[("123", &[(None, "ghi"), (Some(0), "def")])]);
        assert_eq!(get_suffix_delta(&local, Some(0), &remote, Some(0)), ["123"]);
        // tombstone-only suffixes (no frag entries) still compare via None
        let local = hashes_value(&[("777", &[(None, "ts-hash")])]);
        let remote = hashes_value(&[("777", &[(None, "ts-hash")])]);
        assert_eq!(
            get_suffix_delta(&local, Some(1), &remote, Some(2)),
            Vec::<String>::new()
        );
        let remote = hashes_value(&[("777", &[])]);
        assert_eq!(get_suffix_delta(&local, Some(1), &remote, Some(2)), ["777"]);
        // absent on both sides compares equal (Python dict.get -> None twice)
        let local = hashes_value(&[("123", &[(Some(1), "def")])]);
        let remote = hashes_value(&[("123", &[(Some(2), "def")])]);
        assert_eq!(
            get_suffix_delta(&local, Some(1), &remote, Some(2)),
            Vec::<String>::new()
        );
        // bogus local index: local has no entry there, remote does
        let local = hashes_value(&[("123", &[(None, "abc"), (Some(99), "def")])]);
        let remote = hashes_value(&[("123", &[(None, "abc"), (Some(0), "def")])]);
        assert_eq!(get_suffix_delta(&local, Some(0), &remote, Some(0)), ["123"]);
    }

    #[test]
    fn test_revert_requires_exact_all_target_intersection() {
        let devices = tmp_root("revert-intersection");
        let part_path = devices
            .join("sda1")
            .join(swift_diskfile::get_data_dir(POLICY_INDEX))
            .join("3");
        let timestamp = "1751500123.00000";
        let suffix = "abc";
        let object_hash = format!("{:0>29}{suffix}", 2);
        put_frag_hash(&part_path, suffix, &object_hash, timestamp, 2);
        let job = revert_job(&part_path, suffix, Some(2), 2);
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let pusher = ScriptedPusher::new(vec![ReportBehavior::Complete, ReportBehavior::OmitFirst]);
        let fetcher = FakeFetcher {
            by_port: HashMap::new(),
        };
        let mut stats = EcSsyncStats::default();
        process_part_job(
            &devices,
            &hc,
            &cfg,
            POLICY_INDEX,
            ec_kind(),
            &job,
            &pusher,
            &fetcher,
            None,
            &mut stats,
        );
        assert_eq!(stats.reverts, 0, "{stats:?}");
        assert_eq!(stats.failures, 1, "{stats:?}");
        assert!(
            part_path.join(suffix).join(object_hash).exists(),
            "one target's omission must retain the source generation"
        );
        let _ = std::fs::remove_dir_all(&devices);
    }

    #[test]
    fn test_revert_rejects_timestamp_or_page_shape_mismatch() {
        for (tag, behavior) in [
            ("timestamp", ReportBehavior::WrongMetaTimestamp),
            ("shape", ReportBehavior::WrongPageShape),
        ] {
            let devices = tmp_root(&format!("revert-bad-report-{tag}"));
            let part_path = devices
                .join("sda1")
                .join(swift_diskfile::get_data_dir(POLICY_INDEX))
                .join("3");
            let timestamp = "1751500123.00000";
            let suffix = "abc";
            let object_hash = format!("{:0>29}{suffix}", 2);
            put_frag_hash(&part_path, suffix, &object_hash, timestamp, 2);
            let job = revert_job(&part_path, suffix, Some(2), 2);
            let hc = HashPathConfig::new("", "changeme").unwrap();
            let cfg = DiskFileConfig::default();
            let pusher = ScriptedPusher::new(vec![ReportBehavior::Complete, behavior]);
            let fetcher = FakeFetcher {
                by_port: HashMap::new(),
            };
            let mut stats = EcSsyncStats::default();
            process_part_job(
                &devices,
                &hc,
                &cfg,
                POLICY_INDEX,
                ec_kind(),
                &job,
                &pusher,
                &fetcher,
                None,
                &mut stats,
            );
            assert_eq!(stats.reverts, 0, "{tag}: {stats:?}");
            assert_eq!(stats.failures, 1, "{tag}: {stats:?}");
            assert!(
                part_path.join(suffix).join(object_hash).exists(),
                "{tag}: malformed confirmation must retain source"
            );
            let _ = std::fs::remove_dir_all(&devices);
        }
    }

    #[test]
    fn test_revert_retains_generation_mutated_after_reports() {
        let devices = tmp_root("revert-report-mutation");
        let part_path = devices
            .join("sda1")
            .join(swift_diskfile::get_data_dir(POLICY_INDEX))
            .join("3");
        let suffix = "abc";
        let object_hash = format!("{:0>29}{suffix}", 2);
        let hash_dir = part_path.join(suffix).join(&object_hash);
        put_frag_hash(&part_path, suffix, &object_hash, "1751500123.00000", 2);
        let job = revert_job(&part_path, suffix, Some(2), 2);
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let pusher = ScriptedPusher::new(vec![
            ReportBehavior::Complete,
            ReportBehavior::MutateAfter {
                hash_dir: hash_dir.clone(),
                timestamp: "1751500124.00000".to_string(),
                frag_index: 2,
            },
        ]);
        let fetcher = FakeFetcher {
            by_port: HashMap::new(),
        };
        let mut stats = EcSsyncStats::default();
        process_part_job(
            &devices,
            &hc,
            &cfg,
            POLICY_INDEX,
            ec_kind(),
            &job,
            &pusher,
            &fetcher,
            None,
            &mut stats,
        );
        assert_eq!(stats.reverts, 0, "{stats:?}");
        assert_eq!(stats.failures, 1, "{stats:?}");
        assert!(
            hash_dir.join("1751500124.00000#2#d.data").exists(),
            "the post-report foreground generation must survive"
        );
        let _ = std::fs::remove_dir_all(&devices);
    }

    #[test]
    fn test_tombstone_revert_requires_every_target() {
        for (tag, behaviors, should_delete) in [
            (
                "complete",
                vec![ReportBehavior::Complete, ReportBehavior::Complete],
                true,
            ),
            (
                "omitted",
                vec![ReportBehavior::Complete, ReportBehavior::OmitFirst],
                false,
            ),
        ] {
            let devices = tmp_root(&format!("revert-tombstone-{tag}"));
            let part_path = devices
                .join("sda1")
                .join(swift_diskfile::get_data_dir(POLICY_INDEX))
                .join("3");
            let suffix = "abc";
            let object_hash = format!("{:0>29}{suffix}", 9);
            let hash_dir = part_path.join(suffix).join(&object_hash);
            let tombstone = hash_dir.join("1751500123.00000.ts");
            std::fs::create_dir_all(&hash_dir).unwrap();
            std::fs::write(&tombstone, b"tombstone").unwrap();
            let job = revert_job(&part_path, suffix, None, 2);
            let hc = HashPathConfig::new("", "changeme").unwrap();
            let cfg = DiskFileConfig::default();
            let pusher = ScriptedPusher::new(behaviors);
            let fetcher = FakeFetcher {
                by_port: HashMap::new(),
            };
            let mut stats = EcSsyncStats::default();
            process_part_job(
                &devices,
                &hc,
                &cfg,
                POLICY_INDEX,
                ec_kind(),
                &job,
                &pusher,
                &fetcher,
                None,
                &mut stats,
            );
            assert_eq!(!tombstone.exists(), should_delete, "{tag}: {stats:?}");
            assert_eq!(stats.reverts, u64::from(should_delete), "{tag}: {stats:?}");
            let _ = std::fs::remove_dir_all(&devices);
        }
    }

    #[test]
    fn test_revert_page_is_bounded_and_skips_other_fragment_indexes() {
        let devices = tmp_root("revert-page");
        let part_path = devices
            .join("sda1")
            .join(swift_diskfile::get_data_dir(POLICY_INDEX))
            .join("3");
        let suffix = "abc";
        let first_hash = format!("{:0>29}{suffix}", 4);
        let second_hash = format!("{:0>29}{suffix}", 5);
        let other_frag_hash = format!("{:0>29}{suffix}", 1);
        let another_frag_hash = format!("{:0>29}{suffix}", 2);
        put_frag_hash(&part_path, suffix, &first_hash, "1751500123.00000", 2);
        put_frag_hash(&part_path, suffix, &second_hash, "1751500123.00000", 2);
        put_frag_hash(&part_path, suffix, &other_frag_hash, "1751500123.00000", 3);
        put_frag_hash(
            &part_path,
            suffix,
            &another_frag_hash,
            "1751500123.00000",
            3,
        );
        let job = revert_job(&part_path, suffix, Some(2), 1);
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let ssync_job = SsyncJob {
            device: job.device.clone(),
            partition: job.partition,
            policy_index: POLICY_INDEX,
            policy: ec_kind(),
            frag_index: job.frag_index,
        };
        let first_sender = Sender {
            devices: &devices,
            hash_config: &hc,
            diskfile_config: &cfg,
            job: &ssync_job,
            suffixes: Some(&job.suffixes),
            include_non_durable: true,
            max_objects: 1,
            start_after: None,
            sync_frag_target: None,
            diskfile_builder: None,
        };
        let first_page = snapshot_revert_page(&job, &first_sender).unwrap();
        assert_eq!(first_page.objects.keys().collect::<Vec<_>>(), [&first_hash]);
        assert!(first_page.limited_by_max_objects);
        let second_sender = Sender {
            start_after: first_page.last_offered.clone(),
            ..first_sender
        };
        let second_page = snapshot_revert_page(&job, &second_sender).unwrap();
        assert_eq!(
            second_page.objects.keys().collect::<Vec<_>>(),
            [&second_hash]
        );
        assert!(!second_page.limited_by_max_objects);
        let _ = std::fs::remove_dir_all(&devices);
    }

    // ---- process_part_job SYNC with a fake REPLICATE responder -----------

    struct FakeFetcher {
        by_port: HashMap<u32, Value>,
    }

    impl SuffixHashFetcher for FakeFetcher {
        fn fetch_hashes(
            &self,
            node: &SsyncNode,
            _partition: u64,
            _policy_index: u32,
        ) -> Option<Value> {
            self.by_port.get(&node.replication_port).cloned()
        }
    }

    struct HandoffFetcher {
        handoff_port: u32,
        handoff_hashes: Value,
    }

    impl SuffixHashFetcher for HandoffFetcher {
        fn fetch_hashes(
            &self,
            _node: &SsyncNode,
            _partition: u64,
            _policy_index: u32,
        ) -> Option<Value> {
            None
        }

        fn fetch_hashes_with_status(
            &self,
            node: &SsyncNode,
            _partition: u64,
            _policy_index: u32,
        ) -> Result<Value, SuffixSyncError> {
            if node.replication_port == self.handoff_port {
                Ok(self.handoff_hashes.clone())
            } else {
                Err(SuffixSyncError::InsufficientStorage)
            }
        }
    }

    #[derive(Default)]
    struct RecordingPusher {
        pushes: RefCell<Vec<(u32, Vec<String>)>>,
    }

    fn complete_sender_report(sender: &Sender<'_>) -> Result<SenderReport, SsyncSenderError> {
        let available = sender.yield_local_hashes(sender.include_non_durable)?;
        let limit = if sender.max_objects == 0 {
            available.len()
        } else {
            sender.max_objects.min(available.len())
        };
        let mut report = SenderReport {
            limited_by_max_objects: sender.max_objects > 0 && available.len() > sender.max_objects,
            ..SenderReport::default()
        };
        for (suffix, object_hash, timestamps) in available.into_iter().take(limit) {
            report.offered_count += 1;
            report.last_offered = Some((suffix, object_hash.clone()));
            report.can_delete_objs.insert(object_hash, timestamps);
        }
        Ok(report)
    }

    impl SsyncPusher for RecordingPusher {
        fn push(
            &self,
            sender: &Sender<'_>,
            node: &SsyncNode,
        ) -> Result<SenderReport, SsyncSenderError> {
            self.pushes.borrow_mut().push((
                node.replication_port,
                sender.suffixes.map(<[String]>::to_vec).unwrap_or_default(),
            ));
            complete_sender_report(sender)
        }
    }

    #[derive(Clone)]
    enum ReportBehavior {
        Complete,
        OmitFirst,
        WrongMetaTimestamp,
        WrongPageShape,
        MutateAfter {
            hash_dir: PathBuf,
            timestamp: String,
            frag_index: i64,
        },
    }

    struct ScriptedPusher {
        behaviors: RefCell<Vec<ReportBehavior>>,
    }

    impl ScriptedPusher {
        fn new(behaviors: Vec<ReportBehavior>) -> Self {
            Self {
                behaviors: RefCell::new(behaviors),
            }
        }
    }

    impl SsyncPusher for ScriptedPusher {
        fn push(
            &self,
            sender: &Sender<'_>,
            _node: &SsyncNode,
        ) -> Result<SenderReport, SsyncSenderError> {
            let behavior = self.behaviors.borrow_mut().remove(0);
            let mut report = complete_sender_report(sender)?;
            match behavior {
                ReportBehavior::Complete => {}
                ReportBehavior::OmitFirst => {
                    if let Some(first) = report.can_delete_objs.keys().next().cloned() {
                        report.can_delete_objs.remove(&first);
                    }
                }
                ReportBehavior::WrongMetaTimestamp => {
                    if let Some(timestamps) = report.can_delete_objs.values_mut().next() {
                        timestamps.ts_meta = Some("9999999999.00000".parse().unwrap());
                    }
                }
                ReportBehavior::WrongPageShape => {
                    report.offered_count = report.offered_count.saturating_add(1);
                }
                ReportBehavior::MutateAfter {
                    hash_dir,
                    timestamp,
                    frag_index,
                } => {
                    std::fs::write(
                        hash_dir.join(format!("{timestamp}#{frag_index}#d.data")),
                        b"new-generation",
                    )
                    .unwrap();
                }
            }
            Ok(report)
        }
    }

    const POLICY_INDEX: u32 = 0;

    fn ec_kind() -> PolicyKind {
        PolicyKind::Ec {
            n_unique_fragments: Some(4),
        }
    }

    fn now_ts() -> String {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        format!("{secs:.5}")
    }

    /// Lay a durable EC fragment file down under `part_path/<suffix>`.
    fn put_frag(part_path: &Path, suffix: &str, ts: &str, frag_index: i64) {
        let object_hash = format!("{:0>29}{suffix}", frag_index);
        put_frag_hash(part_path, suffix, &object_hash, ts, frag_index);
    }

    fn put_frag_hash(part_path: &Path, suffix: &str, object_hash: &str, ts: &str, frag_index: i64) {
        let hash_dir = part_path.join(suffix).join(object_hash);
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join(format!("{ts}#{frag_index}#d.data")), b"").unwrap();
    }

    fn node(port: u32, backend_index: i64) -> SsyncNode {
        SsyncNode {
            replication_ip: "127.0.0.1".to_string(),
            replication_port: port,
            device: "sda1".to_string(),
            backend_index: Some(backend_index),
        }
    }

    fn revert_job(
        part_path: &Path,
        suffix: &str,
        frag_index: Option<i64>,
        target_count: usize,
    ) -> EcPartJob {
        EcPartJob {
            job_type: EcJobType::Revert,
            frag_index,
            suffixes: vec![suffix.to_string()],
            sync_to: (0..target_count)
                .map(|index| node(11_000 + index as u32, index as i64))
                .collect(),
            sync_handoffs: Vec::new(),
            partition: 3,
            path: part_path.to_path_buf(),
            device: "sda1".to_string(),
            primary_frag_index: None,
        }
    }

    fn sync_job(part_path: &Path, suffixes: &[&str], sync_to: Vec<SsyncNode>) -> EcPartJob {
        EcPartJob {
            job_type: EcJobType::Sync,
            frag_index: Some(1),
            suffixes: suffixes.iter().map(|s| s.to_string()).collect(),
            sync_to,
            sync_handoffs: Vec::new(),
            partition: 3,
            path: part_path.to_path_buf(),
            device: "sda1".to_string(),
            primary_frag_index: Some(1),
        }
    }

    /// Re-key every `Int(1)` frag entry to the partner's backend index and
    /// optionally corrupt one suffix's data hash.
    fn rekeyed_remote(local: &Value, remote_index: i64, corrupt_suffix: Option<&str>) -> Value {
        let Value::Dict(suffixes) = local else {
            panic!("dict")
        };
        Value::Dict(
            suffixes
                .iter()
                .map(|(suffix, sub)| {
                    let Value::Dict(sub) = sub else {
                        panic!("sub dict")
                    };
                    let corrupt = matches!(
                        (suffix, corrupt_suffix),
                        (Value::Str(s), Some(c)) if s == c
                    );
                    (
                        suffix.clone(),
                        Value::Dict(
                            sub.iter()
                                .map(|(fi, hex)| match fi {
                                    Value::Int(_) => (
                                        Value::Int(remote_index),
                                        if corrupt {
                                            Value::Str("0".repeat(32))
                                        } else {
                                            hex.clone()
                                        },
                                    ),
                                    other => (other.clone(), hex.clone()),
                                })
                                .collect(),
                        ),
                    )
                })
                .collect(),
        )
    }

    #[test]
    fn test_sync_job_ssyncs_only_the_delta_and_skips_failed_replicate() {
        let devices = tmp_root("sync");
        let part_path = devices
            .join("sda1")
            .join(swift_diskfile::get_data_dir(POLICY_INDEX))
            .join("3");
        let ts = now_ts();
        put_frag(&part_path, "abc", &ts, 1);
        put_frag(&part_path, "def", &ts, 1);

        let cleanup = CleanupConfig::default();
        let (_hashed, local) =
            get_partition_hashes(&part_path, ec_kind(), &[], true, &cleanup).unwrap();
        // Partner on port 1111 (backend index 2): "abc" in sync, "def" stale.
        // Partner on port 2222: REPLICATE fails entirely.
        let remote = rekeyed_remote(&local.to_value(), 2, Some("def"));
        let fetcher = FakeFetcher {
            by_port: HashMap::from([(1111, remote)]),
        };
        let pusher = RecordingPusher::default();
        let job = sync_job(
            &part_path,
            &["abc", "def"],
            vec![node(1111, 2), node(2222, 2)],
        );

        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let mut stats = EcSsyncStats::default();
        process_part_job(
            &devices,
            &hc,
            &cfg,
            POLICY_INDEX,
            ec_kind(),
            &job,
            &pusher,
            &fetcher,
            None,
            &mut stats,
        );

        // Only the out-of-sync suffix went to the reachable partner; the
        // REPLICATE failure skipped the other node without a fallback sync.
        assert_eq!(
            *pusher.pushes.borrow(),
            vec![(1111, vec!["def".to_string()])]
        );
        assert_eq!(stats.suffix_syncs, 1, "{stats:?}");
        assert_eq!(stats.failures, 0, "REPLICATE failure is a skip: {stats:?}");
        let _ = std::fs::remove_dir_all(&devices);
    }

    #[test]
    fn test_sync_job_retries_matching_handoff_only_after_507() {
        let devices = tmp_root("sync-507-handoff");
        let part_path = devices
            .join("sda1")
            .join(swift_diskfile::get_data_dir(POLICY_INDEX))
            .join("3");
        let ts = now_ts();
        put_frag(&part_path, "abc", &ts, 1);
        let cleanup = CleanupConfig::default();
        get_partition_hashes(&part_path, ec_kind(), &[], true, &cleanup).unwrap();

        let fetcher = HandoffFetcher {
            handoff_port: 2222,
            handoff_hashes: Value::Dict(Vec::new()),
        };
        let pusher = RecordingPusher::default();
        let mut job = sync_job(&part_path, &["abc"], vec![node(1111, 2)]);
        job.sync_handoffs = vec![node(2222, 2), node(3333, 3)];

        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let mut stats = EcSsyncStats::default();
        process_part_job(
            &devices,
            &hc,
            &cfg,
            POLICY_INDEX,
            ec_kind(),
            &job,
            &pusher,
            &fetcher,
            None,
            &mut stats,
        );

        assert_eq!(
            *pusher.pushes.borrow(),
            vec![(2222, vec!["abc".to_string()])],
            "the 507 primary must fall back only to a handoff for index 2"
        );
        assert_eq!(stats.suffix_syncs, 1, "{stats:?}");
        assert_eq!(stats.failures, 0, "{stats:?}");
        let _ = std::fs::remove_dir_all(&devices);
    }

    #[test]
    fn test_sync_job_fully_in_sync_pushes_nothing() {
        let devices = tmp_root("insync");
        let part_path = devices
            .join("sda1")
            .join(swift_diskfile::get_data_dir(POLICY_INDEX))
            .join("3");
        let ts = now_ts();
        put_frag(&part_path, "abc", &ts, 1);

        let cleanup = CleanupConfig::default();
        let (_hashed, local) =
            get_partition_hashes(&part_path, ec_kind(), &[], true, &cleanup).unwrap();
        let fetcher = FakeFetcher {
            by_port: HashMap::from([(1111, rekeyed_remote(&local.to_value(), 2, None))]),
        };
        let pusher = RecordingPusher::default();
        let job = sync_job(&part_path, &["abc"], vec![node(1111, 2)]);

        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let mut stats = EcSsyncStats::default();
        process_part_job(
            &devices,
            &hc,
            &cfg,
            POLICY_INDEX,
            ec_kind(),
            &job,
            &pusher,
            &fetcher,
            None,
            &mut stats,
        );
        assert!(pusher.pushes.borrow().is_empty());
        assert_eq!(stats, EcSsyncStats::default());
        let _ = std::fs::remove_dir_all(&devices);
    }

    // ---- a fragment that vanished behind the hash cache's back -----------

    /// One primary of a partition, all on the same device name and port —
    /// the layout every real node has.
    fn part_dev(id: u64) -> RingDevice {
        RingDevice {
            id,
            region: 1,
            zone: id + 1,
            ip: format!("10.0.0.{}", id + 1),
            port: 6200,
            replication_ip: None,
            replication_port: None,
            device: "sda1".to_string(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        }
    }

    fn sorted(mut suffixes: Vec<String>) -> Vec<String> {
        suffixes.sort();
        suffixes
    }

    #[test]
    fn test_sync_job_stops_advertising_a_fragment_that_vanished() {
        let devices = tmp_root("vanished");
        let part_path = devices
            .join("sda1")
            .join(swift_diskfile::get_data_dir(POLICY_INDEX))
            .join("3");
        let ts = now_ts();
        put_frag(&part_path, "abc", &ts, 1);
        put_frag(&part_path, "def", &ts, 1);
        let cleanup = CleanupConfig::default();
        // prime the cache while both fragments are on disk
        let (_hashed, primed) =
            get_partition_hashes(&part_path, ec_kind(), &[], true, &cleanup).unwrap();
        assert_eq!(sorted(suffixes_claiming_frag(&primed, 1)), ["abc", "def"]);

        // lose one the way a disk loses it: the file goes and nothing tells
        // the hash cache
        let hash_dir = part_path.join("abc").join(format!("{:0>29}abc", 1));
        std::fs::remove_file(hash_dir.join(format!("{ts}#1#d.data"))).unwrap();

        let devs: Vec<RingDevice> = (0..3).map(part_dev).collect();
        let part_nodes: Vec<PartNode<'_>> = devs
            .iter()
            .enumerate()
            .map(|(index, dev)| PartNode { index, dev })
            .collect();
        let jobs = build_part_jobs(
            &part_path,
            3,
            "sda1",
            ec_kind(),
            &cleanup,
            &part_nodes,
            &[],
            2,
            1, // this node is the primary at index 1
            Some(EcScheme {
                ndata: 2,
                nparity: 1,
                segment_size: 1 << 20,
            }),
        );
        assert_eq!(jobs.len(), 1, "{jobs:?}");
        assert_eq!(jobs[0].job_type, EcJobType::Sync);
        assert_eq!(jobs[0].frag_index, Some(1));
        assert_eq!(
            jobs[0].suffixes,
            ["def"],
            "an empty suffix is not ours to offer"
        );

        // the point of the exercise: what a partner now reads over REPLICATE
        // no longer claims a fragment at our index for the emptied suffix, so
        // the partner can see the hole and push a rebuild
        let (_hashed, published) =
            get_partition_hashes(&part_path, ec_kind(), &[], false, &cleanup).unwrap();
        assert_eq!(suffixes_claiming_frag(&published, 1), ["def"]);
        let _ = std::fs::remove_dir_all(&devices);
    }

    #[test]
    fn test_partner_missing_its_own_fragment_is_flagged_for_sync() {
        let local = hashes_value(&[("abc", &[(None, "durable"), (Some(1), "tshash")])]);
        // the partner rehashed after losing its fragment: the suffix survives
        // (its object dir is still there) but claims nothing
        let victim = hashes_value(&[("abc", &[])]);
        assert_eq!(get_suffix_delta(&local, Some(1), &victim, Some(2)), ["abc"]);
        // and this is why the victim has to publish the truth: a stale entry
        // at ITS index reads exactly like being in sync, because an EC suffix
        // hash covers timestamps only and both sides hash the same timestamp
        // under their own index
        let stale = hashes_value(&[("abc", &[(None, "durable"), (Some(2), "tshash")])]);
        assert_eq!(
            get_suffix_delta(&local, Some(1), &stale, Some(2)),
            Vec::<String>::new()
        );
    }

    #[test]
    fn test_sync_job_pushes_to_a_partner_that_lost_its_fragment() {
        let devices = tmp_root("push-victim");
        let part_path = devices
            .join("sda1")
            .join(swift_diskfile::get_data_dir(POLICY_INDEX))
            .join("3");
        let ts = now_ts();
        put_frag(&part_path, "abc", &ts, 1);
        let cleanup = CleanupConfig::default();
        get_partition_hashes(&part_path, ec_kind(), &[], true, &cleanup).unwrap();

        let fetcher = FakeFetcher {
            by_port: HashMap::from([(1111, hashes_value(&[("abc", &[])]))]),
        };
        let pusher = RecordingPusher::default();
        let job = sync_job(&part_path, &["abc"], vec![node(1111, 2)]);
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let mut stats = EcSsyncStats::default();
        process_part_job(
            &devices,
            &hc,
            &cfg,
            POLICY_INDEX,
            ec_kind(),
            &job,
            &pusher,
            &fetcher,
            None,
            &mut stats,
        );
        assert_eq!(
            *pusher.pushes.borrow(),
            vec![(1111, vec!["abc".to_string()])],
            "the partner's own index holds nothing: push it"
        );
        assert_eq!(stats.suffix_syncs, 1, "{stats:?}");
        assert_eq!(stats.failures, 0, "{stats:?}");
        let _ = std::fs::remove_dir_all(&devices);
    }

    // ---- REVERT: partition lock ------------------------------------------

    #[test]
    fn test_revert_job_skips_cleanly_when_partition_lock_held() {
        let devices = tmp_root("revert-lock");
        let part_path = devices
            .join("sda1")
            .join(swift_diskfile::get_data_dir(POLICY_INDEX))
            .join("3");
        let ts = now_ts();
        put_frag(&part_path, "abc", &ts, 2);

        let job = EcPartJob {
            job_type: EcJobType::Revert,
            frag_index: Some(2),
            suffixes: vec!["abc".to_string()],
            sync_to: vec![node(1111, 2)],
            sync_handoffs: Vec::new(),
            partition: 3,
            path: part_path.clone(),
            device: "sda1".to_string(),
            primary_frag_index: None,
        };
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let pusher = RecordingPusher::default();
        let fetcher = FakeFetcher {
            by_port: HashMap::new(),
        };

        // Python's incoming-SSYNC lock: same directory, same name.
        let held = swift_core::lockutil::lock_path(&part_path, 1.0, Some("replication"))
            .expect("test holds the partition lock");
        let mut stats = EcSsyncStats::default();
        process_part_job(
            &devices,
            &hc,
            &cfg,
            POLICY_INDEX,
            ec_kind(),
            &job,
            &pusher,
            &fetcher,
            None,
            &mut stats,
        );
        assert!(
            pusher.pushes.borrow().is_empty(),
            "locked partition must not be reverted"
        );
        assert_eq!(stats, EcSsyncStats::default(), "a skip, not an error");

        // Once the lock is released the same job proceeds.
        drop(held);
        process_part_job(
            &devices,
            &hc,
            &cfg,
            POLICY_INDEX,
            ec_kind(),
            &job,
            &pusher,
            &fetcher,
            None,
            &mut stats,
        );
        assert_eq!(pusher.pushes.borrow().len(), 1);
        assert_eq!(stats.reverts, 1, "{stats:?}");
        assert_eq!(stats.failures, 0, "{stats:?}");
        let _ = std::fs::remove_dir_all(&devices);
    }

    #[test]
    fn test_delete_reverted_waits_for_object_mutation_stripe() {
        let devices = tmp_root("revert-object-lock");
        let part_path = devices
            .join("sda1")
            .join(swift_diskfile::get_data_dir(POLICY_INDEX))
            .join("3");
        let ts = now_ts();
        let suffix = "abc";
        let object_hash = format!("{:0>29}{suffix}", 2);
        put_frag(&part_path, suffix, &ts, 2);
        let hash_dir = part_path.join(suffix).join(&object_hash);
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let df = DiskFile::from_hash_dir(
            &devices.join("sda1"),
            &hash_dir,
            ec_kind(),
            POLICY_INDEX,
            &hc,
            cfg.clone(),
        );
        let held = df
            .acquire_mutation_lock(1.0)
            .expect("test holds the object mutation stripe");
        let job = EcPartJob {
            job_type: EcJobType::Revert,
            frag_index: Some(2),
            suffixes: vec![suffix.to_string()],
            sync_to: Vec::new(),
            sync_handoffs: Vec::new(),
            partition: 3,
            path: part_path,
            device: "sda1".to_string(),
            primary_frag_index: None,
        };
        let timestamp = ts.parse().unwrap();
        let objects = BTreeMap::from([(
            object_hash,
            RevertObjectSnapshot {
                suffix: suffix.to_string(),
                timestamps: ObjectTimestamps {
                    ts_data: timestamp,
                    ts_meta: None,
                    ts_ctype: None,
                    durable: Some(true),
                },
                identity: snapshot_revert_hash_dir(&hash_dir).unwrap(),
            },
        )]);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            drop(held);
        });
        let started = std::time::Instant::now();
        delete_reverted_objs(&devices, &hc, &cfg, POLICY_INDEX, ec_kind(), &job, &objects)
            .expect("revert succeeds after the foreground lock is released");
        releaser.join().unwrap();
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(10),
            "the purge must wait for the foreground mutation stripe"
        );
        assert!(
            !hash_dir.exists(),
            "the revert purges the exact generation after the stripe is released"
        );
        let _ = std::fs::remove_dir_all(&devices);
    }

    #[test]
    fn test_delete_reverted_busy_object_is_retryable_not_success() {
        let devices = tmp_root("revert-object-busy");
        let part_path = devices
            .join("sda1")
            .join(swift_diskfile::get_data_dir(POLICY_INDEX))
            .join("3");
        let ts = now_ts();
        let suffix = "abc";
        let object_hash = format!("{:0>29}{suffix}", 2);
        put_frag(&part_path, suffix, &ts, 2);
        let hash_dir = part_path.join(suffix).join(&object_hash);
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        let df = DiskFile::from_hash_dir(
            &devices.join("sda1"),
            &hash_dir,
            ec_kind(),
            POLICY_INDEX,
            &hc,
            cfg.clone(),
        );
        let _held = df
            .acquire_mutation_lock(1.0)
            .expect("test holds the object mutation stripe");
        let job = EcPartJob {
            job_type: EcJobType::Revert,
            frag_index: Some(2),
            suffixes: vec![suffix.to_string()],
            sync_to: Vec::new(),
            sync_handoffs: Vec::new(),
            partition: 3,
            path: part_path,
            device: "sda1".to_string(),
            primary_frag_index: None,
        };
        let objects = BTreeMap::from([(
            object_hash,
            RevertObjectSnapshot {
                suffix: suffix.to_string(),
                timestamps: ObjectTimestamps {
                    ts_data: ts.parse().unwrap(),
                    ts_meta: None,
                    ts_ctype: None,
                    durable: Some(true),
                },
                identity: snapshot_revert_hash_dir(&hash_dir).unwrap(),
            },
        )]);
        let error =
            delete_reverted_objs(&devices, &hc, &cfg, POLICY_INDEX, ec_kind(), &job, &objects)
                .expect_err("a busy object must leave the revert for a later pass");
        assert!(error.contains("could not lock object"), "{error}");
        assert!(hash_dir.exists(), "a busy generation must remain intact");
        let _ = std::fs::remove_dir_all(&devices);
    }
}

#[cfg(all(test, feature = "ec"))]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn http_fragment_fetcher_prefers_data_timestamp_over_header_order() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let body = b"fragment-archive";
            // Deliberately put the newer metadata timestamp first.  The
            // fetcher must still select X-Backend-Data-Timestamp.
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 X-Backend-Timestamp: 1751500999.99999\r\n\
                 X-Backend-Data-Timestamp: 1751500123.45678\r\n\
                 X-Object-Sysmeta-Ec-Frag-Index: 2\r\n\
                 X-Object-Sysmeta-Ec-Etag: deadbeefdeadbeefdeadbeefdeadbeef\r\n\
                 X-Object-Sysmeta-Ec-Content-Length: {}\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len(),
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
            request
        });

        let node = RingDevice {
            id: 1,
            region: 1,
            zone: 1,
            ip: "127.0.0.1".to_string(),
            port: u32::from(port),
            replication_ip: None,
            replication_port: None,
            device: "sda1".to_string(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        };
        let fetched = HttpFragmentFetcher {
            policy_index: 2,
            conn_timeout: Duration::from_secs(2),
            node_timeout: Duration::from_secs(2),
            ..Default::default()
        }
        .fetch_at(
            &node,
            17,
            "AUTH_test",
            "c-è",
            "o-è/child",
            Some("1751500123.45678"),
        )
        .expect("fetch fragment");

        let request = server.join().unwrap();
        let request = String::from_utf8(request).unwrap();
        assert!(
            request.starts_with("GET /sda1/17/AUTH_test/c-%C3%A8/o-%C3%A8/child HTTP/1.1\r\n"),
            "UTF-8 Swift path segments must be percent-encoded: {request:?}"
        );
        assert!(
            request.contains("X-Backend-Fragment-Preferences: [")
                && request.contains("\"timestamp\":\"1751500123.45678\"")
                && request.contains("\"exclude\":[]"),
            "preferred durable timestamp must reach the peer: {request:?}"
        );
        assert_eq!(fetched.timestamp, "1751500123.45678");
        assert_eq!(fetched.frag_index, 2);
        assert_eq!(fetched.archive, b"fragment-archive");
    }

    #[test]
    fn http_fragment_fetcher_uses_replication_plane() {
        let service_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        service_listener.set_nonblocking(true).unwrap();
        let service_port = service_listener.local_addr().unwrap().port();
        let replication_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let replication_port = replication_listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = replication_listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            let body = b"replication-plane-fragment";
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 X-Backend-Data-Timestamp: 1751500123.45678\r\n\
                 X-Object-Sysmeta-Ec-Frag-Index: 2\r\n\
                 X-Object-Sysmeta-Ec-Etag: deadbeefdeadbeefdeadbeefdeadbeef\r\n\
                 X-Object-Sysmeta-Ec-Content-Length: {}\r\n\
                 Content-Type: application/octet-stream\r\n\
                 Content-Length: {}\r\n\r\n",
                body.len(),
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });
        let node = RingDevice {
            id: 1,
            region: 1,
            zone: 1,
            ip: "127.0.0.1".to_string(),
            port: u32::from(service_port),
            replication_ip: Some("127.0.0.1".to_string()),
            replication_port: Some(u32::from(replication_port)),
            device: "sda1".to_string(),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        };
        let fetched = HttpFragmentFetcher {
            policy_index: 2,
            conn_timeout: Duration::from_secs(1),
            node_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(2),
            ..Default::default()
        }
        .fetch(&node, 17, "a", "c", "o")
        .expect("replication-plane response");
        assert_eq!(fetched.archive, b"replication-plane-fragment");
        assert!(
            matches!(service_listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "the client/service plane must not receive reconstruction GETs"
        );
        server.join().unwrap();
    }

    struct VersionFetcher {
        by_node: HashMap<u64, FetchedFragment>,
    }

    impl FragmentFetcher for VersionFetcher {
        fn fetch(
            &self,
            node: &RingDevice,
            _partition: u64,
            _account: &str,
            _container: &str,
            _object: &str,
        ) -> Option<FetchedFragment> {
            self.by_node.get(&node.id).cloned()
        }
    }

    fn fetched_fragment(index: i32, timestamp: &str, etag: &str, byte: u8) -> FetchedFragment {
        FetchedFragment {
            frag_index: index,
            archive: vec![byte],
            ec_etag: etag.to_string(),
            ec_content_length: 1,
            timestamp: timestamp.to_string(),
            content_type: "application/octet-stream".to_string(),
        }
    }

    #[test]
    fn coherent_gather_ignores_stale_first_peer_and_deduplicates_indexes() {
        let stale_etag = "11111111111111111111111111111111";
        let current_etag = "22222222222222222222222222222222";
        let fetcher = VersionFetcher {
            by_node: HashMap::from([
                (0, fetched_fragment(0, "1751500000.00000", stale_etag, 0)),
                (1, fetched_fragment(1, "1751500001.00000", current_etag, 1)),
                (2, fetched_fragment(2, "1751500001.00000", current_etag, 2)),
            ]),
        };
        let peers = vec![dev(0), dev(1), dev(2)];
        let (chosen, archives) =
            gather_coherent_archives(&peers, 0, "a", "c", "o", 2, &fetcher, None)
                .expect("later coherent quorum");
        assert_eq!(chosen.timestamp, "1751500001.00000");
        assert_eq!(archives, [vec![1], vec![2]]);

        let duplicate_fetcher = VersionFetcher {
            by_node: HashMap::from([
                (0, fetched_fragment(0, "1751500001.00000", current_etag, 0)),
                (1, fetched_fragment(0, "1751500001.00000", current_etag, 9)),
                (2, fetched_fragment(1, "1751500001.00000", current_etag, 1)),
            ]),
        };
        assert!(matches!(
            gather_coherent_archives(&peers, 0, "a", "c", "o", 3, &duplicate_fetcher, None),
            Err(ReconstructError::NotEnoughFragments)
        ));
    }

    /// A fetcher backed by fragment archives held in memory, keyed by node id
    /// (node `i` returns fragment `i`) — the same layout a real cluster holds.
    struct FakeFetcher {
        archives: Vec<Vec<u8>>,
        ec_etag: String,
        ec_content_length: usize,
        timestamp: String,
    }

    impl FragmentFetcher for FakeFetcher {
        fn fetch(
            &self,
            node: &RingDevice,
            _partition: u64,
            _a: &str,
            _c: &str,
            _o: &str,
        ) -> Option<FetchedFragment> {
            let i = node.id as usize;
            Some(FetchedFragment {
                frag_index: i as i32,
                archive: self.archives.get(i)?.clone(),
                ec_etag: self.ec_etag.clone(),
                ec_content_length: self.ec_content_length,
                timestamp: self.timestamp.clone(),
                content_type: "application/octet-stream".to_string(),
            })
        }
    }

    fn dev(id: u64) -> RingDevice {
        RingDevice {
            id,
            region: 1,
            zone: 1,
            ip: "127.0.0.1".to_string(),
            port: 6200 + id as u32,
            replication_ip: None,
            replication_port: None,
            device: format!("sd{id}"),
            weight: 1.0,
            meta: String::new(),
            extra: Default::default(),
        }
    }

    #[test]
    fn test_rebuild_job_persists_identical_durable_fragment() {
        let k = 4usize;
        let m = 2usize;
        let seg = 1000usize;
        let driver = EcDriver::new(k, m).unwrap();
        let data: Vec<u8> = (0..3500u32).map(|i| (i * 7 % 256) as u8).collect();
        let archives = driver.encode_object(&data, seg).unwrap();
        let ec_etag = md5_hex(&data);
        let ts = "1751500123.45678";

        let dir = std::env::temp_dir().join(format!("swift-recon-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        std::fs::create_dir_all(&device).unwrap();
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();

        // Rebuild fragment index 2 (this node lost it) from the other nodes.
        let dest = 2usize;
        let peers: Vec<RingDevice> = (0..(k + m) as u64)
            .filter(|i| *i != dest as u64)
            .map(dev)
            .collect();
        let fetcher = FakeFetcher {
            archives: archives.clone(),
            ec_etag: ec_etag.clone(),
            ec_content_length: data.len(),
            timestamp: ts.to_string(),
        };
        let job = ReconstructJob {
            partition: 0,
            account: "AUTH_test".to_string(),
            container: "c".to_string(),
            object: "o".to_string(),
            destination_index: dest,
            peers,
        };
        let scheme = EcScheme {
            ndata: k,
            nparity: m,
            segment_size: seg,
        };
        rebuild_job(&device, 1, scheme, &hc, &cfg, &job, &fetcher).expect("rebuild");

        // The durable fragment <ts>#2#d.data now holds the byte-identical
        // archive the original PUT would have written to node 2.
        let mut df = DiskFile::new(
            &device,
            0,
            "AUTH_test",
            "c",
            "o",
            PolicyKind::Ec {
                n_unique_fragments: Some((k + m) as u32),
            },
            1,
            &hc,
            cfg.clone(),
        )
        .unwrap();
        df.open(None).expect("reopen rebuilt fragment");
        let idxs = df.fragments().unwrap();
        assert!(
            idxs.iter().any(|(_, set)| set.contains(&(dest as i64))),
            "durable set contains the rebuilt index: {idxs:?}"
        );
        let mut reader = df.reader().unwrap();
        let stored = reader.read_all().unwrap();
        reader.close().ok();
        assert_eq!(stored, archives[dest], "rebuilt fragment is byte-identical");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_rebuild_job_not_enough_fragments() {
        let scheme = EcScheme {
            ndata: 4,
            nparity: 2,
            segment_size: 1000,
        };
        let driver = EcDriver::new(4, 2).unwrap();
        let data = vec![1u8; 2000];
        let archives = driver.encode_object(&data, 1000).unwrap();
        let dir = std::env::temp_dir().join(format!("swift-recon-few-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let device = dir.join("sda1");
        std::fs::create_dir_all(&device).unwrap();
        let hc = HashPathConfig::new("", "changeme").unwrap();
        let cfg = DiskFileConfig::default();
        // only 2 peers available -> fewer than ndata=4
        let fetcher = FakeFetcher {
            archives,
            ec_etag: md5_hex(&data),
            ec_content_length: data.len(),
            timestamp: "1751500000.00000".to_string(),
        };
        let job = ReconstructJob {
            partition: 0,
            account: "a".into(),
            container: "c".into(),
            object: "o".into(),
            destination_index: 0,
            peers: vec![dev(1), dev(3)],
        };
        assert_eq!(
            rebuild_job(&device, 1, scheme, &hc, &cfg, &job, &fetcher),
            Err(ReconstructError::NotEnoughFragments)
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
