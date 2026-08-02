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

//! The `DiskFile` object lifecycle, ported from `BaseDiskFile` /
//! `DiskFile` / `ECDiskFile` and their reader/writer classes: open with
//! fast-POST metadata merging and validation, chunked reads with etag
//! verification, and the tempfile → xattr → fsync → rename write path
//! with EC two-phase commit.
//!
//! Deliberate deviations from Python, tracked for the object-server
//! milestone: no `O_TMPFILE`/`linkat` fast path (always mkstemp-style),
//! no `fallocate`/free-space reserve check, no splice/zero-copy, no
//! partition-power-increase relinking.

use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use md5::{Digest, Md5};
use swift_core::hashing::HashPathConfig;
use swift_core::timestamp::Timestamp;

use crate::cleanup::{cleanup_ondisk_files, CleanupConfig};
use crate::error::DiskFileError;
use crate::hashes::invalidate_hash;
use crate::layout::{get_data_dir, get_tmp_dir, quarantine_renamer, renamer, storage_directory};
use crate::metadata::{
    read_file_metadata, write_file_metadata, MetaValue, Metadata, XattrSource,
    DEFAULT_XATTR_SIZE,
};
use crate::naming::{make_ec_ondisk_filename, make_ondisk_filename, PolicyKind};
use crate::ondisk::{get_ondisk_files, FragPref, OndiskFiles};

/// System metadata keys owned by the `.data` file that a fast-POST can
/// never change (`RESERVED_DATAFILE_META` + `DATAFILE_SYSTEM_META`).
const RESERVED_DATAFILE_META: [&str; 3] = ["content-length", "deleted", "etag"];
const DATAFILE_SYSTEM_META: [&str; 1] = ["x-static-large-object"];
const SYS_META_PREFIX: &str = "x-object-sysmeta-";

fn is_object_sys_meta(key: &str) -> bool {
    key.len() > SYS_META_PREFIX.len() && key.to_ascii_lowercase().starts_with(SYS_META_PREFIX)
}

fn meta_get<'m>(meta: &'m Metadata, key: &str) -> Option<&'m MetaValue> {
    meta.iter()
        .find(|(k, _)| matches!(k, MetaValue::Str(s) if s == key))
        .map(|(_, v)| v)
}

fn meta_get_str<'m>(meta: &'m Metadata, key: &str) -> Option<&'m str> {
    meta_get(meta, key).and_then(|v| v.as_str())
}

/// Python dict assignment: replace in place, else append.
fn meta_set(meta: &mut Metadata, key: &str, value: MetaValue) {
    match meta
        .iter_mut()
        .find(|(k, _)| matches!(k, MetaValue::Str(s) if s == key))
    {
        Some((_, v)) => *v = value,
        None => meta.push((MetaValue::Str(key.to_string()), value)),
    }
}

fn meta_remove(meta: &mut Metadata, key: &str) {
    meta.retain(|(k, _)| !matches!(k, MetaValue::Str(s) if s == key));
}

/// `dict.update` over ordered pairs.
fn meta_update(meta: &mut Metadata, other: &Metadata) {
    for (k, v) in other {
        match meta.iter_mut().find(|(mk, _)| mk == k) {
            Some((_, mv)) => *mv = v.clone(),
            None => meta.push((k.clone(), v.clone())),
        }
    }
}

fn parse_ts(v: Option<&MetaValue>) -> Option<Timestamp> {
    v.and_then(|v| v.as_str()).and_then(|s| s.parse().ok())
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Tunables carried by the Python `DiskFileManager` that the lifecycle
/// needs.
#[derive(Debug, Clone)]
pub struct DiskFileConfig {
    pub cleanup: CleanupConfig,
    pub xattr_size: usize,
    pub disk_chunk_size: usize,
    pub bytes_per_sync: u64,
    /// When true (default), `put` fsyncs the datafile (`sync_all`) and the
    /// rename path fsyncs parent dirs. Set false only for controlled A/B of
    /// the fsync ceiling (L2); not a production durability recommendation.
    pub fsync_on_close: bool,
}

impl Default for DiskFileConfig {
    fn default() -> Self {
        DiskFileConfig {
            cleanup: CleanupConfig::default(),
            xattr_size: DEFAULT_XATTR_SIZE,
            disk_chunk_size: 65536,
            bytes_per_sync: 512 * 1024 * 1024,
            fsync_on_close: true,
        }
    }
}

struct OpenState {
    ondisk: OndiskFiles,
    metadata: Metadata,
    datafile_metadata: Metadata,
    metafile_metadata: Option<Metadata>,
    data_file: PathBuf,
    fp: Option<std::fs::File>,
    content_length: u64,
}

/// Manage one object's files, the Rust `BaseDiskFile`/`DiskFile`/
/// `ECDiskFile`.
pub struct DiskFile {
    device_path: PathBuf,
    datadir: PathBuf,
    tmpdir: PathBuf,
    name: Option<String>,
    policy: PolicyKind,
    frag_index: Option<i64>,
    frag_prefs: Option<Vec<FragPref>>,
    open_expired: bool,
    hash_config: Option<HashPathConfig>,
    cfg: DiskFileConfig,
    state: Option<OpenState>,
}

impl DiskFile {
    /// Construct for an account/container/object, computing the hash dir
    /// from the cluster hash config.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        device_path: &Path,
        partition: u64,
        account: &str,
        container: &str,
        obj: &str,
        policy: PolicyKind,
        policy_index: u32,
        hash_config: &HashPathConfig,
        cfg: DiskFileConfig,
    ) -> Result<Self, DiskFileError> {
        let name_hash = hash_config
            .hash_path(account, Some(container), Some(obj))
            .map_err(|e| DiskFileError::InvalidFilename(e.to_string()))?;
        let datadir = device_path.join(storage_directory(
            Path::new(&get_data_dir(policy_index)),
            partition,
            &name_hash,
        ));
        Ok(DiskFile {
            device_path: device_path.to_path_buf(),
            datadir,
            tmpdir: device_path.join(get_tmp_dir(policy_index)),
            name: Some(format!("/{account}/{container}/{obj}")),
            policy,
            frag_index: None,
            frag_prefs: None,
            open_expired: false,
            hash_config: Some(hash_config.clone()),
            cfg,
            state: None,
        })
    }

    /// Construct against an explicit hash dir (`from_hash_dir`), with the
    /// name learned from the metadata and verified against the dir.
    pub fn from_hash_dir(
        device_path: &Path,
        hash_dir: &Path,
        policy: PolicyKind,
        policy_index: u32,
        hash_config: &HashPathConfig,
        cfg: DiskFileConfig,
    ) -> Self {
        DiskFile {
            device_path: device_path.to_path_buf(),
            datadir: hash_dir.to_path_buf(),
            tmpdir: device_path.join(get_tmp_dir(policy_index)),
            name: None,
            policy,
            frag_index: None,
            frag_prefs: None,
            open_expired: false,
            hash_config: Some(hash_config.clone()),
            cfg,
            state: None,
        }
    }

    /// Override the datadir (test/tooling hook mirroring `_datadir`).
    pub fn with_datadir_override(mut self, datadir: &Path) -> Self {
        self.datadir = datadir.to_path_buf();
        self
    }

    pub fn with_frag_index(mut self, frag_index: Option<i64>) -> Self {
        self.frag_index = frag_index;
        self
    }

    pub fn with_frag_prefs(mut self, frag_prefs: Option<Vec<FragPref>>) -> Self {
        self.frag_prefs = frag_prefs;
        self
    }

    pub fn with_open_expired(mut self, open_expired: bool) -> Self {
        self.open_expired = open_expired;
        self
    }

    pub fn datadir(&self) -> &Path {
        &self.datadir
    }

    fn quarantine(&self, data_file: &Path, msg: &str) -> DiskFileError {
        let _ = quarantine_renamer(&self.device_path, data_file);
        DiskFileError::Quarantined(msg.to_string())
    }

    /// `_read_and_validate_metadata`: quarantine on checksum or pickle
    /// failure.
    fn read_and_validate(
        &self,
        source: XattrSource<'_>,
        quarantine_filename: &Path,
    ) -> Result<Metadata, DiskFileError> {
        match read_file_metadata(source) {
            Err(DiskFileError::XattrNotSupported) => Err(DiskFileError::XattrNotSupported),
            Err(DiskFileError::StateChanged) => Err(DiskFileError::StateChanged),
            Err(DiskFileError::BadMetadataChecksum(msg)) => {
                Err(self.quarantine(quarantine_filename, &msg))
            }
            Err(e) => Err(self.quarantine(
                quarantine_filename,
                &format!("Exception reading metadata: {e}"),
            )),
            Ok(meta) => Ok(meta),
        }
    }

    /// Port of `BaseDiskFile.open`.
    pub fn open(&mut self, current_time: Option<f64>) -> Result<&mut Self, DiskFileError> {
        let files = match std::fs::read_dir(&self.datadir) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => {
                return Err(self.quarantine(
                    &self.datadir.join("made-up-filename"),
                    &format!("Expected directory, found file at {}", self.datadir.display()),
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(DiskFileError::Io(e)),
        };

        let ondisk = get_ondisk_files(
            &files,
            &self.datadir,
            true,
            self.policy,
            self.frag_index,
            self.frag_prefs.as_deref(),
        )?;

        let Some(data_file) = ondisk.data_file.clone() else {
            return Err(self.exception_from_ts_file(&ondisk));
        };

        let fp = match std::fs::File::open(&data_file) {
            Ok(fp) => fp,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(DiskFileError::StateChanged)
            }
            Err(e) => return Err(DiskFileError::Io(e)),
        };
        let datafile_metadata =
            self.read_and_validate(XattrSource::File(&fp), &data_file)?;
        let data_timestamp = parse_ts(meta_get(&datafile_metadata, "X-Timestamp"));

        let mut metadata = Metadata::new();
        let mut metafile_metadata: Option<Metadata> = None;
        if let Some(meta_file) = &ondisk.meta_file {
            let mut mf_meta =
                self.read_and_validate(XattrSource::Path(meta_file), meta_file)?;
            if let Some(ctype_file) = &ondisk.ctype_file {
                if ctype_file != meta_file {
                    self.merge_content_type_metadata(
                        ctype_file,
                        &mut mf_meta,
                        data_timestamp,
                    )?;
                }
            }
            let sys_metadata: Metadata = datafile_metadata
                .iter()
                .filter(|(k, _)| match k {
                    MetaValue::Str(s) => {
                        let lower = s.to_ascii_lowercase();
                        RESERVED_DATAFILE_META.contains(&lower.as_str())
                            || DATAFILE_SYSTEM_META.contains(&lower.as_str())
                            || is_object_sys_meta(s)
                    }
                    _ => false,
                })
                .cloned()
                .collect();
            meta_update(&mut metadata, &mf_meta);
            meta_update(&mut metadata, &sys_metadata);
            // the diskfile writer added 'name' to the metafile; drop it
            // from the metafile view
            meta_remove(&mut mf_meta, "name");
            let metafile_ctype_ts = parse_ts(meta_get(&mf_meta, "Content-Type-Timestamp"));
            if meta_get(&datafile_metadata, "Content-Type").is_some()
                && data_timestamp > metafile_ctype_ts
            {
                meta_set(
                    &mut metadata,
                    "Content-Type",
                    meta_get(&datafile_metadata, "Content-Type").unwrap().clone(),
                );
                meta_remove(&mut metadata, "Content-Type-Timestamp");
            }
            metafile_metadata = Some(mf_meta);
        } else {
            metadata = datafile_metadata.clone();
        }

        self.state = Some(OpenState {
            ondisk,
            metadata,
            datafile_metadata,
            metafile_metadata,
            data_file: data_file.clone(),
            fp: Some(fp),
            content_length: 0,
        });

        if self.name.is_none() {
            // given only a hash dir: learn the name, then verify it
            // hashes back to this directory
            let name = meta_get_str(&self.state.as_ref().unwrap().metadata, "name")
                .map(str::to_string);
            match name {
                Some(name) => {
                    let hash_from_name = self
                        .hash_config
                        .as_ref()
                        .and_then(|hc| {
                            hc.hash_path(name.trim_start_matches('/'), None, None).ok()
                        })
                        .unwrap_or_default();
                    let hash_from_fs = self
                        .datadir
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    if hash_from_fs != hash_from_name {
                        self.state = None;
                        return Err(self.quarantine(
                            &data_file,
                            "Hash of name in metadata does not match directory name",
                        ));
                    }
                    self.name = Some(name);
                }
                None => {
                    self.state = None;
                    return Err(self.quarantine(&data_file, "missing name metadata"));
                }
            }
        }

        if let Err(e) = self.verify_data_file(&data_file, current_time) {
            self.state = None;
            return Err(e);
        }
        Ok(self)
    }

    /// `_construct_exception_from_ts_file`.
    fn exception_from_ts_file(&self, ondisk: &OndiskFiles) -> DiskFileError {
        let Some(ts_file) = &ondisk.ts_file else {
            return DiskFileError::NotExist;
        };
        match self.read_and_validate(XattrSource::Path(ts_file), ts_file) {
            Err(DiskFileError::Quarantined(_)) | Err(DiskFileError::StateChanged) => {
                DiskFileError::NotExist
            }
            Err(e) => e,
            Ok(metadata) => {
                let timestamp = parse_ts(meta_get(&metadata, "X-Timestamp"))
                    .unwrap_or_else(|| Timestamp::from_parts(0, 0).unwrap());
                DiskFileError::Deleted {
                    metadata,
                    timestamp,
                }
            }
        }
    }

    /// `_merge_content_type_metadata`.
    fn merge_content_type_metadata(
        &self,
        ctype_file: &Path,
        metafile_metadata: &mut Metadata,
        data_timestamp: Option<Timestamp>,
    ) -> Result<(), DiskFileError> {
        let ctypefile_metadata =
            self.read_and_validate(XattrSource::Path(ctype_file), ctype_file)?;
        let ctype = meta_get(&ctypefile_metadata, "Content-Type").cloned();
        let ctype_ts = parse_ts(meta_get(&ctypefile_metadata, "Content-Type-Timestamp"));
        let meta_ctype_ts = parse_ts(meta_get(metafile_metadata, "Content-Type-Timestamp"));
        if let (Some(ctype), Some(ctype_ts_val)) = (ctype, ctype_ts) {
            if Some(ctype_ts_val) > meta_ctype_ts && Some(ctype_ts_val) > data_timestamp {
                meta_set(metafile_metadata, "Content-Type", ctype);
                meta_set(
                    metafile_metadata,
                    "Content-Type-Timestamp",
                    MetaValue::Str(ctype_ts_val.internal()),
                );
            }
        }
        Ok(())
    }

    /// `_verify_data_file`.
    fn verify_data_file(
        &mut self,
        data_file: &Path,
        current_time: Option<f64>,
    ) -> Result<(), DiskFileError> {
        let state = self.state.as_ref().unwrap();
        let metadata = &state.metadata;
        let Some(mname) = meta_get_str(metadata, "name") else {
            return Err(self.quarantine(data_file, "missing name metadata"));
        };
        if Some(mname) != self.name.as_deref() {
            return Err(DiskFileError::Collision);
        }
        match meta_get(metadata, "X-Delete-At") {
            None => {}
            Some(v) => {
                let x_delete_at = match v {
                    MetaValue::Int(i) => Some(*i),
                    MetaValue::Str(s) => crate::naming::python_int(s),
                    MetaValue::Bytes(_) => None,
                };
                match x_delete_at {
                    None => {
                        let msg = format!("bad metadata x-delete-at value {v:?}");
                        return Err(self.quarantine(data_file, &msg));
                    }
                    Some(x_delete_at) => {
                        let current_time = current_time.unwrap_or_else(now_secs);
                        if x_delete_at as f64 <= current_time && !self.open_expired {
                            let metadata = metadata.clone();
                            self.state = None;
                            return Err(DiskFileError::Expired { metadata });
                        }
                    }
                }
            }
        }
        let metadata_size = match meta_get(metadata, "Content-Length") {
            None => {
                return Err(self.quarantine(data_file, "missing content-length in metadata"))
            }
            Some(MetaValue::Int(i)) => Some(*i),
            Some(MetaValue::Str(s)) => crate::naming::python_int(s),
            Some(MetaValue::Bytes(_)) => None,
        };
        let Some(metadata_size) = metadata_size else {
            let msg = format!(
                "bad metadata content-length value {}",
                meta_get_str(metadata, "Content-Length").unwrap_or("?")
            );
            return Err(self.quarantine(data_file, &msg));
        };
        let obj_size = match state.fp.as_ref().unwrap().metadata() {
            Ok(m) => m.len(),
            Err(e) => {
                let msg = format!("not stat-able: {e}");
                return Err(self.quarantine(data_file, &msg));
            }
        };
        if obj_size as i64 != metadata_size {
            let msg = format!(
                "metadata content-length {metadata_size} does not match actual object size {obj_size}"
            );
            return Err(self.quarantine(data_file, &msg));
        }
        self.state.as_mut().unwrap().content_length = obj_size;
        Ok(())
    }

    fn opened(&self) -> Result<&OpenState, DiskFileError> {
        self.state.as_ref().ok_or(DiskFileError::NotOpen)
    }

    pub fn get_metadata(&self) -> Result<&Metadata, DiskFileError> {
        Ok(&self.opened()?.metadata)
    }

    pub fn get_datafile_metadata(&self) -> Result<&Metadata, DiskFileError> {
        Ok(&self.opened()?.datafile_metadata)
    }

    pub fn get_metafile_metadata(&self) -> Result<Option<&Metadata>, DiskFileError> {
        Ok(self.opened()?.metafile_metadata.as_ref())
    }

    pub fn content_length(&self) -> Result<u64, DiskFileError> {
        Ok(self.opened()?.content_length)
    }

    pub fn timestamp(&self) -> Result<Timestamp, DiskFileError> {
        parse_ts(meta_get(&self.opened()?.metadata, "X-Timestamp"))
            .ok_or(DiskFileError::NotOpen)
    }

    pub fn data_timestamp(&self) -> Result<Timestamp, DiskFileError> {
        parse_ts(meta_get(&self.opened()?.datafile_metadata, "X-Timestamp"))
            .ok_or(DiskFileError::NotOpen)
    }

    /// Repl: newest data file timestamp; EC: the durable set timestamp.
    pub fn durable_timestamp(&self) -> Result<Option<Timestamp>, DiskFileError> {
        let state = self.opened()?;
        Ok(match self.policy {
            PolicyKind::Replication => {
                parse_ts(meta_get(&state.datafile_metadata, "X-Timestamp"))
            }
            PolicyKind::Ec { .. } => state.ondisk.durable_frag_set_ts,
        })
    }

    pub fn content_type(&self) -> Result<Option<&str>, DiskFileError> {
        Ok(meta_get_str(&self.opened()?.metadata, "Content-Type"))
    }

    pub fn content_type_timestamp(&self) -> Result<Timestamp, DiskFileError> {
        let state = self.opened()?;
        parse_ts(meta_get(&state.metadata, "Content-Type-Timestamp"))
            .or_else(|| parse_ts(meta_get(&state.datafile_metadata, "X-Timestamp")))
            .ok_or(DiskFileError::NotOpen)
    }

    /// EC: every fragment set found, `timestamp -> frag indexes`.
    pub fn fragments(&self) -> Result<Vec<(Timestamp, Vec<i64>)>, DiskFileError> {
        let state = self.opened()?;
        Ok(state
            .ondisk
            .frag_sets
            .iter()
            .map(|(ts, set)| (*ts, set.iter().filter_map(|i| i.frag_index).collect()))
            .collect())
    }

    /// Hand out a reader that owns the open file (etag/size verified on
    /// close, quarantining on mismatch).
    pub fn reader(&mut self) -> Result<DiskFileReader, DiskFileError> {
        let etag = meta_get_str(&self.opened()?.metadata, "ETag")
            .map(str::to_string)
            .unwrap_or_default();
        let obj_size = self.opened()?.content_length;
        let state = self.state.as_mut().unwrap();
        let fp = state.fp.take().ok_or(DiskFileError::NotOpen)?;
        Ok(DiskFileReader {
            fp: Arc::new(fp),
            data_file: state.data_file.clone(),
            device_path: self.device_path.clone(),
            obj_size,
            etag,
            disk_chunk_size: self.cfg.disk_chunk_size,
            bytes_read: 0,
            md5: Some(Md5::new()),
        })
    }

    /// `create()`: a writer over a temp file in the policy tmp dir.
    pub fn create(&self, extension: &str) -> Result<DiskFileWriter<'_>, DiskFileError> {
        let name = self
            .name
            .clone()
            .ok_or_else(|| DiskFileError::InvalidFilename("diskfile has no name".into()))?;
        std::fs::create_dir_all(&self.tmpdir)?;
        let (file, tmppath) = mkstemp(&self.tmpdir)?;
        Ok(DiskFileWriter {
            df: self,
            name,
            file: Some(file),
            tmppath: Some(tmppath),
            extension: extension.to_string(),
            upload_size: 0,
            last_sync: 0,
            md5: Md5::new(),
            put_succeeded: false,
            frag_index: self.frag_index,
        })
    }

    /// Fast-POST: write a `.meta` file.
    pub fn write_metadata(&self, metadata: &Metadata) -> Result<(), DiskFileError> {
        let mut writer = self.create(".meta")?;
        writer.put(metadata.clone())?;
        writer.close();
        Ok(())
    }

    /// DELETE: write a tombstone; older files are cleaned up.
    pub fn delete(&self, timestamp: &Timestamp) -> Result<(), DiskFileError> {
        let mut writer = self.create(".ts")?;
        writer.put(vec![(
            MetaValue::Str("X-Timestamp".to_string()),
            MetaValue::Str(timestamp.internal()),
        )])?;
        writer.close();
        Ok(())
    }

    /// EC `purge`: remove a tombstone/fragment pair after revert.
    pub fn purge(
        &self,
        timestamp: &Timestamp,
        frag_index: Option<i64>,
        nondurable_purge_delay: f64,
        meta_timestamp: Option<&Timestamp>,
    ) -> Result<(), DiskFileError> {
        let remove = |p: PathBuf| {
            let _ = std::fs::remove_file(p);
        };
        remove(self.datadir.join(make_ondisk_filename(timestamp, Some(".ts"), None)));
        if let Some(mts) = meta_timestamp {
            remove(self.datadir.join(make_ondisk_filename(mts, Some(".meta"), None)));
        }
        if let Some(fi) = frag_index {
            let nondurable = self
                .datadir
                .join(make_ec_ondisk_filename(timestamp, fi, false)?);
            if crate::cleanup::is_file_older(&nondurable, nondurable_purge_delay) {
                remove(nondurable);
            }
            remove(
                self.datadir
                    .join(make_ec_ondisk_filename(timestamp, fi, true)?),
            );
            let _ = std::fs::remove_dir(&self.datadir);
        }
        if let Some(suffix_dir) = self.datadir.parent() {
            invalidate_hash(suffix_dir)?;
        }
        Ok(())
    }
}

fn mkstemp(dir: &Path) -> Result<(std::fs::File, PathBuf), DiskFileError> {
    for attempt in 0..100 {
        let path = dir.join(format!(
            "tmp{}-{:x}-{attempt}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((file, path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) if matches!(e.raw_os_error(), Some(28)) => {
                return Err(DiskFileError::NoSpace)
            }
            Err(e) => return Err(DiskFileError::Io(e)),
        }
    }
    Err(DiskFileError::Io(std::io::Error::other(
        "could not create unique tempfile",
    )))
}

/// The Rust `BaseDiskFileWriter` (+ repl/EC `put`/`commit` overrides).
pub struct DiskFileWriter<'a> {
    df: &'a DiskFile,
    name: String,
    file: Option<std::fs::File>,
    tmppath: Option<PathBuf>,
    extension: String,
    upload_size: u64,
    last_sync: u64,
    md5: Md5,
    put_succeeded: bool,
    frag_index: Option<i64>,
}

impl DiskFileWriter<'_> {
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), DiskFileError> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| DiskFileError::Io(std::io::Error::other("writer is not open")))?;
        self.md5.update(chunk);
        file.write_all(chunk)?;
        self.upload_size += chunk.len() as u64;
        // for large files, sync every bytes_per_sync written
        if self.df.cfg.fsync_on_close
            && self.upload_size - self.last_sync >= self.df.cfg.bytes_per_sync
        {
            file.sync_data()?;
            self.last_sync = self.upload_size;
        }
        Ok(())
    }

    pub fn chunks_finished(&self) -> (u64, String) {
        (self.upload_size, format!("{:x}", self.md5.clone().finalize()))
    }

    /// `put()`: finalize on disk. For EC `.data` files the fragment index
    /// is stamped into sysmeta and cleanup is deferred to `commit()`.
    pub fn put(&mut self, mut metadata: Metadata) -> Result<(), DiskFileError> {
        let mut cleanup = true;
        let mut frag_index_arg: Option<i64> = None;
        if matches!(self.df.policy, PolicyKind::Ec { .. }) && self.extension == ".data" {
            let n = match self.df.policy {
                PolicyKind::Ec { n_unique_fragments } => n_unique_fragments,
                PolicyKind::Replication => None,
            };
            let fi_value = match meta_get(&metadata, "X-Object-Sysmeta-Ec-Frag-Index") {
                Some(v) => v.clone(),
                None => {
                    let fi = self.frag_index.ok_or_else(|| {
                        DiskFileError::BadFragmentIndex("Bad fragment index: None".into())
                    })?;
                    let v = MetaValue::Int(fi);
                    meta_set(&mut metadata, "X-Object-Sysmeta-Ec-Frag-Index", v.clone());
                    v
                }
            };
            let fi = match &fi_value {
                MetaValue::Int(i) => Some(*i),
                MetaValue::Str(s) => crate::naming::python_int(s),
                MetaValue::Bytes(_) => None,
            }
            .ok_or_else(|| {
                DiskFileError::BadFragmentIndex(format!("Bad fragment index: {fi_value:?}"))
            })?;
            if fi < 0 {
                return Err(DiskFileError::BadFragmentIndex(format!(
                    "Fragment index must not be negative: {fi}"
                )));
            }
            if let Some(n) = n {
                if fi >= n as i64 {
                    return Err(DiskFileError::BadFragmentIndex(format!(
                        "Fragment index must be less than {n}: {fi}"
                    )));
                }
            }
            frag_index_arg = Some(fi);
            // Persist the resolved fragment index so a subsequent commit()
            // (which reads self.frag_index) can rename the .data to its durable
            // ts#N#d.data name. The proxy supplies the index in the PUT
            // metadata, not at writer construction, so without this commit()
            // sees frag_index=None and the fragment never becomes durable.
            // Python: ECDiskFileWriter.put sets self._diskfile._frag_index = fi.
            self.frag_index = Some(fi);
            cleanup = false;
        }
        self.finalize_put(metadata, cleanup, frag_index_arg)
    }

    fn finalize_put(
        &mut self,
        mut metadata: Metadata,
        cleanup: bool,
        frag_index: Option<i64>,
    ) -> Result<(), DiskFileError> {
        let timestamp: Timestamp = meta_get_str(&metadata, "X-Timestamp")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| {
                DiskFileError::InvalidFilename("missing X-Timestamp in metadata".into())
            })?;
        let ctype_timestamp = parse_ts(meta_get(&metadata, "Content-Type-Timestamp"));
        let filename = match frag_index {
            Some(fi) => make_ec_ondisk_filename(&timestamp, fi, false)?,
            None => make_ondisk_filename(
                &timestamp,
                Some(&self.extension),
                ctype_timestamp.as_ref(),
            ),
        };
        meta_set(&mut metadata, "name", MetaValue::Str(self.name.clone()));
        let target_path = self.df.datadir.join(&filename);

        let file = self
            .file
            .as_ref()
            .ok_or_else(|| DiskFileError::Io(std::io::Error::other("writer is not open")))?;
        // metadata goes down before the fsync so data and metadata flush
        // together
        write_file_metadata(XattrSource::File(file), &metadata, self.df.cfg.xattr_size)?;
        if self.df.cfg.fsync_on_close {
            file.sync_all()?;
        }
        if let Some(suffix_dir) = self.df.datadir.parent() {
            invalidate_hash(suffix_dir)?;
        }
        let tmppath = self.tmppath.as_ref().unwrap();
        renamer(tmppath, &target_path, self.df.cfg.fsync_on_close)?;
        self.put_succeeded = true;
        if cleanup {
            let _ = cleanup_ondisk_files(&self.df.datadir, self.df.policy, &self.df.cfg.cleanup);
        }
        Ok(())
    }

    /// EC two-phase commit: rename the fragment to its durable name
    /// (`ECDiskFileWriter.commit`/`_finalize_durable`).
    pub fn commit(&mut self, timestamp: &Timestamp) -> Result<(), DiskFileError> {
        if !matches!(self.df.policy, PolicyKind::Ec { .. }) {
            return Ok(()); // replication commit is a no-op
        }
        let fi = self.frag_index.ok_or_else(|| {
            DiskFileError::BadFragmentIndex("Bad fragment index: None".into())
        })?;
        let data_file_path = self
            .df
            .datadir
            .join(make_ec_ondisk_filename(timestamp, fi, false)?);
        let durable_data_file_path = self
            .df
            .datadir
            .join(make_ec_ondisk_filename(timestamp, fi, true)?);
        match std::fs::rename(&data_file_path, &durable_data_file_path) {
            Ok(()) => {
                std::fs::File::open(&self.df.datadir)?.sync_all()?;
                let _ = cleanup_ondisk_files(
                    &self.df.datadir,
                    self.df.policy,
                    &self.df.cfg.cleanup,
                );
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // we "succeeded" if another writer cleaned up our data
                let files: Vec<String> = std::fs::read_dir(&self.df.datadir)
                    .map(|rd| {
                        rd.filter_map(|e| e.ok())
                            .map(|e| e.file_name().to_string_lossy().into_owned())
                            .collect()
                    })
                    .unwrap_or_default();
                let results = get_ondisk_files(
                    &files,
                    &self.df.datadir,
                    true,
                    self.df.policy,
                    self.frag_index,
                    None,
                )?;
                if let Some(ts_info) = &results.ts_info {
                    if ts_info.timestamp > *timestamp {
                        return Ok(());
                    }
                }
                if let Some(durable_ts) = results.durable_frag_set_ts {
                    if durable_ts >= *timestamp {
                        return Ok(());
                    }
                }
                Err(DiskFileError::Io(e))
            }
            Err(e) => Err(DiskFileError::Io(e)),
        }
    }

    /// `close()`: remove the temp file when put did not succeed.
    pub fn close(&mut self) {
        self.file = None;
        if let Some(tmppath) = self.tmppath.take() {
            if !self.put_succeeded {
                let _ = std::fs::remove_file(tmppath);
            }
        }
    }
}

impl Drop for DiskFileWriter<'_> {
    fn drop(&mut self) {
        self.close();
    }
}

/// Minimal `BaseDiskFileReader`: sequential chunked reads with the etag
/// and size verification (and quarantine) semantics of the Python
/// reader's close path.
pub struct DiskFileReader {
    fp: Arc<std::fs::File>,
    data_file: PathBuf,
    device_path: PathBuf,
    obj_size: u64,
    etag: String,
    disk_chunk_size: usize,
    bytes_read: u64,
    md5: Option<Md5>,
}

impl DiskFileReader {
    /// Read the next chunk; `None` at EOF.
    pub fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, DiskFileError> {
        let mut buf = vec![0u8; self.disk_chunk_size];
        let n = (&*self.fp).read(&mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        if let Some(md5) = &mut self.md5 {
            md5.update(&buf);
        }
        self.bytes_read += n as u64;
        Ok(Some(buf))
    }

    pub fn read_all(&mut self) -> Result<Vec<u8>, DiskFileError> {
        let mut out = Vec::new();
        while let Some(chunk) = self.next_chunk()? {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// `_handle_close_quarantine`: verify size and etag of a complete
    /// read, quarantining the object on mismatch.
    pub fn close(mut self) -> Result<(), DiskFileError> {
        if self.bytes_read != self.obj_size {
            let msg = format!(
                "Bytes read: {}, does not match metadata: {}",
                self.bytes_read, self.obj_size
            );
            let _ = quarantine_renamer(&self.device_path, &self.data_file);
            return Err(DiskFileError::Quarantined(msg));
        }
        if let Some(md5) = self.md5.take() {
            let computed = format!("{:x}", md5.finalize());
            if computed != self.etag {
                let msg = format!("ETag {} does not match {computed}", self.etag);
                let _ = quarantine_renamer(&self.device_path, &self.data_file);
                return Err(DiskFileError::Quarantined(msg));
            }
        }
        Ok(())
    }

    /// A full-object streaming reader carrying this reader's close-time
    /// verification: the quarantine-on-mismatch side effect fires at
    /// EOF/drop of the stream instead of an explicit `close()` call.
    pub fn into_stream(self) -> DiskFileStreamReader {
        DiskFileStreamReader { inner: Some(self) }
    }

    /// `app_iter_range`: a positional-read window over `[start, stop)` of
    /// the data file, clamped to the object size. Ranged reads skip the
    /// close-time etag/size verification (Python skips
    /// `_handle_close_quarantine` unless the read started at 0 and hit
    /// EOF); windows are independent of the sequential cursor, so several
    /// may serve one multipart/byteranges response.
    pub fn range_window(&self, start: u64, stop: u64) -> DiskFileRangeReader {
        let stop = stop.min(self.obj_size);
        DiskFileRangeReader {
            fp: Arc::clone(&self.fp),
            pos: start.min(stop),
            stop,
        }
    }
}

/// Sequential `Read` with the same md5/byte accounting as
/// [`DiskFileReader::next_chunk`], so `close()` still verifies the full
/// stream.
impl Read for DiskFileReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = (&*self.fp).read(buf)?;
        if n > 0 {
            if let Some(md5) = &mut self.md5 {
                md5.update(&buf[..n]);
            }
            self.bytes_read += n as u64;
        }
        Ok(n)
    }
}

/// Full-object streaming reader: `io::Read` over the data file with the
/// Python reader's close contract. Once the COMPLETE stream has been
/// consumed — the EOF read, or a drop after the final byte — bytes-read
/// and etag are verified against the metadata and the object is
/// quarantined on mismatch, exactly as `read_all` + `close`. A stream
/// dropped before the last byte skips the check (Python's
/// `_started_at_0 and _read_to_eof` close gate: a client disconnect must
/// not quarantine a healthy object).
pub struct DiskFileStreamReader {
    inner: Option<DiskFileReader>,
}

impl Read for DiskFileStreamReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(reader) = self.inner.as_mut() else {
            return Ok(0);
        };
        let n = reader.read(buf)?;
        if n == 0 && !buf.is_empty() {
            // EOF: run the close-time verification exactly once. A short
            // file cannot satisfy the declared Content-Length, so surface
            // an error (the connection aborts rather than under-deliver);
            // an etag mismatch after a byte-complete read is a quarantine
            // side effect only — the bytes already streamed (Python
            // parity: corrupt data is detected post-stream).
            let complete = reader.bytes_read == reader.obj_size;
            let result = self.inner.take().unwrap().close();
            if !complete {
                let msg = match result {
                    Err(e) => e.to_string(),
                    Ok(()) => "short read".to_string(),
                };
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, msg));
            }
        }
        Ok(n)
    }
}

impl Drop for DiskFileStreamReader {
    fn drop(&mut self) {
        if let Some(reader) = self.inner.take() {
            // A consumer that read exactly the declared length may drop the
            // stream without the EOF read; that is still a complete read
            // and must verify. A partial stream is not.
            if reader.bytes_read == reader.obj_size {
                let _ = reader.close();
            }
        }
    }
}

/// A `[start, stop)` window over the data file using positional reads
/// (`pread`), so windows never contend over a shared cursor.
pub struct DiskFileRangeReader {
    fp: Arc<std::fs::File>,
    pos: u64,
    stop: u64,
}

impl Read for DiskFileRangeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.stop.saturating_sub(self.pos);
        if remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let cap = (buf.len() as u64).min(remaining) as usize;
        let n = self.fp.read_at(&mut buf[..cap], self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}
