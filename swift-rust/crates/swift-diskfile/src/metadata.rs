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

//! Object metadata storage: a pickled dict spread across chunked
//! `user.swift.metadata*` xattrs with an md5 checksum attr
//! (`read_metadata` / `write_metadata`).

use std::path::Path;

use md5::{Digest, Md5};
use swift_core::pickle::{self, latin1_decode, Value};

use crate::error::DiskFileError;

pub const METADATA_KEY: &str = "user.swift.metadata";
pub const METADATA_CHECKSUM_KEY: &str = "user.swift.metadata_checksum";
pub const DEFAULT_XATTR_SIZE: usize = 65536;

/// A logical metadata key or value. Python's `str` maps to [`Str`];
/// values that are not valid UTF-8 (Python holds them as
/// surrogate-escaped `str`) map to [`Bytes`] carrying the original
/// octets.
///
/// [`Str`]: MetaValue::Str
/// [`Bytes`]: MetaValue::Bytes
#[derive(Debug, Clone, PartialEq)]
pub enum MetaValue {
    Str(String),
    Bytes(Vec<u8>),
    Int(i64),
}

impl MetaValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            MetaValue::Str(s) => Some(s),
            _ => None,
        }
    }
}

impl From<&str> for MetaValue {
    fn from(s: &str) -> Self {
        MetaValue::Str(s.to_string())
    }
}

/// Object metadata as insertion-ordered pairs (Python dict order matters
/// for byte-identical pickles).
pub type Metadata = Vec<(MetaValue, MetaValue)>;

/// Port of `_encode_metadata`: utf8-encode every string key and value.
pub fn encode_metadata(meta: &Metadata) -> Value {
    fn enc(v: &MetaValue) -> Value {
        match v {
            MetaValue::Str(s) => Value::Bytes(s.as_bytes().to_vec()),
            MetaValue::Bytes(b) => Value::Bytes(b.clone()),
            MetaValue::Int(i) => Value::Int(*i),
        }
    }
    Value::Dict(meta.iter().map(|(k, v)| (enc(k), enc(v))).collect())
}

/// Port of `_decode_metadata`: convert unpickled keys/values to their
/// logical form. `written_by_py3` selects the latin-1 legacy path for old
/// py2-written pickles.
pub fn decode_metadata(value: &Value, written_by_py3: bool) -> Result<Metadata, DiskFileError> {
    let pairs = value.as_dict().ok_or_else(|| {
        DiskFileError::Pickle(pickle::PickleError(format!(
            "metadata pickle is not a dict: {value:?}"
        )))
    })?;

    fn to_meta(v: &Value, written_by_py3: bool, is_name: bool) -> Result<MetaValue, DiskFileError> {
        let v = match v {
            Value::Bytes(b) if !written_by_py3 && !is_name => {
                // do our best to read old py2 data
                return Ok(MetaValue::Str(latin1_decode(b)));
            }
            other => other,
        };
        Ok(match v {
            Value::Bytes(b) => match std::str::from_utf8(b) {
                Ok(s) => MetaValue::Str(s.to_string()),
                // Python surrogate-escapes; we keep the original bytes
                Err(_) => MetaValue::Bytes(b.clone()),
            },
            Value::Str(s) => MetaValue::Str(s.clone()),
            Value::Int(i) => MetaValue::Int(*i),
            other => {
                return Err(DiskFileError::Pickle(pickle::PickleError(format!(
                    "unsupported metadata value: {other:?}"
                ))))
            }
        })
    }

    let mut out = Metadata::with_capacity(pairs.len());
    for (k, v) in pairs {
        let is_name = matches!(k, Value::Bytes(b) if b == b"name")
            || matches!(k, Value::Str(s) if s == "name");
        let key = to_meta(k, written_by_py3, false)?;
        let val = to_meta(v, written_by_py3, is_name)?;
        out.push((key, val));
    }
    Ok(out)
}

/// Deserialize a raw metadata pickle blob, applying the same
/// written-by-py3 sniff as `_read_file_metadata`.
pub fn metadata_from_pickle(blob: &[u8]) -> Result<Metadata, DiskFileError> {
    let sniff = &blob[..blob.len().min(32)];
    let written_by_py3 = sniff
        .windows(b"_codecs\nencode".len())
        .any(|w| w == b"_codecs\nencode");
    let value = pickle::loads(blob)?;
    decode_metadata(&value, written_by_py3)
}

/// Serialize metadata exactly as `pickle.dumps(_encode_metadata(m), 2)`.
pub fn metadata_to_pickle(meta: &Metadata) -> Result<Vec<u8>, DiskFileError> {
    Ok(pickle::dumps(&encode_metadata(meta))?)
}

fn is_enotsup(e: &std::io::Error) -> bool {
    // ENOTSUP/EOPNOTSUPP (95 on Linux, 45 on macOS/BSD)
    matches!(e.raw_os_error(), Some(45) | Some(95))
}

fn chunk_key(index: usize) -> String {
    if index == 0 {
        METADATA_KEY.to_string()
    } else {
        format!("{METADATA_KEY}{index}")
    }
}

/// A file identified by path or by an open descriptor, mirroring
/// Python's fd-or-filename duality in `read_metadata`/`write_metadata`.
pub enum XattrSource<'a> {
    Path(&'a Path),
    File(&'a std::fs::File),
}

impl XattrSource<'_> {
    fn get(&self, name: &str) -> std::io::Result<Option<Vec<u8>>> {
        match self {
            XattrSource::Path(p) => xattr::get(p, name),
            XattrSource::File(f) => {
                use xattr::FileExt;
                f.get_xattr(name)
            }
        }
    }

    fn set(&self, name: &str, value: &[u8]) -> std::io::Result<()> {
        match self {
            XattrSource::Path(p) => xattr::set(p, name, value),
            XattrSource::File(f) => {
                use xattr::FileExt;
                f.set_xattr(name, value)
            }
        }
    }

    fn describe(&self) -> String {
        match self {
            XattrSource::Path(p) => p.display().to_string(),
            XattrSource::File(_) => "<fd>".to_string(),
        }
    }
}

/// Read the raw pickled metadata blob from a file's xattrs, verifying the
/// stored checksum when present (`_read_file_metadata` up to the
/// unpickle).
fn read_metadata_blob(source: &XattrSource<'_>) -> Result<Vec<u8>, DiskFileError> {
    let mut blob = Vec::new();
    for index in 0.. {
        match source.get(&chunk_key(index)) {
            Ok(Some(chunk)) => blob.extend_from_slice(&chunk),
            Ok(None) => break,
            Err(e) if is_enotsup(&e) => return Err(DiskFileError::XattrNotSupported),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(DiskFileError::StateChanged)
            }
            Err(e) => return Err(DiskFileError::Io(e)),
        }
    }
    if let Ok(Some(stored)) = source.get(METADATA_CHECKSUM_KEY) {
        let computed = format!("{:x}", Md5::digest(&blob));
        if stored != computed.as_bytes() {
            return Err(DiskFileError::BadMetadataChecksum(format!(
                "Metadata checksum mismatch for {}: stored checksum={:?}, computed={:?}",
                source.describe(),
                String::from_utf8_lossy(&stored),
                computed
            )));
        }
    }
    Ok(blob)
}

/// `_read_file_metadata`: read and unpickle, raising `StateChanged` when
/// the file has vanished.
pub fn read_file_metadata(source: XattrSource<'_>) -> Result<Metadata, DiskFileError> {
    let blob = read_metadata_blob(&source)?;
    metadata_from_pickle(&blob)
}

/// Port of `read_metadata`: raises `NotExist` when the file has gone.
pub fn read_metadata(path: &Path) -> Result<Metadata, DiskFileError> {
    match read_file_metadata(XattrSource::Path(path)) {
        Err(DiskFileError::StateChanged) => Err(DiskFileError::NotExist),
        other => other,
    }
}

fn write_error(e: std::io::Error) -> DiskFileError {
    if is_enotsup(&e) {
        DiskFileError::XattrNotSupported
    } else if matches!(e.raw_os_error(), Some(28))
        || matches!(e.raw_os_error(), Some(69)) && cfg!(target_os = "macos")
        || matches!(e.raw_os_error(), Some(122)) && cfg!(target_os = "linux")
    {
        // ENOSPC (28), EDQUOT (69 on macOS, 122 on Linux)
        DiskFileError::NoSpace
    } else {
        DiskFileError::Io(e)
    }
}

/// Port of `write_metadata` for a path or an open file: pickle, chunk
/// into `xattr_size`-byte xattrs and store the md5 checksum attr.
pub fn write_file_metadata(
    source: XattrSource<'_>,
    meta: &Metadata,
    xattr_size: usize,
) -> Result<(), DiskFileError> {
    let blob = metadata_to_pickle(meta)?;
    let checksum = format!("{:x}", Md5::digest(&blob));
    for (index, chunk) in blob.chunks(xattr_size.max(1)).enumerate() {
        source.set(&chunk_key(index), chunk).map_err(write_error)?;
    }
    if blob.is_empty() {
        source.set(&chunk_key(0), &[]).map_err(write_error)?;
    }
    source
        .set(METADATA_CHECKSUM_KEY, checksum.as_bytes())
        .map_err(write_error)?;
    Ok(())
}

/// Path-based `write_metadata`.
pub fn write_metadata(
    path: &Path,
    meta: &Metadata,
    xattr_size: usize,
) -> Result<(), DiskFileError> {
    write_file_metadata(XattrSource::Path(path), meta, xattr_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pickle_round_trip() {
        let meta: Metadata = vec![
            ("name".into(), "/a/c/o".into()),
            ("X-Timestamp".into(), "1751500000.00000".into()),
            ("Content-Length".into(), MetaValue::Int(5)),
            (
                "X-Object-Meta-Raw".into(),
                MetaValue::Bytes(vec![0xff, 0xfe, 0x01]),
            ),
        ];
        let blob = metadata_to_pickle(&meta).unwrap();
        assert_eq!(metadata_from_pickle(&blob).unwrap(), meta);
    }

    #[test]
    fn test_xattr_round_trip() {
        let dir = std::env::temp_dir().join(format!("swift-diskfile-meta-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("obj.data");
        std::fs::write(&path, b"body").unwrap();
        let meta: Metadata = vec![
            ("name".into(), "/a/c/o".into()),
            ("X-Object-Meta-Blob".into(), MetaValue::Str("z".repeat(700))),
        ];
        write_metadata(&path, &meta, 254).unwrap();
        assert_eq!(read_metadata(&path).unwrap(), meta);
        // corrupt the checksum: read must fail
        xattr::set(&path, METADATA_CHECKSUM_KEY, b"0000").unwrap();
        assert!(matches!(
            read_metadata(&path),
            Err(DiskFileError::BadMetadataChecksum(_))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_missing_file() {
        assert!(matches!(
            read_metadata(Path::new("/nonexistent/nowhere.data")),
            Err(DiskFileError::NotExist)
        ));
    }
}
