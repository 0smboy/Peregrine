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

//! On-disk object filename encoding and parsing
//! (`parse_on_disk_filename` / `make_on_disk_filename`).

use swift_core::timestamp::{decode_timestamps, encode_timestamps, Timestamp};

use crate::error::DiskFileError;

/// Which diskfile manager's filename rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    Replication,
    /// `n_unique_fragments` bounds valid fragment indexes when known
    /// (`ec_ndata + ec_nparity`); `None` skips the upper-bound check,
    /// matching Python's `policy=None`.
    Ec {
        n_unique_fragments: Option<u32>,
    },
}

/// Parsed info for one on-disk file, the Rust form of the dicts returned
/// by `parse_on_disk_filename` (with the filename added, as
/// `get_ondisk_files` does).
#[derive(Debug, Clone, PartialEq)]
pub struct FileInfo {
    pub timestamp: Timestamp,
    /// Extension including the leading dot, or empty.
    pub ext: String,
    pub ctype_timestamp: Option<Timestamp>,
    pub frag_index: Option<i64>,
    /// `Some` only for EC data files; consumers default missing values to
    /// `true`, mirroring Python's `.get('durable', True)`.
    pub durable: Option<bool>,
    pub filename: String,
}

/// `os.path.splitext` semantics for a bare filename: the extension starts
/// at the last dot, unless every preceding character is a dot.
pub fn splitext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if name[..i].bytes().any(|b| b != b'.') => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

/// Python `int(str(x))` semantics for the ASCII inputs fragment indexes
/// can contain: optional surrounding whitespace, an optional sign, digits
/// with single interior underscores.
pub(crate) fn python_int(s: &str) -> Option<i64> {
    let s = s.trim();
    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    let mut prev_underscore = true; // leading underscore is invalid
    for c in digits.chars() {
        if c == '_' {
            if prev_underscore {
                return None;
            }
            prev_underscore = true;
            continue;
        }
        let d = c.to_digit(10)? as i64;
        value = value.checked_mul(10)?.checked_add(d)?;
        prev_underscore = false;
    }
    if prev_underscore {
        return None; // trailing underscore
    }
    Some(if neg { -value } else { value })
}

/// Port of `ECDiskFileManager.validate_fragment_index`.
fn validate_fragment_index(
    raw: Option<&str>,
    n_unique_fragments: Option<u32>,
) -> Result<i64, DiskFileError> {
    let frag_index = raw.and_then(python_int).ok_or_else(|| {
        DiskFileError::BadFragmentIndex(format!("Bad fragment index: {}", raw.unwrap_or("None")))
    })?;
    if frag_index < 0 {
        return Err(DiskFileError::BadFragmentIndex(format!(
            "Fragment index must not be negative: {frag_index}"
        )));
    }
    if let Some(n) = n_unique_fragments {
        if frag_index >= n as i64 {
            return Err(DiskFileError::BadFragmentIndex(format!(
                "Fragment index must be less than {n}: {frag_index}"
            )));
        }
    }
    Ok(frag_index)
}

/// Parse an on-disk file name under the given policy's rules.
pub fn parse_ondisk_filename(
    filename: &str,
    policy: PolicyKind,
) -> Result<FileInfo, DiskFileError> {
    let (fname, ext) = splitext(filename);
    if let PolicyKind::Ec { n_unique_fragments } = policy {
        if ext == ".data" {
            let parts: Vec<&str> = fname.split('#').collect();
            let timestamp: Timestamp = parts[0].parse().map_err(|_| {
                DiskFileError::InvalidFilename(format!(
                    "Invalid Timestamp value in filename {filename:?}"
                ))
            })?;
            let frag_index = validate_fragment_index(parts.get(1).copied(), n_unique_fragments)?;
            let durable = parts.get(2) == Some(&"d");
            return Ok(FileInfo {
                timestamp,
                ext: ext.to_string(),
                ctype_timestamp: None,
                frag_index: Some(frag_index),
                durable: Some(durable),
                filename: filename.to_string(),
            });
        }
    }
    let (timestamp, ctype_timestamp) = if ext == ".meta" {
        let (t, tc, _) = decode_timestamps(fname, true).map_err(|_| {
            DiskFileError::InvalidFilename(format!(
                "Invalid Timestamp value in filename {filename:?}"
            ))
        })?;
        (t, tc)
    } else {
        let t: Timestamp = fname.parse().map_err(|_| {
            DiskFileError::InvalidFilename(format!(
                "Invalid Timestamp value in filename {filename:?}"
            ))
        })?;
        (t, None)
    };
    Ok(FileInfo {
        timestamp,
        ext: ext.to_string(),
        ctype_timestamp,
        frag_index: None,
        durable: None,
        filename: filename.to_string(),
    })
}

/// Port of `BaseDiskFileManager.make_on_disk_filename`.
pub fn make_ondisk_filename(
    timestamp: &Timestamp,
    ext: Option<&str>,
    ctype_timestamp: Option<&Timestamp>,
) -> String {
    let mut rv = timestamp.internal();
    if ext == Some(".meta") {
        if let Some(tc) = ctype_timestamp {
            rv = encode_timestamps(timestamp, Some(tc), None, true);
        }
    }
    if let Some(ext) = ext {
        rv.push_str(ext);
    }
    rv
}

/// Port of `ECDiskFileManager.make_on_disk_filename` for `.data` files.
pub fn make_ec_ondisk_filename(
    timestamp: &Timestamp,
    frag_index: i64,
    durable: bool,
) -> Result<String, DiskFileError> {
    let frag_index = validate_fragment_index(Some(&frag_index.to_string()), None)?;
    let mut rv = format!("{}#{}", timestamp.internal(), frag_index);
    if durable {
        rv.push_str("#d");
    }
    rv.push_str(".data");
    Ok(rv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_splitext() {
        assert_eq!(splitext("1751.data"), ("1751", ".data"));
        assert_eq!(splitext("no-ext"), ("no-ext", ""));
        assert_eq!(splitext(".meta"), (".meta", ""));
        assert_eq!(splitext("..data"), ("..data", ""));
        assert_eq!(splitext(".1234.data"), (".1234", ".data"));
        assert_eq!(splitext("a."), ("a", "."));
    }

    #[test]
    fn test_python_int() {
        assert_eq!(python_int("3"), Some(3));
        assert_eq!(python_int(" 3 "), Some(3));
        assert_eq!(python_int("+3"), Some(3));
        assert_eq!(python_int("-1"), Some(-1));
        assert_eq!(python_int("1_0"), Some(10));
        assert_eq!(python_int("_1"), None);
        assert_eq!(python_int("1_"), None);
        assert_eq!(python_int("1__0"), None);
        assert_eq!(python_int(""), None);
        assert_eq!(python_int("x"), None);
    }

    #[test]
    fn test_ec_frag_upper_bound() {
        let policy = PolicyKind::Ec {
            n_unique_fragments: Some(6),
        };
        assert!(parse_ondisk_filename("1751500001.00000#5.data", policy).is_ok());
        assert!(matches!(
            parse_ondisk_filename("1751500001.00000#6.data", policy),
            Err(DiskFileError::BadFragmentIndex(_))
        ));
        // extra parts after the durable marker are tolerated, as in Python
        let info = parse_ondisk_filename("1751500001.00000#3#d#x.data", policy).unwrap();
        assert_eq!(info.durable, Some(true));
        let info = parse_ondisk_filename("1751500001.00000#3#x.data", policy).unwrap();
        assert_eq!(info.durable, Some(false));
    }

    #[test]
    fn test_make_filenames() {
        let t1: Timestamp = "1751500001.00000".parse().unwrap();
        let t2: Timestamp = "1751500002.00000".parse().unwrap();
        assert_eq!(
            make_ondisk_filename(&t1, Some(".ts"), None),
            "1751500001.00000.ts"
        );
        assert_eq!(
            make_ondisk_filename(&t1, Some(".meta"), Some(&t2)),
            "1751500001.00000+186a0.meta"
        );
        assert_eq!(
            make_ec_ondisk_filename(&t1, 3, true).unwrap(),
            "1751500001.00000#3#d.data"
        );
    }
}
