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

//! Cluster constraints, ported from `swift/common/constraints.py`.
//!
//! Provides the default constraint values, loading of `[swift-constraints]`
//! overrides from `swift.conf`, and the request-independent validation
//! helpers (`check_utf8`, `check_name_format`, `check_drive`, ...).
//!
//! NOTE: the swob-request-coupled checks (`check_metadata`,
//! `check_object_creation`, `check_delete_headers`) will live in the
//! `swift-http` crate once its `Request` type exists, implemented against
//! the [`Constraints`] struct defined here.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::config::{list_from_csv, ConfigError, SwiftConfig};

pub const MAX_FILE_SIZE: i64 = 5368709122;
pub const MAX_META_NAME_LENGTH: i64 = 128;
pub const MAX_META_VALUE_LENGTH: i64 = 256;
pub const MAX_META_COUNT: i64 = 90;
pub const MAX_META_OVERALL_SIZE: i64 = 4096;
pub const MAX_HEADER_SIZE: i64 = 8192;
pub const MAX_REQUEST_LINE: i64 = 8192;
pub const MAX_OBJECT_NAME_LENGTH: i64 = 1024;
pub const CONTAINER_LISTING_LIMIT: i64 = 10000;
pub const ACCOUNT_LISTING_LIMIT: i64 = 10000;
pub const MAX_ACCOUNT_NAME_LENGTH: i64 = 256;
pub const MAX_CONTAINER_NAME_LENGTH: i64 = 256;
pub const VALID_API_VERSIONS: [&str; 2] = ["v1", "v1.0"];
pub const EXTRA_HEADER_COUNT: i64 = 0;
pub const AUTO_CREATE_ACCOUNT_PREFIX: &str = ".";

/// The reserved byte/character used for namespacing (Python
/// `utils.RESERVED_BYTE` / `RESERVED_STR`).
pub const RESERVED_BYTE: u8 = 0x00;
pub const RESERVED_STR: char = '\x00';

/// Error from a constraint check, carrying the same message text that the
/// Python implementation would put in the HTTP response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintError(pub String);

impl fmt::Display for ConstraintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ConstraintError {}

/// Effective cluster constraints: defaults optionally overridden by the
/// `[swift-constraints]` section of `swift.conf`.
///
/// These values are published by the proxy server in `/info` responses,
/// so field names and default values are a compatibility contract.
#[derive(Debug, Clone, PartialEq)]
pub struct Constraints {
    pub max_file_size: i64,
    pub max_meta_name_length: i64,
    pub max_meta_value_length: i64,
    pub max_meta_count: i64,
    pub max_meta_overall_size: i64,
    pub max_header_size: i64,
    pub max_request_line: i64,
    pub max_object_name_length: i64,
    pub container_listing_limit: i64,
    pub account_listing_limit: i64,
    pub max_account_name_length: i64,
    pub max_container_name_length: i64,
    pub valid_api_versions: Vec<String>,
    pub extra_header_count: i64,
    pub auto_create_account_prefix: String,
}

impl Default for Constraints {
    fn default() -> Self {
        Constraints {
            max_file_size: MAX_FILE_SIZE,
            max_meta_name_length: MAX_META_NAME_LENGTH,
            max_meta_value_length: MAX_META_VALUE_LENGTH,
            max_meta_count: MAX_META_COUNT,
            max_meta_overall_size: MAX_META_OVERALL_SIZE,
            max_header_size: MAX_HEADER_SIZE,
            max_request_line: MAX_REQUEST_LINE,
            max_object_name_length: MAX_OBJECT_NAME_LENGTH,
            container_listing_limit: CONTAINER_LISTING_LIMIT,
            account_listing_limit: ACCOUNT_LISTING_LIMIT,
            max_account_name_length: MAX_ACCOUNT_NAME_LENGTH,
            max_container_name_length: MAX_CONTAINER_NAME_LENGTH,
            valid_api_versions: VALID_API_VERSIONS.iter().map(|s| s.to_string()).collect(),
            extra_header_count: EXTRA_HEADER_COUNT,
            auto_create_account_prefix: AUTO_CREATE_ACCOUNT_PREFIX.to_string(),
        }
    }
}

impl Constraints {
    /// Load constraints from a parsed `swift.conf`, applying any
    /// `[swift-constraints]` overrides over the defaults (Python
    /// `reload_constraints`).
    pub fn from_swift_conf(config: &SwiftConfig) -> Result<Self, ConfigError> {
        let mut c = Constraints::default();
        if !config.has_section("swift-constraints") {
            return Ok(c);
        }
        let get_int = |name: &str, target: &mut i64| -> Result<(), ConfigError> {
            if let Some(v) = config.get("swift-constraints", name)? {
                *target = v.trim().parse().map_err(|_| {
                    ConfigError(format!("invalid literal for int() with base 10: {v:?}"))
                })?;
            }
            Ok(())
        };
        get_int("max_file_size", &mut c.max_file_size)?;
        get_int("max_meta_name_length", &mut c.max_meta_name_length)?;
        get_int("max_meta_value_length", &mut c.max_meta_value_length)?;
        get_int("max_meta_count", &mut c.max_meta_count)?;
        get_int("max_meta_overall_size", &mut c.max_meta_overall_size)?;
        get_int("max_header_size", &mut c.max_header_size)?;
        get_int("max_request_line", &mut c.max_request_line)?;
        get_int("max_object_name_length", &mut c.max_object_name_length)?;
        get_int("container_listing_limit", &mut c.container_listing_limit)?;
        get_int("account_listing_limit", &mut c.account_listing_limit)?;
        get_int("max_account_name_length", &mut c.max_account_name_length)?;
        get_int(
            "max_container_name_length",
            &mut c.max_container_name_length,
        )?;
        get_int("extra_header_count", &mut c.extra_header_count)?;
        if let Some(v) = config.get("swift-constraints", "valid_api_versions")? {
            c.valid_api_versions = list_from_csv(&v);
        }
        if let Some(v) = config.get("swift-constraints", "auto_create_account_prefix")? {
            c.auto_create_account_prefix = v;
        }
        Ok(c)
    }

    /// Load constraints from a `swift.conf` file path; missing file yields
    /// the defaults (Python behaviour when `SWIFT_CONF_FILE` is absent).
    pub fn from_swift_conf_path(path: &Path) -> Result<Self, ConfigError> {
        match SwiftConfig::read_path(path, false) {
            Ok(config) => Self::from_swift_conf(&config),
            Err(_) => Ok(Constraints::default()),
        }
    }

    /// Maximum number of allowed headers: max metadata count plus 36 for
    /// Swift-internal and regular HTTP headers, plus any configured
    /// `extra_header_count`.
    pub fn max_header_count(&self) -> i64 {
        self.max_meta_count + 36 + self.extra_header_count.max(0)
    }

    /// Checks if the requested API version is valid (Python
    /// `valid_api_version`).
    pub fn valid_api_version(&self, version: &str) -> bool {
        self.valid_api_versions.iter().any(|v| v == version)
    }
}

/// Validate that a string is non-empty and contains no reserved
/// characters. `internal` allows the reserved (NUL) character.
///
/// A Rust `&str` is UTF-8 with no surrogates by construction, so only the
/// emptiness and reserved-byte checks remain from the Python version.
pub fn check_utf8(string: &str, internal: bool) -> bool {
    if string.is_empty() {
        return false;
    }
    internal || !string.contains(RESERVED_STR)
}

/// Byte-string variant of [`check_utf8`]: additionally requires the bytes
/// to be valid UTF-8 (which in Rust, as in Python 3, rejects encoded
/// surrogate codepoints).
pub fn check_utf8_bytes(bytes: &[u8], internal: bool) -> bool {
    match std::str::from_utf8(bytes) {
        Ok(s) => check_utf8(s, internal),
        Err(_) => false,
    }
}

/// Helper for checking if a string can be converted to a float.
pub fn check_float(string: &str) -> bool {
    string.trim().parse::<f64>().is_ok()
}

/// Check metadata sent in request headers (Python
/// `constraints.check_metadata`). `headers` is an iterator of
/// `(name, value)` pairs in request order; `target_type` is one of
/// `account`, `container`, or `object`.
///
/// Returns `Ok(())` when the metadata is valid, or a [`ConstraintError`]
/// whose message is byte-for-byte the body Python puts in its
/// `HTTPBadRequest` (400) response.
pub fn check_metadata<'a, I>(headers: I, target_type: &str) -> Result<(), ConstraintError>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let target_type = target_type.to_lowercase();
    let prefix = format!("x-{target_type}-meta-");
    let mut meta_count: i64 = 0;
    let mut meta_size: i64 = 0;
    for (key, value) in headers {
        if value.len() as i64 > MAX_HEADER_SIZE {
            let truncated: String = key.chars().take(MAX_META_NAME_LENGTH as usize).collect();
            return Err(ConstraintError(format!(
                "Header value too long: {truncated}"
            )));
        }
        if !key.to_lowercase().starts_with(&prefix) {
            continue;
        }
        // strip the `x-<type>-meta-` prefix; the prefix is pure ASCII so a
        // byte slice at its length is a valid char boundary.
        let key = &key[prefix.len()..];
        if key.is_empty() {
            return Err(ConstraintError("Metadata name cannot be empty".to_string()));
        }
        let bad_key = !check_utf8(key, false);
        let bad_value = !value.is_empty() && !check_utf8(value, false);
        if (target_type == "account" || target_type == "container") && (bad_key || bad_value) {
            return Err(ConstraintError("Metadata must be valid UTF-8".to_string()));
        }
        meta_count += 1;
        // Python 3 `len(str)` is Unicode scalar count, not UTF-8 bytes.
        // Using byte length 400s TestFileUTF8.testMetadataNumberLimit
        // (`uni…` values) before 90 items.
        let key_len = key.chars().count() as i64;
        let value_len = value.chars().count() as i64;
        meta_size += key_len + value_len;
        if key_len > MAX_META_NAME_LENGTH {
            return Err(ConstraintError(format!(
                "Metadata name too long: {prefix}{key}"
            )));
        }
        if value_len > MAX_META_VALUE_LENGTH {
            return Err(ConstraintError(format!(
                "Metadata value longer than {MAX_META_VALUE_LENGTH}: {prefix}{key}"
            )));
        }
        if meta_count > MAX_META_COUNT {
            return Err(ConstraintError(format!(
                "Too many metadata items; max {MAX_META_COUNT}"
            )));
        }
        if meta_size > MAX_META_OVERALL_SIZE {
            return Err(ConstraintError(format!(
                "Total metadata too large; max {MAX_META_OVERALL_SIZE}"
            )));
        }
    }
    Ok(())
}

/// Validate an account or container name from a header; returns the name
/// or an error whose message matches the Python HTTP response body.
pub fn check_name_format<'a>(name: &'a str, target_type: &str) -> Result<&'a str, ConstraintError> {
    if name.is_empty() {
        return Err(ConstraintError(format!(
            "{target_type} name cannot be empty"
        )));
    }
    if name.contains('/') {
        return Err(ConstraintError(format!(
            "{target_type} name cannot contain slashes"
        )));
    }
    Ok(name)
}

/// Validate an account name (Python `check_account_format`).
pub fn check_account_format(name: &str) -> Result<&str, ConstraintError> {
    check_name_format(name, "Account")
}

/// Validate a container name (Python `check_container_format`).
pub fn check_container_format(name: &str) -> Result<&str, ConstraintError> {
    check_name_format(name, "Container")
}

/// True if `drive` survives `urllib.parse.quote_plus` unchanged, i.e.
/// consists only of ASCII alphanumerics and `_ . - ~`.
fn valid_drive_name(drive: &str) -> bool {
    drive
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'~'))
}

/// Validate that `root/drive` is a valid existing directory, optionally
/// requiring it to be a mount point (Python `check_drive`).
pub fn check_drive(
    root: &Path,
    drive: &str,
    mount_check: bool,
) -> Result<PathBuf, ConstraintError> {
    if !valid_drive_name(drive) {
        return Err(ConstraintError(format!(
            "{drive} is not a valid drive name"
        )));
    }
    let path = root.join(drive);
    if mount_check {
        if !ismount(&path) {
            return Err(ConstraintError(format!(
                "{} is not mounted",
                path.display()
            )));
        }
    } else if !path.is_dir() {
        return Err(ConstraintError(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    Ok(path)
}

/// [`check_drive`] without the mount requirement (Python `check_dir`).
pub fn check_dir(root: &Path, drive: &str) -> Result<PathBuf, ConstraintError> {
    check_drive(root, drive, false)
}

/// [`check_drive`] with the mount requirement (Python `check_mount`).
pub fn check_mount(root: &Path, drive: &str) -> Result<PathBuf, ConstraintError> {
    check_drive(root, drive, true)
}

/// Test whether a path is a mount point, swallowing errors (Python
/// `utils.ismount`). Also honours an operator-placed `.ismount` stub file
/// for symlinked or containerized devices.
#[cfg(unix)]
pub fn ismount(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Ok(s1) = std::fs::symlink_metadata(path) else {
        // it doesn't exist -- so not a mount point :-)
        return false;
    };
    if s1.file_type().is_symlink() {
        // a symlink can only be a mount point for swift's purposes if a
        // stubfile marks it as one
        return path.join(".ismount").is_file();
    }
    let Ok(s2) = std::fs::symlink_metadata(path.join("..")) else {
        return false;
    };
    if s1.dev() != s2.dev() {
        // path/.. on a different device as path
        return true;
    }
    if s1.ino() == s2.ino() {
        // path/.. is the same i-node as path
        return true;
    }
    // device/inode checks don't work in some containerized environments;
    // allow an operator-placed stub file
    path.join(".ismount").is_file()
}

#[cfg(not(unix))]
pub fn ismount(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let c = Constraints::default();
        assert_eq!(c.max_file_size, 5368709122);
        assert_eq!(c.max_meta_count, 90);
        assert_eq!(c.max_header_count(), 90 + 36);
        assert_eq!(c.valid_api_versions, vec!["v1", "v1.0"]);
        assert_eq!(c.auto_create_account_prefix, ".");
    }

    #[test]
    fn test_from_swift_conf_overrides() {
        let conf = "\
[swift-hash]
swift_hash_path_suffix = changeme

[swift-constraints]
max_file_size = 1000
max_meta_count = 5
extra_header_count = 10
valid_api_versions = v1, v2
auto_create_account_prefix = !
";
        let config = SwiftConfig::parse(conf, &[], false).unwrap();
        let c = Constraints::from_swift_conf(&config).unwrap();
        assert_eq!(c.max_file_size, 1000);
        assert_eq!(c.max_meta_count, 5);
        assert_eq!(c.max_header_count(), 5 + 36 + 10);
        assert_eq!(c.valid_api_versions, vec!["v1", "v2"]);
        assert_eq!(c.auto_create_account_prefix, "!");
        // untouched values keep defaults
        assert_eq!(c.max_meta_name_length, 128);
        assert!(c.valid_api_version("v2"));
        assert!(!c.valid_api_version("v1.0"));

        // negative extra_header_count doesn't reduce the header count
        let config =
            SwiftConfig::parse("[swift-constraints]\nextra_header_count = -5\n", &[], false)
                .unwrap();
        let c = Constraints::from_swift_conf(&config).unwrap();
        assert_eq!(c.max_header_count(), 90 + 36);

        // bad int errors
        let config =
            SwiftConfig::parse("[swift-constraints]\nmax_file_size = lots\n", &[], false).unwrap();
        assert!(Constraints::from_swift_conf(&config).is_err());

        // no section: all defaults
        let config = SwiftConfig::parse("[swift-hash]\nx = 1\n", &[], false).unwrap();
        assert_eq!(
            Constraints::from_swift_conf(&config).unwrap(),
            Constraints::default()
        );
    }

    #[test]
    fn test_check_utf8() {
        assert!(!check_utf8("", false));
        assert!(!check_utf8("", true));
        assert!(check_utf8("foo", false));
        assert!(check_utf8("空手道", false));
        // reserved NUL is rejected externally, allowed internally
        assert!(!check_utf8("null\0", false));
        assert!(check_utf8("null\0", true));
        // bytes variant: invalid UTF-8 and encoded surrogates rejected
        assert!(check_utf8_bytes("foo".as_bytes(), false));
        assert!(!check_utf8_bytes(&[0xff, 0xfe], false));
        assert!(!check_utf8_bytes(&[0xed, 0xa0, 0xbe], false)); // U+D83E
        assert!(!check_utf8_bytes(b"null\x00", false));
        assert!(check_utf8_bytes(b"null\x00", true));
    }

    #[test]
    fn test_check_float() {
        assert!(check_float("1.5"));
        assert!(check_float("0"));
        assert!(check_float("-1e5"));
        assert!(!check_float("abc"));
        assert!(!check_float(""));
    }

    #[test]
    fn test_check_metadata() {
        // ok: name exactly at the limit, value exactly at the limit
        let name = format!("X-Account-Meta-{}", "k".repeat(128));
        assert!(check_metadata([(name.as_str(), "v")], "account").is_ok());
        let long_val = "k".repeat(256);
        assert!(
            check_metadata([("X-Account-Meta-Too-Long", long_val.as_str())], "account").is_ok()
        );

        // name one over the limit -> 400
        let name = format!("X-Account-Meta-{}", "k".repeat(129));
        assert!(check_metadata([(name.as_str(), "v")], "account")
            .unwrap_err()
            .0
            .starts_with("Metadata name too long:"));

        // value one over the limit -> 400
        let long_val = "k".repeat(257);
        assert_eq!(
            check_metadata(
                [("X-Container-Meta-Too-Long", long_val.as_str())],
                "container"
            )
            .unwrap_err()
            .0,
            "Metadata value longer than 256: x-container-meta-Too-Long"
        );

        // empty metadata name -> 400
        assert_eq!(
            check_metadata([("X-Account-Meta-", "v")], "account")
                .unwrap_err()
                .0,
            "Metadata name cannot be empty"
        );

        // non-meta headers are ignored
        assert!(
            check_metadata([("X-Timestamp", "123"), ("Content-Length", "0")], "account").is_ok()
        );

        // overall size boundary: keys count after the prefix strip
        let val = "k".repeat(256);
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut size = 0i64;
        let mut x = 0;
        while size < (4096 - 4 - 256) {
            size += 4 + 256;
            headers.push((format!("X-Account-Meta-{x:04}"), val.clone()));
            x += 1;
        }
        // just under -> ok
        let under = 4096 - size - 1;
        let mut ok_headers = headers.clone();
        ok_headers.push(("X-Account-Meta-k".to_string(), "v".repeat(under as usize)));
        let pairs: Vec<(&str, &str)> = ok_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert!(check_metadata(pairs, "account").is_ok());
        // just over -> 400
        let mut over_headers = headers;
        over_headers.push((
            "X-Account-Meta-k".to_string(),
            "x".repeat((4096 - size) as usize),
        ));
        let pairs: Vec<(&str, &str)> = over_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            check_metadata(pairs, "account").unwrap_err().0,
            "Total metadata too large; max 4096"
        );

        // Unicode scalar count, not UTF-8 bytes (Python 3 len(str)).
        let cjk = "中".repeat(15); // 15 chars, 45 bytes
        let mut utf8_headers = Vec::new();
        for i in 0..80 {
            utf8_headers.push((format!("X-Object-Meta-{i:02}"), cjk.clone()));
        }
        let pairs: Vec<(&str, &str)> = utf8_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert!(
            check_metadata(pairs, "object").is_ok(),
            "80 CJK values must count as characters, not bytes"
        );
    }

    #[test]
    fn test_check_name_format() {
        assert_eq!(check_account_format("AUTH_test").unwrap(), "AUTH_test");
        assert_eq!(
            check_account_format("").unwrap_err().0,
            "Account name cannot be empty"
        );
        assert_eq!(
            check_container_format("a/b").unwrap_err().0,
            "Container name cannot contain slashes"
        );
    }

    #[test]
    fn test_valid_drive_name() {
        assert!(valid_drive_name("sdb1"));
        assert!(valid_drive_name("d-1_2.3~x"));
        assert!(!valid_drive_name("sd b1"));
        assert!(!valid_drive_name("sdb1/"));
        assert!(!valid_drive_name("sdb+1"));
        assert!(!valid_drive_name("..%2F"));
    }

    #[test]
    fn test_check_drive() {
        let tmp = std::env::temp_dir().join("swift-core-test-check-drive");
        let _ = std::fs::create_dir_all(tmp.join("sdb1"));
        // invalid name rejected before any filesystem access
        assert_eq!(
            check_drive(&tmp, "sd b1", false).unwrap_err().0,
            "sd b1 is not a valid drive name"
        );
        // existing dir passes check_dir
        assert_eq!(check_dir(&tmp, "sdb1").unwrap(), tmp.join("sdb1"));
        // missing dir fails
        assert!(check_dir(&tmp, "nope")
            .unwrap_err()
            .0
            .ends_with("is not a directory"));
        // a plain temp dir is not a mount point
        assert!(check_mount(&tmp, "sdb1")
            .unwrap_err()
            .0
            .ends_with("is not mounted"));
        // ...unless a .ismount stub is present
        std::fs::write(tmp.join("sdb1").join(".ismount"), b"").unwrap();
        assert_eq!(check_mount(&tmp, "sdb1").unwrap(), tmp.join("sdb1"));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
