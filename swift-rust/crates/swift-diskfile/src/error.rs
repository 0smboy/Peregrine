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

use std::fmt;

use swift_core::pickle::PickleError;
use swift_core::timestamp::TimestampError;

/// Errors from the diskfile layer, mirroring the Python exception
/// hierarchy where the distinction is load-bearing.
#[derive(Debug)]
pub enum DiskFileError {
    /// `DiskFileError` on unparseable filenames.
    InvalidFilename(String),
    /// Bad or out-of-range EC fragment index.
    BadFragmentIndex(String),
    /// `DiskFileXattrNotSupported`
    XattrNotSupported,
    /// `DiskFileNotExist`
    NotExist,
    /// `DiskFileStateChanged`
    StateChanged,
    /// `DiskFileBadMetadataChecksum`
    BadMetadataChecksum(String),
    /// `DiskFileNoSpace`
    NoSpace,
    /// `DiskFileDeleted`: a tombstone is the newest state.
    Deleted {
        metadata: crate::metadata::Metadata,
        timestamp: swift_core::Timestamp,
    },
    /// `DiskFileExpired`: X-Delete-At has passed.
    Expired {
        metadata: crate::metadata::Metadata,
    },
    /// `DiskFileCollision`: client path does not match metadata path.
    Collision,
    /// `DiskFileQuarantined`: the object was moved to quarantine.
    Quarantined(String),
    /// `DiskFileNotOpen`
    NotOpen,
    /// The on-disk file search contract was violated (Python raises
    /// `RuntimeError`).
    ContractBroken(String),
    /// `LockTimeout`
    LockTimeout(String),
    Pickle(PickleError),
    Timestamp(TimestampError),
    Io(std::io::Error),
}

impl fmt::Display for DiskFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiskFileError::InvalidFilename(s) => write!(f, "invalid filename: {s}"),
            DiskFileError::BadFragmentIndex(s) => write!(f, "{s}"),
            DiskFileError::XattrNotSupported => write!(f, "filesystem does not support xattr"),
            DiskFileError::NotExist => write!(f, "diskfile does not exist"),
            DiskFileError::StateChanged => write!(f, "diskfile state changed"),
            DiskFileError::BadMetadataChecksum(s) => write!(f, "{s}"),
            DiskFileError::NoSpace => write!(f, "no space left on device"),
            DiskFileError::Deleted { timestamp, .. } => {
                write!(f, "diskfile deleted at {}", timestamp.internal())
            }
            DiskFileError::Expired { .. } => write!(f, "diskfile expired"),
            DiskFileError::Collision => write!(
                f,
                "Client path does not match path stored in object metadata"
            ),
            DiskFileError::Quarantined(msg) => write!(f, "quarantined: {msg}"),
            DiskFileError::NotOpen => write!(f, "diskfile not open"),
            DiskFileError::ContractBroken(s) => {
                write!(f, "on-disk file search algorithm contract is broken: {s}")
            }
            DiskFileError::LockTimeout(s) => write!(f, "lock timeout: {s}"),
            DiskFileError::Pickle(e) => write!(f, "{e}"),
            DiskFileError::Timestamp(e) => write!(f, "{e}"),
            DiskFileError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DiskFileError {}

impl From<PickleError> for DiskFileError {
    fn from(e: PickleError) -> Self {
        DiskFileError::Pickle(e)
    }
}

impl From<TimestampError> for DiskFileError {
    fn from(e: TimestampError) -> Self {
        DiskFileError::Timestamp(e)
    }
}

impl From<std::io::Error> for DiskFileError {
    fn from(e: std::io::Error) -> Self {
        DiskFileError::Io(e)
    }
}
