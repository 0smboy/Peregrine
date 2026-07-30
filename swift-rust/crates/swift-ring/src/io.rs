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

//! Ring file I/O, ported from `swift/common/ring/io.py`.
//!
//! Ring files are gzip streams. The uncompressed payload starts with the
//! magic `R1NG` followed by a big-endian u16 format version.
//!
//! - **v1** continues with a `!I`-length-prefixed JSON metadata blob and
//!   the raw `replica2part2dev` rows.
//! - **v2** is a sequence of named sections, each a `!Q`-length-prefixed
//!   blob, with a JSON index written at the end. The final 16 uncompressed
//!   bytes are the index's uncompressed and compressed start offsets.
//!
//! The Python reader carefully streams and seeks between `Z_FULL_FLUSH`
//! boundaries to save memory; because ring files are modest in size, this
//! implementation simply decompresses the whole stream and addresses
//! sections by their *uncompressed* index offsets, which is
//! format-equivalent.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use md5::Md5;
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::RingError;
use swift_core::hashing::hex;

/// An entry in a v2 ring file's section index.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexEntry {
    pub compressed_start: u64,
    pub uncompressed_start: u64,
    pub compressed_end: u64,
    pub uncompressed_end: u64,
    pub checksum_method: String,
    pub checksum_value: String,
}

impl IndexEntry {
    pub fn uncompressed_length(&self) -> u64 {
        self.uncompressed_end - self.uncompressed_start
    }
}

/// A fully decompressed ring file with format version detection and, for
/// v2, the section index (Python `RingReader`).
#[derive(Debug)]
pub struct RingFile {
    /// Ring format version (1 or 2).
    pub version: u16,
    /// The entire uncompressed stream.
    pub data: Vec<u8>,
    /// Compressed (on-disk) size in bytes (Python `RingReader.size`).
    pub size: u64,
    /// Uncompressed size in bytes (Python `RingReader.raw_size`).
    pub raw_size: u64,
    /// v2 section index; empty for v1.
    pub index: HashMap<String, IndexEntry>,
}

fn be_u16(data: &[u8]) -> u16 {
    u16::from_be_bytes([data[0], data[1]])
}

pub(crate) fn be_u32(data: &[u8]) -> u32 {
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

pub(crate) fn be_u64(data: &[u8]) -> u64 {
    u64::from_be_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
}

impl RingFile {
    /// Open and fully decompress a ring file, validating the magic and
    /// loading the v2 index if present.
    pub fn open(path: &Path) -> Result<Self, RingError> {
        let compressed = std::fs::read(path)
            .map_err(|e| RingError(format!("Could not read {}: {e}", path.display())))?;
        Self::from_compressed_bytes(&compressed)
    }

    /// Parse an in-memory gzip'd ring file.
    pub fn from_compressed_bytes(compressed: &[u8]) -> Result<Self, RingError> {
        let mut data = Vec::new();
        flate2::read::GzDecoder::new(compressed)
            .read_to_end(&mut data)
            .map_err(|e| RingError(format!("Could not decompress ring file: {e}")))?;

        if data.len() < 6 || &data[..4] != b"R1NG" {
            return Err(RingError(format!(
                "Bad ring magic: {:?}",
                &data[..data.len().min(4)]
            )));
        }
        let version = be_u16(&data[4..6]);
        if !(1..=2).contains(&version) {
            return Err(RingError(format!("Unsupported ring version: {version}")));
        }

        let mut ring_file = RingFile {
            version,
            size: compressed.len() as u64,
            raw_size: data.len() as u64,
            data,
            index: HashMap::new(),
        };
        ring_file.load_index()?;
        Ok(ring_file)
    }

    /// For v2 rings, load the section index stored at the end of the
    /// file. The final 16 uncompressed bytes are the index blob's
    /// uncompressed start followed by its compressed start.
    fn load_index(&mut self) -> Result<(), RingError> {
        if self.version != 2 {
            return Ok(());
        }
        if self.data.len() < 16 {
            return Err(RingError("Could not read index offset".to_string()));
        }
        let index_start = be_u64(&self.data[self.data.len() - 16..]) as usize;
        let blob = self.read_blob_at(index_start)?;
        let parsed: HashMap<String, Value> = serde_json::from_slice(blob)?;
        for (section, entry) in parsed {
            let arr = entry
                .as_array()
                .filter(|a| a.len() == 6)
                .ok_or_else(|| RingError(format!("Invalid index entry for {section}")))?;
            let num = |i: usize| -> Result<u64, RingError> {
                arr[i]
                    .as_u64()
                    .ok_or_else(|| RingError(format!("Invalid index entry for {section}")))
            };
            self.index.insert(
                section.clone(),
                IndexEntry {
                    compressed_start: num(0)?,
                    uncompressed_start: num(1)?,
                    compressed_end: num(2)?,
                    uncompressed_end: num(3)?,
                    checksum_method: arr[4].as_str().unwrap_or_default().to_string(),
                    checksum_value: arr[5].as_str().unwrap_or_default().to_string(),
                },
            );
        }
        Ok(())
    }

    /// Read a `!Q`-length-prefixed blob at an uncompressed offset.
    fn read_blob_at(&self, offset: usize) -> Result<&[u8], RingError> {
        if offset + 8 > self.data.len() {
            return Err(RingError("Blob offset out of range".to_string()));
        }
        let length = be_u64(&self.data[offset..offset + 8]) as usize;
        let start = offset + 8;
        if start + length > self.data.len() {
            return Err(RingError("Blob extends past end of file".to_string()));
        }
        Ok(&self.data[start..start + length])
    }

    /// Whether a v2 section is present.
    pub fn has_section(&self, section: &str) -> bool {
        self.index.contains_key(section)
    }

    /// Read a v2 section's payload, verifying its length against the
    /// index and its checksum (Python `read_section`/`open_section`).
    pub fn read_section(&self, section: &str) -> Result<&[u8], RingError> {
        if self.index.is_empty() {
            return Err(RingError("No index loaded".to_string()));
        }
        let entry = self
            .index
            .get(section)
            .ok_or_else(|| RingError(format!("No section {section:?} in ring file")))?;
        let start = entry.uncompressed_start as usize;
        let blob = self.read_blob_at(start)?;
        if 8 + blob.len() as u64 != entry.uncompressed_length() {
            return Err(RingError("Inconsistent section size".to_string()));
        }
        // the checksum covers the length prefix as well as the payload
        let checked = &self.data[start..start + 8 + blob.len()];
        let digest = match entry.checksum_method.as_str() {
            "md5" => hex(&Md5::digest(checked)),
            "sha1" => hex(&Sha1::digest(checked)),
            "sha256" => hex(&Sha256::digest(checked)),
            "sha512" => hex(&Sha512::digest(checked)),
            other => {
                return Err(RingError(format!(
                    "Unsupported checksum {}:{} for section {}",
                    other, entry.checksum_value, section
                )))
            }
        };
        if digest != entry.checksum_value {
            return Err(RingError(format!(
                "Hash mismatch in block: {:?} found; {:?} expected",
                digest, entry.checksum_value
            )));
        }
        Ok(blob)
    }
}
