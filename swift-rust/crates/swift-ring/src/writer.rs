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

//! Ring file *writing* (v1 format), the inverse of `io.rs`'s reader and
//! the deferred half of Phase 0. Serializes a [`RingData`] to the
//! gzip'd `R1NG` v1 stream that both this reader and the real Python
//! `RingData` accept: magic + big-endian json length + metadata json +
//! the raw little-endian `replica2part2dev_id` rows.

use std::io::Write;

use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::json;

use crate::ring::RingData;
use crate::RingError;

/// The mtime Python stamps into the gzip header so identical ring data
/// yields identical bytes (`RingData.save` default).
const RING_MTIME: u32 = 1300507380;

impl RingData {
    /// Serialize to the compressed v1 ring bytes.
    pub fn serialize_v1(&self) -> Result<Vec<u8>, RingError> {
        let devs = serde_json::to_value(&self.devs)
            .map_err(|e| RingError(format!("serializing devices: {e}")))?;
        let mut meta = json!({
            "devs": devs,
            "part_shift": self.part_shift,
            "replica_count": self.replica2part2dev_id.len(),
            "byteorder": "little",
        });
        if let Some(version) = self.version {
            meta["version"] = json!(version);
        }
        if let Some(npp) = self.next_part_power {
            meta["next_part_power"] = json!(npp);
        }
        // Python uses json.dumps(sort_keys=True, ensure_ascii=True)
        let json_text = canonical_json(&meta);
        let json_bytes = json_text.into_bytes();

        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(b"R1NG");
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&(json_bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(&json_bytes);
        for row in &self.replica2part2dev_id {
            for &dev_id in row {
                // The v1 format stores device ids as 2-byte LE ('H'); a larger
                // id would silently truncate and map partitions to the wrong
                // device. Rings with >65535 devices need the v2 (4-byte) format.
                if dev_id > u16::MAX as u32 {
                    return Err(RingError(format!(
                        "device id {dev_id} does not fit in the v1 ring format (max {}); use v2",
                        u16::MAX
                    )));
                }
                body.extend_from_slice(&(dev_id as u16).to_le_bytes());
            }
        }

        // gzip with a fixed mtime for reproducibility
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        // flate2's GzEncoder header mtime defaults to 0; we want RING_MTIME
        // to match Python. Rebuild the header manually by wrapping.
        encoder
            .write_all(&body)
            .map_err(|e| RingError(format!("gzip write: {e}")))?;
        let compressed = encoder
            .finish()
            .map_err(|e| RingError(format!("gzip finish: {e}")))?;
        Ok(patch_gzip_mtime(compressed, RING_MTIME))
    }

    /// Write the v1 ring to a `.ring.gz` file.
    pub fn save_v1(&self, path: &std::path::Path) -> Result<(), RingError> {
        let bytes = self.serialize_v1()?;
        std::fs::write(path, bytes).map_err(|e| RingError(e.to_string()))?;
        Ok(())
    }
}

/// Overwrite the 4-byte mtime field (bytes 4..8) of a gzip stream.
fn patch_gzip_mtime(mut data: Vec<u8>, mtime: u32) -> Vec<u8> {
    if data.len() >= 8 {
        data[4..8].copy_from_slice(&mtime.to_le_bytes());
    }
    data
}

/// `json.dumps(obj, sort_keys=True, ensure_ascii=True)` — sorted keys,
/// `, `/`: ` separators, non-ASCII escaped. serde_json sorts nothing and
/// uses compact separators, so build it explicitly.
fn canonical_json(v: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_json_string(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_json_string(k, out);
                out.push_str(": ");
                write_canonical(&map[*k], out);
            }
            out.push('}');
        }
    }
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) > 0x7e => {
                let cp = c as u32;
                if cp > 0xffff {
                    let v = cp - 0x10000;
                    out.push_str(&format!("\\u{:04x}", 0xd800 + (v >> 10)));
                    out.push_str(&format!("\\u{:04x}", 0xdc00 + (v & 0x3ff)));
                } else {
                    out.push_str(&format!("\\u{cp:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
