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

//! The drive-audit log scanner, ported from `swift/cli/drive_audit.py`.
//!
//! drive-audit reads the kernel log for I/O errors and, when a device
//! crosses an error threshold, unmounts it so Swift stops writing to failing
//! hardware. This module ports the error-counting core: apply Python's two
//! default regexes to each log line and tally errors per device. Python's
//! defaults are:
//!
//! ```text
//! \berror\b.*\b(sd[a-z]{1,2}\d?)\b     # error ... device
//! \b(sd[a-z]{1,2}\d?)\b.*\berror\b     # device ... error
//! ```
//!
//! We reproduce these without a regex engine: a token matches
//! `sd[a-z]{1,2}\d?` structurally, and a line is scanned for the word
//! `error` on either side of such a token. Deferred: the log-rotation file
//! discovery, reverse-time reading, the timestamp window, and the actual
//! unmount / fstab edit (this is the pure detection core the daemon drives).

use std::collections::BTreeMap;

/// Whether `tok` matches the device pattern `sd[a-z]{1,2}\d?`:
/// `sd`, then one or two lowercase letters, then an optional single digit.
pub fn is_device_token(tok: &str) -> bool {
    let b = tok.as_bytes();
    if b.len() < 3 || &b[0..2] != b"sd" {
        return false;
    }
    let mut i = 2;
    let mut letters = 0;
    while i < b.len() && b[i].is_ascii_lowercase() {
        letters += 1;
        i += 1;
    }
    if !(1..=2).contains(&letters) {
        return false;
    }
    // optional single trailing digit, then end
    if i < b.len() {
        if b[i].is_ascii_digit() && i + 1 == b.len() {
            return true;
        }
        return false;
    }
    true
}

/// Split a line into `\b`-delimited tokens with their byte offsets. A token
/// is a maximal run of `[A-Za-z0-9_]` (Python's `\w`, so `\b` boundaries).
fn word_tokens(line: &str) -> Vec<(usize, &str)> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
            {
                i += 1;
            }
            out.push((start, &line[start..i]));
        } else {
            i += 1;
        }
    }
    out
}

/// Count device errors on one line per Python's two regexes.
/// Returns each `(device, times_counted)` where a device is counted once for
/// each ordering (error→device, device→error) that matches — reproducing the
/// two-regex `findall` tally for the common single-occurrence line.
fn line_errors(line: &str, tally: &mut BTreeMap<String, u64>) {
    let toks = word_tokens(line);
    let error_positions: Vec<usize> = toks
        .iter()
        .filter(|(_, t)| *t == "error")
        .map(|(p, _)| *p)
        .collect();
    if error_positions.is_empty() {
        return;
    }
    let devices: Vec<(usize, &str)> = toks
        .iter()
        .filter(|(_, t)| is_device_token(t))
        .map(|(p, t)| (*p, *t))
        .collect();
    if devices.is_empty() {
        return;
    }
    let first_error = *error_positions.first().unwrap();
    let last_error = *error_positions.last().unwrap();

    // regex1: `\berror\b.*(sd..)` — greedy `.*` captures the LAST device that
    // appears after some error.
    if let Some((_, dev)) = devices.iter().rev().find(|(p, _)| *p > first_error) {
        *tally.entry(dev.to_string()).or_insert(0) += 1;
    }
    // regex2: `(sd..).*\berror\b` — the FIRST device that appears before some
    // error.
    if let Some((_, dev)) = devices.iter().find(|(p, _)| *p < last_error) {
        *tally.entry(dev.to_string()).or_insert(0) += 1;
    }
}

/// Tally drive errors across log lines. Returns device -> error count.
pub fn count_drive_errors<'a>(lines: impl IntoIterator<Item = &'a str>) -> BTreeMap<String, u64> {
    let mut tally = BTreeMap::new();
    for line in lines {
        line_errors(line, &mut tally);
    }
    tally
}

/// Devices whose error count reached `error_limit` (candidates to unmount).
pub fn devices_over_limit(tally: &BTreeMap<String, u64>, error_limit: u64) -> Vec<String> {
    tally
        .iter()
        .filter(|(_, &c)| c >= error_limit)
        .map(|(d, _)| d.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_device_token() {
        assert!(is_device_token("sda"));
        assert!(is_device_token("sdb1"));
        assert!(is_device_token("sdaa"));
        assert!(is_device_token("sdab2"));
        assert!(!is_device_token("sd")); // needs >= 1 letter
        assert!(!is_device_token("sdabc")); // 3 letters
        assert!(!is_device_token("sda12")); // two digits
        assert!(!is_device_token("hda")); // wrong prefix
        assert!(!is_device_token("xsda")); // must start with sd
    }

    #[test]
    fn test_error_before_device() {
        let line = "Nov 1 12:00:00 host kernel: end_request: I/O error, dev sda, sector 42";
        let t = count_drive_errors([line]);
        assert_eq!(t.get("sda"), Some(&1), "{t:?}");
    }

    #[test]
    fn test_device_before_error() {
        let line = "Nov 1 12:00:00 host kernel: sdb1: rw=0, want=1, error -5";
        let t = count_drive_errors([line]);
        assert_eq!(t.get("sdb1"), Some(&1), "{t:?}");
    }

    #[test]
    fn test_no_error_word_ignored() {
        let line = "Nov 1 12:00:00 host kernel: sda: attached scsi disk";
        let t = count_drive_errors([line]);
        assert!(t.is_empty(), "{t:?}");
    }

    #[test]
    fn test_accumulates_and_limit() {
        let lines = [
            "kernel: I/O error dev sda",
            "kernel: I/O error dev sda",
            "kernel: I/O error dev sdc",
        ];
        let t = count_drive_errors(lines);
        assert_eq!(t.get("sda"), Some(&2));
        assert_eq!(t.get("sdc"), Some(&1));
        assert_eq!(devices_over_limit(&t, 2), vec!["sda".to_string()]);
    }
}
