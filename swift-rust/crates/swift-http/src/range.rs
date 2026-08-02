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

//! `swob.Range`, `swob.Match`, `normalize_etag` and the Content-Range
//! header value, with swob's exact validation quirks.

const MAX_RANGES: usize = 50;
const MAX_RANGE_OVERLAPS: usize = 2;
const MAX_NONASCENDING_RANGES: usize = 8;

/// A parsed `Range` header: a list of `(start, end)` options where the
/// header's inclusive-end semantics are preserved as swob does.
#[derive(Debug, Clone, PartialEq)]
pub struct Range {
    pub ranges: Vec<(Option<u64>, Option<u64>)>,
}

/// Python `int()` for range bounds: optional whitespace-free sign plus
/// digits (underscores allowed between digits).
fn py_int_str(s: &str) -> Option<i64> {
    let s = s.trim();
    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    if digits.is_empty() {
        return None;
    }
    let mut value: i64 = 0;
    let mut prev_underscore = true;
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
        return None;
    }
    Some(if neg { -value } else { value })
}

impl Range {
    /// Port of `swob.Range.__init__`; `Err` means the header must be
    /// ignored per the RFC.
    pub fn parse(headerval: &str) -> Result<Range, String> {
        let err = || format!("Invalid Range header: {headerval}");
        if headerval.is_empty() {
            return Err(err());
        }
        let headerval = headerval.replace(' ', "");
        if !headerval.to_lowercase().starts_with("bytes=") {
            return Err(err());
        }
        let mut ranges = Vec::new();
        for rng in headerval[6..].split(',') {
            let Some((start_s, end_s)) = rng.split_once('-') else {
                return Err(err());
            };
            let start = if !start_s.is_empty() {
                match py_int_str(start_s) {
                    // a negative start would have produced a second '-';
                    // int() semantics reject junk
                    Some(v) if v >= 0 => Some(v as u64),
                    Some(_) => return Err(err()),
                    None => return Err(err()),
                }
            } else {
                None
            };
            let end = if !end_s.is_empty() {
                // swob checks isdigit() explicitly to catch things like
                // '--0'
                if !end_s.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(err());
                }
                let end: u64 = end_s.parse().map_err(|_| err())?;
                if let Some(start) = start {
                    if end < start {
                        return Err(err());
                    }
                }
                Some(end)
            } else {
                if start.is_none() {
                    return Err(err());
                }
                None
            };
            ranges.push((start, end));
        }
        Ok(Range { ranges })
    }

    /// `swob.Range.__str__`.
    pub fn to_header(&self) -> String {
        let mut out = String::from("bytes=");
        for (i, (start, end)) in self.ranges.iter().enumerate() {
            if let Some(start) = start {
                out.push_str(&start.to_string());
            }
            out.push('-');
            if let Some(end) = end {
                out.push_str(&end.to_string());
            }
            if i < self.ranges.len() - 1 {
                out.push(',');
            }
        }
        out
    }

    /// Port of `ranges_for_length`: `None` means ignore the header (200
    /// response), an empty vec means unsatisfiable (416), otherwise the
    /// exclusive-end ranges to serve (206).
    pub fn ranges_for_length(&self, length: Option<u64>) -> Option<Vec<(u64, u64)>> {
        let length = length?;
        if self.ranges.is_empty() {
            return None;
        }
        let mut all_ranges: Vec<(u64, u64)> = Vec::new();
        for &(begin, end) in &self.ranges {
            match begin {
                None => {
                    let end = end.unwrap(); // parse guarantees Some
                    if end == 0 {
                        continue; // the bytes=-0 case
                    } else if end > length {
                        all_ranges.push((0, length));
                    } else {
                        all_ranges.push((length - end, length));
                    }
                }
                Some(begin) => match end {
                    None => {
                        if begin < length {
                            all_ranges.push((begin, length));
                        }
                    }
                    Some(end) => {
                        if begin < length {
                            all_ranges.push((begin, (end + 1).min(length)));
                        }
                    }
                },
            }
        }
        if all_ranges.len() > MAX_RANGES {
            return Some(Vec::new());
        }
        let mut overlaps = 0usize;
        for i in 0..all_ranges.len() {
            for j in (i + 1)..all_ranges.len() {
                let (start1, end1) = all_ranges[i];
                let (start2, end2) = all_ranges[j];
                if (start1 < start2 && start2 < end1)
                    || (start1 < end2 && end2 < end1)
                    || (start2 < start1 && start1 < end2)
                    || (start2 < end1 && end1 < end2)
                {
                    overlaps += 1;
                    if overlaps > MAX_RANGE_OVERLAPS {
                        return Some(Vec::new());
                    }
                }
            }
        }
        let ascending = all_ranges.windows(2).all(|w| w[0] <= w[1]);
        if !ascending && all_ranges.len() >= MAX_NONASCENDING_RANGES {
            return Some(Vec::new());
        }
        Some(all_ranges)
    }
}

/// `swob.normalize_etag`.
pub fn normalize_etag(tag: &str) -> &str {
    if tag.len() >= 2 && tag.starts_with('"') && tag.ends_with('"') {
        &tag[1..tag.len() - 1]
    } else {
        tag
    }
}

/// `swob.Match`: the If-Match / If-None-Match tag set.
#[derive(Debug, Clone)]
pub struct Match {
    pub tags: Vec<String>,
}

impl Match {
    pub fn parse(headerval: &str) -> Match {
        let mut tags: Vec<String> = Vec::new();
        for tag in headerval.split(',') {
            let tag = tag.trim();
            if tag.is_empty() {
                continue;
            }
            let tag = normalize_etag(tag).to_string();
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
        Match { tags }
    }

    pub fn matches(&self, val: &str) -> bool {
        self.tags.iter().any(|t| t == "*")
            || self.tags.iter().any(|t| t == normalize_etag(val))
    }
}

/// `swob.content_range_header_value` (exclusive `stop`).
pub fn content_range_header_value(start: u64, stop: u64, size: u64) -> String {
    format!("bytes {start}-{}/{size}", stop - 1)
}

/// The `Content-Type` for a multi-range 206 response.
pub fn multipart_byteranges_content_type(boundary: &str) -> String {
    format!("multipart/byteranges;boundary={boundary}")
}

/// Build a `multipart/byteranges` body for a multi-range 206 response, byte
/// for byte as swob's `multi_range_iterator`: for each `(start, stop)`
/// (exclusive stop) a `--<boundary>` part with `Content-Type` and
/// `Content-Range` headers and the range's bytes, then a `--<boundary>--`
/// terminator.
pub fn multipart_byteranges(
    boundary: &str,
    ranges: &[(u64, u64)],
    body: &[u8],
    content_type: &str,
    size: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    for &(start, stop) in ranges {
        out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        // Current OpenStack Swift emits the header name in each part
        // (`Content-Range: bytes …`); older swob omitted the name.
        out.extend_from_slice(
            format!(
                "Content-Range: {}\r\n\r\n",
                content_range_header_value(start, stop, size)
            )
            .as_bytes(),
        );
        out.extend_from_slice(&body[start as usize..stop as usize]);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{boundary}--").as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match() {
        let m = Match::parse("\"abc\", def, ");
        assert!(m.matches("abc"));
        assert!(m.matches("\"def\""));
        assert!(!m.matches("ghi"));
        assert!(Match::parse("*").matches("anything"));
    }

    #[test]
    fn test_normalize_etag() {
        assert_eq!(normalize_etag("\"abc\""), "abc");
        assert_eq!(normalize_etag("abc"), "abc");
        assert_eq!(normalize_etag("\""), "\"");
    }

    #[test]
    fn test_multipart_byteranges_matches_python() {
        let body = b"0123456789";
        let out = multipart_byteranges("BOUND", &[(0, 3), (5, 8)], body, "text/plain", 10);
        // byte-identical to swob's multi_range_iterator
        let expected: &[u8] = b"--BOUND\r\nContent-Type: text/plain\r\nContent-Range: bytes 0-2/10\r\n\r\n012\r\n\
                                --BOUND\r\nContent-Type: text/plain\r\nContent-Range: bytes 5-7/10\r\n\r\n567\r\n\
                                --BOUND--";
        assert_eq!(out, expected);
        assert_eq!(
            multipart_byteranges_content_type("BOUND"),
            "multipart/byteranges;boundary=BOUND"
        );
    }

    #[test]
    fn test_content_range() {
        assert_eq!(content_range_header_value(0, 5, 10), "bytes 0-4/10");
    }
}
