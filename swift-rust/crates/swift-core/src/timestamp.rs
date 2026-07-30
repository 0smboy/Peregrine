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

//! Timestamp handling, ported from `swift/common/utils/timestamp.py`.
//!
//! All string representations produced here are byte-identical with the
//! Python implementation so that Rust and Python daemons can share on-disk
//! state (datafile names, container DB rows) and wire headers (X-Timestamp,
//! X-Backend-Timestamp).

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Number of hex digits in the offset ("hex part") of the internal format.
pub const HEX_PART_DIGITS: usize = 16;

/// Maximum offset value: `16**16 - 1`, i.e. `u64::MAX`.
pub const MAX_OFFSET: u64 = u64::MAX;

/// Precision of a timestamp in seconds (one deca-microsecond).
pub const PRECISION: f64 = 1e-5;

/// Maximum raw time value (raw time has units of `PRECISION`).
/// Corresponds to the exclusive upper bound of 10_000_000_000.0 seconds.
pub const MAX_RAW_TIME: i64 = 999_999_999_999_999;

/// Errors that can occur constructing or parsing a [`Timestamp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampError {
    /// The timestamp value is negative.
    Negative,
    /// The timestamp value is >= 10000000000 seconds.
    TooLarge,
    /// The value could not be parsed.
    Parse(String),
    /// A delta would make the raw time negative.
    DeltaTooSmall(i64),
    /// The offset overflowed `MAX_OFFSET`.
    OffsetOverflow,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimestampError::Negative => write!(f, "timestamp cannot be negative"),
            TimestampError::TooLarge => write!(f, "timestamp too large"),
            TimestampError::Parse(s) => write!(f, "could not parse timestamp: {s}"),
            TimestampError::DeltaTooSmall(min) => {
                write!(f, "delta must be greater than {min}")
            }
            TimestampError::OffsetOverflow => {
                write!(f, "offset must be less than or equal to {MAX_OFFSET}")
            }
        }
    }
}

impl std::error::Error for TimestampError {}

/// Round half-to-even, matching Python's built-in `round()`.
fn round_half_even(x: f64) -> f64 {
    let t = x.trunc();
    let diff = x - t;
    if diff.abs() == 0.5 {
        // exact tie: round to even
        if (t as i64) % 2 == 0 {
            t
        } else {
            t + diff.signum()
        }
    } else {
        x.round()
    }
}

/// A `Timestamp` uniquely identifies resources in Swift. It is the Rust
/// counterpart of `swift.common.utils.timestamp.Timestamp`.
///
/// The internalized form is a fixed-width float part (seconds since the
/// epoch at deca-microsecond precision) optionally followed by a 16-digit
/// hex offset, e.g.:
///
/// ```text
/// 1402464677.04188_0000000000000001
/// <  float secs  >_<    offset    >
/// ```
///
/// When the offset is zero the hex part is omitted from the internalized
/// form. Ordering and equality are defined over `(raw, offset)`, which is
/// identical to lexicographic ordering of the internalized strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp {
    // NOTE: field order matters for the derived Ord/PartialOrd.
    raw: i64,
    offset: u64,
}

impl Timestamp {
    /// Construct from a raw deca-microsecond count and offset, validating
    /// bounds.
    pub fn from_parts(raw: i64, offset: u64) -> Result<Self, TimestampError> {
        if raw < 0 {
            return Err(TimestampError::Negative);
        }
        if raw > MAX_RAW_TIME {
            return Err(TimestampError::TooLarge);
        }
        Ok(Timestamp { raw, offset })
    }

    /// Construct from seconds since the epoch, rounding to the nearest
    /// deca-microsecond exactly as Python does.
    pub fn from_secs(secs: f64) -> Result<Self, TimestampError> {
        Self::from_secs_offset(secs, 0)
    }

    /// Construct from seconds since the epoch with an offset.
    pub fn from_secs_offset(secs: f64, offset: u64) -> Result<Self, TimestampError> {
        if !secs.is_finite() {
            return Err(TimestampError::Parse(format!("{secs}")));
        }
        let raw = round_half_even(secs / PRECISION);
        // guard the cast before bounds-checking
        if !(-9.3e18..=9.3e18).contains(&raw) {
            return Err(TimestampError::TooLarge);
        }
        Self::from_parts(raw as i64, offset)
    }

    /// A `Timestamp` for the current time.
    pub fn now() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs_f64();
        Self::from_secs(secs).expect("current time out of Timestamp bounds")
    }

    /// The smallest possible `Timestamp`.
    pub const fn zero() -> Self {
        Timestamp { raw: 0, offset: 0 }
    }

    /// Raw time in deca-microseconds since the epoch.
    pub const fn raw(&self) -> i64 {
        self.raw
    }

    /// The internal offset vector.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Seconds since the epoch as a float (Python `float(ts)`).
    pub fn as_secs_f64(&self) -> f64 {
        self.raw as f64 * PRECISION
    }

    /// Python truthiness: false only for the zero timestamp with no offset.
    pub const fn is_truthy(&self) -> bool {
        self.raw != 0 || self.offset != 0
    }

    /// Apply a deca-microsecond delta, returning a new `Timestamp`.
    pub fn apply_delta(&self, delta: i64) -> Result<Self, TimestampError> {
        if delta == 0 {
            return Ok(*self);
        }
        let raw = self
            .raw
            .checked_add(delta)
            .ok_or(TimestampError::TooLarge)?;
        if raw < 0 {
            return Err(TimestampError::DeltaTooSmall(-self.raw - 1));
        }
        Self::from_parts(raw, self.offset)
    }

    /// Increment the offset by `value`.
    pub fn increment_offset(&mut self, value: u64) -> Result<u64, TimestampError> {
        self.offset = self
            .offset
            .checked_add(value)
            .ok_or(TimestampError::OffsetOverflow)?;
        Ok(self.offset)
    }

    /// The normalized string representation of the float part, e.g.
    /// `"1402464677.04188"` (Python `%016.05f`).
    pub fn normal(&self) -> String {
        let secs = self.raw / 100_000;
        let frac = self.raw % 100_000;
        format!("{secs:010}.{frac:05}")
    }

    /// The canonical internalized string representation. Includes the hex
    /// part only when the offset is non-zero.
    pub fn internal(&self) -> String {
        if self.offset != 0 {
            format!("{}_{:016x}", self.normal(), self.offset)
        } else {
            self.normal()
        }
    }

    /// Like [`internal`](Self::internal) but with an unpadded hex part.
    pub fn short(&self) -> String {
        if self.offset != 0 {
            format!("{}_{:x}", self.normal(), self.offset)
        } else {
            self.normal()
        }
    }

    /// Clone of this timestamp with the offset dropped.
    pub fn normalized(&self) -> Self {
        Timestamp {
            raw: self.raw,
            offset: 0,
        }
    }

    /// The float part rounded up to the nearest whole second, as used for
    /// Last-Modified times.
    pub fn ceil(&self) -> i64 {
        (self.raw + 99_999) / 100_000
    }

    /// Bitwise-invert (Python `~ts`), used to sort timestamps in reverse.
    pub fn invert(&self) -> Self {
        if self.offset == 0 {
            Timestamp {
                raw: MAX_RAW_TIME - self.raw,
                offset: 0,
            }
        } else {
            Timestamp {
                raw: MAX_RAW_TIME - self.raw - 1,
                offset: MAX_OFFSET - self.offset + 1,
            }
        }
    }

    /// Isoformat string of the normal part with microsecond precision and
    /// no timezone, e.g. `1970-01-01T00:00:00.000000`.
    pub fn isoformat(&self) -> String {
        let secs = self.raw.div_euclid(100_000);
        let micros = (self.raw.rem_euclid(100_000)) * 10;
        let days = secs.div_euclid(86_400);
        let sod = secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{micros:06}")
    }

    /// Parse an isoformat string (as produced by [`isoformat`](Self::isoformat))
    /// into a `Timestamp`.
    pub fn from_isoformat(s: &str) -> Result<Self, TimestampError> {
        let err = || TimestampError::Parse(s.to_string());
        let (date, time) = s.split_once('T').ok_or_else(err)?;
        let mut dp = date.split('-');
        let y: i64 = dp.next().ok_or_else(err)?.parse().map_err(|_| err())?;
        let m: i64 = dp.next().ok_or_else(err)?.parse().map_err(|_| err())?;
        let d: i64 = dp.next().ok_or_else(err)?.parse().map_err(|_| err())?;
        if dp.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
            return Err(err());
        }
        let mut tp = time.split(':');
        let hh: i64 = tp.next().ok_or_else(err)?.parse().map_err(|_| err())?;
        let mm: i64 = tp.next().ok_or_else(err)?.parse().map_err(|_| err())?;
        let sec_part = tp.next().ok_or_else(err)?;
        if tp.next().is_some() {
            return Err(err());
        }
        let (ss_str, frac) = sec_part.split_once('.').ok_or_else(err)?;
        let ss: i64 = ss_str.parse().map_err(|_| err())?;
        if frac.is_empty() || frac.len() > 6 || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err());
        }
        let mut us: i64 = frac.parse().map_err(|_| err())?;
        us *= 10_i64.pow(6 - frac.len() as u32);
        if hh > 23 || mm > 59 || ss > 59 {
            return Err(err());
        }
        let days = days_from_civil(y, m, d);
        let total = (days * 86_400 + hh * 3600 + mm * 60 + ss) as f64 + us as f64 / 1e6;
        Self::from_secs(total)
    }

    /// Parse with additional offset and delta, mirroring the keyword
    /// arguments of the Python constructor. Any offset parsed from the
    /// string is added to `offset`.
    pub fn parse_with(s: &str, offset: u64, delta: i64) -> Result<Self, TimestampError> {
        let mut ts: Timestamp = s.parse()?;
        ts = ts.apply_delta(delta)?;
        ts.increment_offset(offset)?;
        Ok(ts)
    }
}

impl FromStr for Timestamp {
    type Err = TimestampError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (float_str, hex_str) = match s.split_once('_') {
            Some((f, h)) => (f, h),
            None => (s, ""),
        };
        if hex_str.contains('_') {
            return Err(TimestampError::Parse(format!(
                "invalid hex part: {hex_str:?}"
            )));
        }
        if hex_str.len() > HEX_PART_DIGITS {
            return Err(TimestampError::Parse(format!(
                "hex part too long: {hex_str:?}"
            )));
        }
        let offset = if hex_str.is_empty() {
            0
        } else {
            u64::from_str_radix(hex_str, 16)
                .map_err(|_| TimestampError::Parse(format!("invalid hex part: {hex_str:?}")))?
        };
        let secs: f64 = float_str
            .trim()
            .parse()
            .map_err(|_| TimestampError::Parse(s.to_string()))?;
        Timestamp::from_secs_offset(secs, offset)
    }
}

/// Days-since-epoch to (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + i64::from(m <= 2), m, d)
}

/// (year, month, day) to days-since-epoch. Inverse of `civil_from_days`.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Format a timestamp value into the standardized `xxxxxxxxxx.xxxxx`
/// (10.5) format.
pub fn normalize_timestamp(secs: f64) -> Result<String, TimestampError> {
    Ok(Timestamp::from_secs(secs)?.normal())
}

/// Format a delete-at timestamp into `xxxxxxxxxx` (10) or
/// `xxxxxxxxxx.xxxxx` (10.5) format, clamped to `[0, 9999999999.99999]`.
pub fn normalize_delete_at_timestamp(secs: f64, high_precision: bool) -> String {
    let clamped = secs.clamp(0.0, 9_999_999_999.999_99);
    if high_precision {
        // %016.5f
        let raw = round_half_even(clamped / PRECISION) as i64;
        format!("{:010}.{:05}", raw / 100_000, raw % 100_000)
    } else {
        // %010d truncates toward zero
        format!("{:010}", clamped as i64)
    }
}

/// Encode up to three timestamps into a string of the form
/// `<t1>[<+/-><t2 - t1>[<+/-><t3 - t2>]]`, as used in container DB rows
/// and `.meta` file names.
pub fn encode_timestamps(
    t1: &Timestamp,
    t2: Option<&Timestamp>,
    t3: Option<&Timestamp>,
    explicit: bool,
) -> String {
    let mut out = t1.short();
    let mut explicit = explicit;
    let mut deltas: Vec<i64> = Vec::new();
    if let Some(t2) = t2 {
        let d21 = t2.raw() - t1.raw();
        explicit = explicit || d21 != 0;
        deltas.push(d21);
        if let Some(t3) = t3 {
            let d32 = t3.raw() - t2.raw();
            explicit = explicit || d32 != 0;
            deltas.push(d32);
        }
        if explicit {
            for d in deltas {
                if d < 0 {
                    out.push_str(&format!("-{:x}", -d));
                } else {
                    out.push_str(&format!("+{d:x}"));
                }
            }
        }
    }
    out
}

/// Parse a string generated by [`encode_timestamps`] back into its three
/// component timestamps. When `explicit` is false, missing components take
/// the value of the previous component; when true they are `None`.
pub fn decode_timestamps(
    encoded: &str,
    explicit: bool,
) -> Result<(Timestamp, Option<Timestamp>, Option<Timestamp>), TimestampError> {
    // split into parts and signs, e.g. "x-y+z" -> [x, y, z] / [+1, -1, +1]
    let mut parts: Vec<&str> = Vec::new();
    let mut signs: Vec<i64> = Vec::new();
    for pos_part in encoded.split('+') {
        let neg_parts: Vec<&str> = pos_part.split('-').collect();
        signs.push(1);
        signs.extend(std::iter::repeat_n(-1, neg_parts.len() - 1));
        parts.extend(neg_parts);
    }
    let t1: Timestamp = parts[0].parse()?;
    let mut t2 = None;
    let mut t3 = None;
    if parts.len() > 1 {
        let delta = signs[1]
            * i64::from_str_radix(parts[1], 16)
                .map_err(|_| TimestampError::Parse(parts[1].to_string()))?;
        // preserve any offset in t1 when delta == 0
        t2 = Some(if delta != 0 {
            t1.normalized().apply_delta(delta)?
        } else {
            t1
        });
    } else if !explicit {
        t2 = Some(t1);
    }
    if parts.len() > 2 {
        let prev = t2.unwrap();
        let delta = signs[2]
            * i64::from_str_radix(parts[2], 16)
                .map_err(|_| TimestampError::Parse(parts[2].to_string()))?;
        t3 = Some(if delta != 0 {
            prev.normalized().apply_delta(delta)?
        } else {
            prev
        });
    } else if !explicit {
        t3 = t2;
    }
    Ok((t1, t2, t3))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_format() {
        let ts = Timestamp::from_secs(1402464677.04188).unwrap();
        assert_eq!(ts.normal(), "1402464677.04188");
        assert_eq!(ts.internal(), "1402464677.04188");
        assert_eq!(Timestamp::zero().normal(), "0000000000.00000");
        assert_eq!(Timestamp::from_secs(0.0).unwrap(), Timestamp::zero());
    }

    #[test]
    fn test_internal_format_with_offset() {
        let ts = Timestamp::from_secs_offset(1402464677.04188, 1).unwrap();
        assert_eq!(ts.internal(), "1402464677.04188_0000000000000001");
        assert_eq!(ts.short(), "1402464677.04188_1");
        assert_eq!(ts.normal(), "1402464677.04188");
        let ts = Timestamp::from_secs_offset(1402464677.04188, 16).unwrap();
        assert_eq!(ts.internal(), "1402464677.04188_0000000000000010");
    }

    #[test]
    fn test_parse() {
        let ts: Timestamp = "1402464677.04188".parse().unwrap();
        assert_eq!(ts.raw(), 140246467704188);
        assert_eq!(ts.offset(), 0);

        let ts: Timestamp = "1402464677.04188_0000000000000001".parse().unwrap();
        assert_eq!(ts.offset(), 1);
        assert_eq!(ts.internal(), "1402464677.04188_0000000000000001");

        // max offset
        let ts: Timestamp = "1402464677.04188_ffffffffffffffff".parse().unwrap();
        assert_eq!(ts.offset(), MAX_OFFSET);

        // errors
        assert!("".parse::<Timestamp>().is_err());
        assert!("abc".parse::<Timestamp>().is_err());
        assert!("1.2_3_4".parse::<Timestamp>().is_err());
        assert!("1402464677.04188_ffffffffffffffff0"
            .parse::<Timestamp>()
            .is_err());
        assert!("-1".parse::<Timestamp>().is_err());
        assert!("10000000000".parse::<Timestamp>().is_err());
    }

    #[test]
    fn test_bounds() {
        assert_eq!(
            Timestamp::from_secs(-1.0),
            Err(TimestampError::Negative)
        );
        assert_eq!(
            Timestamp::from_secs(1e10),
            Err(TimestampError::TooLarge)
        );
        // largest valid value
        let ts = Timestamp::from_secs(9999999999.99999).unwrap();
        assert_eq!(ts.raw(), MAX_RAW_TIME);
        assert_eq!(ts.normal(), "9999999999.99999");
    }

    #[test]
    fn test_ordering() {
        let a = Timestamp::from_secs(1402464677.04188).unwrap();
        let b = Timestamp::from_secs_offset(1402464677.04188, 1).unwrap();
        let c = Timestamp::from_secs(1402464677.04189).unwrap();
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
        // ordering matches lexicographic ordering of internal strings
        assert_eq!(a.internal() < b.internal(), a < b);
        assert_eq!(b.internal() < c.internal(), b < c);
        assert_eq!(a, "1402464677.04188".parse::<Timestamp>().unwrap());
    }

    #[test]
    fn test_truthiness() {
        assert!(!Timestamp::zero().is_truthy());
        assert!(Timestamp::from_secs_offset(0.0, 1).unwrap().is_truthy());
        assert!(Timestamp::from_secs(1.0).unwrap().is_truthy());
    }

    #[test]
    fn test_delta() {
        let ts = Timestamp::from_secs(1402464677.04188).unwrap();
        assert_eq!(
            ts.apply_delta(1).unwrap().normal(),
            "1402464677.04189"
        );
        assert_eq!(
            ts.apply_delta(-1).unwrap().normal(),
            "1402464677.04187"
        );
        assert!(Timestamp::zero().apply_delta(-1).is_err());
    }

    #[test]
    fn test_invert() {
        let ts = Timestamp::zero();
        assert_eq!(ts.invert().normal(), "9999999999.99999");
        assert_eq!(ts.invert().invert(), ts);

        let ts = Timestamp::from_secs_offset(0.0, 1).unwrap();
        let inv = ts.invert();
        assert_eq!(inv.internal(), "9999999999.99998_ffffffffffffffff");
        assert_eq!(inv.invert(), ts);

        // inversion reverses ordering
        let a = Timestamp::from_secs(1.0).unwrap();
        let b = Timestamp::from_secs(2.0).unwrap();
        assert!(a < b);
        assert!(a.invert() > b.invert());
    }

    #[test]
    fn test_ceil() {
        assert_eq!(Timestamp::zero().ceil(), 0);
        assert_eq!(Timestamp::from_secs(0.00001).unwrap().ceil(), 1);
        assert_eq!(Timestamp::from_secs(1.0).unwrap().ceil(), 1);
        assert_eq!(Timestamp::from_secs(1.00001).unwrap().ceil(), 2);
    }

    #[test]
    fn test_isoformat() {
        assert_eq!(
            Timestamp::zero().isoformat(),
            "1970-01-01T00:00:00.000000"
        );
        let ts = Timestamp::from_secs(1402466346.38836).unwrap();
        // value verified against the Python implementation
        assert_eq!(ts.isoformat(), "2014-06-11T05:59:06.388360");
        // round trip
        let back = Timestamp::from_isoformat(&ts.isoformat()).unwrap();
        assert_eq!(back, ts);
        assert_eq!(
            Timestamp::from_isoformat("1970-01-01T00:00:00.000000").unwrap(),
            Timestamp::zero()
        );
        assert!(Timestamp::from_isoformat("not a date").is_err());
    }

    #[test]
    fn test_normalize_timestamp() {
        assert_eq!(
            normalize_timestamp(1402464677.04188).unwrap(),
            "1402464677.04188"
        );
        assert_eq!(normalize_timestamp(0.0).unwrap(), "0000000000.00000");
    }

    #[test]
    fn test_normalize_delete_at_timestamp() {
        assert_eq!(normalize_delete_at_timestamp(-1.0, false), "0000000000");
        assert_eq!(normalize_delete_at_timestamp(-1.0, true), "0000000000.00000");
        assert_eq!(
            normalize_delete_at_timestamp(1402464677.04188, false),
            "1402464677"
        );
        assert_eq!(
            normalize_delete_at_timestamp(1402464677.04188, true),
            "1402464677.04188"
        );
        assert_eq!(
            normalize_delete_at_timestamp(1e11, false),
            "9999999999"
        );
        assert_eq!(
            normalize_delete_at_timestamp(1e11, true),
            "9999999999.99999"
        );
    }

    #[test]
    fn test_encode_decode_timestamps() {
        let t1 = Timestamp::from_secs(1402464677.04188).unwrap();
        // all equal -> just t1
        assert_eq!(
            encode_timestamps(&t1, Some(&t1), Some(&t1), false),
            "1402464677.04188"
        );
        // explicit -> zero deltas appended
        assert_eq!(
            encode_timestamps(&t1, Some(&t1), Some(&t1), true),
            "1402464677.04188+0+0"
        );
        let t2 = t1.apply_delta(2).unwrap();
        let t3 = t2.apply_delta(-1).unwrap();
        let enc = encode_timestamps(&t1, Some(&t2), Some(&t3), false);
        assert_eq!(enc, "1402464677.04188+2-1");
        let (d1, d2, d3) = decode_timestamps(&enc, false).unwrap();
        assert_eq!(d1, t1);
        assert_eq!(d2, Some(t2));
        assert_eq!(d3, Some(t3));

        // single value decodes to three equal values when not explicit
        let (d1, d2, d3) = decode_timestamps("1402464677.04188", false).unwrap();
        assert_eq!(d1, t1);
        assert_eq!(d2, Some(t1));
        assert_eq!(d3, Some(t1));
        // ...and to None when explicit
        let (d1, d2, d3) = decode_timestamps("1402464677.04188", true).unwrap();
        assert_eq!(d1, t1);
        assert_eq!(d2, None);
        assert_eq!(d3, None);

        // offset on t1 is preserved through encode/decode
        let t1o = Timestamp::from_secs_offset(1402464677.04188, 1).unwrap();
        let enc = encode_timestamps(&t1o, Some(&t1o), Some(&t1o), false);
        assert_eq!(enc, "1402464677.04188_1");
        let (d1, d2, d3) = decode_timestamps(&enc, false).unwrap();
        assert_eq!(d1, t1o);
        assert_eq!(d2, Some(t1o));
        assert_eq!(d3, Some(t1o));
    }

    #[test]
    fn test_python_golden_vectors() {
        // Vectors generated by swift/common/utils/timestamp.py
        // (random.seed(42)): raw|offset|internal|short
        let vectors: &[(i64, u64, &str, &str)] = &[
            (
                639426798457883,
                13679192365072849617,
                "6394267984.57883_bdd640fb06671ad1",
                "6394267984.57883_bdd640fb06671ad1",
            ),
            (
                244891853803476,
                13585496030504862185,
                "2448918538.03476_bc8960a923b8c1e9",
                "2448918538.03476_bc8960a923b8c1e9",
            ),
            (
                676699487422911,
                10060236952204337488,
                "6766994874.22911_8b9d2434e465e150",
                "6766994874.22911_8b9d2434e465e150",
            ),
            (
                590492512449039,
                549661728470919411,
                "5904925124.49039_07a0ca6e0822e8f3",
                "5904925124.49039_7a0ca6e0822e8f3",
            ),
            (
                218637974803603,
                11105285438068160209,
                "2186379748.03603_9a1de644815ef6d1",
                "2186379748.03603_9a1de644815ef6d1",
            ),
        ];
        for &(raw, offset, internal, short) in vectors {
            let ts = Timestamp::from_parts(raw, offset).unwrap();
            assert_eq!(ts.internal(), internal);
            assert_eq!(ts.short(), short);
            // and parsing round-trips
            assert_eq!(internal.parse::<Timestamp>().unwrap(), ts);
            assert_eq!(short.parse::<Timestamp>().unwrap(), ts);
        }
    }

    #[test]
    fn test_parse_with() {
        let ts = Timestamp::parse_with("1402464677.04188_1", 2, 1).unwrap();
        assert_eq!(ts.normal(), "1402464677.04189");
        assert_eq!(ts.offset(), 3);
    }
}
