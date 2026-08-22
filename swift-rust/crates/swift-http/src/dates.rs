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

//! RFC 1123 HTTP date formatting/parsing (Last-Modified, Date,
//! If-Modified-Since) without a clock/timezone dependency.

const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Days-from-civil (Howard Hinnant's algorithm), and back.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// `time.strftime('%a, %d %b %Y %H:%M:%S GMT', gmtime(secs))`.
pub fn http_date(epoch_secs: i64) -> String {
    let days = epoch_secs.div_euclid(86400);
    let secs_of_day = epoch_secs.rem_euclid(86400);
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday (weekday index 3 with Monday=0)
    let weekday = (days.rem_euclid(7) + 3) % 7;
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[weekday as usize],
        day,
        MONTHS[(month - 1) as usize],
        year,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

fn normalize_year(year: i64) -> i64 {
    if year < 70 {
        year + 2000
    } else if year < 100 {
        year + 1900
    } else {
        year
    }
}

fn month_num(name: &str) -> Option<u32> {
    MONTHS
        .iter()
        .position(|m| name.eq_ignore_ascii_case(m) || name.starts_with(m))
        .map(|i| i as u32 + 1)
}

fn hms_epoch(year: i64, month: u32, day: u32, time: &str) -> Option<i64> {
    let mut hms = time.split(':');
    let h: i64 = hms.next()?.parse().ok()?;
    let m: i64 = hms.next()?.parse().ok()?;
    let s: i64 = hms.next()?.parse().ok()?;
    if !((1..=31).contains(&day) && (1..=12).contains(&month) && h < 24 && m < 60 && s < 61) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86400 + h * 3600 + m * 60 + s)
}

/// Parse RFC 7231 HTTP-date: IMF-fixdate, RFC 850, or asctime.
/// `None` on anything unparseable.
///
/// Functional tests send `If-Unmodified-Since` as RFC 850 (`%A, %d-%b-%y`)
/// and asctime (`%a %b %d %H:%M:%S %Y`); only IMF-fixdate was accepted.
pub fn parse_http_date(value: &str) -> Option<i64> {
    let value = value.trim();
    if let Some((_, rest)) = value.split_once(',') {
        let rest = rest.trim();
        let mut parts = rest.split_whitespace();
        let first = parts.next()?;
        let (day, month_name, year) = if first.contains('-') {
            // RFC 850: `06-Nov-94 08:49:37 GMT`
            let mut dmy = first.split('-');
            let day: u32 = dmy.next()?.parse().ok()?;
            let month_name = dmy.next()?;
            let year: i64 = dmy.next()?.parse().ok()?;
            (day, month_name, year)
        } else {
            // IMF-fixdate: `06 Nov 1994 08:49:37 GMT`
            let day: u32 = first.parse().ok()?;
            let month_name = parts.next()?;
            let year: i64 = parts.next()?.parse().ok()?;
            (day, month_name, year)
        };
        let month = month_num(month_name)?;
        let time = parts.next()?;
        hms_epoch(normalize_year(year), month, day, time)
    } else {
        // asctime: `Sun Nov  6 08:49:37 1994` (optional extra space before day)
        let mut parts = value.split_whitespace();
        let _dow = parts.next()?;
        let month_name = parts.next()?;
        let day: u32 = parts.next()?.parse().ok()?;
        let time = parts.next()?;
        let year: i64 = parts.next()?.parse().ok()?;
        let month = month_num(month_name)?;
        hms_epoch(normalize_year(year), month, day, time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1751500001), "Wed, 02 Jul 2025 23:46:41 GMT");
        for secs in [0i64, 1751500001, 4102444800] {
            assert_eq!(parse_http_date(&http_date(secs)), Some(secs));
        }
        assert_eq!(parse_http_date("garbage"), None);
        let imf = parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(
            parse_http_date("Sunday, 06-Nov-94 08:49:37 GMT"),
            imf,
            "RFC 850"
        );
        assert_eq!(
            parse_http_date("Sun Nov  6 08:49:37 1994"),
            imf,
            "asctime padded day"
        );
        assert_eq!(
            parse_http_date("Sun Nov 6 08:49:37 1994"),
            imf,
            "asctime unpadded day"
        );
        // Functional TestFileComparison.time_old_f2 / time_old_f3 shapes.
        assert!(parse_http_date("Saturday, 21-Aug-26 12:00:00 GMT").is_some());
        assert!(parse_http_date("Sat Aug 21 12:00:00 2026").is_some());
    }
}
