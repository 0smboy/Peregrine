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

//! Configuration value coercion and config-file parsing, ported from
//! `swift/common/utils/config.py`.
//!
//! The [`SwiftConfig`] parser mimics Python's `configparser.ConfigParser`
//! as used by Swift's `readconf()`: case-preserving option keys
//! (`optionxform = str`), a special `[DEFAULT]` section whose options are
//! visible in every section, indentation-based line continuations, and
//! "nicer" `%(name)s` interpolation that is only attempted when a value
//! contains `%(` (so values like `1%` pass through untouched).

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_INTERPOLATION_DEPTH: usize = 10;

/// Values recognised as true by [`config_true_value`].
pub const TRUE_VALUES: [&str; 6] = ["true", "1", "yes", "on", "t", "y"];

/// Error parsing or interpolating configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

/// Returns true if the value is a string in [`TRUE_VALUES`]
/// (case-insensitive).
pub fn config_true_value(value: &str) -> bool {
    TRUE_VALUES.contains(&value.to_lowercase().as_str())
}

/// Check that the value casts to a float and is non-negative.
pub fn non_negative_float(value: &str) -> Result<f64, ConfigError> {
    match value.trim().parse::<f64>() {
        Ok(v) if v >= 0.0 => Ok(v),
        _ => err(format!(
            "Value must be a non-negative float number, not \"{value}\"."
        )),
    }
}

/// Check that the value casts to an int and is non-negative.
pub fn non_negative_int(value: &str) -> Result<i64, ConfigError> {
    match value.trim().parse::<i64>() {
        Ok(v) if v >= 0 => Ok(v),
        _ => err(format!(
            "Value must be a non-negative integer, not \"{value}\"."
        )),
    }
}

/// Returns a positive (> 0) int value, erroring otherwise.
pub fn config_positive_int_value(value: &str) -> Result<i64, ConfigError> {
    match value.trim().parse::<i64>() {
        Ok(v) if v >= 1 => Ok(v),
        _ => err(format!(
            "Config option must be an positive int number, not \"{value}\"."
        )),
    }
}

/// Returns a positive (> 0) float value, erroring otherwise.
pub fn config_positive_float_value(value: &str) -> Result<f64, ConfigError> {
    match value.trim().parse::<f64>() {
        Ok(v) if v > 0.0 => Ok(v),
        _ => err(format!(
            "Config option must be a positive float number, not \"{value}\"."
        )),
    }
}

/// Returns a float value bounded by optional minimum/maximum (inclusive).
pub fn config_float_value(
    value: &str,
    minimum: Option<f64>,
    maximum: Option<f64>,
) -> Result<f64, ConfigError> {
    let fail = || {
        let min_ = minimum.map_or(String::new(), |m| format!(", greater than {m}"));
        let max_ = maximum.map_or(String::new(), |m| format!(", less than {m}"));
        ConfigError(format!(
            "Config option must be a number{min_}{max_}, not \"{value}\"."
        ))
    };
    let val: f64 = value.trim().parse().map_err(|_| fail())?;
    if minimum.is_some_and(|m| val < m) || maximum.is_some_and(|m| val > m) {
        return Err(fail());
    }
    Ok(val)
}

/// Returns `default` if value is `None` or `"auto"`, else the value as an
/// int.
pub fn config_auto_int_value(value: Option<&str>, default: i64) -> Result<i64, ConfigError> {
    match value {
        None => Ok(default),
        Some(v) if v.eq_ignore_ascii_case("auto") => Ok(default),
        Some(v) => v.trim().parse().map_err(|_| {
            ConfigError(format!(
                "Config option must be an integer or the string \"auto\", not \"{v}\"."
            ))
        }),
    }
}

/// Returns a percentage config value as a fraction in `[0.0, 1.0]`.
pub fn config_percent_value(value: &str) -> Result<f64, ConfigError> {
    config_float_value(value, Some(0.0), Some(100.0))
        .map(|v| v / 100.0)
        .map_err(|e| ConfigError(format!("{e}: {value}")))
}

/// Parsed `request_node_count` config value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestNodeCount {
    /// A fixed node count, e.g. `"3"`.
    Absolute(i64),
    /// A multiple of the replica count, e.g. `"2 * replicas"`.
    MultipleOfReplicas(i64),
}

impl RequestNodeCount {
    /// Evaluate for a given replica count.
    pub fn get(&self, replicas: i64) -> i64 {
        match self {
            RequestNodeCount::Absolute(n) => *n,
            RequestNodeCount::MultipleOfReplicas(n) => n * replicas,
        }
    }
}

/// Parse a `request_node_count` value: either `<int>` or
/// `<int> * replicas`.
pub fn config_request_node_count_value(value: &str) -> Result<RequestNodeCount, ConfigError> {
    let lower = value.to_lowercase();
    let parts: Vec<&str> = lower.split_whitespace().collect();
    if let Some(first) = parts.first() {
        if let Ok(n) = first.parse::<i64>() {
            if parts.len() == 1 {
                return Ok(RequestNodeCount::Absolute(n));
            }
            if parts.len() == 3 && parts[1] == "*" && parts[2] == "replicas" {
                return Ok(RequestNodeCount::MultipleOfReplicas(n));
            }
        }
    }
    err(format!("Invalid request_node_count value: {value:?}"))
}

/// Parsed `fallocate_reserve` config value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FallocateReserve {
    /// Absolute number of bytes.
    Bytes(i64),
    /// Percentage of the disk.
    Percent(f64),
}

/// Parse a `fallocate_reserve` value: an integer byte count or a float
/// percentage with a trailing `%`.
pub fn config_fallocate_value(reserve_value: &str) -> Result<FallocateReserve, ConfigError> {
    let fail = || {
        ConfigError(format!(
            "Error: {reserve_value} is an invalid value for fallocate_reserve."
        ))
    };
    if let Some(stripped) = reserve_value.strip_suffix('%') {
        Ok(FallocateReserve::Percent(
            stripped.trim().parse().map_err(|_| fail())?,
        ))
    } else {
        Ok(FallocateReserve::Bytes(
            reserve_value.trim().parse().map_err(|_| fail())?,
        ))
    }
}

/// Split a comma-separated string into a list of trimmed, non-empty
/// values (Python `utils.list_from_csv`).
pub fn list_from_csv(comma_separated_str: &str) -> Vec<String> {
    comma_separated_str
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// A single region/zone matcher parsed from an affinity string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AffinityMatcher {
    region: u64,
    zone: Option<u64>,
    priority: u64,
}

fn parse_r_z(piece: &str) -> Option<(u64, Option<u64>)> {
    // matches r<number> or r<number>z<number>
    let rest = piece.strip_prefix('r')?;
    let (region_str, zone) = match rest.find('z') {
        Some(i) => {
            let z = &rest[i + 1..];
            if z.is_empty() || !z.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (&rest[..i], Some(z.parse().ok()?))
        }
        None => (rest, None),
    };
    if region_str.is_empty() || !region_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((region_str.parse().ok()?, zone))
}

/// Sort-key function for read affinity, built from a config value such as
/// `"r1=1, r2z7=2, r2z8=2"` (Python `affinity_key_function`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffinityKeyFunction {
    matchers: Vec<AffinityMatcher>,
    empty: bool,
}

impl AffinityKeyFunction {
    /// Parse an affinity config value. An empty (or all whitespace) value
    /// yields a function that does not alter node ordering.
    pub fn parse(affinity_str: &str) -> Result<Self, ConfigError> {
        let affinity_str = affinity_str.trim();
        if affinity_str.is_empty() {
            return Ok(AffinityKeyFunction {
                matchers: Vec::new(),
                empty: true,
            });
        }
        let mut matchers = Vec::new();
        for piece in affinity_str.split(',').map(str::trim) {
            let parsed = piece.split_once('=').and_then(|(rz, prio)| {
                let priority: u64 = if prio.bytes().all(|b| b.is_ascii_digit()) && !prio.is_empty()
                {
                    prio.parse().ok()?
                } else {
                    return None;
                };
                let (region, zone) = parse_r_z(rz)?;
                Some(AffinityMatcher {
                    region,
                    zone,
                    priority,
                })
            });
            match parsed {
                Some(m) => matchers.push(m),
                None => return err(format!("Invalid affinity value: {affinity_str:?}")),
            }
        }
        matchers.sort_by_key(|m| m.priority);
        Ok(AffinityKeyFunction {
            matchers,
            empty: false,
        })
    }

    /// Priority key for a node in the given region/zone; lower sorts
    /// first. Unmatched nodes get 2^32 ("a big number").
    pub fn key(&self, region: u64, zone: u64) -> u64 {
        if self.empty {
            return 0;
        }
        for m in &self.matchers {
            if m.region == region && m.zone.is_none_or(|z| z == zone) {
                return m.priority;
            }
        }
        4294967296 // 2^32
    }
}

/// Write-affinity predicate built from a config value such as
/// `"r1, r2z2"` (Python `affinity_locality_predicate`). `parse` returns
/// `None` for an empty value, meaning everything is local.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffinityLocalityPredicate {
    matchers: Vec<(u64, Option<u64>)>,
}

impl AffinityLocalityPredicate {
    /// Parse a write-affinity config value; `Ok(None)` when empty.
    pub fn parse(write_affinity_str: &str) -> Result<Option<Self>, ConfigError> {
        let affinity_str = write_affinity_str.trim();
        if affinity_str.is_empty() {
            return Ok(None);
        }
        let mut matchers = Vec::new();
        for piece in affinity_str.split(',').map(str::trim) {
            match parse_r_z(piece) {
                Some(rz) => matchers.push(rz),
                None => return err(format!("Invalid write-affinity value: {affinity_str:?}")),
            }
        }
        Ok(Some(AffinityLocalityPredicate { matchers }))
    }

    /// Whether a node in the given region/zone is "local".
    pub fn is_local(&self, region: u64, zone: u64) -> bool {
        self.matchers
            .iter()
            .any(|(r, z)| *r == region && z.is_none_or(|z| z == zone))
    }
}

/// A parsed Swift configuration file, mimicking `ConfigParser` with
/// `optionxform = str` and `NicerInterpolation` as used by `readconf()`.
#[derive(Debug, Clone)]
pub struct SwiftConfig {
    /// Options from the `[DEFAULT]` section (plus constructor defaults),
    /// in insertion order.
    defaults: Vec<(String, String)>,
    /// Named sections, in file order, each with options in file order.
    sections: Vec<(String, Vec<(String, String)>)>,
    /// When true, behave like `RawConfigParser`: no interpolation.
    raw: bool,
    /// When true (`ConfigParser` default), duplicate sections/options
    /// within one read are errors; when false (`strict=False`, used for
    /// `swift.conf`), later duplicates win.
    strict: bool,
}

impl Default for SwiftConfig {
    fn default() -> Self {
        SwiftConfig {
            defaults: Vec::new(),
            sections: Vec::new(),
            raw: false,
            strict: true,
        }
    }
}

impl SwiftConfig {
    /// Parse configuration text. `defaults` pre-populates the `[DEFAULT]`
    /// section; `raw` disables `%(name)s` interpolation.
    pub fn parse(
        content: &str,
        defaults: &[(String, String)],
        raw: bool,
    ) -> Result<Self, ConfigError> {
        let mut config = SwiftConfig {
            defaults: defaults.to_vec(),
            raw,
            ..Default::default()
        };
        config.read_string(content)?;
        Ok(config)
    }

    /// Like [`parse`](Self::parse) but with `strict=False` semantics:
    /// duplicate sections merge and duplicate options take the last
    /// value, as Python does when reading `swift.conf` storage policies.
    pub fn parse_lenient(
        content: &str,
        defaults: &[(String, String)],
        raw: bool,
    ) -> Result<Self, ConfigError> {
        let mut config = SwiftConfig {
            defaults: defaults.to_vec(),
            raw,
            strict: false,
            ..Default::default()
        };
        config.read_string(content)?;
        Ok(config)
    }

    /// Read a config file, or a directory of `*.conf` files (sorted, dot
    /// files excluded), like Python `readconf` / `read_conf_dir`.
    pub fn read_path(path: &Path, raw: bool) -> Result<Self, ConfigError> {
        Self::read_path_opts(path, raw, true)
    }

    /// Like [`read_path`](Self::read_path) with `strict=False` semantics.
    pub fn read_path_lenient(path: &Path, raw: bool) -> Result<Self, ConfigError> {
        Self::read_path_opts(path, raw, false)
    }

    fn read_path_opts(path: &Path, raw: bool, strict: bool) -> Result<Self, ConfigError> {
        let mut config = SwiftConfig {
            raw,
            strict,
            ..Default::default()
        };
        let mut files: Vec<PathBuf> = Vec::new();
        if path.is_dir() {
            let entries = fs::read_dir(path)
                .map_err(|e| ConfigError(format!("Unable to read config from {path:?}: {e}")))?;
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".conf") && !name.starts_with('.') {
                    files.push(entry.path());
                }
            }
            files.sort();
        } else {
            files.push(path.to_path_buf());
        }
        let mut read_any = false;
        for f in &files {
            if let Ok(content) = fs::read_to_string(f) {
                config.read_string(&content)?;
                read_any = true;
            }
        }
        if !read_any {
            return err(format!("Unable to read config from {}", path.display()));
        }
        Ok(config)
    }

    /// Parse `content` into this config, merging with existing sections
    /// like sequential `ConfigParser.read()` calls (later files override).
    fn read_string(&mut self, content: &str) -> Result<(), ConfigError> {
        // (section index or None for DEFAULT, option key) currently
        // accumulating continuation lines
        let mut cur_section: Option<Option<usize>> = None;
        let mut cur_option: Option<String> = None;
        // value lines per (section, option) accumulated during this read
        let mut pending: Vec<(Option<usize>, String, Vec<String>)> = Vec::new();
        // sections seen during *this* read, for strict duplicate detection
        let mut seen_sections: Vec<Option<usize>> = Vec::new();

        for (lineno, line) in content.lines().enumerate() {
            let stripped = line.trim();
            // A full-line comment (any indentation) is removed entirely — it
            // does NOT contribute a line to a surrounding multi-line value.
            // (Python configparser: an interior comment vanishes, so
            // "first / second / #c / third" -> "first\nsecond\nthird".)
            let is_comment = stripped.starts_with('#') || stripped.starts_with(';');
            if is_comment {
                continue;
            }
            if stripped.is_empty() {
                if cur_section.is_some() && cur_option.is_some() {
                    // A genuine blank line inside a value IS preserved as an
                    // empty line (Python keeps interior blanks).
                    if let Some(last) = pending.last_mut() {
                        last.2.push(String::new());
                    }
                }
                continue;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                // continuation line
                if cur_section.is_some() && cur_option.is_some() {
                    if let Some(last) = pending.last_mut() {
                        last.2.push(stripped.to_string());
                    }
                    continue;
                }
                return err(format!(
                    "line {}: unexpected continuation line: {line:?}",
                    lineno + 1
                ));
            }
            cur_option = None;
            if let Some(rest) = stripped.strip_prefix('[') {
                let end = rest.find(']').ok_or_else(|| {
                    ConfigError(format!(
                        "line {}: invalid section header: {line:?}",
                        lineno + 1
                    ))
                })?;
                let name = &rest[..end];
                if name.is_empty() {
                    return err(format!(
                        "line {}: invalid section header: {line:?}",
                        lineno + 1
                    ));
                }
                let sect = if name == "DEFAULT" {
                    None
                } else {
                    Some(match self.sections.iter().position(|(n, _)| n == name) {
                        Some(i) => i,
                        None => {
                            self.sections.push((name.to_string(), Vec::new()));
                            self.sections.len() - 1
                        }
                    })
                };
                if self.strict && seen_sections.contains(&sect) {
                    return err(format!(
                        "While reading from config: section {name:?} already exists"
                    ));
                }
                seen_sections.push(sect);
                cur_section = Some(sect);
                continue;
            }
            let Some(sect) = cur_section else {
                return err(format!("File contains no section headers.\nline: {line:?}"));
            };
            // option line: first '=' or ':' is the delimiter
            let delim = stripped
                .char_indices()
                .find(|&(_, c)| c == '=' || c == ':')
                .map(|(i, _)| i);
            let Some(delim) = delim else {
                return err(format!(
                    "line {}: source contains parsing errors: {line:?}",
                    lineno + 1
                ));
            };
            let key = stripped[..delim].trim().to_string();
            let value = stripped[delim + 1..].trim().to_string();
            if self.strict && pending.iter().any(|(s, k, _)| *s == sect && *k == key) {
                return err(format!(
                    "While reading from config: option {key:?} in section already exists"
                ));
            }
            cur_option = Some(key.clone());
            pending.push((sect, key, vec![value]));
        }

        // join multi-line values and merge into the config
        for (sect, key, lines) in pending {
            let value = lines.join("\n").trim_end().to_string();
            let target = match sect {
                None => &mut self.defaults,
                Some(i) => &mut self.sections[i].1,
            };
            match target.iter_mut().find(|(k, _)| *k == key) {
                Some(entry) => entry.1 = value,
                None => target.push((key, value)),
            }
        }
        Ok(())
    }

    /// Section names in file order (excluding DEFAULT).
    pub fn section_names(&self) -> Vec<&str> {
        self.sections.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// Whether the named section exists.
    pub fn has_section(&self, name: &str) -> bool {
        self.sections.iter().any(|(n, _)| n == name)
    }

    fn raw_lookup<'a>(&'a self, section: Option<usize>, key: &str) -> Option<&'a str> {
        if let Some(i) = section {
            if let Some((_, v)) = self.sections[i].1.iter().find(|(k, _)| k == key) {
                return Some(v);
            }
        }
        self.defaults
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Get an interpolated option value from a section (falling back to
    /// DEFAULT), like `ConfigParser.get`.
    ///
    /// `section == "DEFAULT"` reads the DEFAULT map directly. Named-section
    /// lookup already merges DEFAULT, but `get("DEFAULT", key)` used to
    /// return `None` because DEFAULT is not in `sections`. Callers that
    /// write `get(app).or(get("DEFAULT"))` then silently missed bind
    /// knobs on files that only declare `[DEFAULT]`.
    pub fn get(&self, section: &str, key: &str) -> Result<Option<String>, ConfigError> {
        let section_idx = if section == "DEFAULT" {
            None
        } else {
            match self.sections.iter().position(|(n, _)| n == section) {
                Some(i) => Some(i),
                None => return Ok(None),
            }
        };
        match self.raw_lookup(section_idx, key) {
            None => Ok(None),
            Some(v) => Ok(Some(self.before_get(section_idx, v)?)),
        }
    }

    /// All items of a section merged over DEFAULT, interpolated, in
    /// `ConfigParser.items()` order (defaults first, then section-only
    /// keys).
    pub fn items(&self, section: &str) -> Result<Vec<(String, String)>, ConfigError> {
        let i = self
            .sections
            .iter()
            .position(|(n, _)| n == section)
            .ok_or_else(|| ConfigError(format!("No section: {section:?}")))?;
        let mut merged: Vec<(String, &str)> = Vec::new();
        for (k, v) in &self.defaults {
            merged.push((k.clone(), v.as_str()));
        }
        for (k, v) in &self.sections[i].1 {
            match merged.iter_mut().find(|(mk, _)| mk == k) {
                Some(entry) => entry.1 = v.as_str(),
                None => merged.push((k.clone(), v.as_str())),
            }
        }
        merged
            .into_iter()
            .map(|(k, v)| Ok((k, self.before_get(Some(i), v)?)))
            .collect()
    }

    /// `NicerInterpolation.before_get`: skip interpolation entirely
    /// unless the value contains `%(`.
    fn before_get(&self, section: Option<usize>, value: &str) -> Result<String, ConfigError> {
        if self.raw || !value.contains("%(") {
            return Ok(value.to_string());
        }
        self.interpolate(section, value, 1)
    }

    /// `BasicInterpolation`: `%%` is a literal `%`; `%(name)s` is replaced
    /// by the (recursively interpolated) option `name` from the same
    /// section or DEFAULT.
    fn interpolate(
        &self,
        section: Option<usize>,
        value: &str,
        depth: usize,
    ) -> Result<String, ConfigError> {
        if depth > MAX_INTERPOLATION_DEPTH {
            return err(format!("Interpolation too deeply recursive: {value:?}"));
        }
        let mut out = String::new();
        let mut chars = value.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('%') => out.push('%'),
                Some('(') => {
                    let mut name = String::new();
                    loop {
                        match chars.next() {
                            Some(')') => break,
                            Some(ch) => name.push(ch),
                            None => {
                                return err(format!(
                                    "bad interpolation variable reference {value:?}"
                                ))
                            }
                        }
                    }
                    if chars.next() != Some('s') {
                        return err(format!("bad interpolation variable reference {value:?}"));
                    }
                    let raw = self.raw_lookup(section, &name).ok_or_else(|| {
                        ConfigError(format!("Bad value substitution: option {name:?} not found"))
                    })?;
                    out.push_str(&self.interpolate(section, raw, depth + 1)?);
                }
                _ => {
                    return err(format!(
                        "'%' must be followed by '%' or '(', found: {value:?}"
                    ))
                }
            }
        }
        Ok(out)
    }
}

/// Read a config file (or dir) and return one section's items as a map,
/// adding `log_name` if missing (Python `readconf` with a
/// `section_name`).
pub fn readconf_section(
    conf_path: &Path,
    section_name: &str,
    log_name: Option<&str>,
    raw: bool,
) -> Result<Vec<(String, String)>, ConfigError> {
    let config = SwiftConfig::read_path(conf_path, raw)?;
    if !config.has_section(section_name) {
        return err(format!(
            "Unable to find {section_name} config section in {}",
            conf_path.display()
        ));
    }
    let mut conf = config.items(section_name)?;
    if !conf.iter().any(|(k, _)| k == "log_name") {
        conf.push((
            "log_name".to_string(),
            log_name.unwrap_or(section_name).to_string(),
        ));
    }
    Ok(conf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiline_value_comment_and_blank() {
        // interior comment removed entirely; interior blank preserved; trailing
        // blank stripped (matching Python configparser)
        let cfg = "[sec]\nkey = first\n    second\n# a comment\n    third\n";
        let c = SwiftConfig::parse(cfg, &[], false).unwrap();
        assert_eq!(
            c.get("sec", "key").unwrap().as_deref(),
            Some("first\nsecond\nthird")
        );
        let cfg2 = "[sec]\nkey = first\n    second\n\n    third\n";
        let c2 = SwiftConfig::parse(cfg2, &[], false).unwrap();
        assert_eq!(
            c2.get("sec", "key").unwrap().as_deref(),
            Some("first\nsecond\n\nthird")
        );
    }

    #[test]
    fn test_config_true_value() {
        for v in ["true", "1", "yes", "on", "t", "y", "TRUE", "Yes", "T"] {
            assert!(config_true_value(v), "{v} should be true");
        }
        for v in ["false", "0", "no", "off", "f", "n", "", "2", "maybe"] {
            assert!(!config_true_value(v), "{v} should be false");
        }
    }

    #[test]
    fn test_numeric_coercions() {
        assert_eq!(non_negative_float("1.5").unwrap(), 1.5);
        assert_eq!(non_negative_float("0").unwrap(), 0.0);
        assert!(non_negative_float("-1").is_err());
        assert!(non_negative_float("abc").is_err());

        assert_eq!(non_negative_int("5").unwrap(), 5);
        assert!(non_negative_int("-5").is_err());
        assert!(non_negative_int("1.5").is_err());

        assert_eq!(config_positive_int_value("1").unwrap(), 1);
        assert!(config_positive_int_value("0").is_err());
        assert!(config_positive_int_value("-1").is_err());

        assert_eq!(config_positive_float_value("0.5").unwrap(), 0.5);
        assert!(config_positive_float_value("0").is_err());

        assert_eq!(config_float_value("5", Some(0.0), Some(10.0)).unwrap(), 5.0);
        assert!(config_float_value("11", Some(0.0), Some(10.0)).is_err());
        assert!(config_float_value("-1", Some(0.0), None).is_err());

        assert_eq!(config_auto_int_value(None, 3).unwrap(), 3);
        assert_eq!(config_auto_int_value(Some("auto"), 3).unwrap(), 3);
        assert_eq!(config_auto_int_value(Some("AUTO"), 3).unwrap(), 3);
        assert_eq!(config_auto_int_value(Some("7"), 3).unwrap(), 7);
        assert!(config_auto_int_value(Some("x"), 3).is_err());

        assert_eq!(config_percent_value("60").unwrap(), 0.6);
        assert!(config_percent_value("101").is_err());
    }

    #[test]
    fn test_request_node_count() {
        assert_eq!(config_request_node_count_value("3").unwrap().get(4), 3);
        assert_eq!(
            config_request_node_count_value("2 * replicas")
                .unwrap()
                .get(4),
            8
        );
        assert_eq!(
            config_request_node_count_value("2 * REPLICAS")
                .unwrap()
                .get(3),
            6
        );
        assert!(config_request_node_count_value("2 * spam").is_err());
        assert!(config_request_node_count_value("replicas * 2").is_err());
        assert!(config_request_node_count_value("").is_err());
    }

    #[test]
    fn test_fallocate_value() {
        assert_eq!(
            config_fallocate_value("10%").unwrap(),
            FallocateReserve::Percent(10.0)
        );
        assert_eq!(
            config_fallocate_value("2.5%").unwrap(),
            FallocateReserve::Percent(2.5)
        );
        assert_eq!(
            config_fallocate_value("1024").unwrap(),
            FallocateReserve::Bytes(1024)
        );
        assert!(config_fallocate_value("1.5").is_err());
        assert!(config_fallocate_value("abc").is_err());
    }

    #[test]
    fn test_list_from_csv() {
        assert_eq!(list_from_csv("a, b ,c,,"), vec!["a", "b", "c"]);
        assert!(list_from_csv("").is_empty());
    }

    #[test]
    fn test_affinity_key_function() {
        let f = AffinityKeyFunction::parse("r1=1, r2z7=2, r2z8=2").unwrap();
        assert_eq!(f.key(1, 1), 1);
        assert_eq!(f.key(1, 7), 1);
        assert_eq!(f.key(2, 7), 2);
        assert_eq!(f.key(2, 8), 2);
        assert_eq!(f.key(2, 9), 4294967296);
        assert_eq!(f.key(3, 1), 4294967296);

        let empty = AffinityKeyFunction::parse("   ").unwrap();
        assert_eq!(empty.key(9, 9), 0);

        assert!(AffinityKeyFunction::parse("r1").is_err());
        assert!(AffinityKeyFunction::parse("r1z2=a").is_err());
        assert!(AffinityKeyFunction::parse("rz=1").is_err());
    }

    #[test]
    fn test_affinity_locality_predicate() {
        let p = AffinityLocalityPredicate::parse("r1, r2z2")
            .unwrap()
            .unwrap();
        assert!(p.is_local(1, 1));
        assert!(p.is_local(1, 99));
        assert!(p.is_local(2, 2));
        assert!(!p.is_local(2, 3));
        assert!(!p.is_local(3, 1));

        assert!(AffinityLocalityPredicate::parse("").unwrap().is_none());
        assert!(AffinityLocalityPredicate::parse("r1=1").is_err());
    }

    const SAMPLE: &str = "\
[DEFAULT]
user = swift
swift_dir = /etc/swift

[pipeline:main]
pipeline = catch_errors proxy-server

[app:proxy-server]
use = egg:swift#proxy
bind_port = 8080
workers = auto
fallocate_reserve = 1%
log_facility = LOG_LOCAL1
set log_name = proxy
# a comment
; another comment
multi = first
    second
    third
interp = %(user)s-%(bind_port)s
escaped = 100%%
";

    #[test]
    fn test_parse_sections_and_defaults() {
        let c = SwiftConfig::parse(SAMPLE, &[], false).unwrap();
        assert_eq!(c.section_names(), vec!["pipeline:main", "app:proxy-server"]);
        // DEFAULT options visible in every section
        assert_eq!(c.get("pipeline:main", "user").unwrap().unwrap(), "swift");
        assert_eq!(
            c.get("app:proxy-server", "bind_port").unwrap().unwrap(),
            "8080"
        );
        // keys are case-preserving; 'set log_name' stays as-is
        assert_eq!(
            c.get("app:proxy-server", "set log_name").unwrap().unwrap(),
            "proxy"
        );
        assert_eq!(
            c.get("app:proxy-server", "log_facility").unwrap().unwrap(),
            "LOG_LOCAL1"
        );
        // missing option/section
        assert_eq!(c.get("app:proxy-server", "nope").unwrap(), None);
        assert_eq!(c.get("no-such-section", "user").unwrap(), None);
        // ConfigParser allows get('DEFAULT', key); this used to return None.
        assert_eq!(c.get("DEFAULT", "user").unwrap().as_deref(), Some("swift"));
        assert_eq!(c.get("DEFAULT", "bind_port").unwrap(), None);
    }

    #[test]
    fn get_default_section_without_named_sections() {
        let c = SwiftConfig::parse(
            "[DEFAULT]\nbind_port = 18080\nbind_ip = 0.0.0.0\n",
            &[],
            false,
        )
        .unwrap();
        assert_eq!(
            c.get("DEFAULT", "bind_port").unwrap().as_deref(),
            Some("18080")
        );
        assert_eq!(c.get("app:proxy-server", "bind_port").unwrap(), None);
    }

    #[test]
    fn test_multiline_and_interpolation() {
        let c = SwiftConfig::parse(SAMPLE, &[], false).unwrap();
        assert_eq!(
            c.get("app:proxy-server", "multi").unwrap().unwrap(),
            "first\nsecond\nthird"
        );
        // NicerInterpolation: plain '%' passes through
        assert_eq!(
            c.get("app:proxy-server", "fallocate_reserve")
                .unwrap()
                .unwrap(),
            "1%"
        );
        // ...but '%(name)s' interpolates
        assert_eq!(
            c.get("app:proxy-server", "interp").unwrap().unwrap(),
            "swift-8080"
        );
        // '%%' escapes when interpolation is triggered... here it is not
        assert_eq!(
            c.get("app:proxy-server", "escaped").unwrap().unwrap(),
            "100%%"
        );
        // raw mode: no interpolation at all
        let raw = SwiftConfig::parse(SAMPLE, &[], true).unwrap();
        assert_eq!(
            raw.get("app:proxy-server", "interp").unwrap().unwrap(),
            "%(user)s-%(bind_port)s"
        );
    }

    #[test]
    fn test_items_order_and_merge() {
        let c = SwiftConfig::parse(SAMPLE, &[], false).unwrap();
        let items = c.items("pipeline:main").unwrap();
        // defaults come first, then section options
        assert_eq!(items[0].0, "user");
        assert_eq!(items[1].0, "swift_dir");
        assert_eq!(
            items[2],
            ("pipeline".into(), "catch_errors proxy-server".into())
        );
    }

    #[test]
    fn test_parse_errors() {
        // option before any section header
        assert!(SwiftConfig::parse("a = b\n", &[], false).is_err());
        // duplicate section within one read
        assert!(SwiftConfig::parse("[a]\nx = 1\n[a]\ny = 2\n", &[], false).is_err());
        // duplicate option within one read
        assert!(SwiftConfig::parse("[a]\nx = 1\nx = 2\n", &[], false).is_err());
        // line with no delimiter
        assert!(SwiftConfig::parse("[a]\nnot an option\n", &[], false).is_err());
        // missing interpolation target
        let c = SwiftConfig::parse("[a]\nx = %(nope)s\n", &[], false).unwrap();
        assert!(c.get("a", "x").is_err());
    }

    #[test]
    fn test_colon_delimiter_and_constructor_defaults() {
        let c = SwiftConfig::parse(
            "[a]\nkey: value\n",
            &[("preset".to_string(), "1".to_string())],
            false,
        )
        .unwrap();
        assert_eq!(c.get("a", "key").unwrap().unwrap(), "value");
        assert_eq!(c.get("a", "preset").unwrap().unwrap(), "1");
    }
}
