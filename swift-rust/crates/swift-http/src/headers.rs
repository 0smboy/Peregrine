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

//! `HeaderKeyDict`: a dict that title-cases keys on the way in
//! (`swift/common/header_key_dict.py`). Iteration order is insertion
//! order, which Python's dict also guarantees.

/// Store key for `HeaderKeyDict`. Swift title-cases; S3 clients (boto3
/// `Metadata`) require lowercase `x-amz-*` on the wire, matching Python
/// `s3api.s3response.HeaderKeyDict`.
pub fn header_store_key(key: &str) -> String {
    if key.to_ascii_lowercase().starts_with("x-amz-") {
        key.to_ascii_lowercase()
    } else {
        title_case(key)
    }
}

/// Python `bytes.title()` over the latin-1 encoding of the key: the
/// first letter of every alphabetic run is uppercased, the rest
/// lowercased. Only ASCII letters are affected.
pub fn title_case(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut prev_alpha = false;
    for c in key.chars() {
        let is_alpha = c.is_ascii_alphabetic();
        if is_alpha && !prev_alpha {
            out.push(c.to_ascii_uppercase());
        } else if is_alpha {
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
        prev_alpha = is_alpha;
    }
    out
}

/// Case-insensitive, insertion-ordered header map.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HeaderKeyDict {
    pairs: Vec<(String, String)>,
}

impl HeaderKeyDict {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        let key = header_store_key(key);
        self.pairs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Setting `None` in Python deletes the key; use [`remove`] for that.
    ///
    /// [`remove`]: HeaderKeyDict::remove
    pub fn set(&mut self, key: &str, value: impl ToString) {
        let key = header_store_key(key);
        let value = value.to_string();
        match self.pairs.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => *v = value,
            None => self.pairs.push((key, value)),
        }
    }

    pub fn setdefault(&mut self, key: &str, value: impl ToString) {
        if !self.contains_key(key) {
            self.set(key, value);
        }
    }

    pub fn remove(&mut self, key: &str) -> Option<String> {
        let key = header_store_key(key);
        let pos = self.pairs.iter().position(|(k, _)| *k == key)?;
        Some(self.pairs.remove(pos).1)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }
}

impl<K: AsRef<str>, V: ToString> FromIterator<(K, V)> for HeaderKeyDict {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let mut out = HeaderKeyDict::new();
        for (k, v) in iter {
            out.set(k.as_ref(), v.to_string());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_title_case() {
        assert_eq!(title_case("content-length"), "Content-Length");
        assert_eq!(title_case("X-OBJECT-META-foo_bar"), "X-Object-Meta-Foo_Bar");
        assert_eq!(title_case("etag"), "Etag");
        assert_eq!(title_case("x-container-sysmeta-a b"), "X-Container-Sysmeta-A B");
    }

    #[test]
    fn test_case_insensitive_ops() {
        let mut h = HeaderKeyDict::new();
        h.set("content-length", 5);
        assert_eq!(h.get("CONTENT-LENGTH"), Some("5"));
        h.set("Content-Length", "7");
        assert_eq!(h.len(), 1);
        assert_eq!(h.remove("content-LENGTH"), Some("7".to_string()));
        assert!(h.is_empty());
    }

    #[test]
    fn x_amz_headers_stay_lowercase() {
        let mut h = HeaderKeyDict::new();
        h.set("X-Amz-Meta-Meta1", "mymeta");
        h.set("x-amz-request-id", "rid");
        let keys: Vec<&str> = h.iter().map(|(k, _)| k).collect();
        assert!(keys.contains(&"x-amz-meta-meta1"), "{keys:?}");
        assert!(keys.contains(&"x-amz-request-id"), "{keys:?}");
        assert!(!keys.iter().any(|k| *k == "X-Amz-Meta-Meta1"), "{keys:?}");
        assert_eq!(h.get("X-Amz-Meta-Meta1"), Some("mymeta"));
        assert_eq!(h.get("x-amz-meta-meta1"), Some("mymeta"));
    }
}
