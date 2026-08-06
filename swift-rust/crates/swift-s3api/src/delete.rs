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

//! Multi-object delete request parsing (`POST /bucket?delete`).

/// Parsed `POST ?delete` body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MultiDeleteRequest {
    pub quiet: bool,
    pub keys: Vec<String>,
}

/// Extract text between `<Tag>` and `</Tag>` (first occurrence), unescaping
/// the common XML entities. Returns `None` when the tag is absent.
fn xml_tag_text(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(unescape_xml(&body[start..end]))
}

fn unescape_xml(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Parse a MultiDelete XML body. Tolerates whitespace and the S3 xmlns.
pub fn parse_multi_delete_body(body: &[u8]) -> Result<MultiDeleteRequest, String> {
    let text = std::str::from_utf8(body).map_err(|_| "MalformedXML".to_string())?;
    if !text.contains("<Delete") {
        return Err("MalformedXML".into());
    }
    let quiet = text.contains("<Quiet>true</Quiet>") || text.contains("<Quiet>True</Quiet>");
    let mut keys = Vec::new();
    let mut rest = text;
    while let Some(obj_start) = rest.find("<Object>") {
        let after = &rest[obj_start..];
        let Some(obj_end_rel) = after.find("</Object>") else {
            break;
        };
        let obj = &after[..obj_end_rel + "</Object>".len()];
        if let Some(key) = xml_tag_text(obj, "Key") {
            if !key.is_empty() {
                keys.push(key);
            }
        }
        rest = &after[obj_end_rel + "</Object>".len()..];
    }
    Ok(MultiDeleteRequest { quiet, keys })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_keys_and_quiet() {
        let body = br#"<?xml version="1.0"?>
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Quiet>true</Quiet>
  <Object><Key>a</Key></Object>
  <Object><Key>b/c</Key></Object>
</Delete>"#;
        let req = parse_multi_delete_body(body).unwrap();
        assert!(req.quiet);
        assert_eq!(req.keys, vec!["a".to_string(), "b/c".to_string()]);
    }

    #[test]
    fn rejects_non_delete() {
        assert!(parse_multi_delete_body(b"<Hello/>").is_err());
    }
}
