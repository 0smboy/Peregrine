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
    pub objects: Vec<MultiDeleteObject>,
}

/// One object entry in a multi-delete request.  `version_id` is significant:
/// omitting it creates a delete marker in a versioned bucket, while supplying
/// it deletes exactly that version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiDeleteObject {
    pub key: String,
    pub version_id: Option<String>,
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
    let mut objects = Vec::new();
    let mut rest = text;
    let mut saw_object = false;
    while let Some(obj_start) = rest.find("<Object>") {
        saw_object = true;
        let after = &rest[obj_start..];
        let Some(obj_end_rel) = after.find("</Object>") else {
            return Err("MalformedXML".into());
        };
        let obj = &after[..obj_end_rel + "</Object>".len()];
        match xml_tag_text(obj, "Key") {
            Some(key) if !key.is_empty() => {
                objects.push(MultiDeleteObject {
                    key,
                    version_id: xml_tag_text(obj, "VersionId").filter(|value| !value.is_empty()),
                });
            }
            _ => return Err("UserKeyMustBeSpecified".into()),
        }
        rest = &after[obj_end_rel + "</Object>".len()..];
    }
    if !saw_object {
        return Err("MalformedXML".into());
    }
    Ok(MultiDeleteRequest { quiet, objects })
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
  <Object><Key>b/c</Key><VersionId>abc123</VersionId></Object>
</Delete>"#;
        let req = parse_multi_delete_body(body).unwrap();
        assert!(req.quiet);
        assert_eq!(
            req.objects,
            vec![
                MultiDeleteObject {
                    key: "a".to_string(),
                    version_id: None,
                },
                MultiDeleteObject {
                    key: "b/c".to_string(),
                    version_id: Some("abc123".to_string()),
                },
            ]
        );
    }

    #[test]
    fn rejects_non_delete() {
        assert!(parse_multi_delete_body(b"<Hello/>").is_err());
    }

    #[test]
    fn empty_object_list_is_malformed() {
        assert_eq!(
            parse_multi_delete_body(b"<Delete></Delete>").unwrap_err(),
            "MalformedXML"
        );
    }

    #[test]
    fn empty_key_is_user_key_must_be_specified() {
        assert_eq!(
            parse_multi_delete_body(b"<Delete><Object><Key></Key></Object></Delete>").unwrap_err(),
            "UserKeyMustBeSpecified"
        );
    }
}
