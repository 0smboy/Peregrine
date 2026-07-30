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

//! A tiny, hand-rolled XML writer that reproduces the exact byte output of
//! the `lxml.etree.tostring(..., xml_declaration=True, encoding='UTF-8')`
//! calls used in `swift/common/middleware/s3api/etree.py`.
//!
//! Fidelity notes (verified against lxml):
//! * the declaration is `<?xml version='1.0' encoding='UTF-8'?>\n`
//!   (single quotes, trailing newline);
//! * S3 success documents carry the default namespace on the root only:
//!   `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`; error documents
//!   (`tostring(..., use_s3ns=False)`) carry no namespace;
//! * a leaf with text `Some("")` serializes as `<Tag></Tag>`, a leaf with
//!   no text and no children as `<Tag/>`;
//! * text escapes `&`, `<`, `>` and `\r` (matching lxml).

/// The S3 API XML namespace used on success-response roots.
pub const XMLNS_S3: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// An XML element node: either a leaf carrying optional text, or a branch
/// carrying child elements. Mixed content (text + children) is not produced
/// by any S3 shape, so text is ignored once children are present.
#[derive(Debug, Clone)]
pub struct Element {
    tag: String,
    text: Option<String>,
    children: Vec<Element>,
}

impl Element {
    /// An empty element (`<tag/>` unless children/text are added).
    pub fn new(tag: impl Into<String>) -> Element {
        Element {
            tag: tag.into(),
            text: None,
            children: Vec::new(),
        }
    }

    /// A leaf element with text (`<tag>text</tag>`; `<tag></tag>` if empty).
    pub fn leaf(tag: impl Into<String>, text: impl Into<String>) -> Element {
        Element {
            tag: tag.into(),
            text: Some(text.into()),
            children: Vec::new(),
        }
    }

    /// Append an already-built child and return `self` for chaining.
    pub fn with(mut self, child: Element) -> Element {
        self.children.push(child);
        self
    }

    /// Append a leaf `<tag>text</tag>` child and return `self` for chaining.
    pub fn with_leaf(self, tag: impl Into<String>, text: impl Into<String>) -> Element {
        self.with(Element::leaf(tag, text))
    }

    /// Append an already-built child in place.
    pub fn push(&mut self, child: Element) {
        self.children.push(child);
    }

    /// Append a leaf `<tag>text</tag>` child in place.
    pub fn push_leaf(&mut self, tag: impl Into<String>, text: impl Into<String>) {
        self.children.push(Element::leaf(tag, text));
    }

    fn write(&self, out: &mut String, ns: Option<&str>) {
        out.push('<');
        out.push_str(&self.tag);
        if let Some(ns) = ns {
            out.push_str(" xmlns=\"");
            escape_attr(out, ns);
            out.push('"');
        }
        if self.children.is_empty() {
            match &self.text {
                None => {
                    out.push_str("/>");
                    return;
                }
                Some(t) => {
                    out.push('>');
                    escape_text(out, t);
                }
            }
        } else {
            out.push('>');
            for child in &self.children {
                child.write(out, None);
            }
        }
        out.push_str("</");
        out.push_str(&self.tag);
        out.push('>');
    }

    /// Serialize to UTF-8 bytes with the XML declaration. When `use_s3ns` is
    /// true the S3 default namespace is emitted on the root element.
    pub fn to_xml(&self, use_s3ns: bool) -> Vec<u8> {
        let mut out = String::from("<?xml version='1.0' encoding='UTF-8'?>\n");
        self.write(&mut out, if use_s3ns { Some(XMLNS_S3) } else { None });
        out.into_bytes()
    }
}

fn escape_text(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            _ => out.push(c),
        }
    }
}

fn escape_attr(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_shape_no_ns() {
        let mut e = Element::new("Error");
        e.push_leaf("Code", "NoSuchBucket");
        e.push_leaf("Message", "The specified bucket does not exist.");
        e.push_leaf("BucketName", "faux&b<x>");
        let got = String::from_utf8(e.to_xml(false)).unwrap();
        assert_eq!(
            got,
            "<?xml version='1.0' encoding='UTF-8'?>\n\
             <Error><Code>NoSuchBucket</Code>\
             <Message>The specified bucket does not exist.</Message>\
             <BucketName>faux&amp;b&lt;x&gt;</BucketName></Error>"
        );
    }

    #[test]
    fn test_success_shape_with_ns_and_empty_leaf() {
        let mut e = Element::new("ListBucketResult");
        e.push_leaf("Name", "bucket");
        e.push_leaf("Prefix", ""); // empty text -> <Prefix></Prefix>
        e.push_leaf("MaxKeys", "1000");
        e.push_leaf("IsTruncated", "false");
        let got = String::from_utf8(e.to_xml(true)).unwrap();
        assert_eq!(
            got,
            "<?xml version='1.0' encoding='UTF-8'?>\n\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>bucket</Name><Prefix></Prefix><MaxKeys>1000</MaxKeys>\
             <IsTruncated>false</IsTruncated></ListBucketResult>"
        );
    }

    #[test]
    fn test_self_closing_empty_element() {
        let e = Element::new("Empty");
        assert_eq!(
            String::from_utf8(e.to_xml(false)).unwrap(),
            "<?xml version='1.0' encoding='UTF-8'?>\n<Empty/>"
        );
    }
}
