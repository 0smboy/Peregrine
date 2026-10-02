// Copyright (c) 2026 OpenStack Foundation
//! Static website hosting from stored `WebsiteConfiguration`.
//!
//! Trigger (does **not** change REST ListObjects on the normal S3 host):
//! * `Host` contains `s3-website` (AWS website-endpoint shape), or
//! * `x-amz-website-endpoint` is present (signed lab / VIP probe).
//!
//! Then GET/HEAD with no listing/config query:
//! * empty key or a key ending in `/` → IndexDocument suffix (default `index.html`)
//! * missing object → ErrorDocument body with HTTP 404 when configured

/// Parsed subset of `WebsiteConfiguration`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebsiteConfig {
    pub index_suffix: String,
    pub error_key: Option<String>,
}

/// True when this request should use the website endpoint, not the REST API.
pub fn is_website_endpoint(host: Option<&str>, website_header: Option<&str>) -> bool {
    if website_header.is_some_and(|v| !v.trim().is_empty()) {
        return true;
    }
    host.is_some_and(|h| h.to_ascii_lowercase().contains("s3-website"))
}

/// Listing / config queries stay on the REST API even on a website host.
pub fn website_object_params(params: &[(String, String)]) -> bool {
    params.iter().all(|(k, _)| k == "versionId")
}

/// Parse IndexDocument / ErrorDocument from stored website XML.
pub fn parse_website_configuration(xml: &[u8]) -> Option<WebsiteConfig> {
    let text = std::str::from_utf8(xml).ok()?;
    if !text.contains("WebsiteConfiguration") {
        return None;
    }
    let suffix = extract_inner(text, "Suffix")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("index.html")
        .to_string();
    if suffix.contains('/') || suffix.contains('\\') || suffix == "." || suffix == ".." {
        return None;
    }
    let error_key = extract_inner(text, "Key")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Some(WebsiteConfig {
        index_suffix: suffix,
        error_key,
    })
}

/// Resolve the object key for a website GET of `/` or a directory prefix.
pub fn resolve_website_key(requested_key: Option<&str>, cfg: &WebsiteConfig) -> String {
    let prefix = requested_key.unwrap_or("");
    if prefix.is_empty() {
        cfg.index_suffix.clone()
    } else if prefix.ends_with('/') {
        format!("{}{}", prefix, cfg.index_suffix)
    } else {
        prefix.to_string()
    }
}

fn extract_inner<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)?;
    Some(&text[start..start + end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_index_and_error() {
        let xml = br#"<WebsiteConfiguration>
          <IndexDocument><Suffix>home.html</Suffix></IndexDocument>
          <ErrorDocument><Key>err.html</Key></ErrorDocument>
        </WebsiteConfiguration>"#;
        let cfg = parse_website_configuration(xml).unwrap();
        assert_eq!(cfg.index_suffix, "home.html");
        assert_eq!(cfg.error_key.as_deref(), Some("err.html"));
    }

    #[test]
    fn parse_index_only_defaults() {
        let xml = b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>";
        let cfg = parse_website_configuration(xml).unwrap();
        assert_eq!(cfg.index_suffix, "index.html");
        assert!(cfg.error_key.is_none());
    }

    #[test]
    fn reject_path_suffix() {
        let xml = b"<WebsiteConfiguration><IndexDocument><Suffix>a/b</Suffix></IndexDocument></WebsiteConfiguration>";
        assert!(parse_website_configuration(xml).is_none());
    }

    #[test]
    fn resolve_root_and_dir() {
        let cfg = WebsiteConfig {
            index_suffix: "index.html".into(),
            error_key: None,
        };
        assert_eq!(resolve_website_key(None, &cfg), "index.html");
        assert_eq!(resolve_website_key(Some(""), &cfg), "index.html");
        assert_eq!(resolve_website_key(Some("docs/"), &cfg), "docs/index.html");
        assert_eq!(resolve_website_key(Some("page.html"), &cfg), "page.html");
    }

    #[test]
    fn endpoint_host_and_header() {
        assert!(is_website_endpoint(Some("bucket.s3-website.local"), None));
        assert!(is_website_endpoint(Some("10.0.0.10:8085"), Some("1")));
        assert!(!is_website_endpoint(Some("10.0.0.10:8085"), None));
        assert!(!is_website_endpoint(Some("10.0.0.10:8085"), Some("")));
    }

    #[test]
    fn object_params_only_version_id() {
        assert!(website_object_params(&[]));
        assert!(website_object_params(&[(
            "versionId".into(),
            "null".into()
        )]));
        assert!(!website_object_params(&[("list-type".into(), "2".into())]));
    }
}
