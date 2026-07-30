//! Swift client: tempauth login, token-refresh retry, and shared listing helpers.

use crate::util::{enc_obj, enc_seg};
use crate::AppState;
use bytes::Bytes;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug)]
pub enum SwiftError {
    /// The console session could not be re-authenticated; caller should
    /// bounce the user to /login.
    Unauthorized,
    Other(String),
}

impl SwiftError {
    pub fn msg(&self) -> String {
        match self {
            SwiftError::Unauthorized => "session expired".into(),
            SwiftError::Other(m) => m.clone(),
        }
    }
}

/// Authenticate against tempauth. Returns (token, storage_url) with the
/// storage URL host rebased onto the configured LB address (the cluster can
/// return a loopback URL).
pub async fn auth(
    http: &reqwest::Client,
    auth_url: &str,
    swift_base: &str,
    tenant: &str,
    user: &str,
    key: &str,
) -> Result<(String, String), String> {
    let resp = http
        .get(auth_url)
        .header("X-Auth-User", format!("{}:{}", tenant, user))
        .header("X-Auth-Key", key)
        .send()
        .await
        .map_err(|e| format!("auth request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("auth rejected ({})", status.as_u16()));
    }
    let token = resp
        .headers()
        .get("x-auth-token")
        .and_then(|v| v.to_str().ok())
        .ok_or("auth response missing token")?
        .to_string();
    let url = resp
        .headers()
        .get("x-storage-url")
        .and_then(|v| v.to_str().ok())
        .ok_or("auth response missing storage url")?
        .to_string();
    // Rebase host onto the LB: keep only the path (/v1/AUTH_x).
    let path = match url.find("/v1/") {
        Some(i) => &url[i..],
        None => return Err(format!("unexpected storage url: {url}")),
    };
    Ok((token, format!("{}{}", swift_base.trim_end_matches('/'), path)))
}

/// One Swift request with a replayable (buffered) body; transparently
/// re-authenticates once on 401 using the credentials stored in the session.
pub async fn call(
    state: &Arc<AppState>,
    sid: &str,
    method: reqwest::Method,
    subpath: &str, // "" for account, "/container" or "/container/obj" (already percent-encoded)
    query: &[(&str, String)],
    headers: &[(String, String)],
    body: Option<Bytes>,
) -> Result<reqwest::Response, SwiftError> {
    for attempt in 0..2 {
        let sess = state
            .sessions
            .get(sid)
            .ok_or(SwiftError::Unauthorized)?;
        let url = format!("{}{}", sess.storage_url, subpath);
        let mut req = state.http.request(method.clone(), &url);
        if !query.is_empty() {
            req = req.query(query);
        }
        req = req.header("X-Auth-Token", &sess.token);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if let Some(b) = &body {
            req = req.body(b.clone());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| SwiftError::Other(format!("swift request failed: {e}")))?;
        if resp.status().as_u16() == 401 && attempt == 0 {
            // Transparent re-auth, once.
            match auth(
                &state.http,
                &state.cfg.auth_url,
                &state.cfg.swift_base,
                &sess.tenant,
                &sess.user,
                &sess.key,
            )
            .await
            {
                Ok((tok, surl)) => {
                    state.sessions.update_token(sid, &tok, &surl);
                    continue;
                }
                Err(_) => return Err(SwiftError::Unauthorized),
            }
        }
        return Ok(resp);
    }
    Err(SwiftError::Unauthorized)
}

/// Streaming-body Swift request (uploads). No retry: the body is consumed.
pub async fn call_stream(
    state: &Arc<AppState>,
    sid: &str,
    method: reqwest::Method,
    subpath: &str,
    query: &[(&str, String)],
    headers: &[(String, String)],
    body: reqwest::Body,
) -> Result<reqwest::Response, SwiftError> {
    let sess = state
        .sessions
        .get(sid)
        .ok_or(SwiftError::Unauthorized)?;
    let url = format!("{}{}", sess.storage_url, subpath);
    let mut req = state.http.request(method, &url);
    if !query.is_empty() {
        req = req.query(query);
    }
    req = req.header("X-Auth-Token", &sess.token);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req
        .body(body)
        .send()
        .await
        .map_err(|e| SwiftError::Other(format!("swift request failed: {e}")))?;
    if resp.status().as_u16() == 401 {
        return Err(SwiftError::Unauthorized);
    }
    Ok(resp)
}

// ---------------------------------------------------------------- listings

#[derive(Deserialize, Clone)]
pub struct BucketEntry {
    pub name: String,
    pub count: u64,
    pub bytes: u64,
}

#[derive(Deserialize, Clone)]
pub struct ObjEntry {
    pub name: Option<String>,
    pub subdir: Option<String>,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub last_modified: Option<String>,
    #[serde(default)]
    pub hash: Option<String>,
}

pub async fn list_buckets(
    state: &Arc<AppState>,
    sid: &str,
) -> Result<Vec<BucketEntry>, SwiftError> {
    let mut out = Vec::new();
    let mut marker = String::new();
    loop {
        let mut q: Vec<(&str, String)> =
            vec![("format", "json".into()), ("limit", "1000".into())];
        if !marker.is_empty() {
            q.push(("marker", marker.clone()));
        }
        let resp = call(state, sid, reqwest::Method::GET, "", &q, &[], None).await?;
        if !resp.status().is_success() {
            return Err(SwiftError::Other(format!(
                "account listing failed ({})",
                resp.status().as_u16()
            )));
        }
        let page: Vec<BucketEntry> = resp
            .json()
            .await
            .map_err(|e| SwiftError::Other(format!("bad account listing: {e}")))?;
        let n = page.len();
        if let Some(last) = page.last() {
            marker = last.name.clone();
        }
        out.extend(page);
        if n < 1000 {
            break;
        }
        if out.len() > 20000 {
            break;
        }
    }
    Ok(out)
}

pub struct Listing {
    pub files: Vec<ObjEntry>,
    pub folders: Vec<String>,
    pub truncated: bool,
}

/// List a container with optional prefix; delimiter "/" unless `flat`.
pub async fn list_objects(
    state: &Arc<AppState>,
    sid: &str,
    bucket: &str,
    prefix: &str,
    flat: bool,
    cap: usize,
) -> Result<Listing, SwiftError> {
    let mut files = Vec::new();
    let mut folders = Vec::new();
    let mut marker = String::new();
    let mut truncated = false;
    loop {
        let mut q: Vec<(&str, String)> =
            vec![("format", "json".into()), ("limit", "1000".into())];
        if !prefix.is_empty() {
            q.push(("prefix", prefix.to_string()));
        }
        if !flat {
            q.push(("delimiter", "/".into()));
        }
        if !marker.is_empty() {
            q.push(("marker", marker.clone()));
        }
        let sub = format!("/{}", enc_seg(bucket));
        let resp = call(state, sid, reqwest::Method::GET, &sub, &q, &[], None).await?;
        let st = resp.status();
        if st.as_u16() == 404 {
            return Err(SwiftError::Other("bucket not found".into()));
        }
        if !st.is_success() {
            return Err(SwiftError::Other(format!(
                "listing failed ({})",
                st.as_u16()
            )));
        }
        let page: Vec<ObjEntry> = resp
            .json()
            .await
            .map_err(|e| SwiftError::Other(format!("bad listing: {e}")))?;
        let n = page.len();
        for e in page {
            if let Some(sd) = &e.subdir {
                marker = sd.clone();
                folders.push(sd.clone());
            } else if let Some(name) = &e.name {
                marker = name.clone();
                // Hide the pseudo-folder marker object for the prefix itself.
                if !flat && name == prefix {
                    continue;
                }
                files.push(e);
            }
        }
        if n < 1000 {
            break;
        }
        if files.len() + folders.len() >= cap {
            truncated = true;
            break;
        }
    }
    Ok(Listing {
        files,
        folders,
        truncated,
    })
}

/// Convenience: HEAD of account/container/object returning the header map.
pub async fn head(
    state: &Arc<AppState>,
    sid: &str,
    subpath: &str,
) -> Result<(u16, reqwest::header::HeaderMap), SwiftError> {
    let resp = call(state, sid, reqwest::Method::HEAD, subpath, &[], &[], None).await?;
    Ok((resp.status().as_u16(), resp.headers().clone()))
}

pub fn obj_subpath(bucket: &str, path: &str) -> String {
    format!("/{}/{}", enc_seg(bucket), enc_obj(path))
}
