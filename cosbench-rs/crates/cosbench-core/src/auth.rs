//! Authentication providers. Keystone v3 password auth (PR #428 / issue #409).

use crate::config::AuthConfig;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use tracing::info;

#[derive(Debug, Clone)]
pub struct AuthResult {
    /// X-Auth-Token / X-Subject-Token
    pub token: String,
    /// Optional public storage URL from the service catalog (object-store / swift)
    pub storage_url: Option<String>,
    pub project_id: Option<String>,
}

pub async fn authenticate(cfg: &AuthConfig) -> anyhow::Result<Option<AuthResult>> {
    match cfg {
        AuthConfig::None => Ok(None),
        AuthConfig::KeystoneV3 {
            url,
            username,
            password,
            project_name,
            user_domain_name,
            project_domain_name,
            user_domain_id,
            project_domain_id,
            timeout_ms,
        } => {
            let r = keystone_v3_password(
                url,
                username,
                password,
                project_name,
                user_domain_name,
                project_domain_name,
                user_domain_id.as_deref(),
                project_domain_id.as_deref(),
                Duration::from_millis(*timeout_ms),
            )
            .await?;
            Ok(Some(r))
        }
        AuthConfig::TempAuth {
            url,
            user,
            key,
            timeout_ms,
        } => {
            let r = swift_v1_auth(url, user, key, Duration::from_millis(*timeout_ms)).await?;
            Ok(Some(r))
        }
    }
}

/// Swift v1 auth (tempauth / swauth). The token and the account storage URL
/// arrive as response headers, not in a body.
async fn swift_v1_auth(
    url: &str,
    user: &str,
    key: &str,
    timeout: Duration,
) -> anyhow::Result<AuthResult> {
    let client = reqwest::Client::builder().timeout(timeout).build()?;
    let resp = client
        .get(url)
        .header("X-Auth-User", user)
        .header("X-Auth-Key", key)
        .send()
        .await?;
    let status = resp.status();
    let hdr = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };
    let token = hdr("x-auth-token");
    let storage_url = hdr("x-storage-url");
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("swift v1 auth failed HTTP {status}: {text}");
    }
    let token = token.ok_or_else(|| anyhow::anyhow!("swift v1 auth response missing X-Auth-Token"))?;
    info!(storage_url = ?storage_url, "swift v1 auth ok");
    Ok(AuthResult {
        token,
        storage_url,
        project_id: None,
    })
}

async fn keystone_v3_password(
    base_url: &str,
    username: &str,
    password: &str,
    project_name: &str,
    user_domain_name: &str,
    project_domain_name: &str,
    user_domain_id: Option<&str>,
    project_domain_id: Option<&str>,
    timeout: Duration,
) -> anyhow::Result<AuthResult> {
    let url = format!("{}/auth/tokens", base_url.trim_end_matches('/'));

    let user_domain = if let Some(id) = user_domain_id {
        json!({ "id": id })
    } else {
        json!({ "name": user_domain_name })
    };
    let project_domain = if let Some(id) = project_domain_id {
        json!({ "id": id })
    } else {
        json!({ "name": project_domain_name })
    };

    let body = json!({
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": user_domain,
                        "password": password
                    }
                }
            },
            "scope": {
                "project": {
                    "name": project_name,
                    "domain": project_domain
                }
            }
        }
    });

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()?;

    let resp = client.post(&url).json(&body).send().await?;
    let status = resp.status();
    let token = resp
        .headers()
        .get("x-subject-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("keystone v3 auth failed HTTP {status}: {text}");
    }
    let token = token.ok_or_else(|| anyhow::anyhow!("keystone response missing X-Subject-Token"))?;

    #[derive(Deserialize)]
    struct TokenResp {
        token: TokenBody,
    }
    #[derive(Deserialize)]
    struct TokenBody {
        #[serde(default)]
        catalog: Vec<CatalogEntry>,
        project: Option<Project>,
    }
    #[derive(Deserialize)]
    struct Project {
        id: Option<String>,
    }
    #[derive(Deserialize)]
    struct CatalogEntry {
        #[serde(rename = "type")]
        type_: Option<String>,
        endpoints: Option<Vec<Endpoint>>,
    }
    #[derive(Deserialize)]
    struct Endpoint {
        interface: Option<String>,
        url: Option<String>,
    }

    let mut storage_url = None;
    let mut project_id = None;
    if let Ok(parsed) = serde_json::from_str::<TokenResp>(&text) {
        project_id = parsed.token.project.and_then(|p| p.id);
        for ent in parsed.token.catalog {
            let t = ent.type_.unwrap_or_default();
            if t == "object-store" || t == "object_store" {
                if let Some(eps) = ent.endpoints {
                    // prefer public
                    storage_url = eps
                        .iter()
                        .find(|e| e.interface.as_deref() == Some("public"))
                        .and_then(|e| e.url.clone())
                        .or_else(|| eps.into_iter().find_map(|e| e.url));
                }
            }
        }
    }

    info!(
        storage_url = ?storage_url,
        project_id = ?project_id,
        "keystone v3 auth ok"
    );

    Ok(AuthResult {
        token,
        storage_url,
        project_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_config_none() {
        // compile-time / type smoke
        let _ = AuthConfig::None;
    }

    #[tokio::test]
    async fn swift_v1_auth_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_lowercase();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nX-Auth-Token: AUTH_tk_abc\r\nX-Storage-Url: http://{addr}/v1/AUTH_test\r\nContent-Length: 0\r\n\r\n"
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            req
        });
        let cfg = AuthConfig::TempAuth {
            url: format!("http://{addr}/auth/v1.0"),
            user: "test:tester".into(),
            key: "testing".into(),
            timeout_ms: 5_000,
        };
        let r = authenticate(&cfg).await.unwrap().unwrap();
        assert_eq!(r.token, "AUTH_tk_abc");
        assert_eq!(
            r.storage_url.as_deref(),
            Some(format!("http://{addr}/v1/AUTH_test").as_str())
        );
        let req = server.await.unwrap();
        assert!(req.starts_with("get /auth/v1.0 "), "request line: {req}");
        assert!(req.contains("x-auth-user: test:tester"));
        assert!(req.contains("x-auth-key: testing"));
    }

    #[test]
    fn temp_auth_yaml_parses() {
        let yaml = r#"
type: temp_auth
url: http://127.0.0.1:8080/auth/v1.0
user: test:tester
key: testing
"#;
        let cfg: AuthConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(matches!(cfg, AuthConfig::TempAuth { .. }));
    }
}
