use anyhow::{bail, Context, Result};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct S3Creds {
    pub access_key: String,
    pub secret_key: String,
    pub endpoint: String, // host:port, no scheme
}

#[derive(Debug, Clone)]
pub struct SwiftCreds {
    pub auth_url: String, // full v1 auth URL, e.g. http://host:8080/auth/v1.0
    pub user: String,     // account:user, e.g. test:tester
    pub key: String,
}

/// Credentials for whichever storage backend the run targets.
#[derive(Debug, Clone)]
pub enum Creds {
    S3(S3Creds),
    Swift(SwiftCreds),
}

pub fn cabt_home() -> PathBuf {
    dirs_fallback_home().join(".cabt")
}

fn dirs_fallback_home() -> PathBuf {
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h);
    }
    PathBuf::from("/root")
}

pub fn ensure_dirs() -> Result<()> {
    let home = cabt_home();
    for sub in ["config", "result", "fool", "lib"] {
        fs::create_dir_all(home.join(sub))?;
    }
    Ok(())
}

pub fn load_s3_creds() -> Result<S3Creds> {
    let access = std::env::var("accesskey")
        .or_else(|_| std::env::var("ACCESSKEY"))
        .ok();
    let secret = std::env::var("secretkey")
        .or_else(|_| std::env::var("SECRETKEY"))
        .ok();
    let endpoint = std::env::var("endpoint")
        .or_else(|_| std::env::var("ENDPOINT"))
        .ok();

    if let (Some(a), Some(s), Some(e)) = (access, secret, endpoint) {
        return Ok(S3Creds {
            access_key: a,
            secret_key: s,
            endpoint: strip_scheme(&e),
        });
    }

    // ~/.s3cfg
    let s3cfg = dirs_fallback_home().join(".s3cfg");
    if s3cfg.is_file() {
        let text = fs::read_to_string(&s3cfg)?;
        let mut access_key = String::new();
        let mut secret_key = String::new();
        let mut host_base = String::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("access_key") {
                access_key = v.trim().trim_start_matches('=').trim().to_string();
            } else if let Some(v) = line.strip_prefix("secret_key") {
                secret_key = v.trim().trim_start_matches('=').trim().to_string();
            } else if let Some(v) = line.strip_prefix("host_base") {
                host_base = v.trim().trim_start_matches('=').trim().to_string();
            }
        }
        if !access_key.is_empty() && !secret_key.is_empty() && !host_base.is_empty() {
            return Ok(S3Creds {
                access_key,
                secret_key,
                endpoint: strip_scheme(&host_base),
            });
        }
    }

    bail!(
        "Missing S3 credentials. Set accesskey/secretkey/endpoint env or ~/.s3cfg (access_key, secret_key, host_base)."
    );
}

/// True when the classic Swift client env (ST_AUTH) is set — used to
/// auto-select the Swift driver under the default backend.
pub fn swift_env_present() -> bool {
    std::env::var("ST_AUTH").is_ok() || std::env::var("st_auth").is_ok()
}

pub fn load_swift_creds() -> Result<SwiftCreds> {
    let get = |a: &str, b: &str| std::env::var(a).or_else(|_| std::env::var(b)).ok();
    match (
        get("ST_AUTH", "st_auth"),
        get("ST_USER", "st_user"),
        get("ST_KEY", "st_key"),
    ) {
        (Some(a), Some(u), Some(k)) => Ok(SwiftCreds {
            auth_url: a.trim().to_string(),
            user: u,
            key: k,
        }),
        _ => bail!(
            "Missing Swift credentials. Set ST_AUTH (e.g. http://host:8080/auth/v1.0), ST_USER (account:user) and ST_KEY."
        ),
    }
}

pub fn probe_swift(creds: &SwiftCreds) -> Result<()> {
    if std::env::var("CABT_SKIP_S3_PROBE").ok().as_deref() == Some("1") {
        return Ok(());
    }
    let hp = creds
        .auth_url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let hp = hp.split('/').next().unwrap_or(hp);
    let addr = if hp.contains(':') {
        hp.to_string()
    } else {
        format!("{hp}:80")
    };
    use std::net::ToSocketAddrs;
    let sa = addr
        .to_socket_addrs()
        .with_context(|| format!("resolve {addr}"))?
        .next()
        .with_context(|| format!("no address for {addr}"))?;
    std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(3))
        .with_context(|| format!("cannot reach Swift auth endpoint {addr}"))?;
    Ok(())
}

fn strip_scheme(s: &str) -> String {
    s.trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string()
}

pub fn endpoint_url(host: &str) -> String {
    if host.starts_with("http://") || host.starts_with("https://") {
        host.to_string()
    } else {
        format!("http://{host}")
    }
}

/// Optional probe: HEAD/PUT not required for local mock; skip if CABT_SKIP_S3_PROBE=1
pub fn probe_s3(creds: &S3Creds) -> Result<()> {
    if std::env::var("CABT_SKIP_S3_PROBE").ok().as_deref() == Some("1") {
        return Ok(());
    }
    // lightweight TCP connect check to host:port
    let hostport = &creds.endpoint;
    let (host, port) = if let Some((h, p)) = hostport.rsplit_once(':') {
        (h, p.parse::<u16>().unwrap_or(80))
    } else {
        (hostport.as_str(), 80)
    };
    let addr = format!("{host}:{port}");
    std::net::TcpStream::connect_timeout(
        &addr.parse().with_context(|| format!("parse {addr}"))?,
        std::time::Duration::from_secs(3),
    )
    .with_context(|| format!("cannot reach S3 endpoint {addr}"))?;
    Ok(())
}
