//! Minimal COSBench workload XML → Workload mapping.

use crate::config::{
    AuthConfig, IdRange, ObjectSpec, Operation, Stage, StorageConfig, Workload,
};
use std::collections::HashMap;

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("{name}=\"");
    let i = tag.find(&key)?;
    let rest = &tag[i + key.len()..];
    let j = rest.find('"')?;
    Some(&rest[..j])
}

pub fn import_cosbench_xml(xml: &str) -> anyhow::Result<Workload> {
    let name = xml
        .lines()
        .find(|l| l.contains("<workload"))
        .and_then(|l| attr(l, "name"))
        .unwrap_or("imported")
        .to_string();

    let storage = if let Some(line) = xml.lines().find(|l| l.contains("<storage")) {
        let ty = attr(line, "type").unwrap_or("s3");
        let conf = attr(line, "config").unwrap_or("");
        parse_storage(ty, conf)
    } else {
        StorageConfig::Mock { latency_us: 0 }
    };

    let auth = xml.lines().find(|l| l.contains("<auth")).and_then(|line| {
        let ty = attr(line, "type").unwrap_or("");
        let conf = attr(line, "config").unwrap_or("");
        parse_auth(ty, conf)
    });

    let mut stage_meta = Vec::new();
    for line in xml.lines() {
        if !line.contains("<work ") {
            continue;
        }
        let wname = attr(line, "name").unwrap_or("work").to_string();
        let workers: u32 = attr(line, "workers").and_then(|s| s.parse().ok()).unwrap_or(1);
        let runtime_secs: u64 = attr(line, "runtime").and_then(|s| s.parse().ok()).unwrap_or(0);
        let total_ops: u64 = attr(line, "totalOps")
            .or_else(|| attr(line, "totalops"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let kind = if wname.contains("init") {
            "init"
        } else if wname.contains("prep") {
            "prepare"
        } else if wname.contains("clean") || wname.contains("dispose") {
            "cleanup"
        } else {
            "main"
        }
        .to_string();
        stage_meta.push((wname, workers, runtime_secs, total_ops, kind));
    }

    let mut ops = Vec::new();
    for line in xml.lines() {
        if !line.contains("<operation") {
            continue;
        }
        let ty = attr(line, "type").unwrap_or("read").to_string();
        let ratio: u32 = attr(line, "ratio").and_then(|s| s.parse().ok()).unwrap_or(100);
        let conf = attr(line, "config").unwrap_or("");
        let mut config = HashMap::new();
        for pair in conf.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if let Some((k, v)) = pair.split_once('=') {
                config.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
        ops.push(Operation {
            op_type: ty,
            ratio,
            config,
        });
    }
    if ops.is_empty() {
        ops.push(Operation {
            op_type: "write".into(),
            ratio: 100,
            config: HashMap::new(),
        });
    }

    let mut objects = ObjectSpec {
        cprefix: "container".into(),
        containers: IdRange { start: 1, end: 1 },
        oprefix: "object".into(),
        objects: IdRange { start: 1, end: 100 },
        size: 64 * 1024,
        size_min: 0,
        size_max: 0,
        hash_check: false,
    };
    if let Some(op) = ops.first() {
        if let Some(sz) = op.config.get("sizes").or_else(|| op.config.get("size")) {
            if let Some(n) = parse_size_token(sz) {
                objects.size = n;
            }
        }
        if let Some(c) = op.config.get("containers") {
            if let Some((a, b)) = parse_c_range(c) {
                objects.containers = IdRange { start: a, end: b };
            }
        }
        if let Some(o) = op.config.get("objects") {
            if let Some((a, b)) = parse_c_range(o) {
                objects.objects = IdRange { start: a, end: b };
            }
        }
    }

    let stages: Vec<Stage> = if stage_meta.is_empty() {
        vec![Stage {
            name: "main".into(),
            kind: "main".into(),
            workers: 1,
            runtime_secs: 30,
            total_ops: 0,
            operations: ops.clone(),
            objects: objects.clone(),
            sequential: false,
        }]
    } else {
        stage_meta
            .into_iter()
            .map(|(wname, workers, runtime_secs, total_ops, kind)| {
                let sequential = kind == "prepare" || kind == "cleanup" || kind == "init";
                Stage {
                    name: wname,
                    kind: kind.clone(),
                    workers,
                    runtime_secs,
                    total_ops,
                    operations: ops.clone(),
                    objects: objects.clone(),
                    sequential,
                }
            })
            .collect()
    };

    let wl = Workload {
        name,
        description: "imported from COSBench XML (best-effort)".into(),
        storage,
        auth,
        stages,
    };
    wl.validate()?;
    Ok(wl)
}

fn parse_storage(ty: &str, conf: &str) -> StorageConfig {
    let mut map = HashMap::new();
    for pair in conf.split(';') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    match ty.to_ascii_lowercase().as_str() {
        "s3" | "amazons3" => StorageConfig::S3 {
            endpoint: map.get("endpoint").cloned(),
            region: map.get("region").cloned().unwrap_or_else(|| "us-east-1".into()),
            access_key: map
                .get("accesskey")
                .or_else(|| map.get("access_key"))
                .cloned()
                .unwrap_or_default(),
            secret_key: map
                .get("secretkey")
                .or_else(|| map.get("secret_key"))
                .cloned()
                .unwrap_or_default(),
            path_style: map
                .get("path_style_access")
                .map(|v| v == "true")
                .unwrap_or(true),
            timeout_ms: 60_000,
            multipart_threshold: 8 * 1024 * 1024,
            multipart_part_size: 8 * 1024 * 1024,
        },
        "swift" => StorageConfig::Swift {
            endpoint: map
                .get("endpoint")
                .or_else(|| map.get("url"))
                .cloned()
                .unwrap_or_default(),
            timeout_ms: 60_000,
            token: map.get("token").cloned(),
        },
        _ => StorageConfig::Mock { latency_us: 0 },
    }
}

fn parse_auth(ty: &str, conf: &str) -> Option<AuthConfig> {
    let mut map = HashMap::new();
    for pair in conf.split(';') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    match ty.to_ascii_lowercase().as_str() {
        "keystone" | "keystonev3" | "keystone_v3" => Some(AuthConfig::KeystoneV3 {
            url: map
                .get("url")
                .or_else(|| map.get("auth_url"))
                .cloned()
                .unwrap_or_default(),
            username: map.get("username").cloned().unwrap_or_default(),
            password: map.get("password").cloned().unwrap_or_default(),
            project_name: map
                .get("project_name")
                .or_else(|| map.get("tenant_name"))
                .cloned()
                .unwrap_or_default(),
            user_domain_name: map
                .get("user_domain_name")
                .cloned()
                .unwrap_or_else(|| "Default".into()),
            project_domain_name: map
                .get("project_domain_name")
                .cloned()
                .unwrap_or_else(|| "Default".into()),
            user_domain_id: map.get("user_domain_id").cloned(),
            project_domain_id: map.get("project_domain_id").cloned(),
            timeout_ms: 60_000,
        }),
        _ => None,
    }
}

fn parse_c_range(s: &str) -> Option<(u64, u64)> {
    let i = s.find('(')?;
    let j = s.find(')')?;
    let inner = &s[i + 1..j];
    let parts: Vec<_> = inner.split(',').map(|x| x.trim()).collect();
    if parts.len() == 1 {
        let a: u64 = parts[0].parse().ok()?;
        Some((a, a))
    } else if parts.len() >= 2 {
        Some((parts[0].parse().ok()?, parts[1].parse().ok()?))
    } else {
        None
    }
}

fn parse_size_token(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_uppercase();
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    let n: u64 = digits.parse().ok()?;
    if s.contains("GB") {
        Some(n * 1024 * 1024 * 1024)
    } else if s.contains("MB") {
        Some(n * 1024 * 1024)
    } else if s.contains("KB") {
        Some(n * 1024)
    } else {
        Some(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn import_minimal() {
        let xml = r#"
<workload name="w1" description="d">
  <storage type="s3" config="endpoint=http://127.0.0.1:9000;accesskey=a;secretkey=b;path_style_access=true" />
  <workflow>
    <workstage name="s1">
      <work name="main" workers="4" runtime="10">
        <operation type="write" ratio="50" config="containers=c(1);objects=c(1,100);sizes=64KB" />
        <operation type="read" ratio="50" config="containers=c(1);objects=c(1,100)" />
      </work>
    </workstage>
  </workflow>
</workload>
"#;
        let wl = import_cosbench_xml(xml).unwrap();
        assert_eq!(wl.name, "w1");
        assert!(!wl.stages.is_empty());
    }
}
