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

//! `swift-proxy-server <config.conf>`: loads the account/container/object rings
//! from SWIFT_DIR (default /etc/swift) and serves the v1 REST API. Storage
//! policies (incl. erasure coding) come from SWIFT_CONF; a `[filter:tempauth]`
//! section with `user_*` records turns on tempauth.

use std::sync::Arc;

use swift_core::config::SwiftConfig;
use swift_core::hashing::HashPathConfig;
use swift_core::storage_policy::parse_storage_policies;
use swift_proxy_server::{EcPolicyParams, ProxyApp, ProxyConfig};
use swift_ring::{Ring, RingData};

fn parse_conf_file(path: &str) -> Result<SwiftConfig, String> {
    let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    SwiftConfig::parse_lenient(&content, &[], false).map_err(|e| e.to_string())
}

fn main() {
    let conf_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: swift-proxy-server <config.conf>");
        std::process::exit(1);
    });
    let conf = parse_conf_file(&conf_path).unwrap_or_else(|e| {
        eprintln!("could not read {conf_path}: {e}");
        std::process::exit(1);
    });
    let section = "app:proxy-server";
    let get = |key: &str, default: &str| -> String {
        conf.get(section, key)
            .ok()
            .flatten()
            .or_else(|| conf.get("DEFAULT", key).ok().flatten())
            .unwrap_or_else(|| default.to_string())
    };

    let swift_conf_path =
        std::env::var("SWIFT_CONF").unwrap_or_else(|_| "/etc/swift/swift.conf".to_string());
    let swift_conf = parse_conf_file(&swift_conf_path).unwrap_or_else(|e| {
        eprintln!("could not read {swift_conf_path}: {e}");
        std::process::exit(1);
    });
    let hash_config = HashPathConfig::from_swift_conf(&swift_conf).unwrap_or_else(|e| {
        eprintln!("bad swift.conf hash config: {e}");
        std::process::exit(1);
    });

    let swift_dir = std::env::var("SWIFT_DIR").unwrap_or_else(|_| "/etc/swift".to_string());
    let load_ring = |name: &str| -> Ring {
        let path = format!("{swift_dir}/{name}.ring.gz");
        let data = RingData::load(std::path::Path::new(&path)).unwrap_or_else(|e| {
            eprintln!("could not load {path}: {e}");
            std::process::exit(1);
        });
        Ring::new(data, hash_config.clone())
    };
    // Optional per-policy object rings: object-1.ring.gz, object-2.ring.gz, …
    // (policy 0 is object.ring.gz). Load whichever exist.
    let mut object_rings = std::collections::HashMap::new();
    for policy in 1..=64i64 {
        let path = format!("{swift_dir}/object-{policy}.ring.gz");
        if let Ok(data) = RingData::load(std::path::Path::new(&path)) {
            object_rings.insert(policy, Ring::new(data, hash_config.clone()));
        }
    }

    // Storage policies from swift.conf: EC schemes (by index) and the
    // name→index table for resolving container X-Storage-Policy.
    let policies = parse_storage_policies(&swift_conf).ok();
    let ec_policies = policies
        .as_ref()
        .map(|policies| {
            policies
                .iter()
                .filter_map(|p| {
                    p.ec().map(|ec| {
                        let ndata = ec.ec_ndata as usize;
                        // Python EC quorum = ndata + min_parity (× dup_factor);
                        // recover min_parity so a mis-set config can't silently
                        // change the write quorum.
                        let min_parity = (p.quorum(0.0) as usize).saturating_sub(ndata).max(1);
                        (
                            p.idx() as i64,
                            EcPolicyParams {
                                ndata,
                                nparity: ec.ec_nparity as usize,
                                segment_size: ec.ec_segment_size as usize,
                                min_parity,
                            },
                        )
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let policy_names: std::collections::HashMap<String, i64> = policies
        .as_ref()
        .map(|policies| {
            let mut m = std::collections::HashMap::new();
            for p in policies.iter() {
                m.insert(p.name().to_string(), p.idx() as i64);
                for alias in p.alias_list() {
                    m.insert(alias.clone(), p.idx() as i64);
                }
            }
            m
        })
        .unwrap_or_default();

    // Build tempauth first: whether auth is in the pipeline decides whether the
    // proxy enforces container ACLs (auth_enabled) — so a request path that
    // forgets to authorize cannot silently become world-accessible.
    let tempauth = build_tempauth(&conf, &get("storage_url", "http://127.0.0.1:8080"));
    let config = ProxyConfig {
        account_autocreate: matches!(
            get("account_autocreate", "false").to_lowercase().as_str(),
            "true" | "1" | "yes" | "on" | "t" | "y"
        ),
        auth_enabled: tempauth.is_some(),
        ..Default::default()
    };
    // The object data plane must use object.ring.gz, not the container ring —
    // aliasing them mis-routes every object to the wrong devices.
    let app = Arc::new(
        ProxyApp::with_ec_policies(
            load_ring("account"),
            load_ring("container"),
            load_ring("object"),
            object_rings,
            ec_policies,
            config,
        )
        .with_policy_names(policy_names),
    );

    let bind = format!("{}:{}", get("bind_ip", "0.0.0.0"), get("bind_port", "8080"));
    let listener = std::net::TcpListener::bind(&bind).unwrap_or_else(|e| {
        eprintln!("could not bind {bind}: {e}");
        std::process::exit(1);
    });
    eprintln!("swift-proxy-server listening on {bind}");

    // Pipeline below the always-on front matter: tempauth (authenticate + stamp
    // the group list) then server-side copy (Swift's `... <auth> copy ...
    // proxy-server`), so copy's source-GET / dest-PUT subrequests are ACL-checked.
    let mut filters: Vec<Arc<dyn swift_middleware::Middleware>> = Vec::new();
    if let Some(auth) = tempauth {
        eprintln!("tempauth enabled");
        filters.push(Arc::new(auth));
    }
    filters.push(Arc::new(swift_middleware::Copy::new()));
    // Large objects: reassemble SLO (X-Static-Large-Object) and DLO
    // (X-Object-Manifest) manifests on GET/HEAD. Below copy so their segment
    // subrequests are ACL-checked (they carry the authenticated identity).
    filters.push(Arc::new(swift_middleware::Slo::new()));
    filters.push(Arc::new(swift_middleware::DynamicLargeObject::new()));
    if let Err(e) = swift_proxy_server::serve_with_filters(listener, app, filters) {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}

/// Build a `TempAuth` from a `[filter:tempauth]` section, or `None` if there are
/// no user records (auth stays off). Each `user_<account>_<user> = <key>
/// <group...>` line becomes one credential.
fn build_tempauth(conf: &SwiftConfig, storage_url: &str) -> Option<swift_middleware::TempAuth> {
    let items = conf.items("filter:tempauth").ok()?;
    let mut auth = swift_middleware::TempAuth::new(storage_url.to_string());
    let mut any = false;
    for (key, val) in &items {
        let Some(rest) = key.strip_prefix("user_") else {
            continue;
        };
        // `user_<account>_<user>` — account/user must not contain underscores.
        let Some((account, user)) = rest.split_once('_') else {
            continue;
        };
        let mut toks = val.split_whitespace();
        let Some(secret) = toks.next() else { continue };
        let groups: Vec<&str> = toks.collect();
        auth.add_user(account, user, secret, &groups);
        any = true;
    }
    any.then_some(auth)
}
