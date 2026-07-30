//! Ring and storage-policy access: the only module that knows what a ring file
//! is or where `swift.conf` lives.
//!
//! The console cannot link the `swift-ring` crate — that workspace is a
//! separate repo with deliberately near-zero dependencies and no async runtime
//! — so ring work is delegated to the installed CLI binaries. That is a feature
//! rather than a compromise: `swift-ring-sim` runs the *real* placement
//! algorithm, so a simulation cannot drift from what a rebalance would actually
//! do, and it has no write path at all.

// Ring/policy access for the Lab surfaces; consumers land feature by feature.
#![allow(dead_code)]

use crate::nodes;
use crate::AppState;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;

#[derive(Serialize, Clone, Debug)]
pub struct PolicyInfo {
    pub index: u32,
    pub name: String,
    /// "replication" | "erasure_coding"
    pub kind: String,
    pub is_default: bool,
    pub is_deprecated: bool,
    pub ec_type: Option<String>,
    pub ec_ndata: Option<u32>,
    pub ec_nparity: Option<u32>,
    pub ec_segment_size: Option<u64>,
    /// The ring file for this policy: object.ring.gz / object-N.ring.gz.
    pub ring_file: String,
    /// The on-disk data directory: objects / objects-N.
    pub data_dir: String,
}

impl PolicyInfo {
    /// Fragments (EC) or replicas (replication) needed for a readable object.
    pub fn min_readable(&self, replicas: u64) -> u64 {
        match self.ec_ndata {
            Some(k) => k as u64,
            None => 1,
        }
        .max(1)
        .min(replicas.max(1))
    }
    /// Replica slots that must accept a write for it to succeed.
    ///
    /// Replication takes a majority, so 3 replicas survive one node down. EC
    /// needs `k + min_parity_needed(ec_type)`, which for 2+1 is all three
    /// fragments — one node down and writes to that policy stop. Scoring EC
    /// with the replication majority made a scenario report "0 partitions
    /// below quorum" for a policy that in fact could not be written to at all.
    pub fn write_quorum(&self, replicas: u64) -> u64 {
        match (self.ec_ndata, self.ec_nparity) {
            (Some(k), Some(_)) => {
                let ec_type = self.ec_type.as_deref().unwrap_or("");
                (k as u64) + crate::economist::min_parity_needed(ec_type) as u64
            }
            _ => replicas.max(1) / 2 + 1,
        }
        .clamp(1, replicas.max(1))
    }
    pub fn is_ec(&self) -> bool {
        self.kind == "erasure_coding"
    }
}

fn ring_file(index: u32) -> String {
    if index == 0 {
        "object.ring.gz".into()
    } else {
        format!("object-{index}.ring.gz")
    }
}
fn data_dir(index: u32) -> String {
    if index == 0 {
        "objects".into()
    } else {
        format!("objects-{index}")
    }
}

/// Parse the `[storage-policy:N]` stanzas of a swift.conf.
fn parse_policies(conf: &str) -> Vec<PolicyInfo> {
    let mut out: Vec<PolicyInfo> = Vec::new();
    let mut cur: Option<PolicyInfo> = None;
    for raw in conf.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if let Some(p) = cur.take() {
                out.push(p);
            }
            if let Some(rest) = line
                .trim_start_matches('[')
                .trim_end_matches(']')
                .strip_prefix("storage-policy:")
            {
                if let Ok(idx) = rest.trim().parse::<u32>() {
                    cur = Some(PolicyInfo {
                        index: idx,
                        name: format!("Policy-{idx}"),
                        kind: "replication".into(),
                        is_default: false,
                        is_deprecated: false,
                        ec_type: None,
                        ec_ndata: None,
                        ec_nparity: None,
                        ec_segment_size: None,
                        ring_file: ring_file(idx),
                        data_dir: data_dir(idx),
                    });
                }
            }
            continue;
        }
        let Some(p) = cur.as_mut() else { continue };
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim().to_lowercase(), v.trim());
        let truthy = matches!(v.to_lowercase().as_str(), "yes" | "true" | "1" | "on");
        match k.as_str() {
            "name" => p.name = v.to_string(),
            "policy_type" => p.kind = v.to_string(),
            "default" => p.is_default = truthy,
            "deprecated" => p.is_deprecated = truthy,
            "ec_type" => p.ec_type = Some(v.to_string()),
            "ec_num_data_fragments" => p.ec_ndata = v.parse().ok(),
            "ec_num_parity_fragments" => p.ec_nparity = v.parse().ok(),
            "ec_object_segment_size" => p.ec_segment_size = v.parse().ok(),
            _ => {}
        }
    }
    if let Some(p) = cur.take() {
        out.push(p);
    }
    // A swift.conf with no stanza still has the implicit Policy-0.
    if out.is_empty() {
        out.push(PolicyInfo {
            index: 0,
            name: "Policy-0".into(),
            kind: "replication".into(),
            is_default: true,
            is_deprecated: false,
            ec_type: None,
            ec_ndata: None,
            ec_nparity: None,
            ec_segment_size: None,
            ring_file: ring_file(0),
            data_dir: data_dir(0),
        });
    }
    out.sort_by_key(|p| p.index);
    out
}

/// Storage policies, cached briefly — swift.conf changes at deploy time, not
/// per request, and every Lab page wants this.
pub async fn policies(state: &Arc<AppState>) -> Result<Vec<PolicyInfo>, String> {
    {
        let c = state.policy_cache.lock().unwrap();
        if let Some((at, ref v)) = *c {
            if at.elapsed().as_secs() < 60 {
                return Ok(v.clone());
            }
        }
    }
    let path = format!("{}/swift.conf", state.cfg.swift_dir.trim_end_matches('/'));
    let conf = tokio::fs::read_to_string(&path)
        .await
        .map_err(|e| format!("could not read {path}: {e}"))?;
    let list = parse_policies(&conf);
    *state.policy_cache.lock().unwrap() = Some((Instant::now(), list.clone()));
    Ok(list)
}

pub async fn policy(state: &Arc<AppState>, index: u32) -> Result<PolicyInfo, String> {
    policies(state)
        .await?
        .into_iter()
        .find(|p| p.index == index)
        .ok_or_else(|| format!("no storage policy {index}"))
}

pub async fn policy_by_name(state: &Arc<AppState>, name: &str) -> Option<PolicyInfo> {
    let list = policies(state).await.ok()?;
    // A container's X-Storage-Policy carries the name; fall back to the default.
    list.iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
        .or_else(|| list.iter().find(|p| p.is_default))
        .or_else(|| list.first())
        .cloned()
}

pub async fn default_policy(state: &Arc<AppState>) -> Result<PolicyInfo, String> {
    let list = policies(state).await?;
    Ok(list
        .iter()
        .find(|p| p.is_default)
        .or_else(|| list.first())
        .cloned()
        .ok_or("no storage policies")?)
}

fn ring_path(state: &Arc<AppState>, p: &PolicyInfo) -> String {
    format!("{}/{}", state.cfg.swift_dir.trim_end_matches('/'), p.ring_file)
}

// ------------------------------------------------------------- ring queries

/// Ring topology for a policy. The path is built from config plus the policy's
/// own ring name — never from anything a caller supplies.
pub async fn topology(state: &Arc<AppState>, index: u32) -> Result<Value, String> {
    let p = policy(state, index).await?;
    let path = ring_path(state, &p);
    let out = nodes::local(&[&state.cfg.ringsim_bin, "inspect", &path, "--json"], None).await?;
    serde_json::from_str(&out).map_err(|e| format!("bad ring output: {e}"))
}

/// Run a what-if scenario against a copy of the ring. The scenario is validated
/// by the caller and passed on stdin, so it can never become argv.
pub async fn simulate(
    state: &Arc<AppState>,
    index: u32,
    scenario: &Value,
) -> Result<Value, String> {
    let p = policy(state, index).await?;
    let path = ring_path(state, &p);
    let body = serde_json::to_vec(scenario).map_err(|e| e.to_string())?;
    let out = nodes::local(
        &[&state.cfg.ringsim_bin, "simulate", &path, "--json"],
        Some(&body),
    )
    .await?;
    serde_json::from_str(&out).map_err(|e| format!("bad simulate output: {e}"))
}

#[derive(Serialize, Clone, Debug)]
pub struct PlacedNode {
    pub dev_id: u64,
    pub node: String,
    pub ip: String,
    pub port: u16,
    pub device: String,
    pub region: u64,
    pub zone: u64,
    pub index: usize,
    pub handoff: bool,
}

#[derive(Serialize, Clone, Debug)]
pub struct Located {
    pub policy: u32,
    pub partition: u32,
    pub hash: String,
    pub primaries: Vec<PlacedNode>,
    pub handoffs: Vec<PlacedNode>,
}

/// Where an object lives: partition, hash, primaries and handoffs.
pub async fn locate(
    state: &Arc<AppState>,
    index: u32,
    account: &str,
    container: Option<&str>,
    object: Option<&str>,
) -> Result<Located, String> {
    let p = policy(state, index).await?;
    let path = ring_path(state, &p);
    located_from_ring(state, &path, index, account, container, object).await
}

/// Locate a container on the *container* ring (not an object policy ring), so a
/// caller can reach the container server that actually owns it. Used by the
/// Tombstone Museum's policy-lookup fallback.
pub async fn locate_container(
    state: &Arc<AppState>,
    account: &str,
    container: &str,
) -> Result<Located, String> {
    let path = format!(
        "{}/container.ring.gz",
        state.cfg.swift_dir.trim_end_matches('/')
    );
    located_from_ring(state, &path, 0, account, Some(container), None).await
}

/// Run `swift-get-nodes --json <ring> <account> [container] [object]` and parse
/// the placement. Shared by the object-policy and container-ring locates.
#[allow(clippy::too_many_arguments)]
async fn located_from_ring(
    state: &Arc<AppState>,
    ring_path: &str,
    policy: u32,
    account: &str,
    container: Option<&str>,
    object: Option<&str>,
) -> Result<Located, String> {
    let mut argv: Vec<&str> = vec![&state.cfg.getnodes_bin, "--json", ring_path, account];
    if let Some(c) = container {
        argv.push(c);
    }
    if let Some(o) = object {
        argv.push(o);
    }
    let out = nodes::local(&argv, None).await?;
    let v: Value = serde_json::from_str(&out).map_err(|e| format!("bad get-nodes output: {e}"))?;
    let mut primaries = Vec::new();
    let mut handoffs = Vec::new();
    for n in v.get("nodes").and_then(|x| x.as_array()).unwrap_or(&vec![]) {
        let ip = n.get("ip").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let placed = PlacedNode {
            dev_id: n.get("dev_id").and_then(|x| x.as_u64()).unwrap_or(0),
            node: nodes::label(state, &ip),
            ip,
            port: n.get("port").and_then(|x| x.as_u64()).unwrap_or(6200) as u16,
            device: n.get("device").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            region: n.get("region").and_then(|x| x.as_u64()).unwrap_or(1),
            zone: n.get("zone").and_then(|x| x.as_u64()).unwrap_or(1),
            index: n.get("index").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
            handoff: n.get("handoff").and_then(|x| x.as_bool()).unwrap_or(false),
        };
        if placed.handoff {
            handoffs.push(placed);
        } else {
            primaries.push(placed);
        }
    }
    Ok(Located {
        policy,
        partition: v.get("partition").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        hash: v.get("hash").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        primaries,
        handoffs,
    })
}

// ------------------------------------------------------------- capacity

#[derive(Serialize, Clone, Debug)]
pub struct DeviceUsage {
    pub node: String,
    pub device: String,
    pub used: u64,
    pub size: u64,
}

/// Live per-device bytes. RingScope turns "replica slots moved" into "bytes
/// that have to cross the network" with this — the CLI knows slots, only the
/// cluster knows bytes.
/// Every (node, device) pair the rings actually reference, across all policies.
///
/// The ring is the authority on what the cluster is made of; the config file's
/// per-node `devices` list is only a bootstrap hint. A hand-maintained list
/// goes stale the moment a disk is added — which is precisely when capacity
/// numbers matter most — and the failure is silent: `df` is simply never run
/// against the new device, so it vanishes from every derived figure instead of
/// reporting an error. Falls back to the configured list when no ring can be
/// read, so a half-configured cluster still shows something.
pub async fn ring_devices(state: &Arc<AppState>) -> Vec<(String, String)> {
    let mut seen: std::collections::BTreeSet<(String, String)> = Default::default();
    for p in policies(state).await.unwrap_or_default() {
        let Ok(topo) = topology(state, p.index).await else {
            continue;
        };
        let devs = topo
            .get("devices")
            .and_then(|d| d.as_array())
            .cloned()
            .unwrap_or_default();
        for d in devs {
            let (Some(ip), Some(dev)) = (
                d.get("ip").and_then(|v| v.as_str()),
                d.get("device").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            seen.insert((nodes::label(state, ip), dev.to_string()));
        }
    }
    if seen.is_empty() {
        return nodes::all(state)
            .into_iter()
            .flat_map(|n| {
                let name = n.name.clone();
                n.devices.into_iter().map(move |d| (name.clone(), d))
            })
            .collect();
    }
    seen.into_iter().collect()
}

pub async fn device_usage(state: &Arc<AppState>) -> Vec<DeviceUsage> {
    let root = state.cfg.node_root.trim_end_matches('/').to_string();
    let jobs: Vec<(String, String)> = ring_devices(state)
        .await
        .into_iter()
        .map(|(node, d)| {
            (
                node,
                format!("df -B1 --output=used,size {root}/{d} 2>/dev/null | tail -1; echo {d}"),
            )
        })
        .collect();
    let results = nodes::fan_out_each(state, jobs).await;
    let mut out = Vec::new();
    for r in results {
        if !r.ok {
            continue;
        }
        let mut lines = r.out.lines();
        let nums: Vec<u64> = lines
            .next()
            .unwrap_or("")
            .split_whitespace()
            .filter_map(|x| x.parse().ok())
            .collect();
        let device = lines.next().unwrap_or("").trim().to_string();
        if nums.len() == 2 {
            out.push(DeviceUsage {
                node: r.node,
                device,
                used: nums[0],
                size: nums[1],
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "\
[swift-hash]
swift_hash_path_prefix = abc

[storage-policy:0]
name = default
default = yes

[storage-policy:1]
name = ec-2-1
policy_type = erasure_coding
ec_type = liberasurecode_rs_vand
ec_num_data_fragments = 2
ec_num_parity_fragments = 1
ec_object_segment_size = 1048576
";

    #[test]
    fn write_quorum_is_a_majority_for_replication_and_k_plus_parity_for_ec() {
        let p = parse_policies(CONF);
        // 3 replicas: a majority is 2, so one node down still accepts writes.
        assert_eq!(p[0].write_quorum(3), 2);
        // EC 2+1 over rs_vand: k(2) + min_parity_needed(1) = 3 of 3. This is
        // the case that was scored as a majority and so wrongly reported as
        // surviving a node loss.
        assert_eq!(p[1].write_quorum(3), 3);
    }

    #[test]
    fn ec_write_quorum_never_exceeds_the_replica_count() {
        let p = parse_policies(CONF);
        // A caller passing a smaller ring must not get a quorum it can never
        // reach; the clamp keeps the figure answerable.
        assert_eq!(p[1].write_quorum(2), 2);
        assert_eq!(p[1].write_quorum(1), 1);
    }

    #[test]
    fn parses_replication_and_ec_policies() {
        let p = parse_policies(CONF);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].index, 0);
        assert_eq!(p[0].name, "default");
        assert!(p[0].is_default);
        assert!(!p[0].is_ec());
        assert_eq!(p[0].ring_file, "object.ring.gz");
        assert_eq!(p[0].data_dir, "objects");

        assert_eq!(p[1].index, 1);
        assert_eq!(p[1].name, "ec-2-1");
        assert!(p[1].is_ec());
        assert_eq!(p[1].ec_ndata, Some(2));
        assert_eq!(p[1].ec_nparity, Some(1));
        assert_eq!(p[1].ring_file, "object-1.ring.gz");
        assert_eq!(p[1].data_dir, "objects-1");
    }

    #[test]
    fn min_readable_is_k_for_ec_and_one_for_replication() {
        let p = parse_policies(CONF);
        assert_eq!(p[0].min_readable(3), 1, "one replica is enough to read");
        assert_eq!(p[1].min_readable(3), 2, "EC needs k fragments");
    }

    #[test]
    fn empty_conf_still_yields_policy_zero() {
        let p = parse_policies("[swift-hash]\nswift_hash_path_prefix = x\n");
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].index, 0);
        assert!(p[0].is_default);
    }

    #[test]
    fn comments_and_case_are_handled() {
        let p = parse_policies("[storage-policy:0]\n# name = wrong\nName = Right\nDefault = True\n");
        assert_eq!(p[0].name, "Right");
        assert!(p[0].is_default);
    }
}
