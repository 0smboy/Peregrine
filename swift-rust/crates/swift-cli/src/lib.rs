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

//! CLI and ops tooling, ported from `swift/cli/`. Each tool is a small
//! consumer of the finished swift-core / swift-ring crates.

pub mod auditor_daemon;
pub mod daemon;
pub mod dark_data;
pub mod dispersion;
pub mod drive_audit;
pub mod info;
pub mod recon;
pub mod ringsim;
pub mod space_metrics;

use swift_core::hashing::HashPathConfig;
use swift_ring::{Ring, RingError};

/// Port of `swift-get-nodes`: the primary nodes plus (optionally) the
/// handoff nodes responsible for an item or a raw partition. Returns the
/// human-readable report Python prints.
pub struct GetNodesReport {
    pub account: Option<String>,
    pub container: Option<String>,
    pub object: Option<String>,
    pub partition: u32,
    pub hash: Option<String>,
    pub nodes: Vec<PlacedNode>,
}

/// One node responsible for a partition. Carries the ring identity
/// (`dev_id`/`region`/`zone`) as well as the endpoint, so callers can group by
/// failure domain without re-reading the ring.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PlacedNode {
    pub dev_id: u64,
    pub region: u64,
    pub zone: u64,
    pub ip: String,
    pub port: u32,
    pub replication_ip: String,
    pub replication_port: u32,
    pub device: String,
    /// Position among the primaries, or the handoff index.
    pub index: usize,
    pub handoff: bool,
}

fn placed(dev: &swift_ring::RingDevice, index: usize, handoff: bool) -> PlacedNode {
    PlacedNode {
        dev_id: dev.id,
        region: dev.region,
        zone: dev.zone,
        ip: dev.ip.clone(),
        port: dev.port,
        replication_ip: dev.replication_ip.clone().unwrap_or_else(|| dev.ip.clone()),
        replication_port: dev.replication_port.unwrap_or(dev.port),
        device: dev.device.clone(),
        index,
        handoff,
    }
}

impl GetNodesReport {
    /// Compute for an account[/container[/object]].
    pub fn for_item(
        ring: &Ring,
        hash_config: &HashPathConfig,
        account: &str,
        container: Option<&str>,
        object: Option<&str>,
        all_handoffs: bool,
    ) -> Result<GetNodesReport, RingError> {
        let (part, nodes) = ring.get_nodes(account, container, object)?;
        let mut out: Vec<PlacedNode> = nodes
            .iter()
            .map(|n| placed(n.dev, n.index, false))
            .collect();
        let handoffs = ring.get_more_nodes(part)?;
        let take = if all_handoffs {
            handoffs.len()
        } else {
            nodes.len()
        };
        for h in handoffs.iter().take(take) {
            out.push(placed(h.dev, h.handoff_index, true));
        }
        let hash = hash_config.hash_path(account, container, object).ok();
        Ok(GetNodesReport {
            account: Some(account.to_string()),
            container: container.map(str::to_string),
            object: object.map(str::to_string),
            partition: part,
            hash,
            nodes: out,
        })
    }

    /// Compute for a raw partition number.
    pub fn for_partition(
        ring: &Ring,
        part: u32,
        all_handoffs: bool,
    ) -> Result<GetNodesReport, RingError> {
        let nodes = ring.get_part_nodes(part)?;
        let mut out: Vec<PlacedNode> = nodes
            .iter()
            .map(|n| placed(n.dev, n.index, false))
            .collect();
        let handoffs = ring.get_more_nodes(part)?;
        let take = if all_handoffs {
            handoffs.len()
        } else {
            nodes.len()
        };
        for h in handoffs.iter().take(take) {
            out.push(placed(h.dev, h.handoff_index, true));
        }
        Ok(GetNodesReport {
            account: None,
            container: None,
            object: None,
            partition: part,
            hash: None,
            nodes: out,
        })
    }

    /// Render like `swift-get-nodes` (the lines the tests check).
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Partition\t{}\n", self.partition));
        if let Some(hash) = &self.hash {
            out.push_str(&format!("Hash\t{hash}\n"));
        }
        for n in &self.nodes {
            let tag = if n.handoff { "\t # [Handoff]" } else { "" };
            out.push_str(&format!(
                "Server:Port Device\t{}:{} {}{tag}\n",
                n.ip, n.port, n.device
            ));
        }
        out
    }

    /// Machine-readable form for tooling (`swift-get-nodes --json`).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "account": self.account,
            "container": self.container,
            "object": self.object,
            "partition": self.partition,
            "hash": self.hash,
            "nodes": self.nodes,
        })
    }
}
