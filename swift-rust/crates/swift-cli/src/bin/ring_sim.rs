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

//! `swift-ring-sim` — ask what-if questions about a ring without touching it.
//!
//! ```text
//! swift-ring-sim inspect  <ring.gz> [--json]
//! swift-ring-sim simulate <ring.gz> --json      # scenario JSON on stdin
//! swift-ring-sim tolerate <ring.gz> [--json] [--min-readable N]
//! ```
//!
//! **This binary is read-only by construction.** It never calls `save_v1`,
//! `serialize_v1`, or any filesystem write; it loads a ring, mutates an
//! in-memory `RingBuilder` copy, and prints JSON. That is deliberate: the
//! sibling `swift-ring-builder` *does* rewrite the live ring, and a simulation
//! tool must not be one argv typo away from a production rebalance.
//!
//! Because `RingBuilder::rebalance` always reassigns from scratch, a
//! re-derived baseline is only meaningful if the live ring was itself produced
//! by this builder. Every `simulate` run therefore first rebalances the
//! *unmodified* copy and reports the drift as `fidelity.control_slots_moved`,
//! so a caller always knows whether the movement figures are absolute or
//! relative to a re-derived baseline.

use std::collections::HashSet;
use std::path::Path;

use swift_cli::dispersion::dispersion_report;
use swift_cli::ringsim::{
    diff_assignments, select_devices, survival, tier_loads, tolerance, MoveDiff, Op,
};
use swift_core::hashing::HashPathConfig;
use swift_ring::{Ring, RingBuilder, RingData};

fn die(msg: &str) -> ! {
    eprintln!("swift-ring-sim: {msg}");
    std::process::exit(1);
}

fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn load(path: &str) -> RingData {
    RingData::load(Path::new(path)).unwrap_or_else(|e| die(&format!("could not load {path}: {e}")))
}

fn builder_of(data: &RingData) -> RingBuilder {
    RingBuilder::from_ring_data(data)
        .unwrap_or_else(|e| die(&format!("could not derive a builder from the ring: {e}")))
}

/// Dispersion needs a `Ring`, which needs a hash config — but no path is
/// hashed here, so the empty default is correct (same reasoning as
/// `swift-ring-info`).
fn dispersion_json(b: &RingBuilder) -> serde_json::Value {
    let ring = Ring::new(b.to_ring_data(), HashPathConfig::default());
    let d = dispersion_report(&ring);
    serde_json::json!({
        "partitions": d.partitions,
        "region_overlaps": d.region_overlaps,
        "zone_overlaps": d.zone_overlaps,
        "region_dispersion_pct": d.region_dispersion_pct(),
    })
}

fn devices_json(
    b: &RingBuilder,
    load_before: &std::collections::BTreeMap<u32, usize>,
    load_after: &std::collections::BTreeMap<u32, usize>,
    states: &std::collections::HashMap<u64, &'static str>,
    total_slots: usize,
) -> serde_json::Value {
    let total_weight: f64 = b.devices().iter().flatten().map(|d| d.weight).sum();
    let devs: Vec<serde_json::Value> = b
        .devices()
        .iter()
        .flatten()
        .map(|d| {
            let pa = load_after.get(&(d.id as u32)).copied().unwrap_or(0);
            let ideal = if total_weight > 0.0 {
                d.weight / total_weight * total_slots as f64
            } else {
                0.0
            };
            serde_json::json!({
                "dev_id": d.id,
                "region": d.region,
                "zone": d.zone,
                "ip": d.ip,
                "port": d.port,
                "replication_ip": d.replication_ip.clone().unwrap_or_else(|| d.ip.clone()),
                "replication_port": d.replication_port.unwrap_or(d.port),
                "device": d.device,
                "weight": d.weight,
                "state": states.get(&d.id).copied().unwrap_or("ok"),
                "parts_before": load_before.get(&(d.id as u32)).copied().unwrap_or(0),
                "parts_after": pa,
                "ideal_after": ideal,
                "balance_pct": if ideal > 0.0 { (pa as f64 - ideal) / ideal * 100.0 } else { 0.0 },
            })
        })
        .collect();
    serde_json::Value::Array(devs)
}

fn move_json(d: &MoveDiff) -> serde_json::Value {
    serde_json::json!({
        "slots_moved": d.slots_moved,
        "replica_slots": d.replica_slots,
        "moved_pct": if d.replica_slots > 0 {
            d.slots_moved as f64 / d.replica_slots as f64 * 100.0
        } else { 0.0 },
        "parts_touched": d.parts_touched,
        "parts_fully_moved": d.parts_fully_moved,
        "slot_permutations": d.slot_permutations,
        "moved_in": d.moved_in.iter().map(|(k,v)| (k.to_string(), serde_json::json!(*v))).collect::<serde_json::Map<_,_>>(),
        "moved_out": d.moved_out.iter().map(|(k,v)| (k.to_string(), serde_json::json!(*v))).collect::<serde_json::Map<_,_>>(),
        "flows": d.flows.iter().take(64).map(|(f,t,n)| serde_json::json!({"from":f,"to":t,"slots":n})).collect::<Vec<_>>(),
        "part_states": b64(&d.part_states),
    })
}

fn survival_json(s: &swift_cli::ringsim::SurvivalReport) -> serde_json::Value {
    serde_json::json!({
        "down_devs": s.down_devs,
        "parts_total": s.parts_total,
        "parts_full": s.parts_full,
        "parts_degraded": s.parts_degraded,
        "parts_below_quorum": s.parts_below_quorum,
        "parts_lost": s.parts_lost,
        "min_surviving_replicas": s.min_surviving_replicas,
        "quorum": s.quorum,
        "min_readable": s.min_readable,
        "worst_parts": s.worst_parts,
    })
}

fn tolerance_json(t: &swift_cli::ringsim::ToleranceReport) -> serde_json::Value {
    serde_json::json!({
        "node_loss": t.node_loss,
        "zone_loss": t.zone_loss,
        "region_loss": t.region_loss,
        "limiting_domain": t.limiting_domain,
        "limiting_parts": t.limiting_parts,
    })
}

fn parse_ops(scenario: &serde_json::Value, data: &RingData) -> (Vec<Op>, Vec<u64>, Vec<String>) {
    let mut ops = Vec::new();
    let mut failed: Vec<u64> = Vec::new();
    let mut warnings = Vec::new();
    let arr = match scenario.get("ops").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return (ops, failed, warnings),
    };
    if arr.len() > 32 {
        die("too many ops (max 32)");
    }
    for o in arr {
        let op = o.get("op").and_then(|v| v.as_str()).unwrap_or("");
        let dev_id = o.get("dev_id").and_then(|v| v.as_u64());
        let ip = o.get("ip").and_then(|v| v.as_str());
        let device = o.get("device").and_then(|v| v.as_str());
        let region = o.get("region").and_then(|v| v.as_u64());
        let zone = o.get("zone").and_then(|v| v.as_u64());
        match op {
            "fail_device" | "fail_node" | "fail_zone" | "remove_device" => {
                let (r, z) = if op == "fail_zone" {
                    (region, zone)
                } else {
                    (None, None)
                };
                let sel = match op {
                    "fail_node" => select_devices(&data.devs, dev_id, ip, None, None, None),
                    "fail_zone" => select_devices(&data.devs, None, None, None, r, z),
                    _ => select_devices(&data.devs, dev_id, ip, device, None, None),
                };
                match sel {
                    Ok(ids) => {
                        for id in ids {
                            if op == "remove_device" {
                                ops.push(Op::RemoveDev(id));
                            } else {
                                ops.push(Op::FailDev(id));
                                failed.push(id);
                            }
                        }
                    }
                    Err(e) => warnings.push(format!("{op}: {e}")),
                }
            }
            "set_weight" => {
                let w = o
                    .get("weight")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0)
                    .clamp(0.0, 10000.0);
                match select_devices(&data.devs, dev_id, ip, device, None, None) {
                    Ok(ids) => ops.extend(ids.into_iter().map(|id| Op::SetWeight(id, w))),
                    Err(e) => warnings.push(format!("set_weight: {e}")),
                }
            }
            "add_device" => {
                let w = o
                    .get("weight")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(100.0)
                    .clamp(0.0, 10000.0);
                let ipa = ip.unwrap_or("").to_string();
                if ipa.is_empty() {
                    warnings.push("add_device: ip is required".into());
                    continue;
                }
                ops.push(Op::AddDev {
                    region: region.unwrap_or(1),
                    zone: zone.unwrap_or(1),
                    ip: ipa,
                    port: o.get("port").and_then(|v| v.as_u64()).unwrap_or(6200) as u32,
                    replication_ip: o
                        .get("replication_ip")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    replication_port: o
                        .get("replication_port")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                    device: device.unwrap_or("d1").to_string(),
                    weight: w,
                });
            }
            other => warnings.push(format!("unknown op '{other}' ignored")),
        }
    }
    (ops, failed, warnings)
}

fn apply(b: &mut RingBuilder, ops: &[Op]) -> Vec<String> {
    let mut warnings = Vec::new();
    for op in ops {
        match op {
            // A failed device stays in the ring so its current assignment is
            // still visible; zero weight is what takes it out of a rebalance.
            Op::FailDev(id) => {
                if !b.set_dev_weight(*id, 0.0) {
                    warnings.push(format!("fail: no device {id}"));
                }
            }
            Op::RemoveDev(id) => {
                if !b.remove_dev(*id) {
                    warnings.push(format!("remove: no device {id}"));
                }
            }
            Op::SetWeight(id, w) => {
                if !b.set_dev_weight(*id, *w) {
                    warnings.push(format!("set_weight: no device {id}"));
                }
            }
            Op::AddDev {
                region,
                zone,
                ip,
                port,
                replication_ip,
                replication_port,
                device,
                weight,
            } => {
                b.add_dev_full(
                    *region,
                    *zone,
                    ip,
                    *port,
                    replication_ip.as_deref(),
                    *replication_port,
                    device,
                    *weight,
                );
            }
        }
    }
    warnings
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!(
            "usage:\n  swift-ring-sim inspect  <ring.gz> [--json]\n  \
             swift-ring-sim simulate <ring.gz> --json [--quorum N] [--min-readable N]\n  \
             \x20                                        (scenario JSON on stdin)\n  \
             swift-ring-sim tolerate <ring.gz> [--json] [--min-readable N]\n\n\
             --quorum N        writes need N of the replica slots. Default is a\n  \
             \x20                 replication majority; an EC policy must pass\n  \
             \x20                 k + min_parity_needed(ec_type).\n  \
             --min-readable N  reads need N slots (1 for replication, k for EC)."
        );
        std::process::exit(1);
    }
    let cmd = args[0].as_str();
    let path = args[1].clone();
    let json = args.iter().any(|a| a == "--json");
    let min_readable_arg = args
        .iter()
        .position(|a| a == "--min-readable")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u64>().ok());
    let quorum_arg = args
        .iter()
        .position(|a| a == "--quorum")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u64>().ok());

    let data = load(&path);
    let base = builder_of(&data);
    let replicas = base.replica_count();
    let whole = replicas.ceil() as u64;
    // A ring does not know its policy, and the two policy families disagree
    // about what a write quorum is: replication needs a majority, erasure
    // coding needs `k + min_parity_needed(ec_type)` — which for 2+1 is all
    // three fragments. Defaulting to the majority and leaving it at that made
    // an EC policy look like it tolerated a node loss for writes when it does
    // not, so the caller that knows the policy passes the real figure.
    let default_quorum = whole.div_ceil(2);
    let quorum = quorum_arg.unwrap_or(default_quorum).clamp(1, whole.max(1));
    let min_readable = min_readable_arg.unwrap_or(1);

    match cmd {
        "inspect" => {
            let load_now = swift_cli::ringsim::dev_load(base.assignment());
            let total: usize = load_now.values().sum();
            let states = std::collections::HashMap::new();
            let out = serde_json::json!({
                "ok": true,
                "ring": {
                    "path": path,
                    "part_power": base.part_power(),
                    "partitions": 1usize << base.part_power(),
                    "replicas": replicas,
                    "version": data.version,
                    "quorum": quorum,
                },
                "devices": devices_json(&base, &load_now, &load_now, &states, total),
                "dispersion": dispersion_json(&base),
            });
            if json {
                println!("{out}");
            } else {
                println!("partitions\t{}", 1usize << base.part_power());
                println!("replicas\t{replicas}");
                println!("devices\t{}", base.devices().iter().flatten().count());
            }
        }
        "tolerate" => {
            let t = tolerance(base.assignment(), &data.devs, min_readable, &HashSet::new());
            let out = serde_json::json!({ "ok": true, "min_readable": min_readable,
                                          "tolerance": tolerance_json(&t) });
            if json {
                println!("{out}");
            } else {
                println!("node_loss\t{}", t.node_loss);
                println!("zone_loss\t{}", t.zone_loss);
                println!("region_loss\t{}", t.region_loss);
            }
        }
        "simulate" => {
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
                .unwrap_or_else(|e| die(&format!("could not read scenario from stdin: {e}")));
            let scenario: serde_json::Value = if buf.trim().is_empty() {
                serde_json::json!({})
            } else {
                serde_json::from_str(&buf)
                    .unwrap_or_else(|e| die(&format!("bad scenario JSON: {e}")))
            };
            let min_readable = scenario
                .get("min_readable")
                .and_then(|v| v.as_u64())
                .or(min_readable_arg)
                .unwrap_or(1);
            let quorum = scenario
                .get("quorum")
                .and_then(|v| v.as_u64())
                .or(quorum_arg)
                .unwrap_or(default_quorum)
                .clamp(1, whole.max(1));
            let do_rebalance = scenario
                .get("rebalance")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let (ops, failed, mut warnings) = parse_ops(&scenario, &data);

            // ---- fidelity control: rebalance the UNMODIFIED copy ----
            // If this drifts from the live assignment, the ring was not
            // produced by this builder and every movement figure below is
            // relative to a re-derived baseline, not to reality.
            let live = base.assignment().to_vec();
            let mut control = builder_of(&data);
            let control_ok = control.rebalance().is_ok();
            let control_diff = diff_assignments(&live, control.assignment());
            let faithful = control_ok && control_diff.slots_moved == 0;
            let baseline: Vec<Vec<u32>> = if faithful {
                live.clone()
            } else {
                control.assignment().to_vec()
            };

            // ---- apply the scenario to a fresh copy ----
            let mut sim = builder_of(&data);
            warnings.extend(apply(&mut sim, &ops));

            let down: HashSet<u64> = failed.iter().copied().collect();
            let surv = survival(&live, &down, quorum, min_readable);
            let tol_before = tolerance(&live, &data.devs, min_readable, &HashSet::new());

            let mut states: std::collections::HashMap<u64, &'static str> =
                std::collections::HashMap::new();
            for id in &failed {
                states.insert(*id, "failed");
            }
            for op in &ops {
                if let Op::RemoveDev(id) = op {
                    states.insert(*id, "removed");
                }
            }

            let mut rebalance_error = None;
            if do_rebalance {
                if let Err(e) = sim.rebalance() {
                    rebalance_error = Some(e.to_string());
                }
            }
            let after = sim.assignment().to_vec();
            let mv = if do_rebalance && rebalance_error.is_none() {
                diff_assignments(&baseline, &after)
            } else {
                MoveDiff::default()
            };
            let load_before = swift_cli::ringsim::dev_load(&baseline);
            let load_after = swift_cli::ringsim::dev_load(&after);
            let total_slots: usize = load_after.values().sum();
            let tol_after = if rebalance_error.is_none() {
                // "how much MORE can I lose", so the scenario's own casualties count.
                tolerance(&after, &sim.to_ring_data().devs, min_readable, &down)
            } else {
                tol_before.clone()
            };
            let tiers: Vec<serde_json::Value> =
                tier_loads(&baseline, &after, &sim.to_ring_data().devs)
                    .into_iter()
                    .map(|t| {
                        serde_json::json!({
                            "tier": t.tier, "kind": t.kind, "weight": t.weight,
                            "parts_before": t.parts_before, "parts_after": t.parts_after,
                            "ideal_after": t.ideal_after, "balance_pct": t.balance_pct,
                        })
                    })
                    .collect();

            if !faithful {
                warnings.push(
                    "this ring was not produced by this builder; movement is measured \
                     against a re-derived baseline"
                        .into(),
                );
            }
            if let Some(e) = &rebalance_error {
                warnings.push(format!("rebalance failed: {e}"));
            }

            let out = serde_json::json!({
                "ok": rebalance_error.is_none(),
                "error": rebalance_error,
                "ring": {
                    "part_power": base.part_power(),
                    "partitions": 1usize << base.part_power(),
                    "replicas": replicas,
                    "version": data.version,
                    "quorum": quorum,
                    "min_readable": min_readable,
                },
                "fidelity": {
                    "control_slots_moved": control_diff.slots_moved,
                    "faithful": faithful,
                },
                "devices": devices_json(&sim, &load_before, &load_after, &states, total_slots),
                "survival": survival_json(&surv),
                "tolerance_before": tolerance_json(&tol_before),
                "tolerance_after": tolerance_json(&tol_after),
                "dispersion_before": dispersion_json(&base),
                "dispersion_after": dispersion_json(&sim),
                "movement": move_json(&mv),
                "tiers": tiers,
                "warnings": warnings,
            });
            println!("{out}");
        }
        other => die(&format!("unknown command '{other}'")),
    }
}
