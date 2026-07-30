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

//! Ring analytics: what a rebalance actually moved, what survives a failure,
//! and how load lands across failure domains.
//!
//! `RingBuilder::rebalance` reassigns every partition from scratch and reports
//! nothing about the difference, so every number an operator actually wants —
//! "how many replicas have to be copied", "is anything unreadable right now",
//! "how many whole zones can I lose" — has to be computed by diffing the
//! assignment table. That is what this module does. It is pure analysis: it
//! never writes a ring.

use std::collections::{BTreeMap, HashMap, HashSet};

use swift_ring::{RingDevice, RingError};

// ---------------------------------------------------------------- movement

/// One partition's replica-set difference.
///
/// Deliberately a SET diff, not a slot-by-slot diff: a rebalance may hand the
/// same device a different replica *row* without moving a single byte, and
/// counting that as movement would inflate every figure. `gained` is the count
/// of replicas that genuinely have to be fetched from elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartDiff {
    pub part: u32,
    pub gained: Vec<u32>,
    pub lost: Vec<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct MoveDiff {
    pub partitions: usize,
    /// `partitions * replicas` — the total number of replica slots.
    pub replica_slots: usize,
    /// Replicas that must actually be transferred.
    pub slots_moved: usize,
    pub parts_touched: usize,
    pub parts_fully_moved: usize,
    /// Replica rows that changed device without changing the *set* — pure
    /// bookkeeping churn, zero bytes on the wire.
    pub slot_permutations: usize,
    pub moved_in: BTreeMap<u64, usize>,
    pub moved_out: BTreeMap<u64, usize>,
    /// `(from_dev, to_dev, slots)`, densest first.
    pub flows: Vec<(u64, u64, usize)>,
    pub per_part: Vec<PartDiff>,
    /// Per-partition state, one byte each:
    /// 0 unchanged, 1 one replica moved, 2 several moved, 3 fully moved.
    pub part_states: Vec<u8>,
}

fn replica_set(assign: &[Vec<u32>], part: usize) -> Vec<u32> {
    let mut v: Vec<u32> = assign.iter().filter_map(|row| row.get(part).copied()).collect();
    v.sort_unstable();
    v
}

/// Multiset difference of the replica sets per partition.
pub fn diff_assignments(before: &[Vec<u32>], after: &[Vec<u32>]) -> MoveDiff {
    let mut d = MoveDiff::default();
    if after.is_empty() {
        return d;
    }
    let parts = after[0].len();
    d.partitions = parts;
    d.replica_slots = after.iter().map(|r| r.len()).sum();
    let mut flows: HashMap<(u64, u64), usize> = HashMap::new();
    d.part_states = vec![0u8; parts];

    for p in 0..parts {
        let b = replica_set(before, p);
        let a = replica_set(after, p);
        if b == a {
            // Same devices — but the rows may have been permuted.
            let permuted = before
                .iter()
                .zip(after.iter())
                .any(|(rb, ra)| rb.get(p) != ra.get(p));
            if permuted {
                d.slot_permutations += 1;
            }
            continue;
        }
        // Multiset difference, both directions.
        let mut lost = b.clone();
        let mut gained = Vec::new();
        for dev in &a {
            if let Some(i) = lost.iter().position(|x| x == dev) {
                lost.remove(i);
            } else {
                gained.push(*dev);
            }
        }
        if gained.is_empty() && lost.is_empty() {
            continue;
        }
        for g in &gained {
            *d.moved_in.entry(*g as u64).or_insert(0) += 1;
        }
        for l in &lost {
            *d.moved_out.entry(*l as u64).or_insert(0) += 1;
        }
        // Pair losses to gains positionally: an approximation of who feeds
        // whom, which is all a flow table can honestly claim.
        for (i, g) in gained.iter().enumerate() {
            if let Some(l) = lost.get(i) {
                *flows.entry((*l as u64, *g as u64)).or_insert(0) += 1;
            }
        }
        d.slots_moved += gained.len();
        d.parts_touched += 1;
        if gained.len() == a.len() {
            d.parts_fully_moved += 1;
        }
        d.part_states[p] = match gained.len() {
            0 => 0,
            1 => 1,
            n if n == a.len() => 3,
            _ => 2,
        };
        d.per_part.push(PartDiff {
            part: p as u32,
            gained,
            lost,
        });
    }
    d.flows = {
        let mut f: Vec<(u64, u64, usize)> = flows.into_iter().map(|((a, b), n)| (a, b, n)).collect();
        f.sort_by(|x, y| y.2.cmp(&x.2).then(x.0.cmp(&y.0)).then(x.1.cmp(&y.1)));
        f
    };
    d
}

/// Replica slots held per device.
pub fn dev_load(assign: &[Vec<u32>]) -> BTreeMap<u32, usize> {
    let mut m = BTreeMap::new();
    for row in assign {
        for dev in row {
            *m.entry(*dev).or_insert(0) += 1;
        }
    }
    m
}

// ---------------------------------------------------------------- survival

/// What is still readable with a set of devices down, measured against the
/// CURRENT assignment (no rebalance). This is the "right now" question, and it
/// is the one an operator asks during an incident.
#[derive(Debug, Clone, Default)]
pub struct SurvivalReport {
    pub down_devs: Vec<u64>,
    pub parts_total: usize,
    pub parts_full: usize,
    pub parts_degraded: usize,
    pub parts_below_quorum: usize,
    pub parts_lost: usize,
    pub min_surviving_replicas: usize,
    /// The thresholds this report was scored against. `parts_below_quorum` is
    /// meaningless without the quorum that produced it — and the two policy
    /// families use very different ones — so the report carries them rather
    /// than leaving a caller to guess or re-derive.
    pub quorum: u64,
    pub min_readable: u64,
    /// A capped sample of the worst partitions, for drill-down.
    pub worst_parts: Vec<u32>,
}

pub fn survival(
    assign: &[Vec<u32>],
    down: &HashSet<u64>,
    quorum: u64,
    min_readable: u64,
) -> SurvivalReport {
    let mut r = SurvivalReport {
        down_devs: {
            let mut v: Vec<u64> = down.iter().copied().collect();
            v.sort_unstable();
            v
        },
        quorum,
        min_readable,
        min_surviving_replicas: usize::MAX,
        ..Default::default()
    };
    if assign.is_empty() {
        r.min_surviving_replicas = 0;
        return r;
    }
    let parts = assign[0].len();
    r.parts_total = parts;
    let replicas = assign.len();
    for p in 0..parts {
        let alive = assign
            .iter()
            .filter_map(|row| row.get(p))
            .filter(|d| !down.contains(&(**d as u64)))
            .count();
        r.min_surviving_replicas = r.min_surviving_replicas.min(alive);
        if alive == replicas {
            r.parts_full += 1;
        } else if (alive as u64) < min_readable {
            r.parts_lost += 1;
            if r.worst_parts.len() < 64 {
                r.worst_parts.push(p as u32);
            }
        } else if (alive as u64) < quorum {
            r.parts_below_quorum += 1;
            if r.worst_parts.len() < 64 {
                r.worst_parts.push(p as u32);
            }
        } else {
            r.parts_degraded += 1;
        }
    }
    if r.min_surviving_replicas == usize::MAX {
        r.min_surviving_replicas = 0;
    }
    r
}

// ---------------------------------------------------------------- tolerance

#[derive(Debug, Clone, Default)]
pub struct ToleranceReport {
    pub node_loss: u32,
    pub zone_loss: u32,
    pub region_loss: u32,
    pub limiting_domain: String,
    pub limiting_parts: usize,
}

fn domain_key(dev: &RingDevice, kind: &str) -> String {
    match kind {
        "region" => format!("r{}", dev.region),
        "zone" => format!("r{}z{}", dev.region, dev.zone),
        _ => dev.ip.clone(),
    }
}

/// Largest `k` such that losing ANY `k` whole failure domains of this kind
/// still leaves every partition readable.
fn tolerance_for(
    assign: &[Vec<u32>],
    devs: &[Option<RingDevice>],
    kind: &str,
    min_readable: u64,
    already_down: &HashSet<u64>,
) -> (u32, usize) {
    // Domains that are entirely down cannot fail again, and their devices must
    // count as lost in every trial rather than as survivors. Without this the
    // answer is "how much could this ring lose if nothing had happened yet",
    // which is the wrong question once a scenario has already killed something:
    // a run with every node failed reported parts_lost = 1024 and, in the same
    // breath, that it could still tolerate a node loss.
    let mut domains: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for d in devs.iter().flatten() {
        if already_down.contains(&d.id) {
            continue;
        }
        domains.entry(domain_key(d, kind)).or_default().push(d.id);
    }
    let names: Vec<&String> = domains.keys().collect();
    let n = names.len();
    if n == 0 {
        return (0, 0);
    }
    // Exhaustive over subsets for the small domain counts real clusters have;
    // above that the combinatorics stop being worth it and 1 is the honest
    // floor to report.
    if n > 16 {
        return (0, 0);
    }
    let mut best = 0u32;
    let mut limiting = 0usize;
    for k in 1..=n {
        let mut all_ok = true;
        let mut worst = 0usize;
        // Iterate every k-subset via bitmask (n <= 16).
        for mask in 0u32..(1u32 << n) {
            if mask.count_ones() as usize != k {
                continue;
            }
            // Whatever the scenario already took out stays out.
            let mut down: HashSet<u64> = already_down.clone();
            for (i, name) in names.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    down.extend(domains[*name].iter().copied());
                }
            }
            let s = survival(assign, &down, min_readable, min_readable);
            let bad = s.parts_lost + s.parts_below_quorum;
            if bad > 0 {
                all_ok = false;
                worst = worst.max(bad);
                break;
            }
        }
        if all_ok {
            best = k as u32;
        } else {
            limiting = worst;
            break;
        }
    }
    (best, limiting)
}

/// How many MORE failure domains the ring can lose, given whatever is already
/// down. Pass an empty set for the pristine ring.
pub fn tolerance(
    assign: &[Vec<u32>],
    devs: &[Option<RingDevice>],
    min_readable: u64,
    already_down: &HashSet<u64>,
) -> ToleranceReport {
    let (node_loss, n_lim) = tolerance_for(assign, devs, "node", min_readable, already_down);
    let (zone_loss, z_lim) = tolerance_for(assign, devs, "zone", min_readable, already_down);
    let (region_loss, r_lim) = tolerance_for(assign, devs, "region", min_readable, already_down);
    // The limiting domain is the coarsest one that tolerates least.
    let (limiting_domain, limiting_parts) = if region_loss == 0 {
        ("region".to_string(), r_lim)
    } else if zone_loss == 0 {
        ("zone".to_string(), z_lim)
    } else {
        ("node".to_string(), n_lim)
    };
    ToleranceReport {
        node_loss,
        zone_loss,
        region_loss,
        limiting_domain,
        limiting_parts,
    }
}

// ---------------------------------------------------------------- tier load

#[derive(Debug, Clone)]
pub struct TierLoad {
    pub tier: String,
    pub kind: &'static str,
    pub weight: f64,
    pub parts_before: usize,
    pub parts_after: usize,
    pub ideal_after: f64,
    /// Percent off the weight-proportional ideal. Positive = overloaded.
    pub balance_pct: f64,
}

pub fn tier_loads(
    before: &[Vec<u32>],
    after: &[Vec<u32>],
    devs: &[Option<RingDevice>],
) -> Vec<TierLoad> {
    let lb = dev_load(before);
    let la = dev_load(after);
    let total_slots: usize = la.values().sum();
    let mut out = Vec::new();
    for kind in ["region", "zone", "node", "device"] {
        let mut agg: BTreeMap<String, (f64, usize, usize)> = BTreeMap::new();
        for d in devs.iter().flatten() {
            let key = match kind {
                "device" => format!("{}/{}", d.ip, d.device),
                k => domain_key(d, k),
            };
            let e = agg.entry(key).or_insert((0.0, 0, 0));
            e.0 += d.weight;
            e.1 += lb.get(&(d.id as u32)).copied().unwrap_or(0);
            e.2 += la.get(&(d.id as u32)).copied().unwrap_or(0);
        }
        let total_weight: f64 = agg.values().map(|v| v.0).sum();
        for (tier, (weight, pb, pa)) in agg {
            let ideal = if total_weight > 0.0 {
                weight / total_weight * total_slots as f64
            } else {
                0.0
            };
            let balance = if ideal > 0.0 {
                (pa as f64 - ideal) / ideal * 100.0
            } else {
                0.0
            };
            out.push(TierLoad {
                tier,
                kind,
                weight,
                parts_before: pb,
                parts_after: pa,
                ideal_after: ideal,
                balance_pct: balance,
            });
        }
    }
    out
}

// ---------------------------------------------------------------- scenario

/// One mutation to apply to a copy of the ring before rebalancing.
#[derive(Debug, Clone)]
pub enum Op {
    /// Mark unavailable: kept in the ring, weight forced to 0. Answers
    /// "what is readable right now".
    FailDev(u64),
    /// Delete: answers "what moves if I retire this permanently".
    RemoveDev(u64),
    SetWeight(u64, f64),
    AddDev {
        region: u64,
        zone: u64,
        ip: String,
        port: u32,
        replication_ip: Option<String>,
        replication_port: Option<u32>,
        device: String,
        weight: f64,
    },
}

/// Resolve device selectors (`dev_id`, or `ip`/`ip`+`device`, or region+zone)
/// against the ring's device table.
pub fn select_devices(
    devs: &[Option<RingDevice>],
    dev_id: Option<u64>,
    ip: Option<&str>,
    device: Option<&str>,
    region: Option<u64>,
    zone: Option<u64>,
) -> Result<Vec<u64>, RingError> {
    let mut out = Vec::new();
    for d in devs.iter().flatten() {
        let m = dev_id.map(|x| x == d.id).unwrap_or(true)
            && ip.map(|x| x == d.ip).unwrap_or(true)
            && device.map(|x| x == d.device).unwrap_or(true)
            && region.map(|x| x == d.region).unwrap_or(true)
            && zone.map(|x| x == d.zone).unwrap_or(true);
        if m {
            out.push(d.id);
        }
    }
    if out.is_empty() {
        return Err(RingError("no device matched the selector".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(id: u64, region: u64, zone: u64, ip: &str) -> Option<RingDevice> {
        Some(RingDevice {
            id,
            region,
            zone,
            ip: ip.to_string(),
            port: 6200,
            replication_ip: Some(ip.to_string()),
            replication_port: Some(6200),
            device: "d1".into(),
            weight: 100.0,
            meta: String::new(),
            extra: Default::default(),
        })
    }

    #[test]
    fn identical_assignments_move_nothing() {
        let a = vec![vec![0, 1], vec![1, 2], vec![2, 0]];
        let d = diff_assignments(&a, &a);
        assert_eq!(d.slots_moved, 0);
        assert_eq!(d.parts_touched, 0);
        assert_eq!(d.slot_permutations, 0);
        assert_eq!(d.part_states, vec![0, 0]);
    }

    #[test]
    fn row_permutation_is_not_movement() {
        // Same device set per partition, different rows: zero bytes move.
        let before = vec![vec![0], vec![1], vec![2]];
        let after = vec![vec![2], vec![0], vec![1]];
        let d = diff_assignments(&before, &after);
        assert_eq!(d.slots_moved, 0, "a row permutation must not count as movement");
        assert_eq!(d.slot_permutations, 1);
    }

    #[test]
    fn one_replica_replaced_counts_once() {
        let before = vec![vec![0], vec![1], vec![2]];
        let after = vec![vec![0], vec![1], vec![3]];
        let d = diff_assignments(&before, &after);
        assert_eq!(d.slots_moved, 1);
        assert_eq!(d.parts_touched, 1);
        assert_eq!(d.moved_in.get(&3), Some(&1));
        assert_eq!(d.moved_out.get(&2), Some(&1));
        assert_eq!(d.flows, vec![(2, 3, 1)]);
        assert_eq!(d.part_states, vec![1]);
    }

    #[test]
    fn whole_partition_relocation_is_flagged() {
        let before = vec![vec![0], vec![1], vec![2]];
        let after = vec![vec![3], vec![4], vec![5]];
        let d = diff_assignments(&before, &after);
        assert_eq!(d.slots_moved, 3);
        assert_eq!(d.parts_fully_moved, 1);
        assert_eq!(d.part_states, vec![3]);
    }

    #[test]
    fn survival_counts_degraded_and_lost() {
        // 3 replicas, 2 partitions, devices 0/1/2.
        let a = vec![vec![0, 0], vec![1, 1], vec![2, 2]];
        let down: HashSet<u64> = [1u64].into_iter().collect();
        let s = survival(&a, &down, 2, 1);
        assert_eq!(s.parts_total, 2);
        assert_eq!(s.parts_full, 0);
        assert_eq!(s.parts_degraded, 2, "2 of 3 alive is degraded but at quorum");
        assert_eq!(s.parts_below_quorum, 0);
        assert_eq!(s.parts_lost, 0);
        assert_eq!(s.min_surviving_replicas, 2);

        let down2: HashSet<u64> = [0u64, 1u64].into_iter().collect();
        let s2 = survival(&a, &down2, 2, 1);
        assert_eq!(s2.parts_below_quorum, 2, "1 of 3 is readable but below quorum");
        assert_eq!(s2.parts_lost, 0);

        let down3: HashSet<u64> = [0u64, 1u64, 2u64].into_iter().collect();
        let s3 = survival(&a, &down3, 2, 1);
        assert_eq!(s3.parts_lost, 2);
        assert_eq!(s3.min_surviving_replicas, 0);
    }

    #[test]
    fn tolerance_one_zone_per_node_survives_one_loss() {
        let devs = vec![
            dev(0, 1, 1, "10.0.0.1"),
            dev(1, 1, 2, "10.0.0.2"),
            dev(2, 1, 3, "10.0.0.3"),
        ];
        // one replica per zone, min_readable 1 => can lose 2 of 3 zones
        let a = vec![vec![0], vec![1], vec![2]];
        let t = tolerance(&a, &devs, 1, &HashSet::new());
        assert_eq!(t.zone_loss, 2);
        assert_eq!(t.node_loss, 2);
        // Everything is in region 1, so losing that region loses everything.
        assert_eq!(t.region_loss, 0);
        assert_eq!(t.limiting_domain, "region");
    }

    #[test]
    fn tolerance_respects_min_readable() {
        let devs = vec![
            dev(0, 1, 1, "10.0.0.1"),
            dev(1, 1, 2, "10.0.0.2"),
            dev(2, 1, 3, "10.0.0.3"),
        ];
        let a = vec![vec![0], vec![1], vec![2]];
        // EC 2+1: need 2 of 3 fragments, so only one zone may be lost.
        let t = tolerance(&a, &devs, 2, &HashSet::new());
        assert_eq!(t.zone_loss, 1);
    }

    #[test]
    fn tolerance_counts_only_what_is_still_standing() {
        let devs = vec![
            dev(0, 1, 1, "10.0.0.1"),
            dev(1, 1, 2, "10.0.0.2"),
            dev(2, 1, 3, "10.0.0.3"),
        ];
        let a = vec![vec![0], vec![1], vec![2]];
        // Pristine: one replica per zone, min_readable 1 => two zones may go.
        assert_eq!(tolerance(&a, &devs, 1, &HashSet::new()).zone_loss, 2);
        // With zone 1 already gone, only one MORE zone may go.
        let one_down: HashSet<u64> = [0u64].into_iter().collect();
        assert_eq!(tolerance(&a, &devs, 1, &one_down).zone_loss, 1);
        // With two gone, nothing further can be lost.
        let two_down: HashSet<u64> = [0u64, 1].into_iter().collect();
        assert_eq!(tolerance(&a, &devs, 1, &two_down).zone_loss, 0);
    }

    #[test]
    fn tolerance_never_claims_headroom_on_a_dead_ring() {
        // The report that made this a bug: a scenario killed every node, the
        // survival block said every partition was lost, and tolerance still
        // announced it could absorb another failure.
        let devs = vec![
            dev(0, 1, 1, "10.0.0.1"),
            dev(1, 1, 2, "10.0.0.2"),
            dev(2, 1, 3, "10.0.0.3"),
        ];
        let a = vec![vec![0], vec![1], vec![2]];
        let all_down: HashSet<u64> = [0u64, 1, 2].into_iter().collect();
        let s = survival(&a, &all_down, 2, 1);
        assert_eq!(s.parts_lost, 1, "precondition: everything is unreadable");
        let t = tolerance(&a, &devs, 1, &all_down);
        assert_eq!(t.node_loss, 0, "a dead ring tolerates nothing");
        assert_eq!(t.zone_loss, 0);
    }

    #[test]
    fn tier_loads_flags_imbalance() {
        let devs = vec![dev(0, 1, 1, "10.0.0.1"), dev(1, 1, 2, "10.0.0.2")];
        let before = vec![vec![0, 0]];
        let after = vec![vec![0, 1]];
        let t = tier_loads(&before, &after, &devs);
        let z1 = t.iter().find(|x| x.kind == "zone" && x.tier == "r1z1").unwrap();
        assert_eq!(z1.parts_before, 2);
        assert_eq!(z1.parts_after, 1);
        assert!(z1.balance_pct.abs() < 1e-6, "equal weights, equal load => balanced");
    }

    #[test]
    fn selector_matches_by_ip_and_errors_when_empty() {
        let devs = vec![dev(0, 1, 1, "10.0.0.1"), dev(1, 1, 2, "10.0.0.2")];
        let got = select_devices(&devs, None, Some("10.0.0.2"), None, None, None).unwrap();
        assert_eq!(got, vec![1]);
        assert!(select_devices(&devs, None, Some("10.0.0.9"), None, None, None).is_err());
    }
}
