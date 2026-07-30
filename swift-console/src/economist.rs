//! Policy Economist: choosing a storage policy as a constrained trade-off
//! rather than a habit.
//!
//! Durability, cost and recovery speed pull against each other, and the usual
//! way of settling it — "we always use three replicas" — hides what is actually
//! being bought. This puts the candidates side by side on one model, and then
//! says which one it would pick and why, because a table of five candidates is
//! not an answer.
//!
//! Two numbers here are routinely got wrong and are taken from the Swift source
//! rather than from intuition:
//!
//! * **EC write quorum is `k + min_parity_needed(ec_type)`, not `k`**
//!   (`swift-core/src/storage_policy.rs`). For the usual `rs_vand` backend that
//!   is `k+1`, so a 2+1 scheme needs all three fragments to accept a write —
//!   zero write margin.
//! * **Repairing one lost EC device reads `k ×` its contents**, because every
//!   fragment must be reconstructed from k others. Replication reads 1×. This
//!   is the cost that makes wide EC schemes expensive to heal, and it is the
//!   number capacity planning usually forgets.

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Clone, Debug)]
#[serde(tag = "kind")]
pub enum Candidate {
    #[serde(rename = "replication")]
    Replication { replicas: u32 },
    #[serde(rename = "ec")]
    Ec {
        k: u32,
        m: u32,
        #[serde(default = "d_ec_type")]
        ec_type: String,
    },
}
fn d_ec_type() -> String {
    "liberasurecode_rs_vand".into()
}

#[derive(Deserialize, Clone, Debug)]
pub struct Inputs {
    /// Logical data to store, before any redundancy.
    pub raw_tb: f64,
    pub disk_cost_per_tb_year: f64,
    /// Bandwidth available for rebuild traffic.
    pub cross_rack_gbps: f64,
    #[serde(default = "d_util")]
    pub bandwidth_utilisation: f64,
    pub target_durability_nines: f64,
    pub max_repair_hours: f64,
    pub tolerate_node_loss: u32,
    #[serde(default = "d_afr")]
    pub annual_disk_afr: f64,
    pub node_count: u32,
    pub devices_total: u32,
    pub zone_count: u32,
    pub device_tb: f64,
    #[serde(default = "d_years")]
    pub years: f64,
    pub candidates: Vec<Candidate>,
}
fn d_util() -> f64 {
    0.5
}
fn d_afr() -> f64 {
    0.02
}
fn d_years() -> f64 {
    5.0
}

#[derive(Serialize, Clone, Debug)]
#[serde(tag = "code")]
pub enum Reason {
    #[serde(rename = "needs_devices")]
    NeedsDevices { need: u32, have: u32, text: String },
    #[serde(rename = "fewer_zones")]
    FewerZones { need: u32, zones: u32, text: String },
    #[serde(rename = "no_write_margin")]
    NoWriteMargin { text: String },
}

#[derive(Serialize, Clone, Debug)]
pub struct Row {
    pub label: String,
    pub kind: String,
    /// The shape behind the label, so a caller can spell it in its own
    /// language instead of parsing "3× replication" back apart.
    pub replicas: u32,
    pub ec_k: u32,
    pub ec_m: u32,
    pub amplification: f64,
    pub raw_needed_tb: f64,
    pub min_devices: u32,
    pub min_failure_domains: u32,
    pub write_quorum: u32,
    pub write_fanout: u32,
    /// How many devices may be down and still accept a write.
    pub write_margin: i32,
    pub read_min_devices: u32,
    /// Devices that can be lost with the object still readable.
    pub tolerates_loss: u32,
    pub rebuild_read_tb: f64,
    pub repair_hours: f64,
    pub durability_nines: f64,
    pub tco: f64,
    pub feasible: bool,
    /// Structured so the UI can render them in any language; the message text
    /// is a fallback for API consumers, not the source of truth.
    pub reasons: Vec<Reason>,
    pub meets_durability: bool,
    pub meets_repair_time: bool,
    pub meets_node_loss: bool,
}

impl Row {
    pub fn meets_all(&self) -> bool {
        self.meets_durability && self.meets_repair_time && self.meets_node_loss
    }
    fn met(&self) -> u8 {
        self.meets_durability as u8 + self.meets_repair_time as u8 + self.meets_node_loss as u8
    }
}

/// Minimum parity fragments a backend needs before it can decode — the table
/// Swift itself hardcodes.
///
/// Shared with `ringlab` rather than duplicated: RingScope scores a node loss
/// against the write quorum and the Economist reports that same quorum as a
/// margin, so two copies of this table would eventually disagree and one of
/// the two surfaces would be quietly wrong.
pub(crate) fn min_parity_needed(ec_type: &str) -> u32 {
    match ec_type {
        t if t.contains("flat_xor_hd_3") => 2,
        t if t.contains("flat_xor_hd_4") => 3,
        _ => 1,
    }
}

/// Probability of losing an object in a year, from a repair-window model:
/// with `n` copies, `f` may be lost before data is gone, and each must fail
/// inside the window it takes to rebuild the previous one.
///
/// `C(n, f+1) · λ · (λ·MTTR_years)^f`. It is an approximation — it ignores
/// correlated failure, which is usually the thing that actually kills a
/// cluster — so it is a comparison tool between candidates, not a warranty.
fn durability_nines(n: u32, f: u32, afr: f64, repair_hours: f64) -> f64 {
    if f == 0 {
        return 0.0;
    }
    let mttr_years = (repair_hours / 8760.0).max(1e-9);
    let choose = {
        let (n, k) = (n as f64, (f + 1) as f64);
        let mut c = 1.0;
        let mut i = 0.0;
        while i < k {
            c *= (n - i) / (i + 1.0);
            i += 1.0;
        }
        c
    };
    let p = choose * afr * (afr * mttr_years).powi(f as i32);
    if p <= 0.0 {
        return 99.0;
    }
    (-p.log10()).clamp(0.0, 99.0)
}

pub fn evaluate(inp: &Inputs) -> Vec<Row> {
    inp.candidates.iter().map(|c| row(inp, c)).collect()
}

/// Which candidate the tool would actually pick, and what the choice cost.
///
/// The rule is deliberately boring: of the schemes this cluster can host and
/// that clear every stated target, take the cheapest. When nothing clears every
/// target the answer is not "no recommendation" — an operator still has to
/// store the data — so the closest one is named together with the target it
/// misses, which is the part a recommendation usually hides.
#[derive(Serialize, Clone, Debug)]
pub struct Recommendation {
    /// "meets_all" | "compromise" | "none"
    pub outcome: &'static str,
    pub best: Option<usize>,
    /// The next-cheapest placeable candidate, for "what the extra money buys".
    pub runner_up: Option<usize>,
    /// Targets the pick does not clear; empty when `outcome` is `meets_all`.
    pub unmet: Vec<&'static str>,
}

pub fn recommend(rows: &[Row]) -> Recommendation {
    let placeable: Vec<usize> = (0..rows.len()).filter(|i| rows[*i].feasible).collect();
    if placeable.is_empty() {
        return Recommendation {
            outcome: "none",
            best: None,
            runner_up: None,
            unmet: Vec::new(),
        };
    }
    let cheaper = |a: usize, b: usize| {
        rows[a]
            .tco
            .partial_cmp(&rows[b].tco)
            .unwrap_or(std::cmp::Ordering::Equal)
    };
    let clean: Vec<usize> = placeable
        .iter()
        .copied()
        .filter(|i| rows[*i].meets_all())
        .collect();
    let (best, outcome) = if let Some(b) = clean.iter().copied().min_by(|a, b| cheaper(*a, *b)) {
        (b, "meets_all")
    } else {
        // Nothing clears everything: prefer the scheme that misses the fewest
        // targets, and settle ties on price.
        let b = placeable
            .iter()
            .copied()
            .max_by(|a, b| {
                rows[*a]
                    .met()
                    .cmp(&rows[*b].met())
                    .then_with(|| cheaper(*b, *a))
            })
            .unwrap_or(placeable[0]);
        (b, "compromise")
    };
    let runner_up = placeable
        .iter()
        .copied()
        .filter(|i| *i != best)
        .min_by(|a, b| {
            rows[*b]
                .met()
                .cmp(&rows[*a].met())
                .then_with(|| cheaper(*a, *b))
        });
    let r = &rows[best];
    let mut unmet = Vec::new();
    if !r.meets_durability {
        unmet.push("durability");
    }
    if !r.meets_repair_time {
        unmet.push("repair");
    }
    if !r.meets_node_loss {
        unmet.push("loss");
    }
    Recommendation {
        outcome,
        best: Some(best),
        runner_up,
        unmet,
    }
}

fn row(inp: &Inputs, c: &Candidate) -> Row {
    let bytes_per_tb = 1e12;
    let (label, kind, amp, min_devices, write_quorum, write_fanout, read_min, tolerates, rebuild_factor, n, f) =
        match c {
            Candidate::Replication { replicas } => {
                let r = (*replicas).max(1);
                (
                    format!("{r}× replication"),
                    "replication".to_string(),
                    r as f64,
                    r,
                    // Python's quorum_size: floor(n/2) + 1
                    r / 2 + 1,
                    r,
                    1u32,
                    r.saturating_sub(1),
                    1.0f64,
                    r,
                    r.saturating_sub(1),
                )
            }
            Candidate::Ec { k, m, ec_type } => {
                let (k, m) = ((*k).max(1), (*m).max(1));
                let n = k + m;
                let q = k + min_parity_needed(ec_type);
                (
                    format!("EC {k}+{m}"),
                    "erasure_coding".to_string(),
                    n as f64 / k as f64,
                    n,
                    q,
                    n,
                    k,
                    m,
                    k as f64,
                    n,
                    m,
                )
            }
        };
    let (replicas, ec_k, ec_m) = match c {
        Candidate::Replication { replicas } => ((*replicas).max(1), 0, 0),
        Candidate::Ec { k, m, .. } => (0, (*k).max(1), (*m).max(1)),
    };

    let raw_needed_tb = inp.raw_tb * amp;
    // What one device holds once the cluster is full at this amplification.
    let per_device_tb = if inp.devices_total > 0 {
        (raw_needed_tb / inp.devices_total as f64).min(inp.device_tb)
    } else {
        inp.device_tb
    };
    let rebuild_read_tb = per_device_tb * rebuild_factor;
    let usable_bps = inp.cross_rack_gbps * 1e9 / 8.0 * inp.bandwidth_utilisation.clamp(0.01, 1.0);
    let repair_hours = if usable_bps > 0.0 {
        rebuild_read_tb * bytes_per_tb / usable_bps / 3600.0
    } else {
        f64::INFINITY
    };
    let nines = durability_nines(n, f, inp.annual_disk_afr, repair_hours);
    let tco = raw_needed_tb * inp.disk_cost_per_tb_year * inp.years;

    let mut reasons = Vec::new();
    let mut feasible = true;
    if min_devices > inp.devices_total {
        feasible = false;
        reasons.push(Reason::NeedsDevices {
            need: min_devices,
            have: inp.devices_total,
            text: format!(
                "needs {min_devices} devices in distinct failure domains; this cluster has {}",
                inp.devices_total
            ),
        });
    }
    if min_devices > inp.zone_count && inp.zone_count > 0 && min_devices <= inp.devices_total {
        reasons.push(Reason::FewerZones {
            need: min_devices,
            zones: inp.zone_count,
            text: format!(
                "more fragments ({min_devices}) than zones ({}), so some zones hold several",
                inp.zone_count
            ),
        });
    }
    if write_fanout >= write_quorum && write_fanout - write_quorum == 0 {
        reasons.push(Reason::NoWriteMargin {
            text: "write quorum equals the fanout — one node down stops writes".into(),
        });
    }

    let meets_durability = nines >= inp.target_durability_nines;
    let meets_repair_time = repair_hours <= inp.max_repair_hours;
    let meets_node_loss = tolerates >= inp.tolerate_node_loss;

    Row {
        label,
        kind,
        replicas,
        ec_k,
        ec_m,
        amplification: amp,
        raw_needed_tb,
        min_devices,
        min_failure_domains: min_devices,
        write_quorum,
        write_fanout,
        write_margin: write_fanout as i32 - write_quorum as i32,
        read_min_devices: read_min,
        tolerates_loss: tolerates,
        rebuild_read_tb,
        repair_hours,
        durability_nines: nines,
        tco,
        feasible,
        reasons,
        meets_durability,
        meets_repair_time,
        meets_node_loss,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(candidates: Vec<Candidate>) -> Inputs {
        Inputs {
            raw_tb: 1000.0,
            disk_cost_per_tb_year: 20.0,
            cross_rack_gbps: 10.0,
            bandwidth_utilisation: 0.5,
            target_durability_nines: 11.0,
            max_repair_hours: 8.0,
            tolerate_node_loss: 1,
            annual_disk_afr: 0.02,
            node_count: 3,
            devices_total: 3,
            zone_count: 3,
            device_tb: 100.0,
            years: 5.0,
            candidates,
        }
    }

    #[test]
    fn replication_amplification_and_quorum() {
        let r = &evaluate(&base(vec![Candidate::Replication { replicas: 3 }]))[0];
        assert_eq!(r.amplification, 3.0);
        assert_eq!(r.raw_needed_tb, 3000.0);
        assert_eq!(r.min_devices, 3);
        // Swift's quorum_size(3) = 2
        assert_eq!(r.write_quorum, 2);
        assert_eq!(r.write_margin, 1);
        assert_eq!(r.read_min_devices, 1);
        assert_eq!(r.tolerates_loss, 2);
        assert!(r.feasible);
    }

    #[test]
    fn ec_write_quorum_is_k_plus_min_parity_not_k() {
        let r = &evaluate(&base(vec![Candidate::Ec {
            k: 2,
            m: 1,
            ec_type: "liberasurecode_rs_vand".into(),
        }]))[0];
        // The whole point: 2+1 needs 3 of 3 to accept a write.
        assert_eq!(r.write_quorum, 3);
        assert_eq!(r.write_fanout, 3);
        assert_eq!(r.write_margin, 0, "zero write margin");
        assert!(r
            .reasons
            .iter()
            .any(|x| matches!(x, Reason::NoWriteMargin { .. })));
        // ...but reads survive one loss.
        assert_eq!(r.read_min_devices, 2);
        assert_eq!(r.tolerates_loss, 1);
        assert!((r.amplification - 1.5).abs() < 1e-9);
    }

    #[test]
    fn wide_ec_is_infeasible_on_a_small_cluster() {
        let rows = evaluate(&base(vec![
            Candidate::Ec { k: 4, m: 2, ec_type: d_ec_type() },
            Candidate::Ec { k: 8, m: 3, ec_type: d_ec_type() },
        ]));
        assert!(!rows[0].feasible);
        assert!(matches!(rows[0].reasons[0], Reason::NeedsDevices { need: 6, have: 3, .. }));
        assert!(!rows[1].feasible);
        assert!(matches!(rows[1].reasons[0], Reason::NeedsDevices { need: 11, have: 3, .. }));
    }

    #[test]
    fn ec_rebuild_reads_k_times_more_than_replication() {
        let mut inp = base(vec![
            Candidate::Replication { replicas: 3 },
            Candidate::Ec { k: 4, m: 2, ec_type: d_ec_type() },
        ]);
        inp.devices_total = 12; // make both placeable so the comparison is fair
        let rows = evaluate(&inp);
        let (repl, ec) = (&rows[0], &rows[1]);
        // Both fill a 100 TB device here, so the comparison is per-device and
        // direct: replacing one device reads its own contents under
        // replication, but k=4 devices' worth under EC.
        assert!((repl.rebuild_read_tb - 100.0).abs() < 1e-6, "{}", repl.rebuild_read_tb);
        assert!((ec.rebuild_read_tb - 400.0).abs() < 1e-6, "{}", ec.rebuild_read_tb);
        let ratio = ec.rebuild_read_tb / repl.rebuild_read_tb;
        assert!((ratio - 4.0).abs() < 1e-6, "EC repair should read 4x, got {ratio}");
        // ...and that shows up directly as a longer repair window.
        assert!(ec.repair_hours > repl.repair_hours * 3.9);
    }

    #[test]
    fn more_copies_means_more_nines() {
        let rows = evaluate(&base(vec![
            Candidate::Replication { replicas: 2 },
            Candidate::Replication { replicas: 3 },
        ]));
        assert!(
            rows[1].durability_nines > rows[0].durability_nines,
            "3 copies must beat 2: {} vs {}",
            rows[1].durability_nines,
            rows[0].durability_nines
        );
    }

    #[test]
    fn cheaper_amplification_means_lower_tco() {
        let rows = evaluate(&base(vec![
            Candidate::Replication { replicas: 3 },
            Candidate::Ec { k: 2, m: 1, ec_type: d_ec_type() },
        ]));
        // 1.5x vs 3x on the same data.
        assert!(rows[1].tco < rows[0].tco);
        assert!((rows[0].tco / rows[1].tco - 2.0).abs() < 1e-9);
    }

    #[test]
    fn targets_are_reported_per_constraint() {
        let mut inp = base(vec![Candidate::Replication { replicas: 3 }]);
        inp.max_repair_hours = 0.0001;
        inp.tolerate_node_loss = 5;
        let r = &evaluate(&inp)[0];
        assert!(!r.meets_repair_time);
        assert!(!r.meets_node_loss, "3 copies cannot survive 5 losses");
    }

    /// The recommendation is the whole point of the page: of what fits and
    /// clears every target, take the cheapest.
    #[test]
    fn recommends_the_cheapest_scheme_that_clears_every_target() {
        let mut inp = base(vec![
            Candidate::Replication { replicas: 3 },
            Candidate::Ec { k: 2, m: 1, ec_type: d_ec_type() },
        ]);
        inp.devices_total = 12;
        inp.target_durability_nines = 1.0;
        inp.max_repair_hours = 10000.0;
        inp.tolerate_node_loss = 1;
        let rows = evaluate(&inp);
        let rec = recommend(&rows);
        assert_eq!(rec.outcome, "meets_all");
        // EC 2+1 stores the same data on half the disks and still survives one
        // loss, so it wins on price.
        assert_eq!(rec.best, Some(1));
        assert_eq!(rec.runner_up, Some(0));
    }

    #[test]
    fn a_scheme_that_cannot_be_placed_is_never_recommended() {
        // Only wide EC is offered, and this cluster has three devices.
        let rows = evaluate(&base(vec![Candidate::Ec {
            k: 8,
            m: 3,
            ec_type: d_ec_type(),
        }]));
        let rec = recommend(&rows);
        assert_eq!(rec.outcome, "none");
        assert!(rec.best.is_none());
    }

    /// When nothing clears every target the tool still has to answer, and it
    /// has to say which target it is giving up.
    #[test]
    fn names_the_target_a_compromise_gives_up() {
        let mut inp = base(vec![
            Candidate::Replication { replicas: 2 },
            Candidate::Replication { replicas: 3 },
        ]);
        inp.target_durability_nines = 99.0; // unreachable by anything here
        inp.max_repair_hours = 10000.0; // so durability is the only miss
        let rows = evaluate(&inp);
        let rec = recommend(&rows);
        assert_eq!(rec.outcome, "compromise");
        assert_eq!(rec.unmet, vec!["durability"]);
        // Both miss durability, so price decides: two copies.
        assert_eq!(rec.best, Some(0));
    }
}
