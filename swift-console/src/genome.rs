//! Cluster Genome Lab — evolve ring weights under simulated faults.
//!
//! Candidates are weight vectors. Each generation mutates, runs a small fault
//! suite through `swift-ring-sim`, scores a multi-objective fitness vector, and
//! keeps the Pareto front. Nothing writes back to production rings.

use crate::util::esc;
use crate::{i18n, lab, ringlab, AppState};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Fitness {
    /// Higher is better: fraction of partitions still readable under faults.
    pub availability: f64,
    /// Lower is better (stored positive; dominance treats as minimize).
    pub migration: f64,
    /// Lower is better: zone concentration / imbalance.
    pub concentration: f64,
    /// Lower is better: proxy for repair work (parts needing handoff-like moves).
    pub repair: f64,
    /// Lower is better: absolute balance percent.
    pub waste: f64,
}

/// True if `a` dominates `b` (all objectives ≥ / ≤ as appropriate, strict on one).
pub fn dominates(a: &Fitness, b: &Fitness) -> bool {
    let ge = a.availability >= b.availability
        && a.migration <= b.migration
        && a.concentration <= b.concentration
        && a.repair <= b.repair
        && a.waste <= b.waste;
    let gt = a.availability > b.availability
        || a.migration < b.migration
        || a.concentration < b.concentration
        || a.repair < b.repair
        || a.waste < b.waste;
    ge && gt
}

pub fn pareto_front(xs: &[(Vec<f64>, Fitness)]) -> Vec<(Vec<f64>, Fitness)> {
    let mut front = Vec::new();
    for (i, (w, f)) in xs.iter().enumerate() {
        let dominated = xs.iter().enumerate().any(|(j, (_, g))| j != i && dominates(g, f));
        if !dominated {
            front.push((w.clone(), f.clone()));
        }
    }
    front
}

#[derive(Clone, Debug)]
struct DeviceGene {
    id: u64,
    weight: f64,
    zone: u64,
    node: String,
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Tiny deterministic LCG for reproducible runs.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.0
    }
    fn f64(&mut self) -> f64 {
        (self.next() >> 11) as f64 / ((1u64 << 53) as f64)
    }
    fn usize(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() as usize) % n
        }
    }
}

fn extract_devices(topo: &Value) -> Vec<DeviceGene> {
    let mut out = Vec::new();
    let devices = topo
        .get("devices")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    for d in devices {
        // ring_sim inspect uses `dev_id` (not `id`).
        let id = d
            .get("dev_id")
            .or_else(|| d.get("id"))
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let weight = d.get("weight").and_then(|x| x.as_f64()).unwrap_or(100.0);
        let zone = d.get("zone").and_then(|x| x.as_u64()).unwrap_or(0);
        let ip = d.get("ip").and_then(|x| x.as_str()).unwrap_or("");
        out.push(DeviceGene {
            id,
            weight,
            zone,
            node: ip.to_string(),
        });
    }
    out
}

fn mutate(weights: &[f64], rng: &mut Rng) -> Vec<f64> {
    let mut w = weights.to_vec();
    if w.is_empty() {
        return w;
    }
    let i = rng.usize(w.len());
    let factor = 0.7 + rng.f64() * 0.6; // 0.7..1.3
    w[i] = (w[i] * factor).clamp(1.0, 10000.0);
    w
}

fn crossover(a: &[f64], b: &[f64], rng: &mut Rng) -> Vec<f64> {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| if rng.f64() < 0.5 { *x } else { *y })
        .collect()
}

fn fitness_from_sim(sim: &Value, _baseline_balance: f64) -> Fitness {
    // ring_sim simulate JSON: survival / movement / devices / dispersion_*.
    let survival = sim.get("survival").cloned().unwrap_or(json!({}));
    let full = survival
        .get("parts_full")
        .and_then(|x| x.as_f64().or_else(|| x.as_u64().map(|u| u as f64)))
        .unwrap_or(0.0);
    let total = survival
        .get("parts_total")
        .and_then(|x| x.as_f64().or_else(|| x.as_u64().map(|u| u as f64)))
        .unwrap_or(1.0)
        .max(1.0);
    let availability = (full / total).clamp(0.0, 1.0);

    let movement = sim.get("movement").cloned().unwrap_or(json!({}));
    let migration = movement
        .get("slots_moved")
        .and_then(|x| x.as_f64().or_else(|| x.as_u64().map(|u| u as f64)))
        .unwrap_or(0.0);
    let repair = movement
        .get("parts_touched")
        .and_then(|x| x.as_f64().or_else(|| x.as_u64().map(|u| u as f64)))
        .unwrap_or(migration * 0.5);

    let balance = sim
        .get("devices")
        .and_then(|x| x.as_array())
        .map(|devs| {
            devs.iter()
                .filter_map(|d| d.get("balance_pct").and_then(|b| b.as_f64()))
                .map(|b| b.abs())
                .fold(0.0_f64, f64::max)
        })
        .unwrap_or(0.0);

    let zone_overlaps = sim
        .pointer("/dispersion_after/zone_overlaps")
        .and_then(|x| x.as_f64().or_else(|| x.as_u64().map(|u| u as f64)))
        .unwrap_or(0.0);
    let concentration = (zone_overlaps / total).clamp(0.0, 1.0);

    Fitness {
        availability,
        migration,
        concentration,
        repair,
        waste: balance,
    }
}

async fn evaluate_weights(
    state: &Arc<AppState>,
    devices: &[DeviceGene],
    weights: &[f64],
    rng: &mut Rng,
) -> Result<Fitness, String> {
    let mut ops = Vec::new();
    for (d, w) in devices.iter().zip(weights.iter()) {
        ops.push(json!({"op": "set_weight", "dev_id": d.id, "weight": w}));
    }
    // Fault suite: fail one device + soft-stress another in its zone, then
    // rebalance so migration is measured.
    if !devices.is_empty() {
        let victim = &devices[rng.usize(devices.len())];
        ops.push(json!({"op": "fail_device", "dev_id": victim.id}));
        let zone = victim.zone;
        let zone_devs: Vec<&DeviceGene> = devices.iter().filter(|d| d.zone == zone).collect();
        if let Some(zd) = zone_devs.get(rng.usize(zone_devs.len().max(1))) {
            if zd.id != victim.id {
                ops.push(json!({"op": "set_weight", "dev_id": zd.id, "weight": zd.weight * 0.1}));
            }
        }
    }
    let scenario = json!({
        "ops": ops,
        "rebalance": true,
    });
    let sim = ringlab::simulate(state, 0, &scenario).await?;
    Ok(fitness_from_sim(&sim, 0.0))
}

#[derive(Clone, Debug, Serialize)]
struct GenomeResult {
    id: String,
    started: f64,
    generations: u32,
    population: u32,
    front: Vec<Value>,
    note: String,
}

static LAST: LazyLock<Mutex<Option<GenomeResult>>> = LazyLock::new(|| Mutex::new(None));

#[derive(Deserialize)]
pub struct EvolveBody {
    #[serde(default = "d_gen")]
    pub generations: u32,
    #[serde(default = "d_pop")]
    pub population: u32,
    #[serde(default)]
    pub seed: u64,
}

fn d_gen() -> u32 {
    8
}
fn d_pop() -> u32 {
    16
}

fn label_front(front: &[(Vec<f64>, Fitness)]) -> Vec<Value> {
    // Tag extremes for operators.
    let mut out = Vec::new();
    if front.is_empty() {
        return out;
    }
    let mut best_mig = 0usize;
    let mut best_av = 0usize;
    let mut best_waste = 0usize;
    let mut best_repair = 0usize;
    for (i, (_, f)) in front.iter().enumerate() {
        if f.migration < front[best_mig].1.migration {
            best_mig = i;
        }
        if f.availability > front[best_av].1.availability {
            best_av = i;
        }
        if f.waste < front[best_waste].1.waste {
            best_waste = i;
        }
        if f.repair < front[best_repair].1.repair {
            best_repair = i;
        }
    }
    for (i, (w, f)) in front.iter().enumerate() {
        let mut tags = Vec::new();
        if i == best_mig {
            tags.push("lowest_migration");
        }
        if i == best_av {
            tags.push("highest_availability");
        }
        if i == best_waste {
            tags.push("lowest_waste");
        }
        if i == best_repair {
            tags.push("fastest_repair_proxy");
        }
        out.push(json!({
            "tags": tags,
            "fitness": f,
            "weights": w,
        }));
    }
    out
}

/// POST /lab/api/genome/evolve
pub async fn evolve(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<EvolveBody>,
) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let gens = body.generations.clamp(1, 20);
    let pop = body.population.clamp(4, 32);
    let seed = if body.seed == 0 {
        now_secs() as u64
    } else {
        body.seed
    };
    let mut rng = Rng(seed);

    let topo = match ringlab::topology(&state, 0).await {
        Ok(v) => v,
        Err(e) => {
            return Json(json!({"ok": false, "error": e})).into_response();
        }
    };
    let devices = extract_devices(&topo);
    if devices.is_empty() {
        return Json(json!({"ok": false, "error": "no devices in object ring"})).into_response();
    }
    let base: Vec<f64> = devices.iter().map(|d| d.weight).collect();

    let mut population: Vec<(Vec<f64>, Fitness)> = Vec::new();
    for _ in 0..pop {
        let w = mutate(&base, &mut rng);
        match evaluate_weights(&state, &devices, &w, &mut rng).await {
            Ok(f) => population.push((w, f)),
            Err(e) => {
                return Json(json!({"ok": false, "error": e})).into_response();
            }
        }
    }

    for _ in 0..gens {
        let front = pareto_front(&population);
        let mut next = front.clone();
        while next.len() < pop as usize {
            let a = &population[rng.usize(population.len())];
            let b = &population[rng.usize(population.len())];
            let child = mutate(&crossover(&a.0, &b.0, &mut rng), &mut rng);
            match evaluate_weights(&state, &devices, &child, &mut rng).await {
                Ok(f) => next.push((child, f)),
                Err(e) => {
                    return Json(json!({"ok": false, "error": e})).into_response();
                }
            }
        }
        population = next;
    }

    let front = pareto_front(&population);
    let labeled = label_front(&front);
    let id = format!("g{:x}", now_secs() as u64);
    let result = GenomeResult {
        id: id.clone(),
        started: now_secs(),
        generations: gens,
        population: pop,
        front: labeled.clone(),
        note: "Weight-only evolution. Fault suite zeros a device and stresses a zone; rebalance measures migration. Nothing is written to the live ring.".into(),
    };
    *LAST.lock().unwrap() = Some(result.clone());
    Json(json!({
        "ok": true,
        "id": id,
        "generations": gens,
        "population": pop,
        "front": labeled,
        "device_ids": devices.iter().map(|d| d.id).collect::<Vec<_>>(),
        "baseline_weights": base,
        "note": result.note,
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct ResultQ {
    #[serde(default)]
    pub id: String,
}

/// GET /lab/api/genome/result
pub async fn result(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(_q): Query<ResultQ>,
) -> Response {
    if let Err(r) = lab::require_lab_api(&state, &headers) {
        return r;
    }
    let _ = state;
    match LAST.lock().unwrap().as_ref() {
        Some(r) => Json(json!({
            "ok": true,
            "id": r.id,
            "generations": r.generations,
            "population": r.population,
            "front": r.front,
            "note": r.note,
        }))
        .into_response(),
        None => Json(json!({"ok": false, "error": "no genome run yet"})).into_response(),
    }
}

fn render(lang: &str, last: Option<&GenomeResult>) -> String {
    let mut cards = String::new();
    if let Some(r) = last {
        for (i, c) in r.front.iter().enumerate() {
            let tags = c
                .get("tags")
                .and_then(|x| x.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let f = c.get("fitness").cloned().unwrap_or(json!({}));
            cards.push_str(&format!(
                "<div class=\"genome-card\"><h3>Plan {}</h3>\
                 <p class=\"note\">{}</p>\
                 <ul>\
                 <li>availability: {:.3}</li>\
                 <li>migration: {:.0}</li>\
                 <li>concentration: {:.3}</li>\
                 <li>repair: {:.0}</li>\
                 <li>waste (balance%%): {:.2}</li>\
                 </ul></div>",
                (b'A' + (i as u8)) as char,
                esc(&tags),
                f.get("availability").and_then(|x| x.as_f64()).unwrap_or(0.0),
                f.get("migration").and_then(|x| x.as_f64()).unwrap_or(0.0),
                f.get("concentration").and_then(|x| x.as_f64()).unwrap_or(0.0),
                f.get("repair").and_then(|x| x.as_f64()).unwrap_or(0.0),
                f.get("waste").and_then(|x| x.as_f64()).unwrap_or(0.0),
            ));
        }
        if cards.is_empty() {
            cards = format!("<p class=\"note\">{}</p>", esc(i18n::t(lang, "genome.empty")));
        }
    } else {
        cards = format!("<p class=\"note\">{}</p>", esc(i18n::t(lang, "genome.idle")));
    }

    format!(
        r#"<div class="pagehead"><h1>{title}</h1></div>
<p class="statline">{blurb}</p>
<p class="note">{note}</p>
<div class="page-sec">
  <button type="button" class="btn" id="genome-run">{run}</button>
</div>
<div class="page-sec genome-front">{cards}</div>
<script>
(function(){{
  document.getElementById('genome-run').onclick = async () => {{
    const btn = document.getElementById('genome-run');
    btn.disabled = true; btn.textContent = '...';
    const r = await fetch('/lab/api/genome/evolve', {{
      method:'POST', credentials:'same-origin',
      headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{generations:8, population:16}})
    }});
    await r.json();
    location.reload();
  }};
}})();
</script>"#,
        title = esc(i18n::t(lang, "lab.tool.genome.title")),
        blurb = esc(i18n::t(lang, "lab.tool.genome.blurb")),
        note = esc(i18n::t(lang, "genome.note")),
        run = esc(i18n::t(lang, "genome.btn.run")),
        cards = cards,
    )
}

/// GET /lab/genome
pub async fn page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (_, sess) = match lab::require_lab(&state, &headers) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let lang = i18n::lang(&headers);
    let last = LAST.lock().unwrap().clone();
    let body = render(lang, last.as_ref());
    crate::pages::lab_tool_shell(&state, &headers, &sess, "genome", body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dominance_and_pareto() {
        let a = Fitness {
            availability: 0.99,
            migration: 10.0,
            concentration: 0.4,
            repair: 5.0,
            waste: 2.0,
        };
        let b = Fitness {
            availability: 0.90,
            migration: 50.0,
            concentration: 0.8,
            repair: 20.0,
            waste: 8.0,
        };
        let c = Fitness {
            availability: 0.95,
            migration: 5.0,
            concentration: 0.5,
            repair: 8.0,
            waste: 3.0,
        };
        assert!(dominates(&a, &b));
        assert!(!dominates(&a, &c)); // trade-off on migration vs availability
        let pop = vec![(vec![1.0], a.clone()), (vec![2.0], b), (vec![3.0], c.clone())];
        let front = pareto_front(&pop);
        assert_eq!(front.len(), 2);
        assert!(front.iter().any(|(_, f)| f == &a));
        assert!(front.iter().any(|(_, f)| f == &c));
    }
}
