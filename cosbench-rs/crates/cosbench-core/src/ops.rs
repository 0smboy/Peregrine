use crate::config::Operation;
use crate::generator::ObjectGenerator;
use crate::integrity::{generate_payload, verify_payload};
use crate::metrics::StageMetrics;
use crate::storage::Storage;
use rand::distributions::WeightedIndex;
use rand::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Write,
    Read,
    Delete,
    List,
    CreateContainer,
    DeleteContainer,
}

impl OpKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "write" | "w" => Some(Self::Write),
            "read" | "r" => Some(Self::Read),
            "delete" | "d" => Some(Self::Delete),
            "list" | "l" => Some(Self::List),
            "create_container" | "init_container" => Some(Self::CreateContainer),
            "delete_container" => Some(Self::DeleteContainer),
            _ => None,
        }
    }
}

pub struct OpChooser {
    kinds: Vec<OpKind>,
    dist: WeightedIndex<u32>,
    range: Option<(u64, u64)>,
    range_enabled: bool,
}

impl OpChooser {
    pub fn from_operations(ops: &[Operation]) -> anyhow::Result<Self> {
        let mut kinds = Vec::new();
        let mut weights = Vec::new();
        let mut range = None;
        let mut range_enabled = false;
        for op in ops {
            let k = OpKind::parse(&op.op_type)
                .ok_or_else(|| anyhow::anyhow!("unknown op type `{}`", op.op_type))?;
            kinds.push(k);
            weights.push(op.ratio);
            if op
                .config
                .get("is_range_request")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false)
            {
                range_enabled = true;
                let start = op
                    .config
                    .get("range_start")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let end = op
                    .config
                    .get("range_end")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(4096);
                range = Some((start, end));
            }
        }
        if weights.iter().all(|&w| w == 0) {
            anyhow::bail!("all operation ratios are 0");
        }
        let dist = WeightedIndex::new(&weights)?;
        Ok(Self {
            kinds,
            dist,
            range,
            range_enabled,
        })
    }

    pub fn pick(&self, rng: &mut impl Rng) -> OpKind {
        self.kinds[self.dist.sample(rng)]
    }

    pub fn range_for_read(&self, rng: &mut impl Rng) -> Option<(u64, u64)> {
        if !self.range_enabled {
            return None;
        }
        let (lo, hi) = self.range.unwrap_or((0, 4096));
        if hi < lo {
            return Some((hi, lo));
        }
        if lo == hi {
            return Some((lo, hi));
        }
        let a = rng.gen_range(lo..=hi);
        let b = rng.gen_range(lo..=hi);
        Some((a.min(b), a.max(b)))
    }
}

pub struct WorkerCtx {
    pub storage: Arc<dyn Storage>,
    pub gen: ObjectGenerator,
    pub chooser: OpChooser,
    pub metrics: StageMetrics,
    pub stop: Arc<AtomicBool>,
    pub global_ops: Arc<AtomicU64>,
    pub total_ops_limit: u64,
    pub worker_id: u32,
    pub sequential: bool,
    pub seq_counter: Arc<AtomicU64>,
}

pub async fn worker_loop(ctx: Arc<WorkerCtx>) {
    let mut rng = StdRng::seed_from_u64(0xC05B_u64 ^ u64::from(ctx.worker_id));
    while !ctx.stop.load(Ordering::Relaxed) {
        if ctx.total_ops_limit > 0 {
            let n = ctx.global_ops.fetch_add(1, Ordering::Relaxed);
            if n >= ctx.total_ops_limit {
                ctx.stop.store(true, Ordering::Relaxed);
                break;
            }
        }
        let op = ctx.chooser.pick(&mut rng);
        run_one(&ctx, op, &mut rng).await;
    }
}

/// Object-level target: sequential mode walks the full container × object
/// cross product (COSBench prepare semantics).
fn pick_object_target(ctx: &WorkerCtx, rng: &mut impl Rng) -> (u64, String, u64, String) {
    if ctx.sequential {
        let seq = ctx.seq_counter.fetch_add(1, Ordering::Relaxed);
        let ((cid, c), (oid, o)) = ctx.gen.sequential_pair(seq);
        (cid, c, oid, o)
    } else {
        let (cid, c) = ctx.gen.random_container(rng);
        let (oid, o) = ctx.gen.random_object(rng);
        (cid, c, oid, o)
    }
}

/// Container-level target: sequential mode iterates the container range
/// directly (one step per op), so init/cleanup visit every container.
fn pick_container_target(ctx: &WorkerCtx, rng: &mut impl Rng) -> (u64, String) {
    if ctx.sequential {
        let seq = ctx.seq_counter.fetch_add(1, Ordering::Relaxed);
        ctx.gen.sequential_container(seq)
    } else {
        ctx.gen.random_container(rng)
    }
}

async fn run_one(ctx: &WorkerCtx, op: OpKind, rng: &mut impl Rng) {
    let start = Instant::now();
    let result = match op {
        OpKind::Write => {
            let (_cid, c, oid, o) = pick_object_target(ctx, rng);
            let size = ctx.gen.random_size(rng);
            let payload = generate_payload(size, ctx.gen.hash_check(), oid);
            let nbytes = payload.len() as u64;
            match ctx.storage.put_object(&c, &o, payload).await {
                Ok(()) => Ok(nbytes),
                Err(e) => Err(e.to_string()),
            }
        }
        OpKind::Read => {
            let (_cid, c, _oid, o) = pick_object_target(ctx, rng);
            let range = ctx.chooser.range_for_read(rng);
            match ctx.storage.get_object(&c, &o, range).await {
                Ok(data) => {
                    let n = data.len() as u64;
                    if ctx.gen.hash_check() && range.is_none() {
                        if let Err(e) = verify_payload(&data) {
                            Err(e)
                        } else {
                            Ok(n)
                        }
                    } else {
                        Ok(n)
                    }
                }
                Err(e) => Err(e.to_string()),
            }
        }
        OpKind::Delete => {
            let (_cid, c, _oid, o) = pick_object_target(ctx, rng);
            match ctx.storage.delete_object(&c, &o).await {
                Ok(()) => Ok(0),
                Err(e) => Err(e.to_string()),
            }
        }
        OpKind::List => {
            let (_cid, c) = pick_container_target(ctx, rng);
            let prefix = ctx.gen.spec().oprefix.clone();
            match ctx.storage.list_objects(&c, &prefix).await {
                Ok(list) => Ok(list.len() as u64),
                Err(e) => Err(e.to_string()),
            }
        }
        OpKind::CreateContainer => {
            let (_cid, c) = pick_container_target(ctx, rng);
            match ctx.storage.create_container(&c).await {
                Ok(()) => Ok(0),
                Err(e) => Err(e.to_string()),
            }
        }
        OpKind::DeleteContainer => {
            let (_cid, c) = pick_container_target(ctx, rng);
            match ctx.storage.delete_container(&c).await {
                Ok(()) => Ok(0),
                Err(e) => Err(e.to_string()),
            }
        }
    };
    let lat = start.elapsed();
    match result {
        Ok(bytes) => ctx.metrics.record_ok(lat, bytes),
        Err(msg) => ctx.metrics.record_err(lat, msg),
    }
}
