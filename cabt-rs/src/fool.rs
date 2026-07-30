use crate::runner::{self, RunOverrides};
use crate::task::FOOL_SUITE;
use anyhow::{bail, Result};
use tracing::info;

pub async fn run_suite(
    start_task: Option<&str>,
    backend: &str,
    cosbench_url: &str,
) -> Result<()> {
    let start = start_task.unwrap_or("64KB_read_1");
    let mut idx = FOOL_SUITE
        .iter()
        .position(|t| *t == start)
        .ok_or_else(|| anyhow::anyhow!("unknown fool task: {start}"))?;
    for job in &FOOL_SUITE[idx..] {
        println!("job is: {job}");
        run_one_with_defaults(job, backend, cosbench_url).await?;
        idx += 1;
        info!(done = idx, total = FOOL_SUITE.len(), "fool progress");
    }
    Ok(())
}

pub async fn rerun_one(task: &str, backend: &str, cosbench_url: &str) -> Result<()> {
    if !FOOL_SUITE.contains(&task) {
        bail!("unknown fool task: {task}");
    }
    run_one_with_defaults(task, backend, cosbench_url).await?;
    Ok(())
}

async fn run_one_with_defaults(task: &str, backend: &str, cosbench_url: &str) -> Result<()> {
    // mirror fool_job sizes
    let (mut object_count, mut prepare_worker) = if task.starts_with("100MB") {
        (500u64, 100u32)
    } else if task.starts_with("10MB") {
        (5000, 300)
    } else {
        (10000, 1500)
    };

    // Capacity knobs for constrained clusters (all default to full fool):
    //   CABT_FOOL_SCALE       multiply object_count + prepare_worker (e.g. 0.02)
    //   CABT_FOOL_WORKER_CAP  cap the normal/prepare concurrency
    //   CABT_FOOL_RUNTIME     per-task normal-stage seconds (default 150)
    let scale = env_f64("CABT_FOOL_SCALE").filter(|s| *s > 0.0);
    if let Some(s) = scale {
        object_count = ((object_count as f64 * s).round() as u64).max(1);
        prepare_worker = ((prepare_worker as f64 * s).round() as u32).max(1);
    }
    let worker_cap = env_u64("CABT_FOOL_WORKER_CAP").map(|c| c.max(1) as u32);
    let runtime = env_u64("CABT_FOOL_RUNTIME");
    // prepare writes the container × object cross product, so containers
    // multiply stored bytes; CABT_FOOL_CONTAINERS caps that on small disks.
    let container_count = env_u64("CABT_FOOL_CONTAINERS").map(|c| c.max(1));

    let overrides = RunOverrides {
        object_count: Some(object_count),
        prepare_worker: Some(prepare_worker),
        container_count,
        runtime,
        worker_cap,
    };
    // for mock backend shrink
    let overrides = if backend == "mock" {
        RunOverrides {
            object_count: Some(20),
            prepare_worker: Some(4),
            container_count: Some(1),
            runtime: Some(2),
            worker_cap,
        }
    } else {
        overrides
    };
    runner::run_task(task, overrides, backend, cosbench_url, true).await?;
    Ok(())
}

fn env_f64(key: &str) -> Option<f64> {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok())
}

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok().and_then(|v| v.trim().parse().ok())
}
