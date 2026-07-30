use crate::auth::{self, AuthResult};
use crate::config::{StorageConfig, Workload};
use crate::generator::ObjectGenerator;
use crate::metrics::{MetricsSnapshot, StageMetrics};
use crate::ops::{worker_loop, OpChooser, WorkerCtx};
use crate::storage::mock::MockStorage;
use crate::storage::swift::SwiftStorage;
use crate::storage::Storage;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

pub struct Driver {
    workload: Workload,
}

#[derive(Debug, Clone, Serialize)]
pub struct StageReport {
    pub name: String,
    pub elapsed_secs: f64,
    #[serde(skip)]
    pub metrics: MetricsSnapshot,
}

impl Driver {
    pub fn new(workload: Workload) -> Self {
        Self { workload }
    }

    pub fn workload(&self) -> &Workload {
        &self.workload
    }

    pub async fn run_all(&self) -> anyhow::Result<Vec<StageReport>> {
        let auth_result = if let Some(auth_cfg) = &self.workload.auth {
            auth::authenticate(auth_cfg).await?
        } else {
            None
        };
        if let Some(ref r) = auth_result {
            info!(
                token_len = r.token.len(),
                storage_url = ?r.storage_url,
                "authenticated"
            );
        }

        let storage = build_storage(&self.workload.storage, auth_result.as_ref()).await?;
        let mut reports = Vec::new();
        for stage in &self.workload.stages {
            info!(
                stage = %stage.name,
                workers = stage.workers,
                sequential = stage.sequential,
                "starting stage"
            );
            let report = self.run_stage(storage.clone(), stage).await?;
            info!(
                stage = %report.name,
                ok = report.metrics.ops_ok,
                fail = report.metrics.ops_fail,
                success = format!("{:.2}%", report.metrics.success_ratio * 100.0),
                p99_us = report.metrics.lat_p99_us,
                "stage finished"
            );
            reports.push(report);
        }
        Ok(reports)
    }

    async fn run_stage(
        &self,
        storage: Arc<dyn Storage>,
        stage: &crate::config::Stage,
    ) -> anyhow::Result<StageReport> {
        let metrics = StageMetrics::new();
        let gen = ObjectGenerator::new(stage.objects.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let global_ops = Arc::new(AtomicU64::new(0));
        let seq_counter = Arc::new(AtomicU64::new(0));

        let start = Instant::now();
        let mut handles = Vec::new();
        for wid in 0..stage.workers {
            let ctx = Arc::new(WorkerCtx {
                storage: storage.clone(),
                gen: gen.clone(),
                chooser: OpChooser::from_operations(&stage.operations)?,
                metrics: metrics.clone(),
                stop: stop.clone(),
                global_ops: global_ops.clone(),
                total_ops_limit: stage.total_ops,
                worker_id: wid,
                sequential: stage.sequential
                    || stage.kind == "prepare"
                    || stage.kind == "cleanup"
                    || stage.kind == "init",
                seq_counter: seq_counter.clone(),
            });
            handles.push(tokio::spawn(worker_loop(ctx)));
        }

        if let Some(dur) = stage.duration() {
            let stop2 = stop.clone();
            tokio::spawn(async move {
                tokio::time::sleep(dur).await;
                stop2.store(true, Ordering::Relaxed);
            });
        }

        for h in handles {
            if let Err(e) = h.await {
                warn!("worker join error: {e}");
            }
        }

        Ok(StageReport {
            name: stage.name.clone(),
            elapsed_secs: start.elapsed().as_secs_f64(),
            metrics: metrics.snapshot(),
        })
    }
}

async fn build_storage(
    cfg: &StorageConfig,
    auth: Option<&AuthResult>,
) -> anyhow::Result<Arc<dyn Storage>> {
    match cfg {
        StorageConfig::Mock { latency_us } => Ok(Arc::new(MockStorage::new(*latency_us))),
        StorageConfig::S3 {
            endpoint,
            region,
            access_key,
            secret_key,
            path_style,
            timeout_ms,
            multipart_threshold,
            multipart_part_size,
        } => {
            #[cfg(feature = "s3")]
            {
                use crate::storage::s3::{S3Config, S3Storage};
                let s = S3Storage::connect(S3Config {
                    endpoint: endpoint.clone(),
                    region: region.clone(),
                    access_key: access_key.clone(),
                    secret_key: secret_key.clone(),
                    path_style: *path_style,
                    timeout: std::time::Duration::from_millis(*timeout_ms),
                    multipart_threshold: *multipart_threshold,
                    multipart_part_size: *multipart_part_size,
                })
                .await?;
                Ok(Arc::new(s))
            }
            #[cfg(not(feature = "s3"))]
            {
                let _ = (
                    endpoint, region, access_key, secret_key, path_style, timeout_ms,
                    multipart_threshold, multipart_part_size,
                );
                anyhow::bail!("S3 support not compiled");
            }
        }
        StorageConfig::Swift {
            endpoint,
            timeout_ms,
            token,
        } => {
            let token = token
                .clone()
                .or_else(|| auth.map(|a| a.token.clone()))
                .ok_or_else(|| anyhow::anyhow!("swift requires token or keystone auth"))?;
            let base = if endpoint.is_empty() {
                auth.and_then(|a| a.storage_url.clone())
                    .ok_or_else(|| anyhow::anyhow!("swift endpoint empty and no keystone storage_url"))?
            } else {
                endpoint.clone()
            };
            Ok(Arc::new(SwiftStorage::new(
                base,
                token,
                std::time::Duration::from_millis(*timeout_ms),
            )?))
        }
    }
}
