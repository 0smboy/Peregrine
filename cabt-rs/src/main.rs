mod collect;
mod env_cfg;
mod fool;
mod list;
mod progress;
mod remove;
mod report_xlsx;
mod runner;
mod task;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "cabt",
    version,
    about = "Automation benchmark tool using cosbench-rs / Cosbench (Rust)"
)]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a fool suite or a single task like 64KB_write_100
    Run {
        /// "fool" or task name e.g. 64KB_write_100
        target: String,
        #[arg(long)]
        start_task: Option<String>,
        #[arg(long)]
        rerun_task: Option<String>,
        #[arg(long)]
        collect: bool,
        #[arg(long)]
        prepare_worker: Option<u32>,
        #[arg(long)]
        object_count: Option<u64>,
        #[arg(long)]
        container_count: Option<u64>,
        #[arg(long)]
        runtime: Option<u64>,
        /// cosbench-rs (default; auto-selects Swift when ST_AUTH is set),
        /// swift (tempauth via ST_AUTH/ST_USER/ST_KEY), java, or mock
        #[arg(long, default_value = "cosbench-rs")]
        backend: String,
        #[arg(long, default_value = "http://127.0.0.1:19088/controller")]
        cosbench_url: String,
    },
    /// List finished tasks
    List {
        /// pass "fool" to list fool results
        mode: Option<String>,
    },
    /// Remove a result by wid or clear fool results
    Remove {
        target: String,
        /// remove from fool dir by wid
        #[arg(short = 'f', long)]
        fool: bool,
    },
    /// Collect normal results into a CSV report
    Collect {
        #[arg(long)]
        out: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .init();

    match cli.cmd {
        Commands::Run {
            target,
            start_task,
            rerun_task,
            collect,
            prepare_worker,
            object_count,
            container_count,
            runtime,
            backend,
            cosbench_url,
        } => {
            if target == "fool" {
                if collect {
                    collect::collect_fool()?;
                } else if let Some(t) = rerun_task {
                    fool::rerun_one(&t, &backend, &cosbench_url).await?;
                } else {
                    fool::run_suite(start_task.as_deref(), &backend, &cosbench_url).await?;
                    collect::collect_fool()?;
                }
            } else {
                let overrides = runner::RunOverrides {
                    prepare_worker,
                    object_count,
                    container_count,
                    runtime,
                    worker_cap: None,
                };
                runner::run_task(&target, overrides, &backend, &cosbench_url, false).await?;
            }
        }
        Commands::List { mode } => list::list_results(mode.as_deref())?,
        Commands::Remove { target, fool } => remove::remove(&target, fool)?,
        Commands::Collect { out } => collect::collect_normal(out.as_deref())?,
    }
    Ok(())
}
