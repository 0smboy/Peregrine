use anyhow::Context;
use axum::extract::{Path, State};
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use cosbench_core::report::ReportBundle;
use cosbench_core::xml_import::import_cosbench_xml;
use cosbench_core::{Driver, Workload};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "cosbench-rs", version, about = "Cloud object storage benchmark (Rust)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run a workload YAML
    Run {
        #[arg(short, long)]
        config: String,
        #[arg(long)]
        report_dir: Option<String>,
    },
    /// Validate a workload YAML
    Validate {
        #[arg(short, long)]
        config: String,
    },
    /// Import COSBench XML subset to YAML
    ImportXml {
        #[arg(short, long)]
        input: String,
        #[arg(short, long)]
        output: String,
    },
    /// HTTP control plane + simple dashboard
    Serve {
        #[arg(long, default_value = "0.0.0.0:8080")]
        bind: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Validate { config } => {
            let wl = Workload::from_yaml_file(&config).with_context(|| format!("load {config}"))?;
            println!("OK: workload `{}` with {} stage(s)", wl.name, wl.stages.len());
            Ok(())
        }
        Cmd::ImportXml { input, output } => {
            let xml = std::fs::read_to_string(&input)?;
            let wl = import_cosbench_xml(&xml)?;
            std::fs::write(&output, wl.to_yaml()?)?;
            println!("wrote {output}");
            Ok(())
        }
        Cmd::Run { config, report_dir } => {
            let wl = Workload::from_yaml_file(&config).with_context(|| format!("load {config}"))?;
            let name = wl.name.clone();
            println!("Running workload: {name}");
            let driver = Driver::new(wl);
            let reports = driver.run_all().await?;
            print_table(&reports);
            if let Some(dir) = report_dir {
                let bundle = ReportBundle::from_stages(&name, &reports);
                let json_path = format!("{dir}/{name}.json");
                let csv_path = format!("{dir}/{name}.csv");
                bundle.write_json(&json_path)?;
                bundle.write_csv(&csv_path)?;
                println!("reports: {json_path}, {csv_path}");
            }
            Ok(())
        }
        Cmd::Serve { bind } => {
            let addr: SocketAddr = bind.parse()?;
            let state = AppState::default();
            let app = Router::new()
                .route("/", get(index))
                .route("/api/health", get(|| async { "ok" }))
                .route("/api/workloads", post(submit_workload).get(list_workloads))
                .route("/api/workloads/{id}", get(get_workload))
                .with_state(state)
                .layer(CorsLayer::permissive());
            println!("cosbench-rs serve on http://{addr}");
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
            Ok(())
        }
    }
}

fn print_table(reports: &[cosbench_core::StageReport]) {
    println!();
    println!(
        "{:<16} {:>8} {:>8} {:>8} {:>10} {:>10} {:>10} {:>10}",
        "STAGE", "OK", "FAIL", "SUCC%", "OPS/s", "MiB/s", "p50us", "p99us"
    );
    for r in reports {
        let ops = r.metrics.throughput_ops(r.elapsed_secs);
        let bw = r.metrics.bandwidth_mib_s(r.elapsed_secs);
        println!(
            "{:<16} {:>8} {:>8} {:>7.2}% {:>10.1} {:>10.2} {:>10} {:>10}",
            r.name,
            r.metrics.ops_ok,
            r.metrics.ops_fail,
            r.metrics.success_ratio * 100.0,
            ops,
            bw,
            r.metrics.lat_p50_us,
            r.metrics.lat_p99_us
        );
        for e in r.metrics.sample_errors.iter().take(5) {
            println!("  err: {e}");
        }
    }
}

#[derive(Clone, Default)]
struct AppState {
    inner: Arc<RwLock<HashMap<String, Job>>>,
}

#[derive(Clone, Serialize)]
struct Job {
    id: String,
    name: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<ReportBundle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct SubmitBody {
    /// Inline YAML text
    yaml: Option<String>,
    /// Or path on server filesystem
    path: Option<String>,
}

async fn index() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html><head><meta charset=utf-8><title>cosbench-rs</title>
<style>
body{font-family:ui-monospace,Menlo,monospace;max-width:960px;margin:2rem auto;padding:0 1rem;background:#111;color:#e8e8e8}
h1{font-weight:600;letter-spacing:.02em}
textarea{width:100%;height:220px;background:#1a1a1a;color:#e8e8e8;border:1px solid #333;padding:.75rem}
button{background:#e8e8e8;color:#111;border:0;padding:.5rem 1rem;margin-top:.5rem;cursor:pointer}
pre{background:#1a1a1a;padding:1rem;overflow:auto;border:1px solid #333}
a{color:#9cf}
</style></head>
<body>
<h1>cosbench-rs</h1>
<p>POST YAML workloads. API: <code>/api/workloads</code>, health <code>/api/health</code>.</p>
<textarea id=y placeholder="paste workload YAML"></textarea>
<br><button onclick="run()">Submit</button>
<pre id=o>idle</pre>
<script>
async function run(){
  const yaml=document.getElementById('y').value;
  const r=await fetch('/api/workloads',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({yaml})});
  const j=await r.json();
  document.getElementById('o').textContent=JSON.stringify(j,null,2);
  if(j.id){poll(j.id)}
}
async function poll(id){
  for(;;){
    await new Promise(r=>setTimeout(r,500));
    const r=await fetch('/api/workloads/'+id);
    const j=await r.json();
    document.getElementById('o').textContent=JSON.stringify(j,null,2);
    if(j.status==='done'||j.status==='error')break;
  }
}
</script>
</body></html>"#,
    )
}

async fn submit_workload(
    State(st): State<AppState>,
    Json(body): Json<SubmitBody>,
) -> Result<Json<Job>, (axum::http::StatusCode, String)> {
    let yaml = if let Some(y) = body.yaml {
        y
    } else if let Some(p) = body.path {
        std::fs::read_to_string(p).map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?
    } else {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "yaml or path required".into(),
        ));
    };
    let wl: Workload = serde_yaml::from_str(&yaml)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    wl.validate()
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;
    let id = Uuid::new_v4().to_string();
    let name = wl.name.clone();
    let job = Job {
        id: id.clone(),
        name: name.clone(),
        status: "running".into(),
        report: None,
        error: None,
    };
    st.inner.write().insert(id.clone(), job.clone());

    let st2 = st.clone();
    let id2 = id.clone();
    tokio::spawn(async move {
        let result = Driver::new(wl).run_all().await;
        let mut map = st2.inner.write();
        if let Some(j) = map.get_mut(&id2) {
            match result {
                Ok(reports) => {
                    j.status = "done".into();
                    j.report = Some(ReportBundle::from_stages(&j.name, &reports));
                }
                Err(e) => {
                    j.status = "error".into();
                    j.error = Some(format!("{e:#}"));
                }
            }
        }
    });

    Ok(Json(job))
}

async fn list_workloads(State(st): State<AppState>) -> Json<Vec<Job>> {
    let map = st.inner.read();
    Json(map.values().cloned().collect())
}

async fn get_workload(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Job>, axum::http::StatusCode> {
    st.inner
        .read()
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or(axum::http::StatusCode::NOT_FOUND)
}
