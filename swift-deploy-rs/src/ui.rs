use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::safety::{SafetyPolicy, redact};
use crate::workspace::WorkspaceRequest;
use crate::{Inventory, Plan};

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_CSS: &str = include_str!("../web/app.css");
const APP_JS: &str = include_str!("../web/app.js");
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const LOG_LIMIT: usize = 16;

#[derive(Debug, Clone)]
pub struct UiOptions {
    pub bind: String,
    pub port: u16,
    pub bundle: PathBuf,
    pub inventory: PathBuf,
    pub playbook: PathBuf,
    pub plan: PathBuf,
    pub known_hosts: Option<PathBuf>,
    pub auth_token_file: Option<PathBuf>,
    pub workspace_root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UiConfig {
    bundle: String,
    inventory: String,
    playbook: String,
    plan: String,
    #[serde(default)]
    known_hosts: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
struct ApplyRequest {
    #[serde(flatten)]
    config: UiConfig,
    confirm_digest: String,
    approval: String,
    #[serde(default)]
    allow_disk_wipe: bool,
    #[serde(default)]
    allow_firewall: bool,
    #[serde(default)]
    allow_ssh_reconfigure: bool,
    #[serde(default)]
    allow_host_reconfigure: bool,
}

impl From<&UiOptions> for UiConfig {
    fn from(options: &UiOptions) -> Self {
        Self {
            bundle: options.bundle.to_string_lossy().into_owned(),
            inventory: options.inventory.to_string_lossy().into_owned(),
            playbook: options.playbook.to_string_lossy().into_owned(),
            plan: options.plan.to_string_lossy().into_owned(),
            known_hosts: options
                .known_hosts
                .as_ref()
                .map_or_else(String::new, |path| path.to_string_lossy().into_owned()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum JobStatus {
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy)]
enum Action {
    Audit,
    Validate,
    Plan,
    Preflight,
}

impl Action {
    const fn name(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Validate => "validate",
            Self::Plan => "plan",
            Self::Preflight => "preflight",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct JobRecord {
    id: u64,
    kind: String,
    state: JobStatus,
    message: String,
    started_unix: u64,
}

#[derive(Debug, Clone, Serialize)]
struct LogEntry {
    time_unix: u64,
    kind: String,
    ok: bool,
    message: String,
}

#[derive(Debug, Serialize)]
struct UiState {
    config: UiConfig,
    audit: Option<Value>,
    inventory: Option<Value>,
    plan: Option<Value>,
    preflight: Option<Value>,
    execution: Option<Value>,
    workspace: Option<Value>,
    job: Option<JobRecord>,
    log: VecDeque<LogEntry>,
    #[serde(skip)]
    next_job: u64,
    #[serde(skip)]
    bundle_root: PathBuf,
    #[serde(skip)]
    workspace_root: PathBuf,
}

impl UiState {
    fn new(options: &UiOptions) -> Self {
        Self {
            config: UiConfig::from(options),
            audit: None,
            inventory: None,
            plan: None,
            preflight: None,
            execution: None,
            workspace: None,
            job: None,
            log: VecDeque::new(),
            next_job: 1,
            bundle_root: options.bundle.clone(),
            workspace_root: options.workspace_root.clone(),
        }
    }

    fn push_log(&mut self, kind: &str, ok: bool, message: impl Into<String>) {
        self.log.push_front(LogEntry {
            time_unix: unix_seconds(),
            kind: kind.to_owned(),
            ok,
            message: message.into(),
        });
        self.log.truncate(LOG_LIMIT);
    }
}

pub fn serve(options: UiOptions) -> Result<()> {
    let bind = options
        .bind
        .parse::<IpAddr>()
        .with_context(|| format!("UI bind address must be an IP address: {}", options.bind))?;
    if !bind.is_loopback() {
        bail!("UI server only accepts a loopback bind address");
    }
    let listener = TcpListener::bind((bind, options.port))
        .with_context(|| format!("bind Swift Deploy UI to {}:{}", options.bind, options.port))?;
    let address = listener
        .local_addr()
        .context("read Swift Deploy UI address")?;
    let token = Arc::new(process_token(address));
    let authorization = Arc::new(load_ui_authorization(options.auth_token_file.as_deref())?);
    let state = Arc::new(Mutex::new(UiState::new(&options)));
    let executable = Arc::new(std::env::current_exe().context("locate swift-deploy executable")?);
    println!("swift-deploy ui -> http://{address}");

    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let token = Arc::clone(&token);
                let state = Arc::clone(&state);
                let executable = Arc::clone(&executable);
                let authorization = Arc::clone(&authorization);
                thread::spawn(move || {
                    if let Err(error) = serve_connection(
                        stream,
                        &token,
                        authorization.as_deref(),
                        &state,
                        &executable,
                    ) {
                        eprintln!("UI request error: {error:#}");
                    }
                });
            }
            Err(error) => eprintln!("UI connection error: {error}"),
        }
    }
    Ok(())
}

fn process_token(address: SocketAddr) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let source = format!("{}:{now}:{address}", std::process::id());
    hex::encode(Sha256::digest(source.as_bytes()))
}

fn load_ui_authorization(path: Option<&Path>) -> Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("read UI auth token metadata {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("UI auth token must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("UI auth token file must not be accessible by group or other users");
        }
    }
    let secret = fs::read_to_string(path)
        .with_context(|| format!("read UI auth token {}", path.display()))?;
    let secret = secret.trim();
    if secret.len() < 24 || secret.chars().any(char::is_whitespace) {
        bail!("UI auth token must contain at least 24 non-whitespace characters");
    }
    let credentials =
        base64::engine::general_purpose::STANDARD.encode(format!("operator:{secret}"));
    Ok(Some(format!("Basic {credentials}")))
}

fn serve_connection(
    mut stream: TcpStream,
    token: &str,
    authorization: Option<&str>,
    state: &Arc<Mutex<UiState>>,
    executable: &Arc<PathBuf>,
) -> Result<()> {
    let request = read_request(&mut stream)?;
    let response = route(&request, token, authorization, state, executable);
    write_response(&mut stream, response)
}

struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

impl HttpResponse {
    fn text(status: &'static str, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
            headers: Vec::new(),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    fn json(status: &'static str, value: &impl Serialize) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => Self::text(status, "application/json", body),
            Err(error) => Self::text(
                "500 Internal Server Error",
                "application/json",
                format!(r#"{{"error":"serialize response: {error}"}}"#),
            ),
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .context("set UI request timeout")?;
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            bail!("UI request headers exceed {MAX_HEADER_BYTES} bytes");
        }
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).context("read UI HTTP headers")?;
        if read == 0 {
            bail!("incomplete UI HTTP headers");
        }
        bytes.extend_from_slice(&chunk[..read]);
    };
    let header = std::str::from_utf8(&bytes[..header_end]).context("UI headers are not UTF-8")?;
    let mut lines = header.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    let method = request_line.next().unwrap_or_default().to_owned();
    let path = request_line
        .next()
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect::<BTreeMap<_, _>>();
    let content_length = headers
        .get("content-length")
        .map_or(Ok(0), |value| value.parse::<usize>())
        .context("invalid UI Content-Length")?;
    if content_length > MAX_BODY_BYTES {
        bail!("UI request body exceeds {MAX_BODY_BYTES} bytes");
    }
    let total = header_end + content_length;
    while bytes.len() < total {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).context("read UI HTTP body")?;
        if read == 0 {
            bail!("incomplete UI HTTP body");
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        body: bytes[header_end..total].to_vec(),
    })
}

fn route(
    request: &HttpRequest,
    token: &str,
    authorization: Option<&str>,
    state: &Arc<Mutex<UiState>>,
    executable: &Arc<PathBuf>,
) -> HttpResponse {
    if request.path != "/healthz"
        && authorization.is_some_and(|expected| {
            request
                .headers
                .get("authorization")
                .is_none_or(|provided| !secure_text_equal(expected, provided))
        })
    {
        return HttpResponse::json(
            "401 Unauthorized",
            &json!({"error": "operator authentication required"}),
        )
        .with_header(
            "WWW-Authenticate",
            "Basic realm=\"Swift Deploy\", charset=\"UTF-8\"",
        );
    }
    if request.method == "POST" && request.path.starts_with("/api/") {
        if !mutation_is_authorized(request, token) {
            return HttpResponse::json(
                "403 Forbidden",
                &json!({"error": "missing or invalid anti-CSRF token"}),
            );
        }
        if !request
            .headers
            .get("content-type")
            .is_some_and(|value| value.starts_with("application/json"))
        {
            return HttpResponse::json(
                "415 Unsupported Media Type",
                &json!({"error": "application/json is required"}),
            );
        }
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/" | "/index.html") => HttpResponse::text(
            "200 OK",
            "text/html; charset=utf-8",
            INDEX_HTML.replace("__UI_TOKEN__", token),
        ),
        ("GET", "/app.css") => HttpResponse::text("200 OK", "text/css; charset=utf-8", APP_CSS),
        ("GET", "/app.js") => {
            HttpResponse::text("200 OK", "application/javascript; charset=utf-8", APP_JS)
        }
        ("GET", "/favicon.ico") => {
            HttpResponse::text("204 No Content", "image/x-icon", Vec::<u8>::new())
        }
        ("GET", "/healthz") => HttpResponse::json("200 OK", &json!({"ok": true})),
        ("GET", "/api/state") => match state.lock() {
            Ok(state) => HttpResponse::json("200 OK", &*state),
            Err(_) => HttpResponse::json(
                "500 Internal Server Error",
                &json!({"error": "UI state lock is poisoned"}),
            ),
        },
        ("POST", "/api/workspace/preview") => {
            let workspace = match serde_json::from_slice::<WorkspaceRequest>(&request.body) {
                Ok(workspace) => workspace,
                Err(error) => {
                    return HttpResponse::json(
                        "400 Bad Request",
                        &json!({"error": format!("invalid workspace configuration: {error}")}),
                    );
                }
            };
            let bundle = match state.lock() {
                Ok(state) => state.bundle_root.clone(),
                Err(_) => {
                    return HttpResponse::json(
                        "500 Internal Server Error",
                        &json!({"error": "UI state lock is poisoned"}),
                    );
                }
            };
            match workspace.preview(bundle) {
                Ok(preview) => HttpResponse::json("200 OK", &preview),
                Err(error) => HttpResponse::json(
                    "400 Bad Request",
                    &json!({"error": sanitize_text(&format!("{error:#}"))}),
                ),
            }
        }
        ("POST", "/api/workspace/generate") => {
            let workspace = match serde_json::from_slice::<WorkspaceRequest>(&request.body) {
                Ok(workspace) => workspace,
                Err(error) => {
                    return HttpResponse::json(
                        "400 Bad Request",
                        &json!({"error": format!("invalid workspace configuration: {error}")}),
                    );
                }
            };
            let report = workspace.validate();
            if !report.valid {
                return match state.lock() {
                    Ok(state) => match workspace.preview(&state.bundle_root) {
                        Ok(preview) => HttpResponse::json("422 Unprocessable Entity", &preview),
                        Err(error) => HttpResponse::json(
                            "422 Unprocessable Entity",
                            &json!({"error": sanitize_text(&format!("{error:#}"))}),
                        ),
                    },
                    Err(_) => HttpResponse::json(
                        "500 Internal Server Error",
                        &json!({"error": "UI state lock is poisoned"}),
                    ),
                };
            }
            let (bundle, workspace_root, known_hosts) = match state.lock() {
                Ok(state) => (
                    state.bundle_root.clone(),
                    state.workspace_root.clone(),
                    state.config.known_hosts.clone(),
                ),
                Err(_) => {
                    return HttpResponse::json(
                        "500 Internal Server Error",
                        &json!({"error": "UI state lock is poisoned"}),
                    );
                }
            };
            match workspace.generate(&bundle, &workspace_root) {
                Ok(generated) => {
                    let mut response =
                        serde_json::to_value(&generated).unwrap_or_else(|_| json!({}));
                    if let Some(object) = response.as_object_mut() {
                        object.insert("ok".to_owned(), Value::Bool(true));
                    }
                    if let Ok(mut state) = state.lock() {
                        state.config = UiConfig {
                            bundle: bundle.to_string_lossy().into_owned(),
                            inventory: generated.inventory.to_string_lossy().into_owned(),
                            playbook: generated.playbook.to_string_lossy().into_owned(),
                            plan: generated.plan.to_string_lossy().into_owned(),
                            known_hosts,
                        };
                        state.audit = None;
                        state.inventory = None;
                        state.plan = None;
                        state.preflight = None;
                        state.execution = None;
                        state.workspace = Some(response.clone());
                        state.push_log("workspace", true, "deployment workspace generated");
                    }
                    HttpResponse::json("201 Created", &response)
                }
                Err(error) => HttpResponse::json(
                    "409 Conflict",
                    &json!({"error": sanitize_text(&format!("{error:#}"))}),
                ),
            }
        }
        ("POST", "/api/audit" | "/api/validate" | "/api/plan" | "/api/preflight") => {
            let config = match serde_json::from_slice::<UiConfig>(&request.body) {
                Ok(config) => config,
                Err(error) => {
                    return HttpResponse::json(
                        "400 Bad Request",
                        &json!({"error": format!("invalid UI configuration: {error}")}),
                    );
                }
            };
            let action = match request.path.as_str() {
                "/api/audit" => Action::Audit,
                "/api/validate" => Action::Validate,
                "/api/plan" => Action::Plan,
                _ => Action::Preflight,
            };
            match start_action(action, config, Arc::clone(state), Arc::clone(executable)) {
                Ok(id) => HttpResponse::json("202 Accepted", &json!({"ok": true, "id": id})),
                Err(error) => HttpResponse::json(
                    "409 Conflict",
                    &json!({"error": sanitize_text(&format!("{error:#}"))}),
                ),
            }
        }
        ("POST", "/api/apply") => {
            let request = match serde_json::from_slice::<ApplyRequest>(&request.body) {
                Ok(request) => request,
                Err(error) => {
                    return HttpResponse::json(
                        "400 Bad Request",
                        &json!({"error": format!("invalid Apply request: {error}")}),
                    );
                }
            };
            match start_apply(request, Arc::clone(state), Arc::clone(executable)) {
                Ok(id) => HttpResponse::json("202 Accepted", &json!({"ok": true, "id": id})),
                Err(error) => HttpResponse::json(
                    "400 Bad Request",
                    &json!({"error": sanitize_text(&format!("{error:#}"))}),
                ),
            }
        }
        _ => HttpResponse::json("404 Not Found", &json!({"error": "not found"})),
    }
}

fn secure_text_equal(left: &str, right: &str) -> bool {
    let left = Sha256::digest(left.as_bytes());
    let right = Sha256::digest(right.as_bytes());
    left == right
}

fn mutation_is_authorized(request: &HttpRequest, token: &str) -> bool {
    let token_matches = request
        .headers
        .get("x-swift-deploy-token")
        .is_some_and(|value| value == token);
    let same_origin = request
        .headers
        .get("sec-fetch-site")
        .is_none_or(|value| matches!(value.as_str(), "same-origin" | "none"));
    token_matches && same_origin
}

fn start_action(
    action: Action,
    config: UiConfig,
    state: Arc<Mutex<UiState>>,
    executable: Arc<PathBuf>,
) -> Result<u64> {
    validate_action_config(action, &config)?;
    let id = {
        let mut state = state
            .lock()
            .map_err(|_| anyhow::anyhow!("UI state lock is poisoned"))?;
        if state
            .job
            .as_ref()
            .is_some_and(|job| job.state == JobStatus::Running)
        {
            bail!("another deployment UI job is already running");
        }
        let id = state.next_job;
        state.next_job += 1;
        state.config = config.clone();
        if matches!(action, Action::Validate | Action::Plan) {
            state.preflight = None;
        }
        state.job = Some(JobRecord {
            id,
            kind: action.name().to_owned(),
            state: JobStatus::Running,
            message: format!("{} started", action.name()),
            started_unix: unix_seconds(),
        });
        state.push_log(action.name(), true, format!("{} started", action.name()));
        id
    };

    thread::spawn(move || {
        let outcome = execute_action(action, &config, &executable);
        if let Ok(mut state) = state.lock() {
            match outcome {
                Ok(result) => {
                    match action {
                        Action::Audit => state.audit = Some(result.value),
                        Action::Validate => state.inventory = Some(result.value),
                        Action::Plan => state.plan = Some(result.value),
                        Action::Preflight => state.preflight = Some(result.value),
                    }
                    if let Some(job) = state.job.as_mut() {
                        job.state = JobStatus::Succeeded;
                        job.message.clone_from(&result.message);
                    }
                    state.push_log(action.name(), true, result.message);
                }
                Err(error) => {
                    let message = sanitize_text(&format!("{error:#}"));
                    if let Some(job) = state.job.as_mut() {
                        job.state = JobStatus::Failed;
                        job.message.clone_from(&message);
                    }
                    state.push_log(action.name(), false, message);
                }
            }
        }
    });
    Ok(id)
}

struct ActionResult {
    value: Value,
    message: String,
}

fn execute_action(action: Action, config: &UiConfig, executable: &PathBuf) -> Result<ActionResult> {
    let arguments = action_arguments(action, config);
    let output = Command::new(executable)
        .args(&arguments)
        .output()
        .with_context(|| format!("run swift-deploy {}", action.name()))?;
    if !output.status.success() {
        bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    match action {
        Action::Audit => Ok(ActionResult {
            value: serde_json::from_slice(&output.stdout).context("parse audit JSON")?,
            message: "bundle audit passed".to_owned(),
        }),
        Action::Validate => {
            let mut value: Value =
                serde_json::from_slice(&output.stdout).context("parse validation JSON")?;
            if let Some(object) = value.as_object_mut() {
                let blockers = inventory_apply_blockers(Path::new(&config.inventory));
                object.insert(
                    "sample".to_owned(),
                    Value::Bool(is_sample_inventory(&config.inventory) || !blockers.is_empty()),
                );
                object.insert(
                    "apply_blockers".to_owned(),
                    Value::Array(blockers.into_iter().map(Value::String).collect()),
                );
            }
            Ok(ActionResult {
                value,
                message: "inventory validation passed".to_owned(),
            })
        }
        Action::Plan => Ok(ActionResult {
            value: plan_summary(&config.plan, &config.inventory)?,
            message: "sealed plan created".to_owned(),
        }),
        Action::Preflight => {
            let value: Value =
                serde_json::from_slice(&output.stdout).context("parse preflight JSON")?;
            let message = if value.get("ok").and_then(Value::as_bool) == Some(true) {
                "target preflight passed"
            } else {
                "target preflight blocked execution"
            };
            Ok(ActionResult {
                value,
                message: message.to_owned(),
            })
        }
    }
}

fn action_arguments(action: Action, config: &UiConfig) -> Vec<String> {
    match action {
        Action::Audit => vec![
            "audit".to_owned(),
            "--bundle".to_owned(),
            config.bundle.clone(),
            "--json".to_owned(),
        ],
        Action::Validate => vec![
            "validate".to_owned(),
            "--inventory".to_owned(),
            config.inventory.clone(),
            "--json".to_owned(),
        ],
        Action::Plan => vec![
            "plan".to_owned(),
            "--bundle".to_owned(),
            config.bundle.clone(),
            "--inventory".to_owned(),
            config.inventory.clone(),
            "--playbook".to_owned(),
            config.playbook.clone(),
            "--output".to_owned(),
            config.plan.clone(),
        ],
        Action::Preflight => {
            let mut arguments = vec![
                "preflight".to_owned(),
                "--inventory".to_owned(),
                config.inventory.clone(),
            ];
            if !config.bundle.trim().is_empty() {
                arguments.push("--bundle".to_owned());
                arguments.push(config.bundle.clone());
            }
            if !config.known_hosts.trim().is_empty() {
                arguments.push("--known-hosts".to_owned());
                arguments.push(config.known_hosts.clone());
            }
            arguments.push("--json".to_owned());
            arguments
        }
    }
}

fn validate_action_config(action: Action, config: &UiConfig) -> Result<()> {
    match action {
        Action::Audit => validate_path("bundle", &config.bundle),
        Action::Validate | Action::Preflight => validate_path("inventory", &config.inventory),
        Action::Plan => {
            validate_path("bundle", &config.bundle)?;
            validate_path("inventory", &config.inventory)?;
            validate_path("playbook", &config.playbook)?;
            validate_path("plan", &config.plan)
        }
    }
}

fn plan_summary(path: &str, inventory_path: &str) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read UI plan {path}"))?;
    let plan: Plan = serde_json::from_slice(&bytes).context("parse UI plan JSON")?;
    plan.verify()?;
    let mut host_roles = BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    let mut risk_actions = Vec::new();
    for task in plan.tasks.iter().chain(&plan.handlers) {
        for host in &task.hosts {
            host_roles
                .entry(host.clone())
                .or_default()
                .insert(task.role.clone());
        }
        if !task.risk.is_empty() {
            risk_actions.push(json!({
                "hosts": task.hosts,
                "role": task.role,
                "task": task.name,
                "source": task.source,
                "risks": task.risk,
            }));
        }
    }
    let inventory = Inventory::load(Path::new(inventory_path))?;
    let host_disks = plan
        .hosts
        .iter()
        .map(|host| {
            let context = inventory.host_context(host)?;
            let disks = context
                .get("custom_disks")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            Ok((host.clone(), disks))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(json!({
        "digest": plan.digest,
        "hosts": plan.hosts.len(),
        "host_names": plan.hosts,
        "host_roles": host_roles,
        "host_disks": host_disks,
        "tasks": plan.tasks.len(),
        "handlers": plan.handlers.len(),
        "risks": plan.required_capabilities(),
        "risk_actions": risk_actions,
        "playbook": plan.playbook,
    }))
}

fn is_sample_inventory(path: &str) -> bool {
    path.replace('\\', "/")
        .split('/')
        .any(|component| component == "config_sample")
}

fn inventory_apply_blockers(path: &Path) -> Vec<String> {
    let mut blockers = Vec::new();
    if is_sample_inventory(&path.to_string_lossy()) {
        blockers.push(
            "bundled config_sample is a structure example, not a deployable cluster".to_owned(),
        );
    }

    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let mut inputs = vec![path.to_path_buf()];
    for directory in [base.join("group_vars"), base.join("host_vars")] {
        if let Ok(entries) = fs::read_dir(directory) {
            inputs.extend(entries.flatten().map(|entry| entry.path()).filter(|path| {
                path.is_file()
                    && !matches!(
                        path.extension().and_then(|value| value.to_str()),
                        Some("py" | "sh")
                    )
            }));
        }
    }
    let marker_patterns = [
        "/path/to/id_ed25519",
        "enter mariadb",
        "enter keystone",
        "your auth url ip",
        "please set your",
        "pfsuser: xxxxx",
        "tester: testing",
        "tester1: testing1",
        "os_tester: testing",
        "testak: 33774a2e8567",
        "6c3c3fba: d347c28c7b3c",
        "encryption_root_secret = changeme",
    ];
    for input in inputs {
        let Ok(content) = fs::read_to_string(&input) else {
            continue;
        };
        let lowered = content.to_ascii_lowercase();
        for marker in marker_patterns {
            if lowered.contains(marker) {
                blockers.push(format!(
                    "sample or placeholder value {marker:?} remains in {}",
                    input.display()
                ));
            }
        }
    }

    let inventory = match Inventory::load(path) {
        Ok(inventory) => inventory,
        Err(error) => {
            blockers.push(format!("inventory cannot be loaded: {error:#}"));
            blockers.sort();
            blockers.dedup();
            return blockers;
        }
    };
    for group_name in [
        "proxy_servers",
        "account_servers",
        "container_servers",
        "object_servers",
    ] {
        if inventory
            .groups
            .get(group_name)
            .is_none_or(|group| group.hosts.is_empty())
        {
            blockers.push(format!(
                "required inventory group {group_name} has no hosts"
            ));
        }
    }
    for host_name in inventory.hosts.keys() {
        let Ok(context) = inventory.host_context(host_name) else {
            blockers.push(format!("cannot resolve variables for host {host_name}"));
            continue;
        };
        let Some(vars) = context.as_object() else {
            blockers.push(format!("host {host_name} has no variable context"));
            continue;
        };
        for field in [
            "ansible_user",
            "management_network_address",
            "storage_network_address",
            "business_network_address",
        ] {
            if field == "ansible_user" {
                if vars.get(field).and_then(Value::as_str) != Some("root") {
                    blockers.push(format!("host {host_name} must use ansible_user=root"));
                }
            } else if vars
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                blockers.push(format!("host {host_name} is missing {field}"));
            }
        }
    }
    let auth_method = inventory
        .groups
        .get("proxy_servers")
        .and_then(|group| group.vars.get("auth_method"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let rust_stack = inventory
        .groups
        .get("all")
        .and_then(|group| group.vars.get("deploy_stack"))
        .and_then(Value::as_str)
        .map(str::trim)
        == Some("rust");
    if auth_method == "keystone" && !rust_stack {
        for group_name in ["mariadb_servers", "keystones"] {
            if inventory
                .groups
                .get(group_name)
                .is_none_or(|group| group.hosts.is_empty())
            {
                blockers.push(format!(
                    "auth_method=keystone requires a non-empty {group_name} group"
                ));
            }
        }
    }
    blockers.sort();
    blockers.dedup();
    blockers
}

fn validate_apply_request(request: &ApplyRequest) -> Result<Plan> {
    let blockers = inventory_apply_blockers(Path::new(&request.config.inventory));
    if !blockers.is_empty() {
        bail!(
            "Apply is disabled for a sample inventory or unsafe configuration until all blockers are fixed: {}",
            blockers.join("; ")
        );
    }
    if request.approval != "APPLY" {
        bail!("type APPLY to arm execution");
    }
    if request.confirm_digest.len() != 64 {
        bail!("paste the complete 64-character plan digest");
    }
    validate_path("plan", &request.config.plan)?;
    let bytes = fs::read(&request.config.plan)
        .with_context(|| format!("read UI plan {}", request.config.plan))?;
    let plan: Plan = serde_json::from_slice(&bytes).context("parse UI Apply plan")?;
    plan.verify()?;
    if request.confirm_digest != plan.digest {
        bail!("confirmation does not match sealed digest");
    }
    SafetyPolicy {
        allow_disk_wipe: request.allow_disk_wipe,
        allow_firewall: request.allow_firewall,
        allow_ssh_reconfigure: request.allow_ssh_reconfigure,
        allow_host_reconfigure: request.allow_host_reconfigure,
    }
    .authorize(&plan)?;
    Ok(plan)
}

fn start_apply(
    request: ApplyRequest,
    state: Arc<Mutex<UiState>>,
    executable: Arc<PathBuf>,
) -> Result<u64> {
    validate_apply_request(&request)?;
    let id = {
        let mut state = state
            .lock()
            .map_err(|_| anyhow::anyhow!("UI state lock is poisoned"))?;
        if state
            .job
            .as_ref()
            .is_some_and(|job| job.state == JobStatus::Running)
        {
            bail!("another deployment UI job is already running");
        }
        let id = state.next_job;
        state.next_job += 1;
        state.config = request.config.clone();
        state.job = Some(JobRecord {
            id,
            kind: "apply".to_owned(),
            state: JobStatus::Running,
            message: "approved plan execution started".to_owned(),
            started_unix: unix_seconds(),
        });
        state.push_log("apply", true, "approved plan execution started");
        id
    };

    thread::spawn(move || {
        let arguments = apply_arguments(&request);
        let outcome = Command::new(&*executable)
            .args(&arguments)
            .output()
            .context("run swift-deploy apply")
            .and_then(|output| {
                if output.status.success() {
                    serde_json::from_slice::<Value>(&output.stdout)
                        .context("parse Apply execution report")
                } else {
                    bail!("{}", String::from_utf8_lossy(&output.stderr).trim())
                }
            });
        if let Ok(mut state) = state.lock() {
            match outcome {
                Ok(report) => {
                    state.execution = Some(report);
                    if let Some(job) = state.job.as_mut() {
                        job.state = JobStatus::Succeeded;
                        "approved plan execution completed".clone_into(&mut job.message);
                    }
                    state.push_log("apply", true, "approved plan execution completed");
                }
                Err(error) => {
                    let message = sanitize_text(&format!("{error:#}"));
                    if let Some(job) = state.job.as_mut() {
                        job.state = JobStatus::Failed;
                        job.message.clone_from(&message);
                    }
                    state.push_log("apply", false, message);
                }
            }
        }
    });
    Ok(id)
}

fn apply_arguments(request: &ApplyRequest) -> Vec<String> {
    let mut arguments = vec![
        "apply".to_owned(),
        "--bundle".to_owned(),
        request.config.bundle.clone(),
        "--inventory".to_owned(),
        request.config.inventory.clone(),
        "--plan".to_owned(),
        request.config.plan.clone(),
        "--confirm-digest".to_owned(),
        request.confirm_digest.clone(),
    ];
    if !request.config.known_hosts.trim().is_empty() {
        arguments.push("--known-hosts".to_owned());
        arguments.push(request.config.known_hosts.clone());
    }
    for (allowed, flag) in [
        (request.allow_disk_wipe, "--allow-disk-wipe"),
        (request.allow_firewall, "--allow-firewall"),
        (request.allow_ssh_reconfigure, "--allow-ssh-reconfigure"),
        (request.allow_host_reconfigure, "--allow-host-reconfigure"),
    ] {
        if allowed {
            arguments.push(flag.to_owned());
        }
    }
    arguments.push("--json".to_owned());
    arguments
}

fn validate_path(label: &str, path: &str) -> Result<()> {
    if path.trim().is_empty() {
        bail!("{label} path is required");
    }
    if path.len() > 4096 || path.contains('\0') {
        bail!("{label} path is invalid");
    }
    Ok(())
}

fn sanitize_text(text: &str) -> String {
    let redacted = redact(&Value::String(text.to_owned()));
    let text = redacted.as_str().unwrap_or("redacted UI error");
    text.chars().take(2000).collect()
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn write_response(stream: &mut TcpStream, response: HttpResponse) -> Result<()> {
    write!(
        stream,
        concat!(
            "HTTP/1.1 {}\r\n",
            "Content-Type: {}\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n"
        ),
        response.status,
        response.content_type,
        response.body.len()
    )
    .context("write UI HTTP status headers")?;
    for (name, value) in &response.headers {
        write!(stream, "{name}: {value}\r\n").context("write UI extra header")?;
    }
    write!(
        stream,
        concat!(
            "Cache-Control: no-store\r\n",
            "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\n",
            "Cross-Origin-Opener-Policy: same-origin\r\n",
            "Referrer-Policy: no-referrer\r\n",
            "X-Content-Type-Options: nosniff\r\n",
            "X-Frame-Options: DENY\r\n",
            "\r\n"
        ),
    )
    .context("write UI HTTP headers")?;
    stream
        .write_all(&response.body)
        .context("write UI HTTP body")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn configured_basic_auth_protects_everything_except_health() {
        let directory = tempdir().expect("auth test directory");
        let token_file = directory.path().join("ui-token");
        fs::write(&token_file, "0123456789abcdef0123456789abcdef\n").expect("write auth token");
        fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600))
            .expect("secure auth token");
        let authorization = load_ui_authorization(Some(&token_file))
            .expect("load auth token")
            .expect("authorization configured");
        let options = UiOptions {
            bind: "127.0.0.1".to_owned(),
            port: 8788,
            bundle: "bundle".into(),
            inventory: "bundle/config_sample/swift_hosts".into(),
            playbook: "bundle/swift.yml".into(),
            plan: "swift-plan.json".into(),
            known_hosts: None,
            auth_token_file: Some(token_file),
            workspace_root: directory.path().join("projects"),
        };
        let state = Arc::new(Mutex::new(UiState::new(&options)));
        let executable = Arc::new(PathBuf::from("swift-deploy"));
        let request = HttpRequest {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };
        let denied = route(&request, "csrf", Some(&authorization), &state, &executable);
        assert_eq!(denied.status, "401 Unauthorized");
        assert!(
            denied
                .headers
                .iter()
                .any(|(name, _)| name == "WWW-Authenticate")
        );

        let mut authorized = request;
        authorized
            .headers
            .insert("authorization".to_owned(), authorization.clone());
        assert_eq!(
            route(
                &authorized,
                "csrf",
                Some(&authorization),
                &state,
                &executable
            )
            .status,
            "200 OK"
        );

        let health = HttpRequest {
            method: "GET".to_owned(),
            path: "/healthz".to_owned(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        };
        assert_eq!(
            route(&health, "csrf", Some("Basic invalid"), &state, &executable).status,
            "200 OK"
        );
    }
}
