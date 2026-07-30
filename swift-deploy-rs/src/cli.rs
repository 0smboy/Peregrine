use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;
use tempfile::NamedTempFile;

use crate::bundle::audit_bundle;
use crate::executor::Executor;
use crate::inventory::{Inventory, fingerprint_inventory_inputs};
use crate::model::{Plan, SUPPORTED_MODULES};
use crate::planner::Planner;
use crate::preflight::run_preflight_with_bundle;
use crate::safety::SafetyPolicy;
use crate::template::Renderer;
use crate::transport::OpenSshTransport;
use crate::ui::{UiOptions, serve as serve_ui};

#[derive(Debug, Parser)]
#[command(
    name = "swift-deploy",
    version,
    about = "Rust-native, safety-gated Swift deployment"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Strictly audit the bundled v3 task/module/control surface.
    Audit {
        #[arg(long, default_value = "bundle")]
        bundle: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Parse and validate inventory/configuration without contacting hosts.
    Validate {
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Build a deterministic, sealed JSON plan without contacting hosts.
    Plan {
        #[arg(long, default_value = "bundle")]
        bundle: PathBuf,
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long)]
        playbook: PathBuf,
        #[arg(long, default_value = "swift-plan.json")]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Run read-only Rocky 9, network, repository, and disk checks on targets.
    Preflight {
        #[arg(long)]
        inventory: PathBuf,
        /// Active bundle directory; required to verify the rust-stack payload
        /// controller-side when the inventory carries `deploy_stack=rust`.
        #[arg(long)]
        bundle: Option<PathBuf>,
        #[arg(long)]
        known_hosts: Option<PathBuf>,
        #[arg(long)]
        allow_password: bool,
        #[arg(long)]
        json: bool,
    },
    /// Verify and execute an approved plan over strict OpenSSH.
    Apply {
        #[arg(long, default_value = "bundle")]
        bundle: PathBuf,
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        confirm_digest: String,
        #[arg(long)]
        known_hosts: Option<PathBuf>,
        #[arg(long)]
        allow_disk_wipe: bool,
        #[arg(long)]
        allow_firewall: bool,
        #[arg(long)]
        allow_ssh_reconfigure: bool,
        /// Permit package/repository, hostname, locale, `SELinux`, service, and cron changes.
        #[arg(long)]
        allow_host_reconfigure: bool,
        #[arg(long)]
        allow_password: bool,
        #[arg(long)]
        json: bool,
    },
    /// List the exact executable module compatibility surface.
    Modules {
        #[arg(long)]
        json: bool,
    },
    /// Run the loopback-only deployment control console.
    Ui {
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        #[arg(long, default_value_t = 8788)]
        port: u16,
        #[arg(long, default_value = "bundle")]
        bundle: PathBuf,
        #[arg(long, default_value = "bundle/config_sample/swift_hosts")]
        inventory: PathBuf,
        #[arg(long, default_value = "bundle/swift.yml")]
        playbook: PathBuf,
        #[arg(long, default_value = "swift-plan.json")]
        plan: PathBuf,
        #[arg(long)]
        known_hosts: Option<PathBuf>,
        /// File containing the HTTP Basic password for the loopback console.
        #[arg(long)]
        auth_token_file: Option<PathBuf>,
        /// Root directory for UI-generated deployment workspaces.
        #[arg(long, default_value = "/var/lib/swift-deploy/projects")]
        workspace_root: PathBuf,
    },
}

#[derive(Debug, Serialize)]
struct ValidationReport {
    hosts: usize,
    groups: usize,
    fingerprint: String,
    password_hosts: Vec<String>,
    placeholders: Vec<String>,
    warnings: Vec<String>,
}

pub fn run() -> Result<()> {
    run_command(Cli::parse())
}

fn run_command(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Audit { bundle, json } => {
            let audit = audit_bundle(&bundle)?;
            if json {
                print_json(&audit)?;
            } else {
                println!(
                    "compatible={} task_files={} tasks={} modules={} fingerprint={}",
                    audit.is_compatible(),
                    audit.task_files,
                    audit.tasks,
                    audit.executable_module_count(),
                    audit.fingerprint
                );
            }
            if !audit.is_compatible() {
                bail!(
                    "bundle audit failed: unsupported={:?}, parse_errors={:?}",
                    audit.unsupported_modules,
                    audit.parse_errors
                );
            }
        }
        Command::Validate { inventory, json } => {
            let loaded = Inventory::load(&inventory)?;
            let report = validate_inventory(&inventory, &loaded)?;
            if json {
                print_json(&report)?;
            } else {
                println!(
                    "hosts={} groups={} placeholders={} password_hosts={} fingerprint={}",
                    report.hosts,
                    report.groups,
                    report.placeholders.len(),
                    report.password_hosts.len(),
                    report.fingerprint
                );
                for warning in &report.warnings {
                    println!("warning: {warning}");
                }
            }
        }
        Command::Plan {
            bundle,
            inventory,
            playbook,
            output,
            json,
        } => {
            let inventory_fingerprint = fingerprint_inventory_inputs(&inventory)?;
            let loaded = Inventory::load(&inventory)?;
            let plan = Planner::new(&bundle, &loaded).build(&playbook, inventory_fingerprint)?;
            write_json_atomic(&output, &plan)?;
            if json {
                print_json(&plan)?;
            } else {
                println!(
                    "plan={} digest={} hosts={} tasks={} risks={:?}",
                    output.display(),
                    plan.digest,
                    plan.hosts.len(),
                    plan.tasks.len(),
                    plan.required_capabilities()
                );
            }
        }
        Command::Preflight {
            inventory,
            bundle,
            known_hosts,
            allow_password,
            json,
        } => {
            let loaded = Inventory::load(&inventory)?;
            let mut transport = OpenSshTransport::new(allow_password);
            let report =
                run_preflight_with_bundle(&loaded, known_hosts, &mut transport, bundle.as_deref())?;
            if json {
                print_json(&report)?;
            } else {
                println!("ok={} hosts={}", report.ok, report.hosts.len());
                for host in &report.hosts {
                    for error in &host.errors {
                        println!("{}: {error}", host.host);
                    }
                }
            }
        }
        Command::Apply {
            bundle,
            inventory,
            plan,
            confirm_digest,
            known_hosts,
            allow_disk_wipe,
            allow_firewall,
            allow_ssh_reconfigure,
            allow_host_reconfigure,
            allow_password,
            json,
        } => {
            let plan: Plan = serde_json::from_slice(
                &fs::read(&plan).with_context(|| format!("read plan {}", plan.display()))?,
            )
            .context("parse sealed plan JSON")?;
            plan.verify()?;
            if confirm_digest != plan.digest {
                bail!(
                    "plan confirmation does not match sealed digest {}; no hosts were contacted",
                    plan.digest
                );
            }
            let audit = audit_bundle(&bundle)?;
            if audit.fingerprint != plan.bundle_fingerprint {
                bail!("bundle fingerprint changed after plan approval; no hosts were contacted");
            }
            let inventory_fingerprint = fingerprint_inventory_inputs(&inventory)?;
            if inventory_fingerprint != plan.inventory_fingerprint {
                bail!("inventory fingerprint changed after plan approval; no hosts were contacted");
            }
            SafetyPolicy {
                allow_disk_wipe,
                allow_firewall,
                allow_ssh_reconfigure,
                allow_host_reconfigure,
            }
            .authorize(&plan)?;

            let loaded = Inventory::load(&inventory)?;
            let renderer = Renderer::new();
            let mut transport = OpenSshTransport::new(allow_password);
            let preflight = run_preflight_with_bundle(
                &loaded,
                known_hosts.clone(),
                &mut transport,
                Some(&bundle),
            )?;
            preflight.ensure_safe()?;
            let report = Executor::new(&bundle, &loaded, &renderer)
                .with_known_hosts(known_hosts)
                .execute(&plan, &mut transport)?;
            if json {
                print_json(&report)?;
            } else {
                println!(
                    "changed={} unchanged={} skipped={} failed={} tasks={}",
                    report.changed, report.unchanged, report.skipped, report.failed, report.tasks
                );
            }
        }
        Command::Modules { json } => {
            if json {
                print_json(&SUPPORTED_MODULES)?;
            } else {
                for module in SUPPORTED_MODULES {
                    println!("{module}");
                }
            }
        }
        Command::Ui {
            bind,
            port,
            bundle,
            inventory,
            playbook,
            plan,
            known_hosts,
            auth_token_file,
            workspace_root,
        } => serve_ui(UiOptions {
            bind,
            port,
            bundle,
            inventory,
            playbook,
            plan,
            known_hosts,
            auth_token_file,
            workspace_root,
        })?,
    }
    Ok(())
}

fn validate_inventory(path: &Path, inventory: &Inventory) -> Result<ValidationReport> {
    let mut placeholders = BTreeSet::new();
    let mut password_hosts = BTreeSet::new();
    for (name, group) in &inventory.groups {
        for (key, value) in &group.vars {
            scan_placeholders(value, &format!("group:{name}.{key}"), &mut placeholders);
        }
    }
    for (name, host) in &inventory.hosts {
        if host.vars.keys().any(|key| {
            matches!(
                key.as_str(),
                "ansible_password" | "ansible_ssh_pass" | "ansible_become_password"
            )
        }) {
            password_hosts.insert(name.clone());
        }
        for (key, value) in &host.vars {
            scan_placeholders(value, &format!("host:{name}.{key}"), &mut placeholders);
        }
    }
    let mut warnings = inventory.warnings.clone();
    if !password_hosts.is_empty() {
        warnings.push(
            "inline inventory passwords are rejected by apply unless --allow-password is explicit"
                .to_owned(),
        );
    }
    let all = &inventory.groups["all"].vars;
    for missing in ["super_admin_password", "auth_type_salt"] {
        if !all.contains_key(missing) {
            warnings.push(format!(
                "{missing} is absent; provide it explicitly before a role references it"
            ));
        }
    }
    Ok(ValidationReport {
        hosts: inventory.hosts.len(),
        groups: inventory.groups.len(),
        fingerprint: fingerprint_inventory_inputs(path)?,
        password_hosts: password_hosts.into_iter().collect(),
        placeholders: placeholders.into_iter().collect(),
        warnings,
    })
}

fn scan_placeholders(value: &Value, path: &str, output: &mut BTreeSet<String>) {
    match value {
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                scan_placeholders(item, &format!("{path}[{index}]"), output);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                scan_placeholders(item, &format!("{path}.{key}"), output);
            }
        }
        Value::String(text) => {
            let lower = text.to_ascii_lowercase();
            if [
                "enter ",
                "please set",
                "your auth",
                "xxxxx",
                "/path/to/",
                ".x",
            ]
            .iter()
            .any(|marker| lower.contains(marker))
            {
                output.insert(path.to_owned());
            }
        }
        _ => {}
    }
}

fn print_json(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create plan directory {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("create plan file in {}", parent.display()))?;
    serde_json::to_writer_pretty(&mut temporary, value).context("serialize plan")?;
    temporary.write_all(b"\n").context("finish plan file")?;
    temporary.flush().context("flush plan file")?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("persist plan {}", path.display()))?;
    Ok(())
}
