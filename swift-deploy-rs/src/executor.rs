use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::inventory::Inventory;
use crate::model::{ExecutionReport, LoopSpec, ModuleResult, Plan, PlannedTask};
use crate::modules::ModuleDispatcher;
use crate::template::Renderer;
use crate::transport::{ConnectionSpec, Transport};

/// Sequential runtime for a sealed plan. Runtime state is kept per inventory
/// host and never written back into the approved plan.
pub struct Executor<'a> {
    bundle: &'a Path,
    inventory: &'a Inventory,
    renderer: &'a Renderer,
    known_hosts: Option<PathBuf>,
}

impl<'a> Executor<'a> {
    #[must_use]
    pub fn new(bundle: &'a Path, inventory: &'a Inventory, renderer: &'a Renderer) -> Self {
        Self {
            bundle,
            inventory,
            renderer,
            known_hosts: None,
        }
    }

    #[must_use]
    pub fn with_known_hosts(mut self, known_hosts: Option<PathBuf>) -> Self {
        self.known_hosts = known_hosts;
        self
    }

    pub fn execute<T: Transport>(&self, plan: &Plan, transport: &mut T) -> Result<ExecutionReport> {
        plan.verify()?;
        let dispatcher = ModuleDispatcher::new(self.bundle, self.renderer);
        let mut report = ExecutionReport::default();
        let mut states = self.initial_states()?;
        self.gather_facts(plan, transport, &mut states)?;
        refresh_hostvars(&mut states);
        let mut notified: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for task in &plan.tasks {
            let mut hosts = task.hosts.clone();
            if task.run_once && hosts.len() > 1 {
                report.skipped += hosts.len() - 1;
                hosts.truncate(1);
            }
            for host in hosts {
                self.execute_task_for_host(
                    task,
                    &host,
                    transport,
                    &dispatcher,
                    &mut states,
                    &mut notified,
                    &mut report,
                )?;
            }
        }

        for handler in &plan.handlers {
            for host in &handler.hosts {
                let should_run = notified
                    .get(host)
                    .is_some_and(|names| names.contains(&handler.name));
                if !should_run {
                    continue;
                }
                self.execute_task_for_host(
                    handler,
                    host,
                    transport,
                    &dispatcher,
                    &mut states,
                    &mut BTreeMap::new(),
                    &mut report,
                )?;
            }
        }
        Ok(report)
    }

    fn initial_states(&self) -> Result<BTreeMap<String, Map<String, Value>>> {
        self.inventory
            .host_names()
            .into_iter()
            .map(|host| {
                let context = self.inventory.host_context(&host)?;
                let object = context
                    .as_object()
                    .cloned()
                    .context("inventory host context must be a mapping")?;
                Ok((host, object))
            })
            .collect()
    }

    fn gather_facts<T: Transport>(
        &self,
        plan: &Plan,
        transport: &mut T,
        states: &mut BTreeMap<String, Map<String, Value>>,
    ) -> Result<()> {
        for host in &plan.hosts {
            let state = states
                .get(host)
                .cloned()
                .with_context(|| format!("plan contains unknown host {host}"))?;
            let connection = ConnectionSpec::from_context(
                host,
                &Value::Object(state.clone()),
                self.known_hosts.clone(),
            )?;
            let output = transport.run(
                &connection,
                "printf 'HOSTNAME='; hostname -s; printf 'DEFAULT='; ip -o -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"src\") {print $(i+1); exit}}'; printf 'ALL='; ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,\"/\"); print a[1]}' | paste -sd, -",
            )?;
            if output.status != 0 {
                bail!(
                    "fact gathering failed on {}: {}",
                    connection.host,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let text = String::from_utf8_lossy(&output.stdout);
            let hostname = fact_line(&text, "HOSTNAME=")
                .filter(|value| !value.is_empty())
                .unwrap_or(host);
            let default_address = fact_line(&text, "DEFAULT=")
                .filter(|value| !value.is_empty())
                .unwrap_or(host);
            let mut addresses = fact_line(&text, "ALL=")
                .unwrap_or("")
                .split(',')
                .filter(|value| !value.is_empty())
                .map(|value| Value::String(value.to_owned()))
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                addresses.push(Value::String(default_address.to_owned()));
            }
            let state = states.get_mut(host).expect("host state exists");
            state.insert(
                "ansible_hostname".to_owned(),
                Value::String(hostname.to_owned()),
            );
            state.insert(
                "ansible_default_ipv4".to_owned(),
                json!({"address": default_address}),
            );
            state.insert(
                "ansible_all_ipv4_addresses".to_owned(),
                Value::Array(addresses),
            );
            state.insert(
                "ansible_managed".to_owned(),
                Value::String("Managed by swift-deploy-rs".to_owned()),
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_task_for_host<T: Transport>(
        &self,
        task: &PlannedTask,
        host: &str,
        transport: &mut T,
        dispatcher: &ModuleDispatcher<'_>,
        states: &mut BTreeMap<String, Map<String, Value>>,
        notified: &mut BTreeMap<String, BTreeSet<String>>,
        report: &mut ExecutionReport,
    ) -> Result<()> {
        let state = states
            .get(host)
            .cloned()
            .with_context(|| format!("task {} targets unknown host {host}", task.id))?;
        let mut base = state;
        base.extend(
            task.vars
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        let loop_contexts = expand_loops(self.renderer, &task.loops, &base)?;
        if loop_contexts.is_empty() {
            report.skipped += 1;
            return Ok(());
        }

        for loop_vars in loop_contexts {
            let mut raw_context = base.clone();
            raw_context.extend(loop_vars);
            let context = self
                .renderer
                .resolve_context(&Value::Object(raw_context.clone()))
                .with_context(|| format!("resolve context for task {} on {host}", task.id))?;
            if !task
                .when
                .iter()
                .map(|condition| self.renderer.eval_bool(condition, &context))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .all(|value| value)
            {
                report.skipped += 1;
                continue;
            }

            let connection = self.connection_for(task, host, &context, states)?;
            let mut result = dispatcher
                .execute(
                    transport,
                    &connection,
                    &task.role,
                    &task.module,
                    &task.args,
                    &context,
                )
                .with_context(|| {
                    format!(
                        "execute task {} ({}) on {}",
                        task.id, task.name, connection.host
                    )
                })?;
            apply_result_conditions(self.renderer, task, &context, &mut result)?;
            report.tasks += 1;
            if result.failed {
                report.failed += 1;
            } else if result.changed {
                report.changed += 1;
            } else {
                report.unchanged += 1;
            }

            let result_value = result_value(&result);
            let state_hosts = if task.run_once {
                task.hosts.iter().map(String::as_str).collect::<Vec<_>>()
            } else {
                vec![host]
            };
            let mut runtime_state_changed = false;
            if let Some(register) = &task.register {
                for state_host in &state_hosts {
                    states
                        .get_mut(*state_host)
                        .with_context(|| {
                            format!(
                                "run_once task {} targets unknown host {state_host}",
                                task.id
                            )
                        })?
                        .insert(register.clone(), result_value.clone());
                }
                runtime_state_changed = true;
            }
            if task.module == "set_fact"
                && let Some(facts) = result.data.get("facts").and_then(Value::as_object)
            {
                for state_host in &state_hosts {
                    states
                        .get_mut(*state_host)
                        .with_context(|| {
                            format!(
                                "run_once task {} targets unknown host {state_host}",
                                task.id
                            )
                        })?
                        .extend(facts.clone());
                }
                runtime_state_changed = true;
            }
            if runtime_state_changed {
                refresh_hostvars(states);
            }
            if result.changed {
                notified
                    .entry(host.to_owned())
                    .or_default()
                    .extend(task.notify.iter().cloned());
            }
            if result.failed && !task.ignore_errors {
                bail!(
                    "task {} ({}) failed on {}: {}",
                    task.id,
                    task.name,
                    connection.host,
                    result.message
                );
            }
        }
        Ok(())
    }

    fn connection_for(
        &self,
        task: &PlannedTask,
        host: &str,
        context: &Value,
        states: &BTreeMap<String, Map<String, Value>>,
    ) -> Result<ConnectionSpec> {
        let mut connection = if let Some(delegate_expression) = &task.delegate_to {
            let delegate = self.renderer.render_str(delegate_expression, context)?;
            if let Some(delegate_context) = states.get(&delegate) {
                ConnectionSpec::from_context(
                    &delegate,
                    &Value::Object(delegate_context.clone()),
                    self.known_hosts.clone(),
                )?
            } else {
                let mut connection =
                    ConnectionSpec::from_context(host, context, self.known_hosts.clone())?;
                connection.host = delegate;
                connection
            }
        } else {
            ConnectionSpec::from_context(host, context, self.known_hosts.clone())?
        };
        if task.privilege_escalation {
            connection.become_user = Some(
                task.become_user
                    .clone()
                    .unwrap_or_else(|| "root".to_owned()),
            );
        }
        Ok(connection)
    }
}

fn expand_loops(
    renderer: &Renderer,
    loops: &[LoopSpec],
    base: &Map<String, Value>,
) -> Result<Vec<Map<String, Value>>> {
    let mut contexts = vec![Map::new()];
    for loop_spec in loops {
        let mut expanded = Vec::new();
        for existing in contexts {
            let mut evaluation = base.clone();
            evaluation.extend(existing.clone());
            let expression =
                renderer.render_value(&loop_spec.expression, &Value::Object(evaluation))?;
            for item in loop_items(loop_spec, expression)? {
                let mut next = existing.clone();
                next.insert(loop_spec.loop_var.clone(), item);
                expanded.push(next);
            }
        }
        contexts = expanded;
    }
    Ok(contexts)
}

fn loop_items(specification: &LoopSpec, value: Value) -> Result<Vec<Value>> {
    match specification.kind.as_str() {
        "loop" | "with_items" => Ok(match value {
            Value::Array(items) => items,
            Value::Null => Vec::new(),
            item => vec![item],
        }),
        "with_dict" => {
            let map = value
                .as_object()
                .context("with_dict expression must evaluate to a mapping")?;
            Ok(map
                .iter()
                .map(|(key, value)| json!({"key": key, "value": value}))
                .collect())
        }
        "with_together" => {
            let collections = value
                .as_array()
                .context("with_together expression must be a list of lists")?
                .iter()
                .map(|item| {
                    item.as_array()
                        .cloned()
                        .context("with_together member must be a list")
                })
                .collect::<Result<Vec<_>>>()?;
            let length = collections.iter().map(Vec::len).max().unwrap_or(0);
            Ok((0..length)
                .map(|index| {
                    Value::Array(
                        collections
                            .iter()
                            .map(|items| items.get(index).cloned().unwrap_or(Value::Null))
                            .collect(),
                    )
                })
                .collect())
        }
        "with_inidata" => {
            let sections = value
                .as_object()
                .context("with_inidata expression must evaluate to a mapping")?;
            let mut items = Vec::new();
            for (section, options) in sections {
                let options = options
                    .as_object()
                    .context("with_inidata section must be a mapping")?;
                for (option, value) in options {
                    items.push(json!([section, option, value]));
                }
            }
            Ok(items)
        }
        other => bail!("unsupported runtime loop type: {other}"),
    }
}

fn apply_result_conditions(
    renderer: &Renderer,
    task: &PlannedTask,
    context: &Value,
    result: &mut ModuleResult,
) -> Result<()> {
    let mut evaluation = context
        .as_object()
        .cloned()
        .context("task evaluation context must be a mapping")?;
    let value = result_value(result);
    if let Some(register) = &task.register {
        evaluation.insert(register.clone(), value.clone());
    }
    if let Some(object) = value.as_object() {
        evaluation.extend(object.clone());
    }
    let evaluation = Value::Object(evaluation);
    if !task.failed_when.is_empty() {
        result.failed = task
            .failed_when
            .iter()
            .map(|condition| renderer.eval_bool(condition, &evaluation))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .any(|value| value);
    }
    if !task.changed_when.is_empty() {
        result.changed = task
            .changed_when
            .iter()
            .map(|condition| renderer.eval_bool(condition, &evaluation))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .all(|value| value);
    }
    Ok(())
}

fn result_value(result: &ModuleResult) -> Value {
    let mut value = result.data.as_object().cloned().unwrap_or_default();
    value.insert("changed".to_owned(), Value::Bool(result.changed));
    value.insert("failed".to_owned(), Value::Bool(result.failed));
    value.insert("msg".to_owned(), Value::String(result.message.clone()));
    Value::Object(value)
}

fn fact_line<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix))
        .map(str::trim)
}

fn refresh_hostvars(states: &mut BTreeMap<String, Map<String, Value>>) {
    let hostvars = states
        .iter()
        .map(|(host, state)| {
            let mut shallow = state.clone();
            shallow.remove("hostvars");
            (host.clone(), Value::Object(shallow))
        })
        .collect::<Map<_, _>>();
    for state in states.values_mut() {
        state.insert("hostvars".to_owned(), Value::Object(hostvars.clone()));
    }
}
