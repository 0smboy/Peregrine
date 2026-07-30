use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::model::{ModuleResult, SUPPORTED_MODULES};
use crate::template::Renderer;
use crate::transport::{CommandOutput, ConnectionSpec, RemoteFileOptions, Transport};

/// Dispatcher for the exact 28 executable modules observed in the v3 bundle.
pub struct ModuleDispatcher<'a> {
    bundle: &'a Path,
    renderer: &'a Renderer,
}

impl<'a> ModuleDispatcher<'a> {
    #[must_use]
    pub fn new(bundle: &'a Path, renderer: &'a Renderer) -> Self {
        Self { bundle, renderer }
    }

    #[must_use]
    pub const fn supported_modules() -> [&'static str; 28] {
        SUPPORTED_MODULES
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute<T: Transport>(
        &self,
        transport: &mut T,
        connection: &ConnectionSpec,
        role: &str,
        module: &str,
        raw_args: &Value,
        context: &Value,
    ) -> Result<ModuleResult> {
        let args = self.renderer.render_value(raw_args, context)?;
        match module {
            "shell" => execute_command(transport, connection, &args, true),
            "command" => execute_command(transport, connection, &args, false),
            "template" => self.template(transport, connection, role, &args, context),
            "file" => file(transport, connection, &args),
            "lineinfile" => lineinfile(transport, connection, &args),
            "service" => service(transport, connection, &args, false),
            "copy" => self.copy(transport, connection, role, &args),
            "set_fact" => set_fact(&args),
            "yum" | "package" => package(transport, connection, &args),
            "ini_file" => ini_file(transport, connection, &args),
            "fail" => fail_module(&args),
            "blockinfile" => blockinfile(transport, connection, &args),
            "script" => self.script(transport, connection, role, &args),
            "debug" => debug_module(&args),
            "fetch" => fetch(transport, connection, &args),
            "stat" => stat_module(transport, connection, &args),
            "unarchive" => self.unarchive(transport, connection, role, &args),
            "mysql_user" => mysql_user(transport, connection, &args),
            "systemd" => service(transport, connection, &args, true),
            "pip" => pip(transport, connection, &args),
            "uri" => uri(transport, connection, &args),
            "find" => find_module(transport, connection, &args),
            "mysql_db" => mysql_db(transport, connection, &args),
            "timezone" => timezone(transport, connection, &args),
            "user" => user_module(transport, connection, &args),
            "get_url" => get_url(transport, connection, &args),
            "cron" => cron(transport, connection, &args),
            other => bail!("unsupported module dispatcher request: {other}"),
        }
    }

    fn template<T: Transport>(
        &self,
        transport: &mut T,
        connection: &ConnectionSpec,
        role: &str,
        args: &Value,
        context: &Value,
    ) -> Result<ModuleResult> {
        let params = parameters(args)?;
        let source = required(&params, "src")?;
        let destination = destination(&params)?;
        let source_path = self.role_source(role, "templates", &source)?;
        let template = fs::read_to_string(&source_path)
            .with_context(|| format!("read template {}", source_path.display()))?;
        let rendered = self.renderer.render_str(&template, context)?;
        write_if_changed(
            transport,
            connection,
            &destination,
            rendered.as_bytes(),
            file_options(&params),
        )
    }

    fn copy<T: Transport>(
        &self,
        transport: &mut T,
        connection: &ConnectionSpec,
        role: &str,
        args: &Value,
    ) -> Result<ModuleResult> {
        let params = parameters(args)?;
        let mut destination = destination(&params)?;
        if boolean_param(&params, "remote_src", false) {
            let source = required(&params, "src")?;
            let output = transport.run(
                connection,
                &format!("cp -a -- {} {}", quote(&source), quote(&destination)),
            )?;
            return Ok(command_result(output, true));
        }
        let content = if let Some(value) = params.get("content") {
            value_to_string(value).into_bytes()
        } else {
            let source = required(&params, "src")?;
            let source_path = self.role_source(role, "files", &source)?;
            if transport
                .run(connection, &format!("test -d {}", quote(&destination)))?
                .status
                == 0
            {
                let basename = source_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .context("copy source has no filename")?;
                destination = format!("{}/{}", destination.trim_end_matches('/'), basename);
            }
            fs::read(&source_path)
                .with_context(|| format!("read copy source {}", source_path.display()))?
        };
        write_if_changed(
            transport,
            connection,
            &destination,
            &content,
            file_options(&params),
        )
    }

    fn script<T: Transport>(
        &self,
        transport: &mut T,
        connection: &ConnectionSpec,
        role: &str,
        args: &Value,
    ) -> Result<ModuleResult> {
        let specification = raw_or_required(args, "cmd")?;
        let words = shell_words::split(&specification).context("parse script invocation")?;
        let (source, arguments) = words.split_first().context("script path is empty")?;
        let source_path = self.role_source(role, "files", source)?;
        let hash = hex::encode(Sha256::digest(fs::read(&source_path)?));
        let remote = format!("/tmp/swift-deploy-script-{}", &hash[..20]);
        transport.upload(connection, &source_path, &remote)?;
        let command = format!(
            "chmod 0700 -- {remote} && {remote} {}; status=$?; rm -f -- {remote}; exit $status",
            arguments
                .iter()
                .map(|item| quote(item))
                .collect::<Vec<_>>()
                .join(" "),
            remote = quote(&remote)
        );
        Ok(command_result(transport.run(connection, &command)?, true))
    }

    fn unarchive<T: Transport>(
        &self,
        transport: &mut T,
        connection: &ConnectionSpec,
        role: &str,
        args: &Value,
    ) -> Result<ModuleResult> {
        let params = parameters(args)?;
        let source = required(&params, "src")?;
        let destination = destination(&params)?;
        if let Some(creates) = optional(&params, "creates") {
            let probe = transport.run(connection, &format!("test -e {}", quote(&creates)))?;
            if probe.status == 0 {
                return Ok(ModuleResult {
                    message: "archive destination already exists".to_owned(),
                    ..ModuleResult::default()
                });
            }
        }
        let mut prelude = String::new();
        let remote_source = if boolean_param(&params, "remote_src", false) {
            if source.starts_with("http://") || source.starts_with("https://") {
                let hash = hex::encode(Sha256::digest(source.as_bytes()));
                let remote = format!("/tmp/swift-deploy-download-{}", &hash[..20]);
                prelude = format!(
                    "curl --fail --location --silent --show-error {} --output {} && ",
                    quote(&source),
                    quote(&remote)
                );
                remote
            } else {
                source
            }
        } else {
            let local = self.role_source(role, "files", &source)?;
            let hash = hex::encode(Sha256::digest(fs::read(&local)?));
            let remote = format!("/tmp/swift-deploy-archive-{}", &hash[..20]);
            transport.upload(connection, &local, &remote)?;
            remote
        };
        let extraction = if Path::new(&remote_source)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("zip"))
        {
            format!(
                "unzip -o {} -d {}",
                quote(&remote_source),
                quote(&destination)
            )
        } else {
            format!(
                "mkdir -p {} && tar -xf {} -C {}",
                quote(&destination),
                quote(&remote_source),
                quote(&destination)
            )
        };
        Ok(command_result(
            transport.run(connection, &format!("{prelude}{extraction}"))?,
            true,
        ))
    }

    fn role_source(&self, role: &str, category: &str, source: &str) -> Result<PathBuf> {
        let direct = PathBuf::from(source);
        if direct.is_absolute() && direct.is_file() {
            return Ok(direct);
        }
        let role_root = self.bundle.join("roles").join(role);
        let source = source.trim_start_matches('/');
        let candidates = [
            role_root.join(source),
            role_root.join(category).join(source),
            self.bundle.join(source),
        ];
        candidates
            .into_iter()
            .find(|path| path.is_file())
            .with_context(|| format!("source asset not found for role {role}: {source}"))
    }
}

fn execute_command<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
    shell: bool,
) -> Result<ModuleResult> {
    let (command, chdir, creates, removes) = match args {
        Value::String(command) => (command.clone(), None, None, None),
        Value::Object(_) => {
            let params = parameters(args)?;
            (
                optional(&params, "cmd")
                    .or_else(|| optional(&params, "_raw_params"))
                    .context("command requires cmd or _raw_params")?,
                optional(&params, "chdir"),
                optional(&params, "creates"),
                optional(&params, "removes"),
            )
        }
        _ => bail!("command arguments must be a string or mapping"),
    };
    if let Some(path) = creates
        && transport
            .run(connection, &format!("test -e {}", quote(&path)))?
            .status
            == 0
    {
        return Ok(ModuleResult {
            message: format!("skipped because {path} exists"),
            ..ModuleResult::default()
        });
    }
    if let Some(path) = removes
        && transport
            .run(connection, &format!("test -e {}", quote(&path)))?
            .status
            != 0
    {
        return Ok(ModuleResult {
            message: format!("skipped because {path} is absent"),
            ..ModuleResult::default()
        });
    }
    let mut invocation = if shell {
        command
    } else {
        shell_words::split(&command)
            .context("parse command argv")?
            .iter()
            .map(|word| quote(word))
            .collect::<Vec<_>>()
            .join(" ")
    };
    if let Some(directory) = chdir {
        invocation = format!("cd {} && {invocation}", quote(&directory));
    }
    Ok(command_result(
        transport.run(connection, &invocation)?,
        true,
    ))
}

fn file<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let path = destination(&params)?;
    let state = optional(&params, "state").unwrap_or_else(|| "file".to_owned());
    let options = file_options(&params);
    let command = match state.as_str() {
        "absent" => format!(
            "if test -e {path} || test -L {path}; then rm -rf -- {path}; fi",
            path = quote(&path)
        ),
        "directory" => {
            let mode = options.mode.as_deref().unwrap_or("0755");
            format!("install -d -m {} -- {}", quote(mode), quote(&path))
        }
        "touch" => {
            let parent = Path::new(&path)
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_string_lossy();
            format!("mkdir -p {} && touch -- {}", quote(&parent), quote(&path))
        }
        "link" => {
            let source = required(&params, "src")?;
            format!("ln -sfn -- {} {}", quote(&source), quote(&path))
        }
        "hard" => {
            let source = required(&params, "src")?;
            format!("ln -fn -- {} {}", quote(&source), quote(&path))
        }
        "file" => format!("test -e {}", quote(&path)),
        other => bail!("unsupported file state: {other}"),
    };
    let mut result = command_result(transport.run(connection, &command)?, state != "file");
    if !result.failed && state != "absent" {
        if let Some(mode) = &options.mode {
            let output = transport.run(
                connection,
                &format!("chmod {} -- {}", quote(mode), quote(&path)),
            )?;
            if output.status != 0 {
                result = command_result(output, true);
            }
        }
        if options.owner.is_some() || options.group.is_some() {
            let ownership = format!(
                "{}:{}",
                options.owner.as_deref().unwrap_or(""),
                options.group.as_deref().unwrap_or("")
            );
            let output = transport.run(
                connection,
                &format!("chown {} -- {}", quote(&ownership), quote(&path)),
            )?;
            if output.status != 0 {
                result = command_result(output, true);
            }
        }
    }
    Ok(result)
}

fn lineinfile<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let path = destination(&params)?;
    let old = transport.read_file(connection, &path)?;
    if old.is_none() && !boolean_param(&params, "create", false) {
        bail!("lineinfile destination does not exist: {path}");
    }
    let original = String::from_utf8(old.unwrap_or_default())
        .with_context(|| format!("lineinfile destination is not UTF-8: {path}"))?;
    let mut lines = original.lines().map(str::to_owned).collect::<Vec<_>>();
    let state = optional(&params, "state").unwrap_or_else(|| "present".to_owned());
    let regexp = optional(&params, "regexp")
        .map(|pattern| Regex::new(&pattern))
        .transpose()?;
    let line = optional(&params, "line");

    if state == "absent" {
        if let Some(regexp) = &regexp {
            lines.retain(|item| !regexp.is_match(item));
        } else if let Some(line) = &line {
            lines.retain(|item| item != line);
        }
    } else {
        let line = line.context("lineinfile state=present requires line")?;
        let position = regexp
            .as_ref()
            .and_then(|pattern| lines.iter().rposition(|item| pattern.is_match(item)))
            .or_else(|| lines.iter().position(|item| item == &line));
        if let Some(position) = position {
            lines[position] = line;
        } else {
            insert_line(&mut lines, line, &params)?;
        }
    }
    let updated = finish_lines(&lines);
    write_if_changed(
        transport,
        connection,
        &path,
        updated.as_bytes(),
        file_options(&params),
    )
}

fn insert_line(
    lines: &mut Vec<String>,
    line: String,
    params: &BTreeMap<String, Value>,
) -> Result<()> {
    if let Some(before) = optional(params, "insertbefore") {
        if before == "BOF" {
            lines.insert(0, line);
        } else {
            let pattern = Regex::new(&before)?;
            let index = lines
                .iter()
                .position(|item| pattern.is_match(item))
                .unwrap_or(lines.len());
            lines.insert(index, line);
        }
    } else if let Some(after) = optional(params, "insertafter") {
        if after == "EOF" {
            lines.push(line);
        } else {
            let pattern = Regex::new(&after)?;
            let index = lines
                .iter()
                .rposition(|item| pattern.is_match(item))
                .map_or(lines.len(), |index| index + 1);
            lines.insert(index, line);
        }
    } else {
        lines.push(line);
    }
    Ok(())
}

fn blockinfile<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let path = destination(&params)?;
    let old = transport.read_file(connection, &path)?;
    if old.is_none() && !boolean_param(&params, "create", false) {
        bail!("blockinfile destination does not exist: {path}");
    }
    let original = String::from_utf8(old.unwrap_or_default())
        .with_context(|| format!("blockinfile destination is not UTF-8: {path}"))?;
    let marker =
        optional(&params, "marker").unwrap_or_else(|| "# {mark} ANSIBLE MANAGED BLOCK".to_owned());
    let begin = marker.replace("{mark}", "BEGIN");
    let end = marker.replace("{mark}", "END");
    let mut lines = original.lines().map(str::to_owned).collect::<Vec<_>>();
    let start = lines.iter().position(|line| line == &begin);
    let finish = start.and_then(|start| {
        lines
            .iter()
            .enumerate()
            .skip(start + 1)
            .find_map(|(index, line)| (line == &end).then_some(index))
    });
    if let (Some(start), Some(finish)) = (start, finish) {
        lines.drain(start..=finish);
    }
    if optional(&params, "state").as_deref() != Some("absent") {
        let block = optional(&params, "block")
            .or_else(|| optional(&params, "content"))
            .unwrap_or_default();
        let mut managed = vec![begin];
        managed.extend(block.lines().map(str::to_owned));
        managed.push(end);
        lines.extend(managed);
    }
    let updated = finish_lines(&lines);
    write_if_changed(
        transport,
        connection,
        &path,
        updated.as_bytes(),
        file_options(&params),
    )
}

fn ini_file<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let path = destination(&params)?;
    let section = required(&params, "section")?;
    let option = required(&params, "option")?;
    let state = optional(&params, "state").unwrap_or_else(|| "present".to_owned());
    let value = optional(&params, "value").unwrap_or_default();
    let original = String::from_utf8(transport.read_file(connection, &path)?.unwrap_or_default())
        .with_context(|| format!("ini destination is not UTF-8: {path}"))?;
    let mut lines = original.lines().map(str::to_owned).collect::<Vec<_>>();
    edit_ini(&mut lines, &section, &option, &value, &state);
    let updated = finish_lines(&lines);
    write_if_changed(
        transport,
        connection,
        &path,
        updated.as_bytes(),
        file_options(&params),
    )
}

fn edit_ini(lines: &mut Vec<String>, section: &str, option: &str, value: &str, state: &str) {
    let section_header = format!("[{section}]");
    let section_start = if section == "no_ini_type_conf" {
        Some(0)
    } else {
        lines.iter().position(|line| line.trim() == section_header)
    };
    let section_end = section_start.map(|start| {
        lines
            .iter()
            .enumerate()
            .skip(start + usize::from(section != "no_ini_type_conf"))
            .find_map(|(index, line)| {
                let trimmed = line.trim();
                (trimmed.starts_with('[') && trimmed.ends_with(']')).then_some(index)
            })
            .unwrap_or(lines.len())
    });
    let option_regex =
        Regex::new(&format!(r"^\s*{}\s*=", regex::escape(option))).expect("escaped option regex");
    let existing = section_start.zip(section_end).and_then(|(start, end)| {
        lines
            .iter()
            .enumerate()
            .take(end)
            .skip(start + usize::from(section != "no_ini_type_conf"))
            .find_map(|(index, line)| option_regex.is_match(line).then_some(index))
    });
    if state == "absent" {
        if let Some(index) = existing {
            lines.remove(index);
        }
        return;
    }
    let new_line = format!("{option} = {value}");
    if let Some(index) = existing {
        lines[index] = new_line;
    } else if let Some(end) = section_end {
        lines.insert(end, new_line);
    } else {
        if !lines.is_empty() && !lines.last().is_some_and(String::is_empty) {
            lines.push(String::new());
        }
        if section != "no_ini_type_conf" {
            lines.push(section_header);
        }
        lines.push(new_line);
    }
}

fn service<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
    systemd_module: bool,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    if systemd_module && boolean_param(&params, "daemon_reload", false) {
        let reload = transport.run(connection, "systemctl daemon-reload")?;
        if reload.status != 0 {
            return Ok(command_result(reload, true));
        }
    }
    let name = required(&params, "name")?;
    let state = optional(&params, "state");
    let enabled = params.get("enabled").map(ansible_bool);
    let mut commands = Vec::new();
    if let Some(enabled) = enabled {
        commands.push(format!(
            "systemctl {} {}",
            if enabled { "enable" } else { "disable" },
            quote(&name)
        ));
    }
    if let Some(state) = state {
        let action = match state.as_str() {
            "started" => "start",
            "stopped" => "stop",
            "restarted" => "restart",
            "reloaded" => "reload",
            other => other,
        };
        commands.push(format!("systemctl {action} {}", quote(&name)));
    }
    if commands.is_empty() {
        bail!("service requires state, enabled, or daemon_reload");
    }
    Ok(command_result(
        transport.run(connection, &commands.join(" && "))?,
        true,
    ))
}

fn package<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let names = params
        .get("name")
        .or_else(|| params.get("pkg"))
        .context("package requires name")?;
    let names = value_list(names)
        .into_iter()
        .map(|name| quote(&value_to_string(&name)))
        .collect::<Vec<_>>()
        .join(" ");
    let state = optional(&params, "state").unwrap_or_else(|| "present".to_owned());
    let action = match state.as_str() {
        "absent" | "removed" => "remove",
        "latest" | "present" | "installed" => "install",
        other => bail!("unsupported package state: {other}"),
    };
    Ok(command_result(
        transport.run(connection, &format!("dnf -y {action} {names}"))?,
        true,
    ))
}

fn set_fact(args: &Value) -> Result<ModuleResult> {
    let facts = args
        .as_object()
        .context("set_fact arguments must be a mapping")?
        .clone();
    Ok(ModuleResult {
        changed: true,
        data: json!({"facts": facts}),
        ..ModuleResult::default()
    })
}

fn fail_module(args: &Value) -> Result<ModuleResult> {
    let params = parameters(args)?;
    Ok(ModuleResult {
        failed: true,
        message: optional(&params, "msg")
            .unwrap_or_else(|| "failure requested by playbook".to_owned()),
        data: json!({"failed": true}),
        ..ModuleResult::default()
    })
}

fn debug_module(args: &Value) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let message = optional(&params, "msg")
        .or_else(|| optional(&params, "var"))
        .unwrap_or_else(|| value_to_string(args));
    Ok(ModuleResult {
        message,
        data: json!({"changed": false}),
        ..ModuleResult::default()
    })
}

fn fetch<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let source = required(&params, "src")?;
    let mut destination = PathBuf::from(destination(&params)?);
    if !boolean_param(&params, "flat", false) {
        destination = destination
            .join(&connection.host)
            .join(source.trim_start_matches('/'));
    }
    transport.download(connection, &source, &destination)?;
    Ok(ModuleResult {
        changed: true,
        data: json!({"dest": destination}),
        ..ModuleResult::default()
    })
}

fn stat_module<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let path = required(&params, "path").or_else(|_| destination(&params))?;
    let output = transport.run(
        connection,
        &format!(
            "if test -e {path} || test -L {path}; then stat -c '%F\\t%s\\t%a\\t%U\\t%G' -- {path}; else exit 44; fi",
            path = quote(&path)
        ),
    )?;
    if output.status == 44 {
        return Ok(ModuleResult {
            data: json!({"stat": {"exists": false}}),
            ..ModuleResult::default()
        });
    }
    if output.status != 0 {
        return Ok(command_result(output, false));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let fields = text.trim().split('\t').collect::<Vec<_>>();
    Ok(ModuleResult {
        data: json!({
            "stat": {
                "exists": true,
                "type": fields.first().copied().unwrap_or(""),
                "size": fields.get(1).and_then(|value| value.parse::<u64>().ok()),
                "mode": fields.get(2).copied().unwrap_or(""),
                "owner": fields.get(3).copied().unwrap_or(""),
                "group": fields.get(4).copied().unwrap_or("")
            }
        }),
        ..ModuleResult::default()
    })
}

fn mysql_user<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let name = required(&params, "name")?;
    let host = optional(&params, "host").unwrap_or_else(|| "localhost".to_owned());
    let state = optional(&params, "state").unwrap_or_else(|| "present".to_owned());
    let sql = if state == "absent" {
        format!(
            "DROP USER IF EXISTS '{}'@'{}';",
            sql_escape(&name),
            sql_escape(&host)
        )
    } else {
        let password = optional(&params, "password").unwrap_or_default();
        let mut sql = format!(
            "CREATE USER IF NOT EXISTS '{}'@'{}' IDENTIFIED BY '{}'; ALTER USER '{}'@'{}' IDENTIFIED BY '{}';",
            sql_escape(&name),
            sql_escape(&host),
            sql_escape(&password),
            sql_escape(&name),
            sql_escape(&host),
            sql_escape(&password)
        );
        if let Some(privileges) = optional(&params, "priv")
            && let Some((scope, privileges)) = privileges.split_once(':')
        {
            sql.push_str(&format!(
                " GRANT {} ON {} TO '{}'@'{}';",
                privileges,
                scope,
                sql_escape(&name),
                sql_escape(&host)
            ));
        }
        sql
    };
    Ok(command_result(
        transport.run(
            connection,
            &format!("mysql --batch --execute {}", quote(&sql)),
        )?,
        true,
    ))
}

fn mysql_db<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let name = required(&params, "name")?;
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        bail!("mysql database name contains unsupported characters");
    }
    let state = optional(&params, "state").unwrap_or_else(|| "present".to_owned());
    let command = match state.as_str() {
        "present" => format!(
            "mysql --batch --execute {}",
            quote(&format!("CREATE DATABASE IF NOT EXISTS {name};"))
        ),
        "absent" => format!(
            "mysql --batch --execute {}",
            quote(&format!("DROP DATABASE IF EXISTS {name};"))
        ),
        "import" => {
            let target = required(&params, "target")?;
            format!("mysql {} < {}", quote(&name), quote(&target))
        }
        "dump" => {
            let target = required(&params, "target")?;
            format!("mysqldump {} > {}", quote(&name), quote(&target))
        }
        other => bail!("unsupported mysql_db state: {other}"),
    };
    Ok(command_result(transport.run(connection, &command)?, true))
}

fn pip<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let names = params.get("name").context("pip requires name")?;
    let names = value_list(names)
        .iter()
        .map(|name| quote(&value_to_string(name)))
        .collect::<Vec<_>>()
        .join(" ");
    let state = optional(&params, "state").unwrap_or_else(|| "present".to_owned());
    let command = if state == "absent" {
        format!("pip3 uninstall -y {names}")
    } else {
        let upgrade = if state == "latest" { "--upgrade " } else { "" };
        format!("pip3 install {upgrade}{names}")
    };
    Ok(command_result(transport.run(connection, &command)?, true))
}

fn uri<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let url = required(&params, "url")?;
    let method = optional(&params, "method").unwrap_or_else(|| "GET".to_owned());
    let mut command = format!(
        "code=$(curl --silent --show-error -o /tmp/swift-deploy-uri-body.$$ -w '%{{http_code}}' -X {} ",
        quote(&method)
    );
    if let Some(body) = optional(&params, "body") {
        command.push_str(&format!("--data {} ", quote(&body)));
    }
    if let Some(headers) = params.get("headers").and_then(Value::as_object) {
        for (name, value) in headers {
            command.push_str(&format!(
                "-H {} ",
                quote(&format!("{name}: {}", value_to_string(value)))
            ));
        }
    }
    command.push_str(&format!("{url}); status=$?; ", url = quote(&url)));
    if let Some(expected) = optional(&params, "status_code") {
        command.push_str(&format!(
            "test $status -eq 0 && test \"$code\" = {}; status=$?; ",
            quote(&expected)
        ));
    }
    command.push_str(
        "cat /tmp/swift-deploy-uri-body.$$ 2>/dev/null; rm -f /tmp/swift-deploy-uri-body.$$; exit $status",
    );
    Ok(command_result(transport.run(connection, &command)?, false))
}

fn find_module<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let paths = params
        .get("paths")
        .map_or_else(|| vec![Value::String(".".to_owned())], value_list);
    let mut command = format!(
        "find {}",
        paths
            .iter()
            .map(|path| quote(&value_to_string(path)))
            .collect::<Vec<_>>()
            .join(" ")
    );
    if !boolean_param(&params, "recurse", true) {
        command.push_str(" -maxdepth 1");
    }
    if let Some(file_type) = optional(&params, "file_type") {
        match file_type.as_str() {
            "file" => command.push_str(" -type f"),
            "directory" => command.push_str(" -type d"),
            "link" => command.push_str(" -type l"),
            "any" => {}
            other => bail!("unsupported find file_type: {other}"),
        }
    }
    if let Some(patterns) = params.get("patterns") {
        for pattern in value_list(patterns) {
            command.push_str(&format!(" -name {}", quote(&value_to_string(&pattern))));
        }
    }
    if let Some(age) = optional(&params, "age") {
        command.push_str(&format!(" -mtime {}", quote(&age)));
    }
    command.push_str(" -print");
    let output = transport.run(connection, &command)?;
    if output.status != 0 {
        return Ok(command_result(output, false));
    }
    let files = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|path| json!({"path": path}))
        .collect::<Vec<_>>();
    Ok(ModuleResult {
        data: json!({"files": files, "matched": files.len()}),
        ..ModuleResult::default()
    })
}

fn timezone<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let name = required(&params, "name")?;
    Ok(command_result(
        transport.run(
            connection,
            &format!("timedatectl set-timezone {}", quote(&name)),
        )?,
        true,
    ))
}

fn user_module<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let name = required(&params, "name")?;
    let state = optional(&params, "state").unwrap_or_else(|| "present".to_owned());
    let command = if state == "absent" {
        format!(
            "id {} >/dev/null 2>&1 && userdel {} || true",
            quote(&name),
            quote(&name)
        )
    } else {
        let mut options = Vec::new();
        if let Some(shell) = optional(&params, "shell") {
            options.push(format!("-s {}", quote(&shell)));
        }
        if let Some(home) = optional(&params, "home") {
            options.push(format!("-d {}", quote(&home)));
        }
        if let Some(groups) = optional(&params, "groups") {
            options.push(format!("-G {}", quote(&groups)));
        }
        format!(
            "id {name} >/dev/null 2>&1 || useradd {options} {name}",
            name = quote(&name),
            options = options.join(" ")
        )
    };
    Ok(command_result(transport.run(connection, &command)?, true))
}

fn get_url<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let url = required(&params, "url")?;
    let destination = destination(&params)?;
    let mut command = format!(
        "curl --fail --location --silent --show-error {} --output {}",
        quote(&url),
        quote(&destination)
    );
    if let Some(mode) = optional(&params, "mode") {
        command.push_str(&format!(
            " && chmod {} {}",
            quote(&mode),
            quote(&destination)
        ));
    }
    Ok(command_result(transport.run(connection, &command)?, true))
}

fn cron<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    args: &Value,
) -> Result<ModuleResult> {
    let params = parameters(args)?;
    let name = required(&params, "name")?;
    let user = optional(&params, "user").unwrap_or_else(|| "root".to_owned());
    let current = transport.run(
        connection,
        &format!("crontab -u {} -l 2>/dev/null || true", quote(&user)),
    )?;
    let original = String::from_utf8_lossy(&current.stdout);
    let marker = format!("# swift-deploy-rs: {name}");
    let mut lines = original.lines().map(str::to_owned).collect::<Vec<_>>();
    if let Some(index) = lines.iter().position(|line| line == &marker) {
        lines.remove(index);
        if index < lines.len() {
            lines.remove(index);
        }
    }
    if optional(&params, "state").as_deref() != Some("absent") {
        let job = required(&params, "job")?;
        let schedule = if let Some(special) = optional(&params, "special_time") {
            format!("@{special}")
        } else {
            format!(
                "{} {} {} {} {}",
                optional(&params, "minute").unwrap_or_else(|| "*".to_owned()),
                optional(&params, "hour").unwrap_or_else(|| "*".to_owned()),
                optional(&params, "day").unwrap_or_else(|| "*".to_owned()),
                optional(&params, "month").unwrap_or_else(|| "*".to_owned()),
                optional(&params, "weekday").unwrap_or_else(|| "*".to_owned())
            )
        };
        lines.push(marker);
        lines.push(format!("{schedule} {job}"));
    }
    let updated = finish_lines(&lines);
    if updated == original {
        return Ok(ModuleResult::default());
    }
    let remote = format!(
        "/tmp/swift-deploy-cron-{}",
        hex::encode(Sha256::digest(updated.as_bytes()))
    );
    transport.write_file(
        connection,
        &remote,
        updated.as_bytes(),
        &RemoteFileOptions {
            mode: Some("0600".to_owned()),
            ..RemoteFileOptions::default()
        },
    )?;
    let output = transport.run(
        connection,
        &format!(
            "crontab -u {} {}; status=$?; rm -f -- {}; exit $status",
            quote(&user),
            quote(&remote),
            quote(&remote)
        ),
    )?;
    Ok(command_result(output, true))
}

fn write_if_changed<T: Transport>(
    transport: &mut T,
    connection: &ConnectionSpec,
    path: &str,
    content: &[u8],
    options: RemoteFileOptions,
) -> Result<ModuleResult> {
    let content_matches = transport.read_file(connection, path)?.as_deref() == Some(content);
    let metadata_requested =
        options.mode.is_some() || options.owner.is_some() || options.group.is_some();
    if content_matches && !metadata_requested {
        return Ok(ModuleResult {
            data: json!({"dest": path}),
            ..ModuleResult::default()
        });
    }
    transport.write_file(connection, path, content, &options)?;
    Ok(ModuleResult {
        changed: true,
        data: json!({"dest": path}),
        ..ModuleResult::default()
    })
}

fn command_result(output: CommandOutput, changed: bool) -> ModuleResult {
    let failed = output.status != 0;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    ModuleResult {
        changed: changed && !failed,
        failed,
        message: if failed {
            stderr.clone()
        } else {
            String::new()
        },
        data: json!({
            "rc": output.status,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_lines": stdout.lines().collect::<Vec<_>>(),
            "stderr_lines": stderr.lines().collect::<Vec<_>>(),
            "failed": failed,
            "changed": changed && !failed
        }),
    }
}

fn parameters(args: &Value) -> Result<BTreeMap<String, Value>> {
    match args {
        Value::Object(map) => Ok(map
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()),
        Value::String(specification) => {
            let words =
                shell_words::split(specification).context("parse module key=value arguments")?;
            let mut params = BTreeMap::new();
            let mut raw = Vec::new();
            for word in words {
                if let Some((key, value)) = word.split_once('=') {
                    params.insert(key.to_owned(), scalar(value));
                } else {
                    raw.push(word);
                }
            }
            if !raw.is_empty() {
                params.insert("_raw_params".to_owned(), Value::String(raw.join(" ")));
            }
            Ok(params)
        }
        Value::Null => Ok(BTreeMap::new()),
        _ => bail!("module arguments must be a mapping or string"),
    }
}

fn scalar(value: &str) -> Value {
    serde_yaml_ng::from_str(value).unwrap_or_else(|_| Value::String(value.to_owned()))
}

fn required(params: &BTreeMap<String, Value>, key: &str) -> Result<String> {
    params
        .get(key)
        .map(value_to_string)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("module requires {key}"))
}

fn optional(params: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    params.get(key).map(value_to_string)
}

fn destination(params: &BTreeMap<String, Value>) -> Result<String> {
    required(params, "dest").or_else(|_| required(params, "path"))
}

fn raw_or_required(args: &Value, key: &str) -> Result<String> {
    if let Value::String(value) = args {
        Ok(value.clone())
    } else {
        let params = parameters(args)?;
        optional(&params, key)
            .or_else(|| optional(&params, "_raw_params"))
            .with_context(|| format!("module requires {key}"))
    }
}

fn file_options(params: &BTreeMap<String, Value>) -> RemoteFileOptions {
    RemoteFileOptions {
        mode: optional(params, "mode"),
        owner: optional(params, "owner"),
        group: optional(params, "group"),
    }
}

fn boolean_param(params: &BTreeMap<String, Value>, key: &str, default: bool) -> bool {
    params.get(key).map_or(default, ansible_bool)
}

fn ansible_bool(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_i64().is_some_and(|value| value != 0),
        Value::String(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "yes" | "on" | "1"
        ),
        _ => false,
    }
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn value_list(value: &Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items.clone(),
        Value::Null => Vec::new(),
        item => vec![item.clone()],
    }
}

fn finish_lines(lines: &[String]) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    }
}

fn quote(value: &str) -> String {
    shell_words::quote(value).into_owned()
}

fn sql_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "''")
}
