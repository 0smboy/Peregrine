use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

/// SSH connection data resolved from inventory without shell interpolation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionSpec {
    pub host: String,
    pub user: String,
    pub port: u16,
    pub key_path: Option<PathBuf>,
    pub password: Option<String>,
    pub known_hosts: Option<PathBuf>,
    pub become_user: Option<String>,
}

impl ConnectionSpec {
    #[must_use]
    pub fn local(host: &str) -> Self {
        Self {
            host: host.to_owned(),
            user: "root".to_owned(),
            port: 22,
            key_path: None,
            password: None,
            known_hosts: None,
            become_user: None,
        }
    }

    pub fn from_context(host: &str, context: &Value, known_hosts: Option<PathBuf>) -> Result<Self> {
        let user = context
            .get("ansible_user")
            .or_else(|| context.get("ansible_ssh_user"))
            .and_then(Value::as_str)
            .unwrap_or("root")
            .to_owned();
        let remote_host = context
            .get("ansible_host")
            .and_then(Value::as_str)
            .unwrap_or(host)
            .to_owned();
        if !safe_ssh_user(&user) {
            bail!("unsafe SSH user in inventory");
        }
        if !safe_ssh_host(&remote_host) {
            bail!("unsafe SSH host in inventory");
        }
        let port = context
            .get("ansible_port")
            .or_else(|| context.get("ansible_ssh_port"))
            .and_then(value_as_u16)
            .unwrap_or(22);
        let key_path = context
            .get("ansible_ssh_private_key_file")
            .and_then(Value::as_str)
            .map(PathBuf::from);
        let password = context
            .get("ansible_password")
            .or_else(|| context.get("ansible_ssh_pass"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        Ok(Self {
            host: remote_host,
            user,
            port,
            key_path,
            password,
            known_hosts,
            become_user: None,
        })
    }
}

fn value_as_u16(value: &Value) -> Option<u16> {
    value
        .as_u64()
        .and_then(|number| u16::try_from(number).ok())
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

/// Remote process result. A non-zero status is a module result, not a transport
/// construction error.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Optional ownership and permissions for an atomic remote file write.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteFileOptions {
    pub mode: Option<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
}

/// Controller-side transport boundary used by module adapters.
pub trait Transport {
    fn run(&mut self, connection: &ConnectionSpec, command: &str) -> Result<CommandOutput>;
    fn read_file(&mut self, connection: &ConnectionSpec, path: &str) -> Result<Option<Vec<u8>>>;
    fn write_file(
        &mut self,
        connection: &ConnectionSpec,
        path: &str,
        content: &[u8],
        options: &RemoteFileOptions,
    ) -> Result<()>;
    fn upload(&mut self, connection: &ConnectionSpec, local: &Path, remote: &str) -> Result<()>;
    fn download(&mut self, connection: &ConnectionSpec, remote: &str, local: &Path) -> Result<()>;
}

/// OpenSSH transport. Host-key checking is always enabled. Password mode is
/// opt-in and uses sshpass -e so the password never appears in argv.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenSshTransport {
    allow_password: bool,
}

impl OpenSshTransport {
    #[must_use]
    pub fn new(allow_password: bool) -> Self {
        Self { allow_password }
    }

    /// Return the exact controller argv for review and testing.
    pub fn ssh_argv(connection: &ConnectionSpec, command: &str) -> Result<Vec<OsString>> {
        if connection.password.is_some() {
            bail!("inventory password authentication is disabled by default");
        }
        Ok(ssh_argv_without_program(connection, command, false))
    }

    fn invocation<'a>(
        &self,
        connection: &'a ConnectionSpec,
        base: Vec<OsString>,
    ) -> Result<(Vec<OsString>, Option<&'a str>)> {
        if let Some(password) = connection.password.as_deref() {
            if !self.allow_password {
                bail!("inventory password authentication requires explicit opt-in");
            }
            let mut invocation = vec![OsString::from("sshpass"), OsString::from("-e")];
            invocation.extend(base);
            Ok((invocation, Some(password)))
        } else {
            Ok((base, None))
        }
    }

    fn execute(&self, connection: &ConnectionSpec, argv: Vec<OsString>) -> Result<CommandOutput> {
        let (argv, password) = self.invocation(connection, argv)?;
        let (program, arguments) = argv.split_first().context("empty process argv")?;
        let mut command = Command::new(program);
        command.args(arguments);
        if let Some(password) = password {
            command.env("SSHPASS", password);
        }
        let output = command
            .output()
            .with_context(|| format!("start {}", program.to_string_lossy()))?;
        Ok(CommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn copy(&self, connection: &ConnectionSpec, argv: Vec<OsString>) -> Result<()> {
        let output = self.execute(connection, argv)?;
        if output.status != 0 {
            bail!(
                "secure copy failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
}

impl Transport for OpenSshTransport {
    fn run(&mut self, connection: &ConnectionSpec, command: &str) -> Result<CommandOutput> {
        let command = elevated_command(connection, command);
        if is_local(connection) {
            return execute_local(&command);
        }
        let argv = ssh_argv_without_program(connection, &command, self.allow_password);
        self.execute(connection, argv)
    }

    fn read_file(&mut self, connection: &ConnectionSpec, path: &str) -> Result<Option<Vec<u8>>> {
        if is_local(connection) {
            return match fs::read(path) {
                Ok(content) => Ok(Some(content)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error).with_context(|| format!("read local file {path}")),
            };
        }
        let path = quote(path);
        let output = self.run(
            connection,
            &format!("if test -e {path}; then cat -- {path}; else exit 44; fi"),
        )?;
        match output.status {
            0 => Ok(Some(output.stdout)),
            44 => Ok(None),
            _ => bail!(
                "read remote file failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ),
        }
    }

    fn write_file(
        &mut self,
        connection: &ConnectionSpec,
        path: &str,
        content: &[u8],
        options: &RemoteFileOptions,
    ) -> Result<()> {
        if is_local(connection) {
            return write_local_file(connection, path, content, options);
        }
        let mut local = NamedTempFile::new().context("create controller transfer file")?;
        local
            .write_all(content)
            .context("write controller transfer file")?;
        local.flush().context("flush controller transfer file")?;
        let hash = hex::encode(Sha256::digest(content));
        let remote_upload = format!("/tmp/swift-deploy-rs-{}", &hash[..20]);
        self.upload(connection, local.path(), &remote_upload)?;

        let install = remote_atomic_install_command(path, &remote_upload, options);
        let output = self.run(connection, &install)?;
        if output.status != 0 {
            bail!(
                "atomic remote write failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    fn upload(&mut self, connection: &ConnectionSpec, local: &Path, remote: &str) -> Result<()> {
        if is_local(connection) {
            copy_local(local, Path::new(remote))?;
            return Ok(());
        }
        let mut argv = scp_base_argv(connection, self.allow_password);
        argv.push(local.as_os_str().to_owned());
        argv.push(OsString::from(remote_target(connection, remote)));
        self.copy(connection, argv)
    }

    fn download(&mut self, connection: &ConnectionSpec, remote: &str, local: &Path) -> Result<()> {
        if is_local(connection) {
            copy_local(Path::new(remote), local)?;
            return Ok(());
        }
        let mut argv = scp_base_argv(connection, self.allow_password);
        argv.push(OsString::from(remote_target(connection, remote)));
        argv.push(local.as_os_str().to_owned());
        self.copy(connection, argv)
    }
}

fn remote_atomic_install_command(
    path: &str,
    remote_upload: &str,
    options: &RemoteFileOptions,
) -> String {
    let destination = quote(path);
    let upload = quote(remote_upload);
    let temporary = quote(&format!("{path}.swift-deploy-rs.tmp"));
    let mode = options
        .mode
        .as_deref()
        .map_or_else(|| "\"$existing_mode\"".to_owned(), quote);
    let owner = options
        .owner
        .as_deref()
        .map_or_else(|| "\"$existing_owner\"".to_owned(), quote);
    let group = options
        .group
        .as_deref()
        .map_or_else(|| "\"$existing_group\"".to_owned(), quote);

    format!(
        "if test -e {destination}; then existing_mode=$(stat -Lc %a -- {destination}) && existing_owner=$(stat -Lc %u -- {destination}) && existing_group=$(stat -Lc %g -- {destination}); else existing_mode=0644 && existing_owner=$(id -u) && existing_group=$(id -g); fi && install -D -m {mode} -o {owner} -g {group} -- {upload} {temporary} && mv -f -- {temporary} {destination}; status=$?; rm -f -- {upload}; exit $status"
    )
}

fn ssh_argv_without_program(
    connection: &ConnectionSpec,
    command: &str,
    password_mode: bool,
) -> Vec<OsString> {
    let mut argv = Vec::new();
    argv.push(OsString::from("ssh"));
    add_common_ssh_options(&mut argv, connection, password_mode);
    argv.push(OsString::from("-p"));
    argv.push(OsString::from(connection.port.to_string()));
    if let Some(key) = &connection.key_path {
        argv.push(OsString::from("-i"));
        argv.push(key.as_os_str().to_owned());
    }
    argv.push(OsString::from("--"));
    argv.push(OsString::from(format!(
        "{}@{}",
        connection.user, connection.host
    )));
    argv.push(OsString::from(command));
    argv
}

fn scp_base_argv(connection: &ConnectionSpec, password_mode: bool) -> Vec<OsString> {
    let mut argv = vec![OsString::from("scp")];
    add_common_ssh_options(&mut argv, connection, password_mode);
    argv.push(OsString::from("-P"));
    argv.push(OsString::from(connection.port.to_string()));
    if let Some(key) = &connection.key_path {
        argv.push(OsString::from("-i"));
        argv.push(key.as_os_str().to_owned());
    }
    argv.push(OsString::from("--"));
    argv
}

fn add_common_ssh_options(
    argv: &mut Vec<OsString>,
    connection: &ConnectionSpec,
    password_mode: bool,
) {
    argv.push(OsString::from("-o"));
    argv.push(OsString::from("StrictHostKeyChecking=yes"));
    argv.push(OsString::from("-o"));
    argv.push(OsString::from(if password_mode {
        "BatchMode=no"
    } else {
        "BatchMode=yes"
    }));
    argv.push(OsString::from("-o"));
    argv.push(OsString::from("ConnectTimeout=8"));
    argv.push(OsString::from("-o"));
    argv.push(OsString::from("ConnectionAttempts=1"));
    if let Some(known_hosts) = &connection.known_hosts {
        argv.push(OsString::from("-o"));
        argv.push(OsString::from(format!(
            "UserKnownHostsFile={}",
            known_hosts.to_string_lossy()
        )));
    }
}

fn remote_target(connection: &ConnectionSpec, path: &str) -> String {
    format!("{}@{}:{}", connection.user, connection.host, quote(path))
}

fn safe_ssh_user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
}

fn safe_ssh_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:-_[]%".contains(character))
}

fn quote(value: &str) -> String {
    shell_words::quote(value).into_owned()
}

fn is_local(connection: &ConnectionSpec) -> bool {
    matches!(connection.host.as_str(), "localhost" | "127.0.0.1" | "::1")
}

fn elevated_command(connection: &ConnectionSpec, command: &str) -> String {
    connection.become_user.as_ref().map_or_else(
        || command.to_owned(),
        |user| {
            if user == &connection.user {
                command.to_owned()
            } else {
                format!(
                    "sudo -n -u {} -- /bin/sh -c {}",
                    quote(user),
                    quote(command)
                )
            }
        },
    )
}

fn execute_local(command: &str) -> Result<CommandOutput> {
    let output = Command::new("/bin/sh")
        .args(["-c", command])
        .output()
        .context("execute delegated local command")?;
    Ok(CommandOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn write_local_file(
    connection: &ConnectionSpec,
    path: &str,
    content: &[u8],
    options: &RemoteFileOptions,
) -> Result<()> {
    let path = Path::new(path);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create local directory {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("create atomic local file in {}", parent.display()))?;
    temporary
        .write_all(content)
        .with_context(|| format!("write local file {}", path.display()))?;
    temporary.flush().context("flush atomic local file")?;
    if let Some(mode) = &options.mode {
        let mode = u32::from_str_radix(mode.trim_start_matches('0'), 8)
            .with_context(|| format!("invalid file mode {mode}"))?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .context("set local file permissions")?;
    }
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("persist local file {}", path.display()))?;
    if options.owner.is_some() || options.group.is_some() {
        let ownership = format!(
            "{}:{}",
            options.owner.as_deref().unwrap_or(""),
            options.group.as_deref().unwrap_or("")
        );
        let output = execute_local(&elevated_command(
            connection,
            &format!(
                "chown {} -- {}",
                quote(&ownership),
                quote(&path.to_string_lossy())
            ),
        ))?;
        if output.status != 0 {
            bail!(
                "local chown failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    Ok(())
}

fn copy_local(source: &Path, destination: &Path) -> Result<()> {
    if source == destination {
        return Ok(());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create local directory {}", parent.display()))?;
    }
    fs::copy(source, destination).with_context(|| {
        format!(
            "copy local file {} to {}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

/// Actions captured by the non-mutating test transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportAction {
    Run {
        host: String,
        command: String,
    },
    ReadFile {
        host: String,
        path: String,
    },
    WriteFile {
        host: String,
        path: String,
        options: RemoteFileOptions,
    },
    Upload {
        host: String,
        local: PathBuf,
        remote: String,
    },
    Download {
        host: String,
        remote: String,
        local: PathBuf,
    },
}

/// Deterministic in-memory transport used for module and executor tests.
#[derive(Debug, Default)]
pub struct RecordingTransport {
    pub actions: Vec<TransportAction>,
    pub outputs: VecDeque<CommandOutput>,
    files: BTreeMap<(String, String), Vec<u8>>,
}

impl RecordingTransport {
    pub fn set_file(&mut self, host: &str, path: &str, content: Vec<u8>) {
        self.files
            .insert((host.to_owned(), path.to_owned()), content);
    }

    #[must_use]
    pub fn file(&self, host: &str, path: &str) -> Option<&[u8]> {
        self.files
            .get(&(host.to_owned(), path.to_owned()))
            .map(Vec::as_slice)
    }
}

impl Transport for RecordingTransport {
    fn run(&mut self, connection: &ConnectionSpec, command: &str) -> Result<CommandOutput> {
        self.actions.push(TransportAction::Run {
            host: connection.host.clone(),
            command: command.to_owned(),
        });
        Ok(self.outputs.pop_front().unwrap_or(CommandOutput {
            status: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }))
    }

    fn read_file(&mut self, connection: &ConnectionSpec, path: &str) -> Result<Option<Vec<u8>>> {
        self.actions.push(TransportAction::ReadFile {
            host: connection.host.clone(),
            path: path.to_owned(),
        });
        Ok(self
            .files
            .get(&(connection.host.clone(), path.to_owned()))
            .cloned())
    }

    fn write_file(
        &mut self,
        connection: &ConnectionSpec,
        path: &str,
        content: &[u8],
        options: &RemoteFileOptions,
    ) -> Result<()> {
        self.actions.push(TransportAction::WriteFile {
            host: connection.host.clone(),
            path: path.to_owned(),
            options: options.clone(),
        });
        self.files
            .insert((connection.host.clone(), path.to_owned()), content.to_vec());
        Ok(())
    }

    fn upload(&mut self, connection: &ConnectionSpec, local: &Path, remote: &str) -> Result<()> {
        self.actions.push(TransportAction::Upload {
            host: connection.host.clone(),
            local: local.to_path_buf(),
            remote: remote.to_owned(),
        });
        let content =
            fs::read(local).with_context(|| format!("read upload {}", local.display()))?;
        self.files
            .insert((connection.host.clone(), remote.to_owned()), content);
        Ok(())
    }

    fn download(&mut self, connection: &ConnectionSpec, remote: &str, local: &Path) -> Result<()> {
        self.actions.push(TransportAction::Download {
            host: connection.host.clone(),
            remote: remote.to_owned(),
            local: local.to_path_buf(),
        });
        let content = self
            .files
            .get(&(connection.host.clone(), remote.to_owned()))
            .with_context(|| format!("recording transport file missing: {remote}"))?;
        if let Some(parent) = local.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create download directory {}", parent.display()))?;
        }
        fs::write(local, content).with_context(|| format!("write download {}", local.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::{RemoteFileOptions, remote_atomic_install_command};

    #[test]
    fn remote_atomic_install_preserves_metadata_and_defaults_new_files_to_0644() {
        let command = remote_atomic_install_command(
            "/etc/swift/proxy server.conf",
            "/tmp/swift-upload",
            &RemoteFileOptions::default(),
        );

        assert!(command.contains("existing_mode=$(stat -Lc %a"));
        assert!(command.contains("existing_owner=$(stat -Lc %u"));
        assert!(command.contains("existing_group=$(stat -Lc %g"));
        assert!(command.contains("existing_mode=0644"));
        assert!(command.contains("-m \"$existing_mode\""));
        assert!(command.contains("-o \"$existing_owner\""));
        assert!(command.contains("-g \"$existing_group\""));

        let explicit = remote_atomic_install_command(
            "/etc/swift/proxy.conf",
            "/tmp/swift-upload",
            &RemoteFileOptions {
                mode: Some("0600".to_owned()),
                owner: Some("swift".to_owned()),
                group: Some("swift".to_owned()),
            },
        );
        assert!(explicit.contains("install -D -m 0600 -o swift -g swift --"));
    }
}
