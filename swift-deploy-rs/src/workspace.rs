//! Safe, deterministic generation of a deployable Swift inventory workspace.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// Complete operator input for one Swift deployment workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceRequest {
    pub project_name: String,
    /// Deployment stack: `python-v3` (default) or `rust`.
    #[serde(default = "default_stack")]
    pub stack: String,
    pub deployment_mode: String,
    pub saio: bool,
    pub use_wwid: bool,
    pub hostname_modifiable: bool,
    pub hostname_prefix: String,
    pub timezone: String,
    pub ntp_internet_server: String,
    pub local_repo_address: String,
    pub admin_ips: Vec<String>,
    pub ssh_bind_port: u16,
    pub nodes: Vec<Node>,
    pub ring: Ring,
    pub auth: Auth,
    /// `TempAuth` accounts used by the rust stack; empty for python-v3.
    #[serde(default)]
    pub tempauth_accounts: Vec<TempauthAccount>,
    pub ingress: Ingress,
}

/// One `TempAuth` account for the rust stack; the first entry is the admin account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempauthAccount {
    pub account: String,
    pub user: String,
    pub key: String,
}

fn default_stack() -> String {
    "python-v3".to_owned()
}

/// One physical or virtual machine participating in the deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub name: String,
    pub address: String,
    pub ssh_user: String,
    pub ssh_port: u16,
    pub ssh_key_file: String,
    pub management_ip: String,
    pub storage_ip: String,
    pub replication_ip: String,
    pub business_ip: String,
    pub region: u16,
    pub zone: u16,
    pub roles: Vec<String>,
    pub disk_type: String,
    pub system_disk: String,
    pub disks: Vec<String>,
    /// Rust-stack directory device basenames under `srv_node_root` (e.g. `d1`).
    /// Empty means a single `d1`. Never block devices — no wipe/mkfs path.
    #[serde(default)]
    pub swift_devices: Vec<String>,
    pub keepalived_interface: String,
    pub keepalived_priority: Option<u16>,
}

/// Ring settings shared by account, container, and the primary object policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ring {
    pub partition_power: u8,
    pub replicas: u16,
    pub minimum_time: u32,
    pub object_policy_name: String,
    pub object_policy_type: String,
    pub ec_data_fragments: Option<u16>,
    pub ec_parity_fragments: Option<u16>,
    pub ec_segment_size: u64,
    pub device_weight: u16,
}

/// Authentication, service-account, Keystone, and `MariaDB` credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Auth {
    pub method: String,
    pub interface: String,
    pub account_name: String,
    pub admin_user: String,
    pub admin_password: String,
    pub mariadb_root_password: String,
    pub mariadb_keystone_password: String,
    pub mariadb_clustercheck_password: String,
    pub keystone_admin_password: String,
    pub keystone_swift_password: String,
    pub keystone_controller_hostname: String,
    pub haproxy_stats_user: String,
    pub haproxy_stats_password: String,
}

/// Public entry-point and optional HAProxy/Keepalived settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ingress {
    pub mode: String,
    pub http_mode: String,
    pub auth_url_ip: String,
    pub swift_port: u16,
    pub vip_prefix: u8,
    pub virtual_router_id: u8,
    pub vrrp_auth_pass: String,
}

/// A validation finding tied to the wizard step and field that can fix it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub step: String,
    pub field: String,
    pub message: String,
}

/// Structured result returned before any workspace files are written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub valid: bool,
    pub errors: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
}

/// Operator-facing deployment facts derived from a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSummary {
    pub project_name: String,
    pub deployment_mode: String,
    pub node_count: usize,
    pub storage_node_count: usize,
    pub disk_count: usize,
    pub regions: Vec<u16>,
    pub zones: Vec<u16>,
    pub replicas: u16,
    pub auth_method: String,
    pub http_mode: String,
    pub ingress_mode: String,
}

/// A generated file shown to the operator. Secret values are always redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceFile {
    pub path: String,
    pub content: String,
}

/// Dry-run rendering result. Invalid requests contain no generated files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspacePreview {
    pub valid: bool,
    pub errors: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    pub summary: WorkspaceSummary,
    pub files: Vec<WorkspaceFile>,
}

/// Paths and redacted file previews for a newly materialized workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedWorkspace {
    pub project_root: PathBuf,
    pub inventory: PathBuf,
    pub playbook: PathBuf,
    pub plan: PathBuf,
    pub summary: WorkspaceSummary,
    pub files: Vec<WorkspaceFile>,
}

#[derive(Debug, Clone)]
struct RenderedFile {
    path: String,
    content: String,
}

impl WorkspaceRequest {
    /// Validate topology, networking, disks, rings, authentication, and ingress.
    #[must_use]
    pub fn validate(&self) -> ValidationReport {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        self.validate_stack(&mut errors);
        self.validate_project(&mut errors);
        self.validate_nodes(&mut errors, &mut warnings);
        self.validate_required_roles(&mut errors, &mut warnings);
        self.validate_storage(&mut errors, &mut warnings);
        self.validate_ring(&mut errors, &mut warnings);
        self.validate_auth(&mut errors);
        self.validate_ingress(&mut errors);
        self.validate_saio(&mut errors, &mut warnings);

        if !self.is_rust() {
            warning(
                &mut warnings,
                "safety",
                "firewall",
                "v3 会重写 iptables 与 sshd；Apply 必须单独确认防火墙和 SSH 风险，并确保 admin_ips 含当前运维入口。",
            );
            warning(
                &mut warnings,
                "auth",
                "data_encryption",
                "v3 的 Keystone 加密 pipeline 缺少 keymaster/encryption，生成配置已强制关闭 data_encryption。",
            );
        }

        ValidationReport {
            valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    /// Render a secret-redacted workspace preview without writing to disk.
    pub fn preview(&self, bundle: impl AsRef<Path>) -> Result<WorkspacePreview> {
        let report = self.validate();
        let summary = self.summary();
        if !report.valid {
            return Ok(WorkspacePreview {
                valid: false,
                errors: report.errors,
                warnings: report.warnings,
                summary,
                files: Vec::new(),
            });
        }

        let rendered = self.render_files(bundle.as_ref())?;
        Ok(WorkspacePreview {
            valid: true,
            errors: report.errors,
            warnings: report.warnings,
            summary,
            files: self.redacted_files(&rendered),
        })
    }

    /// Atomically create `<workspace_root>/<project-slug>` with restrictive modes.
    pub fn generate(
        &self,
        bundle: impl AsRef<Path>,
        workspace_root: impl AsRef<Path>,
    ) -> Result<GeneratedWorkspace> {
        let report = self.validate();
        if !report.valid {
            let details = report
                .errors
                .iter()
                .map(|issue| format!("{}: {}", issue.field, issue.message))
                .collect::<Vec<_>>()
                .join("; ");
            bail!("workspace validation failed: {details}");
        }

        let bundle = bundle.as_ref();
        let rendered = self.render_files(bundle)?;
        let root = prepare_workspace_root(workspace_root.as_ref())?;
        let slug = project_slug(&self.project_name);
        let project_root = root.join(&slug);
        if fs::symlink_metadata(&project_root).is_ok() {
            bail!("workspace already exists: {}", project_root.display());
        }

        let staging = tempfile::Builder::new()
            .prefix(&format!(".{slug}-"))
            .tempdir_in(&root)
            .with_context(|| format!("create workspace staging directory in {}", root.display()))?;
        set_directory_mode(staging.path())?;
        for file in &rendered {
            write_workspace_file(staging.path(), file)?;
        }
        fs::rename(staging.path(), &project_root)
            .with_context(|| format!("publish generated workspace {}", project_root.display()))?;

        let playbook = bundle
            .join("swift.yml")
            .canonicalize()
            .with_context(|| format!("resolve playbook {}/swift.yml", bundle.display()))?;
        Ok(GeneratedWorkspace {
            inventory: project_root.join("swift_hosts"),
            playbook,
            plan: project_root.join("swift-plan.json"),
            project_root,
            summary: self.summary(),
            files: self.redacted_files(&rendered),
        })
    }

    /// True when this request targets the Rust Swift deployment stack.
    #[must_use]
    pub fn is_rust(&self) -> bool {
        self.stack == "rust"
    }

    /// Effective replication address for one node. python-v3 pins replication
    /// to the storage network; the rust stack allows a dedicated replication
    /// network and falls back to the storage address when none is provided.
    fn effective_replication_ip<'a>(&self, node: &'a Node) -> &'a str {
        if self.is_rust() && node.replication_ip.trim().is_empty() {
            node.storage_ip.as_str()
        } else {
            node.replication_ip.as_str()
        }
    }

    fn validate_stack(&self, errors: &mut Vec<ValidationIssue>) {
        if !matches!(self.stack.as_str(), "python-v3" | "rust") {
            error(
                errors,
                "project",
                "stack",
                "部署栈只能是 python-v3 或 rust。",
            );
        }
    }

    fn validate_project(&self, errors: &mut Vec<ValidationIssue>) {
        if self.project_name.trim().is_empty() {
            error(errors, "project", "project_name", "项目名称不能为空。");
        }
        if self.project_name.chars().any(char::is_control) {
            error(
                errors,
                "project",
                "project_name",
                "项目名称不能包含控制字符。",
            );
        }
        if !matches!(self.deployment_mode.as_str(), "production" | "development") {
            error(
                errors,
                "project",
                "deployment_mode",
                "部署模式只能是 production 或 development。",
            );
        }
        if self.timezone.trim().is_empty() || self.timezone.contains("..") {
            error(
                errors,
                "project",
                "timezone",
                "必须填写合法时区，例如 Asia/Shanghai。",
            );
        }
        if self.ntp_internet_server.trim().is_empty() {
            error(
                errors,
                "project",
                "ntp_internet_server",
                "必须填写上游 NTP 服务器。",
            );
        }
        if !self.is_rust() && self.local_repo_address.parse::<Ipv4Addr>().is_err() {
            error(
                errors,
                "project",
                "local_repo_address",
                "本地软件源必须是单个 IPv4，不能包含协议、端口、DNS 名或路径；v3 会拼接 http://<IP>/yum、/pip、/component。",
            );
        }
        if self.hostname_modifiable && !is_hostname_component(&self.hostname_prefix) {
            error(
                errors,
                "project",
                "hostname_prefix",
                "允许修改 hostname 时必须填写安全的主机名前缀。",
            );
        }
        if self.ssh_bind_port == 0 {
            error(errors, "network", "ssh_bind_port", "SSH 目标端口不能为 0。");
        }
        if self.admin_ips.is_empty() {
            error(
                errors,
                "network",
                "admin_ips",
                "至少配置一个管理员或跳板机 IPv4，否则新 iptables 规则会锁死运维入口。",
            );
        }
        let mut seen = BTreeSet::new();
        for (index, address) in self.admin_ips.iter().enumerate() {
            if address.parse::<Ipv4Addr>().is_err() {
                error(
                    errors,
                    "network",
                    &format!("admin_ips[{index}]"),
                    "管理员地址必须是单个 IPv4，不能使用占位符或 CIDR。",
                );
            } else if !seen.insert(address) {
                error(
                    errors,
                    "network",
                    &format!("admin_ips[{index}]"),
                    "管理员 IPv4 重复。",
                );
            }
        }
    }

    fn validate_nodes(
        &self,
        errors: &mut Vec<ValidationIssue>,
        warnings: &mut Vec<ValidationIssue>,
    ) {
        if self.nodes.is_empty() {
            error(errors, "topology", "nodes", "至少需要一台 Swift 节点。");
            return;
        }

        let mut names = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        let mut networks: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for (index, node) in self.nodes.iter().enumerate() {
            let prefix = format!("nodes[{index}]");
            if !is_inventory_name(&node.name) {
                error(
                    errors,
                    "topology",
                    &format!("{prefix}.name"),
                    "节点名只能包含字母、数字、点、下划线和连字符。",
                );
            } else if !names.insert(node.name.as_str()) {
                error(
                    errors,
                    "topology",
                    &format!("{prefix}.name"),
                    "节点名重复。",
                );
            }
            if !is_connection_address(&node.address) {
                error(
                    errors,
                    "topology",
                    &format!("{prefix}.address"),
                    "SSH 地址必须是 IPv4、IPv6 或安全的 DNS 名称。",
                );
            } else if !addresses.insert(node.address.as_str()) {
                error(
                    errors,
                    "topology",
                    &format!("{prefix}.address"),
                    "SSH 地址重复。",
                );
            }
            if node.ssh_user != "root" {
                error(
                    errors,
                    "topology",
                    &format!("{prefix}.ssh_user"),
                    "选定的 v3 roles 有未声明 become 的特权任务；当前部署合同只允许 root SSH 用户。",
                );
            }
            if node.ssh_port == 0 {
                error(
                    errors,
                    "topology",
                    &format!("{prefix}.ssh_port"),
                    "当前 SSH 端口不能为 0。",
                );
            }
            let key = Path::new(&node.ssh_key_file);
            if !key.is_absolute() || node.ssh_key_file.contains(['\n', '\r']) {
                error(
                    errors,
                    "topology",
                    &format!("{prefix}.ssh_key_file"),
                    "SSH 私钥必须填写部署机上的绝对路径。",
                );
            }
            if node.roles.is_empty() {
                error(
                    errors,
                    "topology",
                    &format!("{prefix}.roles"),
                    "节点至少需要一个角色。",
                );
            }
            for (role_index, role) in node.roles.iter().enumerate() {
                if canonical_role(role).is_none() {
                    error(
                        errors,
                        "topology",
                        &format!("{prefix}.roles[{role_index}]"),
                        &format!("未知角色 {role}。"),
                    );
                }
            }
            if has_role(node, "ntp_server") && has_role(node, "ntp_client") {
                error(
                    errors,
                    "topology",
                    &format!("{prefix}.roles"),
                    "同一节点不能同时是 ntp_server 和 ntp_client。",
                );
            }

            let replication = self.effective_replication_ip(node);
            for (field, value) in [
                ("management_ip", node.management_ip.as_str()),
                ("storage_ip", node.storage_ip.as_str()),
                ("replication_ip", replication),
                ("business_ip", node.business_ip.as_str()),
            ] {
                if value.parse::<Ipv4Addr>().is_err() {
                    error(
                        errors,
                        "network",
                        &format!("{prefix}.{field}"),
                        "网络地址必须是单个 IPv4。",
                    );
                } else if !networks.entry(field).or_default().insert(value) {
                    error(
                        errors,
                        "network",
                        &format!("{prefix}.{field}"),
                        "同一网络中的节点地址不能重复。",
                    );
                }
            }
            if !self.is_rust()
                && node.storage_ip.parse::<Ipv4Addr>().is_ok()
                && node.replication_ip.parse::<Ipv4Addr>().is_ok()
                && node.storage_ip != node.replication_ip
            {
                error(
                    errors,
                    "network",
                    &format!("{prefix}.replication_ip"),
                    "选定的 swift_ansible v3 存储服务与 rsync 只监听 storage_network_address；replication_ip 必须与 storage_ip 一致。",
                );
            }
            let distinct = [
                node.management_ip.as_str(),
                node.storage_ip.as_str(),
                replication,
                node.business_ip.as_str(),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len();
            if distinct == 1 {
                warning(
                    warnings,
                    "network",
                    &format!("{prefix}.management_ip"),
                    "管理、存储与业务网络复用同一 IPv4；实验环境可用，生产环境失去网络隔离。",
                );
            }
            if is_storage_node(node) && node.region == 0 {
                error(
                    errors,
                    "ring",
                    &format!("{prefix}.region"),
                    "region 必须大于 0。",
                );
            }
            if is_storage_node(node) && node.zone == 0 {
                error(
                    errors,
                    "ring",
                    &format!("{prefix}.zone"),
                    "zone 必须大于 0。",
                );
            }
        }
    }

    fn validate_required_roles(
        &self,
        errors: &mut Vec<ValidationIssue>,
        warnings: &mut Vec<ValidationIssue>,
    ) {
        for (role, label) in [
            ("proxy", "proxy"),
            ("account", "account/storage"),
            ("container", "container/storage"),
            ("object", "object/storage"),
        ] {
            if !self.nodes.iter().any(|node| has_effective_role(node, role)) {
                error(
                    errors,
                    "topology",
                    "nodes.roles",
                    &format!("缺少必需的 {label} 角色。"),
                );
            }
        }

        let ntp_servers = self
            .nodes
            .iter()
            .filter(|node| has_role(node, "ntp_server"))
            .count();
        if ntp_servers > 1 {
            error(
                errors,
                "topology",
                "nodes.roles",
                "集群只能选择一个 ntp_server。",
            );
        } else if ntp_servers == 0 {
            error(
                errors,
                "topology",
                "nodes.roles",
                "必须明确选择一台 ntp_server；生产配置不能依赖隐式首节点 fallback。",
            );
        }

        if self.is_rust() {
            for (index, node) in self.nodes.iter().enumerate() {
                if has_role(node, "mariadb") || has_role(node, "keystone") {
                    error(
                        errors,
                        "topology",
                        &format!("nodes[{index}].roles"),
                        "rust 栈自带 TempAuth，不部署 MariaDB/Keystone；请移除该节点的 mariadb/keystone 角色。",
                    );
                }
            }
        }

        if !self.is_rust() && self.auth.method.eq_ignore_ascii_case("keystone") {
            let mut mariadb = self
                .nodes
                .iter()
                .filter(|node| has_role(node, "mariadb"))
                .collect::<Vec<_>>();
            mariadb.sort_by(|left, right| compare_management_ip(left, right));
            if mariadb.is_empty() {
                error(
                    errors,
                    "topology",
                    "nodes.roles",
                    "Keystone 模式至少需要一个 mariadb 节点。",
                );
            }
            if !self.nodes.iter().any(|node| has_role(node, "keystone")) {
                error(
                    errors,
                    "topology",
                    "nodes.roles",
                    "Keystone 模式至少需要一个 keystone 节点。",
                );
            }
            if let Some(first) = mariadb.first()
                && !has_role(first, "keystone")
            {
                error(
                    errors,
                    "topology",
                    "nodes.roles",
                    &format!(
                        "按 inventory 顺序首个 MariaDB 节点 {} 必须同时承担 Keystone 角色。",
                        first.name
                    ),
                );
            }
            if !mariadb.is_empty() && mariadb.len().is_multiple_of(2) {
                warning(
                    warnings,
                    "topology",
                    "nodes.roles",
                    "MariaDB Galera 节点数为偶数，生产环境建议使用 3 个或更多奇数节点。",
                );
            }
        }
    }

    fn validate_storage(
        &self,
        errors: &mut Vec<ValidationIssue>,
        warnings: &mut Vec<ValidationIssue>,
    ) {
        for (index, node) in self.nodes.iter().enumerate() {
            let prefix = format!("nodes[{index}]");
            let storage = is_storage_node(node);
            if storage && node.disks.is_empty() && !self.is_rust() {
                error(
                    errors,
                    "storage",
                    &format!("{prefix}.disks"),
                    "存储节点必须逐盘列出将被清空的设备。",
                );
            }
            // rust stack deploys directory devices only, so no rust plan ever
            // carries the disk_wipe capability; block-device wipe/format stays
            // behind an explicit ticket + --allow-disk-wipe (not in this bundle).
            if self.is_rust() && !node.disks.is_empty() {
                error(
                    errors,
                    "storage",
                    &format!("{prefix}.disks"),
                    "rust 栈只部署目录设备（host_vars.swift_devices，默认 d1），不管理数据盘格式化/wipe；请清空 disks 列表。扩容见 expand.yml + P3-ops 双守卫。",
                );
            }
            if self.is_rust() {
                for (dev_index, device) in node.swift_devices.iter().enumerate() {
                    if !is_safe_swift_device(device) {
                        error(
                            errors,
                            "storage",
                            &format!("{prefix}.swift_devices[{dev_index}]"),
                            "swift_devices 必须是安全的目录基名（如 d1、d2），不能含 /、.. 或空白。",
                        );
                    }
                }
            }
            if !storage && !node.disks.is_empty() {
                error(
                    errors,
                    "storage",
                    &format!("{prefix}.disks"),
                    "非存储节点不能填写数据盘；只有 account/container/object 存储节点会格式化磁盘。",
                );
            }
            let needs_system_disk = storage && (!self.is_rust() || !node.disks.is_empty());
            if needs_system_disk && normalized_system_disk(&node.system_disk).is_none() {
                error(
                    errors,
                    "storage",
                    &format!("{prefix}.system_disk"),
                    "必须明确系统盘，例如 /dev/sda 或 /dev/nvme0n1。",
                );
            }
            if !node.disks.is_empty() && !matches!(node.disk_type.as_str(), "hdd" | "ssd") {
                error(
                    errors,
                    "storage",
                    &format!("{prefix}.disk_type"),
                    "单台主机只能选择一种 disk_type：hdd 或 ssd。",
                );
            }

            let system = normalized_system_disk(&node.system_disk);
            let mut disks = BTreeSet::new();
            for (disk_index, disk) in node.disks.iter().enumerate() {
                let field = format!("{prefix}.disks[{disk_index}]");
                let Some(normalized) = normalized_disk(disk) else {
                    error(
                        errors,
                        "storage",
                        &field,
                        "数据盘必须是 /dev/ 下的完整设备路径，不能包含分号、空白或 ..。",
                    );
                    continue;
                };
                if system.as_deref() == Some(normalized.as_str()) {
                    error(
                        errors,
                        "storage",
                        &field,
                        "数据盘与系统盘冲突；该配置会清空系统盘。",
                    );
                }
                if !disks.insert(normalized) {
                    error(errors, "storage", &field, "同一数据盘重复配置。");
                }
            }
        }
        if self.use_wwid && self.nodes.iter().any(|node| !node.disks.is_empty()) {
            error(
                errors,
                "storage",
                "use_wwid",
                "v3 的显式 custom_disks 路径与 USE_WWID 不兼容；逐盘模式必须关闭 USE_WWID。",
            );
        } else if self.deployment_mode == "production" && !self.use_wwid {
            warning(
                warnings,
                "storage",
                "use_wwid",
                "v3 建议生产使用 WWID，但它与更安全的逐盘 custom_disks 路径冲突；本工作区保留逐盘模式。",
            );
        }
    }

    fn validate_ring(
        &self,
        errors: &mut Vec<ValidationIssue>,
        warnings: &mut Vec<ValidationIssue>,
    ) {
        if !(8..=32).contains(&self.ring.partition_power) {
            error(
                errors,
                "ring",
                "ring.partition_power",
                "partition power 必须在 8 到 32 之间。",
            );
        }
        if self.ring.replicas == 0 {
            error(errors, "ring", "ring.replicas", "replicas 必须大于 0。");
        }
        if self.ring.minimum_time == 0 {
            error(
                errors,
                "ring",
                "ring.minimum_time",
                "ring 最小迁移时间必须大于 0。",
            );
        }
        if self.ring.device_weight == 0 {
            error(errors, "ring", "ring.device_weight", "设备权重必须大于 0。");
        }
        if self.ring.object_policy_name.trim().is_empty()
            || self.ring.object_policy_name.contains('_')
            || self
                .ring
                .object_policy_name
                .chars()
                .any(char::is_whitespace)
        {
            error(
                errors,
                "ring",
                "ring.object_policy_name",
                "对象策略名不能为空、包含空白或下划线。",
            );
        }

        for role in ["account", "container", "object"] {
            let devices = self.role_device_count(role);
            if usize::from(self.ring.replicas) > devices {
                error(
                    errors,
                    "ring",
                    "ring.replicas",
                    &format!(
                        "{role} ring 的副本/分片数 {} 超过可用设备数 {devices}。",
                        self.ring.replicas
                    ),
                );
            }
            let zones = self
                .nodes
                .iter()
                .filter(|node| has_effective_role(node, role))
                .map(|node| (node.region, node.zone))
                .collect::<BTreeSet<_>>();
            if self.deployment_mode == "production" && !self.saio && zones.len() < 2 {
                error(
                    errors,
                    "ring",
                    "nodes.zone",
                    &format!("生产集群的 {role} ring 至少需要两个不同的 region/zone 故障域。"),
                );
            }
            if usize::from(self.ring.replicas) > zones.len() && !zones.is_empty() {
                warning(
                    warnings,
                    "ring",
                    "ring.replicas",
                    &format!(
                        "{role} ring 的副本数大于故障域数量，Swift 会在同一故障域放置额外副本。"
                    ),
                );
            }
        }

        match self.ring.object_policy_type.as_str() {
            "replication" => {
                if self.ring.ec_data_fragments.is_some() || self.ring.ec_parity_fragments.is_some()
                {
                    warning(
                        warnings,
                        "ring",
                        "ring.ec_data_fragments",
                        "replication 策略会忽略 EC 数据片和校验片参数。",
                    );
                }
            }
            "erasure_coding" if self.is_rust() => {
                let data = self.ring.ec_data_fragments.unwrap_or(0);
                let parity = self.ring.ec_parity_fragments.unwrap_or(0);
                if data == 0 {
                    error(
                        errors,
                        "ring",
                        "ring.ec_data_fragments",
                        "EC 数据分片数必须大于 0。",
                    );
                }
                if parity == 0 {
                    error(
                        errors,
                        "ring",
                        "ring.ec_parity_fragments",
                        "EC 校验分片数必须大于 0。",
                    );
                }
                if self.ring.ec_segment_size == 0 {
                    error(
                        errors,
                        "ring",
                        "ring.ec_segment_size",
                        "EC 分段大小必须大于 0。",
                    );
                }
                let object_devices = self.role_device_count("object");
                let fragments = usize::from(data) + usize::from(parity);
                if data > 0 && parity > 0 && object_devices < fragments {
                    error(
                        errors,
                        "ring",
                        "ring.ec_data_fragments",
                        &format!(
                            "EC 需要 object 节点设备总数 ≥ 数据+校验分片数 {fragments}，当前只有 {object_devices}（无盘节点按 1 个目录设备计）。"
                        ),
                    );
                }
            }
            "erasure_coding" => error(
                errors,
                "ring",
                "ring.object_policy_type",
                "当前生成器暂不允许 EC；v3 共用 replicas 字段会把 EC 分片数错误套用到 account/container ring。",
            ),
            _ => error(
                errors,
                "ring",
                "ring.object_policy_type",
                "对象策略类型只能是 replication 或 erasure_coding。",
            ),
        }
    }

    /// Ring devices available to one role. The rust stack counts directory
    /// devices from `swift_devices` (default one `d1` per storage node).
    fn role_device_count(&self, role: &str) -> usize {
        self.nodes
            .iter()
            .filter(|node| has_effective_role(node, role))
            .map(|node| {
                if self.is_rust() {
                    rust_device_basenames(node).len()
                } else {
                    node.disks.len()
                }
            })
            .sum()
    }

    fn validate_auth(&self, errors: &mut Vec<ValidationIssue>) {
        let method = self.auth.method.as_str();
        if self.is_rust() {
            if method != "tempauth" {
                error(
                    errors,
                    "auth",
                    "auth.method",
                    "rust 栈默认 TempAuth；Keystone/authtoken 已在代理接线（ON-BY-CONFIG），但 bundle-rust 仍不部署 MariaDB/Keystone — 需外部 Identity，勿在 Contabo VIP 上切换。",
                );
            }
            if self.auth.interface != "swift" {
                error(
                    errors,
                    "auth",
                    "auth.interface",
                    "当前生成器只开放 Swift API；S3 尚未开放。",
                );
            }
            if self.tempauth_accounts.is_empty() {
                error(
                    errors,
                    "auth",
                    "tempauth_accounts",
                    "rust 栈至少需要一个 TempAuth 账户（account/user/key）。",
                );
            }
            for (index, account) in self.tempauth_accounts.iter().enumerate() {
                if !is_account_component(&account.account) {
                    error(
                        errors,
                        "auth",
                        &format!("tempauth_accounts[{index}].account"),
                        "TempAuth account 名不能为空或包含空白。",
                    );
                }
                if !is_account_component(&account.user) {
                    error(
                        errors,
                        "auth",
                        &format!("tempauth_accounts[{index}].user"),
                        "TempAuth 用户名不能为空或包含空白。",
                    );
                }
                validate_secret(
                    errors,
                    &format!("tempauth_accounts[{index}].key"),
                    &account.key,
                    12,
                );
            }
            if normalized_ingress_mode(&self.ingress.mode) == Some("haproxy") {
                if !is_account_component(&self.auth.haproxy_stats_user)
                    || self.auth.haproxy_stats_user == "admin"
                {
                    error(
                        errors,
                        "auth",
                        "auth.haproxy_stats_user",
                        "HAProxy stats 用户不能为空，且不能继续使用上游固定的 admin。",
                    );
                }
                validate_secret(
                    errors,
                    "auth.haproxy_stats_password",
                    &self.auth.haproxy_stats_password,
                    12,
                );
            }
            return;
        }
        if method != "keystone" {
            error(
                errors,
                "auth",
                "auth.method",
                "当前生成器只允许 Keystone；v3 的 TempAuth 账户配置未由 swift_cluster_accounts 正确驱动，已安全禁用。",
            );
        }
        if self.auth.interface != "swift" {
            error(
                errors,
                "auth",
                "auth.interface",
                "当前生成器只开放 Swift API；v3 的 S3 流程需要 EC2 access/secret 凭据，UI 尚未安全生成这些凭据。",
            );
        }
        if !is_account_component(&self.auth.account_name) {
            error(
                errors,
                "auth",
                "auth.account_name",
                "Swift account 名不能为空或包含空白。",
            );
        }
        if !is_account_component(&self.auth.admin_user)
            || matches!(self.auth.admin_user.as_str(), "swift" | "admin")
        {
            error(
                errors,
                "auth",
                "auth.admin_user",
                "管理员用户名不能为空，且不能使用 swift 或 admin。",
            );
        }
        validate_secret(errors, "auth.admin_password", &self.auth.admin_password, 12);
        if method == "keystone" {
            for (field, secret) in [
                (
                    "auth.mariadb_root_password",
                    &self.auth.mariadb_root_password,
                ),
                (
                    "auth.mariadb_keystone_password",
                    &self.auth.mariadb_keystone_password,
                ),
                (
                    "auth.mariadb_clustercheck_password",
                    &self.auth.mariadb_clustercheck_password,
                ),
                (
                    "auth.keystone_admin_password",
                    &self.auth.keystone_admin_password,
                ),
                (
                    "auth.keystone_swift_password",
                    &self.auth.keystone_swift_password,
                ),
            ] {
                validate_secret(errors, field, secret, 12);
            }
            if !is_account_component(&self.auth.haproxy_stats_user)
                || self.auth.haproxy_stats_user == "admin"
            {
                error(
                    errors,
                    "auth",
                    "auth.haproxy_stats_user",
                    "HAProxy stats 用户不能为空，且不能继续使用上游固定的 admin。",
                );
            }
            validate_secret(
                errors,
                "auth.haproxy_stats_password",
                &self.auth.haproxy_stats_password,
                12,
            );
            if !is_inventory_name(&self.auth.keystone_controller_hostname) {
                error(
                    errors,
                    "auth",
                    "auth.keystone_controller_hostname",
                    "Keystone controller 必须是安全的主机名。",
                );
            }
        }
    }

    fn validate_ingress(&self, errors: &mut Vec<ValidationIssue>) {
        let mode = normalized_ingress_mode(&self.ingress.mode);
        if mode.is_none() {
            error(
                errors,
                "ingress",
                "ingress.mode",
                "入口模式只能是 direct、haproxy 或 keepalived。",
            );
            return;
        }
        // rust stack: keepalived VIP is supported (bundle-rust rust_keepalived +
        // shared HMAC tempauth → HAProxy roundrobin). Same topology rules as
        // python-v3 apply below.
        //
        // P3-ops: rust TempAuth + HAProxy may terminate TLS (`http_mode=https`).
        // python-v3 Keystone bootstrap/endpoints remain HTTP-only.
        let http_mode = self.ingress.http_mode.as_str();
        if self.is_rust() {
            if http_mode != "http" && http_mode != "https" {
                error(
                    errors,
                    "ingress",
                    "ingress.http_mode",
                    "rust 栈 ingress.http_mode 只能是 http 或 https（HAProxy TLS 终止）。",
                );
            }
            if http_mode == "https" && mode == Some("direct") {
                error(
                    errors,
                    "ingress",
                    "ingress.http_mode",
                    "rust HTTPS 仅支持 HAProxy/Keepalived 终止；direct 模式请保持 http（proxy 本身不终结 TLS）。",
                );
            }
        } else if http_mode != "http" {
            error(
                errors,
                "ingress",
                "ingress.http_mode",
                "选定 v3 的 Keystone bootstrap、endpoint 与 proxy authtoken 均硬编码 HTTP；HTTPS 已在 python-v3 模式下禁用（rust 栈见 P3-ops HAProxy TLS）。",
            );
        }
        if self.ingress.auth_url_ip.parse::<Ipv4Addr>().is_err() {
            error(
                errors,
                "ingress",
                "ingress.auth_url_ip",
                "认证入口必须是单个 IPv4。",
            );
        }
        if self.ingress.swift_port == 0 {
            error(
                errors,
                "ingress",
                "ingress.swift_port",
                "Swift 入口端口不能为 0。",
            );
        }

        let haproxy = self
            .nodes
            .iter()
            .filter(|node| has_role(node, "haproxy"))
            .collect::<Vec<_>>();
        let keepalived = self
            .nodes
            .iter()
            .filter(|node| has_role(node, "keepalived"))
            .collect::<Vec<_>>();
        match mode.expect("mode was checked") {
            "direct" => {
                if self.auth.method == "keystone" {
                    error(
                        errors,
                        "ingress",
                        "ingress.mode",
                        "Keystone 模式不能使用 direct；当前 v3 的 Keystone 服务端点需要 HAProxy 入口。",
                    );
                }
                if !self.nodes.iter().any(|node| {
                    has_role(node, "proxy") && node.business_ip == self.ingress.auth_url_ip
                }) {
                    error(
                        errors,
                        "ingress",
                        "ingress.auth_url_ip",
                        "direct 模式的入口 IP 必须属于一台 proxy 节点的业务网络。",
                    );
                }
                if !haproxy.is_empty() || !keepalived.is_empty() {
                    error(
                        errors,
                        "ingress",
                        "nodes.roles",
                        "direct 模式不能包含 HAProxy/Keepalived 角色；请删除未使用的 HA 角色或切换入口模式。",
                    );
                }
            }
            "haproxy" => {
                if haproxy.is_empty() {
                    error(
                        errors,
                        "ingress",
                        "nodes.roles",
                        "haproxy 模式至少需要一台 haproxy 节点。",
                    );
                }
                if !haproxy
                    .iter()
                    .any(|node| node.business_ip == self.ingress.auth_url_ip)
                {
                    error(
                        errors,
                        "ingress",
                        "ingress.auth_url_ip",
                        "无 Keepalived 时入口 IP 必须属于一台 HAProxy 节点。",
                    );
                }
                if !keepalived.is_empty() {
                    error(
                        errors,
                        "ingress",
                        "nodes.roles",
                        "haproxy 模式不能包含 Keepalived 角色；若需要 VIP 请选择 keepalived 模式。",
                    );
                }
            }
            "keepalived" => {
                if haproxy.len() < 2 || keepalived.len() < 2 {
                    error(
                        errors,
                        "ingress",
                        "nodes.roles",
                        "Keepalived VIP 至少需要两台 HAProxy 和两台 Keepalived 节点。",
                    );
                }
                if haproxy.len() != keepalived.len() {
                    error(
                        errors,
                        "ingress",
                        "nodes.roles",
                        "Keepalived 模式下 HAProxy 与 Keepalived 必须配置在同一组节点上，不能保留额外 HAProxy 角色。",
                    );
                }
                let node_ips = self
                    .nodes
                    .iter()
                    .flat_map(|node| {
                        [
                            node.management_ip.as_str(),
                            node.storage_ip.as_str(),
                            node.replication_ip.as_str(),
                            node.business_ip.as_str(),
                        ]
                    })
                    .collect::<BTreeSet<_>>();
                if node_ips.contains(self.ingress.auth_url_ip.as_str()) {
                    error(
                        errors,
                        "ingress",
                        "ingress.auth_url_ip",
                        "Keepalived VIP 必须是未分配给节点的独立地址。",
                    );
                }
                if !(1..=32).contains(&self.ingress.vip_prefix) {
                    error(
                        errors,
                        "ingress",
                        "ingress.vip_prefix",
                        "VIP 前缀必须在 1 到 32 之间。",
                    );
                }
                if let Ok(vip) = self.ingress.auth_url_ip.parse::<Ipv4Addr>() {
                    for node in &keepalived {
                        if let Ok(business) = node.business_ip.parse::<Ipv4Addr>()
                            && !same_ipv4_subnet(vip, business, self.ingress.vip_prefix)
                        {
                            error(
                                errors,
                                "ingress",
                                "ingress.auth_url_ip",
                                &format!(
                                    "Keepalived VIP 必须与节点 {} 的业务网 IP 在 /{} 同一子网；真实同 L2 状态仍需部署前预检。",
                                    node.name, self.ingress.vip_prefix
                                ),
                            );
                        }
                    }
                }
                if self.ingress.virtual_router_id == 0 {
                    error(
                        errors,
                        "ingress",
                        "ingress.virtual_router_id",
                        "VRRP virtual_router_id 必须在 1 到 255 之间。",
                    );
                }
                validate_secret(
                    errors,
                    "ingress.vrrp_auth_pass",
                    &self.ingress.vrrp_auth_pass,
                    5,
                );
                if self.ingress.vrrp_auth_pass.len() > 8 {
                    error(
                        errors,
                        "ingress",
                        "ingress.vrrp_auth_pass",
                        "VRRP PASS 只使用前 8 个字符，必须填写 5 到 8 个字符。",
                    );
                }
                let mut priorities = BTreeSet::new();
                for node in keepalived {
                    let index = self
                        .nodes
                        .iter()
                        .position(|candidate| candidate.name == node.name)
                        .expect("node belongs to request");
                    if !has_role(node, "haproxy") {
                        error(
                            errors,
                            "ingress",
                            &format!("nodes[{index}].roles"),
                            "Keepalived 模式下每台 Keepalived 节点也必须承担 HAProxy 角色。",
                        );
                    }
                    if !is_interface_name(&node.keepalived_interface) {
                        error(
                            errors,
                            "ingress",
                            &format!("nodes[{index}].keepalived_interface"),
                            "Keepalived 节点必须填写实际网卡名。",
                        );
                    }
                    let Some(priority) = node.keepalived_priority else {
                        error(
                            errors,
                            "ingress",
                            &format!("nodes[{index}].keepalived_priority"),
                            "Keepalived 节点必须填写 1 到 255 的唯一优先级。",
                        );
                        continue;
                    };
                    if priority == 0 || priority > 255 {
                        error(
                            errors,
                            "ingress",
                            &format!("nodes[{index}].keepalived_priority"),
                            "Keepalived 优先级必须在 1 到 255 之间。",
                        );
                    } else if !priorities.insert(priority) {
                        error(
                            errors,
                            "ingress",
                            &format!("nodes[{index}].keepalived_priority"),
                            "Keepalived 优先级必须唯一。",
                        );
                    }
                }
            }
            _ => unreachable!("normalized ingress mode is exhaustive"),
        }
    }

    fn validate_saio(
        &self,
        errors: &mut Vec<ValidationIssue>,
        warnings: &mut Vec<ValidationIssue>,
    ) {
        if !self.saio {
            return;
        }
        if self.deployment_mode != "development" {
            error(
                errors,
                "project",
                "saio",
                "SAIO 必须与 development 模式一起使用。",
            );
        }
        if self.nodes.len() != 1 {
            error(errors, "topology", "nodes", "SAIO 只能配置一台节点。");
        }
        if let Some(node) = self.nodes.first() {
            let required: &[&str] = if self.is_rust() {
                &["proxy", "account", "container", "object"]
            } else {
                &[
                    "proxy",
                    "account",
                    "container",
                    "object",
                    "mariadb",
                    "keystone",
                ]
            };
            for role in required.iter().copied() {
                if !has_effective_role(node, role) {
                    error(
                        errors,
                        "topology",
                        "nodes[0].roles",
                        &format!("SAIO 单节点缺少 {role} 角色。"),
                    );
                }
            }
        }
        warning(
            warnings,
            "storage",
            "saio",
            "SAIO 仍会清空所列数据盘，只适用于可丢弃的实验节点。",
        );
    }

    fn summary(&self) -> WorkspaceSummary {
        let storage_nodes = self.nodes.iter().filter(|node| is_storage_node(node));
        let storage_node_count = storage_nodes.clone().count();
        let disk_count = storage_nodes.map(|node| node.disks.len()).sum();
        let regions = self
            .nodes
            .iter()
            .filter(|node| is_storage_node(node))
            .map(|node| node.region)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let zones = self
            .nodes
            .iter()
            .filter(|node| is_storage_node(node))
            .map(|node| node.zone)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        WorkspaceSummary {
            project_name: self.project_name.clone(),
            deployment_mode: self.deployment_mode.clone(),
            node_count: self.nodes.len(),
            storage_node_count,
            disk_count,
            regions,
            zones,
            replicas: self.ring.replicas,
            auth_method: self.auth.method.clone(),
            http_mode: self.ingress.http_mode.clone(),
            ingress_mode: normalized_ingress_mode(&self.ingress.mode)
                .unwrap_or(self.ingress.mode.as_str())
                .to_owned(),
        }
    }

    fn render_files(&self, bundle: &Path) -> Result<Vec<RenderedFile>> {
        let sample = bundle.join("config_sample");
        let sample_group_vars = sample.join("group_vars");
        if !sample_group_vars.is_dir() {
            bail!(
                "bundle is missing config_sample/group_vars: {}",
                bundle.display()
            );
        }
        if !bundle.join("swift.yml").is_file() {
            bail!("bundle is missing swift.yml: {}", bundle.display());
        }

        let mut files = Vec::new();
        files.push(RenderedFile {
            path: "swift_hosts".to_owned(),
            content: self.render_inventory(),
        });
        let mut nodes = self.nodes.iter().collect::<Vec<_>>();
        nodes.sort_by(|left, right| compare_management_ip(left, right));
        for node in nodes {
            files.push(RenderedFile {
                path: format!("host_vars/{}.yml", inventory_hostname(node)),
                content: self.render_host_vars(node)?,
            });
        }

        let overrides = BTreeSet::from([
            "all",
            "all.raw",
            "ring_config.yml",
            "proxy_servers",
            "haproxy_servers",
            "keepalived_servers",
        ]);
        let mut entries = fs::read_dir(&sample_group_vars)
            .with_context(|| format!("read sample group vars {}", sample_group_vars.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if overrides.contains(name.as_str())
                || matches!(
                    path.extension().and_then(|value| value.to_str()),
                    Some("py" | "sh")
                )
            {
                continue;
            }
            let lowered = name.to_ascii_lowercase();
            if self.is_rust() && (lowered.contains("keystone") || lowered.contains("mariadb")) {
                continue;
            }
            files.push(RenderedFile {
                path: format!("group_vars/{name}"),
                content: fs::read_to_string(&path)
                    .with_context(|| format!("read compatible group vars {}", path.display()))?,
            });
        }

        let sample_all_raw = sample_group_vars.join("all.raw");
        let (all_raw, compiled_all) = if self.is_rust() {
            (
                self.render_rust_all_raw(&sample_all_raw)?,
                self.render_rust_compiled_all(&sample_all_raw)?,
            )
        } else {
            (
                self.render_all_raw(&sample_all_raw)?,
                self.render_compiled_all(&sample_all_raw)?,
            )
        };
        files.push(RenderedFile {
            path: "group_vars/all.raw".to_owned(),
            content: all_raw,
        });
        files.push(RenderedFile {
            path: "group_vars/all".to_owned(),
            content: compiled_all,
        });
        files.push(RenderedFile {
            path: "group_vars/ring_config.yml".to_owned(),
            content: self.render_ring_config()?,
        });
        files.push(RenderedFile {
            path: "group_vars/proxy_servers".to_owned(),
            content: self.render_proxy_vars()?,
        });
        files.push(RenderedFile {
            path: "group_vars/haproxy_servers".to_owned(),
            content: self.render_haproxy_vars()?,
        });
        files.push(RenderedFile {
            path: "group_vars/keepalived_servers".to_owned(),
            content: self.render_keepalived_vars()?,
        });
        let mut node_metadata = self.nodes.iter().collect::<Vec<_>>();
        node_metadata.sort_by(|left, right| compare_management_ip(left, right));
        files.push(RenderedFile {
            path: ".swift-deploy-workspace.json".to_owned(),
            content: format!(
                "{}\n",
                serde_json::to_string_pretty(&json!({
                    "schema": 1,
                    "generator": "swift-deploy-rs",
                    "project": self.project_name,
                    "inventory": "swift_hosts",
                    "playbook": "swift.yml",
                    "nodes": node_metadata
                        .into_iter()
                        .map(|node| json!({
                            "label": node.name,
                            "inventory_hostname": inventory_hostname(node)
                        }))
                        .collect::<Vec<_>>()
                }))?
            ),
        });
        files.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(files)
    }

    fn render_inventory(&self) -> String {
        let mut nodes = self.nodes.iter().collect::<Vec<_>>();
        nodes.sort_by(|left, right| compare_management_ip(left, right));
        let mut output =
            String::from("# Generated by swift-deploy-rs. Review before Apply.\n[all]\n");
        for node in &nodes {
            output.push_str(&format!(
                "{} ansible_host={} ansible_user={} ansible_port={} ansible_ssh_private_key_file={}\n",
                inventory_hostname(node),
                inventory_quote(&node.address),
                inventory_quote(&node.ssh_user),
                node.ssh_port,
                inventory_quote(&node.ssh_key_file)
            ));
        }

        let explicit_ntp = nodes
            .iter()
            .filter(|node| has_role(node, "ntp_server"))
            .map(|node| inventory_hostname(node))
            .collect::<Vec<_>>();
        let ntp_server = explicit_ntp
            .first()
            .copied()
            .or_else(|| nodes.first().map(|node| inventory_hostname(node)));
        append_group(
            &mut output,
            "ntp_server",
            ntp_server.into_iter().collect::<Vec<_>>(),
        );
        append_group(
            &mut output,
            "ntp_clients",
            nodes
                .iter()
                .map(|node| inventory_hostname(node))
                .filter(|name| Some(*name) != ntp_server)
                .collect(),
        );
        append_proxy_group(&mut output, &nodes, &self.ingress.http_mode);
        for (group, role) in [
            ("account_servers", "account"),
            ("container_servers", "container"),
            ("object_servers", "object"),
        ] {
            append_group(
                &mut output,
                group,
                nodes
                    .iter()
                    .filter(|node| has_effective_role(node, role))
                    .map(|node| inventory_hostname(node))
                    .collect(),
            );
        }
        output.push_str("\n[swift_nodes:children]\nproxy_servers\naccount_servers\ncontainer_servers\nobject_servers\n");
        output.push_str(
            "\n[storage_nodes:children]\naccount_servers\ncontainer_servers\nobject_servers\n",
        );
        for (group, role) in [
            ("mariadb_servers", "mariadb"),
            ("keystones", "keystone"),
            ("haproxy_servers", "haproxy"),
        ] {
            append_group(
                &mut output,
                group,
                nodes
                    .iter()
                    .filter(|node| has_role(node, role))
                    .map(|node| inventory_hostname(node))
                    .collect(),
            );
        }
        append_keepalived_group(&mut output, &nodes);
        append_group(
            &mut output,
            "format_disk_servers",
            nodes
                .iter()
                .filter(|node| is_storage_node(node) && !node.disks.is_empty())
                .map(|node| inventory_hostname(node))
                .collect(),
        );
        append_group(&mut output, "proxyfs", Vec::new());
        append_group(
            &mut output,
            "performance_tuning",
            nodes
                .iter()
                .filter(|node| has_role(node, "performance_tuning"))
                .map(|node| inventory_hostname(node))
                .collect(),
        );
        append_group(&mut output, "add_new_disk_servers", Vec::new());
        output
    }

    fn render_host_vars(&self, node: &Node) -> Result<String> {
        let system = normalized_system_disk(&node.system_disk)
            .map(|device| format!("/dev/{device}"))
            .unwrap_or_default();
        let mut value = json!({
            "management_network_address": node.management_ip,
            "storage_network_address": node.storage_ip,
            "replication_network_address": self.effective_replication_ip(node),
            "business_network_address": node.business_ip,
            "keystone_node": has_role(node, "keystone"),
            "mariadb_node": has_role(node, "mariadb"),
            "custom_disks": node.disks,
            "disk_type": node.disk_type,
            "exclude_disks": [system]
        });
        if self.is_rust() {
            let map = value
                .as_object_mut()
                .context("host_vars root must be a mapping")?;
            map.insert("region".to_owned(), json!(node.region));
            map.insert("zone".to_owned(), json!(node.zone));
            map.insert("swift_devices".to_owned(), json!(rust_device_basenames(node)));
        }
        yaml_document(&value)
    }

    fn render_all_raw(&self, sample: &Path) -> Result<String> {
        let content = fs::read_to_string(sample)
            .with_context(|| format!("read sample all.raw {}", sample.display()))?;
        let mut root: Value = serde_yaml_ng::from_str(&content)
            .with_context(|| format!("parse sample all.raw {}", sample.display()))?;
        let values = root
            .as_object_mut()
            .context("sample all.raw must be a mapping")?;
        let ntp = selected_ntp_server(&self.nodes)
            .map(|node| node.management_ip.clone())
            .unwrap_or_default();
        let (hash_prefix, hash_suffix, auth_salt) = self.derived_swift_secrets();
        let use_lb = normalized_ingress_mode(&self.ingress.mode) != Some("direct");
        let mariadb_port = if use_lb { 3030 } else { 3306 };
        for (key, value) in [
            ("INSTALL_MODE", json!(self.deployment_mode)),
            ("SAIO", json!(self.saio)),
            ("REINSTALL", json!(false)),
            ("USE_WWID", json!(self.use_wwid)),
            ("ADD_NODES", json!(false)),
            ("use_custom_disks", json!(true)),
            ("install_proxyfs", json!(false)),
            ("proxyfs_public_ip_addr", json!("127.0.0.1")),
            ("proxyfs_private_ip_addr", json!("127.0.0.1")),
            ("proxyfs_swift_accounts", json!([])),
            (
                "ntp_internet_server_address",
                json!(self.ntp_internet_server),
            ),
            ("ntp_local_server_address", json!(ntp)),
            ("local_repo_address", json!(self.local_repo_address)),
            ("timezone", json!(self.timezone)),
            ("hostname_modifiable", json!(self.hostname_modifiable)),
            ("hostname_prefix", json!(self.hostname_prefix)),
            ("swift_hash_path_prefix", json!(hash_prefix)),
            ("swift_hash_path_suffix", json!(hash_suffix)),
            ("auth_type_salt", json!(auth_salt)),
            ("super_admin_password", json!(self.auth.admin_password)),
            ("firewall_type", json!("iptables")),
            ("ssh_bind_port", json!(self.ssh_bind_port)),
            ("admin_ips", json!(self.admin_ips)),
            ("use_local_mariadbs", json!(true)),
            (
                "mariadb_host",
                json!(self.auth.keystone_controller_hostname),
            ),
            (
                "mariadb_root_password",
                json!(self.auth.mariadb_root_password),
            ),
            (
                "mariadb_keystone_pass",
                json!(self.auth.mariadb_keystone_password),
            ),
            ("mariadb_clustercheck_user", json!("clustercheckuser")),
            (
                "mariadb_clustercheck_password",
                json!(self.auth.mariadb_clustercheck_password),
            ),
            ("keystone_endpoint_ip", json!(self.ingress.auth_url_ip)),
            ("keystone_public_interface", json!(self.auth.interface)),
            (
                "keystone_endpoint_controller_hostname",
                json!(self.auth.keystone_controller_hostname),
            ),
            ("keystone_used_mariadb_port", json!(mariadb_port)),
            (
                "keystone_admin_password",
                json!(self.auth.keystone_admin_password),
            ),
            (
                "keystone_swift_password",
                json!(self.auth.keystone_swift_password),
            ),
            ("use_lb", json!(use_lb)),
            ("lb_mode", json!(self.ingress.http_mode)),
            ("auth_url_ip", json!(self.ingress.auth_url_ip)),
            ("haproxy_storage_port", json!(self.ingress.swift_port)),
            ("swift_lb_port", json!(self.ingress.swift_port)),
            ("haproxy_stats_user", json!(self.auth.haproxy_stats_user)),
            (
                "haproxy_stats_password",
                json!(self.auth.haproxy_stats_password),
            ),
            (
                "swift_cluster_accounts",
                json!([{
                    "account_name": self.auth.account_name,
                    "super_users": {
                        self.auth.admin_user.clone(): self.auth.admin_password
                    }
                }]),
            ),
            ("ec2_credentials", json!([])),
        ] {
            values.insert(key.to_owned(), value);
        }
        yaml_document(&root)
    }

    /// Rust-stack `group_vars/all.raw`: sample pass-through plus the rust
    /// variable contract; keystone/mariadb variables are removed.
    fn render_rust_all_raw(&self, sample: &Path) -> Result<String> {
        let content = fs::read_to_string(sample)
            .with_context(|| format!("read sample all.raw {}", sample.display()))?;
        let mut root: Value = serde_yaml_ng::from_str(&content)
            .with_context(|| format!("parse sample all.raw {}", sample.display()))?;
        let values = root
            .as_object_mut()
            .context("sample all.raw must be a mapping")?;
        values.retain(|key, _| {
            let lowered = key.to_ascii_lowercase();
            !lowered.contains("mariadb") && !lowered.contains("keystone")
        });
        let ntp = selected_ntp_server(&self.nodes)
            .map(|node| node.management_ip.clone())
            .unwrap_or_default();
        let (hash_prefix, hash_suffix, auth_salt) = self.derived_swift_secrets();
        let use_lb = normalized_ingress_mode(&self.ingress.mode) != Some("direct");
        for (key, value) in [
            ("deploy_stack", json!("rust")),
            ("INSTALL_MODE", json!(self.deployment_mode)),
            ("SAIO", json!(self.saio)),
            ("timezone", json!(self.timezone)),
            (
                "ntp_internet_server_address",
                json!(self.ntp_internet_server),
            ),
            ("ntp_local_server_address", json!(ntp)),
            ("hostname_modifiable", json!(self.hostname_modifiable)),
            ("hostname_prefix", json!(self.hostname_prefix)),
            ("admin_ips", json!(self.admin_ips)),
            ("ssh_bind_port", json!(self.ssh_bind_port)),
            ("swift_hash_path_prefix", json!(hash_prefix)),
            ("swift_hash_path_suffix", json!(hash_suffix)),
            ("auth_type_salt", json!(auth_salt)),
            ("auth_method", json!("tempauth")),
            ("swift_tempauth_users", self.rust_tempauth_users()),
            ("proxy_bind_port", json!(8080)),
            ("account_bind_port", json!(6202)),
            ("container_bind_port", json!(6201)),
            ("object_bind_port", json!(6200)),
            ("object_port_per_device", json!(true)),
            ("object_servers_per_port", json!(0)),
            ("srv_node_root", json!("/srv/node")),
            (
                "ring_fetch_dir",
                json!(format!(
                    "/var/lib/swift-deploy/rings/{}",
                    project_slug(&self.project_name)
                )),
            ),
            ("object_workers", json!(0)),
            ("swift_policies", self.rust_policies()),
            ("swift_device_weight", json!(self.ring.device_weight)),
            (
                "account_swift_partition_power",
                json!(self.ring.partition_power),
            ),
            ("account_swift_replicas", json!(self.ring.replicas)),
            ("account_swift_minimum_time", json!(self.ring.minimum_time)),
            (
                "container_swift_partition_power",
                json!(self.ring.partition_power),
            ),
            ("container_swift_replicas", json!(self.ring.replicas)),
            (
                "container_swift_minimum_time",
                json!(self.ring.minimum_time),
            ),
            ("use_lb", json!(use_lb)),
            ("lb_mode", json!(self.ingress.http_mode)),
            ("auth_url_ip", json!(self.ingress.auth_url_ip)),
            ("swift_lb_port", json!(self.ingress.swift_port)),
            ("haproxy_stats_user", json!(self.auth.haproxy_stats_user)),
            (
                "haproxy_stats_password",
                json!(self.auth.haproxy_stats_password),
            ),
            // P3-ops TLS defaults (self-signed lab when https; override via
            // haproxy_tls_pem_src for production PEMs).
            ("haproxy_tls_self_signed", json!(true)),
            ("haproxy_tls_days", json!(825)),
            ("haproxy_tls_pem", json!("/etc/haproxy/haproxyCA.pem")),
            ("haproxy_tls_pem_src", json!("")),
            // Expand mode is opt-in via expand.yml set_fact or group_vars.
            ("ring_expand", json!(false)),
            ("ADD_NODES", json!(false)),
            ("ring_force_rebuild", json!(false)),
        ] {
            values.insert(key.to_owned(), value);
        }
        yaml_document(&root)
    }

    /// Rust-stack `group_vars/all`: the raw contract plus compiled address lists.
    fn render_rust_compiled_all(&self, sample: &Path) -> Result<String> {
        let raw = self.render_rust_all_raw(sample)?;
        let mut root: Value = serde_yaml_ng::from_str(&raw)
            .context("parse generated rust all.raw for compilation")?;
        let values = root
            .as_object_mut()
            .context("generated rust all.raw must be a mapping")?;
        for (key, value) in [
            (
                "management_network_addresses",
                json!(
                    self.nodes
                        .iter()
                        .map(|node| node.management_ip.clone())
                        .collect::<Vec<_>>()
                ),
            ),
            (
                "storage_network_addresses",
                json!(
                    self.nodes
                        .iter()
                        .map(|node| node.storage_ip.clone())
                        .collect::<Vec<_>>()
                ),
            ),
            (
                "proxy_storage_network_addresses",
                json!(
                    self.nodes
                        .iter()
                        .filter(|node| has_role(node, "proxy"))
                        .map(|node| node.storage_ip.clone())
                        .collect::<Vec<_>>()
                ),
            ),
            (
                "business_network_addresses",
                json!(
                    self.nodes
                        .iter()
                        .map(|node| node.business_ip.clone())
                        .collect::<Vec<_>>()
                ),
            ),
        ] {
            values.insert(key.to_owned(), value);
        }
        yaml_document(&root)
    }

    fn rust_tempauth_users(&self) -> Value {
        Value::Array(
            self.tempauth_accounts
                .iter()
                .enumerate()
                .map(|(index, account)| {
                    json!({
                        "account": account.account,
                        "user": account.user,
                        "key": account.key,
                        "admin": index == 0
                    })
                })
                .collect(),
        )
    }

    /// Storage policies for the rust stack: replication policy at index 0 is
    /// always present and default; an EC policy is appended when selected.
    fn rust_policies(&self) -> Value {
        let mut policies = vec![json!({
            "index": 0,
            "name": self.ring.object_policy_name,
            "type": "replication",
            "partition_power": self.ring.partition_power,
            "replicas": self.ring.replicas,
            "min_part_hours": self.ring.minimum_time,
            "default": true
        })];
        if self.ring.object_policy_type == "erasure_coding" {
            let data = self.ring.ec_data_fragments.unwrap_or(0);
            let parity = self.ring.ec_parity_fragments.unwrap_or(0);
            policies.push(json!({
                "index": 1,
                "name": format!("EC-{data}-{parity}"),
                "type": "erasure_coding",
                "partition_power": self.ring.partition_power,
                "replicas": data + parity,
                "min_part_hours": self.ring.minimum_time,
                "ec_type": "liberasurecode_rs_vand",
                "ec_data": data,
                "ec_parity": parity,
                "ec_segment_size": self.ring.ec_segment_size
            }));
        }
        Value::Array(policies)
    }

    fn render_ring_config(&self) -> Result<String> {
        let account_nodes = self.ring_content("account", 6002);
        let container_nodes = self.ring_content("container", 6001);
        let object_nodes = self.ring_content("object", 6000);
        let mut policy = Map::new();
        policy.insert("name".to_owned(), json!(self.ring.object_policy_name));
        policy.insert("aliases".to_owned(), json!(self.ring.object_policy_name));
        policy.insert("default".to_owned(), json!("yes"));
        policy.insert(
            "policy_type".to_owned(),
            json!(self.ring.object_policy_type),
        );
        if self.ring.object_policy_type == "erasure_coding" {
            policy.insert("ec_type".to_owned(), json!("liberasurecode_rs_vand"));
            policy.insert(
                "ec_num_data_fragments".to_owned(),
                json!(self.ring.ec_data_fragments),
            );
            policy.insert(
                "ec_num_parity_fragments".to_owned(),
                json!(self.ring.ec_parity_fragments),
            );
            policy.insert(
                "ec_object_segment_size".to_owned(),
                json!(self.ring.ec_segment_size),
            );
        }
        let root = json!({
            "account_ring": {
                "create_ring_info": {
                    "account_swift_partition_power": self.ring.partition_power,
                    "account_swift_replicas": self.ring.replicas,
                    "account_swift_minimum_time": self.ring.minimum_time
                },
                "ring_content": account_nodes
            },
            "container_ring": {
                "create_ring_info": {
                    "container_swift_partition_power": self.ring.partition_power,
                    "container_swift_replicas": self.ring.replicas,
                    "container_swift_minimum_time": self.ring.minimum_time
                },
                "ring_content": container_nodes
            },
            "object_rings": [{
                "create_ring_info": {
                    "builder_name": "object",
                    "object_swift_partition_power": self.ring.partition_power,
                    "object_swift_replicas": self.ring.replicas,
                    "object_swift_minimum_time": self.ring.minimum_time
                },
                "policy": Value::Object(policy),
                "ring_content": object_nodes
            }]
        });
        yaml_document(&root)
    }

    fn render_compiled_all(&self, sample: &Path) -> Result<String> {
        let raw = self.render_all_raw(sample)?;
        let mut root: Value =
            serde_yaml_ng::from_str(&raw).context("parse generated all.raw for compilation")?;
        let values = root
            .as_object_mut()
            .context("generated all.raw must be a mapping")?;

        let account_nodes = self.compiled_ring_nodes("account", 6002);
        let container_nodes = self.compiled_ring_nodes("container", 6001);
        let object_nodes = self.compiled_ring_nodes("object", 6000);
        let mut policy = Map::new();
        policy.insert("name".to_owned(), json!(self.ring.object_policy_name));
        policy.insert("aliases".to_owned(), json!(self.ring.object_policy_name));
        policy.insert("default".to_owned(), json!("yes"));
        policy.insert(
            "policy_type".to_owned(),
            json!(self.ring.object_policy_type),
        );
        if self.ring.object_policy_type == "erasure_coding" {
            policy.insert("ec_type".to_owned(), json!("liberasurecode_rs_vand"));
            policy.insert(
                "ec_num_data_fragments".to_owned(),
                json!(self.ring.ec_data_fragments),
            );
            policy.insert(
                "ec_num_parity_fragments".to_owned(),
                json!(self.ring.ec_parity_fragments),
            );
            policy.insert(
                "ec_object_segment_size".to_owned(),
                json!(self.ring.ec_segment_size),
            );
        }

        for (key, value) in [
            (
                "account_swift_partition_power",
                json!(self.ring.partition_power),
            ),
            ("account_swift_replicas", json!(self.ring.replicas)),
            ("account_swift_minimum_time", json!(self.ring.minimum_time)),
            (
                "container_swift_partition_power",
                json!(self.ring.partition_power),
            ),
            ("container_swift_replicas", json!(self.ring.replicas)),
            (
                "container_swift_minimum_time",
                json!(self.ring.minimum_time),
            ),
            ("account_ring", Value::Array(account_nodes)),
            ("container_ring", Value::Array(container_nodes)),
            ("policies", Value::Array(vec![Value::Object(policy)])),
            (
                "object_rings",
                json!([{
                    "name": "object",
                    "nodes": object_nodes,
                    "object_swift_partition_power": self.ring.partition_power,
                    "object_swift_replicas": self.ring.replicas,
                    "object_swift_minimum_time": self.ring.minimum_time
                }]),
            ),
            (
                "management_network_addresses",
                json!(
                    self.nodes
                        .iter()
                        .map(|node| node.management_ip.clone())
                        .collect::<Vec<_>>()
                ),
            ),
            (
                "storage_network_addresses",
                json!(
                    self.nodes
                        .iter()
                        .map(|node| node.storage_ip.clone())
                        .collect::<Vec<_>>()
                ),
            ),
            (
                "proxy_storage_network_addresses",
                json!(
                    self.nodes
                        .iter()
                        .filter(|node| has_role(node, "proxy"))
                        .map(|node| node.storage_ip.clone())
                        .collect::<Vec<_>>()
                ),
            ),
            (
                "business_network_addresses",
                json!(
                    self.nodes
                        .iter()
                        .map(|node| node.business_ip.clone())
                        .collect::<Vec<_>>()
                ),
            ),
            (
                "keystone_storage_network_addresses",
                json!(
                    self.nodes
                        .iter()
                        .filter(|node| has_role(node, "keystone"))
                        .map(|node| node.storage_ip.clone())
                        .collect::<Vec<_>>()
                ),
            ),
            (
                "mariadb_storage_network_addresses",
                json!(
                    self.nodes
                        .iter()
                        .filter(|node| has_role(node, "mariadb"))
                        .map(|node| node.storage_ip.clone())
                        .collect::<Vec<_>>()
                ),
            ),
            (
                "business_network_public_ports",
                json!([5000, 35357, self.ingress.swift_port, 443]),
            ),
            ("business_network_private_ports", json!([8080, 3030])),
            (
                "storage_network_ports",
                json!([
                    6002, 6001, 6000, 873, 11211, 3306, 9600, 4444, 4567, 4568, 35358, 5001
                ]),
            ),
            (
                "management_network_public_ports",
                json!([1080, self.ssh_bind_port, 22, 5601, 3000, 19088]),
            ),
            (
                "management_network_private_ports",
                json!([80, 514, 123, 323, 9200, 5044, 10050, 10051, 18088]),
            ),
        ] {
            values.insert(key.to_owned(), value);
        }
        yaml_document(&root)
    }

    fn ring_content(&self, role: &str, port: u16) -> Vec<Value> {
        let mut nodes = self
            .nodes
            .iter()
            .filter(|node| has_effective_role(node, role))
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.name.cmp(&right.name));
        nodes
            .into_iter()
            .map(|node| {
                let range = format!("001-{:03}", node.disks.len());
                let (hdd, ssd) = if node.disk_type == "hdd" {
                    (range, String::new())
                } else {
                    (String::new(), range)
                };
                let devices = serde_json::to_string(&json!({"hdd": hdd, "ssd": ssd}))
                    .expect("disk JSON contains only strings");
                json!({
                    "region": node.region,
                    "zone": node.zone,
                    "storage_ips": node.storage_ip,
                    "replication_ips": self.effective_replication_ip(node),
                    "common_disk_info": [format!("{port}_{devices}_{}", self.ring.device_weight)],
                    "dedicated_disk_info": []
                })
            })
            .collect()
    }

    fn compiled_ring_nodes(&self, role: &str, port: u16) -> Vec<Value> {
        let mut nodes = self
            .nodes
            .iter()
            .filter(|node| has_effective_role(node, role))
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.name.cmp(&right.name));
        nodes
            .into_iter()
            .flat_map(|node| {
                node.disks.iter().enumerate().map(move |(index, _disk)| {
                    json!({
                        "region": node.region,
                        "zone": node.zone,
                        "storage_ip": node.storage_ip,
                        "replication_ip": self.effective_replication_ip(node),
                        "port": port,
                        "device": format!("{}{:03}", node.disk_type, index + 1),
                        "weight": self.ring.device_weight
                    })
                })
            })
            .collect()
    }

    fn render_proxy_vars(&self) -> Result<String> {
        yaml_document(&json!({
            "auth_method": self.auth.method,
            "tempauth_pipeline": "catch_errors gatekeeper healthcheck proxy-logging cache cname_lookup domain_remap listing_formats container_sync bulk tempurl list-endpoints ratelimit formpost tempauth read_only staticweb container-quotas account-quotas slo dlo versioned_writes proxy-logging proxy-server",
            "keystone_pipeline": "catch_errors gatekeeper healthcheck proxy-logging cache cname_lookup domain_remap listing_formats container_sync bulk tempurl list-endpoints ratelimit formpost authtoken keystoneauth read_only copy staticweb container-quotas account-quotas slo dlo versioned_writes proxy-logging proxy-server",
            "account_autocreate": "true",
            "data_encryption": false,
            "encryption_root_secret": "",
            "INTERFACE": self.auth.interface
        }))
    }

    fn render_haproxy_vars(&self) -> Result<String> {
        let mut proxies = self
            .nodes
            .iter()
            .filter(|node| has_role(node, "proxy"))
            .collect::<Vec<_>>();
        proxies.sort_by(|left, right| left.name.cmp(&right.name));
        let nodes = proxies
            .into_iter()
            .map(|node| {
                json!({
                    "proxy_server_ip": node.business_ip,
                    "port": "{{ proxy_server_bind_port }}",
                    "weight": self.ring.device_weight,
                    "maxconn": 6000
                })
            })
            .collect::<Vec<_>>();
        yaml_document(&json!({
            "back_apps": {
                "name_prefix": "proxy_",
                "nodes": nodes
            }
        }))
    }

    fn render_keepalived_vars(&self) -> Result<String> {
        yaml_document(&json!({
            "vip_prefix": self.ingress.vip_prefix,
            "keepalived_vrrp_script": {
                "name": "chk_http_port",
                "interval": 1,
                "weight": -10
            },
            "keepalived_mode": "nopreempt",
            "keepalived_servers": {
                "vrrp_instance": {
                    "virtual_router_id": self.ingress.virtual_router_id,
                    "advert_int": 1,
                    "auth_pass": self.ingress.vrrp_auth_pass
                }
            }
        }))
    }

    fn derived_swift_secrets(&self) -> (String, String, String) {
        let mut hasher = Sha256::new();
        for value in [
            self.project_name.as_str(),
            self.auth.admin_password.as_str(),
            self.auth.keystone_admin_password.as_str(),
            self.auth.mariadb_root_password.as_str(),
        ] {
            hasher.update(value.as_bytes());
            hasher.update([0]);
        }
        for account in &self.tempauth_accounts {
            hasher.update(account.key.as_bytes());
            hasher.update([0]);
        }
        let digest = hex::encode(hasher.finalize());
        (
            digest[0..16].to_owned(),
            digest[16..32].to_owned(),
            digest[32..56].to_owned(),
        )
    }

    fn redacted_files(&self, rendered: &[RenderedFile]) -> Vec<WorkspaceFile> {
        let (hash_prefix, hash_suffix, auth_salt) = self.derived_swift_secrets();
        let mut secrets = vec![
            self.auth.admin_password.as_str(),
            self.auth.mariadb_root_password.as_str(),
            self.auth.mariadb_keystone_password.as_str(),
            self.auth.mariadb_clustercheck_password.as_str(),
            self.auth.keystone_admin_password.as_str(),
            self.auth.keystone_swift_password.as_str(),
            self.auth.haproxy_stats_password.as_str(),
            self.ingress.vrrp_auth_pass.as_str(),
            hash_prefix.as_str(),
            hash_suffix.as_str(),
            auth_salt.as_str(),
        ];
        secrets.extend(
            self.tempauth_accounts
                .iter()
                .map(|account| account.key.as_str()),
        );
        rendered
            .iter()
            .map(|file| {
                let mut content = file.content.clone();
                for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
                    content = content.replace(secret, "<redacted>");
                }
                WorkspaceFile {
                    path: file.path.clone(),
                    content,
                }
            })
            .collect()
    }
}

fn error(errors: &mut Vec<ValidationIssue>, step: &str, field: &str, message: &str) {
    errors.push(ValidationIssue {
        step: step.to_owned(),
        field: field.to_owned(),
        message: message.to_owned(),
    });
}

fn warning(warnings: &mut Vec<ValidationIssue>, step: &str, field: &str, message: &str) {
    warnings.push(ValidationIssue {
        step: step.to_owned(),
        field: field.to_owned(),
        message: message.to_owned(),
    });
}

fn canonical_role(role: &str) -> Option<&'static str> {
    match role.trim().to_ascii_lowercase().as_str() {
        "proxy" | "proxy_server" | "proxy_servers" => Some("proxy"),
        "storage" | "storage_node" | "storage_nodes" => Some("storage"),
        "account" | "account_server" | "account_servers" => Some("account"),
        "container" | "container_server" | "container_servers" => Some("container"),
        "object" | "object_server" | "object_servers" => Some("object"),
        "mariadb" | "mariadb_server" | "mariadb_servers" => Some("mariadb"),
        "keystone" | "keystones" => Some("keystone"),
        "haproxy" | "haproxy_server" | "haproxy_servers" => Some("haproxy"),
        "keepalived" | "keepalived_server" | "keepalived_servers" => Some("keepalived"),
        "ntp_server" => Some("ntp_server"),
        "ntp_client" | "ntp_clients" => Some("ntp_client"),
        "format_disk" | "format_disk_server" | "format_disk_servers" => Some("format_disk"),
        "performance_tuning" => Some("performance_tuning"),
        _ => None,
    }
}

fn has_role(node: &Node, role: &str) -> bool {
    node.roles
        .iter()
        .filter_map(|candidate| canonical_role(candidate))
        .any(|candidate| candidate == role)
}

fn has_effective_role(node: &Node, role: &str) -> bool {
    has_role(node, role)
        || (has_role(node, "storage") && matches!(role, "account" | "container" | "object"))
}

/// Safe directory device basenames for the rust stack (no wipe path).
fn is_safe_swift_device(device: &str) -> bool {
    let trimmed = device.trim();
    !trimmed.is_empty()
        && !trimmed.contains('/')
        && !trimmed.contains('\\')
        && !trimmed.contains("..")
        && !trimmed.contains(char::is_whitespace)
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
}

fn rust_device_basenames(node: &Node) -> Vec<String> {
    if node.swift_devices.is_empty() {
        vec!["d1".to_owned()]
    } else {
        node.swift_devices.clone()
    }
}

fn is_storage_node(node: &Node) -> bool {
    ["account", "container", "object"]
        .into_iter()
        .any(|role| has_effective_role(node, role))
}

fn inventory_hostname(node: &Node) -> &str {
    node.management_ip.as_str()
}

fn normalized_ingress_mode(mode: &str) -> Option<&'static str> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "direct" => Some("direct"),
        "haproxy" => Some("haproxy"),
        "keepalived" | "vip" => Some("keepalived"),
        _ => None,
    }
}

fn is_inventory_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        && value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
}

fn is_hostname_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn is_connection_address(value: &str) -> bool {
    !value.is_empty()
        && !value.chars().any(char::is_whitespace)
        && !value.contains([';', '`', '$', '\n', '\r'])
}

fn is_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | ':')
        })
}

fn is_account_component(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 128
        && !value.chars().any(char::is_whitespace)
        && !value.contains([':', '\n', '\r'])
}

fn normalized_disk(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if !trimmed.starts_with("/dev/")
        || trimmed.contains("..")
        || trimmed.contains([';', '`', '$', '\n', '\r'])
        || trimmed.chars().any(char::is_whitespace)
    {
        return None;
    }
    let remainder = trimmed.strip_prefix("/dev/")?;
    if remainder.is_empty()
        || remainder.starts_with('/')
        || !remainder
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/._-".contains(character))
    {
        return None;
    }
    Some(remainder.to_owned())
}

fn normalized_system_disk(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.starts_with("/dev/") {
        return normalized_disk(trimmed);
    }
    if trimmed.is_empty()
        || trimmed.contains("..")
        || trimmed.contains(['/', ';', '`', '$', '\n', '\r'])
        || trimmed.chars().any(char::is_whitespace)
        || !trimmed
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return None;
    }
    Some(trimmed.to_owned())
}

fn validate_secret(
    errors: &mut Vec<ValidationIssue>,
    field: &str,
    secret: &str,
    minimum_length: usize,
) {
    let normalized = secret.trim().to_ascii_lowercase();
    let placeholders = [
        "password",
        "changeme",
        "change-me",
        "change_me",
        "secret",
        "testing",
        "123456",
        "11111",
        "xxxxx",
    ];
    let safe_ascii = secret
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "._~-".contains(character));
    if secret.len() < minimum_length
        || !safe_ascii
        || placeholders.contains(&normalized.as_str())
        || normalized.starts_with("enter ")
        || normalized.contains("please set")
        || normalized.contains("placeholder")
        || normalized.contains("replace_me")
        || (normalized.starts_with('<') && normalized.ends_with('>'))
    {
        error(
            errors,
            "auth",
            field,
            &format!(
                "必须填写至少 {minimum_length} 个字符的真实密钥，只允许 ASCII 字母、数字及 . _ ~ -，不能使用示例占位值。"
            ),
        );
    }
}

fn selected_ntp_server(nodes: &[Node]) -> Option<&Node> {
    let mut explicit = nodes
        .iter()
        .filter(|node| has_role(node, "ntp_server"))
        .collect::<Vec<_>>();
    explicit.sort_by(|left, right| compare_management_ip(left, right));
    if let Some(node) = explicit.first() {
        return Some(node);
    }
    nodes
        .iter()
        .min_by(|left, right| compare_management_ip(left, right))
}

fn compare_management_ip(left: &Node, right: &Node) -> Ordering {
    match (
        left.management_ip.parse::<Ipv4Addr>(),
        right.management_ip.parse::<Ipv4Addr>(),
    ) {
        (Ok(left), Ok(right)) => u32::from(left).cmp(&u32::from(right)),
        _ => left.management_ip.cmp(&right.management_ip),
    }
}

fn same_ipv4_subnet(left: Ipv4Addr, right: Ipv4Addr, prefix: u8) -> bool {
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    (u32::from(left) & mask) == (u32::from(right) & mask)
}

fn project_slug(name: &str) -> String {
    let mut output = String::new();
    let mut separator = false;
    for character in name.trim().chars() {
        if character.is_ascii_alphanumeric() {
            if separator && !output.is_empty() {
                output.push('-');
            }
            output.push(character.to_ascii_lowercase());
            separator = false;
        } else {
            separator = true;
        }
        if output.len() >= 48 {
            break;
        }
    }
    while output.ends_with('-') {
        output.pop();
    }
    if output.is_empty() {
        let digest = Sha256::digest(name.as_bytes());
        return format!("swift-{}", &hex::encode(digest)[..12]);
    }
    output
}

fn inventory_quote(value: &str) -> String {
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "/._:@+-".contains(character))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn append_group(output: &mut String, group: &str, hosts: Vec<&str>) {
    output.push_str(&format!("\n[{group}]\n"));
    for host in hosts {
        output.push_str(host);
        output.push('\n');
    }
}

fn append_proxy_group(output: &mut String, nodes: &[&Node], http_mode: &str) {
    output.push_str("\n[proxy_servers]\n");
    for node in nodes.iter().filter(|node| has_role(node, "proxy")) {
        output.push_str(&format!(
            "{} proxy_mode={}\n",
            inventory_hostname(node),
            http_mode
        ));
    }
}

fn append_keepalived_group(output: &mut String, nodes: &[&Node]) {
    output.push_str("\n[keepalived_servers]\n");
    for node in nodes.iter().filter(|node| has_role(node, "keepalived")) {
        output.push_str(inventory_hostname(node));
        output.push_str(&format!(
            " keepalived_interface={} keepalived_priority={}\n",
            inventory_quote(&node.keepalived_interface),
            node.keepalived_priority.unwrap_or_default()
        ));
    }
}

fn yaml_document(value: &Value) -> Result<String> {
    let body = serde_yaml_ng::to_string(value).context("serialize generated YAML")?;
    Ok(if body.starts_with("---") {
        body
    } else {
        format!("---\n{body}")
    })
}

fn prepare_workspace_root(root: &Path) -> Result<PathBuf> {
    if let Ok(metadata) = fs::symlink_metadata(root)
        && metadata.file_type().is_symlink()
    {
        bail!("workspace root must not be a symlink: {}", root.display());
    }
    fs::create_dir_all(root)
        .with_context(|| format!("create workspace root {}", root.display()))?;
    set_directory_mode(root)?;
    root.canonicalize()
        .with_context(|| format!("resolve workspace root {}", root.display()))
}

fn write_workspace_file(root: &Path, file: &RenderedFile) -> Result<()> {
    let relative = Path::new(&file.path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("unsafe generated workspace path: {}", file.path);
    }
    let target = root.join(relative);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create generated directory {}", parent.display()))?;
        set_directory_mode(parent)?;
    }
    fs::write(&target, file.content.as_bytes())
        .with_context(|| format!("write generated file {}", target.display()))?;
    set_file_mode(&target)?;
    Ok(())
}

#[cfg(unix)]
fn set_directory_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restrict directory permissions {}", path.display()))
}

#[cfg(not(unix))]
fn set_directory_mode(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restrict file permissions {}", path.display()))
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path) -> Result<()> {
    Ok(())
}
