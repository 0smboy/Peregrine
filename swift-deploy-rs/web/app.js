const token = document.querySelector('meta[name="ui-token"]').content;
const byId = (id) => document.getElementById(id);
const serverState = { audit: null, inventory: null, plan: null, execution: null, workspace: null, job: null, log: [], config: null };

let language = localStorage.getItem('swift-deploy-language') || 'zh';
let advancedSeeded = false;
let localBusy = false;
let pollTimer = null;
let previewPayload = null;
let previewSignature = '';
let generatedPayload = null;
let generatedSignature = '';
let lastDigest = '';
let ingressPrevious = 'haproxy';

const english = {
  title: 'Swift cluster deployment workspace',
  lead: 'Initial cluster deployment only: configure nodes, networks, disks, and authentication, then generate inventory, preflight targets, and execute. Expansion, disk addition, upgrade, and shrink workflows are not enabled.',
  loopback: 'loopback access only', readiness: 'configuration readiness', nodeCount: 'deployment nodes', diskCount: 'data disks', currentMissing: 'missing now',
  sixSteps: 'six configuration steps', step1Short: 'foundation', step2Short: 'node roles', step3Short: 'network & disks', step4Short: 'ring / policy', step5Short: 'auth / ingress', step6Short: 'review / execute',
  railNote: 'Red means required. Amber means a decision needs confirmation.',
  step1Title: 'Deployment mode and infrastructure', step1Desc: 'Choose production or SAIO and provide the infrastructure values used to reach every host.',
  projectName: 'Project name', required: 'required', projectHelp: 'Creates an isolated configuration directory. Use letters, numbers, dots, hyphens, and underscores.',
  deploymentMode: 'Deployment mode', production: 'Production', development: 'Development', modeHelp: 'Development forces ring rebalance and must never be used for production.',
  timezone: 'Timezone', timezoneHelp: 'Written to every Swift node.', saioHelp: 'Single-node test environment; requires development mode.',
  wwidLocked: 'USE_WWID (locked off)', wwidHelp: 'The explicit custom_disks contract conflicts with the upstream v3 WWID path. Use a reboot-stable /dev/disk/by-id path and let target preflight verify it.', changeHostname: 'Change hostname', hostnameHelp: 'Enable only when hostnames have no other purpose.',
  hostnamePrefix: 'Hostname prefix', hostnamePrefixHelp: 'When enabled, names look like peregrine_51.', ntpServer: 'Internet NTP', ntpHelp: 'The ntp_server node synchronizes from this source.',
  repoAddress: 'Local repository IPv4', repoHelp: 'Enter only the repository IPv4, with no http://, port, or path. Targets must reach http://IP/yum/, /pip/, and /component/.',
  adminIps: 'Admin allow-list IPs', adminIpsHelp: 'Comma or newline separated. Include this deployment host.', targetSshPort: 'SSH service port after deployment', targetSshHelp: 'The security role writes this sshd port. It is not the initial connection port.',
  step2Title: 'Nodes and roles', step2Desc: 'Every host requires a label, SSH address, initial port, root key, and at least one role. Production must also cover proxy, account, container, object, and time synchronization.',
  proxyRole: 'API ingress', storageRole: 'Swift metadata and object storage', authRole: 'local identity service', haRole: 'high-availability ingress', addNode: 'Add node',
  step3Title: 'Network, failure domains, and disks', step3Desc: 'Every host needs management, storage, and business IPs. Storage hosts also need real failure domains, the system disk, and every data disk. Region/Zone must map to real site, rack, or power boundaries.',
  managementNet: 'Management', managementNetHelp: 'SSH, repository, NTP', storageNet: 'Storage', storageNetHelp: 'reads, writes, replication, rsync', replicationNet: 'Replication address', replicationNetHelp: 'locked to storage IP by v3', businessNet: 'Business', businessNetHelp: 'Proxy / VIP ingress',
  step4Title: 'Ring and storage policy', step4Desc: 'Account, Container, and the default Object ring share these base values. Devices come from the explicit disk list above.',
  partitionPower: 'Partition power', partitionPowerHelp: '10 is a small lab default. Production must derive this value from target capacity and expansion plans, not copy it.', replicas: 'Replicas', replicasHelp: 'Must not exceed available devices and failure domains.', minimumTime: 'Minimum move interval (hours)', minimumTimeHelp: 'Wait before a partition can move again.', deviceWeight: 'Device weight', weightHelp: 'Identical disks normally use 100.',
  ringCapacityConfirmed: 'Production ring capacity and real failure domains confirmed', ringCapacityHelp: 'Production requires confirmation that partition power comes from capacity planning and Region/Zone from the physical failure-domain map, not arbitrary numbers.',
  policyName: 'Object policy name', policyNameHelp: 'Unique, no underscores. The default policy maps to object.builder.', policyType: 'Policy type', replication: 'Replication', erasureCoding: 'Erasure coding', policyTypeHelp: 'python-v3 allows Replication only; the rust stack can add one EC policy (Replication stays the default policy).', currentContract: 'current contract',
  deployStack: 'Deployment stack', stackPython: 'Python Swift v3', stackRust: 'Rust Swift (TempAuth)', deployStackHelp: 'The rust stack deploys Rust-version Swift: TempAuth, optional EC policy; point the bundle at bundle-rust.',
  ecData: 'EC data fragments', ecDataHelp: 'Total object-node devices must be at least data + parity fragments; diskless nodes count as one directory device.', ecParity: 'EC parity fragments', ecSegment: 'EC segment size (bytes)',
  tempauthAccount: 'TempAuth account', tempauthAccountHelp: 'The first account is the admin account written to swift_tempauth_users.', tempauthUser: 'TempAuth user', tempauthKey: 'TempAuth key',
  step5Title: 'Keystone authentication and ingress', step5Desc: 'The browser does not retain secrets. After generation, secrets are written to 0600 group_vars files inside a 0700 workspace on the deployment host; refreshing does not delete that workspace.',
  authConfig: 'Authentication', authMethod: 'Authentication method', authMethodHelp: 'The deployment stack decides the method: python-v3 uses Keystone, rust uses TempAuth.', passwordContract: 'Every authentication password must be at least 12 characters and use only ASCII letters, digits, period, underscore, tilde, or hyphen. Spaces and other symbols are rejected.', interface: 'Access interface', interfaceHelp: 'Swift API only. S3 requires EC2 access/secret credentials that this UI does not yet generate.', accountName: 'Initial account / project', adminUser: 'Swift administrator', adminUserHelp: 'Cannot be named swift or admin.', adminPassword: 'Swift administrator password', controllerHostname: 'Keystone controller hostname', clustercheckHelp: 'Replaces the upstream fixed clustercheckpassword for Galera health checks.', haproxyStatsUser: 'HAProxy stats user', haproxyStatsUserHelp: 'Replaces the upstream fixed admin user; admin is rejected.', haproxyStatsPassword: 'HAProxy stats password', haproxyStatsPasswordHelp: 'Replaces the upstream fixed admin/admin credential.',
  ingressConfig: 'Ingress and high availability', ingressMode: 'Ingress mode', directDisabled: 'Direct (not supported with Keystone)', ingressModeHelp: 'HAProxy needs at least one host; Keepalived needs two hosts also carrying HAProxy. The UI cannot prove shared L2, external VIP availability, or network allowance for VRRP protocol 112; verify these on site.', protocol: 'Protocol', protocolHelp: 'The selected v3 Keystone and Proxy paths hard-code HTTP. HTTPS is disabled.', authUrlIp: 'User-facing IP / VIP', authUrlHelp: 'HAProxy: use the business IP of a haproxy host. Keepalived: use a dedicated VIP that is not assigned to any configured host.', swiftPort: 'Swift ingress port', swiftPortHelp: 'Configurable. Generation synchronizes this value to Swift LB and the HAProxy listener; the firewall must allow the same port.', vipPrefix: 'VIP prefix length', vrrpHelp: '5-8 characters using only ASCII letters, digits, period, underscore, tilde, or hyphen.', transportSecurityBoundary: 'This v3 contract has no end-to-end TLS and disables object at-rest encryption. Deploy only on a trusted isolated network or behind trusted external TLS termination; never expose the HTTP ports directly to an untrusted network.',
  step6Title: 'Review, generate, preflight, and execute', step6Desc: 'Preview the Ansible configuration first. Generation audits the bundle, validates inventory, and seals a plan. A read-only target preflight is required before Apply.', previewConfig: '1. Preview configuration', generateAndPlan: '2. Generate and build plan', preflightHosts: '3. Run target preflight', previewFirst: 'Complete the required values at right, then preview.', nothingGenerated: 'No configuration generated', nothingGeneratedHelp: 'Preview shows host groups, ring, ingress, and redacted target files here.',
  advancedTitle: 'Advanced: generated files and execution paths', advancedHelp: 'Usually no edits are needed. Use this area to import an existing inventory or diagnose a problem.', auditBundle: 'Audit bundle', validateInventory: 'Validate inventory', buildPlan: 'Build plan', notRun: 'not run',
  applyTitle: 'Final execution confirmation', applyDesc: 'The hosts and data disks below will be touched by the plan. Formatting is irreversible and needs explicit authorization.', productionOnlyTitle: 'Dedicated, newly installed Rocky 9 hosts only', productionOnlyDesc: 'Before Apply, snapshot or image every node and schedule a maintenance window. This plan changes the host baseline, not only Swift.', impactRepos: 'replaces enabled yum repositories and runs a full yum upgrade', impactSystem: 'changes hostname, timezone, locale, SELinux, systemd units, users, and cron', impactServices: 'installs packages and enables, stops, or restarts host and Swift services', copyDigest: 'Copy digest', riskCapabilities: 'Independent risk grants', diskRisk: 'allow formatting the listed data disks', firewallRisk: 'allow firewall rules and ports', sshRisk: 'allow moving SSH to the configured port', hostRisk: 'allow yum repo/upgrade, OS baseline, service, and cron changes', pasteDigest: 'Paste the complete plan digest', typeApply: 'Type uppercase APPLY', applyLocked: 'Apply locked: generate a configuration and plan first.', applyAction: 'Execute sealed plan',
  activity: 'Recent activity', idle: 'idle', readinessTitle: 'Deployment readiness', checking: 'checking…', secretNote: 'The browser does not store secrets. Generated 0600 workspace files persist on the deployment host.', footerSafety: 'loopback only · strict host keys · execution requires a sealed plan',
};

const messages = {
  zh: {
    complete: '配置完整，可以预览', gaps: (n) => `还有 ${n} 个必填项`, stepOk: '已完整', stepError: (n) => `${n} 个缺项`, stepWarn: (n) => `${n} 项确认`, awaiting: '待配置', waitingPreview: '待预览', previewValid: '预览通过', planSealed: '计划已密封',
    node: (n) => `节点 ${n}`, remove: '删除节点', roles: '承担角色', connection: 'SSH 连接地址', nodeName: '节点名称', nodeIdentity: '节点名称只是界面标签；inventory 主机键使用管理网 IP。选定 v3 含未声明 become 的特权任务，因此 SSH 用户锁定为 root。', sshUser: 'SSH 用户（v3 锁定）', sshPort: '首次连接端口', sshKey: 'SSH 私钥路径',
    storageFor: (name) => `${name} 的网络与磁盘`, copyNetworks: '管理 IP 复制到部署网络', copyNetworksHelp: 'v3 的复制地址必须等于存储 IP；单网测试可把管理、存储和业务 IP 设为同一地址。', region: 'Region', zone: 'Zone', diskType: '磁盘类型', systemDisk: '系统盘（禁止擦除）', dataDisks: '数据盘清单', diskHelp: '逐盘写绝对设备路径；生成时会进入 format_disk_servers 与 Ring。', rustDiskHelp: 'rust 栈 v1 只部署目录设备 d1（自动创建）；数据盘格式化在带外完成，不在此配置。', nonStorageDiskHelp: '此节点没有 account/container/object 角色，不能添加数据盘。', failureDomainHelp: 'Region/Zone 必须对应真实机房、机架或电源故障边界；相同风险域必须填相同编号。', addDisk: '添加数据盘', removeDisk: '删除', noDataDisk: '尚未配置数据盘', requiredBadge: '必填', fixedBadge: 'v3 固定', storageRequiredBadge: '存储节点必填', keepalivedRequiredBadge: 'Keepalived 必填',
    keepalivedInterface: 'Keepalived 网卡', keepalivedPriority: 'Keepalived 优先级', roleProxy: 'Proxy 入口', roleAccount: 'Account', roleContainer: 'Container', roleObject: 'Object', roleKeystone: 'Keystone', roleMariadb: 'MariaDB', roleHaproxy: 'HAProxy', roleKeepalived: 'Keepalived', roleNtpServer: 'NTP 主', roleNtpClient: 'NTP 客户端', roleTuning: '性能调优',
    previewing: '正在由 Rust 后端校验并预览…', generating: '正在生成隔离配置目录…', pipelineAudit: '正在审计 v3 bundle…', pipelineValidate: '正在校验生成的 inventory…', pipelinePlan: '正在创建密封计划…', generated: (path) => `配置已生成并完成计划：${path}`, previewOk: '预览通过，可以生成配置。', previewFailed: '预览未通过，请先处理错误。', changed: '表单已修改，需要重新预览并生成。', needPreflight: 'Apply 已锁定：先运行实机预检，确认 Rocky 9、网络、软件源和空白数据盘。', preflightOk: (p) => `${p.hosts?.length ?? 0} 台主机 · 实机预检通过`, preflightBlocked: (p) => `${p.hosts?.filter((host) => !host.ok).length ?? 0} 台主机阻断`,
    files: '目标文件', errors: '错误', warnings: '提醒', sampleBlocked: '示例 inventory 永久禁止 Apply。', running: '正在运行', copied: '已复制', needPlan: 'Apply 已锁定：先生成密封计划。', needGenerate: 'Apply 已锁定：表单已变化，请重新生成配置和计划。', needDigest: 'Apply 已锁定：粘贴完整且一致的 digest。', needPhrase: 'Apply 已锁定：输入大写 APPLY。', needRisk: 'Apply 已锁定：逐项授权计划要求的风险。', readyApply: '证据一致，Apply 已解锁。', noTargets: '尚无明确执行目标。', targetHost: '目标主机', targetRoles: '角色', targetDisks: '将格式化的数据盘',
    auditOk: (a) => `${a.task_files ?? '--'} 个任务文件 · ${a.tasks ?? '--'} 个叶子任务`, inventoryOk: (i) => `${i.hosts ?? '--'} 台主机 · ${i.groups ?? '--'} 个组`, planOk: (p) => `${p.hosts ?? '--'} 台主机 · ${p.tasks ?? '--'} 个任务`,
    productionKeystone: 'production 只允许 Keystone；TempAuth 是上游 v3 的未闭环路径。', productionHttp: 'production 只允许 HTTP；上游 v3 的 HTTPS 证书链未闭环。', developmentRisk: 'development 会强制 rebalance，只能用于测试。', wwidRisk: '显式 custom_disks 与 USE_WWID 在上游 v3 不兼容。', stablePath: '生产环境未启用 WWID，请确认 /dev 路径在重启后保持稳定。', fewDomains: '副本数高于独立 region/zone 数；故障域隔离能力不足。', noLocalKeystone: '没有本地 Keystone 节点；请确认 auth_url_ip 指向可用的外部 Keystone/入口。',
  },
  en: {
    complete: 'Configuration complete. Ready to preview.', gaps: (n) => `${n} required values remain`, stepOk: 'complete', stepError: (n) => `${n} missing`, stepWarn: (n) => `${n} to confirm`, awaiting: 'waiting', waitingPreview: 'preview needed', previewValid: 'preview passed', planSealed: 'plan sealed',
    node: (n) => `Node ${n}`, remove: 'Remove node', roles: 'Roles on this host', connection: 'SSH address', nodeName: 'Node label', nodeIdentity: 'The node name is only a UI label; inventory keys use management IPs. The selected v3 has privileged tasks without become, so SSH is locked to root.', sshUser: 'SSH user (v3 locked)', sshPort: 'Initial SSH port', sshKey: 'SSH private key path',
    storageFor: (name) => `${name}: networks and disks`, copyNetworks: 'Copy management IP to deployment networks', copyNetworksHelp: 'v3 requires the replication address to equal the storage IP. A single-network test may reuse management, storage, and business.', region: 'Region', zone: 'Zone', diskType: 'Disk type', systemDisk: 'System disk (never wipe)', dataDisks: 'Data disks', diskHelp: 'List absolute device paths. They enter format_disk_servers and the ring.', rustDiskHelp: 'The rust stack v1 deploys the directory device d1 (auto-created); prepare block devices out-of-band, not here.', nonStorageDiskHelp: 'This host has no account/container/object role, so data disks cannot be added.', failureDomainHelp: 'Region/Zone must map to real site, rack, or power failure boundaries. Hosts sharing a risk boundary must use the same number.', addDisk: 'Add data disk', removeDisk: 'Remove', noDataDisk: 'No data disks configured', requiredBadge: 'required', fixedBadge: 'fixed by v3', storageRequiredBadge: 'required on storage hosts', keepalivedRequiredBadge: 'required with Keepalived',
    keepalivedInterface: 'Keepalived interface', keepalivedPriority: 'Keepalived priority', roleProxy: 'Proxy ingress', roleAccount: 'Account', roleContainer: 'Container', roleObject: 'Object', roleKeystone: 'Keystone', roleMariadb: 'MariaDB', roleHaproxy: 'HAProxy', roleKeepalived: 'Keepalived', roleNtpServer: 'NTP server', roleNtpClient: 'NTP client', roleTuning: 'Performance tuning',
    previewing: 'Validating and previewing through the Rust backend…', generating: 'Generating an isolated configuration directory…', pipelineAudit: 'Auditing the v3 bundle…', pipelineValidate: 'Validating generated inventory…', pipelinePlan: 'Building the sealed plan…', generated: (path) => `Configuration generated and plan completed: ${path}`, previewOk: 'Preview passed. Configuration can be generated.', previewFailed: 'Preview failed. Resolve the errors first.', changed: 'The form changed. Preview and generate again.', needPreflight: 'Apply locked: run the target preflight for Rocky 9, network addresses, repositories, and blank data disks.', preflightOk: (p) => `${p.hosts?.length ?? 0} hosts · preflight passed`, preflightBlocked: (p) => `${p.hosts?.filter((host) => !host.ok).length ?? 0} hosts blocked`,
    files: 'target files', errors: 'errors', warnings: 'warnings', sampleBlocked: 'Sample inventory is permanently blocked from Apply.', running: 'running', copied: 'copied', needPlan: 'Apply locked: build a sealed plan first.', needGenerate: 'Apply locked: the form changed; regenerate configuration and plan.', needDigest: 'Apply locked: paste the exact complete digest.', needPhrase: 'Apply locked: type uppercase APPLY.', needRisk: 'Apply locked: grant each risk required by the plan.', readyApply: 'Proofs match. Apply is armed.', noTargets: 'No explicit execution targets yet.', targetHost: 'Target host', targetRoles: 'Roles', targetDisks: 'Data disks to format',
    auditOk: (a) => `${a.task_files ?? '--'} task files · ${a.tasks ?? '--'} leaf tasks`, inventoryOk: (i) => `${i.hosts ?? '--'} hosts · ${i.groups ?? '--'} groups`, planOk: (p) => `${p.hosts ?? '--'} hosts · ${p.tasks ?? '--'} tasks`,
    productionKeystone: 'Production only allows Keystone; upstream v3 does not close the TempAuth production path.', productionHttp: 'Production only allows HTTP; upstream v3 does not close the HTTPS certificate path.', developmentRisk: 'Development forces rebalance and is test-only.', wwidRisk: 'Upstream v3 cannot combine explicit custom_disks with USE_WWID.', stablePath: 'WWID is disabled in production. Confirm /dev paths stay stable across reboots.', fewDomains: 'Replicas exceed independent region/zone domains; failure isolation is insufficient.', noLocalKeystone: 'No local Keystone node. Confirm auth_url_ip reaches an external Keystone/ingress.',
  },
};

const m = (key, ...args) => {
  const value = messages[language]?.[key] ?? messages.zh[key] ?? key;
  return typeof value === 'function' ? value(...args) : value;
};

const roleDefinitions = [
  ['proxy', 'roleProxy'], ['account', 'roleAccount'], ['container', 'roleContainer'], ['object', 'roleObject'],
  ['keystone', 'roleKeystone'], ['mariadb', 'roleMariadb'], ['haproxy', 'roleHaproxy'], ['keepalived', 'roleKeepalived'],
  ['ntp_server', 'roleNtpServer'], ['ntp_client', 'roleNtpClient'], ['performance_tuning', 'roleTuning'],
];

const storageRoles = new Set(['account', 'container', 'object']);
const advancedIds = { bundle: 'bundle-path', inventory: 'inventory-path', playbook: 'playbook-path', plan: 'plan-path', known_hosts: 'known-hosts-path' };
const endpointByAction = { audit: '/api/audit', validate: '/api/validate', plan: '/api/plan', preflight: '/api/preflight', apply: '/api/apply' };

const newNode = (number) => ({
  name: `swift-${String(number).padStart(2, '0')}`,
  address: '',
  ssh_user: 'root',
  ssh_port: 22,
  ssh_key_file: '/root/.ssh/id_ed25519',
  management_ip: '', storage_ip: '', replication_ip: '', business_ip: '',
  region: 1, zone: 1,
  roles: number === 1 ? ['proxy', 'account', 'container', 'object', 'keystone', 'mariadb', 'haproxy', 'ntp_server'] : ['account', 'container', 'object', 'ntp_client'],
  disk_type: 'hdd', system_disk: '', disks: [''],
  keepalived_interface: '', keepalived_priority: null,
});

let nodes = [newNode(1)];

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[character]);
}

function seedStaticTranslations() {
  document.querySelectorAll('[data-i18n]').forEach((element) => {
    if (!element.dataset.zh) element.dataset.zh = element.textContent.trim();
  });
}

function applyLanguage() {
  document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en';
  document.querySelectorAll('[data-i18n]').forEach((element) => {
    element.textContent = language === 'zh' ? element.dataset.zh : (english[element.dataset.i18n] || element.dataset.zh);
  });
  document.querySelectorAll('[data-language]').forEach((button) => {
    button.setAttribute('aria-pressed', String(button.dataset.language === language));
  });
  renderNodeEditors();
  renderStorageEditors();
  renderAll();
}

function renderNodeEditors() {
  const container = byId('node-list');
  container.innerHTML = nodes.map((node, index) => {
    const roles = roleDefinitions.map(([role, label]) => `
      <label class="role-option">
        <input type="checkbox" data-node-index="${index}" data-role="${role}" ${node.roles.includes(role) ? 'checked' : ''}>
        <span>${escapeHtml(m(label))}</span>
      </label>`).join('');
    return `
      <article class="node-panel" data-node-panel="${index}">
        <header class="node-panel-head">
          <div class="node-title"><strong>${escapeHtml(m('node', index + 1))}</strong><span data-node-caption="${index}">${escapeHtml(node.name || node.address || '—')}</span></div>
          <button class="icon-action" type="button" data-remove-node="${index}" ${nodes.length === 1 ? 'disabled' : ''}>${escapeHtml(m('remove'))}</button>
        </header>
        <div class="node-core">
          ${nodeInput(index, 'name', m('nodeName'), node.name, 'swift-01')}
          ${nodeInput(index, 'address', m('connection'), node.address, '10.0.10.11')}
          ${nodeInput(index, 'ssh_user', m('sshUser'), node.ssh_user, 'root', 'text', true, 'fixed')}
          ${nodeInput(index, 'ssh_port', m('sshPort'), node.ssh_port, '22', 'number')}
          ${nodeInput(index, 'ssh_key_file', m('sshKey'), node.ssh_key_file, '/root/.ssh/id_ed25519')}
        </div>
        <p class="node-identity-note">${escapeHtml(m('nodeIdentity'))}</p>
        <fieldset id="node-${index}-roles" class="role-fieldset"><legend>${escapeHtml(m('roles'))} ${requirementBadge('required')}</legend><div class="role-options">${roles}</div></fieldset>
      </article>`;
  }).join('');
}

function requirementBadge(kind) {
  const key = { required: 'requiredBadge', fixed: 'fixedBadge', storage: 'storageRequiredBadge', keepalived: 'keepalivedRequiredBadge' }[kind];
  return key ? `<em class="requirement-badge">${escapeHtml(m(key))}</em>` : '';
}

function nodeInput(index, field, label, value, placeholder, type = 'text', readonly = false, requirement = 'required') {
  return `<label class="node-field" for="node-${index}-${field}"><span class="node-field-label"><b>${escapeHtml(label)}</b>${requirementBadge(requirement)}</span><input id="node-${index}-${field}" type="${type}" data-node-index="${index}" data-node-field="${field}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}" autocomplete="off" ${readonly ? 'readonly' : ''} required></label>`;
}

function renderStorageEditors() {
  const container = byId('node-storage-list');
  const isRust = byId('deploy-stack').value === 'rust';
  container.innerHTML = nodes.map((node, index) => {
    const diskRows = node.disks.length ? node.disks.map((disk, diskIndex) => `
      <div class="disk-row">
        <input id="node-${index}-disk-${diskIndex}" data-node-index="${index}" data-disk-index="${diskIndex}" value="${escapeHtml(disk)}" placeholder="/dev/sdb 或 /dev/disk/by-id/…" autocomplete="off">
        <button class="icon-action" type="button" data-remove-disk="${index}:${diskIndex}">${escapeHtml(m('removeDisk'))}</button>
      </div>`).join('') : `<p class="quiet">${escapeHtml(m('noDataDisk'))}</p>`;
    const isStorage = node.roles.some((role) => storageRoles.has(role));
    const needsKeepalived = byId('ingress-mode').value === 'keepalived' && node.roles.includes('keepalived');
    return `
      <article class="storage-panel" data-storage-panel="${index}">
        <header class="storage-panel-head"><div class="storage-title"><strong>${escapeHtml(m('storageFor', node.name || m('node', index + 1)))}</strong><span>${escapeHtml(node.address || 'SSH address —')}</span></div></header>
        <div class="storage-panel-body">
          <div class="network-tools"><p>${escapeHtml(m('copyNetworksHelp'))}</p><button class="secondary-action" type="button" data-copy-networks="${index}">${escapeHtml(m('copyNetworks'))}</button></div>
          <div class="network-grid">
            ${storageInput(index, 'management_ip', language === 'zh' ? '管理网 IP' : 'Management IP', node.management_ip, '10.0.10.11', 'text', false, false, 'required')}
            ${storageInput(index, 'storage_ip', language === 'zh' ? '存储网 IP' : 'Storage IP', node.storage_ip, '10.0.20.11', 'text', false, false, 'required')}
            ${isRust
              ? storageInput(index, 'replication_ip', language === 'zh' ? '复制网 IP（可独立于存储网）' : 'Replication IP (may differ from storage)', node.replication_ip, '172.19.1.11', 'text', false, false, 'required')
              : storageInput(index, 'replication_ip', language === 'zh' ? '复制地址（跟随存储网）' : 'Replication address (follows storage)', node.replication_ip, '10.0.20.11', 'text', false, true, 'fixed')}
            ${storageInput(index, 'business_ip', language === 'zh' ? '业务网 IP' : 'Business IP', node.business_ip, '10.0.40.11', 'text', false, false, 'required')}
          </div>
          <div class="failure-disk-grid">
            ${storageInput(index, 'region', m('region'), node.region, '1', 'number', !isStorage, false, 'storage')}
            ${storageInput(index, 'zone', m('zone'), node.zone, '1', 'number', !isStorage, false, 'storage')}
            <label class="node-field" for="node-${index}-disk_type"><span class="node-field-label"><b>${escapeHtml(m('diskType'))}</b>${requirementBadge('storage')}</span><select id="node-${index}-disk_type" data-node-index="${index}" data-node-field="disk_type" ${isStorage ? '' : 'disabled'}><option value="hdd" ${node.disk_type === 'hdd' ? 'selected' : ''}>HDD</option><option value="ssd" ${node.disk_type === 'ssd' ? 'selected' : ''}>SSD</option></select></label>
            ${storageInput(index, 'system_disk', m('systemDisk'), node.system_disk, '/dev/vda', 'text', !isStorage, false, 'storage')}
            ${storageInput(index, 'keepalived_interface', m('keepalivedInterface'), node.keepalived_interface, 'ens5', 'text', !needsKeepalived, false, 'keepalived')}
            ${storageInput(index, 'keepalived_priority', m('keepalivedPriority'), node.keepalived_priority ?? '', '100', 'number', !needsKeepalived, false, 'keepalived')}
            <p class="failure-domain-note">${escapeHtml(m('failureDomainHelp'))}</p>
            <div class="disk-editor">
              <div class="disk-editor-head"><span class="node-field-label"><b>${escapeHtml(m('dataDisks'))}</b>${isStorage && !isRust ? requirementBadge('storage') : ''}</span><span class="${isStorage ? '' : 'warning-text'}">${escapeHtml(m(isRust ? 'rustDiskHelp' : isStorage ? 'diskHelp' : 'nonStorageDiskHelp'))}</span></div>
              <div class="disk-list">${diskRows}</div>
              <button class="secondary-action add-disk" type="button" data-add-disk="${index}" ${isStorage && !isRust ? '' : 'disabled'}>${escapeHtml(m('addDisk'))}</button>
            </div>
          </div>
        </div>
      </article>`;
  }).join('');
}

function storageInput(index, field, label, value, placeholder, type = 'text', disabled = false, readonly = false, requirement = '') {
  const range = field === 'keepalived_priority' ? 'min="1" max="255" step="1"' : (['region', 'zone'].includes(field) ? 'min="1" step="1"' : '');
  return `<label class="node-field" for="node-${index}-${field}"><span class="node-field-label"><b>${escapeHtml(label)}</b>${requirementBadge(requirement)}</span><input id="node-${index}-${field}" type="${type}" data-node-index="${index}" data-node-field="${field}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}" autocomplete="off" ${range} ${disabled ? 'disabled' : ''} ${readonly ? 'readonly' : ''}></label>`;
}

function splitList(value) {
  return String(value || '').split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
}

function numberValue(id) {
  const raw = byId(id).value.trim();
  return raw === '' ? 0 : Number(raw);
}

function buildWorkspaceRequest() {
  const stack = byId('deploy-stack').value;
  const isRust = stack === 'rust';
  const policyType = isRust ? byId('policy-type').value : 'replication';
  const isEc = isRust && policyType === 'erasure_coding';
  return {
    project_name: byId('project-name').value.trim(),
    stack,
    deployment_mode: byId('deployment-mode').value,
    saio: byId('saio').checked,
    use_wwid: byId('use-wwid').checked,
    hostname_modifiable: byId('hostname-modifiable').checked,
    hostname_prefix: byId('hostname-prefix').value.trim(),
    timezone: byId('timezone').value.trim(),
    ntp_internet_server: byId('ntp-internet-server').value.trim(),
    local_repo_address: byId('local-repo-address').value.trim(),
    admin_ips: splitList(byId('admin-ips').value),
    ssh_bind_port: numberValue('ssh-bind-port'),
    nodes: nodes.map((node) => ({
      ...node,
      replication_ip: isRust ? (node.replication_ip || node.storage_ip) : node.storage_ip,
      ssh_port: Number(node.ssh_port) || 0,
      region: Number(node.region) || 0,
      zone: Number(node.zone) || 0,
      keepalived_priority: node.keepalived_priority === '' || node.keepalived_priority == null ? null : Number(node.keepalived_priority),
      disks: node.disks.map((disk) => disk.trim()).filter(Boolean),
    })),
    ring: {
      partition_power: numberValue('partition-power'), replicas: numberValue('replicas'), minimum_time: numberValue('minimum-time'),
      object_policy_name: byId('policy-name').value.trim(), object_policy_type: policyType,
      ec_data_fragments: isEc ? numberValue('ec-data-fragments') : null, ec_parity_fragments: isEc ? numberValue('ec-parity-fragments') : null,
      ec_segment_size: isEc ? numberValue('ec-segment-size') : 1048576, device_weight: numberValue('device-weight'),
    },
    ring_capacity_confirmed: byId('ring-capacity-confirmed').checked,
    auth: {
      method: isRust ? 'tempauth' : 'keystone', interface: byId('swift-interface').value, account_name: byId('account-name').value.trim(), admin_user: byId('admin-user').value.trim(), admin_password: byId('admin-password').value,
      mariadb_root_password: byId('mariadb-root-password').value, mariadb_keystone_password: byId('mariadb-keystone-password').value, mariadb_clustercheck_password: byId('mariadb-clustercheck-password').value, keystone_admin_password: byId('keystone-admin-password').value, keystone_swift_password: byId('keystone-swift-password').value,
      keystone_controller_hostname: byId('keystone-controller').value.trim(), haproxy_stats_user: byId('haproxy-stats-user').value.trim(), haproxy_stats_password: byId('haproxy-stats-password').value,
    },
    tempauth_accounts: isRust ? [{ account: byId('tempauth-account').value.trim(), user: byId('tempauth-user').value.trim(), key: byId('tempauth-key').value }] : [],
    ingress: {
      mode: byId('ingress-mode').value, http_mode: byId('http-mode').value, auth_url_ip: byId('auth-url-ip').value.trim(), swift_port: numberValue('swift-port'), vip_prefix: numberValue('vip-prefix'), virtual_router_id: numberValue('virtual-router-id'), vrrp_auth_pass: byId('vrrp-auth-pass').value,
    },
  };
}

function isIpv4(value) {
  const parts = String(value || '').split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function compareIpv4(left, right) {
  const parse = (value) => String(value || '').split('.').reduce((number, octet) => (number * 256) + Number(octet), 0);
  if (isIpv4(left) && isIpv4(right)) return parse(left) - parse(right);
  return String(left || '').localeCompare(String(right || ''));
}

function isDeploymentPassword(value) {
  return /^[A-Za-z0-9._~-]{12,}$/.test(String(value || ''));
}

function sameIpv4Subnet(left, right, prefix) {
  if (!isIpv4(left) || !isIpv4(right) || prefix < 0 || prefix > 32) return false;
  const toInteger = (value) => value.split('.').reduce((result, octet) => ((result << 8) | Number(octet)) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (toInteger(left) & mask) === (toInteger(right) & mask);
}

function collectValidation() {
  const request = buildWorkspaceRequest();
  const isRust = request.stack === 'rust';
  const errors = [];
  const warnings = [];
  let total = 0;
  let passed = 0;
  const need = (condition, step, id, zh, en = zh) => {
    total += 1;
    if (condition) passed += 1;
    else errors.push({ step, id, message: language === 'zh' ? zh : en });
  };
  const warn = (condition, step, id, zh, en = zh) => { if (condition) warnings.push({ step, id, message: language === 'zh' ? zh : en }); };

  need(/^[A-Za-z0-9._-]+$/.test(request.project_name), 1, 'project-name', '项目名称为空或包含非法字符', 'Project name is empty or contains unsupported characters');
  need(Boolean(request.timezone), 1, 'timezone', '请填写时区', 'Enter a timezone');
  need(Boolean(request.ntp_internet_server), 1, 'ntp-internet-server', '请填写互联网 NTP 地址', 'Enter an Internet NTP server');
  need(isRust || isIpv4(request.local_repo_address), 1, 'local-repo-address', '本地软件源只填单个 IPv4，不带 http://、端口或路径', 'Enter one repository IPv4 with no http://, port, or path');
  need(request.admin_ips.length > 0, 1, 'admin-ips', '至少填写一个管理端白名单 IP，包括当前部署机', 'Enter at least one admin allow-list IP, including this deployment host');
  need(request.admin_ips.every(isIpv4), 1, 'admin-ips', '管理端白名单只能填写单个 IPv4，不能使用 CIDR 或占位符', 'Admin allow-list entries must be individual IPv4 addresses, not CIDRs or placeholders');
  need(request.ssh_bind_port >= 1 && request.ssh_bind_port <= 65535, 1, 'ssh-bind-port', '部署后的 SSH 端口必须在 1-65535', 'Final SSH port must be between 1 and 65535');
  need(!request.hostname_modifiable || Boolean(request.hostname_prefix), 1, 'hostname-prefix', '开启修改 hostname 后必须填写前缀', 'A hostname prefix is required when hostname changes are enabled');
  need(!request.saio || request.deployment_mode === 'development', 1, 'saio', 'SAIO 必须使用 development 模式', 'SAIO requires development mode');
  need(request.auth.method === (isRust ? 'tempauth' : 'keystone'), 5, 'auth-method', isRust ? 'rust 栈只支持 TempAuth 认证' : 'python-v3 栈只支持 Keystone 认证', isRust ? 'The rust stack supports TempAuth only' : 'The python-v3 stack supports Keystone only');
  need(isRust ? ['replication', 'erasure_coding'].includes(request.ring.object_policy_type) : request.ring.object_policy_type === 'replication', 4, 'policy-type', isRust ? '策略类型只能是 Replication 或 Erasure Coding' : 'python-v3 只支持 Replication 策略', isRust ? 'Policy type must be replication or erasure coding' : 'python-v3 supports the Replication policy only');
  need(!isRust || request.ingress.mode !== 'keepalived', 5, 'ingress-mode', 'rust 栈 v1 不支持 Keepalived VIP 入口；请选择 Direct 或 HAProxy', 'The rust stack v1 does not support Keepalived VIP ingress; choose direct or HAProxy');
  need(request.ingress.http_mode === 'http', 5, 'http-mode', '选定 v3 只允许 HTTP；HTTPS 路径未闭环', 'The selected v3 bundle only supports HTTP; its HTTPS path is incomplete');
  need(request.auth.interface === 'swift', 5, 'swift-interface', '当前 UI 只开放 Swift API；S3 凭据链未闭环', 'This UI only enables the Swift API; the S3 credential flow is incomplete');
  need(!(request.auth.method === 'keystone' && request.ingress.mode === 'direct'), 5, 'ingress-mode', 'Keystone 认证不能使用 direct 入口；请选择 HAProxy 或 Keepalived VIP', 'Keystone cannot use direct ingress. Choose HAProxy or Keepalived VIP');
  need(!(request.use_wwid && request.nodes.some((node) => node.disks.length)), 3, 'use-wwid', m('wwidRisk'), m('wwidRisk'));

  need(request.nodes.length > 0, 2, 'node-list', '至少添加一台节点', 'Add at least one node');
  const names = new Set();
  const addresses = new Set();
  request.nodes.forEach((node, index) => {
    need(Boolean(node.name), 2, `node-${index}-name`, `节点 ${index + 1} 缺少名称`, `Node ${index + 1} needs a name`);
    need(Boolean(node.address), 2, `node-${index}-address`, `节点 ${index + 1} 缺少 SSH 连接地址`, `Node ${index + 1} needs an SSH address`);
    need(node.ssh_user === 'root', 2, `node-${index}-ssh_user`, `选定 v3 当前只允许 root SSH 用户`, `The selected v3 bundle currently requires the root SSH user`);
    need(node.ssh_port >= 1 && node.ssh_port <= 65535, 2, `node-${index}-ssh_port`, `节点 ${index + 1} 的首次连接端口无效`, `Node ${index + 1} has an invalid initial SSH port`);
    need(Boolean(node.ssh_key_file), 2, `node-${index}-ssh_key_file`, `节点 ${index + 1} 缺少 SSH 私钥路径`, `Node ${index + 1} needs an SSH private key path`);
    need(node.roles.length > 0, 2, `node-${index}-roles`, `节点 ${index + 1} 至少选择一个角色`, `Node ${index + 1} needs at least one role`);
    need(!(node.roles.includes('ntp_server') && node.roles.includes('ntp_client')), 2, `node-${index}-roles`, `节点 ${index + 1} 不能同时是 NTP 主和客户端`, `Node ${index + 1} cannot be both NTP server and client`);
    need(!isRust || !node.roles.some((role) => role === 'mariadb' || role === 'keystone'), 2, `node-${index}-roles`, `rust 栈自带 TempAuth，不部署 MariaDB/Keystone；请移除节点 ${node.name || index + 1} 的 mariadb/keystone 角色`, `The rust stack ships TempAuth and does not deploy MariaDB/Keystone. Remove those roles from ${node.name || `node ${index + 1}`}`);
    need(isIpv4(node.management_ip), 3, `node-${index}-management_ip`, `节点 ${index + 1} 的管理网必须是单个 IPv4`, `Node ${index + 1} needs one IPv4 management address`);
    need(isIpv4(node.storage_ip), 3, `node-${index}-storage_ip`, `节点 ${index + 1} 的存储网必须是单个 IPv4`, `Node ${index + 1} needs one IPv4 storage address`);
    need(isIpv4(node.replication_ip), 3, `node-${index}-replication_ip`, `节点 ${index + 1} 的复制网必须是单个 IPv4`, `Node ${index + 1} needs one IPv4 replication address`);
    need(isRust || node.replication_ip === node.storage_ip, 3, `node-${index}-replication_ip`, `选定 v3 的复制地址必须与存储网 IP 一致`, `The selected v3 bundle requires the replication address to equal the storage IP`);
    need(isIpv4(node.business_ip), 3, `node-${index}-business_ip`, `节点 ${index + 1} 的业务网必须是单个 IPv4`, `Node ${index + 1} needs one IPv4 business address`);
    const isStorage = node.roles.some((role) => storageRoles.has(role));
    need(!isStorage || node.region > 0, 3, `node-${index}-region`, `存储节点 ${node.name || index + 1} 的 region 无效`, `Storage node ${node.name || index + 1} has an invalid region`);
    need(!isStorage || node.zone > 0, 3, `node-${index}-zone`, `存储节点 ${node.name || index + 1} 的 zone 无效`, `Storage node ${node.name || index + 1} has an invalid zone`);
    need(!isStorage || (isRust && node.disks.length === 0) || (node.system_disk.startsWith('/dev/') && !/\s|\.\./.test(node.system_disk)), 3, `node-${index}-system_disk`, `存储节点 ${node.name || index + 1} 必须填写安全的 /dev 系统盘路径`, `Storage node ${node.name || index + 1} must identify a safe /dev system disk path`);
    need(!isStorage || isRust || node.disks.length > 0, 3, `node-${index}-disk-0`, `存储节点 ${node.name || index + 1} 至少需要一块数据盘`, `Storage node ${node.name || index + 1} needs at least one data disk`);
    need(!isRust || node.disks.length === 0, 3, `node-${index}-disk-0`, `rust 栈 v1 只部署目录设备；请清空节点 ${node.name || index + 1} 的数据盘列表`, `The rust stack v1 deploys directory devices only. Clear node ${node.name || index + 1}'s data-disk list`);
    need(isStorage || node.disks.length === 0, 3, `node-${index}-disk-0`, `非存储节点 ${node.name || index + 1} 不能配置数据盘；请删除磁盘，或先分配 account/container/object 角色`, `Non-storage node ${node.name || index + 1} cannot carry data disks. Remove them or assign account/container/object first`);
    node.disks.forEach((disk, diskIndex) => {
      need(disk.startsWith('/dev/'), 3, `node-${index}-disk-${diskIndex}`, `${node.name || `节点 ${index + 1}`} 的数据盘必须是 /dev 下的绝对路径`, `Data disks on ${node.name || `node ${index + 1}`} must be absolute /dev paths`);
      need(disk !== node.system_disk, 3, `node-${index}-disk-${diskIndex}`, `${node.name || `节点 ${index + 1}`} 的数据盘与系统盘重复`, `A data disk on ${node.name || `node ${index + 1}`} matches the system disk`);
    });
    const keepalived = request.ingress.mode === 'keepalived' && node.roles.includes('keepalived');
    need(!keepalived || Boolean(node.keepalived_interface), 3, `node-${index}-keepalived_interface`, `${node.name || `节点 ${index + 1}`} 缺少 Keepalived 网卡`, `${node.name || `Node ${index + 1}`} needs a Keepalived interface`);
    need(!keepalived || (node.keepalived_priority != null && node.keepalived_priority >= 1 && node.keepalived_priority <= 255), 3, `node-${index}-keepalived_priority`, `${node.name || `节点 ${index + 1}`} 的 Keepalived 优先级必须是 1-255`, `Keepalived priority on ${node.name || `node ${index + 1}`} must be 1-255`);
    need(request.ingress.mode !== 'direct' || !node.roles.some((role) => role === 'haproxy' || role === 'keepalived'), 2, `node-${index}-roles`, `direct 入口不会使用 ${node.name || `节点 ${index + 1}`} 的 HAProxy/Keepalived 角色；请移除多余角色`, `Direct ingress does not use HAProxy/Keepalived on ${node.name || `node ${index + 1}`}. Remove the extra roles`);
    need(request.ingress.mode !== 'haproxy' || !node.roles.includes('keepalived'), 2, `node-${index}-roles`, `HAProxy 入口不会使用 ${node.name || `节点 ${index + 1}`} 的 Keepalived 角色；请移除该角色或改用 Keepalived VIP`, `HAProxy ingress does not use the Keepalived role on ${node.name || `node ${index + 1}`}. Remove it or choose Keepalived VIP`);
    need(request.ingress.mode !== 'keepalived' || !node.roles.includes('keepalived') || node.roles.includes('haproxy'), 2, `node-${index}-roles`, `Keepalived 节点 ${node.name || index + 1} 必须同时承担 HAProxy 角色`, `Keepalived node ${node.name || index + 1} must also carry the HAProxy role`);
    need(!node.name || !names.has(node.name), 2, `node-${index}-name`, `节点名称 ${node.name} 重复`, `Duplicate node name: ${node.name}`);
    need(!node.address || !addresses.has(node.address), 2, `node-${index}-address`, `SSH 地址 ${node.address} 重复`, `Duplicate SSH address: ${node.address}`);
    names.add(node.name); addresses.add(node.address);
  });
  for (const [field, label] of [['management_ip', '管理网'], ['storage_ip', '存储网'], ['replication_ip', '复制网'], ['business_ip', '业务网']]) {
    const values = request.nodes.map((node) => node[field]).filter(isIpv4);
    need(new Set(values).size === values.length, 3, 'node-storage-list', `${label}中存在重复 IP`, `Duplicate IP found in ${field}`);
  }

  for (const [role, zh, en] of [
    ['proxy', '至少一台节点需要 proxy 角色', 'At least one node needs the proxy role'],
    ['account', '至少一台节点需要 account 角色', 'At least one node needs the account role'],
    ['container', '至少一台节点需要 container 角色', 'At least one node needs the container role'],
    ['object', '至少一台节点需要 object 角色', 'At least one node needs the object role'],
    ['ntp_server', '必须且只能先明确一台 NTP 主节点', 'Identify one NTP server node'],
  ]) need(request.nodes.some((node) => node.roles.includes(role)), 2, 'node-list', zh, en);
  need(request.nodes.filter((node) => node.roles.includes('ntp_server')).length === 1, 2, 'node-list', 'NTP 主节点必须且只能有一台', 'Exactly one node must carry ntp_server');
  if (request.auth.method === 'keystone') {
    const mariadbNodes = request.nodes.filter((node) => node.roles.includes('mariadb')).sort((left, right) => compareIpv4(left.management_ip, right.management_ip));
    need(mariadbNodes.length > 0, 2, 'node-list', 'Keystone 模式至少需要一台 mariadb 节点', 'Keystone mode needs at least one mariadb node');
    need(request.nodes.some((node) => node.roles.includes('keystone')), 2, 'node-list', 'Keystone 模式至少需要一台 keystone 节点', 'Keystone mode needs at least one keystone node');
    need(!mariadbNodes.length || mariadbNodes[0].roles.includes('keystone'), 2, 'node-list', '按管理网 IP 排序的首台 MariaDB 节点必须同时承担 Keystone 角色', 'The first MariaDB node by management IP must also carry Keystone');
  }

  need(request.ring.partition_power >= 8 && request.ring.partition_power <= 32, 4, 'partition-power', 'Partition power 必须在 8-32', 'Partition power must be between 8 and 32');
  need(request.deployment_mode !== 'production' || request.ring_capacity_confirmed, 4, 'ring-capacity-confirmed', 'production 必须确认 Partition power 来自容量规划、Region/Zone 来自真实故障域映射', 'Production requires confirmation that partition power comes from capacity planning and Region/Zone from the real failure-domain map');
  need(request.ring.replicas > 0, 4, 'replicas', '副本数必须大于 0', 'Replicas must be greater than zero');
  need(request.ring.minimum_time > 0, 4, 'minimum-time', '最小迁移间隔必须大于 0', 'Minimum move interval must be greater than zero');
  need(request.ring.device_weight > 0, 4, 'device-weight', '设备权重必须大于 0', 'Device weight must be greater than zero');
  need(Boolean(request.ring.object_policy_name) && !request.ring.object_policy_name.includes('_'), 4, 'policy-name', '策略名称不能为空且不能包含下划线', 'Policy name is required and cannot contain underscores');
  const roleDeviceCount = (role) => request.nodes.filter((node) => node.roles.includes(role)).reduce((sum, node) => sum + (isRust ? Math.max(1, node.disks.length) : node.disks.length), 0);
  for (const role of ['account', 'container', 'object']) {
    const roleDiskCount = roleDeviceCount(role);
    need(roleDiskCount >= Math.ceil(request.ring.replicas), 4, 'replicas', `${role} ring 只有 ${roleDiskCount} 块可用盘，少于副本/分片数 ${request.ring.replicas}`, `${role} ring has ${roleDiskCount} devices for ${request.ring.replicas} replicas/fragments`);
  }
  if (isRust && request.ring.object_policy_type === 'erasure_coding') {
    const ecData = request.ring.ec_data_fragments || 0;
    const ecParity = request.ring.ec_parity_fragments || 0;
    need(ecData >= 1, 4, 'ec-data-fragments', 'EC 数据分片数必须大于 0', 'EC data fragments must be greater than zero');
    need(ecParity >= 1, 4, 'ec-parity-fragments', 'EC 校验分片数必须大于 0', 'EC parity fragments must be greater than zero');
    need(request.ring.ec_segment_size >= 1, 4, 'ec-segment-size', 'EC 分段大小必须大于 0', 'EC segment size must be greater than zero');
    const objectDevices = roleDeviceCount('object');
    need(!(ecData >= 1 && ecParity >= 1) || objectDevices >= ecData + ecParity, 4, 'ec-data-fragments', `EC 需要 object 设备总数 ≥ 数据+校验分片数 ${ecData + ecParity}，当前只有 ${objectDevices}（无盘节点按 1 个目录设备计）`, `EC needs at least ${ecData + ecParity} object devices (data + parity); only ${objectDevices} available (diskless nodes count as one directory device)`);
  }
  const roleDomains = {};
  for (const role of ['account', 'container', 'object']) {
    roleDomains[role] = new Set(request.nodes.filter((node) => node.roles.includes(role)).map((node) => `${node.region}/${node.zone}`));
    need(request.deployment_mode !== 'production' || request.saio || roleDomains[role].size >= 2, 4, 'replicas', `生产集群的 ${role} ring 至少需要两个不同的 region/zone 故障域`, `The production ${role} ring needs at least two distinct region/zone failure domains`);
  }

  if (isRust) {
    const tempauth = request.tempauth_accounts[0] || { account: '', user: '', key: '' };
    need(Boolean(tempauth.account), 5, 'tempauth-account', '请填写 TempAuth 账户名', 'Enter the TempAuth account');
    need(Boolean(tempauth.user), 5, 'tempauth-user', '请填写 TempAuth 用户名', 'Enter the TempAuth user');
    need(isDeploymentPassword(tempauth.key), 5, 'tempauth-key', 'TempAuth 密钥至少 12 位，且只能使用 A-Z、a-z、0-9、.、_、~、-', 'TempAuth key must be at least 12 characters and use only A-Z, a-z, 0-9, period, underscore, tilde, or hyphen');
  } else {
    need(Boolean(request.auth.account_name), 5, 'account-name', '请填写初始 Swift 账号', 'Enter the initial Swift account');
    need(Boolean(request.auth.admin_user) && !['swift', 'admin'].includes(request.auth.admin_user), 5, 'admin-user', '管理用户名不能为空，也不能是 swift 或 admin', 'Administrator name is required and cannot be swift or admin');
    need(isDeploymentPassword(request.auth.admin_password), 5, 'admin-password', 'Swift 管理用户密码至少 12 位，且只能使用 A-Z、a-z、0-9、.、_、~、-', 'Swift administrator password must be at least 12 characters and use only A-Z, a-z, 0-9, period, underscore, tilde, or hyphen');
  }
  if (request.auth.method === 'keystone') {
    need(isDeploymentPassword(request.auth.mariadb_root_password), 5, 'mariadb-root-password', 'MariaDB root 密码至少 12 位，且只能使用 A-Z、a-z、0-9、.、_、~、-', 'MariaDB root password must be at least 12 characters and use only A-Z, a-z, 0-9, period, underscore, tilde, or hyphen');
    need(isDeploymentPassword(request.auth.mariadb_keystone_password), 5, 'mariadb-keystone-password', 'MariaDB Keystone 密码至少 12 位，且只能使用 A-Z、a-z、0-9、.、_、~、-', 'MariaDB Keystone password must be at least 12 characters and use only A-Z, a-z, 0-9, period, underscore, tilde, or hyphen');
    need(isDeploymentPassword(request.auth.mariadb_clustercheck_password), 5, 'mariadb-clustercheck-password', 'MariaDB clustercheck 密码至少 12 位，且只能使用 A-Z、a-z、0-9、.、_、~、-', 'MariaDB clustercheck password must be at least 12 characters and use only A-Z, a-z, 0-9, period, underscore, tilde, or hyphen');
    need(isDeploymentPassword(request.auth.keystone_admin_password), 5, 'keystone-admin-password', 'Keystone admin 密码至少 12 位，且只能使用 A-Z、a-z、0-9、.、_、~、-', 'Keystone admin password must be at least 12 characters and use only A-Z, a-z, 0-9, period, underscore, tilde, or hyphen');
    need(isDeploymentPassword(request.auth.keystone_swift_password), 5, 'keystone-swift-password', 'Keystone Swift service 密码至少 12 位，且只能使用 A-Z、a-z、0-9、.、_、~、-', 'Keystone Swift service password must be at least 12 characters and use only A-Z, a-z, 0-9, period, underscore, tilde, or hyphen');
    need(Boolean(request.auth.keystone_controller_hostname), 5, 'keystone-controller', '请填写 Keystone controller hostname', 'Enter the Keystone controller hostname');
  }
  const needsHaproxyStats = !isRust || request.ingress.mode === 'haproxy';
  need(!needsHaproxyStats || (Boolean(request.auth.haproxy_stats_user) && request.auth.haproxy_stats_user !== 'admin'), 5, 'haproxy-stats-user', 'HAProxy stats 用户不能为空，也不能继续使用 admin', 'HAProxy stats user is required and cannot remain admin');
  need(!needsHaproxyStats || isDeploymentPassword(request.auth.haproxy_stats_password), 5, 'haproxy-stats-password', 'HAProxy stats 密码至少 12 位，且只能使用 A-Z、a-z、0-9、.、_、~、-', 'HAProxy stats password must be at least 12 characters and use only A-Z, a-z, 0-9, period, underscore, tilde, or hyphen');
  need(isIpv4(request.ingress.auth_url_ip), 5, 'auth-url-ip', '用户访问地址必须是单个 IPv4', 'The user-facing address must be one IPv4 address');
  need(request.ingress.swift_port >= 1 && request.ingress.swift_port <= 65535, 5, 'swift-port', 'Swift 入口端口必须在 1-65535', 'Swift ingress port must be between 1 and 65535');
  if (request.ingress.mode === 'direct') {
    need(request.nodes.some((node) => node.roles.includes('proxy') && node.business_ip === request.ingress.auth_url_ip), 5, 'auth-url-ip', 'direct 模式的入口 IP 必须等于一台 proxy 节点的业务网 IP', 'Direct ingress must match the business IP of a proxy node');
  }
  if (request.ingress.mode === 'haproxy') {
    need(request.nodes.some((node) => node.roles.includes('haproxy')), 5, 'ingress-mode', 'HAProxy 模式至少需要一台 haproxy 节点', 'HAProxy mode needs at least one haproxy node');
    need(request.nodes.some((node) => node.roles.includes('haproxy') && node.business_ip === request.ingress.auth_url_ip), 5, 'auth-url-ip', 'haproxy 模式的入口 IP 必须等于一台 HAProxy 节点的业务网 IP', 'HAProxy ingress must match the business IP of a haproxy node');
  }
  if (request.ingress.mode === 'keepalived') {
    const haNodes = request.nodes.filter((node) => node.roles.includes('keepalived') && node.roles.includes('haproxy'));
    need(haNodes.length >= 2, 5, 'ingress-mode', 'Keepalived 模式至少需要两台同时承担 haproxy 与 keepalived 的节点', 'Keepalived needs at least two nodes carrying both haproxy and keepalived');
    need(request.ingress.vip_prefix >= 1 && request.ingress.vip_prefix <= 32, 5, 'vip-prefix', 'VIP 前缀长度必须在 1-32', 'VIP prefix must be between 1 and 32');
    need(request.ingress.virtual_router_id >= 1 && request.ingress.virtual_router_id <= 255, 5, 'virtual-router-id', 'virtual_router_id 必须在 1-255', 'virtual_router_id must be between 1 and 255');
    need(/^[A-Za-z0-9._~-]{5,8}$/.test(request.ingress.vrrp_auth_pass), 5, 'vrrp-auth-pass', 'VRRP auth_pass 必须为 5-8 位，且只能使用英文字母、数字和 . _ ~ -', 'VRRP auth_pass must contain 5-8 ASCII letters, digits, period, underscore, tilde, or hyphen');
    const nodeIps = new Set(request.nodes.flatMap((node) => [node.management_ip, node.storage_ip, node.replication_ip, node.business_ip]));
    need(!nodeIps.has(request.ingress.auth_url_ip), 5, 'auth-url-ip', 'Keepalived VIP 必须是未分配给任何节点的独立 IP', 'Keepalived VIP must not be assigned to any node');
    need(haNodes.every((node) => sameIpv4Subnet(request.ingress.auth_url_ip, node.business_ip, request.ingress.vip_prefix)), 5, 'auth-url-ip', 'Keepalived VIP 必须与所有 HA 节点业务网 IP 在所填前缀下同一子网', 'The Keepalived VIP must share the configured subnet with every HA node business IP');
    const priorities = haNodes.map((node) => node.keepalived_priority).filter((value) => value != null);
    need(new Set(priorities).size === priorities.length, 3, 'node-storage-list', 'Keepalived 节点优先级必须唯一', 'Keepalived priorities must be unique');
  }

  warn(request.deployment_mode === 'development', 1, 'deployment-mode', m('developmentRisk'), m('developmentRisk'));
  warn(request.deployment_mode === 'production' && !request.use_wwid, 3, 'use-wwid', m('stablePath'), m('stablePath'));
  warn(Object.values(roleDomains).some((domains) => domains.size > 0 && domains.size < Math.ceil(request.ring.replicas)), 4, 'replicas', m('fewDomains'), m('fewDomains'));

  return { request, errors, warnings, total, passed, completion: total ? Math.round((passed / total) * 100) : 0 };
}

function updateReadiness() {
  const result = collectValidation();
  document.querySelectorAll('[aria-invalid="true"]').forEach((element) => element.removeAttribute('aria-invalid'));
  result.errors.forEach((issue) => byId(issue.id)?.setAttribute('aria-invalid', 'true'));
  const diskCount = result.request.nodes.reduce((sum, node) => sum + node.disks.length, 0);
  byId('completion-percent').textContent = `${result.completion}%`;
  byId('readiness-score').textContent = `${result.completion}%`;
  byId('progress-fill').style.width = `${result.completion}%`;
  byId('header-node-count').textContent = result.request.nodes.length;
  byId('header-disk-count').textContent = diskCount;
  byId('header-missing-count').textContent = result.errors.length;
  byId('header-next-gap').textContent = result.errors[0]?.message || m('complete');
  byId('readiness-summary').textContent = result.errors.length ? m('gaps', result.errors.length) : m('complete');

  const missing = byId('missing-list');
  missing.replaceChildren();
  if (!result.errors.length) {
    const item = document.createElement('li'); item.className = 'complete'; item.textContent = `✓ ${m('complete')}`; missing.append(item);
  } else {
    result.errors.slice(0, 12).forEach((issue) => {
      const item = document.createElement('li');
      const link = document.createElement('a'); link.href = `#${issue.id}`;
      const number = document.createElement('span'); number.textContent = String(issue.step).padStart(2, '0');
      const text = document.createElement('b'); text.textContent = issue.message;
      link.append(number, text); item.append(link); missing.append(item);
    });
    if (result.errors.length > 12) {
      const item = document.createElement('li'); item.className = 'quiet'; item.textContent = `+ ${result.errors.length - 12}`; missing.append(item);
    }
  }
  const warningList = byId('warning-list'); warningList.replaceChildren();
  result.warnings.slice(0, 4).forEach((issue) => { const item = document.createElement('div'); item.textContent = `! ${issue.message}`; warningList.append(item); });

  for (let step = 1; step <= 6; step += 1) {
    const errorCount = result.errors.filter((issue) => issue.step === step).length;
    const warningCount = result.warnings.filter((issue) => issue.step === step).length;
    const output = document.querySelector(`[data-step-status="${step}"]`);
    const link = document.querySelector(`[data-step-link="${step}"]`);
    let state = 'ok'; let label = m('stepOk');
    if (step === 6) {
      if (result.errors.length) { state = 'error'; label = m('awaiting'); }
      else if (serverState.plan && (!generatedSignature || generatedSignature === formSignature())) { state = 'ok'; label = m('planSealed'); }
      else if (previewPayload?.valid && previewSignature === formSignature()) { state = 'warn'; label = m('previewValid'); }
      else { state = 'warn'; label = m('waitingPreview'); }
    } else if (errorCount) { state = 'error'; label = m('stepError', errorCount); }
    else if (warningCount) { state = 'warn'; label = m('stepWarn', warningCount); }
    output.className = `step-status ${state}`; output.textContent = label; link.dataset.state = state;
  }
  const previewReady = !localBusy && result.errors.length === 0;
  byId('preview-workspace').disabled = !previewReady;
  byId('rail-preview').disabled = !previewReady;
  const previewCurrent = previewPayload?.valid && previewSignature === formSignature();
  byId('generate-workspace').disabled = localBusy || !previewCurrent;
  if (result.errors.length) byId('workspace-action-note').textContent = m('gaps', result.errors.length);
  else if (!previewCurrent) byId('workspace-action-note').textContent = m('waitingPreview');
  else byId('workspace-action-note').textContent = m('previewOk');
  renderApplyTargets(result.request);
}

function formSignature() {
  return JSON.stringify(buildWorkspaceRequest());
}

function invalidatePreview() {
  if (previewSignature && previewSignature !== formSignature()) {
    previewPayload = null;
    previewSignature = '';
    byId('workspace-action-note').textContent = m('changed');
  }
}

function updateConditionalFields() {
  const isRust = byId('deploy-stack').value === 'rust';
  byId('auth-method').value = isRust ? 'tempauth' : 'keystone';
  const ingressSelect = byId('ingress-mode');
  const directOption = ingressSelect.querySelector('option[value="direct"]');
  const keepalivedOption = ingressSelect.querySelector('option[value="keepalived"]');
  directOption.disabled = !isRust;
  keepalivedOption.disabled = isRust;
  directOption.textContent = isRust ? 'Direct' : (language === 'zh' ? directOption.dataset.zh : english.directDisabled);
  if (isRust && ingressSelect.value === 'keepalived') ingressSelect.value = 'haproxy';
  if (!isRust && ingressSelect.value === 'direct') ingressSelect.value = 'haproxy';
  document.querySelectorAll('.python-only').forEach((label) => {
    label.style.opacity = isRust ? '0.48' : '1';
    label.querySelectorAll('input, select').forEach((input) => { input.disabled = isRust; });
  });
  const policySelect = byId('policy-type');
  policySelect.disabled = !isRust;
  policySelect.closest('label').classList.toggle('locked-field', !isRust);
  if (!isRust) policySelect.value = 'replication';
  const isEc = isRust && policySelect.value === 'erasure_coding';
  document.querySelectorAll('.rust-only').forEach((label) => {
    const show = isRust && (!label.classList.contains('ec-only') || isEc);
    label.style.opacity = show ? '1' : '0.48';
    label.querySelectorAll('input, select').forEach((input) => { input.disabled = !show; });
  });
  const isKeystone = byId('auth-method').value === 'keystone';
  document.querySelectorAll('.keystone-only').forEach((label) => {
    label.style.opacity = isKeystone ? '1' : '0.48';
    label.querySelector('input').disabled = !isKeystone;
  });
  const isKeepalived = byId('ingress-mode').value === 'keepalived';
  document.querySelectorAll('.ha-only').forEach((label) => {
    label.style.opacity = isKeepalived ? '1' : '0.48';
    label.querySelector('input').disabled = !isKeepalived;
  });
  const power = numberValue('partition-power');
  byId('partition-count').textContent = power >= 0 && power <= 32 ? `2^${power} = ${Number(2 ** power).toLocaleString()} partitions` : '—';
}

function readAdvancedConfig() {
  return Object.fromEntries(Object.entries(advancedIds).map(([key, id]) => [key, byId(id).value.trim()]));
}

function seedAdvanced(config) {
  if (advancedSeeded || !config) return;
  Object.entries(advancedIds).forEach(([key, id]) => { byId(id).value = config[key] || ''; });
  advancedSeeded = true;
}

async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-Swift-Deploy-Token': token },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
  if (!response.ok) {
    const error = new Error(payload.error || `HTTP ${response.status}`); error.payload = payload; throw error;
  }
  return payload;
}

function showError(message) {
  byId('request-error').textContent = message; byId('request-error').hidden = false;
}

function showSuccess(message) {
  byId('request-success').textContent = message; byId('request-success').hidden = false;
}

function clearNotices() {
  byId('request-error').hidden = true; byId('request-error').textContent = '';
  byId('request-success').hidden = true; byId('request-success').textContent = '';
}

async function previewWorkspace({ quiet = false } = {}) {
  clearNotices();
  const validation = collectValidation();
  if (validation.errors.length) { updateReadiness(); return null; }
  localBusy = true;
  byId('workspace-action-note').textContent = m('previewing');
  renderAll();
  try {
    const payload = await api('/api/workspace/preview', validation.request);
    previewPayload = payload;
    previewSignature = formSignature();
    renderWorkspaceResult(payload, false);
    if (!payload.valid && !quiet) showError((payload.errors || [m('previewFailed')]).map(issueMessage).join(' · '));
    return payload;
  } catch (error) {
    previewPayload = error.payload || { valid: false, errors: [error.message], warnings: [], summary: {}, files: [] };
    previewSignature = formSignature();
    renderWorkspaceResult(previewPayload, false);
    if (!quiet) showError(error.message);
    return previewPayload;
  } finally {
    localBusy = false; renderAll();
  }
}

async function generateWorkspace() {
  clearNotices();
  const signature = formSignature();
  if (!previewPayload?.valid || previewSignature !== signature) {
    const preview = await previewWorkspace();
    if (!preview?.valid) return;
  }
  localBusy = true;
  byId('workspace-action-note').textContent = m('generating');
  renderAll();
  try {
    const request = buildWorkspaceRequest();
    const payload = await api('/api/workspace/generate', request);
    generatedPayload = payload;
    generatedSignature = signature;
    previewPayload = { ...previewPayload, ...payload, valid: Boolean(payload.ok ?? true) };
    if (payload.inventory) byId('inventory-path').value = payload.inventory;
    if (payload.playbook) byId('playbook-path').value = payload.playbook;
    if (payload.plan) byId('plan-path').value = payload.plan;
    if (payload.bundle) byId('bundle-path').value = payload.bundle;
    if (payload.known_hosts) byId('known-hosts-path').value = payload.known_hosts;
    serverState.audit = null; serverState.inventory = null; serverState.plan = null; serverState.preflight = null; resetApproval();
    renderWorkspaceResult(payload, true);
    await runGeneratedPipeline();
    showSuccess(m('generated', payload.project_root || request.project_name));
  } catch (error) {
    if (error.payload?.errors || error.payload?.warnings) renderWorkspaceResult(error.payload, false);
    const details = error.payload?.errors?.map(issueMessage).join(' · ');
    showError(details || error.message);
  } finally {
    localBusy = false; renderAll();
  }
}

async function runGeneratedPipeline() {
  for (const [kind, note] of [['audit', 'pipelineAudit'], ['validate', 'pipelineValidate'], ['plan', 'pipelinePlan']]) {
    byId('workspace-action-note').textContent = m(note);
    renderPipeline();
    await api(endpointByAction[kind], readAdvancedConfig());
    const snapshot = await waitForJob(kind);
    Object.assign(serverState, snapshot);
    if (snapshot.job?.state === 'failed') throw new Error(snapshot.job.message || `${kind} failed`);
  }
}

async function waitForJob(kind) {
  for (;;) {
    await new Promise((resolve) => setTimeout(resolve, 350));
    const snapshot = await api('/api/state');
    Object.assign(serverState, snapshot);
    renderPipeline(); renderActivity();
    if (snapshot.job?.kind === kind && snapshot.job.state !== 'running') return snapshot;
  }
}

async function runLegacyAction(kind) {
  clearNotices(); localBusy = true; renderAll();
  const body = readAdvancedConfig();
  if (kind === 'apply') {
    Object.assign(body, {
      confirm_digest: byId('confirm-digest').value.trim(), approval: byId('approval-phrase').value.trim(),
      allow_disk_wipe: byId('allow-disk-wipe').checked, allow_firewall: byId('allow-firewall').checked, allow_ssh_reconfigure: byId('allow-ssh').checked, allow_host_reconfigure: byId('allow-host-reconfigure').checked,
    });
  }
  try {
    await api(endpointByAction[kind], body);
    if (kind !== 'apply') Object.assign(serverState, await waitForJob(kind));
    else await fetchState(false);
  } catch (error) { showError(error.message); }
  finally { localBusy = false; renderAll(); }
}

function normalizeFiles(files) {
  if (Array.isArray(files)) return files.map((file, index) => typeof file === 'string' ? { path: file, content: '' } : { path: file.path || file.name || `file-${index + 1}`, content: file.content || file.preview || '' });
  if (files && typeof files === 'object') return Object.entries(files).map(([path, value]) => typeof value === 'string' ? { path, content: value } : { path, content: value?.content || value?.preview || '' });
  return [];
}

function issueMessage(issue) {
  return typeof issue === 'string' ? issue : (issue?.message || JSON.stringify(issue));
}

function redactSecrets(content) {
  return String(content || '')
    .replace(/^(\s*[^#\n]*(?:password|passwd|pass|secret|auth_pass|hash_path_(?:prefix|suffix))[^:\n]*:\s*).+$/gim, '$1***REDACTED***')
    .replace(/("(?:admin_password|password|secret|vrrp_auth_pass)"\s*:\s*)"[^"]*"/gi, '$1"***REDACTED***"');
}

function renderWorkspaceResult(payload, generated) {
  const container = byId('workspace-result'); container.replaceChildren();
  const summary = payload?.summary || {};
  const files = normalizeFiles(payload?.files);
  const request = buildWorkspaceRequest();
  const diskCount = request.nodes.reduce((sum, node) => sum + node.disks.filter(Boolean).length, 0);
  const summaryValues = [
    [language === 'zh' ? '状态' : 'Status', generated ? (language === 'zh' ? '已生成' : 'generated') : (payload?.valid ? (language === 'zh' ? '可生成' : 'ready') : (language === 'zh' ? '需修正' : 'blocked'))],
    [language === 'zh' ? '节点 / 磁盘' : 'Nodes / disks', `${summary.node_count ?? summary.nodes ?? request.nodes.length} / ${summary.disk_count ?? summary.disks ?? diskCount}`],
    [language === 'zh' ? '入口' : 'Ingress', summary.ingress ?? summary.endpoint ?? `${request.ingress.http_mode}://${request.ingress.auth_url_ip || '—'}:${request.ingress.swift_port}`],
    [m('files'), String(files.length)],
  ];
  const facts = document.createElement('div'); facts.className = 'preview-summary';
  summaryValues.forEach(([label, value]) => { const box = document.createElement('div'); const key = document.createElement('span'); key.textContent = label; const data = document.createElement('strong'); data.textContent = value; box.append(key, data); facts.append(box); });
  container.append(facts);
  const errors = payload?.errors || []; const warnings = payload?.warnings || [];
  if (errors.length || warnings.length) {
    const list = document.createElement('ul'); list.className = 'preview-messages';
    errors.forEach((message) => { const item = document.createElement('li'); item.className = 'error'; item.textContent = issueMessage(message); list.append(item); });
    warnings.forEach((message) => { const item = document.createElement('li'); item.className = 'warning'; item.textContent = issueMessage(message); list.append(item); });
    container.append(list);
  }
  if (files.length) {
    const previews = document.createElement('div'); previews.className = 'file-previews';
    files.forEach((file, index) => {
      const details = document.createElement('details'); if (index === 0) details.open = true;
      const heading = document.createElement('summary'); heading.textContent = file.path;
      const content = document.createElement('pre'); content.textContent = redactSecrets(file.content) || (language === 'zh' ? '文件将在生成时写入；预览未返回正文。' : 'The file will be written during generation; no body was returned in preview.');
      details.append(heading, content); previews.append(details);
    });
    container.append(previews);
  }
}

function setDot(id, status) { byId(id).className = `status-dot ${status}`; }

function renderPipeline() {
  const running = serverState.job?.state === 'running' ? serverState.job.kind : '';
  const audit = serverState.audit;
  setDot('source-dot', running === 'audit' ? 'busy' : audit ? 'good' : 'idle');
  byId('audit-result').textContent = running === 'audit' ? m('running') : audit ? m('auditOk', audit) : (language === 'zh' ? '未运行' : 'not run');
  const inventory = serverState.inventory;
  const inventoryWarn = (inventory?.warnings || []).length || inventory?.sample;
  setDot('inventory-dot', running === 'validate' ? 'busy' : inventory ? (inventoryWarn ? 'warn' : 'good') : 'idle');
  byId('inventory-result').textContent = running === 'validate' ? m('running') : inventory ? m('inventoryOk', inventory) : (language === 'zh' ? '未运行' : 'not run');
  const plan = serverState.plan;
  setDot('plan-dot', running === 'plan' ? 'busy' : plan ? 'good' : 'idle');
  byId('plan-result').textContent = running === 'plan' ? m('running') : plan ? m('planOk', plan) : (language === 'zh' ? '未运行' : 'not run');
  const preflight = serverState.preflight;
  setDot('preflight-dot', running === 'preflight' ? 'busy' : preflight ? (preflight.ok ? 'good' : 'bad') : 'idle');
  byId('preflight-result').textContent = running === 'preflight' ? m('running') : preflight ? m(preflight.ok ? 'preflightOk' : 'preflightBlocked', preflight) : (language === 'zh' ? '未运行' : 'not run');
  const preflightDetails = byId('preflight-details');
  preflightDetails.replaceChildren();
  const failedHosts = preflight?.hosts?.filter((host) => !host.ok) || [];
  preflightDetails.hidden = !failedHosts.length;
  failedHosts.forEach((host) => {
    const title = document.createElement('b'); title.textContent = `${host.host} · ${host.ssh_host || 'SSH'}`;
    const list = document.createElement('ul');
    (host.errors || []).forEach((error) => { const item = document.createElement('li'); item.textContent = error; list.append(item); });
    preflightDetails.append(title, list);
  });
  byId('audit-action').disabled = localBusy || Boolean(running);
  byId('validate-action').disabled = localBusy || Boolean(running);
  byId('plan-action').disabled = localBusy || Boolean(running);
  byId('preflight-action').disabled = localBusy || Boolean(running) || !plan;
  renderPlan();
}

function renderPlan() {
  const plan = serverState.plan;
  byId('seal').hidden = !plan;
  if (!plan) { byId('risk-readout').replaceChildren(); return; }
  byId('plan-digest').textContent = groupDigest(plan.digest);
  if (lastDigest && lastDigest !== plan.digest) resetApproval();
  lastDigest = plan.digest;
  const risks = plan.risks || [];
  const container = byId('risk-readout'); container.replaceChildren();
  const checkboxByRisk = { disk_wipe: 'allow-disk-wipe', firewall: 'allow-firewall', ssh_reconfigure: 'allow-ssh', host_reconfigure: 'allow-host-reconfigure' };
  for (const [key, label] of [['disk_wipe', 'disk wipe'], ['firewall', 'firewall'], ['ssh_reconfigure', 'ssh reconfigure'], ['host_reconfigure', 'host reconfigure']]) {
    const required = risks.includes(key);
    const item = document.createElement('span'); item.className = required ? 'required' : ''; item.textContent = `${required ? '●' : '○'} ${label}`; container.append(item);
    const checkbox = byId(checkboxByRisk[key]);
    checkbox.disabled = !required; checkbox.closest('label').classList.toggle('required', required); if (!required) checkbox.checked = false;
  }
}

function groupDigest(digest = '') { return digest.match(/.{1,8}/g)?.join(' ') || digest; }

function renderApplyTargets(request = buildWorkspaceRequest()) {
  const container = byId('apply-targets'); container.replaceChildren();
  const plannedHosts = serverState.plan?.host_names || [];
  if (!plannedHosts.length && !request.nodes.length) { container.textContent = m('noTargets'); return; }
  const table = document.createElement('table'); table.className = 'target-table';
  const head = document.createElement('thead'); const row = document.createElement('tr');
  [m('targetHost'), m('targetRoles'), m('targetDisks')].forEach((label) => { const cell = document.createElement('th'); cell.textContent = label; row.append(cell); }); head.append(row); table.append(head);
  const body = document.createElement('tbody');
  const nodesByManagement = new Map(request.nodes.map((node) => [node.management_ip, node]));
  const targets = plannedHosts.length ? plannedHosts.map((host) => {
    const node = nodesByManagement.get(host);
    return {
      name: node?.name || host,
      address: node?.address || host,
      roles: node?.roles || serverState.plan?.host_roles?.[host] || [],
      disks: serverState.plan?.host_disks?.[host] || node?.disks || [],
    };
  }) : request.nodes;
  targets.forEach((node) => { const row = document.createElement('tr'); const host = document.createElement('td'); host.textContent = `${node.name || '—'} · ${node.address || '—'}`; const roles = document.createElement('td'); roles.textContent = node.roles.join(', ') || '—'; const disks = document.createElement('td'); disks.textContent = node.disks.join(', ') || (language === 'zh' ? '无' : 'none'); row.append(host, roles, disks); body.append(row); });
  table.append(body); container.append(table);
}

function renderApply() {
  const plan = serverState.plan;
  const config = readAdvancedConfig();
  const sample = Boolean(serverState.inventory?.sample) || config.inventory.replaceAll('\\', '/').split('/').includes('config_sample');
  const staleGenerated = Boolean(generatedSignature && generatedSignature !== formSignature());
  const risks = plan?.risks || [];
  const selected = { disk_wipe: byId('allow-disk-wipe').checked, firewall: byId('allow-firewall').checked, ssh_reconfigure: byId('allow-ssh').checked, host_reconfigure: byId('allow-host-reconfigure').checked };
  let guard = '';
  if (localBusy || serverState.job?.state === 'running') guard = m('running');
  else if (!plan) guard = m('needPlan');
  else if (staleGenerated) guard = m('needGenerate');
  else if (sample) guard = m('sampleBlocked');
  else if (!serverState.preflight?.ok) guard = m('needPreflight');
  else if (byId('confirm-digest').value.trim() !== plan.digest) guard = m('needDigest');
  else if (byId('approval-phrase').value.trim() !== 'APPLY') guard = m('needPhrase');
  else if (risks.some((risk) => !selected[risk])) guard = m('needRisk');
  byId('apply-guard').textContent = guard || m('readyApply');
  byId('apply-action').disabled = Boolean(guard);
  if (serverState.job?.kind === 'apply') setDot('apply-dot', serverState.job.state === 'running' ? 'busy' : serverState.job.state === 'failed' ? 'bad' : 'good');
  else setDot('apply-dot', plan && !sample && !staleGenerated ? 'warn' : 'idle');
  const result = byId('execution-result');
  if (serverState.execution) { result.hidden = false; result.textContent = `changed ${serverState.execution.changed} · unchanged ${serverState.execution.unchanged} · skipped ${serverState.execution.skipped} · failed ${serverState.execution.failed}`; }
  else { result.hidden = true; result.textContent = ''; }
}

function renderActivity() {
  const job = serverState.job;
  byId('job-state').textContent = job ? `${job.kind} · ${job.state}` : (language === 'zh' ? '空闲' : 'idle');
  const log = byId('activity-log'); log.replaceChildren();
  if (!serverState.log?.length) { const empty = document.createElement('li'); empty.className = 'quiet'; empty.textContent = '—'; log.append(empty); return; }
  serverState.log.forEach((entry) => {
    const item = document.createElement('li'); if (!entry.ok) item.className = 'bad';
    const time = document.createElement('span'); time.className = 'log-time'; time.textContent = new Date(entry.time_unix * 1000).toLocaleTimeString([], { hour12: false });
    const kind = document.createElement('span'); kind.className = 'log-kind'; kind.textContent = entry.kind;
    const message = document.createElement('span'); message.className = 'log-message'; message.textContent = entry.message;
    item.append(time, kind, message); log.append(item);
  });
}

function renderAll() {
  updateConditionalFields();
  updateReadiness();
  renderPipeline();
  renderApply();
  renderActivity();
  byId('workspace-form').setAttribute('aria-busy', String(localBusy || serverState.job?.state === 'running'));
}

function resetApproval() {
  byId('confirm-digest').value = ''; byId('approval-phrase').value = '';
  byId('allow-disk-wipe').checked = false; byId('allow-firewall').checked = false; byId('allow-ssh').checked = false; byId('allow-host-reconfigure').checked = false;
}

async function copyDigest() {
  const digest = serverState.plan?.digest; if (!digest) return;
  try { await navigator.clipboard.writeText(digest); byId('copy-digest').textContent = m('copied'); setTimeout(() => { byId('copy-digest').textContent = language === 'zh' ? '复制摘要' : 'Copy digest'; }, 1200); }
  catch (_) { const range = document.createRange(); range.selectNodeContents(byId('plan-digest')); const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range); }
}

async function fetchState(schedule = true) {
  try {
    Object.assign(serverState, await api('/api/state'));
    seedAdvanced(serverState.config);
    renderAll();
  } catch (error) {
    if (!localBusy) showError(`${language === 'zh' ? '状态读取失败' : 'State request failed'}: ${error.message}`);
  }
  clearTimeout(pollTimer);
  if (schedule) pollTimer = setTimeout(fetchState, serverState.job?.state === 'running' ? 900 : 3500);
}

function updateNodeFromInput(target) {
  const index = Number(target.dataset.nodeIndex);
  const node = nodes[index]; if (!node) return;
  if (target.dataset.role) {
    node.roles = target.checked ? [...new Set([...node.roles, target.dataset.role])] : node.roles.filter((role) => role !== target.dataset.role);
    renderStorageEditors();
  } else if (target.dataset.diskIndex !== undefined) {
    node.disks[Number(target.dataset.diskIndex)] = target.value;
  } else if (target.dataset.nodeField) {
    const numeric = ['ssh_port', 'region', 'zone', 'keepalived_priority'].includes(target.dataset.nodeField);
    const previousStorage = node.storage_ip;
    node[target.dataset.nodeField] = numeric ? (target.value === '' ? '' : Number(target.value)) : target.value;
    if (target.dataset.nodeField === 'storage_ip') {
      const isRust = byId('deploy-stack').value === 'rust';
      if (!isRust || !node.replication_ip || node.replication_ip === previousStorage) {
        node.replication_ip = target.value;
        const replicationInput = byId(`node-${index}-replication_ip`);
        if (replicationInput) replicationInput.value = node.replication_ip;
      }
    }
    if (['name', 'address'].includes(target.dataset.nodeField)) {
      document.querySelector(`[data-node-caption="${index}"]`).textContent = node.name || node.address || '—';
      const storageTitle = document.querySelector(`[data-storage-panel="${index}"] .storage-title strong`);
      if (storageTitle) storageTitle.textContent = m('storageFor', node.name || m('node', index + 1));
    }
  }
  invalidatePreview(); renderAll();
}

byId('workspace-form').addEventListener('submit', (event) => event.preventDefault());
byId('workspace-form').addEventListener('input', (event) => {
  if (event.target.dataset.nodeIndex !== undefined) updateNodeFromInput(event.target);
  else {
    if (Object.values(advancedIds).includes(event.target.id)) serverState.preflight = null;
    invalidatePreview(); renderAll();
  }
});
byId('workspace-form').addEventListener('change', (event) => {
  if (event.target.dataset.nodeIndex !== undefined && event.target.dataset.role) updateNodeFromInput(event.target);
  else {
    if (event.target.id === 'ingress-mode') {
      const next = event.target.value; const port = numberValue('swift-port');
      if (ingressPrevious === 'direct' && next !== 'direct' && port === 8080) byId('swift-port').value = '5050';
      if (ingressPrevious !== 'direct' && next === 'direct' && port === 5050) byId('swift-port').value = '8080';
      ingressPrevious = next;
      renderStorageEditors();
    }
    if (event.target.id === 'deploy-stack') renderStorageEditors();
    invalidatePreview(); renderAll();
  }
});

byId('add-node').addEventListener('click', () => { nodes.push(newNode(nodes.length + 1)); renderNodeEditors(); renderStorageEditors(); invalidatePreview(); renderAll(); });
byId('node-list').addEventListener('click', (event) => {
  const button = event.target.closest('[data-remove-node]'); if (!button) return;
  nodes.splice(Number(button.dataset.removeNode), 1); renderNodeEditors(); renderStorageEditors(); invalidatePreview(); renderAll();
});
byId('node-storage-list').addEventListener('click', (event) => {
  const copy = event.target.closest('[data-copy-networks]');
  if (copy) {
    const index = Number(copy.dataset.copyNetworks); const node = nodes[index]; const source = node.management_ip || node.address;
    node.management_ip = source; node.storage_ip = source; node.replication_ip = source; if (!node.business_ip) node.business_ip = source;
    renderStorageEditors(); invalidatePreview(); renderAll(); return;
  }
  const add = event.target.closest('[data-add-disk]');
  if (add) { nodes[Number(add.dataset.addDisk)].disks.push(''); renderStorageEditors(); invalidatePreview(); renderAll(); return; }
  const remove = event.target.closest('[data-remove-disk]');
  if (remove) { const [nodeIndex, diskIndex] = remove.dataset.removeDisk.split(':').map(Number); nodes[nodeIndex].disks.splice(diskIndex, 1); renderStorageEditors(); invalidatePreview(); renderAll(); }
});

document.querySelectorAll('[data-language]').forEach((button) => button.addEventListener('click', () => { language = button.dataset.language; localStorage.setItem('swift-deploy-language', language); applyLanguage(); }));
byId('preview-workspace').addEventListener('click', () => previewWorkspace());
byId('rail-preview').addEventListener('click', () => { byId('step-review').scrollIntoView({ block: 'start' }); previewWorkspace(); });
byId('generate-workspace').addEventListener('click', generateWorkspace);
byId('audit-action').addEventListener('click', () => runLegacyAction('audit'));
byId('validate-action').addEventListener('click', () => runLegacyAction('validate'));
byId('plan-action').addEventListener('click', () => runLegacyAction('plan'));
byId('preflight-action').addEventListener('click', () => runLegacyAction('preflight'));
byId('apply-action').addEventListener('click', () => runLegacyAction('apply'));
byId('copy-digest').addEventListener('click', copyDigest);
for (const id of ['confirm-digest', 'approval-phrase', 'allow-disk-wipe', 'allow-firewall', 'allow-ssh', 'allow-host-reconfigure']) byId(id).addEventListener('input', renderApply);

seedStaticTranslations();
applyLanguage();
fetchState();
