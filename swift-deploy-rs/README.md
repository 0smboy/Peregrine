# swift-deploy-rs

`swift-deploy-rs` 是 `swift_ansible_v3_20230725` 的有界、Rust 原生部署执行器。
它保留上游 playbook、role、template 和 file 资产，但运行时不依赖 Python、
Ansible 或 `ansible-playbook`。未知模块、未知任务语法和被修改过的计划都会关闭式
失败。

## 已完成的范围

- 选定 2023-07-25 源码提交的 v3，而不是被重新打包过的旧 2.1.0。
- 审计并覆盖 v3 的 57 个 task/handler YAML、413 个叶子任务和 28 个执行模块。
- 解析 INI inventory、host/group vars、range、children，以及 v3 的 security/ring
  配置生成逻辑。
- 展开 play、role、静态 include、block、loop、handler、register、delegate 和
  `run_once`，生成确定性的 JSON 计划。
- 使用 SHA-256 密封计划；`apply` 前再次校验计划、bundle、inventory 和精确摘要。
- 磁盘擦除、防火墙和 SSH 重配置分别需要独立授权。
- 通过严格 OpenSSH 连接；主机密钥校验默认开启，inventory 密码默认拒绝。
- 提供内嵌于同一个 Rust 二进制的响应式 Web 控制台，不依赖 Node.js 或外部前端服务。

完整边界见 [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)，来源选择证据见
[docs/COMPARISON.md](docs/COMPARISON.md)。

## Rocky 9 快速使用

构建：

```bash
cd /root/swift-rewrite/work/swift-deploy-rs
cargo build --release --locked
```

### UI 控制台

AWS 控制机已安装 loopback-only 的 systemd 服务。它不会打开公网端口。先在 Mac
建立 SSH 隧道：

```bash
ssh -L 8788:127.0.0.1:8788 root@18.232.108.188
```

保持该终端连接，再访问 `http://127.0.0.1:8788`。控制台按以下顺序工作：

```text
source audit -> inventory validate -> sealed plan -> review -> guarded apply
```

示例 inventory 可以审计、校验和生成计划，但 UI 和后端都会永久拒绝对它执行
Apply。真实执行还要求完整计划摘要、字面量 `APPLY`，以及磁盘擦除、防火墙、SSH
重配置三类风险的独立授权。详细操作和安全边界见 [docs/UI.md](docs/UI.md)。

服务管理：

```bash
systemctl status swift-deploy-ui
journalctl -u swift-deploy-ui -f
```

也可以不使用 systemd，直接前台启动：

```bash
./target/release/swift-deploy ui \
  --bind 127.0.0.1 \
  --port 8788 \
  --bundle bundle \
  --inventory bundle/config_sample/swift_hosts \
  --playbook bundle/swift.yml \
  --plan /var/lib/swift-deploy/swift-plan.json
```

### CLI

先审计内置 v3 bundle：

```bash
./target/release/swift-deploy audit --bundle bundle
./target/release/swift-deploy modules
```

真实配置应放在一个独立目录中，inventory 同级保留 `group_vars/` 和
`host_vars/`。先做完全离线的校验和计划：

```bash
./target/release/swift-deploy validate \
  --inventory /root/swift-config/swift_hosts

./target/release/swift-deploy plan \
  --bundle bundle \
  --inventory /root/swift-config/swift_hosts \
  --playbook bundle/swift.yml \
  --output /root/swift-config/swift-plan.json
```

人工审阅计划后，从 JSON 的 `digest` 字段取得摘要。只有摘要、bundle 和 inventory
都未变化，并且所需风险授权全部给出，才会开始连接主机：

```bash
./target/release/swift-deploy apply \
  --bundle bundle \
  --inventory /root/swift-config/swift_hosts \
  --plan /root/swift-config/swift-plan.json \
  --confirm-digest '<完整 digest>' \
  --known-hosts /root/.ssh/known_hosts \
  --allow-disk-wipe \
  --allow-firewall \
  --allow-ssh-reconfigure
```

不要对 `bundle/config_sample/swift_hosts` 执行 `apply`。它只用于解析和计划测试，
包含示例地址及待替换值。

所有命令都支持 `--json`，便于接入 CI 或审批系统。默认使用 SSH key/agent。
只有明确传入 `--allow-password` 且控制机安装了 `sshpass` 时才允许密码认证。

## 安全工作流

```text
audit -> validate -> plan -> 人工审阅 digest -> apply
                                  |
                                  +-> disk / firewall / ssh 各自授权
```

`validate` 和 `plan` 不接触远端主机。`apply` 在任何 SSH 连接之前完成以下校验：

1. 计划本身的密封摘要有效。
2. `--confirm-digest` 与计划完全一致。
3. bundle 指纹未变。
4. inventory、`group_vars/`、`host_vars/` 指纹未变。
5. 计划需要的高风险能力均已单独授权。

## 开发验证

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

当前发布物在 Rocky Linux 9 x86_64 上构建和验证。生产 Swift 多节点收敛仍应先在
一套可回滚的受控集群中执行；项目没有把示例 inventory 当作真实环境运行。
