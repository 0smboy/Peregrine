# 交付与验收报告

## 结论

主线版本是 `swift_ansible_v3_20230725`。Rust 重写已经在用户提供的 AWS Rocky
Linux 9.7 x86_64 主机上完成、测试和构建。它不调用 Ansible，能够审计、校验、
生成密封计划，并在计划与三类风险授权都通过后用严格 OpenSSH 执行。

在此基础上，`feature/lab-ui` 增加了一个与 CLI 共用安全状态机的 Rust 原生 Web
控制台。HTML、CSS、JavaScript 都嵌入同一个二进制；服务只监听
`127.0.0.1:8788`，通过 SSH 隧道访问，不开放 AWS 公网端口。
生产运行副本位于 `/usr/local/bin/swift-deploy` 和 `/opt/swift-deploy/bundle`，避免
Rocky 9 SELinux 阻止 systemd 从 root home 执行；源码目录不承担常驻服务运行。

## 交付树

```text
swift-deploy-rs/
├── target/release/swift-deploy  # Rocky 9 发布二进制
├── bundle/                      # 已净化的 v3 声明式部署资产
├── src/                         # Rust inventory/planner/executor/modules/CLI
├── web/                         # 嵌入式响应式 UI
├── deploy/                      # Rocky 9 systemd 服务定义
├── tests/                       # bundle、兼容、执行器、CLI、UI 测试
└── docs/
    ├── COMPARISON.md            # 两个归档的选择证据
    ├── COMPATIBILITY.md         # 精确支持边界与非目标
    ├── UI.md                    # UI 访问、工作流和安全门
    └── HANDOFF.md               # 本报告
```

## 已验证

- v3 来源提交时间比 2.1.0 新；2.1.0 的 2024 文件时间只是重新打包时间。
- bundle 审计：57 个 task/handler YAML、413 个叶子任务、28 个执行模块、0 个
  未支持模块、0 个解析错误。
- 真实 v3 sample inventory 可以被 Rust 解析，并可生成超过 300 个展开任务的
  密封计划。
- 磁盘擦除、防火墙、SSH 重配置会被识别为三个相互独立的风险能力。
- 错误 digest、变化后的 bundle/inventory、缺少风险授权都会在任何主机连接前
  拒绝执行。
- 28 个模块都经过 dispatcher 测试；文件编辑在 Rust 中完成，OpenSSH 参数保留
  主机密钥校验。
- UI 的审计、校验、计划和受保护执行 API 均通过 Rust 集成测试；POST 请求需要
  每个进程随机生成的防跨站令牌。
- 真实 Chrome 已跑通审计、校验、密封计划、摘要复制和中英文切换；桌面与移动端
  无横向溢出，浏览器控制台无错误，网络请求无失败。
- 示例 inventory 的 Apply 按钮和后端接口均拒绝执行；摘要、确认词和三类独立
  风险授权缺一不可。
- Rocky 9 上 `cargo fmt --check`、严格 Clippy、完整测试和 release build 均通过。

## 没有冒充验证的部分

这台 AWS 机器是控制机，不是一套可销毁和重建的多节点 Swift 集群。因此没有把
示例 inventory 指向的 `192.168.2.*` 地址执行真实部署，也没有在单机上伪造磁盘
擦除、防火墙和 SSH 重配置成功。生产级“Swift 最终收敛”仍需要一套可回滚的真实
集群做一次受控验收。

## 如何看结果

在 AWS 主机：

```bash
cd /root/swift-rewrite/work/swift-deploy-rs
systemctl status swift-deploy-ui
./target/release/swift-deploy --help
./target/release/swift-deploy audit --bundle bundle
./target/release/swift-deploy validate \
  --inventory bundle/config_sample/swift_hosts
```

在 Mac 建立隧道即可打开 UI：

```bash
ssh -L 8788:127.0.0.1:8788 root@18.232.108.188
```

然后访问 `http://127.0.0.1:8788`。源码分支是 `feature/lab-ui`；CLI 基线保留在
`rewrite/rust-native`。

## 下一步最小动作

只需准备一份真实但可先脱敏的配置目录，目录中放 `swift_hosts`、`group_vars/` 和
`host_vars/`。先运行：

```bash
./target/release/swift-deploy validate --inventory /path/to/swift_hosts
./target/release/swift-deploy plan \
  --bundle bundle \
  --inventory /path/to/swift_hosts \
  --playbook bundle/swift.yml \
  --output /path/to/swift-plan.json
```

这两步都不会接触部署节点。审阅生成计划后，再选择一个可回滚的测试集群执行
一次 `apply`。如果失败，保留计划 JSON 和 CLI 错误即可继续收敛，不需要从头猜测
哪个 playbook 或模块出了问题。

## 基础设施提醒

AWS 主机当前 SSH 会提示会话未协商后量子密钥交换。这不影响本次构建或测试，
但属于控制机的后续加固项；Rust 工具没有关闭主机密钥检查来绕过它。
