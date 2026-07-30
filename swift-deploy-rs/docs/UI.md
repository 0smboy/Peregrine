# Swift Deploy Rust UI

## 访问

UI 只监听 AWS 控制机的 `127.0.0.1:8788`。不要为它开放 Security Group 端口。
在本机建立 SSH 隧道：

```bash
ssh -L 8788:127.0.0.1:8788 root@18.232.108.188
```

保持连接后访问 `http://127.0.0.1:8788`。

## 操作顺序

1. **source audit** 检查 bundle 指纹、任务数和模块覆盖，不连接任何主机。
2. **inventory** 解析 host/group vars、占位符和认证风险，不连接任何主机。
3. **sealed plan** 展开 play、role、loop 和 handler，生成 SHA-256 密封计划。
4. 人工审阅计划摘要和风险能力。
5. **execution** 仅在全部证明一致后建立 SSH 连接。

## Apply 安全门

后端会独立校验每一项，前端禁用按钮不是安全边界：

- 示例 inventory 永久禁止 Apply。
- 计划内部密封摘要必须有效。
- 用户粘贴的 64 位摘要必须精确一致。
- bundle 和 inventory 指纹必须仍与计划一致。
- 确认词必须是区分大小写的 `APPLY`。
- 计划若涉及 DiskWipe、Firewall、SshReconfigure，必须分别授权。
- inventory 密码不会通过 UI 放行；默认只允许 SSH key 或 agent。
- 每个 POST 请求必须携带当前进程的随机防跨站令牌。

## 运行模型

- 单个 Rust 二进制提供静态 UI、JSON API 和部署执行器。
- 不使用 shell 拼接命令；UI 以结构化参数调用同一可执行文件。
- 同一时间只运行一个 job，状态和活动记录可在页面直接看到。
- 页面发送严格 CSP、安全响应头，并限制请求头和请求体大小。
- 服务绑定非 loopback 地址时会关闭式失败。

## 服务

```bash
systemctl status swift-deploy-ui
journalctl -u swift-deploy-ui -f
systemctl restart swift-deploy-ui
```

计划默认写入 `/var/lib/swift-deploy/swift-plan.json`，目录权限由 systemd 的
`StateDirectory` 管理。release 二进制安装在 `/usr/local/bin/swift-deploy`，运行时
bundle 安装在 `/opt/swift-deploy/bundle`；源码和开发构建仍保留在
`/root/swift-rewrite/work/swift-deploy-rs`。

## 当前验证边界

示例配置的审计、校验和计划已在真实浏览器中完成。AWS 控制机不是 Swift
多节点测试集群，因此没有对示例中的 `192.168.2.*` 地址执行部署，也没有伪造
磁盘擦除、防火墙或 SSH 重配置成功。生产 Apply 应先使用一套可回滚的测试集群。
