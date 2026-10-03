# 9. 浏览器

cursor-ide-browser 没能打开标签：`browser_navigate` 返回 “No browser tab available”，新建的 view 随即 “Browser view not found”。没有用截图代替点击。

替代：本机到 swift4 的 `ssh -L 9000:127.0.0.1:9000`，然后用本机 Chrome headless（远程调试端口）真正提交表单、点击按钮，并记录 `Network.responseReceived`。密钥只放进浏览器内存，脚本结束后删除，没有写入本目录。

| id | 方法 | 状态码 | 判定 |
|---|---|---|---|
| B-login-page | 打开 `/login` | 页面 200 | PASS。标题 Sign in · Swift Console |
| B-login-bad | 提交错误密钥 | 仍在 `/login` | PASS。`.err.on` 出现 |
| B-login-good | 提交正确登录 | 进入 `/files` | PASS。h1 Files |
| B-logout | 点击退出 | 回到 `/login` | PASS |
| B-relogin | 再登录 | `/files` | PASS |
| B-lang | 点击中文，再打开 `/files` | 导航完成 | PASS。`html lang` 两次都是 zh-CN，h1 为「文件」。刷新后仍是中文 |
| B-theme | 点击浅色，再打开 `/files` | 导航完成 | PASS。`data-theme` 点击后和再次加载都是 light |
| B-files-no-bucket | 文件页正文 | n/a | PASS（负面）。没有 `console-accept-20261002`。进桶、下载、分享 TempURL 没有对象可点，记 BLOCKED，不是死按钮 |
| B-files-trash | 打开 `/files/trash` | 200 | PASS。h1 回收站，正文「回收站是空的。」 |
| B-files-account | 打开 `/files/account` | 200 | PASS。h1 账户。已用 0 B、0 容器。没有改配额 |
| B-files-search | 打开 `/files/search` | 200 | PASS。已索引 0 个对象 |
| B-files-users | 打开 `/files/users` | 200 | PASS。h1「出错了」，正文「你没有访问租户与用户的权限。」 |
| B-mon-tabs | `/monitor` 上的 tab | 200 | PASS。6 个：集群总览、后端服务、存储节点、磁盘与设备、副本复制、服务健康 |
| B-mon-clicks | 逐个点击这 6 个 tab | 每个 panel 200 | PASS。每次点击都发出 `/monitor/api/panel?id=...`。不是死按钮。四节点是否 up 以 API 为准：nodes_up 仍是 0，见 03 |
| B-deploy-shell | 打开 `/deploy` | 200 | PASS。1 个 iframe，`GET /api/state` 200 |
| B-deploy-apply | 没有点击「执行密封计划」 | n/a | PASS（边界）。`/deploy/` HTML 里有按钮「校验 inventory」「生成计划」「执行密封计划」。执行没有点 |
| B-test-history | 打开 `/test` | `GET /test/api/runs` 200 | PASS。按钮含「开始测试」。没有点它，没有第二发压测 |
| B-lab-index | 打开 `/lab` | 200 | PASS（卡片）/ FAIL（可达性，与 API 一致）。12 个 href。正文 `0 of 4 nodes reachable` |
| B-lab-cards | 依次打开 12 张卡片 | 每页路径等于 href | PASS。标题：RingScope、策略经济学、对象胶囊、墓碑博物馆、接口对照、故障街机、节点宕机演练、Agent 仓库、修复债务指数、过期幽灵观察站、剖析架构地图、集群基因组实验室。没有落到登录页 |
| B-ring-part | Ring 页把 part 输入改成 1 并提交 | 随后 URL `part=1` | PASS。控件发出了导航，不是死的。没有再停任何节点 |

语言和主题的点击没有单独的 XHR（它们是表单提交整页），页面结果变了并在下一次加载还在。
