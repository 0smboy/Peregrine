# 3–5. Monitor、Deploy、Lab

会话是 Console Cookie。密钥未记录。

## Monitor

`GET /monitor/api/dash` 200。六个 dashboard：overview、backends、nodes、storage、replication、services。

| id | 方法 | 状态码 | 判定 |
|---|---|---|---|
| M-page | `GET /monitor` | 200 | PASS |
| M-dash | `GET /monitor/api/dash` | 200 | PASS。六块都在 |
| M-nodes_up | `GET /monitor/api/panel?id=nodes_up&range=3600` | 200 | FAIL。`value` 是 0.0，不是 4，序列里也分不出 swift1–4 |
| M-svc_grid | `GET /monitor/api/panel?id=svc_grid` | 200 | FAIL。swift1–4 的 reachable 都是 false，proxy/object/container/account 都是 unreachable |
| M-dev_used | panel `dev_used` | 200 | WARN。`series: []` |
| M-fs_used | panel `fs_used` | 200 | WARN。`series: []` |
| M-repl_kind | panel `repl_kind` | 200 | WARN。`series: []`。复制面板没有点 |
| M-backend_err | panel `backend_err` | 200 | PASS。series 有点（数值是 0） |
| M-log_err | panel `log_err` | 200 | WARN。`metrics temporarily unavailable`。Loki 侧没有日志点 |
| M-log_vol | panel `log_vol` | 200 | WARN。同上 |
| M-svc_events | panel `svc_events` | 200 | WARN。43 字节，无事件序列 |
| M-unknown | panel `id=not-a-panel` | 200 | PASS。`{"error":"unknown panel"}` |
| M-other-panels | reqs、err5xx、p99、reqs_method、reqs_status、latency、err_ratio、nodes_up_range、backend_reqs、backend_p99、backend_status、cpu、mem、load、net_*、disk_*、dev_inodes、repl_sf、repl_node、repl_fail_node | 200 | WARN。响应大约 50–65 字节，是空序列或空统计，不是四节点数据 |

`nodes_up` 和 `svc_grid` 对不上「四台都 up」。SSH 失败的原因在身份项之外：配置里的私钥文件不存在，见 Lab 索引。Prometheus 对 `backend_err` 仍有序列，所以不是整条 metrics URL 挂了。

## Deploy

| id | 方法 | 状态码 | 判定 |
|---|---|---|---|
| D-page | `GET /deploy` | 200 | PASS |
| D-state-nocookie | `GET /api/state` 无 Cookie | 401 | PASS。`console session required` |
| D-listen | swift4 `ss` `127.0.0.1:8789` | n/a | PASS。`swift-deploy` 在听。不是整节 FAIL 的那种上游缺失 |
| D-state | `GET /api/state` | 200 | PASS。280 字节。config 只有 bundle、inventory、playbook、plan、known_hosts 路径。plan 字段是 null |
| D-validate-bare | `POST /api/validate` `{}` | 403 | 记录。`missing or invalid anti-CSRF token`。说明反代把请求送到了上游 |
| D-validate | `POST /api/validate`，body 为 state 里的 config，头 `X-Swift-Deploy-Token` 来自 `/deploy/` 的 meta（值未记录） | 400 | FAIL。`invalid UI configuration: EOF while parsing a value at line 1 column 0`。本机文件 165 字节，上游收到空 body。Console 反代去掉 Content-Length，swift-deploy 只按 Content-Length 读 body |
| D-plan | 同样方式 `POST /api/plan` | 400 | FAIL。同一句 EOF。没有计划正文 |
| D-apply | 未调用 | n/a | 接线已证明到 state 与 CSRF 检查。apply 按边界未执行，不计入通过，也不算失败 |

## Lab

| id | 方法 | 状态码 | 判定 |
|---|---|---|---|
| L-index | `GET /lab` | 200 | FAIL。12 张卡片都在，但可达性是 `0 of 4 nodes reachable — no answer from swift1, swift2, swift3, swift4`。Console SSH 到 storage IP `root@10.0.4.N`，私钥 `/root/.ssh/id_ed25519` 不存在，Permission denied |
| L-ring-page | `GET /lab/ring` | 200 | PASS。页面有内容（约 259KB） |
| L-topology | `GET /lab/api/ring/topology?policy=0` | 200 | PASS。policies 含 Policy-0（replication，默认）和 ec-2-1。设备名是 d2/d3，节点名能落到 swift1–4 |
| L-part | `GET /lab/api/ring/part?policy=0&part=0` | 200 | PASS。主副本 swift1 d2、swift3 d2、swift2 d2，handoff 含 swift4 d3 |
| L-simulate | `POST /lab/api/ring/simulate` policy 0、ops 空 | 200 | PASS。`ok` true，`error` null。partitions 16384，8 个设备，parts 前后都是 6144/设备（合计 49152） |
| L-policy-page | `GET /lab/policy` | 200 | PASS |
| L-pol-def | `GET /lab/api/policy/defaults` | 200 | WARN。`node_count` 4 符合。`devices_total` 是 8，不是 12。`usage_unknown` true，`device_tb` 0。df 走的是已经失败的 SSH |
| L-pol-empty | `POST /lab/api/policy/compare` `{}` | 422 | PASS。`missing field raw_tb`。这只是参数校验 |
| L-pol-compare | compare，raw_tb 1，node_count 4，devices_total 8，zone_count 4，候选 3 副本和 EC 2+1 | 200 | PASS。2 行，recommendation `meets_all` |
| L-capsule-page | `GET /lab/capsule` | 200 | BLOCKED（对象 API）。第 2 节对象不存在，没有伪造路径 |
| L-tombstone-page | `GET /lab/tombstone` | 200 | BLOCKED。同上 |
| L-debt | `GET /lab/api/debt/snapshot` | 200 | PASS。有 debt 数字和 contributions。unhealthy stock 10 |
| L-genome-page | `GET /lab/genome` | 200 | PASS |
| L-genome-evolve | `POST /lab/api/genome/evolve` generations 2、population 4 | 200 | PASS。front 里有 fitness（availability、migration、repair、waste） |
| L-genome-result | `GET /lab/api/genome/result` | 200 | PASS。同一份 front，不是空对象 |
| L-jobs | `GET /lab/api/warehouse/jobs` | 200 | PASS。jobs 空，verdict 句子说明没有已发布产物 |
| L-sample | `GET /lab/api/warehouse/sample` 未对真实对象调用 | n/a | BLOCKED。没有第 2 节对象。没有调用 promote |
| L-prof-page | `GET /lab/profilemap` | 200 | PASS |
| L-prof | `GET /lab/api/profilemap/snapshot` | 200 | PASS。`ok` true，tree 里有 proxy-server 的 fan_out / ring_lookup 计数 |
| L-prof-pulse | 未发 | n/a | NOT RUN。会写 `lab-profilemap`。桶创建已失败，同一根因 |
| L-exp-page | `GET /lab/expired` | 200 | PASS |
| L-exp | `GET /lab/api/expired/status` | 200 | PASS（只读）。`no active run` |
| L-exp-run | 未发 | n/a | NOT RUN。会写 `lab-expired-*`，预期与建桶同一 404，不单列新 bug |
| L-chaos-page | `GET /lab/chaos` | 200 | PASS |
| L-chaos | `GET /lab/api/chaos/catalogue` | 200 | PASS。armed true，arena `chaos-arcade`，四种 fault：drop_copy、corrupt_copy、drop_durable、stale_timestamp |
| L-shadow-page | `GET /lab/shadow` | 200 | PASS |
| L-corpus | `GET /lab/api/shadow/corpus` | 200 | WARN。能读，`peer` true，`records` 0 |
| L-shadow-peer | `GET http://10.0.0.3:8090/info` | 200 | 记录。对端在听。没有调用 run 或 mutate，因为 run 会写数据 |
| L-nodes-page | `GET /lab/nodes` | 200 | PASS |
| L-nodes | `GET /lab/api/node/status` | 200 | FAIL（相对「四台 up」）。四台 reachable false、up false、active_services 0。原因是 SSH 密钥文件缺失，不是本轮把节点停了 |

其余 Lab 页面（shadow、chaos、warehouse、debt、expired、profilemap、genome、nodes）HTTP 200，见浏览器记录。
