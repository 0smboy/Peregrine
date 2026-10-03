ACCEPT_WITH_WARN: 2026-10-02 deploy apply 仍未执行，证据 `tools/test-results/console-accept-20261002/13-apply.md` 与 `13-apply-plan-summary.md`。`POST /api/plan` 用的是 Contabo identity 清单 `/opt/swift-deploy/config_contabo_identity/swift_hosts`（169.58.108.85/86/87/121，不是 `config_sample`），202，job 5，密封计划 336 tasks，digest 前缀 `d962336aac56`。没有 `POST /api/apply`。计划里仍有 disk_wipe 任务名：`DD before mkfs`、`Format all storage nodes disks`、`Change disks partition table to mbr before DD`（各两条；`format_disk_servers` 无主机，执行器不会对它们跑 mkfs）。同一计划不是空操作：216 个任务带主机，包含四台 `Yum Upgrade`、重启 sshd、改防火墙和 SELinux，以及 swift1–3 的 MariaDB/Keystone 安装。Apply 不能在不改动现网的前提下完成。VIP `10.0.0.10` 仍只在 swift1，`https://10.0.0.10:8085/info` 200（1270 字节）。swift1–4 的 swift-proxy、swift-object、swift-container、swift-account 都是 active。

此前：2026-10-02 三项补跑，证据 `tools/test-results/console-accept-20261002/12-apply-mutate-promote.md`。Shadow mutate PASS（`POST /lab/api/shadow/mutate` 200，run `m839245-3cd595`，8 steps，peer 两侧状态一致，容器已删）。Warehouse promote PASS（job `job-1790954920-93ef44` 200，promote 200，server-side copy，etag 一致；本轮对象和当时新建的 `warehouse` 容器已删）。Deploy apply FAIL：`POST /api/plan` 202，密封计划仍是 UI 里已经接受过的 `bundle/config_sample/swift_hosts`，目标 `192.168.2.51` / `192.168.2.52`，风险含 `disk_wipe`（DD 和 mkfs）。没有 `POST /api/apply`。VIP 仍只在 swift1，`https://10.0.0.10:8085/info` 200。swift1–4 的 swift-proxy、swift-object、swift-container、swift-account 都是 active。没有删不掉的容器。

此前同日的结论是 ACCEPT，证据 `tools/test-results/console-accept-20261002/10-shadow.md` 和 `11-browser-disk.md`。`POST /lab/api/shadow/run` 200，run `r1790948703-8e3c36`，31 cases。浏览器 Files 闭环和 Monitor 在线节点 4 已通过。那一轮 mutate 还没调用，Apply 也还没点。上面这一条把这三项补上之后，总判改为 ACCEPT_WITH_WARN，未通过的是 deploy apply。

下面是同一天早一轮的记录，当时账户还是 DELETED，不是当前结论。

FAIL（早一轮，已被 07 与 09 接上）: 创建桶 `console-accept-20261002` 在 Console 的 storage_url（`http://127.0.0.1:8080/v1/AUTH_test`）和 VIP `https://10.0.0.10:8085` 上都是 404。账户 `AUTH_test` 在活着的 account 主副本上 `status=DELETED`，account-server 对 HEAD/GET/容器登记都回 404，container-server 在全部 account 更新都 404 时把容器 PUT 失败关掉。这是账户状态，不是 Console 页面坏了。

日期：2026-10-02。对象：swift4 上的 Swift Console 操作 contabo-swift-2026。实验口 swift1 `:18080`/`:18082` 未登录、未建桶、未当作通过证据。

## 根因

账户环把 `AUTH_test` 放在 `10.0.4.2:6202 d2`（swift2）、`10.0.4.3:6202 d2`（swift3）、`10.0.4.4:6202 d2`（swift4），handoff 是 swift1。swift3 与 swift4 的 account-server 在 10:38:14Z 对 `HEAD /d2/15623/AUTH_test` 记了 404。swift4 上该库的 `account_stat.status` 是 `DELETED`（swift2 磁盘上的同一哈希、swift3 也是 `DELETED`）。`is_deleted()` 在 status 为 DELETED 时为真，HEAD/GET 走 404。

代理配置 `[app:proxy-server] account_autocreate = true`。客户端 HEAD/GET 账户得到 204、容器数 0。这是缺失/已删除账户被合成成空列表，不能证明账户可写。容器 PUT 仍要向 account-server 登记；登记全部 404 时，container-server 的 `account_update` 回 404（swift-container-server）。swift4 的 container-server 先写下了容器库（日志 201，紧接着又一次 202），swift3 的容器 PUT 是 404。代理对客户端两枪都回了 HTML 404。

要改的地方不在 Console 的建桶封装：同一 token 打本机代理和 VIP 都是 404。要先让 `AUTH_test` 不再处于 DELETED（或换一个未删除的账户），并确认 account 主副本有法定人数。swift2 的 proxy/object/container/account/keepalived 在本轮开始前就是 disabled/inactive，它正是这个账户的一个主副本。本轮没有 enable 它，也没有改代码、没有换二进制、没有 `POST /api/apply`。

## 同一轮里另外失败、但不改总判条款的项

- Monitor `nodes_up` 值是 0.0，不是 4。`svc_grid` 四台都是 unreachable。Console 配置的 SSH 私钥路径 `/root/.ssh/id_ed25519` 不存在，对 `10.0.4.1–4` 的 root SSH 全部 Permission denied。Lab 索引是 `0 of 4 nodes reachable`。
- Deploy 上游 `127.0.0.1:8789` 在听，无 Cookie 的 `/api/state` 是 401，有 Cookie 是 200。带 CSRF 的 `POST /api/validate` 和 `POST /api/plan` 是 400 `EOF while parsing`。Console 反代剥掉 `Content-Length`，swift-deploy 只认 Content-Length，所以计划正文没有生成。这不是「反代没在听」。Apply / 「执行密封计划」没有点。
- 四台 `/info` 哈希不一致。swift1 代理 `352da6f120d4f966`，`/info` sha16 `65ddec492e0821e6`（1668 字节）。swift3/swift4 代理 `ab5cb95c5c3973db`，sha16 `eb6e3f1b0247c8f2`（1475 字节），差在 s3api 的几个字段。swift2 的 `:8080` 拒绝连接。VIP 200，哈希随 HAProxy 打到哪台而变。版本字符串都是 2.33.0。
- swift4 根分区 100%（约 20K 可用），inode 100%（约 59 空闲）。`/srv/node/d1–d3` 另挂，有空间。

## 未执行（不算通过）

- 第 2 节写入闭环：桶创建 404 之后没有 PUT 对象、没有 VIP sha256、没有 `swift-get-nodes` 副本分布、没有 TempURL、没有回收站往返。记 NOT RUN，文件链总判 FAIL。
- HA 停节点：NOT RUN。没有通过 VIP 读回的对象；而且 swift2 已经是 down，再停一台会超出「只停一台」。
- Chaos 四种故障：NOT RUN。第 2 节对象不存在。`lab_mutations` 是开的，catalogue 显示 armed。没有调用 `/lab/api/chaos/run`。
- autocos：NOT RUN。`test_enabled` 为开，但新容器会撞上同一个 404。只读了历史 503 条和 export 表头。没有从页面再发一发压测。
- Profile map `pulse`、Expired `run`、Shadow `run`/`mutate`、Warehouse `sample`、Capsule/Tombstone 对象 API：NOT RUN 或 BLOCKED。pulse/expired/shadow 会写容器；sample 和胶囊需要第 2 节那个对象。Shadow 对端 `http://10.0.0.3:8090/info` 是 200，corpus 能读但 records=0。

## 清理

- API `DELETE` 该容器：本机代理和 VIP 都是 404。账户库里仍有 1 行 `console-accept-20261002`，swift4 上容器库文件仍在（53248 字节，`/srv/node/d2/containers/2441/150/2624a9816b5013979bfcb6ca12c12150/`）。没有手工删 `/srv/node`。
- 本轮没有创建 `lab-profilemap`、`lab-expired-*`、autocos 容器。
- swift1、swift3、swift4 的 proxy/object/container/account/keepalived/haproxy 仍是 active。swift2 仍是进入本轮时的 inactive/disabled（haproxy 仍 active）。VIP `https://10.0.0.10:8085/info` 200。
- 集群没有被本轮停过节点。不能说四台存储节点都是 up。

分项：`00-identity.md`、`01-split-404.md`、`02-files-repl.md`、`03-monitor-deploy-lab.md`、`04-ha-chaos-test.md`、`05-browser.md`、`06-cleanup.md`。
