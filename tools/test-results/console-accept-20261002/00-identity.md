# 0. 现场核对

时间：2026-10-02 约 10:34Z–10:36Z。从本机 `ssh swift4`（以及 swift1–3）只读。密钥未写入本文件。

| id | 方法 | 状态码 | 判定 |
|---|---|---|---|
| I-host | `hostname` on swift4 | n/a | PASS。主机名 swift4 |
| I-nodes | 配置 `cluster_nodes` | n/a | PASS。swift1–4，每台 devices d1 d2 d3，public 10.0.0.1–4，storage 10.0.4.1–4，replication 10.0.8.1–4 |
| I-devs | 四台 `test -d /srv/node/d1\|d2\|d3` | n/a | PASS。12 个挂载点都在 |
| I-vip-owner | `ip addr` | n/a | PASS。VIP `10.0.0.10/22` 在 swift1。swift2/3/4 没有这块地址 |
| I-vip-info | `GET https://10.0.0.10:8085/info` | 200 | PASS。HTTP `:8085` 无响应（curl 52）。现行入口是 HTTPS |
| I-info-s1 | `GET http://10.0.0.1:8080/info` | 200 | WARN。sha16 `65ddec492e0821e6`，1668 字节，swift 2.33.0。与 s3/s4 不一致 |
| I-info-s2 | `GET http://10.0.0.2:8080/info` | 连接拒绝 | FAIL。swift2 的 `:8080` 没有监听 |
| I-info-s3 | `GET http://10.0.0.3:8080/info` | 200 | WARN。sha16 `eb6e3f1b0247c8f2`，1475 字节 |
| I-info-s4 | `GET http://10.0.0.4:8080/info` | 200 | WARN。与 s3 同一 sha16 |
| I-info-diff | 对比 s1 与 s4 的 JSON | n/a | WARN。只差 s3api 的 allow_multipart_uploads、max_bucket_listing、max_multi_delete_objects、max_parts_listing、max_upload_part_num、min_segment_size、s3_acl。s1 有这些字段，s4 没有 |
| I-proxy-hash | `sha256sum` 四台 `/usr/local/bin/swift-proxy-server` | n/a | WARN。swift1 前 16 位 `352da6f120d4f966`。swift2/3/4 前 16 位 `ab5cb95c5c3973db`（swift4 mtime 2026-08-19） |
| I-swift2-units | `systemctl is-active` / `UnitFileState` | n/a | FAIL（现场已是这样，本轮没有改）。proxy、object、container、account、keepalived 为 inactive 且 disabled。haproxy active。journal 自 2026-09-01 起无记录 |
| I-console-proc | 进程与监听 | 200 healthz | PASS。`/usr/local/bin/swift-console /etc/swift-console/config.json`，pid 2199475，启动 2026-08-06。监听 `127.0.0.1:9000`。二进制 sha256 前 16 位 `d00406f72cc4fdc1`，mtime 2026-08-01 |
| I-console-root | `GET /` 无 Cookie | 303 | PASS。`location: /login` |
| I-swift-base | 配置 | n/a | PASS（允许继续）。`swift_base=http://127.0.0.1:8080`，即 swift4 本机代理，属于四台代理之一。`auth_url=http://127.0.0.1:8080/auth/v1.0`。`cluster_name=contabo-swift-2026`。`cluster_vip=https://10.0.0.10:8085` |
| I-flags | 配置，密钥字段已去掉 | n/a | 记录。`lab_enabled=true`，`lab_mutations=true`，`lab_root=/srv/node`，`test_enabled=true`，`account_admin=false`（字段缺失，按默认关），`deploy_upstream=http://127.0.0.1:8789`，`metrics_url=http://127.0.0.1:9090`，`logs_url=http://127.0.0.1:3100`。deploy 在 `127.0.0.1:8789` 监听。Prometheus `127.0.0.1:9090`。Loki `:3100` |
| I-autocreate | 四台 `proxy-server.conf` | n/a | 记录。`[app:proxy-server] account_autocreate=true`。`user_test_tester` 行存在，值未记录 |
| I-lab-ports | swift1 `ss` | n/a | PASS（确认后不再使用）。`127.0.0.1:18082`、`0.0.0.0:18080`、`127.0.0.1:8090` 在听。验收没有打这些端口 |
| I-disk-swift4 | `df` | n/a | WARN。根分区 `/dev/sda4` 100%，约 20K 可用，inode 100%，约 59 空闲。`/dev/shm` 有空间。`/srv/node/d1` 约 4% 已用 |
| I-getnodes-bin | `ls` | n/a | PASS。`/usr/local/bin/swift-get-nodes`、`swift-object-info`、`swift-ring-sim` 存在 |

`swift_base` 指向四台代理之一，按计划继续。
