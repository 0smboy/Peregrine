# 10. 清理

| id | 方法 | 状态码 | 判定 |
|---|---|---|---|
| C-delete-local | `DELETE http://127.0.0.1:8080/v1/AUTH_test/console-accept-20261002` | 404 | FAIL。HTML Not Found。删不掉 |
| C-delete-vip | `DELETE https://10.0.0.10:8085/v1/AUTH_test/console-accept-20261002` | 404 | FAIL。同上 |
| C-row | 只读 sqlite，`container.name=console-accept-20261002` | n/a | 仍有 1 行。账户 status 仍是 DELETED。没有写这张库 |
| C-container-db | 只读 swift4 容器库文件 | n/a | 仍在。路径 `/srv/node/d2/containers/2441/150/2624a9816b5013979bfcb6ca12c12150/`，53248 字节。这是失败的 PUT 留下的。没有 `rm` `/srv/node` |
| C-other-containers | 本轮 pulse / expired / autocos | n/a | PASS。这三个名字本轮没有创建，所以没有删别的容器 |
| C-client-list | `GET /files/api/buckets` | 200 | 列表里没有这个名字（列表本来就是空的） |
| C-swift1 | `systemctl is-active` proxy object container account keepalived haproxy | n/a | 都是 active |
| C-swift2 | 同上 | n/a | proxy/object/container/account/keepalived 仍 inactive。haproxy active。与进入本轮时相同，没有 enable |
| C-swift3 | 同上 | n/a | 都是 active |
| C-swift4 | 同上 | n/a | 都是 active |
| C-vip | `GET https://10.0.0.10:8085/info` | 200 | PASS。1475 字节 |
| C-tunnel | 本机 9000 监听 | n/a | 隧道进程已退出 |
| C-secrets | 本目录与 `/tmp/console-accept-key` | n/a | 密钥文件已删。本目录没有 token、密码或登录密钥 |

账户库副本：swift2 与 swift3 的同一哈希 `status=DELETED`。swift1 handoff 上的库 `status` 是空字符串，container_count 0，和主副本不是同一份内容。

没有停过节点，所以也不存在「演练之后忘了拉起」。四台存储服务并没有都在跑：swift2 从本轮之前就是停的。
