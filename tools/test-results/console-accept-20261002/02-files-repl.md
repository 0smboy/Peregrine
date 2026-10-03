# 2. Files 与复制

桶创建已经 404。下面只做了只读。写入闭环没有做，不能记通过。

| id | 方法 | 状态码 | 判定 |
|---|---|---|---|
| F-files-page | `GET /files` | 200 | PASS。8122 字节，标题 Files |
| F-trash-page | `GET /files/trash` | 200 | PASS |
| F-account-page | `GET /files/account` | 200 | PASS。只读配额，没有改数字 |
| F-users-page | `GET /files/users` | 200 | PASS。正文是「你没有访问租户与用户的权限。」不是假的成功 |
| F-search-page | `GET /files/search` | 200 | PASS |
| F-whoami | `GET /files/api/whoami` | 200 | PASS。同 01 |
| F-buckets | `GET /files/api/buckets` | 200 | FAIL（作为「桶已建成」）。`buckets: []`，account container_count 0、bytes_used 0。不含 `console-accept-20261002` |
| F-account | `GET /files/api/account` | 200 | WARN。计数全 0，`quota_bytes` null，`temp_url_key_set` true。这是合成出来的空账户，和磁盘上 DELETED 库里的行数不一致 |
| F-trash | `GET /files/api/trash` | 200 | PASS。`items: []` |
| F-tempurl-key | `GET /files/api/tempurl-key` | 200 | PASS。`key_set` true，`default_expiry_secs` 86400。密钥本身没有读取进本文件 |
| F-missing-meta | `GET /files/api/bucket/no-such-bucket-accept-20261002/meta` | 404 | PASS。`bucket not found` |
| F-users | `GET /files/api/users` | 403 | PASS。`account administration is disabled` |
| F-reindex | `POST /files/api/search/reindex` body `{"deep":0}` | 200 | WARN。`count` 0，`truncated` false。账户列表是空的，所以索引是空的。没有改成 deep |
| F-put-object | 未发 | n/a | NOT RUN。桶创建 404 |
| F-download-sha | 未发 | n/a | NOT RUN |
| F-vip-get-sha | 未发 | n/a | NOT RUN。没有对象可比 sha256 |
| F-get-nodes | 未对对象调用 | n/a | NOT RUN。没有跨节点副本可以看 |
| F-meta-folder-zip-tempurl-trash-cycle | 未发 | n/a | NOT RUN |

文件链总判：FAIL。根因见 SUMMARY。
