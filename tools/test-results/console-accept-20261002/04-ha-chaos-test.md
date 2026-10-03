# 6–8. HA、Chaos、Test

`lab_mutations` 为开，`test_enabled` 为开。停节点和 chaos 仍未执行，因为第 2 节对象没有通过 VIP 读回。这不是通过。

| id | 方法 | 状态码 | 判定 |
|---|---|---|---|
| H-precondition | 第 2 节对象的 VIP GET | n/a | NOT RUN。对象没有写成。另外 swift2 的 swift 服务在本轮开始前已是 disabled/inactive。再停 swift3 会变成两台存储节点不可用，超出「只停一台」 |
| H-down | `POST /lab/api/node/down` 未发 | n/a | NOT RUN |
| H-up | `POST /lab/api/node/up` 未发 | n/a | NOT RUN。也没有节点需要本轮拉起。离开时没有把任何本轮停掉的节点留下 |
| C-catalogue | 见 03 | 200 | 前置在，不能代替四轮故障 |
| C-run | `POST /lab/api/chaos/run` 未发 | n/a | NOT RUN。工具自己的目标是 arena `chaos-arcade`，而且计划要求第 2 节对象还在。两种条件都不满足「只动本轮那个对象」。没有挪 `/srv/node` |
| C-recover | 未发 | n/a | NOT RUN |
| T-page | `GET /test` | 200 | PASS |
| T-runs | `GET /test/api/runs` | 200 | PASS（只读）。`runs` 长度 503。不要求等于 503 以外的数字，这里恰好是 503 条历史 |
| T-export | `GET /test/api/export.csv` | 200 | PASS。首行是 `finished,size,operation,workers,operations,bytes,avg_response_ms,avg_process_ms,throughput_ops,bandwidth_bytes,success_pct` |
| T-run | `POST /test/api/run` 最小 4KB/write/workers=1/objects=2/runtime=5 未发 | n/a | NOT RUN。新容器会遇到和建桶相同的 404。没有删「本轮 autocos 容器」，因为没有创建 |

浏览器里测试页能看到历史和「开始测试」按钮。没有点开始测试。
