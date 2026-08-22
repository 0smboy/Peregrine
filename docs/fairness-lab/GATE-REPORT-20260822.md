# Gate report（自动口径，2026-08-22）

**Supersedes** `workflow-runs/20260821/GATE-MATRIX.md` 里把 pipeline 对齐 / 假 G0 PASS 写成可关闭的部分。  
规范：`PEREGRINE-NEXT-EXECUTION-DIRECTIVE-20260822.md` + `AGENTS.md` TEST LAB。

```text
G0 provenance: RED
  - product git e65d26a… + dirty worktree（证据 workflow-runs/20260822-g0-checkpoint/）
  - preflight 曾忽略 validate_manifest；现已改为 FAIL
  - ceph/s3-tests@5522d1c 不是 tipabu/s3compat+submodule lineage

G1 environment: RED (not a hardware blocker)
  - OWNER CORRECTION 2026-08-22: Swift1-4 是测试机，四机分阶段复用（M0–M3）。
    资源申请 docs/fairness-lab/LAB-RESOURCE-REQUEST-20260822.md 已 SUPERSEDED，不再是 G7/G8 blocker。
  - G1 不再因“机器名字叫生产节点”永久 RED。VIP 存在 ≠ 非实验流量。
  - 关闭条件改为：LAB-MODE.json + 实测 uncontrolled_competing_traffic=0。
  - 当前未切 M2/M3 维护窗口，G6/G7/G8 仍 NOT RUN。

G2 SAIO pipeline: partial GREEN (live semantic diff 0 after 08-21 align)
  - 生产 /etc/swift pipeline 仍不同；不得混用

G3 Swift PUT/GET: partial evidence only (delta, not absolute counters)
G3 required routes: RED
G3 S3: RED overall; S3-1 and S3-2 live-proven on RSAIO :8081
  - S3-1: unversioned SigV4 PUT 256MiB 200 (commit 897c2d8)
  - S3-2: STREAMING-UNSIGNED-PAYLOAD-TRAILER 70MiB 200; bad chunk 403 + GET 404
    proxy SHA e779eb5fdaf4187e329b645fdeb948f5d72185e70048ef239295bcc9c49e8c5a
    commit 78630f8; native_async +1, block_in_place 0 on both PUT and fail-closed
  - Control S3 (HEAD/List) still block_in_place; versioned PUT still 64MiB buffered
  - G3 not closed: remaining required routes not all GREEN

G4: NOT GATED
G5: NOT GATED
G6: NOT RUN (forbidden on production four-node)
G7: NOT RUN
G8: INVALID
Production readiness: NO-GO
```

本轮生产未变更：VIP / HAProxy / Keepalived / `:8080` / `/usr/local/bin` SHA `ab5cb95c…`。

当前 recon 绝对计数不可当原始基线（曾发过只读 health/recon）。后续只用 before/after delta + route trace。
