# Gate report（自动口径，2026-08-22）

**Supersedes** `workflow-runs/20260821/GATE-MATRIX.md` 里把 pipeline 对齐 / 假 G0 PASS 写成可关闭的部分。  
规范：`PEREGRINE-NEXT-EXECUTION-DIRECTIVE-20260822.md` + `AGENTS.md` TEST LAB。

```text
G0 provenance: RED
  - product git e65d26a… + dirty worktree（证据 workflow-runs/20260822-g0-checkpoint/）
  - preflight 曾忽略 validate_manifest；现已改为 FAIL
  - ceph/s3-tests@5522d1c 不是 tipabu/s3compat+submodule lineage

G1 environment: RED for G7/G8
  - swift1-4 均有生产 :8080 + :8085
  - swift2 VIP 10.0.0.10
  - swift3 生产节点 + 编译机，不是干净测试机
  - blocker: docs/fairness-lab/LAB-RESOURCE-REQUEST-20260822.md

G2 SAIO pipeline: partial GREEN (live semantic diff 0 after 08-21 align)
  - 生产 /etc/swift pipeline 仍不同；不得混用

G3 Swift PUT/GET: partial evidence only (delta, not absolute counters)
G3 required routes: RED
G3 S3: RED
  - intercepts_request + materialize(64MiB)
  - block_in_place + sync handle()
  - characterization tests in crates/swift-s3api/tests/s3_g3_characterization.rs 预期 FAIL

G4: NOT GATED
G5: NOT GATED
G6: NOT RUN (forbidden on production four-node)
G7: NOT RUN
G8: INVALID
Production readiness: NO-GO
```

本轮生产未变更：VIP / HAProxy / Keepalived / `:8080` / `/usr/local/bin` SHA `ab5cb95c…`。

当前 recon 绝对计数不可当原始基线（曾发过只读 health/recon）。后续只用 before/after delta + route trace。
