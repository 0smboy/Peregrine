# Wave 4 — Perf residual notes

Date: 2026-08-01

No further tuning applied. Documented known limits in
`Peregrine/tools/CONTABO-CLUSTER.md` (Perf known limits).

Source: `/root/contabo-deploy-20260801T125749Z/61-PERF-SUMMARY.md`
Verdict remains **ACCEPT_WITH_WARN**:

- 4KB write→read @128: fail=0 (hard gate PASS)
- 16MB / high-concurrency EC: known lab ceiling; not a regression of Contabo wiring
