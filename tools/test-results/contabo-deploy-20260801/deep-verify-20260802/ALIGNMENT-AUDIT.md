# Alignment audit — 2026-08-02

- Git HEAD at audit: see runner

| Class | Claim | Source | Live | Evidence | Note |
|-------|-------|--------|------|----------|------|
| SAIO | Rust c32 264.4 | PASS | PASS | PASS |  |
| SAIO | Python c32 69.8 | PASS | PASS | PASS |  |
| SAIO | ratio ~3.79 | PASS | PASS | PASS |  |
| LEVER | L1a KEEP | PASS | PASS | PASS |  |
| LEVER | L1b DROP | PASS | PASS | PASS |  |
| LEVER | prod sync | PASS | PASS | PASS |  |
| TOPO | VIP 10.0.0.10 | PASS | PASS | PASS |  |
| TOPO | Contabo | PASS | PASS | PASS |  |
| TOPO | no current 10.42.30 | PASS | PASS | PASS |  |
| CLOSED | write-concurrency closed | PASS | SKIP | PASS |  |
| CLOSED | no open Plan biggest lever | PASS | SKIP | PASS |  |

**Unexplained FAIL count:** 0

Source of truth: `perf-levers/SUMMARY.json`, `docs/lab-cluster.md` / Contabo.
Live fetched to `live-performance.md` / `live-lab-cluster.md` when TLS allowed.
