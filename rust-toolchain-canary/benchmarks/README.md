# Benchmarks

Wire existing cluster load tools rather than inventing a new harness:

- `Peregrine/cosbench-rs` — sustained PUT/GET
- `swift-master/rust/tools/bench.py` — A/B HTTP bench

`canary.sh` records binary size and CRUD smoke latency only. Attach a full
throughput run by setting `CANARY_BENCH_CMD` to a script that prints:

```text
GET throughput: <n> ops/s
PUT throughput: <n> ops/s
```

Those lines are copied into the Markdown report when present.
