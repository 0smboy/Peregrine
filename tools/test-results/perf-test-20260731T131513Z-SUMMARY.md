# Perf test — new 4-node cluster — 20260731T131513Z

## Verdict: **ACCEPT_WITH_WARN** (4KB read WARN cleared by client retune — see `perf-4kb-rerun-20260731T134021Z-SUMMARY.md`)

Load generator: swift1 → `http://10.42.30.11:8085` (shared-host noise).
Plan-first: `/root/perf-test-20260731T131513Z/00-PLAN.md`.
Follow-up: 4KB_read failures were load-host TIME_WAIT + `ulimit -n=1024`, not object/proxy bugs; tuned rerun fail=0.

### Pass bars

| Gate | Result |
|------|--------|
| bench-repl err=0 | PASS |
| bench-ec err=0 | PASS |
| cbench/wbench | PASS (errs=0) |
| autocos 6×60s | WARN — 4KB_read_128 normal stage fail=36537 (83.94% success); others fail=0 |
| obs | nodes_up=4; proxy/object journal errors ~0; /srv/node ~12G/node after load |

### bench.py cluster-repl

```
      size  conc   op     ops/s     MB/s    p50ms    p95ms    p99ms  err
        1K     1  PUT      42.1      0.0     22.4     38.9     42.8    0
        1K     1  GET     165.2      0.2      4.5     15.4     19.8    0
        1K    32  PUT     764.5      0.8     34.7     67.6    221.2    0
        1K    32  GET    1395.3      1.4     17.9     51.3     73.9    0
        1K    64  PUT     943.4      1.0     56.5    129.0    163.7    0
        1K    64  GET    1269.8      1.3      7.6     25.1     48.0    0
        1M     1  PUT      21.9     23.0     36.0     76.0    233.0    0
        1M     1  GET     113.9    119.4      7.5     17.1     21.1    0
        1M    32  PUT     247.3    259.4     93.0    344.9    548.2    0
        1M    32  GET     323.7    339.4     95.6    133.9    149.0    0
       16M     8  PUT      12.8    214.1    486.3    969.5   1400.4    0
       16M     8  GET      29.2    489.4    266.7    301.6    310.2    0
```

### bench.py cluster-ec (ec-2-1)

```
      size  conc   op     ops/s     MB/s    p50ms    p95ms    p99ms  err
        1K     1  PUT      30.6      0.0     30.4     47.1     60.6    0
        1K     1  GET      62.1      0.1     14.6     28.4     34.9    0
        1K    32  PUT     408.0      0.4     49.2     80.5   2613.7    0
        1K    32  GET    1278.2      1.3     22.6     45.9     61.7    0
        1K    64  PUT     863.9      0.9     61.6    154.3    237.1    0
        1K    64  GET    1274.5      1.3     36.7    101.6    140.5    0
        1M     1  PUT      21.1     22.1     43.0     65.1    112.8    0
        1M     1  GET      49.3     51.7     18.7     33.8     38.6    0
        1M    32  PUT     248.8    260.9    107.3    238.1    533.5    0
        1M    32  GET     324.9    340.6     96.4    129.3    147.7    0
       16M     8  PUT      13.8    231.5    468.1   1108.6   1211.1    0
       16M     8  GET      29.9    500.8    262.0    312.8    329.4    0
```

### cbench (4KB PUT, conc=64, count=2000)

```
containers=  1 conc=64 count=2000  ->    1126.4 PUT/s  (1.8s, errs=0)
containers=  4 conc=64 count=2000  ->     432.9 PUT/s  (4.6s, errs=0)
containers= 16 conc=64 count=2000  ->    1112.5 PUT/s  (1.8s, errs=0)
containers= 64 conc=64 count=2000  ->     837.3 PUT/s  (2.4s, errs=0)
```

### wbench (4 containers, size=4096, count=2000)

```
conc=16:  510.9 PUT/s  p50=26.6ms p95=47.6ms p99=204.4ms  errs=0
conc=64:  943.2 PUT/s  p50=53.1ms p95=129.5ms p99=303.1ms  errs=0
```

### autocos collect (60s runtime each)

| W-id | Size | Op | Workers | Throughput | Bandwidth | Notes |
|------|------|-----|--------:|------------|-----------|-------|
| w1 | 4KB | write | 128 | 561 op/s | 2.30 MB/s | fail=0 |
| w2 | 4KB | read | 128 | 3785 op/s | 13.01 MB/s | **fail=36537 (83.94%)** |
| w3 | 1MB | write | 32 | 215 op/s | 225 MB/s | fail=0 |
| w4 | 1MB | read | 32 | 1123 op/s | 1178 MB/s | fail=0 |
| w5 | 16MB | write | 8 | 12.4 op/s | 208 MB/s | fail=0 |
| w6 | 16MB | read | 8 | 110 op/s | 1846 MB/s | fail=0 |

### vs prior docs (performance.mdx, informational)

- Prior autocos read peaks: ~4180 op/s (4KB), ~1346 MB/s (1MB), ~1920 MB/s (16MB)
- This run: 3785 op/s (4KB, with errors), 1178 MB/s (1MB), 1846 MB/s (16MB)
- Prior 4KB write p99 after workers=16 ~330ms; this wbench conc=64 p99=303ms

### Artifacts

- Host: `/root/perf-test-20260731T131513Z`
- Mac: `Peregrine/tools/test-results/perf-test-20260731T131513Z*`
- Drive: `gdrive:Peregrine/2026-07-31-lab-456/perf-tests/20260731T131513Z/`
