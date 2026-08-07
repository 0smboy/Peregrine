# Workers semantics residual · 2026-08-07

## Honest equivalence

| Layer | Python eventlet | Rust | Equivalent? |
|-------|-----------------|------|-------------|
| `workers` | prefork OS processes | scales `worker_threads` product (cap 128) when spp=0 | **No** (threads ≠ processes) |
| `max_clients` | greenlets per worker | connection_queue + product factor | Partial |
| `servers_per_port>0` | process per port | Wave2 process-per-(port,worker) supervise | **Closer** (process-isolated) |
| ISO-CONFIG tooling | manual | `swift-effective-concurrency` JSON | **KEEP** |

## Tests
- `servers_per_port::tests::*` **9/9** ok (`01-cargo-test.txt`)

## CLI samples (`02-cli-samples.txt`)
- workers=2 max_clients=64 → worker_threads=128 (capped), formula notes NOT prefork
- spp=4 → acceptors=4, workers ignored
- workers=0 → default cpus*16 clamp

## Verdict
**TOOLING/DOC KEEP** for fairness ISO-CONFIG  
**Process-model residual remains** for classic `workers` prefork equivalence (documented WONTFIX / map-not-clone)

## Authority
`docs/fairness-lab/WORKERS-SEMANTICS.md`
