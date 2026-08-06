# Workers semantics — Python vs Rust (P2c → Wave 2)

**Authority for ISO-CONFIG:** align **effective concurrency** (and CPU quota), not the integer `workers=` alone.

## Python (eventlet)

| Knob | Meaning |
|------|---------|
| `workers` | Preforked OS processes (each with an eventlet hub) |
| `max_clients` | Green-thread concurrency **per worker process** |
| `servers_per_port` | When `>0`, ignore `workers`; fork this many processes **per unique local ring port** |

Total green concurrency ≈ `workers * max_clients` (classic) or `servers_per_port * n_ports * max_clients`.

## Rust (threaded)

| Knob | Meaning |
|------|---------|
| `workers` | **Not** process count. Product `workers * max_clients` → `worker_threads` (cap **128**) when `servers_per_port=0` |
| `max_clients` | Connection queue depth; also scales the product above |
| `servers_per_port` | When `>0`, ignore `workers`; discover local object-ring ports; **parent supervises one OS child per (port, worker_index)** — process-isolated like Python. Each child binds one port (REUSEPORT when multiple children share a port) |
| `workers=0` | Keep `ServerConfig` default: `cpus*16` clamped to `16..128` |

Tooling (exact runtime mapping):

```bash
swift-effective-concurrency --workers 2 --max-clients 64
swift-effective-concurrency --servers-per-port 4 --max-clients 1024 --ports 1
# or (no binary needed):
python3 tools/fairness-lab/scripts/effective-concurrency.py --workers 2 --max-clients 64 --json
```

## `servers_per_port` honesty

| Aspect | Status |
|--------|--------|
| Ring port discovery (`object*.ring.gz`, `ring_ip` / `bind_ip`) | **Implemented** |
| Per-device object ring ports in `build_rings.sh.j2` (`object_port_per_device`, d1→6200, d2→6201, …) | **Implemented** (template + group_vars default true) |
| Multi-port + REUSEPORT acceptors | **Implemented** (child siblings share a port) |
| Per-disk I/O isolation via OS processes | **Implemented** (Wave 2: process-per-port re-exec supervise) |
| Contabo lab rings | **Backlog** — live rebuild (no wipe) after Wave 0 frees space; today discovery still returns `{6200}` until rings are rebuilt with `object_port_per_device` |

## ISO-CONFIG checklist

1. Run `swift-effective-concurrency` for both sides' knobs.
2. Match `worker_threads` / CPU quota, not raw `workers`.
3. Tag claims `ISO-CONFIG` + `iso-config` for `servers_per_port` process model; Contabo single-port rings remain a deploy residual until rebuild.
4. Do not compare CORE-PATH tables taken under different effective concurrency.

Evidence: `tools/test-results/wave2-spp-region-YYYYMMDD/` (and prior `p2c-topology-YYYYMMDD/`).
