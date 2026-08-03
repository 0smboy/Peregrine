# Operating modes

## Compatibility

- Python and Rust **concurrent**
- Disks: Python=`d1`, Rust=`d2`, `d3` reserved (when mode fully provisioned)
- Separate API/backend ports and separate rings (`part_power=9`, 3 replicas)
- Purpose: differential API / “does it behave like Swift?”
- **Throughput from this mode is never a formal performance conclusion**

## Performance

- Exactly **one** implementation owns all 12 disks
- Other implementation: units stopped, **zero residual listeners**
- Entry paths:
  - `DIRECT-4PROXY` — core throughput (distribute across `10.0.0.1–4`)
  - `HA-PATH` — VIP `10.0.0.10` + HAProxy (separate scorecard)
- Profiles: `DATA-PATH` (background stopped after healthy baseline) vs `PRODUCTION-COMPLETE`
- Rings: fresh 12-device, `part_power=11`, checksum in run manifest
- Scheduling: warm-up discarded; formal `A-B-B-A` / `B-A-A-B`; ≥8 measured runs per workload point

## Chaos

- One implementation owns the cluster
- Scripted, timestamped faults under steady load
- Rings frozen unless the scenario is rebalance
- No “foreground-only” score masquerading as chaos

## Mode switch tooling

```bash
tools/fairness-lab/scripts/mode-switch.sh status|stop|perf-rust|perf-python|compat|install-targets
```

## Destructive reset

Only Performance/Chaos. Dual guard:

```bash
ALLOW_DESTRUCTIVE_RESET=YES CONFIRM_TICKET=<id> \
  tools/fairness-lab/scripts/destructive-reset.sh inventory/devices.json
```

Agent automation **refuses to execute** the wipe (exit 3); human operator runs the remote sequence after by-id review. Daily ops and Compatibility must not wipe.
