# Contabo live inventory overlay (2026-08-06)

Aligns `bundle-rust` **intent** with the live Contabo topology after Wave 2/4:

| Live fact | Sample default (old) | This overlay |
|-----------|----------------------|--------------|
| object ports | 6200 + index on d1… | **6210 base** → d2:**6211**, d3:**6212** |
| object devices | d1 (or all) | **d2, d3** (d1 = Python on 2/3/4) |
| A/C | all devices / 6201–2 | **d2 only**, ports 6201/6202 |
| spp | 0 | **1** |
| region | single | r1=swift1/2, r2=swift3/4 (labels) |
| TLS | http | **https** self-signed LAB |

## Gaps still in templates (code follow-up)

1. `build_rings.sh.j2` uses `object_bind_port + device_index` for **all** `swift_devices` in list order — OK if list is only d2,d3 starting at 6210 → 6210,6211 **BUT live listeners are 6211/6212** with conf `bind_port=6210` + spp discovery. Need ring dump reconciliation: live get-nodes shows **6211/6212** for d2/d3 (index from 6210 with d1 skipped historically).
2. Account/container still iterate all `swift_devices` in template — live rings are **d2-only**; overlay cannot express "A/C devices ≠ object devices" without template change (`account_container_devices`).
3. Default sample `object_servers_per_port: 0` would regress Contabo if applied.

## Safe use

- Copy snippets into a Contabo workspace inventory **after** human review.
- Prefer **no ring rebuild** unless ticket; rings already live.
- `swift-deploy plan` dry-run must show zero disk wipe and ports matching 621x.

Evidence: `tools/test-results/deploy-align-20260806/`.
