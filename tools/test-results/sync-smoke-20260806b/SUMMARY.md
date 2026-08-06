# container-sync same-cluster smoke · 2026-08-06b

| Item | Result |
|------|--------|
| Binary | present `50f4ca39…` |
| POST Sync-To / Sync-Key | **204** both containers |
| `swift-container-sync … once` | exit 0 (timeout 45s) |
| Destination object count | **0** (no rows synced) |
| Multi-cluster soak | **not run** |

**Claim:** binary + meta wiring smoke only. Sync path **not** lab-green for object movement (realm/internal_url/auth residual).
