# container-sync live probe · Contabo · 2026-08-06

**Verdict: PATH NOT DEPLOYED**

| Item | Result |
|------|--------|
| `swift-container-sync` binary | **absent** on Contabo (`/usr/local/bin`) |
| systemd unit | inactive / not installed |
| conf `[container-sync]` | not present in live container-server.conf |

Code path exists in git (`swift-container-sync` binary + proxy filter + HTTPS + CA knobs).  
**Multi-cluster live soak / Contabo enable:** requires binary deploy + remote Sync-To pair — not done this wave.
