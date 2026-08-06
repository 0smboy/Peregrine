# P2b auditor evidence — GREEN

Date: 2026-08-04  
VIP: `http://10.0.0.10:8085`  
Verdict: **GREEN**

## What ran

1. Continuous auditor daemons (object + account + container DB) on Contabo ×4.
2. Unit tests: `swift-diskfile` / `swift-db` `audit_devices` + list helpers.
3. Quarantine E2E: corrupt one replica → hash dir moved under `quarantined/`; client GET still 200.
4. CORE-PATH func **54/54**; nightly timer disabled; container-sync explicit wontfix.

## Results

| Gate | Result |
|------|--------|
| cargo auditor unit tests | PASS (`05-cargo-unit.txt`) |
| units active ×4 | PASS (`20-daemon-status.txt`) |
| Quarantine E2E | **PASS** (`10-quarantine-e2e.txt`) |
| CORE-PATH func VIP | **54/54** (`12-func-suite-vip.txt` / `22-func-suite-vip.txt`) |
| Nightly timer | disabled |
| Disk | no wipe; swift1 d1 observed **100%** during cycle (lab residual) |

## SLA

Continuous daemon with Python-default intervals (object 30s, DB 1800s).  
See `docs/fairness-lab/AUDITOR-SLA.md`. Not timer-equivalent.

## Wontfix

container-sync full proxy filter + daemon path — library HMAC/sync-row core only.
