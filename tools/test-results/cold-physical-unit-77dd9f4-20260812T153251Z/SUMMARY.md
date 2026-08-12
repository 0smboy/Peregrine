# Peregrine B+C closeout — physical cold (lab LocalDir) + Contabo SigV4

Date: 2026-08-12 (Asia/Singapore)
Base tip: `77dd9f4` (fleet binary SHA `117d7b088e691be6826cca0fca067353bfc52c76f96b25aec1882f1d80d3052c`)
Stance: **IMPLEMENTED_SUBSET_ONLY**

## C — Contabo live S3 SigV4 (short smoke) — GREEN

- Host: swift1 → VIP `https://10.0.0.10:8085`
- Pipeline: `s3api` + `s3token` present; `/info` does **not** advertise s3api
- Probe: `probe_ec2_sigv4.py` (Keystone EC2)
- Ops: ListBuckets / CreateBucket / PutObject / GetObject → HTTP 200; cleanup 204
- Region: `us-east-1`
- Evidence: `tools/test-results/wave3-s3-contabo-sigv4-77dd9f4-20260812T153101Z/`
- Remote: `/root/work/peregrine-artifacts/wave3-s3-contabo-sigv4-77dd9f4-20260812T153101Z`
- **Not claimed:** multi-hour matrix, full `strict-s3-parity` live suite, AWS IAM cloud

## B — Physical cold lab backend — UNIT GREEN (not fleet-redeployed)

### Landed (code on Mac tree, pending push)
- `LocalDirColdBackend` (`filecold://…`) + `MemoryColdBackend` in `cold_tier.rs`
- `S3Api.cold_backend` + `with_cold_backend`
- Proxy config: `[filter:s3api] cold_backend_root=` or alias `filecold_root=`
- `?restore` RestoreObject: POST stamps restore meta; if URI + backend wired → `restore_stage`
- Unit evidence (swift3): cold_tier 5/5, restore 2/2, proxy wire 1/1 → VERDICT GREEN
  - `tools/test-results/cold-physical-unit-77dd9f4-20260812T153251Z/`

### Claim boundary
- **Lab local bytes only** — not tape / Glacier cloud / Contabo object-lock media
- Default fleet config does **not** set `cold_backend_root` → behavior unchanged until configured
- **Still OPEN:** archive-on-transition (lifecycle due → `ColdBackend::archive` + stamp `SYS_COLD_BACKEND_URI` on live path); physical cold not enabled on Contabo fleet

## Next
1. Commit/push cold+restore branch from `77dd9f4`
2. Optional: wire archive-on-transition + lab enable `cold_backend_root` + canary
3. Optional: longer Contabo S3 matrix (`strict-s3-parity.py`) when wanted
