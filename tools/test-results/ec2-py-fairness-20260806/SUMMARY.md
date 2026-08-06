# EC2 s3token + Python fairness · 2026-08-06

## EC2 SigV4 (Keystone s3tokens)

| Gate | Result |
|------|--------|
| Create OS-EC2 credential (tenant_id) | PASS |
| ListBuckets / Create / Put / Get | **PASS 200** |
| Body match | `ec2-regression-ok` |

**Verdict: GREEN** (`03-ec2-create-retry.txt`)

Note: listing existing EC2 creds does not return `secret`; must create new credential for live SigV4.

## Python 3-node func-suite

| Endpoint | Result |
|----------|--------|
| `http://10.0.0.2:8090` | **PASS=54 FAIL=0** |
| `http://10.0.0.3:8090` | **PASS=54 FAIL=0** |
| `http://10.0.0.4:8090` | **PASS=54 FAIL=0** |

**Verdict: GREEN** — stage-3 Python path live and parity-clean under TempAuth.

Auth: `test:tester` / `[REDACTED-LAB-KEY]`
