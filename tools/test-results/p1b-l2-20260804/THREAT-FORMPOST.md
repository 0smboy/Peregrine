# Formpost threat note (P1b)

**Scope:** Contabo VIP `http://10.0.0.10:8085` with P1b pipeline including `formpost`.  
**Date:** 2026-08-04

## Threat model (short)

Formpost accepts unauthenticated browser `POST multipart/form-data` uploads when
the form carries a valid HMAC over
`path\nredirect\max_file_size\max_file_count\nexpires`, keyed by an account or
container Temp-URL key.

| Threat | Mitigation | Evidence |
|--------|------------|----------|
| Forged signature | HMAC verify against all Temp-URL keys; constant-time compare | suite: tampered → 401 |
| Replay after expiry | `expires` checked at verify time | suite: expired → 401 |
| Oversized upload | `max_file_size` enforced before PUT (buffered to cap+1) | unit + suite |
| Too many files | `max_file_count` enforced | unit |
| Keyless account | empty key list → 401 invalid signature | unit |
| Client forging backend headers | `gatekeeper` strips `X-Backend-*` | P0 gatekeeper |

## Deferred / wontfix (honest)

- Metrics counters (`formpost.digests.*`)
- Mid-stream abort of an already-accepted backend PUT when size overflows
  after bytes have been forwarded (we cap before the subrequest)

## Negatives run

VIP specialty suite (`p1b-l2-suite.sh`): valid upload 201, tampered 401, expired 401.
