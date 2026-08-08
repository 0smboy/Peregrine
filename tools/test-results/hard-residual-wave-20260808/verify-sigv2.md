# STRICT VERIFY — item1 SigV2

**Date:** 2026-08-08  
**Workspace:** `/Users/oboy/Downloads/Peregrine/swift-rust`  
**Command:**
```bash
export CARGO_HOME=/Users/oboy/Downloads/Peregrine/.cargo-home
cd /Users/oboy/Downloads/Peregrine/swift-rust
cargo test -p swift-s3api --lib -- sigv2
```

## VERDICT: KEEP

## Test counts
| Metric | Count |
|--------|------:|
| passed | 11 |
| failed | 0 |
| ignored | 0 |
| measured | 0 |
| filtered out | 209 |
| duration | 0.00s |

## Required paths
| Requirement | Test | Result |
|-------------|------|--------|
| AWS vector | `sigv2::tests::aws_vector_string_to_sign_and_signature` | ok |
| Middleware good-sig | `middleware::tests::sigv2_header_auth_good_sig_reaches_backend` | ok |

## Full test list
```
test middleware::tests::is_sigv2_detects_header_and_query ... ok
test sigv2::tests::parse_header_with_colon_in_access_key ... ok
test sigv2::tests::base64_encode_vectors ... ok
test sigv2::tests::parse_query_auth ... ok
test middleware::tests::sigv2_header_auth_bad_sig_is_403 ... ok
test sigv2::tests::amz_headers_sorted_into_string_to_sign ... ok
test middleware::tests::sigv2_query_auth_bad_sig_is_403 ... ok
test sigv2::tests::rejected_signature ... ok
test middleware::tests::sigv2_header_auth_good_sig_reaches_backend ... ok
test sigv2::tests::query_auth_expired_fails ... ok
test sigv2::tests::aws_vector_string_to_sign_and_signature ... ok

test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 209 filtered out; finished in 0.00s
```

## Notes
- Build: `Finished test profile` (pre-built; 0.04s)
- Warnings only in `swift-middleware` (unused import / dead code); none failed tests
- Package: `swift-s3api` lib filter `sigv2`
