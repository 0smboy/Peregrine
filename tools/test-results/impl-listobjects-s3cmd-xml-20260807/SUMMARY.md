# P1-1 ListObjects XML / s3cmd `ls` · StrictVerify · 2026-08-07

## VERDICT: **KEEP (unit)**

ListObjects v1/v2 responses use `Content-Type: application/xml`, S3 xmlns on
`ListBucketResult`, and quote-wrapped Contents ETags (Python/AWS shape).
`cargo test -p swift-s3api --lib` **201 passed; 0 failed**.

**Claim boundary:** unit + code-path only. Not live Contabo s3cmd re-run.
Not PRODUCTION-GO-LIVE.

---

## Gate (this run)

```text
cd /Users/oboy/Downloads/Peregrine/swift-rust
cargo test -p swift-s3api --lib 2>&1 | tee \
  /Users/oboy/Downloads/Peregrine/tools/test-results/impl-listobjects-s3cmd-xml-20260807/cargo-test.txt

# → test result: ok. 201 passed; 0 failed
```

### List-focused tests (all ok)

| Test | Asserts |
|------|---------|
| `response::tests::test_list_bucket_result_into_response_content_type_and_etag` | CT + xmlns + quoted ETag (v1) |
| `response::tests::test_list_bucket_result_v2_into_response_content_type_and_etag` | CT + xmlns + quoted ETag (v2) |
| `response::tests::test_list_bucket_result_shape` | full v1 XML golden |
| `middleware::tests::list_objects_translates` | CT + xmlns + ETag + limit=1001 |
| `middleware::tests::list_objects_v2_emits_key_count` | CT + xmlns + ETag (v2) |
| `middleware::tests::list_objects_truncation_and_common_prefixes` | IsTruncated + CommonPrefixes + NextMarker |

---

## Grep: ListBucketResult + Content-Type

Source anchors (see `02-content-type-grep.txt`):

- `response.rs` `xml_response` / `into_response` → `Content-Type: application/xml`
- `ListBucketResult` / `ListBucketResultV2` root → `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`
- `object_element` → `ensure_quoted_etag` → `<ETag>"…"</ETag>`
- `middleware.rs` `translate_list_objects` / `_v2` → `lbr.into_response()`
- Middleware tests assert `resp.headers.get("Content-Type") == Some("application/xml")`

---

## Paths

| Role | Path |
|------|------|
| **Root / mainline** | `/Users/oboy/Downloads/Peregrine` |
| **Package** | `/Users/oboy/Downloads/Peregrine/swift-rust/crates/swift-s3api` |
| **Agent worktree** | `/Users/oboy/.grok/worktrees/downloads-swift-master/subagent-019fdb4d-96f4-7243-9fd1-bc448179664f` |
| **Evidence** | `/Users/oboy/Downloads/Peregrine/tools/test-results/impl-listobjects-s3cmd-xml-20260807/` |

Edits landed on Peregrine mainline (`swift-rust/crates/swift-s3api/src/{response,middleware}.rs`).
Worktree is the isolation handle for this agent session.

---

## Residual

- Live s3cmd `ls` @ Contabo VIP not re-run this pack.
- v2 `NextContinuationToken` still raw key (Python base64); s3cmd uses v1 markers.
