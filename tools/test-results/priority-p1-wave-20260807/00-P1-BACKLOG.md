# P1 wave · 2026-08-07 (after P0 publish)

| # | Item | Workflow | Status |
|---|------|----------|--------|
| P1-1 | ListObjects XML / s3cmd ls | impl-listobjects-s3cmd-xml | open |
| P1-2 | ListVersions pagination | impl-listversions-pagination | **KEEP** unit 20260807 |
| P1-3 | Trailer chunk signature | impl-trailer-chunk-sig | open (parallel) |
| P1-4 | ACP grant enforcement subset | impl-acl-grant-enforcement | open |

Gate: cargo test -p swift-s3api --lib
Root: /Users/oboy/Downloads/Peregrine
