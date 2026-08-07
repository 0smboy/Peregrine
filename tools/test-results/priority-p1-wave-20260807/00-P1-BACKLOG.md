# P1 wave · 2026-08-07 (after P0 publish)

| # | Item | Workflow |
|---|------|----------|
| P1-1 | ListObjects XML / s3cmd ls | impl-listobjects-s3cmd-xml |
| P1-2 | ListVersions pagination | impl-listversions-pagination |
| P1-3 | Trailer chunk signature | impl-trailer-chunk-sig |
| P1-4 | ACP grant enforcement subset | impl-acl-grant-enforcement |

Gate: cargo test -p swift-s3api --lib
Root: /Users/oboy/Downloads/Peregrine
