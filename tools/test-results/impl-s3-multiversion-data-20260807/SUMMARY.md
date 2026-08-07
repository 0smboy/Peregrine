# S3 multi-version data plane · 2026-08-07
## Strict verify
`cargo test -p swift-s3api` → **151 passed; 0 failed**
## Claim
When versioning=Enabled: PUT archives prior; versionId GET/DELETE; delete-marker; ListVersions from `{bucket}+versions`.
