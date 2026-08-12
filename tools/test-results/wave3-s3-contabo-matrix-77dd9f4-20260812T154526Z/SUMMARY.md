# Contabo live S3 extended matrix — 77dd9f4 / 20260812T154526Z

**VERDICT=GREEN** — passed=29 failed=0

## Scope (honest)
Bounded extended live matrix against Contabo VIP `https://10.0.0.10:8085` from `swift1`.
Tip binary SHA `117d7b088e691be6826cca0fca067353bfc52c76f96b25aec1882f1d80d3052c` (77dd9f4).

This is **longer than** the short EC2 SigV4 smoke (`wave3-s3-contabo-sigv4-77dd9f4-20260812T153101Z`), but is **NOT**:
- a multi-hour soak
- full `strict-s3-parity.py` dual-oracle (Python Swift peer not in this Contabo path)
- versioning / WORM / aws-chunked / SigV2 live coverage

## Ops
- PASS `tempauth-sigv4:ListBuckets` http=200
- PASS `tempauth-sigv4:CreateBucket` http=200
- PASS `tempauth-sigv4:PutObject` http=200
- PASS `tempauth-sigv4:HeadObject` http=200
- PASS `tempauth-sigv4:GetObject` http=200
- PASS `tempauth-sigv4:GetObjectRange` http=206
- PASS `tempauth-sigv4:ListObjectsV1` http=200
- PASS `tempauth-sigv4:ListObjectsV2` http=200
- PASS `tempauth-sigv4:GetBucketLocation` http=200
- PASS `tempauth-sigv4:GetBucketAcl` http=200
- PASS `tempauth-sigv4:GetObjectAcl` http=200
- PASS `tempauth-sigv4:CopyObject` http=200
- PASS `tempauth-sigv4:GetCopiedObject` http=200
- PASS `tempauth-sigv4:MultiDelete` http=200
- PASS `tempauth-sigv4:CreateMultipartUpload` http=200
- PASS `tempauth-sigv4:UploadPart` http=200
- PASS `tempauth-sigv4:ListParts` http=200
- PASS `tempauth-sigv4:ListMultipartUploads` http=200
- PASS `tempauth-sigv4:AbortMultipartUpload` http=204
- PASS `tempauth-sigv4:DeleteObject` http=204
- PASS `tempauth-sigv4:DeleteBucket` http=204
- PASS `ec2-sigv4:ListBuckets` http=200
- PASS `ec2-sigv4:CreateBucket` http=200
- PASS `ec2-sigv4:PutObject` http=200
- PASS `ec2-sigv4:HeadObject` http=200
- PASS `ec2-sigv4:GetObject` http=200
- PASS `ec2-sigv4:ListObjectsV1` http=200
- PASS `ec2-sigv4:DeleteObject` http=204
- PASS `ec2-sigv4:DeleteBucket` http=204

## Evidence
- Remote: `/root/work/peregrine-artifacts/wave3-s3-contabo-matrix-77dd9f4-20260812T154526Z/`
- Mac mirror: `tools/test-results/wave3-s3-contabo-matrix-77dd9f4-20260812T154526Z/`
