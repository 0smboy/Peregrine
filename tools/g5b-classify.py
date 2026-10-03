#!/usr/bin/env python3
"""Classify a G5-B (Ceph s3compat) FAIL/ERROR census by root-cause signature.

Input: `fail_error_names.txt` as produced by the lab harvest, one record per
line: `STATUS<TAB>module<TAB>test_name<TAB>detail`.

The point is to separate three very different things that a raw PASS count
hides:

  harness   the test never reached the engine (missing config section,
            client-side validation, or a bug in the test itself)
  swift-vs-rgw
            the suite asserts RGW behavior that Python Swift does not have
            either, so it is not a Rust regression; it belongs in a frozen
            known-failure list per the G5 capability policy
  engine    a real engine-side gap or defect worth scoring against Rust

Membership in `swift-vs-rgw` must be justified by a dual-oracle observation,
not by opinion. Signatures below carry the evidence that put them there.

Usage:
  tools/g5b-classify.py fail_error_names.txt [--names CLASS] [--json]
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys

HARNESS = "harness"
SWIFT_VS_RGW = "swift-vs-rgw"
ENGINE = "engine"
UNCLASSIFIED = "unclassified"

# (class, signature id, regex, evidence note)
SIGNATURES: list[tuple[str, str, str, str]] = [
    (
        HARNESS,
        "sts-config-missing",
        r'missing the "(iam|webidentity)" section',
        "ceph-s3.live-13be1dbc.cfg has no [iam]/[webidentity] section; the "
        "harness aborts before any request is sent",
    ),
    (
        HARNESS,
        "botocore-client-side-validation",
        r"Parameter validation failed",
        "botocore rejected the argument locally; no request reached the engine",
    ),
    (
        HARNESS,
        "test-code-py2ism",
        r"'str' object has no attribute 'decode'",
        "py2-era test code under py3 (the H90 soft leftover)",
    ),
    (
        HARNESS,
        "test-code-nameerror",
        r"name '\w+' is not defined",
        "defect in the test body itself",
    ),
    (
        HARNESS,
        "test-code-attr-on-exception",
        r"object has no attribute 'status'",
        "test reads a boto2 attribute off a boto3 exception",
    ),
    (
        HARNESS,
        "harness-wrong-endpoint",
        r"Could not connect to the endpoint URL: \"http://localhost:8000",
        "tenant test points at localhost:8000, which is not the lab endpoint",
    ),
    (
        SWIFT_VS_RGW,
        "create-bucket-not-idempotent",
        r"BucketAlreadyOwnedByYou",
        "dual-oracle 2026-09-18: Rust tip :18080 and Python Swift 2.38.0 "
        "s3api :8090 both answer 409 BucketAlreadyOwnedByYou to a same-owner "
        "re-create; the suite assumes RGW/us-east-1 200",
    ),
    (
        SWIFT_VS_RGW,
        "rgw-usage-extension",
        r"X-RGW-Object-Count|x-rgw-object-count|subresource 'usage' is not implemented",
        "RGW-only usage/extended-head surface, absent from Swift by design",
    ),
    (
        SWIFT_VS_RGW,
        "rgw-append-extension",
        r"test_append",
        "RGW object-append extension; not part of the AWS S3 or Swift surface",
    ),
    (
        SWIFT_VS_RGW,
        "acl-grant-by-email",
        r"UnresolvableGrantByEmailAddress",
        "grant-by-email requires an RGW-style account directory",
    ),
    (
        ENGINE,
        "bucket-logging-unimplemented",
        r"subresource 'logging' is not implemented",
        "bucket logging is unimplemented in the engine",
    ),
    (
        ENGINE,
        "sse-kms-unimplemented",
        r"Server-side encryption with aws:kms is not implemented",
        "SSE-KMS is unimplemented in the engine",
    ),
    (
        ENGINE,
        "sse-c-not-rejected",
        r"test_encryption_(sse_c|key_no_sse_c)",
        "engine accepted an SSE-C request the suite expects it to reject",
    ),
    (
        ENGINE,
        "sse-kms-not-rejected",
        r"test_sse_kms_(not_declared|read_declare)",
        "engine did not raise where the suite expects an SSE-KMS declaration "
        "error; same unimplemented surface as sse-kms-unimplemented",
    ),
    (
        ENGINE,
        "object-lock-delete-denied",
        r"test_object_lock.*",
        "AccessDenied where the suite expects the delete/retention call to be "
        "allowed; one suspected shared root cause",
    ),
    (
        ENGINE,
        "wrong-error-bucketnotempty",
        r"BucketNotEmpty",
        "PutObject/UploadPart answered with a BucketNotEmpty code; error "
        "mapping defect, possibly aggravated by the degraded lab container "
        "replication",
    ),
    (
        ENGINE,
        "presign-expires-range",
        r"test_object_raw_(get_x_amz_expires|put_authenticated_expired)",
        "400 where the suite expects 403 on an out-of-range presign",
    ),
    (
        ENGINE,
        "lifecycle-count-timing",
        r"test_lifecycle",
        "expiration counts/timing differ from the suite's expectation",
    ),
    (
        ENGINE,
        "header-validation-missing",
        r"test_(object|bucket)_create_bad_",
        "engine accepted a malformed request the suite expects it to reject",
    ),
    (
        ENGINE,
        "policy-condition-ifexists",
        r"test_bucket_policy|test_bucketv2_policy|test_user_policy",
        "bucket/user policy evaluation gap",
    ),
    (
        ENGINE,
        "versioned-concurrency",
        r"test_versioned_concurrent",
        "known flake plus a concurrent create/remove mismatch",
    ),
    (
        ENGINE,
        "list-ctime",
        r"test_buckets_list_ctime",
        "bucket ctime source differs from the suite's expectation",
    ),
    (
        ENGINE,
        "unreadable-object-read",
        r"test_object_read_unreadable",
        "404 where the suite expects 400",
    ),
]


def parse(path: str) -> list[dict]:
    records = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            records.append(
                {
                    "status": parts[0].strip(),
                    "module": parts[1].strip(),
                    "test": parts[2].strip(),
                    "detail": parts[3] if len(parts) > 3 else "",
                }
            )
    return records


def classify(rec: dict) -> tuple[str, str, str]:
    haystack = f"{rec['module']} {rec['test']} {rec['detail']}"
    for cls, sig, pattern, note in SIGNATURES:
        if re.search(pattern, haystack):
            return cls, sig, note
    return UNCLASSIFIED, "unmatched", ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--names", help="print test names for this class or signature")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    records = parse(args.path)
    for rec in records:
        rec["class"], rec["signature"], rec["note"] = classify(rec)

    by_class = collections.Counter(r["class"] for r in records)
    by_sig = collections.Counter((r["class"], r["signature"]) for r in records)

    if args.names:
        for rec in records:
            if args.names in (rec["class"], rec["signature"]):
                print(f"{rec['status']}\t{rec['test']}")
        return 0

    if args.json:
        print(
            json.dumps(
                {
                    "total": len(records),
                    "by_class": dict(by_class),
                    "by_signature": {f"{c}/{s}": n for (c, s), n in sorted(by_sig.items())},
                },
                indent=2,
            )
        )
        return 0

    print(f"total FAIL+ERROR records: {len(records)}")
    print()
    for cls in (HARNESS, SWIFT_VS_RGW, ENGINE, UNCLASSIFIED):
        if not by_class[cls]:
            continue
        print(f"{cls}: {by_class[cls]}")
        for (c, sig), n in sorted(by_sig.items(), key=lambda kv: (-kv[1], kv[0][1])):
            if c == cls:
                print(f"    {n:>3}  {sig}")
        print()
    scored = by_class[ENGINE]
    print(
        f"engine-attributable: {scored} of {len(records)}  "
        f"(harness {by_class[HARNESS]}, swift-vs-rgw {by_class[SWIFT_VS_RGW]}"
        + (f", unclassified {by_class[UNCLASSIFIED]}" if by_class[UNCLASSIFIED] else "")
        + ")"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
