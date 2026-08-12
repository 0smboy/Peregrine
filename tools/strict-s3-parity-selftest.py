#!/usr/bin/env python3
"""Offline self-test for strict-s3-parity.py (standard library only)."""

from __future__ import annotations

import contextlib
import ast
import importlib.util
import io
import json
import os
import pathlib
import stat
import sys
import tempfile


MODULE_PATH = pathlib.Path(sys.argv[1])
SPEC = importlib.util.spec_from_file_location("strict_s3_parity", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

assert len(MODULE.REQUIRED_CASES) == len(set(MODULE.REQUIRED_CASES))
tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
assert not any(isinstance(node, ast.Assert) for node in ast.walk(tree))
literal_cases = {
    call.args[0].value
    for call in ast.walk(tree)
    if isinstance(call, ast.Call)
    and isinstance(call.func, ast.Attribute)
    and call.func.attr == "run"
    and call.args
    and isinstance(call.args[0], ast.Constant)
    and isinstance(call.args[0].value, str)
}
dynamic_cases = {"delete-delete-marker", "delete-version-1", "delete-version-2"}
assert set(MODULE.REQUIRED_CASES) == literal_cases | dynamic_cases


# AWS's published SigV4 GET Object vector.
headers, query = MODULE._signed_request(
    method="GET",
    path="/test.txt",
    query=(),
    body=b"",
    headers={"Range": "bytes=0-9"},
    auth="v4-header",
    access="AKIAIOSFODNN7EXAMPLE",
    secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region="us-east-1",
    host="examplebucket.s3.amazonaws.com",
    signed_at=1369353600,  # 2013-05-24T00:00:00Z
    expires=None,
)
assert not query
assert headers["X-Amz-Date"] == "20130524T000000Z"
assert headers["Authorization"].endswith(
    "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
)


# AWS's published SigV2 GET Object vector. Date is deliberately retained
# verbatim so this tests the exact V2 string-to-sign rather than formatdate().
headers, query = MODULE._signed_request(
    method="GET",
    path="/johnsmith/photos/puppy.jpg",
    query=(),
    body=b"",
    headers={"Date": "Tue, 27 Mar 2007 19:36:42 +0000"},
    auth="v2-header",
    access="AKIAIOSFODNN7EXAMPLE",
    secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region="us-east-1",
    host="s3.amazonaws.com",
    signed_at=1175024202,
    expires=None,
)
assert not query
assert headers["Authorization"] == (
    "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU="
)


# Query signing preserves empty subresources, signs before adding Signature,
# and encodes access keys containing ':' rather than leaking them as syntax.
headers, query = MODULE._signed_request(
    method="GET", path="/bucket/object", query=(("versionId", "a/b"),),
    body=b"", headers={}, auth="v4-query", access="test:tester",
    secret="testing", region="us-east-1", host="swift.example:8080",
    signed_at=1767225600, expires=600,
)
wire = MODULE._wire_query(query)
assert "X-Amz-Signature=" in wire
assert "test%3Atester%2F" in wire
assert "versionId=a%2Fb" in wire
assert "Authorization" not in headers

headers, query = MODULE._signed_request(
    method="GET", path="/bucket", query=(("uploads", ""),), body=b"",
    headers={}, auth="v2-query", access="test:tester", secret="testing",
    region="us-east-1", host="swift.example:8080", signed_at=1767225600,
    expires=1767226200,
)
wire = MODULE._wire_query(query)
assert "uploads=" in wire and "AWSAccessKeyId=test%3Atester" in wire
assert "Signature=" in wire and "Authorization" not in headers


# XML normalizers are schema validators, not regex-based field stripping.
tag_xml = (
    b'<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>"
)
assert MODULE._normalize_tagging(tag_xml, {"a": "b"}) == {"tags": [("a", "b")]}
for invalid in (
    b"<Tagging><Unknown/></Tagging>",
    b"<!DOCTYPE x [<!ENTITY y 'z'>]><Tagging><TagSet/></Tagging>",
    b"<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag>"
    b"<Tag><Key>a</Key><Value>c</Value></Tag></TagSet></Tagging>",
):
    try:
        MODULE._normalize_tagging(invalid, {"a": "b"})
    except MODULE.SchemaError:
        pass
    else:
        raise AssertionError("invalid XML schema was accepted")

error = (b"<Error><Code>AccessDenied</Code><Message>Request has expired</Message>"
         b"<RequestId>abc123</RequestId></Error>")
normalized = MODULE._normalize_error(error, "AccessDenied")
assert normalized["RequestId"] == "<dynamic-id>"
for invalid in (
    b"<Error><Code>Wrong</Code><Message>x</Message></Error>",
    b"<Error><Code>AccessDenied</Code><Message>x</Message><Mystery>y</Mystery></Error>",
):
    try:
        MODULE._normalize_error(invalid, "AccessDenied")
    except MODULE.SchemaError:
        pass
    else:
        raise AssertionError("invalid S3 Error XML was accepted")


class DummyClient:
    def request(self, *_args, **_kwargs):
        raise AssertionError("network must not be used by offline self-test")


def target(label: str) -> object:
    return MODULE.Target(label, "http://{}.example:8080".format(label),
                         "test:tester", "testing", "us-east-1",
                         "{}@verified".format(label), DummyClient())


py = target("python")
rs = target("rust")

bucket = "peregrine-s3-20260811-0123456789abcdef"
listing = (
    "<ListBucketResult><Name>{}</Name><Prefix></Prefix><KeyCount>1</KeyCount>"
    "<MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents>"
    "<Key>a.txt</Key><LastModified>2026-08-11T00:00:00.000Z</LastModified>"
    "<ETag>\"900150983cd24fb0d6963f7d28e17f72\"</ETag><Size>3</Size>"
    "<StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>"
).format(bucket).encode("utf-8")
assert MODULE._normalize_listing(
    listing, bucket, {"a.txt": (3, '"900150983cd24fb0d6963f7d28e17f72"')}, True, py,
)["objects"][0]["key"] == "a.txt"

mpu_init = (
    "<InitiateMultipartUploadResult><Bucket>{}</Bucket><Key>m.bin</Key>"
    "<UploadId>upload-py-1</UploadId></InitiateMultipartUploadResult>"
).format(bucket).encode("utf-8")
assert MODULE._normalize_mpu_init(mpu_init, py, bucket, "m.bin")["upload_id"] == "<upload-id>"
mpu_complete = (
    "<CompleteMultipartUploadResult><Location>/{}/m.bin</Location><Bucket>{}</Bucket>"
    "<Key>m.bin</Key><ETag>\"900150983cd24fb0d6963f7d28e17f72\"</ETag>"
    "</CompleteMultipartUploadResult>"
).format(bucket, bucket).encode("utf-8")
assert MODULE._normalize_mpu_complete(
    mpu_complete, bucket, "m.bin", '"900150983cd24fb0d6963f7d28e17f72"',
)["bucket"] == "<owned-bucket>"

py.versions.update({"v1": "py-v1", "v2": "py-v2", "dm": "py-dm"})
versions = (
    "<ListVersionsResult><Name>{}</Name><Prefix>state</Prefix><MaxKeys>1000</MaxKeys>"
    "<IsTruncated>false</IsTruncated>"
    "<DeleteMarker><Key>state</Key><VersionId>py-dm</VersionId><IsLatest>true</IsLatest>"
    "<LastModified>2026-08-11T00:00:02.000Z</LastModified></DeleteMarker>"
    "<Version><Key>state</Key><VersionId>py-v2</VersionId><IsLatest>false</IsLatest>"
    "<LastModified>2026-08-11T00:00:01.000Z</LastModified>"
    "<ETag>\"900150983cd24fb0d6963f7d28e17f72\"</ETag><Size>3</Size>"
    "<StorageClass>STANDARD</StorageClass></Version>"
    "<Version><Key>state</Key><VersionId>py-v1</VersionId><IsLatest>false</IsLatest>"
    "<LastModified>2026-08-11T00:00:00.000Z</LastModified>"
    "<ETag>\"d16fb36f0911f878998c136191af705e\"</ETag><Size>3</Size>"
    "<StorageClass>STANDARD</StorageClass></Version></ListVersionsResult>"
).format(bucket).encode("utf-8")
assert len(MODULE._normalize_list_versions(
    versions, py, bucket, "state",
    {
        "v1": ("Version", 3, '"d16fb36f0911f878998c136191af705e"', False),
        "v2": ("Version", 3, '"900150983cd24fb0d6963f7d28e17f72"', False),
        "dm": ("DeleteMarker", 0, None, True),
    },
)["entries"]) == 3

acl = (
    b'<AccessControlPolicy xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    b"<Owner><ID>owner</ID></Owner><AccessControlList><Grant>"
    b'<Grantee xsi:type="CanonicalUser"><ID>owner</ID></Grantee>'
    b"<Permission>FULL_CONTROL</Permission></Grant></AccessControlList>"
    b"</AccessControlPolicy>"
)
assert MODULE._normalize_acl(acl, py)["grants"] == [("OWNER", "FULL_CONTROL")]

snap_ok = MODULE.Snapshot(200, {"content-length": ("0",)}, b"")
runner = MODULE.Runner(bucket, py, rs)
with contextlib.redirect_stdout(io.StringIO()):
    assert runner.run(
        "create-bucket", lambda _target: snap_ok, (200,), MODULE._empty_body,
        {"content-length": ("uint", "0")},
    )
assert runner.results[-1].passed

snap_bad = MODULE.Snapshot(204, {"content-length": ("0",)}, b"")
runner = MODULE.Runner(bucket, py, rs)
with contextlib.redirect_stdout(io.StringIO()):
    assert not runner.run(
        "create-bucket", lambda selected: snap_ok if selected.label == "python" else snap_bad,
        (200,), MODULE._empty_body, {"content-length": ("uint", "0")},
    )
assert any("status mismatch" in issue for issue in runner.results[-1].issues)


# Dynamic version headers may differ on wire but must be non-null, bounded,
# stable, and map to the same semantic label.
py_snap = MODULE.Snapshot(200, {"x-amz-version-id": ("py-version-1",)}, b"")
rs_snap = MODULE.Snapshot(200, {"x-amz-version-id": ("rs-version-1",)}, b"")
assert MODULE._normalize_headers(py_snap, py, {
    "x-amz-version-id": ("capture-version", "version-1")
}) == {"x-amz-version-id": "<version-1>"}
assert MODULE._normalize_headers(rs_snap, rs, {
    "x-amz-version-id": ("capture-version", "version-1")
}) == {"x-amz-version-id": "<version-1>"}
try:
    MODULE._normalize_headers(
        MODULE.Snapshot(200, {"x-amz-version-id": ("changed",)}, b""), py,
        {"x-amz-version-id": ("capture-version", "version-1")},
    )
except MODULE.SchemaError:
    pass
else:
    raise AssertionError("changed version ID was accepted")


# Cleanup refuses to touch anything without both ownership-clear and a create
# attempt. This is the destructive-action stop line.
fresh = target("python")
cleanup = MODULE._cleanup_target(fresh, "peregrine-s3-20260811-0123456789abcdef")
assert cleanup["attempted"] is False and cleanup["passed"] is True


with tempfile.TemporaryDirectory() as directory:
    destination = pathlib.Path(directory) / "report.json"
    MODULE._atomic_report(destination, {"schema": "test", "secret": None})
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert json.loads(destination.read_text(encoding="utf-8"))["schema"] == "test"
    link = pathlib.Path(directory) / "link.json"
    link.symlink_to(destination)
    try:
        MODULE._atomic_report(link, {})
    except MODULE.ConfigError:
        pass
    else:
        raise AssertionError("symlink report target was accepted")


assert MODULE._merge_exit(0, 1) == 1
assert MODULE._merge_exit(1, 2) == 2
assert MODULE._merge_exit(2, 1) == 2
assert MODULE._merge_exit(2, 130) == 130
assert MODULE._merge_exit(130, 2) == 130

for invalid_endpoint in (
    "ftp://swift.example", "http://user:pass@swift.example",
    "http://swift.example/path", "http://swift.example?x=1",
):
    try:
        MODULE._validate_endpoint(invalid_endpoint, "test")
    except MODULE.ConfigError:
        pass
    else:
        raise AssertionError("unsafe endpoint was accepted")


# A pre-target configuration error still returns 2 and creates a 0600 JSON
# report. Capture output to keep the self-test deterministic.
with tempfile.TemporaryDirectory() as directory:
    report = pathlib.Path(directory) / "config-error.json"
    saved = {name: os.environ.pop(name, None) for name in (
        "PEREGRINE_S3_PY_ACCESS", "PEREGRINE_S3_PY_SECRET",
        "PEREGRINE_S3_RS_ACCESS", "PEREGRINE_S3_RS_SECRET",
    )}
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = MODULE.main([
                "--python", "http://python.example:8090",
                "--rust", "http://rust.example:8080",
                "--python-provenance", "python@a",
                "--rust-provenance", "rust@b",
                "--json-report", str(report),
            ])
        assert rc == MODULE.EXIT_RUNTIME_FAILURE
        parsed = json.loads(report.read_text(encoding="utf-8"))
        assert parsed["summary"]["gate"] == "ERROR"
        assert parsed["summary"]["skipped"] == 0
        assert stat.S_IMODE(report.stat().st_mode) == 0o600
    finally:
        for name, value in saved.items():
            if value is not None:
                os.environ[name] = value


print("strict-s3-parity offline self-test: PASS")
