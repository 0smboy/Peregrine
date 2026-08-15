#!/usr/bin/env python3
"""Offline self-test for strict-extended-parity.py (no network)."""

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import stat
import sys
import tempfile


module_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("strict_extended_parity", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


assert len(module.BASE_CASE_NAMES) == 28
assert len(module.ACL_CASE_NAMES) == 9
assert len(set(module.BASE_CASE_NAMES)) == len(module.BASE_CASE_NAMES)
assert not set(module.BASE_CASE_NAMES).intersection(module.ACL_CASE_NAMES)

ec_payload, segment_one, segment_two = module._payloads()
assert len(ec_payload) == 2 * 1024 * 1024
assert module._md5_hex(ec_payload) == "47813e80213cefd78c4b12282a5b41a3"
assert module._sha256_hex(ec_payload) == (
    "ab74f7f193bbde9c3679a4712380046b853c09004d7c9780f87d4a984a908b15"
)
assert module._md5_hex(segment_one) == "731a99db0ed9802140405654e42a65d4"
assert module._md5_hex(segment_two) == "4dd6fd65d6471232694aad0492bc6133"
assert module._sha256_hex(segment_one + segment_two) == (
    "d02b986efd095ee772a4a2fa72340b2e1a65787234179fb37d7c3ec43660f426"
)
assert module._md5_hex(
    (module._md5_hex(segment_one) + module._md5_hex(segment_two)).encode("ascii")
) == "92849ebd1d6ccb5a1f3b5dea38d783eb"
assert len(module.RANGE_416_BODY) == 97
assert module._sha256_hex(module.RANGE_416_BODY) == (
    "ba190c0c394b00e96fffa7387c456501af3eefbead4e341a5b729195d5c2947a"
)
assert module._normalize_content_type(module.EC_RANGE_416_CONTENT_TYPE) == (
    '["text/html",[["charset","UTF-8"]]]'
)


class AuthClient:
    def __init__(self, storage_url):
        self.storage_url = storage_url

    def request(self, *_args, **_kwargs):
        return module.Snapshot(
            200,
            {
                "x-auth-token": ("must-not-leak-token",),
                "x-storage-url": (self.storage_url,),
            },
            b"",
        )


safe_auth = module._authenticate(
    AuthClient("http://python.example:8090/v1/AUTH_python"),
    "http://python.example:8090",
    "user",
    "must-not-leak-key",
    "http://python.example:8090",
    "AUTH_python",
)
assert safe_auth.storage_path == "/v1/AUTH_python"
for unsafe_url in (
    "/v1/AUTH_python",
    "http://python.example:8090/v1/",
    "http://python.example:8090/v1/AUTH_python/extra",
    "http://python.example:8090/v1/AUTH_other",
    "http://other.example:8090/v1/AUTH_python",
    "http://u:p@python.example:8090/v1/AUTH_python",
    "http://python.example:bad/v1/AUTH_python",
    "http://python.example:8090/v1/AUTH%2Fpython",
):
    try:
        module._authenticate(
            AuthClient(unsafe_url),
            "http://python.example:8090",
            "user",
            "key",
            "http://python.example:8090",
            "AUTH_python",
        )
    except module.ConfigError:
        pass
    else:
        raise AssertionError("unsafe storage URL accepted: {!r}".format(unsafe_url))


assert module._normalize_etag('"ABCDEF0123456789ABCDEF0123456789"') == (
    "abcdef0123456789abcdef0123456789"
)
for invalid_etag in ("abc", "W/\"abcdef0123456789abcdef0123456789\"", "g" * 32):
    try:
        module._normalize_etag(invalid_etag)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid ETag accepted")

left = module._normalize_header(
    "content-type", ("application/json; charset=utf-8; profile=x",)
)
right = module._normalize_header(
    "content-type", ("APPLICATION/JSON; profile=x; charset=utf-8",)
)
assert left == right
for invalid_content_type in (
    "garbage",
    "text/plain;",
    "text/plain; charset",
    "text / plain",
    "text/ plain",
):
    try:
        module._normalize_header("content-type", (invalid_content_type,))
    except ValueError:
        pass
    else:
        raise AssertionError("invalid Content-Type accepted")


raw_expected = [
    {"path": "/segments/p1", "etag": "a" * 32, "size_bytes": 10},
    {"path": "/segments/p2", "etag": "b" * 32, "size_bytes": 11},
]
raw_body = json.dumps(raw_expected, indent=2).encode("utf-8")
assert module._normalize_slo_raw(raw_body, raw_expected)
bad_raw = json.dumps(
    [
        {
            "path": "/segments/p1",
            "etag": "a" * 32,
            "size_bytes": 10,
            "last_modified": "volatile",
        }
    ]
).encode("utf-8")
try:
    module._normalize_slo_raw(bad_raw, raw_expected)
except ValueError:
    pass
else:
    raise AssertionError("SLO raw parser accepted an expanded schema")

listing_expected = [
    {
        "name": "p1",
        "hash": "a" * 32,
        "bytes": 10,
        "content_type": module._normalize_content_type("application/octet-stream"),
    }
]
listing_body = json.dumps(
    [
        {
            "name": "p1",
            "hash": '"{}"'.format("a" * 32),
            "bytes": 10,
            "content_type": "application/octet-stream",
            "last_modified": "2026-08-09T00:00:00.000000",
        }
    ]
).encode("utf-8")
assert module._normalize_segment_listing(listing_body, listing_expected)


# Both implementations returning the same wrong response must not pass.
wrong = module.Snapshot(200, {"etag": ("0" * 32,)}, b"wrong")
runner = module.Runner("oracle-test", ("fixed-oracle",))
with contextlib.redirect_stdout(io.StringIO()):
    result = runner.compare(
        "fixed-oracle",
        wrong,
        wrong,
        200,
        "exact",
        expected_body=b"right",
        expected_headers={"Etag": "1" * 32},
    )
assert not result.passed
assert any("fixed oracle" in issue for issue in result.issues)


# A syntactically valid but unlinked X-Manifest-Etag must fail.  The live gate
# derives each side's value from that side's physical stored-manifest body.
linked_runner = module.Runner("linked-header-test", ("linked-header",))
linked_python = module.Snapshot(
    200, {"x-manifest-etag": ("a" * 32,)}, b"payload"
)
linked_rust = module.Snapshot(
    200, {"x-manifest-etag": ("c" * 32,)}, b"payload"
)
with contextlib.redirect_stdout(io.StringIO()):
    linked_result = linked_runner.compare(
        "linked-header",
        linked_python,
        linked_rust,
        200,
        "exact",
        expected_body=b"payload",
        expected_headers_by_target={
            "python": {"X-Manifest-Etag": "a" * 32},
            "rust": {"X-Manifest-Etag": "b" * 32},
        },
    )
assert not linked_result.passed
assert any("linked oracle" in issue for issue in linked_result.issues)


class DummyTarget:
    def __init__(self, label, account):
        self.label = label
        self.storage_path = "/v1/{}".format(account)
        self.owned_containers = set()
        self.known_objects = {}

    def own(self, container):
        self.owned_containers.add(container)
        self.known_objects.setdefault(container, set())

    def track(self, container, obj):
        self.known_objects.setdefault(container, set()).add(obj)


original_request_pair = module._request_pair
original_wait_for_listing = module._wait_for_listing


def synthetic_request_pair(
    runner,
    _python,
    _rust,
    name,
    _method,
    expected_status,
    body_mode,
    expected_body=None,
    expected_json=None,
    expected_headers=None,
    expected_headers_by_target=None,
    presence_headers=(),
    numeric_headers=(),
    md5_headers=(),
    absent_or_empty_headers=(),
    body_length_header=False,
    body_md5_etag_header=False,
    capture_snapshots=False,
    **_kwargs
):
    common_headers = {
        key.lower(): (value,) for key, value in (expected_headers or {}).items()
    }
    for key in presence_headers:
        common_headers[key.lower()] = ("present",)
    for key in numeric_headers:
        common_headers[key.lower()] = ("0",)
    for key in md5_headers:
        common_headers[key.lower()] = ("f" * 32,)
    body = b""
    if body_mode == "exact":
        body = expected_body
    elif body_mode in ("slo-raw-json", "slo-stored-proof-json"):
        body = json.dumps(expected_json).encode("utf-8")
    if body_length_header:
        common_headers["content-length"] = (str(len(body)),)
    if body_md5_etag_header:
        common_headers["etag"] = (module._md5_hex(body),)
    snapshots = {}
    for label in ("python", "rust"):
        target_headers = dict(common_headers)
        for key, value in (expected_headers_by_target or {}).get(label, {}).items():
            target_headers[key.lower()] = (value,)
        snapshots[label] = module.Snapshot(expected_status, target_headers, body)
    result = runner.compare(
        name,
        snapshots["python"],
        snapshots["rust"],
        expected_status,
        body_mode,
        expected_body=expected_body,
        expected_json=expected_json,
        expected_headers=expected_headers,
        expected_headers_by_target=expected_headers_by_target,
        presence_headers=presence_headers,
        numeric_headers=numeric_headers,
        md5_headers=md5_headers,
        absent_or_empty_headers=absent_or_empty_headers,
        body_length_header=body_length_header,
        body_md5_etag_header=body_md5_etag_header,
    )
    if capture_snapshots:
        return result, snapshots["python"], snapshots["rust"]
    return result


def synthetic_listing(_target, _container, _prefix, expected, _timeout):
    rows = [
        {
            "name": item["name"],
            "hash": item["hash"],
            "bytes": item["bytes"],
            "content_type": "application/octet-stream",
            "last_modified": "2026-08-09T00:00:00.000000",
        }
        for item in expected
    ]
    return module.Snapshot(
        200,
        {"content-type": ("application/json; charset=utf-8",)},
        json.dumps(rows).encode("utf-8"),
    )


module._request_pair = synthetic_request_pair
module._wait_for_listing = synthetic_listing
try:
    for enable_acl, expected_names in (
        (False, module.BASE_CASE_NAMES),
        (True, module.BASE_CASE_NAMES + module.ACL_CASE_NAMES),
    ):
        runner = module.Runner("offline-scenario", expected_names)
        with contextlib.redirect_stdout(io.StringIO()):
            runner.compare(
                "tempauth",
                module.Snapshot(
                    200,
                    {"x-auth-token": ("py",), "x-storage-url": ("py",)},
                    b"",
                ),
                module.Snapshot(
                    200,
                    {"x-auth-token": ("rs",), "x-storage-url": ("rs",)},
                    b"",
                ),
                200,
                "empty",
                presence_headers=("X-Auth-Token", "X-Storage-Url"),
                redacted_headers=("X-Auth-Token", "X-Storage-Url"),
            )
            account_headers = {
                "x-account-container-count": ("0",),
                "x-account-object-count": ("0",),
                "x-account-bytes-used": ("0",),
            }
            runner.compare(
                "advertised-storage-head",
                module.Snapshot(204, account_headers, b""),
                module.Snapshot(204, account_headers, b""),
                204,
                "empty",
                numeric_headers=(
                    "X-Account-Container-Count",
                    "X-Account-Object-Count",
                    "X-Account-Bytes-Used",
                ),
            )
            oracles = module._run_scenario(
                runner,
                DummyTarget("python", "AUTH_python"),
                DummyTarget("rust", "AUTH_rust"),
                1.0,
                enable_acl,
            )
        runner.finalize_coverage()
        assert not runner.failed, runner.coverage_issues
        assert len(runner.results) == len(expected_names)
        assert {item.name for item in runner.results} == set(expected_names)
        assert oracles["ec"]["bytes"] == 2 * 1024 * 1024
        assert oracles["large_object"]["slo_etag"] == (
            "92849ebd1d6ccb5a1f3b5dea38d783eb"
        )
finally:
    module._request_pair = original_request_pair
    module._wait_for_listing = original_wait_for_listing


class CleanupTarget:
    label = "cleanup-fake"

    def __init__(self):
        self.owned_containers = {"owned-large", "owned-segments"}
        self.known_objects = {
            "owned-large": {"slo", "dlo"},
            "owned-segments": {"part-0001", "part-0002"},
        }
        self.calls = []

    def request(self, method, container=None, obj=None, **_kwargs):
        self.calls.append((method, container, obj))
        if method == "GET":
            raise AssertionError("cleanup must not list or discover broad targets")
        if method == "HEAD":
            return module.Snapshot(404, {}, b"")
        return module.Snapshot(204, {}, b"")


cleanup_target = CleanupTarget()
assert module._cleanup_target(cleanup_target) == []
deleted_objects = {
    (container, obj)
    for method, container, obj in cleanup_target.calls
    if method == "DELETE" and obj is not None
}
assert deleted_objects == {
    ("owned-large", "slo"),
    ("owned-large", "dlo"),
    ("owned-segments", "part-0001"),
    ("owned-segments", "part-0002"),
}
assert all(method != "GET" for method, _container, _obj in cleanup_target.calls)


config = module.ValidatedConfig(
    python_endpoint="http://python.example:8090",
    rust_endpoint="http://rust.example:8080",
    python_storage_origin="http://python.example:8090",
    rust_storage_origin="https://rust-vip.example:8085",
    python_request_origin="http://python.example:8090",
    rust_request_origin="http://rust.example:8080",
    python_account="AUTH_python",
    rust_account="AUTH_rust",
    python_provenance="python@commit-a",
    rust_provenance="rust@commit-b+sha256:c",
    python_user_env="PY_USER",
    python_key_env="PY_KEY",
    rust_user_env="RS_USER",
    rust_key_env="RS_KEY",
    namespace_prefix="pgn-ext",
    timeout=30.0,
    consistency_timeout=10.0,
    max_response_bytes=8 * 1024 * 1024,
    insecure=False,
    enable_public_acl=False,
    json_report="unused.json",
)
runner = module.Runner("redaction", ("tempauth",))
with contextlib.redirect_stdout(io.StringIO()):
    runner.compare(
        "tempauth",
        module.Snapshot(
            200,
            {
                "x-auth-token": ("python-secret-token",),
                "x-storage-url": ("http://python.example:8090/v1/AUTH_python",),
            },
            b"",
        ),
        module.Snapshot(
            200,
            {
                "x-auth-token": ("rust-secret-token",),
                "x-storage-url": ("https://rust-vip.example:8085/v1/AUTH_rust",),
            },
            b"",
        ),
        200,
        "empty",
        presence_headers=("X-Auth-Token", "X-Storage-Url"),
        redacted_headers=("X-Auth-Token", "X-Storage-Url"),
    )
runner.finalize_coverage()
report = runner.report(config, module.EXIT_PASS, {})
encoded_report = json.dumps(report)
assert "python-secret-token" not in encoded_report
assert "rust-secret-token" not in encoded_report
assert "/v1/AUTH_" not in encoded_report

with tempfile.TemporaryDirectory() as temp_dir:
    report_path = pathlib.Path(temp_dir) / "report.json"
    module._write_report(str(report_path), report)
    assert stat.S_IMODE(report_path.stat().st_mode) == 0o600
    assert json.loads(report_path.read_text(encoding="utf-8"))["schema"] == (
        "peregrine.strict-extended-parity.v1"
    )
    module._write_report(str(report_path), report)
    assert stat.S_IMODE(report_path.stat().st_mode) == 0o600
    assert not list(report_path.parent.glob(".*.tmp"))


stdout = io.StringIO()
stderr = io.StringIO()
with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
    rc = module.main(
        [
            "--python",
            "http://python.example:8090",
            "--rust",
            "http://rust.example:8080",
            "--python-storage-origin",
            "http://python.example:8090",
            "--rust-storage-origin",
            "https://rust-vip.example:8085",
            "--python-request-origin",
            "http://python.example:8090",
            "--rust-request-origin",
            "http://rust.example:8080",
            "--python-account",
            "AUTH_python",
            "--rust-account",
            "AUTH_rust",
            "--python-provenance",
            "python@commit-a",
            "--rust-provenance",
            "rust@commit-b",
            "--json-report",
            "-",
        ]
    )
assert rc == module.EXIT_RUNTIME_FAILURE
assert "forbidden" in stderr.getvalue()
assert "secret" not in stdout.getvalue() + stderr.getvalue()

first_namespace = module._namespace("pgn-ext")
second_namespace = module._namespace("pgn-ext")
assert first_namespace != second_namespace
assert first_namespace.startswith("pgn-ext-")

print("STRICT_EXTENDED_PARITY_SELF_TEST=PASS")
