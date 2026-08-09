#!/usr/bin/env python3
import contextlib
import http.client
import importlib.util
import io
import pathlib
import sys
import tempfile


module_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("strict_parity", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class AuthClient:
    def __init__(self, storage_url):
        self.storage_url = storage_url

    def request(self, *_args, **_kwargs):
        return module.Snapshot(
            200,
            {
                "x-auth-token": ("redacted-test-token",),
                "x-storage-url": (self.storage_url,),
            },
            b"",
        )


safe = module._authenticate(
    AuthClient("http://swift.example/v1/AUTH_test"),
    "http://swift.example",
    "test:tester",
    "unused",
    "http://swift.example",
    "AUTH_test",
)
assert safe.storage_path == "/v1/AUTH_test"

unsafe_urls = (
    "/v1/AUTH_test",
    "http://swift.example/v1/",
    "http://swift.example/v1/AUTH_test/extra",
    "http://swift.example/v1/.",
    "http://swift.example/v1/..",
    "http://swift.example/v1/AUTH%2Fother",
    "http://user:password@swift.example/v1/AUTH_test",
    "http://swift.example/v1/AUTH_test\n",
)
for unsafe in unsafe_urls:
    try:
        module._authenticate(
            AuthClient(unsafe),
            "http://swift.example",
            "test:tester",
            "unused",
            "http://swift.example",
            "AUTH_test",
        )
    except module.ConfigError:
        pass
    else:
        raise AssertionError("unsafe storage URL accepted: {!r}".format(unsafe))

left = module._normalize_header(
    "content-type", ("multipart/byteranges; boundary=ABC; charset=UTF-8",)
)
reordered = module._normalize_header(
    "content-type", ("multipart/byteranges; charset=UTF-8; boundary=ABC",)
)
different_boundary = module._normalize_header(
    "content-type", ("multipart/byteranges; boundary=abc; charset=UTF-8",)
)
assert left == reordered
assert left != different_boundary
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

valid_listing = b'[{"name":"object","hash":"abc","bytes":3,"content_type":"text/plain","last_modified":"2026-08-09T00:00:00.000000"}]'
module._normalize_listing_json(valid_listing, ("object",))
for invalid in (
    b"{}",
    b'[{"name":"object","hash":"abc","bytes":3,"content_type":"text/plain"}]',
):
    try:
        module._normalize_listing_json(invalid, ("object",))
    except ValueError:
        pass
    else:
        raise AssertionError("invalid listing accepted")

assert module._merge_exit_code(0, 1) == 1
assert module._merge_exit_code(1, 2) == 2
assert module._merge_exit_code(2, 1) == 2
assert module._merge_exit_code(2, 130) == 130
assert module._merge_exit_code(130, 2) == 130


class BrokenResponse:
    code = 200
    headers = type("Headers", (), {"raw_items": lambda self: []})()

    def __init__(self):
        self.closed = False

    def read(self, _limit):
        raise http.client.IncompleteRead(b"", 10)

    def close(self):
        self.closed = True


class BrokenOpener:
    def __init__(self, response):
        self.response = response

    def open(self, *_args, **_kwargs):
        return self.response


response = BrokenResponse()
client = module.HttpClient(1.0, 1024, False)
client._opener = BrokenOpener(response)
try:
    client.request("GET", "http://swift.example/healthcheck")
except module.TransportError as exc:
    assert "synthetic" not in str(exc)
else:
    raise AssertionError("IncompleteRead was not converted to TransportError")
assert response.closed


class OpenBrokenOpener:
    def open(self, *_args, **_kwargs):
        raise http.client.BadStatusLine("synthetic")


client = module.HttpClient(1.0, 1024, False)
client._opener = OpenBrokenOpener()
try:
    client.request("GET", "http://swift.example/healthcheck")
except module.TransportError as exc:
    assert "synthetic" not in str(exc)
else:
    raise AssertionError("open HTTPException was not converted to TransportError")


class CleanupTarget:
    label = "fake"
    safe_to_cleanup = True
    known_objects = {"object"}

    def __init__(self):
        self.calls = []

    def request(self, method, container=None, obj=None, query=None):
        self.calls.append((method, container, obj, query))
        if method == "GET":
            raise RuntimeError("synthetic listing crash")
        if method == "HEAD":
            return module.Snapshot(404, {}, b"")
        return module.Snapshot(204, {}, b"")


cleanup_target = CleanupTarget()
cleanup_issues = module._cleanup_target(cleanup_target, "owned-container")
assert cleanup_issues
assert any(call[0] == "DELETE" and call[2] == "object" for call in cleanup_target.calls)
assert any(call[0] == "HEAD" for call in cleanup_target.calls)

stdout = io.StringIO()
stderr = io.StringIO()
with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
    rc = module.main(
        [
            "--python",
            "http://python.example:8090",
            "--rust",
            "http://rust.example:8080",
            "--python-account",
            "AUTH_test",
            "--rust-account",
            "AUTH_test",
            "--python-provenance",
            "python@commit-a",
            "--rust-provenance",
            "rust@commit-b+sha256:c",
            "--json-report",
            "-",
        ]
    )
assert rc == module.EXIT_RUNTIME_FAILURE
assert "not supported" in stderr.getvalue()

runner = module.Runner("safe-namespace")
report = runner.report(
    "http://python.example:8090",
    "http://rust.example:8080",
    "http://python.example:8090",
    "http://rust.example:8080",
    "http://python.example:8090",
    "http://rust.example:8080",
    "AUTH_test",
    "AUTH_test",
    "python@commit-a",
    "rust@commit-b+sha256:c",
    module.EXIT_PASS,
)
assert report["scope"]["id"] == module.SCOPE_ID
assert report["scope"]["claim"] == "IMPLEMENTED_SUBSET_ONLY"
assert report["summary"]["gate"] == "PASS"
assert report["result"] == {"exit_code": 0, "gate": "PASS"}

for unsafe_origin in (
    "http://swift.example:bad/v1/AUTH_test",
    "http://other.example/v1/AUTH_test",
    "http://swift.example/v1/AUTH_other",
):
    try:
        module._authenticate(
            AuthClient(unsafe_origin),
            "http://swift.example",
            "test:tester",
            "unused",
            "http://swift.example",
            "AUTH_test",
        )
    except module.ConfigError:
        pass
    else:
        raise AssertionError("unsafe storage origin accepted")

snapshot = module.Snapshot(
    204,
    {
        "x-account-container-count": ("not-a-number",),
        "x-account-object-count": ("0",),
        "x-account-bytes-used": ("0",),
    },
    b"",
)
runner = module.Runner("integer-header-test")
with contextlib.redirect_stdout(io.StringIO()):
    result = runner.compare(
        "account-head",
        snapshot,
        snapshot,
        (204,),
        "empty",
        nonnegative_integer_headers=(
            "x-account-container-count",
            "x-account-object-count",
            "x-account-bytes-used",
        ),
    )
assert not result.passed

runner = module.Runner("content-type-test")
with contextlib.redirect_stdout(io.StringIO()):
    result = runner.compare(
        "invalid-content-type",
        module.Snapshot(200, {"content-type": ("garbage",)}, b""),
        module.Snapshot(200, {"content-type": ("text/plain",)}, b""),
        (200,),
        "empty",
        compare_headers=("content-type",),
    )
assert not result.passed
assert any("python invalid content-type" in issue for issue in result.issues)

runner = module.Runner("redaction-test")
redaction_output = io.StringIO()
with contextlib.redirect_stdout(redaction_output):
    result = runner.compare(
        "redacted-header",
        module.Snapshot(200, {"x-auth-token": ("python-secret",)}, b""),
        module.Snapshot(200, {"x-auth-token": ("rust-secret",)}, b""),
        (200,),
        "empty",
        compare_headers=("x-auth-token",),
        redacted_headers=("x-auth-token",),
    )
assert not result.passed
redaction_report = runner.report(
    "http://python.example:8090",
    "http://rust.example:8080",
    "http://python.example:8090",
    "http://rust.example:8080",
    "http://python.example:8090",
    "http://rust.example:8080",
    "AUTH_test",
    "AUTH_test",
    "python@commit-a",
    "rust@commit-b+sha256:c",
    module.EXIT_PARITY_FAILURE,
)
redaction_evidence = redaction_output.getvalue() + module.json.dumps(redaction_report)
assert "python-secret" not in redaction_evidence
assert "rust-secret" not in redaction_evidence

original_authenticate = module._authenticate


def unexpected_auth_error(*_args, **_kwargs):
    raise RuntimeError("must-not-leak")


module._authenticate = unexpected_auth_error
with tempfile.TemporaryDirectory() as temp_dir:
    report_path = pathlib.Path(temp_dir) / "unexpected.json"
    old_user = module.os.environ.get("PEREGRINE_PARITY_USER")
    old_key = module.os.environ.get("PEREGRINE_PARITY_KEY")
    module.os.environ["PEREGRINE_PARITY_USER"] = "test:tester"
    module.os.environ["PEREGRINE_PARITY_KEY"] = "must-not-leak"
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = module.main(
                [
                    "--python",
                    "http://python.example:8090",
                    "--rust",
                    "http://rust.example:8080",
                    "--python-account",
                    "AUTH_test",
                    "--rust-account",
                    "AUTH_test",
                    "--python-provenance",
                    "python@commit-a",
                    "--rust-provenance",
                    "rust@commit-b+sha256:c",
                    "--json-report",
                    str(report_path),
                ]
            )
    finally:
        if old_user is None:
            module.os.environ.pop("PEREGRINE_PARITY_USER", None)
        else:
            module.os.environ["PEREGRINE_PARITY_USER"] = old_user
        if old_key is None:
            module.os.environ.pop("PEREGRINE_PARITY_KEY", None)
        else:
            module.os.environ["PEREGRINE_PARITY_KEY"] = old_key
        module._authenticate = original_authenticate
    assert rc == module.EXIT_RUNTIME_FAILURE
    assert "gate=ERROR" in stdout.getvalue()
    assert "must-not-leak" not in stdout.getvalue() + stderr.getvalue()
    unexpected_report = module.json.loads(report_path.read_text())
    assert unexpected_report["summary"]["gate"] == "ERROR"
    assert unexpected_report["result"]["exit_code"] == module.EXIT_RUNTIME_FAILURE


class NoNetworkClient:
    def __init__(self, *_args, **_kwargs):
        pass

    def request(self, method, url, body=None, headers=None):
        if url.endswith("/auth/v1.0"):
            parsed = module.urlsplit(url)
            origin = "{}://{}".format(parsed.scheme, parsed.netloc)
            return module.Snapshot(
                200,
                {
                    "x-auth-token": ("test-token",),
                    "x-storage-url": (origin + "/v1/AUTH_test",),
                },
                b"",
            )
        if method == "HEAD":
            return module.Snapshot(
                204,
                {
                    "x-account-container-count": ("0",),
                    "x-account-object-count": ("0",),
                    "x-account-bytes-used": ("0",),
                },
                b"",
            )
        raise AssertionError("unexpected synthetic request")


original_http_client = module.HttpClient
original_run_scenario = module._run_scenario
module.HttpClient = NoNetworkClient
module._run_scenario = lambda *_args, **_kwargs: None
with tempfile.TemporaryDirectory() as temp_dir:
    missing_report = pathlib.Path(temp_dir) / "missing" / "report.json"
    old_user = module.os.environ.get("PEREGRINE_PARITY_USER")
    old_key = module.os.environ.get("PEREGRINE_PARITY_KEY")
    module.os.environ["PEREGRINE_PARITY_USER"] = "test:tester"
    module.os.environ["PEREGRINE_PARITY_KEY"] = "must-not-leak"
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = module.main(
                [
                    "--python",
                    "http://python.example:8090",
                    "--rust",
                    "http://rust.example:8080",
                    "--python-account",
                    "AUTH_test",
                    "--rust-account",
                    "AUTH_test",
                    "--python-provenance",
                    "python@commit-a",
                    "--rust-provenance",
                    "rust@commit-b+sha256:c",
                    "--json-report",
                    str(missing_report),
                ]
            )
    finally:
        if old_user is None:
            module.os.environ.pop("PEREGRINE_PARITY_USER", None)
        else:
            module.os.environ["PEREGRINE_PARITY_USER"] = old_user
        if old_key is None:
            module.os.environ.pop("PEREGRINE_PARITY_KEY", None)
        else:
            module.os.environ["PEREGRINE_PARITY_KEY"] = old_key
        module.HttpClient = original_http_client
        module._run_scenario = original_run_scenario
    assert rc == module.EXIT_RUNTIME_FAILURE
    assert "gate=ERROR" in stdout.getvalue()
    assert "gate=PASS" not in stdout.getvalue()
    assert "report write failed" in stderr.getvalue()
    assert not missing_report.exists()

print("STRICT_PARITY_SELF_TEST=PASS")
