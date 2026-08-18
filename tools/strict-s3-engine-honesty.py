#!/usr/bin/env python3
"""Extra live honesty probes for weakly-scored LIVE S3 engines.

Stdlib only. Path-style SigV4, region RegionOne.
Never prints access_key/secret_key. Never writes mytest / AUTH_lab / AUTH_test.
Self-creates one s3-honest-<utc compact> bucket and deletes it at the end.

    python3 tools/strict-s3-engine-honesty.py --selftest
    python3 tools/strict-s3-engine-honesty.py \\
      --rust https://10.0.0.10:8085 --rust-insecure \\
      --json-report /root/work/evidence/strict-s3-engine-honesty-20260818.json

--json-report is required for live and must not already exist.
Exit 0 only if failed=0 and cleanup_failed=0.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import io
import json
import os
import re
import ssl
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from contextlib import redirect_stderr
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_RUNTIME = 2
EXIT_INTERRUPTED = 130
REPORT_SCHEMA = "peregrine.strict-s3-engine-honesty.v1"
TOOL_NAME = "strict-s3-engine-honesty.py"
SERVICE = "s3"
V4_ALGORITHM = "AWS4-HMAC-SHA256"
DEFAULT_ENDPOINT = "https://10.0.0.10:8085"
DEFAULT_REGION = "RegionOne"
DEFAULT_S3CFG = "/root/.s3cfg-tempauth"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 30.0
FORBIDDEN_BUCKETS = frozenset({"mytest"})
FORBIDDEN_PREFIXES = ("auth_lab", "auth_test")
BUCKET_RE = re.compile(r"^s3-honest-[0-9]{8}t[0-9]{6}z$")
S3CFG_KEYS = re.compile(r"^(access_key|secret_key|host_base|host_bucket|"
                        r"use_https|check_ssl_certificate|signature_v2|"
                        r"bucket_location)\s*=\s*(.*)$")

ALL_CASES = (
    "torrent-bencode",
    "session-xml",
    "rename-source-gone",
    "part-copy-bytes",
    "select-star-payload",
    "wgOR-still-501",
)

HONESTY_TXT = b"abc\n"
RENAME_BODY = b"rename-src-body\n"
PART_COPY_BYTES = b"0123456789abcdef"
SELECT_CSV = b"a,1\nb,2\n"
SELECT_XML = (
    b"<SelectRequest><Expression>SELECT * FROM S3Object</Expression>"
    b"<InputSerialization><CSV/></InputSerialization>"
    b"<OutputSerialization><CSV/></OutputSerialization></SelectRequest>"
)
WGOR_NOT_IMPL = (
    b"<Error><Code>NotImplemented</Code>"
    b"<Message>WriteGetObjectResponse is not implemented</Message></Error>"
)
SESSION_OK = (
    b"<CreateSessionResult><Credentials>"
    b"<AccessKeyId>AKIAEXAMPLE</AccessKeyId>"
    b"</Credentials></CreateSessionResult>"
)
# Starts with d, contains 4:info and 6:pieces.
TORRENT_OK = (
    b"d8:announce0:4:infod6:lengthi4e4:name11:honesty.txt"
    b"12:piece lengthi4e6:pieces20:" + (b"x" * 20) + b"ee"
)


class ConfigError(RuntimeError):
    pass


class SetupError(RuntimeError):
    pass


class TransportError(RuntimeError):
    pass


class SchemaError(ValueError):
    pass


class SelfTestError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Snapshot:
    def __init__(self, status: int, headers: Mapping[str, Tuple[str, ...]],
                 body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body

    def first(self, name: str) -> Optional[str]:
        values = self.headers.get(name.lower())
        return values[0] if values else None


def _safe_origin(url: str) -> str:
    parsed = urlsplit(url)
    return "{}://{}".format(parsed.scheme or "<scheme>", parsed.netloc or "<host>")


def _aws_quote(value: str, safe: str = "-_.~") -> str:
    return quote(value, safe=safe, encoding="utf-8", errors="strict")


def _canonical_query(pairs: Sequence[Tuple[str, str]]) -> str:
    encoded = [(_aws_quote(str(k)), _aws_quote(str(v))) for k, v in pairs]
    encoded.sort()
    return "&".join("{}={}".format(k, v) for k, v in encoded)


def _wire_query(pairs: Sequence[Tuple[str, str]]) -> str:
    return "&".join("{}={}".format(_aws_quote(str(k)), _aws_quote(str(v)))
                    for k, v in pairs)


def _normalize_header_value(value: str) -> str:
    return " ".join(value.strip().split())


def _hmac_sha256(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _v4_key(secret: str, stamp: str, region: str) -> bytes:
    key = _hmac_sha256(("AWS4" + secret).encode("utf-8"), stamp)
    key = _hmac_sha256(key, region)
    key = _hmac_sha256(key, SERVICE)
    return _hmac_sha256(key, "aws4_request")


def _signed_request(
    *, method: str, path: str, query: Sequence[Tuple[str, str]], body: bytes,
    headers: Mapping[str, str], access: str, secret: str, region: str,
    host: str, signed_at: int,
) -> Tuple[Dict[str, str], List[Tuple[str, str]]]:
    if not path.startswith("/") or "?" in path or "#" in path:
        raise ConfigError("internal request path is not canonical")
    method = method.upper()
    out = {str(k): str(v) for k, v in headers.items()}
    out["Host"] = host
    q = [(str(k), str(v)) for k, v in query]
    when = datetime.fromtimestamp(signed_at, tz=timezone.utc)
    amz_date = when.strftime("%Y%m%dT%H%M%SZ")
    stamp = when.strftime("%Y%m%d")
    scope = "{}/{}/{}/aws4_request".format(stamp, region, SERVICE)
    payload_hash = hashlib.sha256(body).hexdigest()
    out["X-Amz-Date"] = amz_date
    out["X-Amz-Content-SHA256"] = payload_hash
    signed_names = sorted({
        name.lower() for name in out
        if name.lower() == "host"
        or name.lower().startswith("x-amz-")
        or name.lower() in ("content-md5", "content-type", "range")
    })
    lower = {name.lower(): _normalize_header_value(value) for name, value in out.items()}
    canonical_headers = "".join("{}:{}\n".format(name, lower[name]) for name in signed_names)
    signed_headers = ";".join(signed_names)
    canonical_request = "{}\n{}\n{}\n{}\n{}\n{}".format(
        method, _aws_quote(path, safe="/-_.~"), _canonical_query(q),
        canonical_headers, signed_headers, payload_hash)
    string_to_sign = "{}\n{}\n{}\n{}".format(
        V4_ALGORITHM, amz_date, scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest())
    signature = hmac.new(_v4_key(secret, stamp, region),
                         string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    out["Authorization"] = (
        "{} Credential={}/{}, SignedHeaders={}, Signature={}".format(
            V4_ALGORITHM, access, scope, signed_headers, signature))
    return out, q


def _tag(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _xml_root(payload: bytes) -> ET.Element:
    if not payload:
        raise SchemaError("XML body is empty")
    upper = payload.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise SchemaError("XML DTD/entity declarations are forbidden")
    try:
        return ET.fromstring(payload)
    except ET.ParseError as exc:
        raise SchemaError("invalid XML") from exc


def _error_code(payload: bytes) -> Optional[str]:
    if not payload:
        return None
    try:
        root = _xml_root(payload)
    except SchemaError:
        return None
    if _tag(root) != "Error":
        return None
    for child in list(root):
        if _tag(child) == "Code" and child.text:
            return child.text
    return None


def _xml_text(payload: bytes, name: str) -> Optional[str]:
    try:
        root = _xml_root(payload)
    except SchemaError:
        return None
    for child in root.iter():
        if _tag(child) == name and child.text:
            return child.text
    return None


def _xml_keys(payload: bytes) -> List[str]:
    keys: List[str] = []
    try:
        root = _xml_root(payload)
    except SchemaError:
        return keys
    for child in root.iter():
        if _tag(child) == "Key" and child.text:
            keys.append(child.text)
    return keys


def _has_bytes(payload: bytes, marker: str) -> bool:
    return marker.encode("utf-8") in payload


def _bucket_ok(name: str) -> None:
    lowered = name.lower()
    if lowered in FORBIDDEN_BUCKETS or any(lowered.startswith(p) for p in FORBIDDEN_PREFIXES):
        raise ConfigError("refusing forbidden bucket name")
    if not BUCKET_RE.fullmatch(name):
        raise ConfigError("bucket name is not an s3-honest probe")


def _sidecar_ok(name: str) -> None:
    if name.endswith("+versions") or name.endswith("+segments"):
        _bucket_ok(name.rsplit("+", 1)[0])
        return
    _bucket_ok(name)


def _path(bucket: Optional[str] = None, key: Optional[str] = None) -> str:
    if bucket is None:
        return "/"
    _bucket_ok(bucket)
    value = "/" + _aws_quote(bucket)
    if key is not None:
        value += "/" + _aws_quote(key, safe="-_.~/")
    return value


def _sidecar_path(bucket: str) -> str:
    _sidecar_ok(bucket)
    return "/" + _aws_quote(bucket)


def _redact(message: str, secrets: Sequence[str]) -> str:
    result = message
    for value in sorted((item for item in secrets if item), key=len, reverse=True):
        result = result.replace(value, "<redacted>")
    return result


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%Sz")


def _copy_source(bucket: str, key: str) -> str:
    return "/{}/{}".format(bucket, key)


class HttpClient:
    def __init__(self, timeout: float, max_bytes: int, insecure: bool) -> None:
        handlers: List[Any] = [ProxyHandler({}), _NoRedirect()]
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        handlers.append(HTTPSHandler(context=context))
        self._opener = build_opener(*handlers)
        self._timeout = timeout
        self._max_bytes = max_bytes

    def request(self, method: str, url: str, body: bytes,
                headers: Mapping[str, str]) -> Snapshot:
        clean = {
            "Accept-Encoding": "identity",
            "User-Agent": "peregrine-strict-s3-engine-honesty/1",
            **headers,
        }
        if body or method in ("PUT", "POST"):
            clean.setdefault("Content-Length", str(len(body)))
        req = Request(url=url, data=body if body or method in ("PUT", "POST") else None,
                      headers=clean, method=method)
        try:
            response = self._opener.open(req, timeout=self._timeout)
        except HTTPError as exc:
            response = exc
        except (URLError, http.client.HTTPException, OSError, TimeoutError) as exc:
            raise TransportError("{} request to {} failed ({})".format(
                method, _safe_origin(url), type(exc).__name__)) from exc
        try:
            payload = response.read(self._max_bytes + 1)
            if len(payload) > self._max_bytes:
                raise TransportError("response exceeded {} bytes".format(self._max_bytes))
            normalized: Dict[str, List[str]] = {}
            for name, value in response.headers.raw_items():
                normalized.setdefault(name.strip().lower(), []).append(value.strip())
            return Snapshot(int(response.code),
                            {k: tuple(v) for k, v in normalized.items()}, payload)
        finally:
            try:
                response.close()
            except Exception:
                pass


class Target:
    def __init__(self, endpoint: str, access: str, secret: str, region: str,
                 client: Any) -> None:
        self.endpoint = endpoint
        self.access = access
        self.secret = secret
        self.region = region
        self.client = client

    @property
    def host(self) -> str:
        return urlsplit(self.endpoint).netloc

    def request(self, method: str, path: str,
                query: Sequence[Tuple[str, str]] = (),
                body: bytes = b"",
                headers: Optional[Mapping[str, str]] = None) -> Snapshot:
        request_headers, wire_query = _signed_request(
            method=method, path=path, query=query, body=body,
            headers=headers or {}, access=self.access, secret=self.secret,
            region=self.region, host=self.host, signed_at=int(time.time()),
        )
        url = self.endpoint + path
        if wire_query:
            url += "?" + _wire_query(wire_query)
        return self.client.request(method, url, body, request_headers)


class Case:
    def __init__(self, name: str) -> None:
        self.name = name
        self.issues: List[str] = []
        self.observed: Dict[str, Any] = {}

    def issue(self, message: str) -> None:
        self.issues.append(message)

    @property
    def passed(self) -> bool:
        return not self.issues

    def record(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "gate": "PASS" if self.passed else "FAIL",
            "issues": self.issues,
            "observed": self.observed,
        }


class Runner:
    def __init__(self, target: Target, bucket: str) -> None:
        self.target = target
        self.bucket = bucket
        self.results: List[Case] = []
        self.cleanup: List[Dict[str, Any]] = []
        self.owned: List[str] = []
        self.objects: List[str] = []
        self.upload_id: Optional[str] = None
        self.mpu_key: Optional[str] = None

    def run_case(self, name: str, fn: Callable[[Case], None]) -> Case:
        case = Case(name)
        try:
            fn(case)
        except (TransportError, SchemaError, ConfigError, SetupError, OSError) as exc:
            case.issue(_redact(str(exc), (self.target.access, self.target.secret)))
        self.results.append(case)
        return case

    def req(self, case: Case, method: str, path: str,
            query: Sequence[Tuple[str, str]] = (),
            body: bytes = b"",
            headers: Optional[Mapping[str, str]] = None) -> Snapshot:
        snap = self.target.request(method, path, query, body, headers)
        case.observed.update({
            "method": method,
            "path": path,
            "query": ["{}={}".format(k, v) if v else k for k, v in query],
            "status": snap.status,
            "body_length": len(snap.body),
            "error_code": _error_code(snap.body),
            "content_type": snap.first("content-type"),
        })
        return snap

    def expect_status(self, case: Case, snap: Snapshot, allowed: Sequence[int]) -> None:
        if snap.status not in allowed:
            case.issue("status {} not in {}".format(snap.status, tuple(allowed)))

    def expect_marker(self, case: Case, snap: Snapshot, marker: str) -> None:
        if not _has_bytes(snap.body, marker):
            case.issue("body missing {}".format(marker))

    def track(self, key: str) -> None:
        if key not in self.objects:
            self.objects.append(key)

    def forget(self, key: str) -> None:
        if key in self.objects:
            self.objects.remove(key)


def _load_s3cfg(path: Path) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = S3CFG_KEYS.match(raw.strip())
        if match:
            parsed[match.group(1)] = match.group(2).strip()
    if "access_key" not in parsed or "secret_key" not in parsed:
        raise ConfigError("s3cfg missing access_key/secret_key")
    return parsed


def _load_creds() -> Tuple[str, str]:
    env_access = os.environ.get("PEREGRINE_S3_RS_ACCESS")
    env_secret = os.environ.get("PEREGRINE_S3_RS_SECRET")
    if env_access and env_secret:
        return env_access, env_secret
    cfg = Path(DEFAULT_S3CFG)
    if cfg.is_file():
        parsed = _load_s3cfg(cfg)
        return parsed["access_key"], parsed["secret_key"]
    raise ConfigError(
        "credentials missing: set PEREGRINE_S3_RS_ACCESS/PEREGRINE_S3_RS_SECRET "
        "or provide {}".format(DEFAULT_S3CFG))


def _atomic_new_report(path: Path, report: Mapping[str, Any]) -> None:
    path = path.expanduser()
    if path.is_symlink():
        raise ConfigError("JSON report target must not be a symlink")
    if path.exists():
        raise ConfigError(
            "JSON report {} already exists; refusing overwrite".format(path.name))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".{}-".format(path.name),
                                     suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            json.dump(report, stream, sort_keys=True, indent=2, ensure_ascii=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        os.chmod(path, 0o600)
    except FileExistsError:
        raise ConfigError(
            "JSON report {} appeared during the run; refusing overwrite".format(path.name))
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _tool_sha256() -> str:
    return hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()


def _validate_endpoint(raw: str) -> str:
    endpoint = raw.strip().rstrip("/")
    parsed = urlsplit(endpoint)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError("endpoint must be an absolute HTTP(S) origin")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError("endpoint must not contain credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ConfigError("endpoint must not contain path/query/fragment")
    return endpoint


def _abort_mpu(runner: Runner) -> None:
    if not runner.upload_id or not runner.mpu_key:
        return
    try:
        runner.target.request(
            "DELETE", _path(runner.bucket, runner.mpu_key),
            (("uploadId", runner.upload_id),))
    except (TransportError, ConfigError):
        pass
    runner.upload_id = None
    runner.mpu_key = None


def _run_probes(runner: Runner) -> None:
    bucket = runner.bucket

    def torrent_bencode(case: Case) -> None:
        put = runner.req(case, "PUT", _path(bucket, "honesty.txt"), (), HONESTY_TXT,
                         {"Content-Type": "text/plain"})
        runner.expect_status(case, put, (200, 201))
        if put.status not in (200, 201):
            return
        runner.track("honesty.txt")
        snap = runner.req(case, "GET", _path(bucket, "honesty.txt"), (("torrent", ""),))
        runner.expect_status(case, snap, (200,))
        runner.expect_marker(case, snap, "4:info")
        runner.expect_marker(case, snap, "6:pieces")
        ctype = (snap.first("content-type") or "").lower()
        if "bittorrent" not in ctype and not snap.body.startswith(b"d"):
            case.issue("content-type missing bittorrent and body does not start with d")

    def session_xml(case: Case) -> None:
        snap = runner.req(case, "GET", _path(bucket), (("session", ""),))
        if snap.status in (405, 400) and (_error_code(snap.body) or "") in (
                "MethodNotAllowed", "InvalidRequest", ""):
            snap = runner.req(case, "POST", _path(bucket), (("session", ""),))
        runner.expect_status(case, snap, (200,))
        runner.expect_marker(case, snap, "CreateSessionResult")
        runner.expect_marker(case, snap, "AccessKeyId")

    def rename_source_gone(case: Case) -> None:
        put = runner.req(case, "PUT", _path(bucket, "src.txt"), (), RENAME_BODY,
                         {"Content-Type": "text/plain"})
        runner.expect_status(case, put, (200, 201))
        if put.status not in (200, 201):
            return
        runner.track("src.txt")
        snap = runner.req(
            case, "POST", _path(bucket, "dst.txt"), (), b"",
            {"x-amz-rename-source": _copy_source(bucket, "src.txt"),
             "Content-Length": "0"})
        runner.expect_status(case, snap, (200, 204))
        if snap.status not in (200, 204):
            return
        runner.track("dst.txt")
        got = runner.target.request("GET", _path(bucket, "dst.txt"))
        case.observed["dest_status"] = got.status
        case.observed["dest_length"] = len(got.body)
        if got.status != 200 or got.body != RENAME_BODY:
            case.issue("dest GET does not equal rename source body")
        else:
            runner.forget("src.txt")
        src = runner.target.request("GET", _path(bucket, "src.txt"))
        case.observed["src_status"] = src.status
        if src.status != 404:
            case.issue("src GET is {} not 404".format(src.status))

    def part_copy_bytes(case: Case) -> None:
        put = runner.req(case, "PUT", _path(bucket, "src.bin"), (), PART_COPY_BYTES,
                         {"Content-Type": "application/octet-stream"})
        runner.expect_status(case, put, (200, 201))
        if put.status not in (200, 201):
            return
        runner.track("src.bin")
        init = runner.req(case, "POST", _path(bucket, "copied.bin"), (("uploads", ""),))
        runner.expect_status(case, init, (200,))
        upload_id = _xml_text(init.body, "UploadId")
        if not upload_id:
            case.issue("MPU UploadId missing")
            return
        runner.upload_id = upload_id
        runner.mpu_key = "copied.bin"
        try:
            copy = runner.req(
                case, "PUT", _path(bucket, "copied.bin"),
                (("partNumber", "1"), ("uploadId", upload_id)),
                b"", {"X-Amz-Copy-Source": _copy_source(bucket, "src.bin")})
            runner.expect_status(case, copy, (200,))
            runner.expect_marker(case, copy, "CopyPartResult")
            etag = _xml_text(copy.body, "ETag") or ""
            if not etag:
                case.issue("CopyPartResult ETag missing")
                return
            complete_xml = (
                b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"
                + etag.encode("ascii", "replace")
                + b"</ETag></Part></CompleteMultipartUpload>"
            )
            done = runner.req(
                case, "POST", _path(bucket, "copied.bin"),
                (("uploadId", upload_id),), complete_xml,
                {"Content-Type": "application/xml"})
            runner.expect_status(case, done, (200,))
            if done.status not in (200,):
                return
            runner.upload_id = None
            runner.mpu_key = None
            runner.track("copied.bin")
            got = runner.target.request("GET", _path(bucket, "copied.bin"))
            case.observed["copied_status"] = got.status
            case.observed["copied_length"] = len(got.body)
            if got.status != 200 or got.body != PART_COPY_BYTES:
                case.issue("completed object bytes do not match the 16-byte source")
        finally:
            if runner.upload_id:
                _abort_mpu(runner)

    def select_star_payload(case: Case) -> None:
        put = runner.req(case, "PUT", _path(bucket, "sel.csv"), (), SELECT_CSV,
                         {"Content-Type": "text/csv"})
        runner.expect_status(case, put, (200, 201))
        if put.status not in (200, 201):
            return
        runner.track("sel.csv")
        snap = runner.req(
            case, "POST", _path(bucket, "sel.csv"),
            (("select", ""), ("select-type", "2")), SELECT_XML,
            {"Content-Type": "application/xml"})
        runner.expect_status(case, snap, (200,))
        runner.expect_marker(case, snap, "a,1")

    def wgor_still_501(case: Case) -> None:
        snap = runner.req(
            case, "POST", "/", (), b"",
            {"x-amz-request-route": "route", "x-amz-request-token": "tok"})
        runner.expect_status(case, snap, (501,))
        if snap.status != 501:
            case.issue("WriteGetObjectResponse must stay 501 (do not implement)")
        code = _error_code(snap.body)
        if code != "NotImplemented":
            case.issue("error Code {} != NotImplemented".format(code))

    runner.run_case("torrent-bencode", torrent_bencode)
    runner.run_case("session-xml", session_xml)
    runner.run_case("rename-source-gone", rename_source_gone)
    runner.run_case("part-copy-bytes", part_copy_bytes)
    runner.run_case("select-star-payload", select_star_payload)
    runner.run_case("wgOR-still-501", wgor_still_501)


def _empty_bucket(target: Target, bucket: str) -> None:
    snap = target.request("GET", _path(bucket))
    for key in _xml_keys(snap.body):
        target.request("DELETE", _path(bucket, key))


def _cleanup(runner: Runner) -> int:
    failed = 0
    if runner.upload_id and runner.mpu_key:
        try:
            snap = runner.target.request(
                "DELETE", _path(runner.bucket, runner.mpu_key),
                (("uploadId", runner.upload_id),))
            ok = snap.status in (200, 204, 404)
        except (TransportError, ConfigError):
            ok = False
            snap = Snapshot(0, {}, b"")
        runner.cleanup.append({
            "step": "abort-mpu", "status": snap.status, "passed": ok,
        })
        if not ok:
            failed += 1
        else:
            runner.upload_id = None
    seen = list(runner.objects)
    try:
        listed = runner.target.request("GET", _path(runner.bucket))
        for key in _xml_keys(listed.body):
            if key not in seen:
                seen.append(key)
    except (TransportError, ConfigError, SchemaError):
        pass
    for key in seen:
        try:
            snap = runner.target.request("DELETE", _path(runner.bucket, key))
            ok = snap.status in (200, 204, 404)
        except (TransportError, ConfigError):
            ok = False
            snap = Snapshot(0, {}, b"")
        runner.cleanup.append({
            "step": "delete-object", "key": key, "status": snap.status, "passed": ok,
        })
        if not ok:
            failed += 1
        elif key in runner.objects:
            runner.objects.remove(key)
    for bucket in list(runner.owned):
        try:
            _empty_bucket(runner.target, bucket)
            snap = runner.target.request("DELETE", _path(bucket))
            ok = snap.status in (200, 204, 404)
        except (TransportError, ConfigError):
            ok = False
            snap = Snapshot(0, {}, b"")
        runner.cleanup.append({
            "step": "delete-bucket", "bucket": bucket, "status": snap.status, "passed": ok,
        })
        if not ok:
            failed += 1
        elif bucket in runner.owned:
            runner.owned.remove(bucket)
        for sidecar in (bucket + "+versions", bucket + "+segments"):
            try:
                snap = runner.target.request("DELETE", _sidecar_path(sidecar))
                ok = snap.status in (200, 204, 404)
            except (TransportError, ConfigError):
                ok = False
                snap = Snapshot(0, {}, b"")
            runner.cleanup.append({
                "step": "delete-sidecar", "bucket": sidecar,
                "status": snap.status, "passed": ok,
            })
            if not ok and snap.status not in (400, 403, 405):
                failed += 1
    return failed


def _build_report(runner: Runner, endpoint: str, cleanup_failed: int,
                  started: str, ended: str) -> Dict[str, Any]:
    executed = [c.name for c in runner.results]
    missing = [name for name in ALL_CASES if name not in executed]
    extra = [name for name in executed if name not in ALL_CASES]
    failed_names = [c.name for c in runner.results if not c.passed]
    passed = sum(1 for c in runner.results if c.passed)
    failed = len(failed_names)
    required = len(ALL_CASES)
    ran_all = not missing and not extra and len(executed) == required
    gate = "PASS" if failed == 0 and cleanup_failed == 0 and ran_all else "FAIL"
    return {
        "schema": REPORT_SCHEMA,
        "tool": TOOL_NAME,
        "tool_sha256": _tool_sha256(),
        "endpoint": endpoint,
        "region": runner.target.region,
        "signing": "sigv4-header path-style",
        "started_utc": started,
        "ended_utc": ended,
        "required": required,
        "executed": len(executed),
        "passed": passed,
        "failed": failed,
        "cleanup_failed": cleanup_failed,
        "missing": missing,
        "fail_names": failed_names,
        "gate": gate,
        "bucket": runner.bucket,
        "cases": [c.record() for c in runner.results],
        "cleanup": runner.cleanup,
    }


def _print_digest(report: Mapping[str, Any]) -> None:
    print("schema={}".format(report["schema"]))
    print("cases={}".format(",".join(ALL_CASES)))
    print("required={} executed={} passed={} failed={} cleanup_failed={}".format(
        report["required"], report["executed"], report["passed"],
        report["failed"], report["cleanup_failed"]))
    print("gate={}".format(report["gate"]))
    fails = report.get("fail_names") or []
    print("fail_names={}".format(",".join(fails) if fails else "-"))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--rust", default=DEFAULT_ENDPOINT)
    parser.add_argument("--rust-insecure", action="store_true")
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--json-report")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    return parser


def _q0(query: str) -> str:
    if not query:
        return ""
    return query.split("&")[0].split("=")[0]


class _MockClient:
    def __init__(self, mode: str = "ok") -> None:
        self.mode = mode
        self.objects: Dict[str, bytes] = {}
        self.uploads: Dict[str, Dict[str, Any]] = {}
        self.buckets: set = set()

    def request(self, method: str, url: str, body: bytes,
                headers: Mapping[str, str]) -> Snapshot:
        parsed = urlsplit(url)
        path = parsed.path
        query = parsed.query
        q0 = _q0(query)
        hdrs = {k.lower(): v for k, v in headers.items()}
        parts = [p for p in path.split("/") if p]
        bucket = parts[0] if parts else None
        key = "/".join(parts[1:]) if len(parts) > 1 else None

        if self.mode == "torrent-empty":
            if method == "GET" and q0 == "torrent":
                return Snapshot(200, {"content-type": ("application/octet-stream",)}, b"")
        if self.mode == "wgor-implemented":
            if "x-amz-request-route" in hdrs:
                return Snapshot(200, {}, b"implemented")
        if self.mode == "cleanup-fail" and method == "DELETE" and key is None and bucket:
            return Snapshot(409, {"content-type": ("application/xml",)},
                            b"<Error><Code>BucketNotEmpty</Code></Error>")

        if "x-amz-request-route" in hdrs:
            return Snapshot(501, {"content-type": ("application/xml",)}, WGOR_NOT_IMPL)

        if method == "PUT" and bucket and key is None:
            self.buckets.add(bucket)
            return Snapshot(200, {}, b"")
        if method == "DELETE" and bucket and key is None:
            self.buckets.discard(bucket)
            return Snapshot(204, {}, b"")
        if method == "GET" and bucket and key is None and q0 == "session":
            return Snapshot(200, {"content-type": ("application/xml",)}, SESSION_OK)
        if method == "POST" and bucket and key is None and q0 == "session":
            return Snapshot(200, {"content-type": ("application/xml",)}, SESSION_OK)
        if method == "GET" and bucket and key is None:
            items = "".join("<Contents><Key>{}</Key></Contents>".format(k)
                            for k in self.objects)
            xml = "<ListBucketResult>{}</ListBucketResult>".format(items).encode("ascii")
            return Snapshot(200, {"content-type": ("application/xml",)}, xml)

        if method == "PUT" and bucket and key and q0 != "partNumber" and "uploadId" not in query:
            if "x-amz-rename-source" in hdrs:
                return self._rename(hdrs["x-amz-rename-source"], key)
            self.objects[key] = body
            return Snapshot(200, {}, b"")
        if method == "POST" and bucket and key and "x-amz-rename-source" in hdrs:
            return self._rename(hdrs["x-amz-rename-source"], key)
        if method == "GET" and bucket and key and q0 == "torrent":
            if key not in self.objects:
                return Snapshot(404, {"content-type": ("application/xml",)},
                                b"<Error><Code>NoSuchKey</Code></Error>")
            return Snapshot(200, {"content-type": ("application/x-bittorrent",)}, TORRENT_OK)
        if method == "GET" and bucket and key:
            if key not in self.objects:
                return Snapshot(404, {"content-type": ("application/xml",)},
                                b"<Error><Code>NoSuchKey</Code></Error>")
            return Snapshot(200, {}, self.objects[key])
        if method == "DELETE" and bucket and key and "uploadId" in query:
            self.uploads.pop(key, None)
            return Snapshot(204, {}, b"")
        if method == "DELETE" and bucket and key:
            self.objects.pop(key, None)
            return Snapshot(204, {}, b"")
        if method == "POST" and bucket and key and q0 == "uploads":
            self.uploads[key] = {"id": "u-honest", "parts": {}}
            return Snapshot(
                200, {"content-type": ("application/xml",)},
                b"<InitiateMultipartUploadResult><UploadId>u-honest</UploadId>"
                b"</InitiateMultipartUploadResult>")
        if method == "PUT" and bucket and key and "uploadId" in query and "partNumber" in query:
            src = hdrs.get("x-amz-copy-source") or ""
            src_key = src.rsplit("/", 1)[-1]
            payload = self.objects.get(src_key, b"")
            self.uploads.setdefault(key, {"id": "u-honest", "parts": {}})
            self.uploads[key]["parts"][1] = payload
            return Snapshot(
                200, {"content-type": ("application/xml",)},
                b"<CopyPartResult><ETag>\"part1\"</ETag></CopyPartResult>")
        if method == "POST" and bucket and key and "uploadId" in query and q0 != "select":
            parts = self.uploads.get(key, {}).get("parts", {})
            assembled = parts.get(1, b"")
            self.objects[key] = assembled
            self.uploads.pop(key, None)
            return Snapshot(
                200, {"content-type": ("application/xml",)},
                b"<CompleteMultipartUploadResult><ETag>\"done\"</ETag>"
                b"</CompleteMultipartUploadResult>")
        if method == "POST" and bucket and key and q0 == "select":
            data = self.objects.get(key, b"")
            return Snapshot(
                200, {"content-type": ("application/vnd.amazon.eventstream",)},
                b"\x00\x00event " + data)
        return Snapshot(404, {}, b"<Error><Code>NotFound</Code></Error>")

    def _rename(self, source: str, dest: str) -> Snapshot:
        src_key = source.rsplit("/", 1)[-1]
        if src_key not in self.objects:
            return Snapshot(404, {"content-type": ("application/xml",)},
                            b"<Error><Code>NoSuchKey</Code></Error>")
        self.objects[dest] = self.objects.pop(src_key)
        return Snapshot(204, {}, b"")


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise SelfTestError(message)


def _setup_runner(client: _MockClient, stamp: str = "20260818t000000z") -> Runner:
    bucket = "s3-honest-{}".format(stamp)
    _bucket_ok(bucket)
    target = Target("https://10.0.0.10:8085", "ak", "secret-key-value", "RegionOne", client)
    runner = Runner(target, bucket)
    created = target.request("PUT", _path(bucket))
    _expect(created.status in (200, 201), "mock create-bucket failed")
    runner.owned.append(bucket)
    return runner


def run_selftest() -> int:
    try:
        _selftest_body()
    except (SelfTestError, Exception) as exc:
        print("strict-s3-engine-honesty offline self-test: FAIL -- {}".format(exc),
              file=sys.stderr)
        return EXIT_RUNTIME
    print("strict-s3-engine-honesty offline self-test: PASS")
    return EXIT_PASS


def _selftest_body() -> None:
    _expect(ALL_CASES == (
        "torrent-bencode", "session-xml", "rename-source-gone",
        "part-copy-bytes", "select-star-payload", "wgOR-still-501",
    ), "declared case names drifted")
    _expect(len(ALL_CASES) == len(set(ALL_CASES)), "duplicate case names")

    headers, query = _signed_request(
        method="GET", path="/test.txt", query=(), body=b"",
        headers={"Range": "bytes=0-9"},
        access="AKIAIOSFODNN7EXAMPLE",
        secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region="us-east-1", host="examplebucket.s3.amazonaws.com",
        signed_at=1369353600,
    )
    _expect(not query, "sigv4 must not add query")
    _expect(headers["Authorization"].endswith(
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"),
        "sigv4 signature differs from AWS published vector")

    try:
        _bucket_ok("mytest")
    except ConfigError:
        pass
    else:
        raise SelfTestError("mytest was not forbidden")
    try:
        _bucket_ok("AUTH_test")
    except ConfigError:
        pass
    else:
        raise SelfTestError("AUTH_test was not forbidden")
    try:
        _bucket_ok("s3-matrix-20260818t000000z")
    except ConfigError:
        pass
    else:
        raise SelfTestError("non-honest bucket prefix was accepted")

    runner = _setup_runner(_MockClient("ok"))
    _run_probes(runner)
    cleanup_failed = _cleanup(runner)
    report = _build_report(runner, runner.target.endpoint, cleanup_failed,
                           "2026-08-18T00:00:00Z", "2026-08-18T00:00:01Z")
    _expect(report["executed"] == report["required"] == len(ALL_CASES),
            "selftest did not run every declared case")
    _expect(report["failed"] == 0, "happy-path mock had FAILs: {}".format(
        report["fail_names"]))
    _expect(report["cleanup_failed"] == 0, "happy-path cleanup failed")
    _expect(report["gate"] == "PASS", "happy-path gate is not PASS")
    dumped = json.dumps(report)
    _expect("secret-key-value" not in dumped, "secret leaked into report")
    _expect(runner.target.secret not in dumped, "secret leaked into report")
    session = next(c for c in report["cases"] if c["name"] == "session-xml")
    _expect("AKIAEXAMPLE" not in json.dumps(session["observed"]),
            "session AccessKeyId value stored in observed")

    broken = _setup_runner(_MockClient("torrent-empty"), "20260818t000001z")
    _run_probes(broken)
    torrent = next(c for c in broken.results if c.name == "torrent-bencode")
    _expect(not torrent.passed, "empty torrent body must FAIL")
    _cleanup(broken)

    implemented = _setup_runner(_MockClient("wgor-implemented"), "20260818t000002z")
    _run_probes(implemented)
    wgor = next(c for c in implemented.results if c.name == "wgOR-still-501")
    _expect(not wgor.passed, "implemented WGOR must FAIL")
    _cleanup(implemented)

    dirty = _setup_runner(_MockClient("cleanup-fail"), "20260818t000003z")
    _run_probes(dirty)
    dirty_failed = _cleanup(dirty)
    dirty_report = _build_report(dirty, dirty.target.endpoint, dirty_failed,
                                 "2026-08-18T00:00:00Z", "2026-08-18T00:00:01Z")
    _expect(dirty_report["cleanup_failed"] > 0, "cleanup-fail mock did not fail cleanup")
    _expect(dirty_report["gate"] == "FAIL", "cleanup failure must FAIL the gate")

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "report.json"
        _atomic_new_report(path, {"ok": True})
        try:
            _atomic_new_report(path, {"ok": False})
        except ConfigError:
            pass
        else:
            raise SelfTestError("json-report overwrite was allowed")

    leaked = _redact("access_key=secretvalue secretvalue", ("secretvalue",))
    _expect("secretvalue" not in leaked, "secret leaked through redact")
    err = io.StringIO()
    with redirect_stderr(err):
        rc = main(["--rust", "https://10.0.0.10:8085"])
    _expect(rc == EXIT_RUNTIME, "live without --json-report must refuse")
    _expect("--json-report is required" in err.getvalue(),
            "live refusal message missing")


def _create_bucket(runner: Runner) -> None:
    snap = runner.target.request("PUT", _path(runner.bucket))
    if snap.status not in (200, 201):
        raise SetupError("create-bucket status {}".format(snap.status))
    runner.owned.append(runner.bucket)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.selftest:
        return run_selftest()
    try:
        if not args.json_report:
            raise ConfigError("--json-report is required for live runs")
        endpoint = _validate_endpoint(args.rust)
        access, secret = _load_creds()
        client = HttpClient(args.timeout, MAX_RESPONSE_BYTES, args.rust_insecure)
        target = Target(endpoint, access, secret, args.region, client)
        bucket = "s3-honest-{}".format(_utc_stamp())
        _bucket_ok(bucket)
        runner = Runner(target, bucket)
        started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            _create_bucket(runner)
            _run_probes(runner)
        finally:
            cleanup_failed = _cleanup(runner)
        ended = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        report = _build_report(runner, endpoint, cleanup_failed, started, ended)
        _print_digest(report)
        _atomic_new_report(Path(args.json_report), report)
        print("report={}".format(args.json_report))
        if report["failed"] != 0 or report["cleanup_failed"] != 0:
            return EXIT_FAIL
        return EXIT_PASS
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except (ConfigError, SetupError, TransportError) as exc:
        print("ERROR {}".format(_redact(str(exc), (
            os.environ.get("PEREGRINE_S3_RS_ACCESS") or "",
            os.environ.get("PEREGRINE_S3_RS_SECRET") or "",
        ))), file=sys.stderr)
        return EXIT_RUNTIME


if __name__ == "__main__":
    sys.exit(main())
