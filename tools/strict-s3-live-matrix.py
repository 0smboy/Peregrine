#!/usr/bin/env python3
"""Live S3 client matrix (guarantee, not Python parity).

Stdlib + optional subprocess s3cmd. Path-style SigV4, region RegionOne.
Never prints access_key/secret_key. Never writes mytest / AUTH_lab / AUTH_test.
Self-creates s3-matrix-<utc> buckets and deletes them at the end.

    python3 tools/strict-s3-live-matrix.py --selftest
    python3 tools/strict-s3-live-matrix.py \\
      --rust https://10.0.0.10:8085 --rust-insecure \\
      --json-report /root/work/evidence/strict-s3-live-matrix-20260818.json

Exit 0 only if failed=0 and cleanup_failed=0 and every declared case ran.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
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
REPORT_SCHEMA = "peregrine.strict-s3-live-matrix.v1"
TOOL_NAME = "strict-s3-live-matrix.py"
SERVICE = "s3"
V4_ALGORITHM = "AWS4-HMAC-SHA256"
DEFAULT_ENDPOINT = "https://10.0.0.10:8085"
DEFAULT_REGION = "RegionOne"
DEFAULT_S3CFG = "/root/.s3cfg-tempauth"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 30.0
FORBIDDEN_BUCKETS = frozenset({"mytest"})
FORBIDDEN_PREFIXES = ("auth_lab", "auth_test")
BUCKET_RE = re.compile(r"^s3-matrix-[0-9]{8}t[0-9]{6}z[a-z0-9]{0,8}$")
S3CFG_KEYS = re.compile(r"^(access_key|secret_key|host_base|host_bucket|"
                        r"use_https|check_ssl_certificate|signature_v2|"
                        r"bucket_location)\s*=\s*(.*)$")

UNSUPPORTED_SUBRESOURCES = (
    # WriteGetObjectResponse is header-only (x-amz-request-route), not a query.
)

# query, kind xml|json, body, success marker, missing error (None = 200 empty XML)
STORED_BUCKET_CONFIGS = (
    ("policy", "json",
     b'{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}',
     "Version", "NoSuchBucketPolicy"),
    ("website", "xml",
     b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>",
     "WebsiteConfiguration", "NoSuchWebsiteConfiguration"),
    ("logging", "xml", b"<BucketLoggingStatus/>",
     "BucketLoggingStatus", None),
    ("notification", "xml", b"<NotificationConfiguration/>",
     "NotificationConfiguration", None),
    ("encryption", "xml",
     b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>"
     b"<SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault>"
     b"</Rule></ServerSideEncryptionConfiguration>",
     "ServerSideEncryptionConfiguration", "ServerSideEncryptionConfigurationNotFoundError"),
    ("publicAccessBlock", "xml",
     b"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls>"
     b"<IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy>"
     b"<RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>",
     "PublicAccessBlockConfiguration", "NoSuchPublicAccessBlockConfiguration"),
    ("ownershipControls", "xml",
     b"<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>",
     "OwnershipControls", "OwnershipControlsNotFoundError"),
    ("requestPayment", "xml",
     b"<RequestPaymentConfiguration><Payer>BucketOwner</Payer></RequestPaymentConfiguration>",
     "RequestPaymentConfiguration", None),
    ("accelerate", "xml",
     b"<AccelerateConfiguration><Status>Suspended</Status></AccelerateConfiguration>",
     "AccelerateConfiguration", None),
    ("analytics", "xml",
     b"<AnalyticsConfiguration><Id>matrix</Id></AnalyticsConfiguration>",
     "AnalyticsConfiguration", "NoSuchConfiguration"),
    ("inventory", "xml",
     b"<InventoryConfiguration><Id>matrix</Id><IsEnabled>false</IsEnabled></InventoryConfiguration>",
     "InventoryConfiguration", "NoSuchConfiguration"),
    ("metrics", "xml",
     b"<MetricsConfiguration><Id>matrix</Id></MetricsConfiguration>",
     "MetricsConfiguration", "NoSuchConfiguration"),
    ("intelligent-tiering", "xml",
     b"<IntelligentTieringConfiguration><Id>matrix</Id><Status>Disabled</Status>"
     b"</IntelligentTieringConfiguration>",
     "IntelligentTieringConfiguration", "NoSuchConfiguration"),
    ("replication", "xml",
     b"<ReplicationConfiguration><Role>arn:aws:iam::1:role/r</Role><Rule><ID>r1</ID>"
     b"<Status>Disabled</Status><Destination><Bucket>arn:aws:s3:::dest</Bucket></Destination>"
     b"</Rule></ReplicationConfiguration>",
     "ReplicationConfiguration", "ReplicationConfigurationNotFoundError"),
    ("metadataConfiguration", "xml",
     b"<MetadataConfiguration><JournalTableConfiguration><RecordExpiration>"
     b"<Expiration>NONE</Expiration></RecordExpiration></JournalTableConfiguration>"
     b"</MetadataConfiguration>",
     "MetadataConfiguration", "NoSuchConfiguration"),
    ("metadataTableConfiguration", "xml",
     b"<MetadataTableConfiguration><S3TablesDestination><TableBucketArn>"
     b"arn:aws:s3tables:us-east-1:1:bucket/b</TableBucketArn>"
     b"<TableName>t</TableName></S3TablesDestination></MetadataTableConfiguration>",
     "MetadataTableConfiguration", "NoSuchConfiguration"),
    ("metadataJournalTableConfiguration", "xml",
     b"<JournalTableConfiguration><RecordExpiration><Expiration>NONE</Expiration>"
     b"</RecordExpiration></JournalTableConfiguration>",
     "JournalTableConfiguration", "NoSuchConfiguration"),
    ("metadataInventoryTableConfiguration", "xml",
     b"<InventoryTableConfiguration><ConfigurationState>DISABLED</ConfigurationState>"
     b"</InventoryTableConfiguration>",
     "InventoryTableConfiguration", "NoSuchConfiguration"),
    ("metadataAnnotationTableConfiguration", "xml",
     b"<AnnotationTableConfiguration><ConfigurationState>DISABLED</ConfigurationState>"
     b"</AnnotationTableConfiguration>",
     "AnnotationTableConfiguration", "NoSuchConfiguration"),
    ("abac", "xml",
     b"<AbacStatus><Status>Disabled</Status></AbacStatus>",
     "AbacStatus", "NoSuchConfiguration"),
)
ANNOTATION_XML = (
    b"<ObjectAnnotation><Annotation>matrix</Annotation></ObjectAnnotation>"
)
OBJECT_ENCRYPTION_XML = (
    b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault>"
    b"<SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault>"
    b"</Rule></ServerSideEncryptionConfiguration>"
)
SELECT_XML = (
    b"<SelectRequest><Expression>SELECT * FROM S3Object</Expression>"
    b"<InputSerialization><CSV/></InputSerialization>"
    b"<OutputSerialization><CSV/></OutputSerialization></SelectRequest>"
)
SELECT_LIMIT_XML = (
    b"<SelectRequest><Expression>SELECT * FROM S3Object LIMIT 1</Expression>"
    b"<InputSerialization><CSV/></InputSerialization>"
    b"<OutputSerialization><CSV/></OutputSerialization></SelectRequest>"
)
SELECT_NOT_STAR_XML = (
    b"<SelectRequest><Expression>SELECT _1 FROM S3Object</Expression>"
    b"<InputSerialization><CSV/></InputSerialization>"
    b"<OutputSerialization><CSV/></OutputSerialization></SelectRequest>"
)
SELECT_WHERE_XML = (
    b"<SelectRequest><Expression>SELECT _1 FROM S3Object WHERE _2 = '2'</Expression>"
    b"<InputSerialization><CSV/></InputSerialization>"
    b"<OutputSerialization><CSV/></OutputSerialization></SelectRequest>"
)
SELECT_UNSUPPORTED_XML = (
    b"<SelectRequest><Expression>SELECT * FROM S3Object JOIN x</Expression>"
    b"<InputSerialization><CSV/></InputSerialization>"
    b"<OutputSerialization><CSV/></OutputSerialization></SelectRequest>"
)
ROWS_CSV = b"red,1\nblue,2\ngreen,3\n"
STORED_QUERY_NAMES = frozenset(item[0] for item in STORED_BUCKET_CONFIGS)

RESTORE_XML = (
    b'<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<Days>1</Days></RestoreRequest>"
)
VERSIONING_ENABLED_XML = (
    b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<Status>Enabled</Status></VersioningConfiguration>"
)
OBJECT_BODY = b"s3-matrix-probe-object\n"
COPY_BODY = b"s3-matrix-copy-source\n"
INDEX_HTML = b"<html>matrix-index</html>\n"
ERROR_HTML = b"<html>matrix-error</html>\n"
WEBSITE_HOSTING_XML = (
    b"<WebsiteConfiguration>"
    b"<IndexDocument><Suffix>index.html</Suffix></IndexDocument>"
    b"<ErrorDocument><Key>error.html</Key></ErrorDocument>"
    b"</WebsiteConfiguration>"
)
LIFECYCLE_XML = (
    b"<LifecycleConfiguration><Rule><ID>matrix-expire</ID>"
    b"<Prefix>expire-</Prefix><Status>Enabled</Status>"
    b"<Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>"
)
TAG_XML = (
    b'<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>'
    b"<Tag><Key>matrix</Key><Value>w0</Value></Tag></TagSet></Tagging>"
)


def _declared_cases() -> Tuple[str, ...]:
    names = [
        "list-buckets",
        "account-root-put",
        "account-root-delete",
        "account-root-post",
        "account-root-head",
        "create-bucket",
        "create-bucket-slash",
        "head-bucket",
        "head-bucket-slash",
        "put-object",
        "get-object",
        "head-object",
        "get-object-range",
        "copy-object",
        "list-objects-v1",
        "list-objects-v1-slash",
        "list-objects-v2",
        "list-objects-v2-slash",
        "get-bucket-location",
        "get-bucket-location-slash",
        "multi-delete",
        "mpu-initiate",
        "list-parts",
        "list-multipart-uploads",
        "mpu-abort",
        "mpu-initiate-complete",
        "upload-part",
        "complete-multipart",
        "get-mpu-object",
        "get-bucket-versioning",
        "get-bucket-versioning-slash",
        "put-bucket-versioning",
        "put-bucket-versioning-slash",
        "list-object-versions",
        "list-object-versions-slash",
        "get-bucket-acl",
        "get-bucket-acl-slash",
        "get-object-acl",
        "get-bucket-tagging",
        "get-bucket-tagging-slash",
        "get-bucket-cors",
        "get-bucket-cors-slash",
        "restore-standard",
        "put-bucket-tagging",
        "get-bucket-tagging-after-put",
        "delete-bucket-tagging",
        "put-object-tagging",
        "get-object-tagging",
        "delete-object-tagging",
        "put-lifecycle",
        "get-lifecycle",
        "put-lifecycle-object",
        "head-lifecycle-expiration",
        "get-lifecycle-expiration",
        "delete-lifecycle",
        "get-lifecycle-after-delete",
        "put-website-index",
        "put-website-error",
        "put-website-hosting",
        "website-get-index",
        "website-get-error",
        "put-object-acl",
        "upload-part-copy",
        "get-bucket-policy-status",
        "get-bucket-policy-status-slash",
        "get-object-attributes",
        "rename-object",
        "create-session",
        "put-object-annotation",
        "get-object-annotation",
        "delete-object-annotation",
        "put-object-encryption",
        "get-object-encryption",
        "select-star",
        "select-limit",
        "select-not-star",
        "select-where",
        "select-unsupported",
        "get-object-torrent",
        "write-get-object-response-501",
        "list-directory-buckets",
        "delete-object",
        "delete-bucket",
        "delete-bucket-slash",
        "s3cmd-ls-root",
        "s3cmd-ls-bucket",
        "s3cmd-mb",
        "s3cmd-put",
        "s3cmd-ls-probe",
        "s3cmd-get",
        "s3cmd-del",
        "s3cmd-rb",
    ]
    for query, _kind, _body, _marker, _missing in STORED_BUCKET_CONFIGS:
        names.extend([
            "put-cfg-{}".format(query),
            "get-cfg-{}".format(query),
            "get-cfg-{}-slash".format(query),
            "delete-cfg-{}".format(query),
            "get-cfg-{}-after-delete".format(query),
        ])
    for sub in UNSUPPORTED_SUBRESOURCES:
        names.append("get-unsupported-{}".format(sub))
        names.append("get-unsupported-{}-slash".format(sub))
    return tuple(names)


ALL_CASES = _declared_cases()


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


def _has_root(payload: bytes, name: str) -> bool:
    try:
        return _tag(_xml_root(payload)) == name
    except SchemaError:
        return False


def _xml_expected_ok(body: bytes) -> Optional[str]:
    if not body:
        return "2xx/error XML expected but body empty"
    try:
        _xml_root(body)
    except SchemaError as exc:
        return "XML expected: {}".format(exc)
    return None


def _bucket_ok(name: str) -> None:
    lowered = name.lower()
    if lowered in FORBIDDEN_BUCKETS or any(lowered.startswith(p) for p in FORBIDDEN_PREFIXES):
        raise ConfigError("refusing forbidden bucket name")
    if not BUCKET_RE.fullmatch(name):
        raise ConfigError("bucket name is not an s3-matrix probe")


def _sidecar_ok(name: str) -> None:
    if name.endswith("+versions") or name.endswith("+segments"):
        _bucket_ok(name.rsplit("+", 1)[0])
        return
    _bucket_ok(name)


def _path(bucket: Optional[str] = None, key: Optional[str] = None,
          trailing_slash: bool = False) -> str:
    if bucket is None:
        return "/"
    _bucket_ok(bucket)
    value = "/" + _aws_quote(bucket)
    if key is not None:
        value += "/" + _aws_quote(key, safe="-_.~/")
    elif trailing_slash:
        value += "/"
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
            "User-Agent": "peregrine-strict-s3-live-matrix/1",
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
    def __init__(self, target: Target, buckets: Mapping[str, str],
                 s3cmd: Optional[str], s3cfg: Optional[str],
                 s3cmd_runner: Optional[Callable[..., Tuple[int, str]]] = None) -> None:
        self.target = target
        self.buckets = dict(buckets)
        self.s3cmd = s3cmd
        self.s3cfg = s3cfg
        self.s3cmd_runner = s3cmd_runner
        self.results: List[Case] = []
        self.cleanup: List[Dict[str, Any]] = []
        self.owned: List[str] = []
        self.objects: Dict[str, List[str]] = {}
        self.upload_id: Optional[str] = None
        self.part_etag: Optional[str] = None

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

    def expect_xml(self, case: Case, snap: Snapshot, root: Optional[str] = None) -> None:
        problem = _xml_expected_ok(snap.body)
        if problem:
            case.issue(problem)
            return
        if root and not _has_root(snap.body, root):
            case.issue("XML root is not {}".format(root))

    def expect_error(self, case: Case, snap: Snapshot, status: int, code: str,
                     allow_empty_head: bool = False, method: str = "GET") -> None:
        self.expect_status(case, snap, (status,))
        if allow_empty_head and method == "HEAD":
            return
        problem = _xml_expected_ok(snap.body)
        if problem:
            case.issue(problem)
            return
        got = _error_code(snap.body)
        if got != code:
            case.issue("error Code {} != {}".format(got, code))

    def expect_2xx_xml(self, case: Case, snap: Snapshot, root: str,
                       allowed: Sequence[int] = (200,)) -> None:
        self.expect_status(case, snap, allowed)
        if 200 <= snap.status < 300:
            self.expect_xml(case, snap, root)

    def expect_body_contains(self, case: Case, snap: Snapshot, marker: str,
                             allowed: Sequence[int] = (200,)) -> None:
        self.expect_status(case, snap, allowed)
        if marker.encode("utf-8") not in snap.body:
            case.issue("body missing {}".format(marker))

    def s3cmd_run(self, args: Sequence[str]) -> Tuple[int, str]:
        if self.s3cmd_runner is not None:
            return self.s3cmd_runner(*args)
        if not self.s3cmd:
            return 127, "s3cmd-missing"
        cmd = [self.s3cmd]
        if self.s3cfg:
            cmd.extend(["-c", self.s3cfg])
        cmd.extend(args)
        try:
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=DEFAULT_TIMEOUT, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 127, type(exc).__name__
        text = proc.stdout.decode("utf-8", "replace")
        return proc.returncode, _redact(text, (self.target.access, self.target.secret))


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


def _mpu_upload_id(body: bytes) -> Optional[str]:
    try:
        root = _xml_root(body)
    except SchemaError:
        return None
    for child in root.iter():
        if _tag(child) == "UploadId" and child.text:
            return child.text
    return None


def _version_targets(body: bytes) -> List[Tuple[str, str]]:
    targets: List[Tuple[str, str]] = []
    try:
        root = _xml_root(body)
    except SchemaError:
        return targets
    for child in list(root):
        if _tag(child) not in ("Version", "DeleteMarker"):
            continue
        key = None
        version_id = None
        for item in list(child):
            if _tag(item) == "Key" and item.text:
                key = item.text
            elif _tag(item) == "VersionId" and item.text:
                version_id = item.text
        if key and version_id:
            targets.append((key, version_id))
    return targets


def _empty_bucket(target: Target, bucket: str) -> None:
    for _ in range(8):
        remaining = 0
        snap = target.request("GET", _path(bucket), (("versions", ""),))
        for key, version_id in _version_targets(snap.body):
            target.request("DELETE", _path(bucket, key), (("versionId", version_id),))
            remaining += 1
        snap = target.request("GET", _path(bucket))
        try:
            root = _xml_root(snap.body)
        except SchemaError:
            root = None
        if root is not None:
            for child in root.iter():
                if _tag(child) == "Key" and child.text:
                    gone = target.request("DELETE", _path(bucket, child.text))
                    if gone.status == 412:
                        target.request("PUT", _path(bucket, child.text), (), b"x")
                        target.request("DELETE", _path(bucket, child.text))
                    remaining += 1
        if remaining == 0:
            return


def _run_matrix(runner: Runner) -> None:
    main = runner.buckets["main"]
    slash = runner.buckets["slash"]
    probe = runner.buckets["probe"]

    def list_buckets(case: Case) -> None:
        snap = runner.req(case, "GET", "/")
        runner.expect_2xx_xml(case, snap, "ListAllMyBucketsResult")

    def account_root(method: str):
        def fn(case: Case) -> None:
            headers = {"Content-Length": "0"} if method in ("PUT", "POST") else None
            snap = runner.req(case, method, "/", (), b"", headers)
            if 200 <= snap.status < 300:
                case.issue("account-root {} returned 2xx {}; Guard must 405".format(
                    method, snap.status))
                return
            runner.expect_error(case, snap, 405, "MethodNotAllowed",
                                allow_empty_head=True, method=method)
        return fn

    def create(name: str, trailing: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "PUT", _path(name, trailing_slash=trailing))
            runner.expect_status(case, snap, (200, 201))
            if case.passed:
                runner.owned.append(name)
                runner.objects.setdefault(name, [])
        return fn

    def head_bucket(trailing: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "HEAD", _path(main, trailing_slash=trailing))
            runner.expect_status(case, snap, (200,))
        return fn

    def put_object(case: Case) -> None:
        snap = runner.req(case, "PUT", _path(main, "probe.txt"), (), OBJECT_BODY,
                          {"Content-Type": "text/plain"})
        runner.expect_status(case, snap, (200,))
        if case.passed:
            runner.objects.setdefault(main, []).append("probe.txt")

    def get_object(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main, "probe.txt"))
        runner.expect_status(case, snap, (200,))
        if snap.body != OBJECT_BODY:
            case.issue("object body mismatch")

    def head_object(case: Case) -> None:
        snap = runner.req(case, "HEAD", _path(main, "probe.txt"))
        runner.expect_status(case, snap, (200,))

    def get_range(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main, "probe.txt"), (), b"",
                          {"Range": "bytes=0-8"})
        runner.expect_status(case, snap, (206,))
        if snap.body != OBJECT_BODY[:9]:
            case.issue("range body is not bytes 0-8 of the object")

    def copy_object(case: Case) -> None:
        put = runner.req(case, "PUT", _path(main, "copy-src.txt"), (), COPY_BODY)
        if put.status not in (200,):
            case.issue("copy source put failed")
            return
        runner.objects.setdefault(main, []).append("copy-src.txt")
        snap = runner.req(case, "PUT", _path(main, "copy-dst.txt"), (), b"",
                          {"x-amz-copy-source": "/{}/copy-src.txt".format(main)})
        runner.expect_status(case, snap, (200,))
        if 200 <= snap.status < 300:
            runner.expect_xml(case, snap, "CopyObjectResult")
            runner.objects.setdefault(main, []).append("copy-dst.txt")

    def list_objects(list_type: Optional[str], trailing: bool):
        def fn(case: Case) -> None:
            query = (("list-type", "2"),) if list_type == "2" else ()
            snap = runner.req(case, "GET", _path(main, trailing_slash=trailing), query)
            runner.expect_2xx_xml(case, snap, "ListBucketResult")
        return fn

    def location(trailing: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "GET", _path(main, trailing_slash=trailing),
                              (("location", ""),))
            runner.expect_2xx_xml(case, snap, "LocationConstraint")
        return fn

    def multi_delete(case: Case) -> None:
        for key in ("mdel-a.txt", "mdel-b.txt"):
            put = runner.req(case, "PUT", _path(main, key), (), b"x")
            if put.status == 200:
                runner.objects.setdefault(main, []).append(key)
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b"<Delete><Object><Key>mdel-a.txt</Key></Object>"
            b"<Object><Key>mdel-b.txt</Key></Object></Delete>"
        )
        snap = runner.req(case, "POST", _path(main), (("delete", ""),), body,
                          {"Content-Type": "application/xml"})
        runner.expect_2xx_xml(case, snap, "DeleteResult")
        if case.passed:
            for key in ("mdel-a.txt", "mdel-b.txt"):
                if key in runner.objects.get(main, []):
                    runner.objects[main].remove(key)

    def mpu_init(case: Case) -> None:
        snap = runner.req(case, "POST", _path(main, "mpu.bin"), (("uploads", ""),))
        runner.expect_2xx_xml(case, snap, "InitiateMultipartUploadResult")
        runner.upload_id = _mpu_upload_id(snap.body)
        if not runner.upload_id:
            case.issue("MPU UploadId missing")

    def mpu_abort(case: Case) -> None:
        if not runner.upload_id:
            case.issue("no UploadId from initiate")
            return
        snap = runner.req(case, "DELETE", _path(main, "mpu.bin"),
                          (("uploadId", runner.upload_id),))
        runner.expect_status(case, snap, (204, 200))
        runner.upload_id = None

    def list_parts(case: Case) -> None:
        if not runner.upload_id:
            case.issue("list-parts missing upload_id")
            return
        snap = runner.req(case, "GET", _path(main, "mpu.bin"),
                          (("uploadId", runner.upload_id),))
        runner.expect_2xx_xml(case, snap, "ListPartsResult")

    def list_multipart_uploads(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main), (("uploads", ""),))
        runner.expect_2xx_xml(case, snap, "ListMultipartUploadsResult")

    def upload_part(case: Case) -> None:
        if not runner.upload_id:
            case.issue("upload-part missing upload_id")
            return
        snap = runner.req(
            case, "PUT", _path(main, "mpu.bin"),
            (("partNumber", "1"), ("uploadId", runner.upload_id)),
            OBJECT_BODY, {"Content-Type": "application/octet-stream"})
        runner.expect_status(case, snap, (200,))
        runner.part_etag = snap.first("etag") or '"part1"'

    def complete_multipart(case: Case) -> None:
        if not runner.upload_id:
            case.issue("complete-multipart missing upload_id")
            return
        etag = runner.part_etag or '"part1"'
        body = (
            b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"
            + etag.encode("ascii", "replace")
            + b"</ETag></Part></CompleteMultipartUpload>"
        )
        snap = runner.req(case, "POST", _path(main, "mpu.bin"),
                          (("uploadId", runner.upload_id),), body,
                          {"Content-Type": "application/xml"})
        runner.expect_2xx_xml(case, snap, "CompleteMultipartUploadResult")
        if case.passed:
            runner.objects.setdefault(main, []).append("mpu.bin")
            runner.upload_id = None

    def get_mpu_object(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main, "mpu.bin"))
        runner.expect_status(case, snap, (200,))
        if snap.body != OBJECT_BODY:
            case.issue("completed MPU body mismatch")
        # W5d: unversioned object DELETE sends multipart-manifest=delete.
        dele = runner.req(case, "DELETE", _path(main, "mpu.bin"))
        if dele.status not in (200, 204):
            case.issue("completed MPU SLO delete failed status={}".format(dele.status))
        elif "mpu.bin" in runner.objects.get(main, []):
            runner.objects[main].remove("mpu.bin")

    def get_versioning(trailing: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "GET", _path(main, trailing_slash=trailing),
                              (("versioning", ""),))
            runner.expect_2xx_xml(case, snap, "VersioningConfiguration")
        return fn

    def put_versioning(trailing: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "PUT", _path(main, trailing_slash=trailing),
                              (("versioning", ""),), VERSIONING_ENABLED_XML,
                              {"Content-Type": "application/xml"})
            runner.expect_status(case, snap, (200,))
        return fn

    def list_versions(trailing: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "GET", _path(main, trailing_slash=trailing),
                              (("versions", ""),))
            runner.expect_2xx_xml(case, snap, "ListVersionsResult")
        return fn

    def get_bucket_acl(trailing: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "GET", _path(main, trailing_slash=trailing),
                              (("acl", ""),))
            runner.expect_2xx_xml(case, snap, "AccessControlPolicy")
        return fn

    def get_object_acl(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main, "probe.txt"), (("acl", ""),))
        runner.expect_2xx_xml(case, snap, "AccessControlPolicy")

    def get_tagging(trailing: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "GET", _path(main, trailing_slash=trailing),
                              (("tagging", ""),))
            if snap.status == 404:
                runner.expect_error(case, snap, 404, "NoSuchTagSet")
                return
            runner.expect_2xx_xml(case, snap, "Tagging")
        return fn

    def get_cors(trailing: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "GET", _path(main, trailing_slash=trailing),
                              (("cors", ""),))
            if snap.status == 404:
                runner.expect_error(case, snap, 404, "NoSuchCORSConfiguration")
                return
            runner.expect_2xx_xml(case, snap, "CORSConfiguration")
        return fn

    def restore_standard(case: Case) -> None:
        snap = runner.req(case, "POST", _path(main, "probe.txt"),
                          (("restore", ""),), RESTORE_XML,
                          {"Content-Type": "application/xml"})
        runner.expect_error(case, snap, 400, "InvalidObjectState")

    def put_bucket_tagging(case: Case) -> None:
        snap = runner.req(case, "PUT", _path(main), (("tagging", ""),), TAG_XML,
                          {"Content-Type": "application/xml"})
        runner.expect_status(case, snap, (200,))

    def get_bucket_tagging_after_put(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main), (("tagging", ""),))
        runner.expect_2xx_xml(case, snap, "Tagging")
        if b"<Key>matrix</Key>" not in snap.body:
            case.issue("bucket tagging missing matrix key")

    def delete_bucket_tagging(case: Case) -> None:
        snap = runner.req(case, "DELETE", _path(main), (("tagging", ""),))
        runner.expect_status(case, snap, (204, 200))

    def put_object_tagging(case: Case) -> None:
        snap = runner.req(case, "PUT", _path(main, "probe.txt"),
                          (("tagging", ""),), TAG_XML,
                          {"Content-Type": "application/xml"})
        runner.expect_status(case, snap, (200,))

    def get_object_tagging(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main, "probe.txt"), (("tagging", ""),))
        runner.expect_2xx_xml(case, snap, "Tagging")
        if b"<Key>matrix</Key>" not in snap.body:
            case.issue("object tagging missing matrix key")

    def put_lifecycle(case: Case) -> None:
        snap = runner.req(case, "PUT", _path(main), (("lifecycle", ""),),
                          LIFECYCLE_XML, {"Content-Type": "application/xml"})
        runner.expect_status(case, snap, (200,))

    def get_lifecycle(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main), (("lifecycle", ""),))
        runner.expect_2xx_xml(case, snap, "LifecycleConfiguration")

    def put_lifecycle_object(case: Case) -> None:
        snap = runner.req(case, "PUT", _path(main, "expire-me.txt"), (),
                          OBJECT_BODY, {"Content-Type": "text/plain"})
        runner.expect_status(case, snap, (200,))
        if case.passed:
            runner.objects.setdefault(main, []).append("expire-me.txt")
        exp = snap.first("x-amz-expiration") or ""
        if "expiry-date=" not in exp:
            case.issue("PUT missing x-amz-expiration")

    def head_lifecycle_expiration(case: Case) -> None:
        snap = runner.req(case, "HEAD", _path(main, "expire-me.txt"))
        runner.expect_status(case, snap, (200,))
        exp = snap.first("x-amz-expiration") or ""
        if "expiry-date=" not in exp:
            case.issue("HEAD missing x-amz-expiration")

    def get_lifecycle_expiration(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main, "expire-me.txt"))
        runner.expect_status(case, snap, (200,))
        if snap.body != OBJECT_BODY:
            case.issue("lifecycle object body mismatch")
        exp = snap.first("x-amz-expiration") or ""
        if "expiry-date=" not in exp:
            case.issue("GET missing x-amz-expiration")

    def delete_lifecycle(case: Case) -> None:
        snap = runner.req(case, "DELETE", _path(main), (("lifecycle", ""),))
        runner.expect_status(case, snap, (204, 200))

    def get_lifecycle_after_delete(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main), (("lifecycle", ""),))
        runner.expect_error(case, snap, 404, "NoSuchLifecycleConfiguration")

    def put_website_index(case: Case) -> None:
        snap = runner.req(case, "PUT", _path(main, "index.html"), (), INDEX_HTML,
                          {"Content-Type": "text/html"})
        runner.expect_status(case, snap, (200,))
        if case.passed:
            runner.objects.setdefault(main, []).append("index.html")

    def put_website_error(case: Case) -> None:
        snap = runner.req(case, "PUT", _path(main, "error.html"), (), ERROR_HTML,
                          {"Content-Type": "text/html"})
        runner.expect_status(case, snap, (200,))
        if case.passed:
            runner.objects.setdefault(main, []).append("error.html")

    def put_website_hosting(case: Case) -> None:
        snap = runner.req(case, "PUT", _path(main), (("website", ""),),
                          WEBSITE_HOSTING_XML, {"Content-Type": "application/xml"})
        runner.expect_status(case, snap, (200,))

    def website_get_index(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main, trailing_slash=True), (),
                          b"", {"x-amz-website-endpoint": "1"})
        runner.expect_status(case, snap, (200,))
        if snap.body != INDEX_HTML:
            case.issue("website index body mismatch")

    def website_get_error(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main, "no-such-page"), (),
                          b"", {"x-amz-website-endpoint": "1"})
        runner.expect_status(case, snap, (404,))
        if ERROR_HTML not in snap.body:
            case.issue("website error document missing")

    def delete_object_tagging(case: Case) -> None:
        snap = runner.req(case, "DELETE", _path(main, "probe.txt"),
                          (("tagging", ""),))
        runner.expect_status(case, snap, (204, 200))

    def put_object_acl(case: Case) -> None:
        snap = runner.req(case, "PUT", _path(main, "probe.txt"), (("acl", ""),),
                          b"", {"x-amz-acl": "private"})
        runner.expect_status(case, snap, (200,))

    def upload_part_copy(case: Case) -> None:
        if not runner.upload_id:
            case.issue("upload-part-copy missing upload_id")
            return
        snap = runner.req(
            case, "PUT", _path(main, "mpu.bin"),
            (("partNumber", "1"), ("uploadId", runner.upload_id)),
            b"", {"X-Amz-Copy-Source": "/{}/probe.txt".format(main)})
        runner.expect_2xx_xml(case, snap, "CopyPartResult")

    def policy_status(trailing: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "GET", _path(main, trailing_slash=trailing),
                              (("policyStatus", ""),))
            runner.expect_2xx_xml(case, snap, "PolicyStatus")
        return fn

    def object_attributes(case: Case) -> None:
        snap = runner.req(
            case, "GET", _path(main, "probe.txt"), (("attributes", ""),),
            b"", {"x-amz-object-attributes": "ETag,ObjectSize,StorageClass"})
        runner.expect_2xx_xml(case, snap, "GetObjectAttributesOutput")
        if b"<ETag>" not in snap.body:
            case.issue("attributes missing ETag")
        if b"<ObjectSize>" not in snap.body:
            case.issue("attributes missing ObjectSize")

    def rename_object(case: Case) -> None:
        snap = runner.req(
            case, "PUT", _path(main, "renamed.txt"), (),
            b"", {"X-Amz-Rename-Source": "/{}/probe.txt".format(main),
                  "Content-Length": "0"})
        runner.expect_status(case, snap, (204, 200))
        if case.passed:
            runner.objects.setdefault(main, []).append("renamed.txt")
            if "probe.txt" in runner.objects.get(main, []):
                runner.objects[main].remove("probe.txt")
            # restore probe so later object cases still work
            put = runner.target.request("PUT", _path(main, "probe.txt"), (), OBJECT_BODY)
            if put.status in (200, 201):
                runner.objects.setdefault(main, []).append("probe.txt")

    def create_session(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main), (("session", ""),))
        runner.expect_2xx_xml(case, snap, "CreateSessionResult")

    def put_object_annotation(case: Case) -> None:
        snap = runner.req(case, "PUT", _path(main, "probe.txt"),
                          (("annotation", ""),), ANNOTATION_XML)
        runner.expect_status(case, snap, (200,))

    def get_object_annotation(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main, "probe.txt"), (("annotation", ""),))
        runner.expect_2xx_xml(case, snap, "ObjectAnnotation")

    def delete_object_annotation(case: Case) -> None:
        snap = runner.req(case, "DELETE", _path(main, "probe.txt"), (("annotation", ""),))
        runner.expect_status(case, snap, (204, 200))

    def put_object_encryption(case: Case) -> None:
        snap = runner.req(case, "PUT", _path(main, "probe.txt"),
                          (("encryption", ""),), OBJECT_ENCRYPTION_XML)
        runner.expect_status(case, snap, (200,))

    def get_object_encryption(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main, "probe.txt"), (("encryption", ""),))
        runner.expect_2xx_xml(case, snap, "ServerSideEncryptionConfiguration")

    def select_star(case: Case) -> None:
        snap = runner.req(case, "POST", _path(main, "probe.txt"),
                          (("select", ""), ("select-type", "2")), SELECT_XML)
        runner.expect_status(case, snap, (200,))
        ctype = ""
        for key, value in snap.headers.items():
            if key.lower() == "content-type":
                ctype = value[0] if isinstance(value, tuple) else str(value)
        if "eventstream" not in ctype and snap.body[:4] == b"":
            case.issue("select missing event stream")
        if not snap.body:
            case.issue("select empty body")
        if OBJECT_BODY.strip() not in snap.body and b"s3-matrix-probe-object" not in snap.body:
            case.issue("select-star missing object bytes")

    def select_limit(case: Case) -> None:
        snap = runner.req(case, "POST", _path(main, "probe.txt"),
                          (("select", ""), ("select-type", "2")), SELECT_LIMIT_XML)
        runner.expect_status(case, snap, (200,))
        if not snap.body:
            case.issue("select-limit empty body")

    def select_not_star(case: Case) -> None:
        put = runner.req(case, "PUT", _path(main, "rows.csv"), (), ROWS_CSV,
                         {"Content-Type": "text/csv"})
        runner.expect_status(case, put, (200, 201))
        if case.passed:
            runner.objects.setdefault(main, []).append("rows.csv")
        snap = runner.req(case, "POST", _path(main, "rows.csv"),
                          (("select", ""), ("select-type", "2")), SELECT_NOT_STAR_XML)
        runner.expect_status(case, snap, (200,))
        if not snap.body:
            case.issue("select-not-star empty body")
        if b"red" not in snap.body:
            case.issue("select-not-star missing red")

    def select_where(case: Case) -> None:
        snap = runner.req(case, "POST", _path(main, "rows.csv"),
                          (("select", ""), ("select-type", "2")), SELECT_WHERE_XML)
        runner.expect_status(case, snap, (200,))
        if not snap.body:
            case.issue("select-where empty body")
        if b"blue" not in snap.body:
            case.issue("select-where missing blue")

    def select_unsupported(case: Case) -> None:
        snap = runner.req(case, "POST", _path(main, "probe.txt"),
                          (("select", ""), ("select-type", "2")), SELECT_UNSUPPORTED_XML)
        runner.expect_error(case, snap, 400, "InvalidRequest")

    def get_object_torrent(case: Case) -> None:
        snap = runner.req(case, "GET", _path(main, "probe.txt"), (("torrent", ""),))
        runner.expect_body_contains(case, snap, "4:info")

    def write_get_object_response_501(case: Case) -> None:
        snap = runner.req(
            case, "POST", "/", (), b"",
            {"x-amz-request-route": "route", "x-amz-request-token": "tok"})
        runner.expect_error(case, snap, 501, "NotImplemented")

    def list_directory_buckets(case: Case) -> None:
        snap = runner.req(case, "GET", "/", (("max-directory-buckets", "100"),))
        runner.expect_2xx_xml(case, snap, "ListDirectoryBucketsResult")

    def stored_put(query: str, body: bytes):
        def fn(case: Case) -> None:
            snap = runner.req(case, "PUT", _path(main), ((query, ""),), body)
            runner.expect_status(case, snap, (200,))
        return fn

    def stored_get(query: str, kind: str, marker: str, trailing: bool,
                   missing: Optional[str], after_delete: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "GET", _path(main, trailing_slash=trailing),
                              ((query, ""),))
            if after_delete:
                if missing:
                    runner.expect_error(case, snap, 404, missing)
                else:
                    runner.expect_2xx_xml(case, snap, marker)
                return
            if kind == "json":
                runner.expect_body_contains(case, snap, marker)
            else:
                runner.expect_2xx_xml(case, snap, marker)
        return fn

    def stored_delete(query: str):
        def fn(case: Case) -> None:
            snap = runner.req(case, "DELETE", _path(main), ((query, ""),))
            runner.expect_status(case, snap, (204, 200))
        return fn

    def delete_object(case: Case) -> None:
        snap = runner.req(case, "DELETE", _path(main, "probe.txt"))
        runner.expect_status(case, snap, (204, 200))
        if "probe.txt" in runner.objects.get(main, []):
            runner.objects[main].remove("probe.txt")

    def delete_bucket(name: str, trailing: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "DELETE", _path(name, trailing_slash=trailing))
            runner.expect_status(case, snap, (204, 200))
            if case.passed and name in runner.owned:
                runner.owned.remove(name)
        return fn

    def unsupported(sub: str, trailing: bool):
        def fn(case: Case) -> None:
            snap = runner.req(case, "GET", _path(main, trailing_slash=trailing),
                              ((sub, ""),))
            runner.expect_error(case, snap, 501, "NotImplemented")
        return fn

    def s3cmd_ls_root(case: Case) -> None:
        rc, text = runner.s3cmd_run(["ls"])
        case.observed["rc"] = rc
        case.observed["bytes"] = len(text.encode("utf-8"))
        if rc != 0:
            case.issue("s3cmd ls root rc={}".format(rc))
        if "ParseError" in text or "empty" in text.lower() and "xml" in text.lower():
            case.issue("s3cmd ls root XML parse failure")

    def s3cmd_ls_bucket(case: Case) -> None:
        rc, text = runner.s3cmd_run(["ls", "s3://{}/".format(main)])
        case.observed["rc"] = rc
        if rc != 0:
            case.issue("s3cmd ls bucket rc={}".format(rc))
        if "ParseError" in text:
            case.issue("s3cmd ls bucket XML parse failure")

    def s3cmd_mb(case: Case) -> None:
        rc, _text = runner.s3cmd_run(["mb", "s3://{}/".format(probe)])
        case.observed["rc"] = rc
        if rc != 0:
            case.issue("s3cmd mb rc={}".format(rc))
        else:
            runner.owned.append(probe)
            runner.objects.setdefault(probe, [])

    def s3cmd_put(case: Case) -> None:
        handle, tmp = tempfile.mkstemp(prefix="s3-matrix-", suffix=".txt")
        try:
            os.write(handle, OBJECT_BODY)
            os.close(handle)
            handle = -1
            rc, _text = runner.s3cmd_run(["put", tmp, "s3://{}/probe.txt".format(probe)])
        finally:
            if handle >= 0:
                os.close(handle)
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
        case.observed["rc"] = rc
        if rc != 0:
            case.issue("s3cmd put rc={}".format(rc))
        else:
            runner.objects.setdefault(probe, []).append("probe.txt")

    def s3cmd_ls_probe(case: Case) -> None:
        rc, text = runner.s3cmd_run(["ls", "s3://{}/".format(probe)])
        case.observed["rc"] = rc
        if rc != 0:
            case.issue("s3cmd ls probe rc={}".format(rc))
        if "ParseError" in text:
            case.issue("s3cmd ls probe XML parse failure")

    def s3cmd_get(case: Case) -> None:
        tmp = tempfile.mkdtemp(prefix="s3-matrix-get-")
        dest = str(Path(tmp) / "got-probe.bin")
        try:
            rc, _text = runner.s3cmd_run([
                "get", "--force", "s3://{}/probe.txt".format(probe), dest,
            ])
            case.observed["rc"] = rc
            if rc != 0:
                case.issue("s3cmd get rc={}".format(rc))
            elif Path(dest).read_bytes() != OBJECT_BODY:
                case.issue("s3cmd get body mismatch")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def s3cmd_del(case: Case) -> None:
        rc, _text = runner.s3cmd_run(["del", "s3://{}/probe.txt".format(probe)])
        case.observed["rc"] = rc
        if rc != 0:
            case.issue("s3cmd del rc={}".format(rc))
        elif "probe.txt" in runner.objects.get(probe, []):
            runner.objects[probe].remove("probe.txt")

    def s3cmd_rb(case: Case) -> None:
        rc, _text = runner.s3cmd_run(["rb", "s3://{}/".format(probe)])
        case.observed["rc"] = rc
        if rc != 0:
            case.issue("s3cmd rb rc={}".format(rc))
        elif probe in runner.owned:
            runner.owned.remove(probe)

    runner.run_case("list-buckets", list_buckets)
    runner.run_case("account-root-put", account_root("PUT"))
    runner.run_case("account-root-delete", account_root("DELETE"))
    runner.run_case("account-root-post", account_root("POST"))
    runner.run_case("account-root-head", account_root("HEAD"))
    runner.run_case("create-bucket", create(main, False))
    runner.run_case("create-bucket-slash", create(slash, True))
    runner.run_case("head-bucket", head_bucket(False))
    runner.run_case("head-bucket-slash", head_bucket(True))
    runner.run_case("put-object", put_object)
    runner.run_case("get-object", get_object)
    runner.run_case("head-object", head_object)
    runner.run_case("get-object-range", get_range)
    runner.run_case("copy-object", copy_object)
    runner.run_case("list-objects-v1", list_objects(None, False))
    runner.run_case("list-objects-v1-slash", list_objects(None, True))
    runner.run_case("list-objects-v2", list_objects("2", False))
    runner.run_case("list-objects-v2-slash", list_objects("2", True))
    runner.run_case("get-bucket-location", location(False))
    runner.run_case("get-bucket-location-slash", location(True))
    runner.run_case("multi-delete", multi_delete)
    runner.run_case("mpu-initiate", mpu_init)
    runner.run_case("upload-part-copy", upload_part_copy)
    runner.run_case("list-parts", list_parts)
    runner.run_case("list-multipart-uploads", list_multipart_uploads)
    runner.run_case("mpu-abort", mpu_abort)
    runner.run_case("mpu-initiate-complete", mpu_init)
    runner.run_case("upload-part", upload_part)
    runner.run_case("complete-multipart", complete_multipart)
    runner.run_case("get-mpu-object", get_mpu_object)
    runner.run_case("put-lifecycle", put_lifecycle)
    runner.run_case("get-lifecycle", get_lifecycle)
    runner.run_case("put-lifecycle-object", put_lifecycle_object)
    runner.run_case("head-lifecycle-expiration", head_lifecycle_expiration)
    runner.run_case("get-lifecycle-expiration", get_lifecycle_expiration)
    runner.run_case("delete-lifecycle", delete_lifecycle)
    runner.run_case("get-lifecycle-after-delete", get_lifecycle_after_delete)
    runner.run_case("put-website-index", put_website_index)
    runner.run_case("put-website-error", put_website_error)
    runner.run_case("put-website-hosting", put_website_hosting)
    runner.run_case("website-get-index", website_get_index)
    runner.run_case("website-get-error", website_get_error)
    runner.run_case("get-bucket-versioning", get_versioning(False))
    runner.run_case("get-bucket-versioning-slash", get_versioning(True))
    runner.run_case("put-bucket-versioning", put_versioning(False))
    runner.run_case("put-bucket-versioning-slash", put_versioning(True))
    runner.run_case("list-object-versions", list_versions(False))
    runner.run_case("list-object-versions-slash", list_versions(True))
    runner.run_case("get-bucket-acl", get_bucket_acl(False))
    runner.run_case("get-bucket-acl-slash", get_bucket_acl(True))
    runner.run_case("get-object-acl", get_object_acl)
    runner.run_case("get-bucket-tagging", get_tagging(False))
    runner.run_case("get-bucket-tagging-slash", get_tagging(True))
    runner.run_case("get-bucket-cors", get_cors(False))
    runner.run_case("get-bucket-cors-slash", get_cors(True))
    runner.run_case("restore-standard", restore_standard)
    runner.run_case("put-bucket-tagging", put_bucket_tagging)
    runner.run_case("get-bucket-tagging-after-put", get_bucket_tagging_after_put)
    runner.run_case("delete-bucket-tagging", delete_bucket_tagging)
    runner.run_case("put-object-tagging", put_object_tagging)
    runner.run_case("get-object-tagging", get_object_tagging)
    runner.run_case("delete-object-tagging", delete_object_tagging)
    runner.run_case("put-object-acl", put_object_acl)
    runner.run_case("get-bucket-policy-status", policy_status(False))
    runner.run_case("get-bucket-policy-status-slash", policy_status(True))
    runner.run_case("get-object-attributes", object_attributes)
    runner.run_case("rename-object", rename_object)
    runner.run_case("create-session", create_session)
    runner.run_case("put-object-annotation", put_object_annotation)
    runner.run_case("get-object-annotation", get_object_annotation)
    runner.run_case("delete-object-annotation", delete_object_annotation)
    runner.run_case("put-object-encryption", put_object_encryption)
    runner.run_case("get-object-encryption", get_object_encryption)
    runner.run_case("select-star", select_star)
    runner.run_case("select-limit", select_limit)
    runner.run_case("select-not-star", select_not_star)
    runner.run_case("select-where", select_where)
    runner.run_case("select-unsupported", select_unsupported)
    runner.run_case("get-object-torrent", get_object_torrent)
    runner.run_case("write-get-object-response-501", write_get_object_response_501)
    runner.run_case("list-directory-buckets", list_directory_buckets)
    for query, kind, body, marker, missing in STORED_BUCKET_CONFIGS:
        runner.run_case("put-cfg-{}".format(query), stored_put(query, body))
        runner.run_case("get-cfg-{}".format(query),
                        stored_get(query, kind, marker, False, missing, False))
        runner.run_case("get-cfg-{}-slash".format(query),
                        stored_get(query, kind, marker, True, missing, False))
        runner.run_case("delete-cfg-{}".format(query), stored_delete(query))
        runner.run_case("get-cfg-{}-after-delete".format(query),
                        stored_get(query, kind, marker, False, missing, True))
    runner.run_case("delete-object", delete_object)
    for sub in UNSUPPORTED_SUBRESOURCES:
        runner.run_case("get-unsupported-{}".format(sub), unsupported(sub, False))
        runner.run_case("get-unsupported-{}-slash".format(sub), unsupported(sub, True))
    runner.run_case("s3cmd-ls-root", s3cmd_ls_root)
    runner.run_case("s3cmd-ls-bucket", s3cmd_ls_bucket)
    runner.run_case("s3cmd-mb", s3cmd_mb)
    runner.run_case("s3cmd-put", s3cmd_put)
    runner.run_case("s3cmd-ls-probe", s3cmd_ls_probe)
    runner.run_case("s3cmd-get", s3cmd_get)
    runner.run_case("s3cmd-del", s3cmd_del)
    runner.run_case("s3cmd-rb", s3cmd_rb)
    runner.target.request("DELETE", _path(main, "rows.csv"))
    if "rows.csv" in runner.objects.get(main, []):
        runner.objects[main].remove("rows.csv")
    _empty_bucket(runner.target, main)
    _empty_bucket(runner.target, slash)
    runner.objects[main] = []
    runner.run_case("delete-bucket", delete_bucket(main, False))
    runner.run_case("delete-bucket-slash", delete_bucket(slash, True))


def _cleanup(runner: Runner) -> int:
    failed = 0
    if runner.upload_id:
        snap = runner.target.request(
            "DELETE", _path(runner.buckets["main"], "mpu.bin"),
            (("uploadId", runner.upload_id),))
        entry = {"step": "abort-mpu", "status": snap.status, "passed": snap.status in (200, 204)}
        runner.cleanup.append(entry)
        if not entry["passed"]:
            failed += 1
    for bucket, keys in list(runner.objects.items()):
        for key in list(keys):
            try:
                snap = runner.target.request("DELETE", _path(bucket, key))
                ok = snap.status in (200, 204, 404)
            except (TransportError, ConfigError):
                ok = False
                snap = Snapshot(0, {}, b"")
            runner.cleanup.append({
                "step": "delete-object", "bucket": bucket, "status": snap.status, "passed": ok,
            })
            if not ok:
                failed += 1
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
            if not ok and snap.status not in (400, 405):
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
        "buckets": {k: v for k, v in runner.buckets.items()},
        "cases": [c.record() for c in runner.results],
        "cleanup": runner.cleanup,
    }


def _print_digest(report: Mapping[str, Any]) -> None:
    print("schema={}".format(report["schema"]))
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


class _MockClient:
    def __init__(self, mode: str = "ok") -> None:
        self.mode = mode
        self.calls: List[Tuple[str, str]] = []
        self.stored: Dict[Tuple[str, str], bytes] = {}

    def request(self, method: str, url: str, body: bytes,
                headers: Mapping[str, str]) -> Snapshot:
        parsed = urlsplit(url)
        path = parsed.path
        query = parsed.query
        q0 = query.split("&")[0].split("=")[0] if query else ""
        self.calls.append((method, path + (("?" + query) if query else "")))
        if self.mode == "empty-xml":
            return Snapshot(200, {"content-type": ("application/xml",)}, b"")
        hdrs = {k.lower(): v for k, v in headers.items()}
        if "x-amz-website-endpoint" in hdrs and method in ("GET", "HEAD"):
            if path.endswith("/no-such-page"):
                return Snapshot(404, {"content-type": ("text/html",)}, ERROR_HTML)
            if path.endswith("/") or path.endswith("/index.html"):
                return Snapshot(200, {"content-type": ("text/html",)}, INDEX_HTML)
        if path.endswith("/expire-me.txt"):
            exp = {
                "x-amz-expiration": (
                    'expiry-date="Tue, 14 Nov 2023 22:13:20 GMT", rule-id="Lifecycle"',
                ),
            }
            if method == "PUT":
                return Snapshot(200, exp, b"")
            if method == "HEAD":
                return Snapshot(200, exp, b"")
            if method == "GET":
                return Snapshot(200, exp, OBJECT_BODY)
        if "x-amz-request-route" in hdrs:
            return Snapshot(501, {"content-type": ("application/xml",)},
                            b"<Error><Code>NotImplemented</Code></Error>")
        if path == "/" and method in ("PUT", "DELETE", "POST"):
            xml = (
                b"<Error><Code>MethodNotAllowed</Code><Message>x</Message><Method>"
                + method.encode("ascii")
                + b"</Method><ResourceType>SERVICE</ResourceType></Error>"
            )
            return Snapshot(405, {"content-type": ("application/xml",)}, xml)
        if path == "/" and method == "HEAD":
            return Snapshot(405, {"content-type": ("application/xml",)}, b"")
        if path == "/" and method == "GET" and q0 == "max-directory-buckets":
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<ListDirectoryBucketsResult><Buckets/></ListDirectoryBucketsResult>")
        if path == "/" and method == "GET":
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>")
        if q0 in STORED_QUERY_NAMES:
            key = (path.rstrip("/") or "/", q0)
            spec = next(item for item in STORED_BUCKET_CONFIGS if item[0] == q0)
            _kind, empty_marker, missing = spec[1], spec[3], spec[4]
            if method == "PUT":
                self.stored[key] = body
                return Snapshot(200, {}, b"")
            if method == "DELETE":
                self.stored.pop(key, None)
                return Snapshot(204, {}, b"")
            if method == "GET":
                if key in self.stored:
                    payload = self.stored[key]
                    ctype = "application/json" if payload[:1] == b"{" else "application/xml"
                    return Snapshot(200, {"content-type": (ctype,)}, payload)
                if missing:
                    xml = (
                        b"<Error><Code>" + missing.encode("ascii")
                        + b"</Code><Message>x</Message></Error>"
                    )
                    return Snapshot(404, {"content-type": ("application/xml",)}, xml)
                return Snapshot(
                    200, {"content-type": ("application/xml",)},
                    "<{}/>".format(empty_marker).encode("ascii"),
                )
        if q0 == "tagging":
            key = (path.rstrip("/") or "/", "tagging")
            if method == "PUT":
                self.stored[key] = body
                return Snapshot(200, {}, b"")
            if method == "DELETE":
                self.stored.pop(key, None)
                return Snapshot(204, {}, b"")
            if method == "GET":
                if key in self.stored:
                    return Snapshot(200, {"content-type": ("application/xml",)},
                                    self.stored[key])
                return Snapshot(404, {"content-type": ("application/xml",)},
                                b"<Error><Code>NoSuchTagSet</Code></Error>")
        if q0 == "lifecycle":
            key = (path.rstrip("/") or "/", "lifecycle")
            if method == "PUT":
                self.stored[key] = body
                return Snapshot(200, {}, b"")
            if method == "DELETE":
                self.stored.pop(key, None)
                return Snapshot(204, {}, b"")
            if method == "GET":
                if key in self.stored:
                    return Snapshot(200, {"content-type": ("application/xml",)},
                                    self.stored[key])
                return Snapshot(404, {"content-type": ("application/xml",)},
                                b"<Error><Code>NoSuchLifecycleConfiguration</Code></Error>")
        if q0 == "session":
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<CreateSessionResult><Credentials><AccessKeyId>ak"
                            b"</AccessKeyId></Credentials></CreateSessionResult>")
        if q0 == "annotation":
            key = (path, "annotation")
            if method == "PUT":
                self.stored[key] = body
                return Snapshot(200, {}, b"")
            if method == "DELETE":
                self.stored.pop(key, None)
                return Snapshot(204, {}, b"")
            if key in self.stored:
                return Snapshot(200, {"content-type": ("application/xml",)}, self.stored[key])
            return Snapshot(404, {"content-type": ("application/xml",)},
                            b"<Error><Code>NoSuchConfiguration</Code></Error>")
        if q0 == "encryption" and path.count("/") >= 2:
            key = (path, "obj-encryption")
            if method == "PUT":
                self.stored[key] = body
                return Snapshot(200, {}, b"")
            if method == "GET":
                if key in self.stored:
                    return Snapshot(200, {"content-type": ("application/xml",)}, self.stored[key])
                return Snapshot(404, {"content-type": ("application/xml",)},
                                b"<Error><Code>ServerSideEncryptionConfigurationNotFoundError"
                                b"</Code></Error>")
        if method == "POST" and q0 == "select":
            upper = body.upper()
            if b"JOIN" in upper or b" OR " in upper:
                return Snapshot(400, {"content-type": ("application/xml",)},
                                b"<Error><Code>InvalidRequest</Code></Error>")
            if b"SELECT *" in upper or b"SELECT _" in upper:
                return Snapshot(
                    200, {"content-type": ("application/vnd.amazon.eventstream",)},
                    b"\x00\x00\x00\x20eventstream " + OBJECT_BODY + b" red blue",
                )
            return Snapshot(400, {"content-type": ("application/xml",)},
                            b"<Error><Code>InvalidRequest</Code></Error>")
        if method == "GET" and q0 == "torrent":
            return Snapshot(200, {"content-type": ("application/x-bittorrent",)},
                            b"d8:announce0:4:infoe")
        if "x-amz-rename-source" in hdrs:
            return Snapshot(204, {}, b"")
        if method == "PUT" and path.count("/") == 1:
            return Snapshot(200, {}, b"")
        if method == "HEAD" and "/probe.txt" in path:
            return Snapshot(200, {}, b"")
        if method == "HEAD":
            return Snapshot(200, {}, b"")
        if method == "GET" and path.endswith("/probe.txt") and "acl" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<AccessControlPolicy><Owner/></AccessControlPolicy>")
        if method == "GET" and path.endswith("/probe.txt") and "attributes" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<GetObjectAttributesOutput><ETag>x</ETag>"
                            b"<ObjectSize>1</ObjectSize></GetObjectAttributesOutput>")
        if method == "GET" and path.endswith("/probe.txt"):
            payload = OBJECT_BODY[:9] if "range" in {k.lower() for k in headers} else OBJECT_BODY
            return Snapshot(206 if payload != OBJECT_BODY else 200, {}, payload)
        if method == "PUT" and path.endswith("/copy-dst.txt"):
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<CopyObjectResult><ETag>\"x\"</ETag></CopyObjectResult>")
        if method == "PUT" and "uploadId" in query and "partNumber" in query:
            if "x-amz-copy-source" in hdrs:
                return Snapshot(200, {"content-type": ("application/xml",)},
                                b"<CopyPartResult><ETag>\"p\"</ETag></CopyPartResult>")
            return Snapshot(200, {"etag": ('"part1"',)}, b"")
        if method == "GET" and "uploadId" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<ListPartsResult><UploadId>u1</UploadId></ListPartsResult>")
        if method == "GET" and q0 == "uploads":
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<ListMultipartUploadsResult><Uploads/></ListMultipartUploadsResult>")
        if method == "POST" and "uploadId" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<CompleteMultipartUploadResult><ETag>\"x\"</ETag>"
                            b"</CompleteMultipartUploadResult>")
        if method == "GET" and path.endswith("/mpu.bin"):
            return Snapshot(200, {}, OBJECT_BODY)
        if method == "PUT" and "tagging" in query:
            return Snapshot(200, {}, b"")
        if method == "PUT" and "acl" in query:
            return Snapshot(200, {}, b"")
        if method == "PUT" and path.endswith(".txt"):
            return Snapshot(200, {}, b"")
        if method == "POST" and "uploads" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<InitiateMultipartUploadResult><UploadId>u1</UploadId>"
                            b"</InitiateMultipartUploadResult>")
        if method == "DELETE" and "uploadId" in query:
            return Snapshot(204, {}, b"")
        if method == "POST" and "delete" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<DeleteResult/>")
        if method == "POST" and "restore" in query:
            return Snapshot(400, {"content-type": ("application/xml",)},
                            b"<Error><Code>InvalidObjectState</Code></Error>")
        if method == "GET" and any(q.split("=")[0] in UNSUPPORTED_SUBRESOURCES
                                   for q in query.split("&") if q):
            return Snapshot(501, {"content-type": ("application/xml",)},
                            b"<Error><Code>NotImplemented</Code></Error>")
        if method == "GET" and "policyStatus" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<PolicyStatus><IsPublic>false</IsPublic></PolicyStatus>")
        if method == "GET" and "location" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<LocationConstraint>RegionOne</LocationConstraint>")
        if method == "GET" and "versioning" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<VersioningConfiguration/>")
        if method == "PUT" and "versioning" in query:
            return Snapshot(200, {}, b"")
        if method == "GET" and "versions" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<ListVersionsResult/>")
        if method == "GET" and "acl" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<AccessControlPolicy><Owner/></AccessControlPolicy>")
        if method == "GET" and "tagging" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<Tagging><TagSet/></Tagging>")
        if method == "GET" and "cors" in query:
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<CORSConfiguration/>")
        if method == "GET":
            return Snapshot(200, {"content-type": ("application/xml",)},
                            b"<ListBucketResult/>")
        if method == "DELETE":
            return Snapshot(204, {}, b"")
        return Snapshot(200, {}, b"")


def _mock_s3cmd(*args: str) -> Tuple[int, str]:
    if args and args[0] == "get":
        Path(args[-1]).write_bytes(OBJECT_BODY)
    return 0, "OK " + " ".join(args)


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise SelfTestError(message)


def run_selftest() -> int:
    try:
        _selftest_body()
    except (SelfTestError, Exception) as exc:
        print("strict-s3-live-matrix offline self-test: FAIL -- {}".format(exc),
              file=sys.stderr)
        return EXIT_RUNTIME
    print("strict-s3-live-matrix offline self-test: PASS")
    return EXIT_PASS


def _selftest_body() -> None:
    _expect(len(ALL_CASES) == len(set(ALL_CASES)), "duplicate case names")
    _expect("list-buckets" in ALL_CASES, "ListBuckets missing")
    _expect("account-root-put" in ALL_CASES, "account-root PUT missing")
    _expect("create-bucket-slash" in ALL_CASES, "slash create missing")
    _expect("head-bucket-slash" in ALL_CASES, "slash head missing")
    _expect("delete-bucket-slash" in ALL_CASES, "slash delete missing")
    _expect("upload-part-copy" in ALL_CASES, "UploadPartCopy missing")
    _expect("get-bucket-policy-status" in ALL_CASES, "policyStatus missing")
    _expect("get-object-attributes" in ALL_CASES, "GetObjectAttributes missing")
    _expect("put-object-tagging" in ALL_CASES, "PutObjectTagging missing")
    _expect("rename-object" in ALL_CASES, "RenameObject missing")
    _expect("select-star" in ALL_CASES, "SelectObjectContent missing")
    _expect("select-limit" in ALL_CASES, "Select LIMIT missing")
    _expect("select-not-star" in ALL_CASES, "Select projection missing")
    _expect("select-where" in ALL_CASES, "Select WHERE missing")
    _expect("select-unsupported" in ALL_CASES, "Select unsupported 400 missing")
    _expect("get-object-torrent" in ALL_CASES, "GetObjectTorrent missing")
    _expect("write-get-object-response-501" in ALL_CASES, "WGOR 501 missing")
    _expect("put-cfg-abac" in ALL_CASES, "stored abac PUT missing")
    _expect("put-cfg-metadataConfiguration" in ALL_CASES, "stored metadata PUT missing")
    _expect("list-directory-buckets" in ALL_CASES, "ListDirectoryBuckets missing")
    _expect("put-cfg-website" in ALL_CASES, "stored website PUT missing")
    _expect("complete-multipart" in ALL_CASES, "CompleteMultipartUpload missing")
    _expect("upload-part" in ALL_CASES, "UploadPart missing")
    _expect("list-parts" in ALL_CASES, "ListParts missing")
    _expect("list-multipart-uploads" in ALL_CASES, "ListMultipartUploads missing")
    _expect("put-lifecycle" in ALL_CASES, "PutBucketLifecycle missing")
    _expect("head-lifecycle-expiration" in ALL_CASES, "lifecycle expiration missing")
    _expect("get-object-tagging" in ALL_CASES, "GetObjectTagging missing")
    _expect("website-get-index" in ALL_CASES, "website index missing")
    _expect("website-get-error" in ALL_CASES, "website error missing")
    _expect("put-cfg-policy" in ALL_CASES, "stored policy PUT missing")
    _expect("get-unsupported-policy" not in ALL_CASES, "policy must not stay 501")
    for sub in UNSUPPORTED_SUBRESOURCES:
        _expect("get-unsupported-{}".format(sub) in ALL_CASES, "missing " + sub)
        _expect("get-unsupported-{}-slash".format(sub) in ALL_CASES, "missing slash " + sub)
    for query, _kind, _body, _marker, _missing in STORED_BUCKET_CONFIGS:
        _expect("put-cfg-{}".format(query) in ALL_CASES, "missing put " + query)
        _expect("get-cfg-{}-after-delete".format(query) in ALL_CASES,
                "missing after-delete " + query)

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

    _expect(_xml_expected_ok(b"") == "2xx/error XML expected but body empty",
            "empty XML rule missing")
    _expect(_error_code(b"<Error><Code>NotImplemented</Code></Error>") == "NotImplemented",
            "error code parse failed")
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

    stamp = "20260818t000000z"
    buckets = {
        "main": "s3-matrix-{}a".format(stamp),
        "slash": "s3-matrix-{}b".format(stamp),
        "probe": "s3-matrix-{}c".format(stamp),
    }
    target = Target("https://10.0.0.10:8085", "ak", "sk", "RegionOne", _MockClient("ok"))
    runner = Runner(target, buckets, "/usr/bin/s3cmd", None, _mock_s3cmd)
    _run_matrix(runner)
    cleanup_failed = _cleanup(runner)
    report = _build_report(runner, target.endpoint, cleanup_failed,
                           "2026-08-18T00:00:00Z", "2026-08-18T00:00:01Z")
    _expect(report["executed"] == report["required"] == len(ALL_CASES),
            "selftest did not run every declared case")
    _expect(report["failed"] == 0, "happy-path mock had FAILs: {}".format(
        report["fail_names"]))
    _expect(report["cleanup_failed"] == 0, "happy-path cleanup failed")
    _expect(report["gate"] == "PASS", "happy-path gate is not PASS")

    empty_target = Target("https://10.0.0.10:8085", "ak", "sk", "RegionOne",
                          _MockClient("empty-xml"))
    empty_runner = Runner(empty_target, buckets, "/usr/bin/s3cmd", None, _mock_s3cmd)
    empty_runner.run_case("list-buckets", lambda c: empty_runner.expect_2xx_xml(
        c, empty_runner.req(c, "GET", "/"), "ListAllMyBucketsResult"))
    _expect(not empty_runner.results[0].passed, "empty 2xx XML must FAIL")

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


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.selftest:
        return run_selftest()
    try:
        endpoint = _validate_endpoint(args.rust)
        access, secret = _load_creds()
        client = HttpClient(args.timeout, MAX_RESPONSE_BYTES, args.rust_insecure
                            or endpoint.startswith("https://"))
        target = Target(endpoint, access, secret, args.region, client)
        stamp = _utc_stamp()
        buckets = {
            "main": "s3-matrix-{}a".format(stamp),
            "slash": "s3-matrix-{}b".format(stamp),
            "probe": "s3-matrix-{}c".format(stamp),
        }
        for name in buckets.values():
            _bucket_ok(name)
        s3cfg = DEFAULT_S3CFG if Path(DEFAULT_S3CFG).is_file() else None
        runner = Runner(target, buckets, shutil.which("s3cmd"), s3cfg)
        started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            _run_matrix(runner)
        finally:
            cleanup_failed = _cleanup(runner)
        ended = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        report = _build_report(runner, endpoint, cleanup_failed, started, ended)
        _print_digest(report)
        if args.json_report:
            _atomic_new_report(Path(args.json_report), report)
            print("report={}".format(args.json_report))
        if report["gate"] != "PASS":
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
