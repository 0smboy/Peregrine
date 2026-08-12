#!/usr/bin/env python3
"""Strict live S3 parity gate for Python Swift and Peregrine Rust.

This program is intentionally dependency-free.  It signs raw path-style S3
requests with SigV4 and SigV2, runs the same bounded scenario against two
independently configured endpoints, and compares status, body semantics, XML
schema, and operation-critical response headers.  A PASS is impossible unless
every declared case ran and both per-target cleanup paths ended at HTTP 404.

Credentials are read from four *distinctly named* environment variables.  They
are never printed, included in URLs, or written to the report.  Access-key and
secret values may be equal when both deployments intentionally expose the same
TempAuth user, but each target must still be configured independently.

Example (run on a Linux validation host, never on the source-sync Mac):

  export PEREGRINE_S3_PY_ACCESS='test:tester'
  export PEREGRINE_S3_PY_SECRET='...'
  export PEREGRINE_S3_RS_ACCESS='test:tester'
  export PEREGRINE_S3_RS_SECRET='...'
  python3 tools/strict-s3-parity.py \
    --python http://10.0.0.2:8090 \
    --rust http://10.0.0.3:8080 \
    --python-provenance python-swift@<verified-commit> \
    --rust-provenance peregrine@<verified-commit>+sha256:<verified-binary> \
    --json-report /root/evidence/strict-s3-parity.json

Exit codes:
    0  every required case and both final-404 cleanup checks passed
    1  parity, behavior, schema, missing-case, or cleanup failure
    2  unsafe configuration, authentication, report, or transport failure
  130  interrupted; cleanup was still attempted

Covered subset:
  TempAuth S3 path-style API; SigV4 header/query; SigV2 header/query; bucket
  and object CRUD; HEAD/GET/range/copy; ListObjects v1/v2; MultiDelete;
  multipart initiate/upload/list/complete; owner-private ACL reads and bucket
  ACL write; Python-2.33 tagging empty-GET and mutation-501 behavior; Python-
  2.33 CORS subresource 501 behavior; a two-version/delete-marker lifecycle;
  clock-skew and expiry negatives; restore=501; non-STANDARD rejection.

Explicit exclusions (a PASS makes no claim about these):
  Keystone/EC2 s3tokens; virtual-host/TLS-host routing; cross-account ACL/IAM;
  public/bucket-policy authorization; lifecycle execution; object-lock,
  retention and legal-hold; SSE/KMS; aws-chunked streaming; POST policies;
  website/notification/replication/select; pagination beyond this bounded
  namespace; browser CORS enforcement; performance, HA, durability, and daemon
  convergence.  Native Swift API parity is covered by a separate gate.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import signal
import ssl
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import formatdate, parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


EXIT_PASS = 0
EXIT_PARITY_FAILURE = 1
EXIT_RUNTIME_FAILURE = 2
EXIT_INTERRUPTED = 130
REPORT_SCHEMA = "peregrine.strict-s3-parity.v1"
SCOPE_ID = "tempauth-s3-bounded-live-parity"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_XML_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 30.0
SERVICE = "s3"
V4_ALGORITHM = "AWS4-HMAC-SHA256"
NAMESPACE_RE = re.compile(r"^peregrine-s3-[a-z0-9]{8}-[a-f0-9]{16}$")
VERSION_RE = re.compile(r"^[^\x00-\x20\x7f]{1,1024}$")
ETAG_RE = re.compile(r'^"[0-9a-fA-F]{32}(?:-[0-9]+)?"$')
HEX_RE = re.compile(r"^[0-9a-f]+$")
S3_SUBRESOURCES = frozenset(
    {
        "acl", "cors", "delete", "lifecycle", "location", "logging",
        "notification", "partNumber", "policy", "requestPayment",
        "response-cache-control", "response-content-disposition",
        "response-content-encoding", "response-content-language",
        "response-content-type", "response-expires", "restore", "tagging",
        "torrent", "uploadId", "uploads", "versionId", "versioning",
        "versions", "website",
    }
)
EXCLUSIONS = (
    "keystone-ec2-s3tokens",
    "virtual-host-and-tls-host-routing",
    "cross-account-acl-and-iam",
    "bucket-policy-and-public-access",
    "lifecycle-execution",
    "object-lock-retention-legal-hold",
    "sse-kms-and-client-encryption",
    "sigv4-aws-chunked-streaming",
    "browser-cors-enforcement",
    "post-policy-uploads",
    "website-notification-replication-select",
    "unbounded-pagination-and-scale",
    "performance-ha-durability-daemon-convergence",
    "native-swift-api",
)

REQUIRED_CASES = (
    "credential-list-buckets",
    "ownership-gate",
    "create-bucket",
    "head-bucket-sigv2-header",
    "put-object",
    "head-object-sigv2-header",
    "get-object-sigv4-query",
    "range-object-sigv2-query",
    "copy-object",
    "get-copy",
    "list-objects-v1",
    "list-objects-v2",
    "put-bucket-acl-private",
    "get-bucket-acl",
    "get-object-acl",
    "put-object-acl-not-implemented",
    "get-empty-bucket-tagging",
    "get-empty-object-tagging",
    "put-bucket-tagging-not-implemented",
    "delete-object-tagging-not-implemented",
    "get-bucket-cors-not-implemented",
    "put-bucket-cors-not-implemented",
    "delete-bucket-cors-not-implemented",
    "restore-not-implemented",
    "invalid-storage-class",
    "invalid-storage-class-no-object",
    "sigv4-header-clock-skew",
    "sigv4-query-expired",
    "sigv2-header-clock-skew",
    "sigv2-query-expired",
    "multipart-initiate",
    "multipart-upload-part-1",
    "multipart-upload-part-2",
    "multipart-list-parts",
    "multipart-list-uploads",
    "multipart-complete",
    "multipart-get",
    "put-multidelete-a",
    "put-multidelete-b",
    "multi-delete",
    "post-multidelete-list-empty",
    "put-versioning-enabled",
    "get-versioning-enabled",
    "put-version-1",
    "put-version-2",
    "get-version-1",
    "create-delete-marker",
    "get-current-delete-marker",
    "list-object-versions",
    "delete-delete-marker",
    "delete-version-1",
    "delete-version-2",
    "list-object-versions-empty",
    "put-versioning-suspended",
    "get-versioning-suspended",
    "delete-bucket",
    "final-bucket-404",
)


class ConfigError(RuntimeError):
    """The gate cannot run safely with the supplied configuration."""


class TransportError(RuntimeError):
    """A target did not produce a complete bounded HTTP response."""


class SchemaError(ValueError):
    """A response body/header failed its declared schema."""


class ScenarioAbort(RuntimeError):
    """A prerequisite failed and later mutations are unsafe."""


class Interrupted(RuntimeError):
    """SIGINT/SIGTERM requested cleanup and exit 130."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:  # type: ignore[override]
        return None


@dataclass(frozen=True)
class Snapshot:
    status: int
    headers: Mapping[str, Tuple[str, ...]]
    body: bytes

    def first(self, name: str) -> Optional[str]:
        values = self.headers.get(name.lower())
        return values[0] if values else None


@dataclass
class Target:
    label: str
    endpoint: str
    access: str
    secret: str
    region: str
    provenance: str
    client: "HttpClient"
    ownership_clear: bool = False
    creation_attempted: bool = False
    owned: bool = False
    known_objects: Set[str] = field(default_factory=set)
    uploads: Dict[str, str] = field(default_factory=dict)
    versions: Dict[str, str] = field(default_factory=dict)
    etags: Dict[str, str] = field(default_factory=dict)

    @property
    def host(self) -> str:
        return urlsplit(self.endpoint).netloc

    def request(
        self,
        method: str,
        path: str,
        query: Sequence[Tuple[str, str]] = (),
        body: bytes = b"",
        headers: Optional[Mapping[str, str]] = None,
        auth: str = "v4-header",
        signed_at: Optional[int] = None,
        expires: Optional[int] = None,
    ) -> Snapshot:
        request_headers, wire_query = _signed_request(
            method=method,
            path=path,
            query=query,
            body=body,
            headers=headers or {},
            auth=auth,
            access=self.access,
            secret=self.secret,
            region=self.region,
            host=self.host,
            signed_at=int(time.time()) if signed_at is None else signed_at,
            expires=expires,
        )
        url = self.endpoint + path
        if wire_query:
            url += "?" + _wire_query(wire_query)
        return self.client.request(method, url, body, request_headers)


@dataclass
class CaseResult:
    name: str
    expected_status: Tuple[int, ...]
    python: Dict[str, Any]
    rust: Dict[str, Any]
    issues: List[str]

    @property
    def passed(self) -> bool:
        return not self.issues


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
        clean_headers = {
            "Accept-Encoding": "identity",
            "User-Agent": "peregrine-strict-s3-parity/1",
            **headers,
        }
        if body or method in ("PUT", "POST"):
            clean_headers.setdefault("Content-Length", str(len(body)))
        request = Request(url=url, data=body if body or method in ("PUT", "POST") else None,
                          headers=clean_headers, method=method)
        try:
            response = self._opener.open(request, timeout=self._timeout)
        except HTTPError as exc:
            response = exc
        except (URLError, http.client.HTTPException, OSError, TimeoutError) as exc:
            raise TransportError(
                "{} request to {} failed ({})".format(method, _safe_origin(url), type(exc).__name__)
            ) from exc
        try:
            payload = response.read(self._max_bytes + 1)
            if len(payload) > self._max_bytes:
                raise TransportError("{} response from {} exceeded {} bytes".format(
                    method, _safe_origin(url), self._max_bytes))
            normalized: Dict[str, List[str]] = {}
            for name, value in response.headers.raw_items():
                normalized.setdefault(name.strip().lower(), []).append(value.strip())
            return Snapshot(int(response.code),
                            {name: tuple(values) for name, values in normalized.items()}, payload)
        except TransportError:
            raise
        except (http.client.HTTPException, OSError, TimeoutError, ValueError) as exc:
            raise TransportError("{} response from {} failed ({})".format(
                method, _safe_origin(url), type(exc).__name__)) from exc
        finally:
            try:
                response.close()
            except Exception:
                pass


def _safe_origin(url: str) -> str:
    parsed = urlsplit(url)
    return "{}://{}".format(parsed.scheme or "<scheme>", parsed.netloc or "<host>")


def _aws_quote(value: str, safe: str = "-_.~") -> str:
    return quote(value, safe=safe, encoding="utf-8", errors="strict")


def _canonical_query(pairs: Sequence[Tuple[str, str]]) -> str:
    encoded = [(_aws_quote(str(k)), _aws_quote(str(v))) for k, v in pairs
               if k not in ("X-Amz-Signature", "Signature")]
    encoded.sort()
    return "&".join("{}={}".format(k, v) for k, v in encoded)


def _wire_query(pairs: Sequence[Tuple[str, str]]) -> str:
    return "&".join("{}={}".format(_aws_quote(str(k)), _aws_quote(str(v))) for k, v in pairs)


def _normalize_header_value(value: str) -> str:
    return " ".join(value.strip().split())


def _hmac_sha256(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _v4_key(secret: str, stamp: str, region: str) -> bytes:
    key = _hmac_sha256(("AWS4" + secret).encode("utf-8"), stamp)
    key = _hmac_sha256(key, region)
    key = _hmac_sha256(key, SERVICE)
    return _hmac_sha256(key, "aws4_request")


def _canonical_resource(path: str, query: Sequence[Tuple[str, str]]) -> str:
    selected = sorted(((k, v) for k, v in query if k in S3_SUBRESOURCES),
                      key=lambda item: item[0].lower())
    if not selected:
        return path
    return path + "?" + "&".join(k if v == "" else "{}={}".format(k, v)
                                  for k, v in selected)


def _signed_request(
    *, method: str, path: str, query: Sequence[Tuple[str, str]], body: bytes,
    headers: Mapping[str, str], auth: str, access: str, secret: str,
    region: str, host: str, signed_at: int, expires: Optional[int],
) -> Tuple[Dict[str, str], List[Tuple[str, str]]]:
    if not path.startswith("/") or "?" in path or "#" in path:
        raise ConfigError("internal request path is not canonical")
    method = method.upper()
    out = {str(k): str(v) for k, v in headers.items()}
    out["Host"] = host
    q = [(str(k), str(v)) for k, v in query]
    when = datetime.fromtimestamp(signed_at, tz=timezone.utc)

    if auth in ("v4-header", "v4-query"):
        amz_date = when.strftime("%Y%m%dT%H%M%SZ")
        stamp = when.strftime("%Y%m%d")
        scope = "{}/{}/{}/aws4_request".format(stamp, region, SERVICE)
        payload_hash = hashlib.sha256(body).hexdigest()
        if auth == "v4-header":
            out["X-Amz-Date"] = amz_date
            out["X-Amz-Content-SHA256"] = payload_hash
        else:
            if expires is None or expires < 1 or expires > 604800:
                raise ConfigError("SigV4 query expires must be in 1..604800")
            payload_hash = "UNSIGNED-PAYLOAD"

        signed_names = sorted({name.lower() for name in out
                               if name.lower() == "host"
                               or name.lower().startswith("x-amz-")
                               or name.lower() in ("content-md5", "content-type", "range")})
        lower = {name.lower(): _normalize_header_value(value) for name, value in out.items()}
        canonical_headers = "".join("{}:{}\n".format(name, lower[name]) for name in signed_names)
        signed_headers = ";".join(signed_names)
        if auth == "v4-query":
            q.extend([
                ("X-Amz-Algorithm", V4_ALGORITHM),
                ("X-Amz-Credential", "{}/{}".format(access, scope)),
                ("X-Amz-Date", amz_date),
                ("X-Amz-Expires", str(expires)),
                ("X-Amz-SignedHeaders", signed_headers),
            ])
        canonical_request = "{}\n{}\n{}\n{}\n{}\n{}".format(
            method, _aws_quote(path, safe="/-_.~"), _canonical_query(q),
            canonical_headers, signed_headers, payload_hash)
        string_to_sign = "{}\n{}\n{}\n{}".format(
            V4_ALGORITHM, amz_date, scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest())
        signature = hmac.new(_v4_key(secret, stamp, region),
                             string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        if auth == "v4-header":
            out["Authorization"] = (
                "{} Credential={}/{}, SignedHeaders={}, Signature={}".format(
                    V4_ALGORITHM, access, scope, signed_headers, signature))
        else:
            q.append(("X-Amz-Signature", signature))
        return out, q

    if auth not in ("v2-header", "v2-query"):
        raise ConfigError("unknown auth mode")
    if auth == "v2-header":
        out.setdefault("Date", formatdate(signed_at, usegmt=True))
        date_slot = "" if any(name.lower() == "x-amz-date" for name in out) else out["Date"]
    else:
        if expires is None:
            raise ConfigError("SigV2 query auth requires absolute Expires")
        date_slot = str(expires)
    lower = {name.lower(): _normalize_header_value(value) for name, value in out.items()}
    amz_headers = "".join("{}:{}\n".format(name, lower[name])
                          for name in sorted(lower) if name.startswith("x-amz-"))
    string_to_sign = "{}\n{}\n{}\n{}\n{}{}".format(
        method, lower.get("content-md5", ""), lower.get("content-type", ""),
        date_slot, amz_headers, _canonical_resource(path, q))
    signature = base64.b64encode(hmac.new(secret.encode("utf-8"),
                                          string_to_sign.encode("utf-8"),
                                          hashlib.sha1).digest()).decode("ascii")
    if auth == "v2-header":
        out["Authorization"] = "AWS {}:{}".format(access, signature)
    else:
        q.extend([("AWSAccessKeyId", access), ("Expires", str(expires)),
                  ("Signature", signature)])
    return out, q


def _path(bucket: Optional[str] = None, key: Optional[str] = None) -> str:
    value = "/"
    if bucket is not None:
        value += _aws_quote(bucket)
    if key is not None:
        value += "/" + _aws_quote(key, safe="-_.~/")
    return value


def _md5(payload: bytes) -> str:
    return hashlib.md5(payload, usedforsecurity=False).hexdigest()


def _md5_etag(payload: bytes) -> str:
    return '"{}"'.format(_md5(payload))


def _xml(payload: bytes, expected_root: str) -> ET.Element:
    if not payload or len(payload) > MAX_XML_BYTES:
        raise SchemaError("XML body is empty or oversized")
    upper = payload.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise SchemaError("XML DTD/entity declarations are forbidden")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise SchemaError("invalid XML") from exc
    if _tag(root) != expected_root:
        raise SchemaError("XML root {} != {}".format(_tag(root), expected_root))
    _validate_xml_attributes(root)
    return root


def _tag(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _validate_xml_attributes(root: ET.Element) -> None:
    for element in root.iter():
        if not element.attrib:
            continue
        attrs = {name.rsplit("}", 1)[-1]: value for name, value in element.attrib.items()}
        if (_tag(element) == "Grantee" and set(attrs) == {"type"}
                and attrs["type"] in ("CanonicalUser", "Group", "AmazonCustomerByEmail")):
            continue
        raise SchemaError("{} has unsupported XML attributes".format(_tag(element)))


def _children(element: ET.Element, allowed: Iterable[str]) -> List[ET.Element]:
    allowed_set = set(allowed)
    result = list(element)
    unknown = sorted({_tag(child) for child in result if _tag(child) not in allowed_set})
    if unknown:
        raise SchemaError("{} has unknown children {}".format(_tag(element), unknown))
    return result


def _one(element: ET.Element, name: str, required: bool = True) -> Optional[ET.Element]:
    matches = [child for child in list(element) if _tag(child) == name]
    if len(matches) > 1 or (required and len(matches) != 1):
        raise SchemaError("{} requires {} occurrence(s) of {}".format(
            _tag(element), 1 if required else "at most one", name))
    return matches[0] if matches else None


def _text(element: ET.Element, name: str, required: bool = True) -> Optional[str]:
    child = _one(element, name, required)
    if child is None:
        return None
    if list(child) or child.attrib:
        raise SchemaError("{} must be text-only".format(name))
    value = child.text or ""
    if required and value == "":
        raise SchemaError("{} must be non-empty".format(name))
    return value


def _bool_text(value: str) -> bool:
    if value not in ("true", "false"):
        raise SchemaError("boolean must be true or false")
    return value == "true"


def _uint(value: str, label: str) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise SchemaError("{} must be an unsigned decimal".format(label))
    return int(value)


def _iso_time(value: str) -> str:
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise SchemaError("invalid ISO timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        parsed = parsed.astimezone(timezone.utc)
    return "<timestamp>"


def _http_time(value: str) -> str:
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError) as exc:
        raise SchemaError("invalid HTTP date") from exc
    if parsed.tzinfo is None:
        raise SchemaError("HTTP date lacks timezone")
    return "<http-date>"


def _etag(value: str, expected: Optional[str] = None) -> str:
    if not ETAG_RE.fullmatch(value):
        raise SchemaError("invalid ETag")
    normalized = value.lower()
    if expected is not None and normalized != expected.lower():
        raise SchemaError("ETag does not match expected payload")
    return normalized


def _version(target: Target, value: str, label: Optional[str] = None) -> str:
    if not VERSION_RE.fullmatch(value) or value == "null":
        raise SchemaError("invalid non-null version ID")
    if label is not None:
        existing = target.versions.get(label)
        if existing is not None and existing != value:
            raise SchemaError("version ID changed for {}".format(label))
        target.versions[label] = value
        return "<{}>".format(label)
    for known_label, known in target.versions.items():
        if known == value:
            return "<{}>".format(known_label)
    raise SchemaError("response referenced an unknown version ID")


def _principal(element: ET.Element, target: Target) -> Dict[str, Any]:
    _children(element, ("ID", "DisplayName"))
    ident = _text(element, "ID")
    display = _text(element, "DisplayName", False)
    if ident is None:
        raise SchemaError("principal ID is missing")
    if len(ident) > 1024 or any(ord(ch) < 33 or ord(ch) == 127 for ch in ident):
        raise SchemaError("invalid principal ID")
    return {"id": "<principal>", "display": bool(display)}


def _normalize_error(payload: bytes, expected_code: str) -> Dict[str, Any]:
    root = _xml(payload, "Error")
    allowed = ("Code", "Message", "Resource", "RequestId", "HostId", "Endpoint",
               "BucketName", "Key", "ArgumentName", "ArgumentValue")
    _children(root, allowed)
    code = _text(root, "Code")
    message = _text(root, "Message")
    if code != expected_code:
        raise SchemaError("S3 error code {} != {}".format(code, expected_code))
    normalized: Dict[str, Any] = {"Code": code, "Message": message}
    for name in allowed[2:]:
        value = _text(root, name, False)
        if value is not None:
            if len(value) > 2048 or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
                raise SchemaError("invalid {} field".format(name))
            normalized[name] = "<dynamic-id>" if name in ("RequestId", "HostId") else value
    return normalized


def _normalize_list_buckets(payload: bytes, bucket: str, expected_present: bool,
                            target: Target) -> Dict[str, Any]:
    root = _xml(payload, "ListAllMyBucketsResult")
    _children(root, ("Owner", "Buckets"))
    owner = _one(root, "Owner")
    buckets = _one(root, "Buckets")
    if owner is None or buckets is None:
        raise SchemaError("ListBuckets lacks Owner or Buckets")
    _principal(owner, target)
    names: List[str] = []
    for item in _children(buckets, ("Bucket",)):
        _children(item, ("Name", "CreationDate"))
        name = _text(item, "Name")
        created = _text(item, "CreationDate")
        if name is None or created is None:
            raise SchemaError("Bucket entry lacks name or creation date")
        _iso_time(created)
        names.append(name)
    if len(names) != len(set(names)):
        raise SchemaError("ListBuckets contains duplicate names")
    if (bucket in names) != expected_present:
        raise SchemaError("owned bucket presence does not match expectation")
    return {"owned_bucket_present": expected_present}


def _normalize_listing(payload: bytes, bucket: str,
                       expected: Mapping[str, Tuple[int, str]],
                       v2: bool, target: Target) -> Dict[str, Any]:
    root = _xml(payload, "ListBucketResult")
    allowed = ("Name", "Prefix", "Marker", "NextMarker", "MaxKeys", "Delimiter",
               "IsTruncated", "Contents", "CommonPrefixes", "EncodingType",
               "ContinuationToken", "NextContinuationToken", "StartAfter", "KeyCount")
    _children(root, allowed)
    name = _text(root, "Name")
    if name != bucket:
        raise SchemaError("listing bucket name differs from oracle")
    truncated = _text(root, "IsTruncated")
    if truncated is None:
        raise SchemaError("listing lacks IsTruncated")
    if _bool_text(truncated):
        raise SchemaError("bounded listing unexpectedly truncated")
    max_keys = _text(root, "MaxKeys")
    if max_keys is not None:
        _uint(max_keys, "MaxKeys")
    if v2:
        key_count = _text(root, "KeyCount")
        if key_count is not None:
            if _uint(key_count, "KeyCount") != len(expected):
                raise SchemaError("KeyCount differs from oracle")
    actual: Dict[str, Tuple[int, str]] = {}
    if any(_tag(child) == "CommonPrefixes" for child in list(root)):
        raise SchemaError("non-delimited listing unexpectedly returned CommonPrefixes")
    for item in [child for child in list(root) if _tag(child) == "Contents"]:
        _children(item, ("Key", "LastModified", "ETag", "Size", "StorageClass", "Owner"))
        key = _text(item, "Key")
        modified = _text(item, "LastModified")
        etag = _text(item, "ETag")
        size = _text(item, "Size")
        storage = _text(item, "StorageClass", False)
        if key is None or modified is None or etag is None or size is None:
            raise SchemaError("Contents entry lacks a required field")
        _iso_time(modified)
        if storage is not None and storage != "STANDARD":
            raise SchemaError("unexpected StorageClass")
        owner = _one(item, "Owner", False)
        if owner is not None:
            _principal(owner, target)
        if key in actual:
            raise SchemaError("duplicate listing key")
        actual[key] = (_uint(size, "Size"), _etag(etag))
    normalized_expected = {key: (size, etag.lower()) for key, (size, etag) in expected.items()}
    if actual != normalized_expected:
        raise SchemaError("listing contents differ from the owned namespace oracle")
    return {"version": 2 if v2 else 1,
            "objects": [{"key": k, "size": v[0], "etag": v[1]}
                        for k, v in sorted(actual.items())]}


def _normalize_acl(payload: bytes, target: Target) -> Dict[str, Any]:
    root = _xml(payload, "AccessControlPolicy")
    _children(root, ("Owner", "AccessControlList"))
    owner = _one(root, "Owner")
    acl = _one(root, "AccessControlList")
    if owner is None or acl is None:
        raise SchemaError("ACL lacks Owner or AccessControlList")
    owner_id = _text(owner, "ID")
    _principal(owner, target)
    grants = _children(acl, ("Grant",))
    normalized: List[Tuple[str, str]] = []
    for grant in grants:
        _children(grant, ("Grantee", "Permission"))
        grantee = _one(grant, "Grantee")
        permission = _text(grant, "Permission")
        if grantee is None or permission is None:
            raise SchemaError("ACL grant lacks grantee or permission")
        _children(grantee, ("ID", "DisplayName", "URI", "EmailAddress"))
        gid = _text(grantee, "ID", False)
        uri = _text(grantee, "URI", False)
        email = _text(grantee, "EmailAddress", False)
        if sum(value is not None for value in (gid, uri, email)) != 1:
            raise SchemaError("ACL grantee must have exactly one identity")
        if gid is not None:
            kind = "OWNER" if gid == owner_id else "CANONICAL_OTHER"
        elif uri is not None:
            kind = "GROUP:" + uri
        else:
            kind = "EMAIL"
        normalized.append((kind, permission))
    normalized.sort()
    if normalized != [("OWNER", "FULL_CONTROL")]:
        raise SchemaError("private ACL is not exactly owner FULL_CONTROL")
    return {"grants": normalized}


def _normalize_tagging(payload: bytes, expected: Mapping[str, str]) -> Dict[str, Any]:
    root = _xml(payload, "Tagging")
    _children(root, ("TagSet",))
    tagset = _one(root, "TagSet")
    if tagset is None:
        raise SchemaError("Tagging lacks TagSet")
    actual: Dict[str, str] = {}
    for tag in _children(tagset, ("Tag",)):
        _children(tag, ("Key", "Value"))
        key = _text(tag, "Key")
        value = _text(tag, "Value", False)
        if key is None or value is None:
            raise SchemaError("Tag lacks key or value")
        if key in actual:
            raise SchemaError("duplicate tag key")
        actual[key] = value
    if actual != dict(expected):
        raise SchemaError("tag set differs from oracle")
    return {"tags": sorted(actual.items())}


def _normalize_cors(payload: bytes) -> Dict[str, Any]:
    root = _xml(payload, "CORSConfiguration")
    _children(root, ("CORSRule",))
    rules: List[Dict[str, Any]] = []
    for rule in list(root):
        _children(rule, ("ID", "AllowedOrigin", "AllowedMethod", "AllowedHeader",
                         "ExposeHeader", "MaxAgeSeconds"))
        if _one(rule, "ID", False) is not None:
            raise SchemaError("unexpected CORS rule ID")
        origins = [_text_node(x, "AllowedOrigin") for x in list(rule) if _tag(x) == "AllowedOrigin"]
        methods = [_text_node(x, "AllowedMethod") for x in list(rule) if _tag(x) == "AllowedMethod"]
        headers = [_text_node(x, "AllowedHeader") for x in list(rule) if _tag(x) == "AllowedHeader"]
        expose = [_text_node(x, "ExposeHeader") for x in list(rule) if _tag(x) == "ExposeHeader"]
        age = _text(rule, "MaxAgeSeconds", False)
        if not origins or not methods:
            raise SchemaError("CORS rule lacks origin or method")
        rules.append({"origins": sorted(origins), "methods": sorted(methods),
                      "headers": sorted(headers), "expose": sorted(expose),
                      "max_age": _uint(age, "MaxAgeSeconds") if age is not None else None})
    expected = [{"origins": ["https://parity.invalid"], "methods": ["GET"],
                 "headers": ["x-parity"], "expose": ["ETag"], "max_age": 60}]
    if rules != expected:
        raise SchemaError("CORS configuration differs from oracle")
    return {"rules": rules}


def _text_node(element: ET.Element, label: str) -> str:
    if list(element) or element.attrib or element.text is None or element.text == "":
        raise SchemaError("{} must be non-empty text-only".format(label))
    return element.text


def _normalize_copy(payload: bytes, expected_etag: str) -> Dict[str, Any]:
    root = _xml(payload, "CopyObjectResult")
    _children(root, ("LastModified", "ETag"))
    modified = _text(root, "LastModified")
    etag = _text(root, "ETag")
    if modified is None or etag is None:
        raise SchemaError("CopyObjectResult lacks required fields")
    _iso_time(modified)
    return {"last_modified": "<timestamp>", "etag": _etag(etag, expected_etag)}


def _normalize_delete_result(payload: bytes, expected_keys: Set[str]) -> Dict[str, Any]:
    root = _xml(payload, "DeleteResult")
    _children(root, ("Deleted", "Error"))
    deleted: Set[str] = set()
    errors: List[Dict[str, str]] = []
    for child in list(root):
        if _tag(child) == "Deleted":
            _children(child, ("Key", "VersionId", "DeleteMarker", "DeleteMarkerVersionId"))
            key = _text(child, "Key")
            if key is None:
                raise SchemaError("Deleted entry lacks key")
            if key in deleted:
                raise SchemaError("duplicate Deleted key")
            deleted.add(key)
        else:
            _children(child, ("Key", "VersionId", "Code", "Message"))
            errors.append({name: _text(child, name, False) or ""
                           for name in ("Key", "VersionId", "Code", "Message")})
    if errors or deleted != expected_keys:
        raise SchemaError("MultiDelete result differs from oracle")
    return {"deleted": sorted(deleted), "errors": []}


def _normalize_mpu_init(payload: bytes, target: Target, bucket: str,
                        key: str) -> Dict[str, Any]:
    root = _xml(payload, "InitiateMultipartUploadResult")
    _children(root, ("Bucket", "Key", "UploadId"))
    actual_bucket = _text(root, "Bucket")
    actual_key = _text(root, "Key")
    upload = _text(root, "UploadId")
    if actual_bucket is None or actual_key is None or upload is None:
        raise SchemaError("multipart init lacks a required identity field")
    if actual_bucket != bucket or actual_key != key or not VERSION_RE.fullmatch(upload):
        raise SchemaError("multipart init identity is invalid")
    target.uploads[key] = upload
    return {"bucket": "<owned-bucket>", "key": key, "upload_id": "<upload-id>"}


def _normalize_list_parts(payload: bytes, target: Target, bucket: str, key: str,
                          expected: Sequence[Tuple[int, int, str]]) -> Dict[str, Any]:
    root = _xml(payload, "ListPartsResult")
    allowed = ("Bucket", "Key", "UploadId", "Initiator", "Owner", "StorageClass",
               "PartNumberMarker", "NextPartNumberMarker", "MaxParts", "IsTruncated", "Part")
    _children(root, allowed)
    if (_text(root, "Bucket") != bucket or _text(root, "Key") != key
            or _text(root, "UploadId") != target.uploads.get(key)):
        raise SchemaError("ListParts references wrong upload")
    for principal_name in ("Initiator", "Owner"):
        principal = _one(root, principal_name, False)
        if principal is not None:
            _principal(principal, target)
    truncated = _text(root, "IsTruncated")
    if truncated is not None and _bool_text(truncated):
        raise SchemaError("ListParts unexpectedly truncated")
    parts: List[Tuple[int, int, str]] = []
    for part in [child for child in list(root) if _tag(child) == "Part"]:
        _children(part, ("PartNumber", "LastModified", "ETag", "Size"))
        number = _text(part, "PartNumber")
        modified = _text(part, "LastModified")
        etag = _text(part, "ETag")
        size = _text(part, "Size")
        if None in (number, modified, etag, size):
            raise SchemaError("multipart part lacks a required field")
        _iso_time(str(modified))
        parts.append((_uint(str(number), "PartNumber"), _uint(str(size), "Size"), _etag(str(etag))))
    normalized_expected = [(n, size, etag.lower()) for n, size, etag in expected]
    if parts != normalized_expected:
        raise SchemaError("ListParts differs from oracle")
    return {"parts": parts}


def _normalize_list_uploads(payload: bytes, target: Target, bucket: str,
                            key: str) -> Dict[str, Any]:
    root = _xml(payload, "ListMultipartUploadsResult")
    allowed = ("Bucket", "KeyMarker", "UploadIdMarker", "NextKeyMarker",
               "NextUploadIdMarker", "Delimiter", "Prefix", "EncodingType",
               "MaxUploads", "IsTruncated", "Upload", "CommonPrefixes")
    _children(root, allowed)
    if _text(root, "Bucket") != bucket:
        raise SchemaError("ListMultipartUploads references wrong bucket")
    truncated = _text(root, "IsTruncated")
    if truncated is not None and _bool_text(truncated):
        raise SchemaError("ListMultipartUploads unexpectedly truncated")
    uploads = [child for child in list(root) if _tag(child) == "Upload"]
    found: List[str] = []
    for upload in uploads:
        _children(upload, ("Key", "UploadId", "Initiator", "Owner", "StorageClass", "Initiated"))
        ukey = _text(upload, "Key")
        uid = _text(upload, "UploadId")
        initiated = _text(upload, "Initiated")
        if ukey is None or uid is None or initiated is None:
            raise SchemaError("multipart upload entry lacks a required field")
        _iso_time(initiated)
        if ukey != key or uid != target.uploads.get(key):
            raise SchemaError("unexpected multipart upload in owned namespace")
        found.append(key)
    if found != [key]:
        raise SchemaError("owned multipart upload missing or duplicated")
    return {"owned_uploads": found}


def _normalize_mpu_complete(payload: bytes, bucket: str, key: str,
                            expected_etag: str) -> Dict[str, Any]:
    root = _xml(payload, "CompleteMultipartUploadResult")
    _children(root, ("Location", "Bucket", "Key", "ETag"))
    location = _text(root, "Location")
    actual_bucket = _text(root, "Bucket")
    actual_key = _text(root, "Key")
    etag = _text(root, "ETag")
    if None in (location, actual_bucket, actual_key, etag):
        raise SchemaError("multipart complete result lacks a required field")
    location_text = str(location)
    parsed = urlsplit(location_text)
    if parsed.scheme:
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise SchemaError("multipart Location is not an HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise SchemaError("multipart Location URL is unsafe")
        location_path = parsed.path
    else:
        location_path = location_text
    expected_path = _path(bucket, key)
    if actual_bucket != bucket or actual_key != key or location_path != expected_path:
        raise SchemaError("multipart complete identity differs")
    return {"location": "<target-location>", "bucket": "<owned-bucket>",
            "key": key, "etag": _etag(str(etag), expected_etag)}


def _normalize_versioning(payload: bytes, expected: str) -> Dict[str, Any]:
    root = _xml(payload, "VersioningConfiguration")
    _children(root, ("Status", "MfaDelete"))
    status = _text(root, "Status")
    if status != expected:
        raise SchemaError("versioning status differs from oracle")
    mfa = _text(root, "MfaDelete", False)
    if mfa is not None and mfa not in ("Enabled", "Disabled"):
        raise SchemaError("invalid MfaDelete")
    return {"status": status, "mfa_delete": mfa}


def _normalize_list_versions(
    payload: bytes,
    target: Target,
    bucket: str,
    key: str,
    expected: Mapping[str, Tuple[str, int, Optional[str], bool]],
) -> Dict[str, Any]:
    root = _xml(payload, "ListVersionsResult")
    allowed = ("Name", "Prefix", "KeyMarker", "VersionIdMarker", "NextKeyMarker",
               "NextVersionIdMarker", "MaxKeys", "Delimiter", "IsTruncated",
               "EncodingType", "Version", "DeleteMarker", "CommonPrefixes")
    _children(root, allowed)
    if _text(root, "Name") != bucket:
        raise SchemaError("ListVersions references wrong bucket")
    truncated = _text(root, "IsTruncated")
    if truncated is not None and _bool_text(truncated):
        raise SchemaError("ListVersions unexpectedly truncated")
    entries: List[Tuple[str, str, int, Optional[str], bool]] = []
    for item in [child for child in list(root) if _tag(child) in ("Version", "DeleteMarker")]:
        kind = _tag(item)
        permitted = ("Key", "VersionId", "IsLatest", "LastModified", "Owner",
                     "ETag", "Size", "StorageClass")
        _children(item, permitted)
        actual_key = _text(item, "Key")
        version_id = _text(item, "VersionId")
        latest = _text(item, "IsLatest")
        modified = _text(item, "LastModified")
        if None in (actual_key, version_id, latest, modified):
            raise SchemaError("version entry lacks a required field")
        if actual_key != key:
            raise SchemaError("unexpected key in version listing")
        _iso_time(str(modified))
        mapped = _version(target, str(version_id))
        label = mapped[1:-1]
        is_latest = _bool_text(str(latest))
        owner = _one(item, "Owner", False)
        if owner is not None:
            _principal(owner, target)
        if kind == "Version":
            etag = _text(item, "ETag")
            size = _text(item, "Size")
            if etag is None or size is None:
                raise SchemaError("version entry lacks ETag or Size")
            normalized_etag: Optional[str] = _etag(etag)
            normalized_size = _uint(size, "Size")
        else:
            if _one(item, "ETag", False) is not None or _one(item, "Size", False) is not None:
                raise SchemaError("delete marker carries object data fields")
            normalized_etag = None
            normalized_size = 0
        entries.append((kind, label, normalized_size, normalized_etag, is_latest))
    actual = {label: (kind, size, etag, latest)
              for kind, label, size, etag, latest in entries}
    normalized_expected = {
        label: (kind, size, etag.lower() if etag is not None else None, latest)
        for label, (kind, size, etag, latest) in expected.items()
    }
    if actual != normalized_expected or len(entries) != len(expected):
        raise SchemaError("version listing differs from oracle")
    if entries and sum(1 for _, _, _, _, latest in entries if latest) != 1:
        raise SchemaError("version listing must have exactly one latest entry")
    return {"entries": sorted(entries)}


def _normalize_list_versions_empty(payload: bytes, bucket: str) -> Dict[str, Any]:
    root = _xml(payload, "ListVersionsResult")
    _children(root, ("Name", "Prefix", "KeyMarker", "VersionIdMarker", "NextKeyMarker",
                     "NextVersionIdMarker", "MaxKeys", "Delimiter", "IsTruncated",
                     "EncodingType", "Version", "DeleteMarker", "CommonPrefixes"))
    if _text(root, "Name") != bucket:
        raise SchemaError("empty ListVersions references wrong bucket")
    if any(_tag(child) in ("Version", "DeleteMarker") for child in list(root)):
        raise SchemaError("version listing is not empty")
    truncated = _text(root, "IsTruncated")
    if truncated is not None and _bool_text(truncated):
        raise SchemaError("empty version listing unexpectedly truncated")
    return {"entries": []}


HeaderRule = Tuple[str, Optional[str]]
BodyNormalizer = Callable[[Snapshot, Target], Any]


def _single_header(snapshot: Snapshot, name: str) -> str:
    values = snapshot.headers.get(name.lower())
    if values is None or len(values) != 1 or values[0] == "":
        raise SchemaError("missing or repeated response header {}".format(name.lower()))
    return values[0]


def _media_type(value: str) -> str:
    parts = [part.strip() for part in value.split(";")]
    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+",
                        parts[0]):
        raise SchemaError("invalid Content-Type")
    params: Dict[str, str] = {}
    for raw in parts[1:]:
        if "=" not in raw:
            raise SchemaError("invalid Content-Type parameter")
        key, value = raw.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if not key or not value or key in params:
            raise SchemaError("invalid Content-Type parameter")
        params[key] = value
    return parts[0].lower() + "".join(";{}={}".format(k, params[k]) for k in sorted(params))


def _normalize_headers(snapshot: Snapshot, target: Target,
                       rules: Mapping[str, HeaderRule]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    for header, (mode, argument) in rules.items():
        value = _single_header(snapshot, header)
        key = header.lower()
        if mode == "exact":
            if argument is not None and value != argument:
                raise SchemaError("{} differs from expected value".format(key))
            normalized[key] = value
        elif mode == "uint":
            number = _uint(value, key)
            if argument is not None and number != int(argument):
                raise SchemaError("{} differs from expected integer".format(key))
            normalized[key] = number
        elif mode == "media":
            normalized[key] = _media_type(value)
        elif mode == "etag":
            normalized[key] = _etag(value, argument)
        elif mode == "http-date":
            normalized[key] = _http_time(value)
        elif mode == "capture-version":
            if argument is None:
                raise SchemaError("capture-version rule lacks label")
            normalized[key] = _version(target, value, argument)
        elif mode == "known-version":
            if argument is None or target.versions.get(argument) != value:
                raise SchemaError("{} is not the known {}".format(key, argument))
            normalized[key] = "<{}>".format(argument)
        elif mode == "bool":
            if value.lower() not in ("true", "false"):
                raise SchemaError("{} is not boolean".format(key))
            if argument is not None and value.lower() != argument.lower():
                raise SchemaError("{} differs from expected boolean".format(key))
            normalized[key] = value.lower()
        else:
            raise SchemaError("unknown response-header rule")
    return normalized


def _empty_body(snapshot: Snapshot, _target: Target) -> Dict[str, Any]:
    if snapshot.body != b"":
        raise SchemaError("response body must be empty")
    return {"kind": "empty"}


def _raw_body(expected: bytes) -> BodyNormalizer:
    def normalize(snapshot: Snapshot, _target: Target) -> Dict[str, Any]:
        if snapshot.body != expected:
            raise SchemaError("response bytes differ from fixed oracle")
        return {"kind": "bytes", "length": len(expected),
                "sha256": hashlib.sha256(expected).hexdigest()}
    return normalize


def _error_body(code: str) -> BodyNormalizer:
    return lambda snapshot, _target: _normalize_error(snapshot.body, code)


def _public_snapshot(snapshot: Snapshot, normalized_headers: Mapping[str, Any],
                     normalized_body: Any) -> Dict[str, Any]:
    return {
        "status": snapshot.status,
        "headers": dict(normalized_headers),
        "body": normalized_body,
        "body_length": len(snapshot.body),
        "body_sha256": hashlib.sha256(snapshot.body).hexdigest(),
    }


class Runner:
    def __init__(self, namespace: str, python: Target, rust: Target) -> None:
        self.namespace = namespace
        self.python = python
        self.rust = rust
        self.results: List[CaseResult] = []
        self.cleanup: Dict[str, Dict[str, Any]] = {}
        self.fatal: Optional[str] = None
        self.abort_reason: Optional[str] = None

    def run(
        self,
        name: str,
        operation: Callable[[Target], Snapshot],
        expected_status: Iterable[int],
        body: BodyNormalizer,
        headers: Optional[Mapping[str, HeaderRule]] = None,
    ) -> bool:
        if name not in REQUIRED_CASES:
            raise ConfigError("undeclared case {}".format(name))
        if any(result.name == name for result in self.results):
            raise ConfigError("duplicate case {}".format(name))
        expected = tuple(sorted(set(expected_status)))
        snapshots: Dict[str, Snapshot] = {}
        for target in (self.python, self.rust):
            snapshots[target.label] = operation(target)
        issues: List[str] = []
        py = snapshots["python"]
        rs = snapshots["rust"]
        if py.status != rs.status:
            issues.append("status mismatch python={} rust={}".format(py.status, rs.status))
        for label, snapshot in (("python", py), ("rust", rs)):
            if snapshot.status not in expected:
                issues.append("{} status {} not in {}".format(label, snapshot.status, expected))

        normalized_headers: Dict[str, Dict[str, Any]] = {}
        normalized_bodies: Dict[str, Any] = {}
        rules = headers or {}
        for target, snapshot in ((self.python, py), (self.rust, rs)):
            try:
                normalized_headers[target.label] = _normalize_headers(snapshot, target, rules)
            except SchemaError as exc:
                issues.append("{} header schema: {}".format(target.label, exc))
                normalized_headers[target.label] = {"schema_error": str(exc)}
            try:
                normalized_bodies[target.label] = body(snapshot, target)
            except SchemaError as exc:
                issues.append("{} body schema: {}".format(target.label, exc))
                normalized_bodies[target.label] = {"schema_error": str(exc)}

        if normalized_headers.get("python") != normalized_headers.get("rust"):
            issues.append("critical response headers differ after schema normalization")
        if normalized_bodies.get("python") != normalized_bodies.get("rust"):
            issues.append("response bodies differ after schema normalization")

        result = CaseResult(
            name=name,
            expected_status=expected,
            python=_public_snapshot(py, normalized_headers["python"], normalized_bodies["python"]),
            rust=_public_snapshot(rs, normalized_headers["rust"], normalized_bodies["rust"]),
            issues=issues,
        )
        self.results.append(result)
        if result.passed:
            print("PASS {:<42} python={} rust={}".format(name, py.status, rs.status))
        else:
            print("FAIL {:<42} python={} rust={} issues={}".format(
                name, py.status, rs.status, len(issues)))
            for issue in issues:
                print("     " + issue)
        return result.passed

    def require(self, passed: bool, reason: str) -> None:
        if not passed:
            raise ScenarioAbort(reason)

    def report(self, exit_code: int) -> Dict[str, Any]:
        names = [result.name for result in self.results]
        missing = [name for name in REQUIRED_CASES if name not in names]
        failed = sum(1 for result in self.results if not result.passed)
        cleanup_failed = sum(1 for value in self.cleanup.values() if not value.get("passed"))
        gate = _gate(exit_code)
        return {
            "schema": REPORT_SCHEMA,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scope": {
                "id": SCOPE_ID,
                "claim": "BOUNDED_IMPLEMENTED_SUBSET_ONLY",
                "required_cases": list(REQUIRED_CASES),
                "excludes": list(EXCLUSIONS),
                "dynamic_normalization": {
                    "timestamps": "syntax-validated-then-placeholder",
                    "request_ids": "bounded-printable-then-placeholder",
                    "principal_ids": "schema-and-owner-relation-validated",
                    "upload_and_version_ids": "target-bound-and-stability-validated",
                    "multipart_location": "safe-http-or-absolute-path-and-owned-path-validated",
                },
            },
            "namespace": self.namespace,
            "targets": {
                target.label: {
                    "endpoint": target.endpoint,
                    "region": target.region,
                    "provenance": target.provenance,
                    "credential_source": "independent-environment-variable",
                } for target in (self.python, self.rust)
            },
            "summary": {
                "required_cases": len(REQUIRED_CASES),
                "executed_cases": len(self.results),
                "passed": len(self.results) - failed,
                "failed": failed,
                "missing": len(missing),
                "skipped": 0,
                "cleanup_failed": cleanup_failed,
                "gate": gate,
            },
            "result": {"exit_code": exit_code, "gate": gate},
            "fatal": self.fatal,
            "abort_reason": self.abort_reason,
            "missing_cases": missing,
            "cleanup": self.cleanup,
            "cases": [
                {
                    "name": result.name,
                    "expected_status": list(result.expected_status),
                    "python": result.python,
                    "rust": result.rust,
                    "issues": result.issues,
                    "gate": "PASS" if result.passed else "FAIL",
                }
                for result in self.results
            ],
        }


def _gate(exit_code: int) -> str:
    return {0: "PASS", 1: "FAIL", 2: "ERROR", 130: "INTERRUPTED"}[exit_code]


def _cleanup_xml_versions(payload: bytes) -> List[Tuple[str, str]]:
    root = _xml(payload, "ListVersionsResult")
    found: List[Tuple[str, str]] = []
    for item in list(root):
        if _tag(item) not in ("Version", "DeleteMarker"):
            continue
        key = _text(item, "Key")
        version = _text(item, "VersionId")
        if key is None or version is None:
            raise SchemaError("cleanup version entry lacks key or version")
        if not VERSION_RE.fullmatch(version):
            raise SchemaError("cleanup saw invalid version ID")
        found.append((key, version))
    return found


def _cleanup_xml_objects(payload: bytes) -> List[str]:
    root = _xml(payload, "ListBucketResult")
    found: List[str] = []
    for item in list(root):
        if _tag(item) != "Contents":
            continue
        key = _text(item, "Key")
        if key is None:
            raise SchemaError("cleanup object entry lacks key")
        found.append(key)
    return found


def _cleanup_xml_uploads(payload: bytes) -> List[Tuple[str, str]]:
    root = _xml(payload, "ListMultipartUploadsResult")
    found: List[Tuple[str, str]] = []
    for item in list(root):
        if _tag(item) != "Upload":
            continue
        key = _text(item, "Key")
        upload = _text(item, "UploadId")
        if key is None or upload is None:
            raise SchemaError("cleanup upload entry lacks key or upload ID")
        if not VERSION_RE.fullmatch(upload):
            raise SchemaError("cleanup saw invalid upload ID")
        found.append((key, upload))
    return found


def _cleanup_target(target: Target, bucket: str) -> Dict[str, Any]:
    events: List[Dict[str, Any]] = []
    issues: List[str] = []

    def attempt(label: str, method: str, key: Optional[str] = None,
                query: Sequence[Tuple[str, str]] = (), body: bytes = b"",
                headers: Optional[Mapping[str, str]] = None) -> Optional[Snapshot]:
        try:
            snap = target.request(method, _path(bucket, key), query, body, headers)
            events.append({"action": label, "status": snap.status})
            return snap
        except Exception as exc:
            issues.append("{} failed ({})".format(label, type(exc).__name__))
            events.append({"action": label, "error": type(exc).__name__})
            return None

    if not target.ownership_clear or not (target.creation_attempted or target.owned):
        return {"attempted": False, "passed": True, "final_status": None,
                "events": events, "issues": issues,
                "reason": "no-owned-namespace-was-written"}

    for key, upload in sorted(target.uploads.items()):
        attempt("abort-known-upload", "DELETE", key, (("uploadId", upload),))

    # Discovery is limited to the cryptographically unique bucket that passed
    # the 404 ownership gate.  Three bounded rounds handle delete markers that
    # may be created while removing current objects from a versioned bucket.
    for round_number in range(3):
        uploads = attempt("list-uploads-{}".format(round_number), "GET", None,
                          (("uploads", ""), ("max-uploads", "1000")))
        if uploads is not None and uploads.status == 200:
            try:
                for key, upload in _cleanup_xml_uploads(uploads.body):
                    attempt("abort-discovered-upload", "DELETE", key, (("uploadId", upload),))
            except SchemaError as exc:
                issues.append("upload discovery schema failed: {}".format(exc))

        versions = attempt("list-versions-{}".format(round_number), "GET", None,
                           (("versions", ""), ("max-keys", "1000")))
        if versions is not None and versions.status == 200:
            try:
                for key, version in _cleanup_xml_versions(versions.body):
                    attempt("delete-discovered-version", "DELETE", key,
                            (("versionId", version),))
            except SchemaError as exc:
                issues.append("version discovery schema failed: {}".format(exc))

        listing = attempt("list-objects-{}".format(round_number), "GET", None,
                          (("list-type", "2"), ("max-keys", "1000")))
        discovered: Set[str] = set(target.known_objects)
        if listing is not None and listing.status == 200:
            try:
                discovered.update(_cleanup_xml_objects(listing.body))
            except SchemaError as exc:
                issues.append("object discovery schema failed: {}".format(exc))
        for key in sorted(discovered):
            attempt("delete-object", "DELETE", key)

    suspended = (b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                 b"<Status>Suspended</Status></VersioningConfiguration>")
    attempt("suspend-versioning", "PUT", None, (("versioning", ""),), suspended,
            {"Content-Type": "application/xml"})
    attempt("delete-bucket", "DELETE")
    final = attempt("final-head", "HEAD")
    final_status = final.status if final is not None else None
    if final_status != 404:
        issues.append("final bucket status is {} rather than 404".format(final_status))
    return {"attempted": True, "passed": not issues, "final_status": final_status,
            "events": events, "issues": issues}


def _atomic_report(path: Path, report: Mapping[str, Any]) -> None:
    path = path.expanduser()
    if path.exists() and path.is_symlink():
        raise ConfigError("JSON report target must not be a symlink")
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
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        try:
            directory_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


TAGGING_XML = (
    b'<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<TagSet><Tag><Key>purpose</Key><Value>parity</Value></Tag></TagSet></Tagging>"
)
CORS_XML = (
    b'<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<CORSRule><AllowedOrigin>https://parity.invalid</AllowedOrigin>"
    b"<AllowedMethod>GET</AllowedMethod><AllowedHeader>x-parity</AllowedHeader>"
    b"<ExposeHeader>ETag</ExposeHeader><MaxAgeSeconds>60</MaxAgeSeconds>"
    b"</CORSRule></CORSConfiguration>"
)
VERSIONING_ENABLED_XML = (
    b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<Status>Enabled</Status></VersioningConfiguration>"
)
VERSIONING_SUSPENDED_XML = (
    b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<Status>Suspended</Status></VersioningConfiguration>"
)
RESTORE_XML = (
    b'<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<Days>1</Days></RestoreRequest>"
)


def _remember_put(target: Target, bucket: str, key: str, payload: bytes,
                  headers: Optional[Mapping[str, str]] = None,
                  query: Sequence[Tuple[str, str]] = (),
                  auth: str = "v4-header") -> Snapshot:
    target.known_objects.add(key)
    return target.request("PUT", _path(bucket, key), query, payload, headers, auth)


def _normalize_empty_tagging(snapshot: Snapshot, _target: Target) -> Dict[str, Any]:
    return _normalize_tagging(snapshot.body, {})


def _scenario(runner: Runner) -> None:
    bucket = runner.namespace
    core_key = "core/hello.txt"
    copy_key = "core/copied.txt"
    invalid_key = "negative/invalid-storage-class"
    mpu_key = "multipart/assembled.bin"
    delete_a = "delete/a.txt"
    delete_b = "delete/b.txt"
    version_key = "versions/state.txt"
    core_payload = b"peregrine strict S3 parity\n"
    delete_payload = b"delete-me"
    version_one = b"version-one"
    version_two = b"version-two"
    part_one = b"A" * (5 * 1024 * 1024)
    part_two = b"tail-v2"
    multipart_payload = part_one + part_two
    core_etag = _md5_etag(core_payload)
    part_one_etag = _md5_etag(part_one)
    part_two_etag = _md5_etag(part_two)
    multipart_etag = '"{}-2"'.format(hashlib.md5(
        bytes.fromhex(_md5(part_one)) + bytes.fromhex(_md5(part_two)),
        usedforsecurity=False).hexdigest())

    # Authentication is a dedicated runtime/config gate.  Existing buckets in
    # either account are fully schema-checked but excluded from comparison; the
    # only scoped assertion is that our random bucket is absent.
    credential_ok = runner.run(
        "credential-list-buckets",
        lambda target: target.request("GET", "/"),
        (200,),
        lambda snapshot, target: _normalize_list_buckets(
            snapshot.body, bucket, False, target),
        {"content-type": ("media", None)},
    )
    if not credential_ok:
        raise ConfigError("S3 credential probe failed")

    ownership_ok = runner.run(
        "ownership-gate",
        lambda target: target.request("HEAD", _path(bucket)),
        (404,),
        _empty_body,
    )
    if not ownership_ok:
        raise ConfigError("random namespace did not pass the write-before-404 ownership gate")
    runner.python.ownership_clear = True
    runner.rust.ownership_clear = True

    def create(target: Target) -> Snapshot:
        target.creation_attempted = True
        snapshot = target.request("PUT", _path(bucket))
        if snapshot.status == 200:
            target.owned = True
        return snapshot

    create_ok = runner.run("create-bucket", create, (200,), _empty_body,
                           {"content-length": ("uint", "0")})
    if not create_ok or not all(t.owned for t in (runner.python, runner.rust)):
        raise ScenarioAbort("bucket creation did not complete safely on both targets")

    runner.run("head-bucket-sigv2-header",
               lambda target: target.request("HEAD", _path(bucket), auth="v2-header"),
               (200,), _empty_body)

    runner.run(
        "put-object",
        lambda target: _remember_put(target, bucket, core_key, core_payload,
                                     {"Content-Type": "application/octet-stream"}),
        (200,), _empty_body,
        {"etag": ("etag", core_etag), "content-length": ("uint", "0")},
    )
    object_headers = {
        "etag": ("etag", core_etag),
        "content-length": ("uint", str(len(core_payload))),
        "content-type": ("media", None),
        "last-modified": ("http-date", None),
    }
    runner.run("head-object-sigv2-header",
               lambda target: target.request("HEAD", _path(bucket, core_key), auth="v2-header"),
               (200,), _empty_body, object_headers)
    runner.run("get-object-sigv4-query",
               lambda target: target.request("GET", _path(bucket, core_key),
                                             auth="v4-query", expires=600),
               (200,), _raw_body(core_payload), object_headers)
    runner.run("range-object-sigv2-query",
               lambda target: target.request("GET", _path(bucket, core_key), body=b"",
                                             headers={"Range": "bytes=0-8"},
                                             auth="v2-query", expires=int(time.time()) + 600),
               (206,), _raw_body(core_payload[:9]),
               {"etag": ("etag", core_etag), "content-length": ("uint", "9"),
                "content-range": ("exact", "bytes 0-8/{}".format(len(core_payload)))})

    def copy_object(target: Target) -> Snapshot:
        target.known_objects.add(copy_key)
        return target.request("PUT", _path(bucket, copy_key), headers={
            "X-Amz-Copy-Source": _path(bucket, core_key),
            "Content-Length": "0",
        })

    runner.run("copy-object", copy_object, (200,),
               lambda snapshot, _target: _normalize_copy(snapshot.body, core_etag),
               {"content-type": ("media", None)})
    runner.run("get-copy", lambda target: target.request("GET", _path(bucket, copy_key)),
               (200,), _raw_body(core_payload),
               {"etag": ("etag", core_etag),
                "content-length": ("uint", str(len(core_payload)))})
    listed = {core_key: (len(core_payload), core_etag),
              copy_key: (len(core_payload), core_etag)}
    runner.run("list-objects-v1",
               lambda target: target.request("GET", _path(bucket),
                                             (("prefix", "core/"), ("max-keys", "1000"))),
               (200,), lambda snapshot, target: _normalize_listing(
                   snapshot.body, bucket, listed, False, target),
               {"content-type": ("media", None)})
    runner.run("list-objects-v2",
               lambda target: target.request("GET", _path(bucket),
                                             (("list-type", "2"), ("prefix", "core/"),
                                              ("max-keys", "1000"))),
               (200,), lambda snapshot, target: _normalize_listing(
                   snapshot.body, bucket, listed, True, target),
               {"content-type": ("media", None)})

    runner.run("put-bucket-acl-private",
               lambda target: target.request("PUT", _path(bucket), (("acl", ""),),
                                             headers={"X-Amz-Acl": "private", "Content-Length": "0"}),
               (200,), _empty_body, {"location": ("exact", bucket)})
    runner.run("get-bucket-acl",
               lambda target: target.request("GET", _path(bucket), (("acl", ""),)),
               (200,), lambda snapshot, target: _normalize_acl(snapshot.body, target),
               {"content-type": ("media", None)})
    runner.run("get-object-acl",
               lambda target: target.request("GET", _path(bucket, core_key), (("acl", ""),)),
               (200,), lambda snapshot, target: _normalize_acl(snapshot.body, target),
               {"content-type": ("media", None)})
    runner.run("put-object-acl-not-implemented",
               lambda target: target.request("PUT", _path(bucket, core_key), (("acl", ""),),
                                             headers={"X-Amz-Acl": "private", "Content-Length": "0"}),
               (501,), _error_body("NotImplemented"),
               {"content-type": ("media", None)})

    runner.run("get-empty-bucket-tagging",
               lambda target: target.request("GET", _path(bucket), (("tagging", ""),)),
               (200,), _normalize_empty_tagging, {"content-type": ("media", None)})
    runner.run("get-empty-object-tagging",
               lambda target: target.request("GET", _path(bucket, core_key), (("tagging", ""),)),
               (200,), _normalize_empty_tagging, {"content-type": ("media", None)})
    runner.run("put-bucket-tagging-not-implemented",
               lambda target: target.request("PUT", _path(bucket), (("tagging", ""),),
                                             TAGGING_XML, {"Content-Type": "application/xml"}),
               (501,), _error_body("NotImplemented"), {"content-type": ("media", None)})
    runner.run("delete-object-tagging-not-implemented",
               lambda target: target.request("DELETE", _path(bucket, core_key),
                                             (("tagging", ""),)),
               (501,), _error_body("NotImplemented"), {"content-type": ("media", None)})
    runner.run("get-bucket-cors-not-implemented",
               lambda target: target.request("GET", _path(bucket), (("cors", ""),)),
               (501,), _error_body("NotImplemented"), {"content-type": ("media", None)})
    runner.run("put-bucket-cors-not-implemented",
               lambda target: target.request("PUT", _path(bucket), (("cors", ""),),
                                             CORS_XML, {"Content-Type": "application/xml"}),
               (501,), _error_body("NotImplemented"), {"content-type": ("media", None)})
    runner.run("delete-bucket-cors-not-implemented",
               lambda target: target.request("DELETE", _path(bucket), (("cors", ""),)),
               (501,), _error_body("NotImplemented"), {"content-type": ("media", None)})

    runner.run("restore-not-implemented",
               lambda target: target.request("POST", _path(bucket, core_key),
                                             (("restore", ""),), RESTORE_XML,
                                             {"Content-Type": "application/xml"}),
               (501,), _error_body("NotImplemented"), {"content-type": ("media", None)})
    runner.run("invalid-storage-class",
               lambda target: _remember_put(target, bucket, invalid_key, b"must-not-exist",
                                             {"X-Amz-Storage-Class": "GLACIER"}),
               (400,), _error_body("InvalidStorageClass"),
               {"content-type": ("media", None)})
    runner.run("invalid-storage-class-no-object",
               lambda target: target.request("HEAD", _path(bucket, invalid_key)),
               (404,), _empty_body)

    now = int(time.time())
    runner.run("sigv4-header-clock-skew",
               lambda target: target.request("GET", _path(bucket, core_key),
                                             signed_at=now - 3600),
               (403,), _error_body("RequestTimeTooSkewed"),
               {"content-type": ("media", None)})
    runner.run("sigv4-query-expired",
               lambda target: target.request("GET", _path(bucket, core_key), auth="v4-query",
                                             signed_at=now - 120, expires=1),
               (403,), _error_body("AccessDenied"), {"content-type": ("media", None)})
    runner.run("sigv2-header-clock-skew",
               lambda target: target.request("GET", _path(bucket, core_key),
                                             auth="v2-header", signed_at=now - 3600),
               (403,), _error_body("RequestTimeTooSkewed"),
               {"content-type": ("media", None)})
    runner.run("sigv2-query-expired",
               lambda target: target.request("GET", _path(bucket, core_key),
                                             auth="v2-query", expires=now - 10),
               (403,), _error_body("AccessDenied"), {"content-type": ("media", None)})

    def initiate(target: Target) -> Snapshot:
        target.known_objects.add(mpu_key)
        return target.request("POST", _path(bucket, mpu_key), (("uploads", ""),))

    runner.run("multipart-initiate", initiate, (200,),
               lambda snapshot, target: _normalize_mpu_init(
                   snapshot.body, target, bucket, mpu_key),
               {"content-type": ("media", None)})
    if not all(mpu_key in target.uploads for target in (runner.python, runner.rust)):
        raise ScenarioAbort("multipart initiation did not return safe upload IDs")

    def upload_part(target: Target, number: int, payload: bytes, label: str) -> Snapshot:
        snapshot = target.request("PUT", _path(bucket, mpu_key),
                                  (("partNumber", str(number)),
                                   ("uploadId", target.uploads[mpu_key])), payload)
        if snapshot.status == 200 and snapshot.first("etag"):
            target.etags[label] = snapshot.first("etag") or ""
        return snapshot

    runner.run("multipart-upload-part-1",
               lambda target: upload_part(target, 1, part_one, "part1"),
               (200,), _empty_body,
               {"etag": ("etag", part_one_etag), "content-length": ("uint", "0")})
    runner.run("multipart-upload-part-2",
               lambda target: upload_part(target, 2, part_two, "part2"),
               (200,), _empty_body,
               {"etag": ("etag", part_two_etag), "content-length": ("uint", "0")})
    if not all({"part1", "part2"} <= set(target.etags) for target in
               (runner.python, runner.rust)):
        raise ScenarioAbort("multipart part ETags were not captured on both targets")

    runner.run("multipart-list-parts",
               lambda target: target.request("GET", _path(bucket, mpu_key),
                                             (("uploadId", target.uploads[mpu_key]),)),
               (200,), lambda snapshot, target: _normalize_list_parts(
                   snapshot.body, target, bucket, mpu_key,
                   ((1, len(part_one), part_one_etag), (2, len(part_two), part_two_etag))),
               {"content-type": ("media", None)})
    runner.run("multipart-list-uploads",
               lambda target: target.request("GET", _path(bucket),
                                             (("uploads", ""), ("max-uploads", "1000"))),
               (200,), lambda snapshot, target: _normalize_list_uploads(
                   snapshot.body, target, bucket, mpu_key),
               {"content-type": ("media", None)})

    def complete(target: Target) -> Snapshot:
        complete_xml = (
            "<CompleteMultipartUpload>"
            "<Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>"
            "<Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part>"
            "</CompleteMultipartUpload>".format(target.etags["part1"], target.etags["part2"])
        ).encode("utf-8")
        return target.request("POST", _path(bucket, mpu_key),
                              (("uploadId", target.uploads[mpu_key]),), complete_xml,
                              {"Content-Type": "application/xml"})

    runner.run("multipart-complete", complete, (200,),
               lambda snapshot, _target: _normalize_mpu_complete(
                   snapshot.body, bucket, mpu_key, multipart_etag),
               {"content-type": ("media", None)})
    runner.run("multipart-get", lambda target: target.request("GET", _path(bucket, mpu_key)),
               (200,), _raw_body(multipart_payload),
               {"etag": ("etag", multipart_etag),
                "content-length": ("uint", str(len(multipart_payload)))})

    runner.run("put-multidelete-a",
               lambda target: _remember_put(target, bucket, delete_a, delete_payload),
               (200,), _empty_body,
               {"etag": ("etag", _md5_etag(delete_payload)), "content-length": ("uint", "0")})
    runner.run("put-multidelete-b",
               lambda target: _remember_put(target, bucket, delete_b, delete_payload),
               (200,), _empty_body,
               {"etag": ("etag", _md5_etag(delete_payload)), "content-length": ("uint", "0")})
    delete_keys = {core_key, copy_key, mpu_key, delete_a, delete_b}
    delete_xml = ("<Delete>" + "".join("<Object><Key>{}</Key></Object>".format(key)
                                       for key in sorted(delete_keys)) + "</Delete>").encode("utf-8")
    delete_md5 = base64.b64encode(hashlib.md5(delete_xml, usedforsecurity=False).digest()).decode("ascii")
    runner.run("multi-delete",
               lambda target: target.request("POST", _path(bucket), (("delete", ""),),
                                             delete_xml,
                                             {"Content-Type": "application/xml",
                                              "Content-MD5": delete_md5}),
               (200,), lambda snapshot, _target: _normalize_delete_result(
                   snapshot.body, delete_keys), {"content-type": ("media", None)})
    runner.run("post-multidelete-list-empty",
               lambda target: target.request("GET", _path(bucket),
                                             (("list-type", "2"), ("max-keys", "1000"))),
               (200,), lambda snapshot, target: _normalize_listing(
                   snapshot.body, bucket, {}, True, target),
               {"content-type": ("media", None)})

    runner.run("put-versioning-enabled",
               lambda target: target.request("PUT", _path(bucket), (("versioning", ""),),
                                             VERSIONING_ENABLED_XML,
                                             {"Content-Type": "application/xml"}),
               (200,), _empty_body, {"content-length": ("uint", "0")})
    runner.run("get-versioning-enabled",
               lambda target: target.request("GET", _path(bucket), (("versioning", ""),)),
               (200,), lambda snapshot, _target: _normalize_versioning(snapshot.body, "Enabled"),
               {"content-type": ("media", None)})

    runner.run("put-version-1",
               lambda target: _remember_put(target, bucket, version_key, version_one),
               (200,), _empty_body,
               {"etag": ("etag", _md5_etag(version_one)),
                "x-amz-version-id": ("capture-version", "version-1")})
    runner.run("put-version-2",
               lambda target: _remember_put(target, bucket, version_key, version_two),
               (200,), _empty_body,
               {"etag": ("etag", _md5_etag(version_two)),
                "x-amz-version-id": ("capture-version", "version-2")})
    if not all({"version-1", "version-2"} <= set(target.versions) for target in
               (runner.python, runner.rust)):
        raise ScenarioAbort("versioned PUT did not return safe version IDs")
    runner.run("get-version-1",
               lambda target: target.request("GET", _path(bucket, version_key),
                                             (("versionId", target.versions["version-1"]),)),
               (200,), _raw_body(version_one),
               {"etag": ("etag", _md5_etag(version_one)),
                "x-amz-version-id": ("known-version", "version-1")})

    runner.run("create-delete-marker",
               lambda target: target.request("DELETE", _path(bucket, version_key)),
               (204,), _empty_body,
               {"x-amz-delete-marker": ("bool", "true"),
                "x-amz-version-id": ("capture-version", "delete-marker")})
    if not all("delete-marker" in target.versions for target in (runner.python, runner.rust)):
        raise ScenarioAbort("delete marker did not return safe version IDs")
    runner.run("get-current-delete-marker",
               lambda target: target.request("GET", _path(bucket, version_key)),
               (404,), _error_body("NoSuchKey"),
               {"x-amz-delete-marker": ("bool", "true"),
                "x-amz-version-id": ("known-version", "delete-marker"),
                "content-type": ("media", None)})
    runner.run("list-object-versions",
               lambda target: target.request("GET", _path(bucket),
                                             (("versions", ""), ("prefix", version_key),
                                              ("max-keys", "1000"))),
               (200,), lambda snapshot, target: _normalize_list_versions(
                   snapshot.body, target, bucket, version_key,
                   {
                       "version-1": ("Version", len(version_one), _md5_etag(version_one), False),
                       "version-2": ("Version", len(version_two), _md5_etag(version_two), False),
                       "delete-marker": ("DeleteMarker", 0, None, True),
                   }),
               {"content-type": ("media", None)})

    for case_name, label in (("delete-delete-marker", "delete-marker"),
                             ("delete-version-1", "version-1"),
                             ("delete-version-2", "version-2")):
        runner.run(case_name,
                   lambda target, version_label=label: target.request(
                       "DELETE", _path(bucket, version_key),
                       (("versionId", target.versions[version_label]),)),
                   (204,), _empty_body)
    runner.run("list-object-versions-empty",
               lambda target: target.request("GET", _path(bucket),
                                             (("versions", ""), ("prefix", version_key),
                                              ("max-keys", "1000"))),
               (200,), lambda snapshot, _target: _normalize_list_versions_empty(
                   snapshot.body, bucket),
               {"content-type": ("media", None)})
    runner.run("put-versioning-suspended",
               lambda target: target.request("PUT", _path(bucket), (("versioning", ""),),
                                             VERSIONING_SUSPENDED_XML,
                                             {"Content-Type": "application/xml"}),
               (200,), _empty_body, {"content-length": ("uint", "0")})
    runner.run("get-versioning-suspended",
               lambda target: target.request("GET", _path(bucket), (("versioning", ""),)),
               (200,), lambda snapshot, _target: _normalize_versioning(snapshot.body, "Suspended"),
               {"content-type": ("media", None)})
    runner.run("delete-bucket",
               lambda target: target.request("DELETE", _path(bucket)),
               (204,), _empty_body)
    final_ok = runner.run("final-bucket-404",
                          lambda target: target.request("HEAD", _path(bucket)),
                          (404,), _empty_body)
    if final_ok:
        runner.python.owned = False
        runner.rust.owned = False


def _validate_endpoint(raw: str, label: str) -> str:
    endpoint = raw.strip().rstrip("/")
    parsed = urlsplit(endpoint)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError("{} endpoint must be an absolute HTTP(S) origin".format(label))
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError("{} endpoint must not contain credentials".format(label))
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ConfigError("{} endpoint must not contain path/query/fragment".format(label))
    try:
        parsed.port
    except ValueError as exc:
        raise ConfigError("{} endpoint has invalid port".format(label)) from exc
    return endpoint


def _origin_identity(endpoint: str) -> Tuple[str, str, int]:
    parsed = urlsplit(endpoint)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), (
        parsed.port or (443 if parsed.scheme == "https" else 80))


def _validate_plain(value: str, label: str, maximum: int) -> str:
    if not value or len(value) > maximum or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ConfigError("{} must be non-empty bounded printable text".format(label))
    return value


def _required_env(name: str, label: str, maximum: int) -> str:
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", name):
        raise ConfigError("{} environment variable name is invalid".format(label))
    value = os.environ.get(name)
    if value is None:
        raise ConfigError("required environment variable {} is not set".format(name))
    return _validate_plain(value, label, maximum)


def _validate_region(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", value):
        raise ConfigError("{} region is invalid".format(label))
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", required=True, help="Python Swift S3 origin")
    parser.add_argument("--rust", required=True, help="Peregrine Rust S3 origin")
    parser.add_argument("--python-access-env", default="PEREGRINE_S3_PY_ACCESS")
    parser.add_argument("--python-secret-env", default="PEREGRINE_S3_PY_SECRET")
    parser.add_argument("--rust-access-env", default="PEREGRINE_S3_RS_ACCESS")
    parser.add_argument("--rust-secret-env", default="PEREGRINE_S3_RS_SECRET")
    parser.add_argument("--python-region", default="us-east-1")
    parser.add_argument("--rust-region", default="us-east-1")
    parser.add_argument("--python-provenance", required=True)
    parser.add_argument("--rust-provenance", required=True)
    parser.add_argument("--python-insecure", action="store_true")
    parser.add_argument("--rust-insecure", action="store_true")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-response-bytes", type=int, default=MAX_RESPONSE_BYTES)
    parser.add_argument("--json-report", required=True,
                        help="atomic 0600 JSON report path; '-' is forbidden")
    return parser


def _merge_exit(current: int, candidate: int) -> int:
    priority = {0: 0, 1: 1, 2: 2, 130: 3}
    return candidate if priority[candidate] > priority[current] else current


def _redact(message: str, secrets_to_hide: Sequence[str]) -> str:
    result = message
    for value in sorted((item for item in secrets_to_hide if item), key=len, reverse=True):
        result = result.replace(value, "<redacted>")
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    report_path = Path(args.json_report)
    runner: Optional[Runner] = None
    exit_code = EXIT_PASS
    secrets_to_hide: List[str] = []
    interrupted = False
    pre_target_fatal: Optional[str] = None
    report_enabled = args.json_report != "-"

    def on_signal(_signum: int, _frame: Any) -> None:
        nonlocal interrupted
        interrupted = True
        raise Interrupted("validation interrupted")

    previous_int = signal.signal(signal.SIGINT, on_signal)
    previous_term = signal.signal(signal.SIGTERM, on_signal)
    try:
        if args.json_report == "-":
            raise ConfigError("--json-report must be a filesystem path")
        if not (0.1 <= args.timeout <= 300):
            raise ConfigError("--timeout must be in 0.1..300 seconds")
        if not (1024 <= args.max_response_bytes <= 64 * 1024 * 1024):
            raise ConfigError("--max-response-bytes must be in 1024..67108864")
        env_names = (args.python_access_env, args.python_secret_env,
                     args.rust_access_env, args.rust_secret_env)
        if len(set(env_names)) != 4:
            raise ConfigError("the four credential environment variable names must be distinct")
        python_endpoint = _validate_endpoint(args.python, "python")
        rust_endpoint = _validate_endpoint(args.rust, "rust")
        if _origin_identity(python_endpoint) == _origin_identity(rust_endpoint):
            raise ConfigError("Python and Rust endpoints must be independent origins")
        py_provenance = _validate_plain(args.python_provenance, "python provenance", 512)
        rs_provenance = _validate_plain(args.rust_provenance, "rust provenance", 512)
        if py_provenance == rs_provenance:
            raise ConfigError("Python and Rust provenance strings must be distinct")
        py_access = _required_env(args.python_access_env, "python access key", 1024)
        py_secret = _required_env(args.python_secret_env, "python secret", 4096)
        rs_access = _required_env(args.rust_access_env, "rust access key", 1024)
        rs_secret = _required_env(args.rust_secret_env, "rust secret", 4096)
        secrets_to_hide.extend((py_access, py_secret, rs_access, rs_secret))
        py_region = _validate_region(args.python_region, "python")
        rs_region = _validate_region(args.rust_region, "rust")
        namespace = "peregrine-s3-{}-{}".format(
            datetime.now(timezone.utc).strftime("%Y%m%d"), secrets.token_hex(8))
        if not NAMESPACE_RE.fullmatch(namespace):
            raise ConfigError("internal namespace generation failed")
        python = Target("python", python_endpoint, py_access, py_secret, py_region,
                        py_provenance,
                        HttpClient(args.timeout, args.max_response_bytes, args.python_insecure))
        rust = Target("rust", rust_endpoint, rs_access, rs_secret, rs_region,
                      rs_provenance,
                      HttpClient(args.timeout, args.max_response_bytes, args.rust_insecure))
        runner = Runner(namespace, python, rust)
        _scenario(runner)
    except Interrupted as exc:
        exit_code = EXIT_INTERRUPTED
        if runner is not None:
            runner.fatal = _redact(str(exc), secrets_to_hide)
    except ConfigError as exc:
        exit_code = EXIT_RUNTIME_FAILURE
        if runner is not None:
            runner.fatal = _redact(str(exc), secrets_to_hide)
        else:
            pre_target_fatal = _redact(str(exc), secrets_to_hide)
            print("ERROR " + pre_target_fatal, file=sys.stderr)
    except TransportError as exc:
        exit_code = EXIT_RUNTIME_FAILURE
        if runner is not None:
            runner.fatal = _redact(str(exc), secrets_to_hide)
    except ScenarioAbort as exc:
        exit_code = EXIT_PARITY_FAILURE
        if runner is not None:
            runner.abort_reason = _redact(str(exc), secrets_to_hide)
    except Exception as exc:
        exit_code = EXIT_RUNTIME_FAILURE
        if runner is not None:
            runner.fatal = "unexpected {}: {}".format(
                type(exc).__name__, _redact(str(exc), secrets_to_hide))
        else:
            pre_target_fatal = "unexpected {}".format(type(exc).__name__)
            print("ERROR unexpected {}".format(type(exc).__name__), file=sys.stderr)
    finally:
        # A second terminal signal must not strand an owned namespace midway
        # through cleanup.  SIGKILL remains the operator's explicit hard stop.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if runner is not None:
            for target in (runner.python, runner.rust):
                try:
                    runner.cleanup[target.label] = _cleanup_target(target, runner.namespace)
                except Exception as exc:
                    runner.cleanup[target.label] = {
                        "attempted": True,
                        "passed": False,
                        "final_status": None,
                        "events": [],
                        "issues": ["unexpected cleanup {}".format(type(exc).__name__)],
                    }
            missing = len(runner.results) != len(REQUIRED_CASES)
            failed = any(not result.passed for result in runner.results)
            cleanup_failed = any(not result.get("passed") for result in runner.cleanup.values())
            if exit_code not in (EXIT_RUNTIME_FAILURE, EXIT_INTERRUPTED) and (
                    missing or failed or cleanup_failed):
                exit_code = _merge_exit(exit_code, EXIT_PARITY_FAILURE)
            report = runner.report(exit_code)
        else:
            report = {
                "schema": REPORT_SCHEMA,
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "scope": {"id": SCOPE_ID, "claim": "NO_CLAIM",
                          "required_cases": list(REQUIRED_CASES),
                          "excludes": list(EXCLUSIONS)},
                "summary": {"required_cases": len(REQUIRED_CASES), "executed_cases": 0,
                            "passed": 0, "failed": 0, "missing": len(REQUIRED_CASES),
                            "skipped": 0, "cleanup_failed": 0, "gate": _gate(exit_code)},
                "result": {"exit_code": exit_code, "gate": _gate(exit_code)},
                "fatal": pre_target_fatal or "configuration failed before target construction",
                "missing_cases": list(REQUIRED_CASES), "cleanup": {}, "cases": [],
            }
        if report_enabled:
            try:
                _atomic_report(report_path, report)
            except Exception as exc:
                print("ERROR atomic report write failed ({})".format(type(exc).__name__),
                      file=sys.stderr)
                exit_code = _merge_exit(exit_code, EXIT_RUNTIME_FAILURE)
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)

    if runner is not None:
        summary = runner.report(exit_code)["summary"]
        print("S3_PARITY_SUMMARY gate={} rc={} cases={}/{} failed={} missing={} "
              "cleanup_failed={} report={}".format(
                  _gate(exit_code), exit_code, summary["executed_cases"],
                  summary["required_cases"], summary["failed"], summary["missing"],
                  summary["cleanup_failed"], report_path))
    return EXIT_INTERRUPTED if interrupted else exit_code


if __name__ == "__main__":
    raise SystemExit(main())
