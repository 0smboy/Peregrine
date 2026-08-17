#!/usr/bin/env python3
"""Strict live S3 supplement scoreboard for Peregrine (second scoreboard).

This program is the *supplement* to the frozen 57-case dual-oracle runner
``tools/strict-s3-parity.py`` (sha256 ``f622b336ae3aec2a057fd3b9a0c8314bcf
b834e5083b0bfcb61e4786bfccaec5``).  That primary runner scores byte-level
parity against Python Swift 2.33 and therefore *permanently* records the
seven Rust-ahead extras as FAIL (Python answers 501 NotImplemented).  This
tool scores exactly those extras against **AWS semantics** on the Rust
endpoint only (Section A), and adds three **account-root negatives** that
the 57 cases never cover, run dual-oracle style against both endpoints
(Section B).  Neither scoreboard replaces the other: the primary stays the
parity gate (live 49/8), this one is the extras/negatives gate.

Like the primary runner this program is dependency-free, signs raw
path-style S3 requests (SigV4 header auth only -- the signing matrix is the
primary runner's jurisdiction), never prints credentials, refuses to
overwrite an existing JSON report, and cannot PASS unless every declared
case ran and the Rust-side cleanup ended at HTTP 404.

Section A -- extras, AWS-semantic acceptance, Rust endpoint only (7 cases):
  extras-put-object-acl-readback          PutObjectAcl 200 + GetObjectAcl
                                          reads back the grant change
  extras-put-bucket-tagging-readback      PutBucketTagging success +
                                          GetBucketTagging round-trip
  extras-delete-bucket-tagging-and-get-after   DeleteBucketTagging 204 +
                                          GET-after per AWS (404 NoSuchTagSet)
                                          or recorded Swift-family empty set
  extras-delete-object-tagging-lifecycle  PutObjectTagging 200 -> readback ->
                                          DeleteObjectTagging 204 -> empty set
  extras-put-bucket-cors-readback         PutBucketCors 200 + GetBucketCors
                                          round-trip
  extras-delete-bucket-cors-and-get-after DeleteBucketCors 204 + GET-after per
                                          AWS (404 NoSuchCORSConfiguration) or
                                          recorded Swift-family empty config
  extras-restore-standard-object-invalid-state  RestoreObject on a STANDARD
                                          object -> 400 InvalidObjectState

Section B -- supplement negatives, dual-oracle, both endpoints (3 cases):
  negative-account-root-put               signed PUT /
  negative-account-root-delete            signed DELETE /
  negative-account-root-post              signed POST /
  Scoring: status equality + S3 error Code equality between the two targets,
  plus a security check that neither side answers 2xx (an account-face write
  translated to the Swift account).  Known state at authoring time: Python
  2.33 rejects with 405 MethodNotAllowed; the Rust Gate generation may
  translate to the Swift account face.  Divergence is recorded as FAIL --
  honestly -- and becomes the baseline that turns green once the account-face
  guard deploys.

Credentials are read from four distinctly named environment variables and
are never printed, included in URLs, or written to the report:

  export PEREGRINE_S3_PY_ACCESS='test:tester'
  export PEREGRINE_S3_PY_SECRET='...'
  export PEREGRINE_S3_RS_ACCESS='dev:tester'
  export PEREGRINE_S3_RS_SECRET='...'
  python3 tools/strict-s3-supplement.py --selftest
  python3 tools/strict-s3-supplement.py \
    --rust https://10.0.0.10:8085 --rust-insecure \
    --python http://10.0.0.3:8090 \
    --rust-provenance 'peregrine@gate+sha256:<verified-binary>' \
    --python-provenance 'python-swift@2.33.0+s3api+...' \
    --json-report /root/work/evidence/strict-s3-supplement-<date>-r1.json

Exit codes:
    0  every declared case passed and the Rust cleanup ended at HTTP 404
    1  any case FAIL, missing case, or cleanup failure
    2  unsafe configuration, setup, authentication, report, or transport
       failure (including --selftest failure); no scoreboard claim is made
  130  interrupted; cleanup was still attempted

Freeze discipline: once a live report references this file's SHA-256 the
file is frozen; behavior changes require a new versioned filename
(e.g. strict-s3-supplement-v2.py), never an in-place edit.

Explicit exclusions (a PASS makes no claim about these): everything the
primary runner excludes (Keystone/EC2 s3tokens, virtual-host routing,
cross-account ACL/IAM, bucket policies, lifecycle execution, object-lock /
retention / legal-hold, SSE/KMS, aws-chunked streaming, POST policies,
website/notification/replication/select, pagination beyond this bounded
namespace, browser CORS enforcement, performance/HA/durability/daemons,
native Swift API), plus the 57-case parity-and-signing matrix itself, which
remains the frozen primary runner's jurisdiction.
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
from pathlib import Path
from typing import (Any, Callable, Dict, Iterable, List, Mapping, Optional,
                    Sequence, Set, Tuple)
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlsplit
from urllib.request import (HTTPRedirectHandler, HTTPSHandler, ProxyHandler,
                            Request, build_opener)


EXIT_PASS = 0
EXIT_SUPPLEMENT_FAILURE = 1
EXIT_RUNTIME_FAILURE = 2
EXIT_INTERRUPTED = 130
REPORT_SCHEMA = "peregrine.strict-s3-supplement.v1"
SCOPE_ID = "tempauth-s3-extras-aws-semantics-and-account-root-negatives"
TOOL_NAME = "strict-s3-supplement.py"
PRIMARY_RUNNER_FROZEN = (
    "strict-s3-parity.py@sha256:"
    "f622b336ae3aec2a057fd3b9a0c8314bcfb834e5083b0bfcb61e4786bfccaec5"
)
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_XML_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT = 30.0
SERVICE = "s3"
V4_ALGORITHM = "AWS4-HMAC-SHA256"
NAMESPACE_RE = re.compile(r"^peregrine-supp-[0-9]{8}-[a-f0-9]{16}$")
ETAG_RE = re.compile(r'^"[0-9a-fA-F]{32}(?:-[0-9]+)?"$')
ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
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

SECTION_A_CASES = (
    "extras-put-object-acl-readback",
    "extras-put-bucket-tagging-readback",
    "extras-delete-bucket-tagging-and-get-after",
    "extras-delete-object-tagging-lifecycle",
    "extras-put-bucket-cors-readback",
    "extras-delete-bucket-cors-and-get-after",
    "extras-restore-standard-object-invalid-state",
)
SECTION_B_CASES = (
    "negative-account-root-put",
    "negative-account-root-delete",
    "negative-account-root-post",
)
ALL_CASES = SECTION_A_CASES + SECTION_B_CASES

EXCLUSIONS = (
    "the-57-case-parity-and-signing-matrix (frozen primary runner)",
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

# Fixed request bodies.  Content-MD5 accompanies the bucket-config PUTs
# because AWS requires it for PutBucketTagging / PutBucketCors /
# PutObjectTagging (see the "Content-MD5" required-header notes on the
# respective API pages).
BUCKET_TAGGING_XML = (
    b'<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<TagSet>"
    b"<Tag><Key>purpose</Key><Value>supplement-extras</Value></Tag>"
    b"<Tag><Key>section</Key><Value>a</Value></Tag>"
    b"</TagSet></Tagging>"
)
BUCKET_TAGGING_EXPECTED = {"purpose": "supplement-extras", "section": "a"}
OBJECT_TAGGING_XML = (
    b'<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<TagSet>"
    b"<Tag><Key>state</Key><Value>tagged-for-delete</Value></Tag>"
    b"</TagSet></Tagging>"
)
OBJECT_TAGGING_EXPECTED = {"state": "tagged-for-delete"}
CORS_XML = (
    b'<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<CORSRule><AllowedOrigin>https://supplement.invalid</AllowedOrigin>"
    b"<AllowedMethod>GET</AllowedMethod><AllowedHeader>x-supplement</AllowedHeader>"
    b"<ExposeHeader>ETag</ExposeHeader><MaxAgeSeconds>120</MaxAgeSeconds>"
    b"</CORSRule></CORSConfiguration>"
)
CORS_EXPECTED_RULES = [
    {
        "origins": ["https://supplement.invalid"],
        "methods": ["GET"],
        "headers": ["x-supplement"],
        "expose": ["ETag"],
        "max_age": 120,
    }
]
RESTORE_XML = (
    b'<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<Days>1</Days></RestoreRequest>"
)

OWNER_ONLY_GRANTS = [["OWNER", "FULL_CONTROL"]]
PUBLIC_READ_GRANTS = sorted(
    [["OWNER", "FULL_CONTROL"], ["GROUP:" + ALL_USERS_URI, "READ"]]
)


class ConfigError(RuntimeError):
    """The gate cannot run safely with the supplied configuration."""


class SetupError(RuntimeError):
    """A non-scored setup step failed; no scoreboard claim can be made."""


class TransportError(RuntimeError):
    """A target did not produce a complete bounded HTTP response."""


class SchemaError(ValueError):
    """A response body/header failed its declared schema."""


class Interrupted(RuntimeError):
    """SIGINT/SIGTERM requested cleanup and exit 130."""


class SelfTestError(RuntimeError):
    """An offline self-test expectation failed."""


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
    client: Any
    ownership_clear: bool = False
    creation_attempted: bool = False
    owned: bool = False
    known_objects: Set[str] = field(default_factory=set)

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
        signed_at: Optional[int] = None,
    ) -> Snapshot:
        request_headers, wire_query = _signed_request(
            method=method,
            path=path,
            query=query,
            body=body,
            headers=headers or {},
            access=self.access,
            secret=self.secret,
            region=self.region,
            host=self.host,
            signed_at=int(time.time()) if signed_at is None else signed_at,
        )
        url = self.endpoint + path
        if wire_query:
            url += "?" + _wire_query(wire_query)
        return self.client.request(method, url, body, request_headers)


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
            "User-Agent": "peregrine-strict-s3-supplement/1",
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


# ---------------------------------------------------------------------------
# SigV4 header signing (same construction as the frozen primary runner,
# trimmed to v4-header: the four-mode signing matrix stays the primary's job)
# ---------------------------------------------------------------------------

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
    signed_names = sorted({name.lower() for name in out
                           if name.lower() == "host"
                           or name.lower().startswith("x-amz-")
                           or name.lower() in ("content-md5", "content-type", "range")})
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


def _path(bucket: Optional[str] = None, key: Optional[str] = None) -> str:
    value = "/"
    if bucket is not None:
        value += _aws_quote(bucket)
    if key is not None:
        value += "/" + _aws_quote(key, safe="-_.~/")
    return value


def _md5_b64(payload: bytes) -> str:
    return base64.b64encode(
        hashlib.md5(payload, usedforsecurity=False).digest()).decode("ascii")


def _md5_etag(payload: bytes) -> str:
    return '"{}"'.format(hashlib.md5(payload, usedforsecurity=False).hexdigest())


# ---------------------------------------------------------------------------
# XML schema validation (same guarded-parse style as the primary runner)
# ---------------------------------------------------------------------------

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


def _text_node(element: ET.Element, label: str) -> str:
    if list(element) or element.attrib or element.text is None or element.text == "":
        raise SchemaError("{} must be non-empty text-only".format(label))
    return element.text


def _uint(value: str, label: str) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise SchemaError("{} must be an unsigned decimal".format(label))
    return int(value)


def _error_code(payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Lenient S3 <Error> extraction: (Code, Message) or (None, None).

    Lenient on children because real oracles decorate errors differently
    (Python MethodNotAllowed adds Method/ResourceType; the Rust generation
    adds empty Resource/RequestId).  The DTD/entity guard still applies.
    """
    try:
        root = _xml(payload, "Error")
    except SchemaError:
        return None, None
    code = None
    message = None
    for child in list(root):
        if _tag(child) == "Code" and child.text:
            code = child.text
        elif _tag(child) == "Message" and child.text is not None:
            message = child.text
    return code, message


def _strict_error(payload: bytes, expected_code: str) -> None:
    """Schema-checked S3 Error body carrying exactly the expected Code."""
    root = _xml(payload, "Error")
    allowed = ("Code", "Message", "Resource", "RequestId", "HostId", "Endpoint",
               "BucketName", "Key", "ArgumentName", "ArgumentValue",
               "Method", "ResourceType")
    _children(root, allowed)
    code = _text(root, "Code")
    if code != expected_code:
        raise SchemaError("S3 error code {} != {}".format(code, expected_code))


def _tagging_pairs(payload: bytes) -> Dict[str, str]:
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
    return actual


def _cors_rules(payload: bytes) -> List[Dict[str, Any]]:
    root = _xml(payload, "CORSConfiguration")
    _children(root, ("CORSRule",))
    rules: List[Dict[str, Any]] = []
    for rule in list(root):
        _children(rule, ("ID", "AllowedOrigin", "AllowedMethod", "AllowedHeader",
                         "ExposeHeader", "MaxAgeSeconds"))
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
    return rules


def _acl_grants(payload: bytes) -> List[List[str]]:
    """AccessControlPolicy -> sorted [kind, permission] pairs (owner-relative)."""
    root = _xml(payload, "AccessControlPolicy")
    _children(root, ("Owner", "AccessControlList"))
    owner = _one(root, "Owner")
    acl = _one(root, "AccessControlList")
    if owner is None or acl is None:
        raise SchemaError("ACL lacks Owner or AccessControlList")
    _children(owner, ("ID", "DisplayName"))
    owner_id = _text(owner, "ID")
    if owner_id is None or len(owner_id) > 1024 or any(
            ord(ch) < 33 or ord(ch) == 127 for ch in owner_id):
        raise SchemaError("invalid ACL owner ID")
    grants: List[List[str]] = []
    for grant in _children(acl, ("Grant",)):
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
        grants.append([kind, permission])
    grants.sort()
    return grants


def _media_type_ok(value: str) -> bool:
    return re.fullmatch(
        r"[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+(\s*;.*)?",
        value) is not None


# ---------------------------------------------------------------------------
# Case bookkeeping
# ---------------------------------------------------------------------------

class Case:
    def __init__(self, section: str, name: str, aws_reference: str) -> None:
        self.section = section
        self.name = name
        self.aws_reference = aws_reference
        self.steps: List[Dict[str, Any]] = []
        self.observed: Dict[str, Any] = {}
        self.issues: List[str] = []

    def request(self, target: Target, step: str, method: str, path: str,
                query: Sequence[Tuple[str, str]] = (), body: bytes = b"",
                headers: Optional[Mapping[str, str]] = None,
                note: Optional[str] = None) -> Snapshot:
        snapshot = target.request(method, path, query, body, headers)
        code, _message = _error_code(snapshot.body)
        record: Dict[str, Any] = {
            "step": step,
            "target": target.label,
            "method": method,
            "path": path,
            "query": ["{}={}".format(k, v) if v else k for k, v in query],
            "request_headers": {
                k: v for k, v in (headers or {}).items()
                if k.lower() in ("content-type", "content-md5", "x-amz-acl",
                                 "content-length", "x-amz-storage-class")
            },
            "request_body_length": len(body),
            "status": snapshot.status,
            "content_type": snapshot.first("content-type"),
            "body_length": len(snapshot.body),
            "body_sha256": hashlib.sha256(snapshot.body).hexdigest(),
            "error_code": code,
        }
        if note:
            record["note"] = note
        self.steps.append(record)
        return snapshot

    def issue(self, message: str) -> None:
        self.issues.append(message)

    def expect_status(self, step: str, snapshot: Snapshot,
                      allowed: Sequence[int]) -> bool:
        if snapshot.status not in allowed:
            self.issue("{}: status {} not in {}".format(
                step, snapshot.status, tuple(sorted(set(allowed)))))
            return False
        return True

    def expect_empty_body(self, step: str, snapshot: Snapshot) -> bool:
        if snapshot.body != b"":
            self.issue("{}: response body is not empty ({} bytes)".format(
                step, len(snapshot.body)))
            return False
        return True

    def expect_xml_content_type(self, step: str, snapshot: Snapshot) -> bool:
        value = snapshot.first("content-type")
        if value is None or not _media_type_ok(value):
            self.issue("{}: missing or invalid content-type on XML body".format(step))
            return False
        return True

    def expect_error(self, step: str, snapshot: Snapshot, status: int,
                     code: str) -> bool:
        ok = self.expect_status(step, snapshot, (status,))
        try:
            _strict_error(snapshot.body, code)
        except SchemaError as exc:
            self.issue("{}: error body schema: {}".format(step, exc))
            ok = False
        return ok

    @property
    def passed(self) -> bool:
        return not self.issues

    def record(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "section": self.section,
            "aws_reference": self.aws_reference,
            "steps": self.steps,
            "observed": self.observed,
            "issues": self.issues,
            "gate": "PASS" if self.passed else "FAIL",
        }


class Runner:
    def __init__(self, namespace: str, python: Target, rust: Target) -> None:
        self.namespace = namespace
        self.python = python
        self.rust = rust
        self.results: List[Case] = []
        self.setup: List[Dict[str, Any]] = []
        self.cleanup: Dict[str, Dict[str, Any]] = {}
        self.fatal: Optional[str] = None

    def run_case(self, section: str, name: str, aws_reference: str,
                 fn: Callable[[Case], None]) -> Case:
        if name not in ALL_CASES:
            raise ConfigError("undeclared case {}".format(name))
        if any(result.name == name for result in self.results):
            raise ConfigError("duplicate case {}".format(name))
        case = Case(section, name, aws_reference)
        fn(case)
        self.results.append(case)
        if case.passed:
            print("PASS [{}] {:<46} steps={}".format(section, name, len(case.steps)))
        else:
            print("FAIL [{}] {:<46} steps={} issues={}".format(
                section, name, len(case.steps), len(case.issues)))
            for issue in case.issues:
                print("     " + issue)
        return case

    def setup_step(self, step: str, target: Target, method: str, path: str,
                   query: Sequence[Tuple[str, str]] = (), body: bytes = b"",
                   headers: Optional[Mapping[str, str]] = None,
                   expect: Sequence[int] = (200,)) -> Snapshot:
        snapshot = target.request(method, path, query, body, headers)
        self.setup.append({
            "step": step,
            "target": target.label,
            "method": method,
            "path": path,
            "status": snapshot.status,
            "body_length": len(snapshot.body),
        })
        if snapshot.status not in expect:
            raise SetupError("setup step {} got status {} (expected {})".format(
                step, snapshot.status, tuple(expect)))
        return snapshot

    def report(self, exit_code: int, tool_sha256: str) -> Dict[str, Any]:
        names = [result.name for result in self.results]
        missing = [name for name in ALL_CASES if name not in names]
        a_results = [r for r in self.results if r.section == "A"]
        b_results = [r for r in self.results if r.section == "B"]
        a_failed = sum(1 for r in a_results if not r.passed)
        b_failed = sum(1 for r in b_results if not r.passed)
        cleanup_failed = sum(1 for value in self.cleanup.values() if not value.get("passed"))
        gate = _gate(exit_code)
        return {
            "schema": REPORT_SCHEMA,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tool": {
                "name": TOOL_NAME,
                "sha256": tool_sha256,
                "frozen_primary_runner": PRIMARY_RUNNER_FROZEN,
            },
            "scope": {
                "id": SCOPE_ID,
                "claim": "EXTRAS_AWS_SEMANTICS_AND_ACCOUNT_ROOT_NEGATIVES_ONLY",
                "relationship_to_primary": (
                    "Second scoreboard beside the frozen 57-case parity runner "
                    "(live 49/8). The primary scores Python-2.33 parity, where "
                    "the seven Rust-ahead extras legitimately FAIL against 501; "
                    "this supplement scores those extras against AWS semantics "
                    "on the Rust endpoint and adds account-root negatives the "
                    "57 cases never cover. Neither gate replaces the other."
                ),
                "section_a": {"target": "rust-only", "cases": list(SECTION_A_CASES)},
                "section_b": {"target": "dual-oracle", "cases": list(SECTION_B_CASES)},
                "excludes": list(EXCLUSIONS),
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
            "setup": self.setup,
            "summary": {
                "section_a": {
                    "required": len(SECTION_A_CASES),
                    "executed": len(a_results),
                    "passed": len(a_results) - a_failed,
                    "failed": a_failed,
                },
                "section_b": {
                    "required": len(SECTION_B_CASES),
                    "executed": len(b_results),
                    "passed": len(b_results) - b_failed,
                    "failed": b_failed,
                },
                "missing": len(missing),
                "cleanup_failed": cleanup_failed,
                "gate": gate,
            },
            "result": {"exit_code": exit_code, "gate": gate},
            "fatal": self.fatal,
            "missing_cases": missing,
            "cleanup": self.cleanup,
            "cases": [result.record() for result in self.results],
        }


def _gate(exit_code: int) -> str:
    return {0: "PASS", 1: "FAIL", 2: "ERROR", 130: "INTERRUPTED"}[exit_code]


# ---------------------------------------------------------------------------
# Section A -- extras against AWS semantics (Rust endpoint only)
# ---------------------------------------------------------------------------

def _case_put_object_acl(runner: Runner, bucket: str, key: str) -> None:
    """PutObjectAcl + GetObjectAcl read back the authorization change.

    AWS semantics:
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectAcl.html
        -- canned ACL via x-amz-acl; success is HTTP 200 with empty body;
           canned "public-read": owner FULL_CONTROL + AllUsers group READ.
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAcl.html
        -- returns AccessControlPolicy (Owner + Grant list).
    The frozen primary records Python 2.33's 501 for this operation; here the
    Rust implementation is accepted per the AWS contract above.
    """
    def fn(case: Case) -> None:
        rust = runner.rust
        path = _path(bucket, key)

        snap = case.request(rust, "get-object-acl-baseline", "GET", path, (("acl", ""),))
        if case.expect_status("get-object-acl-baseline", snap, (200,)):
            case.expect_xml_content_type("get-object-acl-baseline", snap)
            try:
                grants = _acl_grants(snap.body)
                if grants != OWNER_ONLY_GRANTS:
                    case.issue("baseline ACL is not exactly owner FULL_CONTROL: {}".format(grants))
            except SchemaError as exc:
                case.issue("get-object-acl-baseline: body schema: {}".format(exc))

        snap = case.request(rust, "put-object-acl-public-read", "PUT", path,
                            (("acl", ""),), b"",
                            {"X-Amz-Acl": "public-read", "Content-Length": "0"})
        case.expect_status("put-object-acl-public-read", snap, (200,))
        case.expect_empty_body("put-object-acl-public-read", snap)

        snap = case.request(rust, "get-object-acl-readback", "GET", path, (("acl", ""),))
        if case.expect_status("get-object-acl-readback", snap, (200,)):
            case.expect_xml_content_type("get-object-acl-readback", snap)
            try:
                grants = _acl_grants(snap.body)
                case.observed["readback_grants"] = grants
                if grants != PUBLIC_READ_GRANTS:
                    case.issue(
                        "readback grants {} do not show the public-read change "
                        "(expected owner FULL_CONTROL + AllUsers READ)".format(grants))
            except SchemaError as exc:
                case.issue("get-object-acl-readback: body schema: {}".format(exc))

        snap = case.request(rust, "put-object-acl-restore-private", "PUT", path,
                            (("acl", ""),), b"",
                            {"X-Amz-Acl": "private", "Content-Length": "0"})
        case.expect_status("put-object-acl-restore-private", snap, (200,))

        snap = case.request(rust, "get-object-acl-private-again", "GET", path, (("acl", ""),))
        if case.expect_status("get-object-acl-private-again", snap, (200,)):
            try:
                grants = _acl_grants(snap.body)
                if grants != OWNER_ONLY_GRANTS:
                    case.issue("ACL did not return to owner-only after private PUT: {}".format(grants))
            except SchemaError as exc:
                case.issue("get-object-acl-private-again: body schema: {}".format(exc))

    runner.run_case(
        "A", "extras-put-object-acl-readback",
        "AWS PutObjectAcl (200, canned public-read => AllUsers READ grant) + "
        "GetObjectAcl readback; docs.aws.amazon.com/AmazonS3/latest/API/"
        "API_PutObjectAcl.html", fn)


def _case_put_bucket_tagging(runner: Runner, bucket: str) -> None:
    """PutBucketTagging success + GetBucketTagging round-trip.

    AWS semantics:
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html
        -- Response Elements: "an HTTP 200 response with an empty HTTP body";
           the doc's own Sample Response shows "HTTP/1.1 204 No Content".
           Both success forms are accepted; the observed status is recorded.
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html
        -- 200 + Tagging/TagSet.
    """
    def fn(case: Case) -> None:
        rust = runner.rust
        path = _path(bucket)
        snap = case.request(rust, "put-bucket-tagging", "PUT", path, (("tagging", ""),),
                            BUCKET_TAGGING_XML,
                            {"Content-Type": "application/xml",
                             "Content-MD5": _md5_b64(BUCKET_TAGGING_XML)})
        if case.expect_status("put-bucket-tagging", snap, (200, 204)):
            case.observed["put_bucket_tagging_status"] = snap.status
        case.expect_empty_body("put-bucket-tagging", snap)

        snap = case.request(rust, "get-bucket-tagging-readback", "GET", path,
                            (("tagging", ""),))
        if case.expect_status("get-bucket-tagging-readback", snap, (200,)):
            case.expect_xml_content_type("get-bucket-tagging-readback", snap)
            try:
                tags = _tagging_pairs(snap.body)
                case.observed["readback_tags"] = sorted(tags.items())
                if tags != BUCKET_TAGGING_EXPECTED:
                    case.issue("readback TagSet {} != written TagSet {}".format(
                        sorted(tags.items()), sorted(BUCKET_TAGGING_EXPECTED.items())))
            except SchemaError as exc:
                case.issue("get-bucket-tagging-readback: body schema: {}".format(exc))

    runner.run_case(
        "A", "extras-put-bucket-tagging-readback",
        "AWS PutBucketTagging (doc states 200-empty-body, doc sample shows "
        "204; both accepted, observed recorded) + GetBucketTagging round-trip; "
        "docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html", fn)


def _case_delete_bucket_tagging(runner: Runner, bucket: str) -> None:
    """DeleteBucketTagging 204 + GET-after-delete semantics.

    AWS semantics:
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketTagging.html
        -- success is HTTP 204 No Content.
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html
        -- a bucket without a tag set answers 404 NoSuchTagSet.
    The Swift-s3api family (both oracles, proven by the frozen primary's
    PASSing get-empty-bucket-tagging case) instead answers 200 with an empty
    TagSet.  Both shapes prove the delete cleared the tags, so both are
    accepted and the observed semantics recorded; any surviving tag or other
    shape is a FAIL.
    """
    def fn(case: Case) -> None:
        rust = runner.rust
        path = _path(bucket)
        snap = case.request(rust, "delete-bucket-tagging", "DELETE", path,
                            (("tagging", ""),))
        case.expect_status("delete-bucket-tagging", snap, (204,))
        case.expect_empty_body("delete-bucket-tagging", snap)

        snap = case.request(rust, "get-bucket-tagging-after-delete", "GET", path,
                            (("tagging", ""),))
        if snap.status == 404:
            try:
                _strict_error(snap.body, "NoSuchTagSet")
                case.observed["get_after_delete_semantics"] = "aws-exact-nosuchtagset"
            except SchemaError as exc:
                case.issue("get-bucket-tagging-after-delete: 404 body schema: {}".format(exc))
        elif snap.status == 200:
            try:
                tags = _tagging_pairs(snap.body)
                if tags:
                    case.issue("tags survived DeleteBucketTagging: {}".format(sorted(tags.items())))
                else:
                    case.observed["get_after_delete_semantics"] = "swift-family-empty-tagset"
            except SchemaError as exc:
                case.issue("get-bucket-tagging-after-delete: 200 body schema: {}".format(exc))
        else:
            case.issue("get-bucket-tagging-after-delete: status {} is neither AWS 404 "
                       "NoSuchTagSet nor Swift-family 200 empty TagSet".format(snap.status))

    runner.run_case(
        "A", "extras-delete-bucket-tagging-and-get-after",
        "AWS DeleteBucketTagging (204) + GetBucketTagging-after (AWS: 404 "
        "NoSuchTagSet; Swift-family 200 empty TagSet accepted and recorded); "
        "docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketTagging.html", fn)


def _case_delete_object_tagging(runner: Runner, bucket: str, key: str) -> None:
    """Full object-tagging delete lifecycle.

    AWS semantics:
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectTagging.html
        -- success is HTTP 200.
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjectTagging.html
        -- success is HTTP 204 No Content.
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html
        -- 200 + TagSet; an untagged object answers 200 with an empty TagSet
           (unlike bucket tagging there is no NoSuchTagSet here).
    """
    def fn(case: Case) -> None:
        rust = runner.rust
        path = _path(bucket, key)
        snap = case.request(rust, "put-object-tagging", "PUT", path, (("tagging", ""),),
                            OBJECT_TAGGING_XML,
                            {"Content-Type": "application/xml",
                             "Content-MD5": _md5_b64(OBJECT_TAGGING_XML)})
        case.expect_status("put-object-tagging", snap, (200,))

        snap = case.request(rust, "get-object-tagging-readback", "GET", path,
                            (("tagging", ""),))
        if case.expect_status("get-object-tagging-readback", snap, (200,)):
            try:
                tags = _tagging_pairs(snap.body)
                if tags != OBJECT_TAGGING_EXPECTED:
                    case.issue("readback TagSet {} != written TagSet {}".format(
                        sorted(tags.items()), sorted(OBJECT_TAGGING_EXPECTED.items())))
            except SchemaError as exc:
                case.issue("get-object-tagging-readback: body schema: {}".format(exc))

        snap = case.request(rust, "delete-object-tagging", "DELETE", path,
                            (("tagging", ""),))
        case.expect_status("delete-object-tagging", snap, (204,))
        case.expect_empty_body("delete-object-tagging", snap)

        snap = case.request(rust, "get-object-tagging-after-delete", "GET", path,
                            (("tagging", ""),))
        if case.expect_status("get-object-tagging-after-delete", snap, (200,)):
            try:
                tags = _tagging_pairs(snap.body)
                if tags:
                    case.issue("tags survived DeleteObjectTagging: {}".format(sorted(tags.items())))
            except SchemaError as exc:
                case.issue("get-object-tagging-after-delete: body schema: {}".format(exc))

    runner.run_case(
        "A", "extras-delete-object-tagging-lifecycle",
        "AWS PutObjectTagging (200) -> readback -> DeleteObjectTagging (204) "
        "-> GetObjectTagging empty TagSet (200); docs.aws.amazon.com/AmazonS3/"
        "latest/API/API_DeleteObjectTagging.html", fn)


def _case_put_bucket_cors(runner: Runner, bucket: str) -> None:
    """PutBucketCors 200 + GetBucketCors round-trip.

    AWS semantics:
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketCors.html
        -- success is HTTP 200 (Content-MD5 required; sent here).
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketCors.html
        -- 200 + CORSConfiguration with the stored rules.
    """
    def fn(case: Case) -> None:
        rust = runner.rust
        path = _path(bucket)
        snap = case.request(rust, "put-bucket-cors", "PUT", path, (("cors", ""),),
                            CORS_XML,
                            {"Content-Type": "application/xml",
                             "Content-MD5": _md5_b64(CORS_XML)})
        case.expect_status("put-bucket-cors", snap, (200,))
        case.expect_empty_body("put-bucket-cors", snap)

        snap = case.request(rust, "get-bucket-cors-readback", "GET", path, (("cors", ""),))
        if case.expect_status("get-bucket-cors-readback", snap, (200,)):
            case.expect_xml_content_type("get-bucket-cors-readback", snap)
            try:
                rules = _cors_rules(snap.body)
                case.observed["readback_rules"] = rules
                if rules != CORS_EXPECTED_RULES:
                    case.issue("readback CORS rules {} != written rules {}".format(
                        rules, CORS_EXPECTED_RULES))
            except SchemaError as exc:
                case.issue("get-bucket-cors-readback: body schema: {}".format(exc))

    runner.run_case(
        "A", "extras-put-bucket-cors-readback",
        "AWS PutBucketCors (200) + GetBucketCors round-trip; "
        "docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketCors.html", fn)


def _case_delete_bucket_cors(runner: Runner, bucket: str) -> None:
    """DeleteBucketCors 204 + GET-after-delete semantics.

    AWS semantics:
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketCors.html
        -- success is HTTP 204 No Content.
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketCors.html
        -- a bucket without CORS answers 404 NoSuchCORSConfiguration.
    The Rust generation (proven by the frozen primary's postgate evidence:
    GET ?cors before any PUT answered 200 with a CORSConfiguration root)
    follows the Swift-family shape of 200 + empty configuration.  Both shapes
    prove the delete cleared the rules, so both are accepted and recorded;
    any surviving rule or other shape is a FAIL.
    """
    def fn(case: Case) -> None:
        rust = runner.rust
        path = _path(bucket)
        snap = case.request(rust, "delete-bucket-cors", "DELETE", path, (("cors", ""),))
        case.expect_status("delete-bucket-cors", snap, (204,))
        case.expect_empty_body("delete-bucket-cors", snap)

        snap = case.request(rust, "get-bucket-cors-after-delete", "GET", path,
                            (("cors", ""),))
        if snap.status == 404:
            try:
                _strict_error(snap.body, "NoSuchCORSConfiguration")
                case.observed["get_after_delete_semantics"] = "aws-exact-nosuchcors"
            except SchemaError as exc:
                case.issue("get-bucket-cors-after-delete: 404 body schema: {}".format(exc))
        elif snap.status == 200:
            try:
                rules = _cors_rules(snap.body)
                if rules:
                    case.issue("CORS rules survived DeleteBucketCors: {}".format(rules))
                else:
                    case.observed["get_after_delete_semantics"] = "swift-family-empty-config"
            except SchemaError as exc:
                case.issue("get-bucket-cors-after-delete: 200 body schema: {}".format(exc))
        else:
            case.issue("get-bucket-cors-after-delete: status {} is neither AWS 404 "
                       "NoSuchCORSConfiguration nor Swift-family 200 empty "
                       "configuration".format(snap.status))

    runner.run_case(
        "A", "extras-delete-bucket-cors-and-get-after",
        "AWS DeleteBucketCors (204) + GetBucketCors-after (AWS: 404 "
        "NoSuchCORSConfiguration; Swift-family 200 empty config accepted and "
        "recorded); docs.aws.amazon.com/AmazonS3/latest/API/"
        "API_DeleteBucketCors.html", fn)


def _case_restore_standard(runner: Runner, bucket: str, key: str) -> None:
    """RestoreObject on a STANDARD-class object must answer InvalidObjectState.

    AWS semantics:
      https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html
      https://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
        -- restoring an object that is not in an archived storage class is
           rejected with InvalidObjectState ("Restore is not allowed for the
           object's current storage class"); observed on AWS as HTTP 400.
    This equals the honest rejection Peregrine gives while the cold backend
    is disabled, so AWS semantics and the cold-off posture coincide here.
    """
    def fn(case: Case) -> None:
        rust = runner.rust
        snap = case.request(rust, "restore-standard-object", "POST",
                            _path(bucket, key), (("restore", ""),), RESTORE_XML,
                            {"Content-Type": "application/xml"})
        case.expect_error("restore-standard-object", snap, 400, "InvalidObjectState")
        code, message = _error_code(snap.body)
        case.observed["error_code"] = code
        case.observed["error_message"] = message

    runner.run_case(
        "A", "extras-restore-standard-object-invalid-state",
        "AWS RestoreObject on non-archived storage class -> 400 "
        "InvalidObjectState; docs.aws.amazon.com/AmazonS3/latest/API/"
        "API_RestoreObject.html", fn)


# ---------------------------------------------------------------------------
# Section B -- account-root negatives (dual-oracle)
# ---------------------------------------------------------------------------

def _case_account_root(runner: Runner, method: str, case_name: str) -> None:
    """Signed account-root request (bucket=None) against both targets.

    AWS defines no service-root PUT/DELETE/POST operation (the S3 API index
    has only GET / = ListBuckets), so a conforming endpoint rejects these;
    Python 2.33 s3api answers 405 MethodNotAllowed (ServiceController has no
    such handler).  Scoring is dual-oracle: status equality + S3 error Code
    equality, plus a security check that neither side answers 2xx.  A Rust
    2xx means the request was translated onto the Swift account face (in this
    lab a harmless dev-tenant account-metadata touch, but the S3 face must
    reject it); it is recorded as FAIL with the observed behavior described.
    """
    def fn(case: Case) -> None:
        sides: Dict[str, Dict[str, Any]] = {}
        for target in (runner.python, runner.rust):
            step = "{}-account-root-{}".format(target.label, method.lower())
            snap = case.request(target, step, method, "/", (), b"",
                                {"Content-Length": "0"} if method in ("PUT", "POST") else None)
            code, message = _error_code(snap.body)
            body_class = "s3-error-xml" if code is not None else (
                "empty" if not snap.body else "non-s3-xml-or-other")
            sides[target.label] = {
                "status": snap.status,
                "error_code": code,
                "error_message": message,
                "body_class": body_class,
            }
            if 200 <= snap.status < 300:
                case.issue(
                    "{} accepted account-root {} with 2xx status {} -- the "
                    "request reached the account face instead of being "
                    "rejected at the S3 layer (dev-tenant metadata touch; "
                    "harmless in this lab, still a FAIL)".format(
                        target.label, method, snap.status))
        case.observed.update(sides)
        py, rs = sides["python"], sides["rust"]
        if py["status"] != rs["status"]:
            case.issue("status mismatch python={} rust={}".format(
                py["status"], rs["status"]))
        if py["error_code"] != rs["error_code"]:
            case.issue("error code mismatch python={} rust={}".format(
                py["error_code"], rs["error_code"]))

    runner.run_case(
        "B", case_name,
        "No AWS service-root {} exists (S3 API index); conforming endpoints "
        "reject -- Python 2.33 s3api: 405 MethodNotAllowed. Scored as "
        "dual-oracle status+Code equality with a no-2xx security check."
        .format(method), fn)


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------

ACL_KEY = "acl/subject.txt"
TAGGING_KEY = "tagging/subject.txt"
RESTORE_KEY = "restore/subject.txt"
SUBJECT_PAYLOAD = b"peregrine strict S3 supplement subject\n"


def _scenario(runner: Runner) -> None:
    bucket = runner.namespace
    rust = runner.rust

    # Setup (recorded, not scored): the primary runner owns bucket/object CRUD
    # scoring; a setup failure here means "no supplement claim" (exit 2), not
    # a scoreboard FAIL.  Ownership gate: the cryptographically random bucket
    # must 404 before this run may create and later delete it.
    runner.setup_step("rust-ownership-gate", rust, "HEAD", _path(bucket), expect=(404,))
    rust.ownership_clear = True

    rust.creation_attempted = True
    runner.setup_step("rust-create-bucket", rust, "PUT", _path(bucket))
    rust.owned = True
    for key in (ACL_KEY, TAGGING_KEY, RESTORE_KEY):
        rust.known_objects.add(key)
        runner.setup_step("rust-put-{}".format(key.split("/", 1)[0]), rust, "PUT",
                          _path(bucket, key), body=SUBJECT_PAYLOAD,
                          headers={"Content-Type": "application/octet-stream"})

    # Section A -- extras, AWS semantics, Rust only.
    _case_put_object_acl(runner, bucket, ACL_KEY)
    _case_put_bucket_tagging(runner, bucket)
    _case_delete_bucket_tagging(runner, bucket)
    _case_delete_object_tagging(runner, bucket, TAGGING_KEY)
    _case_put_bucket_cors(runner, bucket)
    _case_delete_bucket_cors(runner, bucket)
    _case_restore_standard(runner, bucket, RESTORE_KEY)

    # Section B -- account-root negatives, dual-oracle.
    _case_account_root(runner, "PUT", "negative-account-root-put")
    _case_account_root(runner, "DELETE", "negative-account-root-delete")
    _case_account_root(runner, "POST", "negative-account-root-post")


# ---------------------------------------------------------------------------
# Cleanup ledger (Rust owns the only written namespace; Python gets none)
# ---------------------------------------------------------------------------

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


def _cleanup_rust(target: Target, bucket: str) -> Dict[str, Any]:
    events: List[Dict[str, Any]] = []
    issues: List[str] = []

    def attempt(label: str, method: str, key: Optional[str] = None,
                query: Sequence[Tuple[str, str]] = ()) -> Optional[Snapshot]:
        try:
            snap = target.request(method, _path(bucket, key), query)
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

    # Discovery is limited to the cryptographically unique bucket that passed
    # the 404 ownership gate.  Two bounded rounds; the supplement bucket is
    # unversioned and has no multipart uploads.
    for round_number in range(2):
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

    attempt("delete-bucket", "DELETE")
    final = attempt("final-head", "HEAD")
    final_status = final.status if final is not None else None
    if final_status != 404:
        issues.append("final bucket status is {} rather than 404".format(final_status))
    return {"attempted": True, "passed": not issues, "final_status": final_status,
            "events": events, "issues": issues}


def _run_cleanup(runner: Runner) -> None:
    try:
        runner.cleanup["rust"] = _cleanup_rust(runner.rust, runner.namespace)
    except Exception as exc:
        runner.cleanup["rust"] = {
            "attempted": True, "passed": False, "final_status": None,
            "events": [], "issues": ["unexpected cleanup {}".format(type(exc).__name__)],
        }
    runner.cleanup["python"] = {
        "attempted": False, "passed": True, "final_status": None, "events": [],
        "issues": [], "reason": "account-root-probes-only-no-namespace-written",
    }


# ---------------------------------------------------------------------------
# Report writing (atomic, 0600, REFUSES to overwrite an existing file)
# ---------------------------------------------------------------------------

def _atomic_new_report(path: Path, report: Mapping[str, Any]) -> None:
    path = path.expanduser()
    if path.is_symlink():
        raise ConfigError("JSON report target must not be a symlink")
    if path.exists():
        raise ConfigError(
            "JSON report {} already exists; this scoreboard never overwrites "
            "evidence -- choose a new file name".format(path.name))
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
        # A racing writer between the exists() check and this link is treated
        # as fatal rather than silently replaced.
        os.link(temporary, path)
        os.chmod(path, 0o600)
        try:
            directory_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    except FileExistsError:
        raise ConfigError(
            "JSON report {} appeared during the run; refusing to overwrite".format(path.name))
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _tool_sha256() -> str:
    return hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Configuration validation (family conventions)
# ---------------------------------------------------------------------------

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


def _merge_exit(current: int, candidate: int) -> int:
    priority = {0: 0, 1: 1, 2: 2, 130: 3}
    return candidate if priority[candidate] > priority[current] else current


def _redact(message: str, secrets_to_hide: Sequence[str]) -> str:
    result = message
    for value in sorted((item for item in secrets_to_hide if item), key=len, reverse=True):
        result = result.replace(value, "<redacted>")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--selftest", action="store_true",
                        help="run the offline (no-network) self-test and exit")
    parser.add_argument("--python", help="Python Swift S3 origin (oracle)")
    parser.add_argument("--rust", help="Peregrine Rust S3 origin")
    parser.add_argument("--python-access-env", default="PEREGRINE_S3_PY_ACCESS")
    parser.add_argument("--python-secret-env", default="PEREGRINE_S3_PY_SECRET")
    parser.add_argument("--rust-access-env", default="PEREGRINE_S3_RS_ACCESS")
    parser.add_argument("--rust-secret-env", default="PEREGRINE_S3_RS_SECRET")
    parser.add_argument("--python-region", default="us-east-1")
    parser.add_argument("--rust-region", default="us-east-1")
    parser.add_argument("--python-provenance")
    parser.add_argument("--rust-provenance")
    parser.add_argument("--python-insecure", action="store_true")
    parser.add_argument("--rust-insecure", action="store_true")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-response-bytes", type=int, default=MAX_RESPONSE_BYTES)
    parser.add_argument("--json-report",
                        help="atomic 0600 JSON report path; must not already exist")
    return parser


# ---------------------------------------------------------------------------
# Live entry point
# ---------------------------------------------------------------------------

def _finalize_exit(runner: Runner, exit_code: int) -> int:
    missing = len(runner.results) != len(ALL_CASES)
    failed = any(not result.passed for result in runner.results)
    cleanup_failed = any(not entry.get("passed") for entry in runner.cleanup.values())
    if exit_code not in (EXIT_RUNTIME_FAILURE, EXIT_INTERRUPTED) and (
            missing or failed or cleanup_failed):
        exit_code = _merge_exit(exit_code, EXIT_SUPPLEMENT_FAILURE)
    return exit_code


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.selftest:
        return run_selftest()
    for required in ("python", "rust", "python_provenance", "rust_provenance",
                     "json_report"):
        if getattr(args, required) in (None, ""):
            print("ERROR --{} is required outside --selftest".format(
                required.replace("_", "-")), file=sys.stderr)
            return EXIT_RUNTIME_FAILURE

    report_path = Path(args.json_report)
    runner: Optional[Runner] = None
    exit_code = EXIT_PASS
    secrets_to_hide: List[str] = []
    interrupted = False
    pre_target_fatal: Optional[str] = None

    def on_signal(_signum: int, _frame: Any) -> None:
        nonlocal interrupted
        interrupted = True
        raise Interrupted("validation interrupted")

    previous_int = signal.signal(signal.SIGINT, on_signal)
    previous_term = signal.signal(signal.SIGTERM, on_signal)
    try:
        if report_path.exists() or report_path.is_symlink():
            raise ConfigError(
                "JSON report {} already exists; choose a new file name".format(report_path))
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
        namespace = "peregrine-supp-{}-{}".format(
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
    except (ConfigError, SetupError) as exc:
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
        else:
            pre_target_fatal = _redact(str(exc), secrets_to_hide)
            print("ERROR " + pre_target_fatal, file=sys.stderr)
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
            _run_cleanup(runner)
            exit_code = _finalize_exit(runner, exit_code)
            report = runner.report(exit_code, _tool_sha256())
        else:
            report = {
                "schema": REPORT_SCHEMA,
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tool": {"name": TOOL_NAME, "sha256": _tool_sha256(),
                         "frozen_primary_runner": PRIMARY_RUNNER_FROZEN},
                "scope": {"id": SCOPE_ID, "claim": "NO_CLAIM",
                          "section_a": {"cases": list(SECTION_A_CASES)},
                          "section_b": {"cases": list(SECTION_B_CASES)},
                          "excludes": list(EXCLUSIONS)},
                "summary": {
                    "section_a": {"required": len(SECTION_A_CASES), "executed": 0,
                                  "passed": 0, "failed": 0},
                    "section_b": {"required": len(SECTION_B_CASES), "executed": 0,
                                  "passed": 0, "failed": 0},
                    "missing": len(ALL_CASES), "cleanup_failed": 0,
                    "gate": _gate(exit_code),
                },
                "result": {"exit_code": exit_code, "gate": _gate(exit_code)},
                "fatal": pre_target_fatal or "configuration failed before target construction",
                "missing_cases": list(ALL_CASES), "cleanup": {}, "cases": [],
            }
        try:
            _atomic_new_report(report_path, report)
        except Exception as exc:
            print("ERROR atomic report write failed ({})".format(type(exc).__name__),
                  file=sys.stderr)
            exit_code = _merge_exit(exit_code, EXIT_RUNTIME_FAILURE)
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)

    if runner is not None:
        summary = runner.report(exit_code, "")["summary"]
        print("S3_SUPPLEMENT_SUMMARY gate={} rc={} a={}/{} b={}/{} "
              "a_failed={} b_failed={} missing={} cleanup_failed={} report={}".format(
                  _gate(exit_code), exit_code,
                  summary["section_a"]["executed"], summary["section_a"]["required"],
                  summary["section_b"]["executed"], summary["section_b"]["required"],
                  summary["section_a"]["failed"], summary["section_b"]["failed"],
                  summary["missing"], summary["cleanup_failed"], report_path))
    return EXIT_INTERRUPTED if interrupted else exit_code


# ---------------------------------------------------------------------------
# Offline self-test (--selftest): no sockets, mock targets only
# ---------------------------------------------------------------------------

def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise SelfTestError(message)


def _mock_xml_response(status: int, body: bytes) -> Snapshot:
    return Snapshot(status, {"content-type": ("application/xml",),
                             "content-length": (str(len(body)),)}, body)


def _mock_empty(status: int, extra: Optional[Mapping[str, Tuple[str, ...]]] = None) -> Snapshot:
    headers = {"content-length": ("0",)}
    if extra:
        headers.update(extra)
    return Snapshot(status, headers, b"")


def _mock_error(code: str, status: int) -> Snapshot:
    body = ("<Error><Code>{}</Code><Message>mock</Message>"
            "<RequestId>tx-mock</RequestId></Error>".format(code)).encode()
    return _mock_xml_response(status, body)


def _mock_acl_xml(owner: str, canned: str) -> bytes:
    grants = ('<Grant><Grantee><ID>{0}</ID><DisplayName>{0}</DisplayName>'
              "</Grantee><Permission>FULL_CONTROL</Permission></Grant>").format(owner)
    if canned in ("public-read", "public-read-write"):
        grants += ("<Grant><Grantee><URI>{}</URI></Grantee>"
                   "<Permission>READ</Permission></Grant>").format(ALL_USERS_URI)
    return ("<AccessControlPolicy><Owner><ID>{0}</ID><DisplayName>{0}</DisplayName>"
            "</Owner><AccessControlList>{1}</AccessControlList>"
            "</AccessControlPolicy>").format(owner, grants).encode()


def _mock_tagging_xml(tags: Mapping[str, str]) -> bytes:
    inner = "".join("<Tag><Key>{}</Key><Value>{}</Value></Tag>".format(k, v)
                    for k, v in sorted(tags.items()))
    return "<Tagging><TagSet>{}</TagSet></Tagging>".format(inner).encode()


def _mock_cors_xml(rule: Optional[Mapping[str, Any]]) -> bytes:
    if rule is None:
        return b"<CORSConfiguration></CORSConfiguration>"
    inner = "".join("<AllowedOrigin>{}</AllowedOrigin>".format(o) for o in rule["origins"])
    inner += "".join("<AllowedMethod>{}</AllowedMethod>".format(m) for m in rule["methods"])
    inner += "".join("<AllowedHeader>{}</AllowedHeader>".format(h) for h in rule["headers"])
    inner += "".join("<ExposeHeader>{}</ExposeHeader>".format(e) for e in rule["expose"])
    inner += "<MaxAgeSeconds>{}</MaxAgeSeconds>".format(rule["max_age"])
    return "<CORSConfiguration><CORSRule>{}</CORSRule></CORSConfiguration>".format(inner).encode()


def _mock_listing_xml(bucket: str, keys: Sequence[str]) -> bytes:
    contents = "".join(
        "<Contents><Key>{}</Key><LastModified>2026-08-17T00:00:00.000Z</LastModified>"
        '<ETag>"d41d8cd98f00b204e9800998ecf8427e"</ETag><Size>0</Size>'
        "</Contents>".format(k) for k in keys)
    return ("<ListBucketResult><Name>{}</Name><Prefix></Prefix>"
            "<KeyCount>{}</KeyCount><MaxKeys>1000</MaxKeys>"
            "<IsTruncated>false</IsTruncated>{}</ListBucketResult>"
            .format(bucket, len(keys), contents)).encode()


class _MockRustClient:
    """State machine mirroring the live Rust handlers this tool asserts on.

    ``broken`` flags flip specific behaviors so the self-test can prove the
    scoreboard actually fails when reality diverges:
      restore-200        RestoreObject on STANDARD wrongly answers 200
      root-put-2xx       account-root PUT wrongly answers 201 (account face)
      tagging-delete-200 DeleteBucketTagging wrongly answers 200
    """

    def __init__(self, owner: str = "dev:tester",
                 broken: Iterable[str] = ()) -> None:
        self.owner = owner
        self.broken = frozenset(broken)
        self.bucket: Optional[str] = None
        self.objects: Dict[str, bytes] = {}
        self.object_acl: Dict[str, str] = {}
        self.object_tags: Dict[str, Dict[str, str]] = {}
        self.bucket_tags: Optional[Dict[str, str]] = None
        self.bucket_cors: Optional[Dict[str, Any]] = None

    def request(self, method: str, url: str, body: bytes,
                headers: Mapping[str, str]) -> Snapshot:
        parsed = urlsplit(url)
        path = unquote(parsed.path)
        query: Dict[str, str] = {}
        if parsed.query:
            for chunk in parsed.query.split("&"):
                name, _, value = chunk.partition("=")
                query[unquote(name)] = unquote(value)
        segments = [s for s in path.split("/") if s]
        bucket = segments[0] if segments else None
        key = "/".join(segments[1:]) if len(segments) > 1 else None

        if bucket is None:
            if method in ("GET", "HEAD"):
                return _mock_xml_response(200, (
                    "<ListAllMyBucketsResult><Owner><ID>{0}</ID>"
                    "<DisplayName>{0}</DisplayName></Owner><Buckets>"
                    "</Buckets></ListAllMyBucketsResult>").format(self.owner).encode())
            if method == "PUT" and "root-put-2xx" in self.broken:
                return _mock_empty(201)
            # Gate-generation behavior stand-in for the happy-path self-test:
            # the S3 face rejects account-root writes like the Python oracle.
            return _mock_error("MethodNotAllowed", 405)

        exists = self.bucket == bucket
        if key is None and not any(q in query for q in
                                   ("tagging", "cors", "acl", "restore")):
            if method == "HEAD":
                return _mock_empty(200) if exists else _mock_empty(404)
            if method == "PUT":
                self.bucket = bucket
                return _mock_empty(200)
            if method == "DELETE":
                if not exists:
                    return _mock_error("NoSuchBucket", 404)
                if self.objects:
                    return _mock_error("BucketNotEmpty", 409)
                self.bucket = None
                return _mock_empty(204)
            if method == "GET" and query.get("list-type") == "2":
                if not exists:
                    return _mock_error("NoSuchBucket", 404)
                return _mock_xml_response(200, _mock_listing_xml(
                    bucket, sorted(self.objects)))
        if not exists:
            return _mock_error("NoSuchBucket", 404)

        if "acl" in query and key is not None:
            if method == "GET":
                return _mock_xml_response(200, _mock_acl_xml(
                    self.owner, self.object_acl.get(key, "private")))
            if method == "PUT":
                canned = ""
                for name, value in headers.items():
                    if name.lower() == "x-amz-acl":
                        canned = value
                self.object_acl[key] = canned or "private"
                return _mock_empty(200)
        if "tagging" in query and key is None:
            if method == "PUT":
                self.bucket_tags = dict(_tagging_pairs_from_body(body))
                return _mock_empty(200)
            if method == "GET":
                return _mock_xml_response(200, _mock_tagging_xml(self.bucket_tags or {}))
            if method == "DELETE":
                self.bucket_tags = None
                if "tagging-delete-200" in self.broken:
                    return _mock_empty(200)
                return _mock_empty(204)
        if "tagging" in query and key is not None:
            if method == "PUT":
                self.object_tags[key] = dict(_tagging_pairs_from_body(body))
                return _mock_empty(200)
            if method == "GET":
                return _mock_xml_response(200, _mock_tagging_xml(
                    self.object_tags.get(key, {})))
            if method == "DELETE":
                self.object_tags.pop(key, None)
                return _mock_empty(204)
        if "cors" in query and key is None:
            if method == "PUT":
                rules = _cors_rules(body)
                self.bucket_cors = rules[0] if rules else None
                return _mock_empty(200)
            if method == "GET":
                return _mock_xml_response(200, _mock_cors_xml(self.bucket_cors))
            if method == "DELETE":
                self.bucket_cors = None
                return _mock_empty(204)
        if "restore" in query and key is not None and method == "POST":
            if key not in self.objects:
                return _mock_error("NoSuchKey", 404)
            if "restore-200" in self.broken:
                return _mock_empty(200)
            return _mock_error("InvalidObjectState", 400)

        if key is not None:
            if method == "PUT":
                self.objects[key] = body
                return _mock_empty(200, {"etag": (_md5_etag(body),)})
            if method == "DELETE":
                self.objects.pop(key, None)
                self.object_acl.pop(key, None)
                self.object_tags.pop(key, None)
                return _mock_empty(204)
            if method in ("GET", "HEAD"):
                if key not in self.objects:
                    return _mock_error("NoSuchKey", 404)
                payload = self.objects[key] if method == "GET" else b""
                return Snapshot(200, {"content-length": (str(len(self.objects[key])),),
                                      "etag": (_md5_etag(self.objects[key]),)}, payload)
        return _mock_error("MethodNotAllowed", 405)


def _tagging_pairs_from_body(body: bytes) -> Dict[str, str]:
    try:
        return _tagging_pairs(body)
    except SchemaError:
        return {}


class _MockPythonClient:
    """Python 2.33 oracle stand-in: only the account-root probes reach it."""

    def request(self, method: str, url: str, body: bytes,
                headers: Mapping[str, str]) -> Snapshot:
        parsed = urlsplit(url)
        if unquote(parsed.path) not in ("", "/"):
            raise SelfTestError("self-test python target received a bucket path")
        if method in ("GET", "HEAD"):
            return _mock_xml_response(200, b"<ListAllMyBucketsResult/>")
        # Real Python MethodNotAllowed decorates the Error with Method and
        # ResourceType children; keep them to prove the lenient extractor.
        body_xml = ("<Error><Code>MethodNotAllowed</Code>"
                    "<Message>The specified method is not allowed against this "
                    "resource.</Message><Method>{}</Method>"
                    "<ResourceType>SERVICE</ResourceType>"
                    "<RequestId>tx-mock</RequestId></Error>".format(method)).encode()
        return _mock_xml_response(405, body_xml)


def _selftest_targets(broken: Iterable[str] = ()) -> Tuple[Target, Target]:
    python = Target("python", "http://python.example:8090", "test:tester",
                    "py-secret", "us-east-1", "python@selftest",
                    _MockPythonClient())
    rust = Target("rust", "https://rust.example:8085", "dev:tester",
                  "rs-secret", "us-east-1", "rust@selftest",
                  _MockRustClient(broken=broken))
    return python, rust


def _selftest_run(namespace: str, broken: Iterable[str] = ()) -> Tuple[Runner, int]:
    python, rust = _selftest_targets(broken)
    runner = Runner(namespace, python, rust)
    exit_code = EXIT_PASS
    try:
        _scenario(runner)
    except SetupError as exc:
        runner.fatal = str(exc)
        exit_code = EXIT_RUNTIME_FAILURE
    _run_cleanup(runner)
    return runner, _finalize_exit(runner, exit_code)


def run_selftest() -> int:
    try:
        _selftest_body()
    except SelfTestError as exc:
        print("strict-s3-supplement offline self-test: FAIL -- {}".format(exc),
              file=sys.stderr)
        return EXIT_RUNTIME_FAILURE
    print("strict-s3-supplement offline self-test: PASS")
    return EXIT_PASS


def _selftest_body() -> None:
    import ast

    # The tool itself must carry no assert statements (strippable under -O).
    tree = ast.parse(Path(__file__).resolve().read_text(encoding="utf-8"))
    _expect(not any(isinstance(node, ast.Assert) for node in ast.walk(tree)),
            "tool file contains assert statements")
    _expect(len(ALL_CASES) == len(set(ALL_CASES)) == 10, "case registry is not 7+3 unique")

    # AWS's published SigV4 GET Object vector (same vector the primary
    # runner's self-test pins).
    headers, query = _signed_request(
        method="GET", path="/test.txt", query=(), body=b"",
        headers={"Range": "bytes=0-9"},
        access="AKIAIOSFODNN7EXAMPLE",
        secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region="us-east-1", host="examplebucket.s3.amazonaws.com",
        signed_at=1369353600,
    )
    _expect(not query, "sigv4 header auth must not add query parameters")
    _expect(headers["X-Amz-Date"] == "20130524T000000Z", "sigv4 amz-date differs")
    _expect(headers["Authorization"].endswith(
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"),
        "sigv4 signature differs from the AWS published vector")

    # XML validators are schema validators, not regex scrapes.
    _expect(_tagging_pairs(BUCKET_TAGGING_XML) == BUCKET_TAGGING_EXPECTED,
            "bucket tagging fixture round-trip failed")
    _expect(_cors_rules(CORS_XML) == CORS_EXPECTED_RULES,
            "cors fixture round-trip failed")
    for invalid in (
        b"<Tagging><Unknown/></Tagging>",
        b"<!DOCTYPE x [<!ENTITY y 'z'>]><Tagging><TagSet/></Tagging>",
        b"<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag>"
        b"<Tag><Key>a</Key><Value>c</Value></Tag></TagSet></Tagging>",
    ):
        try:
            _tagging_pairs(invalid)
        except SchemaError:
            pass
        else:
            raise SelfTestError("invalid Tagging XML was accepted")
    _expect(_acl_grants(_mock_acl_xml("o", "public-read")) == PUBLIC_READ_GRANTS,
            "public-read ACL grant extraction failed")
    _expect(_acl_grants(_mock_acl_xml("o", "private")) == OWNER_ONLY_GRANTS,
            "private ACL grant extraction failed")

    # Lenient error extraction tolerates Python's Method/ResourceType extras.
    code, _ = _error_code(
        b"<Error><Code>MethodNotAllowed</Code><Message>x</Message>"
        b"<Method>PUT</Method><ResourceType>SERVICE</ResourceType></Error>")
    _expect(code == "MethodNotAllowed", "lenient error extraction failed")
    _expect(_error_code(b"not xml") == (None, None), "non-XML must yield no code")
    try:
        _strict_error(b"<Error><Code>Wrong</Code><Message>x</Message></Error>",
                      "InvalidObjectState")
    except SchemaError:
        pass
    else:
        raise SelfTestError("strict error accepted a wrong code")

    # Endpoint and namespace guards.
    for invalid_endpoint in ("ftp://swift.example", "http://user:pass@swift.example",
                             "http://swift.example/path", "http://swift.example?x=1"):
        try:
            _validate_endpoint(invalid_endpoint, "test")
        except ConfigError:
            pass
        else:
            raise SelfTestError("unsafe endpoint was accepted")
    _expect(NAMESPACE_RE.fullmatch("peregrine-supp-20260817-0123456789abcdef") is not None,
            "namespace regex rejects the canonical form")
    _expect(NAMESPACE_RE.fullmatch("peregrine-s3-20260817-0123456789abcdef") is None,
            "namespace regex accepts the primary runner's namespace")
    _expect(_merge_exit(0, 1) == 1 and _merge_exit(1, 2) == 2
            and _merge_exit(2, 1) == 2 and _merge_exit(130, 2) == 130,
            "exit merge table differs")

    # Cleanup stop line: never touch a namespace that was not gated+created.
    fresh = Target("rust", "https://rust.example:8085", "dev:tester", "s",
                   "us-east-1", "rust@selftest", _MockRustClient())
    ledger = _cleanup_rust(fresh, "peregrine-supp-20260817-0123456789abcdef")
    _expect(ledger["attempted"] is False and ledger["passed"] is True,
            "cleanup ran without ownership")

    # Happy path: every case passes, cleanup ends at 404, report is written
    # once and never overwritten.
    namespace = "peregrine-supp-20260817-0123456789abcdef"
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        runner, rc = _selftest_run(namespace)
    _expect(rc == EXIT_PASS, "happy-path exit code is {} not 0".format(rc))
    _expect([c.name for c in runner.results] == list(ALL_CASES),
            "executed case names differ from the declared registry")
    _expect(all(c.passed for c in runner.results), "happy-path case failed")
    _expect(runner.cleanup["rust"]["final_status"] == 404,
            "happy-path cleanup did not end at 404")
    tagging_case = next(c for c in runner.results
                        if c.name == "extras-delete-bucket-tagging-and-get-after")
    _expect(tagging_case.observed.get("get_after_delete_semantics")
            == "swift-family-empty-tagset",
            "swift-family tagging semantics were not recorded")
    b_case = next(c for c in runner.results if c.name == "negative-account-root-put")
    _expect(b_case.observed["python"]["error_code"] == "MethodNotAllowed"
            and b_case.observed["rust"]["error_code"] == "MethodNotAllowed",
            "account-root codes were not extracted on both sides")

    report = runner.report(rc, _tool_sha256())
    _expect(report["summary"]["section_a"] == {"required": 7, "executed": 7,
                                               "passed": 7, "failed": 0},
            "section A summary differs")
    _expect(report["summary"]["section_b"] == {"required": 3, "executed": 3,
                                               "passed": 3, "failed": 0},
            "section B summary differs")
    _expect(report["tool"]["sha256"] == _tool_sha256(), "tool hash not embedded")
    _expect(report["targets"]["python"]["provenance"] == "python@selftest"
            and report["targets"]["rust"]["provenance"] == "rust@selftest",
            "both provenance strings must appear in the report")
    serialized = json.dumps(report)
    for secret in ("py-secret", "rs-secret"):
        _expect(secret not in serialized, "credential material leaked into the report")

    import stat
    with tempfile.TemporaryDirectory() as directory:
        destination = Path(directory) / "supplement.json"
        _atomic_new_report(destination, report)
        _expect(stat.S_IMODE(destination.stat().st_mode) == 0o600,
                "report mode is not 0600")
        parsed = json.loads(destination.read_text(encoding="utf-8"))
        _expect(parsed["schema"] == REPORT_SCHEMA, "report schema field differs")
        try:
            _atomic_new_report(destination, report)
        except ConfigError:
            pass
        else:
            raise SelfTestError("existing report was overwritten")
        link = Path(directory) / "link.json"
        link.symlink_to(destination)
        try:
            _atomic_new_report(link, report)
        except ConfigError:
            pass
        else:
            raise SelfTestError("symlink report target was accepted")

    # Broken world: the scoreboard must actually fail and describe why.
    with contextlib.redirect_stdout(io.StringIO()):
        runner, rc = _selftest_run(namespace, broken=(
            "restore-200", "root-put-2xx", "tagging-delete-200"))
    _expect(rc == EXIT_SUPPLEMENT_FAILURE, "broken-path exit code is {} not 1".format(rc))
    by_name = {c.name: c for c in runner.results}
    _expect(not by_name["extras-restore-standard-object-invalid-state"].passed,
            "restore-200 was not caught")
    _expect(not by_name["extras-delete-bucket-tagging-and-get-after"].passed,
            "tagging-delete-200 was not caught")
    root_put = by_name["negative-account-root-put"]
    _expect(not root_put.passed, "root-put-2xx was not caught")
    _expect(any("2xx" in issue for issue in root_put.issues),
            "account-root 2xx security description missing")
    _expect(any("status mismatch" in issue for issue in root_put.issues),
            "account-root status mismatch missing")
    _expect(by_name["extras-put-bucket-cors-readback"].passed,
            "unrelated case was dragged down in the broken world")


if __name__ == "__main__":
    raise SystemExit(main())
