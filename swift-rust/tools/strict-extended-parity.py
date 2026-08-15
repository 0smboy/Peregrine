#!/usr/bin/env python3
"""Strict live parity gate for the comparable extended Swift v1 subset.

This tool exercises Python Swift and Peregrine independently with the same
fixed, externally computed oracles.  It covers the ``ec-2-1`` storage policy,
SLO, DLO, and (only when explicitly enabled) public container-read ACL revoke.
It is intentionally not a general Swift conformance suite.

Safety properties:

* Python 3.9 standard library only.
* Separate credential environment-variable names for Python and Rust.
* Explicit auth, advertised-storage, request origins, account names, and
  provenance for both targets.
* One cryptographically unique namespace shared by the two independent runs.
* Every exact container is proven absent before any write.
* Cleanup deletes only known objects and exact owned containers, then requires
  a final HEAD 404 for every container on every target.
* Tokens, keys, full storage URLs, and response bodies never enter the report.
* The JSON report is written atomically with mode 0600.

The provenance strings are operator-supplied evidence, not automatic
attestation.  Verify source commits, routes, processes, and binary hashes
independently before treating a PASS as release evidence.

Exit codes:
    0  all required cases and cleanup passed
    1  parity, fixed-oracle, coverage, or cleanup failure
    2  configuration, authentication, report, or transport failure
  130  interrupted after cleanup was attempted
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import secrets
import signal
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)


EXIT_PASS = 0
EXIT_PARITY_FAILURE = 1
EXIT_RUNTIME_FAILURE = 2
EXIT_INTERRUPTED = 130
SCOPE_ID = "extended-swift-v1-ec-slo-dlo"
SCOPE_CLAIM = "IMPLEMENTED_SUBSET_ONLY"
EC_POLICY = "ec-2-1"
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
NAMESPACE_PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$")
ACCOUNT_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
NONNEGATIVE_INTEGER_RE = re.compile(r"^[0-9]+$")
MD5_RE = re.compile(r"^[0-9a-f]{32}$")
SECRET_RESPONSE_HEADERS = frozenset(
    {"x-auth-token", "x-storage-token", "x-storage-url"}
)
RANGE_416_BODY = (
    b"<html><h1>Requested Range Not Satisfiable</h1>"
    b"<p>The Range requested is not available.</p></html>"
)
# Python Swift's EC proxy raises HTTPRequestedRangeNotSatisfiable after it
# reconstructs the object length.  That swob exception keeps the object ETag
# and range headers but emits its own HTML media type.  This deliberately
# differs from the replicated-object 416 contract covered by strict-parity.py.
EC_RANGE_416_CONTENT_TYPE = "text/html; charset=UTF-8"

SCOPE_EXCLUDES = (
    "s3-api-and-s3-multipart",
    "nested-slo-inline-slo-heartbeat-and-slo-delete",
    "multi-range-and-multipart-byteranges",
    "slo-dlo-conditional-part-number-and-416-response-contracts",
    "slo-max-segments-reserved-header-client-etag-and-async-delete-negatives",
    "slo-plain-stored-manifest-optional-field-schema-proof-only",
    "etag-wire-quote-formatting-semantic-md5-values-are-compared",
    "dlo-pagination-beyond-the-small-controlled-listing",
    "tempurl-formpost-bulk-staticweb-and-other-middleware",
    "keystone-cross-account-and-non-public-acl-matrices",
    "background-daemons-repair-fault-injection-ha-and-performance",
)

BASE_CASE_NAMES = (
    "tempauth",
    "advertised-storage-head",
    "preflight-ec-container-absent",
    "preflight-segment-container-absent",
    "preflight-large-container-absent",
    "ec-container-create",
    "ec-container-policy-head",
    "ec-object-put-2mib",
    "ec-object-get-2mib",
    "ec-object-head-2mib",
    "ec-object-cross-boundary-range",
    "ec-object-unsatisfiable-range",
    "segment-container-create",
    "segment-put-0001",
    "segment-put-0002",
    "segment-listing-visible",
    "large-container-create",
    "slo-manifest-put",
    "slo-stored-manifest-proof",
    "slo-reassembled-get",
    "slo-reassembled-head",
    "slo-cross-segment-range",
    "slo-raw-manifest-semantic",
    "dlo-manifest-put",
    "dlo-reassembled-get",
    "dlo-reassembled-head",
    "dlo-cross-segment-range",
    "dlo-raw-manifest-get",
)

ACL_CASE_NAMES = (
    "preflight-acl-container-absent",
    "acl-container-create",
    "acl-object-put",
    "acl-public-read-grant",
    "acl-public-read-head",
    "acl-anonymous-get",
    "acl-public-read-revoke",
    "acl-revoked-head",
    "acl-anonymous-get-denied",
)


class ConfigError(RuntimeError):
    """The comparison cannot be run safely with the supplied configuration."""


class TransportError(RuntimeError):
    """A target did not produce a complete HTTP response."""


class ScenarioAbort(RuntimeError):
    """A write prerequisite failed, so dependent requests were not safe."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


@dataclass(frozen=True)
class Snapshot:
    status: int
    headers: Mapping[str, Tuple[str, ...]]
    body: bytes

    def first_header(self, name: str) -> Optional[str]:
        values = self.headers.get(name.lower())
        return values[0] if values else None


@dataclass(frozen=True)
class AuthResult:
    snapshot: Snapshot
    token: str
    storage_path: str
    storage_origin: str


@dataclass
class Target:
    label: str
    endpoint: str
    token: str
    storage_path: str
    client: "HttpClient"
    owned_containers: Set[str] = field(default_factory=set)
    known_objects: Dict[str, Set[str]] = field(default_factory=dict)

    @property
    def storage_base(self) -> str:
        return self.endpoint.rstrip("/") + self.storage_path.rstrip("/")

    def storage_url(
        self,
        container: Optional[str] = None,
        obj: Optional[str] = None,
        query: Optional[Mapping[str, str]] = None,
    ) -> str:
        url = self.storage_base
        if container is not None:
            url += "/" + quote(container, safe="")
        if obj is not None:
            url += "/" + quote(obj, safe="/")
        if query:
            url += "?" + urlencode(query)
        return url

    def request(
        self,
        method: str,
        container: Optional[str] = None,
        obj: Optional[str] = None,
        query: Optional[Mapping[str, str]] = None,
        body: Optional[bytes] = None,
        headers: Optional[Mapping[str, str]] = None,
        authenticated: bool = True,
    ) -> Snapshot:
        request_headers: Dict[str, str] = {}
        if authenticated:
            request_headers["X-Auth-Token"] = self.token
        if headers:
            request_headers.update(headers)
        return self.client.request(
            method,
            self.storage_url(container, obj, query),
            body=body,
            headers=request_headers,
        )

    def own(self, container: str) -> None:
        self.owned_containers.add(container)
        self.known_objects.setdefault(container, set())

    def track(self, container: str, obj: str) -> None:
        self.known_objects.setdefault(container, set()).add(obj)


@dataclass
class CaseResult:
    name: str
    expected_status: int
    body_mode: str
    python: Dict[str, Any]
    rust: Dict[str, Any]
    issues: List[str]

    @property
    def passed(self) -> bool:
        return not self.issues


class HttpClient:
    def __init__(self, timeout: float, max_response_bytes: int, insecure: bool) -> None:
        handlers: List[Any] = [ProxyHandler({}), _NoRedirect()]
        context = (
            ssl._create_unverified_context()  # noqa: SLF001
            if insecure
            else ssl.create_default_context()
        )
        handlers.append(HTTPSHandler(context=context))
        self._opener = build_opener(*handlers)
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes

    def request(
        self,
        method: str,
        url: str,
        body: Optional[bytes] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Snapshot:
        request_headers = {
            "Accept-Encoding": "identity",
            "User-Agent": "peregrine-strict-extended-parity/1",
        }
        if headers:
            request_headers.update(headers)
        if body is not None:
            request_headers.setdefault("Content-Length", str(len(body)))
        request = Request(url=url, data=body, headers=request_headers, method=method)
        try:
            response: Any = self._opener.open(request, timeout=self._timeout)
        except HTTPError as exc:
            response = exc
        except (URLError, http.client.HTTPException, OSError, TimeoutError) as exc:
            raise TransportError(
                "{} request to {} failed ({})".format(
                    method, _safe_origin(url), type(exc).__name__
                )
            ) from exc

        snapshot: Optional[Snapshot] = None
        lifecycle_error: Optional[BaseException] = None
        try:
            body_bytes = response.read(self._max_response_bytes + 1)
            if len(body_bytes) > self._max_response_bytes:
                raise TransportError(
                    "{} response from {} exceeded {} bytes".format(
                        method, _safe_origin(url), self._max_response_bytes
                    )
                )
            normalized: Dict[str, List[str]] = {}
            for name, value in response.headers.raw_items():
                normalized.setdefault(name.strip().lower(), []).append(value.strip())
            snapshot = Snapshot(
                int(response.code),
                {name: tuple(values) for name, values in normalized.items()},
                body_bytes,
            )
        except TransportError as exc:
            lifecycle_error = exc
        except (http.client.HTTPException, OSError, TimeoutError, ValueError) as exc:
            lifecycle_error = exc
        finally:
            try:
                response.close()
            except (http.client.HTTPException, OSError, TimeoutError, ValueError) as exc:
                if lifecycle_error is None:
                    lifecycle_error = exc
        if lifecycle_error is not None:
            if isinstance(lifecycle_error, TransportError):
                raise lifecycle_error
            raise TransportError(
                "{} response from {} failed during read/close ({})".format(
                    method, _safe_origin(url), type(lifecycle_error).__name__
                )
            ) from lifecycle_error
        if snapshot is None:
            raise TransportError(
                "{} response from {} produced no snapshot".format(
                    method, _safe_origin(url)
                )
            )
        return snapshot


class Runner:
    def __init__(self, namespace: str, expected_case_names: Sequence[str]) -> None:
        self.namespace = namespace
        self.expected_case_names = tuple(expected_case_names)
        self.results: List[CaseResult] = []
        self.cleanup_issues: List[str] = []
        self.coverage_issues: List[str] = []
        self.fatal: Optional[str] = None
        self.abort_reason: Optional[str] = None

    @property
    def failed(self) -> bool:
        return (
            any(not item.passed for item in self.results)
            or bool(self.cleanup_issues)
            or bool(self.coverage_issues)
            or self.fatal is not None
        )

    def finalize_coverage(self) -> None:
        actual = [item.name for item in self.results]
        duplicates = sorted({name for name in actual if actual.count(name) > 1})
        missing = [name for name in self.expected_case_names if name not in actual]
        unexpected = [name for name in actual if name not in self.expected_case_names]
        issues: List[str] = []
        if duplicates:
            issues.append("duplicate cases: {}".format(",".join(duplicates)))
        if missing:
            issues.append("missing cases: {}".format(",".join(missing)))
        if unexpected:
            issues.append("unexpected cases: {}".format(",".join(unexpected)))
        self.coverage_issues = issues

    def compare(
        self,
        name: str,
        python: Snapshot,
        rust: Snapshot,
        expected_status: int,
        body_mode: str,
        expected_body: Optional[bytes] = None,
        expected_json: Optional[Any] = None,
        expected_headers: Optional[Mapping[str, str]] = None,
        expected_headers_by_target: Optional[
            Mapping[str, Mapping[str, str]]
        ] = None,
        presence_headers: Sequence[str] = (),
        numeric_headers: Sequence[str] = (),
        md5_headers: Sequence[str] = (),
        absent_or_empty_headers: Sequence[str] = (),
        redacted_headers: Sequence[str] = (),
        body_length_header: bool = False,
        body_md5_etag_header: bool = False,
    ) -> CaseResult:
        issues: List[str] = []
        redacted = frozenset(name.lower() for name in redacted_headers)
        by_target = expected_headers_by_target or {}
        unknown_targets = set(by_target).difference(("python", "rust"))
        if unknown_targets:
            raise ValueError(
                "unknown target-specific header oracle labels: {}".format(
                    ",".join(sorted(unknown_targets))
                )
            )
        common_header_names = {
            header.lower() for header in (expected_headers or {})
        }
        target_header_names = {
            header.lower()
            for values in by_target.values()
            for header in values
        }
        overlap = common_header_names.intersection(target_header_names)
        if overlap:
            raise ValueError(
                "header oracle cannot be both common and target-specific: {}".format(
                    ",".join(sorted(overlap))
                )
            )
        if python.status != rust.status:
            issues.append(
                "status mismatch python={} rust={}".format(python.status, rust.status)
            )
        for label, snapshot in (("python", python), ("rust", rust)):
            if snapshot.status != expected_status:
                issues.append(
                    "{} status {} != fixed oracle {}".format(
                        label, snapshot.status, expected_status
                    )
                )

        body_issues, normalized_bodies = _validate_bodies(
            body_mode, python.body, rust.body, expected_body, expected_json
        )
        issues.extend(body_issues)
        if (
            normalized_bodies.get("python") is not None
            and normalized_bodies.get("rust") is not None
            and normalized_bodies["python"] != normalized_bodies["rust"]
        ):
            issues.append("normalized response bodies differ")

        selected: List[str] = []
        for header, fixed_value in (expected_headers or {}).items():
            key = header.lower()
            selected.append(key)
            try:
                fixed = _normalize_header(key, (fixed_value,))
            except ValueError as exc:
                raise ValueError("invalid fixed header oracle {}: {}".format(key, exc))
            values_by_target: Dict[str, Tuple[str, ...]] = {}
            for label, snapshot in (("python", python), ("rust", rust)):
                values = snapshot.headers.get(key)
                if not values:
                    issues.append("{} missing expected header {}".format(label, key))
                    continue
                try:
                    normalized = _normalize_header(key, values)
                except ValueError as exc:
                    issues.append("{} invalid {} header: {}".format(label, key, exc))
                    continue
                values_by_target[label] = normalized
                if normalized != fixed:
                    display: Any = normalized
                    if key in redacted or key in SECRET_RESPONSE_HEADERS:
                        display = "<redacted>"
                    issues.append(
                        "{} header {} differs from fixed oracle expected={} actual={}".format(
                            label,
                            key,
                            "<redacted>"
                            if key in redacted or key in SECRET_RESPONSE_HEADERS
                            else fixed,
                            display,
                        )
                    )
            if len(values_by_target) == 2 and (
                values_by_target["python"] != values_by_target["rust"]
            ):
                issues.append("header {} differs across targets".format(key))

        for label, snapshot in (("python", python), ("rust", rust)):
            for header, fixed_value in by_target.get(label, {}).items():
                key = header.lower()
                selected.append(key)
                try:
                    fixed = _normalize_header(key, (fixed_value,))
                except ValueError as exc:
                    raise ValueError(
                        "invalid target-specific header oracle {}.{}: {}".format(
                            label, key, exc
                        )
                    )
                values = snapshot.headers.get(key)
                if not values:
                    issues.append(
                        "{} missing target-specific expected header {}".format(
                            label, key
                        )
                    )
                    continue
                try:
                    normalized = _normalize_header(key, values)
                except ValueError as exc:
                    issues.append("{} invalid {} header: {}".format(label, key, exc))
                    continue
                if normalized != fixed:
                    hide = key in redacted or key in SECRET_RESPONSE_HEADERS
                    issues.append(
                        "{} header {} differs from its linked oracle expected={} actual={}".format(
                            label,
                            key,
                            "<redacted>" if hide else fixed,
                            "<redacted>" if hide else normalized,
                        )
                    )

        for header in presence_headers:
            key = header.lower()
            selected.append(key)
            for label, snapshot in (("python", python), ("rust", rust)):
                if not snapshot.headers.get(key):
                    issues.append("{} missing header {}".format(label, key))

        for header in numeric_headers:
            key = header.lower()
            selected.append(key)
            for label, snapshot in (("python", python), ("rust", rust)):
                values = snapshot.headers.get(key)
                if (
                    not values
                    or len(values) != 1
                    or not NONNEGATIVE_INTEGER_RE.fullmatch(values[0])
                ):
                    issues.append(
                        "{} header {} must be one non-negative integer".format(
                            label, key
                        )
                    )

        for header in md5_headers:
            key = header.lower()
            selected.append(key)
            for label, snapshot in (("python", python), ("rust", rust)):
                values = snapshot.headers.get(key)
                if not values or len(values) != 1:
                    issues.append("{} missing one MD5 header {}".format(label, key))
                    continue
                try:
                    _normalize_etag(values[0])
                except ValueError as exc:
                    issues.append("{} invalid {} header: {}".format(label, key, exc))

        for header in absent_or_empty_headers:
            key = header.lower()
            selected.append(key)
            for label, snapshot in (("python", python), ("rust", rust)):
                values = snapshot.headers.get(key)
                if values and any(value != "" for value in values):
                    issues.append(
                        "{} header {} must be absent or empty".format(label, key)
                    )

        if body_length_header:
            selected.append("content-length")
            for label, snapshot in (("python", python), ("rust", rust)):
                values = snapshot.headers.get("content-length")
                fixed = str(len(snapshot.body))
                if not values or len(values) != 1 or values[0] != fixed:
                    issues.append(
                        "{} content-length must equal its response body length {}".format(
                            label, fixed
                        )
                    )

        if body_md5_etag_header:
            selected.append("etag")
            for label, snapshot in (("python", python), ("rust", rust)):
                values = snapshot.headers.get("etag")
                fixed = _md5_hex(snapshot.body)
                if not values or len(values) != 1:
                    issues.append("{} missing response-body ETag".format(label))
                    continue
                try:
                    actual = _normalize_etag(values[0])
                except ValueError as exc:
                    issues.append("{} invalid etag header: {}".format(label, exc))
                    continue
                if actual != fixed:
                    issues.append(
                        "{} ETag must equal MD5 of its response body {}".format(
                            label, fixed
                        )
                    )

        result = CaseResult(
            name=name,
            expected_status=expected_status,
            body_mode=body_mode,
            python=_public_snapshot(python, selected, redacted),
            rust=_public_snapshot(rust, selected, redacted),
            issues=issues,
        )
        self.results.append(result)
        if result.passed:
            print("PASS {:<38} python={} rust={}".format(name, python.status, rust.status))
        else:
            print(
                "FAIL {:<38} python={} rust={} issues={}".format(
                    name, python.status, rust.status, len(issues)
                )
            )
            for issue in issues:
                print("     " + issue)
        return result

    def report(
        self,
        config: "ValidatedConfig",
        exit_code: int,
        oracles: Mapping[str, Any],
    ) -> Dict[str, Any]:
        passed = sum(1 for item in self.results if item.passed)
        failed = len(self.results) - passed
        return {
            "schema": "peregrine.strict-extended-parity.v1",
            "generated_at": _utc_now(),
            "namespace": self.namespace,
            "scope": {
                "id": SCOPE_ID,
                "claim": SCOPE_CLAIM,
                "included": [
                    "ec-2-1-2mib-put-get-head-range-416",
                    "slo-two-segment-put-stored-digest-link-get-head-cross-segment-range-raw",
                    "dlo-two-segment-put-get-head-cross-segment-range-raw",
                ]
                + (["public-read-acl-grant-revoke"] if config.enable_public_acl else []),
                "excludes": list(SCOPE_EXCLUDES),
            },
            "targets": {
                "python": {
                    "auth_origin": config.python_endpoint,
                    "advertised_storage_origin": config.python_storage_origin,
                    "request_origin": config.python_request_origin,
                    "account": config.python_account,
                    "provenance": config.python_provenance,
                },
                "rust": {
                    "auth_origin": config.rust_endpoint,
                    "advertised_storage_origin": config.rust_storage_origin,
                    "request_origin": config.rust_request_origin,
                    "account": config.rust_account,
                    "provenance": config.rust_provenance,
                },
            },
            "configuration": {
                "ec_policy": EC_POLICY,
                "public_acl_enabled": config.enable_public_acl,
                "tls_verification_disabled": config.insecure,
                "credential_env_names": {
                    "python_user": config.python_user_env,
                    "python_key": config.python_key_env,
                    "rust_user": config.rust_user_env,
                    "rust_key": config.rust_key_env,
                },
            },
            "fixed_oracles": dict(oracles),
            "summary": {
                "expected_cases": len(self.expected_case_names),
                "cases": len(self.results),
                "passed": passed,
                "failed": failed,
                "coverage_failed": len(self.coverage_issues),
                "cleanup_failed": len(self.cleanup_issues),
                "gate": _gate_for_exit(exit_code),
            },
            "result": {"exit_code": exit_code, "gate": _gate_for_exit(exit_code)},
            "fatal": self.fatal,
            "abort_reason": self.abort_reason,
            "coverage_issues": list(self.coverage_issues),
            "cleanup_issues": list(self.cleanup_issues),
            "cases": [
                {
                    "name": item.name,
                    "expected_status": item.expected_status,
                    "body_mode": item.body_mode,
                    "python": item.python,
                    "rust": item.rust,
                    "issues": list(item.issues),
                    "gate": "PASS" if item.passed else "FAIL",
                }
                for item in self.results
            ],
        }


@dataclass(frozen=True)
class ValidatedConfig:
    python_endpoint: str
    rust_endpoint: str
    python_storage_origin: str
    rust_storage_origin: str
    python_request_origin: str
    rust_request_origin: str
    python_account: str
    rust_account: str
    python_provenance: str
    rust_provenance: str
    python_user_env: str
    python_key_env: str
    rust_user_env: str
    rust_key_env: str
    namespace_prefix: str
    timeout: float
    consistency_timeout: float
    max_response_bytes: int
    insecure: bool
    enable_public_acl: bool
    json_report: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _merge_exit_code(current: int, candidate: int) -> int:
    priority = {
        EXIT_PASS: 0,
        EXIT_PARITY_FAILURE: 1,
        EXIT_RUNTIME_FAILURE: 2,
        EXIT_INTERRUPTED: 3,
    }
    return candidate if priority[candidate] > priority[current] else current


def _gate_for_exit(exit_code: int) -> str:
    return {
        EXIT_PASS: "PASS",
        EXIT_PARITY_FAILURE: "FAIL",
        EXIT_RUNTIME_FAILURE: "ERROR",
        EXIT_INTERRUPTED: "INTERRUPTED",
    }[exit_code]


def _safe_origin(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or "<invalid-host>"
    try:
        port = parsed.port
    except ValueError:
        port = "<invalid-port>"
    if port is not None:
        host += ":{}".format(port)
    return "{}://{}".format(parsed.scheme, host)


def _origin_identity(raw: str) -> Tuple[str, str, int]:
    parsed = urlsplit(raw)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigError("origin has an invalid port") from exc
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def _validate_endpoint(raw: str, label: str) -> str:
    endpoint = raw.strip().rstrip("/")
    parsed = urlsplit(endpoint)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError("{} must be an absolute http or https origin".format(label))
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError("{} must not contain credentials".format(label))
    if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ConfigError("{} must be an origin without path/query/fragment".format(label))
    try:
        parsed.port
    except ValueError as exc:
        raise ConfigError("{} has an invalid port".format(label)) from exc
    return endpoint


def _validate_account(raw: str, label: str) -> str:
    value = raw.strip()
    if value in ("", ".", "..") or not ACCOUNT_SEGMENT_RE.fullmatch(value):
        raise ConfigError("{} account is not one safe path segment".format(label))
    return value


def _validate_provenance(raw: str, label: str) -> str:
    value = raw.strip()
    if not value or len(value) > 512:
        raise ConfigError("{} provenance must contain 1-512 characters".format(label))
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ConfigError("{} provenance contains a control character".format(label))
    return value


def _validate_env_name(raw: str, label: str) -> str:
    value = raw.strip()
    if not ENV_NAME_RE.fullmatch(value):
        raise ConfigError("{} is not a safe environment-variable name".format(label))
    return value


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise ConfigError("required environment variable {} is not set".format(name))
    if "\r" in value or "\n" in value:
        raise ConfigError("environment variable {} contains a newline".format(name))
    return value


def _canonical_origin(raw: str) -> str:
    parsed = urlsplit(raw)
    return "{}://{}".format(parsed.scheme.lower(), parsed.netloc)


def _authenticate(
    client: HttpClient,
    endpoint: str,
    user: str,
    key: str,
    allowed_storage_origin: str,
    expected_account: str,
) -> AuthResult:
    snapshot = client.request(
        "GET",
        endpoint.rstrip("/") + "/auth/v1.0",
        headers={"X-Auth-User": user, "X-Auth-Key": key},
    )
    token = snapshot.first_header("x-auth-token") or snapshot.first_header(
        "x-storage-token"
    )
    storage_url = snapshot.first_header("x-storage-url")
    if snapshot.status != 200:
        raise ConfigError(
            "authentication at {} returned status {}".format(
                _safe_origin(endpoint), snapshot.status
            )
        )
    if not token or not storage_url:
        raise ConfigError(
            "authentication at {} omitted token or storage URL".format(
                _safe_origin(endpoint)
            )
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in storage_url):
        raise ConfigError("authentication returned a storage URL with controls")
    parsed = urlsplit(storage_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigError("authentication returned a non-absolute storage URL")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError("authentication returned credentials in the storage URL")
    if parsed.query or parsed.fragment:
        raise ConfigError("authentication returned an unsafe storage URL")
    if _origin_identity(storage_url) != _origin_identity(allowed_storage_origin):
        raise ConfigError("authentication returned a storage origin outside the allowlist")
    parts = parsed.path.split("/")
    if len(parts) != 3 or parts[:2] != ["", "v1"]:
        raise ConfigError("authentication returned an invalid storage path")
    account = parts[2]
    if account != expected_account or not ACCOUNT_SEGMENT_RE.fullmatch(account):
        raise ConfigError("authentication returned an unexpected account segment")
    return AuthResult(
        snapshot=snapshot,
        token=token,
        storage_path=parsed.path,
        storage_origin=_canonical_origin(storage_url),
    )


def _split_header_parameters(value: str) -> List[str]:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("contains a control character")
    parts: List[str] = []
    current: List[str] = []
    quoted = False
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif quoted and char == "\\":
            current.append(char)
            escaped = True
        elif char == '"':
            current.append(char)
            quoted = not quoted
        elif char == ";" and not quoted:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quoted or escaped:
        raise ValueError("contains an unterminated quoted string")
    parts.append("".join(current).strip())
    return parts


def _decode_parameter_value(raw: str) -> str:
    if HTTP_TOKEN_RE.fullmatch(raw):
        return raw
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        raise ValueError("contains an invalid parameter value")
    decoded: List[str] = []
    escaped = False
    for char in raw[1:-1]:
        if escaped:
            decoded.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"' or ord(char) < 32 or ord(char) == 127:
            raise ValueError("contains an invalid quoted parameter")
        else:
            decoded.append(char)
    if escaped:
        raise ValueError("contains an unterminated quoted escape")
    return "".join(decoded)


def _normalize_content_type(value: str) -> str:
    parts = _split_header_parameters(value)
    if not parts[0] or parts[0].count("/") != 1:
        raise ValueError("does not contain a valid media type")
    major, minor = parts[0].strip().split("/", 1)
    if not HTTP_TOKEN_RE.fullmatch(major) or not HTTP_TOKEN_RE.fullmatch(minor):
        raise ValueError("does not contain a valid media type")
    parameters: List[Tuple[str, str]] = []
    seen: Set[str] = set()
    for parameter in parts[1:]:
        if not parameter or "=" not in parameter:
            raise ValueError("contains an invalid parameter")
        raw_key, raw_value = parameter.split("=", 1)
        key = raw_key.strip().lower()
        if not HTTP_TOKEN_RE.fullmatch(key) or key in seen:
            raise ValueError("contains an invalid or duplicate parameter name")
        seen.add(key)
        parameters.append((key, _decode_parameter_value(raw_value.strip())))
    return json.dumps(
        ["{}/{}".format(major.lower(), minor.lower()), sorted(parameters)],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _normalize_etag(value: str) -> str:
    normalized = value.strip()
    if len(normalized) > 1 and normalized.startswith('"') and normalized.endswith('"'):
        normalized = normalized[1:-1]
    normalized = normalized.lower()
    if not MD5_RE.fullmatch(normalized):
        raise ValueError("must be one MD5 hex value, optionally quoted")
    return normalized


def _normalize_header(name: str, values: Sequence[str]) -> Tuple[str, ...]:
    normalized: List[str] = []
    for raw in values:
        value = raw.strip()
        if name == "content-type":
            value = _normalize_content_type(value)
        elif name == "etag":
            value = _normalize_etag(value)
        elif name in ("x-static-large-object", "accept-ranges"):
            value = value.lower()
        normalized.append(value)
    return tuple(sorted(normalized))


def _md5_hex(body: bytes) -> str:
    try:
        return hashlib.md5(body, usedforsecurity=False).hexdigest()
    except TypeError:
        return hashlib.md5(body).hexdigest()  # noqa: S324


def _sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _repeat_to_length(seed: bytes, length: int) -> bytes:
    if not seed or length < 0:
        raise ValueError("invalid deterministic payload request")
    return (seed * ((length + len(seed) - 1) // len(seed)))[:length]


def _payloads() -> Tuple[bytes, bytes, bytes]:
    ec = _repeat_to_length(b"PEREGRINE-EC-2-1\x00\xff", 2 * 1024 * 1024)
    segment_one = _repeat_to_length(b"PEREGRINE-SLO-DLO-SEGMENT-ONE\n", 1024 * 1024)
    segment_two = _repeat_to_length(b"PEREGRINE-SLO-DLO-SEGMENT-TWO\r\n", 1024 * 1024)
    return ec, segment_one, segment_two


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _normalize_slo_raw(body: bytes, expected: Any) -> bytes:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("is not UTF-8 JSON") from exc
    if not isinstance(value, list):
        raise ValueError("root must be an array")
    normalized: List[Dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"path", "etag", "size_bytes"}:
            raise ValueError("entries must contain exactly path, etag, size_bytes")
        if not isinstance(entry["path"], str):
            raise ValueError("path must be a string")
        if isinstance(entry["size_bytes"], bool) or not isinstance(entry["size_bytes"], int):
            raise ValueError("size_bytes must be an integer")
        if not isinstance(entry["etag"], str):
            raise ValueError("etag must be a string")
        normalized.append(
            {
                "path": entry["path"],
                "etag": _normalize_etag(entry["etag"]),
                "size_bytes": entry["size_bytes"],
            }
        )
    canonical = _canonical_json(normalized)
    if canonical != _canonical_json(expected):
        raise ValueError("semantic value differs from fixed manifest oracle")
    return canonical


def _normalize_slo_stored_proof(body: bytes, expected: Any) -> bytes:
    """Normalize only stable stored-manifest fields used as digest evidence.

    Python persists content_type and last_modified while the Rust
    implementation currently persists only the core fields.  This proof is
    deliberately not a stored-schema parity claim: it binds each target's
    physical manifest body to its own ETag, then binds that ETag to the public
    X-Manifest-Etag returned by reassembled reads.
    """
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("is not UTF-8 JSON") from exc
    if not isinstance(value, list):
        raise ValueError("root must be an array")
    allowed = {
        "name",
        "hash",
        "bytes",
        "content_type",
        "last_modified",
        "range",
        "sub_slo",
    }
    required = {"name", "hash", "bytes"}
    normalized: List[Dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise ValueError("entries must be objects")
        keys = set(entry)
        if not required.issubset(keys) or not keys.issubset(allowed):
            raise ValueError("stored entry has an unexpected schema")
        if not isinstance(entry["name"], str) or not isinstance(entry["hash"], str):
            raise ValueError("stored name/hash must be strings")
        if isinstance(entry["bytes"], bool) or not isinstance(entry["bytes"], int):
            raise ValueError("stored bytes must be an integer")
        if "content_type" in entry:
            if not isinstance(entry["content_type"], str):
                raise ValueError("stored content_type must be a string")
            if _normalize_content_type(entry["content_type"]) != _normalize_content_type(
                "application/octet-stream"
            ):
                raise ValueError("stored content_type differs from segment oracle")
        if "last_modified" in entry and (
            not isinstance(entry["last_modified"], str)
            or not entry["last_modified"]
        ):
            raise ValueError("stored last_modified must be a non-empty string")
        if "range" in entry or "sub_slo" in entry:
            raise ValueError("controlled stored entry unexpectedly has range/sub_slo")
        normalized.append(
            {
                "name": entry["name"],
                "hash": _normalize_etag(entry["hash"]),
                "bytes": entry["bytes"],
            }
        )
    canonical = _canonical_json(normalized)
    if canonical != _canonical_json(expected):
        raise ValueError("semantic value differs from fixed stored-manifest oracle")
    return canonical


def _normalize_segment_listing(body: bytes, expected: Any) -> bytes:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("is not UTF-8 JSON") from exc
    if not isinstance(value, list):
        raise ValueError("root must be an array")
    normalized: List[Dict[str, Any]] = []
    for entry in value:
        required = {"name", "hash", "bytes", "content_type", "last_modified"}
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError("listing entry has an unexpected schema")
        if not isinstance(entry["last_modified"], str) or not entry["last_modified"]:
            raise ValueError("last_modified must be a non-empty string")
        if not isinstance(entry["name"], str) or not isinstance(entry["hash"], str):
            raise ValueError("listing name/hash must be strings")
        if isinstance(entry["bytes"], bool) or not isinstance(entry["bytes"], int):
            raise ValueError("listing bytes must be an integer")
        if not isinstance(entry["content_type"], str):
            raise ValueError("listing content_type must be a string")
        normalized.append(
            {
                "name": entry["name"],
                "hash": _normalize_etag(entry["hash"]),
                "bytes": entry["bytes"],
                "content_type": _normalize_content_type(entry["content_type"]),
            }
        )
    normalized.sort(key=lambda item: item["name"])
    canonical = _canonical_json(normalized)
    if canonical != _canonical_json(expected):
        raise ValueError("semantic value differs from fixed listing oracle")
    return canonical


def _validate_bodies(
    mode: str,
    python: bytes,
    rust: bytes,
    expected_body: Optional[bytes],
    expected_json: Optional[Any],
) -> Tuple[List[str], Dict[str, Optional[bytes]]]:
    issues: List[str] = []
    normalized: Dict[str, Optional[bytes]] = {"python": None, "rust": None}
    if mode == "empty":
        fixed = b""
        for label, body in (("python", python), ("rust", rust)):
            if body != fixed:
                issues.append("{} body expected empty, length={}".format(label, len(body)))
            normalized[label] = body
        return issues, normalized
    if mode == "exact":
        if expected_body is None:
            raise ValueError("exact body mode requires a fixed oracle")
        for label, body in (("python", python), ("rust", rust)):
            if body != expected_body:
                issues.append(
                    "{} body differs from fixed oracle expected_len={} expected_sha256={} actual_len={} actual_sha256={}".format(
                        label,
                        len(expected_body),
                        _sha256_hex(expected_body),
                        len(body),
                        _sha256_hex(body),
                    )
                )
            normalized[label] = body
        return issues, normalized
    if mode in (
        "slo-raw-json",
        "slo-stored-proof-json",
        "segment-listing-json",
    ):
        if expected_json is None:
            raise ValueError("semantic JSON body mode requires a fixed oracle")
        if mode == "slo-raw-json":
            parser = _normalize_slo_raw
        elif mode == "slo-stored-proof-json":
            parser = _normalize_slo_stored_proof
        else:
            parser = _normalize_segment_listing
        for label, body in (("python", python), ("rust", rust)):
            try:
                normalized[label] = parser(body, expected_json)
            except ValueError as exc:
                issues.append("{} body {}".format(label, exc))
        return issues, normalized
    raise ValueError("unknown body mode {}".format(mode))


def _public_snapshot(
    snapshot: Snapshot,
    selected_headers: Sequence[str],
    redacted_headers: Set[str],
) -> Dict[str, Any]:
    public: Dict[str, Any] = {}
    for name in dict.fromkeys(selected_headers):
        values = snapshot.headers.get(name)
        if not values:
            public[name] = None
        elif name in redacted_headers or name in SECRET_RESPONSE_HEADERS:
            public[name] = "<present>"
        else:
            public[name] = list(values)
    return {
        "status": snapshot.status,
        "headers": public,
        "body_len": len(snapshot.body),
        "body_sha256": _sha256_hex(snapshot.body),
    }


def _request_pair(
    runner: Runner,
    python: Target,
    rust: Target,
    name: str,
    method: str,
    expected_status: int,
    body_mode: str,
    container: Optional[str] = None,
    obj: Optional[str] = None,
    query: Optional[Mapping[str, str]] = None,
    body: Optional[bytes] = None,
    headers: Optional[Mapping[str, str]] = None,
    authenticated: bool = True,
    expected_body: Optional[bytes] = None,
    expected_json: Optional[Any] = None,
    expected_headers: Optional[Mapping[str, str]] = None,
    expected_headers_by_target: Optional[
        Mapping[str, Mapping[str, str]]
    ] = None,
    presence_headers: Sequence[str] = (),
    numeric_headers: Sequence[str] = (),
    md5_headers: Sequence[str] = (),
    absent_or_empty_headers: Sequence[str] = (),
    body_length_header: bool = False,
    body_md5_etag_header: bool = False,
    capture_snapshots: bool = False,
) -> Any:
    py = python.request(
        method,
        container=container,
        obj=obj,
        query=query,
        body=body,
        headers=headers,
        authenticated=authenticated,
    )
    rs = rust.request(
        method,
        container=container,
        obj=obj,
        query=query,
        body=body,
        headers=headers,
        authenticated=authenticated,
    )
    result = runner.compare(
        name,
        py,
        rs,
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
        return result, py, rs
    return result


def _both_status(result: CaseResult, status: int) -> bool:
    return result.python["status"] == status and result.rust["status"] == status


def _listing_matches(snapshot: Snapshot, expected: Any) -> bool:
    if snapshot.status != 200:
        return False
    try:
        _normalize_segment_listing(snapshot.body, expected)
    except ValueError:
        return False
    return True


def _wait_for_listing(
    target: Target,
    container: str,
    prefix: str,
    expected: Any,
    timeout: float,
) -> Snapshot:
    deadline = time.monotonic() + timeout
    last: Optional[Snapshot] = None
    while True:
        last = target.request(
            "GET",
            container=container,
            query={"format": "json", "prefix": prefix},
        )
        if _listing_matches(last, expected):
            return last
        if time.monotonic() >= deadline:
            return last
        time.sleep(0.25)


def _run_scenario(
    runner: Runner,
    python: Target,
    rust: Target,
    consistency_timeout: float,
    enable_public_acl: bool,
) -> Mapping[str, Any]:
    namespace = runner.namespace
    containers = {
        "ec": namespace + "-ec",
        "segments": namespace + "-segments",
        "large": namespace + "-large",
        "acl": namespace + "-acl",
    }
    ec_obj = "ec-2mib.bin"
    segment_names = ("part-0001", "part-0002")
    slo_obj = "slo.bin"
    dlo_obj = "dlo.bin"
    acl_obj = "public.txt"
    ec_payload, segment_one, segment_two = _payloads()
    segments = (segment_one, segment_two)
    assembled = segment_one + segment_two
    ec_etag = _md5_hex(ec_payload)
    segment_etags = tuple(_md5_hex(item) for item in segments)
    aggregate_etag = _md5_hex("".join(segment_etags).encode("ascii"))
    boundary_start = len(segment_one) - 32
    boundary_end = len(segment_one) + 31
    boundary_body = assembled[boundary_start : boundary_end + 1]
    ec_range_start = 1024 * 1024 - 24
    ec_range_end = 1024 * 1024 + 39
    ec_range_body = ec_payload[ec_range_start : ec_range_end + 1]
    fixed_slo_raw = [
        {
            "path": "/{}/{}".format(containers["segments"], name),
            "etag": etag,
            "size_bytes": len(payload),
        }
        for name, etag, payload in zip(segment_names, segment_etags, segments)
    ]
    fixed_slo_stored = [
        {
            "name": entry["path"],
            "hash": entry["etag"],
            "bytes": entry["size_bytes"],
        }
        for entry in fixed_slo_raw
    ]
    fixed_listing = [
        {
            "name": name,
            "hash": etag,
            "bytes": len(payload),
            "content_type": _normalize_content_type("application/octet-stream"),
        }
        for name, etag, payload in zip(segment_names, segment_etags, segments)
    ]

    preflights = [
        ("preflight-ec-container-absent", containers["ec"]),
        ("preflight-segment-container-absent", containers["segments"]),
        ("preflight-large-container-absent", containers["large"]),
    ]
    if enable_public_acl:
        preflights.append(("preflight-acl-container-absent", containers["acl"]))
    for name, container in preflights:
        result = _request_pair(
            runner,
            python,
            rust,
            name,
            "HEAD",
            404,
            "empty",
            container=container,
        )
        if not _both_status(result, 404) or not result.passed:
            raise ScenarioAbort("namespace ownership preflight failed; no writes were made")
    for target in (python, rust):
        for _, container in preflights:
            target.own(container)

    result = _request_pair(
        runner,
        python,
        rust,
        "ec-container-create",
        "PUT",
        201,
        "empty",
        container=containers["ec"],
        body=b"",
        headers={"X-Storage-Policy": EC_POLICY},
    )
    if not _both_status(result, 201):
        raise ScenarioAbort("EC container creation failed")
    _request_pair(
        runner,
        python,
        rust,
        "ec-container-policy-head",
        "HEAD",
        204,
        "empty",
        container=containers["ec"],
        expected_headers={"X-Storage-Policy": EC_POLICY},
    )
    for target in (python, rust):
        target.track(containers["ec"], ec_obj)
    result = _request_pair(
        runner,
        python,
        rust,
        "ec-object-put-2mib",
        "PUT",
        201,
        "empty",
        container=containers["ec"],
        obj=ec_obj,
        body=ec_payload,
        headers={"Content-Type": "application/octet-stream"},
        expected_headers={"Etag": ec_etag},
    )
    if not _both_status(result, 201):
        raise ScenarioAbort("EC object PUT failed")
    object_headers = {
        "Etag": ec_etag,
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(ec_payload)),
        "Accept-Ranges": "bytes",
    }
    _request_pair(
        runner,
        python,
        rust,
        "ec-object-get-2mib",
        "GET",
        200,
        "exact",
        container=containers["ec"],
        obj=ec_obj,
        expected_body=ec_payload,
        expected_headers=object_headers,
    )
    _request_pair(
        runner,
        python,
        rust,
        "ec-object-head-2mib",
        "HEAD",
        200,
        "empty",
        container=containers["ec"],
        obj=ec_obj,
        expected_headers=object_headers,
    )
    _request_pair(
        runner,
        python,
        rust,
        "ec-object-cross-boundary-range",
        "GET",
        206,
        "exact",
        container=containers["ec"],
        obj=ec_obj,
        headers={"Range": "bytes={}-{}".format(ec_range_start, ec_range_end)},
        expected_body=ec_range_body,
        expected_headers={
            "Etag": ec_etag,
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(ec_range_body)),
            "Content-Range": "bytes {}-{}/{}".format(
                ec_range_start, ec_range_end, len(ec_payload)
            ),
            "Accept-Ranges": "bytes",
        },
    )
    _request_pair(
        runner,
        python,
        rust,
        "ec-object-unsatisfiable-range",
        "GET",
        416,
        "exact",
        container=containers["ec"],
        obj=ec_obj,
        headers={"Range": "bytes={}-{}".format(len(ec_payload) + 9, len(ec_payload) + 19)},
        expected_body=RANGE_416_BODY,
        expected_headers={
            "Etag": ec_etag,
            "Content-Type": EC_RANGE_416_CONTENT_TYPE,
            "Content-Length": str(len(RANGE_416_BODY)),
            "Content-Range": "bytes */{}".format(len(ec_payload)),
            "Accept-Ranges": "bytes",
        },
    )

    result = _request_pair(
        runner,
        python,
        rust,
        "segment-container-create",
        "PUT",
        201,
        "empty",
        container=containers["segments"],
        body=b"",
    )
    if not _both_status(result, 201):
        raise ScenarioAbort("segment container creation failed")
    for index, (name, payload, etag) in enumerate(
        zip(segment_names, segments, segment_etags), 1
    ):
        for target in (python, rust):
            target.track(containers["segments"], name)
        result = _request_pair(
            runner,
            python,
            rust,
            "segment-put-{:04d}".format(index),
            "PUT",
            201,
            "empty",
            container=containers["segments"],
            obj=name,
            body=payload,
            headers={"Content-Type": "application/octet-stream"},
            expected_headers={"Etag": etag},
        )
        if not _both_status(result, 201):
            raise ScenarioAbort("segment PUT failed")

    py_listing = _wait_for_listing(
        python,
        containers["segments"],
        "part-",
        fixed_listing,
        consistency_timeout,
    )
    rs_listing = _wait_for_listing(
        rust,
        containers["segments"],
        "part-",
        fixed_listing,
        consistency_timeout,
    )
    listing_result = runner.compare(
        "segment-listing-visible",
        py_listing,
        rs_listing,
        200,
        "segment-listing-json",
        expected_json=fixed_listing,
        expected_headers={"Content-Type": "application/json; charset=utf-8"},
    )
    if not listing_result.passed:
        raise ScenarioAbort("segment listing did not converge to the fixed oracle")

    result = _request_pair(
        runner,
        python,
        rust,
        "large-container-create",
        "PUT",
        201,
        "empty",
        container=containers["large"],
        body=b"",
    )
    if not _both_status(result, 201):
        raise ScenarioAbort("large-object container creation failed")

    slo_manifest = _canonical_json(fixed_slo_raw)
    for target in (python, rust):
        target.track(containers["large"], slo_obj)
    slo_put = _request_pair(
        runner,
        python,
        rust,
        "slo-manifest-put",
        "PUT",
        201,
        "empty",
        container=containers["large"],
        obj=slo_obj,
        query={"multipart-manifest": "put"},
        body=slo_manifest,
        headers={"Content-Type": "application/octet-stream"},
        expected_headers={"Etag": aggregate_etag},
    )
    if _both_status(slo_put, 201):
        stored_result, py_stored, rs_stored = _request_pair(
            runner,
            python,
            rust,
            "slo-stored-manifest-proof",
            "GET",
            200,
            "slo-stored-proof-json",
            container=containers["large"],
            obj=slo_obj,
            query={"multipart-manifest": "get"},
            expected_json=fixed_slo_stored,
            expected_headers={"Content-Type": "application/json; charset=utf-8"},
            body_length_header=True,
            body_md5_etag_header=True,
            capture_snapshots=True,
        )
        manifest_etags: Dict[str, str] = {}
        for label, snapshot in (("python", py_stored), ("rust", rs_stored)):
            values = snapshot.headers.get("etag")
            try:
                if not values or len(values) != 1:
                    raise ValueError("missing one ETag")
                manifest_etags[label] = _normalize_etag(values[0])
            except ValueError:
                # The proof case is already red.  Keep later safe read cases
                # observable without allowing a missing digest to become a
                # runtime/configuration failure.
                manifest_etags[label] = "0" * 32
        if not stored_result.passed:
            runner.abort_reason = (
                "stored SLO manifest proof failed; the overall gate remains red"
            )
        linked_manifest_headers = {
            "python": {"X-Manifest-Etag": manifest_etags["python"]},
            "rust": {"X-Manifest-Etag": manifest_etags["rust"]},
        }
        large_headers = {
            "Etag": aggregate_etag,
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(assembled)),
            "Accept-Ranges": "bytes",
            "X-Static-Large-Object": "true",
        }
        _request_pair(
            runner,
            python,
            rust,
            "slo-reassembled-get",
            "GET",
            200,
            "exact",
            container=containers["large"],
            obj=slo_obj,
            expected_body=assembled,
            expected_headers=large_headers,
            expected_headers_by_target=linked_manifest_headers,
        )
        _request_pair(
            runner,
            python,
            rust,
            "slo-reassembled-head",
            "HEAD",
            200,
            "empty",
            container=containers["large"],
            obj=slo_obj,
            expected_headers=large_headers,
            expected_headers_by_target=linked_manifest_headers,
        )
        _request_pair(
            runner,
            python,
            rust,
            "slo-cross-segment-range",
            "GET",
            206,
            "exact",
            container=containers["large"],
            obj=slo_obj,
            headers={"Range": "bytes={}-{}".format(boundary_start, boundary_end)},
            expected_body=boundary_body,
            expected_headers={
                "Etag": aggregate_etag,
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(boundary_body)),
                "Content-Range": "bytes {}-{}/{}".format(
                    boundary_start, boundary_end, len(assembled)
                ),
                "Accept-Ranges": "bytes",
                "X-Static-Large-Object": "true",
            },
            expected_headers_by_target=linked_manifest_headers,
        )
        _request_pair(
            runner,
            python,
            rust,
            "slo-raw-manifest-semantic",
            "GET",
            200,
            "slo-raw-json",
            container=containers["large"],
            obj=slo_obj,
            query={"multipart-manifest": "get", "format": "raw"},
            expected_json=fixed_slo_raw,
            expected_headers={
                "Content-Type": "application/octet-stream",
                "X-Static-Large-Object": "true",
            },
            absent_or_empty_headers=("X-Manifest-Etag",),
            body_length_header=True,
            body_md5_etag_header=True,
        )
    else:
        runner.abort_reason = "SLO manifest creation failed; dependent SLO cases skipped"

    for target in (python, rust):
        target.track(containers["large"], dlo_obj)
    dlo_put = _request_pair(
        runner,
        python,
        rust,
        "dlo-manifest-put",
        "PUT",
        201,
        "empty",
        container=containers["large"],
        obj=dlo_obj,
        body=b"",
        headers={
            "Content-Type": "application/octet-stream",
            "X-Object-Manifest": "{}/part-".format(containers["segments"]),
        },
        expected_headers={"Etag": _md5_hex(b"")},
    )
    if _both_status(dlo_put, 201):
        dlo_headers = {
            "Etag": aggregate_etag,
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(assembled)),
            "Accept-Ranges": "bytes",
            "X-Object-Manifest": "{}/part-".format(containers["segments"]),
        }
        _request_pair(
            runner,
            python,
            rust,
            "dlo-reassembled-get",
            "GET",
            200,
            "exact",
            container=containers["large"],
            obj=dlo_obj,
            expected_body=assembled,
            expected_headers=dlo_headers,
        )
        _request_pair(
            runner,
            python,
            rust,
            "dlo-reassembled-head",
            "HEAD",
            200,
            "empty",
            container=containers["large"],
            obj=dlo_obj,
            expected_headers=dlo_headers,
        )
        _request_pair(
            runner,
            python,
            rust,
            "dlo-cross-segment-range",
            "GET",
            206,
            "exact",
            container=containers["large"],
            obj=dlo_obj,
            headers={"Range": "bytes={}-{}".format(boundary_start, boundary_end)},
            expected_body=boundary_body,
            expected_headers={
                "Etag": aggregate_etag,
                "Content-Type": "application/octet-stream",
                "Content-Length": str(len(boundary_body)),
                "Content-Range": "bytes {}-{}/{}".format(
                    boundary_start, boundary_end, len(assembled)
                ),
                "Accept-Ranges": "bytes",
                "X-Object-Manifest": "{}/part-".format(containers["segments"]),
            },
        )
        _request_pair(
            runner,
            python,
            rust,
            "dlo-raw-manifest-get",
            "GET",
            200,
            "exact",
            container=containers["large"],
            obj=dlo_obj,
            query={"multipart-manifest": "get"},
            expected_body=b"",
            expected_headers={
                "Etag": _md5_hex(b""),
                "Content-Type": "application/octet-stream",
                "Content-Length": "0",
                "X-Object-Manifest": "{}/part-".format(containers["segments"]),
            },
        )
    else:
        runner.abort_reason = "DLO manifest creation failed; dependent DLO cases skipped"

    if enable_public_acl:
        acl_payload = b"peregrine-public-acl-proof\n"
        result = _request_pair(
            runner,
            python,
            rust,
            "acl-container-create",
            "PUT",
            201,
            "empty",
            container=containers["acl"],
            body=b"",
        )
        if not _both_status(result, 201):
            raise ScenarioAbort("ACL container creation failed")
        for target in (python, rust):
            target.track(containers["acl"], acl_obj)
        result = _request_pair(
            runner,
            python,
            rust,
            "acl-object-put",
            "PUT",
            201,
            "empty",
            container=containers["acl"],
            obj=acl_obj,
            body=acl_payload,
            headers={"Content-Type": "text/plain"},
            expected_headers={"Etag": _md5_hex(acl_payload)},
        )
        if not _both_status(result, 201):
            raise ScenarioAbort("ACL object PUT failed")
        _request_pair(
            runner,
            python,
            rust,
            "acl-public-read-grant",
            "POST",
            204,
            "empty",
            container=containers["acl"],
            body=b"",
            headers={"X-Container-Read": ".r:*"},
        )
        _request_pair(
            runner,
            python,
            rust,
            "acl-public-read-head",
            "HEAD",
            204,
            "empty",
            container=containers["acl"],
            expected_headers={"X-Container-Read": ".r:*"},
        )
        _request_pair(
            runner,
            python,
            rust,
            "acl-anonymous-get",
            "GET",
            200,
            "exact",
            container=containers["acl"],
            obj=acl_obj,
            authenticated=False,
            expected_body=acl_payload,
            expected_headers={
                "Etag": _md5_hex(acl_payload),
                "Content-Type": "text/plain",
                "Content-Length": str(len(acl_payload)),
            },
        )
        _request_pair(
            runner,
            python,
            rust,
            "acl-public-read-revoke",
            "POST",
            204,
            "empty",
            container=containers["acl"],
            body=b"",
            headers={"X-Remove-Container-Read": "true"},
        )
        _request_pair(
            runner,
            python,
            rust,
            "acl-revoked-head",
            "HEAD",
            204,
            "empty",
            container=containers["acl"],
            absent_or_empty_headers=("X-Container-Read",),
        )
        _request_pair(
            runner,
            python,
            rust,
            "acl-anonymous-get-denied",
            "GET",
            401,
            "exact",
            container=containers["acl"],
            obj=acl_obj,
            authenticated=False,
            expected_body=(
                b"<html><h1>Unauthorized</h1><p>This server could not verify "
                b"that you are authorized to access the document you "
                b"requested.</p></html>"
            ),
            expected_headers={
                "Content-Type": "text/html; charset=UTF-8",
                "Content-Length": "131",
            },
            presence_headers=("Www-Authenticate",),
        )

    return {
        "ec": {
            "bytes": len(ec_payload),
            "md5": ec_etag,
            "sha256": _sha256_hex(ec_payload),
            "range": "{}-{}".format(ec_range_start, ec_range_end),
            "range_sha256": _sha256_hex(ec_range_body),
            "range_416_body_sha256": _sha256_hex(RANGE_416_BODY),
        },
        "large_object": {
            "bytes": len(assembled),
            "body_sha256": _sha256_hex(assembled),
            "segment_bytes": [len(item) for item in segments],
            "segment_md5": list(segment_etags),
            "slo_etag": aggregate_etag,
            "dlo_etag_unquoted": aggregate_etag,
            "cross_segment_range": "{}-{}".format(boundary_start, boundary_end),
            "cross_segment_range_sha256": _sha256_hex(boundary_body),
        },
    }


def _cleanup_target(target: Target) -> List[str]:
    issues: List[str] = []
    preferred = sorted(
        target.owned_containers,
        key=lambda name: (0 if name.endswith("-large") else 1 if name.endswith("-segments") else 2, name),
    )
    for container in preferred:
        for obj in sorted(target.known_objects.get(container, set())):
            try:
                response = target.request("DELETE", container=container, obj=obj)
                if response.status not in (204, 404):
                    issues.append(
                        "{} cleanup {}/{} returned {}".format(
                            target.label, container, obj, response.status
                        )
                    )
            except TransportError as exc:
                issues.append("{} cleanup object failed: {}".format(target.label, exc))
            except Exception as exc:
                issues.append(
                    "{} cleanup object crashed: {}".format(target.label, type(exc).__name__)
                )

        final_status: Optional[int] = None
        for attempt in range(4):
            try:
                response = target.request("DELETE", container=container)
                if response.status not in (204, 404, 409):
                    issues.append(
                        "{} cleanup container {} returned {}".format(
                            target.label, container, response.status
                        )
                    )
                head = target.request("HEAD", container=container)
                final_status = head.status
                if final_status == 404:
                    break
            except TransportError as exc:
                issues.append(
                    "{} cleanup container {} attempt {} failed: {}".format(
                        target.label, container, attempt + 1, exc
                    )
                )
            except Exception as exc:
                issues.append(
                    "{} cleanup container {} attempt {} crashed: {}".format(
                        target.label, container, attempt + 1, type(exc).__name__
                    )
                )
            if attempt < 3:
                time.sleep(0.25)
        if final_status != 404:
            issues.append(
                "{} cleanup {} not proven by final HEAD (status={})".format(
                    target.label, container, final_status
                )
            )
    return issues


def _write_report(path: str, report: Mapping[str, Any]) -> None:
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    report_path = Path(path)
    temporary = report_path.with_name(
        ".{}.{}.{}.tmp".format(report_path.name, os.getpid(), secrets.token_hex(8))
    )
    descriptor: Optional[int] = None
    try:
        descriptor = os.open(
            str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, report_path)
        directory_fd = os.open(str(report_path.parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _namespace(prefix: str) -> str:
    if not NAMESPACE_PREFIX_RE.fullmatch(prefix):
        raise ConfigError(
            "namespace prefix must match {}".format(NAMESPACE_PREFIX_RE.pattern)
        )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return "{}-{}-{}-{}".format(prefix, stamp, os.getpid(), secrets.token_hex(12))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Strict EC/SLO/DLO parity gate for Python Swift and Peregrine"
    )
    parser.add_argument("--python", required=True, help="Python auth origin")
    parser.add_argument("--rust", required=True, help="Rust auth origin")
    parser.add_argument("--python-storage-origin", required=True)
    parser.add_argument("--rust-storage-origin", required=True)
    parser.add_argument("--python-request-origin", required=True)
    parser.add_argument("--rust-request-origin", required=True)
    parser.add_argument("--python-account", required=True)
    parser.add_argument("--rust-account", required=True)
    parser.add_argument("--python-provenance", required=True)
    parser.add_argument("--rust-provenance", required=True)
    parser.add_argument(
        "--python-user-env", default="PEREGRINE_EXT_PARITY_PY_USER"
    )
    parser.add_argument(
        "--python-key-env", default="PEREGRINE_EXT_PARITY_PY_KEY"
    )
    parser.add_argument(
        "--rust-user-env", default="PEREGRINE_EXT_PARITY_RS_USER"
    )
    parser.add_argument(
        "--rust-key-env", default="PEREGRINE_EXT_PARITY_RS_KEY"
    )
    parser.add_argument("--namespace-prefix", default="pgn-ext")
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--consistency-timeout", type=float, default=10.0)
    parser.add_argument(
        "--max-response-bytes", type=int, default=DEFAULT_MAX_RESPONSE_BYTES
    )
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument(
        "--enable-public-acl",
        action="store_true",
        help="also grant anonymous object GET, revoke it, and prove 401",
    )
    parser.add_argument(
        "--json-report", required=True, help="atomic mode-0600 report path; '-' forbidden"
    )
    return parser


def _validated_config(args: argparse.Namespace) -> ValidatedConfig:
    values = {
        "python_endpoint": _validate_endpoint(args.python, "Python auth origin"),
        "rust_endpoint": _validate_endpoint(args.rust, "Rust auth origin"),
        "python_storage_origin": _validate_endpoint(
            args.python_storage_origin, "Python advertised storage origin"
        ),
        "rust_storage_origin": _validate_endpoint(
            args.rust_storage_origin, "Rust advertised storage origin"
        ),
        "python_request_origin": _validate_endpoint(
            args.python_request_origin, "Python request origin"
        ),
        "rust_request_origin": _validate_endpoint(
            args.rust_request_origin, "Rust request origin"
        ),
    }
    for kind in ("endpoint", "storage_origin", "request_origin"):
        if _origin_identity(values["python_" + kind]) == _origin_identity(
            values["rust_" + kind]
        ):
            raise ConfigError("Python and Rust {} values must differ".format(kind))
    python_account = _validate_account(args.python_account, "Python")
    rust_account = _validate_account(args.rust_account, "Rust")
    python_provenance = _validate_provenance(args.python_provenance, "Python")
    rust_provenance = _validate_provenance(args.rust_provenance, "Rust")
    if python_provenance == rust_provenance:
        raise ConfigError("Python and Rust provenance must differ")
    env_names = (
        _validate_env_name(args.python_user_env, "Python user env"),
        _validate_env_name(args.python_key_env, "Python key env"),
        _validate_env_name(args.rust_user_env, "Rust user env"),
        _validate_env_name(args.rust_key_env, "Rust key env"),
    )
    if len(set(env_names)) != len(env_names):
        raise ConfigError("all four credential environment-variable names must differ")
    if args.json_report == "-":
        raise ConfigError("--json-report - is forbidden; provide a file path")
    if args.timeout <= 0 or args.timeout > 300:
        raise ConfigError("timeout must be greater than 0 and at most 300 seconds")
    if args.consistency_timeout <= 0 or args.consistency_timeout > 60:
        raise ConfigError(
            "consistency-timeout must be greater than 0 and at most 60 seconds"
        )
    if args.max_response_bytes < 4 * 1024 * 1024 or args.max_response_bytes > 64 * 1024 * 1024:
        raise ConfigError("max-response-bytes must be between 4 MiB and 64 MiB")
    if not NAMESPACE_PREFIX_RE.fullmatch(args.namespace_prefix):
        raise ConfigError(
            "namespace prefix must match {}".format(NAMESPACE_PREFIX_RE.pattern)
        )
    return ValidatedConfig(
        **values,
        python_account=python_account,
        rust_account=rust_account,
        python_provenance=python_provenance,
        rust_provenance=rust_provenance,
        python_user_env=env_names[0],
        python_key_env=env_names[1],
        rust_user_env=env_names[2],
        rust_key_env=env_names[3],
        namespace_prefix=args.namespace_prefix,
        timeout=args.timeout,
        consistency_timeout=args.consistency_timeout,
        max_response_bytes=args.max_response_bytes,
        insecure=args.insecure,
        enable_public_acl=args.enable_public_acl,
        json_report=args.json_report,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    config: Optional[ValidatedConfig] = None
    runner: Optional[Runner] = None
    python_target: Optional[Target] = None
    rust_target: Optional[Target] = None
    oracles: Mapping[str, Any] = {}
    exit_code = EXIT_RUNTIME_FAILURE

    def terminate(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    previous_term = signal.signal(signal.SIGTERM, terminate)
    try:
        config = _validated_config(args)
        expected_names = list(BASE_CASE_NAMES)
        if config.enable_public_acl:
            expected_names.extend(ACL_CASE_NAMES)
        runner = Runner(_namespace(config.namespace_prefix), expected_names)
        client = HttpClient(config.timeout, config.max_response_bytes, config.insecure)
        py_auth = _authenticate(
            client,
            config.python_endpoint,
            _required_env(config.python_user_env),
            _required_env(config.python_key_env),
            config.python_storage_origin,
            config.python_account,
        )
        rs_auth = _authenticate(
            client,
            config.rust_endpoint,
            _required_env(config.rust_user_env),
            _required_env(config.rust_key_env),
            config.rust_storage_origin,
            config.rust_account,
        )
        runner.compare(
            "tempauth",
            py_auth.snapshot,
            rs_auth.snapshot,
            200,
            "empty",
            presence_headers=("X-Auth-Token", "X-Storage-Url"),
            redacted_headers=("X-Auth-Token", "X-Storage-Url"),
        )
        py_advertised = Target(
            "python-advertised",
            py_auth.storage_origin,
            py_auth.token,
            py_auth.storage_path,
            client,
        )
        rs_advertised = Target(
            "rust-advertised",
            rs_auth.storage_origin,
            rs_auth.token,
            rs_auth.storage_path,
            client,
        )
        runner.compare(
            "advertised-storage-head",
            py_advertised.request("HEAD"),
            rs_advertised.request("HEAD"),
            204,
            "empty",
            numeric_headers=(
                "X-Account-Container-Count",
                "X-Account-Object-Count",
                "X-Account-Bytes-Used",
            ),
        )
        python_target = Target(
            "python",
            config.python_request_origin,
            py_auth.token,
            py_auth.storage_path,
            client,
        )
        rust_target = Target(
            "rust",
            config.rust_request_origin,
            rs_auth.token,
            rs_auth.storage_path,
            client,
        )
        print("namespace={}".format(runner.namespace))
        print("python={}".format(config.python_endpoint))
        print("rust={}".format(config.rust_endpoint))
        print("scope={} claim={}".format(SCOPE_ID, SCOPE_CLAIM))
        oracles = _run_scenario(
            runner,
            python_target,
            rust_target,
            config.consistency_timeout,
            config.enable_public_acl,
        )
        runner.finalize_coverage()
        exit_code = EXIT_PARITY_FAILURE if runner.failed else EXIT_PASS
    except ScenarioAbort as exc:
        if runner is not None:
            runner.abort_reason = str(exc)
        print("ABORT {}".format(exc), file=sys.stderr)
        exit_code = EXIT_PARITY_FAILURE
    except KeyboardInterrupt:
        if runner is not None:
            runner.fatal = "interrupted"
        print("INTERRUPTED: cleanup will be attempted", file=sys.stderr)
        exit_code = EXIT_INTERRUPTED
    except (ConfigError, TransportError) as exc:
        if runner is not None:
            runner.fatal = str(exc)
        print("FATAL {}".format(exc), file=sys.stderr)
        exit_code = EXIT_RUNTIME_FAILURE
    except (OSError, ValueError) as exc:
        fatal = "runtime error: {}".format(type(exc).__name__)
        if runner is not None:
            runner.fatal = fatal
        print("FATAL {}".format(fatal), file=sys.stderr)
        exit_code = EXIT_RUNTIME_FAILURE
    except Exception as exc:
        fatal = "unexpected internal error: {}".format(type(exc).__name__)
        if runner is not None:
            runner.fatal = fatal
        print("FATAL {}".format(fatal), file=sys.stderr)
        exit_code = EXIT_RUNTIME_FAILURE
    finally:
        if runner is not None:
            for target in (python_target, rust_target):
                if target is not None:
                    try:
                        runner.cleanup_issues.extend(_cleanup_target(target))
                    except Exception as exc:
                        runner.cleanup_issues.append(
                            "{} cleanup crashed outside guard: {}".format(
                                target.label, type(exc).__name__
                            )
                        )
            if runner.cleanup_issues:
                for issue in runner.cleanup_issues:
                    print("CLEANUP FAIL " + issue, file=sys.stderr)
                exit_code = _merge_exit_code(exit_code, EXIT_PARITY_FAILURE)
            runner.finalize_coverage()
            if runner.coverage_issues:
                for issue in runner.coverage_issues:
                    print("COVERAGE FAIL " + issue, file=sys.stderr)
                exit_code = _merge_exit_code(exit_code, EXIT_PARITY_FAILURE)
            if config is not None:
                report = runner.report(config, exit_code, oracles)
                try:
                    _write_report(config.json_report, report)
                except Exception as exc:
                    print(
                        "FATAL report write failed ({})".format(type(exc).__name__),
                        file=sys.stderr,
                    )
                    exit_code = _merge_exit_code(exit_code, EXIT_RUNTIME_FAILURE)
            print(
                "RESULT scope={} gate={} cases={} expected={} passed={} failed={} coverage_failed={} cleanup_failed={}".format(
                    SCOPE_ID,
                    _gate_for_exit(exit_code),
                    len(runner.results),
                    len(runner.expected_case_names),
                    sum(1 for item in runner.results if item.passed),
                    sum(1 for item in runner.results if not item.passed),
                    len(runner.coverage_issues),
                    len(runner.cleanup_issues),
                )
            )
        signal.signal(signal.SIGTERM, previous_term)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
