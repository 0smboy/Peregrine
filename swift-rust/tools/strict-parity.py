#!/usr/bin/env python3
"""Strict, bounded HTTP parity gate for Python Swift and Peregrine.

The gate uses only the Python standard library. It creates one cryptographically
unique container in each target account, exercises a core Swift v1 lifecycle,
compares every response, and removes only that namespace in a ``finally`` block.
Its PASS is deliberately scoped to the TempAuth + core Swift v1 subset; it does
not claim EC, S3, specialty middleware, sharding, or daemon parity.

Credentials are accepted only through named environment variables. They are
never placed in arguments, reports, or console output. This program does not
source an env file and does not install, deploy, restart, or reconfigure anything.

Example (load the variables by your normal secret-safe mechanism first):

    python3 strict-parity.py \
      --python http://127.0.0.1:18090 \
      --rust http://10.0.0.3:8080 \
      --python-account AUTH_test \
      --rust-account AUTH_test \
      --python-provenance python-swift@<verified-commit> \
      --rust-provenance peregrine@<verified-commit>+proxy-sha256:<verified-sha> \
      --json-report /tmp/strict-parity.json

The provenance strings are recorded evidence, not automatic attestation. The
operator must independently verify the source, process, route, and binary hash.

Exit codes:
    0  all comparisons and cleanup passed
    1  parity, expected-behavior, or cleanup failure
    2  configuration, authentication, or transport failure
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
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
NAMESPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
ACCOUNT_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
NONNEGATIVE_INTEGER_RE = re.compile(r"^[0-9]+$")
LISTING_VOLATILE_KEYS = frozenset({"last_modified"})
SECRET_RESPONSE_HEADERS = frozenset({"x-auth-token", "x-storage-token"})
SCOPE_ID = "core-swift-v1-tempauth"
SCOPE_EXCLUDES = (
    "erasure-coding",
    "s3",
    "slo-dlo",
    "tempurl-formpost-bulk-staticweb",
    "symlink-versioning-quotas-acl",
    "keystone-crypto",
    "sharding-and-background-daemons",
)


class ConfigError(RuntimeError):
    """The requested comparison cannot be run safely."""


class TransportError(RuntimeError):
    """A target could not produce an HTTP response."""


class ScenarioAbort(RuntimeError):
    """A prerequisite failed, so dependent cases must not run."""


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
    safe_to_cleanup: bool = False
    known_objects: Set[str] = field(default_factory=set)

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
            url += "/" + quote(obj, safe="")
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
    ) -> Snapshot:
        request_headers = {"X-Auth-Token": self.token}
        if headers:
            request_headers.update(headers)
        return self.client.request(
            method,
            self.storage_url(container, obj, query),
            body=body,
            headers=request_headers,
        )


@dataclass
class CaseResult:
    name: str
    expected_statuses: Tuple[int, ...]
    body_mode: str
    python: Dict[str, Any]
    rust: Dict[str, Any]
    issues: List[str]

    @property
    def passed(self) -> bool:
        return not self.issues


class HttpClient:
    def __init__(
        self,
        timeout: float,
        max_response_bytes: int,
        insecure: bool,
    ) -> None:
        handlers: List[Any] = [ProxyHandler({}), _NoRedirect()]
        if insecure:
            context = ssl._create_unverified_context()  # noqa: SLF001
        else:
            context = ssl.create_default_context()
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
            "User-Agent": "peregrine-strict-parity/1",
        }
        if headers:
            request_headers.update(headers)
        if body is not None:
            request_headers.setdefault("Content-Length", str(len(body)))
        request = Request(
            url=url,
            data=body,
            headers=request_headers,
            method=method,
        )

        response: Any
        try:
            response = self._opener.open(request, timeout=self._timeout)
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
            normalized_headers: Dict[str, List[str]] = {}
            for name, value in response.headers.raw_items():
                normalized_headers.setdefault(name.strip().lower(), []).append(
                    value.strip()
                )
            snapshot = Snapshot(
                status=int(response.code),
                headers={
                    name: tuple(values)
                    for name, values in normalized_headers.items()
                },
                body=body_bytes,
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
    def __init__(self, namespace: str) -> None:
        self.namespace = namespace
        self.results: List[CaseResult] = []
        self.cleanup_issues: List[str] = []
        self.fatal: Optional[str] = None
        self.abort_reason: Optional[str] = None

    @property
    def failed(self) -> bool:
        return (
            any(not result.passed for result in self.results)
            or bool(self.cleanup_issues)
            or self.fatal is not None
        )

    def compare(
        self,
        name: str,
        python: Snapshot,
        rust: Snapshot,
        expected_statuses: Iterable[int],
        body_mode: str,
        compare_headers: Sequence[str] = (),
        presence_headers: Sequence[str] = (),
        redacted_headers: Sequence[str] = (),
        nonnegative_integer_headers: Sequence[str] = (),
        expected_body: Optional[bytes] = None,
        expected_listing_names: Sequence[str] = (),
        expected_header_values: Optional[Mapping[str, str]] = None,
    ) -> CaseResult:
        expected = tuple(sorted(set(expected_statuses)))
        issues: List[str] = []
        redacted = frozenset(header.lower() for header in redacted_headers)

        if python.status != rust.status:
            issues.append(
                "status mismatch python={} rust={}".format(
                    python.status, rust.status
                )
            )
        for label, snapshot in (("python", python), ("rust", rust)):
            if snapshot.status not in expected:
                issues.append(
                    "{} status {} not in {}".format(label, snapshot.status, expected)
                )

        for header in compare_headers:
            key = header.lower()
            python_values = python.headers.get(key)
            rust_values = rust.headers.get(key)
            if not python_values:
                issues.append("python missing header {}".format(key))
            if not rust_values:
                issues.append("rust missing header {}".format(key))
            if python_values and rust_values:
                normalized: Dict[str, Tuple[str, ...]] = {}
                for label, values in (
                    ("python", python_values),
                    ("rust", rust_values),
                ):
                    try:
                        normalized[label] = _normalize_header(key, values)
                    except ValueError as exc:
                        issues.append(
                            "{} invalid {} header: {}".format(label, key, exc)
                        )
                if (
                    len(normalized) == 2
                    and normalized["python"] != normalized["rust"]
                ):
                    if key in redacted or key in SECRET_RESPONSE_HEADERS:
                        py_display: Any = "<redacted>"
                        rs_display: Any = "<redacted>"
                    else:
                        py_display = normalized["python"]
                        rs_display = normalized["rust"]
                    issues.append(
                        "header {} mismatch python={} rust={}".format(
                            key, py_display, rs_display
                        )
                    )

        for header in presence_headers:
            key = header.lower()
            if not python.headers.get(key):
                issues.append("python missing header {}".format(key))
            if not rust.headers.get(key):
                issues.append("rust missing header {}".format(key))

        for header in nonnegative_integer_headers:
            key = header.lower()
            for label, snapshot in (("python", python), ("rust", rust)):
                values = snapshot.headers.get(key)
                if not values:
                    issues.append("{} missing header {}".format(label, key))
                elif len(values) != 1 or not NONNEGATIVE_INTEGER_RE.fullmatch(
                    values[0]
                ):
                    issues.append(
                        "{} header {} must be one non-negative decimal integer".format(
                            label, key
                        )
                    )

        for header, expected_value in (expected_header_values or {}).items():
            key = header.lower()
            expected_normalized = _normalize_header(key, (expected_value,))
            for label, snapshot in (("python", python), ("rust", rust)):
                actual_values = snapshot.headers.get(key)
                if not actual_values:
                    issues.append("{} missing expected header {}".format(label, key))
                    continue
                try:
                    actual_normalized = _normalize_header(key, actual_values)
                except ValueError as exc:
                    issues.append(
                        "{} invalid {} header: {}".format(label, key, exc)
                    )
                    continue
                if actual_normalized != expected_normalized:
                    actual_display: Any = actual_normalized
                    if key in redacted or key in SECRET_RESPONSE_HEADERS:
                        actual_display = "<redacted>"
                    issues.append(
                        "{} header {} differs from fixed oracle expected={} actual={}"
                        .format(
                            label,
                            key,
                            "<redacted>"
                            if key in redacted or key in SECRET_RESPONSE_HEADERS
                            else expected_normalized,
                            actual_display,
                        )
                    )

        body_issues = _compare_bodies(
            body_mode,
            python.body,
            rust.body,
            expected_body=expected_body,
            expected_listing_names=expected_listing_names,
        )
        issues.extend(body_issues)

        selected_headers = tuple(
            dict.fromkeys(
                [header.lower() for header in compare_headers]
                + [header.lower() for header in presence_headers]
                + [header.lower() for header in nonnegative_integer_headers]
                + [
                    header.lower()
                    for header in (expected_header_values or {})
                ]
            )
        )
        result = CaseResult(
            name=name,
            expected_statuses=expected,
            body_mode=body_mode,
            python=_public_snapshot(python, selected_headers, redacted),
            rust=_public_snapshot(rust, selected_headers, redacted),
            issues=issues,
        )
        self.results.append(result)
        if result.passed:
            print(
                "PASS {:<28} python={} rust={}".format(
                    name, python.status, rust.status
                )
            )
        else:
            print(
                "FAIL {:<28} python={} rust={} issues={}".format(
                    name, python.status, rust.status, len(issues)
                )
            )
            for issue in issues:
                print("     " + issue)
        return result

    def report(
        self,
        python_endpoint: str,
        rust_endpoint: str,
        python_storage_origin: str,
        rust_storage_origin: str,
        python_request_origin: str,
        rust_request_origin: str,
        python_account: str,
        rust_account: str,
        python_provenance: str,
        rust_provenance: str,
        exit_code: int,
    ) -> Dict[str, Any]:
        passed = sum(1 for result in self.results if result.passed)
        failed = len(self.results) - passed
        return {
            "schema": "peregrine.strict-parity.v1",
            "generated_at": _utc_now(),
            "namespace": self.namespace,
            "scope": {
                "id": SCOPE_ID,
                "claim": "IMPLEMENTED_SUBSET_ONLY",
                "excludes": list(SCOPE_EXCLUDES),
            },
            "targets": {
                "python": {
                    "endpoint": python_endpoint,
                    "storage_origin": python_storage_origin,
                    "request_origin": python_request_origin,
                    "account": python_account,
                    "provenance": python_provenance,
                },
                "rust": {
                    "endpoint": rust_endpoint,
                    "storage_origin": rust_storage_origin,
                    "request_origin": rust_request_origin,
                    "account": rust_account,
                    "provenance": rust_provenance,
                },
            },
            "summary": {
                "cases": len(self.results),
                "passed": passed,
                "failed": failed,
                "cleanup_failed": len(self.cleanup_issues),
                "gate": _gate_for_exit(exit_code),
            },
            "result": {
                "exit_code": exit_code,
                "gate": _gate_for_exit(exit_code),
            },
            "fatal": self.fatal,
            "abort_reason": self.abort_reason,
            "cleanup_issues": list(self.cleanup_issues),
            "cases": [
                {
                    "name": result.name,
                    "expected_statuses": list(result.expected_statuses),
                    "body_mode": result.body_mode,
                    "python": result.python,
                    "rust": result.rust,
                    "issues": list(result.issues),
                    "gate": "PASS" if result.passed else "FAIL",
                }
                for result in self.results
            ],
        }


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
    if exit_code == EXIT_PASS:
        return "PASS"
    if exit_code == EXIT_INTERRUPTED:
        return "INTERRUPTED"
    if exit_code == EXIT_RUNTIME_FAILURE:
        return "ERROR"
    return "FAIL"


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


def _canonical_origin(raw: str) -> str:
    parsed = urlsplit(raw)
    # _validate_endpoint or _authenticate validates the netloc first.
    return "{}://{}".format(parsed.scheme.lower(), parsed.netloc)


def _validate_endpoint(raw: str) -> str:
    endpoint = raw.strip().rstrip("/")
    parsed = urlsplit(endpoint)
    if parsed.scheme not in ("http", "https"):
        raise ConfigError("endpoint must use http or https")
    if not parsed.hostname:
        raise ConfigError("endpoint must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigError("endpoint must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ConfigError("endpoint must not contain a query or fragment")
    if parsed.path not in ("", "/"):
        raise ConfigError("endpoint must be an origin without a path")
    try:
        parsed.port
    except ValueError as exc:
        raise ConfigError("endpoint has an invalid port") from exc
    return endpoint


def _validate_provenance(raw: str, label: str) -> str:
    value = raw.strip()
    if not value or len(value) > 512:
        raise ConfigError("{} provenance must contain 1-512 characters".format(label))
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ConfigError("{} provenance contains a control character".format(label))
    return value


def _validate_account(raw: str, label: str) -> str:
    account = raw.strip()
    if (
        account in ("", ".", "..")
        or not ACCOUNT_SEGMENT_RE.fullmatch(account)
    ):
        raise ConfigError("{} account is not one safe path segment".format(label))
    return account


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value:
        raise ConfigError("required environment variable {} is not set".format(name))
    if "\r" in value or "\n" in value:
        raise ConfigError("environment variable {} contains a newline".format(name))
    return value


def _auth_env_names(
    common_user: str,
    common_key: str,
    specific_user: Optional[str],
    specific_key: Optional[str],
) -> Tuple[str, str]:
    return specific_user or common_user, specific_key or common_key


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
        raise ConfigError("authentication returned a storage URL with control characters")
    parsed_storage = urlsplit(storage_url)
    if parsed_storage.scheme not in ("http", "https") or not parsed_storage.hostname:
        raise ConfigError("authentication returned a non-absolute storage URL")
    if parsed_storage.username is not None or parsed_storage.password is not None:
        raise ConfigError("authentication returned credentials in the storage URL")
    if parsed_storage.query or parsed_storage.fragment:
        raise ConfigError("authentication returned an unsafe storage URL")
    storage_identity = _origin_identity(storage_url)
    if storage_identity != _origin_identity(allowed_storage_origin):
        raise ConfigError(
            "authentication returned a storage origin outside the allowed origin"
        )
    path_parts = parsed_storage.path.split("/")
    if len(path_parts) != 3 or path_parts[:2] != ["", "v1"]:
        raise ConfigError("authentication returned an invalid storage path")
    account_segment = path_parts[2]
    if (
        account_segment in ("", ".", "..")
        or not ACCOUNT_SEGMENT_RE.fullmatch(account_segment)
    ):
        raise ConfigError("authentication returned an unsafe account segment")
    if account_segment != expected_account:
        raise ConfigError("authentication returned an unexpected account segment")
    return AuthResult(
        snapshot=snapshot,
        token=token,
        storage_path=parsed_storage.path,
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
    media_type, media_subtype = parts[0].strip().split("/", 1)
    if not HTTP_TOKEN_RE.fullmatch(media_type) or not HTTP_TOKEN_RE.fullmatch(
        media_subtype
    ):
        raise ValueError("does not contain a valid media type")

    canonical_params: List[Tuple[str, str]] = []
    seen_params: Set[str] = set()
    for parameter in parts[1:]:
        if not parameter or "=" not in parameter:
            raise ValueError("contains an invalid parameter")
        raw_key, raw_value = parameter.split("=", 1)
        key = raw_key.strip().lower()
        value_text = raw_value.strip()
        if not HTTP_TOKEN_RE.fullmatch(key) or key in seen_params:
            raise ValueError("contains an invalid or duplicate parameter name")
        seen_params.add(key)
        canonical_params.append((key, _decode_parameter_value(value_text)))
    return json.dumps(
        ["{}/{}".format(media_type.lower(), media_subtype.lower()), sorted(canonical_params)],
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _normalize_header(name: str, values: Sequence[str]) -> Tuple[str, ...]:
    normalized = [value.strip() for value in values]
    if name == "content-type":
        normalized = [_normalize_content_type(value) for value in normalized]
    return tuple(sorted(normalized))


def _md5_hex(body: bytes) -> str:
    try:
        return hashlib.md5(body, usedforsecurity=False).hexdigest()
    except TypeError:
        return hashlib.md5(body).hexdigest()  # noqa: S324


def _sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _normalize_listing_json(
    body: bytes, expected_names: Sequence[str]
) -> bytes:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid UTF-8 JSON listing: {}".format(exc)) from exc

    if not isinstance(value, list):
        raise ValueError("listing root must be an array")
    expected_fields = {"name", "hash", "bytes", "content_type", "last_modified"}
    names: List[str] = []
    normalized: List[Dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise ValueError("listing entry must be an object")
        if set(entry) != expected_fields:
            raise ValueError(
                "listing entry fields {} != {}".format(
                    sorted(entry), sorted(expected_fields)
                )
            )
        if not isinstance(entry["name"], str):
            raise ValueError("listing name must be a string")
        if not isinstance(entry["hash"], str):
            raise ValueError("listing hash must be a string")
        if isinstance(entry["bytes"], bool) or not isinstance(entry["bytes"], int):
            raise ValueError("listing bytes must be an integer")
        if not isinstance(entry["content_type"], str):
            raise ValueError("listing content_type must be a string")
        if not isinstance(entry["last_modified"], str) or not entry["last_modified"]:
            raise ValueError("listing last_modified must be a non-empty string")
        names.append(entry["name"])
        normalized.append(
            {
                key: child
                for key, child in sorted(entry.items())
                if key not in LISTING_VOLATILE_KEYS
            }
        )
    if len(names) != len(set(names)):
        raise ValueError("listing contains duplicate object names")
    if sorted(names) != sorted(expected_names):
        raise ValueError(
            "listing names {} != expected {}".format(
                sorted(names), sorted(expected_names)
            )
        )
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _compare_bodies(
    mode: str,
    python: bytes,
    rust: bytes,
    expected_body: Optional[bytes] = None,
    expected_listing_names: Sequence[str] = (),
) -> List[str]:
    issues: List[str] = []
    if mode == "empty":
        if python:
            issues.append("python body expected empty but length={}".format(len(python)))
        if rust:
            issues.append("rust body expected empty but length={}".format(len(rust)))
        if python != rust:
            issues.append("empty-body mismatch")
        return issues
    if mode == "exact":
        if python != rust:
            issues.append(
                "body mismatch python_len={} python_sha256={} rust_len={} rust_sha256={}".format(
                    len(python),
                    _sha256_hex(python),
                    len(rust),
                    _sha256_hex(rust),
                )
            )
        if expected_body is not None:
            for label, body in (("python", python), ("rust", rust)):
                if body != expected_body:
                    issues.append(
                        "{} body differs from fixed oracle expected_len={} expected_sha256={}"
                        .format(
                            label,
                            len(expected_body),
                            _sha256_hex(expected_body),
                        )
                    )
        return issues
    if mode == "json-listing":
        normalized: Dict[str, bytes] = {}
        for label, body in (("python", python), ("rust", rust)):
            try:
                normalized[label] = _normalize_listing_json(
                    body, expected_listing_names
                )
            except ValueError as exc:
                issues.append("{} body {}".format(label, exc))
        if len(normalized) == 2 and normalized["python"] != normalized["rust"]:
            issues.append(
                "semantic listing mismatch python_sha256={} rust_sha256={}".format(
                    _sha256_hex(normalized["python"]),
                    _sha256_hex(normalized["rust"]),
                )
            )
        return issues
    raise ValueError("unknown body mode {}".format(mode))


def _public_snapshot(
    snapshot: Snapshot,
    selected_headers: Sequence[str],
    redacted_headers: Set[str],
) -> Dict[str, Any]:
    public_headers: Dict[str, Any] = {}
    for name in selected_headers:
        values = snapshot.headers.get(name)
        if not values:
            public_headers[name] = None
        elif name in redacted_headers or name in SECRET_RESPONSE_HEADERS:
            public_headers[name] = "<present>"
        else:
            public_headers[name] = list(values)
    return {
        "status": snapshot.status,
        "headers": public_headers,
        "body_len": len(snapshot.body),
        "body_sha256": _sha256_hex(snapshot.body),
    }


def _request_pair(
    runner: Runner,
    python: Target,
    rust: Target,
    name: str,
    method: str,
    expected_statuses: Iterable[int],
    body_mode: str,
    container: Optional[str] = None,
    obj: Optional[str] = None,
    query: Optional[Mapping[str, str]] = None,
    body: Optional[bytes] = None,
    headers: Optional[Mapping[str, str]] = None,
    compare_headers: Sequence[str] = (),
    presence_headers: Sequence[str] = (),
    nonnegative_integer_headers: Sequence[str] = (),
    expected_body: Optional[bytes] = None,
    expected_listing_names: Sequence[str] = (),
    expected_header_values: Optional[Mapping[str, str]] = None,
) -> CaseResult:
    py_snapshot = python.request(
        method,
        container=container,
        obj=obj,
        query=query,
        body=body,
        headers=headers,
    )
    rs_snapshot = rust.request(
        method,
        container=container,
        obj=obj,
        query=query,
        body=body,
        headers=headers,
    )
    return runner.compare(
        name,
        py_snapshot,
        rs_snapshot,
        expected_statuses,
        body_mode,
        compare_headers=compare_headers,
        presence_headers=presence_headers,
        nonnegative_integer_headers=nonnegative_integer_headers,
        expected_body=expected_body,
        expected_listing_names=expected_listing_names,
        expected_header_values=expected_header_values,
    )


def _run_scenario(runner: Runner, python: Target, rust: Target) -> None:
    container = runner.namespace
    payload = b"peregrine-strict-parity-v1\n"
    payload_etag = _md5_hex(payload)
    accepted_body = (
        b"<html><h1>Accepted</h1>"
        b"<p>The request is accepted for processing.</p></html>"
    )

    _request_pair(
        runner,
        python,
        rust,
        "account-head",
        "HEAD",
        (204,),
        "empty",
        nonnegative_integer_headers=(
            "x-account-container-count",
            "x-account-object-count",
            "x-account-bytes-used",
        ),
    )

    preflight = _request_pair(
        runner,
        python,
        rust,
        "namespace-absent",
        "HEAD",
        (404,),
        "empty",
        container=container,
    )
    if not preflight.passed:
        raise ScenarioAbort("namespace ownership preflight failed; no writes were made")
    python.safe_to_cleanup = True
    rust.safe_to_cleanup = True

    create = _request_pair(
        runner,
        python,
        rust,
        "container-create",
        "PUT",
        (201,),
        "empty",
        container=container,
        body=b"",
    )
    if not create.passed:
        raise ScenarioAbort("container creation failed; dependent writes were skipped")

    _request_pair(
        runner,
        python,
        rust,
        "container-idempotent-put",
        "PUT",
        (202,),
        # Python's swob 202 response carries a fixed 76-byte explanatory
        # body. Compare it byte-for-byte instead of assuming an empty body.
        "exact",
        container=container,
        body=b"",
        expected_body=accepted_body,
    )
    _request_pair(
        runner,
        python,
        rust,
        "container-post-meta",
        "POST",
        (204,),
        "empty",
        container=container,
        body=b"",
        headers={"X-Container-Meta-Parity": "strict-v1"},
    )
    _request_pair(
        runner,
        python,
        rust,
        "container-head",
        "HEAD",
        (204,),
        "empty",
        container=container,
        compare_headers=(
            "x-container-meta-parity",
            "x-container-object-count",
            "x-container-bytes-used",
        ),
        expected_header_values={
            "x-container-meta-parity": "strict-v1",
            "x-container-object-count": "0",
            "x-container-bytes-used": "0",
        },
    )

    for target in (python, rust):
        target.known_objects.add("object")
    put_object = _request_pair(
        runner,
        python,
        rust,
        "object-put",
        "PUT",
        (201,),
        "empty",
        container=container,
        obj="object",
        body=payload,
        headers={
            "Content-Type": "application/octet-stream",
            "X-Object-Meta-Parity": "initial",
        },
        compare_headers=("etag",),
        expected_header_values={"etag": payload_etag},
    )
    if not put_object.passed:
        raise ScenarioAbort("object PUT failed; dependent object cases were skipped")

    object_headers = (
        "etag",
        "content-type",
        "content-length",
        "x-object-meta-parity",
        "accept-ranges",
    )
    _request_pair(
        runner,
        python,
        rust,
        "object-get",
        "GET",
        (200,),
        "exact",
        container=container,
        obj="object",
        compare_headers=object_headers,
        expected_body=payload,
        expected_header_values={
            "etag": payload_etag,
            "content-type": "application/octet-stream",
            "content-length": str(len(payload)),
            "x-object-meta-parity": "initial",
            "accept-ranges": "bytes",
        },
    )
    _request_pair(
        runner,
        python,
        rust,
        "object-head",
        "HEAD",
        (200,),
        "empty",
        container=container,
        obj="object",
        compare_headers=object_headers,
        expected_header_values={
            "etag": payload_etag,
            "content-type": "application/octet-stream",
            "content-length": str(len(payload)),
            "x-object-meta-parity": "initial",
            "accept-ranges": "bytes",
        },
    )
    _request_pair(
        runner,
        python,
        rust,
        "object-range",
        "GET",
        (206,),
        "exact",
        container=container,
        obj="object",
        headers={"Range": "bytes=3-12"},
        compare_headers=(
            "etag",
            "content-type",
            "content-length",
            "content-range",
        ),
        expected_body=payload[3:13],
        expected_header_values={
            "etag": payload_etag,
            "content-type": "application/octet-stream",
            "content-length": "10",
            "content-range": "bytes 3-12/{}".format(len(payload)),
        },
    )
    _request_pair(
        runner,
        python,
        rust,
        "object-not-modified",
        "GET",
        (304,),
        "empty",
        container=container,
        obj="object",
        headers={"If-None-Match": payload_etag},
    )
    _request_pair(
        runner,
        python,
        rust,
        "object-post-meta",
        "POST",
        (202,),
        "exact",
        container=container,
        obj="object",
        headers={
            "Content-Length": "0",
            "X-Object-Meta-Parity": "updated",
        },
        expected_body=accepted_body,
    )
    _request_pair(
        runner,
        python,
        rust,
        "object-head-after-post",
        "HEAD",
        (200,),
        "empty",
        container=container,
        obj="object",
        compare_headers=object_headers,
        expected_header_values={
            "etag": payload_etag,
            "content-type": "application/octet-stream",
            "content-length": str(len(payload)),
            "x-object-meta-parity": "updated",
            "accept-ranges": "bytes",
        },
    )

    for target in (python, rust):
        target.known_objects.add("copy")
    copy_result = _request_pair(
        runner,
        python,
        rust,
        "object-copy",
        "COPY",
        (201,),
        "empty",
        container=container,
        obj="object",
        headers={"Destination": "/{}/copy".format(container)},
        compare_headers=("etag",),
    )
    if copy_result.passed:
        _request_pair(
            runner,
            python,
            rust,
            "copy-get",
            "GET",
            (200,),
            "exact",
            container=container,
            obj="copy",
            compare_headers=object_headers,
            expected_body=payload,
            expected_header_values={
                "etag": payload_etag,
                "content-type": "application/octet-stream",
                "content-length": str(len(payload)),
                "x-object-meta-parity": "updated",
                "accept-ranges": "bytes",
            },
        )

    for target in (python, rust):
        target.known_objects.add("empty")
    _request_pair(
        runner,
        python,
        rust,
        "zero-byte-put",
        "PUT",
        (201,),
        "empty",
        container=container,
        obj="empty",
        body=b"",
        headers={"Content-Type": "application/octet-stream"},
        compare_headers=("etag",),
        expected_header_values={"etag": _md5_hex(b"")},
    )
    _request_pair(
        runner,
        python,
        rust,
        "zero-byte-get",
        "GET",
        (200,),
        "exact",
        container=container,
        obj="empty",
        compare_headers=("etag", "content-type", "content-length"),
        expected_body=b"",
        expected_header_values={
            "etag": _md5_hex(b""),
            "content-type": "application/octet-stream",
            "content-length": "0",
        },
    )
    _request_pair(
        runner,
        python,
        rust,
        "container-json-listing",
        "GET",
        (200,),
        "json-listing",
        container=container,
        query={"format": "json"},
        compare_headers=("content-type",),
        expected_listing_names=("copy", "empty", "object"),
    )
    _request_pair(
        runner,
        python,
        rust,
        "range-unsatisfiable",
        "GET",
        (416,),
        "exact",
        container=container,
        obj="object",
        headers={"Range": "bytes=999-1000"},
        compare_headers=("content-range", "content-type", "content-length"),
    )
    _request_pair(
        runner,
        python,
        rust,
        "missing-object",
        "GET",
        (404,),
        "exact",
        container=container,
        obj="missing",
        compare_headers=("content-type", "content-length"),
    )

    for obj in ("empty", "copy", "object"):
        _request_pair(
            runner,
            python,
            rust,
            "delete-{}".format(obj),
            "DELETE",
            (204,),
            "empty",
            container=container,
            obj=obj,
        )
    _request_pair(
        runner,
        python,
        rust,
        "container-get-empty",
        "GET",
        (204,),
        "empty",
        container=container,
    )
    _request_pair(
        runner,
        python,
        rust,
        "container-delete",
        "DELETE",
        (204,),
        "empty",
        container=container,
    )


def _listing_names(snapshot: Snapshot) -> Set[str]:
    if snapshot.status in (204, 404):
        return set()
    if snapshot.status != 200:
        raise ValueError("listing returned status {}".format(snapshot.status))
    try:
        listing = json.loads(snapshot.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("cleanup listing was not UTF-8 JSON") from exc
    if not isinstance(listing, list):
        raise ValueError("cleanup listing was not an array")
    names: Set[str] = set()
    for entry in listing:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise ValueError("cleanup listing contained an invalid entry")
        names.add(entry["name"])
    return names


def _cleanup_target(target: Target, container: str) -> List[str]:
    if not target.safe_to_cleanup:
        return []
    issues: List[str] = []
    objects = set(target.known_objects)
    try:
        listing = target.request(
            "GET",
            container=container,
            query={"format": "json", "limit": "10000"},
        )
        objects.update(_listing_names(listing))
    except (TransportError, ValueError) as exc:
        issues.append("{} cleanup listing failed: {}".format(target.label, exc))
    except Exception as exc:  # best-effort cleanup must continue to the peer
        issues.append(
            "{} cleanup listing crashed: {}".format(
                target.label, type(exc).__name__
            )
        )

    for obj in sorted(objects):
        try:
            response = target.request("DELETE", container=container, obj=obj)
            if response.status not in (204, 404):
                issues.append(
                    "{} cleanup object returned {}".format(
                        target.label, response.status
                    )
                )
        except TransportError as exc:
            issues.append("{} cleanup object failed: {}".format(target.label, exc))
        except Exception as exc:  # continue deleting the remaining known objects
            issues.append(
                "{} cleanup object crashed: {}".format(
                    target.label, type(exc).__name__
                )
            )

    final_head_status: Optional[int] = None
    for attempt in range(4):
        try:
            response = target.request("DELETE", container=container)
            if response.status not in (204, 404, 409):
                issues.append(
                    "{} cleanup container returned {}".format(
                        target.label, response.status
                    )
                )
            head = target.request("HEAD", container=container)
            final_head_status = head.status
            if head.status == 404:
                break
            if attempt < 3:
                time.sleep(0.25)
        except TransportError as exc:
            issues.append(
                "{} cleanup container attempt {} failed: {}".format(
                    target.label, attempt + 1, exc
                )
            )
        except Exception as exc:  # preserve later retries and the peer cleanup
            issues.append(
                "{} cleanup container attempt {} crashed: {}".format(
                    target.label, attempt + 1, type(exc).__name__
                )
            )
    if final_head_status != 404:
        issues.append(
            "{} cleanup not proven by final HEAD (status={})".format(
                target.label, final_head_status
            )
        )
    return issues


def _write_report(path: str, report: Mapping[str, Any]) -> None:
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    report_path = Path(path)
    temporary = report_path.with_name(
        ".{}.{}.{}.tmp".format(
            report_path.name, os.getpid(), secrets.token_hex(6)
        )
    )
    try:
        descriptor = os.open(
            str(temporary),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, report_path)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Strict, cleanup-safe Swift v1 HTTP comparison between a Python "
            "oracle and Peregrine"
        )
    )
    parser.add_argument("--python", required=True, help="Python Swift origin")
    parser.add_argument("--rust", required=True, help="Peregrine origin")
    parser.add_argument(
        "--python-storage-origin",
        help="allowed Python X-Storage-URL origin (defaults to --python)",
    )
    parser.add_argument(
        "--rust-storage-origin",
        help="allowed Rust X-Storage-URL origin (defaults to --rust)",
    )
    parser.add_argument(
        "--python-request-origin",
        help="Python core-test origin (defaults to advertised storage origin)",
    )
    parser.add_argument(
        "--rust-request-origin",
        help="Rust core-test origin (defaults to advertised storage origin)",
    )
    parser.add_argument(
        "--python-account",
        required=True,
        help="expected Python account segment from X-Storage-URL",
    )
    parser.add_argument(
        "--rust-account",
        required=True,
        help="expected Rust account segment from X-Storage-URL",
    )
    parser.add_argument(
        "--python-provenance",
        required=True,
        help="independently verified Python source commit/runtime identity",
    )
    parser.add_argument(
        "--rust-provenance",
        required=True,
        help="independently verified Rust source commit and binary hash",
    )
    parser.add_argument(
        "--user-env",
        default="PEREGRINE_PARITY_USER",
        help="common auth-user environment variable name",
    )
    parser.add_argument(
        "--key-env",
        default="PEREGRINE_PARITY_KEY",
        help="common auth-key environment variable name",
    )
    parser.add_argument("--python-user-env", help="Python auth-user env override")
    parser.add_argument("--python-key-env", help="Python auth-key env override")
    parser.add_argument("--rust-user-env", help="Rust auth-user env override")
    parser.add_argument("--rust-key-env", help="Rust auth-key env override")
    parser.add_argument(
        "--namespace-prefix",
        default="peregrine-parity",
        help="safe prefix; a random suffix is always appended",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=DEFAULT_MAX_RESPONSE_BYTES,
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS verification for both lab endpoints",
    )
    parser.add_argument(
        "--json-report",
        help="write a secret-free JSON report to this file path",
    )
    return parser


def _namespace(prefix: str) -> str:
    if not NAMESPACE_RE.fullmatch(prefix):
        raise ConfigError(
            "namespace prefix must match {}".format(NAMESPACE_RE.pattern)
        )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return "{}-{}-{}-{}".format(prefix, stamp, os.getpid(), secrets.token_hex(6))


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    runner: Optional[Runner] = None
    python_target: Optional[Target] = None
    rust_target: Optional[Target] = None
    exit_code = EXIT_RUNTIME_FAILURE

    def terminate(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    previous_term = signal.signal(signal.SIGTERM, terminate)
    try:
        python_endpoint = _validate_endpoint(args.python)
        rust_endpoint = _validate_endpoint(args.rust)
        python_storage_origin = _validate_endpoint(
            args.python_storage_origin or python_endpoint
        )
        rust_storage_origin = _validate_endpoint(
            args.rust_storage_origin or rust_endpoint
        )
        python_request_origin = _validate_endpoint(
            args.python_request_origin or python_storage_origin
        )
        rust_request_origin = _validate_endpoint(
            args.rust_request_origin or rust_storage_origin
        )
        python_account = _validate_account(args.python_account, "Python")
        rust_account = _validate_account(args.rust_account, "Rust")
        python_provenance = _validate_provenance(
            args.python_provenance, "Python"
        )
        rust_provenance = _validate_provenance(args.rust_provenance, "Rust")
        if _origin_identity(python_endpoint) == _origin_identity(rust_endpoint):
            raise ConfigError("Python and Rust endpoints must be different")
        if _origin_identity(python_storage_origin) == _origin_identity(
            rust_storage_origin
        ):
            raise ConfigError("Python and Rust storage origins must be different")
        if _origin_identity(python_request_origin) == _origin_identity(
            rust_request_origin
        ):
            raise ConfigError("Python and Rust request origins must be different")
        if python_provenance == rust_provenance:
            raise ConfigError("Python and Rust provenance must be different")
        if args.json_report == "-":
            raise ConfigError("--json-report - is not supported; provide a file path")
        if args.timeout <= 0:
            raise ConfigError("timeout must be greater than zero")
        if args.max_response_bytes <= 0:
            raise ConfigError("max-response-bytes must be greater than zero")

        namespace = _namespace(args.namespace_prefix)
        runner = Runner(namespace)
        client = HttpClient(
            timeout=args.timeout,
            max_response_bytes=args.max_response_bytes,
            insecure=args.insecure,
        )

        py_user_env, py_key_env = _auth_env_names(
            args.user_env,
            args.key_env,
            args.python_user_env,
            args.python_key_env,
        )
        rs_user_env, rs_key_env = _auth_env_names(
            args.user_env,
            args.key_env,
            args.rust_user_env,
            args.rust_key_env,
        )
        py_auth = _authenticate(
            client,
            python_endpoint,
            _required_env(py_user_env),
            _required_env(py_key_env),
            python_storage_origin,
            python_account,
        )
        rs_auth = _authenticate(
            client,
            rust_endpoint,
            _required_env(rs_user_env),
            _required_env(rs_key_env),
            rust_storage_origin,
            rust_account,
        )

        runner.compare(
            "tempauth",
            py_auth.snapshot,
            rs_auth.snapshot,
            (200,),
            "empty",
            presence_headers=("x-auth-token", "x-storage-url"),
            redacted_headers=("x-auth-token", "x-storage-url"),
        )
        python_advertised_target = Target(
            label="python-advertised",
            endpoint=py_auth.storage_origin,
            token=py_auth.token,
            storage_path=py_auth.storage_path,
            client=client,
        )
        rust_advertised_target = Target(
            label="rust-advertised",
            endpoint=rs_auth.storage_origin,
            token=rs_auth.token,
            storage_path=rs_auth.storage_path,
            client=client,
        )
        runner.compare(
            "tempauth-storage-head",
            python_advertised_target.request("HEAD"),
            rust_advertised_target.request("HEAD"),
            (204,),
            "empty",
            nonnegative_integer_headers=(
                "x-account-container-count",
                "x-account-object-count",
                "x-account-bytes-used",
            ),
        )
        python_target = Target(
            label="python",
            endpoint=python_request_origin,
            token=py_auth.token,
            storage_path=py_auth.storage_path,
            client=client,
        )
        rust_target = Target(
            label="rust",
            endpoint=rust_request_origin,
            token=rs_auth.token,
            storage_path=rs_auth.storage_path,
            client=client,
        )

        print("namespace={}".format(namespace))
        print("python={}".format(python_endpoint))
        print("rust={}".format(rust_endpoint))
        print("scope={} claim=IMPLEMENTED_SUBSET_ONLY".format(SCOPE_ID))
        _run_scenario(runner, python_target, rust_target)
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
    except Exception as exc:  # fail closed without exposing exception payloads
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
                        runner.cleanup_issues.extend(
                            _cleanup_target(target, runner.namespace)
                        )
                    except Exception as exc:
                        runner.cleanup_issues.append(
                            "{} cleanup crashed outside its guard: {}".format(
                                target.label, type(exc).__name__
                            )
                        )
            if runner.cleanup_issues:
                for issue in runner.cleanup_issues:
                    print("CLEANUP FAIL " + issue, file=sys.stderr)
                exit_code = _merge_exit_code(exit_code, EXIT_PARITY_FAILURE)

            report = runner.report(
                _safe_origin(args.python),
                _safe_origin(args.rust),
                _safe_origin(args.python_storage_origin or args.python),
                _safe_origin(args.rust_storage_origin or args.rust),
                _safe_origin(
                    args.python_request_origin
                    or args.python_storage_origin
                    or args.python
                ),
                _safe_origin(
                    args.rust_request_origin or args.rust_storage_origin or args.rust
                ),
                python_account,
                rust_account,
                python_provenance,
                rust_provenance,
                exit_code,
            )
            summary = report["summary"]
            if args.json_report:
                try:
                    _write_report(args.json_report, report)
                except Exception as exc:
                    print(
                        "FATAL report write failed ({})".format(type(exc).__name__),
                        file=sys.stderr,
                    )
                    exit_code = _merge_exit_code(exit_code, EXIT_RUNTIME_FAILURE)
            final_gate = _gate_for_exit(exit_code)
            print(
                "RESULT scope={} gate={} cases={} passed={} failed={} cleanup_failed={}".format(
                    SCOPE_ID,
                    final_gate,
                    summary["cases"],
                    summary["passed"],
                    summary["failed"],
                    summary["cleanup_failed"],
                )
            )
        signal.signal(signal.SIGTERM, previous_term)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
