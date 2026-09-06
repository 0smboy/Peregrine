#!/usr/bin/env python3
"""Send G6 rebuild ``proxy_get`` to isolated rust HTTP, not ``egg:swift#proxy``.

Field ``988b81b``: ``test_rebuild_missing_frags.proxy_get`` uses Python
``InternalClient.get_object`` loaded from ``/etc/g6-rust/internal-client.conf``
(``use = egg:swift#proxy``). That is in-process classic Swift WSGI. It does
**not** HTTP to rust ``:18080``. Access 404s were ``swift[python-pid]`` while
the rust overseer stayed idle. Live curl to ``:18080`` already emits
``G6_DIAG proxy-server: EC GET``.

When ``PROXY_BASE_URL`` is set (IsolatedIdentity ``http://127.0.0.1:18080``),
this adapter wraps ``InternalClient.make_request`` so GET/HEAD go to that
base over HTTP. PUT/POST/DELETE stay on the original client (official
rebuild PUT/POST already use python-swiftclient ``self.url``).

Fail-closed: if ``PROXY_BASE_URL`` is set, a GET/HEAD that would still
enter the WSGI app raises. ``egg:swift#proxy`` in internal-client.conf
without this adapter installed is also an error.

Enable on the lab probe:

    export PYTHONPATH=/path/to/Peregrine/swift-rust/tools/test-lab:$PYTHONPATH
    export PROXY_BASE_URL=http://127.0.0.1:18080
    pytest -p g6_rust_proxy_get test/probe/test_reconstructor_rebuild.py ...

``sitecustomize.py`` in this directory auto-installs when the dir is on
``PYTHONPATH`` and ``PROXY_BASE_URL`` is set.
"""
from __future__ import annotations

import http.client
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterable, Mapping, Optional

EGG_PROXY_RE = re.compile(r"(?im)^\s*use\s*=\s*egg:swift#proxy\s*$")
OBJECT_GET_METHODS = frozenset({"GET", "HEAD"})

INTERNAL_CLIENT_CONF_CANDIDATES = (
    "SWIFT_INTERNAL_CLIENT_CONF",
    "INTERNAL_CLIENT_CONF",
)

DEFAULT_CONF_PATHS = (
    "/etc/g6-rust/internal-client.conf",
    "/etc/swift/internal-client.conf",
)


class RustProxyGetError(RuntimeError):
    """PROXY_BASE_URL is set but the GET would still miss rust HTTP."""


class _HttpResp:
    """swob-shaped object for ``InternalClient.get_object`` / ``make_request``."""

    def __init__(self, status: int, headers: Mapping[str, str], body: bytes):
        self.status_int = int(status)
        phrase = http.client.responses.get(self.status_int, "Unknown")
        self.status = f"{self.status_int} {phrase}"
        self.headers = dict(headers)
        self.body = body
        self.app_iter: Iterable[bytes] = [body] if body else []


def proxy_base_url(environ: Optional[Mapping[str, str]] = None) -> str:
    env = environ if environ is not None else os.environ
    return (env.get("PROXY_BASE_URL") or "").strip()


def join_proxy_url(
    base: str, path: str, params: Optional[Mapping[str, Any]] = None
) -> str:
    """Join IsolatedIdentity PROXY_BASE_URL with InternalClient.make_path.

    ``http://127.0.0.1:18080`` + ``/v1/a/c/o`` → ``http://127.0.0.1:18080/v1/a/c/o``.
    A base that already ends in ``/v1`` is not doubled.
    """
    base = (base or "").strip().rstrip("/")
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if base.endswith("/v1") and path.startswith("/v1"):
        url = base[: -len("/v1")] + path
    else:
        url = base + path
    if params:
        qs = urllib.parse.urlencode(params, doseq=True)
        url += ("&" if "?" in url else "?") + qs
    return url


def conf_uses_egg_swift_proxy(text: str) -> bool:
    return bool(EGG_PROXY_RE.search(text or ""))


def find_internal_client_conf(
    environ: Optional[Mapping[str, str]] = None,
) -> Optional[str]:
    env = environ if environ is not None else os.environ
    for key in INTERNAL_CLIENT_CONF_CANDIDATES:
        raw = (env.get(key) or "").strip()
        if raw:
            return raw
    swift_dir = (env.get("SWIFT_DIR") or "").strip()
    if swift_dir:
        candidate = os.path.join(swift_dir, "internal-client.conf")
        if os.path.isfile(candidate):
            return candidate
    for path in DEFAULT_CONF_PATHS:
        if os.path.isfile(path):
            return path
    return None


def rust_object_get_guard(
    environ: Optional[Mapping[str, str]] = None,
    conf_text: Optional[str] = None,
    adapter_installed: Optional[bool] = None,
) -> None:
    """Fail closed when IsolatedIdentity GETs would still use egg:swift#proxy."""
    env = environ if environ is not None else os.environ
    base = proxy_base_url(env)
    if not base:
        return
    installed = is_installed() if adapter_installed is None else adapter_installed
    if installed:
        return
    text = conf_text
    if text is None:
        path = find_internal_client_conf(env)
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        else:
            text = ""
    if conf_uses_egg_swift_proxy(text) or text == "":
        raise RustProxyGetError(
            f"PROXY_BASE_URL={base} is set but InternalClient GET still uses "
            "in-process egg:swift#proxy (adapter not installed). "
            "G6 rebuild proxy_get would never hit rust :18080."
        )


def g6_auth_headers(environ: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    """Same classic probe env the suite already exports (TempAuth / ST_*)."""
    env = environ if environ is not None else os.environ
    headers: dict[str, str] = {}
    token = (env.get("OS_AUTH_TOKEN") or env.get("ST_AUTH_TOKEN") or "").strip()
    if token:
        headers["X-Auth-Token"] = token
    user = (env.get("ST_USER") or "").strip()
    key = (env.get("ST_KEY") or "").strip()
    if user:
        headers["X-Auth-User"] = user
    if key:
        headers["X-Auth-Key"] = key
    return headers


def _header_items(headers: Optional[Mapping[str, Any]]) -> list[tuple[str, str]]:
    if not headers:
        return []
    items = getattr(headers, "items", None)
    raw = list(items()) if callable(items) else list(headers)
    out: list[tuple[str, str]] = []
    for pair in raw:
        if isinstance(pair, (tuple, list)) and len(pair) == 2:
            out.append((str(pair[0]), str(pair[1])))
    return out


def rust_http_exchange(
    method: str,
    url: str,
    headers: Optional[Mapping[str, Any]] = None,
    timeout: float = 30.0,
    opener: Optional[Callable[..., Any]] = None,
) -> _HttpResp:
    req = urllib.request.Request(url, method=method.upper())
    for name, value in _header_items(headers):
        if name.lower() in {"content-length", "transfer-encoding", "host"}:
            continue
        req.add_header(name, value)
    open_url = opener or urllib.request.urlopen
    try:
        with open_url(req, timeout=timeout) as resp:
            body = resp.read()
            status = getattr(resp, "status", None) or resp.getcode()
            return _HttpResp(int(status), dict(resp.headers), body)
    except urllib.error.HTTPError as err:
        body = err.read() if err.fp is not None else b""
        hdrs = dict(err.headers) if err.headers is not None else {}
        return _HttpResp(int(err.code), hdrs, body)


def rust_http_make_request(
    method: str,
    path: str,
    headers: Optional[Mapping[str, Any]],
    acceptable_statuses: Iterable[Any],
    params: Optional[Mapping[str, Any]] = None,
    environ: Optional[Mapping[str, str]] = None,
    opener: Optional[Callable[..., Any]] = None,
    unexpected_cls: Optional[type] = None,
) -> _HttpResp:
    base = proxy_base_url(environ)
    if not base:
        raise RustProxyGetError("PROXY_BASE_URL is empty; refusing rust HTTP GET")
    merged = dict(_header_items(headers))
    for name, value in g6_auth_headers(environ).items():
        merged.setdefault(name, value)
    merged.setdefault("X-Backend-Allow-Reserved-Names", "true")
    url = join_proxy_url(base, path, params)
    resp = rust_http_exchange(method, url, merged, opener=opener)
    acceptable = tuple(acceptable_statuses)
    status = resp.status_int
    ok = status in acceptable or (status // 100) in acceptable
    if ok:
        return resp
    exc_cls = unexpected_cls or _unexpected_response_class()
    msg = f"Unexpected response: {resp.status}"
    if status // 100 != 2 and resp.body:
        msg += f" ({resp.body!r})"
    raise exc_cls(msg, resp)


def _unexpected_response_class() -> type:
    try:
        from swift.common.internal_client import UnexpectedResponse

        return UnexpectedResponse
    except Exception:

        class UnexpectedResponse(Exception):
            def __init__(self, message, resp):
                super().__init__(message)
                self.resp = resp

        return UnexpectedResponse


_installed_targets: list[Any] = []


def is_installed() -> bool:
    return bool(_installed_targets)


def _wrap_make_request(orig: Callable[..., Any]) -> Callable[..., Any]:
    def make_request(
        self,
        method,
        path,
        headers,
        acceptable_statuses,
        body_file=None,
        params=None,
    ):
        del body_file
        method_u = str(method or "").upper()
        if proxy_base_url() and method_u in OBJECT_GET_METHODS:
            return rust_http_make_request(
                method_u, path, headers, acceptable_statuses, params=params
            )
        return orig(
            self,
            method,
            path,
            headers,
            acceptable_statuses,
            body_file=None,
            params=params,
        )

    make_request._g6_rust_http = True  # type: ignore[attr-defined]
    make_request._g6_rust_http_orig = orig  # type: ignore[attr-defined]
    return make_request


def install(target: Optional[type] = None) -> bool:
    """Patch InternalClient.make_request (or ``target``) for rust HTTP GET/HEAD."""
    cls = target
    if cls is None:
        try:
            from swift.common.internal_client import InternalClient
        except Exception:
            return False
        cls = InternalClient
    current = getattr(cls, "make_request", None)
    if current is not None and getattr(current, "_g6_rust_http", False):
        if cls not in _installed_targets:
            _installed_targets.append(cls)
        return True
    if current is None:
        return False
    cls.make_request = _wrap_make_request(current)
    if cls not in _installed_targets:
        _installed_targets.append(cls)
    rust_object_get_guard(adapter_installed=True)
    return True


def uninstall() -> None:
    while _installed_targets:
        cls = _installed_targets.pop()
        current = getattr(cls, "make_request", None)
        orig = getattr(current, "_g6_rust_http_orig", None)
        if orig is not None:
            cls.make_request = orig


def maybe_autostart() -> bool:
    if not proxy_base_url():
        return False
    ok = install()
    rust_object_get_guard(adapter_installed=is_installed())
    return ok


def pytest_configure(config):  # noqa: ARG001
    if proxy_base_url():
        maybe_autostart()


def pytest_sessionstart(session):  # noqa: ARG001
    base = proxy_base_url()
    if not base:
        return
    print(
        f"G6 rust proxy GET: PROXY_BASE_URL={base} adapter="
        f"{'installed' if is_installed() else 'MISSING'}",
        flush=True,
    )
    rust_object_get_guard(adapter_installed=is_installed())


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail closed if PROXY_BASE_URL is set without the rust GET adapter",
    )
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args(argv)
    if args.install:
        ok = maybe_autostart()
        print(f"adapter_installed={ok} PROXY_BASE_URL={proxy_base_url()!r}")
        return 0 if ok or not proxy_base_url() else 2
    if args.check:
        rust_object_get_guard()
        print(
            f"ok PROXY_BASE_URL={proxy_base_url()!r} adapter_installed={is_installed()}"
        )
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
