#!/usr/bin/env python3
"""Send G6 rebuild ``proxy_get`` to isolated rust HTTP, not ``egg:swift#proxy``.

Field ``988b81b``: official ``proxy_get`` used in-process
``InternalClient`` / ``egg:swift#proxy``. After forcing GET onto rust
HTTP ``:18080`` (swiftclient, same auth as PUT/POST) that tip **PASSED**
``test_rebuild_missing_frags`` (~10s, 30× ``G6_DIAG … status=200
reason=ok``). Lab patch: if ``PROXY_BASE_URL`` contains ``:18080``,
``proxy_get()`` uses ``swiftclient``; else InternalClient.

This module is that honesty for the IsolatedIdentity runner:

1. ``--prepare`` / ``g6_isolated_probe.sh`` rewrite official ``proxy_get``
   when ``PROXY_BASE_URL`` contains ``:18080`` (same as lab
   ``bak.httpget-988b81b``).
2. Runtime-wrap ``TestReconstructorRebuild.proxy_get`` the same way.
3. Fail closed if ``:18080`` is set and GET/HEAD/PUT would still use
   ``InternalClient`` / ``egg:swift#proxy``. Official lonely-frag HEAD
   and non-durable v2 ``upload_object`` are ``make_request``; both
   rewrite to rust HTTP **with the body**. Do not drop ``body_file``.

Field ``/workspace/rebuild-nondurable-2d774ae/`` (2026-09-06):
``ProbeBody.read(amount)`` requires a size (``read()`` TypeError), and
``upload_object`` sets ``Transfer-Encoding: chunked`` without framing.
A one-shot urllib/http.client send of ~3.5MiB then **BrokenPipe** on
the eventlet green socket (server closed mid-send). Drain with sized
reads, make ``Body.read`` file-like, and PUT with ``Content-Length``
plus chunked socket writes. No ``Expect`` / no unframed chunked TE.

``PROXY_BASE_URL`` without ``:18080`` (classic ``:8080``) is left alone.
Do not reopen gather-bucket chasing, lonely_frag, or missing_frags.

    export PROXY_BASE_URL=http://127.0.0.1:18080
    # IsolatedIdentity must go through this wrapper (or --prepare):
    swift-rust/tools/test-lab/g6_isolated_probe.sh pytest \\
        test/probe/test_reconstructor_rebuild.py::TestReconstructorRebuild::test_rebuild_missing_frags -vv
"""
from __future__ import annotations

import hashlib
import http.client
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterable, Mapping, Optional

EGG_PROXY_RE = re.compile(r"(?im)^\s*use\s*=\s*egg:swift#proxy\s*$")
OBJECT_GET_METHODS = frozenset({"GET", "HEAD"})
# Official test_rebuild_with_non_durable_newer_data PUTs v2 via
# InternalClient.upload_object (make_request PUT + body). GET/HEAD-only
# wrapping dropped that body (body_file=None) so rust never saw v2.
OBJECT_HTTP_METHODS = frozenset({"GET", "HEAD", "PUT", "POST", "DELETE"})

INTERNAL_CLIENT_CONF_CANDIDATES = (
    "SWIFT_INTERNAL_CLIENT_CONF",
    "INTERNAL_CLIENT_CONF",
)

DEFAULT_CONF_PATHS = (
    "/etc/g6-rust/internal-client.conf",
    "/etc/swift/internal-client.conf",
)


ISOLATED_RUST_PORT_TOKEN = ":18080"
PUT_SEND_CHUNK = 64 * 1024
PUT_TIMEOUT_SECS = 120.0
BODY_READ_CHUNK = 64 * 1024
HOP_BY_HOP_REQUEST = frozenset(
    {"content-length", "transfer-encoding", "host", "expect", "connection"}
)
CONTINUE_WAIT_SECS = 30.0
PROBE_PATCH_MARKER = "Peregrine G6: IsolatedIdentity rust :18080 must HTTP"
DEFAULT_OFFICIAL_PROBE = (
    "/root/work/swift-master/test/probe/test_reconstructor_rebuild.py"
)
PROBE_PATH_ENV_KEYS = ("G6_REBUILD_PROBE_PATH", "SWIFT_RECONSTRUCTOR_REBUILD")
SWIFT_SOURCE_ENV_KEYS = ("SWIFT_SOURCE", "SWIFT_REPO", "SWIFT_MASTER")

OFFICIAL_PROXY_GET_HEAD = """    def proxy_get(self):
        # Use internal-client instead of python-swiftclient, since we can't
        # handle UTF-8 headers properly w/ swiftclient.
        # Still a proxy-server tho!
"""

LAB_PROXY_GET_HEAD = f"""    def proxy_get(self):
        # {PROBE_PATCH_MARKER}, not egg:swift#proxy.
        import os
        if '{ISOLATED_RUST_PORT_TOKEN}' in (os.environ.get('PROXY_BASE_URL') or ''):
            headers, body = client.get_object(
                self.url, self.token, self.container_name, self.object_name)
            resp_checksum = md5(usedforsecurity=False)
            if isinstance(body, (bytes, bytearray)):
                resp_checksum.update(body)
            else:
                for chunk in body:
                    resp_checksum.update(chunk)
            return HeaderKeyDict(headers), resp_checksum.hexdigest()
        # Use internal-client instead of python-swiftclient, since we can't
        # handle UTF-8 headers properly w/ swiftclient.
        # Still a proxy-server tho!
"""


class RustProxyGetError(RuntimeError):
    """PROXY_BASE_URL points at rust :18080 but GET would still miss rust HTTP."""


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


def uses_isolated_rust_proxy(environ: Optional[Mapping[str, str]] = None) -> bool:
    """Lab gate: IsolatedIdentity rust listen is ``:18080``, not production ``:8080``."""
    return ISOLATED_RUST_PORT_TOKEN in proxy_base_url(environ)


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


def official_probe_candidates(
    environ: Optional[Mapping[str, str]] = None,
) -> list[str]:
    """Lab official probe, then IsolatedIdentity env overrides."""
    env = environ if environ is not None else os.environ
    out: list[str] = []
    for key in PROBE_PATH_ENV_KEYS:
        raw = (env.get(key) or "").strip()
        if raw:
            out.append(raw)
    for key in SWIFT_SOURCE_ENV_KEYS:
        raw = (env.get(key) or "").strip()
        if raw:
            out.append(
                os.path.join(raw, "test/probe/test_reconstructor_rebuild.py")
            )
    out.append(DEFAULT_OFFICIAL_PROBE)
    seen: set[str] = set()
    uniq: list[str] = []
    for path in out:
        if path not in seen:
            seen.add(path)
            uniq.append(path)
    return uniq


def find_official_probe(
    environ: Optional[Mapping[str, str]] = None,
) -> Optional[str]:
    for path in official_probe_candidates(environ):
        if os.path.isfile(path):
            return path
    return None


def official_probe_routes_rust_http(
    environ: Optional[Mapping[str, str]] = None,
    text: Optional[str] = None,
    path: Optional[str] = None,
) -> bool:
    if text is not None:
        return probe_source_routes_rust_http(text)
    probe = path or find_official_probe(environ)
    if not probe:
        return False
    with open(probe, encoding="utf-8") as fh:
        return probe_source_routes_rust_http(fh.read())


def rust_object_get_guard(
    environ: Optional[Mapping[str, str]] = None,
    conf_text: Optional[str] = None,
    adapter_installed: Optional[bool] = None,
    source_routes_http: Optional[bool] = None,
) -> None:
    """Fail closed when IsolatedIdentity GETs would still use egg:swift#proxy."""
    env = environ if environ is not None else os.environ
    if not uses_isolated_rust_proxy(env):
        return
    base = proxy_base_url(env)
    installed = is_installed() if adapter_installed is None else adapter_installed
    if installed:
        return
    routed = (
        official_probe_routes_rust_http(env)
        if source_routes_http is None
        else source_routes_http
    )
    if routed:
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
            f"PROXY_BASE_URL={base} is set but InternalClient GET/HEAD/PUT still "
            "uses in-process egg:swift#proxy (adapter not installed; official "
            "proxy_get has no :18080 swiftclient branch). "
            "G6 rebuild GET/HEAD/PUT would never hit rust :18080."
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


def read_request_body(body_file: Any, chunk_size: int = BODY_READ_CHUNK) -> bytes:
    """Drain InternalClient.upload_object's ProbeBody.

    Official ``test.probe.common.Body.read(amount)`` requires a size.
    ``read()`` / ``read(-1)`` TypeError (field ``2d774ae``). Do not call
    ``read(-1)`` on the unpatched class: ``buff[:-1]`` drops a byte.
    """
    if body_file is None:
        return b""
    if isinstance(body_file, (bytes, bytearray)):
        return bytes(body_file)
    read = getattr(body_file, "read", None)
    if not callable(read):
        return b""
    try:
        data = read()
    except TypeError:
        data = None
    else:
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        return b""
    chunks: list[bytes] = []
    while True:
        try:
            piece = read(chunk_size)
        except TypeError:
            try:
                piece = read(size=chunk_size)
            except TypeError:
                break
        if not piece:
            break
        if not isinstance(piece, (bytes, bytearray)):
            break
        chunks.append(bytes(piece))
    return b"".join(chunks)


def _wrap_probe_body_read(orig: Callable[..., Any]) -> Callable[..., Any]:
    """Official ProbeBody.read(amount) → file-like read(size=-1)."""

    def read(self, amount=None, size=None):
        n = amount if amount is not None else size
        if n is None or (isinstance(n, int) and n < 0):
            chunks: list[bytes] = []
            while True:
                piece = orig(self, BODY_READ_CHUNK)
                if not piece:
                    break
                chunks.append(piece)
            return b"".join(chunks)
        return orig(self, int(n))

    read._g6_filelike_read = True  # type: ignore[attr-defined]
    read._g6_rust_http_orig = orig  # type: ignore[attr-defined]
    return read


def install_probe_body_read(target: Optional[type] = None) -> bool:
    """Patch official ProbeBody so read() and read(int) both work."""
    cls = target
    if cls is None:
        try:
            from test.probe.common import Body as ProbeBody
        except Exception:
            return False
        cls = ProbeBody
    current = getattr(cls, "read", None)
    if current is None:
        return False
    if getattr(current, "_g6_filelike_read", False):
        if cls not in _installed_targets:
            _installed_targets.append(cls)
        return True
    cls.read = _wrap_probe_body_read(current)
    if cls not in _installed_targets:
        _installed_targets.append(cls)
    return True


def _filter_outgoing_headers(
    headers: Optional[Mapping[str, Any]],
) -> list[tuple[str, str]]:
    """Drop hop-by-hop / framing headers IsolatedIdentity must not forward.

    ``upload_object`` sets ``Transfer-Encoding: chunked`` without chunk
    framing. Forwarding that with a raw body makes rust Hyper close
    mid-send (field BrokenPipe on ``:18080``).
    """
    out: list[tuple[str, str]] = []
    for name, value in _header_items(headers):
        if name.lower() in HOP_BY_HOP_REQUEST:
            continue
        out.append((name, value))
    return out


def _eventlet_hub_yield() -> None:
    """Let eventlet flush the green socket between PUT chunks."""
    try:
        import eventlet

        eventlet.sleep(0)
    except Exception:
        pass


def _read_http_head(sock: Any, timeout: float) -> tuple[int, bytes]:
    """Read one HTTP response head from a raw (possibly greened) socket."""
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 64 * 1024:
            raise RustProxyGetError("HTTP response head too large from rust :18080")
    if b"\r\n\r\n" not in buf:
        raise RustProxyGetError(
            f"no HTTP response head from rust :18080 ({buf[:200]!r})"
        )
    head, leftover = buf.split(b"\r\n\r\n", 1)
    if leftover:
        raise RustProxyGetError(
            "unexpected bytes after informational response head "
            f"({len(leftover)} leftover)"
        )
    status_line = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
    parts = status_line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise RustProxyGetError(f"bad HTTP status line {status_line!r}")
    return int(parts[1]), head


def rust_http_send_body(
    method: str,
    url: str,
    headers: Optional[Mapping[str, Any]],
    data: bytes,
    timeout: float = PUT_TIMEOUT_SECS,
    connection_cls: Optional[type] = None,
) -> _HttpResp:
    """PUT/POST to rust :18080 with Content-Length and chunked writes.

    Field ``/workspace/rebuild-nondurable-4e284ae/`` (2026-09-06):
    blasting the 3735552-byte body right after headers BrokenPipe on
    eventlet — rust Hyper peek/max_buf reset mid-send. Send
    ``Expect: 100-continue``, wait for 100, then 64KiB ``bytes`` writes
    with an eventlet yield. Look up HTTPConnection at call time so
    ``eventlet.monkey_patch`` is visible.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    payload = data if data is not None else b""
    if connection_cls is None:
        import http.client as http_client

        connection_cls = http_client.HTTPConnection
    conn = connection_cls(host, port, timeout=timeout)
    try:
        conn.putrequest(method.upper(), path, skip_accept_encoding=True)
        for name, value in _filter_outgoing_headers(headers):
            conn.putheader(name, value)
        conn.putheader("Content-Length", str(len(payload)))
        conn.putheader("Expect", "100-continue")
        conn.putheader("Connection", "close")
        conn.endheaders()
        wait = min(float(timeout), CONTINUE_WAIT_SECS) if timeout else CONTINUE_WAIT_SECS
        status, _head = _read_http_head(conn.sock, wait)
        if status == 100:
            for offset in range(0, len(payload), PUT_SEND_CHUNK):
                conn.send(bytes(payload[offset : offset + PUT_SEND_CHUNK]))
                _eventlet_hub_yield()
            resp = conn.getresponse()
            body = resp.read()
            hdrs = {k: v for k, v in resp.getheaders()}
            return _HttpResp(int(resp.status), hdrs, body)
        if status == 417:
            conn.close()
            return _put_without_expect(
                connection_cls, host, port, path, method, headers, payload, timeout
            )
        # Final response before the body (error). Do not send payload.
        return _HttpResp(status, {}, b"")
    except (BrokenPipeError, ConnectionResetError) as err:
        raise RustProxyGetError(
            f"BrokenPipe PUT {url} ({len(payload)} bytes) to rust :18080: {err}"
        ) from err
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _put_without_expect(
    connection_cls: type,
    host: str,
    port: int,
    path: str,
    method: str,
    headers: Optional[Mapping[str, Any]],
    payload: bytes,
    timeout: float,
) -> _HttpResp:
    conn = connection_cls(host, port, timeout=timeout)
    try:
        conn.putrequest(method.upper(), path, skip_accept_encoding=True)
        for name, value in _filter_outgoing_headers(headers):
            conn.putheader(name, value)
        conn.putheader("Content-Length", str(len(payload)))
        conn.putheader("Connection", "close")
        conn.endheaders()
        for offset in range(0, len(payload), PUT_SEND_CHUNK):
            conn.send(bytes(payload[offset : offset + PUT_SEND_CHUNK]))
            _eventlet_hub_yield()
        resp = conn.getresponse()
        body = resp.read()
        hdrs = {k: v for k, v in resp.getheaders()}
        return _HttpResp(int(resp.status), hdrs, body)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def rust_http_exchange(
    method: str,
    url: str,
    headers: Optional[Mapping[str, Any]] = None,
    timeout: float = 30.0,
    opener: Optional[Callable[..., Any]] = None,
    data: Optional[bytes] = None,
    connection_cls: Optional[type] = None,
) -> _HttpResp:
    method_u = method.upper()
    payload = data if data else b""
    if opener is None and (payload or method_u in {"PUT", "POST"}):
        return rust_http_send_body(
            method_u,
            url,
            headers,
            payload,
            timeout=timeout if timeout and timeout > 0 else PUT_TIMEOUT_SECS,
            connection_cls=connection_cls,
        )
    req = urllib.request.Request(
        url, data=payload or None, method=method_u
    )
    for name, value in _filter_outgoing_headers(headers):
        req.add_header(name, value)
    if payload:
        req.add_header("Content-Length", str(len(payload)))
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
    body: Optional[bytes] = None,
) -> _HttpResp:
    if not uses_isolated_rust_proxy(environ):
        raise RustProxyGetError(
            "PROXY_BASE_URL does not point at isolated rust :18080; "
            "refusing to rewrite InternalClient HTTP"
        )
    base = proxy_base_url(environ)
    merged = dict(_header_items(headers))
    for name, value in g6_auth_headers(environ).items():
        merged.setdefault(name, value)
    merged.setdefault("X-Backend-Allow-Reserved-Names", "true")
    url = join_proxy_url(base, path, params)
    timeout = PUT_TIMEOUT_SECS if body or method.upper() in {"PUT", "POST"} else 30.0
    resp = rust_http_exchange(
        method, url, merged, timeout=timeout, opener=opener, data=body
    )
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
        method_u = str(method or "").upper()
        if uses_isolated_rust_proxy() and method_u in OBJECT_HTTP_METHODS:
            # Official test_rebuild_with_non_durable_newer_data PUTs v2
            # via upload_object. Dropping body_file made rust see an
            # empty PUT; durable v1 etag then equalled prefs GET.
            # Field `/workspace/g6-rebuild-988b81b-httpget/` (2026-09-06).
            return rust_http_make_request(
                method_u,
                path,
                headers,
                acceptable_statuses,
                params=params,
                body=read_request_body(body_file),
            )
        return orig(
            self,
            method,
            path,
            headers,
            acceptable_statuses,
            body_file=body_file,
            params=params,
        )

    make_request._g6_rust_http = True  # type: ignore[attr-defined]
    make_request._g6_rust_http_orig = orig  # type: ignore[attr-defined]
    return make_request


def _md5():
    try:
        return hashlib.md5(usedforsecurity=False)
    except TypeError:
        return hashlib.md5()


def rust_swiftclient_proxy_get(
    probe: Any,
    *,
    get_object: Optional[Callable[..., Any]] = None,
    header_dict: Optional[type] = None,
) -> tuple[Any, str]:
    """Field-confirmed ``proxy_get``: swiftclient HTTP to ``self.url`` / token.

    Same return as official ``TestReconstructorRebuild.proxy_get``:
    ``(headers, md5_hex)``.
    """
    getter = get_object
    if getter is None:
        from swiftclient import client as swiftclient_client

        getter = swiftclient_client.get_object
    headers, body = getter(
        probe.url, probe.token, probe.container_name, probe.object_name
    )
    digest = _md5()
    if isinstance(body, (bytes, bytearray)):
        digest.update(body)
    else:
        for chunk in body:
            digest.update(chunk)
    wrapped = header_dict(headers) if header_dict is not None else dict(headers)
    return wrapped, digest.hexdigest()


def _wrap_probe_proxy_get(orig: Callable[..., Any]) -> Callable[..., Any]:
    def proxy_get(self):
        if uses_isolated_rust_proxy():
            header_dict = None
            try:
                from swift.common.header_key_dict import HeaderKeyDict

                header_dict = HeaderKeyDict
            except Exception:
                header_dict = dict
            return rust_swiftclient_proxy_get(self, header_dict=header_dict)
        return orig(self)

    proxy_get._g6_rust_http = True  # type: ignore[attr-defined]
    proxy_get._g6_rust_http_orig = orig  # type: ignore[attr-defined]
    return proxy_get


def probe_source_routes_rust_http(text: str) -> bool:
    return PROBE_PATCH_MARKER in (text or "") or (
        "def proxy_get" in (text or "")
        and ISOLATED_RUST_PORT_TOKEN in (text or "")
        and "client.get_object" in (text or "")
    )


def apply_lab_proxy_get_to_source(text: str) -> tuple[str, bool]:
    """Insert the field-confirmed ``:18080`` swiftclient branch into official proxy_get."""
    if PROBE_PATCH_MARKER in text:
        return text, False
    if OFFICIAL_PROXY_GET_HEAD not in text:
        raise RustProxyGetError(
            "cannot find official TestReconstructorRebuild.proxy_get to patch"
        )
    return text.replace(OFFICIAL_PROXY_GET_HEAD, LAB_PROXY_GET_HEAD, 1), True


def apply_lab_proxy_get_to_file(path: str) -> bool:
    with open(path, encoding="utf-8") as fh:
        original = fh.read()
    updated, changed = apply_lab_proxy_get_to_source(original)
    if changed:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(updated)
    return changed


def install_probe_proxy_get(target: Optional[type] = None) -> bool:
    cls = target
    if cls is None:
        try:
            from test.probe.test_reconstructor_rebuild import TestReconstructorRebuild
        except Exception:
            return False
        cls = TestReconstructorRebuild
    current = getattr(cls, "proxy_get", None)
    if current is None:
        return False
    if getattr(current, "_g6_rust_http", False):
        if cls not in _installed_targets:
            _installed_targets.append(cls)
        return True
    cls.proxy_get = _wrap_probe_proxy_get(current)
    if cls not in _installed_targets:
        _installed_targets.append(cls)
    return True


def install(target: Optional[type] = None) -> bool:
    """Install swiftclient ``proxy_get`` + fail-closed InternalClient GET."""
    ok = install_probe_body_read()
    ok = install_probe_proxy_get() or ok
    cls = target
    if cls is None:
        try:
            from swift.common.internal_client import InternalClient
        except Exception:
            InternalClient = None  # type: ignore[assignment]
        cls = InternalClient
    if cls is not None:
        current = getattr(cls, "make_request", None)
        if current is not None and not getattr(current, "_g6_rust_http", False):
            cls.make_request = _wrap_make_request(current)
            if cls not in _installed_targets:
                _installed_targets.append(cls)
            ok = True
        elif current is not None and getattr(current, "_g6_rust_http", False):
            if cls not in _installed_targets:
                _installed_targets.append(cls)
            ok = True
    return ok


def uninstall() -> None:
    while _installed_targets:
        cls = _installed_targets.pop()
        for attr in ("make_request", "proxy_get", "read"):
            current = getattr(cls, attr, None)
            orig = getattr(current, "_g6_rust_http_orig", None)
            if orig is not None:
                setattr(cls, attr, orig)


def prepare_isolated_proxy_get(
    environ: Optional[Mapping[str, str]] = None,
    probe_path: Optional[str] = None,
) -> dict[str, Any]:
    """IsolatedIdentity entry: apply lab ``proxy_get`` + fail closed.

    When ``PROXY_BASE_URL`` contains ``:18080``, rewrite the official
    probe if present (same honesty as ``bak.httpget-988b81b``), wrap
    runtime ``proxy_get``, and refuse ``egg:swift#proxy`` GET unless
    one of those routes is live.
    """
    env = environ if environ is not None else os.environ
    result: dict[str, Any] = {
        "proxy_base_url": proxy_base_url(env),
        "isolated": uses_isolated_rust_proxy(env),
        "probe_path": None,
        "probe_changed": False,
        "probe_routes_http": False,
        "adapter_installed": False,
    }
    if not result["isolated"]:
        return result
    path = probe_path or find_official_probe(env)
    result["probe_path"] = path
    if path:
        result["probe_changed"] = apply_lab_proxy_get_to_file(path)
        result["probe_routes_http"] = official_probe_routes_rust_http(
            env, path=path
        )
    result["adapter_installed"] = install()
    rust_object_get_guard(
        environ=env,
        adapter_installed=is_installed(),
        source_routes_http=result["probe_routes_http"],
    )
    return result


def maybe_autostart() -> bool:
    result = prepare_isolated_proxy_get()
    return bool(
        result["adapter_installed"]
        or result["probe_routes_http"]
        or not result["isolated"]
    )


def pytest_configure(config):  # noqa: ARG001
    if uses_isolated_rust_proxy():
        maybe_autostart()


def pytest_sessionstart(session):  # noqa: ARG001
    base = proxy_base_url()
    if not uses_isolated_rust_proxy():
        return
    print(
        f"G6 rust proxy GET/HEAD: PROXY_BASE_URL={base} adapter="
        f"{'installed' if is_installed() else 'MISSING'} route=rust-http",
        flush=True,
    )
    rust_object_get_guard(adapter_installed=is_installed())


def main(argv: Optional[list[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail closed if :18080 is set without swiftclient proxy_get "
        "(adapter or already-patched official source)",
    )
    parser.add_argument("--install", action="store_true")
    parser.add_argument(
        "--prepare",
        action="store_true",
        help="IsolatedIdentity hook: apply lab proxy_get + fail closed",
    )
    parser.add_argument(
        "--apply-probe",
        metavar="PATH",
        help="rewrite official test_reconstructor_rebuild.py proxy_get "
        "(lab file /root/work/swift-master/test/probe/test_reconstructor_rebuild.py)",
    )
    args = parser.parse_args(argv)
    if args.apply_probe:
        changed = apply_lab_proxy_get_to_file(args.apply_probe)
        print(f"apply_probe={args.apply_probe} changed={changed}")
        return 0
    if args.prepare:
        result = prepare_isolated_proxy_get()
        print(
            "prepare isolated={isolated} PROXY_BASE_URL={proxy_base_url!r} "
            "probe={probe_path} changed={probe_changed} "
            "routes_http={probe_routes_http} "
            "adapter_installed={adapter_installed}".format(**result)
        )
        return 0
    if args.install:
        ok = maybe_autostart()
        print(f"adapter_installed={ok} PROXY_BASE_URL={proxy_base_url()!r}")
        return 0 if ok or not uses_isolated_rust_proxy() else 2
    if args.check:
        rust_object_get_guard()
        print(
            f"ok PROXY_BASE_URL={proxy_base_url()!r} "
            f"adapter_installed={is_installed()} "
            f"probe_routes_http={official_probe_routes_rust_http()}"
        )
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
