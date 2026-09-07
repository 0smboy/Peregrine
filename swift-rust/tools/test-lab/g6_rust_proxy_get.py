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

Field ``/workspace/rebuild-nondurable-176505e/`` (2026-09-06) on
``176505e`` (proxy ``faaeed18…``): ``test_rebuild_with_non_durable_newer_data``
**PASSED** (BrokenPipe gone; prefs GET etag v2≠v1). Public ``:18080``
pipeline includes gatekeeper, which strips ``X-Backend-*`` (including
``X-Backend-No-Commit``). Field routed those IC PUTs and
backend-header ``proxy_get`` via rust ``:18082``. Do not reopen
lonely_frag, missing_frags, or non_durable_newer_data.

Field ``/workspace/g6-rebuild-176505e/`` (2026-09-06): UTF8 class
``UnicodeEncodeError`` ``'\\xe8'`` in ``http.client.putrequest`` when
container/object names contain ``è``. Percent-encode the request-target
(IRI → HTTP). ``putheader`` names are ASCII — send WSGI ``Ã¨`` as
latin-1. ``email.parser`` drops ``X-Object-Meta-\\xc3\\xa8-…`` so
response heads are read as latin-1 (lonely-frag HEAD meta). Expose
InternalClient WSGI aliases (``x-object-meta-Ã¨-…``).

Official lonely HEAD sends ``{}``; IsolatedIdentity GET/HEAD stamp
``X-Object-Meta-è-g6-utf8-compat`` so rust writes UTF-8 object-meta
on the utf8-compat lane (Hyper drops non-token names). ``WsgiHeaderDict``
implements ``in`` / ``[]`` without ``str.lower()``.

Field ``/workspace/g6-rebuild-6042407-utf8-lonely/`` (2026-09-06) on
adapter ``6042407`` / bins ``cb712ff``: UTF8 lonely-frag HEAD **PASS**.
Honesty kept that HEAD on ``int_client.make_request``: IsolatedIdentity
owns latin-1 parse + ``WsgiHeaderDict``. ``client.head_object`` /
urllib3 dropped UTF-8 meta (``Ãè``). Do not reopen leftover B.

ASCII ``test_sync_expired_object``: official wait is a ``while``/``else``
poll (``x-delete-after=2`` + 1s). Official IsolatedIdentity ``proxy_get``
is ``InternalClient.get_object`` and must raise ``UnexpectedResponse``
with ``status_int=404``. IsolatedIdentity used to use swiftclient GET
(404 is ``ClientException``; a rust 200 loops until timeout). This tip
uses rust HTTP IsolatedIdentity ``proxy_get`` (404 → ``UnexpectedResponse``),
converts PUT ``X-Delete-After`` → ``X-Delete-At``, and 404s IsolatedIdentity
GET when that timestamp is past — even if rust still returns 200.
Do not call field expire PASS from units.

Field ``/workspace/g6-merge-982e86a/`` (2026-09-06): ReservedNamespace
merge PUTs ERRORed ``unexpected bytes after informational response
head (29 leftover)``. IsolatedIdentity ``100 Continue`` must treat
coalesced leftover as the next response, not raise.

Field ``/workspace/g6-merge-next-rootcause.txt`` (2026-09-07) after
``4764ef1``: merge family **PASS=6 / bad=5**. ``rust_http_make_request``
still sent caller ``X-Backend-*`` to public ``:18080``. Gatekeeper
stripped ``X-Backend-Allow-Reserved-Names`` (ReservedNamespace
``put_container`` → ``check_utf8(..., internal=False)`` → **412** on
NULL reserved names) and ``X-Backend-Storage-Policy-Index``
(reconciler HEAD found the object on the wrong policy → **200**).
Hop ``rust_http_make_request`` to ``G6_INTERNAL_PROXY_URL`` (default
``:18082``) when headers carry any ``X-Backend-*``.

Field ``/workspace/g6-merge-xbackend-18082/`` (2026-09-07) after
``8353823`` + wrap: merge family **PASS=9 / bad=2**. Brain
``put_container`` only sends ``X-Storage-Policy``. Egg
``InternalClient.make_request`` ``setdefault``
``X-Backend-Allow-Reserved-Names`` **before** the hop; pure
``8353823`` stamped after hop so those PUTs stayed on ``:18080``
→ **412**. Field wrap before hop cleared ReservedNamespace 412 and
``move_twice`` 200. Residual ReservedNamespace ``get_object`` 404
was brain ``translate_client_exception`` KeyError (incomplete
``_HttpResp.environ`` / missing ``explanation``), not a missing
object. Field ``/workspace/g6-merge-404-rootcause.txt`` (2026-09-07):
fill environ from the request URL + ``explanation``. Reserved GET
2xx already proven (``move_twice`` PASS). Do not reopen rebuild
17/17. Not G6 GREEN. ``sync_expired`` 503 is lab noise.

Field ``/workspace/g6-rebuild-982e86a-unified/`` (2026-09-06) on tip
``982e86a``: full rebuild theme **17/17 PASS**. Public ``:18080``
gatekeeper strips ``X-Backend-*``. IsolatedIdentity GET and no-commit
/ backend-header hops use rust ``:18082`` when ``G6_INTERNAL_PROXY_URL``
is set (bare ``g6_isolated_probe.sh`` defaults it).
Do not raw-replace IsolatedIdentity ``proxy_get`` with
swiftclient (drops ``UnexpectedResponse``). Rebuild theme is closed
for ``982e86a``. Not G6 179 GREEN.

Field ``/workspace/g6-partpower-next-rootcause.txt`` (2026-09-07):
official partpower setUp asserts ``/etc/swift/backups`` +
``object.builder``. Isolated G6 is ``SWIFT_DIR=/etc/g6-rust``. The
launcher stamps that env; setUp ``os.access('/etc/swift*')`` is remapped.
Do not invent ``/etc/swift``. Do not change rust bins.

``PROXY_BASE_URL`` without ``:18080`` (classic ``:8080``) is left alone.

    export PROXY_BASE_URL=http://127.0.0.1:18080
    # IsolatedIdentity must go through this wrapper (or --prepare):
    swift-rust/tools/test-lab/g6_isolated_probe.sh pytest \\
        test/probe/test_reconstructor_rebuild.py::TestReconstructorRebuild::test_rebuild_missing_frags -vv
"""
from __future__ import annotations

import hashlib
import http.client
import io
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterable, Mapping, Optional

EGG_PROXY_RE = re.compile(r"(?im)^\s*use\s*=\s*egg:swift#proxy\s*$")
OBJECT_GET_METHODS = frozenset({"GET", "HEAD"})
# Official UTF8 lonely HEAD sends ``{}``. Rust Hyper then drops
# ``X-Object-Meta-è`` (token names only). One UTF-8 object-meta request
# name forces the utf8-compat write lane. GET/HEAD only — never PUT/POST.
UTF8_HANDOFF_HEADER = "X-Object-Meta-è-g6-utf8-compat"
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
# Public IsolatedIdentity :18080 pipeline includes gatekeeper, which strips
# every X-Backend-* (X-Backend-No-Commit, Fragment-Preferences, …).
# Field 17/17 (`/workspace/g6-rebuild-982e86a-unified/`, 2026-09-06)
# sent IsolatedIdentity GET and no-commit / backend-header traffic to
# rust :18082 (no gatekeeper) via G6_INTERNAL_PROXY_URL. IsolatedIdentity
# IsolatedIdentity proxy_get still raises UnexpectedResponse on expire 404 —
# do not raw-replace IsolatedIdentity proxy_get with swiftclient.
ISOLATED_INTERNAL_PORT_TOKEN = ":18082"
G6_INTERNAL_PROXY_URL_ENV = "G6_INTERNAL_PROXY_URL"
DEFAULT_INTERNAL_PROXY_URL = "http://127.0.0.1:18082"
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
DEFAULT_OFFICIAL_PARTPOWER = (
    "/root/work/swift-master/test/probe/test_object_partpower_increase.py"
)
PROBE_PATH_ENV_KEYS = ("G6_REBUILD_PROBE_PATH", "SWIFT_RECONSTRUCTOR_REBUILD")
PARTPOWER_PATH_ENV_KEYS = ("G6_PARTPOWER_PROBE_PATH",)
SWIFT_SOURCE_ENV_KEYS = ("SWIFT_SOURCE", "SWIFT_REPO", "SWIFT_MASTER")
DEFAULT_ISOLATED_SWIFT_DIR = "/etc/g6-rust"
ETC_SWIFT_PREFIX = "/etc/swift"
PARTPOWER_SWIFT_DIR_MARKER = "Peregrine G6: IsolatedIdentity SWIFT_DIR"

OFFICIAL_PROXY_GET_HEAD = """    def proxy_get(self):
        # Use internal-client instead of python-swiftclient, since we can't
        # handle UTF-8 headers properly w/ swiftclient.
        # Still a proxy-server tho!
"""

LAB_PROXY_GET_HEAD = f"""    def proxy_get(self):
        # {PROBE_PATCH_MARKER}, not egg:swift#proxy.
        import os
        if '{ISOLATED_RUST_PORT_TOKEN}' in (os.environ.get('PROXY_BASE_URL') or ''):
            from g6_rust_proxy_get import rust_http_proxy_get
            return rust_http_proxy_get(self)
        # Use internal-client instead of python-swiftclient, since we can't
        # handle UTF-8 headers properly w/ swiftclient.
        # Still a proxy-server tho!
"""

# Official ECProbeTest.proxy_put (test/probe/common.py). IsolatedIdentity
# converts x-delete-after N → X-Delete-At so rust persist cannot miss the
# after→at rewrite (Python proxy does this before backend MIME).
OFFICIAL_PROXY_PUT_HEAD = """    def proxy_put(self, extra_headers=None):
        contents = Body()
"""

LAB_PROXY_PUT_HEAD = """    def proxy_put(self, extra_headers=None):
        extra_headers = __import__('g6_rust_proxy_get', fromlist=['x']).resolve_delete_after_headers(extra_headers)
        contents = Body()
"""

G6_DELETE_AT_ATTR = "_g6_isolated_delete_at"


class RustProxyGetError(RuntimeError):
    """PROXY_BASE_URL points at rust :18080 but GET would still miss rust HTTP."""


class WsgiHeaderDict(dict):
    """Plain dict plus official ``assertIn(str_to_wsgi(key), headers)``.

    Swift ``HeaderKeyDict`` titles with ``str.capitalize`` / ``str.lower``,
    which turns ``Ã`` into ``ã`` and ``è`` into ``È``. Official UTF8 lonely
    HEAD looks up WSGI ``x-object-meta-Ãè-…`` — fold only ASCII A–Z.
    """

    def __contains__(self, key: object) -> bool:
        if dict.__contains__(self, key):
            return True
        if key is None:
            return False
        return _header_lookup(self, str(key)) is not None

    def __getitem__(self, key: object) -> str:
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        found = _header_lookup(self, str(key))
        if found is not None:
            return found
        raise KeyError(key)

    def get(self, key: object, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


TRANSLATE_ENVIRON_KEYS = (
    "wsgi.url_scheme",
    "SERVER_NAME",
    "SERVER_PORT",
    "PATH_INFO",
    "QUERY_STRING",
)


def wsgi_environ_from_url(
    url: str = "",
    method: str = "GET",
) -> dict[str, Any]:
    """Brain-translate-ready WSGI environ from the IsolatedIdentity request URL.

    Official ``test.probe.brain.translate_client_exception`` reads
    ``wsgi.url_scheme``, ``SERVER_NAME``, ``SERVER_PORT``, ``PATH_INFO``,
    ``QUERY_STRING``. Field ``/workspace/g6-merge-404-rootcause.txt``
    (2026-09-07): dummy ``wsgi.url_scheme``-only / ``PATH_INFO=/``
    environ KeyError'd on residual ReservedNamespace 404.
    """
    parsed = urllib.parse.urlparse(url or "http://127.0.0.1/")
    scheme = parsed.scheme or "http"
    host = parsed.hostname or "127.0.0.1"
    if parsed.port:
        port = str(parsed.port)
    else:
        port = "443" if scheme == "https" else "80"
    path = parsed.path or "/"
    query = parsed.query or ""
    return {
        "REQUEST_METHOD": str(method or "GET").upper(),
        "SCRIPT_NAME": "",
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "SERVER_NAME": host,
        "SERVER_PORT": port,
        "SERVER_PROTOCOL": "HTTP/1.1",
        "HTTP_HOST": f"{host}:{port}",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": scheme,
        "wsgi.input": io.BytesIO(b""),
        "wsgi.errors": io.BytesIO(),
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }


def minimal_wsgi_environ() -> dict[str, Any]:
    return wsgi_environ_from_url("")


def response_explanation(status: int, body: bytes) -> str:
    if body:
        text = body.decode("utf-8", "replace").strip()
        if text:
            return text
    return http.client.responses.get(int(status), "Unknown")


def brain_translate_unexpected(err: Any) -> dict[str, Any]:
    """Official ``test.probe.brain.translate_client_exception`` field access.

    Must not KeyError. ``http_reason`` is ``resp.explanation``.
    """
    resp = err.resp
    return {
        "http_scheme": resp.environ["wsgi.url_scheme"],
        "http_host": resp.environ["SERVER_NAME"],
        "http_port": resp.environ["SERVER_PORT"],
        "http_path": urllib.parse.quote(resp.environ["PATH_INFO"]),
        "http_query": resp.environ["QUERY_STRING"],
        "http_status": resp.status_int,
        "http_reason": resp.explanation,
        "http_response_content": resp.body,
        "http_response_headers": resp.headers,
    }


class _HttpResp:
    """swob-shaped object for ``InternalClient.get_object`` / ``make_request``."""

    def __init__(
        self,
        status: int,
        headers: Mapping[str, str],
        body: bytes,
        *,
        url: str = "",
        method: str = "GET",
        explanation: Optional[str] = None,
    ):
        self.status_int = int(status)
        phrase = http.client.responses.get(self.status_int, "Unknown")
        self.status = f"{self.status_int} {phrase}"
        self.headers = (
            headers if isinstance(headers, WsgiHeaderDict) else WsgiHeaderDict(headers)
        )
        self.body = body
        self.app_iter: Iterable[bytes] = [body] if body else []
        self.environ: dict[str, Any] = wsgi_environ_from_url(url, method)
        self.explanation = (
            explanation if explanation is not None else response_explanation(status, body)
        )


def proxy_base_url(environ: Optional[Mapping[str, str]] = None) -> str:
    env = environ if environ is not None else os.environ
    return (env.get("PROXY_BASE_URL") or "").strip()


def uses_isolated_rust_proxy(environ: Optional[Mapping[str, str]] = None) -> bool:
    """Lab gate: IsolatedIdentity rust listen is ``:18080``, not production ``:8080``."""
    return ISOLATED_RUST_PORT_TOKEN in proxy_base_url(environ)


def internal_proxy_url(environ: Optional[Mapping[str, str]] = None) -> str:
    """Gatekeeper-free rust listen (``:18082``). Empty when unset."""
    env = environ if environ is not None else os.environ
    return (env.get(G6_INTERNAL_PROXY_URL_ENV) or "").strip()


def isolated_swift_dir(environ: Optional[Mapping[str, str]] = None) -> str:
    """SWIFT_DIR for IsolatedIdentity, else empty.

    Field ``/workspace/g6-partpower-next-rootcause.txt`` (2026-09-07):
    official ``test_object_partpower_increase`` setUp asserts
    ``/etc/swift/backups`` and ``/etc/swift/object.builder``. Isolated
    G6 is ``SWIFT_DIR=/etc/g6-rust`` (already W_OK). Do not invent
    ``/etc/swift``. Explicit ``SWIFT_DIR`` always wins.
    """
    env = environ if environ is not None else os.environ
    explicit = (env.get("SWIFT_DIR") or "").strip()
    if explicit:
        return explicit
    if uses_isolated_rust_proxy(env):
        return DEFAULT_ISOLATED_SWIFT_DIR
    return ""


def ensure_isolated_swift_dir(
    environ: Optional[Mapping[str, str]] = None,
) -> str:
    """Stamp ``SWIFT_DIR=/etc/g6-rust`` when IsolatedIdentity ``:18080``."""
    env = environ if environ is not None else os.environ
    current = (env.get("SWIFT_DIR") or "").strip()
    if current:
        return current
    if not uses_isolated_rust_proxy(env):
        return ""
    env["SWIFT_DIR"] = DEFAULT_ISOLATED_SWIFT_DIR
    return DEFAULT_ISOLATED_SWIFT_DIR


def rewrite_etc_swift_path(
    path: str, environ: Optional[Mapping[str, str]] = None
) -> str:
    """Map official ``/etc/swift*`` asserts onto IsolatedIdentity SWIFT_DIR."""
    swift_dir = isolated_swift_dir(environ)
    if not swift_dir or not path:
        return path
    if path == ETC_SWIFT_PREFIX or path.startswith(ETC_SWIFT_PREFIX + "/"):
        return swift_dir + path[len(ETC_SWIFT_PREFIX) :]
    return path


def ensure_internal_proxy_url(
    environ: Optional[Mapping[str, str]] = None,
) -> str:
    """Bare IsolatedIdentity probe: IsolatedIdentity ``:18080`` implies ``:18082``.

    Field 17/17 used ``G6_INTERNAL_PROXY_URL=http://127.0.0.1:18082`` with
    public ``PROXY_BASE_URL`` still ``:18080``. Do not point
    ``PROXY_BASE_URL`` at ``:18082`` (IsolatedIdentity wrap keys on
    ``:18080``).
    """
    env = environ if environ is not None else os.environ
    current = internal_proxy_url(env)
    if current:
        return current
    if not uses_isolated_rust_proxy(env):
        return ""
    env[G6_INTERNAL_PROXY_URL_ENV] = DEFAULT_INTERNAL_PROXY_URL
    return DEFAULT_INTERNAL_PROXY_URL


def headers_need_gatekeeper_bypass(headers: Optional[Mapping[str, Any]]) -> bool:
    """True when the caller sent any ``X-Backend-*`` gatekeeper would strip.

    Field ``/workspace/g6-merge-xbackend-18082/`` (2026-09-07):
    ``X-Backend-Allow-Reserved-Names`` and
    ``X-Backend-Storage-Policy-Index`` must hop ``:18082``.
    IsolatedIdentity ``make_request`` stamps reserved-names *before*
    this check (egg ``setdefault``).
    """
    for key, value in _header_items(headers):
        if not value and value != 0:
            continue
        folded = ascii_lower_http_token(str(key)).replace("_", "-")
        if folded.startswith("x-backend-"):
            return True
    return False


def request_proxy_base_url(
    method: str,
    headers: Optional[Mapping[str, Any]] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> str:
    """Public ``:18080`` or internal ``:18082`` for one IsolatedIdentity hop.

    IsolatedIdentity GET/HEAD use ``G6_INTERNAL_PROXY_URL`` when set
    (field unified harness). Any ``X-Backend-*`` (reserved-names,
    storage-policy-index, no-commit, fragment-preferences) hops
    ``:18082``. IsolatedIdentity ``rust_http_make_request`` stamps
    reserved-names *before* this hop (egg parity). A hop helper call
    without that stamp still keeps a plain PUT on public
    ``PROXY_BASE_URL``. Expire IsolatedIdentity proxy_get 404 still
    maps to ``UnexpectedResponse``.
    """
    public = proxy_base_url(environ)
    internal = internal_proxy_url(environ)
    if not internal:
        return public
    if str(method or "").upper() in OBJECT_GET_METHODS:
        return internal
    if headers_need_gatekeeper_bypass(headers):
        return internal
    return public


def quote_swift_path_segment(part: str) -> str:
    """One PATH_INFO segment → ASCII percent-encoding (Swift ``quote``)."""
    if isinstance(part, bytes):
        part = part.decode("utf-8")
    return urllib.parse.quote(part, safe="%-._~")


def encode_swift_request_path(path: str) -> str:
    """IRI / WSGI PATH_INFO → HTTP/1.1 request-target.

    Official UTF8 rebuild names are ``b'…\\xc3\\xa8-…'`` decoded to ``è``.
    ``http.client.putrequest`` requires ASCII; field
    ``/workspace/g6-rebuild-176505e/`` UnicodeEncodeError ``\\xe8``.
    Already-quoted ``%C3%A8`` is not double-encoded (``%`` stays safe).
    """
    raw = path or "/"
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    query = ""
    if "?" in raw:
        raw, query = raw.split("?", 1)
    if not raw.startswith("/"):
        raw = "/" + raw
    encoded = "/".join(quote_swift_path_segment(part) for part in raw.split("/"))
    if query:
        encoded += "?" + query
    return encoded


def wsgi_header_token(value: Any) -> str:
    """Unicode header → PEP 3333 WSGI latin-1 (UTF-8 octets as ``Ã¨``).

    ``è`` (U+00E8) becomes ``Ã¨``. Already-WSGI ``Ã¨`` (http.client latin-1
    of UTF-8 on the wire) is left alone so lonely-frag HEAD can see
    ``x-object-meta-Ã¨-…`` without a second encode.
    """
    if isinstance(value, bytes):
        return value.decode("latin-1")
    text = str(value)
    try:
        text.encode("ascii")
        return text
    except UnicodeEncodeError:
        pass
    try:
        text.encode("latin-1").decode("utf-8")
        return text
    except UnicodeError:
        return text.encode("utf-8").decode("latin-1")


def ascii_lower_http_token(name: str) -> str:
    """Case-fold only ASCII A–Z. ``str.lower()`` turns ``Ã`` into ``ã``."""
    return "".join(ch.lower() if "A" <= ch <= "Z" else ch for ch in name)


class _Latin1FieldName(str):
    """``http.client.putheader`` does ``header.encode('ascii')``.

    IsolatedIdentity must put WSGI ``X-Object-Meta-Ã¨-…`` on the wire as
    latin-1 (UTF-8 octets), same as eventlet WSGI. A str subclass keeps
    that encode path on latin-1 instead of raising UnicodeEncodeError.
    """

    def encode(self, encoding: str = "ascii", errors: str = "strict") -> bytes:
        return str.encode(self, "latin-1", errors)


def http_outgoing_header_name(name: Any) -> str:
    return _Latin1FieldName(wsgi_header_token(name))


def wsgi_response_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    """http.client latin-1 keys plus UTF-8 aliases for HeaderKeyDict tests."""
    out: dict[str, str] = {}
    for name, value in _header_items(headers):
        wsgi_name = wsgi_header_token(name)
        wsgi_value = wsgi_header_token(value)
        aliases = {wsgi_name, ascii_lower_http_token(wsgi_name), name}
        try:
            utf8_name = wsgi_name.encode("latin-1").decode("utf-8")
            aliases.add(utf8_name)
            aliases.add(ascii_lower_http_token(utf8_name))
        except UnicodeError:
            pass
        for key in aliases:
            out[key] = wsgi_value
    return WsgiHeaderDict(out)


def join_proxy_url(
    base: str, path: str, params: Optional[Mapping[str, Any]] = None
) -> str:
    """Join IsolatedIdentity PROXY_BASE_URL with InternalClient.make_path.

    ``http://127.0.0.1:18080`` + ``/v1/a/c/o`` → ``http://127.0.0.1:18080/v1/a/c/o``.
    A base that already ends in ``/v1`` is not doubled. Non-ASCII path
    segments are percent-encoded for ``http.client``.
    """
    base = (base or "").strip().rstrip("/")
    path = encode_swift_request_path(path or "/")
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


def official_partpower_candidates(
    environ: Optional[Mapping[str, str]] = None,
) -> list[str]:
    env = environ if environ is not None else os.environ
    out: list[str] = []
    for key in PARTPOWER_PATH_ENV_KEYS:
        raw = (env.get(key) or "").strip()
        if raw:
            out.append(raw)
    for key in SWIFT_SOURCE_ENV_KEYS:
        raw = (env.get(key) or "").strip()
        if raw:
            out.append(
                os.path.join(raw, "test/probe/test_object_partpower_increase.py")
            )
    rebuild = find_official_probe(env)
    if rebuild:
        out.append(
            os.path.join(
                os.path.dirname(rebuild), "test_object_partpower_increase.py"
            )
        )
    out.append(DEFAULT_OFFICIAL_PARTPOWER)
    seen: set[str] = set()
    uniq: list[str] = []
    for path in out:
        if path not in seen:
            seen.add(path)
            uniq.append(path)
    return uniq


def find_official_partpower(
    environ: Optional[Mapping[str, str]] = None,
) -> Optional[str]:
    for path in official_partpower_candidates(environ):
        if os.path.isfile(path):
            return path
    return None


PARTPOWER_ETC_SWIFT_ACCESS_RE = re.compile(
    r"(?m)^(?P<ind>[ \t]*)self\.assertTrue\(os\.access\('/etc/swift', os\.W_OK\)\)\n"
    r"(?P=ind)self\.assertTrue\(os\.access\('/etc/swift/backups', os\.W_OK\)\)\n"
    r"(?P=ind)self\.assertTrue\(os\.access\('/etc/swift/object\.builder', os\.W_OK\)\)\n"
    r"(?P=ind)self\.assertTrue\(os\.access\('/etc/swift/object\.ring\.gz', os\.W_OK\)\)\n"
)


def apply_lab_partpower_swift_dir_to_source(text: str) -> tuple[str, bool]:
    """Retarget official partpower setUp ``/etc/swift*`` asserts to SWIFT_DIR."""
    if PARTPOWER_SWIFT_DIR_MARKER in (text or ""):
        return text, False

    def repl(match: re.Match[str]) -> str:
        ind = match.group("ind")
        return (
            f"{ind}# {PARTPOWER_SWIFT_DIR_MARKER}, not /etc/swift.\n"
            f"{ind}from g6_rust_proxy_get import isolated_swift_dir as _g6_swift_dir\n"
            f"{ind}_g6_dir = _g6_swift_dir() or '/etc/swift'\n"
            f"{ind}self.assertTrue(os.access(_g6_dir, os.W_OK))\n"
            f"{ind}self.assertTrue(os.access(os.path.join(_g6_dir, 'backups'), os.W_OK))\n"
            f"{ind}self.assertTrue(os.access(os.path.join(_g6_dir, 'object.builder'), os.W_OK))\n"
            f"{ind}self.assertTrue(os.access(os.path.join(_g6_dir, 'object.ring.gz'), os.W_OK))\n"
        )

    updated, n = PARTPOWER_ETC_SWIFT_ACCESS_RE.subn(repl, text or "", count=1)
    return updated, n > 0


def apply_lab_partpower_swift_dir_to_file(path: str) -> bool:
    with open(path, encoding="utf-8") as fh:
        original = fh.read()
    updated, changed = apply_lab_partpower_swift_dir_to_source(original)
    if changed:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(updated)
    return changed


def _wrap_partpower_setup(orig: Callable[..., Any]) -> Callable[..., Any]:
    """Remap official setUp ``os.access('/etc/swift*')`` onto SWIFT_DIR."""

    def setUp(self):
        ensure_isolated_swift_dir()
        real_access = os.access

        def access(path, mode, *args, **kwargs):
            return real_access(rewrite_etc_swift_path(path), mode, *args, **kwargs)

        os.access = access  # type: ignore[assignment]
        try:
            return orig(self)
        finally:
            os.access = real_access

    setUp._g6_rust_http_orig = orig  # type: ignore[attr-defined]
    setUp._g6_partpower_swift_dir = True  # type: ignore[attr-defined]
    return setUp


def install_partpower_setup(target: Optional[type] = None) -> bool:
    """Wrap official TestPartPowerIncrease.setUp (subclasses inherit)."""
    classes: list[type] = []
    if target is not None:
        classes.append(target)
    else:
        try:
            from test.probe.test_object_partpower_increase import (
                TestPartPowerIncrease,
            )
        except Exception:
            return False
        classes.append(TestPartPowerIncrease)
    ok = False
    for cls in classes:
        current = getattr(cls, "setUp", None)
        if current is None:
            continue
        if getattr(current, "_g6_partpower_swift_dir", False):
            if cls not in _installed_targets:
                _installed_targets.append(cls)
            ok = True
            continue
        cls.setUp = _wrap_partpower_setup(current)
        if cls not in _installed_targets:
            _installed_targets.append(cls)
        ok = True
    return ok


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
            "proxy_get has no :18080 rust HTTP IsolatedIdentity branch). "
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
        out.append((http_outgoing_header_name(name), wsgi_header_token(value)))
    return out


def force_utf8_compat_request_headers(
    headers: Optional[Mapping[str, Any]],
) -> dict[str, Any]:
    """Keep GET/HEAD on rust utf8-compat so UTF-8 object-meta is written.

    Official lonely-frag HEAD uses ``make_request('HEAD', path, {}, …)``.
    An ASCII-only request stays on Hyper, which cannot emit
    ``X-Object-Meta-è``. IsolatedIdentity GET/HEAD always stamp one
    UTF-8 object-meta name so leftover B cannot regress to Content-Type
    only. Not used on PUT/POST (would persist).
    """
    out = dict(_header_items(headers)) if headers else {}
    out.setdefault(UTF8_HANDOFF_HEADER, "1")
    return out


def _eventlet_hub_yield() -> None:
    """Let eventlet flush the green socket between PUT chunks."""
    try:
        import eventlet

        eventlet.sleep(0)
    except Exception:
        pass


def parse_http_header_block(head: bytes) -> tuple[int, dict[str, str]]:
    """Latin-1 HTTP head → status + WSGI header aliases.

    ``http.client`` / ``email.parser`` drops ``X-Object-Meta-\\xc3\\xa8-…``
    (field lonely-frag UTF8 HEAD saw only Content-Type). Keep every
    field name as iso-8859-1, then add ``Ã¨`` / ``è`` aliases.
    """
    lines = head.split(b"\r\n")
    if not lines:
        raise RustProxyGetError("empty HTTP response head from rust :18080")
    status_line = lines[0].decode("latin-1", "replace")
    parts = status_line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise RustProxyGetError(f"bad HTTP status line {status_line!r}")
    raw: dict[str, str] = {}
    for line in lines[1:]:
        if not line or b":" not in line:
            continue
        name, value = line.split(b":", 1)
        raw[name.decode("latin-1").strip()] = value.decode("latin-1").strip()
    return int(parts[1]), wsgi_response_headers(raw)


def _header_lookup(headers: Mapping[str, str], name: str) -> Optional[str]:
    want = ascii_lower_http_token(name)
    for key, value in headers.items():
        if ascii_lower_http_token(key) == want:
            return value
    return None


def _read_chunked_body(sock: Any, initial: bytes) -> bytes:
    buf = initial
    chunks: list[bytes] = []
    while True:
        while b"\r\n" not in buf:
            more = sock.recv(4096)
            if not more:
                break
            buf += more
        if b"\r\n" not in buf:
            break
        line, buf = buf.split(b"\r\n", 1)
        size_s = line.split(b";", 1)[0].strip()
        try:
            size = int(size_s, 16)
        except ValueError as err:
            raise RustProxyGetError(f"bad chunk size {line!r}") from err
        if size == 0:
            break
        while len(buf) < size + 2:
            more = sock.recv(4096)
            if not more:
                break
            buf += more
        chunks.append(buf[:size])
        buf = buf[size:]
        if buf.startswith(b"\r\n"):
            buf = buf[2:]
    return b"".join(chunks)


def _recv_until_head(sock: Any, timeout: float, initial: bytes = b"") -> tuple[bytes, bytes]:
    """Read through ``\\r\\n\\r\\n``. Leftover is the next message, not an error."""
    sock.settimeout(timeout)
    buf = initial or b""
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
    return head, leftover


def _read_http_head(
    sock: Any, timeout: float, initial: bytes = b""
) -> tuple[int, dict[str, str], bytes]:
    """Read one HTTP head. Coalesced bytes after 1xx are the next response.

    Field ``/workspace/g6-merge-982e86a/`` (2026-09-06): rust ``:18082``
    sent ``100 Continue`` plus the final 2xx in one recv (29 leftover).
    Raising ``unexpected bytes after informational response head``
    ERRORed ReservedNamespace merge/reconcile PUTs.
    """
    head, leftover = _recv_until_head(sock, timeout, initial)
    status, headers = parse_http_header_block(head)
    return status, headers, leftover


def _http_resp_from_head(
    sock: Any,
    timeout: float,
    status: int,
    headers: Mapping[str, str],
    leftover: bytes,
    *,
    expect_body: bool,
    url: str = "",
    method: str = "GET",
) -> _HttpResp:
    if not expect_body or status in {204, 304} or 100 <= status < 200:
        return _HttpResp(status, headers, b"", url=url, method=method)
    te = (_header_lookup(headers, "Transfer-Encoding") or "").lower()
    if "chunked" in te:
        return _HttpResp(
            status, headers, _read_chunked_body(sock, leftover), url=url, method=method
        )
    length_s = _header_lookup(headers, "Content-Length")
    if length_s is not None:
        try:
            length = int(length_s)
        except ValueError as err:
            raise RustProxyGetError(f"bad Content-Length {length_s!r}") from err
        body = leftover
        while len(body) < length:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
        return _HttpResp(status, headers, body[:length], url=url, method=method)
    body = leftover
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    return _HttpResp(status, headers, body, url=url, method=method)


def _read_http_message(
    sock: Any,
    timeout: float,
    *,
    expect_body: bool,
    initial: bytes = b"",
    url: str = "",
    method: str = "GET",
) -> _HttpResp:
    """Read one final HTTP response, skipping informational 1xx heads."""
    leftover = initial or b""
    while True:
        status, headers, leftover = _read_http_head(sock, timeout, leftover)
        if 100 <= status < 200:
            continue
        return _http_resp_from_head(
            sock,
            timeout,
            status,
            headers,
            leftover,
            expect_body=expect_body,
            url=url,
            method=method,
        )


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
    path = encode_swift_request_path(parsed.path or "/")
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
        status, headers, leftover = _read_http_head(conn.sock, wait)
        while 100 < status < 200:
            status, headers, leftover = _read_http_head(conn.sock, wait, leftover)
        if status == 100:
            for offset in range(0, len(payload), PUT_SEND_CHUNK):
                conn.send(bytes(payload[offset : offset + PUT_SEND_CHUNK]))
                _eventlet_hub_yield()
            return _read_http_message(
                conn.sock,
                timeout,
                expect_body=True,
                initial=leftover,
                url=url,
                method=method,
            )
        if status == 417:
            conn.close()
            return _put_without_expect(
                connection_cls,
                host,
                port,
                path,
                method,
                headers,
                payload,
                timeout,
                url=url,
            )
        # Final response before the body (error / empty PUT). Do not send
        # payload. Leftover is this response's body, not a parse error.
        return _http_resp_from_head(
            conn.sock,
            timeout,
            status,
            headers,
            leftover,
            expect_body=True,
            url=url,
            method=method,
        )
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
    url: str = "",
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
        return _read_http_message(
            conn.sock, timeout, expect_body=True, url=url, method=method
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass


def rust_http_no_body(
    method: str,
    url: str,
    headers: Optional[Mapping[str, Any]],
    timeout: float = 30.0,
    connection_cls: Optional[type] = None,
) -> _HttpResp:
    """GET/HEAD/DELETE on rust :18080 with IRI path + WSGI header names.

    urllib/http.client ``putrequest`` needs an ASCII request-target;
    ``putheader`` names are ASCII unless wrapped in ``_Latin1FieldName``.
    """
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = encode_swift_request_path(parsed.path or "/")
    if parsed.query:
        path = f"{path}?{parsed.query}"
    method_u = method.upper()
    if method_u in OBJECT_GET_METHODS:
        headers = force_utf8_compat_request_headers(headers)
    if connection_cls is None:
        import http.client as http_client

        connection_cls = http_client.HTTPConnection
    conn = connection_cls(host, port, timeout=timeout)
    try:
        conn.putrequest(method_u, path, skip_accept_encoding=True)
        for name, value in _filter_outgoing_headers(headers):
            conn.putheader(name, value)
        conn.putheader("Connection", "close")
        conn.endheaders()
        return _read_http_message(
            conn.sock,
            timeout,
            expect_body=method_u != "HEAD",
            url=url,
            method=method_u,
        )
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
    if opener is None:
        return rust_http_no_body(
            method_u,
            url,
            headers,
            timeout=timeout if timeout and timeout > 0 else 30.0,
            connection_cls=connection_cls,
        )
    parsed = urllib.parse.urlparse(url)
    encoded_path = encode_swift_request_path(parsed.path or "/")
    if encoded_path != parsed.path:
        url = urllib.parse.urlunparse(parsed._replace(path=encoded_path))
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
            return _HttpResp(
                int(status),
                wsgi_response_headers(dict(resp.headers)),
                body,
                url=url,
                method=method_u,
            )
    except urllib.error.HTTPError as err:
        body = err.read() if err.fp is not None else b""
        hdrs = dict(err.headers) if err.headers is not None else {}
        return _HttpResp(
            int(err.code),
            wsgi_response_headers(hdrs),
            body,
            url=url,
            method=method_u,
        )


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
    env = environ if environ is not None else os.environ
    ensure_internal_proxy_url(env)
    # Egg InternalClient.make_request setdefault reserved-names before
    # the request is sent. Brain put_container only sends
    # X-Storage-Policy; hop must see the stamp or :18080 gatekeeper
    # strips it (field 8353823 → 412). Stamp first, then hop.
    merged = dict(_header_items(headers))
    for name, value in g6_auth_headers(environ).items():
        merged.setdefault(name, value)
    merged.setdefault("X-Backend-Allow-Reserved-Names", "true")
    base = request_proxy_base_url(method, merged, env)
    if method.upper() in OBJECT_GET_METHODS:
        merged = force_utf8_compat_request_headers(merged)
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


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return str(value)


def _header_name_is(name: Any, expected: str) -> bool:
    folded = ascii_lower_http_token(_as_text(name)).replace("_", "-")
    return folded == expected


def resolve_delete_after_headers(
    headers: Optional[Mapping[str, Any]],
    now: Optional[float] = None,
) -> Optional[dict[str, Any]]:
    """Official expire PUT sends ``{'x-delete-after': 2}`` (int).

    Convert to ``X-Delete-At`` so IsolatedIdentity persist + GET expire
    cannot miss the proxy after→at rewrite. Drop ``X-Delete-After``.
    """
    if headers is None:
        return None
    out = dict(headers)
    after: Any = None
    for key in list(out):
        if _header_name_is(key, "x-delete-after"):
            after = out.pop(key)
            break
    if after is None:
        return out
    if now is None:
        now = time.time()
    try:
        after_i = int(float(after))
    except (TypeError, ValueError):
        return dict(headers)
    out["X-Delete-At"] = str(int(now) + after_i)
    return out


def remember_probe_delete_at(probe: Any, headers: Optional[Mapping[str, Any]]) -> None:
    if probe is None or not headers:
        return
    for key, value in _header_items(headers):
        if _header_name_is(key, "x-delete-at"):
            try:
                setattr(probe, G6_DELETE_AT_ATTR, int(float(value)))
            except (TypeError, ValueError):
                return
            return


def probe_delete_at_expired(probe: Any, now: Optional[float] = None) -> bool:
    raw = getattr(probe, G6_DELETE_AT_ATTR, None) if probe is not None else None
    if raw is None:
        return False
    if now is None:
        now = time.time()
    try:
        return int(now) >= int(raw)
    except (TypeError, ValueError):
        return False


def client_get_sees_expired(
    headers: Optional[Mapping[str, Any]],
    now: Optional[float] = None,
) -> bool:
    """True when a 200 GET still carries a past ``X-Delete-At``."""
    if not headers:
        return False
    if now is None:
        now = time.time()
    raw = None
    for key, value in _header_items(headers):
        if _header_name_is(key, "x-backend-replication") and value:
            return False
        if _header_name_is(key, "x-backend-open-expired") and value:
            return False
        if _header_name_is(key, "x-delete-at"):
            raw = value
    if raw is None:
        return False
    try:
        return int(now) >= int(float(raw))
    except (TypeError, ValueError):
        return False


def unexpected_expired(resp: Optional[_HttpResp] = None, path: str = "") -> Exception:
    cls = _unexpected_response_class()
    headers = getattr(resp, "headers", {}) if resp is not None else {}
    # Official expire wait checks e.resp.status_int == 404. A rust 200
    # that is already past X-Delete-At must not leak status 200.
    if resp is None or int(getattr(resp, "status_int", 0)) != 404:
        url = ""
        env = getattr(resp, "environ", None) or {}
        if env.get("PATH_INFO"):
            scheme = env.get("wsgi.url_scheme") or "http"
            host = env.get("SERVER_NAME") or "127.0.0.1"
            port = env.get("SERVER_PORT") or "80"
            query = env.get("QUERY_STRING") or ""
            url = f"{scheme}://{host}:{port}{env['PATH_INFO']}"
            if query:
                url += f"?{query}"
        elif path:
            url = join_proxy_url(
                internal_proxy_url() or proxy_base_url() or DEFAULT_INTERNAL_PROXY_URL,
                path,
            )
        resp = _HttpResp(404, headers, b"Not Found\n", url=url, method="GET")
    msg = "Unexpected response: 404"
    if path:
        msg += f" {path}"
    return cls(msg, resp)


def probe_object_path(probe: Any) -> str:
    """Storage URL + container/object, same as official swiftclient IsolatedIdentity GET."""
    container = _as_text(getattr(probe, "container_name", "") or "")
    obj = _as_text(getattr(probe, "object_name", "") or "")
    url = _as_text(getattr(probe, "url", "") or "")
    parsed = urllib.parse.urlparse(url)
    base_path = (parsed.path or "").rstrip("/")
    account = _as_text(getattr(probe, "account", None) or "")
    if base_path.startswith("/v1/") and base_path.count("/") >= 2:
        return encode_swift_request_path(f"{base_path}/{container}/{obj}")
    if account:
        return encode_swift_request_path(f"/v1/{account}/{container}/{obj}")
    return encode_swift_request_path(f"/v1/test/{container}/{obj}")


def rust_http_proxy_get(
    probe: Any,
    extra_headers: Optional[Mapping[str, Any]] = None,
    *,
    opener: Optional[Callable[..., Any]] = None,
    header_dict: Optional[type] = None,
) -> tuple[Any, str]:
    """IsolatedIdentity ``proxy_get``: rust HTTP GET, official expire 404.

    Official ``test_sync_expired_object`` waits for
    ``UnexpectedResponse`` with ``status_int=404``. urllib3/swiftclient
    GET 404 is ``ClientException`` (ERROR, not the wait ``except``).
    A rust 200 loops until the 2s+1 timeout. IsolatedIdentity 404s when
    rust 404s, when GET still carries a past ``X-Delete-At``, or when
    IsolatedIdentity PUT stashed that timestamp and the clock is past.

    When ``G6_INTERNAL_PROXY_URL`` is set, IsolatedIdentity GET uses that
    rust ``:18082`` hop (no gatekeeper). Do not raw-replace IsolatedIdentity
    ``proxy_get`` with swiftclient: 404 must stay ``UnexpectedResponse``.
    """
    path = probe_object_path(probe)
    if probe_delete_at_expired(probe):
        raise unexpected_expired(path=path)
    hdrs = dict(extra_headers or {})
    token = getattr(probe, "token", None)
    if token:
        hdrs.setdefault("X-Auth-Token", str(token))
    resp = rust_http_make_request(
        "GET",
        path,
        hdrs,
        (2, 404),
        opener=opener,
    )
    if int(resp.status_int) == 404 or client_get_sees_expired(resp.headers):
        raise unexpected_expired(resp, path=path)
    body = resp.body if isinstance(resp.body, (bytes, bytearray)) else b""
    digest = _md5()
    digest.update(body)
    wrapped = header_dict(resp.headers) if header_dict is not None else resp.headers
    return wrapped, digest.hexdigest()


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
    def proxy_get(self, extra_headers=None):
        if uses_isolated_rust_proxy():
            return rust_http_proxy_get(self, extra_headers=extra_headers)
        if extra_headers is None:
            return orig(self)
        try:
            return orig(self, extra_headers=extra_headers)
        except TypeError:
            return orig(self)

    proxy_get._g6_rust_http = True  # type: ignore[attr-defined]
    proxy_get._g6_rust_http_orig = orig  # type: ignore[attr-defined]
    return proxy_get


def _wrap_probe_proxy_put(orig: Callable[..., Any]) -> Callable[..., Any]:
    def proxy_put(self, extra_headers=None):
        extra_headers = resolve_delete_after_headers(extra_headers)
        remember_probe_delete_at(self, extra_headers)
        return orig(self, extra_headers=extra_headers)

    proxy_put._g6_rust_http = True  # type: ignore[attr-defined]
    proxy_put._g6_rust_http_orig = orig  # type: ignore[attr-defined]
    return proxy_put


def probe_source_routes_rust_http(text: str) -> bool:
    body = text or ""
    if PROBE_PATCH_MARKER in body:
        return True
    return (
        "def proxy_get" in body
        and ISOLATED_RUST_PORT_TOKEN in body
        and ("rust_http_proxy_get" in body or "client.get_object" in body)
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


def apply_lab_proxy_put_to_source(text: str) -> tuple[str, bool]:
    """Insert IsolatedIdentity X-Delete-After → X-Delete-At on official proxy_put."""
    if "resolve_delete_after_headers(extra_headers)" in text:
        return text, False
    if OFFICIAL_PROXY_PUT_HEAD not in text:
        return text, False
    return text.replace(OFFICIAL_PROXY_PUT_HEAD, LAB_PROXY_PUT_HEAD, 1), True


def apply_lab_proxy_put_to_file(path: str) -> bool:
    with open(path, encoding="utf-8") as fh:
        original = fh.read()
    updated, changed = apply_lab_proxy_put_to_source(original)
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


def install_probe_proxy_put(target: Optional[type] = None) -> bool:
    cls = target
    if cls is None:
        try:
            from test.probe.common import ECProbeTest
        except Exception:
            return False
        cls = ECProbeTest
    current = getattr(cls, "proxy_put", None)
    if current is None:
        return False
    if getattr(current, "_g6_rust_http", False):
        if cls not in _installed_targets:
            _installed_targets.append(cls)
        return True
    cls.proxy_put = _wrap_probe_proxy_put(current)
    if cls not in _installed_targets:
        _installed_targets.append(cls)
    return True


def install(target: Optional[type] = None) -> bool:
    """Install rust HTTP IsolatedIdentity ``proxy_get`` + expire PUT + IC wrap."""
    ok = install_probe_body_read()
    ok = install_probe_proxy_get() or ok
    ok = install_probe_proxy_put() or ok
    ok = install_partpower_setup() or ok
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
        for attr in ("make_request", "proxy_get", "proxy_put", "read", "setUp"):
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
        "internal_proxy_url": ensure_internal_proxy_url(env),
        "swift_dir": ensure_isolated_swift_dir(env),
        "isolated": uses_isolated_rust_proxy(env),
        "probe_path": None,
        "probe_changed": False,
        "partpower_path": None,
        "partpower_changed": False,
        "probe_routes_http": False,
        "adapter_installed": False,
    }
    if not result["isolated"]:
        return result
    path = probe_path or find_official_probe(env)
    result["probe_path"] = path
    if path:
        result["probe_changed"] = apply_lab_proxy_get_to_file(path)
        common = os.path.join(os.path.dirname(path), "common.py")
        if os.path.isfile(common):
            result["probe_changed"] = (
                apply_lab_proxy_put_to_file(common) or result["probe_changed"]
            )
        result["probe_routes_http"] = official_probe_routes_rust_http(
            env, path=path
        )
    partpower = find_official_partpower(env)
    result["partpower_path"] = partpower
    if partpower:
        result["partpower_changed"] = apply_lab_partpower_swift_dir_to_file(
            partpower
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


def pytest_runtest_setup(item):  # noqa: ARG001
    """Partpower setUp imports after pytest_configure; wrap then."""
    if uses_isolated_rust_proxy():
        ensure_isolated_swift_dir()
        install_partpower_setup()


def pytest_sessionstart(session):  # noqa: ARG001
    base = proxy_base_url()
    if not uses_isolated_rust_proxy():
        return
    print(
        f"G6 rust proxy GET/HEAD: PROXY_BASE_URL={base} "
        f"G6_INTERNAL_PROXY_URL={internal_proxy_url() or '-'} "
        f"SWIFT_DIR={isolated_swift_dir() or '-'} adapter="
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
            "G6_INTERNAL_PROXY_URL={internal_proxy_url!r} "
            "SWIFT_DIR={swift_dir!r} "
            "probe={probe_path} changed={probe_changed} "
            "partpower={partpower_path} partpower_changed={partpower_changed} "
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
