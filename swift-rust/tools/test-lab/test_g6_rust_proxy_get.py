#!/usr/bin/env python3
"""Fail-closed tests for the G6 rust HTTP proxy_get adapter. No Swift, no SSH."""
from __future__ import annotations

import io
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
from email.message import EmailMessage
from unittest import mock

import g6_rust_proxy_get as adapter


class OfficialProbeBody:
    """Official test.probe.common.Body.read(amount) — size is required."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def read(self, amount):
        chunk = self._data[self._pos : self._pos + amount]
        self._pos += len(chunk)
        return chunk


EGG_CONF = """
[pipeline:main]
pipeline = catch_errors proxy-logging cache symlink proxy-server

[app:proxy-server]
use = egg:swift#proxy
account_autocreate = true
"""


class DummyInternalClient:
    def __init__(self):
        self.wsgi_calls = []

    def make_request(
        self, method, path, headers, acceptable_statuses, body_file=None, params=None
    ):
        self.wsgi_calls.append(
            (method, path, headers, acceptable_statuses, params, body_file)
        )
        raise AssertionError(f"WSGI egg:swift#proxy used for {method} {path}")


class JoinAndGuard(unittest.TestCase):
    def test_join_does_not_double_v1(self):
        self.assertEqual(
            adapter.join_proxy_url("http://127.0.0.1:18080", "/v1/a/c/o"),
            "http://127.0.0.1:18080/v1/a/c/o",
        )
        self.assertEqual(
            adapter.join_proxy_url("http://127.0.0.1:18080/v1", "/v1/a/c/o"),
            "http://127.0.0.1:18080/v1/a/c/o",
        )
        self.assertEqual(
            adapter.join_proxy_url(
                "http://127.0.0.1:18080", "/v1/a/c/o", {"format": "json"}
            ),
            "http://127.0.0.1:18080/v1/a/c/o?format=json",
        )

    def test_egg_proxy_conf_detected(self):
        self.assertTrue(adapter.conf_uses_egg_swift_proxy(EGG_CONF))
        self.assertFalse(
            adapter.conf_uses_egg_swift_proxy("[app:proxy-server]\nuse = egg:other#proxy\n")
        )

    def test_isolated_rust_port_is_18080_not_any_proxy_base(self):
        self.assertTrue(
            adapter.uses_isolated_rust_proxy(
                {"PROXY_BASE_URL": "http://127.0.0.1:18080"}
            )
        )
        self.assertFalse(
            adapter.uses_isolated_rust_proxy(
                {"PROXY_BASE_URL": "http://127.0.0.1:8080"}
            )
        )
        self.assertFalse(adapter.uses_isolated_rust_proxy({}))

    def test_guard_silent_without_proxy_base(self):
        adapter.rust_object_get_guard(
            environ={},
            conf_text=EGG_CONF,
            adapter_installed=False,
        )
        adapter.rust_object_get_guard(
            environ={"PROXY_BASE_URL": "http://127.0.0.1:8080"},
            conf_text=EGG_CONF,
            adapter_installed=False,
        )

    def test_guard_fails_when_base_set_and_egg_conf_without_adapter(self):
        with self.assertRaises(adapter.RustProxyGetError) as ctx:
            adapter.rust_object_get_guard(
                environ={"PROXY_BASE_URL": "http://127.0.0.1:18080"},
                conf_text=EGG_CONF,
                adapter_installed=False,
            )
        self.assertIn("egg:swift#proxy", str(ctx.exception))
        self.assertIn("18080", str(ctx.exception))

    def test_guard_ok_when_adapter_installed(self):
        adapter.rust_object_get_guard(
            environ={"PROXY_BASE_URL": "http://127.0.0.1:18080"},
            conf_text=EGG_CONF,
            adapter_installed=True,
        )

    def test_guard_fails_when_base_set_and_conf_missing(self):
        with self.assertRaises(adapter.RustProxyGetError):
            adapter.rust_object_get_guard(
                environ={"PROXY_BASE_URL": "http://127.0.0.1:18080"},
                conf_text="",
                adapter_installed=False,
            )

    def test_auth_headers_from_st_env(self):
        hdrs = adapter.g6_auth_headers(
            {"ST_USER": "test:tester", "ST_KEY": "testing", "ST_AUTH_TOKEN": "AUTH_tk"}
        )
        self.assertEqual(hdrs["X-Auth-User"], "test:tester")
        self.assertEqual(hdrs["X-Auth-Key"], "testing")
        self.assertEqual(hdrs["X-Auth-Token"], "AUTH_tk")


class Utf8PathAndHeaders(unittest.TestCase):
    """Field /workspace/g6-rebuild-176505e/: IRI path + WSGI meta keys."""

    def tearDown(self):
        adapter.uninstall()
        os.environ.pop("PROXY_BASE_URL", None)
        os.environ.pop("G6_INTERNAL_PROXY_URL", None)

    def test_encode_swift_request_path_quotes_e_grave(self):
        self.assertEqual(
            adapter.encode_swift_request_path("/v1/a/cè/o"),
            "/v1/a/c%C3%A8/o",
        )
        official = b"%s\xc3\xa8-%s" % (b"container", b"uuid")
        path = "/v1/AUTH_ec/%s/%s" % (
            official.decode("utf-8"),
            (b"obj\xc3\xa8-uuid").decode("utf-8"),
        )
        self.assertEqual(
            adapter.encode_swift_request_path(path),
            "/v1/AUTH_ec/container%C3%A8-uuid/obj%C3%A8-uuid",
        )

    def test_encode_swift_request_path_does_not_double_quote(self):
        self.assertEqual(
            adapter.encode_swift_request_path("/v1/a/c%C3%A8/o"),
            "/v1/a/c%C3%A8/o",
        )

    def test_join_proxy_url_percent_encodes_utf8_path(self):
        self.assertEqual(
            adapter.join_proxy_url("http://127.0.0.1:18080", "/v1/a/cè/oè"),
            "http://127.0.0.1:18080/v1/a/c%C3%A8/o%C3%A8",
        )
        self.assertEqual(
            adapter.join_proxy_url("http://127.0.0.1:18080", "/v1/a/c%C3%A8/o"),
            "http://127.0.0.1:18080/v1/a/c%C3%A8/o",
        )

    def test_wsgi_header_token_e_grave_is_mojibake_not_double_encoded(self):
        self.assertEqual(
            adapter.wsgi_header_token("X-Object-Meta-è-color"),
            "X-Object-Meta-Ã¨-color",
        )
        already = "X-Object-Meta-Ã¨-color"
        self.assertEqual(adapter.wsgi_header_token(already), already)
        self.assertEqual(adapter.wsgi_header_token("Content-Type"), "Content-Type")
        self.assertEqual(
            adapter.ascii_lower_http_token("X-Object-Meta-Ã¨-color"),
            "x-object-meta-Ã¨-color",
        )
        self.assertNotEqual(
            "X-Object-Meta-Ã¨-color".lower(),
            "x-object-meta-Ã¨-color",
        )

    def test_outgoing_utf8_meta_is_wsgi_for_http_client(self):
        filtered = adapter._filter_outgoing_headers(
            {"X-Object-Meta-è-color": "red", "Transfer-Encoding": "chunked"}
        )
        self.assertEqual(filtered, [("X-Object-Meta-Ã¨-color", "red")])
        name, value = filtered[0]
        name.encode("latin-1")
        value.encode("latin-1")

    def test_parse_http_header_block_keeps_utf8_meta_name(self):
        """email.parser drops X-Object-Meta-\\xc3\\xa8-…; we must not."""
        status, hdrs = adapter.parse_http_header_block(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"X-Object-Meta-\xc3\xa8-color: blue\r\n"
        )
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("Content-Type"), "text/plain")
        self.assertEqual(hdrs.get("x-object-meta-Ã¨-color"), "blue")

    def test_response_headers_expose_lonely_frag_wsgi_meta_key(self):
        from_wire_utf8 = adapter.wsgi_response_headers(
            {"X-Object-Meta-Ã¨-color": "blue", "Content-Type": "text/plain"}
        )
        self.assertEqual(from_wire_utf8.get("X-Object-Meta-Ã¨-color"), "blue")
        self.assertEqual(from_wire_utf8.get("x-object-meta-Ã¨-color"), "blue")
        self.assertEqual(from_wire_utf8.get("X-Object-Meta-è-color"), "blue")
        from_latin1_e = adapter.wsgi_response_headers({"X-Object-Meta-è-color": "blue"})
        self.assertEqual(from_latin1_e.get("x-object-meta-Ã¨-color"), "blue")
        self.assertEqual(from_latin1_e.get("X-Object-Meta-è-color"), "blue")

    def test_lonely_head_headers_assertin_wsgi_key_without_unicode_lower(self):
        """Official lonely HEAD: assertIn(str_to_wsgi(key), resp.headers)."""
        status, hdrs = adapter.parse_http_header_block(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"X-Object-Meta-\xc3\xa8-uuid: meta-bar-\xc3\xa8\r\n"
        )
        self.assertEqual(status, 200)
        # str_to_wsgi(è) is UTF-8 C3 A8 as latin-1: Ã + U+00A8 (not è).
        wsgi_key = "x-object-meta-\u00c3\u00a8-uuid"
        self.assertIn(wsgi_key, hdrs)
        self.assertEqual(hdrs[wsgi_key], "meta-bar-\u00c3\u00a8")
        resp = adapter._HttpResp(200, hdrs, b"")
        self.assertIn(wsgi_key, resp.headers)
        self.assertEqual(resp.headers[wsgi_key], "meta-bar-\u00c3\u00a8")
        titled = adapter.wsgi_response_headers(
            {"X-Object-Meta-\u00e8-Uuid": "meta-bar-\u00e8"}
        )
        self.assertIn(wsgi_key, titled)
        self.assertNotEqual(wsgi_key.lower(), "x-object-meta-\u00c3\u00a8-uuid")

    def test_head_forces_utf8_compat_handoff_header(self):
        filtered = adapter._filter_outgoing_headers(
            adapter.force_utf8_compat_request_headers({})
        )
        names = [name for name, _ in filtered]
        self.assertTrue(
            any("g6-utf8-compat" in name for name in names),
            names,
        )
        name, value = next((n, v) for n, v in filtered if "g6-utf8-compat" in n)
        name.encode("latin-1")
        self.assertEqual(value, "1")

    def test_http_get_opener_sees_ascii_percent_encoded_url(self):
        class FakeResp:
            status = 200
            headers = {"X-Object-Meta-Ã¨-color": "blue"}

            def read(self):
                return b""

            def getcode(self):
                return 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def opener(req, timeout=None):
            req.full_url.encode("ascii")
            self.assertEqual(
                req.full_url,
                "http://127.0.0.1:18082/v1/AUTH_ec/c%C3%A8/o%C3%A8",
            )
            return FakeResp()

        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        resp = adapter.rust_http_make_request(
            "GET",
            "/v1/AUTH_ec/cè/oè",
            {"X-Object-Meta-è-color": "blue"},
            (2,),
            opener=opener,
        )
        self.assertEqual(resp.status_int, 200)
        self.assertEqual(resp.headers.get("x-object-meta-Ã¨-color"), "blue")

    def test_http_client_putrequest_accepts_utf8_object_path(self):
        """Field UnicodeEncodeError was http.client._encode_request ascii."""
        received = {}

        def serve():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
            received["port"] = sock.getsockname()[1]
            received["ready"].set()
            conn, _addr = sock.accept()
            sock.close()
            try:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                head, _rest = buf.split(b"\r\n\r\n", 1)
                received["request_line"] = head.split(b"\r\n", 1)[0]
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
                    b"X-Object-Meta-\xc3\xa8-color: blue\r\n"
                    b"Connection: close\r\n\r\n"
                )
            finally:
                conn.close()

        received["ready"] = threading.Event()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.assertTrue(received["ready"].wait(2), "test server did not bind")
        resp = adapter.rust_http_exchange(
            "GET",
            f"http://127.0.0.1:{received['port']}/v1/a/cè/oè-uuid",
            {},
            timeout=5.0,
        )
        thread.join(2)
        self.assertEqual(resp.status_int, 200)
        line = received["request_line"]
        line.decode("ascii")
        self.assertIn(b"/v1/a/c%C3%A8/o%C3%A8-uuid", line)
        self.assertEqual(resp.headers.get("x-object-meta-Ã¨-color"), "blue")

    def test_http_put_percent_encodes_path_and_wsgi_meta(self):
        received = {}

        def serve():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
            received["port"] = sock.getsockname()[1]
            received["ready"].set()
            conn, _addr = sock.accept()
            sock.close()
            try:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                head, rest = buf.split(b"\r\n\r\n", 1)
                lines = head.split(b"\r\n")
                headers = {}
                for line in lines[1:]:
                    if b":" in line:
                        name, value = line.split(b":", 1)
                        headers[
                            adapter.ascii_lower_http_token(name.decode("latin1"))
                        ] = value.strip().decode("latin1")
                received["request_line"] = lines[0]
                received["raw_head"] = head
                received["headers"] = headers
                if headers.get("expect", "").lower() == "100-continue":
                    conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                length = int(headers.get("content-length", "0"))
                while len(rest) < length:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    rest += chunk
                received["body"] = rest[:length]
                conn.sendall(
                    b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
            finally:
                conn.close()

        received["ready"] = threading.Event()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.assertTrue(received["ready"].wait(2), "test server did not bind")
        resp = adapter.rust_http_exchange(
            "PUT",
            f"http://127.0.0.1:{received['port']}/v1/a/cè/oè",
            {"X-Object-Meta-è-color": "red"},
            timeout=5.0,
            data=b"utf8-body",
        )
        thread.join(2)
        self.assertEqual(resp.status_int, 201)
        received["request_line"].decode("ascii")
        self.assertIn(b"/v1/a/c%C3%A8/o%C3%A8", received["request_line"])
        self.assertEqual(received["body"], b"utf8-body")
        self.assertIn(b"X-Object-Meta-\xc3\xa8-color: red", received["raw_head"])
        self.assertEqual(received["headers"].get("x-object-meta-\u00c3\u00a8-color"), "red")
        self.assertNotIn("x-object-meta-\u00e8-color", received["headers"])


class HttpAndPatch(unittest.TestCase):
    def tearDown(self):
        adapter.uninstall()
        os.environ.pop("PROXY_BASE_URL", None)
        os.environ.pop("G6_INTERNAL_PROXY_URL", None)

    def test_http_put_sends_body_and_no_commit_header(self):
        class FakeResp:
            status = 201
            headers = {}

            def read(self):
                return b""

            def getcode(self):
                return 201

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def opener(req, timeout=None):
            self.assertEqual(req.get_method(), "PUT")
            self.assertEqual(req.data, b"v2-probe-body")
            self.assertEqual(req.get_header("X-backend-no-commit"), "True")
            return FakeResp()

        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        resp = adapter.rust_http_make_request(
            "PUT",
            "/v1/AUTH_ec/c/o",
            {"x-backend-no-commit": "True"},
            (2,),
            opener=opener,
            body=b"v2-probe-body",
        )
        self.assertEqual(resp.status_int, 201)

    def test_put_sends_content_length_in_chunks_after_100_continue(self):
        """Official-size IsolatedIdentity PUT: Expect 100, then CL chunks."""
        received = {}

        def serve():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
            received["port"] = sock.getsockname()[1]
            received["ready"].set()
            conn, _addr = sock.accept()
            sock.close()
            try:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                head, rest = buf.split(b"\r\n\r\n", 1)
                lines = head.split(b"\r\n")
                headers = {}
                for line in lines[1:]:
                    if b":" in line:
                        name, value = line.split(b":", 1)
                        headers[name.decode("latin1").lower()] = value.strip().decode(
                            "latin1"
                        )
                received["request_line"] = lines[0].decode("latin1")
                received["headers"] = headers
                if "transfer-encoding" in headers:
                    conn.close()
                    received["closed_on_te"] = True
                    return
                if headers.get("expect", "").lower() == "100-continue":
                    conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                length = int(headers.get("content-length", "0"))
                while len(rest) < length:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    rest += chunk
                received["body"] = rest[:length]
                conn.sendall(
                    b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
            finally:
                conn.close()

        received["ready"] = threading.Event()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.assertTrue(received["ready"].wait(2), "test server did not bind")
        payload = os.urandom(int(3.5 * 2**20))
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        resp = adapter.rust_http_exchange(
            "PUT",
            f"http://127.0.0.1:{received['port']}/v1/AUTH_ec/c/o",
            {
                "Transfer-Encoding": "chunked",
                "Expect": "100-continue",
                "x-backend-no-commit": "True",
            },
            timeout=30.0,
            data=payload,
        )
        thread.join(2)
        self.assertEqual(resp.status_int, 201)
        self.assertNotIn("closed_on_te", received)
        self.assertEqual(received["body"], payload)
        headers = received["headers"]
        self.assertEqual(headers.get("content-length"), str(len(payload)))
        self.assertNotIn("transfer-encoding", headers)
        self.assertEqual(headers.get("expect"), "100-continue")
        self.assertEqual(headers.get("x-backend-no-commit"), "True")
        self.assertEqual(headers.get("connection"), "close")

    def test_coalesced_100_continue_plus_final_is_not_leftover_error(self):
        """Field g6-merge-982e86a: 29 leftover after 100 Continue is the 2xx."""
        received = {}
        final = (
            b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n"
            b"Connection: close\r\n\r\n"
        )

        def serve():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
            received["port"] = sock.getsockname()[1]
            received["ready"].set()
            conn, _addr = sock.accept()
            sock.close()
            try:
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                _head, rest = buf.split(b"\r\n\r\n", 1)
                # Coalesce 100 + start of 201 (field: 29 leftover bytes).
                prefix = final[:29]
                received["coalesced_leftover"] = len(prefix)
                conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n" + prefix)
                length = 0
                for line in _head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1].strip())
                while len(rest) < length:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    rest += chunk
                received["body"] = rest[:length]
                conn.sendall(final[29:])
            finally:
                conn.close()

        received["ready"] = threading.Event()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.assertTrue(received["ready"].wait(2), "test server did not bind")
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        resp = adapter.rust_http_exchange(
            "PUT",
            f"http://127.0.0.1:{received['port']}/v1/AUTH_ec/c/o",
            {},
            timeout=5.0,
            data=b"merge-put",
        )
        thread.join(2)
        self.assertEqual(received["coalesced_leftover"], 29)
        self.assertEqual(resp.status_int, 201)
        self.assertEqual(received["body"], b"merge-put")

    def test_read_http_head_returns_coalesced_leftover(self):
        pair = socket.socketpair()
        try:
            pair[0].sendall(
                b"HTTP/1.1 100 Continue\r\n\r\n" + b"HTTP/1.1 201 Created\r\n"
            )
            pair[0].close()
            status, _headers, leftover = adapter._read_http_head(pair[1], 2.0)
            self.assertEqual(status, 100)
            self.assertEqual(leftover, b"HTTP/1.1 201 Created\r\n")
        finally:
            pair[1].close()

    def test_read_request_body_from_fileobj(self):
        self.assertEqual(adapter.read_request_body(None), b"")
        self.assertEqual(adapter.read_request_body(b"abc"), b"abc")
        self.assertEqual(adapter.read_request_body(io.BytesIO(b"probe")), b"probe")

    def test_read_request_body_official_probabody_requires_amount(self):
        body = OfficialProbeBody(b"v2-non-durable")
        with self.assertRaises(TypeError):
            body.read()
        self.assertEqual(adapter.read_request_body(body), b"v2-non-durable")

    def test_probe_body_read_accepts_int_size_and_optional(self):
        """Field 2d774ae: ProbeBody.read(amount) TypeError; file-like read(size)."""
        src = OfficialProbeBody(b"abcdefghij")
        wrapped = adapter._wrap_probe_body_read(OfficialProbeBody.read)
        src.read = wrapped.__get__(src, OfficialProbeBody)
        self.assertEqual(src.read(4), b"abcd")
        self.assertEqual(src.read(size=2), b"ef")
        self.assertEqual(src.read(), b"ghij")
        self.assertEqual(src.read(8), b"")

    def test_install_probe_body_read_patches_class(self):
        class Body:
            def __init__(self, data):
                self._data = data
                self._pos = 0

            def read(self, amount):
                chunk = self._data[self._pos : self._pos + amount]
                self._pos += len(chunk)
                return chunk

        self.assertTrue(adapter.install_probe_body_read(Body))
        probe = Body(b"xyz")
        self.assertEqual(probe.read(2), b"xy")
        self.assertEqual(probe.read(), b"z")

    def test_http_get_200_returns_status_headers_app_iter(self):
        class FakeResp:
            status = 200
            headers = {"Etag": "abc", "X-Object-Meta-Color": "red"}

            def read(self):
                return b"payload"

            def getcode(self):
                return 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def opener(req, timeout=None):
            self.assertEqual(req.get_method(), "GET")
            self.assertEqual(req.full_url, "http://127.0.0.1:18082/v1/AUTH_ec/c/o")
            self.assertEqual(req.get_header("X-backend-allow-reserved-names"), "true")
            return FakeResp()

        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        resp = adapter.rust_http_make_request(
            "GET",
            "/v1/AUTH_ec/c/o",
            {},
            (2,),
            opener=opener,
        )
        self.assertEqual(resp.status_int, 200)
        self.assertEqual(b"".join(resp.app_iter), b"payload")
        self.assertEqual(resp.headers.get("Etag"), "abc")
        self.assertEqual(resp.environ["wsgi.url_scheme"], "http")

    def test_http_404_raises_unexpected(self):
        def opener(req, timeout=None):
            hdrs = EmailMessage()
            raise urllib.error.HTTPError(
                req.full_url, 404, "Not Found", hdrs, io.BytesIO(b"missing")
            )

        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"

        class Boom(Exception):
            def __init__(self, message, resp):
                super().__init__(message)
                self.resp = resp

        with self.assertRaises(Boom) as ctx:
            adapter.rust_http_make_request(
                "GET",
                "/v1/a/c/o",
                {},
                (2,),
                opener=opener,
                unexpected_cls=Boom,
            )
        self.assertEqual(ctx.exception.resp.status_int, 404)
        translated = adapter.brain_translate_unexpected(ctx.exception)
        self.assertEqual(translated["http_status"], 404)
        self.assertEqual(translated["http_scheme"], "http")
        self.assertEqual(translated["http_host"], "127.0.0.1")
        self.assertEqual(translated["http_port"], "18082")
        self.assertEqual(translated["http_path"], "/v1/a/c/o")
        self.assertEqual(translated["http_query"], "")
        self.assertTrue(translated["http_reason"])
        for key in adapter.TRANSLATE_ENVIRON_KEYS:
            self.assertIn(key, ctx.exception.resp.environ)

    def test_internal_client_get_and_head_route_to_rust_http_on_18080(self):
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        self.assertTrue(adapter.install(DummyInternalClient))
        client = DummyInternalClient()
        seen = []

        def fake_http(method, path, headers, acceptable, **kwargs):
            del headers, kwargs
            seen.append((method, path, tuple(acceptable)))
            return adapter._HttpResp(200, {"X-Object-Meta-Color": "red"}, b"")

        with mock.patch.object(adapter, "rust_http_make_request", fake_http):
            get_resp = client.make_request("GET", "/v1/AUTH_ec/probe/obj", {}, (2,))
            head_resp = client.make_request("HEAD", "/v1/AUTH_ec/probe/obj", {}, (2,))
        self.assertEqual(get_resp.status_int, 200)
        self.assertEqual(head_resp.status_int, 200)
        self.assertEqual(head_resp.headers.get("X-Object-Meta-Color"), "red")
        self.assertEqual(
            seen,
            [
                ("GET", "/v1/AUTH_ec/probe/obj", (2,)),
                ("HEAD", "/v1/AUTH_ec/probe/obj", (2,)),
            ],
        )
        self.assertEqual(client.wsgi_calls, [])

    def test_internal_client_put_forwards_body_to_rust_http_on_18080(self):
        """Official non_durable_newer_data v2 is upload_object + no-commit."""
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        self.assertTrue(adapter.install(DummyInternalClient))
        client = DummyInternalClient()
        seen = []

        def fake_http(method, path, headers, acceptable, **kwargs):
            seen.append(
                {
                    "method": method,
                    "path": path,
                    "headers": dict(headers or {}),
                    "acceptable": tuple(acceptable),
                    "body": kwargs.get("body"),
                }
            )
            return adapter._HttpResp(201, {}, b"")

        with mock.patch.object(adapter, "rust_http_make_request", fake_http):
            resp = client.make_request(
                "PUT",
                "/v1/AUTH_ec/probe/obj",
                {"x-backend-no-commit": "True"},
                (2,),
                body_file=io.BytesIO(b"v2-probe-body"),
            )
        self.assertEqual(resp.status_int, 201)
        self.assertEqual(seen[0]["method"], "PUT")
        self.assertEqual(seen[0]["body"], b"v2-probe-body")
        self.assertEqual(seen[0]["headers"].get("x-backend-no-commit"), "True")
        self.assertEqual(client.wsgi_calls, [])

    def test_internal_client_put_drains_official_probabody(self):
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        self.assertTrue(adapter.install(DummyInternalClient))
        client = DummyInternalClient()
        seen = []

        def fake_http(method, path, headers, acceptable, **kwargs):
            del path, headers, acceptable
            seen.append((method, kwargs.get("body")))
            return adapter._HttpResp(201, {}, b"")

        with mock.patch.object(adapter, "rust_http_make_request", fake_http):
            resp = client.make_request(
                "PUT",
                "/v1/AUTH_ec/probe/obj",
                {"Transfer-Encoding": "chunked", "x-backend-no-commit": "True"},
                (2,),
                body_file=OfficialProbeBody(b"v2-from-probabody"),
            )
        self.assertEqual(resp.status_int, 201)
        self.assertEqual(seen, [("PUT", b"v2-from-probabody")])

    def test_non_isolated_put_keeps_original_body_file(self):
        adapter.install(DummyInternalClient)
        client = DummyInternalClient()
        body = io.BytesIO(b"keep-me")
        with self.assertRaises(AssertionError) as ctx:
            client.make_request(
                "PUT",
                "/v1/AUTH_ec/probe/obj",
                {},
                (2,),
                body_file=body,
            )
        self.assertIn("WSGI", str(ctx.exception))
        self.assertEqual(client.wsgi_calls[0][0], "PUT")
        self.assertIs(client.wsgi_calls[0][5], body)

    def test_swiftclient_proxy_get_matches_official_return(self):
        """Official proxy_get returns (headers, md5_hex). Lab used swiftclient."""

        class Probe:
            url = "http://127.0.0.1:18080/auth/v1.0"
            token = "AUTH_tk"
            container_name = b"c"
            object_name = b"o"

        def get_object(url, token, container, obj):
            self.assertEqual(url, Probe.url)
            self.assertEqual(token, Probe.token)
            return {"Etag": "ignored"}, b"abc"

        headers, etag = adapter.rust_swiftclient_proxy_get(
            Probe(), get_object=get_object
        )
        self.assertEqual(headers.get("Etag"), "ignored")
        self.assertEqual(etag, "900150983cd24fb0d6963f7d28e17f72")

    def test_probe_proxy_get_routes_to_rust_http_on_18080(self):
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"

        class Probe:
            url = "http://127.0.0.1:18080/v1/AUTH"
            token = "tk"
            container_name = "c"
            object_name = "o"
            int_hits = 0

            def proxy_get(self):
                self.int_hits += 1
                raise AssertionError("InternalClient proxy_get used")

        self.assertTrue(adapter.install_probe_proxy_get(Probe))
        with mock.patch.object(
            adapter,
            "rust_http_proxy_get",
            return_value=({"Etag": "x"}, "deadbeef"),
        ) as routed:
            headers, etag = Probe().proxy_get()
        self.assertEqual(etag, "deadbeef")
        routed.assert_called_once()

    def test_apply_lab_patch_inserts_18080_rust_http_branch(self):
        official = (
            adapter.OFFICIAL_PROXY_GET_HEAD
            + "        status, headers, body = self.int_client.get_object(a, c, o)\n"
        )
        updated, changed = adapter.apply_lab_proxy_get_to_source(official)
        self.assertTrue(changed)
        self.assertTrue(adapter.probe_source_routes_rust_http(updated))
        self.assertIn("rust_http_proxy_get", updated)
        self.assertIn(":18080", updated)
        again, changed_again = adapter.apply_lab_proxy_get_to_source(updated)
        self.assertFalse(changed_again)
        self.assertEqual(again, updated)

    def test_guard_ok_when_official_source_already_routes_http(self):
        official = (
            adapter.OFFICIAL_PROXY_GET_HEAD
            + "        status, headers, body = self.int_client.get_object(a, c, o)\n"
        )
        patched, _ = adapter.apply_lab_proxy_get_to_source(official)
        adapter.rust_object_get_guard(
            environ={"PROXY_BASE_URL": "http://127.0.0.1:18080"},
            conf_text=EGG_CONF,
            adapter_installed=False,
            source_routes_http=adapter.probe_source_routes_rust_http(patched),
        )

    def test_prepare_rewrites_official_probe_and_is_idempotent(self):
        import tempfile

        official = (
            adapter.OFFICIAL_PROXY_GET_HEAD
            + "        status, headers, body = self.int_client.get_object(a, c, o)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "test_reconstructor_rebuild.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(official)
            env = {
                "PROXY_BASE_URL": "http://127.0.0.1:18080",
                "G6_REBUILD_PROBE_PATH": path,
            }
            first = adapter.prepare_isolated_proxy_get(environ=env, probe_path=path)
            self.assertTrue(first["isolated"])
            self.assertTrue(first["probe_changed"])
            self.assertTrue(first["probe_routes_http"])
            with open(path, encoding="utf-8") as fh:
                body = fh.read()
            self.assertTrue(adapter.probe_source_routes_rust_http(body))
            second = adapter.prepare_isolated_proxy_get(environ=env, probe_path=path)
            self.assertFalse(second["probe_changed"])
            self.assertTrue(second["probe_routes_http"])

    def test_find_official_probe_prefers_g6_rebuild_probe_path(self):
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as fh:
            fh.write(b"# probe\n")
            path = fh.name
        try:
            found = adapter.find_official_probe({"G6_REBUILD_PROBE_PATH": path})
            self.assertEqual(found, path)
        finally:
            os.unlink(path)

    def test_prepare_is_noop_without_18080(self):
        result = adapter.prepare_isolated_proxy_get(environ={})
        self.assertFalse(result["isolated"])
        self.assertFalse(result["probe_changed"])


class PartPowerSwiftDir(unittest.TestCase):
    """Field /workspace/g6-partpower-next-rootcause.txt: no /etc/swift invent."""

    def tearDown(self):
        adapter.uninstall()
        os.environ.pop("PROXY_BASE_URL", None)
        os.environ.pop("G6_INTERNAL_PROXY_URL", None)
        os.environ.pop("SWIFT_DIR", None)

    def test_isolated_swift_dir_defaults_g6_rust_on_18080(self):
        self.assertEqual(
            adapter.isolated_swift_dir(
                {"PROXY_BASE_URL": "http://127.0.0.1:18080"}
            ),
            "/etc/g6-rust",
        )
        self.assertEqual(
            adapter.isolated_swift_dir(
                {
                    "PROXY_BASE_URL": "http://127.0.0.1:18080",
                    "SWIFT_DIR": "/tmp/g6-swift",
                }
            ),
            "/tmp/g6-swift",
        )
        self.assertEqual(
            adapter.isolated_swift_dir(
                {"PROXY_BASE_URL": "http://127.0.0.1:8080"}
            ),
            "",
        )

    def test_rewrite_etc_swift_path_maps_only_etc_swift(self):
        env = {
            "PROXY_BASE_URL": "http://127.0.0.1:18080",
            "SWIFT_DIR": "/etc/g6-rust",
        }
        self.assertEqual(
            adapter.rewrite_etc_swift_path("/etc/swift/backups", env),
            "/etc/g6-rust/backups",
        )
        self.assertEqual(
            adapter.rewrite_etc_swift_path("/etc/swift/object.builder", env),
            "/etc/g6-rust/object.builder",
        )
        self.assertEqual(
            adapter.rewrite_etc_swift_path("/etc/swift/object.ring.gz", env),
            "/etc/g6-rust/object.ring.gz",
        )
        self.assertEqual(
            adapter.rewrite_etc_swift_path("/srv/node/d1", env),
            "/srv/node/d1",
        )
        self.assertEqual(
            adapter.rewrite_etc_swift_path(
                "/etc/swift/backups",
                {"PROXY_BASE_URL": "http://127.0.0.1:8080"},
            ),
            "/etc/swift/backups",
        )

    def test_ensure_isolated_swift_dir_stamps_env(self):
        env = {"PROXY_BASE_URL": "http://127.0.0.1:18080"}
        self.assertEqual(adapter.ensure_isolated_swift_dir(env), "/etc/g6-rust")
        self.assertEqual(env["SWIFT_DIR"], "/etc/g6-rust")
        keep = {
            "PROXY_BASE_URL": "http://127.0.0.1:18080",
            "SWIFT_DIR": "/already",
        }
        self.assertEqual(adapter.ensure_isolated_swift_dir(keep), "/already")

    def test_partpower_source_rewrite_retargets_etc_swift_access(self):
        official = (
            "        self.assertTrue(os.access('/etc/swift', os.W_OK))\n"
            "        self.assertTrue(os.access('/etc/swift/backups', os.W_OK))\n"
            "        self.assertTrue(os.access('/etc/swift/object.builder', os.W_OK))\n"
            "        self.assertTrue(os.access('/etc/swift/object.ring.gz', os.W_OK))\n"
        )
        updated, changed = adapter.apply_lab_partpower_swift_dir_to_source(official)
        self.assertTrue(changed)
        self.assertIn(adapter.PARTPOWER_SWIFT_DIR_MARKER, updated)
        self.assertNotIn("os.access('/etc/swift/backups'", updated)
        again, changed_again = adapter.apply_lab_partpower_swift_dir_to_source(
            updated
        )
        self.assertFalse(changed_again)
        self.assertEqual(again, updated)

    def test_partpower_setup_wrap_remaps_os_access(self):
        import tempfile

        class Probe:
            def setUp(self):
                self.backups_ok = os.access("/etc/swift/backups", os.W_OK)
                self.builder_ok = os.access("/etc/swift/object.builder", os.W_OK)

        with tempfile.TemporaryDirectory() as tmp:
            backups = os.path.join(tmp, "backups")
            os.mkdir(backups)
            open(os.path.join(tmp, "object.builder"), "w").close()
            os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
            os.environ["SWIFT_DIR"] = tmp
            self.assertTrue(adapter.install_partpower_setup(Probe))
            probe = Probe()
            probe.setUp()
            self.assertTrue(probe.backups_ok)
            self.assertTrue(probe.builder_ok)
            self.assertTrue(os.path.isdir(backups))

    def test_isolated_relinker_argv_routes_python_relinker_not_path(self):
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        rewritten = adapter.isolated_relinker_argv(
            ["swift-object-relinker", "relink", "/etc/g6-rust/object-server/1.conf"]
        )
        self.assertEqual(rewritten[0], sys.executable)
        self.assertEqual(rewritten[1:3], ["-m", "g6_rust_proxy_get"])
        self.assertEqual(rewritten[3], "--relinker")
        self.assertEqual(
            rewritten[4:],
            ["relink", "/etc/g6-rust/object-server/1.conf"],
        )
        self.assertEqual(
            adapter.isolated_relinker_argv(["swift-object-replicator", "once"]),
            ["swift-object-replicator", "once"],
        )

    def test_inject_relinker_swift_dir_is_idempotent(self):
        self.assertEqual(
            adapter.inject_relinker_swift_dir(
                ["relink", "/etc/g6-rust/object-server/1.conf"],
                "/etc/g6-rust",
            ),
            [
                "--swift-dir",
                "/etc/g6-rust",
                "relink",
                "/etc/g6-rust/object-server/1.conf",
            ],
        )
        already = ["--swift-dir", "/etc/g6-rust", "relink", "x.conf"]
        self.assertEqual(
            adapter.inject_relinker_swift_dir(already, "/etc/g6-rust"),
            already,
        )

    def test_check_call_wrap_rewrites_relinker_only(self):
        seen = []

        def fake_check_call(cmd, *args, **kwargs):
            seen.append(list(cmd))
            return 0

        subprocess.check_call = fake_check_call  # type: ignore[assignment]
        try:
            os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
            self.assertTrue(adapter.install_partpower_relinker())
            subprocess.check_call(
                ["swift-object-relinker", "cleanup", "/etc/g6-rust/object-server/1.conf"]
            )
            subprocess.check_call(["echo", "ok"])
        finally:
            adapter.uninstall()
        self.assertEqual(seen[0][1:4], ["-m", "g6_rust_proxy_get", "--relinker"])
        self.assertEqual(seen[0][-2:], ["cleanup", "/etc/g6-rust/object-server/1.conf"])
        self.assertEqual(seen[1], ["echo", "ok"])

    def test_run_isolated_relinker_set_swift_dir_then_python_main(self):
        calls = []

        def fake_bind(swift_dir):
            calls.append(("bind", swift_dir))

        class RelinkerMain:
            def __init__(self):
                self.argv = None

            def __call__(self, argv=None):
                self.argv = list(argv)
                calls.append(("main", self.argv))
                return 0

        relinker_main = RelinkerMain()
        fake_relinker = type("cli", (), {"relinker": type("r", (), {"main": relinker_main})})
        with mock.patch.object(adapter, "bind_relinker_to_swift_dir", fake_bind):
            with mock.patch.dict(
                sys.modules,
                {"swift": type(sys)("swift"), "swift.cli": type(sys)("swift.cli")},
            ):
                sys.modules["swift.cli"] = type(sys)("swift.cli")
                sys.modules["swift.cli.relinker"] = fake_relinker.relinker
                env = {
                    "PROXY_BASE_URL": "http://127.0.0.1:18080",
                    "SWIFT_DIR": "/etc/g6-rust",
                }
                rc = adapter.run_isolated_relinker(
                    ["relink", "/etc/g6-rust/object-server/1.conf"],
                    environ=env,
                )
        self.assertEqual(rc, 0)
        self.assertEqual(calls[0], ("bind", "/etc/g6-rust"))
        self.assertEqual(calls[1][0], "main")
        self.assertEqual(calls[1][1][:2], ["--swift-dir", "/etc/g6-rust"])
        self.assertIn("relink", calls[1][1])


class ExpireWaitHonesty(unittest.TestCase):
    """ASCII test_sync_expired_object: IsolatedIdentity GET must 404 in ~2s."""

    def tearDown(self):
        adapter.uninstall()
        os.environ.pop("PROXY_BASE_URL", None)
        os.environ.pop("G6_INTERNAL_PROXY_URL", None)

    def test_resolve_delete_after_becomes_delete_at(self):
        now = 1_700_000_000.4
        out = adapter.resolve_delete_after_headers({"x-delete-after": 2}, now=now)
        self.assertEqual(out["X-Delete-At"], str(int(now) + 2))
        self.assertNotIn("x-delete-after", out)
        self.assertIsNone(adapter.resolve_delete_after_headers(None))
        kept = adapter.resolve_delete_after_headers({"X-Object-Meta-Color": "red"})
        self.assertEqual(kept["X-Object-Meta-Color"], "red")

    def test_probe_delete_at_stash_expires(self):
        class Probe:
            pass

        probe = Probe()
        adapter.remember_probe_delete_at(probe, {"X-Delete-At": "100"})
        self.assertTrue(adapter.probe_delete_at_expired(probe, now=100))
        self.assertTrue(adapter.probe_delete_at_expired(probe, now=101))
        self.assertFalse(adapter.probe_delete_at_expired(probe, now=99))

    def test_client_get_sees_expired_from_headers(self):
        self.assertTrue(
            adapter.client_get_sees_expired({"X-Delete-At": "50"}, now=50)
        )
        self.assertFalse(
            adapter.client_get_sees_expired({"X-Delete-At": "50"}, now=49)
        )
        self.assertFalse(
            adapter.client_get_sees_expired(
                {"X-Delete-At": "50", "X-Backend-Replication": "true"},
                now=50,
            )
        )

    def test_rust_http_proxy_get_200_returns_md5(self):
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"

        class Probe:
            url = "http://127.0.0.1:18080/v1/AUTH_test"
            token = "tk"
            container_name = "c"
            object_name = "live"

        class FakeResp:
            status = 200
            headers = {"Etag": "ignored"}

            def read(self):
                return b"abc"

            def getcode(self):
                return 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        headers, etag = adapter.rust_http_proxy_get(Probe(), opener=lambda req, timeout=None: FakeResp())
        self.assertEqual(etag, "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(headers.get("Etag"), "ignored")

    def test_rust_http_proxy_get_404_is_unexpected_response(self):
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"

        class Probe:
            url = "http://127.0.0.1:18080/v1/AUTH_test"
            token = "tk"
            container_name = "c"
            object_name = "expired"

        def opener(req, timeout=None):
            raise urllib.error.HTTPError(
                req.full_url, 404, "Not Found", EmailMessage(), io.BytesIO(b"")
            )

        with self.assertRaises(Exception) as ctx:
            adapter.rust_http_proxy_get(Probe(), opener=opener)
        self.assertEqual(ctx.exception.resp.status_int, 404)

    def test_rust_http_proxy_get_200_with_past_delete_at_is_404(self):
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"

        class Probe:
            url = "http://127.0.0.1:18080/v1/AUTH_test"
            token = "tk"
            container_name = "c"
            object_name = "stale"

        class FakeResp:
            status = 200
            headers = {"X-Delete-At": "1"}

            def read(self):
                return b"still-here"

            def getcode(self):
                return 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def opener(req, timeout=None):
            return FakeResp()

        with self.assertRaises(Exception) as ctx:
            adapter.rust_http_proxy_get(Probe(), opener=opener)
        self.assertEqual(ctx.exception.resp.status_int, 404)

    def test_stashed_delete_at_404s_without_http(self):
        class Probe:
            url = "http://127.0.0.1:18080/v1/AUTH_test"
            container_name = "c"
            object_name = "o"
            _g6_isolated_delete_at = 1

        with self.assertRaises(Exception) as ctx:
            adapter.rust_http_proxy_get(Probe())
        self.assertEqual(ctx.exception.resp.status_int, 404)

    def test_official_expire_wait_loop_breaks_on_404(self):
        """Official while/else: UnexpectedResponse 404 breaks; 200 times out."""
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"

        class Probe:
            url = "http://127.0.0.1:18080/v1/AUTH_test"
            token = "tk"
            container_name = b"c"
            object_name = b"o"
            hits = 0

        class FakeResp:
            def __init__(self, status, headers, body):
                self.status = status
                self.headers = headers
                self._body = body

            def read(self):
                return self._body

            def getcode(self):
                return self.status

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def opener(req, timeout=None):
            Probe.hits += 1
            if Probe.hits < 2:
                return FakeResp(200, {}, b"live")
            raise urllib.error.HTTPError(
                req.full_url, 404, "Not Found", EmailMessage(), io.BytesIO(b"")
            )

        timeout = time.time() + 2 + 1
        broke = False
        while time.time() < timeout:
            try:
                adapter.rust_http_proxy_get(Probe(), opener=opener)
            except Exception as err:
                resp = getattr(err, "resp", None)
                if resp is not None and getattr(resp, "status_int", None) == 404:
                    broke = True
                    break
                raise
        else:
            self.fail("Timed out waiting for c/o to expire after 2s")
        self.assertTrue(broke)
        self.assertEqual(Probe.hits, 2)

    def test_proxy_put_wrap_converts_and_stashes_delete_at(self):
        class Probe:
            def proxy_put(self, extra_headers=None):
                self.seen = extra_headers

        self.assertTrue(adapter.install_probe_proxy_put(Probe))
        now = 1_700_000_010
        with mock.patch.object(adapter.time, "time", return_value=now):
            inst = Probe()
            inst.proxy_put(extra_headers={"x-delete-after": 2})
        self.assertEqual(inst.seen["X-Delete-At"], str(now + 2))
        self.assertEqual(inst._g6_isolated_delete_at, now + 2)

    def test_apply_lab_put_patch_is_idempotent(self):
        official = (
            adapter.OFFICIAL_PROXY_PUT_HEAD
            + "        headers = {}\n"
        )
        updated, changed = adapter.apply_lab_proxy_put_to_source(official)
        self.assertTrue(changed)
        self.assertIn("resolve_delete_after_headers", updated)
        again, changed_again = adapter.apply_lab_proxy_put_to_source(updated)
        self.assertFalse(changed_again)
        self.assertEqual(again, updated)

    def test_probe_object_path_uses_storage_url_account(self):
        class Probe:
            url = "http://127.0.0.1:18080/v1/AUTH_test"
            container_name = b"cont\xc3\xa8-x"
            object_name = b"obj\xc3\xa8-y"

        self.assertEqual(
            adapter.probe_object_path(Probe()),
            "/v1/AUTH_test/cont%C3%A8-x/obj%C3%A8-y",
        )


class UnifiedInternalHop(unittest.TestCase):
    """Field g6-rebuild-982e86a-unified: :18082 GET + expire UnexpectedResponse."""

    def tearDown(self):
        adapter.uninstall()
        os.environ.pop("PROXY_BASE_URL", None)
        os.environ.pop("G6_INTERNAL_PROXY_URL", None)

    def test_ensure_internal_defaults_on_18080(self):
        env = {"PROXY_BASE_URL": "http://127.0.0.1:18080"}
        self.assertEqual(
            adapter.ensure_internal_proxy_url(env),
            "http://127.0.0.1:18082",
        )
        self.assertEqual(env[adapter.G6_INTERNAL_PROXY_URL_ENV], "http://127.0.0.1:18082")
        env_keep = {
            "PROXY_BASE_URL": "http://127.0.0.1:18080",
            "G6_INTERNAL_PROXY_URL": "http://10.0.0.1:18082",
        }
        self.assertEqual(
            adapter.ensure_internal_proxy_url(env_keep),
            "http://10.0.0.1:18082",
        )
        self.assertEqual(adapter.ensure_internal_proxy_url({}), "")

    def test_get_and_no_commit_hop_18082_plain_put_stays_18080(self):
        env = {
            "PROXY_BASE_URL": "http://127.0.0.1:18080",
            "G6_INTERNAL_PROXY_URL": "http://127.0.0.1:18082",
        }
        self.assertEqual(
            adapter.request_proxy_base_url("GET", {}, env),
            "http://127.0.0.1:18082",
        )
        self.assertEqual(
            adapter.request_proxy_base_url(
                "PUT", {"x-backend-no-commit": "True"}, env
            ),
            "http://127.0.0.1:18082",
        )
        self.assertEqual(
            adapter.request_proxy_base_url("PUT", {"Content-Type": "text/plain"}, env),
            "http://127.0.0.1:18080",
        )
        # Hop helper without IsolatedIdentity stamp: plain PUT stays :18080.
        # rust_http_make_request stamps reserved-names *before* hop (egg).
        self.assertTrue(
            adapter.headers_need_gatekeeper_bypass(
                {"X-Backend-Allow-Reserved-Names": "true"}
            )
        )
        self.assertTrue(
            adapter.headers_need_gatekeeper_bypass(
                {"X-Backend-Storage-Policy-Index": "0"}
            )
        )
        self.assertTrue(
            adapter.headers_need_gatekeeper_bypass({"x-backend-no-commit": "True"})
        )
        self.assertEqual(
            adapter.request_proxy_base_url(
                "PUT", {"X-Backend-Allow-Reserved-Names": "true"}, env
            ),
            "http://127.0.0.1:18082",
        )
        self.assertEqual(
            adapter.request_proxy_base_url(
                "HEAD", {"X-Backend-Storage-Policy-Index": "0"}, env
            ),
            "http://127.0.0.1:18082",
        )

    def test_rust_http_proxy_get_uses_18082_and_keeps_unexpected_404(self):
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        os.environ["G6_INTERNAL_PROXY_URL"] = "http://127.0.0.1:18082"
        seen = {}

        class Probe:
            url = "http://127.0.0.1:18080/v1/AUTH_test"
            token = "tk"
            container_name = "c"
            object_name = "expired"

        def opener(req, timeout=None):
            seen["url"] = req.full_url
            raise urllib.error.HTTPError(
                req.full_url, 404, "Not Found", EmailMessage(), io.BytesIO(b"")
            )

        with self.assertRaises(Exception) as ctx:
            adapter.rust_http_proxy_get(Probe(), opener=opener)
        self.assertEqual(ctx.exception.resp.status_int, 404)
        self.assertTrue(seen["url"].startswith("http://127.0.0.1:18082/"))

    def test_no_commit_put_uses_18082(self):
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        os.environ["G6_INTERNAL_PROXY_URL"] = "http://127.0.0.1:18082"
        seen = {}

        class FakeResp:
            status = 201
            headers = {}

            def read(self):
                return b""

            def getcode(self):
                return 201

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def opener(req, timeout=None):
            seen["url"] = req.full_url
            return FakeResp()

        resp = adapter.rust_http_make_request(
            "PUT",
            "/v1/AUTH_ec/c/o",
            {"x-backend-no-commit": "True"},
            (2,),
            opener=opener,
            body=b"v2",
        )
        self.assertEqual(resp.status_int, 201)
        self.assertTrue(seen["url"].startswith("http://127.0.0.1:18082/"))

    def test_make_request_backend_headers_hop_18082(self):
        """Caller X-Backend-* on rust_http_make_request hops :18082.

        Reconciler HEAD stamps Storage-Policy-Index. ReservedNamespace
        put_container is covered by setdefault-before-hop (brain sends
        X-Storage-Policy only).
        """
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        os.environ["G6_INTERNAL_PROXY_URL"] = "http://127.0.0.1:18082"
        seen = {}

        class FakeResp:
            status = 204
            headers = {}

            def read(self):
                return b""

            def getcode(self):
                return 204

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def opener(req, timeout=None):
            seen["url"] = req.full_url
            seen["method"] = req.get_method()
            seen["reserved"] = req.get_header("X-backend-allow-reserved-names")
            seen["policy"] = req.get_header("X-backend-storage-policy-index")
            return FakeResp()

        resp = adapter.rust_http_make_request(
            "PUT",
            "/v1/.expiring_objects/1234",
            {"X-Backend-Allow-Reserved-Names": "true"},
            (2,),
            opener=opener,
        )
        self.assertEqual(resp.status_int, 204)
        self.assertTrue(seen["url"].startswith("http://127.0.0.1:18082/"))
        self.assertEqual(seen["reserved"], "true")

        seen.clear()

        class HeadResp(FakeResp):
            status = 404

            def getcode(self):
                return 404

        def head_opener(req, timeout=None):
            seen["url"] = req.full_url
            seen["policy"] = req.get_header("X-backend-storage-policy-index")
            return HeadResp()

        resp = adapter.rust_http_make_request(
            "HEAD",
            "/v1/AUTH_test/c/o",
            {"X-Backend-Storage-Policy-Index": "0"},
            (2, 4),
            opener=head_opener,
        )
        self.assertEqual(resp.status_int, 404)
        self.assertTrue(seen["url"].startswith("http://127.0.0.1:18082/"))
        self.assertEqual(seen["policy"], "0")

    def test_unexpected_404_brain_translate_fields_no_keyerror(self):
        """Official translate_client_exception must not KeyError on 404.

        Field /workspace/g6-merge-404-rootcause.txt (2026-09-07): residual
        ReservedNamespace get_object / reconcile_symlink ERROR was incomplete
        _HttpResp.environ (not a missing object). Reserved GET 2xx already
        proven (move_twice PASS). Fill scheme/host/port/path/query from the
        request URL plus explanation.
        """
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        os.environ["G6_INTERNAL_PROXY_URL"] = "http://127.0.0.1:18082"

        class Boom(Exception):
            def __init__(self, message, resp):
                super().__init__(message)
                self.resp = resp

        def opener(req, timeout=None):
            raise urllib.error.HTTPError(
                req.full_url,
                404,
                "Not Found",
                EmailMessage(),
                io.BytesIO(b"Not Found"),
            )

        with self.assertRaises(Boom) as ctx:
            adapter.rust_http_make_request(
                "GET",
                "/v1/.expiring_objects/1234/obj",
                {},
                (2,),
                params={"format": "json"},
                opener=opener,
                unexpected_cls=Boom,
            )
        resp = ctx.exception.resp
        self.assertEqual(resp.environ["wsgi.url_scheme"], "http")
        self.assertEqual(resp.environ["SERVER_NAME"], "127.0.0.1")
        self.assertEqual(resp.environ["SERVER_PORT"], "18082")
        self.assertEqual(resp.environ["PATH_INFO"], "/v1/.expiring_objects/1234/obj")
        self.assertEqual(resp.environ["QUERY_STRING"], "format=json")
        self.assertTrue(resp.explanation)
        translated = adapter.brain_translate_unexpected(ctx.exception)
        self.assertEqual(translated["http_status"], 404)
        self.assertEqual(translated["http_port"], "18082")
        self.assertEqual(translated["http_path"], "/v1/.expiring_objects/1234/obj")
        self.assertEqual(translated["http_query"], "format=json")
        self.assertEqual(translated["http_reason"], resp.explanation)

        built = adapter._HttpResp(
            404,
            {},
            b"Not Found",
            url="http://127.0.0.1:18082/v1/AUTH_test/c/o?symlink=get",
            method="GET",
        )
        self.assertEqual(built.environ["PATH_INFO"], "/v1/AUTH_test/c/o")
        self.assertEqual(built.environ["QUERY_STRING"], "symlink=get")
        self.assertEqual(built.environ["SERVER_PORT"], "18082")
        fake_err = Boom("Unexpected response: 404 Not Found", built)
        self.assertEqual(
            adapter.brain_translate_unexpected(fake_err)["http_query"],
            "symlink=get",
        )

    def test_make_request_setdefault_reserved_before_hop(self):
        """Egg parity: IsolatedIdentity stamps Allow-Reserved-Names before hop.

        Field /workspace/g6-merge-xbackend-18082/ (2026-09-07) on 8353823+wrap:
        PASS=9/bad=2. Brain put_container only sends X-Storage-Policy.
        Pure 8353823 stamped reserved-names after hop → stayed :18080 → 412.
        setdefault before hop cleared ReservedNamespace 412 and move_twice 200.
        Do not chase residual ReservedNamespace get_object 404.
        """
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        os.environ["G6_INTERNAL_PROXY_URL"] = "http://127.0.0.1:18082"
        seen = {}

        class FakeResp:
            status = 201
            headers = {}

            def read(self):
                return b""

            def getcode(self):
                return 201

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def opener(req, timeout=None):
            seen["url"] = req.full_url
            seen["reserved"] = req.get_header("X-backend-allow-reserved-names")
            return FakeResp()

        resp = adapter.rust_http_make_request(
            "PUT",
            "/v1/.expiring_objects/1234",
            {"X-Storage-Policy": "gold"},
            (2,),
            opener=opener,
        )
        self.assertEqual(resp.status_int, 201)
        self.assertTrue(seen["url"].startswith("http://127.0.0.1:18082/"))
        self.assertEqual(seen["reserved"], "true")
        self.assertEqual(resp.environ["wsgi.url_scheme"], "http")

        seen.clear()
        resp = adapter.rust_http_make_request(
            "PUT",
            "/v1/AUTH_test/c",
            {"X-Timestamp": "1"},
            (2,),
            opener=opener,
        )
        self.assertEqual(resp.status_int, 201)
        self.assertTrue(seen["url"].startswith("http://127.0.0.1:18082/"))
        self.assertEqual(seen["reserved"], "true")

        env = {
            "PROXY_BASE_URL": "http://127.0.0.1:18080",
            "G6_INTERNAL_PROXY_URL": "http://127.0.0.1:18082",
        }
        # Hop helper without IsolatedIdentity stamp still stays public.
        self.assertEqual(
            adapter.request_proxy_base_url("PUT", {"X-Storage-Policy": "gold"}, env),
            "http://127.0.0.1:18080",
        )
        stamped = {"X-Storage-Policy": "gold"}
        stamped.setdefault("X-Backend-Allow-Reserved-Names", "true")
        self.assertEqual(
            adapter.request_proxy_base_url("PUT", stamped, env),
            "http://127.0.0.1:18082",
        )

    def test_prepare_defaults_internal_url(self):
        import tempfile

        official = (
            adapter.OFFICIAL_PROXY_GET_HEAD
            + "        status, headers, body = self.int_client.get_object(a, c, o)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "test_reconstructor_rebuild.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(official)
            env = {
                "PROXY_BASE_URL": "http://127.0.0.1:18080",
                "G6_REBUILD_PROBE_PATH": path,
            }
            result = adapter.prepare_isolated_proxy_get(environ=env, probe_path=path)
        self.assertTrue(result["isolated"])
        self.assertEqual(result["internal_proxy_url"], "http://127.0.0.1:18082")
        self.assertEqual(env[adapter.G6_INTERNAL_PROXY_URL_ENV], "http://127.0.0.1:18082")

    def test_isolated_wrap_still_calls_rust_http_proxy_get(self):
        """Do not raw-replace IsolatedIdentity proxy_get (drops UnexpectedResponse)."""
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"

        class Probe:
            def proxy_get(self):
                raise AssertionError("official IsolatedIdentity proxy_get used")

        self.assertTrue(adapter.install_probe_proxy_get(Probe))
        with mock.patch.object(
            adapter, "rust_http_proxy_get", return_value=({}, "deadbeef")
        ) as routed:
            Probe().proxy_get()
        routed.assert_called_once()


if __name__ == "__main__":
    unittest.main()
