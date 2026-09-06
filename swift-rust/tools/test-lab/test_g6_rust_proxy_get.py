#!/usr/bin/env python3
"""Fail-closed tests for the G6 rust HTTP proxy_get adapter. No Swift, no SSH."""
from __future__ import annotations

import io
import os
import socket
import threading
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


class HttpAndPatch(unittest.TestCase):
    def tearDown(self):
        adapter.uninstall()
        os.environ.pop("PROXY_BASE_URL", None)

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
            self.assertEqual(req.full_url, "http://127.0.0.1:18080/v1/AUTH_ec/c/o")
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

    def test_probe_proxy_get_routes_to_swiftclient_on_18080(self):
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
            "rust_swiftclient_proxy_get",
            return_value=({"Etag": "x"}, "deadbeef"),
        ) as routed:
            headers, etag = Probe().proxy_get()
        self.assertEqual(etag, "deadbeef")
        routed.assert_called_once()

    def test_apply_lab_patch_inserts_18080_swiftclient_branch(self):
        official = (
            adapter.OFFICIAL_PROXY_GET_HEAD
            + "        status, headers, body = self.int_client.get_object(a, c, o)\n"
        )
        updated, changed = adapter.apply_lab_proxy_get_to_source(official)
        self.assertTrue(changed)
        self.assertTrue(adapter.probe_source_routes_rust_http(updated))
        self.assertIn("client.get_object", updated)
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


if __name__ == "__main__":
    unittest.main()
