#!/usr/bin/env python3
"""Fail-closed tests for the G6 rust HTTP proxy_get adapter. No Swift, no SSH."""
from __future__ import annotations

import io
import os
import unittest
import urllib.error
from email.message import EmailMessage
from unittest import mock

import g6_rust_proxy_get as adapter


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
        self.wsgi_calls.append((method, path, headers, acceptable_statuses, params))
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

    def test_guard_silent_without_proxy_base(self):
        adapter.rust_object_get_guard(
            environ={},
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

    def test_patched_get_never_calls_wsgi(self):
        class FakeResp:
            status = 200
            headers = {}

            def read(self):
                return b"ok"

            def getcode(self):
                return 200

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def opener(req, timeout=None):
            return FakeResp()

        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        self.assertTrue(adapter.install(DummyInternalClient))
        client = DummyInternalClient()
        with mock.patch.object(adapter, "rust_http_exchange", side_effect=lambda *a, **k: adapter._HttpResp(200, {}, b"from-rust")):
            status_headers_body = client.make_request(
                "GET", "/v1/AUTH_ec/probe/obj", {}, (2,)
            )
        self.assertEqual(client.wsgi_calls, [])
        self.assertEqual(status_headers_body.status_int, 200)
        self.assertEqual(b"".join(status_headers_body.app_iter), b"from-rust")

    def test_patched_put_still_uses_original(self):
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        adapter.install(DummyInternalClient)
        client = DummyInternalClient()
        with self.assertRaises(AssertionError) as ctx:
            client.make_request("PUT", "/v1/AUTH_ec/probe/obj", {}, (2,))
        self.assertIn("WSGI", str(ctx.exception))
        self.assertEqual(client.wsgi_calls[0][0], "PUT")

    def test_get_object_shape_matches_official_proxy_get(self):
        """Official proxy_get unpacks (status, headers, body_iter)."""
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        adapter.install(DummyInternalClient)

        class ProbeClient(DummyInternalClient):
            def get_object(self, account, container, obj, headers=None, acceptable_statuses=(2,), params=None):
                path = f"/v1/{account}/{container}/{obj}"
                resp = self.make_request("GET", path, headers or {}, acceptable_statuses, params=params)
                return (resp.status_int, resp.headers, resp.app_iter)

        client = ProbeClient()
        with mock.patch.object(
            adapter,
            "rust_http_exchange",
            return_value=adapter._HttpResp(200, {"Etag": "deadbeef"}, b"abc"),
        ):
            status, headers, body = client.get_object("AUTH_ec", "probe", "obj")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Etag"), "deadbeef")
        self.assertEqual(b"".join(body), b"abc")
        self.assertEqual(client.wsgi_calls, [])


if __name__ == "__main__":
    unittest.main()
