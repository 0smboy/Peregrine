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

    def test_patched_put_still_uses_original(self):
        os.environ["PROXY_BASE_URL"] = "http://127.0.0.1:18080"
        adapter.install(DummyInternalClient)
        client = DummyInternalClient()
        with self.assertRaises(AssertionError) as ctx:
            client.make_request("PUT", "/v1/AUTH_ec/probe/obj", {}, (2,))
        self.assertIn("WSGI", str(ctx.exception))
        self.assertEqual(client.wsgi_calls[0][0], "PUT")

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
