# IsolatedIdentity adds this directory to PYTHONPATH (g6_isolated_probe.sh
# does too). When PROXY_BASE_URL contains :18080, rebuild proxy_get must
# use swiftclient HTTP to rust — apply the lab patch if the official
# probe file is present, otherwise fail closed.
# Gatekeeper on :18080 strips X-Backend-*. IsolatedIdentity GET and
# no-commit / frag-prefs use rust :18082 via G6_INTERNAL_PROXY_URL
# (field g6-rebuild-982e86a-unified, 2026-09-06). IsolatedIdentity
# proxy_get stays rust_http_proxy_get (UnexpectedResponse).
try:
    import g6_rust_proxy_get
except Exception:
    pass
else:
    try:
        g6_rust_proxy_get.maybe_autostart()
    except g6_rust_proxy_get.RustProxyGetError:
        raise
    except Exception:
        # Missing swift / probe imports must not break unrelated CPython.
        pass
