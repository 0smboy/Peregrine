# IsolatedIdentity adds this directory to PYTHONPATH (g6_isolated_probe.sh
# does too). When PROXY_BASE_URL contains :18080, rebuild proxy_get must
# use swiftclient HTTP to rust — apply the lab patch if the official
# probe file is present, otherwise fail closed.
# Gatekeeper on :18080 strips X-Backend-*. IC no-commit / frag-prefs
# honesty is rust :18082 (field rebuild-nondurable-176505e, 2026-09-06).
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
