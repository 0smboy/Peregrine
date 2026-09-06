# IsolatedIdentity adds this directory to PYTHONPATH. When PROXY_BASE_URL
# contains :18080, rebuild proxy_get must use swiftclient HTTP to rust.
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
