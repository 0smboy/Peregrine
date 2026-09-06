# IsolatedIdentity adds this directory to PYTHONPATH. When PROXY_BASE_URL
# is set, InternalClient GET/HEAD must HTTP to rust :18080.
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
