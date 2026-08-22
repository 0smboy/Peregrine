#!/usr/bin/env python3
"""Eventlet WSGI using in-tree SwiftHttpProtocol (wsgi.py:435-458).

Prints PORT=<n> then serves. Used by gate5_python_wire dual-feed tests.
"""
import sys
import warnings

warnings.filterwarnings("ignore", message="capitalize_response_headers is disabled")
warnings.filterwarnings("ignore", category=DeprecationWarning)

from eventlet import listen
from eventlet import wsgi

from swift.common.http_protocol import SwiftHttpProtocol


def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "")
    # First read of wsgi.input fires Expect: 100-continue
    # (http_protocol.py:214-217).
    body = b""
    if method in ("PUT", "POST", "SSYNC", "DELETE", "COPY"):
        inp = environ.get("wsgi.input")
        if inp is not None and method != "DELETE" and method != "COPY":
            body = inp.read()
        elif inp is not None and method in ("DELETE", "COPY"):
            # Don't force a body read; COPY/DELETE have empty bodies.
            pass
    if method == "PUT":
        start_response(
            "201 Created",
            [("Content-Length", "0"), ("ETag", '"abc"'), ("Content-Type", "text/plain")],
        )
        return [b""]
    if method == "DELETE":
        start_response("204 No Content", [("Content-Length", "0")])
        return [b""]
    if method == "COPY":
        start_response(
            "201 Created",
            [("Content-Length", "0"), ("X-Copied-From", "c/o")],
        )
        return [b""]
    if method == "SSYNC":
        out = b"\r\n"
        start_response(
            "200 OK",
            [
                ("Content-Length", str(len(out))),
                ("X-Backend-Accept-No-Commit", "True"),
            ],
        )
        return [out]
    if method == "HEAD":
        start_response("204 No Content", [("Content-Length", "0")])
        return [b""]
    start_response(
        "200 OK",
        [("Content-Length", "2"), ("ETag", '"ok"'), ("Content-Type", "text/plain")],
    )
    return [b"ok"]


def main():
    sock = listen(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    print(f"PORT={port}", flush=True)
    wsgi.server(
        sock,
        app,
        protocol=SwiftHttpProtocol,
        capitalize_response_headers=False,
        socket_timeout=2,
        keepalive=False,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
