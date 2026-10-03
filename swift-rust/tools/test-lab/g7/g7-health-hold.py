#!/usr/bin/env python3
"""Persistent loopback HEAD sampler. One connection, no accept storm."""
import json
import os
import socket
import sys
import time

stop = sys.argv[1]
out = sys.argv[2]
host = sys.argv[3]
port = int(sys.argv[4])
path = sys.argv[5]
delay = float(sys.argv[6]) if len(sys.argv) > 6 else 0.0
req = (
    f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n"
).encode()
xs = []
ok = 0
sock = None
started = time.monotonic()
while not os.path.exists(stop) and len(xs) < 40:
    t0 = time.monotonic()
    try:
        if sock is None:
            sock = socket.create_connection((host, port), 2)
            sock.settimeout(2)
        sock.sendall(req)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(1024)
            if not chunk:
                raise OSError("eof")
            buf += chunk
        status = int(buf.split(None, 2)[1])
        if status == 200 and (time.monotonic() - started) >= delay:
            xs.append((time.monotonic() - t0) * 1000.0)
            ok += 1
    except Exception:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        sock = None
    time.sleep(0.25)
if sock is not None:
    try:
        sock.close()
    except OSError:
        pass
xs.sort()
p99 = xs[int((len(xs) - 1) * 0.99)] if xs else 0
with open(out, "w", encoding="utf-8") as fh:
    json.dump({"n": len(xs), "ok": ok, "p99_ms": p99}, fh)
