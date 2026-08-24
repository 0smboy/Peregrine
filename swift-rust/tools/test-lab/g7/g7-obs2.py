#!/usr/bin/env python3
"""Compare new-connection HEAD vs persistent keep-alive HEAD."""
import json, socket, sys, time

host, port, n = "10.0.0.1", 18080, 40
if len(sys.argv) >= 3:
    host, port = sys.argv[1], int(sys.argv[2])
if len(sys.argv) >= 4:
    n = int(sys.argv[3])

req_ka = (
    b"HEAD /healthcheck HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n"
    % host.encode()
)
req_close = (
    b"HEAD /healthcheck HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host.encode()
)


def read_resp(s):
    buf = b""
    s.settimeout(2)
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def p99(xs):
    xs = sorted(xs)
    if not xs:
        return None
    return xs[int((len(xs) - 1) * 0.99)]


def p50(xs):
    xs = sorted(xs)
    return xs[len(xs) // 2] if xs else None


persist = []
persist_err = None
try:
    s = socket.create_connection((host, port), 3)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(req_ka)
    read_resp(s)
    for _ in range(n):
        t0 = time.monotonic()
        s.sendall(req_ka)
        body = read_resp(s)
        persist.append((time.monotonic() - t0) * 1000)
        if b"200" not in body.split(b"\r\n", 1)[0]:
            persist[-1] = 2000.0
    s.close()
except Exception as e:
    persist_err = str(e)
    persist.append(2000.0)

fresh = []
fresh_err = None
for _ in range(n):
    try:
        t0 = time.monotonic()
        c = socket.create_connection((host, port), 3)
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        c.sendall(req_close)
        body = read_resp(c)
        fresh.append((time.monotonic() - t0) * 1000)
        c.close()
        if b"200" not in body.split(b"\r\n", 1)[0]:
            fresh[-1] = 2000.0
    except Exception as e:
        fresh_err = str(e)
        fresh.append(2000.0)

print(
    json.dumps(
        {
            "persist_n": len(persist),
            "persist_p50_ms": p50(persist),
            "persist_p99_ms": p99(persist),
            "persist_err": persist_err,
            "fresh_n": len(fresh),
            "fresh_p50_ms": p50(fresh),
            "fresh_p99_ms": p99(fresh),
            "fresh_err": fresh_err,
        }
    )
)
