#!/usr/bin/env python3
"""Slow GET (200 slow readers) then bounded overload. Observer is separate."""
import os, socket, sys, threading, time, urllib.request

HOST, PORT = "10.0.0.1", 18080
SRCS = ["10.0.0.4", "10.0.4.4", "10.0.8.4"]


def auth():
    req = urllib.request.Request(
        f"http://{HOST}:{PORT}/auth/v1.0",
        headers={"X-Auth-User": "test:tester", "X-Auth-Key": "testing"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.headers.get("X-Auth-Token") or r.headers.get("x-auth-token")


def put(token, name, body: bytes):
    req = urllib.request.Request(
        f"http://{HOST}:{PORT}/v1/AUTH_test/g7slow/{name}",
        data=body,
        method="PUT",
        headers={"X-Auth-Token": token, "Content-Type": "application/octet-stream"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def slow_get(token, n=200, hold=12.0):
    opened = [0]
    stop = threading.Event()

    def one(i):
        s = socket.socket()
        s.settimeout(8)
        try:
            s.bind((SRCS[i % 3], 0))
            s.connect((HOST, PORT))
            s.sendall(
                (
                    f"GET /v1/AUTH_test/g7slow/blob1m HTTP/1.1\r\n"
                    f"Host: h\r\nX-Auth-Token: {token}\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                ).encode()
            )
            opened[0] += 1
            while not stop.is_set():
                try:
                    d = s.recv(1024)
                    if not d:
                        break
                    time.sleep(0.5)
                except Exception:
                    break
        except Exception:
            pass
        finally:
            s.close()

    th = [threading.Thread(target=one, args=(i,), daemon=True) for i in range(n)]
    for t in th:
        t.start()
    time.sleep(hold)
    got = opened[0]
    stop.set()
    for t in th:
        t.join(timeout=1)
    return got


def overload(token, n=4000, body=b"X" * 65536):
    ok = fail = 0
    lock = threading.Lock()

    def one(i):
        nonlocal ok, fail
        try:
            st = put(token, f"ov{i}", body)
            with lock:
                if st and 200 <= st < 300:
                    ok += 1
                else:
                    fail += 1
        except Exception:
            with lock:
                fail += 1

    th = [threading.Thread(target=one, args=(i,), daemon=True) for i in range(n)]
    for t in th:
        t.start()
    for t in th:
        t.join(timeout=120)
    return ok, fail


def main():
    token = auth()
    mode = sys.argv[1] if len(sys.argv) > 1 else "slowget"
    if mode == "seed":
        print("SEED", put(token, "blob1m", b"Y" * 1048576), flush=True)
    elif mode == "slowget":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 200
        print("SLOWGET", slow_get(token, n=n), flush=True)
    elif mode == "overload":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 4000
        ok, fail = overload(token, n=n)
        print("OVERLOAD", ok, fail, flush=True)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()
