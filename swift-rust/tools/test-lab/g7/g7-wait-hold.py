#!/usr/bin/env python3
import sys, time, urllib.request

need = float(sys.argv[1]) if len(sys.argv) > 1 else 49900
url = sys.argv[2] if len(sys.argv) > 2 else "http://10.0.0.1:18080/recon/concurrency"
stable = 0
for i in range(120):
    try:
        body = urllib.request.urlopen(url, timeout=3).read().decode()
    except Exception as e:
        print("err", e, flush=True)
        time.sleep(1)
        continue
    d = {}
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        p = line.split()
        if len(p) >= 2:
            try:
                d[p[0].split("{", 1)[0]] = float(p[-1])
            except ValueError:
                pass
    c = d.get("connections_open", 0.0)
    idle = d.get("connections_idle", 0.0)
    th = d.get("process_threads", 0.0)
    print("poll", i, "open", int(c), "idle", int(idle), "threads", int(th), flush=True)
    if c >= need and idle >= c - 20:
        stable += 1
        if stable >= 2:
            sys.stdout.write(body)
            print("HOLD_READY", flush=True)
            sys.exit(0)
    else:
        stable = 0
    time.sleep(1)
print("HOLD_NOT_READY", flush=True)
sys.exit(2)
