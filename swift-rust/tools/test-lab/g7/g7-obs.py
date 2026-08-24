#!/usr/bin/env python3
"""Independent health observer. Run on the SUT host (few fds), not the loadgen."""
import json, sys, time, urllib.request

n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
url = sys.argv[2] if len(sys.argv) > 2 else "http://10.0.0.1:18080/healthcheck"
xs = []
oks = 0
for _ in range(n):
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=2) as r:
            st = r.status
        ms = (time.monotonic() - t0) * 1000.0
        xs.append(ms)
        if st == 200:
            oks += 1
    except Exception:
        xs.append(2000.0)
    time.sleep(0.02)
xs.sort()
out = {
    "n": len(xs),
    "ok": oks,
    "p50_ms": xs[len(xs) // 2] if xs else None,
    "p99_ms": xs[int((len(xs) - 1) * 0.99)] if xs else None,
    "min_ms": xs[0] if xs else None,
    "max_ms": xs[-1] if xs else None,
}
print(json.dumps(out))
