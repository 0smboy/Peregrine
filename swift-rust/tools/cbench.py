#!/usr/bin/env python3
"""Locate the write bottleneck: PUT small objects spread across N containers at
a fixed concurrency and report throughput. If ops/s rises sharply with more
containers, the limiter is per-container serialization (pending-file lock /
container DB); if flat, it's a global limit (container-server workers / disk).

  cbench.py <endpoint> <user> <key> <containers> <concurrency> <count>
"""
import sys, time, threading, random
from concurrent.futures import ThreadPoolExecutor
import requests

EP, USR, KEY = sys.argv[1], sys.argv[2], sys.argv[3]
NC, CONC, N = int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])

r = requests.get(f"{EP}/auth/v1.0", headers={"X-Auth-User": USR, "X-Auth-Key": KEY}, timeout=20)
r.raise_for_status()
TOK = r.headers["x-auth-token"]
sp = r.headers["x-storage-url"].split("//", 1)[1]
BASE = EP + "/" + sp.split("/", 1)[1]
H = {"X-Auth-Token": TOK}

pfx = f"cb{random.randint(0,1<<20)}"
conts = [f"{pfx}-{i}" for i in range(NC)]
for c in conts:
    requests.put(f"{BASE}/{c}", headers=H, timeout=20)

_tl = threading.local()
def sess():
    s = getattr(_tl, "s", None)
    if s is None:
        s = _tl.s = requests.Session()
    return s

blob = b"x" * 4096
errs = [0]
def one(i):
    c = conts[i % NC]
    try:
        resp = sess().put(f"{BASE}/{c}/o-{i}", headers=H, data=blob, timeout=60)
        if resp.status_code != 201:
            errs[0] += 1
    except Exception:
        errs[0] += 1

t0 = time.time()
with ThreadPoolExecutor(max_workers=CONC) as ex:
    list(ex.map(one, range(N)))
wall = time.time() - t0
print(f"containers={NC:3d} conc={CONC} count={N}  ->  {N/wall:8.1f} PUT/s  ({wall:.1f}s, errs={errs[0]})")

# cleanup
def dele(i):
    try: sess().delete(f"{BASE}/{conts[i % NC]}/o-{i}", headers=H, timeout=30)
    except Exception: pass
with ThreadPoolExecutor(max_workers=32) as ex:
    list(ex.map(dele, range(N)))
for c in conts:
    requests.delete(f"{BASE}/{c}", headers=H, timeout=20)
