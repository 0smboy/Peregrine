#!/usr/bin/env python3
"""Write-only benchmark with latency percentiles.
  wbench.py <endpoint> <user> <key> <containers> <concurrency> <count> <size>
"""
import sys, time, threading, random
from concurrent.futures import ThreadPoolExecutor
import requests

EP, USR, KEY = sys.argv[1], sys.argv[2], sys.argv[3]
NC, CONC, N, SZ = int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]), int(sys.argv[7])

r = requests.get(f"{EP}/auth/v1.0", headers={"X-Auth-User": USR, "X-Auth-Key": KEY}, timeout=20)
r.raise_for_status()
TOK = r.headers["x-auth-token"]
sp = r.headers["x-storage-url"].split("//", 1)[1]
BASE = EP + "/" + sp.split("/", 1)[1]
H = {"X-Auth-Token": TOK}
pfx = f"wb{random.randint(0,1<<20)}"
conts = [f"{pfx}-{i}" for i in range(NC)]
for c in conts:
    requests.put(f"{BASE}/{c}", headers=H, timeout=20)

_tl = threading.local()
def sess():
    s = getattr(_tl, "s", None)
    if s is None: s = _tl.s = requests.Session()
    return s
blob = b"x" * SZ
lat = [0.0]*N; errs=[0]
def one(i):
    t0=time.time()
    try:
        resp=sess().put(f"{BASE}/{conts[i%NC]}/o-{i}", headers=H, data=blob, timeout=60)
        if resp.status_code!=201: errs[0]+=1
    except Exception: errs[0]+=1
    lat[i]=(time.time()-t0)*1000.0
t0=time.time()
with ThreadPoolExecutor(max_workers=CONC) as ex: list(ex.map(one, range(N)))
wall=time.time()-t0
def pctl(p):
    xs=sorted(lat); k=(len(xs)-1)*p/100.0; f=int(k); c=min(f+1,len(xs)-1)
    return xs[f]+(xs[c]-xs[f])*(k-f)
print(f"  {N/wall:8.1f} PUT/s  p50={pctl(50):7.1f}ms p95={pctl(95):8.1f}ms p99={pctl(99):8.1f}ms  errs={errs[0]}")
def dele(i):
    try: sess().delete(f"{BASE}/{conts[i%NC]}/o-{i}", headers=H, timeout=30)
    except Exception: pass
with ThreadPoolExecutor(max_workers=32) as ex: list(ex.map(dele, range(N)))
for c in conts: requests.delete(f"{BASE}/{c}", headers=H, timeout=20)
