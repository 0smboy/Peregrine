#!/usr/bin/env python3
"""Concurrent Swift benchmark: PUT then GET a batch of objects at a target
concurrency, for a matrix of object sizes. Reports throughput (ops/s, MB/s) and
latency percentiles. Same script runs against Rust and Python stacks for an A/B.

  bench.py <endpoint> <user> <key> <label> [policy]
"""
import sys, os, time, threading, statistics, random
from concurrent.futures import ThreadPoolExecutor
import requests

EP, USR, KEY, LABEL = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
POLICY = sys.argv[5] if len(sys.argv) > 5 else None

# ---- auth (v1.0), rewrite storage host to EP ----
r = requests.get(f"{EP}/auth/v1.0", headers={"X-Auth-User": USR, "X-Auth-Key": KEY}, timeout=20)
r.raise_for_status()
TOK = r.headers["x-auth-token"]
sp = r.headers["x-storage-url"].split("//", 1)[1]
PATH = "/" + sp.split("/", 1)[1]
BASE = EP + PATH
H = {"X-Auth-Token": TOK}

CT = f"bench-{LABEL}-{POLICY or 'repl'}"
ch = dict(H)
if POLICY:
    ch["X-Storage-Policy"] = POLICY
requests.put(f"{BASE}/{CT}", headers=ch, timeout=20)

_tl = threading.local()
def sess():
    s = getattr(_tl, "s", None)
    if s is None:
        s = _tl.s = requests.Session()
    return s

def pctl(xs, p):
    xs = sorted(xs); k = (len(xs)-1)*p/100.0
    f = int(k); c = min(f+1, len(xs)-1)
    return xs[f] + (xs[c]-xs[f])*(k-f)

def run_phase(names, size, conc, kind, blob):
    lat = [0.0]*len(names); errs = [0]
    def one(i):
        u = f"{BASE}/{CT}/{names[i]}"
        t0 = time.time()
        try:
            if kind == "PUT":
                resp = sess().put(u, headers=H, data=blob, timeout=120)
                okc = (201,)
            else:
                resp = sess().get(u, headers=H, timeout=120); _ = resp.content
                okc = (200,)
            if resp.status_code not in okc: errs[0]+=1
        except Exception:
            errs[0]+=1
        lat[i] = (time.time()-t0)*1000.0
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=conc) as ex:
        list(ex.map(one, range(len(names))))
    wall = time.time()-t0
    ops = len(names)/wall
    mbps = len(names)*size/1e6/wall
    return dict(kind=kind, ops=ops, mbps=mbps, wall=wall, errs=errs[0],
                p50=pctl(lat,50), p95=pctl(lat,95), p99=pctl(lat,99))

# size(bytes), count, concurrency
MATRIX = [
    (1024,        500,  1),
    (1024,        3000, 32),
    (1024,        3000, 64),
    (1024*1024,   200,  1),
    (1024*1024,   600,  32),
    (16*1024*1024,40,   8),
]
print(f"{'='*96}", flush=True)
print(f"BENCH  label={LABEL}  endpoint={EP}  policy={POLICY or 'repl(0)'}  {time.strftime('%FT%TZ', time.gmtime())}", flush=True)
print(f"{'size':>10} {'conc':>5} {'op':>4} {'ops/s':>9} {'MB/s':>8} {'p50ms':>8} {'p95ms':>8} {'p99ms':>8} {'err':>4}", flush=True)
for size, count, conc in MATRIX:
    blob = os.urandom(size)
    names = [f"o-{size}-{conc}-{i}-{random.randint(0,1<<30)}" for i in range(count)]
    for kind in ("PUT", "GET"):
        s = run_phase(names, size, conc, kind, blob)
        hz = f"{size//1024}K" if size < 1024*1024 else f"{size//(1024*1024)}M"
        print(f"{hz:>10} {conc:>5} {s['kind']:>4} {s['ops']:>9.1f} {s['mbps']:>8.1f} "
              f"{s['p50']:>8.1f} {s['p95']:>8.1f} {s['p99']:>8.1f} {s['errs']:>4}", flush=True)
    # cleanup this batch
    def dele(n):
        try: sess().delete(f"{BASE}/{CT}/{n}", headers=H, timeout=30)
        except Exception: pass
    with ThreadPoolExecutor(max_workers=32) as ex:
        list(ex.map(dele, names))
requests.delete(f"{BASE}/{CT}", headers=H, timeout=20)
print("BENCH-DONE", LABEL)
