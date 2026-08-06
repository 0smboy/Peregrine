#!/usr/bin/env python3
import json
import os
import urllib.parse
import urllib.request

AUTH = os.environ.get("SWIFT_AUTH_URL", "http://10.0.0.10:8085/auth/v1.0")
USER = os.environ.get("ST_USER", "test:tester")
KEY = os.environ.get("ST_KEY", "azure-swift-2026.bench")

req = urllib.request.Request(
    AUTH, headers={"X-Auth-User": USER, "X-Auth-Key": KEY}
)
with urllib.request.urlopen(req, timeout=30) as r:
    token = r.headers.get("X-Auth-Token")
    storage = r.headers.get("X-Storage-Url")
print("storage", storage)

req = urllib.request.Request(storage, method="HEAD", headers={"X-Auth-Token": token})
with urllib.request.urlopen(req, timeout=30) as r:
    h = {k.lower(): v for k, v in r.headers.items()}
    for k in sorted(h):
        if k.startswith("x-account"):
            print(k, h[k])

marker = ""
ctrs = []
while True:
    q = "?format=json&limit=1000"
    if marker:
        q += "&marker=" + urllib.parse.quote(marker)
    req = urllib.request.Request(storage + q, headers={"X-Auth-Token": token})
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read()
    items = json.loads(body) if body else []
    if not items:
        break
    ctrs.extend(items)
    marker = items[-1]["name"]

objs = sum(int(c.get("count", 0)) for c in ctrs)
bytes_ = sum(int(c.get("bytes", 0)) for c in ctrs)
print("containers_listed", len(ctrs))
print("objects_sum", objs)
print("bytes_sum", bytes_)
top = sorted(ctrs, key=lambda c: int(c.get("count", 0)), reverse=True)[:15]
for c in top:
    name = c["name"]
    print(f"  {name!r} count={c.get('count')} bytes={c.get('bytes')}")
