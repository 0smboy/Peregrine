#!/usr/bin/env python3
"""Wave 0B: seed objects, DELETE (create .ts), sample tombstone metrics over ~14m."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

AUTH_URL = os.environ.get("SWIFT_AUTH_URL", "http://10.0.0.10:8085/auth/v1.0")
USER = os.environ.get("ST_USER", "test:tester")
KEY = os.environ.get("ST_KEY", "azure-swift-2026.bench")
CONTAINER = os.environ.get("WAVE0_TS_CONTAINER", "wave0-tombstone-lab")
N = int(os.environ.get("WAVE0_TS_OBJECTS", "200"))
BODY = b"wave0-tombstone-payload-" + (b"x" * 256)
BIN = os.environ.get("SWIFT_RECON", "/usr/local/bin/swift-recon")


def http(method, url, headers=None, body=None, timeout=60):
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def auth():
    st, h, _ = http("GET", AUTH_URL, {"X-Auth-User": USER, "X-Auth-Key": KEY})
    if st != 200:
        raise SystemExit(f"auth {st}")
    return h.get("X-Auth-Token") or h.get("x-auth-token"), h.get(
        "X-Storage-Url"
    ) or h.get("x-storage-url")


def count_ts_recon():
    try:
        out = subprocess.check_output(
            [BIN, "tombstones", "/srv/node"], text=True, timeout=180
        )
        for line in out.splitlines():
            if line.startswith("total_count"):
                return int(line.split("\t")[1]), out
        return -1, out
    except Exception as e:
        return -1, str(e)


def main():
    token, storage = auth()
    base = storage.rstrip("/") + "/" + urllib.parse.quote(CONTAINER)
    print(f"seed N={N} container={CONTAINER}", flush=True)
    http("PUT", base, {"X-Auth-Token": token, "Content-Length": "0"})
    for i in range(N):
        url = base + "/" + urllib.parse.quote(f"obj-{i:05d}")
        st, _, _ = http(
            "PUT",
            url,
            {"X-Auth-Token": token, "Content-Type": "application/octet-stream"},
            BODY,
        )
        if st not in (201, 202):
            print(f"PUT fail {i} -> {st}", flush=True)
            sys.exit(2)
    print("seeded", flush=True)
    t0 = time.time()
    before, before_raw = count_ts_recon()
    print(f"ts_before_delete={before}", flush=True)
    for i in range(N):
        url = base + "/" + urllib.parse.quote(f"obj-{i:05d}")
        st, _, _ = http("DELETE", url, {"X-Auth-Token": token})
        if st not in (204, 404):
            print(f"DELETE fail {i} -> {st}", flush=True)
    # leave container until end
    after_del, after_raw = count_ts_recon()
    print(f"ts_after_delete={after_del}", flush=True)
    samples = [
        {
            "t_rel_sec": 0.0,
            "ts_local": after_del,
            "phase": "after_delete",
            "epoch": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    ]
    deadline = t0 + int(os.environ.get("WAVE0_TS_WAIT_SEC", "840"))
    while time.time() < deadline:
        time.sleep(60)
        n, _ = count_ts_recon()
        sample = {
            "t_rel_sec": round(time.time() - t0, 1),
            "ts_local": n,
            "phase": "wait",
            "epoch": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        samples.append(sample)
        print(json.dumps(sample), flush=True)
    http("DELETE", base, {"X-Auth-Token": token})
    out = {
        "container": CONTAINER,
        "n": N,
        "ts_before_delete_local": before,
        "ts_after_delete_local": after_del,
        "samples": samples,
        "before_raw": before_raw,
        "after_delete_raw": after_raw,
    }
    path = os.environ.get("WAVE0_TS_OUT", "/tmp/wave0_tombstone_experiment.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print("wrote", path, flush=True)
    print(json.dumps({k: out[k] for k in out if k not in ("before_raw", "after_delete_raw")}, indent=2))


if __name__ == "__main__":
    main()
