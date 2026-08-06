#!/usr/bin/env python3
"""Delete only containers that still HEAD 200 (skip stale account ghosts)."""
from __future__ import annotations

import concurrent.futures
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

AUTH_URL = os.environ.get("SWIFT_AUTH_URL", "http://10.0.0.10:8085/auth/v1.0")
USER = os.environ.get("ST_USER", "test:tester")
KEY = os.environ.get("ST_KEY", "azure-swift-2026.bench")
WORKERS = int(os.environ.get("WAVE0_DELETE_WORKERS", "64"))


def http(method, url, headers=None, timeout=60):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def auth():
    st, h, _ = http("GET", AUTH_URL, {"X-Auth-User": USER, "X-Auth-Key": KEY})
    token = h.get("X-Auth-Token") or h.get("x-auth-token")
    storage = h.get("X-Storage-Url") or h.get("x-storage-url")
    return token, storage


def list_containers(token, storage):
    out, marker = [], ""
    while True:
        q = "?format=json&limit=10000"
        if marker:
            q += "&marker=" + urllib.parse.quote(marker)
        st, _, body = http("GET", storage + q, {"X-Auth-Token": token})
        if st != 200 or not body:
            break
        items = json.loads(body.decode())
        if not items:
            break
        out.extend(items)
        marker = items[-1]["name"]
    return out


def list_objects(token, storage, container):
    out, marker = [], ""
    base = storage.rstrip("/") + "/" + urllib.parse.quote(container)
    while True:
        q = "?format=json&limit=10000"
        if marker:
            q += "&marker=" + urllib.parse.quote(marker)
        st, _, body = http("GET", base + q, {"X-Auth-Token": token})
        if st in (204, 404) or not body:
            break
        if st != 200:
            break
        try:
            items = json.loads(body.decode())
        except json.JSONDecodeError:
            break
        if not items:
            break
        out.extend(it["name"] for it in items)
        marker = items[-1]["name"]
    return out


def main():
    token, storage = auth()
    ctrs = list_containers(token, storage)
    live, gone, deleted_objs, deleted_ctrs = [], 0, 0, 0
    for c in ctrs:
        name = c["name"]
        st, _, _ = http(
            "HEAD",
            storage.rstrip("/") + "/" + urllib.parse.quote(name),
            {"X-Auth-Token": token},
        )
        if st == 404:
            gone += 1
            continue
        if st != 204 and st != 200:
            print(f"skip {name} HEAD {st}", flush=True)
            continue
        live.append(name)
    print(f"account_listed={len(ctrs)} live={len(live)} gone_404={gone}", flush=True)
    for name in live:
        objs = list_objects(token, storage, name)
        print(f"delete live {name!r} objects={len(objs)}", flush=True)
        if objs:
            with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
                futs = []
                for o in objs:
                    url = (
                        storage.rstrip("/")
                        + "/"
                        + urllib.parse.quote(name)
                        + "/"
                        + urllib.parse.quote(o)
                    )
                    futs.append(
                        pool.submit(http, "DELETE", url, {"X-Auth-Token": token})
                    )
                for f in concurrent.futures.as_completed(futs):
                    st, _, _ = f.result()
                    if st in (204, 404):
                        deleted_objs += 1
        for _ in range(6):
            st, _, _ = http(
                "DELETE",
                storage.rstrip("/") + "/" + urllib.parse.quote(name),
                {"X-Auth-Token": token},
            )
            if st in (204, 404):
                deleted_ctrs += 1
                break
            time.sleep(0.5)
    # recount live
    still = 0
    for c in list_containers(token, storage):
        st, _, _ = http(
            "HEAD",
            storage.rstrip("/") + "/" + urllib.parse.quote(c["name"]),
            {"X-Auth-Token": token},
        )
        if st in (200, 204):
            still += 1
    summary = {
        "deleted_objs": deleted_objs,
        "deleted_ctrs": deleted_ctrs,
        "still_live_containers": still,
        "stale_account_ghosts": gone,
    }
    print(json.dumps(summary, indent=2))
    if still:
        sys.exit(2)


if __name__ == "__main__":
    main()
