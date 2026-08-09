#!/usr/bin/env python3
"""Wave 0A: API clear via Swift REST (equivalent of `swift delete -a`).

No mkfs / destructive-reset / wipe of /srv/node.
Parallel object DELETEs; run on-cluster (VIP often blocked from laptops).
"""
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
KEY = os.environ.get("ST_KEY", "PEREGRINE_LAB_KEY_REQUIRED")
WORKERS = int(os.environ.get("WAVE0_DELETE_WORKERS", "64"))
EXTRA_STORAGE = [
    u.strip()
    for u in os.environ.get("SWIFT_EXTRA_STORAGE_URLS", "").split(",")
    if u.strip()
]


def http(method: str, url: str, headers: dict | None = None, timeout=120):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
    except Exception as e:
        return 0, {}, str(e).encode()


def auth():
    status, hdrs, _ = http(
        "GET",
        AUTH_URL,
        {"X-Auth-User": USER, "X-Auth-Key": KEY},
        timeout=30,
    )
    if status != 200:
        raise SystemExit(f"auth failed HTTP {status}")
    token = hdrs.get("X-Auth-Token") or hdrs.get("x-auth-token")
    storage = hdrs.get("X-Storage-Url") or hdrs.get("x-storage-url")
    if not token or not storage:
        raise SystemExit(f"auth missing token/url headers: {hdrs}")
    return token, storage


def list_containers(token: str, storage: str) -> list[dict]:
    out: list[dict] = []
    marker = ""
    while True:
        q = "?format=json&limit=10000"
        if marker:
            q += "&marker=" + urllib.parse.quote(marker)
        status, _, body = http("GET", storage + q, {"X-Auth-Token": token})
        if status == 204 or (status == 200 and not body):
            break
        if status != 200:
            raise SystemExit(f"list containers HTTP {status}: {body[:200]!r}")
        try:
            items = json.loads(body.decode())
        except json.JSONDecodeError:
            raise SystemExit(f"list containers non-json: {body[:200]!r}")
        if not items:
            break
        out.extend(items)
        marker = items[-1]["name"]
    return out


def parse_listing(body: bytes):
    if not body or not body.strip():
        return []
    text = body.decode(errors="replace").strip()
    if not text:
        return []
    if text[0] in "[{":
        data = json.loads(text)
        if isinstance(data, list):
            return data
        return []
    # plain text listing
    return [{"name": line} for line in text.splitlines() if line]


def list_objects(token: str, storage: str, container: str) -> list[str]:
    out: list[str] = []
    marker = ""
    base = storage.rstrip("/") + "/" + urllib.parse.quote(container)
    for _attempt in range(3):
        try:
            while True:
                q = "?format=json&limit=10000"
                if marker:
                    q += "&marker=" + urllib.parse.quote(marker)
                status, _, body = http("GET", base + q, {"X-Auth-Token": token})
                if status in (204, 404, 0):
                    return out
                if status != 200:
                    time.sleep(0.3)
                    break
                items = parse_listing(body)
                if not items:
                    return out
                for it in items:
                    if isinstance(it, dict) and "name" in it:
                        out.append(it["name"])
                    elif isinstance(it, str):
                        out.append(it)
                marker = out[-1]
            else:
                return out
        except json.JSONDecodeError:
            time.sleep(0.5)
            continue
    return out


def delete_object(token: str, storage: str, container: str, obj: str) -> int:
    url = (
        storage.rstrip("/")
        + "/"
        + urllib.parse.quote(container)
        + "/"
        + urllib.parse.quote(obj)
    )
    status, _, _ = http("DELETE", url, {"X-Auth-Token": token}, timeout=60)
    return status


def delete_container(token: str, storage: str, container: str) -> int:
    url = storage.rstrip("/") + "/" + urllib.parse.quote(container)
    status, _, _ = http("DELETE", url, {"X-Auth-Token": token}, timeout=60)
    return status


def clear_account(token: str, storage: str, log) -> dict:
    t0 = time.time()
    containers = list_containers(token, storage)
    log(f"account {storage}: {len(containers)} containers")
    deleted_objs = 0
    deleted_ctrs = 0
    errors: list[str] = []
    for i, cinfo in enumerate(containers):
        c = cinfo["name"]
        expected = int(cinfo.get("count", 0))
        try:
            objs = list_objects(token, storage, c)
        except Exception as e:
            errors.append(f"list {c}: {e}")
            objs = []
            log(f"[{i+1}/{len(containers)}] container {c!r}: LIST_ERR {e}")
        else:
            log(
                f"[{i+1}/{len(containers)}] container {c!r}: listed={len(objs)} expected~{expected}"
            )
        if objs:
            with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
                futs = [pool.submit(delete_object, token, storage, c, o) for o in objs]
                for fut in concurrent.futures.as_completed(futs):
                    try:
                        st = fut.result()
                    except Exception as e:
                        errors.append(f"DELETE obj {c}: {e}")
                        continue
                    if st in (204, 404):
                        deleted_objs += 1
                    else:
                        errors.append(f"DELETE obj {c} -> {st}")
        for attempt in range(8):
            st = delete_container(token, storage, c)
            if st in (204, 404):
                deleted_ctrs += 1
                break
            if st == 409:
                time.sleep(0.4 * (attempt + 1))
                leftovers = list_objects(token, storage, c)
                if leftovers:
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=WORKERS
                    ) as pool:
                        list(
                            pool.map(
                                lambda o: delete_object(token, storage, c, o),
                                leftovers,
                            )
                        )
                        deleted_objs += len(leftovers)
                continue
            errors.append(f"DELETE container {c} -> {st}")
            break
    elapsed = time.time() - t0
    remaining = [c["name"] for c in list_containers(token, storage)]
    return {
        "storage": storage,
        "containers_seen": len(containers),
        "objects_deleted": deleted_objs,
        "containers_deleted": deleted_ctrs,
        "remaining_containers": remaining,
        "errors": errors[:50],
        "error_count": len(errors),
        "elapsed_sec": round(elapsed, 2),
        "workers": WORKERS,
    }


def main():
    def log(m):
        print(m, flush=True)

    token, storage = auth()
    log(f"auth ok storage={storage} workers={WORKERS}")
    results = [clear_account(token, storage, log)]
    for extra in EXTRA_STORAGE:
        results.append(clear_account(token, extra, log))
    summary = {
        "auth_url": AUTH_URL,
        "user": USER,
        "results": results,
        "all_empty": all(not r["remaining_containers"] for r in results),
    }
    print(json.dumps(summary, indent=2))
    # exit 0 if account listing empty even with soft errors
    if not summary["all_empty"]:
        sys.exit(2)


if __name__ == "__main__":
    main()
