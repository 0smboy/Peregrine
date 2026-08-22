#!/usr/bin/env python3
"""Live RSAIO :8081 G3 counter probe for S3 GET/HEAD/List/MPU/versioned PUT.

Run on swift2 against 127.0.0.1:8081. Does not touch :8080.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

HOST = "127.0.0.1:8081"
BASE = f"http://{HOST}"
ACCESS = "test:tester"
SECRET = "315602f1a99efa2671b6fbd0d5eb37cf1e479ea26ffc3d80d4cc5aaa30facfcd"
REGION = "us-east-1"
SERVICE = "s3"


def recon() -> dict[str, float]:
    text = urllib.request.urlopen(f"{BASE}/recon/concurrency", timeout=5).read().decode()
    out: dict[str, float] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(
            r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+([-+0-9.eE]+)\s*$',
            line,
        )
        if not m:
            continue
        name, labels, value = m.group(1), m.group(2) or "", float(m.group(3))
        out[name] = value
        if labels:
            out[f"{name}{{{labels}}}"] = value
    return out


def g3(samples: dict[str, float]) -> dict[str, float]:
    def grab(*keys: str) -> float:
        for k in keys:
            if k in samples:
                return float(samples[k])
        return 0.0

    return {
        "native_async_requests_total": grab("native_async_requests_total"),
        "legacy_sync_handler_requests_total": grab("legacy_sync_handler_requests_total"),
        "block_in_place_total": grab("block_in_place_total"),
        "blocking_network_wait_total": grab("blocking_network_wait_total"),
        "http_requests_total_hyper": grab(
            'http_requests_total{engine="hyper"}', "http_requests_total"
        ),
    }


def sign(method: str, path: str, query: str, headers: dict[str, str], body: bytes) -> dict[str, str]:
    now = datetime.now(timezone.utc)
    amz = now.strftime("%Y%m%dT%H%M%SZ")
    stamp = now.strftime("%Y%m%d")
    payload = "UNSIGNED-PAYLOAD"
    out = dict(headers)
    out["Host"] = HOST
    out["X-Amz-Date"] = amz
    out["X-Amz-Content-SHA256"] = payload
    signed_names = sorted(
        n.lower()
        for n in out
        if n.lower() == "host" or n.lower().startswith("x-amz-") or n.lower() in ("content-type", "range")
    )
    lower = {k.lower(): " ".join(v.strip().split()) for k, v in out.items()}
    canonical_headers = "".join(f"{n}:{lower[n]}\n" for n in signed_names)
    signed_headers = ";".join(signed_names)
    canonical_query = ""
    if query:
        parts = []
        for item in query.split("&"):
            if "=" in item:
                k, v = item.split("=", 1)
            else:
                k, v = item, ""
            parts.append((k, v))
        parts.sort()
        canonical_query = "&".join(f"{k}={v}" for k, v in parts)
    canonical = "\n".join(
        [method, path, canonical_query, canonical_headers, signed_headers, payload]
    )
    scope = f"{stamp}/{REGION}/{SERVICE}/aws4_request"
    sts = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz,
            scope,
            hashlib.sha256(canonical.encode()).hexdigest(),
        ]
    )

    def hmk(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k = hmk(("AWS4" + SECRET).encode(), stamp)
    k = hmac.new(k, REGION.encode(), hashlib.sha256).digest()
    k = hmac.new(k, SERVICE.encode(), hashlib.sha256).digest()
    k = hmac.new(k, b"aws4_request", hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    out["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={sig}"
    )
    return out


def request(
    method: str, path: str, query: str = "", body: bytes = b"", extra: dict[str, str] | None = None
) -> tuple[int, dict[str, str], bytes]:
    headers = sign(method, path, query, extra or {}, body)
    url = BASE + path
    if query:
        url += "?" + query
    req = urllib.request.Request(url, data=body if method in ("PUT", "POST") else None, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    if body and method in ("PUT", "POST"):
        req.add_header("Content-Length", str(len(body)))
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
            rh = {k: v for k, v in resp.headers.items()}
            return resp.status, rh, data
    except urllib.error.HTTPError as e:
        data = e.read()
        rh = {k: v for k, v in e.headers.items()}
        return e.code, rh, data


def evaluate(delta: dict[str, float], path: str) -> dict[str, Any]:
    native = delta.get("native_async_requests_total", 0)
    legacy = delta.get("legacy_sync_handler_requests_total", 0)
    bip = delta.get("block_in_place_total", 0)
    net = delta.get("blocking_network_wait_total", 0)
    reasons = []
    if native <= 0:
        reasons.append("native_async_requests_total did not increase")
    if legacy > 0:
        reasons.append(f"legacy={legacy}")
    if bip > 0:
        reasons.append(f"block_in_place={bip}")
    if net > 0:
        reasons.append(f"blocking_network_wait={net}")
    return {
        "path": path,
        "result": "GREEN" if not reasons else "NO-GO",
        "reasons": reasons,
        "delta": delta,
    }


def probe(name: str, fn) -> dict[str, Any]:
    before = g3(recon())
    status, headers, body = fn()
    after = g3(recon())
    delta = {k: after.get(k, 0) - before.get(k, 0) for k in set(before) | set(after)}
    trans = (
        headers.get("X-Trans-Id")
        or headers.get("x-trans-id")
        or headers.get("x-amz-id-2")
        or headers.get("x-amz-request-id")
        or headers.get("X-Amz-Request-Id")
        or ""
    )
    ev = evaluate(delta, name)
    ev.update(
        {
            "status": status,
            "trans_id": trans,
            "amz_request_id": headers.get("x-amz-request-id") or headers.get("X-Amz-Request-Id"),
            "body_head": body[:180].decode("utf-8", "replace"),
            "before": before,
            "after": after,
        }
    )
    return ev


def main() -> int:
    stamp = str(int(time.time()))
    bucket = f"g3s4-{stamp}"
    key = "obj1"
    results: list[dict[str, Any]] = []

    def put_small():
        return request("PUT", f"/{bucket}/{key}", body=b"hello-s3-4")

    def get_obj():
        return request("GET", f"/{bucket}/{key}")

    def head_obj():
        return request("HEAD", f"/{bucket}/{key}")

    def list_obj():
        return request("GET", f"/{bucket}")

    def list_buckets():
        return request("GET", "/")

    # bucket + object first (streaming PUT already proven; still needed as fixture)
    st, _, _ = request("PUT", f"/{bucket}")
    if st not in (200, 201, 409):
        # CreateBucket 200; already owned 409
        pass
    results.append(probe("s3-put-fixture", put_small))
    results.append(probe("s3-get", get_obj))
    results.append(probe("s3-head", head_obj))
    results.append(probe("s3-list-objects", list_obj))
    results.append(probe("s3-list-buckets", list_buckets))

    # MPU init / complete / abort
    def mpu_init():
        return request("POST", f"/{bucket}/mpu-obj", query="uploads")

    init = probe("s3-mpu-init", mpu_init)
    results.append(init)
    uid = ""
    m = re.search(r"<UploadId>([^<]+)</UploadId>", init.get("body_head") or "")
    if m:
        uid = m.group(1)
    if uid:
        part_body = b"part-one-data"
        st, hdrs, _ = request(
            "PUT",
            f"/{bucket}/mpu-obj",
            query=f"partNumber=1&uploadId={uid}",
            body=part_body,
        )
        etag = (hdrs.get("ETag") or hdrs.get("etag") or "part-one-data").strip('"')
        xml = (
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
            f"<ETag>\"{etag}\"</ETag></Part></CompleteMultipartUpload>"
        ).encode()

        def mpu_complete():
            return request(
                "POST",
                f"/{bucket}/mpu-obj",
                query=f"uploadId={uid}",
                body=xml,
                extra={"Content-Type": "application/xml"},
            )

        results.append(probe("s3-mpu-complete", mpu_complete))

        init2 = request("POST", f"/{bucket}/mpu-abort", query="uploads")
        uid2 = ""
        if init2[0] == 200:
            m2 = re.search(rb"<UploadId>([^<]+)</UploadId>", init2[2])
            if m2:
                uid2 = m2.group(1).decode()

        def mpu_abort():
            return request("DELETE", f"/{bucket}/mpu-abort", query=f"uploadId={uid2 or uid}")

        results.append(probe("s3-mpu-abort", mpu_abort))

    # versioned PUT (enable versioning, then stream a >1MiB body)
    xml_v = b"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>"
    request("PUT", f"/{bucket}", query="versioning", body=xml_v, extra={"Content-Type": "application/xml"})
    vbody = (b"v" * (128 * 1024))

    def versioned_put():
        return request("PUT", f"/{bucket}/ver-obj", body=vbody)

    results.append(probe("s3-versioned-put", versioned_put))

    green = all(r["result"] == "GREEN" and 200 <= r["status"] < 300 for r in results)
    report = {
        "bucket": bucket,
        "proxy_probe_host": HOST,
        "overall": "GREEN" if green else "NO-GO",
        "results": results,
    }
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if green else 1


if __name__ == "__main__":
    raise SystemExit(main())
