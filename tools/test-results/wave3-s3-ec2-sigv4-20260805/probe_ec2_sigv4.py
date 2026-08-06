#!/usr/bin/env python3
"""VIP S3 SigV4 PUT/GET with Keystone EC2 credentials (post s3api deferral)."""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

VIP = "https://10.0.0.10:8085"
REGION = "us-east-1"  # Rust s3api default location unless filter overrides
SERVICE = "s3"
CTX = ssl._create_unverified_context()

cred = json.loads(Path("/root/contabo-s3-ec2-tester.json").read_text())
ACCESS = cred["access"]
SECRET = cred["secret"]
PROJECT = cred.get("project_id", "")
print("access", ACCESS[:16], "project", PROJECT[:16] if PROJECT else "?")


def _sign(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def signing_key(secret: str, date: str, region: str, service: str) -> bytes:
    k_date = _sign(("AWS4" + secret).encode(), date.encode())
    k_region = _sign(k_date, region.encode())
    k_service = _sign(k_region, service.encode())
    return _sign(k_service, b"aws4_request")


def sigv4_request(
    method: str,
    path: str,
    body: bytes = b"",
    extra_headers: dict | None = None,
    amz_content_sha256: str | None = None,
) -> tuple[int, dict, bytes]:
    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    host = "10.0.0.10:8085"
    payload_hash = amz_content_sha256 or hashlib.sha256(body).hexdigest()
    headers = {
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Content-SHA256": payload_hash,
    }
    if extra_headers:
        headers.update(extra_headers)
    # Canonical headers: host + x-amz-* sorted
    signed_header_names = sorted(k.lower() for k in headers)
    canonical_headers = "".join(
        f"{k}:{headers[[h for h in headers if h.lower() == k][0]].strip()}\n"
        for k in signed_header_names
    )
    signed_headers = ";".join(signed_header_names)
    canonical_request = (
        f"{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    scope = f"{date_stamp}/{REGION}/{SERVICE}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )
    key = signing_key(SECRET, date_stamp, REGION, SERVICE)
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = (
        f"AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    headers["Authorization"] = auth
    url = VIP + path
    req = urllib.request.Request(url, data=body if method in ("PUT", "POST") else None, method=method)
    for k, v in headers.items():
        if k == "Host":
            continue
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30, context=CTX) as resp:
            return resp.status, dict(resp.headers.items()), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()) if e.headers else {}, e.read()


# Probe region from filter if present via a signed ListBuckets first with us-east-1,
# then retry RegionOne if needed.
def try_regions():
    global REGION
    for region in ("us-east-1", "RegionOne", "us-east-1"):
        REGION = region
        code, _, body = sigv4_request("GET", "/")
        print(f"ListBuckets region={region} HTTP {code} body={body[:160]!r}")
        if code == 200:
            return True
        if code != 403:
            # unexpected — keep trying
            continue
        if b"InvalidAccessKeyId" in body:
            print("STILL InvalidAccessKeyId — deferral not live on VIP path")
            return False
        if b"SignatureDoesNotMatch" in body:
            continue
    return False


if not try_regions():
    # one more dump
    code, hdrs, body = sigv4_request("GET", "/")
    print("FINAL ListBuckets", code, body[:300])
    raise SystemExit(2)

bucket = "ec2-sigv4-wave3"
key = "hello.txt"
payload = b"ec2-sigv4-put-get-ok"

# Create bucket
code, _, body = sigv4_request("PUT", f"/{bucket}")
print(f"CreateBucket HTTP {code} body={body[:120]!r}")

# PUT object
code, hdrs, body = sigv4_request("PUT", f"/{bucket}/{key}", body=payload)
print(f"PutObject HTTP {code} etag={hdrs.get('ETag') or hdrs.get('etag')} body={body[:80]!r}")
put_ok = code in (200, 201)

# GET object
code, _, body = sigv4_request("GET", f"/{bucket}/{key}")
print(f"GetObject HTTP {code} body={body!r}")
get_ok = code == 200 and body == payload

# cleanup best-effort
code_d, _, _ = sigv4_request("DELETE", f"/{bucket}/{key}")
code_b, _, _ = sigv4_request("DELETE", f"/{bucket}")
print(f"cleanup delobj={code_d} delbucket={code_b}")

verdict = "GREEN" if put_ok and get_ok else "FAIL"
print(f"VERDICT {verdict} region={REGION}")
raise SystemExit(0 if verdict == "GREEN" else 1)
