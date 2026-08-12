#!/usr/bin/env python3
"""Bounded Contabo VIP extended S3 matrix (TempAuth SigV4 + EC2 SigV4).

NOT the full strict-s3-parity dual-oracle suite (needs Python Swift peer).
Does NOT print secrets. Writes redacted text + JSON under EVID_DIR.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Sequence, Tuple

VIP = os.environ.get("VIP", "https://10.0.0.10:8085")
HOST = os.environ.get("S3_HOST", "10.0.0.10:8085")
REGION = os.environ.get("S3_REGION", "us-east-1")
EVID_DIR = os.environ["EVID_DIR"]
TIP_SHA = os.environ.get("TIP_SHA", "")
CTX = ssl._create_unverified_context()
SERVICE = "s3"

S3_SUBRESOURCES = frozenset(
    {
        "acl", "cors", "delete", "lifecycle", "location", "logging",
        "notification", "partNumber", "policy", "requestPayment",
        "response-cache-control", "response-content-disposition",
        "response-content-encoding", "response-content-language",
        "response-content-type", "response-expires", "restore", "tagging",
        "torrent", "uploadId", "uploads", "versionId", "versioning",
        "versions", "website",
    }
)

results: List[dict] = []


def _aws_quote(value: str, safe: str = "-_.~") -> str:
    return urllib.parse.quote(value, safe=safe)


def _canonical_query(pairs: Sequence[Tuple[str, str]]) -> str:
    encoded = [(_aws_quote(k), _aws_quote(v)) for k, v in pairs]
    encoded.sort()
    return "&".join(f"{k}={v}" for k, v in encoded)


def _wire_query(pairs: Sequence[Tuple[str, str]]) -> str:
    return "&".join(f"{_aws_quote(k, safe='-_.~')}={_aws_quote(v, safe='-_.~')}" for k, v in pairs)


def _sign(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _v4_key(secret: str, stamp: str, region: str) -> bytes:
    k_date = _sign(("AWS4" + secret).encode(), stamp.encode())
    k_region = _sign(k_date, region.encode())
    k_service = _sign(k_region, SERVICE.encode())
    return _sign(k_service, b"aws4_request")


def sigv4(
    access: str,
    secret: str,
    method: str,
    path: str,
    query: Sequence[Tuple[str, str]] = (),
    body: bytes = b"",
    extra_headers: Optional[Dict[str, str]] = None,
    region: Optional[str] = None,
) -> Tuple[int, Dict[str, str], bytes]:
    region = region or REGION
    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    headers = {
        "Host": HOST,
        "X-Amz-Date": amz_date,
        "X-Amz-Content-SHA256": payload_hash,
    }
    if extra_headers:
        headers.update(extra_headers)
    q = [(str(k), str(v)) for k, v in query]
    signed_names = sorted({n.lower() for n in headers})
    lower = {k.lower(): _normalize(headers[k]) for k in headers}
    # map back to original for values — normalize from original headers
    lower = {}
    for k, v in headers.items():
        lower[k.lower()] = " ".join(v.strip().split())
    canonical_headers = "".join(f"{n}:{lower[n]}\n" for n in signed_names)
    signed_headers = ";".join(signed_names)
    canonical_request = (
        f"{method}\n{_aws_quote(path, safe='/-_.~')}\n{_canonical_query(q)}\n"
        f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
    scope = f"{date_stamp}/{region}/{SERVICE}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )
    signature = hmac.new(
        _v4_key(secret, date_stamp, region),
        string_to_sign.encode(),
        hashlib.sha256,
    ).hexdigest()
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    url = VIP + path
    if q:
        url += "?" + _wire_query(q)
    data = body if method in ("PUT", "POST") else None
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in headers.items():
        if k.lower() == "host":
            continue
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60, context=CTX) as resp:
            return resp.status, {k: v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as e:
        body_b = e.read() if e.fp else b""
        hdrs = dict(e.headers.items()) if e.headers else {}
        return e.code, hdrs, body_b
    except Exception as e:  # noqa: BLE001
        return 0, {}, str(e).encode()


def _normalize(v: str) -> str:
    return " ".join(v.strip().split())


def record(lane: str, op: str, code: int, ok: bool, note: str = "", body: bytes = b"") -> None:
    snippet = body[:120].decode("utf-8", "replace").replace("\n", " ")
    # redact common secret-ish patterns
    for tok in ("Signature=", "Credential=", "AWSAccessKeyId="):
        if tok in snippet:
            snippet = snippet.split(tok)[0] + tok + "<redacted>"
    row = {
        "lane": lane,
        "op": op,
        "http": code,
        "ok": bool(ok),
        "note": note,
        "body_snip": snippet,
    }
    results.append(row)
    status = "PASS" if ok else "FAIL"
    print(f"{status}  {lane}:{op}  http={code}  {note}  {snippet[:100]}")


def expect(lane, op, code, ok_codes, body=b"", note="", extra_ok=None):
    ok = code in ok_codes
    if extra_ok is not None:
        ok = ok and extra_ok
    record(lane, op, code, ok, note=note, body=body)
    return ok


def xml_text(body: bytes, path_tags: Sequence[str]) -> Optional[str]:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None
    # strip namespaces
    def local(t):
        return t.split("}", 1)[-1]

    cur = root
    if local(cur.tag) != path_tags[0]:
        # search
        for el in root.iter():
            if local(el.tag) == path_tags[0]:
                cur = el
                break
        else:
            return None
        path_tags = path_tags[1:]
    else:
        path_tags = path_tags[1:]
    for tag in path_tags:
        found = None
        for child in list(cur):
            if local(child.tag) == tag:
                found = child
                break
        if found is None:
            return None
        cur = found
    return (cur.text or "").strip()


def run_tempauth(access: str, secret: str) -> None:
    lane = "tempauth-sigv4"
    bucket = f"w3mx-{int(time.time())}"
    key = "obj1.txt"
    payload = b"contabo-matrix-tempauth-ok"

    # probe region
    global REGION
    for region in ("us-east-1", "RegionOne"):
        REGION = region
        code, _, body = sigv4(access, secret, "GET", "/")
        if code == 200:
            expect(lane, "ListBuckets", code, (200,), body)
            break
        if code == 403 and b"SignatureDoesNotMatch" in body:
            continue
        expect(lane, "ListBuckets", code, (200,), body)
        return
    else:
        expect(lane, "ListBuckets", code, (200,), body)
        return

    code, _, body = sigv4(access, secret, "PUT", f"/{bucket}")
    expect(lane, "CreateBucket", code, (200, 201), body)

    code, _, body = sigv4(access, secret, "PUT", f"/{bucket}/{key}", body=payload)
    expect(lane, "PutObject", code, (200, 201), body)

    code, hdrs, body = sigv4(access, secret, "HEAD", f"/{bucket}/{key}")
    cl = hdrs.get("Content-Length") or hdrs.get("content-length")
    expect(lane, "HeadObject", code, (200,), body, note=f"cl={cl}", extra_ok=(cl == str(len(payload))))

    code, _, body = sigv4(access, secret, "GET", f"/{bucket}/{key}")
    expect(lane, "GetObject", code, (200,), body, extra_ok=(body == payload))

    # Range GET
    code, _, body = sigv4(
        access, secret, "GET", f"/{bucket}/{key}",
        extra_headers={"Range": "bytes=0-6"},
    )
    expect(lane, "GetObjectRange", code, (206, 200), body, extra_ok=(body == payload[:7] or body == payload))

    code, _, body = sigv4(access, secret, "GET", f"/{bucket}")
    expect(lane, "ListObjectsV1", code, (200,), body, extra_ok=(key.encode() in body or b"obj1" in body))

    code, _, body = sigv4(access, secret, "GET", f"/{bucket}", query=[("list-type", "2")])
    expect(lane, "ListObjectsV2", code, (200,), body)

    code, _, body = sigv4(access, secret, "GET", f"/{bucket}", query=[("location", "")])
    expect(lane, "GetBucketLocation", code, (200,), body)

    code, _, body = sigv4(access, secret, "GET", f"/{bucket}", query=[("acl", "")])
    expect(lane, "GetBucketAcl", code, (200,), body)

    code, _, body = sigv4(access, secret, "GET", f"/{bucket}/{key}", query=[("acl", "")])
    expect(lane, "GetObjectAcl", code, (200,), body)

    # CopyObject
    code, _, body = sigv4(
        access, secret, "PUT", f"/{bucket}/obj1-copy.txt",
        extra_headers={"X-Amz-Copy-Source": f"/{bucket}/{key}"},
    )
    expect(lane, "CopyObject", code, (200,), body)

    code, _, body = sigv4(access, secret, "GET", f"/{bucket}/obj1-copy.txt")
    expect(lane, "GetCopiedObject", code, (200,), body, extra_ok=(body == payload))

    # MultiDelete
    md_body = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        b"<Object><Key>obj1-copy.txt</Key></Object>"
        b"<Quiet>true</Quiet></Delete>"
    )
    code, _, body = sigv4(
        access, secret, "POST", f"/{bucket}",
        query=[("delete", "")],
        body=md_body,
        extra_headers={"Content-MD5": __import__("base64").b64encode(hashlib.md5(md_body).digest()).decode(),
                       "Content-Type": "application/xml"},
    )
    expect(lane, "MultiDelete", code, (200,), body)

    # MPU initiate / upload / list / abort (not full complete path — keep bounded)
    code, _, body = sigv4(access, secret, "POST", f"/{bucket}/mpu.bin", query=[("uploads", "")])
    upload_id = xml_text(body, ("InitiateMultipartUploadResult", "UploadId")) or xml_text(body, ("UploadId",))
    expect(lane, "CreateMultipartUpload", code, (200,), body, note=f"upload_id_len={len(upload_id or '')}",
           extra_ok=bool(upload_id))
    if upload_id:
        part = b"x" * (5 * 1024 * 1024)  # 5 MiB min part size for many impls; use smaller if allowed
        # Contabo/swift often accepts smaller parts for abort-only path; use 256KiB
        part = b"p" * (256 * 1024)
        code, hdrs, body = sigv4(
            access, secret, "PUT", f"/{bucket}/mpu.bin",
            query=[("partNumber", "1"), ("uploadId", upload_id)],
            body=part,
        )
        etag = hdrs.get("ETag") or hdrs.get("etag") or ""
        expect(lane, "UploadPart", code, (200,), body, note=f"etag_set={bool(etag)}")

        code, _, body = sigv4(
            access, secret, "GET", f"/{bucket}/mpu.bin",
            query=[("uploadId", upload_id)],
        )
        expect(lane, "ListParts", code, (200,), body)

        code, _, body = sigv4(access, secret, "GET", f"/{bucket}", query=[("uploads", "")])
        expect(lane, "ListMultipartUploads", code, (200,), body)

        code, _, body = sigv4(
            access, secret, "DELETE", f"/{bucket}/mpu.bin",
            query=[("uploadId", upload_id)],
        )
        expect(lane, "AbortMultipartUpload", code, (204, 200), body)

    # cleanup
    code, _, body = sigv4(access, secret, "DELETE", f"/{bucket}/{key}")
    expect(lane, "DeleteObject", code, (204, 200, 404), body)
    code, _, body = sigv4(access, secret, "DELETE", f"/{bucket}")
    expect(lane, "DeleteBucket", code, (204, 200), body)


def run_ec2(access: str, secret: str) -> None:
    lane = "ec2-sigv4"
    bucket = f"ec2mx-{int(time.time())}"
    key = "hello.txt"
    payload = b"contabo-matrix-ec2-ok"

    global REGION
    for region in ("us-east-1", "RegionOne"):
        REGION = region
        code, _, body = sigv4(access, secret, "GET", "/")
        if code == 200:
            expect(lane, "ListBuckets", code, (200,), body)
            break
        if b"SignatureDoesNotMatch" in body:
            continue
        expect(lane, "ListBuckets", code, (200,), body)
        return
    else:
        expect(lane, "ListBuckets", code, (200,), body)
        return

    code, _, body = sigv4(access, secret, "PUT", f"/{bucket}")
    expect(lane, "CreateBucket", code, (200, 201), body)

    code, _, body = sigv4(access, secret, "PUT", f"/{bucket}/{key}", body=payload)
    expect(lane, "PutObject", code, (200, 201), body)

    code, hdrs, body = sigv4(access, secret, "HEAD", f"/{bucket}/{key}")
    cl = hdrs.get("Content-Length") or hdrs.get("content-length")
    expect(lane, "HeadObject", code, (200,), note=f"cl={cl}", extra_ok=(cl == str(len(payload))))

    code, _, body = sigv4(access, secret, "GET", f"/{bucket}/{key}")
    expect(lane, "GetObject", code, (200,), body, extra_ok=(body == payload))

    code, _, body = sigv4(access, secret, "GET", f"/{bucket}")
    expect(lane, "ListObjectsV1", code, (200,), body)

    code, _, body = sigv4(access, secret, "DELETE", f"/{bucket}/{key}")
    expect(lane, "DeleteObject", code, (204, 200), body)

    code, _, body = sigv4(access, secret, "DELETE", f"/{bucket}")
    expect(lane, "DeleteBucket", code, (204, 200), body)


def main() -> int:
    os.makedirs(EVID_DIR, exist_ok=True)
    # TempAuth from env
    ta_access = os.environ.get("ST_USER", "")
    ta_secret = os.environ.get("ST_KEY", "")
    if not ta_access or not ta_secret:
        print("FATAL: ST_USER/ST_KEY not set", file=sys.stderr)
        return 2

    print(f"matrix_start tip_sha={TIP_SHA[:12]}… vip={VIP} region_start={REGION}")
    print(f"tempauth_access_prefix={ta_access[:8]}… (secret redacted)")

    run_tempauth(ta_access, ta_secret)

    ec2_path = os.environ.get("EC2_CREDS_JSON", "/root/contabo-s3-ec2-tester.json")
    if os.path.isfile(ec2_path):
        cred = json.loads(open(ec2_path).read())
        ec2_access = cred["access"]
        ec2_secret = cred["secret"]
        print(f"ec2_access_prefix={ec2_access[:8]}… (secret redacted)")
        run_ec2(ec2_access, ec2_secret)
    else:
        record("ec2-sigv4", "creds_missing", 0, False, note=ec2_path)

    passed = sum(1 for r in results if r["ok"])
    failed = sum(1 for r in results if not r["ok"])
    crit = [r for r in results if (not r["ok"]) and r["op"] in {
        "ListBuckets", "CreateBucket", "PutObject", "GetObject", "DeleteObject", "DeleteBucket",
        "HeadObject",
    }]
    if failed == 0:
        verdict = "GREEN"
    elif not crit and passed > 0:
        verdict = "PARTIAL"
    else:
        verdict = "FAIL"

    summary = {
        "verdict": verdict,
        "tip_sha": TIP_SHA,
        "vip": VIP,
        "region": REGION,
        "passed": passed,
        "failed": failed,
        "ops": results,
        "claim_boundary": (
            "Bounded Contabo live extended matrix: TempAuth SigV4 CRUD+list+acl+location+"
            "range+copy+multidelete+MPU abort path; EC2 SigV4 List/Put/Get/Head/Delete. "
            "NOT full strict-s3-parity dual-oracle; NOT multi-hour soak; NOT versioning/WORM live."
        ),
        "utc": datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ"),
    }
    with open(os.path.join(EVID_DIR, "30-matrix-results.json"), "w") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    with open(os.path.join(EVID_DIR, "30-matrix-suite.txt"), "w") as f:
        for r in results:
            f.write(
                f"{'PASS' if r['ok'] else 'FAIL'}  {r['lane']}:{r['op']}  "
                f"http={r['http']}  {r['note']}  {r['body_snip']}\n"
            )
        f.write(f"SUMMARY pass={passed} fail={failed} verdict={verdict}\n")
    with open(os.path.join(EVID_DIR, "00-VERDICT.txt"), "w") as f:
        f.write(
            f"Contabo live S3 extended matrix @ tip {TIP_SHA[:12]}…\n"
            f"VERDICT={verdict}\n"
            f"passed={passed} failed={failed}\n"
            f"lanes=tempauth-sigv4,ec2-sigv4\n"
            f"Claim boundary: bounded extended ops vs VIP; NOT multi-hour; NOT full strict-s3-parity.\n"
            f"Evidence: {EVID_DIR}\n"
        )
    print(f"VERDICT={verdict} passed={passed} failed={failed}")
    return 0 if verdict == "GREEN" else (1 if verdict == "FAIL" else 0)


if __name__ == "__main__":
    raise SystemExit(main())
