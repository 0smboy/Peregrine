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
import re
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
EVID_DIR = os.environ.get("EVID_DIR", "")
TIP_SHA = os.environ.get("TIP_SHA", "")
CTX = ssl._create_unverified_context()
SERVICE = "s3"

EXIT_PARITY_GREEN = 0
EXIT_FAIL = 1
EXIT_CONFIG_ERROR = 2
EXIT_BLOCKED = 3
EXIT_OPS_ONLY = 4
EXIT_PARTIAL = 5
EXIT_SKIPPED = 6
TIP_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")

REQUIRED_OPS = frozenset(
    {
        ("tempauth-sigv4", "ListBuckets"),
        ("tempauth-sigv4", "CreateBucket"),
        ("tempauth-sigv4", "PutObject"),
        ("tempauth-sigv4", "HeadObject"),
        ("tempauth-sigv4", "GetObject"),
        ("tempauth-sigv4", "GetObjectRange"),
        ("tempauth-sigv4", "ListObjectsV1"),
        ("tempauth-sigv4", "ListObjectsV2"),
        ("tempauth-sigv4", "GetBucketLocation"),
        ("tempauth-sigv4", "GetBucketAcl"),
        ("tempauth-sigv4", "GetObjectAcl"),
        ("tempauth-sigv4", "CopyObject"),
        ("tempauth-sigv4", "GetCopiedObject"),
        ("tempauth-sigv4", "MultiDelete"),
        ("tempauth-sigv4", "CreateMultipartUpload"),
        ("tempauth-sigv4", "UploadPart"),
        ("tempauth-sigv4", "ListParts"),
        ("tempauth-sigv4", "ListMultipartUploads"),
        ("tempauth-sigv4", "AbortMultipartUpload"),
        ("tempauth-sigv4", "DeleteObject"),
        ("tempauth-sigv4", "DeleteBucket"),
        ("ec2-sigv4", "ListBuckets"),
        ("ec2-sigv4", "CreateBucket"),
        ("ec2-sigv4", "PutObject"),
        ("ec2-sigv4", "HeadObject"),
        ("ec2-sigv4", "GetObject"),
        ("ec2-sigv4", "ListObjectsV1"),
        ("ec2-sigv4", "DeleteObject"),
        ("ec2-sigv4", "DeleteBucket"),
    }
)

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


def record(
    lane: str,
    op: str,
    code: int,
    ok: bool,
    note: str = "",
    body: bytes = b"",
    cleanup: bool = False,
) -> None:
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
        "cleanup": bool(cleanup),
    }
    results.append(row)
    status = "PASS" if ok else "FAIL"
    print(f"{status}  {lane}:{op}  http={code}  {note}  {snippet[:100]}")


def expect(
    lane,
    op,
    code,
    ok_codes,
    body=b"",
    note="",
    extra_ok=None,
    cleanup=False,
):
    ok = code in ok_codes
    if extra_ok is not None:
        ok = ok and extra_ok
    record(lane, op, code, ok, note=note, body=body, cleanup=cleanup)
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
    expect(lane, "MultiDelete", code, (200,), body, cleanup=True)

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
        expect(lane, "AbortMultipartUpload", code, (204, 200), body, cleanup=True)
    elif code in (200, 201):
        record(
            lane,
            "AbortMultipartUpload",
            0,
            False,
            note="cleanup impossible: successful initiate returned no upload id",
            cleanup=True,
        )

    # cleanup
    code, _, body = sigv4(access, secret, "DELETE", f"/{bucket}/{key}")
    expect(lane, "DeleteObject", code, (204, 200, 404), body, cleanup=True)
    code, _, body = sigv4(access, secret, "DELETE", f"/{bucket}")
    expect(lane, "DeleteBucket", code, (204, 200, 404), body, cleanup=True)


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
    expect(lane, "DeleteObject", code, (204, 200, 404), body, cleanup=True)

    code, _, body = sigv4(access, secret, "DELETE", f"/{bucket}")
    expect(lane, "DeleteBucket", code, (204, 200, 404), body, cleanup=True)


def _utc_stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _configuration_errors() -> List[str]:
    errors: List[str] = []
    if not EVID_DIR:
        errors.append("EVID_DIR is required")
    parsed = urllib.parse.urlsplit(VIP)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        errors.append("VIP must be an absolute HTTP(S) origin without credentials or path")
    try:
        _ = parsed.port
    except ValueError:
        errors.append("VIP has an invalid port")
    if not HOST or any(c.isspace() for c in HOST) or "/" in HOST:
        errors.append("S3_HOST must be a non-empty host[:port]")
    if not REGION or any(c.isspace() for c in REGION):
        errors.append("S3_REGION must be a non-empty token")
    if not TIP_SHA_RE.fullmatch(TIP_SHA):
        errors.append("TIP_SHA must be a 7-64 character hexadecimal commit id")
    if not os.environ.get("ST_USER", "") or not os.environ.get("ST_KEY", ""):
        errors.append("ST_USER and ST_KEY are required")
    return errors


def _load_ec2_credentials(path: str) -> Tuple[str, str]:
    if not os.path.isfile(path):
        raise ValueError("EC2_CREDS_JSON does not exist")
    try:
        with open(path, encoding="utf-8") as f:
            value = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("EC2_CREDS_JSON is not readable valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("EC2_CREDS_JSON must contain an object")
    access = value.get("access")
    secret = value.get("secret")
    if not isinstance(access, str) or not access or not isinstance(secret, str) or not secret:
        raise ValueError("EC2_CREDS_JSON requires non-empty access and secret strings")
    return access, secret


def classify_ops(rows: Sequence[dict]) -> Tuple[str, int, int, int, int]:
    """Return verdict, exit code, pass, fail, cleanup-fail counts.

    This one-origin matrix can never return PARITY_GREEN. Complete operations
    are OPS_ONLY/4 until the independent strict-s3-parity gate runs.
    """
    if not rows:
        return "PARTIAL", EXIT_PARTIAL, 0, 0, 0
    passed = sum(1 for row in rows if row["ok"])
    failed_rows = [row for row in rows if not row["ok"]]
    cleanup_failed = sum(1 for row in failed_rows if row.get("cleanup"))
    present = {(row["lane"], row["op"]) for row in rows}
    missing_required = REQUIRED_OPS - present
    critical_ops = {
        "ListBuckets",
        "CreateBucket",
        "PutObject",
        "GetObject",
        "DeleteObject",
        "DeleteBucket",
        "HeadObject",
    }
    critical_failed = any(row["op"] in critical_ops for row in failed_rows)
    if cleanup_failed or critical_failed:
        return "FAIL", EXIT_FAIL, passed, len(failed_rows), cleanup_failed
    if failed_rows or missing_required:
        return "PARTIAL", EXIT_PARTIAL, passed, len(failed_rows), cleanup_failed
    return "OPS_ONLY", EXIT_OPS_ONLY, passed, 0, 0


def _write_early_verdict(verdict: str, reason: str, exit_code: int) -> None:
    message = (
        f"VERDICT={verdict} CLAIM=OPS_ONLY reason={reason} "
        f"exit_code={exit_code} parity_oracle=NOT_RUN"
    )
    print(message, file=sys.stderr)
    if not EVID_DIR:
        return
    try:
        os.makedirs(EVID_DIR, exist_ok=True)
        with open(os.path.join(EVID_DIR, "00-VERDICT.txt"), "w", encoding="utf-8") as f:
            f.write(message + "\n")
        with open(
            os.path.join(EVID_DIR, "30-matrix-results.json"), "w", encoding="utf-8"
        ) as f:
            json.dump(
                {
                    "verdict": verdict,
                    "claim": "OPS_ONLY",
                    "exit_code": exit_code,
                    "reason": reason,
                    "parity_oracle": "NOT_RUN",
                    "tip_sha": TIP_SHA,
                    "utc": _utc_stamp(),
                },
                f,
                indent=2,
            )
            f.write("\n")
    except OSError as exc:
        print(f"FATAL: unable to write evidence: {type(exc).__name__}", file=sys.stderr)


def _write_results(verdict: str, exit_code: int) -> None:
    passed = sum(1 for row in results if row["ok"])
    failed = sum(1 for row in results if not row["ok"])
    cleanup_failed = sum(
        1 for row in results if (not row["ok"]) and row.get("cleanup")
    )
    present = {(row["lane"], row["op"]) for row in results}
    missing_ops = sorted(f"{lane}:{op}" for lane, op in REQUIRED_OPS - present)
    summary = {
        "verdict": verdict,
        "claim": "OPS_ONLY",
        "exit_code": exit_code,
        "parity_oracle": "NOT_RUN",
        "parity_green": False,
        "tip_sha": TIP_SHA,
        "vip": VIP,
        "region": REGION,
        "passed": passed,
        "failed": failed,
        "cleanup_failed": cleanup_failed,
        "required_ops": len(REQUIRED_OPS),
        "missing_ops": missing_ops,
        "ops": results,
        "claim_boundary": (
            "OPS_ONLY bounded Contabo live extended matrix: TempAuth SigV4 CRUD+list+acl+"
            "location+range+copy+multidelete+MPU abort path; EC2 SigV4 "
            "List/Put/Get/Head/Delete. Python S3 oracle NOT_RUN, therefore this result is "
            "never parity GREEN. NOT multi-hour soak; NOT versioning/WORM live."
        ),
        "zero_exit_policy": (
            "Exit 0 is reserved for a separate successful strict-s3-parity two-origin gate."
        ),
        "utc": _utc_stamp(),
    }
    with open(
        os.path.join(EVID_DIR, "30-matrix-results.json"), "w", encoding="utf-8"
    ) as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    with open(os.path.join(EVID_DIR, "30-matrix-suite.txt"), "w", encoding="utf-8") as f:
        for row in results:
            f.write(
                f"{'PASS' if row['ok'] else 'FAIL'}  {row['lane']}:{row['op']}  "
                f"http={row['http']} cleanup={str(row.get('cleanup', False)).lower()}  "
                f"{row['note']}  {row['body_snip']}\n"
            )
        f.write(
            f"SUMMARY claim=OPS_ONLY parity_oracle=NOT_RUN pass={passed} fail={failed} "
            f"cleanup_fail={cleanup_failed} missing={len(missing_ops)} "
            f"verdict={verdict} exit_code={exit_code}\n"
        )
    with open(os.path.join(EVID_DIR, "00-VERDICT.txt"), "w", encoding="utf-8") as f:
        f.write(
            f"Contabo live S3 extended matrix @ tip {TIP_SHA[:12]}…\n"
            f"VERDICT={verdict}\n"
            f"CLAIM=OPS_ONLY\n"
            f"PARITY_ORACLE=NOT_RUN\n"
            f"EXIT_CODE={exit_code}\n"
            f"passed={passed} failed={failed} cleanup_failed={cleanup_failed} "
            f"missing={len(missing_ops)}\n"
            f"lanes=tempauth-sigv4,ec2-sigv4\n"
            f"Claim boundary: bounded one-origin extended ops vs VIP; not parity GREEN.\n"
            f"Evidence: {EVID_DIR}\n"
        )


def main() -> int:
    global results
    results = []
    config_errors = _configuration_errors()
    if config_errors:
        _write_early_verdict("CONFIG_ERROR", "; ".join(config_errors), EXIT_CONFIG_ERROR)
        return EXIT_CONFIG_ERROR

    try:
        os.makedirs(EVID_DIR, exist_ok=True)
    except OSError as exc:
        print(f"FATAL: unable to create EVID_DIR: {type(exc).__name__}", file=sys.stderr)
        return EXIT_CONFIG_ERROR

    ec2_path = os.environ.get("EC2_CREDS_JSON", "/root/contabo-s3-ec2-tester.json")
    try:
        ec2_access, ec2_secret = _load_ec2_credentials(ec2_path)
    except ValueError as exc:
        _write_early_verdict("CONFIG_ERROR", str(exc), EXIT_CONFIG_ERROR)
        return EXIT_CONFIG_ERROR

    ta_access = os.environ["ST_USER"]
    ta_secret = os.environ["ST_KEY"]
    print(f"matrix_start tip_sha={TIP_SHA[:12]}… vip={VIP} region_start={REGION}")
    print("CLAIM=OPS_ONLY parity_oracle=NOT_RUN zero_exit_allowed=false")
    print(f"tempauth_access_prefix={ta_access[:8]}… (secret redacted)")

    try:
        run_tempauth(ta_access, ta_secret)
        print(f"ec2_access_prefix={ec2_access[:8]}… (secret redacted)")
        run_ec2(ec2_access, ec2_secret)
    except KeyboardInterrupt:
        record(
            "runner",
            "cleanup_completion",
            0,
            False,
            note="interrupted; cleanup completion is not proven",
            cleanup=True,
        )
        _write_results("INTERRUPTED", 130)
        return 130
    except Exception as exc:  # noqa: BLE001
        record(
            "runner",
            "cleanup_completion",
            0,
            False,
            note=f"unexpected {type(exc).__name__}; cleanup completion is not proven",
            cleanup=True,
        )
        _write_results("FAIL", EXIT_FAIL)
        return EXIT_FAIL

    verdict, exit_code, passed, failed, cleanup_failed = classify_ops(results)
    _write_results(verdict, exit_code)
    print(
        f"VERDICT={verdict} CLAIM=OPS_ONLY PARITY_ORACLE=NOT_RUN "
        f"passed={passed} failed={failed} cleanup_failed={cleanup_failed} "
        f"exit_code={exit_code}"
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
