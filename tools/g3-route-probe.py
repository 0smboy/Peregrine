#!/usr/bin/env python3
"""G3 per-route activation probe against a live Rust proxy.

The G3 contract is not "`/recon/concurrency` returns 200". For every required
route it wants a real request plus counter deltas showing:

    native_async_requests_total          > 0
    legacy_sync_handler_requests_total  == 0
    block_in_place_total                == 0
    blocking_network_wait_total         == 0

This drives one real request per route through the proxy, snapshots
`/recon/concurrency` either side of it, and reports the delta and a verdict.
Routes it cannot drive are listed as UNCOVERED rather than assumed good.

Dependency-free on purpose: the lab nodes have no boto3.

  PROBE_S3_AK / PROBE_S3_SK      S3 credentials (else read from PROBE_CFG)
  PROBE_SWIFT_USER / _KEY        tempauth user (e.g. test:tester) and key
  PROBE_HOST / PROBE_PORT        proxy under test (default 127.0.0.1:18080)
  PROBE_CFG                      s3compat config to read S3 keys from
"""
from __future__ import annotations

import configparser
import datetime
import hashlib
import hmac
import http.client as http_client
import json
import os
import re
import sys
import uuid

HOST = os.environ.get("PROBE_HOST", "127.0.0.1")
PORT = int(os.environ.get("PROBE_PORT", "18080"))
REGION = os.environ.get("PROBE_REGION", "us-east-1")
CFG = os.environ.get("PROBE_CFG", "/root/work/s3compat/config/ceph-s3.live-13be1dbc.cfg")

COUNTERS = (
    "native_async_requests_total",
    "legacy_sync_handler_requests_total",
    "block_in_place_total",
    "blocking_network_wait_total",
)
METRIC_LINE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>[-+0-9.eE]+)\s*$"
)

# G3 required routes per the G0-G8 execution directive.
REQUIRED_ROUTES = [
    "swift-PUT", "swift-GET", "swift-HEAD", "swift-COPY", "swift-Range", "swift-SLO",
    "ec-PUT", "ec-GET",
    "s3-PUT", "s3-GET", "s3-MPU",
    "ssync",
]


def hget(headers, name, default=""):
    """Case-insensitive header lookup (Swift answers `Etag`, AWS `ETag`)."""
    lowered = name.lower()
    for k, v in headers.items():
        if k.lower() == lowered:
            return v
    return default


def http(method, path, headers=None, body=b"", host=HOST, port=PORT):
    conn = http_client.HTTPConnection(host, port, timeout=60)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    hdrs = dict(resp.getheaders())
    conn.close()
    return resp.status, hdrs, data


def counters():
    status, _, body = http("GET", "/recon/concurrency")
    if status != 200:
        raise RuntimeError(f"/recon/concurrency returned {status}")
    out = {}
    for raw in body.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = METRIC_LINE.match(line)
        if m:
            out[m.group("name")] = float(m.group("value"))
    return out


# ----------------------------------------------------------------- S3 SigV4

def s3_creds():
    ak, sk = os.environ.get("PROBE_S3_AK"), os.environ.get("PROBE_S3_SK")
    if ak and sk:
        return ak, sk
    cp = configparser.ConfigParser()
    cp.read(CFG)
    return cp.get("s3 main", "access_key"), cp.get("s3 main", "secret_key")


def _sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def canonical_query(query: str) -> str:
    """SigV4 canonical query: sorted `key=value`, valueless keys kept as `key=`."""
    if not query:
        return ""
    pairs = []
    for part in query.split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        pairs.append((k, v))
    return "&".join(f"{k}={v}" for k, v in sorted(pairs))


def s3(method, path, query="", body=b"", extra=None):
    ak, sk = s3_creds()
    amz_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    datestamp = amz_date[:8]
    payload_hash = hashlib.sha256(body).hexdigest()
    hostheader = f"{HOST}:{PORT}"

    signed = {"host": hostheader, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
    for k, v in (extra or {}).items():
        signed[k.lower()] = v
    names = sorted(signed)
    canonical_headers = "".join(f"{n}:{signed[n]}\n" for n in names)
    signed_headers = ";".join(names)
    canonical_request = "\n".join(
        [method, path, canonical_query(query), canonical_headers, signed_headers,
         payload_hash]
    )
    scope = f"{datestamp}/{REGION}/s3/aws4_request"
    sts = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope,
         hashlib.sha256(canonical_request.encode()).hexdigest()]
    )
    k = _sign(("AWS4" + sk).encode(), datestamp)
    for part in (REGION, "s3", "aws4_request"):
        k = _sign(k, part)
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()

    headers = dict(signed)
    headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={sig}"
    )
    return http(method, path + (f"?{query}" if query else ""), headers, body)


# ---------------------------------------------------------------- Swift auth

def swift_token():
    user = os.environ.get("PROBE_SWIFT_USER")
    key = os.environ.get("PROBE_SWIFT_KEY")
    if not (user and key):
        return None, None
    status, hdrs, _ = http("GET", "/auth/v1.0", {"X-Auth-User": user, "X-Auth-Key": key})
    if status // 100 != 2:
        return None, None
    token = hget(hdrs, "X-Auth-Token")
    storage = hget(hdrs, "X-Storage-Url")
    path = "/" + storage.split("/", 3)[3] if storage and storage.count("/") >= 3 else None
    return token, path


# -------------------------------------------------------------------- probe

def measure(label, fn):
    """Drive one route and score it.

    A route only counts as evidence when the request actually succeeded: a 403
    or 501 exercises the error path, not the route, so it must not pass G3.
    """
    before = counters()
    try:
        ok, detail = fn()
    except Exception as exc:  # noqa: BLE001 - a probe reports, it does not crash
        detail, ok = f"probe error: {exc!r}", False
    after = counters()
    delta = {c: after.get(c, 0.0) - before.get(c, 0.0) for c in COUNTERS}
    verdict = "PASS"
    if not ok:
        verdict = "NO-EVIDENCE (request rejected)"
    elif delta["native_async_requests_total"] <= 0:
        verdict = "FAIL native_async delta == 0"
    else:
        for c in COUNTERS[1:]:
            if delta[c] != 0:
                verdict = f"FAIL {c} delta {delta[c]:+g}"
                break
    return {"route": label, "detail": detail, "delta": delta, "verdict": verdict}


def main() -> int:
    results = []
    bucket = "g3probe-" + uuid.uuid4().hex[:10]
    key = "obj"

    st, _, _ = s3("PUT", f"/{bucket}")
    if st // 100 != 2:
        print(f"cannot create probe bucket: HTTP {st}", file=sys.stderr)
        return 2

    body = b"g3-probe-body-" + b"x" * 512

    def ok2(st):
        return 200 <= st < 300

    def s3_put():
        st, _, _ = s3("PUT", f"/{bucket}/{key}", body=body)
        return ok2(st), f"PUT /{bucket}/{key} -> {st}"

    def s3_get():
        st, _, _ = s3("GET", f"/{bucket}/{key}")
        return ok2(st), f"GET /{bucket}/{key} -> {st}"

    def s3_head():
        st, _, _ = s3("HEAD", f"/{bucket}/{key}")
        return ok2(st), f"HEAD /{bucket}/{key} -> {st}"

    def s3_range():
        st, _, _ = s3("GET", f"/{bucket}/{key}", extra={"range": "bytes=0-15"})
        return ok2(st), f"GET range /{bucket}/{key} -> {st}"

    def s3_copy():
        st, _, _ = s3("PUT", f"/{bucket}/{key}-copy",
                      extra={"x-amz-copy-source": f"/{bucket}/{key}"})
        return ok2(st), f"COPY -> {st}"

    def s3_mpu():
        st, _, data = s3("POST", f"/{bucket}/{key}-mpu", query="uploads=")
        text = data.decode("utf-8", "replace")
        if "<UploadId>" not in text:
            return False, f"initiate MPU -> {st} (no UploadId)"
        upload_id = text.split("<UploadId>")[1].split("</UploadId>")[0]
        part = b"y" * (5 * 1024 * 1024)
        st2, hdrs, _ = s3("PUT", f"/{bucket}/{key}-mpu",
                          query=f"partNumber=1&uploadId={upload_id}", body=part)
        etag = hget(hdrs, "ETag").strip()
        complete = (
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>"
            f"<ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
        ).encode()
        st3, _, _ = s3("POST", f"/{bucket}/{key}-mpu",
                       query=f"uploadId={upload_id}", body=complete)
        return ok2(st) and ok2(st2) and ok2(st3), (
            f"initiate {st} / part {st2} / complete {st3}"
        )

    for label, fn in [
        ("s3-PUT", s3_put), ("s3-GET", s3_get), ("s3-HEAD", s3_head),
        ("s3-Range", s3_range), ("s3-COPY", s3_copy), ("s3-MPU", s3_mpu),
    ]:
        results.append(measure(label, fn))

    token, acct = swift_token()
    if token and acct:
        cont = "g3probe-c-" + uuid.uuid4().hex[:8]
        auth = {"X-Auth-Token": token}
        http("PUT", f"{acct}/{cont}", auth)

        def sw_put():
            st, _, _ = http("PUT", f"{acct}/{cont}/o", auth, body)
            return ok2(st), f"PUT -> {st}"

        def sw_get():
            st, _, _ = http("GET", f"{acct}/{cont}/o", auth)
            return ok2(st), f"GET -> {st}"

        def sw_head():
            st, _, _ = http("HEAD", f"{acct}/{cont}/o", auth)
            return ok2(st), f"HEAD -> {st}"

        def sw_range():
            h = dict(auth, Range="bytes=0-15")
            st, _, _ = http("GET", f"{acct}/{cont}/o", h)
            return ok2(st), f"GET range -> {st}"

        def sw_copy():
            h = dict(auth, Destination=f"{cont}/o-copy")
            st, _, _ = http("COPY", f"{acct}/{cont}/o", h)
            return ok2(st), f"COPY -> {st}"

        def sw_slo():
            seg = "g3probe-seg-" + uuid.uuid4().hex[:8]
            http("PUT", f"{acct}/{seg}", auth)
            part = b"z" * (1024 * 1024)
            st1, h1, _ = http("PUT", f"{acct}/{seg}/p1", auth, part)
            etag = hget(h1, "Etag").strip('"')
            manifest = json.dumps(
                [{"path": f"/{seg}/p1", "etag": etag, "size_bytes": len(part)}]
            ).encode()
            st2, _, _ = http(
                "PUT", f"{acct}/{cont}/slo-manifest?multipart-manifest=put", auth, manifest
            )
            st3, _, _ = http("GET", f"{acct}/{cont}/slo-manifest", auth)
            return ok2(st1) and ok2(st2) and ok2(st3), (
                f"segment {st1} / manifest {st2} / GET {st3}"
            )

        def ec_put_get():
            ec = "g3probe-ec-" + uuid.uuid4().hex[:8]
            stc, _, _ = http("PUT", f"{acct}/{ec}", dict(auth, **{"X-Storage-Policy": "ec42"}))
            st1, _, _ = http("PUT", f"{acct}/{ec}/o", auth, body)
            st2, _, data = http("GET", f"{acct}/{ec}/o", auth)
            return ok2(stc) and ok2(st1) and ok2(st2) and data == body, (
                f"container {stc} / PUT {st1} / GET {st2}"
            )

        for label, fn in [
            ("swift-PUT", sw_put), ("swift-GET", sw_get), ("swift-HEAD", sw_head),
            ("swift-Range", sw_range), ("swift-COPY", sw_copy),
            ("swift-SLO", sw_slo), ("ec-PUT/GET", ec_put_get),
        ]:
            results.append(measure(label, fn))
    else:
        results.append({
            "route": "swift-*", "detail": "no tempauth credentials supplied",
            "delta": {}, "verdict": "UNCOVERED",
        })

    covered = {r["route"] for r in results if r["verdict"] == "PASS"}
    if "ec-PUT/GET" in covered:
        covered |= {"ec-PUT", "ec-GET"}
    uncovered = [r for r in REQUIRED_ROUTES if r not in covered]

    print(f"proxy under test: {HOST}:{PORT}")
    print(f"{'route':<12} {'verdict':<34} native  legacy  bip  netwait  detail")
    for r in results:
        d = r["delta"]
        print(
            f"{r['route']:<12} {r['verdict']:<34} "
            f"{d.get('native_async_requests_total', 0):>6.0f} "
            f"{d.get('legacy_sync_handler_requests_total', 0):>7.0f} "
            f"{d.get('block_in_place_total', 0):>4.0f} "
            f"{d.get('blocking_network_wait_total', 0):>8.0f}  {r['detail']}"
        )
    print()
    print(f"required routes still UNCOVERED by this probe: {', '.join(uncovered) or 'none'}")
    print("G3 is not green until every required route has evidence.")

    out = os.environ.get("PROBE_JSON")
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump({"proxy": f"{HOST}:{PORT}", "results": results,
                       "uncovered": uncovered}, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
