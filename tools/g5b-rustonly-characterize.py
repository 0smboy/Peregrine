#!/usr/bin/env python3
"""Characterize the two non-wall Rust-only G5-B identities.

A. test_object_create_bad_contentlength_mismatch_above
   Declare Content-Length one byte above the body and stop sending. AWS and
   Python Swift answer 400 RequestTimeout. Measure what this server does,
   with a bounded client timeout so we never hold a worker for long.

B. test_buckets_create_then_list
   Create N buckets, then ListBuckets and check every one is present. The
   test's NameError only triggers when one is missing, so this reproduces the
   underlying condition directly. Repeat to separate a hard defect from a
   flake caused by degraded account replication.
"""
import http.client
import importlib.util
import os
import socket
import sys
import time
import uuid

spec = importlib.util.spec_from_file_location("probe", os.environ.get(
    "PROBE_LIB", "/root/work/peregrine-probe-20260918/g3-route-probe.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

HOST = P.HOST
PORT = P.PORT
CLIENT_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "15"))


def probe_a():
    print("A. Content-Length one byte above the body")
    bucket = "clprobe-" + uuid.uuid4().hex[:10]
    st, _, _ = P.s3("PUT", f"/{bucket}")
    if st // 100 != 2:
        print(f"   cannot create bucket: {st}")
        return
    content = b"bar"
    declared = len(content) + 1

    # sign for the declared body so the signature is not the thing under test
    ak, sk = P.s3_creds()
    import datetime, hashlib, hmac
    amz = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ds = amz[:8]
    payload = "UNSIGNED-PAYLOAD"
    hh = f"{HOST}:{PORT}"
    signed = {"host": hh, "x-amz-content-sha256": payload, "x-amz-date": amz}
    names = sorted(signed)
    ch = "".join(f"{n}:{signed[n]}\n" for n in names)
    sh = ";".join(names)
    cr = "\n".join(["PUT", f"/{bucket}/k", "", ch, sh, payload])
    scope = f"{ds}/{P.REGION}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope,
                     hashlib.sha256(cr.encode()).hexdigest()])
    k = hmac.new(("AWS4" + sk).encode(), ds.encode(), hashlib.sha256).digest()
    for part in (P.REGION, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()

    raw = (
        f"PUT /{bucket}/k HTTP/1.1\r\n"
        f"Host: {hh}\r\n"
        f"x-amz-date: {amz}\r\n"
        f"x-amz-content-sha256: {payload}\r\n"
        f"Authorization: AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
        f"SignedHeaders={sh}, Signature={sig}\r\n"
        f"Content-Length: {declared}\r\n"
        f"\r\n"
    ).encode() + content

    s = socket.create_connection((HOST, PORT), timeout=CLIENT_TIMEOUT)
    s.sendall(raw)
    t0 = time.time()
    try:
        s.settimeout(CLIENT_TIMEOUT)
        data = s.recv(4096)
        dt = time.time() - t0
        if not data:
            print(f"   server closed with no response after {dt:.1f}s")
        else:
            head = data.decode("utf-8", "replace").split("\r\n")[0]
            code = ""
            body = data.decode("utf-8", "replace")
            if "<Code>" in body:
                code = body.split("<Code>")[1].split("</Code>")[0]
            print(f"   responded in {dt:.1f}s: {head}  errorcode={code or '-'}")
    except socket.timeout:
        print(f"   NO RESPONSE within {CLIENT_TIMEOUT:.0f}s -> request hangs "
              f"(expected: 400 RequestTimeout)")
    finally:
        s.close()
        print("   client socket closed (worker not held open by this probe)")


def probe_b(rounds=3, n=5):
    print("B. create N buckets, then ListBuckets and check membership")
    for r in range(1, rounds + 1):
        names = ["listprobe-" + uuid.uuid4().hex[:10] for _ in range(n)]
        for nm in names:
            st, _, _ = P.s3("PUT", f"/{nm}")
            if st // 100 != 2:
                print(f"   round {r}: create {nm} -> {st}")
        st, _, data = P.s3("GET", "/")
        listing = data.decode("utf-8", "replace")
        missing = [nm for nm in names if f"<Name>{nm}</Name>" not in listing]
        print(f"   round {r}: ListBuckets HTTP {st}, missing {len(missing)}/{n}"
              + (f" -> {missing}" if missing else ""))
        for nm in names:
            P.s3("DELETE", f"/{nm}")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    print(f"target {HOST}:{PORT}")
    if which in ("a", "both"):
        probe_a()
    if which in ("b", "both"):
        probe_b()
