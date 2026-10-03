#!/usr/bin/env python3
"""Dependency-free SigV4 probe for one narrow question at a time.

Reads credentials from the s3compat live config so keys never leave the node.
Never targets prod :8080.
"""
import configparser
import datetime
import hashlib
import hmac
import http.client
import os
import sys
import uuid

CFG = os.environ.get("PROBE_CFG", "/root/work/s3compat/config/ceph-s3.live-13be1dbc.cfg")
REGION = os.environ.get("PROBE_REGION", "us-east-1")
SERVICE = "s3"


def creds(section="s3 main"):
    """Credentials from PROBE_AK/PROBE_SK when set, else from the suite config.

    Reading them on the node keeps keys out of any transcript.
    """
    if os.environ.get("PROBE_AK") and os.environ.get("PROBE_SK"):
        return os.environ["PROBE_AK"], os.environ["PROBE_SK"]
    cp = configparser.ConfigParser()
    cp.read(CFG)
    return cp.get(section, "access_key"), cp.get(section, "secret_key")


def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def request(host, port, method, path, ak, sk, body=b"", query=""):
    amz_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    datestamp = amz_date[:8]
    payload_hash = hashlib.sha256(body).hexdigest()
    hostheader = f"{host}:{port}"

    canonical_headers = f"host:{hostheader}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = "\n".join(
        [method, path, query, canonical_headers, signed_headers, payload_hash]
    )

    scope = f"{datestamp}/{REGION}/{SERVICE}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    k = sign(("AWS4" + sk).encode("utf-8"), datestamp)
    k = sign(k, REGION)
    k = sign(k, SERVICE)
    k = sign(k, "aws4_request")
    signature = hmac.new(k, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    headers = {
        "Host": hostheader,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }
    conn = http.client.HTTPConnection(host, port, timeout=30)
    url = path + ("?" + query if query else "")
    conn.request(method, url, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data.decode("utf-8", "replace")


def err_code(xml):
    if "<Code>" in xml:
        return xml.split("<Code>")[1].split("</Code>")[0]
    return ""


def probe_create_idempotency(label, host, port):
    ak, sk = creds()
    name = "peregrine-probe-" + uuid.uuid4().hex[:12]
    out = [f"--- {label} ({host}:{port}) bucket={name}"]
    s1, b1 = request(host, port, "PUT", f"/{name}", ak, sk)
    out.append(f"    create#1: HTTP {s1} {err_code(b1)}")
    s2, b2 = request(host, port, "PUT", f"/{name}", ak, sk)
    out.append(f"    create#2 (same owner, same name): HTTP {s2} {err_code(b2)}")
    s3, b3 = request(host, port, "DELETE", f"/{name}", ak, sk)
    out.append(f"    cleanup delete: HTTP {s3} {err_code(b3)}")
    verdict = "IDEMPOTENT (AWS us-east-1 / RGW behavior)" if s2 == 200 else f"NOT idempotent -> {s2} {err_code(b2)}"
    out.append(f"    verdict: {verdict}")
    return "\n".join(out)


if __name__ == "__main__":
    targets = [("rust-tip", "10.0.0.1", 18080), ("python-saio", "127.0.0.1", 8090)]
    if len(sys.argv) > 1 and sys.argv[1] == "--rust-only":
        targets = targets[:1]
    for label, h, p in targets:
        try:
            print(probe_create_idempotency(label, h, p))
        except Exception as exc:  # noqa: BLE001 - probe should report, not crash
            print(f"--- {label} ({h}:{p})\n    PROBE ERROR: {exc!r}")
