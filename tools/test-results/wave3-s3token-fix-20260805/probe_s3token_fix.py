#!/usr/bin/env python3
"""Contabo live probe: Keystone /v3/s3tokens + Swift native + S3 EC2 (VIP)."""
import datetime
import hashlib
import hmac
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import pymysql
import yaml

sec = yaml.safe_load(Path("/root/contabo-identity-secrets.yml").read_text())
conn = pymysql.connect(
    host="127.0.0.1",
    user="keystone",
    password=sec["mariadb_keystone_pass"],
    database="keystone",
    cursorclass=pymysql.cursors.DictCursor,
)
cur = conn.cursor()
cur.execute(
    "SELECT id, type, key_hash, LENGTH(encrypted_blob) elen, "
    "LEFT(encrypted_blob, 48) ehead FROM credential WHERE type=%s",
    ("ec2",),
)
rows = cur.fetchall()
print("DB_EC2", len(rows))
for r in rows:
    kh = (r["key_hash"] or "")[:16]
    print(
        "id={} key_hash={} elen={} ehead={!r}".format(
            r["id"][:12], kh, r["elen"], r["ehead"]
        )
    )
conn.close()

t = json.loads(Path("/root/contabo-s3-ec2-tester.json").read_text())
access, secret = t["access"], t["secret"]
print("tester_access", access[:12], "project", (t.get("project_id") or "")[:12])


def sign_v4(sts, secret_key):
    parts = sts.split(b"\n")
    scope = parts[2].split(b"/")

    def _sign(k, m):
        return hmac.new(k, m, hashlib.sha256).digest()

    signed = _sign(("AWS4" + secret_key).encode(), scope[0])
    for p in scope[1:]:
        signed = _sign(signed, p)
    return hmac.new(signed, sts, hashlib.sha256).hexdigest()


sts = (
    b"AWS4-HMAC-SHA256\n20260805T101500Z\n20260805/RegionOne/s3/aws4_request\n"
    + hashlib.sha256(b"demo").hexdigest().encode()
)
token_b64 = __import__("base64").urlsafe_b64encode(sts).decode()
sig = sign_v4(sts, secret)
body = json.dumps(
    {"credentials": {"access": access, "token": token_b64, "signature": sig}}
).encode()

ok = fail = 0
for i in range(30):
    req = urllib.request.Request(
        "http://127.0.0.1:5001/v3/s3tokens",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            ok += int(r.status == 200)
    except Exception as e:
        fail += 1
        print("fail", i, type(e).__name__, e)
print("STRESS ok", ok, "fail", fail)

for label, payload in [
    (
        "rust_style_date",
        {"credentials": {"access": access, "token": "20260805T101500Z", "signature": sig}},
    ),
    (
        "bad_b64",
        {"credentials": {"access": access, "token": "!!!notb64!!!", "signature": sig}},
    ),
    (
        "wrong_sig",
        {"credentials": {"access": access, "token": token_b64, "signature": "0" * 64}},
    ),
]:
    b = json.dumps(payload).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:5001/v3/s3tokens",
        data=b,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(label, "status", r.status)
    except urllib.error.HTTPError as e:
        print(label, "HTTP", e.code, e.read()[:120])
    except Exception as e:
        print(label, "EXC", type(e).__name__, e)

ctx = ssl._create_unverified_context()
ok = fail = 0
for i in range(10):
    req = urllib.request.Request(
        "https://10.0.0.10:5000/v3/s3tokens",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            ok += int(r.status == 200)
    except Exception as e:
        fail += 1
        print("vip_fail", type(e).__name__, e)
print("VIP_STRESS ok", ok, "fail", fail)

req = urllib.request.Request(
    "https://10.0.0.10:5000/v3/s3tokens",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
    tok_body = json.load(r)
    subj = r.headers.get("X-Subject-Token")
project_id = tok_body["token"]["project"]["id"]
auth_tok = subj or tok_body["token"].get("id")
print(
    "project",
    project_id,
    "subj_len",
    len(subj or ""),
    "auth_tok_len",
    len(auth_tok or ""),
    "token_keys",
    list(tok_body["token"].keys()),
)

swift_base = "https://10.0.0.10:8085/v1/AUTH_{}".format(project_id)
for method, path, data, label in [
    ("PUT", "{}/w3s3tokfix".format(swift_base), None, "create_container"),
    (
        "PUT",
        "{}/w3s3tokfix/hello.txt".format(swift_base),
        b"s3token-fix-hello",
        "put_object",
    ),
    ("GET", "{}/w3s3tokfix/hello.txt".format(swift_base), None, "get_object"),
]:
    headers = {"X-Auth-Token": auth_tok or ""}
    if data is not None:
        headers["Content-Length"] = str(len(data))
    req = urllib.request.Request(path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            b = r.read()
            print(label, "HTTP", r.status, "len", len(b), b[:40])
    except urllib.error.HTTPError as e:
        print(label, "HTTP", e.code, e.read()[:200])
    except Exception as e:
        print(label, "EXC", type(e).__name__, e)


def aws_sigv4_headers(method, url, access_key, secret_key, region="RegionOne", payload=b""):
    u = urlparse(url)
    host = u.netloc
    path = u.path or "/"
    amz_date = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    datestamp = amz_date[:8]
    payload_hash = hashlib.sha256(payload).hexdigest()
    canonical_headers = (
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n".format(
            host, payload_hash, amz_date
        )
    )
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = "{}\n{}\n\n{}\n{}\n{}".format(
        method, path, canonical_headers, signed_headers, payload_hash
    )
    credential_scope = "{}/{}/s3/aws4_request".format(datestamp, region)
    string_to_sign = "AWS4-HMAC-SHA256\n{}\n{}\n{}".format(
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    )

    def _sign(k, m):
        if isinstance(m, str):
            m = m.encode()
        return hmac.new(k, m, hashlib.sha256).digest()

    k = _sign(("AWS4" + secret_key).encode(), datestamp)
    k = _sign(k, region)
    k = _sign(k, "s3")
    k = _sign(k, "aws4_request")
    signature = hmac.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = (
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}".format(
            access_key, credential_scope, signed_headers, signature
        )
    )
    return {
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Content-SHA256": payload_hash,
        "Authorization": auth,
    }


s3_url = "https://10.0.0.10:8085/"
hdrs = aws_sigv4_headers("GET", s3_url, access, secret)
req = urllib.request.Request(s3_url, headers=hdrs, method="GET")
try:
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        print("S3_ListBuckets_EC2 HTTP", r.status, r.read()[:120])
except urllib.error.HTTPError as e:
    print("S3_ListBuckets_EC2 HTTP", e.code, e.read()[:300])
except Exception as e:
    print("S3_ListBuckets_EC2 EXC", type(e).__name__, e)
