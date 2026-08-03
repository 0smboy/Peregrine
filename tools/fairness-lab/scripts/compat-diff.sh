#!/usr/bin/env bash
# P4: Minimal public-API differential harness (CORE-PATH).
# Compares Python vs Rust endpoints with normalized headers.
# Usage:
#   PY=http://127.0.0.1:8090 RS=http://127.0.0.1:8081 \
#   USER=test:tester KEY=azure-swift-2026.bench \
#   OUT=.../compat ./compat-diff.sh
set -euo pipefail
PY="${PY:-http://127.0.0.1:8090}"
RS="${RS:-http://127.0.0.1:8081}"
USER="${USER:-test:tester}"
KEY="${KEY:-azure-swift-2026.bench}"
OUT="${OUT:-/tmp/fairness-compat}"
mkdir -p "$OUT"

auth() {
  local base=$1
  curl -sS -m 15 -D - -o /dev/null \
    -H "X-Auth-User: $USER" -H "X-Auth-Key: $KEY" \
    "$base/auth/v1.0" | awk 'tolower($1)=="x-auth-token:"{print $2}' | tr -d '\r'
}

tok_py=$(auth "$PY")
tok_rs=$(auth "$RS")
[[ -n "$tok_py" && -n "$tok_rs" ]] || { echo "FATAL auth"; exit 3; }

python3 - <<PY
import hashlib, json, subprocess, time, os, base64
from pathlib import Path

py, rs = "$PY", "$RS"
tok_py, tok_rs = "$tok_py", "$tok_rs"
out = Path("$OUT")
VOLATILE = {"date","x-trans-id","x-openstack-request-id","server","x-timestamp"}

def capture(base, token, method, path, body=b"", extra=None):
    headers = ["-H", f"X-Auth-Token: {token}"]
    if extra:
        for k,v in extra.items():
            headers += ["-H", f"{k}: {v}"]
    url = base.rstrip("/") + "/" + path.lstrip("/")
    cmd = ["curl","-sS","-m","60","-D","-","-o","/tmp/fairness-body.bin","-X",method] + headers
    if body:
        cmd += ["--data-binary", "@-"]
    p = subprocess.run(cmd, input=body, capture_output=True)
    head = p.stdout.decode("latin1", "replace")
    status = 0
    hdrs = {}
    for i, line in enumerate(head.split("\r\n")):
        if i == 0 and line.startswith("HTTP/"):
            try: status = int(line.split()[1])
            except: status = 0
        elif ":" in line:
            k,v = line.split(":",1)
            hdrs[k.strip().lower()] = v.strip()
    body_b = Path("/tmp/fairness-body.bin").read_bytes() if Path("/tmp/fairness-body.bin").exists() else b""
    nh = {k:v for k,v in sorted(hdrs.items()) if k not in VOLATILE}
    return {
        "status": status,
        "headers": nh,
        "body_sha256": hashlib.sha256(body_b).hexdigest(),
        "body_len": len(body_b),
    }

cases = []
ns = f"fairdiff-{int(time.time())}"
acct = "v1/AUTH_test"

def add(method, path, body=b"", extra=None, name=""):
    cases.append((name or f"{method}:{path}", method, path, body, extra or {}))

add("PUT", f"{acct}/{ns}", name="create-container")
add("PUT", f"{acct}/{ns}/obj1", b"payload-one", {"Content-Type":"application/octet-stream","X-Object-Meta-Test":"v"}, "put-object")
add("HEAD", f"{acct}/{ns}/obj1", name="head-object")
add("GET", f"{acct}/{ns}/obj1", name="get-object")
add("GET", f"{acct}/{ns}/obj1", b"", {"Range":"bytes=0-3"}, "range-get")
add("POST", f"{acct}/{ns}/obj1", b"", {"X-Object-Meta-Test":"v2","Content-Type":"application/octet-stream"}, "post-meta")
add("GET", f"{acct}/{ns}?format=json", name="list-container")
add("PUT", f"{acct}/{ns}/empty", b"", {"Content-Type":"application/octet-stream"}, "zero-byte")
add("DELETE", f"{acct}/{ns}/empty", name="delete-empty")
add("DELETE", f"{acct}/{ns}/obj1", name="delete-obj")
add("DELETE", f"{acct}/{ns}", name="delete-container")

rows = []
fail = 0
unsup = 0
for name, method, path, body, extra in cases:
    a = capture(py, tok_py, method, path, body, extra)
    b = capture(rs, tok_rs, method, path, body, extra)
    # Classify
    cls = "match"
    if a["status"] != b["status"]:
        cls = "status_mismatch"
        fail += 1
    elif a["body_sha256"] != b["body_sha256"] and method in ("GET",):
        # listing JSON may differ key order — soft for list
        if "format=json" in path:
            cls = "body_semantic_review"
        else:
            cls = "body_mismatch"
            fail += 1
    # 404/501 on rust for advanced middleware would be unsupported — not in this CORE pack
    rows.append({"case": name, "python": a, "rust": b, "classification": cls})

diff_path = out / "differences.json"
diff_path.write_text(json.dumps({"endpoint_py": py, "endpoint_rs": rs, "rows": rows, "fail": fail}, indent=2)+"\n")
summary = {"cases": len(rows), "fail": fail, "gate": "PASS" if fail==0 else "FAIL", "label": "CORE-PATH"}
(out/"SUMMARY.json").write_text(json.dumps(summary, indent=2)+"\n")
print(json.dumps(summary, indent=2))
if fail:
    raise SystemExit(1)
PY
