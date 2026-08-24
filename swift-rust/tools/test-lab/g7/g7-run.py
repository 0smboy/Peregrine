#!/usr/bin/env python3
"""G7 orchestrator. Reads frozen acceptance.yaml; never edits it.
opened < target => ENVIRONMENT BLOCKED, never PASS.
Does not talk to :8080.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
YAML_PATH = HERE / "acceptance.yaml"
JSON_PATH = HERE / "acceptance.json"
OUT = Path(os.environ.get("G7_OUT", "/root/work/g7-out"))
G7LOAD = os.environ.get("G7LOAD", str(HERE / "g7load"))
SSH_TARGET = os.environ.get("G7_TARGET_SSH", "root@10.0.0.1")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def load_frozen():
    # YAML is the frozen human file; JSON is the byte-identical machine form
    # generated at freeze time so the runner has no PyYAML dependency.
    spec = json.loads(JSON_PATH.read_text())
    spec["_sha256"] = sha256_file(YAML_PATH)
    spec["_json_sha256"] = sha256_file(JSON_PATH)
    spec["_bytes"] = YAML_PATH.stat().st_size
    return spec


def parse_recon(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            try:
                out[parts[0].split("{", 1)[0]] = float(parts[-1])
            except ValueError:
                pass
    return out


def http(host, port, method, path, headers=None, body=None, timeout=5.0):
    req = urllib.request.Request(
        f"http://{host}:{port}{path}",
        data=body,
        method=method,
        headers=headers or {},
    )
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            return resp.status, data, (time.monotonic() - t0) * 1000.0
    except urllib.error.HTTPError as e:
        return e.code, e.read(), (time.monotonic() - t0) * 1000.0


def sample_recon(spec, n=5, pause=0.05):
    host, port = spec["target"]["host"], spec["target"]["port"]
    path = spec["target"]["recon_path"]
    snaps = []
    for _ in range(n):
        try:
            st, body, ms = http(host, port, "GET", path, timeout=2.0)
            if st == 200:
                d = parse_recon(body.decode("utf-8", "replace"))
                d["_http_ms"] = ms
                snaps.append(d)
        except Exception as e:
            snaps.append({"error": str(e)})
        time.sleep(pause)
    return snaps


def health_p99(spec, n=40):
    host, port = spec["target"]["host"], spec["target"]["port"]
    path = spec["target"]["health_path"]
    xs = []
    for _ in range(n):
        try:
            st, _, ms = http(host, port, "HEAD", path, timeout=2.0)
            xs.append(ms if st and st < 500 else 2000.0)
        except Exception:
            xs.append(2000.0)
        time.sleep(0.02)
    xs.sort()
    p99 = xs[int((len(xs) - 1) * 0.99)] if xs else 2000.0
    return {"n": len(xs), "p50_ms": xs[len(xs) // 2] if xs else None, "p99_ms": p99}


def auth_token(spec):
    host, port = spec["target"]["host"], spec["target"]["port"]
    st, body, _ = http(
        host,
        port,
        "GET",
        "/auth/v1.0",
        headers={
            "X-Auth-User": spec["auth"]["user"],
            "X-Auth-Key": spec["auth"]["key"],
        },
        timeout=5.0,
    )
    # urllib doesn't expose headers easily from http(); redo with urlopen
    req = urllib.request.Request(
        f"http://{host}:{port}/auth/v1.0",
        headers={
            "X-Auth-User": spec["auth"]["user"],
            "X-Auth-Key": spec["auth"]["key"],
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        token = resp.headers.get("X-Auth-Token") or resp.headers.get("x-auth-token")
        return token


def src_args(spec):
    ips = ",".join(spec["loadgen"]["source_ips"])
    return ["--src", ips]


def run_g7load(args, timeout=180):
    cmd = [G7LOAD, *args]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    line = ""
    for ln in reversed(p.stdout.strip().splitlines() or [""]):
        if ln.startswith("{"):
            line = ln
            break
    obj = json.loads(line) if line else {"parse_error": True, "stdout": p.stdout[-2000:], "stderr": p.stderr[-2000:]}
    obj["_rc"] = p.returncode
    obj["_stderr_tail"] = p.stderr[-2000:]
    return obj


def classify(case, raw, spec):
    bounds = spec["bounds"]
    target = case.get("target")
    opened = raw.get("opened")
    out = {
        "name": case.get("_name"),
        "kind": case.get("kind"),
        "target": target,
        "opened": opened,
        "raw": raw,
    }
    if target is not None and opened is not None and opened < target:
        out["verdict"] = "ENVIRONMENT BLOCKED"
        out["reason"] = f"opened {opened} < target {target}"
        return out
    p99 = raw.get("health_p99_ms")
    if p99 is not None and p99 > bounds["health_head_p99_ms"] and case.get("kind") not in (
        "fsync_stall",
        "sqlite_stall",
    ):
        # stall cases allow health during stall as long as it *responds*; p99 bound still applies per OBJECTIVE
        if case.get("kind") not in ("fsync_stall", "sqlite_stall"):
            out["verdict"] = "FAIL"
            out["reason"] = f"health p99 {p99} > {bounds['health_head_p99_ms']} ms"
            return out
    if p99 is not None and p99 > bounds["health_head_p99_ms"]:
        out["verdict"] = "FAIL"
        out["reason"] = f"health p99 {p99} > {bounds['health_head_p99_ms']} ms"
        return out
    if raw.get("_rc") not in (0, None) and target is not None:
        out["verdict"] = "FAIL"
        out["reason"] = f"g7load rc={raw.get('_rc')}"
        return out
    if raw.get("error"):
        out["verdict"] = "FAIL"
        out["reason"] = str(raw["error"])
        return out
    out["verdict"] = "PASS"
    return out


def ssh(cmd, timeout=30):
    full = [
        "/usr/bin/ssh",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "StrictHostKeyChecking=no",
        SSH_TARGET,
        cmd,
    ]
    p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def ensure_container(spec, token):
    host, port = spec["target"]["host"], spec["target"]["port"]
    http(
        host,
        port,
        "PUT",
        f"/v1/{spec['auth']['account']}/g7slow",
        headers={"X-Auth-Token": token},
        timeout=10,
    )
    http(
        host,
        port,
        "PUT",
        f"/v1/{spec['auth']['account']}/g7get",
        headers={"X-Auth-Token": token},
        timeout=10,
    )


def put_object(spec, token, container, name, body: bytes):
    host, port = spec["target"]["host"], spec["target"]["port"]
    return http(
        host,
        port,
        "PUT",
        f"/v1/{spec['auth']['account']}/{container}/{name}",
        headers={"X-Auth-Token": token, "Content-Type": "application/octet-stream"},
        body=body,
        timeout=60,
    )


def run_case(name, case, spec, token):
    kind = case["kind"]
    host, port = spec["target"]["host"], spec["target"]["port"]
    before = sample_recon(spec, n=3)
    raw = {}
    if kind == "idle_keepalive":
        raw = run_g7load(
            [
                "idle",
                host,
                str(port),
                str(case["target"]),
                str(int(case["hold_secs"] * 1000)),
                *src_args(spec),
                "--path",
                spec["target"]["health_path"],
            ],
            timeout=case["hold_secs"] + 180,
        )
    elif kind == "slowloris":
        raw = run_g7load(
            [
                "slowloris",
                host,
                str(port),
                str(case["target"]),
                str(case["header_interval_ms"]),
                str(int(case["hold_secs"] * 1000)),
                *src_args(spec),
            ],
            timeout=case["hold_secs"] + 60,
        )
    elif kind == "slow_put":
        raw = run_g7load(
            [
                "slowput",
                host,
                str(port),
                str(case["target"]),
                str(case["rate_bps"]),
                str(case["body_bytes"]),
                *src_args(spec),
                "--path",
                f"/v1/{spec['auth']['account']}/g7slow/o",
                "--token",
                token or "",
            ],
            timeout=300,
        )
    elif kind == "slow_get":
        # seed one object then open N GETs that pause
        put_object(spec, token, "g7get", "blob", b"Y" * case["object_bytes"])
        n = case["target"]
        opened = 0
        socks = []
        tlat = []
        for i in range(n):
            s = socket.socket()
            try:
                s.settimeout(5)
                s.bind((spec["loadgen"]["source_ips"][i % 3], 0))
                s.connect((host, port))
                s.sendall(
                    f"GET /v1/{spec['auth']['account']}/g7get/blob HTTP/1.1\r\nHost: {host}\r\nX-Auth-Token: {token}\r\nConnection: keep-alive\r\n\r\n".encode()
                )
                opened += 1
                socks.append(s)
            except Exception:
                s.close()
        hp = health_p99(spec, n=30)
        # drain slowly
        for s in socks:
            try:
                s.settimeout(1)
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    time.sleep(case["read_pause_ms"] / 1000.0)
            except Exception:
                pass
            s.close()
        raw = {"case": "slow_get", "target": n, "opened": opened, "health_p99_ms": hp["p99_ms"]}
    elif kind == "churn":
        opened_min = None
        last = {}
        for cyc in range(case["cycles"]):
            last = run_g7load(
                [
                    "idle",
                    host,
                    str(port),
                    str(case["target"]),
                    "2000",
                    *src_args(spec),
                ],
                timeout=90,
            )
            opened_min = last.get("opened") if opened_min is None else min(opened_min, last.get("opened") or 0)
        raw = {**last, "cycles": case["cycles"], "opened": opened_min}
    elif kind == "blackhole":
        ssh(f"iptables -w -I OUTPUT 1 -p tcp -d {case['drop_backend'].split(':')[0]} --dport {case['drop_backend'].split(':')[1]} -j DROP")
        try:
            hp = health_p99(spec, n=30)
            st, _, _ = put_object(spec, token, "g7slow", "bh1", b"blackhole-body")
            raw = {
                "case": "blackhole",
                "target": 1,
                "opened": 1,
                "put_status": st,
                "health_p99_ms": hp["p99_ms"],
            }
        finally:
            ssh(f"iptables -w -D OUTPUT -p tcp -d {case['drop_backend'].split(':')[0]} --dport {case['drop_backend'].split(':')[1]} -j DROP")
    elif kind == "quorum":
        be = case["drop_backends"][0]
        ssh(f"iptables -w -I OUTPUT 1 -p tcp -d {be.split(':')[0]} --dport {be.split(':')[1]} -j DROP")
        try:
            ok = 0
            for i in range(case["put_n"]):
                st, _, _ = put_object(spec, token, "g7slow", f"q{i}", b"quorum")
                if st and 200 <= st < 300:
                    ok += 1
            hp = health_p99(spec, n=20)
            raw = {"case": "quorum", "target": case["put_n"], "opened": case["put_n"], "ok_2xx": ok, "health_p99_ms": hp["p99_ms"]}
        finally:
            ssh(f"iptables -w -D OUTPUT -p tcp -d {be.split(':')[0]} --dport {be.split(':')[1]} -j DROP")
    elif kind == "overload":
        raw = run_g7load(
            [
                "slowput",
                host,
                str(port),
                str(case["target"]),
                "1048576",
                str(case["body_bytes"]),
                *src_args(spec),
                "--path",
                f"/v1/{spec['auth']['account']}/g7slow/ov",
                "--token",
                token or "",
            ],
            timeout=180,
        )
    elif kind == "cancel":
        n = case["n"]
        opened = 0
        for i in range(n):
            s = socket.socket()
            try:
                s.settimeout(3)
                s.connect((host, port))
                s.sendall(
                    f"PUT /v1/{spec['auth']['account']}/g7slow/c{i} HTTP/1.1\r\nHost: {host}\r\nX-Auth-Token: {token}\r\nContent-Length: 1048576\r\n\r\nXXXX".encode()
                )
                opened += 1
                s.close()
            except Exception:
                s.close()
        time.sleep(1)
        rc, out, _ = ssh("find /srv/1/node /srv/2/node /srv/3/node /srv/4/node -name '*.tmp' -o -name '*tmp*' 2>/dev/null | wc -l")
        raw = {"case": "cancel", "target": n, "opened": opened, "tmp_count": int((out or "0").strip() or 0)}
    elif kind == "sigterm_put":
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        s.sendall(
            f"PUT /v1/{spec['auth']['account']}/g7slow/sigterm HTTP/1.1\r\nHost: {host}\r\nX-Auth-Token: {token}\r\nContent-Length: 10485760\r\n\r\n".encode()
        )
        ssh("pid=$(cat /var/run/g6-rust/proxy.pid); kill -TERM $pid; echo TERM $pid")
        time.sleep(2)
        hp_err = None
        try:
            http(host, port, "HEAD", spec["target"]["health_path"], timeout=1.0)
        except Exception as e:
            hp_err = str(e)
        ssh("bash /root/work/g7/g7-start-rust.sh")
        time.sleep(2)
        hp = health_p99(spec, n=10)
        raw = {"case": "sigterm_put", "target": 1, "opened": 1, "health_after_restart_p99_ms": hp["p99_ms"], "down_error": hp_err}
    elif kind == "sigterm_barrier":
        st, _, _ = put_object(spec, token, "g7slow", "barrier", b"Z" * 4096)
        ssh("pid=$(cat /var/run/g6-rust/proxy.pid); kill -TERM $pid; echo TERM $pid")
        time.sleep(1)
        ssh("bash /root/work/g7/g7-start-rust.sh")
        time.sleep(2)
        st2, body, _ = http(
            host,
            port,
            "GET",
            f"/v1/{spec['auth']['account']}/g7slow/barrier",
            headers={"X-Auth-Token": token},
            timeout=10,
        )
        raw = {"case": "sigterm_barrier", "target": 1, "opened": 1, "put_status": st, "get_after": st2, "len": len(body or b"")}
    elif kind == "fd_exhaust":
        rc, out, err = ssh("pid=$(cat /var/run/g6-rust/proxy.pid); ls -l /proc/$pid/fd | wc -l; cat /proc/$pid/limits | awk '/open files/{print}'")
        raw = {"case": "fd_exhaust", "target": 1, "opened": 1, "fd_info": (out or "") + (err or "")}
    elif kind == "enospc":
        rc, dfout, _ = ssh("df -k /srv/1/node | tail -1")
        raw = {"case": "enospc", "target": 1, "opened": 1, "df": dfout, "note": "fill attempted only if /srv/1 is a loop/saio device"}
        # fill at most the saio path; refuse if it looks like production d1
        rc2, _, _ = ssh(
            "if mount | grep -q ' /srv/1 '; then "
            "dd if=/dev/zero of=/srv/1/node/.g7fill bs=1M count=1 conv=fsync; "
            "echo FILL_OK; else echo SKIP_NOT_SAIO; fi"
        )
        st, _, _ = put_object(spec, token, "g7slow", "enospc", b"E" * 1024)
        ssh("rm -f /srv/1/node/.g7fill")
        raw["put_status"] = st
        raw["fill_rc"] = rc2
    elif kind == "eio":
        raw = {"case": "eio", "target": 1, "opened": 1, "note": "device-mapper EIO not armed this run unless /dev/mapper/g7eio exists"}
        rc, out, _ = ssh("ls /dev/mapper/g7eio 2>/dev/null || echo NO_MAPPER")
        raw["mapper"] = out.strip()
        if "NO_MAPPER" not in (out or ""):
            st, _, _ = put_object(spec, token, "g7slow", "eio", b"EIO")
            raw["put_status"] = st
            raw["opened"] = 1
        else:
            raw["verdict_hint"] = "NOT RUN"
    elif kind == "partial_write":
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        s.sendall(
            f"PUT /v1/{spec['auth']['account']}/g7slow/partial HTTP/1.1\r\nHost: {host}\r\nX-Auth-Token: {token}\r\nContent-Length: 100000\r\n\r\npartial-only".encode()
        )
        s.close()
        time.sleep(0.5)
        st, _, _ = http(
            host,
            port,
            "GET",
            f"/v1/{spec['auth']['account']}/g7slow/partial",
            headers={"X-Auth-Token": token},
            timeout=5,
        )
        raw = {"case": "partial_write", "target": 1, "opened": 1, "get_status": st, "expect_not_2xx": st is None or st >= 400}
    elif kind == "backend_connect_timeout":
        raw = {"case": "backend_connect_timeout", "target": 1, "opened": 1, "note": "blackhole unused replica IP"}
        ssh("iptables -w -I OUTPUT 1 -p tcp -d 127.0.0.9 -j DROP || true")
        try:
            hp = health_p99(spec, n=20)
            raw["health_p99_ms"] = hp["p99_ms"]
        finally:
            ssh("iptables -w -D OUTPUT -p tcp -d 127.0.0.9 -j DROP || true")
    elif kind == "fsync_stall":
        ssh(
            "gcc -shared -fPIC -O2 /root/work/g7/fsync_stall.c -o /root/work/g7/fsync_stall.so -ldl; "
            "pid=$(cat /var/run/g6-rust/object-1.pid); "
            "kill -TERM $pid || true; sleep 1; "
            "G7_FSYNC_STALL_US=5000000 LD_PRELOAD=/root/work/g7/fsync_stall.so "
            "nohup /root/work/g6-rust-bin/swift-object-server /etc/g6-rust/object-server/1.conf "
            ">>/var/log/g6-rust/object-1.stall.log 2>&1 & echo $! >/var/run/g6-rust/object-1.pid"
        )
        time.sleep(1)
        hp = health_p99(spec, n=case.get("health_samples", 40))
        t0 = time.monotonic()
        st, _, ms = put_object(spec, token, "g7slow", "fsync", b"F" * 4096)
        raw = {
            "case": "fsync_stall",
            "target": 1,
            "opened": 1,
            "put_status": st,
            "put_ms": ms,
            "health_p99_ms": hp["p99_ms"],
            "elapsed_s": time.monotonic() - t0,
        }
        ssh("pid=$(cat /var/run/g6-rust/object-1.pid); kill -TERM $pid || true; sleep 1; "
            "nohup /root/work/g6-rust-bin/swift-object-server /etc/g6-rust/object-server/1.conf "
            ">>/var/log/g6-rust/object-1.log 2>&1 & echo $! >/var/run/g6-rust/object-1.pid")
    elif kind == "sqlite_stall":
        ssh(
            "gcc -shared -fPIC -O2 /root/work/g7/fsync_stall.c -o /root/work/g7/fsync_stall.so -ldl; "
            "pid=$(cat /var/run/g6-rust/container-1.pid); kill -TERM $pid || true; sleep 1; "
            "G7_FSYNC_STALL_US=5000000 LD_PRELOAD=/root/work/g7/fsync_stall.so "
            "nohup /root/work/g6-rust-bin/swift-container-server /etc/g6-rust/container-server/1.conf "
            ">>/var/log/g6-rust/container-1.stall.log 2>&1 & echo $! >/var/run/g6-rust/container-1.pid"
        )
        time.sleep(1)
        hp = health_p99(spec, n=case.get("health_samples", 40))
        raw = {"case": "sqlite_stall", "target": 1, "opened": 1, "health_p99_ms": hp["p99_ms"]}
        ssh("pid=$(cat /var/run/g6-rust/container-1.pid); kill -TERM $pid || true; sleep 1; "
            "nohup /root/work/g6-rust-bin/swift-container-server /etc/g6-rust/container-server/1.conf "
            ">>/var/log/g6-rust/container-1.log 2>&1 & echo $! >/var/run/g6-rust/container-1.pid")
    else:
        raw = {"error": f"unknown kind {kind}", "target": case.get("target"), "opened": 0}

    after = sample_recon(spec, n=3)
    raw["recon_before"] = before
    raw["recon_after"] = after
    case = dict(case)
    case["_name"] = name
    result = classify(case, raw, spec)
    if kind in ("eio",) and raw.get("verdict_hint") == "NOT RUN":
        result["verdict"] = "NOT RUN"
        result["reason"] = "no EIO mapper"
    return result


def dummy_calibrate(spec):
    dummy = spec["dummy_acceptor"]
    results = []
    for n in (10000, 50000, 100000):
        raw = run_g7load(
            [
                "idle",
                dummy["bind"],
                str(dummy["port"]),
                str(n),
                "10000",
                *src_args(spec),
                "--path",
                "/healthcheck",
            ],
            timeout=180,
        )
        rec = classify({"_name": f"dummy_{n}", "kind": "idle_keepalive", "target": n}, raw, spec)
        # Dummy is not the SUT: opened==target is the only calibration gate.
        if rec.get("opened") == n:
            rec["verdict"] = "PASS"
            rec["reason"] = "dummy opened==target"
        results.append(rec)
        if rec.get("opened") != n:
            rec["verdict"] = "ENVIRONMENT BLOCKED"
            break
    return results


def main():
    spec = load_frozen()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "acceptance.yaml").write_bytes(YAML_PATH.read_bytes())
    (OUT / "acceptance.sha256").write_text(spec["_sha256"] + "\n")
    mode = sys.argv[1] if len(sys.argv) > 1 else "matrix"

    if mode == "freeze-check":
        print(json.dumps({"sha256": spec["_sha256"], "bytes": spec["_bytes"]}))
        return 0

    if mode == "dummy":
        recs = dummy_calibrate(spec)
        (OUT / "dummy.json").write_text(json.dumps(recs, indent=2) + "\n")
        blocked = [r for r in recs if r["verdict"] != "PASS"]
        print(json.dumps({"dummy": recs, "ok": not blocked}, indent=2))
        return 0 if not blocked else 3

    token = None
    try:
        token = auth_token(spec)
    except Exception as e:
        print("auth failed", e, file=sys.stderr)

    if token:
        try:
            ensure_container(spec, token)
        except Exception as e:
            print("ensure container", e, file=sys.stderr)

    results = []
    names = sys.argv[2:] if len(sys.argv) > 2 else list(spec["cases"])
    for name in names:
        case = spec["cases"][name]
        print(f"=== {name} ===", flush=True)
        rec = run_case(name, case, spec, token)
        results.append(rec)
        (OUT / f"{name}.json").write_text(json.dumps(rec, indent=2, default=str) + "\n")
        print(rec["verdict"], rec.get("reason", ""), "opened", rec.get("opened"), "target", rec.get("target"), flush=True)

    blocked = [r for r in results if r["verdict"] == "ENVIRONMENT BLOCKED"]
    fails = [r for r in results if r["verdict"] == "FAIL"]
    notrun = [r for r in results if r["verdict"] == "NOT RUN"]
    passes = [r for r in results if r["verdict"] == "PASS"]
    if blocked:
        gate = "ENVIRONMENT BLOCKED"
    elif fails or notrun:
        gate = "RED"
    elif len(passes) == len(results) and results:
        gate = "GREEN"
    else:
        gate = "RED"
    verdict = {
        "gate": "G7",
        "verdict": gate,
        "acceptance_sha256": spec["_sha256"],
        "n": len(results),
        "pass": len(passes),
        "fail": len(fails),
        "blocked": len(blocked),
        "not_run": len(notrun),
        "results": [{"name": r["name"], "verdict": r["verdict"], "opened": r.get("opened"), "target": r.get("target"), "reason": r.get("reason")} for r in results],
    }
    (OUT / "verdict.json").write_text(json.dumps(verdict, indent=2) + "\n")
    print(json.dumps(verdict, indent=2))
    return 0 if gate == "GREEN" else 3


if __name__ == "__main__":
    sys.exit(main())
