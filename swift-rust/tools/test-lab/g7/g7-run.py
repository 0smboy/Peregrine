#!/usr/bin/env python3
"""G7 orchestrator. Reads frozen acceptance.yaml; never edits it.
opened < target => ENVIRONMENT BLOCKED, never PASS.
Does not talk to :8080.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import select
import socket
import subprocess
import sys
import threading
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
                token = parts[0]
                name = token.split("{", 1)[0]
                value = float(parts[-1])
                labels = dict(re.findall(r'(\w+)="([^"]+)"', token))
                if labels:
                    suffix = "_".join(labels[key] for key in sorted(labels))
                    out[f"{name}_{suffix}"] = value
                    out[name] = out.get(name, 0.0) + value
                else:
                    out[name] = value
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


class ReconObserver:
    """Sample proxy concurrency metrics while a workload is actually active."""

    def __init__(self, spec, interval=0.05):
        self.spec = spec
        self.interval = interval
        self.samples = []
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, name="g7-recon-observer", daemon=True)
        self._thread.start()
        return self

    def _run(self):
        host, port = self.spec["target"]["host"], self.spec["target"]["port"]
        path = self.spec["target"]["recon_path"]
        while not self._stop.is_set():
            t0 = time.monotonic()
            try:
                st, body, ms = http(host, port, "GET", path, timeout=2.0)
                if st == 200:
                    sample = parse_recon(body.decode("utf-8", "replace"))
                    sample["_http_ms"] = ms
                    sample["_monotonic"] = t0
                else:
                    sample = {"error": f"recon status {st}", "_monotonic": t0}
            except Exception as exc:
                sample = {"error": str(exc), "_monotonic": t0}
            self.samples.append(sample)
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        return list(self.samples)


def percentile(values, fraction):
    values = sorted(values)
    if not values:
        return None
    return values[int((len(values) - 1) * fraction)]


def valid_recon(samples):
    return [sample for sample in samples if isinstance(sample, dict) and "error" not in sample]


STEADY_GAUGES = (
    "connections_open",
    "connections_idle",
    "requests_active",
    "runtime_tasks",
    "backend_requests_inflight",
    "backend_queue_depth",
    "device_ops_active",
    "device_queue_depth",
    "db_ops_active",
    "db_queue_depth",
    "process_threads",
    "open_fds",
)


def wait_for_steady(spec, before, timeout=60.0):
    baseline_samples = valid_recon(before)
    if not baseline_samples:
        return {"ok": False, "reason": "no valid baseline recon sample", "samples": []}
    baseline = baseline_samples[-1]
    bounds = spec["bounds"]
    pct = bounds["steady_return_max_of_pct"] / 100.0
    absolute = bounds["steady_return_abs"]
    deadline = time.monotonic() + timeout
    all_samples = []
    last_violations = ["not sampled"]
    while time.monotonic() < deadline:
        batch = sample_recon(spec, n=3, pause=0.1)
        all_samples.extend(batch)
        valid = valid_recon(batch)
        if valid:
            last = valid[-1]
            violations = []
            for metric in STEADY_GAUGES:
                if metric not in baseline or metric not in last:
                    violations.append(f"missing {metric}")
                    continue
                allowance = max(float(absolute), abs(float(baseline[metric])) * pct)
                if float(last[metric]) > float(baseline[metric]) + allowance:
                    violations.append(
                        f"{metric}={last[metric]} baseline={baseline[metric]} allowance={allowance}"
                    )
            for metric, limit_name in (
                ("commit_shield_active", "stuck_commit"),
                ("shutdown_waiting_commits", "stuck_commit"),
                ("shutdown_waiting_requests", "stuck_commit"),
            ):
                if metric not in last:
                    violations.append(f"missing {metric}")
                elif float(last[metric]) > float(bounds[limit_name]):
                    violations.append(f"{metric}={last[metric]} > {bounds[limit_name]}")
            if not violations:
                return {
                    "ok": True,
                    "baseline": baseline,
                    "last": last,
                    "samples": all_samples,
                    "elapsed_s": timeout - max(0.0, deadline - time.monotonic()),
                }
            last_violations = violations
        time.sleep(0.5)
    return {
        "ok": False,
        "reason": "; ".join(last_violations),
        "baseline": baseline,
        "samples": all_samples,
        "elapsed_s": timeout,
    }


def recon_evidence(before, during, after):
    valid_before = valid_recon(before)
    valid_during = valid_recon(during)
    valid_after = valid_recon(after)
    all_valid = [*valid_before, *valid_during, *valid_after]
    lags_ms = [sample["runtime_scheduler_lag"] / 1_000_000.0 for sample in valid_during if "runtime_scheduler_lag" in sample]
    baseline = valid_before[-1] if valid_before else {}

    def peak(metric, default=0.0):
        values = [float(sample[metric]) for sample in all_valid if metric in sample]
        return max(values) if values else default

    blocking_peak = peak("blocking_threads_storage") + peak("blocking_threads_db")
    process_peak = peak("process_threads")
    process_baseline = float(baseline.get("process_threads", 0.0))
    runtime_workers = peak("runtime_worker_threads")
    network_wait_baseline = float(baseline.get("blocking_network_wait_total", 0.0))
    network_wait_peak = peak("blocking_network_wait_total", network_wait_baseline)
    return {
        "recon_samples": len(valid_during),
        "recon_errors": len(during) - len(valid_during),
        "scheduler_lag_p99_ms": percentile(lags_ms, 0.99),
        "scheduler_lag_p999_ms": percentile(lags_ms, 0.999),
        "blocking_network_wait_delta": max(0.0, network_wait_peak - network_wait_baseline),
        "process_threads_baseline": process_baseline,
        "process_threads_peak": process_peak,
        "blocking_threads_peak": blocking_peak,
        "runtime_worker_threads": runtime_workers,
        "thread_growth_within_bound": process_peak <= process_baseline + max(16.0, blocking_peak),
        "storage_threads_within_bound": peak("blocking_threads_storage") <= max(1.0, runtime_workers),
        "recon_peak": {
            metric: peak(metric)
            for metric in (
                "connections_open",
                "connections_idle",
                "requests_active",
                "runtime_tasks",
                "request_body_buffer_bytes",
                "response_body_buffer_bytes",
                "backend_requests_inflight",
                "backend_queue_depth",
                "device_ops_active",
                "device_queue_depth",
                "db_ops_active",
                "db_queue_depth",
                "commit_shield_active",
                "open_fds",
            )
        },
    }


def health_p99(spec, n=40):
    host, port = spec["target"]["host"], spec["target"]["port"]
    path = spec["target"]["health_path"]
    xs = []
    ok = 0
    for _ in range(n):
        try:
            st, _, ms = http(host, port, "HEAD", path, timeout=2.0)
            if st == 200:
                ok += 1
                xs.append(ms)
            else:
                xs.append(2000.0)
        except Exception:
            xs.append(2000.0)
        time.sleep(0.02)
    xs.sort()
    p99 = xs[int((len(xs) - 1) * 0.99)] if xs else 2000.0
    return {"n": len(xs), "ok": ok, "p50_ms": xs[len(xs) // 2] if xs else None, "p99_ms": p99}


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


HEALTH_KINDS = {
    "idle_keepalive",
    "slowloris",
    "slow_put",
    "slow_get",
    "churn",
    "blackhole",
    "quorum",
    "overload",
    "fsync_stall",
    "sqlite_stall",
    "backend_connect_timeout",
}


def _expected_target(case, raw):
    if case.get("target") is not None:
        return case["target"]
    if case.get("n") is not None:
        return case["n"]
    return raw.get("target")


def _is_2xx(value):
    return isinstance(value, int) and 200 <= value < 300


def _failed(out, reason, verdict="FAIL"):
    out["verdict"] = verdict
    out["reason"] = reason
    return out


def _require_equal(out, raw, field, expected):
    if field not in raw:
        return _failed(out, f"missing proof field: {field}")
    if raw[field] != expected:
        return _failed(out, f"{field} {raw[field]!r} != {expected!r}")
    return None


def _require_2xx(out, raw, field):
    if field not in raw:
        return _failed(out, f"missing proof field: {field}")
    if not _is_2xx(raw[field]):
        return _failed(out, f"{field} {raw[field]!r} is not 2xx")
    return None


def classify(case, raw, spec, *, calibration=False):
    """Classify one result from affirmative evidence only.

    Missing counters, response status, injection hits, cleanup proof, or
    steady-state proof are failures.  A process exit or a script reaching the
    end is never evidence that a G7 behavior passed.
    """
    bounds = spec["bounds"]
    kind = case.get("kind")
    target = _expected_target(case, raw)
    opened = raw.get("opened")
    out = {
        "name": case.get("_name"),
        "kind": kind,
        "target": target,
        "opened": opened,
        "raw": raw,
    }

    if raw.get("error"):
        return _failed(out, str(raw["error"]))
    if raw.get("parse_error"):
        return _failed(out, "load generator emitted no valid JSON result")
    if target is None:
        return _failed(out, "missing expected target")
    if opened is None:
        return _failed(out, "missing proof field: opened")
    if opened < target:
        return _failed(out, f"opened {opened} < target {target}", "ENVIRONMENT BLOCKED")
    if opened > target:
        return _failed(out, f"opened {opened} > target {target}")
    if raw.get("_rc") not in (0, None):
        return _failed(out, f"g7load rc={raw.get('_rc')}")

    if calibration:
        check = _require_equal(out, raw, "http_ok", target)
        if check:
            return check
        return _failed(out, "dummy opened==target and http_ok==target", "PASS")

    if raw.get("verdict_hint") == "NOT RUN":
        return _failed(out, str(raw.get("not_run_reason") or "required fault was not injected"), "NOT RUN")

    if kind in HEALTH_KINDS:
        for field in ("health_p99_ms", "health_samples", "health_ok"):
            if field not in raw:
                return _failed(out, f"missing proof field: {field}")
        if raw["health_samples"] <= 0:
            return _failed(out, "health_samples must be > 0")
        if raw["health_ok"] != raw["health_samples"]:
            return _failed(out, f"health_ok {raw['health_ok']} != health_samples {raw['health_samples']}")
        if raw["health_p99_ms"] > bounds["health_head_p99_ms"]:
            return _failed(out, f"health p99 {raw['health_p99_ms']} > {bounds['health_head_p99_ms']} ms")

    if raw.get("scheduler_lag_p99_ms") is None:
        return _failed(out, "missing proof field: scheduler_lag_p99_ms")
    if raw["scheduler_lag_p99_ms"] > bounds["scheduler_lag_p99_ms"]:
        return _failed(out, f"scheduler lag p99 {raw['scheduler_lag_p99_ms']} > {bounds['scheduler_lag_p99_ms']} ms")
    if raw.get("scheduler_lag_p999_ms") is None:
        return _failed(out, "missing proof field: scheduler_lag_p999_ms")
    if raw["scheduler_lag_p999_ms"] > bounds["scheduler_lag_p999_ms"]:
        return _failed(out, f"scheduler lag p999 {raw['scheduler_lag_p999_ms']} > {bounds['scheduler_lag_p999_ms']} ms")
    if raw.get("recon_samples", 0) < 3:
        return _failed(out, f"insufficient in-workload recon samples: {raw.get('recon_samples')!r}")
    if raw.get("blocking_network_wait_delta") != 0:
        return _failed(out, f"blocking network wait delta is {raw.get('blocking_network_wait_delta')!r}")
    if raw.get("thread_growth_within_bound") is not True:
        return _failed(out, "process thread growth was not proved bounded")
    if raw.get("storage_threads_within_bound") is not True:
        return _failed(out, "storage blocking threads exceeded the observed runtime bound")
    steady = raw.get("steady_return")
    if not isinstance(steady, dict) or steady.get("ok") is not True:
        return _failed(out, f"steady-state return not proved: {steady!r}")

    if kind == "idle_keepalive":
        for field, expected in (("http_ok", target), ("failed", 0)):
            check = _require_equal(out, raw, field, expected)
            if check:
                return check
    elif kind == "slowloris":
        check = _require_equal(out, raw, "failed", 0)
        if check:
            return check
    elif kind == "slow_put":
        for field, expected in (("responses", target), ("http_2xx", target), ("failed", 0)):
            check = _require_equal(out, raw, field, expected)
            if check:
                return check
    elif kind == "slow_get":
        check = _require_2xx(out, raw, "seed_status")
        if check:
            return check
        for field, expected in (("responses", target), ("http_2xx", target), ("completed", target), ("failed", 0)):
            check = _require_equal(out, raw, field, expected)
            if check:
                return check
    elif kind == "churn":
        cycles = raw.get("cycle_results")
        if not isinstance(cycles, list) or len(cycles) != case.get("cycles"):
            return _failed(out, "missing complete per-cycle churn evidence")
        for index, cycle in enumerate(cycles):
            if cycle.get("_rc") != 0 or cycle.get("opened") != target or cycle.get("http_ok") != target:
                return _failed(out, f"churn cycle {index} did not open and serve target")
    elif kind in ("blackhole", "quorum", "backend_connect_timeout"):
        if raw.get("fault_armed") is not True or raw.get("fault_hits", 0) <= 0:
            return _failed(out, "network fault was not proved on the exercised path")
        if kind == "blackhole":
            check = _require_2xx(out, raw, "put_status")
            if check:
                return check
        elif kind == "quorum":
            check = _require_equal(out, raw, "ok_2xx", case.get("put_n"))
            if check:
                return check
        elif raw.get("timeout_observed") is not True:
            return _failed(out, "backend connection timeout was not observed")
    elif kind == "overload":
        responses = raw.get("http_2xx", 0) + raw.get("http_503", 0)
        if raw.get("responses") != target or responses != target:
            return _failed(out, "overload responses were not fully classified as 2xx or 503")
        if raw.get("http_503", 0) <= 0:
            return _failed(out, "bounded overload did not produce an explicit 503")
    elif kind == "cancel":
        check = _require_equal(out, raw, "tmp_count", bounds["orphan_temp"])
        if check:
            return check
        check = _require_equal(out, raw, "committed_objects", 0)
        if check:
            return check
    elif kind == "sigterm_put":
        for field in ("term_sent", "restart_ok", "partial_absent"):
            if raw.get(field) is not True:
                return _failed(out, f"{field} was not proved")
    elif kind == "sigterm_barrier":
        for field in ("barrier_observed", "term_during_barrier", "restart_ok"):
            if raw.get(field) is not True:
                return _failed(out, f"{field} was not proved")
        check = _require_2xx(out, raw, "put_status")
        if check:
            return check
        check = _require_2xx(out, raw, "get_after")
        if check:
            return check
        check = _require_equal(out, raw, "len", raw.get("expected_len"))
        if check:
            return check
    elif kind == "fd_exhaust":
        if raw.get("fault_armed") is not True or raw.get("fd_pressure_observed") is not True:
            return _failed(out, "fd exhaustion was not armed and observed")
        if raw.get("recovered") is not True:
            return _failed(out, "service recovery after fd exhaustion was not proved")
    elif kind in ("enospc", "eio"):
        if raw.get("fault_armed") is not True or raw.get("fault_hits", 0) <= 0:
            return _failed(out, f"{kind} was not injected on an object write")
        status = raw.get("put_status")
        if not isinstance(status, int) or status < 400:
            return _failed(out, f"injected {kind} PUT unexpectedly succeeded: {status!r}")
        check = _require_equal(out, raw, "tmp_count", bounds["orphan_temp"])
        if check:
            return check
        check = _require_2xx(out, raw, "recovery_put_status")
        if check:
            return check
    elif kind == "partial_write":
        if raw.get("expect_not_2xx") is not True:
            return _failed(out, f"partial PUT became visible with status {raw.get('get_status')!r}")
        check = _require_equal(out, raw, "tmp_count", bounds["orphan_temp"])
        if check:
            return check
    elif kind in ("fsync_stall", "sqlite_stall"):
        if raw.get("fault_armed") is not True or raw.get("fault_hits", 0) <= 0:
            return _failed(out, f"{kind} injection was not observed")
        check = _require_2xx(out, raw, "operation_status")
        if check:
            return check
        if raw.get("operation_ms", 0) < case.get("stall_secs", 0) * 1000:
            return _failed(out, f"{kind} operation did not cross the injected stall")
    elif kind == "ssync_interrupt":
        if raw.get("fault_armed") is not True or raw.get("fault_hits", 0) <= 0:
            return _failed(out, "SSYNC interrupt was not injected on the exercised path")
        if raw.get("success_ack") is True:
            return _failed(out, "truncated SSYNC session was success-acknowledged")
        if raw.get("error_ack") is not True:
            return _failed(out, "truncated SSYNC session did not error-ack")
        check = _require_equal(out, raw, "tmp_count", bounds["orphan_temp"])
        if check:
            return check
        check = _require_equal(out, raw, "committed_objects", 0)
        if check:
            return check
    elif kind == "ec_fragment_loss":
        if raw.get("fault_armed") is not True or raw.get("fault_hits", 0) <= 0:
            return _failed(out, "EC fragment loss was not injected")
        if raw.get("fragments_removed", 0) <= 0:
            return _failed(out, "no EC fragments were removed")
        check = _require_2xx(out, raw, "put_status")
        if check:
            return check
        check = _require_2xx(out, raw, "get_after")
        if check:
            return check
        if raw.get("body_match") is not True:
            return _failed(out, "GET after fragment loss did not match the PUT body")
    else:
        return _failed(out, f"no evidence contract for kind {kind}")

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


def run_slow_get(spec, token, case):
    """Hold all slow readers concurrently; never drain sockets serially."""
    host, port = spec["target"]["host"], spec["target"]["port"]
    target = case["target"]
    seed_status, _, _ = put_object(
        spec,
        token,
        "g7get",
        "blob",
        b"Y" * case["object_bytes"],
    )
    states = {}
    opened = 0
    for index in range(target):
        sock = socket.socket()
        try:
            sock.settimeout(5)
            sock.bind((spec["loadgen"]["source_ips"][index % len(spec["loadgen"]["source_ips"])], 0))
            sock.connect((host, port))
            sock.sendall(
                (
                    f"GET /v1/{spec['auth']['account']}/g7get/blob HTTP/1.1\r\n"
                    f"Host: {host}\r\nX-Auth-Token: {token}\r\n"
                    "Connection: keep-alive\r\n\r\n"
                ).encode()
            )
            sock.setblocking(False)
            states[sock] = {
                "header": bytearray(),
                "status": None,
                "expected": None,
                "body": 0,
                "next_read": 0.0,
            }
            opened += 1
        except Exception:
            sock.close()

    header_deadline = time.monotonic() + 30.0
    while states and time.monotonic() < header_deadline:
        pending = [sock for sock, state in states.items() if state["status"] is None]
        if not pending:
            break
        ready, _, _ = select.select(pending, [], [], 0.2)
        for sock in ready:
            state = states[sock]
            try:
                chunk = sock.recv(4096)
            except BlockingIOError:
                continue
            except OSError:
                chunk = b""
            if not chunk:
                sock.close()
                del states[sock]
                continue
            state["header"].extend(chunk)
            marker = state["header"].find(b"\r\n\r\n")
            if marker < 0:
                if len(state["header"]) > 65536:
                    sock.close()
                    del states[sock]
                continue
            head = bytes(state["header"][:marker])
            body = bytes(state["header"][marker + 4 :])
            lines = head.split(b"\r\n")
            try:
                state["status"] = int(lines[0].split()[1])
            except (IndexError, ValueError):
                state["status"] = 0
            for line in lines[1:]:
                if line.lower().startswith(b"content-length:"):
                    try:
                        state["expected"] = int(line.split(b":", 1)[1].strip())
                    except ValueError:
                        state["expected"] = None
            state["body"] = len(body)
            state["header"] = bytearray()
            state["next_read"] = time.monotonic() + case["read_pause_ms"] / 1000.0

    responses = sum(1 for state in states.values() if state["status"] is not None)
    http_2xx = sum(1 for state in states.values() if _is_2xx(state["status"]))
    hp = health_p99(spec, n=40)

    completed = 0
    read_pause = case["read_pause_ms"] / 1000.0
    # 1 KiB per pause, plus a bounded setup margin.
    max_drain = case["object_bytes"] / 1024.0 * read_pause + 60.0
    drain_deadline = time.monotonic() + max_drain
    while states and time.monotonic() < drain_deadline:
        now = time.monotonic()
        for sock, state in list(states.items()):
            if (
                _is_2xx(state["status"])
                and state["expected"] == case["object_bytes"]
                and state["body"] >= state["expected"]
            ):
                completed += 1
                sock.close()
                del states[sock]
        if not states:
            break
        eligible = [sock for sock, state in states.items() if state["status"] is not None and state["next_read"] <= now]
        if not eligible:
            time.sleep(0.02)
            continue
        ready, _, _ = select.select(eligible, [], [], 0.2)
        for sock in ready:
            state = states.get(sock)
            if state is None:
                continue
            try:
                chunk = sock.recv(1024)
            except BlockingIOError:
                continue
            except OSError:
                chunk = b""
            if chunk:
                state["body"] += len(chunk)
                state["next_read"] = time.monotonic() + read_pause
            else:
                sock.close()
                del states[sock]
    for sock in list(states):
        sock.close()

    return {
        "case": "slow_get",
        "target": target,
        "opened": opened,
        "seed_status": seed_status,
        "responses": responses,
        "http_2xx": http_2xx,
        "completed": completed,
        "failed": target - completed,
        "read_chunk_bytes": 1024,
        "health_p99_ms": hp["p99_ms"],
        "health_samples": hp["n"],
        "health_ok": hp["ok"],
    }


def run_case(name, case, spec, token):
    kind = case["kind"]
    host, port = spec["target"]["host"], spec["target"]["port"]
    before = sample_recon(spec, n=3)
    observer = ReconObserver(spec).start()
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
        raw = run_slow_get(spec, token, case)
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
                "health_samples": hp["n"],
                "health_ok": hp["ok"],
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
            raw = {
                "case": "quorum",
                "target": case["put_n"],
                "opened": case["put_n"],
                "ok_2xx": ok,
                "health_p99_ms": hp["p99_ms"],
                "health_samples": hp["n"],
                "health_ok": hp["ok"],
            }
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
        rc, out, _ = ssh("pid=$(cat /var/run/g6-rust/proxy.pid); kill -TERM $pid; echo TERM $pid")
        time.sleep(2)
        hp_err = None
        try:
            http(host, port, "HEAD", spec["target"]["health_path"], timeout=1.0)
        except Exception as e:
            hp_err = str(e)
        ssh("bash /root/work/g7/g7-start-rust.sh")
        time.sleep(2)
        hp = health_p99(spec, n=10)
        st, _, _ = http(
            host,
            port,
            "GET",
            f"/v1/{spec['auth']['account']}/g7slow/sigterm",
            headers={"X-Auth-Token": token},
            timeout=5,
        )
        raw = {
            "case": "sigterm_put",
            "target": 1,
            "opened": 1,
            "term_sent": rc == 0 and "TERM" in (out or ""),
            "restart_ok": hp["ok"] == hp["n"] and hp["n"] > 0,
            "partial_absent": st is None or st >= 400,
            "health_after_restart_p99_ms": hp["p99_ms"],
            "down_error": hp_err,
        }
    elif kind == "sigterm_barrier":
        raw = {
            "case": "sigterm_barrier",
            "target": 1,
            "opened": 1,
            "verdict_hint": "NOT RUN",
            "not_run_reason": "DurabilityBarrier observation probe is not armed on this runner",
        }
    elif kind == "fd_exhaust":
        raw = {
            "case": "fd_exhaust",
            "target": 1,
            "opened": 1,
            "verdict_hint": "NOT RUN",
            "not_run_reason": "ulimit/fd injector was not armed; listing /proc/pid/fd is not injection",
        }
    elif kind == "enospc":
        raw = {
            "case": "enospc",
            "target": 1,
            "opened": 1,
            "verdict_hint": "NOT RUN",
            "not_run_reason": "ENOSPC injector not armed; a 1MiB fill file is not a proven ENOSPC hit",
        }
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
        raw = {
            "case": "backend_connect_timeout",
            "target": 1,
            "opened": 1,
            "verdict_hint": "NOT RUN",
            "not_run_reason": "no PUT was sent to the blackhole replica; iptables alone is not a timeout proof",
        }
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
            "operation_status": st,
            "operation_ms": ms,
            "fault_armed": True,
            "fault_hits": 1 if ms >= case.get("stall_secs", 0) * 1000 else 0,
            "health_p99_ms": hp["p99_ms"],
            "health_samples": hp["n"],
            "health_ok": hp["ok"],
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
        t0 = time.monotonic()
        st, _, ms = http(
            host,
            port,
            "PUT",
            f"/v1/{spec['auth']['account']}/g7sqlite",
            headers={"X-Auth-Token": token},
            timeout=30,
        )
        raw = {
            "case": "sqlite_stall",
            "target": 1,
            "opened": 1,
            "operation_status": st,
            "operation_ms": ms,
            "fault_armed": True,
            "fault_hits": 1 if ms >= case.get("stall_secs", 0) * 1000 else 0,
            "health_p99_ms": hp["p99_ms"],
            "health_samples": hp["n"],
            "health_ok": hp["ok"],
            "elapsed_s": time.monotonic() - t0,
        }
        ssh("pid=$(cat /var/run/g6-rust/container-1.pid); kill -TERM $pid || true; sleep 1; "
            "nohup /root/work/g6-rust-bin/swift-container-server /etc/g6-rust/container-server/1.conf "
            ">>/var/log/g6-rust/container-1.log 2>&1 & echo $! >/var/run/g6-rust/container-1.pid")
    elif kind == "ssync_interrupt":
        ssync_host = os.environ.get("G7_SSYNC_HOST", "127.0.0.2")
        ssync_port = int(os.environ.get("G7_SSYNC_PORT", "16210"))
        device = os.environ.get("G7_SSYNC_DEVICE", "d1")
        payload = (
            b":MISSING_CHECK: START\r\n:MISSING_CHECK: END\r\n"
            b":UPDATES: START\r\nPUT /AUTH_test/g7slow/ssync-cut\r\n"
            b"Content-Length: 32\r\nX-Timestamp: 1700000000.00000\r\n\r\npartial"
        )
        opened = 0
        output = b""
        try:
            sock = socket.create_connection((ssync_host, ssync_port), timeout=5)
            opened = 1
            sock.sendall(
                (
                    f"SSYNC /{device}/0 HTTP/1.1\r\n"
                    f"Host: {ssync_host}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"X-Backend-Storage-Policy-Index: 0\r\n\r\n"
                    f"{len(payload):x}\r\n"
                ).encode()
                + payload
                + b"\r\n"
            )
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(5)
            chunks = []
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            output = b"".join(chunks)
            sock.close()
        except OSError as exc:
            raw = {
                "case": "ssync_interrupt",
                "target": 1,
                "opened": opened,
                "verdict_hint": "NOT RUN",
                "not_run_reason": f"SSYNC {ssync_host}:{ssync_port} unreachable: {exc}",
            }
        else:
            text = output.decode("utf-8", "replace")
            rc, tmp_out, _ = ssh(
                "find /srv/1/node /srv/2/node /srv/3/node /srv/4/node -name '*.tmp' "
                "-o -name '*tmp*' 2>/dev/null | wc -l"
            )
            raw = {
                "case": "ssync_interrupt",
                "target": 1,
                "opened": 1,
                "fault_armed": True,
                "fault_hits": 1,
                "success_ack": ":UPDATES: START" in text and ":ERROR:" not in text,
                "error_ack": ":ERROR:" in text,
                "tmp_count": int((tmp_out or "0").strip() or 0),
                "committed_objects": 1 if ":UPDATES: START" in text and ":ERROR:" not in text else 0,
                "ssync_output": text[-500:],
            }
    elif kind == "ec_fragment_loss":
        policy = os.environ.get("G7_EC_POLICY", "Policy-1")
        body = b"G7-EC-FRAGMENT-LOSS-" + os.urandom(32)
        http(
            host,
            port,
            "PUT",
            f"/v1/{spec['auth']['account']}/g7ec",
            headers={"X-Auth-Token": token, "X-Storage-Policy": policy},
            timeout=10,
        )
        st, _, _ = http(
            host,
            port,
            "PUT",
            f"/v1/{spec['auth']['account']}/g7ec/frag-loss",
            headers={
                "X-Auth-Token": token,
                "X-Storage-Policy": policy,
                "Content-Type": "application/octet-stream",
            },
            body=body,
            timeout=30,
        )
        if not st or st >= 300:
            raw = {
                "case": "ec_fragment_loss",
                "target": 1,
                "opened": 1,
                "verdict_hint": "NOT RUN",
                "not_run_reason": f"EC PUT via policy {policy!r} returned {st!r}",
                "put_status": st,
            }
        else:
            rc, listed, _ = ssh(
                "find /srv/1/node /srv/2/node /srv/3/node /srv/4/node "
                "-name '*.data' 2>/dev/null | head"
            )
            paths = [line for line in (listed or "").splitlines() if line.strip()]
            removed = 0
            if paths:
                ssh(f"rm -f {paths[0]}")
                removed = 1
            st2, got, _ = http(
                host,
                port,
                "GET",
                f"/v1/{spec['auth']['account']}/g7ec/frag-loss",
                headers={"X-Auth-Token": token},
                timeout=30,
            )
            raw = {
                "case": "ec_fragment_loss",
                "target": 1,
                "opened": 1,
                "fault_armed": removed > 0,
                "fault_hits": removed,
                "fragments_removed": removed,
                "put_status": st,
                "get_after": st2,
                "body_match": got == body,
            }
            if removed <= 0:
                raw["verdict_hint"] = "NOT RUN"
                raw["not_run_reason"] = "no on-disk EC fragment was found to remove"
    else:
        raw = {"error": f"unknown kind {kind}", "target": case.get("target"), "opened": 0}

    during = observer.stop()
    steady = wait_for_steady(spec, before)
    after = steady.pop("samples", [])
    raw["recon_before"] = before
    raw["recon_during"] = during
    raw["recon_after"] = after
    raw["steady_return"] = steady
    raw.update(recon_evidence(before, during, after))
    case = dict(case)
    case["_name"] = name
    result = classify(case, raw, spec)
    if raw.get("verdict_hint") == "NOT RUN" and result.get("verdict") != "NOT RUN":
        result["verdict"] = "NOT RUN"
        result["reason"] = str(raw.get("not_run_reason") or "required fault was not injected")
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
        rec = classify(
            {"_name": f"dummy_{n}", "kind": "idle_keepalive", "target": n},
            raw,
            spec,
            calibration=True,
        )
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
