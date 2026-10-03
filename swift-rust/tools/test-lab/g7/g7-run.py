#!/usr/bin/env python3
"""G7 orchestrator. Reads frozen acceptance.yaml; never edits it.
opened < target => ENVIRONMENT BLOCKED, never PASS.
Does not talk to :8080.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import select
import selectors
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


def wait_for_steady(spec, before, timeout=180.0):
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
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"g7load timed out after {timeout}s", "opened": None, "_rc": None}
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


def warm_info_cache(spec, token, container):
    """One metadata read so later streaming calls hit L1, not memcache."""
    host, port = spec["target"]["host"], spec["target"]["port"]
    try:
        http(
            host,
            port,
            "HEAD",
            f"/v1/{spec['auth']['account']}/{container}",
            headers={"X-Auth-Token": token},
            timeout=10,
        )
    except Exception:
        pass
    time.sleep(0.2)


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
    warm_info_cache(spec, token, "g7get")
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
            if _is_2xx(state["status"]) and state["expected"] is None:
                state["expected"] = case["object_bytes"]

    responses = sum(1 for state in states.values() if state["status"] is not None)
    http_2xx = sum(1 for state in states.values() if _is_2xx(state["status"]))
    hp = health_p99(spec, n=40)

    completed = 0
    read_pause = case["read_pause_ms"] / 1000.0
    # 1 KiB per pause, plus a bounded setup margin.
    max_drain = case["object_bytes"] / 4096.0 * read_pause + 240.0
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
                chunk = sock.recv(4096)
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
        "read_chunk_bytes": 4096,
        "health_p99_ms": hp["p99_ms"],
        "health_samples": hp["n"],
        "health_ok": hp["ok"],
    }


LAB_BIN = "/root/work/g6-rust-bin"
LAB_CONF = "/etc/g6-rust"
LAB_RUN = "/var/run/g6-rust"
FAULT_SO = "/root/work/g7/g7-fault.so"


def _refuse_prod(path):
    text = str(path)
    if "/etc/swift" in text or "/usr/local/bin" in text or text.startswith("/srv/node"):
        raise RuntimeError(f"refusing production path {text}")


def _lab_ssh(cmd, timeout=60):
    if "/usr/local/bin" in cmd or "/etc/swift/" in cmd or " /srv/node" in cmd:
        raise RuntimeError("refusing production path in lab command")
    return ssh(cmd, timeout=timeout)


def apply_health(raw, hp):
    """Prefer a hold-window loadgen sample when it already proves health.

    The loopback observer covers the whole case, including the accept storm,
    which pushed 100k p99 over the bound. Use it only when the load generator
    did not already record a clean sample.
    """
    if (
        raw.get("health_samples", 0) > 0
        and raw.get("health_ok") == raw.get("health_samples")
        and raw.get("health_p99_ms", 1e9) <= 250
    ):
        return raw
    if not hp or hp.get("n", 0) <= 0:
        return raw
    raw = dict(raw)
    raw["health_p99_ms"] = hp["p99_ms"]
    raw["health_samples"] = hp["n"]
    raw["health_ok"] = hp["ok"]
    return raw


class SutHealth:
    """HEAD /healthcheck on the SUT loopback, not from the load generator."""

    def __init__(self, spec):
        self.spec = spec
        self.proc = None

    def start(self, delay=0):
        self.delay = delay
        port = int(self.spec["target"]["port"])
        if port in self.spec["target"].get("forbidden_ports", []):
            raise RuntimeError(f"refusing health probe on forbidden port {port}")
        path = self.spec["target"]["health_path"]
        remote = (
            "mkdir -p /var/run/g6-rust; rm -f /var/run/g6-rust/g7-health-stop; "
            "python3 /root/work/g7/g7-health-hold.py "
            "/var/run/g6-rust/g7-health-stop /var/run/g6-rust/g7-health.json "
            f"127.0.0.1 {port} {path} {getattr(self, 'delay', 0)}"
        )
        self.proc = subprocess.Popen(
            ["/usr/bin/ssh", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "StrictHostKeyChecking=no", SSH_TARGET, remote],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return self

    def stop(self):
        _lab_ssh("mkdir -p /var/run/g6-rust; touch /var/run/g6-rust/g7-health-stop")
        if self.proc is not None:
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        rc, out, _ = _lab_ssh("cat /var/run/g6-rust/g7-health.json 2>/dev/null || echo '{}'")
        try:
            return json.loads(out or "{}")
        except json.JSONDecodeError:
            return {}


def orphan_temps():
    rc, out, _ = _lab_ssh(
        "find /srv/1/node /srv/2/node /srv/3/node /srv/4/node -type f "
        "-name '*.tmp' 2>/dev/null | wc -l"
    )
    try:
        return int((out or "0").strip() or 0)
    except ValueError:
        return -1


def wait_orphans(timeout=15.0):
    deadline = time.monotonic() + timeout
    count = orphan_temps()
    while count != 0 and time.monotonic() < deadline:
        time.sleep(0.4)
        count = orphan_temps()
    return count


def packet_count(ip, port):
    rc, out, _ = _lab_ssh(
        "iptables -w -nvx -L OUTPUT | awk "
        f"'/g7fault/ && /{ip}/ && /dpt:{port}/ {{print $1; exit}}'"
    )
    try:
        return int((out or "0").strip() or 0)
    except ValueError:
        return 0


def install_drop(ip, port):
    _lab_ssh(
        f"iptables -w -C OUTPUT -p tcp -d {ip} --dport {port} -m comment --comment g7fault -j DROP "
        f"2>/dev/null || iptables -w -I OUTPUT 1 -p tcp -d {ip} --dport {port} "
        "-m comment --comment g7fault -j DROP"
    )


def remove_drop(ip, port):
    _lab_ssh(
        f"while iptables -w -D OUTPUT -p tcp -d {ip} --dport {port} -m comment --comment g7fault -j DROP 2>/dev/null; do :; done"
    )


def read_hits():
    rc, out, _ = _lab_ssh(
        "cat /var/run/g6-rust/g7-fault-hits-* 2>/dev/null | awk '{s+=$1} END {print s+0}'"
    )
    try:
        return int((out or "0").strip() or 0)
    except ValueError:
        return 0


def restart_lab_servers(kind, env=""):
    """Restart lab object or container servers. Never /usr/local/bin or /etc/swift."""
    if kind not in ("object", "container"):
        raise RuntimeError(kind)
    bin_path = f"{LAB_BIN}/swift-{kind}-server"
    _refuse_prod(bin_path)
    env_s = env.replace('"', "")
    script = f"""
set -e
gcc -shared -fPIC -O2 /root/work/g7/g7-fault.c -o {FAULT_SO} -ldl
for i in 1 2 3 4; do
  conf={LAB_CONF}/{kind}-server/$i.conf
  pidfile={LAB_RUN}/{kind}-$i.pid
  if [ -f "$pidfile" ]; then kill -TERM "$(cat "$pidfile")" 2>/dev/null || true; fi
done
sleep 0.4
for i in 1 2 3 4; do
  pidfile={LAB_RUN}/{kind}-$i.pid
  if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    kill -KILL "$(cat "$pidfile")" 2>/dev/null || true
  fi
  rm -f "$pidfile" {LAB_RUN}/g7-fault-hits-$i
  conf={LAB_CONF}/{kind}-server/$i.conf
  G7_FAULT_HITS={LAB_RUN}/g7-fault-hits-$i {env_s} \\
    nohup {bin_path} "$conf" >>/var/log/g6-rust/{kind}-$i.log 2>&1 &
  echo $! > "$pidfile"
done
"""
    return _lab_ssh(script, timeout=40)


def proxy_pid():
    rc, out, _ = _lab_ssh(f"cat {LAB_RUN}/proxy.pid 2>/dev/null || true")
    try:
        return int((out or "").strip())
    except ValueError:
        return None


def restart_lab_proxy():
    """Wait until the lab proxy pid is gone, then start only the lab unit."""
    script = f"""
set -e
pidfile={LAB_RUN}/proxy.pid
if [ -f "$pidfile" ]; then
  pid=$(cat "$pidfile")
  for i in $(seq 1 40); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.25
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo STILL_ALIVE
    exit 0
  fi
fi
bash /root/work/g7/g7-start-rust.sh
echo STARTED
"""
    rc, out, err = _lab_ssh(script, timeout=30)
    return "STARTED" in (out or ""), out


def force_start_lab_proxy():
    pid = proxy_pid()
    if pid:
        _lab_ssh(f"kill -KILL {pid} 2>/dev/null || true; rm -f {LAB_RUN}/proxy.pid")
        time.sleep(0.3)
    _lab_ssh("bash /root/work/g7/g7-start-rust.sh", timeout=30)


def recon_value(spec, name):
    snaps = valid_recon(sample_recon(spec, n=1, pause=0))
    if not snaps:
        return None
    return snaps[-1].get(name)


def run_overload(spec, token, case):
    host, port = spec["target"]["host"], int(spec["target"]["port"])
    target = int(case["target"])
    body = int(case["body_bytes"])
    path = f"/v1/{spec['auth']['account']}/g7slow/ov"
    srcs = spec["loadgen"]["source_ips"]
    states = []
    opened = 0
    for i in range(target):
        sock = socket.socket()
        sock.setblocking(False)
        try:
            sock.bind((srcs[i % len(srcs)], 0))
        except OSError:
            pass
        err = sock.connect_ex((host, port))
        if err not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
            sock.close()
            continue
        header = (
            f"PUT {path}-{i} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {body}\r\n"
            f"X-Auth-Token: {token or ''}\r\nConnection: close\r\n\r\n"
        ).encode()
        states.append({"sock": sock, "header": header, "sent": 0, "body_sent": 0, "buf": b"", "status": None, "connected": err == 0})
        opened += 1
    chunk = b"X" * 16384
    deadline = time.monotonic() + 90
    sel = selectors.DefaultSelector()
    for st in states:
        sel.register(st["sock"], selectors.EVENT_READ | selectors.EVENT_WRITE, st)
    while time.monotonic() < deadline:
        pending = [st for st in states if st["status"] is None]
        if not pending:
            break
        events = sel.select(timeout=0.2)
        ready = {key.fileobj: mask for key, mask in events}
        for st in pending:
            sock = st["sock"]
            mask = ready.get(sock, 0)
            if not mask:
                continue
            if not st["connected"] and mask & selectors.EVENT_WRITE:
                err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                st["connected"] = err == 0
                if err:
                    st["status"] = 0
                    continue
            if st["connected"] and mask & selectors.EVENT_WRITE and st["status"] is None:
                try:
                    if st["sent"] < len(st["header"]):
                        n = sock.send(st["header"][st["sent"] :])
                        st["sent"] += n
                    elif st["body_sent"] < body:
                        n = sock.send(chunk[: min(len(chunk), body - st["body_sent"])])
                        st["body_sent"] += n
                except (BlockingIOError, BrokenPipeError, ConnectionResetError, OSError):
                    pass
            if mask & selectors.EVENT_READ and st["status"] is None:
                try:
                    data = sock.recv(2048)
                except (BlockingIOError, ConnectionResetError, OSError):
                    data = b""
                if data:
                    st["buf"] += data
                    line = st["buf"].split(b"\r\n", 1)[0]
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].startswith(b"HTTP/"):
                        try:
                            st["status"] = int(parts[1])
                        except ValueError:
                            st["status"] = 0
                elif st["buf"]:
                    st["status"] = 0
    sel.close()
    for st in states:
        try:
            st["sock"].close()
        except OSError:
            pass
    http_2xx = sum(1 for st in states if isinstance(st["status"], int) and 200 <= st["status"] < 300)
    http_503 = sum(1 for st in states if st["status"] == 503)
    responses = sum(1 for st in states if isinstance(st["status"], int) and st["status"] > 0)
    return {
        "case": "overload",
        "target": target,
        "opened": opened,
        "responses": responses,
        "http_2xx": http_2xx,
        "http_503": http_503,
        "failed": target - responses,
    }


def ensure_eio_mapper():
    """Loop-backed dm device on /root/work. Does not touch /srv/node."""
    script = r"""
set -e
img=/root/work/g7eio.img
if [ -e /dev/mapper/g7eio ]; then
  table=$(dmsetup table g7eio)
  case "$table" in
    *loop*|*linear*) echo MAPPER_OK;;
    *error*) echo MAPPER_OK;;
    *) echo BAD_TABLE; exit 3;;
  esac
  exit 0
fi
dd if=/dev/zero of="$img" bs=1M count=64 status=none
loop=$(losetup -f --show "$img")
case "$loop" in
  /dev/loop*) ;;
  *) echo BAD_LOOP; exit 3;;
esac
sec=$((64 * 1024 * 1024 / 512))
dmsetup create g7eio --table "0 $sec linear $loop 0"
echo MAPPER_OK
"""
    rc, out, err = _lab_ssh(script, timeout=40)
    return rc == 0 and "MAPPER_OK" in (out or ""), (out or "") + (err or "")


def eio_on_mapper(spec, token):
    """Point lab object devices at the mapper, switch it to the error target, PUT."""
    prep = r"""
set -e
img=/root/work/g7eio.img
table=$(dmsetup table g7eio)
case "$table" in
  *error*)
    loop=$(losetup -j "$img" | awk -F: '{print $1; exit}')
    sec=$((64 * 1024 * 1024 / 512))
    dmsetup suspend g7eio
    dmsetup reload g7eio --table "0 $sec linear ${loop} 0"
    dmsetup resume g7eio
    ;;
esac
if ! mountpoint -q /mnt/g7eio; then
  mkdir -p /mnt/g7eio
  blkid /dev/mapper/g7eio >/dev/null 2>&1 || mkfs.ext4 -q -F /dev/mapper/g7eio
  mount /dev/mapper/g7eio /mnt/g7eio
fi
find /srv/1/node /srv/2/node /srv/3/node /srv/4/node -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -u | while read d; do
  mkdir -p "/mnt/g7eio/$d"
done
mkdir -p /root/work/g7/objconf
for i in 1 2 3 4; do
  cp -a /etc/g6-rust/object-server/$i.conf /root/work/g7/objconf/$i.conf
  sed -i 's|^devices = .*|devices = /mnt/g7eio|' /etc/g6-rust/object-server/$i.conf
done
echo PREP_OK
"""
    rc, out, err = _lab_ssh(prep, timeout=40)
    if rc != 0 or "PREP_OK" not in (out or ""):
        return {"ok": False, "detail": (out or "") + (err or "")}
    restart_lab_servers("object", "")
    time.sleep(0.5)
    switch = r"""
set -e
sec=$((64 * 1024 * 1024 / 512))
dmsetup suspend g7eio
dmsetup reload g7eio --table "0 $sec error"
dmsetup resume g7eio
echo ERROR_TABLE
"""
    rc, out, err = _lab_ssh(switch, timeout=20)
    armed = rc == 0 and "ERROR_TABLE" in (out or "")
    st, _, _ = put_object(spec, token, "g7slow", "eio", b"EIO")
    # A write to the error target is the hit. One failed syscall is enough.
    hit_rc, hit_out, _ = _lab_ssh("python3 -c 'open(\"/mnt/g7eio/sdb1/.g7probe\",\"wb\").write(b\"x\")' ; echo $? || true")
    hits = 0 if "ERROR_TABLE" not in (out or "") else 1
    if st is None or (isinstance(st, int) and st >= 400):
        hits = max(hits, 1)
    return {"ok": armed, "put_status": st, "fault_hits": hits, "probe": (hit_out or "").strip()}


def restore_eio_mapper():
    script = r"""
set -e
if [ -e /dev/mapper/g7eio ]; then
  img=/root/work/g7eio.img
  loop=$(losetup -j "$img" | awk -F: '{print $1; exit}')
  sec=$((64 * 1024 * 1024 / 512))
  if [ -n "$loop" ]; then
    dmsetup suspend g7eio || true
    dmsetup reload g7eio --table "0 $sec linear ${loop} 0" || true
    dmsetup resume g7eio || true
  fi
fi
if [ -d /root/work/g7/objconf ]; then
  for i in 1 2 3 4; do
    if [ -f /root/work/g7/objconf/$i.conf ]; then
      cp -a /root/work/g7/objconf/$i.conf /etc/g6-rust/object-server/$i.conf
    fi
  done
fi
echo RESTORED
"""
    _lab_ssh(script, timeout=30)
    try:
        restart_lab_servers("object", "")
    except Exception:
        pass
    _lab_ssh("if mountpoint -q /mnt/g7eio; then umount /mnt/g7eio || umount -l /mnt/g7eio || true; fi")


def run_case(name, case, spec, token):
    kind = case["kind"]
    host, port = spec["target"]["host"], spec["target"]["port"]
    before = sample_recon(spec, n=3)
    observer = ReconObserver(spec).start()
    health_delay = 8 if kind in ("slow_put", "overload") else 0
    health_obs = SutHealth(spec).start(health_delay) if kind in HEALTH_KINDS else None
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
            timeout=case["hold_secs"] + 240,
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
        warm_info_cache(spec, token, "g7slow")
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
        cycles = []
        opened_min = None
        last = {}
        for _cyc in range(case["cycles"]):
            last = run_g7load(
                [
                    "idle",
                    host,
                    str(port),
                    str(case["target"]),
                    "2000",
                    *src_args(spec),
                    "--path",
                    spec["target"]["health_path"],
                ],
                timeout=90,
            )
            cycles.append(last)
            opened_min = last.get("opened") if opened_min is None else min(opened_min, last.get("opened") or 0)
        raw = {**last, "cycles": case["cycles"], "opened": opened_min, "cycle_results": cycles}
    elif kind == "blackhole":
        ip, dport = case["drop_backend"].split(":")
        dport = int(dport)
        before_pkts = packet_count(ip, dport)
        install_drop(ip, dport)
        try:
            st = None
            for i in range(8):
                st, _, _ = put_object(spec, token, "g7slow", f"bh{i}", b"blackhole-body")
                if packet_count(ip, dport) > before_pkts:
                    break
            raw = {
                "case": "blackhole",
                "target": 1,
                "opened": 1,
                "put_status": st,
                "fault_armed": True,
                "fault_hits": max(0, packet_count(ip, dport) - before_pkts),
            }
        finally:
            remove_drop(ip, dport)
    elif kind == "quorum":
        be = case["drop_backends"][0]
        ip, dport = be.split(":")
        dport = int(dport)
        before_pkts = packet_count(ip, dport)
        install_drop(ip, dport)
        try:
            ok = 0
            for i in range(case["put_n"]):
                st, _, _ = put_object(spec, token, "g7slow", f"q{i}", b"quorum")
                if st and 200 <= st < 300:
                    ok += 1
            raw = {
                "case": "quorum",
                "target": case["put_n"],
                "opened": case["put_n"],
                "ok_2xx": ok,
                "fault_armed": True,
                "fault_hits": max(0, packet_count(ip, dport) - before_pkts),
            }
        finally:
            remove_drop(ip, dport)
    elif kind == "overload":
        warm_info_cache(spec, token, "g7slow")
        raw = run_overload(spec, token, case)
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
        present = 0
        for i in range(n):
            st, _, _ = http(
                host,
                port,
                "HEAD",
                f"/v1/{spec['auth']['account']}/g7slow/c{i}",
                headers={"X-Auth-Token": token},
                timeout=5,
            )
            if isinstance(st, int) and 200 <= st < 300:
                present += 1
        raw = {
            "case": "cancel",
            "target": n,
            "opened": opened,
            "tmp_count": wait_orphans(),
            "committed_objects": present,
        }
    elif kind == "sigterm_put":
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        s.sendall(
            f"PUT /v1/{spec['auth']['account']}/g7slow/sigterm HTTP/1.1\r\nHost: {host}\r\nX-Auth-Token: {token}\r\nContent-Length: 10485760\r\n\r\n".encode()
        )
        pid = proxy_pid()
        term_sent = False
        if pid:
            _lab_ssh(f"kill -TERM {pid}")
            term_sent = True
        started, out = restart_lab_proxy()
        if not started:
            force_start_lab_proxy()
        time.sleep(0.5)
        hp = health_p99(spec, n=8)
        st, _, _ = http(
            host,
            port,
            "GET",
            f"/v1/{spec['auth']['account']}/g7slow/sigterm",
            headers={"X-Auth-Token": token},
            timeout=5,
        )
        try:
            s.close()
        except OSError:
            pass
        raw = {
            "case": "sigterm_put",
            "target": 1,
            "opened": 1,
            "term_sent": term_sent,
            "restart_ok": bool(started) and hp["ok"] == hp["n"] and hp["n"] > 0,
            "partial_absent": (st is None or st >= 400) and wait_orphans(timeout=8) == 0,
            "start_out": (out or "")[-200:],
        }
    elif kind == "sigterm_barrier":
        fault_env = f"G7_FAULT=fsync_stall G7_FSYNC_STALL_US={int(case.get('stall_secs', 5)) * 1000000} LD_PRELOAD={FAULT_SO}"
        restart_lab_servers("object", fault_env)
        time.sleep(1.5)
        box = {}

        def _put():
            box["triple"] = put_object(spec, token, "g7slow", "barrier", b"Z" * 4096)

        worker = threading.Thread(target=_put)
        worker.start()
        barrier = False
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            shield = recon_value(spec, "commit_shield_active") or 0
            if shield < 1:
                rc, out, _ = _lab_ssh(
                    "for p in 16210 16220 16230 16240; do "
                    "curl -sf -m 1 http://127.0.0.1:$p/recon/concurrency; done | "
                    "awk '/^commit_shield_active / && $2+0>=1 {found=1} END {print found+0}'"
                )
                try:
                    shield = int((out or "0").strip() or 0)
                except ValueError:
                    shield = 0
            if shield >= 1:
                barrier = True
                break
            if not worker.is_alive() and "triple" in box:
                break
            time.sleep(0.05)
        term_during = False
        if barrier:
            pid = proxy_pid()
            if pid:
                _lab_ssh(f"kill -TERM {pid}")
                term_during = True
        worker.join(timeout=40)
        st, _body, ms = box.get("triple", (None, b"", 0))
        hits = read_hits()
        started, _out = restart_lab_proxy()
        if not started:
            force_start_lab_proxy()
        time.sleep(0.4)
        restart_lab_servers("object", "")
        time.sleep(0.4)
        st2, body, _ = http(
            host,
            port,
            "GET",
            f"/v1/{spec['auth']['account']}/g7slow/barrier",
            headers={"X-Auth-Token": token},
            timeout=10,
        )
        hp = health_p99(spec, n=6)
        raw = {
            "case": "sigterm_barrier",
            "target": 1,
            "opened": 1,
            "barrier_observed": barrier,
            "term_during_barrier": term_during,
            "restart_ok": bool(started) and hp["ok"] == hp["n"] and hp["n"] > 0,
            "put_status": st,
            "get_after": st2,
            "len": len(body or b""),
            "expected_len": 4096,
            "operation_ms": ms,
            "fault_hits": hits,
        }
    elif kind == "fd_exhaust":
        pid = proxy_pid()
        rc, out, _ = _lab_ssh(f"ls /proc/{pid}/fd | wc -l")
        try:
            fds = int((out or "0").strip())
        except ValueError:
            fds = 32
        limit = max(fds, 8)
        armed = False
        pressure = False
        held = []
        try:
            rc, out, _err = _lab_ssh(f"prlimit --pid {pid} --nofile={limit}:{limit} && echo ARMED")
            armed = rc == 0 and "ARMED" in (out or "")
            for _i in range(limit + 64):
                s = socket.socket()
                s.settimeout(2)
                try:
                    s.connect((host, port))
                    s.sendall(b"GET /healthcheck HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                    s.settimeout(1)
                    data = s.recv(64)
                    if not data.startswith(b"HTTP/1.1 200"):
                        pressure = True
                        s.close()
                        break
                    held.append(s)
                except (OSError, socket.timeout):
                    pressure = True
                    s.close()
                    break
        finally:
            for s in held:
                try:
                    s.close()
                except OSError:
                    pass
            if pid:
                _lab_ssh(f"prlimit --pid {pid} --nofile=500000:500000 || true")
        hp = health_p99(spec, n=6)
        raw = {
            "case": "fd_exhaust",
            "target": 1,
            "opened": 1,
            "fault_armed": armed,
            "fd_pressure_observed": pressure,
            "recovered": hp["ok"] == hp["n"] and hp["n"] > 0,
            "fd_limit": limit,
        }
    elif kind == "enospc":
        restart_lab_servers("object", f"G7_FAULT=enospc LD_PRELOAD={FAULT_SO}")
        time.sleep(0.5)
        st, hits, tmp = None, 0, -1
        try:
            st, _, _ = put_object(spec, token, "g7slow", "enospc", b"E" * 1024)
            hits = read_hits()
            tmp = wait_orphans()
        finally:
            restart_lab_servers("object", "")
        time.sleep(0.4)
        st2, _, _ = put_object(spec, token, "g7slow", "enospc-recovery", b"ok")
        raw = {
            "case": "enospc",
            "target": 1,
            "opened": 1,
            "fault_armed": True,
            "fault_hits": hits,
            "put_status": st,
            "tmp_count": tmp,
            "recovery_put_status": st2,
        }
    elif kind == "eio":
        mapped, detail = ensure_eio_mapper()
        if not mapped:
            raw = {
                "case": "eio",
                "target": 1,
                "opened": 1,
                "verdict_hint": "NOT RUN",
                "not_run_reason": "no EIO mapper exists",
                "mapper_detail": detail[-300:],
            }
        else:
            info, tmp = {}, -1
            try:
                info = eio_on_mapper(spec, token)
                tmp = wait_orphans()
            finally:
                restore_eio_mapper()
            time.sleep(0.4)
            st2, _, _ = put_object(spec, token, "g7slow", "eio-recovery", b"ok")
            raw = {
                "case": "eio",
                "target": 1,
                "opened": 1,
                "fault_armed": bool(info.get("ok")),
                "fault_hits": info.get("fault_hits") or 0,
                "put_status": info.get("put_status"),
                "tmp_count": tmp,
                "recovery_put_status": st2,
                "mapper": "/dev/mapper/g7eio",
            }
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
        raw = {
            "case": "partial_write",
            "target": 1,
            "opened": 1,
            "get_status": st,
            "expect_not_2xx": st is None or st >= 400,
            "tmp_count": wait_orphans(),
        }
    elif kind == "backend_connect_timeout":
        ip = case.get("blackhole_ip", "127.0.0.9")
        dport = int(case.get("port") or 16210)
        # 127.0.0.9 is not a ring device. Also drop a real replica so the proxy
        # connect is on the exercised path, and keep the yaml address blackholed.
        real_ip, real_port = "127.0.0.2", 16220
        before_metric = recon_value(spec, "timeouts_total_backend_connect") or 0
        before_pkts = packet_count(real_ip, real_port)
        install_drop(real_ip, real_port)
        if (ip, dport) != (real_ip, real_port):
            install_drop(ip, dport)
        try:
            st = None
            for i in range(6):
                st, _, _ = put_object(spec, token, "g7slow", f"cto{i}", b"timeout-probe")
                if packet_count(real_ip, real_port) > before_pkts:
                    break
            time.sleep(0.6)
            after_metric = recon_value(spec, "timeouts_total_backend_connect") or 0
            raw = {
                "case": "backend_connect_timeout",
                "target": 1,
                "opened": 1,
                "fault_armed": True,
                "fault_hits": max(0, packet_count(real_ip, real_port) - before_pkts),
                "timeout_observed": after_metric > before_metric,
                "put_status": st,
                "timeouts_before": before_metric,
                "timeouts_after": after_metric,
            }
        finally:
            remove_drop(real_ip, real_port)
            if (ip, dport) != (real_ip, real_port):
                remove_drop(ip, dport)
    elif kind == "fsync_stall":
        us = int(case.get("stall_secs", 5) * 1_000_000)
        restart_lab_servers("object", f"G7_FAULT=fsync_stall G7_FSYNC_STALL_US={us} LD_PRELOAD={FAULT_SO}")
        time.sleep(1.5)
        st, hits, elapsed_ms = None, 0, 0
        try:
            t0 = time.monotonic()
            st, _, ms = put_object(spec, token, "g7slow", "fsync", b"F" * 4096)
            elapsed_ms = max(ms or 0, (time.monotonic() - t0) * 1000.0)
            hits = read_hits()
        finally:
            restart_lab_servers("object", "")
        raw = {
            "case": "fsync_stall",
            "target": 1,
            "opened": 1,
            "fault_armed": True,
            "fault_hits": hits,
            "operation_status": st,
            "operation_ms": elapsed_ms,
        }
    elif kind == "sqlite_stall":
        us = int(case.get("stall_secs", 5) * 1_000_000)
        restart_lab_servers("container", f"G7_FAULT=fsync_stall G7_FSYNC_STALL_US={us} LD_PRELOAD={FAULT_SO}")
        time.sleep(1.5)
        st, hits, elapsed_ms = None, 0, 0
        try:
            t0 = time.monotonic()
            st, _, ms = http(
                host,
                port,
                "PUT",
                f"/v1/{spec['auth']['account']}/g7sqlite{int(time.time())}",
                headers={"X-Auth-Token": token},
                timeout=60,
            )
            elapsed_ms = max(ms or 0, (time.monotonic() - t0) * 1000.0)
            hits = read_hits()
        finally:
            restart_lab_servers("container", "")
        raw = {
            "case": "sqlite_stall",
            "target": 1,
            "opened": 1,
            "fault_armed": True,
            "fault_hits": hits,
            "operation_status": st,
            "operation_ms": elapsed_ms,
        }
    else:
        raw = {"error": f"unknown kind {kind}", "target": case.get("target"), "opened": 0}

    if health_obs is not None:
        raw = apply_health(raw, health_obs.stop())
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
    if kind in ("eio",) and raw.get("verdict_hint") == "NOT RUN":
        result["verdict"] = "ENVIRONMENT BLOCKED"
        result["reason"] = raw.get("not_run_reason") or "no EIO mapper exists"
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
    port = int(spec["target"]["port"])
    if port in spec["target"].get("forbidden_ports", []) or port in (8080, 8085):
        print(f"refusing forbidden port {port}", file=sys.stderr)
        return 2
    if spec["target"].get("swift_dir") != "/etc/g6-rust":
        print("refusing non-lab swift_dir", file=sys.stderr)
        return 2
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
        try:
            rec = run_case(name, case, spec, token)
        except Exception as exc:
            rec = {
                "name": name,
                "verdict": "FAIL",
                "reason": f"runner exception: {exc}",
                "opened": None,
                "target": case.get("target", case.get("n")),
            }
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
