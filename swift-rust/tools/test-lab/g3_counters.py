#!/usr/bin/env python3
"""Parse `/recon/concurrency` Prometheus text for G3 activation counters.

`/recon/concurrency` HTTP 200 is not a pass. Native-async vs legacy-sync vs
`block_in_place` totals after a real request are the proof.
"""
from __future__ import annotations

import re
from typing import Any

METRIC_LINE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>[-+0-9.eE]+)\s*$"
)


def parse_prometheus(text: str) -> dict[str, float]:
    """Map `name` and `name{label="v"}` to values. Last sample wins."""
    out: dict[str, float] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = METRIC_LINE.match(line)
        if not m:
            continue
        name = m.group("name")
        labels = m.group("labels") or ""
        value = float(m.group("value"))
        out[name] = value
        if labels:
            key = f"{name}{{{labels}}}"
            out[key] = value
            # also name{k=v} without spaces
            compact = "".join(labels.split())
            out[f"{name}{{{compact}}}"] = value
    return out


def extract_g3(samples: dict[str, float]) -> dict[str, float]:
    def grab(*keys: str) -> float:
        for k in keys:
            if k in samples:
                return float(samples[k])
        return 0.0

    return {
        "http_requests_total_hyper": grab(
            'http_requests_total{engine="hyper"}',
            "http_requests_total{engine=hyper}",
            "http_requests_total",
        ),
        "native_async_requests_total": grab("native_async_requests_total"),
        "legacy_sync_handler_requests_total": grab("legacy_sync_handler_requests_total"),
        "block_in_place_total": grab("block_in_place_total"),
        "spawn_blocking_total_storage": grab(
            'spawn_blocking_total{domain="storage"}', "spawn_blocking_total"
        ),
        "blocking_network_wait_total": grab("blocking_network_wait_total"),
        "connections_open": grab("connections_open"),
        "connections_idle": grab("connections_idle"),
        "requests_active": grab("requests_active"),
        "runtime_worker_threads": grab("runtime_worker_threads"),
        "process_threads": grab("process_threads"),
    }


def delta(before: dict[str, float], after: dict[str, float]) -> dict[str, float]:
    keys = set(before) | set(after)
    return {k: float(after.get(k, 0) or 0) - float(before.get(k, 0) or 0) for k in keys}


def evaluate_path(delta_g3: dict[str, float], *, path: str) -> dict[str, Any]:
    """Gate a single request class.

    Migrated Swift paths require native_async > 0 and zero legacy / block_in_place
    / blocking_network_wait. S3 currently uses block_in_place → NO-GO.
    """
    native = delta_g3.get("native_async_requests_total", 0)
    legacy = delta_g3.get("legacy_sync_handler_requests_total", 0)
    bip = delta_g3.get("block_in_place_total", 0)
    net = delta_g3.get("blocking_network_wait_total", 0)
    hyper = delta_g3.get("http_requests_total_hyper", 0)
    s3 = path.lower().startswith("s3")
    reasons = []
    if hyper <= 0:
        reasons.append("http_requests_total{engine=hyper} did not increase")
    if native <= 0:
        reasons.append("native_async_requests_total did not increase")
    if legacy > 0:
        reasons.append(f"legacy_sync_handler_requests_total={legacy}")
    if bip > 0:
        reasons.append(f"block_in_place_total={bip}")
    if net > 0:
        reasons.append(f"blocking_network_wait_total={net}")
    if s3 and bip > 0:
        result = "NO-GO"
        reasons.append("S3 ASYNC GATE = NO-GO (block_in_place_total > 0)")
    elif reasons:
        result = "NO-GO"
    else:
        result = "GREEN"
    return {
        "path": path,
        "result": result,
        "reasons": reasons,
        "delta": delta_g3,
    }
