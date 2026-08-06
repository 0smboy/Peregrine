#!/usr/bin/env python3
"""Effective concurrency calibrator for Rust Swift servers (P2c).

Mirrors swift-object-server::servers_per_port::effective_concurrency so
ISO-CONFIG A/B can align thread pools / CPU quota instead of raw workers=.

Examples:
  effective-concurrency.py --workers 2 --max-clients 64
  effective-concurrency.py --conf /etc/swift/object-server.conf
  effective-concurrency.py --conf /etc/swift/object-server.conf --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

WORKER_THREADS_CAP = 128


def effective_concurrency(
    workers: int,
    max_clients: int,
    servers_per_port: int,
    bind_ports: int,
    cpus: int | None = None,
) -> dict:
    max_clients = max(1, max_clients)
    notes: list[str] = []
    if servers_per_port > 0:
        n_ports = max(1, bind_ports)
        acceptors = max(1, servers_per_port * n_ports)
        notes.append("servers_per_port>0: workers knob ignored (Python parity)")
        notes.append("Rust Wave2: one OS process per (port, worker) — process-isolated")
        # Per-process pool sized to max_clients (cap 128). Aggregate across
        # children ≈ servers_per_port * n_ports * max_clients.
        worker_threads = max(1, min(max_clients, WORKER_THREADS_CAP))
        if max_clients > WORKER_THREADS_CAP:
            notes.append("per-process worker_threads clamped to 128")
        notes.append(
            "aggregate ≈ servers_per_port * n_ports * max_clients across children"
        )
        return {
            "workers": workers,
            "max_clients": max_clients,
            "servers_per_port": servers_per_port,
            "bind_ports": n_ports,
            "worker_threads": worker_threads,
            "connection_queue": max_clients,
            "acceptors": acceptors,
            "formula": "per-process: max_clients → worker_threads; children = spp * n_ports",
            "notes": notes,
        }
    if workers > 0:
        notes.append("Rust maps workers*max_clients → worker_threads (NOT prefork processes)")
        product = workers * max_clients
        worker_threads = max(1, min(product, WORKER_THREADS_CAP))
        if product > WORKER_THREADS_CAP:
            notes.append("worker_threads clamped to 128")
        return {
            "workers": workers,
            "max_clients": max_clients,
            "servers_per_port": 0,
            "bind_ports": 1,
            "worker_threads": worker_threads,
            "connection_queue": max_clients,
            "acceptors": 1,
            "formula": "workers * max_clients → worker_threads (cap 128)",
            "notes": notes,
        }
    ncpu = cpus if cpus and cpus > 0 else (os.cpu_count() or 4)
    worker_threads = max(16, min(ncpu * 16, WORKER_THREADS_CAP))
    notes.append("workers=0: use ServerConfig default (cpus*16, clamp 16..128)")
    return {
        "workers": 0,
        "max_clients": max_clients,
        "servers_per_port": 0,
        "bind_ports": 1,
        "worker_threads": worker_threads,
        "connection_queue": max_clients,
        "acceptors": 1,
        "formula": "default: cpus*16 → worker_threads (clamp 16..128)",
        "notes": notes,
    }


def parse_conf(path: Path) -> dict[str, str]:
    text = path.read_text(errors="replace")
    # Prefer [app:object-server], fall back to [DEFAULT]
    sections: dict[str, dict[str, str]] = {}
    cur = "DEFAULT"
    sections[cur] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith(";"):
            continue
        m = re.match(r"\[(.+)\]$", s)
        if m:
            cur = m.group(1)
            sections.setdefault(cur, {})
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            sections[cur][k.strip()] = v.strip()
    app = sections.get("app:object-server", {})
    default = sections.get("DEFAULT", {})
    def get(key: str, fallback: str = "") -> str:
        return app.get(key) or default.get(key) or fallback
    return {
        "workers": get("workers", "0"),
        "max_clients": get("max_clients", "1024"),
        "servers_per_port": get("servers_per_port", "0"),
        "bind_port": get("bind_port", "6200"),
        "bind_ip": get("bind_ip", "0.0.0.0"),
        "ring_ip": get("ring_ip", "") or get("bind_ip", "0.0.0.0"),
    }


def count_local_ring_ports(swift_dir: Path, ring_ip: str) -> int:
    """Best-effort: count unique ports from *.ring.gz.builder.json for ring_ip."""
    ports: set[int] = set()
    for p in sorted(swift_dir.glob("object*.ring.gz.builder.json")):
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        for d in data.get("devices") or []:
            if not isinstance(d, dict):
                continue
            if ring_ip in ("0.0.0.0", "::", "") or d.get("ip") == ring_ip:
                # For wildcard, count all; caller should filter by local IPs
                # in production — here we count ports for matching ip or all.
                if ring_ip in ("0.0.0.0", "::", ""):
                    ports.add(int(d.get("port") or 0))
                else:
                    ports.add(int(d.get("port") or 0))
    ports.discard(0)
    return len(ports) if ports else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--max-clients", type=int, default=None)
    ap.add_argument("--servers-per-port", type=int, default=None)
    ap.add_argument("--bind-ports", type=int, default=None)
    ap.add_argument("--cpus", type=int, default=None)
    ap.add_argument("--conf", type=Path, default=None)
    ap.add_argument("--swift-dir", type=Path, default=Path("/etc/swift"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    workers = 0
    max_clients = 1024
    servers_per_port = 0
    bind_ports = 1

    if args.conf:
        knobs = parse_conf(args.conf)
        workers = int(float(knobs["workers"] or 0)) if knobs["workers"] not in ("auto", "") else 0
        try:
            workers = int(knobs["workers"])
        except ValueError:
            workers = 0
        max_clients = int(knobs["max_clients"] or 1024)
        servers_per_port = int(knobs["servers_per_port"] or 0)
        if servers_per_port > 0 and args.bind_ports is None:
            bind_ports = count_local_ring_ports(args.swift_dir, knobs["ring_ip"])
        print(f"# conf={args.conf} ring_ip={knobs['ring_ip']}", file=sys.stderr)

    if args.workers is not None:
        workers = args.workers
    if args.max_clients is not None:
        max_clients = args.max_clients
    if args.servers_per_port is not None:
        servers_per_port = args.servers_per_port
    if args.bind_ports is not None:
        bind_ports = args.bind_ports

    result = effective_concurrency(
        workers, max_clients, servers_per_port, bind_ports, cpus=args.cpus
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"formula:          {result['formula']}")
        print(f"workers:          {result['workers']}")
        print(f"max_clients:      {result['max_clients']}")
        print(f"servers_per_port: {result['servers_per_port']}")
        print(f"bind_ports:       {result['bind_ports']}")
        print(f"acceptors:        {result['acceptors']}")
        print(f"worker_threads:   {result['worker_threads']}")
        print(f"connection_queue: {result['connection_queue']}")
        for n in result["notes"]:
            print(f"note: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
