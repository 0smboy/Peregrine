#!/usr/bin/env python3
"""Canonical pipeline normalize + diff (AGENTS.md TEST LAB G2).

Pipeline is the program. Both Python and Rust confs must be rendered from
one semantic profile, then compared as normalized JSON. Unexpected
differences are listed; they are never silently ignored.

This module is a pure function over text so unit tests feed fixtures
without SSH.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable

# Hyphen/underscore aliases that mean the same Swift filter.
ALIASES = {
    "catch-errors": "catch_errors",
    "health-check": "healthcheck",
    "health_check": "healthcheck",
    "proxy_logging": "proxy-logging",
    "proxylogging": "proxy-logging",
    "listing-formats": "listing_formats",
    "container-quotas": "container_quotas",
    "account-quotas": "account_quotas",
    "versioned-writes": "versioned_writes",
    "etag-quoter": "etag_quoter",
    "container-sync": "container_sync",
    "cross-domain": "crossdomain",
    "name-check": "name_check",
    "read-only": "read_only",
    "list-endpoints": "list_endpoints",
    "cname-lookup": "cname_lookup",
    "domain-remap": "domain_remap",
    "backend-ratelimit": "backend_ratelimit",
}

APP_NAMES = {"proxy-server", "proxy_server", "proxy"}


def canonical_name(raw: str) -> str:
    name = raw.strip().lower()
    if not name:
        return ""
    return ALIASES.get(name, name)


def parse_pipeline_tokens(line: str) -> list[str]:
    """Split a `pipeline = a b c` value into canonical filter names.

    The WSGI app (`proxy-server`) is dropped: both sides always end in the
    app; comparing it hides real filter drift.
    """
    value = line
    if "=" in line and re.match(r"^\s*pipeline\s*=", line, re.I):
        value = line.split("=", 1)[1]
    value = value.split("#", 1)[0]
    out: list[str] = []
    for tok in value.split():
        name = canonical_name(tok)
        if not name or name in APP_NAMES:
            continue
        out.append(name)
    return out


def extract_pipeline_from_conf(text: str) -> list[str]:
    """Return the first `[pipeline:main] pipeline =` line as canonical names."""
    in_section = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_section = line.lower() in ("[pipeline:main]", "[pipeline]")
            continue
        if in_section and re.match(r"^pipeline\s*=", line, re.I):
            return parse_pipeline_tokens(line)
        if re.match(r"^pipeline\s*=", line, re.I):
            # Tolerate a bare pipeline= outside the section (some dumps).
            tokens = parse_pipeline_tokens(line)
            if tokens:
                return tokens
    return []


def normalize(names: Iterable[str]) -> list[str]:
    return [n for n in (canonical_name(x) for x in names) if n and n not in APP_NAMES]


def load_simple_yaml(path: Path) -> dict:
    """Minimal YAML subset: `key: value`, `key:`, and `- item` lists.

    Avoids a PyYAML dependency so the lab runs on a stock CPython.
    """
    data: dict = {}
    current_list: str | None = None
    current_map: str | None = None
    map_item: dict | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.split("#", 1)[0].rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        line = stripped.strip()
        if line.startswith("- "):
            item = line[2:].strip()
            if current_map is not None:
                if map_item:
                    data.setdefault(current_map, []).append(map_item)
                map_item = {}
                if ":" in item:
                    k, v = item.split(":", 1)
                    map_item[k.strip()] = _scalar(v.strip())
                else:
                    data.setdefault(current_list or current_map, []).append(_scalar(item))
                    map_item = None
            elif current_list is not None:
                data.setdefault(current_list, []).append(_scalar(item))
            continue
        if indent >= 2 and current_map is not None and map_item is not None and ":" in line:
            k, v = line.split(":", 1)
            map_item[k.strip()] = _scalar(v.strip())
            continue
        if current_map is not None and map_item:
            data.setdefault(current_map, []).append(map_item)
            map_item = None
            current_map = None
        if line.endswith(":") and ":" == line[-1] and line.count(":") == 1:
            key = line[:-1].strip()
            # Heuristic: storage_policies is a list of maps; pipeline is a list of strs.
            if key in ("storage_policies",):
                current_map = key
                current_list = None
                data[key] = []
            else:
                current_list = key
                current_map = None
                data[key] = []
            continue
        if ":" in line:
            current_list = None
            current_map = None
            k, v = line.split(":", 1)
            data[k.strip()] = _scalar(v.strip())
    if current_map is not None and map_item:
        data.setdefault(current_map, []).append(map_item)
    return data


def _scalar(v: str):
    if v.lower() == "true":
        return True
    if v.lower() == "false":
        return False
    if v.isdigit():
        return int(v)
    return v


def load_profile(path: Path) -> dict:
    profile = load_simple_yaml(path)
    if "pipeline" not in profile or not profile["pipeline"]:
        raise ValueError(f"{path}: profile missing pipeline list")
    profile["pipeline"] = normalize(profile["pipeline"])
    return profile


def render_proxy_conf(profile: dict, dialect: str) -> str:
    """Render a `[pipeline:main]` snippet. dialect is `python` or `rust`.

    Filter names are already canonical; both dialects emit the same tokens
    so a true semantic difference cannot hide behind hyphen vs underscore.
    """
    _ = dialect
    names = list(profile["pipeline"])
    app = profile.get("app") or "proxy-server"
    line = " ".join(names + [app])
    return (
        f"# generated from profile {profile.get('name', 'unknown')}\n"
        "[pipeline:main]\n"
        f"pipeline = {line}\n"
    )


def diff_pipelines(left: list[str], right: list[str]) -> dict:
    """Compare two canonical pipelines.

    `unexpected` is the set of names present on only one side, plus any
    order mismatch of the shared prefix. Identical lists → unexpected=[].
    """
    a = normalize(left)
    b = normalize(right)
    only_left = [n for n in a if n not in b]
    only_right = [n for n in b if n not in a]
    order_mismatch = a != b and not only_left and not only_right
    unexpected: list[dict] = []
    for n in only_left:
        unexpected.append({"name": n, "side": "left"})
    for n in only_right:
        unexpected.append({"name": n, "side": "right"})
    if order_mismatch:
        unexpected.append(
            {
                "name": "<order>",
                "side": "both",
                "left": a,
                "right": b,
            }
        )
    return {
        "left": a,
        "right": b,
        "only_left": only_left,
        "only_right": only_right,
        "order_mismatch": order_mismatch,
        "unexpected": unexpected,
        "unexpected_count": len(unexpected),
    }


def pipeline_sha256(names: Iterable[str]) -> str:
    blob = " ".join(normalize(names)).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def dumps_normalized(names: Iterable[str]) -> str:
    return json.dumps(normalize(names), indent=2) + "\n"
