#!/usr/bin/env python3
"""G0 provenance freeze: required keys, fail-closed validation.

Empty or invented SHAs fail. `swift.version=2.33.0` from `/info` is not a
substitute for `python_swift_git_sha`.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

REQUIRED_KEYS = [
    "peregrine_git_sha",
    "python_swift_git_sha",
    "python_swift_version",
    "swift_tests_git_sha",
    "s3compat_git_sha",
    "s3compat_ceph_tests_submodule_sha",
    "rustc_version",
    "cargo_lock_sha256",
    "source_tree_sha256",
    "kernel",
    "glibc",
    "liberasurecode_version",
    "test_config_sha256",
    "ring_sha256",
    "pipeline_sha256",
]

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def is_git_sha(value: Any) -> bool:
    return isinstance(value, str) and bool(GIT_SHA_RE.fullmatch(value.strip().lower()))


def is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(SHA256_RE.fullmatch(value.strip().lower()))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_manifest(doc: dict) -> list[str]:
    """Return a list of fail reasons. Empty list means the freeze is usable."""
    fails: list[str] = []
    if not isinstance(doc, dict):
        return ["manifest is not an object"]
    for key in REQUIRED_KEYS:
        if key not in doc:
            fails.append(f"missing key {key}")
            continue
        val = doc[key]
        if val is None or (isinstance(val, str) and not val.strip()):
            fails.append(f"empty {key}")
    git_keys = (
        "peregrine_git_sha",
        "python_swift_git_sha",
        "swift_tests_git_sha",
        "s3compat_git_sha",
        "s3compat_ceph_tests_submodule_sha",
    )
    for key in git_keys:
        val = doc.get(key)
        if val and not is_git_sha(val):
            fails.append(f"{key} is not a 40-char git SHA: {val!r}")
    hash_keys = (
        "cargo_lock_sha256",
        "source_tree_sha256",
        "test_config_sha256",
        "ring_sha256",
        "pipeline_sha256",
    )
    for key in hash_keys:
        val = doc.get(key)
        if val and not is_sha256(val):
            fails.append(f"{key} is not a sha256: {val!r}")
    version = str(doc.get("python_swift_version") or "")
    if version in ("2.33.0", "2.33") and not is_git_sha(doc.get("python_swift_git_sha")):
        fails.append(
            "python_swift_version from /info is not a provenance pin; "
            "python_swift_git_sha must be a real checkout SHA"
        )
    if doc.get("ceph_s3tests_git_sha") and not (
        is_git_sha(doc.get("s3compat_git_sha"))
        and is_git_sha(doc.get("s3compat_ceph_tests_submodule_sha"))
    ):
        fails.append(
            "ceph_s3tests_git_sha without s3compat+submodule is the wrong harness lineage; "
            "pin tipabu/s3compat and its ceph-tests submodule"
        )
    if doc.get("worktree_clean") is not True:
        fails.append(
            "worktree is not clean; peregrine_git_sha cannot rebuild deployed binaries "
            f"(dirty_count={doc.get('dirty_count', 'unmeasured')})"
        )
    if doc.get("deployed_binary_matches_commit") is not True:
        fails.append("deployed binary is not proven to match peregrine_git_sha+source_tree_sha256")
    return fails


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_manifest(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
