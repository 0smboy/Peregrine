#!/usr/bin/env python3
"""Exact-name diff of a Rust G5-B census against a Python Swift baseline.

The G5 contract scores expected vs unexpected results by full test name, with a
Python baseline established first. This computes that diff from the two xunit
files, so each identity lands in exactly one bucket:

  both-fail    Python Swift fails too -> expected, belongs in known-failures
  rust-only    only Rust fails        -> the real Rust gap list
  python-only  only Python fails      -> Rust is ahead, or the oracle differs
  both-pass    clean on both

Module-level teardown errors (nose emits them as a testcase whose name is a
module) are reported separately; they are not identities.

Usage:
  tools/g5b-oracle-diff.py RUST.xml PYTHON.xml [--names BUCKET] [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET

BAD = ("failure", "error")


def load(path: str) -> tuple[dict[str, str], list[str]]:
    """Return {identity: outcome} plus the module-level teardown errors."""
    root = ET.parse(path).getroot()
    outcomes: dict[str, str] = {}
    teardown: list[str] = []
    for tc in root.iter("testcase"):
        cls = tc.attrib.get("classname", "")
        name = tc.attrib.get("name", "")
        outcome = "pass"
        for kind in BAD:
            if tc.find(kind) is not None:
                outcome = kind
                break
        if tc.find("skipped") is not None and outcome == "pass":
            outcome = "skip"
        if name.startswith("test suite for") or "nose.suite" in cls:
            teardown.append(f"{cls}:{name}")
            continue
        outcomes[f"{cls}:{name}"] = outcome
    return outcomes, teardown


def failed(outcome: str) -> bool:
    return outcome in BAD


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rust_xml")
    ap.add_argument("python_xml")
    ap.add_argument("--names", help="print identities in this bucket")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rust, rust_td = load(args.rust_xml)
    py, py_td = load(args.python_xml)

    shared = sorted(set(rust) & set(py))
    buckets: dict[str, list[str]] = {
        "both-fail": [], "rust-only": [], "python-only": [], "both-pass": [],
        "skipped-either": [],
    }
    for ident in shared:
        r, p = rust[ident], py[ident]
        if r == "skip" or p == "skip":
            buckets["skipped-either"].append(ident)
        elif failed(r) and failed(p):
            buckets["both-fail"].append(ident)
        elif failed(r):
            buckets["rust-only"].append(ident)
        elif failed(p):
            buckets["python-only"].append(ident)
        else:
            buckets["both-pass"].append(ident)

    only_rust_ids = sorted(set(rust) - set(py))
    only_py_ids = sorted(set(py) - set(rust))

    if args.names:
        for ident in buckets.get(args.names, []):
            print(ident)
        return 0

    summary = {
        "rust_identities": len(rust),
        "python_identities": len(py),
        "compared": len(shared),
        "not_in_python_run": len(only_rust_ids),
        "not_in_rust_run": len(only_py_ids),
        "buckets": {k: len(v) for k, v in buckets.items()},
        "module_teardown_errors": {"rust": len(rust_td), "python": len(py_td)},
    }
    if args.json:
        print(json.dumps({"summary": summary, "buckets": buckets}, indent=2))
        return 0

    print(f"rust identities   : {len(rust)}  ({args.rust_xml})")
    print(f"python identities : {len(py)}  ({args.python_xml})")
    print(f"compared          : {len(shared)}")
    if only_rust_ids:
        print(f"  not run against python: {len(only_rust_ids)}")
    if only_py_ids:
        print(f"  not in the rust census: {len(only_py_ids)}")
    print()
    for k in ("both-pass", "both-fail", "rust-only", "python-only", "skipped-either"):
        print(f"{k:<16} {len(buckets[k]):>4}")
    print()
    print(
        "module-level teardown errors (not identities): "
        f"rust {len(rust_td)}, python {len(py_td)}"
    )
    print()
    print(
        f"Rust-attributable G5-B gap after the oracle diff: {len(buckets['rust-only'])} "
        f"(down from the raw {sum(1 for o in rust.values() if failed(o))} FAIL+ERROR)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
