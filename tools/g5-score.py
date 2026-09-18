#!/usr/bin/env python3
"""Score a G5 run against a frozen known-failure policy.

This is the gate arithmetic from `validation-gates.mdx`: results are matched by
exact test name and the gate passes only when **unexpected = 0**.

Four things are counted, and three of them can fail the gate:

  unexpected-failure  failed, not in the policy            -> fails the gate
  unexpected-skip     skipped, not frozen as expected-skip -> fails the gate
  stale-entry         frozen expected-fail but it passed   -> fails the gate,
                      because the policy must be re-frozen, not silently kept
  expected-failure    failed and frozen, with a reason     -> allowed

A stale entry failing the gate is deliberate. A known-failure list that keeps
entries after they start passing stops describing the system.

Usage:
  tools/g5-score.py RUN.xml --policy policy.tsv [--json]
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import xml.etree.ElementTree as ET


def load_policy(path: str):
    expected_fail: dict[str, tuple[str, str]] = {}
    expected_skip: set[str] = set()
    meta: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("#"):
                meta.append(line.rstrip("\n"))
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 2:
                continue
            ident, label = parts[0], parts[1]
            sig = parts[2] if len(parts) > 2 else ""
            if label == "expected-skip":
                expected_skip.add(ident)
            else:
                expected_fail[ident] = (label, sig)
    return expected_fail, expected_skip, meta


def outcomes(path: str):
    root = ET.parse(path).getroot()
    out: dict[str, str] = {}
    teardown = 0
    for tc in root.iter("testcase"):
        cls = tc.attrib.get("classname", "")
        name = tc.attrib.get("name", "")
        if name.startswith("test suite for") or "nose.suite" in cls:
            teardown += 1
            continue
        if tc.find("failure") is not None:
            state = "failure"
        elif tc.find("error") is not None:
            state = "error"
        elif tc.find("skipped") is not None:
            state = "skip"
        else:
            state = "pass"
        out[f"{cls}:{name}"] = state
    return out, teardown


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_xml")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    exp_fail, exp_skip, _meta = load_policy(args.policy)
    run, teardown = outcomes(args.run_xml)

    unexpected_failure: list[str] = []
    unexpected_skip: list[str] = []
    stale: list[str] = []
    expected_failure: list[str] = []
    passed: list[str] = []

    for ident, state in sorted(run.items()):
        if state in ("failure", "error"):
            (expected_failure if ident in exp_fail else unexpected_failure).append(ident)
        elif state == "skip":
            if ident not in exp_skip:
                unexpected_skip.append(ident)
        else:
            passed.append(ident)
            if ident in exp_fail:
                stale.append(ident)

    by_class = collections.Counter(exp_fail[i][0] for i in expected_failure)
    verdict = "PASS" if not (unexpected_failure or unexpected_skip or stale) else "FAIL"

    summary = {
        "verdict": verdict,
        "identities": len(run),
        "passed": len(passed),
        "expected_failure": len(expected_failure),
        "unexpected_failure": len(unexpected_failure),
        "unexpected_skip": len(unexpected_skip),
        "stale_entries": len(stale),
        "expected_failure_by_class": dict(by_class),
        "module_teardown_errors": teardown,
    }

    if args.json:
        print(json.dumps({
            "summary": summary,
            "unexpected_failure": unexpected_failure,
            "unexpected_skip": unexpected_skip,
            "stale_entries": stale,
        }, indent=2))
        return 0 if verdict == "PASS" else 1

    print(f"run      : {args.run_xml}")
    print(f"policy   : {args.policy}")
    print(f"identities scored : {len(run)}")
    print()
    print(f"passed                : {len(passed)}")
    print(f"expected failure      : {len(expected_failure)}")
    for label, n in sorted(by_class.items(), key=lambda kv: -kv[1]):
        print(f"    {n:>4}  {label}")
    print(f"unexpected failure    : {len(unexpected_failure)}")
    for ident in unexpected_failure:
        print(f"    {ident}")
    print(f"unexpected skip       : {len(unexpected_skip)}")
    for ident in unexpected_skip[:10]:
        print(f"    {ident}")
    print(f"stale policy entries  : {len(stale)}")
    for ident in stale[:10]:
        print(f"    {ident}")
    print()
    print(f"G5 verdict under this policy: {verdict}")
    if verdict == "FAIL":
        print("unexpected must be 0 and the policy must carry no stale entries.")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
