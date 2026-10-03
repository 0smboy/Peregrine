#!/usr/bin/env python3
"""Freeze a G5 known-failure policy from a paired Rust + Python Swift run.

The policy exists so G5 can be scored the way `validation-gates.mdx` defines it
("capability/known-failure policy, exact-name diff, unexpected test names = 0")
instead of by a raw PASS count.

The rule that keeps the list honest and falsifiable:

    an identity may be frozen as expected-fail ONLY IF the Python Swift oracle
    fails it too in the paired baseline run, or the harness cannot execute it
    at all.

Anything that fails on Rust while the oracle passes is deliberately left out,
so it scores as unexpected and stays visible. A frozen entry that later passes
is reported as stale, so the list cannot rot into an alibi.

Usage:
  tools/g5-freeze-known-failures.py RUST.xml PYTHON.xml \
      --fail-error-names fail_error_names.txt --out policy.tsv
"""
from __future__ import annotations

import argparse
import importlib.util
import pathlib
import sys
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve().parent

CLASS_LABEL = {
    "harness": "harness-blocked",
    "swift-vs-rgw": "not-applicable-rgw",
    "engine": "swift-family-gap",
}


def load_classifier():
    spec = importlib.util.spec_from_file_location("g5bc", HERE / "g5b-classify.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def outcomes(path: str) -> dict[str, str]:
    root = ET.parse(path).getroot()
    out = {}
    for tc in root.iter("testcase"):
        cls = tc.attrib.get("classname", "")
        name = tc.attrib.get("name", "")
        if name.startswith("test suite for") or "nose.suite" in cls:
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
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rust_xml")
    ap.add_argument("python_xml")
    ap.add_argument("--fail-error-names", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--rust-label", default="rust tip 9531eb62 (G5B-live-9531eb62, 2026-09-15)")
    ap.add_argument("--python-label",
                    default="python swift 2.33.0 s3api 10.0.0.2:8090 (G5B-pybaseline-20260918)")
    args = ap.parse_args()

    C = load_classifier()
    reasons: dict[str, tuple[str, str]] = {}
    for rec in C.parse(args.fail_error_names):
        cls, sig, _note = C.classify(rec)
        reasons[f"{rec['module']}:{rec['test']}"] = (cls, sig)

    rust = outcomes(args.rust_xml)
    py = outcomes(args.python_xml)

    frozen: list[tuple[str, str, str]] = []
    expected_skip: list[str] = []
    withheld: list[tuple[str, str]] = []

    for ident in sorted(set(rust) & set(py)):
        r, p = rust[ident], py[ident]
        if r == "skip" and p == "skip":
            expected_skip.append(ident)
            continue
        if r not in ("failure", "error"):
            continue
        cls, sig = reasons.get(ident, ("engine", "unmatched"))
        if p in ("failure", "error"):
            frozen.append((ident, CLASS_LABEL.get(cls, "swift-family-gap"), sig))
        else:
            withheld.append((ident, sig))

    out = pathlib.Path(args.out)
    with out.open("w", encoding="utf-8") as fh:
        fh.write("# G5-B known-failure policy (Ceph s3compat identity set)\n")
        fh.write("#\n")
        fh.write("# Basis: an identity is frozen expected-fail only if the Python Swift\n")
        fh.write("# oracle fails it too, or the harness cannot execute it.\n")
        fh.write(f"# rust   : {args.rust_label}\n")
        fh.write(f"# python : {args.python_label}\n")
        fh.write("#\n")
        fh.write("# classes:\n")
        fh.write("#   harness-blocked    the suite never reaches the engine here\n")
        fh.write("#   not-applicable-rgw RGW-only surface, outside AWS S3 and Swift\n")
        fh.write("#   swift-family-gap   both Swift implementations lack the behavior\n")
        fh.write("#   expected-skip      skipped by both sides\n")
        fh.write("#\n")
        fh.write("# columns: identity<TAB>class<TAB>signature\n")
        for ident, label, sig in frozen:
            fh.write(f"{ident}\t{label}\t{sig}\n")
        for ident in expected_skip:
            fh.write(f"{ident}\texpected-skip\tskipped-both-sides\n")

    print(f"frozen expected-fail : {len(frozen)}")
    print(f"frozen expected-skip : {len(expected_skip)}")
    print(f"withheld (rust-only, must stay unexpected): {len(withheld)}")
    for ident, sig in withheld:
        print(f"    {ident}  [{sig}]")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
