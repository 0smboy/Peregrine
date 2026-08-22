#!/usr/bin/env python3
"""Assemble a facts JSON for preflight from host dumps + provenance fields.

Host dumps are plain text files (optional). Missing measurements fail closed
in preflight; this script does not invent SHAs.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pipeline
import provenance


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--provenance", help="existing TEST-PROVENANCE.json")
    p.add_argument("--python-pipeline-conf")
    p.add_argument("--rust-pipeline-conf")
    p.add_argument("--python-pipeline-line")
    p.add_argument("--rust-pipeline-line")
    p.add_argument("--swift2-vip", action="store_true")
    p.add_argument("--rings-equivalent", action="store_true")
    p.add_argument("--storage-policies-identical", action="store_true")
    p.add_argument("--filesystem-equivalent", action="store_true")
    p.add_argument("--cpu-equivalent", action="store_true")
    p.add_argument("--memory-equivalent", action="store_true")
    p.add_argument("--data-clean", action="store_true")
    p.add_argument("--no-competing-benchmark", action="store_true")
    p.add_argument("--tests-frozen", action="store_true")
    args = p.parse_args()

    facts: dict = {}
    if args.provenance:
        facts["provenance"] = provenance.load_manifest(Path(args.provenance))
        facts.update(facts["provenance"])

    py = []
    rs = []
    if args.python_pipeline_conf:
        py = pipeline.extract_pipeline_from_conf(
            Path(args.python_pipeline_conf).read_text(encoding="utf-8")
        )
    elif args.python_pipeline_line:
        py = pipeline.parse_pipeline_tokens(args.python_pipeline_line)
    if args.rust_pipeline_conf:
        rs = pipeline.extract_pipeline_from_conf(
            Path(args.rust_pipeline_conf).read_text(encoding="utf-8")
        )
    elif args.rust_pipeline_line:
        rs = pipeline.parse_pipeline_tokens(args.rust_pipeline_line)
    if py or rs:
        facts["python_pipeline"] = py
        facts["rust_pipeline"] = rs
        facts["pipeline_unexpected_count"] = pipeline.diff_pipelines(py, rs)["unexpected_count"]
        facts["pipeline_diff"] = pipeline.diff_pipelines(py, rs)

    facts["swift2_vip_present"] = bool(args.swift2_vip)
    facts["host_production_traffic"] = bool(args.swift2_vip)
    # CLI booleans are operator declarations. Preflight rejects them as evidence.
    declared = {
        "rings_equivalent": args.rings_equivalent,
        "storage_policies_identical": args.storage_policies_identical,
        "filesystem_equivalent": args.filesystem_equivalent,
        "cpu_budgets_equivalent": args.cpu_equivalent,
        "memory_budgets_equivalent": args.memory_equivalent,
        "data_state_clean": args.data_clean,
        "no_competing_benchmark_process": args.no_competing_benchmark,
        "collected_test_names_frozen": args.tests_frozen,
    }
    facts.update(declared)
    facts["measurement_source"] = {
        k: ("operator_declared" if v else "unmeasured") for k, v in declared.items()
    }

    Path(args.out).write_text(json.dumps(facts, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
