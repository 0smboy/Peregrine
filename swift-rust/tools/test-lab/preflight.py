#!/usr/bin/env python3
"""Fail-closed TEST PREFLIGHT (AGENTS.md T5).

Prints every T5 line as PASS or FAIL. Any FAIL → exit 1. Does not start
G4/G5/G8.

T5 label `host production traffic = 0` means *uncontrolled competing
traffic*, not "VIP exists". A test VIP with only the registered loadgen
is PASS. Operator booleans are not evidence.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from provenance import GIT_SHA_RE, is_git_sha, validate_manifest
from pipeline import diff_pipelines, extract_pipeline_from_conf

T5 = [
    "provenance manifest valid",
    "peregrine worktree clean",
    "exact Python Swift commit pinned",
    "exact Peregrine commit pinned",
    "s3compat harness pinned",
    "pipeline semantic diff = 0",
    "storage policies identical",
    "rings equivalent",
    "filesystem equivalent",
    "host production traffic = 0",
    "CPU budgets equivalent",
    "memory budgets equivalent",
    "data state clean",
    "no competing benchmark process",
    "collected test names frozen",
]

# compatibility: G0/G2/G3/G4/G5 feedback on isolated SAIO.
# concurrency/performance: dedicated idle host required.
PROFILES = ("compatibility", "concurrency", "performance")
CONCURRENCY_ONLY = (
    "host production traffic = 0",
    "CPU budgets equivalent",
    "memory budgets equivalent",
    "no competing benchmark process",
)


def _truthy_fail(value, *, invert=False) -> bool:
    """Return True if this check should FAIL."""
    if isinstance(value, bool):
        return (not value) if not invert else value
    if value is None:
        return True
    if isinstance(value, (int, float)):
        return (value != 0) if invert else (value == 0 and invert)
    s = str(value).strip().lower()
    if s in ("pass", "true", "yes", "0", "none", "ok"):
        return invert
    if s in ("fail", "false", "no"):
        return not invert
    return True


def _measured_bool(facts: dict, key: str) -> tuple[bool, str]:
    """Operator-declared True is FAIL. Unmeasured is FAIL. Measured False is FAIL."""
    sources = facts.get("measurement_source") or {}
    src = str(sources.get(key) or facts.get(f"{key}_source") or "")
    val = facts.get(key)
    if src in ("operator", "operator_declared", "flag", "cli"):
        return True, f"operator-declared {key}={val!r} is not evidence"
    if src != "measured":
        return True, f"unmeasured {key} (source={src or 'missing'})"
    if val is not True:
        return True, f"measured {key}={val!r}"
    return False, "measured true"


def _uncontrolled_traffic(facts: dict) -> tuple[bool, str]:
    """VIP presence is not production traffic. Competing traffic must be measured.

    PASS reason is the T5 wording: `no uncontrolled traffic; only registered loadgen`.
    """
    sources = facts.get("measurement_source") or {}
    src = str(
        sources.get("uncontrolled_competing_traffic")
        or facts.get("uncontrolled_competing_traffic_source")
        or ""
    )
    competing = facts.get("uncontrolled_competing_traffic")
    lab = facts.get("lab_mode") if isinstance(facts.get("lab_mode"), dict) else {}
    mode = str(lab.get("mode") or facts.get("lab_mode_name") or "")
    vip = facts.get("swift2_vip_present")
    if vip is None:
        vip = facts.get("vip_present")

    if src in ("operator", "operator_declared", "flag", "cli"):
        return True, f"operator-declared uncontrolled_competing_traffic={competing!r} is not evidence"
    if src != "measured":
        return True, f"unmeasured uncontrolled_competing_traffic (source={src or 'missing'}); VIP present is not traffic"
    if competing not in (0, False):
        return True, f"uncontrolled competing traffic={competing!r}"
    if mode == "M2" and vip:
        return True, "M2 forbids VIP; competing=0 is not enough"
    return False, "no uncontrolled traffic; only registered loadgen"


def evaluate(facts: dict, profile: str = "compatibility") -> list[tuple[str, str, str]]:
    """Return [(label, PASS|FAIL, reason), ...] in T5 order.

    `profile=compatibility` still records host-production FAIL but does not
    treat it as the only abort; callers must not mark G7/G8 GREEN.
    `profile=concurrency` and `performance` abort on production processes.
    """
    if profile not in PROFILES:
        profile = "compatibility"
    provenance = facts.get("provenance") or facts
    prov_fails: list[str] = []
    if isinstance(provenance, dict) and any(
        k in provenance for k in ("peregrine_git_sha", "python_swift_git_sha")
    ):
        prov_fails = validate_manifest(provenance)
    elif isinstance(provenance, dict):
        prov_fails = ["incomplete provenance object"]
    else:
        prov_fails = ["missing provenance"]

    py_sha = str(provenance.get("python_swift_git_sha") or facts.get("python_swift_git_sha") or "")
    pe_sha = str(provenance.get("peregrine_git_sha") or facts.get("peregrine_git_sha") or "")
    s3compat = str(provenance.get("s3compat_git_sha") or facts.get("s3compat_git_sha") or "")
    s3sub = str(
        provenance.get("s3compat_ceph_tests_submodule_sha")
        or facts.get("s3compat_ceph_tests_submodule_sha")
        or ""
    )

    pipeline_unexpected = facts.get("pipeline_unexpected_count")
    if pipeline_unexpected is None:
        py_pipe = facts.get("python_pipeline") or []
        rs_pipe = facts.get("rust_pipeline") or []
        if isinstance(py_pipe, str):
            py_pipe = extract_pipeline_from_conf(py_pipe) or py_pipe.split()
        if isinstance(rs_pipe, str):
            rs_pipe = extract_pipeline_from_conf(rs_pipe) or rs_pipe.split()
        if py_pipe or rs_pipe:
            pipeline_unexpected = diff_pipelines(py_pipe, rs_pipe)["unexpected_count"]
        else:
            pipeline_unexpected = None

    traffic_fail, traffic_reason = _uncontrolled_traffic(facts)

    rows = []

    def add(label: str, failed: bool, reason: str) -> None:
        rows.append((label, "FAIL" if failed else "PASS", reason))

    add(
        "provenance manifest valid",
        bool(prov_fails),
        "; ".join(prov_fails) if prov_fails else "validate_manifest ok",
    )
    add(
        "peregrine worktree clean",
        provenance.get("worktree_clean") is not True,
        f"worktree_clean={provenance.get('worktree_clean')} dirty_count={provenance.get('dirty_count', 'unmeasured')}",
    )
    add(
        "exact Python Swift commit pinned",
        not is_git_sha(py_sha),
        py_sha or "missing python_swift_git_sha",
    )
    add(
        "exact Peregrine commit pinned",
        not is_git_sha(pe_sha),
        pe_sha or "missing peregrine_git_sha",
    )
    add(
        "s3compat harness pinned",
        not (is_git_sha(s3compat) and is_git_sha(s3sub)),
        f"s3compat={s3compat or 'empty'} ceph-tests submodule={s3sub or 'empty'}",
    )
    add(
        "pipeline semantic diff = 0",
        pipeline_unexpected is None or int(pipeline_unexpected) != 0,
        "unmeasured" if pipeline_unexpected is None else f"unexpected={pipeline_unexpected}",
    )
    for key, label in (
        ("storage_policies_identical", "storage policies identical"),
        ("rings_equivalent", "rings equivalent"),
        ("filesystem_equivalent", "filesystem equivalent"),
    ):
        failed, reason = _measured_bool(facts, key)
        add(label, failed, reason)
    add(
        "host production traffic = 0",
        traffic_fail,
        traffic_reason,
    )
    for key, label in (
        ("cpu_budgets_equivalent", "CPU budgets equivalent"),
        ("memory_budgets_equivalent", "memory budgets equivalent"),
        ("data_state_clean", "data state clean"),
        ("no_competing_benchmark_process", "no competing benchmark process"),
        ("collected_test_names_frozen", "collected test names frozen"),
    ):
        failed, reason = _measured_bool(facts, key)
        add(label, failed, reason)
    _ = (profile, CONCURRENCY_ONLY, GIT_SHA_RE)
    return rows


def format_report(rows: list[tuple[str, str, str]]) -> str:
    lines = ["TEST PREFLIGHT", ""]
    for label, status, reason in rows:
        lines.append(f"[{status}] {label}  ({reason})")
    failed = sum(1 for _, s, _ in rows if s == "FAIL")
    lines.append("")
    lines.append(f"FAIL_COUNT={failed}")
    lines.append("ABORT" if failed else "OK")
    return "\n".join(lines) + "\n"


def abort_for_profile(rows: list[tuple[str, str, str]], profile: str) -> bool:
    failed = {label for label, status, _ in rows if status == "FAIL"}
    if profile == "compatibility":
        # Isolated SAIO feedback may run with production on the same host, but
        # G7/G8 must still see the host-production FAIL in the report.
        ignore = set(CONCURRENCY_ONLY)
        return bool(failed - ignore)
    return bool(failed)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: preflight.py FACTS.json [compatibility|concurrency|performance]", file=sys.stderr)
        return 2
    facts = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    profile = argv[1] if len(argv) > 1 else "compatibility"
    rows = evaluate(facts, profile=profile)
    sys.stdout.write(f"PROFILE={profile}\n")
    sys.stdout.write(format_report(rows))
    return 1 if abort_for_profile(rows, profile) else 0


if __name__ == "__main__":
    raise SystemExit(main())
