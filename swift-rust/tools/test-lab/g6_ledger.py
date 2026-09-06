#!/usr/bin/env python3
"""G6 identity ledger scorer: no retry-to-PASS, no timeout-as-PASS.

The live probe runner lives on Swift2. This module is the fail-closed
score of a merged 179-identity ledger (147 replication + 32 EC).

Historical w103 (175 OK + 4 skips) is invalid: a runner that retried a
FAIL/TIMEOUT into PASS, or scored a leftover timeout child as PASS, must
not be able to produce GREEN here.

This scorer does not talk to production, SSH, or the VIP.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

REPLICATION_COUNT = 147
EC_COUNT = 32
TOTAL_IDENTITIES = REPLICATION_COUNT + EC_COUNT

PASS_ALIASES = frozenset({"PASS", "OK", "SUCCESS"})
TIMEOUT_ALIASES = frozenset({"TIMEOUT", "TIMED_OUT", "TIME_OUT", "TIMEDOUT"})
FAIL_ALIASES = frozenset({"FAIL", "FAILED", "ERROR", "NOT_RUN", "NOT RUN"})
LANES = frozenset({"replication", "ec"})


def _as_bool(value: Any) -> bool:
    return value is True or value == 1 or (
        isinstance(value, str) and value.strip().lower() in {"1", "true", "yes"}
    )


def _raw_status(row: Any) -> str:
    if isinstance(row, str):
        return row.strip().upper().replace("-", "_")
    if not isinstance(row, dict):
        return ""
    raw = row.get("status", row.get("verdict", ""))
    return str(raw or "").strip().upper().replace("-", "_")


def child_timed_out(row: dict) -> bool:
    if _as_bool(row.get("timeout_child")):
        return True
    if _as_bool(row.get("leftover_timeout")):
        return True
    if _as_bool(row.get("child_timed_out")):
        return True
    if _raw_status(row) in TIMEOUT_ALIASES:
        return True
    for child in row.get("children") or []:
        if isinstance(child, dict) and child_timed_out(child):
            return True
    return False


def row_status(row: Any) -> str:
    """Normalize one identity. Timeout leftovers cannot become PASS."""
    if isinstance(row, str):
        raw = _raw_status(row)
        if raw in PASS_ALIASES:
            return "PASS"
        if raw in TIMEOUT_ALIASES:
            return "TIMEOUT"
        if raw in FAIL_ALIASES or raw == "SKIP":
            return "SKIP" if raw == "SKIP" else raw.replace("FAILED", "FAIL").replace("NOT_RUN", "NOT RUN")
        return raw or "UNKNOWN"
    if not isinstance(row, dict):
        return "UNKNOWN"
    if child_timed_out(row):
        return "TIMEOUT"
    raw = _raw_status(row)
    if raw in PASS_ALIASES:
        return "PASS"
    if raw in TIMEOUT_ALIASES:
        return "TIMEOUT"
    if raw == "SKIP":
        return "SKIP"
    if raw in {"FAIL", "FAILED"}:
        return "FAIL"
    if raw in {"ERROR"}:
        return "ERROR"
    if raw in {"NOT_RUN", "NOT RUN"}:
        return "NOT RUN"
    return raw or "UNKNOWN"


def retry_to_pass(row: dict) -> bool:
    """True when a prior FAIL/TIMEOUT/ERROR is later reported as PASS."""
    if not isinstance(row, dict):
        return False
    attempts = row.get("attempts")
    if isinstance(attempts, list) and attempts:
        seen_bad = False
        for attempt in attempts:
            st = row_status(attempt) if not isinstance(attempt, str) else row_status({"status": attempt})
            if st in {"FAIL", "TIMEOUT", "ERROR"}:
                seen_bad = True
            if st == "PASS" and seen_bad:
                return True
        return False
    try:
        retries = int(row.get("retry_count") or 0)
    except (TypeError, ValueError):
        retries = 0
    return retries > 1 and row_status(row) == "PASS"


def score(ledger: dict) -> dict:
    """Score a merged ledger. GREEN only with exact 179 and zero violations."""
    violations: list[str] = []
    if not isinstance(ledger, dict):
        return {
            "verdict": "FAIL",
            "identities": 0,
            "replication": 0,
            "ec": 0,
            "violations": ["ledger is not an object"],
        }
    rows = ledger.get("identities")
    if not isinstance(rows, list):
        return {
            "verdict": "FAIL",
            "identities": 0,
            "replication": 0,
            "ec": 0,
            "violations": ["identities is not a list"],
        }

    seen: dict[str, str] = {}
    counts = {"replication": 0, "ec": 0}
    by_status: dict[str, int] = {}
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            violations.append(f"identity[{i}] is not an object")
            continue
        ident = str(row.get("id") or row.get("identity") or "").strip()
        lane = str(row.get("lane") or "").strip().lower()
        if not ident:
            violations.append(f"identity[{i}] missing id")
            continue
        if lane not in LANES:
            violations.append(f"{ident}: lane must be replication or ec, got {lane!r}")
        if ident in seen:
            violations.append(f"{ident}: merged more than once")
        seen[ident] = lane
        if lane in counts:
            counts[lane] += 1
        status = row_status(row)
        by_status[status] = by_status.get(status, 0) + 1
        if retry_to_pass(row):
            violations.append(f"{ident}: retry-to-PASS is forbidden")
        if child_timed_out(row) and _raw_status(row) in PASS_ALIASES:
            violations.append(f"{ident}: leftover timeout child cannot be PASS")
        if status == "TIMEOUT":
            violations.append(f"{ident}: TIMEOUT remains FAIL (leftover timeout process)")
        elif status not in {"PASS", "SKIP"}:
            violations.append(f"{ident}: {status} is not a G6 pass")

    if counts["replication"] != REPLICATION_COUNT:
        violations.append(
            f"replication identities {counts['replication']} != {REPLICATION_COUNT}"
        )
    if counts["ec"] != EC_COUNT:
        violations.append(f"ec identities {counts['ec']} != {EC_COUNT}")
    if len(seen) != TOTAL_IDENTITIES:
        violations.append(f"unique identities {len(seen)} != {TOTAL_IDENTITIES}")

    verdict = "GREEN" if not violations else "FAIL"
    return {
        "verdict": verdict,
        "identities": len(seen),
        "replication": counts["replication"],
        "ec": counts["ec"],
        "by_status": by_status,
        "violations": violations,
    }


def load_ledger(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("ledger", type=Path, help="merged 179-identity JSON ledger")
    args = p.parse_args(argv)
    result = score(load_ledger(args.ledger))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "GREEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
