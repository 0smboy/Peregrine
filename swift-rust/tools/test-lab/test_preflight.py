#!/usr/bin/env python3
from __future__ import annotations

import unittest

import preflight


_SHA = "541a59863752de0636a1747e5c3223676a904c35"
_HASH = "aa" * 32
GREEN_FACTS = {
    "python_swift_git_sha": _SHA,
    "peregrine_git_sha": _SHA,
    "swift_tests_git_sha": _SHA,
    "s3compat_git_sha": _SHA,
    "s3compat_ceph_tests_submodule_sha": _SHA,
    "python_swift_version": "0.0.0",
    "rustc_version": "rustc 1.97.1",
    "cargo_lock_sha256": _HASH,
    "source_tree_sha256": _HASH,
    "kernel": "x",
    "glibc": "x",
    "liberasurecode_version": "1",
    "test_config_sha256": _HASH,
    "ring_sha256": _HASH,
    "pipeline_sha256": _HASH,
    "worktree_clean": True,
    "dirty_count": 0,
    "deployed_binary_matches_commit": True,
    "pipeline_unexpected_count": 0,
    "storage_policies_identical": True,
    "rings_equivalent": True,
    "filesystem_equivalent": True,
    "host_production_traffic": False,
    "cpu_budgets_equivalent": True,
    "memory_budgets_equivalent": True,
    "data_state_clean": True,
    "no_competing_benchmark_process": True,
    "collected_test_names_frozen": True,
    "measurement_source": {
        "storage_policies_identical": "measured",
        "rings_equivalent": "measured",
        "filesystem_equivalent": "measured",
        "cpu_budgets_equivalent": "measured",
        "memory_budgets_equivalent": "measured",
        "data_state_clean": "measured",
        "no_competing_benchmark_process": "measured",
        "collected_test_names_frozen": "measured",
    },
}


class PreflightT5(unittest.TestCase):
    def test_all_pass_when_facts_green(self):
        rows = preflight.evaluate(GREEN_FACTS)
        labels = [r[0] for r in rows]
        self.assertEqual(labels, preflight.T5)
        self.assertTrue(all(s == "PASS" for _, s, _ in rows), rows)
        report = preflight.format_report(rows)
        self.assertIn("[PASS] host production traffic = 0", report)
        self.assertIn("FAIL_COUNT=0", report)

    def test_vip_fails_production_traffic_line(self):
        facts = dict(GREEN_FACTS)
        facts["host_production_traffic"] = True
        rows = preflight.evaluate(facts)
        by = {label: status for label, status, _ in rows}
        self.assertEqual(by["host production traffic = 0"], "FAIL")
        self.assertEqual(by["exact Python Swift commit pinned"], "PASS")
        report = preflight.format_report(rows)
        self.assertIn("ABORT", report)

    def test_pipeline_drift_fails(self):
        facts = dict(GREEN_FACTS)
        facts["python_pipeline"] = "catch_errors tempauth copy"
        facts["rust_pipeline"] = "catch_errors bulk tempauth copy"
        facts.pop("pipeline_unexpected_count")
        rows = preflight.evaluate(facts)
        by = {label: status for label, status, _ in rows}
        self.assertEqual(by["pipeline semantic diff = 0"], "FAIL")

    def test_unmeasured_is_fail_closed(self):
        rows = preflight.evaluate(
            {
                "python_swift_git_sha": "541a59863752de0636a1747e5c3223676a904c35",
                "peregrine_git_sha": "e65d26a05a34ba16caad2054d011563fad3c1320",
            }
        )
        failed = [label for label, status, _ in rows if status == "FAIL"]
        self.assertIn("provenance manifest valid", failed)
        self.assertIn("s3compat harness pinned", failed)
        self.assertIn("pipeline semantic diff = 0", failed)
        self.assertGreaterEqual(len(failed), 3)

    def test_operator_declared_true_is_fail(self):
        facts = dict(GREEN_FACTS)
        facts["measurement_source"] = dict(GREEN_FACTS["measurement_source"])
        facts["measurement_source"]["rings_equivalent"] = "operator_declared"
        rows = preflight.evaluate(facts)
        by = {label: (status, reason) for label, status, reason in rows}
        self.assertEqual(by["rings equivalent"][0], "FAIL")
        self.assertIn("operator-declared", by["rings equivalent"][1])

    def test_provenance_fails_are_not_ignored(self):
        facts = dict(GREEN_FACTS)
        facts["worktree_clean"] = False
        facts["dirty_count"] = 48
        rows = preflight.evaluate(facts)
        by = {label: status for label, status, _ in rows}
        self.assertEqual(by["provenance manifest valid"], "FAIL")
        self.assertEqual(by["peregrine worktree clean"], "FAIL")

    def test_compatibility_profile_does_not_abort_only_on_vip(self):
        facts = dict(GREEN_FACTS)
        facts["host_production_traffic"] = True
        rows = preflight.evaluate(facts, profile="compatibility")
        self.assertTrue(preflight.abort_for_profile(rows, "concurrency"))
        self.assertFalse(preflight.abort_for_profile(rows, "compatibility"))


if __name__ == "__main__":
    unittest.main()
