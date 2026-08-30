#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
G7_DIR = HERE / "g7"
if not G7_DIR.is_dir():
    G7_DIR = HERE / "g7-audit-ec23bff"
MODULE_SPEC = importlib.util.spec_from_file_location("g7_runner", G7_DIR / "g7-run.py")
g7 = importlib.util.module_from_spec(MODULE_SPEC)
assert MODULE_SPEC.loader is not None
MODULE_SPEC.loader.exec_module(g7)

SPEC = {
    "bounds": {
        "health_head_p99_ms": 250,
        "scheduler_lag_p99_ms": 100,
        "scheduler_lag_p999_ms": 500,
        "orphan_temp": 0,
    }
}


def raw_base(target=1, *, health=False):
    raw = {
        "target": target,
        "opened": target,
        "scheduler_lag_p99_ms": 1.0,
        "scheduler_lag_p999_ms": 2.0,
        "recon_samples": 20,
        "blocking_network_wait_delta": 0,
        "thread_growth_within_bound": True,
        "storage_threads_within_bound": True,
        "steady_return": {"ok": True},
    }
    if health:
        raw.update({"health_p99_ms": 5.0, "health_samples": 40, "health_ok": 40})
    return raw


class G7FailClosedClassification(unittest.TestCase):
    def classify(self, kind, raw, **case_fields):
        case = {"_name": "unit", "kind": kind, **case_fields}
        return g7.classify(case, raw, SPEC)

    def test_missing_opened_is_fail(self):
        raw = raw_base()
        del raw["opened"]
        result = self.classify("cancel", raw, n=1)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("opened", result["reason"])

    def test_short_open_is_environment_blocked(self):
        result = self.classify("cancel", {**raw_base(10), "opened": 9}, n=10)
        self.assertEqual(result["verdict"], "ENVIRONMENT BLOCKED")

    def test_idle_requires_response_correctness(self):
        raw = raw_base(10, health=True)
        result = self.classify("idle_keepalive", raw, target=10)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("http_ok", result["reason"])

    def test_idle_affirmative_proof_passes(self):
        raw = {**raw_base(10, health=True), "http_ok": 10, "failed": 0}
        result = self.classify("idle_keepalive", raw, target=10)
        self.assertEqual(result["verdict"], "PASS")

    def test_health_missing_is_fail(self):
        raw = {**raw_base(10), "http_ok": 10, "failed": 0}
        result = self.classify("idle_keepalive", raw, target=10)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("health_p99_ms", result["reason"])

    def test_slow_put_requires_all_http_responses(self):
        raw = {**raw_base(3, health=True), "responses": 2, "http_2xx": 2, "failed": 1}
        result = self.classify("slow_put", raw, target=3)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("responses", result["reason"])

    def test_cancel_rejects_orphan_temp(self):
        raw = {**raw_base(4), "tmp_count": 1, "committed_objects": 0}
        result = self.classify("cancel", raw, n=4)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("tmp_count", result["reason"])

    def test_cancel_requires_objects_absent(self):
        raw = {**raw_base(4), "tmp_count": 0}
        result = self.classify("cancel", raw, n=4)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("committed_objects", result["reason"])

    def test_network_fault_requires_a_packet_hit(self):
        raw = {
            **raw_base(1, health=True),
            "fault_armed": True,
            "fault_hits": 0,
            "put_status": 201,
        }
        result = self.classify("blackhole", raw, target=1)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("exercised path", result["reason"])

    def test_partial_write_must_not_commit_and_must_clean_tmp(self):
        raw = {**raw_base(1), "expect_not_2xx": True, "get_status": 404, "tmp_count": 0}
        result = self.classify("partial_write", raw, target=1)
        self.assertEqual(result["verdict"], "PASS")

    def test_eio_without_injection_is_not_run(self):
        raw = {**raw_base(1), "verdict_hint": "NOT RUN", "not_run_reason": "no isolated injector"}
        result = self.classify("eio", raw, target=1)
        self.assertEqual(result["verdict"], "NOT RUN")

    def test_durability_sigterm_requires_barrier_observation(self):
        raw = {
            **raw_base(1),
            "put_status": 201,
            "get_after": 200,
            "len": 4096,
            "expected_len": 4096,
            "restart_ok": True,
        }
        result = self.classify("sigterm_barrier", raw, target=1)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("barrier_observed", result["reason"])

    def test_scheduler_lag_threshold_is_enforced(self):
        raw = {
            **raw_base(1),
            "tmp_count": 0,
            "committed_objects": 0,
            "scheduler_lag_p99_ms": 101,
        }
        result = self.classify("cancel", raw, n=1)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertIn("scheduler lag p99", result["reason"])

    def test_dummy_calibration_does_not_require_sut_metrics(self):
        case = {"_name": "dummy_10", "kind": "idle_keepalive", "target": 10}
        raw = {"opened": 10, "http_ok": 10, "_rc": 0}
        result = g7.classify(case, raw, SPEC, calibration=True)
        self.assertEqual(result["verdict"], "PASS")


class G7ReconEvidence(unittest.TestCase):
    def test_labeled_metrics_keep_domain_identity_and_total(self):
        parsed = g7.parse_recon(
            'blocking_threads{domain="storage"} 3\n'
            'blocking_threads{domain="db"} 2\n'
            'spawn_blocking_total{domain="other"} 7\n'
        )
        self.assertEqual(parsed["blocking_threads_storage"], 3)
        self.assertEqual(parsed["blocking_threads_db"], 2)
        self.assertEqual(parsed["blocking_threads"], 5)
        self.assertEqual(parsed["spawn_blocking_total_other"], 7)

    def test_recon_evidence_converts_scheduler_nanoseconds_to_ms(self):
        before = [
            {
                "runtime_scheduler_lag": 1_000_000,
                "process_threads": 10,
                "runtime_worker_threads": 4,
                "blocking_threads_storage": 0,
                "blocking_threads_db": 0,
                "blocking_network_wait_total": 0,
            }
        ]
        during = [
            {
                "runtime_scheduler_lag": lag,
                "process_threads": 12,
                "runtime_worker_threads": 4,
                "blocking_threads_storage": 1,
                "blocking_threads_db": 1,
                "blocking_network_wait_total": 0,
            }
            for lag in (1_000_000, 2_000_000, 3_000_000)
        ]
        evidence = g7.recon_evidence(before, during, during[-1:])
        self.assertEqual(evidence["recon_samples"], 3)
        self.assertEqual(evidence["scheduler_lag_p99_ms"], 2.0)
        self.assertEqual(evidence["scheduler_lag_p999_ms"], 2.0)
        self.assertTrue(evidence["thread_growth_within_bound"])
        self.assertEqual(evidence["blocking_network_wait_delta"], 0)


if __name__ == "__main__":
    unittest.main()
