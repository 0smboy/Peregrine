#!/usr/bin/env python3
from __future__ import annotations

import unittest

import g6_ledger


def ledger(n_rep=147, n_ec=32, status="PASS", mutate=None):
    rows = []
    for i in range(n_rep):
        rows.append({"id": f"rep-{i:03d}", "lane": "replication", "status": status})
    for i in range(n_ec):
        rows.append({"id": f"ec-{i:03d}", "lane": "ec", "status": status})
    if mutate:
        mutate(rows)
    return {"identities": rows}


class G6LedgerFailClosed(unittest.TestCase):
    def test_exact_179_pass_is_green(self):
        result = g6_ledger.score(ledger())
        self.assertEqual(result["verdict"], "GREEN", result)
        self.assertEqual(result["identities"], 179)
        self.assertEqual(result["replication"], 147)
        self.assertEqual(result["ec"], 32)

    def test_expected_skips_still_green(self):
        def four_skips(rows):
            for row in rows[:4]:
                row["status"] = "SKIP"

        result = g6_ledger.score(ledger(mutate=four_skips))
        self.assertEqual(result["verdict"], "GREEN", result)

    def test_178_is_not_green(self):
        result = g6_ledger.score(ledger(n_rep=146, n_ec=32))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any("147" in v for v in result["violations"]), result)

    def test_retry_fail_then_pass_is_forbidden(self):
        def retry(rows):
            rows[0]["attempts"] = [{"status": "FAIL"}, {"status": "PASS"}]
            rows[0]["status"] = "PASS"

        result = g6_ledger.score(ledger(mutate=retry))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any("retry-to-PASS" in v for v in result["violations"]), result)

    def test_retry_count_cannot_wash_timeout_into_pass(self):
        def retry(rows):
            rows[0]["retry_count"] = 2
            rows[0]["status"] = "PASS"

        result = g6_ledger.score(ledger(mutate=retry))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any("retry-to-PASS" in v for v in result["violations"]), result)

    def test_timeout_status_cannot_be_pass(self):
        def timeout(rows):
            rows[0]["status"] = "TIMEOUT"

        result = g6_ledger.score(ledger(mutate=timeout))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any("TIMEOUT" in v for v in result["violations"]), result)
        self.assertEqual(g6_ledger.row_status({"status": "TIMEOUT"}), "TIMEOUT")

    def test_leftover_timeout_child_cannot_be_scored_pass(self):
        claimed = {
            "id": "rep-000",
            "lane": "replication",
            "status": "PASS",
            "leftover_timeout": True,
        }
        self.assertEqual(g6_ledger.row_status(claimed), "TIMEOUT")
        self.assertTrue(g6_ledger.child_timed_out(claimed))

        def leftover(rows):
            rows[0].update({"status": "PASS", "timeout_child": True})

        result = g6_ledger.score(ledger(mutate=leftover))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any("timeout" in v.lower() for v in result["violations"]),
            result,
        )

    def test_parent_pass_with_timeout_child_is_timeout(self):
        row = {
            "id": "rep-000",
            "lane": "replication",
            "status": "PASS",
            "children": [{"status": "TIMEOUT", "leftover_timeout": True}],
        }
        self.assertEqual(g6_ledger.row_status(row), "TIMEOUT")

        def nested(rows):
            rows[0]["children"] = [{"status": "TIMEOUT"}]

        result = g6_ledger.score(ledger(mutate=nested))
        self.assertEqual(result["verdict"], "FAIL")

    def test_duplicate_identity_is_not_a_second_merge(self):
        def dup(rows):
            rows.append(dict(rows[0]))

        result = g6_ledger.score(ledger(mutate=dup))
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(any("more than once" in v for v in result["violations"]), result)

    def test_ok_alias_is_pass_but_not_via_retry(self):
        self.assertEqual(g6_ledger.row_status({"status": "ok"}), "PASS")
        self.assertTrue(
            g6_ledger.retry_to_pass(
                {"status": "PASS", "attempts": ["TIMEOUT", "OK"]}
            )
        )


if __name__ == "__main__":
    unittest.main()
