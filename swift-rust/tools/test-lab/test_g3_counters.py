#!/usr/bin/env python3
from __future__ import annotations

import unittest

import g3_counters

SAMPLE = """
# HELP native_async_requests_total Requests served by a native AsyncService.
# TYPE native_async_requests_total gauge
native_async_requests_total 4
legacy_sync_handler_requests_total 0
block_in_place_total 2
http_requests_total{engine="hyper"} 6
blocking_network_wait_total 0
connections_open 1
"""


class G3Parse(unittest.TestCase):
    def test_parse_labeled_and_plain(self):
        samples = g3_counters.parse_prometheus(SAMPLE)
        g3 = g3_counters.extract_g3(samples)
        self.assertEqual(g3["native_async_requests_total"], 4)
        self.assertEqual(g3["legacy_sync_handler_requests_total"], 0)
        self.assertEqual(g3["block_in_place_total"], 2)
        self.assertEqual(g3["http_requests_total_hyper"], 6)

    def test_swift_path_green(self):
        before = {
            "http_requests_total_hyper": 0,
            "native_async_requests_total": 0,
            "legacy_sync_handler_requests_total": 0,
            "block_in_place_total": 0,
            "blocking_network_wait_total": 0,
        }
        after = dict(before)
        after["http_requests_total_hyper"] = 1
        after["native_async_requests_total"] = 1
        verdict = g3_counters.evaluate_path(g3_counters.delta(before, after), path="Swift GET")
        self.assertEqual(verdict["result"], "GREEN")

    def test_s3_block_in_place_is_nogo(self):
        before = {
            "http_requests_total_hyper": 0,
            "native_async_requests_total": 1,
            "legacy_sync_handler_requests_total": 0,
            "block_in_place_total": 0,
            "blocking_network_wait_total": 0,
        }
        after = dict(before)
        after["http_requests_total_hyper"] = 1
        after["native_async_requests_total"] = 2
        after["block_in_place_total"] = 1
        verdict = g3_counters.evaluate_path(g3_counters.delta(before, after), path="S3 GET")
        self.assertEqual(verdict["result"], "NO-GO")
        self.assertTrue(any("S3 ASYNC GATE" in r for r in verdict["reasons"]))

    def test_recon_only_is_not_activation(self):
        zero = {
            "http_requests_total_hyper": 0,
            "native_async_requests_total": 0,
            "legacy_sync_handler_requests_total": 0,
            "block_in_place_total": 0,
            "blocking_network_wait_total": 0,
        }
        verdict = g3_counters.evaluate_path(g3_counters.delta(zero, zero), path="Swift GET")
        self.assertEqual(verdict["result"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
