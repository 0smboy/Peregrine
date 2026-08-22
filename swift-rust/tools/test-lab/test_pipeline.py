#!/usr/bin/env python3
"""Drive the shipped pipeline normalize/diff (not a copy)."""
from __future__ import annotations

import unittest
from pathlib import Path

import pipeline

HERE = Path(__file__).resolve().parent
PROFILES = HERE.parents[1] / "tests" / "profiles"


class PipelineNormalizeDiff(unittest.TestCase):
    def test_hyphen_underscore_aliases_match(self):
        left = pipeline.parse_pipeline_tokens(
            "pipeline = catch-errors health-check proxy_logging listing-formats tempauth"
        )
        right = pipeline.parse_pipeline_tokens(
            "pipeline = catch_errors healthcheck proxy-logging listing_formats tempauth"
        )
        diff = pipeline.diff_pipelines(left, right)
        self.assertEqual(diff["unexpected_count"], 0, diff)

    def test_identical_canonical_render_has_zero_unexpected(self):
        profile = pipeline.load_profile(PROFILES / "swift-core.yaml")
        py_conf = pipeline.render_proxy_conf(profile, "python")
        rs_conf = pipeline.render_proxy_conf(profile, "rust")
        py_n = pipeline.extract_pipeline_from_conf(py_conf)
        rs_n = pipeline.extract_pipeline_from_conf(rs_conf)
        diff = pipeline.diff_pipelines(py_n, rs_n)
        self.assertEqual(py_n, rs_n)
        self.assertEqual(diff["unexpected_count"], 0, diff)

    def test_mutant_extra_filter_is_unexpected(self):
        profile = pipeline.load_profile(PROFILES / "swift-core.yaml")
        py_conf = pipeline.render_proxy_conf(profile, "python")
        mutant = dict(profile)
        mutant["pipeline"] = list(profile["pipeline"]) + ["bulk"]
        rs_conf = pipeline.render_proxy_conf(mutant, "rust")
        diff = pipeline.diff_pipelines(
            pipeline.extract_pipeline_from_conf(py_conf),
            pipeline.extract_pipeline_from_conf(rs_conf),
        )
        self.assertGreater(diff["unexpected_count"], 0, diff)
        self.assertIn("bulk", diff["only_right"])

    def test_live_python_vs_rust_saio_is_unexpected(self):
        python = (
            "catch_errors gatekeeper healthcheck proxy-logging cache "
            "listing_formats s3api tempauth copy slo dlo versioned_writes symlink"
        )
        rust = (
            "catch_errors gatekeeper healthcheck proxy-logging cache listing_formats "
            "bulk tempurl formpost staticweb container_quotas account_quotas symlink "
            "versioned_writes s3api tempauth copy slo dlo"
        )
        diff = pipeline.diff_pipelines(python.split(), rust.split())
        self.assertGreater(diff["unexpected_count"], 0)
        for extra in ("bulk", "tempurl", "formpost", "staticweb"):
            self.assertIn(extra, diff["only_right"])

    def test_s3_tempauth_profile_loads(self):
        profile = pipeline.load_profile(PROFILES / "s3-tempauth.yaml")
        self.assertIn("s3api", profile["pipeline"])
        self.assertLess(
            profile["pipeline"].index("s3api"),
            profile["pipeline"].index("tempauth"),
        )


if __name__ == "__main__":
    unittest.main()
