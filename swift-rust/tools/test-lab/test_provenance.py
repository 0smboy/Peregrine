#!/usr/bin/env python3
from __future__ import annotations

import unittest

import provenance


VALID = {
    "peregrine_git_sha": "b9e4ef976d2d3b17feff4f99b813ca2f481a6f1a",
    "python_swift_git_sha": "541a59863752de0636a1747e5c3223676a904c35",
    "python_swift_version": "0.0.0",
    "swift_tests_git_sha": "541a59863752de0636a1747e5c3223676a904c35",
    "s3compat_git_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "s3compat_ceph_tests_submodule_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "rustc_version": "1.93.0",
    "cargo_lock_sha256": "56e00f4fc7627a0d397d1f2296e693004547f8a7b2163dfae71205571115bc30",
    "source_tree_sha256": "44" * 32,
    "kernel": "5.14.0-687.31.1.el9_8.x86_64",
    "glibc": "glibc-2.34-274.el9_8",
    "liberasurecode_version": "1.0.0",
    "test_config_sha256": "11" * 32,
    "ring_sha256": "22" * 32,
    "pipeline_sha256": "33" * 32,
    "worktree_clean": True,
    "dirty_count": 0,
    "deployed_binary_matches_commit": True,
}


class ProvenanceValidate(unittest.TestCase):
    def test_complete_manifest_passes(self):
        self.assertEqual(provenance.validate_manifest(VALID), [])

    def test_empty_sha_fails(self):
        bad = dict(VALID)
        bad["python_swift_git_sha"] = ""
        fails = provenance.validate_manifest(bad)
        self.assertTrue(any("python_swift_git_sha" in f for f in fails), fails)

    def test_info_version_without_git_sha_fails(self):
        bad = dict(VALID)
        bad["python_swift_git_sha"] = ""
        bad["python_swift_version"] = "2.33.0"
        fails = provenance.validate_manifest(bad)
        self.assertTrue(fails)

    def test_short_git_sha_fails(self):
        bad = dict(VALID)
        bad["peregrine_git_sha"] = "abc123"
        fails = provenance.validate_manifest(bad)
        self.assertTrue(any("peregrine_git_sha" in f for f in fails), fails)

    def test_missing_key_fails(self):
        bad = dict(VALID)
        del bad["cargo_lock_sha256"]
        fails = provenance.validate_manifest(bad)
        self.assertTrue(any("cargo_lock_sha256" in f for f in fails), fails)

    def test_dirty_worktree_fails(self):
        bad = dict(VALID)
        bad["worktree_clean"] = False
        bad["dirty_count"] = 48
        fails = provenance.validate_manifest(bad)
        self.assertTrue(any("worktree is not clean" in f for f in fails), fails)

    def test_ceph_s3tests_without_s3compat_fails_lineage(self):
        bad = dict(VALID)
        bad["ceph_s3tests_git_sha"] = "cccccccccccccccccccccccccccccccccccccccc"
        bad["s3compat_git_sha"] = ""
        fails = provenance.validate_manifest(bad)
        self.assertTrue(any("wrong harness lineage" in f or "s3compat" in f for f in fails), fails)


if __name__ == "__main__":
    unittest.main()
