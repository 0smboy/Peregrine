#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("freeze_candidate", HERE / "freeze-candidate.py")
freeze_mod = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(freeze_mod)

SHA_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
SHA_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
REAL_YAML = HERE / "g7" / "acceptance.yaml"
REAL_JSON = HERE / "g7" / "acceptance.json"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def _seed_repo(root: Path) -> Path:
    repo = root / "Peregrine"
    g7 = repo / "swift-rust" / "tools" / "test-lab" / "g7"
    g7.mkdir(parents=True)
    (repo / "swift-rust" / "Cargo.lock").write_text("# lock\n", encoding="utf-8")
    (g7 / "acceptance.yaml").write_text(REAL_YAML.read_text(encoding="utf-8"), encoding="utf-8")
    (g7 / "acceptance.json").write_text(REAL_JSON.read_text(encoding="utf-8"), encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "freeze@test")
    _git(repo, "config", "user.name", "freeze")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "seed")
    return repo


class FreezeCandidate(unittest.TestCase):
    def test_real_files_are_still_pending(self):
        self.assertEqual(freeze_mod.read_candidate(REAL_YAML), "PENDING_FREEZE")
        self.assertEqual(freeze_mod.read_candidate(REAL_JSON), "PENDING_FREEZE")

    def test_freeze_is_idempotent_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _seed_repo(Path(tmp))
            first = freeze_mod.freeze(repo, SHA_A, write=True, allow_dirty=True)
            self.assertEqual(first["action"], "frozen")
            self.assertTrue(first["changed"])
            self.assertEqual(first["acceptance_yaml_candidate"], SHA_A)
            self.assertEqual(first["acceptance_json_candidate"], SHA_A)
            yaml_hash = first["acceptance_yaml_sha256"]

            again = freeze_mod.freeze(repo, SHA_A, write=True, allow_dirty=True)
            self.assertEqual(again["action"], "already-frozen")
            self.assertFalse(again["changed"])
            self.assertEqual(again["acceptance_yaml_sha256"], yaml_hash)

            with self.assertRaises(SystemExit):
                freeze_mod.freeze(repo, SHA_B, write=True, allow_dirty=True)
            self.assertEqual(freeze_mod.read_candidate(repo / freeze_mod.YAML_REL), SHA_A)

    def test_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _seed_repo(Path(tmp))
            out = freeze_mod.freeze(repo, SHA_A, write=False, allow_dirty=True)
            self.assertEqual(out["action"], "would-freeze")
            self.assertFalse(out["changed"])
            self.assertEqual(freeze_mod.read_candidate(repo / freeze_mod.YAML_REL), "PENDING_FREEZE")

    def test_refuses_production_write_path(self):
        self.assertEqual(
            freeze_mod.FORBIDDEN_WRITE_PREFIXES,
            ("/etc", "/srv", "/usr", "/var/run", "/var/log"),
        )
        with self.assertRaises(SystemExit):
            freeze_mod.assert_in_repo_write(Path("/etc/g6-rust/acceptance.yaml"), Path("/tmp/x"))
        # repo=/ would otherwise allow these; prefixes must still refuse.
        for path in (
            "/etc/g6-rust/acceptance.yaml",
            "/srv/node/d1",
            "/usr/local/bin/swift-proxy-server",
        ):
            with self.assertRaises(SystemExit):
                freeze_mod.assert_in_repo_write(Path(path), Path("/"))

    def test_lab_checkout_under_root_work_is_not_forbidden(self):
        self.assertNotIn("/root/work", freeze_mod.FORBIDDEN_WRITE_PREFIXES)
        lab = Path(
            "/root/work/pa-v2-cfinal/swift-rust/tools/test-lab/g7/acceptance.yaml"
        )
        text = str(lab)
        self.assertFalse(
            any(text == prefix or text.startswith(prefix + "/")
                for prefix in freeze_mod.FORBIDDEN_WRITE_PREFIXES),
            freeze_mod.FORBIDDEN_WRITE_PREFIXES,
        )

    def test_checklist_names_g0_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = _seed_repo(Path(tmp))
            out = freeze_mod.freeze(repo, SHA_A, write=False, allow_dirty=True)
            self.assertEqual(out["peregrine_git_sha"], SHA_A)
            self.assertIn("python_swift_git_sha", out["remaining_g0_not_run"])
            self.assertTrue(any("/proc/exe" in item for item in out["remaining_g0_not_run"]))
            self.assertEqual(len(out["acceptance_yaml_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
