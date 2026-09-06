#!/usr/bin/env python3
"""Freeze G7 candidate_commit (PENDING_FREEZE → SHA) and print G0 fields.

In-repo only. Does not SSH, bind ports, or write under /etc /srv /usr /var.
Idempotent: the same SHA is a no-op success. A different SHA is fail-closed.

This does not make any gate GREEN. It only records the SHA that a later
Swift2 run must build and score.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import provenance

HERE = Path(__file__).resolve().parent
DEFAULT_REPO = HERE.parents[2]
YAML_REL = Path("swift-rust/tools/test-lab/g7/acceptance.yaml")
JSON_REL = Path("swift-rust/tools/test-lab/g7/acceptance.json")
LOCK_REL = Path("swift-rust/Cargo.lock")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN_WRITE_PREFIXES = (
    "/etc",
    "/srv",
    "/usr",
    "/var/run",
    "/var/log",
    "/root/work",
)
PENDING = "PENDING_FREEZE"


def die(msg: str, code: int = 2) -> None:
    print(f"freeze-candidate: {msg}", file=sys.stderr)
    raise SystemExit(code)


def is_git_sha(value: str) -> bool:
    return bool(GIT_SHA_RE.fullmatch(value.strip().lower()))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_in_repo_write(path: Path, repo: Path) -> None:
    resolved = path.resolve()
    try:
        resolved.relative_to(repo.resolve())
    except ValueError:
        die(f"refusing to write outside the repo: {resolved}")
    text = str(resolved)
    for prefix in FORBIDDEN_WRITE_PREFIXES:
        if text == prefix or text.startswith(prefix + "/"):
            die(f"refusing production/lab write path {resolved}")


def git_head(repo: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        die(f"git rev-parse HEAD failed: {proc.stderr.strip() or proc.stdout.strip()}")
    sha = proc.stdout.strip().lower()
    if not is_git_sha(sha):
        die(f"HEAD is not a 40-char SHA: {sha!r}")
    return sha


def git_dirty_count(repo: Path) -> int:
    proc = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return -1
    return len([line for line in proc.stdout.splitlines() if line.strip()])


def rustc_version() -> str:
    proc = subprocess.run(
        ["rustc", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return "NOT MEASURED"
    return proc.stdout.strip() or "NOT MEASURED"


def read_candidate(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        doc = json.loads(text)
        val = doc.get("candidate_commit")
        return str(val) if val is not None else ""
    match = re.search(r'(?m)^candidate_commit:\s*"?([A-Za-z0-9_]+)"?\s*$', text)
    if not match:
        die(f"no candidate_commit field in {path}")
    return match.group(1)


def replace_candidate(text: str, old: str, new: str) -> str:
    if old not in text:
        die(f"candidate token {old!r} not found in file")
    return text.replace(old, new, 1)


def freeze(
    repo: Path,
    sha: str | None = None,
    *,
    write: bool = True,
    allow_dirty: bool = False,
    yaml_path: Path | None = None,
    json_path: Path | None = None,
) -> dict:
    repo = repo.resolve()
    yaml_path = (yaml_path or (repo / YAML_REL)).resolve()
    json_path = (json_path or (repo / JSON_REL)).resolve()
    lock_path = repo / LOCK_REL
    if write:
        assert_in_repo_write(yaml_path, repo)
        assert_in_repo_write(json_path, repo)

    target = (sha or git_head(repo)).strip().lower()
    if not is_git_sha(target):
        die(f"refusing non-SHA freeze target {target!r}")

    dirty = git_dirty_count(repo)
    worktree_clean = dirty == 0
    if write and not allow_dirty and not worktree_clean:
        die(
            "worktree is dirty; freeze the commit you will build, or pass --allow-dirty "
            f"(dirty_count={dirty})"
        )

    yaml_cur = read_candidate(yaml_path)
    json_cur = read_candidate(json_path)
    if yaml_cur != json_cur:
        die(f"acceptance.yaml ({yaml_cur}) and acceptance.json ({json_cur}) disagree")

    changed = False
    if yaml_cur == target:
        action = "already-frozen"
    elif yaml_cur == PENDING:
        if write:
            yaml_path.write_text(
                replace_candidate(yaml_path.read_text(encoding="utf-8"), PENDING, target),
                encoding="utf-8",
            )
            json_path.write_text(
                replace_candidate(json_path.read_text(encoding="utf-8"), PENDING, target),
                encoding="utf-8",
            )
            changed = True
        action = "frozen" if write else "would-freeze"
    else:
        die(
            f"already frozen to {yaml_cur}; refusing to overwrite with {target}. "
            "A scored freeze is immutable."
        )

    checklist = {
        "action": action,
        "changed": changed,
        "peregrine_git_sha": target,
        "worktree_clean": worktree_clean,
        "dirty_count": dirty,
        "acceptance_yaml_candidate": read_candidate(yaml_path) if write or yaml_cur == target else target,
        "acceptance_json_candidate": read_candidate(json_path) if write or json_cur == target else target,
        "acceptance_yaml_sha256": sha256_file(yaml_path),
        "acceptance_json_sha256": sha256_file(json_path),
        "cargo_lock_sha256": sha256_file(lock_path) if lock_path.is_file() else "NOT MEASURED",
        "rustc_version": rustc_version() + " (this host; re-measure on Swift2)",
        "remaining_g0_not_run": [
            key
            for key in provenance.REQUIRED_KEYS
            if key
            not in {
                "peregrine_git_sha",
                "cargo_lock_sha256",
            }
        ]
        + [
            "live /proc/exe SHA of isolated rust binaries (not /usr/local/bin)",
            "deployed_binary_matches_commit",
        ],
    }
    return checklist


def print_checklist(doc: dict) -> None:
    print("=== G0 freeze checklist (in-repo fields only) ===")
    for key in (
        "action",
        "peregrine_git_sha",
        "worktree_clean",
        "dirty_count",
        "acceptance_yaml_candidate",
        "acceptance_json_candidate",
        "acceptance_yaml_sha256",
        "acceptance_json_sha256",
        "cargo_lock_sha256",
        "rustc_version",
    ):
        print(f"{key}: {doc[key]}")
    print("=== G0 fields that remain NOT RUN until Swift2 ===")
    for item in doc["remaining_g0_not_run"]:
        print(f"- {item}")
    print("No field gate is GREEN. This freeze does not accept G0–G7.")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    p.add_argument("--sha", help="40-char git SHA (default: git rev-parse HEAD)")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="print the checklist without writing acceptance files",
    )
    p.add_argument(
        "--allow-dirty",
        action="store_true",
        help="allow a dirty worktree (G0 validate_manifest will still fail)",
    )
    args = p.parse_args(argv)
    checklist = freeze(
        args.repo,
        args.sha,
        write=not args.dry_run,
        allow_dirty=args.allow_dirty,
    )
    print_checklist(checklist)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
