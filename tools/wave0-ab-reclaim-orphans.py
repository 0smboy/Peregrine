#!/usr/bin/env python3
"""Wave 0 follow-up A+B: force tombstone reclaim + orphan .data purge.

A: remove *.ts whose embedded timestamp is older than reclaim_age seconds
   (default 600), then prune empty hash dirs.
B: build set of object hashes still referenced by non-deleted container DB
   rows; delete on-disk object hash dirs not in that set (orphans).

   Contabo lab note (2026-08-05): early A+B runs reported kept_dirs=0 with
   ~650k referenced hashes because this script omitted the '/' after
   swift_hash_path_prefix (broker uses prefix/account/container/obj+suffix).
   Fixed 2026-08-05 — see w0-meta-repair evidence. Ghost account/container
   DB rows still need a separate meta-repair pass after object purge.

Usage:
  dry-run:  python3 wave0-ab-reclaim-orphans.py /srv/node --reclaim-age 600
  apply:    python3 wave0-ab-reclaim-orphans.py /srv/node --reclaim-age 600 --apply

Safe defaults: dry-run. Does not mkfs or touch account/container DB files.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sqlite3
import sys
import time
from pathlib import Path


def swift_hash(account: str, container: str, obj: str) -> str:
    # OpenStack Swift / Peregrine rust-core: MD5 of
    #   <prefix>/<account>/<container>/<object><suffix>
    # (slash AFTER prefix is mandatory — missing it made Contabo A+B
    # kept_dirs=0 despite ~650k referenced container rows).
    prefix = os.environ.get("SWIFT_HASH_PATH_PREFIX", "")
    suffix = os.environ.get("SWIFT_HASH_PATH_SUFFIX", "")
    path = f"{prefix}/{account}/{container}/{obj}{suffix}"
    return hashlib.md5(path.encode()).hexdigest()


def load_hash_path_from_conf() -> tuple[str, str]:
    prefix = suffix = ""
    conf = Path("/etc/swift/swift.conf")
    if not conf.is_file():
        return prefix, suffix
    section = None
    for line in conf.read_text().splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1]
            continue
        if section != "swift-hash":
            continue
        if "=" not in s or s.startswith("#"):
            continue
        k, v = [x.strip() for x in s.split("=", 1)]
        if k == "swift_hash_path_prefix":
            prefix = v
        elif k == "swift_hash_path_suffix":
            suffix = v
    return prefix, suffix


def parse_ts_from_filename(name: str) -> float | None:
    # e.g. 1735689600.12345.ts
    if not name.endswith(".ts"):
        return None
    base = name[: -len(".ts")]
    try:
        return float(base.split("_")[0])
    except ValueError:
        return None


def object_datadirs(devices_root: Path) -> list[Path]:
    out: list[Path] = []
    for dev in sorted(devices_root.iterdir()):
        if not dev.is_dir() or not dev.name.startswith("d"):
            continue
        for child in sorted(dev.iterdir()):
            if child.is_dir() and (
                child.name == "objects" or child.name.startswith("objects-")
            ):
                out.append(child)
    return out


def collect_referenced_hashes(devices_root: Path, prefix: str, suffix: str) -> set[str]:
    """Hashes for non-deleted objects in container DBs.

    Container broker stores name only; hash needs account/container.
    We derive account/container from DB path when possible; if metadata
    tables exist use them. Fallback: hash name alone is WRONG — use
    broker's stored hash if present, else skip strict match and rely on
    name listing via path components under accounts.

    Contabo layout: .../containers/<part>/<suff>/<hash>/<hash>.db
    Account/container names live in DB info table.
    """
    refs: set[str] = set()
    for dev in devices_root.iterdir():
        if not dev.is_dir():
            continue
        for root, _dirs, files in os.walk(dev / "containers"):
            for f in files:
                if not f.endswith(".db"):
                    continue
                p = Path(root) / f
                try:
                    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
                except sqlite3.Error:
                    continue
                try:
                    # account/container from container_stat / container_info
                    account = container = None
                    for table in ("container_stat", "container_info"):
                        try:
                            row = con.execute(
                                f"select account, container from {table} limit 1"
                            ).fetchone()
                            if row:
                                account, container = row[0], row[1]
                                break
                        except sqlite3.Error:
                            continue
                    if not account or not container:
                        continue
                    try:
                        rows = con.execute(
                            "select name from object where deleted = 0"
                        ).fetchall()
                    except sqlite3.Error:
                        continue
                    for (name,) in rows:
                        # Must match swift-core HashPathConfig::hash_path_raw
                        path = f"{prefix}/{account}/{container}/{name}{suffix}"
                        refs.add(hashlib.md5(path.encode()).hexdigest())
                finally:
                    con.close()
    return refs


def iter_hash_dirs(datadir: Path):
    # objects/<partition>/<suffix>/<hash>/
    if not datadir.is_dir():
        return
    for part in datadir.iterdir():
        if not part.is_dir():
            continue
        for suff in part.iterdir():
            if not suff.is_dir():
                continue
            for hdir in suff.iterdir():
                if hdir.is_dir() and len(hdir.name) == 32:
                    yield hdir


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("devices_root", type=Path)
    ap.add_argument("--reclaim-age", type=float, default=600.0)
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--skip-a", action="store_true", help="skip tombstone reclaim")
    ap.add_argument("--skip-b", action="store_true", help="skip orphan purge")
    args = ap.parse_args()
    root: Path = args.devices_root
    now = time.time()
    apply = args.apply
    mode = "APPLY" if apply else "DRY-RUN"
    print(f"mode={mode} root={root} reclaim_age={args.reclaim_age}", flush=True)

    prefix, suffix = load_hash_path_from_conf()
    os.environ["SWIFT_HASH_PATH_PREFIX"] = prefix
    os.environ["SWIFT_HASH_PATH_SUFFIX"] = suffix
    print(f"hash_prefix_len={len(prefix)} hash_suffix_len={len(suffix)}", flush=True)

    ts_removed = ts_bytes = 0
    orphan_dirs = orphan_files = orphan_bytes = 0
    kept_dirs = 0

    if not args.skip_a:
        print("=== A: tombstone reclaim walk ===", flush=True)
        for datadir in object_datadirs(root):
            for hdir in iter_hash_dirs(datadir):
                try:
                    names = list(os.listdir(hdir))
                except OSError:
                    continue
                for name in names:
                    if not name.endswith(".ts"):
                        continue
                    ts = parse_ts_from_filename(name)
                    if ts is None or (now - ts) <= args.reclaim_age:
                        continue
                    path = hdir / name
                    try:
                        sz = path.stat().st_size
                    except OSError:
                        continue
                    ts_removed += 1
                    ts_bytes += sz
                    if apply:
                        try:
                            path.unlink()
                        except OSError as e:
                            print(f"warn unlink {path}: {e}", flush=True)
                # prune empty hash dir
                if apply:
                    try:
                        if not any(hdir.iterdir()):
                            hdir.rmdir()
                    except OSError:
                        pass
        print(f"A: ts_reclaimable={ts_removed} bytes={ts_bytes}", flush=True)

    if not args.skip_b:
        print("=== B: orphan hash-dir purge ===", flush=True)
        refs = collect_referenced_hashes(root, prefix, suffix)
        print(f"B: referenced_hashes={len(refs)}", flush=True)
        for datadir in object_datadirs(root):
            for hdir in iter_hash_dirs(datadir):
                h = hdir.name
                if h in refs:
                    kept_dirs += 1
                    continue
                # orphan: remove entire hash dir
                try:
                    for dirpath, _dirnames, filenames in os.walk(hdir):
                        for fn in filenames:
                            fp = Path(dirpath) / fn
                            try:
                                orphan_bytes += fp.stat().st_size
                            except OSError:
                                pass
                            orphan_files += 1
                            if apply:
                                try:
                                    fp.unlink()
                                except OSError:
                                    pass
                    if apply:
                        # bottom-up remove dirs
                        for dirpath, dirnames, _filenames in os.walk(hdir, topdown=False):
                            for dn in dirnames:
                                try:
                                    (Path(dirpath) / dn).rmdir()
                                except OSError:
                                    pass
                            try:
                                Path(dirpath).rmdir()
                            except OSError:
                                pass
                    orphan_dirs += 1
                except OSError as e:
                    print(f"warn orphan {hdir}: {e}", flush=True)
        print(
            f"B: orphan_dirs={orphan_dirs} orphan_files={orphan_files} "
            f"orphan_bytes={orphan_bytes} kept_dirs={kept_dirs}",
            flush=True,
        )

    print(
        f"DONE mode={mode} A_ts={ts_removed} A_bytes={ts_bytes} "
        f"B_dirs={orphan_dirs} B_files={orphan_files} B_bytes={orphan_bytes}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
