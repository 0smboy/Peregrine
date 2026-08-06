#!/usr/bin/env python3
"""W0′ meta repair after A+B object purge.

Root-cause companion to wave0-ab-reclaim-orphans.py:
  - Contabo A+B kept_dirs=0 was a hash_path bug: script used
    prefix+account/... ; broker/rust-core uses prefix/account/...
  - Ghost account container rows (API HEAD 404) + zombie container object
    rows (deleted=0 with no on-disk hash dir) must be cleared for listing /
    quota integrity.
  - Optional VACUUM of touched DBs.

Safe default: dry-run. Does not mkfs.

Usage:
  python3 wave0-meta-repair.py --devices /srv/node --diagnose
  python3 wave0-meta-repair.py --devices /srv/node --ghosts-only --apply --vacuum \\
      --storage-url http://10.0.0.10:8085/v1/AUTH_test --token "$TOK"
  python3 wave0-meta-repair.py --devices /srv/node --ghosts-only --apply \\
      --preserve-file /tmp/preserve.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def load_hash_path_from_conf(conf: Path) -> tuple[str, str]:
    prefix = suffix = ""
    section = None
    if not conf.is_file():
        return prefix, suffix
    for line in conf.read_text().splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1]
            continue
        if section != "swift-hash" or "=" not in s or s.startswith("#"):
            continue
        k, v = [x.strip() for x in s.split("=", 1)]
        if k == "swift_hash_path_prefix":
            prefix = v
        elif k == "swift_hash_path_suffix":
            suffix = v
    return prefix, suffix


def hash_path(prefix: str, suffix: str, account: str, container: str, obj: str) -> str:
    # swift-core: prefix + "/" + account + "/" + container + "/" + object + suffix
    return hashlib.md5(
        f"{prefix}/{account}/{container}/{obj}{suffix}".encode()
    ).hexdigest()


def hash_path_buggy(prefix: str, suffix: str, account: str, container: str, obj: str) -> str:
    # Pre-fix wave0-ab formula (missing slash after prefix)
    return hashlib.md5(
        f"{prefix}{account}/{container}/{obj}{suffix}".encode()
    ).hexdigest()


def collect_disk_hashes(devices_root: Path) -> set[str]:
    out: set[str] = set()
    for p in devices_root.glob("d*/objects*/*/*/*"):
        if p.is_dir() and len(p.name) == 32:
            out.add(p.name)
    return out


def _register_chexor_stub(con: sqlite3.Connection) -> None:
    """Swift brokers register chexor(); stock sqlite3 cannot DELETE without it."""

    def chexor(h, name, ts):  # noqa: ARG001
        return h if h is not None else "00000000000000000000000000000000"

    con.create_function("chexor", 3, chexor)


def diagnose(devices_root: Path, conf: Path) -> dict:
    prefix, suffix = load_hash_path_from_conf(conf)
    disk = collect_disk_hashes(devices_root)
    correct_hits = buggy_hits = sampled = 0
    live_rows = 0
    sample_mismatch = []
    for db in devices_root.glob("d*/containers/*/*/*/*.db"):
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        except sqlite3.Error:
            continue
        try:
            row = con.execute(
                "select account, container from container_stat limit 1"
            ).fetchone()
            if not row:
                continue
            account, container = row
            for (name,) in con.execute(
                "select name from object where deleted = 0 limit 50"
            ):
                live_rows += 1
                if sampled >= 5000:
                    continue
                sampled += 1
                h_ok = hash_path(prefix, suffix, account, container, name)
                h_bad = hash_path_buggy(prefix, suffix, account, container, name)
                if h_ok in disk:
                    correct_hits += 1
                if h_bad in disk:
                    buggy_hits += 1
                if h_ok not in disk and len(sample_mismatch) < 5:
                    sample_mismatch.append(
                        {
                            "account": account,
                            "container": container,
                            "object": name,
                            "hash_correct": h_ok,
                            "hash_buggy": h_bad,
                        }
                    )
        finally:
            con.close()

    acc_live = 0
    for db in devices_root.glob("d*/accounts/*/*/*/*.db"):
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            acc_live += con.execute(
                "select count(*) from container where deleted = 0"
            ).fetchone()[0]
            con.close()
        except sqlite3.Error:
            pass

    return {
        "prefix": prefix,
        "suffix": suffix,
        "prefix_len": len(prefix),
        "suffix_len": len(suffix),
        "disk_hash_dirs": len(disk),
        "container_live_object_rows_seen": live_rows,
        "hash_sample_n": sampled,
        "correct_formula_disk_hits": correct_hits,
        "buggy_formula_disk_hits": buggy_hits,
        "account_live_container_rows": acc_live,
        "sample_mismatch": sample_mismatch,
        "root_cause": (
            "wave0-ab used prefix+account/... without '/' after prefix; "
            "broker/rust-core uses prefix/account/container/object+suffix"
        ),
    }


def api_request(method: str, url: str, token: str, timeout: float = 30.0):
    req = urllib.request.Request(url, method=method, headers={"X-Auth-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def classify_api_containers(storage_url: str, token: str) -> dict:
    status, _hdrs, body = api_request(
        "GET", storage_url.rstrip("/") + "?format=json", token
    )
    if status != 200:
        return {"ok": False, "list_status": status}
    try:
        containers = json.loads(body.decode())
    except json.JSONDecodeError:
        containers = [
            {"name": ln.strip()} for ln in body.decode().splitlines() if ln.strip()
        ]
    live: list[str] = []
    ghosts: list[str] = []
    other: list[tuple[str, object]] = []
    for c in containers:
        name = c["name"] if isinstance(c, dict) else str(c)
        url = f"{storage_url.rstrip('/')}/{urllib.parse.quote(name)}"
        st, _, _ = api_request("HEAD", url, token, timeout=15.0)
        if st in (200, 204):
            live.append(name)
        elif st == 404:
            ghosts.append(name)
        else:
            other.append((name, st))
    return {
        "ok": True,
        "listed": len(containers),
        "live": live,
        "ghosts": ghosts,
        "other": other[:20],
    }


def zero_zombie_object_rows(
    devices_root: Path,
    conf: Path,
    apply: bool,
    vacuum: bool,
    preserve_containers: set[str] | None,
) -> dict:
    """DELETE zombie object rows; soft-delete ghost container_info."""
    prefix, suffix = load_hash_path_from_conf(conf)
    disk = collect_disk_hashes(devices_root)
    dbs = rows_marked = vacuumed = ghost_soft = 0
    errors: list[str] = []
    for db in devices_root.glob("d*/containers/*/*/*/*.db"):
        dbs += 1
        try:
            con = sqlite3.connect(str(db))
            _register_chexor_stub(con)
        except sqlite3.Error as e:
            errors.append(f"{db}: {e}")
            continue
        try:
            row = con.execute(
                "select account, container from container_stat limit 1"
            ).fetchone()
            if not row:
                con.close()
                continue
            account, container = row
            is_ghost = (
                preserve_containers is not None and container not in preserve_containers
            )
            live = con.execute("select name from object where deleted = 0").fetchall()
            to_del = []
            for (name,) in live:
                if is_ghost:
                    to_del.append(name)
                    continue
                h = hash_path(prefix, suffix, account, container, name)
                if h not in disk:
                    to_del.append(name)
            rows_marked += len(to_del)
            if apply and (to_del or is_ghost):
                if to_del:
                    con.executemany(
                        "delete from object where name = ? and deleted = 0",
                        [(n,) for n in to_del],
                    )
                remaining = con.execute(
                    "select count(*) from object where deleted = 0"
                ).fetchone()[0]
                bytes_used = 0
                if remaining:
                    try:
                        bytes_used = con.execute(
                            "select coalesce(sum(size),0) from object where deleted = 0"
                        ).fetchone()[0]
                    except sqlite3.Error:
                        bytes_used = 0
                now_ts = f"{time.time():.5f}"
                try:
                    con.execute(
                        "update policy_stat set object_count = ?, bytes_used = ?",
                        (remaining, bytes_used),
                    )
                except sqlite3.Error:
                    pass
                try:
                    if is_ghost or remaining == 0:
                        con.execute(
                            "update container_info set reported_object_count = ?, "
                            "reported_bytes_used = ?, delete_timestamp = ?",
                            (remaining, bytes_used, now_ts),
                        )
                    else:
                        con.execute(
                            "update container_info set reported_object_count = ?, "
                            "reported_bytes_used = ?",
                            (remaining, bytes_used),
                        )
                except sqlite3.Error:
                    pass
                if is_ghost:
                    ghost_soft += 1
                con.commit()
                if vacuum:
                    con.execute("vacuum")
                    vacuumed += 1
            con.close()
        except sqlite3.Error as e:
            errors.append(f"{db}: {e}")
            try:
                con.close()
            except Exception:
                pass
    return {
        "container_dbs_seen": dbs,
        "disk_hash_dirs": len(disk),
        "live_rows_marked": rows_marked,
        "ghost_containers_soft_deleted": ghost_soft,
        "vacuumed": vacuumed,
        "errors": errors[:20],
        "mode": "APPLY" if apply else "DRY-RUN",
    }


def zero_account_container_rows(
    devices_root: Path,
    apply: bool,
    vacuum: bool,
    preserve: set[str] | None = None,
) -> dict:
    dbs = rows_marked = vacuumed = preserved = 0
    errors: list[str] = []
    for db in devices_root.glob("d*/accounts/*/*/*/*.db"):
        dbs += 1
        try:
            con = sqlite3.connect(str(db))
            _register_chexor_stub(con)
        except sqlite3.Error as e:
            errors.append(f"{db}: {e}")
            continue
        try:
            rows = con.execute(
                "select name from container where deleted = 0"
            ).fetchall()
            if not rows:
                con.close()
                continue
            to_del = []
            for (name,) in rows:
                if preserve is not None and name in preserve:
                    preserved += 1
                    continue
                to_del.append(name)
            rows_marked += len(to_del)
            if apply and to_del:
                con.executemany(
                    "delete from container where name = ? and deleted = 0",
                    [(n,) for n in to_del],
                )
                live = con.execute(
                    "select count(*) from container where deleted = 0"
                ).fetchone()[0]
                try:
                    if live == 0:
                        con.execute(
                            "update account_stat set container_count = 0, "
                            "object_count = 0, bytes_used = 0"
                        )
                    else:
                        con.execute(
                            "update account_stat set container_count = ?", (live,)
                        )
                except sqlite3.Error:
                    pass
                try:
                    if live == 0:
                        con.execute(
                            "update policy_stat set container_count = 0, "
                            "object_count = 0, bytes_used = 0"
                        )
                    else:
                        con.execute(
                            "update policy_stat set container_count = ?", (live,)
                        )
                except sqlite3.Error:
                    pass
                con.commit()
                if vacuum:
                    con.execute("vacuum")
                    vacuumed += 1
            con.close()
        except sqlite3.Error as e:
            errors.append(f"{db}: {e}")
            try:
                con.close()
            except Exception:
                pass
    return {
        "account_dbs_seen": dbs,
        "live_rows_marked": rows_marked,
        "preserved_rows": preserved,
        "vacuumed": vacuumed,
        "errors": errors[:20],
        "mode": "APPLY" if apply else "DRY-RUN",
        "preserve_count": len(preserve) if preserve is not None else None,
    }


def zero_container_object_rows(devices_root: Path, apply: bool, vacuum: bool) -> dict:
    """Nuclear: delete ALL live object rows on this node."""
    return zero_zombie_object_rows(
        devices_root, Path("/etc/swift/swift.conf"), apply, vacuum, set()
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--devices", type=Path, default=Path("/srv/node"))
    ap.add_argument("--conf", type=Path, default=Path("/etc/swift/swift.conf"))
    ap.add_argument("--diagnose", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--vacuum", action="store_true")
    ap.add_argument("--via-api", action="store_true")
    ap.add_argument("--zero-dbs", action="store_true")
    ap.add_argument("--ghosts-only", action="store_true")
    ap.add_argument("--storage-url", default="")
    ap.add_argument("--token", default=os.environ.get("OS_AUTH_TOKEN", ""))
    ap.add_argument("--preserve-file", type=Path, default=None)
    ap.add_argument("--json-out", type=Path, default=None)
    args = ap.parse_args()

    report: dict = {"ts": time.time(), "host": os.uname().nodename}
    actions = args.via_api or args.zero_dbs or args.ghosts_only
    if args.diagnose or not actions:
        report["diagnose"] = diagnose(args.devices, args.conf)
        print(json.dumps(report["diagnose"], indent=2), flush=True)
        if not actions:
            if args.json_out:
                args.json_out.write_text(json.dumps(report, indent=2))
            return 0

    if args.ghosts_only:
        if args.preserve_file and args.preserve_file.is_file():
            preserve = set(json.loads(args.preserve_file.read_text()))
            report["preserve_source"] = str(args.preserve_file)
        elif args.storage_url and args.token:
            clf = classify_api_containers(args.storage_url, args.token)
            report["classify"] = {
                "ok": clf.get("ok"),
                "listed": clf.get("listed"),
                "live": clf.get("live"),
                "ghost_count": len(clf.get("ghosts") or []),
                "other": clf.get("other"),
            }
            print(json.dumps(report["classify"], indent=2), flush=True)
            if not clf.get("ok"):
                return 2
            preserve = set(clf["live"])
        else:
            print(
                "ERROR: --ghosts-only needs --preserve-file or --storage-url + --token",
                file=sys.stderr,
            )
            return 2
        report["zombie_zero"] = zero_zombie_object_rows(
            args.devices, args.conf, args.apply, args.vacuum, preserve
        )
        report["account_zero"] = zero_account_container_rows(
            args.devices, args.apply, args.vacuum, preserve
        )
        print(
            json.dumps(
                {
                    "preserve": sorted(preserve),
                    "zombie_zero": report["zombie_zero"],
                    "account_zero": report["account_zero"],
                },
                indent=2,
            ),
            flush=True,
        )

    if args.zero_dbs:
        report["container_zero"] = zero_container_object_rows(
            args.devices, args.apply, args.vacuum
        )
        report["account_zero"] = zero_account_container_rows(
            args.devices, args.apply, args.vacuum, None
        )
        print(
            json.dumps(
                {
                    "container_zero": report["container_zero"],
                    "account_zero": report["account_zero"],
                },
                indent=2,
            ),
            flush=True,
        )

    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
