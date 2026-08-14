#!/usr/bin/env python3
"""Offline exit-contract selftest for contabo_ext_s3_matrix.py."""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile


HERE = pathlib.Path(__file__).resolve().parent
TARGET = HERE / "contabo_ext_s3_matrix.py"
SPEC = importlib.util.spec_from_file_location("contabo_ext_s3_matrix", TARGET)
assert SPEC is not None and SPEC.loader is not None
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)


CLEANUP_OPS = {
    ("tempauth-sigv4", "MultiDelete"),
    ("tempauth-sigv4", "AbortMultipartUpload"),
    ("tempauth-sigv4", "DeleteObject"),
    ("tempauth-sigv4", "DeleteBucket"),
    ("ec2-sigv4", "DeleteObject"),
    ("ec2-sigv4", "DeleteBucket"),
}


def complete_rows():
    return [
        {
            "lane": lane,
            "op": op,
            "http": 200,
            "ok": True,
            "note": "selftest",
            "body_snip": "",
            "cleanup": (lane, op) in CLEANUP_OPS,
        }
        for lane, op in sorted(matrix.REQUIRED_OPS)
    ]


def assert_classification() -> None:
    rows = complete_rows()
    assert matrix.classify_ops(rows) == (
        "OPS_ONLY",
        matrix.EXIT_OPS_ONLY,
        len(matrix.REQUIRED_OPS),
        0,
        0,
    )
    assert matrix.classify_ops([])[0:2] == ("PARTIAL", matrix.EXIT_PARTIAL)

    missing = rows[:-1]
    assert matrix.classify_ops(missing)[0:2] == ("PARTIAL", matrix.EXIT_PARTIAL)

    noncritical = complete_rows()
    row = next(r for r in noncritical if r["op"] == "GetObjectAcl")
    row["ok"] = False
    assert matrix.classify_ops(noncritical)[0:2] == ("PARTIAL", matrix.EXIT_PARTIAL)

    critical = complete_rows()
    row = next(r for r in critical if r["op"] == "GetObject")
    row["ok"] = False
    assert matrix.classify_ops(critical)[0:2] == ("FAIL", matrix.EXIT_FAIL)

    cleanup = complete_rows()
    row = next(r for r in cleanup if r["op"] == "AbortMultipartUpload")
    row["ok"] = False
    verdict, rc, _, _, cleanup_failed = matrix.classify_ops(cleanup)
    assert (verdict, rc, cleanup_failed) == ("FAIL", matrix.EXIT_FAIL, 1)

    # No bounded one-origin result, complete or otherwise, may return zero.
    for candidate in (rows, [], missing, noncritical, critical, cleanup):
        assert matrix.classify_ops(candidate)[1] != matrix.EXIT_PARITY_GREEN


def fake_lane(lane: str) -> None:
    for required_lane, op in sorted(matrix.REQUIRED_OPS):
        if required_lane != lane:
            continue
        matrix.record(
            lane,
            op,
            200,
            True,
            note="offline selftest",
            cleanup=(lane, op) in CLEANUP_OPS,
        )


def assert_main_contract() -> None:
    old_env = os.environ.copy()
    old_values = {
        "EVID_DIR": matrix.EVID_DIR,
        "VIP": matrix.VIP,
        "HOST": matrix.HOST,
        "REGION": matrix.REGION,
        "TIP_SHA": matrix.TIP_SHA,
        "run_tempauth": matrix.run_tempauth,
        "run_ec2": matrix.run_ec2,
    }
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            creds = tmp_path / "ec2.json"
            creds.write_text(
                json.dumps({"access": "selftest-access", "secret": "selftest-secret"}),
                encoding="utf-8",
            )
            os.environ.update(
                {
                    "ST_USER": "test:tester",
                    "ST_KEY": "selftest-key",
                    "EC2_CREDS_JSON": str(creds),
                }
            )
            matrix.VIP = "https://rust.example.test:8085"
            matrix.HOST = "rust.example.test:8085"
            matrix.REGION = "us-east-1"
            matrix.TIP_SHA = "0123456789abcdef"
            matrix.EVID_DIR = str(tmp_path / "complete")
            matrix.run_tempauth = lambda _access, _secret: fake_lane("tempauth-sigv4")
            matrix.run_ec2 = lambda _access, _secret: fake_lane("ec2-sigv4")
            rc = matrix.main()
            assert rc == matrix.EXIT_OPS_ONLY
            report = json.loads(
                (pathlib.Path(matrix.EVID_DIR) / "30-matrix-results.json").read_text(
                    encoding="utf-8"
                )
            )
            assert report["verdict"] == "OPS_ONLY"
            assert report["claim"] == "OPS_ONLY"
            assert report["parity_oracle"] == "NOT_RUN"
            assert report["parity_green"] is False
            assert report["exit_code"] == matrix.EXIT_OPS_ONLY
            assert report["cleanup_failed"] == 0
            assert report["missing_ops"] == []

            def failing_ec2(_access, _secret):
                fake_lane("ec2-sigv4")
                row = next(
                    r
                    for r in matrix.results
                    if r["lane"] == "ec2-sigv4" and r["op"] == "DeleteBucket"
                )
                row["ok"] = False

            matrix.EVID_DIR = str(tmp_path / "cleanup-failure")
            matrix.run_ec2 = failing_ec2
            rc = matrix.main()
            assert rc == matrix.EXIT_FAIL
            report = json.loads(
                (pathlib.Path(matrix.EVID_DIR) / "30-matrix-results.json").read_text(
                    encoding="utf-8"
                )
            )
            assert report["verdict"] == "FAIL"
            assert report["claim"] == "OPS_ONLY"
            assert report["cleanup_failed"] == 1
            assert report["exit_code"] == matrix.EXIT_FAIL

            matrix.EVID_DIR = str(tmp_path / "missing-ec2")
            matrix.run_ec2 = lambda _access, _secret: fake_lane("ec2-sigv4")
            os.environ["EC2_CREDS_JSON"] = str(tmp_path / "does-not-exist.json")
            rc = matrix.main()
            assert rc == matrix.EXIT_CONFIG_ERROR
            report = json.loads(
                (pathlib.Path(matrix.EVID_DIR) / "30-matrix-results.json").read_text(
                    encoding="utf-8"
                )
            )
            assert report["verdict"] == "CONFIG_ERROR"
            assert report["claim"] == "OPS_ONLY"
            assert report["exit_code"] == matrix.EXIT_CONFIG_ERROR
    finally:
        os.environ.clear()
        os.environ.update(old_env)
        matrix.EVID_DIR = old_values["EVID_DIR"]
        matrix.VIP = old_values["VIP"]
        matrix.HOST = old_values["HOST"]
        matrix.REGION = old_values["REGION"]
        matrix.TIP_SHA = old_values["TIP_SHA"]
        matrix.run_tempauth = old_values["run_tempauth"]
        matrix.run_ec2 = old_values["run_ec2"]


assert_classification()
assert_main_contract()
print("contabo_ext_s3_matrix exit-contract selftest: PASS")
