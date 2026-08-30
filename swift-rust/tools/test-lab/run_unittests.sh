#!/usr/bin/env bash
# Run the shipped G0/G2/G3/G7 pure-function tests. No SSH.
set -euo pipefail
cd "$(dirname "$0")"
python3 -m unittest test_pipeline test_provenance test_preflight test_g3_counters test_g7_runner -v
