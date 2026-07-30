#!/bin/bash
# Unit tests for the other Peregrine Rust components on the build host.
set -u
export PATH="/root/.cargo/bin:$PATH"
for r in swift-deploy-rs cosbench-rs cabt-rs; do
  echo "==================== REPO $r ===================="
  cd "/root/work/$r" || { echo "  MISSING"; continue; }
  cargo test --workspace 2>&1 | grep -E "test result:|error\[|^error:|could not compile" | tail -30
done
echo "ALLREPO-TESTS-DONE"
