#!/bin/bash
# Full workspace regression: non-EC workspace + EC-featured crates. Prints only
# failures plus a pass/fail tally.
set -u
cd /root/work/swift-rust || exit 2
export PATH="/root/.cargo/bin:$PATH"
ECF=swift-proxy-server/ec,swift-object-server/ec

echo "### workspace no-EC"
cargo test --release --workspace --exclude swift-ec 2>&1 | tee /tmp/r1.txt | grep -E "FAILED|error\[|panicked" | head
echo "### EC crates"
cargo test --release -p swift-ec -p swift-object-server -p swift-proxy-server --features "$ECF" 2>&1 | tee /tmp/r2.txt | grep -E "FAILED|error\[|panicked" | head

pass=$(grep -hoE "test result: ok\. [0-9]+ passed" /tmp/r1.txt /tmp/r2.txt | awk '{s+=$4} END{print s}')
fail=$(grep -hoE "[0-9]+ failed" /tmp/r1.txt /tmp/r2.txt | awk '{s+=$1} END{print s}')
echo "TALLY passed=$pass failed=$fail"
