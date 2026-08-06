#!/usr/bin/env bash
set -euo pipefail
RB=/usr/local/bin/swift-ring-builder
rm -f object.ring.gz object.ring.gz.builder.json
"$RB" object.ring.gz create 14 3 1
# swift1 r1z1
"$RB" object.ring.gz add r1z1-10.0.4.1:6200R10.0.8.1:6200/d1 100
"$RB" object.ring.gz add r1z1-10.0.4.1:6201R10.0.8.1:6201/d2 100
"$RB" object.ring.gz add r1z1-10.0.4.1:6202R10.0.8.1:6202/d3 100
# swift2 r1z2
"$RB" object.ring.gz add r1z2-10.0.4.2:6200R10.0.8.2:6200/d1 100
"$RB" object.ring.gz add r1z2-10.0.4.2:6201R10.0.8.2:6201/d2 100
"$RB" object.ring.gz add r1z2-10.0.4.2:6202R10.0.8.2:6202/d3 100
# swift3 r2z1
"$RB" object.ring.gz add r2z1-10.0.4.3:6200R10.0.8.3:6200/d1 100
"$RB" object.ring.gz add r2z1-10.0.4.3:6201R10.0.8.3:6201/d2 100
"$RB" object.ring.gz add r2z1-10.0.4.3:6202R10.0.8.3:6202/d3 100
# swift4 r2z2
"$RB" object.ring.gz add r2z2-10.0.4.4:6200R10.0.8.4:6200/d1 100
"$RB" object.ring.gz add r2z2-10.0.4.4:6201R10.0.8.4:6201/d2 100
"$RB" object.ring.gz add r2z2-10.0.4.4:6202R10.0.8.4:6202/d3 100
"$RB" object.ring.gz rebalance
