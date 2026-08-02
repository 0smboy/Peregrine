# Lab 12 Deep Test — Canonical Criteria (locked)

Shadow MUST be real dual: cluster Rust HA (:8085) vs Python SAIO (:8090). Wrong peer/mock/single-mode → REJECT Shadow.
Breaking diffs = 0, zero exemption by default.
Profile / Open-Expired capability missing → REJECT that tool (not WARN).
Chaos: ALL 4 faults (drop_copy, corrupt_copy, drop_durable, stale_timestamp).

Order: E0 → Shadow → Readonly → Forensics → Warehouse → Chaos → Expired → Profile → Nodes LAST → Archive.
