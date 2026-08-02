# Lab12 deep Contabo SUMMARY

- **Verdict:** ACCEPT
- Shadow: mode=dual peer=Python:8090 **breaking=0** cases=31 run=`r1785596893-bc2f9c`
- Chaos ×4: drop_copy={'run': '9b99d7e725d5', 'phase': 'done'}; corrupt_copy={'run': 'f9da521c572e', 'phase': 'done'}; drop_durable={'run': '850d5ccce752', 'phase': 'done'} (policy=1 EC); stale_timestamp={'run': 'b31a1a69211a', 'phase': 'done'}; recover after each; services 4/4 up
- Nodes HA last: degraded 20/20 repl+EC; recover 4/4; HA-TEST-DONE=True
- Func oracles: cluster / py-saio / rust-saio FAIL=0
- WARN (non-blocking): capsule/tombstone HTTP 400; warehouse 502

- OUT: `/root/contabo-deploy-20260801T125749Z/lab12-deep-final`
