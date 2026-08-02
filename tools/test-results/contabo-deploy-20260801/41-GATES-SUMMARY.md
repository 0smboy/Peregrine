# Contabo install gates G0–G8

| Gate | Result | Notes |
|------|--------|-------|
| G0 | **PASS** | 4/4 services active; 12/12 mounts; :8080/:8085/VIP health 200 |
| G1 | **PASS** | func-suite vip+haproxy1+haproxy2 all PASS=54 FAIL=0 |
| G2 | **PASS** | edge-diag etag/422/POST/EC via proxy+VIP; acl-meta ok |
| G3 | **PASS** | swift2 down: repl+ec degraded 20/20; restore 4/4 up |
| G4 | **PASS** | EC heal degraded+post-heal match; recon failures=0; part-871=0 |
| G5 | see finish | Prom `up{job="node"}` |
| G6 | **PASS*** | console-test PASS=36; 3 content-grep FAILs are harness false negatives (APIs returned 200; manual JSON has AUTH_test/swift1/faults) — see finish log |
| G7 | **PASS** | EC features proven by G2/G4 live EC PUT/GET/heal; object-1 ring; liberasurecode loaded |
| G8 | see finish | VIP auth ≥95% |

======== G5 retry ========
nodes_up 4 of 4
G5 PASS
======== G6 content sanity (manual) ========
whoami: {"cluster":"contabo-swift-2026","storage_url":"http://10.0.0.10:8085/v1/AUTH_test","tenant":"test","user":"tester","version":"0.1.0"}
nodes: ['swift1', 'swift2', 'swift3', 'swift4'] up 4
chaos sample: {"arena":"chaos-arcade","armed":true,"deadline_default":150,"faults":[{"ec_only":false,"id":"drop_copy","name":"Drop one copy","question":"With one replica or fragment gone, does the object still read — and who rebuilds it, how fast?"},{"ec_only":false,"id":"corrupt_copy","name":"Corrupt one copy","question":"The name and size are untouched and only the bytes are wrong. Does the cluster notice?"
======== G7 EC feature proof ========
	liberasurecode.so.1 => /lib64/liberasurecode.so.1 (0x00007effc0505000)
	liberasurecode_rs_vand.so.1 => /lib64/liberasurecode_rs_vand.so.1 (0x00007effc04d4000)
swift-proxy-server size=2438136 ec_policy_ok=see_G2_G4
swift-object-server size=1767480 ec_policy_ok=see_G2_G4
	liberasurecode.so.1 => /lib64/liberasurecode.so.1 (0x00007fd65f183000)
	liberasurecode_rs_vand.so.1 => /lib64/liberasurecode_rs_vand.so.1 (0x00007fd65f152000)
swift-object-reconstructor size=1757280 ec_policy_ok=see_G2_G4
	libnullcode.so.1 (libc6,x86-64) => /lib64/libnullcode.so.1
	libnullcode.so (libc6,x86-64) => /lib64/libnullcode.so
	liberasurecode_rs_vand.so.1 (libc6,x86-64) => /lib64/liberasurecode_rs_vand.so.1
	liberasurecode.so.1 (libc6,x86-64) => /lib64/liberasurecode.so.1
	liberasurecode.so (libc6,x86-64) => /lib64/liberasurecode.so
object-1.ring.gz present
G7_PASS_EC_proven_by_G2_G4
======== G8 VIP auth ========
VIP auth ok=100/100 (100%)
G8_PASS
