# Deep R1/R2 summary

## R1 func-suite
- func-n1.log: RESULT  label=node1  PASS=54  FAIL=0
- func-n2.log: RESULT  label=node2  PASS=54  FAIL=0
- func-n3.log: RESULT  label=node3  PASS=54  FAIL=0
- func-n4.log: RESULT  label=node4  PASS=54  FAIL=0
- func-rsaio.log: RESULT  label=rust-saio  PASS=54  FAIL=0
- func-vip.log: RESULT  label=vip  PASS=54  FAIL=0

## R2
- ha.log: DONE
           4 "up":true
   ===== TAKE swift2 DOWN via console =====
       swift2 DOWN held_down 0 / 10
   ===== WORKLOAD WITH swift2 DOWN (HA: survivors must serve) =====
     repl degraded    writes ok=20/20 [     20 201 ] | reads ok=20/20 [     20 200 ]
     ec degraded      writes ok=20/20 [     20 201 ] | reads ok=20/20 [     20 200 ]
           4 "up":true
     repl recovered   writes ok=10/10 [     10 201 ] | reads ok=10/10 [     10 200 ]
- console.log: RESULT  PASS=36  FAIL=3
- recon: failures lines:
     swift1  suffix_syncs=9 reverts=7 failures=0
     swift2  suffix_syncs=24 reverts=0 failures=0
     swift3  suffix_syncs=5 reverts=3 failures=0
     swift4  suffix_syncs=7 reverts=6 failures=0
   TOTAL part-871 revert errors (5 min): 0
- func-pysaio.log: RESULT  label=py-saio  PASS=53  FAIL=1
py-saio recheck: RESULT  label=py-saio  PASS=54  FAIL=0
R1R2_ACCEPT
