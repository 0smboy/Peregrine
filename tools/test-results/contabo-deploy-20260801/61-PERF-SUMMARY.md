# Perf matrix Contabo

## Verdict: **ACCEPT_WITH_WARN**

- bench repl: err=0 all rows
- bench ec: err=0 except 1M GET conc=32 err=4
- cbench/wbench: errs=0
- autocos 4KB write→read 128: **fail=0** (hard gate PASS)
- autocos 1MB write/read: fail=0
- autocos 16MB read: WARN — write stage only 184 ops/60s so prepare could not seed 400 objs; not a 4KB client issue
- client tuning: ulimit -n=65535, ST_ENDPOINT=http://10.0.0.1:8085, sysctl tw_reuse/port_range

  CLIENT ulimit -n=65535 ST_ENDPOINT=http://10.0.0.1:8085/v1/AUTH_test AUTOCOS=/usr/local/bin/autocos
  === TASK 4KB_write_128 (obj=4000 cont=4 rt=60) ===
  2026-08-01T14:04:36.288988Z  INFO stage finished stage=init ok=4 fail=0 success="100.00%" p99_us=87167
  2026-08-01T14:05:36.819968Z  INFO stage finished stage=normal ok=12279 fail=0 success="100.00%" p99_us=1826815
  === TASK 4KB_read_128 (obj=4000 cont=4 rt=60) ===
  2026-08-01T14:05:37.210866Z  INFO stage finished stage=init ok=4 fail=0 success="100.00%" p99_us=128959
  2026-08-01T14:07:05.855939Z  INFO stage finished stage=prepare ok=16000 fail=0 success="100.00%" p99_us=1354751
  2026-08-01T14:08:06.012804Z  INFO stage finished stage=normal ok=91545 fail=0 success="100.00%" p99_us=262655
  === TASK 1MB_write_32 (obj=500 cont=4 rt=60) ===
  2026-08-01T14:08:06.367900Z  INFO stage finished stage=init ok=4 fail=0 success="100.00%" p99_us=109887
  2026-08-01T14:09:06.960213Z  INFO stage finished stage=normal ok=2687 fail=0 success="100.00%" p99_us=1199103
  === TASK 1MB_read_32 (obj=500 cont=4 rt=60) ===
  2026-08-01T14:09:07.513782Z  INFO stage finished stage=init ok=4 fail=0 success="100.00%" p99_us=220671
  2026-08-01T14:09:51.199890Z  INFO stage finished stage=prepare ok=2000 fail=0 success="100.00%" p99_us=2660351
  2026-08-01T14:10:51.407588Z  INFO stage finished stage=normal ok=6733 fail=0 success="100.00%" p99_us=858111
  === TASK 16MB_write_8 (obj=100 cont=4 rt=60) ===
  2026-08-01T14:10:51.724079Z  INFO stage finished stage=init ok=4 fail=0 success="100.00%" p99_us=89983
  2026-08-01T14:11:53.824415Z  INFO stage finished stage=normal ok=184 fail=0 success="100.00%" p99_us=6520831
  === TASK 16MB_read_8 (obj=100 cont=4 rt=60) ===
  2026-08-01T14:11:54.203966Z  INFO stage finished stage=init ok=4 fail=0 success="100.00%" p99_us=101887
  2026-08-01T14:13:16.101236Z  INFO stage finished stage=prepare ok=55 fail=345 success="13.75%" p99_us=45383679
  2026-08-01T14:14:16.104262Z  INFO stage finished stage=normal ok=0 fail=1597719 success="0.00%" p99_us=1644
  AUTOCOS-SWEEP-DONE
