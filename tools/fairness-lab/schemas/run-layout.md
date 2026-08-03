# Result storage layout (per RUN-ID)

```text
tools/test-results/fairness-lab/<RUN-ID>/
├── manifest.yml
├── validity.json
├── workload.yml
├── client/
│   ├── summary.json
│   └── *.log
├── compatibility/
│   ├── differences.json
│   └── SUMMARY.json
├── metrics/
│   └── host-notes.txt
├── swift/
│   ├── rings/
│   ├── configs/
│   └── logs/
├── chaos/
│   ├── events.jsonl
│   └── SUMMARY.json
└── checksums.sha256
```

Validity reject criteria (predeclared): client CPU saturated; unintended NIC ceiling;
CPU steal over threshold; unexpected unmount; clock drift; residual inactive impl
listeners; ring/config checksum mismatch; error rate over workload gate; pre/post
baseline drift.
