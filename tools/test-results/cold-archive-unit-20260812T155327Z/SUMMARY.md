# cold archive-on-transition unit (swift3)

VERDICT: GREEN
Remote: `/root/work/peregrine-artifacts/cold-archive-unit-20260812T155327Z`
Tree: `/root/work/peregrine-cold-physical-77dd9f4/swift-rust` (rsync from Mac tip)

## Results
- cold_tier: 8 passed
- get_due_cold_transition: 2 passed
- put_immediate_cold: 1 passed
- Total relevant: 11/11

## Claim boundary
Lab LocalDir/Memory cold bytes only. Not tape/Glacier. Not fleet-deployed.
Archive hooks: GET/HEAD auth path + PUT immediate due; anonymous/versioned paths not wired.
