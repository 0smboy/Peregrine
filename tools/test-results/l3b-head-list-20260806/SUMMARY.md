# Sharded HEAD Object-Count == list length

## Change
- Container HEAD for sharded roots reuses `maybe_sharded_container_listing`
  then returns 204 with empty body and the listing's Object-Count/Bytes-Used.
- Fallback `patch_sharded_head_counts` remains when fan-out does not apply.
- Sharder shrink: multi-device local search for donor DB on same host.

## Lab
- shrinklab: HEAD 20 / list 20
- l3bclean: HEAD 170 / list 170

## Residual
- Multi-primary shrink still needs container-replicator to place root
  range table on the node holding the donor (operational; replicator active).
