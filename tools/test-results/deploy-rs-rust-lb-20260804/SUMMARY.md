# deploy-rs rust LB gate — 2026-08-04

**Verdict: PASS**

| Gate | Result |
|------|--------|
| `swift-deploy apply` stack=rust keepalived+roundrobin | converged (4× proxy/object/haproxy/keepalived active) |
| Disk wipe | not requested; plan risks=`HostReconfigure` only |
| VIP auth | PASS |
| Cross-proxy same token | PASS (4/4) |
| VIP PUT/GET | PASS |
| ≥40 req four backends | PASS (14/14/13/13) |
| Failover VIP move + IO | PASS (1→2, health/auth 200) |

Workspace: `/var/lib/swift-deploy/projects/contabo-rust-lb` on Contabo swift1.  
Hashes preserved: `contabo-f5183cf3f3eaf886` / `4afcbe289acfdfa1`.
