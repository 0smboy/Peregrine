# Wave2 code landed check

| Surface | Status |
|---------|--------|
| Peregrine `build_rings.sh.j2` `object_port_per_device` | present (repo) |
| Peregrine `servers_per_port.rs` + object-server main | present (prior wave2 pack unit 9/9) |
| Contabo `/usr/local/bin/swift-object-server` | contains `servers_per_port` strings; sha256 `69a7e5eb…` |
| Contabo live `/etc/swift/build_rings.sh` | **STALE** — d1-only, all r1, no per-device ports |
| Contabo `/opt/swift-deploy/.../build_rings.sh.j2` | sha differs from Peregrine working tree (`08-CODE-PARITY.txt`) |

Conclusion: runtime binary can do spp; **deployed ring plan on Contabo is not yet wave2**. Live apply = runbook.
