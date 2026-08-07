# python_only_extras (docs mapping)

| Python role | Playbook | Rust note |
|-------------|----------|-----------|
| `docker` | `install_cosbench.yml` | ABSENT |
| `cosbench` | `install_cosbench.yml` | Use monorepo `cosbench-rs` / `autocos` for fairness labs |
| `proxyfs` | `swift.yml` when `install_proxyfs` | ABSENT; not Contabo rust claim |
| `new_ring` | `add_new_ring.yml` | PARTIAL via `swift_policies` + ring stamp/expand |
| `example_structure` | scaffold | N/A |

Matrix: [ANSIBLE-V3-SURFACE.md](../../../../docs/fairness-lab/ANSIBLE-V3-SURFACE.md).
