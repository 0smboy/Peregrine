# Role coverage 26/26 checklist

**Playbook:** `bundle-rust/swift-full-v3.yml`
**ansible.cfg:** `roles_path = roles:../bundle/roles`
**Score: 26/26 COVERED**

| # | Python role | Status | Twin coverage | Resolution |
|--:|---------------|:------:|---------------|------------|
| 1 | `check` | **COVERED** | python-include `check` | symlink → ../../bundle/roles/check |
| 2 | `chrony` | **COVERED** | python-include `chrony` (`enable_python_platform`) | symlink → ../../bundle/roles/chrony |
| 3 | `common` | **COVERED** | rust `rust_common` | roles_path only (../bundle/roles) |
| 4 | `cosbench` | **COVERED** | python-include `cosbench` (`enable_python_extras`) | symlink → ../../bundle/roles/cosbench |
| 5 | `docker` | **COVERED** | python-include `docker` (`enable_python_extras`) | symlink → ../../bundle/roles/docker |
| 6 | `example_structure` | **COVERED** | scaffold no-op (`enable_example_structure`) | local role dir |
| 7 | `finalize_installation` | **COVERED** | rust `rust_systemd` + `rust_verify` | roles_path only (../bundle/roles) |
| 8 | `format_disks` | **COVERED** | python-include `format_disks` (`allow_disk_format`) | symlink → ../../bundle/roles/format_disks |
| 9 | `format_new_disks` | **COVERED** | python-include `format_new_disks` (`allow_disk_format`) | symlink → ../../bundle/roles/format_new_disks |
| 10 | `haproxy_servers` | **COVERED** | rust `rust_haproxy` | roles_path only (../bundle/roles) |
| 11 | `keepalived_servers` | **COVERED** | rust `rust_keepalived` | roles_path only (../bundle/roles) |
| 12 | `keystone_install` | **COVERED** | python-include (`enable_identity_provision` / auth_method) | symlink → ../../bundle/roles/keystone_install |
| 13 | `keystones` | **COVERED** | python-include + rust_identity_bridge 对接 | symlink → ../../bundle/roles/keystones |
| 14 | `mariadb_servers` | **COVERED** | python-include (`enable_identity_provision` / use_local_mariadbs) | symlink → ../../bundle/roles/mariadb_servers |
| 15 | `new_ring` | **COVERED** | python-include (`enable_new_ring` / `enable_python_extras`) | symlink → ../../bundle/roles/new_ring |
| 16 | `performance_tuning` | **COVERED** | python-include (`enable_python_platform`) | symlink → ../../bundle/roles/performance_tuning |
| 17 | `proxyfs` | **COVERED** | python-include (`install_proxyfs` / `enable_python_extras`) | symlink → ../../bundle/roles/proxyfs |
| 18 | `ring_builder` | **COVERED** | rust `rust_rings` | roles_path only (../bundle/roles) |
| 19 | `ring_utils` | **COVERED** | rust `rust_rings` | roles_path only (../bundle/roles) |
| 20 | `security` | **COVERED** | python-include (`enable_python_platform`) | symlink → ../../bundle/roles/security |
| 21 | `storage_nodes_common` | **COVERED** | rust `rust_common`+`rust_disks`+`rust_replication_key` | roles_path only (../bundle/roles) |
| 22 | `swift_account` | **COVERED** | rust `rust_config`+`rust_systemd` | roles_path only (../bundle/roles) |
| 23 | `swift_container` | **COVERED** | rust `rust_config`+`rust_systemd` | roles_path only (../bundle/roles) |
| 24 | `swift_object` | **COVERED** | rust `rust_config`+`rust_systemd` | roles_path only (../bundle/roles) |
| 25 | `swift_proxy` | **COVERED** | rust payload+config+systemd+verify | roles_path only (../bundle/roles) |
| 26 | `system_tuning` | **COVERED** | python-include (`enable_python_platform`) | symlink → ../../bundle/roles/system_tuning |

