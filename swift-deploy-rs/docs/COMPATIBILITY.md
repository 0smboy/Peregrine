# v3 compatibility boundary

This project intentionally implements the deployment surface observed in
`swift_ansible_v3_20230725`; it is not a general-purpose Ansible replacement.
The strict bundle audit is the authority. A new or unknown module/control causes
the audit or planner to fail instead of being silently ignored.

## Audited surface

| Item | Verified value |
|---|---:|
| Task and handler YAML files | 57 |
| Leaf tasks | 413 |
| Executable modules | 28 |
| Unsupported modules in selected v3 bundle | 0 |
| YAML parse errors in selected v3 bundle | 0 |

The 28 module adapters are:

`blockinfile`, `command`, `copy`, `cron`, `debug`, `fail`, `fetch`, `file`,
`find`, `get_url`, `ini_file`, `lineinfile`, `mysql_db`, `mysql_user`,
`package`, `pip`, `script`, `service`, `set_fact`, `shell`, `stat`, `systemd`,
`template`, `timezone`, `unarchive`, `uri`, `user`, and `yum`.

All 28 names are dispatched in an integration test. The file-editing adapters
(`template`, `copy`, `lineinfile`, `blockinfile`, and `ini_file`) calculate the
new content in Rust and use atomic uploads. Command-backed adapters construct
their command from structured parameters and run through the same transport.

## Inventory and v3 helper compatibility

Supported inventory behavior:

- INI host groups, `[group:children]`, and `[group:vars]`.
- Numeric ascending and descending host ranges.
- Inline host variables plus sibling `group_vars/` and `host_vars/` files.
- Deterministic host/group membership and variable merge order.
- Bare legacy Jinja scalars found in the v3 sample configuration.
- Compilation of the v3 security category data into business port rules.
- Native compilation of `ring_config.yml`, including IP and disk range
  expansion, without invoking `ring_config_helper.py`.
- Aggregate management, storage, business, Keystone, and MariaDB address lists.

The inventory fingerprint covers the inventory file and all sibling variable
files. Generated plans, logs and unrelated helper files are excluded from that
fingerprint.

## Planner and runtime controls

Supported controls observed in v3:

- plays, roles, role `defaults/` and `vars/`, handlers;
- static `include` and `include_tasks`, including `key=value` parameters;
- nested `block` inheritance and include-cycle detection;
- `when`, `failed_when`, `changed_when`, `ignore_errors`;
- `register`, `notify`, `run_once`, `delegate_to`;
- `become` and `become_user`;
- `loop`, `with_items`, `with_dict`, `with_together`, `with_inidata`;
- task-level `args`, role variables and task variables.

The Jinja compatibility layer is strict and includes the expressions and
string/list operations used by v3, including `split`, `find`, `join`, `lower`,
`strip`, `replace`, mapping `get`, `intersect`, registered-result `failed`, and
legacy embedded `{{ ... }}` in conditions. It is not the complete Ansible
filter/plugin ecosystem.

## Safety semantics

Plans are canonical JSON sealed with SHA-256. Every field except the digest
itself contributes to the seal. `apply` refuses to contact any host until it has
verified:

- the plan seal and the caller's exact digest confirmation;
- the selected bundle fingerprint;
- the inventory and variable-file fingerprint;
- independent authorization for every required `disk_wipe`, `firewall`, and
  `ssh_reconfigure` capability.

OpenSSH arguments preserve strict host-key checking. Key or agent authentication
is the default. Password variables are rejected unless `--allow-password` is
explicit; that path also requires `sshpass` on the controller. Sensitive field
names and values are redacted from diagnostic output.

## Deliberate non-goals and remaining validation

- No arbitrary Ansible collections, lookup plugins, dynamic Python modules,
  Vault, tags, check mode, strategy plugins or parallel forks.
- No automatic rollback for external commands or destructive storage actions.
- No claim of byte-for-byte equivalence with every version of Ansible; behavior
  is bounded to the selected archive and fails closed outside it.
- The Rocky 9 test run verifies planning, safety gates, all dispatch paths,
  OpenSSH construction and non-destructive/local execution behavior. A live
  multi-node Swift convergence run was intentionally not performed against the
  supplied single controller. Production acceptance still requires one
  controlled, recoverable cluster trial with the real inventory.
