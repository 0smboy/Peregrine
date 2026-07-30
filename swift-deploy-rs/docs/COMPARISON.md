# Source comparison and baseline decision

| Evidence | `swift_ansible_v3_20230725.tar.gz` | `swift_ansible-2.1.0.tar.gz` |
|---|---:|---:|
| SHA-256 | `d5da56428441852a7bed47a3c44d6b213bb70c76505a5404f63ee1871a276522` | `7ced3cfc2f65ba238ad6fae8a781aac87309e028fe1a189a845602045d346aab` |
| Archive entries | 811 | 749 |
| Unsafe archive paths | 0 | 0 |
| Embedded Git HEAD | `6101dda45f9f5276946d8178380c2d601c3a5c4b` | `5529c612a330a36474f4b5a0819ce04ade76114a` |
| Source commit date | 2023-07-25 16:22:55 +08:00 | 2022-11-25 16:26:42 +08:00 |
| Working tree | one MariaDB DNS-hardening line | modified/deleted runtime configuration and extra untracked files |

Decision: use v3. The apparent 2024 date on the 2.1.0 archive is a repackaging
timestamp, not a newer source commit. The v3 working tree's
`skip-name-resolve = 1` line is retained because the requested comparison is of
the archives as delivered, not only their Git commits.

The new project's bundle excludes both archives' `.git` directories, actual
inventories, real `group_vars`, real `host_vars`, log files, bytecode and caches.

## Compatibility findings carried into the rewrite

The comparison was not limited to filenames. Planning the selected v3 tree
exposed two source-era assumptions that the Rust implementation now handles
directly:

- `config_sample/group_vars/security` is configuration input even though the
  sample inventory has no `security` host group. A stock group-vars loader can
  therefore leave the port model unused. The Rust inventory compiler reads this
  declared security input and produces the business-port rules deterministically.
- `ring_config_helper.py` is an interactive Python generator for
  `ring_config.yml`, and several sample YAML scalars use bare legacy Jinja. The
  Rust loader normalizes those scalars and compiles ring nodes, IP ranges and
  disk ranges natively. No interactive helper or Python runtime is required.

These are compatibility repairs for the selected v3 input, not reasons to fall
back to the older 2.1.0 archive.
