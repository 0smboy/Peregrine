# Swift Deploy RS Design

## Decision

`swift_ansible_v3_20230725.tar.gz` is the rewrite baseline. Its embedded Git
HEAD is `6101dda45f9f5276946d8178380c2d601c3a5c4b` from 2023-07-25. The archive
also contains one later working-tree change, `skip-name-resolve = 1`, which is
part of the selected input. `swift_ansible-2.1.0.tar.gz` is a repackaged older
tree: HEAD `5529c612a330a36474f4b5a0819ce04ade76114a` from 2022-11-25. Its 2024
archive timestamp is not a source-version timestamp.

The implementation is a Rust-native compatibility executor. It reads the
selected bundle's inventory, variable, playbook, role, task, template, and file
assets, but it never invokes `ansible` or `ansible-playbook`. The executable
implements the exact task-module and control-flow surface found by the audit.
Unknown modules and unsupported syntax fail closed.

## Approaches considered

1. Wrap `ansible-playbook` in Rust. This would be fast, but it is not a rewrite
   and retains the Python/Ansible runtime and its unsafe defaults. Rejected.
2. Translate all 413 tasks into hand-written Rust functions. This duplicates a
   large amount of declarative data, makes upstream comparison difficult, and
   increases the chance of silently changing a command or template. Rejected.
3. Implement a bounded Rust execution engine for this bundle's 28 executable
   modules and its observed loops, conditions, includes, registers, handlers,
   delegation, and run-once semantics. This preserves reviewable deployment
   intent while removing the Ansible runtime. Selected.

## Architecture

The CLI has four user-visible stages:

- `audit`: inventory every task/control/module, calculate a deterministic bundle
  fingerprint, and reject unsupported syntax.
- `validate`: parse inventory and variables, expand host ranges/child groups,
  report password-auth and placeholder warnings, and never contact hosts.
- `plan`: resolve plays, roles, static includes, hosts, inherited conditions and
  nested loops into a deterministic JSON plan. The plan contains raw template
  expressions, never expanded secret values. Its SHA-256 digest is the approval
  token.
- `apply`: verify bundle, inventory and plan fingerprints, require the exact
  digest, then execute sequentially over OpenSSH. Disk wiping, firewall changes,
  and SSH reconfiguration each require a separate explicit flag.

`inventory.rs` owns INI inventory expansion and variable precedence.
`bundle.rs` owns strict YAML task discovery and include flattening.
`template.rs` owns Jinja rendering and the small Ansible compatibility layer.
`planner.rs` builds deterministic plans. `safety.rs` classifies risk and redacts
secrets. `transport.rs` invokes OpenSSH without a shell on the controller and
keeps host-key checking enabled. `executor.rs` evaluates runtime conditions and
loops and dispatches module behavior. `modules.rs` implements remote mutations;
file editing modules modify content in Rust and upload the result atomically.

## Data and security boundaries

Only upstream roles, templates, scripts, playbooks and `config_sample` enter the
new bundle. Real `group_vars`, `host_vars`, inventories, logs, `.git`, bytecode,
and cache directories are excluded. The runtime refuses inline inventory
passwords by default; OpenSSH key or agent authentication is the supported path.
Logs redact fields and command fragments containing password, passphrase,
secret, token, access key, or private key.

The old Ansible configuration disabled host-key checking. The Rust rewrite does
not. Apply uses the user's standard known-hosts file or an explicitly supplied
one. A plan containing disk, firewall, or SSH-lockout risk cannot execute merely
because `--confirm` is correct; the matching risk capability flag is also
required.

## Verification

The full v3 bundle is the compatibility fixture. Audit must report 57 task files,
413 leaf tasks, no unsupported modules, and all 28 executable modules covered by
the dispatcher. Unit tests cover inventory ranges/children, expression and
template compatibility, include/loop inheritance, plan determinism, risk gates,
secret redaction, file editors, and command construction. CLI smoke tests run
`audit`, `validate`, and `plan` on Rocky Linux 9. Release completion requires
`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
`cargo test --all-features`, a release build, and a non-destructive Rocky 9
local transport smoke test.

Live application to a real multi-node Swift cluster is outside the available
hardware boundary. The handoff therefore states that execution mechanics and
Rocky 9 behavior are verified, while a production Swift convergence run still
requires one controlled cluster validation.

