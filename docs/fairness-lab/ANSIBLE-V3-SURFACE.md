# Ansible v3 surface — Python `bundle/` vs Rust `bundle-rust/`

**As of:** 2026-08-07  
**Authority for:** Platform row *Full ansible v3 surface* in [RUST-VS-PYTHON-PARITY.md](RUST-VS-PYTHON-PARITY.md)  
**Evidence (default PARTIAL):** [`tools/test-results/impl-ansible-v3-surface-20260807/`](../../tools/test-results/impl-ansible-v3-surface-20260807/)  
**Evidence (FULL TWIN PATH opt-in):** [`tools/test-results/impl-ansible-v3-twin-20260807/`](../../tools/test-results/impl-ansible-v3-twin-20260807/)  
**Related:** [DEPLOY-HYBRID.md](DEPLOY-HYBRID.md) · [P3-OPS-CONTRACT.md](P3-OPS-CONTRACT.md) · [KEYSTONE-LIVE.md](KEYSTONE-LIVE.md) · [MULTI-REGION.md](MULTI-REGION.md)

## Claim level (honest)

| Stack | Path | Claim |
|-------|------|-------|
| Python ansible-v3 | `swift-deploy-rs/bundle/` | Near-full upstream-style surface (format disks, Keystone install, security, cosbench, …) |
| Rust stack **default** | `bundle-rust/swift.yml` | **PARTIAL / GREEN** — data-plane + LB + expand + Identity *对接*; Contabo-safe (no format_disks) |
| Rust stack **FULL TWIN PATH** | `bundle-rust/swift-full-v3.yml` | **AVAILABLE (opt-in)** — **26/26** role reachability; rust preferred else Python via `roles_path`/symlinks |
| Monitoring agents | `swift-deploy-rs/bundle-monitoring/` | Separate bundle; not inlined into `bundle-rust/swift.yml` |

**Default remains PARTIAL.** Contabo production data-plane target is pure `bundle-rust apply` via **`swift.yml`** (safe: no disk wipe).  

**FULL TWIN PATH (opt-in only):** `bundle-rust/swift-full-v3.yml` reaches **26/26** Python `bundle/roles/*` names — rust preferred when implemented, else Python include via `roles_path = roles:../bundle/roles` and local symlinks. See [§ Full v3 twin path](#full-v3-twin-path-swift-full-v3yml).

---

## Full v3 twin path (`swift-full-v3.yml`)

| Item | Value |
|------|--------|
| Playbook | `swift-deploy-rs/bundle-rust/swift-full-v3.yml` |
| Default Contabo? | **No** — use `swift.yml` |
| `ansible.cfg` | `roles_path = roles:../bundle/roles` |
| Disk format | `format_disks` / `format_new_disks` only when `allow_disk_format \| default(false)` |
| Keystone / MariaDB install | only when `enable_identity_provision \| default(false)` |
| Platform extras | `enable_python_platform \| default(false)` (chrony, security, performance_tuning, system_tuning) |
| Cosbench / docker / proxyfs / new_ring | `enable_python_extras \| default(false)` (and related flags) |
| Evidence | [`tools/test-results/impl-ansible-v3-twin-20260807/`](../../tools/test-results/impl-ansible-v3-twin-20260807/) |

### Coverage table — 26/26 COVERED

| # | Python role (`bundle/roles/`) | Twin coverage | Mechanism |
|--:|-------------------------------|---------------|-----------|
| 1 | `check` | **COVERED** | python-include `check` |
| 2 | `chrony` | **COVERED** | python-include `chrony` (`enable_python_platform`) |
| 3 | `common` | **COVERED** | rust `rust_common` |
| 4 | `cosbench` | **COVERED** | python-include `cosbench` (`enable_python_extras`) |
| 5 | `docker` | **COVERED** | python-include `docker` (`enable_python_extras`) |
| 6 | `example_structure` | **COVERED** | scaffold no-op role (`enable_example_structure`) |
| 7 | `finalize_installation` | **COVERED** | rust `rust_systemd` + `rust_verify` |
| 8 | `format_disks` | **COVERED** | python-include `format_disks` (`allow_disk_format`) |
| 9 | `format_new_disks` | **COVERED** | python-include `format_new_disks` (`allow_disk_format`) |
| 10 | `haproxy_servers` | **COVERED** | rust `rust_haproxy` |
| 11 | `keepalived_servers` | **COVERED** | rust `rust_keepalived` |
| 12 | `keystone_install` | **COVERED** | python-include (`enable_identity_provision`) |
| 13 | `keystones` | **COVERED** | python-include (`enable_identity_provision`); 对接 also via `rust_identity_bridge` |
| 14 | `mariadb_servers` | **COVERED** | python-include (`enable_identity_provision`) |
| 15 | `new_ring` | **COVERED** | python-include (`enable_python_extras` / `enable_new_ring`) |
| 16 | `performance_tuning` | **COVERED** | python-include (`enable_python_platform`) |
| 17 | `proxyfs` | **COVERED** | python-include (`enable_python_extras` / `install_proxyfs`) |
| 18 | `ring_builder` | **COVERED** | rust `rust_rings` |
| 19 | `ring_utils` | **COVERED** | rust `rust_rings` |
| 20 | `security` | **COVERED** | python-include (`enable_python_platform`) |
| 21 | `storage_nodes_common` | **COVERED** | rust `rust_common` + `rust_disks` + `rust_replication_key` |
| 22 | `swift_account` | **COVERED** | rust `rust_config` + `rust_systemd` (+ payload) |
| 23 | `swift_container` | **COVERED** | rust `rust_config` + `rust_systemd` (+ payload) |
| 24 | `swift_object` | **COVERED** | rust `rust_config` + `rust_systemd` (+ payload) |
| 25 | `swift_proxy` | **COVERED** | rust `rust_payload` + `rust_config` + `rust_systemd` + `rust_verify` |
| 26 | `system_tuning` | **COVERED** | python-include (`enable_python_platform`) |

**Score: 26/26 COVERED** (rust equivalent preferred, else python-include via `roles_path`).

Python-include roles are resolved either as symlinks under `bundle-rust/roles/<name> → ../../bundle/roles/<name>` (deploy-rs planner) or via `roles_path` for real Ansible.

### Operator invoke (plan only recommended for Contabo)

```sh
# Safe default Contabo data-plane
swift-deploy plan --bundle bundle-rust --playbook bundle-rust/swift.yml \
  --inventory <inv> --output plan-swift.json

# Opt-in full twin (flags default false → format/identity/platform skipped)
swift-deploy plan --bundle bundle-rust --playbook bundle-rust/swift-full-v3.yml \
  --inventory <inv> --output plan-full-v3.json
# Never apply full-v3 against live Contabo disks without ticket + allow_disk_format
# and independent safety caps (--allow-disk-wipe etc.).
```

---

## 1. Full role matrix

Status legend:

| Status | Meaning |
|--------|---------|
| **DONE** | Implemented in `bundle-rust` and on the default or opt-in apply path |
| **PARTIAL** | Covered only for a subset of Python behavior, or via config flags / composite roles |
| **ABSENT** | Not implemented in `bundle-rust`; use Python bundle or OOB (documented) |
| **N/A** | Scaffold / dead / not part of production Contabo claim |

### 1.1 Roles used by `bundle/swift.yml`

| Python role | Rust equivalent | Status | Notes |
|-------------|-----------------|:------:|-------|
| `check` | swift-deploy-rs preflight / workspace validation | **PARTIAL** | No SAIO-mode fail role; engine preflight + `deploy_stack=rust` gates |
| `common` | `rust_common` | **PARTIAL** | timezone, dirs, rsync; no Keystone hosts-file, no REINSTALL kill-all, no hostname_modifiable |
| `performance_tuning` | — / `python_only_platform` docs | **ABSENT** | limits/sysctl NIC tuning not in rust bundle |
| `chrony` | groups kept empty-ok / `python_only_platform` | **ABSENT** | NTP groups exist for inventory validation only; not managed |
| `haproxy_servers` | `rust_haproxy` | **DONE** | `when: use_lb`; TLS via `lb_mode=https` (operator PEM or self-signed) |
| `keepalived_servers` | `rust_keepalived` | **DONE** | `when: use_lb`; VIP health tracks haproxy |
| `swift_proxy` | `rust_payload` + `rust_config` + `rust_systemd` + `rust_verify` | **DONE** | TempAuth default; Keystone filters on-by-config only |
| `storage_nodes_common` | `rust_common` + `rust_disks` + `rust_replication_key` | **PARTIAL** | pkgs subset; mkdir devices only |
| `format_disks` | **never** on default / full-twin python-include | **ABSENT** (default) | Default `swift.yml` never includes. Full twin: `when: allow_disk_format \| default(false)` |
| `swift_account` | `rust_config` + `rust_systemd` (+ payload) | **DONE** | account server + reaper/auditor units as implemented |
| `swift_container` | `rust_config` + `rust_systemd` (+ payload) | **DONE** | + sharder/updater/reconciler units as present |
| `swift_object` | `rust_config` + `rust_systemd` (+ payload) | **DONE** | + replicator/reconstructor/expirer/auditor |
| `ring_builder` | `rust_rings` | **DONE** | stamp rebuild; expand via `expand.yml` |
| `ring_utils` | `rust_rings` (fetch/distribute) | **DONE** | controller `ring_fetch_dir` staging |
| `finalize_installation` | `rust_systemd` + `rust_verify` | **PARTIAL** | no `/etc/.peregrine` backup dance; fail-closed health + tempauth PUT/GET |
| `mariadb_servers` | Python only / `python_only_identity` | **ABSENT** | Galera not rewritten into rust (`KEYSTONE-LIVE.md`) |
| `keystone_install` | Python only / `python_only_identity` | **ABSENT** | install packages via python inventory |
| `keystones` | Identity 对接 flags + `rust_identity_bridge` | **PARTIAL** | No bootstrap role; proxy filters + optional HAProxy listeners only |
| `proxyfs` | — / `python_only_extras` | **ABSENT** | not in Contabo rust claim |
| `security` | — / `python_only_platform` | **ABSENT** | sshd bind + firewall intentionally not auto-applied |

### 1.2 Roles only on other Python playbooks

| Python role | Playbook(s) | Rust equivalent | Status | Notes |
|-------------|-------------|-----------------|:------:|-------|
| `format_new_disks` | `add_new_disks.yml` | OOB mount + `expand.yml` | **ABSENT** | no mkfs in rust; operator prepares XFS |
| `new_ring` | `add_new_ring.yml` | multi-policy in `swift_policies` + ring rebuild | **PARTIAL** | no dedicated add-policy playbook; greenfield stamp / expand |
| `docker` | `install_cosbench.yml` | — | **ABSENT** | |
| `cosbench` | `install_cosbench.yml` | — / autocos-rs / cosbench-rs OOB | **ABSENT** | fairness tools live under monorepo `cosbench-rs` / `autocos` |
| `system_tuning` | `system_tuning_deploy.yml` | — | **ABSENT** | |
| `example_structure` | (scaffold) | — | **N/A** | |

### 1.3 Rust-only roles (no Python 1:1)

| Rust role | Purpose | Python nearest |
|-----------|---------|----------------|
| `rust_payload` | seal binaries + liberasurecode into bundle | yum packages under `swift_*` |
| `rust_disks` | mkdir-only devices; dual-guard comments | `format_disks` (opposite: never wipe) |
| `rust_replication_key` | ed25519 rsync-over-ssh | storage_nodes rsync setup |
| `rust_expand_mode` | `set_fact ring_expand=true` for expand.yml | add_nodes / add_new_disks mode |
| `rust_verify` | fail-closed healthcheck + tempauth CRUD | parts of finalize / manual smoke |
| `rust_identity_bridge` | optional assert/docs when identity flags on; **never installs Keystone** | `keystones` bootstrap (docs only) |
| `python_only_*` | README + fail-closed if mis-included | map ABSENT Python roles |
| `monitoring_overlay_path` | points at `bundle-monitoring` | n/a in python v3 core |

### 1.4 Monitoring (separate bundle)

| Piece | Path | Status vs python v3 |
|-------|------|---------------------|
| mon agents playbook | `bundle-monitoring/swift.yml` | **DONE** as overlay; not a `bundle/` role |
| roles | `mon_payload`, `mon_config`, `mon_systemd` | R0 node_exporter / statsd_exporter / Alloy |
| Contabo Prom rules / textfile | `tools/monitoring/` | ops overlay |

---

## 2. Play coverage differences

### 2.1 Greenfield

| Python `bundle/swift.yml` plays | Rust `bundle-rust/swift.yml` |
|---------------------------------|------------------------------|
| all → check | (engine preflight) |
| all → common | all → `rust_common`, `rust_payload` |
| performance_tuning | **ABSENT** |
| ntp_server/clients → chrony | **ABSENT** (groups may be empty) |
| haproxy_servers | haproxy_servers → `rust_haproxy` `when: use_lb` |
| keepalived_servers | keepalived_servers → `rust_keepalived` `when: use_lb` |
| proxy_servers → swift_proxy | folded into config/systemd/verify |
| storage_nodes → storage_nodes_common | storage_nodes → `rust_disks`, `rust_replication_key` |
| format_disk_servers → format_disks | **never present** |
| account/container/object server roles | all → `rust_config`, `rust_rings`, `rust_systemd` |
| ring_builder + ring_utils | `rust_rings` |
| finalize_installation | proxy → `rust_verify` |
| mariadb_servers / keystones / proxyfs / security | **not installed**; optional Identity 对接 only |

### 2.2 Companion playbooks

| Python | Rust / operator path |
|--------|----------------------|
| `add_new_disks.yml` (format_new_disks + rings) | Mount OOB → update `swift_devices` → **`expand.yml`** |
| `add_nodes.yml` | Inventory + **`expand.yml`** (rings + LB + verify) |
| `add_new_ring.yml` | Policy list + greenfield stamp / force rebuild (no dedicated playbook) |
| `install_mariadb_keystone.yml` | **Python** `bundle/` + `config_contabo_identity` only; rust **`deferred-python.yml`** documents optional `when: include_python_keystone_install` (fail-closed) |
| `install_cosbench.yml` | Out of band / monorepo tools; `deferred-python.yml` extras flag |
| `system_tuning_deploy.yml` | Out of band; `deferred-python.yml` platform flag |
| `deploy_utils.yml` | stub TODO in Python; N/A |
| — | **`identity.yml`** — optional Identity 对接 re-render (`when:` flags) |
| — | **`monitoring.yml`** — pointer + tags → **`bundle-monitoring/swift.yml`** |
| — | **`deferred-python.yml`** — Python-only surfaces with explicit `when:` default false |
| — | **`swift-full-v3.yml`** — OPT-IN full twin (26/26 roles; rust preferred else python-include) |
| — | **`bundle-monitoring/swift.yml`** for agents (tags: `monitoring`, `mon_*`) |
| — | TLS operator scripts: `tools/ops/apply-vip-tls-pem.sh` |

### 2.2b Tags (documentation / real-Ansible; deploy-rs does not filter)

| Playbook | Tags |
|----------|------|
| `bundle-rust/swift.yml` | `common`, `payload`, `disks`, `replication`, `config`, `rings`, `systemd`, `haproxy`, `keepalived`, `lb`, `identity`, `verify` |
| `bundle-rust/expand.yml` | `expand`, `disks`, `replication`, `rings`, `haproxy`, `keepalived`, `lb`, `verify` |
| `bundle-rust/identity.yml` | `identity`, `identity_proxy`, `identity_haproxy`, `config`, `haproxy`, `lb` |
| `bundle-rust/monitoring.yml` | `monitoring`, `mon_agents` |
| `bundle-rust/deferred-python.yml` | `deferred`, `python_only`, `keystone_install`, `mariadb_servers`, `format_disks`, `platform`, `extras` |
| `bundle-rust/swift-full-v3.yml` | `full_v3`, plus data-plane + `format_disks` / `identity_provision` / `platform` / `extras` (opt-in `when:`) |
| `bundle-monitoring/swift.yml` | `monitoring`, `mon_agents`, `mon_payload`, `mon_config`, `mon_systemd` |

### 2.3 Identity (对接, not provision)

Default Contabo: **TempAuth** on VIP; both `identity_*_enabled` flags **false**.

| Knob | Effect in rust |
|------|----------------|
| `identity_haproxy_enabled` | HAProxy listeners :5000 / :35357 / MariaDB :3030 |
| `identity_proxy_enabled` or `auth_method` ∈ {`keystone`,`keystone_coexist`} | proxy `authtoken` + `keystoneauth` filters |
| `rust_identity_bridge` play (on `swift.yml` + `identity.yml`) | `when:` identity flags / keystone auth_method — assert/docs only |
| Standalone `identity.yml` | Re-render `rust_config` / `rust_haproxy` Identity pieces without full greenfield |

**Never** force Keystone or MariaDB install from `bundle-rust`.

---

## 3. How to enable optional Python-only paths without wiping Contabo

### 3.1 Dual-guard (hard rules)

1. **`rust_disks` never** runs `mkfs` / `wipefs` / `dd` / `parted` — mkdir under `srv_node_root` only.  
2. **Workspace** rejects non-empty `node.disks` for `stack: rust` (no `RiskClass::DiskWipe` on default rust plans).  
3. **Default path `swift.yml` never** lists `format_disks`.  
4. **Full twin dual-guard:** `swift-full-v3.yml` includes Python `format_disks` / `format_new_disks` **only** when `allow_disk_format | default(false)` is true.  
5. Contabo wipe of `/srv/node` requires an **explicit ticket** + `--allow-disk-wipe` + empty/new devices (never live object disks).  
6. Do **not** put live Contabo hosts into `format_disk_servers` without a maintenance window.

### 3.2 Keystone + MariaDB (Identity provisioning)

**Optional import / deferred pattern (bundle-rust):**  
`deferred-python.yml` lists `python_only_identity` with:

```yaml
when: include_python_keystone_install | default(false)
```

Default is **false**. Setting the flag true without switching to the Python
bundle **fails closed** (role refuses install). Real provisioning is always:

```sh
# Prefer Python playbook — not include_role into rust
swift-deploy apply … --bundle bundle --playbook install_mariadb_keystone.yml
# or: bundle/swift.yml with tags mariadb_servers,keystones_install,keystones_setup
```

Safe sequence for Contabo (data plane already on rust):

1. Use **separate** inventory: `swift-deploy-rs/bundle/config_contabo_identity/` (or equivalent).  
2. Apply **Python** playbook **only** for identity hosts — **do not** point `format_disk_servers` at Contabo data disks.  
3. Verify Galera `wsrep_cluster_size` and Keystone token issue **before** touching Swift VIP.  
4. On **rust** workspace / group_vars, enable 对接 only:
   ```yaml
   identity_haproxy_enabled: true
   identity_mariadb_backends: [10.0.4.1, 10.0.4.2, 10.0.4.3]   # example
   identity_keystone_backends: [10.0.4.1, 10.0.4.2, 10.0.4.3]
   identity_proxy_enabled: true   # or auth_method: keystone_coexist
   ```
5. `swift-deploy apply` **stack=rust** (`swift.yml` or focused **`identity.yml`**). Swift frontend VIP must stay on rust `rust_haproxy`.  
6. Smoke: Keystone token + Swift CRUD; keep TempAuth policy per window.  
7. Details: [KEYSTONE-LIVE.md](KEYSTONE-LIVE.md), `bundle-rust/IDENTITY.md`.

### 3.3 format_disks / new disks

**Default path:** never present.

**Deferred fail-closed wrapper:** `deferred-python.yml` → `python_only_format_disks` with
`when: include_python_format_disks | default(false)` — even if forced true, **fails closed**.

**Full twin opt-in:**

```yaml
# swift-full-v3.yml
- hosts: format_disk_servers
  roles:
    - role: format_disks
      when: allow_disk_format | default(false)
```

`rust_disks` refuses inventory wipe flags (`force_format_disks`,
`include_python_format_disks`, `allow_disk_wipe`, `use_format_disks`).

| Goal | Safe path |
|------|-----------|
| Greenfield empty lab disks | Full twin `allow_disk_format=true` **or** Python `format_disks` on `format_disk_servers` with `custom_disks` — **not** Contabo live objects |
| Contabo add disk | (1) Partition/format/mount **OOB** to `/srv/node/<name>` (2) append to `swift_devices` (3) `expand.yml` |
| Contabo add node | Inventory + ssh + empty device dirs → `expand.yml` |

### 3.4 Platform extras (chrony, security, performance, cosbench)

Run **Python** playbooks/roles against the intended host groups **without** including `format_disks` or full `swift.yml` if Contabo data already lives under rust. Prefer tags / dedicated playbooks (`system_tuning_deploy.yml`, `install_cosbench.yml`). Treat `security` (sshd bind + firewall) as high-risk: apply only with network access plan.

---

## 4. Implemented rust surface checklist (operator map)

| Surface | How to enable |
|---------|----------------|
| Data plane binaries + conf + systemd | default `swift.yml` |
| Device dirs | `host_vars.swift_devices`; dual-guard mkdir |
| Rings greenfield | `rust_rings` stamp |
| Expand add-disk/add-node | **`expand.yml`** (`ring_expand`) |
| HAProxy | `use_lb: true` |
| Keepalived VIP | `use_lb` + `keepalived_servers` inventory + workspace `ingress.mode=keepalived` |
| TLS terminate at HAProxy | `lb_mode: https` + PEM or self-signed; ops scripts under `tools/ops/` |
| Identity 对接 | flags in group_vars; see §3.2 |
| Monitoring agents | `bundle-monitoring/swift.yml` on same inventory |
| Multi-region ring ids | host_vars `region`/`zone` → [MULTI-REGION.md](MULTI-REGION.md) |

---

## 5. Residual list (honest)

### Default Contabo path (`swift.yml`) — why not FULL without twin

1. **No** `format_disks` / `format_new_disks` on default path (by design dual-guard).  
2. **No** MariaDB Galera / Keystone package install on default path.  
3. **No** `security` / `chrony` / `performance_tuning` / `system_tuning` on default path.  
4. **No** `proxyfs` / `docker` / `cosbench` on default path.  
5. Ring expand semantics differ (Rust builder rebalance without replica2part2dev persistence).  
6. Monitoring is a **sibling** bundle.  
7. Executor does not filter Ansible `tags:`.

### Full twin path (`swift-full-v3.yml`)

- **26/26** role names **COVERED** (rust preferred else python-include).  
- Opt-in flags default **false** — safe dry plan does not schedule wipe/install unless inventory overrides.  
- Python role body semantics (partial rust mapping fidelity) remain as in §1 matrix; twin = *reachability*, not 1:1 behavior clone.  
- Contabo live: still prefer `swift.yml`; full-v3 is lab / hybrid / documented opt-in only.

**Status for parity table:** Full ansible v3 surface → default **PARTIAL**; **FULL TWIN PATH available (opt-in)** via `swift-full-v3.yml` = **26/26 COVERED** (role reachability; not 1:1 behavior clone).

---

## 6. Thin wrapper roles (docs mapping)

Under `swift-deploy-rs/bundle-rust/roles/`:

| Role | Documents |
|------|-----------|
| `python_only_format_disks` | Use `bundle/roles/format_disks` + dual-guard rules |
| `python_only_identity` | Use `mariadb_servers` / `keystone_install` / `keystones` + rust 对接 |
| `python_only_platform` | chrony, security, performance_tuning, system_tuning |
| `python_only_extras` | cosbench, docker, proxyfs |
| `monitoring_overlay_path` | `bundle-monitoring` |
| `rust_identity_bridge` | Optional play when identity config present |

Wrappers are **not** on the default apply path. If mistakenly listed in a playbook, tasks **fail closed** with a pointer here — they never wipe disks or install Keystone.
