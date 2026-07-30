# Swift Deploy RS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the selected Swift Ansible v3 runtime with a self-contained,
strict, safety-gated Rust deployment CLI while preserving its audited task and
template bundle.

**Architecture:** Parse the selected Ansible-shaped declarative inputs into a
bounded internal model, produce a deterministic approved plan, then execute that
plan through a Rust module dispatcher over strict OpenSSH. Unsupported behavior
is an error and high-risk operations require independent capabilities.

**Tech Stack:** Rust 1.97.0, clap, serde, serde_json, serde_yaml_ng, MiniJinja,
regex, sha2, tempfile, walkdir, shell-words, system OpenSSH.

## Global Constraints

- Baseline archive SHA-256: `d5da56428441852a7bed47a3c44d6b213bb70c76505a5404f63ee1871a276522`.
- Baseline Git HEAD: `6101dda45f9f5276946d8178380c2d601c3a5c4b` plus the archived working-tree change.
- Do not invoke Ansible or Python at runtime.
- Do not copy real inventory, group variables, host variables, or logs.
- Preserve SSH host-key verification.
- Refuse unknown modules or syntax.
- Require separate gates for disk wipe, firewall mutation, and SSH reconfiguration.
- All tests and release builds run on the supplied Rocky Linux 9 host.

---

### Task 1: Establish the audited, sanitized baseline

**Files:**
- Create: `docs/COMPARISON.md`
- Create: `bundle/**` from the selected archive
- Test: `tests/bundle_audit.rs`

**Interfaces:**
- Produces: `BundleAudit { task_files, tasks, modules, controls, fingerprint }`.

- [ ] Record both archive hashes, embedded Git heads/dates, working-tree state,
  and the selection rationale.
- [ ] Copy only roles, lookup plugin, playbooks, templates, scripts, and sample
  configuration. Prove excluded paths are absent with `find` and secret scans.
- [ ] Write a failing test expecting 57 task files, 413 tasks, and no unsupported
  executable module.
- [ ] Implement strict recursive task discovery in `src/bundle.rs`.
- [ ] Run `cargo test --test bundle_audit`; expected result: PASS.

### Task 2: Parse inventory and render the observed template language

**Files:**
- Create: `src/inventory.rs`
- Create: `src/template.rs`
- Test: `tests/inventory_template.rs`

**Interfaces:**
- Produces: `Inventory::parse`, `Inventory::resolve`,
  `Inventory::host_context`, `Renderer::render`, `Renderer::eval`.

- [ ] Add failing tests for numeric host ranges, child groups, variable merge,
  exact-value expressions, `default`, `join`, `replace`, `first`, `int`,
  `intersect`, `is failed`, and the two observed Python-style string calls.
- [ ] Implement inventory parsing without shell evaluation.
- [ ] Implement strict MiniJinja rendering with only the observed compatibility
  extensions.
- [ ] Run `cargo test --test inventory_template`; expected result: PASS.

### Task 3: Build deterministic plans and safety approvals

**Files:**
- Create: `src/model.rs`
- Create: `src/planner.rs`
- Create: `src/safety.rs`
- Test: `tests/planner_safety.rs`

**Interfaces:**
- Produces: `Planner::build`, `Plan::seal`, `Plan::verify`,
  `SafetyPolicy::authorize`, `redact`.

- [ ] Add failing tests for role conditions, block/include inheritance, nested
  loops, run-once, handler registration, deterministic digest, redaction, and
  all three independent high-risk gates.
- [ ] Implement static include flattening with cycle detection and source spans.
- [ ] Store raw task expressions and input fingerprints, not resolved secrets.
- [ ] Classify each task and seal the canonical JSON plan with SHA-256.
- [ ] Run `cargo test --test planner_safety`; expected result: PASS.

### Task 4: Implement strict transport and all 28 module adapters

**Files:**
- Create: `src/transport.rs`
- Create: `src/modules.rs`
- Create: `src/executor.rs`
- Test: `tests/executor_modules.rs`

**Interfaces:**
- Consumes: sealed `Plan`, `Inventory`, bundle and renderer.
- Produces: `ExecutionReport` with changed/skipped/failed task counts.

- [ ] Add a recording transport and failing tests for command, package, service,
  transfer, file-edit, database, HTTP, fact, control and error paths.
- [ ] Build OpenSSH arguments as an argv array; keep strict host checking and
  reject inventory passwords unless explicitly enabled with `sshpass` present.
- [ ] Implement runtime loop/condition/register/delegate/run-once/notify logic.
- [ ] Implement all observed modules: shell, command, template, file,
  lineinfile, service, copy, set_fact, yum, ini_file, fail, blockinfile,
  script, debug, fetch, stat, unarchive, mysql_user, systemd, pip, uri, find,
  mysql_db, timezone, user, get_url, cron, and package.
- [ ] Run `cargo test --test executor_modules`; expected result: PASS.

### Task 5: Deliver the CLI and prove it on Rocky Linux 9

**Files:**
- Create: `src/cli.rs`
- Create: `src/lib.rs`
- Modify: `src/main.rs`
- Create: `README.md`
- Create: `docs/COMPATIBILITY.md`
- Test: `tests/cli_smoke.rs`

**Interfaces:**
- Produces: `swift-deploy audit|validate|plan|apply|modules`.

- [ ] Add CLI tests for successful audit/plan, malformed inventory, plan digest
  mismatch, and missing safety capabilities.
- [ ] Implement concise text output plus stable JSON output for automation.
- [ ] Document one canonical path from sample config to plan and apply.
- [ ] Run `cargo fmt --check`.
- [ ] Run `cargo clippy --all-targets --all-features -- -D warnings`.
- [ ] Run `cargo test --all-features`.
- [ ] Run full-bundle `audit`, sample `validate`, sample `plan`, digest rejection,
  and safety-gate rejection on Rocky Linux 9.
- [ ] Run `cargo build --release --locked` and record binary SHA-256.
- [ ] Archive the source and reports, copy the deliverable back to the shared
  `outputs` directory, and leave `/root/swift-rewrite/work/swift-deploy-rs` as
  the only remote mainline.

