# Swift Deploy UI Design

## Reference and direction

The reference is the user's local `lab-ui`: a single-file, dependency-light
operations console with a dark terminal-boot atmosphere, bilingual labels,
live state polling, asynchronous jobs, compact tables, and activity history.
The new interface keeps that operating rhythm but does not copy its Colab
content or blindly reproduce its all-monospace styling.

The Swift-specific signature is a live sealed-deployment manifest. It shows the
audited v3 baseline, inventory reach, plan digest, host/task counts, and the
three independent risk capabilities as one operational chain. Data and digests
use monospace; controls and explanatory text use the system UI face for faster
reading. The palette is graphite, oxidized copper, muted green, amber, and red.
There are no gradients, floating cards, fake windows, entrance-hidden content,
or decorative motion.

## Approaches considered

1. A React/Vite frontend plus a Rust API offers a large component ecosystem but
   adds a second build/runtime surface and diverges from the reference's compact
   appliance character.
2. An embedded HTML/CSS/JavaScript console served by the existing Rust binary
   adds no runtime dependency and keeps the CLI as the single execution truth.
   This is selected.
3. A Tauri desktop app would feel native but is the wrong deployment shape for
   a remote Rocky Linux controller reached over SSH.

## Architecture and data flow

`swift-deploy ui` starts a small standard-library HTTP server. It refuses any
non-loopback bind. Static assets are compiled into the binary with
`include_str!`, so there is no Node process or frontend build in production.
The UI polls `/api/state` and posts action requests to `/api/audit`,
`/api/validate`, `/api/plan`, and `/api/apply`.

Each action runs asynchronously and serially. The server invokes the current
`swift-deploy` executable with structured arguments, never through a shell, so
the CLI remains the authoritative implementation of parsing, planning, digest
verification, risk authorization, OpenSSH, and execution. Audit and validation
return JSON. Planning writes the sealed plan, then the UI reads only its compact
summary. Apply returns the aggregate execution report. A bounded activity log
retains redacted output and errors.

## Safety and failure behavior

The server is loopback-only and intended for an SSH local-forward. POSTs require
a per-process anti-CSRF token delivered only in the same-origin page; security
headers deny framing, external scripts, forms, and cross-origin connections.
The API never exposes password authentication. It refuses Apply when the
inventory path is under `config_sample`, when the stored plan seal is invalid,
when the pasted digest is not exact, or when the operator has not typed
`APPLY`. Disk wiping, firewall mutation, and SSH reconfiguration remain separate
checkboxes and separate CLI flags.

Only one job can run at once. Long Apply jobs are not given a cosmetic cancel
button because abruptly terminating a deployment can leave hosts in a worse
state. Errors remain visible, redacted, and retryable. Content renders visibly
before JavaScript state arrives; progress uses a small spinner without hiding
the underlying controls.

## Verification

Rust tests cover request parsing, loopback enforcement, command argument
construction, sample-inventory blocking, digest confirmation, static asset
presence, and the existing 28-module/CLI suite. Final verification runs format,
strict Clippy, all tests, and a locked release build on Rocky 9. A real browser
then exercises audit, validate, plan, language switching, copy/confirmation,
sample Apply blocking, responsive layout, and console/request errors. The final
service runs on `127.0.0.1:8788`; no public security-group port is opened.
