# Peregrine documentation-site audit — 2026-08-31

## Scope and source of truth

This audit covers only the Rust Swift family:

- `swift-rust`
- `swift-console`
- `swift-deploy-rs`
- `cosbench-rs`
- `autocos`

`swiftfuse` is excluded. The source baseline is the pushed candidate branch
`codex/g6-integration-20260831` at
`17adf0bfa78b30b2a7eed9f39836e0d63c715d2c`. It is G6-accepted source, not a
production release: formal W068 replication and W069 EC merge exactly once in
W070 for a strict 179/179 GREEN result. G7 is NOT ACCEPTED and production
readiness is NO-GO.

Documentation claims were checked against the candidate's workspace manifest,
source/config/CLI surfaces, the dated release handoff, and the exact lab evidence
named on the status page. Historical documents remain visible only when their
date and superseded claim boundary are explicit.

## Page matrix

| Order | Page | Audit result | Canonical boundary used |
|---:|---|---|---|
| 0 | `welcome.mdx` | Reframed as an engineering platform with scoped compatibility; added current gate boundary and product map. | Current status, five in-scope programs. |
| 1 | `status-2026-08-31.mdx` | Added dated source/release/gate/evidence snapshot. | Accepted source SHA, W068/W069/W070 accounting, production isolation. |
| 2 | `architecture.mdx` | Corrected workspace to 16 crates; added `swift-runtime`; separated implemented async serve path from acceptance. | Root `Cargo.toml`, `swift-http`, `swift-runtime`, current gate state. |
| 3 | `concurrency.mdx` | Added network/runtime/blocking-domain/backpressure/cancellation/durability model and route-proof rules. | `hyper_serve.rs`, `AsyncService`, `IncomingBody`, runtime boundaries. |
| 4 | `getting-started.mdx` | Added candidate and production warnings; retained bounded developer setup. | Repository build surface; not a go-live recipe. |
| 5 | `authentication.mdx` | Added TempAuth, Keystone, S3 signing, console/deployer credential handling, and evidence redaction. | Middleware/config/CLI credential surfaces. |
| 6 | `swift-api.mdx` | Added native Swift REST semantics, streaming, middleware and official-suite validation boundary. | Server/middleware routes and Python-oracle policy. |
| 7 | `s3-api.mdx` | Retained implemented surface but added candidate/no-go boundary and stricter evidence language. | `swift-s3api`, dated dual-oracle evidence. |
| 8 | `configuration.mdx` | Rebuilt around Hyper/Tokio: `workers` is runtime threads; `process_workers`, connections and active requests are independent. | Config structs/defaults and server CLI behavior. |
| 9 | `known-limitations.mdx` | Added explicit compatibility, G3/G6/G7, lab, auxiliary-build and production limits. | Current candidate/release facts. |
| 10 | `swift-rust.mdx` | Corrected 16-crate map and `swift-runtime`; removed unaccepted memory-performance claim. | Root manifest and candidate source. |
| 11 | `swift-deploy-rs.mdx` | Expanded exact command lifecycle, sealed plan, preflight, independent safety grants and failure policy. | Deployer CLI/schema/source. |
| 12 | `cosbench-rs.mdx` | Expanded validated workload schema, commands, control server and report formats. | Load-generator CLI/config/source. |
| 13 | `autocos.mdx` | Corrected CLI/environment contract and removed unsupported `ST_ENDPOINT` claim. | `autocos` CLI/config/source. |
| 14 | `swift-console.mdx` | Documented config and default-off control surfaces; separated observation from release acceptance. | Console config/routes/source. |
| 15 | `cli-reference.mdx` | Added verified command and environment reference for deploy, load and automation tools. | The three CLI definitions and help surfaces. |
| 16 | `parity.mdx` | Added current no-go banner and preserved partial-equals-not-implemented policy. | Strict parity table and current gate state. |
| 17 | `dual-oracle.mdx` | Marked the 57-case result historical and prevented it from closing current gates. | Dated strict-S3 scoreboard. |
| 18 | `versioning-worm.mdx` | Scoped semantics and rewrote live-sounding Guard claims as dated historical evidence. | Middleware semantics plus historical canaries. |
| 18.5 | `production-contract.mdx` | Retitled and fenced as historical; removed present-tense production implication. | 2026-08-18 contract only. |
| 19 | `deploy.mdx` | Added current release boundary and separated examples from authorized rollout. | Deployer/runbook surface. |
| 20 | `operations.mdx` | Added evidence/provenance requirements to health and repair procedures. | Recon/daemon behavior and current no-go state. |
| 21 | `observability.mdx` | Added logs, metrics, recon, PID/SHA provenance, alerting and acceptance-evidence rules. | Runtime/config/recon interfaces. |
| 22 | `testing.mdx` | Added ordered G0-G8 model and exact W068/W069/W070 boundary. | Frozen identity accounting and current lane evidence. |
| 23 | `lab-cluster.mdx` | Added candidate lane status and made production isolation explicit. | Swift1-Swift4 topology and dated evidence. |
| 24 | `recovery.mdx` | Added triage, quarantine, replication/EC/DB repair, protected commit and rollback rules. | Daemon/storage behavior and release safety. |
| 24.5 | `upgrades.mdx` | Added gated node-by-node promotion, config/migration checks and exact rollback. | Release provenance and production boundary. |
| 25 | `performance.mdx` | Marked historical/noisy results superseded and preserved G8 fairness requirements. | Dated performance evidence and fairness contract. |
| 26 | `validation-gates.mdx` | Added full G0-G8 contract, evidence, stop conditions and current red boundary. | Ordered acceptance program. |
| 27 | `releases.mdx` | Added candidate provenance, no-tag/no-main-merge state, bundle contents and gate limits. | Git/read-back/release handoff. |
| 28 | `runbooks.mdx` | Added current no-go banner and prevented historical rollout steps from authorizing a new one. | Dated fleet runbooks. |
| 29 | `security.mdx` | Expanded access, secrets, supply chain, unsafe surfaces and evidence limitations. | Config/source plus current candidate state. |
| 30 | `incidents.mdx` | Added historical banner and fixed the account-freeze anchor. | Dated incident record and configuration page. |
| 31 | `cold-contabo-delivery.mdx` | Marked as historical; kept LocalDir/cold prototype limitations visible. | Dated lab delivery only. |
| 32 | `contributing.mdx` | Added clean-tree, evidence, Rust/docs checks and review expectations. | Repository and gate discipline. |
| 33 | `philosophy.mdx` | Replaced broad marketing language with format-fidelity and evidence-scoped principles. | Architecture and parity boundaries. |

The site now contains 36 documentation pages and one reusable partial. Every
page has frontmatter, a unique navigation order, and a generated HTML, Markdown
and MDX representation.

## Required concurrency correction

Source `17adf0b` contains an implemented async serving path:

- `swift-http/hyper_serve.rs`
- `AsyncService`
- `IncomingBody`
- `serve_with_core_filters_and_config`
- native async SSYNC and object-MIME hand-offs
- the dedicated `swift-runtime` crate

The site describes these as **isolated-candidate implementation under
revalidation**, not production acceptance. G3 remains route-specific, G6 is
GREEN through the strict same-candidate ledger, and G7 is not accepted. The
old Phase-0 ADR statement that async serving was unimplemented is explicitly
labelled historical baseline material.

## Verification record

Completed locally in the clean documentation checkout:

- `npm run typecheck`: 96 files, 0 errors, 0 warnings, 0 hints.
- `npm run build`: 38 HTML routes, 36 indexed docs pages, sitemap, Pagefind,
  OpenGraph images, `llms.txt`, `llms-full.txt`, robots and Markdown/MDX views.
- `nimbus-docs lint`: 37 content files clean.
- `tools/docs-claim-audit.sh`: passed with native arm64 `rg`/Python in `PATH`.
- Generated internal link/anchor scan: one authored broken anchor was found and
  fixed; framework home/404 skip targets were fixed with `id="main-content"`.
- Public external link scan: OpenStack Swift is reachable. Peregrine GitHub
  routes return 404 without repository authorization, and both Drive folders
  redirect to Google sign-in; they are authenticated evidence links, not
  anonymous public artifacts.

Final post-change rebuild, commit, push, production deployment and live URL
checks are recorded in the parent task's release report after W070 and the
publication identity are frozen into the pages.

## Unverified and intentionally unclaimed

- Any G7 concurrency/fault acceptance result.
- G8 fairness, performance or 24-hour soak acceptance.
- A production rollout of the `17adf0b` release line.
- Newly built Linux binaries for the four auxiliary programs; the offline cache
  lacked `axum`, so the release bundle carries their source rather than claiming
  fresh auxiliary binaries.
- Anonymous public access to the private/authenticated GitHub and Drive evidence
  links.
