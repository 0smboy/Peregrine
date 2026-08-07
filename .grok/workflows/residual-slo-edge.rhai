let meta = #{
    name: "residual-slo-edge",
    description: "SLO edge residuals: inline data, heartbeat PUT, multipart-manifest=delete (sync+async)",
    phases: [
        #{ title: "Audit", detail: "locate code + tests" },
        #{ title: "Verify", detail: "cargo test SLO edge suite" },
        #{ title: "Evidence", detail: "write test-results + parity note" },
    ],
    when_to_use: "Close or prove SLO inline/heartbeat/multipart-delete residuals",
};

let report_schema = #{
    "type": "object",
    "required": ["verdict", "summary", "evidence_path"],
    "properties": #{
        "verdict": #{ "type": "string" },
        "summary": #{ "type": "string" },
        "evidence_path": #{ "type": "string" },
        "tests_passed": #{ "type": "boolean" },
        "gaps": #{ "type": "array", "items": #{ "type": "string" } },
    },
};

let root = if args == () { () } else { args.root };
if root == () {
    pause("verification", "Pass args.root = absolute path to Peregrine monorepo (or swift-rust).");
}

phase("Audit");
let audit = agent(
    "In repo " + root + " audit SLO edge features under swift-rust:\n"
        + "1) inline data segment on SLO PUT/GET\n"
        + "2) heartbeat=on multipart-manifest=put (202 + whitespace stream)\n"
        + "3) multipart-manifest=delete sync and async=yes\n"
        + "Use grep/read_file on crates/swift-middleware/src/slo.rs and tests. "
        + "List existing unit tests by name. Report gaps only if code or tests missing. "
        + "Do not claim production-go-live.",
    #{ label: "slo-audit", capability_mode: "read-only" },
);

phase("Verify");
let verify = agent(
    "In repo " + root + " (swift-rust workspace):\n"
        + "Run: cargo test -p swift-middleware --lib slo:: -- --nocapture\n"
        + "Also run any integration tests that mention multipart-manifest=delete or heartbeat if present.\n"
        + "If a real bug is found, fix it with minimal code and re-run tests.\n"
        + "Write evidence under tools/test-results/residual-slo-edge-20260807/ "
        + "(01-cargo-test.txt + SUMMARY.md with VERDICT KEEP or PARTIAL).\n"
        + "Update docs/fairness-lab/RUST-VS-PYTHON-PARITY.md only if status changes.\n"
        + "Canonical code path: Peregrine/swift-rust. Working tree may be " + root + ".",
    #{ label: "slo-verify", capability_mode: "all", output_schema: report_schema },
);

phase("Evidence");
let summary = "SLO edge workflow finished";
if verify != () && verify.success && verify.output.summary != () {
    summary = verify.output.summary;
}
complete(#{
    summary: summary,
    audit_ok: audit != () && audit.success,
    verify: if verify != () && verify.success { verify.output } else { () },
});
