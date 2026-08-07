let meta = #{
    name: "residual-s3-surface",
    description: "S3 residual surface: IAM ACL, multi-rule CORS, SigV2, aws-chunked, versioning",
    phases: [
        #{ title: "Audit", detail: "map implemented vs WONTFIX" },
        #{ title: "Verify", detail: "unit tests + stable 501" },
        #{ title: "Close", detail: "evidence + parity honesty" },
    ],
    when_to_use: "Close S3 residual matrix rows (implement or WONTFIX with tests)",
};

let report_schema = #{
    "type": "object",
    "required": ["verdict", "summary", "evidence_path"],
    "properties": #{
        "verdict": #{ "type": "string" },
        "summary": #{ "type": "string" },
        "evidence_path": #{ "type": "string" },
        "wontfix": #{ "type": "array", "items": #{ "type": "string" } },
        "keep": #{ "type": "array", "items": #{ "type": "string" } },
    },
};

let root = if args == () { () } else { args.root };
if root == () {
    pause("verification", "Pass args.root = absolute path to Peregrine monorepo.");
}

phase("Audit");
let audit = agent(
    "In " + root + "/swift-rust audit S3 residuals in crates/swift-s3api:\n"
        + "- full IAM / grant-header ACL vs canned ACL\n"
        + "- multi-rule CORS\n"
        + "- SigV2 (expect WONTFIX 501)\n"
        + "- aws-chunked (expect WONTFIX 501)\n"
        + "- versioning (expect WONTFIX 501)\n"
        + "Read lib.rs and middleware.rs module docs + tests. List exact status.",
    #{ label: "s3-audit", capability_mode: "read-only" },
);

phase("Verify");
let verify = agent(
    "In " + root + "/swift-rust:\n"
        + "1) cargo test -p swift-s3api -- --nocapture\n"
        + "2) Confirm SigV2 / aws-chunked / versioning return stable 501 with unit coverage; "
        + "if missing tests, add minimal unit tests for 501 paths.\n"
        + "3) Confirm multi-rule CORS test passes; if broken, fix.\n"
        + "4) Full IAM grant-header ACL: if not implemented, document residual honestly "
        + "(do NOT falsely claim KEEP). Optional: only if small, improve canned ACL docs.\n"
        + "5) Write tools/test-results/residual-s3-surface-20260807/01-cargo-test.txt + SUMMARY.md\n"
        + "6) Refresh RUST-VS-PYTHON-PARITY.md S3 rows to match reality.",
    #{ label: "s3-verify", capability_mode: "all", output_schema: report_schema },
);

phase("Close");
complete(#{
    summary: if verify != () && verify.success && verify.output.summary != () {
        verify.output.summary
    } else {
        "S3 residual workflow finished (check agent output)"
    },
    audit_ok: audit != () && audit.success,
    verify: if verify != () && verify.success { verify.output } else { () },
});
