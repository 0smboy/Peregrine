let meta = #{
    name: "residual-pipeline-account",
    description: "Paste unknown filter names + allow_account_management parity",
    phases: [
        #{ title: "Audit", detail: "pipeline skip vs hard-fail; account mgmt gate" },
        #{ title: "Implement", detail: "strict_pipeline conf + tests" },
        #{ title: "Verify", detail: "cargo test + evidence" },
    ],
    when_to_use: "Close unknown Paste filter residual and reaffirm allow_account_management",
};

let report_schema = #{
    "type": "object",
    "required": ["verdict", "summary", "evidence_path"],
    "properties": #{
        "verdict": #{ "type": "string" },
        "summary": #{ "type": "string" },
        "evidence_path": #{ "type": "string" },
        "strict_pipeline": #{ "type": "boolean" },
        "allow_account_management": #{ "type": "boolean" },
    },
};

let root = if args == () { () } else { args.root };
if root == () {
    pause("verification", "Pass args.root = absolute path to Peregrine monorepo.");
}

phase("Audit");
let audit = agent(
    "In " + root + "/swift-rust audit:\n"
        + "1) build_configured_filters unknown filter handling in swift-proxy-server main.rs\n"
        + "2) allow_account_management in ProxyConfig + account PUT/DELETE 405 gate\n"
        + "Report current behavior vs Python Paste (unknown filter typically fails pipeline load).",
    #{ label: "pipe-audit", capability_mode: "read-only" },
);

phase("Implement");
let impl_r = agent(
    "In " + root + "/swift-rust implement residual pipeline parity:\n"
        + "1) Add conf knob [app:proxy-server] strict_pipeline (or pipeline_strict) default false "
        + "for lab safety. When true, unknown filter names in [pipeline:main] cause startup "
        + "hard-fail (exit 1 after logging). When false, keep current skip+note behavior.\n"
        + "2) Unit tests: unknown filter with strict=true surfaces fatal note or error path; "
        + "strict=false still skips.\n"
        + "3) Reaffirm allow_account_management tests still pass; add live-style unit if missing.\n"
        + "4) Do not break Contabo default conf (strict off).\n"
        + "Minimal diff only.",
    #{ label: "pipe-impl", capability_mode: "all" },
);

phase("Verify");
let verify = agent(
    "In " + root + "/swift-rust run:\n"
        + "cargo test -p swift-proxy-server --lib -- --nocapture\n"
        + "Focus tests for allow_account_management and pipeline/strict.\n"
        + "Write tools/test-results/residual-pipeline-account-20260807/ "
        + "01-cargo-test.txt + SUMMARY.md.\n"
        + "Update RUST-VS-PYTHON-PARITY.md for unknown filter + allow_account_management rows.",
    #{ label: "pipe-verify", capability_mode: "all", output_schema: report_schema },
);

complete(#{
    summary: if verify != () && verify.success && verify.output.summary != () {
        verify.output.summary
    } else {
        "pipeline/account residual workflow finished"
    },
    audit_ok: audit != () && audit.success,
    impl_ok: impl_r != () && impl_r.success,
    verify: if verify != () && verify.success { verify.output } else { () },
});
