let meta = #{
    name: "residual-workers-semantics",
    description: "eventlet multi-process workers semantic mapping / ISO-CONFIG tooling",
    phases: [
        #{ title: "Audit", detail: "Python vs Rust workers mapping" },
        #{ title: "Verify", detail: "effective_concurrency tests + docs" },
        #{ title: "Close", detail: "parity honesty + evidence" },
    ],
    when_to_use: "Close or document workers semantic residual for fairness lab",
};

let report_schema = #{
    "type": "object",
    "required": ["verdict", "summary", "evidence_path"],
    "properties": #{
        "verdict": #{ "type": "string" },
        "summary": #{ "type": "string" },
        "evidence_path": #{ "type": "string" },
        "process_model_equivalent": #{ "type": "boolean" },
        "iso_config_tooling": #{ "type": "boolean" },
    },
};

let root = if args == () { () } else { args.root };
if root == () {
    pause("verification", "Pass args.root = absolute path to Peregrine monorepo.");
}

phase("Audit");
let audit = agent(
    "In " + root + " read docs/fairness-lab/WORKERS-SEMANTICS.md and "
        + "swift-rust crates for workers/max_clients/servers_per_port mapping "
        + "(proxy, account, container, object). Explain what is equivalent vs not "
        + "vs Python eventlet prefork. No false equivalence claims.",
    #{ label: "workers-audit", capability_mode: "read-only" },
);

phase("Verify");
let verify = agent(
    "In " + root + "/swift-rust:\n"
        + "1) cargo test -p swift-object-server effective_concurrency -- --nocapture\n"
        + "2) If swift-effective-concurrency binary builds, run a few CLI samples and capture output.\n"
        + "3) Optionally strengthen unit tests if mapping edge cases missing (workers=0, spp>0).\n"
        + "4) Do NOT rewrite the whole server to true eventlet prefork — that is out of scope; "
        + "document residual honestly if process model remains non-equivalent for proxy path.\n"
        + "5) Write tools/test-results/residual-workers-semantics-20260807/ "
        + "01-cargo-test.txt + SUMMARY.md.\n"
        + "6) Update RUST-VS-PYTHON-PARITY.md workers row: tooling GREEN / process model residual.",
    #{ label: "workers-verify", capability_mode: "all", output_schema: report_schema },
);

phase("Close");
complete(#{
    summary: if verify != () && verify.success && verify.output.summary != () {
        verify.output.summary
    } else {
        "workers semantics workflow finished"
    },
    audit_ok: audit != () && audit.success,
    verify: if verify != () && verify.success { verify.output } else { () },
});
