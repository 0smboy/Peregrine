let meta = #{
    name: "impl-worm-governance-bypass",
    description: "P0-2: Object Lock x-amz-bypass-governance-retention",
    phases: [#{ title: "Implement" }, #{ title: "StrictVerify" }],
};

let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root required"); }

phase("Implement");
let p = "";
p += "Workspace: " + root + "/swift-rust package swift-s3api.\n";
p += "TASK P0-2: Implement Object Lock governance bypass.\n";
p += "Files: object_lock_worm.rs, middleware.rs (worm_check_object / worm_blocks_key / DELETE path).\n";
p += "REQUIREMENTS (AWS semantics):\n";
p += "1) Header x-amz-bypass-governance-retention: true|True|1 allows bypass ONLY when\n";
p += "   lock mode is GOVERNANCE and retain-until is the only block reason.\n";
p += "2) COMPLIANCE mode MUST NOT be bypassed.\n";
p += "3) Legal-hold ON MUST NOT be bypassed by this header.\n";
p += "4) Without header: existing worm_blocks_delete behavior unchanged.\n";
p += "5) API design: extend worm_blocks_delete or add worm_blocks_delete_with_bypass(headers, now, bypass_governance: bool)\n";
p += "   and worm_allows_operation(...). Wire middleware to read request header on DELETE and overwrite PUT.\n";
p += "6) Unit tests covering: governance+bypass→allow; compliance+bypass→deny; legal-hold+bypass→deny;\n";
p += "   governance without bypass→deny; expired retain→allow.\n";
p += "7) Evidence: " + root + "/tools/test-results/impl-worm-governance-bypass-20260807/SUMMARY.md\n";
p += "8) cargo test -p swift-s3api must pass. Update lib.rs residual notes: bypass IMPLEMENTED for GOVERNANCE.\n";
let r = agent(p, #{ label: "worm-bypass-impl", capability_mode: "all" });

phase("StrictVerify");
let v = "";
v += "Strict verify P0-2 in " + root + "/swift-rust:\n";
v += "cargo test -p swift-s3api worm bypass governance 2>&1 | tee "
    + root + "/tools/test-results/impl-worm-governance-bypass-20260807/cargo-test.txt\n";
v += "Then full: cargo test -p swift-s3api. Confirm middleware reads x-amz-bypass-governance-retention.\n";
v += "VERDICT KEEP only if unit tests prove COMPLIANCE/legal-hold still blocked.\n";
let t = agent(v, #{ label: "worm-bypass-verify", capability_mode: "all" });

complete(#{ ok: r.success && t.success, item: "P0-2-worm-governance-bypass" });
