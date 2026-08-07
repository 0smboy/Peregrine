let meta = #{
    name: "impl-listversions-pagination",
    description: "P1-2: ListVersions key-marker / version-id-marker fidelity",
    phases: [#{ title: "Implement" }, #{ title: "StrictVerify" }],
};

let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root required"); }

phase("Implement");
let p = "";
p += "Workspace: " + root + "/swift-rust package swift-s3api.\n";
p += "TASK P1-2: ListVersions pagination fidelity (key-marker, version-id-marker, max-keys).\n";
p += "Data plane EXISTS (versioning_store + handle_list_versions). Harden:\n";
p += "1) list_versions_result_xml applies markers correctly across multi-key indexes.\n";
p += "2) IsTruncated + NextKeyMarker + NextVersionIdMarker when max-keys cuts mid-list.\n";
p += "3) Unit tests: multi-key multi-version pagination; prefix filter; empty versions container.\n";
p += "4) Evidence: " + root + "/tools/test-results/impl-listversions-pagination-20260807/\n";
p += "5) cargo test -p swift-s3api --lib pass. Update parity if KEEP.\n";
let r = agent(p, #{ label: "listversions-impl", capability_mode: "all", isolation_worktree: true });

phase("StrictVerify");
let v = "";
v += "Strict verify P1-2 resume worktree. cargo test -p swift-s3api --lib | tee "
    + root + "/tools/test-results/impl-listversions-pagination-20260807/cargo-test.txt\n";
v += "SUMMARY.md VERDICT KEEP only if pagination unit tests exist and pass.\n";
let t = agent(v, #{ label: "listversions-verify", capability_mode: "all", isolation_worktree: true, resume_from: r.agent_id });

complete(#{ ok: r.success && t.success, item: "P1-2-listversions-pagination" });
