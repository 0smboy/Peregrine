let meta = #{
    name: "impl-slo-expirer-hash",
    description: "Implement SLO async-delete expirer hash_path sharding + ACL probes",
    phases: [#{ title: "Implement" }, #{ title: "Test" }, #{ title: "Evidence" }],
};
let root = if args == () { () } else { args.root };
if root == () { pause("verification", "Pass args.root"); }
phase("Implement");
let r = agent(
    "In " + root + "/swift-rust implement Python parity for SLO async delete:\n"
    + "1) expirer task container = day_bucket - (hash_path(acc,cont,obj)%100) per Python ExpirerConfig.get_expirer_container\n"
    + "2) ACL probes: authorize write on manifest container and segment container (HEAD/info + deny 401/403)\n"
    + "3) Unit tests for hash sharding (known vectors) and ACL deny path\n"
    + "4) Update module docs; remove Deferred notes for these items when done\n"
    + "Files: crates/swift-middleware/src/slo.rs, HashPathConfig from swift-core.\n"
    + "Write evidence tools/test-results/impl-slo-expirer-hash-20260807/",
    #{ label: "slo-impl", capability_mode: "all" });
phase("Test");
let t = agent(
    "In " + root + "/swift-rust run cargo test -p swift-middleware --lib slo:: and fix failures. Append output to tools/test-results/impl-slo-expirer-hash-20260807/01-cargo-test.txt",
    #{ label: "slo-test", capability_mode: "all" });
complete(#{ summary: "slo expirer hash done", ok: r.success && t.success });
