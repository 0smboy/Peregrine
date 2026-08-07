let meta = #{
    name: "impl-s3-versioning-surface",
    description: "Implement S3 versioning/tagging/lifecycle/object-lock subresource handlers",
    phases: [#{ title: "Implement" }, #{ title: "Test" }],
};
let root = if args == () { () } else { args.root };
if root == () { pause("verification", "Pass args.root"); }
phase("Implement");
let r = agent(
    "In " + root + "/swift-rust crates/swift-s3api implement MVP for:\n"
    + "- ?versioning GET/PUT (store Enabled|Suspended on container meta; return VersioningConfiguration XML)\n"
    + "- ?tagging GET/PUT/DELETE for bucket and object (store tags in sysmeta)\n"
    + "- ?lifecycle GET/PUT/DELETE (store raw XML in container meta)\n"
    + "- ?object-lock GET/PUT (store config XML on bucket)\n"
    + "Remove these from UNSUPPORTED_SUBRESOURCES 501 list.\n"
    + "Object versioning of data (multiple versions stored) may be residual if huge — document honestly but subresource API must not 501.\n"
    + "Evidence tools/test-results/impl-s3-versioning-surface-20260807/",
    #{ label: "s3-ver-impl", capability_mode: "all" });
phase("Test");
let t = agent(
    "cargo test -p swift-s3api; evidence to tools/test-results/impl-s3-versioning-surface-20260807/01-cargo-test.txt",
    #{ label: "s3-ver-test", capability_mode: "all" });
complete(#{ summary: "s3 versioning surface", ok: r.success && t.success });
