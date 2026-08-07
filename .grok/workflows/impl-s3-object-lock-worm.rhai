let meta = #{
    name: "impl-s3-object-lock-worm",
    description: "Object Lock WORM: retention + legal-hold enforce on DELETE",
    phases: [#{ title: "Implement" }, #{ title: "StrictVerify" }],
};
let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root required"); }
phase("Implement");
let r = agent(
    "In " + root + "/swift-rust implement object-lock WORM enforcement:\n"
    + "1) Object subresources: ?legal-hold GET/PUT, ?retention GET/PUT storing sysmeta\n"
    + "2) On DELETE object: if legal-hold ON or retain-until-date in future → 403 AccessDenied (AccessDenied XML)\n"
    + "3) Bypass only with residual documented (none by default)\n"
    + "4) PUT object may stamp default retention from bucket ObjectLockConfiguration if present\n"
    + "5) Unit tests: set legal-hold → DELETE 403; set retention future → DELETE 403; after release → DELETE ok\n"
    + "Evidence tools/test-results/impl-s3-object-lock-worm-20260807/\n"
    + "cargo test -p swift-s3api must pass.",
    #{ label: "worm-impl", capability_mode: "all" });
phase("StrictVerify");
let t = agent(
    "cargo test -p swift-s3api legal_hold retention worm lock in " + root + "/swift-rust; full package; evidence.",
    #{ label: "worm-test", capability_mode: "all" });
complete(#{ ok: r.success && t.success, summary: "worm" });
