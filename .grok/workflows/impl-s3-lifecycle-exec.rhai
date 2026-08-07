let meta = #{
    name: "impl-s3-lifecycle-exec",
    description: "Execute S3 lifecycle Expiration rules (Days/Date) via delete-at / expirer",
    phases: [#{ title: "Implement" }, #{ title: "StrictVerify" }],
};
let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root required"); }
phase("Implement");
let r = agent(
    "In " + root + "/swift-rust implement lifecycle EXECUTION (not just store XML):\n"
    + "1) Parse LifecycleConfiguration for Rule with Status Enabled and Expiration Days or Date\n"
    + "2) On object PUT (and optional apply helper): if bucket has lifecycle meta matching Prefix, set X-Delete-At = now+Days*86400 or Date\n"
    + "3) Unit tests: rule Days=1 → X-Delete-At header present on translated PUT; Prefix filter; Disabled rule ignored\n"
    + "4) Pure functions in bucket_config or new lifecycle.rs for compute_delete_at\n"
    + "5) Evidence tools/test-results/impl-s3-lifecycle-exec-20260807/\n"
    + "cargo test -p swift-s3api must pass.",
    #{ label: "lc-impl", capability_mode: "all" });
phase("StrictVerify");
let t = agent(
    "cargo test -p swift-s3api lifecycle in " + root + "/swift-rust; full package test; evidence SUMMARY.",
    #{ label: "lc-test", capability_mode: "all" });
complete(#{ ok: r.success && t.success, summary: "lifecycle-exec" });
