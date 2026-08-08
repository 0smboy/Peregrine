let meta = #{
    name: "hard9-lifecycle-transition",
    description: "Lifecycle Transition cold-class GET block + restore",
    phases: [#{ title: "Verify" }],
};
let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root"); }
phase("Verify");
let p = "";
p += "Strict verify lifecycle Transition execution in " + root + "/swift-rust:\n";
p += "cargo test -p swift-s3api --lib cold_transition apply_due lifecycle\n";
p += "Confirm transition_blocks_get, apply_restore_days, GET InvalidObjectState path.\n";
p += "Evidence " + root + "/tools/test-results/hard9-residual-wave-20260808/lifecycle-SUMMARY.md\n";
let r = agent(p, #{ label: "lc-trans-v", capability_mode: "all" });
complete(#{ ok: r.success, item: "lifecycle-transition" });
