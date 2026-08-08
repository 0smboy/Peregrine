let meta = #{
    name: "hard9-slo-workers",
    description: "SLO concurrent/refetch + process_workers prefork",
    phases: [#{ title: "Verify" }],
};
let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root"); }
phase("Verify");
let p = "";
p += "Strict verify SLO + workers in " + root + "/swift-rust:\n";
p += "1) cargo test -p swift-middleware --lib slo:: refetch\n";
p += "2) cargo test -p swift-proxy-server --bin swift-proxy-server process_workers server_options\n";
p += "3) Confirm Slo concurrent_gets/yield_frequency fields; process_workers_from_conf; prefork_workers\n";
p += "Evidence hard9-residual-wave-20260808/slo-workers-SUMMARY.md\n";
let r = agent(p, #{ label: "slo-w-v", capability_mode: "all" });
complete(#{ ok: r.success, item: "slo-workers" });
