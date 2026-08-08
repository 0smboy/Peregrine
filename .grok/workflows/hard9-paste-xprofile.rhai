let meta = #{
    name: "hard9-paste-xprofile",
    description: "Paste full names + xprofile + list_endpoints verify",
    phases: [#{ title: "Verify" }],
};
let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root"); }
phase("Verify");
let p = "";
p += "In " + root + "/swift-rust run STRICT verify for Paste+xprofile:\n";
p += "1) cargo test -p swift-middleware --lib xprofile list_endpoints passthrough\n";
p += "2) cargo test -p swift-proxy-server --bin swift-proxy-server pipeline\n";
p += "3) Confirm build_configured_filters wires xprofile, list_endpoints, NamedPassthrough for catch_errors/gatekeeper/healthcheck/memcache/recon\n";
p += "4) Write " + root + "/tools/test-results/hard9-residual-wave-20260808/paste-xprofile-SUMMARY.md with VERDICT KEEP|FAIL\n";
let r = agent(p, #{ label: "paste-xp-v", capability_mode: "all" });
complete(#{ ok: r.success, item: "paste-xprofile" });
