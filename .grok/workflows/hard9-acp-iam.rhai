let meta = #{
    name: "hard9-acp-iam",
    description: "ACP store/enforce + IAM identity directory",
    phases: [#{ title: "Verify" }],
};
let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root"); }
phase("Verify");
let p = "";
p += "Strict verify ACP+IAM in " + root + "/swift-rust:\n";
p += "cargo test -p swift-s3api --lib iam object_grants acl grant acp\n";
p += "Confirm object_acl_denies_write wired on PUT/DELETE; IAM email map; store/GET ACP.\n";
p += "Evidence hard9-residual-wave-20260808/acp-iam-SUMMARY.md\n";
let r = agent(p, #{ label: "acp-iam-v", capability_mode: "all" });
complete(#{ ok: r.success, item: "acp-iam" });
