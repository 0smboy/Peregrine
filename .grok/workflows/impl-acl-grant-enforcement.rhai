let meta = #{
    name: "impl-acl-grant-enforcement",
    description: "P1-4: S3 ACP grant enforcement on object GET/PUT subset",
    phases: [#{ title: "Implement" }, #{ title: "StrictVerify" }],
};

let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root required"); }

phase("Implement");
let p = "";
p += "Workspace: " + root + "/swift-rust package swift-s3api.\n";
p += "TASK P1-4: ACP grant **enforcement** residual (store/GET already KEEP).\n";
p += "LAB-HARD-GREEN scope (not full IAM):\n";
p += "1) On object GET/HEAD: if object has S3_OBJECT_ACL_JSON_META grants and request principal\n";
p += "   (cred access_key / account id) is not owner and not granted READ/FULL_CONTROL → AccessDenied.\n";
p += "2) Owner always allowed. Empty/missing grants → existing canned/Swift path (no new denials).\n";
p += "3) AllUsers READ grants still do NOT open anonymous unauthenticated path (document residual).\n";
p += "4) Unit middleware tests with mock next(): private object + foreign principal denied;\n";
p += "   grant READ to principal id allowed; owner always OK.\n";
p += "5) Evidence: " + root + "/tools/test-results/impl-acl-grant-enforcement-20260807/\n";
p += "6) cargo test -p swift-s3api --lib pass. Update lib.rs residual notes.\n";
let r = agent(p, #{ label: "acl-enforce-impl", capability_mode: "all", isolation_worktree: true });

phase("StrictVerify");
let v = "";
v += "Strict verify P1-4. cargo test -p swift-s3api --lib | tee "
    + root + "/tools/test-results/impl-acl-grant-enforcement-20260807/cargo-test.txt\n";
v += "SUMMARY.md VERDICT KEEP|PARTIAL|FAIL + worktree path.\n";
let t = agent(v, #{ label: "acl-enforce-verify", capability_mode: "all", isolation_worktree: true, resume_from: r.agent_id });

complete(#{ ok: r.success && t.success, item: "P1-4-acl-grant-enforcement" });
