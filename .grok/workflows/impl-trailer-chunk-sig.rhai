let meta = #{
    name: "impl-trailer-chunk-sig",
    description: "P1-3: STREAMING trailer / x-amz-trailer-signature residual",
    phases: [#{ title: "Implement" }, #{ title: "StrictVerify" }],
};

let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root required"); }

phase("Implement");
let p = "";
p += "Workspace: " + root + "/swift-rust package swift-s3api.\n";
p += "TASK P1-3: Trailer signature residual for STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER.\n";
p += "Chunk body sigs are already ENFORCED (P0-1). Extend:\n";
p += "1) When mode is *-PAYLOAD-TRAILER and trailers present, verify trailer signature if\n";
p += "   x-amz-trailer-signature (or AWS trailer chain) is present; fail SignatureDoesNotMatch.\n";
p += "2) If unsigned trailer mode STREAMING-UNSIGNED-PAYLOAD-TRAILER, accept trailers without HMAC.\n";
p += "3) Unit tests for signed trailer success + bad trailer sig fail; unsigned still OK.\n";
p += "4) Document residual if full AWS trailer string-to-sign vector unavailable — at minimum\n";
p += "   reject clearly invalid trailer sig when signed mode.\n";
p += "5) Evidence: " + root + "/tools/test-results/impl-trailer-chunk-sig-20260807/\n";
p += "6) cargo test -p swift-s3api --lib pass.\n";
let r = agent(p, #{ label: "trailer-impl", capability_mode: "all", isolation_worktree: true });

phase("StrictVerify");
let v = "";
v += "Strict verify P1-3. cargo test -p swift-s3api --lib | tee "
    + root + "/tools/test-results/impl-trailer-chunk-sig-20260807/cargo-test.txt\n";
v += "SUMMARY.md VERDICT + worktree path.\n";
let t = agent(v, #{ label: "trailer-verify", capability_mode: "all", isolation_worktree: true, resume_from: r.agent_id });

complete(#{ ok: r.success && t.success, item: "P1-3-trailer-chunk-sig" });
