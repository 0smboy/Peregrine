let meta = #{
    name: "impl-aws-chunked",
    description: "Implement aws-chunked / STREAMING-* body decode for S3 PUT",
    phases: [#{ title: "Implement" }, #{ title: "Test" }],
};
let root = if args == () { () } else { args.root };
if root == () { pause("verification", "Pass args.root"); }
phase("Implement");
let r = agent(
    "In " + root + "/swift-rust crates/swift-s3api IMPLEMENT (not WONTFIX) aws-chunked:\n"
    + "1) Decode aws-chunked framing into raw body for PUT/POST with Content-Encoding aws-chunked or X-Amz-Content-SHA256 STREAMING-*\n"
    + "2) STREAMING-UNSIGNED-PAYLOAD-TRAILER: dechunk without signature verify\n"
    + "3) STREAMING-AWS4-HMAC-SHA256-PAYLOAD: dechunk; optional signature verify residual ok if dechunk works\n"
    + "4) Remove early 501 for these; update tests that expected 501 to expect success decode\n"
    + "5) Evidence tools/test-results/impl-aws-chunked-20260807/",
    #{ label: "chunked-impl", capability_mode: "all" });
phase("Test");
let t = agent(
    "cargo test -p swift-s3api in " + root + "/swift-rust; capture to tools/test-results/impl-aws-chunked-20260807/01-cargo-test.txt",
    #{ label: "chunked-test", capability_mode: "all" });
complete(#{ summary: "aws-chunked", ok: r.success && t.success });
