let meta = #{
    name: "impl-chunk-sig-enforce",
    description: "P0-1: enforce aws-chunked per-chunk HMAC signatures",
    phases: [#{ title: "Implement" }, #{ title: "StrictVerify" }],
};

let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root required (Peregrine path)"); }

phase("Implement");
let p = "";
p += "Workspace root: " + root + "\n";
p += "Crate: " + root + "/swift-rust (package swift-s3api).\n";
p += "TASK P0-1: Enforce STREAMING-AWS4-HMAC-SHA256-PAYLOAD per-chunk signatures.\n";
p += "Current state: decode_aws_chunked verifies when ChunkSigContext is set but middleware IGNORES\n";
p += "chunk_signatures_valid==Some(false) (see middleware dechunk residual comment).\n";
p += "REQUIREMENTS:\n";
p += "1) When X-Amz-Content-SHA256 is STREAMING-AWS4-HMAC-SHA256-PAYLOAD or *-TRAILER and\n";
p += "   ChunkSigContext is present: if any chunk-signature fails or is missing, return S3 error\n";
p += "   SignatureDoesNotMatch (HTTP 403) with Code=SignatureDoesNotMatch — do NOT forward body.\n";
p += "2) STREAMING-UNSIGNED-PAYLOAD-TRAILER must still dechunk without requiring signatures.\n";
p += "3) Keep ECDSA streaming as 501 NotImplemented.\n";
p += "4) Prefer adding AwsChunkedError::InvalidChunkSignature and map it in middleware; or check\n";
p += "   decoded.chunk_signatures_valid == Some(false) and error. Document in aws_chunked.rs + lib.rs\n";
p += "   that per-chunk sig is ENFORCED when signed streaming mode + credentials available.\n";
p += "5) Unit tests: (a) correctly signed multi-chunk body dechunks and PUT proceeds in middleware\n";
p += "   test if feasible; (b) bad chunk-signature → SignatureDoesNotMatch / decode error; (c)\n";
p += "   unsigned trailer still OK. Use crypto hmac helpers already in crate.\n";
p += "6) Evidence dir: " + root + "/tools/test-results/impl-chunk-sig-enforce-20260807/\n";
p += "   Write SUMMARY.md with files changed + cargo output excerpt.\n";
p += "7) Do NOT touch SigV2 WONTFIX. Minimal focused diff.\n";
p += "Implement fully; run cargo test -p swift-s3api and fix failures.\n";
let r = agent(p, #{ label: "chunk-sig-impl", capability_mode: "all" });

phase("StrictVerify");
let v = "";
v += "Strict verify P0-1 in " + root + "/swift-rust:\n";
v += "1) cargo test -p swift-s3api 2>&1 | tee " + root + "/tools/test-results/impl-chunk-sig-enforce-20260807/cargo-test.txt\n";
v += "2) rg -n 'chunk_signatures_valid|InvalidChunkSignature|SignatureDoesNotMatch' crates/swift-s3api/src/\n";
v += "3) Confirm middleware no longer ignores Some(false). Fail closed if residual remains.\n";
v += "4) Append VERDICT: KEEP|FAIL to SUMMARY.md with test counts.\n";
v += "Return verdict string and key evidence paths.\n";
let t = agent(v, #{ label: "chunk-sig-verify", capability_mode: "all" });

complete(#{
    ok: r.success && t.success,
    item: "P0-1-chunk-sig-enforce",
    impl_ok: r.success,
    verify_ok: t.success,
});
