let meta = #{
    name: "impl-listobjects-s3cmd-xml",
    description: "P1-1: ListObjects XML Content-Type for s3cmd ls",
    phases: [#{ title: "Implement" }, #{ title: "StrictVerify" }],
};

let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root required"); }

phase("Implement");
let p = "";
p += "Workspace: " + root + "/swift-rust package swift-s3api.\n";
p += "TASK P1-1: Fix ListObjects v1/v2 XML so s3cmd `ls` parses (mb/put/get/del already OK).\n";
p += "Known issue: s3cmd list fails XML plain-text parse — check Content-Type application/xml,\n";
p += "namespace on ListBucketResult, encoding of keys, IsTruncated/Contents/CommonPrefixes shape\n";
p += "vs AWS/Python s3api. Use response.rs list_bucket_* builders + middleware list path.\n";
p += "REQUIREMENTS:\n";
p += "1) Ensure ListObjects and ListObjectsV2 responses use Content-Type: application/xml\n";
p += "   (or text/xml) consistently with other S3 XML responses.\n";
p += "2) Unit tests asserting Content-Type + root element + at least one Contents ETag quoted shape.\n";
p += "3) If s3cmd fails on unquoted ETag or missing xmlns, match Python s3api output shape.\n";
p += "4) Evidence: " + root + "/tools/test-results/impl-listobjects-s3cmd-xml-20260807/\n";
p += "5) cargo test -p swift-s3api --lib must pass. Minimal focused diff.\n";
let r = agent(p, #{ label: "listobjects-impl", capability_mode: "all", isolation_worktree: true });

phase("StrictVerify");
let v = "";
v += "Strict verify P1-1 same worktree (resume). Root " + root + ".\n";
v += "cargo test -p swift-s3api --lib 2>&1 | tee "
    + root + "/tools/test-results/impl-listobjects-s3cmd-xml-20260807/cargo-test.txt\n";
v += "Grep ListBucketResult Content-Type. SUMMARY.md with VERDICT + worktree path.\n";
let t = agent(v, #{ label: "listobjects-verify", capability_mode: "all", isolation_worktree: true, resume_from: r.agent_id });

complete(#{ ok: r.success && t.success, item: "P1-1-listobjects-s3cmd-xml" });
