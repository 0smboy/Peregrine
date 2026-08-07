let meta = #{
    name: "impl-s3-multiversion-data",
    description: "S3 multi-version object data plane (versionId PUT/GET/DELETE/list/delete-marker)",
    phases: [#{ title: "Implement" }, #{ title: "StrictVerify" }],
};
let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root required"); }
phase("Implement");
let r = agent(
    "In " + root + "/swift-rust implement S3 multi-version OBJECT data plane in crates/swift-s3api:\n"
    + "When bucket versioning=Enabled:\n"
    + "1) PUT object: generate version_id; archive previous current to versions store; store new current with X-Amz-Version-Id response header; persist version index\n"
    + "2) GET/HEAD ?versionId= : fetch that version; missing → NoSuchVersion\n"
    + "3) DELETE without versionId: create delete-marker as current; archive prior\n"
    + "4) DELETE ?versionId=: remove that version; if current, promote/null appropriately\n"
    + "5) GET ?versions: ListVersionsResult with Version + DeleteMarker entries from store\n"
    + "Storage: use sidecar container `{bucket}+versions` object names `{hexkey}/{version_id}` + sysmeta on current for version-id and is-delete-marker\n"
    + "When Suspended/unconfigured: keep null version behavior (single object).\n"
    + "Strict unit tests covering PUT x2 → two versions, GET versionId, list versions, delete-marker, delete versionId.\n"
    + "Evidence: tools/test-results/impl-s3-multiversion-data-20260807/\n"
    + "cargo test -p swift-s3api must pass 100%.",
    #{ label: "mv-impl", capability_mode: "all" });
phase("StrictVerify");
let t = agent(
    "In " + root + "/swift-rust: cargo test -p swift-s3api -- --nocapture; "
    + "cargo test -p swift-s3api version -- --nocapture; "
    + "Write 01-cargo-test.txt + SUMMARY with claim boundaries. Fail if any test fails.",
    #{ label: "mv-test", capability_mode: "all" });
complete(#{ ok: r.success && t.success, summary: "multiversion" });
