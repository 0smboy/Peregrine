let meta = #{
    name: "impl-grant-acp-acl",
    description: "P0-3: S3 grant-header + AccessControlPolicy ACL body",
    phases: [#{ title: "Implement" }, #{ title: "StrictVerify" }],
};

let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root required"); }

phase("Implement");
let p = "";
p += "Workspace: " + root + "/swift-rust package swift-s3api.\n";
p += "TASK P0-3: Grant-header + ACP XML ACL beyond canned x-amz-acl.\n";
p += "Current: canned only (private/public-read/…) via S3_OBJECT_ACL_META and container Read/Write.\n";
p += "REQUIREMENTS (LAB-HARD-GREEN scope — not full IAM identity service):\n";
p += "1) Parse PUT object/bucket ?acl body AccessControlPolicy XML into structured grants\n";
p += "   (Grantee ID/URI + Permission FULL_CONTROL|READ|WRITE|READ_ACP|WRITE_ACP).\n";
p += "2) Store grants as compact JSON or XML in sysmeta:\n";
p += "   object: X-Object-Sysmeta-S3-Acl-Json (or extend meta without breaking canned GET ?acl)\n";
p += "   bucket: map AllUsers READ/WRITE to X-Container-Read/Write; store full policy meta for GET.\n";
p += "3) Headers x-amz-grant-read, x-amz-grant-write, x-amz-grant-full-control, x-amz-grant-read-acp,\n";
p += "   x-amz-grant-write-acp: parse 'id=...,uri=http://acs.amazonaws.com/groups/global/AllUsers,emailAddress=...'\n";
p += "   list form (comma-separated grantees) and merge into same grant store on PUT object/bucket ACL.\n";
p += "4) GET ?acl reconstructs AccessControlPolicy from stored grants; if only canned meta present, keep existing path.\n";
p += "5) Canned x-amz-acl continues to work and takes precedence if both present (document order: canned first or AWS-like).\n";
p += "6) Unit tests: ACP body round-trip; grant-read AllUsers → public-read-like container headers;\n";
p += "   object ACP JSON store + GET acl XML contains Grant/Permission.\n";
p += "7) Do NOT implement anonymous unauthenticated GET authorization rewire (document residual).\n";
p += "8) Evidence: " + root + "/tools/test-results/impl-grant-acp-acl-20260807/\n";
p += "9) cargo test -p swift-s3api pass; update acl_cors module docs + lib.rs residuals.\n";
let r = agent(p, #{ label: "grant-acp-impl", capability_mode: "all" });

phase("StrictVerify");
let v = "";
v += "Strict verify P0-3 in " + root + "/swift-rust:\n";
v += "cargo test -p swift-s3api acl grant acp 2>&1 | tee "
    + root + "/tools/test-results/impl-grant-acp-acl-20260807/cargo-test.txt\n";
v += "Full package test. Grep for AccessControlPolicy parse + grant header apply. VERDICT KEEP|PARTIAL|FAIL.\n";
let t = agent(v, #{ label: "grant-acp-verify", capability_mode: "all" });

complete(#{ ok: r.success && t.success, item: "P0-3-grant-acp-acl" });
