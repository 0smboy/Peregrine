let meta = #{
    name: "impl-lifecycle-transitions",
    description: "P0-4: Lifecycle Transition + AbortIncompleteMPU rules",
    phases: [#{ title: "Implement" }, #{ title: "StrictVerify" }],
};

let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root required"); }

phase("Implement");
let p = "";
p += "Workspace: " + root + "/swift-rust package swift-s3api.\n";
p += "TASK P0-4: Lifecycle Transitions + AbortIncompleteMultipartUpload.\n";
p += "Existing KEEP: Expiration Days/Date → X-Delete-At on PUT (lifecycle_exec.rs).\n";
p += "REQUIREMENTS:\n";
p += "1) Parse Enabled rules with <Transition><Days|Date><StorageClass> and optional Prefix/Filter.\n";
p += "2) On object PUT: if Transition matches and StorageClass present, stamp object meta e.g.\n";
p += "   X-Object-Meta-S3-Storage-Class and X-Object-Sysmeta-S3-Transition-At (unix) for observability.\n";
p += "   Do NOT fake tiering backends; document as metadata stamp (LAB-HARD-GREEN).\n";
p += "3) Parse AbortIncompleteMultipartUpload <DaysAfterInitiation> per Enabled rule+prefix.\n";
p += "4) Store abort rules accessible from mpu path: on InitiateMultipartUpload or Complete,\n";
p += "   if rule matches, stamp X-Delete-At on the upload marker / segments container object so expirer\n";
p += "   cleans incomplete MPUs (or stamp sysmeta X-Object-Sysmeta-S3-Abort-Mpu-Days for later).\n";
p += "   Prefer practical path: stamp X-Delete-At = now+Days*86400 on the multipart marker object when created.\n";
p += "5) Unit tests: parse Transition + AbortIncomplete from sample LifecycleConfiguration XML;\n";
p += "   apply transition meta on matching key; non-matching prefix skips; expiration still works.\n";
p += "6) Evidence: " + root + "/tools/test-results/impl-lifecycle-transitions-20260807/\n";
p += "7) cargo test -p swift-s3api pass. Update lib.rs residual list (remove Transition residual if KEEP).\n";
let r = agent(p, #{ label: "lifecycle-trans-impl", capability_mode: "all" });

phase("StrictVerify");
let v = "";
v += "Strict verify P0-4 in " + root + "/swift-rust:\n";
v += "cargo test -p swift-s3api lifecycle transition abort 2>&1 | tee "
    + root + "/tools/test-results/impl-lifecycle-transitions-20260807/cargo-test.txt\n";
v += "Full package. VERDICT KEEP only if parse+apply unit tests exist and pass.\n";
let t = agent(v, #{ label: "lifecycle-trans-verify", capability_mode: "all" });

complete(#{ ok: r.success && t.success, item: "P0-4-lifecycle-transitions" });
