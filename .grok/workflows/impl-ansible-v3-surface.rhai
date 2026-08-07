let meta = #{
    name: "impl-ansible-v3-surface",
    description: "Close Full ansible v3 surface gap vs Python bundle",
    phases: [#{ title: "Inventory" }, #{ title: "Expand" }, #{ title: "Evidence" }],
};
let root = if args == () { () } else { args.root };
if root == () { pause("verification", "Pass args.root"); }
phase("Inventory");
let a = agent(
    "In " + root + " compare swift-deploy-rs/bundle (Python ansible v3) vs bundle-rust roles and swift.yml. Produce a complete role/play matrix.",
    #{ label: "ans-inv", capability_mode: "read-only" });
phase("Expand");
let e = agent(
    "In " + root + " expand ansible surface for Rust stack:\n"
    + "1) Write docs/fairness-lab/ANSIBLE-V3-SURFACE.md with full role matrix (Python | Rust | status)\n"
    + "2) Add any missing bundle-rust plays that map to already-implemented features (identity optional include, monitoring tags, expand)\n"
    + "3) Where Python-only (Keystone install, format_disks wipe): document as optional import/include_role or deferred with explicit when:\n"
    + "4) Do not wipe Contabo disks. Dual-guard.\n"
    + "5) Evidence tools/test-results/impl-ansible-v3-surface-20260807/",
    #{ label: "ans-expand", capability_mode: "all" });
complete(#{ summary: "ansible surface", ok: e.success });
