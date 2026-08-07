let meta = #{
    name: "impl-ansible-v3-twin",
    description: "Ansible full v3 twin: every Python role reachable from rust stack path",
    phases: [#{ title: "Implement" }, #{ title: "StrictVerify" }],
};
let root = if args == () { () } else { args.root };
if root == () { pause("verification", "args.root required"); }
phase("Implement");
let r = agent(
    "In " + root + "/swift-deploy-rs create FULL ansible v3 twin path:\n"
    + "1) bundle-rust/swift-full-v3.yml playbook that covers EVERY role from bundle/swift.yml\n"
    + "   - For roles with rust equivalent: use rust role\n"
    + "   - For ABSENT roles: include from ../bundle/roles via roles_path or symlink/import\n"
    + "2) ansible.cfg in bundle-rust roles_path = roles:../bundle/roles\n"
    + "3) Default Contabo path stays swift.yml (safe); full twin is opt-in swift-full-v3.yml\n"
    + "4) Dual-guard: format_disks only when allow_disk_format=true (default false)\n"
    + "5) Update ANSIBLE-V3-SURFACE.md: claim FULL TWIN PATH available (opt-in), default still PARTIAL\n"
    + "6) Evidence tools/test-results/impl-ansible-v3-twin-20260807/ with role coverage 26/26 checklist\n"
    + "7) Run swift-deploy plan if binary available for both playbooks (no apply to Contabo wipe)",
    #{ label: "ans-twin", capability_mode: "all" });
phase("StrictVerify");
let t = agent(
    "Verify every Python bundle role name appears in full-v3 playbook or matrix DONE/INCLUDED. "
    + "Evidence SUMMARY with 26/26 table. Fail if any role missing.",
    #{ label: "ans-verify", capability_mode: "all" });
complete(#{ ok: r.success && t.success, summary: "ansible-twin" });
