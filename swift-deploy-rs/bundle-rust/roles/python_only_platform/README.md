# python_only_platform (docs mapping)

Platform roles present in Python ansible-v3 but **absent** from bundle-rust.

| Python role | Play / hosts | Notes |
|-------------|--------------|-------|
| `chrony` | `ntp_server`, `ntp_clients` on `swift.yml` | Inventory groups may exist empty for rust validation |
| `performance_tuning` | `performance_tuning` group | limits + sysctl |
| `security` | end of `swift.yml` | sshd bind + firewall — high risk on Contabo |
| `system_tuning` | `system_tuning_deploy.yml` | file-driven tuning |

## Guidance

- Prefer OOB or dedicated Python playbooks with **narrow host groups**.
- Do not run full Python `swift.yml` against Contabo rust data disks (format_disks + security side effects).
- NTP: manage outside rust apply if needed; rust does not configure chrony.

Matrix: [ANSIBLE-V3-SURFACE.md](../../../../docs/fairness-lab/ANSIBLE-V3-SURFACE.md).
