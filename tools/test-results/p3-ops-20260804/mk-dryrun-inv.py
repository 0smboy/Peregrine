#!/usr/bin/env python3
"""Build a temporary inventory for P3-ops plan dry-run."""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BUNDLE = ROOT / "swift-deploy-rs" / "bundle-rust"
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/p3-ops-inv")

OUT.mkdir(parents=True, exist_ok=True)
(OUT / "group_vars").mkdir(exist_ok=True)
(OUT / "host_vars").mkdir(exist_ok=True)

(OUT / "swift_hosts").write_text(
    """[proxy_servers]
10.88.0.11
10.88.0.12
10.88.0.13

[account_servers]
10.88.0.11
10.88.0.12
10.88.0.13

[container_servers]
10.88.0.11
10.88.0.12
10.88.0.13

[object_servers]
10.88.0.11
10.88.0.12
10.88.0.13

[storage_nodes:children]
account_servers
container_servers
object_servers

[haproxy_servers]
10.88.0.11
10.88.0.12
10.88.0.13

[keepalived_servers]
10.88.0.11
10.88.0.12
10.88.0.13

[mariadb_servers]

[keystones]

[ntp_server]
10.88.0.11

[ntp_clients]
10.88.0.12
10.88.0.13

[all:vars]
ansible_user=root
"""
)

text = (BUNDLE / "config_sample" / "group_vars" / "all").read_text()
text = text.replace("use_lb: false", "use_lb: true")
text = text.replace("lb_mode: http", "lb_mode: https")
text = text.replace("auth_url_ip: 10.0.0.11", "auth_url_ip: 10.88.20.100")
(OUT / "group_vars" / "all").write_text(text)

nodes = [
    ("10.88.0.11", 1, 1, ["d1"]),
    ("10.88.0.12", 1, 2, ["d1", "d2"]),
    ("10.88.0.13", 2, 1, ["d1"]),
]
for ip, region, zone, devices in nodes:
    stor = ip.replace("10.88.0.", "10.88.10.")
    biz = ip.replace("10.88.0.", "10.88.20.")
    devices_yaml = "\n".join(f"  - {d}" for d in devices)
    (OUT / "host_vars" / f"{ip}.yml").write_text(
        f"""management_network_address: {ip}
storage_network_address: {stor}
replication_network_address: {stor}
business_network_address: {biz}
disk_type: hdd
custom_disks: []
region: {region}
zone: {zone}
swift_devices:
{devices_yaml}
"""
    )

print(OUT)
