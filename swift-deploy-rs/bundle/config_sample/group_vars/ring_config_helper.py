#!/usr/bin/env python
# encoding: utf-8

import os
import json
from netaddr import IPAddress, IPRange
from pprint import pprint
import subprocess
import yaml
from jinja2 import Environment, FileSystemLoader

host_vars_folder = os.path.join(os.path.dirname(os.getcwd()), 'host_vars')


def get_node_ip_addresses():
    addresses = {
        'storage_network_addresses': [],
        'management_network_addresses': [],
        'business_network_addresses': [],
        'keystone_storage_network_addresses': [],
        'mariadb_storage_network_addresses': []
    }
    nodes = subprocess.check_output(['ls', host_vars_folder]).strip(str.encode('\n')).split(str.encode('\n'))
    for node in nodes:
        node=node.decode()
        try:
            IPAddress(node)
        except:
            continue
        with open(os.path.join(host_vars_folder, node), 'r') as f:
            yml = yaml.load(f)
            addresses['storage_network_addresses'].append(yml['storage_network_address'])
            addresses['management_network_addresses'].append(yml['management_network_address'])
            addresses['business_network_addresses'].append(yml['business_network_address'])
            if str(yml.get('keystone_node', '')).lower() == 'true':
                addresses['keystone_storage_network_addresses'].append(yml['storage_network_address'])
            if str(yml.get('mariadb_node', '')).lower() == 'true':
                addresses['mariadb_storage_network_addresses'].append(yml['storage_network_address'])
    return addresses


with open('all.raw', 'r+') as f:
    group_all = yaml.load(f)

    if not group_all.get('ssh_bind_port'):
        raise ValueError("Invalid ssh_bind_port value: %s" % group_all.get('ssh_bind_port'))

    # set swauth super_admin_password once if not set before
    if not group_all.get('super_admin_password'):
        super_admin_password = subprocess.check_output(
            ['openssl', 'rand', '-base64', '12']).split()[0]
        group_all['super_admin_password'] = super_admin_password
        f.write("# Dont't delete or modify me\n")
        f.write('super_admin_password: %s' % super_admin_password)
    # set swauth auth_type_salt once if not set before
    if not group_all.get('auth_type_salt'):
        auth_type_salt = subprocess.check_output(
            ['openssl', 'rand', '-base64', '12']).split()[0]
        group_all['auth_type_salt'] = auth_type_salt
        f.write("\n# Dont't delete or modify me\n")
        f.write('auth_type_salt: %s' % auth_type_salt)


with open('security', 'r') as f:
    env = Environment(loader=FileSystemLoader('./'))
    security_template = env.get_template('security')
    security_rendered = security_template.render(**group_all)
    security_ports = yaml.safe_load(security_rendered)
    security_ports_all = {}
    for name, val in security_ports.items():
        for _, ports in val.items():
            if type(ports) in [str, int]:
                ports = [ports]
            got_ports = security_ports_all.get(name, [])
            got_ports.extend([int(p) for p in ports])
            security_ports_all[name] = got_ports
    group_all.update(security_ports_all)

try:
    group_all.pop('account_ring')
    group_all.pop('container_ring')
    group_all.pop('object_rings')
    group_all.pop('account_swift_partition_power')
    group_all.pop('account_swift_replicas')
    group_all.pop('account_swift_minimum_time')
    group_all.pop('container_swift_partition_power')
    group_all.pop('container_swift_replicas')
    group_all.pop('container_swift_minimum_time')
except Exception:
    pass

with open('ring_config.yml', 'r') as ring_config_yml:
    helper_config = yaml.load(ring_config_yml)

account_ring_list = helper_config['account_ring']['ring_content']
container_ring_list = helper_config['container_ring']['ring_content']
object_rings = helper_config.get('object_rings')
keys = ['account_ring', 'container_ring', 'object_rings']
group_all['account_swift_partition_power'] = helper_config[
    'account_ring']['create_ring_info']['account_swift_partition_power']
group_all['account_swift_replicas'] = helper_config[
    'account_ring']['create_ring_info']['account_swift_replicas']
group_all['account_swift_minimum_time'] = helper_config[
    'account_ring']['create_ring_info']['account_swift_minimum_time']
group_all['container_swift_partition_power'] = helper_config[
    'container_ring']['create_ring_info']['container_swift_partition_power']
group_all['container_swift_replicas'] = helper_config[
    'container_ring']['create_ring_info']['container_swift_replicas']
group_all['container_swift_minimum_time'] = helper_config[
    'container_ring']['create_ring_info']['container_swift_minimum_time']
group_all['policies'] = []
for item in helper_config['object_rings']:
    group_all['policies'].append(item['policy'])


def flatten_disks(disks_info):
    """Flatten common and dedicated disks info

    :common_disks_info: list

    return:
        if common disks, return
            [[port, sdx, weight],
             [port, sdy, weight], ...]
        if dedicated disks, return
            [[storage_ip, replication_ip, port, sdx, weight],
             [storage_ip, replication_ip, port, sdx, weight], ...]
    """

    disks = []
    if len(disks_info[0].split('_')) == 3:
        for line in disks_info:
            items = line.split('_')
            hdd_disks = []
            ssd_disks = []
            raw_data = json.loads(items[1])
            if raw_data.get('hdd'):
                hdd_nums = range(int(raw_data.get('hdd').split('-')[0]),
                                 int(raw_data.get('hdd').split('-')[1]) + 1)
                hdd_disks = ['hdd' + '{:03d}'.format(num) for num in hdd_nums]
            if raw_data.get('ssd'):
                ssd_nums = range(int(raw_data.get('ssd').split('-')[0]),
                                 int(raw_data.get('ssd').split('-')[1]) + 1)
                ssd_disks = ['ssd' + '{:03d}'.format(num) for num in ssd_nums]
            disks += [[int(items[0]), device, int(items[2])]
                      for device in hdd_disks + ssd_disks]
    if len(disks_info[0].split('_')) == 5:
        for line in disks_info:
            items = line.split('_')
            hdd_disks = []
            ssd_disks = []
            raw_data = json.loads(items[3])
            if raw_data.get('hdd'):
                hdd_nums = range(int(raw_data.get('hdd').split('-')[0]),
                                 int(raw_data.get('hdd').split('-')[1]) + 1)
                hdd_disks = ['hdd' + '{:03d}'.format(num) for num in hdd_nums]
            if raw_data.get('ssd'):
                ssd_nums = range(int(raw_data.get('ssd').split('-')[0]),
                                 int(raw_data.get('ssd').split('-')[1]) + 1)
                ssd_disks = ['ssd' + '{:03d}'.format(num) for num in ssd_nums]
            disks += [[items[0], items[1],
                       int(items[2]), device,
                       int(items[4])]
                      for device in hdd_disks + ssd_disks]
    return disks


def assemble_common(region, zone, storage_ips, replication_ips, common_disk_info):  # noqa
    result = []
    for pdw in common_disk_info:
        # each pdw element is a list consist [port, device, weight]
        for pair in zip(storage_ips, replication_ips):
            result.append({
                'region': region,
                'zone': zone,
                'storage_ip': pair[0].format(),
                'replication_ip': pair[1].format(),
                'device': pdw[1],
                'port': pdw[0],
                'weight': pdw[2]
            })
    return result


def assemble_dedicated(region, zone, dedicated_disk_info):
    result = []
    for item in dedicated_disk_info:
        result.append({
            'region': region,
            'zone': zone,
            'storage_ip': item[0].format(),
            'replication_ip': item[1].format(),
            'port': item[2],
            'device': item[3],
            'weight': item[4]
        })
    return result


def get_ips(ip_conf_str):
    ip_blobs = ip_conf_str.replace(' ', '').split(',')
    ip_addrs = []
    for ip_blob in ip_blobs:
        if '-' in ip_blob:
            ip_ranges = ip_blob.split('-', 1)
            ips = list(IPRange(ip_ranges[0], ip_ranges[1]))
            ip_addrs.extend(ips)
        else:
            ip_addrs.append(IPAddress(ip_blob))
    return ip_addrs


def setter(ring_list, key=None):
    group_all[key] = []
    if key == 'account_ring' or key == 'container_ring':
        for item in ring_list:
            if item.get('common_disk_info'):
                region = item['region']
                zone = item['zone']
                storage_ips = get_ips(item['storage_ips'])
                replication_ips = get_ips(item['replication_ips'])
                if len(storage_ips) != len(replication_ips):
                    raise
                common_disk_info = flatten_disks(
                    item['common_disk_info'])
                group_all[key] += assemble_common(region,
                                                  zone,
                                                  storage_ips,
                                                  replication_ips,
                                                  common_disk_info)
            if item.get('dedicated_disk_info'):
                region = item['region']
                zone = item['zone']
                dedicated_disk_info = flatten_disks(
                    item['dedicated_disk_info'])
                group_all[key] += assemble_dedicated(region,
                                                     zone,
                                                     dedicated_disk_info)
    if key == 'object_rings':
        for item in ring_list:
            create_ring_info = item['create_ring_info']
            builder_name = create_ring_info['builder_name']
            object_swift_partition_power = \
                create_ring_info['object_swift_partition_power']
            object_swift_replicas = create_ring_info['object_swift_replicas']
            object_swift_minimum_time = \
                create_ring_info['object_swift_minimum_time']
            ring_content = item['ring_content']
            nodes = []
            for item in ring_content:
                if item.get('common_disk_info'):
                    region = item['region']
                    zone = item['zone']
                    storage_ips = get_ips(item['storage_ips'])
                    replication_ips = get_ips(item['replication_ips'])
                    if len(storage_ips) != len(replication_ips):
                        raise
                    common_disk_info = flatten_disks(
                        item['common_disk_info'])
                    common = assemble_common(region,
                                             zone,
                                             storage_ips,
                                             replication_ips,
                                             common_disk_info)

                if item.get('dedicated_disk_info'):
                    region = item['region']
                    zone = item['zone']
                    dedicated_disk_info = flatten_disks(
                        item['dedicated_disk_info'])
                    dedicated = assemble_dedicated(region,
                                                   zone,
                                                   dedicated_disk_info)
                common = common if 'common' in locals() else []
                dedicated = dedicated if 'dedicated' in locals() else []
                nodes += common + dedicated
            group_all[key].append({
                'name': builder_name,
                'nodes': nodes,
                'object_swift_partition_power': object_swift_partition_power,
                'object_swift_replicas': object_swift_replicas,
                'object_swift_minimum_time': object_swift_minimum_time
            })


list(map(setter, [account_ring_list, container_ring_list, object_rings], keys))
print('######################## Account Ring #############################')
pprint(str(group_all['account_ring']).split('},'))
print('####################### Container Ring ############################')
pprint(str(group_all['container_ring']).split('},'))
print('######################### Object Ring #############################')
for i in str(group_all['object_rings']).split('}, {'):
    pprint(i.split("{'"))
print('###################################################################')

confirm = input('Confirm above ring info ? Type [yes/no]: ')

if confirm == 'yes':
    addresses = get_node_ip_addresses()
    group_all.update(addresses)
    with open('all', 'w') as f:
        yaml.dump(group_all, f,
                  default_flow_style=False,
                  canonical=False,
                  indent=4,
                  explicit_start=False,
                  line_break=False,
                  explicit_end=False)
