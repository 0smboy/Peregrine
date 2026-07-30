#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Generate golden ring fixtures using the *real* Python Swift implementation.

Run from the repository root:

    python3 rust/crates/swift-ring/tests/fixtures/generate.py

Produces v1/v2 ring files plus expectations.json capturing the exact
node lookup results the Rust implementation must reproduce.
"""
import array
import json
import os
import sys
import tempfile

FIXTURE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(FIXTURE_DIR, *[os.pardir] * 5))
sys.path.insert(0, REPO_ROOT)

HASH_SUFFIX = 'changeme'

# swift.conf must exist before swift.common.utils validates configuration
_swift_conf = tempfile.NamedTemporaryFile(
    mode='w', suffix='.conf', delete=False)
_swift_conf.write('[swift-hash]\nswift_hash_path_suffix = %s\n' % HASH_SUFFIX)
_swift_conf.close()

import swift.common.utils  # noqa: E402
swift.common.utils.SWIFT_CONF_FILE = _swift_conf.name

from swift.common.ring.ring import Ring, RingData  # noqa: E402

PART_POWER = 6
PARTS = 2 ** PART_POWER
PART_SHIFT = 32 - PART_POWER

# 8 devices across 2 regions / 2 zones each, with duplicate IPs and a
# hole at id 4 to exercise sparse device tables
DEVS = [
    {'id': 0, 'region': 1, 'zone': 1, 'ip': '10.0.0.1', 'port': 6200,
     'device': 'sda', 'weight': 100.0, 'meta': ''},
    {'id': 1, 'region': 1, 'zone': 1, 'ip': '10.0.0.1', 'port': 6201,
     'device': 'sdb', 'weight': 100.0, 'meta': 'rack1'},
    {'id': 2, 'region': 1, 'zone': 2, 'ip': '10.0.0.2', 'port': 6200,
     'device': 'sda', 'weight': 50.0, 'meta': ''},
    {'id': 3, 'region': 1, 'zone': 2, 'ip': '10.0.0.3', 'port': 6200,
     'device': 'sda', 'weight': 0.0, 'meta': ''},
    None,
    {'id': 5, 'region': 2, 'zone': 1, 'ip': '10.1.0.1', 'port': 6200,
     'device': 'sda', 'weight': 100.0, 'meta': ''},
    {'id': 6, 'region': 2, 'zone': 1, 'ip': '10.1.0.2', 'port': 6200,
     'device': 'sda', 'weight': 100.0, 'meta': ''},
    {'id': 7, 'region': 2, 'zone': 2, 'ip': '10.1.0.3', 'port': 6200,
     'device': 'sda', 'weight': 100.0, 'meta': ''},
    {'id': 8, 'region': 2, 'zone': 2, 'ip': '10.1.0.3', 'port': 6201,
     'device': 'sdb', 'weight': 100.0, 'meta': ''},
]
DEV_IDS = [d['id'] for d in DEVS if d]


def make_table(replicas, parts):
    """Deterministic part assignments; distinct devices per partition."""
    return [
        array.array('H', (DEV_IDS[(part + 3 * replica) % len(DEV_IDS)]
                          for part in range(parts)))
        for replica in range(replicas)
    ]


def sample_expectations(path):
    ring = Ring(path)
    gets = []
    for account, container, obj in [
            ('a', None, None),
            ('a', 'c', None),
            ('a', 'c', 'o'),
            ('AUTH_test', 'container', 'some/obj/with/slashes'),
            ('AUTH_test', '\N{SNOWMAN}', '\N{PILE OF POO}')]:
        part, nodes = ring.get_nodes(account, container, obj)
        gets.append({
            'account': account, 'container': container, 'obj': obj,
            'part': part,
            'node_ids': [n['id'] for n in nodes],
            'node_indexes': [n['index'] for n in nodes],
        })
    more_nodes = {}
    for part in (0, 17, 42, PARTS - 1):
        more_nodes[str(part)] = [n['id'] for n in ring.get_more_nodes(part)]
    return {
        'replica_count': ring.replica_count,
        'partition_count': ring.partition_count,
        'part_shift': ring._part_shift,
        'dev_id_bytes': ring.dev_id_bytes,
        'next_part_power': ring.next_part_power,
        'builder_version': ring.version,
        'device_count': ring.device_count,
        'weighted_device_count': ring.weighted_device_count,
        'assigned_device_count': ring.assigned_device_count,
        'gets': gets,
        'more_nodes': more_nodes,
    }


def main():
    expectations = {'hash_prefix': '', 'hash_suffix': HASH_SUFFIX, 'rings': {}}

    # whole-replica ring, saved in both formats
    whole = RingData(make_table(3, PARTS), json.loads(json.dumps(DEVS)),
                     PART_SHIFT, version=9)
    # fractional-replica ring with next_part_power, v2 only
    frac_table = make_table(2, PARTS) + [
        array.array('H', (DEV_IDS[(part + 6) % len(DEV_IDS)]
                          for part in range(PARTS // 2)))]
    frac = RingData(frac_table, json.loads(json.dumps(DEVS)),
                    PART_SHIFT, next_part_power=PART_POWER + 1, version=10)

    for name, ring_data, fmt in [
            ('v1.ring.gz', whole, 1),
            ('v2.ring.gz', whole, 2),
            ('v2_frac.ring.gz', frac, 2)]:
        path = os.path.join(FIXTURE_DIR, name)
        ring_data.save(path, format_version=fmt)
        expectations['rings'][name] = sample_expectations(path)

    with open(os.path.join(FIXTURE_DIR, 'expectations.json'), 'w') as fp:
        json.dump(expectations, fp, indent=1, sort_keys=True)
    print('wrote fixtures to', FIXTURE_DIR)


if __name__ == '__main__':
    main()
