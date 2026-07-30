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
Golden container-server fixtures: drive the real Python
ContainerController through WSGI and record every response. See the
account server twin for conventions.
"""
import io
import json
import os
import sys
import tempfile
import types
import urllib.parse

FIXTURE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(FIXTURE_DIR, *[os.pardir] * 5))
sys.path.insert(0, REPO_ROOT)

HASH_SUFFIX = 'changeme'
_swift_conf = tempfile.NamedTemporaryFile(
    mode='w', suffix='.conf', delete=False)
_swift_conf.write('[swift-hash]\nswift_hash_path_suffix = %s\n' % HASH_SUFFIX)
_swift_conf.close()

import swift.common.utils  # noqa: E402
swift.common.utils.SWIFT_CONF_FILE = _swift_conf.name

# ---- pyeclib import shim (no EC codec path is exercised) ----
_pyeclib = types.ModuleType('pyeclib')
_ec_iface = types.ModuleType('pyeclib.ec_iface')
for _name in ('ECDriverError', 'ECInvalidFragmentMetadata',
              'ECInvalidParameter', 'ECBadFragmentChecksum'):
    setattr(_ec_iface, _name, type(_name, (Exception,), {}))


class _ECDriver(object):
    pass


_ec_iface.ECDriver = _ECDriver
_ec_iface.VALID_EC_TYPES = ['liberasurecode_rs_vand']
_ec_iface.PyECLib_FRAGHDRCHKSUM_Types = types.SimpleNamespace(
    inline_crc32='inline_crc32')
_pyeclib.ec_iface = _ec_iface
sys.modules['pyeclib'] = _pyeclib
sys.modules['pyeclib.ec_iface'] = _ec_iface
# ---- end shim ----

import swift.common.db as cdb  # noqa: E402
import swift.container.backend as cb  # noqa: E402
from swift.container.server import ContainerController  # noqa: E402
from swift.common.utils import Timestamp  # noqa: E402

from swift.common.utils.timestamp import NormalTimestamp as _RealNT


class _FixedNormalTimestamp(_RealNT):
    """A real NormalTimestamp whose now() is pinned for determinism."""
    @classmethod
    def now(cls, *a, **kw):
        return _RealNT(1751500000.0)

DB_CREATED_AT = '1751500000.00000'
cdb.DatabaseBroker._new_db_id = lambda self: 'fixed-db-id-0001'
cb.NormalTimestamp = _FixedNormalTimestamp

T0 = Timestamp(1751500000).internal
T1 = Timestamp(1751500001).internal
T2 = Timestamp(1751500002).internal
T3 = Timestamp(1751500003).internal
T4 = Timestamp(1751500004).internal
T5 = Timestamp(1751500005).internal
T6 = Timestamp(1751500006).internal

INTERESTING = ('x-container-', 'x-backend-', 'x-put-timestamp',
               'x-timestamp', 'content-type', 'last-modified')

UPDATE_BODY = json.dumps([
    {'name': 'upd1', 'created_at': T3, 'size': 7,
     'content_type': 'text/up', 'etag': 'eu', 'deleted': 0,
     'storage_policy_index': 0},
    {'name': 'o1', 'created_at': T3, 'size': 9,
     'content_type': 'text/newer', 'etag': 'e1b', 'deleted': 0,
     'storage_policy_index': 0},
])

REQUESTS = [
    ('put-container', 'PUT', '/sda1/0/a/c', '', {'X-Timestamp': T0}, ''),
    ('put-container-again', 'PUT', '/sda1/0/a/c', '', {'X-Timestamp': T0},
     ''),
    ('put-bad-policy', 'PUT', '/sda1/0/a/c', '',
     {'X-Timestamp': T0, 'X-Backend-Storage-Policy-Index': '5'}, ''),
    ('post-meta', 'POST', '/sda1/0/a/c', '',
     {'X-Timestamp': T1, 'X-Container-Meta-Color': 'blue',
      'X-Container-Read': '.r:*'}, ''),
    ('put-obj-o1', 'PUT', '/sda1/0/a/c/o1', '',
     {'X-Timestamp': T2, 'X-Size': '5', 'X-Content-Type': 'text/plain',
      'X-Etag': 'e1'}, ''),
    ('put-obj-unicode', 'PUT',
     '/sda1/0/a/c/' + urllib.parse.quote('中文 obj'), '',
     {'X-Timestamp': T2, 'X-Size': '11',
      'X-Content-Type': 'app/slo;swift_bytes=99', 'X-Etag': 'e2'}, ''),
    ('put-obj-photos-x', 'PUT', '/sda1/0/a/c/photos/x', '',
     {'X-Timestamp': T2, 'X-Size': '1', 'X-Content-Type': 'text/x',
      'X-Etag': 'e3'}, ''),
    ('put-obj-photos-y', 'PUT', '/sda1/0/a/c/photos/y', '',
     {'X-Timestamp': T2, 'X-Size': '2', 'X-Content-Type': 'text/y',
      'X-Etag': 'e4'}, ''),
    ('put-obj-gonezo', 'PUT', '/sda1/0/a/c/gonezo', '',
     {'X-Timestamp': T2, 'X-Size': '3', 'X-Content-Type': 'text/g',
      'X-Etag': 'e5'}, ''),
    ('delete-obj-gonezo', 'DELETE', '/sda1/0/a/c/gonezo', '',
     {'X-Timestamp': T3}, ''),
    ('head-container', 'HEAD', '/sda1/0/a/c', '', {}, ''),
    ('get-json', 'GET', '/sda1/0/a/c', 'format=json', {}, ''),
    ('get-plain', 'GET', '/sda1/0/a/c', '', {}, ''),
    ('get-xml', 'GET', '/sda1/0/a/c', 'format=xml', {}, ''),
    ('get-prefix-delim', 'GET', '/sda1/0/a/c',
     'format=json&prefix=photos/&delimiter=/', {}, ''),
    ('get-delim-only', 'GET', '/sda1/0/a/c', 'format=json&delimiter=/',
     {}, ''),
    ('get-path', 'GET', '/sda1/0/a/c', 'format=json&path=photos', {}, ''),
    ('get-marker', 'GET', '/sda1/0/a/c', 'format=json&marker=o1', {}, ''),
    ('get-reverse', 'GET', '/sda1/0/a/c', 'format=json&reverse=true', {},
     ''),
    ('get-limit-too-big', 'GET', '/sda1/0/a/c', 'limit=10001', {}, ''),
    ('update-verb', 'UPDATE', '/sda1/0/a/c', '', {'X-Timestamp': T3},
     UPDATE_BODY),
    ('get-after-update', 'GET', '/sda1/0/a/c', 'format=json', {}, ''),
    ('delete-container-conflict', 'DELETE', '/sda1/0/a/c', '',
     {'X-Timestamp': T4}, ''),
    ('delete-obj-o1', 'DELETE', '/sda1/0/a/c/o1', '', {'X-Timestamp': T4},
     ''),
    ('delete-obj-unicode', 'DELETE',
     '/sda1/0/a/c/' + urllib.parse.quote('中文 obj'), '',
     {'X-Timestamp': T4}, ''),
    ('delete-obj-photos-x', 'DELETE', '/sda1/0/a/c/photos/x', '',
     {'X-Timestamp': T4}, ''),
    ('delete-obj-photos-y', 'DELETE', '/sda1/0/a/c/photos/y', '',
     {'X-Timestamp': T4}, ''),
    ('delete-obj-upd1', 'DELETE', '/sda1/0/a/c/upd1', '',
     {'X-Timestamp': T4}, ''),
    ('delete-container', 'DELETE', '/sda1/0/a/c', '', {'X-Timestamp': T5},
     ''),
    ('get-after-delete', 'GET', '/sda1/0/a/c', 'format=json', {}, ''),
    ('put-recreate', 'PUT', '/sda1/0/a/c', '', {'X-Timestamp': T6}, ''),
    ('head-recreated', 'HEAD', '/sda1/0/a/c', '', {}, ''),
    ('head-missing', 'HEAD', '/sda1/0/a/nope', '', {}, ''),
    ('put-obj-autocreate', 'PUT', '/sda1/0/.expiring_objects/queue/o', '',
     {'X-Timestamp': T2, 'X-Size': '0', 'X-Content-Type': 'text/q',
      'X-Etag': 'eq', 'X-Backend-Storage-Policy-Index': '0'}, ''),
    ('options', 'OPTIONS', '/sda1/0/a/c', '', {}, ''),
    ('bad-method', 'PATCH', '/sda1/0/a/c', '', {}, ''),
    ('bad-drive', 'GET', '/nodrive/0/a/c', '', {}, ''),
    ('no-timestamp', 'PUT', '/sda1/0/a/c2', '', {}, ''),
]


def run():
    tmp = tempfile.mkdtemp()
    os.makedirs(os.path.join(tmp, 'sda1'))
    controller = ContainerController(
        {'devices': tmp, 'mount_check': 'false', 'log_requests': 'false',
         'fallocate_reserve': '0'})
    results = []
    for label, method, path, query, headers, body in REQUESTS:
        body_bytes = body.encode('utf-8')
        env = {
            'REQUEST_METHOD': method,
            'PATH_INFO': urllib.parse.unquote(path, errors='surrogateescape')
            .encode('utf8', 'surrogateescape').decode('latin1'),
            'QUERY_STRING': query,
            'SERVER_NAME': 'localhost', 'SERVER_PORT': '6201',
            'SERVER_PROTOCOL': 'HTTP/1.0',
            'wsgi.input': io.BytesIO(body_bytes),
            'CONTENT_LENGTH': str(len(body_bytes)),
        }
        for k, v in headers.items():
            env['HTTP_' + k.upper().replace('-', '_')] = v
        captured = {}

        def start_response(status, resp_headers, exc_info=None):
            captured['status'] = status
            captured['headers'] = resp_headers

        resp_body = b''.join(controller(env, start_response))
        interesting = {}
        for k, v in captured['headers']:
            kl = k.lower()
            if any(kl.startswith(p) for p in INTERESTING):
                interesting[k] = v
        results.append({
            'label': label,
            'method': method,
            'path': path,
            'query': query,
            'headers': headers,
            'body': body,
            'status': int(captured['status'].split()[0]),
            'response_headers': interesting,
            'response_body': resp_body.decode('utf-8', 'replace'),
        })
    return results



def encode_replicate():
    """Drive the Python ReplicatorRpc merge_items op and record the
    resulting container rows, so the Rust REPLICATE handler can be
    checked against it."""
    import swift.common.db_replicator as dbr
    from swift.common.utils import Timestamp

    tmp = tempfile.mkdtemp()
    os.makedirs(os.path.join(tmp, 'sda1', 'tmp'), exist_ok=True)
    # create a container DB at the RPC hash path
    account, container = 'a', 'repl'
    from swift.common.utils import hash_path, storage_directory
    hsh = hash_path(account, container)
    part = '7'
    db_dir = os.path.join(tmp, 'sda1',
                          storage_directory('containers', part, hsh))
    os.makedirs(db_dir, exist_ok=True)
    db_file = os.path.join(db_dir, hsh + '.db')
    b = cb.ContainerBroker(db_file, account=account, container=container)
    b.initialize(T0, 0)
    dict(b.get_info())

    rpc = dbr.ReplicatorRpc(tmp, 'containers',
                            cb.ContainerBroker, mount_check=False)
    # merge_items op: [op, item_list, source_id]
    items = [
        {'ROWID': 1, 'name': 'ri1', 'created_at': T2, 'size': 3,
         'content_type': 'text/r', 'etag': 'er1', 'deleted': 0,
         'storage_policy_index': 0},
        {'ROWID': 2, 'name': 'ri2', 'created_at': T3, 'size': 0,
         'content_type': 'application/deleted', 'etag': 'noetag',
         'deleted': 1, 'storage_policy_index': 0},
    ]
    import json as _json

    class FakeReq:
        def __init__(self, body):
            self.environ = {'wsgi.input': __import__('io').BytesIO(body)}
    # call dispatch directly with parsed args
    resp = rpc.dispatch(('sda1', part, hsh),
                        ['merge_items', items, 'remote-node-1'])
    status = int(str(resp.status).split()[0])
    import sqlite3 as sq
    conn = sq.connect(db_file)
    rows = conn.execute('SELECT ROWID, name, created_at, size, content_type,'
                        ' etag, deleted, storage_policy_index FROM object'
                        ' ORDER BY ROWID').fetchall()
    sync_rows = conn.execute(
        'SELECT remote_id, sync_point FROM incoming_sync'
        ' ORDER BY remote_id').fetchall()
    conn.close()

    # merge_syncs op
    resp2 = rpc.dispatch(('sda1', part, hsh),
                         ['merge_syncs', [{'sync_point': 42,
                                           'remote_id': 'peer-2'}]])
    conn = sq.connect(db_file)
    sync_rows2 = conn.execute(
        'SELECT remote_id, sync_point FROM incoming_sync'
        ' ORDER BY remote_id').fetchall()
    conn.close()

    return {
        'account': account, 'container': container, 'partition': part,
        'hash': hsh,
        'merge_items': {
            'op': ['merge_items', items, 'remote-node-1'],
            'status': status,
            'rows': [list(r) for r in rows],
            'incoming_sync': [list(r) for r in sync_rows],
        },
        'merge_syncs': {
            'status': int(str(resp2.status).split()[0]),
            'incoming_sync': [list(r) for r in sync_rows2],
        },
    }


def main():
    expectations = {'hash_suffix': HASH_SUFFIX, 'requests': run(),
                    'replicate': encode_replicate()}
    with open(os.path.join(FIXTURE_DIR, 'expectations.json'), 'w') as fp:
        json.dump(expectations, fp, indent=1, sort_keys=True)
    print('wrote fixtures to', FIXTURE_DIR)


if __name__ == '__main__':
    main()
