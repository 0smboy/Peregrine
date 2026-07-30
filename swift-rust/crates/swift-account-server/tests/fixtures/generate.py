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
Golden account-server fixtures: drive the real Python AccountController
through WSGI with a deterministic request sequence and record every
response (status, interesting headers, body). The Rust server replays
the same sequence over real HTTP and must produce the same responses.

Run from the repository root:

    python3 rust/crates/swift-account-server/tests/fixtures/generate.py
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

# ---- pyeclib import shim (same rationale as the diskfile generator:
# storage_policy imports it at module level; no EC codec path is
# exercised by these fixtures) ----
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
import swift.account.backend as ab  # noqa: E402
from swift.account.server import AccountController  # noqa: E402
from swift.common.utils import Timestamp  # noqa: E402

from swift.common.utils.timestamp import NormalTimestamp as _RealNT


class _FixedNormalTimestamp(_RealNT):
    """A real NormalTimestamp whose now() is pinned for determinism."""
    @classmethod
    def now(cls, *a, **kw):
        return _RealNT(1751500000.0)

# determinism
DB_CREATED_AT = '1751500000.00000'
cdb.DatabaseBroker._new_db_id = lambda self: 'fixed-db-id-0001'
ab.NormalTimestamp = _FixedNormalTimestamp

T0 = Timestamp(1751500000).internal
T1 = Timestamp(1751500001).internal
T2 = Timestamp(1751500002).internal
T3 = Timestamp(1751500003).internal
T4 = Timestamp(1751500004).internal
T5 = Timestamp(1751500005).internal

INTERESTING_PREFIXES = ('x-account-', 'x-put-timestamp', 'x-timestamp',
                        'content-type')

REQUESTS = [
    # (label, method, path, query, headers)
    ('put-account', 'PUT', '/sda1/0/AUTH_test', '', {'X-Timestamp': T0}),
    ('put-account-again', 'PUT', '/sda1/0/AUTH_test', '',
     {'X-Timestamp': T0}),
    ('put-account-no-ts', 'PUT', '/sda1/0/AUTH_ts', '', {}),
    ('post-meta', 'POST', '/sda1/0/AUTH_test', '',
     {'X-Timestamp': T1, 'X-Account-Meta-Color': 'blue',
      'X-Account-Sysmeta-S': 'sv'}),
    ('head-empty', 'HEAD', '/sda1/0/AUTH_test', '', {}),
    ('get-empty-plain', 'GET', '/sda1/0/AUTH_test', '', {}),
    ('put-container-c1', 'PUT', '/sda1/0/AUTH_test/c1', '',
     {'X-Put-Timestamp': T1, 'X-Delete-Timestamp': '0',
      'X-Object-Count': '3', 'X-Bytes-Used': '42',
      'X-Backend-Storage-Policy-Index': '0'}),
    ('put-container-unicode', 'PUT',
     '/sda1/0/AUTH_test/' + urllib.parse.quote('中文子'), '',
     {'X-Put-Timestamp': T2, 'X-Delete-Timestamp': '0',
      'X-Object-Count': '0', 'X-Bytes-Used': '0'}),
    ('put-container-deleted', 'PUT', '/sda1/0/AUTH_test/gone', '',
     {'X-Put-Timestamp': T1, 'X-Delete-Timestamp': T2,
      'X-Object-Count': '0', 'X-Bytes-Used': '0'}),
    ('head-after', 'HEAD', '/sda1/0/AUTH_test', '', {}),
    ('get-json', 'GET', '/sda1/0/AUTH_test', 'format=json', {}),
    ('get-plain', 'GET', '/sda1/0/AUTH_test', '', {}),
    ('get-xml', 'GET', '/sda1/0/AUTH_test', 'format=xml', {}),
    ('get-accept-json', 'GET', '/sda1/0/AUTH_test', '',
     {'Accept': 'application/json'}),
    ('get-limit-1', 'GET', '/sda1/0/AUTH_test', 'format=json&limit=1', {}),
    ('get-limit-too-big', 'GET', '/sda1/0/AUTH_test', 'limit=10001', {}),
    ('get-marker', 'GET', '/sda1/0/AUTH_test', 'format=json&marker=c1', {}),
    ('get-prefix-delim', 'GET', '/sda1/0/AUTH_test',
     'format=json&prefix=' + urllib.parse.quote('中文') +
     '&delimiter=' + urllib.parse.quote('/'), {}),
    ('get-delim-only', 'GET', '/sda1/0/AUTH_test',
     'format=json&delimiter=' + urllib.parse.quote('/'), {}),
    ('get-reverse', 'GET', '/sda1/0/AUTH_test', 'format=json&reverse=true',
     {}),
    ('put-container-autocreate', 'PUT', '/sda1/0/.shards_AUTH_test/rows', '',
     {'X-Put-Timestamp': T3, 'X-Delete-Timestamp': '0',
      'X-Object-Count': '0', 'X-Bytes-Used': '0', 'X-Timestamp': T3}),
    ('put-container-no-account', 'PUT', '/sda1/0/AUTH_missing/c', '',
     {'X-Put-Timestamp': T3, 'X-Delete-Timestamp': '0',
      'X-Object-Count': '0', 'X-Bytes-Used': '0'}),
    ('delete-account', 'DELETE', '/sda1/0/AUTH_test', '',
     {'X-Timestamp': T4}),
    ('get-after-delete', 'GET', '/sda1/0/AUTH_test', 'format=json', {}),
    ('put-after-delete', 'PUT', '/sda1/0/AUTH_test', '',
     {'X-Timestamp': T5}),
    ('head-missing', 'HEAD', '/sda1/0/AUTH_nope', '', {}),
    ('bad-method', 'OPTIONS', '/sda1/0/AUTH_test', '', {}),
    ('bad-drive', 'GET', '/nodrive/0/AUTH_test', '', {}),
    ('bad-path', 'GET', '/sda1/0', '', {}),
]


def run():
    tmp = tempfile.mkdtemp()
    os.makedirs(os.path.join(tmp, 'sda1'))
    controller = AccountController(
        {'devices': tmp, 'mount_check': 'false', 'log_requests': 'false',
         'fallocate_reserve': '0'})
    results = []
    for label, method, path, query, headers in REQUESTS:
        env = {
            'REQUEST_METHOD': method,
            'PATH_INFO': urllib.parse.unquote(path, errors='surrogateescape')
            .encode('utf8', 'surrogateescape').decode('latin1'),
            'QUERY_STRING': query,
            'SERVER_NAME': 'localhost', 'SERVER_PORT': '6202',
            'SERVER_PROTOCOL': 'HTTP/1.0',
            'wsgi.input': io.BytesIO(b''),
            'CONTENT_LENGTH': '0',
        }
        for k, v in headers.items():
            env['HTTP_' + k.upper().replace('-', '_')] = v
        status_headers = {}

        def start_response(status, resp_headers, exc_info=None):
            status_headers['status'] = status
            status_headers['headers'] = resp_headers

        body = b''.join(controller(env, start_response))
        interesting = {}
        for k, v in status_headers['headers']:
            kl = k.lower()
            if any(kl.startswith(p) for p in INTERESTING_PREFIXES):
                interesting[k] = v
        results.append({
            'label': label,
            'method': method,
            'path': path,
            'query': query,
            'headers': headers,
            'status': int(status_headers['status'].split()[0]),
            'response_headers': interesting,
            'body': body.decode('utf-8', 'replace'),
        })
    return results


def main():
    expectations = {
        'hash_suffix': HASH_SUFFIX,
        'requests': run(),
    }
    with open(os.path.join(FIXTURE_DIR, 'expectations.json'), 'w') as fp:
        json.dump(expectations, fp, indent=1, sort_keys=True)
    print('wrote fixtures to', FIXTURE_DIR)


if __name__ == '__main__':
    main()
