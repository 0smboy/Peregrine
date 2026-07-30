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
"""Golden object-server fixtures via the real Python ObjectController."""
import hashlib
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
_swift_conf = tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False)
_swift_conf.write('[swift-hash]\nswift_hash_path_suffix = %s\n' % HASH_SUFFIX)
_swift_conf.close()

import swift.common.utils  # noqa: E402
swift.common.utils.SWIFT_CONF_FILE = _swift_conf.name

_pyeclib = types.ModuleType('pyeclib')
_ec_iface = types.ModuleType('pyeclib.ec_iface')
for _name in ('ECDriverError', 'ECInvalidFragmentMetadata',
              'ECInvalidParameter', 'ECBadFragmentChecksum'):
    setattr(_ec_iface, _name, type(_name, (Exception,), {}))
_ec_iface.ECDriver = type('ECDriver', (object,), {})
_ec_iface.VALID_EC_TYPES = ['liberasurecode_rs_vand']
_ec_iface.PyECLib_FRAGHDRCHKSUM_Types = types.SimpleNamespace(
    inline_crc32='inline_crc32')
_pyeclib.ec_iface = _ec_iface
sys.modules['pyeclib'] = _pyeclib
sys.modules['pyeclib.ec_iface'] = _ec_iface

from swift.obj.server import ObjectController  # noqa: E402
from swift.common.utils import Timestamp  # noqa: E402
import swift.obj.diskfile as _df  # noqa: E402
from swift.common.storage_policy import BaseStoragePolicy  # noqa: E402


# The replication diskfile manager is normally resolved through an egg
# entry point that needs installed package metadata (blocked here by the
# native PyECLib build). Bind it directly instead; no EC codec is used.
def _get_diskfile_manager(self, *args, **kwargs):
    return _df.DiskFileManager(*args, **kwargs)


BaseStoragePolicy.get_diskfile_manager = _get_diskfile_manager

T = {i: Timestamp(1751500000 + i).internal for i in range(10)}
INTERESTING = ('x-timestamp', 'x-backend-timestamp', 'x-backend-data-timestamp',
               'content-type', 'content-length', 'etag', 'x-object-meta-',
               'content-range', 'accept-ranges', 'x-backend-content-type')

BODY = b'hello swift world'
ETAG = hashlib.md5(BODY).hexdigest()

REQUESTS = [
    ('put', 'PUT', '/sda1/0/a/c/o', {
        'X-Timestamp': T[1], 'Content-Type': 'text/plain',
        'Content-Length': str(len(BODY)), 'X-Object-Meta-Color': 'blue'}, BODY),
    ('put-bad-etag', 'PUT', '/sda1/0/a/c/o2', {
        'X-Timestamp': T[1], 'Content-Type': 'text/plain',
        'Content-Length': str(len(BODY)), 'ETag': 'deadbeef'}, BODY),
    ('put-no-ctype', 'PUT', '/sda1/0/a/c/o3', {
        'X-Timestamp': T[1], 'Content-Length': '3'}, b'abc'),
    ('head', 'HEAD', '/sda1/0/a/c/o', {}, b''),
    ('get', 'GET', '/sda1/0/a/c/o', {}, b''),
    ('get-range', 'GET', '/sda1/0/a/c/o', {'Range': 'bytes=0-4'}, b''),
    ('get-suffix-range', 'GET', '/sda1/0/a/c/o', {'Range': 'bytes=-5'}, b''),
    ('get-unsat-range', 'GET', '/sda1/0/a/c/o',
     {'Range': 'bytes=100-200'}, b''),
    ('post', 'POST', '/sda1/0/a/c/o', {
        'X-Timestamp': T[2], 'Content-Type': 'text/html',
        'X-Object-Meta-Color': 'red'}, b''),
    ('head-after-post', 'HEAD', '/sda1/0/a/c/o', {}, b''),
    ('post-stale', 'POST', '/sda1/0/a/c/o', {'X-Timestamp': T[0]}, b''),
    ('put-newer', 'PUT', '/sda1/0/a/c/o', {
        'X-Timestamp': T[5], 'Content-Type': 'text/plain',
        'Content-Length': '2'}, b'hi'),
    ('get-after-newer', 'GET', '/sda1/0/a/c/o', {}, b''),
    ('delete-stale', 'DELETE', '/sda1/0/a/c/o', {'X-Timestamp': T[3]}, b''),
    ('delete', 'DELETE', '/sda1/0/a/c/o', {'X-Timestamp': T[6]}, b''),
    ('get-after-delete', 'GET', '/sda1/0/a/c/o', {}, b''),
    ('head-missing', 'HEAD', '/sda1/0/a/c/nope', {}, b''),
    ('delete-missing', 'DELETE', '/sda1/0/a/c/nope', {'X-Timestamp': T[6]},
     b''),
    ('put-no-ts', 'PUT', '/sda1/0/a/c/o5', {'Content-Type': 't',
     'Content-Length': '0'}, b''),
    ('bad-method', 'PATCH', '/sda1/0/a/c/o', {}, b''),
]


def run():
    tmp = tempfile.mkdtemp()
    os.makedirs(os.path.join(tmp, 'sda1'))
    ctrl = ObjectController(
        {'devices': tmp, 'mount_check': 'false', 'log_requests': 'false'})
    results = []
    for label, method, path, headers, body in REQUESTS:
        env = {
            'REQUEST_METHOD': method,
            'PATH_INFO': urllib.parse.unquote(path),
            'QUERY_STRING': '',
            'SERVER_NAME': 'localhost', 'SERVER_PORT': '6200',
            'SERVER_PROTOCOL': 'HTTP/1.0',
            'wsgi.input': io.BytesIO(body),
            'CONTENT_LENGTH': str(len(body)),
        }
        for k, v in headers.items():
            env['HTTP_' + k.upper().replace('-', '_')] = v
        if 'Content-Length' in headers:
            env['CONTENT_LENGTH'] = headers['Content-Length']
        if 'Content-Type' in headers:
            env['CONTENT_TYPE'] = headers['Content-Type']
        cap = {}

        def start_response(status, resp_headers, exc_info=None):
            cap['status'] = status
            cap['headers'] = resp_headers

        resp_body = b''.join(ctrl(env, start_response))
        interesting = {}
        for k, v in cap['headers']:
            if any(k.lower().startswith(p) for p in INTERESTING):
                interesting[k] = v
        results.append({
            'label': label, 'method': method, 'path': path,
            'headers': headers,
            'body': body.decode('latin1'),
            'status': int(cap['status'].split()[0]),
            'response_headers': interesting,
            'response_body': resp_body.decode('latin1'),
        })
    return results


def main():
    exp = {'hash_suffix': HASH_SUFFIX, 'body': BODY.decode('latin1'),
           'etag': ETAG, 'requests': run()}
    with open(os.path.join(FIXTURE_DIR, 'expectations.json'), 'w') as fp:
        json.dump(exp, fp, indent=1, sort_keys=True)
    print('wrote fixtures to', FIXTURE_DIR)


if __name__ == '__main__':
    main()
