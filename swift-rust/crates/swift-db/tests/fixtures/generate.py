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
Generate golden container-DB fixtures using the *real* Python Swift
implementation (swift/container/backend.py).

Run from the repository root:

    python3 rust/crates/swift-db/tests/fixtures/generate.py

Produces expectations.json plus container_sc2.db (a Python-created
container database the Rust broker must read directly).
"""
import json
import os
import shutil
import sys
import tempfile

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

from swift.common.utils import Timestamp  # noqa: E402

from swift.common.utils.timestamp import NormalTimestamp as _RealNT


class _FixedNormalTimestamp(_RealNT):
    """A real NormalTimestamp whose now() is pinned for determinism."""
    @classmethod
    def now(cls, *a, **kw):
        return _RealNT(1751500000.0)

def ts(secs, offset=0):
    return Timestamp(secs, offset=offset)


T0 = ts(1751500000)
T1 = ts(1751500001)
T2 = ts(1751500002)
T3 = ts(1751500003)
T4 = ts(1751500004)
T1_OFF = ts(1751500001, offset=1)


# ---------------------------------------------------------------------------
# 7. container DB (swift-db golden data; fixtures shared via this generator)
# ---------------------------------------------------------------------------

DB_CREATED_AT = '1751500000.00000'
DB_ID = 'fixed-db-id-0001'


def encode_container_db():
    import sqlite3
    import types as _types
    import swift.container.backend as cb
    import swift.common.db as cdb

    # determinism: fixed created_at and db id
    cb.NormalTimestamp = _FixedNormalTimestamp
    cdb.DatabaseBroker._new_db_id = lambda self: DB_ID

    def dump_schema(db_file):
        conn = sqlite3.connect(db_file)
        rows = conn.execute(
            'SELECT name, sql FROM sqlite_master ORDER BY name').fetchall()
        conn.close()
        return [[n, s] for n, s in rows]

    def dump_objects(db_file):
        conn = sqlite3.connect(db_file)
        rows = conn.execute(
            'SELECT ROWID, name, created_at, size, content_type, etag,'
            ' deleted, storage_policy_index FROM object'
            ' ORDER BY ROWID').fetchall()
        conn.close()
        return [list(r) for r in rows]

    def broker_in(tmp):
        db_file = os.path.join(tmp, 'containers', 'ctest.db')
        return cb.ContainerBroker(db_file, account='a', container='c')

    scenarios = []

    # sc1: initialize only
    with tempfile.TemporaryDirectory() as tmp:
        b = broker_in(tmp)
        b.initialize(T0.internal, 0)
        scenarios.append({
            'desc': 'init-only',
            'schema': dump_schema(b.db_file),
            'info': dict(b.get_info()),
            'objects': dump_objects(b.db_file),
        })

    # sc2: puts through the pending file, then merge
    puts_sc2 = [
        ['obj1', T1.internal, 42, 'text/plain;swift_bytes=10', 'etag1', 0],
        ['中文/☃', T2.internal, 0, 'application/octet-stream', 'etag2', 0],
        ['z-obj', T1_OFF.internal, 7, 'text/plain', 'etag3', 0],
    ]
    with tempfile.TemporaryDirectory() as tmp:
        b = broker_in(tmp)
        b.initialize(T0.internal, 0)
        for name, ts_, size, ct, etag, deleted in puts_sc2:
            b.put_object(name, ts_, size, ct, etag, deleted=deleted)
        with open(b.pending_file, 'rb') as f:
            pending_hex = f.read().hex()
        info = dict(b.get_info())  # commits pending
        pending_after = os.path.getsize(b.pending_file)
        shutil.copy(b.db_file, os.path.join(FIXTURE_DIR, 'container_sc2.db'))
        scenarios.append({
            'desc': 'puts-and-merge',
            'puts': puts_sc2,
            'pending_hex': pending_hex,
            'pending_size_after_commit': pending_after,
            'info': info,
            'objects': dump_objects(b.db_file),
        })

    # sc3: overwrites, stale writes and delete markers
    with tempfile.TemporaryDirectory() as tmp:
        b = broker_in(tmp)
        b.initialize(T0.internal, 0)
        b.put_object('o', T1.internal, 5, 'text/plain', 'e1')
        b.put_object('o', T0.internal, 99, 'stale/ct', 'e0')
        b.delete_object('gone', T2.internal)
        b.put_object('o2', T1.internal, 7, 'text/plain;swift_bytes=3', 'e2')
        dict(b.get_info())
        b.delete_object('o', T4.internal)
        info = dict(b.get_info())
        scenarios.append({
            'desc': 'overwrite-and-delete',
            'info': info,
            'objects': dump_objects(b.db_file),
        })

    # sc4: content-type and metadata timestamp merging (fast-POST rows)
    with tempfile.TemporaryDirectory() as tmp:
        b = broker_in(tmp)
        b.initialize(T0.internal, 0)
        b.put_object('x', T1.internal, 10, 'text/plain;swift_bytes=99', 'ex')
        dict(b.get_info())
        b.put_object('x', T1.internal, 10, 'text/updated', 'ex',
                     ctype_timestamp=T2.internal, meta_timestamp=T3.internal)
        dict(b.get_info())
        b.put_object('x', T1.internal, 10, 'text/ignored', 'ex',
                     ctype_timestamp=T0.internal)
        info = dict(b.get_info())
        scenarios.append({
            'desc': 'ctype-meta-merge',
            'info': info,
            'objects': dump_objects(b.db_file),
        })

    # sc5: duplicate names within one pending batch
    with tempfile.TemporaryDirectory() as tmp:
        b = broker_in(tmp)
        b.initialize(T0.internal, 0)
        b.put_object('dup', T2.internal, 2, 'ct/2', 'e2')
        b.put_object('dup', T1.internal, 1, 'ct/1', 'e1')
        b.put_object('dup', T3.internal, 3, 'ct/3', 'e3')
        info = dict(b.get_info())
        scenarios.append({
            'desc': 'batch-duplicates',
            'info': info,
            'objects': dump_objects(b.db_file),
        })

    return {
        'put_timestamp': T0.internal,
        'created_at': DB_CREATED_AT,
        'db_id': DB_ID,
        'scenarios': scenarios,
    }


DB_ID2 = 'fixed-db-id-0002'


def encode_account_db():
    import sqlite3
    import types as _types
    import swift.account.backend as ab
    import swift.common.db as cdb

    ab.NormalTimestamp = _FixedNormalTimestamp
    cdb.DatabaseBroker._new_db_id = lambda self: DB_ID2

    def dump_schema(db_file):
        conn = sqlite3.connect(db_file)
        rows = conn.execute(
            'SELECT name, sql FROM sqlite_master ORDER BY name').fetchall()
        conn.close()
        return [[n, s] for n, s in rows]

    def dump_containers(db_file):
        conn = sqlite3.connect(db_file)
        rows = conn.execute(
            'SELECT ROWID, name, put_timestamp, delete_timestamp,'
            ' object_count, bytes_used, deleted, storage_policy_index'
            ' FROM container ORDER BY ROWID').fetchall()
        conn.close()
        return [list(r) for r in rows]

    def dump_policy_stat(db_file):
        conn = sqlite3.connect(db_file)
        rows = conn.execute(
            'SELECT storage_policy_index, container_count, object_count,'
            ' bytes_used FROM policy_stat'
            ' ORDER BY storage_policy_index').fetchall()
        conn.close()
        return [list(r) for r in rows]

    def broker_in(tmp):
        db_file = os.path.join(tmp, 'accounts', 'atest.db')
        return ab.AccountBroker(db_file, account='AUTH_test')

    scenarios = []

    # a1: initialize only
    with tempfile.TemporaryDirectory() as tmp:
        b = broker_in(tmp)
        b.initialize(T0.internal)
        scenarios.append({
            'desc': 'a-init-only',
            'schema': dump_schema(b.db_file),
            'info': dict(b.get_info()),
            'containers': dump_containers(b.db_file),
            'policy_stat': dump_policy_stat(b.db_file),
        })

    # a2: put containers through pending (mixed str/int counts, policies)
    puts_a2 = [
        ['c1', T1.internal, '0', '0', '0', 0],
        ['中文容器', T2.internal, '0', 3, 42, 1],
        ['c-del', T1.internal, T3.internal, 0, 0, 0],
    ]
    with tempfile.TemporaryDirectory() as tmp:
        b = broker_in(tmp)
        b.initialize(T0.internal)
        for name, put_ts, del_ts, oc, bu, spi in puts_a2:
            b.put_container(name, put_ts, del_ts, oc, bu, spi)
        with open(b.pending_file, 'rb') as f:
            pending_hex = f.read().hex()
        info = dict(b.get_info())
        scenarios.append({
            'desc': 'a-puts-and-merge',
            'puts': puts_a2,
            'pending_hex': pending_hex,
            'info': info,
            'containers': dump_containers(b.db_file),
            'policy_stat': dump_policy_stat(b.db_file),
        })
        shutil.copy(b.db_file, os.path.join(FIXTURE_DIR, 'account_a2.db'))

    # a3: merge with existing rows (newest timestamps win, deleted recompute)
    with tempfile.TemporaryDirectory() as tmp:
        b = broker_in(tmp)
        b.initialize(T0.internal)
        b.put_container('c', T1.internal, '0', 5, 50, 0)
        dict(b.get_info())
        # older put with newer delete -> deleted (counts zero-like)
        b.put_container('c', T0.internal, T2.internal, 0, 0, 0)
        dict(b.get_info())
        # resurrect with newer put
        b.put_container('c', T3.internal, '0', '7', '70', 0)
        info = dict(b.get_info())
        scenarios.append({
            'desc': 'a-merge-semantics',
            'info': info,
            'containers': dump_containers(b.db_file),
            'policy_stat': dump_policy_stat(b.db_file),
        })

    return {
        'put_timestamp': T0.internal,
        'created_at': DB_CREATED_AT,
        'db_id': DB_ID2,
        'scenarios': scenarios,
    }



def container_listing_matrix(b):
    cases = []
    calls = [
        dict(limit=100, marker='', end_marker='', prefix=None, delimiter=None),
        dict(limit=3, marker='', end_marker='', prefix=None, delimiter=None),
        dict(limit=100, marker='b', end_marker='', prefix=None, delimiter=None),
        dict(limit=100, marker='', end_marker='c', prefix=None, delimiter=None),
        dict(limit=100, marker='', end_marker='', prefix='photos/',
             delimiter=None),
        dict(limit=100, marker='', end_marker='', prefix='photos/',
             delimiter='/'),
        dict(limit=100, marker='', end_marker='', prefix='', delimiter='/'),
        dict(limit=100, marker='', end_marker='', prefix=None, delimiter='/'),
        dict(limit=100, marker='photos/animals/', end_marker='', prefix='photos/',
             delimiter='/'),
        dict(limit=100, marker='', end_marker='', prefix=None, delimiter=None,
             reverse=True),
        dict(limit=2, marker='', end_marker='', prefix='photos/',
             delimiter='/', reverse=True),
        dict(limit=100, marker='', end_marker='', prefix=None, delimiter=None,
             path='photos'),
        dict(limit=100, marker='', end_marker='', prefix=None, delimiter=None,
             path=''),
        dict(limit=100, marker='', end_marker='', prefix=None, delimiter=None,
             include_deleted=True),
        dict(limit=100, marker='a/', end_marker='中/文2', prefix=None,
             delimiter=None),
        dict(limit=100, marker='', end_marker='', prefix='b', delimiter='/'),
    ]
    for call in calls:
        rows = b.list_objects_iter(
            call['limit'], call['marker'], call['end_marker'],
            call['prefix'], call['delimiter'], path=call.get('path'),
            storage_policy_index=0, reverse=call.get('reverse', False),
            include_deleted=call.get('include_deleted', False))
        cases.append({'call': call, 'rows': [list(r) for r in rows]})
    return cases


def encode_container_extras():
    import swift.container.backend as cb

    scenarios = {}
    # listings
    with tempfile.TemporaryDirectory() as tmp:
        db_file = os.path.join(tmp, 'containers', 'ctest.db')
        b = cb.ContainerBroker(db_file, account='a', container='c')
        b.initialize(T0.internal, 0)
        objects = [
            ('a/1', T1, 1, 'text/a', 'e1', 0),
            ('a/2', T1, 2, 'text/a', 'e2', 0),
            ('b', T2, 3, 'text/b', 'e3', 0),
            ('b/', T2, 4, 'text/b', 'e4', 0),
            ('b/x', T2, 5, 'text/b', 'e5', 0),
            ('c', T1, 6, 'text/c', 'e6', 0),
            ('photos/animals/cat.jpg', T2, 7, 'image/jpeg', 'e7', 0),
            ('photos/animals/dog.jpg', T3, 8, 'image/jpeg', 'e8', 0),
            ('photos/plants/rose.jpg', T3, 9, 'image/jpeg', 'e9', 0),
            ('photos', T1, 10, 'app/dir', 'e10', 0),
            ('中/文', T2, 11, 'text/zh', 'e11', 0),
            ('zz', T1, 12, 'text/z', 'e12', 0),
            ('deleted-obj', T2, 0, 'application/deleted', 'noetag', 1),
        ]
        for name, ts_, size, ct, etag, deleted in objects:
            b.put_object(name, ts_.internal, size, ct, etag, deleted=deleted)
        dict(b.get_info())
        scenarios['listings'] = {
            'objects': [[n, t.internal, s, c, e, d]
                        for n, t, s, c, e, d in objects],
            'cases': container_listing_matrix(b),
        }

    # metadata + delete_db + reclaim
    with tempfile.TemporaryDirectory() as tmp:
        db_file = os.path.join(tmp, 'containers', 'ctest.db')
        b = cb.ContainerBroker(db_file, account='a', container='c')
        b.initialize(T0.internal, 0)
        steps = []
        b.update_metadata({'X-Container-Meta-Color': ['blue', T1.internal]})
        steps.append(['set-color', b.get_raw_metadata()])
        b.update_metadata({
            'X-Container-Meta-Color': ['red', T3.internal],
            'X-Container-Sysmeta-S': ['sv', T1.internal],
            'X-Container-Meta-中文': ['值\u0001"x"', T1.internal]})
        steps.append(['newer-and-more', b.get_raw_metadata()])
        b.update_metadata({'X-Container-Meta-Color': ['green', T2.internal]})
        steps.append(['older-ignored', b.get_raw_metadata()])
        b.update_metadata({'X-Container-Meta-中文': ['', T2.internal]})
        steps.append(['delete-key', b.get_raw_metadata()])
        # tombstone rows for reclaim
        b.put_object('old-tomb', ts(1000000000).internal, 0,
                     'application/deleted', 'noetag', deleted=1)
        b.put_object('new-tomb', T2.internal, 0,
                     'application/deleted', 'noetag', deleted=1)
        b.put_object('live', T2.internal, 5, 'text/x', 'el')
        dict(b.get_info())
        reclaimer = b.reclaim(1500000000.5, 1500000000.5)
        steps.append(['post-reclaim-metadata', b.get_raw_metadata()])
        import sqlite3 as sq
        conn = sq.connect(b.db_file)
        names = [r[0] for r in conn.execute(
            'SELECT name FROM object ORDER BY name')]
        conn.close()
        b.delete_db(T4.internal)
        info = dict(b.get_info())
        scenarios['metadata'] = {
            'steps': steps,
            'reclaim_age_timestamp': 1500000000.5,
            'reclaimed': reclaimer.reclaimed,
            'post_reclaim_names': names,
            'post_delete_info': info,
            'post_delete_metadata': b.get_raw_metadata(),
            'is_deleted': b.is_deleted(),
        }
    return scenarios


def account_listing_matrix(b):
    cases = []
    calls = [
        dict(limit=100, marker='', end_marker='', prefix=None, delimiter=None),
        dict(limit=2, marker='', end_marker='', prefix=None, delimiter=None),
        dict(limit=100, marker='apple', end_marker='', prefix=None,
             delimiter=None),
        dict(limit=100, marker='', end_marker='cherry', prefix=None,
             delimiter=None),
        dict(limit=100, marker='', end_marker='', prefix='apple',
             delimiter='/'),
        dict(limit=100, marker='', end_marker='', prefix='', delimiter='/'),
        dict(limit=100, marker='', end_marker='', prefix=None, delimiter=None,
             reverse=True),
        dict(limit=100, marker='', end_marker='', prefix='cherry/',
             delimiter='/'),
    ]
    for call in calls:
        rows = b.list_containers_iter(
            call['limit'], call['marker'], call['end_marker'],
            call['prefix'], call['delimiter'],
            reverse=call.get('reverse', False))
        cases.append({'call': call, 'rows': [list(r) for r in rows]})
    return cases


def encode_account_extras():
    import swift.account.backend as ab

    scenarios = {}
    with tempfile.TemporaryDirectory() as tmp:
        db_file = os.path.join(tmp, 'accounts', 'atest.db')
        b = ab.AccountBroker(db_file, account='AUTH_test')
        b.initialize(T0.internal)
        containers = [
            ('apple', T1, '0', 3, 30, 0),
            ('apple/pie', T1, '0', 1, 10, 0),
            ('apple/tart', T2, '0', 2, 20, 1),
            ('banana', T2, '0', 0, 0, 0),
            ('cherry/tart', T2, '0', 5, 50, 0),
            ('中文', T2, '0', 1, 1, 0),
            ('gone', T1, T3.internal, 0, 0, 0),
        ]
        for name, put_ts, del_ts, oc, bu, spi in containers:
            b.put_container(name, put_ts.internal, del_ts
                            if isinstance(del_ts, str) else del_ts,
                            oc, bu, spi)
        dict(b.get_info())
        scenarios['listings'] = {
            'containers': [[n, p.internal,
                            d if isinstance(d, str) else d, oc, bu, spi]
                           for n, p, d, oc, bu, spi in containers],
            'cases': account_listing_matrix(b),
        }

    with tempfile.TemporaryDirectory() as tmp:
        db_file = os.path.join(tmp, 'accounts', 'atest.db')
        b = ab.AccountBroker(db_file, account='AUTH_test')
        b.initialize(T0.internal)
        b.update_metadata({'X-Account-Meta-Temp': ['1', T1.internal],
                           'X-Account-Meta-Gone': ['', ts(1000000000).internal]})
        raw_before = b.get_raw_metadata()
        b.reclaim(1500000000.5, 1500000000.5)
        raw_after = b.get_raw_metadata()
        b.delete_db(T4.internal)
        scenarios['metadata'] = {
            'raw_before': raw_before,
            'raw_after': raw_after,
            'post_delete_metadata': b.get_raw_metadata(),
            'post_delete_info': dict(b.get_info()),
            'is_deleted': b.is_deleted(),
        }
    return scenarios


def main():
    container = encode_container_db()
    container.update(encode_container_extras())
    account = encode_account_db()
    account.update(encode_account_extras())
    with open(os.path.join(FIXTURE_DIR, 'expectations.json'), 'w') as fp:
        json.dump({'container': container, 'account': account},
                  fp, indent=1, sort_keys=True)
    print('wrote fixtures to', FIXTURE_DIR)


if __name__ == '__main__':
    main()
