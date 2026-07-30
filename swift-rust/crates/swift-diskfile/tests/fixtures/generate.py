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
Generate golden diskfile fixtures using the *real* Python Swift
implementation.

Run from the repository root:

    python3 rust/crates/swift-diskfile/tests/fixtures/generate.py

Produces expectations.json capturing:
  - canonical pickle bytes for object metadata (as written into xattrs)
  - on-disk file selection results (get_ondisk_files) for both the
    replication and EC diskfile managers
  - hashes.pkl encode/decode expectations
  - whole-partition suffix hashing (_get_hashes) flows, including
    cleanup/reclaim side effects and invalidation/consolidation

NOTE on pyeclib: swift.obj.diskfile imports pyeclib at module level, but
none of the code paths exercised here touch the EC codec (we only use
filename parsing and file-selection logic, always with policy=None). To
avoid requiring the native liberasurecode build on the fixture machine we
install a minimal import shim. No EC encode/decode result is derived from
the shim.
"""
import hashlib
import json
import os
import pickle
import shutil
import sys
import tempfile
import types

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

# ---- pyeclib import shim (see module docstring) ----
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

import swift.obj.diskfile as df  # noqa: E402
import swift.common.exceptions as df_exceptions  # noqa: E402
from swift.common.utils import Timestamp  # noqa: E402


class NullLogger(object):
    def __getattr__(self, name):
        return lambda *a, **kw: None


REPL_MGR = df.DiskFileManager({'commit_window': '0'}, NullLogger())
EC_MGR = df.ECDiskFileManager({'commit_window': '0'}, NullLogger())


def ts(secs, offset=0):
    return Timestamp(secs, offset=offset)


def meta_name(mgr, t, ctype_t=None):
    return mgr.make_on_disk_filename(t, '.meta', ctype_timestamp=ctype_t)


# ---------------------------------------------------------------------------
# 1. metadata pickle corpus
# ---------------------------------------------------------------------------

def big_dict():
    # >255 memo entries forces LONG_BINPUT; >1000 items forces a second
    # SETITEMS batch.
    d = {'name': '/a/c/big'}
    for i in range(1050):
        d['X-Object-Meta-K%04d' % i] = 'value-%04d' % i
    return d


PICKLE_CASES = [
    ('empty', {}),
    ('basic', {'name': '/a/c/o',
               'X-Timestamp': '1751500000.00000',
               'Content-Length': '5',
               'Content-Type': 'application/octet-stream',
               'ETag': 'd41d8cd98f00b204e9800998ecf8427e'}),
    ('unicode', {'name': '/AUTH_test/\N{SNOWMAN}/中文对象',
                 'X-Timestamp': '1751500001.00000_0000000000000002',
                 'X-Object-Meta-Mood': '😀 émoji',
                 'Content-Length': '0'}),
    ('int-value', {'name': '/a/c/o', 'Content-Length': 12345,
                   'X-Big': 5000000000, 'X-Small': 7}),
    ('non-utf8-value', {'name': '/a/c/o',
                        'X-Object-Meta-Raw': b'\xff\xfe\x01raw'}),
    ('long-value', {'name': '/a/c/long',
                    'X-Object-Meta-Blob': 'x' * 70000}),
    ('big-dict', big_dict()),
]


def encode_pickle_cases():
    out = []
    for desc, d in PICKLE_CASES:
        blob = pickle.dumps(df._encode_metadata(d), df.PICKLE_PROTOCOL)
        # what Python would logically read back
        decoded = df._decode_metadata(
            pickle.loads(blob, encoding='bytes'), True)
        entry = {
            'desc': desc,
            'blob': blob.hex(),
            'checksum': hashlib.md5(blob).hexdigest(),
            'pairs': [],
            'raw_values': {},
        }
        for k, v in d.items():
            if isinstance(v, bytes):
                # non-utf8-capable values are recorded raw; the Rust side
                # exposes them as byte strings
                entry['raw_values'][k] = v.hex()
                entry['pairs'].append([k, None])
            else:
                entry['pairs'].append([k, v])
        # sanity: python round trip preserves logical values
        for k, v in d.items():
            if isinstance(v, bytes):
                assert decoded[k].encode('utf8', 'surrogateescape') == v
            else:
                assert decoded[k] == v, (k, decoded[k], v)
        out.append(entry)
    return out


def legacy_py2_pickle():
    # Hand-assembled protocol-2 pickle using SHORT_BINSTRING, as py2 swift
    # wrote it (py2 str pickles directly, no _codecs.encode reduce).
    def short_binstring(b):
        return b'U' + bytes([len(b)]) + b

    items = [(b'name', b'/a/c/py2'),
             (b'X-Timestamp', b'1400000000.00000'),
             (b'X-Object-Meta-M\xf6t', b'caf\xe9')]  # latin1 bytes
    body = b'\x80\x02}q\x00('
    memo = 1
    for k, v in items:
        body += short_binstring(k) + b'q' + bytes([memo])
        memo += 1
        body += short_binstring(v) + b'q' + bytes([memo])
        memo += 1
    body += b'u.'
    loaded = pickle.loads(body, encoding='bytes')
    decoded = df._decode_metadata(loaded, False)
    return {
        'desc': 'legacy-py2-latin1',
        'blob': body.hex(),
        'pairs': [[k, v] for k, v in decoded.items()],
    }


# ---------------------------------------------------------------------------
# 2. get_ondisk_files scenarios
# ---------------------------------------------------------------------------

T0 = ts(1751500000)
T1 = ts(1751500001)
T2 = ts(1751500002)
T3 = ts(1751500003)
T4 = ts(1751500004)
T1_OFF = ts(1751500001, offset=1)

REPL_SCENARIOS = [
    ('r-empty', []),
    ('r-data-only', ['%s.data' % T1.internal]),
    ('r-two-datas', ['%s.data' % T2.internal, '%s.data' % T1.internal]),
    ('r-data-newer-meta', ['%s.meta' % T2.internal, '%s.data' % T1.internal]),
    ('r-data-older-meta', ['%s.meta' % T1.internal, '%s.data' % T2.internal]),
    ('r-data-same-ts-meta',
     ['%s.meta' % T1.internal, '%s.data' % T1.internal]),
    ('r-ts-only', ['%s.ts' % T1.internal]),
    ('r-ts-over-data', ['%s.ts' % T2.internal, '%s.data' % T1.internal]),
    ('r-data-over-ts', ['%s.data' % T2.internal, '%s.ts' % T1.internal]),
    ('r-two-ts', ['%s.ts' % T2.internal, '%s.ts' % T1.internal]),
    ('r-many-metas', ['%s.meta' % T3.internal, '%s.meta' % T2.internal,
                      '%s.data' % T1.internal]),
    ('r-meta-only', ['%s.meta' % T2.internal]),
    ('r-offset-data', ['%s.data' % T1_OFF.internal, '%s.data' % T1.internal]),
    ('r-garbage', ['not-a-timestamp.data', '.1234567890.data.Xy095a',
                   '%s.data' % T1.internal]),
    ('r-ctype-split',
     # newest meta at T3 (no ctype); older meta at T2 carrying newer ctype T4
     [meta_name(REPL_MGR, T3), meta_name(REPL_MGR, T2, T4),
      '%s.data' % T1.internal]),
    ('r-ctype-same-ts',
     # both metas at T3, one with newer ctype: only the ctype one retained
     [meta_name(REPL_MGR, T3), meta_name(REPL_MGR, T3, T4),
      '%s.data' % T1.internal]),
    ('r-ctype-older-than-data',
     [meta_name(REPL_MGR, T2, T1), '%s.data' % T1_OFF.internal]),
    ('r-complex',
     ['%s.meta' % T4.internal, '%s.data' % T3.internal,
      '%s.ts' % T2.internal, '%s.data' % T1.internal,
      '%s.meta' % T0.internal]),
]

EC_SCENARIOS = [
    # (desc, files, kwargs)
    ('e-durable-frag', ['%s#2#d.data' % T1.internal], {}),
    ('e-nondurable-frag', ['%s#2.data' % T1.internal], {}),
    ('e-legacy-durable',
     ['%s.durable' % T1.internal, '%s#3.data' % T1.internal], {}),
    ('e-two-frags-one-durable',
     ['%s#3#d.data' % T1.internal, '%s#5.data' % T1.internal], {}),
    ('e-newer-nondurable-set',
     ['%s#1.data' % T2.internal, '%s#3#d.data' % T1.internal], {}),
    ('e-newer-nondurable-set-prefs',
     ['%s#1.data' % T2.internal, '%s#3#d.data' % T1.internal],
     {'frag_prefs': []}),
    ('e-prefs-exclude',
     ['%s#1.data' % T2.internal, '%s#4.data' % T2.internal,
      '%s#3#d.data' % T1.internal],
     {'frag_prefs': [{'timestamp': T2, 'exclude': [1, 4]},
                     {'timestamp': T1, 'exclude': []}]}),
    ('e-prefs-pick-highest',
     ['%s#1.data' % T2.internal, '%s#4.data' % T2.internal,
      '%s#3#d.data' % T1.internal],
     {'frag_prefs': [{'timestamp': T2, 'exclude': [4]}]}),
    ('e-frag-index-hit',
     ['%s#3#d.data' % T1.internal, '%s#5#d.data' % T1.internal],
     {'frag_index': 3}),
    ('e-frag-index-miss',
     ['%s#3#d.data' % T1.internal, '%s#5#d.data' % T1.internal],
     {'frag_index': 7}),
    ('e-ts-over-durable',
     ['%s.ts' % T2.internal, '%s#3#d.data' % T1.internal], {}),
    ('e-meta-hidden-between',
     # durable at T1, meta at T2, non-durable frags at T3 chosen via prefs;
     # the meta between chosen and durable must be hidden, not obsolete
     ['%s#2.data' % T3.internal, '%s.meta' % T2.internal,
      '%s#2#d.data' % T1.internal],
     {'frag_prefs': [{'timestamp': T3, 'exclude': []}]}),
    ('e-isolated-durable', ['%s.durable' % T1.internal], {}),
    ('e-durable-supersedes-legacy',
     ['%s#1#d.data' % T2.internal, '%s.durable' % T1.internal,
      '%s#1.data' % T1.internal], {}),
    ('e-meta-over-durable',
     ['%s.meta' % T2.internal, '%s#0#d.data' % T1.internal], {}),
    ('e-bad-frag-index',
     ['%s#x.data' % T1.internal, '%s#-1.data' % T1.internal,
      '%s.data' % T2.internal, '%s#0#d.data' % T0.internal], {}),
]


def run_ondisk_scenario(mgr, files, kwargs):
    r = mgr.get_ondisk_files(list(files), '/dd', policy=None, **kwargs)
    out = {}
    for key in ('data_file', 'meta_file', 'ts_file', 'ctype_file'):
        out[key] = os.path.basename(r[key]) if r[key] else None
    for key in ('obsolete', 'possible_reclaim'):
        out[key] = sorted(i['filename'] for i in r.get(key, []))
    out['unexpected'] = sorted(
        os.path.basename(p) for p in r.get('unexpected', []))
    if 'data_info' in r:
        out['data_durable'] = bool(r['data_info'].get('durable', False))
    if r.get('durable_frag_set'):
        out['durable_timestamp'] = r['durable_frag_set'][0][
            'timestamp'].internal
    return out


def encode_ondisk():
    out = []
    for desc, files in REPL_SCENARIOS:
        out.append({'desc': desc, 'policy': 'repl', 'files': files,
                    'result': run_ondisk_scenario(REPL_MGR, files, {})})
    for desc, files, kwargs in EC_SCENARIOS:
        jk = {}
        if 'frag_index' in kwargs:
            jk['frag_index'] = kwargs['frag_index']
        if 'frag_prefs' in kwargs:
            jk['frag_prefs'] = [
                {'timestamp': p['timestamp'].internal,
                 'exclude': p['exclude']}
                for p in kwargs['frag_prefs']]
        out.append({'desc': desc, 'policy': 'ec', 'files': files,
                    'result': run_ondisk_scenario(EC_MGR, files, kwargs),
                    **jk})
    return out


# ---------------------------------------------------------------------------
# 3. hashes.pkl corpus
# ---------------------------------------------------------------------------

FROZEN_TIME = 1751512345.678901


def encode_hashes_pkl():
    real_time = df.time.time
    df.time.time = lambda: FROZEN_TIME
    try:
        write_cases = []
        for desc, hashes in [
            ('repl', {'abc': 'd41d8cd98f00b204e9800998ecf8427e',
                      '07f': None, 'valid': True}),
            ('needs-valid', {'abc': None}),
            ('ec-nested', {'abc': {3: '68b329da9893e34099c7d8ad5cb9c940',
                                   None: '5d41402abc4b2a76b9719d911017c592'},
                           'valid': True}),
        ]:
            hashes = dict(hashes)  # write_hashes mutates
            # replicate write_hashes' pickling without the file dance
            hashes.setdefault('valid', False)
            hashes['updated'] = df.time.time()
            blob = pickle.dumps(hashes, df.PICKLE_PROTOCOL)

            def norm_value(v):
                if isinstance(v, dict):
                    return {('null' if k is None else str(k)): sv
                            for k, sv in v.items()}
                return v

            write_cases.append({
                'desc': desc,
                'blob': blob.hex(),
                'pairs': [[k, norm_value(v)] for k, v in hashes.items()],
            })
    finally:
        df.time.time = real_time

    read_cases = []
    tmp = tempfile.mkdtemp()
    try:
        for desc, raw in [
            ('valid', pickle.dumps(
                {'abc': 'd41d8cd98f00b204e9800998ecf8427e',
                 'valid': True, 'updated': FROZEN_TIME}, 2)),
            ('no-valid-key', pickle.dumps(
                {'abc': 'd41d8cd98f00b204e9800998ecf8427e'}, 2)),
            ('corrupt', b'\x80\x02not really a pickle'),
            ('bad-suffix-key', pickle.dumps(
                {'zzzz': 'x', 'valid': True}, 2)),
            ('non-str-key', pickle.dumps({3: 'x', 'valid': True}, 2)),
            ('empty-file', b''),
            ('missing-file', None),
        ]:
            pdir = os.path.join(tmp, desc)
            os.makedirs(pdir)
            if raw is not None:
                with open(os.path.join(pdir, df.HASH_FILE), 'wb') as f:
                    f.write(raw)
            got = df.read_hashes(pdir)
            read_cases.append({
                'desc': desc,
                'blob': raw.hex() if raw is not None else None,
                'expected': {str(k): v for k, v in got.items()},
            })
    finally:
        shutil.rmtree(tmp)
    return {'frozen_time': FROZEN_TIME,
            'write_cases': write_cases, 'read_cases': read_cases}


# ---------------------------------------------------------------------------
# 4. partition suffix-hashing flows
# ---------------------------------------------------------------------------

OLD = ts(1000000000)          # 2001: reclaimable forever after
FUT = ts(3286000000)          # 2074: not reclaimable for decades
FUT2 = ts(3286000001)
FUT3 = ts(3286000002)


def build_tree(dev_dir, datadir_name, tree):
    for hashdir_rel, files in tree.items():
        hd = os.path.join(dev_dir, datadir_name, hashdir_rel)
        os.makedirs(hd, exist_ok=True)
        for fname in files:
            with open(os.path.join(hd, fname), 'wb'):
                pass


def snapshot_tree(dev_dir, datadir_name, partition):
    part_dir = os.path.join(dev_dir, datadir_name, partition)
    out = {}
    for root, dirs, files in os.walk(part_dir):
        rel = os.path.relpath(root, part_dir)
        interesting = [f for f in files
                       if not f.startswith('.lock')
                       and f != df.HASH_FILE
                       and f != df.HASH_INVALIDATIONS_FILE]
        if rel != '.' and len(rel.split(os.sep)) == 2:
            out[rel] = sorted(interesting)
    return out


def normalize_hashes(hashes):
    out = {}
    for suffix, h in hashes.items():
        if isinstance(h, dict):
            out[suffix] = {('null' if k is None else str(k)): v
                           for k, v in h.items()}
        else:
            out[suffix] = h
    return out


def encode_partitions():
    cases = []

    # --- repl partition: clean, obsolete and reclaimable content
    repl_tree = {
        # suffix abc: hashdir with live data+meta, second hashdir where an
        # older data must be deleted
        '1234/abc/00000000000000000000000000000abc': [
            '%s.data' % FUT.internal, '%s.meta' % FUT2.internal],
        '1234/abc/11111111111111111111111111111abc': [
            '%s.data' % FUT2.internal, '%s.data' % FUT.internal],
        # suffix def: only an ancient tombstone -> reclaimed, suffix dropped
        '1234/def/22222222222222222222222222222def': [
            '%s.ts' % OLD.internal],
        # suffix f00: recent tombstone survives
        '1234/f00/33333333333333333333333333333f00': [
            '%s.ts' % FUT.internal],
    }
    with tempfile.TemporaryDirectory() as tmp:
        dev = os.path.join(tmp, 'sda1')
        build_tree(dev, 'objects', repl_tree)
        mgr = df.DiskFileManager(
            {'devices': tmp, 'mount_check': 'false', 'commit_window': '0'},
            NullLogger())
        from swift.common.storage_policy import POLICIES
        hashed, hashes = mgr._get_hashes('sda1', '1234', POLICIES[0])
        cases.append({
            'desc': 'repl-basic',
            'policy': 'repl',
            'partition': '1234',
            'tree': repl_tree,
            'hashed': hashed,
            'hashes': normalize_hashes(hashes),
            'survivors': snapshot_tree(dev, 'objects', '1234'),
        })

        # --- second run: invalidate one suffix after adding a newer file
        hd = os.path.join(dev, 'objects',
                          '1234/abc/00000000000000000000000000000abc')
        with open(os.path.join(hd, '%s.meta' % FUT3.internal), 'wb'):
            pass
        df.invalidate_hash(os.path.dirname(hd))
        hashed2, hashes2 = mgr._get_hashes('sda1', '1234', POLICIES[0])
        cases.append({
            'desc': 'repl-invalidate-rehash',
            'policy': 'repl',
            'partition': '1234',
            'tree': None,  # continues previous state
            'added': {'1234/abc/00000000000000000000000000000abc':
                      ['%s.meta' % FUT3.internal]},
            'hashed': hashed2,
            'hashes': normalize_hashes(hashes2),
            'survivors': snapshot_tree(dev, 'objects', '1234'),
        })

    # --- EC partition
    ec_tree = {
        # durable set with two frags
        '99/ab0/00000000000000000000000000000ab0': [
            '%s#3#d.data' % FUT.internal, '%s#5.data' % FUT.internal],
        # legacy durable
        '99/ab0/11111111111111111111111111111ab0': [
            '%s.durable' % FUT.internal, '%s#1.data' % FUT.internal],
        # ancient non-durable stray: reclaimed (commit_window=0)
        '99/cd0/22222222222222222222222222222cd0': [
            '%s#4.data' % OLD.internal],
        # recent non-durable frag survives, but suffix hash reflects it
        '99/ef0/33333333333333333333333333333ef0': [
            '%s#2.data' % FUT2.internal,
            '%s.meta' % FUT3.internal],
    }
    with tempfile.TemporaryDirectory() as tmp:
        dev = os.path.join(tmp, 'sda1')
        build_tree(dev, 'objects-2', ec_tree)
        mgr = df.ECDiskFileManager(
            {'devices': tmp, 'mount_check': 'false', 'commit_window': '0'},
            NullLogger())

        from swift.common.storage_policy import StoragePolicy
        # only .idx is consulted by these code paths; a replication-type
        # policy object at index 2 stands in for the EC policy because
        # constructing a real ECStoragePolicy requires the native EC driver
        fake_ec_policy = StoragePolicy(2, 'fake-ec')
        # frag-index validation consults these; 4+2 covers every index
        # used in the fixture tree
        fake_ec_policy.ec_ndata = 4
        fake_ec_policy.ec_nparity = 2
        hashed, hashes = mgr._get_hashes('sda1', '99', fake_ec_policy)
        cases.append({
            'desc': 'ec-basic',
            'policy': 'ec',
            'partition': '99',
            'tree': ec_tree,
            'hashed': hashed,
            'hashes': normalize_hashes(hashes),
            'survivors': snapshot_tree(dev, 'objects-2', '99'),
        })
    return cases


# ---------------------------------------------------------------------------
# 5. live xattr chunk layout (real python write_metadata + real xattrs)
# ---------------------------------------------------------------------------

def encode_xattr_layout():
    import xattr as pyxattr
    d = {'name': '/a/c/o', 'X-Timestamp': '1751500000.00000',
         'X-Object-Meta-Blob': 'y' * 700}
    blob = pickle.dumps(df._encode_metadata(d), df.PICKLE_PROTOCOL)
    out = {'blob': blob.hex(),
           'checksum': hashlib.md5(blob).hexdigest()}
    with tempfile.NamedTemporaryFile() as f:
        df.write_metadata(f.name, d, xattr_size=254)
        keys = sorted(k for k in pyxattr.listxattr(f.name)
                      if k.startswith('user.swift.metadata')
                      and 'checksum' not in k)
        chunks = []
        i = 0
        while True:
            key = 'user.swift.metadata' + (str(i) if i else '')
            if key not in keys:
                break
            chunks.append(len(pyxattr.getxattr(f.name, key)))
            i += 1
        reassembled = b''.join(
            pyxattr.getxattr(f.name, 'user.swift.metadata' +
                             (str(i) if i else ''))
            for i in range(len(chunks)))
        assert reassembled == blob
        checksum_attr = pyxattr.getxattr(
            f.name, 'user.swift.metadata_checksum').decode('ascii')
        assert checksum_attr == out['checksum']
        out['chunk_sizes_254'] = chunks
        out['xattr_keys'] = keys
        # verify python reads back what it wrote
        got = df.read_metadata(f.name)
        assert got == d, got
    return out


# ---------------------------------------------------------------------------
# 6. DiskFile lifecycle scenarios (open/merge/put/commit/delete)
# ---------------------------------------------------------------------------

def hashdir_snapshot(datadir):
    try:
        return sorted(os.listdir(datadir))
    except FileNotFoundError:
        return None


def xattr_blob(path):
    import xattr as pyxattr
    blob = b''
    i = 0
    while True:
        try:
            blob += pyxattr.getxattr(
                path, 'user.swift.metadata' + (str(i) if i else ''))
        except OSError:
            break
        i += 1
    return blob.hex()


def open_result(df, current_time):
    try:
        df.open(current_time=current_time)
    # NB: DiskFileExpired subclasses DiskFileDeleted, so it must be
    # caught first
    except df_exceptions.DiskFileExpired as e:
        return {'error': 'expired', 'metadata': dict(e.metadata)}
    except df_exceptions.DiskFileDeleted as e:
        return {'error': 'deleted',
                'timestamp': e.timestamp.internal,
                'metadata': dict(e.metadata)}
    except df_exceptions.DiskFileNotExist:
        return {'error': 'not_exist'}
    except df_exceptions.DiskFileCollision:
        return {'error': 'collision'}
    except df_exceptions.DiskFileQuarantined:
        return {'error': 'quarantined'}
    out = {
        'metadata': dict(df.get_metadata()),
        'datafile_metadata': dict(df.get_datafile_metadata()),
        'metafile_metadata': (dict(df.get_metafile_metadata())
                              if df.get_metafile_metadata() else None),
        'content_length': df.content_length,
        'data_timestamp': df.data_timestamp.internal,
        'timestamp': df.timestamp.internal,
        'content_type': df.content_type,
        'content_type_timestamp': df.content_type_timestamp.internal,
        'durable_timestamp': (df.durable_timestamp.internal
                              if df.durable_timestamp else None),
    }
    df._fp.close()
    df._fp = None
    return out


def encode_lifecycle():
    from swift.common.storage_policy import POLICIES, StoragePolicy
    scenarios = []
    body = b'hello swift'
    etag = hashlib.md5(body).hexdigest()

    def make_repl(tmp):
        os.makedirs(os.path.join(tmp, 'sda1'), exist_ok=True)
        return df.DiskFileManager(
            {'devices': tmp, 'mount_check': 'false', 'commit_window': '0'},
            NullLogger())

    def put_object(dfobj, put_meta):
        with dfobj.create() as writer:
            writer.write(body)
            writer.put(dict(put_meta))

    put_meta = {
        'X-Timestamp': T1.internal,
        'Content-Type': 'text/plain',
        'ETag': etag,
        'Content-Length': str(len(body)),
        'X-Object-Sysmeta-Origin': 'put',
        'X-Object-Meta-User': 'original',
    }

    # A: put then open (repl)
    with tempfile.TemporaryDirectory() as tmp:
        mgr = make_repl(tmp)
        dfobj = mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0])
        put_object(dfobj, put_meta)
        datadir = dfobj._datadir
        data_path = os.path.join(datadir, '%s.data' % T1.internal)
        scenarios.append({
            'desc': 'repl-put-open',
            'policy': 'repl', 'acco': ['a', 'c', 'o'],
            'ops': [{'op': 'put', 'body': body.decode(),
                     'metadata': [[k, v] for k, v in put_meta.items()]}],
            'tree': hashdir_snapshot(datadir),
            'data_xattr_blob': xattr_blob(data_path),
            'open': open_result(
                mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0]),
                FROZEN_TIME),
        })

    # B: put + fast-POST metadata, sysmeta must survive from the data file
    post_meta = {
        'X-Timestamp': T3.internal,
        'X-Object-Meta-User': 'updated',
        'X-Object-Sysmeta-Origin': 'post-should-lose',
    }
    with tempfile.TemporaryDirectory() as tmp:
        mgr = make_repl(tmp)
        dfobj = mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0])
        put_object(dfobj, put_meta)
        dfobj.write_metadata(dict(post_meta))
        datadir = dfobj._datadir
        scenarios.append({
            'desc': 'repl-post-merge',
            'policy': 'repl', 'acco': ['a', 'c', 'o'],
            'ops': [{'op': 'put', 'body': body.decode(),
                     'metadata': [[k, v] for k, v in put_meta.items()]},
                    {'op': 'post',
                     'metadata': [[k, v] for k, v in post_meta.items()]}],
            'tree': hashdir_snapshot(datadir),
            'open': open_result(
                mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0]),
                FROZEN_TIME),
        })

    # C: two metas, older one carrying newer content-type (ctype split)
    post_ctype = {
        'X-Timestamp': T2.internal,
        'Content-Type': 'application/x-updated',
        'Content-Type-Timestamp': T4.internal,
        'X-Object-Meta-User': 'ctype-writer',
    }
    with tempfile.TemporaryDirectory() as tmp:
        mgr = make_repl(tmp)
        dfobj = mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0])
        put_object(dfobj, put_meta)
        dfobj.write_metadata(dict(post_ctype))
        dfobj.write_metadata(dict(post_meta))
        datadir = dfobj._datadir
        scenarios.append({
            'desc': 'repl-ctype-split-merge',
            'policy': 'repl', 'acco': ['a', 'c', 'o'],
            'ops': [{'op': 'put', 'body': body.decode(),
                     'metadata': [[k, v] for k, v in put_meta.items()]},
                    {'op': 'post',
                     'metadata': [[k, v] for k, v in post_ctype.items()]},
                    {'op': 'post',
                     'metadata': [[k, v] for k, v in post_meta.items()]}],
            'tree': hashdir_snapshot(datadir),
            'open': open_result(
                mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0]),
                FROZEN_TIME),
        })

    # D: delete -> tombstone
    with tempfile.TemporaryDirectory() as tmp:
        mgr = make_repl(tmp)
        dfobj = mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0])
        put_object(dfobj, put_meta)
        dfobj.delete(T2)
        datadir = dfobj._datadir
        ts_path = os.path.join(datadir, '%s.ts' % T2.internal)
        scenarios.append({
            'desc': 'repl-delete',
            'policy': 'repl', 'acco': ['a', 'c', 'o'],
            'ops': [{'op': 'put', 'body': body.decode(),
                     'metadata': [[k, v] for k, v in put_meta.items()]},
                    {'op': 'delete', 'timestamp': T2.internal}],
            'tree': hashdir_snapshot(datadir),
            'ts_xattr_blob': xattr_blob(ts_path),
            'open': open_result(
                mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0]),
                FROZEN_TIME),
        })

    # E: expired object
    exp_meta = dict(put_meta)
    exp_meta['X-Delete-At'] = '1000000000'
    with tempfile.TemporaryDirectory() as tmp:
        mgr = make_repl(tmp)
        dfobj = mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0])
        put_object(dfobj, exp_meta)
        datadir = dfobj._datadir
        scenarios.append({
            'desc': 'repl-expired',
            'policy': 'repl', 'acco': ['a', 'c', 'o'],
            'ops': [{'op': 'put', 'body': body.decode(),
                     'metadata': [[k, v] for k, v in exp_meta.items()]}],
            'tree': hashdir_snapshot(datadir),
            'open': open_result(
                mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0]),
                FROZEN_TIME),
            'open_before_expiry': open_result(
                mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0]),
                999999999.0),
        })

    # F: content-length mismatch quarantines on open
    bad_meta = dict(put_meta)
    bad_meta['Content-Length'] = '999'
    with tempfile.TemporaryDirectory() as tmp:
        mgr = make_repl(tmp)
        dfobj = mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0])
        put_object(dfobj, bad_meta)
        datadir = dfobj._datadir
        pre_tree = hashdir_snapshot(datadir)
        result = open_result(
            mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0]),
            FROZEN_TIME)
        quarantined_dir = os.path.join(
            tmp, 'sda1', 'quarantined', 'objects',
            os.path.basename(datadir))
        scenarios.append({
            'desc': 'repl-quarantine-content-length',
            'policy': 'repl', 'acco': ['a', 'c', 'o'],
            'ops': [{'op': 'put', 'body': body.decode(),
                     'metadata': [[k, v] for k, v in bad_meta.items()]}],
            'tree': pre_tree,
            'open': result,
            'post_open_tree': hashdir_snapshot(datadir),
            'quarantined_tree': hashdir_snapshot(quarantined_dir),
        })

    # G: name collision
    with tempfile.TemporaryDirectory() as tmp:
        mgr = make_repl(tmp)
        dfobj = mgr.get_diskfile('sda1', '1234', 'a', 'c', 'o', POLICIES[0])
        put_object(dfobj, put_meta)
        datadir = dfobj._datadir
        other = df.DiskFile(mgr, os.path.join(tmp, 'sda1'), '1234',
                            account='a', container='c', obj='other',
                            _datadir=datadir, policy=POLICIES[0])
        scenarios.append({
            'desc': 'repl-collision',
            'policy': 'repl', 'acco': ['a', 'c', 'o'],
            'collide_acco': ['a', 'c', 'other'],
            'ops': [{'op': 'put', 'body': body.decode(),
                     'metadata': [[k, v] for k, v in put_meta.items()]}],
            'tree': hashdir_snapshot(datadir),
            'open': open_result(other, FROZEN_TIME),
        })

    # H/I: EC put + commit, and uncommitted EC opens only with frag_prefs
    ec_policy = StoragePolicy(2, 'fake-ec')
    ec_policy.ec_ndata = 4
    ec_policy.ec_nparity = 2
    ec_put_meta = dict(put_meta)
    for committed in (True, False):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, 'sda1'), exist_ok=True)
            emgr = df.ECDiskFileManager(
                {'devices': tmp, 'mount_check': 'false',
                 'commit_window': '0'}, NullLogger())
            dfobj = emgr.get_diskfile('sda1', '1234', 'a', 'c', 'o',
                                      ec_policy, frag_index=3)
            with dfobj.create() as writer:
                writer.write(body)
                writer.put(dict(ec_put_meta))
                if committed:
                    writer.commit(T1)
            datadir = dfobj._datadir
            fname = '%s#3%s.data' % (T1.internal, '#d' if committed else '')
            entry = {
                'desc': 'ec-put-%s' % ('commit' if committed else 'nocommit'),
                'policy': 'ec', 'acco': ['a', 'c', 'o'],
                'frag_index': 3,
                'ops': [{'op': 'put', 'body': body.decode(),
                         'metadata': [[k, v] for k, v in ec_put_meta.items()],
                         'commit': committed,
                         'commit_timestamp': T1.internal}],
                'tree': hashdir_snapshot(datadir),
                'data_xattr_blob': xattr_blob(os.path.join(datadir, fname)),
                'open': open_result(
                    emgr.get_diskfile('sda1', '1234', 'a', 'c', 'o',
                                      ec_policy, frag_index=3),
                    FROZEN_TIME),
            }
            if not committed:
                entry['open_with_prefs'] = open_result(
                    emgr.get_diskfile('sda1', '1234', 'a', 'c', 'o',
                                      ec_policy, frag_index=3,
                                      frag_prefs=[]),
                    FROZEN_TIME)
            scenarios.append(entry)

    return {'frozen_time': FROZEN_TIME, 'scenarios': scenarios}


def main():
    expectations = {
        'pickles': encode_pickle_cases(),
        'legacy_pickles': [legacy_py2_pickle()],
        'ondisk': encode_ondisk(),
        'hashes_pkl': encode_hashes_pkl(),
        'partitions': encode_partitions(),
        'xattr_layout': encode_xattr_layout(),
        'lifecycle': encode_lifecycle(),
    }
    with open(os.path.join(FIXTURE_DIR, 'expectations.json'), 'w') as fp:
        json.dump(expectations, fp, indent=1, sort_keys=True)
    print('wrote fixtures to', FIXTURE_DIR)


if __name__ == '__main__':
    main()
