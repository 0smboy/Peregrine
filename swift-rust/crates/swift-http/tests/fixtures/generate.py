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
Generate golden swob fixtures (Range/Match/title-case/http dates) using
the real Python implementation.

Run from the repository root:

    python3 rust/crates/swift-http/tests/fixtures/generate.py
"""
import json
import os
import sys
import time

FIXTURE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(FIXTURE_DIR, *[os.pardir] * 5))
sys.path.insert(0, REPO_ROOT)

from swift.common.swob import Range, Match, normalize_etag  # noqa: E402
from swift.common.header_key_dict import HeaderKeyDict  # noqa: E402

RANGE_HEADERS = [
    'bytes=0-99', 'bytes=-5', 'bytes=5-', 'bytes= 0 - 5', 'BYTES=0-5',
    'bytes=0-0', 'bytes=-0', 'bytes=5-3', 'bytes=-', 'bytes=45',
    'bytes=0-5,10-19', 'bytes=0-5,x-19', 'bytes=--0', 'bytes=1-2,-3',
    'bytes=+5-7', 'bytes=05-007', 'bytes=', 'notbytes=0-5',
    'bytes=0-5,5-10,10-15,3-4',
    'bytes=' + ','.join('%d-%d' % (i * 10, i * 10 + 5) for i in range(51)),
    'bytes=' + ','.join('%d-%d' % ((9 - i) * 10, (9 - i) * 10 + 5)
                        for i in range(9)),
    'bytes=0-5,0-5,0-5', 'bytes=100-', 'bytes=-200',
]

LENGTHS = [None, 0, 1, 10, 100, 200]


def encode_ranges():
    out = []
    for header in RANGE_HEADERS:
        entry = {'header': header}
        try:
            rng = Range(header)
        except ValueError:
            entry['valid'] = False
            out.append(entry)
            continue
        entry['valid'] = True
        entry['ranges'] = [[s, e] for s, e in rng.ranges]
        entry['str'] = str(rng)
        entry['for_length'] = {}
        for length in LENGTHS:
            got = rng.ranges_for_length(length)
            key = 'null' if length is None else str(length)
            entry['for_length'][key] = (
                None if got is None else [[s, e] for s, e in got])
        out.append(entry)
    return out


def encode_matches():
    cases = []
    for header, vals in [
            ('"abc", def', ['abc', '"abc"', 'def', 'ghi']),
            ('*', ['anything']),
            (' , ,"x"', ['x', '']),
            ('W/"weak"', ['weak', 'W/"weak"']),
    ]:
        m = Match(header)
        cases.append({'header': header,
                      'checks': {v: (v in m) for v in vals}})
    return cases


def encode_titles():
    keys = ['content-length', 'x-object-meta-foo_bar', 'ETAG',
            'x-container-sysmeta-a b', 'x--double', 'a1b2', '123abc',
            'wsgi-läder']
    return {k: HeaderKeyDict._title(k) for k in keys}


def encode_dates():
    out = []
    for secs in [0, 1751500001, 4102444800, 86399, 951827696]:
        out.append({'secs': secs,
                    'formatted': time.strftime(
                        '%a, %d %b %Y %H:%M:%S GMT', time.gmtime(secs))})
    return out


def main():
    expectations = {
        'ranges': encode_ranges(),
        'matches': encode_matches(),
        'titles': encode_titles(),
        'dates': encode_dates(),
    }
    with open(os.path.join(FIXTURE_DIR, 'expectations.json'), 'w') as fp:
        json.dump(expectations, fp, indent=1, sort_keys=True)
    print('wrote fixtures to', FIXTURE_DIR)


if __name__ == '__main__':
    main()
