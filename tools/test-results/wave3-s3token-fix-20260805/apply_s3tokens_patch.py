#!/usr/bin/env python3
"""Patch Keystone s3tokens.py: catch bad base64; set X-Subject-Token."""
import shutil
import subprocess
import sys
from pathlib import Path

p = Path("/usr/lib/python3.9/site-packages/keystone/api/s3tokens.py")
bak = Path(str(p) + ".bak-20260805")
if not bak.exists():
    shutil.copy2(p, bak)

text = p.read_text()
changed = False

if "import binascii" not in text:
    text = text.replace("import base64\n", "import base64\nimport binascii\n", 1)
    changed = True

old_check = """    @staticmethod
    def _check_signature(creds_ref, credentials):
        string_to_sign = base64.urlsafe_b64decode(str(credentials['token']))

        if string_to_sign[0:4] != b'AWS4':
"""
new_check = """    @staticmethod
    def _check_signature(creds_ref, credentials):
        # Contabo LAB fix 2026-08-05: invalid base64 used to raise binascii.Error
        # uncaught → uwsgi 500/RemoteDisconnected. Return Unauthorized instead.
        try:
            string_to_sign = base64.urlsafe_b64decode(str(credentials['token']))
        except (TypeError, ValueError, binascii.Error):
            raise exception.Unauthorized(
                message=_('Invalid EC2 signature.'))

        if string_to_sign[0:4] != b'AWS4':
"""
if "binascii.Error" not in text:
    if old_check not in text:
        print("OLD_CHECK_NOT_FOUND", file=sys.stderr)
        sys.exit(2)
    text = text.replace(old_check, new_check, 1)
    changed = True

old_post = """        response = flask.make_response(resp_body, http.client.OK)
        response.headers['Content-Type'] = 'application/json'
        return response


class S3Api"""
new_post = """        response = flask.make_response(resp_body, http.client.OK)
        # Match /v3/ec2tokens — Fernet token id is not in JSON body.
        response.headers['X-Subject-Token'] = token.id
        response.headers['Content-Type'] = 'application/json'
        return response


class S3Api"""
if "X-Subject-Token" not in text:
    if old_post not in text:
        print("OLD_POST_NOT_FOUND", file=sys.stderr)
        sys.exit(3)
    text = text.replace(old_post, new_post, 1)
    changed = True

if changed:
    p.write_text(text)
    print("PATCHED", p)
else:
    print("ALREADY_OK", p)

try:
    print(subprocess.check_output(["diff", "-u", str(bak), str(p)], text=True))
except subprocess.CalledProcessError as e:
    print(e.output)
