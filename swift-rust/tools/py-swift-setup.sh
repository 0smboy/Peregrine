#!/bin/bash
# Stand up a Python OpenStack Swift environment on the Azure build host, from the
# in-repo source, for the Rust-vs-Python parity/perf comparison. Logs every step;
# non-fatal on PyECLib (EC on Python is a nice-to-have, replication parity is the
# floor). Run under nohup; output -> $LOG.
set -u
SRC=/root/work/swift-master
VENV=/root/work/pyswift-venv
LOG=${1:-/root/work/py-swift-setup.log}

say() { echo; echo "########## $* ##########"; }

{
  say "PY-SWIFT SETUP START $(date -u +%FT%TZ)"

  say "OS packages (devel headers, memcached, rsync)"
  dnf install -y python3-devel libffi-devel memcached rsync gcc 2>&1 | tail -8
  echo "liberasurecode headers:"; ls /usr/include/liberasurecode* /usr/local/include/liberasurecode* 2>/dev/null || echo "  (none found -> PyECLib may fail)"

  say "venv @ $VENV"
  rm -rf "$VENV"
  python3 -m venv "$VENV"
  source "$VENV/bin/activate"
  python -m pip install -U pip wheel setuptools 2>&1 | tail -3
  python --version; pip --version

  say "core requirements (eventlet, paste, lxml, xattr, cryptography, dnspython)"
  pip install eventlet greenlet PasteDeploy lxml requests 'xattr>=0.7.2' cryptography dnspython 2>&1 | tail -12

  say "PyECLib (needs liberasurecode headers; non-fatal)"
  pip install PyECLib 2>&1 | tail -15 || echo "PYECLIB-FAILED (EC-on-python unavailable)"

  say "swift (editable, from repo)"
  cd "$SRC" && pip install -e . 2>&1 | tail -10

  say "python-swiftclient + test extras (for functional suite)"
  pip install python-swiftclient nose pytest 2>&1 | tail -6

  say "VERIFY imports + binaries"
  python -c "import swift, eventlet, xattr; print('swift', swift.__version__); print('eventlet', eventlet.__version__)" 2>&1
  python -c "import pyeclib; print('pyeclib OK')" 2>&1 || echo "pyeclib NOT available"
  ls "$VENV"/bin/swift-proxy-server "$VENV"/bin/swift-object-server "$VENV"/bin/swift 2>&1

  say "PY-SWIFT SETUP DONE $(date -u +%FT%TZ)"
} >"$LOG" 2>&1
echo "PY-SWIFT-SETUP-COMPLETE" >>"$LOG"
