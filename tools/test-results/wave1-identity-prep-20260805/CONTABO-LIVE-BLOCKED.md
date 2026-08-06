# Contabo live Galera/Keystone — BLOCKED

**Date:** 2026-08-05  
**Decision:** Do not install MariaDB/Keystone on Contabo in this cycle.

## Evidence

| Check | Result |
|-------|--------|
| `/srv/node/d1` Use% | swift1 **100%**, swift2 92%, swift3 99%, swift4 91% |
| `/srv/node/d2–d3` | ~89–91% all nodes |
| Root `/` free | 22–33 GiB (package install *could* fit) |
| MemAvailable | ~2.3–3.9 GiB with full Rust daemon set |
| Keystone/MariaDB present | **ABSENT** ×4 (`/etc/keystone`, `/var/lib/mysql`, listeners) |
| Wave 0 clear proven | **No** (no `wave0-clear-*` evidence pack at prep time) |
| mkfs | **FORBIDDEN** (plan + operator) |

## Why root headroom is not enough

Galera datadir lives on `/` but Contabo nodes already run a full Rust Swift
stack. Adding Galera+Keystone+uwsgi under disk pressure on object devices and
tight RAM risks OOM and IO starvation. Plan boundary: do not force Identity
live before Wave 0 proves reclaim.

## What completed anyway

Inventory, dry-run plan JSON, KEYSTONE-LIVE.md, bundle-rust Identity 对接
templates, `HttpTokenValidator` https support. See `SUMMARY.md`.
