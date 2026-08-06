# EC heal live · 2026-08-06 (final)

## Root cause (found)

Reconstructor used conf `bind_port=6210` for `ring_device_id`, but Contabo rings place object devices on **6211/6212** (`servers_per_port=1`). Every device skipped → `suffix_syncs=0` forever.

## Fix (code + deploy)

- `localdev::ring_device_id_local_name` — match by **local IP + device name**
- reconstructor: when `servers_per_port>0`, use name-local identity
- Deployed reconstructor sha256 `62400abcd…` ×4; log shows `servers_per_port=1`

## Re-proof (`03-heal-after-fix.log`)

| Step | Result |
|------|--------|
| PUT/GET EC 2MB | PASS md5 |
| frags before | **3** |
| delete 1 frag | **2** |
| degraded GET | **YES** |
| reconstructor `once` ×4 | ran |
| +10s frags | **3** (restored) |
| post GET | **YES** |

**Verdict: GREEN** — fragment restored within ~10s after `once`.

(Earlier `HEAL=PARTIAL_READ_OK` line is a script bug: it re-counted frags *after* object DELETE.)
