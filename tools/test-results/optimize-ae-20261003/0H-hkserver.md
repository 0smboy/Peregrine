# hkserver joined as Swift node 5

Date: 2026-10-04. Apply digest `9c78c318b439ee077cb5c56953a2d188af2da3af28908cc52eb3c3a73f0ce5b8`. That is the digest in `0H-hkserver-plan.md`. `POST /api/plan` on the loopback deploy UI returned that digest before `POST /api/apply`. Digests `8195ef0adca513ae7c67c2966ff4aaaa11693bfb19d4efea6bf386d7abe6a9b9` and `d962336aac56` were not sent. `config_sample` was not applied.

The apply report is 75 changed, 0 failed, 0 skipped.

## Addresses

| role | address |
|---|---|
| SSH | `103.117.121.203` |
| management on the host | `10.0.36.5` (`eth0`) |
| Tailscale | `100.70.202.32` (already installed; not used for Swift) |
| business / proxy | `10.0.0.5` |
| storage | `10.0.4.5` |
| replication | `10.0.8.5` |
| tunnel | `10.44.0.5` on `wg-hk` |

swift1–4 keep `10.0.0.N`, `10.0.4.N`, and `10.0.8.N`. The tunnel is WireGuard `wg-hk`, UDP 51820, only among these five hosts. swift1–4 allow that UDP port from `103.117.121.203` only. hkserver's public zone target is DROP, service ssh, and UDP from `169.58.108.85`, `.86`, `.87`, and `.121` only. `wg-hk` is in the trusted zone. Proxy and replication TCP ports are not added to the public zone.

## Disk

hkserver has no block device besides root `vda` / `vda1` (xfs on `/`). That disk was not formatted. The data device is a 40G XFS image `/var/lib/peregrine-node/d2.img`, mounted at `/srv/node/d2` on `/dev/loop0`. After apply, `df` showed `/dev/vda1` still the root filesystem and `/dev/loop0` on `/srv/node/d2` (1% used).

Ring devices added, weight 80:

| ring | device |
|---|---|
| account | `r1z5-10.0.4.5:6202R10.0.8.5:6202/d2` |
| container | `r1z5-10.0.4.5:6201R10.0.8.5:6201/d2` |
| object and object-1 | `r3z1-10.0.4.5:6211R10.0.8.5:6211/d2` |

Account and container builders went from 4 devices to 5. Object and object-1 went from 8 to 9.

## swift1–4 filesystems

XFS UUIDs and the sample container db inode matched the pre-apply reading. Nothing under `/srv/node` was reformatted.

| node | d1 UUID | d2 UUID | d3 UUID | sample inode |
|---|---|---|---|---|
| swift1 | `6eab8051-ec34-43cf-bcc2-cd688154660a` | `feb30b1d-551b-4926-a447-59ac90e6eaf3` | `5a766bc5-d852-4cfb-b9e6-37100e6d45e3` | 67240101 |
| swift2 | `c077bb14-3c39-4844-b3f2-2d4c5d17f424` | `cf8e0400-bc0d-4119-b9b1-7d56d46d8182` | `6b6dcbc3-ce1f-403d-8b34-27c88c3ca676` | 67524828 |
| swift3 | `82f8bcf7-56b4-477b-a404-5a855908827b` | `389b00e1-90ae-4ee5-8e70-9cd9b445df6b` | `ae5c701b-5a97-4cc0-bd30-9a0d6fd5900f` | 177 |
| swift4 | `7b653187-088c-41aa-9df2-9378e1c802bf` | `41cb5b5e-7e2d-4715-9ccc-c12d7adb01b3` | `befb258c-ab42-47d2-b95b-52586069c7cf` | 100663454 |

Sample path on each node: `/srv/node/d2/containers/967/339/f1cedba93db4ea479ad436ab97241339/f1cedba93db4ea479ad436ab97241339.db`, size 53248.

## Service check

VIP `10.0.0.10/22` stayed on swift1 `eth1`. It was absent on swift2, swift3, swift4, and hkserver. `https://10.0.0.10:8085/info` was 200.

hkserver `swift-proxy`, `swift-object`, `swift-container`, `swift-account`, replicators, reconstructor, updaters, and `haproxy` were active. `http://10.0.0.5:8080/healthcheck` was 200. The proxy binary needed `liberasurecode.so.1` from `/usr/local/lib`. `ldconfig` did not search that directory until `/etc/ld.so.conf.d/usr-local.conf` was added, after the apply report. `systemctl restart swift-proxy` then returned 200 on local `/info`. SELinux on hkserver is Disabled, so `restorecon` does not attach `bin_t`. The four existing nodes were not relabeled.

HAProxy on swift1 still has `proxy2` `disabled` and now has `server proxy5 10.0.0.5:8080`. keepalived was not restarted and hkserver does not run it.

From swift4, tempauth `test:tester` against `https://10.0.0.10:8085`:

| step | code |
|---|---|
| `GET /auth/v1.0` | 200, storage `https://10.0.0.10:8085/v1/AUTH_test` |
| `PUT /v1/AUTH_test/hkadd-20261004` | 201 |
| `PUT .../hkadd-20261004/obj1` | 201 |
| `GET` the object | 200, body matches, sha256 `2336ddd1fab23d1a32486467bba4b8c54a8b2f36226bece6d30c0019881c9b87` |

`swift-get-nodes` for `AUTH_test/hkadd-20261004/obj1` (partition 15966):

```
10.0.4.2:6211 d2
10.0.4.4:6211 d2
10.0.4.5:6211 d2
```

The object directory is on hkserver at `/srv/node/d2/objects/15966/71f/f9789e06490f7680ca4f80250bb0671f`. Replication SSH from swift1 to `root@10.0.8.5` with the existing replication key returned `REPL_OK`.

## Binaries copied onto hkserver

These match swift1 `/usr/local/bin` at apply time. They are not the older `/root/work/g6-rust-bin` copies.

| binary | sha256 |
|---|---|
| swift-proxy-server | `dc22cca7b45e6bbc4a096f99675aeab8855282276fc9f8caaa2d6ed00f402314` |
| swift-object-server | `6c3cd551c6943422cc87dc7b4652987e566d9136fc75960e472c7dd16b33f315` |
| swift-container-server | `6e697697545d9ab7c1d5bd0276348bfacd2d86d6ed7558f351690c13b504a263` |
| swift-account-server | `f2cb830c4403febc28bee0d33036c497c6a3194d6ed28d13c1e0128b80cc00c9` |
