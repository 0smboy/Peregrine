# 00-SECURITY Contabo (2026-08-01)

## SSH
- PasswordAuthentication **no** (`/etc/ssh/sshd_config.d/00-no-password.conf`; cloud-init override neutralized)
- PubkeyAuthentication yes; root key login verified for swift1–4 from management host

## firewalld
- eth0 public: zone=public, **target=DROP**, service=ssh only
- eth1/eth2/eth3 (10.0.0/4/8): zone=trusted ACCEPT
- Contabo edge may complete TCP handshake on public IPs; application payload fails (Empty reply / No route to host from peer public IPs)

## Bind lockdown
| Service | Bind |
|---------|------|
| HAProxy :8085 | 10.0.0.N (+ VIP 10.0.0.10 on swift1) |
| HAProxy stats | 127.0.0.1:8404 |
| swift-proxy | 127.0.0.1:8080 |
| account/container/object | 10.0.4.N |

## Verification
- VIP `http://10.0.0.10:8085/healthcheck` → 200
- Per-node private HAProxy health → 200
- External Mac → public :8085 → Empty reply (not usable API)
- Key SSH to all four nodes → OK
