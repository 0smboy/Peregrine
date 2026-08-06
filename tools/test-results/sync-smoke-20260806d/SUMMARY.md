# container-sync object path KEEP (2026-08-06d)

## Claim
Same-cluster legacy container-sync **object transfer** works on Contabo LAB
after three code fixes + conf + 4-node deploy.

## Fixes
1. **Proxy `authorize`**: legacy `X-Container-Sync-Key` + timestamp
   (accepts gatekeeper-shunted `X-Backend-Inbound-X-Timestamp`) — inbound
   sync PUT was 401 under TempAuth.
2. **Proxy POST metadata**: pass `X-Container-Sync-To` / `X-Container-Sync-Key`
   through to container servers (was empty meta after 204).
3. **`swift-container-sync` ProxyObjectSource**: TempAuth token
   (`internal_client_auth_user/key`); read responses by header end +
   Content-Length (keep-alive safe); dechunk; strip hop-by-hop headers
   before remote PUT (`Transfer-Encoding`/`Content-Length` were poisoning puts).

## Lab evidence
- Pair `synclive1786027144` → `synclivedst1786027144`
- recon: **puts=28 fails=0**
- dst object_count=5; obj1..obj5 GET 200 size=9
- Manual inbound sync PUT (no token) = 201 after authorize fix
- See `01-sync-e2e.txt`

## Not claimed
- Multi-cluster realm HMAC soak
- PRODUCTION-GO-LIVE
- Product Python parity soak
