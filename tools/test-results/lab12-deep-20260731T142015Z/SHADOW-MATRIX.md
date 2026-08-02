# Shadow matrix run=r1785508038-148b56

mode=dual peer=True cases=31 breaking=15 semantic=12 cosmetic=0 identical=4

Verdict: **REJECT** (breaking>0, zero exemption)

## Notes

- Side A: Rust HA cluster http://10.42.30.11:8085
- Side B: Python SAIO http://127.0.0.1:8090
- Replay: base=r1785508038-148b56 holds=31 drifted=0 errors=0
- Mutate seeds 111/222/333: divergence_class=identical, peer=true, HTTP 200
- Negative (py proxy killed): `error=second endpoint refused the login...` — NEG_OK (not silent single)

## Breaking themes

- listing.* / meta.*: `accept-ranges` missing on B; account meta temp-url; timestamp drift (also semantic)
- range.unsatisfiable / range.multi: boundary + body/ctype differences
- error.etag.mismatch: last-modified missing on B
- convergence.post.delete: accept-ranges + listing last_modified

Full corpus left on host: `/var/lib/swift-console/shadow/corpus.jsonl` and `$OUT/05-shadow-*` (stranded until VM restart).
