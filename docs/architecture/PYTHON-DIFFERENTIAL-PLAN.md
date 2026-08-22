# Python Swift differential plan (Gate 5)

- **Status:** Plan only. Gate 5 is **not** claimed. In-process HTTP idle (`worker_starvation` at `spawn_server(2)`) is currently expected **PASS**; that is not semantic parity and is not “Eventlet solved”.
- **Date:** 2026-08-20
- **Constitution:** `AGENTS.md` §28, §35 Gate 5, L9, NON-GOAL 13
- **Oracle:** Python OpenStack Swift in this workspace (`swift/`, Eventlet WSGI)
- **Subject:** Peregrine HTTP serve in this merge tree (`swift-rust/`): Tokio connection tasks; idle keep-alive is a pending Future; Handler still sync; **body fully buffered on async path**; SSYNC hijack broken on production serve (`Body::Buffered`); `spawn_blocking` only in `blocking.rs`. There is no `read_raw_head`. Buffering is `IncomingBody::materialize` → `Body::Buffered` in `LegacyService::call` (`swift-http/src/server.rs:81-108`) and object/account `handle_async`.
- **Rule:** feed **the same bytes** to both; compare **client-visible** wire. Any semantic regression is NO-GO.

**Invariant (non-negotiable):** do **not** raise `workers`, `worker_threads`, `process_workers`, or SAIO `workers=64` to obtain a differential result, to make a concurrency gate pass, or to hide L1. Python `workers=2` are processes; Peregrine must match observable behaviour at the **same numeric `workers`**. Raising workers is not a Gate 5 result.

Python is the reference oracle, not the implementation blueprint. Eventlet greenlets explain *why* Python can hold 1024 keep-alives per worker process; Peregrine must match the **observable** behaviour with async tasks, not with green threads.

```
same request bytes
    ├─► Python Swift (SAIO / lab oracle)
    └─► Peregrine
            │
            ▼
     status · headers · ETag · connection · chunking · timeout
     Expect: 100-continue · range · conditional · S3 · COPY · DELETE · SSYNC
     (+ bad HTTP, listed in AGENTS.md §28)
```

Gate 5 is **not claimed**. Library golden tests (`swift-http` range/Match/title-case/dates) and the frozen S3 dual-oracle harness (`tools/strict-s3-parity.py`) are subsets. In-process `worker_starvation` PASS at `spawn_server(2)` does not waive live boto keep-alive dual-feed.

## Method

1. Record request line + headers + body framing (and any interim `100 Continue` the client waits for).
2. Replay against Python (Eventlet `max_clients=1024` per process, default `workers=2` **processes**) and Peregrine (same conf names; today `workers` / `worker_threads` size the **Tokio runtime**, not Eventlet greenlets). Keep the **same numeric worker count**.
3. Capture the full response sequence: interim 1xx, final status line, header block as sent, body framing, whether the TCP connection stayed open, timeouts, and RST vs FIN.
4. Diff with the tables below. Header *presence and value* are compared case-insensitively except where S3 requires a literal (`ETag`, lowercase `x-amz-*`).
5. Do **not** retune `worker_threads` / SAIO `workers=64` to make a case pass. That hides L1 and invalidates Gate 5. Forbidden.

Existing in-process vehicles (not dual-feed):

| Vehicle | What it is | Gate 5 |
|---|---|---|
| `swift-http` lib tests in `src/server.rs` | Protocol unit on **legacy** `handle_connection`: lazy 100-continue, 417, withhold on unread, multiphase re-arm, SSYNC hijack | not dual-feed; **not** the production `LegacyService` path |
| `tests/golden.rs` + `fixtures/expectations.json` | swob Range / Match / `title_case` / `http_date` | library only |
| `tests/concurrency/worker_starvation.rs` | 2 workers + 2 idle keep-alives + 3rd GET | **MUST stay `spawn_server(2, …)`**. Currently **PASS** because idle keep-alive is a pending Future, not because workers were raised. Do not raise workers. Do not retune the harness. |
| `tests/concurrency/align_expect_continue.rs` | same 3-keep-alive / 2-worker occupancy; 3rd client is `Expect: 100-continue` PUT | **MUST stay `spawn_server(2, …)`**. Currently **PASS** on occupancy because idle is a Future. Production 100 is **eager** (`IncomingBody::next_chunk` before `materialize` finishes, `server.rs:654-660`, `89-107`) — **not** Python `wsgi.input` first-read (`swift/common/http_protocol.py:215-217`). Occupancy green ≠ Gate 5 dual-feed. Do not raise workers. |
| `tools/strict-s3-parity.py` | 57-case live dual-oracle S3 | S3 subset; not keep-alive L1 |

`tests/concurrency/*.rs` are explicit `[[test]]` targets in `swift-http/Cargo.toml` (cargo does not auto-discover that directory). `--lib` does not run them.

---

## What to compare

Each row: **compare** (client-visible), **Python oracle**, **Peregrine today**, **later dual-feed**.

### Status

| Compare | Python oracle | Peregrine today | Dual-feed |
|---|---|---|---|
| Status code | swob / controllers (`swift/common/swob.py` `RESPONSE_REASONS`; object PUT 201; DELETE 204; unsatisfiable range 416; unsupported `Expect` 417; mismatch ETag 422; disconnect 499; overload 503; ENOSPC 507) | `reason_phrase` in `swift-http/src/request.rs`; object/proxy controllers decide the code | exact `u16` |
| Reason phrase | `HTTP/1.1 {code} {reason}` from swob; Eventlet may title-case | same table (`201 Created`, `416 Requested Range Not Satisfiable`, `499 Client Disconnect`, `500 Internal Error` not “Internal Server Error”) | exact reason string |
| Quorum-padded 503 | `_compute_quorum_response` pads with 503 to `node_number` (`proxy/controllers/base.py`) | `best_response` padding (`swift-proxy-server`) | same final client status, not which replica was slow |
| 1xx vs final | `100 Continue` is not the resource status | Production: `IncomingBody` writes `HTTP/1.1 100 Continue` during `materialize`, then a separate final response. Legacy `InterimResponder` is unused on `Body::Buffered`. | sequence: 100 then 2xx/4xx/5xx; never smash into one status line |

### Headers

| Compare | Python oracle | Peregrine today | Dual-feed |
|---|---|---|---|
| Field names on the wire | Eventlet `capitalize_response_headers: False` (`swift/common/wsgi.py:443-446`) so S3 can emit `ETag` not `Etag` | `HeaderKeyDict` uses Python `bytes.title()` (`title_case("etag") == "Etag"`); `x-amz-*` forced lowercase (`headers.rs`) | Swift: title-case except S3 `ETag` / `x-amz-*`. Do not “fix” title-case while changing the runtime (L9; Eventlet matrix) |
| Values | IMF-fixdate `Date` / `Last-Modified`; `X-Timestamp`; `X-Trans-Id` / `X-Openstack-Request-Id` | `http_date` golden-tested; trans-id stamped on proxy | date format + trans-id **presence**; trans-id **value** is not comparable (new id each request) |
| Hop-by-hop | hop-by-hop stripped on backend hops | proxy strips `Connection` / `Transfer-Encoding` on write (`server.rs` `write_response` / `write_response_async`) | no leaked hop-by-hop to the client except the connection token the server chose |
| Default `Content-Type` | `SwiftHttpProtocol.MessageClass.get_default_type` returns `''` (not `application/octet-stream`) | must not invent a default the client did not send | empty vs missing vs `application/octet-stream` |
| High-cardinality | path / trans-id / account belong in logs, not Prom labels | same constraint (`AGENTS.md` §23) | out of band; not a wire compare |

### ETag

| Compare | Python oracle | Peregrine today | Dual-feed |
|---|---|---|---|
| Swift object ETag | MD5 hex of body; header name typically `Etag` via title-case; value often quoted in swob responses | stored/compared via `normalize_etag` (strip one pair of quotes); object server sets ETag from writer | quoted vs bare must match Python for the **same API** (Swift vs S3 differ) |
| Conditional input | `If-Match` / `If-None-Match` use `swob.Match` + `normalize_etag` | `swift-http/src/range.rs` `Match` + golden fixtures | 304/412 vs 200 on the same tags |
| S3 `ETag` | literal `ETag` (Eventlet capitalize off); objects `"md5"`; MPU `"md5-N"` | s3api must emit `ETag` not `Etag` | byte-for-byte header name + quoted value |
| Crypto / EC | `X-Backend-Etag-Is-At` → plaintext HMAC / EC etag for conditionals | `resolve_etag_is_at` (`conditional.rs`) | 304/412 using the resolved tag, not ciphertext MD5 |
| COPY / SLO | copy result ETag is the new object; SLO manifest ETag is the SLO formula | copy + SLO middleware | ETag of COPY/SLO GET/HEAD, not of a segment |

### Connection

| Compare | Python oracle | Peregrine today | Dual-feed |
|---|---|---|---|
| HTTP/1.1 default | keep-alive unless `Connection: close` (`http_protocol.py` parse_request) | same (`read_head` `keep_alive`) | `Connection` token + whether fd stays open |
| HTTP/1.0 | keep-alive only if requested | same | same |
| Idle keep-alive cost | **greenlet + fd**, not an OS worker. `workers=2` processes × `max_clients=1024` greenlets. Three boto keep-alive clients (s3-tests) proceed | Production Tokio path: idle wait is a **pending Future** (`read_head_async`, `server.rs:858-871`; there is no `read_raw_head`). `worker_starvation` **PASS** at `spawn_server(2)`. Legacy `handle_connection` still holds a thread (lib tests only). | **In-process Gate 1 green.** Full Gate 5 (S3 boto live, dual-feed, SSYNC async session) is still NO-GO. Do not raise workers |
| Drain / reuse | unread body must be consumed to reuse the socket | Production: **body fully buffered on async path**, so the adapter already consumed the body before the Handler. Legacy drain ≤64KiB remainder; larger → close (`KEEPALIVE_DRAIN_CAP`, `server.rs:128`). If `Expect: 100-continue` was never answered (`continue_pending`), close — **legacy only**; production always answers 100 during `materialize` when Expect is set | reuse vs close after unread / withheld-100 |
| Pipelining | Eventlet can read the next request on the same greenlet | `max_requests_per_connection` loop | two pipelined requests (golden `test_server_round_trip` is single-process only) |
| Close shape | FIN vs RST on error mid-body | shutdown write then drain up to 1MiB to avoid RST killing a 422 (`server.rs` legacy; async path `AsyncWriteExt::shutdown`) | client still sees the error body |
| HTTP/2 | not Swift’s client wire for this program | **forbidden** this phase (`AGENTS.md` §6) | do not compare HTTP/2 |

**Gate 5 keep-alive (must stay at 2 workers; raising workers is forbidden):**

```
Python:  workers=2 (processes) + 3 keep-alive clients  → all three serve
Peregrine today: worker_threads=2 (Tokio runtime) + 3 keep-alive clients
                 → third GET serves (idle is a Future). Confirmed:
                   cargo test -p swift-http --test worker_starvation  → PASS
                   (expected PASS; MUST stay spawn_server(2); do not raise workers)

tests (do not change spawn_server(2, …); do not raise workers):
  swift-http --test worker_starvation     # GET /health — PASS on Tokio serve
  swift-http --test align_expect_continue # 3rd client = PUT Expect: 100-continue — PASS
                                          # occupancy, not Gate 5; production 100 is eager
```

Making them pass by `spawn_server(3, …)` or SAIO `workers=64` is still an L1 hide, not Gate 5. They currently pass **without** that hide. That is necessary for Gate 1, not sufficient for Gate 5 / “Eventlet solved”.

### Chunking

| Compare | Python oracle | Peregrine today | Dual-feed |
|---|---|---|---|
| Request `Transfer-Encoding: chunked` | `wsgi.input.chunked_input`; last-chunk `0\r\n\r\n`; trailers | `IncomingBody` chunked decode during **full materialize**; trailers bounded; TE + Content-Length together → 400 | decode identity; 400 on combined headers |
| Response framing | Content-Length when known; otherwise close-delimited (Eventlet WSGI rarely chunks responses) | known length → `Content-Length`; unknown streamed → `Connection: close` (not chunked encode) (`write_response_async`) | client-visible framing, not whether an internal hop was chunked |
| Chunk extensions / bad sizes | 400 | 400 | 400 + connection close |
| Multiphase PUT | second `100 Continue` resets `chunk_length` so a **new** chunked sequence is the commit (`obj/server.py` `_send_multi_stage_continue_headers`) | `InterimResponder::send_continue` sets `resume_chunked` (`body.rs`) on **Streamed** bodies. Production `Body::Buffered` has **no** interim handle (`body.rs:213-217`) | two chunked sequences around two 100s; capability headers on the first 100 (`X-Obj-Multiphase-Commit`, `X-Obj-Metadata-Footer`) |
| S3 `aws-chunked` | s3api dechunks after SigV4 | dechunk + per-chunk HMAC | unsigned vs signed chunk errors (`SignatureDoesNotMatch`) |

### Timeout

| Compare | Python oracle | Peregrine today | Dual-feed |
|---|---|---|---|
| Header / idle keep-alive | Eventlet `socket_timeout=client_timeout` (default 60); optional `keepalive_timeout` (`wsgi.py:442`, `wsgi.py:449-450`) | Tokio path: empty keepalive wait = `client_timeout_secs`; in-progress head = `head_deadline_secs` (`server.rs:858-875`). Not typed `KeepAliveIdleDeadline` / `HeaderDeadline`. | when the idle conn is closed; **not** whether a third conn was starved (that occupancy test is `worker_starvation`, currently PASS at 2 workers) |
| Body idle vs lifetime | `ChunkReadTimeout(client_timeout)` per chunk; `max_upload_time` wall clock on object PUT (`obj/server.py`) | **Body fully buffered on async path.** `IncomingBody::next_chunk` has **no** per-read timeout (`server.rs:654-748`). No typed `body_idle` vs `UploadLifetimeDeadline` on the serve path. Do not describe this as `BridgeRead` / `run_handler_with_body`. | 408/499 timing; progress must refresh idle, not lifetime (`AGENTS.md` §19) |
| Backend | `conn_timeout` connect; `node_timeout` read/write; `post_quorum_timeout` after adequate PUT | `conn_timeout` + `node_timeout` on the same `TcpStream`; no post-quorum cancel | which timeout fires, client status (504 vs 503 vs 201 with 2/3) |
| 100-continue wait | client waits for 100 before the body; server may wait on `wsgi.input` read | Production `handle_connection_async` + `LegacyService` is **eager** (`next_chunk` sends 100, then `materialize`, then Handler; `server.rs:654-660`, `89-107`). Occupancy at 2 workers is no longer the starve. Dual-feed not run. Withheld-100 on unread reject **does not match Python** on production serve. | 100 within a few hundred ms with 2 workers + 2 idle keep-alives — occupancy **PASS**; withheld-100 on unread reject must still match Python (currently a production gap) |
| SSYNC | `MessageTimeout` per line (`ssync_receiver.py` / `ssync_sender.py`) | **SSYNC hijack broken on production serve (`Body::Buffered`).** `Body::Buffered::hijack` is `None` (`body.rs:227-231`). Object `handle_async` materializes (`swift-object-server/src/lib.rs:565-582`) then `ssync` returns 500 (`lib.rs:897-900`). Sender is chunked (`ssync_sender.rs:185-186`); that does not restore hijack. `spawn_blocking` only in `blocking.rs:577`. | phase-level timeout, not a hung worker; duplex conduit must still work on production serve |

Do not collapse these into a single `Timeout(60)`.

### Expect: 100-continue

Characterise **current** Peregrine; do not re-unit-test `server.rs`.

| Compare | Python oracle | Peregrine today | Dual-feed / tests |
|---|---|---|---|
| When 100 is sent | `wsgi.input` sends `HTTP/1.1 100 Continue\r\n` on first read (`http_protocol.py:215-217` sets `wfile` / `wfile_line`). A handler that never reads the body never triggers the upload | **Eager on production serve.** `IncomingBody::next_chunk` writes 100 before the first body byte (`server.rs:654-660`); `LegacyService` / object `handle_async` always `materialize` the body into `Body::Buffered` before the Handler (`server.rs:89-107`; `swift-object-server/src/lib.rs:565-582`). A Handler that never reads the body **still** gets a 100. Legacy `ConnBodyReader::maybe_send_continue` on first `Read` (`server.rs:1155-1168`) remains lazy — lib tests `expect_continue_is_sent_only_when_the_body_is_read` / `…_withheld_when_the_handler_rejects_unread` prove **`handle_connection`**, not `LegacyService`. | lazy 100 vs withheld 403/404/412/422 **without** a 100. Dual-feed must use the production serve path. Production currently cannot withhold 100. |
| Unsupported Expect | 417 | 417, no 100 (`unsupported_expectation_is_rejected_without_continue`) | 417 |
| Multiphase | `set_hundred_continue_response_headers` then extra `send_hundred_continue_response` (`obj/server.py`) | `InterimResponder::send_continue(&[headers])` + chunked re-arm (`multiphase_interim_responses_rearm_chunked_reading`) on Streamed bodies. `Body::Buffered` has no interim handle (`body.rs:213-217`) | capability headers + second 100 + commit sequence |
| Proxy PUT | `Expect: 100-continue` to each replica **before** teeing the client body (`proxy/controllers/obj.py` `Putter.connect`); 507/412 node is not fed the body | `connect_putter` + `Expect: 100-continue` (`swift-proxy-server`). Client body is **already fully buffered** by `LegacyService` before `stream_put_object` | 412/507 from one replica must not consume the client body; quorum still 201 |
| Keep-alive ∩ 100 | 100 and final response on one connection; next request on the same fd is a greenlet yield, not a new OS thread | Occupancy: third client **does** get a 100 at `spawn_server(2)` (`align_expect_continue` PASS). Protocol: that 100 is **eager** (adapter `materialize`). Do not raise workers. | `align_expect_continue.rs`: 3 keep-alive clients, 2 workers, 3rd is PUT+Expect. **MUST stay spawn_server(2).** Occupancy green ≠ Gate 5 dual-feed. |

`src/server.rs` lib tests prove the **legacy** protocol machine (`handle_connection` and `ConnBodyReader`). Production serve is `handle_connection_async` + `LegacyService` (body fully buffered). Gate 5 occupancy at 2 workers is currently green. Gate 5 dual-feed is not. Do **not** raise workers.

### Range

| Compare | Python oracle | Peregrine today | Dual-feed |
|---|---|---|---|
| Parse / ignore | `swob.Range`: max 50 ranges, 2 overlaps, 8 non-ascending; some headers ignored (200 whole object) | `range.rs` + `tests/golden.rs` `ranges` | 206 vs 200 vs 416 |
| Single range | `206`, `Content-Range: bytes start-end/total` | `content_range_header_value` | headers + body slice |
| Multi range | `multipart/byteranges`; boundary | `multipart_byteranges` | MIME shape, each part’s Content-Range |
| Suffix / open | `bytes=-N`, `bytes=N-` | golden `for_length` | same slice |
| COPY + Range | Python copy range semantics | copy middleware | not a GET range |

### Conditional

| Compare | Python oracle | Peregrine today | Dual-feed |
|---|---|---|---|
| Evaluation order | 1. If-None-Match hit → 304; 2. If-Match miss → 412; 3. 404 + `If-Match: *` → 412; 4. Last-Modified ≤ IMS → 304; 5. Last-Modified > IUS → 412 (`swob._get_conditional_response_status`) | `conditional_response_status` documents the same order | 304/412/200/404 on stacked headers |
| `*` | `If-None-Match: *` / `If-Match: *` | `Match` tags | 304 on existing; 412 on missing + If-Match:* |
| Combined with Range | 304 has no body; 206 only after conditionals pass | `apply_conditional` | no 206 on 304 |
| PUT If-None-Match / If-Match | object server 412 on clash | object server | 412 vs 201 |

### S3

Live dual-oracle already exists (`tools/strict-s3-parity.py`, 57 cases; docs-site dual-oracle). It does **not** cover keep-alive occupancy or Swift COPY/SSYNC.

| Compare | Python s3api | Peregrine today | Dual-feed |
|---|---|---|---|
| Status + error XML | `Code`, `Message`, `RequestId`, `Resource` | s3api error docs | XML shape; do not 501 Rust-ahead extras to match Python |
| `ETag` literal | needs Eventlet capitalize-off | must stay `ETag` | header name |
| List / MPU / versioning / delete-marker | frozen 57-case runner | lab 49/8 with explained residuals | that runner; do not edit assertions to pass |
| boto keep-alive | three clients (main/alt/tenant) reuse HTTP/1.1 connections | In-process HTTP idle no longer starves at `workers=2` (`worker_starvation` PASS). Live s3-tests / 5h11 fingerprint is **not** re-run in this drop. Do not “fix” leftovers by raising SAIO workers. | Gate 5: a ListBuckets from a third keep-alive client must return 200 without a 30s header deadline, at the **same** worker count as Python. Do not raise workers. |
| `Expect: 100-continue` | boto/AWS CLI PUT | eager 100 on production object PUT path (full-buffer adapter) | 100 then 200/201; 403 unsigned must not 100 if body unread — **production currently sends 100** |
| CopyObject / MultiDelete | S3 wrappers over Swift COPY/DELETE | s3api | S3 status/headers, not only Swift |

### COPY

| Compare | Python oracle | Peregrine today | Dual-feed |
|---|---|---|---|
| Verbs | `COPY` + `Destination`; PUT + `X-Copy-From` | copy middleware | both forms, same resulting object |
| Status | 201 created | copy middleware | 201 vs 200 |
| ETag / Last-Modified | dest object | dest object | match dest HEAD |
| Conditionals | `If-Match` on source | copy middleware | 412 vs 201 |
| Fresh metadata | `X-Fresh-Metadata` | copy middleware | metadata set vs inherited |
| SLO/DLO | manifest copy vs concatenated | SLO/DLO + copy | ETag formula |
| Cross-account / policy | container ACL + storage policy | same | 403/404 vs 201 |
| Range copy | supported subset | copy middleware | body length + ETag |

### DELETE

| Compare | Python oracle | Peregrine today | Dual-feed |
|---|---|---|---|
| Object | 204 empty | object server | 204, no body |
| Missing | 404 (or 204 on some S3 delete-missing) | Swift 404; S3 DeleteObject often 204 | API-specific |
| If-Delete-At / expired | 404 after expirer; 409/400 on bad timestamp | expirer + object server | 404 vs 204 vs 400 |
| SLO | `?multipart-manifest=delete` sync/async | SLO middleware | 200 XML vs 204 |
| WORM / object lock | 403 | s3api object lock | 403 vs 204 |
| Tombstone | `.ts` datafile, container update | diskfile + container update | subsequent GET 404; listing gone after updater |
| Account/container | 204; 409 if not empty | account/container servers | 204 vs 409 |

### SSYNC

SSYNC is not REST. Compare the **conduit**, not a single object status.

| Compare | Python oracle | Peregrine today | Dual-feed |
|---|---|---|---|
| Verb / conduit | `SSYNC` HTTP/1.1 chunked; `Response(app_iter=receiver())` (`obj/server.py:1406-1415`) | `"SSYNC" => ssync` then `Body::hijack` (`swift-object-server/src/lib.rs:843-900`, `997`). **SSYNC hijack broken on production serve (`Body::Buffered`):** `handle_async` materializes (`lib.rs:565-582`); `Body::Buffered::hijack` is `None` (`body.rs:227-231`) → 500 `"SSYNC requires a hijackable connection"`. Sender is chunked (`ssync_sender.rs:185-186`); that still lands in `Body::Buffered`. Still not an async `SsyncSession`. | first bytes + session completion on **production** serve (`serve_forever_multi` / `serve_forever_multi_service`) |
| Kick | first `yield b'\r\n'` so Eventlet sends the head (`ssync_receiver.py:294-296`) | `write_chunk(wire, b"\r\n")` after hijack (`lib.rs:2698-2701`). Production `Body::Buffered` never reaches that kick (`hijack()` is `None` → 500). | sender does not block forever on headers |
| Phases | missing-check, updates, release | same four steps after hijack (unit tests attach a synthetic hijack sink on **legacy** `handle_connection`) | hashes missing, updates applied, 200-ish completion |
| Subrequest PUT/DELETE | DiskFile on the SSYNC greenlet; fsync via tpool | Unreachable on production serve. Legacy hijack would run DiskFile on the `handle_connection` worker. `spawn_blocking` only in `blocking.rs:577`. | durable objects + DELETE tombstones match Python |
| Overload | `replication_concurrency` semaphore, non-blocking acquire → 503 | no process-wide SSYNC semaphore today | 503 vs accept |
| Isolation | other client greenlets still run | **SSYNC hijack broken on production serve (`Body::Buffered`).** Do not “fix” by throwing the socket at a raw `spawn_blocking` (`AGENTS.md` §20). Do not raise workers. | a client GET during SSYNC fsync must still complete |

### Bad HTTP (AGENTS.md §28, included)

| Compare | Python | Peregrine today | Dual-feed |
|---|---|---|---|
| Line too long / too many headers | 431 (`http_protocol.py`) | 400 with configured max header bytes | code may differ (431 vs 400) — **record**, then decide L9 |
| HTTP/2 preface / bad version | 505 | 400/close | record |
| `Expect: kittens` | 417 | 417 | 417, no 100 |
| Bare `GET /` HTTP/0.9 | Python subset | 400 unless GET | 400 |

A documented 431-vs-400 is an L9 decision, not a silent runtime change.

---

## Current Gate 5 verdict

| Dimension | Library / unit | Live dual-feed | Keep-alive / L1 |
|---|---|---|---|
| status / headers / ETag / range / conditional | partial (`golden.rs`, `conditional.rs`, `title_case`) | not a full Swift replay | n/a |
| 100-continue protocol | **legacy GREEN** lazy-100 on `ConnBodyReader` (`handle_connection` only). Production `LegacyService` is **eager** (body fully buffered). | not yet | occupancy **PASS** at 2 workers (`align_expect_continue`); production 100 is **eager**. Dual-feed not run. |
| connection keep-alive density | n/a | live s3-tests not re-run this drop | **PASS** (`worker_starvation` at `spawn_server(2)`). Do not raise workers. |
| chunking / timeout / COPY / DELETE / SSYNC | unit / functional islands | not Gate 5 complete | SSYNC still not an async `SsyncSession`. **SSYNC hijack broken on production serve (`Body::Buffered`).** Handler still sync. Body fully buffered on async path. |
| S3 | frozen 57-case dual-oracle | 49/8 explained residuals | in-process idle occupancy no longer the 2-worker starve; live boto not re-certified here |

**Gate 5 = NO-GO.** Occupancy at 2 workers is no longer the blocker. Remaining: no full dual-feed, SSYNC hijack broken on production serve (`Body::Buffered`), proxy `std::net` fan-out, Handler still sync, body fully buffered on async path (NON-GOAL 8; eager 100 vs Python lazy 100), GET/HEAD + streamed response `Read` on the runtime thread, no live boto re-cert.

**Do not raise `workers` to close any of those.** That is still an L1 hide and is forbidden.

**Do not claim Eventlet solved.** `worker_starvation` PASS is Gate 1 in-process HTTP, not Gates 2–5.

---

## Invariants for later phases

- Dual-feed must not change Swift wire/storage semantics to make async easier (L9).
- `capitalize_response_headers` / `ETag` / lazy 100-continue / multiphase re-arm / SSYNC kick `\r\n` stay oracle-shaped.
- `align_expect_continue.rs` and `worker_starvation.rs` stay at `spawn_server(2, …)`. They are currently GREEN / expected PASS because idle connections are reactor-pending, **not** because the test grew a third thread. Reverting them to `spawn_server(3, …)` or SAIO `workers=64` is forbidden.
- Do **not** raise `workers` / `worker_threads` / `process_workers` / SAIO `workers=64` for differential, soak, or s3-tests.
- `--lib` stays green across this plan (no `swift-http/src/server.rs` edits in this drop).
