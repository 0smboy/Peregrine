# P1 Streaming Data Path — Pinned API Contract (v1)

Audience: implementation agents for stages B1 (middleware), B2 (object
server + diskfile), B3 (account/container servers), C (proxy). Stage A
(swift-http) implements everything in section 1 and is ALREADY COMMITTED
when you start — code against it, do NOT modify swift-http. If the
contract is insufficient for your stage, STOP and report the gap in your
final answer instead of changing swift-http.

Goal: no code path materializes an object-sized body unless that is the
explicitly-documented status quo (marked `P1-leftover`). 5GB PUT/GET must
flow through bounded (~64KB) buffers end-to-end.

## 1. swift-http types (Stage A — the fixed foundation)

### 1.1 Body (used by BOTH Request and Response)

```rust
// swift_http::Body (re-exported at crate root)
pub enum Body {
    Buffered(Vec<u8>),
    Streamed(StreamedBody),
}
pub struct StreamedBody { /* private */ }
```

API (all on `Body`):

- `Body::empty() -> Body` — `Buffered(vec![])`.
- `impl From<Vec<u8>> / From<&[u8]> / From<String> / From<&str> for Body`.
- `Body::from_reader(reader: Box<dyn Read + Send>, content_length: Option<u64>) -> Body`
  — wrap any reader; `content_length: None` means "unknown until EOF".
- `fn content_length(&self) -> Option<u64>` — Buffered → `Some(len)`;
  Streamed → the declared length (None if unknown).
- `fn materialize(&mut self, cap: u64) -> std::io::Result<&[u8]>` — if
  Streamed, reads fully into memory (replacing self with Buffered) and
  returns the bytes; idempotent; reading more than `cap` bytes aborts with
  the too-large error (map to 413/appropriate status). A Buffered body
  larger than `cap` is returned as-is (cap guards the *read*, it is not a
  validator).
- `fn into_vec(self, cap: u64) -> std::io::Result<Vec<u8>>` — consuming
  variant.
- `fn into_reader(self) -> (Box<dyn Read + Send>, Option<u64>)` —
  Buffered → `(Cursor, Some(len))`.
- `fn take(&mut self) -> Body` — `mem::replace(self, Body::empty())`.
- `fn is_definitely_empty(&self) -> bool` — Buffered empty, or Streamed
  with declared length 0.
- `swift_http::body_too_large(err: &std::io::Error) -> bool` — detect the
  materialize-cap error.
- `Body` implements `Debug` (summary only). `Body` does NOT implement
  `Clone`.

Helper readers (in `swift_http`, for B1/B2/C use):

- `ChainReader::new(parts: Vec<Box<dyn Read + Send>>) -> ChainReader`
  — `impl Read`, reads parts in order.
- `FnReader::new(next: F) -> FnReader<F>` where
  `F: FnMut() -> Option<std::io::Result<Box<dyn Read + Send>>> + Send`
  — pull-based lazy chain: the closure is called when the previous part
  is exhausted; `None` = EOF. Use for SLO/DLO lazy segment streaming.

Materialize-cap constants (in `swift_http`):

- `pub const MAX_CONTROL_BODY: u64 = 64 * 1024 * 1024;` — for
  control-plane bodies (auth, REPLICATE args, listings, manifests other
  than the cases below).
- For status-quo big-body sites use
  `swift_core::constraints::MAX_FILE_SIZE as u64` and mark the line with
  a `// P1-leftover: still buffered` comment.

### 1.2 Request / Response

```rust
pub struct Request {
    pub method: String,
    pub path: String,
    pub query_string: String,
    pub headers: HeaderKeyDict,
    pub body: Body,                 // was Vec<u8>
}
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: HeaderKeyDict,
    pub body: Body,                 // was Vec<u8>
}
```

- NEITHER type implements `Clone` any more. Both implement `Debug`.
- `Request::clone_head(&self) -> Request` — same method/path/query/headers,
  `body: Body::empty()`. Use for the `orig_req = req.clone()` subrequest
  patterns; move the real body explicitly with `req.body.take()` when the
  subrequest must carry it.
- `Response::new(status)` unchanged. `Response::with_body(status, b)` now
  takes `impl Into<Body>` — existing `with_body(200, vec)` /
  `with_body(200, "text")` call sites keep compiling. `Response::error`
  unchanged.
- Struct-literal sites: `body: Vec::new()` → `body: Body::empty()`;
  `body: some_vec` → `body: some_vec.into()`.
- Read sites: `resp.body.len()` etc. do not compile any more. For
  test-only assertions use `resp.body.materialize(cap)` /
  `into_vec(cap)`. In src, decide per site: stream (preferred) or
  materialize with the documented cap.

### 1.3 Server behavior (informative — Stage A implements)

- The server no longer pre-reads bodies. `Request.body` arrives as
  `Streamed` (Content-Length-framed or chunked-decoding reader over the
  connection) whenever the request declares a body; otherwise
  `Body::empty()`.
- `Expect: 100-continue` is answered lazily on the FIRST read of the
  streamed body — a handler that rejects without reading the body never
  triggers the client upload (Python/eventlet parity).
- `max_body_bytes` is still enforced: at header-parse time for
  Content-Length, during decode for chunked.
- Response writing: Buffered as before. Streamed with known length →
  `Content-Length` set from it (when the header is absent) and a 64KB
  copy loop. Streamed with unknown length → `Connection: close` framing.
  A mid-stream read error aborts the connection (status already sent).
- HEAD responses: body is dropped WITHOUT being read.
- Keep-alive: after the handler, an unconsumed request body ≤64KB is
  drained; larger remainders close the connection.
- New `ServerConfig` fields: `head_deadline_secs: u64` (default 30, 0
  disables) — total wall-clock budget for request line + headers
  (slowloris guard). Body reads keep the per-chunk `client_timeout`
  semantics (Python parity).

## 2. swift-middleware pipeline (Stage B1 owns the change)

```rust
pub type NextFn = Arc<dyn Fn(Request) -> Response + Send + Sync>;
pub trait Middleware: Send + Sync {
    fn handle(&self, req: Request, next: &NextFn) -> Response;
}
pub fn build_pipeline(filters: Vec<Arc<dyn Middleware>>, app: NextFn) -> NextFn;
```

`next(req)` call sites keep working (auto-deref). The Arc makes it legal
to `Arc::clone(next)` INTO a streaming response body (lazy SLO/DLO
segment readers). s3api implements this trait too → the s3api crate is in
B1's scope.

## 3. Per-stage obligations

### B1 — swift-middleware + swift-s3api

- Apply the pipeline signature change (section 2) everywhere.
- `req.clone()` sites → `clone_head()` (+ explicit `body.take()` where the
  body must travel).
- SLO GET: replace `fetch_segments` concatenation with a
  `FnReader`-based lazy reader that issues each segment subrequest
  (via a cloned `NextFn`) only when the stream reaches it; response
  `content_length` = manifest total; segment status/etag/size mismatch
  mid-stream → the reader returns `Err` (connection aborts — Python
  parity). SLO manifest PUT: `materialize(8 * 1024 * 1024)` (Python
  max_manifest_size).
- DLO GET: same lazy pattern over the container listing.
- copy + versioned_writes: plumb source-GET response body into
  destination-PUT request body via `Body::from_reader(resp.body.into_reader())`
  — never materialize object bodies.
- bulk, formpost: status quo (buffered) with
  `materialize(MAX_FILE_SIZE)` + `// P1-leftover: still buffered`.
- Everything else that reads request/response bodies (listing_formats,
  staticweb, tempauth …): `materialize(MAX_CONTROL_BODY)`; on too-large
  return 413 (requests) / 502-ish passthrough judgment (responses —
  prefer passing the response through untouched if it is unexpectedly
  huge rather than erroring).
- Gate: `cargo test -p swift-middleware -p swift-s3api` green, clippy
  clean for those crates.

### B2 — swift-object-server + swift-diskfile

- PUT: consume `req.body` as a stream: loop `read` (64KB) → md5 update →
  `DiskFileWriter::write(chunk)`; enforce `MAX_FILE_SIZE` cumulatively
  (413), verify actual bytes == Content-Length when declared (mismatch →
  499 client-disconnect handling: abort without commit), fallocate_reserve
  checked against declared Content-Length (0/absent for chunked). ETag
  and Content-Length metadata computed from what was actually written.
  Client read error mid-body → 499, no commit, temp file cleaned by
  DiskFileWriter drop/close.
- GET: stream from disk. Add to `DiskFileReader`: range-window support
  (`app_iter_range`-equivalent: seek + bounded read) so single-range 206
  streams; expose an `impl Read` adapter (quarantine-on-close semantics
  preserved for FULL reads; ranged reads skip the etag check — Python
  parity). Multi-range 206: compose part headers + range windows with
  `ChainReader` (streaming, no whole-object buffer). HEAD must not open
  the data file's contents at all (metadata only).
- SSYNC/REPLICATE and every other body consumer: `materialize` with the
  existing session bounds (SSYNC: `MAX_SESSION_BYTES`) or
  `MAX_CONTROL_BODY`.
- `handle(&self, req: Request)` may change internal signatures
  (`&Request` → `&mut Request` / by-value) freely within the crate.
- Gate: `cargo test -p swift-object-server -p swift-diskfile` green,
  clippy clean for those crates. (The `ec` feature is Linux-only — do NOT
  try to build it; keep `#[cfg(feature = "ec")]` code compiling by eye,
  using materialize for fragment bodies with the P1-leftover marker.)

### B3 — swift-account-server + swift-container-server

- Mechanical: materialize request bodies at the consuming sites with
  `MAX_CONTROL_BODY` (REPLICATE pickled/JSON args, shard-range PUT
  bodies). Responses stay buffered (listings — status quo, they are
  bounded by listing limits).
- Gate: `cargo test -p swift-account-server -p swift-container-server`
  green, clippy clean for those crates.

### C — swift-proxy-server (+ any bin fallout, workspace green)

- `BackendResponse.body` becomes `swift_http::Body`. `backend_request`
  keeps a `&[u8]` send-body (control plane) but gains header-first
  response handling: object GET paths hand the socket to the response as
  a Content-Length-framed (or close-delimited) reader; error/control
  responses materialize (≤ `MAX_CONTROL_BODY`).
- Object GET/HEAD (`get_or_head` object path): stream the winning
  source's body to the client; 404/5xx decision logic reads headers only
  (as today). No mid-stream failover (documented non-goal this pass).
- Object PUT: replace `make_requests(body.clone())` with a ported
  connect-then-stream protocol (obj.py `_get_put_connections` /
  `_transfer_data` shape): (1) connect to nodes from the pool, send
  headers with `Expect: 100-continue` (Content-Length passthrough, or
  `Transfer-Encoding: chunked` when the client length is unknown), await
  100 within node_timeout, error-limit failures and pull replacement
  nodes until the pool is dry; abort 503 unless ≥ quorum connections; (2)
  ONE read loop over the client body writing each 64KB chunk to every
  live connection (a write failure drops that connection; if live conns
  fall below quorum → abort 503; client read error → 499); (3) collect
  final statuses, pad failures with 503 stubs, `best_response`. Announce
  `Etag` handling exactly as the buffered path did where feasible
  (backend computes/validates; proxy no longer pre-computes md5).
- Account/container requests and object POST/DELETE: keep the buffered
  `make_requests` (materialize client body ≤ `MAX_CONTROL_BODY`).
- EC PUT/GET (`#[cfg(feature = "ec")]`): materialize with
  `MAX_FILE_SIZE` + `// P1-leftover: still buffered` (streaming EC is a
  later pass; must still compile on Linux).
- proxy `main.rs`: adapt to the B1 pipeline types.
- Gate: FULL workspace `cargo test` green + `cargo clippy` clean.

## 4. Shared rules

- Never call `materialize` without an explicit, justified cap.
- Copy-loop buffer size: 64KB (`64 * 1024`).
- Do not add dependencies to any Cargo.toml.
- Tests that constructed `Request { body: vec }` literals: `vec.into()`.
  Tests asserting on `resp.body`: `materialize`/`into_vec` with a test
  cap (`usize::MAX as u64` is fine in tests).
- Keep every existing golden/oracle test green — byte-format behavior
  must not change.
