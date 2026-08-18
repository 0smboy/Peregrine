// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! swob-compatible HTTP primitives (`swift/common/swob.py`,
//! `header_key_dict.py`) and a small threaded HTTP/1.1 server used by the
//! Rust account/container/object servers.
//!
//! The parsing semantics here are compatibility contracts: `Range` and
//! `Match` reproduce swob's RFC-2616-plus-quirks behavior exactly
//! (golden-tested against the Python implementation).

mod body;
pub mod clock_health;
mod conditional;
mod dates;
mod headers;
mod mime;
mod range;
mod request;
pub mod server;
pub mod thread_concurrency;

pub use body::{
    body_too_large, Body, ChainReader, FnReader, InterimResponder, SharedBytesReader, StreamedBody,
    MAX_CONTROL_BODY, STREAM_CHUNK,
};
pub use clock_health::{parse_chronyc_tracking_csv, ClockHealth, ClockOffsetReader};
pub use conditional::{apply_conditional, conditional_response_status, resolve_etag_is_at};
pub use dates::{http_date, parse_http_date};
pub use headers::{title_case, HeaderKeyDict};
pub use mime::MimeDocs;
pub use range::{
    content_range_header_value, multipart_byteranges, multipart_byteranges_content_type,
    normalize_etag, Match, Range,
};
pub use request::{parse_query, reason_phrase, split_path, unquote, Request, Response};
pub use server::{
    bind_listener, install_sigterm_flag, serve_forever, serve_forever_multi,
    serve_forever_with_config, AccessLog, Handler, ServerConfig,
};
pub use thread_concurrency::{
    compute_concurrency, cooperative_yield, green_sleep, should_yield_heartbeat, yield_count,
    EventletConcurrency, GreenLocal, GreenthreadPool, WORKER_THREADS_CAP,
};
