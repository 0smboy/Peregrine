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

//! Core types and utilities shared by all Swift components.
//!
//! This crate is the Rust counterpart of `swift/common/utils/` and related
//! foundational modules in the Python implementation. Everything here is a
//! *compatibility contract*: string and wire representations must be
//! byte-identical with the Python implementation so that Rust and Python
//! daemons can coexist in the same cluster.

pub mod config;
pub mod constraints;
pub mod daemon;
pub mod fsutil;
pub mod hashing;
pub mod localdev;
pub mod lockutil;
pub mod obslog;
pub mod otlp;
pub mod pickle;
pub mod recon;
pub mod stage;
pub mod statsd;
pub mod storage_policy;
pub mod timestamp;

pub use constraints::Constraints;
pub use hashing::HashPathConfig;
pub use obslog::{LogLevel, Logger};
pub use statsd::StatsdClient;
pub use storage_policy::{StoragePolicy, StoragePolicyCollection};
pub use timestamp::Timestamp;
