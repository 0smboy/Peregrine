//! COSBench core engine (Rust v1.0).

pub mod auth;
pub mod config;
pub mod driver;
pub mod generator;
pub mod integrity;
pub mod metrics;
pub mod ops;
pub mod report;
pub mod storage;
pub mod xml_import;

pub use config::Workload;
pub use driver::{Driver, StageReport};
pub use metrics::{MetricsSnapshot, StageMetrics};
pub use report::ReportBundle;
