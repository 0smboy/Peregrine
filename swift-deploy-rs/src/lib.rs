//! Rust-native, safety-gated execution for the audited Swift deployment bundle.

pub mod bundle;
pub mod cli;
pub mod executor;
pub mod inventory;
pub mod model;
pub mod modules;
pub mod planner;
pub mod preflight;
pub mod safety;
pub mod template;
pub mod transport;
pub mod ui;
pub mod workspace;

pub use bundle::{audit_bundle, fingerprint_path};
pub use executor::Executor;
pub use inventory::{Group, Host, Inventory, fingerprint_inventory_inputs};
pub use model::{
    BundleAudit, ExecutionReport, LoopSpec, ModuleResult, PLAN_SCHEMA_VERSION, Plan, PlannedTask,
    RiskClass, SUPPORTED_MODULES,
};
pub use modules::ModuleDispatcher;
pub use planner::Planner;
pub use preflight::{HostPreflight, PreflightReport, run_preflight, run_preflight_with_bundle};
pub use safety::{SafetyPolicy, classify_task, redact};
pub use template::Renderer;
pub use transport::{
    CommandOutput, ConnectionSpec, OpenSshTransport, RecordingTransport, RemoteFileOptions,
    Transport, TransportAction,
};
pub use workspace::{
    Auth, GeneratedWorkspace, Ingress, Node, Ring, TempauthAccount, ValidationIssue,
    ValidationReport, WorkspaceFile, WorkspacePreview, WorkspaceRequest, WorkspaceSummary,
};
