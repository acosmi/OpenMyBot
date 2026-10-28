//! Foreground local composition and authenticated Unix control transport.

mod channels;
mod config;
mod control;
mod daemon;
mod delegation;
mod engine;
mod init;
mod pairing;
mod pg;
mod tenant;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use config::resolve_data_dir;
pub use control::status;
pub use daemon::daemon;
pub use engine::Engine;
pub use init::init;
pub use pairing::{PairRequest, pair};
pub use pg::Postgres;

pub struct DataDirectoryInput {
    pub explicit: Option<PathBuf>,
    pub environment: Option<PathBuf>,
    pub home: Option<PathBuf>,
}
pub struct InitOptions {
    pub data_dir: PathBuf,
    pub pg_bin_dir: PathBuf,
}
pub struct DaemonOptions {
    pub data_dir: PathBuf,
}
pub struct StatusOptions {
    pub data_dir: PathBuf,
}
#[derive(Debug, Serialize)]
pub struct InitResult {
    pub deployment_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusSnapshot {
    pub deployment_id: String,
    pub daemon_pid: u32,
    pub pg_pid: u32,
    pub pg_server_version_num: u32,
    pub daemon_version: String,
    pub engine_pin: String,
    pub authentication_failures: u64,
    pub channels: Vec<ChannelStatus>,
}
/// One receiver in the status channel segment; times are RFC 3339 UTC.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelStatus {
    pub channel: String,
    pub binding_id: String,
    pub status: String,
    pub status_reason: Option<String>,
    pub pending_dispatch: u64,
    pub gaps: Vec<GapStatus>,
    pub note: String,
    pub counters: ChannelCounters,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GapStatus {
    pub reason: String,
    pub started_at: String,
    pub ended_at: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelCounters {
    pub platform_payload_unparseable: u64,
    pub event_conflict: u64,
    pub unsupported_update: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    Usage,
    NotRunning,
    Rejected,
    Internal,
}

macro_rules! errors {
    ($($variant:ident => ($code:literal, $class:ident)),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
        pub enum DaemonError { $(#[error($code)] $variant),+ }
        impl DaemonError {
            pub const fn code(&self) -> &'static str { match self { $(Self::$variant => $code),+ } }
            pub const fn class(&self) -> ErrorClass { match self { $(Self::$variant => ErrorClass::$class),+ } }
        }
    }
}
errors! {
    InvalidArguments => ("invalid_arguments", Usage),
    DataDirNotEmpty => ("data_dir_not_empty", Rejected),
    DataDirPermissionsInvalid => ("data_dir_permissions_invalid", Rejected),
    ControlSocketPathTooLong => ("control_socket_path_too_long", Rejected),
    PgBinariesRejected => ("pg_binaries_rejected", Rejected),
    DaemonAlreadyRunning => ("daemon_already_running", Rejected),
    StalePostgresRunning => ("stale_postgres_running", Rejected),
    PostmasterPidForeign => ("postmaster_pid_foreign", Rejected),
    PgVersionRejected => ("pg_version_rejected", Rejected),
    PgHbaRejected => ("pg_hba_rejected", Rejected),
    DaemonNotRunning => ("daemon_not_running", NotRunning),
    RequestTimeout => ("request_timeout", Rejected),
    OpNotAllowed => ("op_not_allowed", Rejected),
    InvalidRequest => ("invalid_request", Rejected),
    InitFailed => ("init_failed", Internal),
    PgStartFailed => ("pg_start_failed", Internal),
    EngineInitializationFailed => ("engine_initialization_failed", Internal),
    TenantPackageFailed => ("tenant_package_failed", Internal),
    ControlTokenFailed => ("control_token_failed", Internal),
    EngineAssemblyFailed => ("engine_assembly_failed", Internal),
    ControlSocketFailed => ("control_socket_failed", Internal),
    ShutdownFailed => ("shutdown_failed", Internal),
    InternalError => ("internal_error", Internal),
    OmbMigrationDrift => ("omb_migration_drift", Rejected),
    OmbSchemaNewer => ("omb_schema_newer", Rejected),
    OmbMigrationFailed => ("omb_migration_failed", Internal),
    ChannelAlreadyBound => ("channel_already_bound", Rejected),
    ReceiverNotActive => ("receiver_not_active", Rejected),
    WorkspaceInvalid => ("workspace_invalid", Rejected),
    BindingNotFound => ("binding_not_found", Rejected),
    BindingStateInvalid => ("binding_state_invalid", Rejected),
    BindingFailed => ("binding_failed", Internal),
}
