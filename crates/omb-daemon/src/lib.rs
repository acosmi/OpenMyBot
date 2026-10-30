//! Foreground local composition and authenticated Unix control transport.

mod agent;
mod channels;
mod config;
mod control;
mod daemon;
mod delegation;
mod engine;
mod init;
#[cfg(test)]
mod integration;
mod ops;
mod pairing;
mod pg;
mod reconcile;
mod tenant;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub use config::resolve_data_dir;
pub use control::{call, call_mcp, status};
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
/// One control operation and its arguments; the arguments may carry a channel secret.
pub struct CallOptions {
    pub data_dir: PathBuf,
    pub op: String,
    pub args: serde_json::Value,
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
            pub fn from_code(code: &str) -> Option<DaemonError> { match code { $($code => Some(Self::$variant),)+ _ => None } }
            pub const ALL: &'static [DaemonError] = &[$(Self::$variant),+];
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
    HostBinaryInvalid => ("host_binary_invalid", Rejected),
    WorkspaceRootInvalid => ("workspace_root_invalid", Rejected),
    AgentRuntimeFailed => ("agent_runtime_failed", Internal),
    PermissionNotPending => ("permission_not_pending", Rejected),
    PermissionExpired => ("permission_expired", Rejected),
    RunNotFound => ("run_not_found", Rejected),
    CredentialRejected => ("credential_rejected", Rejected),
    WebhookConflict => ("webhook_conflict", Rejected),
    ChannelUnreachable => ("channel_unreachable", Rejected),
    HostNotBound => ("host_not_bound", Rejected),
    HostBindingSuspended => ("host_binding_suspended", Rejected),
    OperationConflict => ("operation_conflict", Rejected),
    RunNotTerminal => ("run_not_terminal", Rejected),
    DispatchQueueFull => ("dispatch_queue_full", Rejected),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn from_code_inverts_code_for_every_variant() {
        for error in DaemonError::ALL {
            assert_eq!(DaemonError::from_code(error.code()), Some(*error));
        }
        assert_eq!(DaemonError::ALL.len(), 46);
        assert_eq!(DaemonError::from_code("channel_not_supported"), None);
        for unknown in ["", "INTERNAL_ERROR", "not_a_code", "internal_error "] {
            assert_eq!(DaemonError::from_code(unknown), None);
        }
        for (code, error) in [
            ("permission_not_pending", DaemonError::PermissionNotPending),
            ("permission_expired", DaemonError::PermissionExpired),
            ("run_not_found", DaemonError::RunNotFound),
            ("credential_rejected", DaemonError::CredentialRejected),
            ("webhook_conflict", DaemonError::WebhookConflict),
            ("channel_unreachable", DaemonError::ChannelUnreachable),
            ("host_not_bound", DaemonError::HostNotBound),
            ("host_binding_suspended", DaemonError::HostBindingSuspended),
            ("operation_conflict", DaemonError::OperationConflict),
            ("run_not_terminal", DaemonError::RunNotTerminal),
            ("dispatch_queue_full", DaemonError::DispatchQueueFull),
        ] {
            assert_eq!(DaemonError::from_code(code), Some(error));
            assert_eq!(error.class(), ErrorClass::Rejected);
        }
    }
}
