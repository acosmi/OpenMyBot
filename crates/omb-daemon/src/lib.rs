//! Foreground local composition and authenticated Unix control transport.

mod agent;
mod channels;
mod config;
mod control;
mod daemon;
mod delegation;
mod dispatch;
mod engine;
mod init;
#[cfg(test)]
mod integration;
mod ops;
mod outbound;
mod pairing;
mod pg;
mod plugins;
mod reconcile;
mod supervisor;
mod tenant;

use omb_store::{ReplyTexts, StateLabels};
use serde::{Deserialize, Serialize};
use std::{future::Future, path::PathBuf, sync::atomic::AtomicU64, time::Duration};
use tokio::{sync::oneshot, task::JoinHandle};
use uuid::Uuid;

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
    pub plugins: Vec<PluginStatus>,
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
/// One installed channel plugin in the status plugin segment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct PluginStatus {
    pub name: String,
    pub version: String,
    pub channels: Vec<String>,
    pub process: ProcessState,
    pub last_exit_code: Option<i32>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    Running,
    Stopped,
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
    PluginNotInstalled => ("plugin_not_installed", Rejected),
    PluginInvalid => ("plugin_invalid", Rejected),
    ChannelKindTaken => ("channel_kind_taken", Rejected),
    PluginInUse => ("plugin_in_use", Rejected),
    PluginUnavailable => ("plugin_unavailable", Rejected),
}

pub(crate) const HEARTBEAT: Duration = Duration::from_secs(30);
pub(crate) const HEARTBEAT_GAP: Duration = Duration::from_secs(90);
pub(crate) const BACKOFF_MIN: Duration = Duration::from_secs(1);
pub(crate) const BACKOFF_MAX: Duration = Duration::from_secs(60);
pub(crate) const DISPATCH_RETRY: Duration = Duration::from_secs(5);
pub(crate) const DISPATCH_PENDING_TTL: Duration = Duration::from_secs(24 * 3600);
/// Deadline of the tasks' own store writes.
pub(crate) const STORE_BUDGET: Duration = Duration::from_secs(2);
/// UTF-8 bytes of one outbound message text.
pub(crate) const DELIVERY_BODY_MAX: usize = 3 * 1024;
/// How often an idle outbound task looks for due delivery rows.
pub(crate) const DELIVERY_POLL: Duration = Duration::from_secs(1);
/// Waits before the first to the fifth retry of a definite delivery failure.
pub(crate) const DELIVERY_RETRY: [Duration; 5] = [
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(240),
    Duration::from_secs(480),
    Duration::from_secs(960),
];
pub(crate) const SWEEP_INTERVAL: Duration = Duration::from_secs(600);
pub(crate) const TOMBSTONE_RETENTION: Duration = Duration::from_secs(30 * 24 * 3600);
pub(crate) const CONTENT_RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);
/// Capacity of the engine's terminal notices on their way to the outbound task.
pub(crate) const TERMINAL_QUEUE: usize = 256;

pub(crate) const OMB_REPLY_HELP_V1: &str = "OpenMyBot 已就绪。直接发送消息即可在绑定的工作区内开始一轮工作。命令：/status 查看当前状态，/cancel 取消当前任务，/help 显示本说明。";
pub(crate) const OMB_REPLY_STATUS_V1: &str = "绑定：{channel} 已激活，工作区 {dir}。最近一轮：{state}。待处理：{pending} 条。最近中断：{gap}。";
pub(crate) const OMB_REPLY_CANCEL_REQUESTED_V1: &str = "已请求取消当前任务。";
pub(crate) const OMB_REPLY_CANCEL_NONE_V1: &str = "当前没有进行中的任务。";
pub(crate) const OMB_REJECT_OUTSIDE_WINDOW_V1: &str = "消息时间超出接收窗口，未处理。";
pub(crate) const OMB_REJECT_TOO_LONG_V1: &str = "消息过长，未处理。";
pub(crate) const OMB_REJECT_UNSUPPORTED_V1: &str = "仅支持文本消息，未处理。";
pub(crate) const OMB_REJECT_QUEUE_FULL_V1: &str = "待处理消息已满，请稍后再发。";
pub(crate) const OMB_EXPIRY_NOTICE_V1: &str = "消息等待超过 24 小时未能处理，已过期。";
pub(crate) const OMB_REPLY_ALREADY_BOUND_V1: &str = "已绑定";
pub(crate) const OMB_REPLY_UNKNOWN_COMMAND_V1: &str = "未知命令，发送 /help";
pub(crate) const OMB_RESULT_SUCCEEDED_V1: &str = "已完成";
pub(crate) const OMB_RESULT_FAILED_V1: &str = "失败";
pub(crate) const OMB_RESULT_CANCELLED_V1: &str = "已取消";
pub(crate) const OMB_RESULT_UNKNOWN_V1: &str =
    "结果未知，在本机执行 openmybot status --run {run_id} 核对";
pub(crate) const OMB_STATE_LABELS_V1: StateLabels<'static> = StateLabels {
    none: "无",
    queued: "排队中",
    running: "进行中",
    conflict: "冲突",
    expired: "已过期",
    cancelled: "已取消",
    succeeded: "已完成",
    failed: "失败",
    reconciliation: "待对账",
};
pub(crate) const OMB_REPLY_TEXTS_V1: ReplyTexts<'static> = ReplyTexts {
    help: OMB_REPLY_HELP_V1,
    already_bound: OMB_REPLY_ALREADY_BOUND_V1,
    unknown_command: OMB_REPLY_UNKNOWN_COMMAND_V1,
    cancel_requested: OMB_REPLY_CANCEL_REQUESTED_V1,
    cancel_none: OMB_REPLY_CANCEL_NONE_V1,
    status: OMB_REPLY_STATUS_V1,
    states: OMB_STATE_LABELS_V1,
    outside_window: OMB_REJECT_OUTSIDE_WINDOW_V1,
    too_long: OMB_REJECT_TOO_LONG_V1,
    unsupported: OMB_REJECT_UNSUPPORTED_V1,
    queue_full: OMB_REJECT_QUEUE_FULL_V1,
};
/// Capacity of the `/cancel` hand-off from the receiving side to the daemon's run canceller.
pub(crate) const CANCEL_QUEUE: usize = 16;
/// The narrow handle the receiving side holds: it passes only the binding id of a committed
/// `/cancel`.
pub(crate) type CancelRequests = tokio::sync::mpsc::Sender<Uuid>;

/// Task intervals and plugin limits; `Default` is the specified budget, tests shorten them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timings {
    pub(crate) heartbeat: Duration,
    pub(crate) heartbeat_gap: Duration,
    pub(crate) backoff_min: Duration,
    pub(crate) backoff_max: Duration,
    pub(crate) dispatch_retry: Duration,
    pub(crate) pending_ttl: Duration,
    pub(crate) delivery_poll: Duration,
    pub(crate) delivery_retry: [Duration; 5],
    pub(crate) sweep_interval: Duration,
    pub(crate) tombstone_retention: Duration,
    pub(crate) content_retention: Duration,
    pub(crate) plugin_hello: Duration,
    pub(crate) plugin_ack: Duration,
    pub(crate) plugin_send: Duration,
    /// The first restart delay of a crashed plugin; later restarts back off up to `backoff_max`.
    pub(crate) plugin_restart: Duration,
}
impl Default for Timings {
    fn default() -> Self {
        Self {
            heartbeat: HEARTBEAT,
            heartbeat_gap: HEARTBEAT_GAP,
            backoff_min: BACKOFF_MIN,
            backoff_max: BACKOFF_MAX,
            dispatch_retry: DISPATCH_RETRY,
            pending_ttl: DISPATCH_PENDING_TTL,
            delivery_poll: DELIVERY_POLL,
            delivery_retry: DELIVERY_RETRY,
            sweep_interval: SWEEP_INTERVAL,
            tombstone_retention: TOMBSTONE_RETENTION,
            content_retention: CONTENT_RETENTION,
            plugin_hello: omb_channel_sdk::HELLO_TIMEOUT,
            plugin_ack: omb_channel_sdk::ACK_TIMEOUT,
            plugin_send: omb_channel_sdk::SEND_TIMEOUT,
            plugin_restart: BACKOFF_MIN,
        }
    }
}
/// In-process counters of channel input that leaves no row.
#[derive(Debug, Default)]
pub(crate) struct Counters {
    pub(crate) platform_payload_unparseable: AtomicU64,
    pub(crate) event_conflict: AtomicU64,
    pub(crate) unsupported_update: AtomicU64,
    /// Plugin frames out of place, malformed, unknown or over the size limit.
    pub(crate) protocol_violation: AtomicU64,
    /// `sent` or `send_failed` after the delivery attempt already ended.
    pub(crate) late_send_result: AtomicU64,
}
/// A store connection owned by one task.
pub(crate) struct Connection {
    pub(crate) client: tokio_postgres::Client,
    pub(crate) driver: JoinHandle<Result<(), tokio_postgres::Error>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ChannelError {
    #[error("channel_store_failed")]
    StoreFailed,
}
/// One running dispatcher, heartbeat, outbound task or sweeper with its stop signal and connection.
pub(crate) struct Task {
    stop: oneshot::Sender<()>,
    handle: JoinHandle<Result<(), ChannelError>>,
    driver: JoinHandle<Result<(), tokio_postgres::Error>>,
}
impl Task {
    pub(crate) fn spawn<F>(
        connection: Connection,
        run: impl FnOnce(tokio_postgres::Client, oneshot::Receiver<()>) -> F,
    ) -> Self
    where
        F: Future<Output = Result<(), ChannelError>> + Send + 'static,
    {
        let (stop, signal) = oneshot::channel();
        Self {
            stop,
            handle: tokio::spawn(run(connection.client, signal)),
            driver: connection.driver,
        }
    }
    /// Resolves when the task ends on its own; must not be called again after it resolved.
    pub(crate) async fn finished(&mut self) -> Result<(), ChannelError> {
        (&mut self.handle)
            .await
            .unwrap_or(Err(ChannelError::StoreFailed))
    }
    /// Signals the task, joins it unless it already ended, then joins the connection it owned.
    pub(crate) async fn stop(self) {
        let _ = self.stop.send(());
        if !self.handle.is_finished() {
            let _ = self.handle.await;
        }
        let _ = self.driver.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn from_code_inverts_code_for_every_variant() {
        for error in DaemonError::ALL {
            assert_eq!(DaemonError::from_code(error.code()), Some(*error));
        }
        assert_eq!(DaemonError::ALL.len(), 51);
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
            ("plugin_not_installed", DaemonError::PluginNotInstalled),
            ("plugin_invalid", DaemonError::PluginInvalid),
            ("channel_kind_taken", DaemonError::ChannelKindTaken),
            ("plugin_in_use", DaemonError::PluginInUse),
            ("plugin_unavailable", DaemonError::PluginUnavailable),
        ] {
            assert_eq!(DaemonError::from_code(code), Some(error));
            assert_eq!(error.class(), ErrorClass::Rejected);
        }
    }
    #[test]
    fn timings_default_equals_spec_constants() {
        let timings = Timings::default();
        assert_eq!(timings.heartbeat, Duration::from_secs(30));
        assert_eq!(timings.heartbeat_gap, Duration::from_secs(90));
        assert_eq!(timings.backoff_min, Duration::from_secs(1));
        assert_eq!(timings.backoff_max, Duration::from_secs(60));
        assert_eq!(timings.dispatch_retry, Duration::from_secs(5));
        assert_eq!(timings.pending_ttl, Duration::from_secs(24 * 3600));
        assert_eq!(timings.delivery_poll, Duration::from_secs(1));
        assert_eq!(
            timings.delivery_retry,
            [60, 120, 240, 480, 960].map(Duration::from_secs)
        );
        assert_eq!(timings.sweep_interval, Duration::from_secs(600));
        assert_eq!(
            timings.tombstone_retention,
            Duration::from_secs(30 * 24 * 3600)
        );
        assert_eq!(
            timings.content_retention,
            Duration::from_secs(7 * 24 * 3600)
        );
        assert_eq!(timings.plugin_hello, Duration::from_secs(5));
        assert_eq!(timings.plugin_ack, Duration::from_secs(3));
        assert_eq!(timings.plugin_send, Duration::from_secs(35));
        assert_eq!(timings.plugin_restart, Duration::from_secs(1));
    }
    #[test]
    fn reply_constants_and_help_text_are_fixed() {
        assert_eq!(
            OMB_REPLY_HELP_V1,
            "OpenMyBot 已就绪。直接发送消息即可在绑定的工作区内开始一轮工作。命令：/status 查看当前状态，/cancel 取消当前任务，/help 显示本说明。"
        );
        assert_eq!(OMB_REPLY_CANCEL_REQUESTED_V1, "已请求取消当前任务。");
        assert_eq!(OMB_REPLY_CANCEL_NONE_V1, "当前没有进行中的任务。");
        assert_eq!(
            OMB_REPLY_TEXTS_V1.cancel_requested,
            OMB_REPLY_CANCEL_REQUESTED_V1
        );
        assert_eq!(OMB_REPLY_TEXTS_V1.cancel_none, OMB_REPLY_CANCEL_NONE_V1);
        assert_eq!(OMB_REPLY_TEXTS_V1.help, OMB_REPLY_HELP_V1);
        assert_eq!(CANCEL_QUEUE, 16);
    }
    #[test]
    fn delivery_constants_and_result_texts_are_fixed() {
        assert_eq!(DELIVERY_BODY_MAX, 3072);
        assert_eq!(TERMINAL_QUEUE, 256);
        assert_eq!(OMB_RESULT_SUCCEEDED_V1, "已完成");
        assert_eq!(OMB_RESULT_FAILED_V1, "失败");
        assert_eq!(OMB_RESULT_CANCELLED_V1, "已取消");
        assert_eq!(
            OMB_RESULT_UNKNOWN_V1,
            "结果未知，在本机执行 openmybot status --run {run_id} 核对"
        );
    }
}
