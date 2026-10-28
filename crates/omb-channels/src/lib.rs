//! Outbound channel receivers, the delegated-run dispatcher and the daemon heartbeat.
mod dispatcher;
mod telegram;
#[cfg(feature = "testkit")]
pub mod testkit;

pub use dispatcher::start_dispatcher;
pub use telegram::{
    CredentialProblem, FingerprintInput, Normalized, ReceiverContext, backoff, backoff_ceiling,
    canonical_json, classify, fingerprint, next_offset, normalize, start_receiver,
    verify_credentials,
};

use omb_store::{ReplyTexts, StateLabels, touch_heartbeat};
use openbot_infra::net::safe_http::{SafeDialer, SchemePolicy};
use std::{future::Future, sync::atomic::AtomicU64, time::Duration};
use tokio::{sync::oneshot, task::JoinHandle, time::Instant};
use url::Url;
use uuid::Uuid;

pub const HEARTBEAT: Duration = Duration::from_secs(30);
pub const HEARTBEAT_GAP: Duration = Duration::from_secs(90);
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);
pub const TG_POLL_TIMEOUT: Duration = Duration::from_secs(50);
/// The HTTP deadline of one long poll is the poll timeout plus this margin.
pub const TG_HTTP_MARGIN: Duration = Duration::from_secs(15);
pub const TG_POLL_LIMIT: u32 = 100;
pub const TG_OFFSET_STALE: Duration = Duration::from_secs(6 * 24 * 3600);
pub const DISPATCH_RETRY: Duration = Duration::from_secs(5);
pub const DISPATCH_PENDING_TTL: Duration = Duration::from_secs(24 * 3600);
/// Larger `getUpdates` bodies are refused as a broken stream and fetched again.
pub const TG_RESPONSE_MAX: usize = 8 * 1024 * 1024;
/// Deadline of the tasks' own store writes.
const STORE_BUDGET: Duration = Duration::from_secs(2);

pub const OMB_REPLY_HELP_V1: &str = "OpenMyBot 已就绪。直接发送消息即可在绑定的工作区内开始一轮工作。命令：/status 查看当前状态，/help 显示本说明。";
pub const OMB_REPLY_STATUS_V1: &str = "绑定：{channel} 已激活，工作区 {dir}。最近一轮：{state}。待处理：{pending} 条。最近中断：{gap}。";
pub const OMB_REPLY_CANCEL_UNAVAILABLE_V1: &str = "取消暂不可用。";
pub const OMB_REJECT_OUTSIDE_WINDOW_V1: &str = "消息时间超出接收窗口，未处理。";
pub const OMB_REJECT_TOO_LONG_V1: &str = "消息过长，未处理。";
pub const OMB_REJECT_UNSUPPORTED_V1: &str = "仅支持文本消息，未处理。";
pub const OMB_REJECT_QUEUE_FULL_V1: &str = "待处理消息已满，请稍后再发。";
pub const OMB_EXPIRY_NOTICE_V1: &str = "消息等待超过 24 小时未能处理，已过期。";
pub const OMB_REPLY_ALREADY_BOUND_V1: &str = "已绑定";
pub const OMB_REPLY_UNKNOWN_COMMAND_V1: &str = "未知命令，发送 /help";
pub const OMB_STATE_LABELS_V1: StateLabels<'static> = StateLabels {
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
pub const OMB_REPLY_TEXTS_V1: ReplyTexts<'static> = ReplyTexts {
    help: OMB_REPLY_HELP_V1,
    already_bound: OMB_REPLY_ALREADY_BOUND_V1,
    unknown_command: OMB_REPLY_UNKNOWN_COMMAND_V1,
    cancel_unavailable: OMB_REPLY_CANCEL_UNAVAILABLE_V1,
    status: OMB_REPLY_STATUS_V1,
    states: OMB_STATE_LABELS_V1,
    outside_window: OMB_REJECT_OUTSIDE_WINDOW_V1,
    too_long: OMB_REJECT_TOO_LONG_V1,
    unsupported: OMB_REJECT_UNSUPPORTED_V1,
    queue_full: OMB_REJECT_QUEUE_FULL_V1,
};
/// Status note of the Telegram receiver.
pub const CHANNEL_NOTE: &str = "telegram 长轮询";

/// Task intervals; `Default` is the specified budget, tests shorten them.
#[derive(Clone, Copy, Debug)]
pub struct Timings {
    pub heartbeat: Duration,
    pub heartbeat_gap: Duration,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
    pub poll_timeout: Duration,
    pub dispatch_retry: Duration,
    pub pending_ttl: Duration,
}
impl Default for Timings {
    fn default() -> Self {
        Self {
            heartbeat: HEARTBEAT,
            heartbeat_gap: HEARTBEAT_GAP,
            backoff_min: BACKOFF_MIN,
            backoff_max: BACKOFF_MAX,
            poll_timeout: TG_POLL_TIMEOUT,
            dispatch_retry: DISPATCH_RETRY,
            pending_ttl: DISPATCH_PENDING_TTL,
        }
    }
}
/// In-process counters of platform input that leaves no row.
#[derive(Debug, Default)]
pub struct Counters {
    pub platform_payload_unparseable: AtomicU64,
    pub event_conflict: AtomicU64,
    pub unsupported_update: AtomicU64,
}
/// A store connection owned by one task.
pub struct Connection {
    pub client: tokio_postgres::Client,
    pub driver: JoinHandle<Result<(), tokio_postgres::Error>>,
}
/// Where the Bot API is reached; production is HTTPS to the public endpoint only.
#[derive(Clone)]
pub struct TelegramEndpoint {
    pub api_base: Url,
    pub dialer: SafeDialer,
    pub scheme: SchemePolicy,
}
impl TelegramEndpoint {
    pub fn production(dialer: SafeDialer) -> Self {
        Self {
            api_base: Url::parse("https://api.telegram.org/").expect("static Bot API origin"),
            dialer,
            scheme: SchemePolicy::HttpsOnly,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    #[error("channel_store_failed")]
    StoreFailed,
}

/// One running receiver, dispatcher or heartbeat with its stop signal and connection.
pub struct Task {
    stop: oneshot::Sender<()>,
    handle: JoinHandle<Result<(), ChannelError>>,
    driver: JoinHandle<Result<(), tokio_postgres::Error>>,
}
impl Task {
    fn spawn<F>(
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
    pub async fn finished(&mut self) -> Result<(), ChannelError> {
        (&mut self.handle)
            .await
            .unwrap_or(Err(ChannelError::StoreFailed))
    }
    /// Signals the task, joins it unless it already ended, then joins the connection it owned.
    pub async fn stop(self) {
        let _ = self.stop.send(());
        if !self.handle.is_finished() {
            let _ = self.handle.await;
        }
        let _ = self.driver.await;
    }
}

/// Advances `last_heartbeat_at` every `heartbeat`; a store failure ends the task.
pub fn start_heartbeat(connection: Connection, token_id: Uuid, timings: Timings) -> Task {
    Task::spawn(connection, move |mut client, mut stop| async move {
        loop {
            tokio::select! {
                _ = &mut stop => return Ok(()),
                () = tokio::time::sleep(timings.heartbeat) => {}
            }
            touch_heartbeat(
                &mut client,
                token_id,
                timings.heartbeat_gap,
                Instant::now() + STORE_BUDGET,
            )
            .await
            .map_err(|_| ChannelError::StoreFailed)?;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timings_default_equals_spec_constants() {
        let timings = Timings::default();
        assert_eq!(timings.heartbeat, Duration::from_secs(30));
        assert_eq!(timings.heartbeat_gap, Duration::from_secs(90));
        assert_eq!(timings.backoff_min, Duration::from_secs(1));
        assert_eq!(timings.backoff_max, Duration::from_secs(60));
        assert_eq!(timings.poll_timeout, Duration::from_secs(50));
        assert_eq!(timings.dispatch_retry, Duration::from_secs(5));
        assert_eq!(timings.pending_ttl, Duration::from_secs(24 * 3600));
        assert_eq!(
            timings.poll_timeout + TG_HTTP_MARGIN,
            Duration::from_secs(65)
        );
        assert_eq!(TG_POLL_LIMIT, 100);
        assert_eq!(TG_OFFSET_STALE, Duration::from_secs(6 * 24 * 3600));
        assert_eq!(TG_RESPONSE_MAX, 8 * 1024 * 1024);
    }
}
