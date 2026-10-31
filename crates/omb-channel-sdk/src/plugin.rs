//! Plugin-side runtime: reads [`ToPlugin`] frames from stdin and writes [`FromPlugin`] frames to stdout.
//!
//! One task reads stdin, wakes `accepted` waiters by `event_key` and queues every other command; the
//! loop in [`run_channel_plugin`] handles the commands in order; one task writes stdout frames in
//! order. `verify` and `send` therefore run one at a time, while `accepted` keeps flowing to
//! [`Outbox::emit`] callers.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use crate::PROTOCOL;
use crate::frame::{FrameError, decode, encode, read_frame, write_frame};
use crate::protocol::{
    EventFrame, FailureClass, FromPlugin, GapReason, SendErrorCode, SkipCounter, SuspendReason,
    ToPlugin, VerifyFailure,
};

pub struct HelloInfo {
    pub plugin_name: String,
    pub plugin_version: String,
    pub channel_kind: String,
}

/// The `start` frame. `credential` must not be persisted or printed.
pub struct StartArgs {
    pub source_key: String,
    pub credential: String,
    pub last_event_key: Option<String>,
    pub last_accepted_at: Option<String>,
}

pub struct SendArgs {
    pub delivery_id: String,
    pub chat_key: String,
    pub body: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    Sent {
        platform_message_id: Option<String>,
    },
    Failed {
        class: FailureClass,
        code: SendErrorCode,
        retry_after_ms: Option<u64>,
    },
}

pub trait ChannelPlugin: Send + 'static {
    /// Called once the daemon's `hello` arrived; `channel_kind` must equal the one in `hello`.
    fn hello_ok(&self) -> HelloInfo;
    /// Checks a credential against the platform and returns the source key it belongs to.
    fn verify(
        &mut self,
        credential: String,
        source_key: Option<String>,
    ) -> impl Future<Output = Result<String, VerifyFailure>> + Send;
    /// Starts receiving in a task the plugin spawns itself and returns; events go through `outbox`.
    fn start(&mut self, start: StartArgs, outbox: Outbox) -> impl Future<Output = ()> + Send;
    /// Stops receiving; sending keeps working.
    fn stop(&mut self) -> impl Future<Output = ()> + Send;
    fn send(&mut self, send: SendArgs) -> impl Future<Output = SendOutcome> + Send;
}

#[derive(Debug, thiserror::Error)]
#[error("ack_timeout")]
pub struct AckTimeout;

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("sdk_frame")]
    Frame(#[from] FrameError),
    /// The first frame was not a matching `hello`, or a second `hello` arrived.
    #[error("sdk_handshake")]
    Handshake,
}

type Waiters = Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>;

/// Hands frames to the single stdout writer; usable from any task after `start`.
#[derive(Clone)]
pub struct Outbox {
    frames: mpsc::Sender<FromPlugin>,
    waiters: Waiters,
    ack_timeout: Duration,
}

impl Outbox {
    /// Writes the event and waits for its `accepted` up to `hello.limits.ack_timeout_ms`.
    pub async fn emit(&self, event: EventFrame) -> Result<(), AckTimeout> {
        let key = event.event_key.clone();
        let (waiter, accepted) = oneshot::channel();
        self.waiters.lock().unwrap().insert(key.clone(), waiter);
        let _ = self.frames.send(FromPlugin::Event(event)).await;
        if let Ok(Ok(())) = timeout(self.ack_timeout, accepted).await {
            return Ok(());
        }
        self.waiters.lock().unwrap().remove(&key);
        Err(AckTimeout)
    }

    pub async fn skipped(&self, counter: SkipCounter) {
        let _ = self.frames.send(FromPlugin::Skipped { counter }).await;
    }

    pub async fn gap(&self, reason: GapReason) {
        let _ = self.frames.send(FromPlugin::Gap { reason }).await;
    }

    pub async fn gap_closed(&self) {
        let _ = self.frames.send(FromPlugin::GapClosed {}).await;
    }

    pub async fn suspend(&self, reason: SuspendReason) {
        let _ = self.frames.send(FromPlugin::Suspend { reason }).await;
    }
}

/// Runs the plugin over stdin/stdout until stdin ends. A first frame other than a `hello` with
/// [`PROTOCOL`] and the plugin's `channel_kind` is an error; `main` should exit non-zero on any error.
pub async fn run_channel_plugin<P: ChannelPlugin>(mut plugin: P) -> Result<(), SdkError> {
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let Some(first) = read_frame(&mut stdin).await? else {
        return Err(SdkError::Handshake);
    };
    let ToPlugin::Hello {
        protocol,
        channel_kind,
        limits,
    } = decode(&first)?
    else {
        return Err(SdkError::Handshake);
    };
    let info = plugin.hello_ok();
    if protocol != PROTOCOL || channel_kind != info.channel_kind {
        return Err(SdkError::Handshake);
    }
    let hello_ok = FromPlugin::HelloOk {
        plugin_name: info.plugin_name,
        plugin_version: info.plugin_version,
        channel_kind: info.channel_kind,
    };
    write_frame(&mut stdout, &encode(&hello_ok)?).await?;

    let (frames, mut queue) = mpsc::channel::<FromPlugin>(64);
    tokio::spawn(async move {
        while let Some(message) = queue.recv().await {
            // A failed write means the daemon closed the pipe; stdin reaches EOF next and ends the loop.
            let Ok(payload) = encode(&message) else { break };
            if write_frame(&mut stdout, &payload).await.is_err() {
                break;
            }
        }
    });
    let waiters = Waiters::default();
    let (commands_tx, mut commands) = mpsc::channel::<ToPlugin>(64);
    let reader = tokio::spawn({
        let waiters = waiters.clone();
        async move {
            while let Some(payload) = read_frame(&mut stdin).await? {
                match decode::<ToPlugin>(&payload)? {
                    // Unknown or late keys have no waiter and are ignored.
                    ToPlugin::Accepted { event_key } => {
                        if let Some(waiter) = waiters.lock().unwrap().remove(&event_key) {
                            let _ = waiter.send(());
                        }
                    }
                    command => {
                        if commands_tx.send(command).await.is_err() {
                            break;
                        }
                    }
                }
            }
            Ok::<(), FrameError>(())
        }
    });
    let outbox = Outbox {
        frames: frames.clone(),
        waiters,
        ack_timeout: Duration::from_millis(limits.ack_timeout_ms),
    };

    while let Some(command) = commands.recv().await {
        let reply = match command {
            ToPlugin::Verify {
                credential,
                source_key,
            } => match plugin.verify(credential, source_key).await {
                Ok(source_key) => FromPlugin::Verified { source_key },
                Err(code) => FromPlugin::VerifyFailed { code },
            },
            ToPlugin::Start {
                source_key,
                credential,
                last_event_key,
                last_accepted_at,
            } => {
                let start = StartArgs {
                    source_key,
                    credential,
                    last_event_key,
                    last_accepted_at,
                };
                plugin.start(start, outbox.clone()).await;
                continue;
            }
            ToPlugin::Stop {} => {
                plugin.stop().await;
                continue;
            }
            ToPlugin::Send {
                delivery_id,
                chat_key,
                body,
                idempotency_key,
            } => {
                let send = SendArgs {
                    delivery_id: delivery_id.clone(),
                    chat_key,
                    body,
                    idempotency_key,
                };
                match plugin.send(send).await {
                    SendOutcome::Sent {
                        platform_message_id,
                    } => FromPlugin::Sent {
                        delivery_id,
                        platform_message_id,
                    },
                    SendOutcome::Failed {
                        class,
                        code,
                        retry_after_ms,
                    } => FromPlugin::SendFailed {
                        delivery_id,
                        class,
                        code,
                        retry_after_ms,
                    },
                }
            }
            // A second hello is a protocol violation; accepted frames never reach this loop.
            ToPlugin::Hello { .. } | ToPlugin::Accepted { .. } => return Err(SdkError::Handshake),
        };
        let _ = frames.send(reply).await;
    }
    reader.await.expect("stdin reader task panicked")?;
    Ok(())
}
