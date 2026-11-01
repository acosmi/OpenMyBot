//! One supervisor task per channel kind. It runs the kind's plugin process, accepts the events of
//! the kind's active receiver, and relays `verify` and `send` to the plugin. A process that exits
//! unexpectedly or breaks the protocol is ended through the stop ladder; while a receiver is
//! active it gets a `stream_broken` gap and the process is started again after a backoff, once its
//! process group is empty. A plugin failure never ends the daemon; a store failure does.
use crate::{
    CancelRequests, ChannelError, Connection, Counters, DaemonError, OMB_REPLY_TEXTS_V1,
    STORE_BUDGET, Timings,
    channels::{normalize, utc_millis},
    dispatch::backoff,
    ops::service,
    plugins::{Installed, Plugins, View},
};
use omb_channel_sdk::{
    PROTOCOL,
    frame::{decode, encode, read_frame, write_frame},
    plugin::SendArgs,
    protocol::{
        EventFrame, FailureClass, FromPlugin, GapReason, Limits, SendErrorCode, SkipCounter,
        SuspendReason, ToPlugin, VerifyFailure,
    },
};
use omb_hostdriver::{CC_KILL_GRACE, CC_TERM_GRACE};
use omb_store::{
    ACCEPT_TX_BUDGET, AcceptOutcome, ChannelKind, IdentityKey, KEY_MAX, PollGapReason, ReceiverRow,
    StoreError, Suspension, accept_event, close_poll_gaps, latest_event, open_poll_gap,
    suspend_receiver,
};
use openbot_contracts::ids::ActorId;
use openbot_domain::vault::{SecretKind, SecretPrincipal};
use openbot_infra::vault::CredentialRecordVault;
use rustix::process::{Pid, Signal};
use std::{
    collections::{HashMap, VecDeque},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    process::{Child, ChildStdin},
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
    task::JoinSet,
    time::{Instant, sleep, sleep_until, timeout},
};
use uuid::Uuid;

/// Interval of the process-group probe while the stop ladder takes effect.
const PROBE: Duration = Duration::from_millis(20);

/// What every supervisor shares.
pub(crate) struct Context {
    pub(crate) plugins: Plugins,
    pub(crate) vault: CredentialRecordVault,
    pub(crate) owner: ActorId,
    pub(crate) timings: Timings,
    pub(crate) counters: Arc<Counters>,
    /// The dispatcher's wake-up, signalled after every acceptance.
    pub(crate) wake: Arc<Notify>,
    pub(crate) cancel: CancelRequests,
    /// One permit per live plugin process, `PLUGIN_MAX` in all.
    pub(crate) slots: Arc<Semaphore>,
}

/// The outcome of one `send`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SendResult {
    Sent(String),
    Failed {
        class: FailureClass,
        code: SendErrorCode,
        retry_after: Option<Duration>,
    },
    /// The frame may have reached the plugin: no reply within the limit, or the process ended.
    Unknown,
    /// No running process took the frame.
    NotRunning,
}

type VerifyReply = oneshot::Sender<Result<String, VerifyFailure>>;
enum Command {
    Verify {
        credential: String,
        source_key: Option<String>,
        reply: VerifyReply,
    },
    Start {
        row: ReceiverRow,
        connection: Connection,
        done: oneshot::Sender<Result<(), DaemonError>>,
    },
    /// Stops receiving for the binding, or for any receiver with `None`.
    Stop {
        binding_id: Option<Uuid>,
        done: oneshot::Sender<()>,
    },
    Send {
        args: SendArgs,
        reply: oneshot::Sender<SendResult>,
    },
    /// Ends the process through the stop ladder and keeps the supervisor; answered once the
    /// process group is empty.
    Retire {
        done: oneshot::Sender<()>,
    },
    Terminate,
}

/// The handle of one kind's supervisor; every request is handled in arrival order.
#[derive(Clone)]
pub(crate) struct PluginProcess(mpsc::Sender<Command>);
impl PluginProcess {
    pub(crate) fn spawn(
        kind: ChannelKind,
        context: Arc<Context>,
        set: &mut JoinSet<Result<(), ChannelError>>,
    ) -> Self {
        let (commands, receiver) = mpsc::channel(16);
        set.spawn(
            Supervisor {
                kind,
                context,
                process: None,
                receiver: None,
                verifies: VecDeque::new(),
                verifying: None,
                sends: HashMap::new(),
                restart: None,
                failures: 0,
                last_exit_code: None,
            }
            .run(receiver),
        );
        Self(commands)
    }
    /// Starts the process when none runs; one `verify` is in flight at a time. The reply is
    /// dropped when the process cannot start or ends first.
    pub(crate) async fn verify(
        &self,
        credential: String,
        source_key: Option<String>,
        reply: VerifyReply,
    ) {
        let _ = self
            .0
            .send(Command::Verify {
                credential,
                source_key,
                reply,
            })
            .await;
    }
    /// Makes `row` the kind's receiver, replacing the running one, and sends `start` without
    /// waiting for the platform.
    pub(crate) async fn start(
        &self,
        row: ReceiverRow,
        connection: Connection,
        done: oneshot::Sender<Result<(), DaemonError>>,
    ) {
        let _ = self
            .0
            .send(Command::Start {
                row,
                connection,
                done,
            })
            .await;
    }
    pub(crate) async fn stop(&self, binding_id: Option<Uuid>, done: oneshot::Sender<()>) {
        let _ = self.0.send(Command::Stop { binding_id, done }).await;
    }
    /// Waits up to `limit` for `sent` or `send_failed`.
    pub(crate) async fn send(&self, args: SendArgs, limit: Duration) -> SendResult {
        let (reply, receipt) = oneshot::channel();
        if self.0.send(Command::Send { args, reply }).await.is_err() {
            return SendResult::NotRunning;
        }
        match timeout(limit, receipt).await {
            Ok(Ok(result)) => result,
            _ => SendResult::Unknown,
        }
    }
    /// Ends the process of a removed or replaced installation; `done` answers once its group is
    /// empty.
    pub(crate) async fn retire(&self, done: oneshot::Sender<()>) {
        let _ = self.0.send(Command::Retire { done }).await;
    }
    /// Ends the process through the stop ladder, then the supervisor.
    pub(crate) async fn terminate(&self) {
        let _ = self.0.send(Command::Terminate).await;
    }
}

struct Receiver {
    row: ReceiverRow,
    connection: Connection,
}
struct Running {
    child: Child,
    stdin: ChildStdin,
    /// Decoded stdout frames; `None` is a frame that broke the protocol, the end is the exit.
    frames: mpsc::Receiver<Option<FromPlugin>>,
    /// The installation the process was started from.
    installed_at: String,
    _slot: OwnedSemaphorePermit,
}
struct Supervisor {
    kind: ChannelKind,
    context: Arc<Context>,
    process: Option<Running>,
    receiver: Option<Receiver>,
    verifies: VecDeque<(String, Option<String>, VerifyReply)>,
    verifying: Option<VerifyReply>,
    sends: HashMap<String, oneshot::Sender<SendResult>>,
    restart: Option<Instant>,
    /// Restarts since the receiver was last started; the backoff grows with it.
    failures: u32,
    last_exit_code: Option<i32>,
}
enum Next {
    Command(Option<Command>),
    Frame(Option<Option<FromPlugin>>),
    Restart,
}

/// Writes one frame; a failed write means the process is ending, which its stdout shows next.
async fn write(process: &mut Option<Running>, frame: &ToPlugin) -> bool {
    match (process, encode(frame)) {
        (Some(running), Ok(payload)) => write_frame(&mut running.stdin, &payload).await.is_ok(),
        _ => false,
    }
}
/// Ends a receiver's store connection.
async fn close(receiver: Receiver) {
    drop(receiver.connection.client);
    let _ = receiver.connection.driver.await;
}
/// The stop ladder: stdin closes, the group gets TERM, KILL after `CC_TERM_GRACE`, and the ladder
/// waits until the group is empty, sending KILL again once `CC_KILL_GRACE` passed. Returns the
/// plugin's exit code, `None` when a signal ended it.
async fn terminate(mut child: Child, stdin: ChildStdin) -> Option<i32> {
    drop(stdin);
    let group = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw);
    if let Some(group) = group {
        let _ = rustix::process::kill_process_group(group, Signal::TERM);
    }
    let status = match timeout(CC_TERM_GRACE, child.wait()).await {
        Ok(status) => status,
        Err(_) => {
            if let Some(group) = group {
                let _ = rustix::process::kill_process_group(group, Signal::KILL);
            }
            child.wait().await
        }
    };
    if let Some(group) = group {
        let until = Instant::now() + CC_KILL_GRACE;
        // Other members of the group can outlive the plugin.
        while rustix::process::test_kill_process_group(group) != Err(rustix::io::Errno::SRCH) {
            if Instant::now() >= until {
                let _ = rustix::process::kill_process_group(group, Signal::KILL);
            }
            sleep(PROBE).await;
        }
    }
    status.ok().and_then(|status| status.code())
}
/// Starts `kind`'s command of `installed` in its run environment and completes `hello`; a start
/// that fails after the spawn runs the stop ladder and returns the exit code.
async fn spawn(
    kind: &ChannelKind,
    context: &Context,
    installed: &Installed,
) -> Result<Running, Option<i32>> {
    let plugins = &context.plugins;
    let entry = &installed.channels[kind.as_str()];
    let slot = Arc::clone(&context.slots)
        .try_acquire_owned()
        .map_err(|_| None)?;
    let root = plugins.package(&installed.name);
    let data = plugins.data(&installed.name);
    let tmp = data.join("tmp");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&tmp)
        .map_err(|_| None)?;
    let path = std::env::join_paths(
        ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
            .into_iter()
            .map(PathBuf::from)
            .chain(plugins.path_extra.iter().cloned()),
    )
    .map_err(|_| None)?;
    let mut child = tokio::process::Command::new(root.join(&entry.command))
        .args(&entry.args)
        .env_clear()
        .env("PATH", path)
        .env("HOME", &plugins.home)
        .env("LANG", "en_US.UTF-8")
        .env("TERM", "dumb")
        .env("TMPDIR", &tmp)
        .env("OPENMYBOT_PLUGIN_ROOT", &root)
        .env("OPENMYBOT_PLUGIN_DATA", &data)
        .env("OPENMYBOT_CHANNEL_PLUGIN", "1")
        .current_dir(&root)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| None)?;
    let (Some(mut stdin), Some(mut stdout), Some(mut stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        unreachable!("all three stdio streams are piped");
    };
    // Plugin stderr may carry credentials; it is drained and never kept.
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await;
    });
    let hello = ToPlugin::Hello {
        protocol: PROTOCOL.to_owned(),
        channel_kind: kind.as_str().to_owned(),
        limits: Limits {
            send_timeout_ms: context.timings.plugin_send.as_millis() as u64,
            ack_timeout_ms: context.timings.plugin_ack.as_millis() as u64,
        },
    };
    let answered = async {
        write_frame(&mut stdin, &encode(&hello).ok()?).await.ok()?;
        match decode::<FromPlugin>(&read_frame(&mut stdout).await.ok()??).ok()? {
            FromPlugin::HelloOk { channel_kind, .. } => {
                (channel_kind == kind.as_str()).then_some(())
            }
            _ => None,
        }
    };
    if !matches!(
        timeout(context.timings.plugin_hello, answered).await,
        Ok(Some(()))
    ) {
        return Err(terminate(child, stdin).await);
    }
    let (sender, frames) = mpsc::channel(64);
    tokio::spawn(async move {
        loop {
            let frame = match read_frame(&mut stdout).await {
                Ok(None) => return,
                Ok(Some(payload)) => decode::<FromPlugin>(&payload).ok(),
                Err(_) => None,
            };
            let broken = frame.is_none();
            if sender.send(frame).await.is_err() || broken {
                return;
            }
        }
    });
    Ok(Running {
        child,
        stdin,
        frames,
        installed_at: installed.installed_at.clone(),
        _slot: slot,
    })
}

impl Supervisor {
    async fn run(mut self, mut commands: mpsc::Receiver<Command>) -> Result<(), ChannelError> {
        loop {
            let restart = self.restart;
            let next = tokio::select! {
                command = commands.recv() => Next::Command(command),
                frame = async {
                    match &mut self.process {
                        Some(running) => running.frames.recv().await,
                        None => std::future::pending().await,
                    }
                } => Next::Frame(frame),
                () = async {
                    match restart {
                        Some(at) => sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                } => Next::Restart,
            };
            match next {
                Next::Command(None | Some(Command::Terminate)) => {
                    self.end_process().await;
                    if let Some(receiver) = self.receiver.take() {
                        close(receiver).await;
                    }
                    return Ok(());
                }
                Next::Command(Some(Command::Verify {
                    credential,
                    source_key,
                    reply,
                })) => {
                    if self.running().await {
                        self.verifies.push_back((credential, source_key, reply));
                        self.next_verify().await;
                    }
                }
                Next::Command(Some(Command::Start {
                    row,
                    connection,
                    done,
                })) => {
                    // Frames the old stream already queued must never reach the new receiver: the
                    // process ends and `begin` starts a fresh one.
                    if let Some(replaced) = self.receiver.take() {
                        close(replaced).await;
                        self.end_process().await;
                    }
                    self.receiver = Some(Receiver { row, connection });
                    self.failures = 0;
                    self.restart = None;
                    self.begin().await?;
                    let _ = done.send(Ok(()));
                }
                Next::Command(Some(Command::Stop { binding_id, done })) => {
                    let serves = self.receiver.as_ref().is_some_and(|receiver| {
                        binding_id.is_none_or(|id| id == receiver.row.binding_id)
                    });
                    if serves && let Some(receiver) = self.receiver.take() {
                        write(&mut self.process, &ToPlugin::Stop {}).await;
                        self.restart = None;
                        close(receiver).await;
                    }
                    let _ = done.send(());
                }
                Next::Command(Some(Command::Retire { done })) => {
                    self.end_process().await;
                    let _ = done.send(());
                }
                Next::Command(Some(Command::Send { args, reply })) => {
                    let delivery_id = args.delivery_id.clone();
                    let frame = ToPlugin::Send {
                        delivery_id: args.delivery_id,
                        chat_key: args.chat_key,
                        body: args.body,
                        idempotency_key: args.idempotency_key,
                    };
                    if write(&mut self.process, &frame).await {
                        self.sends.insert(delivery_id, reply);
                    } else {
                        let _ = reply.send(SendResult::NotRunning);
                    }
                }
                Next::Frame(Some(Some(frame))) => self.frame(frame).await?,
                Next::Frame(Some(None)) => self.crashed(true).await?,
                Next::Frame(None) => self.crashed(false).await?,
                Next::Restart => {
                    self.restart = None;
                    self.begin().await?;
                }
            }
        }
    }
    /// Whether a process of the kind's current installation runs; one is started with `hello`
    /// when none does, after a process of a replaced installation ended.
    async fn running(&mut self) -> bool {
        let installed = self.context.plugins.provider(&self.kind);
        if let (Some(running), Some(installed)) = (&self.process, &installed)
            && running.installed_at == installed.installed_at
        {
            return true;
        }
        self.end_process().await;
        let Some(installed) = installed else {
            return false;
        };
        match spawn(&self.kind, &self.context, &installed).await {
            Ok(running) => self.process = Some(running),
            Err(code) => self.last_exit_code = code,
        }
        self.context.plugins.set_view(
            &self.kind,
            View {
                running: self.process.is_some(),
                last_exit_code: self.last_exit_code,
            },
        );
        self.process.is_some()
    }
    /// Ends the process through the stop ladder; the pending verify and send replies are dropped.
    async fn end_process(&mut self) {
        let Some(running) = self.process.take() else {
            return;
        };
        self.verifying = None;
        self.verifies.clear();
        self.sends.clear();
        let Running { child, stdin, .. } = running;
        self.last_exit_code = terminate(child, stdin).await;
        self.context.plugins.set_view(
            &self.kind,
            View {
                running: false,
                last_exit_code: self.last_exit_code,
            },
        );
    }
    /// The process ended or broke the protocol.
    async fn crashed(&mut self, violation: bool) -> Result<(), ChannelError> {
        if violation {
            self.context
                .counters
                .protocol_violation
                .fetch_add(1, Ordering::Relaxed);
        }
        self.end_process().await;
        self.broken().await
    }
    /// The active receiver gets a `stream_broken` gap and receiving starts again after a backoff.
    async fn broken(&mut self) -> Result<(), ChannelError> {
        let Some(receiver) = &mut self.receiver else {
            return Ok(());
        };
        open_poll_gap(
            &mut receiver.connection.client,
            receiver.row.binding_id,
            PollGapReason::StreamBroken,
            Instant::now() + STORE_BUDGET,
        )
        .await
        .map_err(|_| ChannelError::StoreFailed)?;
        let timings = &self.context.timings;
        self.restart = Some(
            Instant::now() + backoff(self.failures, timings.plugin_restart, timings.backoff_max),
        );
        self.failures = self.failures.saturating_add(1);
        Ok(())
    }
    /// Receiving starts for the active receiver: the credential is opened from its envelope,
    /// `start` carries the last accepted event, and the receiver's polling gaps close.
    async fn begin(&mut self) -> Result<(), ChannelError> {
        if self.receiver.is_none() {
            return Ok(());
        }
        if !self.running().await {
            return self.broken().await;
        }
        let store = |_: StoreError| ChannelError::StoreFailed;
        let Some(receiver) = &mut self.receiver else {
            return Ok(());
        };
        let binding_id = receiver.row.binding_id;
        let credential = self
            .context
            .vault
            .open(
                &binding_id,
                SecretKind::Connector,
                SecretPrincipal::Actor(self.context.owner.clone()),
                SecretPrincipal::Service(service(&self.kind)),
                &receiver.row.credential_envelope,
            )
            .ok()
            .and_then(|opened| String::from_utf8(opened.into_secret().expose().to_vec()).ok());
        let Some(credential) = credential else {
            suspend_receiver(
                &mut receiver.connection.client,
                binding_id,
                Suspension::CredentialRejected,
                Instant::now() + STORE_BUDGET,
            )
            .await
            .map_err(store)?;
            if let Some(receiver) = self.receiver.take() {
                close(receiver).await;
            }
            return Ok(());
        };
        let last = latest_event(
            &receiver.connection.client,
            &self.kind,
            &receiver.row.source_key,
        )
        .await
        .map_err(store)?;
        let start = ToPlugin::Start {
            source_key: receiver.row.source_key.clone(),
            credential,
            last_accepted_at: last.as_ref().map(|(_, at)| utc_millis(*at)),
            last_event_key: last.map(|(key, _)| key),
        };
        write(&mut self.process, &start).await;
        close_poll_gaps(
            &mut receiver.connection.client,
            binding_id,
            Instant::now() + STORE_BUDGET,
        )
        .await
        .map_err(store)?;
        Ok(())
    }
    /// Sends the next queued `verify` once none is in flight.
    async fn next_verify(&mut self) {
        if self.verifying.is_some() {
            return;
        }
        let Some((credential, source_key, reply)) = self.verifies.pop_front() else {
            return;
        };
        if write(
            &mut self.process,
            &ToPlugin::Verify {
                credential,
                source_key,
            },
        )
        .await
        {
            self.verifying = Some(reply);
        }
    }
    /// Hands a send outcome to its waiting delivery; an outcome nobody waits for any more is late.
    fn settle(&mut self, delivery_id: &str, result: SendResult) {
        let delivered = self
            .sends
            .remove(delivery_id)
            .is_some_and(|reply| reply.send(result).is_ok());
        if !delivered {
            self.context
                .counters
                .late_send_result
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    async fn frame(&mut self, frame: FromPlugin) -> Result<(), ChannelError> {
        let store = |_: StoreError| ChannelError::StoreFailed;
        let counters = Arc::clone(&self.context.counters);
        match frame {
            FromPlugin::Event(event) => return self.event(event).await,
            FromPlugin::Verified { source_key } => match self.verifying.take() {
                Some(reply) if IdentityKey::parse(&source_key).is_some() => {
                    let _ = reply.send(Ok(source_key));
                    self.next_verify().await;
                }
                Some(_) => return self.crashed(true).await,
                None => {
                    counters.protocol_violation.fetch_add(1, Ordering::Relaxed);
                }
            },
            FromPlugin::VerifyFailed { code } => match self.verifying.take() {
                Some(reply) => {
                    let _ = reply.send(Err(code));
                    self.next_verify().await;
                }
                None => {
                    counters.protocol_violation.fetch_add(1, Ordering::Relaxed);
                }
            },
            FromPlugin::Sent {
                delivery_id,
                platform_message_id,
            } => {
                let id = platform_message_id.unwrap_or_default();
                // The delivery row keeps at most this many bytes of the platform's id.
                if id.len() > KEY_MAX {
                    return self.crashed(true).await;
                }
                self.settle(&delivery_id, SendResult::Sent(id));
            }
            FromPlugin::SendFailed {
                delivery_id,
                class,
                code,
                retry_after_ms,
            } => self.settle(
                &delivery_id,
                SendResult::Failed {
                    class,
                    code,
                    retry_after: retry_after_ms.map(Duration::from_millis),
                },
            ),
            FromPlugin::Skipped { counter } => {
                match counter {
                    SkipCounter::PlatformPayloadUnparseable => {
                        &counters.platform_payload_unparseable
                    }
                    SkipCounter::UnsupportedUpdate => &counters.unsupported_update,
                }
                .fetch_add(1, Ordering::Relaxed);
            }
            FromPlugin::Gap { reason } => {
                if let Some(receiver) = &mut self.receiver {
                    let reason = match reason {
                        GapReason::ConnectFailed => PollGapReason::ConnectFailed,
                        GapReason::StreamBroken => PollGapReason::StreamBroken,
                    };
                    open_poll_gap(
                        &mut receiver.connection.client,
                        receiver.row.binding_id,
                        reason,
                        Instant::now() + STORE_BUDGET,
                    )
                    .await
                    .map_err(store)?;
                }
            }
            FromPlugin::GapClosed {} => {
                if let Some(receiver) = &mut self.receiver {
                    close_poll_gaps(
                        &mut receiver.connection.client,
                        receiver.row.binding_id,
                        Instant::now() + STORE_BUDGET,
                    )
                    .await
                    .map_err(store)?;
                }
            }
            FromPlugin::Suspend { reason } => {
                if let Some(mut receiver) = self.receiver.take() {
                    let why = match reason {
                        SuspendReason::CredentialRejected => Suspension::CredentialRejected,
                        SuspendReason::WebhookConflict => Suspension::WebhookConflict,
                    };
                    suspend_receiver(
                        &mut receiver.connection.client,
                        receiver.row.binding_id,
                        why,
                        Instant::now() + STORE_BUDGET,
                    )
                    .await
                    .map_err(store)?;
                    close(receiver).await;
                    self.restart = None;
                    self.end_process().await;
                }
            }
            FromPlugin::HelloOk { .. } => {
                counters.protocol_violation.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }
    /// Accepts one event for the active receiver and confirms it with `accepted` after the commit,
    /// whatever the committed outcome.
    async fn event(&mut self, frame: EventFrame) -> Result<(), ChannelError> {
        let Some(receiver) = &mut self.receiver else {
            return Ok(());
        };
        let event_key = frame.event_key.clone();
        let Some(event) = normalize(&self.kind, &receiver.row.source_key, frame) else {
            return self.crashed(true).await;
        };
        let accepted = accept_event(
            &mut receiver.connection.client,
            receiver.row.binding_id,
            &event,
            &OMB_REPLY_TEXTS_V1,
            Instant::now() + ACCEPT_TX_BUDGET,
        )
        .await;
        // Every outcome wakes, an error too: its commit may have landed.
        self.context.wake.notify_one();
        let committed = match accepted {
            Ok(AcceptOutcome::Conflict) => {
                self.context
                    .counters
                    .event_conflict
                    .fetch_add(1, Ordering::Relaxed);
                true
            }
            // Handed over only after the commit; a closed channel means the daemon is stopping.
            Ok(AcceptOutcome::Cancel(binding)) => {
                let _ = self.context.cancel.send(binding).await;
                true
            }
            Ok(_) => true,
            // The binding left `active`: receiving stops, and the process ends so that frames of
            // its stream never reach a later receiver; a later use starts a fresh one.
            Err(StoreError::ReceiverNotActive) => {
                if let Some(receiver) = self.receiver.take() {
                    close(receiver).await;
                }
                self.end_process().await;
                false
            }
            // Not committed: without a receipt the plugin delivers the event again.
            Err(_) => false,
        };
        if committed {
            write(&mut self.process, &ToPlugin::Accepted { event_key }).await;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        CANCEL_QUEUE, StatusSnapshot, TERMINAL_QUEUE,
        channels::{Channels, Outbound, Processes},
        delegation::fixture::{self, Fixture},
        plugins::tests::{Logs, installed},
    };
    use omb_channel_sdk::{PLUGIN_MAX, protocol::EventKind};
    use omb_store::testkit;
    use openbot_domain::vault::SecretBytes;
    use openbot_infra::auth::single_user::SINGLE_USER_ACTOR_ID;
    use serde_json::{Value, json};
    use tokio_postgres::Client;

    /// Repetitions of each race case.
    const RACE_REPEAT_MIN: usize = 10;
    const LIMIT: Duration = Duration::from_secs(60);
    const SECRET: &str = "SENTINEL-plugin-credential";

    fn quick() -> Timings {
        Timings {
            heartbeat: Duration::from_millis(100),
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(200),
            dispatch_retry: Duration::from_millis(100),
            delivery_poll: Duration::from_millis(50),
            delivery_retry: [Duration::from_millis(200); 5],
            plugin_hello: Duration::from_secs(1),
            plugin_send: Duration::from_secs(2),
            plugin_restart: Duration::from_millis(50),
            ..Timings::default()
        }
    }
    fn kind() -> ChannelKind {
        ChannelKind::from_static("fake")
    }
    async fn until(what: &str, mut probe: impl AsyncFnMut() -> bool) {
        let limit = Instant::now() + LIMIT;
        while !probe().await {
            assert!(Instant::now() < limit, "{what}");
            sleep(Duration::from_millis(20)).await;
        }
    }
    async fn count(client: &Client, sql: &str, binding: Uuid) -> i64 {
        client.query_one(sql, &[&binding]).await.unwrap().get(0)
    }
    /// A private text event of the fake channel from chat `fake:42`.
    fn event(key: &str) -> Value {
        json!({
            "event_key": key,
            "event_type": "fake.message",
            "occurred_at": utc_millis(time::OffsetDateTime::now_utc()),
            "private": true,
            "sender_key": "fake:42",
            "chat_key": "fake:42",
            "kind": "text",
            "text": "hello",
            "data": {"text": "hello"},
        })
    }

    /// The fake installed as `kind` under the fixture's data directory, its supervisor, and its
    /// process started by one `verify`: what an outbound task sends through.
    pub(crate) struct Serving {
        pub(crate) processes: Processes,
        process: PluginProcess,
        set: JoinSet<Result<(), ChannelError>>,
    }
    impl Serving {
        pub(crate) async fn start(fixture: &Fixture, kind: &str, logs: &Logs) -> Self {
            let kind = ChannelKind::parse(kind).unwrap();
            let context = Arc::new(Context {
                plugins: installed(&fixture.root, kind.as_str(), logs, "normal"),
                vault: fixture.engine().vault.clone(),
                owner: ActorId::new(SINGLE_USER_ACTOR_ID),
                timings: quick(),
                counters: Arc::default(),
                wake: Arc::new(Notify::new()),
                cancel: mpsc::channel(CANCEL_QUEUE).0,
                slots: Arc::new(Semaphore::new(PLUGIN_MAX)),
            });
            let mut set = JoinSet::new();
            let process = PluginProcess::spawn(kind.clone(), context, &mut set);
            let (reply, receipt) = oneshot::channel();
            process.verify("credential".into(), None, reply).await;
            assert!(receipt.await.unwrap().is_ok());
            let processes = Processes::default();
            processes.lock().unwrap().insert(kind, process.clone());
            Self {
                processes,
                process,
                set,
            }
        }
        pub(crate) async fn stop(mut self) {
            self.process.terminate().await;
            assert_eq!(self.set.join_next().await.unwrap().unwrap(), Ok(()));
        }
    }

    /// The fake installed for channel `fake` with a scenario, optionally an active `fake`
    /// receiver on source `1001` sealed with `SECRET`, and the channel tasks.
    struct Rig {
        fixture: Fixture,
        client: Client,
        logs: Logs,
        plugins: Plugins,
        token: Uuid,
        receiver: Option<Uuid>,
        channels: Option<Channels>,
    }
    impl Rig {
        async fn start(scenario: &str, receiving: bool, timings: Timings) -> Self {
            let mut fixture = Fixture::start().await;
            let token = Uuid::now_v7();
            let mut digest = [0; 32];
            digest[..16].copy_from_slice(token.as_bytes());
            fixture
                .pg
                .start_control_token(omb_store::ControlTokenStart {
                    token_id: token,
                    token_sha256: digest,
                    daemon_pid: 1,
                    engine_pin: "0123456789abcdef0123456789abcdef01234567",
                    omb_version: "0.0.0",
                })
                .await
                .unwrap();
            let client = fixture.client().await;
            let logs = Logs::new();
            let plugins = installed(&fixture.root, "fake", &logs, scenario);
            let mut rig = Self {
                fixture,
                client,
                logs,
                plugins,
                token,
                receiver: None,
                channels: None,
            };
            if receiving {
                rig.receiver = Some(rig.sealed_receiver().await);
            }
            rig.channels = Some(rig.channels(timings).await);
            rig
        }
        async fn sealed_receiver(&self) -> Uuid {
            let binding = fixture::receiver(&self.client, "fake").await;
            let envelope = self
                .fixture
                .engine()
                .vault
                .seal(
                    &binding,
                    SecretKind::Connector,
                    SecretPrincipal::Actor(ActorId::new(SINGLE_USER_ACTOR_ID)),
                    SecretPrincipal::Service(service(&kind())),
                    &SecretBytes::new(SECRET.as_bytes().to_vec()),
                )
                .unwrap();
            self.client
                .execute(
                    "UPDATE openmybot.channel_bindings SET credential_envelope=$2 WHERE binding_id=$1",
                    &[&binding, &envelope],
                )
                .await
                .unwrap();
            binding
        }
        async fn channels(&mut self, timings: Timings) -> Channels {
            let engine = self.fixture.engine.as_ref().unwrap();
            Channels::start(
                &mut self.fixture.pg,
                engine,
                self.token,
                timings,
                self.plugins.clone(),
                mpsc::channel(CANCEL_QUEUE).0,
                Outbound {
                    terminals: mpsc::channel(TERMINAL_QUEUE).1,
                    crabcode: None,
                },
                Arc::default(),
            )
            .await
            .unwrap()
        }
        fn started(&mut self) -> &mut Channels {
            self.channels.as_mut().unwrap()
        }
        fn counters(&self) -> Arc<Counters> {
            self.channels.as_ref().unwrap().status_source().counters
        }
        fn view(&self) -> (crate::ProcessState, Option<i32>) {
            let plugin = self.plugins.provider(&kind()).unwrap();
            self.plugins.process(&plugin)
        }
        async fn gaps(&self, reason: &str) -> (i64, i64) {
            let binding = self.receiver.unwrap();
            let total = count(&self.client, &format!("SELECT count(*) FROM openmybot.channel_events WHERE record_kind='gap' AND binding_id=$1 AND gap_reason='{reason}'"), binding).await;
            let open = count(&self.client, &format!("SELECT count(*) FROM openmybot.channel_events WHERE record_kind='gap' AND binding_id=$1 AND gap_reason='{reason}' AND gap_ended_at IS NULL"), binding).await;
            (total, open)
        }
        async fn rows(&self, key: &str) -> i64 {
            self.client
                .query_one(
                    "SELECT count(*) FROM openmybot.channel_events WHERE record_kind='event' AND event_key=$1",
                    &[&key],
                )
                .await
                .unwrap()
                .get(0)
        }
        fn accepted(&self, key: &str) -> bool {
            self.logs
                .received_of("accepted")
                .iter()
                .any(|frame| frame["event_key"] == key)
        }
        /// A `fake` sender on the receiver's source with one pending control reply.
        async fn delivery(&self) -> Uuid {
            let sender =
                testkit::insert_sender(&self.client, "fake", "1001", "fake:42", "T1").await;
            testkit::insert_delivery(
                &self.client,
                sender,
                "control_reply",
                "control_reply:1",
                Some("reply text"),
                "pending",
                None,
            )
            .await
        }
        async fn delivery_row(&self, id: Uuid) -> Value {
            self.client
                .query_one(
                    "SELECT row_to_json(d) FROM openmybot.deliveries d WHERE delivery_id=$1",
                    &[&id],
                )
                .await
                .unwrap()
                .get(0)
        }
        async fn stop(mut self) {
            if let Some(channels) = self.channels.take() {
                channels.stop().await;
            }
            self.fixture.stop().await;
        }
    }

    /// The digests the in-process Telegram and Feishu receivers produced for the same fields,
    /// and new vectors computed independently with Python's `json.dumps(sort_keys=True,
    /// separators=(",", ":"), ensure_ascii=False)` and `hashlib`.
    #[test]
    fn fingerprint_golden_vectors_match_the_in_process_receivers() {
        const ESCAPES: &str = "hi \"you\"\\ \u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f} é 中";
        const FEISHU: &str = "feishu.im.message.receive_v1";
        let vectors = [
            // The in-process receivers' vectors.
            (
                "telegram",
                "telegram.message",
                Some("2026-10-28T15:43:07Z"),
                vec![
                    ("chatId", "-1001"),
                    ("fromId", "42"),
                    ("messageId", "77"),
                    ("messageKind", "text"),
                    ("text", ESCAPES),
                ],
                "578ed2e26fd764a1ba54a491b575af6f1d28b5216e1e76ae4ecbe3f6c4dd5174",
            ),
            (
                "telegram",
                "telegram.message",
                Some("2026-10-28T15:43:07Z"),
                vec![
                    ("chatId", "42"),
                    ("fromId", "42"),
                    ("messageId", "77"),
                    ("messageKind", "other"),
                    ("text", ""),
                ],
                "62f5ad742ffd8c7b994acd6c19dcc4d5da5ce88d9013ff254de1985ecc1a95d5",
            ),
            (
                "feishu",
                FEISHU,
                Some("2026-10-29T08:00:00.123Z"),
                vec![
                    ("chatId", "oc_chat"),
                    ("content", "{\"text\":\"你好\"}"),
                    ("messageId", "om_1"),
                    ("messageType", "text"),
                    ("openId", "ou_user"),
                ],
                "dcbcf8f503062bdc046eba31fc043dad5489983c3aa6088f686f49feb91c8a21",
            ),
            // New: an offset time is re-formatted in UTC with milliseconds.
            (
                "telegram",
                "telegram.message",
                Some("2026-10-30T09:15:00+08:00"),
                vec![
                    ("messageKind", "text"),
                    ("text", "/status 状态 😀"),
                    ("chatId", "-1002"),
                    ("fromId", "7"),
                    ("messageId", "9001"),
                ],
                "1e5750ef1cb1bc7d65978b8d3216ac5814b5b8a36aa9814432b892ea4e9b0527",
            ),
            (
                "feishu",
                FEISHU,
                Some("2026-10-29T08:00:01.5Z"),
                vec![
                    ("chatId", "oc_group"),
                    (
                        "content",
                        r#"{"title":"t","content":[[{"tag":"text","text":"a\nb"}]]}"#,
                    ),
                    ("messageId", "om_2"),
                    ("messageType", "post"),
                    ("openId", "ou_user"),
                ],
                "fef9d8e838575464892dea192fe1162016bd5ea6ff9a4913145ab7e43a44d4f3",
            ),
            // New: a missing time leaves `occurredAt` out.
            (
                "feishu",
                FEISHU,
                None,
                vec![
                    ("chatId", "oc_chat"),
                    ("content", r#"{"image_key":"img_1"}"#),
                    ("messageId", "om_3"),
                    ("messageType", "image"),
                    ("openId", "ou_user"),
                ],
                "7061a3deb8118d72c1744a5fe98c827bba70a483de19941f64cd4d9c908e9f37",
            ),
        ];
        for (kind, event_type, occurred_at, data, digest) in vectors {
            let kind = ChannelKind::parse(kind).unwrap();
            let frame = EventFrame {
                event_key: "e1".into(),
                event_type: event_type.into(),
                occurred_at: occurred_at.map(Into::into),
                private: true,
                sender_key: Some(format!("{}:42", kind.as_str())),
                chat_key: Some(format!("{}:42", kind.as_str())),
                kind: EventKind::Text,
                text: "x".into(),
                data: data
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
                    .collect(),
            };
            let fingerprint = normalize(&kind, "1001", frame)
                .unwrap()
                .fingerprint
                .unwrap();
            let hex: String = fingerprint
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(hex, digest, "{event_type} {occurred_at:?}");
        }
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn plugin_hello_timeout_marks_plugin_unavailable() {
        let mut rig = Rig::start("slow_hello", false, quick()).await;
        let began = Instant::now();
        let (reply, receipt) = oneshot::channel();
        rig.started()
            .verify(kind(), "credential".into(), None, reply)
            .await;
        // A dropped reply is `plugin_unavailable` for the operation.
        assert!(receipt.await.is_err());
        assert!(began.elapsed() < quick().plugin_hello + CC_TERM_GRACE);
        assert_eq!(rig.view().0, crate::ProcessState::Stopped);
        // Exactly the hello reached the plugin; no verify was sent.
        assert_eq!(rig.logs.received_of("hello").len(), 1);
        assert!(rig.logs.received_of("verify").is_empty());
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn plugin_crash_writes_stream_broken_gap_and_restarts_after_backoff() {
        let mut rig = Rig::start("crash_after_hello", true, quick()).await;
        for round in 1..=RACE_REPEAT_MIN {
            until("restart after the crash", async || {
                rig.logs.received_of("start").len() > round
                    && rig.gaps("stream_broken").await.0 >= round as i64
            })
            .await;
        }
        // Each start carried the stored credential; the exit code of the crash is kept.
        assert!(
            rig.logs
                .received_of("start")
                .iter()
                .all(|frame| frame["credential"] == SECRET && frame["source_key"] == "1001")
        );
        until("exit code", async || rig.view().1 == Some(3)).await;
        // A plugin failure never ends the daemon.
        assert!(
            timeout(Duration::from_millis(50), rig.started().finished())
                .await
                .is_err()
        );
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn oversize_frame_terminates_and_restarts_the_plugin() {
        let rig = Rig::start("oversize_frame", true, quick()).await;
        until("restart after the oversize frame", async || {
            rig.logs.received_of("hello").len() >= 3
        })
        .await;
        assert!(rig.counters().protocol_violation.load(Ordering::Relaxed) >= 2);
        assert!(rig.gaps("stream_broken").await.0 >= 2);
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn unknown_field_frame_terminates_and_restarts_the_plugin() {
        let rig = Rig::start("unknown_field", true, quick()).await;
        until("restart after the unknown field", async || {
            rig.logs.received_of("hello").len() >= 3
        })
        .await;
        assert!(rig.counters().protocol_violation.load(Ordering::Relaxed) >= 2);
        // The frame itself, a gap, was never applied: only the daemon's stream_broken gaps exist.
        assert!(rig.gaps("stream_broken").await.0 >= 2);
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn accepted_is_sent_only_after_commit() {
        let rig = Rig::start("normal", true, quick()).await;
        until("start", async || !rig.logs.received_of("start").is_empty()).await;
        for round in 0..RACE_REPEAT_MIN {
            let key = format!("k{round}");
            rig.logs.push(&event(&key));
            let limit = Instant::now() + LIMIT;
            while !rig.accepted(&key) {
                assert!(Instant::now() < limit, "accepted {key}");
                sleep(Duration::from_millis(1)).await;
            }
            // The receipt became visible only after the row did.
            assert_eq!(rig.rows(&key).await, 1, "{key}");
        }
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn duplicate_resend_without_ack_does_not_create_a_second_row() {
        // The fake sends the events present at `start` twice, so they exist before the receiver.
        let mut rig = Rig::start("no_ack_wait", false, quick()).await;
        let keys = ["d1", "d2", "d3"];
        for key in keys {
            rig.logs.push(&event(key));
        }
        rig.receiver = Some(rig.sealed_receiver().await);
        rig.channels.take().unwrap().stop().await;
        rig.channels = Some(rig.channels(quick()).await);
        until("both copies accepted", async || {
            rig.logs.received_of("accepted").len() == 2 * keys.len()
        })
        .await;
        for key in keys {
            assert_eq!(rig.rows(key).await, 1, "{key}");
        }
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn send_failed_once_consumes_one_retry_slot_then_sent() {
        let rig = Rig::start("send_fail_once:retryable:server_error", true, quick()).await;
        let id = rig.delivery().await;
        until("sent", async || {
            rig.delivery_row(id).await["status"] == "sent"
        })
        .await;
        let row = rig.delivery_row(id).await;
        assert_eq!(row["attempts"], 2);
        assert_eq!(row["platform_message_id"], "fake-2");
        assert_eq!(row["last_error_code"], "server_error");
        let sent = rig.logs.sent();
        assert_eq!(sent.len(), 2);
        for line in &sent {
            assert_eq!(line["delivery_id"], id.to_string());
            assert_eq!(line["chat_key"], "fake:42");
            assert_eq!(line["body"], "reply text");
            assert_eq!(line["idempotency_key"], "control_reply:1");
        }
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn send_hang_finishes_delivery_as_unknown() {
        let rig = Rig::start("send_hang", true, quick()).await;
        let id = rig.delivery().await;
        until("unknown", async || {
            rig.delivery_row(id).await["status"] == "unknown"
        })
        .await;
        let row = rig.delivery_row(id).await;
        assert_eq!(row["attempts"], 1);
        assert_eq!(row["last_error_code"], "result_unknown");
        assert_eq!(rig.logs.sent().len(), 1);
        // The hung plugin still ends through the stop ladder.
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn send_failed_retry_after_extends_the_schedule() {
        let rig = Rig::start("send_fail:retryable:rate_limited:60000", true, quick()).await;
        let id = rig.delivery().await;
        until("retry scheduled", async || {
            rig.delivery_row(id).await["last_error_code"] == "rate_limited"
        })
        .await;
        let wait: f64 = rig
            .client
            .query_one(
                "SELECT extract(epoch FROM next_attempt_at-now())::float8 FROM openmybot.deliveries WHERE delivery_id=$1",
                &[&id],
            )
            .await
            .unwrap()
            .get(0);
        // The platform's 60 s outweigh the planned 200 ms.
        assert!(wait > 50.0, "{wait}");
        assert_eq!(rig.delivery_row(id).await["status"], "pending");
        assert_eq!(rig.logs.sent().len(), 1);
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn missing_plugin_opens_plugin_missing_gap_and_hello_closes_it() {
        let mut rig = Rig::start("normal", false, quick()).await;
        rig.receiver = Some(rig.sealed_receiver().await);
        rig.channels.take().unwrap().stop().await;
        // Without the plugin: no process, an open gap and the fixed note.
        let installed = rig.plugins.list();
        let empty = Plugins::load(
            &rig.fixture.root.join("missing"),
            Vec::new(),
            rig.fixture.root.clone(),
        )
        .unwrap();
        let plugins = std::mem::replace(&mut rig.plugins, empty);
        rig.channels = Some(rig.channels(quick()).await);
        assert_eq!(rig.gaps("plugin_missing").await, (1, 1));
        let status = rig
            .channels
            .as_ref()
            .unwrap()
            .status_source()
            .read()
            .await
            .unwrap();
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].note, "no plugin installed for this channel");
        assert!(rig.logs.received().is_empty());
        rig.channels.take().unwrap().stop().await;
        // With the plugin again: hello and start close the gap.
        rig.plugins = plugins;
        assert_eq!(rig.plugins.list(), installed);
        rig.channels = Some(rig.channels(quick()).await);
        until("gap closed", async || {
            rig.gaps("plugin_missing").await == (1, 0)
        })
        .await;
        assert_eq!(rig.logs.received_of("hello").len(), 1);
        let status = rig
            .channels
            .as_ref()
            .unwrap()
            .status_source()
            .read()
            .await
            .unwrap();
        assert_eq!(status[0].note, "fake fake note");
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn suspend_frame_suspends_receiver_and_terminates_process() {
        let rig = Rig::start("suspend:credential_rejected", true, quick()).await;
        let binding = rig.receiver.unwrap();
        until("suspended", async || {
            count(&rig.client, "SELECT count(*) FROM openmybot.channel_bindings WHERE binding_id=$1 AND status='suspended' AND status_reason='credential_rejected'", binding).await == 1
        })
        .await;
        until("process ended", async || {
            rig.view().0 == crate::ProcessState::Stopped
        })
        .await;
        // No restart follows a suspension.
        sleep(Duration::from_millis(300)).await;
        assert_eq!(rig.logs.received_of("hello").len(), 1);
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn stderr_secret_never_appears_in_status_or_errors() {
        let rig = Rig::start("stderr_secret", true, quick()).await;
        until("start", async || !rig.logs.received_of("start").is_empty()).await;
        sleep(Duration::from_millis(300)).await;
        let source = rig.channels.as_ref().unwrap().status_source();
        let snapshot = StatusSnapshot {
            deployment_id: "omb-local-test".into(),
            daemon_pid: 1,
            pg_pid: 1,
            pg_server_version_num: 170011,
            daemon_version: "0.0.0".into(),
            engine_pin: "pin".into(),
            authentication_failures: 0,
            channels: source.read().await.unwrap(),
            plugins: source.plugins(),
        };
        let text = serde_json::to_string(&snapshot).unwrap();
        assert!(text.contains("fake-fake"));
        assert!(!text.contains(SECRET));
        for error in DaemonError::ALL {
            assert!(!error.code().contains(SECRET));
            assert!(!format!("{error:?} {error}").contains(SECRET));
        }
        // Nothing of the plugin's stderr lands in the data directory's logs or plugin data.
        let mut pending = vec![
            rig.fixture.root.join("logs"),
            rig.fixture.root.join("plugins-data"),
        ];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    assert!(
                        !String::from_utf8_lossy(&std::fs::read(&path).unwrap()).contains(SECRET)
                    );
                }
            }
        }
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn verify_during_start_is_serialized() {
        let mut rig = Rig::start("verify_slow:500", false, quick()).await;
        let binding = rig.sealed_receiver().await;
        let envelope: String = rig
            .client
            .query_one(
                "SELECT credential_envelope FROM openmybot.channel_bindings WHERE binding_id=$1",
                &[&binding],
            )
            .await
            .unwrap()
            .get(0);
        for _ in 0..RACE_REPEAT_MIN {
            let channels = rig.channels.as_mut().unwrap();
            let mut verified = Vec::new();
            for _ in 0..2 {
                let (reply, receipt) = oneshot::channel();
                channels
                    .verify(kind(), "credential".into(), Some("1001".into()), reply)
                    .await;
                verified.push(receipt);
            }
            let (done, started) = oneshot::channel();
            channels
                .start_receiver(
                    &mut rig.fixture.pg,
                    ReceiverRow {
                        binding_id: binding,
                        channel: kind(),
                        source_key: "1001".into(),
                        credential_envelope: envelope.clone(),
                    },
                    done,
                )
                .await;
            assert_eq!(started.await.unwrap(), Ok(()));
            for receipt in verified {
                assert_eq!(receipt.await.unwrap(), Ok("fake-source".to_owned()));
            }
            let (done, stopped) = oneshot::channel();
            channels.stop_receiver(binding, done).await;
            stopped.await.unwrap();
        }
        // One process served every round. Each `start` went out while the first slow `verify`
        // was in flight, ahead of the queued second one: one `verify` in flight at a time, and a
        // `start` never waits behind the queue.
        until("frames", async || {
            rig.logs.received_of("stop").len() == RACE_REPEAT_MIN
        })
        .await;
        let kinds: Vec<Value> = rig
            .logs
            .received()
            .into_iter()
            .map(|frame| frame["type"].clone())
            .collect();
        let expected: Vec<Value> = std::iter::once(json!("hello"))
            .chain(
                (0..RACE_REPEAT_MIN)
                    .flat_map(|_| ["verify", "start", "verify", "stop"].map(|kind| json!(kind))),
            )
            .collect();
        assert_eq!(kinds, expected);
        rig.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn replaced_receiver_never_accepts_an_event_of_the_old_stream() {
        use crate::plugins::tests::{fake_channel, package};
        use std::io::Write;
        let mut rig = Rig::start("normal", false, quick()).await;
        // The fake tails one events file per source: a new `start` cannot replay the old stream.
        let mut channel = fake_channel(
            "fake",
            &rig.logs,
            "normal",
            json!([{"name": "token", "secret": true}]),
        );
        channel["args"][3] = json!(rig.logs.dir.join("events-{source}.jsonl"));
        let dir = package("fake-fake", json!({ "fake": channel }));
        rig.plugins
            .install(&dir, &std::collections::HashSet::new())
            .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        let binding = rig.sealed_receiver().await;
        let envelope: String = rig
            .client
            .query_one(
                "SELECT credential_envelope FROM openmybot.channel_bindings WHERE binding_id=$1",
                &[&binding],
            )
            .await
            .unwrap()
            .get(0);
        let row = |source_key: &str| ReceiverRow {
            binding_id: binding,
            channel: kind(),
            source_key: source_key.into(),
            credential_envelope: envelope.clone(),
        };
        let (done, started) = oneshot::channel();
        rig.channels
            .as_mut()
            .unwrap()
            .start_receiver(&mut rig.fixture.pg, row("1001"), done)
            .await;
        assert_eq!(started.await.unwrap(), Ok(()));
        // The old stream is busy when the receiver is replaced.
        let mut old = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(rig.logs.dir.join("events-1001.jsonl"))
            .unwrap();
        for at in 0..50 {
            writeln!(old, "{}", event(&format!("old-{at}"))).unwrap();
        }
        until("old stream flowing", async || rig.accepted("old-0")).await;
        rig.client
            .execute(
                "UPDATE openmybot.channel_bindings SET source_key='2002' WHERE binding_id=$1",
                &[&binding],
            )
            .await
            .unwrap();
        let (done, started) = oneshot::channel();
        rig.channels
            .as_mut()
            .unwrap()
            .start_receiver(&mut rig.fixture.pg, row("2002"), done)
            .await;
        assert_eq!(started.await.unwrap(), Ok(()));
        sleep(Duration::from_millis(500)).await;
        let leaked: i64 = rig
            .client
            .query_one(
                "SELECT count(*) FROM openmybot.channel_events WHERE record_kind='event' AND source_key='2002'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(leaked, 0);
        // A new process started the new receiver, without a cursor from the old stream.
        assert_eq!(rig.logs.received_of("hello").len(), 2);
        let starts = rig.logs.received_of("start");
        let last = starts.last().unwrap();
        assert_eq!(
            (&last["source_key"], &last["last_event_key"]),
            (&json!("2002"), &Value::Null)
        );
        rig.stop().await;
    }
}
