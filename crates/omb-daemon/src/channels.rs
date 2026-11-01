//! Daemon wiring of the channel plugins and the receivers they serve, the dispatcher, the heartbeat,
//! the outbound task, the sweeper and the status segment; the one boundary mapping of plugin events.
use crate::reconcile::{self, REPLAY_DEADLINE, Reconciler};
use crate::{
    CancelRequests, ChannelCounters, ChannelError, ChannelStatus, Connection, Counters,
    DaemonError, GapStatus, PluginStatus, STORE_BUDGET, Task, Timings,
    dispatch::start_dispatcher,
    engine::Engine,
    outbound::{OutboundContext, start_outbound},
    pg::{AuthorityConnection, Postgres, map_store_error},
    plugins::Plugins,
    supervisor::{Context, PluginProcess},
};
use omb_channel_sdk::{
    PLUGIN_MAX,
    protocol::{EventFrame, EventKind, VerifyFailure},
};
use omb_hostdriver::{CC_KILL_GRACE, CC_TERM_GRACE};
use omb_store::{
    ChannelKind, Command, Content, IdentityKey, KEY_MAX, NormalizedEvent, ReceiverRow,
    touch_heartbeat,
};
use openbot_application::RunTerminalNotice;
use openbot_contracts::ids::ActorId;
use openbot_infra::auth::single_user::SINGLE_USER_ACTOR_ID;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
};
use time::{
    OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339, macros::format_description,
};
use tokio::{
    sync::{Mutex, Notify, Semaphore, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use uuid::Uuid;

/// Status note of a channel without an installed plugin.
pub(crate) const NO_PLUGIN_NOTE: &str = "no plugin installed for this channel";
/// The supervisors' handles by channel kind, shared with the outbound task.
pub(crate) type Processes = Arc<std::sync::Mutex<HashMap<ChannelKind, PluginProcess>>>;

/// Read side of the status channel and plugin segments: its own connection, the counters and the
/// installed plugins.
pub(crate) struct StatusSource {
    pub(crate) client: Arc<tokio_postgres::Client>,
    pub(crate) counters: Arc<Counters>,
    pub(crate) plugins: Plugins,
}
/// RFC 3339 in UTC with `Z` and only the fractional digits the instant needs.
pub(crate) fn rfc3339_utc(unix_nanos: i128) -> Result<String, DaemonError> {
    i64::try_from(unix_nanos)
        .map(|nanos| {
            chrono::DateTime::from_timestamp_nanos(nanos)
                .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
        })
        .map_err(|_| DaemonError::InternalError)
}
/// RFC 3339 in UTC with exactly three fractional digits, truncated: the fingerprint's
/// `occurredAt` and `start.last_accepted_at`.
pub(crate) fn utc_millis(at: OffsetDateTime) -> String {
    at.to_offset(UtcOffset::UTC)
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .unwrap_or_default()
}
impl StatusSource {
    pub(crate) async fn read(&self) -> Result<Vec<ChannelStatus>, DaemonError> {
        let error = DaemonError::InternalError;
        let counters = ChannelCounters {
            platform_payload_unparseable: self
                .counters
                .platform_payload_unparseable
                .load(Ordering::Relaxed),
            event_conflict: self.counters.event_conflict.load(Ordering::Relaxed),
            unsupported_update: self.counters.unsupported_update.load(Ordering::Relaxed),
        };
        omb_store::channel_status(&self.client)
            .await
            .map_err(|_| error)?
            .into_iter()
            .map(|receiver| {
                Ok(ChannelStatus {
                    channel: receiver.channel.as_str().to_owned(),
                    binding_id: receiver.binding_id.to_string(),
                    status: receiver.status,
                    status_reason: receiver.status_reason,
                    pending_dispatch: receiver.pending_dispatch,
                    gaps: receiver
                        .gaps
                        .into_iter()
                        .map(|gap| {
                            Ok(GapStatus {
                                reason: gap.reason,
                                started_at: rfc3339_utc(gap.started_at.unix_timestamp_nanos())?,
                                ended_at: gap
                                    .ended_at
                                    .map(|at| rfc3339_utc(at.unix_timestamp_nanos()))
                                    .transpose()?,
                            })
                        })
                        .collect::<Result<_, DaemonError>>()?,
                    note: self.plugins.provider(&receiver.channel).map_or_else(
                        || NO_PLUGIN_NOTE.to_owned(),
                        |plugin| {
                            plugin.channels[receiver.channel.as_str()]
                                .status_note
                                .clone()
                        },
                    ),
                    counters: counters.clone(),
                })
            })
            .collect()
    }
    /// Every installed plugin with the state of its processes.
    pub(crate) fn plugins(&self) -> Vec<PluginStatus> {
        self.plugins
            .list()
            .into_iter()
            .map(|plugin| {
                let (process, last_exit_code) = self.plugins.process(&plugin);
                PluginStatus {
                    channels: plugin.channels.keys().cloned().collect(),
                    name: plugin.name,
                    version: plugin.version,
                    process,
                    last_exit_code,
                }
            })
            .collect()
    }
}

/// Control command of the first word, and the `/pair` code when the whole text is `/pair <code>`.
pub(crate) fn classify(text: &str) -> (Option<Command>, Option<String>) {
    let pair_code = text.strip_prefix("/pair").and_then(|rest| {
        let code = rest.trim_start();
        (code.len() < rest.len() && !code.is_empty() && !code.contains(char::is_whitespace))
            .then(|| code.to_owned())
    });
    let word = text.split_whitespace().next().unwrap_or_default();
    let command = word.starts_with('/').then(|| {
        let name = word.split('@').next().unwrap_or_default().to_lowercase();
        match name.as_str() {
            "/help" => Command::Help,
            "/start" => Command::Start,
            "/status" => Command::Status,
            "/cancel" => Command::Cancel,
            "/pair" => Command::Pair,
            _ => Command::Unknown,
        }
    });
    (command, pair_code)
}
/// The boundary mapping of one event of a `kind` plugin; `None` breaks the protocol. Missing or
/// foreign identity keys, an unparseable time, a text with NUL or the plugin's own `malformed`
/// make the event malformed, which keeps the obtainable identity and has no fingerprint. The
/// fingerprint is SHA-256 of the RFC 8785 form of `{eventType, occurredAt?, data}`.
pub(crate) fn normalize(
    kind: &ChannelKind,
    source_key: &str,
    frame: EventFrame,
) -> Option<NormalizedEvent> {
    let ours = |text: &str, separator: char| {
        text.strip_prefix(kind.as_str())
            .is_some_and(|rest| rest.starts_with(separator))
    };
    if !(1..=KEY_MAX).contains(&frame.event_key.len())
        || frame.event_key.contains('\0')
        || !ours(&frame.event_type, '.')
    {
        return None;
    }
    let identity = |key: Option<&str>| {
        key.filter(|key| ours(key, ':'))
            .and_then(IdentityKey::parse)
    };
    let sender = identity(frame.sender_key.as_deref());
    let chat = identity(frame.chat_key.as_deref());
    let parsed = frame
        .occurred_at
        .as_deref()
        .map(|at| OffsetDateTime::parse(at, &Rfc3339));
    let malformed = sender.is_none()
        || chat.is_none()
        || matches!(parsed, Some(Err(_)))
        || match frame.kind {
            EventKind::Text => frame.text.contains('\0'),
            EventKind::Other => false,
            EventKind::Malformed => true,
        };
    let occurred_at = parsed.and_then(Result::ok);
    let (fingerprint, content) = if malformed {
        (None, Content::Malformed)
    } else {
        // Keys sort by UTF-16 code units; serde_json escapes strings the way RFC 8785 does.
        let string = |value: &str| serde_json::to_string(value).unwrap_or_default();
        let mut data: Vec<(&String, &String)> = frame.data.iter().collect();
        data.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
        let data: Vec<String> = data
            .into_iter()
            .map(|(key, value)| format!("{}:{}", string(key), string(value)))
            .collect();
        let occurred = occurred_at
            .map(|at| format!(r#","occurredAt":{}"#, string(&utc_millis(at))))
            .unwrap_or_default();
        let canonical = format!(
            r#"{{"data":{{{}}},"eventType":{}{occurred}}}"#,
            data.join(","),
            string(&frame.event_type),
        );
        let content = match frame.kind {
            EventKind::Text => {
                let (command, pair_code) = classify(&frame.text);
                Content::Text {
                    text: frame.text,
                    command,
                    pair_code,
                }
            }
            _ => Content::Other,
        };
        (Some(Sha256::digest(canonical.as_bytes()).into()), content)
    };
    Some(NormalizedEvent {
        channel: kind.clone(),
        source_key: source_key.to_owned(),
        event_key: frame.event_key,
        event_type: frame.event_type,
        occurred_at,
        private: frame.private,
        sender,
        chat,
        fingerprint,
        content,
    })
}

/// Advances `last_heartbeat_at` every `heartbeat`; a store failure ends the task.
pub(crate) fn start_heartbeat(connection: Connection, token_id: Uuid, timings: Timings) -> Task {
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

/// What the outbound side starts from: the engine's terminal notices and the configured host
/// binary that startup reconciliation compares orphan process-group leaders with.
pub(crate) struct Outbound {
    pub(crate) terminals: mpsc::Receiver<RunTerminalNotice>,
    pub(crate) crabcode: Option<PathBuf>,
}

/// The kind's supervisor, started on first use.
fn supervisor(
    processes: &Processes,
    supervisors: &mut JoinSet<Result<(), ChannelError>>,
    context: &Arc<Context>,
    kind: &ChannelKind,
) -> PluginProcess {
    processes
        .lock()
        .unwrap()
        .entry(kind.clone())
        .or_insert_with(|| PluginProcess::spawn(kind.clone(), Arc::clone(context), supervisors))
        .clone()
}

/// One plugin supervisor per channel kind in use with the binding of its receiver, the dispatcher,
/// the heartbeat, the outbound task, the sweeper and the status connection.
pub(crate) struct Channels {
    processes: Processes,
    supervisors: JoinSet<Result<(), ChannelError>>,
    receivers: HashMap<ChannelKind, Uuid>,
    pub(crate) context: Arc<Context>,
    dispatcher: Task,
    heartbeat: Task,
    outbound: Task,
    sweeper: Task,
    status: Arc<tokio_postgres::Client>,
    status_driver: JoinHandle<Result<(), tokio_postgres::Error>>,
}
impl Channels {
    /// Records startup gaps and reconciles the store, then starts the heartbeat, the dispatcher on
    /// `gate`, the plugin of every active receiver, the outbound task and the sweeper, each on its
    /// own connection. An active receiver whose channel has no installed plugin only gets a
    /// `plugin_missing` gap.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn start(
        postgres: &mut Postgres,
        engine: &Engine,
        token_id: Uuid,
        timings: Timings,
        plugins: Plugins,
        cancel: CancelRequests,
        outbound: Outbound,
        gate: Arc<Mutex<HashSet<String>>>,
    ) -> Result<Self, DaemonError> {
        postgres.record_startup_gaps(token_id).await?;
        let entry = engine
            .assembly
            .delegated_entry
            .clone()
            .ok_or(DaemonError::InternalError)?;
        let connection = |opened: AuthorityConnection| Connection {
            client: opened.client,
            driver: opened.driver,
        };
        let heartbeat = connection(
            postgres
                .open_resident_connection("openmybot-heartbeat")
                .await?,
        );
        let mut dispatcher = connection(
            postgres
                .open_resident_connection("openmybot-dispatcher")
                .await?,
        );
        let status = postgres
            .open_resident_connection("openmybot-status")
            .await?;
        let mut receivers = Vec::new();
        for view in omb_store::list_bindings(&status.client, Instant::now() + STORE_BUDGET)
            .await
            .map_err(map_store_error)?
        {
            if view.binding_kind != "receiver" || view.status != "active" {
                continue;
            }
            let kind = ChannelKind::parse(&view.channel_kind).ok_or(DaemonError::InternalError)?;
            if plugins.provider(&kind).is_none() {
                omb_store::open_plugin_missing_gap(
                    &status.client,
                    view.binding_id,
                    Instant::now() + STORE_BUDGET,
                )
                .await
                .map_err(map_store_error)?;
                continue;
            }
            // The live-binding index allows one active receiver per channel.
            if let Some(row) = postgres.list_active_receivers(kind).await?.pop() {
                let opened = postgres
                    .open_resident_connection("openmybot-receiver")
                    .await?;
                receivers.push((row, connection(opened)));
            }
        }
        let delivery = connection(
            postgres
                .open_resident_connection("openmybot-delivery")
                .await?,
        );
        let sweeper = connection(
            postgres
                .open_resident_connection("openmybot-sweeper")
                .await?,
        );
        let wake = Arc::new(Notify::new());
        let reconciler = Reconciler {
            application: engine.assembly.application.clone(),
            resolver: engine.resolver.clone(),
            crabcode: outbound.crabcode,
            term_grace: CC_TERM_GRACE,
            kill_grace: CC_KILL_GRACE,
            replay_deadline: REPLAY_DEADLINE,
            wake: Arc::clone(&wake),
        };
        reconcile::startup(&mut dispatcher.client, &reconciler)
            .await
            .map_err(map_store_error)?;
        let context = Arc::new(Context {
            plugins,
            vault: engine.vault.clone(),
            owner: ActorId::new(SINGLE_USER_ACTOR_ID),
            timings,
            counters: Arc::new(Counters::default()),
            wake: Arc::clone(&wake),
            cancel,
            slots: Arc::new(Semaphore::new(PLUGIN_MAX)),
        });
        let heartbeat = start_heartbeat(heartbeat, token_id, timings);
        let dispatcher = start_dispatcher(dispatcher, entry, timings, Arc::clone(&wake), gate);
        let processes = Processes::default();
        let mut supervisors = JoinSet::new();
        let mut running = HashMap::new();
        for (row, opened) in receivers {
            let process = supervisor(&processes, &mut supervisors, &context, &row.channel);
            running.insert(row.channel.clone(), row.binding_id);
            // Startup has no one waiting for the receipt.
            let (done, _) = oneshot::channel();
            process.start(row, opened, done).await;
        }
        let outbound = start_outbound(
            delivery,
            OutboundContext {
                processes: Arc::clone(&processes),
                timings,
                wake,
            },
            outbound.terminals,
        );
        Ok(Self {
            processes,
            supervisors,
            receivers: running,
            context,
            dispatcher,
            heartbeat,
            outbound,
            sweeper: reconcile::start_sweeper(sweeper, reconciler, timings),
            status: Arc::new(status.client),
            status_driver: status.driver,
        })
    }
    pub(crate) fn status_source(&self) -> StatusSource {
        StatusSource {
            client: Arc::clone(&self.status),
            counters: Arc::clone(&self.context.counters),
            plugins: self.context.plugins.clone(),
        }
    }
    /// The dispatcher's wake-up, shared with the supervisors, the outbound task and the reconciler.
    pub(crate) fn wake(&self) -> Arc<Notify> {
        Arc::clone(&self.context.wake)
    }
    /// The supervisor of `kind`, when a plugin provides it.
    fn process(&mut self, kind: &ChannelKind) -> Option<PluginProcess> {
        self.context.plugins.provider(kind)?;
        Some(supervisor(
            &self.processes,
            &mut self.supervisors,
            &self.context,
            kind,
        ))
    }
    /// Makes `row` its channel's receiver on a new resident connection; the plugin of the channel
    /// replaces the running receiver and answers `done` once `start` is sent.
    pub(crate) async fn start_receiver(
        &mut self,
        postgres: &mut Postgres,
        row: ReceiverRow,
        done: oneshot::Sender<Result<(), DaemonError>>,
    ) {
        let Some(process) = self.process(&row.channel) else {
            let _ = done.send(Err(DaemonError::PluginNotInstalled));
            return;
        };
        match postgres
            .open_resident_connection("openmybot-receiver")
            .await
        {
            Ok(opened) => {
                self.receivers.insert(row.channel.clone(), row.binding_id);
                let connection = Connection {
                    client: opened.client,
                    driver: opened.driver,
                };
                process.start(row, connection, done).await;
            }
            Err(error) => {
                let _ = done.send(Err(error));
            }
        }
    }
    /// Stops receiving for `binding_id`, if a plugin receives for it.
    pub(crate) async fn stop_receiver(&mut self, binding_id: Uuid, done: oneshot::Sender<()>) {
        let kind = self
            .receivers
            .iter()
            .find(|(_, running)| **running == binding_id)
            .map(|(kind, _)| kind.clone());
        let process = kind.and_then(|kind| {
            self.receivers.remove(&kind);
            self.processes.lock().unwrap().get(&kind).cloned()
        });
        match process {
            Some(process) => process.stop(Some(binding_id), done).await,
            None => {
                let _ = done.send(());
            }
        }
    }
    /// Ends the processes of `kinds` through the stop ladder before their package is removed or
    /// replaced; `done` answers once every process group is empty.
    pub(crate) async fn retire(&mut self, kinds: Vec<String>, done: oneshot::Sender<()>) {
        let processes: Vec<PluginProcess> = self
            .processes
            .lock()
            .unwrap()
            .iter()
            .filter(|(kind, _)| kinds.iter().any(|retired| retired == kind.as_str()))
            .map(|(_, process)| process.clone())
            .collect();
        let mut receipts = Vec::new();
        for process in processes {
            let (ended, receipt) = oneshot::channel();
            process.retire(ended).await;
            receipts.push(receipt);
        }
        // The main loop keeps serving while the ladders run.
        tokio::spawn(async move {
            for receipt in receipts {
                let _ = receipt.await;
            }
            let _ = done.send(());
        });
    }
    /// Hands a credential check to the channel's plugin; the reply is dropped when no plugin
    /// provides the channel.
    pub(crate) async fn verify(
        &mut self,
        kind: ChannelKind,
        credential: String,
        source_key: Option<String>,
        reply: oneshot::Sender<Result<String, VerifyFailure>>,
    ) {
        if let Some(process) = self.process(&kind) {
            process.verify(credential, source_key, reply).await;
        }
    }
    /// Resolves with `internal_error` when the heartbeat, the dispatcher, the outbound task, the
    /// sweeper or a plugin supervisor ends; a supervisor ends only on a store failure.
    pub(crate) async fn finished(&mut self) -> DaemonError {
        tokio::select! {
            _ = self.heartbeat.finished() => {}
            _ = self.dispatcher.finished() => {}
            _ = self.outbound.finished() => {}
            _ = self.sweeper.finished() => {}
            Some(_) = self.supervisors.join_next(), if !self.supervisors.is_empty() => {}
        }
        DaemonError::InternalError
    }
    /// Receiving stops first; then the outbound task, the sweeper and the dispatcher; then every
    /// plugin process goes through the stop ladder; the heartbeat and the status connection that
    /// request handlers may still share end last.
    pub(crate) async fn stop(mut self) {
        let processes: Vec<PluginProcess> =
            self.processes.lock().unwrap().values().cloned().collect();
        for process in &processes {
            let (done, stopped) = oneshot::channel();
            process.stop(None, done).await;
            let _ = stopped.await;
        }
        self.outbound.stop().await;
        self.sweeper.stop().await;
        self.dispatcher.stop().await;
        for process in &processes {
            process.terminate().await;
        }
        while self.supervisors.join_next().await.is_some() {}
        self.heartbeat.stop().await;
        self.status_driver.abort();
        let _ = self.status_driver.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{Op, Ops};
    use crate::{
        CANCEL_QUEUE, OMB_REPLY_TEXTS_V1, StatusSnapshot, TERMINAL_QUEUE,
        delegation::fixture::{self, Fixture},
        plugins::tests::{Logs, fake_channel, installed, package},
    };
    use crate::{
        agent::{
            AgentRuntime,
            tests::{self as agent, Run},
        },
        reconcile::tests as rt,
    };
    use omb_hostdriver::WorkspaceRoots;
    use omb_store::testkit;
    use omb_store::{
        AcceptOutcome, Disposition, PairStart, PollGapReason, accept_event, open_poll_gap,
        pair_start,
    };
    use openbot_application::RunTerminalKind;
    use openbot_application::{BeginDelegatedThreadRun, DelegatedUntrustedMaterial};
    use openbot_contracts::command::CancelThreadRun;
    use openbot_contracts::{
        auth::DelegationSource,
        command::{AppCommand, AppReply},
        ids::{BotId, RunId, ThreadId},
    };
    use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal};
    use serde_json::{Value, json};
    use std::time::Duration;
    use tokio_postgres::Client;

    const TELEGRAM: ChannelKind = ChannelKind::from_static("telegram");
    const FEISHU: ChannelKind = ChannelKind::from_static("feishu");

    fn cancel() -> CancelRequests {
        tokio::sync::mpsc::channel(CANCEL_QUEUE).0
    }
    /// The outbound side on a queue of its own, without a configured host binary.
    fn outbound() -> Outbound {
        Outbound {
            terminals: mpsc::channel(TERMINAL_QUEUE).1,
            crabcode: None,
        }
    }

    fn deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(30)
    }
    fn quick() -> Timings {
        Timings {
            heartbeat: Duration::from_millis(100),
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(100),
            dispatch_retry: Duration::from_millis(100),
            plugin_restart: Duration::from_millis(50),
            ..Timings::default()
        }
    }
    async fn connection(fixture: &mut Fixture, name: &str) -> Connection {
        let opened = fixture.pg.open_resident_connection(name).await.unwrap();
        Connection {
            client: opened.client,
            driver: opened.driver,
        }
    }
    /// No installed plugin: a data directory of its own under the fixture's.
    fn none(fixture: &Fixture) -> Plugins {
        Plugins::load(
            &fixture.root.join("no-plugins"),
            Vec::new(),
            fixture.root.clone(),
        )
        .unwrap()
    }
    /// The fake installed for `telegram` and, as a second plugin, for `feishu` with its scenario.
    fn both(fixture: &Fixture, telegram: &Logs, feishu: &Logs, scenario: &str) -> Plugins {
        let plugins = installed(&fixture.root, "telegram", telegram, "normal");
        let dir = package(
            "fake-feishu",
            json!({"feishu": fake_channel("feishu", feishu, scenario, json!([{"name": "token", "secret": true}]))}),
        );
        plugins.install(&dir, &HashSet::new()).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        plugins
    }
    /// A private text event of `kind`'s chat `42`, occurred now.
    fn message(kind: &str, key: &str, text: &str) -> Value {
        json!({
            "event_key": key,
            "event_type": format!("{kind}.message"),
            "occurred_at": utc_millis(OffsetDateTime::now_utc()),
            "private": true,
            "sender_key": format!("{kind}:42"),
            "chat_key": format!("{kind}:42"),
            "kind": "text",
            "text": text,
            "data": {"text": text},
        })
    }
    /// The `start` frames the fake received with `credential`, once there is one.
    async fn starts_with(logs: &Logs, credential: &str) -> usize {
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let seen = logs
                .received_of("start")
                .iter()
                .filter(|frame| frame["credential"] == credential)
                .count();
            if seen > 0 {
                return seen;
            }
            assert!(
                tokio::time::Instant::now() < limit,
                "no start with {credential}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    /// A Telegram sender paired on a freshly minted thread at the owner's current generation,
    /// with one accepted message `10`.
    async fn paired(fixture: &mut Fixture) -> (Client, Uuid) {
        let mut client = fixture.client().await;
        let receiver = fixture::receiver(&client, "telegram").await;
        let engine = fixture.engine();
        let AppReply::ThreadMinted(minted) = engine
            .assembly
            .application
            .execute(
                engine.resolver.local_context().unwrap(),
                AppCommand::MintThreadId,
            )
            .await
            .unwrap()
        else {
            panic!("mint reply");
        };
        let generation = engine
            .resolver
            .local_context()
            .unwrap()
            .auth_generation()
            .get();
        let started = pair_start(
            &mut client,
            PairStart {
                channel: TELEGRAM,
                workspace_dir: "/workspaces/project",
                thread_id: minted.thread_id.as_str(),
                granted_generation: generation,
                run_deadline: None,
            },
            deadline(),
        )
        .await
        .unwrap();
        let now = client
            .query_one("SELECT statement_timestamp()", &[])
            .await
            .unwrap()
            .get(0);
        let event = |key: &str, text: String, pair_code: Option<String>| NormalizedEvent {
            channel: TELEGRAM,
            source_key: "1001".into(),
            event_key: key.into(),
            event_type: "telegram.message".into(),
            occurred_at: Some(now),
            private: true,
            sender: IdentityKey::parse("telegram:42"),
            chat: IdentityKey::parse("telegram:42"),
            fingerprint: Some([key.len() as u8; 32]),
            content: Content::Text {
                text,
                command: pair_code.as_ref().map(|_| Command::Pair),
                pair_code,
            },
        };
        let code = started.code.display();
        let pairing = event("1", format!("/pair {code}"), Some(code));
        for (incoming, disposition) in [
            (pairing, Disposition::PairingSucceeded),
            (
                event("10", "please refactor".into(), None),
                Disposition::AcceptedMessage,
            ),
        ] {
            assert_eq!(
                accept_event(
                    &mut client,
                    receiver,
                    &incoming,
                    &OMB_REPLY_TEXTS_V1,
                    deadline()
                )
                .await
                .unwrap(),
                AcceptOutcome::Recorded(disposition)
            );
        }
        (client, started.binding_id)
    }
    async fn row(client: &Client, key: &str) -> serde_json::Value {
        client
            .query_one(
                "SELECT row_to_json(e) FROM openmybot.channel_events e WHERE event_key=$1",
                &[&key],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn settled(client: &Client, key: &str) -> serde_json::Value {
        let limit = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let stored = row(client, key).await;
            if stored["dispatch_status"] != "pending" {
                return stored;
            }
            assert!(tokio::time::Instant::now() < limit, "dispatch deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn dispatcher(fixture: &mut Fixture) -> (Task, Arc<Notify>) {
        let entry = fixture.engine().assembly.delegated_entry.clone().unwrap();
        let wake = Arc::new(Notify::new());
        let task = start_dispatcher(
            connection(fixture, "test-dispatcher").await,
            entry,
            quick(),
            Arc::clone(&wake),
            Arc::default(),
        );
        (task, wake)
    }
    fn replay(binding: Uuid, stored: &serde_json::Value) -> BeginDelegatedThreadRun {
        let record = stored["record_id"].as_str().unwrap();
        BeginDelegatedThreadRun {
            source: DelegationSource::ExternalBinding {
                binding_id: binding.to_string(),
            },
            revision: 1,
            trigger_id: record.into(),
            thread_id: ThreadId::new(stored["thread_id"].as_str().unwrap()),
            run_id: RunId::new(stored["run_id"].as_str().unwrap()),
            bot_id: BotId::new("omb-crabcode"),
            untrusted_material: Some(DelegatedUntrustedMaterial {
                source_ref: format!("omb:channel_events:{record}"),
                text: stored["text"].as_str().unwrap().into(),
            }),
        }
    }
    async fn binding_state(client: &Client, id: Uuid) -> (String, Option<String>) {
        let row = client
            .query_one(
                "SELECT status,status_reason FROM openmybot.channel_bindings WHERE binding_id=$1",
                &[&id],
            )
            .await
            .unwrap();
        (row.get(0), row.get(1))
    }
    async fn token(fixture: &mut Fixture) -> Uuid {
        let token_id = Uuid::now_v7();
        let mut digest = [0; 32];
        digest[..16].copy_from_slice(token_id.as_bytes());
        fixture
            .pg
            .start_control_token(omb_store::ControlTokenStart {
                token_id,
                token_sha256: digest,
                daemon_pid: 1,
                engine_pin: "0123456789abcdef0123456789abcdef01234567",
                omb_version: "0.0.0",
            })
            .await
            .unwrap();
        token_id
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn dispatch_begins_run_for_pending_event_and_marks_dispatched() {
        let mut fixture = Fixture::start_with_bot().await;
        let (client, binding) = paired(&mut fixture).await;
        let (task, wake) = dispatcher(&mut fixture).await;
        wake.notify_one();
        let stored = settled(&client, "10").await;
        assert_eq!(stored["dispatch_status"], "dispatched");
        assert_eq!(stored["dispatch_attempts"], 1);
        assert!(!stored["dispatched_at"].is_null());
        let entry = fixture.engine().assembly.delegated_entry.clone().unwrap();
        let started = entry.begin(replay(binding, &stored)).await.unwrap();
        assert!(started.replayed);
        assert_eq!(started.run_id.as_str(), stored["run_id"].as_str().unwrap());
        task.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn redispatch_of_same_run_id_returns_replayed_and_marks_dispatched() {
        let mut fixture = Fixture::start_with_bot().await;
        let (client, binding) = paired(&mut fixture).await;
        let (task, wake) = dispatcher(&mut fixture).await;
        wake.notify_one();
        let first = settled(&client, "10").await;
        assert_eq!(first["dispatch_status"], "dispatched");
        let entry = fixture.engine().assembly.delegated_entry.clone().unwrap();
        assert!(entry.begin(replay(binding, &first)).await.unwrap().replayed);
        client.execute("UPDATE openmybot.channel_events SET dispatch_status='pending',dispatched_at=NULL WHERE event_key='10'", &[]).await.unwrap();
        wake.notify_one();
        let second = settled(&client, "10").await;
        assert_eq!(second["dispatch_status"], "dispatched");
        assert_eq!(second["dispatch_attempts"], 2);
        assert_eq!(second["run_id"], first["run_id"]);
        task.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn same_run_id_with_changed_text_maps_to_conflict() {
        let mut fixture = Fixture::start_with_bot().await;
        let (client, binding) = paired(&mut fixture).await;
        let (task, wake) = dispatcher(&mut fixture).await;
        wake.notify_one();
        let first = settled(&client, "10").await;
        assert_eq!(first["dispatch_status"], "dispatched");
        let mut changed = replay(binding, &first);
        changed.untrusted_material.as_mut().unwrap().text = "something else".into();
        let entry = fixture.engine().assembly.delegated_entry.clone().unwrap();
        let error = entry.begin(changed).await.unwrap_err();
        assert!(
            matches!(
                error,
                openbot_contracts::error::AppError::RequestConflict { .. }
            ),
            "{error:?}"
        );
        client.execute("UPDATE openmybot.channel_events SET dispatch_status='pending',dispatched_at=NULL,text='something else' WHERE event_key='10'", &[]).await.unwrap();
        wake.notify_one();
        let second = settled(&client, "10").await;
        assert_eq!(second["dispatch_status"], "conflict");
        assert_eq!(second["dispatch_attempts"], 2);
        assert_eq!(binding_state(&client, binding).await.0, "active");
        task.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn revoked_binding_is_not_dispatched() {
        let mut fixture = Fixture::start_with_bot().await;
        let (mut client, binding) = paired(&mut fixture).await;
        omb_store::revoke_binding(&mut client, binding, deadline())
            .await
            .unwrap();
        let (task, wake) = dispatcher(&mut fixture).await;
        wake.notify_one();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let stored = row(&client, "10").await;
        assert_eq!(stored["dispatch_status"], "cancelled");
        assert_eq!(stored["dispatch_attempts"], 0);
        assert!(stored["dispatched_at"].is_null());
        task.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn stale_revision_refusal_cancels_event_and_suspends_binding() {
        let mut fixture = Fixture::start_with_bot().await;
        let (client, binding) = paired(&mut fixture).await;
        // The binding's grant no longer matches the owner's current generation, so the engine
        // refuses the registration as not current.
        client.execute("UPDATE openmybot.channel_bindings SET granted_generation=granted_generation+1 WHERE binding_id=$1", &[&binding]).await.unwrap();
        let (task, wake) = dispatcher(&mut fixture).await;
        wake.notify_one();
        let stored = settled(&client, "10").await;
        assert_eq!(stored["dispatch_status"], "cancelled");
        assert_eq!(
            binding_state(&client, binding).await,
            ("suspended".into(), Some("grant_stale".into()))
        );
        task.stop().await;
        fixture.stop().await;
    }

    async fn status_source(
        fixture: &mut Fixture,
        plugins: Plugins,
    ) -> (StatusSource, JoinHandle<Result<(), tokio_postgres::Error>>) {
        let opened = fixture
            .pg
            .open_resident_connection("test-status")
            .await
            .unwrap();
        (
            StatusSource {
                client: Arc::new(opened.client),
                counters: Arc::new(Counters::default()),
                plugins,
            },
            opened.driver,
        )
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn status_snapshot_carries_channel_segment_with_closed_shape() {
        let mut fixture = Fixture::start().await;
        let mut client = fixture.client().await;
        let receiver = fixture::receiver(&client, "telegram").await;
        open_poll_gap(
            &mut client,
            receiver,
            PollGapReason::StreamBroken,
            deadline(),
        )
        .await
        .unwrap();
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        let (source, driver) = status_source(&mut fixture, plugins).await;
        source
            .counters
            .platform_payload_unparseable
            .fetch_add(1, Ordering::Relaxed);
        source
            .counters
            .event_conflict
            .fetch_add(2, Ordering::Relaxed);
        source
            .counters
            .unsupported_update
            .fetch_add(3, Ordering::Relaxed);
        let channels = source.read().await.unwrap();
        let snapshot = StatusSnapshot {
            deployment_id: "omb-local-test".into(),
            daemon_pid: 1,
            pg_pid: 2,
            pg_server_version_num: 170011,
            daemon_version: "0.0.0".into(),
            engine_pin: "0".repeat(40),
            authentication_failures: 0,
            channels,
            plugins: source.plugins(),
        };
        let value = serde_json::to_value(&snapshot).unwrap();
        let segment = value["channels"].as_array().unwrap();
        assert_eq!(segment.len(), 1);
        let item = segment[0].as_object().unwrap();
        let mut keys: Vec<&str> = item.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "binding_id",
                "channel",
                "counters",
                "gaps",
                "note",
                "pending_dispatch",
                "status",
                "status_reason"
            ]
        );
        assert_eq!(item["channel"], "telegram");
        assert_eq!(item["binding_id"], receiver.to_string());
        assert_eq!(item["status"], "active");
        assert!(item["status_reason"].is_null());
        assert_eq!(item["pending_dispatch"], 0);
        assert_eq!(
            item["counters"],
            serde_json::json!({"platform_payload_unparseable": 1, "event_conflict": 2, "unsupported_update": 3})
        );
        let gap = item["gaps"][0].as_object().unwrap();
        let mut gap_keys: Vec<&str> = gap.keys().map(String::as_str).collect();
        gap_keys.sort_unstable();
        assert_eq!(gap_keys, ["ended_at", "reason", "started_at"]);
        assert_eq!(
            value["plugins"],
            json!([{"name": "fake-telegram", "version": "0.1.0", "channels": ["telegram"], "process": "stopped", "last_exit_code": null}])
        );
        assert!(serde_json::from_value::<StatusSnapshot>(value.clone()).is_ok());
        let mut extra = value.clone();
        extra["channels"][0]["unknown"] = serde_json::json!(1);
        assert!(serde_json::from_value::<StatusSnapshot>(extra).is_err());
        let mut extra = value.clone();
        extra["channels"][0]["gaps"][0]["unknown"] = serde_json::json!(1);
        assert!(serde_json::from_value::<StatusSnapshot>(extra).is_err());
        let mut extra = value;
        extra["plugins"][0]["unknown"] = serde_json::json!(1);
        assert!(serde_json::from_value::<StatusSnapshot>(extra).is_err());
        driver.abort();
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn status_segment_times_are_rfc3339_utc_and_note_is_fixed() {
        let mut fixture = Fixture::start().await;
        let mut client = fixture.client().await;
        let receiver = fixture::receiver(&client, "telegram").await;
        open_poll_gap(
            &mut client,
            receiver,
            PollGapReason::ConnectFailed,
            deadline(),
        )
        .await
        .unwrap();
        omb_store::close_poll_gaps(&mut client, receiver, deadline())
            .await
            .unwrap();
        open_poll_gap(
            &mut client,
            receiver,
            PollGapReason::StreamBroken,
            deadline(),
        )
        .await
        .unwrap();
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        let (source, driver) = status_source(&mut fixture, plugins).await;
        let channels = source.read().await.unwrap();
        // The note is the installed plugin's, or fixed without one.
        assert_eq!(channels[0].note, "telegram fake note");
        let plugins = none(&fixture);
        let (bare, bare_driver) = status_source(&mut fixture, plugins).await;
        assert_eq!(bare.read().await.unwrap()[0].note, NO_PLUGIN_NOTE);
        bare_driver.abort();
        let gaps = &channels[0].gaps;
        assert_eq!(gaps.len(), 2);
        assert_eq!(
            (gaps[0].reason.as_str(), gaps[0].ended_at.as_deref()),
            ("stream_broken", None)
        );
        let stored: i64 = client.query_one("SELECT (extract(epoch FROM gap_started_at)*1000000)::bigint FROM openmybot.channel_events WHERE gap_reason='connect_failed'", &[]).await.unwrap().get(0);
        for text in [
            &gaps[0].started_at,
            &gaps[1].started_at,
            gaps[1].ended_at.as_ref().unwrap(),
        ] {
            assert!(text.ends_with('Z'), "{text}");
            let parsed = chrono::DateTime::parse_from_rfc3339(text).unwrap();
            assert_eq!(parsed.offset().local_minus_utc(), 0);
        }
        let parsed = chrono::DateTime::parse_from_rfc3339(&gaps[1].started_at).unwrap();
        assert_eq!(parsed.timestamp_micros(), stored);
        driver.abort();
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn heartbeat_task_updates_last_heartbeat_every_interval() {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let initial = omb_store::read_heartbeat(&client, token)
            .await
            .unwrap()
            .unwrap();
        let task = start_heartbeat(
            connection(&mut fixture, "test-heartbeat").await,
            token,
            quick(),
        );
        let mut seen = vec![initial];
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while seen.len() < 5 {
            assert!(tokio::time::Instant::now() < limit, "heartbeat deadline");
            let current = omb_store::read_heartbeat(&client, token)
                .await
                .unwrap()
                .unwrap();
            if current != *seen.last().unwrap() {
                seen.push(current);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for pair in seen.windows(2) {
            let step = pair[1].unix_timestamp_nanos() - pair[0].unix_timestamp_nanos();
            assert!(step >= 90_000_000, "{step}");
        }
        task.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn heartbeat_task_finishes_with_store_failed_when_database_stops() {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let mut task = start_heartbeat(
            connection(&mut fixture, "test-heartbeat").await,
            token,
            quick(),
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        fixture.engine.take().unwrap().shutdown().await;
        fixture.pg.stop().await.unwrap();
        let ended = tokio::time::timeout(Duration::from_secs(10), task.finished())
            .await
            .unwrap();
        assert_eq!(ended, Err(ChannelError::StoreFailed));
        task.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn daemon_start_writes_daemon_down_gap_for_active_receiver() {
        let mut fixture = Fixture::start().await;
        let first = token(&mut fixture).await;
        let client = fixture.client().await;
        client.execute("UPDATE openmybot.control_tokens SET last_heartbeat_at=statement_timestamp()-interval '10 minutes' WHERE token_id=$1", &[&first]).await.unwrap();
        let receiver = fixture::receiver(&client, "telegram").await;
        let second = token(&mut fixture).await;
        let plugins = none(&fixture);
        let engine = fixture.engine.as_ref().unwrap();
        let channels = Channels::start(
            &mut fixture.pg,
            engine,
            second,
            quick(),
            plugins,
            cancel(),
            outbound(),
            Arc::default(),
        )
        .await
        .unwrap();
        let rows = client.query("SELECT binding_id,gap_started_at=(SELECT last_heartbeat_at FROM openmybot.control_tokens WHERE token_id=$1),gap_ended_at>=(SELECT created_at FROM openmybot.control_tokens WHERE token_id=$2) FROM openmybot.channel_events WHERE gap_reason='daemon_down'", &[&first, &second]).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<_, Uuid>(0), receiver);
        assert!(rows[0].get::<_, bool>(1));
        assert!(rows[0].get::<_, bool>(2));
        channels.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn stop_sequence_stops_tasks_before_listener_and_engine() {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let receiver = fixture::receiver(&client, "telegram").await;
        let envelope = fixture
            .engine()
            .vault
            .seal(
                &receiver,
                SecretKind::Connector,
                SecretPrincipal::Actor(ActorId::new(SINGLE_USER_ACTOR_ID)),
                SecretPrincipal::Service(crate::ops::service(&TELEGRAM)),
                &SecretBytes::new(b"1001:stop-sequence-token".to_vec()),
            )
            .unwrap();
        client
            .execute(
                "UPDATE openmybot.channel_bindings SET credential_envelope=$2 WHERE binding_id=$1",
                &[&receiver, &envelope],
            )
            .await
            .unwrap();
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        let engine = fixture.engine.as_ref().unwrap();
        let channels = Channels::start(
            &mut fixture.pg,
            engine,
            token,
            quick(),
            plugins.clone(),
            cancel(),
            outbound(),
            Arc::default(),
        )
        .await
        .unwrap();
        let live = "SELECT count(*) FROM pg_stat_activity WHERE application_name IN ('openmybot-heartbeat','openmybot-dispatcher','openmybot-status','openmybot-receiver')";
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while client.query_one(live, &[]).await.unwrap().get::<_, i64>(0) < 4 {
            assert!(tokio::time::Instant::now() < limit, "connections deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        starts_with(&logs, "1001:stop-sequence-token").await;
        tokio::time::timeout(Duration::from_secs(10), channels.stop())
            .await
            .unwrap();
        // Receiving stopped before the process went through the stop ladder.
        let kinds: Vec<Value> = logs
            .received()
            .into_iter()
            .map(|frame| frame["type"].clone())
            .collect();
        assert_eq!(kinds, ["hello", "start", "stop"]);
        let plugin = plugins.provider(&TELEGRAM).unwrap();
        assert_eq!(plugins.process(&plugin).0, crate::ProcessState::Stopped);
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while client.query_one(live, &[]).await.unwrap().get::<_, i64>(0) > 0 {
            assert!(
                tokio::time::Instant::now() < limit,
                "task connections remain"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(binding_state(&client, receiver).await.0, "active");
        // The engine is still serving after the channel tasks stopped; it shuts down afterwards.
        let engine = fixture.engine();
        assert!(matches!(
            engine
                .assembly
                .application
                .execute(
                    engine.resolver.local_context().unwrap(),
                    AppCommand::MintThreadId
                )
                .await
                .unwrap(),
            AppReply::ThreadMinted(_)
        ));
        fixture.stop().await;
    }

    #[test]
    fn rfc3339_utc_matches_the_status_segment_format() {
        for (nanos, expected) in [
            (0, "1970-01-01T00:00:00Z"),
            (1_500_000_000, "1970-01-01T00:00:01.500Z"),
            (1_000_001_000, "1970-01-01T00:00:01.000001Z"),
            (1_793_202_187_000_000_007, "2026-10-28T15:43:07.000000007Z"),
        ] {
            let text = rfc3339_utc(nanos).unwrap();
            assert_eq!(text, expected);
            let parsed = chrono::DateTime::parse_from_rfc3339(&text).unwrap();
            assert_eq!(parsed.offset().local_minus_utc(), 0);
            assert_eq!(i128::from(parsed.timestamp_nanos_opt().unwrap()), nanos);
        }
        assert_eq!(
            rfc3339_utc(i128::from(i64::MAX) + 1),
            Err(DaemonError::InternalError)
        );
    }

    /// An active Telegram receiver row whose envelope seals `token` for the owner.
    async fn sealed_receiver(fixture: &Fixture, client: &Client, token: &str) -> ReceiverRow {
        let binding_id = fixture::receiver(client, "telegram").await;
        ReceiverRow {
            binding_id,
            channel: TELEGRAM,
            source_key: "1001".into(),
            credential_envelope: resealed(fixture, client, binding_id, token).await,
        }
    }
    async fn resealed(fixture: &Fixture, client: &Client, binding_id: Uuid, token: &str) -> String {
        let envelope = fixture
            .engine()
            .vault
            .seal(
                &binding_id,
                SecretKind::Connector,
                SecretPrincipal::Actor(ActorId::new(SINGLE_USER_ACTOR_ID)),
                SecretPrincipal::Service(crate::ops::service(&TELEGRAM)),
                &SecretBytes::new(token.as_bytes().to_vec()),
            )
            .unwrap();
        client
            .execute(
                "UPDATE openmybot.channel_bindings SET credential_envelope=$2 WHERE binding_id=$1",
                &[&binding_id, &envelope],
            )
            .await
            .unwrap();
        envelope
    }
    async fn receivers(client: &Client) -> i64 {
        client
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name='openmybot-receiver'",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }
    async fn receivers_reach(client: &Client, expected: i64) {
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while receivers(client).await != expected {
            assert!(tokio::time::Instant::now() < limit, "receiver connections");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn runtime_receiver_start_and_stop_through_commands_with_fake_telegram() {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        let mut channels = started(&mut fixture, token, quick(), plugins, outbound()).await;
        assert_eq!(receivers(&client).await, 0);
        let row = sealed_receiver(&fixture, &client, "1001:runtime-token").await;
        let binding = row.binding_id;
        let (done, started) = oneshot::channel();
        channels.start_receiver(&mut fixture.pg, row, done).await;
        assert_eq!(started.await.unwrap(), Ok(()));
        starts_with(&logs, "1001:runtime-token").await;
        receivers_reach(&client, 1).await;
        let (done, stopped) = oneshot::channel();
        channels.stop_receiver(binding, done).await;
        stopped.await.unwrap();
        receivers_reach(&client, 0).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let kinds: Vec<Value> = logs
            .received()
            .into_iter()
            .map(|frame| frame["type"].clone())
            .collect();
        assert_eq!(kinds, ["hello", "start", "stop"]);
        channels.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn stop_receiver_for_another_binding_id_is_a_no_op_and_start_replaces_the_running_receiver()
     {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        let mut channels = started(&mut fixture, token, quick(), plugins, outbound()).await;
        let first = sealed_receiver(&fixture, &client, "1001:token-a").await;
        let binding = first.binding_id;
        let (done, _) = oneshot::channel();
        channels.start_receiver(&mut fixture.pg, first, done).await;
        starts_with(&logs, "1001:token-a").await;
        let (done, stopped) = oneshot::channel();
        channels.stop_receiver(Uuid::now_v7(), done).await;
        stopped.await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(logs.received_of("stop").is_empty());
        receivers_reach(&client, 1).await;
        let envelope = resealed(&fixture, &client, binding, "1001:token-b").await;
        let second = ReceiverRow {
            binding_id: binding,
            channel: TELEGRAM,
            source_key: "1001".into(),
            credential_envelope: envelope.clone(),
        };
        let (done, _) = oneshot::channel();
        channels.start_receiver(&mut fixture.pg, second, done).await;
        starts_with(&logs, "1001:token-b").await;
        // The old process ended through the stop ladder before a new one started the receiver.
        let kinds: Vec<Value> = logs
            .received()
            .into_iter()
            .map(|frame| frame["type"].clone())
            .collect();
        assert_eq!(kinds, ["hello", "start", "hello", "start"]);
        receivers_reach(&client, 1).await;
        // A receiver that stopped itself, on an event of a binding no longer active, can be
        // started again.
        client.execute("UPDATE openmybot.channel_bindings SET status='suspended',status_reason='credential_rejected' WHERE binding_id=$1", &[&binding]).await.unwrap();
        logs.push(&message("telegram", "5", "while suspended"));
        receivers_reach(&client, 0).await;
        assert!(logs.received_of("stop").is_empty());
        client.execute("UPDATE openmybot.channel_bindings SET status='active',status_reason=NULL WHERE binding_id=$1", &[&binding]).await.unwrap();
        let third = ReceiverRow {
            binding_id: binding,
            channel: TELEGRAM,
            source_key: "1001".into(),
            credential_envelope: envelope,
        };
        let (done, _) = oneshot::channel();
        channels.start_receiver(&mut fixture.pg, third, done).await;
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while logs.received_of("start").len() < 3 {
            assert!(
                tokio::time::Instant::now() < limit,
                "restarted receiver did not start"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        receivers_reach(&client, 1).await;
        channels.stop().await;
        fixture.stop().await;
    }

    // ---- Outbound delivery and reconciliation --------------------------------------------

    /// Starts the channel tasks on the fixture's store and engine.
    async fn started(
        fixture: &mut Fixture,
        token: Uuid,
        timings: Timings,
        plugins: Plugins,
        outbound: Outbound,
    ) -> Channels {
        let engine = fixture.engine.as_ref().unwrap();
        Channels::start(
            &mut fixture.pg,
            engine,
            token,
            timings,
            plugins,
            cancel(),
            outbound,
            Arc::default(),
        )
        .await
        .unwrap()
    }
    /// Channel timings with a short delivery poll.
    fn outbound_timings() -> Timings {
        Timings {
            delivery_poll: Duration::from_millis(50),
            ..quick()
        }
    }
    fn slow(root: &std::path::Path) -> omb_hostdriver::HostDriverConfig {
        agent::host(
            root,
            "slow_result",
            agent::quick(),
            &[("FAKE_CRABCODE_DELAY_MS", "1500")],
        )
    }
    async fn cancel_run(fixture: &Fixture, run: &Run) {
        let engine = fixture.engine();
        engine
            .assembly
            .application
            .execute(
                engine.resolver.local_context().unwrap(),
                AppCommand::CancelThreadRun(CancelThreadRun {
                    thread_id: run.thread.clone(),
                    run_id: run.run.clone(),
                }),
            )
            .await
            .unwrap();
    }
    /// Waits for the engine's terminal notice of `run` on the fixture's queue.
    async fn noticed(
        terminals: &mut mpsc::Receiver<RunTerminalNotice>,
        run: &Run,
    ) -> RunTerminalKind {
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                let notice = terminals.recv().await.unwrap();
                if notice.run_id == run.run {
                    return notice.terminal;
                }
            }
        })
        .await
        .unwrap()
    }
    /// A run of an `unconfirmable` host on a sender binding, cancelled until the engine requires
    /// reconciliation; its notice is consumed here, so no sender sees it.
    async fn unconfirmed(fixture: &mut Fixture, client: &Client) -> (Uuid, Run) {
        let mut terminals = fixture.take_terminals();
        let (binding, thread) = rt::sender(fixture, client, "telegram").await;
        let run = rt::begun(fixture, client, binding, &thread).await;
        agent::initialized(client, &run.run).await;
        cancel_run(fixture, &run).await;
        assert_eq!(
            noticed(&mut terminals, &run).await,
            RunTerminalKind::ReconciliationRequired
        );
        let engine = fixture.engine();
        let conversation = engine
            .assembly
            .application
            .execute(
                engine.resolver.local_context().unwrap(),
                AppCommand::GetThreadConversation {
                    thread_id: run.thread.clone(),
                },
            )
            .await;
        assert!(
            matches!(
                conversation,
                Err(openbot_contracts::error::AppError::DependencyUnavailable { .. })
            ),
            "{conversation:?}"
        );
        (binding, run)
    }
    fn kill_group(row: &serde_json::Value) {
        let pgid = rustix::process::Pid::from_raw(row["pgid"].as_i64().unwrap() as i32).unwrap();
        let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
    }
    async fn event_by_key(client: &Client, key: &str) -> serde_json::Value {
        let limit = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let found = client
                .query(
                    "SELECT row_to_json(e) FROM openmybot.channel_events e WHERE event_key=$1",
                    &[&key],
                )
                .await
                .unwrap();
            if let Some(row) = found.first() {
                return row.get(0);
            }
            assert!(tokio::time::Instant::now() < limit, "event {key} deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn application_names(client: &Client) -> Vec<String> {
        client
            .query(
                "SELECT application_name FROM pg_stat_activity WHERE application_name LIKE 'openmybot-%'",
                &[],
            )
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect()
    }
    const FAIL_ROW: &str = "CREATE FUNCTION openmybot.fail_row() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test failure'; END$$";

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn channels_start_marks_sending_deliveries_unknown_and_sends_nothing() {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        rt::sealed(&fixture, &client).await;
        let binding =
            testkit::insert_sender(&client, "telegram", "1001", "telegram:42", "T1").await;
        let row = testkit::insert_delivery(
            &client,
            binding,
            "control_reply",
            "control_reply:1",
            Some("reply"),
            "sending",
            None,
        )
        .await;
        let timings = outbound_timings();
        let channels = started(&mut fixture, token, timings, plugins, outbound()).await;
        let stored = testkit::read_row(&client, "deliveries", "delivery_id", row).await;
        assert_eq!(stored["status"], "unknown");
        assert_eq!(stored["last_error_code"], "daemon_restart");
        assert!(stored["finished_at"].is_string());
        tokio::time::sleep(timings.delivery_poll * 4).await;
        assert!(logs.sent().is_empty());
        assert_eq!(
            testkit::read_row(&client, "deliveries", "delivery_id", row).await,
            stored
        );
        channels.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn channels_start_backfills_terminal_and_result_row_from_the_replayed_journal() {
        let mut fixture = Fixture::start_with_host(slow).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        // The notices are lost: nobody receives from the engine's queue.
        drop(fixture.take_terminals());
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        // One sender per channel: the host resolves a binding's oldest run without a terminal.
        let (telegram, thread) = rt::sender(&fixture, &client, "telegram").await;
        let done = rt::begun(&fixture, &client, telegram, &thread).await;
        agent::settled(&fixture, &thread).await;
        let (feishu, other) = rt::sender(&fixture, &client, "feishu").await;
        let stopped = rt::begun(&fixture, &client, feishu, &other).await;
        agent::initialized(&client, &stopped.run).await;
        cancel_run(&fixture, &stopped).await;
        agent::settled(&fixture, &other).await;
        for run in [&done, &stopped] {
            assert!(rt::event(&client, &run.run).await["terminal_kind"].is_null());
        }
        let plugins = none(&fixture);
        let channels = started(&mut fixture, token, outbound_timings(), plugins, outbound()).await;
        for (run, kind) in [(&done, "succeeded"), (&stopped, "cancelled")] {
            assert_eq!(rt::event(&client, &run.run).await["terminal_kind"], kind);
            assert_eq!(rt::results(&client, &run.run).await.len(), 1);
        }
        channels.stop().await;
        runtime.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn startup_backfills_reconciliation_required_although_the_conversation_read_is_unavailable()
     {
        let mut fixture = Fixture::start_with_host(agent::unconfirmable).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let mut client = fixture.client().await;
        let (_, run) = unconfirmed(&mut fixture, &client).await;
        assert!(rt::event(&client, &run.run).await["terminal_kind"].is_null());
        reconcile::startup(&mut client, &rt::reconciler(&fixture))
            .await
            .unwrap();
        assert_eq!(
            rt::event(&client, &run.run).await["terminal_kind"],
            "reconciliation_required"
        );
        let rows = rt::results(&client, &run.run).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["status"], "pending");
        kill_group(&agent::session(&client, &run.run).await);
        runtime.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn startup_replay_is_bounded_by_the_replay_deadline() {
        let mut fixture = Fixture::start_with_host(agent::unconfirmable).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let mut client = fixture.client().await;
        let (binding, run) = unconfirmed(&mut fixture, &client).await;
        // Another dispatched run on the same thread whose terminal never enters the journal.
        let ghost = RunId::new(format!("run-{}", Uuid::now_v7()));
        let record = testkit::insert_event_for_run(
            &client,
            binding,
            ghost.as_str(),
            run.thread.as_str(),
            "dispatched",
        )
        .await;
        testkit::shift_event(&client, record, "dispatched_at", 0.0).await;
        let reconciler = Reconciler {
            replay_deadline: Duration::from_millis(300),
            ..rt::reconciler(&fixture)
        };
        let started = tokio::time::Instant::now();
        reconcile::startup(&mut client, &reconciler).await.unwrap();
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(300), "{took:?}");
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert!(rt::event(&client, &ghost).await["terminal_kind"].is_null());
        assert!(rt::results(&client, &ghost).await.is_empty());
        assert_eq!(
            rt::event(&client, &run.run).await["terminal_kind"],
            "reconciliation_required"
        );
        kill_group(&agent::session(&client, &run.run).await);
        runtime.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn engine_notifies_the_terminal_queue_for_a_finished_run() {
        let mut fixture = Fixture::start_with_host(rt::happy).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let mut terminals = fixture.take_terminals();
        let (run, client) = agent::begin(&mut fixture).await;
        assert_eq!(
            noticed(&mut terminals, &run).await,
            RunTerminalKind::Succeeded
        );
        runtime.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn notice_after_the_queue_receiver_is_closed_is_dropped_and_shutdown_is_clean() {
        let mut fixture = Fixture::start_with_host(rt::happy).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        drop(fixture.take_terminals());
        let (run, client) = agent::begin(&mut fixture).await;
        let snapshot = agent::settled(&fixture, &run.thread).await;
        assert_eq!(snapshot.active_run_id, None);
        assert_eq!(
            agent::session(&client, &run.run).await["end_reason"],
            "result_success"
        );
        runtime.stop().await;
        drop(client);
        tokio::time::timeout(Duration::from_secs(60), fixture.stop())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn start_opens_delivery_and_sweeper_connections_and_stop_closes_them_before_the_dispatcher()
     {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        rt::sealed(&fixture, &client).await;
        let channels = started(&mut fixture, token, outbound_timings(), plugins, outbound()).await;
        let six = [
            "openmybot-heartbeat",
            "openmybot-dispatcher",
            "openmybot-status",
            "openmybot-receiver",
            "openmybot-delivery",
            "openmybot-sweeper",
        ];
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let names = application_names(&client).await;
            if six.iter().all(|name| names.iter().any(|seen| seen == name)) {
                break;
            }
            assert!(tokio::time::Instant::now() < limit, "{names:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let stopping = tokio::spawn(channels.stop());
        // The poll at which each connection was first seen gone.
        let mut gone = [None; 3];
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        for poll in 0_usize.. {
            let names = application_names(&client).await;
            for (slot, name) in gone.iter_mut().zip([
                "openmybot-delivery",
                "openmybot-sweeper",
                "openmybot-dispatcher",
            ]) {
                if slot.is_none() && !names.iter().any(|seen| seen == name) {
                    *slot = Some(poll);
                }
            }
            if stopping.is_finished() && !names.iter().any(|seen| six.contains(&seen.as_str())) {
                break;
            }
            assert!(tokio::time::Instant::now() < limit, "{names:?}");
        }
        stopping.await.unwrap();
        let [delivery, sweeper, dispatcher] = gone.map(Option::unwrap);
        assert!(delivery <= dispatcher, "{gone:?}");
        assert!(sweeper <= dispatcher, "{gone:?}");
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn finished_reports_internal_error_when_the_sender_or_the_sweeper_ends() {
        let mut fixture = Fixture::start().await;
        let client = fixture.client().await;
        let binding =
            testkit::insert_sender(&client, "telegram", "1001", "telegram:42", "T1").await;
        client.batch_execute(FAIL_ROW).await.unwrap();
        // The sender fails on its claim update.
        let first = token(&mut fixture).await;
        let plugins = none(&fixture);
        let mut channels =
            started(&mut fixture, first, outbound_timings(), plugins, outbound()).await;
        client.batch_execute("CREATE TRIGGER fail_update BEFORE UPDATE ON openmybot.deliveries FOR EACH ROW EXECUTE FUNCTION openmybot.fail_row()").await.unwrap();
        testkit::insert_delivery(
            &client,
            binding,
            "control_reply",
            "control_reply:1",
            Some("reply"),
            "pending",
            None,
        )
        .await;
        let ended = tokio::time::timeout(Duration::from_secs(10), channels.finished())
            .await
            .unwrap();
        assert_eq!(ended, DaemonError::InternalError);
        channels.stop().await;
        client
            .batch_execute(
                "DROP TRIGGER fail_update ON openmybot.deliveries; DELETE FROM openmybot.deliveries",
            )
            .await
            .unwrap();
        // The sweeper fails on its first deletion.
        let second = token(&mut fixture).await;
        let plugins = none(&fixture);
        let mut channels = started(
            &mut fixture,
            second,
            Timings {
                sweep_interval: Duration::from_millis(150),
                tombstone_retention: Duration::from_secs(20),
                ..outbound_timings()
            },
            plugins,
            outbound(),
        )
        .await;
        client.batch_execute("CREATE TRIGGER fail_delete BEFORE DELETE ON openmybot.channel_events FOR EACH ROW EXECUTE FUNCTION openmybot.fail_row()").await.unwrap();
        let old =
            testkit::insert_event_for_run(&client, binding, "run-old", "T1", "conflict").await;
        testkit::shift_event(&client, old, "accepted_at", -60.0).await;
        let ended = tokio::time::timeout(Duration::from_secs(10), channels.finished())
            .await
            .unwrap();
        assert_eq!(ended, DaemonError::InternalError);
        channels.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn e2e_happy_run_sends_one_result_message_through_the_same_endpoint() {
        let mut fixture = Fixture::start_with_host(rt::happy).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        rt::sealed(&fixture, &client).await;
        let (binding, thread) = rt::sender(&fixture, &client, "telegram").await;
        let terminals = fixture.take_terminals();
        let channels = started(
            &mut fixture,
            token,
            outbound_timings(),
            plugins,
            Outbound {
                terminals,
                crabcode: None,
            },
        )
        .await;
        let run = rt::begun(&fixture, &client, binding, &thread).await;
        rt::messages(&logs, 1).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let sent = logs.sent();
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0]["chat_key"], "telegram:42");
        assert_eq!(
            sent[0]["body"],
            format!(
                "[OpenMyBot] 已完成 · run {}\nhello from fake",
                &run.run.as_str()[..8]
            )
        );
        // The process that sent is the one receiving with the bound credential.
        assert_eq!(logs.received_of("hello").len(), 1);
        starts_with(&logs, rt::TOKEN).await;
        let rows = rt::results(&client, &run.run).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["status"], "sent");
        assert_eq!(
            rt::event(&client, &run.run).await["terminal_kind"],
            "succeeded"
        );
        channels.stop().await;
        runtime.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn e2e_permission_run_sends_notice_then_result_with_artifacts_after_cli_approve() {
        let mut fixture = Fixture::start_with_host(rt::asking).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        rt::sealed(&fixture, &client).await;
        let (binding, thread) = rt::sender(&fixture, &client, "telegram").await;
        let terminals = fixture.take_terminals();
        let channels = started(
            &mut fixture,
            token,
            outbound_timings(),
            plugins,
            Outbound {
                terminals,
                crabcode: None,
            },
        )
        .await;
        let run = rt::begun(&fixture, &client, binding, &thread).await;
        let id = rt::permission_of(&client, &run.run).await;
        let notice = rt::messages(&logs, 1).await;
        assert!(notice[0].contains(&id), "{notice:?}");
        assert_eq!(
            testkit::decide(&client, &id, omb_store::Decision::Allow).await,
            omb_store::Decided::Decided
        );
        let sent = rt::messages(&logs, 2).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(logs.sent().len(), 2);
        let result = &sent[1];
        assert!(
            result.starts_with(&format!(
                "[OpenMyBot] 已完成 · run {}",
                &run.run.as_str()[..8]
            )),
            "{result}"
        );
        let (_, artifacts) = result.split_once("\n成果：").unwrap();
        assert_eq!(artifacts, "approved.txt");
        assert!(!result.contains(fixture.root.to_str().unwrap()), "{result}");
        channels.stop().await;
        runtime.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn e2e_expired_permission_notice_is_sent_and_late_approve_is_not_pending() {
        let mut fixture = Fixture::start_with_host(rt::asking).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        rt::sealed(&fixture, &client).await;
        let (binding, thread) = rt::sender(&fixture, &client, "telegram").await;
        let run = rt::begun(&fixture, &client, binding, &thread).await;
        let id = rt::permission_of(&client, &run.run).await;
        let body: String = client
            .query_one(
                "SELECT body FROM openmybot.deliveries WHERE kind='permission_notice' AND idempotency_key LIKE '%'||$1",
                &[&id],
            )
            .await
            .unwrap()
            .get(0);
        // The owner never answers; the daemon starts and stops the run's permission.
        let terminals = fixture.take_terminals();
        let channels = started(
            &mut fixture,
            token,
            outbound_timings(),
            plugins,
            Outbound {
                terminals,
                crabcode: None,
            },
        )
        .await;
        assert_eq!(
            testkit::permission_row_json(&client, &id).await["decided_via"],
            "run_stopped"
        );
        let sent = rt::messages(&logs, 1).await;
        assert_eq!(sent[0], body);
        assert_eq!(
            testkit::decide(&client, &id, omb_store::Decision::Allow).await,
            omb_store::Decided::NotPending
        );
        agent::settled(&fixture, &thread).await;
        channels.stop().await;
        runtime.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn e2e_unconfirmable_stop_writes_reconciliation_required_and_keeps_later_events_pending()
    {
        let mut fixture = Fixture::start_with_host(agent::unconfirmable).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        rt::sealed(&fixture, &client).await;
        let (binding, thread) = rt::sender(&fixture, &client, "telegram").await;
        let terminals = fixture.take_terminals();
        let channels = started(
            &mut fixture,
            token,
            outbound_timings(),
            plugins,
            Outbound {
                terminals,
                crabcode: None,
            },
        )
        .await;
        let run = rt::begun(&fixture, &client, binding, &thread).await;
        agent::initialized(&client, &run.run).await;
        cancel_run(&fixture, &run).await;
        let sent = rt::messages(&logs, 1).await;
        assert!(
            sent[0].starts_with(&format!(
                "[OpenMyBot] 结果未知，在本机执行 openmybot status --run {} 核对 · run {}",
                run.run.as_str(),
                &run.run.as_str()[..8]
            )),
            "{sent:?}"
        );
        assert_eq!(
            rt::event(&client, &run.run).await["terminal_kind"],
            "reconciliation_required"
        );
        // A later message of the same sender stays pending on the paused thread.
        logs.push(&message("telegram", "2", "after the unknown stop"));
        let later = event_by_key(&client, "2").await;
        assert_eq!(later["thread_id"], thread.as_str());
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(
            event_by_key(&client, "2").await["dispatch_status"],
            "pending"
        );
        // Moved to a fresh thread by the control operation, it is dispatched without a further
        // inbound message.
        let control = fixture
            .pg
            .open_resident_connection("openmybot-control")
            .await
            .unwrap();
        let canceller_connection = fixture
            .pg
            .open_resident_connection("openmybot-canceller")
            .await
            .unwrap();
        let engine = fixture.engine();
        let ops = Ops {
            control: tokio::sync::Mutex::new(control.client),
            application: engine.assembly.application.clone(),
            resolver: engine.resolver.clone(),
            vault: engine.vault.clone(),
            owner: ActorId::new(SINGLE_USER_ACTOR_ID),
            roots: WorkspaceRoots::parse(
                &fixture.root.join("home"),
                &[fixture.root.join("home/ws")],
            )
            .unwrap(),
            plugins: none(&fixture),
            receiver: mpsc::channel(8).0,
            wake: channels.wake(),
            minter: crate::ops::ThreadMinter::new(
                engine.assembly.application.clone(),
                engine.resolver.clone(),
            ),
            canceller: crate::ops::BindingRunCanceller::new(
                engine.assembly.application.clone(),
                engine.resolver.clone(),
                Arc::new(canceller_connection.client),
                Arc::default(),
            ),
            counters: Arc::new(Counters::default()),
        };
        ops.run(
            Op::BindingsResetThread,
            serde_json::json!({"binding_id": binding.to_string(), "ack_unknown": run.run.as_str()}),
            deadline(),
            token,
        )
        .await
        .unwrap();
        let fresh: String = client
            .query_one(
                "SELECT thread_id FROM openmybot.channel_bindings WHERE binding_id=$1",
                &[&binding],
            )
            .await
            .unwrap()
            .get(0);
        assert_ne!(fresh, thread.as_str());
        let limit = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let moved = event_by_key(&client, "2").await;
            if moved["dispatch_status"] == "dispatched" {
                assert_eq!(moved["thread_id"], fresh.as_str());
                break;
            }
            assert!(tokio::time::Instant::now() < limit, "{moved}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let sessions = client
            .query(
                "SELECT row_to_json(h) FROM openmybot.host_driver_sessions h WHERE record_kind='session' AND pgid IS NOT NULL",
                &[],
            )
            .await
            .unwrap();
        for row in sessions {
            kill_group(&row.get(0));
        }
        drop(ops);
        channels.stop().await;
        runtime.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn duplicate_update_wakes_the_dispatcher_for_an_event_whose_wake_was_lost() {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let mut client = fixture.client().await;
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        let receiver = rt::sealed(&fixture, &client).await;
        rt::sender(&fixture, &client, "telegram").await;
        let channels = started(&mut fixture, token, quick(), plugins, outbound()).await;
        let limit = tokio::time::Instant::now() + Duration::from_secs(30);
        while !client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name='openmybot-dispatcher' AND state='idle' AND query LIKE 'SELECT e.record_id,%')",
                &[],
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        {
            assert!(tokio::time::Instant::now() < limit, "dispatcher idle deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Written without a wake-up by a commit that takes a second; meanwhile the platform
        // delivers the update again and the receiver finds it a duplicate.
        client.batch_execute("CREATE FUNCTION openmybot.fixture_commit_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NULL; END $$; CREATE CONSTRAINT TRIGGER fixture_commit_delay AFTER INSERT ON openmybot.channel_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openmybot.fixture_commit_delay()").await.unwrap();
        let watcher = fixture.client().await;
        let incoming = message("telegram", "7", "work");
        let event = normalize(
            &TELEGRAM,
            "1001",
            serde_json::from_value(incoming.clone()).unwrap(),
        )
        .unwrap();
        let (accepted, ()) = tokio::join!(
            accept_event(
                &mut client,
                receiver,
                &event,
                &OMB_REPLY_TEXTS_V1,
                deadline()
            ),
            async {
                let limit = tokio::time::Instant::now() + Duration::from_secs(30);
                while !watcher
                    .query_one(
                        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE wait_event='PgSleep')",
                        &[],
                    )
                    .await
                    .unwrap()
                    .get::<_, bool>(0)
                {
                    assert!(tokio::time::Instant::now() < limit, "commit deadline");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                logs.push(&incoming);
            }
        );
        assert_eq!(
            accepted.unwrap(),
            AcceptOutcome::Recorded(Disposition::AcceptedMessage)
        );
        let limit = tokio::time::Instant::now() + Duration::from_secs(30);
        while event_by_key(&client, "7").await["dispatch_status"] != "dispatched" {
            assert!(tokio::time::Instant::now() < limit, "dispatch deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let counters = channels.status_source().counters;
        assert_eq!(counters.event_conflict.load(Ordering::Relaxed), 0);
        channels.stop().await;
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn e2e_pairing_reply_and_control_reply_are_sent_to_the_chat() {
        let mut fixture = Fixture::start_with_bot().await;
        let token = token(&mut fixture).await;
        let (mut client, _) = paired(&mut fixture).await;
        let receiver: Uuid = client
            .query_one(
                "SELECT binding_id FROM openmybot.channel_bindings WHERE binding_kind='receiver'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        resealed(&fixture, &client, receiver, rt::TOKEN).await;
        let now = client
            .query_one("SELECT statement_timestamp()", &[])
            .await
            .unwrap()
            .get(0);
        let status = NormalizedEvent {
            channel: TELEGRAM,
            source_key: "1001".into(),
            event_key: "20".into(),
            event_type: "telegram.message".into(),
            occurred_at: Some(now),
            private: true,
            sender: IdentityKey::parse("telegram:42"),
            chat: IdentityKey::parse("telegram:42"),
            fingerprint: Some([20; 32]),
            content: Content::Text {
                text: "/status".into(),
                command: Some(Command::Status),
                pair_code: None,
            },
        };
        assert_eq!(
            accept_event(
                &mut client,
                receiver,
                &status,
                &OMB_REPLY_TEXTS_V1,
                deadline()
            )
            .await
            .unwrap(),
            AcceptOutcome::Recorded(Disposition::ControlCommand)
        );
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "telegram", &logs, "normal");
        let channels = started(&mut fixture, token, outbound_timings(), plugins, outbound()).await;
        let limit = tokio::time::Instant::now() + Duration::from_secs(30);
        let rows = loop {
            let rows: Vec<(String, String, String)> = client
                .query(
                    "SELECT kind,body,status FROM openmybot.deliveries WHERE kind IN ('pairing_reply','control_reply') ORDER BY created_at",
                    &[],
                )
                .await
                .unwrap()
                .into_iter()
                .map(|row| (row.get(0), row.get(1), row.get(2)))
                .collect();
            if rows.len() == 2 && rows.iter().all(|(_, _, status)| status == "sent") {
                break rows;
            }
            assert!(tokio::time::Instant::now() < limit, "{rows:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(rows[0].0, "pairing_reply");
        assert_eq!(rows[1].0, "control_reply");
        let sent = logs.sent();
        for (_, body, _) in &rows {
            let message = sent
                .iter()
                .find(|sent| sent["body"] == body.as_str())
                .unwrap();
            assert_eq!(message["chat_key"], "telegram:42");
        }
        channels.stop().await;
        drop(client);
        fixture.stop().await;
    }

    // ---- One plugin process per channel ----------------------------------------------------

    /// A Feishu receiver row of `binding_id` whose envelope seals the app secret for the owner.
    fn feishu_row(fixture: &Fixture, binding_id: Uuid) -> ReceiverRow {
        let credential_envelope = fixture
            .engine()
            .vault
            .seal(
                &binding_id,
                SecretKind::Connector,
                SecretPrincipal::Actor(ActorId::new(SINGLE_USER_ACTOR_ID)),
                SecretPrincipal::Service(crate::ops::service(&FEISHU)),
                &SecretBytes::new(b"feishu-secret".to_vec()),
            )
            .unwrap();
        ReceiverRow {
            binding_id,
            channel: FEISHU,
            source_key: "cli_a".into(),
            credential_envelope,
        }
    }
    /// An active Feishu receiver row with a sealed app secret.
    async fn sealed_feishu(fixture: &Fixture, client: &Client) -> ReceiverRow {
        let row = feishu_row(fixture, fixture::receiver(client, "feishu").await);
        client
            .execute(
                "UPDATE openmybot.channel_bindings SET source_key=$2,credential_envelope=$3 WHERE binding_id=$1",
                &[&row.binding_id, &row.source_key, &row.credential_envelope],
            )
            .await
            .unwrap();
        row
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn start_runs_one_receiver_per_channel_and_status_notes_follow_the_channel() {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let (telegram, feishu) = (Logs::new(), Logs::new());
        let plugins = both(&fixture, &telegram, &feishu, "normal");
        sealed_receiver(&fixture, &client, "1001:both-token").await;
        sealed_feishu(&fixture, &client).await;
        let channels = started(&mut fixture, token, quick(), plugins, outbound()).await;
        starts_with(&telegram, "1001:both-token").await;
        starts_with(&feishu, "feishu-secret").await;
        receivers_reach(&client, 2).await;
        let statuses = channels.status_source().read().await.unwrap();
        let notes: Vec<(&str, &str)> = statuses
            .iter()
            .map(|status| (status.channel.as_str(), status.note.as_str()))
            .collect();
        assert_eq!(
            notes,
            [
                ("feishu", "feishu fake note"),
                ("telegram", "telegram fake note")
            ]
        );
        channels.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn start_receiver_replaces_only_the_slot_of_its_channel() {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let (telegram_logs, feishu) = (Logs::new(), Logs::new());
        let plugins = both(&fixture, &telegram_logs, &feishu, "normal");
        let telegram = sealed_receiver(&fixture, &client, "1001:slot-token").await;
        sealed_feishu(&fixture, &client).await;
        let mut channels = started(&mut fixture, token, quick(), plugins, outbound()).await;
        starts_with(&telegram_logs, "1001:slot-token").await;
        starts_with(&feishu, "feishu-secret").await;
        receivers_reach(&client, 2).await;
        let replacement = feishu_row(&fixture, Uuid::now_v7());
        let (done, _) = oneshot::channel();
        channels
            .start_receiver(&mut fixture.pg, replacement, done)
            .await;
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while feishu.received_of("start").len() < 2 {
            assert!(
                tokio::time::Instant::now() < limit,
                "no second Feishu start"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        receivers_reach(&client, 2).await;
        assert!(telegram_logs.received_of("stop").is_empty());
        let (done, stopped) = oneshot::channel();
        channels.stop_receiver(telegram.binding_id, done).await;
        stopped.await.unwrap();
        receivers_reach(&client, 1).await;
        assert_eq!(telegram_logs.received_of("stop").len(), 1);
        assert!(feishu.received_of("stop").is_empty());
        let (done, stopped) = oneshot::channel();
        channels.stop_receiver(Uuid::now_v7(), done).await;
        stopped.await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(receivers(&client).await, 1);
        // The replaced Feishu process ended through the stop ladder and a new one started.
        assert!(feishu.received_of("stop").is_empty());
        assert_eq!(feishu.received_of("hello").len(), 2);
        channels.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn suspended_feishu_receiver_is_removed_and_finished_keeps_waiting() {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let (telegram, feishu) = (Logs::new(), Logs::new());
        let plugins = both(&fixture, &telegram, &feishu, "suspend:credential_rejected");
        sealed_receiver(&fixture, &client, "1001:kept-token").await;
        let row = sealed_feishu(&fixture, &client).await;
        let mut channels = started(&mut fixture, token, quick(), plugins, outbound()).await;
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while binding_state(&client, row.binding_id).await.0 != "suspended" {
            assert!(
                tokio::time::Instant::now() < limit,
                "receiver did not suspend"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            binding_state(&client, row.binding_id).await.1.as_deref(),
            Some("credential_rejected")
        );
        starts_with(&telegram, "1001:kept-token").await;
        assert!(
            tokio::time::timeout(Duration::from_secs(2), channels.finished())
                .await
                .is_err()
        );
        receivers_reach(&client, 1).await;
        assert!(telegram.received_of("stop").is_empty());
        assert_eq!(feishu.received_of("hello").len(), 1);
        channels.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn stop_ends_both_receiver_connections_before_the_delivery_connection() {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let (telegram, feishu) = (Logs::new(), Logs::new());
        let plugins = both(&fixture, &telegram, &feishu, "normal");
        sealed_receiver(&fixture, &client, "1001:stop-token").await;
        sealed_feishu(&fixture, &client).await;
        let channels = started(
            &mut fixture,
            token,
            outbound_timings(),
            plugins.clone(),
            outbound(),
        )
        .await;
        starts_with(&telegram, "1001:stop-token").await;
        starts_with(&feishu, "feishu-secret").await;
        receivers_reach(&client, 2).await;
        let stopping = tokio::spawn(channels.stop());
        // The poll at which the receivers' and the delivery connection were first seen gone.
        let mut gone = [None; 2];
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        for poll in 0_usize.. {
            let names = application_names(&client).await;
            for (slot, name) in gone
                .iter_mut()
                .zip(["openmybot-receiver", "openmybot-delivery"])
            {
                if slot.is_none() && !names.iter().any(|seen| seen == name) {
                    *slot = Some(poll);
                }
            }
            if stopping.is_finished() && gone.iter().all(Option::is_some) {
                break;
            }
            assert!(tokio::time::Instant::now() < limit, "{names:?}");
        }
        stopping.await.unwrap();
        let [receivers, delivery] = gone.map(Option::unwrap);
        assert!(receivers <= delivery, "{gone:?}");
        // Both processes went through the stop ladder.
        for plugin in plugins.list() {
            assert_eq!(plugins.process(&plugin).0, crate::ProcessState::Stopped);
        }
        drop(client);
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn daemon_start_writes_daemon_down_gap_for_the_feishu_receiver() {
        let mut fixture = Fixture::start().await;
        let first = token(&mut fixture).await;
        let client = fixture.client().await;
        client.execute("UPDATE openmybot.control_tokens SET last_heartbeat_at=statement_timestamp()-interval '10 minutes' WHERE token_id=$1", &[&first]).await.unwrap();
        let receiver = fixture::receiver(&client, "feishu").await;
        let second = token(&mut fixture).await;
        let plugins = none(&fixture);
        let channels = started(&mut fixture, second, quick(), plugins, outbound()).await;
        let rows = client.query("SELECT binding_id,gap_started_at=(SELECT last_heartbeat_at FROM openmybot.control_tokens WHERE token_id=$1),gap_ended_at>=(SELECT created_at FROM openmybot.control_tokens WHERE token_id=$2) FROM openmybot.channel_events WHERE gap_reason='daemon_down'", &[&first, &second]).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<_, Uuid>(0), receiver);
        assert!(rows[0].get::<_, bool>(1));
        assert!(rows[0].get::<_, bool>(2));
        channels.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn feishu_disconnect_gap_and_lost_note_show_in_the_status_segment() {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let logs = Logs::new();
        // The plugin reports a broken stream and closes the gap a second later.
        let plugins = installed(&fixture.root, "feishu", &logs, "gap_then_closed");
        let row = sealed_feishu(&fixture, &client).await;
        let channels = started(&mut fixture, token, quick(), plugins, outbound()).await;
        let source = channels.status_source();
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        let entry = loop {
            let entry = source.read().await.unwrap().remove(0);
            if !entry.gaps.is_empty() {
                break entry;
            }
            assert!(tokio::time::Instant::now() < limit, "no gap");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(entry.binding_id, row.binding_id.to_string());
        assert_eq!(entry.gaps[0].reason, "stream_broken");
        assert_eq!(entry.gaps[0].ended_at, None);
        assert_eq!(entry.note, "feishu fake note");
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while source.read().await.unwrap()[0].gaps[0].ended_at.is_none() {
            assert!(tokio::time::Instant::now() < limit, "gap still open");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let events: i64 = client
            .query_one(
                "SELECT count(*) FROM openmybot.channel_events WHERE record_kind='event'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(events, 0);
        channels.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn e2e_feishu_pairing_reply_and_control_reply_are_sent_to_the_chat() {
        let mut fixture = Fixture::start_with_bot().await;
        let token = token(&mut fixture).await;
        let mut client = fixture.client().await;
        sealed_feishu(&fixture, &client).await;
        let engine = fixture.engine();
        let AppReply::ThreadMinted(minted) = engine
            .assembly
            .application
            .execute(
                engine.resolver.local_context().unwrap(),
                AppCommand::MintThreadId,
            )
            .await
            .unwrap()
        else {
            panic!("mint reply");
        };
        let generation = engine
            .resolver
            .local_context()
            .unwrap()
            .auth_generation()
            .get();
        let started_pair = pair_start(
            &mut client,
            PairStart {
                channel: FEISHU,
                workspace_dir: "/workspaces/project",
                thread_id: minted.thread_id.as_str(),
                granted_generation: generation,
                run_deadline: None,
            },
            deadline(),
        )
        .await
        .unwrap();
        let logs = Logs::new();
        let plugins = installed(&fixture.root, "feishu", &logs, "normal");
        let channels = started(&mut fixture, token, outbound_timings(), plugins, outbound()).await;
        starts_with(&logs, "feishu-secret").await;
        let code = started_pair.code.display();
        logs.push(&message("feishu", "ev_pair", &format!("/pair {code}")));
        let limit = tokio::time::Instant::now() + Duration::from_secs(30);
        while logs.sent().is_empty() {
            assert!(tokio::time::Instant::now() < limit, "no pairing reply");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let sender = testkit::read_row(
            &client,
            "channel_bindings",
            "binding_id",
            started_pair.binding_id,
        )
        .await;
        assert_eq!(
            [&sender["status"], &sender["chat_key"]],
            ["active", "feishu:42"]
        );
        logs.push(&message("feishu", "ev_status", "/status"));
        let limit = tokio::time::Instant::now() + Duration::from_secs(30);
        let rows = loop {
            let rows: Vec<(String, String, String)> = client
                .query(
                    "SELECT kind,body,status FROM openmybot.deliveries WHERE kind IN ('pairing_reply','control_reply') ORDER BY created_at",
                    &[],
                )
                .await
                .unwrap()
                .into_iter()
                .map(|row| (row.get(0), row.get(1), row.get(2)))
                .collect();
            if rows.len() == 2 && rows.iter().all(|(_, _, status)| status == "sent") {
                break rows;
            }
            assert!(tokio::time::Instant::now() < limit, "{rows:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(rows[0].0, "pairing_reply");
        assert_eq!(rows[1].0, "control_reply");
        let sent = logs.sent();
        for (_, body, _) in &rows {
            let message = sent
                .iter()
                .find(|sent| sent["body"] == body.as_str())
                .unwrap();
            assert_eq!(message["chat_key"], "feishu:42");
        }
        let accepted: Vec<Value> = logs
            .received_of("accepted")
            .into_iter()
            .map(|frame| frame["event_key"].clone())
            .collect();
        assert_eq!(accepted, ["ev_pair", "ev_status"]);
        channels.stop().await;
        drop(client);
        fixture.stop().await;
    }
}
