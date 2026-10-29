//! Daemon wiring of the channel receivers, the dispatcher, the heartbeat and the status segment.
use crate::reconcile::{self, REPLAY_DEADLINE, Reconciler};
use crate::{
    ChannelCounters, ChannelStatus, DaemonError, GapStatus,
    engine::Engine,
    pg::{AuthorityConnection, Postgres, map_store_error},
};
use omb_channels::{
    CHANNEL_NOTE, CancelRequests, Connection, Counters, ReceiverContext, Task, TelegramEndpoint,
    Timings, start_dispatcher, start_heartbeat, start_receiver,
};
use omb_channels::{SenderContext, start_sender};
use omb_hostdriver::{CC_KILL_GRACE, CC_TERM_GRACE};
use omb_store::{Channel, ReceiverRow};
use openbot_application::RunTerminalNotice;
use openbot_contracts::ids::ActorId;
use openbot_infra::auth::single_user::SINGLE_USER_ACTOR_ID;
use std::{
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
};
use tokio::{
    sync::{Notify, mpsc},
    task::JoinHandle,
};
use uuid::Uuid;

/// Read side of the status channel segment: its own connection plus the receivers' counters.
pub(crate) struct StatusSource {
    pub(crate) client: Arc<tokio_postgres::Client>,
    pub(crate) counters: Arc<Counters>,
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
                    channel: match receiver.channel {
                        Channel::Telegram => "telegram",
                        Channel::Feishu => "feishu",
                    }
                    .to_owned(),
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
                    note: CHANNEL_NOTE.to_owned(),
                    counters: counters.clone(),
                })
            })
            .collect()
    }
}

/// What the outbound side starts from: the engine's terminal notices and the configured host
/// binary that startup reconciliation compares orphan process-group leaders with.
pub(crate) struct Outbound {
    pub(crate) terminals: mpsc::Receiver<RunTerminalNotice>,
    pub(crate) crabcode: Option<PathBuf>,
}

/// The running receiver with its binding, the dispatcher and heartbeat, the context every
/// receiver starts with, the status connection, the outbound sender and the sweeper.
pub(crate) struct Channels {
    receiver: Option<(Uuid, Task)>,
    context: ReceiverContext,
    dispatcher: Task,
    heartbeat: Task,
    status: Arc<tokio_postgres::Client>,
    status_driver: JoinHandle<Result<(), tokio_postgres::Error>>,
    sender: Task,
    sweeper: Task,
}
impl Channels {
    /// Records startup gaps, reconciles the store, then starts the heartbeat, the dispatcher, each
    /// active receiver, the outbound sender and the sweeper, every one on its own connection.
    pub(crate) async fn start(
        postgres: &mut Postgres,
        engine: &Engine,
        token_id: Uuid,
        timings: Timings,
        endpoint: TelegramEndpoint,
        cancel: CancelRequests,
        outbound: Outbound,
    ) -> Result<Self, DaemonError> {
        postgres.record_startup_gaps(token_id).await?;
        let receivers = postgres.list_active_receivers(Channel::Telegram).await?;
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
        // The live-binding index allows one receiver per channel.
        let receiver = match receivers.into_iter().next() {
            Some(row) => Some((
                row,
                connection(
                    postgres
                        .open_resident_connection("openmybot-receiver")
                        .await?,
                ),
            )),
            None => None,
        };
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
        let context = ReceiverContext {
            vault: engine.vault.clone(),
            owner: ActorId::new(SINGLE_USER_ACTOR_ID),
            endpoint,
            timings,
            counters: Arc::new(Counters::default()),
            wake: Arc::clone(&wake),
            cancel,
        };
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
        let sender = SenderContext {
            vault: engine.vault.clone(),
            owner: ActorId::new(SINGLE_USER_ACTOR_ID),
            endpoint: context.endpoint.clone(),
            timings,
            wake: Arc::clone(&wake),
        };
        Ok(Self {
            heartbeat: start_heartbeat(heartbeat, token_id, timings),
            dispatcher: start_dispatcher(dispatcher, entry, timings, wake),
            receiver: receiver.map(|(row, opened)| {
                (row.binding_id, start_receiver(opened, row, context.clone()))
            }),
            sender: start_sender(delivery, sender, outbound.terminals),
            sweeper: reconcile::start_sweeper(sweeper, reconciler, timings),
            context,
            status: Arc::new(status.client),
            status_driver: status.driver,
        })
    }
    pub(crate) fn status_source(&self) -> StatusSource {
        StatusSource {
            client: Arc::clone(&self.status),
            counters: Arc::clone(&self.context.counters),
        }
    }
    /// The dispatcher's wake-up, shared with the receiver, the sender and the reconciler.
    pub(crate) fn wake(&self) -> Arc<Notify> {
        Arc::clone(&self.context.wake)
    }
    /// Stops the running receiver, then starts `row` on a new resident connection.
    pub(crate) async fn start_receiver(
        &mut self,
        postgres: &mut Postgres,
        row: ReceiverRow,
    ) -> Result<(), DaemonError> {
        if let Some((_, task)) = self.receiver.take() {
            task.stop().await;
        }
        let opened = postgres
            .open_resident_connection("openmybot-receiver")
            .await?;
        let connection = Connection {
            client: opened.client,
            driver: opened.driver,
        };
        self.receiver = Some((
            row.binding_id,
            start_receiver(connection, row, self.context.clone()),
        ));
        Ok(())
    }
    /// Stops the running receiver only when it serves `binding_id`.
    pub(crate) async fn stop_receiver(&mut self, binding_id: Uuid) {
        if self
            .receiver
            .as_ref()
            .is_some_and(|(running, _)| *running == binding_id)
            && let Some((_, task)) = self.receiver.take()
        {
            task.stop().await;
        }
    }
    /// Resolves with `internal_error` when the heartbeat, the dispatcher, the sender or the
    /// sweeper ends, or a receiver fails; a receiver that stopped itself after suspension or
    /// deactivation is only removed.
    pub(crate) async fn finished(&mut self) -> DaemonError {
        let Self {
            receiver,
            dispatcher,
            heartbeat,
            sender,
            sweeper,
            ..
        } = self;
        loop {
            let ended = tokio::select! {
                _ = heartbeat.finished() => return DaemonError::InternalError,
                _ = dispatcher.finished() => return DaemonError::InternalError,
                _ = sender.finished() => return DaemonError::InternalError,
                _ = sweeper.finished() => return DaemonError::InternalError,
                ended = async {
                    match receiver.as_mut() {
                        Some((_, task)) => task.finished().await,
                        None => std::future::pending().await,
                    }
                } => ended,
            };
            if ended.is_err() {
                return DaemonError::InternalError;
            }
            *receiver = None;
        }
    }
    /// Stops the receiver, the sender, the sweeper, the dispatcher and the heartbeat in that
    /// order, then ends the status connection that request handlers may still share.
    pub(crate) async fn stop(self) {
        if let Some((_, receiver)) = self.receiver {
            receiver.stop().await;
        }
        self.sender.stop().await;
        self.sweeper.stop().await;
        self.dispatcher.stop().await;
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
        StatusSnapshot,
        delegation::fixture::{self, Fixture},
    };
    use crate::{
        agent::{
            AgentRuntime,
            tests::{self as agent, Run},
        },
        reconcile::tests as rt,
    };
    use omb_channels::OMB_REPLY_TEXTS_V1;
    use omb_channels::{CANCEL_QUEUE, TERMINAL_QUEUE, testkit::FakeTelegram};
    use omb_hostdriver::WorkspaceRoots;
    use omb_store::testkit;
    use omb_store::{
        AcceptOutcome, Command, Content, Disposition, IdentityKey, NormalizedEvent, PairStart,
        PollGapReason, accept_event, open_poll_gap, pair_start,
    };
    use openbot_application::RunTerminalKind;
    use openbot_application::{BeginDelegatedThreadRun, DelegatedUntrustedMaterial};
    use openbot_contracts::command::CancelThreadRun;
    use openbot_contracts::{
        auth::DelegationSource,
        command::{AppCommand, AppReply},
        ids::{BotId, RunId, ThreadId},
    };
    use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
    use openbot_infra::net::safe_http::{CidrAllowlist, EgressPolicy, SafeDialer, SchemePolicy};
    use std::time::Duration;
    use tokio_postgres::Client;

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
                channel: Channel::Telegram,
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
            channel: Channel::Telegram,
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
    fn refused_endpoint() -> TelegramEndpoint {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        TelegramEndpoint {
            api_base: url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
            dialer: SafeDialer::new(EgressPolicy::new(
                CidrAllowlist::parse_exact(["127.0.0.1/32"]).unwrap(),
            )),
            scheme: SchemePolicy::HttpOrHttps,
        }
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
        let (source, driver) = status_source(&mut fixture).await;
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
        assert!(serde_json::from_value::<StatusSnapshot>(value.clone()).is_ok());
        let mut extra = value.clone();
        extra["channels"][0]["unknown"] = serde_json::json!(1);
        assert!(serde_json::from_value::<StatusSnapshot>(extra).is_err());
        let mut extra = value;
        extra["channels"][0]["gaps"][0]["unknown"] = serde_json::json!(1);
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
        let (source, driver) = status_source(&mut fixture).await;
        let channels = source.read().await.unwrap();
        assert_eq!(channels[0].note, "telegram 长轮询");
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
        assert_eq!(ended, Err(omb_channels::ChannelError::StoreFailed));
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
        let engine = fixture.engine.as_ref().unwrap();
        let channels = Channels::start(
            &mut fixture.pg,
            engine,
            second,
            quick(),
            refused_endpoint(),
            cancel(),
            outbound(),
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
                SecretPrincipal::Service(ServiceId::new("openmybot.telegram")),
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
        let engine = fixture.engine.as_ref().unwrap();
        let channels = Channels::start(
            &mut fixture.pg,
            engine,
            token,
            quick(),
            refused_endpoint(),
            cancel(),
            outbound(),
        )
        .await
        .unwrap();
        let live = "SELECT count(*) FROM pg_stat_activity WHERE application_name IN ('openmybot-heartbeat','openmybot-dispatcher','openmybot-status','openmybot-receiver')";
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while client.query_one(live, &[]).await.unwrap().get::<_, i64>(0) < 4 {
            assert!(tokio::time::Instant::now() < limit, "connections deadline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while client
            .query_one(
                "SELECT count(*) FROM openmybot.channel_events WHERE gap_reason='connect_failed'",
                &[],
            )
            .await
            .unwrap()
            .get::<_, i64>(0)
            < 1
        {
            assert!(
                tokio::time::Instant::now() < limit,
                "receiver poll deadline"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::timeout(Duration::from_secs(10), channels.stop())
            .await
            .unwrap();
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
                SecretPrincipal::Service(ServiceId::new("openmybot.telegram")),
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
    async fn polls_with(fake: &FakeTelegram, token: &str) -> usize {
        let path = format!("/bot{token}/getUpdates");
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let seen = fake
                .calls("getUpdates")
                .iter()
                .filter(|request| request.path == path)
                .count();
            if seen > 0 {
                return seen;
            }
            assert!(tokio::time::Instant::now() < limit, "no poll with {token}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn runtime_receiver_start_and_stop_through_commands_with_fake_telegram() {
        let mut fixture = Fixture::start().await;
        let token = token(&mut fixture).await;
        let client = fixture.client().await;
        let fake = FakeTelegram::start().await;
        let engine = fixture.engine.as_ref().unwrap();
        let mut channels = Channels::start(
            &mut fixture.pg,
            engine,
            token,
            quick(),
            fake.endpoint(),
            cancel(),
            outbound(),
        )
        .await
        .unwrap();
        assert_eq!(receivers(&client).await, 0);
        let row = sealed_receiver(&fixture, &client, "1001:runtime-token").await;
        let binding = row.binding_id;
        channels.start_receiver(&mut fixture.pg, row).await.unwrap();
        polls_with(&fake, "1001:runtime-token").await;
        receivers_reach(&client, 1).await;
        channels.stop_receiver(binding).await;
        let seen = fake.requests().len();
        receivers_reach(&client, 0).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(fake.requests().len(), seen);
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
        let fake = FakeTelegram::start().await;
        let engine = fixture.engine.as_ref().unwrap();
        let mut channels = Channels::start(
            &mut fixture.pg,
            engine,
            token,
            quick(),
            fake.endpoint(),
            cancel(),
            outbound(),
        )
        .await
        .unwrap();
        let first = sealed_receiver(&fixture, &client, "1001:token-a").await;
        let binding = first.binding_id;
        channels
            .start_receiver(&mut fixture.pg, first)
            .await
            .unwrap();
        let before = polls_with(&fake, "1001:token-a").await;
        channels.stop_receiver(Uuid::now_v7()).await;
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while polls_with(&fake, "1001:token-a").await <= before {
            assert!(tokio::time::Instant::now() < limit, "receiver stopped");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let envelope = resealed(&fixture, &client, binding, "1001:token-b").await;
        let second = ReceiverRow {
            binding_id: binding,
            source_key: "1001".into(),
            credential_envelope: envelope.clone(),
        };
        channels
            .start_receiver(&mut fixture.pg, second)
            .await
            .unwrap();
        polls_with(&fake, "1001:token-b").await;
        let requests = fake.calls("getUpdates");
        let last_old = requests
            .iter()
            .filter(|r| r.path.contains("token-a"))
            .map(|r| r.at)
            .max()
            .unwrap();
        let first_new = requests
            .iter()
            .filter(|r| r.path.contains("token-b"))
            .map(|r| r.at)
            .min()
            .unwrap();
        assert!(last_old < first_new);
        receivers_reach(&client, 1).await;
        // A receiver that suspended itself can be started again.
        fake.script(
            "getUpdates",
            401,
            br#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#.to_vec(),
        );
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while binding_state(&client, binding).await.0 != "suspended" {
            assert!(
                tokio::time::Instant::now() < limit,
                "receiver did not suspend"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        client.execute("UPDATE openmybot.channel_bindings SET status='active',status_reason=NULL WHERE binding_id=$1", &[&binding]).await.unwrap();
        let seen = fake.calls("getUpdates").len();
        let third = ReceiverRow {
            binding_id: binding,
            source_key: "1001".into(),
            credential_envelope: envelope,
        };
        channels
            .start_receiver(&mut fixture.pg, third)
            .await
            .unwrap();
        let limit = tokio::time::Instant::now() + Duration::from_secs(10);
        while fake.calls("getUpdates").len() <= seen {
            assert!(
                tokio::time::Instant::now() < limit,
                "restarted receiver did not poll"
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
        endpoint: TelegramEndpoint,
        outbound: Outbound,
    ) -> Channels {
        let engine = fixture.engine.as_ref().unwrap();
        Channels::start(
            &mut fixture.pg,
            engine,
            token,
            timings,
            endpoint,
            cancel(),
            outbound,
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
    /// A private Telegram text message from the paired chat `42`.
    fn update(id: u64, text: &str) -> serde_json::Value {
        serde_json::json!({"update_id": id, "message": {"message_id": id, "date": chrono::Utc::now().timestamp(), "from": {"id": 42, "is_bot": false}, "chat": {"id": 42, "type": "private"}, "text": text}})
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
        let fake = FakeTelegram::start().await;
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
        let channels = started(&mut fixture, token, timings, fake.endpoint(), outbound()).await;
        let stored = testkit::read_row(&client, "deliveries", "delivery_id", row).await;
        assert_eq!(stored["status"], "unknown");
        assert_eq!(stored["last_error_code"], "daemon_restart");
        assert!(stored["finished_at"].is_string());
        tokio::time::sleep(timings.delivery_poll * 4).await;
        assert!(fake.calls("sendMessage").is_empty());
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
        let channels = started(
            &mut fixture,
            token,
            outbound_timings(),
            refused_endpoint(),
            outbound(),
        )
        .await;
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
        let fake = FakeTelegram::start().await;
        rt::sealed(&fixture, &client).await;
        let channels = started(
            &mut fixture,
            token,
            outbound_timings(),
            fake.endpoint(),
            outbound(),
        )
        .await;
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
        let mut channels = started(
            &mut fixture,
            first,
            outbound_timings(),
            refused_endpoint(),
            outbound(),
        )
        .await;
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
        let mut channels = started(
            &mut fixture,
            second,
            Timings {
                sweep_interval: Duration::from_millis(150),
                tombstone_retention: Duration::from_secs(20),
                ..outbound_timings()
            },
            refused_endpoint(),
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
        let fake = FakeTelegram::start().await;
        rt::sealed(&fixture, &client).await;
        let (binding, thread) = rt::sender(&fixture, &client, "telegram").await;
        let terminals = fixture.take_terminals();
        let channels = started(
            &mut fixture,
            token,
            outbound_timings(),
            fake.endpoint(),
            Outbound {
                terminals,
                crabcode: None,
            },
        )
        .await;
        let run = rt::begun(&fixture, &client, binding, &thread).await;
        rt::messages(&fake, 1).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let sent = fake.sent_messages();
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].chat_id, 42);
        assert_eq!(sent[0].path, format!("/bot{}/sendMessage", rt::TOKEN));
        assert!(!sent[0].has_parse_mode);
        assert_eq!(
            sent[0].text,
            format!(
                "[OpenMyBot] 已完成 · run {}\nhello from fake",
                &run.run.as_str()[..8]
            )
        );
        assert!(!fake.calls("getUpdates").is_empty());
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
        let fake = FakeTelegram::start().await;
        rt::sealed(&fixture, &client).await;
        let (binding, thread) = rt::sender(&fixture, &client, "telegram").await;
        let terminals = fixture.take_terminals();
        let channels = started(
            &mut fixture,
            token,
            outbound_timings(),
            fake.endpoint(),
            Outbound {
                terminals,
                crabcode: None,
            },
        )
        .await;
        let run = rt::begun(&fixture, &client, binding, &thread).await;
        let id = rt::permission_of(&client, &run.run).await;
        let notice = rt::messages(&fake, 1).await;
        assert!(notice[0].contains(&id), "{notice:?}");
        assert_eq!(
            testkit::decide(&client, &id, omb_store::Decision::Allow).await,
            omb_store::Decided::Decided
        );
        let sent = rt::messages(&fake, 2).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(fake.sent_messages().len(), 2);
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
        let fake = FakeTelegram::start().await;
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
            fake.endpoint(),
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
        let sent = rt::messages(&fake, 1).await;
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
        let fake = FakeTelegram::start().await;
        rt::sealed(&fixture, &client).await;
        let (binding, thread) = rt::sender(&fixture, &client, "telegram").await;
        let terminals = fixture.take_terminals();
        let channels = started(
            &mut fixture,
            token,
            outbound_timings(),
            fake.endpoint(),
            Outbound {
                terminals,
                crabcode: None,
            },
        )
        .await;
        let run = rt::begun(&fixture, &client, binding, &thread).await;
        agent::initialized(&client, &run.run).await;
        cancel_run(&fixture, &run).await;
        let sent = rt::messages(&fake, 1).await;
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
        fake.push_update(update(2, "after the unknown stop"));
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
            endpoint: fake.endpoint(),
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
            channel: Channel::Telegram,
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
        let fake = FakeTelegram::start().await;
        let channels = started(
            &mut fixture,
            token,
            outbound_timings(),
            fake.endpoint(),
            outbound(),
        )
        .await;
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
        let sent = fake.sent_messages();
        for (_, body, _) in &rows {
            let message = sent.iter().find(|sent| &sent.text == body).unwrap();
            assert_eq!(message.chat_id, 42);
        }
        channels.stop().await;
        drop(client);
        fixture.stop().await;
    }
}
