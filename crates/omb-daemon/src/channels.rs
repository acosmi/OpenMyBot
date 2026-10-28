//! Daemon wiring of the channel receivers, the dispatcher, the heartbeat and the status segment.
use crate::{
    ChannelCounters, ChannelStatus, DaemonError, GapStatus,
    engine::Engine,
    pg::{AuthorityConnection, Postgres},
};
use omb_channels::{
    CHANNEL_NOTE, Connection, Counters, ReceiverContext, Task, TelegramEndpoint, Timings,
    start_dispatcher, start_heartbeat, start_receiver,
};
use omb_store::Channel;
use openbot_contracts::ids::ActorId;
use openbot_infra::auth::single_user::SINGLE_USER_ACTOR_ID;
use std::sync::{Arc, atomic::Ordering};
use tokio::{sync::Notify, task::JoinHandle};
use uuid::Uuid;

/// Read side of the status channel segment: its own connection plus the receivers' counters.
pub(crate) struct StatusSource {
    pub(crate) client: Arc<tokio_postgres::Client>,
    pub(crate) counters: Arc<Counters>,
}
impl StatusSource {
    pub(crate) async fn read(&self) -> Result<Vec<ChannelStatus>, DaemonError> {
        let error = DaemonError::InternalError;
        let time = |unix_nanos: i128| {
            i64::try_from(unix_nanos)
                .map(|nanos| {
                    chrono::DateTime::from_timestamp_nanos(nanos)
                        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
                })
                .map_err(|_| error)
        };
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
                                started_at: time(gap.started_at.unix_timestamp_nanos())?,
                                ended_at: gap
                                    .ended_at
                                    .map(|at| time(at.unix_timestamp_nanos()))
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

/// The running receiver, dispatcher and heartbeat, and the status connection.
pub(crate) struct Channels {
    receiver: Option<Task>,
    dispatcher: Task,
    heartbeat: Task,
    status: Arc<tokio_postgres::Client>,
    status_driver: JoinHandle<Result<(), tokio_postgres::Error>>,
    counters: Arc<Counters>,
}
impl Channels {
    /// Records startup gaps, then starts the heartbeat, the dispatcher and each active receiver,
    /// every one on its own connection.
    pub(crate) async fn start(
        postgres: &mut Postgres,
        engine: &Engine,
        token_id: Uuid,
        timings: Timings,
        endpoint: TelegramEndpoint,
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
        let dispatcher = connection(
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
        let counters = Arc::new(Counters::default());
        let wake = Arc::new(Notify::new());
        Ok(Self {
            heartbeat: start_heartbeat(heartbeat, token_id, timings),
            dispatcher: start_dispatcher(dispatcher, entry, timings, Arc::clone(&wake)),
            receiver: receiver.map(|(row, opened)| {
                start_receiver(
                    opened,
                    row,
                    ReceiverContext {
                        vault: engine.vault.clone(),
                        owner: ActorId::new(SINGLE_USER_ACTOR_ID),
                        endpoint,
                        timings,
                        counters: Arc::clone(&counters),
                        wake,
                    },
                )
            }),
            status: Arc::new(status.client),
            status_driver: status.driver,
            counters,
        })
    }
    pub(crate) fn status_source(&self) -> StatusSource {
        StatusSource {
            client: Arc::clone(&self.status),
            counters: Arc::clone(&self.counters),
        }
    }
    /// Resolves with `internal_error` when the heartbeat or the dispatcher ends, or a receiver
    /// fails; a receiver that stopped itself after suspension or deactivation is only removed.
    pub(crate) async fn finished(&mut self) -> DaemonError {
        let Self {
            receiver,
            dispatcher,
            heartbeat,
            ..
        } = self;
        loop {
            let ended = tokio::select! {
                _ = heartbeat.finished() => return DaemonError::InternalError,
                _ = dispatcher.finished() => return DaemonError::InternalError,
                ended = async {
                    match receiver.as_mut() {
                        Some(task) => task.finished().await,
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
    /// Stops the receiver, the dispatcher and the heartbeat in that order, then ends the status
    /// connection that request handlers may still share.
    pub(crate) async fn stop(self) {
        if let Some(receiver) = self.receiver {
            receiver.stop().await;
        }
        self.dispatcher.stop().await;
        self.heartbeat.stop().await;
        self.status_driver.abort();
        let _ = self.status_driver.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        StatusSnapshot,
        delegation::fixture::{self, Fixture},
    };
    use omb_channels::OMB_REPLY_TEXTS_V1;
    use omb_store::{
        AcceptOutcome, Command, Content, Disposition, IdentityKey, NormalizedEvent, PairStart,
        PollGapReason, accept_event, open_poll_gap, pair_start,
    };
    use openbot_application::{BeginDelegatedThreadRun, DelegatedUntrustedMaterial};
    use openbot_contracts::{
        auth::DelegationSource,
        command::{AppCommand, AppReply},
        ids::{BotId, RunId, ThreadId},
    };
    use openbot_domain::vault::{SecretBytes, SecretKind, SecretPrincipal, ServiceId};
    use openbot_infra::net::safe_http::{CidrAllowlist, EgressPolicy, SafeDialer, SchemePolicy};
    use std::time::Duration;
    use tokio_postgres::Client;

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

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn production_tenant_without_bot_cancels_first_event_and_suspends_binding_with_grant_stale()
     {
        let mut fixture = Fixture::start().await;
        let (client, binding) = paired(&mut fixture).await;
        let entry = fixture.engine().assembly.delegated_entry.clone().unwrap();
        let pending = row(&client, "10").await;
        let error = entry.begin(replay(binding, &pending)).await.unwrap_err();
        assert_eq!(error.http_status(), 403);
        assert!(
            matches!(&error, openbot_contracts::error::AppError::PolicyRefused { rule, .. } if rule == "delegation_not_current"),
            "{error:?}"
        );
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
        let channels =
            Channels::start(&mut fixture.pg, engine, second, quick(), refused_endpoint())
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
        let channels = Channels::start(&mut fixture.pg, engine, token, quick(), refused_endpoint())
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
}
