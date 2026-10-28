//! The engine's built-in Agent runtime with the run relay, assembled for the OpenMyBot Bot.
use crate::{DaemonError, engine::Engine};
use async_trait::async_trait;
use openbot_agent::{
    AuthorizedAgentToolGateway, BuiltInAgentConfig, BuiltInAgentRuntime, ProviderRouter,
    RetryingProvider, RetryingProviderConfig,
};
use openbot_application::{ProviderAdapter, ProviderPortError, ProviderRequest, ProviderSession};
use openbot_infra::{
    agent_audit::PostgresAgentAudit,
    agent_tools::{PostgresAgentAuthorizationSource, PostgresAgentToolSequence},
    db::pool::DatabaseConfig,
    provider::context::PostgresAgentContextSource,
    run_runtime::RunRelay,
};
use std::sync::Arc;

/// The router's package route. The Bot is routed only to the `crabcode` extension, so this route
/// is never chosen; if it were, the start is refused.
pub(crate) struct RefusingProvider;
#[async_trait]
impl ProviderAdapter for RefusingProvider {
    async fn start(
        &self,
        _request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        Err(ProviderPortError::Unavailable)
    }
}

pub(crate) struct AgentRuntime {
    relay: RunRelay,
    agent: BuiltInAgentRuntime,
}
impl AgentRuntime {
    /// One extension registration consumed by both the router and the context source; the run
    /// relay listens on its own connection named `openbot-run-control`.
    pub(crate) fn start(engine: &Engine, database: DatabaseConfig) -> Result<Self, DaemonError> {
        let assembly = &engine.assembly;
        let extensions = assembly.provider_extensions.clone();
        let provider = Arc::new(
            RetryingProvider::new(
                Arc::new(
                    ProviderRouter::new(Arc::new(RefusingProvider), None)
                        .with_extensions(extensions.clone()),
                ),
                RetryingProviderConfig::default(),
            )
            .map_err(|_| DaemonError::AgentRuntimeFailed)?,
        );
        let context = Arc::new(
            PostgresAgentContextSource::new(
                engine.pool.clone(),
                engine.deployment.clone(),
                engine.tenant.clone(),
                None,
            )
            .map_err(|_| DaemonError::AgentRuntimeFailed)?
            .with_extensions(extensions),
        );
        let tools = Arc::new(AuthorizedAgentToolGateway::with_sequence_and_cancellations(
            assembly.application.clone(),
            Arc::new(PostgresAgentAuthorizationSource::new(
                engine.pool.clone(),
                engine.deployment.clone(),
                engine.tenant.clone(),
                true,
            )),
            Arc::new(PostgresAgentToolSequence::new(engine.pool.clone())),
            assembly.tool_cancellations.clone(),
        ));
        let audit = Arc::new(
            PostgresAgentAudit::new(
                engine.pool.clone(),
                engine.agent_audit_key.expose().to_vec(),
            )
            .map_err(|_| DaemonError::AgentRuntimeFailed)?,
        );
        let agent = BuiltInAgentRuntime::start_with_remote_interrupts(
            assembly.run_runtime.clone(),
            context,
            provider,
            tools,
            audit,
            assembly.remote_interrupts.clone(),
            BuiltInAgentConfig::default(),
        )
        .map_err(|_| DaemonError::AgentRuntimeFailed)?;
        let relay = RunRelay::start_with_database(
            assembly.run_runtime.clone(),
            agent.consumer(),
            database.with_application_name("openbot-run-control"),
        );
        Ok(Self { relay, agent })
    }
    pub(crate) async fn stop(self) {
        self.relay.stop().await;
        self.agent.stop().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::{BOT_ID, fixture::Fixture};
    use omb_hostdriver::{HostDriverConfig, Limits, VersionWindow, WorkspaceRoots};
    use openbot_application::{
        BeginDelegatedThreadRun, DelegatedUntrustedMaterial, ProviderExtensionKey, ProviderRoute,
    };
    use openbot_contracts::{
        auth::DelegationSource,
        command::{
            AppCommand, AppReply, CancelThreadRun, ThreadConversationSnapshot,
            ThreadForegroundRunState, ThreadHistoryRole,
        },
        ids::{BotId, RunId, ThreadId},
        reconciliation::RunReconciliationStatus,
    };
    use std::{
        path::{Path, PathBuf},
        time::Duration,
    };
    use uuid::Uuid;

    /// The in-repository fake host binary, built by the hostdriver crate's testkit feature.
    fn fake() -> PathBuf {
        let path = PathBuf::from(
            std::env::var_os("OMB_TEST_FAKE_CRABCODE")
                .expect("OMB_TEST_FAKE_CRABCODE: absolute path of the fake host binary"),
        );
        assert!(path.is_absolute());
        path
    }
    /// A host driver on `<root>/home/ws` whose fake plays `scenario`.
    fn host(root: &Path, scenario: &str, limits: Limits) -> HostDriverConfig {
        let home = root.join("home");
        let workspace = home.join("ws");
        std::fs::create_dir_all(&workspace).unwrap();
        let window = serde_json::json!({"accepted": [{
            "version": "1.1.16",
            "extra_args": [],
            "extra_env": {
                "FAKE_CRABCODE_SCENARIO": scenario,
                "FAKE_CRABCODE_REPORT": home.join("report.jsonl"),
            },
            "gates": {"G1": "pass", "G2": "pass", "G3": "pass", "G4": "pass", "G5": "pass", "G6": "pass"},
            "verified_at": "2026-10-28T00:00:00Z",
            "engine_commit": "0123456789abcdef0123456789abcdef01234567",
            "record": "compat/crabcode/1.1.16.md"
        }]});
        HostDriverConfig {
            binary: Some(fake()),
            home: home.clone(),
            tmp_dir: root.join("hosts/crabcode/tmp"),
            roots: WorkspaceRoots::parse(&home, &[workspace]).unwrap(),
            window: VersionWindow::parse(&window.to_string()).unwrap(),
            limits,
        }
    }
    fn quick() -> Limits {
        Limits {
            stop_grace: Duration::from_secs(2),
            term_grace: Duration::from_secs(1),
            kill_grace: Duration::from_secs(1),
            ..Limits::default()
        }
    }
    fn happy(root: &Path) -> HostDriverConfig {
        host(root, "happy", quick())
    }
    fn cooperative(root: &Path) -> HostDriverConfig {
        host(root, "cooperative", quick())
    }
    fn unconfirmable(root: &Path) -> HostDriverConfig {
        host(
            root,
            "ignore_term",
            Limits {
                stop_grace: Duration::from_millis(200),
                term_grace: Duration::from_millis(200),
                kill_grace: Duration::ZERO,
                ..Limits::default()
            },
        )
    }
    fn lingering(root: &Path) -> HostDriverConfig {
        host(
            root,
            "ignore_eof",
            Limits {
                stop_grace: Duration::from_millis(300),
                ..quick()
            },
        )
    }

    struct Run {
        thread: ThreadId,
        run: RunId,
    }
    /// Activates the host binding on the fixture's workspace, records its accepted event and
    /// begins the delegated run through the engine's delegated entry.
    async fn begin(fixture: &mut Fixture) -> (Run, tokio_postgres::Client) {
        let mut client = fixture.client().await;
        let local = fixture.engine().resolver.local_context().unwrap();
        let workspace = fixture.root.join("home/ws");
        let binding = omb_store::activate_host(
            &mut client,
            omb_store::HostBinding {
                workspace_dir: workspace.to_str().unwrap(),
                granted_generation: local.auth_generation().get(),
                run_deadline: None,
            },
            tokio::time::Instant::now() + Duration::from_secs(30),
        )
        .await
        .unwrap();
        let AppReply::ThreadMinted(minted) = fixture
            .engine()
            .assembly
            .application
            .execute(local, AppCommand::MintThreadId)
            .await
            .unwrap()
        else {
            panic!("mint reply");
        };
        let record = Uuid::now_v7();
        let run = format!("run-{record}");
        client.execute("INSERT INTO openmybot.channel_events(record_id,record_kind,channel_kind,source_key,event_key,accepted_at,binding_id,disposition,text,text_sha256,run_id,thread_id,dispatch_status) VALUES ($1,'event','host','crabcode',$2,statement_timestamp(),$3,'accepted_message','do the work',sha256('do the work'::bytea),$4,$5,'dispatched')", &[&record, &format!("op:{record}"), &binding, &run, &minted.thread_id.as_str()]).await.unwrap();
        fixture
            .engine()
            .assembly
            .delegated_entry
            .clone()
            .unwrap()
            .begin(BeginDelegatedThreadRun {
                source: DelegationSource::ExternalBinding {
                    binding_id: binding.to_string(),
                },
                revision: 1,
                trigger_id: record.to_string(),
                thread_id: minted.thread_id.clone(),
                run_id: RunId::new(&run),
                bot_id: BotId::new(BOT_ID),
                untrusted_material: Some(DelegatedUntrustedMaterial {
                    source_ref: format!("omb:channel_events:{record}"),
                    text: "do the work".into(),
                }),
            })
            .await
            .unwrap();
        (
            Run {
                thread: minted.thread_id,
                run: RunId::new(&run),
            },
            client,
        )
    }
    async fn conversation(fixture: &Fixture, thread: &ThreadId) -> ThreadConversationSnapshot {
        let local = fixture.engine().resolver.local_context().unwrap();
        let AppReply::ThreadConversation(snapshot) = fixture
            .engine()
            .assembly
            .application
            .execute(
                local,
                AppCommand::GetThreadConversation {
                    thread_id: thread.clone(),
                },
            )
            .await
            .unwrap()
        else {
            panic!("conversation reply");
        };
        snapshot
    }
    /// The conversation once its foreground run no longer queues, runs or cancels.
    async fn settled(fixture: &Fixture, thread: &ThreadId) -> ThreadConversationSnapshot {
        let limit = tokio::time::Instant::now() + Duration::from_secs(90);
        loop {
            let snapshot = conversation(fixture, thread).await;
            if !matches!(
                snapshot.active_run_state,
                Some(
                    ThreadForegroundRunState::Queued
                        | ThreadForegroundRunState::Running
                        | ThreadForegroundRunState::Cancelling
                )
            ) {
                return snapshot;
            }
            assert!(tokio::time::Instant::now() < limit, "run settle deadline");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    async fn session(client: &tokio_postgres::Client, run: &RunId) -> serde_json::Value {
        client
            .query_one("SELECT row_to_json(h) FROM openmybot.host_driver_sessions h WHERE record_kind='session' AND run_id=$1", &[&run.as_str()])
            .await
            .unwrap()
            .get(0)
    }
    /// The session row once the child sent its `system/init`.
    async fn initialized(client: &tokio_postgres::Client, run: &RunId) -> serde_json::Value {
        let limit = tokio::time::Instant::now() + Duration::from_secs(90);
        loop {
            let found = client
                .query("SELECT row_to_json(h) FROM openmybot.host_driver_sessions h WHERE record_kind='session' AND run_id=$1 AND init_at IS NOT NULL", &[&run.as_str()])
                .await
                .unwrap();
            if let Some(row) = found.first() {
                return row.get(0);
            }
            assert!(tokio::time::Instant::now() < limit, "host init deadline");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    fn group_gone(row: &serde_json::Value) -> bool {
        let pgid = rustix::process::Pid::from_raw(row["pgid"].as_i64().unwrap() as i32).unwrap();
        rustix::process::test_kill_process_group(pgid) == Err(rustix::io::Errno::SRCH)
    }
    async fn cancel(fixture: &Fixture, run: &Run) {
        let local = fixture.engine().resolver.local_context().unwrap();
        fixture
            .engine()
            .assembly
            .application
            .execute(
                local,
                AppCommand::CancelThreadRun(CancelThreadRun {
                    thread_id: run.thread.clone(),
                    run_id: run.run.clone(),
                }),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn runtime_starts_and_stops_with_the_registered_extension() {
        let fixture = Fixture::start().await;
        let key = ProviderExtensionKey::new("crabcode").unwrap();
        // The router and the context source both receive this one registration.
        assert!(
            fixture
                .engine()
                .assembly
                .provider_extensions
                .get(&key)
                .is_some()
        );
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        runtime.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    async fn package_route_is_refused_by_refusing_provider() {
        let request = ProviderRequest {
            route: ProviderRoute::PackageOpenAi,
            messages: Vec::new(),
            tools: Vec::new(),
            max_output_tokens: None,
            rate_card: None,
            cost_cap: None,
        };
        assert_eq!(
            RefusingProvider.start(request).await.err(),
            Some(ProviderPortError::Unavailable)
        );
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn delegated_run_through_fake_crabcode_completes_and_writes_session_row() {
        let mut fixture = Fixture::start_with_host(happy).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let (run, client) = begin(&mut fixture).await;
        let snapshot = settled(&fixture, &run.thread).await;
        assert_eq!(snapshot.active_run_id, None);
        assert!(
            snapshot
                .messages
                .iter()
                .any(|m| m.role == ThreadHistoryRole::Assistant && m.content == "hello from fake"),
            "{snapshot:?}"
        );
        let row = session(&client, &run.run).await;
        assert_eq!(row["end_reason"], "result_success");
        assert!(group_gone(&row));
        runtime.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancelling_active_run_with_cooperative_child_ends_cancelled() {
        let mut fixture = Fixture::start_with_host(cooperative).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let (run, client) = begin(&mut fixture).await;
        initialized(&client, &run.run).await;
        cancel(&fixture, &run).await;
        let snapshot = settled(&fixture, &run.thread).await;
        assert_eq!(snapshot.active_run_id, None);
        assert_eq!(snapshot.active_run_state, None);
        assert!(
            !snapshot
                .messages
                .iter()
                .any(|m| m.role == ThreadHistoryRole::Assistant)
        );
        let row = session(&client, &run.run).await;
        assert_eq!(row["end_reason"], "stop_requested");
        assert_eq!(row["stop_outcome"], "confirmed");
        assert!(group_gone(&row));
        runtime.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn cancelling_with_unconfirmable_stop_ends_reconciliation_required() {
        let mut fixture = Fixture::start_with_host(unconfirmable).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let (run, client) = begin(&mut fixture).await;
        initialized(&client, &run.run).await;
        cancel(&fixture, &run).await;
        // A cancelled run whose stop stayed unknown is read through the reconciliation view.
        let limit = tokio::time::Instant::now() + Duration::from_secs(90);
        let reconciliation = loop {
            let local = fixture.engine().resolver.local_context().unwrap();
            if let Ok(AppReply::RunReconciliation(snapshot)) = fixture
                .engine()
                .assembly
                .application
                .execute(
                    local,
                    AppCommand::GetRunReconciliation {
                        thread_id: run.thread.clone(),
                        run_id: run.run.clone(),
                        after: None,
                        limit: None,
                    },
                )
                .await
            {
                break snapshot;
            }
            assert!(
                tokio::time::Instant::now() < limit,
                "reconciliation deadline"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(
            reconciliation.status,
            RunReconciliationStatus::ReconciliationRequired
        );
        assert!(reconciliation.foreground_blocked);
        let row = session(&client, &run.run).await;
        assert_eq!(row["end_reason"], "stop_requested");
        assert_eq!(row["stop_outcome"], "unknown");
        let pgid = rustix::process::Pid::from_raw(row["pgid"].as_i64().unwrap() as i32).unwrap();
        let _ = rustix::process::kill_process_group(pgid, rustix::process::Signal::KILL);
        runtime.stop().await;
        fixture.stop().await;
    }

    #[tokio::test]
    #[ignore = "own PG17.11; explicit binary directory; serial"]
    async fn daemon_stop_order_reaps_live_child_before_engine_shutdown() {
        let mut fixture = Fixture::start_with_host(lingering).await;
        let runtime = AgentRuntime::start(fixture.engine(), fixture.pg.database_config()).unwrap();
        let (run, client) = begin(&mut fixture).await;
        let row = initialized(&client, &run.run).await;
        assert!(!group_gone(&row));
        runtime.stop().await;
        fixture.host.as_ref().unwrap().shutdown().await;
        assert!(group_gone(&row));
        assert!(session(&client, &run.run).await["end_reason"].is_string());
        drop(client);
        fixture.stop().await;
    }
}
