//! A downstream host uses the real assembly, local principal and durable runtime.
mod harness {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/postgres_harness.rs"
    ));
}
#[path = "../../openbot-infra/tests/support/delegated_assembly_fixture.rs"]
pub mod fixture;
use async_trait::async_trait;
use fixture::{Fixture, Options, text};
use harness::{admin_config, with_temp_database};
use openbot_agent::{BuiltInAgentConfig, BuiltInAgentRuntime, NoAgentToolInvoker, ProviderRouter};
use openbot_application::*;
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_infra::auth::config::default_session_lifetime;
use openbot_infra::auth::single_user::load_single_user_principal;
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::run_runtime::RunRelay;
use openbot_server::SingleUserAuthResolver;
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

#[derive(Default)]
struct AnswerProvider {
    calls: AtomicUsize,
}
struct AnswerSession(std::collections::VecDeque<ProviderEvent>);
#[async_trait]
impl ProviderSession for AnswerSession {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        Ok(self.0.pop_front())
    }
}
#[async_trait]
impl ProviderAdapter for AnswerProvider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(matches!(request.route, ProviderRoute::Extension(_)));
        assert!(request.rate_card.is_none());
        Ok(Box::new(AnswerSession(
            vec![
                ProviderEvent::TextDelta {
                    index: 0,
                    delta: "Actual delegated result".into(),
                },
                ProviderEvent::Usage(ProviderUsage {
                    input_tokens: 1,
                    output_tokens: 1,
                    total_tokens: 2,
                }),
                ProviderEvent::Completed,
            ]
            .into(),
        )))
    }
}
async fn local_resolver(f: &Fixture) -> Result<SingleUserAuthResolver, String> {
    let principal = load_single_user_principal(
        &f.pool,
        f.auth.deployment().clone(),
        f.auth.tenant().clone(),
    )
    .await
    .map_err(text)?;
    Ok(SingleUserAuthResolver::from_verified_principal(
        principal,
        default_session_lifetime(),
    ))
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn e07_fake_extension_delegated_run_terminal_and_local_read() {
    with_temp_database(&admin_config("downstream_e07"), "downstreame07", |config| async move {
        let provider = Arc::new(AnswerProvider::default());
        let f = Fixture::with_options(&config, Options { extensions: vec![(ProviderExtensionKey::new("fake_host").map_err(text)?, provider.clone())], ..Options::default() }).await?;
        let resolver = local_resolver(&f).await?;
        let context = PostgresAgentContextSource::new(f.pool.clone(), f.auth.deployment().clone(), f.auth.tenant().clone(), Some(32)).map_err(text)?.with_extensions(f.assembly.provider_extensions.clone());
        let router = ProviderRouter::new(Arc::new(AnswerProvider::default()), None).with_extensions(f.assembly.provider_extensions.clone());
        let agent = BuiltInAgentRuntime::start(f.assembly.run_runtime.clone(), Arc::new(context), Arc::new(router), Arc::new(NoAgentToolInvoker), Arc::new(NoAgentAudit), BuiltInAgentConfig::default()).map_err(|error| format!("{error:?}"))?;
        let relay = RunRelay::start(f.assembly.run_runtime.clone(), agent.consumer());
        let result: Result<(), String> = async {
            assert_eq!(resolver.local_context().map_err(text)?, f.auth);
            let request = f.request("e07-run").await?;
            let receipt = f.assembly.delegated_entry.as_ref().ok_or("missing delegated entry")?.begin(request.clone()).await.map_err(text)?;
            tokio::time::timeout(Duration::from_secs(10), async {
                while f.notices.0.lock().unwrap().is_empty() { tokio::time::sleep(Duration::from_millis(10)).await; }
            }).await.map_err(text)?;
            let notices = f.notices.0.lock().unwrap().clone();
            assert_eq!(notices, vec![RunTerminalNotice { deployment: f.auth.deployment().clone(), tenant: f.auth.tenant().clone(), thread_id: receipt.thread_id.clone(), run_id: receipt.run_id.clone(), terminal: RunTerminalKind::Succeeded }]);
            assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
            assert!(f.authority.calls.load(Ordering::SeqCst)>=2);
            let reply = f.assembly.application.execute(resolver.local_context().map_err(text)?, AppCommand::GetThreadConversation { thread_id: receipt.thread_id.clone() }).await.map_err(text)?;
            assert!(serde_json::to_string(&reply).map_err(text)?.contains("Actual delegated result"));
            let c=f.pool.get().await.map_err(text)?;
            let row=c.query_one("SELECT status,(SELECT count(*) FROM public.run_events e WHERE e.run_id=r.run_id AND e.seq=r.terminal_event_seq) FROM public.runs r WHERE run_id=$1", &[&receipt.run_id.as_str()]).await.map_err(text)?;
            assert_eq!(row.get::<_, String>(0), "completed");
            assert_eq!(row.get::<_, i64>(1), 1);
            Ok(())
        }.await;
        relay.stop().await; agent.stop().await;
        f.assembly.shutdown().await; f.pool.close(); result
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn e08_three_default_inputs_preserve_legacy_assembly() {
    with_temp_database(
        &admin_config("downstream_e08"),
        "downstreame08",
        |config| async move {
            let f = Fixture::with_options(
                &config,
                Options {
                    delegated: false,
                    subscribe: false,
                    ..Options::default()
                },
            )
            .await?;
            let result: Result<(), String> = async {
                assert!(f.assembly.provider_extensions.is_empty());
                assert!(f.assembly.delegated_entry.is_none());
                let resolver = local_resolver(&f).await?;
                let before = f.image().await?;
                let auth = resolver.local_context().map_err(text)?;
                assert_eq!(auth, f.auth);
                assert!(auth.delegation().is_none());
                let current = f
                    .assembly
                    .application
                    .execute(auth.clone(), AppCommand::GetCurrentUser)
                    .await
                    .map_err(text)?;
                assert!(matches!(current, AppReply::CurrentUser(_)));
                assert_eq!(before, f.image().await?);
                let minted = f.request("legacy-id").await?;
                let reply = f
                    .assembly
                    .application
                    .execute(
                        auth.clone(),
                        AppCommand::GetThreadStatus {
                            thread_id: minted.thread_id.clone(),
                        },
                    )
                    .await
                    .map_err(text)?;
                assert_eq!(
                    serde_json::to_vec(&reply).map_err(text)?,
                    serde_json::to_vec(&json!({"kind":"thread_status","known":false}))
                        .map_err(text)?
                );
                let missing = f
                    .assembly
                    .application
                    .execute(
                        auth,
                        AppCommand::GetThreadConversation {
                            thread_id: minted.thread_id,
                        },
                    )
                    .await;
                assert_eq!(serde_json::to_value(missing.map_err(text)?).map_err(text)?,json!({"kind":"thread_conversation","messages":[],"activeRunId":null,"activeRunState":null,"activeRunCancellable":false,"activeRunText":"","lastEventSequence":null}));
                let malformed=f.assembly.application.execute(f.auth.clone(),AppCommand::GetThreadConversation {thread_id:openbot_contracts::ids::ThreadId::new("bad-thread")}).await.unwrap_err();
                assert_eq!(malformed,openbot_contracts::error::AppError::MalformedPayload {field:"thread_id"});
                assert_eq!(f.authority.calls.load(Ordering::SeqCst), 0);
                assert!(f.notices.0.lock().unwrap().is_empty());
                let snapshot = f.image().await?;
                for table in ["threads", "runs", "messages", "events", "outbox"] {
                    assert_eq!(snapshot[table], json!([]));
                }
                let request=f.request("legacy-run").await?;
                let legacy=AppCommand::BeginThreadRun(openbot_contracts::command::BeginThreadRun {model_selection:None,thread_id:request.thread_id.clone(),run_id:request.run_id.clone(),bot_id:request.bot_id.clone(),anchor:openbot_contracts::command::ThreadRunAnchor::DirectBot,message:"Legacy user input".into(),selected_skill_slugs:vec![],artifact_refs:vec![]});
                let reply=f.assembly.application.execute(f.auth.clone(),legacy.clone()).await.map_err(text)?;
                assert_eq!(serde_json::to_value(reply).map_err(text)?,json!({"kind":"thread_run_started","threadId":request.thread_id,"runId":"legacy-run","messageSequence":0,"eventSequence":0,"replayed":false}));
                let c=f.pool.get().await.map_err(text)?;
                let projection:serde_json::Value=c.query_one("SELECT jsonb_build_object('message',m.content,'role',m.role,'run_status',r.status,'run_next',r.next_event_seq,'event_kind',e.event_type,'event_payload',e.payload,'outbox_payload',o.payload) FROM public.runs r JOIN public.messages m ON m.message_id=r.run_id||':input' JOIN public.run_events e ON e.run_id=r.run_id AND e.seq=0 JOIN public.outbox o ON o.outbox_id=r.run_id||':agent_run_dispatch' WHERE r.run_id='legacy-run'",&[]).await.map_err(text)?.get(0);
                assert_eq!(projection,json!({"message":{"text":"Legacy user input"},"role":"user","run_status":"running","run_next":1,"event_kind":"started","event_payload":{"runId":"legacy-run","messageId":"legacy-run:input","botId":"delegated-bot"},"outbox_payload":{"runId":"legacy-run","threadId":request.thread_id,"eventSequence":0}}));
                drop(c);
                let replay=f.assembly.application.execute(f.auth.clone(),legacy).await.map_err(text)?;
                assert!(matches!(replay,AppReply::ThreadRunStarted(r) if r.replayed));
                let claim=f.assembly.run_runtime.claim_dispatch().await.map_err(text)?.ok_or("legacy dispatch absent")?;
                let lease=f.assembly.run_runtime.acknowledge_dispatch(&claim).await.map_err(text)?;
                f.assembly.run_runtime.finish_run(&lease,lease.next_event_sequence(),RunTerminal::Completed).await.map_err(text)?;
                assert_eq!(f.authority.calls.load(Ordering::SeqCst),0);
                assert!(f.notices.0.lock().unwrap().is_empty());
                Ok(())
            }
            .await;
            f.assembly.shutdown().await;
            f.pool.close();
            result
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn assembly_duplicate_and_ninth_extension_fail_before_workers() {
    // Separate owned databases prevent a seed failure from masquerading as validation.
    for (entries, duplicate, expected) in [
        (8, false, None),
        (2, true, Some("Duplicate")),
        (9, false, Some("TooMany")),
    ] {
        with_temp_database(
            &admin_config("downstream_registry"),
            &format!("registry{entries}"),
            |config| async move {
                let provider = Arc::new(AnswerProvider::default());
                let registrations = (0..entries)
                    .map(|i| {
                        (
                            ProviderExtensionKey::new(
                                if duplicate {
                                    "same".to_owned()
                                } else {
                                    format!("key_{i}")
                                }
                                .as_str(),
                            )
                            .unwrap(),
                            provider.clone() as Arc<dyn ProviderAdapter>,
                        )
                    })
                    .collect();
                let result = Fixture::with_options(
                    &config,
                    Options {
                        extensions: registrations,
                        ..Options::default()
                    },
                )
                .await;
                if let Some(expected) = expected {
                    let err = match result {
                        Ok(f) => {
                            f.assembly.shutdown().await;
                            f.pool.close();
                            return Err("invalid registry was assembled".into());
                        }
                        Err(e) => e,
                    };
                    // The public assembly error is a closed stable code, not an arbitrary seed error.
                    assert_eq!(
                        err, "postgres_application_assembly_failed",
                        "{expected}: {err}"
                    );
                } else {
                    let f = result?;
                    assert_eq!(f.assembly.provider_extensions.len(), 8);
                    let weak = Arc::downgrade(&f.assembly.run_runtime);
                    f.assembly.shutdown().await;
                    f.pool.close();
                    assert!(weak.upgrade().is_none());
                }
                assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
                assert_eq!(
                    Arc::strong_count(&provider),
                    1,
                    "failed assembly retained adapter/worker"
                );
                Ok(())
            },
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn assembly_rejects_non_single_user_delegated_configuration() {
    for mode in 0..4 {
        with_temp_database(
            &admin_config("downstream_multi"),
            &format!("multi{mode}"),
            |config| async move {
                let options = Options {
                    single_user: false,
                    delegated: mode == 1,
                    subscribe: mode == 2,
                    extensions: if mode == 3 {
                        vec![(
                            ProviderExtensionKey::new("fake_host").map_err(text)?,
                            Arc::new(AnswerProvider::default()) as Arc<dyn ProviderAdapter>,
                        )]
                    } else {
                        vec![]
                    },
                    subscriber: None,
                };
                match Fixture::with_options(&config, options).await {
                    Ok(f) if mode == 0 => {
                        assert!(f.assembly.delegated_entry.is_none());
                        assert!(f.assembly.provider_extensions.is_empty());
                        f.assembly.shutdown().await;
                        f.pool.close();
                    }
                    Ok(f) => {
                        f.assembly.shutdown().await;
                        f.pool.close();
                        return Err("multi-user downstream assembly accepted".into());
                    }
                    Err(e) if mode != 0 => assert_eq!(e, "postgres_application_assembly_failed"),
                    Err(e) => return Err(e),
                }
                Ok(())
            },
        )
        .await;
    }
}
