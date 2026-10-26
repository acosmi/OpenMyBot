//! Persisted delegation, real lease/authenticator/gateway and original tool pipeline.
mod harness {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-support/postgres_harness.rs"
    ));
}
#[path = "support/delegated_assembly_fixture.rs"]
pub mod fixture;
use async_trait::async_trait;
use fixture::{CommitAckProxy, Fixture, Options, text};
use harness::{admin_config, with_temp_database};
use openbot_agent::{
    AgentToolInvokeError, AgentToolInvoker, AuthorizedAgentToolGateway, BuiltInAgentConfig,
    BuiltInAgentRuntime, NoAgentToolInvoker, ProviderRouter, RemoteAgentToolInvoker,
};
use openbot_application::*;
use openbot_contracts::auth::{AuthContextBuilder, AuthGeneration, VerifiedDelegation};
use openbot_contracts::command::{AppCommand, AppReply};
use openbot_contracts::components::{
    ComponentApprovalAnswer, ComponentApprovalDecision, ComponentCatalogueRequest,
    ComponentDecisionRequest, ComponentHumanDecisionAnswer, ComponentHumanDecisionRequest,
    compiled_component_manifest,
};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::{ActorId, BotId, RunId, ThreadId, ToolCallId};
use openbot_contracts::policy::{
    ActionPolicyDocument as ActionPolicy, ActionPolicyMode as PolicyMode,
};
use openbot_contracts::tool::{ToolApprovalDecision, ToolInvocation};
use openbot_domain::audit::hash::{CanonicalWriter, Sha256Digest};
use openbot_domain::remote_callback::{RemoteRunScope, RemoteToolSet};
use openbot_infra::agent_tools::{PostgresAgentAuthorizationSource, PostgresAgentToolSequence};
use openbot_infra::provider::context::PostgresAgentContextSource;
use openbot_infra::run_runtime::RunRelay;
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, SystemTime};

const READ: &str = "mcp__fixture__read";
const WRITE: &str = "mcp__fixture__write";
#[derive(Default)]
struct Provider {
    calls: AtomicUsize,
}
struct Session(bool);
#[async_trait]
impl ProviderSession for Session {
    async fn next_event(&mut self) -> Result<Option<ProviderEvent>, ProviderPortError> {
        if self.0 {
            Ok(None)
        } else {
            self.0 = true;
            Ok(Some(ProviderEvent::Completed))
        }
    }
}
#[async_trait]
impl ProviderAdapter for Provider {
    async fn start(
        &self,
        request: ProviderRequest,
    ) -> Result<Box<dyn ProviderSession>, ProviderPortError> {
        assert!(matches!(request.route, ProviderRoute::Extension(_)));
        assert!(request.rate_card.is_none());
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Session(false)))
    }
}
fn remember() -> Value {
    json!({"memoryKind":"preference","scope":"user","content":"synthetic delegated preference","tags":["fixture"],"sensitivity":"normal"})
}
async fn allow(f: &Fixture) -> Result<(), String> {
    f.assembly
        .application
        .execute(
            f.auth.clone(),
            AppCommand::SetActionPolicy {
                policy: ActionPolicy {
                    mode: PolicyMode::Enforce,
                    deny: vec![],
                    allow: vec!["true".into()],
                },
            },
        )
        .await
        .map_err(text)?;
    Ok(())
}
async fn begin(f: &Fixture, id: &str) -> Result<BeginDelegatedThreadRun, String> {
    let r = f.request(id).await?;
    f.assembly
        .delegated_entry
        .as_ref()
        .ok_or("missing entry")?
        .begin(r.clone())
        .await
        .map_err(text)?;
    Ok(r)
}
async fn claim(f: &Fixture, id: &str) -> Result<RunExecutionLease, String> {
    let c = f
        .assembly
        .run_runtime
        .claim_dispatch()
        .await
        .map_err(text)?
        .ok_or("missing dispatch")?;
    assert_eq!(c.lease().run_id().as_str(), id);
    f.assembly
        .run_runtime
        .acknowledge_dispatch(&c)
        .await
        .map_err(text)
}
fn gateway(f: &Fixture) -> AuthorizedAgentToolGateway {
    AuthorizedAgentToolGateway::with_sequence_and_cancellations(
        f.assembly.application.clone(),
        Arc::new(PostgresAgentAuthorizationSource::new(
            f.pool.clone(),
            f.auth.deployment().clone(),
            f.auth.tenant().clone(),
            true,
        )),
        Arc::new(PostgresAgentToolSequence::new(f.pool.clone())),
        f.assembly.tool_cancellations.clone(),
    )
}
async fn row(f: &Fixture, id: &str) -> Result<(String, Option<String>, i64), String> {
    let c = f.pool.get().await.map_err(text)?;
    let r=c.query_one("SELECT status,error_code,(SELECT count(*) FROM public.tool_attempts a JOIN public.tool_calls t USING(tool_call_id) WHERE t.run_id=r.run_id AND a.status IN ('executing','completed','reconciliation_required')) FROM public.runs r WHERE run_id=$1",&[&id]).await.map_err(text)?;
    Ok((r.get(0), r.get(1), r.get(2)))
}
async fn row_pool(
    pool: &openbot_infra::db::pool::DatabasePool,
    id: &str,
) -> Result<String, String> {
    let c = pool.get().await.map_err(text)?;
    Ok(
        c.query_one("SELECT status FROM public.runs WHERE run_id=$1", &[&id])
            .await
            .map_err(text)?
            .get(0),
    )
}
async fn close(f: Fixture) {
    f.assembly.shutdown().await;
    f.pool.close();
}
fn refused(e: &AppError) -> bool {
    matches!(e,AppError::PolicyRefused{rule,..} if rule=="delegated_authority_refused")
}
fn not_current(e: &AppError) -> bool {
    matches!(e,AppError::PolicyRefused{rule,..} if rule=="delegation_not_current")
}
fn tool_command(l: &RunExecutionLease, name: &str, seq: u64) -> AppCommand {
    AppCommand::InvokeTool(ToolInvocation {
        call_id: ToolCallId::new(format!("{}-call-{seq}", l.run_id().as_str())),
        run_id: l.run_id().clone(),
        bot_id: l.bot_id().clone(),
        call_seq: seq,
        tool_name: name.into(),
        arguments: if name == "remember" {
            remember()
        } else {
            json!({})
        },
    })
}

// A synthetic current catalog uses the exact stored hash and transport identity consumed by
// the original authenticator. No credential or authority is supplied by the callback payload.
async fn callback_token(f: &Fixture) -> Result<String, String> {
    let schema = json!({"type":"object","properties":{},"additionalProperties":false});
    let schema_hash = Sha256Digest::of(&serde_json::to_vec(&schema).map_err(text)?).to_hex();
    let endpoint = "https://fixture.invalid/mcp";
    let mut identity = CanonicalWriter::new("openbot:mcp-transport:v2");
    identity.str(endpoint);
    identity.str("fixture");
    identity.str("custom");
    identity.str("mcp");
    identity.u64(0);
    identity.str("2026-07-28");
    let fingerprint = identity.digest_of_written().to_hex();
    let c = f.pool.get().await.map_err(text)?;
    c.execute("UPDATE public.agents SET type='remote_ag_ui',configuration='{\"endpoint\":\"https://fixture.invalid\"}' WHERE id='delegated-bot'",&[]).await.map_err(text)?;
    c.execute("INSERT INTO public.mcp_servers(id,title,vendor,url,provenance,catalog_generation,catalog_hash,catalog_transport_fingerprint,egress_allow_cidrs) VALUES('fixture','Fixture','fixture',$1,'custom',1,repeat('0',64),$2,ARRAY[]::text[]) ON CONFLICT(id) DO NOTHING",&[&endpoint,&fingerprint]).await.map_err(text)?;
    for (name, effect) in [("read", "read"), ("write", "write")] {
        c.execute("INSERT INTO public.mcp_tools(server_id,name,description,input_schema,schema_hash,effect,catalog_generation,first_seen_at,last_seen_at,available) VALUES('fixture',$1,'Synthetic tool',$2,$3,$4,1,clock_timestamp(),clock_timestamp(),true) ON CONFLICT(server_id,name) DO NOTHING",&[&name,&schema,&schema_hash,&effect]).await.map_err(text)?;
        c.execute("INSERT INTO public.plugin_grants(kind,ref,agent_id,granted_by,state,catalog_generation,schema_hash,effect,transport_fingerprint,credential_generation) VALUES('mcp','fixture/'||$1,'delegated-bot','dev-local-user','active',1,$2,$3,$4,0) ON CONFLICT DO NOTHING",&[&name,&schema_hash,&effect,&fingerprint]).await.map_err(text)?;
    }
    drop(c);
    let actual = f
        .assembly
        .mcp_catalog
        .granted_tools(&BotId::new("delegated-bot"), f.auth.actor())
        .await
        .map_err(text)?;
    assert_eq!(actual.len(), 2);
    let reply = f
        .assembly
        .application
        .execute(
            f.auth.clone(),
            AppCommand::IssueAgentCallbackToken {
                agent_id: BotId::new("delegated-bot"),
            },
        )
        .await
        .map_err(text)?;
    match reply {
        AppReply::AgentCallbackToken(t) => Ok(t.expose().to_owned()),
        _ => Err("callback token reply".into()),
    }
}
async fn assertion(
    f: &Fixture,
    l: &RunExecutionLease,
    age: i64,
    scope: Option<RemoteRunScope>,
) -> Result<Value, String> {
    let c = f.pool.get().await.map_err(text)?;
    let now: i64 = c
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .map_err(text)?
        .get(0);
    let tools = RemoteToolSet::new([READ, WRITE]).map_err(text)?;
    let s = scope.unwrap_or_else(|| RemoteRunScope {
        deployment: f.auth.deployment().clone(),
        tenant: f.auth.tenant().clone(),
        bot: l.bot_id().clone(),
        actor: l.actor_id().clone(),
        run: l.run_id().clone(),
    });
    Ok(Value::String(
        f.signer.mint(s, &tools, now - age).map_err(text)?,
    ))
}
async fn authorize(
    f: &Fixture,
    l: &RunExecutionLease,
    token: &str,
    tool: &str,
) -> Result<RemoteCallbackAuthorization, String> {
    let signed = assertion(f, l, 0, None).await?;
    let a = f
        .assembly
        .remote_callback_auth
        .authorize(token, &signed, tool)
        .await
        .map_err(text)?;
    assert!(a.auth().delegation().is_some());
    assert_eq!(a.run(), l.run_id());
    assert_eq!(a.thread(), l.thread_id());
    Ok(a)
}
async fn terminal_once(f: &Fixture, id: &str, state: &str) -> Result<(), String> {
    let c = f.pool.get().await.map_err(text)?;
    let r=c.query_one("SELECT status,error_code,(SELECT count(*) FROM public.run_events e WHERE e.run_id=r.run_id AND e.seq=r.terminal_event_seq) FROM public.runs r WHERE run_id=$1",&[&id]).await.map_err(text)?;
    assert_eq!(r.get::<_, String>(0), state);
    assert_eq!(
        r.get::<_, Option<String>>(1),
        Some(
            if state == "reconciliation_required" {
                "journal_commit_unknown"
            } else {
                "delegation_not_current"
            }
            .into()
        )
    );
    assert_eq!(r.get::<_, i64>(2), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn sampling_and_each_effect_remint_same_persisted_delegation() {
    with_temp_database(
        &admin_config("delegated_sampling"),
        "delegatedsampling",
        |config| async move {
            let p = Arc::new(Provider::default());
            let f = Fixture::with_options(
                &config,
                Options {
                    extensions: vec![(
                        ProviderExtensionKey::new("fake_host").map_err(text)?,
                        p.clone(),
                    )],
                    ..Options::default()
                },
            )
            .await?;
            let result: Result<(), String> = async {
                allow(&f).await?;
                // Revision zero, an empty owner template and a compatible long Unicode core RunId
                // remain legal; source and trigger retain their separate bounded ASCII contract.
                *f.authority.state.lock().unwrap() = Ok(DelegationGrant::new(
                    f.auth.actor().clone(),
                    BotId::new("delegated-bot"),
                    0,
                    f.auth.auth_generation(),
                    None,
                    None,
                    String::new(),
                ));
                let mut r = f.request("sampling").await?;
                r.revision = 0;
                r.run_id = RunId::new(format!("运行{}", "x".repeat(160)));
                f.assembly
                    .delegated_entry
                    .as_ref()
                    .unwrap()
                    .begin(r.clone())
                    .await
                    .map_err(text)?;
                let l = claim(&f, r.run_id.as_str()).await?;
                let before = f.authority.calls.load(Ordering::SeqCst);
                let source = PostgresAgentContextSource::new(
                    f.pool.clone(),
                    f.auth.deployment().clone(),
                    f.auth.tenant().clone(),
                    Some(32),
                )
                .map_err(text)?
                .with_extensions(f.assembly.provider_extensions.clone());
                let request = source.load(&l).await.map_err(text)?;
                ProviderRouter::new(Arc::new(Provider::default()), None)
                    .with_extensions(f.assembly.provider_extensions.clone())
                    .start(request)
                    .await
                    .map_err(text)?;
                assert_eq!(p.calls.load(Ordering::SeqCst), 1);
                let g = gateway(&f);
                for phase in 0..2 {
                    let reply = g
                        .invoke(&l, &format!("effect-{phase}"), "remember", remember())
                        .await
                        .map_err(text)?;
                    assert!(reply.error_code().is_none(), "{reply:?}");
                    l.check_delegated_sampling().await.map_err(text)?;
                }
                assert!(f.authority.calls.load(Ordering::SeqCst) >= before + 7);
                assert_eq!(row(&f, r.run_id.as_str()).await?.2, 2);
                let c = f.pool.get().await.map_err(text)?;
                assert_eq!(
                    c.query_one(
                        "SELECT count(*) FROM public.remember_effect_receipts WHERE run_id=$1",
                        &[&r.run_id.as_str()]
                    )
                    .await
                    .map_err(text)?
                    .get::<_, i64>(0),
                    2
                );
                Ok(())
            }
            .await;
            close(f).await;
            result
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn revoked_expired_generation_or_revision_changed_run_fails_before_work() {
    for mode in 0..8 {
        with_temp_database(&admin_config("delegated_revoked"),&format!("revoked{mode}"),|config|async move{
            let p=Arc::new(Provider::default());
            let f=Fixture::with_options(&config,Options {extensions:vec![(ProviderExtensionKey::new("fake_host").map_err(text)?,p.clone())],..Options::default()}).await?;
            let r=begin(&f,"revoked-run").await?;
            if mode==0 {*f.authority.state.lock().unwrap()=Err(DelegationAuthorityError::NotCurrent);} else {
                let generation=if mode==2 {AuthGeneration::new(f.auth.auth_generation().get()+1)} else {f.auth.auth_generation()};
                *f.authority.state.lock().unwrap()=Ok(DelegationGrant::new(if mode==4 {ActorId::new("other-owner")} else {f.auth.actor().clone()},if mode==5 {BotId::new("other-bot")} else {r.bot_id.clone()},if mode==3 {2}else{1},generation,if mode==1 {Some(SystemTime::UNIX_EPOCH)}else{None},None,"Frozen owner template".into()));
                if mode==6 {*f.authority.expected_source.lock().unwrap()=Some(r.source.clone());}
                if mode>=6 {let c=f.pool.get().await.map_err(text)?;c.execute(if mode==6 {"UPDATE public.messages SET content=jsonb_set(content,'{delegation,source,bindingId}','\"other-binding\"') WHERE run_id='revoked-run' AND message_id='revoked-run:input'"} else {"UPDATE public.users SET auth_generation=auth_generation+1 WHERE id='dev-local-user'"},&[]).await.map_err(text)?;}
            }
            let context=PostgresAgentContextSource::new(f.pool.clone(),f.auth.deployment().clone(),f.auth.tenant().clone(),Some(32)).map_err(text)?.with_extensions(f.assembly.provider_extensions.clone());
            let agent=BuiltInAgentRuntime::start(f.assembly.run_runtime.clone(),Arc::new(context),Arc::new(ProviderRouter::new(Arc::new(Provider::default()),None).with_extensions(f.assembly.provider_extensions.clone())),Arc::new(NoAgentToolInvoker),Arc::new(NoAgentAudit),BuiltInAgentConfig::default()).map_err(|error| format!("{error:?}"))?;
            let relay=RunRelay::start(f.assembly.run_runtime.clone(),agent.consumer());
            let result:Result<(),String>=async{
                tokio::time::timeout(Duration::from_secs(10),async{loop{if row(&f,"revoked-run").await?.0!="running" {return Ok::<_,String>(());}tokio::time::sleep(Duration::from_millis(10)).await;}}).await.map_err(text)??;
                terminal_once(&f,"revoked-run","failed").await?;assert_eq!(p.calls.load(Ordering::SeqCst),0);assert_eq!(row(&f,"revoked-run").await?.2,0);Ok(())
            }.await;
            relay.stop().await;agent.stop().await;close(f).await;result
        }).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn callback_rechecks_after_authentication_before_actual_invoke() {
    for approved in [false, true] {
        for round in 0..10 {
            with_temp_database(
                &admin_config("callback_recheck"),
                &format!("callbackrecheck{approved}{round}"),
                |config| async move {
                    let f = Fixture::new(&config).await?;
                    allow(&f).await?;
                    let token = callback_token(&f).await?;
                    begin(&f, "callback").await?;
                    let l = claim(&f, "callback").await?;
                    let ordinary = l
                        .remint_delegated_auth()
                        .await
                        .map_err(text)?
                        .ok_or("missing ordinary proof")?;
                    let authorization =
                        authorize(&f, &l, &token, if approved { WRITE } else { READ }).await?;
                    let result: Result<(), String> = async {
                        if approved {
                            let g = gateway(&f);
                            let invoke = tokio::spawn(async move {
                                g.invoke_callback(authorization, WRITE, json!({})).await
                            });
                            let pending = tokio::time::timeout(Duration::from_secs(5), async {
                                loop {
                                    let reply = f
                                        .assembly
                                        .application
                                        .execute(
                                            f.auth.clone(),
                                            AppCommand::ListPendingToolApprovals,
                                        )
                                        .await
                                        .map_err(text)?;
                                    if let AppReply::PendingToolApprovals(page) = reply
                                        && let Some(p) = page.approvals.into_iter().next()
                                    {
                                        return Ok::<_, String>(p);
                                    }
                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                }
                            })
                            .await
                            .map_err(text)??;
                            // Hold only the controlled authority port while the real approval commits.
                            // The worker cannot complete the post-approval recheck until it sees revocation.
                            let authority = f.authority.clone();
                            let (locked_tx, locked_rx) = std::sync::mpsc::channel();
                            let (release_tx, release_rx) = std::sync::mpsc::channel();
                            let holder = std::thread::spawn(move || {
                                let mut s = authority.state.lock().unwrap();
                                locked_tx.send(()).unwrap();
                                release_rx.recv().unwrap();
                                *s = Err(DelegationAuthorityError::NotCurrent);
                            });
                            locked_rx
                                .recv_timeout(Duration::from_secs(2))
                                .map_err(text)?;
                            let decision = f
                                .assembly
                                .application
                                .execute(
                                    f.auth.clone(),
                                    AppCommand::DecideToolApproval {
                                        approval_id: pending.approval_id,
                                        decision: ToolApprovalDecision::Grant,
                                    },
                                )
                                .await;
                            release_tx.send(()).map_err(text)?;
                            holder
                                .join()
                                .map_err(|_| "authority barrier thread panic".to_owned())?;
                            decision.map_err(text)?;
                            assert_eq!(
                                invoke.await.map_err(text)?,
                                Err(AgentToolInvokeError::DelegationNotCurrent)
                            );
                        } else {
                            if round%3==0 {
                                *f.authority.state.lock().unwrap()=Err(DelegationAuthorityError::NotCurrent);
                            } else {
                                let c=f.pool.get().await.map_err(text)?;
                                c.execute(if round%3==1 {"UPDATE public.users SET auth_generation=auth_generation+1 WHERE id='dev-local-user'"} else {"DELETE FROM public.user_roles WHERE user_id='dev-local-user'"},&[]).await.map_err(text)?;
                            }
                            let before = f.image().await?;
                            let ordinary_result = f
                                .assembly
                                .application
                                .execute(ordinary, tool_command(&l, READ, 700))
                                .await
                                .unwrap_err();
                            assert!(not_current(&ordinary_result));
                            assert_eq!(
                                f.image().await?,
                                before,
                                "ordinary lease proof must not use callback terminal bridge"
                            );
                            assert_eq!(
                                gateway(&f)
                                    .invoke_callback(authorization, READ, json!({}))
                                    .await,
                                Err(AgentToolInvokeError::DelegationNotCurrent)
                            );
                        }
                        terminal_once(&f, "callback", "failed").await?;
                        assert_eq!(row(&f, "callback").await?.2, 0);
                        Ok(())
                    }
                    .await;
                    close(f).await;
                    result
                },
            )
            .await;
        }
    }
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn invalid_callback_cannot_terminalize_any_run() {
    with_temp_database(
        &admin_config("callback_invalid"),
        "callbackinvalid",
        |config| async move {
            let f = Fixture::new(&config).await?;
            let token = callback_token(&f).await?;
            begin(&f, "invalid").await?;
            let l = claim(&f, "invalid").await?;
            let result: Result<(), String> = async {
                let signed = assertion(&f, &l, 0, None).await?;
                let wrong = RemoteRunScope {
                    deployment: f.auth.deployment().clone(),
                    tenant: f.auth.tenant().clone(),
                    bot: BotId::new("wrong-bot"),
                    actor: l.actor_id().clone(),
                    run: l.run_id().clone(),
                };
                for (presented, assertion, tool) in [
                    ("bad-token".to_owned(), signed.clone(), READ),
                    (token.clone(), json!("bad.signature"), READ),
                    (token.clone(), assertion(&f, &l, 700_000, None).await?, READ),
                    (
                        token.clone(),
                        assertion(&f, &l, 0, Some(wrong)).await?,
                        READ,
                    ),
                    (token.clone(), signed.clone(), "mcp__fixture__absent"),
                ] {
                    let before = f.image().await?;
                    assert!(
                        f.assembly
                            .remote_callback_auth
                            .authorize(&presented, &assertion, tool)
                            .await
                            .is_err()
                    );
                    assert_eq!(f.image().await?, before);
                }
                for scope in [
                    RemoteRunScope {deployment:f.auth.deployment().clone(),tenant:f.auth.tenant().clone(),bot:l.bot_id().clone(),actor:ActorId::new("other-owner"),run:l.run_id().clone()},
                    RemoteRunScope {deployment:f.auth.deployment().clone(),tenant:f.auth.tenant().clone(),bot:l.bot_id().clone(),actor:l.actor_id().clone(),run:RunId::new("wrong-run")},
                    RemoteRunScope {deployment:openbot_contracts::ids::DeploymentId::new("wrong-deployment"),tenant:f.auth.tenant().clone(),bot:l.bot_id().clone(),actor:l.actor_id().clone(),run:l.run_id().clone()},
                    RemoteRunScope {deployment:f.auth.deployment().clone(),tenant:openbot_contracts::ids::TenantId::new("wrong-tenant"),bot:l.bot_id().clone(),actor:l.actor_id().clone(),run:l.run_id().clone()},
                ] {
                    let wrong=assertion(&f,&l,0,Some(scope)).await?;
                    let before=f.image().await?;
                    assert!(f.assembly.remote_callback_auth.authorize(&token,&wrong,READ).await.is_err());
                    assert_eq!(f.image().await?,before);
                }
                let c=f.pool.get().await.map_err(text)?;
                let now:i64=c.query_one("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",&[]).await.map_err(text)?.get(0);drop(c);
                let wrong_set=json!(f.signer.mint(RemoteRunScope {deployment:f.auth.deployment().clone(),tenant:f.auth.tenant().clone(),bot:l.bot_id().clone(),actor:l.actor_id().clone(),run:l.run_id().clone()},&RemoteToolSet::empty(),now).map_err(text)?);
                let before=f.image().await?;
                assert!(f.assembly.remote_callback_auth.authorize(&token,&wrong_set,READ).await.is_err());
                assert_eq!(f.image().await?,before);
                let a = authorize(&f, &l, &token, READ).await?;
                let original = a.auth();
                let d = original.delegation().unwrap();
                let equal = AuthContextBuilder::from_verified_delegation(
                    original.deployment().clone(),
                    original.tenant().clone(),
                    original.actor().clone(),
                    original.auth_generation(),
                    true,
                    VerifiedDelegation::from_verified_grant(
                        d.source().clone(),
                        d.revision(),
                        d.trigger_id().into(),
                        d.granted_generation(),
                        d.expires_at(),
                    )
                    .map_err(text)?,
                )
                .with_roles(original.roles().clone())
                .build();
                assert_eq!(equal, *original);
                let before = f.image().await?;
                let e = f
                    .assembly
                    .application
                    .execute(equal, tool_command(&l, READ, 900))
                    .await
                    .unwrap_err();
                assert!(refused(&e));
                assert_eq!(f.image().await?, before);
                for (run, thread, bot) in [
                    (
                        RunId::new("wrong-run"),
                        l.thread_id().clone(),
                        l.bot_id().clone(),
                    ),
                    (
                        l.run_id().clone(),
                        ThreadId::new("wrong-thread"),
                        l.bot_id().clone(),
                    ),
                    (
                        l.run_id().clone(),
                        l.thread_id().clone(),
                        BotId::new("wrong-bot"),
                    ),
                ] {
                    let a = authorize(&f, &l, &token, READ).await?;
                    let forged = RunExecutionLease::new(
                        run,
                        thread,
                        bot,
                        l.actor_id().clone(),
                        l.fencing(),
                        l.next_event_sequence(),
                    )
                    .map_err(text)?;
                    let before = f.image().await?;
                    let command = if forged.thread_id() != l.thread_id() {
                        AppCommand::AwaitComponentHumanDecision(ComponentHumanDecisionRequest {
                            decision_id: "synthetic-wrong-thread".into(),
                            provider_call_id: "provider-wrong-thread".into(),
                            run_id: forged.run_id().clone(),
                            thread_id: forged.thread_id().clone(),
                            agent_id: forged.bot_id().clone(),
                            component_name: "askApproval".into(),
                            arguments: json!({}),
                        })
                    } else {
                        tool_command(&forged, READ, 901)
                    };
                    let e = f
                        .assembly
                        .application
                        .execute(a.auth().clone(), command)
                        .await
                        .unwrap_err();
                    assert!(refused(&e));
                    assert_eq!(f.image().await?, before);
                }
                // A real proof is consumed by the component command; it cannot become a callback tool proof.
                let a = authorize(&f, &l, &token, READ).await?;
                let component = f
                    .assembly
                    .application
                    .execute(
                        a.auth().clone(),
                        AppCommand::DecideComponent {
                            component_name: "not-published".into(),
                            request: ComponentDecisionRequest {
                                agent_id: l.bot_id().clone(),
                                functions: vec![],
                            },
                        },
                    )
                    .await;
                assert!(!matches!(&component,Err(e) if refused(e)));
                let before = f.image().await?;
                let e = f
                    .assembly
                    .application
                    .execute(a.auth().clone(), tool_command(&l, READ, 902))
                    .await
                    .unwrap_err();
                assert!(refused(&e));
                assert_eq!(f.image().await?, before);
                assert!(
                    authorize(&f, &l, &token, READ)
                        .await?
                        .auth()
                        .delegation()
                        .is_some()
                );
                assert_eq!(row(&f, "invalid").await?.0, "running");
                begin(&f,"expired-proof").await?;
                let expiring=claim(&f,"expired-proof").await?;
                let c=f.pool.get().await.map_err(text)?;
                c.execute("UPDATE public.thread_leases SET expires_at=clock_timestamp()+interval '1 second' WHERE thread_id=$1",&[&expiring.thread_id().as_str()]).await.map_err(text)?;drop(c);
                let expired=authorize(&f,&expiring,&token,READ).await?;
                let before=f.image().await?;
                tokio::time::sleep(Duration::from_millis(1100)).await;
                assert!(refused(&f.assembly.application.execute(expired.auth().clone(),tool_command(&expiring,READ,903)).await.unwrap_err()));
                assert_eq!(f.image().await?,before);
                Ok(())
            }
            .await;
            if let Err(error)=result {close(f).await;return Err(error);}
            // Keep only the actual Application and callback-origin proof, then release the runtime.
            // The store's Weak binding must become unavailable without a coordinator/lease cycle.
            let proof=authorize(&f,&l,&token,READ).await?;
            let application=f.assembly.application.clone();
            let weak_runtime=Arc::downgrade(&f.assembly.run_runtime);
            f.assembly.shutdown().await;
            assert!(weak_runtime.upgrade().is_none());
            *f.authority.state.lock().unwrap()=Err(DelegationAuthorityError::NotCurrent);
            let error=application.execute(proof.auth().clone(),tool_command(&l,READ,904)).await.unwrap_err();
            assert!(matches!(error,AppError::DependencyUnavailable {dependency:"delegation_terminal"}));
            assert_eq!(row_pool(&f.pool,"invalid").await?,"running");
            drop(application);f.pool.close();
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn same_owner_two_runs_and_same_source_two_triggers_never_share_proof() {
    with_temp_database(&admin_config("callback_isolation"),"callbackisolation",|config|async move{
        let f=Fixture::new(&config).await?;let token=callback_token(&f).await?;
        begin(&f,"sibling-a").await?;let a=claim(&f,"sibling-a").await?;
        begin(&f,"sibling-b").await?;let b=claim(&f,"sibling-b").await?;
        let result:Result<(),String>=async{
            let proof=authorize(&f,&a,&token,READ).await?;let before=f.image().await?;
            assert!(refused(&f.assembly.application.execute(proof.auth().clone(),tool_command(&b,READ,800)).await.unwrap_err()));assert_eq!(f.image().await?,before);
            let proof=authorize(&f,&a,&token,READ).await?;
            let c=f.pool.get().await.map_err(text)?;
            c.execute("UPDATE public.messages SET content=jsonb_set(content,'{delegation,triggerId}','\"sibling-b\"') WHERE message_id='sibling-a:input'",&[]).await.map_err(text)?;drop(c);
            let before=f.image().await?;
            assert!(f.assembly.application.execute(proof.auth().clone(),tool_command(&a,READ,801)).await.is_err());assert_eq!(f.image().await?,before);
            assert_eq!(row(&f,"sibling-a").await?.0,"running");assert_eq!(row(&f,"sibling-b").await?.0,"running");Ok(())
        }.await;close(f).await;result
    }).await;
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn legal_component_chain_refreshes_proof_for_each_command() {
    with_temp_database(
        &admin_config("component_chain"),
        "componentchain",
        |config| async move {
            let f = Fixture::new(&config).await?;
            allow(&f).await?;
            begin(&f, "chain").await?;
            let l = claim(&f, "chain").await?;
            let result: Result<(), String> = async {
                f.assembly.application.execute(f.auth.clone(),AppCommand::SyncComponentCatalogue(ComponentCatalogueRequest {components:compiled_component_manifest()})).await.map_err(text)?;
                let saved=f.assembly.application.execute(f.auth.clone(),AppCommand::SaveSandboxedComponent(serde_json::from_value(json!({"slug":"delegated_ui","title":"Delegated UI","description":"Show synthetic information","html":"<p>Synthetic information</p>","css":"","jsFunctions":"","argumentSchema":{"type":"object","properties":{},"additionalProperties":false},"sampleArguments":{}})).map_err(text)?)).await.map_err(text)?;
                let AppReply::SandboxedComponent(saved)=saved else{return Err("sandbox save reply".into());};
                f.assembly.application.execute(f.auth.clone(),AppCommand::PublishSandboxedComponent {component_name:saved.component.name,expected_revision:saved.component.editing_revision}).await.map_err(text)?;
                let g = gateway(&f);
                let before = f.authority.calls.load(Ordering::SeqCst);
                for i in 0..2 {
                    let reply = g
                        .invoke(&l, &format!("ordinary-{i}"), "remember", remember())
                        .await
                        .map_err(text)?;
                    assert!(reply.error_code().is_none());
                }
                for command in [
                    AppCommand::DecideComponent {
                        component_name: "askApproval".into(),
                        request: ComponentDecisionRequest {
                            agent_id: l.bot_id().clone(),
                            functions: vec![],
                        },
                    },
                    AppCommand::AuthorizeSandboxedComponent {
                        component_name: "custom_delegated_ui".into(),
                        agent_id: l.bot_id().clone(),
                        arguments: json!({}),
                    },
                ] {
                    let auth = l
                        .remint_delegated_auth()
                        .await
                        .map_err(text)?
                        .ok_or("missing reminted auth")?;
                    let result = f
                        .assembly
                        .application
                        .execute(auth.clone(), command.clone())
                        .await;
                    assert!(matches!(&result,Ok(AppReply::ComponentDecision(decision)) if decision.allowed),"{result:?}");
                    assert!(refused(
                        &f.assembly
                            .application
                            .execute(auth, command)
                            .await
                            .unwrap_err()
                    ));
                }
                let auth=l.remint_delegated_auth().await.map_err(text)?.ok_or("human command missing proof")?;
                let app=f.assembly.application.clone();
                let human_auth=auth.clone();
                let human_command=AppCommand::AwaitComponentHumanDecision(ComponentHumanDecisionRequest {decision_id:uuid::Uuid::now_v7().to_string(),provider_call_id:"chain-human".into(),run_id:l.run_id().clone(),thread_id:l.thread_id().clone(),agent_id:l.bot_id().clone(),component_name:"askApproval".into(),arguments:json!({"title":"Synthetic approval","summary":"Continue this synthetic task"})});
                let human=tokio::spawn(async move {app.execute(human_auth,human_command).await});
                let pending=tokio::time::timeout(Duration::from_secs(5),async {loop {
                    let reply=f.assembly.application.execute(f.auth.clone(),AppCommand::ListPendingComponentHumanDecisions).await.map_err(text)?;
                    if let AppReply::PendingComponentHumanDecisions(page)=reply && let Some(p)=page.decisions.into_iter().next(){return Ok::<_,String>(p);}
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }}).await.map_err(text)??;
                f.assembly.application.execute(f.auth.clone(),AppCommand::ResolveComponentHumanDecision {decision_id:pending.decision_id,answer:ComponentHumanDecisionAnswer::Approval(ComponentApprovalAnswer {decision:ComponentApprovalDecision::Approved,note:None})}).await.map_err(text)?;
                assert!(matches!(human.await.map_err(text)?.map_err(text)?,AppReply::ComponentHumanDecisionResolved(_)));
                assert!(refused(&f.assembly.application.execute(auth,tool_command(&l,"remember",950)).await.unwrap_err()));
                let auth = l.remint_delegated_auth().await.map_err(text)?.unwrap();
                assert!(refused(
                    &f.assembly
                        .application
                        .execute(
                            auth,
                            AppCommand::IssueAgentCallbackToken {
                                agent_id: l.bot_id().clone()
                            }
                        )
                        .await
                        .unwrap_err()
                ));
                assert!(f.authority.calls.load(Ordering::SeqCst) >= before + 8);
                assert_eq!(row(&f, "chain").await?.2, 2);
                Ok(())
            }
            .await;
            close(f).await;
            result
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn callback_revocation_preserves_started_effect_unknown() {
    for unknown in [false, true] {
        for round in 0..10 {
            with_temp_database(&admin_config("callback_uncertain"),&format!("callbackuncertain{unknown}{round}"),|config|async move{
                let proxy=CommitAckProxy::start(&config).await?;
                let f=Fixture::new(&proxy.config).await?;allow(&f).await?;let token=callback_token(&f).await?;
                begin(&f,"uncertain").await?;let l=claim(&f,"uncertain").await?;
                let result:Result<(),String>=async{
                    let reply=gateway(&f).invoke(&l,"original-effect","remember",remember()).await.map_err(text)?;assert!(reply.error_code().is_none());
                    let c=f.pool.get().await.map_err(text)?;
                    c.execute(if unknown {"UPDATE public.tool_attempts SET status='reconciliation_required',commit_state='unknown' WHERE tool_call_id IN(SELECT tool_call_id FROM public.tool_calls WHERE run_id='uncertain')"} else {"UPDATE public.tool_attempts SET status='executing',commit_state=NULL,finished_at=NULL WHERE tool_call_id IN(SELECT tool_call_id FROM public.tool_calls WHERE run_id='uncertain')"},&[]).await.map_err(text)?;drop(c);
                    let a=authorize(&f,&l,&token,READ).await?;
                    *f.authority.state.lock().unwrap()=Err(DelegationAuthorityError::NotCurrent);
                    if unknown {proxy.drop_next_commit_ack();}
                    let result=gateway(&f).invoke_callback(a.clone(),READ,json!({})).await;
                    if unknown {
                        assert_eq!(result,Err(AgentToolInvokeError::ReconciliationRequired));
                        assert_eq!(proxy.dropped.load(Ordering::SeqCst),1);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        assert!(f.notices.0.lock().unwrap().is_empty());
                        // Consumed callback proof cannot blindly retry the uncertain write.
                        assert!(gateway(&f).invoke_callback(a,READ,json!({})).await.is_err());
                        assert_eq!(proxy.dropped.load(Ordering::SeqCst),1);
                    } else {assert_eq!(result,Err(AgentToolInvokeError::DelegationNotCurrent));}
                    terminal_once(&f,"uncertain","reconciliation_required").await?;
                    assert_eq!(row(&f,"uncertain").await?.2,1);
                    let c=f.pool.get().await.map_err(text)?;
                    assert_eq!(c.query_one("SELECT count(*) FROM public.thread_run_occupancy WHERE run_id='uncertain'",&[]).await.map_err(text)?.get::<_,i64>(0),1);
                    assert_eq!(c.query_one("SELECT count(*) FROM public.remember_effect_receipts WHERE run_id='uncertain'",&[]).await.map_err(text)?.get::<_,i64>(0),1);
                    Ok(())
                }.await;close(f).await;proxy.stop().await?;result
            }).await;
        }
    }
}

#[tokio::test]
#[ignore = "requires explicitly injected fresh owned PostgreSQL 17.11"]
async fn restart_remints_from_persisted_record_and_never_extends_deadline() {
    with_temp_database(&admin_config("delegated_restart"),"delegatedrestart",|config|async move{
        let f=Fixture::new(&config).await?;f.grant("Frozen owner template",Some(Duration::from_secs(90)));
        let r=begin(&f,"restart").await?;
        let c=f.pool.get().await.map_err(text)?;
        let deadline:Value=c.query_one("SELECT content->'delegationSnapshot'->'absoluteDeadline' FROM public.messages WHERE message_id='restart:input'",&[]).await.map_err(text)?.get(0);
        c.execute("UPDATE public.thread_leases SET acquired_at=clock_timestamp()-interval '10 seconds',expires_at=clock_timestamp()-interval '1 second',updated_at=clock_timestamp() WHERE thread_id=$1",&[&r.thread_id.as_str()]).await.map_err(text)?;drop(c);
        close(f).await;
        let restarted=Fixture::reopen(&config).await?;restarted.grant("Frozen owner template",Some(Duration::from_secs(90)));
        let result:Result<(),String>=async{
            let l=claim(&restarted,"restart").await?;assert!(l.fencing().get()>1);
            assert_eq!(l.absolute_deadline(),deadline.as_u64().and_then(|n|SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(n))));
            l.check_delegated_sampling().await.map_err(text)?;
            let proof=l.remint_delegated_auth().await.map_err(text)?.ok_or("restart lost persisted delegation")?;
            assert_eq!(proof.delegation().unwrap().trigger_id(),"restart");
            *restarted.authority.state.lock().unwrap()=Err(DelegationAuthorityError::NotCurrent);
            assert!(l.check_delegated_sampling().await.is_err());
            let c=restarted.pool.get().await.map_err(text)?;
            assert_eq!(c.query_one("SELECT content->'delegationSnapshot'->'absoluteDeadline' FROM public.messages WHERE message_id='restart:input'",&[]).await.map_err(text)?.get::<_,Value>(0),deadline);
            assert!(restarted.notices.0.lock().unwrap().is_empty());Ok(())
        }.await;close(restarted).await;result
    }).await;
}
