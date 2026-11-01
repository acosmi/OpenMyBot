use crate::RunExecutionLease;
use crate::delegation::*;
use async_trait::async_trait;
use openbot_contracts::auth::{
    AuthContext, AuthGeneration, DelegationSource, Role, VerifiedDelegation,
};
use openbot_contracts::command::{AppCommand, ThreadRunStarted};
use openbot_contracts::components::{ComponentDecisionRequest, ComponentHumanDecisionRequest};
use openbot_contracts::error::AppError;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, RunId, TenantId, ToolCallId};
use openbot_contracts::tool::ToolInvocation;
use openbot_domain::thread::FencingToken;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, SystemTime};

struct Authority {
    grant: Mutex<Result<DelegationGrant, DelegationAuthorityError>>,
    calls: AtomicUsize,
}
#[async_trait]
impl DelegationAuthority for Authority {
    async fn verify_current(
        &self,
        _: &DeploymentId,
        _: &TenantId,
        _: &DelegationSource,
        _: u64,
    ) -> Result<DelegationGrant, DelegationAuthorityError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.grant.lock().unwrap().clone()
    }
}
struct Store {
    record: Mutex<DelegatedRunRecord>,
    calls: AtomicUsize,
    terminals: AtomicUsize,
}
impl Store {
    fn facts(&self) -> DelegatedOwnerSnapshot {
        let r = self.record.lock().unwrap();
        DelegatedOwnerSnapshot {
            deployment: r.deployment.clone(),
            tenant: r.tenant.clone(),
            owner: r.actor_id.clone(),
            bot_id: r.bot_id.clone(),
            roles: vec![Role::Admin],
            auth_generation: r.granted_generation,
            revoked: false,
            bot_visible: true,
            database_now: SystemTime::now(),
        }
    }
}
#[async_trait]
impl DelegatedRunStore for Store {
    async fn begin(
        &self,
        r: DelegatedBegin,
        i: &dyn DelegatedContextIssuer,
    ) -> Result<ThreadRunStarted, AppError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        i.issue(self.facts())?;
        Ok(ThreadRunStarted {
            thread_id: r.request.thread_id,
            run_id: r.request.run_id,
            message_sequence: 0,
            event_sequence: 0,
            replayed: false,
        })
    }
    async fn load_run(
        &self,
        _: &DeploymentId,
        _: &TenantId,
        _: &RunId,
    ) -> Result<Option<DelegatedRunRecord>, AppError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(self.record.lock().unwrap().clone()))
    }
    async fn remint(
        &self,
        _: DelegatedCurrentRequest,
        i: &dyn DelegatedContextIssuer,
    ) -> Result<AuthContext, AppError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        i.issue(self.facts())
    }
    async fn fail_confirmed_callback(
        &self,
        record: &DelegatedRunRecord,
        lease: &RunExecutionLease,
    ) -> Result<crate::RunWriteReceipt, crate::RunRuntimeError> {
        assert_eq!(&record.run_id, lease.run_id());
        assert_eq!(&record.thread_id, lease.thread_id());
        self.terminals.fetch_add(1, Ordering::SeqCst);
        Ok(crate::RunWriteReceipt {
            run_event_sequence: 1,
            thread_event_sequence: 1,
            message_sequence: None,
            replayed: false,
        })
    }
}
fn fixture() -> (
    Arc<DelegationRuntime>,
    Arc<Authority>,
    Arc<Store>,
    BeginDelegatedThreadRun,
    RunExecutionLease,
) {
    let deployment = DeploymentId::new("dep");
    let tenant = TenantId::new("tenant");
    let thread = ThreadIdentity::new(&deployment).mint_from_entropy([7; 16]);
    let source = DelegationSource::ExternalBinding {
        binding_id: "binding".into(),
    };
    let request = BeginDelegatedThreadRun {
        source: source.clone(),
        revision: 1,
        trigger_id: "event".into(),
        thread_id: thread.clone(),
        run_id: RunId::new("run"),
        bot_id: BotId::new("bot"),
        untrusted_material: None,
    };
    let grant = DelegationGrant::new(
        ActorId::new("owner"),
        request.bot_id.clone(),
        1,
        AuthGeneration::new(2),
        None,
        None,
        "private-template".into(),
    );
    let authority = Arc::new(Authority {
        grant: Mutex::new(Ok(grant)),
        calls: AtomicUsize::new(0),
    });
    let record = DelegatedRunRecord {
        deployment: deployment.clone(),
        tenant: tenant.clone(),
        run_id: request.run_id.clone(),
        thread_id: thread.clone(),
        bot_id: request.bot_id.clone(),
        actor_id: ActorId::new("owner"),
        fencing: FencingToken::new(3).unwrap(),
        source,
        revision: 1,
        trigger_id: "event".into(),
        granted_generation: AuthGeneration::new(2),
        expires_at: None,
        absolute_deadline: SystemTime::now() + Duration::from_secs(1800),
        lease_expires_at: SystemTime::now() + Duration::from_secs(60),
    };
    let lease = RunExecutionLease::new(
        record.run_id.clone(),
        thread,
        record.bot_id.clone(),
        record.actor_id.clone(),
        record.fencing,
        1,
    )
    .unwrap();
    let store = Arc::new(Store {
        record: Mutex::new(record),
        calls: AtomicUsize::new(0),
        terminals: AtomicUsize::new(0),
    });
    let runtime = Arc::new(DelegationRuntime::new(
        deployment,
        tenant,
        true,
        authority.clone(),
        store.clone(),
    ));
    (runtime, authority, store, request, lease)
}
fn invocation(r: &BeginDelegatedThreadRun) -> AppCommand {
    AppCommand::InvokeTool(ToolInvocation {
        call_id: ToolCallId::new("call"),
        run_id: r.run_id.clone(),
        bot_id: r.bot_id.clone(),
        call_seq: 1,
        tool_name: "remember".into(),
        arguments: serde_json::json!({}),
    })
}

#[tokio::test]
async fn shape_fails_before_authority_and_store() {
    let (runtime, a, s, request, _) = fixture();
    let entry = DelegatedRunEntry::new(runtime);
    let mut cases = Vec::new();
    let mut r = request.clone();
    r.trigger_id = String::new();
    cases.push(r);
    let mut r = request.clone();
    r.trigger_id = "bad space".into();
    cases.push(r);
    let mut r = request.clone();
    r.run_id = RunId::new("");
    cases.push(r);
    let mut r = request.clone();
    r.source = DelegationSource::ExternalBinding {
        binding_id: "x".repeat(129),
    };
    cases.push(r);
    let mut r = request.clone();
    r.trigger_id = "é".into();
    cases.push(r);
    let mut r = request.clone();
    r.bot_id = BotId::new("");
    cases.push(r);
    let mut r = request.clone();
    r.thread_id = openbot_contracts::ids::ThreadId::new("not-a-minted-thread");
    cases.push(r);
    for (source_ref, text) in [
        ("x".repeat(257), "ok".into()),
        ("x".into(), "é".repeat(131073)),
        ("x".into(), "nul\0".into()),
    ] {
        let mut r = request.clone();
        r.untrusted_material = Some(DelegatedUntrustedMaterial { source_ref, text });
        cases.push(r);
    }
    for r in cases {
        assert!(matches!(
            entry.begin(r).await,
            Err(AppError::MalformedPayload { .. })
        ));
    }
    assert_eq!(a.calls.load(Ordering::SeqCst), 0);
    assert_eq!(s.calls.load(Ordering::SeqCst), 0);
    assert!(entry.begin(request).await.is_ok());
    assert_eq!(a.calls.load(Ordering::SeqCst), 1);
    assert_eq!(s.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn grant_failures_preserve_error_precedence() {
    let (runtime, a, s, r, _) = fixture();
    let entry = DelegatedRunEntry::new(runtime);
    let good = a.grant.lock().unwrap().clone().unwrap();
    *a.grant.lock().unwrap() = Err(DelegationAuthorityError::Unavailable);
    assert!(matches!(
        entry.begin(r.clone()).await,
        Err(AppError::DependencyUnavailable {
            dependency: "delegation_authority"
        })
    ));
    *a.grant.lock().unwrap() = Err(DelegationAuthorityError::NotCurrent);
    assert!(
        matches!(entry.begin(r.clone()).await,Err(AppError::PolicyRefused{rule,..}) if rule=="delegation_not_current")
    );
    for grant in [
        DelegationGrant::new(
            ActorId::new("owner"),
            BotId::new("other"),
            1,
            AuthGeneration::new(2),
            None,
            None,
            "template".into(),
        ),
        DelegationGrant::new(
            ActorId::new("owner"),
            r.bot_id.clone(),
            1,
            AuthGeneration::new(2),
            Some(SystemTime::UNIX_EPOCH),
            None,
            "template".into(),
        ),
        DelegationGrant::new(
            ActorId::new("owner"),
            r.bot_id.clone(),
            1,
            AuthGeneration::new(2),
            None,
            Some(Duration::ZERO),
            "template".into(),
        ),
    ] {
        *a.grant.lock().unwrap() = Ok(grant);
        assert!(entry.begin(r.clone()).await.is_err());
    }
    assert_eq!(s.calls.load(Ordering::SeqCst), 0);
    *a.grant.lock().unwrap() = Ok(good);
    assert!(entry.begin(r.clone()).await.is_ok());
    let mut zero = r;
    zero.revision = 0;
    zero.run_id = RunId::new(format!("运行{}", "x".repeat(200)));
    zero.bot_id = BotId::new(format!("机器人{}", "x".repeat(200)));
    let owner = ActorId::new(format!("所有者{}", "x".repeat(200)));
    {
        let mut record = s.record.lock().unwrap();
        record.bot_id = zero.bot_id.clone();
        record.actor_id = owner.clone();
        record.revision = 0;
    }
    *a.grant.lock().unwrap() = Ok(DelegationGrant::new(
        owner,
        zero.bot_id.clone(),
        0,
        AuthGeneration::new(2),
        None,
        None,
        String::new(),
    ));
    assert!(entry.begin(zero).await.is_ok());
}
#[test]
fn debug_never_exposes_template_material_or_ids() {
    let (_, a, _, mut r, _) = fixture();
    r.untrusted_material = Some(DelegatedUntrustedMaterial {
        source_ref: "secret-ref".into(),
        text: "secret-material".into(),
    });
    let text = format!(
        "{r:?} {:?} {:?}",
        r.untrusted_material,
        a.grant.lock().unwrap().as_ref().unwrap()
    );
    for secret in [
        "private-template",
        "secret-ref",
        "secret-material",
        "binding",
        "owner",
    ] {
        assert!(!text.contains(secret));
    }
    assert_eq!(
        r.untrusted_material.as_ref().unwrap().text,
        "secret-material"
    );
}
#[tokio::test]
async fn run_proof_requires_exact_context_object_and_scope() {
    let (runtime, _, store, r, lease) = fixture();
    let auth = runtime.remint_lease(&lease).await.unwrap();
    let v = auth.delegation().unwrap();
    let copy = AuthContext::for_test_delegated(
        auth.deployment().clone(),
        auth.tenant().clone(),
        auth.actor().clone(),
        auth.roles().clone(),
        auth.auth_generation(),
        true,
        VerifiedDelegation::from_verified_grant(
            v.source().clone(),
            v.revision(),
            v.trigger_id().into(),
            v.granted_generation(),
            v.expires_at(),
        )
        .unwrap(),
    );
    assert_eq!(copy, auth);
    assert!(runtime.admit_command(&copy, &invocation(&r)).await.is_err());
    let mut wrong = r.clone();
    wrong.run_id = RunId::new("another");
    assert!(
        runtime
            .admit_command(&auth, &invocation(&wrong))
            .await
            .is_err()
    );
    for field in 0..5 {
        let auth = runtime.remint_lease(&lease).await.unwrap();
        {
            let mut record = store.record.lock().unwrap();
            match field {
                0 => {
                    record.thread_id =
                        ThreadIdentity::new(auth.deployment()).mint_from_entropy([9; 16])
                }
                1 => record.bot_id = BotId::new("other"),
                2 => record.actor_id = ActorId::new("other"),
                3 => record.granted_generation = AuthGeneration::new(3),
                _ => record.fencing = FencingToken::new(4).unwrap(),
            }
        }
        assert!(runtime.admit_command(&auth, &invocation(&r)).await.is_err());
        let (_, _, reset, _, _) = fixture();
        *store.record.lock().unwrap() = reset.record.lock().unwrap().clone();
    }
    let auth = runtime.remint_lease(&lease).await.unwrap();
    assert!(runtime.admit_command(&auth, &invocation(&r)).await.is_ok());
}
#[tokio::test]
async fn run_proof_is_single_use_and_cross_command_replay_is_refused() {
    for _ in 0..10 {
        let (runtime, _, _, r, lease) = fixture();
        let auth = runtime.remint_lease(&lease).await.unwrap();
        let command = invocation(&r);
        let (one, two) = tokio::join!(
            runtime.admit_command(&auth, &command),
            runtime.admit_command(&auth, &command)
        );
        assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
        assert!(
            runtime
                .admit_command(
                    &auth,
                    &AppCommand::AuthorizeSandboxedComponent {
                        component_name: "sandbox".into(),
                        agent_id: r.bot_id.clone(),
                        arguments: serde_json::json!({})
                    }
                )
                .await
                .is_err()
        );
    }

    let (runtime, authority, store, r, lease) = fixture();
    // A full matching nondelegated original scope is required even in the in-memory port fixture.
    let original = crate::RemoteCallbackAuthorization::new(
        openbot_contracts::auth::AuthContextBuilder::from_verified_session(
            DeploymentId::new("dep"),
            TenantId::new("tenant"),
            lease.actor_id().clone(),
            AuthGeneration::new(2),
            true,
        )
        .with_role(Role::Admin)
        .build(),
        r.run_id.clone(),
        r.thread_id.clone(),
        r.bot_id.clone(),
    );
    let callback = runtime.remint_callback(&original, &lease).await.unwrap();
    *authority.grant.lock().unwrap() = Err(DelegationAuthorityError::NotCurrent);
    let command = invocation(&r);
    let (first, second) = tokio::join!(
        runtime.admit_command(&callback, &command),
        runtime.admit_command(&callback, &command)
    );
    assert!(first.is_err() && second.is_err());
    assert_eq!(store.terminals.load(Ordering::SeqCst), 1);
    assert!(runtime.admit_command(&callback, &command).await.is_err());
    assert_eq!(store.terminals.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn proof_capacity_expiry_and_terminal_cleanup_fail_closed() {
    let (runtime, authority, store, r, lease) = fixture();
    let future = SystemTime::UNIX_EPOCH + Duration::from_secs(4_000_000_000);
    let invalid = SystemTime::UNIX_EPOCH - Duration::from_secs(1);
    for (grant_expiry, record_expiry, accepted) in [
        (None, None, true),
        (
            Some(future + Duration::from_nanos(999_999)),
            Some(future),
            true,
        ),
        (Some(future), Some(future + Duration::from_millis(1)), false),
        (Some(future), None, false),
        (None, Some(future), false),
        // Conversion failure must not become None and match an absent grant expiry.
        (None, Some(invalid), false),
    ] {
        *authority.grant.lock().unwrap() = Ok(DelegationGrant::new(
            ActorId::new("owner"),
            r.bot_id.clone(),
            1,
            AuthGeneration::new(2),
            grant_expiry,
            None,
            "private-template".into(),
        ));
        store.record.lock().unwrap().expires_at = record_expiry;
        let calls_before = store.calls.load(Ordering::SeqCst);
        let result = runtime.check_sampling(&lease).await;
        if accepted {
            result.unwrap();
            assert_eq!(store.calls.load(Ordering::SeqCst), calls_before + 2);
        } else {
            assert!(matches!(result, Err(AppError::PolicyRefused { rule, .. })
                if rule == "delegation_not_current"));
            assert_eq!(store.calls.load(Ordering::SeqCst), calls_before + 1);
        }
    }

    let (runtime, a, store, r, lease) = fixture();
    runtime.check_sampling(&lease).await.unwrap();
    for _ in 0..256 {
        runtime.remint_lease(&lease).await.unwrap();
    }
    assert!(runtime.remint_lease(&lease).await.is_err());
    runtime.retire_run(&r.run_id);
    let auth = runtime.remint_lease(&lease).await.unwrap();
    assert!(runtime.admit_command(&auth, &invocation(&r)).await.is_ok());
    store.record.lock().unwrap().lease_expires_at = SystemTime::UNIX_EPOCH;
    assert!(runtime.remint_lease(&lease).await.is_err());
    assert!(runtime.check_sampling(&lease).await.is_err());
    *a.grant.lock().unwrap() = Err(DelegationAuthorityError::NotCurrent);
    assert!(runtime.remint_lease(&lease).await.is_err());

    let (runtime, authority, store, r, lease) = fixture();
    store.record.lock().unwrap().lease_expires_at = SystemTime::now() + Duration::from_millis(150);
    let auth = runtime.remint_lease(&lease).await.unwrap();
    let before_authority = authority.calls.load(Ordering::SeqCst);
    let before_store = store.calls.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(runtime.admit_command(&auth, &invocation(&r)).await.is_err());
    assert_eq!(authority.calls.load(Ordering::SeqCst), before_authority);
    assert_eq!(store.calls.load(Ordering::SeqCst), before_store);
}
#[tokio::test]
async fn legal_internal_commands_preserve_fresh_and_sensitive_denials() {
    let (runtime, authority, store, r, lease) = fixture();
    let commands = [
        invocation(&r),
        AppCommand::DecideComponent {
            component_name: "chart".into(),
            request: ComponentDecisionRequest {
                agent_id: r.bot_id.clone(),
                functions: Vec::new(),
            },
        },
        AppCommand::AuthorizeSandboxedComponent {
            component_name: "sandbox".into(),
            agent_id: r.bot_id.clone(),
            arguments: serde_json::json!({}),
        },
        AppCommand::AwaitComponentHumanDecision(ComponentHumanDecisionRequest {
            decision_id: "decision".into(),
            provider_call_id: "provider-call".into(),
            run_id: r.run_id.clone(),
            thread_id: r.thread_id.clone(),
            agent_id: r.bot_id.clone(),
            component_name: "askApproval".into(),
            arguments: serde_json::json!({}),
        }),
    ];
    for command in commands {
        let auth = runtime.remint_lease(&lease).await.unwrap();
        assert!(runtime.admit_command(&auth, &command).await.is_ok());
        assert!(auth.request_binding().is_none());
    }
    let credential = || {
        serde_json::from_value(serde_json::json!({"kind":"model","provider":"fixture","keyId":"fixture","metadata":{},"plaintext":"fixture-only-secret"})).unwrap()
    };
    for command in [
        AppCommand::GetCurrentUser,
        AppCommand::AdminStatus,
        AppCommand::GetUiPreferences,
        AppCommand::UpdateComponentGovernance(
            openbot_contracts::components::ComponentGovernanceMutation::SetPublication {
                component_name: "chart".into(),
                published: true,
            },
        ),
        AppCommand::CreateCredential(credential()),
        AppCommand::RotateCredential {
            credential_id: "credential".into(),
            input: credential(),
        },
        AppCommand::RevokeCredential {
            credential_id: "credential".into(),
        },
        AppCommand::IssueAgentCallbackToken {
            agent_id: r.bot_id.clone(),
        },
        AppCommand::IssueScreenSession(openbot_contracts::screen::ScreenSessionRequest {
            target: openbot_contracts::screen::ScreenSessionTarget {
                computer_id: openbot_contracts::ids::ComputerId::new("computer"),
                computer_generation: openbot_contracts::ids::ComputerGeneration::new(1),
                tab_id: openbot_contracts::ids::TabId::new("tab"),
            },
            binding: openbot_contracts::screen::ScreenViewerBindingRequest::Server {
                origin: "https://fixture.invalid".into(),
            },
        }),
    ] {
        let auth = runtime.remint_lease(&lease).await.unwrap();
        let authority_before = authority.calls.load(Ordering::SeqCst);
        let store_before = store.calls.load(Ordering::SeqCst);
        assert!(
            matches!(runtime.admit_command(&auth,&command).await,Err(AppError::PolicyRefused{rule,..}) if rule=="delegated_authority_refused")
        );
        assert_eq!(authority.calls.load(Ordering::SeqCst), authority_before);
        assert_eq!(store.calls.load(Ordering::SeqCst), store_before);
    }
}
