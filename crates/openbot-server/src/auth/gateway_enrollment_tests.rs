//! Whole original token-owner adoption through the genuine parent Host, PG and TLS fixture.
//! All cases require a separately admitted owned-fixture runtime; SOURCE is not a PASS.
use super::fixture::Fixture;
use super::*;
use openbot_contracts::ids::ActorId;
use openbot_domain::vault::{KeyVersion, SecretKind, SecretPrincipal, ServiceId, WrappingKey};
use openbot_infra::gateway_authority::GatewayConnectionReceipt;
use openbot_infra::gateway_transport::{GatewayAttempt, GatewayHttpOutcomes};
use openbot_infra::vault::CredentialRecordVault;
use openbot_infra::{
    GatewayAuthorizationEnrollmentCleanupState as Cleanup,
    GatewayAuthorizationEnrollmentError as EnrollmentError,
    GatewayAuthorizationEnrollmentKind as Kind, GatewayAuthorizationEnrollmentStage as Stage,
    GatewayAuthorizationEnrollmentWriteTerminal as WriteTerminal,
};
use std::sync::Mutex;

type EnrollmentResult = Result<GatewayConnectionReceipt, EnrollmentError>;

#[derive(Default)]
struct Outcomes(Mutex<Vec<GatewayAttempt>>);
impl GatewayHttpOutcomes for Outcomes {
    fn started(&self, attempt: GatewayAttempt) {
        let mut attempts = self.0.lock().unwrap();
        assert!(attempts.len() < 8, "bounded genuine enrollment attempts");
        attempts.push(attempt);
    }
}
fn vault() -> CredentialRecordVault {
    CredentialRecordVault::single_key(
        TenantId::new(TENANT),
        KeyVersion::new(1),
        WrappingKey::from_bytes(vec![0x43; 32]).unwrap(),
    )
}
fn rejected(result: EnrollmentResult) -> Result<EnrollmentError, String> {
    result
        .err()
        .ok_or_else(|| "enrollment unexpectedly returned a receipt".into())
}
async fn token(
    f: &Fixture,
    parent: CancellationToken,
    deadline: Instant,
) -> Result<(AuthContext, GatewayAuthorizationTokenOwner, AttemptRow), String> {
    let (auth, verified, input) = super::verified(f, parent, deadline).await?;
    let old = f.rows().await?.remove(0);
    let factory = f.factory(Some("/oauth/desktop/register"))?;
    let owner = f
        .journal
        .dispatch_token(&auth, verified, &factory)
        .await
        .map_err(|e| e.to_string())?;
    code_success(f, &old, &owner, &input).await?;
    let admitted = f.row(old.attempt_id).await?;
    Ok((auth, owner, admitted))
}
fn original_id(row: &AttemptRow) -> Result<uuid::Uuid, String> {
    row.enrollment_id
        .ok_or_else(|| "original reservation ID absent".into())
}
async fn sdk_counts(f: &Fixture) -> Result<(i64, i64), String> {
    let client = f.pool.get().await.map_err(|e| e.to_string())?;
    let row = client.query_one("SELECT (SELECT count(*) FROM public.sdk_gateway_connections), (SELECT count(*) FROM public.sdk_gateway_secrets)", &[]).await.map_err(|e| e.to_string())?;
    Ok((row.get(0), row.get(1)))
}
fn no_resend(f: &Fixture) -> Result<(), String> {
    check(
        token_posts(f)?.len() == 1,
        "only the original genuine token POST; no automatic resend",
    )
}
fn consumer_network(f: &Fixture, before: usize, complete: bool) -> Result<(), String> {
    let captures = f.captures()?;
    let calls = captures
        .get(before..)
        .ok_or("capture baseline exceeded actual records")?;
    let metadata = calls
        .iter()
        .filter(|v| v["path"] == "/.well-known/oauth-authorization-server/desktop")
        .count();
    let profile = calls
        .iter()
        .filter(|v| v["path"] == "/api/oauth/profile")
        .count();
    check(
        metadata <= 1 && profile <= 1,
        "no repeated discovery/profile",
    )?;
    if complete {
        check(
            metadata == 1 && profile == 1 && calls.len() == 2,
            "one actual discovery and Bearer profile",
        )?;
    }
    no_resend(f)
}
fn history(
    error: &EnrollmentError,
    metadata: Ack,
    profile: Ack,
    write: WriteTerminal,
    readback: Ack,
) -> Result<(), String> {
    check(
        error.metadata_headers_rollback_ack() == metadata,
        "original metadata rollback fact",
    )?;
    check(
        error.profile_headers_rollback_ack() == profile,
        "original profile rollback fact",
    )?;
    check(
        error.adoption_write_terminal() == write,
        "original write action and ACK fact",
    )?;
    check(
        error.adoption_readback_rollback_ack() == readback,
        "original RO rollback fact",
    )
}
async fn persisted(
    f: &Fixture,
    auth: &AuthContext,
    original: &AttemptRow,
    receipt: &GatewayConnectionReceipt,
    vault: &CredentialRecordVault,
    name: &str,
) -> Result<(), String> {
    let id = original_id(original)?;
    check(
        receipt.id() == id && receipt.revision() == 1 && receipt.credential_generation() == 1,
        "same original connection ID and initial generations",
    )?;
    check(
        f.row(original.attempt_id).await? == *original,
        "all20 original code_admitted journal columns unchanged",
    )?;
    let client = f.pool.get().await.map_err(|e| e.to_string())?;
    let row = client.query_one("SELECT c.name,c.issuer,c.client_id,c.account_id,c.organization_id,c.auth_contract_version,c.error_contract_version,c.enabled,c.revision,c.credential_generation,c.auth_generation,c.state,c.current_secret_id,c.pending_operation_id,c.deleted_at,s.encrypted_value,s.retired_at FROM public.sdk_gateway_connections c JOIN public.sdk_gateway_secrets s ON s.id=c.current_secret_id AND s.connection_id=c.id AND s.credential_generation=c.credential_generation WHERE c.id=$1 AND c.deployment_id=$2 AND c.tenant_id=$3 AND c.owner_user_id=$4", &[&id,&DEP,&TENANT,&auth.actor().as_str()]).await.map_err(|e| e.to_string())?;
    check(
        row.get::<_, String>(0) == name && row.get::<_, String>(1) == f.issuer(),
        "original name bytes and verified issuer",
    )?;
    check(
        row.get::<_, String>(2) == "owned-registration-client"
            && row.get::<_, String>(3) == "owned-account"
            && row.get::<_, Option<String>>(4).as_deref() == Some("owned-org"),
        "actual Bearer profile supplies account and organization",
    )?;
    check(
        row.get::<_, i16>(5) == 2 && row.get::<_, i16>(6) == 1 && row.get::<_, bool>(7),
        "fixed contracts and enabled",
    )?;
    check(
        row.get::<_, i64>(8) == 1
            && row.get::<_, i64>(9) == 1
            && row.get::<_, i64>(10) == 7
            && row.get::<_, String>(11) == "ready",
        "initial persistent authority generations and state",
    )?;
    let secret: uuid::Uuid = row.get(12);
    check(
        row.get::<_, Option<uuid::Uuid>>(13).is_none()
            && row.get::<_, Option<time::OffsetDateTime>>(14).is_none()
            && row.get::<_, Option<time::OffsetDateTime>>(16).is_none(),
        "no pending/deleted/retired credential",
    )?;
    let encrypted: String = row.get(15);
    check(
        !encrypted.contains("owned-access-token") && !encrypted.contains("owned-refresh-token"),
        "persistent envelope never plaintext token bytes",
    )?;
    let opened = vault
        .open(
            &secret,
            SecretKind::Model,
            SecretPrincipal::Actor(auth.actor().clone()),
            SecretPrincipal::Service(ServiceId::new(id.to_string())),
            &encrypted,
        )
        .map_err(|e| e.to_string())?;
    check(!opened.needs_migration(), "v2 envelope only")?;
    let stored: Value =
        serde_json::from_slice(opened.into_secret().expose()).map_err(|e| e.to_string())?;
    check(
        stored["schemaVersion"] == 1
            && stored["connectionId"] == id.to_string()
            && stored["credentialGeneration"] == 1
            && stored["authGeneration"] == 7,
        "durable envelope binds exact connection and generations",
    )?;
    check(
        stored["issuer"] == f.issuer()
            && stored["accountId"] == "owned-account"
            && stored["organizationId"] == "owned-org"
            && stored["clientId"] == "owned-registration-client",
        "durable subject and client",
    )?;
    let tokens = stored["tokens"]
        .as_object()
        .ok_or("six token fields absent")?;
    check(
        tokens.len() == 6
            && tokens["access_token"] == "owned-access-token"
            && tokens["refresh_token"] == "owned-refresh-token"
            && tokens["scope"] == "ai account"
            && tokens["client_id"] == "owned-registration-client"
            && tokens["server_url"] == f.issuer(),
        "five independently known original SDK fields, exact scope bytes",
    )?;
    let expires = tokens["expires_at"]
        .as_str()
        .ok_or("SDK expiration absent")?;
    let expiry =
        time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
            .map_err(|e| e.to_string())?;
    check(
        expires.len() <= 64
            && expiry > time::OffsetDateTime::now_utc()
            && expiry < time::OffsetDateTime::now_utc() + time::Duration::seconds(65),
        "genuine producer bounded SDK expiration; raw producer equality additionally enforced inside sealed adoption and p07",
    )?;
    check(
        vault
            .open(
                &secret,
                SecretKind::Model,
                SecretPrincipal::Actor(ActorId::new("owned-journal-other")),
                SecretPrincipal::Service(ServiceId::new(id.to_string())),
                &encrypted,
            )
            .is_err(),
        "foreign Actor AAD cannot open",
    )?;
    let audits: i64 = client.query_one("SELECT count(*) FROM public.audit_events WHERE event_type='configuration.changed' AND target_kind='sdk_gateway_connection' AND target_id=$1", &[&id.to_string()]).await.map_err(|e| e.to_string())?.get(0);
    check(
        audits == 1,
        "one existing configuration.changed adoption audit",
    )?;
    drop(client);
    check(
        sdk_counts(f).await? == (1, 1),
        "one connection and one secret only",
    )
}

#[derive(Clone, Copy)]
enum ProfilePoint {
    Request,
    Body,
}
async fn pending<F: Future<Output = EnrollmentResult>>(
    f: &Fixture,
    call: &mut Pin<Box<F>>,
    point: ProfilePoint,
) -> Result<(), String> {
    let event = match point {
        ProfilePoint::Request => "profile_request_received",
        ProfilePoint::Body => "profile_body_pending",
    };
    let observed = async {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if f.events()?
                .iter()
                .any(|v| v["event"] == event && v["path"] == "/api/oauth/profile")
            {
                return Ok::<(), String>(());
            }
            if Instant::now() >= until {
                return Err("owned profile barrier not reached".into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::select! { biased; result = &mut *call => return Err(format!("enrollment missed original profile barrier: {result:?}")), result = observed => result?, }
    tokio::select! { biased; result = &mut *call => return Err(format!("enrollment escaped withheld profile: {result:?}")), () = tokio::task::yield_now() => {}, }
    Ok(())
}

async fn success(
    cfg: openbot_infra::db::pool::DatabaseConfig,
    single_user: bool,
) -> Result<(), String> {
    let metadata =
        PgTerminalAckGate::new(&cfg, TerminalStage::EnrollmentMetadataRollback, false).await;
    let profile = PgTerminalAckGate::new(
        &metadata.config,
        TerminalStage::EnrollmentProfileRollback,
        false,
    )
    .await;
    let write =
        PgTerminalAckGate::new(&profile.config, TerminalStage::EnrollmentCommit, false).await;
    let readback = PgTerminalAckGate::new(
        &write.config,
        TerminalStage::EnrollmentReadbackRollback,
        false,
    )
    .await;
    let f = Fixture::new_enrollment(readback.config.clone(), 1).await?;
    let vault = vault();
    let accounts = f.enrollment_accounts(f.pool.clone(), vault.clone())?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let (single, runtime, journal, auth, owner, original) = if single_user {
        let (runtime, journal) = f.fresh_pair()?;
        let single = f.single(&journal).await?;
        let sink = GatewayCallbackUrlSink::new();
        single
            .install_gateway_callback_url_sink(Arc::clone(&sink))
            .map_err(|e| format!("{e:?}"))?;
        let auth = single
            .resolve(
                &http::Request::builder()
                    .uri("/owned-enrollment")
                    .body(())
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .await
            .map_err(|e| e.to_string())?;
        check(
            auth.actor().as_str() == "dev-local-user",
            "genuine SingleUser Host",
        )?;
        let (verified, input) = verified_on(
            &f,
            &journal,
            &auth,
            &sink,
            CancellationToken::new(),
            deadline,
        )
        .await?;
        let old = f.rows().await?.remove(0);
        let factory = f.factory(Some("/oauth/desktop/register"))?;
        let owner = journal
            .dispatch_token(&auth, verified, &factory)
            .await
            .map_err(|e| e.to_string())?;
        code_success(&f, &old, &owner, &input).await?;
        let original = f.row(old.attempt_id).await?;
        (Some(single), Some(runtime), journal, auth, owner, original)
    } else {
        let (auth, owner, original) = token(&f, CancellationToken::new(), deadline).await?;
        (None, None, Arc::clone(&f.journal), auth, owner, original)
    };
    let baseline = f.captures()?.len();
    for relay in [&metadata, &profile, &write, &readback] {
        relay.arm_enrollment();
    }
    let name = "  owned 名称  ";
    let outcomes = Arc::new(Outcomes::default());
    let mut call =
        Box::pin(journal.enroll_token_owner(&auth, owner, &accounts, name, outcomes.clone()));
    for relay in [&metadata, &profile, &write, &readback] {
        tokio::select! { biased; () = relay.held() => {}, result = &mut call => return Err(format!("adoption skipped a real original terminal: {result:?}")), }
        relay.release_original_ack().await;
    }
    let receipt = call.await.map_err(|e| e.to_string())?;
    for relay in [&metadata, &profile, &write, &readback] {
        relay.assert_target(1);
    }
    check(
        outcomes.0.lock().unwrap().len() == 2,
        "two real transport outcomes, no token resend",
    )?;
    consumer_network(&f, baseline, true)?;
    persisted(&f, &auth, &original, &receipt, &vault, name).await?;
    if let Some(single) = single {
        single.close_request_bindings();
    }
    if let Some(runtime) = runtime {
        runtime.close();
    }
    f.finish_enrollment().await?;
    readback.stop().await;
    write.stop().await;
    profile.stop().await;
    metadata.stop().await;
    Ok(())
}

#[derive(Clone, Copy)]
enum AckFault {
    Discard,
    CallerDeadline,
    SqlDeadline,
    CurrentRefused,
}
async fn ack_failure(
    cfg: openbot_infra::db::pool::DatabaseConfig,
    stage: TerminalStage,
    fault: AckFault,
) -> Result<(), String> {
    let discard = matches!(fault, AckFault::Discard);
    let caller_late = matches!(fault, AckFault::CallerDeadline);
    let sql_late = matches!(fault, AckFault::SqlDeadline);
    let revoke = matches!(fault, AckFault::CurrentRefused);
    let require_cleanup_unknown = caller_late;
    let relay = PgTerminalAckGate::new(&cfg, stage, discard).await;
    let f = Fixture::new_enrollment(relay.config.clone(), 1).await?;
    let deadline = Instant::now() + Duration::from_secs(if caller_late { 3 } else { 60 });
    let (auth, owner, original) = token(&f, CancellationToken::new(), deadline).await?;
    let accounts = f.enrollment_accounts(f.pool.clone(), vault())?;
    let baseline = f.captures()?.len();
    relay.arm_enrollment();
    let mut call = Box::pin(f.journal.enroll_token_owner(
        &auth,
        owner,
        &accounts,
        "owned ACK",
        Arc::new(Outcomes::default()),
    ));
    tokio::select! { biased; () = relay.held() => {}, result = &mut call => return Err(format!("enrollment missed original selected ACK: {result:?}")), }
    if revoke {
        f.disarm_host();
    }
    if caller_late {
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline + Duration::from_millis(150),
        ))
        .await;
    }
    if sql_late {
        tokio::time::sleep(Duration::from_millis(5150)).await;
    }
    if !discard {
        relay.release_original_ack().await;
    }
    let error = rejected(call.await)?;
    check(
        error.reserved_connection_id() == Some(original_id(&original)?),
        "all post-entry uncertainty keeps original ID",
    )?;
    let selected = if discard {
        Ack::Unknown
    } else if caller_late || sql_late {
        Ack::Late
    } else {
        Ack::Timely
    };
    match stage {
        TerminalStage::EnrollmentMetadataRollback => history(
            &error,
            selected,
            Ack::NotAttempted,
            WriteTerminal::NotAttempted,
            Ack::NotAttempted,
        )?,
        TerminalStage::EnrollmentProfileRollback => history(
            &error,
            Ack::Timely,
            selected,
            WriteTerminal::NotAttempted,
            Ack::NotAttempted,
        )?,
        TerminalStage::EnrollmentCommit => history(
            &error,
            Ack::Timely,
            Ack::Timely,
            WriteTerminal::Commit(selected),
            Ack::NotAttempted,
        )?,
        TerminalStage::EnrollmentReadbackRollback => history(
            &error,
            Ack::Timely,
            Ack::Timely,
            WriteTerminal::Commit(Ack::Timely),
            selected,
        )?,
        _ => return Err("only registered enrollment ACK stages".into()),
    }
    if discard && matches!(stage, TerminalStage::EnrollmentCommit) {
        check(
            error.kind() == Kind::CommitUnknown,
            "lost original COMMIT ACK remains Unknown",
        )?;
    }
    if sql_late && matches!(stage, TerminalStage::EnrollmentCommit) {
        check(
            error.kind() == Kind::CommitAcknowledgedAfterDeadline,
            "actual late original COMMIT not reset by timeout",
        )?;
    }
    if require_cleanup_unknown {
        check(
            error.cleanup_state() == Cleanup::Unknown,
            "expired original close budget retains Unknown, never manufactures closure",
        )?;
    }
    if revoke {
        check(
            error.kind() == Kind::BeforeAdoptionRefused,
            "real current tail refusal",
        )?;
    }
    check(
        f.row(original.attempt_id).await? == original,
        "all20 original journal history unchanged",
    )?;
    let expected = if matches!(
        stage,
        TerminalStage::EnrollmentCommit | TerminalStage::EnrollmentReadbackRollback
    ) {
        (1, 1)
    } else {
        (0, 0)
    };
    check(
        sdk_counts(&f).await? == expected,
        "real PG effect preserved independently of original ACK error",
    )?;
    consumer_network(
        &f,
        baseline,
        matches!(
            stage,
            TerminalStage::EnrollmentCommit | TerminalStage::EnrollmentReadbackRollback
        ),
    )?;
    relay.assert_target(usize::from(!discard));
    eprintln!(
        "ENROLLMENT_ACK_ORACLE stage={stage:?} selected={selected:?} actual_error_stage={:?} actual_kind={:?} final_after_assembly_barrier=UNPROVEN",
        error.stage(),
        error.kind()
    );
    f.finish_enrollment().await?;
    relay.stop().await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r01_session_original_whole_token_adopts_same_id() {
    let admin = harness::admin_config("enrollment-r01");
    harness::with_temp_database(&admin, "enroll_r01", |cfg| success(cfg, false)).await;
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r02_singleuser_original_whole_token_adopts_same_id() {
    let admin = harness::admin_config("enrollment-r02");
    harness::with_temp_database(&admin, "enroll_r02", |cfg| success(cfg, true)).await;
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r03_distinct_manager_same_config_refuses() {
    let admin = harness::admin_config("enrollment-r03");
    harness::with_temp_database(&admin, "enroll_r03", |cfg| async move {
        let f = Fixture::new_enrollment(cfg, 2).await?;
        let (auth, owner, original) = token(
            &f,
            CancellationToken::new(),
            Instant::now() + Duration::from_secs(60),
        )
        .await?;
        let other_pool = f.direct().await?;
        check(
            !std::ptr::eq(other_pool.manager(), f.pool.manager()),
            "same PG configuration is a genuinely different Manager",
        )?;
        let accounts = f.enrollment_accounts(other_pool.clone(), vault())?;
        let before = f.captures()?.len();
        let error = rejected(
            f.journal
                .enroll_token_owner(
                    &auth,
                    owner,
                    &accounts,
                    "foreign manager",
                    Arc::new(Outcomes::default()),
                )
                .await,
        )?;
        check(
            error.kind() == Kind::BeforeAdoptionRefused && error.reserved_connection_id().is_none(),
            "foreign Manager rejected before validated ID disclosure",
        )?;
        history(
            &error,
            Ack::NotAttempted,
            Ack::NotAttempted,
            WriteTerminal::NotAttempted,
            Ack::NotAttempted,
        )?;
        check(
            error.cleanup_state() == Cleanup::NotNeeded
                && f.captures()?.len() == before
                && sdk_counts(&f).await? == (0, 0),
            "foreign Manager opens no new network or adoption session",
        )?;
        check(
            f.row(original.attempt_id).await? == original,
            "original journal retained",
        )?;
        no_resend(&f)?;
        other_pool.close();
        f.finish_enrollment().await
    })
    .await;
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r04_real_body_pending_current_revocation_refuses() {
    let admin = harness::admin_config("enrollment-r04");
    harness::with_temp_database(&admin, "enroll_r04", |cfg| async move {
        let f = Fixture::new_enrollment(cfg, 2).await?;
        f.configure_profile(&json!({"hold_body":true}))?;
        let (auth, owner, original) = token(
            &f,
            CancellationToken::new(),
            Instant::now() + Duration::from_secs(60),
        )
        .await?;
        let accounts = f.enrollment_accounts(f.pool.clone(), vault())?;
        let before = f.captures()?.len();
        let mut call = Box::pin(f.journal.enroll_token_owner(
            &auth,
            owner,
            &accounts,
            "revoked body",
            Arc::new(Outcomes::default()),
        ));
        pending(&f, &mut call, ProfilePoint::Body).await?;
        f.disarm_host();
        f.release_profile_body()?;
        let error = rejected(call.await)?;
        check(
            error.kind() == Kind::BeforeAdoptionRefused && error.stage() == Stage::Profile,
            "real pending profile loses original Host authority",
        )?;
        check(
            error.reserved_connection_id() == Some(original_id(&original)?),
            "already validated reservation remains descriptive",
        )?;
        history(
            &error,
            Ack::Timely,
            Ack::Timely,
            WriteTerminal::NotAttempted,
            Ack::NotAttempted,
        )?;
        check(
            error.cleanup_state() == Cleanup::OriginalResourcesDestroyed,
            "earlier two real owners remain destroyed after later body refusal",
        )?;
        check(
            sdk_counts(&f).await? == (0, 0) && f.row(original.attempt_id).await? == original,
            "no adoption and no journal terminal rewrite",
        )?;
        consumer_network(&f, before, true)?;
        f.finish_enrollment().await
    })
    .await;
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r05_original_cap_covers_metadata_profile_and_adoption() {
    let admin = harness::admin_config("enrollment-r05");
    for stage in [
        TerminalStage::EnrollmentMetadataRollback,
        TerminalStage::EnrollmentCommit,
    ] {
        harness::with_temp_database(&admin, "enroll_r05_ack", |cfg| {
            ack_failure(cfg, stage, AckFault::CallerDeadline)
        })
        .await;
    }
    harness::with_temp_database(&admin, "enroll_r05_profile", |cfg| async move {
        let f = Fixture::new_enrollment(cfg, 2).await?;
        f.configure_profile(&json!({"hold_body":true}))?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let (auth, owner, original) = token(&f, CancellationToken::new(), deadline).await?;
        let accounts = f.enrollment_accounts(f.pool.clone(), vault())?;
        let mut call = Box::pin(f.journal.enroll_token_owner(
            &auth,
            owner,
            &accounts,
            "original cap",
            Arc::new(Outcomes::default()),
        ));
        pending(&f, &mut call, ProfilePoint::Body).await?;
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline + Duration::from_millis(150),
        ))
        .await;
        f.release_profile_body()?;
        let error = rejected(call.await)?;
        check(
            error.kind() == Kind::Deadline
                && error.reserved_connection_id() == Some(original_id(&original)?),
            "no fresh60s budget after original caller cap",
        )?;
        history(
            &error,
            Ack::Timely,
            Ack::Timely,
            WriteTerminal::NotAttempted,
            Ack::NotAttempted,
        )?;
        check(
            sdk_counts(&f).await? == (0, 0),
            "expired body does not adopt",
        )?;
        no_resend(&f)?;
        f.finish_enrollment().await
    })
    .await;
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r06_headers_channels_are_once_and_require_original_rollback() {
    let admin = harness::admin_config("enrollment-r06");
    for stage in [
        TerminalStage::EnrollmentMetadataRollback,
        TerminalStage::EnrollmentProfileRollback,
    ] {
        harness::with_temp_database(&admin, "enroll_r06", |cfg| {
            ack_failure(cfg, stage, AckFault::Discard)
        })
        .await;
    }
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r07_reserved_id_conflict_never_overwrites_or_remints() {
    let admin = harness::admin_config("enrollment-r07");
    harness::with_temp_database(&admin, "enroll_r07", |cfg| async move {
        let f = Fixture::new_enrollment(cfg, 2).await?;
        let (auth, owner, original) = token(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
        let id = original_id(&original)?;
        let accounts = f.enrollment_accounts(f.pool.clone(), vault())?;
        let client = f.pool.get().await.map_err(|e| e.to_string())?;
        client.execute("INSERT INTO public.sdk_gateway_connections(id,deployment_id,tenant_id,owner_user_id,name,issuer,client_id,account_id,organization_id,auth_contract_version,error_contract_version,enabled,revision,credential_generation,auth_generation,state,current_secret_id,pending_operation_id,created_at,updated_at) VALUES($1,$2,$3,$4,'preexisting original','https://original.invalid','preexisting-client','preexisting-account',NULL,2,1,true,9,7,7,'missing',NULL,NULL,clock_timestamp(),clock_timestamp())", &[&id,&DEP,&TENANT,&auth.actor().as_str()]).await.map_err(|e| e.to_string())?;
        let before: Value = client.query_one("SELECT to_jsonb(c) FROM public.sdk_gateway_connections c WHERE id=$1", &[&id]).await.map_err(|e| e.to_string())?.get(0);
        drop(client);
        let error = rejected(f.journal.enroll_token_owner(&auth, owner, &accounts, "must not overwrite", Arc::new(Outcomes::default())).await)?;
        check(error.kind() == Kind::Conflict && error.stage() == Stage::Write && error.reserved_connection_id() == Some(id), "only original connection INSERT conflict, original ID retained")?;
        history(&error, Ack::Timely, Ack::Timely, WriteTerminal::Rollback(Ack::Timely), Ack::NotAttempted)?;
        let client = f.pool.get().await.map_err(|e| e.to_string())?;
        let after: Value = client.query_one("SELECT to_jsonb(c) FROM public.sdk_gateway_connections c WHERE id=$1", &[&id]).await.map_err(|e| e.to_string())?.get(0);
        check(after == before, "existing connection is byte-logically untouched")?; drop(client);
        check(sdk_counts(&f).await? == (1, 0) && f.row(original.attempt_id).await? == original, "no alternate connection or secret minted")?;
        no_resend(&f)?; f.finish_enrollment().await
    }).await;
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r08_vault_or_audit_failure_rolls_back_atomically() {
    let admin = harness::admin_config("enrollment-r08");
    harness::with_temp_database(&admin, "enroll_r08", |cfg| async move {
        let f = Fixture::new_enrollment(cfg, 2).await?;
        let (auth, owner, original) = token(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
        let accounts = f.enrollment_accounts(f.pool.clone(), vault())?;
        let journal_audits = f.audits().await?;
        let client = f.pool.get().await.map_err(|e| e.to_string())?;
        client.batch_execute("CREATE FUNCTION public.owned_enrollment_audit_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type='configuration.changed' AND NEW.target_kind='sdk_gateway_connection' THEN RAISE EXCEPTION 'owned_enrollment_audit_reject'; END IF; RETURN NEW; END $$; CREATE TRIGGER owned_enrollment_audit_reject BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.owned_enrollment_audit_reject();").await.map_err(|e| e.to_string())?;
        drop(client);
        let error = rejected(f.journal.enroll_token_owner(&auth, owner, &accounts, "atomic audit", Arc::new(Outcomes::default())).await)?;
        check(error.stage() == Stage::Write && error.kind() == Kind::Unavailable, "actual adoption audit statement failed")?;
        history(&error, Ack::Timely, Ack::Timely, WriteTerminal::Rollback(Ack::Timely), Ack::NotAttempted)?;
        check(sdk_counts(&f).await? == (0, 0) && f.audits().await? == journal_audits && f.row(original.attempt_id).await? == original, "connection, secret and new audit atomically rolled back; journal history retained")?;
        no_resend(&f)?; f.finish_enrollment().await
    }).await;
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r09_commit_unknown_keeps_original_id_and_action() {
    let admin = harness::admin_config("enrollment-r09");
    harness::with_temp_database(&admin, "enroll_r09", |cfg| {
        ack_failure(cfg, TerminalStage::EnrollmentCommit, AckFault::Discard)
    })
    .await;
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r10_readback_failure_preserves_known_commit() {
    let admin = harness::admin_config("enrollment-r10");
    harness::with_temp_database(&admin, "enroll_r10_ack", |cfg| {
        ack_failure(
            cfg,
            TerminalStage::EnrollmentReadbackRollback,
            AckFault::Discard,
        )
    })
    .await;
    harness::with_temp_database(&admin, "enroll_r10_vault", |cfg| async move {
        let direct = openbot_infra::db::pool::connect(&cfg).await.map_err(|e| e.to_string())?;
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::EnrollmentCommit, false).await;
        let f = Fixture::new_enrollment(relay.config.clone(), 1).await?;
        let (auth, owner, original) = token(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
        let id = original_id(&original)?;
        let accounts = f.enrollment_accounts(f.pool.clone(), vault())?;
        relay.arm_enrollment();
        let mut call = Box::pin(f.journal.enroll_token_owner(&auth, owner, &accounts, "real readback", Arc::new(Outcomes::default())));
        tokio::select! { biased; () = relay.held() => {}, result = &mut call => return Err(format!("readback corruption missed real committed write: {result:?}")), }
        let client = direct.get().await.map_err(|e| e.to_string())?;
        let changed = client.execute("UPDATE public.sdk_gateway_secrets SET encrypted_value='owned-invalid-v2' WHERE connection_id=$1", &[&id]).await.map_err(|e| e.to_string())?;
        check(changed == 1, "one actually committed secret changed before genuine RO")?;
        drop(client); relay.release_original_ack().await;
        let error = rejected(call.await)?;
        check(error.stage() == Stage::Readback && error.kind() == Kind::Corrupt, "real persisted Vault readback failure refuses receipt")?;
        check(error.reserved_connection_id() == Some(id), "readback error keeps committed original ID")?;
        history(&error, Ack::Timely, Ack::Timely, WriteTerminal::Commit(Ack::Timely), Ack::Timely)?;
        check(sdk_counts(&f).await? == (1, 1), "known committed effect remains; no automatic repair")?;
        no_resend(&f)?; relay.assert_target(1); direct.close(); f.finish_enrollment().await?; relay.stop().await; Ok(())
    }).await;
    harness::with_temp_database(&admin, "enroll_r10_sixth", |cfg| async move {
        let direct = openbot_infra::db::pool::connect(&cfg).await.map_err(|e| e.to_string())?;
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::EnrollmentCommit, false).await;
        let f = Fixture::new_enrollment(relay.config.clone(), 1).await?;
        let (auth, owner, original) = token(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
        let id = original_id(&original)?;
        let vault = vault();
        let accounts = f.enrollment_accounts(f.pool.clone(), vault.clone())?;
        relay.arm_enrollment();
        let mut call = Box::pin(f.journal.enroll_token_owner(&auth, owner, &accounts, "original sixth field", Arc::new(Outcomes::default())));
        tokio::select! { biased; () = relay.held() => {}, result = &mut call => return Err(format!("sixth-field vector missed actual COMMIT ACK: {result:?}")), }
        // This observer only touches this genuine, already committed, owned original scope.
        let client = direct.get().await.map_err(|e| e.to_string())?;
        let row = client.query_one("SELECT s.id,s.encrypted_value,to_jsonb(s)-'encrypted_value',to_jsonb(c) FROM public.sdk_gateway_connections c JOIN public.sdk_gateway_secrets s ON s.id=c.current_secret_id AND s.connection_id=c.id AND s.credential_generation=c.credential_generation WHERE c.id=$1 AND c.deployment_id=$2 AND c.tenant_id=$3 AND c.owner_user_id=$4 AND s.deployment_id=$2 AND s.tenant_id=$3 AND s.owner_user_id=$4 AND s.retired_at IS NULL", &[&id,&DEP,&TENANT,&auth.actor().as_str()]).await.map_err(|e| e.to_string())?;
        let secret: uuid::Uuid = row.get(0);
        let encrypted: String = row.get(1);
        let secret_metadata: Value = row.get(2);
        let connection_metadata: Value = row.get(3);
        let opened = vault.open(&secret, SecretKind::Model, SecretPrincipal::Actor(auth.actor().clone()), SecretPrincipal::Service(ServiceId::new(id.to_string())), &encrypted).map_err(|e| e.to_string())?;
        check(!opened.needs_migration(), "sixth-field oracle begins with actual v2 envelope")?;
        let stored: Value = serde_json::from_slice(opened.into_secret().expose()).map_err(|e| e.to_string())?;
        let tokens = stored["tokens"].as_object().ok_or("original six fields absent")?;
        check(tokens.len() == 6, "original exact six token fields")?;
        let original_expires = tokens["expires_at"].as_str().ok_or("original sixth field absent")?.to_owned();
        let expiry = time::OffsetDateTime::parse(&original_expires, &time::format_description::well_known::Rfc3339).map_err(|e| e.to_string())?;
        check(expiry > time::OffsetDateTime::now_utc(), "original sixth field is still valid")?;
        let changed_expiry = expiry + time::Duration::seconds(1);
        let changed_expires = changed_expiry.format(&time::format_description::well_known::Rfc3339).map_err(|e| e.to_string())?;
        check(changed_expires.len() <= 64 && changed_expires != original_expires && changed_expiry > time::OffsetDateTime::now_utc(), "valid unequal sixth original value, never expiry or malformed substitution")?;
        let mut changed = stored.clone();
        changed["tokens"]["expires_at"] = Value::String(changed_expires.clone());
        for key in ["access_token", "refresh_token", "scope", "client_id", "server_url"] {
            check(changed["tokens"][key].as_str().map(str::as_bytes) == stored["tokens"][key].as_str().map(str::as_bytes) && stored["tokens"][key].is_string(), "other five original token strings retain exact bytes")?;
        }
        let mut restored = changed.clone();
        restored["tokens"]["expires_at"] = Value::String(original_expires);
        check(restored == stored, "all envelope metadata and other fields retain original values")?;
        let changed_plaintext = SecretBytes::new(serde_json::to_vec(&changed).map_err(|e| e.to_string())?);
        let resealed = vault.seal(&secret, SecretKind::Model, SecretPrincipal::Actor(auth.actor().clone()), SecretPrincipal::Service(ServiceId::new(id.to_string())), &changed_plaintext).map_err(|e| e.to_string())?;
        let modified = client.execute("UPDATE public.sdk_gateway_secrets SET encrypted_value=$1 WHERE id=$2 AND connection_id=$3 AND deployment_id=$4 AND tenant_id=$5 AND owner_user_id=$6 AND encrypted_value=$7 AND retired_at IS NULL", &[&resealed,&secret,&id,&DEP,&TENANT,&auth.actor().as_str(),&encrypted]).await.map_err(|e| e.to_string())?;
        check(modified == 1, "only the exact original committed secret resealed")?;
        let observed = client.query_one("SELECT s.encrypted_value,to_jsonb(s)-'encrypted_value',to_jsonb(c) FROM public.sdk_gateway_connections c JOIN public.sdk_gateway_secrets s ON s.id=c.current_secret_id AND s.connection_id=c.id WHERE c.id=$1 AND s.id=$2", &[&id,&secret]).await.map_err(|e| e.to_string())?;
        check(observed.get::<_, Value>(1) == secret_metadata && observed.get::<_, Value>(2) == connection_metadata, "all PG record metadata remains unchanged")?;
        let modified_envelope: String = observed.get(0);
        let modified_opened = vault.open(&secret, SecretKind::Model, SecretPrincipal::Actor(auth.actor().clone()), SecretPrincipal::Service(ServiceId::new(id.to_string())), &modified_envelope).map_err(|e| e.to_string())?;
        check(!modified_opened.needs_migration(), "modified envelope valid under exact original AAD")?;
        let modified_value: Value = serde_json::from_slice(modified_opened.into_secret().expose()).map_err(|e| e.to_string())?;
        check(modified_value == changed && changed_expiry > time::OffsetDateTime::now_utc(), "persisted unequal sixth field remains valid immediately before actual ACK release")?;
        drop(client);
        relay.release_original_ack().await;
        let error = rejected(call.await)?;
        check(error.stage() == Stage::Readback && error.kind() == Kind::Corrupt && error.reserved_connection_id() == Some(id), "genuine RO rejects valid unequal sixth original field and retains ID")?;
        history(&error, Ack::Timely, Ack::Timely, WriteTerminal::Commit(Ack::Timely), Ack::Timely)?;
        check(sdk_counts(&f).await? == (1, 1) && f.row(original.attempt_id).await? == original, "known committed effect and all original journal columns retained")?;
        no_resend(&f)?;
        relay.assert_target(1);
        direct.close();
        f.finish_enrollment().await?;
        relay.stop().await;
        Ok(())
    }).await;
    harness::with_temp_database(&admin, "enroll_r10_scope", |cfg| async move {
        let direct = openbot_infra::db::pool::connect(&cfg).await.map_err(|e| e.to_string())?;
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::EnrollmentCommit, false).await;
        let f = Fixture::new_enrollment(relay.config.clone(), 1).await?;
        let (auth, owner, original) = token(&f, CancellationToken::new(), Instant::now() + Duration::from_secs(60)).await?;
        let id = original_id(&original)?;
        let vault = vault();
        let accounts = f.enrollment_accounts(f.pool.clone(), vault.clone())?;
        relay.arm_enrollment();
        let mut call = Box::pin(f.journal.enroll_token_owner(&auth, owner, &accounts, "persisted bad scope", Arc::new(Outcomes::default())));
        tokio::select! { biased; () = relay.held() => {}, result = &mut call => return Err(format!("bad-scope vector missed actual COMMIT ACK: {result:?}")), }
        let client = direct.get().await.map_err(|e| e.to_string())?;
        let row = client.query_one("SELECT s.id,s.encrypted_value,to_jsonb(s)-'encrypted_value',to_jsonb(c) FROM public.sdk_gateway_connections c JOIN public.sdk_gateway_secrets s ON s.id=c.current_secret_id AND s.connection_id=c.id AND s.credential_generation=c.credential_generation WHERE c.id=$1 AND c.deployment_id=$2 AND c.tenant_id=$3 AND c.owner_user_id=$4 AND s.deployment_id=$2 AND s.tenant_id=$3 AND s.owner_user_id=$4 AND s.retired_at IS NULL", &[&id,&DEP,&TENANT,&auth.actor().as_str()]).await.map_err(|e| e.to_string())?;
        let secret: uuid::Uuid = row.get(0);
        let encrypted: String = row.get(1);
        let secret_metadata: Value = row.get(2);
        let connection_metadata: Value = row.get(3);
        let opened = vault.open(&secret, SecretKind::Model, SecretPrincipal::Actor(auth.actor().clone()), SecretPrincipal::Service(ServiceId::new(id.to_string())), &encrypted).map_err(|e| e.to_string())?;
        check(!opened.needs_migration(), "bad-scope oracle begins with actual v2 envelope")?;
        let stored: Value = serde_json::from_slice(opened.into_secret().expose()).map_err(|e| e.to_string())?;
        let tokens = stored["tokens"].as_object().ok_or("original six fields absent")?;
        check(tokens.len() == 6 && tokens["scope"] == "ai account", "genuine original exact scope includes both required words")?;
        let expires = tokens["expires_at"].as_str().ok_or("original unchanged expiry absent")?;
        let expiry = time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339).map_err(|e| e.to_string())?;
        check(expiry > time::OffsetDateTime::now_utc(), "bad-scope vector never substitutes an expired credential")?;
        let mut changed = stored.clone();
        changed["tokens"]["scope"] = Value::String("ai".into());
        for key in ["access_token", "refresh_token", "client_id", "server_url", "expires_at"] {
            check(changed["tokens"][key].as_str().map(str::as_bytes) == stored["tokens"][key].as_str().map(str::as_bytes) && stored["tokens"][key].is_string(), "other five original token strings retain exact bytes")?;
        }
        let mut restored = changed.clone();
        restored["tokens"]["scope"] = tokens["scope"].clone();
        check(restored == stored, "every other plaintext member and metadata value remains original")?;
        let changed_plaintext = SecretBytes::new(serde_json::to_vec(&changed).map_err(|e| e.to_string())?);
        let resealed = vault.seal(&secret, SecretKind::Model, SecretPrincipal::Actor(auth.actor().clone()), SecretPrincipal::Service(ServiceId::new(id.to_string())), &changed_plaintext).map_err(|e| e.to_string())?;
        let modified = client.execute("UPDATE public.sdk_gateway_secrets SET encrypted_value=$1 WHERE id=$2 AND connection_id=$3 AND deployment_id=$4 AND tenant_id=$5 AND owner_user_id=$6 AND encrypted_value=$7 AND retired_at IS NULL", &[&resealed,&secret,&id,&DEP,&TENANT,&auth.actor().as_str(),&encrypted]).await.map_err(|e| e.to_string())?;
        check(modified == 1, "only exact original committed secret receives bad-scope envelope")?;
        let observed = client.query_one("SELECT s.encrypted_value,to_jsonb(s)-'encrypted_value',to_jsonb(c) FROM public.sdk_gateway_connections c JOIN public.sdk_gateway_secrets s ON s.id=c.current_secret_id AND s.connection_id=c.id WHERE c.id=$1 AND s.id=$2", &[&id,&secret]).await.map_err(|e| e.to_string())?;
        check(observed.get::<_, Value>(1) == secret_metadata && observed.get::<_, Value>(2) == connection_metadata, "all committed PG metadata is unchanged")?;
        let actual_envelope: String = observed.get(0);
        let actual = vault.open(&secret, SecretKind::Model, SecretPrincipal::Actor(auth.actor().clone()), SecretPrincipal::Service(ServiceId::new(id.to_string())), &actual_envelope).map_err(|e| e.to_string())?;
        check(!actual.needs_migration(), "bad scope is stored in a valid v2 envelope with original AAD")?;
        let actual_plaintext: Value = serde_json::from_slice(actual.into_secret().expose()).map_err(|e| e.to_string())?;
        check(actual_plaintext == changed && actual_plaintext["tokens"]["scope"] == "ai" && expiry > time::OffsetDateTime::now_utc(), "actual persisted failure is missing account scope, not expiry or ciphertext")?;
        drop(client);
        relay.release_original_ack().await;
        let error = rejected(call.await)?;
        check(error.stage() == Stage::Readback && error.kind() == Kind::Corrupt && error.reserved_connection_id() == Some(id), "persisted bad scope maps to Corrupt, never caller InvalidInput, and retains original ID")?;
        history(&error, Ack::Timely, Ack::Timely, WriteTerminal::Commit(Ack::Timely), Ack::Timely)?;
        check(sdk_counts(&f).await? == (1, 1) && f.row(original.attempt_id).await? == original, "known committed effect and original journal history retained without repair")?;
        no_resend(&f)?;
        relay.assert_target(1);
        direct.close();
        f.finish_enrollment().await?;
        relay.stop().await;
        Ok(())
    }).await;
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r11_final_current_refusal_keeps_adoption_facts() {
    let admin = harness::admin_config("enrollment-r11");
    harness::with_temp_database(&admin, "enroll_r11", |cfg| {
        ack_failure(
            cfg,
            TerminalStage::EnrollmentReadbackRollback,
            AckFault::CurrentRefused,
        )
    })
    .await;
    harness::with_temp_database(&admin, "enroll_r11_final", |cfg| async move {
        let relay = PgTerminalAckGate::new(&cfg, TerminalStage::EnrollmentReadbackRollback, false).await;
        let f = Fixture::new_enrollment(relay.config.clone(), 1).await?;
        // This is the same absolute caller cap carried through the original producer and consumer.
        let deadline = Instant::now() + Duration::from_secs(10);
        let (auth, owner, original) = token(&f, CancellationToken::new(), deadline).await?;
        let id = original_id(&original)?;
        let accounts = f.enrollment_accounts(f.pool.clone(), vault())?;
        let baseline = f.captures()?.len();
        relay.arm_enrollment();
        let mut call = Box::pin(f.journal.enroll_token_owner(&auth, owner, &accounts, "real final handoff", Arc::new(Outcomes::default())));
        tokio::select! { biased; () = relay.held() => {}, result = &mut call => return Err(format!("final handoff vector missed original RO ACK: {result:?}")), }
        check(f.pool.ownership_snapshot().retiring == 0, "one consumer and no other retiring original owner before RO ACK")?;
        relay.release_original_ack().await;
        loop {
            if Instant::now() >= deadline {
                return Err("HOLD: no lawful final retirement progress point within original caller cap".into());
            }
            // poll_fn itself is Ready: no scheduler yield between this original poll,
            // the same-Pool progress snapshot and synchronous Host revocation.
            let polled = std::future::poll_fn(|cx| std::task::Poll::Ready(call.as_mut().poll(cx))).await;
            if matches!(polled, std::task::Poll::Ready(_)) {
                return Err("HOLD: business future completed before observed original retirement await".into());
            }
            let retiring = f.pool.ownership_snapshot().retiring;
            if retiring == 1 {
                // This only locates read_adoption's original retire await. It is not
                // an ACK, destruction, join or after-assembly observation.
                f.disarm_host();
                break;
            }
            check(retiring == 0, "no ambiguous second retiring owner in this fixed single-consumer vector")?;
            tokio::task::yield_now().await;
        }
        let error = rejected(call.await)?;
        check(error.stage() == Stage::FinalHandoff && error.kind() == Kind::BeforeAdoptionRefused && error.reserved_connection_id() == Some(id), "actual final Current gate refuses after known RO tail and retains original ID")?;
        history(&error, Ack::Timely, Ack::Timely, WriteTerminal::Commit(Ack::Timely), Ack::Timely)?;
        check(error.cleanup_state() == Cleanup::OriginalResourcesDestroyed, "actual original destruction observation completes before FinalHandoff error")?;
        check(sdk_counts(&f).await? == (1, 1) && f.row(original.attempt_id).await? == original, "real committed adoption and original journal history remain; no refund")?;
        consumer_network(&f, baseline, true)?;
        relay.assert_target(1);
        f.finish_enrollment().await?;
        relay.stop().await;
        Ok(())
    }).await;
    // The real boundary is the original RO terminal tail. An after-assembly barrier remains UNPROVEN.
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r12_typed_terminal_late_ack_is_not_reset_by_deadline() {
    let admin = harness::admin_config("enrollment-r12");
    harness::with_temp_database(&admin, "enroll_r12", |cfg| {
        ack_failure(cfg, TerminalStage::EnrollmentCommit, AckFault::SqlDeadline)
    })
    .await;
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r13_cancel_or_drop_never_refunds_owner_or_resends() {
    let admin = harness::admin_config("enrollment-r13");
    for drop_caller in [false, true] {
        harness::with_temp_database(&admin, "enroll_r13", |cfg| async move {
            let f = Fixture::new_enrollment(cfg, 2).await?;
            f.configure_profile(&if drop_caller {
                json!({"hold_headers":true})
            } else {
                json!({"hold_body":true})
            })?;
            let parent = CancellationToken::new();
            let (auth, owner, original) =
                token(&f, parent.clone(), Instant::now() + Duration::from_secs(60)).await?;
            let accounts = f.enrollment_accounts(f.pool.clone(), vault())?;
            let mut call = Box::pin(f.journal.enroll_token_owner(
                &auth,
                owner,
                &accounts,
                "one owner",
                Arc::new(Outcomes::default()),
            ));
            pending(
                &f,
                &mut call,
                if drop_caller {
                    ProfilePoint::Request
                } else {
                    ProfilePoint::Body
                },
            )
            .await?;
            if drop_caller {
                drop(call);
            } else {
                parent.cancel();
                let error = rejected(call.await)?;
                check(
                    error.kind() == Kind::Cancelled
                        && error.reserved_connection_id() == Some(original_id(&original)?),
                    "original parent cancellation retains only descriptive ID",
                )?;
                history(
                    &error,
                    Ack::Timely,
                    Ack::Timely,
                    WriteTerminal::NotAttempted,
                    Ack::NotAttempted,
                )?;
            }
            f.release_profile_headers()?;
            f.release_profile_body()?;
            let until = Instant::now() + Duration::from_secs(5);
            loop {
                if f.events()?
                    .iter()
                    .any(|v| v["event"] == "response_finished" && v["path"] == "/api/oauth/profile")
                {
                    break;
                }
                if Instant::now() >= until {
                    return Err("owned profile did not finish after caller end".into());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            check(
                sdk_counts(&f).await? == (0, 0) && f.row(original.attempt_id).await? == original,
                "caller end creates no adoption or replacement owner",
            )?;
            no_resend(&f)?;
            f.finish_enrollment().await
        })
        .await;
    }
}
#[tokio::test]
#[ignore = "requires separately admitted owned PostgreSQL, TLS and original terminal receipts"]
async fn r14_stage_retirement_unknown_never_returns_receipt() {
    let admin = harness::admin_config("enrollment-r14");
    harness::with_temp_database(&admin, "enroll_r14", |cfg| {
        ack_failure(
            cfg,
            TerminalStage::EnrollmentMetadataRollback,
            AckFault::CallerDeadline,
        )
    })
    .await;
    // This tests a genuinely exhausted original close-observation budget, not a synthetic driver hang.
}
