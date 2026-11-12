use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;

struct BlockingRotation {
    calls: AtomicUsize,
    started: Notify,
    release: Notify,
}

#[async_trait]
impl RotatingOAuthTokenExchanger for BlockingRotation {
    async fn exchange_rotating(
        &self,
        request: OAuthRefreshExchange<'_>,
    ) -> Result<RotatingOAuthGrant, OAuthTokenExchangeError> {
        request.admit_token_send().await?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        self.release.notified().await;
        Ok(RotatingOAuthGrant::new(
            SecretBytes::new(b"access-after-owned-send".to_vec()),
            Some(SecretBytes::new(b"refresh-after-owned-send".to_vec())),
            None,
        ))
    }
}

fn blocked_rotation() -> Arc<BlockingRotation> {
    Arc::new(BlockingRotation {
        calls: AtomicUsize::new(0),
        started: Notify::new(),
        release: Notify::new(),
    })
}

async fn operation_state(fixture: &Fixture) -> Result<(String, bool, i64), String> {
    let row = fixture.pool.get().await.map_err(|e| e.to_string())?
        .query_one("SELECT state,admitted_at IS NOT NULL,generation FROM public.oauth_refresh_operations ORDER BY created_at DESC LIMIT 1", &[])
        .await.map_err(|e| e.to_string())?;
    Ok((row.get(0), row.get(1), row.get(2)))
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; set OPENBOT_TEST_DATABASE_URL"]
async fn only_one_replica_sends_and_reusable_success_also_commits() {
    with_fixture("only_one_replica_sends", "refresh_one_sender", |fixture| async move {
        register_client(&fixture, DRIVE).await?;
        connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
        let exchanger = blocked_rotation();
        let task_store = fixture.store.clone();
        let task_exchange = exchanger.clone();
        let task = tokio::spawn(async move { task_store.fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &*task_exchange).await });
        exchanger.started.notified().await;
        assert_eq!(operation_state(&fixture).await?, ("pending".to_owned(), true, 1));
        // A separately constructed broker represents another replica, with no shared mutex.
        let replica = PluginUserCredentialStore::new(fixture.pool.clone(), fixture.vault.clone(), openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&fixture.pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside"))).with_rotation_audit_key(AUDIT_KEY.to_vec()).unwrap();
        assert!(matches!(replica.fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &*exchanger).await,
            Err(UserOAuthAccessError::Selection(UserCredentialSelectionError::RotationPending))));
        assert_eq!(exchanger.calls.load(Ordering::SeqCst), 1);
        exchanger.release.notify_one();
        task.await.map_err(|e| e.to_string())?.map_err(|e| e.to_string())?;
        assert_eq!(operation_state(&fixture).await?, ("committed".to_owned(), true, 1));
        // Drive's reusable flow still works repeatedly and has durable receipts/audit each time.
        let reusable = RecordingExchanger::default();
        replica.fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &reusable).await.map_err(|e| e.to_string())?;
        replica.fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &reusable).await.map_err(|e| e.to_string())?;
        assert_eq!(reusable.calls().len(), 2);
        assert_eq!(operation_state(&fixture).await?, ("committed".to_owned(), true, 3));
        let pg = fixture.pool.get().await.map_err(|e| e.to_string())?;
        assert_eq!(pg.query_one("SELECT count(*)::bigint FROM public.audit_events WHERE event_type='mcp.token_refreshed'", &[]).await.map_err(|e| e.to_string())?.get::<_,i64>(0), 2);
        Ok(())
    }).await;
}

struct LostResponse {
    calls: AtomicUsize,
}
#[async_trait]
impl RotatingOAuthTokenExchanger for LostResponse {
    async fn exchange_rotating(
        &self,
        request: OAuthRefreshExchange<'_>,
    ) -> Result<RotatingOAuthGrant, OAuthTokenExchangeError> {
        request.admit_token_send().await?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(OAuthTokenExchangeError::Unavailable)
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; set OPENBOT_TEST_DATABASE_URL"]
async fn lost_response_restart_and_old_timestamp_never_resend_but_reconnect_recovers() {
    with_fixture("lost_response_no_resend", "refresh_lost", |fixture| async move {
        register_client(&fixture, DRIVE).await?;
        let original = connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
        let exchanger = LostResponse { calls: AtomicUsize::new(0) };
        assert!(fixture.store.fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &exchanger).await.is_err());
        assert_eq!(operation_state(&fixture).await?, ("unknown".to_owned(), true, 1));
        let pg = fixture.pool.get().await.map_err(|e| e.to_string())?;
        pg.execute("UPDATE public.oauth_refresh_operations SET created_at=clock_timestamp()-interval '30 days' WHERE credential_id=$1", &[&original]).await.map_err(|e| e.to_string())?;
        drop(pg);
        let restarted = PluginUserCredentialStore::new(fixture.pool.clone(), fixture.vault.clone(), openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&fixture.pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside"))).with_rotation_audit_key(AUDIT_KEY.to_vec()).unwrap();
        assert!(matches!(restarted.fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &exchanger).await,
            Err(UserOAuthAccessError::Selection(UserCredentialSelectionError::RotationPending))));
        assert_eq!(exchanger.calls.load(Ordering::SeqCst), 1);
        connect(&fixture, DRIVE, ASKER, b"explicit-new-authorized-refresh").await?;
        successful_exchange(&fixture, DRIVE, ASKER).await?;
        let pg = fixture.pool.get().await.map_err(|e| e.to_string())?;
        assert_eq!(pg.query_one("SELECT state FROM public.oauth_refresh_operations WHERE credential_id=$1", &[&original]).await.map_err(|e| e.to_string())?.get::<_,String>(0), "unknown");
        Ok(())
    }).await;
}

struct DriftBeforeSend {
    pool: openbot_infra::db::pool::DatabasePool,
    calls: AtomicUsize,
}
#[async_trait]
impl RotatingOAuthTokenExchanger for DriftBeforeSend {
    async fn exchange_rotating(
        &self,
        request: OAuthRefreshExchange<'_>,
    ) -> Result<RotatingOAuthGrant, OAuthTokenExchangeError> {
        // Represents an authority change during MCP metadata discovery, before token POST.
        self.pool
            .get()
            .await
            .map_err(|_| OAuthTokenExchangeError::Unavailable)?
            .execute(
                "UPDATE public.users SET auth_generation=coalesce(auth_generation,0)+1 WHERE id=$1",
                &[&ASKER],
            )
            .await
            .map_err(|_| OAuthTokenExchangeError::Unavailable)?;
        request.admit_token_send().await?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(OAuthTokenExchangeError::Unavailable)
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; set OPENBOT_TEST_DATABASE_URL"]
async fn discovery_race_has_zero_token_sends() {
    with_fixture(
        "discovery_race",
        "refresh_admission",
        |fixture| async move {
            register_client(&fixture, DRIVE).await?;
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            let exchanger = DriftBeforeSend {
                pool: fixture.pool.clone(),
                calls: AtomicUsize::new(0),
            };
            assert!(
                fixture
                    .store
                    .fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &exchanger)
                    .await
                    .is_err()
            );
            assert_eq!(exchanger.calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                operation_state(&fixture).await?,
                ("pending".to_owned(), false, 1)
            );
            Ok(())
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; set OPENBOT_TEST_DATABASE_URL"]
async fn revocation_or_generation_change_after_send_never_releases_or_retries() {
    with_fixture("refresh_revoke_race", "refresh_revoke", |fixture| async move {
        register_client(&fixture, DRIVE).await?;
        for mutation in [
            "UPDATE public.credentials SET revoked_at=clock_timestamp() WHERE kind='mcp_user_token' AND revoked_at IS NULL",
            "UPDATE public.users SET auth_generation=coalesce(auth_generation,0)+1 WHERE id='credential-asker'",
            "UPDATE public.mcp_servers SET credential_generation=coalesce(credential_generation,0)+1 WHERE id='google-drive'",
        ] {
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            let exchanger = blocked_rotation();
            let store = fixture.store.clone();
            let child = exchanger.clone();
            let task = tokio::spawn(async move { store.fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &*child).await });
            exchanger.started.notified().await;
            fixture.pool.get().await.map_err(|e| e.to_string())?.batch_execute(mutation).await.map_err(|e| e.to_string())?;
            exchanger.release.notify_one();
            assert!(task.await.map_err(|e| e.to_string())?.is_err());
            assert_eq!(operation_state(&fixture).await?.0, "unknown");
            assert!(fixture.store.fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &*exchanger).await.is_err());
            assert_eq!(exchanger.calls.load(Ordering::SeqCst), 1);
        }
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; set OPENBOT_TEST_DATABASE_URL"]
async fn audit_or_final_commit_failure_preserves_unresolved_send_and_no_access() {
    with_fixture("refresh_commit_failure", "refresh_commit_fail", |fixture| async move {
        register_client(&fixture, DRIVE).await?;
        for trigger in [
            "CREATE FUNCTION reject_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$; CREATE TRIGGER reject_refresh BEFORE INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION reject_refresh()",
            "CREATE FUNCTION reject_refresh() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state='committed' THEN RAISE EXCEPTION 'injected deferred commit'; END IF; RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER reject_refresh AFTER UPDATE ON public.oauth_refresh_operations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_refresh()",
        ] {
            connect(&fixture, DRIVE, ASKER, ASKER_REFRESH).await?;
            fixture.pool.get().await.map_err(|e| e.to_string())?.batch_execute(trigger).await.map_err(|e| e.to_string())?;
            let reusable = RecordingExchanger::default();
            assert!(fixture.store.fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &reusable).await.is_err());
            assert_eq!(operation_state(&fixture).await?.0, "unknown");
            fixture.pool.get().await.map_err(|e| e.to_string())?.batch_execute("DROP FUNCTION reject_refresh() CASCADE").await.map_err(|e| e.to_string())?;
            assert!(matches!(fixture.store.fresh_user_access_token(DRIVE, &ActorId::new(ASKER), &reusable).await,
                Err(UserOAuthAccessError::Selection(UserCredentialSelectionError::RotationPending))));
            assert_eq!(reusable.calls().len(), 1);
        }
        Ok(())
    }).await;
}
