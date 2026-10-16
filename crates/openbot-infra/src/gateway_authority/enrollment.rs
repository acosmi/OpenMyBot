//! Same original whole-token adoption: borrowed SQL leaves, no independent transaction owner.

use std::sync::Arc;

use openbot_contracts::auth::AuthContext;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;
use uuid::Uuid;

use crate::db::pool::DatabasePool;
use crate::gateway_account::{GatewayAccountClient, GatewayAccountIdentity};
use crate::gateway_authorization::journal::enrollment::EnrollmentCurrent;
use crate::gateway_transport::{GatewayHttpAuthority, GatewayHttpOutcomes};

use super::{GatewayAuthorityError, PostgresGatewayAccounts, Scope, store};

pub(crate) struct EnrollmentAdoption<'a> {
    accounts: &'a PostgresGatewayAccounts,
    current: &'a EnrollmentCurrent<'a>,
    auth: &'a AuthContext,
    name: &'a str,
    tokens: &'a acosmi::TokenSet,
    scope: Scope,
}

impl PostgresGatewayAccounts {
    pub(crate) fn check_enrollment_scope(
        &self,
        current: &EnrollmentCurrent<'_>,
        pool: &DatabasePool,
        auth: &AuthContext,
        issuer: &str,
    ) -> Result<(), GatewayAuthorityError> {
        current
            .check()
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        self.check_auth(auth)?;
        if !std::ptr::eq(self.pool.manager(), pool.manager())
            || self.origin != issuer
            || !self.vault.matches_tenant(&self.tenant)
        {
            return Err(GatewayAuthorityError::NotVisible);
        }
        Ok(())
    }

    pub(crate) fn enrollment_client(
        &self,
        current: &EnrollmentCurrent<'_>,
        authority: Arc<dyn GatewayHttpAuthority>,
        outcomes: Arc<dyn GatewayHttpOutcomes>,
    ) -> Result<GatewayAccountClient, GatewayAuthorityError> {
        current
            .check()
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        let deadline = current
            .deadline()
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        let transport = self.transport(authority, outcomes, deadline)?;
        GatewayAccountClient::new(&self.origin, transport).map_err(super::map_account)
    }

    pub(crate) async fn enrollment_session_permit(
        &self,
        current: &EnrollmentCurrent<'_>,
        acquisition_deadline: Instant,
    ) -> Result<OwnedSemaphorePermit, GatewayAuthorityError> {
        current
            .check()
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        let deadline = current
            .deadline()
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        if acquisition_deadline > deadline {
            return Err(GatewayAuthorityError::InvalidInput);
        }
        let permit = store::acquire_enrollment_session_permit(
            current.original_parent(),
            acquisition_deadline,
        )
        .await?;
        current
            .check()
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        Ok(permit)
    }

    pub(crate) fn prepare_token_adoption<'a>(
        &'a self,
        current: &'a EnrollmentCurrent<'_>,
        auth: &'a AuthContext,
        connection_id: Uuid,
        name: &'a str,
        tokens: &'a acosmi::TokenSet,
        profile: &GatewayAccountIdentity,
    ) -> Result<EnrollmentAdoption<'a>, GatewayAuthorityError> {
        current
            .check_adoption_inputs(auth, connection_id, tokens)
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        self.check_auth(auth)?;
        if name.is_empty()
            || name.len() > 100
            || profile.issuer() != self.origin
            || tokens.server_url != self.origin
            || !self.vault.matches_tenant(&self.tenant)
        {
            return Err(GatewayAuthorityError::InvalidInput);
        }
        store::validate_token_shape(tokens, &self.origin, &tokens.client_id)?;
        let auth_generation = i64::try_from(auth.auth_generation().get())
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        let scope = Scope {
            auth: auth.clone(),
            deployment: self.deployment.clone(),
            tenant: self.tenant.clone(),
            connection_id,
            expected_revision: 1,
            auth_generation,
            issuer: profile.issuer().to_owned(),
            client_id: tokens.client_id.clone(),
            account_id: profile.account_id().to_owned(),
            organization_id: profile.organization_id().map(str::to_owned),
            cancel: current.original_parent().clone(),
            deadline: current
                .deadline()
                .map_err(|_| GatewayAuthorityError::NotVisible)?,
        };
        store::validate_token(tokens, &scope, 1)?;
        Ok(EnrollmentAdoption {
            accounts: self,
            current,
            auth,
            name,
            tokens,
            scope,
        })
    }
}

impl EnrollmentAdoption<'_> {
    // Exact registered consuming bridge; no SQL, clock, owner or public constructor.
    pub(crate) fn finish(self) -> Result<super::GatewayConnectionReceipt, GatewayAuthorityError> {
        self.current
            .check_adoption_inputs(self.auth, self.scope.connection_id, self.tokens)
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        Ok(super::GatewayConnectionReceipt {
            id: self.scope.connection_id,
            revision: 1,
            credential_generation: 1,
        })
    }

    pub(crate) async fn insert(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
    ) -> Result<Uuid, GatewayAuthorityError> {
        self.current
            .check_adoption_inputs(self.auth, self.scope.connection_id, self.tokens)
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        let id = store::insert_enrollment_in_transaction(
            tx,
            &self.accounts.vault,
            self.accounts.audit_key.expose(),
            &self.scope,
            self.name,
            self.tokens,
        )
        .await?;
        self.current
            .check_adoption_inputs(self.auth, self.scope.connection_id, self.tokens)
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        Ok(id)
    }

    pub(crate) async fn readback(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        secret_id: Uuid,
    ) -> Result<(), GatewayAuthorityError> {
        self.current
            .check_adoption_inputs(self.auth, self.scope.connection_id, self.tokens)
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        store::read_enrollment_in_transaction(
            tx,
            &self.accounts.vault,
            &self.scope,
            self.name,
            secret_id,
            self.tokens,
        )
        .await?;
        self.current
            .check_adoption_inputs(self.auth, self.scope.connection_id, self.tokens)
            .map_err(|_| GatewayAuthorityError::NotVisible)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{pool, pool::ConnectionDestruction};
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    mod harness {
        use crate as openbot_infra;
        use std::future::Future;
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-support/postgres_harness.rs"
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires isolated owned PostgreSQL17; exact opt-in only"]
    async fn q01_old_and_new_share_eight_permits_across_cancellation() {
        let admin = harness::admin_config("whole_token_enrollment_eight_permits");
        harness::with_temp_database(&admin, "enrollment8", |config| async move {
            let db = pool::connect(&config.clone().with_max_pool_size(12))
                .await
                .map_err(|e| e.to_string())?;
            let cancel = CancellationToken::new();
            let cap = Instant::now() + Duration::from_secs(30);
            let mut old = Vec::new();
            let mut new = Vec::new();
            for _ in 0..4 {
                old.push(
                    store::DetachedSession::acquire(&db, &cancel, cap)
                        .await
                        .map_err(|e| e.to_string())?,
                );
            }
            for _ in 0..4 {
                let permit = store::acquire_enrollment_session_permit(&cancel, cap)
                    .await
                    .map_err(|e| e.to_string())?;
                new.push(
                    db.get_guarded_with_session_permit(cap.into_std(), permit)
                        .await
                        .map_err(|e| e.to_string())?,
                );
            }
            let at_eight = db.ownership_snapshot();
            assert_eq!(at_eight.active_resources, 8);
            let ninth = store::acquire_enrollment_session_permit(
                &cancel,
                Instant::now() + Duration::from_millis(40),
            )
            .await;
            assert!(matches!(ninth, Err(GatewayAuthorityError::Timeout)));
            assert_eq!(db.ownership_snapshot(), at_eight);
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            assert!(matches!(
                store::acquire_enrollment_session_permit(&cancelled, cap).await,
                Err(GatewayAuthorityError::Cancelled)
            ));
            let mut reclaimed = Vec::new();
            for client in new {
                let observation = client.retire_original();
                // current_thread: no driver can run between these synchronous edges.
                assert!(observation.snapshot().destruction.is_none());
                {
                    let waiting = store::acquire_enrollment_session_permit(&cancel, cap);
                    let mut waiting = std::pin::pin!(waiting);
                    let pending =
                        poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx).is_pending())).await;
                    assert!(
                        pending,
                        "new path must hold its original permit until actual destruction"
                    );
                }
                observation
                    .wait_for_destruction_before(cap.into_std())
                    .await
                    .map_err(|e| e.to_string())?;
                reclaimed.push(
                    store::acquire_enrollment_session_permit(&cancel, cap)
                        .await
                        .map_err(|e| e.to_string())?,
                );
            }
            drop(reclaimed);
            // Old-path observations here are only final owned-fixture cleanup, never a
            // claim about its all-times physical8 upper bound or production joins.
            let old_observations = db.connection_observations();
            assert_eq!(old_observations.len(), 4);
            for session in old {
                session.schedule_close();
            }
            for observation in old_observations {
                observation
                    .wait_for_destruction_before(cap.into_std())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            db.close();

            // A fresh single original checkout is cancelled after its actual connect
            // future starts, before this caller receives a lease. No unrelated owner exists.
            let fresh = pool::connect(&config.with_max_pool_size(1))
                .await
                .map_err(|e| e.to_string())?;
            let mut seven = Vec::new();
            for _ in 0..7 {
                seven.push(
                    store::acquire_enrollment_session_permit(&cancel, cap)
                        .await
                        .map_err(|e| e.to_string())?,
                );
            }
            let permit = store::acquire_enrollment_session_permit(&cancel, cap)
                .await
                .map_err(|e| e.to_string())?;
            let observation;
            {
                let get = fresh.get_guarded_with_session_permit(cap.into_std(), permit);
                let mut get = std::pin::pin!(get);
                assert!(poll_fn(|cx| Poll::Ready(get.as_mut().poll(cx).is_pending())).await);
                let observations = fresh.connection_observations();
                assert_eq!(observations.len(), 1);
                observation = observations.into_iter().next().unwrap();
                for _ in 0..16 {
                    if observation.snapshot().connecting_future_started {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                assert!(observation.snapshot().connecting_future_started);
                assert!(observation.snapshot().destruction.is_none());
            }
            assert!(observation.snapshot().destruction.is_none());
            {
                let waiting = store::acquire_enrollment_session_permit(&cancel, cap);
                let mut waiting = std::pin::pin!(waiting);
                assert!(poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx).is_pending())).await);
            }
            let destruction = observation
                .wait_for_destruction_before(cap.into_std())
                .await
                .map_err(|e| e.to_string())?;
            assert!(matches!(
                destruction,
                ConnectionDestruction::ConnectingFutureDestroyed
                    | ConnectionDestruction::ConnectionDestroyed
            ));
            let final_permit = store::acquire_enrollment_session_permit(&cancel, cap)
                .await
                .map_err(|e| e.to_string())?;
            drop(final_permit);
            drop(seven);
            fresh.close();
            Ok(())
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires isolated owned PostgreSQL17; exact opt-in only"]
    async fn q02_guarded_original_retirement_limits_and_legacy_reuse() {
        let admin = harness::admin_config("whole_token_enrollment_guarded_limits");
        harness::with_temp_database(&admin,"enrollmentlimits",|config|async move {
            let db=pool::connect(&config.with_max_pool_size(1)).await.map_err(|e|e.to_string())?;
            let cancel=CancellationToken::new();
            let original=Instant::now()+Duration::from_secs(25);
            let mut legacy=db.get_guarded(original.into_std()).await.map_err(|e|e.to_string())?;
            let before:i32=legacy.as_client().query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            legacy.begin_read_committed().await.map_err(|e|e.to_string())?.commit().await.map_err(|e|e.to_string())?;
            drop(legacy);assert_eq!(db.status().available,1);
            let mut legacy=db.get_guarded(original.into_std()).await.map_err(|e|e.to_string())?;
            let after:i32=legacy.as_client().query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            assert_eq!(before,after);
            legacy.begin_read_committed().await.map_err(|e|e.to_string())?.rollback().await.map_err(|e|e.to_string())?;
            drop(legacy);

            let acquisition=original.min(Instant::now()+Duration::from_secs(5));
            let permit=store::acquire_enrollment_session_permit(&cancel,acquisition).await.map_err(|e|e.to_string())?;
            let mut guarded=tokio::time::timeout_at(acquisition,db.get_guarded_with_session_permit(original.into_std(),permit))
                .await.map_err(|_|"original acquisition cap ended")?.map_err(|e|e.to_string())?;
            tokio::time::timeout_at(acquisition,guarded.as_client().batch_execute(
                "SET statement_timeout='5000ms';SET lock_timeout='5000ms';SET idle_in_transaction_session_timeout='15000ms'"))
                .await.map_err(|_|"same acquisition cap ended during SET")?.map_err(|e|e.to_string())?;
            for (sql,expected) in [("SHOW statement_timeout","5s"),("SHOW lock_timeout","5s"),("SHOW idle_in_transaction_session_timeout","15s")] {
                let value:String=tokio::time::timeout_at(original.min(Instant::now()+Duration::from_secs(5)),guarded.as_client().query_one(sql,&[]))
                    .await.map_err(|_|"owned SHOW timeout")?.map_err(|e|e.to_string())?.get(0);
                assert_eq!(value,expected);
            }
            let tx=guarded.begin_read_committed().await.map_err(|e|e.to_string())?;
            // Observe the real PG fixed statement limit. Original terminal/cleanup remain separate.
            let timed=tokio::time::timeout_at(original,tx.as_transaction().query_one("SELECT pg_sleep(6)",&[]))
                .await.map_err(|_|"owned SQL exceeded original cap")?;
            let error=timed.expect_err("fixed statement_timeout must cancel a six-second SQL");
            assert_eq!(error.code(),Some(&tokio_postgres::error::SqlState::QUERY_CANCELED));
            let cleanup=original.min(Instant::now()+Duration::from_secs(1));
            tx.rollback_before(cleanup.into_std()).await.map_err(|e|e.to_string())?;
            let exact=guarded.retire_original();
            exact.wait_for_destruction_before(cleanup.into_std()).await.map_err(|e|e.to_string())?;
            assert_eq!(db.status().available,0);

            let permit=store::acquire_enrollment_session_permit(&cancel,original).await.map_err(|e|e.to_string())?;
            let mut guarded=db.get_guarded_with_session_permit(original.into_std(),permit).await.map_err(|e|e.to_string())?;
            guarded.begin_read_committed().await.map_err(|e|e.to_string())?
                .rollback_before(original.min(Instant::now()+Duration::from_secs(5)).into_std()).await.map_err(|e|e.to_string())?;
            // Fresh isolated pool has exactly this one owner; snapshot before Drop, not
            // arbitrary post-cancellation matching in the production consumer.
            let observations=db.connection_observations();assert_eq!(observations.len(),1);
            let exact=observations.into_iter().next().unwrap();
            drop(guarded); // The ACK -> caller-Drop edge must still permanently retire.
            assert_eq!(db.status().available,0);assert!(exact.snapshot().destruction.is_none());
            exact.wait_for_destruction_before(original.min(Instant::now()+Duration::from_secs(1)).into_std())
                .await.map_err(|e|e.to_string())?;
            assert!(exact.snapshot().connection_destroyed);
            db.close();Ok(())
        }).await;
    }
}
