//! A dedicated external controller restarts only its newly created synthetic PG cluster.
//! The controller must stop/start the same data directory before acknowledging this test.
//! Watch `request` in the explicit handshake directory and write `ready` with the exact marker
//! below only after `pg_ctl -w stop` and `pg_ctl -w start` have both exited successfully.

use super::*;
use openbot_application::ThreadConversationRequest;
use openbot_infra::repo::run::RunRepo;
use std::path::PathBuf;

async fn postmaster_started(pool: &Pool) -> Result<time::OffsetDateTime, String> {
    pool.get()
        .await
        .map_err(|e| e.to_string())?
        .query_one("SELECT pg_postmaster_start_time()", &[])
        .await
        .map_err(|e| e.to_string())?
        .try_get(0)
        .map_err(|e| e.to_string())
}

async fn occupancy(pool: &Pool) -> Result<Value, String> {
    pool.get().await.map_err(|e| e.to_string())?
        .query_one("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY thread_id),'[]') FROM public.thread_run_occupancy t", &[])
        .await.map_err(|e| e.to_string())?.try_get(0).map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "requires an owned PG stop/start controller and OPENBOT_TEST_RESTART_HANDSHAKE_DIR"]
async fn actual_postgres_restart_preserves_unknown_occupancy_and_positive_effect_history() {
    let handshake = PathBuf::from(
        std::env::var_os("OPENBOT_TEST_RESTART_HANDSHAKE_DIR")
            .expect("explicit owned PG restart controller required"),
    );
    assert!(handshake.is_absolute() && handshake.is_dir());
    assert!(!handshake.join("request").exists() && !handshake.join("ready").exists());
    fixture("occupancyactualrestart", |f| async move {
        // Real capability + memory producer commit, followed by a synthetic journal failure.
        let (result, request, _) = support::pipeline(
            &f.pool,
            &f.auth(),
            f.invocation(0, "thread"),
            Some(store(&f.pool)),
            true,
        )
        .await?;
        assert!(matches!(
            result,
            Err(AppError::ReconciliationRequired { .. })
        ));
        f.terminal().await?;
        let before_effects = effects(&f.pool).await?;
        let before_lifecycle = lifecycle(&f.pool).await?;
        let before_occupancy = occupancy(&f.pool).await?;
        assert_eq!(before_occupancy.as_array().unwrap().len(), 1);
        assert_eq!(before_effects["receipts"].as_array().unwrap().len(), 1);
        assert_eq!(before_lifecycle["attempts"].as_array().unwrap().len(), 1);
        assert_eq!(before_lifecycle["attempts"][0]["status"], "executing");
        assert!(before_lifecycle["attempts"][0]["commit_state"].is_null());
        let before_read = f.read().await?;
        // The later new-begin conflict must be occupancy, not another owner's live lease.
        assert!(f.pool.get().await.map_err(|e| e.to_string())?
            .query_one("SELECT coalesce(bool_and(expires_at<=now()),true) FROM public.thread_leases WHERE thread_id=$1", &[&f.begin.command.thread_id.as_str()])
            .await.map_err(|e| e.to_string())?.get::<_, bool>(0));
        let before_start = postmaster_started(&f.pool).await?;
        let config = f.config.clone();
        let query = f.query();
        let begin = f.begin.clone();
        f.pool.close();
        drop(f);

        std::fs::write(handshake.join("request"), b"restart-owned-cluster\n")
            .map_err(|e| e.to_string())?;
        tokio::time::timeout(Duration::from_secs(45), async {
            while !handshake.join("ready").is_file() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .map_err(|_| "owned PG restart acknowledgement timed out")?;
        assert_eq!(
            std::fs::read(handshake.join("ready")).map_err(|e| e.to_string())?,
            b"same-data-directory-restarted\n"
        );

        let restarted = pool::connect(&config).await.map_err(|e| e.to_string())?;
        let outcome = async {
            assert!(postmaster_started(&restarted).await? > before_start);
            assert_eq!(effects(&restarted).await?, before_effects);
            assert_eq!(lifecycle(&restarted).await?, before_lifecycle);
            assert_eq!(occupancy(&restarted).await?, before_occupancy);
            let directory = PostgresThreadDirectory::with_runtime(
                restarted.clone(),
                config,
                "restarted-runtime".into(),
                time::Duration::minutes(10),
                openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&restarted, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
            )
            .map_err(|e| e.to_string())?;
            let conversation = directory
                .thread_conversation(ThreadConversationRequest {
                    deployment: begin.deployment.clone(),
                    tenant: begin.tenant.clone(),
                    actor: begin.actor.clone(),
                    thread: begin.command.thread_id.clone(),
                })
                .await
                .map_err(|e| e.to_string())?;
            assert_eq!(
                conversation.active_run_id,
                Some(begin.command.run_id.clone())
            );
            let active = RunRepo::new(restarted.clone())
                .active_foreground_for_thread(begin.command.thread_id.as_str())
                .await
                .map_err(|e| e.to_string())?
                .ok_or("restart lost occupancy")?;
            assert_eq!(active.run_id, begin.command.run_id.as_str());
            assert_eq!(active.status, "reconciliation_required");
            assert!(
                directory
                    .run_reconciliation(query.clone())
                    .await
                    .map_err(|e| e.to_string())?
                    .foreground_blocked
            );
            let actual = directory
                .run_effect_receipts(query)
                .await
                .map_err(|e| e.to_string())?;
            assert_eq!(actual.receipts, before_read.receipts);
            assert_eq!(
                actual.terminal_event_sequence,
                before_read.terminal_event_sequence
            );
            assert!(actual.foreground_blocked);
            let mut next = begin.clone();
            next.command.run_id = RunId::new("restart-must-stay-blocked");
            assert_eq!(
                directory.begin_thread_run(next).await,
                Err(ThreadDirectoryError::LeaseConflict)
            );
            assert!(
                directory
                    .begin_thread_run(begin)
                    .await
                    .map_err(|e| e.to_string())?
                    .replayed
            );
            let historical = store(&restarted)
                .remember_from_tool(request)
                .await
                .map_err(|e| e.to_string())?;
            assert_eq!(historical.receipt_id, before_read.receipts[0].receipt_id);
            assert_eq!(effects(&restarted).await?, before_effects);
            assert_eq!(lifecycle(&restarted).await?, before_lifecycle);
            assert_eq!(occupancy(&restarted).await?, before_occupancy);
            Ok(())
        }
        .await;
        restarted.close();
        outcome
    })
    .await;
}
