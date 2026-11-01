use super::*;

async fn dedicated(
    config: &DatabaseConfig,
    name: &str,
    repeatable: bool,
) -> Result<(Pool, i32), String> {
    let p = pool::connect(
        &config
            .clone()
            .with_max_pool_size(1)
            .with_application_name(name),
    )
    .await
    .map_err(|e| e.to_string())?;
    let c = p.get().await.map_err(|e| e.to_string())?;
    if repeatable {
        c.batch_execute("SET default_transaction_isolation='repeatable read'")
            .await
            .map_err(|e| e.to_string())?;
    }
    let pid = c
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    drop(c);
    Ok((p, pid))
}

async fn blocked(observer: &tokio_postgres::Client, worker: i32, owner: i32) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            // PostgreSQL may put a later SHARE waiter behind a queued UPDATE tuple waiter.
            // Prove the full blocking chain reaches the intended owner, rather than treating
            // any wait as sufficient or insisting every waiter is directly behind that owner.
            if observer
                .query_one("WITH RECURSIVE waits(pid,path) AS (SELECT $1::integer,ARRAY[$1::integer] UNION ALL SELECT blocker.pid,waits.path||blocker.pid FROM waits CROSS JOIN LATERAL unnest(pg_blocking_pids(waits.pid)) blocker(pid) WHERE NOT blocker.pid=ANY(waits.path) AND cardinality(waits.path)<16) SELECT EXISTS(SELECT 1 FROM waits WHERE pid=$2 AND cardinality(path)>1)", &[&worker, &owner])
                .await
                .map_err(|e| e.to_string())?
                .get::<_, bool>(0)
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "owned barrier did not observe lock wait".to_owned())?
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn concurrent_exact_duplicate_commits_one_effect_and_no_additional_audit() {
    fixture("rememberduplicate", |f| async move {
        let request = f.capture(0).await?;
        let (producer, producer_pid) = dedicated(&f.config, "duplicate-producer", false).await?;
        let (duplicate, duplicate_pid) = dedicated(&f.config, "duplicate-waiter", false).await?;
        let observer = f.pool.get().await.map_err(|e| e.to_string())?;
        let mut blocker = f.pool.get().await.map_err(|e| e.to_string())?;
        let blocker_pid = blocker
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let tx = blocker.transaction().await.map_err(|e| e.to_string())?;
        tx.batch_execute("LOCK TABLE public.memory_events IN ACCESS EXCLUSIVE MODE")
            .await
            .map_err(|e| e.to_string())?;
        let a = store(&producer);
        let first_request = request.clone();
        let first = tokio::spawn(async move { a.remember_from_tool(first_request).await });
        blocked(&observer, producer_pid, blocker_pid).await?;
        let b = store(&duplicate);
        let second = tokio::spawn(async move { b.remember_from_tool(request).await });
        blocked(&observer, duplicate_pid, producer_pid).await?;
        tx.commit().await.map_err(|e| e.to_string())?;
        let (one, two) = (
            first.await.map_err(|e| e.to_string())?,
            second.await.map_err(|e| e.to_string())?,
        );
        assert_eq!(one, two);
        one.map_err(|e| e.to_string())?;
        let state = effects(&f.pool).await?;
        for field in ["memories", "events", "receipts"] {
            assert_eq!(state[field].as_array().unwrap().len(), 1);
        }
        assert_eq!(
            state["audit"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|a| a["event_type"] == "memory.effect_committed")
                .count(),
            1
        );
        producer.close();
        duplicate.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn current_actor_and_absent_default_control_recheck_after_actor_lock_wait() {
    for revoke in [true, false] {
        fixture(if revoke {"rememberrevokefirst"} else {"rememberdisablefirst"},|f|async move {
            let request=f.capture(0).await?;let before=effects(&f.pool).await?;
            let (worker,pid)=dedicated(&f.config,"effect-actor-wait",false).await?;
            let observer=f.pool.get().await.map_err(|e|e.to_string())?;
            let mut owner=f.pool.get().await.map_err(|e|e.to_string())?;
            let owner_pid=owner.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            let tx=owner.transaction().await.map_err(|e|e.to_string())?;
            if revoke {tx.batch_execute("UPDATE public.users SET auth_generation=1 WHERE id='actor-a'").await.map_err(|e|e.to_string())?;}
            else {tx.batch_execute("SELECT id FROM public.users WHERE id='actor-a' FOR SHARE; INSERT INTO public.user_memory_controls(tenant_id,actor_user_id,writes_enabled,updated_at) VALUES('tenant-a','actor-a',false,clock_timestamp())").await.map_err(|e|e.to_string())?;}
            let memory=store(&worker);let task=tokio::spawn(async move {memory.remember_from_tool(request).await});
            blocked(&observer,pid,owner_pid).await?;tx.commit().await.map_err(|e|e.to_string())?;
            let result=task.await.map_err(|e|e.to_string())?;
            assert_eq!(result,Err(if revoke {MemoryError::NotVisible} else {MemoryError::WritesDisabled}));
            assert_eq!(effects(&f.pool).await?,before);worker.close();Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn producer_actor_update_serializes_real_control_and_journal_sees_new_receipt_under_rr_default()
 {
    fixture("rememberlocking", |f| async move {
        let (_, request, mut draft) =
            support::pipeline(&f.pool, &f.auth(), f.invocation(0, "user"), None, true).await?;
        draft.outcome.commit_state = CommitState::NotCommitted;
        let (producer, producer_pid) = dedicated(&f.config, "effect-producer", false).await?;
        let (journal_pool, journal_pid) =
            dedicated(&f.config, "effect-journal-repeatable-default", true).await?;
        let (control_pool, control_pid) =
            dedicated(&f.config, "effect-memory-control", false).await?;
        let observer = f.pool.get().await.map_err(|e| e.to_string())?;
        let mut blocker = f.pool.get().await.map_err(|e| e.to_string())?;
        let blocker_pid = blocker
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let tx = blocker.transaction().await.map_err(|e| e.to_string())?;
        tx.batch_execute("LOCK TABLE public.memory_events IN ACCESS EXCLUSIVE MODE")
            .await
            .map_err(|e| e.to_string())?;
        let memory = store(&producer);
        let production = tokio::spawn(async move { memory.remember_from_tool(request).await });
        blocked(&observer, producer_pid, blocker_pid).await?;
        let journal = PostgresToolJournal::new(journal_pool.clone(), KEY.to_vec())
            .map_err(|e| e.to_string())?;
        let journal_task = tokio::spawn(async move { journal.record_outcome(&draft).await });
        blocked(&observer, journal_pid, producer_pid).await?;
        let memory = store(&control_pool);
        let update = UpdateMemoryControlRequest {
            tenant: f.begin.tenant.clone(),
            actor: f.begin.actor.clone(),
            auth_generation: AuthGeneration::new(0),
            update: UpdateMemoryControl {
                writes_enabled: false,
            },
        };
        let control = tokio::spawn(async move { memory.update_memory_control(update).await });
        blocked(&observer, control_pid, producer_pid).await?;
        tx.commit().await.map_err(|e| e.to_string())?;
        production
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        assert_eq!(
            journal_task.await.map_err(|e| e.to_string())?,
            Err(openbot_application::ToolPortError::Conflict)
        );
        assert!(
            !control
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?
                .writes_enabled
        );
        let attempt = observer
            .query_one("SELECT status,commit_state FROM public.tool_attempts", &[])
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(attempt.get::<_, String>(0), "executing");
        assert_eq!(attempt.get::<_, Option<String>>(1), None);
        assert_eq!(
            effects(&f.pool).await?["receipts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        producer.close();
        journal_pool.close();
        control_pool.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn terminal_lease_and_accepted_cancellation_fence_fresh_effect() {
    fixture("remembercancel", |f| async move {
        let request = f.capture(0).await?;
        let before = effects(&f.pool).await?;
        f.directory
            .cancel_thread_run(CancelThreadRunRequest {
                deployment: f.begin.deployment.clone(),
                tenant: f.begin.tenant.clone(),
                actor: f.begin.actor.clone(),
                command: CancelThreadRun {
                    thread_id: f.begin.command.thread_id.clone(),
                    run_id: f.begin.command.run_id.clone(),
                },
            })
            .await
            .map_err(|e| e.to_string())?;
        for status in ["pending", "delivering", "delivered", "dead_letter"] {
            f.sql(&format!(
                "UPDATE public.outbox SET status='{status}',claimed_by=CASE WHEN '{status}'='delivering' THEN 'owned-fixture' ELSE NULL END,claim_expires_at=CASE WHEN '{status}'='delivering' THEN clock_timestamp()+interval '1 minute' ELSE NULL END,delivered_at=CASE WHEN '{status}'='delivered' THEN clock_timestamp() ELSE NULL END WHERE destination='agent_run_cancel'"
            ))
            .await?;
            assert_eq!(
                store(&f.pool).remember_from_tool(request.clone()).await,
                Err(MemoryError::Conflict)
            );
        }
        f.sql("UPDATE public.outbox SET payload='{}' WHERE destination='agent_run_cancel'")
            .await?;
        assert!(matches!(
            store(&f.pool).remember_from_tool(request).await,
            Err(MemoryError::Corrupt { .. })
        ));
        assert_eq!(effects(&f.pool).await?, before);
        Ok(())
    })
    .await;
    fixture("rememberterminal", |f| async move {
        let request = f.capture(0).await?;
        let before = effects(&f.pool).await?;
        f.sql("UPDATE public.thread_leases SET acquired_at=clock_timestamp()-interval '2 minutes',updated_at=clock_timestamp()-interval '1 minute',expires_at=clock_timestamp()-interval '1 second'")
            .await?;
        assert_eq!(
            store(&f.pool).remember_from_tool(request.clone()).await,
            Err(MemoryError::Conflict)
        );
        f.sql("UPDATE public.thread_leases SET expires_at=clock_timestamp()+interval '10 minutes'")
            .await?;
        f.terminal().await?;
        assert_eq!(
            store(&f.pool).remember_from_tool(request).await,
            Err(MemoryError::Conflict)
        );
        assert_eq!(effects(&f.pool).await?, before);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn nowait_lock_and_audit_timeout_rollback_without_claiming_negative_evidence() {
    fixture("rememberlockfailure", |f| async move {
        let request = f.capture(0).await?;
        let before = effects(&f.pool).await?;
        let mut owner = f.pool.get().await.map_err(|e| e.to_string())?;
        let tx = owner.transaction().await.map_err(|e| e.to_string())?;
        tx.batch_execute("SELECT run_id FROM public.runs FOR UPDATE")
            .await
            .map_err(|e| e.to_string())?;
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            store(&f.pool).remember_from_tool(request.clone()),
        )
        .await
        .map_err(|_| "run NOWAIT waited".to_owned())?;
        assert_eq!(result, Err(MemoryError::Unavailable));
        tx.rollback().await.map_err(|e| e.to_string())?;
        let tx = owner.transaction().await.map_err(|e| e.to_string())?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock($1)",
            &[&0x4f50_454e_4155_4431_i64],
        )
        .await
        .map_err(|e| e.to_string())?;
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            store(&f.pool).remember_from_tool(request.clone()),
        )
        .await
        .map_err(|_| "audit lock exceeded transaction lock timeout".to_owned())?;
        assert_eq!(result, Err(MemoryError::Unavailable));
        assert_eq!(effects(&f.pool).await?, before);
        // Caller timeout drops the future/transaction; releasing the barrier cannot create an effect.
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                store(&f.pool).remember_from_tool(request.clone())
            )
            .await
            .is_err()
        );
        tx.rollback().await.map_err(|e| e.to_string())?;
        f.terminal().await?;
        assert_eq!(
            store(&f.pool).remember_from_tool(request).await,
            Err(MemoryError::Conflict)
        );
        assert_eq!(effects(&f.pool).await?, before);
        assert!(f.read().await?.receipts.is_empty());
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn existing_bot_profile_locks_refuse_fresh_and_historical_requests_without_negative_outcome()
{
    fixture("rememberprofilelocks", |f| async move {
        let (_, request, mut negative) =
            support::pipeline(&f.pool, &f.auth(), f.invocation(0, "user"), None, true).await?;
        let journal =
            PostgresToolJournal::new(f.pool.clone(), KEY.to_vec()).map_err(|e| e.to_string())?;
        let mut owner = f.pool.get().await.map_err(|e| e.to_string())?;
        for historical in [false, true] {
            if historical {
                store(&f.pool)
                    .remember_from_tool(request.clone())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            for table in ["agents", "agent_profiles"] {
                let before = effects(&f.pool).await?;
                let original_lifecycle = lifecycle(&f.pool).await?;
                let tx = owner.transaction().await.map_err(|e| e.to_string())?;
                let key = if table == "agents" { "id" } else { "agent_id" };
                tx.batch_execute(&format!(
                    "SELECT {key} FROM public.{table} WHERE {key}='bot-a' FOR UPDATE"
                ))
                .await
                .map_err(|e| e.to_string())?;
                let result = tokio::time::timeout(
                    Duration::from_secs(2),
                    store(&f.pool).remember_from_tool(request.clone()),
                )
                .await
                .map_err(|_| "ACL NOWAIT waited".to_owned())?;
                assert_eq!(result, Err(MemoryError::Unavailable));
                if historical {
                    negative.outcome.commit_state = CommitState::NotCommitted;
                    assert_eq!(
                        journal.record_outcome(&negative).await,
                        Err(openbot_application::ToolPortError::Conflict)
                    );
                }
                assert_eq!(effects(&f.pool).await?, before);
                assert_eq!(lifecycle(&f.pool).await?, original_lifecycle);
                tx.rollback().await.map_err(|e| e.to_string())?;
            }
        }
        let before = effects(&f.pool).await?;
        store(&f.pool)
            .remember_from_tool(request)
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(effects(&f.pool).await?, before);
        f.terminal().await?;
        assert_eq!(f.read().await?.receipts.len(), 1);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn producer_first_commit_orders_real_terminal_and_cancellation_without_erasing_receipt() {
    for cancel in [false, true] {
        fixture(if cancel {"effectbeforecancel"} else {"effectbeforeterminal"},|f|async move {
            let request=f.capture(0).await?;
            let (producer,producer_pid)=dedicated(&f.config,"effect-first-producer",false).await?;
            let (next_pool,next_pid)=dedicated(&f.config,"effect-next-run-operation",false).await?;
            let observer=f.pool.get().await.map_err(|e|e.to_string())?;
            let original_attempt=observer.query_one("SELECT to_jsonb(a) FROM public.tool_attempts a",&[]).await.map_err(|e|e.to_string())?.get::<_,Value>(0);
            let mut blocker=f.pool.get().await.map_err(|e|e.to_string())?;
            let blocker_pid=blocker.query_one("SELECT pg_backend_pid()",&[]).await.map_err(|e|e.to_string())?.get(0);
            let tx=blocker.transaction().await.map_err(|e|e.to_string())?;
            tx.batch_execute("LOCK TABLE public.memory_events IN ACCESS EXCLUSIVE MODE").await.map_err(|e|e.to_string())?;
            let memory=store(&producer);let first_request=request.clone();
            let production=tokio::spawn(async move {memory.remember_from_tool(first_request).await});
            blocked(&observer,producer_pid,blocker_pid).await?;
            let directory=PostgresThreadDirectory::with_runtime(next_pool.clone(),f.config.clone(),"effect-owner".into(),time::Duration::minutes(10), openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&next_pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside"))).map_err(|e|e.to_string())?;
            let runtime=PostgresRunRuntime::new(next_pool.clone(),"effect-owner".into(),time::Duration::minutes(10),DEFAULT_DISPATCH_CLAIM_DURATION, openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&next_pool, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside"))).map_err(|e|e.to_string())?;
            let lease=f.lease.clone();let begin=f.begin.clone();
            let next=tokio::spawn(async move {
                if cancel {
                    directory.cancel_thread_run(CancelThreadRunRequest {deployment:begin.deployment,tenant:begin.tenant,actor:begin.actor,command:CancelThreadRun {thread_id:begin.command.thread_id,run_id:begin.command.run_id}}).await.map(|_|()).map_err(|e|e.to_string())
                } else {
                    runtime.finish_run(&lease,lease.next_event_sequence(),RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown)).await.map(|_|()).map_err(|e|e.to_string())
                }
            });
            // This is the actual production run operation waiting on the producer's run lock.
            blocked(&observer,next_pid,producer_pid).await?;
            tx.commit().await.map_err(|e|e.to_string())?;
            let historical=production.await.map_err(|e|e.to_string())?.map_err(|e|e.to_string())?;
            next.await.map_err(|e|e.to_string())??;
            if cancel {
                let row=observer.query_one("SELECT status,(SELECT count(*) FROM public.outbox WHERE destination='agent_run_cancel' AND status='pending') AS accepted FROM public.runs",&[]).await.map_err(|e|e.to_string())?;
                assert_eq!(row.get::<_,String>("status"),"running");assert_eq!(row.get::<_,i64>("accepted"),1);
                let before=effects(&f.pool).await?;
                assert_eq!(store(&f.pool).remember_from_tool(request.clone()).await.map_err(|e|e.to_string())?,historical);
                assert_eq!(effects(&f.pool).await?,before);
                f.terminal().await?;
            }
            let before=effects(&f.pool).await?;let original_lifecycle=lifecycle(&f.pool).await?;
            assert_eq!(before["receipts"].as_array().unwrap().len(),1);
            assert_eq!(store(&f.pool).remember_from_tool(request).await.map_err(|e|e.to_string())?,historical);
            let read=f.read().await?;assert_eq!(read.receipts[0].receipt_id,historical.receipt_id);assert!(read.foreground_blocked);
            assert_eq!(observer.query_one("SELECT to_jsonb(a) FROM public.tool_attempts a",&[]).await.map_err(|e|e.to_string())?.get::<_,Value>(0),original_attempt);
            assert_eq!(effects(&f.pool).await?,before);assert_eq!(lifecycle(&f.pool).await?,original_lifecycle);
            producer.close();next_pool.close();Ok(())
        }).await;
    }
}
