use super::*;

fn journal_rows(value: &Value) -> Value {
    serde_json::json!({"calls":value["calls"],"attempts":value["attempts"],
        "receipts":value["receipts"],"audit":value["audit"]})
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn four_repositories_wait_for_real_terminal_and_read_new_state_under_repeatable_default() {
    fixture("journal_terminal_first", |f| async move {
        for kind in WRITES {
            let case = f.run().await?;
            let operation = Operation::prepare(&f.pool, &case.draft, kind).await?;
            let before = snapshot(&f.pool).await?;
            let (writer, writer_pid) =
                dedicated(&f.config, "journal-terminal-writer", true).await?;
            let (terminal, terminal_pid) =
                dedicated(&f.config, "journal-terminal-owner", false).await?;
            trigger(
                &f.pool,
                "thread_leases",
                "UPDATE",
                case.lease.run_id().as_str(),
                false,
            )
            .await?;
            let (gate_client, gate_pid) = gate(&f.pool).await?;
            let observer = f.pool.get().await.map_err(|e| e.to_string())?;
            let terminal_runtime = runtime(&terminal)?;
            let lease = case.lease.clone();
            let terminal_task = tokio::spawn(async move {
                terminal_runtime
                    .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
                    .await
            });
            blocked(&observer, terminal_pid, gate_pid).await?;
            let writer_pool = writer.clone();
            let writer_task = tokio::spawn(async move { operation.invoke(&writer_pool).await });
            blocked(&observer, writer_pid, terminal_pid).await?;
            ungate(&gate_client).await?;
            terminal_task
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
            assert_write_conflict(writer_task.await.map_err(|e| e.to_string())?);
            assert_eq!(
                journal_rows(&snapshot(&f.pool).await?),
                journal_rows(&before),
                "{kind:?}"
            );
            untrigger(&f.pool, "thread_leases").await?;
            writer.close();
            terminal.close();
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn four_real_writers_serialize_terminal_after_commit_and_after_rollback() {
    fixture("journal_writer_first", |f| async move {
        for fail in [false, true] {
            for kind in WRITES {
                let case = f.run().await?;
                let operation = Operation::prepare(&f.pool, &case.draft, kind).await?;
                let before = snapshot(&f.pool).await?;
                let (table, event) = match kind {
                    WriteKind::Decision => ("tool_calls", "INSERT"),
                    WriteKind::Retry => ("tool_attempts", "INSERT"),
                    WriteKind::Attach | WriteKind::Outcome => ("tool_attempts", "UPDATE"),
                };
                trigger(&f.pool, table, event, case.draft.call_id.as_str(), fail).await?;
                let (writer, writer_pid) =
                    dedicated(&f.config, "journal-first-writer", true).await?;
                let (terminal, terminal_pid) =
                    dedicated(&f.config, "journal-waiting-terminal", false).await?;
                let (gate_client, gate_pid) = gate(&f.pool).await?;
                let observer = f.pool.get().await.map_err(|e| e.to_string())?;
                let writer_pool = writer.clone();
                let writer_operation = operation.clone();
                let writer_task =
                    tokio::spawn(async move { writer_operation.invoke(&writer_pool).await });
                blocked(&observer, writer_pid, gate_pid).await?;
                let terminal_runtime = runtime(&terminal)?;
                let lease = case.lease.clone();
                let terminal_task = tokio::spawn(async move {
                    terminal_runtime
                        .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
                        .await
                });
                blocked(&observer, terminal_pid, writer_pid).await?;
                ungate(&gate_client).await?;
                let result = writer_task.await.map_err(|e| e.to_string())?;
                if fail {
                    assert_eq!(result.unwrap_err().sqlstate(), Some("P0001"));
                } else {
                    result.map_err(|e| e.to_string())?;
                }
                terminal_task
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())?;
                let after = snapshot(&f.pool).await?;
                if fail {
                    assert_eq!(
                        journal_rows(&after),
                        journal_rows(&before),
                        "{kind:?} rollback"
                    );
                } else {
                    assert_ne!(
                        journal_rows(&after),
                        journal_rows(&before),
                        "{kind:?} commit"
                    );
                }
                assert_write_conflict(operation.invoke(&f.pool).await);
                assert_eq!(snapshot(&f.pool).await?, after);
                untrigger(&f.pool, table).await?;
                writer.close();
                terminal.close();
            }
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn run_lock_timeout_and_call_attempt_nowait_roll_back_as_unavailable() {
    fixture("journal_lock_failures", |f| async move {
        let case = f.run().await?;
        let before = snapshot(&f.pool).await?;
        let mut control = f.pool.get().await.map_err(|e| e.to_string())?;
        let owner: i32 = control
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let tx = control.transaction().await.map_err(|e| e.to_string())?;
        tx.query_one(
            "SELECT run_id FROM public.runs WHERE run_id=$1 FOR UPDATE",
            &[&case.lease.run_id().as_str()],
        )
        .await
        .map_err(|e| e.to_string())?;
        let (writer, writer_pid) = dedicated(&f.config, "journal-timeout", true).await?;
        let j = journal(&writer);
        let draft = case.draft.clone();
        let task = tokio::spawn(async move { j.record_decision(&draft).await });
        let observer = f.pool.get().await.map_err(|e| e.to_string())?;
        blocked(&observer, writer_pid, owner).await?;
        let result = tokio::time::timeout(Duration::from_secs(8), task)
            .await
            .map_err(|_| "journal lock timeout missing")?
            .map_err(|e| e.to_string())?;
        assert!(matches!(result, Err(ToolPortError::Unavailable { .. })));
        tx.rollback().await.map_err(|e| e.to_string())?;
        assert_eq!(snapshot(&f.pool).await?, before);
        writer.close();

        let d = executing(&f.pool, case.draft).await?;
        for sql in [
            "SELECT tool_call_id FROM public.tool_calls WHERE tool_call_id=$1 FOR UPDATE",
            "SELECT tool_call_id FROM public.tool_attempts WHERE tool_call_id=$1 FOR UPDATE",
        ] {
            let before = snapshot(&f.pool).await?;
            let tx = control.transaction().await.map_err(|e| e.to_string())?;
            tx.query_one(sql, &[&d.decision.call_id.as_str()])
                .await
                .map_err(|e| e.to_string())?;
            let result =
                tokio::time::timeout(Duration::from_secs(2), journal(&f.pool).record_outcome(&d))
                    .await
                    .map_err(|_| "journal NOWAIT unexpectedly waited")?;
            assert!(matches!(result, Err(ToolPortError::Unavailable { .. })));
            tx.rollback().await.map_err(|e| e.to_string())?;
            assert_eq!(snapshot(&f.pool).await?, before);
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn generic_journal_outcome_waits_for_terminal_under_repeatable_default() {
    fixture("journal_outcome_terminal", |f| async move {
        let case = f.run().await?;
        let d = executing(&f.pool, case.draft).await?;
        let before = snapshot(&f.pool).await?;
        let (writer, writer_pid) = dedicated(&f.config, "journal-outcome-writer", true).await?;
        let (terminal, terminal_pid) =
            dedicated(&f.config, "journal-outcome-terminal", false).await?;
        trigger(
            &f.pool,
            "thread_leases",
            "UPDATE",
            case.lease.run_id().as_str(),
            false,
        )
        .await?;
        let (gate_client, gate_pid) = gate(&f.pool).await?;
        let observer = f.pool.get().await.map_err(|e| e.to_string())?;
        let terminal_runtime = runtime(&terminal)?;
        let lease = case.lease;
        let terminal_task = tokio::spawn(async move {
            terminal_runtime
                .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
                .await
        });
        blocked(&observer, terminal_pid, gate_pid).await?;
        let j = journal(&writer);
        let writer_task = tokio::spawn(async move { j.record_outcome(&d).await });
        blocked(&observer, writer_pid, terminal_pid).await?;
        ungate(&gate_client).await?;
        terminal_task
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        assert_eq!(
            writer_task.await.map_err(|e| e.to_string())?,
            Err(ToolPortError::Conflict)
        );
        assert_eq!(
            journal_rows(&snapshot(&f.pool).await?),
            journal_rows(&before)
        );
        writer.close();
        terminal.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn remember_waits_for_actor_before_run_and_reads_terminal_after_actor_wait() {
    fixture("journal_remember_actor", |f| async move {
        let case = f.run().await?;
        let d = executing(&f.pool, remember_draft(case.draft)).await?;
        let before = snapshot(&f.pool).await?;
        let mut control = f.pool.get().await.map_err(|e| e.to_string())?;
        let control_pid: i32 = control
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let tx = control.transaction().await.map_err(|e| e.to_string())?;
        tx.query_one(
            "SELECT id FROM public.users WHERE id=$1 FOR UPDATE",
            &[&ACTOR],
        )
        .await
        .map_err(|e| e.to_string())?;
        let (writer, writer_pid) = dedicated(&f.config, "journal-remember-actor", true).await?;
        let j = journal(&writer);
        let task = tokio::spawn(async move { j.record_outcome(&d).await });
        let observer = f.pool.get().await.map_err(|e| e.to_string())?;
        blocked(&observer, writer_pid, control_pid).await?;
        // Finishing while the actor lock is still held proves the journal did not lock run first.
        tokio::time::timeout(
            Duration::from_secs(2),
            runtime(&f.pool)?.finish_run(
                &case.lease,
                case.lease.next_event_sequence(),
                RunTerminal::Completed,
            ),
        )
        .await
        .map_err(|_| "remember acquired run before actor")?
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        assert_eq!(
            task.await.map_err(|e| e.to_string())?,
            Err(ToolPortError::Conflict)
        );
        assert_eq!(
            journal_rows(&snapshot(&f.pool).await?),
            journal_rows(&before)
        );
        writer.close();
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn remember_run_nowait_and_writer_first_real_terminal_remain_serialized() {
    fixture("journal_remember_run", |f| async move {
        let case = f.run().await?;
        let d = executing(&f.pool, remember_draft(case.draft)).await?;
        let before = snapshot(&f.pool).await?;
        let mut control = f.pool.get().await.map_err(|e| e.to_string())?;
        let tx = control.transaction().await.map_err(|e| e.to_string())?;
        tx.query_one(
            "SELECT run_id FROM public.runs WHERE run_id=$1 FOR UPDATE",
            &[&case.lease.run_id().as_str()],
        )
        .await
        .map_err(|e| e.to_string())?;
        let result =
            tokio::time::timeout(Duration::from_secs(2), journal(&f.pool).record_outcome(&d))
                .await
                .map_err(|_| "remember run guard unexpectedly waited")?;
        assert!(matches!(result, Err(ToolPortError::Unavailable { .. })));
        tx.rollback().await.map_err(|e| e.to_string())?;
        assert_eq!(snapshot(&f.pool).await?, before);
        trigger(
            &f.pool,
            "audit_events",
            "INSERT",
            case.lease.run_id().as_str(),
            false,
        )
        .await?;
        let (writer, writer_pid) = dedicated(&f.config, "remember-first-writer", true).await?;
        let (terminal, terminal_pid) =
            dedicated(&f.config, "remember-waiting-terminal", false).await?;
        let (gate_client, gate_pid) = gate(&f.pool).await?;
        let observer = f.pool.get().await.map_err(|e| e.to_string())?;
        let j = journal(&writer);
        let task = tokio::spawn(async move { j.record_outcome(&d).await });
        blocked(&observer, writer_pid, gate_pid).await?;
        let terminal_runtime = runtime(&terminal)?;
        let lease = case.lease;
        let terminal_task = tokio::spawn(async move {
            terminal_runtime
                .finish_run(&lease, lease.next_event_sequence(), RunTerminal::Completed)
                .await
        });
        blocked(&observer, terminal_pid, writer_pid).await?;
        ungate(&gate_client).await?;
        task.await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        terminal_task
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        let after = snapshot(&f.pool).await?;
        assert_eq!(after["audit"].as_array().unwrap().len(), 1);
        assert_eq!(after["attempts"][0]["status"], "completed");
        assert_eq!(
            after["receipts"], before["receipts"],
            "journal is not an effect producer"
        );
        writer.close();
        terminal.close();
        Ok(())
    })
    .await;
}
