use super::*;

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn generic_outcome_compares_every_original_receipt_and_decision_field() {
    fixture("journal_bound_fields", |f| async move {
        let mut case = f.run().await?;
        // Both declared execute and unknown classification use execute, isolating downgrade.
        case.draft.metadata.effect = EffectClassification::declared(Effect::Execute);
        let original = executing(&f.pool, case.draft).await?;
        let before = snapshot(&f.pool).await?;
        for field in 0..21 {
            let mut d = original.clone();
            match field {
                0 => {
                    d.receipt = DurableDecisionReceipt::issued_by_repository(
                        PolicyDecisionId::new(Uuid::now_v7().to_string()),
                        d.receipt.attempt().clone(),
                    )
                }
                1 => {
                    d.receipt = DurableDecisionReceipt::issued_by_repository(
                        d.receipt.decision().clone(),
                        AttemptId::new(Uuid::now_v7().to_string()),
                    )
                }
                2 => d.decision.call_id = ToolCallId::new(Uuid::now_v7().to_string()),
                3 => d.decision.run_id = RunId::new(Uuid::now_v7().to_string()),
                4 => d.decision.call_seq += 1,
                5 => d.decision.actor = ActorId::new("other-actor"),
                6 => d.decision.bot = BotId::new("other-bot"),
                7 => d.capability_id = CapabilityId::new(Uuid::now_v7().to_string()),
                8 => d.decision.metadata.name = ToolName::new("computer.other").unwrap(),
                9 => d.decision.args_hash = Sha256Digest::of(b"other arguments"),
                10 => d.decision.metadata.schema_hash = Sha256Digest::of(b"other schema"),
                11 => d.decision.metadata.catalog_generation = CatalogGeneration::new(4),
                12 => d.decision.target.kind = "other_target",
                13 => d.decision.target.id = "other-target".to_owned(),
                14 => d.decision.metadata.effect = EffectClassification::declared(Effect::Write),
                15 => d.decision.metadata.effect = EffectClassification::classify("unknown-effect"),
                16 => d.decision.metadata.idempotency = Idempotency::Idempotent,
                17 => {
                    d.decision.idempotency_key =
                        Some(IdempotencyKey::new("owned-other-key").unwrap())
                }
                18 => d.decision.metadata.approval_class = ApprovalClass::EveryCall,
                19 => d.decision.policy_version = PolicyVersionTag::new("other-policy"),
                20 => d.decision.approval_id = Some(Uuid::now_v7().to_string()),
                _ => unreachable!(),
            }
            assert_eq!(
                journal(&f.pool).record_outcome(&d).await,
                Err(ToolPortError::Conflict),
                "field {field}"
            );
            assert_eq!(snapshot(&f.pool).await?, before, "field {field}");
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn foreign_receipt_attempt_is_not_locked_or_written() {
    fixture("journal_foreign_attempt", |f| async move {
        let mut first = executing(&f.pool, f.run().await?.draft).await?;
        let second = executing(&f.pool, f.run().await?.draft).await?;
        first.receipt = DurableDecisionReceipt::issued_by_repository(
            first.receipt.decision().clone(),
            second.receipt.attempt().clone(),
        );
        let before = snapshot(&f.pool).await?;
        let mut client = f.pool.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        tx.query_one(
            "SELECT attempt_id FROM public.tool_attempts WHERE attempt_id=$1 FOR UPDATE",
            &[&second.receipt.attempt().as_str()],
        )
        .await
        .map_err(|e| e.to_string())?;
        assert_eq!(
            journal(&f.pool).record_outcome(&first).await,
            Err(ToolPortError::Conflict)
        );
        tx.rollback().await.map_err(|e| e.to_string())?;
        assert_eq!(snapshot(&f.pool).await?, before);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn missing_expected_rows_conflict_but_stored_binding_status_and_decode_damage_are_corrupt() {
    fixture("journal_corruption", |f| async move {
        let case = f.run().await?;
        let mut missing = case.draft.clone();
        missing.run_id = RunId::new(Uuid::now_v7().to_string());
        let before = snapshot(&f.pool).await?;
        assert_eq!(
            journal(&f.pool).record_decision(&missing).await,
            Err(ToolPortError::Conflict)
        );
        assert_eq!(
            journal(&f.pool)
                .attach_capability(&missing.call_id, &CapabilityId::new("missing-cap"))
                .await,
            Err(ToolPortError::Conflict)
        );
        assert_eq!(snapshot(&f.pool).await?, before);
        let d = executing(&f.pool, case.draft).await?;
        let client = f.pool.get().await.map_err(|e| e.to_string())?;
        for (column, value, original) in [
            ("actor_id", "bad-stored-actor", ACTOR),
            ("bot_id", "bad-stored-bot", BOT),
        ] {
            client
                .execute(
                    &format!("UPDATE public.tool_calls SET {column}=$1 WHERE tool_call_id=$2"),
                    &[&value, &d.decision.call_id.as_str()],
                )
                .await
                .map_err(|e| e.to_string())?;
            let before = snapshot(&f.pool).await?;
            assert!(matches!(
                journal(&f.pool).record_outcome(&d).await,
                Err(ToolPortError::Corrupt { .. })
            ));
            assert!(matches!(
                journal(&f.pool)
                    .attach_capability(&d.decision.call_id, &d.capability_id)
                    .await,
                Err(ToolPortError::Corrupt { .. })
            ));
            assert_eq!(snapshot(&f.pool).await?, before);
            client
                .execute(
                    &format!("UPDATE public.tool_calls SET {column}=$1 WHERE tool_call_id=$2"),
                    &[&original, &d.decision.call_id.as_str()],
                )
                .await
                .map_err(|e| e.to_string())?;
        }
        // Only this disposable database drops checks to model persisted damage. Production SQL is unchanged.
        client
            .batch_execute(
                "ALTER TABLE public.runs DISABLE TRIGGER USER;
            ALTER TABLE public.runs DROP CONSTRAINT runs_status_known,
            DROP CONSTRAINT runs_terminal_shape,DROP CONSTRAINT runs_started_shape;
            ALTER TABLE public.tool_attempts DROP CONSTRAINT tool_attempts_status_known;
            ALTER TABLE public.tool_calls DROP CONSTRAINT tool_calls_run_id_fkey;
            ALTER TABLE public.tool_calls ALTER COLUMN actor_id DROP NOT NULL;",
            )
            .await
            .map_err(|e| e.to_string())?;
        for (damage, restore) in [
            (
                "UPDATE public.runs SET status='unknown_status'",
                "UPDATE public.runs SET status='running'",
            ),
            (
                "UPDATE public.tool_attempts SET status='unknown_status'",
                "UPDATE public.tool_attempts SET status='executing'",
            ),
            (
                "UPDATE public.tool_calls SET run_id='missing-stored-run'",
                "UPDATE public.tool_calls SET run_id=(SELECT run_id FROM public.runs)",
            ),
            (
                "UPDATE public.tool_calls SET actor_id=NULL",
                "UPDATE public.tool_calls SET actor_id='journal-actor'",
            ),
        ] {
            client
                .batch_execute(damage)
                .await
                .map_err(|e| e.to_string())?;
            let before = snapshot(&f.pool).await?;
            assert!(
                matches!(
                    journal(&f.pool).record_outcome(&d).await,
                    Err(ToolPortError::Corrupt { .. })
                ),
                "{damage}"
            );
            assert_eq!(snapshot(&f.pool).await?, before);
            client
                .batch_execute(restore)
                .await
                .map_err(|e| e.to_string())?;
        }
        // The product calls below run with the Run guard restored (the capability attach now
        // observes the complete writer schema first); the dropped checks stay dropped.
        client
            .batch_execute("ALTER TABLE public.runs ENABLE TRIGGER USER")
            .await
            .map_err(|e| e.to_string())?;
        client
            .execute(
                "DELETE FROM public.tool_attempts WHERE attempt_id=$1",
                &[&d.receipt.attempt().as_str()],
            )
            .await
            .map_err(|e| e.to_string())?;
        let before = snapshot(&f.pool).await?;
        assert_eq!(
            journal(&f.pool).record_outcome(&d).await,
            Err(ToolPortError::Conflict)
        );
        assert_eq!(
            journal(&f.pool)
                .attach_capability(&d.decision.call_id, &d.capability_id)
                .await,
            Err(ToolPortError::Conflict)
        );
        assert_eq!(snapshot(&f.pool).await?, before);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn stored_remember_name_cannot_bypass_guard_via_draft_rename_or_low_level_outcome() {
    fixture("journal_remember_bypass", |f| async move {
        let mut remember = executing(&f.pool, remember_draft(f.run().await?.draft)).await?;
        remember.decision.metadata.name = ToolName::new("computer.write").unwrap();
        remember.outcome.commit_state = CommitState::NotCommitted;
        let before = snapshot(&f.pool).await?;
        assert_eq!(
            journal(&f.pool).record_outcome(&remember).await,
            Err(ToolPortError::Conflict)
        );
        let low = ToolAttemptRepo::new(f.pool.clone())
            .record_outcome(
                remember.decision.call_id.as_str(),
                0,
                remember.capability_id.as_str(),
                &persisted(),
            )
            .await;
        assert_write_conflict(low.map(|_| ()));
        assert_eq!(snapshot(&f.pool).await?, before);
        let mut generic = executing(&f.pool, f.run().await?.draft).await?;
        generic.decision.metadata.name = ToolName::new("remember").unwrap();
        let before = snapshot(&f.pool).await?;
        assert_eq!(
            journal(&f.pool).record_outcome(&generic).await,
            Err(ToolPortError::Conflict)
        );
        assert_eq!(snapshot(&f.pool).await?, before);
        Ok(())
    })
    .await;
}

async fn unique_fault(
    pool: &Pool,
    table: &str,
    event: &str,
    constraint: &str,
) -> Result<(), String> {
    assert!(matches!(
        table,
        "tool_calls" | "tool_attempts" | "audit_events"
    ));
    assert!(matches!(event, "INSERT" | "UPDATE"));
    assert!(
        constraint
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_')
    );
    pool.get().await.map_err(|e| e.to_string())?.batch_execute(&format!(
        "CREATE OR REPLACE FUNCTION public.owned_unique_fault() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RAISE EXCEPTION USING ERRCODE='23505',CONSTRAINT='{constraint}',MESSAGE='owned unique fault'; END $$;
         CREATE TRIGGER owned_unique_fault BEFORE {event} ON public.{table}
         FOR EACH ROW EXECUTE FUNCTION public.owned_unique_fault();"
    )).await.map_err(|e| e.to_string())
}

async fn remove_unique_fault(pool: &Pool, table: &str) -> Result<(), String> {
    assert!(matches!(
        table,
        "tool_calls" | "tool_attempts" | "audit_events"
    ));
    pool.get()
        .await
        .map_err(|e| e.to_string())?
        .batch_execute(&format!(
            "DROP TRIGGER owned_unique_fault ON public.{table}"
        ))
        .await
        .map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn only_six_named_tool_unique_faults_are_conflicts_at_actual_write_sites() {
    fixture("journal_unique_classification", |f| async move {
        for (constraint, table, event) in [
            ("tool_calls_pkey", "tool_calls", "INSERT"),
            ("tool_calls_run_call_seq_key", "tool_calls", "INSERT"),
            ("tool_calls_decision_id_key", "tool_calls", "INSERT"),
            ("tool_attempts_pkey", "tool_attempts", "INSERT"),
            ("tool_attempts_attempt_id_key", "tool_attempts", "INSERT"),
            ("tool_attempts_capability_id_key", "tool_attempts", "UPDATE"),
            ("owned_unlisted_unique_key", "tool_calls", "INSERT"),
        ] {
            let case = f.run().await?;
            let j = journal(&f.pool);
            if event == "UPDATE" {
                j.record_decision(&case.draft)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            let before = snapshot(&f.pool).await?;
            unique_fault(&f.pool, table, event, constraint).await?;
            let result = if event == "UPDATE" {
                j.attach_capability(
                    &case.draft.call_id,
                    &CapabilityId::new(Uuid::now_v7().to_string()),
                )
                .await
            } else {
                j.record_decision(&case.draft).await.map(|_| ())
            };
            if constraint == "owned_unlisted_unique_key" {
                assert!(matches!(result, Err(ToolPortError::Unavailable { .. })));
            } else {
                assert_eq!(result, Err(ToolPortError::Conflict), "{constraint}");
            }
            assert_eq!(snapshot(&f.pool).await?, before);
            remove_unique_fault(&f.pool, table).await?;
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn real_audit_unique_failure_rolls_back_outcome_and_never_uses_tool_write_mapper() {
    fixture("journal_audit_rollback", |f| async move {
        let d = executing(&f.pool, f.run().await?.draft).await?;
        for constraint in ["audit_events_pkey", "tool_calls_pkey"] {
            let before = snapshot(&f.pool).await?;
            unique_fault(&f.pool, "audit_events", "INSERT", constraint).await?;
            assert!(matches!(
                journal(&f.pool).record_outcome(&d).await,
                Err(ToolPortError::Unavailable { .. })
            ));
            assert_eq!(snapshot(&f.pool).await?, before);
            remove_unique_fault(&f.pool, "audit_events").await?;
        }
        journal(&f.pool)
            .record_outcome(&d)
            .await
            .map_err(|e| e.to_string())?;
        let after = snapshot(&f.pool).await?;
        assert_eq!(after["attempts"][0]["status"], "completed");
        assert_eq!(after["audit"].as_array().unwrap().len(), 1);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn generic_audit_invariant_failure_is_unavailable_and_preserves_original_remember_mapper() {
    fixture("journal_audit_invariant", |f| async move {
        let first = executing(&f.pool, f.run().await?.draft).await?;
        journal(&f.pool)
            .record_outcome(&first)
            .await
            .map_err(|e| e.to_string())?;
        let generic = executing(&f.pool, f.run().await?.draft).await?;
        let remember = executing(&f.pool, remember_draft(f.run().await?.draft)).await?;
        // Deliberate damage in this disposable fixture reaches audit_chain_without_genesis_checkpoint.
        f.pool.get().await.map_err(|e| e.to_string())?.batch_execute(
            "ALTER TABLE public.audit_checkpoints DISABLE TRIGGER audit_checkpoints_append_only;
             DELETE FROM public.audit_checkpoints;
             ALTER TABLE public.audit_checkpoints ENABLE TRIGGER audit_checkpoints_append_only;"
        ).await.map_err(|e| e.to_string())?;
        let before = snapshot(&f.pool).await?;
        assert_eq!(
            journal(&f.pool).record_outcome(&generic).await,
            Err(ToolPortError::Unavailable {
                dependency: "database"
            })
        );
        assert_eq!(snapshot(&f.pool).await?, before);
        assert!(matches!(
            journal(&f.pool).record_outcome(&remember).await,
            Err(ToolPortError::Corrupt { .. })
        ));
        assert_eq!(snapshot(&f.pool).await?, before);
        let refusal = ToolRefusalDraft {
            decision: generic.decision,
            rule: openbot_domain::tool::pipeline::PolicyRuleId::new("owned-refusal"),
            error_code: "policy_refused",
        };
        assert!(matches!(
            journal(&f.pool).record_refusal(&refusal).await,
            Err(ToolPortError::Corrupt { .. })
        ));
        assert_eq!(snapshot(&f.pool).await?, before);
        Ok(())
    })
    .await;
}

async fn approval(pool: &Pool, draft: &ToolDecisionDraft) -> Result<(), String> {
    pool.get().await.map_err(|e| e.to_string())?.execute(
        "INSERT INTO public.tool_approvals(
          approval_id,tool_call_id,deployment_id,tenant_id,thread_id,run_id,actor_id,bot_id,
          auth_generation,tool_name,args_hash,target_kind,target_id,effect,approval_class,
          computer_generation,catalog_generation,policy_version,state,
          requested_at,expires_at,decided_at,decided_by,created_at,updated_at)
         SELECT $1,$2,'journal-deployment','journal-tenant',r.thread_id,r.run_id,r.actor_id,r.bot_id,
          0,$4,$5,$6,$7,$8,$9,0,$10,$11,'granted',
          statement_timestamp(),statement_timestamp()+interval '10 minutes',statement_timestamp(),r.actor_id,
          statement_timestamp(),statement_timestamp()
         FROM public.runs r WHERE r.run_id=$3",
        &[&draft.approval_id,&draft.call_id.as_str(),&draft.run_id.as_str(),&draft.metadata.name.as_str(),
          &draft.args_hash.to_hex(),&draft.target.kind,&draft.target.id,&draft.metadata.effect.effect().as_str(),
          &draft.metadata.approval_class.as_str(),&i64::try_from(draft.metadata.catalog_generation.get()).unwrap(),
          &draft.policy_version.as_str()]
    ).await.map_err(|e| e.to_string())?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL via OPENBOT_TEST_DATABASE_URL"]
async fn approval_current_binding_is_unchanged_and_only_decision_maps_stale_to_conflict() {
    fixture("journal_approval_classification", |f| async move {
        for state in ["current", "missing", "expired", "denied", "wrong_binding"] {
            let mut d = f.run().await?.draft;
            d.metadata.approval_class = ApprovalClass::EveryCall;
            d.approval_id = Some(Uuid::now_v7().to_string());
            d.policy_version = PolicyVersionTag::new(Sha256Digest::of(b"owned-approval-policy").to_hex());
            if state != "missing" { approval(&f.pool, &d).await?; }
            let change = match state {
                "expired" => Some("UPDATE public.tool_approvals SET created_at=statement_timestamp()-interval '2 minutes',
                    requested_at=statement_timestamp()-interval '2 minutes',expires_at=statement_timestamp()-interval '1 minute',
                    decided_at=statement_timestamp()-interval '90 seconds',updated_at=statement_timestamp() WHERE approval_id=$1"),
                "denied" => Some("UPDATE public.tool_approvals SET state='denied' WHERE approval_id=$1"),
                "wrong_binding" => Some("UPDATE public.tool_approvals SET target_id='wrong-owned-target' WHERE approval_id=$1"),
                _ => None,
            };
            if let Some(sql) = change {
                f.pool.get().await.map_err(|e| e.to_string())?.execute(sql, &[&d.approval_id])
                    .await.map_err(|e| e.to_string())?;
            }
            let before = snapshot(&f.pool).await?;
            let mut missing_id = d.clone();
            missing_id.approval_id = None;
            assert_eq!(journal(&f.pool).record_decision(&missing_id).await,
                Err(ToolPortError::Corrupt { field: "approval_id" }));
            let mut wrong_class = d.clone();
            wrong_class.metadata.approval_class = ApprovalClass::NotRequired;
            assert_eq!(journal(&f.pool).record_decision(&wrong_class).await,
                Err(ToolPortError::Corrupt { field: "approval_id" }));
            assert_eq!(snapshot(&f.pool).await?, before);
            if state == "current" {
                journal(&f.pool).record_decision(&d).await.map_err(|e| e.to_string())?;
                let linked: Option<String> = f.pool.get().await.map_err(|e| e.to_string())?
                    .query_one("SELECT approval_id FROM public.tool_calls WHERE tool_call_id=$1", &[&d.call_id.as_str()])
                    .await.map_err(|e| e.to_string())?.get(0);
                assert_eq!(linked, d.approval_id);
            } else {
                assert!(matches!(ToolCallRepo::new(f.pool.clone()).record_first_decision(&first(&d)).await,
                    Err(InfraError::RepositoryInvariant { code: "tool_approval_binding_not_current" })), "{state}");
                assert_eq!(snapshot(&f.pool).await?, before);
                assert_eq!(journal(&f.pool).record_decision(&d).await, Err(ToolPortError::Conflict), "{state}");
                assert_eq!(snapshot(&f.pool).await?, before);
            }
        }
        Ok(())
    }).await;
}
