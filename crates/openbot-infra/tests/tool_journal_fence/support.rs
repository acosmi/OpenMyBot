use super::*;

pub const KEY: &[u8] = b"owned-journal-fence-audit-key";
pub const ACTOR: &str = "journal-actor";
pub const BOT: &str = "journal-bot";
pub const OWNER: &str = "journal-runtime";

pub struct Fixture {
    pub pool: Pool,
    pub config: DatabaseConfig,
}

pub async fn fixture<F, Fut>(name: &str, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    with_temp_database(&admin_config(name), name, |config| async move {
        let p = pool::connect(&config.clone().with_max_pool_size(8))
            .await.map_err(|e| e.to_string())?;
        let result = async {
            let mut client = p.get().await.map_err(|e| e.to_string())?;
            baseline::apply(&client).await.map_err(|e| e.to_string())?;
            native::apply(&mut client).await.map_err(|e| e.to_string())?;
            client.batch_execute(
                "INSERT INTO public.users(id,email) VALUES('journal-actor','journal@example.test');
                 INSERT INTO public.user_roles(user_id,role) VALUES('journal-actor','user');
                 INSERT INTO public.agents(id,name,type,configuration)
                   VALUES('journal-bot','Journal Bot','built_in','{}');
                 INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
                   VALUES('journal-bot',NULL,'Journal Bot','role','seed','public');"
            ).await.map_err(|e| e.to_string())?;
            drop(client);
            body(Fixture { pool: p.clone(), config }).await
        }.await;
        p.close();
        result
    }).await;
}

pub struct RunCase {
    pub lease: RunExecutionLease,
    pub draft: ToolDecisionDraft,
}

impl Fixture {
    pub async fn run(&self) -> Result<RunCase, String> {
        let deployment = DeploymentId::new("journal-deployment");
        let thread = ThreadIdentity::new(&deployment).mint_from_entropy(*Uuid::now_v7().as_bytes());
        let run = RunId::new(Uuid::now_v7().to_string());
        let directory = PostgresThreadDirectory::with_runtime(
            self.pool.clone(),
            self.config.clone(),
            OWNER.to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|e| e.to_string())?;
        directory
            .begin_thread_run(BeginThreadRunRequest {
                deployment,
                tenant: TenantId::new("journal-tenant"),
                actor: ActorId::new(ACTOR),
                auth_generation: AuthGeneration::new(0),
                command: BeginThreadRun {
                    artifact_refs: Vec::new(),
                    model_selection: None,
                    selected_skill_slugs: Vec::new(),
                    thread_id: thread,
                    run_id: run.clone(),
                    bot_id: BotId::new(BOT),
                    anchor: ThreadRunAnchor::DirectBot,
                    message: "owned journal fence case".to_owned(),
                },
            })
            .await
            .map_err(|e| e.to_string())?;
        let runtime = runtime(&self.pool)?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(|e| e.to_string())?
            .ok_or("missing owned dispatch")?;
        let lease = runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|e| e.to_string())?;
        assert_eq!(lease.run_id(), &run);
        Ok(RunCase {
            lease,
            draft: draft(run),
        })
    }
}

pub fn runtime(pool: &Pool) -> Result<PostgresRunRuntime, String> {
    PostgresRunRuntime::new(
        pool.clone(),
        OWNER.to_owned(),
        DEFAULT_THREAD_LEASE_DURATION,
        DEFAULT_DISPATCH_CLAIM_DURATION,
    )
    .map_err(|e| e.to_string())
}

pub fn journal(pool: &Pool) -> PostgresToolJournal {
    PostgresToolJournal::new(pool.clone(), KEY.to_vec()).unwrap()
}

pub fn draft(run: RunId) -> ToolDecisionDraft {
    ToolDecisionDraft {
        call_id: ToolCallId::new(Uuid::now_v7().to_string()),
        run_id: run,
        call_seq: 0,
        actor: ActorId::new(ACTOR),
        bot: BotId::new(BOT),
        metadata: ToolMetadata {
            name: ToolName::new("computer.write").unwrap(),
            schema_hash: Sha256Digest::of(b"journal schema"),
            catalog_generation: CatalogGeneration::new(3),
            effect: EffectClassification::declared(Effect::Write),
            idempotency: Idempotency::NonIdempotent,
            parallel_safe: false,
            timeout: Duration::from_secs(5),
            approval_class: ApprovalClass::NotRequired,
            sandbox: SandboxRequirement::RequiredNoEgress,
            limits: ToolLimits {
                max_input_bytes: 1024,
                max_output_bytes: 1024,
                max_model_visible_bytes: 1024,
            },
            resource_locks: Vec::new(),
        },
        args_hash: Sha256Digest::of(b"journal arguments"),
        target: ApprovalTarget {
            kind: "browser_tab",
            id: "owned-tab".to_owned(),
        },
        policy_version: PolicyVersionTag::new("journal-policy"),
        approval_id: None,
        idempotency_key: None,
    }
}

pub fn remember_draft(mut draft: ToolDecisionDraft) -> ToolDecisionDraft {
    draft.metadata.name = ToolName::new("remember").unwrap();
    draft.target = ApprovalTarget {
        kind: "memory_user",
        id: ACTOR.to_owned(),
    };
    draft
}

pub fn pristine(call: &str, sequence: i64) -> tool_attempts::Row {
    tool_attempts::Row {
        tool_call_id: call.to_owned(),
        attempt_seq: sequence,
        attempt_id: Uuid::now_v7().to_string(),
        capability_id: None,
        status: "decision_recorded".to_owned(),
        commit_state: None,
        output_bytes: None,
        duration_ms: None,
        error_code: None,
        started_at: None,
        finished_at: None,
        created_at: OffsetDateTime::now_utc(),
    }
}

pub fn first(d: &ToolDecisionDraft) -> FirstDurableDecision {
    FirstDurableDecision {
        call: tool_calls::Row {
            tool_call_id: d.call_id.as_str().to_owned(),
            run_id: d.run_id.as_str().to_owned(),
            call_seq: i64::try_from(d.call_seq).unwrap(),
            decision_id: Uuid::now_v7().to_string(),
            actor_id: d.actor.as_str().to_owned(),
            bot_id: d.bot.as_str().to_owned(),
            tool_name: d.metadata.name.as_str().to_owned(),
            schema_hash: d.metadata.schema_hash.to_hex(),
            catalog_generation: i64::try_from(d.metadata.catalog_generation.get()).unwrap(),
            args_hash: d.args_hash.to_hex(),
            target_kind: d.target.kind.to_owned(),
            target_id: d.target.id.clone(),
            effect: d.metadata.effect.effect().as_str().to_owned(),
            effect_downgraded: d.metadata.effect.was_downgraded(),
            idempotency: d.metadata.idempotency.as_str().to_owned(),
            idempotency_key: d.idempotency_key.as_ref().map(|k| k.as_str().to_owned()),
            approval_class: d.metadata.approval_class.as_str().to_owned(),
            policy_version: d.policy_version.as_str().to_owned(),
            decided_at: OffsetDateTime::now_utc(),
        },
        approval_id: d.approval_id.clone(),
        attempt: pristine(d.call_id.as_str(), 0),
    }
}

pub fn persisted() -> PersistedToolOutcome {
    PersistedToolOutcome {
        commit_state: CommitState::Committed,
        output_bytes: 12,
        duration: Duration::from_millis(1),
        error_code: None,
        finished_at: OffsetDateTime::now_utc(),
    }
}

pub async fn executing(
    pool: &Pool,
    decision: ToolDecisionDraft,
) -> Result<ToolOutcomeDraft, String> {
    let j = journal(pool);
    let receipt = j
        .record_decision(&decision)
        .await
        .map_err(|e| e.to_string())?;
    let capability_id = CapabilityId::new(Uuid::now_v7().to_string());
    j.attach_capability(&decision.call_id, &capability_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(ToolOutcomeDraft {
        decision,
        receipt,
        capability_id,
        outcome: ToolOutcome {
            commit_state: CommitState::Committed,
            output_bytes: 12,
            duration: Duration::from_millis(1),
            error_code: None,
        },
    })
}

#[derive(Clone, Copy, Debug)]
pub enum WriteKind {
    Decision,
    Retry,
    Attach,
    Outcome,
}
pub const WRITES: [WriteKind; 4] = [
    WriteKind::Decision,
    WriteKind::Retry,
    WriteKind::Attach,
    WriteKind::Outcome,
];

#[derive(Clone)]
pub struct Operation {
    pub kind: WriteKind,
    pub first: FirstDurableDecision,
    pub capability: String,
}

impl Operation {
    pub async fn prepare(
        pool: &Pool,
        d: &ToolDecisionDraft,
        kind: WriteKind,
    ) -> Result<Self, String> {
        let mut first = first(d);
        let capability = Uuid::now_v7().to_string();
        if !matches!(kind, WriteKind::Decision) {
            ToolCallRepo::new(pool.clone())
                .record_first_decision(&first)
                .await
                .map_err(|e| e.to_string())?;
        }
        if matches!(kind, WriteKind::Outcome) {
            ToolAttemptRepo::new(pool.clone())
                .attach_capability(
                    &first.call.tool_call_id,
                    0,
                    &capability,
                    OffsetDateTime::now_utc(),
                )
                .await
                .map_err(|e| e.to_string())?
                .ok_or("missing capability fixture")?;
        }
        if matches!(kind, WriteKind::Retry) {
            first.attempt = pristine(&first.call.tool_call_id, 1);
        }
        Ok(Self {
            kind,
            first,
            capability,
        })
    }

    pub async fn invoke(&self, pool: &Pool) -> Result<(), InfraError> {
        let attempts = ToolAttemptRepo::new(pool.clone());
        match self.kind {
            WriteKind::Decision => ToolCallRepo::new(pool.clone())
                .record_first_decision(&self.first)
                .await
                .map(|_| ()),
            WriteKind::Retry => attempts.insert_retry(&self.first.attempt).await.map(|_| ()),
            WriteKind::Attach => attempts
                .attach_capability(
                    &self.first.call.tool_call_id,
                    0,
                    &self.capability,
                    OffsetDateTime::now_utc(),
                )
                .await?
                .map(|_| ())
                .ok_or_else(|| InfraError::repository_invariant("owned_expected_attach")),
            WriteKind::Outcome => attempts
                .record_outcome(
                    &self.first.call.tool_call_id,
                    0,
                    &self.capability,
                    &persisted(),
                )
                .await?
                .map(|_| ())
                .ok_or_else(|| InfraError::repository_invariant("owned_expected_outcome")),
        }
    }
}

pub async fn snapshot(pool: &Pool) -> Result<Value, String> {
    pool.get().await.map_err(|e| e.to_string())?.query_one(
        "SELECT jsonb_build_object(
         'runs',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY run_id),'[]') FROM public.runs x),
         'threads',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY thread_id),'[]') FROM public.threads x),
         'calls',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY tool_call_id),'[]') FROM public.tool_calls x),
         'attempts',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY attempt_id),'[]') FROM public.tool_attempts x),
         'events',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY run_id,seq),'[]') FROM public.run_events x),
         'leases',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY thread_id),'[]') FROM public.thread_leases x),
         'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY outbox_id),'[]') FROM public.outbox x),
         'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY receipt_id),'[]') FROM public.remember_effect_receipts x),
         'approvals',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY approval_id),'[]') FROM public.tool_approvals x),
         'checkpoints',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY sequence),'[]') FROM public.audit_checkpoints x),
         'audit',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY created_at,id),'[]') FROM public.audit_events x))", &[]
    ).await.map_err(|e| e.to_string()).map(|row| row.get(0))
}

pub async fn dedicated(
    config: &DatabaseConfig,
    name: &str,
    repeatable: bool,
) -> Result<(Pool, i32), String> {
    let pool = pool::connect(
        &config
            .clone()
            .with_max_pool_size(1)
            .with_application_name(name),
    )
    .await
    .map_err(|e| e.to_string())?;
    let c = pool.get().await.map_err(|e| e.to_string())?;
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
    Ok((pool, pid))
}

pub async fn blocked(
    observer: &tokio_postgres::Client,
    worker: i32,
    owner: i32,
) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let found: bool = observer
                .query_one(
                    "WITH RECURSIVE waits(pid,path) AS (
                  SELECT $1::integer,ARRAY[$1::integer]
                  UNION ALL SELECT b.pid,waits.path||b.pid FROM waits
                  CROSS JOIN LATERAL unnest(pg_blocking_pids(waits.pid)) b(pid)
                  WHERE NOT b.pid=ANY(waits.path) AND cardinality(waits.path)<16)
                 SELECT EXISTS(SELECT 1 FROM waits WHERE pid=$2 AND cardinality(path)>1)",
                    &[&worker, &owner],
                )
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            if found {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "owned journal barrier did not reach expected blocker".to_owned())?
}

pub async fn gate(pool: &Pool) -> Result<(openbot_infra::db::pool::PooledClient, i32), String> {
    let client = pool.get().await.map_err(|e| e.to_string())?;
    let pid = client.query_one("SELECT pg_backend_pid(),pg_advisory_lock(hashtextextended(current_database()||':journal_fence',0))", &[])
        .await.map_err(|e| e.to_string())?.get(0);
    Ok((client, pid))
}

pub async fn ungate(client: &tokio_postgres::Client) -> Result<(), String> {
    assert!(client.query_one("SELECT pg_advisory_unlock(hashtextextended(current_database()||':journal_fence',0))", &[])
        .await.map_err(|e| e.to_string())?.get::<_, bool>(0));
    Ok(())
}

pub async fn trigger(
    pool: &Pool,
    table: &str,
    event: &str,
    identity: &str,
    fail: bool,
) -> Result<(), String> {
    // table/event are closed test constants and identity is an owned generated UUID.
    assert!(matches!(
        table,
        "tool_calls" | "tool_attempts" | "thread_leases" | "audit_events"
    ));
    assert!(matches!(event, "INSERT" | "UPDATE"));
    assert!(identity.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'));
    // A foreign trigger on a 0051-observed writer table (e.g. run_events) is refused by the exact
    // writer schema check, so the terminal gate sits on finish's own later lease release, still
    // inside the transaction that holds the Run row lock.
    let predicate = if table == "thread_leases" {
        "NEW.thread_id=(SELECT r.thread_id FROM public.runs r WHERE r.run_id=TG_ARGV[0])"
    } else if table == "audit_events" {
        "true"
    } else {
        "NEW.tool_call_id=TG_ARGV[0]"
    };
    let sql = format!(
        "CREATE OR REPLACE FUNCTION public.owned_journal_gate() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN IF {predicate} THEN
           PERFORM pg_advisory_xact_lock(hashtextextended(current_database()||':journal_fence',0));
           IF TG_ARGV[1]='fail' THEN RAISE EXCEPTION 'owned journal injected failure'; END IF;
         END IF; RETURN NEW; END $$;
         CREATE TRIGGER owned_journal_gate BEFORE {event} ON public.{table}
         FOR EACH ROW EXECUTE FUNCTION public.owned_journal_gate('{identity}','{}')",
        if fail { "fail" } else { "pass" });
    pool.get()
        .await
        .map_err(|e| e.to_string())?
        .batch_execute(&sql)
        .await
        .map_err(|e| e.to_string())
}

pub async fn untrigger(pool: &Pool, table: &str) -> Result<(), String> {
    assert!(matches!(
        table,
        "tool_calls" | "tool_attempts" | "thread_leases" | "audit_events"
    ));
    pool.get()
        .await
        .map_err(|e| e.to_string())?
        .batch_execute(&format!(
            "DROP TRIGGER owned_journal_gate ON public.{table}"
        ))
        .await
        .map_err(|e| e.to_string())
}

pub fn assert_write_conflict(result: Result<(), InfraError>) {
    assert!(matches!(
        result,
        Err(InfraError::RepositoryInvariant {
            code: "tool_journal_write_conflict"
        })
    ));
}
