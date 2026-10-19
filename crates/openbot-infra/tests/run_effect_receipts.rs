//! Real PG read-path evidence using explicit synthetic journal/receipt rows.
//! This verifies authority and projection; actual remember commits are tested separately.
//! The caller supplies its owned disposable PostgreSQL supervisor; this harness creates and drops
//! one temporary database per test. It neither contacts vendors nor certifies disposition/continuation.

mod harness;

use std::future::Future;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    BeginThreadRunRequest, RunEffectReceiptsRequest, RunFailureCode, RunRuntime, RunTerminal,
    ThreadDirectory, ThreadDirectoryError,
};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId};
use openbot_contracts::reconciliation::{
    RunEffectReceiptFact, RunEffectReceiptsSnapshot, RunReconciliationCursor,
    RunReconciliationStatus,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use serde_json::Value;

const PRIVATE_MARKER: &str = "PRIVATE_BUSINESS_SENTINEL_075";

struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    directory: PostgresThreadDirectory,
    begin: BeginThreadRunRequest,
}

impl Fixture {
    async fn new(config: pool::DatabaseConfig, channel: bool) -> Result<Self, String> {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        {
            let mut client = pool.get().await.map_err(|error| error.to_string())?;
            baseline::apply(&client)
                .await
                .map_err(|error| error.to_string())?;
            native::apply(&mut client)
                .await
                .map_err(|error| error.to_string())?;
            client.batch_execute(
                "INSERT INTO public.users(id,email) VALUES
                   ('actor-a','Owner@Example.Test'),('actor-b','other@example.test');
                 INSERT INTO public.user_roles(user_id,role) VALUES
                   ('actor-a','user'),('actor-b','admin');
                 INSERT INTO public.agents(id,name,type,configuration)
                   VALUES('bot-a','Readback fixture','built_in','{}');
                 INSERT INTO public.agent_profiles(
                   agent_id,owner_user_id,title,role_description,avatar_seed,visibility
                 ) VALUES('bot-a','actor-a','Fixture','fixture','fixture','public');
                 INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum)
                   VALUES('00000000-0000-4000-8000-000000000074','tenant-b','fixture','fixture');
                 INSERT INTO public.channels(id,name,description) VALUES('channel-a','Fixture','fixture');
                 INSERT INTO public.channel_memberships(channel_id,user_id)
                   VALUES('channel-a','actor-a'),('channel-a','actor-b');
                 INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel-a','bot-a');"
            ).await.map_err(|error| error.to_string())?;
        }
        let deployment = DeploymentId::new("reconciliation-deployment");
        let begin = BeginThreadRunRequest {
            auth_generation: AuthGeneration::new(0),
            deployment: deployment.clone(),
            tenant: TenantId::new("tenant-a"),
            actor: ActorId::new("actor-a"),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([7; 16]),
                run_id: RunId::new("opaque/run%原始"),
                bot_id: BotId::new("bot-a"),
                anchor: if channel {
                    ThreadRunAnchor::Channel {
                        channel_id: ChannelId::new("channel-a"),
                    }
                } else {
                    ThreadRunAnchor::DirectBot
                },
                message: PRIVATE_MARKER.to_owned(),
                selected_skill_slugs: Vec::new(),
                model_selection: None,
            },
        };
        let directory = PostgresThreadDirectory::with_runtime(
            pool.clone(),
            config,
            "readback-fixture-owner".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
        )
        .map_err(|error| error.to_string())?;
        directory
            .begin_thread_run(begin.clone())
            .await
            .map_err(|error| error.to_string())?;
        // Distinct event coordinate systems must not accidentally pass through equal numbers.
        // The other actor is also a direct member, so the owner test proves the run-owner check.
        pool.get()
            .await
            .map_err(|error| error.to_string())?
            .batch_execute(
                "INSERT INTO public.thread_memberships(thread_id,user_id)
               SELECT thread_id,'actor-b' FROM public.threads;
             UPDATE public.threads SET next_event_seq=77;",
            )
            .await
            .map_err(|error| error.to_string())?;
        let runtime = PostgresRunRuntime::new(
            pool.clone(),
            "readback-fixture-owner".to_owned(),
            DEFAULT_THREAD_LEASE_DURATION,
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .map_err(|error| error.to_string())?;
        let claim = runtime
            .claim_dispatch()
            .await
            .map_err(|error| error.to_string())?
            .ok_or("fixture dispatch missing")?;
        let lease = runtime
            .acknowledge_dispatch(&claim)
            .await
            .map_err(|error| error.to_string())?;
        runtime
            .finish_run(
                &lease,
                lease.next_event_sequence(),
                RunTerminal::ReconciliationRequired(RunFailureCode::JournalCommitUnknown),
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self {
            pool,
            directory,
            begin,
        })
    }

    fn request(&self) -> RunEffectReceiptsRequest {
        RunEffectReceiptsRequest {
            deployment: self.begin.deployment.clone(),
            tenant: self.begin.tenant.clone(),
            actor: self.begin.actor.clone(),
            auth_generation: self.begin.auth_generation,
            thread: self.begin.command.thread_id.clone(),
            run: self.begin.command.run_id.clone(),
            after: None,
            limit: 50,
        }
    }

    async fn read(&self) -> Result<RunEffectReceiptsSnapshot, String> {
        self.directory
            .run_effect_receipts(self.request())
            .await
            .map_err(|error| error.to_string())
    }

    async fn sql(&self, sql: &str) -> Result<(), String> {
        self.pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .batch_execute(sql)
            .await
            .map_err(|error| error.to_string())
    }

    // 0051 refuses these corrupt terminal/event shapes at the source. Only in this owned
    // disposable DB, after proving the ordinary refusal, the exact Run/event writer guards
    // are suppressed for the single corrupting statement and restored before COMMIT.
    async fn controlled_terminal_corruption(
        &self,
        sql: &str,
        ordinary_refused: bool,
    ) -> Result<(), String> {
        const GUARDS: [(&str, &str); 5] = [
            ("public.run_events", "run_events_history_body_before"),
            ("public.run_events", "run_events_history_terminal_final"),
            ("public.runs", "runs_history_body_before"),
            ("public.runs", "runs_history_canonical_before"),
            ("public.runs", "runs_history_terminal_final"),
        ];
        // Only the writer guards of the one table this static statement mutates.
        let target = if sql.contains("public.run_events") {
            "public.run_events"
        } else {
            "public.runs"
        };
        let guards = GUARDS.into_iter().filter(|(table, _)| *table == target);
        let mut client = self.pool.get().await.map_err(|e| e.to_string())?;
        let tx = client.transaction().await.map_err(|e| e.to_string())?;
        tx.batch_execute("SET CONSTRAINTS ALL IMMEDIATE")
            .await
            .map_err(|e| e.to_string())?;
        if ordinary_refused {
            tx.batch_execute("SAVEPOINT owned_terminal_probe")
                .await
                .map_err(|e| e.to_string())?;
            let ordinary = tx.batch_execute(sql).await;
            tx.batch_execute(
                "ROLLBACK TO SAVEPOINT owned_terminal_probe; RELEASE SAVEPOINT owned_terminal_probe",
            )
            .await
            .map_err(|e| e.to_string())?;
            if !ordinary
                .as_ref()
                .err()
                .and_then(|e| e.as_db_error())
                .is_some_and(|e| {
                    e.code().code() == "55000" && e.message().starts_with("thread_history_writer_")
                })
            {
                return Err(format!(
                    "ordinary corrupt terminal DML was not refused: {sql}"
                ));
            }
        }
        for (table, guard) in guards.clone() {
            tx.batch_execute(&format!("ALTER TABLE {table} DISABLE TRIGGER {guard}"))
                .await
                .map_err(|e| e.to_string())?;
        }
        tx.batch_execute(sql).await.map_err(|e| e.to_string())?;
        for (table, guard) in guards {
            tx.batch_execute(&format!("ALTER TABLE {table} ENABLE TRIGGER {guard}"))
                .await
                .map_err(|e| e.to_string())?;
            let state: String = tx
                .query_one(
                    "SELECT tgenabled::text FROM pg_catalog.pg_trigger \
                     WHERE tgrelid=$1::text::regclass AND tgname=$2 AND NOT tgisinternal",
                    &[&table, &guard],
                )
                .await
                .map_err(|e| e.to_string())?
                .get(0);
            if state != "O" {
                return Err(format!("owned writer guard {guard} was not restored"));
            }
        }
        tx.commit().await.map_err(|e| e.to_string())
    }

    async fn seed_attempts(&self, count: i64) -> Result<(), String> {
        let client = self.pool.get().await.map_err(|error| error.to_string())?;
        client
            .execute(
                "INSERT INTO public.tool_calls(
               tool_call_id,run_id,call_seq,decision_id,actor_id,bot_id,tool_name,schema_hash,
               catalog_generation,args_hash,target_kind,target_id,effect,effect_downgraded,
               idempotency,idempotency_key,approval_class,policy_version
             ) SELECT 'call-'||i,$1,i,'decision-'||i,'actor-a','bot-a','remember',repeat('a',64),
                 1,repeat('b',64),'memory_user','actor-a','write',false,'non_idempotent',NULL,
                 'not_required',$3 FROM generate_series(0,$2::bigint-1) i",
                &[&self.begin.command.run_id.as_str(), &count, &PRIVATE_MARKER],
            )
            .await
            .map_err(|error| error.to_string())?;
        client
            .execute(
                "INSERT INTO public.tool_attempts(
               tool_call_id,attempt_seq,attempt_id,capability_id,status,commit_state,error_code,
               started_at,finished_at
             ) SELECT 'call-'||i,0,'attempt-'||i,'capability-'||i,
                 CASE i%3 WHEN 0 THEN 'executing' WHEN 1 THEN 'completed'
                   ELSE 'reconciliation_required' END,
                 CASE i%3 WHEN 1 THEN 'committed' WHEN 2 THEN 'unknown' ELSE NULL END,
                 $2,now(),CASE WHEN i%3=0 THEN NULL ELSE now() END
               FROM generate_series(0,$1::bigint-1) i",
                &[&count, &PRIVATE_MARKER],
            )
            .await
            .map_err(|error| error.to_string())?;
        drop(client);
        self.seed_receipts().await
    }

    async fn seed_receipts(&self) -> Result<(), String> {
        self.pool
            .get()
            .await
            .map_err(|error| error.to_string())?
            .batch_execute(
                "INSERT INTO public.remember_effect_receipts(
              receipt_id,deployment_id,tenant_id,thread_id,run_id,actor_id,bot_id,
              auth_generation,tool_call_id,call_seq,attempt_id,attempt_seq,decision_id,
              capability_id,args_hash,schema_hash,catalog_generation,target_kind,target_id,
              memory_id,memory_event_seq,audit_event_id,recorded_at)
             SELECT md5('receipt-'||a.attempt_id)::uuid::text,t.deployment_id,t.tenant_id,
              r.thread_id,r.run_id,r.actor_id,r.bot_id,0,c.tool_call_id,c.call_seq,
              a.attempt_id,a.attempt_seq,c.decision_id,a.capability_id,c.args_hash,
              c.schema_hash,c.catalog_generation,c.target_kind,c.target_id,
              md5('memory-'||a.attempt_id)::uuid::text,0,
              md5('audit-'||a.attempt_id)::uuid::text,now()
             FROM public.tool_attempts a JOIN public.tool_calls c USING(tool_call_id)
             JOIN public.runs r ON r.run_id=c.run_id JOIN public.threads t USING(thread_id)
             WHERE NOT EXISTS(SELECT 1 FROM public.remember_effect_receipts e
                              WHERE e.attempt_id=a.attempt_id)",
            )
            .await
            .map_err(|error| error.to_string())
    }

    async fn persisted_state(&self) -> Result<Value, String> {
        self.pool.get().await.map_err(|error| error.to_string())?.query_one(
            "SELECT jsonb_build_object(
              'runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY run_id) FROM public.runs r),
              'calls',(SELECT jsonb_agg(to_jsonb(c) ORDER BY tool_call_id) FROM public.tool_calls c),
              'attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY tool_call_id,attempt_seq) FROM public.tool_attempts a),
              'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY run_id,seq) FROM public.run_events e),
              'threads',(SELECT jsonb_agg(to_jsonb(t) ORDER BY thread_id) FROM public.threads t),
              'leases',(SELECT jsonb_agg(to_jsonb(l) ORDER BY thread_id) FROM public.thread_leases l),
              'outbox',(SELECT jsonb_agg(to_jsonb(o) ORDER BY outbox_id) FROM public.outbox o),
              'receipts',(SELECT jsonb_agg(to_jsonb(e) ORDER BY receipt_id) FROM public.remember_effect_receipts e),
              'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM public.audit_events a))", &[],
        ).await.map_err(|error| error.to_string())?.try_get(0).map_err(|error| error.to_string())
    }

    async fn expect_invisible(&self) -> Result<(), String> {
        require(
            self.directory.run_effect_receipts(self.request()).await
                == Err(ThreadDirectoryError::NotVisible),
            "current authority change must hide reconciliation",
        )
    }

    async fn expect_corrupt(&self) -> Result<(), String> {
        require(
            matches!(
                self.directory.run_effect_receipts(self.request()).await,
                Err(ThreadDirectoryError::Corrupt { .. })
            ),
            "malformed persisted binding or state must be corrupt",
        )
    }
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

async fn with_fixture<F, Fut>(name: &str, channel: bool, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let admin = admin_config(name);
    with_temp_database(&admin, name, |config| async move {
        let fixture = Fixture::new(config, channel).await?;
        let pool = fixture.pool.clone();
        let outcome = body(fixture).await;
        pool.close();
        outcome
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn effect_receipts_read_preserves_unknown_and_all_original_records() {
    with_fixture("re_facts", false, |fixture| async move {
        let before = fixture.persisted_state().await?;
        let empty = fixture.read().await?;
        require(
            empty.receipts.is_empty() && empty.next.is_none(),
            "zero receipts must be a visible empty page",
        )?;
        require(
            empty.status == RunReconciliationStatus::ReconciliationRequired
                && empty.foreground_blocked
                && empty.available_actions.is_empty()
                && empty.terminal_event_sequence == 1,
            "original Unknown facts drifted",
        )?;
        require(
            before == fixture.persisted_state().await?,
            "empty read mutated original records",
        )?;
        fixture.seed_attempts(5).await?;
        let before = fixture.persisted_state().await?;
        let page = fixture.read().await?;
        require(page.receipts.len() == 5, "receipt count drifted")?;
        for receipt in &page.receipts {
            require(
                receipt.fact == RunEffectReceiptFact::MemoryCreated,
                "historical receipt must retain its positive fact",
            )?;
        }
        let serialized = serde_json::to_string(&page).map_err(|error| error.to_string())?;
        require(
            !serialized.contains(PRIVATE_MARKER)
                && !serialized.contains("capability")
                && !serialized.contains("targetId")
                && !serialized.contains("argsHash"),
            "business content escaped the safe projection",
        )?;
        let reloaded = PostgresThreadDirectory::new(fixture.pool.clone())
            .run_effect_receipts(fixture.request())
            .await
            .map_err(|error| error.to_string())?;
        require(
            reloaded.receipts == page.receipts && reloaded.foreground_blocked,
            "new directory instance must read the same durable Unknown",
        )?;
        let mut next = fixture.begin.clone();
        next.command.run_id = RunId::new("explicit-new-run");
        require(
            fixture.directory.begin_thread_run(next).await
                == Err(ThreadDirectoryError::LeaseConflict),
            "readback must not release Unknown foreground occupancy",
        )?;
        require(
            before == fixture.persisted_state().await?,
            "read or refused begin mutated original records",
        )
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn effect_receipts_pages_are_bounded_and_use_both_attempt_coordinates() {
    with_fixture("re_pages", false, |fixture| async move {
        fixture.seed_attempts(101).await?;
        fixture
            .sql(
                "INSERT INTO public.tool_attempts(tool_call_id,attempt_seq,attempt_id,capability_id,status)
          VALUES('call-0',1,'attempt-second','capability-second','executing')",
            )
            .await?;
        fixture.seed_receipts().await?;
        let before = fixture.persisted_state().await?;
        let mut request = fixture.request();
        request.limit = 100;
        let first = fixture
            .directory
            .run_effect_receipts(request.clone())
            .await
            .map_err(|e| e.to_string())?;
        require(
            first.receipts.len() == 100 && first.receipts[1].attempt_sequence == 1,
            "maximum page or same-call attempt ordering drifted",
        )?;
        require(
            first.next
                == Some(RunReconciliationCursor {
                    call_sequence: 98,
                    attempt_sequence: 0,
                }),
            "next must be the final returned coordinate",
        )?;
        let repeated = fixture
            .directory
            .run_effect_receipts(request.clone())
            .await
            .map_err(|e| e.to_string())?;
        require(
            first.receipts == repeated.receipts && first.next == repeated.next,
            "exact reread drifted",
        )?;
        request.after = first.next;
        let second = fixture
            .directory
            .run_effect_receipts(request.clone())
            .await
            .map_err(|e| e.to_string())?;
        require(
            second.receipts.len() == 2
                && second.receipts[0].call_sequence == 99
                && second.receipts[1].call_sequence == 100
                && second.next.is_none(),
            "next page skipped or repeated an attempt",
        )?;
        request.after = Some(RunReconciliationCursor {
            call_sequence: i64::MAX,
            attempt_sequence: i64::MAX,
        });
        let beyond = fixture
            .directory
            .run_effect_receipts(request)
            .await
            .map_err(|e| e.to_string())?;
        require(
            beyond.receipts.is_empty() && beyond.next.is_none(),
            "cursor beyond last row should be an empty visible page",
        )?;
        require(
            before == fixture.persisted_state().await?,
            "pagination mutated records",
        )?;
        fixture
            .sql("UPDATE public.users SET auth_generation=1 WHERE id='actor-a'")
            .await?;
        fixture.expect_invisible().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn effect_receipts_direct_current_authority_and_owner_are_rechecked() {
    with_fixture("re_direct_auth", false, |fixture| async move {
        fixture.seed_attempts(1).await?;
        for request in [
            RunEffectReceiptsRequest { actor: ActorId::new("actor-b"), ..fixture.request() },
            RunEffectReceiptsRequest { tenant: TenantId::new("tenant-b"), ..fixture.request() },
            RunEffectReceiptsRequest { deployment: DeploymentId::new("other-deployment"), ..fixture.request() },
            RunEffectReceiptsRequest { run: RunId::new("nonexistent-run"), ..fixture.request() },
            RunEffectReceiptsRequest { auth_generation: AuthGeneration::new(1), ..fixture.request() },
            RunEffectReceiptsRequest {
                thread: ThreadIdentity::new(&fixture.begin.deployment).mint_from_entropy([8; 16]),
                ..fixture.request()
            },
        ] {
            require(fixture.directory.run_effect_receipts(request).await == Err(ThreadDirectoryError::NotVisible),
                "identity, scope, stale generation or admin cannot bypass run owner")?;
        }
        for (change, restore) in [
            ("DELETE FROM public.user_roles WHERE user_id='actor-a'",
             "INSERT INTO public.user_roles(user_id,role) VALUES('actor-a','user')"),
            ("INSERT INTO public.revoked_access(email,revoked_by) VALUES('owner@example.test','actor-b')",
             "DELETE FROM public.revoked_access WHERE email='owner@example.test'"),
            ("DELETE FROM public.thread_memberships WHERE user_id='actor-a'",
             "INSERT INTO public.thread_memberships(thread_id,user_id) SELECT thread_id,'actor-a' FROM public.threads"),
            ("UPDATE public.threads SET status='deleted',deleted_at=now()",
             "UPDATE public.threads SET status='active',deleted_at=NULL"),
            ("UPDATE public.agent_profiles SET deleted_at=now()",
             "UPDATE public.agent_profiles SET deleted_at=NULL"),
            ("UPDATE public.agent_profiles SET visibility='private',owner_user_id='actor-b'",
             "UPDATE public.agent_profiles SET visibility='public',owner_user_id='actor-a'"),
            ("UPDATE public.agents SET package_id='00000000-0000-4000-8000-000000000074'",
             "UPDATE public.agents SET package_id=NULL"),
        ] {
            fixture.sql(change).await?;
            fixture.expect_invisible().await?;
            fixture.sql(restore).await?;
            fixture.read().await?;
        }
        fixture.sql("UPDATE public.users SET auth_generation=1 WHERE id='actor-a'").await?;
        fixture.expect_invisible().await?;
        let fresh = RunEffectReceiptsRequest { auth_generation: AuthGeneration::new(1), ..fixture.request() };
        let page = fixture.directory.run_effect_receipts(fresh).await.map_err(|error| error.to_string())?;
        require(page.receipts.len() == 1, "new login generation must retain historical positive receipt")?;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn effect_receipts_channel_membership_bot_link_and_packages_are_current() {
    with_fixture("re_channel_auth", true, |fixture| async move {
        fixture.seed_attempts(1).await?;
        fixture.read().await?;
        for (change, restore) in [
            ("DELETE FROM public.channel_memberships WHERE user_id='actor-a'",
             "INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel-a','actor-a')"),
            ("DELETE FROM public.channel_agents WHERE agent_id='bot-a'",
             "INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel-a','bot-a')"),
            ("UPDATE public.channels SET package_id='00000000-0000-4000-8000-000000000074'",
             "UPDATE public.channels SET package_id=NULL"),
            ("UPDATE public.agents SET package_id='00000000-0000-4000-8000-000000000074'",
             "UPDATE public.agents SET package_id=NULL"),
        ] {
            fixture.sql(change).await?;
            fixture.expect_invisible().await?;
            fixture.sql(restore).await?;
            fixture.read().await?;
        }
        // Dedicated negative fixture: inject a non-Unknown endpoint state, not a permitted RR transition.
        fixture.sql("BEGIN; ALTER TABLE public.runs DISABLE TRIGGER USER;
          ALTER TABLE public.thread_run_occupancy DISABLE TRIGGER USER;
          UPDATE public.runs SET status='failed'; DELETE FROM public.thread_run_occupancy;
          ALTER TABLE public.runs ENABLE TRIGGER USER;
          ALTER TABLE public.thread_run_occupancy ENABLE TRIGGER USER; COMMIT").await?;
        require(fixture.directory.run_effect_receipts(fixture.request()).await == Err(ThreadDirectoryError::RequestConflict),
            "visible non-Unknown run must be a conflict")?;
        fixture.sql("DELETE FROM public.channel_memberships WHERE user_id='actor-a'").await?;
        fixture.expect_invisible().await
    }).await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn effect_receipts_rejects_hidden_bad_bindings_and_unbound_terminal_events() {
    with_fixture("re_bindings", false, |fixture| async move {
        fixture.seed_attempts(2).await?;
        fixture.sql("UPDATE public.tool_calls SET actor_id='actor-b' WHERE call_seq=0").await?;
        let request = RunEffectReceiptsRequest {
            after: Some(RunReconciliationCursor { call_sequence: 0, attempt_sequence: 0 }),
            limit: 1, ..fixture.request()
        };
        require(matches!(fixture.directory.run_effect_receipts(request).await,
            Err(ThreadDirectoryError::Corrupt { .. })), "cursor cannot hide a bad call binding")?;
        fixture.sql("UPDATE public.tool_calls SET actor_id='actor-a',bot_id='wrong-bot' WHERE call_seq=0").await?;
        fixture.expect_corrupt().await?;
        fixture.sql("UPDATE public.tool_calls SET bot_id='bot-a' WHERE call_seq=0").await?;
        fixture.read().await?;
        fixture.controlled_terminal_corruption("UPDATE public.run_events SET event_type='failed' WHERE terminal", true).await?;
        fixture.expect_corrupt().await?;
        fixture.sql("UPDATE public.run_events SET event_type='reconciliation_required' WHERE terminal").await?;
        fixture.sql("INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id)
          VALUES('550e8400-e29b-41d4-a716-446655440074','tenant-a','reconciliation-deployment',
                 'actor-a','direct_bot','bot-a')").await?;
        fixture.controlled_terminal_corruption("UPDATE public.run_events SET thread_id='550e8400-e29b-41d4-a716-446655440074' WHERE terminal", true).await?;
        fixture.expect_corrupt().await?;
        fixture.controlled_terminal_corruption("UPDATE public.run_events e SET thread_id=r.thread_id FROM public.runs r
          WHERE e.run_id=r.run_id AND e.terminal", true).await?;
        fixture.controlled_terminal_corruption("UPDATE public.run_events SET event_type='checkpoint',terminal=false
          WHERE event_type='reconciliation_required'", true).await?;
        fixture.expect_corrupt().await?;
        fixture.sql("UPDATE public.run_events SET event_type='reconciliation_required',terminal=true
          WHERE event_type='checkpoint'").await?;
        fixture.controlled_terminal_corruption("UPDATE public.runs SET terminal_event_seq=999", true).await?;
        fixture.expect_corrupt().await?;
        fixture.sql("UPDATE public.runs SET terminal_event_seq=1").await?;
        fixture.read().await?;
        // Model a legacy background RR in this corruption-only database; production downgrade is prohibited.
        fixture.sql("BEGIN; ALTER TABLE public.runs DISABLE TRIGGER USER;
          ALTER TABLE public.thread_run_occupancy DISABLE TRIGGER USER;
          UPDATE public.runs SET foreground=false; DELETE FROM public.thread_run_occupancy;
          ALTER TABLE public.runs ENABLE TRIGGER USER;
          ALTER TABLE public.thread_run_occupancy ENABLE TRIGGER USER; COMMIT").await?;
        require(!fixture.read().await?.foreground_blocked,
            "foregroundBlocked must describe only this original run")?;
        fixture
            .controlled_terminal_corruption("DELETE FROM public.run_events WHERE terminal", true)
            .await?;
        fixture.expect_corrupt().await
    }).await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn effect_receipts_refuses_malformed_ids_states_and_typed_page_values() {
    with_fixture("re_bounds", false, |fixture| async move {
        fixture.seed_attempts(1).await?;
        let before = fixture.persisted_state().await?;
        for request in [
            RunEffectReceiptsRequest {
                limit: 0,
                ..fixture.request()
            },
            RunEffectReceiptsRequest {
                limit: 101,
                ..fixture.request()
            },
            RunEffectReceiptsRequest {
                run: RunId::new("x".repeat(513)),
                ..fixture.request()
            },
            RunEffectReceiptsRequest {
                run: RunId::new("bad\nrun"),
                ..fixture.request()
            },
            RunEffectReceiptsRequest {
                after: Some(RunReconciliationCursor {
                    call_sequence: -1,
                    attempt_sequence: 0,
                }),
                ..fixture.request()
            },
        ] {
            require(
                matches!(
                    fixture.directory.run_effect_receipts(request).await,
                    Err(ThreadDirectoryError::InvalidInput { .. })
                ),
                "typed port must refuse malformed bounds",
            )?;
        }
        require(
            before == fixture.persisted_state().await?,
            "invalid read mutated records",
        )?;
        let client = fixture
            .pool
            .get()
            .await
            .map_err(|error| error.to_string())?;
        for bad_id in ["x".repeat(513), "\n".to_owned(), "\u{85}".to_owned()] {
            client
                .execute("UPDATE public.tool_attempts SET attempt_id=$1", &[&bad_id])
                .await
                .map_err(|error| error.to_string())?;
            fixture.expect_corrupt().await?;
        }
        client
            .execute(
                "UPDATE public.tool_attempts SET attempt_id=$1",
                &[&"attempt-0"],
            )
            .await
            .map_err(|error| error.to_string())?;
        fixture.read().await?;
        drop(client);
        fixture
            .sql(
                "ALTER TABLE public.tool_attempts DROP CONSTRAINT tool_attempts_status_known;
          UPDATE public.tool_attempts SET status='PRIVATE_BUSINESS_SENTINEL_075'",
            )
            .await?;
        fixture.expect_corrupt().await?;
        fixture
            .sql(
                "UPDATE public.tool_attempts SET status='executing';
          ALTER TABLE public.tool_attempts DROP CONSTRAINT tool_attempts_commit_state_known;
          UPDATE public.tool_attempts SET commit_state='PRIVATE_BUSINESS_SENTINEL_075'",
            )
            .await?;
        fixture.expect_corrupt().await
    })
    .await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn effect_receipts_integrity_cannot_be_hidden_outside_the_requested_page() {
    with_fixture("re_full_integrity", false, |fixture| async move {
        fixture.seed_attempts(2).await?;
        fixture.sql("UPDATE public.tool_attempts SET capability_id='bad-later-cap' WHERE attempt_id='attempt-1'").await?;
        require(matches!(fixture.directory.run_effect_receipts(RunEffectReceiptsRequest {
            limit: 1, ..fixture.request()
        }).await, Err(ThreadDirectoryError::Corrupt { .. })),
            "LIMIT must not hide the later contradictory receipt")?;
        fixture.sql("UPDATE public.tool_attempts SET capability_id='capability-1' WHERE attempt_id='attempt-1'").await?;
        let request = RunEffectReceiptsRequest {
            after: Some(RunReconciliationCursor { call_sequence: 0, attempt_sequence: 0 }),
            limit: 1,
            ..fixture.request()
        };
        for (change, restore) in [
            ("UPDATE public.tool_calls SET tool_name='other' WHERE call_seq=0",
             "UPDATE public.tool_calls SET tool_name='remember' WHERE call_seq=0"),
            ("UPDATE public.tool_calls SET decision_id='other-decision' WHERE call_seq=0",
             "UPDATE public.tool_calls SET decision_id='decision-0' WHERE call_seq=0"),
            ("UPDATE public.tool_calls SET schema_hash=repeat('c',64) WHERE call_seq=0",
             "UPDATE public.tool_calls SET schema_hash=repeat('a',64) WHERE call_seq=0"),
            ("UPDATE public.tool_calls SET args_hash=repeat('c',64) WHERE call_seq=0",
             "UPDATE public.tool_calls SET args_hash=repeat('b',64) WHERE call_seq=0"),
            ("UPDATE public.tool_calls SET catalog_generation=2 WHERE call_seq=0",
             "UPDATE public.tool_calls SET catalog_generation=1 WHERE call_seq=0"),
            ("UPDATE public.tool_calls SET target_kind='memory_bot',target_id='bot-a' WHERE call_seq=0",
             "UPDATE public.tool_calls SET target_kind='memory_user',target_id='actor-a' WHERE call_seq=0"),
            ("UPDATE public.tool_calls SET call_seq=999 WHERE call_seq=0",
             "UPDATE public.tool_calls SET call_seq=0 WHERE call_seq=999"),
            ("UPDATE public.tool_attempts SET capability_id='other-cap' WHERE attempt_id='attempt-0'",
             "UPDATE public.tool_attempts SET capability_id='capability-0' WHERE attempt_id='attempt-0'"),
            ("UPDATE public.tool_attempts SET attempt_seq=3 WHERE attempt_id='attempt-0'",
             "UPDATE public.tool_attempts SET attempt_seq=0 WHERE attempt_id='attempt-0'"),
            ("UPDATE public.tool_attempts SET commit_state='not_committed' WHERE attempt_id='attempt-0'",
             "UPDATE public.tool_attempts SET commit_state=NULL WHERE attempt_id='attempt-0'"),
        ] {
            fixture.sql(change).await?;
            require(matches!(fixture.directory.run_effect_receipts(request.clone()).await,
                Err(ThreadDirectoryError::Corrupt { .. })),
                "pagination hid a contradictory or misbound positive receipt")?;
            fixture.sql(restore).await?;
            fixture.read().await?;
        }
        fixture.sql("DELETE FROM public.tool_attempts WHERE attempt_id='attempt-0'").await?;
        require(matches!(fixture.directory.run_effect_receipts(request).await,
            Err(ThreadDirectoryError::Corrupt { .. })),
            "missing original attempt must not erase or hide immutable receipt")
    }).await;
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL through OPENBOT_TEST_DATABASE_URL"]
async fn effect_receipts_missing_call_retains_history_but_refuses_the_broken_chain() {
    with_fixture("re_missing_call", false, |fixture| async move {
        fixture.seed_attempts(1).await?;
        let before = fixture.read().await?;
        require(
            before.receipts.len() == 1,
            "expected original positive reference",
        )?;
        fixture
            .sql("DELETE FROM public.tool_calls WHERE tool_call_id='call-0'")
            .await?;
        fixture.expect_corrupt().await?;
        let count: i64 = fixture
            .pool
            .get()
            .await
            .map_err(|e| e.to_string())?
            .query_one(
                "SELECT count(*)::bigint FROM public.remember_effect_receipts",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        require(
            count == 1,
            "business cascade must not erase positive history",
        )
    })
    .await;
}
