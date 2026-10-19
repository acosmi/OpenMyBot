//! R409: actual thread/runtime entry points and fail-closed occupancy readers.

mod harness;

use openbot_application::{
    BeginThreadRunRequest, RunFailureCode, RunReconciliationRequest, RunRuntime, RunTerminal,
    ThreadConversationRequest, ThreadDirectory, ThreadDirectoryError,
};
use openbot_contracts::auth::AuthGeneration;
use openbot_contracts::command::{BeginThreadRun, ThreadRunAnchor};
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{ActorId, BotId, ChannelId, DeploymentId, RunId, TenantId};
use openbot_contracts::reconciliation::RunReconciliationCursor;
use openbot_infra::db::{InfraError, fresh, pool};
use openbot_infra::repo::run::RunRepo;
use openbot_infra::run_runtime::{DEFAULT_DISPATCH_CLAIM_DURATION, PostgresRunRuntime};
use openbot_infra::thread_directory::{DEFAULT_THREAD_LEASE_DURATION, PostgresThreadDirectory};
use serde_json::Value;
use std::future::Future;

const OWNER: &str = "occupancy-runtime";

struct Fixture {
    pool: openbot_infra::db::pool::DatabasePool,
    config: pool::DatabaseConfig,
    directory: PostgresThreadDirectory,
    begin: BeginThreadRunRequest,
    supports_replay: bool,
}

impl Fixture {
    async fn new(config: pool::DatabaseConfig) -> Self {
        let p = pool::connect(&config.clone().with_max_pool_size(6))
            .await
            .unwrap();
        let mut c = p.get().await.unwrap();
        fresh::apply(&mut c).await.unwrap();
        c.batch_execute("INSERT INTO public.users(id,email) VALUES('actor','actor@occupancy.example'),('outsider','outsider@occupancy.example'); INSERT INTO public.user_roles(user_id,role) VALUES('actor','user'),('outsider','admin'); INSERT INTO public.agents(id,name,type,configuration) VALUES('bot','Occupancy Bot','built_in','{}'); INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility) VALUES('bot',NULL,'Occupancy Bot','role','seed','public')").await.unwrap();
        drop(c);
        let deployment = DeploymentId::new("occupancy-deployment");
        let begin = BeginThreadRunRequest {
            auth_generation: AuthGeneration::new(0),
            deployment: deployment.clone(),
            tenant: TenantId::new("tenant"),
            actor: ActorId::new("actor"),
            command: BeginThreadRun {
                artifact_refs: Vec::new(),
                model_selection: None,
                selected_skill_slugs: Vec::new(),
                thread_id: ThreadIdentity::new(&deployment).mint_from_entropy([0x77; 16]),
                run_id: RunId::new("original"),
                bot_id: BotId::new("bot"),
                anchor: ThreadRunAnchor::DirectBot,
                message: "owned occupancy journey".into(),
            },
        };
        let directory = directory(&p, &config);
        directory.begin_thread_run(begin.clone()).await.unwrap();
        Self {
            pool: p,
            config,
            directory,
            begin,
            supports_replay: true,
        }
    }

    fn read_request(&self) -> RunReconciliationRequest {
        RunReconciliationRequest {
            deployment: self.begin.deployment.clone(),
            tenant: self.begin.tenant.clone(),
            actor: self.begin.actor.clone(),
            auth_generation: self.begin.auth_generation,
            thread: self.begin.command.thread_id.clone(),
            run: self.begin.command.run_id.clone(),
            after: Some(RunReconciliationCursor {
                call_sequence: 999,
                attempt_sequence: 999,
            }),
            limit: 1,
        }
    }

    fn conversation(&self) -> ThreadConversationRequest {
        ThreadConversationRequest {
            deployment: self.begin.deployment.clone(),
            tenant: self.begin.tenant.clone(),
            actor: self.begin.actor.clone(),
            thread: self.begin.command.thread_id.clone(),
        }
    }

    async fn finish(&self, terminal: RunTerminal) {
        let runtime = PostgresRunRuntime::new(
            self.pool.clone(),
            OWNER.into(),
            DEFAULT_THREAD_LEASE_DURATION,
            DEFAULT_DISPATCH_CLAIM_DURATION,
        )
        .unwrap();
        let dispatch = runtime.claim_dispatch().await.unwrap().unwrap();
        let lease = runtime.acknowledge_dispatch(&dispatch).await.unwrap();
        runtime
            .finish_run(&lease, lease.next_event_sequence(), terminal)
            .await
            .unwrap();
    }

    async fn snapshot(&self) -> Vec<Value> {
        let c = self.pool.get().await.unwrap();
        let mut result = Vec::new();
        for table in [
            "runs",
            "thread_run_occupancy",
            "threads",
            "thread_leases",
            "messages",
            "run_events",
            "outbox",
            "tool_attempts",
            "remember_effect_receipts",
        ] {
            let sql = format!(
                "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM public.{table} t"
            );
            result.push(c.query_one(&sql, &[]).await.unwrap().get(0));
        }
        result
    }

    async fn assert_all_readers_reject(&self) {
        let before = self.snapshot().await;
        assert_eq!(
            self.directory
                .thread_conversation(self.conversation())
                .await,
            Err(ThreadDirectoryError::Corrupt {
                field: "thread_run_occupancy"
            })
        );
        assert!(matches!(
            RunRepo::new(self.pool.clone())
                .active_foreground_for_thread(self.begin.command.thread_id.as_str())
                .await,
            Err(InfraError::RepositoryInvariant {
                code: "thread_run_occupancy_inconsistent"
            })
        ));
        assert!(matches!(
            self.directory.run_reconciliation(self.read_request()).await,
            Err(ThreadDirectoryError::Corrupt { .. })
        ));
        assert!(matches!(
            self.directory
                .run_effect_receipts(self.read_request())
                .await,
            Err(ThreadDirectoryError::Corrupt { .. })
        ));
        // Exact idempotent replay and a fresh begin must both reject, without lease/message writes.
        if self.supports_replay {
            assert_eq!(
                self.directory.begin_thread_run(self.begin.clone()).await,
                Err(ThreadDirectoryError::Corrupt {
                    field: "thread_run_occupancy"
                })
            );
        }
        let mut next = self.begin.clone();
        next.command.run_id = RunId::new("new-run");
        assert_eq!(
            self.directory.begin_thread_run(next).await,
            Err(ThreadDirectoryError::Corrupt {
                field: "thread_run_occupancy"
            })
        );
        assert_eq!(self.snapshot().await, before);
        let mut hidden = self.read_request();
        hidden.actor = ActorId::new("outsider");
        assert_eq!(
            self.directory.run_reconciliation(hidden.clone()).await,
            Err(ThreadDirectoryError::NotVisible)
        );
        assert_eq!(
            self.directory.run_effect_receipts(hidden).await,
            Err(ThreadDirectoryError::NotVisible)
        );
        let mut conversation = self.conversation();
        conversation.actor = ActorId::new("outsider");
        assert!(
            self.directory
                .thread_conversation(conversation)
                .await
                .unwrap()
                .active_run_id
                .is_none()
        );
        let mut hidden_begin = self.begin.clone();
        hidden_begin.actor = ActorId::new("outsider");
        assert_eq!(
            self.directory.begin_thread_run(hidden_begin).await,
            Err(ThreadDirectoryError::NotVisible)
        );
        assert_eq!(self.snapshot().await, before);
    }
}

fn directory(
    p: &openbot_infra::db::pool::DatabasePool,
    config: &pool::DatabaseConfig,
) -> PostgresThreadDirectory {
    PostgresThreadDirectory::with_runtime(
        p.clone(),
        config.clone(),
        OWNER.into(),
        DEFAULT_THREAD_LEASE_DURATION,
    )
    .unwrap()
}

async fn fixture<F, Fut>(name: &str, body: F)
where
    F: FnOnce(Fixture) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(name), name, |config| async move {
        let f = Fixture::new(config).await;
        let p = f.pool.clone();
        let result = body(f).await;
        p.close();
        result
    })
    .await;
}

async fn finish_unknown_and_observe_blocking(f: &Fixture) {
    f.finish(RunTerminal::ReconciliationRequired(
        RunFailureCode::JournalCommitUnknown,
    ))
    .await;
    assert!(
        f.directory
            .run_reconciliation(f.read_request())
            .await
            .unwrap()
            .foreground_blocked
    );
    assert!(
        f.directory
            .run_effect_receipts(f.read_request())
            .await
            .unwrap()
            .foreground_blocked
    );
}

async fn damage_occupancy(f: &Fixture, damage: &str) {
    let c = f.pool.get().await.unwrap();
    // Only these disposable corruption fixtures bypass the projection's guards and FK.
    c.batch_execute(&format!("BEGIN; ALTER TABLE public.thread_run_occupancy DISABLE TRIGGER ALL; {damage}; ALTER TABLE public.thread_run_occupancy ENABLE TRIGGER ALL; COMMIT;")).await.unwrap();
}

async fn corrupted(name: &str, damage: &str) {
    fixture(name, |f| async move {
        finish_unknown_and_observe_blocking(&f).await;
        damage_occupancy(&f, damage).await;
        f.assert_all_readers_reject().await;
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn missing_slot_is_never_idle_in_any_reader_or_exact_begin_replay() {
    corrupted(
        "occupancy_missing",
        "DELETE FROM public.thread_run_occupancy",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn a_run_projected_under_the_wrong_thread_is_rejected_by_all_readers() {
    corrupted(
        "occupancy_wrong_thread",
        "UPDATE public.thread_run_occupancy SET thread_id='wrong-thread'",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn an_extra_foreign_slot_is_rejected_even_when_the_correct_slot_still_exists() {
    corrupted("occupancy_extra_foreign","INSERT INTO public.thread_run_occupancy(thread_id,run_id) VALUES('wrong-thread','original')").await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn reverse_integrity_rejects_orphan_and_nonblocking_slots_without_any_missing_expected_slot()
{
    for nonblocking in [false, true] {
        fixture(if nonblocking {"occupancy_reverse_nonblocking"} else {"occupancy_reverse_orphan"},|mut f| async move {
            let thread=ThreadIdentity::new(&f.begin.deployment).mint_from_entropy([0x78;16]);
            let c=f.pool.get().await.unwrap();
            // Legitimate born-background RR with a real terminal row; its thread has no expected O slot.
            c.execute("INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,next_event_seq) VALUES($1,'tenant','occupancy-deployment','actor','direct_bot','bot',2)",&[&thread.as_str()]).await.unwrap();
            c.execute("INSERT INTO public.thread_memberships(thread_id,user_id) VALUES($1,'actor')",&[&thread.as_str()]).await.unwrap();
            // The terminal Run and its exactly-once terminal event commit together (0051).
            c.batch_execute("BEGIN").await.unwrap();
            c.execute("INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq,terminal_event_seq,error_code,started_at,finished_at) VALUES('background',$1,'bot','actor',false,'reconciliation_required',1,2,1,'fixture_unknown',now(),now())",&[&thread.as_str()]).await.unwrap();
            c.execute("INSERT INTO public.run_events(run_id,seq,thread_id,event_seq,event_type,payload,terminal) VALUES('background',0,$1,0,'started','{}',false),('background',1,$1,1,'reconciliation_required','{}',true)",&[&thread.as_str()]).await.unwrap();
            c.batch_execute("COMMIT").await.unwrap();
            f.begin.command.thread_id=thread.clone();f.begin.command.run_id=RunId::new("background");f.supports_replay=false;
            assert!(!f.directory.run_reconciliation(f.read_request()).await.unwrap().foreground_blocked);
            assert!(!f.directory.run_effect_receipts(f.read_request()).await.unwrap().foreground_blocked);
            assert!(RunRepo::new(f.pool.clone()).active_foreground_for_thread(thread.as_str()).await.unwrap().is_none());
            // Only the corruption injection disables guards/FK; no expected slot is removed.
            c.batch_execute("ALTER TABLE public.thread_run_occupancy DISABLE TRIGGER ALL").await.unwrap();
            let target=if nonblocking {"background"} else {"nonexistent"};
            c.execute("INSERT INTO public.thread_run_occupancy(thread_id,run_id) VALUES($1,$2)",&[&thread.as_str(),&target]).await.unwrap();
            c.batch_execute("ALTER TABLE public.thread_run_occupancy ENABLE TRIGGER ALL").await.unwrap();
            drop(c);
            f.assert_all_readers_reject().await;
            Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn begin_uses_rc_even_when_the_reused_database_session_defaults_to_rr() {
    fixture("occupancy_begin_rc",|f|async move {
        let c=f.pool.get().await.unwrap();
        // The probe watches begin's own lease write; a foreign trigger on runs would be refused
        // up front by the exact 0051 writer schema observer.
        c.batch_execute("CREATE FUNCTION public.require_begin_rc() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF current_setting('transaction_isolation') <> 'read committed' OR current_setting('default_transaction_isolation') <> 'repeatable read' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='begin isolation mismatch'; END IF; RETURN NEW; END $$; CREATE TRIGGER require_begin_rc BEFORE INSERT ON public.thread_leases FOR EACH ROW EXECUTE FUNCTION public.require_begin_rc(); SET default_transaction_isolation='repeatable read'").await.unwrap();
        drop(c);
        let mut request=f.begin.clone();request.command.thread_id=ThreadIdentity::new(&request.deployment).mint_from_entropy([0x79;16]);request.command.run_id=RunId::new("rc-begin");
        f.directory.begin_thread_run(request).await.unwrap();
        assert!(RunRepo::new(f.pool.clone()).find_by_id("rc-begin").await.unwrap().is_some());
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn a_dangling_slot_is_rejected_by_all_readers_without_authority_leak() {
    corrupted(
        "occupancy_dangling",
        "UPDATE public.thread_run_occupancy SET run_id='missing-run'",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn new_begin_keeps_target_visibility_precedence_while_exact_replay_checks_integrity() {
    for channel in [false, true] {
        fixture(
            if channel {
                "occupancy_removed_channel_bot"
            } else {
                "occupancy_deleted_bot"
            },
            |mut f| async move {
                let c = f.pool.get().await.unwrap();
                if channel {
                    c.batch_execute("INSERT INTO public.channels(id,name,description) VALUES('channel','Channel','fixture'); INSERT INTO public.channel_memberships(channel_id,user_id) VALUES('channel','actor'); INSERT INTO public.channel_agents(channel_id,agent_id) VALUES('channel','bot')").await.unwrap();
                    f.begin.command.thread_id = ThreadIdentity::new(&f.begin.deployment)
                        .mint_from_entropy([0x7a; 16]);
                    f.begin.command.run_id = RunId::new("channel-run");
                    f.begin.command.anchor = ThreadRunAnchor::Channel {
                        channel_id: ChannelId::new("channel"),
                    };
                    f.directory.begin_thread_run(f.begin.clone()).await.unwrap();
                    c.batch_execute("DELETE FROM public.channel_agents WHERE channel_id='channel' AND agent_id='bot'").await.unwrap();
                    assert!(c.query_one("SELECT EXISTS(SELECT 1 FROM public.channel_memberships WHERE channel_id='channel' AND user_id='actor')", &[]).await.unwrap().get::<_, bool>(0));
                } else {
                    c.batch_execute("UPDATE public.agent_profiles SET deleted_at=now() WHERE agent_id='bot'").await.unwrap();
                }
                assert!(c.query_one("SELECT EXISTS(SELECT 1 FROM public.thread_memberships WHERE thread_id=$1 AND user_id='actor')", &[&f.begin.command.thread_id.as_str()]).await.unwrap().get::<_, bool>(0));
                let mut next = f.begin.clone();
                next.command.run_id = RunId::new("unauthorized-next");
                let healthy = f.snapshot().await;
                assert_eq!(f.directory.begin_thread_run(next.clone()).await, Err(ThreadDirectoryError::NotVisible));
                // Historical replay retains its original authority, even after target revocation.
                assert!(f.directory.begin_thread_run(f.begin.clone()).await.unwrap().replayed);
                assert_eq!(f.snapshot().await, healthy);

                // Dedicated corruption fixture: remove only this run's protected occupancy.
                c.batch_execute("BEGIN; ALTER TABLE public.thread_run_occupancy DISABLE TRIGGER USER").await.unwrap();
                c.execute("DELETE FROM public.thread_run_occupancy WHERE thread_id=$1", &[&f.begin.command.thread_id.as_str()]).await.unwrap();
                c.batch_execute("ALTER TABLE public.thread_run_occupancy ENABLE TRIGGER USER; COMMIT").await.unwrap();
                drop(c);
                let damaged = f.snapshot().await;
                assert_eq!(f.directory.begin_thread_run(next).await, Err(ThreadDirectoryError::NotVisible));
                assert!(matches!(f.directory.begin_thread_run(f.begin.clone()).await, Err(ThreadDirectoryError::Corrupt { field: "thread_run_occupancy" })));
                assert_eq!(f.snapshot().await, damaged);
                Ok(())
            },
        )
        .await;
    }
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn a_competing_runtime_lease_cannot_hide_visible_occupancy_corruption() {
    fixture("occupancy_competing_lease", |f| async move {
        let competing = PostgresThreadDirectory::with_runtime(
            f.pool.clone(),
            f.config.clone(),
            "competing-runtime".into(),
            DEFAULT_THREAD_LEASE_DURATION,
        ).unwrap();
        let mut request = f.begin.clone();
        request.command.run_id = RunId::new("competing-run");
        let healthy = f.snapshot().await;
        assert_eq!(competing.begin_thread_run(request.clone()).await, Err(ThreadDirectoryError::LeaseConflict));
        assert_eq!(f.snapshot().await, healthy);
        let c = f.pool.get().await.unwrap();
        assert!(c.query_one("SELECT owner_id=$2 AND expires_at>now() FROM public.thread_leases WHERE thread_id=$1", &[&f.begin.command.thread_id.as_str(), &OWNER]).await.unwrap().get::<_, bool>(0));
        // Dedicated corruption fixture; the real original runtime lease remains valid.
        c.batch_execute("BEGIN; ALTER TABLE public.thread_run_occupancy DISABLE TRIGGER USER; DELETE FROM public.thread_run_occupancy; ALTER TABLE public.thread_run_occupancy ENABLE TRIGGER USER; COMMIT").await.unwrap();
        drop(c);
        let damaged = f.snapshot().await;
        assert!(matches!(competing.begin_thread_run(request).await, Err(ThreadDirectoryError::Corrupt { field: "thread_run_occupancy" })));
        assert_eq!(f.snapshot().await, damaged);
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn a_nonblocking_run_cannot_hide_the_missing_unknown_owner_after_a_page_cursor() {
    fixture("occupancy_nonblocking", |f| async move {
        finish_unknown_and_observe_blocking(&f).await;
        let c=f.pool.get().await.unwrap();
        // The completed 'history' Run is ordinary DML, not part of the corruption: its terminal
        // event takes the Thread's next event slot and both Run and Thread counters advance past it.
        c.batch_execute("BEGIN; WITH r AS (INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq,terminal_event_seq,created_at,started_at,finished_at) SELECT 'history',thread_id,bot_id,actor_id,true,'completed',fencing_token,1,0,created_at,started_at,finished_at FROM public.runs WHERE run_id='original' RETURNING run_id,thread_id) INSERT INTO public.run_events(run_id,seq,thread_id,event_seq,event_type,payload,terminal) SELECT r.run_id,0,r.thread_id,t.next_event_seq,'completed','{}'::jsonb,true FROM r JOIN public.threads t ON t.thread_id=r.thread_id; UPDATE public.threads SET next_event_seq=next_event_seq+1 WHERE thread_id=(SELECT thread_id FROM public.runs WHERE run_id='history'); COMMIT").await.unwrap();
        let consistent:bool=c.query_one("SELECT t.next_event_seq=(SELECT max(e.event_seq)+1 FROM public.run_events e WHERE e.thread_id=t.thread_id) AND r.next_event_seq=(SELECT max(e.seq)+1 FROM public.run_events e WHERE e.run_id=r.run_id) AND r.terminal_event_seq=r.next_event_seq-1 FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id WHERE r.run_id='history'",&[]).await.unwrap().get(0);
        assert!(consistent,"history Run and Thread event counters must cover the new event");
        drop(c);
        // Control: with the slot still on the unknown owner, every reader accepts this state, so
        // the rejections below can only come from the moved slot.
        let conversation=f.directory.thread_conversation(f.conversation()).await.unwrap();
        assert_eq!(conversation.active_run_id,Some(RunId::new("original")));
        assert_eq!(RunRepo::new(f.pool.clone()).active_foreground_for_thread(f.begin.command.thread_id.as_str()).await.unwrap().unwrap().run_id,"original");
        assert!(f.directory.run_reconciliation(f.read_request()).await.unwrap().foreground_blocked);
        assert!(f.directory.run_effect_receipts(f.read_request()).await.unwrap().foreground_blocked);
        assert!(f.directory.begin_thread_run(f.begin.clone()).await.unwrap().replayed);
        damage_occupancy(&f, "UPDATE public.thread_run_occupancy SET run_id='history'").await;
        f.assert_all_readers_reject().await;
        Ok(())
    }).await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn completed_run_releases_only_its_slot_and_new_begin_selects_the_new_run() {
    fixture("occupancy_next", |f| async move {
        let original = f
            .directory
            .thread_conversation(f.conversation())
            .await
            .unwrap();
        assert_eq!(original.active_run_id, Some(RunId::new("original")));
        f.finish(RunTerminal::Completed).await;
        assert!(
            RunRepo::new(f.pool.clone())
                .active_foreground_for_thread(f.begin.command.thread_id.as_str())
                .await
                .unwrap()
                .is_none()
        );
        let mut next = f.begin.clone();
        next.command.run_id = RunId::new("successor");
        f.directory.begin_thread_run(next).await.unwrap();
        assert_eq!(
            f.directory
                .thread_conversation(f.conversation())
                .await
                .unwrap()
                .active_run_id,
            Some(RunId::new("successor"))
        );
        assert_eq!(
            RunRepo::new(f.pool.clone())
                .find_by_id("original")
                .await
                .unwrap()
                .unwrap()
                .status,
            "completed"
        );
        let before = f.snapshot().await;
        assert!(
            f.directory
                .begin_thread_run(f.begin.clone())
                .await
                .unwrap()
                .replayed
        );
        assert_eq!(f.snapshot().await, before);
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn unknown_remains_blocking_after_pool_reconnect_and_preserves_all_history() {
    fixture("occupancy_reconnect", |f| async move {
        f.finish(RunTerminal::ReconciliationRequired(
            RunFailureCode::JournalCommitUnknown,
        ))
        .await;
        let before = f.snapshot().await;
        let fresh_pool = pool::connect(&f.config).await.unwrap();
        let restarted = directory(&fresh_pool, &f.config);
        let mut next = f.begin.clone();
        next.command.run_id = RunId::new("must-not-start");
        assert_eq!(
            restarted.begin_thread_run(next).await,
            Err(ThreadDirectoryError::LeaseConflict)
        );
        assert_eq!(
            restarted
                .thread_conversation(f.conversation())
                .await
                .unwrap()
                .active_run_id,
            Some(RunId::new("original"))
        );
        assert!(
            restarted
                .run_reconciliation(f.read_request())
                .await
                .unwrap()
                .foreground_blocked
        );
        assert!(
            restarted
                .run_effect_receipts(f.read_request())
                .await
                .unwrap()
                .foreground_blocked
        );
        assert_eq!(f.snapshot().await, before);
        fresh_pool.close();
        Ok(())
    })
    .await;
}
