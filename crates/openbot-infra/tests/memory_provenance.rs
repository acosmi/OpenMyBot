//! R417 counterexamples through current production Memory paths, on owned PostgreSQL only.
mod harness;

use openbot_application::UpdateMemoryControlRequest;
use openbot_application::{
    CorrectMemoryRequest, MemoryAdministration, MemoryAdministrationError, MemoryPageRequest,
    RecallMemoriesRequest, RememberMemoryRequest,
};
use openbot_contracts::auth::{AuthGeneration, Role};
use openbot_contracts::ids::{ActorId, BotId, DeploymentId, TenantId, ThreadId};
use openbot_contracts::memory::UpdateMemoryControl;
use openbot_contracts::memory::{
    CorrectMemory, MemoryKind, MemoryRecord, MemoryScope, MemorySensitivity, MemorySource,
    RecallMemories, RememberMemory,
};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::memory_admin::PostgresMemoryAdministration;
use std::future::Future;
use tokio_postgres::error::SqlState;

const DIRECT: &str = "550e8400-e29b-41d4-a716-446655440000";
const OTHER: &str = "550e8400-e29b-41d4-a716-446655440001";
const CHANNEL: &str = "550e8400-e29b-41d4-a716-446655440002";

async fn fixture<F, Fut>(label: &str, body: F)
where
    F: FnOnce(openbot_infra::db::pool::DatabasePool) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    harness::with_temp_database(&harness::admin_config(label), label, |config| async move {
        let p = pool::connect(&config.with_max_pool_size(6))
            .await
            .map_err(|e| e.to_string())?;
        let result = body(p.clone()).await;
        p.close();
        result
    })
    .await;
}

async fn provision(p: &openbot_infra::db::pool::DatabasePool, version: i32) {
    let mut c = p.get().await.unwrap();
    baseline::apply(&c).await.unwrap();
    native::apply_through(&mut c, version).await.unwrap();
    c.batch_execute(r#"INSERT INTO public.users(id,email,auth_generation) VALUES
        ('actor','actor@example.test',0),('other','other@example.test',0);
        INSERT INTO public.user_roles(user_id,role) VALUES ('actor','user'),('other','user');
        INSERT INTO public.deployment_packages(id,tenant_id,source_path,checksum)
          VALUES ('00000000-0000-0000-0000-000000000417','foreign-tenant','synthetic',repeat('a',64));
        INSERT INTO public.agents(id,name,type,configuration,package_id) VALUES
          ('bot','Bot','built_in','{}',NULL),('foreign-bot','Foreign','built_in','{}','00000000-0000-0000-0000-000000000417');
        INSERT INTO public.agent_profiles(agent_id,owner_user_id,title,role_description,avatar_seed,visibility)
          VALUES ('bot',NULL,'Bot','fixture','seed','public'),('foreign-bot',NULL,'Foreign','fixture','seed','public');
        INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups)
          VALUES ('channel','Channel','fixture','{}','{}');
        INSERT INTO public.channel_memberships(channel_id,user_id) VALUES ('channel','actor');
        INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,next_message_seq)
          VALUES ('550e8400-e29b-41d4-a716-446655440000','tenant','deployment','actor','direct_bot','bot',3),
          ('550e8400-e29b-41d4-a716-446655440001','tenant','deployment','actor','direct_bot','bot',1),
          ('550e8400-e29b-41d4-a716-446655440002','tenant','deployment','actor','channel','channel',1);
        INSERT INTO public.thread_memberships(thread_id,user_id) VALUES
          ('550e8400-e29b-41d4-a716-446655440000','actor'),
          ('550e8400-e29b-41d4-a716-446655440001','actor'),
          ('550e8400-e29b-41d4-a716-446655440002','actor');
        INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token) VALUES
          ('run-a','550e8400-e29b-41d4-a716-446655440000','bot','actor',false,'queued',1),
          ('run-b','550e8400-e29b-41d4-a716-446655440001','bot','actor',false,'queued',1);
        INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,run_id,actor_id) VALUES
          ('bound','550e8400-e29b-41d4-a716-446655440000',0,'user','{"text":"source"}','source','run-a','actor'),
          ('unbound','550e8400-e29b-41d4-a716-446655440000',1,'user','{"text":"source"}','source',NULL,'actor'),
          ('mismatched','550e8400-e29b-41d4-a716-446655440000',2,'user','{"text":"source"}','source','run-b','actor'),
          ('channel-message','550e8400-e29b-41d4-a716-446655440002',0,'user','{"text":"source"}','source',NULL,'actor');"#).await.unwrap();
    if version == 37 {
        // The fixture rows are inserted at the historical prefix; the consumers under test
        // require the current native prefix, so upgrade once the rows exist.
        native::apply(&mut c).await.unwrap();
    }
}

fn request(thread: &str, message: &str, scope: MemoryScope) -> RememberMemoryRequest {
    RememberMemoryRequest {
        tenant: TenantId::new("tenant"),
        actor: ActorId::new("actor"),
        deployment: DeploymentId::new("deployment"),
        auth_generation: AuthGeneration::new(0),
        input: RememberMemory {
            memory_kind: MemoryKind::Fact,
            scope,
            content: "provenance evidence".into(),
            tags: vec![],
            sensitivity: MemorySensitivity::Normal,
            source: Some(MemorySource {
                thread_id: ThreadId::new(thread),
                message_id: message.into(),
            }),
            expires_at: None,
        },
    }
}
fn correction(record: &MemoryRecord, generation: u64) -> CorrectMemoryRequest {
    CorrectMemoryRequest {
        tenant: TenantId::new("tenant"),
        actor: ActorId::new("actor"),
        deployment: DeploymentId::new("deployment"),
        auth_generation: AuthGeneration::new(generation),
        memory_id: record.memory_id.clone(),
        correction: CorrectMemory {
            content: "provenance corrected".into(),
            tags: vec![],
            sensitivity: MemorySensitivity::Normal,
            expires_at: None,
        },
    }
}
fn recall(thread: Option<&str>) -> RecallMemoriesRequest {
    RecallMemoriesRequest {
        tenant: TenantId::new("tenant"),
        actor: ActorId::new("actor"),
        deployment: DeploymentId::new("deployment"),
        auth_generation: AuthGeneration::new(0),
        input: RecallMemories {
            query: "provenance".into(),
            tags: vec![],
            bot_id: Some(BotId::new("bot")),
            thread_id: thread.map(ThreadId::new),
            limit: Some(100),
        },
    }
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn exact_source_run_is_captured_and_null_never_follows_a_later_message_binding() {
    fixture("memorysourcecapture", |p| async move {
        provision(&p, 37).await;
        let store = PostgresMemoryAdministration::new(p.clone());
        let bound = store
            .remember(request(DIRECT, "bound", MemoryScope::User))
            .await
            .unwrap();
        assert_eq!(
            bound.source_run_id.as_ref().map(|r| r.as_str()),
            Some("run-a")
        );
        let snapshot = bound.source_authorization_snapshot.as_ref().unwrap();
        assert_eq!(snapshot.actor_id.as_str(), "actor");
        assert_eq!(snapshot.tenant_id.as_str(), "tenant");
        assert_eq!(snapshot.deployment_id.as_str(), "deployment");
        assert_eq!(snapshot.auth_generation, 0);
        assert_eq!(snapshot.roles, [Role::User]);
        assert_eq!(snapshot.scope, MemoryScope::User);
        let unknown = store
            .remember(request(DIRECT, "unbound", MemoryScope::User))
            .await
            .unwrap();
        assert!(unknown.source_run_id.is_none());
        assert!(unknown.source_authorization_snapshot.is_some());
        p.get()
            .await
            .unwrap()
            .execute(
                "UPDATE public.messages SET run_id='run-a' WHERE message_id='unbound'",
                &[],
            )
            .await
            .unwrap();
        let replacement = store.correct(correction(&unknown, 0)).await.unwrap();
        assert!(replacement.source_run_id.is_none());
        assert_eq!(
            replacement.source_authorization_snapshot,
            unknown.source_authorization_snapshot
        );
        assert_eq!(replacement.source, unknown.source);
        let page = store
            .list_memories(MemoryPageRequest {
                tenant: TenantId::new("tenant"),
                actor: ActorId::new("actor"),
                auth_generation: AuthGeneration::new(0),
                cursor: None,
                limit: 100,
            })
            .await
            .unwrap();
        assert!(
            page.memories
                .iter()
                .any(|r| r.memory_id == unknown.memory_id && r.source_run_id.is_none())
        );
        for invalid in [
            request(OTHER, "bound", MemoryScope::User),
            request(DIRECT, "missing", MemoryScope::User),
        ] {
            assert_eq!(
                store.remember(invalid).await,
                Err(MemoryAdministrationError::NotVisible)
            );
        }
        assert_eq!(
            store
                .remember(request(DIRECT, "mismatched", MemoryScope::User))
                .await,
            Err(MemoryAdministrationError::Corrupt {
                field: "source_run"
            })
        );
        assert_eq!(
            store
                .remember(request(
                    DIRECT,
                    "bound",
                    MemoryScope::Thread {
                        thread_id: ThreadId::new(OTHER)
                    }
                ))
                .await,
            Err(MemoryAdministrationError::InvalidInput { field: "scope" })
        );
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn source_revocation_stops_new_saves_and_explicit_context_but_retains_chosen_saved_copy_scope()
 {
    fixture("memorysourcerevoke", |p| async move {
        provision(&p, 37).await;
        let store = PostgresMemoryAdministration::new(p.clone());
        let mut copies = vec![];
        for scope in [
            MemoryScope::User,
            MemoryScope::Bot {
                bot_id: BotId::new("bot"),
            },
        ] {
            copies.push(
                store
                    .remember(request(CHANNEL, "channel-message", scope))
                    .await
                    .unwrap(),
            );
        }
        let c = p.get().await.unwrap();
        c.batch_execute(
            "DELETE FROM public.channel_memberships WHERE channel_id='channel' AND user_id='actor'",
        )
        .await
        .unwrap();
        assert_eq!(
            store
                .remember(request(CHANNEL, "channel-message", MemoryScope::User))
                .await,
            Err(MemoryAdministrationError::NotVisible)
        );
        assert_eq!(
            store.recall(recall(Some(CHANNEL))).await,
            Err(MemoryAdministrationError::NotVisible)
        );
        let saved = store.recall(recall(None)).await.unwrap().memories;
        assert_eq!(saved.len(), 2);
        assert!(copies.iter().all(|r| saved.contains(r)));
        // Corrections keep the original provenance despite source revocation; their own scope remains authorized.
        for copy in copies {
            let replacement = store.correct(correction(&copy, 0)).await.unwrap();
            assert_eq!(
                replacement.source_authorization_snapshot,
                copy.source_authorization_snapshot
            );
        }
        let mut wrong = request(DIRECT, "bound", MemoryScope::User);
        wrong.deployment = DeploymentId::new("other-deployment");
        assert_eq!(
            store.remember(wrong).await,
            Err(MemoryAdministrationError::NotVisible)
        );
        assert_eq!(
            store
                .remember(request(
                    DIRECT,
                    "bound",
                    MemoryScope::Bot {
                        bot_id: BotId::new("foreign-bot")
                    }
                ))
                .await,
            Err(MemoryAdministrationError::NotVisible)
        );
        c.batch_execute(
            "INSERT INTO public.channel_memberships(channel_id,user_id) VALUES ('channel','actor');
            UPDATE public.channels SET package_id='00000000-0000-0000-0000-000000000417' WHERE id='channel'",
        )
        .await
        .unwrap();
        assert_eq!(
            store
                .remember(request(CHANNEL, "channel-message", MemoryScope::User))
                .await,
            Err(MemoryAdministrationError::NotVisible)
        );
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn correction_inherits_then_authorization_and_separately_records_current_action_authorization()
 {
    fixture("memorysourcecorrection", |p| async move {
        provision(&p, 37).await;
        let store = PostgresMemoryAdministration::new(p.clone());
        let old = store
            .remember(request(DIRECT, "bound", MemoryScope::User))
            .await
            .unwrap();
        let c = p.get().await.unwrap();
        c.batch_execute(
            "BEGIN; UPDATE public.users SET auth_generation=1 WHERE id='actor';
            DELETE FROM public.user_roles WHERE user_id='actor';
            INSERT INTO public.user_roles(user_id,role) VALUES ('actor','admin'); COMMIT",
        )
        .await
        .unwrap();
        assert_eq!(
            store.correct(correction(&old, 0)).await,
            Err(MemoryAdministrationError::NotVisible)
        );
        let new = store.correct(correction(&old, 1)).await.unwrap();
        assert_eq!(new.source_run_id, old.source_run_id);
        assert_eq!(
            new.source_authorization_snapshot,
            old.source_authorization_snapshot
        );
        assert!(new.created_at >= old.created_at);
        let event: serde_json::Value = c
            .query_one(
                "SELECT metadata FROM public.memory_events WHERE memory_id=$1 AND seq=0",
                &[&new.memory_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(event["actionAuthorization"]["authGeneration"], 1);
        assert_eq!(
            event["actionAuthorization"]["roles"],
            serde_json::json!(["admin"])
        );
        let before = c
            .query_one(
                "SELECT row_to_json(m)::jsonb FROM public.memories m WHERE memory_id=$1",
                &[&old.memory_id],
            )
            .await
            .unwrap()
            .get::<_, serde_json::Value>(0);
        for assignment in [
            "owner_user_id='other'",
            "created_at=created_at-interval '1 second'",
            "source_run_id=NULL",
            "source_thread_id=NULL,source_message_id=NULL,source_run_id=NULL",
            "source_authorization_snapshot=NULL",
            "scope_kind='bot',scope_id='bot'",
            "origin='remember_tool'",
        ] {
            let error = c
                .execute(
                    &format!("UPDATE public.memories SET {assignment} WHERE memory_id=$1"),
                    &[&old.memory_id],
                )
                .await
                .unwrap_err();
            assert_eq!(error.code(), Some(&SqlState::CHECK_VIOLATION));
            let after = c
                .query_one(
                    "SELECT row_to_json(m)::jsonb FROM public.memories m WHERE memory_id=$1",
                    &[&old.memory_id],
                )
                .await
                .unwrap()
                .get::<_, serde_json::Value>(0);
            assert_eq!(before, after);
        }
        Ok(())
    })
    .await;
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn upgrade_preserves_legacy_null_and_correction_cannot_invent_source_authorization() {
    fixture("memorysourcelegacy", |p| async move {
        provision(&p,36).await;
        let mut c=p.get().await.unwrap();
        c.batch_execute("INSERT INTO public.memories(memory_id,tenant_id,owner_user_id,scope_kind,memory_kind,content,
            sensitivity,origin,created_by) VALUES ('legacy','tenant','actor','user','preference','legacy evidence','normal','user_action','actor')").await.unwrap();
        let before:serde_json::Value=c.query_one("SELECT row_to_json(m)::jsonb FROM public.memories m",&[]).await.unwrap().get(0);
        native::apply(&mut c).await.unwrap();
        let after:serde_json::Value=c.query_one("SELECT row_to_json(m)::jsonb FROM public.memories m",&[]).await.unwrap().get(0);
        assert_eq!(before.as_object().unwrap(),&after.as_object().unwrap().iter().filter(|(k,_)|!matches!(k.as_str(),"source_run_id"|"source_authorization_snapshot"))
            .map(|(k,v)|(k.clone(),v.clone())).collect::<serde_json::Map<_,_>>());
        assert!(after["source_run_id"].is_null()); assert!(after["source_authorization_snapshot"].is_null());
        drop(c);
        let store=PostgresMemoryAdministration::new(p.clone());
        let old=store.list_memories(MemoryPageRequest {tenant:TenantId::new("tenant"),actor:ActorId::new("actor"),
            auth_generation:AuthGeneration::new(0),cursor:None,limit:100}).await.unwrap().memories.remove(0);
        let new=store.correct(correction(&old,0)).await.unwrap();
        assert!(new.source.is_none()); assert!(new.source_run_id.is_none()); assert!(new.source_authorization_snapshot.is_none());
        let c=p.get().await.unwrap();
        let forged=serde_json::json!({"actorId":"actor","tenantId":"tenant","deploymentId":"deployment","authGeneration":0,"roles":["user"],"scope":{"kind":"user"},"capturedAt":"2020-01-01T00:00:00Z"});
        assert_eq!(c.execute("UPDATE public.memories SET source_authorization_snapshot=$1 WHERE memory_id='legacy'",&[&forged]).await.unwrap_err().code(),Some(&SqlState::CHECK_VIOLATION));
        assert_eq!(native::apply(&mut p.get().await.unwrap()).await.unwrap(),native::ApplyOutcome::AlreadyApplied);
        Ok(())
    }).await;
}

async fn wait_for_blocker(
    c: &openbot_infra::db::pool::PooledClient,
    query_fragment: &str,
    blocker: i32,
) -> i32 {
    tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            // This observer holds the owned advisory barrier transaction. PostgreSQL statistics
            // otherwise retain its first activity snapshot and hide the subsequently started waiter.
            c.query_one("SELECT pg_stat_clear_snapshot()", &[])
                .await
                .unwrap();
            let row = c
                .query_opt(
                    "SELECT pid FROM pg_stat_activity WHERE pid<>pg_backend_pid()
                AND strpos(query,$1)>0 AND $2=ANY(pg_blocking_pids(pid))",
                    &[&query_fragment, &blocker],
                )
                .await
                .unwrap();
            if let Some(row) = row {
                return row.get(0);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("actual PostgreSQL wait chain not observed for {query_fragment} behind {blocker}")
    })
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn disabling_writes_orders_gui_save_and_correction_before_or_after_control_commit() {
    for mode in ["save_first", "correct_first", "control_first"] {
        fixture(&format!("memorycontrol_{mode}"), |p| async move {
            provision(&p, 37).await;
            let store = PostgresMemoryAdministration::new(p.clone());
            let old = if mode == "correct_first" {
                Some(
                    store
                        .remember(request(DIRECT, "bound", MemoryScope::User))
                        .await
                        .unwrap(),
                )
            } else {
                None
            };
            let c = p.get().await.unwrap();
            let table = if mode == "control_first" {
                "user_memory_controls"
            } else {
                "memories"
            };
            // The owned table lock pauses the real write after actor admission and before
            // effect commit, without changing the catalog checked by the current schema guard.
            c.batch_execute(&format!("BEGIN; LOCK TABLE public.{table} IN SHARE MODE"))
                .await
                .unwrap();
            let barrier_pid: i32 = c
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .unwrap()
                .get(0);
            let writer_store = store.clone();
            let write = async move {
                if let Some(old) = old {
                    writer_store.correct(correction(&old, 0)).await
                } else {
                    writer_store
                        .remember(request(DIRECT, "bound", MemoryScope::User))
                        .await
                }
            };
            let control_store = store.clone();
            let control = async move {
                control_store
                    .update_memory_control(UpdateMemoryControlRequest {
                        tenant: TenantId::new("tenant"),
                        actor: ActorId::new("actor"),
                        auth_generation: AuthGeneration::new(0),
                        update: UpdateMemoryControl {
                            writes_enabled: false,
                        },
                    })
                    .await
            };
            let (writer, controller) = if mode == "control_first" {
                let controller = tokio::spawn(control);
                let controller_pid =
                    wait_for_blocker(&c, "INSERT INTO public.user_memory_controls", barrier_pid)
                        .await;
                let writer = tokio::spawn(write);
                wait_for_blocker(&c, "FOR SHARE OF u", controller_pid).await;
                (writer, controller)
            } else {
                let writer = tokio::spawn(write);
                let query_fragment = if mode == "correct_first" {
                    "UPDATE public.memories SET status='superseded'"
                } else {
                    "INSERT INTO public.memories"
                };
                let writer_pid = wait_for_blocker(&c, query_fragment, barrier_pid).await;
                let controller = tokio::spawn(control);
                wait_for_blocker(&c, "FOR UPDATE OF u", writer_pid).await;
                (writer, controller)
            };
            c.batch_execute("COMMIT").await.unwrap();
            let written = writer.await.unwrap();
            let disabled = controller.await.unwrap().unwrap();
            assert!(!disabled.writes_enabled);
            if mode == "control_first" {
                assert_eq!(written, Err(MemoryAdministrationError::WritesDisabled));
            } else {
                assert!(written.is_ok());
            }
            let count: i64 = c
                .query_one("SELECT count(*) FROM public.memories", &[])
                .await
                .unwrap()
                .get(0);
            assert_eq!(
                count,
                match mode {
                    "control_first" => 0,
                    "correct_first" => 2,
                    _ => 1,
                }
            );
            assert_eq!(
                store
                    .remember(request(DIRECT, "bound", MemoryScope::User))
                    .await,
                Err(MemoryAdministrationError::WritesDisabled)
            );
            Ok(())
        })
        .await;
    }
}
