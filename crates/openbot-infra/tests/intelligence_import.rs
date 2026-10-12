//! Intelligence bundle cursor/resume/checksum 的 PostgreSQL 17 真库证据。

mod harness;

use harness::{admin_config, with_temp_database};
use openbot_application::{
    INTELLIGENCE_SOURCE_COMMIT, IntelligenceImportError, IntelligenceImportReportStatus,
    IntelligenceImportStore, VerifiedIntelligenceBundle, compute_intelligence_thread_checksum,
    import_intelligence_bundle,
};
use openbot_contracts::command::ThreadRunEventKind;
use openbot_contracts::ids::thread::ThreadIdentity;
use openbot_contracts::ids::{DeploymentId, ThreadId};
use openbot_contracts::intelligence::{
    INTELLIGENCE_BUNDLE_SCHEMA_VERSION, IntelligenceBundlePayload, IntelligenceBundleProvenance,
    IntelligenceImportMapping, IntelligenceMemoryExport, IntelligenceMemoryScope,
    IntelligenceMemoryStatus, IntelligenceMessageExport, IntelligenceMessageRole,
    IntelligenceRunEventExport, IntelligenceRunExport, IntelligenceRunStatus,
    IntelligenceThreadAnchor, IntelligenceThreadChecksum, IntelligenceThreadExport,
    IntelligenceThreadStatus,
};
use openbot_contracts::memory::{MemoryKind, MemorySensitivity, MemorySource};
use openbot_infra::db::{baseline, native, pool};
use openbot_infra::intelligence_import::PostgresIntelligenceImportStore;
use serde_json::json;
use time::macros::datetime;

async fn provision(pool: &openbot_infra::db::pool::DatabasePool) -> Result<(), String> {
    let mut client = pool.get().await.map_err(|error| error.to_string())?;
    baseline::apply(&client)
        .await
        .map_err(|error| error.to_string())?;
    native::apply(&mut client)
        .await
        .map_err(|error| error.to_string())?;
    client
        .batch_execute(
            "INSERT INTO public.users(id,email) VALUES('actor-a','a@example.test');
             INSERT INTO public.agents(id,name,type,configuration)
               VALUES('bot-1','Bot 1','built_in','{}'::jsonb);
             INSERT INTO public.agent_profiles(
               agent_id,owner_user_id,title,role_description,avatar_seed,visibility,deleted_at
             ) VALUES('bot-1',NULL,'Bot 1','test role','seed','public',NULL);
             INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups)
               VALUES('channel-1','Channel 1','test','{}','{}');",
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn fixture() -> (
    VerifiedIntelligenceBundle,
    IntelligenceImportMapping,
    Vec<String>,
) {
    fixture_with_unknown(false)
}

fn fixture_with_unknown(
    unknown: bool,
) -> (
    VerifiedIntelligenceBundle,
    IntelligenceImportMapping,
    Vec<String>,
) {
    let deployment = DeploymentId::new("target-deployment");
    let identity = ThreadIdentity::new(&deployment);
    let first_id = identity.mint_from_entropy([1; 16]).as_str().to_owned();
    let second_id = identity.mint_from_entropy([2; 16]).as_str().to_owned();
    let mut first = IntelligenceThreadExport {
        thread_id: first_id,
        created_by: "legacy-user".to_owned(),
        members: vec!["legacy-user".to_owned()],
        title: Some("Imported direct thread".to_owned()),
        anchor: IntelligenceThreadAnchor::DirectBot {
            bot_id: "legacy-bot".to_owned(),
        },
        status: IntelligenceThreadStatus::Active,
        messages: vec![
            IntelligenceMessageExport {
                message_id: "message-1-user".to_owned(),
                sequence: 0,
                role: IntelligenceMessageRole::User,
                content: json!({"text":"hello"}),
                search_text: "hello".to_owned(),
                run_id: Some("run-1".to_owned()),
                actor_id: Some("legacy-user".to_owned()),
                created_at: datetime!(2026-08-24 00:00:00 UTC),
            },
            IntelligenceMessageExport {
                message_id: "message-1-assistant".to_owned(),
                sequence: 1,
                role: IntelligenceMessageRole::Assistant,
                content: json!({"text":"world"}),
                search_text: "world".to_owned(),
                run_id: Some("run-1".to_owned()),
                actor_id: None,
                created_at: datetime!(2026-08-24 00:00:02 UTC),
            },
        ],
        runs: vec![IntelligenceRunExport {
            run_id: "run-1".to_owned(),
            bot_id: "legacy-bot".to_owned(),
            actor_id: "legacy-user".to_owned(),
            foreground: true,
            status: IntelligenceRunStatus::Completed,
            error_code: None,
            events: vec![
                IntelligenceRunEventExport {
                    sequence: 0,
                    event_sequence: 0,
                    event_type: ThreadRunEventKind::Started,
                    payload: json!({"runId":"run-1"}),
                    created_at: datetime!(2026-08-24 00:00:00 UTC),
                },
                IntelligenceRunEventExport {
                    sequence: 1,
                    event_sequence: 1,
                    event_type: ThreadRunEventKind::SemanticChunk,
                    payload: json!({"channel":"text","delta":"world"}),
                    created_at: datetime!(2026-08-24 00:00:01 UTC),
                },
                IntelligenceRunEventExport {
                    sequence: 2,
                    event_sequence: 2,
                    event_type: ThreadRunEventKind::Completed,
                    payload: json!({"status":"completed"}),
                    created_at: datetime!(2026-08-24 00:00:02 UTC),
                },
            ],
            created_at: datetime!(2026-08-24 00:00:00 UTC),
            started_at: Some(datetime!(2026-08-24 00:00:00 UTC)),
            finished_at: datetime!(2026-08-24 00:00:02 UTC),
        }],
        // 故意让 child 在 parent 前，adapter 必须按 supersedes 拓扑插入。
        memories: vec![
            IntelligenceMemoryExport {
                memory_id: "memory-2".to_owned(),
                owner_user_id: "legacy-user".to_owned(),
                scope: IntelligenceMemoryScope::User,
                memory_kind: MemoryKind::Preference,
                content: "prefer concise answers".to_owned(),
                tags: vec!["style".to_owned()],
                sensitivity: MemorySensitivity::Normal,
                source: MemorySource {
                    thread_id: ThreadId::new("placeholder"),
                    message_id: "message-1-user".to_owned(),
                },
                created_by: "legacy-user".to_owned(),
                supersedes_id: Some("memory-1".to_owned()),
                status: IntelligenceMemoryStatus::Active,
                expires_at: None,
                created_at: datetime!(2026-08-24 00:00:04 UTC),
                updated_at: datetime!(2026-08-24 00:00:04 UTC),
            },
            IntelligenceMemoryExport {
                memory_id: "memory-1".to_owned(),
                owner_user_id: "legacy-user".to_owned(),
                scope: IntelligenceMemoryScope::Bot {
                    bot_id: "legacy-bot".to_owned(),
                },
                memory_kind: MemoryKind::Fact,
                content: "Friday office hours".to_owned(),
                tags: vec!["office".to_owned(), "schedule".to_owned()],
                sensitivity: MemorySensitivity::Sensitive,
                source: MemorySource {
                    thread_id: ThreadId::new("placeholder"),
                    message_id: "message-1-user".to_owned(),
                },
                created_by: "legacy-user".to_owned(),
                supersedes_id: None,
                status: IntelligenceMemoryStatus::Superseded,
                expires_at: None,
                created_at: datetime!(2026-08-24 00:00:03 UTC),
                updated_at: datetime!(2026-08-24 00:00:04 UTC),
            },
        ],
        checksum: zero_checksum(),
        created_at: datetime!(2026-08-24 00:00:00 UTC),
        updated_at: datetime!(2026-08-24 00:00:04 UTC),
        deleted_at: None,
    };
    for memory in &mut first.memories {
        memory.source.thread_id = ThreadId::new(&first.thread_id);
    }
    if unknown {
        first.runs[0].status = IntelligenceRunStatus::ReconciliationRequired;
        first.runs[0].error_code = Some("journal_commit_unknown".to_owned());
        let terminal = first.runs[0].events.last_mut().unwrap();
        terminal.event_type = ThreadRunEventKind::ReconciliationRequired;
        terminal.payload = json!({"status":"reconciliation_required"});
    }
    first.checksum = compute_intelligence_thread_checksum(&first).unwrap();

    let mut second = IntelligenceThreadExport {
        thread_id: second_id,
        created_by: "legacy-user".to_owned(),
        members: vec!["legacy-user".to_owned()],
        title: Some("Imported deleted thread".to_owned()),
        anchor: IntelligenceThreadAnchor::Channel {
            channel_id: "legacy-channel".to_owned(),
        },
        status: IntelligenceThreadStatus::Deleted,
        messages: vec![IntelligenceMessageExport {
            message_id: "message-2".to_owned(),
            sequence: 0,
            role: IntelligenceMessageRole::Summary,
            content: json!({"text":"prior context"}),
            search_text: "prior context".to_owned(),
            run_id: None,
            actor_id: None,
            created_at: datetime!(2026-08-24 01:00:00 UTC),
        }],
        runs: Vec::new(),
        memories: Vec::new(),
        checksum: zero_checksum(),
        created_at: datetime!(2026-08-24 01:00:00 UTC),
        updated_at: datetime!(2026-08-24 01:00:01 UTC),
        deleted_at: Some(datetime!(2026-08-24 01:00:01 UTC)),
    };
    second.checksum = compute_intelligence_thread_checksum(&second).unwrap();
    let mut threads = vec![second, first];
    let mut sorted_ids = threads
        .iter()
        .map(|thread| thread.thread_id.clone())
        .collect::<Vec<_>>();
    sorted_ids.sort();
    let payload = IntelligenceBundlePayload {
        schema_version: INTELLIGENCE_BUNDLE_SCHEMA_VERSION,
        bundle_id: "bundle-pg-1".to_owned(),
        source_deployment_id: "source-deployment".to_owned(),
        exported_at: datetime!(2026-08-24 02:00:00 UTC),
        provenance: IntelligenceBundleProvenance {
            upstream_commit: INTELLIGENCE_SOURCE_COMMIT.to_owned(),
            exporter_version: "legacy-exporter-v1".to_owned(),
            project_id: "project-1".to_owned(),
        },
        threads: {
            threads.reverse();
            threads
        },
    };
    let verified =
        VerifiedIntelligenceBundle::new(payload, "c".repeat(64), "migration-key-1".to_owned())
            .unwrap();
    let mapping = IntelligenceImportMapping {
        target_deployment_id: "target-deployment".to_owned(),
        target_tenant_id: "tenant-a".to_owned(),
        users: [("legacy-user".to_owned(), "actor-a".to_owned())]
            .into_iter()
            .collect(),
        bots: [("legacy-bot".to_owned(), "bot-1".to_owned())]
            .into_iter()
            .collect(),
        channels: [("legacy-channel".to_owned(), "channel-1".to_owned())]
            .into_iter()
            .collect(),
        claimed_thread_ids: Default::default(),
    };
    (verified, mapping, sorted_ids)
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL 17"]
async fn imported_unknown_owns_a_slot_and_exact_import_replay_preserves_it() {
    let admin = admin_config("imported_unknown_occupancy");
    with_temp_database(&admin, "imported_unknown_occupancy", |config| async move {
        let p = pool::connect(&config).await.map_err(|e| e.to_string())?;
        provision(&p).await?;
        let (bundle, mapping, _) = fixture_with_unknown(true);
        let store = PostgresIntelligenceImportStore::new(p.clone());
        let report = import_intelligence_bundle(&store, bundle.clone(), mapping.clone())
            .await.map_err(|e| e.to_string())?;
        assert_eq!(report.status, IntelligenceImportReportStatus::Completed);
        let c = p.get().await.map_err(|e| e.to_string())?;
        let query = "SELECT o.thread_id,o.run_id,o.xmin::text,o.ctid::text FROM public.thread_run_occupancy o JOIN public.runs r ON r.run_id=o.run_id WHERE r.status='reconciliation_required'";
        let row = c.query_one(query, &[]).await.map_err(|e| e.to_string())?;
        let before: (String,String,String,String) = (row.get(0),row.get(1),row.get(2),row.get(3));
        assert_eq!(before.1,"run-1");
        assert_eq!(import_intelligence_bundle(&store,bundle,mapping).await.map_err(|e|e.to_string())?,report);
        // Exercise the import's actual SQL conflict behavior too: no inserted row means no AFTER maintenance.
        c.batch_execute("INSERT INTO public.runs SELECT * FROM public.runs WHERE run_id='run-1' ON CONFLICT(run_id) DO NOTHING").await.map_err(|e|e.to_string())?;
        let row = c.query_one(query, &[]).await.map_err(|e| e.to_string())?;
        let after: (String,String,String,String) = (row.get(0),row.get(1),row.get(2),row.get(3));
        assert_eq!(before,after);
        drop(c);p.close();Ok(())
    }).await;
}

fn zero_checksum() -> IntelligenceThreadChecksum {
    IntelligenceThreadChecksum {
        projection_hash: "0".repeat(64),
        message_count: 0,
        message_hash: "0".repeat(64),
        event_count: 0,
        event_hash: "0".repeat(64),
        terminal_state_hash: "0".repeat(64),
        memory_count: 0,
        memory_hash: "0".repeat(64),
        sample_render_hash: "0".repeat(64),
    }
}

#[tokio::test]
#[ignore = "requires owned isolated PostgreSQL"]
async fn import_keeps_original_unknown_provenance_and_completed_or_resumed_observation_rejects_enrichment()
 {
    for column in ["source_run_id", "source_authorization_snapshot"] {
        with_temp_database(&admin_config(column),column,|config| async move {
            let p=pool::connect(&config).await.map_err(|e|e.to_string())?;
            provision(&p).await?;
            let (bundle,mapping,ids)=fixture();
            let store=PostgresIntelligenceImportStore::new(p.clone());
            let original=import_intelligence_bundle(&store,bundle.clone(),mapping.clone()).await.unwrap();
            let c=p.get().await.unwrap();
            assert!(c.query_one("SELECT bool_and(source_run_id IS NULL AND source_authorization_snapshot IS NULL) FROM public.memories",&[]).await.unwrap().get::<_,bool>(0));
            assert_eq!(import_intelligence_bundle(&store,bundle.clone(),mapping.clone()).await.unwrap(),original);
            // Construct a conflicting row in this owned negative fixture, without disabling the guard.
            // An initial INSERT can carry provenance absent from the old signed format; replay must notice it.
            let enrichment=if column=="source_run_id" {"'run-1'::text,NULL::jsonb"} else {
                "NULL::text,jsonb_build_object('actorId',owner_user_id,'tenantId',tenant_id,'deploymentId','target-deployment','authGeneration',0,'roles',jsonb_build_array('user'),
                 'scope',jsonb_build_object('kind','user'),'capturedAt','2020-01-01T00:00:00Z')"
            };
            c.batch_execute(&format!("WITH removed AS (DELETE FROM public.memories WHERE memory_id='memory-2' RETURNING *)
                INSERT INTO public.memories(memory_id,tenant_id,owner_user_id,scope_kind,scope_id,memory_kind,
                  content,tags,sensitivity,source_thread_id,source_message_id,origin,created_by,supersedes_id,
                  status,expires_at,created_at,updated_at,source_run_id,source_authorization_snapshot)
                SELECT memory_id,tenant_id,owner_user_id,scope_kind,scope_id,memory_kind,content,tags,sensitivity,
                  source_thread_id,source_message_id,origin,created_by,supersedes_id,status,expires_at,created_at,
                  updated_at,{enrichment} FROM removed")).await.unwrap();
            // Both direct resumed-page verification and Application completed replay use real adapters.
            assert_eq!(store.verify_thread(&ids[0]).await,Err(IntelligenceImportError::Corrupt {field:"memory_source_provenance"}));
            assert_eq!(import_intelligence_bundle(&store,bundle,mapping).await,Err(IntelligenceImportError::Corrupt {field:"memory_source_provenance"}));
            drop(c);p.close();Ok(())
        }).await;
    }
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn per_thread_failure_marks_cursor_and_resume_finishes_with_database_rechecksum() {
    let admin = admin_config(
        "per_thread_failure_marks_cursor_and_resume_finishes_with_database_rechecksum",
    );
    with_temp_database(&admin, "intelligenceimport", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let (verified, mapping, sorted_ids) = fixture();
            let second = sorted_ids[1].clone();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(&format!(
                    // The fault is injected at the second thread's own cursor write, late in
                    // its import transaction. A foreign trigger on a body table (messages)
                    // would instead be refused up front by the exact 0051 writer schema check.
                    "CREATE FUNCTION fail_second_bundle_thread() RETURNS trigger LANGUAGE plpgsql AS $$
                       BEGIN
                         IF NEW.cursor='{second}' THEN RAISE EXCEPTION 'forced second thread'; END IF;
                         RETURN NEW;
                       END $$;
                     CREATE TRIGGER fail_second_bundle_thread_trigger
                       BEFORE INSERT OR UPDATE ON public.intelligence_import_cursors
                       FOR EACH ROW EXECUTE FUNCTION fail_second_bundle_thread();"
                ))
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let store = PostgresIntelligenceImportStore::new(pool.clone());
            if import_intelligence_bundle(&store, verified.clone(), mapping.clone()).await
                != Err(IntelligenceImportError::Unavailable)
            {
                return Err("第二 thread 故障必须显式失败".to_owned());
            }
            let progress = store
                .load_progress("bundle-pg-1", "target-deployment", &"c".repeat(64))
                .await
                .map_err(|error| error.to_string())?
                .ok_or("第一 thread 后 cursor 缺失")?;
            if progress.cursor != sorted_ids[0]
                || progress.status.as_str() != "failed"
                || (progress.thread_count, progress.message_count, progress.event_count, progress.memory_count)
                    != (1, 2, 3, 2)
            {
                return Err(format!("失败 cursor/累计数漂移：{progress:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    "DROP TRIGGER fail_second_bundle_thread_trigger ON public.intelligence_import_cursors;
                     DROP FUNCTION fail_second_bundle_thread();",
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let report = import_intelligence_bundle(&store, verified.clone(), mapping.clone())
                .await
                .map_err(|error| error.to_string())?;
            if report.status != IntelligenceImportReportStatus::Completed
                || (report.thread_count, report.message_count, report.event_count, report.memory_count)
                    != (2, 3, 3, 2)
                || report.cursor != sorted_ids[1]
            {
                return Err(format!("resume report 漂移：{report:?}"));
            }
            let replay = import_intelligence_bundle(&store, verified.clone(), mapping.clone())
                .await
                .map_err(|error| error.to_string())?;
            if replay != report {
                return Err(format!("completed rerun 应只重验：{report:?}/{replay:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let cursor_shape: (i64, i64, bool, bool) = {
                let row = client
                    .query_one(
                        "SELECT count(*)::bigint,
                                count(*) FILTER (WHERE status='completed')::bigint,
                                bool_and(cursor=$2),
                                bool_and(provenance ? 'signingKeyId' AND provenance->>'payloadSha256'=$3)
                         FROM public.intelligence_import_cursors WHERE bundle_id=$1",
                        &[&"bundle-pg-1", &sorted_ids[1], &"c".repeat(64)],
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                (
                    row.try_get(0).map_err(|error| error.to_string())?,
                    row.try_get(1).map_err(|error| error.to_string())?,
                    row.try_get(2).map_err(|error| error.to_string())?,
                    row.try_get(3).map_err(|error| error.to_string())?,
                )
            };
            if cursor_shape != (4, 4, true, true) {
                return Err(format!("completed cursor/provenance 漂移：{cursor_shape:?}"));
            }
            client
                .execute(
                    r#"UPDATE public.messages SET content='{"text":"tampered"}'::jsonb
                       WHERE message_id='message-1-assistant'"#,
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            if import_intelligence_bundle(&store, verified, mapping).await
                != Err(IntelligenceImportError::Corrupt {
                    field: "final_database_checksum",
                })
            {
                return Err("completed rerun 必须发现 DB projection tamper".to_owned());
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn existing_thread_binding_conflict_rolls_back_aggregate_and_writes_failed_zero_cursor() {
    let admin = admin_config(
        "existing_thread_binding_conflict_rolls_back_aggregate_and_writes_failed_zero_cursor",
    );
    with_temp_database(&admin, "intelligenceconflict", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let (verified, mapping, sorted_ids) = fixture();
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .execute(
                    "INSERT INTO public.threads(
                       thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id
                     ) VALUES($1,'tenant-a','target-deployment','actor-a','direct_bot','wrong-bot')",
                    &[&sorted_ids[0]],
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let store = PostgresIntelligenceImportStore::new(pool.clone());
            if import_intelligence_bundle(&store, verified, mapping).await
                != Err(IntelligenceImportError::Conflict { field: "thread" })
            {
                return Err("同 thread id 异 binding 必须 conflict".to_owned());
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            let row = client
                .query_one(
                    "SELECT
                       (SELECT count(*)::bigint FROM public.messages),
                       (SELECT count(*)::bigint FROM public.runs),
                       (SELECT count(*)::bigint FROM public.intelligence_import_cursors),
                       (SELECT count(*)::bigint FROM public.intelligence_import_cursors
                        WHERE status='failed' AND cursor='$none' AND imported_count=0)",
                    &[],
                )
                .await
                .map_err(|error| error.to_string())?;
            let shape: (i64, i64, i64, i64) = (
                row.try_get(0).map_err(|error| error.to_string())?,
                row.try_get(1).map_err(|error| error.to_string())?,
                row.try_get(2).map_err(|error| error.to_string())?,
                row.try_get(3).map_err(|error| error.to_string())?,
            );
            if shape != (0, 0, 4, 4) {
                return Err(format!("conflict rollback/failed cursor 漂移：{shape:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}

#[tokio::test]
#[ignore = "需要真实 PostgreSQL：设 OPENBOT_TEST_DATABASE_URL 后加 --include-ignored 运行"]
async fn staged_tool_run_fk_refuses_incomplete_orphans_then_validates_after_repair() {
    let admin =
        admin_config("staged_tool_run_fk_refuses_incomplete_orphans_then_validates_after_repair");
    with_temp_database(&admin, "intelligencefk", |config| async move {
        let pool = pool::connect(&config)
            .await
            .map_err(|error| error.to_string())?;
        let result = async {
            provision(&pool).await?;
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    r#"ALTER TABLE public.tool_calls DROP CONSTRAINT tool_calls_run_id_fkey;
                     INSERT INTO public.tool_calls(
                       tool_call_id,run_id,call_seq,decision_id,actor_id,bot_id,tool_name,
                       schema_hash,catalog_generation,args_hash,target_kind,target_id,effect,
                       effect_downgraded,idempotency,idempotency_key,approval_class,policy_version
                     ) VALUES(
                       'call-orphan','run-missing',0,'decision-orphan','actor-a','bot-1','read',
                       repeat('0',64),0,repeat('1',64),'thread','thread-x','read',false,
                       'idempotent',NULL,'not_required','policy-1'
                     );
                     ALTER TABLE public.tool_calls ADD CONSTRAINT tool_calls_run_id_fkey
                       FOREIGN KEY(run_id) REFERENCES public.runs(run_id) ON DELETE RESTRICT NOT VALID;
                     INSERT INTO public.intelligence_import_cursors(
                       bundle_id,aggregate_kind,deployment_id,cursor,last_hash,imported_count,status,
                       provenance
                     ) VALUES(
                       'bundle-incomplete','thread','target-deployment','$none',repeat('0',64),0,
                       'running','{"payloadSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'::jsonb
                     );"#,
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let store = PostgresIntelligenceImportStore::new(pool.clone());
            let blocked = store
                .validate_tool_run_fk()
                .await
                .map_err(|error| error.to_string())?;
            if (blocked.incomplete_bundle_count, blocked.orphan_tool_call_count, blocked.validated)
                != (1, 1, false)
            {
                return Err(format!("FK preflight 未阻断：{blocked:?}"));
            }
            let client = pool.get().await.map_err(|error| error.to_string())?;
            client
                .batch_execute(
                    r#"DELETE FROM public.tool_calls WHERE tool_call_id='call-orphan';
                     UPDATE public.intelligence_import_cursors SET status='completed';
                     INSERT INTO public.intelligence_import_cursors(
                       bundle_id,aggregate_kind,deployment_id,cursor,last_hash,imported_count,status,
                       provenance
                     ) SELECT 'bundle-incomplete',kind,'target-deployment','$none',repeat('0',64),0,
                              'completed','{"payloadSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'::jsonb
                       FROM unnest(ARRAY['message','run_event','memory']) kind;"#,
                )
                .await
                .map_err(|error| error.to_string())?;
            drop(client);
            let completed = store
                .validate_tool_run_fk()
                .await
                .map_err(|error| error.to_string())?;
            if (completed.incomplete_bundle_count, completed.orphan_tool_call_count, completed.validated)
                != (0, 0, true)
            {
                return Err(format!("FK repair 后未 validate：{completed:?}"));
            }
            Ok(())
        }
        .await;
        pool.close();
        result
    })
    .await;
}
