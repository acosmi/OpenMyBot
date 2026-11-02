// Reuse the original isolated-database, V1/V2, import and connection teardown controls.
// Historical0051 and current0052 remain separate independently authored immutable fixtures.
include!("thread_history_admission_schema_fixture.rs");
const THREAD_INSERT: &str = "INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,title,status,next_message_seq,next_event_seq,created_at,updated_at,deleted_at) VALUES($1,'owned-origin-tenant','owned-origin-deployment','origin-a','direct_bot',$2,'Owned permanent ID','active',0,0,'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z',NULL)";
const OP: &str = "019a1234-5678-7abc-8abc-000000000001";

async fn head(c: &Client, id: &str) -> TestResult<Option<Value>> {
    c.query_opt("SELECT to_jsonb(h)||jsonb_build_object('storageXmin',xmin::text) FROM openbot_internal.thread_history_heads h WHERE thread_id=$1",&[&id]).await.map_err(|e|e.to_string())?.map(|r|r.try_get(0).map_err(|e|e.to_string())).transpose()
}
async fn check_base_head(c: &Client, id: &str) -> TestResult<Value> {
    let h = head(c, id)
        .await?
        .ok_or("real Thread has no permanent head")?;
    require(
        h.as_object().map(|x| x.len()) == Some(15) && h["head_schema"] == 1 && h["phase"] == "open",
        "head stored shape/schema/phase differs",
    )?;
    let r=c.query_one("SELECT (h.deployment_id,h.tenant_id,h.thread_id,h.anchor_kind,h.anchor_id,h.thread_created_at)=(t.deployment_id,t.tenant_id,t.thread_id,t.anchor_kind,t.anchor_id,t.created_at),isfinite(h.recorded_at),h.closure_operation_id IS NULL AND h.closure_request_id IS NULL AND h.closure_actor_id IS NULL AND h.closure_auth_generation IS NULL AND h.closed_at IS NULL FROM openbot_internal.thread_history_heads h JOIN public.threads t USING(thread_id) WHERE h.thread_id=$1",&[&id]).await.map_err(|e|e.to_string())?;
    require(
        (0..3).all(|i| r.get::<_, bool>(i)),
        "actual Thread/full base/head open tuple differs",
    )?;
    Ok(h)
}
async fn raw_thread(c: &Client, id: &str) -> TestResult {
    c.execute(THREAD_INSERT, &[&id, &"origin-bot"])
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn writer_check(c: &Client) -> TestResult {
    native::validate_current(c)
        .await
        .map_err(|e| e.to_string())?;
    admission_schema::verify(c)
        .await
        .map_err(|e| e.to_string())?;
    origin_schema::verify(c).await.map_err(|e| e.to_string())?;
    let ledger = native::validate_known_prefix(c, 53)
        .await
        .map_err(|e| e.to_string())?;
    require(
        ledger.latest_version() == 53,
        "current prefix not exact0053",
    )?;
    Ok(())
}
async fn writer_check_legacy51(c: &mut pool::PooledClient) -> TestResult {
    let ledger = native::validate_known_prefix(c, 51)
        .await
        .map_err(|e| e.to_string())?;
    require(
        ledger.latest_version() == 51,
        "historical prefix not exact0051",
    )?;
    // This explicit no-DDL replay consumes the original full39 prefix and independent0051
    // writer oracle inside the migration transaction. It supplies no current52 admission.
    require(
        native::apply_through(c, 51)
            .await
            .map_err(|e| e.to_string())?
            == native::ApplyOutcome::AlreadyApplied,
        "historical0051 whole-schema replay changed or refused",
    )?;
    let public = openbot_infra::db::schema_facts::fetch(c)
        .await
        .map_err(|e| e.to_string())?;
    let expected: openbot_infra::db::schema_facts::SchemaFacts =
        serde_json::from_str(include_str!("../../../../fixtures/db/schema-0051.json"))
            .map_err(|e| e.to_string())?;
    require(public == expected, "historical0051 public oracle changed")?;
    require(
        admission_schema::verify(c).await.is_err(),
        "historical0051 supplied current0052 admission",
    )
}
async fn writer_snapshot(p: &pool::DatabasePool) -> TestResult<Value> {
    let c = p.get().await.map_err(|e| e.to_string())?;
    let mut result = serde_json::Map::new();
    for table in [
        "public.threads",
        "public.thread_memberships",
        "public.thread_leases",
        "public.messages",
        "public.runs",
        "public.run_events",
        "public.outbox",
        "public.run_model_selections",
        "openbot_internal.run_model_selection_v2_snapshots",
        "public.tool_approvals",
        "public.component_human_decisions",
        "public.remote_agent_interrupts",
        "public.audit_events",
        "public.audit_checkpoints",
        "public.intelligence_import_cursors",
        "public.memories",
        "public.channels",
        "public.channel_memberships",
        "public.channel_agents",
        "openbot_internal.thread_origins",
        "openbot_internal.thread_history_heads",
        "openbot_internal.thread_history_clear_intents",
        "openbot_internal.channel_history_sources",
        "openbot_internal.thread_history_clear_batches",
        "openbot_internal.thread_history_clear_completions",
    ] {
        let rows:Value=c.query_one(&format!("SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb) FROM {table} x"),&[]).await.map_err(|e|e.to_string())?.get(0);
        result.insert(table.into(), rows);
    }
    Ok(Value::Object(result))
}
async fn close_writer_head(c: &Client, id: &str) -> TestResult {
    c.batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
        .await
        .map_err(|e| e.to_string())?;
    let op = Uuid::now_v7().to_string();
    let request = Uuid::now_v7().to_string();
    let at: time::OffsetDateTime = c
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    c.execute("INSERT INTO openbot_internal.thread_history_clear_intents(deployment_id,tenant_id,thread_id,intent_schema,intent_kind,operation_id,request_id,actor_id,auth_generation,anchor_kind,anchor_id,thread_created_at,recorded_at) SELECT deployment_id,tenant_id,thread_id,1,'stop_clear',$2,$3,'owned-close-actor',7,anchor_kind,anchor_id,thread_created_at,$4 FROM openbot_internal.thread_history_heads WHERE thread_id=$1",&[&id,&op,&request,&at]).await.map_err(|e|e.to_string())?;
    c.execute("UPDATE openbot_internal.thread_history_heads SET phase='closed',closure_operation_id=$2,closure_request_id=$3,closure_actor_id='owned-close-actor',closure_auth_generation=7,closed_at=$4 WHERE thread_id=$1",&[&id,&op,&request,&at]).await.map_err(|e|e.to_string())?;
    c.batch_execute("COMMIT").await.map_err(|e| e.to_string())?;
    require(
        head(c, id).await?.ok_or("closed H absent")?["phase"] == "closed",
        "H/Q fixture did not naturally commit",
    )
}
fn writer_runtime(p: &pool::DatabasePool) -> TestResult<PostgresRunRuntime> {
    PostgresRunRuntime::new(
        p.clone(),
        PROCESS.into(),
        DEFAULT_THREAD_LEASE_DURATION,
        DEFAULT_DISPATCH_CLAIM_DURATION,
        openbot_infra::recovery_control::RecoveryReadGate::outside_recovery_domain(&p, &openbot_contracts::ids::DeploymentId::new("outside"), &openbot_contracts::ids::TenantId::new("outside")),
    )
    .map_err(|e| e.to_string())
}
async fn writer_running(
    p: &pool::DatabasePool,
    config: &pool::DatabaseConfig,
    index: u64,
    channel: Option<&str>,
) -> TestResult<(BeginThreadRunRequest, PostgresRunRuntime, RunExecutionLease)> {
    let mut req = request("origin-a", index);
    if let Some(id) = channel {
        req.command.anchor = ThreadRunAnchor::Channel {
            channel_id: ChannelId::new(id),
        };
    }
    directory(p, config)?
        .begin_thread_run(req.clone())
        .await
        .map_err(|e| e.to_string())?;
    let runtime = writer_runtime(p)?;
    let claim = runtime
        .claim_dispatch()
        .await
        .map_err(|e| e.to_string())?
        .ok_or("actual claim missing")?;
    let lease = runtime
        .acknowledge_dispatch(&claim)
        .await
        .map_err(|e| e.to_string())?;
    require(
        lease.run_id() == &req.command.run_id,
        "actual claim selected another run",
    )?;
    Ok((req, runtime, lease))
}
async fn writer_channel(p: &pool::DatabasePool, id: &str) -> TestResult {
    let c = p.get().await.map_err(|e| e.to_string())?;
    c.execute("INSERT INTO public.channels(id,name,description,suggested_prompts,allowed_groups) VALUES($1,'Owned writer channel','',ARRAY[]::text[],ARRAY[]::text[])",&[&id]).await.map_err(|e|e.to_string())?;
    c.execute(
        "INSERT INTO public.channel_memberships(channel_id,user_id) VALUES($1,'origin-a')",
        &[&id],
    )
    .await
    .map_err(|e| e.to_string())?;
    c.execute(
        "INSERT INTO public.channel_agents(channel_id,agent_id) VALUES($1,'origin-bot')",
        &[&id],
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}
async fn writer_refusal(c: &Client, sql: &str, code: &str) -> TestResult {
    c.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
    let result = c.batch_execute(sql).await;
    c.batch_execute("ROLLBACK")
        .await
        .map_err(|e| e.to_string())?;
    let e = result
        .err()
        .ok_or_else(|| format!("ordinary SQL unexpectedly accepted: {sql}"))?;
    require(
        e.as_db_error()
            .is_some_and(|d| d.code().code() == "55000" && d.message() == code),
        "SQL refused outside exact writer cause",
    )
}
async fn writer_components(p: &pool::DatabasePool) -> TestResult {
    let c = p.get().await.map_err(|e| e.to_string())?;
    c.execute("INSERT INTO public.components(name,title,kind,draft_description,published_description,published,published_at,updated_by,created_at,updated_at) VALUES($1,$2,'decision',$3,$3,true,clock_timestamp(),'the build',clock_timestamp(),clock_timestamp())",&[&ASK_APPROVAL_COMPONENT_NAME,&ASK_APPROVAL_COMPONENT_TITLE,&ASK_APPROVAL_COMPONENT_DESCRIPTION]).await.map_err(|e|e.to_string())?;
    Ok(())
}
fn writer_component_scope(req: &BeginThreadRunRequest) -> ComponentHumanDecisionScope {
    ComponentHumanDecisionScope {
        deployment: req.deployment.clone(),
        tenant: req.tenant.clone(),
        actor: req.actor.clone(),
        auth_generation: req.auth_generation,
        admin: false,
        thread_id: req.command.thread_id.clone(),
        run_id: req.command.run_id.clone(),
        agent_id: req.command.bot_id.clone(),
    }
}
fn writer_decision(id: &str) -> ComponentHumanDecisionDraft {
    let arguments = json!({"title":"Owned writer approval","summary":"Owned finite decision"});
    ComponentHumanDecisionDraft {
        decision_id: id.into(),
        provider_call_id: format!("provider-{id}"),
        component_name: ASK_APPROVAL_COMPONENT_NAME.into(),
        arguments_hash: ToolArguments::new(arguments.clone())
            .unwrap()
            .canonical_hash(),
        arguments,
        ttl: COMPONENT_HUMAN_DECISION_TTL,
    }
}
fn writer_interrupt(run: &str, id: &str) -> TestResult<ProviderRemoteInterruptBatch> {
    let item = ProviderRemoteInterrupt::new(ProviderRemoteInterruptInput {
        id: id.into(),
        reason: "human_input".into(),
        message: Some("Owned finite remote question".into()),
        tool_call_id: None,
        response_schema: Some(json!({"type":"object"})),
        expires_at: Some("2099-01-01T00:00:00Z".into()),
        metadata: None,
    })
    .map_err(|e| e.to_string())?;
    ProviderRemoteInterruptBatch::new(run.into(), vec![item]).map_err(|e| e.to_string())
}
async fn writer_blocked(c: &Client, worker: i32, owner: i32) -> TestResult {
    tokio::time::timeout(Duration::from_secs(8),async{
        loop { let r=c.query_one("WITH RECURSIVE waits(pid,path) AS (SELECT $1::integer,ARRAY[$1::integer] UNION ALL SELECT b.pid,waits.path||b.pid FROM waits CROSS JOIN LATERAL unnest(pg_blocking_pids(waits.pid)) b(pid) WHERE NOT b.pid=ANY(waits.path) AND cardinality(waits.path)<16) SELECT EXISTS(SELECT 1 FROM waits WHERE pid=$2 AND cardinality(path)>1)",&[&worker,&owner]).await.map_err(|e|e.to_string())?;
            if r.get::<_,bool>(0) { return Ok(()); } tokio::task::yield_now().await;
        }
    }).await.map_err(|_|"actual two-Tx blocker was not observed".to_owned())?
}
async fn writer_dedicated(
    config: &pool::DatabaseConfig,
    name: &str,
) -> TestResult<(pool::DatabasePool, i32)> {
    let p = pool::connect(
        &config
            .clone()
            .with_max_pool_size(1)
            .with_application_name(name),
    )
    .await
    .map_err(|e| e.to_string())?;
    let c = p.get().await.map_err(|e| e.to_string())?;
    let pid = c
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    drop(c);
    Ok((p, pid))
}
async fn writer_raw_open(c: &Client, thread: &str, run: &str) -> TestResult {
    raw_thread(c, thread).await?;
    c.execute("INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq,created_at,started_at) VALUES($1,$2,'origin-bot','origin-a',false,'running',1,0,'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z')",&[&run,&thread]).await.map_err(|e|e.to_string())?;
    Ok(())
}
fn writer_raw_body_sql(thread: &str, run: &str) -> Vec<(&'static str, String)> {
    // Finite owned ASCII identities and known table/column constants only.
    let prefix = "WITH stamp AS(SELECT clock_timestamp() at) ";
    vec![
        (
            "threads",
            format!("UPDATE public.threads SET title='new-body' WHERE thread_id='{thread}'"),
        ),
        (
            "runs",
            format!(
                "INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq,created_at,started_at) VALUES('new-{run}','{thread}','origin-bot','origin-a',false,'running',1,0,'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z')"
            ),
        ),
        (
            "messages",
            format!(
                r#"INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at) VALUES('msg-{thread}','{thread}',1,'user','{{"text":"owned body"}}','owned body','{run}','origin-a',clock_timestamp())"#
            ),
        ),
        (
            "run_events",
            format!(
                r#"INSERT INTO public.run_events(run_id,seq,thread_id,event_seq,event_type,payload,terminal,created_at) VALUES('{run}',1,'{thread}',1,'semantic_chunk','{{"kind":"text","chunk":"owned body"}}',false,clock_timestamp())"#
            ),
        ),
        (
            "tool_approvals",
            format!(
                r#"{prefix}INSERT INTO public.tool_approvals(approval_id,tool_call_id,deployment_id,tenant_id,thread_id,run_id,actor_id,bot_id,auth_generation,tool_name,args_hash,target_kind,target_id,effect,approval_class,computer_generation,catalog_generation,policy_version,arguments_summary,state,requested_at,expires_at,created_at,updated_at) SELECT 'approval-{thread}','call-{thread}','{DEP}','{TENANT}','{thread}','{run}','origin-a','origin-bot',7,'computer.write',repeat('a',64),'thread','{thread}','write','every_call',1,1,repeat('b',64),'{{"summary":"owned body"}}','pending',at,at+interval '1 hour',at,at FROM stamp"#
            ),
        ),
        (
            "component_human_decisions",
            format!(
                r#"{prefix}INSERT INTO public.component_human_decisions(decision_id,deployment_id,tenant_id,thread_id,run_id,actor_id,bot_id,auth_generation,provider_call_id,component_name,arguments,arguments_hash,state,requested_at,expires_at,created_at,updated_at) SELECT 'decision-{thread}','{DEP}','{TENANT}','{thread}','{run}','origin-a','origin-bot',7,'provider-{thread}','askApproval','{{"title":"owned body"}}',repeat('a',64),'pending',at,at+interval '1 hour',at,at FROM stamp"#
            ),
        ),
        (
            "remote_agent_interrupts",
            format!(
                r#"{prefix}INSERT INTO public.remote_agent_interrupts(request_id,deployment_id,tenant_id,thread_id,run_id,actor_id,bot_id,auth_generation,protocol_run_id,interrupt_id,position,descriptor,state,requested_at,expires_at,created_at,updated_at) SELECT '{OP}','{DEP}','{TENANT}','{thread}','{run}','origin-a','origin-bot',7,'{run}','interrupt-{thread}',0,'{{"id":"interrupt-{thread}","reason":"human_input"}}','pending',at,at+interval '1 hour',at,at FROM stamp"#
            ),
        ),
    ]
}
async fn writer_pair_sql_pg(
    c: &Client,
    channel: &str,
    message: &str,
    source_first: bool,
) -> Result<(), tokio_postgres::Error> {
    let source = "INSERT INTO openbot_internal.channel_history_sources(channel_id,source_schema,deployment_id,tenant_id,thread_id,run_id,message_id,message_role,message_created_at,last_message_agent_id,preview_checksum,preview_utf8_bytes) SELECT $1,1,t.deployment_id,t.tenant_id,t.thread_id,r.run_id,m.message_id,m.role,m.created_at,CASE WHEN m.role='assistant' THEN r.bot_id END,encode(sha256(convert_to(openbot_internal.thread_history_preview(m.search_text),'UTF8')),'hex'),octet_length(openbot_internal.thread_history_preview(m.search_text)) FROM public.messages m JOIN public.runs r ON r.run_id=m.run_id JOIN public.threads t ON t.thread_id=r.thread_id WHERE m.message_id=$2 ON CONFLICT(channel_id) DO UPDATE SET deployment_id=EXCLUDED.deployment_id,tenant_id=EXCLUDED.tenant_id,thread_id=EXCLUDED.thread_id,run_id=EXCLUDED.run_id,message_id=EXCLUDED.message_id,message_role=EXCLUDED.message_role,message_created_at=EXCLUDED.message_created_at,last_message_agent_id=EXCLUDED.last_message_agent_id,preview_checksum=EXCLUDED.preview_checksum,preview_utf8_bytes=EXCLUDED.preview_utf8_bytes";
    let projection = "UPDATE public.channels c SET last_message=openbot_internal.thread_history_preview(m.search_text),last_message_at=m.created_at,last_message_agent_id=CASE WHEN m.role='assistant' THEN r.bot_id END,updated_at=greatest(c.updated_at,m.created_at) FROM public.messages m JOIN public.runs r ON r.run_id=m.run_id WHERE c.id=$1 AND m.message_id=$2";
    let (a, b) = if source_first {
        (source, projection)
    } else {
        (projection, source)
    };
    c.execute(a, &[&channel, &message]).await?;
    c.execute(b, &[&channel, &message]).await?;
    Ok(())
}
async fn writer_pair_sql(
    c: &Client,
    channel: &str,
    message: &str,
    source_first: bool,
) -> TestResult {
    writer_pair_sql_pg(c, channel, message, source_first)
        .await
        .map_err(|e| e.to_string())
}
async fn writer_stage_close(c: &Client, id: &str) -> TestResult {
    let op = Uuid::now_v7().to_string();
    let request = Uuid::now_v7().to_string();
    let at: time::OffsetDateTime = c
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(|e| e.to_string())?
        .get(0);
    c.execute("INSERT INTO openbot_internal.thread_history_clear_intents(deployment_id,tenant_id,thread_id,intent_schema,intent_kind,operation_id,request_id,actor_id,auth_generation,anchor_kind,anchor_id,thread_created_at,recorded_at) SELECT deployment_id,tenant_id,thread_id,1,'stop_clear',$2,$3,'owned-close-actor',7,anchor_kind,anchor_id,thread_created_at,$4 FROM openbot_internal.thread_history_heads WHERE thread_id=$1",&[&id,&op,&request,&at]).await.map_err(|e|e.to_string())?;
    c.execute("UPDATE openbot_internal.thread_history_heads SET phase='closed',closure_operation_id=$2,closure_request_id=$3,closure_actor_id='owned-close-actor',closure_auth_generation=7,closed_at=$4 WHERE thread_id=$1",&[&id,&op,&request,&at]).await.map_err(|e|e.to_string())?;
    Ok(())
}
// Channel, Thread, Run and message identities bound by one `writer_canonical` call.
struct WriterCanonicalIds<'a> {
    channel: &'a str,
    thread: &'a str,
    run: &'a str,
    message: &'a str,
}
async fn writer_canonical(
    p: &pool::DatabasePool,
    ids: WriterCanonicalIds<'_>,
    text: &str,
    role: &str,
    second: i64,
) -> TestResult {
    let WriterCanonicalIds {
        channel,
        thread,
        run,
        message,
    } = ids;
    let c = p.get().await.map_err(|e| e.to_string())?;
    if !c
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM public.threads WHERE thread_id=$1)",
            &[&thread],
        )
        .await
        .map_err(|e| e.to_string())?
        .get::<_, bool>(0)
    {
        c.execute("INSERT INTO public.threads(thread_id,tenant_id,deployment_id,created_by,anchor_kind,anchor_id,status,next_message_seq,next_event_seq,created_at,updated_at) VALUES($1,$2,$3,'origin-a','channel',$4,'active',0,0,'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z')",&[&thread,&TENANT,&DEP,&channel]).await.map_err(|e|e.to_string())?;
        c.execute("INSERT INTO public.runs(run_id,thread_id,bot_id,actor_id,foreground,status,fencing_token,next_event_seq,created_at,started_at) VALUES($1,$2,'origin-bot','origin-a',false,'running',1,0,'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z')",&[&run,&thread]).await.map_err(|e|e.to_string())?;
    }
    let actor = if role == "user" {
        Some("origin-a")
    } else {
        None
    };
    let at = datetime!(2026-09-01 00:00 UTC) + time::Duration::seconds(second);
    c.execute("INSERT INTO public.messages(message_id,thread_id,seq,role,content,search_text,run_id,actor_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",&[&message,&thread,&second,&role,&json!({"text":text}),&text,&run,&actor,&at]).await.map_err(|e|e.to_string())?;
    Ok(())
}
fn writer_import_terminal(
    index: u64,
) -> TestResult<(
    VerifiedIntelligenceBundle,
    IntelligenceImportMapping,
    String,
    String,
)> {
    use openbot_contracts::command::ThreadRunEventKind;
    use openbot_contracts::intelligence::{
        IntelligenceRunEventExport, IntelligenceRunExport, IntelligenceRunStatus,
    };
    let (base, mapping, _) = import_fixture(index)?;
    let mut payload = base.payload().clone();
    let thread = &mut payload.threads[0];
    let run_id = format!("writer-import-run-{index}");
    thread.runs = vec![IntelligenceRunExport {
        run_id: run_id.clone(),
        bot_id: "legacy-bot".into(),
        actor_id: "legacy-creator".into(),
        foreground: false,
        status: IntelligenceRunStatus::Failed,
        error_code: Some("owned_legacy_valid_error".into()),
        events: vec![
            IntelligenceRunEventExport {
                sequence: 0,
                event_sequence: 0,
                event_type: ThreadRunEventKind::Started,
                payload: json!({"legacy":"arbitrary started object"}),
                created_at: datetime!(2026-09-01 00:00 UTC),
            },
            IntelligenceRunEventExport {
                sequence: 1,
                event_sequence: 1,
                event_type: ThreadRunEventKind::SemanticChunk,
                payload: json!({"channel":"reasoning","delta":"OWNED_LEGACY_REASONING","retained":true}),
                created_at: datetime!(2026-09-01 00:00:01 UTC),
            },
            IntelligenceRunEventExport {
                sequence: 2,
                event_sequence: 2,
                event_type: ThreadRunEventKind::Failed,
                payload: json!({"legacy":"arbitrary terminal object","customError":"owned_legacy_valid_error"}),
                created_at: datetime!(2026-09-01 00:00:02 UTC),
            },
        ],
        created_at: datetime!(2026-09-01 00:00 UTC),
        started_at: Some(datetime!(2026-09-01 00:00 UTC)),
        finished_at: datetime!(2026-09-01 00:00:02 UTC),
    }];
    thread.updated_at = datetime!(2026-09-01 00:00:02 UTC);
    thread.checksum = compute_intelligence_thread_checksum(thread).map_err(|e| e.to_string())?;
    let thread_id = thread.thread_id.clone();
    Ok((
        VerifiedIntelligenceBundle::new(
            payload,
            "d".repeat(64),
            "owned-writer-maintenance-key".into(),
        )
        .map_err(|e| e.to_string())?,
        mapping,
        thread_id,
        run_id,
    ))
}
async fn writer_listen(
    config: &pool::DatabaseConfig,
) -> TestResult<(
    Client,
    tokio::sync::mpsc::UnboundedReceiver<String>,
    tokio::task::JoinHandle<TestResult>,
)> {
    let (c, mut connection) = config
        .to_pg_config()
        .connect(tokio_postgres::NoTls)
        .await
        .map_err(|e| e.to_string())?;
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let driver = tokio::spawn(async move {
        loop {
            match std::future::poll_fn(|cx| connection.poll_message(cx)).await {
                Some(Ok(tokio_postgres::AsyncMessage::Notification(n))) => {
                    if tx.send(n.payload().to_owned()).is_err() {
                        return Ok(());
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.to_string()),
                None => return Ok(()),
            }
        }
    });
    c.batch_execute("LISTEN openbot_channel_activity")
        .await
        .map_err(|e| e.to_string())?;
    Ok((c, rx, driver))
}
async fn writer_notify_barrier(
    c: &Client,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
) -> TestResult {
    // PostgreSQL processes pending LISTEN notifications while this same listener
    // starts its next command. Driver forwards them before its ReadyForQuery reply.
    c.query_one("SELECT 1", &[])
        .await
        .map_err(|e| e.to_string())?;
    require(
        matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ),
        "refused/equal/older/rollback writer delivered a NOTIFY",
    )
}
async fn writer_reverse_matrix(p: &pool::DatabasePool) -> TestResult {
    writer_channel(p, "writer-reverse-matrix").await?;
    writer_canonical(
        p,
        WriterCanonicalIds {
            channel: "writer-reverse-matrix",
            thread: "writer-matrix-thread",
            run: "writer-matrix-run",
            message: "writer-matrix-old",
        },
        "matrix original",
        "assistant",
        1,
    )
    .await?;
    writer_canonical(
        p,
        WriterCanonicalIds {
            channel: "writer-reverse-matrix",
            thread: "writer-matrix-thread",
            run: "writer-matrix-run",
            message: "writer-matrix-new",
        },
        "matrix replacement",
        "assistant",
        2,
    )
    .await?;
    // Keep the malformed NEW binding as its own refusal, then provision the
    // real NEW channel before testing the shared OLD/NEW channel mutex.
    let missing = p.get().await.map_err(|e| e.to_string())?;
    writer_refusal(
        &missing,
        "UPDATE public.threads SET anchor_id='owned-reverse-other' WHERE thread_id='writer-matrix-thread'",
        "thread_history_writer_binding_invalid",
    )
    .await?;
    drop(missing);
    writer_channel(p, "owned-reverse-other").await?;
    let a = p.get().await.map_err(|e| e.to_string())?;
    let b = p.get().await.map_err(|e| e.to_string())?;
    a.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
    writer_pair_sql(&a, "writer-reverse-matrix", "writer-matrix-old", true).await?;
    a.batch_execute("COMMIT").await.map_err(|e| e.to_string())?;
    for sql in [
        "UPDATE public.messages SET content=content||'{\"extra\":true}' WHERE message_id='writer-matrix-old'",
        "DELETE FROM public.messages WHERE message_id='writer-matrix-old'",
        "UPDATE public.runs SET actor_id='origin-b' WHERE run_id='writer-matrix-run'",
        "DELETE FROM public.runs WHERE run_id='writer-matrix-run'",
        "UPDATE public.threads SET anchor_id='owned-reverse-other' WHERE thread_id='writer-matrix-thread'",
        "DELETE FROM public.threads WHERE thread_id='writer-matrix-thread'",
    ] {
        a.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
        a.query_one(
            "SELECT id FROM public.channels WHERE id='writer-reverse-matrix' FOR UPDATE",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
        b.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
        let e = b.batch_execute(sql).await;
        b.batch_execute("ROLLBACK")
            .await
            .map_err(|e| e.to_string())?;
        a.batch_execute("ROLLBACK")
            .await
            .map_err(|e| e.to_string())?;
        require(
            e.is_err_and(|e| e.code().is_some_and(|s| s.code() == "55P03")),
            "real canonical UPDATE/DELETE did not take shared channel mutex NOWAIT",
        )?;
    }
    for lock in [
        "SELECT message_id FROM public.messages WHERE message_id='writer-matrix-new' FOR UPDATE",
        "SELECT run_id FROM public.runs WHERE run_id='writer-matrix-run' FOR UPDATE",
        "SELECT thread_id FROM public.threads WHERE thread_id='writer-matrix-thread' FOR UPDATE",
    ] {
        b.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
        b.query_one(lock, &[]).await.map_err(|e| e.to_string())?;
        a.batch_execute("BEGIN").await.map_err(|e| e.to_string())?;
        let result =
            writer_pair_sql_pg(&a, "writer-reverse-matrix", "writer-matrix-new", true).await;
        a.batch_execute("ROLLBACK")
            .await
            .map_err(|e| e.to_string())?;
        b.batch_execute("ROLLBACK")
            .await
            .map_err(|e| e.to_string())?;
        require(
            result.is_err_and(|e| e.code().is_some_and(|c| c.code() == "55P03")),
            "source replacement did not take actual m/r/t SHARE NOWAIT",
        )?;
    }
    Ok(())
}
