-- Native0052: immutable same-transaction history-clear batches and completion.
-- Only the fixed tombstone UPDATE of a closed history receives the batch exception.
-- No user grant, no hard delete, no migration backfill, no restore claim or physical erase claim.
DO $clear_owner$
DECLARE v_owner oid;v_role oid;
BEGIN
 SELECT c.relowner INTO v_owner FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname='threads' AND c.relkind='r';
 SELECT oid INTO v_role FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER;
 IF v_owner IS NULL OR v_role IS DISTINCT FROM v_owner OR
    pg_catalog.getdatabaseencoding()<>'UTF8' OR NOT EXISTS(
     SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='openbot_internal' AND nspowner=v_owner
    ) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_schema_invalid';END IF;
END;
$clear_owner$;
LOCK TABLE public.threads,public.runs,public.messages,public.run_events,
 public.tool_approvals,public.component_human_decisions,public.remote_agent_interrupts,
 public.channels,public.memories,openbot_internal.thread_history_heads,
 openbot_internal.thread_history_clear_intents,openbot_internal.channel_history_sources
 IN ACCESS EXCLUSIVE MODE;

CREATE TABLE openbot_internal.thread_history_clear_batches (
 operation_id text COLLATE pg_catalog."C" NOT NULL,
 batch_seq bigint NOT NULL,
 xact_id xid8 DEFAULT pg_catalog.pg_current_xact_id() NOT NULL,
 recorded_at timestamptz DEFAULT pg_catalog.clock_timestamp() NOT NULL,

 threads_cleared bigint NOT NULL,
 messages_cleared bigint NOT NULL,
 run_events_cleared bigint NOT NULL,
 tool_approvals_cleared bigint NOT NULL,
 component_decisions_cleared bigint NOT NULL,
 remote_interrupts_cleared bigint NOT NULL,
 channel_sources_cleared bigint NOT NULL,
 channels_cleared bigint NOT NULL,
 memories_cleared bigint NOT NULL,
 run_output_expired bigint NOT NULL,

 CONSTRAINT thread_history_clear_batches_pkey PRIMARY KEY(operation_id,batch_seq),
 CONSTRAINT thread_history_clear_batches_xact_key UNIQUE(xact_id),
 CONSTRAINT thread_history_clear_batches_operation_fkey FOREIGN KEY(operation_id)
  REFERENCES openbot_internal.thread_history_clear_intents(operation_id)
  ON UPDATE RESTRICT ON DELETE RESTRICT NOT DEFERRABLE,
 CONSTRAINT thread_history_clear_batches_sequence_check CHECK(batch_seq>=1),
 CONSTRAINT thread_history_clear_batches_time_check CHECK(pg_catalog.isfinite(recorded_at)),
 CONSTRAINT thread_history_clear_batches_counts_check CHECK(

  threads_cleared BETWEEN 0 AND 1 AND
  messages_cleared BETWEEN 0 AND 128 AND
  run_events_cleared BETWEEN 0 AND 128 AND
  tool_approvals_cleared BETWEEN 0 AND 128 AND
  component_decisions_cleared BETWEEN 0 AND 128 AND
  remote_interrupts_cleared BETWEEN 0 AND 128 AND
  channel_sources_cleared BETWEEN 0 AND 128 AND
  channels_cleared BETWEEN 0 AND 128 AND
  memories_cleared BETWEEN 0 AND 128 AND run_output_expired=0)
);


CREATE TABLE openbot_internal.thread_history_clear_completions (
 operation_id text COLLATE pg_catalog."C" NOT NULL,
 deployment_id text COLLATE pg_catalog."C" NOT NULL,
 tenant_id text COLLATE pg_catalog."C" NOT NULL,
 thread_id text COLLATE pg_catalog."C" NOT NULL,
 completion_schema smallint NOT NULL,
 source text COLLATE pg_catalog."C" NOT NULL,
 completed_at timestamptz DEFAULT pg_catalog.clock_timestamp() NOT NULL,
 batches bigint NOT NULL,

 threads_cleared bigint NOT NULL,
 messages_cleared bigint NOT NULL,
 run_events_cleared bigint NOT NULL,
 tool_approvals_cleared bigint NOT NULL,
 component_decisions_cleared bigint NOT NULL,
 remote_interrupts_cleared bigint NOT NULL,
 channel_sources_cleared bigint NOT NULL,
 channels_cleared bigint NOT NULL,
 memories_cleared bigint NOT NULL,
 run_output_expired bigint NOT NULL,

 CONSTRAINT thread_history_clear_completions_pkey PRIMARY KEY(operation_id),
 CONSTRAINT thread_history_clear_completions_thread_key UNIQUE(deployment_id,tenant_id,thread_id),
 CONSTRAINT thread_history_clear_completions_operation_fkey FOREIGN KEY(operation_id)
  REFERENCES openbot_internal.thread_history_clear_intents(operation_id)
  ON UPDATE RESTRICT ON DELETE RESTRICT NOT DEFERRABLE,
 CONSTRAINT thread_history_clear_completions_schema_check CHECK(completion_schema=1),
 CONSTRAINT thread_history_clear_completions_source_check CHECK(source IN('stop_clear','maintenance')),
 CONSTRAINT thread_history_clear_completions_time_check CHECK(pg_catalog.isfinite(completed_at)),
 CONSTRAINT thread_history_clear_completions_identity_check CHECK(
  pg_catalog.octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(thread_id) BETWEEN 1 AND 512 AND thread_id !~ U&'[\0001-\001F\007F-\009F]'),
 CONSTRAINT thread_history_clear_completions_counts_check CHECK(batches>=1 AND

  threads_cleared>=0 AND
  messages_cleared>=0 AND
  run_events_cleared>=0 AND
  tool_approvals_cleared>=0 AND
  component_decisions_cleared>=0 AND
  remote_interrupts_cleared>=0 AND
  channel_sources_cleared>=0 AND
  channels_cleared>=0 AND
  memories_cleared>=0 AND
  run_output_expired>=0 AND run_output_expired=0)
);


-- A batch may never borrow a committed or another transaction's xid. The two tables
-- are append-only even for the original owner using ordinary DML; DDL owner attack is not claimed.
CREATE FUNCTION openbot_internal.guard_thread_history_clear_fact() RETURNS trigger
 LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE SECURITY INVOKER
 COST 100 SET search_path=pg_catalog,openbot_internal AS $$
DECLARE v_q openbot_internal.thread_history_clear_intents%ROWTYPE;
 v_h openbot_internal.thread_history_heads%ROWTYPE;
 v_expected_seq bigint;
BEGIN
 IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_TABLE_NAME NOT IN(
   'thread_history_clear_batches','thread_history_clear_completions') OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_fact_mutation_refused';
 END IF;
 -- Serialize this operation before any H lock or sequence read. The producer
 -- takes this same immutable Q NOWAIT before planning a batch; this guard also
 -- fences a direct INSERT. Lock contention remains native 55P03, never Corrupt.
 SELECT q.* INTO v_q FROM openbot_internal.thread_history_clear_intents q
  WHERE q.operation_id=NEW.operation_id FOR UPDATE OF q NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_binding_invalid';END IF;
 -- Shared batch versus exclusive completion, both NOWAIT: no future batch can
 -- pass the completion snapshot and change its immutable accumulated counts.
 IF TG_TABLE_NAME='thread_history_clear_batches' THEN
  SELECT h.* INTO v_h FROM openbot_internal.thread_history_heads h
   WHERE h.thread_id=v_q.thread_id FOR SHARE OF h NOWAIT;
 ELSE
  SELECT h.* INTO v_h FROM openbot_internal.thread_history_heads h
   WHERE h.thread_id=v_q.thread_id FOR UPDATE OF h NOWAIT;
 END IF;
 IF NOT FOUND OR v_h.phase IS DISTINCT FROM 'closed' OR
    ROW(v_h.deployment_id,v_h.tenant_id,v_h.thread_id,v_h.closure_operation_id,
        v_h.closure_request_id,v_h.closure_actor_id,v_h.closure_auth_generation,
        v_h.anchor_kind,v_h.anchor_id,v_h.thread_created_at,v_h.closed_at)
    IS DISTINCT FROM ROW(v_q.deployment_id,v_q.tenant_id,v_q.thread_id,v_q.operation_id,
        v_q.request_id,v_q.actor_id,v_q.auth_generation,v_q.anchor_kind,v_q.anchor_id,
        v_q.thread_created_at,v_q.recorded_at) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_binding_invalid';
 END IF;
 IF TG_TABLE_NAME='thread_history_clear_batches' THEN
  -- A new RC statement after Q ownership reads the last committed sequence.
  SELECT COALESCE(max(b.batch_seq),0)+1 INTO v_expected_seq
   FROM openbot_internal.thread_history_clear_batches b WHERE b.operation_id=NEW.operation_id;
  IF NEW.xact_id IS DISTINCT FROM pg_catalog.pg_current_xact_id() OR
     NEW.batch_seq IS DISTINCT FROM v_expected_seq OR NEW.recorded_at<v_q.recorded_at OR
     EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_completions c
      WHERE c.operation_id=NEW.operation_id) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_binding_invalid';
  END IF;
 ELSE
  IF ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id) IS DISTINCT FROM
     ROW(v_q.deployment_id,v_q.tenant_id,v_q.thread_id) OR
     NEW.source IS DISTINCT FROM CASE v_q.intent_kind WHEN 'stop_clear' THEN 'stop_clear'
       WHEN 'maintenance_clear' THEN 'maintenance' ELSE NULL END OR
     NEW.completed_at<v_q.recorded_at THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_binding_invalid';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;

CREATE TRIGGER thread_history_clear_batches_guard
 BEFORE INSERT OR UPDATE OR DELETE ON openbot_internal.thread_history_clear_batches
 FOR EACH ROW EXECUTE FUNCTION openbot_internal.guard_thread_history_clear_fact();
CREATE TRIGGER thread_history_clear_batches_no_truncate
 BEFORE TRUNCATE ON openbot_internal.thread_history_clear_batches
 FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.guard_thread_history_clear_fact();
CREATE TRIGGER thread_history_clear_completions_guard
 BEFORE INSERT OR UPDATE OR DELETE ON openbot_internal.thread_history_clear_completions
 FOR EACH ROW EXECUTE FUNCTION openbot_internal.guard_thread_history_clear_fact();
CREATE TRIGGER thread_history_clear_completions_no_truncate
 BEFORE TRUNCATE ON openbot_internal.thread_history_clear_completions
 FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.guard_thread_history_clear_fact();

CREATE FUNCTION openbot_internal.thread_history_clear_batch_active(p_thread text)
 RETURNS boolean LANGUAGE sql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE
 SECURITY INVOKER COST 100 SET search_path=pg_catalog,openbot_internal AS $$
 SELECT EXISTS(SELECT 1 FROM openbot_internal.thread_history_heads h
  JOIN openbot_internal.thread_history_clear_intents q
   ON q.operation_id=h.closure_operation_id AND q.deployment_id=h.deployment_id
    AND q.tenant_id=h.tenant_id AND q.thread_id=h.thread_id
  JOIN openbot_internal.thread_history_clear_batches b ON b.operation_id=q.operation_id
  WHERE h.thread_id=p_thread AND h.phase='closed' AND b.xact_id=pg_catalog.pg_current_xact_id()
   AND NOT EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_completions c
    WHERE c.operation_id=q.operation_id))
$$;

-- Both writer UPDATE and completion proof use exactly this finite projection. Unknown
-- or missing imported discriminators are erased, never echoed or made into trusted values.
-- A historical error code survives only as the actual immutable Run's existing metadata.
CREATE FUNCTION openbot_internal.thread_history_clear_event_payload(p_type text,p_old jsonb,p_error text)
 RETURNS jsonb LANGUAGE plpgsql IMMUTABLE CALLED ON NULL INPUT PARALLEL SAFE
 SECURITY INVOKER COST 100 SET search_path=pg_catalog,openbot_internal AS $$
BEGIN
 CASE p_type
 WHEN 'started' THEN RETURN '{"retained":false}'::jsonb;
 WHEN 'semantic_chunk' THEN
  IF p_old->>'channel' IN('text','reasoning') THEN
   RETURN pg_catalog.jsonb_build_object('channel',p_old->>'channel','retained',false);
  END IF;
  RETURN '{"retained":false}'::jsonb;
 WHEN 'checkpoint' THEN
  IF p_old->>'kind' IN('tool_exchange','remote_agui_projection') THEN
   RETURN pg_catalog.jsonb_build_object('kind',p_old->>'kind','retained',false);
  END IF;
  RETURN '{"retained":false}'::jsonb;
 WHEN 'completed','failed','cancelled','reconciliation_required' THEN
  IF p_error IS NULL THEN RETURN pg_catalog.jsonb_build_object('status',p_type);END IF;
  RETURN pg_catalog.jsonb_build_object('status',p_type,'errorCode',p_error);
 ELSE RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_binding_invalid';
 END CASE;
END;
$$;

CREATE OR REPLACE FUNCTION openbot_internal.thread_history_lock_joint(p_thread text,p_run text)
 RETURNS boolean LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE
 SECURITY INVOKER COST 100 SET search_path=pg_catalog,openbot_internal AS $$
DECLARE v_t public.threads%ROWTYPE;
 v_h openbot_internal.thread_history_heads%ROWTYPE;
BEGIN
 IF p_thread IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
 END IF;
 IF p_run IS NULL THEN
  SELECT t.* INTO v_t FROM public.threads t WHERE t.thread_id=p_thread FOR SHARE OF t NOWAIT;
 ELSE
  SELECT t.* INTO v_t FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id
   WHERE r.run_id=p_run AND t.thread_id=p_thread FOR SHARE OF r,t NOWAIT;
 END IF;
 IF NOT FOUND THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
 END IF;
 -- The original caller's bounded unique wait is allowed. The following separate
 -- volatile-function statement is a new RC snapshot; SERIALIZABLE stays unchanged.
 INSERT INTO openbot_internal.thread_history_heads
  (deployment_id,tenant_id,thread_id,head_schema,phase,anchor_kind,anchor_id,thread_created_at)
 VALUES(v_t.deployment_id,v_t.tenant_id,v_t.thread_id,1,'open',v_t.anchor_kind,v_t.anchor_id,v_t.created_at)
 ON CONFLICT(thread_id) DO NOTHING;
 SELECT h.* INTO v_h FROM openbot_internal.thread_history_heads h
  WHERE h.thread_id=p_thread FOR SHARE OF h NOWAIT;
 IF NOT FOUND OR v_h.head_schema IS DISTINCT FROM 1 OR
    ROW(v_h.deployment_id,v_h.tenant_id,v_h.thread_id,v_h.anchor_kind,v_h.anchor_id,v_h.thread_created_at)
       IS DISTINCT FROM ROW(v_t.deployment_id,v_t.tenant_id,v_t.thread_id,v_t.anchor_kind,v_t.anchor_id,v_t.created_at)
    OR NOT pg_catalog.isfinite(v_t.created_at) OR NOT pg_catalog.isfinite(v_h.recorded_at) OR
       v_t.anchor_kind NOT IN('direct_bot','channel') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
 END IF;
 IF v_h.phase='open' THEN
  IF ROW(v_h.closure_operation_id,v_h.closure_request_id,v_h.closure_actor_id,
         v_h.closure_auth_generation,v_h.closed_at) IS DISTINCT FROM ROW(NULL::text,NULL::text,NULL::text,NULL::bigint,NULL::timestamptz) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
  END IF;
  RETURN true;
 ELSIF v_h.phase='closed' THEN
  IF v_h.closure_operation_id IS NULL OR v_h.closure_request_id IS NULL OR v_h.closure_actor_id IS NULL OR
     v_h.closure_auth_generation IS NULL OR v_h.closure_auth_generation<0 OR
     v_h.closed_at IS NULL OR NOT pg_catalog.isfinite(v_h.closed_at) OR
     pg_catalog.octet_length(v_h.closure_actor_id) NOT BETWEEN 1 AND 512 OR
     v_h.closure_actor_id ~ U&'[\0001-\001F\007F-\009F]' OR
     v_h.closure_operation_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' OR
     v_h.closure_request_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' OR
     NOT EXISTS(SELECT 1 FROM openbot_internal.thread_history_clear_intents q
       WHERE q.intent_schema=1 AND q.intent_kind IN('stop_clear','maintenance_clear') AND
             ROW(q.deployment_id,q.tenant_id,q.thread_id,q.operation_id,q.request_id,q.actor_id,q.auth_generation,
                 q.anchor_kind,q.anchor_id,q.thread_created_at,q.recorded_at)
          IS NOT DISTINCT FROM ROW(v_h.deployment_id,v_h.tenant_id,v_h.thread_id,v_h.closure_operation_id,
                 v_h.closure_request_id,v_h.closure_actor_id,v_h.closure_auth_generation,v_h.anchor_kind,
                 v_h.anchor_id,v_h.thread_created_at,v_h.closed_at)) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
  END IF;
  RETURN false;
 END IF;
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
END;
$$;

CREATE OR REPLACE FUNCTION openbot_internal.guard_thread_history_body() RETURNS trigger
 LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE SECURITY INVOKER
 COST 100 SET search_path=pg_catalog,openbot_internal AS $$
DECLARE v_old jsonb;v_new jsonb;v_sources text[];v_bodies text[];v_key text;
 v_source_changed boolean:=false;v_body_changed boolean:=false;
 v_scrub boolean:=false;v_old_open boolean:=true;v_new_open boolean;
 v_row jsonb;v_rows jsonb[];v_run text;v_namespace_match boolean;
 v_clear boolean:=false;v_error text;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME NOT IN('threads','runs','messages','run_events',
    'tool_approvals','component_human_decisions','remote_agent_interrupts') OR
    TG_OP NOT IN('INSERT','UPDATE') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
 END IF;
 v_new:=pg_catalog.to_jsonb(NEW);
 IF TG_OP='UPDATE' THEN v_old:=pg_catalog.to_jsonb(OLD);END IF;
 CASE TG_TABLE_NAME
 WHEN 'threads' THEN
  v_sources:=ARRAY['thread_id','tenant_id','deployment_id','anchor_kind','anchor_id','created_at'];
  v_bodies:=ARRAY['title'];
 WHEN 'runs' THEN
  v_sources:=ARRAY['run_id','thread_id','bot_id','actor_id'];v_bodies:=ARRAY[]::text[];
 WHEN 'messages' THEN
  v_sources:=ARRAY['message_id','thread_id','run_id','role','actor_id','created_at'];
  v_bodies:=ARRAY['content','search_text'];
 WHEN 'run_events' THEN
  v_sources:=ARRAY['run_id','thread_id','seq','event_seq','event_type','terminal','created_at'];
  v_bodies:=ARRAY['payload'];
 WHEN 'tool_approvals' THEN
  v_sources:=ARRAY['approval_id','deployment_id','tenant_id','thread_id','run_id','actor_id','bot_id'];
  v_bodies:=ARRAY['arguments_summary','change_summary'];
 WHEN 'component_human_decisions' THEN
  v_sources:=ARRAY['decision_id','deployment_id','tenant_id','thread_id','run_id','actor_id','bot_id'];
  v_bodies:=ARRAY['arguments','answer'];
 WHEN 'remote_agent_interrupts' THEN
  v_sources:=ARRAY['request_id','deployment_id','tenant_id','thread_id','run_id','actor_id','bot_id'];
  v_bodies:=ARRAY['descriptor','response_payload'];
 END CASE;
 IF TG_OP='UPDATE' THEN
  FOREACH v_key IN ARRAY v_sources LOOP
   IF (v_old->v_key) IS DISTINCT FROM (v_new->v_key) THEN v_source_changed:=true;END IF;
  END LOOP;
  FOREACH v_key IN ARRAY v_bodies LOOP
   IF (v_old->v_key) IS DISTINCT FROM (v_new->v_key) THEN v_body_changed:=true;END IF;
  END LOOP;
  IF NOT v_source_changed AND NOT v_body_changed THEN RETURN NEW;END IF;
 END IF;
 -- Thread INSERT runs AFTER physical insertion; newRun checks its existing Thread
 -- with p_run=NULL rather than querying nonexistent NEW Run. Run UPDATE's OLD
 -- actual Run joint is checked, while its NEW referenced Thread is checked directly.
 IF TG_OP='UPDATE' THEN
  v_run:=CASE WHEN TG_TABLE_NAME='threads' THEN NULL ELSE v_old->>'run_id' END;
  v_old_open:=openbot_internal.thread_history_lock_joint(v_old->>'thread_id',v_run);
 END IF;
 v_run:=CASE WHEN TG_TABLE_NAME IN('threads','runs') THEN NULL ELSE v_new->>'run_id' END;
 v_new_open:=openbot_internal.thread_history_lock_joint(v_new->>'thread_id',v_run);
 IF TG_TABLE_NAME IN('tool_approvals','component_human_decisions','remote_agent_interrupts') THEN
  v_rows:=CASE WHEN TG_OP='UPDATE' THEN ARRAY[v_old,v_new] ELSE ARRAY[v_new] END;
  FOREACH v_row IN ARRAY v_rows LOOP
   SELECT true INTO v_namespace_match FROM public.runs r JOIN public.threads t ON t.thread_id=r.thread_id
    WHERE r.run_id=v_row->>'run_id' AND t.thread_id=v_row->>'thread_id'
      AND ROW(t.deployment_id,t.tenant_id,r.actor_id,r.bot_id) IS NOT DISTINCT FROM
       ROW(v_row->>'deployment_id',v_row->>'tenant_id',v_row->>'actor_id',v_row->>'bot_id')
    FOR SHARE OF r,t NOWAIT;
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';END IF;
  END LOOP;
 END IF;
 -- The new answer-shape literal is solely the clear UPDATE, not an additional
 -- business answer on an open history or an INSERT of a supposedly cleared row.
 IF TG_TABLE_NAME='component_human_decisions' THEN
  IF NEW.answer='{"retained":false}'::jsonb THEN
  IF TG_OP<>'UPDATE' OR v_source_changed OR v_old_open OR v_new_open OR
     NEW.arguments IS DISTINCT FROM '{"retained":false}'::jsonb OR
     NOT openbot_internal.thread_history_clear_batch_active(NEW.thread_id) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_closed';
  END IF;
  END IF;
 END IF;
 IF v_old_open AND v_new_open THEN RETURN NEW;END IF;
 -- Every OLD/NEW source migration requires both actual source J states open.
 IF TG_OP='UPDATE' AND v_source_changed THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_closed';
 END IF;
 -- Only an UPDATE preserving every source column may use this transaction's
 -- batch. Existing closed-finish and the old scrub exceptions remain below.
 IF TG_OP='UPDATE' AND NOT v_source_changed AND
    openbot_internal.thread_history_clear_batch_active(v_new->>'thread_id') THEN
  CASE TG_TABLE_NAME
  WHEN 'threads' THEN v_clear:=NEW.title IS NULL;
  WHEN 'messages' THEN v_clear:=NEW.content='{"text":"","retained":false}'::jsonb AND NEW.search_text='';
  WHEN 'tool_approvals' THEN v_clear:=NEW.arguments_summary IS NULL AND NEW.change_summary IS NULL;
  WHEN 'component_human_decisions' THEN
   v_clear:=NEW.arguments='{"retained":false}'::jsonb AND
    ((NEW.state='answered' AND NEW.answer='{"retained":false}'::jsonb) OR
     (NEW.state<>'answered' AND NEW.answer IS NULL));
  WHEN 'remote_agent_interrupts' THEN v_clear:=NEW.state='retired' AND NEW.descriptor IS NULL AND NEW.response_payload IS NULL;
  WHEN 'run_events' THEN
   SELECT r.error_code INTO v_error FROM public.runs r
    WHERE r.run_id=NEW.run_id AND r.thread_id=NEW.thread_id;
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';END IF;
   v_clear:=NEW.payload IS NOT DISTINCT FROM
    openbot_internal.thread_history_clear_event_payload(OLD.event_type,OLD.payload,v_error);
  ELSE v_clear:=false;
  END CASE;
  IF v_clear THEN RETURN NEW;END IF;
 END IF;
 IF TG_TABLE_NAME='run_events' THEN
  IF NEW.terminal AND openbot_internal.thread_history_terminal_payload(NEW.event_type,NEW.payload) THEN
   RETURN NEW;
  END IF;
 END IF;
 IF TG_OP='UPDATE' THEN
  IF TG_TABLE_NAME IN('threads','tool_approvals','remote_agent_interrupts') THEN
   v_scrub:=true;
   FOREACH v_key IN ARRAY v_bodies LOOP
    IF (v_old->v_key) IS DISTINCT FROM (v_new->v_key) AND
       (v_new->v_key) IS DISTINCT FROM 'null'::jsonb THEN v_scrub:=false;END IF;
   END LOOP;
  ELSIF TG_TABLE_NAME='component_human_decisions' THEN
   v_scrub:=(v_old->'arguments') IS NOT DISTINCT FROM (v_new->'arguments')
     AND NEW.answer IS NULL;
  ELSIF TG_TABLE_NAME='run_events' THEN
   v_scrub:=(OLD.event_type='semantic_chunk' AND OLD.payload->>'channel'='reasoning'
       AND NEW.payload='{"channel":"reasoning","delta":"","retained":false}'::jsonb)
     OR (OLD.event_type='checkpoint' AND OLD.payload->>'kind'='remote_agui_projection'
       AND OLD.payload->>'source'='remote_ag_ui'
       AND NEW.payload='{"kind":"remote_agui_projection","source":"remote_ag_ui","retained":false,"untrusted":true}'::jsonb);
  END IF;
 END IF;
 IF v_scrub THEN RETURN NEW;END IF;
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_closed';
END;
$$;

CREATE OR REPLACE FUNCTION openbot_internal.thread_history_validate_terminal_run(p_run text,p_terminal_changed boolean)
 RETURNS void LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE
 SECURITY INVOKER COST 100 SET search_path=pg_catalog,openbot_internal AS $$
DECLARE v_r public.runs%ROWTYPE;v_e public.run_events%ROWTYPE;v_event_found boolean;v_open boolean;
BEGIN
 IF p_terminal_changed IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
 END IF;
 SELECT r.* INTO v_r FROM public.runs r WHERE r.run_id=p_run FOR SHARE OF r NOWAIT;
 IF NOT FOUND THEN
  IF EXISTS(SELECT 1 FROM public.run_events e WHERE e.run_id=p_run AND e.terminal) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
  END IF;
  RETURN;
 END IF;
 v_open:=openbot_internal.thread_history_lock_joint(v_r.thread_id,v_r.run_id);
 SELECT e.run_id,e.thread_id,e.event_type,e.seq
  INTO v_e.run_id,v_e.thread_id,v_e.event_type,v_e.seq
  FROM public.run_events e WHERE e.run_id=p_run AND e.terminal FOR SHARE OF e NOWAIT;
 v_event_found:=FOUND;
 IF v_r.status IN('queued','running') THEN
  IF v_event_found THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';END IF;
  RETURN;
 END IF;
 IF v_r.status NOT IN('completed','failed','cancelled','reconciliation_required') OR NOT v_event_found OR
    ROW(v_r.run_id,v_r.thread_id,v_r.status,v_r.terminal_event_seq)
     IS DISTINCT FROM ROW(v_e.run_id,v_e.thread_id,v_e.event_type,v_e.seq) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
 END IF;
 -- Preserve the original open-J import contract: its verified bundle allows an
 -- arbitrary object terminal payload and valid historical error identifier. The
 -- fixed21-code payload is only the actual changed CLOSED terminal exception,
 -- not a new open import validator or revalidation of unchanged historical body.
 -- Nonterminal scrubs and terminal metadata do not read that historical payload.
 -- The final Run/event identity/status/sequence joint above is shared.
 IF v_open OR NOT p_terminal_changed THEN RETURN;END IF;
 SELECT e.payload INTO v_e.payload FROM public.run_events e
  WHERE e.run_id=v_e.run_id AND e.seq=v_e.seq AND e.terminal FOR SHARE OF e NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';END IF;
 -- Only the current clear batch may normalize a verified imported historical
 -- terminal using its Run's actual error identifier. Ordinary closed finish keeps
 -- the old 21-code validator, and unchanged historical payloads keep their old rule.
 IF openbot_internal.thread_history_clear_batch_active(v_r.thread_id) AND
    v_e.payload IS NOT DISTINCT FROM openbot_internal.thread_history_clear_event_payload(
     v_r.status,v_e.payload,v_r.error_code) THEN RETURN;END IF;
 IF NOT openbot_internal.thread_history_terminal_payload(v_e.event_type,v_e.payload) OR
    v_r.error_code IS DISTINCT FROM v_e.payload->>'errorCode' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
 END IF;
END;
$$;


-- Thread-scoped memory is retained by that J even when it has no source message.
-- User/Bot copies keep the original independent-copy rules and the 0037 provenance
-- guard remains byte-for-byte unchanged. A source reference is not a scope change.
CREATE FUNCTION openbot_internal.guard_thread_history_memory_body() RETURNS trigger
 LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE SECURITY INVOKER
 COST 100 SET search_path=pg_catalog,openbot_internal AS $$
DECLARE v_open boolean;v_head_found boolean;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'memories' OR TG_OP NOT IN('INSERT','UPDATE') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
 END IF;
 IF NEW.scope_kind IS DISTINCT FROM 'thread' THEN RETURN NEW;END IF;
 IF TG_OP='UPDATE' THEN
  -- The unchanged 0037 trigger owns its original 23514 refusal of provenance
  -- changes. This early return is not admission: that original guard still runs.
  IF ROW(NEW.tenant_id,NEW.owner_user_id,NEW.scope_kind,NEW.scope_id,NEW.memory_kind,
         NEW.source_thread_id,NEW.source_message_id,NEW.source_run_id,
         NEW.source_authorization_snapshot,NEW.origin,NEW.created_by,NEW.created_at)
    IS DISTINCT FROM
     ROW(OLD.tenant_id,OLD.owner_user_id,OLD.scope_kind,OLD.scope_id,OLD.memory_kind,
         OLD.source_thread_id,OLD.source_message_id,OLD.source_run_id,
         OLD.source_authorization_snapshot,OLD.origin,OLD.created_by,OLD.created_at) THEN RETURN NEW;END IF;
 END IF;
 -- Preserve the real tenant/base binding; the complete original joint below also
 -- proves the deployment, immutable base identity, H phase and exact closed Q.
 PERFORM 1 FROM public.threads t WHERE t.thread_id=NEW.scope_id AND t.tenant_id=NEW.tenant_id
  FOR SHARE OF t NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';END IF;
 PERFORM 1 FROM openbot_internal.thread_history_heads h WHERE h.thread_id=NEW.scope_id
  FOR SHARE OF h NOWAIT;
 v_head_found:=FOUND;
 IF NOT v_head_found THEN
  -- A legitimate pre0050 Thread may lack H. Exclusive base NOWAIT excludes every
  -- original H registrar, which first owns this T (the delete registrar already
  -- owns its DELETE row lock). Keep lazy registration without adding a unique wait.
  PERFORM 1 FROM public.threads t WHERE t.thread_id=NEW.scope_id AND t.tenant_id=NEW.tenant_id
   FOR UPDATE OF t NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';END IF;
 END IF;
 -- A new statement after the lock/upgrade observes any committed lazy winner.
 -- Original lock_joint holds T/H SHARE until this same transaction ends.
 v_open:=openbot_internal.thread_history_lock_joint(NEW.scope_id,NULL);
 IF v_open THEN RETURN NEW;END IF;
 IF TG_OP='UPDATE' THEN
  IF NEW.memory_id IS DISTINCT FROM OLD.memory_id THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_binding_invalid';
  END IF;
  IF NEW.status='deleted' AND NEW.content IS NULL AND
     openbot_internal.thread_history_clear_batch_active(NEW.scope_id) THEN RETURN NEW;END IF;
  -- This is the original Memory Delete/Forbid body-erasing closure, not a new save
  -- or recovery grant. In particular a completion's already deleted memory stays
  -- deleted with NULL content; a raw deleted-to-forbidden rewrite is not allowed.
  IF NEW.content IS NULL AND NEW.status IN('deleted','forbidden') AND
     (OLD.status<>'deleted' OR NEW.status='deleted') THEN RETURN NEW;END IF;
 END IF;
 -- Even a fixed tombstone INSERT is new material. No new row or ordinary fresh
 -- content/correction may pass a closed J, before or after its completion.
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_writer_closed';
END;
$$;
CREATE TRIGGER memories_history_body_before BEFORE INSERT OR UPDATE ON public.memories
 FOR EACH ROW EXECUTE FUNCTION openbot_internal.guard_thread_history_memory_body();

ALTER TABLE public.component_human_decisions DROP CONSTRAINT component_human_decisions_answer_shape;
ALTER TABLE public.component_human_decisions ADD CONSTRAINT component_human_decisions_answer_shape CHECK (
        answer IS NULL OR answer='{"retained":false}'::jsonb OR (
            jsonb_typeof(answer) = 'object' AND (
                (
                    component_name = 'askApproval'
                    AND answer ? 'decision'
                    AND answer->>'decision' IN ('approved','declined')
                    AND (answer - ARRAY['decision','note']::text[]) = '{}'::jsonb
                    AND (
                        NOT answer ? 'note'
                        OR (jsonb_typeof(answer->'note') = 'string' AND answer->>'note' <> '')
                    )
                ) OR (
                    component_name = 'askChoice'
                    AND answer ?& ARRAY['choice','label']::text[]
                    AND jsonb_typeof(answer->'choice') = 'string'
                    AND answer->>'choice' <> ''
                    AND jsonb_typeof(answer->'label') = 'string'
                    AND answer->>'label' <> ''
                    AND (answer - ARRAY['choice','label']::text[]) = '{}'::jsonb
                )
            )
        )
    );


-- The reserved maintenance subject is an internal actor literal, never a User/Auth context.
-- User stop_clear rows and their original closed binding retain their existing actor identity.
ALTER TABLE openbot_internal.thread_history_clear_intents
 DROP CONSTRAINT thread_history_clear_intents_kind_check;
ALTER TABLE openbot_internal.thread_history_clear_intents
 ADD CONSTRAINT thread_history_clear_intents_kind_check CHECK(intent_kind IN('stop_clear','maintenance_clear'));
ALTER TABLE openbot_internal.thread_history_clear_intents
 ADD CONSTRAINT thread_history_clear_intents_maintenance_actor_check CHECK(
  intent_kind<>'maintenance_clear' OR (actor_id='system:thread-history-clear' AND auth_generation=0));

-- Maintenance is only for an actually soft-deleted base. This is a storage
-- binding check, not a User or Host eligibility producer.
CREATE FUNCTION openbot_internal.require_thread_history_maintenance_source() RETURNS trigger
 LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE SECURITY INVOKER
 COST 100 SET search_path=pg_catalog,openbot_internal AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_TABLE_NAME<>'thread_history_clear_intents' OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_binding_invalid';
 END IF;
 IF NEW.intent_kind='maintenance_clear' THEN
  IF NEW.actor_id IS DISTINCT FROM 'system:thread-history-clear' OR NEW.auth_generation IS DISTINCT FROM 0 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_binding_invalid';
  END IF;
  PERFORM 1 FROM public.threads t WHERE t.thread_id=NEW.thread_id
   AND ROW(t.deployment_id,t.tenant_id,t.anchor_kind,t.anchor_id,t.created_at)
    IS NOT DISTINCT FROM ROW(NEW.deployment_id,NEW.tenant_id,NEW.anchor_kind,NEW.anchor_id,NEW.thread_created_at)
   AND t.status='deleted' AND t.deleted_at IS NOT NULL FOR SHARE OF t NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_binding_invalid';END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER thread_history_clear_intents_maintenance_before
 BEFORE INSERT ON openbot_internal.thread_history_clear_intents
 FOR EACH ROW EXECUTE FUNCTION openbot_internal.require_thread_history_maintenance_source();

CREATE FUNCTION openbot_internal.thread_history_clear_readers_quiescent(p_operation text)
 RETURNS boolean LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE
 SECURITY INVOKER COST 100 SET search_path=pg_catalog,openbot_internal AS $$
DECLARE v_last numeric;v_current numeric;v_database oid;
BEGIN
 SELECT max(b.xact_id::text::numeric) INTO v_last
  FROM openbot_internal.thread_history_clear_batches b WHERE b.operation_id=p_operation;
 IF v_last IS NULL THEN RETURN false;END IF;
 v_current:=pg_catalog.pg_current_xact_id()::text::numeric;
 SELECT oid INTO v_database FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database();
 -- backend_xmin is xid (32 bits), batches store xid8. Map its signed 32-bit
 -- distance to the nearest full-XID epoch, including wrap and an xmin allocated
 -- after this completion's own xid. An equal xmin may have seen the last batch
 -- still in progress: require >. Hidden state never proves a NULL xmin.
 RETURN NOT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity a
  WHERE a.datid=v_database AND a.pid<>pg_catalog.pg_backend_pid() AND
   (a.state IS NULL OR (a.backend_xmin IS NOT NULL AND
     v_current+pg_catalog.mod(a.backend_xmin::text::numeric-
      pg_catalog.mod(v_current,4294967296)+6442450944,4294967296)-2147483648<=v_last)));
END;
$$;

-- This finite predicate is shared by source preparation's producer and the
-- final deferred proof. It returns false for an unknown operation; the caller must
-- separately establish its trusted namespace and actual closed H/Q binding.
CREATE FUNCTION openbot_internal.thread_history_clear_bodies_erased(p_operation text)
 RETURNS boolean LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE
 SECURITY INVOKER COST 100 SET search_path=pg_catalog,openbot_internal AS $$
DECLARE v_q openbot_internal.thread_history_clear_intents%ROWTYPE;v_thread text;
BEGIN
 SELECT q.* INTO v_q FROM openbot_internal.thread_history_clear_intents q
  WHERE q.operation_id=p_operation;
 IF NOT FOUND THEN RETURN false;END IF;
 v_thread:=v_q.thread_id;
 RETURN NOT (
EXISTS(SELECT 1 FROM public.threads WHERE thread_id=v_thread AND title IS NOT NULL) OR
    EXISTS(SELECT 1 FROM public.messages WHERE thread_id=v_thread AND
     (content IS DISTINCT FROM '{"text":"","retained":false}'::jsonb OR search_text IS DISTINCT FROM '')) OR
    EXISTS(SELECT 1 FROM public.run_events e JOIN public.runs r ON r.run_id=e.run_id
     WHERE e.thread_id=v_thread AND (r.thread_id IS DISTINCT FROM e.thread_id OR
       (e.terminal AND ROW(e.event_type,e.seq) IS DISTINCT FROM ROW(r.status,r.terminal_event_seq)) OR
       e.payload IS DISTINCT FROM openbot_internal.thread_history_clear_event_payload(e.event_type,e.payload,r.error_code))) OR
    EXISTS(SELECT 1 FROM public.tool_approvals WHERE thread_id=v_thread AND
     (arguments_summary IS NOT NULL OR change_summary IS NOT NULL OR state='pending')) OR
    EXISTS(SELECT 1 FROM public.component_human_decisions WHERE thread_id=v_thread AND
     (arguments IS DISTINCT FROM '{"retained":false}'::jsonb OR
      (state='answered' AND answer IS DISTINCT FROM '{"retained":false}'::jsonb) OR
      (state<>'answered' AND answer IS NOT NULL))) OR
    EXISTS(SELECT 1 FROM public.remote_agent_interrupts WHERE thread_id=v_thread AND
     (state<>'retired' OR descriptor IS NOT NULL OR response_payload IS NOT NULL)) OR
    EXISTS(SELECT 1 FROM openbot_internal.channel_history_sources WHERE thread_id=v_thread) OR
    EXISTS(SELECT 1 FROM public.channels c WHERE c.id=v_q.anchor_id AND v_q.anchor_kind='channel'
      AND NOT EXISTS(SELECT 1 FROM openbot_internal.channel_history_sources s WHERE s.channel_id=c.id)
      AND ROW(c.last_message,c.last_message_at,c.last_message_agent_id)
        IS DISTINCT FROM ROW(NULL::text,NULL::timestamptz,NULL::text)) OR
    EXISTS(SELECT 1 FROM public.memories WHERE scope_kind='thread' AND scope_id=v_thread AND
     (tenant_id IS DISTINCT FROM v_q.tenant_id OR status IS DISTINCT FROM 'deleted' OR content IS NOT NULL)));
END;
$$;

CREATE FUNCTION openbot_internal.require_thread_history_clear_completion() RETURNS trigger
 LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE SECURITY INVOKER
 COST 100 SET search_path=pg_catalog,openbot_internal AS $$
DECLARE v_q openbot_internal.thread_history_clear_intents%ROWTYPE;
 v_b record;v_count bigint;v_thread text;
BEGIN
 IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_TABLE_NAME<>'thread_history_clear_completions'
    OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_binding_invalid';
 END IF;
 SELECT q.* INTO v_q FROM openbot_internal.thread_history_clear_intents q
  WHERE q.operation_id=NEW.operation_id;
 IF NOT FOUND OR ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id) IS DISTINCT FROM
   ROW(v_q.deployment_id,v_q.tenant_id,v_q.thread_id) OR
   openbot_internal.thread_history_lock_joint(v_q.thread_id,NULL) IS DISTINCT FROM false THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_binding_invalid';
 END IF;
 v_thread:=v_q.thread_id;
 IF NOT EXISTS(SELECT 1 FROM openbot_internal.thread_history_heads h
   WHERE h.thread_id=v_thread AND h.phase='closed' AND h.closure_operation_id=NEW.operation_id) OR
   NEW.source IS DISTINCT FROM CASE v_q.intent_kind WHEN 'stop_clear' THEN 'stop_clear'
    WHEN 'maintenance_clear' THEN 'maintenance' ELSE NULL END THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_binding_invalid';
 END IF;
 SELECT count(*) AS batches,max(batch_seq) AS max_seq,max(recorded_at) AS last_at,

  COALESCE(sum(threads_cleared),0) AS threads_cleared,
  COALESCE(sum(messages_cleared),0) AS messages_cleared,
  COALESCE(sum(run_events_cleared),0) AS run_events_cleared,
  COALESCE(sum(tool_approvals_cleared),0) AS tool_approvals_cleared,
  COALESCE(sum(component_decisions_cleared),0) AS component_decisions_cleared,
  COALESCE(sum(remote_interrupts_cleared),0) AS remote_interrupts_cleared,
  COALESCE(sum(channel_sources_cleared),0) AS channel_sources_cleared,
  COALESCE(sum(channels_cleared),0) AS channels_cleared,
  COALESCE(sum(memories_cleared),0) AS memories_cleared,
  COALESCE(sum(run_output_expired),0) AS run_output_expired

 INTO v_b FROM openbot_internal.thread_history_clear_batches WHERE operation_id=NEW.operation_id;
 IF v_b.batches<1 OR v_b.max_seq IS DISTINCT FROM v_b.batches OR NEW.batches IS DISTINCT FROM v_b.batches OR
    NEW.completed_at<v_b.last_at OR

    NEW.threads_cleared IS DISTINCT FROM v_b.threads_cleared OR
    NEW.messages_cleared IS DISTINCT FROM v_b.messages_cleared OR
    NEW.run_events_cleared IS DISTINCT FROM v_b.run_events_cleared OR
    NEW.tool_approvals_cleared IS DISTINCT FROM v_b.tool_approvals_cleared OR
    NEW.component_decisions_cleared IS DISTINCT FROM v_b.component_decisions_cleared OR
    NEW.remote_interrupts_cleared IS DISTINCT FROM v_b.remote_interrupts_cleared OR
    NEW.channel_sources_cleared IS DISTINCT FROM v_b.channel_sources_cleared OR
    NEW.channels_cleared IS DISTINCT FROM v_b.channels_cleared OR
    NEW.memories_cleared IS DISTINCT FROM v_b.memories_cleared OR
    NEW.run_output_expired IS DISTINCT FROM v_b.run_output_expired
 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_binding_invalid';
 END IF;
 IF EXISTS(SELECT 1 FROM public.runs WHERE thread_id=v_thread AND status IN('queued','running')) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_live_run';
 END IF;
 IF NOT openbot_internal.thread_history_clear_bodies_erased(NEW.operation_id) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_body_remaining';
 END IF;
 IF NEW.run_output_expired<>0 OR EXISTS(SELECT 1 FROM openbot_internal.artifact_records
    WHERE source_thread_id=v_thread AND status IN('available','failed_partial')
     AND retention_class IS DISTINCT FROM 'explicit_saved') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='run_output_producer_unregistered';
 END IF;
 IF NOT openbot_internal.thread_history_clear_readers_quiescent(NEW.operation_id) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_readers_active';
 END IF;
 RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER thread_history_clear_completions_require_final
 AFTER INSERT ON openbot_internal.thread_history_clear_completions
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
 EXECUTE FUNCTION openbot_internal.require_thread_history_clear_completion();

REVOKE ALL ON TABLE openbot_internal.thread_history_clear_batches,
 openbot_internal.thread_history_clear_completions FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION openbot_internal.guard_thread_history_clear_fact() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION openbot_internal.thread_history_clear_batch_active(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION openbot_internal.thread_history_clear_event_payload(text,jsonb,text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION openbot_internal.require_thread_history_clear_completion() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION openbot_internal.thread_history_clear_readers_quiescent(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION openbot_internal.thread_history_clear_bodies_erased(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION openbot_internal.require_thread_history_maintenance_source() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION openbot_internal.thread_history_lock_joint(text,text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION openbot_internal.guard_thread_history_body() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION openbot_internal.guard_thread_history_memory_body() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION openbot_internal.thread_history_validate_terminal_run(text,boolean) FROM PUBLIC;

-- Catalogue-only postcondition for the new objects and amended public constraint.
-- No historical data or migration journal version is changed here.
DO $clear_postcondition$
DECLARE v_owner oid;v_row record;v_name text;v_oid oid;v_count integer;
BEGIN
 SELECT c.relowner INTO v_owner FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='public' AND c.relname='threads' AND c.relkind='r';
 FOREACH v_name IN ARRAY ARRAY['thread_history_clear_batches','thread_history_clear_completions'] LOOP
  SELECT c.* INTO v_row FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='openbot_internal' AND c.relname=v_name;
  IF NOT FOUND OR v_row.relkind<>'r' OR v_row.relowner IS DISTINCT FROM v_owner OR
     v_row.relpersistence<>'p' OR v_row.relrowsecurity OR v_row.relforcerowsecurity OR
     v_row.relispartition OR v_row.relreplident<>'d' OR v_row.reloptions IS NOT NULL OR
     EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(v_row.relacl,pg_catalog.acldefault('r',v_owner))) a
       WHERE a.grantee<>v_owner OR a.grantor<>v_owner OR a.is_grantable) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_schema_invalid';
  END IF;
  v_oid:=v_row.oid;
  SELECT count(*) INTO v_count FROM pg_catalog.pg_attribute
   WHERE attrelid=v_oid AND attnum>0 AND NOT attisdropped;
  IF v_count<>CASE v_name WHEN 'thread_history_clear_batches' THEN 14 ELSE 18 END OR
     EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid=v_oid AND attnum>0 AND
       (attisdropped OR NOT attnotnull OR attidentity<>'' OR attgenerated<>'')) OR
     EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=v_oid) OR
     EXISTS(SELECT 1 FROM pg_catalog.pg_policy WHERE polrelid=v_oid) OR
     EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=v_oid OR inhparent=v_oid) OR
     (SELECT count(*) FROM pg_catalog.pg_constraint WHERE conrelid=v_oid)<>
       CASE v_name WHEN 'thread_history_clear_batches' THEN 6 ELSE 9 END OR
     EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid=v_oid AND
       (NOT convalidated OR (contype<>'t' AND (condeferrable OR condeferred)))) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_schema_invalid';
  END IF;
  IF EXISTS(
   WITH expected(relation_name,position,column_name,type_oid,c_collation,has_default) AS (VALUES
   ('thread_history_clear_batches',1,'operation_id','pg_catalog.text'::regtype::oid,true,false),
   ('thread_history_clear_batches',2,'batch_seq','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_batches',3,'xact_id','pg_catalog.xid8'::regtype::oid,false,true),
   ('thread_history_clear_batches',4,'recorded_at','pg_catalog.timestamptz'::regtype::oid,false,true),
   ('thread_history_clear_batches',5,'threads_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_batches',6,'messages_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_batches',7,'run_events_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_batches',8,'tool_approvals_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_batches',9,'component_decisions_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_batches',10,'remote_interrupts_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_batches',11,'channel_sources_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_batches',12,'channels_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_batches',13,'memories_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_batches',14,'run_output_expired','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_completions',1,'operation_id','pg_catalog.text'::regtype::oid,true,false),
   ('thread_history_clear_completions',2,'deployment_id','pg_catalog.text'::regtype::oid,true,false),
   ('thread_history_clear_completions',3,'tenant_id','pg_catalog.text'::regtype::oid,true,false),
   ('thread_history_clear_completions',4,'thread_id','pg_catalog.text'::regtype::oid,true,false),
   ('thread_history_clear_completions',5,'completion_schema','pg_catalog.int2'::regtype::oid,false,false),
   ('thread_history_clear_completions',6,'source','pg_catalog.text'::regtype::oid,true,false),
   ('thread_history_clear_completions',7,'completed_at','pg_catalog.timestamptz'::regtype::oid,false,true),
   ('thread_history_clear_completions',8,'batches','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_completions',9,'threads_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_completions',10,'messages_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_completions',11,'run_events_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_completions',12,'tool_approvals_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_completions',13,'component_decisions_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_completions',14,'remote_interrupts_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_completions',15,'channel_sources_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_completions',16,'channels_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_completions',17,'memories_cleared','pg_catalog.int8'::regtype::oid,false,false),
   ('thread_history_clear_completions',18,'run_output_expired','pg_catalog.int8'::regtype::oid,false,false)
   ) SELECT 1 FROM expected e LEFT JOIN pg_catalog.pg_attribute a
      ON a.attrelid=v_oid AND a.attnum=e.position
     WHERE e.relation_name=v_name AND (a.attnum IS NULL OR a.attname IS DISTINCT FROM e.column_name OR
      a.atttypid IS DISTINCT FROM e.type_oid OR a.atttypmod<>-1 OR a.attndims<>0 OR
      a.attcollation IS DISTINCT FROM CASE WHEN e.c_collation THEN 'pg_catalog."C"'::regcollation::oid ELSE 0::oid END OR
      a.atthasdef IS DISTINCT FROM e.has_default OR a.attstorage IS DISTINCT FROM CASE WHEN e.c_collation THEN 'x'::"char" ELSE 'p'::"char" END OR
      a.attcompression<>'' OR a.attstattarget<>-1 OR NOT a.attislocal OR a.attinhcount<>0 OR
      a.attacl IS NOT NULL OR a.attoptions IS NOT NULL OR a.attfdwoptions IS NOT NULL OR
      a.atthasmissing OR a.attmissingval IS NOT NULL)
  ) OR (SELECT count(*) FROM pg_catalog.pg_index WHERE indrelid=v_oid)<>2 OR
    EXISTS(SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class idx ON idx.oid=i.indexrelid
       JOIN pg_catalog.pg_am am ON am.oid=idx.relam WHERE i.indrelid=v_oid AND
      (NOT i.indisunique OR NOT i.indisvalid OR NOT i.indisready OR NOT i.indislive OR
       NOT i.indimmediate OR i.indnullsnotdistinct OR i.indisexclusion OR i.indisclustered OR i.indisreplident OR
       i.indexprs IS NOT NULL OR i.indpred IS NOT NULL OR i.indnatts<>i.indnkeyatts OR am.amname<>'btree' OR
       idx.relowner IS DISTINCT FROM v_owner OR idx.reloptions IS NOT NULL)) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_schema_invalid';
  END IF;
  IF EXISTS(
   WITH expected(name,type_bits,keys) AS (VALUES
    ('thread_history_clear_batches_pkey','p',ARRAY[1,2]::int2[]),
    ('thread_history_clear_batches_xact_key','u',ARRAY[3]::int2[]),
    ('thread_history_clear_batches_operation_fkey','f',ARRAY[1]::int2[]),
    ('thread_history_clear_batches_sequence_check','c',ARRAY[2]::int2[]),
    ('thread_history_clear_batches_time_check','c',ARRAY[4]::int2[]),
    ('thread_history_clear_batches_counts_check','c',ARRAY[5,6,7,8,9,10,11,12,13,14]::int2[]),
    ('thread_history_clear_completions_pkey','p',ARRAY[1]::int2[]),
    ('thread_history_clear_completions_thread_key','u',ARRAY[2,3,4]::int2[]),
    ('thread_history_clear_completions_operation_fkey','f',ARRAY[1]::int2[]),
    ('thread_history_clear_completions_schema_check','c',ARRAY[5]::int2[]),
    ('thread_history_clear_completions_source_check','c',ARRAY[6]::int2[]),
    ('thread_history_clear_completions_time_check','c',ARRAY[7]::int2[]),
    ('thread_history_clear_completions_identity_check','c',ARRAY[2,3,4]::int2[]),
    ('thread_history_clear_completions_counts_check','c',ARRAY[8,9,10,11,12,13,14,15,16,17,18]::int2[])
   ) SELECT 1 FROM expected e LEFT JOIN pg_catalog.pg_constraint c ON c.conrelid=v_oid AND c.conname=e.name
    WHERE pg_catalog.left(e.name,pg_catalog.length(v_name)+1)=v_name||'_' AND
     (c.oid IS NULL OR c.contype::text IS DISTINCT FROM e.type_bits OR c.conkey IS DISTINCT FROM e.keys OR
      NOT c.conislocal OR c.coninhcount<>0 OR c.connoinherit IS DISTINCT FROM (c.contype<>'c') OR
      (c.contype='f' AND (c.confrelid IS DISTINCT FROM 'openbot_internal.thread_history_clear_intents'::regclass::oid OR
       c.confkey IS DISTINCT FROM ARRAY[6]::int2[] OR c.confupdtype<>'r' OR c.confdeltype<>'r' OR c.confmatchtype<>'s')))
  ) OR EXISTS(SELECT 1 FROM pg_catalog.pg_attrdef d JOIN pg_catalog.pg_attribute a
       ON a.attrelid=d.adrelid AND a.attnum=d.adnum WHERE d.adrelid=v_oid AND
      pg_catalog.pg_get_expr(d.adbin,d.adrelid) IS DISTINCT FROM CASE a.attname
       WHEN 'xact_id' THEN 'pg_current_xact_id()' WHEN 'recorded_at' THEN 'clock_timestamp()'
       WHEN 'completed_at' THEN 'clock_timestamp()' ELSE NULL END) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_schema_invalid';
  END IF;
  IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid=v_oid AND NOT tgisinternal)<>
      CASE v_name WHEN 'thread_history_clear_batches' THEN 2 ELSE 3 END OR
     EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=v_oid AND NOT tgisinternal AND
      (tgenabled<>'O' OR tgnargs<>0 OR tgargs<>''::bytea OR tgqual IS NOT NULL)) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_schema_invalid';
  END IF;
  IF EXISTS(
   WITH expected(name,type_bits,function_name,deferred) AS (VALUES
    ('thread_history_clear_batches_guard',31,'guard_thread_history_clear_fact',false),
    ('thread_history_clear_batches_no_truncate',34,'guard_thread_history_clear_fact',false),
    ('thread_history_clear_completions_guard',31,'guard_thread_history_clear_fact',false),
    ('thread_history_clear_completions_no_truncate',34,'guard_thread_history_clear_fact',false),
    ('thread_history_clear_completions_require_final',5,'require_thread_history_clear_completion',true)
   ) SELECT 1 FROM expected e LEFT JOIN pg_catalog.pg_trigger t ON t.tgrelid=v_oid AND t.tgname=e.name
    LEFT JOIN pg_catalog.pg_proc f ON f.oid=t.tgfoid LEFT JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace
    WHERE pg_catalog.left(e.name,pg_catalog.length(v_name)+1)=v_name||'_' AND (t.oid IS NULL OR t.tgtype IS DISTINCT FROM e.type_bits OR
     f.proname IS DISTINCT FROM e.function_name OR n.nspname IS DISTINCT FROM 'openbot_internal' OR
     t.tgdeferrable IS DISTINCT FROM e.deferred OR t.tginitdeferred IS DISTINCT FROM e.deferred OR
     (t.tgconstraint<>0) IS DISTINCT FROM e.deferred)
  ) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_schema_invalid';END IF;
 END LOOP;
 FOREACH v_name IN ARRAY ARRAY['guard_thread_history_clear_fact','thread_history_clear_batch_active',
   'thread_history_clear_event_payload','require_thread_history_clear_completion','thread_history_clear_readers_quiescent',
   'require_thread_history_maintenance_source','thread_history_clear_bodies_erased',
   'thread_history_lock_joint','guard_thread_history_body','guard_thread_history_memory_body','thread_history_validate_terminal_run'] LOOP
  SELECT p.* INTO v_row FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname='openbot_internal' AND p.proname=v_name;
  IF NOT FOUND OR (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='openbot_internal' AND p.proname=v_name)<>1 OR
     v_row.proowner IS DISTINCT FROM v_owner OR v_row.prosecdef OR v_row.proleakproof OR
     v_row.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, openbot_internal']::text[] OR
     EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(v_row.proacl,pg_catalog.acldefault('f',v_owner))) a
       WHERE a.grantee<>v_owner OR a.grantor<>v_owner OR a.is_grantable) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_schema_invalid';
  END IF;
  IF EXISTS(
   WITH expected(name,argument_types,return_type,language,volatility,parallelism) AS (VALUES
    ('guard_thread_history_clear_fact',ARRAY[]::oid[],'pg_catalog.trigger'::regtype::oid,'plpgsql','v','u'),
    ('thread_history_clear_batch_active',ARRAY[25]::oid[],16::oid,'sql','v','u'),
    ('thread_history_clear_event_payload',ARRAY[25,3802,25]::oid[],3802::oid,'plpgsql','i','s'),
    ('require_thread_history_clear_completion',ARRAY[]::oid[],'pg_catalog.trigger'::regtype::oid,'plpgsql','v','u'),
    ('thread_history_clear_readers_quiescent',ARRAY[25]::oid[],16::oid,'plpgsql','v','u'),
    ('require_thread_history_maintenance_source',ARRAY[]::oid[],'pg_catalog.trigger'::regtype::oid,'plpgsql','v','u'),
    ('thread_history_clear_bodies_erased',ARRAY[25]::oid[],16::oid,'plpgsql','v','u'),
    ('thread_history_lock_joint',ARRAY[25,25]::oid[],16::oid,'plpgsql','v','u'),
    ('guard_thread_history_body',ARRAY[]::oid[],'pg_catalog.trigger'::regtype::oid,'plpgsql','v','u'),
    ('guard_thread_history_memory_body',ARRAY[]::oid[],'pg_catalog.trigger'::regtype::oid,'plpgsql','v','u'),
    ('thread_history_validate_terminal_run',ARRAY[25,16]::oid[],'pg_catalog.void'::regtype::oid,'plpgsql','v','u')
   ) SELECT 1 FROM expected e JOIN pg_catalog.pg_language l ON l.oid=v_row.prolang
    WHERE e.name=v_name AND (ARRAY(SELECT x FROM pg_catalog.unnest(v_row.proargtypes::oid[]) x) IS DISTINCT FROM e.argument_types OR
     v_row.prorettype IS DISTINCT FROM e.return_type OR l.lanname IS DISTINCT FROM e.language OR
     v_row.provolatile::text IS DISTINCT FROM e.volatility OR v_row.proparallel::text IS DISTINCT FROM e.parallelism OR
     v_row.prokind<>'f' OR v_row.proisstrict OR v_row.proretset OR v_row.procost<>100 OR v_row.prorows<>0 OR
     v_row.pronargs<>pg_catalog.cardinality(e.argument_types) OR v_row.pronargdefaults<>0 OR
     v_row.provariadic<>0 OR v_row.prosupport<>0 OR v_row.proallargtypes IS NOT NULL OR
     v_row.proargmodes IS NOT NULL OR v_row.proargdefaults IS NOT NULL OR v_row.protrftypes IS NOT NULL OR
     v_row.probin IS NOT NULL OR v_row.prosqlbody IS NOT NULL)
  ) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_schema_invalid';END IF;
 END LOOP;
 -- The new admission trigger and the original 0037 provenance trigger are the
 -- complete current memories trigger set. No original public function ACL changes.
 IF (SELECT count(*) FROM pg_catalog.pg_trigger
     WHERE tgrelid='public.memories'::regclass AND NOT tgisinternal)<>2 OR EXISTS(
   WITH expected(name,type_bits,function_schema,function_name) AS (VALUES
    ('memories_history_body_before',23,'openbot_internal','guard_thread_history_memory_body'),
    ('memory_provenance_immutable',19,'public','guard_memory_provenance')
   ) SELECT 1 FROM expected e LEFT JOIN pg_catalog.pg_trigger t
      ON t.tgrelid='public.memories'::regclass AND t.tgname=e.name
    LEFT JOIN pg_catalog.pg_proc f ON f.oid=t.tgfoid LEFT JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace
    WHERE t.oid IS NULL OR t.tgtype IS DISTINCT FROM e.type_bits OR t.tgenabled<>'O' OR
     t.tgnargs<>0 OR t.tgargs<>''::bytea OR t.tgqual IS NOT NULL OR t.tgattr<>''::int2vector OR
     t.tgdeferrable OR t.tginitdeferred OR t.tgconstraint<>0 OR t.tgoldtable IS NOT NULL OR t.tgnewtable IS NOT NULL OR
     f.proname IS DISTINCT FROM e.function_name OR n.nspname IS DISTINCT FROM e.function_schema OR
     f.proowner IS DISTINCT FROM v_owner
  ) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_schema_invalid';END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conrelid='public.component_human_decisions'::regclass
      AND conname='component_human_decisions_answer_shape' AND contype='c' AND convalidated) OR
    NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conrelid='openbot_internal.thread_history_clear_intents'::regclass
      AND conname='thread_history_clear_intents_kind_check' AND contype='c' AND convalidated) OR
    NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint
    WHERE conrelid='openbot_internal.thread_history_clear_intents'::regclass
      AND conname='thread_history_clear_intents_maintenance_actor_check' AND contype='c' AND convalidated) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_clear_schema_invalid';
 END IF;
END;
$clear_postcondition$;
