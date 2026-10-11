-- PRIVATE DRAFT ONLY / authorGO false / NOTRUN.
-- native0050: durable same-J state and prospective Thread identity retention.
-- No body-writer closure, public close producer, deletion action, ACK or Ready.
DO $thread_history_owner$
DECLARE v_owner pg_catalog.oid; v_role pg_catalog.oid;
BEGIN
 SELECT c.relowner INTO v_owner FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname='threads' AND c.relkind='r';
 SELECT oid INTO v_role FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER;
 IF v_owner IS NULL OR v_role IS DISTINCT FROM v_owner OR
    NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='openbot_internal' AND nspowner=v_owner) OR
    NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
               WHERE n.nspname='openbot_internal' AND c.relname='schema_migrations' AND c.relkind='r' AND c.relowner=v_owner) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
 END IF;
END;
$thread_history_owner$;
CREATE TABLE openbot_internal.thread_history_heads (
 deployment_id text COLLATE pg_catalog."C" NOT NULL,
 tenant_id text COLLATE pg_catalog."C" NOT NULL,
 thread_id text COLLATE pg_catalog."C" NOT NULL,
 head_schema smallint NOT NULL,
 phase text COLLATE pg_catalog."C" NOT NULL,
 anchor_kind text COLLATE pg_catalog."C" NOT NULL,
 anchor_id text COLLATE pg_catalog."C" NOT NULL,
 thread_created_at timestamp with time zone NOT NULL,
 recorded_at timestamp with time zone DEFAULT pg_catalog.clock_timestamp() NOT NULL,
 closure_operation_id text COLLATE pg_catalog."C",
 closure_request_id text COLLATE pg_catalog."C",
 closure_actor_id text COLLATE pg_catalog."C",
 closure_auth_generation bigint,
 closed_at timestamp with time zone,
 CONSTRAINT thread_history_heads_pkey PRIMARY KEY(deployment_id,tenant_id,thread_id),
 CONSTRAINT thread_history_heads_thread_id_key UNIQUE(thread_id),
 CONSTRAINT thread_history_heads_base_key UNIQUE(deployment_id,tenant_id,thread_id,anchor_kind,anchor_id,thread_created_at),
 CONSTRAINT thread_history_heads_identity_check CHECK(
  pg_catalog.octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(thread_id) BETWEEN 1 AND 512 AND thread_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(anchor_id) BETWEEN 1 AND 512 AND anchor_id !~ U&'[\0001-\001F\007F-\009F]'),
 CONSTRAINT thread_history_heads_schema_check CHECK(head_schema=1),
 CONSTRAINT thread_history_heads_anchor_check CHECK(anchor_kind IN('direct_bot','channel')),
 CONSTRAINT thread_history_heads_phase_check CHECK(phase IN('open','closed')),
 CONSTRAINT thread_history_heads_time_check CHECK(pg_catalog.isfinite(thread_created_at) AND pg_catalog.isfinite(recorded_at)
  AND (closed_at IS NULL OR pg_catalog.isfinite(closed_at))),
 CONSTRAINT thread_history_heads_closure_shape_check CHECK(
  (phase='open' AND closure_operation_id IS NULL AND closure_request_id IS NULL AND closure_actor_id IS NULL AND closure_auth_generation IS NULL AND closed_at IS NULL) OR
  (phase='closed' AND closure_operation_id IS NOT NULL AND closure_request_id IS NOT NULL AND closure_actor_id IS NOT NULL AND closure_auth_generation IS NOT NULL AND closed_at IS NOT NULL)),
 CONSTRAINT thread_history_heads_closure_identity_check CHECK(closure_operation_id IS NULL OR (
  closure_operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' AND
  closure_request_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' AND
  pg_catalog.octet_length(closure_actor_id) BETWEEN 1 AND 512 AND closure_actor_id !~ U&'[\0001-\001F\007F-\009F]')),
 CONSTRAINT thread_history_heads_closure_generation_check CHECK(closure_auth_generation IS NULL OR closure_auth_generation>=0)
);
CREATE TABLE openbot_internal.thread_history_clear_intents (
 deployment_id text COLLATE pg_catalog."C" NOT NULL,
 tenant_id text COLLATE pg_catalog."C" NOT NULL,
 thread_id text COLLATE pg_catalog."C" NOT NULL,
 intent_schema smallint NOT NULL,
 intent_kind text COLLATE pg_catalog."C" NOT NULL,
 operation_id text COLLATE pg_catalog."C" NOT NULL,
 request_id text COLLATE pg_catalog."C" NOT NULL,
 actor_id text COLLATE pg_catalog."C" NOT NULL,
 auth_generation bigint NOT NULL,
 anchor_kind text COLLATE pg_catalog."C" NOT NULL,
 anchor_id text COLLATE pg_catalog."C" NOT NULL,
 thread_created_at timestamp with time zone NOT NULL,
 recorded_at timestamp with time zone DEFAULT pg_catalog.clock_timestamp() NOT NULL,
 CONSTRAINT thread_history_clear_intents_pkey PRIMARY KEY(operation_id),
 CONSTRAINT thread_history_clear_intents_thread_key UNIQUE(deployment_id,tenant_id,thread_id),
 CONSTRAINT thread_history_clear_intents_request_key UNIQUE(deployment_id,tenant_id,request_id),
 CONSTRAINT thread_history_clear_intents_closed_binding_key UNIQUE(deployment_id,tenant_id,thread_id,operation_id,request_id,actor_id,auth_generation,anchor_kind,anchor_id,thread_created_at,recorded_at),
 CONSTRAINT thread_history_clear_intents_identity_check CHECK(
  pg_catalog.octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(thread_id) BETWEEN 1 AND 512 AND thread_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(actor_id) BETWEEN 1 AND 512 AND actor_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(anchor_id) BETWEEN 1 AND 512 AND anchor_id !~ U&'[\0001-\001F\007F-\009F]'),
 CONSTRAINT thread_history_clear_intents_schema_check CHECK(intent_schema=1),
 CONSTRAINT thread_history_clear_intents_kind_check CHECK(intent_kind='stop_clear'),
 CONSTRAINT thread_history_clear_intents_anchor_check CHECK(anchor_kind IN('direct_bot','channel')),
 CONSTRAINT thread_history_clear_intents_uuid_check CHECK(
  operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' AND
  request_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
 CONSTRAINT thread_history_clear_intents_generation_check CHECK(auth_generation>=0),
 CONSTRAINT thread_history_clear_intents_time_check CHECK(pg_catalog.isfinite(thread_created_at) AND pg_catalog.isfinite(recorded_at))
);
ALTER TABLE openbot_internal.thread_history_clear_intents
 ADD CONSTRAINT thread_history_clear_intents_head_base_fkey
 FOREIGN KEY(deployment_id,tenant_id,thread_id,anchor_kind,anchor_id,thread_created_at)
 REFERENCES openbot_internal.thread_history_heads(deployment_id,tenant_id,thread_id,anchor_kind,anchor_id,thread_created_at)
 MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE openbot_internal.thread_history_heads
 ADD CONSTRAINT thread_history_heads_closed_intent_fkey
 FOREIGN KEY(deployment_id,tenant_id,thread_id,closure_operation_id,closure_request_id,closure_actor_id,closure_auth_generation,anchor_kind,anchor_id,thread_created_at,closed_at)
 REFERENCES openbot_internal.thread_history_clear_intents(deployment_id,tenant_id,thread_id,operation_id,request_id,actor_id,auth_generation,anchor_kind,anchor_id,thread_created_at,recorded_at)
 MATCH SIMPLE ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED;

-- Seven function bodies below are copied exactly from the independent pre-product contract.
-- Their Root adoption remains pending; they are not candidate-derived expected.
CREATE FUNCTION openbot_internal.bind_thread_history_head_on_insert() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE v_base public.threads%ROWTYPE;
 v_head openbot_internal.thread_history_heads%ROWTYPE;
 v_base_found boolean;
 v_inserted text;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'threads' OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';
 END IF;
 SELECT t.* INTO v_base FROM public.threads t WHERE t.thread_id=NEW.thread_id FOR SHARE OF t;
 v_base_found:=FOUND;
 IF v_base_found THEN
  IF ROW(v_base.deployment_id,v_base.tenant_id,v_base.thread_id,v_base.anchor_kind,v_base.anchor_id,v_base.created_at) IS DISTINCT FROM ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id,NEW.anchor_kind,NEW.anchor_id,NEW.created_at) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';
  END IF;
  INSERT INTO openbot_internal.thread_history_heads (deployment_id,tenant_id,thread_id,head_schema,phase,anchor_kind,anchor_id,thread_created_at) VALUES (v_base.deployment_id,v_base.tenant_id,v_base.thread_id,1,'open',v_base.anchor_kind,v_base.anchor_id,v_base.created_at) ON CONFLICT(thread_id) DO NOTHING;
  SELECT h.* INTO v_head FROM openbot_internal.thread_history_heads h
   WHERE h.thread_id=NEW.thread_id FOR SHARE OF h;
  IF NOT FOUND OR ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(v_base.deployment_id,v_base.tenant_id,v_base.thread_id,v_base.anchor_kind,v_base.anchor_id,v_base.created_at) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';
  END IF;
  RETURN NEW;
 END IF;
 IF EXISTS(SELECT 1 FROM openbot_internal.thread_origins o WHERE o.thread_id=NEW.thread_id) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';
 END IF;
 INSERT INTO openbot_internal.thread_history_heads (deployment_id,tenant_id,thread_id,head_schema,phase,anchor_kind,anchor_id,thread_created_at) VALUES (NEW.deployment_id,NEW.tenant_id,NEW.thread_id,1,'open',NEW.anchor_kind,NEW.anchor_id,NEW.created_at) ON CONFLICT(thread_id) DO NOTHING RETURNING thread_id INTO v_inserted;
 IF v_inserted IS NOT NULL THEN
  RETURN NEW;
 END IF;
 SELECT t.* INTO v_base FROM public.threads t WHERE t.thread_id=NEW.thread_id FOR SHARE OF t;
 IF NOT FOUND THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';
 END IF;
 SELECT h.* INTO v_head FROM openbot_internal.thread_history_heads h
  WHERE h.thread_id=NEW.thread_id FOR SHARE OF h;
 IF NOT FOUND OR ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(v_base.deployment_id,v_base.tenant_id,v_base.thread_id,v_base.anchor_kind,v_base.anchor_id,v_base.created_at)
    OR ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id,NEW.anchor_kind,NEW.anchor_id,NEW.created_at) IS DISTINCT FROM ROW(v_base.deployment_id,v_base.tenant_id,v_base.thread_id,v_base.anchor_kind,v_base.anchor_id,v_base.created_at) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';
 END IF;
 RETURN NEW;
END;
$$;
CREATE FUNCTION openbot_internal.guard_thread_history_head_mutation() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_TABLE_NAME<>'thread_history_heads'
    OR TG_OP NOT IN('UPDATE','DELETE','TRUNCATE') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_mutation_refused';
 END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.phase='open' AND NEW.phase='closed'
     AND ROW(OLD.deployment_id,OLD.tenant_id,OLD.thread_id,OLD.head_schema,OLD.anchor_kind,OLD.anchor_id,OLD.thread_created_at,OLD.recorded_at) IS NOT DISTINCT FROM ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id,NEW.head_schema,NEW.anchor_kind,NEW.anchor_id,NEW.thread_created_at,NEW.recorded_at) THEN
   RETURN NEW;
  END IF;
 END IF;
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_mutation_refused';
END;
$$;
CREATE FUNCTION openbot_internal.prevent_thread_history_base_truncate() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'threads' OR TG_OP<>'TRUNCATE' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';
 END IF;
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';
END;
$$;
CREATE FUNCTION openbot_internal.prevent_thread_history_intent_mutation() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_TABLE_NAME<>'thread_history_clear_intents'
    OR TG_OP NOT IN('UPDATE','DELETE','TRUNCATE') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_mutation_refused';
 END IF;
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_mutation_refused';
END;
$$;
CREATE FUNCTION openbot_internal.protect_thread_history_base_identity() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE v_head openbot_internal.thread_history_heads%ROWTYPE;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'threads' OR TG_OP<>'UPDATE' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';
 END IF;
 IF NEW.thread_id IS DISTINCT FROM OLD.thread_id THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';
 END IF;
 SELECT h.* INTO v_head FROM openbot_internal.thread_history_heads h
  WHERE h.thread_id=OLD.thread_id FOR SHARE OF h;
 IF FOUND AND (ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(OLD.deployment_id,OLD.tenant_id,OLD.thread_id,OLD.anchor_kind,OLD.anchor_id,OLD.created_at)
     OR ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id,NEW.anchor_kind,NEW.anchor_id,NEW.created_at)) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';
 END IF;
 RETURN NEW;
END;
$$;
CREATE FUNCTION openbot_internal.require_thread_history_intent_closed_head() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE v_matches boolean;
BEGIN
 IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_TABLE_NAME<>'thread_history_clear_intents'
    OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';
 END IF;
 SELECT true INTO v_matches FROM openbot_internal.thread_history_heads h
 WHERE h.deployment_id=NEW.deployment_id AND h.tenant_id=NEW.tenant_id
   AND h.thread_id=NEW.thread_id AND h.phase='closed'
   AND h.closure_operation_id=NEW.operation_id AND h.closure_request_id=NEW.request_id
   AND h.closure_actor_id=NEW.actor_id AND h.closure_auth_generation=NEW.auth_generation
   AND h.anchor_kind=NEW.anchor_kind AND h.anchor_id=NEW.anchor_id
   AND h.thread_created_at=NEW.thread_created_at AND h.closed_at=NEW.recorded_at
 FOR SHARE OF h;
 IF v_matches IS DISTINCT FROM true THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';
 END IF;
 RETURN NEW;
END;
$$;
CREATE FUNCTION openbot_internal.retain_thread_history_head_on_delete() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE v_head openbot_internal.thread_history_heads%ROWTYPE;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'threads' OR TG_OP<>'DELETE' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';
 END IF;
 INSERT INTO openbot_internal.thread_history_heads (deployment_id,tenant_id,thread_id,head_schema,phase,anchor_kind,anchor_id,thread_created_at) VALUES (OLD.deployment_id,OLD.tenant_id,OLD.thread_id,1,'open',OLD.anchor_kind,OLD.anchor_id,OLD.created_at) ON CONFLICT(thread_id) DO NOTHING;
 SELECT h.* INTO v_head FROM openbot_internal.thread_history_heads h
  WHERE h.thread_id=OLD.thread_id FOR SHARE OF h;
 IF NOT FOUND OR ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(OLD.deployment_id,OLD.tenant_id,OLD.thread_id,OLD.anchor_kind,OLD.anchor_id,OLD.created_at) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';
 END IF;
 RETURN OLD;
END;
$$;
CREATE TRIGGER thread_history_heads_guard_update_delete BEFORE UPDATE OR DELETE
 ON openbot_internal.thread_history_heads FOR EACH ROW
 EXECUTE FUNCTION openbot_internal.guard_thread_history_head_mutation();
CREATE TRIGGER thread_history_heads_no_truncate BEFORE TRUNCATE
 ON openbot_internal.thread_history_heads FOR EACH STATEMENT
 EXECUTE FUNCTION openbot_internal.guard_thread_history_head_mutation();
CREATE TRIGGER thread_history_clear_intents_no_update_delete BEFORE UPDATE OR DELETE
 ON openbot_internal.thread_history_clear_intents FOR EACH ROW
 EXECUTE FUNCTION openbot_internal.prevent_thread_history_intent_mutation();
CREATE TRIGGER thread_history_clear_intents_no_truncate BEFORE TRUNCATE
 ON openbot_internal.thread_history_clear_intents FOR EACH STATEMENT
 EXECUTE FUNCTION openbot_internal.prevent_thread_history_intent_mutation();
CREATE CONSTRAINT TRIGGER thread_history_clear_intents_require_closed_head AFTER INSERT
 ON openbot_internal.thread_history_clear_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
 EXECUTE FUNCTION openbot_internal.require_thread_history_intent_closed_head();
CREATE TRIGGER threads_history_bind_insert BEFORE INSERT ON public.threads FOR EACH ROW
 EXECUTE FUNCTION openbot_internal.bind_thread_history_head_on_insert();
CREATE TRIGGER threads_history_retain_delete BEFORE DELETE ON public.threads FOR EACH ROW
 EXECUTE FUNCTION openbot_internal.retain_thread_history_head_on_delete();
CREATE TRIGGER threads_history_protect_identity_update
 BEFORE UPDATE OF thread_id,tenant_id,deployment_id,anchor_kind,anchor_id,created_at
 ON public.threads FOR EACH ROW
 EXECUTE FUNCTION openbot_internal.protect_thread_history_base_identity();
CREATE TRIGGER threads_history_no_truncate BEFORE TRUNCATE ON public.threads FOR EACH STATEMENT
 EXECUTE FUNCTION openbot_internal.prevent_thread_history_base_truncate();

-- Pure catalogue postcondition; native journal50 is recorded after this SQL.
DO $thread_history_postcondition$
DECLARE
 v_raw jsonb; v_matches boolean;
 v_schema jsonb; v_acl jsonb; v_raw_acl jsonb; v_state jsonb;
 v_row jsonb; v_col jsonb; v_anchor jsonb; v_table jsonb;
 v_class jsonb; v_collation jsonb; v_index jsonb; v_ref jsonb;
 v_function jsonb; v_constraint jsonb;
 v_pos bigint; v_owner pg_catalog.oid; v_bootstrap pg_catalog.oid;
 v_base pg_catalog.oid; v_role_owner pg_catalog.oid; v_oid pg_catalog.oid;
 v_attr smallint; v_type integer; v_label text; v_key text;
 v_letter text; v_normal_name text; v_prefix text; v_path text[];
 v_expected jsonb := $thread_history_expected${"allowedTableAclStates":[{"aclIsNull":true,"rawAcl":null},{"aclIsNull":false,"rawAcl":[{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"DELETE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"INSERT"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"MAINTAIN"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"REFERENCES"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"SELECT"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"TRIGGER"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"TRUNCATE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"UPDATE"}]}],"format":"thread-history-admission-oracle-v1","schema":{"constraints":[{"columns":[],"deferrable":true,"deferred":true,"definition":"TRIGGER DEFERRABLE INITIALLY DEFERRED","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"t","local":true,"name":"thread_history_clear_intents_require_closed_head","namespace":"openbot_internal","noInherit":true,"reference":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":1,"name":"deployment_id","ordinal":1},{"attributeNumber":2,"name":"tenant_id","ordinal":2},{"attributeNumber":3,"name":"thread_id","ordinal":3},{"attributeNumber":10,"name":"anchor_kind","ordinal":4},{"attributeNumber":11,"name":"anchor_id","ordinal":5},{"attributeNumber":12,"name":"thread_created_at","ordinal":6}],"deferrable":true,"deferred":true,"definition":"FOREIGN KEY (deployment_id, tenant_id, thread_id, anchor_kind, anchor_id, thread_created_at) REFERENCES openbot_internal.thread_history_heads(deployment_id, tenant_id, thread_id, anchor_kind, anchor_id, thread_created_at) DEFERRABLE INITIALLY DEFERRED","foreignEqualityOperators":[{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":1,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":2,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":3,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":4,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":5,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"timestamp with time zone, timestamp with time zone","name":"timestamptz_eq","schema":"pg_catalog"},"leftType":"timestamp with time zone","name":"=","ordinal":6,"resultType":"boolean","rightType":"timestamp with time zone","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":1,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":2,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":3,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":4,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":5,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"timestamp with time zone, timestamp with time zone","name":"timestamptz_eq","schema":"pg_catalog"},"leftType":"timestamp with time zone","name":"=","ordinal":6,"resultType":"boolean","rightType":"timestamp with time zone","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":1,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":2,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":3,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":4,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":5,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"timestamp with time zone, timestamp with time zone","name":"timestamptz_eq","schema":"pg_catalog"},"leftType":"timestamp with time zone","name":"=","ordinal":6,"resultType":"boolean","rightType":"timestamp with time zone","schema":"pg_catalog"}],"hasParent":false,"inheritanceCount":0,"kind":"f","local":true,"name":"thread_history_clear_intents_head_base_fkey","namespace":"openbot_internal","noInherit":true,"reference":{"columns":[{"attributeNumber":1,"name":"deployment_id","ordinal":1},{"attributeNumber":2,"name":"tenant_id","ordinal":2},{"attributeNumber":3,"name":"thread_id","ordinal":3},{"attributeNumber":6,"name":"anchor_kind","ordinal":4},{"attributeNumber":7,"name":"anchor_id","ordinal":5},{"attributeNumber":8,"name":"thread_created_at","ordinal":6}],"deleteAction":"a","deleteSetColumns":null,"match":"s","referencedKeys":[{"deferrable":false,"deferred":false,"definition":"UNIQUE (deployment_id, tenant_id, thread_id, anchor_kind, anchor_id, thread_created_at)","kind":"u","name":"thread_history_heads_base_key","validated":true}],"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"updateAction":"a"},"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":{"name":"thread_history_heads_base_key","schema":"openbot_internal"},"validated":true},{"columns":[{"attributeNumber":1,"name":"deployment_id","ordinal":1},{"attributeNumber":2,"name":"tenant_id","ordinal":2},{"attributeNumber":3,"name":"thread_id","ordinal":3},{"attributeNumber":10,"name":"closure_operation_id","ordinal":4},{"attributeNumber":11,"name":"closure_request_id","ordinal":5},{"attributeNumber":12,"name":"closure_actor_id","ordinal":6},{"attributeNumber":13,"name":"closure_auth_generation","ordinal":7},{"attributeNumber":6,"name":"anchor_kind","ordinal":8},{"attributeNumber":7,"name":"anchor_id","ordinal":9},{"attributeNumber":8,"name":"thread_created_at","ordinal":10},{"attributeNumber":14,"name":"closed_at","ordinal":11}],"deferrable":true,"deferred":true,"definition":"FOREIGN KEY (deployment_id, tenant_id, thread_id, closure_operation_id, closure_request_id, closure_actor_id, closure_auth_generation, anchor_kind, anchor_id, thread_created_at, closed_at) REFERENCES openbot_internal.thread_history_clear_intents(deployment_id, tenant_id, thread_id, operation_id, request_id, actor_id, auth_generation, anchor_kind, anchor_id, thread_created_at, recorded_at) DEFERRABLE INITIALLY DEFERRED","foreignEqualityOperators":[{"family":"fkFk","function":{"arguments":"bigint, bigint","name":"int8eq","schema":"pg_catalog"},"leftType":"bigint","name":"=","ordinal":7,"resultType":"boolean","rightType":"bigint","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":1,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":2,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":3,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":4,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":5,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":6,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":8,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":9,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"timestamp with time zone, timestamp with time zone","name":"timestamptz_eq","schema":"pg_catalog"},"leftType":"timestamp with time zone","name":"=","ordinal":10,"resultType":"boolean","rightType":"timestamp with time zone","schema":"pg_catalog"},{"family":"fkFk","function":{"arguments":"timestamp with time zone, timestamp with time zone","name":"timestamptz_eq","schema":"pg_catalog"},"leftType":"timestamp with time zone","name":"=","ordinal":11,"resultType":"boolean","rightType":"timestamp with time zone","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"bigint, bigint","name":"int8eq","schema":"pg_catalog"},"leftType":"bigint","name":"=","ordinal":7,"resultType":"boolean","rightType":"bigint","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":1,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":2,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":3,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":4,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":5,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":6,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":8,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":9,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"timestamp with time zone, timestamp with time zone","name":"timestamptz_eq","schema":"pg_catalog"},"leftType":"timestamp with time zone","name":"=","ordinal":10,"resultType":"boolean","rightType":"timestamp with time zone","schema":"pg_catalog"},{"family":"pkFk","function":{"arguments":"timestamp with time zone, timestamp with time zone","name":"timestamptz_eq","schema":"pg_catalog"},"leftType":"timestamp with time zone","name":"=","ordinal":11,"resultType":"boolean","rightType":"timestamp with time zone","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"bigint, bigint","name":"int8eq","schema":"pg_catalog"},"leftType":"bigint","name":"=","ordinal":7,"resultType":"boolean","rightType":"bigint","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":1,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":2,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":3,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":4,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":5,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":6,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":8,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"text, text","name":"texteq","schema":"pg_catalog"},"leftType":"text","name":"=","ordinal":9,"resultType":"boolean","rightType":"text","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"timestamp with time zone, timestamp with time zone","name":"timestamptz_eq","schema":"pg_catalog"},"leftType":"timestamp with time zone","name":"=","ordinal":10,"resultType":"boolean","rightType":"timestamp with time zone","schema":"pg_catalog"},{"family":"pkPk","function":{"arguments":"timestamp with time zone, timestamp with time zone","name":"timestamptz_eq","schema":"pg_catalog"},"leftType":"timestamp with time zone","name":"=","ordinal":11,"resultType":"boolean","rightType":"timestamp with time zone","schema":"pg_catalog"}],"hasParent":false,"inheritanceCount":0,"kind":"f","local":true,"name":"thread_history_heads_closed_intent_fkey","namespace":"openbot_internal","noInherit":true,"reference":{"columns":[{"attributeNumber":1,"name":"deployment_id","ordinal":1},{"attributeNumber":2,"name":"tenant_id","ordinal":2},{"attributeNumber":3,"name":"thread_id","ordinal":3},{"attributeNumber":6,"name":"operation_id","ordinal":4},{"attributeNumber":7,"name":"request_id","ordinal":5},{"attributeNumber":8,"name":"actor_id","ordinal":6},{"attributeNumber":9,"name":"auth_generation","ordinal":7},{"attributeNumber":10,"name":"anchor_kind","ordinal":8},{"attributeNumber":11,"name":"anchor_id","ordinal":9},{"attributeNumber":12,"name":"thread_created_at","ordinal":10},{"attributeNumber":13,"name":"recorded_at","ordinal":11}],"deleteAction":"a","deleteSetColumns":null,"match":"s","referencedKeys":[{"deferrable":false,"deferred":false,"definition":"UNIQUE (deployment_id, tenant_id, thread_id, operation_id, request_id, actor_id, auth_generation, anchor_kind, anchor_id, thread_created_at, recorded_at)","kind":"u","name":"thread_history_clear_intents_closed_binding_key","validated":true}],"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"updateAction":"a"},"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"supportingIndex":{"name":"thread_history_clear_intents_closed_binding_key","schema":"openbot_internal"},"validated":true},{"columns":[{"attributeNumber":1,"name":"deployment_id","ordinal":1},{"attributeNumber":2,"name":"tenant_id","ordinal":2},{"attributeNumber":3,"name":"thread_id","ordinal":3},{"attributeNumber":6,"name":"anchor_kind","ordinal":4},{"attributeNumber":7,"name":"anchor_id","ordinal":5},{"attributeNumber":8,"name":"thread_created_at","ordinal":6}],"deferrable":false,"deferred":false,"definition":"UNIQUE (deployment_id, tenant_id, thread_id, anchor_kind, anchor_id, thread_created_at)","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"u","local":true,"name":"thread_history_heads_base_key","namespace":"openbot_internal","noInherit":true,"reference":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"supportingIndex":{"name":"thread_history_heads_base_key","schema":"openbot_internal"},"validated":true},{"columns":[{"attributeNumber":1,"name":"deployment_id","ordinal":1},{"attributeNumber":2,"name":"tenant_id","ordinal":2},{"attributeNumber":3,"name":"thread_id","ordinal":3},{"attributeNumber":6,"name":"operation_id","ordinal":4},{"attributeNumber":7,"name":"request_id","ordinal":5},{"attributeNumber":8,"name":"actor_id","ordinal":6},{"attributeNumber":9,"name":"auth_generation","ordinal":7},{"attributeNumber":10,"name":"anchor_kind","ordinal":8},{"attributeNumber":11,"name":"anchor_id","ordinal":9},{"attributeNumber":12,"name":"thread_created_at","ordinal":10},{"attributeNumber":13,"name":"recorded_at","ordinal":11}],"deferrable":false,"deferred":false,"definition":"UNIQUE (deployment_id, tenant_id, thread_id, operation_id, request_id, actor_id, auth_generation, anchor_kind, anchor_id, thread_created_at, recorded_at)","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"u","local":true,"name":"thread_history_clear_intents_closed_binding_key","namespace":"openbot_internal","noInherit":true,"reference":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":{"name":"thread_history_clear_intents_closed_binding_key","schema":"openbot_internal"},"validated":true},{"columns":[{"attributeNumber":1,"name":"deployment_id","ordinal":1},{"attributeNumber":2,"name":"tenant_id","ordinal":2},{"attributeNumber":3,"name":"thread_id","ordinal":3},{"attributeNumber":7,"name":"anchor_id","ordinal":4}],"deferrable":false,"deferred":false,"definition":"CHECK ((((octet_length(deployment_id) >= 1) AND (octet_length(deployment_id) <= 512)) AND (deployment_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND ((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 512)) AND (tenant_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND ((octet_length(thread_id) >= 1) AND (octet_length(thread_id) <= 512)) AND (thread_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND ((octet_length(anchor_id) >= 1) AND (octet_length(anchor_id) <= 512)) AND (anchor_id !~ '[\u0001-\u001f\u007f-\u009f]'::text)))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_heads_identity_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":1,"name":"deployment_id","ordinal":1},{"attributeNumber":2,"name":"tenant_id","ordinal":2},{"attributeNumber":3,"name":"thread_id","ordinal":3},{"attributeNumber":8,"name":"actor_id","ordinal":4},{"attributeNumber":11,"name":"anchor_id","ordinal":5}],"deferrable":false,"deferred":false,"definition":"CHECK ((((octet_length(deployment_id) >= 1) AND (octet_length(deployment_id) <= 512)) AND (deployment_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND ((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 512)) AND (tenant_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND ((octet_length(thread_id) >= 1) AND (octet_length(thread_id) <= 512)) AND (thread_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND ((octet_length(actor_id) >= 1) AND (octet_length(actor_id) <= 512)) AND (actor_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND ((octet_length(anchor_id) >= 1) AND (octet_length(anchor_id) <= 512)) AND (anchor_id !~ '[\u0001-\u001f\u007f-\u009f]'::text)))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_clear_intents_identity_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":1,"name":"deployment_id","ordinal":1},{"attributeNumber":2,"name":"tenant_id","ordinal":2},{"attributeNumber":3,"name":"thread_id","ordinal":3}],"deferrable":false,"deferred":false,"definition":"PRIMARY KEY (deployment_id, tenant_id, thread_id)","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"p","local":true,"name":"thread_history_heads_pkey","namespace":"openbot_internal","noInherit":true,"reference":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"supportingIndex":{"name":"thread_history_heads_pkey","schema":"openbot_internal"},"validated":true},{"columns":[{"attributeNumber":1,"name":"deployment_id","ordinal":1},{"attributeNumber":2,"name":"tenant_id","ordinal":2},{"attributeNumber":3,"name":"thread_id","ordinal":3}],"deferrable":false,"deferred":false,"definition":"UNIQUE (deployment_id, tenant_id, thread_id)","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"u","local":true,"name":"thread_history_clear_intents_thread_key","namespace":"openbot_internal","noInherit":true,"reference":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":{"name":"thread_history_clear_intents_thread_key","schema":"openbot_internal"},"validated":true},{"columns":[{"attributeNumber":1,"name":"deployment_id","ordinal":1},{"attributeNumber":2,"name":"tenant_id","ordinal":2},{"attributeNumber":7,"name":"request_id","ordinal":3}],"deferrable":false,"deferred":false,"definition":"UNIQUE (deployment_id, tenant_id, request_id)","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"u","local":true,"name":"thread_history_clear_intents_request_key","namespace":"openbot_internal","noInherit":true,"reference":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":{"name":"thread_history_clear_intents_request_key","schema":"openbot_internal"},"validated":true},{"columns":[{"attributeNumber":10,"name":"anchor_kind","ordinal":1}],"deferrable":false,"deferred":false,"definition":"CHECK ((anchor_kind = ANY (ARRAY['direct_bot'::text, 'channel'::text])))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_clear_intents_anchor_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":10,"name":"closure_operation_id","ordinal":1},{"attributeNumber":11,"name":"closure_request_id","ordinal":2},{"attributeNumber":12,"name":"closure_actor_id","ordinal":3}],"deferrable":false,"deferred":false,"definition":"CHECK (((closure_operation_id IS NULL) OR ((closure_operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text) AND (closure_request_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text) AND ((octet_length(closure_actor_id) >= 1) AND (octet_length(closure_actor_id) <= 512)) AND (closure_actor_id !~ '[\u0001-\u001f\u007f-\u009f]'::text))))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_heads_closure_identity_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":12,"name":"thread_created_at","ordinal":1},{"attributeNumber":13,"name":"recorded_at","ordinal":2}],"deferrable":false,"deferred":false,"definition":"CHECK ((isfinite(thread_created_at) AND isfinite(recorded_at)))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_clear_intents_time_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":13,"name":"closure_auth_generation","ordinal":1}],"deferrable":false,"deferred":false,"definition":"CHECK (((closure_auth_generation IS NULL) OR (closure_auth_generation >= 0)))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_heads_closure_generation_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":3,"name":"thread_id","ordinal":1}],"deferrable":false,"deferred":false,"definition":"UNIQUE (thread_id)","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"u","local":true,"name":"thread_history_heads_thread_id_key","namespace":"openbot_internal","noInherit":true,"reference":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"supportingIndex":{"name":"thread_history_heads_thread_id_key","schema":"openbot_internal"},"validated":true},{"columns":[{"attributeNumber":4,"name":"head_schema","ordinal":1}],"deferrable":false,"deferred":false,"definition":"CHECK ((head_schema = 1))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_heads_schema_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":4,"name":"intent_schema","ordinal":1}],"deferrable":false,"deferred":false,"definition":"CHECK ((intent_schema = 1))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_clear_intents_schema_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":5,"name":"intent_kind","ordinal":1}],"deferrable":false,"deferred":false,"definition":"CHECK ((intent_kind = 'stop_clear'::text))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_clear_intents_kind_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":5,"name":"phase","ordinal":1},{"attributeNumber":10,"name":"closure_operation_id","ordinal":2},{"attributeNumber":11,"name":"closure_request_id","ordinal":3},{"attributeNumber":12,"name":"closure_actor_id","ordinal":4},{"attributeNumber":13,"name":"closure_auth_generation","ordinal":5},{"attributeNumber":14,"name":"closed_at","ordinal":6}],"deferrable":false,"deferred":false,"definition":"CHECK ((((phase = 'open'::text) AND (closure_operation_id IS NULL) AND (closure_request_id IS NULL) AND (closure_actor_id IS NULL) AND (closure_auth_generation IS NULL) AND (closed_at IS NULL)) OR ((phase = 'closed'::text) AND (closure_operation_id IS NOT NULL) AND (closure_request_id IS NOT NULL) AND (closure_actor_id IS NOT NULL) AND (closure_auth_generation IS NOT NULL) AND (closed_at IS NOT NULL))))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_heads_closure_shape_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":5,"name":"phase","ordinal":1}],"deferrable":false,"deferred":false,"definition":"CHECK ((phase = ANY (ARRAY['open'::text, 'closed'::text])))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_heads_phase_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":6,"name":"anchor_kind","ordinal":1}],"deferrable":false,"deferred":false,"definition":"CHECK ((anchor_kind = ANY (ARRAY['direct_bot'::text, 'channel'::text])))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_heads_anchor_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":6,"name":"operation_id","ordinal":1},{"attributeNumber":7,"name":"request_id","ordinal":2}],"deferrable":false,"deferred":false,"definition":"CHECK (((operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text) AND (request_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text)))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_clear_intents_uuid_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":6,"name":"operation_id","ordinal":1}],"deferrable":false,"deferred":false,"definition":"PRIMARY KEY (operation_id)","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"p","local":true,"name":"thread_history_clear_intents_pkey","namespace":"openbot_internal","noInherit":true,"reference":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":{"name":"thread_history_clear_intents_pkey","schema":"openbot_internal"},"validated":true},{"columns":[{"attributeNumber":8,"name":"thread_created_at","ordinal":1},{"attributeNumber":9,"name":"recorded_at","ordinal":2},{"attributeNumber":14,"name":"closed_at","ordinal":3}],"deferrable":false,"deferred":false,"definition":"CHECK ((isfinite(thread_created_at) AND isfinite(recorded_at) AND ((closed_at IS NULL) OR isfinite(closed_at))))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_heads_time_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":9,"name":"auth_generation","ordinal":1}],"deferrable":false,"deferred":false,"definition":"CHECK ((auth_generation >= 0))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_history_clear_intents_generation_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"supportingIndex":null,"validated":true}],"format":"thread-history-admission-schema-v1","functions":[{"acl":[{"grantable":false,"grantee":"PUBLIC","grantor":"original_pg17_bootstrap_owner","privilege":"EXECUTE"},{"grantable":false,"grantee":"original_pg17_bootstrap_owner","grantor":"original_pg17_bootstrap_owner","privilege":"EXECUTE"}],"aclIsNull":true,"allArgumentTypes":[],"allArgumentTypesIsNull":true,"argumentDefaults":null,"argumentModes":null,"argumentNames":null,"binary":null,"configuration":null,"cost":1,"defaultArgumentCount":0,"definition":"CREATE OR REPLACE FUNCTION pg_catalog.\"RI_FKey_check_ins\"()\n RETURNS trigger\n LANGUAGE internal\n PARALLEL SAFE STRICT\nAS $function$RI_FKey_check_ins$function$\n","identity":{"arguments":"","name":"RI_FKey_check_ins","schema":"pg_catalog"},"inputArgumentCount":0,"inputTypes":[],"isSyncFunction":false,"kind":"f","language":"internal","leakproof":false,"ownerRef":"original_pg17_bootstrap_owner","parallel":"s","rawAcl":null,"returnType":{"formatted":"trigger","name":"trigger","schema":"pg_catalog"},"rows":0,"securityDefiner":false,"setReturning":false,"source":"RI_FKey_check_ins","sqlBody":null,"strict":true,"supportFunction":null,"transformTypes":[],"transformTypesIsNull":true,"variadicType":null,"volatility":"v"},{"acl":[{"grantable":false,"grantee":"PUBLIC","grantor":"original_pg17_bootstrap_owner","privilege":"EXECUTE"},{"grantable":false,"grantee":"original_pg17_bootstrap_owner","grantor":"original_pg17_bootstrap_owner","privilege":"EXECUTE"}],"aclIsNull":true,"allArgumentTypes":[],"allArgumentTypesIsNull":true,"argumentDefaults":null,"argumentModes":null,"argumentNames":null,"binary":null,"configuration":null,"cost":1,"defaultArgumentCount":0,"definition":"CREATE OR REPLACE FUNCTION pg_catalog.\"RI_FKey_check_upd\"()\n RETURNS trigger\n LANGUAGE internal\n PARALLEL SAFE STRICT\nAS $function$RI_FKey_check_upd$function$\n","identity":{"arguments":"","name":"RI_FKey_check_upd","schema":"pg_catalog"},"inputArgumentCount":0,"inputTypes":[],"isSyncFunction":false,"kind":"f","language":"internal","leakproof":false,"ownerRef":"original_pg17_bootstrap_owner","parallel":"s","rawAcl":null,"returnType":{"formatted":"trigger","name":"trigger","schema":"pg_catalog"},"rows":0,"securityDefiner":false,"setReturning":false,"source":"RI_FKey_check_upd","sqlBody":null,"strict":true,"supportFunction":null,"transformTypes":[],"transformTypesIsNull":true,"variadicType":null,"volatility":"v"},{"acl":[{"grantable":false,"grantee":"PUBLIC","grantor":"original_pg17_bootstrap_owner","privilege":"EXECUTE"},{"grantable":false,"grantee":"original_pg17_bootstrap_owner","grantor":"original_pg17_bootstrap_owner","privilege":"EXECUTE"}],"aclIsNull":true,"allArgumentTypes":[],"allArgumentTypesIsNull":true,"argumentDefaults":null,"argumentModes":null,"argumentNames":null,"binary":null,"configuration":null,"cost":1,"defaultArgumentCount":0,"definition":"CREATE OR REPLACE FUNCTION pg_catalog.\"RI_FKey_noaction_del\"()\n RETURNS trigger\n LANGUAGE internal\n PARALLEL SAFE STRICT\nAS $function$RI_FKey_noaction_del$function$\n","identity":{"arguments":"","name":"RI_FKey_noaction_del","schema":"pg_catalog"},"inputArgumentCount":0,"inputTypes":[],"isSyncFunction":false,"kind":"f","language":"internal","leakproof":false,"ownerRef":"original_pg17_bootstrap_owner","parallel":"s","rawAcl":null,"returnType":{"formatted":"trigger","name":"trigger","schema":"pg_catalog"},"rows":0,"securityDefiner":false,"setReturning":false,"source":"RI_FKey_noaction_del","sqlBody":null,"strict":true,"supportFunction":null,"transformTypes":[],"transformTypesIsNull":true,"variadicType":null,"volatility":"v"},{"acl":[{"grantable":false,"grantee":"PUBLIC","grantor":"original_pg17_bootstrap_owner","privilege":"EXECUTE"},{"grantable":false,"grantee":"original_pg17_bootstrap_owner","grantor":"original_pg17_bootstrap_owner","privilege":"EXECUTE"}],"aclIsNull":true,"allArgumentTypes":[],"allArgumentTypesIsNull":true,"argumentDefaults":null,"argumentModes":null,"argumentNames":null,"binary":null,"configuration":null,"cost":1,"defaultArgumentCount":0,"definition":"CREATE OR REPLACE FUNCTION pg_catalog.\"RI_FKey_noaction_upd\"()\n RETURNS trigger\n LANGUAGE internal\n PARALLEL SAFE STRICT\nAS $function$RI_FKey_noaction_upd$function$\n","identity":{"arguments":"","name":"RI_FKey_noaction_upd","schema":"pg_catalog"},"inputArgumentCount":0,"inputTypes":[],"isSyncFunction":false,"kind":"f","language":"internal","leakproof":false,"ownerRef":"original_pg17_bootstrap_owner","parallel":"s","rawAcl":null,"returnType":{"formatted":"trigger","name":"trigger","schema":"pg_catalog"},"rows":0,"securityDefiner":false,"setReturning":false,"source":"RI_FKey_noaction_upd","sqlBody":null,"strict":true,"supportFunction":null,"transformTypes":[],"transformTypesIsNull":true,"variadicType":null,"volatility":"v"},{"acl":[{"grantable":false,"grantee":"PUBLIC","grantor":"original_threads_owner","privilege":"EXECUTE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"EXECUTE"}],"aclIsNull":true,"allArgumentTypes":[],"allArgumentTypesIsNull":true,"argumentDefaults":null,"argumentModes":null,"argumentNames":null,"binary":null,"configuration":null,"cost":100,"defaultArgumentCount":0,"definition":"CREATE OR REPLACE FUNCTION openbot_internal.bind_thread_history_head_on_insert()\n RETURNS trigger\n LANGUAGE plpgsql\nAS $function$\nDECLARE v_base public.threads%ROWTYPE;\n v_head openbot_internal.thread_history_heads%ROWTYPE;\n v_base_found boolean;\n v_inserted text;\nBEGIN\n IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'threads' OR TG_OP<>'INSERT' THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n SELECT t.* INTO v_base FROM public.threads t WHERE t.thread_id=NEW.thread_id FOR SHARE OF t;\n v_base_found:=FOUND;\n IF v_base_found THEN\n  IF ROW(v_base.deployment_id,v_base.tenant_id,v_base.thread_id,v_base.anchor_kind,v_base.anchor_id,v_base.created_at) IS DISTINCT FROM ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id,NEW.anchor_kind,NEW.anchor_id,NEW.created_at) THEN\n   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n  END IF;\n  INSERT INTO openbot_internal.thread_history_heads (deployment_id,tenant_id,thread_id,head_schema,phase,anchor_kind,anchor_id,thread_created_at) VALUES (v_base.deployment_id,v_base.tenant_id,v_base.thread_id,1,'open',v_base.anchor_kind,v_base.anchor_id,v_base.created_at) ON CONFLICT(thread_id) DO NOTHING;\n  SELECT h.* INTO v_head FROM openbot_internal.thread_history_heads h\n   WHERE h.thread_id=NEW.thread_id FOR SHARE OF h;\n  IF NOT FOUND OR ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(v_base.deployment_id,v_base.tenant_id,v_base.thread_id,v_base.anchor_kind,v_base.anchor_id,v_base.created_at) THEN\n   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n  END IF;\n  RETURN NEW;\n END IF;\n IF EXISTS(SELECT 1 FROM openbot_internal.thread_origins o WHERE o.thread_id=NEW.thread_id) THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';\n END IF;\n INSERT INTO openbot_internal.thread_history_heads (deployment_id,tenant_id,thread_id,head_schema,phase,anchor_kind,anchor_id,thread_created_at) VALUES (NEW.deployment_id,NEW.tenant_id,NEW.thread_id,1,'open',NEW.anchor_kind,NEW.anchor_id,NEW.created_at) ON CONFLICT(thread_id) DO NOTHING RETURNING thread_id INTO v_inserted;\n IF v_inserted IS NOT NULL THEN\n  RETURN NEW;\n END IF;\n SELECT t.* INTO v_base FROM public.threads t WHERE t.thread_id=NEW.thread_id FOR SHARE OF t;\n IF NOT FOUND THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';\n END IF;\n SELECT h.* INTO v_head FROM openbot_internal.thread_history_heads h\n  WHERE h.thread_id=NEW.thread_id FOR SHARE OF h;\n IF NOT FOUND OR ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(v_base.deployment_id,v_base.tenant_id,v_base.thread_id,v_base.anchor_kind,v_base.anchor_id,v_base.created_at)\n    OR ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id,NEW.anchor_kind,NEW.anchor_id,NEW.created_at) IS DISTINCT FROM ROW(v_base.deployment_id,v_base.tenant_id,v_base.thread_id,v_base.anchor_kind,v_base.anchor_id,v_base.created_at) THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n RETURN NEW;\nEND;\n$function$\n","identity":{"arguments":"","name":"bind_thread_history_head_on_insert","schema":"openbot_internal"},"inputArgumentCount":0,"inputTypes":[],"isSyncFunction":false,"kind":"f","language":"plpgsql","leakproof":false,"ownerRef":"original_threads_owner","parallel":"u","rawAcl":null,"returnType":{"formatted":"trigger","name":"trigger","schema":"pg_catalog"},"rows":0,"securityDefiner":false,"setReturning":false,"source":"\nDECLARE v_base public.threads%ROWTYPE;\n v_head openbot_internal.thread_history_heads%ROWTYPE;\n v_base_found boolean;\n v_inserted text;\nBEGIN\n IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'threads' OR TG_OP<>'INSERT' THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n SELECT t.* INTO v_base FROM public.threads t WHERE t.thread_id=NEW.thread_id FOR SHARE OF t;\n v_base_found:=FOUND;\n IF v_base_found THEN\n  IF ROW(v_base.deployment_id,v_base.tenant_id,v_base.thread_id,v_base.anchor_kind,v_base.anchor_id,v_base.created_at) IS DISTINCT FROM ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id,NEW.anchor_kind,NEW.anchor_id,NEW.created_at) THEN\n   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n  END IF;\n  INSERT INTO openbot_internal.thread_history_heads (deployment_id,tenant_id,thread_id,head_schema,phase,anchor_kind,anchor_id,thread_created_at) VALUES (v_base.deployment_id,v_base.tenant_id,v_base.thread_id,1,'open',v_base.anchor_kind,v_base.anchor_id,v_base.created_at) ON CONFLICT(thread_id) DO NOTHING;\n  SELECT h.* INTO v_head FROM openbot_internal.thread_history_heads h\n   WHERE h.thread_id=NEW.thread_id FOR SHARE OF h;\n  IF NOT FOUND OR ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(v_base.deployment_id,v_base.tenant_id,v_base.thread_id,v_base.anchor_kind,v_base.anchor_id,v_base.created_at) THEN\n   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n  END IF;\n  RETURN NEW;\n END IF;\n IF EXISTS(SELECT 1 FROM openbot_internal.thread_origins o WHERE o.thread_id=NEW.thread_id) THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';\n END IF;\n INSERT INTO openbot_internal.thread_history_heads (deployment_id,tenant_id,thread_id,head_schema,phase,anchor_kind,anchor_id,thread_created_at) VALUES (NEW.deployment_id,NEW.tenant_id,NEW.thread_id,1,'open',NEW.anchor_kind,NEW.anchor_id,NEW.created_at) ON CONFLICT(thread_id) DO NOTHING RETURNING thread_id INTO v_inserted;\n IF v_inserted IS NOT NULL THEN\n  RETURN NEW;\n END IF;\n SELECT t.* INTO v_base FROM public.threads t WHERE t.thread_id=NEW.thread_id FOR SHARE OF t;\n IF NOT FOUND THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';\n END IF;\n SELECT h.* INTO v_head FROM openbot_internal.thread_history_heads h\n  WHERE h.thread_id=NEW.thread_id FOR SHARE OF h;\n IF NOT FOUND OR ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(v_base.deployment_id,v_base.tenant_id,v_base.thread_id,v_base.anchor_kind,v_base.anchor_id,v_base.created_at)\n    OR ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id,NEW.anchor_kind,NEW.anchor_id,NEW.created_at) IS DISTINCT FROM ROW(v_base.deployment_id,v_base.tenant_id,v_base.thread_id,v_base.anchor_kind,v_base.anchor_id,v_base.created_at) THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n RETURN NEW;\nEND;\n","sqlBody":null,"strict":false,"supportFunction":null,"transformTypes":[],"transformTypesIsNull":true,"variadicType":null,"volatility":"v"},{"acl":[{"grantable":false,"grantee":"PUBLIC","grantor":"original_threads_owner","privilege":"EXECUTE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"EXECUTE"}],"aclIsNull":true,"allArgumentTypes":[],"allArgumentTypesIsNull":true,"argumentDefaults":null,"argumentModes":null,"argumentNames":null,"binary":null,"configuration":null,"cost":100,"defaultArgumentCount":0,"definition":"CREATE OR REPLACE FUNCTION openbot_internal.guard_thread_history_head_mutation()\n RETURNS trigger\n LANGUAGE plpgsql\nAS $function$\nBEGIN\n IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_TABLE_NAME<>'thread_history_heads'\n    OR TG_OP NOT IN('UPDATE','DELETE','TRUNCATE') THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_mutation_refused';\n END IF;\n IF TG_OP='UPDATE' THEN\n  IF OLD.phase='open' AND NEW.phase='closed'\n     AND ROW(OLD.deployment_id,OLD.tenant_id,OLD.thread_id,OLD.head_schema,OLD.anchor_kind,OLD.anchor_id,OLD.thread_created_at,OLD.recorded_at) IS NOT DISTINCT FROM ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id,NEW.head_schema,NEW.anchor_kind,NEW.anchor_id,NEW.thread_created_at,NEW.recorded_at) THEN\n   RETURN NEW;\n  END IF;\n END IF;\n RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_mutation_refused';\nEND;\n$function$\n","identity":{"arguments":"","name":"guard_thread_history_head_mutation","schema":"openbot_internal"},"inputArgumentCount":0,"inputTypes":[],"isSyncFunction":false,"kind":"f","language":"plpgsql","leakproof":false,"ownerRef":"original_threads_owner","parallel":"u","rawAcl":null,"returnType":{"formatted":"trigger","name":"trigger","schema":"pg_catalog"},"rows":0,"securityDefiner":false,"setReturning":false,"source":"\nBEGIN\n IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_TABLE_NAME<>'thread_history_heads'\n    OR TG_OP NOT IN('UPDATE','DELETE','TRUNCATE') THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_mutation_refused';\n END IF;\n IF TG_OP='UPDATE' THEN\n  IF OLD.phase='open' AND NEW.phase='closed'\n     AND ROW(OLD.deployment_id,OLD.tenant_id,OLD.thread_id,OLD.head_schema,OLD.anchor_kind,OLD.anchor_id,OLD.thread_created_at,OLD.recorded_at) IS NOT DISTINCT FROM ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id,NEW.head_schema,NEW.anchor_kind,NEW.anchor_id,NEW.thread_created_at,NEW.recorded_at) THEN\n   RETURN NEW;\n  END IF;\n END IF;\n RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_mutation_refused';\nEND;\n","sqlBody":null,"strict":false,"supportFunction":null,"transformTypes":[],"transformTypesIsNull":true,"variadicType":null,"volatility":"v"},{"acl":[{"grantable":false,"grantee":"PUBLIC","grantor":"original_threads_owner","privilege":"EXECUTE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"EXECUTE"}],"aclIsNull":true,"allArgumentTypes":[],"allArgumentTypesIsNull":true,"argumentDefaults":null,"argumentModes":null,"argumentNames":null,"binary":null,"configuration":null,"cost":100,"defaultArgumentCount":0,"definition":"CREATE OR REPLACE FUNCTION openbot_internal.prevent_thread_history_base_truncate()\n RETURNS trigger\n LANGUAGE plpgsql\nAS $function$\nBEGIN\n IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'threads' OR TG_OP<>'TRUNCATE' THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';\n END IF;\n RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';\nEND;\n$function$\n","identity":{"arguments":"","name":"prevent_thread_history_base_truncate","schema":"openbot_internal"},"inputArgumentCount":0,"inputTypes":[],"isSyncFunction":false,"kind":"f","language":"plpgsql","leakproof":false,"ownerRef":"original_threads_owner","parallel":"u","rawAcl":null,"returnType":{"formatted":"trigger","name":"trigger","schema":"pg_catalog"},"rows":0,"securityDefiner":false,"setReturning":false,"source":"\nBEGIN\n IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'threads' OR TG_OP<>'TRUNCATE' THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';\n END IF;\n RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';\nEND;\n","sqlBody":null,"strict":false,"supportFunction":null,"transformTypes":[],"transformTypesIsNull":true,"variadicType":null,"volatility":"v"},{"acl":[{"grantable":false,"grantee":"PUBLIC","grantor":"original_threads_owner","privilege":"EXECUTE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"EXECUTE"}],"aclIsNull":true,"allArgumentTypes":[],"allArgumentTypesIsNull":true,"argumentDefaults":null,"argumentModes":null,"argumentNames":null,"binary":null,"configuration":null,"cost":100,"defaultArgumentCount":0,"definition":"CREATE OR REPLACE FUNCTION openbot_internal.prevent_thread_history_intent_mutation()\n RETURNS trigger\n LANGUAGE plpgsql\nAS $function$\nBEGIN\n IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_TABLE_NAME<>'thread_history_clear_intents'\n    OR TG_OP NOT IN('UPDATE','DELETE','TRUNCATE') THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_mutation_refused';\n END IF;\n RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_mutation_refused';\nEND;\n$function$\n","identity":{"arguments":"","name":"prevent_thread_history_intent_mutation","schema":"openbot_internal"},"inputArgumentCount":0,"inputTypes":[],"isSyncFunction":false,"kind":"f","language":"plpgsql","leakproof":false,"ownerRef":"original_threads_owner","parallel":"u","rawAcl":null,"returnType":{"formatted":"trigger","name":"trigger","schema":"pg_catalog"},"rows":0,"securityDefiner":false,"setReturning":false,"source":"\nBEGIN\n IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_TABLE_NAME<>'thread_history_clear_intents'\n    OR TG_OP NOT IN('UPDATE','DELETE','TRUNCATE') THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_mutation_refused';\n END IF;\n RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_mutation_refused';\nEND;\n","sqlBody":null,"strict":false,"supportFunction":null,"transformTypes":[],"transformTypesIsNull":true,"variadicType":null,"volatility":"v"},{"acl":[{"grantable":false,"grantee":"PUBLIC","grantor":"original_threads_owner","privilege":"EXECUTE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"EXECUTE"}],"aclIsNull":true,"allArgumentTypes":[],"allArgumentTypesIsNull":true,"argumentDefaults":null,"argumentModes":null,"argumentNames":null,"binary":null,"configuration":null,"cost":100,"defaultArgumentCount":0,"definition":"CREATE OR REPLACE FUNCTION openbot_internal.protect_thread_history_base_identity()\n RETURNS trigger\n LANGUAGE plpgsql\nAS $function$\nDECLARE v_head openbot_internal.thread_history_heads%ROWTYPE;\nBEGIN\n IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'threads' OR TG_OP<>'UPDATE' THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n IF NEW.thread_id IS DISTINCT FROM OLD.thread_id THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';\n END IF;\n SELECT h.* INTO v_head FROM openbot_internal.thread_history_heads h\n  WHERE h.thread_id=OLD.thread_id FOR SHARE OF h;\n IF FOUND AND (ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(OLD.deployment_id,OLD.tenant_id,OLD.thread_id,OLD.anchor_kind,OLD.anchor_id,OLD.created_at)\n     OR ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id,NEW.anchor_kind,NEW.anchor_id,NEW.created_at)) THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n RETURN NEW;\nEND;\n$function$\n","identity":{"arguments":"","name":"protect_thread_history_base_identity","schema":"openbot_internal"},"inputArgumentCount":0,"inputTypes":[],"isSyncFunction":false,"kind":"f","language":"plpgsql","leakproof":false,"ownerRef":"original_threads_owner","parallel":"u","rawAcl":null,"returnType":{"formatted":"trigger","name":"trigger","schema":"pg_catalog"},"rows":0,"securityDefiner":false,"setReturning":false,"source":"\nDECLARE v_head openbot_internal.thread_history_heads%ROWTYPE;\nBEGIN\n IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'threads' OR TG_OP<>'UPDATE' THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n IF NEW.thread_id IS DISTINCT FROM OLD.thread_id THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_identity_reuse_refused';\n END IF;\n SELECT h.* INTO v_head FROM openbot_internal.thread_history_heads h\n  WHERE h.thread_id=OLD.thread_id FOR SHARE OF h;\n IF FOUND AND (ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(OLD.deployment_id,OLD.tenant_id,OLD.thread_id,OLD.anchor_kind,OLD.anchor_id,OLD.created_at)\n     OR ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(NEW.deployment_id,NEW.tenant_id,NEW.thread_id,NEW.anchor_kind,NEW.anchor_id,NEW.created_at)) THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n RETURN NEW;\nEND;\n","sqlBody":null,"strict":false,"supportFunction":null,"transformTypes":[],"transformTypesIsNull":true,"variadicType":null,"volatility":"v"},{"acl":[{"grantable":false,"grantee":"PUBLIC","grantor":"original_threads_owner","privilege":"EXECUTE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"EXECUTE"}],"aclIsNull":true,"allArgumentTypes":[],"allArgumentTypesIsNull":true,"argumentDefaults":null,"argumentModes":null,"argumentNames":null,"binary":null,"configuration":null,"cost":100,"defaultArgumentCount":0,"definition":"CREATE OR REPLACE FUNCTION openbot_internal.require_thread_history_intent_closed_head()\n RETURNS trigger\n LANGUAGE plpgsql\nAS $function$\nDECLARE v_matches boolean;\nBEGIN\n IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_TABLE_NAME<>'thread_history_clear_intents'\n    OR TG_OP<>'INSERT' THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n SELECT true INTO v_matches FROM openbot_internal.thread_history_heads h\n WHERE h.deployment_id=NEW.deployment_id AND h.tenant_id=NEW.tenant_id\n   AND h.thread_id=NEW.thread_id AND h.phase='closed'\n   AND h.closure_operation_id=NEW.operation_id AND h.closure_request_id=NEW.request_id\n   AND h.closure_actor_id=NEW.actor_id AND h.closure_auth_generation=NEW.auth_generation\n   AND h.anchor_kind=NEW.anchor_kind AND h.anchor_id=NEW.anchor_id\n   AND h.thread_created_at=NEW.thread_created_at AND h.closed_at=NEW.recorded_at\n FOR SHARE OF h;\n IF v_matches IS DISTINCT FROM true THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n RETURN NEW;\nEND;\n$function$\n","identity":{"arguments":"","name":"require_thread_history_intent_closed_head","schema":"openbot_internal"},"inputArgumentCount":0,"inputTypes":[],"isSyncFunction":false,"kind":"f","language":"plpgsql","leakproof":false,"ownerRef":"original_threads_owner","parallel":"u","rawAcl":null,"returnType":{"formatted":"trigger","name":"trigger","schema":"pg_catalog"},"rows":0,"securityDefiner":false,"setReturning":false,"source":"\nDECLARE v_matches boolean;\nBEGIN\n IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_TABLE_NAME<>'thread_history_clear_intents'\n    OR TG_OP<>'INSERT' THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n SELECT true INTO v_matches FROM openbot_internal.thread_history_heads h\n WHERE h.deployment_id=NEW.deployment_id AND h.tenant_id=NEW.tenant_id\n   AND h.thread_id=NEW.thread_id AND h.phase='closed'\n   AND h.closure_operation_id=NEW.operation_id AND h.closure_request_id=NEW.request_id\n   AND h.closure_actor_id=NEW.actor_id AND h.closure_auth_generation=NEW.auth_generation\n   AND h.anchor_kind=NEW.anchor_kind AND h.anchor_id=NEW.anchor_id\n   AND h.thread_created_at=NEW.thread_created_at AND h.closed_at=NEW.recorded_at\n FOR SHARE OF h;\n IF v_matches IS DISTINCT FROM true THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n RETURN NEW;\nEND;\n","sqlBody":null,"strict":false,"supportFunction":null,"transformTypes":[],"transformTypesIsNull":true,"variadicType":null,"volatility":"v"},{"acl":[{"grantable":false,"grantee":"PUBLIC","grantor":"original_threads_owner","privilege":"EXECUTE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"EXECUTE"}],"aclIsNull":true,"allArgumentTypes":[],"allArgumentTypesIsNull":true,"argumentDefaults":null,"argumentModes":null,"argumentNames":null,"binary":null,"configuration":null,"cost":100,"defaultArgumentCount":0,"definition":"CREATE OR REPLACE FUNCTION openbot_internal.retain_thread_history_head_on_delete()\n RETURNS trigger\n LANGUAGE plpgsql\nAS $function$\nDECLARE v_head openbot_internal.thread_history_heads%ROWTYPE;\nBEGIN\n IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'threads' OR TG_OP<>'DELETE' THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n INSERT INTO openbot_internal.thread_history_heads (deployment_id,tenant_id,thread_id,head_schema,phase,anchor_kind,anchor_id,thread_created_at) VALUES (OLD.deployment_id,OLD.tenant_id,OLD.thread_id,1,'open',OLD.anchor_kind,OLD.anchor_id,OLD.created_at) ON CONFLICT(thread_id) DO NOTHING;\n SELECT h.* INTO v_head FROM openbot_internal.thread_history_heads h\n  WHERE h.thread_id=OLD.thread_id FOR SHARE OF h;\n IF NOT FOUND OR ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(OLD.deployment_id,OLD.tenant_id,OLD.thread_id,OLD.anchor_kind,OLD.anchor_id,OLD.created_at) THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n RETURN OLD;\nEND;\n$function$\n","identity":{"arguments":"","name":"retain_thread_history_head_on_delete","schema":"openbot_internal"},"inputArgumentCount":0,"inputTypes":[],"isSyncFunction":false,"kind":"f","language":"plpgsql","leakproof":false,"ownerRef":"original_threads_owner","parallel":"u","rawAcl":null,"returnType":{"formatted":"trigger","name":"trigger","schema":"pg_catalog"},"rows":0,"securityDefiner":false,"setReturning":false,"source":"\nDECLARE v_head openbot_internal.thread_history_heads%ROWTYPE;\nBEGIN\n IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'threads' OR TG_OP<>'DELETE' THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n INSERT INTO openbot_internal.thread_history_heads (deployment_id,tenant_id,thread_id,head_schema,phase,anchor_kind,anchor_id,thread_created_at) VALUES (OLD.deployment_id,OLD.tenant_id,OLD.thread_id,1,'open',OLD.anchor_kind,OLD.anchor_id,OLD.created_at) ON CONFLICT(thread_id) DO NOTHING;\n SELECT h.* INTO v_head FROM openbot_internal.thread_history_heads h\n  WHERE h.thread_id=OLD.thread_id FOR SHARE OF h;\n IF NOT FOUND OR ROW(v_head.deployment_id,v_head.tenant_id,v_head.thread_id,v_head.anchor_kind,v_head.anchor_id,v_head.thread_created_at) IS DISTINCT FROM ROW(OLD.deployment_id,OLD.tenant_id,OLD.thread_id,OLD.anchor_kind,OLD.anchor_id,OLD.created_at) THEN\n  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_state_binding_invalid';\n END IF;\n RETURN OLD;\nEND;\n","sqlBody":null,"strict":false,"supportFunction":null,"transformTypes":[],"transformTypesIsNull":true,"variadicType":null,"volatility":"v"}],"indexes":[{"accessMethod":"btree","aclIsNull":true,"attributeCount":1,"checkXmin":{"predicate":"pg17_hot_runtime_boolean_v1"},"clustered":false,"collations":[{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":1}],"definition":"CREATE UNIQUE INDEX thread_history_clear_intents_pkey ON openbot_internal.thread_history_clear_intents USING btree (operation_id)","exclusion":false,"expressions":null,"identity":{"name":"thread_history_clear_intents_pkey","schema":"openbot_internal"},"immediate":true,"keyCount":1,"keys":"6","kind":"i","live":true,"nullsNotDistinct":false,"operatorClasses":[{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":1,"schema":"pg_catalog"}],"options":null,"optionsPerKey":"0","ownerIsOriginal":true,"persistence":"p","predicate":null,"primary":true,"rawAcl":null,"ready":true,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"replicaIdentity":false,"unique":true,"valid":true},{"accessMethod":"btree","aclIsNull":true,"attributeCount":1,"checkXmin":{"predicate":"pg17_hot_runtime_boolean_v1"},"clustered":false,"collations":[{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":1}],"definition":"CREATE UNIQUE INDEX thread_history_heads_thread_id_key ON openbot_internal.thread_history_heads USING btree (thread_id)","exclusion":false,"expressions":null,"identity":{"name":"thread_history_heads_thread_id_key","schema":"openbot_internal"},"immediate":true,"keyCount":1,"keys":"3","kind":"i","live":true,"nullsNotDistinct":false,"operatorClasses":[{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":1,"schema":"pg_catalog"}],"options":null,"optionsPerKey":"0","ownerIsOriginal":true,"persistence":"p","predicate":null,"primary":false,"rawAcl":null,"ready":true,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"replicaIdentity":false,"unique":true,"valid":true},{"accessMethod":"btree","aclIsNull":true,"attributeCount":11,"checkXmin":{"predicate":"pg17_hot_runtime_boolean_v1"},"clustered":false,"collations":[{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":1},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":2},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":3},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":4},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":5},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":6},{"collation":null,"ordinal":7},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":8},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":9},{"collation":null,"ordinal":10},{"collation":null,"ordinal":11}],"definition":"CREATE UNIQUE INDEX thread_history_clear_intents_closed_binding_key ON openbot_internal.thread_history_clear_intents USING btree (deployment_id, tenant_id, thread_id, operation_id, request_id, actor_id, auth_generation, anchor_kind, anchor_id, thread_created_at, recorded_at)","exclusion":false,"expressions":null,"identity":{"name":"thread_history_clear_intents_closed_binding_key","schema":"openbot_internal"},"immediate":true,"keyCount":11,"keys":"1 2 3 6 7 8 9 10 11 12 13","kind":"i","live":true,"nullsNotDistinct":false,"operatorClasses":[{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":1,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":2,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":3,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":4,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":5,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":6,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"integer_ops","schema":"pg_catalog"},"inputType":"bigint","keyType":null,"name":"int8_ops","ordinal":7,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":8,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":9,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"datetime_ops","schema":"pg_catalog"},"inputType":"timestamp with time zone","keyType":null,"name":"timestamptz_ops","ordinal":10,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"datetime_ops","schema":"pg_catalog"},"inputType":"timestamp with time zone","keyType":null,"name":"timestamptz_ops","ordinal":11,"schema":"pg_catalog"}],"options":null,"optionsPerKey":"0 0 0 0 0 0 0 0 0 0 0","ownerIsOriginal":true,"persistence":"p","predicate":null,"primary":false,"rawAcl":null,"ready":true,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"replicaIdentity":false,"unique":true,"valid":true},{"accessMethod":"btree","aclIsNull":true,"attributeCount":3,"checkXmin":{"predicate":"pg17_hot_runtime_boolean_v1"},"clustered":false,"collations":[{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":1},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":2},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":3}],"definition":"CREATE UNIQUE INDEX thread_history_clear_intents_request_key ON openbot_internal.thread_history_clear_intents USING btree (deployment_id, tenant_id, request_id)","exclusion":false,"expressions":null,"identity":{"name":"thread_history_clear_intents_request_key","schema":"openbot_internal"},"immediate":true,"keyCount":3,"keys":"1 2 7","kind":"i","live":true,"nullsNotDistinct":false,"operatorClasses":[{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":1,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":2,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":3,"schema":"pg_catalog"}],"options":null,"optionsPerKey":"0 0 0","ownerIsOriginal":true,"persistence":"p","predicate":null,"primary":false,"rawAcl":null,"ready":true,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"replicaIdentity":false,"unique":true,"valid":true},{"accessMethod":"btree","aclIsNull":true,"attributeCount":3,"checkXmin":{"predicate":"pg17_hot_runtime_boolean_v1"},"clustered":false,"collations":[{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":1},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":2},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":3}],"definition":"CREATE UNIQUE INDEX thread_history_clear_intents_thread_key ON openbot_internal.thread_history_clear_intents USING btree (deployment_id, tenant_id, thread_id)","exclusion":false,"expressions":null,"identity":{"name":"thread_history_clear_intents_thread_key","schema":"openbot_internal"},"immediate":true,"keyCount":3,"keys":"1 2 3","kind":"i","live":true,"nullsNotDistinct":false,"operatorClasses":[{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":1,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":2,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":3,"schema":"pg_catalog"}],"options":null,"optionsPerKey":"0 0 0","ownerIsOriginal":true,"persistence":"p","predicate":null,"primary":false,"rawAcl":null,"ready":true,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"replicaIdentity":false,"unique":true,"valid":true},{"accessMethod":"btree","aclIsNull":true,"attributeCount":3,"checkXmin":{"predicate":"pg17_hot_runtime_boolean_v1"},"clustered":false,"collations":[{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":1},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":2},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":3}],"definition":"CREATE UNIQUE INDEX thread_history_heads_pkey ON openbot_internal.thread_history_heads USING btree (deployment_id, tenant_id, thread_id)","exclusion":false,"expressions":null,"identity":{"name":"thread_history_heads_pkey","schema":"openbot_internal"},"immediate":true,"keyCount":3,"keys":"1 2 3","kind":"i","live":true,"nullsNotDistinct":false,"operatorClasses":[{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":1,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":2,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":3,"schema":"pg_catalog"}],"options":null,"optionsPerKey":"0 0 0","ownerIsOriginal":true,"persistence":"p","predicate":null,"primary":true,"rawAcl":null,"ready":true,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"replicaIdentity":false,"unique":true,"valid":true},{"accessMethod":"btree","aclIsNull":true,"attributeCount":6,"checkXmin":{"predicate":"pg17_hot_runtime_boolean_v1"},"clustered":false,"collations":[{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":1},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":2},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":3},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":4},{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":5},{"collation":null,"ordinal":6}],"definition":"CREATE UNIQUE INDEX thread_history_heads_base_key ON openbot_internal.thread_history_heads USING btree (deployment_id, tenant_id, thread_id, anchor_kind, anchor_id, thread_created_at)","exclusion":false,"expressions":null,"identity":{"name":"thread_history_heads_base_key","schema":"openbot_internal"},"immediate":true,"keyCount":6,"keys":"1 2 3 6 7 8","kind":"i","live":true,"nullsNotDistinct":false,"operatorClasses":[{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":1,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":2,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":3,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":4,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":5,"schema":"pg_catalog"},{"accessMethod":"btree","default":true,"family":{"name":"datetime_ops","schema":"pg_catalog"},"inputType":"timestamp with time zone","keyType":null,"name":"timestamptz_ops","ordinal":6,"schema":"pg_catalog"}],"options":null,"optionsPerKey":"0 0 0 0 0 0","ownerIsOriginal":true,"persistence":"p","predicate":null,"primary":false,"rawAcl":null,"ready":true,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"replicaIdentity":false,"unique":true,"valid":true}],"relations":[{"accessMethod":"heap","acl":[{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"DELETE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"INSERT"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"MAINTAIN"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"REFERENCES"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"SELECT"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"TRIGGER"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"TRUNCATE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"UPDATE"}],"attributeCount":13,"checkCount":7,"columns":[{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"deployment_id","notNull":true,"ordinal":1,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"tenant_id","notNull":true,"ordinal":2,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"thread_id","notNull":true,"ordinal":3,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"intent_schema","notNull":true,"ordinal":4,"type":{"formatted":"smallint","modifier":-1,"name":"int2","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"intent_kind","notNull":true,"ordinal":5,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"operation_id","notNull":true,"ordinal":6,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"request_id","notNull":true,"ordinal":7,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"actor_id","notNull":true,"ordinal":8,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"auth_generation","notNull":true,"ordinal":9,"type":{"formatted":"bigint","modifier":-1,"name":"int8","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"anchor_kind","notNull":true,"ordinal":10,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"anchor_id","notNull":true,"ordinal":11,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"thread_created_at","notNull":true,"ordinal":12,"type":{"formatted":"timestamp with time zone","modifier":-1,"name":"timestamptz","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":"clock_timestamp()","dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"recorded_at","notNull":true,"ordinal":13,"type":{"formatted":"timestamp with time zone","modifier":-1,"name":"timestamptz","schema":"pg_catalog"}}],"droppedAttributes":[],"forceRowSecurity":false,"identity":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"inheritanceChildren":[],"inheritanceParents":[],"kind":"r","options":null,"ownerIsOriginal":true,"partition":false,"persistence":"p","policies":[],"replicaIdentity":"d","rowSecurity":false,"rules":[]},{"accessMethod":"heap","acl":[{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"DELETE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"INSERT"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"MAINTAIN"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"REFERENCES"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"SELECT"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"TRIGGER"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"TRUNCATE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"UPDATE"}],"attributeCount":14,"checkCount":8,"columns":[{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"deployment_id","notNull":true,"ordinal":1,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"tenant_id","notNull":true,"ordinal":2,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"thread_id","notNull":true,"ordinal":3,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"head_schema","notNull":true,"ordinal":4,"type":{"formatted":"smallint","modifier":-1,"name":"int2","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"phase","notNull":true,"ordinal":5,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"anchor_kind","notNull":true,"ordinal":6,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"anchor_id","notNull":true,"ordinal":7,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"thread_created_at","notNull":true,"ordinal":8,"type":{"formatted":"timestamp with time zone","modifier":-1,"name":"timestamptz","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":"clock_timestamp()","dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"recorded_at","notNull":true,"ordinal":9,"type":{"formatted":"timestamp with time zone","modifier":-1,"name":"timestamptz","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"closure_operation_id","notNull":false,"ordinal":10,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"closure_request_id","notNull":false,"ordinal":11,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"closure_actor_id","notNull":false,"ordinal":12,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"closure_auth_generation","notNull":false,"ordinal":13,"type":{"formatted":"bigint","modifier":-1,"name":"int8","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"closed_at","notNull":false,"ordinal":14,"type":{"formatted":"timestamp with time zone","modifier":-1,"name":"timestamptz","schema":"pg_catalog"}}],"droppedAttributes":[],"forceRowSecurity":false,"identity":{"name":"thread_history_heads","schema":"openbot_internal"},"inheritanceChildren":[],"inheritanceParents":[],"kind":"r","options":null,"ownerIsOriginal":true,"partition":false,"persistence":"p","policies":[],"replicaIdentity":"d","rowSecurity":false,"rules":[]}],"triggers":[{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":null,"constraintIndex":null,"constraintRelation":null,"deferrable":false,"deferred":false,"definition":"CREATE TRIGGER thread_history_clear_intents_no_truncate BEFORE TRUNCATE ON openbot_internal.thread_history_clear_intents FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_thread_history_intent_mutation()","enabled":"O","function":{"arguments":"","kind":"f","name":"prevent_thread_history_intent_mutation","schema":"openbot_internal"},"hasParent":false,"internal":false,"name":"thread_history_clear_intents_no_truncate","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"type":34},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":null,"constraintIndex":null,"constraintRelation":null,"deferrable":false,"deferred":false,"definition":"CREATE TRIGGER thread_history_clear_intents_no_update_delete BEFORE DELETE OR UPDATE ON openbot_internal.thread_history_clear_intents FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_thread_history_intent_mutation()","enabled":"O","function":{"arguments":"","kind":"f","name":"prevent_thread_history_intent_mutation","schema":"openbot_internal"},"hasParent":false,"internal":false,"name":"thread_history_clear_intents_no_update_delete","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"type":27},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":null,"constraintIndex":null,"constraintRelation":null,"deferrable":false,"deferred":false,"definition":"CREATE TRIGGER thread_history_heads_guard_update_delete BEFORE DELETE OR UPDATE ON openbot_internal.thread_history_heads FOR EACH ROW EXECUTE FUNCTION openbot_internal.guard_thread_history_head_mutation()","enabled":"O","function":{"arguments":"","kind":"f","name":"guard_thread_history_head_mutation","schema":"openbot_internal"},"hasParent":false,"internal":false,"name":"thread_history_heads_guard_update_delete","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"type":27},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":null,"constraintIndex":null,"constraintRelation":null,"deferrable":false,"deferred":false,"definition":"CREATE TRIGGER thread_history_heads_no_truncate BEFORE TRUNCATE ON openbot_internal.thread_history_heads FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.guard_thread_history_head_mutation()","enabled":"O","function":{"arguments":"","kind":"f","name":"guard_thread_history_head_mutation","schema":"openbot_internal"},"hasParent":false,"internal":false,"name":"thread_history_heads_no_truncate","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"type":34},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":null,"constraintIndex":null,"constraintRelation":null,"deferrable":false,"deferred":false,"definition":"CREATE TRIGGER threads_history_bind_insert BEFORE INSERT ON public.threads FOR EACH ROW EXECUTE FUNCTION openbot_internal.bind_thread_history_head_on_insert()","enabled":"O","function":{"arguments":"","kind":"f","name":"bind_thread_history_head_on_insert","schema":"openbot_internal"},"hasParent":false,"internal":false,"name":"threads_history_bind_insert","newTransition":null,"oldTransition":null,"relation":{"name":"threads","schema":"public"},"type":7},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":null,"constraintIndex":null,"constraintRelation":null,"deferrable":false,"deferred":false,"definition":"CREATE TRIGGER threads_history_no_truncate BEFORE TRUNCATE ON public.threads FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_thread_history_base_truncate()","enabled":"O","function":{"arguments":"","kind":"f","name":"prevent_thread_history_base_truncate","schema":"openbot_internal"},"hasParent":false,"internal":false,"name":"threads_history_no_truncate","newTransition":null,"oldTransition":null,"relation":{"name":"threads","schema":"public"},"type":34},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":null,"constraintIndex":null,"constraintRelation":null,"deferrable":false,"deferred":false,"definition":"CREATE TRIGGER threads_history_retain_delete BEFORE DELETE ON public.threads FOR EACH ROW EXECUTE FUNCTION openbot_internal.retain_thread_history_head_on_delete()","enabled":"O","function":{"arguments":"","kind":"f","name":"retain_thread_history_head_on_delete","schema":"openbot_internal"},"hasParent":false,"internal":false,"name":"threads_history_retain_delete","newTransition":null,"oldTransition":null,"relation":{"name":"threads","schema":"public"},"type":11},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":{"kind":"f","name":"thread_history_clear_intents_head_base_fkey","relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"}},"constraintIndex":{"name":"thread_history_heads_base_key","schema":"openbot_internal"},"constraintRelation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"deferrable":true,"deferred":true,"definition":"CREATE CONSTRAINT TRIGGER \"RI_ConstraintTrigger_a_<checked-trigger-oid>\" AFTER DELETE ON openbot_internal.thread_history_heads FROM openbot_internal.thread_history_clear_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION \"RI_FKey_noaction_del\"()","enabled":"O","function":{"arguments":"","kind":"f","name":"RI_FKey_noaction_del","schema":"pg_catalog"},"hasParent":false,"internal":true,"name":"RI_ConstraintTrigger_a_<checked-trigger-oid>","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"type":9},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":{"kind":"f","name":"thread_history_clear_intents_head_base_fkey","relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"}},"constraintIndex":{"name":"thread_history_heads_base_key","schema":"openbot_internal"},"constraintRelation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"deferrable":true,"deferred":true,"definition":"CREATE CONSTRAINT TRIGGER \"RI_ConstraintTrigger_a_<checked-trigger-oid>\" AFTER UPDATE ON openbot_internal.thread_history_heads FROM openbot_internal.thread_history_clear_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION \"RI_FKey_noaction_upd\"()","enabled":"O","function":{"arguments":"","kind":"f","name":"RI_FKey_noaction_upd","schema":"pg_catalog"},"hasParent":false,"internal":true,"name":"RI_ConstraintTrigger_a_<checked-trigger-oid>","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"type":17},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":{"kind":"f","name":"thread_history_clear_intents_head_base_fkey","relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"}},"constraintIndex":{"name":"thread_history_heads_base_key","schema":"openbot_internal"},"constraintRelation":{"name":"thread_history_heads","schema":"openbot_internal"},"deferrable":true,"deferred":true,"definition":"CREATE CONSTRAINT TRIGGER \"RI_ConstraintTrigger_c_<checked-trigger-oid>\" AFTER INSERT ON openbot_internal.thread_history_clear_intents FROM openbot_internal.thread_history_heads DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION \"RI_FKey_check_ins\"()","enabled":"O","function":{"arguments":"","kind":"f","name":"RI_FKey_check_ins","schema":"pg_catalog"},"hasParent":false,"internal":true,"name":"RI_ConstraintTrigger_c_<checked-trigger-oid>","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"type":5},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":{"kind":"f","name":"thread_history_clear_intents_head_base_fkey","relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"}},"constraintIndex":{"name":"thread_history_heads_base_key","schema":"openbot_internal"},"constraintRelation":{"name":"thread_history_heads","schema":"openbot_internal"},"deferrable":true,"deferred":true,"definition":"CREATE CONSTRAINT TRIGGER \"RI_ConstraintTrigger_c_<checked-trigger-oid>\" AFTER UPDATE ON openbot_internal.thread_history_clear_intents FROM openbot_internal.thread_history_heads DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION \"RI_FKey_check_upd\"()","enabled":"O","function":{"arguments":"","kind":"f","name":"RI_FKey_check_upd","schema":"pg_catalog"},"hasParent":false,"internal":true,"name":"RI_ConstraintTrigger_c_<checked-trigger-oid>","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"type":17},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":{"kind":"f","name":"thread_history_heads_closed_intent_fkey","relation":{"name":"thread_history_heads","schema":"openbot_internal"}},"constraintIndex":{"name":"thread_history_clear_intents_closed_binding_key","schema":"openbot_internal"},"constraintRelation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"deferrable":true,"deferred":true,"definition":"CREATE CONSTRAINT TRIGGER \"RI_ConstraintTrigger_c_<checked-trigger-oid>\" AFTER INSERT ON openbot_internal.thread_history_heads FROM openbot_internal.thread_history_clear_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION \"RI_FKey_check_ins\"()","enabled":"O","function":{"arguments":"","kind":"f","name":"RI_FKey_check_ins","schema":"pg_catalog"},"hasParent":false,"internal":true,"name":"RI_ConstraintTrigger_c_<checked-trigger-oid>","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"type":5},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":{"kind":"f","name":"thread_history_heads_closed_intent_fkey","relation":{"name":"thread_history_heads","schema":"openbot_internal"}},"constraintIndex":{"name":"thread_history_clear_intents_closed_binding_key","schema":"openbot_internal"},"constraintRelation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"deferrable":true,"deferred":true,"definition":"CREATE CONSTRAINT TRIGGER \"RI_ConstraintTrigger_c_<checked-trigger-oid>\" AFTER UPDATE ON openbot_internal.thread_history_heads FROM openbot_internal.thread_history_clear_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION \"RI_FKey_check_upd\"()","enabled":"O","function":{"arguments":"","kind":"f","name":"RI_FKey_check_upd","schema":"pg_catalog"},"hasParent":false,"internal":true,"name":"RI_ConstraintTrigger_c_<checked-trigger-oid>","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_heads","schema":"openbot_internal"},"type":17},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":{"kind":"f","name":"thread_history_heads_closed_intent_fkey","relation":{"name":"thread_history_heads","schema":"openbot_internal"}},"constraintIndex":{"name":"thread_history_clear_intents_closed_binding_key","schema":"openbot_internal"},"constraintRelation":{"name":"thread_history_heads","schema":"openbot_internal"},"deferrable":true,"deferred":true,"definition":"CREATE CONSTRAINT TRIGGER \"RI_ConstraintTrigger_a_<checked-trigger-oid>\" AFTER DELETE ON openbot_internal.thread_history_clear_intents FROM openbot_internal.thread_history_heads DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION \"RI_FKey_noaction_del\"()","enabled":"O","function":{"arguments":"","kind":"f","name":"RI_FKey_noaction_del","schema":"pg_catalog"},"hasParent":false,"internal":true,"name":"RI_ConstraintTrigger_a_<checked-trigger-oid>","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"type":9},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":{"kind":"f","name":"thread_history_heads_closed_intent_fkey","relation":{"name":"thread_history_heads","schema":"openbot_internal"}},"constraintIndex":{"name":"thread_history_clear_intents_closed_binding_key","schema":"openbot_internal"},"constraintRelation":{"name":"thread_history_heads","schema":"openbot_internal"},"deferrable":true,"deferred":true,"definition":"CREATE CONSTRAINT TRIGGER \"RI_ConstraintTrigger_a_<checked-trigger-oid>\" AFTER UPDATE ON openbot_internal.thread_history_clear_intents FROM openbot_internal.thread_history_heads DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION \"RI_FKey_noaction_upd\"()","enabled":"O","function":{"arguments":"","kind":"f","name":"RI_FKey_noaction_upd","schema":"pg_catalog"},"hasParent":false,"internal":true,"name":"RI_ConstraintTrigger_a_<checked-trigger-oid>","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"type":17},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":{"kind":"t","name":"thread_history_clear_intents_require_closed_head","relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"}},"constraintIndex":null,"constraintRelation":null,"deferrable":true,"deferred":true,"definition":"CREATE CONSTRAINT TRIGGER thread_history_clear_intents_require_closed_head AFTER INSERT ON openbot_internal.thread_history_clear_intents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openbot_internal.require_thread_history_intent_closed_head()","enabled":"O","function":{"arguments":"","kind":"f","name":"require_thread_history_intent_closed_head","schema":"openbot_internal"},"hasParent":false,"internal":false,"name":"thread_history_clear_intents_require_closed_head","newTransition":null,"oldTransition":null,"relation":{"name":"thread_history_clear_intents","schema":"openbot_internal"},"type":5},{"argumentCount":0,"argumentsHex":"","columns":"1 2 3 5 6 11","conditionIsNull":true,"conditionTreeRaw":null,"constraint":null,"constraintIndex":null,"constraintRelation":null,"deferrable":false,"deferred":false,"definition":"CREATE TRIGGER threads_history_protect_identity_update BEFORE UPDATE OF thread_id, tenant_id, deployment_id, anchor_kind, anchor_id, created_at ON public.threads FOR EACH ROW EXECUTE FUNCTION openbot_internal.protect_thread_history_base_identity()","enabled":"O","function":{"arguments":"","kind":"f","name":"protect_thread_history_base_identity","schema":"openbot_internal"},"hasParent":false,"internal":false,"name":"threads_history_protect_identity_update","newTransition":null,"oldTransition":null,"relation":{"name":"threads","schema":"public"},"type":19}]}}$thread_history_expected$::jsonb;
BEGIN
 SELECT actual.thread_history_raw::jsonb, actual.function_acl_matches_builtin
 INTO v_raw,v_matches FROM (
WITH
wanted_relations(schema_name, relation_name) AS (
 VALUES ('openbot_internal'::text,'thread_history_heads'::text),
        ('openbot_internal'::text,'thread_history_clear_intents'::text)
),
relations AS (
 SELECT c.*, n.nspname AS schema_name
 FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 JOIN wanted_relations w ON w.schema_name=n.nspname AND w.relation_name=c.relname
),
original_owner AS (
 SELECT r.oid AS relation_oid, r.relowner AS owner_oid
 FROM pg_catalog.pg_class r JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace
 WHERE n.nspname='public' AND r.relname='threads' AND r.relkind='r'
),
named_guards AS (
 SELECT p.* FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='openbot_internal' AND p.proname IN ('guard_thread_history_head_mutation','prevent_thread_history_intent_mutation','require_thread_history_intent_closed_head','bind_thread_history_head_on_insert','retain_thread_history_head_on_delete','protect_thread_history_base_identity','prevent_thread_history_base_truncate')
),
constraints_scope AS (
 SELECT c.*
 FROM pg_catalog.pg_constraint c
 WHERE c.conrelid IN (SELECT oid FROM relations)
    OR (c.contype='f' AND c.confrelid IN (SELECT oid FROM relations))
),
indexes_scope AS (
 SELECT i.*
 FROM pg_catalog.pg_index i
 WHERE i.indrelid IN (SELECT oid FROM relations)
    OR i.indexrelid IN (SELECT conindid FROM constraints_scope WHERE conindid<>0)
),
triggers_scope AS (
 SELECT t.*
 FROM pg_catalog.pg_trigger t
 WHERE t.tgrelid IN (SELECT oid FROM relations)
    OR t.tgconstraint IN (SELECT oid FROM constraints_scope)
    OR t.tgfoid IN (SELECT oid FROM named_guards)
    OR (NOT t.tgisinternal AND t.tgrelid IN (SELECT relation_oid FROM original_owner))
),
functions_scope AS (
 SELECT p.*
 FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE p.oid IN (SELECT tgfoid FROM triggers_scope)
    OR p.oid IN (SELECT oid FROM named_guards)
),
relation_facts AS (
 SELECT r.schema_name, r.relname,
 pg_catalog.jsonb_build_object(
  'identity',pg_catalog.jsonb_build_object('oidRaw',r.oid::text,'schema',r.schema_name,'name',r.relname),
  'kind',r.relkind::text,'persistence',r.relpersistence::text,
  'partition',r.relispartition,'rowSecurity',r.relrowsecurity,
  'forceRowSecurity',r.relforcerowsecurity,'accessMethod',am.amname,
  'replicaIdentity',r.relreplident::text,'options',r.reloptions,
  'attributeCount',r.relnatts,'checkCount',r.relchecks,
  'ownerOidRaw',r.relowner::text,'aclIsNull',r.relacl IS NULL,
  'rawAcl',CASE WHEN r.relacl IS NULL THEN NULL ELSE (
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'grantorOidRaw',a.grantor::text,'granteeOidRaw',a.grantee::text,
    'privilege',a.privilege_type,'grantable',a.is_grantable)
    ORDER BY a.grantor,a.grantee,a.privilege_type COLLATE pg_catalog."C",a.is_grantable),'[]'::jsonb)
   FROM pg_catalog.aclexplode(r.relacl) a
  ) END,
  'acl',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'grantorOidRaw',a.grantor::text,'granteeOidRaw',a.grantee::text,
    'privilege',a.privilege_type,'grantable',a.is_grantable)
    ORDER BY a.grantor,a.grantee,a.privilege_type COLLATE pg_catalog."C",a.is_grantable),'[]'::jsonb)
   FROM pg_catalog.aclexplode(coalesce(r.relacl,pg_catalog.acldefault('r'::pg_catalog."char",r.relowner))) a
  ),
  'columns',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'ordinal',a.attnum,'name',a.attname,
    'type',pg_catalog.jsonb_build_object('oidRaw',a.atttypid::text,'schema',tn.nspname,'name',ty.typname,
      'formatted',pg_catalog.format_type(a.atttypid,a.atttypmod),'modifier',a.atttypmod),
    'notNull',a.attnotnull,'dimensions',a.attndims,'identity',a.attidentity::text,'generated',a.attgenerated::text,
    'local',a.attislocal,'inheritanceCount',a.attinhcount,
    'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid,false),
    'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE pg_catalog.jsonb_build_object(
      'oidRaw',co.oid::text,'schema',cn.nspname,'name',co.collname,
      'provider',co.collprovider::text,'deterministic',co.collisdeterministic,'encoding',co.collencoding) END,
    'aclIsNull',a.attacl IS NULL,
    'acl',(
     SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'grantorOidRaw',x.grantor::text,'granteeOidRaw',x.grantee::text,
      'privilege',x.privilege_type,'grantable',x.is_grantable)
      ORDER BY x.grantor,x.grantee,x.privilege_type COLLATE pg_catalog."C",x.is_grantable),'[]'::jsonb)
     FROM pg_catalog.aclexplode(a.attacl) x
    )) ORDER BY a.attnum),'[]'::jsonb)
   FROM pg_catalog.pg_attribute a
   JOIN pg_catalog.pg_type ty ON ty.oid=a.atttypid
   JOIN pg_catalog.pg_namespace tn ON tn.oid=ty.typnamespace
   LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
   LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace
   WHERE a.attrelid=r.oid AND a.attnum>0 AND NOT a.attisdropped
  ),
  'droppedAttributes',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'ordinal',a.attnum,'name',a.attname,'dropped',a.attisdropped) ORDER BY a.attnum),'[]'::jsonb)
   FROM pg_catalog.pg_attribute a WHERE a.attrelid=r.oid AND a.attnum>0 AND a.attisdropped
  ),
  'inheritanceParents',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'schema',n.nspname,'relation',c.relname,'sequence',i.inhseqno,'detachPending',i.inhdetachpending)
    ORDER BY i.inhseqno,n.nspname COLLATE pg_catalog."C",c.relname COLLATE pg_catalog."C"),'[]'::jsonb)
   FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class c ON c.oid=i.inhparent
   JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE i.inhrelid=r.oid
  ),
  'inheritanceChildren',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'schema',n.nspname,'relation',c.relname,'sequence',i.inhseqno,'detachPending',i.inhdetachpending)
    ORDER BY n.nspname COLLATE pg_catalog."C",c.relname COLLATE pg_catalog."C",i.inhseqno),'[]'::jsonb)
   FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class c ON c.oid=i.inhrelid
   JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE i.inhparent=r.oid
  ),
  'policies',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'oidRaw',p.oid::text,'name',p.polname,'command',p.polcmd::text,'permissive',p.polpermissive,
    'relationOidRaw',p.polrelid::text,
    'roles',(
     SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'ordinal',u.ordinal,'roleOidRaw',u.role_oid::text,
      'roleNameRaw',CASE WHEN u.role_oid=0 THEN 'PUBLIC'::text ELSE pr.rolname::text END)
      ORDER BY u.ordinal),'[]'::jsonb)
     FROM pg_catalog.unnest(p.polroles) WITH ORDINALITY u(role_oid,ordinal)
     LEFT JOIN pg_catalog.pg_roles pr ON pr.oid=u.role_oid
    ),
    'using',pg_catalog.pg_get_expr(p.polqual,p.polrelid,false),
    'check',pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid,false))
    ORDER BY p.polname COLLATE pg_catalog."C"),'[]'::jsonb)
   FROM pg_catalog.pg_policy p WHERE p.polrelid=r.oid
  ),
  'rules',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'name',x.rulename,'event',x.ev_type::text,'enabled',x.ev_enabled::text,'instead',x.is_instead,
    'definition',pg_catalog.pg_get_ruledef(x.oid,false)) ORDER BY x.rulename COLLATE pg_catalog."C"),'[]'::jsonb)
   FROM pg_catalog.pg_rewrite x WHERE x.ev_class=r.oid
  )
 ) AS facts
 FROM relations r LEFT JOIN pg_catalog.pg_am am ON am.oid=r.relam
),
constraint_facts AS (
 SELECT rn.nspname AS schema_name,r.relname,c.conname,c.contype,
 pg_catalog.jsonb_build_object(
  'oidRaw',c.oid::text,
  'relation',pg_catalog.jsonb_build_object('oidRaw',r.oid::text,'schema',rn.nspname,'name',r.relname),
  'name',c.conname,'kind',c.contype::text,
  'namespace',(SELECT ns.nspname FROM pg_catalog.pg_namespace ns WHERE ns.oid=c.connamespace),
  'validated',c.convalidated,'deferrable',c.condeferrable,'deferred',c.condeferred,
  'local',c.conislocal,'inheritanceCount',c.coninhcount,'noInherit',c.connoinherit,
  'hasParent',c.conparentid<>0,
  'columns',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'ordinal',k.ordinal,'attributeNumber',k.attnum,'name',a.attname)
    ORDER BY k.ordinal),'[]'::jsonb)
   FROM pg_catalog.unnest(c.conkey) WITH ORDINALITY AS k(attnum,ordinal)
   LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
  ),
  'definition',pg_catalog.pg_get_constraintdef(c.oid,false),
  'supportingIndex',CASE WHEN c.conindid=0 THEN NULL ELSE (
   SELECT pg_catalog.jsonb_build_object('oidRaw',ic.oid::text,'schema',ns.nspname,'name',ic.relname)
   FROM pg_catalog.pg_class ic JOIN pg_catalog.pg_namespace ns ON ns.oid=ic.relnamespace WHERE ic.oid=c.conindid
  ) END,
  'reference',CASE WHEN c.contype<>'f' THEN NULL ELSE (
   SELECT pg_catalog.jsonb_build_object(
    'relation',pg_catalog.jsonb_build_object('oidRaw',rr.oid::text,'schema',nn.nspname,'name',rr.relname),
    'columns',(
     SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'ordinal',k.ordinal,'attributeNumber',k.attnum,'name',a.attname) ORDER BY k.ordinal),'[]'::jsonb)
     FROM pg_catalog.unnest(c.confkey) WITH ORDINALITY AS k(attnum,ordinal)
     LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum
    ),
    'updateAction',c.confupdtype::text,'deleteAction',c.confdeltype::text,'match',c.confmatchtype::text,
    'deleteSetColumns',c.confdelsetcols,
    'referencedKeys',(
     SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'oidRaw',p.oid::text,'name',p.conname,'kind',p.contype::text,
      'validated',p.convalidated,'deferrable',p.condeferrable,'deferred',p.condeferred,
      'indexOidRaw',p.conindid::text,'definition',pg_catalog.pg_get_constraintdef(p.oid,false))
      ORDER BY p.conname COLLATE pg_catalog."C",p.contype::text COLLATE pg_catalog."C"),'[]'::jsonb)
     FROM pg_catalog.pg_constraint p
     WHERE p.conrelid=c.confrelid AND p.conindid=c.conindid AND p.contype IN ('p','u')
    )
   )
   FROM pg_catalog.pg_class rr JOIN pg_catalog.pg_namespace nn ON nn.oid=rr.relnamespace
   WHERE rr.oid=c.confrelid
  ) END,
  'foreignEqualityOperators',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'family',k.family,'ordinal',u.ordinal,'oidRaw',op.oid::text,
    'schema',ons.nspname,'name',op.oprname,
    'leftType',pg_catalog.format_type(op.oprleft,NULL),'rightType',pg_catalog.format_type(op.oprright,NULL),
    'resultType',pg_catalog.format_type(op.oprresult,NULL),
    'function',pg_catalog.jsonb_build_object('oidRaw',p.oid::text,'schema',pn.nspname,'name',p.proname,
      'arguments',pg_catalog.pg_get_function_identity_arguments(p.oid)))
    ORDER BY k.family COLLATE pg_catalog."C",u.ordinal),'[]'::jsonb)
   FROM (VALUES ('pkFk'::text,c.conpfeqop),('pkPk'::text,c.conppeqop),('fkFk'::text,c.conffeqop)) k(family,operators)
   CROSS JOIN LATERAL pg_catalog.unnest(k.operators) WITH ORDINALITY u(operator_oid,ordinal)
   LEFT JOIN pg_catalog.pg_operator op ON op.oid=u.operator_oid
   LEFT JOIN pg_catalog.pg_namespace ons ON ons.oid=op.oprnamespace
   LEFT JOIN pg_catalog.pg_proc p ON p.oid=op.oprcode
   LEFT JOIN pg_catalog.pg_namespace pn ON pn.oid=p.pronamespace
  )
 ) AS facts
 FROM constraints_scope c JOIN pg_catalog.pg_class r ON r.oid=c.conrelid
 JOIN pg_catalog.pg_namespace rn ON rn.oid=r.relnamespace
 WHERE c.contype<>'n'
),
index_facts AS (
 SELECT n.nspname AS schema_name,c.relname,
 pg_catalog.jsonb_build_object(
  'identity',pg_catalog.jsonb_build_object('oidRaw',c.oid::text,'schema',n.nspname,'name',c.relname),
  'relation',pg_catalog.jsonb_build_object('oidRaw',r.oid::text,'schema',rn.nspname,'name',r.relname),
  'ownerOidRaw',c.relowner::text,'aclIsNull',c.relacl IS NULL,
  'rawAcl',CASE WHEN c.relacl IS NULL THEN NULL ELSE (
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'grantorOidRaw',a.grantor::text,'granteeOidRaw',a.grantee::text,
    'privilege',a.privilege_type,'grantable',a.is_grantable)
    ORDER BY a.grantor,a.grantee,a.privilege_type COLLATE pg_catalog."C",a.is_grantable),'[]'::jsonb)
   FROM pg_catalog.aclexplode(c.relacl) a
  ) END,
  'kind',c.relkind::text,'persistence',c.relpersistence::text,'options',c.reloptions,'accessMethod',am.amname,
  'primary',i.indisprimary,'unique',i.indisunique,'nullsNotDistinct',i.indnullsnotdistinct,
  'exclusion',i.indisexclusion,'immediate',i.indimmediate,'clustered',i.indisclustered,
  'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive,'checkXmin',i.indcheckxmin,
  'replicaIdentity',i.indisreplident,'keyCount',i.indnkeyatts,'attributeCount',i.indnatts,
  'keys',i.indkey::text,'optionsPerKey',i.indoption::text,
  'predicate',pg_catalog.pg_get_expr(i.indpred,i.indrelid,false),
  'expressions',pg_catalog.pg_get_expr(i.indexprs,i.indrelid,false),
  'definition',pg_catalog.pg_get_indexdef(i.indexrelid,0,false),
  'collations',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'ordinal',u.ordinal,'collation',CASE WHEN u.collation_oid=0 THEN NULL ELSE pg_catalog.jsonb_build_object(
      'oidRaw',co.oid::text,'schema',ns.nspname,'name',co.collname,
      'provider',co.collprovider::text,'deterministic',co.collisdeterministic,'encoding',co.collencoding) END)
    ORDER BY u.ordinal),'[]'::jsonb)
   FROM pg_catalog.unnest(i.indcollation::pg_catalog.oid[]) WITH ORDINALITY u(collation_oid,ordinal)
   LEFT JOIN pg_catalog.pg_collation co ON co.oid=u.collation_oid
   LEFT JOIN pg_catalog.pg_namespace ns ON ns.oid=co.collnamespace
  ),
  'operatorClasses',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'ordinal',u.ordinal,'oidRaw',oc.oid::text,'schema',ns.nspname,'name',oc.opcname,
    'accessMethod',oam.amname,'default',oc.opcdefault,
    'inputType',pg_catalog.format_type(oc.opcintype,NULL),
    'keyType',CASE WHEN oc.opckeytype=0 THEN NULL ELSE pg_catalog.format_type(oc.opckeytype,NULL) END,
    'family',pg_catalog.jsonb_build_object('oidRaw',f.oid::text,'schema',fn.nspname,'name',f.opfname))
    ORDER BY u.ordinal),'[]'::jsonb)
   FROM pg_catalog.unnest(i.indclass::pg_catalog.oid[]) WITH ORDINALITY u(opclass_oid,ordinal)
   LEFT JOIN pg_catalog.pg_opclass oc ON oc.oid=u.opclass_oid
   LEFT JOIN pg_catalog.pg_namespace ns ON ns.oid=oc.opcnamespace
   LEFT JOIN pg_catalog.pg_am oam ON oam.oid=oc.opcmethod
   LEFT JOIN pg_catalog.pg_opfamily f ON f.oid=oc.opcfamily
   LEFT JOIN pg_catalog.pg_namespace fn ON fn.oid=f.opfnamespace
  )
 ) AS facts
 FROM indexes_scope i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 JOIN pg_catalog.pg_class r ON r.oid=i.indrelid
 JOIN pg_catalog.pg_namespace rn ON rn.oid=r.relnamespace
 LEFT JOIN pg_catalog.pg_am am ON am.oid=c.relam
),
trigger_facts AS (
 SELECT rn.nspname AS schema_name,r.relname,t.tgname,
 pg_catalog.jsonb_build_object(
  'oidRaw',t.oid::text,'name',t.tgname,'definition',pg_catalog.pg_get_triggerdef(t.oid,false),
  'relation',pg_catalog.jsonb_build_object('oidRaw',r.oid::text,'schema',rn.nspname,'name',r.relname),
  'internal',t.tgisinternal,'enabled',t.tgenabled::text,'type',t.tgtype::integer,
  'hasParent',t.tgparentid<>0,'deferrable',t.tgdeferrable,'deferred',t.tginitdeferred,
  'argumentCount',t.tgnargs,'columns',t.tgattr::text,'argumentsHex',pg_catalog.encode(t.tgargs,'hex'),
  'conditionIsNull',t.tgqual IS NULL,'conditionTreeRaw',t.tgqual::text,
  -- OLD/NEW WHEN is deparsed by pg_get_triggerdef above, never pg_get_expr.
  'oldTransition',t.tgoldtable,'newTransition',t.tgnewtable,
  'constraintOidRaw',t.tgconstraint::text,
  'constraint',CASE WHEN t.tgconstraint=0 THEN NULL ELSE (
   SELECT pg_catalog.jsonb_build_object('oidRaw',cc.oid::text,'name',cc.conname,'kind',cc.contype::text,
    'relation',pg_catalog.jsonb_build_object('oidRaw',cr.oid::text,'schema',cn.nspname,'name',cr.relname))
   FROM pg_catalog.pg_constraint cc JOIN pg_catalog.pg_class cr ON cr.oid=cc.conrelid
   JOIN pg_catalog.pg_namespace cn ON cn.oid=cr.relnamespace WHERE cc.oid=t.tgconstraint
  ) END,
  'constraintRelation',CASE WHEN t.tgconstrrelid=0 THEN NULL ELSE (
   SELECT pg_catalog.jsonb_build_object('oidRaw',cr.oid::text,'schema',cn.nspname,'name',cr.relname)
   FROM pg_catalog.pg_class cr JOIN pg_catalog.pg_namespace cn ON cn.oid=cr.relnamespace WHERE cr.oid=t.tgconstrrelid
  ) END,
  'constraintIndex',CASE WHEN t.tgconstrindid=0 THEN NULL ELSE (
   SELECT pg_catalog.jsonb_build_object('oidRaw',ic.oid::text,'schema',ns.nspname,'name',ic.relname)
   FROM pg_catalog.pg_class ic JOIN pg_catalog.pg_namespace ns ON ns.oid=ic.relnamespace WHERE ic.oid=t.tgconstrindid
  ) END,
  'function',pg_catalog.jsonb_build_object('oidRaw',p.oid::text,'schema',pn.nspname,'name',p.proname,
    'arguments',pg_catalog.pg_get_function_identity_arguments(p.oid),'kind',p.prokind::text)
 ) AS facts
 FROM triggers_scope t JOIN pg_catalog.pg_class r ON r.oid=t.tgrelid
 JOIN pg_catalog.pg_namespace rn ON rn.oid=r.relnamespace
 JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
 JOIN pg_catalog.pg_namespace pn ON pn.oid=p.pronamespace
),
function_facts AS (
 SELECT n.nspname AS schema_name,p.proname,
 pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_arguments,
 pg_catalog.jsonb_build_object(
  'identity',pg_catalog.jsonb_build_object('oidRaw',p.oid::text,'schema',n.nspname,'name',p.proname,
    'arguments',pg_catalog.pg_get_function_identity_arguments(p.oid)),
  'isSyncFunction',n.nspname='openbot_internal' AND p.proname='sync_custom_model_catalog',
  'ownerOidRaw',p.proowner::text,'aclIsNull',p.proacl IS NULL,
  'rawAcl',CASE WHEN p.proacl IS NULL THEN NULL ELSE (
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'grantorOidRaw',a.grantor::text,'granteeOidRaw',a.grantee::text,
    'privilege',a.privilege_type,'grantable',a.is_grantable)
    ORDER BY a.grantor,a.grantee,a.privilege_type COLLATE pg_catalog."C",a.is_grantable),'[]'::jsonb)
   FROM pg_catalog.aclexplode(p.proacl) a
  ) END,
  'acl',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'grantorOidRaw',a.grantor::text,'granteeOidRaw',a.grantee::text,
    'privilege',a.privilege_type,'grantable',a.is_grantable)
    ORDER BY a.grantor,a.grantee,a.privilege_type COLLATE pg_catalog."C",a.is_grantable),'[]'::jsonb)
   FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f'::pg_catalog."char",p.proowner))) a
  ),
  'kind',p.prokind::text,'language',l.lanname,'securityDefiner',p.prosecdef,
  'configuration',p.proconfig,'volatility',p.provolatile::text,'parallel',p.proparallel::text,
  'strict',p.proisstrict,'leakproof',p.proleakproof,'setReturning',p.proretset,
  'returnType',pg_catalog.jsonb_build_object('oidRaw',rt.oid::text,'schema',rtn.nspname,'name',rt.typname,
    'formatted',pg_catalog.format_type(p.prorettype,NULL)),
  'inputArgumentCount',p.pronargs,'defaultArgumentCount',p.pronargdefaults,
  'inputTypes',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'ordinal',u.ordinal,'oidRaw',ty.oid::text,'schema',ns.nspname,'name',ty.typname)
    ORDER BY u.ordinal),'[]'::jsonb)
   FROM pg_catalog.unnest(p.proargtypes::pg_catalog.oid[]) WITH ORDINALITY u(type_oid,ordinal)
   LEFT JOIN pg_catalog.pg_type ty ON ty.oid=u.type_oid
   LEFT JOIN pg_catalog.pg_namespace ns ON ns.oid=ty.typnamespace
  ),
  'allArgumentTypesIsNull',p.proallargtypes IS NULL,
  'allArgumentTypes',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'ordinal',u.ordinal,'oidRaw',ty.oid::text,'schema',ns.nspname,'name',ty.typname)
    ORDER BY u.ordinal),'[]'::jsonb)
   FROM pg_catalog.unnest(p.proallargtypes) WITH ORDINALITY u(type_oid,ordinal)
   LEFT JOIN pg_catalog.pg_type ty ON ty.oid=u.type_oid
   LEFT JOIN pg_catalog.pg_namespace ns ON ns.oid=ty.typnamespace
  ),
  'argumentModes',p.proargmodes::text[],'argumentNames',p.proargnames,
  'argumentDefaults',pg_catalog.pg_get_expr(p.proargdefaults,0::pg_catalog.oid,false),
  'variadicType',CASE WHEN p.provariadic=0 THEN NULL ELSE pg_catalog.format_type(p.provariadic,NULL) END,
  'supportFunction',CASE WHEN p.prosupport=0 THEN NULL ELSE (
   SELECT pg_catalog.jsonb_build_object('oidRaw',s.oid::text,'schema',sn.nspname,'name',s.proname,
     'arguments',pg_catalog.pg_get_function_identity_arguments(s.oid))
   FROM pg_catalog.pg_proc s JOIN pg_catalog.pg_namespace sn ON sn.oid=s.pronamespace WHERE s.oid=p.prosupport
  ) END,
  'transformTypesIsNull',p.protrftypes IS NULL,
  'transformTypes',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'ordinal',u.ordinal,'oidRaw',ty.oid::text,'schema',ns.nspname,'name',ty.typname)
    ORDER BY u.ordinal),'[]'::jsonb)
   FROM pg_catalog.unnest(p.protrftypes) WITH ORDINALITY u(type_oid,ordinal)
   LEFT JOIN pg_catalog.pg_type ty ON ty.oid=u.type_oid
   LEFT JOIN pg_catalog.pg_namespace ns ON ns.oid=ty.typnamespace
  ),
  'cost',p.procost,'rows',p.prorows,
  'source',p.prosrc,'binary',p.probin,'sqlBody',p.prosqlbody::text,
  'definition',CASE WHEN p.prokind IN ('f','p') THEN pg_catalog.pg_get_functiondef(p.oid) ELSE NULL END
 ) AS facts
 FROM functions_scope p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 JOIN pg_catalog.pg_language l ON l.oid=p.prolang
 JOIN pg_catalog.pg_type rt ON rt.oid=p.prorettype
 JOIN pg_catalog.pg_namespace rtn ON rtn.oid=rt.typnamespace
)
SELECT pg_catalog.jsonb_build_object(
 'format','thread-history-admission-raw-v1',
 'storage',pg_catalog.jsonb_build_object(
  'serverEncoding',pg_catalog.current_setting('server_encoding'),
  'blockSize',pg_catalog.current_setting('block_size')::integer,
  'serverVersion',pg_catalog.current_setting('server_version_num')::integer),
 'deparseContextRaw',pg_catalog.jsonb_build_object(
  'searchPath',pg_catalog.current_setting('search_path'),'currentSchemas',pg_catalog.current_schemas(false)),
 'ownerAnchorRaw',(
  SELECT pg_catalog.jsonb_build_object(
   'relationOidRaw',o.relation_oid::text,'ownerOidRaw',o.owner_oid::text,
   'ownerNameRaw',pg_catalog.pg_get_userbyid(o.owner_oid),
   'ownerRoleCount',(SELECT count(*) FROM pg_catalog.pg_roles r WHERE r.oid=o.owner_oid),
   'currentUserNameRaw',CURRENT_USER::text,
   'currentUserOidRaw',(SELECT x.oid::text FROM pg_catalog.pg_roles x WHERE x.rolname=CURRENT_USER),
   'builtinTableDefaultAcl',(
    SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
     'grantorOidRaw',a.grantor::text,'granteeOidRaw',a.grantee::text,
     'privilege',a.privilege_type,'grantable',a.is_grantable)
     ORDER BY a.grantor,a.grantee,a.privilege_type COLLATE pg_catalog."C",a.is_grantable),'[]'::jsonb)
    FROM pg_catalog.aclexplode(pg_catalog.acldefault('r'::pg_catalog."char",o.owner_oid)) a
   )) FROM original_owner o
 ),
 'systemOwnerRaw',(
  SELECT pg_catalog.jsonb_build_object('ownerOidRaw',p.proowner::text,
    'ownerRoleCount',(SELECT count(*) FROM pg_catalog.pg_roles r WHERE r.oid=p.proowner))
  FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
  WHERE p.oid=1644 AND n.nspname='pg_catalog' AND p.proname='RI_FKey_check_ins'
 ),
 'builtinAnchorsRaw',pg_catalog.jsonb_build_object(
  'types',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('oidRaw',t.oid::text,'schema',n.nspname,'name',t.typname) ORDER BY t.typname COLLATE pg_catalog."C")
    FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
    WHERE n.nspname='pg_catalog' AND t.typname IN ('text','timestamptz','int2','int8','jsonb','trigger')),
  'collation',(SELECT pg_catalog.jsonb_build_object('oidRaw',c.oid::text,'schema',n.nspname,'name',c.collname)
    FROM pg_catalog.pg_collation c JOIN pg_catalog.pg_namespace n ON n.oid=c.collnamespace
    WHERE n.nspname='pg_catalog' AND c.collname='C' AND c.collencoding=-1),
  'operatorClasses',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('oidRaw',c.oid::text,'schema',n.nspname,'name',c.opcname,
    'familyOidRaw',f.oid::text,'familySchema',fn.nspname,'familyName',f.opfname)
    ORDER BY c.opcname COLLATE pg_catalog."C")
    FROM pg_catalog.pg_opclass c JOIN pg_catalog.pg_namespace n ON n.oid=c.opcnamespace
    JOIN pg_catalog.pg_am a ON a.oid=c.opcmethod JOIN pg_catalog.pg_opfamily f ON f.oid=c.opcfamily
    JOIN pg_catalog.pg_namespace fn ON fn.oid=f.opfnamespace
    WHERE n.nspname='pg_catalog' AND c.opcname IN ('text_ops','int8_ops','timestamptz_ops') AND a.amname='btree'),
  'equalityOperators',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('oidRaw',op.oid::text,'schema',ons.nspname,'name',op.oprname,
    'leftType',pg_catalog.format_type(op.oprleft,NULL),'rightType',pg_catalog.format_type(op.oprright,NULL),'resultType',pg_catalog.format_type(op.oprresult,NULL),
    'function',pg_catalog.jsonb_build_object('oidRaw',p.oid::text,'schema',pn.nspname,'name',p.proname,'arguments',pg_catalog.pg_get_function_identity_arguments(p.oid)))
    ORDER BY op.oprleft)
    FROM pg_catalog.pg_operator op JOIN pg_catalog.pg_namespace ons ON ons.oid=op.oprnamespace
    JOIN pg_catalog.pg_proc p ON p.oid=op.oprcode JOIN pg_catalog.pg_namespace pn ON pn.oid=p.pronamespace
    WHERE ons.nspname='pg_catalog' AND op.oprname='=' AND op.oprleft IN (20,25,1184) AND op.oprright=op.oprleft)

 ),
 'legacyOwnershipRaw',pg_catalog.jsonb_build_object(
  'relations',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'schema',n.nspname,'name',c.relname,'oidRaw',c.oid::text,
    'ownerOidRaw',c.relowner::text,'ownerNameRaw',pg_catalog.pg_get_userbyid(c.relowner),
    'aclIsNull',c.relacl IS NULL,
    'acl',(
     SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'grantorOidRaw',a.grantor::text,'granteeOidRaw',a.grantee::text,'privilege',a.privilege_type,'grantable',a.is_grantable)
      ORDER BY a.grantor,a.grantee,a.privilege_type COLLATE pg_catalog."C",a.is_grantable),'[]'::jsonb)
     FROM pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r'::pg_catalog."char",c.relowner))) a
    )) ORDER BY n.nspname COLLATE pg_catalog."C",c.relname COLLATE pg_catalog."C"),'[]'::jsonb)
   FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE (n.nspname='public' AND c.relname='threads')
      OR (n.nspname='openbot_internal' AND c.relname='schema_migrations')
  ),
  'namespaces',(
   SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
    'schema',n.nspname,'oidRaw',n.oid::text,'ownerOidRaw',n.nspowner::text,
    'ownerNameRaw',pg_catalog.pg_get_userbyid(n.nspowner),'aclIsNull',n.nspacl IS NULL,
    'acl',(
     SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'grantorOidRaw',a.grantor::text,'granteeOidRaw',a.grantee::text,'privilege',a.privilege_type,'grantable',a.is_grantable)
      ORDER BY a.grantor,a.grantee,a.privilege_type COLLATE pg_catalog."C",a.is_grantable),'[]'::jsonb)
     FROM pg_catalog.aclexplode(coalesce(n.nspacl,pg_catalog.acldefault('n'::pg_catalog."char",n.nspowner))) a
    )) ORDER BY n.nspname COLLATE pg_catalog."C"),'[]'::jsonb)
   FROM pg_catalog.pg_namespace n WHERE n.nspname IN ('public','openbot_internal')
  )
 ),
 'relations',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.relname COLLATE pg_catalog."C"),'[]'::jsonb) FROM relation_facts f),
 'constraints',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.relname COLLATE pg_catalog."C",f.conname COLLATE pg_catalog."C",f.contype::text COLLATE pg_catalog."C"),'[]'::jsonb) FROM constraint_facts f),
 'indexes',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.relname COLLATE pg_catalog."C"),'[]'::jsonb) FROM index_facts f),
 'triggers',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.relname COLLATE pg_catalog."C",f.tgname COLLATE pg_catalog."C"),'[]'::jsonb) FROM trigger_facts f),
 'functions',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.proname COLLATE pg_catalog."C",f.identity_arguments COLLATE pg_catalog."C"),'[]'::jsonb) FROM function_facts f)
)::text AS thread_history_raw,
NOT EXISTS (
 (SELECT p.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable
  FROM functions_scope p
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f'::pg_catalog."char",p.proowner))) a)
 EXCEPT ALL
 (SELECT p.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable
  FROM functions_scope p
  CROSS JOIN LATERAL pg_catalog.aclexplode(pg_catalog.acldefault('f'::pg_catalog."char",p.proowner)) a)
) AND NOT EXISTS (
 (SELECT p.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable
  FROM functions_scope p
  CROSS JOIN LATERAL pg_catalog.aclexplode(pg_catalog.acldefault('f'::pg_catalog."char",p.proowner)) a)
 EXCEPT ALL
 (SELECT p.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable
  FROM functions_scope p
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f'::pg_catalog."char",p.proowner))) a)
) AS function_acl_matches_builtin
 ) actual;
 -- Validate raw cardinalities and owner anchors before portable OID removal.
 v_owner := (v_raw->'ownerAnchorRaw'->>'ownerOidRaw')::pg_catalog.oid;
 v_bootstrap := (v_raw->'systemOwnerRaw'->>'ownerOidRaw')::pg_catalog.oid;
 v_base := (v_raw->'ownerAnchorRaw'->>'relationOidRaw')::pg_catalog.oid;
 IF v_owner IS NULL OR v_owner=0 OR v_base IS NULL OR v_base=0 OR
    v_bootstrap IS DISTINCT FROM 10::pg_catalog.oid OR
    v_raw->'systemOwnerRaw'->'ownerRoleCount' IS DISTINCT FROM '1'::jsonb OR
    v_raw->'ownerAnchorRaw'->'ownerRoleCount' IS DISTINCT FROM '1'::jsonb OR
    v_owner IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER) OR
    v_raw->>'format' IS DISTINCT FROM 'thread-history-admission-raw-v1' OR v_matches IS DISTINCT FROM true OR
    jsonb_array_length(v_raw->'relations')<>2 OR jsonb_array_length(v_raw->'constraints')<>25 OR
    jsonb_array_length(v_raw->'indexes')<>7 OR jsonb_array_length(v_raw->'triggers')<>17 OR
    jsonb_array_length(v_raw->'functions')<>11 OR
    v_raw->'storage'->>'serverEncoding' IS DISTINCT FROM 'UTF8' OR
    (v_raw->'storage'->>'blockSize')::integer IS DISTINCT FROM 8192 OR
    coalesce((v_raw->'storage'->>'serverVersion')::integer,0) NOT BETWEEN 170000 AND 179999 OR
    jsonb_array_length(v_raw->'legacyOwnershipRaw'->'relations')<>2 OR
    EXISTS(SELECT 1 FROM jsonb_array_elements(v_raw->'legacyOwnershipRaw'->'relations') r
      WHERE (r->>'ownerOidRaw')::pg_catalog.oid IS DISTINCT FROM v_owner) OR
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements(v_raw->'legacyOwnershipRaw'->'namespaces') n
      WHERE n->>'schema'='openbot_internal' AND (n->>'ownerOidRaw')::pg_catalog.oid=v_owner) OR
    (SELECT count(DISTINCT (r->'identity'->>'oidRaw')::pg_catalog.oid) FROM jsonb_array_elements(v_raw->'relations') r)<>2 OR
    (SELECT count(DISTINCT (r->'identity'->>'oidRaw')::pg_catalog.oid) FROM jsonb_array_elements(v_raw->'indexes') r)<>7 OR
    (SELECT count(DISTINCT (r->>'oidRaw')::pg_catalog.oid) FROM jsonb_array_elements(v_raw->'constraints') r)<>25 OR
    (SELECT count(DISTINCT (r->>'oidRaw')::pg_catalog.oid) FROM jsonb_array_elements(v_raw->'triggers') r)<>17 OR
    (SELECT count(DISTINCT (r->'identity'->>'oidRaw')::pg_catalog.oid) FROM jsonb_array_elements(v_raw->'functions') r)<>11 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
 END IF;
 IF EXISTS((SELECT k FROM jsonb_object_keys(v_raw) k) EXCEPT ALL
   (SELECT unnest(ARRAY['format','storage','deparseContextRaw','ownerAnchorRaw','systemOwnerRaw','builtinAnchorsRaw','legacyOwnershipRaw','relations','constraints','indexes','triggers','functions']))) OR
    EXISTS((SELECT unnest(ARRAY['format','storage','deparseContextRaw','ownerAnchorRaw','systemOwnerRaw','builtinAnchorsRaw','legacyOwnershipRaw','relations','constraints','indexes','triggers','functions'])) EXCEPT ALL
   (SELECT k FROM jsonb_object_keys(v_raw) k)) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
 END IF;
 -- These actual builtins are bound before removing any nested OID.
 IF jsonb_array_length(v_raw->'builtinAnchorsRaw'->'types')<>6 OR
    EXISTS(SELECT 1 FROM (VALUES ('text',25),('int2',21),('int8',20),('timestamptz',1184),('jsonb',3802),('trigger',2279)) expected(name,type_oid)
      LEFT JOIN jsonb_array_elements(v_raw->'builtinAnchorsRaw'->'types') actual
        ON actual->>'name'=expected.name AND actual->>'schema'='pg_catalog'
      WHERE (actual->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM expected.type_oid::pg_catalog.oid) OR
    v_raw->'builtinAnchorsRaw'->'collation'->>'schema' IS DISTINCT FROM 'pg_catalog' OR
    v_raw->'builtinAnchorsRaw'->'collation'->>'name' IS DISTINCT FROM 'C' OR
    coalesce((v_raw->'builtinAnchorsRaw'->'collation'->>'oidRaw')::pg_catalog.oid,0)=0 OR
    jsonb_array_length(v_raw->'builtinAnchorsRaw'->'operatorClasses')<>3 OR
    jsonb_array_length(v_raw->'builtinAnchorsRaw'->'equalityOperators')<>3 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
 END IF;
 v_schema := v_raw-ARRAY['ownerAnchorRaw','systemOwnerRaw','legacyOwnershipRaw','deparseContextRaw','storage','builtinAnchorsRaw'];
 v_schema := jsonb_set(v_schema,'{format}','"thread-history-admission-schema-v1"'::jsonb);
 FOR v_row,v_pos IN SELECT value,ordinality FROM jsonb_array_elements(v_raw->'relations') WITH ORDINALITY LOOP
  IF v_row->'identity'->>'schema' IS DISTINCT FROM 'openbot_internal' OR
     v_row->'identity'->>'name' NOT IN('thread_history_heads','thread_history_clear_intents') OR
     coalesce((v_row->'identity'->>'oidRaw')::pg_catalog.oid,0)=0 OR
     (v_row->>'ownerOidRaw')::pg_catalog.oid IS DISTINCT FROM v_owner THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
  END IF;
  FOR v_col IN SELECT value FROM jsonb_array_elements(v_row->'columns') LOOP
   SELECT ty INTO v_anchor FROM jsonb_array_elements(v_raw->'builtinAnchorsRaw'->'types') ty WHERE ty->>'name'=v_col->'type'->>'name';
   IF NOT FOUND OR v_col->'type'->>'schema' IS DISTINCT FROM 'pg_catalog' OR
      v_col->'type'->>'name' NOT IN('text','int2','int8','timestamptz') OR
      (v_col->'type'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_anchor->>'oidRaw')::pg_catalog.oid OR
      (v_col->'collation'<>'null'::jsonb AND (v_col->'collation'->>'schema' IS DISTINCT FROM 'pg_catalog' OR
        v_col->'collation'->>'name' IS DISTINCT FROM 'C' OR
        (v_col->'collation'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_raw->'builtinAnchorsRaw'->'collation'->>'oidRaw')::pg_catalog.oid)) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
  END LOOP;
  IF EXISTS((SELECT (a->>'grantorOidRaw')::pg_catalog.oid,(a->>'granteeOidRaw')::pg_catalog.oid,a->>'privilege',(a->>'grantable')::boolean FROM jsonb_array_elements(v_row->'acl') a)
       EXCEPT ALL (SELECT grantor,grantee,privilege_type,is_grantable FROM pg_catalog.aclexplode(pg_catalog.acldefault('r'::pg_catalog."char",v_owner)))) OR
     EXISTS((SELECT grantor,grantee,privilege_type,is_grantable FROM pg_catalog.aclexplode(pg_catalog.acldefault('r'::pg_catalog."char",v_owner)))
       EXCEPT ALL (SELECT (a->>'grantorOidRaw')::pg_catalog.oid,(a->>'granteeOidRaw')::pg_catalog.oid,a->>'privilege',(a->>'grantable')::boolean FROM jsonb_array_elements(v_row->'acl') a)) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
  END IF;
  SELECT jsonb_agg(jsonb_build_object('grantor','original_threads_owner','grantee','original_threads_owner',
   'privilege',a->>'privilege','grantable',(a->>'grantable')::boolean) ORDER BY a->>'privilege' COLLATE pg_catalog."C") INTO v_acl FROM jsonb_array_elements(v_row->'acl') a;
  IF (v_row->>'aclIsNull')::boolean THEN
   IF v_row->'rawAcl' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid'; END IF;
   v_state:=jsonb_build_object('aclIsNull',true,'rawAcl',NULL);
  ELSE
   IF EXISTS((SELECT x FROM jsonb_array_elements(v_row->'rawAcl') x) EXCEPT ALL (SELECT x FROM jsonb_array_elements(v_row->'acl') x)) OR
      EXISTS((SELECT x FROM jsonb_array_elements(v_row->'acl') x) EXCEPT ALL (SELECT x FROM jsonb_array_elements(v_row->'rawAcl') x)) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
   v_state:=jsonb_build_object('aclIsNull',false,'rawAcl',v_acl);
  END IF;
  IF (SELECT count(*) FROM jsonb_array_elements(v_expected->'allowedTableAclStates') s WHERE s=v_state)<>1 THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
  END IF;
  v_schema:=jsonb_set(v_schema,ARRAY['relations',(v_pos-1)::text],(v_row-ARRAY['aclIsNull','rawAcl'])||jsonb_build_object('ownerIsOriginal',true,'acl',v_acl));
 END LOOP;
 FOR v_row,v_pos IN SELECT value,ordinality FROM jsonb_array_elements(v_raw->'indexes') WITH ORDINALITY LOOP
  SELECT r INTO v_table FROM jsonb_array_elements(v_raw->'relations') r WHERE r->'identity'->>'schema'=v_row->'relation'->>'schema' AND r->'identity'->>'name'=v_row->'relation'->>'name';
  IF NOT FOUND OR coalesce((v_row->'identity'->>'oidRaw')::pg_catalog.oid,0)=0 OR
     (v_row->>'ownerOidRaw')::pg_catalog.oid IS DISTINCT FROM v_owner OR
     (v_row->'relation'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_table->'identity'->>'oidRaw')::pg_catalog.oid OR
     jsonb_typeof(v_row->'checkXmin') IS DISTINCT FROM 'boolean' OR
     jsonb_array_length(v_row->'operatorClasses') IS DISTINCT FROM (v_row->>'keyCount')::integer OR
     jsonb_array_length(v_row->'collations') IS DISTINCT FROM (v_row->>'keyCount')::integer THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
  END IF;
  FOR v_class IN SELECT value FROM jsonb_array_elements(v_row->'operatorClasses') LOOP
   v_attr:=(split_part(v_row->>'keys',' ',(v_class->>'ordinal')::integer))::smallint;
   SELECT c INTO v_col FROM jsonb_array_elements(v_table->'columns') c WHERE (c->>'ordinal')::smallint=v_attr;
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid'; END IF;
   v_key:=CASE v_col->'type'->>'name' WHEN 'text' THEN 'text_ops' WHEN 'int8' THEN 'int8_ops' WHEN 'timestamptz' THEN 'timestamptz_ops' ELSE NULL END;
   SELECT c INTO v_anchor FROM jsonb_array_elements(v_raw->'builtinAnchorsRaw'->'operatorClasses') c WHERE c->>'schema'='pg_catalog' AND c->>'name'=v_key;
   IF NOT FOUND OR v_class->>'schema' IS DISTINCT FROM 'pg_catalog' OR v_class->>'name' IS DISTINCT FROM v_key OR
      (v_class->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_anchor->>'oidRaw')::pg_catalog.oid OR
      (v_class->'family'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_anchor->>'familyOidRaw')::pg_catalog.oid OR
      v_class->'family'->>'schema' IS DISTINCT FROM v_anchor->>'familySchema' OR
      v_class->'family'->>'name' IS DISTINCT FROM v_anchor->>'familyName' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
   SELECT c->'collation' INTO v_collation FROM jsonb_array_elements(v_row->'collations') c WHERE c->'ordinal'=v_class->'ordinal';
   IF NOT FOUND OR (v_key='text_ops' AND (v_collation->>'schema' IS DISTINCT FROM 'pg_catalog' OR v_collation->>'name' IS DISTINCT FROM 'C' OR
      (v_collation->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_raw->'builtinAnchorsRaw'->'collation'->>'oidRaw')::pg_catalog.oid)) OR
      (v_key<>'text_ops' AND v_collation IS DISTINCT FROM 'null'::jsonb) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
  END LOOP;
  v_schema:=jsonb_set(v_schema,ARRAY['indexes',(v_pos-1)::text],v_row||jsonb_build_object('ownerIsOriginal',true,'checkXmin',jsonb_build_object('predicate','pg17_hot_runtime_boolean_v1')));
 END LOOP;
 -- Bind complete constraint graph, supporting/referring indexes, attribute names and equality builtins.
 FOR v_row IN SELECT value FROM jsonb_array_elements(v_raw->'constraints') LOOP
  SELECT r INTO v_table FROM jsonb_array_elements(v_raw->'relations') r WHERE r->'identity'->>'schema'=v_row->'relation'->>'schema' AND r->'identity'->>'name'=v_row->'relation'->>'name';
  IF NOT FOUND OR coalesce((v_row->>'oidRaw')::pg_catalog.oid,0)=0 OR
     (v_row->'relation'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_table->'identity'->>'oidRaw')::pg_catalog.oid THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
  END IF;
  FOR v_col IN SELECT value FROM jsonb_array_elements(v_row->'columns') LOOP
   IF NOT (EXISTS(SELECT 1 FROM jsonb_array_elements(v_table->'columns') c WHERE c->'ordinal'=v_col->'attributeNumber' AND c->>'name'=v_col->>'name')) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
  END LOOP;
  IF v_row->'supportingIndex'<>'null'::jsonb THEN
   SELECT i INTO v_index FROM jsonb_array_elements(v_raw->'indexes') i WHERE i->'identity'->>'schema'=v_row->'supportingIndex'->>'schema' AND i->'identity'->>'name'=v_row->'supportingIndex'->>'name';
   IF NOT FOUND OR (v_index->'identity'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_row->'supportingIndex'->>'oidRaw')::pg_catalog.oid THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
  END IF;
  IF v_row->>'kind'='f' THEN
   SELECT r INTO v_ref FROM jsonb_array_elements(v_raw->'relations') r WHERE r->'identity'->>'schema'=v_row->'reference'->'relation'->>'schema' AND r->'identity'->>'name'=v_row->'reference'->'relation'->>'name';
   IF NOT FOUND OR (v_ref->'identity'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_row->'reference'->'relation'->>'oidRaw')::pg_catalog.oid THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
   FOR v_col IN SELECT value FROM jsonb_array_elements(v_row->'reference'->'columns') LOOP
    IF NOT (EXISTS(SELECT 1 FROM jsonb_array_elements(v_ref->'columns') c WHERE c->'ordinal'=v_col->'attributeNumber' AND c->>'name'=v_col->>'name')) THEN
     RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
    END IF;
   END LOOP;
   FOR v_col IN SELECT value FROM jsonb_array_elements(v_row->'reference'->'referencedKeys') LOOP
    IF NOT (EXISTS(SELECT 1 FROM jsonb_array_elements(v_raw->'constraints') c WHERE c->'relation'->>'schema'=v_ref->'identity'->>'schema' AND c->'relation'->>'name'=v_ref->'identity'->>'name'
       AND c->>'name'=v_col->>'name' AND (c->>'oidRaw')::pg_catalog.oid=(v_col->>'oidRaw')::pg_catalog.oid
       AND (c->'supportingIndex'->>'oidRaw')::pg_catalog.oid=(v_col->>'indexOidRaw')::pg_catalog.oid
       AND c->>'kind'=v_col->>'kind' AND c->>'definition'=v_col->>'definition')) THEN
     RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
    END IF;
   END LOOP;
  END IF;
  FOR v_col IN SELECT value FROM jsonb_array_elements(v_row->'foreignEqualityOperators') LOOP
   SELECT c INTO v_anchor FROM jsonb_array_elements(v_raw->'builtinAnchorsRaw'->'equalityOperators') c WHERE c->>'leftType'=v_col->>'leftType' AND c->>'rightType'=v_col->>'rightType';
   IF NOT FOUND OR v_col->>'schema' IS DISTINCT FROM 'pg_catalog' OR v_col->>'name' IS DISTINCT FROM '=' OR v_col->>'resultType' IS DISTINCT FROM 'boolean' OR
      (v_col->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_anchor->>'oidRaw')::pg_catalog.oid OR
      (v_col->'function'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_anchor->'function'->>'oidRaw')::pg_catalog.oid OR
      (v_col->'function'-'oidRaw') IS DISTINCT FROM (v_anchor->'function'-'oidRaw') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
  END LOOP;
 END LOOP;
 -- Seven original-owner functions and four registered actual PG17 bootstrap functions.
 FOR v_row,v_pos IN SELECT value,ordinality FROM jsonb_array_elements(v_raw->'functions') WITH ORDINALITY LOOP
  IF v_row->'identity'->>'schema'='openbot_internal' THEN
   v_role_owner:=v_owner; v_label:='original_threads_owner';
   IF coalesce((v_row->'identity'->>'oidRaw')::pg_catalog.oid,0)=0 THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
  ELSIF v_row->'identity'->>'schema'='pg_catalog' THEN
   v_role_owner:=v_bootstrap; v_label:='original_pg17_bootstrap_owner';
   v_oid:=CASE v_row->'identity'->>'name' WHEN 'RI_FKey_check_ins' THEN 1644 WHEN 'RI_FKey_check_upd' THEN 1645 WHEN 'RI_FKey_noaction_del' THEN 1654 WHEN 'RI_FKey_noaction_upd' THEN 1655 ELSE 0 END;
   IF v_oid=0 OR (v_row->'identity'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM v_oid THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
  ELSE RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
  END IF;
  IF (v_row->>'ownerOidRaw')::pg_catalog.oid IS DISTINCT FROM v_role_owner OR
     (v_row->'returnType'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM 2279::pg_catalog.oid OR
     EXISTS(SELECT 1 FROM jsonb_array_elements(v_row->'acl') a WHERE (a->>'grantorOidRaw')::pg_catalog.oid IS DISTINCT FROM v_role_owner OR (a->>'granteeOidRaw')::pg_catalog.oid NOT IN(0,v_role_owner)) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
  END IF;
  SELECT jsonb_agg(jsonb_build_object('grantor',v_label,'grantee',CASE WHEN (a->>'granteeOidRaw')::pg_catalog.oid=0 THEN 'PUBLIC' ELSE v_label END,
    'privilege',a->>'privilege','grantable',(a->>'grantable')::boolean) ORDER BY (a->>'granteeOidRaw')::pg_catalog.oid,a->>'privilege' COLLATE pg_catalog."C") INTO v_acl FROM jsonb_array_elements(v_row->'acl') a;
  IF (v_row->>'aclIsNull')::boolean THEN
   IF v_row->'rawAcl' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid'; END IF;
   v_raw_acl:='null'::jsonb;
  ELSE
   IF EXISTS((SELECT x FROM jsonb_array_elements(v_row->'rawAcl') x) EXCEPT ALL (SELECT x FROM jsonb_array_elements(v_row->'acl') x)) OR
      EXISTS((SELECT x FROM jsonb_array_elements(v_row->'acl') x) EXCEPT ALL (SELECT x FROM jsonb_array_elements(v_row->'rawAcl') x)) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
   v_raw_acl:=v_acl;
  END IF;
  v_schema:=jsonb_set(v_schema,ARRAY['functions',(v_pos-1)::text],v_row||jsonb_build_object('ownerRef',v_label,'acl',v_acl,'rawAcl',v_raw_acl));
 END LOOP;
 -- Bind every trigger to its actual relation/function/constraint/index before names normalize.
 FOR v_row,v_pos IN SELECT value,ordinality FROM jsonb_array_elements(v_raw->'triggers') WITH ORDINALITY LOOP
  v_constraint:='null'::jsonb;
  IF v_row->'relation'->>'schema'='public' AND v_row->'relation'->>'name'='threads' THEN
   v_oid:=v_base;
  ELSE
   SELECT (r->'identity'->>'oidRaw')::pg_catalog.oid INTO v_oid FROM jsonb_array_elements(v_raw->'relations') r WHERE r->'identity'->>'schema'=v_row->'relation'->>'schema' AND r->'identity'->>'name'=v_row->'relation'->>'name';
   IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid'; END IF;
  END IF;
  SELECT f INTO v_function FROM jsonb_array_elements(v_raw->'functions') f WHERE f->'identity'->>'schema'=v_row->'function'->>'schema' AND f->'identity'->>'name'=v_row->'function'->>'name' AND f->'identity'->>'arguments'=v_row->'function'->>'arguments';
  IF NOT FOUND OR coalesce((v_row->>'oidRaw')::pg_catalog.oid,0)=0 OR
     (v_row->'relation'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM v_oid OR
     (v_row->'function'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_function->'identity'->>'oidRaw')::pg_catalog.oid THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
  END IF;
  IF (v_row->>'constraintOidRaw')::pg_catalog.oid<>0 THEN
   SELECT c INTO v_constraint FROM jsonb_array_elements(v_raw->'constraints') c WHERE c->'relation'->>'schema'=v_row->'constraint'->'relation'->>'schema' AND c->'relation'->>'name'=v_row->'constraint'->'relation'->>'name' AND c->>'name'=v_row->'constraint'->>'name';
   IF NOT FOUND OR (v_constraint->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_row->>'constraintOidRaw')::pg_catalog.oid OR
      (v_row->'constraint'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_constraint->>'oidRaw')::pg_catalog.oid OR
      (v_row->'constraint'->'relation'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_constraint->'relation'->>'oidRaw')::pg_catalog.oid OR
      v_row->'constraint'->>'kind' IS DISTINCT FROM v_constraint->>'kind' THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
  ELSIF v_row->'constraint' IS DISTINCT FROM 'null'::jsonb THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
  END IF;
  IF (v_row->>'internal')::boolean THEN
   IF coalesce((v_row->>'constraintOidRaw')::pg_catalog.oid,0)=0 OR
      v_constraint->>'kind' IS DISTINCT FROM 'f' OR v_constraint->>'name' NOT IN('thread_history_clear_intents_head_base_fkey','thread_history_heads_closed_intent_fkey') THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
   v_key:=v_row->'function'->>'name';
   IF v_key IN('RI_FKey_noaction_del','RI_FKey_noaction_upd') THEN
    v_letter:='a'; v_ref:=v_constraint->'relation'; v_table:=v_constraint->'reference'->'relation';
    v_type:=CASE v_key WHEN 'RI_FKey_noaction_del' THEN 9 ELSE 17 END;
   ELSIF v_key IN('RI_FKey_check_ins','RI_FKey_check_upd') THEN
    v_letter:='c'; v_ref:=v_constraint->'reference'->'relation'; v_table:=v_constraint->'relation';
    v_type:=CASE v_key WHEN 'RI_FKey_check_ins' THEN 5 ELSE 17 END;
   ELSE RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
   IF v_row->'function'->>'schema' IS DISTINCT FROM 'pg_catalog' OR
      (v_row->'relation'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_table->>'oidRaw')::pg_catalog.oid OR
      (v_row->'constraintRelation'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_ref->>'oidRaw')::pg_catalog.oid OR
      (v_row->'constraintIndex'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_constraint->'supportingIndex'->>'oidRaw')::pg_catalog.oid OR
      (v_row->>'type')::integer IS DISTINCT FROM v_type OR
      v_row->>'name' IS DISTINCT FROM 'RI_ConstraintTrigger_'||v_letter||'_'||(v_row->>'oidRaw') OR
      v_row->'deferrable' IS DISTINCT FROM 'true'::jsonb OR v_row->'deferred' IS DISTINCT FROM 'true'::jsonb THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
   v_normal_name:='RI_ConstraintTrigger_'||v_letter||'_<checked-trigger-oid>';
   v_prefix:='CREATE CONSTRAINT TRIGGER '||pg_catalog.quote_ident(v_row->>'name')||' ';
   IF left(v_row->>'definition',length(v_prefix)) IS DISTINCT FROM v_prefix THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
   v_schema:=jsonb_set(v_schema,ARRAY['triggers',(v_pos-1)::text],v_row||jsonb_build_object('name',v_normal_name,
     'definition','CREATE CONSTRAINT TRIGGER '||pg_catalog.quote_ident(v_normal_name)||' '||substr(v_row->>'definition',length(v_prefix)+1)));
  ELSE
   IF v_row->'constraintRelation'<>'null'::jsonb OR v_row->'constraintIndex'<>'null'::jsonb THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
   END IF;
  END IF;
 END LOOP;
 -- Only this local, fully bound comparison removes portable OIDs. Actual capture stays raw.
 FOR v_path IN WITH RECURSIVE walk(path,value) AS (
   SELECT '{}'::text[],v_schema UNION ALL
   SELECT w.path||child.key,child.value FROM walk w CROSS JOIN LATERAL (
    SELECT key,value FROM jsonb_each(CASE WHEN jsonb_typeof(w.value)='object' THEN w.value ELSE '{}'::jsonb END)
    UNION ALL SELECT (ordinality-1)::text,value FROM jsonb_array_elements(CASE WHEN jsonb_typeof(w.value)='array' THEN w.value ELSE '[]'::jsonb END) WITH ORDINALITY
   ) child
  ) SELECT path FROM walk WHERE path[cardinality(path)] IN('oidRaw','ownerOidRaw','indexOidRaw','constraintOidRaw') ORDER BY cardinality(path) DESC
 LOOP v_schema:=v_schema #- v_path; END LOOP;
 IF v_schema->>'format' IS DISTINCT FROM v_expected->'schema'->>'format' OR
    EXISTS((SELECT k FROM jsonb_object_keys(v_schema) k) EXCEPT ALL (SELECT k FROM jsonb_object_keys(v_expected->'schema') k)) OR
    EXISTS((SELECT k FROM jsonb_object_keys(v_expected->'schema') k) EXCEPT ALL (SELECT k FROM jsonb_object_keys(v_schema) k)) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
 END IF;
 FOREACH v_key IN ARRAY ARRAY['relations','constraints','indexes','triggers','functions'] LOOP
  IF EXISTS((SELECT x FROM jsonb_array_elements(v_schema->v_key) x) EXCEPT ALL (SELECT x FROM jsonb_array_elements(v_expected->'schema'->v_key) x)) OR
     EXISTS((SELECT x FROM jsonb_array_elements(v_expected->'schema'->v_key) x) EXCEPT ALL (SELECT x FROM jsonb_array_elements(v_schema->v_key) x)) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_history_admission_schema_invalid';
  END IF;
 END LOOP;
END;
$thread_history_postcondition$;
