-- Native0053: append-only restore retirement and reconfirmation PG facts.
-- A row is not a restore-owner proof, a COMMIT ACK, Current, or Ready.
-- The original private candidate producer must already hold the external owner,
-- frozen configuration inventory and its original finite operation budget.
DO $restore53_owner$
DECLARE original_owner oid; actual_owner oid;
BEGIN
 SELECT c.relowner INTO original_owner FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname='threads' AND c.relkind='r';
 SELECT oid INTO actual_owner FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER;
 IF original_owner IS NULL OR original_owner IS DISTINCT FROM actual_owner OR
    pg_catalog.getdatabaseencoding()<>'UTF8' OR NOT EXISTS (
     SELECT 1 FROM pg_catalog.pg_namespace
     WHERE nspname='openbot_internal' AND nspowner=original_owner
    ) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_schema_invalid';
 END IF;
END;
$restore53_owner$;

CREATE TABLE openbot_internal.restore_pg_operations (
 operation_id uuid NOT NULL,
 epoch bytea NOT NULL,
 candidate_generation uuid NOT NULL,
 source_bundle_id uuid NOT NULL,
 deployment_id text COLLATE pg_catalog."C" NOT NULL,
 tenant_id text COLLATE pg_catalog."C" NOT NULL,
 dataset_id text COLLATE pg_catalog."C" NOT NULL,
 source_installation_id text COLLATE pg_catalog."C" NOT NULL,
 target_installation_id text COLLATE pg_catalog."C" NOT NULL,
 candidate_database_oid oid NOT NULL,
 pg_system_identifier text NOT NULL,
 profile_binding bytea NOT NULL,
 max_batches bigint NOT NULL,
 max_requirements bigint NOT NULL,
 xact_id xid8 DEFAULT pg_catalog.pg_current_xact_id() NOT NULL,
 recorded_at timestamptz DEFAULT pg_catalog.clock_timestamp() NOT NULL,
 CONSTRAINT restore_pg_operations_pkey PRIMARY KEY(operation_id),
 CONSTRAINT restore_pg_operations_epoch_key UNIQUE(epoch),
 CONSTRAINT restore_pg_operations_operation_epoch_key UNIQUE(operation_id,epoch),
 CONSTRAINT restore_pg_operations_candidate_epoch_key UNIQUE(candidate_generation,epoch),
 CONSTRAINT restore_pg_operations_uuid_check CHECK(
  operation_id<>'00000000-0000-0000-0000-000000000000'::uuid AND
  candidate_generation<>'00000000-0000-0000-0000-000000000000'::uuid AND
  source_bundle_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 CONSTRAINT restore_pg_operations_epoch_check CHECK(
  pg_catalog.octet_length(epoch)=32 AND epoch<>pg_catalog.decode(pg_catalog.repeat('00',32),'hex')),
 CONSTRAINT restore_pg_operations_binding_check CHECK(pg_catalog.octet_length(profile_binding)=32),
 CONSTRAINT restore_pg_operations_identity_check CHECK(
  pg_catalog.octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(dataset_id) BETWEEN 1 AND 512 AND dataset_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(source_installation_id) BETWEEN 1 AND 512 AND source_installation_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(target_installation_id) BETWEEN 1 AND 512 AND target_installation_id !~ U&'[\0001-\001F\007F-\009F]'),
 CONSTRAINT restore_pg_operations_pg_identity_check CHECK(candidate_database_oid<>0 AND
  pg_catalog.octet_length(pg_system_identifier) BETWEEN 1 AND 20 AND
  pg_system_identifier ~ '^[0-9]+$' AND pg_system_identifier !~ '^0+$'),
 CONSTRAINT restore_pg_operations_caps_check CHECK(max_batches>0 AND max_requirements>0),
 CONSTRAINT restore_pg_operations_time_check CHECK(pg_catalog.isfinite(recorded_at))
);

CREATE TABLE openbot_internal.restore_pg_batches (
 operation_id uuid NOT NULL,
 epoch bytea NOT NULL,
 batch_seq bigint NOT NULL,
 action text NOT NULL,
 affected_count bigint NOT NULL,
 remaining_count bigint NOT NULL,
 xact_id xid8 DEFAULT pg_catalog.pg_current_xact_id() NOT NULL,
 recorded_at timestamptz DEFAULT pg_catalog.clock_timestamp() NOT NULL,
 CONSTRAINT restore_pg_batches_pkey PRIMARY KEY(operation_id,batch_seq),
 CONSTRAINT restore_pg_batches_xact_action_key UNIQUE(operation_id,xact_id,action),
 CONSTRAINT restore_pg_batches_operation_fkey FOREIGN KEY(operation_id,epoch)
  REFERENCES openbot_internal.restore_pg_operations(operation_id,epoch)
  ON UPDATE RESTRICT ON DELETE RESTRICT NOT DEFERRABLE,
 CONSTRAINT restore_pg_batches_uuid_check CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 CONSTRAINT restore_pg_batches_epoch_check CHECK(
  pg_catalog.octet_length(epoch)=32 AND epoch<>pg_catalog.decode(pg_catalog.repeat('00',32),'hex')),
 CONSTRAINT restore_pg_batches_sequence_check CHECK(batch_seq>=1),
 CONSTRAINT restore_pg_batches_action_check CHECK(action IN(
  'auth_generation','sessions_retired','approvals_cancelled','human_decisions_cancelled',
  'leases_expired','capabilities_aborted','oauth_states_retired',
  'callback_registrations_retired','remote_interrupts_expired',
  'subject_requirements','credential_requirements')),
 CONSTRAINT restore_pg_batches_counts_check CHECK(affected_count>=0 AND remaining_count>=0),
 CONSTRAINT restore_pg_batches_time_check CHECK(pg_catalog.isfinite(recorded_at))
);

CREATE TABLE openbot_internal.restore_reconfirm_requirements (
 operation_id uuid NOT NULL,
 epoch bytea NOT NULL,
 requirement_id uuid NOT NULL,
 requirement_seq bigint NOT NULL,
 source_kind text NOT NULL,
 source_ref text COLLATE pg_catalog."C" NOT NULL,
 binding_generation bigint NOT NULL,
 source_created_at timestamptz,
 source_revision bigint,
 public_binding bytea NOT NULL,
 owner_kind text NOT NULL,
 owner_id text COLLATE pg_catalog."C" NOT NULL,
 owner_created_at timestamptz,
 xact_id xid8 DEFAULT pg_catalog.pg_current_xact_id() NOT NULL,
 recorded_at timestamptz DEFAULT pg_catalog.clock_timestamp() NOT NULL,
 CONSTRAINT restore_reconfirm_requirements_pkey PRIMARY KEY(requirement_id),
 CONSTRAINT restore_reconfirm_requirements_operation_fkey FOREIGN KEY(operation_id,epoch)
  REFERENCES openbot_internal.restore_pg_operations(operation_id,epoch)
  ON UPDATE RESTRICT ON DELETE RESTRICT NOT DEFERRABLE,
 CONSTRAINT restore_reconfirm_requirements_operation_id_key UNIQUE(operation_id,epoch,requirement_id),
 CONSTRAINT restore_reconfirm_requirements_sequence_key UNIQUE(operation_id,requirement_seq),
 CONSTRAINT restore_reconfirm_requirements_generation_key UNIQUE(operation_id,source_kind,source_ref,binding_generation),
 CONSTRAINT restore_reconfirm_requirements_uuid_check CHECK(
  operation_id<>'00000000-0000-0000-0000-000000000000'::uuid AND
  requirement_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 CONSTRAINT restore_reconfirm_requirements_epoch_check CHECK(
  pg_catalog.octet_length(epoch)=32 AND epoch<>pg_catalog.decode(pg_catalog.repeat('00',32),'hex')),
 CONSTRAINT restore_reconfirm_requirements_sequence_check CHECK(requirement_seq>=1 AND binding_generation>=0),
 CONSTRAINT restore_reconfirm_requirements_kind_check CHECK(source_kind IN(
  'subject','credential','model_secret','sdk_secret','sso_provider','config_slot')),
 CONSTRAINT restore_reconfirm_requirements_identity_check CHECK(
  pg_catalog.octet_length(source_ref) BETWEEN 1 AND 512 AND source_ref !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(owner_id) BETWEEN 1 AND 512 AND owner_id !~ U&'[\0001-\001F\007F-\009F]'),
 CONSTRAINT restore_reconfirm_requirements_source_check CHECK(
  (source_created_at IS NULL OR pg_catalog.isfinite(source_created_at)) AND
  (source_revision IS NULL OR source_revision>=0) AND
  (owner_created_at IS NULL OR pg_catalog.isfinite(owner_created_at))),
 CONSTRAINT restore_reconfirm_requirements_binding_check CHECK(pg_catalog.octet_length(public_binding)=32),
 CONSTRAINT restore_reconfirm_requirements_owner_check CHECK(owner_kind IN('actor','installation','service')),
 CONSTRAINT restore_reconfirm_requirements_time_check CHECK(pg_catalog.isfinite(recorded_at))
);
CREATE INDEX restore_reconfirm_requirements_source_idx
 ON openbot_internal.restore_reconfirm_requirements USING btree
 (operation_id,source_kind,source_ref,binding_generation DESC);

CREATE TABLE openbot_internal.restore_reconfirm_receipts (
 operation_id uuid NOT NULL,
 epoch bytea NOT NULL,
 requirement_id uuid NOT NULL,
 confirmation_id uuid NOT NULL,
 proof_ref uuid NOT NULL,
 confirmed_by text COLLATE pg_catalog."C" NOT NULL,
 proof_kind text NOT NULL,
 xact_id xid8 DEFAULT pg_catalog.pg_current_xact_id() NOT NULL,
 recorded_at timestamptz DEFAULT pg_catalog.clock_timestamp() NOT NULL,
 CONSTRAINT restore_reconfirm_receipts_pkey PRIMARY KEY(requirement_id),
 CONSTRAINT restore_reconfirm_receipts_confirmation_key UNIQUE(operation_id,confirmation_id),
 CONSTRAINT restore_reconfirm_receipts_proof_key UNIQUE(operation_id,proof_ref),
 CONSTRAINT restore_reconfirm_receipts_operation_fkey FOREIGN KEY(operation_id,epoch)
  REFERENCES openbot_internal.restore_pg_operations(operation_id,epoch)
  ON UPDATE RESTRICT ON DELETE RESTRICT NOT DEFERRABLE,
 CONSTRAINT restore_reconfirm_receipts_requirement_fkey FOREIGN KEY(operation_id,epoch,requirement_id)
  REFERENCES openbot_internal.restore_reconfirm_requirements(operation_id,epoch,requirement_id)
  ON UPDATE RESTRICT ON DELETE RESTRICT NOT DEFERRABLE,
 CONSTRAINT restore_reconfirm_receipts_uuid_check CHECK(
  operation_id<>'00000000-0000-0000-0000-000000000000'::uuid AND
  requirement_id<>'00000000-0000-0000-0000-000000000000'::uuid AND
  confirmation_id<>'00000000-0000-0000-0000-000000000000'::uuid AND
  proof_ref<>'00000000-0000-0000-0000-000000000000'::uuid),
 CONSTRAINT restore_reconfirm_receipts_epoch_check CHECK(
  pg_catalog.octet_length(epoch)=32 AND epoch<>pg_catalog.decode(pg_catalog.repeat('00',32),'hex')),
 CONSTRAINT restore_reconfirm_receipts_identity_check CHECK(
  pg_catalog.octet_length(confirmed_by) BETWEEN 1 AND 512 AND confirmed_by !~ U&'[\0001-\001F\007F-\009F]'),
 CONSTRAINT restore_reconfirm_receipts_proof_check CHECK(proof_kind IN('fresh_actor','fresh_local_os','fresh_service_operator')),
 CONSTRAINT restore_reconfirm_receipts_time_check CHECK(pg_catalog.isfinite(recorded_at))
);

CREATE TABLE openbot_internal.restore_pg_seals (
 operation_id uuid NOT NULL,
 epoch bytea NOT NULL,
 batches bigint NOT NULL,
 subject_requirements bigint NOT NULL,
 credential_requirements bigint NOT NULL,
 xact_id xid8 DEFAULT pg_catalog.pg_current_xact_id() NOT NULL,
 recorded_at timestamptz DEFAULT pg_catalog.clock_timestamp() NOT NULL,
 CONSTRAINT restore_pg_seals_pkey PRIMARY KEY(operation_id),
 CONSTRAINT restore_pg_seals_operation_fkey FOREIGN KEY(operation_id,epoch)
  REFERENCES openbot_internal.restore_pg_operations(operation_id,epoch)
  ON UPDATE RESTRICT ON DELETE RESTRICT NOT DEFERRABLE,
 CONSTRAINT restore_pg_seals_uuid_check CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 CONSTRAINT restore_pg_seals_epoch_check CHECK(
  pg_catalog.octet_length(epoch)=32 AND epoch<>pg_catalog.decode(pg_catalog.repeat('00',32),'hex')),
 CONSTRAINT restore_pg_seals_counts_check CHECK(batches>=0 AND subject_requirements>=0 AND credential_requirements>=0),
 CONSTRAINT restore_pg_seals_time_check CHECK(pg_catalog.isfinite(recorded_at))
);

CREATE FUNCTION openbot_internal.restore53_reject_mutation() RETURNS trigger
 LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE SECURITY INVOKER
 COST 100 SET search_path=pg_catalog AS $restore53_immutable$
BEGIN
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_facts_immutable';
END;
$restore53_immutable$;

CREATE FUNCTION openbot_internal.restore53_guard_insert() RETURNS trigger
 LANGUAGE plpgsql VOLATILE CALLED ON NULL INPUT PARALLEL UNSAFE SECURITY INVOKER
 COST 100 SET search_path=pg_catalog AS $restore53_insert$
DECLARE
 operation openbot_internal.restore_pg_operations%ROWTYPE;
 requirement openbot_internal.restore_reconfirm_requirements%ROWTYPE;
 live_source record;
 original_owner oid;
 current_owner oid;
 expected_seq bigint;
 previous_generation bigint;
 actual_remaining bigint;
 source_kind text;
 source_ref text;
 actual_batches bigint;
 actual_subjects bigint;
 actual_credentials bigint;
 actual_requirements bigint;
 actual_high_water bigint;
 candidate_cohort_matches boolean;
BEGIN
 IF TG_TABLE_SCHEMA<>'openbot_internal' OR TG_OP<>'INSERT' OR TG_TABLE_NAME NOT IN(
  'restore_pg_operations','restore_pg_batches','restore_reconfirm_requirements',
  'restore_reconfirm_receipts','restore_pg_seals') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_fact_invalid';
 END IF;
 IF NEW.xact_id IS DISTINCT FROM pg_catalog.pg_current_xact_id() THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_xact_invalid';
 END IF;
 NEW.recorded_at:=pg_catalog.clock_timestamp();
 SELECT c.relowner INTO original_owner FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname='threads' AND c.relkind='r';
 SELECT oid INTO current_owner FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER;
 IF original_owner IS NULL OR original_owner IS DISTINCT FROM current_owner OR
    NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace
     WHERE nspname='openbot_internal' AND nspowner=original_owner) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_owner_invalid';
 END IF;
 IF TG_TABLE_NAME='restore_pg_operations' THEN
  IF NEW.candidate_database_oid IS DISTINCT FROM (
    SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()) OR
   NEW.pg_system_identifier IS DISTINCT FROM (
    SELECT system_identifier::text FROM pg_catalog.pg_control_system()) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_database_invalid';
  END IF;
  RETURN NEW;
 END IF;
 -- Every child serializes against the same immutable original operation row.
 -- The held external candidate owner/GuardedRC supplies the absolute deadline.
 SELECT o.* INTO operation FROM openbot_internal.restore_pg_operations o
  WHERE o.operation_id=NEW.operation_id AND o.epoch=NEW.epoch FOR UPDATE OF o;
 IF NOT FOUND OR operation.candidate_database_oid IS DISTINCT FROM (
    SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()) OR
   operation.pg_system_identifier IS DISTINCT FROM (
    SELECT system_identifier::text FROM pg_catalog.pg_control_system()) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_operation_invalid';
 END IF;
 IF TG_TABLE_NAME IN('restore_pg_batches','restore_reconfirm_requirements') AND EXISTS(
  SELECT 1 FROM openbot_internal.restore_pg_seals s WHERE s.operation_id=operation.operation_id
 ) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_cohort_sealed';
 END IF;
 IF TG_TABLE_NAME='restore_pg_batches' THEN
  SELECT coalesce(pg_catalog.max(b.batch_seq),0)+1 INTO expected_seq
   FROM openbot_internal.restore_pg_batches b WHERE b.operation_id=operation.operation_id;
  IF NEW.batch_seq IS DISTINCT FROM expected_seq OR NEW.batch_seq>operation.max_batches THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_batch_sequence_invalid';
  END IF;
  -- affected_count is the original producer's mutation RETURNING count, not an
  -- authority bit. This guard independently re-queries its actual residual.
  CASE NEW.action
  WHEN 'auth_generation' THEN SELECT pg_catalog.count(*) INTO actual_remaining FROM public.users WHERE auth_generation IS NULL OR auth_generation<1;
  WHEN 'sessions_retired' THEN SELECT pg_catalog.count(*) INTO actual_remaining FROM public.sessions;
  WHEN 'approvals_cancelled' THEN SELECT pg_catalog.count(*) INTO actual_remaining FROM public.tool_approvals WHERE state='pending';
  WHEN 'human_decisions_cancelled' THEN SELECT pg_catalog.count(*) INTO actual_remaining FROM public.component_human_decisions WHERE state='pending';
  WHEN 'leases_expired' THEN SELECT pg_catalog.count(*) INTO actual_remaining FROM public.thread_leases WHERE expires_at>NEW.recorded_at;
  WHEN 'capabilities_aborted' THEN SELECT pg_catalog.count(*) INTO actual_remaining FROM public.tool_attempts WHERE status='executing' AND capability_id IS NOT NULL;
  WHEN 'oauth_states_retired' THEN SELECT pg_catalog.count(*) INTO actual_remaining FROM public.verifications;
  WHEN 'callback_registrations_retired' THEN SELECT pg_catalog.count(*) INTO actual_remaining FROM public.agent_profiles WHERE callback_token_hash IS NOT NULL OR callback_token_issued_at IS NOT NULL;
  WHEN 'remote_interrupts_expired' THEN SELECT pg_catalog.count(*) INTO actual_remaining FROM public.remote_agent_interrupts WHERE state='pending';
  WHEN 'subject_requirements','credential_requirements' THEN
   -- The whole inventory equality is authenticated again by the seal below.
   -- There is deliberately no caller-supplied "inventory_complete" flag.
   SELECT pg_catalog.count(*) INTO actual_remaining FROM (
    SELECT 'subject' AS kind,u.id AS ref FROM public.users u
    UNION ALL SELECT 'credential',c.id::text FROM public.credentials c
    UNION ALL SELECT 'model_secret',c.id::text FROM public.model_connections c
    UNION ALL SELECT 'sdk_secret',c.id::text FROM public.sdk_gateway_connections c
    UNION ALL SELECT 'sso_provider',s.id FROM public.sso_providers s
   ) inventory WHERE (inventory.kind='subject')=(NEW.action='subject_requirements') AND NOT EXISTS(
    SELECT 1 FROM openbot_internal.restore_reconfirm_requirements r
    WHERE r.operation_id=operation.operation_id AND r.source_kind=inventory.kind AND r.source_ref=inventory.ref);
  ELSE RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_batch_action_invalid';
  END CASE;
  IF NEW.remaining_count IS DISTINCT FROM actual_remaining THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_batch_residual_invalid';
  END IF;
  RETURN NEW;
 END IF;

 IF TG_TABLE_NAME='restore_reconfirm_requirements' THEN
  SELECT coalesce(pg_catalog.max(r.requirement_seq),0)+1 INTO expected_seq
   FROM openbot_internal.restore_reconfirm_requirements r WHERE r.operation_id=operation.operation_id;
  SELECT pg_catalog.max(r.binding_generation) INTO previous_generation
   FROM openbot_internal.restore_reconfirm_requirements r
   WHERE r.operation_id=operation.operation_id AND r.source_kind=NEW.source_kind AND r.source_ref=NEW.source_ref;
  IF NEW.requirement_seq IS DISTINCT FROM expected_seq OR NEW.requirement_seq>operation.max_requirements OR
     NEW.binding_generation IS DISTINCT FROM coalesce(previous_generation+1,0) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_requirement_sequence_invalid';
  END IF;
  requirement:=NEW;
 ELSIF TG_TABLE_NAME='restore_reconfirm_receipts' THEN
  SELECT r.* INTO requirement FROM openbot_internal.restore_reconfirm_requirements r
   WHERE r.operation_id=operation.operation_id AND r.epoch=operation.epoch AND r.requirement_id=NEW.requirement_id;
  IF NOT FOUND OR EXISTS(SELECT 1 FROM openbot_internal.restore_reconfirm_requirements r
   WHERE r.operation_id=operation.operation_id AND r.source_kind=requirement.source_kind
    AND r.source_ref=requirement.source_ref AND r.binding_generation>requirement.binding_generation) OR
   NEW.confirmed_by IS DISTINCT FROM requirement.owner_id OR
   NEW.proof_kind IS DISTINCT FROM (CASE requirement.owner_kind
     WHEN 'actor' THEN 'fresh_actor' WHEN 'installation' THEN 'fresh_local_os'
     WHEN 'service' THEN 'fresh_service_operator' END) OR
   (requirement.source_kind='subject' AND NEW.confirmed_by IS DISTINCT FROM requirement.source_ref) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_confirmation_invalid';
  END IF;
  -- A SQL row cannot authenticate the fresh proof or a later ACK. The original
  -- Pending/Current private producer must consume that proof before this INSERT.
 END IF;
 IF TG_TABLE_NAME IN('restore_reconfirm_requirements','restore_reconfirm_receipts') THEN
  source_kind:=requirement.source_kind; source_ref:=requirement.source_ref;
  IF source_kind='config_slot' THEN
   -- External slots are never reconstructed from these SQL rows. Only the
   -- original producer can compare its frozen external inventory and binding.
   IF requirement.source_created_at IS NOT NULL OR requirement.source_revision IS NOT NULL OR
      requirement.owner_created_at IS NOT NULL OR
      NOT ((requirement.owner_kind='installation' AND requirement.owner_id=operation.target_installation_id) OR
           (requirement.owner_kind='service' AND requirement.owner_id=operation.deployment_id)) THEN
    RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_configuration_owner_invalid';
   END IF;
   RETURN NEW;
  END IF;
  -- Public identities only: no ciphertext, secret, code, verification value,
  -- OAuth state or secret hash enters the binding or the fact tables.
  WITH credential_references AS (
   SELECT c.id,pg_catalog.jsonb_agg(ref.value ORDER BY ref.value::text COLLATE pg_catalog."C") AS refs,
    pg_catalog.min(ref.actor) AS actor,pg_catalog.count(DISTINCT ref.actor) AS actors,
    pg_catalog.bool_or(ref.actor IS NULL) AS service_reference
   FROM public.credentials c LEFT JOIN LATERAL (
    SELECT pg_catalog.jsonb_build_array('mcp_user',s.id,pg_catalog.to_char(s.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),s.url,u.user_id,u.scope) AS value,u.user_id AS actor
     FROM public.mcp_user_credentials u JOIN public.mcp_servers s ON s.id=u.server_id WHERE u.credential_id=c.id
    UNION ALL SELECT pg_catalog.jsonb_build_array('mcp_client',s.id,pg_catalog.to_char(s.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),s.url,s.added_by),s.added_by
     FROM public.mcp_servers s WHERE s.credential_id=c.id
   ) ref ON true GROUP BY c.id
  ), inventory(kind,ref,birth,revision,owner_kind,owner_id,owner_birth,public_fields) AS (
   SELECT 'subject',u.id,u.created_at,NULL::bigint,'actor',u.id,u.created_at,
    pg_catalog.jsonb_build_array(u.id,pg_catalog.to_char(u.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) FROM public.users u
   UNION ALL SELECT 'credential',c.id::text,c.created_at,NULL::bigint,
    CASE WHEN r.actors=1 AND NOT r.service_reference THEN 'actor' ELSE 'service' END,
    CASE WHEN r.actors=1 AND NOT r.service_reference THEN r.actor ELSE operation.deployment_id END,
    CASE WHEN r.actors=1 AND NOT r.service_reference THEN u.created_at ELSE NULL END,
    pg_catalog.jsonb_build_array(c.id,pg_catalog.to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),c.kind,c.provider,r.refs)
    FROM public.credentials c JOIN credential_references r ON r.id=c.id LEFT JOIN public.users u ON u.id=r.actor
    WHERE r.actors<=1 AND NOT (r.actors=1 AND r.service_reference)
   UNION ALL SELECT 'model_secret',c.id::text,c.created_at,c.revision,'actor',c.owner_user_id,u.created_at,
    pg_catalog.jsonb_build_array(c.id,pg_catalog.to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),c.revision,c.deployment_id,c.tenant_id,c.owner_user_id,c.protocol,c.endpoint,c.model)
    FROM public.model_connections c JOIN public.users u ON u.id=c.owner_user_id
    JOIN public.model_connection_secrets s ON s.id=c.current_secret_id AND s.connection_id=c.id
     AND s.deployment_id=c.deployment_id AND s.tenant_id=c.tenant_id AND s.owner_user_id=c.owner_user_id
    WHERE c.deployment_id=operation.deployment_id AND c.tenant_id=operation.tenant_id
   UNION ALL SELECT 'sdk_secret',c.id::text,c.created_at,c.revision,'actor',c.owner_user_id,u.created_at,
    pg_catalog.jsonb_build_array(c.id,pg_catalog.to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),c.revision,c.deployment_id,c.tenant_id,c.owner_user_id,c.issuer,c.client_id,c.account_id,c.organization_id)
    FROM public.sdk_gateway_connections c JOIN public.users u ON u.id=c.owner_user_id
    WHERE c.deployment_id=operation.deployment_id AND c.tenant_id=operation.tenant_id AND
     (c.current_secret_id IS NULL OR EXISTS(SELECT 1 FROM public.sdk_gateway_secrets s
      WHERE s.id=c.current_secret_id AND s.connection_id=c.id AND s.deployment_id=c.deployment_id
       AND s.tenant_id=c.tenant_id AND s.owner_user_id=c.owner_user_id AND s.credential_generation=c.credential_generation))
   UNION ALL SELECT 'sso_provider',s.id,NULL::timestamptz,NULL::bigint,
    CASE WHEN s.user_id IS NULL THEN 'service' ELSE 'actor' END,coalesce(s.user_id,operation.deployment_id),u.created_at,
    pg_catalog.jsonb_build_array(s.id,s.provider_id,s.issuer,s.organization_id,s.domain,s.user_id)
    FROM public.sso_providers s LEFT JOIN public.users u ON u.id=s.user_id
  ) SELECT i.* INTO live_source FROM inventory i WHERE i.kind=source_kind AND i.ref=source_ref;
  IF NOT FOUND OR ROW(requirement.source_created_at,requirement.source_revision,requirement.owner_kind,
    requirement.owner_id,requirement.owner_created_at,requirement.public_binding) IS DISTINCT FROM
    ROW(live_source.birth,live_source.revision,live_source.owner_kind,live_source.owner_id,live_source.owner_birth,
     pg_catalog.sha256(pg_catalog.convert_to('wrokbot.restore.public-binding.v1'||chr(10)||
      pg_catalog.jsonb_build_array(source_kind,live_source.public_fields)::text,'UTF8'))) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_source_binding_invalid';
  END IF;
  IF TG_TABLE_NAME='restore_reconfirm_receipts' AND source_kind='sdk_secret' AND NOT EXISTS(
   SELECT 1 FROM public.sdk_gateway_connections c JOIN public.users u ON u.id=c.owner_user_id
   WHERE c.id::text=source_ref AND c.enabled AND c.deleted_at IS NULL AND c.state='ready'
    AND c.pending_operation_id IS NULL AND c.auth_generation=coalesce(u.auth_generation,0)
  ) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_sdk_confirmation_invalid';
  END IF;
  RETURN NEW;
 END IF;

 -- Only the PG half of closure is recorded here. Neither this seal nor its
 -- counts replaces original external inventory, RAM/worker/lock closure,
 -- confirmed credential gates, true ACK/readback or Current publication.
 IF EXISTS(SELECT 1 FROM public.sessions) OR
    EXISTS(SELECT 1 FROM public.users WHERE auth_generation IS NULL OR auth_generation<1) OR
    EXISTS(SELECT 1 FROM public.tool_approvals WHERE state='pending') OR
    EXISTS(SELECT 1 FROM public.component_human_decisions WHERE state='pending') OR
    EXISTS(SELECT 1 FROM public.thread_leases WHERE expires_at>NEW.recorded_at) OR
    EXISTS(SELECT 1 FROM public.tool_attempts WHERE status='executing' AND capability_id IS NOT NULL) OR
    EXISTS(SELECT 1 FROM public.verifications) OR
    EXISTS(SELECT 1 FROM public.agent_profiles WHERE callback_token_hash IS NOT NULL OR callback_token_issued_at IS NOT NULL) OR
    EXISTS(SELECT 1 FROM public.remote_agent_interrupts WHERE state='pending') THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_retirement_incomplete';
 END IF;
 -- The schema has no external configuration table; it must not invent one or
 -- treat requirement rows as the independent external inventory. That separate
 -- closure is enforced by the original producer before accepting this PG fact.
 WITH credential_references AS (
  SELECT c.id,pg_catalog.jsonb_agg(ref.value ORDER BY ref.value::text COLLATE pg_catalog."C") AS refs,
   pg_catalog.min(ref.actor) AS actor,pg_catalog.count(DISTINCT ref.actor) AS actors,
   pg_catalog.bool_or(ref.actor IS NULL) AS service_reference
  FROM public.credentials c LEFT JOIN LATERAL (
   SELECT pg_catalog.jsonb_build_array('mcp_user',s.id,pg_catalog.to_char(s.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),s.url,u.user_id,u.scope) AS value,u.user_id AS actor
    FROM public.mcp_user_credentials u JOIN public.mcp_servers s ON s.id=u.server_id WHERE u.credential_id=c.id
   UNION ALL SELECT pg_catalog.jsonb_build_array('mcp_client',s.id,pg_catalog.to_char(s.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),s.url,s.added_by),s.added_by
    FROM public.mcp_servers s WHERE s.credential_id=c.id
  ) ref ON true GROUP BY c.id
 ), sources(kind,ref,birth,revision,owner_kind,owner_id,owner_birth,public_fields) AS (
  SELECT 'subject',u.id,u.created_at,NULL::bigint,'actor',u.id,u.created_at,
   pg_catalog.jsonb_build_array(u.id,pg_catalog.to_char(u.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) FROM public.users u
  UNION ALL SELECT 'credential',c.id::text,c.created_at,NULL::bigint,
   CASE WHEN r.actors=1 AND NOT r.service_reference THEN 'actor' ELSE 'service' END,
   CASE WHEN r.actors=1 AND NOT r.service_reference THEN r.actor ELSE operation.deployment_id END,
   CASE WHEN r.actors=1 AND NOT r.service_reference THEN u.created_at ELSE NULL END,
   pg_catalog.jsonb_build_array(c.id,pg_catalog.to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),c.kind,c.provider,r.refs)
   FROM public.credentials c JOIN credential_references r ON r.id=c.id LEFT JOIN public.users u ON u.id=r.actor
  UNION ALL SELECT 'model_secret',c.id::text,c.created_at,c.revision,'actor',c.owner_user_id,u.created_at,
   pg_catalog.jsonb_build_array(c.id,pg_catalog.to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),c.revision,c.deployment_id,c.tenant_id,c.owner_user_id,c.protocol,c.endpoint,c.model)
   FROM public.model_connections c JOIN public.users u ON u.id=c.owner_user_id
  UNION ALL SELECT 'sdk_secret',c.id::text,c.created_at,c.revision,'actor',c.owner_user_id,u.created_at,
   pg_catalog.jsonb_build_array(c.id,pg_catalog.to_char(c.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),c.revision,c.deployment_id,c.tenant_id,c.owner_user_id,c.issuer,c.client_id,c.account_id,c.organization_id)
   FROM public.sdk_gateway_connections c JOIN public.users u ON u.id=c.owner_user_id
  UNION ALL SELECT 'sso_provider',s.id,NULL::timestamptz,NULL::bigint,
   CASE WHEN s.user_id IS NULL THEN 'service' ELSE 'actor' END,coalesce(s.user_id,operation.deployment_id),u.created_at,
   pg_catalog.jsonb_build_array(s.id,s.provider_id,s.issuer,s.organization_id,s.domain,s.user_id)
   FROM public.sso_providers s LEFT JOIN public.users u ON u.id=s.user_id
 ), inventory AS (
  SELECT kind,ref,birth,revision,owner_kind,owner_id,owner_birth,
   pg_catalog.sha256(pg_catalog.convert_to('wrokbot.restore.public-binding.v1'||chr(10)||
    pg_catalog.jsonb_build_array(kind,public_fields)::text,'UTF8')) AS binding FROM sources
 ), latest AS (
  SELECT DISTINCT ON(r.source_kind,r.source_ref) r.*
   FROM openbot_internal.restore_reconfirm_requirements r WHERE r.operation_id=operation.operation_id
   ORDER BY r.source_kind,r.source_ref,r.binding_generation DESC
 ), observed AS (
  SELECT l.source_kind,l.source_ref,l.source_created_at,l.source_revision,l.owner_kind,l.owner_id,l.owner_created_at,l.public_binding
   FROM latest l WHERE l.source_kind<>'config_slot'
 ), missing AS (SELECT * FROM inventory EXCEPT SELECT * FROM observed),
 extra AS (SELECT * FROM observed EXCEPT SELECT * FROM inventory)
 SELECT NOT EXISTS(SELECT 1 FROM missing) AND NOT EXISTS(SELECT 1 FROM extra) AND
  NOT EXISTS(SELECT 1 FROM credential_references r WHERE r.actors>1 OR (r.actors=1 AND r.service_reference))
 INTO candidate_cohort_matches;
 IF NOT candidate_cohort_matches THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_cohort_invalid';
 END IF;
 IF EXISTS(SELECT 1 FROM public.model_connections c WHERE c.deployment_id<>operation.deployment_id OR c.tenant_id<>operation.tenant_id OR
    NOT EXISTS(SELECT 1 FROM public.model_connection_secrets s WHERE s.id=c.current_secret_id AND s.connection_id=c.id
     AND s.deployment_id=c.deployment_id AND s.tenant_id=c.tenant_id AND s.owner_user_id=c.owner_user_id)) OR
    EXISTS(SELECT 1 FROM public.sdk_gateway_connections c WHERE c.deployment_id<>operation.deployment_id OR c.tenant_id<>operation.tenant_id OR
     (c.current_secret_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.sdk_gateway_secrets s
      WHERE s.id=c.current_secret_id AND s.connection_id=c.id AND s.deployment_id=c.deployment_id
       AND s.tenant_id=c.tenant_id AND s.owner_user_id=c.owner_user_id AND s.credential_generation=c.credential_generation))) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_connection_binding_invalid';
 END IF;
 SELECT pg_catalog.count(*),coalesce(pg_catalog.max(b.batch_seq),0)
  INTO actual_batches,actual_high_water FROM openbot_internal.restore_pg_batches b WHERE b.operation_id=operation.operation_id;
 IF actual_batches<>actual_high_water OR actual_batches>operation.max_batches OR NEW.batches<>actual_batches THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_seal_batches_invalid';
 END IF;
 SELECT pg_catalog.count(*),coalesce(pg_catalog.max(r.requirement_seq),0)
  INTO actual_requirements,actual_high_water FROM openbot_internal.restore_reconfirm_requirements r WHERE r.operation_id=operation.operation_id;
 -- Counts/high-water retain every appended generation; only the cohort
 -- equality above excludes superseded generations.
 SELECT pg_catalog.count(*) FILTER(WHERE r.source_kind='subject'),
  pg_catalog.count(*) FILTER(WHERE r.source_kind<>'subject') INTO actual_subjects,actual_credentials
  FROM openbot_internal.restore_reconfirm_requirements r WHERE r.operation_id=operation.operation_id;
 IF actual_requirements<>actual_high_water OR actual_requirements>operation.max_requirements OR
    NEW.subject_requirements<>actual_subjects OR NEW.credential_requirements<>actual_credentials THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='restore_pg_seal_requirements_invalid';
 END IF;
 RETURN NEW;
END;
$restore53_insert$;

CREATE TRIGGER restore_pg_operations_insert BEFORE INSERT ON openbot_internal.restore_pg_operations FOR EACH ROW EXECUTE FUNCTION openbot_internal.restore53_guard_insert();
CREATE TRIGGER restore_pg_operations_immutable BEFORE UPDATE OR DELETE ON openbot_internal.restore_pg_operations FOR EACH ROW EXECUTE FUNCTION openbot_internal.restore53_reject_mutation();
CREATE TRIGGER restore_pg_operations_no_truncate BEFORE TRUNCATE ON openbot_internal.restore_pg_operations FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.restore53_reject_mutation();
CREATE TRIGGER restore_pg_batches_insert BEFORE INSERT ON openbot_internal.restore_pg_batches FOR EACH ROW EXECUTE FUNCTION openbot_internal.restore53_guard_insert();
CREATE TRIGGER restore_pg_batches_immutable BEFORE UPDATE OR DELETE ON openbot_internal.restore_pg_batches FOR EACH ROW EXECUTE FUNCTION openbot_internal.restore53_reject_mutation();
CREATE TRIGGER restore_pg_batches_no_truncate BEFORE TRUNCATE ON openbot_internal.restore_pg_batches FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.restore53_reject_mutation();
CREATE TRIGGER restore_reconfirm_requirements_insert BEFORE INSERT ON openbot_internal.restore_reconfirm_requirements FOR EACH ROW EXECUTE FUNCTION openbot_internal.restore53_guard_insert();
CREATE TRIGGER restore_reconfirm_requirements_immutable BEFORE UPDATE OR DELETE ON openbot_internal.restore_reconfirm_requirements FOR EACH ROW EXECUTE FUNCTION openbot_internal.restore53_reject_mutation();
CREATE TRIGGER restore_reconfirm_requirements_no_truncate BEFORE TRUNCATE ON openbot_internal.restore_reconfirm_requirements FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.restore53_reject_mutation();
CREATE TRIGGER restore_reconfirm_receipts_insert BEFORE INSERT ON openbot_internal.restore_reconfirm_receipts FOR EACH ROW EXECUTE FUNCTION openbot_internal.restore53_guard_insert();
CREATE TRIGGER restore_reconfirm_receipts_immutable BEFORE UPDATE OR DELETE ON openbot_internal.restore_reconfirm_receipts FOR EACH ROW EXECUTE FUNCTION openbot_internal.restore53_reject_mutation();
CREATE TRIGGER restore_reconfirm_receipts_no_truncate BEFORE TRUNCATE ON openbot_internal.restore_reconfirm_receipts FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.restore53_reject_mutation();
CREATE TRIGGER restore_pg_seals_insert BEFORE INSERT ON openbot_internal.restore_pg_seals FOR EACH ROW EXECUTE FUNCTION openbot_internal.restore53_guard_insert();
CREATE TRIGGER restore_pg_seals_immutable BEFORE UPDATE OR DELETE ON openbot_internal.restore_pg_seals FOR EACH ROW EXECUTE FUNCTION openbot_internal.restore53_reject_mutation();
CREATE TRIGGER restore_pg_seals_no_truncate BEFORE TRUNCATE ON openbot_internal.restore_pg_seals FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.restore53_reject_mutation();

REVOKE ALL ON TABLE openbot_internal.restore_pg_operations,openbot_internal.restore_pg_batches,
 openbot_internal.restore_reconfirm_requirements,openbot_internal.restore_reconfirm_receipts,
 openbot_internal.restore_pg_seals FROM PUBLIC;
REVOKE ALL ON FUNCTION openbot_internal.restore53_guard_insert(),openbot_internal.restore53_reject_mutation() FROM PUBLIC;
