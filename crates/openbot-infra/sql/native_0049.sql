-- native0049: immutable historical Thread origin facts, additive on the original native Tx.
-- Immutable historical origin facts, no current session/Host/delete authority.
DO $thread_origin_owner$
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
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_origin_schema_invalid';
 END IF;
END;
$thread_origin_owner$;
CREATE TABLE openbot_internal.thread_origins (
 thread_id text COLLATE pg_catalog."C" NOT NULL,
 deployment_id text COLLATE pg_catalog."C" NOT NULL,
 tenant_id text COLLATE pg_catalog."C" NOT NULL,
 creator_actor_id text COLLATE pg_catalog."C" NOT NULL,
 anchor_kind text COLLATE pg_catalog."C" NOT NULL,
 anchor_id text COLLATE pg_catalog."C" NOT NULL,
 thread_created_at timestamp with time zone NOT NULL,
 origin_kind text COLLATE pg_catalog."C" NOT NULL,
 origin_schema smallint NOT NULL,
 recorded_at timestamp with time zone NOT NULL,
 import_bundle_id text COLLATE pg_catalog."C",
 import_payload_sha256 text COLLATE pg_catalog."C",
 import_signing_key_id text COLLATE pg_catalog."C",
 import_thread_checksum jsonb,
 CONSTRAINT thread_origins_pkey PRIMARY KEY(thread_id),
 CONSTRAINT thread_origins_identity_check CHECK(
  pg_catalog.octet_length(thread_id) BETWEEN 1 AND 512 AND thread_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(creator_actor_id) BETWEEN 1 AND 512 AND creator_actor_id !~ U&'[\0001-\001F\007F-\009F]' AND
  pg_catalog.octet_length(anchor_id) BETWEEN 1 AND 512 AND anchor_id !~ U&'[\0001-\001F\007F-\009F]'),
 CONSTRAINT thread_origins_schema_check CHECK(origin_schema=1),
 CONSTRAINT thread_origins_anchor_check CHECK(anchor_kind IN('direct_bot','channel')),
 CONSTRAINT thread_origins_kind_check CHECK(origin_kind IN('native_begin_v1','native_begin_v2','private_agent_channel','maintenance_import')),
 CONSTRAINT thread_origins_channel_check CHECK(origin_kind<>'private_agent_channel' OR anchor_kind='channel'),
 CONSTRAINT thread_origins_time_check CHECK(pg_catalog.isfinite(thread_created_at) AND pg_catalog.isfinite(recorded_at)),
 CONSTRAINT thread_origins_import_presence_check CHECK(
  (origin_kind='maintenance_import' AND import_bundle_id IS NOT NULL AND import_payload_sha256 IS NOT NULL
    AND import_signing_key_id IS NOT NULL AND import_thread_checksum IS NOT NULL) OR
  (origin_kind<>'maintenance_import' AND import_bundle_id IS NULL AND import_payload_sha256 IS NULL
    AND import_signing_key_id IS NULL AND import_thread_checksum IS NULL)),
 CONSTRAINT thread_origins_import_identity_check CHECK(
  import_bundle_id IS NULL OR (pg_catalog.octet_length(import_bundle_id) BETWEEN 1 AND 512
   AND import_bundle_id !~ U&'[\0001-\001F\007F-\009F]' AND
   pg_catalog.octet_length(import_signing_key_id) BETWEEN 1 AND 512
   AND import_signing_key_id !~ U&'[\0001-\001F\007F-\009F]' AND import_payload_sha256 ~ '^[0-9a-f]{64}$')),
 CONSTRAINT thread_origins_import_checksum_check CHECK(import_thread_checksum IS NULL OR
  (pg_catalog.jsonb_typeof(import_thread_checksum)='object'
   AND import_thread_checksum ?& ARRAY['projectionHash','messageCount','messageHash','eventCount','eventHash','terminalStateHash','memoryCount','memoryHash','sampleRenderHash']
   AND (import_thread_checksum-ARRAY['projectionHash','messageCount','messageHash','eventCount','eventHash','terminalStateHash','memoryCount','memoryHash','sampleRenderHash'])='{}'::jsonb
   AND pg_catalog.jsonb_typeof(import_thread_checksum->'projectionHash')='string' AND (import_thread_checksum->>'projectionHash') ~ '^[0-9a-f]{64}$'
   AND pg_catalog.jsonb_typeof(import_thread_checksum->'messageHash')='string' AND (import_thread_checksum->>'messageHash') ~ '^[0-9a-f]{64}$'
   AND pg_catalog.jsonb_typeof(import_thread_checksum->'eventHash')='string' AND (import_thread_checksum->>'eventHash') ~ '^[0-9a-f]{64}$'
   AND pg_catalog.jsonb_typeof(import_thread_checksum->'terminalStateHash')='string' AND (import_thread_checksum->>'terminalStateHash') ~ '^[0-9a-f]{64}$'
   AND pg_catalog.jsonb_typeof(import_thread_checksum->'memoryHash')='string' AND (import_thread_checksum->>'memoryHash') ~ '^[0-9a-f]{64}$'
   AND pg_catalog.jsonb_typeof(import_thread_checksum->'sampleRenderHash')='string' AND (import_thread_checksum->>'sampleRenderHash') ~ '^[0-9a-f]{64}$'
   AND pg_catalog.jsonb_typeof(import_thread_checksum->'messageCount')='number' AND (import_thread_checksum->>'messageCount')::numeric >= '0'::numeric AND (import_thread_checksum->>'messageCount')::numeric <= 18446744073709551615 AND pg_catalog.trunc((import_thread_checksum->>'messageCount')::numeric) = (import_thread_checksum->>'messageCount')::numeric
   AND pg_catalog.jsonb_typeof(import_thread_checksum->'eventCount')='number' AND (import_thread_checksum->>'eventCount')::numeric >= '0'::numeric AND (import_thread_checksum->>'eventCount')::numeric <= 18446744073709551615 AND pg_catalog.trunc((import_thread_checksum->>'eventCount')::numeric) = (import_thread_checksum->>'eventCount')::numeric
   AND pg_catalog.jsonb_typeof(import_thread_checksum->'memoryCount')='number' AND (import_thread_checksum->>'memoryCount')::numeric >= '0'::numeric AND (import_thread_checksum->>'memoryCount')::numeric <= 18446744073709551615 AND pg_catalog.trunc((import_thread_checksum->>'memoryCount')::numeric) = (import_thread_checksum->>'memoryCount')::numeric))
);
CREATE FUNCTION openbot_internal.prevent_thread_origin_mutation() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER AS $thread_origin_guard$
BEGIN
 RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_origin_mutation_refused';
END;
$thread_origin_guard$;
CREATE TRIGGER thread_origins_no_update_delete BEFORE UPDATE OR DELETE
 ON openbot_internal.thread_origins FOR EACH ROW
 EXECUTE FUNCTION openbot_internal.prevent_thread_origin_mutation();
CREATE TRIGGER thread_origins_no_truncate BEFORE TRUNCATE
 ON openbot_internal.thread_origins FOR EACH STATEMENT
 EXECUTE FUNCTION openbot_internal.prevent_thread_origin_mutation();

-- Full original-owner/ACL/catalog postcondition. Any drift rolls back the same migration Tx.
DO $thread_origin_postcondition$
DECLARE
 v_raw jsonb; v_schema jsonb; v_state jsonb; v_acl jsonb;
 v_owner pg_catalog.oid; v_table pg_catalog.oid; v_index pg_catalog.oid; v_function pg_catalog.oid;
 v_matches boolean; v_row jsonb; v_pos bigint; v_path text[]; v_key text;
 v_expected jsonb := $thread_origin_expected${"allowedTableAclStates":[{"aclIsNull":true,"rawAcl":null},{"aclIsNull":false,"rawAcl":[{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"DELETE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"INSERT"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"MAINTAIN"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"REFERENCES"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"SELECT"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"TRIGGER"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"TRUNCATE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"UPDATE"}]}],"format":"thread-origins-oracle-v1","schema":{"constraints":[{"columns":[{"attributeNumber":1,"name":"thread_id","ordinal":1},{"attributeNumber":2,"name":"deployment_id","ordinal":2},{"attributeNumber":3,"name":"tenant_id","ordinal":3},{"attributeNumber":4,"name":"creator_actor_id","ordinal":4},{"attributeNumber":6,"name":"anchor_id","ordinal":5}],"deferrable":false,"deferred":false,"definition":"CHECK ((((octet_length(thread_id) >= 1) AND (octet_length(thread_id) <= 512)) AND (thread_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND ((octet_length(deployment_id) >= 1) AND (octet_length(deployment_id) <= 512)) AND (deployment_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND ((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 512)) AND (tenant_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND ((octet_length(creator_actor_id) >= 1) AND (octet_length(creator_actor_id) <= 512)) AND (creator_actor_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND ((octet_length(anchor_id) >= 1) AND (octet_length(anchor_id) <= 512)) AND (anchor_id !~ '[\u0001-\u001f\u007f-\u009f]'::text)))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_origins_identity_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_origins","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":1,"name":"thread_id","ordinal":1}],"deferrable":false,"deferred":false,"definition":"PRIMARY KEY (thread_id)","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"p","local":true,"name":"thread_origins_pkey","namespace":"openbot_internal","noInherit":true,"reference":null,"relation":{"name":"thread_origins","schema":"openbot_internal"},"supportingIndex":{"name":"thread_origins_pkey","schema":"openbot_internal"},"validated":true},{"columns":[{"attributeNumber":11,"name":"import_bundle_id","ordinal":1},{"attributeNumber":13,"name":"import_signing_key_id","ordinal":2},{"attributeNumber":12,"name":"import_payload_sha256","ordinal":3}],"deferrable":false,"deferred":false,"definition":"CHECK (((import_bundle_id IS NULL) OR (((octet_length(import_bundle_id) >= 1) AND (octet_length(import_bundle_id) <= 512)) AND (import_bundle_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND ((octet_length(import_signing_key_id) >= 1) AND (octet_length(import_signing_key_id) <= 512)) AND (import_signing_key_id !~ '[\u0001-\u001f\u007f-\u009f]'::text) AND (import_payload_sha256 ~ '^[0-9a-f]{64}$'::text))))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_origins_import_identity_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_origins","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":14,"name":"import_thread_checksum","ordinal":1}],"deferrable":false,"deferred":false,"definition":"CHECK (((import_thread_checksum IS NULL) OR ((jsonb_typeof(import_thread_checksum) = 'object'::text) AND (import_thread_checksum ?& ARRAY['projectionHash'::text, 'messageCount'::text, 'messageHash'::text, 'eventCount'::text, 'eventHash'::text, 'terminalStateHash'::text, 'memoryCount'::text, 'memoryHash'::text, 'sampleRenderHash'::text]) AND ((import_thread_checksum - ARRAY['projectionHash'::text, 'messageCount'::text, 'messageHash'::text, 'eventCount'::text, 'eventHash'::text, 'terminalStateHash'::text, 'memoryCount'::text, 'memoryHash'::text, 'sampleRenderHash'::text]) = '{}'::jsonb) AND (jsonb_typeof((import_thread_checksum -> 'projectionHash'::text)) = 'string'::text) AND ((import_thread_checksum ->> 'projectionHash'::text) ~ '^[0-9a-f]{64}$'::text) AND (jsonb_typeof((import_thread_checksum -> 'messageHash'::text)) = 'string'::text) AND ((import_thread_checksum ->> 'messageHash'::text) ~ '^[0-9a-f]{64}$'::text) AND (jsonb_typeof((import_thread_checksum -> 'eventHash'::text)) = 'string'::text) AND ((import_thread_checksum ->> 'eventHash'::text) ~ '^[0-9a-f]{64}$'::text) AND (jsonb_typeof((import_thread_checksum -> 'terminalStateHash'::text)) = 'string'::text) AND ((import_thread_checksum ->> 'terminalStateHash'::text) ~ '^[0-9a-f]{64}$'::text) AND (jsonb_typeof((import_thread_checksum -> 'memoryHash'::text)) = 'string'::text) AND ((import_thread_checksum ->> 'memoryHash'::text) ~ '^[0-9a-f]{64}$'::text) AND (jsonb_typeof((import_thread_checksum -> 'sampleRenderHash'::text)) = 'string'::text) AND ((import_thread_checksum ->> 'sampleRenderHash'::text) ~ '^[0-9a-f]{64}$'::text) AND (jsonb_typeof((import_thread_checksum -> 'messageCount'::text)) = 'number'::text) AND (((import_thread_checksum ->> 'messageCount'::text))::numeric >= '0'::numeric) AND (((import_thread_checksum ->> 'messageCount'::text))::numeric <= '18446744073709551615'::numeric) AND (trunc(((import_thread_checksum ->> 'messageCount'::text))::numeric) = ((import_thread_checksum ->> 'messageCount'::text))::numeric) AND (jsonb_typeof((import_thread_checksum -> 'eventCount'::text)) = 'number'::text) AND (((import_thread_checksum ->> 'eventCount'::text))::numeric >= '0'::numeric) AND (((import_thread_checksum ->> 'eventCount'::text))::numeric <= '18446744073709551615'::numeric) AND (trunc(((import_thread_checksum ->> 'eventCount'::text))::numeric) = ((import_thread_checksum ->> 'eventCount'::text))::numeric) AND (jsonb_typeof((import_thread_checksum -> 'memoryCount'::text)) = 'number'::text) AND (((import_thread_checksum ->> 'memoryCount'::text))::numeric >= '0'::numeric) AND (((import_thread_checksum ->> 'memoryCount'::text))::numeric <= '18446744073709551615'::numeric) AND (trunc(((import_thread_checksum ->> 'memoryCount'::text))::numeric) = ((import_thread_checksum ->> 'memoryCount'::text))::numeric))))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_origins_import_checksum_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_origins","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":5,"name":"anchor_kind","ordinal":1}],"deferrable":false,"deferred":false,"definition":"CHECK ((anchor_kind = ANY (ARRAY['direct_bot'::text, 'channel'::text])))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_origins_anchor_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_origins","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":7,"name":"thread_created_at","ordinal":1},{"attributeNumber":10,"name":"recorded_at","ordinal":2}],"deferrable":false,"deferred":false,"definition":"CHECK ((isfinite(thread_created_at) AND isfinite(recorded_at)))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_origins_time_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_origins","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":8,"name":"origin_kind","ordinal":1},{"attributeNumber":11,"name":"import_bundle_id","ordinal":2},{"attributeNumber":12,"name":"import_payload_sha256","ordinal":3},{"attributeNumber":13,"name":"import_signing_key_id","ordinal":4},{"attributeNumber":14,"name":"import_thread_checksum","ordinal":5}],"deferrable":false,"deferred":false,"definition":"CHECK ((((origin_kind = 'maintenance_import'::text) AND (import_bundle_id IS NOT NULL) AND (import_payload_sha256 IS NOT NULL) AND (import_signing_key_id IS NOT NULL) AND (import_thread_checksum IS NOT NULL)) OR ((origin_kind <> 'maintenance_import'::text) AND (import_bundle_id IS NULL) AND (import_payload_sha256 IS NULL) AND (import_signing_key_id IS NULL) AND (import_thread_checksum IS NULL))))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_origins_import_presence_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_origins","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":8,"name":"origin_kind","ordinal":1},{"attributeNumber":5,"name":"anchor_kind","ordinal":2}],"deferrable":false,"deferred":false,"definition":"CHECK (((origin_kind <> 'private_agent_channel'::text) OR (anchor_kind = 'channel'::text)))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_origins_channel_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_origins","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":8,"name":"origin_kind","ordinal":1}],"deferrable":false,"deferred":false,"definition":"CHECK ((origin_kind = ANY (ARRAY['native_begin_v1'::text, 'native_begin_v2'::text, 'private_agent_channel'::text, 'maintenance_import'::text])))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_origins_kind_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_origins","schema":"openbot_internal"},"supportingIndex":null,"validated":true},{"columns":[{"attributeNumber":9,"name":"origin_schema","ordinal":1}],"deferrable":false,"deferred":false,"definition":"CHECK ((origin_schema = 1))","foreignEqualityOperators":[],"hasParent":false,"inheritanceCount":0,"kind":"c","local":true,"name":"thread_origins_schema_check","namespace":"openbot_internal","noInherit":false,"reference":null,"relation":{"name":"thread_origins","schema":"openbot_internal"},"supportingIndex":null,"validated":true}],"format":"thread-origins-schema-v1","functions":[{"acl":[{"grantable":false,"grantee":"PUBLIC","grantor":"original_threads_owner","privilege":"EXECUTE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"EXECUTE"}],"aclIsNull":true,"allArgumentTypes":[],"allArgumentTypesIsNull":true,"argumentDefaults":null,"argumentModes":null,"argumentNames":null,"binary":null,"configuration":null,"cost":100,"defaultArgumentCount":0,"definition":"CREATE OR REPLACE FUNCTION openbot_internal.prevent_thread_origin_mutation()\n RETURNS trigger\n LANGUAGE plpgsql\nAS $function$\nBEGIN\n RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_origin_mutation_refused';\nEND;\n$function$\n","identity":{"arguments":"","name":"prevent_thread_origin_mutation","schema":"openbot_internal"},"inputArgumentCount":0,"inputTypes":[],"isSyncFunction":false,"kind":"f","language":"plpgsql","leakproof":false,"ownerRef":"original_threads_owner","parallel":"u","rawAcl":null,"returnType":{"formatted":"trigger","name":"trigger","schema":"pg_catalog"},"rows":0,"securityDefiner":false,"setReturning":false,"source":"\nBEGIN\n RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_origin_mutation_refused';\nEND;\n","sqlBody":null,"strict":false,"supportFunction":null,"transformTypes":[],"transformTypesIsNull":true,"variadicType":null,"volatility":"v"}],"indexes":[{"accessMethod":"btree","aclIsNull":true,"attributeCount":1,"checkXmin":{"predicate":"pg17_hot_runtime_boolean_v1"},"clustered":false,"collations":[{"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"ordinal":1}],"definition":"CREATE UNIQUE INDEX thread_origins_pkey ON openbot_internal.thread_origins USING btree (thread_id)","exclusion":false,"expressions":null,"identity":{"name":"thread_origins_pkey","schema":"openbot_internal"},"immediate":true,"keyCount":1,"keys":"1","kind":"i","live":true,"nullsNotDistinct":false,"operatorClasses":[{"accessMethod":"btree","default":true,"family":{"name":"text_ops","schema":"pg_catalog"},"inputType":"text","keyType":null,"name":"text_ops","ordinal":1,"schema":"pg_catalog"}],"options":null,"optionsPerKey":"0","ownerIsOriginal":true,"persistence":"p","predicate":null,"primary":true,"rawAcl":null,"ready":true,"relation":{"name":"thread_origins","schema":"openbot_internal"},"replicaIdentity":false,"unique":true,"valid":true}],"relations":[{"accessMethod":"heap","acl":[{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"DELETE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"INSERT"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"MAINTAIN"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"REFERENCES"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"SELECT"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"TRIGGER"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"TRUNCATE"},{"grantable":false,"grantee":"original_threads_owner","grantor":"original_threads_owner","privilege":"UPDATE"}],"attributeCount":14,"checkCount":9,"columns":[{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"thread_id","notNull":true,"ordinal":1,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"deployment_id","notNull":true,"ordinal":2,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"tenant_id","notNull":true,"ordinal":3,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"creator_actor_id","notNull":true,"ordinal":4,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"anchor_kind","notNull":true,"ordinal":5,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"anchor_id","notNull":true,"ordinal":6,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"thread_created_at","notNull":true,"ordinal":7,"type":{"formatted":"timestamp with time zone","modifier":-1,"name":"timestamptz","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"origin_kind","notNull":true,"ordinal":8,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"origin_schema","notNull":true,"ordinal":9,"type":{"formatted":"smallint","modifier":-1,"name":"int2","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"recorded_at","notNull":true,"ordinal":10,"type":{"formatted":"timestamp with time zone","modifier":-1,"name":"timestamptz","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"import_bundle_id","notNull":false,"ordinal":11,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"import_payload_sha256","notNull":false,"ordinal":12,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":{"deterministic":true,"encoding":-1,"name":"C","provider":"c","schema":"pg_catalog"},"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"import_signing_key_id","notNull":false,"ordinal":13,"type":{"formatted":"text","modifier":-1,"name":"text","schema":"pg_catalog"}},{"acl":[],"aclIsNull":true,"collation":null,"default":null,"dimensions":0,"generated":"","identity":"","inheritanceCount":0,"local":true,"name":"import_thread_checksum","notNull":false,"ordinal":14,"type":{"formatted":"jsonb","modifier":-1,"name":"jsonb","schema":"pg_catalog"}}],"droppedAttributes":[],"forceRowSecurity":false,"identity":{"name":"thread_origins","schema":"openbot_internal"},"inheritanceChildren":[],"inheritanceParents":[],"kind":"r","options":null,"ownerIsOriginal":true,"partition":false,"persistence":"p","policies":[],"replicaIdentity":"d","rowSecurity":false,"rules":[]}],"triggers":[{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":null,"constraintIndex":null,"constraintRelation":null,"deferrable":false,"deferred":false,"definition":"CREATE TRIGGER thread_origins_no_truncate BEFORE TRUNCATE ON openbot_internal.thread_origins FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_thread_origin_mutation()","enabled":"O","function":{"arguments":"","kind":"f","name":"prevent_thread_origin_mutation","schema":"openbot_internal"},"hasParent":false,"internal":false,"name":"thread_origins_no_truncate","newTransition":null,"oldTransition":null,"relation":{"name":"thread_origins","schema":"openbot_internal"},"type":34},{"argumentCount":0,"argumentsHex":"","columns":"","conditionIsNull":true,"conditionTreeRaw":null,"constraint":null,"constraintIndex":null,"constraintRelation":null,"deferrable":false,"deferred":false,"definition":"CREATE TRIGGER thread_origins_no_update_delete BEFORE DELETE OR UPDATE ON openbot_internal.thread_origins FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_thread_origin_mutation()","enabled":"O","function":{"arguments":"","kind":"f","name":"prevent_thread_origin_mutation","schema":"openbot_internal"},"hasParent":false,"internal":false,"name":"thread_origins_no_update_delete","newTransition":null,"oldTransition":null,"relation":{"name":"thread_origins","schema":"openbot_internal"},"type":27}]}}$thread_origin_expected$::jsonb;
BEGIN
 SELECT actual.thread_origin_raw::jsonb, actual.function_acl_matches_builtin
 INTO v_raw, v_matches FROM (
WITH
wanted_relations(schema_name, relation_name) AS (
 VALUES ('openbot_internal'::text,'thread_origins'::text)
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
 WHERE n.nspname='openbot_internal' AND p.proname='prevent_thread_origin_mutation'
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
 'format','thread-origins-raw-v1',
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
 'builtinAnchorsRaw',pg_catalog.jsonb_build_object(
  'types',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('oidRaw',t.oid::text,'schema',n.nspname,'name',t.typname) ORDER BY t.typname COLLATE pg_catalog."C")
    FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
    WHERE n.nspname='pg_catalog' AND t.typname IN ('text','timestamptz','int2','jsonb','trigger')),
  'collation',(SELECT pg_catalog.jsonb_build_object('oidRaw',c.oid::text,'schema',n.nspname,'name',c.collname)
    FROM pg_catalog.pg_collation c JOIN pg_catalog.pg_namespace n ON n.oid=c.collnamespace
    WHERE n.nspname='pg_catalog' AND c.collname='C' AND c.collencoding=-1),
  'operatorClass',(SELECT pg_catalog.jsonb_build_object('oidRaw',c.oid::text,'schema',n.nspname,'name',c.opcname,
    'familyOidRaw',f.oid::text,'familySchema',fn.nspname,'familyName',f.opfname)
    FROM pg_catalog.pg_opclass c JOIN pg_catalog.pg_namespace n ON n.oid=c.opcnamespace
    JOIN pg_catalog.pg_am a ON a.oid=c.opcmethod JOIN pg_catalog.pg_opfamily f ON f.oid=c.opcfamily
    JOIN pg_catalog.pg_namespace fn ON fn.oid=f.opfnamespace
    WHERE n.nspname='pg_catalog' AND c.opcname='text_ops' AND a.amname='btree')
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
)::text AS thread_origin_raw,
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
 v_owner := (v_raw->'ownerAnchorRaw'->>'ownerOidRaw')::pg_catalog.oid;
 IF v_owner IS NULL OR v_owner=0 OR NOT v_matches OR
    v_owner IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=CURRENT_USER) OR
    jsonb_array_length(v_raw->'relations')<>1 OR jsonb_array_length(v_raw->'constraints')<>10 OR
    jsonb_array_length(v_raw->'indexes')<>1 OR jsonb_array_length(v_raw->'triggers')<>2 OR
    jsonb_array_length(v_raw->'functions')<>1 OR
    v_raw->'storage'->>'serverEncoding'<>'UTF8' OR (v_raw->'storage'->>'blockSize')::integer<>8192 OR
    (v_raw->'storage'->>'serverVersion')::integer NOT BETWEEN 170000 AND 179999 OR
    EXISTS(SELECT 1 FROM jsonb_array_elements(v_raw->'legacyOwnershipRaw'->'relations') r
      WHERE (r->>'ownerOidRaw')::pg_catalog.oid IS DISTINCT FROM v_owner) OR
    NOT EXISTS(SELECT 1 FROM jsonb_array_elements(v_raw->'legacyOwnershipRaw'->'namespaces') n
      WHERE n->>'schema'='openbot_internal' AND (n->>'ownerOidRaw')::pg_catalog.oid=v_owner) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_origin_schema_invalid';
 END IF;
 v_table := (v_raw->'relations'->0->'identity'->>'oidRaw')::pg_catalog.oid;
 v_index := (v_raw->'indexes'->0->'identity'->>'oidRaw')::pg_catalog.oid;
 v_function := (v_raw->'functions'->0->'identity'->>'oidRaw')::pg_catalog.oid;
 IF v_table=0 OR v_index=0 OR v_function=0 OR
    (v_raw->'relations'->0->>'ownerOidRaw')::pg_catalog.oid IS DISTINCT FROM v_owner OR
    (v_raw->'indexes'->0->>'ownerOidRaw')::pg_catalog.oid IS DISTINCT FROM v_owner OR
    (v_raw->'functions'->0->>'ownerOidRaw')::pg_catalog.oid IS DISTINCT FROM v_owner OR
    (v_raw->'indexes'->0->'relation'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM v_table OR
    EXISTS(SELECT 1 FROM jsonb_array_elements(v_raw->'constraints') c
      WHERE (c->'relation'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM v_table OR
       ((c->>'kind')='p' AND (c->'supportingIndex'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM v_index)) OR
    EXISTS(SELECT 1 FROM jsonb_array_elements(v_raw->'triggers') t
      WHERE (t->'relation'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM v_table OR
       (t->'function'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM v_function OR
       (t->>'constraintOidRaw')::pg_catalog.oid<>0) THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_origin_schema_invalid';
 END IF;
 -- Bind every builtin OID before any portable comparison removes it.
 IF jsonb_array_length(v_raw->'builtinAnchorsRaw'->'types')<>5 OR
    EXISTS(SELECT 1 FROM (VALUES ('text',25),('int2',21),('timestamptz',1184),('jsonb',3802),('trigger',2279)) expected(name,type_oid)
      LEFT JOIN jsonb_array_elements(v_raw->'builtinAnchorsRaw'->'types') actual
        ON actual->>'name'=expected.name AND actual->>'schema'='pg_catalog'
      WHERE (actual->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM expected.type_oid::pg_catalog.oid) OR
    EXISTS(SELECT 1 FROM jsonb_array_elements(v_raw->'relations'->0->'columns') c
      LEFT JOIN jsonb_array_elements(v_raw->'builtinAnchorsRaw'->'types') ty
        ON ty->>'name'=c->'type'->>'name'
      WHERE c->'type'->>'schema' IS DISTINCT FROM 'pg_catalog' OR
        c->'type'->>'name'='trigger' OR
        (c->'type'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (ty->>'oidRaw')::pg_catalog.oid OR
        (c->'collation'<>'null'::jsonb AND (
          c->'collation'->>'schema' IS DISTINCT FROM 'pg_catalog' OR c->'collation'->>'name' IS DISTINCT FROM 'C' OR
          (c->'collation'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_raw->'builtinAnchorsRaw'->'collation'->>'oidRaw')::pg_catalog.oid))) OR
    (v_raw->'functions'->0->'returnType'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM 2279::pg_catalog.oid OR
    v_raw->'builtinAnchorsRaw'->'collation'->>'schema' IS DISTINCT FROM 'pg_catalog' OR
    v_raw->'builtinAnchorsRaw'->'collation'->>'name' IS DISTINCT FROM 'C' OR
    (v_raw->'builtinAnchorsRaw'->'collation'->>'oidRaw')::pg_catalog.oid=0 OR
    jsonb_array_length(v_raw->'indexes'->0->'collations')<>1 OR
    (v_raw->'indexes'->0->'collations'->0->'collation'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_raw->'builtinAnchorsRaw'->'collation'->>'oidRaw')::pg_catalog.oid OR
    v_raw->'builtinAnchorsRaw'->'operatorClass'->>'schema' IS DISTINCT FROM 'pg_catalog' OR
    v_raw->'builtinAnchorsRaw'->'operatorClass'->>'name' IS DISTINCT FROM 'text_ops' OR
    jsonb_array_length(v_raw->'indexes'->0->'operatorClasses')<>1 OR
    (v_raw->'indexes'->0->'operatorClasses'->0->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_raw->'builtinAnchorsRaw'->'operatorClass'->>'oidRaw')::pg_catalog.oid OR
    (v_raw->'indexes'->0->'operatorClasses'->0->'family'->>'oidRaw')::pg_catalog.oid IS DISTINCT FROM (v_raw->'builtinAnchorsRaw'->'operatorClass'->>'familyOidRaw')::pg_catalog.oid OR
    v_raw->'indexes'->0->'operatorClasses'->0->'family'->>'schema' IS DISTINCT FROM v_raw->'builtinAnchorsRaw'->'operatorClass'->>'familySchema' OR
    v_raw->'indexes'->0->'operatorClasses'->0->'family'->>'name' IS DISTINCT FROM v_raw->'builtinAnchorsRaw'->'operatorClass'->>'familyName' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_origin_schema_invalid';
 END IF;
 -- Require the full table ACL multiset, including PG17 MAINTAIN, before replacing portable OIDs.
 IF EXISTS(
   (SELECT (a->>'grantorOidRaw')::pg_catalog.oid,(a->>'granteeOidRaw')::pg_catalog.oid,a->>'privilege',(a->>'grantable')::boolean
    FROM jsonb_array_elements(v_raw->'relations'->0->'acl') a)
   EXCEPT ALL
   (SELECT grantor,grantee,privilege_type,is_grantable FROM pg_catalog.aclexplode(pg_catalog.acldefault('r'::pg_catalog."char",v_owner)))
 ) OR EXISTS(
   (SELECT grantor,grantee,privilege_type,is_grantable FROM pg_catalog.aclexplode(pg_catalog.acldefault('r'::pg_catalog."char",v_owner)))
   EXCEPT ALL
   (SELECT (a->>'grantorOidRaw')::pg_catalog.oid,(a->>'granteeOidRaw')::pg_catalog.oid,a->>'privilege',(a->>'grantable')::boolean
    FROM jsonb_array_elements(v_raw->'relations'->0->'acl') a)
 ) THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_origin_schema_invalid'; END IF;
 SELECT jsonb_agg(jsonb_build_object('grantor','original_threads_owner','grantee','original_threads_owner',
   'privilege',a->>'privilege','grantable',(a->>'grantable')::boolean) ORDER BY a->>'privilege' COLLATE pg_catalog."C")
 INTO v_acl FROM jsonb_array_elements(v_raw->'relations'->0->'acl') a;
 v_state := jsonb_build_object('aclIsNull',(v_raw->'relations'->0->>'aclIsNull')::boolean,
   'rawAcl',CASE WHEN (v_raw->'relations'->0->>'aclIsNull')::boolean THEN NULL ELSE v_acl END);
 IF (SELECT count(*) FROM jsonb_array_elements(v_expected->'allowedTableAclStates') s WHERE s=v_state)<>1 THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_origin_schema_invalid';
 END IF;
 v_schema := v_raw-ARRAY['ownerAnchorRaw','legacyOwnershipRaw','deparseContextRaw','storage','builtinAnchorsRaw'];
 v_schema := jsonb_set(v_schema,'{format}','"thread-origins-schema-v1"'::jsonb);
 v_schema := jsonb_set(v_schema,'{relations,0}',(v_schema->'relations'->0)-ARRAY['aclIsNull','rawAcl']||jsonb_build_object('ownerIsOriginal',true,'acl',v_acl));
 v_schema := jsonb_set(v_schema,'{indexes,0}',(v_schema->'indexes'->0)||jsonb_build_object('ownerIsOriginal',true));
 SELECT jsonb_agg(jsonb_build_object('grantor','original_threads_owner',
   'grantee',CASE WHEN (a->>'granteeOidRaw')::pg_catalog.oid=0 THEN 'PUBLIC' ELSE 'original_threads_owner' END,
   'privilege',a->>'privilege','grantable',(a->>'grantable')::boolean)
   ORDER BY (a->>'granteeOidRaw')::pg_catalog.oid,a->>'privilege' COLLATE pg_catalog."C")
 INTO v_acl FROM jsonb_array_elements(v_raw->'functions'->0->'acl') a;
 v_schema := jsonb_set(v_schema,'{functions,0}',(v_schema->'functions'->0)||jsonb_build_object('ownerRef','original_threads_owner','acl',v_acl));
 -- Keep raw facts in the observer; only this local, fully bound comparison removes portable OIDs.
 FOR v_path IN
  WITH RECURSIVE walk(path,value) AS (
   SELECT '{}'::text[],v_schema
   UNION ALL
   SELECT w.path||child.key,child.value FROM walk w
   CROSS JOIN LATERAL (
    SELECT key,value FROM jsonb_each(CASE WHEN jsonb_typeof(w.value)='object' THEN w.value ELSE '{}'::jsonb END)
    UNION ALL
    SELECT (ordinality-1)::text,value FROM jsonb_array_elements(CASE WHEN jsonb_typeof(w.value)='array' THEN w.value ELSE '[]'::jsonb END) WITH ORDINALITY
   ) child
  ) SELECT path FROM walk WHERE path[cardinality(path)] IN ('oidRaw','ownerOidRaw','indexOidRaw','constraintOidRaw') ORDER BY cardinality(path) DESC
 LOOP v_schema := v_schema #- v_path; END LOOP;
 IF jsonb_typeof(v_schema->'indexes'->0->'checkXmin')<>'boolean' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_origin_schema_invalid';
 END IF;
 v_schema := jsonb_set(v_schema,'{indexes,0,checkXmin}','{"predicate":"pg17_hot_runtime_boolean_v1"}'::jsonb);
 IF v_schema->>'format' IS DISTINCT FROM v_expected->'schema'->>'format' THEN
  RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_origin_schema_invalid';
 END IF;
 FOREACH v_key IN ARRAY ARRAY['relations','constraints','indexes','triggers','functions'] LOOP
  IF EXISTS((SELECT x FROM jsonb_array_elements(v_schema->v_key) x) EXCEPT ALL (SELECT x FROM jsonb_array_elements(v_expected->'schema'->v_key) x)) OR
     EXISTS((SELECT x FROM jsonb_array_elements(v_expected->'schema'->v_key) x) EXCEPT ALL (SELECT x FROM jsonb_array_elements(v_schema->v_key) x)) THEN
   RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='thread_origin_schema_invalid';
  END IF;
 END LOOP;
END;
$thread_origin_postcondition$;
