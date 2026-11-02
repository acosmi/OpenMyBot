//! Complete current writer graph, canonical channel source and retained one-J history metadata.
//! The observer preserves original OIDs/ACLs and never derives or widens its independent oracle.

use super::{InfraError, RowDecodeError, native};
use serde_json::{Value, json};
use tokio_postgres::{Client, GenericClient, Transaction};

/// Whole portable schema, the actual table ACL state and original raw facts.
pub type ThreadHistoryWriterSchemaFacts = Value;
const REGISTERED_SCHEMA: &str =
    include_str!("../../../../fixtures/db/thread-history-writer-0052.json");
const LEGACY0051_SCHEMA: &str =
    include_str!("../../../../fixtures/db/thread-history-writer-0051.json");

const CAPTURE_SQL: &str = r####"WITH
wanted_relations(schema_name, relation_name) AS (
 VALUES ('openbot_internal'::text,'thread_history_heads'::text),
        ('openbot_internal'::text,'thread_history_clear_intents'::text),
        ('openbot_internal'::text,'channel_history_sources'::text)
 UNION ALL SELECT 'openbot_internal','thread_history_clear_batches' WHERE $2::boolean
 UNION ALL SELECT 'openbot_internal','thread_history_clear_completions' WHERE $2::boolean
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
 WHERE (n.nspname='openbot_internal' AND (p.proname IN ('guard_thread_history_head_mutation','prevent_thread_history_intent_mutation','require_thread_history_intent_closed_head','bind_thread_history_head_on_insert','retain_thread_history_head_on_delete','protect_thread_history_base_identity','prevent_thread_history_base_truncate','thread_history_preview','thread_history_lock_joint','thread_history_lock_channel_ids','thread_history_related_channel_ids','thread_history_validate_channel_source','guard_channel_history_source','guard_thread_history_channel_projection','thread_history_validate_channel_final','require_thread_history_channel_final','thread_history_terminal_payload','guard_thread_history_body','thread_history_validate_terminal_run','require_thread_history_terminal_final','guard_thread_history_canonical_reverse','prevent_thread_history_writer_truncate','maintain_thread_run_occupancy','guard_thread_run_occupancy')
 OR ($2::boolean AND p.proname IN ('guard_thread_history_clear_fact','thread_history_clear_batch_active','thread_history_clear_event_payload','require_thread_history_clear_completion','thread_history_clear_readers_quiescent','thread_history_clear_bodies_erased','require_thread_history_maintenance_source','guard_thread_history_memory_body'))))
 OR ($2::boolean AND n.nspname='public' AND p.proname='guard_memory_provenance')
),
constraints_scope AS (
 SELECT c.*
 FROM pg_catalog.pg_constraint c
 WHERE c.conrelid IN (SELECT oid FROM relations)
    OR (c.contype='f' AND c.confrelid IN (SELECT oid FROM relations))
    OR c.oid IN (SELECT t.tgconstraint FROM pg_catalog.pg_trigger t
                WHERE t.tgfoid IN (SELECT oid FROM named_guards) AND t.tgconstraint<>0)
    OR ($2::boolean AND c.conrelid='public.memories'::regclass AND c.conname IN
        ('memories_scope_shape','memories_content_shape','memories_source_run_shape','memories_source_authorization_shape'))
    OR ($2::boolean AND c.conrelid='public.component_human_decisions'::regclass
        AND c.conname='component_human_decisions_answer_shape')
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
    -- Old Run function facts remain complete; their triggers use the public source-table scope.
    OR t.tgfoid IN (SELECT oid FROM named_guards
                   WHERE proname NOT IN ('maintain_thread_run_occupancy','guard_thread_run_occupancy'))
    OR (NOT t.tgisinternal AND t.tgrelid IN (
       SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname='public' AND c.relname IN ('threads','runs','messages','run_events','tool_approvals',
          'component_human_decisions','remote_agent_interrupts','channels')))
    OR ($2::boolean AND NOT t.tgisinternal AND t.tgrelid='public.memories'::regclass)
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
),
source_class AS (SELECT * FROM relations WHERE relname='channel_history_sources'),
source_types AS (
 SELECT t.* FROM pg_catalog.pg_type t WHERE t.oid IN (
  SELECT r.reltype FROM source_class r UNION ALL
  SELECT t.typarray FROM source_class r JOIN pg_catalog.pg_type t ON t.oid=r.reltype)
),
source_toast AS (
 SELECT c.* FROM pg_catalog.pg_class c WHERE c.oid IN (SELECT reltoastrelid FROM source_class)
),
source_toast_indexes AS (SELECT i.* FROM pg_catalog.pg_index i WHERE i.indrelid IN (SELECT oid FROM source_toast)),
physical_class AS (
 SELECT * FROM source_class
 UNION ALL SELECT * FROM relations WHERE $2::boolean AND relname IN
  ('thread_history_clear_batches','thread_history_clear_completions')
),
physical_types AS (
 SELECT t.* FROM pg_catalog.pg_type t WHERE t.oid IN (
  SELECT r.reltype FROM physical_class r UNION ALL
  SELECT t.typarray FROM physical_class r JOIN pg_catalog.pg_type t ON t.oid=r.reltype)
),
physical_toast AS (SELECT c.* FROM pg_catalog.pg_class c WHERE c.oid IN (SELECT reltoastrelid FROM physical_class)),
physical_toast_indexes AS (SELECT i.* FROM pg_catalog.pg_index i WHERE i.indrelid IN (SELECT oid FROM physical_toast)),
clear_physical_facts AS (
 SELECT r.relname,pg_catalog.jsonb_build_object(
  'name',r.relname,
  'sourceClass',(SELECT (pg_catalog.to_jsonb(s)-'schema_name')||pg_catalog.jsonb_build_object('oid',s.oid::pg_catalog.int8,'relnamespace',s.relnamespace::pg_catalog.int8,'reltype',s.reltype::pg_catalog.int8,'reloftype',s.reloftype::pg_catalog.int8,'relowner',s.relowner::pg_catalog.int8,'relam',s.relam::pg_catalog.int8,'relfilenode',s.relfilenode::pg_catalog.int8,'reltablespace',s.reltablespace::pg_catalog.int8,'reltoastrelid',s.reltoastrelid::pg_catalog.int8,'relrewrite',s.relrewrite::pg_catalog.int8) FROM physical_class s WHERE s.oid=r.oid),
  'sourceTypes',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(t)||pg_catalog.jsonb_build_object('oid',t.oid::pg_catalog.int8,'typnamespace',t.typnamespace::pg_catalog.int8,'typowner',t.typowner::pg_catalog.int8,'typrelid',t.typrelid::pg_catalog.int8,'typelem',t.typelem::pg_catalog.int8,'typarray',t.typarray::pg_catalog.int8,'typbasetype',t.typbasetype::pg_catalog.int8,'typcollation',t.typcollation::pg_catalog.int8,'typinput',t.typinput::pg_catalog.oid::pg_catalog.int8,'typoutput',t.typoutput::pg_catalog.oid::pg_catalog.int8,'typreceive',t.typreceive::pg_catalog.oid::pg_catalog.int8,'typsend',t.typsend::pg_catalog.oid::pg_catalog.int8,'typmodin',t.typmodin::pg_catalog.oid::pg_catalog.int8,'typmodout',t.typmodout::pg_catalog.oid::pg_catalog.int8,'typanalyze',t.typanalyze::pg_catalog.oid::pg_catalog.int8,'typsubscript',t.typsubscript::pg_catalog.oid::pg_catalog.int8) ORDER BY t.oid),'[]'::jsonb) FROM physical_types t WHERE t.typrelid=r.oid OR t.typelem=r.reltype),
  'sourceAttributes',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(a)||pg_catalog.jsonb_build_object('attrelid',a.attrelid::pg_catalog.int8,'atttypid',a.atttypid::pg_catalog.int8,'attcollation',a.attcollation::pg_catalog.int8) ORDER BY a.attnum),'[]'::jsonb) FROM pg_catalog.pg_attribute a WHERE a.attrelid=r.oid AND a.attnum>0),
  'sourceToast',pg_catalog.jsonb_build_object(
   'relation',(SELECT pg_catalog.to_jsonb(t)||pg_catalog.jsonb_build_object('oid',t.oid::pg_catalog.int8,'relnamespace',t.relnamespace::pg_catalog.int8,'reltype',t.reltype::pg_catalog.int8,'reloftype',t.reloftype::pg_catalog.int8,'relowner',t.relowner::pg_catalog.int8,'relam',t.relam::pg_catalog.int8,'relfilenode',t.relfilenode::pg_catalog.int8,'reltablespace',t.reltablespace::pg_catalog.int8,'reltoastrelid',t.reltoastrelid::pg_catalog.int8,'relrewrite',t.relrewrite::pg_catalog.int8) FROM physical_toast t WHERE t.oid=r.reltoastrelid),
   'indexes',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('class',pg_catalog.to_jsonb(c)||pg_catalog.jsonb_build_object('oid',c.oid::pg_catalog.int8,'relnamespace',c.relnamespace::pg_catalog.int8,'reltype',c.reltype::pg_catalog.int8,'reloftype',c.reloftype::pg_catalog.int8,'relowner',c.relowner::pg_catalog.int8,'relam',c.relam::pg_catalog.int8,'relfilenode',c.relfilenode::pg_catalog.int8,'reltablespace',c.reltablespace::pg_catalog.int8,'reltoastrelid',c.reltoastrelid::pg_catalog.int8,'relrewrite',c.relrewrite::pg_catalog.int8),'index',pg_catalog.to_jsonb(i)||pg_catalog.jsonb_build_object('indexrelid',i.indexrelid::pg_catalog.int8,'indrelid',i.indrelid::pg_catalog.int8)||pg_catalog.jsonb_build_object('indkey',pg_catalog.to_jsonb(i.indkey::smallint[]),'indclass',pg_catalog.to_jsonb(i.indclass::pg_catalog.oid[]::pg_catalog.int8[]),'indcollation',pg_catalog.to_jsonb(i.indcollation::pg_catalog.oid[]::pg_catalog.int8[]),'indoption',pg_catalog.to_jsonb(i.indoption::smallint[]))) ORDER BY i.indexrelid),'[]'::jsonb) FROM physical_toast_indexes i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid WHERE i.indrelid=r.reltoastrelid),
   'attributes',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(a)||pg_catalog.jsonb_build_object('attrelid',a.attrelid::pg_catalog.int8,'atttypid',a.atttypid::pg_catalog.int8,'attcollation',a.attcollation::pg_catalog.int8) ORDER BY a.attnum),'[]'::jsonb) FROM pg_catalog.pg_attribute a WHERE a.attrelid=r.reltoastrelid AND a.attnum>0),
   'operatorClasses',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('class',pg_catalog.to_jsonb(o)||pg_catalog.jsonb_build_object('oid',o.oid::pg_catalog.int8,'opcmethod',o.opcmethod::pg_catalog.int8,'opcnamespace',o.opcnamespace::pg_catalog.int8,'opcowner',o.opcowner::pg_catalog.int8,'opcfamily',o.opcfamily::pg_catalog.int8,'opcintype',o.opcintype::pg_catalog.int8,'opckeytype',o.opckeytype::pg_catalog.int8),'family',pg_catalog.to_jsonb(f)||pg_catalog.jsonb_build_object('oid',f.oid::pg_catalog.int8,'opfmethod',f.opfmethod::pg_catalog.int8,'opfnamespace',f.opfnamespace::pg_catalog.int8,'opfowner',f.opfowner::pg_catalog.int8),'method',pg_catalog.to_jsonb(m)||pg_catalog.jsonb_build_object('oid',m.oid::pg_catalog.int8,'amhandler',m.amhandler::pg_catalog.oid::pg_catalog.int8)) ORDER BY o.oid),'[]'::jsonb)
    FROM pg_catalog.pg_opclass o JOIN pg_catalog.pg_opfamily f ON f.oid=o.opcfamily JOIN pg_catalog.pg_am m ON m.oid=o.opcmethod
    WHERE o.oid IN (SELECT pg_catalog.unnest(i.indclass::pg_catalog.oid[]) FROM physical_toast_indexes i WHERE i.indrelid=r.reltoastrelid))),
  'sourceDefaults',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('oid',d.oid::pg_catalog.int8,'adrelid',d.adrelid::pg_catalog.int8,'adnum',d.adnum) ORDER BY d.oid),'[]'::jsonb) FROM pg_catalog.pg_attrdef d WHERE d.adrelid=r.oid)
 ) AS facts FROM physical_class r WHERE $2::boolean AND r.relname IN
  ('thread_history_clear_batches','thread_history_clear_completions')
),
new_functions AS (SELECT p.* FROM named_guards p WHERE p.proname IN ('thread_history_preview','thread_history_lock_joint','thread_history_lock_channel_ids','thread_history_related_channel_ids','thread_history_validate_channel_source','guard_channel_history_source','guard_thread_history_channel_projection','thread_history_validate_channel_final','require_thread_history_channel_final','thread_history_terminal_payload','guard_thread_history_body','thread_history_validate_terminal_run','require_thread_history_terminal_final','guard_thread_history_canonical_reverse','prevent_thread_history_writer_truncate')
 OR ($2::boolean AND p.proname IN ('guard_thread_history_clear_fact','thread_history_clear_batch_active','thread_history_clear_event_payload','require_thread_history_clear_completion','thread_history_clear_readers_quiescent','thread_history_clear_bodies_erased','require_thread_history_maintenance_source','guard_thread_history_memory_body'))),
new_triggers AS (SELECT t.* FROM triggers_scope t WHERE t.tgfoid IN (SELECT oid FROM new_functions)),
new_constraints AS (SELECT c.* FROM constraints_scope c WHERE c.conrelid IN (SELECT oid FROM physical_class)
 OR c.oid IN (SELECT tgconstraint FROM new_triggers WHERE tgconstraint<>0)),
writer_addresses(classid,objid) AS (
 SELECT 'pg_catalog.pg_class'::pg_catalog.regclass::oid,r.oid FROM physical_class r
 UNION ALL SELECT 'pg_catalog.pg_class'::pg_catalog.regclass::oid,i.indexrelid FROM indexes_scope i WHERE i.indrelid IN (SELECT oid FROM physical_class)
 UNION ALL SELECT 'pg_catalog.pg_class'::pg_catalog.regclass::oid,t.oid FROM physical_toast t
 UNION ALL SELECT 'pg_catalog.pg_class'::pg_catalog.regclass::oid,i.indexrelid FROM physical_toast_indexes i
 UNION ALL SELECT 'pg_catalog.pg_type'::pg_catalog.regclass::oid,t.oid FROM physical_types t
 UNION ALL SELECT 'pg_catalog.pg_proc'::pg_catalog.regclass::oid,p.oid FROM new_functions p
 UNION ALL SELECT 'pg_catalog.pg_trigger'::pg_catalog.regclass::oid,t.oid FROM new_triggers t
 UNION ALL SELECT 'pg_catalog.pg_constraint'::pg_catalog.regclass::oid,c.oid FROM new_constraints c
 UNION ALL SELECT 'pg_catalog.pg_attrdef'::pg_catalog.regclass::oid,d.oid FROM pg_catalog.pg_attrdef d WHERE d.adrelid IN (SELECT oid FROM physical_class)
),
writer_expression_facts AS (
 SELECT c.conname AS name,c.conkey AS attnums,pg_catalog.pg_get_constraintdef(c.oid,false) AS deparsed,c.conbin::text AS node_tree
 FROM new_constraints c WHERE c.contype='c' AND c.conrelid IN (SELECT oid FROM source_class)
 UNION ALL
 SELECT 'channel_history_sources.'||a.attname,ARRAY[a.attnum]::smallint[],pg_catalog.pg_get_expr(d.adbin,d.adrelid,false),d.adbin::text
 FROM pg_catalog.pg_attrdef d JOIN pg_catalog.pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum
 WHERE d.adrelid IN (SELECT oid FROM source_class)
 UNION ALL
 SELECT c.conname,c.conkey,pg_catalog.pg_get_constraintdef(c.oid,false),c.conbin::text
 FROM constraints_scope c WHERE $2::boolean AND c.contype='c'
  AND (c.conrelid IN (SELECT oid FROM relations WHERE relname IN
       ('thread_history_clear_batches','thread_history_clear_completions'))
       OR c.conname IN ('thread_history_clear_intents_kind_check',
           'thread_history_clear_intents_maintenance_actor_check','component_human_decisions_answer_shape',
           'memories_scope_shape','memories_content_shape','memories_source_run_shape','memories_source_authorization_shape'))
 UNION ALL
 SELECT r.relname||'.'||a.attname,ARRAY[a.attnum]::smallint[],
  pg_catalog.pg_get_expr(d.adbin,d.adrelid,false),d.adbin::text
 FROM relations r JOIN pg_catalog.pg_attrdef d ON d.adrelid=r.oid
 JOIN pg_catalog.pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum
 WHERE $2::boolean AND r.relname IN ('thread_history_clear_batches','thread_history_clear_completions')
)
SELECT pg_catalog.jsonb_build_object(
 'format','thread-history-writer-raw-v1',
 'storage',pg_catalog.jsonb_build_object(
  'serverEncoding',pg_catalog.current_setting('server_encoding'),
  'blockSize',pg_catalog.current_setting('block_size')::integer,
  'serverVersion',pg_catalog.current_setting('server_version_num')::integer),
 'deparseContextRaw',pg_catalog.jsonb_build_object(
  'searchPath',pg_catalog.current_setting('search_path'),'currentSchemas',pg_catalog.current_schemas(false),'currentSchemasWithImplicit',pg_catalog.current_schemas(true)),
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
    WHERE n.nspname='pg_catalog' AND (t.typname IN ('text','timestamptz','int2','int4','int8','jsonb','trigger','bool','void','_text') OR ($2::boolean AND t.typname='xid8'))),
  'collation',(SELECT pg_catalog.jsonb_build_object('oidRaw',c.oid::text,'schema',n.nspname,'name',c.collname)
    FROM pg_catalog.pg_collation c JOIN pg_catalog.pg_namespace n ON n.oid=c.collnamespace
    WHERE n.nspname='pg_catalog' AND c.collname='C' AND c.collencoding=-1),
  'operatorClasses',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('oidRaw',c.oid::text,'schema',n.nspname,'name',c.opcname,
    'familyOidRaw',f.oid::text,'familySchema',fn.nspname,'familyName',f.opfname)
    ORDER BY c.opcname COLLATE pg_catalog."C")
    FROM pg_catalog.pg_opclass c JOIN pg_catalog.pg_namespace n ON n.oid=c.opcnamespace
    JOIN pg_catalog.pg_am a ON a.oid=c.opcmethod JOIN pg_catalog.pg_opfamily f ON f.oid=c.opcfamily
    JOIN pg_catalog.pg_namespace fn ON fn.oid=f.opfnamespace
    WHERE n.nspname='pg_catalog' AND (c.opcname IN ('text_ops','int8_ops','timestamptz_ops') OR ($2::boolean AND c.opcname='xid8_ops')) AND a.amname='btree'),
  'equalityOperators',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('oidRaw',op.oid::text,'schema',ons.nspname,'name',op.oprname,
    'leftType',pg_catalog.format_type(op.oprleft,NULL),'rightType',pg_catalog.format_type(op.oprright,NULL),'resultType',pg_catalog.format_type(op.oprresult,NULL),
    'function',pg_catalog.jsonb_build_object('oidRaw',p.oid::text,'schema',pn.nspname,'name',p.proname,'arguments',pg_catalog.pg_get_function_identity_arguments(p.oid)))
    ORDER BY op.oprleft)
    FROM pg_catalog.pg_operator op JOIN pg_catalog.pg_namespace ons ON ons.oid=op.oprnamespace
    JOIN pg_catalog.pg_proc p ON p.oid=op.oprcode JOIN pg_catalog.pg_namespace pn ON pn.oid=p.pronamespace
    WHERE ons.nspname='pg_catalog' AND op.oprname='=' AND (op.oprleft IN (20,25,1184) OR ($2::boolean AND op.oprleft=5069)) AND op.oprright=op.oprleft)

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
   WHERE (n.nspname='public' AND c.relname IN ('threads','runs','messages','run_events','tool_approvals','component_human_decisions','remote_agent_interrupts','channels'))
      OR (n.nspname='openbot_internal' AND c.relname='schema_migrations')
      OR ($2::boolean AND n.nspname='public' AND c.relname='memories')
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
 'writerRaw',pg_catalog.jsonb_build_object(
  'sourceClass',(SELECT (pg_catalog.to_jsonb(r)-'schema_name')||pg_catalog.jsonb_build_object('oid',r.oid::pg_catalog.int8,'relnamespace',r.relnamespace::pg_catalog.int8,'reltype',r.reltype::pg_catalog.int8,'reloftype',r.reloftype::pg_catalog.int8,'relowner',r.relowner::pg_catalog.int8,'relam',r.relam::pg_catalog.int8,'relfilenode',r.relfilenode::pg_catalog.int8,'reltablespace',r.reltablespace::pg_catalog.int8,'reltoastrelid',r.reltoastrelid::pg_catalog.int8,'relrewrite',r.relrewrite::pg_catalog.int8) FROM source_class r),
  'sourceTypes',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(t)||pg_catalog.jsonb_build_object('oid',t.oid::pg_catalog.int8,'typnamespace',t.typnamespace::pg_catalog.int8,'typowner',t.typowner::pg_catalog.int8,'typrelid',t.typrelid::pg_catalog.int8,'typelem',t.typelem::pg_catalog.int8,'typarray',t.typarray::pg_catalog.int8,'typbasetype',t.typbasetype::pg_catalog.int8,'typcollation',t.typcollation::pg_catalog.int8,'typinput',t.typinput::pg_catalog.oid::pg_catalog.int8,'typoutput',t.typoutput::pg_catalog.oid::pg_catalog.int8,'typreceive',t.typreceive::pg_catalog.oid::pg_catalog.int8,'typsend',t.typsend::pg_catalog.oid::pg_catalog.int8,'typmodin',t.typmodin::pg_catalog.oid::pg_catalog.int8,'typmodout',t.typmodout::pg_catalog.oid::pg_catalog.int8,'typanalyze',t.typanalyze::pg_catalog.oid::pg_catalog.int8,'typsubscript',t.typsubscript::pg_catalog.oid::pg_catalog.int8) ORDER BY t.oid),'[]'::jsonb) FROM source_types t),
  'sourceAttributes',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(a)||pg_catalog.jsonb_build_object('attrelid',a.attrelid::pg_catalog.int8,'atttypid',a.atttypid::pg_catalog.int8,'attcollation',a.attcollation::pg_catalog.int8) ORDER BY a.attnum),'[]'::jsonb) FROM pg_catalog.pg_attribute a WHERE a.attrelid IN (SELECT oid FROM source_class) AND a.attnum>0),
  'sourceToast',pg_catalog.jsonb_build_object(
   'relation',(SELECT pg_catalog.to_jsonb(t)||pg_catalog.jsonb_build_object('oid',t.oid::pg_catalog.int8,'relnamespace',t.relnamespace::pg_catalog.int8,'reltype',t.reltype::pg_catalog.int8,'reloftype',t.reloftype::pg_catalog.int8,'relowner',t.relowner::pg_catalog.int8,'relam',t.relam::pg_catalog.int8,'relfilenode',t.relfilenode::pg_catalog.int8,'reltablespace',t.reltablespace::pg_catalog.int8,'reltoastrelid',t.reltoastrelid::pg_catalog.int8,'relrewrite',t.relrewrite::pg_catalog.int8) FROM source_toast t),
   'indexes',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('class',pg_catalog.to_jsonb(c)||pg_catalog.jsonb_build_object('oid',c.oid::pg_catalog.int8,'relnamespace',c.relnamespace::pg_catalog.int8,'reltype',c.reltype::pg_catalog.int8,'reloftype',c.reloftype::pg_catalog.int8,'relowner',c.relowner::pg_catalog.int8,'relam',c.relam::pg_catalog.int8,'relfilenode',c.relfilenode::pg_catalog.int8,'reltablespace',c.reltablespace::pg_catalog.int8,'reltoastrelid',c.reltoastrelid::pg_catalog.int8,'relrewrite',c.relrewrite::pg_catalog.int8),'index',pg_catalog.to_jsonb(i)||pg_catalog.jsonb_build_object('indexrelid',i.indexrelid::pg_catalog.int8,'indrelid',i.indrelid::pg_catalog.int8)||pg_catalog.jsonb_build_object('indkey',pg_catalog.to_jsonb(i.indkey::smallint[]),'indclass',pg_catalog.to_jsonb(i.indclass::pg_catalog.oid[]::pg_catalog.int8[]),'indcollation',pg_catalog.to_jsonb(i.indcollation::pg_catalog.oid[]::pg_catalog.int8[]),'indoption',pg_catalog.to_jsonb(i.indoption::smallint[]))) ORDER BY i.indexrelid),'[]'::jsonb) FROM source_toast_indexes i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid),
   'attributes',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(a)||pg_catalog.jsonb_build_object('attrelid',a.attrelid::pg_catalog.int8,'atttypid',a.atttypid::pg_catalog.int8,'attcollation',a.attcollation::pg_catalog.int8) ORDER BY a.attnum),'[]'::jsonb) FROM pg_catalog.pg_attribute a WHERE a.attrelid IN (SELECT oid FROM source_toast) AND a.attnum>0),
   'operatorClasses',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('class',pg_catalog.to_jsonb(o)||pg_catalog.jsonb_build_object('oid',o.oid::pg_catalog.int8,'opcmethod',o.opcmethod::pg_catalog.int8,'opcnamespace',o.opcnamespace::pg_catalog.int8,'opcowner',o.opcowner::pg_catalog.int8,'opcfamily',o.opcfamily::pg_catalog.int8,'opcintype',o.opcintype::pg_catalog.int8,'opckeytype',o.opckeytype::pg_catalog.int8),'family',pg_catalog.to_jsonb(f)||pg_catalog.jsonb_build_object('oid',f.oid::pg_catalog.int8,'opfmethod',f.opfmethod::pg_catalog.int8,'opfnamespace',f.opfnamespace::pg_catalog.int8,'opfowner',f.opfowner::pg_catalog.int8),'method',pg_catalog.to_jsonb(m)||pg_catalog.jsonb_build_object('oid',m.oid::pg_catalog.int8,'amhandler',m.amhandler::pg_catalog.oid::pg_catalog.int8)) ORDER BY o.oid),'[]'::jsonb)
    FROM pg_catalog.pg_opclass o JOIN pg_catalog.pg_opfamily f ON f.oid=o.opcfamily JOIN pg_catalog.pg_am m ON m.oid=o.opcmethod
    WHERE o.oid IN (SELECT pg_catalog.unnest(i.indclass::pg_catalog.oid[]) FROM source_toast_indexes i))),
  'newFunctionLanguages',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('oid',p.oid::pg_catalog.int8,'prolang',p.prolang::pg_catalog.int8) ORDER BY p.oid),'[]'::jsonb) FROM new_functions p),
  'plpgsql',(SELECT pg_catalog.to_jsonb(l)||pg_catalog.jsonb_build_object('oid',l.oid::pg_catalog.int8,'lanowner',l.lanowner::pg_catalog.int8,'lanplcallfoid',l.lanplcallfoid::pg_catalog.int8,'laninline',l.laninline::pg_catalog.int8,'lanvalidator',l.lanvalidator::pg_catalog.int8) FROM pg_catalog.pg_language l WHERE l.lanname='plpgsql'),
  'languageContract',pg_catalog.jsonb_build_object(
   'format','pg17-plpgsql-extension-execution-contract-v1',
   'language',(SELECT pg_catalog.to_jsonb(l)||pg_catalog.jsonb_build_object('oid',l.oid::pg_catalog.int8,'lanowner',l.lanowner::pg_catalog.int8,'lanplcallfoid',l.lanplcallfoid::pg_catalog.int8,'laninline',l.laninline::pg_catalog.int8,'lanvalidator',l.lanvalidator::pg_catalog.int8) FROM pg_catalog.pg_language l WHERE l.lanname='plpgsql'),
   'functions',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(p)||pg_catalog.jsonb_build_object('oid',p.oid::pg_catalog.int8,'pronamespace',p.pronamespace::pg_catalog.int8,'proowner',p.proowner::pg_catalog.int8,'prolang',p.prolang::pg_catalog.int8,'provariadic',p.provariadic::pg_catalog.int8,'prosupport',p.prosupport::pg_catalog.oid::pg_catalog.int8,'prorettype',p.prorettype::pg_catalog.int8,'proargtypes',pg_catalog.to_jsonb(p.proargtypes::pg_catalog.oid[]::pg_catalog.int8[]),'proallargtypes',pg_catalog.to_jsonb(p.proallargtypes::pg_catalog.oid[]::pg_catalog.int8[]),'protrftypes',pg_catalog.to_jsonb(p.protrftypes::pg_catalog.oid[]::pg_catalog.int8[])) ORDER BY p.oid),'[]'::jsonb)
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pg_catalog' AND p.proname IN ('plpgsql_call_handler','plpgsql_inline_handler','plpgsql_validator')),
   'languageEffectiveAcl',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('grantor',a.grantor::pg_catalog.int8,'grantee',a.grantee::pg_catalog.int8,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantor,a.grantee,a.privilege_type COLLATE pg_catalog."C",a.is_grantable),'[]'::jsonb)
    FROM pg_catalog.pg_language l CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(l.lanacl,pg_catalog.acldefault('l'::pg_catalog."char",l.lanowner))) a WHERE l.lanname='plpgsql'),
   'functionEffectiveAcls',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('name',p.proname,'acl',(
     SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('grantor',a.grantor::pg_catalog.int8,'grantee',a.grantee::pg_catalog.int8,'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantor,a.grantee,a.privilege_type COLLATE pg_catalog."C",a.is_grantable),'[]'::jsonb)
     FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f'::pg_catalog."char",p.proowner))) a
    )) ORDER BY p.proname COLLATE pg_catalog."C",p.oid),'[]'::jsonb)
    FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='pg_catalog' AND p.proname IN ('plpgsql_call_handler','plpgsql_inline_handler','plpgsql_validator'))),
  'sourceDefaults',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('oid',d.oid::pg_catalog.int8,'adrelid',d.adrelid::pg_catalog.int8,'adnum',d.adnum) ORDER BY d.oid),'[]'::jsonb) FROM pg_catalog.pg_attrdef d WHERE d.adrelid IN (SELECT oid FROM source_class)),
  'databaseOid',(SELECT d.oid::pg_catalog.int8 FROM pg_catalog.pg_database d WHERE d.datname=pg_catalog.current_database()),
  'sharedDependencies',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(d)||pg_catalog.jsonb_build_object('dbid',d.dbid::pg_catalog.int8,'classid',d.classid::pg_catalog.int8,'objid',d.objid::pg_catalog.int8,'refclassid',d.refclassid::pg_catalog.int8,'refobjid',d.refobjid::pg_catalog.int8) ORDER BY d.classid,d.objid,d.objsubid,d.refclassid,d.refobjid,d.deptype),'[]'::jsonb) FROM pg_catalog.pg_shdepend d WHERE d.dbid=(SELECT db.oid FROM pg_catalog.pg_database db WHERE db.datname=pg_catalog.current_database()) AND EXISTS(SELECT 1 FROM writer_addresses a WHERE a.classid=d.classid AND a.objid=d.objid)),
  'dependencies',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(d)||pg_catalog.jsonb_build_object('classid',d.classid::pg_catalog.int8,'objid',d.objid::pg_catalog.int8,'refclassid',d.refclassid::pg_catalog.int8,'refobjid',d.refobjid::pg_catalog.int8) ORDER BY d.classid,d.objid,d.objsubid,d.refclassid,d.refobjid,d.refobjsubid,d.deptype),'[]'::jsonb)
    FROM pg_catalog.pg_depend d WHERE EXISTS(SELECT 1 FROM writer_addresses a WHERE (a.classid=d.classid AND a.objid=d.objid) OR (a.classid=d.refclassid AND a.objid=d.refobjid))),
  'sourceExpressions',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('name',f.name,'attnums',f.attnums,'deparsed',f.deparsed,'nodeTree',f.node_tree) ORDER BY f.name COLLATE pg_catalog."C"),'[]'::jsonb) FROM writer_expression_facts f),
  'builtinFunctions',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(p)||pg_catalog.jsonb_build_object('oid',p.oid::pg_catalog.int8,'pronamespace',p.pronamespace::pg_catalog.int8,'proowner',p.proowner::pg_catalog.int8,'prolang',p.prolang::pg_catalog.int8,'provariadic',p.provariadic::pg_catalog.int8,'prosupport',p.prosupport::pg_catalog.oid::pg_catalog.int8,'prorettype',p.prorettype::pg_catalog.int8,'proargtypes',pg_catalog.to_jsonb(p.proargtypes::pg_catalog.oid[]::pg_catalog.int8[]),'proallargtypes',pg_catalog.to_jsonb(p.proallargtypes::pg_catalog.oid[]::pg_catalog.int8[]),'protrftypes',pg_catalog.to_jsonb(p.protrftypes::pg_catalog.oid[]::pg_catalog.int8[])) ORDER BY p.oid),'[]'::jsonb)
    FROM pg_catalog.pg_proc p WHERE p.oid IN (SELECT (x->>'oid')::pg_catalog.oid FROM pg_catalog.jsonb_array_elements($1::jsonb->'builtinFunctions') x)),
  'builtinOperators',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(p)||pg_catalog.jsonb_build_object('oid',p.oid::pg_catalog.int8,'oprnamespace',p.oprnamespace::pg_catalog.int8,'oprowner',p.oprowner::pg_catalog.int8,'oprleft',p.oprleft::pg_catalog.int8,'oprright',p.oprright::pg_catalog.int8,'oprresult',p.oprresult::pg_catalog.int8,'oprcom',p.oprcom::pg_catalog.int8,'oprnegate',p.oprnegate::pg_catalog.int8,'oprcode',p.oprcode::pg_catalog.oid::pg_catalog.int8,'oprrest',p.oprrest::pg_catalog.oid::pg_catalog.int8,'oprjoin',p.oprjoin::pg_catalog.oid::pg_catalog.int8) ORDER BY p.oid),'[]'::jsonb)
    FROM pg_catalog.pg_operator p WHERE p.oid IN (SELECT (x->>'oid')::pg_catalog.oid FROM pg_catalog.jsonb_array_elements($1::jsonb->'builtinOperators') x)),
  'builtinCasts',(SELECT coalesce(pg_catalog.jsonb_agg((pg_catalog.to_jsonb(p)-'oid')||pg_catalog.jsonb_build_object('castsource',p.castsource::pg_catalog.int8,'casttarget',p.casttarget::pg_catalog.int8,'castfunc',p.castfunc::pg_catalog.int8) ORDER BY p.castsource,p.casttarget),'[]'::jsonb)
    FROM pg_catalog.pg_cast p WHERE EXISTS(SELECT 1 FROM pg_catalog.jsonb_array_elements($1::jsonb->'builtinCasts') x WHERE p.castsource=(x->>'castsource')::pg_catalog.oid AND p.casttarget=(x->>'casttarget')::pg_catalog.oid)),
  'accessMethods',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(p)||pg_catalog.jsonb_build_object('oid',p.oid::pg_catalog.int8,'amhandler',p.amhandler::pg_catalog.oid::pg_catalog.int8) ORDER BY p.oid),'[]'::jsonb) FROM pg_catalog.pg_am p WHERE p.oid IN(SELECT(x->>'oid')::pg_catalog.oid FROM pg_catalog.jsonb_array_elements($1::jsonb->'accessMethods')x)),
  'toastOperatorClasses',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(p)||pg_catalog.jsonb_build_object('oid',p.oid::pg_catalog.int8,'opcmethod',p.opcmethod::pg_catalog.int8,'opcnamespace',p.opcnamespace::pg_catalog.int8,'opcowner',p.opcowner::pg_catalog.int8,'opcfamily',p.opcfamily::pg_catalog.int8,'opcintype',p.opcintype::pg_catalog.int8,'opckeytype',p.opckeytype::pg_catalog.int8) ORDER BY p.oid),'[]'::jsonb) FROM pg_catalog.pg_opclass p WHERE p.oid IN(SELECT(x->>'oid')::pg_catalog.oid FROM pg_catalog.jsonb_array_elements($1::jsonb->'toastOperatorClasses')x)),
  'toastOperatorFamilies',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(p)||pg_catalog.jsonb_build_object('oid',p.oid::pg_catalog.int8,'opfmethod',p.opfmethod::pg_catalog.int8,'opfnamespace',p.opfnamespace::pg_catalog.int8,'opfowner',p.opfowner::pg_catalog.int8) ORDER BY p.oid),'[]'::jsonb) FROM pg_catalog.pg_opfamily p WHERE p.oid IN(SELECT(x->>'oid')::pg_catalog.oid FROM pg_catalog.jsonb_array_elements($1::jsonb->'toastOperatorFamilies')x)),
  'collations',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(p)||pg_catalog.jsonb_build_object('oid',p.oid::pg_catalog.int8,'collnamespace',p.collnamespace::pg_catalog.int8,'collowner',p.collowner::pg_catalog.int8) ORDER BY p.oid),'[]'::jsonb) FROM pg_catalog.pg_collation p WHERE p.oid IN(SELECT(x->>'oid')::pg_catalog.oid FROM pg_catalog.jsonb_array_elements($1::jsonb->'collations')x)),
  'aggregates',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(p)||pg_catalog.jsonb_build_object('aggfnoid',p.aggfnoid::pg_catalog.oid::pg_catalog.int8,'aggtransfn',p.aggtransfn::pg_catalog.oid::pg_catalog.int8,'aggfinalfn',p.aggfinalfn::pg_catalog.oid::pg_catalog.int8,'aggcombinefn',p.aggcombinefn::pg_catalog.oid::pg_catalog.int8,'aggserialfn',p.aggserialfn::pg_catalog.oid::pg_catalog.int8,'aggdeserialfn',p.aggdeserialfn::pg_catalog.oid::pg_catalog.int8,'aggmtransfn',p.aggmtransfn::pg_catalog.oid::pg_catalog.int8,'aggminvtransfn',p.aggminvtransfn::pg_catalog.oid::pg_catalog.int8,'aggmfinalfn',p.aggmfinalfn::pg_catalog.oid::pg_catalog.int8,'aggsortop',p.aggsortop::pg_catalog.int8,'aggtranstype',p.aggtranstype::pg_catalog.int8,'aggmtranstype',p.aggmtranstype::pg_catalog.int8) ORDER BY p.aggfnoid),'[]'::jsonb)
    FROM pg_catalog.pg_aggregate p WHERE p.aggfnoid IN (SELECT (x->>'aggfnoid')::pg_catalog.oid FROM pg_catalog.jsonb_array_elements($1::jsonb->'aggregates') x))) || CASE WHEN $2::boolean THEN pg_catalog.jsonb_build_object(
  'clearRelations',(SELECT coalesce(pg_catalog.jsonb_agg(c.facts ORDER BY c.relname COLLATE pg_catalog."C"),'[]'::jsonb) FROM clear_physical_facts c)
 ) ELSE '{}'::jsonb END,
 'relations',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.relname COLLATE pg_catalog."C"),'[]'::jsonb) FROM relation_facts f),
 'constraints',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.relname COLLATE pg_catalog."C",f.conname COLLATE pg_catalog."C",f.contype::text COLLATE pg_catalog."C"),'[]'::jsonb) FROM constraint_facts f),
 'indexes',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.relname COLLATE pg_catalog."C"),'[]'::jsonb) FROM index_facts f),
 'triggers',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.relname COLLATE pg_catalog."C",f.tgname COLLATE pg_catalog."C"),'[]'::jsonb) FROM trigger_facts f),
 'functions',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.proname COLLATE pg_catalog."C",f.identity_arguments COLLATE pg_catalog."C"),'[]'::jsonb) FROM function_facts f)
)::text AS thread_history_raw,
NOT EXISTS (
 (SELECT p.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable
  FROM functions_scope p
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f'::pg_catalog."char",p.proowner))) a WHERE p.proname NOT IN ('thread_history_preview','thread_history_lock_joint','thread_history_lock_channel_ids','thread_history_related_channel_ids','thread_history_validate_channel_source','guard_channel_history_source','guard_thread_history_channel_projection','thread_history_validate_channel_final','require_thread_history_channel_final','thread_history_terminal_payload','guard_thread_history_body','thread_history_validate_terminal_run','require_thread_history_terminal_final','guard_thread_history_canonical_reverse','prevent_thread_history_writer_truncate','guard_thread_history_clear_fact','thread_history_clear_batch_active','thread_history_clear_event_payload','require_thread_history_clear_completion','thread_history_clear_readers_quiescent','thread_history_clear_bodies_erased','require_thread_history_maintenance_source','guard_thread_history_memory_body'))
 EXCEPT ALL
 (SELECT p.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable
  FROM functions_scope p
  CROSS JOIN LATERAL pg_catalog.aclexplode(pg_catalog.acldefault('f'::pg_catalog."char",p.proowner)) a WHERE p.proname NOT IN ('thread_history_preview','thread_history_lock_joint','thread_history_lock_channel_ids','thread_history_related_channel_ids','thread_history_validate_channel_source','guard_channel_history_source','guard_thread_history_channel_projection','thread_history_validate_channel_final','require_thread_history_channel_final','thread_history_terminal_payload','guard_thread_history_body','thread_history_validate_terminal_run','require_thread_history_terminal_final','guard_thread_history_canonical_reverse','prevent_thread_history_writer_truncate','guard_thread_history_clear_fact','thread_history_clear_batch_active','thread_history_clear_event_payload','require_thread_history_clear_completion','thread_history_clear_readers_quiescent','thread_history_clear_bodies_erased','require_thread_history_maintenance_source','guard_thread_history_memory_body'))
) AND NOT EXISTS (
 (SELECT p.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable
  FROM functions_scope p
  CROSS JOIN LATERAL pg_catalog.aclexplode(pg_catalog.acldefault('f'::pg_catalog."char",p.proowner)) a WHERE p.proname NOT IN ('thread_history_preview','thread_history_lock_joint','thread_history_lock_channel_ids','thread_history_related_channel_ids','thread_history_validate_channel_source','guard_channel_history_source','guard_thread_history_channel_projection','thread_history_validate_channel_final','require_thread_history_channel_final','thread_history_terminal_payload','guard_thread_history_body','thread_history_validate_terminal_run','require_thread_history_terminal_final','guard_thread_history_canonical_reverse','prevent_thread_history_writer_truncate','guard_thread_history_clear_fact','thread_history_clear_batch_active','thread_history_clear_event_payload','require_thread_history_clear_completion','thread_history_clear_readers_quiescent','thread_history_clear_bodies_erased','require_thread_history_maintenance_source','guard_thread_history_memory_body'))
 EXCEPT ALL
 (SELECT p.oid,a.grantor,a.grantee,a.privilege_type,a.is_grantable
  FROM functions_scope p
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f'::pg_catalog."char",p.proowner))) a WHERE p.proname NOT IN ('thread_history_preview','thread_history_lock_joint','thread_history_lock_channel_ids','thread_history_related_channel_ids','thread_history_validate_channel_source','guard_channel_history_source','guard_thread_history_channel_projection','thread_history_validate_channel_final','require_thread_history_channel_final','thread_history_terminal_payload','guard_thread_history_body','thread_history_validate_terminal_run','require_thread_history_terminal_final','guard_thread_history_canonical_reverse','prevent_thread_history_writer_truncate','guard_thread_history_clear_fact','thread_history_clear_batch_active','thread_history_clear_event_payload','require_thread_history_clear_completion','thread_history_clear_readers_quiescent','thread_history_clear_bodies_erased','require_thread_history_maintenance_source','guard_thread_history_memory_body'))
) AS function_acl_matches_builtin
"####;

fn erase_checked_oid_fields(v: &mut Value) {
    match v {
        Value::Object(o) => {
            for key in ["oidRaw", "ownerOidRaw", "indexOidRaw", "constraintOidRaw"] {
                o.remove(key);
            }
            for child in o.values_mut() {
                erase_checked_oid_fields(child);
            }
        }
        Value::Array(a) => {
            for child in a {
                erase_checked_oid_fields(child);
            }
        }
        _ => {}
    }
}
fn sort_foreign_operator_multisets(v: &mut Value) -> Result<(), InfraError> {
    // Each complete operator row carries its family and ordinal. Preserve every
    // field and duplicate while comparing this unordered metadata multiset.
    // The original raw facts and all positional catalogue arrays remain intact.
    let constraints = v
        .get_mut("constraints")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| corrupt("thread_history_writer_schema_invalid"))?;
    for constraint in constraints {
        let operators = constraint
            .get_mut("foreignEqualityOperators")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| corrupt("thread_history_writer_schema_invalid"))?;
        let mut keyed = std::mem::take(operators)
            .into_iter()
            .map(|value| canonical_bytes(&value).map(|key| (key, value)))
            .collect::<Result<Vec<_>, _>>()?;
        keyed.sort_by(|left, right| left.0.cmp(&right.0));
        *operators = keyed.into_iter().map(|(_, value)| value).collect();
    }
    Ok(())
}
fn sort_top_level_multisets(v: &mut Value) -> Result<(), InfraError> {
    // Never sort column order, conkey/confkey, opclasses/collations, argument order
    // or proconfig. Only unordered top-level object multisets are canonically sorted.
    for key in [
        "relations",
        "constraints",
        "indexes",
        "triggers",
        "functions",
    ] {
        let a = v
            .get_mut(key)
            .and_then(Value::as_array_mut)
            .ok_or_else(|| corrupt("thread_history_writer_schema_invalid"))?;
        let mut keyed = std::mem::take(a)
            .into_iter()
            .map(|value| canonical_bytes(&value).map(|key| (key, value)))
            .collect::<Result<Vec<_>, _>>()?;
        keyed.sort_by(|left, right| left.0.cmp(&right.0));
        *a = keyed.into_iter().map(|(_, value)| value).collect(); // duplicates retained
    }
    Ok(())
}
fn canonical_value(v: &Value) -> Value {
    match v {
        Value::Object(o) => {
            let mut pairs = o.iter().collect::<Vec<_>>();
            pairs.sort_by_key(|(a, _)| *a);
            let mut out = serde_json::Map::new();
            for (key, value) in pairs {
                out.insert(key.clone(), canonical_value(value));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical_value).collect()),
        _ => v.clone(),
    }
}
fn canonical_bytes(v: &Value) -> Result<Vec<u8>, InfraError> {
    serde_json::to_vec(&canonical_value(v))
        .map_err(|_| corrupt("thread_history_writer_schema_invalid"))
}

fn corrupt(_field: &'static str) -> InfraError {
    InfraError::repository_invariant("thread_history_writer_schema_invalid")
}
fn require(value: bool) -> Result<(), InfraError> {
    if value { Ok(()) } else { Err(corrupt("shape")) }
}
fn obj(v: &Value) -> Result<&serde_json::Map<String, Value>, InfraError> {
    v.as_object().ok_or_else(|| corrupt("facts"))
}
fn arr(v: &Value) -> Result<&[Value], InfraError> {
    v.as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| corrupt("facts"))
}
fn text(v: &Value) -> Result<&str, InfraError> {
    v.as_str().ok_or_else(|| corrupt("facts"))
}
fn oid(v: &Value) -> Result<u32, InfraError> {
    text(v)?.parse::<u32>().map_err(|_| corrupt("oid"))
}
fn same_identity(v: &Value, schema: &str, name: &str) -> bool {
    v.get("schema").and_then(Value::as_str) == Some(schema)
        && v.get("name").and_then(Value::as_str) == Some(name)
}
fn unique(rows: &[Value], predicate: impl Fn(&Value) -> bool) -> Result<&Value, InfraError> {
    let mut matching = rows.iter().filter(|row| predicate(row));
    let first = matching.next().ok_or_else(|| corrupt("missing"))?;
    require(matching.next().is_none())?;
    Ok(first)
}
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Acl {
    grantor: u32,
    grantee: u32,
    privilege: String,
    grantable: bool,
}
fn acl_rows(v: &Value) -> Result<Vec<Acl>, InfraError> {
    let mut out = Vec::new();
    for row in arr(v)? {
        let keys = obj(row)?
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        require(
            keys == ["grantorOidRaw", "granteeOidRaw", "privilege", "grantable"]
                .into_iter()
                .collect(),
        )?;
        out.push(Acl {
            grantor: oid(&row["grantorOidRaw"])?,
            grantee: oid(&row["granteeOidRaw"])?,
            privilege: text(&row["privilege"])?.to_owned(),
            grantable: row["grantable"].as_bool().ok_or_else(|| corrupt("acl"))?,
        });
    }
    out.sort(); // Full multiset: no deduplication and no discarded grant options.
    Ok(out)
}
fn relative_acl(v: &Value, owner: u32) -> Result<Value, InfraError> {
    let rows = acl_rows(v)?;
    require(
        rows.iter()
            .all(|row| row.grantor == owner && row.grantee == owner && !row.grantable),
    )?;
    Ok(Value::Array(
        rows.into_iter()
            .map(|row| {
                json!({
                    "grantor":"original_threads_owner", "grantee":"original_threads_owner",
                    "privilege":row.privilege, "grantable":row.grantable
                })
            })
            .collect(),
    ))
}

fn check_storage(raw: &Value) -> Result<(), InfraError> {
    let server = raw["storage"]["serverVersion"]
        .as_i64()
        .ok_or_else(|| corrupt("storage"))?;
    if raw["storage"]["serverEncoding"] != "UTF8"
        || raw["storage"]["blockSize"] != 8192
        || !(170_000..180_000).contains(&server)
    {
        return Err(InfraError::repository_invariant(
            "thread_history_writer_schema_invalid",
        ));
    }
    Ok(())
}

const H: &str = "thread_history_heads";
const Q: &str = "thread_history_clear_intents";
const USER_FUNCTIONS: [&str; 7] = [
    "guard_thread_history_head_mutation",
    "prevent_thread_history_intent_mutation",
    "require_thread_history_intent_closed_head",
    "bind_thread_history_head_on_insert",
    "retain_thread_history_head_on_delete",
    "protect_thread_history_base_identity",
    "prevent_thread_history_base_truncate",
];

fn relation_oid(raw: &Value, identity: &Value) -> Result<u32, InfraError> {
    if identity["schema"] == "public" {
        let r = unique(arr(&raw["legacyOwnershipRaw"]["relations"])?, |r| {
            r["schema"] == identity["schema"] && r["name"] == identity["name"]
        })?;
        return oid(&r["oidRaw"]);
    }
    let r = unique(arr(&raw["relations"])?, |r| {
        r["identity"]["schema"] == identity["schema"] && r["identity"]["name"] == identity["name"]
    })?;
    oid(&r["identity"]["oidRaw"])
}
fn bind_relation(raw: &Value, identity: &Value) -> Result<(), InfraError> {
    require(
        oid(&identity["oidRaw"])? != 0 && oid(&identity["oidRaw"])? == relation_oid(raw, identity)?,
    )
}
fn index_named<'a>(raw: &'a Value, identity: &Value) -> Result<&'a Value, InfraError> {
    unique(arr(&raw["indexes"])?, |i| {
        i["identity"]["schema"] == identity["schema"] && i["identity"]["name"] == identity["name"]
    })
}
fn bind_index(raw: &Value, identity: &Value) -> Result<(), InfraError> {
    let i = index_named(raw, identity)?;
    require(oid(&identity["oidRaw"])? != 0 && identity == &i["identity"])
}
fn constraint_named<'a>(raw: &'a Value, name: &Value) -> Result<&'a Value, InfraError> {
    unique(arr(&raw["constraints"])?, |c| &c["name"] == name)
}
fn function_named<'a>(raw: &'a Value, identity: &Value) -> Result<&'a Value, InfraError> {
    unique(arr(&raw["functions"])?, |f| {
        f["identity"]["schema"] == identity["schema"]
            && f["identity"]["name"] == identity["name"]
            && f["identity"]["arguments"] == identity["arguments"]
    })
}

fn check_raw_bindings(raw: &Value, current52: bool) -> Result<(u32, u32), InfraError> {
    require(raw["format"] == "thread-history-writer-raw-v1")?;
    check_storage(raw)?;
    let owner = oid(&raw["ownerAnchorRaw"]["ownerOidRaw"])?;
    let base_oid = oid(&raw["ownerAnchorRaw"]["relationOidRaw"])?;
    let system = oid(&raw["systemOwnerRaw"]["ownerOidRaw"])?;
    require(
        owner != 0
            && base_oid != 0
            && raw["ownerAnchorRaw"]["ownerRoleCount"] == 1
            && system == 10
            && raw["systemOwnerRaw"]["ownerRoleCount"] == 1,
    )?;
    let legacy = arr(&raw["legacyOwnershipRaw"]["relations"])?;
    require(legacy.len() == if current52 { 10 } else { 9 })?;
    let mut legacy_relations = vec![
        ("public", "threads"),
        ("public", "runs"),
        ("public", "messages"),
        ("public", "run_events"),
        ("public", "tool_approvals"),
        ("public", "component_human_decisions"),
        ("public", "remote_agent_interrupts"),
        ("public", "channels"),
        ("openbot_internal", "schema_migrations"),
    ];
    if current52 {
        legacy_relations.push(("public", "memories"));
    }
    for (schema, name) in legacy_relations {
        let r = unique(legacy, |r| same_identity(r, schema, name))?;
        require(oid(&r["ownerOidRaw"])? == owner && oid(&r["oidRaw"])? != 0)?;
        if schema == "public" && name == "threads" {
            require(oid(&r["oidRaw"])? == base_oid)?;
        }
    }
    let ns = arr(&raw["legacyOwnershipRaw"]["namespaces"])?;
    require(ns.len() == 2)?;
    let internal = unique(ns, |n| n["schema"] == "openbot_internal")?;
    require(oid(&internal["oidRaw"])? != 0 && oid(&internal["ownerOidRaw"])? == owner)?;
    unique(ns, |n| n["schema"] == "public")?;
    let relations = arr(&raw["relations"])?;
    require(relations.len() == if current52 { 5 } else { 3 })?;
    let mut all_relation_oids = std::collections::BTreeSet::from([base_oid]);
    let types = arr(&raw["builtinAnchorsRaw"]["types"])?;
    require(types.len() == if current52 { 11 } else { 10 })?;
    let mut builtin_types = vec![
        ("text", 25),
        ("int2", 21),
        ("int4", 23),
        ("bool", 16),
        ("void", 2278),
        ("_text", 1009),
        ("int8", 20),
        ("timestamptz", 1184),
        ("jsonb", 3802),
        ("trigger", 2279),
    ];
    if current52 {
        builtin_types.push(("xid8", 5069));
    }
    for (name, id) in builtin_types {
        let t = unique(types, |t| same_identity(t, "pg_catalog", name))?;
        require(oid(&t["oidRaw"])? == id)?;
    }
    let collation = &raw["builtinAnchorsRaw"]["collation"];
    require(same_identity(collation, "pg_catalog", "C") && oid(&collation["oidRaw"])? != 0)?;
    let mut relation_columns = vec![(H, 14), (Q, 13), ("channel_history_sources", 13)];
    if current52 {
        relation_columns.extend([
            ("thread_history_clear_batches", 14),
            ("thread_history_clear_completions", 18),
        ]);
    }
    for (name, cols) in relation_columns {
        let r = unique(relations, |r| {
            same_identity(&r["identity"], "openbot_internal", name)
        })?;
        let id = oid(&r["identity"]["oidRaw"])?;
        require(id != 0 && all_relation_oids.insert(id) && oid(&r["ownerOidRaw"])? == owner)?;
        let columns = arr(&r["columns"])?;
        require(columns.len() == cols)?;
        for column in columns {
            let t = unique(types, |t| t["name"] == column["type"]["name"])?;
            require(
                column["type"]["schema"] == "pg_catalog"
                    && oid(&column["type"]["oidRaw"])? == oid(&t["oidRaw"])?
                    && column["type"]["name"] != "trigger",
            )?;
            if !column["collation"].is_null() {
                require(
                    same_identity(&column["collation"], "pg_catalog", "C")
                        && oid(&column["collation"]["oidRaw"])? == oid(&collation["oidRaw"])?,
                )?;
            }
        }
    }
    let classes = arr(&raw["builtinAnchorsRaw"]["operatorClasses"])?;
    require(classes.len() == if current52 { 4 } else { 3 })?;
    let mut operator_classes = vec!["text_ops", "int8_ops", "timestamptz_ops"];
    if current52 {
        operator_classes.push("xid8_ops");
    }
    for n in operator_classes {
        let c = unique(classes, |c| same_identity(c, "pg_catalog", n))?;
        require(oid(&c["oidRaw"])? != 0 && oid(&c["familyOidRaw"])? != 0)?;
    }
    let equality = arr(&raw["builtinAnchorsRaw"]["equalityOperators"])?;
    require(equality.len() == if current52 { 4 } else { 3 })?;
    let mut equality_types = vec!["text", "bigint", "timestamp with time zone"];
    if current52 {
        equality_types.push("xid8");
    }
    for t in equality_types {
        let op = unique(equality, |op| op["leftType"] == t && op["rightType"] == t)?;
        require(
            same_identity(op, "pg_catalog", "=")
                && oid(&op["oidRaw"])? != 0
                && op["resultType"] == "boolean"
                && op["function"]["schema"] == "pg_catalog"
                && oid(&op["function"]["oidRaw"])? != 0,
        )?;
    }
    let indexes = arr(&raw["indexes"])?;
    require(indexes.len() == if current52 { 12 } else { 8 })?;
    let mut index_oids = std::collections::BTreeSet::new();
    for i in indexes {
        let id = oid(&i["identity"]["oidRaw"])?;
        require(
            id != 0
                && index_oids.insert(id)
                && !all_relation_oids.contains(&id)
                && i["identity"]["schema"] == "openbot_internal"
                && oid(&i["ownerOidRaw"])? == owner,
        )?;
        bind_relation(raw, &i["relation"])?;
        for c in arr(&i["operatorClasses"])? {
            let anchor = unique(classes, |a| {
                a["schema"] == c["schema"] && a["name"] == c["name"]
            })?;
            require(
                oid(&c["oidRaw"])? == oid(&anchor["oidRaw"])?
                    && oid(&c["family"]["oidRaw"])? == oid(&anchor["familyOidRaw"])?
                    && c["family"]["schema"] == anchor["familySchema"]
                    && c["family"]["name"] == anchor["familyName"],
            )?;
        }
        for c in arr(&i["collations"])? {
            if !c["collation"].is_null() {
                require(
                    same_identity(&c["collation"], "pg_catalog", "C")
                        && oid(&c["collation"]["oidRaw"])? == oid(&collation["oidRaw"])?,
                )?;
            }
        }
    }
    let constraints = arr(&raw["constraints"])?;
    require(constraints.len() == if current52 { 60 } else { 39 })?;
    let mut constraint_oids = std::collections::BTreeSet::new();
    for c in constraints {
        let id = oid(&c["oidRaw"])?;
        require(id != 0 && constraint_oids.insert(id))?;
        bind_relation(raw, &c["relation"])?;
        if !c["supportingIndex"].is_null() {
            bind_index(raw, &c["supportingIndex"])?;
        }
        match text(&c["kind"])? {
            "p" | "u" => {
                require(
                    c["name"] == c["supportingIndex"]["name"]
                        && c["relation"] == index_named(raw, &c["supportingIndex"])?["relation"]
                        && c["reference"].is_null(),
                )?;
            }
            "c" | "t" => require(c["supportingIndex"].is_null() && c["reference"].is_null())?,
            "f" => {
                let reference = &c["reference"];
                bind_relation(raw, &reference["relation"])?;
                let ix = index_named(raw, &c["supportingIndex"])?;
                require(reference["relation"] == ix["relation"])?;
                let keys = arr(&reference["referencedKeys"])?;
                require(keys.len() == 1)?;
                let referenced = constraint_named(raw, &keys[0]["name"])?;
                require(
                    keys[0]["oidRaw"] == referenced["oidRaw"]
                        && keys[0]["indexOidRaw"] == c["supportingIndex"]["oidRaw"]
                        && referenced["supportingIndex"] == c["supportingIndex"]
                        && referenced["relation"] == reference["relation"],
                )?;
                for op in arr(&c["foreignEqualityOperators"])? {
                    let anchor = unique(equality, |a| {
                        a["leftType"] == op["leftType"] && a["rightType"] == op["rightType"]
                    })?;
                    let mut bound = op.clone();
                    let o = bound.as_object_mut().ok_or_else(|| corrupt("operator"))?;
                    o.remove("family");
                    o.remove("ordinal");
                    require(&bound == anchor)?;
                }
            }
            _ => return Err(corrupt("constraint")),
        }
    }
    let functions = arr(&raw["functions"])?;
    require(functions.len() == if current52 { 39 } else { 28 })?;
    let mut function_oids = std::collections::BTreeSet::new();
    for name in USER_FUNCTIONS {
        let f = unique(functions, |f| {
            same_identity(&f["identity"], "openbot_internal", name)
                && f["identity"]["arguments"] == ""
        })?;
        require(oid(&f["ownerOidRaw"])? == owner)?;
    }
    let mut ri_functions = vec![
        ("RI_FKey_check_ins", 1644),
        ("RI_FKey_check_upd", 1645),
        ("RI_FKey_noaction_del", 1654),
        ("RI_FKey_noaction_upd", 1655),
    ];
    if current52 {
        ri_functions.extend([
            ("RI_FKey_restrict_del", 1648),
            ("RI_FKey_restrict_upd", 1649),
        ]);
    }
    for (name, id) in ri_functions {
        let f = unique(functions, |f| {
            same_identity(&f["identity"], "pg_catalog", name) && f["identity"]["arguments"] == ""
        })?;
        require(oid(&f["identity"]["oidRaw"])? == id && oid(&f["ownerOidRaw"])? == system)?;
    }
    for f in functions {
        let id = oid(&f["identity"]["oidRaw"])?;
        if f["identity"]["schema"] == "openbot_internal" {
            require(oid(&f["ownerOidRaw"])? == owner)?;
        } else if f["identity"]["schema"] == "public" {
            require(
                current52
                    && f["identity"]["name"] == "guard_memory_provenance"
                    && oid(&f["ownerOidRaw"])? == owner,
            )?;
        }
        require(
            id != 0
                && function_oids.insert(id)
                && if f["returnType"]["schema"] == "pg_catalog" {
                    let t = unique(types, |t| t["name"] == f["returnType"]["name"])?;
                    oid(&f["returnType"]["oidRaw"])? == oid(&t["oidRaw"])?
                } else {
                    false
                },
        )?;
    }
    let triggers = arr(&raw["triggers"])?;
    require(triggers.len() == if current52 { 60 } else { 44 })?;
    let mut trigger_oids = std::collections::BTreeSet::new();
    let mut ri_signatures = Vec::new();
    for t in triggers {
        let id = oid(&t["oidRaw"])?;
        require(id != 0 && trigger_oids.insert(id))?;
        bind_relation(raw, &t["relation"])?;
        let f = function_named(raw, &t["function"])?;
        require(
            t["function"]["oidRaw"] == f["identity"]["oidRaw"]
                && t["function"]["kind"] == f["kind"],
        )?;
        let constraint_id = oid(&t["constraintOidRaw"])?;
        if constraint_id == 0 {
            require(
                t["constraint"].is_null()
                    && t["constraintIndex"].is_null()
                    && t["constraintRelation"].is_null()
                    && t["internal"] == false,
            )?;
        } else {
            let c = constraint_named(raw, &t["constraint"]["name"])?;
            require(
                t["constraint"]["oidRaw"] == c["oidRaw"]
                    && constraint_id == oid(&c["oidRaw"])?
                    && t["constraint"]["relation"] == c["relation"]
                    && t["constraint"]["kind"] == c["kind"],
            )?;
            if t["internal"] == true {
                require(c["kind"] == "f" && t["constraintIndex"] == c["supportingIndex"])?;
                bind_index(raw, &t["constraintIndex"])?;
                bind_relation(raw, &t["constraintRelation"])?;
                let child = t["relation"] == c["relation"];
                if child {
                    require(t["constraintRelation"] == c["reference"]["relation"])?;
                } else {
                    require(
                        t["relation"] == c["reference"]["relation"]
                            && t["constraintRelation"] == c["relation"],
                    )?;
                }
                let clear_fk = current52
                    && matches!(
                        text(&c["name"])?,
                        "thread_history_clear_batches_operation_fkey"
                            | "thread_history_clear_completions_operation_fkey"
                    );
                let deferred = !clear_fk;
                require(
                    t["function"]["schema"] == "pg_catalog"
                        && c["deferrable"] == deferred
                        && c["deferred"] == deferred
                        && t["deferrable"] == deferred
                        && t["deferred"] == deferred,
                )?;
                let prefix = if child {
                    "RI_ConstraintTrigger_c"
                } else {
                    "RI_ConstraintTrigger_a"
                };
                require(text(&t["name"])? == format!("{prefix}_{id}"))?;
                ri_signatures.push((
                    text(&c["name"])?.to_owned(),
                    child,
                    text(&t["function"]["name"])?.to_owned(),
                    t["type"].as_i64().ok_or_else(|| corrupt("trigger"))?,
                ));
            } else {
                require(
                    c["kind"] == "t"
                        && t["constraintIndex"].is_null()
                        && t["constraintRelation"].is_null()
                        && t["relation"] == c["relation"],
                )?;
            }
        }
    }
    let mut expected = Vec::new();
    for name in [
        "thread_history_clear_intents_head_base_fkey",
        "thread_history_heads_closed_intent_fkey",
    ] {
        for (child, function, kind) in [
            (true, "RI_FKey_check_ins", 5),
            (true, "RI_FKey_check_upd", 17),
            (false, "RI_FKey_noaction_del", 9),
            (false, "RI_FKey_noaction_upd", 17),
        ] {
            expected.push((name.to_owned(), child, function.to_owned(), kind));
        }
    }
    if current52 {
        for name in [
            "thread_history_clear_batches_operation_fkey",
            "thread_history_clear_completions_operation_fkey",
        ] {
            for (child, function, kind) in [
                (true, "RI_FKey_check_ins", 5),
                (true, "RI_FKey_check_upd", 17),
                (false, "RI_FKey_restrict_del", 9),
                (false, "RI_FKey_restrict_upd", 17),
            ] {
                expected.push((name.to_owned(), child, function.to_owned(), kind));
            }
        }
    }
    ri_signatures.sort();
    expected.sort();
    require(ri_signatures == expected)?;
    let schemas = arr(&raw["deparseContextRaw"]["currentSchemasWithImplicit"])?;
    require(
        schemas.first() == Some(&json!("pg_catalog"))
            && !schemas.iter().any(|s| s == "openbot_internal"),
    )?;
    check_source_types_and_attributes(
        raw,
        &raw["writerRaw"],
        owner,
        "channel_history_sources",
        13,
        &[13],
    )?;
    check_source_toast(
        raw,
        &raw["writerRaw"],
        owner,
        "channel_history_sources",
        13,
        6,
    )?;
    if current52 {
        let clear = arr(&raw["writerRaw"]["clearRelations"])?;
        require(clear.len() == 2)?;
        for (name, columns, checks, defaults) in [
            ("thread_history_clear_batches", 14, 3, &[3, 4][..]),
            ("thread_history_clear_completions", 18, 5, &[7][..]),
        ] {
            let physical = unique(clear, |r| r["name"] == name)?;
            require(
                obj(physical)?
                    .keys()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
                    == [
                        "name",
                        "sourceClass",
                        "sourceTypes",
                        "sourceAttributes",
                        "sourceToast",
                        "sourceDefaults",
                    ]
                    .into_iter()
                    .collect(),
            )?;
            check_source_types_and_attributes(raw, physical, owner, name, columns, defaults)?;
            check_source_toast(raw, physical, owner, name, columns, checks)?;
        }
    }
    check_source_dependencies(raw, owner, current52)?;
    // Remaining names, columns, ordering, bodies, policies, ACLs and flags must exactly match
    // the independent complete oracle. Raw OIDs above are bound before any are removed.
    Ok((owner, system))
}

const NEW_FUNCTIONS: [&str; 15] = [
    "thread_history_preview",
    "thread_history_lock_joint",
    "thread_history_lock_channel_ids",
    "thread_history_related_channel_ids",
    "thread_history_validate_channel_source",
    "guard_channel_history_source",
    "guard_thread_history_channel_projection",
    "thread_history_validate_channel_final",
    "require_thread_history_channel_final",
    "thread_history_terminal_payload",
    "guard_thread_history_body",
    "thread_history_validate_terminal_run",
    "require_thread_history_terminal_final",
    "guard_thread_history_canonical_reverse",
    "prevent_thread_history_writer_truncate",
];
const CLEAR_FUNCTIONS: [&str; 8] = [
    "guard_thread_history_clear_fact",
    "thread_history_clear_batch_active",
    "thread_history_clear_event_payload",
    "require_thread_history_clear_completion",
    "thread_history_clear_readers_quiescent",
    "thread_history_clear_bodies_erased",
    "require_thread_history_maintenance_source",
    "guard_thread_history_memory_body",
];
fn sole_function_acl(v: &Value, owner: u32, role: &str) -> Result<Value, InfraError> {
    let rows = acl_rows(v)?;
    require(
        rows.len() == 1
            && rows[0].grantor == owner
            && rows[0].grantee == owner
            && rows[0].privilege == "EXECUTE"
            && !rows[0].grantable,
    )?;
    Ok(json!([{"grantor":role,"grantee":role,"privilege":"EXECUTE","grantable":false}]))
}

fn function_acl(v: &Value, owner: u32, owner_ref: &str) -> Result<Value, InfraError> {
    let rows = acl_rows(v)?;
    require(
        rows.len() == 2
            && rows[0].grantee == 0
            && rows[1].grantee == owner
            && rows.iter().all(|r| {
                r.grantor == owner
                    && (r.grantee == 0 || r.grantee == owner)
                    && r.privilege == "EXECUTE"
                    && !r.grantable
            }),
    )?;
    Ok(Value::Array(rows.into_iter().map(|r| json!({"grantor":owner_ref,"grantee":if r.grantee == 0 {"PUBLIC"} else {owner_ref},"privilege":r.privilege,"grantable":r.grantable})).collect()))
}
fn portable_ri_identifier(t: &Value) -> Result<(String, String), InfraError> {
    require(t["internal"] == true && t["constraint"]["kind"] == "f")?;
    let original = text(&t["name"])?;
    let id = oid(&t["oidRaw"])?;
    let child = t["relation"] == t["constraint"]["relation"];
    let prefix = if child {
        "RI_ConstraintTrigger_c"
    } else {
        "RI_ConstraintTrigger_a"
    };
    require(id != 0 && original == format!("{prefix}_{id}"))?;
    let quoted = format!("\"{original}\"");
    let definition = text(&t["definition"])?;
    require(
        definition.starts_with(&format!("CREATE CONSTRAINT TRIGGER {quoted} "))
            && definition.matches(&quoted).count() == 1,
    )?;
    let portable = format!("{prefix}_<checked-trigger-oid>");
    Ok((
        portable.clone(),
        definition.replacen(&quoted, &format!("\"{portable}\""), 1),
    ))
}

fn normalize_owner_relative(
    mut raw: Value,
    current52: bool,
) -> Result<ThreadHistoryWriterSchemaFacts, InfraError> {
    let (owner, system) = check_raw_bindings(&raw, current52)?;
    let raw_facts = raw.clone();
    let mut table_acl_states = Vec::new();
    for r in raw["relations"]
        .as_array_mut()
        .ok_or_else(|| corrupt("relations"))?
    {
        let acl_is_null = r["aclIsNull"].as_bool().ok_or_else(|| corrupt("acl"))?;
        let acl = relative_acl(&r["acl"], owner)?;
        let state = json!({"aclIsNull":acl_is_null,"rawAcl":if acl_is_null {Value::Null} else {relative_acl(&r["rawAcl"],owner)?}});
        if acl_is_null {
            require(r["rawAcl"].is_null())?;
        }
        table_acl_states.push(json!({"relation":{"schema":r["identity"]["schema"],"name":r["identity"]["name"]},"state":state}));
        let o = r.as_object_mut().ok_or_else(|| corrupt("relation"))?;
        o.insert("acl".to_owned(), acl);
        o.insert("ownerIsOriginal".to_owned(), Value::Bool(true));
        o.remove("aclIsNull");
        o.remove("rawAcl");
    }
    for i in raw["indexes"]
        .as_array_mut()
        .ok_or_else(|| corrupt("indexes"))?
    {
        i.as_object_mut()
            .ok_or_else(|| corrupt("index"))?
            .insert("ownerIsOriginal".to_owned(), Value::Bool(true));
    }
    for f in raw["functions"]
        .as_array_mut()
        .ok_or_else(|| corrupt("functions"))?
    {
        let builtin = f["identity"]["schema"] == "pg_catalog";
        let (actual_owner, role) = if builtin {
            (system, "original_pg17_bootstrap_owner")
        } else {
            (owner, "original_threads_owner")
        };
        let name = text(&f["identity"]["name"])?;
        let sole = NEW_FUNCTIONS.contains(&name) || (current52 && CLEAR_FUNCTIONS.contains(&name));
        let acl = if sole {
            sole_function_acl(&f["acl"], actual_owner, role)?
        } else {
            function_acl(&f["acl"], actual_owner, role)?
        };
        let raw_acl = if f["rawAcl"].is_null() {
            require(!sole)?;
            Value::Null
        } else if sole {
            sole_function_acl(&f["rawAcl"], actual_owner, role)?
        } else {
            function_acl(&f["rawAcl"], actual_owner, role)?
        };
        let o = f.as_object_mut().ok_or_else(|| corrupt("function"))?;
        o.insert("ownerRef".to_owned(), json!(role));
        o.insert("acl".to_owned(), acl);
        o.insert("rawAcl".to_owned(), raw_acl);
    }
    for t in raw["triggers"]
        .as_array_mut()
        .ok_or_else(|| corrupt("triggers"))?
    {
        if t["internal"] == true {
            let (name, definition) = portable_ri_identifier(t)?;
            let o = t.as_object_mut().ok_or_else(|| corrupt("trigger"))?;
            o.insert("name".to_owned(), json!(name));
            o.insert("definition".to_owned(), json!(definition));
        }
    }
    let o = raw.as_object_mut().ok_or_else(|| corrupt("raw"))?;
    for k in [
        "ownerAnchorRaw",
        "systemOwnerRaw",
        "legacyOwnershipRaw",
        "deparseContextRaw",
        "storage",
        "builtinAnchorsRaw",
        "writerRaw",
    ] {
        o.remove(k);
    }
    o.insert(
        "format".to_owned(),
        json!("thread-history-writer-schema-v1"),
    );
    erase_checked_oid_fields(&mut raw);
    sort_foreign_operator_multisets(&mut raw)?;
    sort_top_level_multisets(&mut raw)?;
    Ok(canonical_value(
        &json!({"format":"thread-history-writer-observation-v1","schema":raw,"tableAclStates":table_acl_states,"rawFacts":raw_facts}),
    ))
}
fn hot_marker() -> Value {
    json!({"predicate":"pg17_hot_runtime_boolean_v1"})
}
fn count_hot_markers(v: &Value) -> usize {
    if v == &hot_marker() {
        return 1;
    }
    match v {
        Value::Object(o) => o.values().map(count_hot_markers).sum(),
        Value::Array(a) => a.iter().map(count_hot_markers).sum(),
        _ => 0,
    }
}
fn hot_comparison_clone(
    expected: &Value,
    actual: &Value,
    current52: bool,
) -> Result<Value, InfraError> {
    let count = if current52 { 12 } else { 8 };
    require(count_hot_markers(expected) == count && count_hot_markers(actual) == 0)?;
    let es = arr(&expected["indexes"])?;
    let actuals = arr(&actual["indexes"])?;
    require(es.len() == count && actuals.len() == count)?;
    let mut indexes = Vec::new();
    for e in es {
        require(e["checkXmin"] == hot_marker())?;
        let a = unique(actuals, |a| {
            a["identity"] == e["identity"] && a["relation"] == e["relation"]
        })?;
        require(a["checkXmin"].is_boolean())?;
        let mut matched = a.clone();
        matched
            .as_object_mut()
            .ok_or_else(|| corrupt("index"))?
            .insert("checkXmin".to_owned(), hot_marker());
        require(&matched == e)?;
        indexes.push(matched);
    }
    let mut out = actual.clone();
    out["indexes"] = Value::Array(indexes);
    sort_top_level_multisets(&mut out)?;
    Ok(out)
}
async fn observation_on<C: GenericClient + Sync>(
    client: &C,
    current52: bool,
) -> Result<ThreadHistoryWriterSchemaFacts, InfraError> {
    let registered = if current52 {
        REGISTERED_SCHEMA
    } else {
        LEGACY0051_SCHEMA
    };
    let expected: Value = serde_json::from_str(registered).map_err(|_| corrupt("oracle"))?;
    let contract = &expected["rawContract"];
    check_raw_contract_shape(contract, current52)?;
    let row = client
        .query_one(CAPTURE_SQL, &[contract, &current52])
        .await
        .map_err(|source| InfraError::query("只读观察 Thread 持久状态与来源ID schema", source))?;
    let payload: String = row.try_get("thread_history_raw").map_err(|source| {
        RowDecodeError::column(
            "(thread_history_writer_schema)",
            "thread_history_raw",
            source,
        )
    })?;
    let matches: bool = row
        .try_get("function_acl_matches_builtin")
        .map_err(|source| {
            RowDecodeError::column(
                "(thread_history_writer_schema)",
                "function_acl_matches_builtin",
                source,
            )
        })?;
    require(matches)?;
    let raw = serde_json::from_str(&payload).map_err(|_| corrupt("facts"))?;
    normalize_owner_relative(raw, current52)
}
fn compare_registered(
    observation: &ThreadHistoryWriterSchemaFacts,
    current52: bool,
) -> Result<(), InfraError> {
    let registered = if current52 {
        REGISTERED_SCHEMA
    } else {
        LEGACY0051_SCHEMA
    };
    let expected: Value = serde_json::from_str(registered).map_err(|_| corrupt("oracle"))?;
    let keys = obj(&expected)?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    require(
        keys == ["format", "schema", "allowedTableAclStates", "rawContract"]
            .into_iter()
            .collect()
            && expected["format"] == "thread-history-writer-oracle-v1"
            && expected["schema"]["format"] == "thread-history-writer-schema-v1"
            && observation["format"] == "thread-history-writer-observation-v1",
    )?;
    check_independent_raw_contract(
        &expected["rawContract"],
        &observation["rawFacts"],
        current52,
    )?;
    let states = arr(&expected["allowedTableAclStates"])?;
    require(states.len() == 2)?;
    let observed = arr(&observation["tableAclStates"])?;
    require(observed.len() == if current52 { 5 } else { 3 })?;
    let mut names = vec![H, Q, "channel_history_sources"];
    if current52 {
        names.extend([
            "thread_history_clear_batches",
            "thread_history_clear_completions",
        ]);
    }
    for name in names {
        let s = unique(observed, |s| {
            same_identity(&s["relation"], "openbot_internal", name)
        })?;
        require(
            states
                .iter()
                .filter(|allowed| *allowed == &s["state"])
                .count()
                == 1,
        )?;
    }
    require(
        expected["schema"]
            == hot_comparison_clone(&expected["schema"], &observation["schema"], current52)?,
    )
}
/// Require exact current53/41, the entire unchanged0052 graph and additive0053 catalog.
pub async fn verify(client: &Client) -> Result<(), InfraError> {
    let ledger = native::validate_known_prefix(client, native::NATIVE_0053_VERSION).await?;
    require(ledger.latest_version() == native::NATIVE_0053_VERSION)?;
    verify_schema(client).await?;
    super::restore_reconfirmation_schema::verify_schema(client).await
}
/// Schema-only helper after the caller proves its original exact native prefix.
pub(crate) async fn verify_schema(client: &Client) -> Result<(), InfraError> {
    compare_registered(&observation_on(client, true).await?, true)
}
/// Whole0052 on the original transaction; never checks out, repairs or closes it.
pub(crate) async fn verify_in_transaction(tx: &Transaction<'_>) -> Result<(), InfraError> {
    compare_registered(&observation_on(tx, true).await?, true)
}
/// Schema-only historical51 helper after an explicit exact pre-upgrade prefix proof.
pub(crate) async fn verify_schema_legacy0051(client: &Client) -> Result<(), InfraError> {
    compare_registered(&observation_on(client, false).await?, false)
}
/// Original whole0051 schema and oracle, only on an explicitly proven 39-item legacy prefix.
pub(crate) async fn verify_legacy0051_in_transaction(
    tx: &Transaction<'_>,
) -> Result<(), InfraError> {
    compare_registered(&observation_on(tx, false).await?, false)
}

// The independent fixture declares the finite builtin scope. Candidate observations
// are consumers of these original declarations and never create an expected row.
fn check_raw_contract_shape(v: &Value, current52: bool) -> Result<(), InfraError> {
    let keys = obj(v)?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    require(
        keys == [
            "format",
            "builtinFunctions",
            "builtinOperators",
            "builtinCasts",
            "aggregates",
            "sourceExpressions",
            "accessMethods",
            "toastOperatorClasses",
            "toastOperatorFamilies",
            "collations",
            "languageContract",
        ]
        .into_iter()
        .collect()
            && v["format"] == "thread-history-writer-raw-contract-v1",
    )?;
    require(
        !arr(&v["builtinFunctions"])?.is_empty()
            && arr(&v["sourceExpressions"])?.len() == if current52 { 25 } else { 7 },
    )?;
    for key in [
        "builtinFunctions",
        "builtinOperators",
        "aggregates",
        "accessMethods",
        "toastOperatorClasses",
        "toastOperatorFamilies",
        "collations",
    ] {
        let mut ids = std::collections::BTreeSet::new();
        for row in arr(&v[key])? {
            let id = row[if key == "aggregates" {
                "aggfnoid"
            } else {
                "oid"
            }]
            .as_u64()
            .ok_or_else(|| corrupt("builtin_oid"))?;
            require(id != 0 && id <= u32::MAX as u64 && ids.insert(id))?;
        }
    }
    let mut casts = std::collections::BTreeSet::new();
    for row in arr(&v["builtinCasts"])? {
        require(casts.insert((number(&row["castsource"])?, number(&row["casttarget"])?)))?;
    }
    let mut names = std::collections::BTreeSet::new();
    for expression in arr(&v["sourceExpressions"])? {
        require(names.insert(text(&expression["name"])?))?;
        arr(&expression["attnums"])?;
        text(&expression["deparsed"])?;
        obj(&expression["ast"])?;
    }
    check_language_contract_shape(&v["languageContract"])?;
    Ok(())
}
fn multiset(v: &Value) -> Result<Vec<Vec<u8>>, InfraError> {
    let mut out = arr(v)?
        .iter()
        .map(canonical_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    out.sort();
    Ok(out)
}
fn check_independent_raw_contract(
    expected: &Value,
    raw: &Value,
    current52: bool,
) -> Result<(), InfraError> {
    check_raw_contract_shape(expected, current52)?;
    let observed = &raw["writerRaw"];
    check_language_contract(&expected["languageContract"], raw)?;
    for key in [
        "builtinFunctions",
        "builtinOperators",
        "builtinCasts",
        "aggregates",
        "accessMethods",
        "toastOperatorClasses",
        "toastOperatorFamilies",
        "collations",
    ] {
        require(multiset(&expected[key])? == multiset(&observed[key])?)?;
    }
    let expressions = arr(&observed["sourceExpressions"])?;
    require(expressions.len() == if current52 { 25 } else { 7 })?;
    for expected in arr(&expected["sourceExpressions"])? {
        let actual = unique(expressions, |v| v["name"] == expected["name"])?;
        require(
            actual["attnums"] == expected["attnums"] && actual["deparsed"] == expected["deparsed"],
        )?;
        require(parse_pg_node_tree(text(&actual["nodeTree"])?)? == expected["ast"])?;
    }
    Ok(())
}

// Preserve the exact typed PostgreSQL node tree. Positional lists, null tokens,
// type/operator/function/collation OIDs and every Datum byte remain significant.
// Only the parser's source-location field is explicitly omitted after validating
// that it contains exactly one integer. This is never an arbitrary OID scrub.
struct PgNodeParser<'a> {
    bytes: &'a [u8],
    offset: usize,
    nodes: usize,
}
impl<'a> PgNodeParser<'a> {
    fn whitespace(&mut self) {
        while self.offset < self.bytes.len() && self.bytes[self.offset].is_ascii_whitespace() {
            self.offset += 1;
        }
    }
    fn peek(&mut self) -> Option<u8> {
        self.whitespace();
        self.bytes.get(self.offset).copied()
    }
    fn consume(&mut self, want: u8) -> Result<(), InfraError> {
        require(self.peek() == Some(want))?;
        self.offset += 1;
        Ok(())
    }
    fn atom(&mut self) -> Result<String, InfraError> {
        self.whitespace();
        let start = self.offset;
        while let Some(b) = self.bytes.get(self.offset) {
            if b.is_ascii_whitespace()
                || matches!(*b, b'{' | b'}' | b'(' | b')' | b'[' | b']' | b':')
            {
                break;
            }
            // These finite CHECK/default trees use numeric values, enum atoms and
            // the exact <> null token. Escaped/quoted atoms are not accepted by
            // this grammar and therefore cannot silently change a literal.
            require(!matches!(*b, b'\\' | b'"'))?;
            self.offset += 1;
        }
        require(self.offset > start)?;
        std::str::from_utf8(&self.bytes[start..self.offset])
            .map(str::to_owned)
            .map_err(|_| corrupt("node_atom"))
    }
    fn value(&mut self, depth: usize) -> Result<Value, InfraError> {
        require(depth <= 128 && self.nodes < 16_384)?;
        self.nodes += 1;
        match self.peek().ok_or_else(|| corrupt("node_eof"))? {
            b'{' => self.node(depth + 1),
            b'(' => self.list(depth + 1),
            b'[' => self.datum(depth + 1),
            _ => Ok(json!(self.atom()?)),
        }
    }
    fn node(&mut self, depth: usize) -> Result<Value, InfraError> {
        self.consume(b'{')?;
        let tag = self.atom()?;
        require(tag.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'))?;
        let mut fields = serde_json::Map::new();
        let mut seen = std::collections::BTreeSet::new();
        loop {
            if self.peek() == Some(b'}') {
                self.offset += 1;
                break;
            }
            self.consume(b':')?;
            let key = self.atom()?;
            require(key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))?;
            let mut values = Vec::new();
            while !matches!(self.peek(), Some(b':') | Some(b'}') | None) {
                values.push(self.value(depth + 1)?);
            }
            require(!values.is_empty() && seen.insert(key.clone()))?;
            if key == "location" {
                require(values.len() == 1 && text(&values[0])?.parse::<i32>().is_ok())?;
            } else {
                fields.insert(key, Value::Array(values));
            }
        }
        Ok(json!({"tag":tag,"fields":fields}))
    }
    fn list(&mut self, depth: usize) -> Result<Value, InfraError> {
        self.consume(b'(')?;
        let mut list = Vec::new();
        while self.peek() != Some(b')') {
            require(self.peek().is_some())?;
            list.push(self.value(depth + 1)?);
        }
        self.consume(b')')?;
        let list_type = if list
            .first()
            .and_then(Value::as_str)
            .is_some_and(|s| matches!(s, "i" | "o" | "b"))
        {
            Some(list.remove(0))
        } else {
            None
        };
        Ok(json!({"list":list,"listType":list_type}))
    }
    fn datum(&mut self, depth: usize) -> Result<Value, InfraError> {
        self.consume(b'[')?;
        let mut bytes = Vec::new();
        while self.peek() != Some(b']') {
            require(self.peek().is_some())?;
            let value = self.value(depth + 1)?;
            require(
                text(&value)?
                    .parse::<i16>()
                    .is_ok_and(|b| (-128..=255).contains(&b)),
            )?;
            bytes.push(value);
        }
        self.consume(b']')?;
        Ok(json!({"datum":bytes}))
    }
}
fn parse_pg_node_tree(v: &str) -> Result<Value, InfraError> {
    require(!v.is_empty() && v.len() <= 262_144)?;
    let mut parser = PgNodeParser {
        bytes: v.as_bytes(),
        offset: 0,
        nodes: 0,
    };
    let value = parser.value(0)?;
    require(parser.peek().is_none())?;
    obj(&value)?;
    Ok(value)
}

fn number(v: &Value) -> Result<u32, InfraError> {
    let n = v.as_u64().ok_or_else(|| corrupt("number"))?;
    u32::try_from(n).map_err(|_| corrupt("number"))
}
fn raw_builtin_function(raw: &Value, name: &str) -> Result<u32, InfraError> {
    let row = unique(arr(&raw["writerRaw"]["builtinFunctions"])?, |r| {
        r["proname"] == name
    })?;
    require(row["pronamespace"] == 11 && row["proowner"] == 10)?;
    number(&row["oid"])
}
fn check_source_types_and_attributes(
    raw: &Value,
    writer: &Value,
    owner: u32,
    name: &str,
    count: u32,
    defaults: &[u32],
) -> Result<(), InfraError> {
    let source = unique(arr(&raw["relations"])?, |r| {
        same_identity(&r["identity"], "openbot_internal", name)
    })?;
    let class = &writer["sourceClass"];
    let source_id = oid(&source["identity"]["oidRaw"])?;
    require(
        number(&class["oid"])? == source_id
            && number(&class["relowner"])? == owner
            && class["relkind"] == "r"
            && class["relpersistence"] == "p",
    )?;
    let internal = unique(arr(&raw["legacyOwnershipRaw"]["namespaces"])?, |n| {
        n["schema"] == "openbot_internal"
    })?;
    require(number(&class["relnamespace"])? == oid(&internal["oidRaw"])?)?;
    let types = arr(&writer["sourceTypes"])?;
    require(types.len() == 2)?;
    let composite = unique(types, |t| t["typname"] == name)?;
    let array_name = format!("_{name}");
    let array = unique(types, |t| t["typname"] == array_name)?;
    let composite_id = number(&composite["oid"])?;
    let array_id = number(&array["oid"])?;
    require(
        composite_id != 0
            && array_id != 0
            && composite_id != array_id
            && number(&class["reltype"])? == composite_id,
    )?;
    for t in [composite, array] {
        complete_raw_type_keys(t)?;
        require(
            number(&t["typowner"])? == owner
                && number(&t["typnamespace"])? == oid(&internal["oidRaw"])?,
        )?;
        for (key, want) in [
            ("typlen", json!(-1)),
            ("typbyval", json!(false)),
            ("typispreferred", json!(false)),
            ("typisdefined", json!(true)),
            ("typdelim", json!(",")),
            ("typmodin", json!(0)),
            ("typmodout", json!(0)),
            ("typalign", json!("d")),
            ("typstorage", json!("x")),
            ("typnotnull", json!(false)),
            ("typbasetype", json!(0)),
            ("typtypmod", json!(-1)),
            ("typndims", json!(0)),
            ("typcollation", json!(0)),
            ("typdefaultbin", Value::Null),
            ("typdefault", Value::Null),
            ("typacl", Value::Null),
        ] {
            require(t.get(key) == Some(&want))?;
        }
    }
    require(
        composite["typtype"] == "c"
            && composite["typcategory"] == "C"
            && number(&composite["typrelid"])? == source_id
            && composite["typelem"] == 0
            && number(&composite["typarray"])? == array_id
            && composite["typsubscript"] == 0
            && composite["typanalyze"] == 0,
    )?;
    require(
        array["typtype"] == "b"
            && array["typcategory"] == "A"
            && array["typrelid"] == 0
            && number(&array["typelem"])? == composite_id
            && array["typarray"] == 0,
    )?;
    for (t, names) in [
        (
            composite,
            ["record_in", "record_out", "record_recv", "record_send"],
        ),
        (array, ["array_in", "array_out", "array_recv", "array_send"]),
    ] {
        for (key, name) in ["typinput", "typoutput", "typreceive", "typsend"]
            .into_iter()
            .zip(names)
        {
            require(number(&t[key])? == raw_builtin_function(raw, name)?)?;
        }
    }
    require(
        number(&array["typsubscript"])? == raw_builtin_function(raw, "array_subscript_handler")?
            && number(&array["typanalyze"])? == raw_builtin_function(raw, "array_typanalyze")?,
    )?;
    // Only the original source composite is a declared function argument.
    // The new clearing tables do not widen that legacy function-type contract.
    for f in arr(&raw["functions"])?
        .iter()
        .filter(|_| name == "channel_history_sources")
    {
        for field in ["inputTypes", "allArgumentTypes", "transformTypes"] {
            for t in arr(&f[field])? {
                let actual = oid(&t["oidRaw"])?;
                if same_identity(t, "openbot_internal", "channel_history_sources") {
                    require(actual == composite_id)?;
                } else {
                    let anchor = unique(arr(&raw["builtinAnchorsRaw"]["types"])?, |b| {
                        b["schema"] == t["schema"] && b["name"] == t["name"]
                    })?;
                    require(actual == oid(&anchor["oidRaw"])?)?;
                }
            }
        }
    }
    let attributes = arr(&writer["sourceAttributes"])?;
    let columns = arr(&source["columns"])?;
    require(attributes.len() == count as usize && columns.len() == count as usize)?;
    for column in columns {
        let ordinal = number(&column["ordinal"])?;
        let a = unique(attributes, |a| a["attnum"] == column["ordinal"])?;
        complete_raw_attribute_keys(a)?;
        require(
            number(&a["attrelid"])? == source_id
                && a["attname"] == column["name"]
                && number(&a["atttypid"])? == oid(&column["type"]["oidRaw"])?,
        )?;
        for (key, want) in [
            ("attstattarget", Value::Null),
            ("attcacheoff", json!(-1)),
            ("attndims", json!(0)),
            ("atttypmod", json!(-1)),
            ("attcompression", json!("")),
            ("atthasmissing", json!(false)),
            ("attidentity", json!("")),
            ("attgenerated", json!("")),
            ("attisdropped", json!(false)),
            ("attislocal", json!(true)),
            ("attinhcount", json!(0)),
            ("attacl", Value::Null),
            ("attoptions", Value::Null),
            ("attfdwoptions", Value::Null),
            ("attmissingval", Value::Null),
        ] {
            require(a.get(key) == Some(&want))?;
        }
        require(
            a["attnotnull"] == column["notNull"]
                && a["atthasdef"] == json!(defaults.contains(&ordinal)),
        )?;
        let (length, byval, align, storage) = match text(&column["type"]["name"])? {
            "text" => (-1, false, "i", "x"),
            "int2" => (2, true, "s", "p"),
            "int4" => (4, true, "i", "p"),
            "int8" | "xid8" if name != "channel_history_sources" => (8, true, "d", "p"),
            "timestamptz" => (8, true, "d", "p"),
            _ => return Err(corrupt("source_column")),
        };
        require(
            a["attlen"] == length
                && a["attbyval"] == byval
                && a["attalign"] == align
                && a["attstorage"] == storage,
        )?;
        let collation = if column["collation"].is_null() {
            0
        } else {
            oid(&column["collation"]["oidRaw"])?
        };
        require(number(&a["attcollation"])? == collation)?;
    }
    Ok(())
}

fn complete_raw_type_keys(v: &Value) -> Result<(), InfraError> {
    let keys = obj(v)?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    require(
        keys == [
            "oid",
            "typname",
            "typnamespace",
            "typowner",
            "typlen",
            "typbyval",
            "typtype",
            "typcategory",
            "typispreferred",
            "typisdefined",
            "typdelim",
            "typrelid",
            "typsubscript",
            "typelem",
            "typarray",
            "typinput",
            "typoutput",
            "typreceive",
            "typsend",
            "typmodin",
            "typmodout",
            "typanalyze",
            "typalign",
            "typstorage",
            "typnotnull",
            "typbasetype",
            "typtypmod",
            "typndims",
            "typcollation",
            "typdefaultbin",
            "typdefault",
            "typacl",
        ]
        .into_iter()
        .collect(),
    )
}
fn complete_raw_attribute_keys(v: &Value) -> Result<(), InfraError> {
    let keys = obj(v)?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    require(
        keys == [
            "attrelid",
            "attname",
            "atttypid",
            "attstattarget",
            "attlen",
            "attnum",
            "attndims",
            "attcacheoff",
            "atttypmod",
            "attbyval",
            "attalign",
            "attstorage",
            "attcompression",
            "attnotnull",
            "atthasdef",
            "atthasmissing",
            "attidentity",
            "attgenerated",
            "attisdropped",
            "attislocal",
            "attinhcount",
            "attcollation",
            "attacl",
            "attoptions",
            "attfdwoptions",
            "attmissingval",
        ]
        .into_iter()
        .collect(),
    )
}
// This private catalog checker keeps each independent raw fact explicit.
#[allow(clippy::too_many_arguments)]
fn check_class_storage(
    v: &Value,
    name: &str,
    kind: &str,
    namespace: u32,
    owner: u32,
    ty: u32,
    toast: u32,
    natts: u32,
    checks: u32,
    has_triggers: bool,
    tablespace: u32,
) -> Result<(), InfraError> {
    let keys = obj(v)?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    require(
        keys == [
            "oid",
            "relname",
            "relnamespace",
            "reltype",
            "reloftype",
            "relowner",
            "relam",
            "relfilenode",
            "reltablespace",
            "relpages",
            "reltuples",
            "relallvisible",
            "reltoastrelid",
            "relhasindex",
            "relisshared",
            "relpersistence",
            "relkind",
            "relnatts",
            "relchecks",
            "relhasrules",
            "relhastriggers",
            "relhassubclass",
            "relrowsecurity",
            "relforcerowsecurity",
            "relispopulated",
            "relreplident",
            "relispartition",
            "relrewrite",
            "relfrozenxid",
            "relminmxid",
            "relacl",
            "reloptions",
            "relpartbound",
        ]
        .into_iter()
        .collect(),
    )?;
    require(
        v["relname"] == name
            && v["relkind"] == kind
            && number(&v["relnamespace"])? == namespace
            && number(&v["relowner"])? == owner
            && number(&v["reltype"])? == ty
            && number(&v["reltoastrelid"])? == toast
            && number(&v["relnatts"])? == natts
            && number(&v["relchecks"])? == checks
            && number(&v["reltablespace"])? == tablespace,
    )?;
    for (key, want) in [
        ("reloftype", json!(0)),
        ("relam", json!(if kind == "i" { 403 } else { 2 })),
        ("relisshared", json!(false)),
        ("relpersistence", json!("p")),
        ("relhasindex", json!(kind != "i")),
        ("relhasrules", json!(false)),
        ("relhastriggers", json!(has_triggers)),
        ("relhassubclass", json!(false)),
        ("relrowsecurity", json!(false)),
        ("relforcerowsecurity", json!(false)),
        ("relispopulated", json!(true)),
        ("relreplident", json!(if kind == "r" { "d" } else { "n" })),
        ("relispartition", json!(false)),
        ("relrewrite", json!(0)),
        ("reloptions", Value::Null),
        ("relpartbound", Value::Null),
    ] {
        require(v.get(key) == Some(&want))?;
    }
    // These seven storage facts legitimately vary under writes, ANALYZE and
    // VACUUM. Validate their native domains instead of inventing frozen values.
    require(number(&v["oid"])? != 0 && number(&v["relfilenode"])? != 0)?;
    let pages = v["relpages"].as_i64().ok_or_else(|| corrupt("relpages"))?;
    let visible = v["relallvisible"]
        .as_i64()
        .ok_or_else(|| corrupt("relallvisible"))?;
    let tuples = v["reltuples"]
        .as_f64()
        .ok_or_else(|| corrupt("reltuples"))?;
    require(
        pages >= 0 && visible >= 0 && visible <= pages && tuples.is_finite() && tuples >= -1.0,
    )?;
    let frozen = text(&v["relfrozenxid"])?
        .parse::<u32>()
        .map_err(|_| corrupt("frozen"))?;
    let minmx = text(&v["relminmxid"])?
        .parse::<u32>()
        .map_err(|_| corrupt("minmx"))?;
    require(if kind == "i" {
        frozen == 0 && minmx == 0
    } else {
        frozen != 0 && minmx != 0
    })?;
    if kind != "r" {
        require(v["relacl"].is_null())?;
    }
    Ok(())
}
fn check_source_toast(
    raw: &Value,
    writer: &Value,
    owner: u32,
    name: &str,
    count: u32,
    checks: u32,
) -> Result<(), InfraError> {
    let source = &writer["sourceClass"];
    let source_id = number(&source["oid"])?;
    let toast_id = number(&source["reltoastrelid"])?;
    let composite = unique(arr(&writer["sourceTypes"])?, |t| t["typname"] == name)?;
    let namespace = number(&source["relnamespace"])?;
    let tablespace = number(&source["reltablespace"])?;
    check_class_storage(
        source,
        name,
        "r",
        namespace,
        owner,
        number(&composite["oid"])?,
        toast_id,
        count,
        checks,
        true,
        tablespace,
    )?;
    require(toast_id != 0 && toast_id != source_id)?;
    let toast = &writer["sourceToast"]["relation"];
    require(number(&toast["oid"])? == toast_id)?;
    let toast_name = format!("pg_toast_{source_id}");
    check_class_storage(
        toast,
        &toast_name,
        "t",
        99,
        owner,
        0,
        0,
        3,
        0,
        false,
        tablespace,
    )?;
    let attributes = arr(&writer["sourceToast"]["attributes"])?;
    require(attributes.len() == 3)?;
    for (ordinal, name, ty, length, byval, align) in [
        (1, "chunk_id", 26, 4, true, "i"),
        (2, "chunk_seq", 23, 4, true, "i"),
        (3, "chunk_data", 17, -1, false, "i"),
    ] {
        let a = unique(attributes, |a| a["attnum"] == ordinal)?;
        complete_raw_attribute_keys(a)?;
        require(
            number(&a["attrelid"])? == toast_id
                && a["attname"] == name
                && a["atttypid"] == ty
                && a["attlen"] == length
                && a["attbyval"] == byval
                && a["attalign"] == align,
        )?;
        for (key, want) in [
            ("attstattarget", Value::Null),
            ("attcacheoff", json!(-1)),
            ("attndims", json!(0)),
            ("atttypmod", json!(-1)),
            ("attstorage", json!("p")),
            ("attcompression", json!("")),
            ("attnotnull", json!(false)),
            ("atthasdef", json!(false)),
            ("atthasmissing", json!(false)),
            ("attidentity", json!("")),
            ("attgenerated", json!("")),
            ("attisdropped", json!(false)),
            ("attislocal", json!(true)),
            ("attinhcount", json!(0)),
            ("attcollation", json!(0)),
            ("attacl", Value::Null),
            ("attoptions", Value::Null),
            ("attfdwoptions", Value::Null),
            ("attmissingval", Value::Null),
        ] {
            require(a.get(key) == Some(&want))?;
        }
    }
    let indexes = arr(&writer["sourceToast"]["indexes"])?;
    require(indexes.len() == 1)?;
    let index = &indexes[0]["index"];
    let index_class = &indexes[0]["class"];
    let index_id = number(&index["indexrelid"])?;
    require(
        index_id != 0
            && number(&index_class["oid"])? == index_id
            && number(&index["indrelid"])? == toast_id,
    )?;
    check_class_storage(
        index_class,
        &format!("{toast_name}_index"),
        "i",
        99,
        owner,
        0,
        0,
        2,
        0,
        false,
        tablespace,
    )?;
    let keys = obj(index)?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    require(
        keys == [
            "indexrelid",
            "indrelid",
            "indnatts",
            "indnkeyatts",
            "indisunique",
            "indnullsnotdistinct",
            "indisprimary",
            "indisexclusion",
            "indimmediate",
            "indisclustered",
            "indisvalid",
            "indcheckxmin",
            "indisready",
            "indislive",
            "indisreplident",
            "indkey",
            "indcollation",
            "indclass",
            "indoption",
            "indexprs",
            "indpred",
        ]
        .into_iter()
        .collect(),
    )?;
    for (key, want) in [
        ("indnatts", json!(2)),
        ("indnkeyatts", json!(2)),
        ("indisunique", json!(true)),
        ("indnullsnotdistinct", json!(false)),
        ("indisprimary", json!(true)),
        ("indisexclusion", json!(false)),
        ("indimmediate", json!(true)),
        ("indisclustered", json!(false)),
        ("indisvalid", json!(true)),
        ("indisready", json!(true)),
        ("indislive", json!(true)),
        ("indisreplident", json!(false)),
        ("indkey", json!([1, 2])),
        ("indcollation", json!([0, 0])),
        ("indclass", json!([1981, 1978])),
        ("indoption", json!([0, 0])),
        ("indexprs", Value::Null),
        ("indpred", Value::Null),
    ] {
        require(index.get(key) == Some(&want))?;
    }
    require(index["indcheckxmin"].is_boolean())?;
    let classes = arr(&writer["sourceToast"]["operatorClasses"])?;
    require(classes.len() == 2)?;
    for row in classes {
        for (field, key) in [
            ("class", "toastOperatorClasses"),
            ("family", "toastOperatorFamilies"),
            ("method", "accessMethods"),
        ] {
            let catalog = unique(arr(&raw["writerRaw"][key])?, |c| {
                c["oid"] == row[field]["oid"]
            })?;
            require(&row[field] == catalog)?;
        }
    }
    Ok(())
}

fn dependence(
    class: u32,
    id: u32,
    sub: u32,
    ref_class: u32,
    ref_id: u32,
    ref_sub: u32,
    kind: &str,
) -> Value {
    json!({"classid":class,"objid":id,"objsubid":sub,"refclassid":ref_class,"refobjid":ref_id,"refobjsubid":ref_sub,"deptype":kind})
}
fn check_source_dependencies(raw: &Value, owner: u32, current52: bool) -> Result<(), InfraError> {
    // Relational prior: dependent row/array types inherit source ownership;
    // toast and indexes do not invent independent owner/namespace dependencies.
    const CLASS: u32 = 1259;
    const TYPE: u32 = 1247;
    const PROC: u32 = 1255;
    const TRIGGER: u32 = 2620;
    const CONSTRAINT: u32 = 2606;
    const ATTRDEF: u32 = 2604;
    const NAMESPACE: u32 = 2615;
    const LANGUAGE: u32 = 2612;
    let writer = &raw["writerRaw"];
    let source = &writer["sourceClass"];
    let source_id = number(&source["oid"])?;
    let namespace = number(&source["relnamespace"])?;
    let source_types = arr(&writer["sourceTypes"])?;
    let composite = unique(source_types, |t| t["typname"] == "channel_history_sources")?;
    let array = unique(source_types, |t| t["typname"] == "_channel_history_sources")?;
    let composite_id = number(&composite["oid"])?;
    let array_id = number(&array["oid"])?;
    let toast = number(&source["reltoastrelid"])?;
    let toast_index = number(&arr(&writer["sourceToast"]["indexes"])?[0]["index"]["indexrelid"])?;
    let plpgsql = &writer["plpgsql"];
    let language = number(&plpgsql["oid"])?;
    require(
        language != 0
            && plpgsql["lanname"] == "plpgsql"
            && plpgsql["lanispl"] == true
            && plpgsql["lanpltrusted"] == true
            && plpgsql["lanowner"] == 10,
    )?;
    let mut expected = vec![
        dependence(CLASS, source_id, 0, NAMESPACE, namespace, 0, "n"),
        dependence(TYPE, composite_id, 0, CLASS, source_id, 0, "i"),
        dependence(TYPE, array_id, 0, TYPE, composite_id, 0, "i"),
        dependence(CLASS, toast, 0, CLASS, source_id, 0, "i"),
        dependence(CLASS, toast_index, 0, CLASS, toast, 1, "a"),
        dependence(CLASS, toast_index, 0, CLASS, toast, 2, "a"),
    ];
    let mut physical = vec![(writer, source_id, &[13][..])];
    let mut physical_ids = std::collections::BTreeSet::from([source_id]);
    if current52 {
        for (name, defaults) in [
            ("thread_history_clear_batches", &[3, 4][..]),
            ("thread_history_clear_completions", &[7][..]),
        ] {
            let row = unique(arr(&writer["clearRelations"])?, |r| r["name"] == name)?;
            let class = &row["sourceClass"];
            let relation = number(&class["oid"])?;
            require(physical_ids.insert(relation))?;
            let types = arr(&row["sourceTypes"])?;
            let composite = unique(types, |t| t["typname"] == name)?;
            let array_name = format!("_{name}");
            let array = unique(types, |t| t["typname"] == array_name)?;
            let toast = number(&class["reltoastrelid"])?;
            let toast_index =
                number(&arr(&row["sourceToast"]["indexes"])?[0]["index"]["indexrelid"])?;
            expected.extend([
                dependence(CLASS, relation, 0, NAMESPACE, namespace, 0, "n"),
                dependence(TYPE, number(&composite["oid"])?, 0, CLASS, relation, 0, "i"),
                dependence(
                    TYPE,
                    number(&array["oid"])?,
                    0,
                    TYPE,
                    number(&composite["oid"])?,
                    0,
                    "i",
                ),
                dependence(CLASS, toast, 0, CLASS, relation, 0, "i"),
                dependence(CLASS, toast_index, 0, CLASS, toast, 1, "a"),
                dependence(CLASS, toast_index, 0, CLASS, toast, 2, "a"),
            ]);
            physical.push((row, relation, defaults));
        }
    }
    let functions = arr(&raw["functions"])?;
    let languages = arr(&writer["newFunctionLanguages"])?;
    require(languages.len() == if current52 { 23 } else { 15 })?;
    let mut new_function_ids = std::collections::BTreeSet::new();
    let extra_functions = if current52 { &CLEAR_FUNCTIONS[..] } else { &[] };
    for name in NEW_FUNCTIONS
        .into_iter()
        .chain(extra_functions.iter().copied())
    {
        let f = unique(functions, |f| {
            same_identity(&f["identity"], "openbot_internal", name)
        })?;
        let id = oid(&f["identity"]["oidRaw"])?;
        require(new_function_ids.insert(id))?;
        let l = unique(languages, |l| l["oid"] == id)?;
        let builtin_sql = current52 && name == "thread_history_clear_batch_active";
        // PG17's SQLlanguageId is the pinned builtin 14. Only this exact 0052
        // helper uses it; every legacy and other clearing function remains plpgsql.
        require(number(&l["prolang"])? == if builtin_sql { 14 } else { language })?;
        require(f["language"] == if builtin_sql { "sql" } else { "plpgsql" })?;
        expected.push(dependence(PROC, id, 0, NAMESPACE, namespace, 0, "n"));
        // recordMultipleDependencies omits a pinned referenced builtin. An
        // unexpected SQL-language dependency must still fail the exact multiset.
        if !builtin_sql {
            expected.push(dependence(PROC, id, 0, LANGUAGE, language, 0, "n"));
        }
        if name == "thread_history_validate_channel_source" {
            expected.push(dependence(PROC, id, 0, TYPE, composite_id, 0, "n"));
        }
    }
    let triggers = arr(&raw["triggers"])?;
    let mut new_trigger_ids = std::collections::BTreeSet::new();
    let mut new_constraint_ids = std::collections::BTreeSet::new();
    for t in triggers {
        let f = oid(&t["function"]["oidRaw"])?;
        if !new_function_ids.contains(&f) {
            continue;
        }
        let id = oid(&t["oidRaw"])?;
        require(new_trigger_ids.insert(id))?;
        let relation = oid(&t["relation"]["oidRaw"])?;
        expected.push(dependence(TRIGGER, id, 0, PROC, f, 0, "n"));
        expected.push(dependence(TRIGGER, id, 0, CLASS, relation, 0, "a"));
        let mut columns = std::collections::BTreeSet::new();
        for column in text(&t["columns"])?.split_whitespace() {
            let ordinal = column
                .parse::<u32>()
                .map_err(|_| corrupt("trigger_column"))?;
            require(ordinal > 0 && columns.insert(ordinal))?;
            expected.push(dependence(TRIGGER, id, 0, CLASS, relation, ordinal, "n"));
        }
        let c = oid(&t["constraintOidRaw"])?;
        if c != 0 {
            require(new_constraint_ids.insert(c))?;
            expected.push(dependence(CONSTRAINT, c, 0, TRIGGER, id, 0, "i"));
        }
    }
    let expected_triggers = if current52 { 32 } else { 25 };
    let expected_constraints = if current52 { 8 } else { 7 };
    require(
        new_trigger_ids.len() == expected_triggers
            && new_constraint_ids.len() == expected_constraints,
    )?;
    let constraints = arr(&raw["constraints"])?;
    let mut clear_fk_ids = std::collections::BTreeSet::new();
    for c in constraints {
        let id = oid(&c["oidRaw"])?;
        let relation = oid(&c["relation"]["oidRaw"])?;
        if !new_constraint_ids.contains(&id) && !physical_ids.contains(&relation) {
            continue;
        }
        let columns = arr(&c["columns"])?;
        if columns.is_empty() {
            expected.push(dependence(CONSTRAINT, id, 0, CLASS, relation, 0, "a"));
        } else {
            for column in columns {
                expected.push(dependence(
                    CONSTRAINT,
                    id,
                    0,
                    CLASS,
                    relation,
                    number(&column["attributeNumber"])?,
                    "a",
                ));
                if c["kind"] == "c" {
                    expected.push(dependence(
                        CONSTRAINT,
                        id,
                        0,
                        CLASS,
                        relation,
                        number(&column["attributeNumber"])?,
                        "n",
                    ));
                }
            }
        }
        if c["kind"] == "p" || c["kind"] == "u" {
            let index = oid(&c["supportingIndex"]["oidRaw"])?;
            expected.push(dependence(CLASS, index, 0, CONSTRAINT, id, 0, "i"));
        }
        if c["kind"] == "f" {
            require(
                current52
                    && matches!(
                        text(&c["name"])?,
                        "thread_history_clear_batches_operation_fkey"
                            | "thread_history_clear_completions_operation_fkey"
                    )
                    && clear_fk_ids.insert(id),
            )?;
            let reference = &c["reference"];
            let target = oid(&reference["relation"]["oidRaw"])?;
            require(same_identity(&reference["relation"], "openbot_internal", Q))?;
            for column in arr(&reference["columns"])? {
                expected.push(dependence(
                    CONSTRAINT,
                    id,
                    0,
                    CLASS,
                    target,
                    number(&column["attributeNumber"])?,
                    "n",
                ));
            }
            expected.push(dependence(
                CONSTRAINT,
                id,
                0,
                CLASS,
                oid(&c["supportingIndex"]["oidRaw"])?,
                0,
                "n",
            ));
        }
    }
    require(clear_fk_ids.len() == if current52 { 2 } else { 0 })?;
    let mut clear_ri_ids = std::collections::BTreeSet::new();
    for t in triggers {
        let constraint = oid(&t["constraintOidRaw"])?;
        if clear_fk_ids.contains(&constraint) {
            let id = oid(&t["oidRaw"])?;
            require(t["internal"] == true && clear_ri_ids.insert(id))?;
            // These eight internal RI triggers depend on their FK constraint.
            // Their pinned pg_catalog functions have no dependency row.
            expected.push(dependence(TRIGGER, id, 0, CONSTRAINT, constraint, 0, "i"));
        }
    }
    require(clear_ri_ids.len() == if current52 { 8 } else { 0 })?;
    for (row, relation, ordinals) in physical {
        let defaults = arr(&row["sourceDefaults"])?;
        require(defaults.len() == ordinals.len())?;
        for ordinal in ordinals {
            let default = unique(defaults, |d| d["adnum"] == *ordinal)?;
            require(number(&default["adrelid"])? == relation)?;
            expected.push(dependence(
                ATTRDEF,
                number(&default["oid"])?,
                0,
                CLASS,
                relation,
                *ordinal,
                "a",
            ));
        }
    }
    // Builtin types/functions/operators/C/default collations/heap/btree/opclasses
    // are the independently pinned PG17 catalog objects. PostgreSQL omits their
    // dependency rows; their complete catalog attributes are checked separately.
    require(multiset(&Value::Array(expected))? == multiset(&writer["dependencies"])?)?;
    let mut shared = Vec::new();
    if owner != 10 {
        let database = number(&writer["databaseOid"])?;
        require(database != 0)?;
        for (class, id) in physical_ids
            .into_iter()
            .map(|id| (CLASS, id))
            .chain(new_function_ids.into_iter().map(|id| (PROC, id)))
        {
            shared.push(json!({"dbid":database,"classid":class,"objid":id,"objsubid":0,"refclassid":1260,"refobjid":owner,"deptype":"o"}));
        }
    }
    require(multiset(&Value::Array(shared))? == multiset(&writer["sharedDependencies"])?)
}

// Four extension identities are dynamic. Bind their actual qualified names and
// signatures first, then substitute only these designated independent tags.
// Every remaining catalog field, builtin OID and raw/effective ACL is exact.
fn check_language_contract_shape(v: &Value) -> Result<(), InfraError> {
    let keys = obj(v)?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    require(
        keys == [
            "format",
            "language",
            "functions",
            "languageEffectiveAcl",
            "functionEffectiveAcls",
        ]
        .into_iter()
        .collect()
            && v["format"] == "pg17-plpgsql-extension-execution-contract-v1",
    )?;
    let keys = obj(&v["language"])?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    require(
        keys == [
            "oid",
            "lanname",
            "lanowner",
            "lanispl",
            "lanpltrusted",
            "lanplcallfoid",
            "laninline",
            "lanvalidator",
            "lanacl",
        ]
        .into_iter()
        .collect(),
    )?;
    require(arr(&v["functions"])?.len() == 3 && arr(&v["functionEffectiveAcls"])?.len() == 3)?;
    arr(&v["languageEffectiveAcl"])?;
    Ok(())
}
fn check_language_contract(expected: &Value, raw: &Value) -> Result<(), InfraError> {
    check_language_contract_shape(expected)?;
    let actual = &raw["writerRaw"]["languageContract"];
    check_language_contract_shape(actual)?;
    require(actual["language"] == raw["writerRaw"]["plpgsql"])?;
    let actual_language = &actual["language"];
    let language_id = number(&actual_language["oid"])?;
    let mut dynamic_ids = std::collections::BTreeSet::new();
    require(language_id != 0 && dynamic_ids.insert(language_id))?;
    let mut expected_language = expected["language"].clone();
    require(expected_language["oid"] == "<bound_plpgsql_language_oid>")?;
    expected_language["oid"] = json!(language_id);
    let expected_functions = arr(&expected["functions"])?;
    let actual_functions = arr(&actual["functions"])?;
    let mut bound_functions = Vec::new();
    for (name, args, field, tag) in [
        (
            "plpgsql_call_handler",
            json!([]),
            "lanplcallfoid",
            "<bound_plpgsql_call_handler_oid>",
        ),
        (
            "plpgsql_inline_handler",
            json!([2281]),
            "laninline",
            "<bound_plpgsql_inline_handler_oid>",
        ),
        (
            "plpgsql_validator",
            json!([26]),
            "lanvalidator",
            "<bound_plpgsql_validator_oid>",
        ),
    ] {
        let f = unique(actual_functions, |row| row["proname"] == name)?;
        let original = unique(expected_functions, |row| row["proname"] == name)?;
        require(f["pronamespace"] == 11 && f["proargtypes"] == args)?;
        let id = number(&f["oid"])?;
        require(
            id != 0
                && dynamic_ids.insert(id)
                && number(&actual_language[field])? == id
                && original["oid"] == tag
                && expected_language[field] == tag,
        )?;
        let mut bound = original.clone();
        bound["oid"] = json!(id);
        require(&bound == f)?;
        bound_functions.push(bound);
        expected_language[field] = json!(id);
    }
    require(
        &expected_language == actual_language
            && multiset(&Value::Array(bound_functions))? == multiset(&actual["functions"])?,
    )?;
    require(
        multiset(&expected["languageEffectiveAcl"])? == multiset(&actual["languageEffectiveAcl"])?,
    )?;
    for name in [
        "plpgsql_call_handler",
        "plpgsql_inline_handler",
        "plpgsql_validator",
    ] {
        let original = unique(arr(&expected["functionEffectiveAcls"])?, |row| {
            row["name"] == name
        })?;
        let observed = unique(arr(&actual["functionEffectiveAcls"])?, |row| {
            row["name"] == name
        })?;
        let keys = obj(observed)?
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        require(
            keys == ["name", "acl"].into_iter().collect()
                && obj(original)?
                    .keys()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
                    == keys,
        )?;
        require(multiset(&original["acl"])? == multiset(&observed["acl"])?)?;
    }
    Ok(())
}
