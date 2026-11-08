//! Exact original-owner-relative facts for immutable custom-V2 snapshots.
//! The acceptance oracle is independently authored; observations never widen it.

use super::{InfraError, RowDecodeError, native};
use serde_json::{Value, json};
use tokio_postgres::{Client, GenericClient, Transaction};

/// Portable schema facts plus the actual raw table-ACL null state.
pub type CustomModelV2SchemaFacts = Value;
const REGISTERED_SCHEMA: &str =
    include_str!("../../../../fixtures/db/custom-model-v2-snapshots-0047.json");
/// The registered oracle tree, parsed once per process and borrowed by every
/// observation (spec revision R484 ¶8040).
static REGISTERED: std::sync::LazyLock<Option<Value>> =
    std::sync::LazyLock::new(|| serde_json::from_str(REGISTERED_SCHEMA).ok());

const CAPTURE_SQL: &str = r####"WITH
wanted_relations(schema_name, relation_name) AS (
 VALUES ('openbot_internal'::text,'run_model_selection_v2_snapshots'::text)
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
 WHERE n.nspname='public' AND r.relname='model_connections' AND r.relkind='r'
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
),
functions_scope AS (
 SELECT p.*
 FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE p.oid IN (SELECT tgfoid FROM triggers_scope)
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
 'format','custom-model-v2-snapshots-raw-v1',
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
   WHERE (n.nspname='public' AND c.relname IN ('model_connections','model_connection_secrets'))
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
)::text AS custom_model_v2_raw
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
            .ok_or_else(|| corrupt("custom_model_v2_schema_invalid"))?;
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
    serde_json::to_vec(&canonical_value(v)).map_err(|_| corrupt("custom_model_v2_schema_invalid"))
}

fn corrupt(_field: &'static str) -> InfraError {
    InfraError::repository_invariant("custom_model_v2_schema_invalid")
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
fn ordered_names(columns: &Value) -> Result<Vec<&str>, InfraError> {
    arr(columns)?.iter().map(|col| text(&col["name"])).collect()
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
    Ok(Value::Array(rows.into_iter().map(|row| json!({
        "grantor":"original_model_connections_owner", "grantee":"original_model_connections_owner",
        "privilege":row.privilege, "grantable":row.grantable
    })).collect()))
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
            "custom_model_v2_storage_incompatible",
        ));
    }
    Ok(())
}

fn check_snapshot_contract(raw: &Value, owner: u32) -> Result<(), InfraError> {
    require(owner != 0 && oid(&raw["ownerAnchorRaw"]["relationOidRaw"])? != 0)?;
    require(oid(&raw["ownerAnchorRaw"]["currentUserOidRaw"])? == owner)?;
    let relations = arr(&raw["relations"])?;
    require(relations.len() == 1)?;
    let table = &relations[0];
    require(same_identity(
        &table["identity"],
        "openbot_internal",
        "run_model_selection_v2_snapshots",
    ))?;
    require(oid(&table["ownerOidRaw"])? == owner)?;
    require(
        table["kind"] == "r" && table["persistence"] == "p" && table["accessMethod"] == "heap",
    )?;
    require(
        table["partition"] == false
            && table["rowSecurity"] == false
            && table["forceRowSecurity"] == false,
    )?;
    require(
        table["options"].is_null()
            && arr(&table["rules"])?.is_empty()
            && arr(&table["policies"])?.is_empty()
            && arr(&table["droppedAttributes"])?.is_empty()
            && arr(&table["inheritanceParents"])?.is_empty()
            && arr(&table["inheritanceChildren"])?.is_empty(),
    )?;
    require(table["attributeCount"] == 21 && table["checkCount"] == 14)?;
    let names = [
        "run_id",
        "deployment_id",
        "tenant_id",
        "owner_user_id",
        "auth_generation",
        "connection_id",
        "connection_revision",
        "secret_id",
        "protocol",
        "endpoint",
        "model",
        "created_at",
        "snapshot_schema",
        "source",
        "model_id",
        "catalog_revision",
        "dataset_id",
        "dataset_binding_schema",
        "dataset_initial_origin",
        "dataset_binding_created_at",
        "credential_policy",
    ];
    let types = [
        "text",
        "text",
        "text",
        "text",
        "int8",
        "uuid",
        "int8",
        "uuid",
        "text",
        "text",
        "text",
        "timestamptz",
        "int2",
        "text",
        "text",
        "int8",
        "text",
        "int2",
        "text",
        "timestamptz",
        "text",
    ];
    let columns = arr(&table["columns"])?;
    require(columns.len() == names.len())?;
    for (index, column) in columns.iter().enumerate() {
        require(
            text(&column["name"])? == names[index]
                && column["ordinal"].as_u64() == Some((index + 1) as u64),
        )?;
        require(same_identity(&column["type"], "pg_catalog", types[index]))?;
        require(
            column["notNull"] == true
                && column["default"].is_null()
                && column["identity"] == ""
                && column["generated"] == ""
                && column["dimensions"] == 0
                && column["local"] == true
                && column["inheritanceCount"] == 0,
        )?;
        require(column["aclIsNull"] == true && arr(&column["acl"])?.is_empty())?;
        if types[index] == "text" {
            require(same_identity(&column["collation"], "pg_catalog", "C"))?;
        } else {
            require(column["collation"].is_null())?;
        }
    }
    let builtin = acl_rows(&raw["ownerAnchorRaw"]["builtinTableDefaultAcl"])?;
    let expected_privileges = [
        "DELETE",
        "INSERT",
        "MAINTAIN",
        "REFERENCES",
        "SELECT",
        "TRIGGER",
        "TRUNCATE",
        "UPDATE",
    ];
    require(builtin.len() == expected_privileges.len())?;
    for (row, privilege) in builtin.iter().zip(expected_privileges) {
        require(
            row.grantor == owner
                && row.grantee == owner
                && !row.grantable
                && row.privilege == privilege,
        )?;
    }
    require(acl_rows(&table["acl"])? == builtin)?;
    match table["aclIsNull"].as_bool() {
        Some(true) => require(table["rawAcl"].is_null())?,
        Some(false) => require(acl_rows(&table["rawAcl"])? == builtin)?,
        None => return Err(corrupt("acl")),
    }
    let constraints = arr(&raw["constraints"])?;
    require(constraints.len() == 16)?;
    let mut actual_names = Vec::new();
    for constraint in constraints {
        require(same_identity(
            &constraint["relation"],
            "openbot_internal",
            "run_model_selection_v2_snapshots",
        ))?;
        require(
            constraint["validated"] == true
                && constraint["deferrable"] == false
                && constraint["deferred"] == false,
        )?;
        actual_names.push(text(&constraint["name"])?);
    }
    actual_names.sort_unstable();
    let mut expected_names = [
        "run_model_selection_v2_snapshots_pkey",
        "run_model_selection_v2_snapshots_run_fkey",
        "run_model_selection_v2_snapshots_scope_check",
        "run_model_selection_v2_snapshots_auth_generation_nonnegative",
        "run_model_selection_v2_snapshots_connection_revision_positive",
        "run_model_selection_v2_snapshots_protocol_check",
        "run_model_selection_v2_snapshots_endpoint_check",
        "run_model_selection_v2_snapshots_model_check",
        "run_model_selection_v2_snapshots_snapshot_schema_check",
        "run_model_selection_v2_snapshots_source_check",
        "run_model_selection_v2_snapshots_model_id_shape",
        "run_model_selection_v2_snapshots_catalog_revision_positive",
        "run_model_selection_v2_snapshots_dataset_id_check",
        "run_model_selection_v2_snapshots_dataset_binding_schema_check",
        "run_model_selection_v2_snapshots_dataset_initial_origin_check",
        "run_model_selection_v2_snapshots_credential_policy_check",
    ];
    expected_names.sort_unstable();
    require(actual_names == expected_names)?;
    let pk = unique(constraints, |c| {
        c["name"] == "run_model_selection_v2_snapshots_pkey"
    })?;
    require(pk["kind"] == "p" && ordered_names(&pk["columns"])? == ["run_id"])?;
    let fk = unique(constraints, |c| {
        c["name"] == "run_model_selection_v2_snapshots_run_fkey"
    })?;
    require(fk["kind"] == "f" && ordered_names(&fk["columns"])? == ["run_id"])?;
    for constraint in constraints {
        if constraint["name"] != pk["name"] && constraint["name"] != fk["name"] {
            require(constraint["kind"] == "c")?;
        }
    }
    require(same_identity(
        &fk["reference"]["relation"],
        "public",
        "runs",
    ))?;
    require(ordered_names(&fk["reference"]["columns"])? == ["run_id"])?;
    require(
        fk["reference"]["updateAction"] == "r"
            && fk["reference"]["deleteAction"] == "c"
            && fk["reference"]["match"] == "s"
            && fk["reference"]["deleteSetColumns"].is_null(),
    )?;
    require(same_identity(&fk["supportingIndex"], "public", "runs_pkey"))?;
    let operators = arr(&fk["foreignEqualityOperators"])?;
    require(operators.len() == 3)?;
    let mut families = Vec::new();
    for operator in operators {
        require(
            operator["ordinal"] == 1
                && operator["schema"] == "pg_catalog"
                && operator["name"] == "="
                && operator["leftType"] == "text"
                && operator["rightType"] == "text"
                && operator["resultType"] == "boolean",
        )?;
        require(
            same_identity(&operator["function"], "pg_catalog", "texteq")
                && operator["function"]["arguments"] == "text, text",
        )?;
        families.push(text(&operator["family"])?);
    }
    families.sort_unstable();
    require(families == ["fkFk", "pkFk", "pkPk"])?;
    let references = arr(&fk["reference"]["referencedKeys"])?;
    require(
        references.len() == 1
            && references[0]["name"] == "runs_pkey"
            && references[0]["kind"] == "p"
            && references[0]["validated"] == true
            && references[0]["deferrable"] == false
            && references[0]["deferred"] == false,
    )?;
    require(oid(&references[0]["indexOidRaw"])? == oid(&fk["supportingIndex"]["oidRaw"])?)?;
    let indexes = arr(&raw["indexes"])?;
    require(indexes.len() == 2)?;
    for (schema, relation, name) in [
        (
            "openbot_internal",
            "run_model_selection_v2_snapshots",
            "run_model_selection_v2_snapshots_pkey",
        ),
        ("public", "runs", "runs_pkey"),
    ] {
        let index = unique(indexes, |i| same_identity(&i["identity"], schema, name))?;
        require(same_identity(&index["relation"], schema, relation))?;
        require(
            index["kind"] == "i"
                && index["accessMethod"] == "btree"
                && index["primary"] == true
                && index["unique"] == true,
        )?;
        require(
            index["immediate"] == true
                && index["valid"] == true
                && index["ready"] == true
                && index["live"] == true
                && index["nullsNotDistinct"] == false
                && index["exclusion"] == false,
        )?;
        require(
            index["keyCount"] == 1
                && index["attributeCount"] == 1
                && index["keys"] == "1"
                && index["predicate"].is_null()
                && index["expressions"].is_null(),
        )?;
        if schema == "openbot_internal" {
            require(oid(&index["ownerOidRaw"])? == owner && index["aclIsNull"] == true)?;
            require(pk["supportingIndex"]["oidRaw"] == index["identity"]["oidRaw"])?;
        } else {
            require(fk["supportingIndex"]["oidRaw"] == index["identity"]["oidRaw"])?;
        }
    }
    check_foreign_key_hooks(raw, fk)
}

fn check_foreign_key_hooks(raw: &Value, fk: &Value) -> Result<(), InfraError> {
    let triggers = arr(&raw["triggers"])?;
    require(triggers.len() == 4)?;
    let mut signatures = Vec::new();
    for trigger in triggers {
        require(
            trigger["internal"] == true
                && trigger["enabled"] == "O"
                && trigger["hasParent"] == false
                && trigger["deferrable"] == false
                && trigger["deferred"] == false,
        )?;
        require(
            trigger["argumentCount"] == 0
                && trigger["columns"] == ""
                && trigger["argumentsHex"] == ""
                && trigger["conditionIsNull"] == true
                && trigger["conditionTreeRaw"].is_null()
                && trigger["oldTransition"].is_null()
                && trigger["newTransition"].is_null(),
        )?;
        require(
            trigger["constraintOidRaw"] == fk["oidRaw"]
                && trigger["constraint"]["oidRaw"] == fk["oidRaw"]
                && trigger["constraint"]["kind"] == "f"
                && trigger["constraint"]["relation"] == fk["relation"],
        )?;
        require(trigger["constraintIndex"]["oidRaw"] == fk["supportingIndex"]["oidRaw"])?;
        require(
            trigger["function"]["schema"] == "pg_catalog"
                && trigger["function"]["arguments"] == ""
                && trigger["function"]["kind"] == "f",
        )?;
        let child = same_identity(
            &trigger["relation"],
            "openbot_internal",
            "run_model_selection_v2_snapshots",
        );
        if child {
            require(same_identity(
                &trigger["constraintRelation"],
                "public",
                "runs",
            ))?;
        } else {
            require(
                same_identity(&trigger["relation"], "public", "runs")
                    && same_identity(
                        &trigger["constraintRelation"],
                        "openbot_internal",
                        "run_model_selection_v2_snapshots",
                    ),
            )?;
        }
        signatures.push((
            child,
            text(&trigger["function"]["name"])?.to_owned(),
            trigger["type"].as_i64().ok_or_else(|| corrupt("hooks"))?,
        ));
    }
    signatures.sort();
    let mut expected = vec![
        (false, "RI_FKey_cascade_del".to_owned(), 9),
        (false, "RI_FKey_restrict_upd".to_owned(), 17),
        (true, "RI_FKey_check_ins".to_owned(), 5),
        (true, "RI_FKey_check_upd".to_owned(), 17),
    ];
    expected.sort();
    require(signatures == expected)?;
    let functions = arr(&raw["functions"])?;
    require(functions.len() == 4)?;
    for function in functions {
        require(
            function["identity"]["schema"] == "pg_catalog"
                && function["identity"]["arguments"] == ""
                && function["kind"] == "f"
                && function["securityDefiner"] == false
                && function["isSyncFunction"] == false,
        )?;
        let name = text(&function["identity"]["name"])?;
        require(
            expected
                .iter()
                .any(|(_, expected_name, _)| expected_name == name),
        )?;
        for trigger in triggers
            .iter()
            .filter(|trigger| trigger["function"]["name"] == name)
        {
            require(trigger["function"]["oidRaw"] == function["identity"]["oidRaw"])?;
        }
    }
    Ok(())
}

fn normalize_owner_relative(mut raw: Value) -> Result<CustomModelV2SchemaFacts, InfraError> {
    require(raw["format"] == "custom-model-v2-snapshots-raw-v1")?;
    check_storage(&raw)?;
    let owner = oid(&raw["ownerAnchorRaw"]["ownerOidRaw"])?;
    check_snapshot_contract(&raw, owner)?;
    let table_acl_state = {
        let table = &raw["relations"][0];
        let is_null = table["aclIsNull"].as_bool().ok_or_else(|| corrupt("acl"))?;
        json!({
            "aclIsNull":is_null,
            "rawAcl":if is_null { Value::Null } else { relative_acl(&table["rawAcl"], owner)? }
        })
    };
    for relation in raw["relations"]
        .as_array_mut()
        .ok_or_else(|| corrupt("facts"))?
    {
        let acl = relative_acl(&relation["acl"], owner)?;
        let object = relation.as_object_mut().ok_or_else(|| corrupt("facts"))?;
        object.insert("acl".to_owned(), acl);
        object.insert("ownerIsOriginal".to_owned(), Value::Bool(true));
        // The observed null/raw state remains in tableAclState and is independently matched.
        // Removing it from schema does not erase or infer its actual state.
        object.remove("aclIsNull");
        object.remove("rawAcl");
    }
    for index in raw["indexes"]
        .as_array_mut()
        .ok_or_else(|| corrupt("facts"))?
    {
        let own = same_identity(
            &index["relation"],
            "openbot_internal",
            "run_model_selection_v2_snapshots",
        );
        let object = index.as_object_mut().ok_or_else(|| corrupt("facts"))?;
        object.remove("checkXmin"); // Runtime HOT safety state, not a persistent schema definition.
        if own {
            object.insert("ownerIsOriginal".to_owned(), Value::Bool(true));
        } else {
            object.remove("aclIsNull"); // Existing referenced index ownership is not remapped.
        }
    }
    for function in raw["functions"]
        .as_array_mut()
        .ok_or_else(|| corrupt("facts"))?
    {
        let object = function.as_object_mut().ok_or_else(|| corrupt("facts"))?;
        object.remove("acl");
        object.remove("aclIsNull");
    }
    for trigger in raw["triggers"]
        .as_array_mut()
        .ok_or_else(|| corrupt("facts"))?
    {
        let object = trigger.as_object_mut().ok_or_else(|| corrupt("facts"))?;
        // Only the four already bound genuine internal FK hooks reach this normalization.
        object.remove("name");
        object.remove("definition");
        object.remove("conditionTreeRaw");
    }
    let object = raw.as_object_mut().ok_or_else(|| corrupt("facts"))?;
    for key in [
        "ownerAnchorRaw",
        "legacyOwnershipRaw",
        "deparseContextRaw",
        "storage",
    ] {
        object.remove(key);
    }
    object.insert(
        "format".to_owned(),
        Value::String("custom-model-v2-snapshots-schema-v1".to_owned()),
    );
    erase_checked_oid_fields(&mut raw);
    sort_top_level_multisets(&mut raw)?;
    Ok(canonical_value(&json!({
        "format":"custom-model-v2-snapshots-observation-v1",
        "schema":raw,
        "tableAclState":table_acl_state,
    })))
}

async fn observation_on<C: GenericClient + Sync>(
    client: &C,
) -> Result<CustomModelV2SchemaFacts, InfraError> {
    let row = client
        .query_one(CAPTURE_SQL, &[])
        .await
        .map_err(|source| InfraError::query("只读观察 custom V2 私有快照结构", source))?;
    let payload: String = row.try_get("custom_model_v2_raw").map_err(|source| {
        RowDecodeError::column("(custom_model_v2_schema)", "custom_model_v2_raw", source)
    })?;
    let raw = serde_json::from_str(&payload).map_err(|_| corrupt("facts"))?;
    normalize_owner_relative(raw)
}

fn compare_registered(observation: &CustomModelV2SchemaFacts) -> Result<(), InfraError> {
    let expected = REGISTERED.as_ref().ok_or_else(|| corrupt("oracle"))?;
    let expected_keys = obj(expected)?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    require(
        expected_keys
            == ["format", "schema", "allowedTableAclStates"]
                .into_iter()
                .collect(),
    )?;
    require(
        expected["format"] == "custom-model-v2-snapshots-oracle-v1"
            && observation["format"] == "custom-model-v2-snapshots-observation-v1",
    )?;
    let states = arr(&expected["allowedTableAclStates"])?;
    require(states.len() == 2)?;
    require(
        states
            .iter()
            .any(|state| state == &observation["tableAclState"]),
    )?;
    // Whole independent schema equality. No database-derived expected definition or widening.
    require(expected["schema"] == observation["schema"])
}

/// Observe full owner-relative shape and the actual table ACL state without consulting the oracle.
/// This read-only diagnostic supplies no current user, model, dataset or credential grant.
pub async fn capture(client: &Client) -> Result<CustomModelV2SchemaFacts, InfraError> {
    observation_on(client).await
}

/// Verify the complete known native prefix and the independently registered snapshot oracle.
pub async fn verify(client: &Client) -> Result<(), InfraError> {
    native::validate_known_prefix(client, native::NATIVE_0047_VERSION).await?;
    compare_registered(&observation_on(client).await?)
}

/// Only the original model/native transaction calls this observer after its full-prefix check.
/// It does not acquire another client or transaction, migrate, repair or finish the transaction.
pub(crate) async fn verify_in_transaction(tx: &Transaction<'_>) -> Result<(), InfraError> {
    compare_registered(&observation_on(tx).await?)
}
/// Registered oracle text length; its tree is charged once per operation.
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub(crate) const ORACLE_BYTES: u64 = REGISTERED_SCHEMA.len() as u64;

/// Payload text length one [`verify_in_transaction`] observes, measured on
/// the same transaction before it runs.
#[cfg(all(feature = "server-runtime", target_os = "macos"))]
pub(crate) async fn observation_bytes_in_transaction(
    tx: &Transaction<'_>,
) -> Result<u64, InfraError> {
    let row = tx
        .query_one(
            &format!("SELECT coalesce(octet_length(custom_model_v2_raw),0)::bigint FROM ({CAPTURE_SQL}) observed"),
            &[],
        )
        .await
        .map_err(|source| InfraError::query("measure custom model v2 schema observation", source))?;
    let payload: i64 = row.try_get(0).map_err(|source| {
        super::RowDecodeError::column("(custom_model_v2_schema)", "bytes", source)
    })?;
    u64::try_from(payload)
        .map_err(|_| InfraError::repository_invariant("custom_model_v2_schema_observation_bytes"))
}
