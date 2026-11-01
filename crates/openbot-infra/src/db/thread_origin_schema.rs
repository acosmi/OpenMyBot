//! Complete catalog observation of immutable historical Thread origin facts.
//! The observer preserves original OIDs/ACLs and never derives or widens its independent oracle.

use super::{InfraError, RowDecodeError, native};
use serde_json::{Value, json};
use tokio_postgres::{Client, GenericClient, Transaction};

/// Whole portable schema, the actual table ACL state and original raw facts.
pub type ThreadOriginSchemaFacts = Value;
const REGISTERED_SCHEMA: &str = include_str!("../../../../fixtures/db/thread-origins-0049.json");

const CAPTURE_SQL: &str = r####"WITH
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
            .ok_or_else(|| corrupt("thread_origin_schema_invalid"))?;
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
    serde_json::to_vec(&canonical_value(v)).map_err(|_| corrupt("thread_origin_schema_invalid"))
}

fn corrupt(_field: &'static str) -> InfraError {
    InfraError::repository_invariant("thread_origin_schema_invalid")
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
            "thread_origin_schema_invalid",
        ));
    }
    Ok(())
}

fn check_raw_bindings(raw: &Value) -> Result<u32, InfraError> {
    require(raw["format"] == "thread-origins-raw-v1")?;
    check_storage(raw)?;
    let anchor = &raw["ownerAnchorRaw"];
    let owner = oid(&anchor["ownerOidRaw"])?;
    let table_anchor = oid(&anchor["relationOidRaw"])?;
    require(owner != 0 && table_anchor != 0 && anchor["ownerRoleCount"] == 1)?;
    let legacy = arr(&raw["legacyOwnershipRaw"]["relations"])?;
    require(legacy.len() == 2)?;
    for (schema, name) in [
        ("public", "threads"),
        ("openbot_internal", "schema_migrations"),
    ] {
        let relation = unique(legacy, |r| same_identity(r, schema, name))?;
        require(oid(&relation["ownerOidRaw"])? == owner && oid(&relation["oidRaw"])? != 0)?;
        if schema == "public" {
            require(oid(&relation["oidRaw"])? == table_anchor)?;
        }
    }
    let namespaces = arr(&raw["legacyOwnershipRaw"]["namespaces"])?;
    require(namespaces.len() == 2)?;
    let internal = unique(namespaces, |n| n["schema"] == "openbot_internal")?;
    require(oid(&internal["oidRaw"])? != 0 && oid(&internal["ownerOidRaw"])? == owner)?;
    unique(namespaces, |n| n["schema"] == "public")?;
    let relations = arr(&raw["relations"])?;
    require(relations.len() == 1)?;
    let table = &relations[0];
    require(same_identity(
        &table["identity"],
        "openbot_internal",
        "thread_origins",
    ))?;
    let table_oid = oid(&table["identity"]["oidRaw"])?;
    require(table_oid != 0 && table_oid != table_anchor && oid(&table["ownerOidRaw"])? == owner)?;
    let builtin = &raw["builtinAnchorsRaw"];
    let types = arr(&builtin["types"])?;
    require(types.len() == 5)?;
    for (name, expected_oid) in [
        ("text", 25),
        ("int2", 21),
        ("timestamptz", 1184),
        ("jsonb", 3802),
        ("trigger", 2279),
    ] {
        let actual = unique(types, |t| same_identity(t, "pg_catalog", name))?;
        require(oid(&actual["oidRaw"])? == expected_oid)?;
    }
    let c = &builtin["collation"];
    require(same_identity(c, "pg_catalog", "C") && oid(&c["oidRaw"])? != 0)?;
    let columns = arr(&table["columns"])?;
    require(columns.len() == 14)?;
    for column in columns {
        let ty = unique(types, |ty| ty["name"] == column["type"]["name"])?;
        require(
            column["type"]["schema"] == "pg_catalog"
                && oid(&column["type"]["oidRaw"])? == oid(&ty["oidRaw"])?
                && column["type"]["name"] != "trigger",
        )?;
        if !column["collation"].is_null() {
            require(
                same_identity(&column["collation"], "pg_catalog", "C")
                    && oid(&column["collation"]["oidRaw"])? == oid(&c["oidRaw"])?,
            )?;
        }
    }
    let indexes = arr(&raw["indexes"])?;
    require(indexes.len() == 1)?;
    let index = &indexes[0];
    require(
        same_identity(
            &index["identity"],
            "openbot_internal",
            "thread_origins_pkey",
        ) && same_identity(&index["relation"], "openbot_internal", "thread_origins")
            && oid(&index["relation"]["oidRaw"])? == table_oid
            && oid(&index["ownerOidRaw"])? == owner,
    )?;
    let index_oid = oid(&index["identity"]["oidRaw"])?;
    require(index_oid != 0 && index_oid != table_oid)?;
    let classes = arr(&index["operatorClasses"])?;
    require(classes.len() == 1)?;
    let class = &classes[0];
    let class_anchor = &builtin["operatorClass"];
    require(
        same_identity(class, "pg_catalog", "text_ops")
            && same_identity(class_anchor, "pg_catalog", "text_ops")
            && oid(&class["oidRaw"])? == oid(&class_anchor["oidRaw"])?
            && oid(&class["family"]["oidRaw"])? == oid(&class_anchor["familyOidRaw"])?
            && class["family"]["schema"] == class_anchor["familySchema"]
            && class["family"]["name"] == class_anchor["familyName"],
    )?;
    let collations = arr(&index["collations"])?;
    require(
        collations.len() == 1
            && same_identity(&collations[0]["collation"], "pg_catalog", "C")
            && oid(&collations[0]["collation"]["oidRaw"])? == oid(&c["oidRaw"])?,
    )?;
    let constraints = arr(&raw["constraints"])?;
    require(constraints.len() == 10)?;
    let mut constraint_oids = std::collections::BTreeSet::new();
    for constraint in constraints {
        let constraint_oid = oid(&constraint["oidRaw"])?;
        require(
            constraint_oid != 0
                && constraint_oids.insert(constraint_oid)
                && same_identity(
                    &constraint["relation"],
                    "openbot_internal",
                    "thread_origins",
                )
                && oid(&constraint["relation"]["oidRaw"])? == table_oid
                && constraint["reference"].is_null(),
        )?;
        if constraint["kind"] == "p" {
            require(
                constraint["name"] == "thread_origins_pkey"
                    && same_identity(
                        &constraint["supportingIndex"],
                        "openbot_internal",
                        "thread_origins_pkey",
                    )
                    && oid(&constraint["supportingIndex"]["oidRaw"])? == index_oid,
            )?;
        } else {
            require(constraint["kind"] == "c" && constraint["supportingIndex"].is_null())?;
        }
    }
    let functions = arr(&raw["functions"])?;
    require(functions.len() == 1)?;
    let function = &functions[0];
    require(
        same_identity(
            &function["identity"],
            "openbot_internal",
            "prevent_thread_origin_mutation",
        ) && function["identity"]["arguments"] == ""
            && oid(&function["ownerOidRaw"])? == owner
            && same_identity(&function["returnType"], "pg_catalog", "trigger")
            && oid(&function["returnType"]["oidRaw"])? == 2279,
    )?;
    let function_oid = oid(&function["identity"]["oidRaw"])?;
    require(function_oid != 0)?;
    let triggers = arr(&raw["triggers"])?;
    require(triggers.len() == 2)?;
    let mut trigger_oids = std::collections::BTreeSet::new();
    for trigger in triggers {
        let trigger_oid = oid(&trigger["oidRaw"])?;
        require(
            trigger_oid != 0
                && trigger_oids.insert(trigger_oid)
                && same_identity(&trigger["relation"], "openbot_internal", "thread_origins")
                && oid(&trigger["relation"]["oidRaw"])? == table_oid
                && same_identity(
                    &trigger["function"],
                    "openbot_internal",
                    "prevent_thread_origin_mutation",
                )
                && trigger["function"]["arguments"] == ""
                && oid(&trigger["function"]["oidRaw"])? == function_oid
                && oid(&trigger["constraintOidRaw"])? == 0,
        )?;
    }
    // The whole independently fixed schema below checks every remaining captured field,
    // including all unknown objects. No OID is removed before its actual binding is checked.
    Ok(owner)
}

fn function_acl(v: &Value, owner: u32) -> Result<Value, InfraError> {
    let rows = acl_rows(v)?;
    require(
        rows.len() == 2
            && rows.iter().all(|r| {
                r.grantor == owner
                    && (r.grantee == 0 || r.grantee == owner)
                    && r.privilege == "EXECUTE"
                    && !r.grantable
            }),
    )?;
    require(rows[0].grantee == 0 && rows[1].grantee == owner)?;
    Ok(Value::Array(rows.into_iter().map(|r| json!({"grantor":"original_threads_owner","grantee":if r.grantee == 0 {"PUBLIC"} else {"original_threads_owner"},"privilege":r.privilege,"grantable":r.grantable})).collect()))
}

fn normalize_owner_relative(mut raw: Value) -> Result<ThreadOriginSchemaFacts, InfraError> {
    let owner = check_raw_bindings(&raw)?;
    let raw_facts = raw.clone();
    let table = &raw["relations"][0];
    let is_null = table["aclIsNull"].as_bool().ok_or_else(|| corrupt("acl"))?;
    let table_acl_state = json!({"aclIsNull":is_null,"rawAcl":if is_null {Value::Null} else {relative_acl(&table["rawAcl"],owner)?}});
    for relation in raw["relations"]
        .as_array_mut()
        .ok_or_else(|| corrupt("relations"))?
    {
        let acl = relative_acl(&relation["acl"], owner)?;
        let o = relation
            .as_object_mut()
            .ok_or_else(|| corrupt("relation"))?;
        o.insert("acl".to_owned(), acl);
        o.insert("ownerIsOriginal".to_owned(), Value::Bool(true));
        o.remove("aclIsNull");
        o.remove("rawAcl");
    }
    for index in raw["indexes"]
        .as_array_mut()
        .ok_or_else(|| corrupt("indexes"))?
    {
        index
            .as_object_mut()
            .ok_or_else(|| corrupt("index"))?
            .insert("ownerIsOriginal".to_owned(), Value::Bool(true));
    }
    for function in raw["functions"]
        .as_array_mut()
        .ok_or_else(|| corrupt("functions"))?
    {
        let acl = function_acl(&function["acl"], owner)?;
        let raw_acl = if function["rawAcl"].is_null() {
            Value::Null
        } else {
            function_acl(&function["rawAcl"], owner)?
        };
        let o = function
            .as_object_mut()
            .ok_or_else(|| corrupt("function"))?;
        o.insert("ownerRef".to_owned(), json!("original_threads_owner"));
        o.insert("acl".to_owned(), acl);
        o.insert("rawAcl".to_owned(), raw_acl);
    }
    let object = raw.as_object_mut().ok_or_else(|| corrupt("facts"))?;
    for key in [
        "ownerAnchorRaw",
        "legacyOwnershipRaw",
        "deparseContextRaw",
        "storage",
        "builtinAnchorsRaw",
    ] {
        object.remove(key);
    }
    object.insert("format".to_owned(), json!("thread-origins-schema-v1"));
    erase_checked_oid_fields(&mut raw);
    sort_top_level_multisets(&mut raw)?;
    Ok(canonical_value(
        &json!({"format":"thread-origins-observation-v1","schema":raw,"tableAclState":table_acl_state,"rawFacts":raw_facts}),
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
fn hot_comparison_clone(expected: &Value, actual: &Value) -> Result<Value, InfraError> {
    require(count_hot_markers(expected) == 1 && count_hot_markers(actual) == 0)?;
    let expected_indexes = arr(&expected["indexes"])?;
    let actual_indexes = arr(&actual["indexes"])?;
    require(expected_indexes.len() == 1 && actual_indexes.len() == 1)?;
    let e = &expected_indexes[0];
    let a = &actual_indexes[0];
    require(
        same_identity(&e["identity"], "openbot_internal", "thread_origins_pkey")
            && same_identity(&a["identity"], "openbot_internal", "thread_origins_pkey")
            && same_identity(&a["relation"], "openbot_internal", "thread_origins")
            && e["checkXmin"] == hot_marker()
            && a["checkXmin"].is_boolean(),
    )?;
    let mut checked_index = a.clone();
    checked_index
        .as_object_mut()
        .ok_or_else(|| corrupt("index"))?
        .insert("checkXmin".to_owned(), hot_marker());
    require(&checked_index == e)?; // Every other index flag and binding must match first.
    let mut comparison = actual.clone();
    comparison["indexes"] = json!([checked_index]);
    sort_top_level_multisets(&mut comparison)?;
    Ok(comparison)
}

async fn observation_on<C: GenericClient + Sync>(
    client: &C,
) -> Result<ThreadOriginSchemaFacts, InfraError> {
    let row = client
        .query_one(CAPTURE_SQL, &[])
        .await
        .map_err(|source| InfraError::query("只读观察 Thread 历史来源结构", source))?;
    let payload: String = row.try_get("thread_origin_raw").map_err(|source| {
        RowDecodeError::column("(thread_origin_schema)", "thread_origin_raw", source)
    })?;
    let acl_matches: bool = row
        .try_get("function_acl_matches_builtin")
        .map_err(|source| {
            RowDecodeError::column(
                "(thread_origin_schema)",
                "function_acl_matches_builtin",
                source,
            )
        })?;
    require(acl_matches)?;
    let raw = serde_json::from_str(&payload).map_err(|_| corrupt("facts"))?;
    normalize_owner_relative(raw)
}
fn compare_registered(observation: &ThreadOriginSchemaFacts) -> Result<(), InfraError> {
    let expected: Value = serde_json::from_str(REGISTERED_SCHEMA).map_err(|_| corrupt("oracle"))?;
    let keys = obj(&expected)?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    require(
        keys == ["format", "schema", "allowedTableAclStates"]
            .into_iter()
            .collect(),
    )?;
    require(
        expected["format"] == "thread-origins-oracle-v1"
            && observation["format"] == "thread-origins-observation-v1",
    )?;
    let states = arr(&expected["allowedTableAclStates"])?;
    require(states.len() == 2 && states.iter().any(|s| s == &observation["tableAclState"]))?;
    require(
        expected["schema"] == hot_comparison_clone(&expected["schema"], &observation["schema"])?,
    )
}

/// Complete actual catalog observation; does not consult the registered oracle.
/// This proves no current user, session, source deletion or permission grant.
pub async fn capture(client: &Client) -> Result<ThreadOriginSchemaFacts, InfraError> {
    observation_on(client).await
}
/// Require exact current53, the complete old origin/history graph and additive0053 catalog.
pub async fn verify(client: &Client) -> Result<(), InfraError> {
    let ledger = native::validate_known_prefix(client, native::NATIVE_0053_VERSION).await?;
    require(ledger.latest_version() == native::NATIVE_0053_VERSION)?;
    compare_registered(&observation_on(client).await?)?;
    super::thread_history_admission_schema::verify_schema(client).await?;
    super::restore_reconfirmation_schema::verify_schema(client).await
}
/// Explicit strict52 pre-upgrade observation; never qualifies as current53 admission.
pub(crate) async fn verify_legacy0052(client: &Client) -> Result<(), InfraError> {
    let ledger = native::validate_known_prefix(client, native::NATIVE_0052_VERSION).await?;
    require(ledger.latest_version() == native::NATIVE_0052_VERSION)?;
    compare_registered(&observation_on(client).await?)?;
    super::thread_history_admission_schema::verify_schema(client).await
}
/// Explicit historical49 pre-upgrade branch; never qualifies as current53 admission.
pub(crate) async fn verify_legacy0049(client: &Client) -> Result<(), InfraError> {
    let ledger = native::validate_known_prefix(client, native::NATIVE_0049_VERSION).await?;
    require(ledger.latest_version() == native::NATIVE_0049_VERSION)?;
    compare_registered(&observation_on(client).await?)
}
/// Explicit historical50, with the original full HQ schema on the same Client.
pub(crate) async fn verify_legacy0050(client: &Client) -> Result<(), InfraError> {
    let ledger = native::validate_known_prefix(client, native::NATIVE_0050_VERSION).await?;
    require(ledger.latest_version() == native::NATIVE_0050_VERSION)?;
    compare_registered(&observation_on(client).await?)?;
    super::thread_history_admission_schema::verify_schema_legacy0050(client).await
}
/// Explicit historical51, preserving its original whole writer observation and oracle.
pub(crate) async fn verify_legacy0051(client: &Client) -> Result<(), InfraError> {
    let ledger = native::validate_known_prefix(client, native::NATIVE_0051_VERSION).await?;
    require(ledger.latest_version() == native::NATIVE_0051_VERSION)?;
    compare_registered(&observation_on(client).await?)?;
    super::thread_history_writer_schema::verify_schema_legacy0051(client).await
}
/// Only observes origin schema after the caller proves the exact native prefix on this original Tx.
pub(crate) async fn verify_in_transaction(tx: &Transaction<'_>) -> Result<(), InfraError> {
    compare_registered(&observation_on(tx).await?)
}
