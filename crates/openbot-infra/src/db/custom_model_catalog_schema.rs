//! Read-only checks for custom model catalog shape and connection mapping.
//! Catalog facts use the original model connection owner as their portable anchor.

use super::{InfraError, native};
use serde_json::{Value, json};
use tokio_postgres::{Client, GenericClient, Transaction};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CustomModelCatalogSchemaError {
    #[error("custom_model_catalog_schema_unavailable")]
    Unavailable,
    #[error("custom_model_catalog_storage_incompatible")]
    IncompatibleStorage,
    #[error("custom_model_catalog_schema_corrupt")]
    Corrupt { field: &'static str },
}

const REGISTERED_NATIVE_FLOOR: i32 = native::NATIVE_0046_VERSION;
const REGISTERED_SCHEMA: &str =
    include_str!("../../../../fixtures/db/custom-model-catalogs-0046.json");
/// The registered oracle tree, parsed once per process and borrowed by every
/// observation (spec revision R484 ¶7984).
static REGISTERED: std::sync::LazyLock<Option<Value>> =
    std::sync::LazyLock::new(|| serde_json::from_str(REGISTERED_SCHEMA).ok());
const CAPTURE_SQL: &str = r####"WITH
wanted_relations(schema_name, relation_name) AS (
 VALUES ('public'::text,'model_connections'::text),
        ('public'::text,'model_connection_secrets'::text),
        ('public'::text,'custom_model_catalogs'::text)
),
relations AS (
 SELECT c.*, n.nspname AS schema_name
 FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 JOIN wanted_relations w ON w.schema_name=n.nspname AND w.relation_name=c.relname
),
original_owner AS (
 SELECT r.oid AS relation_oid, r.relowner AS owner_oid
 FROM relations r
 WHERE r.schema_name='public' AND r.relname='model_connections' AND r.relkind='r'
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
 WHERE (n.nspname='openbot_internal' AND p.proname='sync_custom_model_catalog')
    OR p.oid IN (SELECT tgfoid FROM triggers_scope)
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
 'format','custom-model-catalog-raw-v1',
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
 'nativeLedger',(
  SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
   'version',m.version,'name',m.name,'checksum',m.checksum)
   ORDER BY m.version,m.name COLLATE pg_catalog."C",m.checksum COLLATE pg_catalog."C"),'[]'::jsonb)
  FROM openbot_internal.schema_migrations m WHERE m.version<=$1::integer
 ),
 'relations',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.relname COLLATE pg_catalog."C"),'[]'::jsonb) FROM relation_facts f),
 'constraints',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.relname COLLATE pg_catalog."C",f.conname COLLATE pg_catalog."C",f.contype::text COLLATE pg_catalog."C"),'[]'::jsonb) FROM constraint_facts f),
 'indexes',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.relname COLLATE pg_catalog."C"),'[]'::jsonb) FROM index_facts f),
 'triggers',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.relname COLLATE pg_catalog."C",f.tgname COLLATE pg_catalog."C"),'[]'::jsonb) FROM trigger_facts f),
 'functions',(SELECT coalesce(pg_catalog.jsonb_agg(f.facts ORDER BY f.schema_name COLLATE pg_catalog."C",f.proname COLLATE pg_catalog."C",f.identity_arguments COLLATE pg_catalog."C"),'[]'::jsonb) FROM function_facts f)
)::text AS custom_model_catalog_raw
"####;
const MAPPING_SQL: &str = r####"SELECT NOT EXISTS (
 SELECT 1
 FROM public.model_connections m
 FULL OUTER JOIN public.custom_model_catalogs c ON c.connection_id=m.id
 WHERE m.id IS NULL OR c.connection_id IS NULL OR c.catalog_revision<=0 OR
  ROW(c.connection_id,c.deployment_id,c.tenant_id,c.owner_user_id,
      c.model_id,c.protocol,c.endpoint,c.model,c.enabled,c.retired)
  IS DISTINCT FROM
  ROW(m.id,m.deployment_id,m.tenant_id,m.owner_user_id,
      'custom:'::text||m.id::text,m.protocol,m.endpoint,m.model,m.enabled,m.deleted_at IS NOT NULL)
) AS mapping_ok
"####;
const STORAGE_SQL: &str = "SELECT pg_catalog.current_setting('server_encoding'), \
    pg_catalog.current_setting('block_size')::integer, \
    pg_catalog.current_setting('server_version_num')::integer";

// Exact source of the catalog synchronization function.
const FUNCTION_SOURCE_BODY: &str = r###"
DECLARE
    v_catalog public.custom_model_catalogs%ROWTYPE;
    v_revision bigint;
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO public.custom_model_catalogs (
            connection_id, deployment_id, tenant_id, owner_user_id,
            model_id, catalog_revision, protocol, endpoint, model, enabled, retired
        ) VALUES (
            NEW.id, NEW.deployment_id, NEW.tenant_id, NEW.owner_user_id,
            'custom:'::text || NEW.id::text, 1,
            NEW.protocol, NEW.endpoint, NEW.model, NEW.enabled, NEW.deleted_at IS NOT NULL
        );
        RETURN NEW;
    END IF;
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    SELECT c.* INTO v_catalog
    FROM public.custom_model_catalogs c
    WHERE c.connection_id = OLD.id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    IF v_catalog.catalog_revision <= 0 OR
       ROW(v_catalog.connection_id, v_catalog.deployment_id, v_catalog.tenant_id,
           v_catalog.owner_user_id, v_catalog.model_id, v_catalog.protocol,
           v_catalog.endpoint, v_catalog.model, v_catalog.enabled, v_catalog.retired)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.deployment_id, OLD.tenant_id, OLD.owner_user_id,
           'custom:'::text || OLD.id::text, OLD.protocol, OLD.endpoint, OLD.model,
           OLD.enabled, OLD.deleted_at IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    IF ROW(NEW.id, NEW.deployment_id, NEW.tenant_id, NEW.owner_user_id)
       IS DISTINCT FROM ROW(OLD.id, OLD.deployment_id, OLD.tenant_id, OLD.owner_user_id) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    IF ROW(NEW.protocol, NEW.endpoint, NEW.model, NEW.enabled, NEW.deleted_at IS NOT NULL)
       IS NOT DISTINCT FROM
       ROW(OLD.protocol, OLD.endpoint, OLD.model, OLD.enabled, OLD.deleted_at IS NOT NULL) THEN
        RETURN NEW;
    END IF;
    IF v_catalog.catalog_revision = 9223372036854775807 THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    v_revision := v_catalog.catalog_revision + 1;
    UPDATE public.custom_model_catalogs
    SET catalog_revision = v_revision, protocol = NEW.protocol, endpoint = NEW.endpoint,
        model = NEW.model, enabled = NEW.enabled, retired = NEW.deleted_at IS NOT NULL
    WHERE connection_id = OLD.id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'custom_model_catalog_invariant';
    END IF;
    RETURN NEW;
END;
"###;

const fn corrupt(field: &'static str) -> CustomModelCatalogSchemaError {
    CustomModelCatalogSchemaError::Corrupt { field }
}
fn facts<T>() -> Result<T, CustomModelCatalogSchemaError> {
    Err(corrupt("catalog_facts"))
}
fn shape<T>() -> Result<T, CustomModelCatalogSchemaError> {
    Err(corrupt("catalog_schema"))
}
fn require(value: bool) -> Result<(), CustomModelCatalogSchemaError> {
    if value { Ok(()) } else { shape() }
}
fn obj(v: &Value) -> Result<&serde_json::Map<String, Value>, CustomModelCatalogSchemaError> {
    v.as_object().ok_or_else(|| corrupt("catalog_facts"))
}
fn arr(v: &Value) -> Result<&[Value], CustomModelCatalogSchemaError> {
    v.as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| corrupt("catalog_facts"))
}
fn text(v: &Value) -> Result<&str, CustomModelCatalogSchemaError> {
    v.as_str().ok_or_else(|| corrupt("catalog_facts"))
}
fn flag(v: &Value) -> Result<bool, CustomModelCatalogSchemaError> {
    v.as_bool().ok_or_else(|| corrupt("catalog_facts"))
}
fn oid(v: &Value) -> Result<u32, CustomModelCatalogSchemaError> {
    let s = text(v)?;
    if s.is_empty() || !s.bytes().all(|x| x.is_ascii_digit()) {
        return facts();
    }
    s.parse::<u32>().map_err(|_| corrupt("catalog_facts"))
}
fn same_identity(v: &Value, schema: &str, name: &str) -> bool {
    v.get("schema").and_then(Value::as_str) == Some(schema)
        && v.get("name").and_then(Value::as_str) == Some(name)
}
fn unique(
    values: &[Value],
    mut pred: impl FnMut(&Value) -> bool,
) -> Result<&Value, CustomModelCatalogSchemaError> {
    let mut rows = values.iter().filter(|v| pred(v));
    let first = rows.next().ok_or_else(|| corrupt("catalog_schema"))?;
    require(rows.next().is_none())?;
    Ok(first)
}
fn identity(v: &Value) -> Result<&Value, CustomModelCatalogSchemaError> {
    v.get("identity").ok_or_else(|| corrupt("catalog_facts"))
}
fn ordered_names(columns: &Value) -> Result<Vec<&str>, CustomModelCatalogSchemaError> {
    arr(columns)?.iter().map(|v| text(&v["name"])).collect()
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Acl {
    grantor: u32,
    grantee: u32,
    privilege: String,
    grantable: bool,
}
fn acl_rows(v: &Value) -> Result<Vec<Acl>, CustomModelCatalogSchemaError> {
    let mut out = Vec::new();
    for row in arr(v)? {
        // Exact multiset: never deduplicate, ignore grantor, or discard grant options.
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
            grantable: flag(&row["grantable"])?,
        });
    }
    out.sort();
    Ok(out)
}
fn relative_acl(v: &Value, owner: u32) -> Result<Value, CustomModelCatalogSchemaError> {
    let rows = acl_rows(v)?;
    require(
        rows.iter()
            .all(|r| r.grantor == owner && r.grantee == owner && !r.grantable),
    )?;
    Ok(Value::Array(rows.into_iter().map(|r|json!({
        "grantor":"original_model_connections_owner", "grantee":"original_model_connections_owner",
        "privilege":r.privilege,"grantable":r.grantable
    })).collect()))
}

fn storage_values(
    encoding: &str,
    block: i32,
    server: i32,
) -> Result<(), CustomModelCatalogSchemaError> {
    if encoding != "UTF8" || block != 8192 || !(170_000..180_000).contains(&server) {
        return Err(CustomModelCatalogSchemaError::IncompatibleStorage);
    }
    Ok(())
}
async fn storage_on<C: GenericClient + Sync>(
    client: &C,
) -> Result<(), CustomModelCatalogSchemaError> {
    let row = client
        .query_one(STORAGE_SQL, &[])
        .await
        .map_err(|_| CustomModelCatalogSchemaError::Unavailable)?;
    let encoding: String = row.try_get(0).map_err(|_| corrupt("server_encoding"))?;
    let block: i32 = row.try_get(1).map_err(|_| corrupt("block_size"))?;
    let server: i32 = row.try_get(2).map_err(|_| corrupt("server_version"))?;
    storage_values(&encoding, block, server)
}
fn storage_in_raw(raw: &Value) -> Result<(), CustomModelCatalogSchemaError> {
    let e = text(&raw["storage"]["serverEncoding"])?;
    let b = raw["storage"]["blockSize"]
        .as_i64()
        .and_then(|v| i32::try_from(v).ok())
        .ok_or_else(|| corrupt("block_size"))?;
    let s = raw["storage"]["serverVersion"]
        .as_i64()
        .and_then(|v| i32::try_from(v).ok())
        .ok_or_else(|| corrupt("server_version"))?;
    storage_values(e, b, s)
}

fn check_new_catalog_contract(
    raw: &Value,
    owner: u32,
) -> Result<(), CustomModelCatalogSchemaError> {
    let relations = arr(&raw["relations"])?;
    require(relations.len() == 3)?;
    // RLS flags do not prove the absence of dormant policies. All three registered
    // relation baselines require an actually observed empty pg_policy collection.
    for relation in relations {
        require(arr(&relation["policies"])?.is_empty())?;
    }
    let old = unique(relations, |v| {
        same_identity(&v["identity"], "public", "model_connections")
    })?;
    require(oid(&old["identity"]["oidRaw"])? == oid(&raw["ownerAnchorRaw"]["relationOidRaw"])?)?;
    require(oid(&old["ownerOidRaw"])? == owner)?;
    let _secret = unique(relations, |v| {
        same_identity(&v["identity"], "public", "model_connection_secrets")
    })?;
    let cat = unique(relations, |v| {
        same_identity(&v["identity"], "public", "custom_model_catalogs")
    })?;
    require(oid(&cat["ownerOidRaw"])? == owner)?;
    require(cat["kind"] == "r" && cat["persistence"] == "p" && cat["accessMethod"] == "heap")?;
    require(
        cat["partition"] == false
            && cat["rowSecurity"] == false
            && cat["forceRowSecurity"] == false,
    )?;
    require(
        cat["options"].is_null()
            && arr(&cat["rules"])?.is_empty()
            && arr(&cat["droppedAttributes"])?.is_empty(),
    )?;
    require(
        arr(&cat["inheritanceParents"])?.is_empty() && arr(&cat["inheritanceChildren"])?.is_empty(),
    )?;
    let names = [
        "connection_id",
        "deployment_id",
        "tenant_id",
        "owner_user_id",
        "model_id",
        "catalog_revision",
        "protocol",
        "endpoint",
        "model",
        "enabled",
        "retired",
    ];
    let types = [
        "uuid", "text", "text", "text", "text", "int8", "text", "text", "text", "bool", "bool",
    ];
    let columns = arr(&cat["columns"])?;
    require(columns.len() == 11)?;
    for (index, col) in columns.iter().enumerate() {
        require(
            text(&col["name"])? == names[index]
                && col["ordinal"].as_u64() == Some((index + 1) as u64),
        )?;
        require(same_identity(&col["type"], "pg_catalog", types[index]))?;
        require(
            col["notNull"] == true
                && col["default"].is_null()
                && col["identity"] == ""
                && col["generated"] == "",
        )?;
        require(col["aclIsNull"] == true && arr(&col["acl"])?.is_empty())?;
        if names[index] == "model_id" {
            require(same_identity(&col["collation"], "pg_catalog", "C"))?;
        }
    }
    let expected_acl = acl_rows(&raw["ownerAnchorRaw"]["builtinTableDefaultAcl"])?;
    require(
        !expected_acl.is_empty()
            && expected_acl
                .iter()
                .all(|r| r.grantor == owner && r.grantee == owner && !r.grantable),
    )?;
    // PG17 MAINTAIN is observed through acldefault, not omitted by a seven-privilege list.
    require(expected_acl.iter().any(|r| r.privilege == "MAINTAIN"))?;
    require(acl_rows(&cat["acl"])? == expected_acl)?;
    let all_constraints = arr(&raw["constraints"])?;
    let constraints = all_constraints
        .iter()
        .filter(|v| same_identity(&v["relation"], "public", "custom_model_catalogs"))
        .collect::<Vec<_>>();
    require(constraints.len() == 8)?;
    let mut actual_names = constraints
        .iter()
        .map(|v| text(&v["name"]))
        .collect::<Result<Vec<_>, _>>()?;
    actual_names.sort_unstable();
    let mut wanted_names = vec![
        "custom_model_catalogs_pkey",
        "custom_model_catalogs_model_id_key",
        "custom_model_catalogs_model_id_shape",
        "custom_model_catalogs_catalog_revision_positive",
        "custom_model_catalogs_protocol_check",
        "custom_model_catalogs_endpoint_check",
        "custom_model_catalogs_model_check",
        "custom_model_catalogs_connection_scope_fkey",
    ];
    wanted_names.sort_unstable();
    require(actual_names == wanted_names)?;
    let indexes = arr(&raw["indexes"])?;
    let own = indexes
        .iter()
        .filter(|v| same_identity(&v["relation"], "public", "custom_model_catalogs"))
        .collect::<Vec<_>>();
    require(own.len() == 2)?;
    for (name, primary, keys) in [
        ("custom_model_catalogs_pkey", true, "1"),
        ("custom_model_catalogs_model_id_key", false, "5"),
    ] {
        let idx = unique(indexes, |v| same_identity(&v["identity"], "public", name))?;
        require(
            same_identity(&idx["relation"], "public", "custom_model_catalogs")
                && oid(&idx["ownerOidRaw"])? == owner,
        )?;
        require(
            idx["kind"] == "i"
                && idx["accessMethod"] == "btree"
                && idx["primary"] == primary
                && idx["unique"] == true,
        )?;
        require(
            idx["immediate"] == true
                && idx["valid"] == true
                && idx["ready"] == true
                && idx["live"] == true
                && idx["nullsNotDistinct"] == false,
        )?;
        require(
            idx["keyCount"] == 1
                && idx["attributeCount"] == 1
                && idx["keys"] == keys
                && idx["predicate"].is_null()
                && idx["expressions"].is_null(),
        )?;
    }
    let fk = unique(all_constraints, |v| {
        same_identity(&v["relation"], "public", "custom_model_catalogs")
            && v["name"] == "custom_model_catalogs_connection_scope_fkey"
    })?;
    require(
        fk["kind"] == "f"
            && fk["validated"] == true
            && fk["deferrable"] == false
            && fk["deferred"] == false,
    )?;
    require(
        ordered_names(&fk["columns"])?
            == [
                "connection_id",
                "deployment_id",
                "tenant_id",
                "owner_user_id",
            ],
    )?;
    require(same_identity(
        &fk["reference"]["relation"],
        "public",
        "model_connections",
    ))?;
    require(
        ordered_names(&fk["reference"]["columns"])?
            == ["id", "deployment_id", "tenant_id", "owner_user_id"],
    )?;
    require(
        fk["reference"]["updateAction"] == "r"
            && fk["reference"]["deleteAction"] == "c"
            && fk["reference"]["match"] == "s"
            && fk["reference"]["deleteSetColumns"].is_null(),
    )?;
    let old_key_name = "model_connections_id_deployment_id_tenant_id_owner_user_id_key";
    require(same_identity(
        &fk["supportingIndex"],
        "public",
        old_key_name,
    ))?;
    let keys = arr(&fk["reference"]["referencedKeys"])?;
    require(keys.len() == 1)?;
    require(
        keys[0]["name"] == old_key_name
            && keys[0]["kind"] == "u"
            && keys[0]["validated"] == true
            && keys[0]["deferrable"] == false
            && keys[0]["deferred"] == false,
    )?;
    require(oid(&keys[0]["indexOidRaw"])? == oid(&fk["supportingIndex"]["oidRaw"])?)?;
    let supporting = unique(indexes, |v| {
        v["identity"]["oidRaw"] == fk["supportingIndex"]["oidRaw"]
    })?;
    require(same_identity(
        &supporting["relation"],
        "public",
        "model_connections",
    ))?;
    require(
        supporting["primary"] == false
            && supporting["unique"] == true
            && supporting["immediate"] == true
            && supporting["valid"] == true
            && supporting["ready"] == true
            && supporting["live"] == true,
    )?;
    require(
        supporting["keyCount"] == 4
            && supporting["attributeCount"] == 4
            && supporting["keys"] == "1 2 3 4",
    )?;
    Ok(())
}

fn check_function_and_trigger_binding(
    raw: &Value,
    owner: u32,
) -> Result<(), CustomModelCatalogSchemaError> {
    let functions = arr(&raw["functions"])?;
    let same_name = functions
        .iter()
        .filter(|v| v["isSyncFunction"] == true)
        .collect::<Vec<_>>();
    require(same_name.len() == 1)?;
    let f = same_name[0];
    require(same_identity(
        identity(f)?,
        "openbot_internal",
        "sync_custom_model_catalog",
    ))?;
    require(
        f["identity"]["arguments"] == ""
            && f["inputArgumentCount"] == 0
            && f["defaultArgumentCount"] == 0,
    )?;
    require(
        f["kind"] == "f"
            && f["language"] == "plpgsql"
            && f["securityDefiner"] == false
            && f["strict"] == false
            && f["leakproof"] == false
            && f["setReturning"] == false,
    )?;
    require(
        f["volatility"] == "v"
            && f["parallel"] == "u"
            && f["configuration"] == json!(["search_path=pg_catalog"]),
    )?;
    require(same_identity(&f["returnType"], "pg_catalog", "trigger"))?;
    require(
        f["source"].as_str() == Some(FUNCTION_SOURCE_BODY)
            && f["binary"].is_null()
            && f["sqlBody"].is_null(),
    )?;
    require(
        f["variadicType"].is_null()
            && f["supportFunction"].is_null()
            && f["argumentDefaults"].is_null(),
    )?;
    require(
        f["allArgumentTypesIsNull"] == true
            && arr(&f["inputTypes"])?.is_empty()
            && arr(&f["allArgumentTypes"])?.is_empty(),
    )?;
    require(
        f["argumentModes"].is_null()
            && f["argumentNames"].is_null()
            && f["transformTypesIsNull"] == true
            && arr(&f["transformTypes"])?.is_empty(),
    )?;
    require(oid(&f["ownerOidRaw"])? == owner)?;
    require(
        acl_rows(&f["acl"])?
            == vec![Acl {
                grantor: owner,
                grantee: owner,
                privilege: "EXECUTE".to_owned(),
                grantable: false,
            }],
    )?;
    let triggers = arr(&raw["triggers"])?;
    let t = unique(triggers, |v| {
        same_identity(&v["relation"], "public", "model_connections")
            && v["name"] == "model_connections_custom_catalog_sync"
    })?;
    require(
        t["internal"] == false && t["enabled"] == "O" && t["type"] == 21 && t["hasParent"] == false,
    )?;
    require(
        t["deferrable"] == false
            && t["deferred"] == false
            && t["argumentCount"] == 0
            && t["columns"] == ""
            && t["argumentsHex"] == "",
    )?;
    require(
        t["conditionIsNull"] == true
            && t["conditionTreeRaw"].is_null()
            && t["oldTransition"].is_null()
            && t["newTransition"].is_null(),
    )?;
    require(
        oid(&t["constraintOidRaw"])? == 0
            && t["constraint"].is_null()
            && t["constraintRelation"].is_null()
            && t["constraintIndex"].is_null(),
    )?;
    require(
        t["function"]["oidRaw"] == f["identity"]["oidRaw"]
            && t["function"]["arguments"] == ""
            && t["function"]["kind"] == "f",
    )?;
    // Wrong or extra user hooks remain in canonical arrays and differ from the real oracle.
    Ok(())
}

fn check_foreign_key_hooks(raw: &Value) -> Result<(), CustomModelCatalogSchemaError> {
    let constraints = arr(&raw["constraints"])?;
    let fk = unique(constraints, |v| {
        same_identity(&v["relation"], "public", "custom_model_catalogs")
            && v["name"] == "custom_model_catalogs_connection_scope_fkey"
    })?;
    let mut signatures = Vec::new();
    for t in arr(&raw["triggers"])? {
        if t["internal"] == true {
            // Every captured internal hook must retain its actual constraint binding,
            // not merely a generated name. Other old constraints have their own genuine
            // mixed deferral properties; do not force all old hooks to equal the FK flag.
            require(t["constraint"]["kind"] == "f")?;
            let _bound = unique(constraints, |c| c["oidRaw"] == t["constraintOidRaw"])?;
        }
        if t["constraintOidRaw"] != fk["oidRaw"] {
            continue;
        }
        require(
            t["internal"] == true
                && t["enabled"] == "O"
                && t["hasParent"] == false
                && t["deferrable"] == false
                && t["deferred"] == false,
        )?;
        require(
            t["argumentCount"] == 0
                && t["columns"] == ""
                && t["argumentsHex"] == ""
                && t["conditionIsNull"] == true
                && t["conditionTreeRaw"].is_null()
                && t["oldTransition"].is_null()
                && t["newTransition"].is_null(),
        )?;
        require(
            t["constraint"]["oidRaw"] == fk["oidRaw"]
                && t["constraint"]["relation"] == fk["relation"],
        )?;
        require(t["constraintIndex"]["oidRaw"] == fk["supportingIndex"]["oidRaw"])?;
        require(
            t["function"]["schema"] == "pg_catalog"
                && t["function"]["arguments"] == ""
                && t["function"]["kind"] == "f",
        )?;
        let rel = text(&t["relation"]["name"])?;
        let other = if rel == "custom_model_catalogs" {
            "model_connections"
        } else {
            "custom_model_catalogs"
        };
        require(
            same_identity(&t["relation"], "public", rel)
                && same_identity(&t["constraintRelation"], "public", other),
        )?;
        signatures.push((
            rel.to_owned(),
            text(&t["function"]["name"])?.to_owned(),
            t["type"].as_i64().ok_or_else(|| corrupt("catalog_facts"))?,
        ));
    }
    signatures.sort();
    // These are DDL-required PG17 hook identities, NOT actual-capture JSON.
    let mut wanted = vec![
        (
            "custom_model_catalogs".to_owned(),
            "RI_FKey_check_ins".to_owned(),
            5,
        ),
        (
            "custom_model_catalogs".to_owned(),
            "RI_FKey_check_upd".to_owned(),
            17,
        ),
        (
            "model_connections".to_owned(),
            "RI_FKey_cascade_del".to_owned(),
            9,
        ),
        (
            "model_connections".to_owned(),
            "RI_FKey_restrict_upd".to_owned(),
            17,
        ),
    ];
    wanted.sort();
    require(signatures == wanted)
}

// OIDs are erased only after their actual owner/binding checks above; all retained
// qualified identities and full semantic fields still undergo whole-oracle equality.
// This exact key allowlist is not ends_with("Raw") and never strips unknown fields.
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
fn sort_top_level_multisets(v: &mut Value) -> Result<(), CustomModelCatalogSchemaError> {
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
            .ok_or_else(|| corrupt("catalog_facts"))?;
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
fn canonical_bytes(v: &Value) -> Result<Vec<u8>, CustomModelCatalogSchemaError> {
    serde_json::to_vec(&canonical_value(v)).map_err(|_| corrupt("catalog_facts"))
}
fn normalize_owner_relative(mut raw: Value) -> Result<Value, CustomModelCatalogSchemaError> {
    require(raw["format"] == "custom-model-catalog-raw-v1")?;
    storage_in_raw(&raw)?;
    let owner = oid(&raw["ownerAnchorRaw"]["ownerOidRaw"])?;
    require(owner != 0)?;
    check_new_catalog_contract(&raw, owner)?;
    check_function_and_trigger_binding(&raw, owner)?;
    check_foreign_key_hooks(&raw)?;
    for r in raw["relations"]
        .as_array_mut()
        .ok_or_else(|| corrupt("catalog_facts"))?
    {
        let new = same_identity(&r["identity"], "public", "custom_model_catalogs");
        let o = r.as_object_mut().ok_or_else(|| corrupt("catalog_facts"))?;
        if new {
            let acl = relative_acl(o.get("acl").ok_or_else(|| corrupt("catalog_facts"))?, owner)?;
            o.insert("acl".to_owned(), acl);
            o.insert("ownerIsOriginal".to_owned(), Value::Bool(true));
            o.remove("aclIsNull"); // semantic NULL/default equality was checked against old-O builtin default
        } else {
            o.remove("acl");
            o.remove("aclIsNull");
        }
        if !new {
            // Legacy ACLs are retained in private raw capture and compared pre/post
            // on the same DB; no fresh-oracle assumption about their actual roles.
            for col in o
                .get_mut("columns")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| corrupt("catalog_facts"))?
            {
                let co = col
                    .as_object_mut()
                    .ok_or_else(|| corrupt("catalog_facts"))?;
                co.remove("acl");
                co.remove("aclIsNull");
            }
        }
    }
    for idx in raw["indexes"]
        .as_array_mut()
        .ok_or_else(|| corrupt("catalog_facts"))?
    {
        // indcheckxmin is HOT/query-safety runtime state, retained only in raw facts.
        // It is excluded from portable oracle comparison.
        idx.as_object_mut()
            .ok_or_else(|| corrupt("catalog_facts"))?
            .remove("checkXmin");
        if same_identity(&idx["relation"], "public", "custom_model_catalogs") {
            require(oid(&idx["ownerOidRaw"])? == owner)?;
            require(idx["aclIsNull"] == true)?;
            idx.as_object_mut()
                .ok_or_else(|| corrupt("catalog_facts"))?
                .insert("ownerIsOriginal".to_owned(), Value::Bool(true));
        } else {
            // Existing index ownership/ACL is only a same-database raw preservation fact.
            idx.as_object_mut()
                .ok_or_else(|| corrupt("catalog_facts"))?
                .remove("aclIsNull");
        }
    }
    for f in raw["functions"]
        .as_array_mut()
        .ok_or_else(|| corrupt("catalog_facts"))?
    {
        let sync = f["isSyncFunction"] == true;
        let o = f.as_object_mut().ok_or_else(|| corrupt("catalog_facts"))?;
        if sync {
            let acl = relative_acl(o.get("acl").ok_or_else(|| corrupt("catalog_facts"))?, owner)?;
            o.insert("acl".to_owned(), acl);
            o.insert("ownerIsOriginal".to_owned(), Value::Bool(true));
        } else {
            o.remove("acl");
        }
        o.remove("aclIsNull"); // legacy pg_catalog owner/ACL remains raw; function content/attrs remain exact
    }
    for t in raw["triggers"]
        .as_array_mut()
        .ok_or_else(|| corrupt("catalog_facts"))?
    {
        let internal = t["internal"] == true;
        let o = t.as_object_mut().ok_or_else(|| corrupt("catalog_facts"))?;
        // The raw pg_node_tree can contain database-local OIDs; exact user WHEN
        // text remains in pg_get_triggerdef, and conditionIsNull stays canonical.
        o.remove("conditionTreeRaw");
        if internal {
            o.remove("name");
            o.remove("definition"); // only proven bound internal auto-name text
        }
    }
    let o = raw
        .as_object_mut()
        .ok_or_else(|| corrupt("catalog_facts"))?;
    for key in [
        "ownerAnchorRaw",
        "legacyOwnershipRaw",
        "deparseContextRaw",
        "storage",
    ] {
        o.remove(key);
    }
    o.insert(
        "format".to_owned(),
        Value::String("custom-model-catalog-schema-v1".to_owned()),
    );
    erase_checked_oid_fields(&mut raw);
    sort_top_level_multisets(&mut raw)?;
    Ok(canonical_value(&raw))
}

async fn raw_on<C: GenericClient + Sync>(
    client: &C,
) -> Result<Value, CustomModelCatalogSchemaError> {
    let row = client
        .query_one(CAPTURE_SQL, &[&REGISTERED_NATIVE_FLOOR])
        .await
        .map_err(|_| CustomModelCatalogSchemaError::Unavailable)?;
    let raw: String = row
        .try_get("custom_model_catalog_raw")
        .map_err(|_| corrupt("catalog_facts"))?;
    serde_json::from_str(&raw).map_err(|_| corrupt("catalog_facts"))
}
async fn canonical_on<C: GenericClient + Sync>(
    client: &C,
) -> Result<Value, CustomModelCatalogSchemaError> {
    normalize_owner_relative(raw_on(client).await?)
}
fn compare_registered(actual: &Value) -> Result<(), CustomModelCatalogSchemaError> {
    let expected = REGISTERED
        .as_ref()
        .ok_or_else(|| corrupt("schema_oracle"))?;
    // The include is frozen from independent raw owned-PG observations after registration.
    // No expected builder, database-derived widening, field subtraction or fallback.
    if actual != expected {
        return shape();
    }
    Ok(())
}
async fn mapping_on<C: GenericClient + Sync>(
    client: &C,
) -> Result<(), CustomModelCatalogSchemaError> {
    let row = client
        .query_one(MAPPING_SQL, &[])
        .await
        .map_err(|_| CustomModelCatalogSchemaError::Unavailable)?;
    let valid: bool = row
        .try_get("mapping_ok")
        .map_err(|_| corrupt("catalog_mapping"))?;
    if !valid {
        return Err(corrupt("catalog_mapping"));
    }
    Ok(())
}

/// 在原连接读取实际目录形状并作固定owner相对规范化；不读取oracle、不写业务行、不授予权限。
pub async fn capture(client: &Client) -> Result<Value, CustomModelCatalogSchemaError> {
    storage_on(client).await?;
    canonical_on(client).await
}
/// 核原完整已知prefix、独立真实oracle与完整映射；不返回权限、Host或库存Ready。
pub async fn verify(client: &Client) -> Result<(), CustomModelCatalogSchemaError> {
    storage_on(client).await?;
    native::validate_known_prefix(client, REGISTERED_NATIVE_FLOOR)
        .await
        .map_err(|error| match error {
            InfraError::Connect { .. } | InfraError::Query { .. } => {
                CustomModelCatalogSchemaError::Unavailable
            }
            _ => corrupt("native_prefix"),
        })?;
    compare_registered(&canonical_on(client).await?)?;
    mapping_on(client).await
}
/// 仅原native hook/未来具名原Tx调用；caller必须先在同一Tx完成bounded完整known-prefix。
/// 不调用只接受Client的validator，不另取Pool，不开始第二Tx，不递归apply/repair。
pub(crate) async fn verify_in_transaction(
    tx: &Transaction<'_>,
) -> Result<(), CustomModelCatalogSchemaError> {
    storage_on(tx).await?;
    compare_registered(&canonical_on(tx).await?)?;
    mapping_on(tx).await
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
            &format!("SELECT coalesce(octet_length(custom_model_catalog_raw),0)::bigint FROM ({CAPTURE_SQL}) observed"),
            &[&REGISTERED_NATIVE_FLOOR],
        )
        .await
        .map_err(|source| InfraError::query("measure custom model catalog schema observation", source))?;
    let payload: i64 = row.try_get(0).map_err(|source| {
        super::RowDecodeError::column("(custom_model_catalog_schema)", "bytes", source)
    })?;
    u64::try_from(payload).map_err(|_| {
        InfraError::repository_invariant("custom_model_catalog_schema_observation_bytes")
    })
}
