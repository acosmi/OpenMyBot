//! Exact additive restore catalog observation; this module mints no authority.
//!
//! The original migration owner must separately authenticate the exact native
//! prefix and its complete old schema before applying the registered increment.
//! These functions neither apply SQL nor obtain a pool, commit, repair, confirm a
//! principal, or interpret a PG seal as an external restore/Current fact.

use super::{InfraError, RowDecodeError};
use openbot_domain::audit::hash::Sha256Digest;
use serde_json::Value;
use tokio_postgres::{Client, GenericClient, Transaction};

const ORACLE: &str = include_str!("../../../../fixtures/db/restore-reconfirmation-0053.json");
const MIGRATION_SQL: &str = include_str!("../../sql/native_0053.sql");
const MAX_CATALOG_BYTES: usize = 1_048_576;

// This is a fixed catalog query, not a caller-supplied SQL or relation selector.
// Include unknown restore-prefixed relations/functions and every trigger that
// calls the named guards, so extras are rejected instead of filtered away.
const CATALOG_SQL: &str = r####"WITH
original_owner AS (
 SELECT c.relowner AS owner FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname='threads' AND c.relkind='r'
), relations AS (
 SELECT c.* FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='openbot_internal' AND pg_catalog.left(c.relname,8)='restore_'
  AND c.relkind NOT IN('i','I','S','t')
), functions AS (
 SELECT p.* FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='openbot_internal' AND pg_catalog.left(p.proname,10)='restore53_'
), constraints AS (
 SELECT c.* FROM pg_catalog.pg_constraint c WHERE c.conrelid IN(SELECT oid FROM relations)
  OR c.confrelid IN(SELECT oid FROM relations)
), indexes AS (
 SELECT i.* FROM pg_catalog.pg_index i WHERE i.indrelid IN(SELECT oid FROM relations)
), triggers AS (
 SELECT t.* FROM pg_catalog.pg_trigger t WHERE t.tgrelid IN(SELECT oid FROM relations)
  OR t.tgfoid IN(SELECT oid FROM functions)
), catalog AS (
 SELECT pg_catalog.jsonb_build_object(
  'tables',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
   'name',c.relname,
   'columns',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
    a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,
    CASE WHEN a.attcollation=0 THEN NULL ELSE cn.nspname||'.'||co.collname END,
    pg_catalog.pg_get_expr(d.adbin,d.adrelid,false)) ORDER BY a.attnum),'[]'::jsonb)
    FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type ty ON ty.oid=a.atttypid
    LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
    LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace
    LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
    WHERE a.attrelid=c.oid AND a.attnum>0),
   'constraints',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
    x.conname,x.contype::text,pg_catalog.pg_get_constraintdef(x.oid,false))
    ORDER BY x.conname COLLATE pg_catalog."C"),'[]'::jsonb)
    FROM constraints x WHERE x.conrelid=c.oid),
   'indexes',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.pg_get_indexdef(i.indexrelid,0,false)
    ORDER BY ic.relname COLLATE pg_catalog."C"),'[]'::jsonb)
    FROM indexes i JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid WHERE i.indrelid=c.oid),
   'triggers',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
    t.tgname,t.tgtype,pn.nspname,p.proname) ORDER BY t.tgname COLLATE pg_catalog."C"),'[]'::jsonb)
    FROM triggers t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
    JOIN pg_catalog.pg_namespace pn ON pn.oid=p.pronamespace
    WHERE t.tgrelid=c.oid AND NOT t.tgisinternal)
  ) ORDER BY c.relname COLLATE pg_catalog."C"),'[]'::jsonb) FROM relations c),
  'functions',(SELECT coalesce(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
   p.proname,pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex'))
   ORDER BY p.proname COLLATE pg_catalog."C"),'[]'::jsonb) FROM functions p)
 ) AS payload
), raw_checks AS (
 SELECT
  (SELECT pg_catalog.count(*)=1 FROM original_owner) AND
  (SELECT pg_catalog.count(*)=1 FROM pg_catalog.pg_namespace n,original_owner o
   WHERE n.nspname='openbot_internal' AND n.nspowner=o.owner) AND
  pg_catalog.getdatabaseencoding()='UTF8' AND
  pg_catalog.current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND
  (SELECT pg_catalog.count(*)=5 FROM relations) AND
  NOT EXISTS(SELECT 1 FROM relations c,original_owner o WHERE
   c.relowner<>o.owner OR c.relkind<>'r' OR c.relpersistence<>'p' OR
   c.relam<>(SELECT oid FROM pg_catalog.pg_am WHERE amname='heap' AND amtype='t') OR c.relrowsecurity OR c.relforcerowsecurity OR
   c.relispartition OR c.relpartbound IS NOT NULL OR c.reloftype<>0 OR
   c.relrewrite<>0 OR c.reloptions IS NOT NULL OR c.reltablespace<>0 OR
   c.relreplident<>'d' OR c.relispartition OR
   EXISTS(SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid=c.oid) OR
   EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite r WHERE r.ev_class=c.oid) OR
   EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid) OR
   EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a
    WHERE a.grantee<>o.owner OR a.grantor<>o.owner OR a.is_grantable) OR
   (SELECT pg_catalog.count(*) FROM pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))))<>8
  ) AND
  NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a JOIN relations c ON c.oid=a.attrelid
   LEFT JOIN pg_catalog.pg_type ty ON ty.oid=a.atttypid
   LEFT JOIN pg_catalog.pg_namespace tn ON tn.oid=ty.typnamespace
   WHERE a.attnum>0 AND (a.attisdropped OR a.attnum<1 OR a.attstattarget<>-1 OR
    a.atttypmod<>-1 OR a.attndims<>0 OR NOT a.attislocal OR a.attinhcount<>0 OR
    a.attidentity<>'' OR a.attgenerated<>'' OR a.atthasmissing OR a.attmissingval IS NOT NULL OR
    a.attacl IS NOT NULL OR a.attoptions IS NOT NULL OR a.attfdwoptions IS NOT NULL OR
    a.attcompression<>'' OR a.attstorage<>ty.typstorage OR tn.nspname IS DISTINCT FROM 'pg_catalog' OR
    ty.typtype<>'b' OR ty.typbasetype<>0 OR ty.typowner<>10 OR
    ty.typname NOT IN('uuid','bytea','text','oid','int8','xid8','timestamptz') OR
    (a.atthasdef IS DISTINCT FROM EXISTS(SELECT 1 FROM pg_catalog.pg_attrdef d
     WHERE d.adrelid=a.attrelid AND d.adnum=a.attnum)))) AND
  NOT EXISTS(SELECT 1 FROM constraints c WHERE NOT c.convalidated OR c.condeferrable OR
   c.condeferred OR NOT c.conislocal OR c.coninhcount<>0 OR c.conparentid<>0 OR
   c.contypid<>0 OR c.contype NOT IN('p','u','f','c') OR
   (c.contype='c' AND (c.conbin IS NULL OR c.connoinherit)) OR
   (c.contype<>'c' AND (c.conbin IS NOT NULL OR NOT c.connoinherit)) OR
   (c.contype='f' AND (c.confupdtype<>'r' OR c.confdeltype<>'r' OR c.confmatchtype<>'s' OR
    c.confrelid NOT IN(SELECT oid FROM relations) OR c.confdelsetcols IS NOT NULL))) AND
  NOT EXISTS(SELECT 1 FROM indexes i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
   JOIN pg_catalog.pg_am am ON am.oid=c.relam CROSS JOIN original_owner o WHERE
   NOT i.indisvalid OR NOT i.indisready OR NOT i.indislive OR NOT i.indimmediate OR
   i.indisclustered OR i.indisreplident OR i.indcheckxmin OR i.indnullsnotdistinct OR
   i.indisexclusion OR i.indexprs IS NOT NULL OR i.indpred IS NOT NULL OR
   i.indnkeyatts<>i.indnatts OR c.relowner<>o.owner OR c.relkind<>'i' OR
   am.amname<>'btree' OR am.amtype<>'i' OR c.reloptions IS NOT NULL OR c.reltablespace<>0 OR
   EXISTS(SELECT 1 FROM pg_catalog.unnest(i.indclass::oid[]) x(oid)
    LEFT JOIN pg_catalog.pg_opclass cl ON cl.oid=x.oid
    LEFT JOIN pg_catalog.pg_namespace n ON n.oid=cl.opcnamespace WHERE
    n.nspname IS DISTINCT FROM 'pg_catalog' OR cl.opcowner<>10 OR NOT cl.opcdefault OR
    cl.opcname NOT IN('uuid_ops','bytea_ops','int8_ops','text_ops','xid8_ops'))) AND
  (SELECT pg_catalog.count(*)=2 FROM functions) AND
  NOT EXISTS(SELECT 1 FROM functions p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
   CROSS JOIN original_owner o WHERE p.proowner<>o.owner OR l.lanname<>'plpgsql' OR
    NOT l.lanispl OR NOT l.lanpltrusted OR p.prokind<>'f' OR p.prosecdef OR p.proleakproof OR
    p.proisstrict OR p.proretset OR p.provolatile<>'v' OR p.proparallel<>'u' OR
    p.prorettype<>'pg_catalog.trigger'::regtype OR p.pronargs<>0 OR p.pronargdefaults<>0 OR
    p.provariadic<>0 OR p.prosupport<>0 OR p.proallargtypes IS NOT NULL OR p.proargmodes IS NOT NULL OR
    p.proargnames IS NOT NULL OR p.proargdefaults IS NOT NULL OR p.protrftypes IS NOT NULL OR
    p.probin IS NOT NULL OR p.prosqlbody IS NOT NULL OR p.procost<>100 OR p.prorows<>0 OR
    p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']::text[] OR
    (SELECT pg_catalog.count(*) FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))))<>1 OR
    EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
     WHERE a.grantee<>o.owner OR a.grantor<>o.owner OR a.is_grantable OR a.privilege_type<>'EXECUTE')) AND
  NOT EXISTS(SELECT 1 FROM triggers t WHERE t.tgenabled<>'O' OR t.tgdeferrable OR
   t.tginitdeferred OR t.tgqual IS NOT NULL OR t.tgnargs<>0 OR pg_catalog.octet_length(t.tgargs)<>0 OR
   t.tgattr::text<>'' OR t.tgparentid<>0 OR t.tgoldtable IS NOT NULL OR t.tgnewtable IS NOT NULL OR
   t.tgrelid NOT IN(SELECT oid FROM relations) OR
   (NOT t.tgisinternal AND (t.tgconstraint<>0 OR t.tgconstrrelid<>0 OR t.tgconstrindid<>0 OR
     t.tgfoid NOT IN(SELECT oid FROM functions) OR t.tgtype NOT IN(7,27,34)))) AND
  -- Every nondeferrable RESTRICT FK has exactly its four original builtin RI
  -- triggers, on the actual source/target OIDs and the actual constraint OID.
  NOT EXISTS(SELECT 1 FROM constraints c WHERE c.contype='f' AND (
   (SELECT pg_catalog.count(*) FROM triggers t WHERE t.tgisinternal AND t.tgconstraint=c.oid)<>4 OR
   EXISTS(SELECT 1 FROM triggers t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
    JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE t.tgisinternal AND t.tgconstraint=c.oid AND
    NOT (n.nspname='pg_catalog' AND (
     (p.proname='RI_FKey_check_ins' AND t.tgtype=5 AND t.tgrelid=c.conrelid AND t.tgconstrrelid=c.confrelid) OR
     (p.proname='RI_FKey_check_upd' AND t.tgtype=17 AND t.tgrelid=c.conrelid AND t.tgconstrrelid=c.confrelid) OR
     (p.proname='RI_FKey_restrict_del' AND t.tgtype=9 AND t.tgrelid=c.confrelid AND t.tgconstrrelid=c.conrelid) OR
     (p.proname='RI_FKey_restrict_upd' AND t.tgtype=17 AND t.tgrelid=c.confrelid AND t.tgconstrrelid=c.conrelid)))))) AND
  NOT EXISTS(SELECT 1 FROM triggers t WHERE t.tgisinternal AND t.tgconstraint NOT IN(
   SELECT oid FROM constraints WHERE contype='f')) AS valid
)
SELECT CASE WHEN pg_catalog.octet_length(c.payload::text)<=$1::bigint THEN c.payload::text ELSE NULL END AS facts,
 r.valid AS raw_valid FROM catalog c CROSS JOIN raw_checks r
"####;

fn invalid() -> InfraError {
    InfraError::repository_invariant("restore_reconfirmation_schema_invalid")
}

fn expected() -> Result<Value, InfraError> {
    let value: Value = serde_json::from_str(ORACLE).map_err(|_| invalid())?;
    let fields = value.as_object().ok_or_else(invalid)?;
    if fields.len() != 4
        || value["format"] != "restore-reconfirmation-oracle-v1"
        || value["nativeVersion"] != 53
        || value["migrationSha256"] != Sha256Digest::of(MIGRATION_SQL.as_bytes()).to_hex()
        || value["schema"].as_object().is_none_or(|object| object.len() != 2)
        || value["schema"]["tables"].as_array().is_none_or(|rows| rows.len() != 5)
        || value["schema"]["functions"].as_array().is_none_or(|rows| rows.len() != 2)
    {
        return Err(invalid());
    }
    Ok(value)
}

async fn verify_additive_on<C: GenericClient + Sync>(client: &C) -> Result<(), InfraError> {
    let expected = expected()?;
    let limit = i64::try_from(MAX_CATALOG_BYTES).map_err(|_| invalid())?;
    let row = client
        .query_one(CATALOG_SQL, &[&limit])
        .await
        .map_err(|source| InfraError::query("只读核验恢复重确认 catalog", source))?;
    let raw_valid: bool = row.try_get("raw_valid").map_err(|source| {
        RowDecodeError::column("(restore_reconfirmation_schema)", "raw_valid", source)
    })?;
    let payload: Option<String> = row.try_get("facts").map_err(|source| {
        RowDecodeError::column("(restore_reconfirmation_schema)", "facts", source)
    })?;
    let payload = payload.filter(|text| text.len() <= MAX_CATALOG_BYTES).ok_or_else(invalid)?;
    let actual: Value = serde_json::from_str(&payload).map_err(|_| invalid())?;
    if !raw_valid || actual != expected["schema"] {
        return Err(invalid());
    }
    Ok(())
}

/// New catalog only, after the caller's exact prefix/full legacy schema proof.
/// No ledger/version count can substitute for these actual catalog facts.
pub(crate) async fn verify_schema(client: &Client) -> Result<(), InfraError> {
    verify_additive_on(client).await
}

/// Same-transaction additive observation, including the unchanged history graph.
/// The native registry's complete old public/origin/catalog validation remains a
/// separate prerequisite; this DATA helper never mints candidate authority.
pub(crate) async fn verify_in_transaction(tx: &Transaction<'_>) -> Result<(), InfraError> {
    super::thread_origin_schema::verify_in_transaction(tx).await?;
    super::thread_history_writer_schema::verify_in_transaction(tx).await?;
    verify_additive_on(tx).await
}
