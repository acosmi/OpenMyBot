WITH relations AS (
    SELECT c.* FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='openbot_internal' AND left(c.relname,11)='automation_'
      AND c.relkind NOT IN ('i','I','t')
), original_owner AS (
    SELECT c.relowner FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname='threads' AND c.relkind='r'
), constraints_scope AS (
    SELECT c.* FROM pg_catalog.pg_constraint c
    WHERE c.conrelid IN (SELECT oid FROM relations)
       OR (c.contype='f' AND c.confrelid IN (SELECT oid FROM relations))
)
SELECT pg_catalog.jsonb_build_object(
 'tables', coalesce((SELECT jsonb_agg(jsonb_build_object(
    'name',r.relname,'kind',r.relkind::text,'persistence',r.relpersistence::text,
    'ownerMatchesCore',(r.relowner=(SELECT relowner FROM original_owner)),
    'acl',r.relacl::text,'options',r.reloptions,'partition',r.relispartition,
    'rowSecurity',r.relrowsecurity,'forceRowSecurity',r.relforcerowsecurity,
    'replicaIdentity',r.relreplident::text,'accessMethod',am.amname,
    'columns',coalesce((SELECT jsonb_agg(jsonb_build_object(
        'ordinal',a.attnum,'name',a.attname,'dropped',a.attisdropped,
        'type',pg_catalog.format_type(a.atttypid,a.atttypmod),'notNull',a.attnotnull,
        'dimensions',a.attndims,'identity',a.attidentity::text,'generated',a.attgenerated::text,
        'local',a.attislocal,'inherited',a.attinhcount,'acl',a.attacl::text,
        'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid,false),
        'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE cn.nspname||'.'||co.collname END
    ) ORDER BY a.attnum) FROM pg_catalog.pg_attribute a
      LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
      LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation
      LEFT JOIN pg_catalog.pg_namespace cn ON cn.oid=co.collnamespace
      WHERE a.attrelid=r.oid AND a.attnum>0),'[]'::jsonb),
    'indexes',coalesce((SELECT jsonb_agg(jsonb_build_object(
        'name',ic.relname,'definition',pg_catalog.pg_get_indexdef(i.indexrelid,0,false),
        'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive,
        'unique',i.indisunique,'primary',i.indisprimary,'exclusion',i.indisexclusion,
        'immediate',i.indimmediate,'nullsNotDistinct',i.indnullsnotdistinct,
        'ownerMatchesCore',(ic.relowner=(SELECT relowner FROM original_owner)),
        'options',ic.reloptions,'acl',ic.relacl::text
    ) ORDER BY ic.relname) FROM pg_catalog.pg_index i
      JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid WHERE i.indrelid=r.oid),'[]'::jsonb),
    'triggers',coalesce((SELECT jsonb_agg(pg_catalog.pg_get_triggerdef(t.oid,false) ORDER BY t.tgname)
      FROM pg_catalog.pg_trigger t WHERE t.tgrelid=r.oid AND NOT t.tgisinternal),'[]'::jsonb),
    'policies',coalesce((SELECT jsonb_agg(jsonb_build_object('name',p.polname,
        'command',p.polcmd::text,'permissive',p.polpermissive,
        'using',pg_catalog.pg_get_expr(p.polqual,p.polrelid,false),
        'check',pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid,false)) ORDER BY p.polname)
      FROM pg_catalog.pg_policy p WHERE p.polrelid=r.oid),'[]'::jsonb),
    'rules',coalesce((SELECT jsonb_agg(pg_catalog.pg_get_ruledef(w.oid,false) ORDER BY w.rulename)
      FROM pg_catalog.pg_rewrite w WHERE w.ev_class=r.oid),'[]'::jsonb),
    'inheritance',coalesce((SELECT jsonb_agg(jsonb_build_object(
        'parent',i.inhparent::regclass::text,'child',i.inhrelid::regclass::text,'sequence',i.inhseqno)
        ORDER BY i.inhparent::regclass::text,i.inhrelid::regclass::text,i.inhseqno)
      FROM pg_catalog.pg_inherits i WHERE i.inhparent=r.oid OR i.inhrelid=r.oid),'[]'::jsonb)
 ) ORDER BY r.relname) FROM relations r LEFT JOIN pg_catalog.pg_am am ON am.oid=r.relam),'[]'::jsonb),
 'constraints',coalesce((SELECT jsonb_agg(jsonb_build_object(
    'schema',n.nspname,'table',r.relname,'name',c.conname,'kind',c.contype::text,
    'definition',pg_catalog.pg_get_constraintdef(c.oid,false),
    'deferrable',c.condeferrable,'deferred',c.condeferred,'validated',c.convalidated,
    'local',c.conislocal,'inherited',c.coninhcount,'noInherit',c.connoinherit
 ) ORDER BY n.nspname,r.relname,c.conname) FROM constraints_scope c
   JOIN pg_catalog.pg_class r ON r.oid=c.conrelid
   JOIN pg_catalog.pg_namespace n ON n.oid=r.relnamespace),'[]'::jsonb),
 'functions',coalesce((SELECT jsonb_agg(pg_catalog.pg_get_functiondef(p.oid) ORDER BY p.proname)
   FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname='openbot_internal' AND left(p.proname,11)='automation_'),'[]'::jsonb)
);
