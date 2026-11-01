-- Explicit ACL tuples, not effective-table privilege approximations. Column
-- ACLs are captured even when no table SELECT is granted. No application rows.
WITH rights AS (
 SELECT CASE WHEN c.relkind='S' THEN 'sequence' ELSE 'table' END kind,
 n.nspname||'.'||c.relname object_name,''::text column_name,x.*
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner))) x
 WHERE n.nspname IN ('public','vader_private') AND c.relkind IN ('r','p','v','m','f','S')
 UNION ALL
 SELECT 'column',n.nspname||'.'||c.relname,a.attname::text,x.*
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
 CROSS JOIN LATERAL aclexplode(a.attacl) x
 WHERE n.nspname IN ('public','vader_private') AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL
 SELECT 'schema',n.nspname,'',x.* FROM pg_namespace n
 CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) x
 WHERE n.nspname IN ('public','extensions','vader_private','vader_api','vader_user_api')
 UNION ALL
 SELECT 'function',n.nspname||'.'||p.proname||'('||oidvectortypes(p.proargtypes)||')','',x.*
 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) x
 WHERE n.nspname IN ('vader_private','vader_api','vader_user_api')
), tuples AS (
 SELECT jsonb_build_array(kind,object_name,column_name,pg_get_userbyid(grantor),
 CASE WHEN grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(grantee) END,privilege_type,is_grantable) value FROM rights
)
SELECT coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C"),'[]'::jsonb)::text AS write_acl FROM tuples
\gset
