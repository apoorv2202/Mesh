-- Capture every public column, including foundation/audit fields, separately
-- from the historical comparison format. Never alters the trusted baseline.
SELECT coalesce(jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'ordinal',a.attnum,
 'type',format_type(a.atttypid,a.atttypmod),'nullable',NOT a.attnotnull,'identity',a.attidentity,
 'generated',a.attgenerated,'expression',pg_get_expr(d.adbin,d.adrelid),'acl',a.attacl)
 ORDER BY c.relname,a.attnum),'[]'::jsonb)::text AS write_columns
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
WHERE n.nspname='public' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
\gset
