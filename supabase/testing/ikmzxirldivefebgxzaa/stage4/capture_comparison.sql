-- Revision 2. Retain the exact original raw snapshot and all non-schema checks.
-- The only normalized field is native.schemas, preserving its original row shape/order.
\ir ../stage3/snapshot.sql
\set raw_snapshot :snapshot
WITH recognized_temporary AS (
 SELECT n.oid,n.nspname,n.nspowner,n.nspacl
 FROM pg_namespace n
 WHERE n.nspname ~ '^pg_(temp|toast_temp)_[0-9]+$'
 AND (
  pg_is_other_temp_schema(n.oid)
  OR n.oid=pg_my_temp_schema()
  OR n.nspname=(SELECT 'pg_toast_temp_'||substring(m.nspname FROM '^pg_temp_([0-9]+)$')
               FROM pg_namespace m WHERE m.oid=pg_my_temp_schema())
 )
), retained AS (
 SELECT coalesce(jsonb_agg(e.value ORDER BY e.ordinality),'[]'::jsonb) AS schemas
 FROM jsonb_array_elements(:'raw_snapshot'::jsonb #> '{native,schemas}') WITH ORDINALITY e(value,ordinality)
 WHERE NOT EXISTS(SELECT 1 FROM recognized_temporary t WHERE t.oid=(e.value->>'oid')::oid)
)
SELECT jsonb_set(:'raw_snapshot'::jsonb,'{native,schemas}',(SELECT schemas FROM retained))::text AS comparison_snapshot,
 coalesce((SELECT jsonb_agg(jsonb_build_object('oid',oid,'name',nspname,'owner',nspowner,'acl',nspacl) ORDER BY oid)
 FROM recognized_temporary WHERE oid IN
 (SELECT (e->>'oid')::oid FROM jsonb_array_elements(:'raw_snapshot'::jsonb #> '{native,schemas}') e)),'[]'::jsonb)::text AS ignored_temp_namespaces
\gset
-- Diagnostics are flushed to --output BEFORE the caller can raise an exception.
SELECT jsonb_build_object('record_type','metadata_check','phase',:'metadata_phase',
 'expected_md5',:'expected_post_md5','raw_md5',md5(:'raw_snapshot'),
 'comparison_md5',md5(:'comparison_snapshot'),
 'matches_expected',md5(:'comparison_snapshot')=:'expected_post_md5',
 'ignored_temporary_namespaces',:'ignored_temp_namespaces'::jsonb,
 'raw_snapshot',:'raw_snapshot'::jsonb,
 'target_columns',(SELECT jsonb_agg(jsonb_build_object('table_name',c.relname,'column_name',a.attname,
 'ordinal_position',a.attnum,'postgres_type',format_type(a.atttypid,a.atttypmod),
 'nullable',NOT a.attnotnull,'identity_kind',a.attidentity,
 'default_or_generation_expression',pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attnum)
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
 LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 WHERE n.nspname='public' AND c.relname IN
 ('security_events','security_findings','security_incidents','incident_events','security_risk_scores')
 AND a.attnum>0 AND NOT a.attisdropped)) AS diagnostic;
