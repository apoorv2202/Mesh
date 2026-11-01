"""Offline preparation; never connects, runs SQL, or alters trusted artifacts."""
from pathlib import Path
import hashlib
import json

ROOT=Path(__file__).resolve().parent
PROJECT=ROOT.parent
stage4=PROJECT/'stage4'
EXPECTED='90a71db3b16ed177b3455f61a59343b2'
pins=json.loads((stage4/'pins.json').read_text())
for name,digest in pins['files'].items():
    assert hashlib.sha256((stage4/name).read_bytes()).hexdigest()==digest,name
baseline=(PROJECT/'stage3/evidence/verify_no_dml.txt').read_text(encoding='utf-8-sig').strip()
assert hashlib.md5(baseline.encode('utf-8')).hexdigest()==EXPECTED
source=(PROJECT/'stage3/snapshot.sql').read_text()
assert source.endswith('\\gset\n')
exact_query=source[:-len('\\gset\n')]
collision=(stage4/'preflight_collisions_read_only.sql').read_text()
# Reuse the exact fixed IDs and numbers in the standalone read-only collision query.
# No Auth-table access needed for fixture cleanup diagnosis.
checks=collision[collision.index('WITH users('):collision.index('), auth_checks AS (')]+')\n'
fixture_query=checks+"SELECT jsonb_build_object('counts', (SELECT jsonb_agg(to_jsonb(c) ORDER BY check_name) FROM checks c), 'fixtures_absent', (SELECT bool_and(collision_count=0) FROM checks)) AS fixture_status\n"
sql="""-- Independent SELECT-only TEST diagnostic. NO runtime, fixtures or corrections.
-- Verify Dashboard URL contains TEST ikmzxirldivefebgxzaa before execution.
-- Use SQL Editor role postgres. Never run in production khweikfvsnervfuswhon.
-- snapshot_capture contains the ORIGINAL query, without its psql-only \\gset.
WITH snapshot_capture AS MATERIALIZED (
"""+exact_query+"""), fixture_capture AS (
"""+fixture_query+"""), columns_capture AS (
 SELECT jsonb_agg(jsonb_build_object('table_name',c.relname,'column_name',a.attname,
 'ordinal_position',a.attnum,'postgres_type',format_type(a.atttypid,a.atttypmod),
 'nullable',NOT a.attnotnull,'identity_kind',a.attidentity,
 'default_or_generation_expression',pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attnum) AS columns
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 JOIN pg_attribute a ON a.attrelid=c.oid
 LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 WHERE n.nspname='public' AND c.relname IN
 ('security_events','security_findings','security_incidents','incident_events','security_risk_scores')
 AND a.attnum>0 AND NOT a.attisdropped
), labels_capture AS (
 SELECT jsonb_build_object(
 'relations',(SELECT jsonb_object_agg(c.oid::text,n.nspname||'.'||c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace),
 'functions',(SELECT jsonb_object_agg(p.oid::text,n.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')') FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace)
 ) AS labels
)
SELECT jsonb_build_object(
 'diagnostic_version',1,
 'client_asserted_test_ref','ikmzxirldivefebgxzaa',
 'project_identity_independently_verified',false,
 'captured_at',statement_timestamp(),
 'expected_baseline_md5','"""+EXPECTED+"""',
 'actual_snapshot_md5',md5(s.snapshot::text),
 'hash_matches_expected',md5(s.snapshot::text)='"""+EXPECTED+"""',
 'snapshot_text',s.snapshot::text,
 'operator_checks',jsonb_build_object('current_user',current_user,'session_user',session_user,
 'database',current_database(),'postgres_role_selected',current_user='postgres',
 'operator_bypassrls',(SELECT rolbypassrls FROM pg_roles WHERE rolname=current_user)),
 'session_settings',(SELECT jsonb_object_agg(name,setting) FROM pg_settings WHERE name IN
 ('server_version','server_version_num','server_encoding','client_encoding','search_path','DateStyle',
 'IntervalStyle','TimeZone','extra_float_digits','bytea_output','standard_conforming_strings',
 'backslash_quote','escape_string_warning','quote_all_identifiers','row_security','role',
 'session_replication_role','default_transaction_isolation','transaction_isolation',
 'default_transaction_read_only','transaction_read_only','lc_collate','lc_ctype')),
 'effective_schemas',current_schemas(true),
 'current_schema',current_schema(),
 'target_columns',(SELECT columns FROM columns_capture),
 'object_labels',(SELECT labels FROM labels_capture),
 'fixture_status',(SELECT fixture_status FROM fixture_capture)
) AS metadata_diagnostic
FROM snapshot_capture s;
"""
out=ROOT/'capture_metadata_read_only.sql'
out.write_text(sql,encoding='utf-8',newline='\n')
assert sql[sql.index(exact_query):sql.index(exact_query)+len(exact_query)]==exact_query
assert '\\gset' not in sql.split('WITH snapshot_capture',1)[1]
manifest={'expected_baseline_md5':EXPECTED,'query_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),
 'source_snapshot_sha256':hashlib.sha256((PROJECT/'stage3/snapshot.sql').read_bytes()).hexdigest(),
 'baseline_sha256':hashlib.sha256((PROJECT/'stage3/evidence/verify_no_dml.txt').read_bytes()).hexdigest(),
 'failed_runtime_receipt_sha256':hashlib.sha256((stage4/'evidence/runtime.receipt.json').read_bytes()).hexdigest(),
 'failed_runtime_output_sha256':hashlib.sha256((stage4/'evidence/runtime.txt').read_bytes()).hexdigest()}
(ROOT/'diagnostic_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n')
print('Prepared standalone SELECT-only diagnostic. Exact original snapshot SELECT retained. No SQL executed.')
