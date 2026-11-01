-- Independent SELECT-only TEST diagnostic. NO runtime, fixtures or corrections.
-- Verify Dashboard URL contains TEST ikmzxirldivefebgxzaa before execution.
-- Use SQL Editor role postgres. Never run in production khweikfvsnervfuswhon.
-- snapshot_capture contains the ORIGINAL query, without its psql-only \gset.
WITH snapshot_capture AS MATERIALIZED (
-- Metadata only. Called inside the driver's transaction. Produces one JSON value.
WITH targets AS (
 SELECT c.oid,c.relname,c.relowner,c.relacl,c.relrowsecurity,c.relforcerowsecurity
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind='r' AND c.relname IN
 ('security_events','security_findings','security_incidents','incident_events','security_risk_scores')
), roles AS (
 SELECT oid,rolname FROM pg_roles WHERE rolname IN ('anon','authenticated','authenticator','service_role','postgres')
), effective AS (
 SELECT r.rolname,t.relname,p.privilege,
 has_table_privilege(r.oid,t.oid,p.privilege) AS allowed
 FROM targets t CROSS JOIN roles r CROSS JOIN unnest(
 ARRAY['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']) p(privilege)
)
SELECT jsonb_build_object(
 'effective',(SELECT jsonb_agg(to_jsonb(e) ORDER BY rolname,relname,privilege) FROM effective e),
 'target_acls',(SELECT jsonb_agg(jsonb_build_object('table',relname,'owner',relowner,'acl',relacl) ORDER BY relname) FROM targets),
 'column_acls',(SELECT jsonb_agg(jsonb_build_object('table',t.relname,'column',a.attname,'acl',a.attacl) ORDER BY t.relname,a.attnum)
 FROM targets t JOIN pg_attribute a ON a.attrelid=t.oid WHERE a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL),
 'native',jsonb_build_object(
 'roles',(SELECT jsonb_agg(jsonb_build_object('oid',oid,'name',rolname,'super',rolsuper,'inherit',rolinherit,
 'login',rolcanlogin,'bypass',rolbypassrls,'createrole',rolcreaterole,'createdb',rolcreatedb,'replication',rolreplication) ORDER BY oid) FROM pg_roles),
 'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY roleid,member,grantor) FROM pg_auth_members m),
 'schemas',(SELECT jsonb_agg(jsonb_build_object('oid',oid,'owner',nspowner,'acl',nspacl) ORDER BY oid) FROM pg_namespace),
 'functions',(SELECT jsonb_agg(jsonb_build_object('oid',p.oid,'owner',proowner,'acl',proacl,'settings_md5',md5(proconfig::text),
 'definition_md5',CASE WHEN prokind IN ('f','p') THEN md5(pg_get_functiondef(p.oid)) ELSE NULL END) ORDER BY p.oid) FROM pg_proc p),
 'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY oid) FROM pg_event_trigger e),
 'defaults',(SELECT jsonb_agg(to_jsonb(d) ORDER BY oid) FROM pg_default_acl d),
 'relations',(SELECT jsonb_agg(jsonb_build_object('oid',c.oid,'owner',relowner,'acl',relacl,'rls',relrowsecurity,'forced',relforcerowsecurity) ORDER BY c.oid)
 FROM pg_class c WHERE c.oid NOT IN (SELECT oid FROM targets)),
 'sequences',(SELECT jsonb_agg(to_jsonb(s) ORDER BY seqrelid) FROM pg_sequence s),
 'policies',(SELECT jsonb_agg(to_jsonb(p) ORDER BY oid) FROM pg_policy p),
 'constraints',(SELECT jsonb_agg(to_jsonb(c) ORDER BY oid) FROM pg_constraint c),
 'indexes',(SELECT jsonb_agg(to_jsonb(i) ORDER BY indexrelid) FROM pg_index i),
 'triggers',(SELECT jsonb_agg(jsonb_build_object('oid',oid,'row_md5',md5(to_jsonb(t)::text)) ORDER BY oid) FROM pg_trigger t),
 'target_rls',(SELECT jsonb_agg(jsonb_build_object('table',relname,'owner',relowner,'enabled',relrowsecurity,'forced',relforcerowsecurity) ORDER BY relname) FROM targets)
 )) AS snapshot
), fixture_capture AS (
WITH users(company,user_id) AS (
 VALUES ('A','72a7251d-b69b-4149-8a7f-a082e4b920e9'::uuid),
        ('B','8c9907c9-4acf-480b-aaee-dcd08f3cbc6a'::uuid)
), orgs(id) AS (
 VALUES ('44444444-4444-4444-8444-000000000001'::uuid),
        ('44444444-4444-4444-8444-000000000002'::uuid)
), checks(check_name,collision_count) AS (
 SELECT 'public_profiles',count(*) FROM public.profiles WHERE id IN (SELECT user_id FROM users)
 UNION ALL SELECT 'user_memberships_any_organization',count(*) FROM public.organization_members WHERE user_id IN (SELECT user_id FROM users)
 UNION ALL SELECT 'organizations',count(*) FROM public.organizations WHERE id IN (SELECT id FROM orgs)
 UNION ALL SELECT 'memberships_in_reserved_orgs',count(*) FROM public.organization_members WHERE organization_id IN (SELECT id FROM orgs)
 UNION ALL SELECT 'assets_ids_or_reserved_orgs',count(*) FROM public.security_assets
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('44444444-4444-4444-8444-000000000010','44444444-4444-4444-8444-000000000011')
 UNION ALL SELECT 'events_ids_or_reserved_orgs',count(*) FROM public.security_events
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('44444444-4444-4444-8444-000000000012','44444444-4444-4444-8444-000000000013',
  '44444444-4444-4444-8444-000000000080')
 UNION ALL SELECT 'findings_ids_or_reserved_orgs',count(*) FROM public.security_findings
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('44444444-4444-4444-8444-000000000014','44444444-4444-4444-8444-000000000015',
  '44444444-4444-4444-8444-000000000081','44444444-4444-4444-8444-000000000082')
 UNION ALL SELECT 'incidents_ids_numbers_or_reserved_orgs',count(*) FROM public.security_incidents
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('44444444-4444-4444-8444-000000000016','44444444-4444-4444-8444-000000000017')
 OR incident_number IN (-44001,-44002,-44999)
 UNION ALL SELECT 'incident_links_ids_or_reserved_orgs',count(*) FROM public.incident_events
 WHERE organization_id IN (SELECT id FROM orgs)
 OR incident_id IN ('44444444-4444-4444-8444-000000000016','44444444-4444-4444-8444-000000000017')
 OR event_id IN ('44444444-4444-4444-8444-000000000012','44444444-4444-4444-8444-000000000013')
 UNION ALL SELECT 'risk_ids_or_reserved_orgs',count(*) FROM public.security_risk_scores
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('44444444-4444-4444-8444-000000000020','44444444-4444-4444-8444-000000000021')
)
SELECT jsonb_build_object('counts', (SELECT jsonb_agg(to_jsonb(c) ORDER BY check_name) FROM checks c), 'fixtures_absent', (SELECT bool_and(collision_count=0) FROM checks)) AS fixture_status
), columns_capture AS (
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
 'expected_baseline_md5','90a71db3b16ed177b3455f61a59343b2',
 'actual_snapshot_md5',md5(s.snapshot::text),
 'hash_matches_expected',md5(s.snapshot::text)='90a71db3b16ed177b3455f61a59343b2',
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
