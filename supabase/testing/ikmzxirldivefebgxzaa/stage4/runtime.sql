\ir guard.sql
BEGIN;
SET LOCAL statement_timeout='60s';
SET LOCAL lock_timeout='5s';
LOCK TABLE public.organizations,public.profiles,public.organization_members,public.security_assets,
 public.security_events,public.security_findings,public.security_incidents,public.incident_events,public.security_risk_scores IN ACCESS EXCLUSIVE MODE;
\set metadata_phase preflight
\ir capture_comparison.sql
\ir assert_comparison.sql
\ir assert_schema.sql
SELECT set_config('mesh_stage4.before', :'comparison_snapshot',true) AS ignored \gset
SELECT set_config('mesh_stage4.user_a', :'user_a',true) AS ignored \gset
SELECT set_config('mesh_stage4.user_b', :'user_b',true) AS ignored \gset
DO $users$ BEGIN
 IF current_setting('mesh_stage4.user_a')::uuid=current_setting('mesh_stage4.user_b')::uuid THEN
 RAISE EXCEPTION 'Two different NEW synthetic TEST Auth users required'; END IF;
END $users$;
\ir assert_clean.sql
SAVEPOINT fixture;
\ir fixture.sql
\ir owner_controls.sql
\ir acl_tests.sql
\ir helper_tests.sql
\ir fk_tests.sql
\ir documented_gaps.sql
SELECT current_setting('mesh_stage4.acl_tests') AS acl_probe_count \gset
ROLLBACK TO SAVEPOINT fixture;
\ir assert_clean.sql
\set metadata_phase restored
\ir capture_comparison.sql
\ir assert_comparison.sql
\ir assert_schema.sql
SELECT set_config('mesh_stage4.restored', :'comparison_snapshot',true) AS ignored \gset
DO $restore$ BEGIN
 IF current_setting('mesh_stage4.before')::jsonb IS DISTINCT FROM current_setting('mesh_stage4.restored')::jsonb THEN
 RAISE EXCEPTION 'Metadata/grants/roles/policies changed'; END IF;
END $restore$;
SELECT jsonb_build_object('test','stage4_runtime','passed',true,'acl_probes',:'acl_probe_count'::int,
 'fixture_removed',true,'metadata_restored',true,'rls_row_filtering','BLOCKED_NO_SELECT_GRANT',
 'positive_api_writes','BLOCKED_NO_GRANTS_OR_WRITE_POLICIES',
 'known_gaps',ARRAY['risk_subject_not_tenant_fk','actor_user_not_org_member_fk','assigned_to_not_org_member_fk']) AS result;
ROLLBACK;
SELECT 'STAGE4_ROLLBACK_ACKNOWLEDGED';
