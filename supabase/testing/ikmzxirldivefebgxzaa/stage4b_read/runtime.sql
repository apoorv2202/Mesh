\ir guard.sql
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='60s';
LOCK TABLE public.organizations,public.profiles,public.organization_members,public.security_assets,
 public.security_events,public.security_findings,public.security_incidents,public.incident_events,public.security_risk_scores IN ACCESS EXCLUSIVE MODE;
\set metadata_phase preflight
\ir ../stage4/capture_comparison.sql
\ir ../stage4/assert_comparison.sql
\ir ../stage4/assert_schema.sql
SELECT set_config('mesh_stage4bread.before', :'comparison_snapshot',true) AS ignored \gset
SELECT set_config('mesh_stage4bread.user_a', :'user_a',true) AS ignored \gset
SELECT set_config('mesh_stage4bread.user_b', :'user_b',true) AS ignored \gset
\ir assert_clean.sql
SAVEPOINT read_fixture;
\ir fixture.sql
SELECT set_config('mesh_stage4bread.grant_approved','on',true) AS ignored \gset
\ir grant_select_proposal.sql
\set metadata_phase granted
\ir ../stage4/capture_comparison.sql
SELECT set_config('mesh_stage4bread.granted', :'comparison_snapshot',true) AS ignored \gset
\ir assert_delta.sql
\ir ../stage4/assert_schema.sql
\ir boundary_reads.sql
\ir select_tests.sql
-- No authenticated mutation is ever attempted; fixture membership changes are admin-only.
\set metadata_phase tested
\ir ../stage4/capture_comparison.sql
SELECT set_config('mesh_stage4bread.granted', :'comparison_snapshot',true) AS ignored \gset
\ir assert_delta.sql
ROLLBACK TO SAVEPOINT read_fixture;
\ir assert_clean.sql
\set metadata_phase restored
\ir ../stage4/capture_comparison.sql
\ir ../stage4/assert_comparison.sql
\ir ../stage4/assert_schema.sql
SELECT set_config('mesh_stage4bread.restored', :'comparison_snapshot',true) AS ignored \gset
DO $restore$ BEGIN
 IF current_setting('mesh_stage4bread.before')::jsonb IS DISTINCT FROM current_setting('mesh_stage4bread.restored')::jsonb THEN
 RAISE EXCEPTION 'Original metadata/permissions not exactly restored'; END IF;
END $restore$;
SELECT jsonb_build_object('test','stage4b_read_runtime','passed',true,'fixture_removed',true,
 'grant_rolled_back',true,'metadata_restored',true,'read_assertions',590,'cases',14,
 'authentication_mode','TRUSTED_SQL_ROLE_SIMULATION','real_jwt_verified',false) AS result;
ROLLBACK;
SELECT 'STAGE4B_READ_ROLLBACK_ACKNOWLEDGED';
