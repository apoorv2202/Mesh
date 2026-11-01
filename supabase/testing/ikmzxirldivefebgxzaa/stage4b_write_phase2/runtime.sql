\set ON_ERROR_STOP on
\ir guard.sql
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='90s';
SET LOCAL timezone='UTC';
LOCK TABLE public.organizations,public.profiles,public.organization_members,public.audit_logs,
 public.security_assets,public.security_events,public.security_findings,public.security_incidents,
 public.incident_events,public.security_risk_scores IN ACCESS EXCLUSIVE MODE;
\set metadata_phase before
\ir ../stage4/capture_comparison.sql
\ir ../stage4/assert_comparison.sql
SELECT set_config('mesh_write.before',:'comparison_snapshot',true) AS ignored \gset
\ir capture_columns.sql
SELECT set_config('mesh_write.columns_before',:'write_columns',true) AS ignored \gset
\ir capture_acl.sql
SELECT set_config('mesh_write.acl_before',:'write_acl',true) AS ignored \gset
SELECT jsonb_build_object('record_type','acl_baseline','md5',md5(:'write_acl')) AS diagnostic;
\ir collisions.sql
SAVEPOINT write_scope;
SELECT set_config('mesh_review.test_ref','ikmzxirldivefebgxzaa',true) AS ignored \gset
SELECT set_config('mesh_review.audit_hardening_approved','on',true) AS ignored \gset
SELECT set_config('mesh_review.reference_integrity_approved','on',true) AS ignored \gset
SELECT set_config('mesh_review.assignment_lifecycle_approved','on',true) AS ignored \gset
SELECT set_config('mesh_review.writer_approved','on',true) AS ignored \gset
SELECT set_config('mesh_review.triage_approved','on',true) AS ignored \gset
SELECT set_config('mesh_review.status_transitions_approved','on',true) AS ignored \gset
\ir ../../../proposals/stage4b_write_phase2/01_audit_permissions.body.psql
\ir ../../../proposals/stage4b_write_phase2/02_reference_integrity.body.psql
\ir ../../../proposals/stage4b_write_phase2/03_machine_writer.body.psql
\ir ../../../proposals/stage4b_write_phase2/04_human_triage.body.psql
\set metadata_phase installed
\ir ../stage4/capture_comparison.sql
SELECT set_config('mesh_write.after',:'comparison_snapshot',true) AS ignored \gset
\ir assert_delta.sql
-- Reuse the unchanged, pinned synthetic application fixture, not managed Auth rows.
\ir ../stage4b_read/fixture.sql
\ir human_tests.sql
\set metadata_phase after_tests
\ir ../stage4/capture_comparison.sql
SELECT set_config('mesh_write.after',:'comparison_snapshot',true) AS ignored \gset
\ir assert_delta.sql
ROLLBACK TO SAVEPOINT write_scope;
\ir collisions.sql
\set metadata_phase restored
\ir ../stage4/capture_comparison.sql
\ir ../stage4/assert_comparison.sql
\ir capture_columns.sql
SELECT :'write_columns'::jsonb=current_setting('mesh_write.columns_before')::jsonb AS columns_restored \gset
\if :columns_restored
\else
DO $fail$ BEGIN RAISE EXCEPTION 'Public column definitions/ACLs not restored'; END $fail$;
\endif
\ir capture_acl.sql
SELECT :'write_acl'::jsonb=current_setting('mesh_write.acl_before')::jsonb AS acl_restored \gset
\if :acl_restored
\else
DO $fail$ BEGIN RAISE EXCEPTION 'Exact ACL baseline not restored'; END $fail$;
\endif
SELECT :'comparison_snapshot'::jsonb=current_setting('mesh_write.before')::jsonb AS exactly_restored \gset
\if :exactly_restored
\else
DO $fail$ BEGIN RAISE EXCEPTION 'Exact pre-attempt metadata not restored'; END $fail$;
\endif
ROLLBACK;
SELECT 'STAGE4B_WRITE_ROLLBACK_ACKNOWLEDGED';
SELECT jsonb_build_object('record_type','stage4b_write_result','passed',true,
 'scope','ROLLBACK_DDL_AND_HUMAN_SQL_ROLE_ONLY','machine_login_verified',false,
 'real_jwt_verified',false,'metadata_restored',true,'fixtures_absent',true);
