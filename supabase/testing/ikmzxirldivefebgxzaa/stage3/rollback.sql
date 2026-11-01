\ir guard.sql
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='60s';
LOCK TABLE public.security_events,public.security_findings,public.security_incidents,
 public.incident_events,public.security_risk_scores IN ACCESS EXCLUSIVE MODE;
\ir snapshot.sql
SELECT md5(:'snapshot')=:'expected_baseline_md5' AS baseline_unchanged \gset
\if :baseline_unchanged
\else
\echo Baseline drift; STOP before migration.
\quit 3
\endif
SELECT set_config('mesh_stage3.before', :'snapshot', true) AS ignored \gset
\ir assert_baseline.sql
\ir dml_probes.sql
SELECT set_config('mesh_review.security_approved','on',true) AS ignored \gset
SAVEPOINT before_migration;
\ir migration01_body.sql
\ir snapshot.sql
SELECT set_config('mesh_stage3.after', :'snapshot', true) AS ignored \gset
\ir assert_hardened.sql
\ir dml_probes.sql
-- Only this exact intentional exception may be tolerated.
\set ON_ERROR_STOP off
DO $abort$ BEGIN RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='VADER_STAGE3_INTENTIONAL_ABORT'; END $abort$;
\set intentional_state :SQLSTATE
\set ON_ERROR_STOP on
ROLLBACK TO SAVEPOINT before_migration;
SELECT :'intentional_state'='P0001' AS expected_abort \gset
\if :expected_abort
\else
\quit 3
\endif
\ir snapshot.sql
SELECT set_config('mesh_stage3.restored', :'snapshot', true) AS ignored \gset
DO $restore$ BEGIN
 IF current_setting('mesh_stage3.before')::jsonb IS DISTINCT FROM current_setting('mesh_stage3.restored')::jsonb THEN
 RAISE EXCEPTION 'Rollback did not exactly restore baseline'; END IF;
END $restore$;
\ir assert_baseline.sql
SELECT jsonb_build_object('test','rollback','restored',true,'baseline',current_setting('mesh_stage3.before')::jsonb) AS result;
ROLLBACK;
