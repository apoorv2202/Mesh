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
SELECT set_config('mesh_review.security_approved','on',true) AS ignored \gset
\ir migration01_body.sql
\ir snapshot.sql
SELECT set_config('mesh_stage3.after', :'snapshot', true) AS ignored \gset
\ir assert_hardened.sql
SELECT jsonb_build_object('test','apply_precommit','before',current_setting('mesh_stage3.before')::jsonb,'after',current_setting('mesh_stage3.after')::jsonb) AS result;
COMMIT;
SELECT 'MIGRATION01_COMMIT_ACKNOWLEDGED';
