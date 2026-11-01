\set ON_ERROR_STOP on
\ir ../target_guard.psql
\if :{?stage3_approved}
\else
\echo Stage 3 requires explicit execution approval through its launcher.
\quit 3
\endif
SELECT :'stage3_approved'='ikmzxirldivefebgxzaa' AS stage3_ok \gset
\if :stage3_ok
\else
\quit 3
\endif
DO $guard$
BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres' OR current_database()<>'postgres'
 OR current_setting('server_version_num')::int / 10000<>17 THEN
  RAISE EXCEPTION 'Unexpected TEST operator/database/server';
 END IF;
 IF (SELECT count(*) FROM pg_roles WHERE rolname IN ('anon','authenticated','authenticator','service_role'))<>4 THEN
  RAISE EXCEPTION 'Missing expected role';
 END IF;
 IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN ('security_events','security_findings','security_incidents','incident_events','security_risk_scores')
 AND c.relkind='r' AND c.relrowsecurity AND NOT c.relforcerowsecurity AND pg_get_userbyid(c.relowner)='postgres')<>5 THEN
  RAISE EXCEPTION 'Target inventory/ownership/RLS drift';
 END IF;
END $guard$;
