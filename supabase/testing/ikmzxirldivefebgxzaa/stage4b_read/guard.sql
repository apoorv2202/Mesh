\set ON_ERROR_STOP on
\ir ../target_guard.psql
\if :{?stage4bread_approved}
\else
DO $fail$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='STAGE4B_READ_APPROVAL_MISSING'; END $fail$;
\endif
SELECT :'stage4bread_approved'='ikmzxirldivefebgxzaa' AS approved \gset
\if :approved
\else
DO $fail$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='STAGE4B_READ_APPROVAL_REJECTED'; END $fail$;
\endif
DO $guard$ BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres' OR current_database()<>'postgres'
 OR current_setting('server_version_num')::int/10000<>17 THEN
 RAISE EXCEPTION 'Unexpected TEST operator/database/server'; END IF;
 IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN ('security_events','security_findings','security_incidents','incident_events','security_risk_scores')
 AND c.relkind='r' AND c.relrowsecurity AND NOT c.relforcerowsecurity AND pg_get_userbyid(c.relowner)='postgres')<>5 THEN
 RAISE EXCEPTION 'Target ownership/RLS inventory drift'; END IF;
END $guard$;
