\set ON_ERROR_STOP on
\ir ../target_guard.psql
\if :{?stage4_approved}
\else
SELECT jsonb_build_object('record_type','failure','code','STAGE4_APPROVAL_MISSING') AS diagnostic;
DO $fail$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='STAGE4_APPROVAL_MISSING'; END $fail$;
\endif
SELECT :'stage4_approved'='ikmzxirldivefebgxzaa' AS approved \gset
\if :approved
\else
SELECT jsonb_build_object('record_type','failure','code','STAGE4_APPROVAL_REJECTED') AS diagnostic;
DO $fail$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='STAGE4_APPROVAL_REJECTED'; END $fail$;
\endif
DO $guard$ BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres' OR current_database()<>'postgres'
 OR current_setting('server_version_num')::int/10000<>17 THEN
 RAISE EXCEPTION 'Wrong TEST identity/database/server'; END IF;
 IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname IN ('security_events','security_findings','security_incidents','incident_events','security_risk_scores')
 AND c.relkind='r' AND c.relrowsecurity AND NOT c.relforcerowsecurity AND pg_get_userbyid(c.relowner)='postgres')<>5 THEN
 RAISE EXCEPTION 'Target inventory/ownership/RLS drift'; END IF;
END $guard$;
