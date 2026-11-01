-- REVIEW ONLY / TEST preparation. Not a deployed migration. No SQL executed.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
DO $gate$ BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres' OR current_database()<>'postgres'
 OR current_setting('server_version_num')::int/10000<>17
 OR current_setting('mesh_review.test_ref',true) IS DISTINCT FROM 'ikmzxirldivefebgxzaa'
 OR current_setting('mesh_review.audit_hardening_approved',true) IS DISTINCT FROM 'on' THEN
 RAISE EXCEPTION 'Closed TEST/audit-hardening review gate'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='public.audit_logs'::regclass
 AND relkind='r' AND relrowsecurity AND pg_get_userbyid(relowner)='postgres') THEN
 RAISE EXCEPTION 'Unexpected audit table ownership/RLS'; END IF;
 IF EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='public.audit_logs'::regclass
 AND attnum>0 AND NOT attisdropped AND attacl IS NOT NULL) THEN
 RAISE EXCEPTION 'Audit column ACL drift requires review'; END IF;
END $gate$;
REVOKE TRUNCATE,REFERENCES,TRIGGER,MAINTAIN,INSERT,UPDATE,DELETE
 ON public.audit_logs FROM PUBLIC,anon,authenticated,service_role;
DO $audit$ DECLARE r text; p text; BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','authenticator','service_role'] LOOP
  FOREACH p IN ARRAY ARRAY['TRUNCATE','REFERENCES','TRIGGER','MAINTAIN','INSERT','UPDATE','DELETE'] LOOP
   IF has_table_privilege(r,'public.audit_logs',p) THEN RAISE EXCEPTION 'Residual effective audit privilege for %, %',r,p; END IF;
  END LOOP;
 END LOOP;
END $audit$;
-- No SELECT grants, managed membership changes or creator-wide defaults altered.
COMMIT;
