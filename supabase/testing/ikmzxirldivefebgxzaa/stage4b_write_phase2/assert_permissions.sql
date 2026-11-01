-- Exact effective public column privileges for new non-owner roles.
DO $assert$ DECLARE r text; t text; p text; col record; permitted boolean; expected boolean; fn record; expected_owner text;
BEGIN
 FOREACH r IN ARRAY ARRAY['vader_writer_owner','vader_triage_owner','vader_ingest'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=r AND NOT rolcanlogin AND NOT rolsuper
    AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication) THEN
   RAISE EXCEPTION 'Unsafe role attributes %',r; END IF;
  FOREACH t IN ARRAY ARRAY['security_events','security_findings','security_incidents','incident_events','security_risk_scores','audit_logs'] LOOP
   FOREACH p IN ARRAY ARRAY['SELECT','INSERT','UPDATE','REFERENCES'] LOOP
    FOR col IN SELECT attname FROM pg_attribute WHERE attrelid=to_regclass('public.'||t) AND attnum>0 AND NOT attisdropped LOOP
     expected:=false;
     IF r='vader_writer_owner' AND p='SELECT' AND t<>'audit_logs' THEN expected:=true; END IF;
     IF r='vader_triage_owner' AND p='SELECT' AND t IN ('security_findings','security_incidents') THEN expected:=true; END IF;
     IF r='vader_writer_owner' AND p='INSERT' THEN
      expected:=CASE t
       WHEN 'security_events' THEN col.attname=ANY(ARRAY['id','organization_id','source','external_event_id','event_type','actor_identifier','source_ip','event_time','details'])
       WHEN 'security_findings' THEN col.attname=ANY(ARRAY['id','organization_id','source_event_id','title','description','finding_type','severity','evidence'])
       WHEN 'security_incidents' THEN col.attname=ANY(ARRAY['id','organization_id','title','description','severity','risk_score','confidence','summary'])
       WHEN 'incident_events' THEN col.attname=ANY(ARRAY['organization_id','incident_id','event_id'])
       WHEN 'security_risk_scores' THEN col.attname=ANY(ARRAY['id','organization_id','subject_type','subject_id','score','confidence','factors','explanation','model_version'])
       ELSE false END;
     END IF;
     IF t='audit_logs' AND p='INSERT' AND r IN ('vader_writer_owner','vader_triage_owner') THEN
      expected:=col.attname=ANY(ARRAY['id','organization_id','actor_user_id','action','target_type','target_id','metadata']); END IF;
     IF r='vader_triage_owner' AND p='UPDATE' THEN
      expected:=CASE t WHEN 'security_findings' THEN col.attname=ANY(ARRAY['status','remediation','resolved_at'])
       WHEN 'security_incidents' THEN col.attname=ANY(ARRAY['status','assigned_to','resolved_at']) ELSE false END; END IF;
     permitted:=has_column_privilege(r,'public.'||t,col.attname,p);
     IF permitted IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Unexpected effective column permission %, %, %, %',r,t,col.attname,p; END IF;
    END LOOP;
   END LOOP;
   FOREACH p IN ARRAY ARRAY['DELETE','TRUNCATE','TRIGGER','MAINTAIN'] LOOP
    IF has_table_privilege(r,'public.'||t,p) THEN RAISE EXCEPTION 'Dangerous role privilege %, %, %',r,t,p; END IF;
   END LOOP;
  END LOOP;
 END LOOP;
 FOREACH r IN ARRAY ARRAY['anon','authenticated','authenticator','service_role'] LOOP
  FOREACH t IN ARRAY ARRAY['security_events','security_findings','security_incidents','incident_events','security_risk_scores','audit_logs'] LOOP
   FOREACH p IN ARRAY ARRAY['INSERT','UPDATE','REFERENCES'] LOOP
    IF has_any_column_privilege(r,'public.'||t,p) THEN RAISE EXCEPTION 'API write/reference escape %, %, %',r,t,p; END IF;
   END LOOP;
   FOREACH p IN ARRAY ARRAY['DELETE','TRUNCATE','TRIGGER','MAINTAIN'] LOOP
    IF has_table_privilege(r,'public.'||t,p) THEN RAISE EXCEPTION 'API dangerous privilege'; END IF;
   END LOOP;
  END LOOP;
 END LOOP;
 FOR fn IN SELECT p.*,n.nspname,pg_get_userbyid(p.proowner) owner_name FROM pg_proc p
 JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('vader_private','vader_api','vader_user_api') LOOP
  expected_owner:=CASE
   WHEN fn.proname IN ('machine_scope_v1','human_guard_v1','triage_token_v1') THEN 'postgres'
   WHEN fn.proname IN ('tenant_v1','append_machine_audit_v1','id_v1','claim_v1','read_history_v1','commit_bundle_v1') THEN 'vader_writer_owner'
   WHEN fn.proname IN ('transition_allowed_v1','triage_v1','triage_state_v1','triage_finding_v1','triage_incident_v1','finding_state_v1','incident_state_v1') THEN 'vader_triage_owner'
   ELSE NULL END;
  IF expected_owner IS NULL OR fn.owner_name<>expected_owner THEN RAISE EXCEPTION 'Function inventory/owner differs %',fn.oid::regprocedure; END IF;
  IF fn.prosecdef IS DISTINCT FROM (fn.proname NOT IN ('id_v1','claim_v1','append_machine_audit_v1','transition_allowed_v1')) THEN RAISE EXCEPTION 'Unexpected definer mode'; END IF;
  IF NOT coalesce(fn.proconfig,'{}'::text[]) @> ARRAY['search_path=pg_catalog, pg_temp'] THEN
   -- PostgreSQL preserves SET clause whitespace; accept exactly the two equivalent fixed values.
   IF NOT coalesce(fn.proconfig,'{}'::text[]) @> ARRAY['search_path=pg_catalog,pg_temp'] THEN RAISE EXCEPTION 'Unsafe search path %',fn.oid::regprocedure; END IF;
  END IF;
  IF fn.prosecdef AND fn.owner_name NOT IN ('postgres','vader_writer_owner','vader_triage_owner') THEN RAISE EXCEPTION 'Unexpected definer owner'; END IF;
  IF fn.owner_name='postgres' AND fn.proname NOT IN ('machine_scope_v1','human_guard_v1','triage_token_v1') THEN RAISE EXCEPTION 'Unexpected privileged helper'; END IF;
  IF EXISTS(SELECT 1 FROM aclexplode(coalesce(fn.proacl,acldefault('f',fn.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') THEN RAISE EXCEPTION 'PUBLIC function execute'; END IF;
  IF EXISTS(SELECT 1 FROM aclexplode(coalesce(fn.proacl,acldefault('f',fn.proowner))) a
   WHERE a.grantee<>fn.proowner AND NOT
    ((fn.proname='machine_scope_v1' AND pg_get_userbyid(a.grantee)='vader_writer_owner')
     OR (fn.proname IN ('human_guard_v1','triage_token_v1') AND pg_get_userbyid(a.grantee)='vader_triage_owner')
     OR (fn.nspname='vader_api' AND pg_get_userbyid(a.grantee)='vader_ingest')
     OR (fn.nspname='vader_user_api' AND pg_get_userbyid(a.grantee)='authenticated'))) THEN RAISE EXCEPTION 'Unexpected function ACL grantee'; END IF;
  FOREACH r IN ARRAY ARRAY['anon','authenticated','authenticator','service_role','vader_ingest'] LOOP
   expected:=(fn.nspname='vader_user_api' AND r='authenticated') OR (fn.nspname='vader_api' AND r='vader_ingest');
   IF has_function_privilege(r,fn.oid,'EXECUTE') IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Unexpected API function execution %, %',r,fn.oid::regprocedure; END IF;
  END LOOP;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_class c WHERE c.relnamespace='vader_private'::regnamespace AND c.relkind='r'
  AND (pg_get_userbyid(c.relowner)<>'postgres' OR NOT c.relrowsecurity OR c.relforcerowsecurity)) THEN RAISE EXCEPTION 'Private table ownership/RLS mismatch'; END IF;
 IF NOT has_sequence_privilege('vader_writer_owner','public.security_incidents_incident_number_seq','USAGE')
 OR has_sequence_privilege('vader_writer_owner','public.security_incidents_incident_number_seq','UPDATE') THEN RAISE EXCEPTION 'Sequence privilege mismatch'; END IF;
 IF EXISTS(SELECT 1 FROM pg_namespace WHERE nspname IN ('vader_private','vader_api','vader_user_api')
 AND (has_schema_privilege('vader_writer_owner',oid,'CREATE') OR has_schema_privilege('vader_triage_owner',oid,'CREATE'))) THEN RAISE EXCEPTION 'Residual owner CREATE'; END IF;
END $assert$;
