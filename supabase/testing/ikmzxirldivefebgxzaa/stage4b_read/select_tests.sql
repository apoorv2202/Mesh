-- SQL-role policy simulation only. All setup/claims/membership changes by admin.
DO $read$
DECLARE c jsonb; t text; member_id uuid; member_org uuid; subject text; own_org uuid;
 foreign_org uuid; n bigint; groups bigint; bad bigint; state text; probes int:=0; case_probes int;
BEGIN
 PERFORM set_config('mesh_stage4bread.case_results','[]',true);
 FOR c IN SELECT value FROM jsonb_array_elements($cases$[{"name": "active_security_a", "member": "A", "role": "security_team", "status": "active", "identity": "A", "metadata": "normal", "expected": 1}, {"name": "active_security_b", "member": "B", "role": "security_team", "status": "active", "identity": "B", "metadata": "normal", "expected": 1}, {"name": "owner", "member": "A", "role": "owner", "status": "active", "identity": "A", "metadata": "normal", "expected": 0}, {"name": "hr", "member": "A", "role": "hr", "status": "active", "identity": "A", "metadata": "normal", "expected": 0}, {"name": "senior_developer", "member": "A", "role": "senior_developer", "status": "active", "identity": "A", "metadata": "normal", "expected": 0}, {"name": "junior_developer", "member": "A", "role": "junior_developer", "status": "active", "identity": "A", "metadata": "normal", "expected": 0}, {"name": "suspended", "member": "A", "role": "security_team", "status": "suspended", "identity": "A", "metadata": "normal", "expected": 0}, {"name": "offboarded", "member": "A", "role": "security_team", "status": "offboarded", "identity": "A", "metadata": "normal", "expected": 0}, {"name": "pending", "member": "A", "role": "security_team", "status": "pending", "identity": "A", "metadata": "normal", "expected": 0}, {"name": "outsider", "member": "A", "role": "security_team", "status": "active", "identity": "outsider", "metadata": "normal", "expected": 0}, {"name": "missing_identity", "member": "A", "role": "security_team", "status": "active", "identity": "missing", "metadata": "normal", "expected": 0}, {"name": "spoof_foreign_organization", "member": "A", "role": "security_team", "status": "active", "identity": "A", "metadata": "spoof", "expected": 1}, {"name": "metadata_role_escalation", "member": "A", "role": "junior_developer", "status": "active", "identity": "A", "metadata": "spoof", "expected": 0}, {"name": "invalid_identity", "member": "A", "role": "security_team", "status": "active", "identity": "invalid", "metadata": "normal", "expected": 0}]$cases$::jsonb) LOOP
  member_id:=current_setting(CASE WHEN c->>'member'='A' THEN 'mesh_stage4bread.user_a' ELSE 'mesh_stage4bread.user_b' END)::uuid;
  member_org:=CASE WHEN c->>'member'='A' THEN '55555555-5555-4555-8555-000000000001'::uuid ELSE '55555555-5555-4555-8555-000000000002'::uuid END;
  UPDATE public.organization_members SET role=(c->>'role')::public.mesh_role,status=(c->>'status')::public.mesh_member_status
   WHERE organization_id=member_org AND user_id=member_id;
  GET DIAGNOSTICS n=ROW_COUNT; IF n<>1 THEN RAISE EXCEPTION 'Wrong fixture membership count'; END IF;
  own_org:=member_org;
  foreign_org:=CASE WHEN own_org='55555555-5555-4555-8555-000000000001'::uuid THEN '55555555-5555-4555-8555-000000000002'::uuid ELSE '55555555-5555-4555-8555-000000000001'::uuid END;
  subject:=CASE c->>'identity' WHEN 'A' THEN current_setting('mesh_stage4bread.user_a')
    WHEN 'B' THEN current_setting('mesh_stage4bread.user_b') WHEN 'missing' THEN ''
    WHEN 'invalid' THEN 'not-a-uuid' ELSE '55555555-5555-4555-8555-000000000099' END;
  PERFORM set_config('request.jwt.claim.sub',subject,true);
  PERFORM set_config('request.jwt.claims',CASE WHEN subject='' THEN '{}' ELSE jsonb_build_object('sub',subject,
   'organization_id',foreign_org,'user_metadata',CASE WHEN c->>'metadata'='spoof' THEN jsonb_build_object('role','security_team','organization_id',foreign_org) ELSE '{}'::jsonb END)::text END,true);
  case_probes:=0;
  FOREACH t IN ARRAY ARRAY['security_events','security_findings','security_incidents','incident_events','security_risk_scores'] LOOP
   IF c->>'identity'='invalid' THEN
    state:=NULL;
    BEGIN
     SET LOCAL ROLE authenticated;
     EXECUTE format('SELECT count(*) FROM public.%I',t) INTO n;
     RESET ROLE;
    EXCEPTION WHEN invalid_text_representation THEN state:=SQLSTATE;
    END;
    IF state IS DISTINCT FROM '22P02' THEN RAISE EXCEPTION 'Invalid identity was not rejected: %',t; END IF;
    case_probes:=case_probes+1;
    CONTINUE;
   END IF;
   SET LOCAL ROLE authenticated;
   EXECUTE format('SELECT count(*) FROM public.%I',t) INTO n;
   IF n<>(c->>'expected')::int THEN RAISE EXCEPTION 'Unfiltered read failed: %, %',c->>'name',t; END IF;
   EXECUTE format('SELECT count(*) FROM public.%I WHERE organization_id=$1',t) INTO n USING own_org;
   IF n<>(c->>'expected')::int THEN RAISE EXCEPTION 'Own read failed'; END IF;
   EXECUTE format('SELECT count(*) FROM public.%I WHERE organization_id=$1',t) INTO n USING foreign_org;
   IF n<>0 THEN RAISE EXCEPTION 'Foreign read leaked'; END IF;
   EXECUTE format('SELECT count(*) FROM (SELECT organization_id,count(*) FROM public.%I GROUP BY organization_id) q',t) INTO groups;
   IF groups<>(c->>'expected')::int THEN RAISE EXCEPTION 'Grouped count leaked'; END IF;
   EXECUTE format('SELECT count(*) FROM (SELECT organization_id FROM public.%I ORDER BY organization_id OFFSET 0 LIMIT 10) q',t) INTO n;
   IF n<>(c->>'expected')::int THEN RAISE EXCEPTION 'Pagination leaked'; END IF;
   EXECUTE format('SELECT count(*) FROM public.%I WHERE organization_id<>$1',t) INTO bad USING own_org;
   IF bad<>0 THEN RAISE EXCEPTION 'Non-tenant row leaked'; END IF;
   EXECUTE format('SELECT count(DISTINCT organization_id) FROM public.%I',t) INTO n;
   IF n<>(c->>'expected')::int THEN RAISE EXCEPTION 'DISTINCT leaked'; END IF;
   EXECUTE format('SELECT count(*) FROM public.%I t JOIN public.security_events e USING (organization_id)',t) INTO n;
   IF n<>(c->>'expected')::int THEN RAISE EXCEPTION 'Same-tenant join failed'; END IF;
   EXECUTE format('SELECT count(*) FROM public.%I t JOIN public.security_events e ON t.organization_id<>e.organization_id',t) INTO n;
   IF n<>0 THEN RAISE EXCEPTION 'Cross-tenant join leaked'; END IF;
   RESET ROLE;
   case_probes:=case_probes+9;
  END LOOP;
  probes:=probes+case_probes;
  PERFORM set_config('mesh_stage4bread.case_results',
   (current_setting('mesh_stage4bread.case_results')::jsonb || jsonb_build_array(jsonb_build_object(
    'case',c->>'name','passed',true,'assertions',case_probes,'expected_visible_rows',(c->>'expected')::int)))::text,true);
  RAISE NOTICE 'READ CASE % PASS (% checks)',c->>'name',case_probes;
 END LOOP;
 IF probes<>590 THEN RAISE EXCEPTION 'Incomplete read suite: %',probes; END IF;
 PERFORM set_config('mesh_stage4bread.probes',probes::text,true);
END $read$;
SELECT jsonb_build_object('record_type','read_suite','passed',true,'cases',14,
 'assertions',current_setting('mesh_stage4bread.probes')::int,'mode','SQL_ROLE_SIMULATION',
 'case_results',current_setting('mesh_stage4bread.case_results')::jsonb) AS result;
