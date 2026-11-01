-- SQL-role simulation only. No JWT signature or backend LOGIN authentication claim.
DO $human$ DECLARE org uuid; actor uuid; finding uuid; incident uuid; other_org uuid;
 state jsonb; req jsonb; answer jsonb; replay jsonb; stale text; step text; n int:=0;
BEGIN
 FOR org,actor,finding,incident,other_org IN SELECT * FROM (VALUES
 ('55555555-5555-4555-8555-000000000001'::uuid,current_setting('mesh_stage4bread.user_a')::uuid,'55555555-5555-4555-8555-000000000014'::uuid,'55555555-5555-4555-8555-000000000016'::uuid,'55555555-5555-4555-8555-000000000002'::uuid),
 ('55555555-5555-4555-8555-000000000002'::uuid,current_setting('mesh_stage4bread.user_b')::uuid,'55555555-5555-4555-8555-000000000015'::uuid,'55555555-5555-4555-8555-000000000017'::uuid,'55555555-5555-4555-8555-000000000001'::uuid)) q LOOP
  PERFORM set_config('request.jwt.claim.sub',actor::text,true);
  PERFORM set_config('request.jwt.claims',jsonb_build_object('sub',actor,'user_metadata',jsonb_build_object('organization_id',other_org,'role','owner'))::text,true);
  SET LOCAL ROLE authenticated;
  state:=vader_user_api.finding_state_v1(org,finding);
  req:=jsonb_build_object('organization_id',org,'target_id',finding,'request_key','phase2-start','expected_state',state->>'state_token','reason','synthetic test','status','investigating');
  answer:=vader_user_api.triage_finding_v1(req);
  replay:=vader_user_api.triage_finding_v1(req);
  IF replay IS DISTINCT FROM answer THEN RAISE EXCEPTION 'Exact human replay changed result'; END IF;
  IF (answer#>>'{state,revision}')::bigint<>1 THEN RAISE EXCEPTION 'Revision not incremented'; END IF;
  n:=n+2;
  stale:=NULL; BEGIN PERFORM vader_user_api.triage_finding_v1(req||'{"reason":"changed"}'::jsonb); EXCEPTION WHEN OTHERS THEN stale:=SQLSTATE; END;
  IF stale IS DISTINCT FROM '22000' THEN RAISE EXCEPTION 'Replay conflict expected 22000, got %',stale; END IF;
  stale:=NULL; BEGIN PERFORM vader_user_api.triage_finding_v1(req||'{"request_key":"stale"}'::jsonb); EXCEPTION WHEN OTHERS THEN stale:=SQLSTATE; END;
  IF stale IS DISTINCT FROM '40001' THEN RAISE EXCEPTION 'Stale update expected 40001, got %',stale; END IF;
  stale:=NULL; BEGIN PERFORM vader_user_api.triage_finding_v1(req||jsonb_build_object('organization_id',other_org,'request_key','cross')); EXCEPTION WHEN OTHERS THEN stale:=SQLSTATE; END;
  IF stale IS DISTINCT FROM '42501' THEN RAISE EXCEPTION 'Cross tenant expected 42501, got %',stale; END IF;
  stale:=NULL; BEGIN PERFORM vader_user_api.triage_finding_v1(req||'{"request_key":"bad-column","severity":"critical"}'::jsonb); EXCEPTION WHEN OTHERS THEN stale:=SQLSTATE; END;
  IF stale IS DISTINCT FROM '22023' THEN RAISE EXCEPTION 'Restricted column accepted'; END IF;
  n:=n+4;
  FOREACH step IN ARRAY ARRAY['remediating','resolved','investigating','false_positive','investigating'] LOOP
   state:=vader_user_api.finding_state_v1(org,finding);
   PERFORM vader_user_api.triage_finding_v1(jsonb_build_object('organization_id',org,'target_id',finding,'request_key','finding-'||n,
    'expected_state',state->>'state_token','reason','synthetic lifecycle','status',step)); n:=n+1;
  END LOOP;
  FOREACH step IN ARRAY ARRAY['triaged','investigating','contained','remediating','recovering','resolved','triaged','false_positive','triaged'] LOOP
   state:=vader_user_api.incident_state_v1(org,incident);
   PERFORM vader_user_api.triage_incident_v1(jsonb_build_object('organization_id',org,'target_id',incident,'request_key','incident-'||n,
    'expected_state',state->>'state_token','reason','synthetic lifecycle','status',step)); n:=n+1;
  END LOOP;
  state:=vader_user_api.incident_state_v1(org,incident);
  req:=jsonb_build_object('organization_id',org,'target_id',incident,'request_key','assign-self','expected_state',state->>'state_token','reason','synthetic assignment','assigned_to',actor);
  PERFORM vader_user_api.triage_incident_v1(req);n:=n+1;
  state:=vader_user_api.incident_state_v1(org,incident);
  stale:=NULL;BEGIN
   PERFORM vader_user_api.triage_incident_v1(req||jsonb_build_object('request_key','cross-assignee','expected_state',state->>'state_token','assigned_to',
    CASE WHEN actor=current_setting('mesh_stage4bread.user_a')::uuid THEN current_setting('mesh_stage4bread.user_b') ELSE current_setting('mesh_stage4bread.user_a') END));
  EXCEPTION WHEN OTHERS THEN stale:=SQLSTATE;END;
  IF stale IS DISTINCT FROM '42501' THEN RAISE EXCEPTION 'Cross tenant assignment accepted'; END IF;n:=n+1;
  PERFORM vader_user_api.triage_incident_v1(req||jsonb_build_object('request_key','unassign','expected_state',state->>'state_token','assigned_to',NULL));n:=n+1;
  RESET ROLE;
 END LOOP;
 PERFORM set_config('mesh_write.human_assertions',n::text,true);
END $human$;

-- Deny all non-security roles, inactive statuses and missing identity. Restore each
-- administrative membership edit before leaving this block; outer rollback is final.
DO $denial$ DECLARE role_name text; member_status text; error_state text; n int:=0;
BEGIN
 FOREACH role_name IN ARRAY ARRAY['owner','hr','senior_developer','junior_developer','security_team'] LOOP
  FOREACH member_status IN ARRAY ARRAY['active','pending','suspended','offboarded'] LOOP
   IF role_name='security_team' AND member_status='active' THEN CONTINUE; END IF;
   UPDATE public.organization_members SET role=role_name::public.mesh_role,status=member_status::public.mesh_member_status
    WHERE organization_id='55555555-5555-4555-8555-000000000001' AND user_id=current_setting('mesh_stage4bread.user_a')::uuid;
   PERFORM set_config('request.jwt.claim.sub',current_setting('mesh_stage4bread.user_a'),true);
   error_state:=NULL;
   BEGIN
    SET LOCAL ROLE authenticated;
    PERFORM vader_user_api.triage_finding_v1(jsonb_build_object('organization_id','55555555-5555-4555-8555-000000000001','target_id','55555555-5555-4555-8555-000000000014','request_key','denied','expected_state',repeat('0',64),'reason','synthetic denial','status','remediating'));
   EXCEPTION WHEN OTHERS THEN error_state:=SQLSTATE;
   END;
   RESET ROLE;
   IF error_state IS DISTINCT FROM '42501' THEN RAISE EXCEPTION 'Membership authorization failure %, %, %',role_name,member_status,error_state; END IF;
   n:=n+1;
  END LOOP;
 END LOOP;
 UPDATE public.organization_members SET role='security_team',status='active' WHERE organization_id='55555555-5555-4555-8555-000000000001' AND user_id=current_setting('mesh_stage4bread.user_a')::uuid;
 PERFORM set_config('request.jwt.claim.sub','',true);PERFORM set_config('request.jwt.claims','{}',true);
 error_state:=NULL;
 BEGIN SET LOCAL ROLE authenticated;
  PERFORM vader_user_api.finding_state_v1('55555555-5555-4555-8555-000000000001','55555555-5555-4555-8555-000000000014');
 EXCEPTION WHEN OTHERS THEN error_state:=SQLSTATE; END;
 RESET ROLE;
 IF error_state IS DISTINCT FROM '42501' THEN RAISE EXCEPTION 'Missing identity accepted'; END IF;
 PERFORM set_config('mesh_write.denial_assertions',(n+1)::text,true);
END $denial$;

DO $fk$ DECLARE code text;
BEGIN
 code:=NULL; BEGIN
  INSERT INTO public.security_risk_scores(id,organization_id,subject_type,subject_id,score,model_version)
  VALUES('55555555-5555-4555-8555-000000000080','55555555-5555-4555-8555-000000000001','finding','55555555-5555-4555-8555-000000000015',1,'synthetic');
 EXCEPTION WHEN foreign_key_violation THEN code:=SQLSTATE; END;
 IF code IS DISTINCT FROM '23503' THEN RAISE EXCEPTION 'Cross tenant risk FK accepted'; END IF;
 code:=NULL; BEGIN
  UPDATE public.security_incidents SET assigned_to=current_setting('mesh_stage4bread.user_b')::uuid WHERE id='55555555-5555-4555-8555-000000000016';
 EXCEPTION WHEN foreign_key_violation THEN code:=SQLSTATE; END;
 IF code IS DISTINCT FROM '23503' THEN RAISE EXCEPTION 'Cross tenant assignee FK accepted'; END IF;
END $fk$;

SAVEPOINT audit_fault;
REVOKE INSERT(id,organization_id,actor_user_id,action,target_type,target_id,metadata) ON public.audit_logs FROM vader_triage_owner;
DO $audit_fault$ DECLARE req jsonb; state jsonb; code text; before_count bigint;
BEGIN
 SELECT count(*) INTO before_count FROM public.audit_logs WHERE organization_id='55555555-5555-4555-8555-000000000001';
 PERFORM set_config('request.jwt.claim.sub',current_setting('mesh_stage4bread.user_a'),true);
 SET LOCAL ROLE authenticated;
 state:=vader_user_api.finding_state_v1('55555555-5555-4555-8555-000000000001','55555555-5555-4555-8555-000000000014');
 req:=jsonb_build_object('organization_id','55555555-5555-4555-8555-000000000001','target_id','55555555-5555-4555-8555-000000000014',
  'request_key','audit-fault','expected_state',state->>'state_token','reason','synthetic audit fault','status','remediating');
 code:=NULL;BEGIN PERFORM vader_user_api.triage_finding_v1(req);EXCEPTION WHEN OTHERS THEN code:=SQLSTATE;END;
 IF code IS DISTINCT FROM '42501' THEN RAISE EXCEPTION 'Audit fault did not reject: %',code; END IF;
 IF state IS DISTINCT FROM vader_user_api.finding_state_v1('55555555-5555-4555-8555-000000000001','55555555-5555-4555-8555-000000000014') THEN RAISE EXCEPTION 'Audit fault changed state/revision'; END IF;
 RESET ROLE;
 IF EXISTS(SELECT 1 FROM vader_private.triage_receipts WHERE request_key='audit-fault') THEN RAISE EXCEPTION 'Audit fault left receipt'; END IF;
 IF before_count<>(SELECT count(*) FROM public.audit_logs WHERE organization_id='55555555-5555-4555-8555-000000000001') THEN RAISE EXCEPTION 'Audit fault left audit row'; END IF;
END $audit_fault$;
ROLLBACK TO SAVEPOINT audit_fault;
SELECT jsonb_build_object('record_type','write_assertions','human',current_setting('mesh_write.human_assertions')::int,
 'membership_denials',current_setting('mesh_write.denial_assertions')::int,'fk_denials',2,'audit_fault',true,
 'concurrent_database_sessions_tested',false,'machine_login_tested',false);
