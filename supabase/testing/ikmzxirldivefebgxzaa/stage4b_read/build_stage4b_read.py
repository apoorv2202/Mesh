"""Offline preparation only. Generates NEW files; never modifies R2 or executes SQL."""
from pathlib import Path
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parent
PROJECT=ROOT.parent
R2=PROJECT/'stage4'
old=json.loads((R2/'pins.json').read_text())
for name,digest in old['files'].items():assert hashlib.sha256((R2/name).read_bytes()).hexdigest()==digest,name
source=json.loads((R2/'verified_schema.json').read_text())
tables=['security_events','security_findings','security_incidents','incident_events','security_risk_scores']
assert len(source['10_policies'])==5
assert all(p['command']=='SELECT' and p['roles']==['authenticated'] and p['using_expression']=="is_mesh_member(organization_id, ARRAY['security_team'::mesh_role])" for p in source['10_policies'])
prefix='55555555-5555-4555-8555-'
def translate(text):return text.replace('44444444-4444-4444-8444-',prefix).replace('-44001','-54001').replace('-44002','-54002').replace('-44999','-54999').replace('vader-stage4','vader-stage4b-read').replace('Stage4','Stage4B-read')
(ROOT/'fixture.sql').write_text(translate((R2/'fixture.sql').read_text()),encoding='utf-8',newline='\n')
collision=translate((R2/'preflight_collisions_read_only.sql').read_text())
checks=collision[collision.index('WITH users('):collision.index('), auth_checks AS (')]+')\n'
checks=checks.replace("'72a7251d-b69b-4149-8a7f-a082e4b920e9'::uuid",":'user_a'::uuid").replace("'8c9907c9-4acf-480b-aaee-dcd08f3cbc6a'::uuid",":'user_b'::uuid")
clean=checks+"SELECT bool_and(collision_count=0) AS namespace_clear, jsonb_agg(to_jsonb(c) ORDER BY check_name)::text AS collision_counts FROM checks c\n\\gset\n"
clean+="""SELECT jsonb_build_object('record_type','collision_check','passed',:'namespace_clear'::boolean,
 'counts',:'collision_counts'::jsonb) AS diagnostic;
\\if :namespace_clear
\\else
DO $fail$ BEGIN RAISE EXCEPTION 'Stage4B-read fixture namespace collision or residue'; END $fail$;
\\endif
DO $identity$ BEGIN
 IF (SELECT count(*) FROM auth.users WHERE id IN (current_setting('mesh_stage4bread.user_a')::uuid,current_setting('mesh_stage4bread.user_b')::uuid))<>2 THEN
 RAISE EXCEPTION 'Both reviewed synthetic Auth identities must exist'; END IF;
 IF EXISTS(SELECT 1 FROM auth.users WHERE id='55555555-5555-4555-8555-000000000099') THEN
 RAISE EXCEPTION 'Reserved outsider UUID belongs to an existing Auth identity'; END IF;
END $identity$;
"""
(ROOT/'assert_clean.sql').write_text(clean,encoding='utf-8',newline='\n')
cases=[
 ('active_security_a','A','security_team','active','A','normal',1),
 ('active_security_b','B','security_team','active','B','normal',1),
 ('owner','A','owner','active','A','normal',0),('hr','A','hr','active','A','normal',0),
 ('senior_developer','A','senior_developer','active','A','normal',0),('junior_developer','A','junior_developer','active','A','normal',0),
 ('suspended','A','security_team','suspended','A','normal',0),('offboarded','A','security_team','offboarded','A','normal',0),
 ('pending','A','security_team','pending','A','normal',0),('outsider','A','security_team','active','outsider','normal',0),
 ('missing_identity','A','security_team','active','missing','normal',0),
 ('spoof_foreign_organization','A','security_team','active','A','spoof',1),
 ('metadata_role_escalation','A','junior_developer','active','A','spoof',0),
 ('invalid_identity','A','security_team','active','invalid','normal',0),
]
objects=[dict(zip(['name','member','role','status','identity','metadata','expected'],c)) for c in cases]
(ROOT/'test_matrix.json').write_text(json.dumps(objects,indent=2)+'\n',encoding='utf-8',newline='\n')
sql="""-- SQL-role policy simulation only. All setup/claims/membership changes by admin.
DO $read$
DECLARE c jsonb; t text; member_id uuid; member_org uuid; subject text; own_org uuid;
 foreign_org uuid; n bigint; groups bigint; bad bigint; state text; probes int:=0; case_probes int;
BEGIN
 PERFORM set_config('mesh_stage4bread.case_results','[]',true);
 FOR c IN SELECT value FROM jsonb_array_elements($cases$"""+json.dumps(objects)+"""$cases$::jsonb) LOOP
  member_id:=current_setting(CASE WHEN c->>'member'='A' THEN 'mesh_stage4bread.user_a' ELSE 'mesh_stage4bread.user_b' END)::uuid;
  member_org:=CASE WHEN c->>'member'='A' THEN '"""+prefix+"""000000000001'::uuid ELSE '"""+prefix+"""000000000002'::uuid END;
  UPDATE public.organization_members SET role=(c->>'role')::public.mesh_role,status=(c->>'status')::public.mesh_member_status
   WHERE organization_id=member_org AND user_id=member_id;
  GET DIAGNOSTICS n=ROW_COUNT; IF n<>1 THEN RAISE EXCEPTION 'Wrong fixture membership count'; END IF;
  own_org:=member_org;
  foreign_org:=CASE WHEN own_org='"""+prefix+"""000000000001'::uuid THEN '"""+prefix+"""000000000002'::uuid ELSE '"""+prefix+"""000000000001'::uuid END;
  subject:=CASE c->>'identity' WHEN 'A' THEN current_setting('mesh_stage4bread.user_a')
    WHEN 'B' THEN current_setting('mesh_stage4bread.user_b') WHEN 'missing' THEN ''
    WHEN 'invalid' THEN 'not-a-uuid' ELSE '"""+prefix+"""000000000099' END;
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
"""
(ROOT/'select_tests.sql').write_text(sql,encoding='utf-8',newline='\n')
# Pin every unchanged R2 dependency, all four R2 completion artifacts, and NEW files.
names={str(Path('..')/'stage4'/name).replace('\\','/') for name in old['files']}
names.add('../stage4/pins.json')
for phase in ['runtime','cleanup_check']:
    names|={f'../stage4/evidence_r2/{phase}.txt',f'../stage4/evidence_r2/{phase}.receipt.json'}
names|={p.name for p in ROOT.iterdir() if p.suffix in ['.sql','.ps1','.py','.json'] and p.name!='pins.json'}
pins={'test_ref':'ikmzxirldivefebgxzaa','harness':'stage4b_read_v1','baseline_md5':'90a71db3b16ed177b3455f61a59343b2',
 'files':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sorted(names)}}
(ROOT/'pins.json').write_text(json.dumps(pins,indent=2)+'\n',encoding='utf-8',newline='\n')
print('Prepared NEW Stage4B-read artifacts offline. R2/baseline unchanged; NO SQL executed.')
