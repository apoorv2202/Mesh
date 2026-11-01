"""Offline preparation from captured catalogs; never connects or runs SQL."""
from pathlib import Path
import hashlib
import json

ROOT=Path(__file__).resolve().parent
PROJECT=ROOT.parent
tables=['security_events','security_findings','security_incidents','incident_events','security_risk_scores']
schema=json.loads((PROJECT/'post_bootstrap_verification.json').read_text(encoding='utf-8-sig'))
post=json.loads((PROJECT/'stage3/evidence/verify_no_dml.txt').read_text(encoding='utf-8-sig'))
assert len(post['effective'])==200
assert not any(r['allowed'] for r in post['effective'] if r['rolname'] in ['anon','authenticated','service_role','authenticator'])
for t in tables:
    policies=[p for p in schema['10_policies']['inspection'] if p['table_name']==t]
    assert len(policies)==1 and policies[0]['command']=='SELECT'
    assert policies[0]['roles']==['authenticated']
    assert policies[0]['using_expression']=="is_mesh_member(organization_id, ARRAY['security_team'::mesh_role])"
mapping={k:[r for r in schema[k]['inspection'] if r.get('table_name') in tables] for k in ['02_columns','03_constraints','04_indexes','09_rls_status','10_policies']}
mapping['post_migration_effective']=post['effective']
mapping['post_migration_target_acls']=post['target_acls']
verification=json.loads((PROJECT.parents[1]/'inspection/vader_verification.json').read_text())
mapping['helper_security']=[{k:v for k,v in r.items() if k not in {'definition','routine_oid'}} for r in verification['functions']['definitions_and_settings'] if r.get('routine_name')=='is_mesh_member']
(ROOT/'verified_schema.json').write_text(json.dumps(mapping,indent=2)+'\n',encoding='utf-8',newline='\n')
column_specs=[{'table_name':r['table_name'],'column_name':r['column_name'],'ordinal_position':r['ordinal_position'],
 'postgres_type':r['postgres_type'],'nullable':r['nullable'],'identity_kind':r['identity_kind'],
 'default_or_generation_expression':r['default_or_generation_expression']} for r in mapping['02_columns']]
column_specs.sort(key=lambda r:(r['table_name'],r['ordinal_position']))
assert_columns="""-- Exact live column guard: the older M01 snapshot did not serialize pg_attribute.
DO $columns$ DECLARE actual jsonb; BEGIN
 SELECT jsonb_agg(jsonb_build_object('table_name',c.relname,'column_name',a.attname,
 'ordinal_position',a.attnum,'postgres_type',format_type(a.atttypid,a.atttypmod),'nullable',NOT a.attnotnull,
 'identity_kind',a.attidentity,'default_or_generation_expression',pg_get_expr(d.adbin,d.adrelid))
 ORDER BY c.relname,a.attnum) INTO actual
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 JOIN pg_attribute a ON a.attrelid=c.oid
 LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum
 WHERE n.nspname='public' AND c.relname IN ('security_events','security_findings','security_incidents','incident_events','security_risk_scores')
 AND a.attnum>0 AND NOT a.attisdropped;
 IF actual IS DISTINCT FROM $expected$"""+json.dumps(column_specs)+"""$expected$::jsonb THEN
 RAISE EXCEPTION 'Exact target column/type/default/nullability/identity drift'; END IF;
END $columns$;
"""
(ROOT/'assert_schema.sql').write_text(assert_columns,encoding='utf-8',newline='\n')
def uid(n):return f'44444444-4444-4444-8444-{n:012d}'
A,B=uid(1),uid(2)
ids={t:(uid(10+i*2),uid(11+i*2)) for i,t in enumerate(['security_assets']+tables) if t!='incident_events'}
assetA,assetB=ids['security_assets'];eventA,eventB=ids['security_events'];findingA,findingB=ids['security_findings'];incidentA,incidentB=ids['security_incidents'];riskA,riskB=ids['security_risk_scores']
fixture=f"""-- Synthetic application fixture only. No managed Auth writes or sequence calls.
INSERT INTO public.organizations(id,name,status) VALUES ('{A}','Company A Stage4','active'),('{B}','Company B Stage4','active');
INSERT INTO public.profiles(id,full_name) VALUES (:'user_a'::uuid,'Stage4 synthetic A'),(:'user_b'::uuid,'Stage4 synthetic B');
INSERT INTO public.organization_members(organization_id,user_id,role,status) VALUES
 ('{A}',:'user_a'::uuid,'security_team','active'),('{B}',:'user_b'::uuid,'security_team','active');
INSERT INTO public.security_assets(id,organization_id,name,asset_type) VALUES
 ('{assetA}','{A}','Stage4 A','test'),('{assetB}','{B}','Stage4 B','test');
INSERT INTO public.security_events(id,organization_id,asset_id,source,external_event_id,event_type,event_time) VALUES
 ('{eventA}','{A}','{assetA}','vader-stage4','a','login','2026-01-01T00:00:00Z'),
 ('{eventB}','{B}','{assetB}','vader-stage4','b','login','2026-01-01T00:00:00Z');
INSERT INTO public.security_findings(id,organization_id,asset_id,source_event_id,title,finding_type) VALUES
 ('{findingA}','{A}','{assetA}','{eventA}','Stage4 A','test'),('{findingB}','{B}','{assetB}','{eventB}','Stage4 B','test');
-- Explicit negative test numbers avoid nontransactional identity-sequence advance.
INSERT INTO public.security_incidents(id,organization_id,incident_number,title) OVERRIDING SYSTEM VALUE VALUES
 ('{incidentA}','{A}',-44001,'Stage4 A'),('{incidentB}','{B}',-44002,'Stage4 B');
INSERT INTO public.incident_events(organization_id,incident_id,event_id) VALUES
 ('{A}','{incidentA}','{eventA}'),('{B}','{incidentB}','{eventB}');
INSERT INTO public.security_risk_scores(id,organization_id,subject_type,subject_id,score,model_version) VALUES
 ('{riskA}','{A}','finding','{findingA}',25,'stage4'),('{riskB}','{B}','finding','{findingB}',25,'stage4');
"""
(ROOT/'fixture.sql').write_text(fixture,encoding='utf-8',newline='\n')
checks=[]
for t in tables+['security_assets','organization_members','organizations']:
    col='id' if t=='organizations' else 'organization_id'
    checks.append(f"IF EXISTS(SELECT 1 FROM public.{t} WHERE {col} IN ('{A}','{B}')) THEN RAISE EXCEPTION 'Reserved Stage4 rows exist: {t}'; END IF;")
checks.append("IF EXISTS(SELECT 1 FROM public.profiles WHERE id IN (current_setting('mesh_stage4.user_a')::uuid,current_setting('mesh_stage4.user_b')::uuid)) THEN RAISE EXCEPTION 'Synthetic profile collision/cleanup failure'; END IF;")
(ROOT/'assert_clean.sql').write_text('DO $clean$ BEGIN\n'+'\n'.join(checks)+'\nEND $clean$;\n',encoding='utf-8',newline='\n')
# All actual API CRUD attempts must be ACL-denied; do not pretend this tests RLS filtering.
probes=[]
for t in tables:
    for org in [A,B]:
        predicate=f"organization_id='{org}'"
        values={
          'security_events':f"(organization_id,source,event_type,event_time) VALUES ('{org}','stage4-denied','login','2026-01-01T00:00:00Z')",
          'security_findings':f"(organization_id,title,finding_type) VALUES ('{org}','stage4-denied','test')",
          'security_incidents':f"(organization_id,incident_number,title) OVERRIDING SYSTEM VALUE VALUES ('{org}',-44999,'stage4-denied')",
          'incident_events':f"(organization_id,incident_id,event_id) VALUES ('{org}','{incidentA}','{eventA}')",
          'security_risk_scores':f"(organization_id,subject_type,subject_id,score,model_version) VALUES ('{org}','finding','{findingA}',1,'stage4-denied')",
        }
        stmts=[f'SELECT organization_id FROM public.{t} WHERE {predicate}', f'INSERT INTO public.{t} {values[t]}',f'UPDATE public.{t} SET organization_id=organization_id WHERE {predicate}',f'DELETE FROM public.{t} WHERE {predicate}']
        for op,stmt in zip(['SELECT','INSERT','UPDATE','DELETE'],stmts):
            probes.append({'table':t,'organization':org,'operation':op,'sql':stmt})
sql="""-- API roles must fail BEFORE RLS, for same and foreign orgs and spoofed claims.
DO $acl$
DECLARE r text; subj text; claim_org text; p jsonb; blocked boolean; count_tests int:=0;
BEGIN
 FOREACH r IN ARRAY ARRAY['anon','authenticated','service_role'] LOOP
  FOREACH subj IN ARRAY ARRAY[current_setting('mesh_stage4.user_a'),current_setting('mesh_stage4.user_b')] LOOP
   FOREACH claim_org IN ARRAY ARRAY['"""+A+"""','"""+B+"""'] LOOP
    PERFORM set_config('request.jwt.claim.sub',subj,true);
    PERFORM set_config('request.jwt.claims',jsonb_build_object('sub',subj,'organization_id',claim_org,'user_metadata',jsonb_build_object('organization_id',claim_org,'role','security_team'))::text,true);
    FOR p IN SELECT value FROM jsonb_array_elements($cases$"""+json.dumps(probes)+"""$cases$::jsonb) LOOP
     blocked:=false;
     BEGIN
      EXECUTE format('SET LOCAL ROLE %I',r);
      EXECUTE (p->>'sql');
      RESET ROLE;
     EXCEPTION WHEN insufficient_privilege THEN blocked:=true;
     END;
     IF NOT blocked THEN RAISE EXCEPTION 'Unexpected API access role %, table %, op %',r,p->>'table',p->>'operation'; END IF;
     count_tests:=count_tests+1;
    END LOOP;
   END LOOP;
  END LOOP;
 END LOOP;
 IF count_tests<>480 THEN RAISE EXCEPTION 'Incomplete ACL probes'; END IF;
 PERFORM set_config('mesh_stage4.acl_tests',count_tests::text,true);
END $acl$;
"""
(ROOT/'acl_tests.sql').write_text(sql,encoding='utf-8',newline='\n')
fkcases=[
 ('security_events',f"UPDATE public.security_events SET asset_id='{assetB}' WHERE id='{eventA}'",'security_events_organization_id_asset_id_fkey'),
 ('security_findings',f"UPDATE public.security_findings SET asset_id='{assetB}' WHERE id='{findingA}'",'security_findings_organization_id_asset_id_fkey'),
 ('security_findings',f"UPDATE public.security_findings SET source_event_id='{eventB}' WHERE id='{findingA}'",'security_findings_organization_id_source_event_id_fkey'),
 ('incident_events',f"UPDATE public.incident_events SET incident_id='{incidentB}' WHERE organization_id='{A}'",'incident_events_organization_id_incident_id_fkey'),
 ('incident_events',f"UPDATE public.incident_events SET event_id='{eventB}' WHERE organization_id='{A}'",'incident_events_organization_id_event_id_fkey'),
]
fkcases += [
 ('security_events',f"INSERT INTO public.security_events(id,organization_id,asset_id,source,event_type,event_time) VALUES ('{uid(80)}','{A}','{assetB}','stage4-fk','login','2026-01-01T00:00:00Z')",'security_events_organization_id_asset_id_fkey'),
 ('security_findings',f"INSERT INTO public.security_findings(id,organization_id,source_event_id,title,finding_type) VALUES ('{uid(81)}','{A}','{eventB}','stage4-fk','test')",'security_findings_organization_id_source_event_id_fkey'),
 ('security_findings',f"INSERT INTO public.security_findings(id,organization_id,asset_id,title,finding_type) VALUES ('{uid(82)}','{A}','{assetB}','stage4-fk','test')",'security_findings_organization_id_asset_id_fkey'),
 ('incident_events',f"INSERT INTO public.incident_events(organization_id,incident_id,event_id) VALUES ('{A}','{incidentB}','{eventA}')",'incident_events_organization_id_incident_id_fkey'),
 ('incident_events',f"INSERT INTO public.incident_events(organization_id,incident_id,event_id) VALUES ('{A}','{incidentA}','{eventB}')",'incident_events_organization_id_event_id_fkey'),
]
for t,stmt,constraint in fkcases:
    assert any(r['constraint_name']==constraint for r in mapping['03_constraints']),constraint
fk='DO $fk$ DECLARE got text; BEGIN\n'
for t,stmt,constraint in fkcases:
    fk+=f"BEGIN\n {stmt};\n RAISE EXCEPTION 'Expected composite FK rejection: {constraint}';\nEXCEPTION WHEN foreign_key_violation THEN\n GET STACKED DIAGNOSTICS got=CONSTRAINT_NAME;\n IF got<>'{constraint}' THEN RAISE EXCEPTION 'Wrong FK: %',got; END IF;\nEND;\n"
fk+='END $fk$;\n'
(ROOT/'fk_tests.sql').write_text(fk,encoding='utf-8',newline='\n')
# Owner positive CRUD is a fixture/control, never an API authorization proof.
owner='SAVEPOINT owner_crud;\nDO $owner$ DECLARE n int; BEGIN\n'
for t in tables:
    owner+=f"IF (SELECT count(*) FROM public.{t} WHERE organization_id IN ('{A}','{B}'))<>2 THEN RAISE EXCEPTION 'Positive owner SELECT/INSERT failure: {t}'; END IF;\n"
    owner+=f"UPDATE public.{t} SET organization_id=organization_id WHERE organization_id IN ('{A}','{B}');\nGET DIAGNOSTICS n=ROW_COUNT; IF n<>2 THEN RAISE EXCEPTION 'Owner UPDATE failure: {t}'; END IF;\n"
for t in ['incident_events','security_risk_scores','security_findings','security_incidents','security_events']:
    owner+=f"DELETE FROM public.{t} WHERE organization_id IN ('{A}','{B}');\nGET DIAGNOSTICS n=ROW_COUNT; IF n<>2 THEN RAISE EXCEPTION 'Owner DELETE failure: {t}'; END IF;\n"
owner+='END $owner$;\nROLLBACK TO SAVEPOINT owner_crud;\n'
(ROOT/'owner_controls.sql').write_text(owner,encoding='utf-8',newline='\n')
# No FK presently enforces risk subject or organization membership of Auth references.
gaps=f"""SAVEPOINT documented_gaps;
UPDATE public.security_risk_scores SET subject_id='{findingB}' WHERE id='{riskA}';
UPDATE public.security_events SET actor_user_id=:'user_b'::uuid WHERE id='{eventA}';
UPDATE public.security_incidents SET assigned_to=:'user_b'::uuid WHERE id='{incidentA}';
-- These succeed as owner: known missing constraints, NOT a tenant-security PASS.
ROLLBACK TO SAVEPOINT documented_gaps;
"""
(ROOT/'documented_gaps.sql').write_text(gaps,encoding='utf-8',newline='\n')
pins={'test_ref':'ikmzxirldivefebgxzaa','files':{}}
names=[p for p in ROOT.iterdir() if p.suffix in {'.sql','.ps1','.py','.json'} and p.name!='pins.json']
names += [PROJECT/'target_guard.psql',PROJECT/'stage3/snapshot.sql',PROJECT/'stage3/evidence/verify_no_dml.txt',PROJECT/'stage3/evidence/verify_no_dml.receipt.json',PROJECT/'post_bootstrap_verification.json']
for path in names:
    name=str(path.relative_to(ROOT)) if path.parent==ROOT else str(Path('..')/path.relative_to(PROJECT))
    pins['files'][name.replace('\\','/')]=hashlib.sha256(path.read_bytes()).hexdigest()
pins['files']['../../../inspection/vader_verification.json']=hashlib.sha256((PROJECT.parents[1]/'inspection/vader_verification.json').read_bytes()).hexdigest()
(ROOT/'pins.json').write_text(json.dumps(pins,indent=2)+'\n',encoding='utf-8',newline='\n')
print('Stage4 prepared offline. NO SQL/users/network operations executed.')
