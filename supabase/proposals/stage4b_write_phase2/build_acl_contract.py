"""Offline ACL oracle: explicit intended grants, not inferred from candidate GRANTs."""
from pathlib import Path
import json

HERE=Path(__file__).resolve().parent
TEST=HERE.parents[1]/'testing/ikmzxirldivefebgxzaa/stage4b_write_phase2'
add=[]
def grant(kind,obj,role,privs,*,column='',owner='postgres'):
    for privilege in privs.split(','):
        add.append([kind,obj,column,owner,role,privilege,False])

for role in ('vader_writer_owner','vader_triage_owner'):
    grant('schema','vader_private',role,'USAGE')
for schema in ('vader_private','vader_api','vader_user_api'):
    grant('schema',schema,'postgres','USAGE,CREATE')
for role in ('vader_writer_owner','vader_ingest'):grant('schema','vader_api',role,'USAGE')
for role in ('vader_triage_owner','authenticated'):grant('schema','vader_user_api',role,'USAGE')
grant('schema','extensions','vader_writer_owner','USAGE')
grant('function','public.is_mesh_member(uuid, public.mesh_role[])','vader_triage_owner','EXECUTE')
for table,role in [('principals','vader_writer_owner'),('receipts','vader_writer_owner'),
                   ('triage_receipts','vader_triage_owner'),('triage_versions','vader_triage_owner')]:
    grant('table','vader_private.'+table,'postgres','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
    grant('table','vader_private.'+table,role,'SELECT' if table=='principals' else 'SELECT,INSERT,UPDATE')
insert_columns={
 'security_events':'id,organization_id,source,external_event_id,event_type,actor_identifier,source_ip,event_time,details',
 'security_findings':'id,organization_id,source_event_id,title,description,finding_type,severity,evidence',
 'security_incidents':'id,organization_id,title,description,severity,risk_score,confidence,summary',
 'incident_events':'organization_id,incident_id,event_id',
 'security_risk_scores':'id,organization_id,subject_type,subject_id,score,confidence,factors,explanation,model_version'}
for table,columns in insert_columns.items():
    grant('table','public.'+table,'vader_writer_owner','SELECT')
    for col in columns.split(','):grant('column','public.'+table,'vader_writer_owner','INSERT',column=col)
for table,cols in [('security_findings','status,remediation,resolved_at'),('security_incidents','status,assigned_to,resolved_at')]:
    grant('table','public.'+table,'vader_triage_owner','SELECT')
    for col in cols.split(','):grant('column','public.'+table,'vader_triage_owner','UPDATE',column=col)
for role in ('vader_writer_owner','vader_triage_owner'):
    for col in 'id,organization_id,actor_user_id,action,target_type,target_id,metadata'.split(','):
        grant('column','public.audit_logs',role,'INSERT',column=col)
grant('sequence','public.security_incidents_incident_number_seq','vader_writer_owner','USAGE')
for spec in json.loads((HERE/'object_contract.json').read_text())['functions']:
    types=[{'timestamptz':'timestamp with time zone'}.get(t,t) for t in spec['arg_types']]
    identity=spec['schema']+'.'+spec['name']+'('+', '.join(types)+')'
    grant('function',identity,spec['owner'],'EXECUTE',owner=spec['owner'])
    extra={'machine_scope_v1':'vader_writer_owner','human_guard_v1':'vader_triage_owner','triage_token_v1':'vader_triage_owner'}.get(spec['name'])
    if spec['schema']=='vader_api':extra='vader_ingest'
    if spec['schema']=='vader_user_api':extra='authenticated'
    if extra:grant('function',identity,extra,'EXECUTE',owner=spec['owner'])
assert len(add)==len({tuple(x) for x in add})
contract={'tuple_fields':['kind','object','column','grantor','grantee','privilege','grantable'],
 'remove':{'kind':'table','object':'public.audit_logs','grantees':['PUBLIC','anon','authenticated','service_role'],
           'privileges':['INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN']},
 'add':sorted(add)}
(HERE/'acl_contract.json').write_text(json.dumps(contract,indent=2)+'\n',encoding='utf8')
manifest=json.dumps(contract)
sql='''-- Exact ACL equality. Unexpected grants are reported before raising.
\\ir capture_acl.sql
SELECT set_config('mesh_write.acl_actual',:'write_acl',true) AS ignored \\gset
-- Keep the historical write_acl fingerprint unchanged. Capture only the named
-- public helper separately, before/after, from the full metadata snapshots.
WITH helper_before AS (
 SELECT value AS f FROM jsonb_array_elements(current_setting('mesh_write.before')::jsonb#>'{native,functions}')
 WHERE (value->>'oid')::oid='public.is_mesh_member(uuid,public.mesh_role[])'::regprocedure
), helper_rights AS (
 SELECT x.* FROM helper_before b CROSS JOIN LATERAL aclexplode(
 CASE WHEN jsonb_typeof(b.f->'acl')='array' THEN
 ARRAY(SELECT value::aclitem FROM jsonb_array_elements_text(b.f->'acl'))
 ELSE acldefault('f',(b.f->>'owner')::oid) END) x
), helper_actual AS (
 SELECT x.* FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) x
 WHERE p.oid='public.is_mesh_member(uuid,public.mesh_role[])'::regprocedure
), combined AS (
 SELECT 'before' phase,value FROM jsonb_array_elements(current_setting('mesh_write.acl_before')::jsonb)
 UNION ALL SELECT 'actual',value FROM jsonb_array_elements(current_setting('mesh_write.acl_actual')::jsonb)
 UNION ALL SELECT 'before',jsonb_build_array('function','public.is_mesh_member(uuid, public.mesh_role[])','',
 pg_get_userbyid(grantor),CASE WHEN grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(grantee) END,privilege_type,is_grantable) FROM helper_rights
 UNION ALL SELECT 'actual',jsonb_build_array('function','public.is_mesh_member(uuid, public.mesh_role[])','',
 pg_get_userbyid(grantor),CASE WHEN grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(grantee) END,privilege_type,is_grantable) FROM helper_actual
)
SELECT set_config('mesh_write.acl_extended_before',(SELECT jsonb_agg(value ORDER BY value::text COLLATE "C")::text FROM combined WHERE phase='before'),true) AS helper_before_ignored,
 set_config('mesh_write.acl_actual',(SELECT jsonb_agg(value ORDER BY value::text COLLATE "C")::text FROM combined WHERE phase='actual'),true) AS helper_actual_ignored
\\gset
WITH contract AS (SELECT $acl_contract$'''+manifest+'''$acl_contract$::jsonb v), expected AS (
 SELECT x.value FROM jsonb_array_elements(current_setting('mesh_write.acl_extended_before')::jsonb) x,contract c
 WHERE NOT (x.value->>0=c.v#>>'{remove,kind}' AND x.value->>1=c.v#>>'{remove,object}'
 AND x.value->>4 IN (SELECT jsonb_array_elements_text(c.v#>'{remove,grantees}'))
 AND x.value->>5 IN (SELECT jsonb_array_elements_text(c.v#>'{remove,privileges}')))
 UNION SELECT jsonb_array_elements(v->'add') FROM contract
)
SELECT set_config('mesh_write.acl_expected',coalesce(jsonb_agg(value ORDER BY value::text COLLATE "C"),'[]'::jsonb)::text,true) AS ignored FROM expected
\\gset
SELECT jsonb_build_object('record_type','exact_acl_delta',
 'passed',current_setting('mesh_write.acl_expected')::jsonb=current_setting('mesh_write.acl_actual')::jsonb,
 'unexpected',(SELECT coalesce(jsonb_agg(value),'[]'::jsonb) FROM
  (SELECT value FROM jsonb_array_elements(current_setting('mesh_write.acl_actual')::jsonb)
   EXCEPT SELECT value FROM jsonb_array_elements(current_setting('mesh_write.acl_expected')::jsonb)) q),
 'missing',(SELECT coalesce(jsonb_agg(value),'[]'::jsonb) FROM
  (SELECT value FROM jsonb_array_elements(current_setting('mesh_write.acl_expected')::jsonb)
   EXCEPT SELECT value FROM jsonb_array_elements(current_setting('mesh_write.acl_actual')::jsonb)) q)) AS diagnostic;
DO $acl_exact$ BEGIN
 IF current_setting('mesh_write.acl_expected')::jsonb IS DISTINCT FROM current_setting('mesh_write.acl_actual')::jsonb THEN
  RAISE EXCEPTION 'Exact ACL delta rejected; unexpected/missing tuples precede this error'; END IF;
END $acl_exact$;
'''
(TEST/'assert_acl_exact.sql').write_text(sql,encoding='utf8',newline='\n')
print('Frozen exact ACL contract:',len(add),'explicit additions; no SQL executed.')
