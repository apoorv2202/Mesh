"""Offline exact-anchor revision; original Migration02 and evidence are read-only."""
from pathlib import Path
import hashlib
import json
import re

ROOT=Path(__file__).resolve().parent
SOURCE=ROOT.parent/'02_vader_transactional_writer.sql'
raw=SOURCE.read_bytes();sql=raw.decode().replace('\r\n','\n')
def replace(old,new,count=1):
    global sql
    assert sql.count(old)==count,old[:100]
    sql=sql.replace(old,new)
replace("IF current_setting('mesh_review.writer_approved',true) IS DISTINCT FROM 'on' THEN",
 "IF current_user<>'postgres' OR session_user<>'postgres' OR current_database()<>'postgres'\n OR current_setting('mesh_review.test_ref',true) IS DISTINCT FROM 'ikmzxirldivefebgxzaa'\n OR current_setting('mesh_review.writer_approved',true) IS DISTINCT FROM 'on'\n OR current_setting('mesh_review.audit_hardening_approved',true) IS DISTINCT FROM 'on' THEN")
start=sql.index('-- Existing checks allow four polymorphic subject kinds;')
end=sql.index('GRANT SELECT,INSERT ON public.security_events',start)
sql=sql[:start]+"""-- Reference-integrity proposal must already be validated; never duplicate DDL.
DO $integrity$ BEGIN
 IF (SELECT count(*) FROM pg_constraint WHERE convalidated AND contype='f' AND
 ((conrelid='public.security_risk_scores'::regclass AND conname='vader_risk_finding_tenant_fk' AND confrelid='public.security_findings'::regclass)
 OR (conrelid='public.security_risk_scores'::regclass AND conname='vader_risk_incident_tenant_fk' AND confrelid='public.security_incidents'::regclass)
 OR (conrelid='public.security_incidents'::regclass AND conname='vader_assignee_tenant_fk' AND confrelid='public.organization_members'::regclass)))<>3 THEN
 RAISE EXCEPTION 'Reference integrity proposal not installed/validated'; END IF;
 IF EXISTS(SELECT 1 FROM pg_roles r CROSS JOIN unnest(ARRAY['TRUNCATE','REFERENCES','TRIGGER','MAINTAIN','INSERT','UPDATE','DELETE']) p(privilege)
 WHERE r.rolname IN ('anon','authenticated','authenticator','service_role')
 AND has_table_privilege(r.oid,'public.audit_logs',p.privilege)) THEN RAISE EXCEPTION 'Audit hardening prerequisite missing'; END IF;
END $integrity$;

"""+sql[end:]
old="""GRANT SELECT,INSERT ON public.security_events,public.security_findings,
 public.security_incidents,public.incident_events,public.security_risk_scores TO vader_writer_owner;"""
new="""GRANT SELECT ON public.security_events,public.security_findings,
 public.security_incidents,public.incident_events,public.security_risk_scores TO vader_writer_owner;
GRANT INSERT(id,organization_id,source,external_event_id,event_type,actor_identifier,source_ip,event_time,details) ON public.security_events TO vader_writer_owner;
GRANT INSERT(id,organization_id,source_event_id,title,description,finding_type,severity,evidence) ON public.security_findings TO vader_writer_owner;
GRANT INSERT(id,organization_id,title,description,severity,risk_score,confidence,summary) ON public.security_incidents TO vader_writer_owner;
GRANT INSERT(organization_id,incident_id,event_id) ON public.incident_events TO vader_writer_owner;
GRANT INSERT(id,organization_id,subject_type,subject_id,score,confidence,factors,explanation,model_version) ON public.security_risk_scores TO vader_writer_owner;"""
replace(old,new)
# Retain original function signature; delegate to the new locked scope helper.
start=sql.index('DECLARE tenant uuid; principal record;')
end=sql.index('\n$fn$;',start)
sql=sql[:start]+"BEGIN\n RETURN vader_private.machine_scope_v1();\nEND"+sql[end:]
# Support is split around tenant_v1: principal policy/helper first, audit functions after tenant.
support=(ROOT/'machine_support.sql.in').read_text()
split=support.index('GRANT INSERT(id,organization_id,actor_user_id')
before=support[:split];after=support[split:]
point=sql.index('CREATE FUNCTION vader_private.tenant_v1()')
sql=sql[:point]+before+'\n'+sql[point:]
point=sql.index('-- Durable payload equality')
sql=sql[:point]+after+'\n'+sql[point:]
replace("result_events jsonb:='[]'; result_findings jsonb:='[]'; result_incidents jsonb:='[]'; result_risks jsonb:='[]';",
 "result_events jsonb:='[]'; result_findings jsonb:='[]'; result_incidents jsonb:='[]'; result_risks jsonb:='[]';\n result_audits jsonb:='[]'; link_created int;")
for statement,action,target,key in [
 ("VALUES(id,tenant,e.source,e.external_event_id,e.event_type,e.actor_identifier,e.source_ip,e.event_time,e.details);",'event_ingested','security_events','id::text'),
 ("VALUES(id,tenant,f.source_event_id,f.title,f.description,f.finding_type,f.severity,f.evidence);",'finding_created','security_findings','id::text'),
 ("VALUES(id,tenant,i.title,i.description,i.severity,i.risk_score,i.confidence,i.summary);",'incident_created','security_incidents','id::text'),
 ("VALUES(id,tenant,r.subject_type,r.subject_id,r.score,r.confidence,r.factors,r.explanation,r.model_version);",'risk_created','security_risk_scores','id::text')]:
 replace(statement,statement+f"\n   result_audits:=result_audits || jsonb_build_array(vader_private.append_machine_audit_v1('{action}','{target}',{key},batch));")
replace("VALUES(tenant,id,linked) ON CONFLICT (incident_id,event_id) DO NOTHING;",
 "VALUES(tenant,id,linked) ON CONFLICT (incident_id,event_id) DO NOTHING;\n   GET DIAGNOSTICS link_created=ROW_COUNT;\n   IF link_created=1 THEN\n    result_audits:=result_audits || jsonb_build_array(vader_private.append_machine_audit_v1('incident_link_created','incident_events',id::text||':'||linked::text,batch));\n   END IF;")
replace("'incident_ids',result_incidents,'risk_ids',result_risks);","'incident_ids',result_incidents,'risk_ids',result_risks,'audit_ids',result_audits);")
replace("MESSAGE='VADER bundle rejected; transaction rolled back'","MESSAGE='VADER bundle rejected; operation changes rolled back'")
sql='-- Revised Migration02 candidate, TEST review only. Original proposal preserved.\n'+sql
(ROOT/'03_machine_writer_r2.sql').write_text(sql,encoding='utf-8',newline='\n')
(ROOT/'machine_revision_source.json').write_text(json.dumps({'original_proposal_sha256':hashlib.sha256(raw).hexdigest(),
 'revised_candidate_sha256':hashlib.sha256((ROOT/'03_machine_writer_r2.sql').read_bytes()).hexdigest(),
 'original_modified':False},indent=2)+'\n',encoding='utf-8',newline='\n')
print('Prepared revised machine candidate locally; original proposal unchanged. NO SQL executed.')
