-- Exact function prosrc, argument OIDs/names, owner and mode from reviewed candidates.
DO $verify_objects$ DECLARE spec jsonb; f record; expected_types oid[]; expected_names text[]; p record;
 contract jsonb:=$contract${
  "functions": [
    {
      "schema": "vader_private",
      "name": "machine_scope_v1",
      "arg_names": [],
      "arg_types": [],
      "returns": "uuid",
      "language": "plpgsql",
      "definer": true,
      "strict": false,
      "volatility": "v",
      "body": "\nDECLARE principal record; tenant uuid;\nBEGIN\n SELECT oid,rolname,rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb\n INTO principal FROM pg_catalog.pg_roles WHERE rolname=session_user;\n IF NOT FOUND OR NOT principal.rolcanlogin OR principal.rolsuper OR principal.rolbypassrls\n OR principal.rolcreaterole OR principal.rolcreatedb OR principal.rolname IN\n ('postgres','authenticator','anon','authenticated','service_role') THEN\n RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='VADER machine denied'; END IF;\n IF EXISTS(SELECT 1 FROM pg_catalog.pg_roles other WHERE other.oid<>principal.oid\n AND other.rolname<>'vader_ingest' AND pg_catalog.pg_has_role(principal.oid,other.oid,'MEMBER')) THEN\n RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='VADER machine membership denied'; END IF;\n SELECT p.organization_id INTO tenant FROM vader_private.principals p\n WHERE p.principal_oid=principal.oid AND p.principal_name=principal.rolname AND p.enabled FOR SHARE;\n IF tenant IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='VADER machine binding denied'; END IF;\n PERFORM 1 FROM public.organizations WHERE id=tenant AND status='active' FOR SHARE;\n IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='VADER organization denied'; END IF;\n RETURN tenant;\nEND ",
      "owner": "postgres"
    },
    {
      "schema": "vader_private",
      "name": "tenant_v1",
      "arg_names": [],
      "arg_types": [],
      "returns": "uuid",
      "language": "plpgsql",
      "definer": true,
      "strict": false,
      "volatility": "v",
      "body": "\nBEGIN\n RETURN vader_private.machine_scope_v1();\nEND\n",
      "owner": "vader_writer_owner"
    },
    {
      "schema": "vader_private",
      "name": "append_machine_audit_v1",
      "arg_names": [
        "action_name",
        "target_kind",
        "target_key",
        "request_id"
      ],
      "arg_types": [
        "text",
        "text",
        "text",
        "uuid"
      ],
      "returns": "uuid",
      "language": "plpgsql",
      "definer": false,
      "strict": false,
      "volatility": "v",
      "body": "\nDECLARE audit_id uuid:=gen_random_uuid(); tenant uuid:=vader_private.tenant_v1();\nBEGIN\n IF action_name IS NULL OR target_kind IS NULL OR action_name NOT IN ('event_ingested','finding_created','incident_created','incident_link_created','risk_created')\n OR target_kind NOT IN ('security_events','security_findings','security_incidents','incident_events','security_risk_scores')\n OR target_key IS NULL OR request_id IS NULL THEN RAISE EXCEPTION 'Invalid internal audit descriptor'; END IF;\n INSERT INTO public.audit_logs(id,organization_id,actor_user_id,action,target_type,target_id,metadata)\n VALUES(audit_id,tenant,NULL,'vader.'||action_name,target_kind,target_key,\n jsonb_build_object('request_id',request_id,'principal_name',session_user,\n 'principal_oid',(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=session_user),\n 'operation_version','vader-machine-write-r2'));\n RETURN audit_id;\nEND ",
      "owner": "vader_writer_owner"
    },
    {
      "schema": "vader_private",
      "name": "id_v1",
      "arg_names": [
        "kind",
        "tenant",
        "identity_parts"
      ],
      "arg_types": [
        "text",
        "uuid",
        "jsonb"
      ],
      "returns": "uuid",
      "language": "sql",
      "definer": false,
      "strict": true,
      "volatility": "i",
      "body": "\n SELECT extensions.uuid_generate_v5('95980ed1-c0d3-5b64-90cc-9ea71f7b0385'::uuid,\n   jsonb_build_array('mesh-vader-storage-v1',kind,tenant,identity_parts)::text)\n",
      "owner": "vader_writer_owner"
    },
    {
      "schema": "vader_private",
      "name": "claim_v1",
      "arg_names": [
        "kind",
        "id",
        "body"
      ],
      "arg_types": [
        "text",
        "uuid",
        "jsonb"
      ],
      "returns": "boolean",
      "language": "plpgsql",
      "definer": false,
      "strict": false,
      "volatility": "v",
      "body": "\nDECLARE inserted integer; prior jsonb; tenant uuid := vader_private.tenant_v1();\nBEGIN\n INSERT INTO vader_private.receipts(organization_id,kind,object_id,payload)\n VALUES(tenant,kind,id,body) ON CONFLICT DO NOTHING;\n GET DIAGNOSTICS inserted=ROW_COUNT;\n IF inserted=1 THEN RETURN true; END IF;\n SELECT payload INTO prior FROM vader_private.receipts\n WHERE organization_id=tenant AND receipts.kind=claim_v1.kind AND object_id=id;\n IF prior IS DISTINCT FROM body THEN\n  RAISE EXCEPTION USING ERRCODE='22000', MESSAGE='Immutable VADER identity payload conflict';\n END IF;\n RETURN false;\nEND\n",
      "owner": "vader_writer_owner"
    },
    {
      "schema": "vader_api",
      "name": "read_history_v1",
      "arg_names": [
        "actor",
        "from_time",
        "to_time"
      ],
      "arg_types": [
        "text",
        "timestamptz",
        "timestamptz"
      ],
      "returns": "jsonb",
      "language": "plpgsql",
      "definer": true,
      "strict": false,
      "volatility": "v",
      "body": "\nDECLARE tenant uuid := vader_private.tenant_v1(); rows jsonb;\nBEGIN\n IF actor IS NULL OR btrim(actor)='' OR from_time IS NULL OR to_time IS NULL\n    OR to_time<from_time OR to_time-from_time>interval '120 minutes' THEN\n  RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Invalid bounded history scope';\n END IF;\n PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));\n SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY event_time,id),'[]'::jsonb) INTO rows\n FROM (SELECT * FROM public.security_events WHERE organization_id=tenant\n       AND actor_identifier=actor AND event_time BETWEEN from_time AND to_time\n       ORDER BY event_time,id LIMIT 1001) e;\n IF jsonb_array_length(rows)>1000 THEN\n  RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='History scope exceeds bounded writer limit';\n END IF;\n RETURN jsonb_build_object('events',rows,'revision',encode(extensions.digest(convert_to(rows::text,'UTF8'),'sha256'),'hex'));\nEND\n",
      "owner": "vader_writer_owner"
    },
    {
      "schema": "vader_api",
      "name": "commit_bundle_v1",
      "arg_names": [
        "bundle"
      ],
      "arg_types": [
        "jsonb"
      ],
      "returns": "jsonb",
      "language": "plpgsql",
      "definer": true,
      "strict": false,
      "volatility": "v",
      "body": "\nDECLARE\n tenant uuid := vader_private.tenant_v1(); batch uuid; prior jsonb; response jsonb;\n item jsonb; payload jsonb; id uuid; history jsonb; fresh boolean; k text;\n e public.security_events; f public.security_findings; i public.security_incidents; r public.security_risk_scores;\n event_ids uuid[]; linked uuid; previous_time timestamptz; ev public.security_events;\n result_events jsonb:='[]'; result_findings jsonb:='[]'; result_incidents jsonb:='[]'; result_risks jsonb:='[]';\n result_audits jsonb:='[]'; link_created int;\nBEGIN\n IF jsonb_typeof(bundle) IS DISTINCT FROM 'object' OR octet_length(bundle::text)>1048576 THEN\n  RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Invalid or oversized VADER bundle';\n END IF;\n IF EXISTS(SELECT 1 FROM jsonb_object_keys(bundle) z(key) WHERE key NOT IN\n ('request_key','actor','history_from','history_to','history_revision','events','findings','incidents','risks'))\n OR coalesce(btrim(bundle->>'request_key'),'')='' OR coalesce(btrim(bundle->>'actor'),'')='' THEN\n  RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Invalid bundle keys';\n END IF;\n FOREACH k IN ARRAY ARRAY['events','findings','incidents','risks'] LOOP\n  IF jsonb_typeof(bundle->k) IS DISTINCT FROM 'array' THEN\n   RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Required entity array missing';\n  END IF;\n  IF jsonb_array_length(bundle->k)>100 THEN\n   RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='Entity array limit exceeded';\n  END IF;\n END LOOP;\n PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));\n batch:=vader_private.id_v1('bundle',tenant,jsonb_build_array(bundle->>'request_key'));\n IF NOT vader_private.claim_v1('bundle',batch,bundle) THEN\n  SELECT receipts.response INTO response FROM vader_private.receipts\n   WHERE organization_id=tenant AND kind='bundle' AND object_id=batch;\n  IF response IS NULL THEN RAISE EXCEPTION 'Incomplete receipt'; END IF;\n  RETURN response;\n END IF;\n history:=vader_api.read_history_v1(bundle->>'actor',(bundle->>'history_from')::timestamptz,\n                                  (bundle->>'history_to')::timestamptz);\n IF bundle->>'history_revision' IS DISTINCT FROM history->>'revision' THEN\n  RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='Stale history revision; reload and recompute';\n END IF;\n\n FOR item IN SELECT value FROM jsonb_array_elements(bundle->'events') LOOP\n  IF jsonb_typeof(item) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Invalid event object'; END IF;\n  IF EXISTS(SELECT 1 FROM jsonb_object_keys(item) z(key) WHERE key NOT IN ('source','external_event_id','event_type','actor_identifier','source_ip','event_time','details')) THEN\n   RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Unknown event field';\n  END IF;\n  SELECT * INTO e FROM jsonb_populate_record(NULL::public.security_events,item);\n  IF e.source IS NULL OR btrim(e.source)='' OR e.external_event_id IS NULL OR btrim(e.external_event_id)='' OR e.actor_identifier IS DISTINCT FROM bundle->>'actor' OR e.event_time IS NULL OR e.event_type NOT IN ('login','privilege_escalation','sensitive_resource_access','data_transfer') OR e.event_type IS NULL OR jsonb_typeof(e.details) IS DISTINCT FROM 'object' THEN\n   RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Invalid event fields';\n  END IF;\n  IF e.event_time NOT BETWEEN (bundle->>'history_from')::timestamptz AND (bundle->>'history_to')::timestamptz\n     OR (item->>'event_time') !~ '(Z|[+-][0-9]{2}:[0-9]{2})$' THEN\n   RAISE EXCEPTION 'Event time outside scope or missing explicit timezone';\n  END IF;\n  IF (e.event_type='login' AND (jsonb_typeof(e.details->'failed_attempts') IS DISTINCT FROM 'number'\n        OR (e.details->>'failed_attempts') !~ '^[0-9]+$'))\n     OR (e.event_type IN ('privilege_escalation','sensitive_resource_access')\n        AND jsonb_typeof(e.details->'authorized') IS DISTINCT FROM 'boolean')\n     OR (e.event_type='data_transfer' AND (jsonb_typeof(e.details->'bytes_transferred') IS DISTINCT FROM 'number'\n        OR (e.details->>'bytes_transferred') !~ '^[0-9]+$')) THEN\n   RAISE EXCEPTION 'Invalid event-specific details';\n  END IF;\n  id:=vader_private.id_v1('event',tenant,jsonb_build_array(e.source,e.external_event_id));\n  payload:=jsonb_build_object('source',e.source,'external_event_id',e.external_event_id,'event_type',e.event_type,'actor_identifier',e.actor_identifier,'source_ip',e.source_ip,'event_time',e.event_time,'details',e.details);\n  fresh:=vader_private.claim_v1('event',id,payload);\n  IF fresh THEN\n   INSERT INTO public.security_events(id,organization_id,source,external_event_id,event_type,actor_identifier,source_ip,event_time,details)\n   VALUES(id,tenant,e.source,e.external_event_id,e.event_type,e.actor_identifier,e.source_ip,e.event_time,e.details);\n   result_audits:=result_audits || jsonb_build_array(vader_private.append_machine_audit_v1('event_ingested','security_events',id::text,batch));\n  ELSIF NOT EXISTS(SELECT 1 FROM public.security_events WHERE organization_id=tenant AND security_events.id=commit_bundle_v1.id) THEN\n   RAISE EXCEPTION 'Receipt row missing; administrative reconciliation required';\n  END IF;\n  result_events:=result_events || jsonb_build_array(id);\n END LOOP;\n\n FOR item IN SELECT value FROM jsonb_array_elements(bundle->'findings') LOOP\n  IF jsonb_typeof(item) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Invalid finding object'; END IF;\n  IF EXISTS(SELECT 1 FROM jsonb_object_keys(item) z(key) WHERE key NOT IN ('source_event_id','title','description','finding_type','severity','evidence')) THEN\n   RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Unknown finding field';\n  END IF;\n  SELECT * INTO f FROM jsonb_populate_record(NULL::public.security_findings,item);\n  IF f.source_event_id IS NULL OR coalesce(btrim(f.title),'')='' OR coalesce(btrim(f.finding_type),'')='' OR f.severity IS NULL OR jsonb_typeof(f.evidence) IS DISTINCT FROM 'object' OR coalesce(btrim(f.evidence->>'detector_version'),'')='' THEN\n   RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Invalid finding fields';\n  END IF;\n  IF NOT EXISTS(SELECT 1 FROM public.security_events WHERE organization_id=tenant AND security_events.id=f.source_event_id\n    AND actor_identifier=bundle->>'actor' AND event_time BETWEEN (bundle->>'history_from')::timestamptz AND (bundle->>'history_to')::timestamptz) THEN\n   RAISE EXCEPTION USING ERRCODE='23503',MESSAGE='Finding event outside authorized scope';\n  END IF;\n  id:=vader_private.id_v1('finding',tenant,jsonb_build_array(f.source_event_id,f.finding_type,f.evidence->>'detector_version'));\n  payload:=jsonb_build_object('source_event_id',f.source_event_id,'title',f.title,'description',f.description,'finding_type',f.finding_type,'severity',f.severity,'evidence',f.evidence);\n  fresh:=vader_private.claim_v1('finding',id,payload);\n  IF fresh THEN\n   INSERT INTO public.security_findings(id,organization_id,source_event_id,title,description,finding_type,severity,evidence)\n   VALUES(id,tenant,f.source_event_id,f.title,f.description,f.finding_type,f.severity,f.evidence);\n   result_audits:=result_audits || jsonb_build_array(vader_private.append_machine_audit_v1('finding_created','security_findings',id::text,batch));\n  ELSIF NOT EXISTS(SELECT 1 FROM public.security_findings WHERE organization_id=tenant AND security_findings.id=commit_bundle_v1.id) THEN\n   RAISE EXCEPTION 'Receipt row missing; administrative reconciliation required';\n  END IF;\n  result_findings:=result_findings || jsonb_build_array(id);\n END LOOP;\n\n FOR item IN SELECT value FROM jsonb_array_elements(bundle->'incidents') LOOP\n  IF jsonb_typeof(item) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Invalid incident object'; END IF;\n  IF EXISTS(SELECT 1 FROM jsonb_object_keys(item) z(key) WHERE key NOT IN ('title','description','severity','risk_score','confidence','summary')) THEN\n   RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Unknown incident field';\n  END IF;\n  SELECT * INTO i FROM jsonb_populate_record(NULL::public.security_incidents,item);\n  IF coalesce(btrim(i.title),'')='' OR i.severity IS NULL OR jsonb_typeof(i.summary) IS DISTINCT FROM 'object' OR coalesce(btrim(i.summary->>'correlation_version'),'')='' OR jsonb_typeof(i.summary->'ordered_event_ids') IS DISTINCT FROM 'array' THEN\n   RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Invalid incident fields';\n  END IF;\n  IF jsonb_array_length(i.summary->'ordered_event_ids')<>4 THEN RAISE EXCEPTION 'Four-stage chain required'; END IF;\n  SELECT array_agg(value::uuid ORDER BY ord) INTO event_ids\n   FROM jsonb_array_elements_text(i.summary->'ordered_event_ids') WITH ORDINALITY z(value,ord);\n  -- Canonical UUID values, not caller JSON spelling/case, define chain identity.\n  i.summary:=jsonb_set(i.summary,'{ordered_event_ids}',to_jsonb(event_ids));\n  IF (SELECT count(DISTINCT u) FROM unnest(event_ids) u)<>4 THEN RAISE EXCEPTION 'Duplicate chain event'; END IF;\n  previous_time:=NULL;\n  FOREACH linked IN ARRAY event_ids LOOP\n   SELECT * INTO ev FROM public.security_events WHERE organization_id=tenant AND security_events.id=linked\n    AND actor_identifier=bundle->>'actor'\n    AND event_time BETWEEN (bundle->>'history_from')::timestamptz AND (bundle->>'history_to')::timestamptz;\n   IF NOT FOUND OR (previous_time IS NOT NULL AND ev.event_time<=previous_time) THEN\n    RAISE EXCEPTION USING ERRCODE='23503',MESSAGE='Chain event outside ordered tenant scope';\n   END IF;\n   IF (CASE array_position(event_ids,linked)\n     WHEN 1 THEN ev.event_type='login' AND (ev.details->>'failed_attempts')::numeric>=5\n     WHEN 2 THEN ev.event_type='privilege_escalation' AND ev.details->'authorized'='false'::jsonb\n     WHEN 3 THEN ev.event_type='sensitive_resource_access' AND ev.details->'authorized'='false'::jsonb\n     WHEN 4 THEN ev.event_type='data_transfer' AND (ev.details->>'bytes_transferred')::numeric>=1000000000\n     ELSE false END) IS NOT TRUE THEN\n    RAISE EXCEPTION 'Chain stages do not match Phase 1 demonstration rules';\n   END IF;\n   previous_time:=ev.event_time;\n  END LOOP;\n  IF (SELECT max(event_time)-min(event_time) FROM public.security_events WHERE organization_id=tenant AND security_events.id=ANY(event_ids))>interval '60 minutes' THEN\n   RAISE EXCEPTION 'Chain exceeds correlation window';\n  END IF;\n  id:=vader_private.id_v1('incident',tenant,jsonb_build_array(i.summary->'ordered_event_ids',i.summary->>'correlation_version'));\n  payload:=jsonb_build_object('title',i.title,'description',i.description,'severity',i.severity,'risk_score',i.risk_score,'confidence',i.confidence,'summary',i.summary);\n  fresh:=vader_private.claim_v1('incident',id,payload);\n  IF fresh THEN\n   INSERT INTO public.security_incidents(id,organization_id,title,description,severity,risk_score,confidence,summary)\n   VALUES(id,tenant,i.title,i.description,i.severity,i.risk_score,i.confidence,i.summary);\n   result_audits:=result_audits || jsonb_build_array(vader_private.append_machine_audit_v1('incident_created','security_incidents',id::text,batch));\n  ELSIF NOT EXISTS(SELECT 1 FROM public.security_incidents WHERE organization_id=tenant AND security_incidents.id=commit_bundle_v1.id) THEN\n   RAISE EXCEPTION 'Receipt row missing; administrative reconciliation required';\n  END IF;\n  result_incidents:=result_incidents || jsonb_build_array(id);\n  FOREACH linked IN ARRAY event_ids LOOP\n   INSERT INTO public.incident_events(organization_id,incident_id,event_id)\n    VALUES(tenant,id,linked) ON CONFLICT (incident_id,event_id) DO NOTHING;\n   GET DIAGNOSTICS link_created=ROW_COUNT;\n   IF link_created=1 THEN\n    result_audits:=result_audits || jsonb_build_array(vader_private.append_machine_audit_v1('incident_link_created','incident_events',id::text||':'||linked::text,batch));\n   END IF;\n   IF NOT EXISTS(SELECT 1 FROM public.incident_events WHERE organization_id=tenant AND incident_id=id AND event_id=linked) THEN\n    RAISE EXCEPTION 'Incident link integrity failure';\n   END IF;\n  END LOOP;\n END LOOP;\n\n FOR item IN SELECT value FROM jsonb_array_elements(bundle->'risks') LOOP\n  IF jsonb_typeof(item) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Invalid risk object'; END IF;\n  IF EXISTS(SELECT 1 FROM jsonb_object_keys(item) z(key) WHERE key NOT IN ('subject_type','subject_id','score','confidence','factors','explanation','model_version')) THEN\n   RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Unknown risk field';\n  END IF;\n  SELECT * INTO r FROM jsonb_populate_record(NULL::public.security_risk_scores,item);\n  IF r.subject_type IS NULL OR r.subject_type NOT IN ('finding','incident') OR r.subject_id IS NULL OR r.score IS NULL OR coalesce(btrim(r.model_version),'')='' OR jsonb_typeof(r.factors) IS DISTINCT FROM 'object' OR coalesce(btrim(r.factors->>'input_revision'),'')='' THEN\n   RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='Invalid risk fields';\n  END IF;\n  IF (r.subject_type='finding' AND NOT EXISTS(SELECT 1 FROM public.security_findings WHERE organization_id=tenant AND security_findings.id=r.subject_id))\n     OR (r.subject_type='incident' AND NOT EXISTS(SELECT 1 FROM public.security_incidents WHERE organization_id=tenant AND security_incidents.id=r.subject_id)) THEN\n   RAISE EXCEPTION USING ERRCODE='23503',MESSAGE='Risk subject outside authorized tenant';\n  END IF;\n  id:=vader_private.id_v1('risk',tenant,jsonb_build_array(r.subject_type,r.subject_id,r.factors->>'input_revision',r.model_version));\n  payload:=jsonb_build_object('subject_type',r.subject_type,'subject_id',r.subject_id,'score',r.score,'confidence',r.confidence,'factors',r.factors,'explanation',r.explanation,'model_version',r.model_version);\n  fresh:=vader_private.claim_v1('risk',id,payload);\n  IF fresh THEN\n   INSERT INTO public.security_risk_scores(id,organization_id,subject_type,subject_id,score,confidence,factors,explanation,model_version)\n   VALUES(id,tenant,r.subject_type,r.subject_id,r.score,r.confidence,r.factors,r.explanation,r.model_version);\n   result_audits:=result_audits || jsonb_build_array(vader_private.append_machine_audit_v1('risk_created','security_risk_scores',id::text,batch));\n  ELSIF NOT EXISTS(SELECT 1 FROM public.security_risk_scores WHERE organization_id=tenant AND security_risk_scores.id=commit_bundle_v1.id) THEN\n   RAISE EXCEPTION 'Receipt row missing; administrative reconciliation required';\n  END IF;\n  result_risks:=result_risks || jsonb_build_array(id);\n END LOOP;\n\n response:=jsonb_build_object('request_id',batch,'event_ids',result_events,'finding_ids',result_findings,\n                             'incident_ids',result_incidents,'risk_ids',result_risks,'audit_ids',result_audits);\n UPDATE vader_private.receipts SET response=commit_bundle_v1.response\n WHERE organization_id=tenant AND kind='bundle' AND object_id=batch;\n RETURN response;\nEXCEPTION WHEN OTHERS THEN\n -- Do not relay raw FK/key values, evidence or upstream payloads to callers.\n RAISE EXCEPTION USING ERRCODE=SQLSTATE,MESSAGE='VADER bundle rejected; operation changes rolled back';\nEND\n",
      "owner": "vader_writer_owner"
    },
    {
      "schema": "vader_private",
      "name": "human_guard_v1",
      "arg_names": [
        "tenant",
        "assignee"
      ],
      "arg_types": [
        "uuid",
        "uuid"
      ],
      "returns": "uuid",
      "language": "plpgsql",
      "definer": true,
      "strict": false,
      "volatility": "v",
      "body": "\nDECLARE actor uuid:=auth.uid(); m record; actor_ok boolean:=false; assignee_ok boolean:=assignee IS NULL;\nBEGIN\n IF actor IS NULL OR tenant IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='VADER human scope denied'; END IF;\n PERFORM 1 FROM public.organizations WHERE id=tenant AND status='active' FOR SHARE;\n IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='VADER human scope denied'; END IF;\n FOR m IN SELECT user_id,role,status FROM public.organization_members\n WHERE organization_id=tenant AND user_id IN (actor,assignee) ORDER BY user_id FOR SHARE LOOP\n  IF m.user_id=actor AND m.role='security_team' AND m.status='active' THEN actor_ok:=true; END IF;\n  IF m.user_id=assignee AND m.role='security_team' AND m.status='active' THEN assignee_ok:=true; END IF;\n END LOOP;\n IF NOT actor_ok OR NOT assignee_ok THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='VADER human scope denied'; END IF;\n RETURN actor;\nEND ",
      "owner": "postgres"
    },
    {
      "schema": "vader_private",
      "name": "triage_token_v1",
      "arg_names": [
        "kind",
        "state"
      ],
      "arg_types": [
        "text",
        "jsonb"
      ],
      "returns": "text",
      "language": "sql",
      "definer": true,
      "strict": true,
      "volatility": "i",
      "body": "\n SELECT encode(extensions.digest(convert_to(jsonb_build_array('vader-triage-state-v1',kind,state)::text,'UTF8'),'sha256'),'hex')\n",
      "owner": "postgres"
    },
    {
      "schema": "vader_private",
      "name": "transition_allowed_v1",
      "arg_names": [
        "kind",
        "prior",
        "next_state"
      ],
      "arg_types": [
        "text",
        "text",
        "text"
      ],
      "returns": "boolean",
      "language": "sql",
      "definer": false,
      "strict": true,
      "volatility": "i",
      "body": "\n SELECT (prior=next_state AND prior NOT IN ('resolved','false_positive','accepted_risk')) OR\n CASE WHEN kind='finding' THEN\n  (prior='open' AND next_state='investigating') OR\n  (prior='investigating' AND next_state='remediating') OR\n  (prior='remediating' AND next_state='resolved') OR\n  (prior IN ('open','investigating') AND next_state='false_positive') OR\n  (prior IN ('resolved','false_positive') AND next_state='investigating')\n WHEN kind='incident' THEN\n  (prior='detected' AND next_state='triaged') OR (prior='triaged' AND next_state='investigating') OR\n  (prior='investigating' AND next_state='contained') OR (prior='contained' AND next_state='remediating') OR\n  (prior='remediating' AND next_state='recovering') OR (prior='recovering' AND next_state='resolved') OR\n  (prior IN ('detected','triaged','investigating') AND next_state='false_positive') OR\n  (prior IN ('resolved','false_positive') AND next_state='triaged') ELSE false END\n",
      "owner": "vader_triage_owner"
    },
    {
      "schema": "vader_private",
      "name": "triage_v1",
      "arg_names": [
        "kind",
        "request"
      ],
      "arg_types": [
        "text",
        "jsonb"
      ],
      "returns": "jsonb",
      "language": "plpgsql",
      "definer": true,
      "strict": false,
      "volatility": "v",
      "body": "\nDECLARE tenant uuid; target uuid; actor uuid; assignment uuid; key text; before_state jsonb;\n after_state jsonb; prior_payload jsonb; answer jsonb; requested_status text; reason text;\n f public.security_findings; i public.security_incidents; current_revision bigint; fresh int; audit_id uuid:=gen_random_uuid();\nBEGIN\n IF kind NOT IN ('finding','incident') OR jsonb_typeof(request) IS DISTINCT FROM 'object'\n OR octet_length(request::text)>16384 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid triage input'; END IF;\n IF EXISTS(SELECT 1 FROM jsonb_object_keys(request) AS z(key) WHERE z.key NOT IN\n ('organization_id','target_id','request_key','expected_state','reason','status',\n CASE WHEN kind='finding' THEN 'remediation' ELSE 'assigned_to' END)) THEN\n RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Unknown triage column'; END IF;\n tenant:=(request->>'organization_id')::uuid; target:=(request->>'target_id')::uuid;\n key:=request->>'request_key';reason:=request->>'reason';\n IF tenant IS NULL OR target IS NULL OR coalesce(length(btrim(key)),0) NOT BETWEEN 1 AND 256\n OR coalesce(length(btrim(reason)),0) NOT BETWEEN 1 AND 2000\n OR coalesce(length(request->>'expected_state'),0)<>64 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Missing triage fields'; END IF;\n IF kind='incident' AND request ? 'assigned_to' THEN assignment:=(request->>'assigned_to')::uuid; END IF;\n actor:=vader_private.human_guard_v1(tenant,assignment);\n -- Serialize same actor/request before row locks. Cross-actor updates use row lock + token.\n INSERT INTO vader_private.triage_receipts(organization_id,actor_user_id,operation,request_key,payload)\n VALUES(tenant,actor,kind,key,request) ON CONFLICT DO NOTHING;\n GET DIAGNOSTICS fresh=ROW_COUNT;\n IF fresh=0 THEN\n  SELECT r.payload,r.response INTO prior_payload,answer FROM vader_private.triage_receipts r\n  WHERE r.organization_id=tenant AND r.actor_user_id=actor AND r.operation=kind AND r.request_key=key;\n  IF prior_payload IS DISTINCT FROM request THEN RAISE EXCEPTION USING ERRCODE='22000',MESSAGE='Triage replay conflict'; END IF;\n  IF answer IS NULL THEN RAISE EXCEPTION 'Incomplete triage receipt'; END IF;\n  RETURN answer;\n END IF;\n IF kind='finding' THEN\n  SELECT * INTO f FROM public.security_findings WHERE organization_id=tenant AND id=target FOR UPDATE;\n  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Triage target denied'; END IF;\n  before_state:=jsonb_build_object('organization_id',tenant,'id',target,'status',f.status,'remediation',f.remediation,'resolved_at',f.resolved_at);\n ELSE\n  SELECT * INTO i FROM public.security_incidents WHERE organization_id=tenant AND id=target FOR UPDATE;\n  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Triage target denied'; END IF;\n  before_state:=jsonb_build_object('organization_id',tenant,'id',target,'status',i.status,'assigned_to',i.assigned_to,'resolved_at',i.resolved_at);\n END IF;\n SELECT coalesce((SELECT v.revision FROM vader_private.triage_versions v\n WHERE v.organization_id=tenant AND v.operation=kind AND v.target_id=target),0) INTO current_revision;\n before_state:=before_state || jsonb_build_object('revision',current_revision);\n IF kind='incident' AND NOT (request ? 'assigned_to') AND i.assigned_to IS NOT NULL THEN\n  PERFORM vader_private.human_guard_v1(tenant,i.assigned_to);\n END IF;\n IF request->>'expected_state' IS DISTINCT FROM vader_private.triage_token_v1(kind,before_state) THEN\n RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Stale triage state'; END IF;\n requested_status:=CASE WHEN request ? 'status' THEN request->>'status' ELSE before_state->>'status' END;\n IF requested_status IS NULL OR NOT vader_private.transition_allowed_v1(kind,before_state->>'status',requested_status) THEN\n RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Unapproved triage transition'; END IF;\n IF kind='finding' THEN\n  IF request ? 'remediation' AND request->'remediation'<>'null'::jsonb AND\n    (jsonb_typeof(request->'remediation')<>'string' OR length(request->>'remediation')>4000) THEN\n   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid remediation'; END IF;\n  UPDATE public.security_findings SET status=requested_status,\n   remediation=CASE WHEN request ? 'remediation' THEN request->>'remediation' ELSE f.remediation END,\n   resolved_at=CASE WHEN requested_status=before_state->>'status' THEN f.resolved_at\n     WHEN requested_status IN ('resolved','false_positive') THEN clock_timestamp() ELSE NULL END\n  WHERE organization_id=tenant AND id=target RETURNING * INTO f;\n  after_state:=jsonb_build_object('organization_id',tenant,'id',target,'status',f.status,'remediation',f.remediation,'resolved_at',f.resolved_at);\n ELSE\n  UPDATE public.security_incidents SET status=requested_status,\n   assigned_to=CASE WHEN request ? 'assigned_to' THEN assignment ELSE i.assigned_to END,\n   resolved_at=CASE WHEN requested_status=before_state->>'status' THEN i.resolved_at\n     WHEN requested_status IN ('resolved','false_positive') THEN clock_timestamp() ELSE NULL END\n  WHERE organization_id=tenant AND id=target RETURNING * INTO i;\n  after_state:=jsonb_build_object('organization_id',tenant,'id',target,'status',i.status,'assigned_to',i.assigned_to,'resolved_at',i.resolved_at);\n END IF;\n IF (before_state-'revision')=after_state THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='No triage change requested'; END IF;\n INSERT INTO vader_private.triage_versions(organization_id,operation,target_id,revision)\n VALUES(tenant,kind,target,current_revision+1)\n ON CONFLICT(organization_id,operation,target_id) DO UPDATE SET revision=EXCLUDED.revision;\n after_state:=after_state || jsonb_build_object('revision',current_revision+1);\n INSERT INTO public.audit_logs(id,organization_id,actor_user_id,action,target_type,target_id,metadata)\n VALUES(audit_id,tenant,actor,'vader.'||kind||'_triaged',CASE WHEN kind='finding' THEN 'security_findings' ELSE 'security_incidents' END,target::text,\n jsonb_build_object('request_key',key,'operation_version','vader-triage-v1','reason',reason,\n 'before_status',before_state->>'status','after_status',after_state->>'status',\n 'before_assigned_to',before_state->'assigned_to','after_assigned_to',after_state->'assigned_to',\n 'before_state_token',vader_private.triage_token_v1(kind,before_state),'after_state_token',vader_private.triage_token_v1(kind,after_state)));\n answer:=jsonb_build_object('target_id',target,'state',after_state,'state_token',vader_private.triage_token_v1(kind,after_state),'audit_id',audit_id);\n UPDATE vader_private.triage_receipts SET response=answer\n WHERE organization_id=tenant AND actor_user_id=actor AND operation=kind AND request_key=key;\n RETURN answer;\nEXCEPTION WHEN OTHERS THEN\n RAISE EXCEPTION USING ERRCODE=SQLSTATE,MESSAGE='VADER triage rejected; operation changes rolled back';\nEND ",
      "owner": "vader_triage_owner"
    },
    {
      "schema": "vader_private",
      "name": "triage_state_v1",
      "arg_names": [
        "kind",
        "tenant",
        "target"
      ],
      "arg_types": [
        "text",
        "uuid",
        "uuid"
      ],
      "returns": "jsonb",
      "language": "plpgsql",
      "definer": true,
      "strict": false,
      "volatility": "v",
      "body": "\nDECLARE state jsonb;\nBEGIN\n PERFORM vader_private.human_guard_v1(tenant,NULL);\n IF kind='finding' THEN\n  SELECT jsonb_build_object('organization_id',tenant,'id',id,'status',status,'remediation',remediation,'resolved_at',resolved_at,'revision',coalesce((SELECT v.revision FROM vader_private.triage_versions v WHERE v.organization_id=tenant AND v.operation=kind AND v.target_id=target),0))\n  INTO state FROM public.security_findings WHERE organization_id=tenant AND id=target;\n ELSIF kind='incident' THEN\n  SELECT jsonb_build_object('organization_id',tenant,'id',id,'status',status,'assigned_to',assigned_to,'resolved_at',resolved_at,'revision',coalesce((SELECT v.revision FROM vader_private.triage_versions v WHERE v.organization_id=tenant AND v.operation=kind AND v.target_id=target),0))\n  INTO state FROM public.security_incidents WHERE organization_id=tenant AND id=target;\n END IF;\n IF state IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Triage state denied'; END IF;\n RETURN jsonb_build_object('state',state,'state_token',vader_private.triage_token_v1(kind,state));\nEND ",
      "owner": "vader_triage_owner"
    },
    {
      "schema": "vader_user_api",
      "name": "triage_finding_v1",
      "arg_names": [
        "request"
      ],
      "arg_types": [
        "jsonb"
      ],
      "returns": "jsonb",
      "language": "sql",
      "definer": true,
      "strict": false,
      "volatility": "v",
      "body": " SELECT vader_private.triage_v1('finding',request) ",
      "owner": "vader_triage_owner"
    },
    {
      "schema": "vader_user_api",
      "name": "triage_incident_v1",
      "arg_names": [
        "request"
      ],
      "arg_types": [
        "jsonb"
      ],
      "returns": "jsonb",
      "language": "sql",
      "definer": true,
      "strict": false,
      "volatility": "v",
      "body": " SELECT vader_private.triage_v1('incident',request) ",
      "owner": "vader_triage_owner"
    },
    {
      "schema": "vader_user_api",
      "name": "finding_state_v1",
      "arg_names": [
        "tenant",
        "target"
      ],
      "arg_types": [
        "uuid",
        "uuid"
      ],
      "returns": "jsonb",
      "language": "sql",
      "definer": true,
      "strict": false,
      "volatility": "v",
      "body": " SELECT vader_private.triage_state_v1('finding',tenant,target) ",
      "owner": "vader_triage_owner"
    },
    {
      "schema": "vader_user_api",
      "name": "incident_state_v1",
      "arg_names": [
        "tenant",
        "target"
      ],
      "arg_types": [
        "uuid",
        "uuid"
      ],
      "returns": "jsonb",
      "language": "sql",
      "definer": true,
      "strict": false,
      "volatility": "v",
      "body": " SELECT vader_private.triage_state_v1('incident',tenant,target) ",
      "owner": "vader_triage_owner"
    }
  ],
  "policies": [
    {
      "name": "vader_principal_self_read",
      "schema": "vader_private",
      "table": "principals",
      "command": "r",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_machine_audit_insert",
      "schema": "public",
      "table": "audit_logs",
      "command": "a",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_receipt_scope",
      "schema": "vader_private",
      "table": "receipts",
      "command": "*",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_writer_select",
      "schema": "public",
      "table": "security_events",
      "command": "r",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_writer_insert",
      "schema": "public",
      "table": "security_events",
      "command": "a",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_writer_select",
      "schema": "public",
      "table": "security_findings",
      "command": "r",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_writer_insert",
      "schema": "public",
      "table": "security_findings",
      "command": "a",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_writer_select",
      "schema": "public",
      "table": "security_incidents",
      "command": "r",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_writer_insert",
      "schema": "public",
      "table": "security_incidents",
      "command": "a",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_writer_select",
      "schema": "public",
      "table": "incident_events",
      "command": "r",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_writer_insert",
      "schema": "public",
      "table": "incident_events",
      "command": "a",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_writer_select",
      "schema": "public",
      "table": "security_risk_scores",
      "command": "r",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_writer_insert",
      "schema": "public",
      "table": "security_risk_scores",
      "command": "a",
      "role": "vader_writer_owner"
    },
    {
      "name": "vader_triage_select",
      "schema": "public",
      "table": "security_findings",
      "command": "r",
      "role": "vader_triage_owner"
    },
    {
      "name": "vader_triage_update",
      "schema": "public",
      "table": "security_findings",
      "command": "w",
      "role": "vader_triage_owner"
    },
    {
      "name": "vader_triage_select",
      "schema": "public",
      "table": "security_incidents",
      "command": "r",
      "role": "vader_triage_owner"
    },
    {
      "name": "vader_triage_update",
      "schema": "public",
      "table": "security_incidents",
      "command": "w",
      "role": "vader_triage_owner"
    },
    {
      "name": "vader_human_receipt_scope",
      "schema": "vader_private",
      "table": "triage_receipts",
      "command": "*",
      "role": "vader_triage_owner"
    },
    {
      "name": "vader_human_audit_insert",
      "schema": "public",
      "table": "audit_logs",
      "command": "a",
      "role": "vader_triage_owner"
    },
    {
      "name": "vader_human_version_scope",
      "schema": "vader_private",
      "table": "triage_versions",
      "command": "*",
      "role": "vader_triage_owner"
    }
  ],
  "ownership_transfers": [
    {
      "schema": "vader_private",
      "name": "tenant_v1",
      "arg_types": [],
      "owner": "vader_writer_owner"
    },
    {
      "schema": "vader_private",
      "name": "append_machine_audit_v1",
      "arg_types": [
        "text",
        "text",
        "text",
        "uuid"
      ],
      "owner": "vader_writer_owner"
    },
    {
      "schema": "vader_private",
      "name": "id_v1",
      "arg_types": [
        "text",
        "uuid",
        "jsonb"
      ],
      "owner": "vader_writer_owner"
    },
    {
      "schema": "vader_private",
      "name": "claim_v1",
      "arg_types": [
        "text",
        "uuid",
        "jsonb"
      ],
      "owner": "vader_writer_owner"
    },
    {
      "schema": "vader_api",
      "name": "read_history_v1",
      "arg_types": [
        "text",
        "timestamp with time zone",
        "timestamp with time zone"
      ],
      "owner": "vader_writer_owner"
    },
    {
      "schema": "vader_api",
      "name": "commit_bundle_v1",
      "arg_types": [
        "jsonb"
      ],
      "owner": "vader_writer_owner"
    },
    {
      "schema": "vader_private",
      "name": "transition_allowed_v1",
      "arg_types": [
        "text",
        "text",
        "text"
      ],
      "owner": "vader_triage_owner"
    },
    {
      "schema": "vader_private",
      "name": "triage_v1",
      "arg_types": [
        "text",
        "jsonb"
      ],
      "owner": "vader_triage_owner"
    },
    {
      "schema": "vader_private",
      "name": "triage_state_v1",
      "arg_types": [
        "text",
        "uuid",
        "uuid"
      ],
      "owner": "vader_triage_owner"
    },
    {
      "schema": "vader_user_api",
      "name": "triage_finding_v1",
      "arg_types": [
        "jsonb"
      ],
      "owner": "vader_triage_owner"
    },
    {
      "schema": "vader_user_api",
      "name": "triage_incident_v1",
      "arg_types": [
        "jsonb"
      ],
      "owner": "vader_triage_owner"
    },
    {
      "schema": "vader_user_api",
      "name": "finding_state_v1",
      "arg_types": [
        "uuid",
        "uuid"
      ],
      "owner": "vader_triage_owner"
    },
    {
      "schema": "vader_user_api",
      "name": "incident_state_v1",
      "arg_types": [
        "uuid",
        "uuid"
      ],
      "owner": "vader_triage_owner"
    }
  ]
}$contract$::jsonb;
BEGIN
 FOR spec IN SELECT value FROM jsonb_array_elements(contract->'functions') LOOP
  SELECT coalesce(array_agg(to_regtype(x.value)::oid ORDER BY x.n),'{}'::oid[]) INTO expected_types
   FROM jsonb_array_elements_text(spec->'arg_types') WITH ORDINALITY x(value,n);
  SELECT array_agg(x.value ORDER BY x.n) INTO expected_names FROM jsonb_array_elements_text(spec->'arg_names') WITH ORDINALITY x(value,n);
  SELECT q.*,l.lanname INTO f FROM pg_proc q JOIN pg_namespace n ON n.oid=q.pronamespace JOIN pg_language l ON l.oid=q.prolang
   WHERE n.nspname=spec->>'schema' AND q.proname=spec->>'name' AND q.proargtypes::oid[]=expected_types;
  -- oidvector::oid[] can carry a zero lower bound: compare via ordered unnest below.
  IF NOT FOUND THEN
   SELECT q.*,l.lanname INTO f FROM pg_proc q JOIN pg_namespace n ON n.oid=q.pronamespace JOIN pg_language l ON l.oid=q.prolang
    WHERE n.nspname=spec->>'schema' AND q.proname=spec->>'name' AND
     ARRAY(SELECT unnest(q.proargtypes))=expected_types;
  END IF;
  IF NOT FOUND OR f.prosrc IS DISTINCT FROM spec->>'body' OR f.proargnames IS DISTINCT FROM expected_names
   OR f.prorettype<>to_regtype(spec->>'returns') OR f.lanname<>spec->>'language'
   OR pg_get_userbyid(f.proowner)<>spec->>'owner' OR f.prosecdef<>(spec->>'definer')::boolean
   OR f.proisstrict<>(spec->>'strict')::boolean OR f.provolatile::text<>spec->>'volatility' THEN
   RAISE EXCEPTION 'Exact function contract mismatch: %.%',spec->>'schema',spec->>'name'; END IF;
 END LOOP;
 FOR spec IN SELECT value FROM jsonb_array_elements(contract->'policies') LOOP
  SELECT * INTO p FROM pg_policy WHERE polrelid=to_regclass((spec->>'schema')||'.'||(spec->>'table')) AND polname=spec->>'name';
  IF NOT FOUND OR NOT p.polpermissive OR p.polcmd::text<>spec->>'command'
   OR p.polroles<>ARRAY[(SELECT oid FROM pg_roles WHERE rolname=spec->>'role')] THEN RAISE EXCEPTION 'Policy role/command inventory mismatch'; END IF;
 END LOOP;
END $verify_objects$;
