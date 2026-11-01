-- Full ordered FK contract, not just a constraint name/count.
DO $assert$ DECLARE e record; c record; child_names text[]; parent_names text[];
BEGIN
 FOR e IN SELECT * FROM (VALUES
 ('security_events','security_events_organization_id_asset_id_fkey','security_assets','asset_id','id','a'),
 ('security_findings','security_findings_organization_id_asset_id_fkey','security_assets','asset_id','id','a'),
 ('security_findings','security_findings_organization_id_source_event_id_fkey','security_events','source_event_id','id','a'),
 ('incident_events','incident_events_organization_id_event_id_fkey','security_events','event_id','id','a'),
 ('incident_events','incident_events_organization_id_incident_id_fkey','security_incidents','incident_id','id','c'),
 ('security_risk_scores','vader_risk_finding_tenant_fk','security_findings','vader_finding_subject_id','id','a'),
 ('security_risk_scores','vader_risk_incident_tenant_fk','security_incidents','vader_incident_subject_id','id','a'),
 ('security_incidents','vader_assignee_tenant_fk','organization_members','assigned_to','user_id','a')
 ) q(child,name,parent,child_key,parent_key,delete_action) LOOP
  SELECT * INTO c FROM pg_constraint WHERE conrelid=to_regclass('public.'||e.child) AND conname=e.name;
  IF NOT FOUND THEN RAISE EXCEPTION 'Missing FK %',e.name; END IF;
  SELECT array_agg(a.attname::text ORDER BY k.n) INTO child_names
   FROM unnest(c.conkey) WITH ORDINALITY k(id,n) JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.id;
  SELECT array_agg(a.attname::text ORDER BY k.n) INTO parent_names
   FROM unnest(c.confkey) WITH ORDINALITY k(id,n) JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.id;
  IF c.contype<>'f' OR NOT c.convalidated OR c.condeferrable OR c.condeferred
   OR c.confmatchtype<>'s' OR c.confupdtype<>'a' OR c.confdeltype::text<>e.delete_action
   OR c.confrelid<>to_regclass('public.'||e.parent)
   OR child_names<>ARRAY['organization_id',e.child_key] OR parent_names<>ARRAY['organization_id',e.parent_key]
  THEN RAISE EXCEPTION 'Tenant FK differs: %',e.name; END IF;
 END LOOP;
 FOR e IN SELECT * FROM (VALUES ('vader_finding_subject_id','finding'),('vader_incident_subject_id','incident')) q(col,kind) LOOP
  SELECT a.attgenerated,format_type(a.atttypid,a.atttypmod) typ,pg_get_expr(d.adbin,d.adrelid) expr INTO c
   FROM pg_attribute a JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE a.attrelid='public.security_risk_scores'::regclass AND a.attname=e.col;
  IF NOT FOUND OR c.attgenerated<>'s' OR c.typ<>'uuid' OR
   regexp_replace(c.expr,'\s','','g')<>format('CASEWHEN(subject_type=%L::text)THENsubject_idELSENULL::uuidEND',e.kind)
  THEN RAISE EXCEPTION 'Risk generated expression differs: %',e.col; END IF;
 END LOOP;
END $assert$;
