-- Exact table/sequence ACL tuple differences, including grantor/grant options.
DO $acl$ DECLARE b jsonb:=current_setting('mesh_write.before')::jsonb; t text; item jsonb; c record;
 old_acl aclitem[]; old_right record; new_right record; removed boolean; added boolean;
BEGIN
 FOREACH t IN ARRAY ARRAY['security_events','security_findings','security_incidents','incident_events','security_risk_scores','audit_logs','security_incidents_incident_number_seq'] LOOP
  SELECT * INTO c FROM pg_class WHERE oid=to_regclass('public.'||t);
  IF t IN ('audit_logs','security_incidents_incident_number_seq') THEN
   SELECT value INTO item FROM jsonb_array_elements(b#>'{native,relations}') WHERE (value->>'oid')::oid=c.oid;
  ELSE
   SELECT value INTO item FROM jsonb_array_elements(b->'target_acls') WHERE value->>'table'=t;
  END IF;
  IF item IS NULL THEN RAISE EXCEPTION 'Missing old ACL evidence'; END IF;
  old_acl:=CASE WHEN jsonb_typeof(item->'acl')='array' THEN
   ARRAY(SELECT value::aclitem FROM jsonb_array_elements_text(item->'acl'))
   ELSE acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner) END;
  FOR old_right IN SELECT * FROM aclexplode(old_acl) LOOP
   removed:=t='audit_logs' AND (old_right.grantee=0 OR pg_get_userbyid(old_right.grantee) IN ('anon','authenticated','service_role'))
    AND old_right.privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN');
   IF EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner))) x
    WHERE (x.grantor,x.grantee,x.privilege_type,x.is_grantable)=(old_right.grantor,old_right.grantee,old_right.privilege_type,old_right.is_grantable))=removed THEN
    RAISE EXCEPTION 'Old ACL tuple removal mismatch: %',t; END IF;
  END LOOP;
  FOR new_right IN SELECT * FROM aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner))) LOOP
   IF EXISTS(SELECT 1 FROM aclexplode(old_acl) x WHERE (x.grantor,x.grantee,x.privilege_type,x.is_grantable)=
    (new_right.grantor,new_right.grantee,new_right.privilege_type,new_right.is_grantable)) THEN CONTINUE; END IF;
   added:=NOT new_right.is_grantable AND new_right.grantor=c.relowner AND (
    (t='security_incidents_incident_number_seq' AND pg_get_userbyid(new_right.grantee)='vader_writer_owner' AND new_right.privilege_type='USAGE')
    OR (t IN ('security_events','security_findings','security_incidents','incident_events','security_risk_scores') AND new_right.privilege_type='SELECT'
     AND (pg_get_userbyid(new_right.grantee)='vader_writer_owner' OR (t IN ('security_findings','security_incidents') AND pg_get_userbyid(new_right.grantee)='vader_triage_owner'))));
   IF NOT added THEN RAISE EXCEPTION 'Unapproved ACL tuple addition: %',t; END IF;
  END LOOP;
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid CROSS JOIN LATERAL aclexplode(a.attacl) x
  WHERE c.relnamespace='public'::regnamespace AND a.attnum>0 AND NOT a.attisdropped
  AND pg_get_userbyid(x.grantee) IN ('vader_writer_owner','vader_triage_owner','vader_ingest')
  AND (x.is_grantable OR x.grantor<>c.relowner)) THEN RAISE EXCEPTION 'Unreviewed column grantor/grant option'; END IF;
END $acl$;
