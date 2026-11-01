-- Full preservation of historical rows; exact new-object inventory, no schema wildcard exemption.
-- Additional checks below verify definitions and effective permissions independently.
DO $delta$ DECLARE b jsonb:=current_setting('mesh_write.before')::jsonb;
 a jsonb:=current_setting('mesh_write.after')::jsonb; category text; oldrow jsonb; newrow jsonb;
 key_name text; new_count int; allowed int; object_oid oid; audit_oid oid:='public.audit_logs'::regclass;
BEGIN
 IF b->'effective' IS DISTINCT FROM a->'effective' THEN RAISE EXCEPTION 'Existing five-table API permissions changed'; END IF;
 FOREACH category IN ARRAY ARRAY['roles','memberships','schemas','functions','events','defaults','relations','sequences','policies','constraints','indexes','triggers','target_rls'] LOOP
  key_name:=CASE category WHEN 'memberships' THEN NULL WHEN 'sequences' THEN 'seqrelid'
   WHEN 'indexes' THEN 'indexrelid' WHEN 'target_rls' THEN 'table' ELSE 'oid' END;
  IF key_name IS NULL THEN
   -- Exact old/new membership tuples are checked by assert_memberships.sql.
   CONTINUE;
  END IF;
  FOR oldrow IN SELECT value FROM jsonb_array_elements(coalesce(nullif(b#>ARRAY['native',category],'null'::jsonb),'[]'::jsonb)) LOOP
   SELECT value INTO newrow FROM jsonb_array_elements(coalesce(nullif(a#>ARRAY['native',category],'null'::jsonb),'[]'::jsonb)) WHERE value->key_name=oldrow->key_name;
   IF newrow IS NULL THEN RAISE EXCEPTION 'Existing metadata removed: % %',category,oldrow->key_name; END IF;
   IF (category='relations' AND (oldrow->>'oid')::oid IN (audit_oid,'public.security_incidents_incident_number_seq'::regclass))
    OR (category='schemas' AND (oldrow->>'oid')::oid='extensions'::regnamespace)
    OR (category='functions' AND (oldrow->>'oid')::oid='public.is_mesh_member(uuid,public.mesh_role[])'::regprocedure) THEN
    IF oldrow-'acl' IS DISTINCT FROM newrow-'acl' THEN RAISE EXCEPTION 'Audit/sequence non-ACL metadata changed'; END IF;
   ELSIF oldrow IS DISTINCT FROM newrow THEN RAISE EXCEPTION 'Persistent metadata changed: % %',category,oldrow->key_name; END IF;
  END LOOP;
  SELECT count(*) INTO new_count FROM jsonb_array_elements(coalesce(nullif(a#>ARRAY['native',category],'null'::jsonb),'[]'::jsonb)) x
   WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(nullif(b#>ARRAY['native',category],'null'::jsonb),'[]'::jsonb)) y WHERE x.value->key_name=y.value->key_name);
  allowed:=CASE category WHEN 'roles' THEN 3 WHEN 'schemas' THEN 3 WHEN 'functions' THEN 16
   WHEN 'policies' THEN 20 WHEN 'constraints' THEN 20 WHEN 'indexes' THEN 8 WHEN 'triggers' THEN 40
   WHEN 'relations' THEN 0 ELSE 0 END;
  IF category='relations' THEN
   IF new_count<>15 THEN RAISE EXCEPTION 'Expected 4 private tables, 5 private indexes and 3 TOAST table/index pairs'; END IF;
   -- New private table/index/TOAST objects only. Counts are derived from catalog
   -- dependencies, while private table and index inventories are asserted below.
   FOR newrow IN SELECT x.value FROM jsonb_array_elements(a#>'{native,relations}') x WHERE NOT EXISTS
    (SELECT 1 FROM jsonb_array_elements(b#>'{native,relations}') y WHERE y.value->'oid'=x.value->'oid') LOOP
    object_oid:=(newrow->>'oid')::oid;
    IF NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.oid=object_oid AND
     (c.relnamespace='vader_private'::regnamespace OR c.oid IN
      (SELECT reltoastrelid FROM pg_class WHERE relnamespace='vader_private'::regnamespace)
      OR c.oid IN (SELECT i.indexrelid FROM pg_index i JOIN pg_class t ON t.reltoastrelid=i.indrelid WHERE t.relnamespace='vader_private'::regnamespace))) THEN
     RAISE EXCEPTION 'Unexpected new relation'; END IF;
   END LOOP;
  ELSIF new_count<>allowed THEN RAISE EXCEPTION 'Unexpected added metadata count: % expected %, actual %',category,allowed,new_count;
  END IF;
 END LOOP;
 IF (SELECT array_agg(nspname::text ORDER BY nspname) FROM pg_namespace WHERE oid IN
  (SELECT (x->>'oid')::oid FROM jsonb_array_elements(a#>'{native,schemas}') x WHERE NOT EXISTS
  (SELECT 1 FROM jsonb_array_elements(b#>'{native,schemas}') y WHERE y->'oid'=x->'oid'))) <> ARRAY['vader_api','vader_private','vader_user_api'] THEN RAISE EXCEPTION 'New schema inventory'; END IF;
 IF (SELECT array_agg(relname::text ORDER BY relname) FROM pg_class WHERE relnamespace='vader_private'::regnamespace AND relkind='r')
  <>ARRAY['principals','receipts','triage_receipts','triage_versions'] THEN RAISE EXCEPTION 'Private table inventory'; END IF;
 IF (SELECT count(*) FROM pg_class WHERE relnamespace='vader_private'::regnamespace AND relkind='i')<>5 THEN RAISE EXCEPTION 'Private index inventory'; END IF;
 IF (SELECT array_agg(rolname::text ORDER BY rolname) FROM pg_roles WHERE oid IN
  (SELECT (x->>'oid')::oid FROM jsonb_array_elements(a#>'{native,roles}') x WHERE NOT EXISTS
  (SELECT 1 FROM jsonb_array_elements(b#>'{native,roles}') y WHERE y->'oid'=x->'oid'))) <> ARRAY['vader_ingest','vader_triage_owner','vader_writer_owner'] THEN RAISE EXCEPTION 'New role inventory'; END IF;
 -- Changed target table ACLs: only the two named internal owners may be added.
 IF EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) x
  WHERE c.oid IN ('public.security_events'::regclass,'public.security_findings'::regclass,'public.security_incidents'::regclass,'public.incident_events'::regclass,'public.security_risk_scores'::regclass)
  AND x.grantee<>c.relowner AND pg_get_userbyid(x.grantee) NOT IN ('vader_writer_owner','vader_triage_owner')) THEN RAISE EXCEPTION 'Unexpected target table ACL grantee'; END IF;
 -- Audit old ACL tuples, minus exactly the reviewed revocations, must survive.
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(b#>'{native,relations}') t,
 LATERAL aclexplode((ARRAY(SELECT jsonb_array_elements_text(t->'acl')))::aclitem[]) x
 WHERE (t->>'oid')::oid=audit_oid AND NOT
  ((x.grantee=0 OR pg_get_userbyid(x.grantee) IN ('anon','authenticated','service_role'))
   AND x.privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER','MAINTAIN'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) y WHERE c.oid=audit_oid
 AND (x.grantee,x.grantor,x.privilege_type,x.is_grantable)=(y.grantee,y.grantor,y.privilege_type,y.is_grantable))) THEN
 RAISE EXCEPTION 'Unapproved audit ACL removal'; END IF;
END $delta$;
\ir assert_integrity.sql
\ir assert_permissions.sql
\ir assert_acl_delta.sql
\ir assert_acl_exact.sql
\ir assert_memberships.sql
\ir assert_object_contract.sql
\ir capture_columns.sql
SELECT set_config('mesh_write.columns_after',:'write_columns',true) AS ignored \gset
DO $columns$ DECLARE oldrow jsonb; newrow jsonb; b jsonb:=current_setting('mesh_write.columns_before')::jsonb;
 a jsonb:=current_setting('mesh_write.columns_after')::jsonb;
BEGIN
 FOR oldrow IN SELECT value FROM jsonb_array_elements(b) LOOP
  SELECT value INTO newrow FROM jsonb_array_elements(a) WHERE value->'table'=oldrow->'table' AND value->'column'=oldrow->'column';
  IF newrow IS NULL OR oldrow-'acl' IS DISTINCT FROM newrow-'acl' THEN RAISE EXCEPTION 'Existing public column definition changed'; END IF;
  -- No table-wide ACL exemption: assert_acl_exact checks every public column,
  -- including SELECT, all grantees/grantors and grant options.
 END LOOP;
 IF (SELECT jsonb_agg(value->>'column' ORDER BY value->>'column') FROM jsonb_array_elements(a) x
  WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(b) y WHERE y->'table'=x.value->'table' AND y->'column'=x.value->'column'))
  IS DISTINCT FROM '["vader_finding_subject_id","vader_incident_subject_id"]'::jsonb THEN RAISE EXCEPTION 'Unexpected added public columns'; END IF;
END $columns$;
