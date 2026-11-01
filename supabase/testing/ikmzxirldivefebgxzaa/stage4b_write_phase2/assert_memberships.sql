-- Expected PG17 bootstrap creator grants only; never exempt all new-role edges.
DO $memberships$ DECLARE b jsonb:=current_setting('mesh_write.before')::jsonb;
 oldrow jsonb; row_now jsonb; edge record; n int:=0;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE oid=10 AND rolsuper) THEN
  RAISE EXCEPTION 'Unexpected PG17 bootstrap grantor; review, do not broaden'; END IF;
 FOR oldrow IN SELECT value FROM jsonb_array_elements(b#>'{native,memberships}') LOOP
  SELECT to_jsonb(m) INTO row_now FROM pg_auth_members m WHERE m.oid=(oldrow->>'oid')::oid;
  IF row_now IS DISTINCT FROM oldrow THEN RAISE EXCEPTION 'Existing managed membership changed'; END IF;
 END LOOP;
 FOR edge IN SELECT m.*,r.rolname FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid
 WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(b#>'{native,memberships}') x WHERE (x->>'oid')::oid=m.oid) LOOP
  IF edge.rolname NOT IN ('vader_writer_owner','vader_triage_owner','vader_ingest')
   OR edge.member<>(SELECT oid FROM pg_roles WHERE rolname='postgres') OR NOT
    ((edge.grantor=10 AND edge.admin_option AND NOT edge.set_option AND NOT edge.inherit_option)
     OR (edge.grantor=(SELECT oid FROM pg_roles WHERE rolname='postgres') AND NOT edge.admin_option AND edge.set_option AND edge.inherit_option)) THEN
   RAISE EXCEPTION 'Unexpected new role relationship'; END IF;
  n:=n+1;
 END LOOP;
 IF n<>6 OR (SELECT count(DISTINCT m.roleid) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid
 WHERE r.rolname IN ('vader_writer_owner','vader_triage_owner','vader_ingest'))<>3 THEN
  RAISE EXCEPTION 'Expected exactly six scoped creator relationships'; END IF;
 -- SET capability is a separate requirement from ADMIN membership.
 IF NOT pg_has_role('postgres','vader_writer_owner','SET')
 OR NOT pg_has_role('postgres','vader_triage_owner','SET') THEN RAISE EXCEPTION 'Owner transfer SET capability absent'; END IF;
END $memberships$;
