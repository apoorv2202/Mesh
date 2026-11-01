-- Allow EXACTLY five new effective SELECT cells and five non-grantable ACL items.
DO $delta$
DECLARE b jsonb:=current_setting('mesh_stage4bread.before')::jsonb;
 a jsonb:=current_setting('mesh_stage4bread.granted')::jsonb;
 cell jsonb; old_allowed boolean; changed int:=0; tab jsonb; old_tab jsonb;
 expected_acl jsonb; actual_acl jsonb;
BEGIN
 IF b->'native' IS DISTINCT FROM a->'native' OR b->'column_acls' IS DISTINCT FROM a->'column_acls' THEN
 RAISE EXCEPTION 'Unapproved native/schema/policy/column ACL delta'; END IF;
 IF jsonb_array_length(a->'effective')<>200 OR jsonb_array_length(a->'target_acls')<>5 THEN
 RAISE EXCEPTION 'Incomplete permission-delta snapshot'; END IF;
 FOR cell IN SELECT value FROM jsonb_array_elements(a->'effective') LOOP
  SELECT (value->>'allowed')::boolean INTO old_allowed FROM jsonb_array_elements(b->'effective')
  WHERE value->>'rolname'=cell->>'rolname' AND value->>'relname'=cell->>'relname' AND value->>'privilege'=cell->>'privilege';
  IF old_allowed IS NULL THEN RAISE EXCEPTION 'Unknown effective permission cell'; END IF;
  IF cell->>'rolname'='authenticated' AND cell->>'privilege'='SELECT' THEN
   IF old_allowed OR NOT (cell->>'allowed')::boolean THEN RAISE EXCEPTION 'Wrong authenticated SELECT transition'; END IF;
   changed:=changed+1;
  ELSIF old_allowed IS DISTINCT FROM (cell->>'allowed')::boolean THEN
   RAISE EXCEPTION 'Unauthorized effective privilege change: %',cell;
  END IF;
 END LOOP;
 IF changed<>5 THEN RAISE EXCEPTION 'Expected five SELECT additions'; END IF;
 FOR tab IN SELECT value FROM jsonb_array_elements(a->'target_acls') LOOP
  SELECT value INTO old_tab FROM jsonb_array_elements(b->'target_acls') WHERE value->>'table'=tab->>'table';
  IF old_tab IS NULL OR (old_tab-'acl') IS DISTINCT FROM (tab-'acl') THEN RAISE EXCEPTION 'Target inventory/owner changed'; END IF;
  SELECT jsonb_agg(value ORDER BY value) INTO expected_acl
  FROM jsonb_array_elements(old_tab->'acl' || jsonb_build_array('authenticated=r/postgres'));
  SELECT jsonb_agg(value ORDER BY value) INTO actual_acl FROM jsonb_array_elements(tab->'acl');
  IF actual_acl IS DISTINCT FROM expected_acl THEN RAISE EXCEPTION 'Wrong ACL delta for %',tab->>'table'; END IF;
 END LOOP;
END $delta$;
SELECT jsonb_build_object('record_type','permission_delta','passed',true,
 'effective_select_additions',5,'direct_acl_additions',5,'grantable',false) AS result;
