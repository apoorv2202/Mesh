-- Require all 60 previously verified dangerous effective privileges before testing.
DO $check$
DECLARE b jsonb:=current_setting('mesh_stage3.before')::jsonb;
BEGIN
 IF b->'column_acls'<>'null'::jsonb OR
 (SELECT count(*) FROM jsonb_array_elements(b->'effective') e
 WHERE e->>'rolname' IN ('anon','authenticated','service_role')
 AND e->>'privilege' IN ('TRUNCATE','REFERENCES','TRIGGER','MAINTAIN') AND (e->>'allowed')::boolean)<>60 THEN
  RAISE EXCEPTION 'Unexpected baseline: dangerous grants missing or column ACL drift';
 END IF;
END $check$;
