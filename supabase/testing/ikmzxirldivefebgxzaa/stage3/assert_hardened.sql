DO $check$
DECLARE b jsonb:=current_setting('mesh_stage3.before')::jsonb;
 a jsonb:=current_setting('mesh_stage3.after')::jsonb;
 e jsonb; old_allowed boolean;
BEGIN
 IF b->'native' IS DISTINCT FROM a->'native' OR b->'column_acls' IS DISTINCT FROM a->'column_acls' THEN
  RAISE EXCEPTION 'Native permissions/roles/policies/schema changed; abort';
 END IF;
 IF jsonb_array_length(a->'effective')<>200 THEN RAISE EXCEPTION 'Incomplete effective-rights matrix'; END IF;
 FOR e IN SELECT value FROM jsonb_array_elements(a->'effective') LOOP
  IF (e->>'privilege' IN ('TRUNCATE','REFERENCES','TRIGGER','MAINTAIN')
      AND e->>'rolname' IN ('anon','authenticated','authenticator','service_role'))
   OR (e->>'privilege' IN ('INSERT','UPDATE','DELETE') AND e->>'rolname' IN ('anon','authenticated')) THEN
   IF (e->>'allowed')::boolean THEN RAISE EXCEPTION 'Residual dangerous/frontend privilege: %',e; END IF;
  ELSE
   SELECT (value->>'allowed')::boolean INTO old_allowed FROM jsonb_array_elements(b->'effective')
   WHERE value->>'rolname'=e->>'rolname' AND value->>'relname'=e->>'relname' AND value->>'privilege'=e->>'privilege';
   IF old_allowed IS DISTINCT FROM (e->>'allowed')::boolean THEN
    RAISE EXCEPTION 'Unexpected legitimate privilege change: %',e;
   END IF;
  END IF;
 END LOOP;
END $check$;
