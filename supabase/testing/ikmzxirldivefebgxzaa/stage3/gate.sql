\ir guard.sql
BEGIN;
\ir snapshot.sql
SELECT set_config('mesh_stage3.before', :'snapshot', true) AS ignored \gset
SELECT set_config('mesh_review.security_approved','off',true) AS ignored \gset
DO $test$
BEGIN
 BEGIN
 EXECUTE $tested$DO $guard$
BEGIN
 IF current_setting('mesh_review.security_approved',true) IS DISTINCT FROM 'on' THEN
   RAISE EXCEPTION 'Review-only proposal: security review gate is closed';
 END IF;
END
$guard$;$tested$;
 RAISE EXCEPTION 'Expected closed-gate failure did not occur';
 EXCEPTION WHEN SQLSTATE 'P0001' THEN
  IF SQLERRM<>'Review-only proposal: security review gate is closed' THEN RAISE; END IF;
 END;
END $test$;
\ir snapshot.sql
SELECT set_config('mesh_stage3.restored', :'snapshot', true) AS ignored \gset
DO $restore$ BEGIN
 IF current_setting('mesh_stage3.before')::jsonb IS DISTINCT FROM current_setting('mesh_stage3.restored')::jsonb THEN
 RAISE EXCEPTION 'Closed-gate test changed metadata'; END IF;
END $restore$;
SELECT jsonb_build_object('test','closed_gate','passed',true,'expected_sqlstate','P0001') AS result;
ROLLBACK;
