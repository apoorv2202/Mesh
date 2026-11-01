\ir guard.sql
BEGIN READ ONLY;
\ir snapshot.sql
SELECT set_config('mesh_stage3.before', :'snapshot', true) AS ignored \gset
\ir assert_baseline.sql
SELECT jsonb_build_object('snapshot',:'snapshot'::jsonb,'snapshot_md5',md5(:'snapshot')) AS result;
ROLLBACK;
