\ir guard.sql
BEGIN READ ONLY;
\ir snapshot.sql
SELECT set_config('mesh_stage3.before', :'snapshot', true) AS ignored \gset
SELECT set_config('mesh_stage3.after', :'snapshot', true) AS ignored \gset
\ir assert_hardened.sql
SELECT :'snapshot'::jsonb AS result;
ROLLBACK;
