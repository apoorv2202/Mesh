-- Fresh connection only. No DELETE/DROP/setval/Auth management.
\ir guard.sql
BEGIN READ ONLY;
SELECT set_config('mesh_stage4.user_a', :'user_a',true) AS ignored \gset
SELECT set_config('mesh_stage4.user_b', :'user_b',true) AS ignored \gset
\set metadata_phase cleanup
\ir capture_comparison.sql
\ir assert_comparison.sql
\ir assert_clean.sql
\ir assert_schema.sql
SELECT jsonb_build_object('test','stage4_cleanup','passed',true,'fixture_removed',true,'metadata_unchanged',true) AS result;
ROLLBACK;
