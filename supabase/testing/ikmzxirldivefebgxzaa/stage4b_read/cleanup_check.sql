\ir guard.sql
BEGIN READ ONLY;
SELECT set_config('mesh_stage4bread.user_a', :'user_a',true) AS ignored \gset
SELECT set_config('mesh_stage4bread.user_b', :'user_b',true) AS ignored \gset
\set metadata_phase cleanup
\ir ../stage4/capture_comparison.sql
\ir ../stage4/assert_comparison.sql
\ir ../stage4/assert_schema.sql
\ir assert_clean.sql
SELECT jsonb_build_object('test','stage4b_read_cleanup','passed',true,'fixture_removed',true,
 'grant_rolled_back',true,'metadata_unchanged',true) AS result;
ROLLBACK;
