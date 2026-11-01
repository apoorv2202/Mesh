\set ON_ERROR_STOP on
\ir guard.sql
BEGIN READ ONLY;
\set metadata_phase fresh_cleanup
\ir ../stage4/capture_comparison.sql
\ir ../stage4/assert_comparison.sql
\ir ../stage4/assert_schema.sql
\ir collisions.sql
\ir capture_acl.sql
SELECT md5(:'write_acl')=:'expected_write_acl_md5' AS original_acl_restored \gset
\if :original_acl_restored
\else
DO $fail$ BEGIN RAISE EXCEPTION 'Fresh cleanup ACL fingerprint differs from recorded pre-attempt state'; END $fail$;
\endif
ROLLBACK;
SELECT jsonb_build_object('record_type','stage4b_write_cleanup','passed',true,
 'metadata_restored',true,'fixtures_absent',true,'proposed_objects_absent',true);
