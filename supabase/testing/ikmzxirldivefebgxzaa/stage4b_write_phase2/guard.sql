\set ON_ERROR_STOP on
\ir ../target_guard.psql
\if :{?stage4bwrite_approved}
\else
DO $fail$ BEGIN RAISE EXCEPTION 'Separate write rollback authorization missing'; END $fail$;
\endif
SELECT :'stage4bwrite_approved'='ikmzxirldivefebgxzaa'
 AND :'user_a'='72a7251d-b69b-4149-8a7f-a082e4b920e9'
 AND :'user_b'='8c9907c9-4acf-480b-aaee-dcd08f3cbc6a' AS approved \gset
\if :approved
\else
DO $fail$ BEGIN RAISE EXCEPTION 'Write approval/user mapping rejected'; END $fail$;
\endif
DO $guard$ BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres' OR current_database()<>'postgres'
 OR current_setting('server_version_num')::int/10000<>17 THEN RAISE EXCEPTION 'Unexpected TEST operator/server'; END IF;
END $guard$;
SELECT set_config('mesh_stage4bread.user_a',:'user_a',false) AS ignored \gset
SELECT set_config('mesh_stage4bread.user_b',:'user_b',false) AS ignored \gset
