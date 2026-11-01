-- Predicate unit tests only. SELECT on the actual five tables remains denied.
SELECT set_config('request.jwt.claim.sub', :'user_a',true) AS ignored \gset
SELECT set_config('request.jwt.claims',jsonb_build_object('sub',:'user_a','organization_id','44444444-4444-4444-8444-000000000002','user_metadata',jsonb_build_object('role','owner','organization_id','44444444-4444-4444-8444-000000000002'))::text,true) AS ignored \gset
SET LOCAL ROLE authenticated;
DO $a$ BEGIN
 IF NOT public.is_mesh_member('44444444-4444-4444-8444-000000000001',ARRAY['security_team'::public.mesh_role])
 OR public.is_mesh_member('44444444-4444-4444-8444-000000000002',ARRAY['security_team'::public.mesh_role]) THEN
 RAISE EXCEPTION 'A membership/organization-metadata spoof test failed'; END IF;
END $a$;
RESET ROLE;
SELECT set_config('request.jwt.claim.sub', :'user_b',true) AS ignored \gset
SELECT set_config('request.jwt.claims',jsonb_build_object('sub',:'user_b')::text,true) AS ignored \gset
SET LOCAL ROLE authenticated;
DO $b$ BEGIN
 IF NOT public.is_mesh_member('44444444-4444-4444-8444-000000000002',ARRAY['security_team'::public.mesh_role])
 OR public.is_mesh_member('44444444-4444-4444-8444-000000000001',ARRAY['security_team'::public.mesh_role]) THEN
 RAISE EXCEPTION 'B membership test failed'; END IF;
END $b$;
RESET ROLE;
UPDATE public.organization_members SET status='suspended'
 WHERE organization_id='44444444-4444-4444-8444-000000000002' AND user_id=:'user_b'::uuid;
SET LOCAL ROLE authenticated;
DO $s$ BEGIN
 IF public.is_mesh_member('44444444-4444-4444-8444-000000000002') THEN
 RAISE EXCEPTION 'Suspended membership accepted'; END IF;
END $s$;
RESET ROLE;
UPDATE public.organization_members SET status='active',role='owner'
 WHERE organization_id='44444444-4444-4444-8444-000000000002' AND user_id=:'user_b'::uuid;
SET LOCAL ROLE authenticated;
DO $owner$ BEGIN
 IF NOT public.is_mesh_member('44444444-4444-4444-8444-000000000002') OR
 public.is_mesh_member('44444444-4444-4444-8444-000000000002',ARRAY['security_team'::public.mesh_role]) THEN
 RAISE EXCEPTION 'Unexpected owner override of security-team restriction'; END IF;
END $owner$;
RESET ROLE;
SELECT set_config('request.jwt.claim.sub','44444444-4444-4444-8444-000000000099',true) AS ignored \gset
SELECT set_config('request.jwt.claims','{}',true) AS ignored \gset
SET LOCAL ROLE authenticated;
DO $outsider$ BEGIN
 IF public.is_mesh_member('44444444-4444-4444-8444-000000000001') OR
 public.is_mesh_member('44444444-4444-4444-8444-000000000002') THEN
 RAISE EXCEPTION 'Outsider authorized'; END IF;
END $outsider$;
RESET ROLE;
SELECT set_config('request.jwt.claim.sub','',true) AS ignored \gset
SET LOCAL ROLE authenticated;
DO $missing$ BEGIN
 IF public.is_mesh_member('44444444-4444-4444-8444-000000000001') THEN
 RAISE EXCEPTION 'Missing identity authorized'; END IF;
END $missing$;
RESET ROLE;
