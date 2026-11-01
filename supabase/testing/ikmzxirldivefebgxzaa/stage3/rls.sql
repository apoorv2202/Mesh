-- Optional synthetic fixture; needs two distinct NEW TEST Auth user UUIDs.
-- No Auth records are read/created/updated; existing Auth FKs validate UUIDs.
-- Temporary SELECT grant and every fixture row are rolled back. No policy changes.
\ir guard.sql
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='60s';
\ir snapshot.sql
SELECT set_config('mesh_stage3.before', :'snapshot', true) AS ignored \gset
SELECT set_config('mesh_stage3.user_a', :'user_a',true) AS ignored \gset
SELECT set_config('mesh_stage3.user_b', :'user_b',true) AS ignored \gset
DO $users$ BEGIN
 IF current_setting('mesh_stage3.user_a')::uuid=current_setting('mesh_stage3.user_b')::uuid THEN
 RAISE EXCEPTION 'Two distinct synthetic Auth UUIDs required'; END IF;
END $users$;
SAVEPOINT fixture;
INSERT INTO public.organizations(id,name,status) VALUES
 ('33333333-3333-4333-8333-333333333331','Stage3 synthetic A','active'),
 ('33333333-3333-4333-8333-333333333332','Stage3 synthetic B','active');
INSERT INTO public.profiles(id,full_name) VALUES
 (:'user_a'::uuid,'Stage3 synthetic A'),(:'user_b'::uuid,'Stage3 synthetic B');
INSERT INTO public.organization_members(organization_id,user_id,role,status) VALUES
 ('33333333-3333-4333-8333-333333333331',:'user_a'::uuid,'security_team','active'),
 ('33333333-3333-4333-8333-333333333332',:'user_b'::uuid,'security_team','active');
INSERT INTO public.security_events(organization_id,source,external_event_id,event_type,event_time) VALUES
 ('33333333-3333-4333-8333-333333333331','vader-stage3','rls-a','login','2026-01-01T00:00:00Z'),
 ('33333333-3333-4333-8333-333333333332','vader-stage3','rls-b','login','2026-01-01T00:00:00Z');
-- Necessary only to isolate policy behavior from the currently denied table ACL.
GRANT SELECT ON public.security_events TO authenticated;
SELECT set_config('request.jwt.claim.sub', :'user_a', true) AS ignored \gset
SET LOCAL ROLE authenticated;
DO $a$ BEGIN
 IF (SELECT count(*) FROM public.security_events WHERE source='vader-stage3')<>1 OR
 EXISTS(SELECT 1 FROM public.security_events WHERE source='vader-stage3' AND external_event_id<>'rls-a') THEN
 RAISE EXCEPTION 'Tenant A policy failure'; END IF;
END $a$;
RESET ROLE;
SELECT set_config('request.jwt.claim.sub', :'user_b', true) AS ignored \gset
SET LOCAL ROLE authenticated;
DO $b$ BEGIN
 IF (SELECT count(*) FROM public.security_events WHERE source='vader-stage3')<>1 OR
 EXISTS(SELECT 1 FROM public.security_events WHERE source='vader-stage3' AND external_event_id<>'rls-b') THEN
 RAISE EXCEPTION 'Tenant B policy failure'; END IF;
END $b$;
RESET ROLE;
UPDATE public.organization_members SET status='suspended'
 WHERE organization_id='33333333-3333-4333-8333-333333333332' AND user_id=:'user_b'::uuid;
SET LOCAL ROLE authenticated;
DO $suspended$ BEGIN
 IF EXISTS(SELECT 1 FROM public.security_events WHERE source='vader-stage3') THEN
 RAISE EXCEPTION 'Suspended member visibility failure'; END IF;
END $suspended$;
RESET ROLE;
SELECT set_config('request.jwt.claim.sub','33333333-3333-4333-8333-333333333339',true) AS ignored \gset
SET LOCAL ROLE authenticated;
DO $outsider$ BEGIN
 IF EXISTS(SELECT 1 FROM public.security_events WHERE source='vader-stage3') THEN
 RAISE EXCEPTION 'Outsider visibility failure'; END IF;
END $outsider$;
RESET ROLE;
ROLLBACK TO SAVEPOINT fixture;
\ir snapshot.sql
SELECT set_config('mesh_stage3.restored', :'snapshot', true) AS ignored \gset
DO $restore$ BEGIN
 IF current_setting('mesh_stage3.before')::jsonb IS DISTINCT FROM current_setting('mesh_stage3.restored')::jsonb THEN
 RAISE EXCEPTION 'RLS fixture ACL/native state restoration failed'; END IF;
END $restore$;
SELECT jsonb_build_object('test','rls','passed',true,'cases',ARRAY['tenant_a','tenant_b','suspended','outsider'],'rolled_back',true) AS result;
ROLLBACK;
