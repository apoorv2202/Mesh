WITH users(company,user_id) AS (
 VALUES ('A',:'user_a'::uuid),
        ('B',:'user_b'::uuid)
), orgs(id) AS (
 VALUES ('55555555-5555-4555-8555-000000000001'::uuid),
        ('55555555-5555-4555-8555-000000000002'::uuid)
), checks(check_name,collision_count) AS (
 SELECT 'public_profiles',count(*) FROM public.profiles WHERE id IN (SELECT user_id FROM users)
 UNION ALL SELECT 'user_memberships_any_organization',count(*) FROM public.organization_members WHERE user_id IN (SELECT user_id FROM users)
 UNION ALL SELECT 'organizations',count(*) FROM public.organizations WHERE id IN (SELECT id FROM orgs)
 UNION ALL SELECT 'memberships_in_reserved_orgs',count(*) FROM public.organization_members WHERE organization_id IN (SELECT id FROM orgs)
 UNION ALL SELECT 'assets_ids_or_reserved_orgs',count(*) FROM public.security_assets
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('55555555-5555-4555-8555-000000000010','55555555-5555-4555-8555-000000000011')
 UNION ALL SELECT 'events_ids_or_reserved_orgs',count(*) FROM public.security_events
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('55555555-5555-4555-8555-000000000012','55555555-5555-4555-8555-000000000013',
  '55555555-5555-4555-8555-000000000080')
 UNION ALL SELECT 'findings_ids_or_reserved_orgs',count(*) FROM public.security_findings
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('55555555-5555-4555-8555-000000000014','55555555-5555-4555-8555-000000000015',
  '55555555-5555-4555-8555-000000000081','55555555-5555-4555-8555-000000000082')
 UNION ALL SELECT 'incidents_ids_numbers_or_reserved_orgs',count(*) FROM public.security_incidents
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('55555555-5555-4555-8555-000000000016','55555555-5555-4555-8555-000000000017')
 OR incident_number IN (-54001,-54002,-54999)
 UNION ALL SELECT 'incident_links_ids_or_reserved_orgs',count(*) FROM public.incident_events
 WHERE organization_id IN (SELECT id FROM orgs)
 OR incident_id IN ('55555555-5555-4555-8555-000000000016','55555555-5555-4555-8555-000000000017')
 OR event_id IN ('55555555-5555-4555-8555-000000000012','55555555-5555-4555-8555-000000000013')
 UNION ALL SELECT 'risk_ids_or_reserved_orgs',count(*) FROM public.security_risk_scores
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('55555555-5555-4555-8555-000000000020','55555555-5555-4555-8555-000000000021')
)
SELECT bool_and(collision_count=0) AS namespace_clear, jsonb_agg(to_jsonb(c) ORDER BY check_name)::text AS collision_counts FROM checks c
\gset
SELECT jsonb_build_object('record_type','collision_check','passed',:'namespace_clear'::boolean,
 'counts',:'collision_counts'::jsonb) AS diagnostic;
\if :namespace_clear
\else
DO $fail$ BEGIN RAISE EXCEPTION 'Stage4B-read fixture namespace collision or residue'; END $fail$;
\endif
DO $identity$ BEGIN
 IF (SELECT count(*) FROM auth.users WHERE id IN (current_setting('mesh_stage4bread.user_a')::uuid,current_setting('mesh_stage4bread.user_b')::uuid))<>2 THEN
 RAISE EXCEPTION 'Both reviewed synthetic Auth identities must exist'; END IF;
 IF EXISTS(SELECT 1 FROM auth.users WHERE id='55555555-5555-4555-8555-000000000099') THEN
 RAISE EXCEPTION 'Reserved outsider UUID belongs to an existing Auth identity'; END IF;
END $identity$;
