-- READ ONLY: run ONLY in Dashboard SQL Editor for TEST ikmzxirldivefebgxzaa.
-- No SQL-only project-identity oracle exists; verify the Dashboard URL first.
-- Standalone preparation artifact; does not change the reviewed Stage4 package.
-- One SELECT; no application/Auth records returned, only targeted counts.
WITH users(company,user_id) AS (
 VALUES ('A','72a7251d-b69b-4149-8a7f-a082e4b920e9'::uuid),
        ('B','8c9907c9-4acf-480b-aaee-dcd08f3cbc6a'::uuid)
), orgs(id) AS (
 VALUES ('44444444-4444-4444-8444-000000000001'::uuid),
        ('44444444-4444-4444-8444-000000000002'::uuid)
), checks(check_name,collision_count) AS (
 SELECT 'public_profiles',count(*) FROM public.profiles WHERE id IN (SELECT user_id FROM users)
 UNION ALL SELECT 'user_memberships_any_organization',count(*) FROM public.organization_members WHERE user_id IN (SELECT user_id FROM users)
 UNION ALL SELECT 'organizations',count(*) FROM public.organizations WHERE id IN (SELECT id FROM orgs)
 UNION ALL SELECT 'memberships_in_reserved_orgs',count(*) FROM public.organization_members WHERE organization_id IN (SELECT id FROM orgs)
 UNION ALL SELECT 'assets_ids_or_reserved_orgs',count(*) FROM public.security_assets
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('44444444-4444-4444-8444-000000000010','44444444-4444-4444-8444-000000000011')
 UNION ALL SELECT 'events_ids_or_reserved_orgs',count(*) FROM public.security_events
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('44444444-4444-4444-8444-000000000012','44444444-4444-4444-8444-000000000013',
  '44444444-4444-4444-8444-000000000080')
 UNION ALL SELECT 'findings_ids_or_reserved_orgs',count(*) FROM public.security_findings
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('44444444-4444-4444-8444-000000000014','44444444-4444-4444-8444-000000000015',
  '44444444-4444-4444-8444-000000000081','44444444-4444-4444-8444-000000000082')
 UNION ALL SELECT 'incidents_ids_numbers_or_reserved_orgs',count(*) FROM public.security_incidents
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('44444444-4444-4444-8444-000000000016','44444444-4444-4444-8444-000000000017')
 OR incident_number IN (-44001,-44002,-44999)
 UNION ALL SELECT 'incident_links_ids_or_reserved_orgs',count(*) FROM public.incident_events
 WHERE organization_id IN (SELECT id FROM orgs)
 OR incident_id IN ('44444444-4444-4444-8444-000000000016','44444444-4444-4444-8444-000000000017')
 OR event_id IN ('44444444-4444-4444-8444-000000000012','44444444-4444-4444-8444-000000000013')
 UNION ALL SELECT 'risk_ids_or_reserved_orgs',count(*) FROM public.security_risk_scores
 WHERE organization_id IN (SELECT id FROM orgs) OR id IN
 ('44444444-4444-4444-8444-000000000020','44444444-4444-4444-8444-000000000021')
), auth_checks AS (
 SELECT u.company,count(a.id) AS matching_auth_users
 FROM users u LEFT JOIN auth.users a ON a.id=u.user_id GROUP BY u.company
)
SELECT
 (current_user='postgres' AND current_database()='postgres'
  AND (SELECT bool_and(collision_count=0) FROM checks)
  AND (SELECT count(*)=2 AND bool_and(matching_auth_users=1) FROM auth_checks)
 )::boolean AS identifiers_clear,
 jsonb_build_object(
 'client_asserted_test_ref','ikmzxirldivefebgxzaa',
 'database',current_database(),'operator',current_user,
 'auth_user_checks',(SELECT jsonb_agg(to_jsonb(a) ORDER BY company) FROM auth_checks a),
 'collision_checks',(SELECT jsonb_agg(to_jsonb(c) ORDER BY check_name) FROM checks c)
) AS stage4_preflight;
