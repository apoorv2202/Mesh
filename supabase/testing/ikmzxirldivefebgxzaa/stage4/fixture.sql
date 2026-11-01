-- Synthetic application fixture only. No managed Auth writes or sequence calls.
INSERT INTO public.organizations(id,name,status) VALUES ('44444444-4444-4444-8444-000000000001','Company A Stage4','active'),('44444444-4444-4444-8444-000000000002','Company B Stage4','active');
INSERT INTO public.profiles(id,full_name) VALUES (:'user_a'::uuid,'Stage4 synthetic A'),(:'user_b'::uuid,'Stage4 synthetic B');
INSERT INTO public.organization_members(organization_id,user_id,role,status) VALUES
 ('44444444-4444-4444-8444-000000000001',:'user_a'::uuid,'security_team','active'),('44444444-4444-4444-8444-000000000002',:'user_b'::uuid,'security_team','active');
INSERT INTO public.security_assets(id,organization_id,name,asset_type) VALUES
 ('44444444-4444-4444-8444-000000000010','44444444-4444-4444-8444-000000000001','Stage4 A','test'),('44444444-4444-4444-8444-000000000011','44444444-4444-4444-8444-000000000002','Stage4 B','test');
INSERT INTO public.security_events(id,organization_id,asset_id,source,external_event_id,event_type,event_time) VALUES
 ('44444444-4444-4444-8444-000000000012','44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000010','vader-stage4','a','login','2026-01-01T00:00:00Z'),
 ('44444444-4444-4444-8444-000000000013','44444444-4444-4444-8444-000000000002','44444444-4444-4444-8444-000000000011','vader-stage4','b','login','2026-01-01T00:00:00Z');
INSERT INTO public.security_findings(id,organization_id,asset_id,source_event_id,title,finding_type) VALUES
 ('44444444-4444-4444-8444-000000000014','44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000010','44444444-4444-4444-8444-000000000012','Stage4 A','test'),('44444444-4444-4444-8444-000000000015','44444444-4444-4444-8444-000000000002','44444444-4444-4444-8444-000000000011','44444444-4444-4444-8444-000000000013','Stage4 B','test');
-- Explicit negative test numbers avoid nontransactional identity-sequence advance.
INSERT INTO public.security_incidents(id,organization_id,incident_number,title) OVERRIDING SYSTEM VALUE VALUES
 ('44444444-4444-4444-8444-000000000016','44444444-4444-4444-8444-000000000001',-44001,'Stage4 A'),('44444444-4444-4444-8444-000000000017','44444444-4444-4444-8444-000000000002',-44002,'Stage4 B');
INSERT INTO public.incident_events(organization_id,incident_id,event_id) VALUES
 ('44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000016','44444444-4444-4444-8444-000000000012'),('44444444-4444-4444-8444-000000000002','44444444-4444-4444-8444-000000000017','44444444-4444-4444-8444-000000000013');
INSERT INTO public.security_risk_scores(id,organization_id,subject_type,subject_id,score,model_version) VALUES
 ('44444444-4444-4444-8444-000000000020','44444444-4444-4444-8444-000000000001','finding','44444444-4444-4444-8444-000000000014',25,'stage4'),('44444444-4444-4444-8444-000000000021','44444444-4444-4444-8444-000000000002','finding','44444444-4444-4444-8444-000000000015',25,'stage4');
