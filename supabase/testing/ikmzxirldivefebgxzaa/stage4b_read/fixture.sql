-- Synthetic application fixture only. No managed Auth writes or sequence calls.
INSERT INTO public.organizations(id,name,status) VALUES ('55555555-5555-4555-8555-000000000001','Company A Stage4B-read','active'),('55555555-5555-4555-8555-000000000002','Company B Stage4B-read','active');
INSERT INTO public.profiles(id,full_name) VALUES (:'user_a'::uuid,'Stage4B-read synthetic A'),(:'user_b'::uuid,'Stage4B-read synthetic B');
INSERT INTO public.organization_members(organization_id,user_id,role,status) VALUES
 ('55555555-5555-4555-8555-000000000001',:'user_a'::uuid,'security_team','active'),('55555555-5555-4555-8555-000000000002',:'user_b'::uuid,'security_team','active');
INSERT INTO public.security_assets(id,organization_id,name,asset_type) VALUES
 ('55555555-5555-4555-8555-000000000010','55555555-5555-4555-8555-000000000001','Stage4B-read A','test'),('55555555-5555-4555-8555-000000000011','55555555-5555-4555-8555-000000000002','Stage4B-read B','test');
INSERT INTO public.security_events(id,organization_id,asset_id,source,external_event_id,event_type,event_time) VALUES
 ('55555555-5555-4555-8555-000000000012','55555555-5555-4555-8555-000000000001','55555555-5555-4555-8555-000000000010','vader-stage4b-read','a','login','2026-01-01T00:00:00Z'),
 ('55555555-5555-4555-8555-000000000013','55555555-5555-4555-8555-000000000002','55555555-5555-4555-8555-000000000011','vader-stage4b-read','b','login','2026-01-01T00:00:00Z');
INSERT INTO public.security_findings(id,organization_id,asset_id,source_event_id,title,finding_type) VALUES
 ('55555555-5555-4555-8555-000000000014','55555555-5555-4555-8555-000000000001','55555555-5555-4555-8555-000000000010','55555555-5555-4555-8555-000000000012','Stage4B-read A','test'),('55555555-5555-4555-8555-000000000015','55555555-5555-4555-8555-000000000002','55555555-5555-4555-8555-000000000011','55555555-5555-4555-8555-000000000013','Stage4B-read B','test');
-- Explicit negative test numbers avoid nontransactional identity-sequence advance.
INSERT INTO public.security_incidents(id,organization_id,incident_number,title) OVERRIDING SYSTEM VALUE VALUES
 ('55555555-5555-4555-8555-000000000016','55555555-5555-4555-8555-000000000001',-54001,'Stage4B-read A'),('55555555-5555-4555-8555-000000000017','55555555-5555-4555-8555-000000000002',-54002,'Stage4B-read B');
INSERT INTO public.incident_events(organization_id,incident_id,event_id) VALUES
 ('55555555-5555-4555-8555-000000000001','55555555-5555-4555-8555-000000000016','55555555-5555-4555-8555-000000000012'),('55555555-5555-4555-8555-000000000002','55555555-5555-4555-8555-000000000017','55555555-5555-4555-8555-000000000013');
INSERT INTO public.security_risk_scores(id,organization_id,subject_type,subject_id,score,model_version) VALUES
 ('55555555-5555-4555-8555-000000000020','55555555-5555-4555-8555-000000000001','finding','55555555-5555-4555-8555-000000000014',25,'stage4'),('55555555-5555-4555-8555-000000000021','55555555-5555-4555-8555-000000000002','finding','55555555-5555-4555-8555-000000000015',25,'stage4');
