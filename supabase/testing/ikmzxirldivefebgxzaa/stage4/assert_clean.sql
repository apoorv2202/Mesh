DO $clean$ BEGIN
IF EXISTS(SELECT 1 FROM public.security_events WHERE organization_id IN ('44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000002')) THEN RAISE EXCEPTION 'Reserved Stage4 rows exist: security_events'; END IF;
IF EXISTS(SELECT 1 FROM public.security_findings WHERE organization_id IN ('44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000002')) THEN RAISE EXCEPTION 'Reserved Stage4 rows exist: security_findings'; END IF;
IF EXISTS(SELECT 1 FROM public.security_incidents WHERE organization_id IN ('44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000002')) THEN RAISE EXCEPTION 'Reserved Stage4 rows exist: security_incidents'; END IF;
IF EXISTS(SELECT 1 FROM public.incident_events WHERE organization_id IN ('44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000002')) THEN RAISE EXCEPTION 'Reserved Stage4 rows exist: incident_events'; END IF;
IF EXISTS(SELECT 1 FROM public.security_risk_scores WHERE organization_id IN ('44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000002')) THEN RAISE EXCEPTION 'Reserved Stage4 rows exist: security_risk_scores'; END IF;
IF EXISTS(SELECT 1 FROM public.security_assets WHERE organization_id IN ('44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000002')) THEN RAISE EXCEPTION 'Reserved Stage4 rows exist: security_assets'; END IF;
IF EXISTS(SELECT 1 FROM public.organization_members WHERE organization_id IN ('44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000002')) THEN RAISE EXCEPTION 'Reserved Stage4 rows exist: organization_members'; END IF;
IF EXISTS(SELECT 1 FROM public.organizations WHERE id IN ('44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000002')) THEN RAISE EXCEPTION 'Reserved Stage4 rows exist: organizations'; END IF;
IF EXISTS(SELECT 1 FROM public.profiles WHERE id IN (current_setting('mesh_stage4.user_a')::uuid,current_setting('mesh_stage4.user_b')::uuid)) THEN RAISE EXCEPTION 'Synthetic profile collision/cleanup failure'; END IF;
END $clean$;
