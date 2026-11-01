DO $fk$ DECLARE got text; BEGIN
BEGIN
 UPDATE public.security_events SET asset_id='44444444-4444-4444-8444-000000000011' WHERE id='44444444-4444-4444-8444-000000000012';
 RAISE EXCEPTION 'Expected composite FK rejection: security_events_organization_id_asset_id_fkey';
EXCEPTION WHEN foreign_key_violation THEN
 GET STACKED DIAGNOSTICS got=CONSTRAINT_NAME;
 IF got<>'security_events_organization_id_asset_id_fkey' THEN RAISE EXCEPTION 'Wrong FK: %',got; END IF;
END;
BEGIN
 UPDATE public.security_findings SET asset_id='44444444-4444-4444-8444-000000000011' WHERE id='44444444-4444-4444-8444-000000000014';
 RAISE EXCEPTION 'Expected composite FK rejection: security_findings_organization_id_asset_id_fkey';
EXCEPTION WHEN foreign_key_violation THEN
 GET STACKED DIAGNOSTICS got=CONSTRAINT_NAME;
 IF got<>'security_findings_organization_id_asset_id_fkey' THEN RAISE EXCEPTION 'Wrong FK: %',got; END IF;
END;
BEGIN
 UPDATE public.security_findings SET source_event_id='44444444-4444-4444-8444-000000000013' WHERE id='44444444-4444-4444-8444-000000000014';
 RAISE EXCEPTION 'Expected composite FK rejection: security_findings_organization_id_source_event_id_fkey';
EXCEPTION WHEN foreign_key_violation THEN
 GET STACKED DIAGNOSTICS got=CONSTRAINT_NAME;
 IF got<>'security_findings_organization_id_source_event_id_fkey' THEN RAISE EXCEPTION 'Wrong FK: %',got; END IF;
END;
BEGIN
 UPDATE public.incident_events SET incident_id='44444444-4444-4444-8444-000000000017' WHERE organization_id='44444444-4444-4444-8444-000000000001';
 RAISE EXCEPTION 'Expected composite FK rejection: incident_events_organization_id_incident_id_fkey';
EXCEPTION WHEN foreign_key_violation THEN
 GET STACKED DIAGNOSTICS got=CONSTRAINT_NAME;
 IF got<>'incident_events_organization_id_incident_id_fkey' THEN RAISE EXCEPTION 'Wrong FK: %',got; END IF;
END;
BEGIN
 UPDATE public.incident_events SET event_id='44444444-4444-4444-8444-000000000013' WHERE organization_id='44444444-4444-4444-8444-000000000001';
 RAISE EXCEPTION 'Expected composite FK rejection: incident_events_organization_id_event_id_fkey';
EXCEPTION WHEN foreign_key_violation THEN
 GET STACKED DIAGNOSTICS got=CONSTRAINT_NAME;
 IF got<>'incident_events_organization_id_event_id_fkey' THEN RAISE EXCEPTION 'Wrong FK: %',got; END IF;
END;
BEGIN
 INSERT INTO public.security_events(id,organization_id,asset_id,source,event_type,event_time) VALUES ('44444444-4444-4444-8444-000000000080','44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000011','stage4-fk','login','2026-01-01T00:00:00Z');
 RAISE EXCEPTION 'Expected composite FK rejection: security_events_organization_id_asset_id_fkey';
EXCEPTION WHEN foreign_key_violation THEN
 GET STACKED DIAGNOSTICS got=CONSTRAINT_NAME;
 IF got<>'security_events_organization_id_asset_id_fkey' THEN RAISE EXCEPTION 'Wrong FK: %',got; END IF;
END;
BEGIN
 INSERT INTO public.security_findings(id,organization_id,source_event_id,title,finding_type) VALUES ('44444444-4444-4444-8444-000000000081','44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000013','stage4-fk','test');
 RAISE EXCEPTION 'Expected composite FK rejection: security_findings_organization_id_source_event_id_fkey';
EXCEPTION WHEN foreign_key_violation THEN
 GET STACKED DIAGNOSTICS got=CONSTRAINT_NAME;
 IF got<>'security_findings_organization_id_source_event_id_fkey' THEN RAISE EXCEPTION 'Wrong FK: %',got; END IF;
END;
BEGIN
 INSERT INTO public.security_findings(id,organization_id,asset_id,title,finding_type) VALUES ('44444444-4444-4444-8444-000000000082','44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000011','stage4-fk','test');
 RAISE EXCEPTION 'Expected composite FK rejection: security_findings_organization_id_asset_id_fkey';
EXCEPTION WHEN foreign_key_violation THEN
 GET STACKED DIAGNOSTICS got=CONSTRAINT_NAME;
 IF got<>'security_findings_organization_id_asset_id_fkey' THEN RAISE EXCEPTION 'Wrong FK: %',got; END IF;
END;
BEGIN
 INSERT INTO public.incident_events(organization_id,incident_id,event_id) VALUES ('44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000017','44444444-4444-4444-8444-000000000012');
 RAISE EXCEPTION 'Expected composite FK rejection: incident_events_organization_id_incident_id_fkey';
EXCEPTION WHEN foreign_key_violation THEN
 GET STACKED DIAGNOSTICS got=CONSTRAINT_NAME;
 IF got<>'incident_events_organization_id_incident_id_fkey' THEN RAISE EXCEPTION 'Wrong FK: %',got; END IF;
END;
BEGIN
 INSERT INTO public.incident_events(organization_id,incident_id,event_id) VALUES ('44444444-4444-4444-8444-000000000001','44444444-4444-4444-8444-000000000016','44444444-4444-4444-8444-000000000013');
 RAISE EXCEPTION 'Expected composite FK rejection: incident_events_organization_id_event_id_fkey';
EXCEPTION WHEN foreign_key_violation THEN
 GET STACKED DIAGNOSTICS got=CONSTRAINT_NAME;
 IF got<>'incident_events_organization_id_event_id_fkey' THEN RAISE EXCEPTION 'Wrong FK: %',got; END IF;
END;
END $fk$;
