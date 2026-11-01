\ir ../stage4b_read/assert_clean.sql
DO $probes$ DECLARE t text; n bigint; BEGIN
 FOREACH t IN ARRAY ARRAY['security_events','security_findings','security_incidents','security_risk_scores'] LOOP
  EXECUTE format('SELECT count(*) FROM public.%I WHERE id IN ($1,$2,$3)',t) INTO n USING
   '55555555-5555-4555-8555-000000000080'::uuid,'55555555-5555-4555-8555-000000000081'::uuid,'55555555-5555-4555-8555-000000000082'::uuid;
  IF n<>0 THEN RAISE EXCEPTION 'Probe UUID collision/residue in %',t; END IF;
 END LOOP;
END $probes$;
-- All scopes, not just reserved organizations, plus dynamically generated audit IDs.
SELECT count(*)=0 AS audits_clear FROM public.audit_logs
 WHERE organization_id IN ('55555555-5555-4555-8555-000000000001','55555555-5555-4555-8555-000000000002') \gset
SELECT NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname IN ('vader_private','vader_api','vader_user_api'))
 AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('vader_writer_owner','vader_triage_owner','vader_ingest'))
 AND NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname IN ('vader_risk_finding_tenant_fk','vader_risk_incident_tenant_fk','vader_assignee_tenant_fk'))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='public.security_risk_scores'::regclass AND NOT attisdropped
 AND attname IN ('vader_finding_subject_id','vader_incident_subject_id')) AS objects_clear \gset
\if :audits_clear
\else
DO $fail$ BEGIN RAISE EXCEPTION 'Reserved audit namespace collision/residue'; END $fail$;
\endif
\if :objects_clear
\else
DO $fail$ BEGIN RAISE EXCEPTION 'Proposed object collision/residue'; END $fail$;
\endif
