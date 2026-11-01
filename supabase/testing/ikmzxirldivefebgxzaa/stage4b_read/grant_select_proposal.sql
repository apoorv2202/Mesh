-- TEST-only transaction fragment. Never a standalone deployment/migration.
-- The harness owns BEGIN/ROLLBACK. No persistent permission change is intended.
DO $grant_guard$ BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres' OR
 current_setting('mesh_stage4bread.grant_approved',true) IS DISTINCT FROM 'on' THEN
 RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='STAGE4B_READ_GRANT_GATE_CLOSED'; END IF;
END $grant_guard$;
GRANT SELECT ON TABLE public.security_events,public.security_findings,
 public.security_incidents,public.incident_events,public.security_risk_scores
TO authenticated;
