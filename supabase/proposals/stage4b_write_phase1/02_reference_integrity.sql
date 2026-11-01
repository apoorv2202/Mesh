-- REVIEW ONLY. Proposed new generated fields/FKs, never assumed to exist.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='60s';
DO $gate$ BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres'
 OR current_setting('mesh_review.test_ref',true) IS DISTINCT FROM 'ikmzxirldivefebgxzaa'
 OR current_setting('mesh_review.reference_integrity_approved',true) IS DISTINCT FROM 'on'
 OR current_setting('mesh_review.assignment_lifecycle_approved',true) IS DISTINCT FROM 'on' THEN
 RAISE EXCEPTION 'Closed reference/assignment lifecycle review gate'; END IF;
END $gate$;
ALTER TABLE public.security_risk_scores
 ADD COLUMN vader_finding_subject_id uuid GENERATED ALWAYS AS
  (CASE WHEN subject_type='finding' THEN subject_id END) STORED,
 ADD COLUMN vader_incident_subject_id uuid GENERATED ALWAYS AS
  (CASE WHEN subject_type='incident' THEN subject_id END) STORED,
 ADD CONSTRAINT vader_risk_finding_tenant_fk FOREIGN KEY(organization_id,vader_finding_subject_id)
  REFERENCES public.security_findings(organization_id,id),
 ADD CONSTRAINT vader_risk_incident_tenant_fk FOREIGN KEY(organization_id,vader_incident_subject_id)
  REFERENCES public.security_incidents(organization_id,id);
ALTER TABLE public.security_incidents
 ADD CONSTRAINT vader_assignee_tenant_fk FOREIGN KEY(organization_id,assigned_to)
 REFERENCES public.organization_members(organization_id,user_id);
-- Existing cross-tenant rows abort validation. No cleanup, CASCADE, NOT VALID,
-- weakened RLS, actor mapping or global prohibition of legacy asset/identity scores.
-- Hard-deleting a membership referenced by assigned_to will now be rejected.
-- Status offboarding remains possible; active eligibility is checked by the RPC.
COMMIT;
