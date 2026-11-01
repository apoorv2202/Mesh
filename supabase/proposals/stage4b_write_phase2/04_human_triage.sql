-- Phase2 candidate; not executed.
-- REVIEW-ONLY design candidate. No SQL executed. Lifecycle/transition gates CLOSED.
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='60s';
DO $gate$ BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres'
 OR current_setting('mesh_review.test_ref',true) IS DISTINCT FROM 'ikmzxirldivefebgxzaa'
 OR current_setting('mesh_review.triage_approved',true) IS DISTINCT FROM 'on'
 OR current_setting('mesh_review.status_transitions_approved',true) IS DISTINCT FROM 'on'
 OR current_setting('mesh_review.assignment_lifecycle_approved',true) IS DISTINCT FROM 'on'
 OR current_setting('mesh_review.audit_hardening_approved',true) IS DISTINCT FROM 'on' THEN
 RAISE EXCEPTION 'Closed triage/transition/assignment/audit review gate'; END IF;
 IF to_regnamespace('vader_private') IS NULL OR NOT EXISTS(SELECT 1 FROM pg_constraint
 WHERE conname='vader_assignee_tenant_fk' AND conrelid='public.security_incidents'::regclass AND convalidated) THEN
 RAISE EXCEPTION 'Machine/private schema and validated integrity prerequisites missing'; END IF;
END $gate$;
SET LOCAL createrole_self_grant='set,inherit';
CREATE ROLE vader_triage_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
DO $ownership_capability$ BEGIN
 IF NOT pg_has_role('postgres','vader_triage_owner','SET')
 OR NOT pg_has_role('postgres','vader_triage_owner','USAGE') THEN
 RAISE EXCEPTION 'Scoped triage SET/INHERIT capability absent'; END IF;
END $ownership_capability$;
CREATE SCHEMA vader_user_api;
REVOKE ALL ON SCHEMA vader_user_api FROM PUBLIC,anon,authenticated,service_role;
GRANT USAGE ON SCHEMA vader_user_api TO authenticated;
GRANT USAGE,CREATE ON SCHEMA vader_user_api TO vader_triage_owner;
GRANT USAGE,CREATE ON SCHEMA vader_private TO vader_triage_owner;
-- No public/auth schema ACL change: public USAGE already exists via PUBLIC.
DO $usage$ BEGIN
 IF NOT has_schema_privilege('vader_triage_owner','public','USAGE') THEN RAISE EXCEPTION 'Expected public USAGE absent; do not add unreviewed native schema grant'; END IF;
END $usage$;
-- Only this existing helper ACL is extended; no definition/owner/settings change.
GRANT EXECUTE ON FUNCTION public.is_mesh_member(uuid,public.mesh_role[]) TO vader_triage_owner;
DO $member_usage$ BEGIN
 IF NOT has_function_privilege('vader_triage_owner','public.is_mesh_member(uuid,public.mesh_role[])','EXECUTE') THEN
 RAISE EXCEPTION 'Existing membership helper EXECUTE prerequisite absent'; END IF;
END $member_usage$;
GRANT SELECT ON public.security_findings,public.security_incidents TO vader_triage_owner;
GRANT UPDATE(status,remediation,resolved_at) ON public.security_findings TO vader_triage_owner;
GRANT UPDATE(status,assigned_to,resolved_at) ON public.security_incidents TO vader_triage_owner;
CREATE POLICY vader_triage_select ON public.security_findings FOR SELECT TO vader_triage_owner
 USING (public.is_mesh_member(organization_id,ARRAY['security_team'::public.mesh_role]));
CREATE POLICY vader_triage_update ON public.security_findings FOR UPDATE TO vader_triage_owner
 USING (public.is_mesh_member(organization_id,ARRAY['security_team'::public.mesh_role]))
 WITH CHECK (public.is_mesh_member(organization_id,ARRAY['security_team'::public.mesh_role]));
CREATE POLICY vader_triage_select ON public.security_incidents FOR SELECT TO vader_triage_owner
 USING (public.is_mesh_member(organization_id,ARRAY['security_team'::public.mesh_role]));
CREATE POLICY vader_triage_update ON public.security_incidents FOR UPDATE TO vader_triage_owner
 USING (public.is_mesh_member(organization_id,ARRAY['security_team'::public.mesh_role]))
 WITH CHECK (public.is_mesh_member(organization_id,ARRAY['security_team'::public.mesh_role]));

-- Narrow postgres-owned read/locking helper; API callers cannot execute it.
-- FOR SHARE blocks status/role UPDATE and membership deletion until transaction end.
CREATE FUNCTION vader_private.human_guard_v1(tenant uuid,assignee uuid DEFAULT NULL) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
DECLARE actor uuid:=auth.uid(); m record; actor_ok boolean:=false; assignee_ok boolean:=assignee IS NULL;
BEGIN
 IF actor IS NULL OR tenant IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='VADER human scope denied'; END IF;
 PERFORM 1 FROM public.organizations WHERE id=tenant AND status='active' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='VADER human scope denied'; END IF;
 FOR m IN SELECT user_id,role,status FROM public.organization_members
 WHERE organization_id=tenant AND user_id IN (actor,assignee) ORDER BY user_id FOR SHARE LOOP
  IF m.user_id=actor AND m.role='security_team' AND m.status='active' THEN actor_ok:=true; END IF;
  IF m.user_id=assignee AND m.role='security_team' AND m.status='active' THEN assignee_ok:=true; END IF;
 END LOOP;
 IF NOT actor_ok OR NOT assignee_ok THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='VADER human scope denied'; END IF;
 RETURN actor;
END $fn$;
REVOKE ALL ON FUNCTION vader_private.human_guard_v1(uuid,uuid) FROM PUBLIC,anon,authenticated,service_role,vader_ingest,vader_writer_owner;
GRANT EXECUTE ON FUNCTION vader_private.human_guard_v1(uuid,uuid) TO vader_triage_owner;

CREATE FUNCTION vader_private.triage_token_v1(kind text,state jsonb) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$
 SELECT encode(extensions.digest(convert_to(jsonb_build_array('vader-triage-state-v1',kind,state)::text,'UTF8'),'sha256'),'hex')
$fn$;
REVOKE ALL ON FUNCTION vader_private.triage_token_v1(text,jsonb) FROM PUBLIC,anon,authenticated,service_role,vader_ingest,vader_writer_owner;
GRANT EXECUTE ON FUNCTION vader_private.triage_token_v1(text,jsonb) TO vader_triage_owner;

CREATE TABLE vader_private.triage_receipts (
 organization_id uuid NOT NULL REFERENCES public.organizations(id),
 actor_user_id uuid NOT NULL REFERENCES auth.users(id),
 operation text NOT NULL CHECK(operation IN ('finding','incident')),
 request_key text NOT NULL CHECK(length(request_key) BETWEEN 1 AND 256),
 payload jsonb NOT NULL,
 response jsonb,
 PRIMARY KEY(organization_id,actor_user_id,operation,request_key)
);
REVOKE ALL ON vader_private.triage_receipts FROM PUBLIC,anon,authenticated,service_role,vader_ingest,vader_writer_owner;
GRANT SELECT,INSERT,UPDATE ON vader_private.triage_receipts TO vader_triage_owner;
ALTER TABLE vader_private.triage_receipts ENABLE ROW LEVEL SECURITY;
CREATE POLICY vader_human_receipt_scope ON vader_private.triage_receipts TO vader_triage_owner
 USING(actor_user_id=vader_private.human_guard_v1(organization_id,NULL))
 WITH CHECK(actor_user_id=vader_private.human_guard_v1(organization_id,NULL));
GRANT INSERT(id,organization_id,actor_user_id,action,target_type,target_id,metadata) ON public.audit_logs TO vader_triage_owner;
CREATE POLICY vader_human_audit_insert ON public.audit_logs FOR INSERT TO vader_triage_owner
 WITH CHECK(actor_user_id=vader_private.human_guard_v1(organization_id,NULL));

CREATE FUNCTION vader_private.transition_allowed_v1(kind text,prior text,next_state text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $fn$
 SELECT (prior=next_state AND prior NOT IN ('resolved','false_positive','accepted_risk')) OR
 CASE WHEN kind='finding' THEN
  (prior='open' AND next_state='investigating') OR
  (prior='investigating' AND next_state='remediating') OR
  (prior='remediating' AND next_state='resolved') OR
  (prior IN ('open','investigating') AND next_state='false_positive') OR
  (prior IN ('resolved','false_positive') AND next_state='investigating')
 WHEN kind='incident' THEN
  (prior='detected' AND next_state='triaged') OR (prior='triaged' AND next_state='investigating') OR
  (prior='investigating' AND next_state='contained') OR (prior='contained' AND next_state='remediating') OR
  (prior='remediating' AND next_state='recovering') OR (prior='recovering' AND next_state='resolved') OR
  (prior IN ('detected','triaged','investigating') AND next_state='false_positive') OR
  (prior IN ('resolved','false_positive') AND next_state='triaged') ELSE false END
$fn$;
ALTER FUNCTION vader_private.transition_allowed_v1(text,text,text) OWNER TO vader_triage_owner;
REVOKE ALL ON FUNCTION vader_private.transition_allowed_v1(text,text,text) FROM PUBLIC,anon,authenticated,service_role,vader_ingest,vader_writer_owner;

-- Revision protects against ABA; no application columns are repurposed.
CREATE TABLE vader_private.triage_versions (
 organization_id uuid NOT NULL REFERENCES public.organizations(id),
 operation text NOT NULL CHECK(operation IN ('finding','incident')),
 target_id uuid NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 finding_id uuid GENERATED ALWAYS AS (CASE WHEN operation='finding' THEN target_id END) STORED,
 incident_id uuid GENERATED ALWAYS AS (CASE WHEN operation='incident' THEN target_id END) STORED,
 PRIMARY KEY(organization_id,operation,target_id),
 FOREIGN KEY(organization_id,finding_id) REFERENCES public.security_findings(organization_id,id),
 FOREIGN KEY(organization_id,incident_id) REFERENCES public.security_incidents(organization_id,id)
);
REVOKE ALL ON vader_private.triage_versions FROM PUBLIC,anon,authenticated,service_role,vader_ingest,vader_writer_owner;
GRANT SELECT,INSERT,UPDATE ON vader_private.triage_versions TO vader_triage_owner;
ALTER TABLE vader_private.triage_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY vader_human_version_scope ON vader_private.triage_versions TO vader_triage_owner
 USING(vader_private.human_guard_v1(organization_id,NULL) IS NOT NULL)
 WITH CHECK(vader_private.human_guard_v1(organization_id,NULL) IS NOT NULL);

-- Core is private. Public API consists of separate, fixed-kind wrappers below.
CREATE FUNCTION vader_private.triage_v1(kind text,request jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $fn$
DECLARE tenant uuid; target uuid; actor uuid; assignment uuid; key text; before_state jsonb;
 after_state jsonb; prior_payload jsonb; answer jsonb; requested_status text; reason text;
 f public.security_findings; i public.security_incidents; current_revision bigint; fresh int; audit_id uuid:=gen_random_uuid();
BEGIN
 IF kind NOT IN ('finding','incident') OR jsonb_typeof(request) IS DISTINCT FROM 'object'
 OR octet_length(request::text)>16384 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid triage input'; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_object_keys(request) AS z(key) WHERE z.key NOT IN
 ('organization_id','target_id','request_key','expected_state','reason','status',
 CASE WHEN kind='finding' THEN 'remediation' ELSE 'assigned_to' END)) THEN
 RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Unknown triage column'; END IF;
 tenant:=(request->>'organization_id')::uuid; target:=(request->>'target_id')::uuid;
 key:=request->>'request_key';reason:=request->>'reason';
 IF tenant IS NULL OR target IS NULL OR coalesce(length(btrim(key)),0) NOT BETWEEN 1 AND 256
 OR coalesce(length(btrim(reason)),0) NOT BETWEEN 1 AND 2000
 OR coalesce(length(request->>'expected_state'),0)<>64 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Missing triage fields'; END IF;
 IF kind='incident' AND request ? 'assigned_to' THEN assignment:=(request->>'assigned_to')::uuid; END IF;
 actor:=vader_private.human_guard_v1(tenant,assignment);
 -- Serialize same actor/request before row locks. Cross-actor updates use row lock + token.
 INSERT INTO vader_private.triage_receipts(organization_id,actor_user_id,operation,request_key,payload)
 VALUES(tenant,actor,kind,key,request) ON CONFLICT DO NOTHING;
 GET DIAGNOSTICS fresh=ROW_COUNT;
 IF fresh=0 THEN
  SELECT r.payload,r.response INTO prior_payload,answer FROM vader_private.triage_receipts r
  WHERE r.organization_id=tenant AND r.actor_user_id=actor AND r.operation=kind AND r.request_key=key;
  IF prior_payload IS DISTINCT FROM request THEN RAISE EXCEPTION USING ERRCODE='22000',MESSAGE='Triage replay conflict'; END IF;
  IF answer IS NULL THEN RAISE EXCEPTION 'Incomplete triage receipt'; END IF;
  RETURN answer;
 END IF;
 IF kind='finding' THEN
  SELECT * INTO f FROM public.security_findings WHERE organization_id=tenant AND id=target FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Triage target denied'; END IF;
  before_state:=jsonb_build_object('organization_id',tenant,'id',target,'status',f.status,'remediation',f.remediation,'resolved_at',f.resolved_at);
 ELSE
  SELECT * INTO i FROM public.security_incidents WHERE organization_id=tenant AND id=target FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Triage target denied'; END IF;
  before_state:=jsonb_build_object('organization_id',tenant,'id',target,'status',i.status,'assigned_to',i.assigned_to,'resolved_at',i.resolved_at);
 END IF;
 SELECT coalesce((SELECT v.revision FROM vader_private.triage_versions v
 WHERE v.organization_id=tenant AND v.operation=kind AND v.target_id=target),0) INTO current_revision;
 before_state:=before_state || jsonb_build_object('revision',current_revision);
 IF kind='incident' AND NOT (request ? 'assigned_to') AND i.assigned_to IS NOT NULL THEN
  PERFORM vader_private.human_guard_v1(tenant,i.assigned_to);
 END IF;
 IF request->>'expected_state' IS DISTINCT FROM vader_private.triage_token_v1(kind,before_state) THEN
 RAISE EXCEPTION USING ERRCODE='40001',MESSAGE='Stale triage state'; END IF;
 requested_status:=CASE WHEN request ? 'status' THEN request->>'status' ELSE before_state->>'status' END;
 IF requested_status IS NULL OR NOT vader_private.transition_allowed_v1(kind,before_state->>'status',requested_status) THEN
 RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Unapproved triage transition'; END IF;
 IF kind='finding' THEN
  IF request ? 'remediation' AND request->'remediation'<>'null'::jsonb AND
    (jsonb_typeof(request->'remediation')<>'string' OR length(request->>'remediation')>4000) THEN
   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='Invalid remediation'; END IF;
  UPDATE public.security_findings SET status=requested_status,
   remediation=CASE WHEN request ? 'remediation' THEN request->>'remediation' ELSE f.remediation END,
   resolved_at=CASE WHEN requested_status=before_state->>'status' THEN f.resolved_at
     WHEN requested_status IN ('resolved','false_positive') THEN clock_timestamp() ELSE NULL END
  WHERE organization_id=tenant AND id=target RETURNING * INTO f;
  after_state:=jsonb_build_object('organization_id',tenant,'id',target,'status',f.status,'remediation',f.remediation,'resolved_at',f.resolved_at);
 ELSE
  UPDATE public.security_incidents SET status=requested_status,
   assigned_to=CASE WHEN request ? 'assigned_to' THEN assignment ELSE i.assigned_to END,
   resolved_at=CASE WHEN requested_status=before_state->>'status' THEN i.resolved_at
     WHEN requested_status IN ('resolved','false_positive') THEN clock_timestamp() ELSE NULL END
  WHERE organization_id=tenant AND id=target RETURNING * INTO i;
  after_state:=jsonb_build_object('organization_id',tenant,'id',target,'status',i.status,'assigned_to',i.assigned_to,'resolved_at',i.resolved_at);
 END IF;
 IF (before_state-'revision')=after_state THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='No triage change requested'; END IF;
 INSERT INTO vader_private.triage_versions(organization_id,operation,target_id,revision)
 VALUES(tenant,kind,target,current_revision+1)
 ON CONFLICT(organization_id,operation,target_id) DO UPDATE SET revision=EXCLUDED.revision;
 after_state:=after_state || jsonb_build_object('revision',current_revision+1);
 INSERT INTO public.audit_logs(id,organization_id,actor_user_id,action,target_type,target_id,metadata)
 VALUES(audit_id,tenant,actor,'vader.'||kind||'_triaged',CASE WHEN kind='finding' THEN 'security_findings' ELSE 'security_incidents' END,target::text,
 jsonb_build_object('request_key',key,'operation_version','vader-triage-v1','reason',reason,
 'before_status',before_state->>'status','after_status',after_state->>'status',
 'before_assigned_to',before_state->'assigned_to','after_assigned_to',after_state->'assigned_to',
 'before_state_token',vader_private.triage_token_v1(kind,before_state),'after_state_token',vader_private.triage_token_v1(kind,after_state)));
 answer:=jsonb_build_object('target_id',target,'state',after_state,'state_token',vader_private.triage_token_v1(kind,after_state),'audit_id',audit_id);
 UPDATE vader_private.triage_receipts SET response=answer
 WHERE organization_id=tenant AND actor_user_id=actor AND operation=kind AND request_key=key;
 RETURN answer;
EXCEPTION WHEN OTHERS THEN
 RAISE EXCEPTION USING ERRCODE=SQLSTATE,MESSAGE='VADER triage rejected; operation changes rolled back';
END $fn$;
ALTER FUNCTION vader_private.triage_v1(text,jsonb) OWNER TO vader_triage_owner;
REVOKE ALL ON FUNCTION vader_private.triage_v1(text,jsonb) FROM PUBLIC,anon,authenticated,service_role,vader_ingest,vader_writer_owner;

CREATE FUNCTION vader_private.triage_state_v1(kind text,tenant uuid,target uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET timezone='UTC' AS $fn$
DECLARE state jsonb;
BEGIN
 PERFORM vader_private.human_guard_v1(tenant,NULL);
 IF kind='finding' THEN
  SELECT jsonb_build_object('organization_id',tenant,'id',id,'status',status,'remediation',remediation,'resolved_at',resolved_at,'revision',coalesce((SELECT v.revision FROM vader_private.triage_versions v WHERE v.organization_id=tenant AND v.operation=kind AND v.target_id=target),0))
  INTO state FROM public.security_findings WHERE organization_id=tenant AND id=target;
 ELSIF kind='incident' THEN
  SELECT jsonb_build_object('organization_id',tenant,'id',id,'status',status,'assigned_to',assigned_to,'resolved_at',resolved_at,'revision',coalesce((SELECT v.revision FROM vader_private.triage_versions v WHERE v.organization_id=tenant AND v.operation=kind AND v.target_id=target),0))
  INTO state FROM public.security_incidents WHERE organization_id=tenant AND id=target;
 END IF;
 IF state IS NULL THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='Triage state denied'; END IF;
 RETURN jsonb_build_object('state',state,'state_token',vader_private.triage_token_v1(kind,state));
END $fn$;
ALTER FUNCTION vader_private.triage_state_v1(text,uuid,uuid) OWNER TO vader_triage_owner;
REVOKE ALL ON FUNCTION vader_private.triage_state_v1(text,uuid,uuid) FROM PUBLIC,anon,authenticated,service_role,vader_ingest,vader_writer_owner;

CREATE FUNCTION vader_user_api.triage_finding_v1(request jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$ SELECT vader_private.triage_v1('finding',request) $fn$;
CREATE FUNCTION vader_user_api.triage_incident_v1(request jsonb) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$ SELECT vader_private.triage_v1('incident',request) $fn$;
CREATE FUNCTION vader_user_api.finding_state_v1(tenant uuid,target uuid) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$ SELECT vader_private.triage_state_v1('finding',tenant,target) $fn$;
CREATE FUNCTION vader_user_api.incident_state_v1(tenant uuid,target uuid) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fn$ SELECT vader_private.triage_state_v1('incident',tenant,target) $fn$;
ALTER FUNCTION vader_user_api.triage_finding_v1(jsonb) OWNER TO vader_triage_owner;
ALTER FUNCTION vader_user_api.triage_incident_v1(jsonb) OWNER TO vader_triage_owner;
ALTER FUNCTION vader_user_api.finding_state_v1(uuid,uuid) OWNER TO vader_triage_owner;
ALTER FUNCTION vader_user_api.incident_state_v1(uuid,uuid) OWNER TO vader_triage_owner;
REVOKE ALL ON FUNCTION vader_user_api.triage_finding_v1(jsonb),vader_user_api.triage_incident_v1(jsonb),
 vader_user_api.finding_state_v1(uuid,uuid),vader_user_api.incident_state_v1(uuid,uuid)
 FROM PUBLIC,anon,authenticated,service_role,vader_ingest,vader_writer_owner,authenticator;
GRANT EXECUTE ON FUNCTION vader_user_api.triage_finding_v1(jsonb),vader_user_api.triage_incident_v1(jsonb),
 vader_user_api.finding_state_v1(uuid,uuid),vader_user_api.incident_state_v1(uuid,uuid) TO authenticated;
REVOKE CREATE ON SCHEMA vader_private,vader_user_api FROM vader_triage_owner;
-- Do NOT expose this schema in PostgREST here. API configuration is a separate review.
COMMIT;
